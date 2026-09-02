//! Bitcoin P2P version/verack handshake over TCP.
//!
//! `connect` opens a stream to a peer, sends a `version` message, exchanges
//! `verack`, and logs each step, writing what the peer advertised into a
//! caller-owned `PeerInfo`. The wire format is a 24-byte header (magic,
//! 12-byte command, payload length, truncated double-SHA256 checksum) followed
//! by the payload.
//!
//! No memory is allocated: the peer's `version` is read into a stack buffer and
//! every other message is skipped in place.

const std = @import("std");
const assert = std.debug.assert;

const net = std.Io.net;
const log = std.log.scoped(.p2p);

/// Network magic prefixing every message on each network.
pub const mainnet_magic: u32 = 0xd9b4bef9;
pub const testnet3_magic: u32 = 0x0709110b;
pub const signet_magic: u32 = 0x40cf030a;

// Message-header layout, in bytes.
const magic_len = 4;
const command_len = 12;
const length_len = 4;
const checksum_len = 4;
const header_len = magic_len + command_len + length_len + checksum_len;
const magic_offset = 0;
const command_offset = magic_offset + magic_len;
const length_offset = command_offset + command_len;
const checksum_offset = length_offset + length_len;

/// Sanity bound on a message's length field. The protocol maximum is 32 MiB; a
/// handshake never approaches it, and non-`version` messages are skipped
/// without buffering, so this only guards the length field itself.
const message_payload_max = 4 * 1024 * 1024;

/// `MAX_SUBVERSION_LENGTH` in Bitcoin Core.
const max_user_agent_len = 256;

/// Byte offset of the user-agent var_str within a `version` payload:
/// version(4) + services(8) + timestamp(8) + addr_recv(26) + addr_from(26) + nonce(8).
const version_prefix_len = 4 + 8 + 8 + 26 + 26 + 8;

/// Smallest and largest `version` payload we produce or accept: the fixed
/// prefix, the user-agent var_str (length prefix up to 3 bytes, string up to
/// `max_user_agent_len`), then start_height(4) + relay(1).
const version_payload_min = version_prefix_len + 1 + 0 + 4 + 1;
const version_payload_max = version_prefix_len + 3 + max_user_agent_len + 4 + 1;

/// Upper bound on messages read during a handshake. version + verack is the
/// core exchange; BIP-155 lets a few zero-payload messages (wtxidrelay,
/// sendaddrv2, sendcmpct, feefilter, an early ping) arrive in between.
const messages_max = 32;

/// Addresses a single DNS-seed lookup may yield before we stop dialing.
const dial_addresses_max = 32;

const read_buffer_len = 8 * 1024;
const write_buffer_len = 4 * 1024;

comptime {
    assert(header_len == 24);
    assert(command_offset == magic_len);
    assert(length_offset == magic_len + command_len);
    assert(checksum_offset == magic_len + command_len + length_len);
    assert(version_payload_min <= version_payload_max);
    assert(version_payload_max <= message_payload_max);
    assert(max_user_agent_len < version_payload_max);
    assert(version_payload_max <= read_buffer_len);
}

pub const Options = struct {
    /// Protocol version to advertise (70016 = wtxid relay, BIP-339).
    protocol_version: i32 = 70016,
    /// Service bits to advertise. 0 = NODE_NONE: we serve nothing, we crawl.
    services: u64 = 0,
    /// User agent string (BIP-14).
    user_agent: []const u8 = "/btc-crawler:0.1.0/",
    /// Network magic.
    magic: u32 = mainnet_magic,
    /// Restrict a DNS name's resolved addresses to one family before dialing.
    /// Defaults to IPv4: `std.Io.Threaded` (0.16.0) has no connect timeout, so a
    /// black-holed IPv6 address would hang forever on a host without IPv6.
    /// `null` tries both, `.ip6` forces IPv6.
    address_family: ?net.IpAddress.Family = .ip4,
};

/// What the peer advertised in its own `version`. Filled in place by `connect`.
pub const PeerInfo = struct {
    protocol_version: i32,
    services: u64,
    timestamp: i64,
    user_agent_len: u32,
    user_agent_buffer: [max_user_agent_len]u8,

    pub fn user_agent(peer: *const PeerInfo) []const u8 {
        assert(peer.user_agent_len <= peer.user_agent_buffer.len);
        return peer.user_agent_buffer[0..peer.user_agent_len];
    }
};

pub const HandshakeError = error{
    /// A message did not begin with the expected network magic.
    MagicMismatch,
    /// The peer's `version` checksum did not match its payload.
    ChecksumMismatch,
    /// A length field exceeded `message_payload_max`, or a `version` exceeded
    /// `version_payload_max`.
    MessageTooLarge,
    /// The peer's `version` payload was too short or internally inconsistent.
    MalformedVersion,
    /// `messages_max` messages passed without both `version` and `verack`.
    HandshakeIncomplete,
};

/// Connect to `host:port`, complete the version/verack handshake, and write the
/// peer's advertised details into `peer`.
///
/// `host` may be a literal IPv4/IPv6 address or a DNS name; a name is resolved
/// via `io` and its addresses are dialed in order until one connects.
pub fn connect(peer: *PeerInfo, io: std.Io, host: []const u8, port: u16, options: Options) !void {
    assert(host.len > 0);
    assert(port != 0);
    assert(options.magic != 0);
    assert(options.user_agent.len > 0);
    assert(options.user_agent.len <= max_user_agent_len);

    log.info("connecting to {s}:{d}", .{ host, port });
    const stream = try dial(io, host, port, options.address_family);
    defer stream.close(io);
    log.info("tcp connected", .{});

    var read_buffer: [read_buffer_len]u8 = undefined;
    var write_buffer: [write_buffer_len]u8 = undefined;
    var stream_reader = stream.reader(io, &read_buffer);
    var stream_writer = stream.writer(io, &write_buffer);

    var version_buffer: [version_payload_max]u8 = undefined;
    const version_payload = build_version(io, &version_buffer, port, options);
    try write_message(&stream_writer, options.magic, "version", version_payload);
    log.info("-> version (protocol={d}, user_agent={s})", .{
        options.protocol_version, options.user_agent,
    });

    var version_received = false;
    var verack_received = false;
    var scratch: [version_payload_max]u8 = undefined;

    var messages_seen: u32 = 0;
    while (messages_seen < messages_max) : (messages_seen += 1) {
        const header = try read_header(&stream_reader, options.magic);

        if (command_eql(&header.command, "version")) {
            try receive_version(peer, &stream_reader, &header, &scratch);
            version_received = true;
            log.info("<- version (protocol={d}, services=0x{x}, user_agent={s})", .{
                peer.protocol_version, peer.services, peer.user_agent(),
            });
            try write_message(&stream_writer, options.magic, "verack", &.{});
            log.info("-> verack", .{});
        } else {
            // verack and anything else carry no payload we need; skip in place.
            stream_reader.interface.discardAll(header.payload_len) catch |err|
                return read_err(&stream_reader, err);
            if (command_eql(&header.command, "verack")) {
                verack_received = true;
                log.info("<- verack", .{});
            } else {
                log.debug("<- {s} ({d} bytes, ignored)", .{
                    command_name(&header.command), header.payload_len,
                });
            }
        }

        if (version_received and verack_received) {
            assert(peer.user_agent_len <= peer.user_agent_buffer.len);
            log.info("handshake complete with {s}:{d}", .{ host, port });
            return;
        }
    }

    assert(messages_seen == messages_max);
    return error.HandshakeIncomplete;
}

/// Open a TCP stream to `host:port`. A literal IPv4/IPv6 `host` connects
/// directly; a DNS name is resolved via `io` and its addresses are dialed in
/// order until one connects.
///
/// There is no connect timeout: `std.Io.Threaded` (0.16.0) panics on a
/// non-`.none` `ConnectOptions.timeout`, and `HostName.connect`'s concurrent
/// dial can hang on an unroutable address. Sequential dialing keeps the failure
/// modes predictable until the io_uring event loop lands.
fn dial(io: std.Io, host: []const u8, port: u16, family: ?net.IpAddress.Family) !net.Stream {
    assert(host.len > 0);
    assert(port != 0);

    const options: net.IpAddress.ConnectOptions = .{ .mode = .stream, .timeout = .none };

    if (net.IpAddress.parse(host, port)) |address| {
        return address.connect(io, options);
    } else |_| {
        // Not a literal address; resolve it below.
    }

    const name = try net.HostName.init(host);
    var results_buffer: [dial_addresses_max]net.HostName.LookupResult = undefined;
    var results: std.Io.Queue(net.HostName.LookupResult) = .init(&results_buffer);
    try name.lookup(io, &results, .{ .port = port, .family = family });

    var last_error: ?net.IpAddress.ConnectError = null;
    var addresses_tried: u32 = 0;
    while (results.getOneUncancelable(io)) |result| {
        switch (result) {
            .canonical_name => {},
            .address => |address| {
                assert(addresses_tried < dial_addresses_max);
                addresses_tried += 1;
                log.debug("dialing {f}", .{address});
                if (address.connect(io, options)) |stream| {
                    return stream;
                } else |err| {
                    last_error = err;
                }
            },
        }
    } else |_| {
        // Queue closed: the lookup finished producing results.
    }

    if (addresses_tried == 0) return error.UnknownHostName;
    return last_error orelse error.ConnectionRefused;
}

const Header = struct {
    command: [command_len]u8,
    payload_len: u32,
    checksum: [checksum_len]u8,
};

/// Read and validate a 24-byte message header. The payload is left unread; the
/// caller consumes exactly `payload_len` bytes before the next call.
fn read_header(stream_reader: *net.Stream.Reader, magic: u32) !Header {
    assert(magic != 0);
    const reader = &stream_reader.interface;

    const magic_found = reader.takeInt(u32, .little) catch |err|
        return read_err(stream_reader, err);
    if (magic_found != magic) return error.MagicMismatch;

    // takeArray points into the reader's buffer; copy out before the next take
    // can rebase it.
    const command = (reader.takeArray(command_len) catch |err|
        return read_err(stream_reader, err)).*;
    const payload_len = reader.takeInt(u32, .little) catch |err|
        return read_err(stream_reader, err);
    const checksum = (reader.takeArray(checksum_len) catch |err|
        return read_err(stream_reader, err)).*;

    if (payload_len > message_payload_max) return error.MessageTooLarge;
    assert(payload_len <= message_payload_max);
    return .{ .command = command, .payload_len = payload_len, .checksum = checksum };
}

/// Read a `version` payload into `scratch`, verify its checksum, and parse it
/// into `peer`.
fn receive_version(
    peer: *PeerInfo,
    stream_reader: *net.Stream.Reader,
    header: *const Header,
    scratch: []u8,
) !void {
    assert(command_eql(&header.command, "version"));
    assert(scratch.len == version_payload_max);

    if (header.payload_len > scratch.len) return error.MessageTooLarge;
    assert(header.payload_len <= scratch.len);

    const payload = scratch[0..header.payload_len];
    stream_reader.interface.readSliceAll(payload) catch |err|
        return read_err(stream_reader, err);

    if (!std.mem.eql(u8, &double_sha256_prefix(payload), &header.checksum)) {
        return error.ChecksumMismatch;
    }
    try parse_version(peer, payload);
}

const ReadError = net.Stream.Reader.Error || error{ EndOfStream, ReadFailed };

/// Replace the reader interface's opaque failure with the concrete socket error
/// the stream recorded, so callers see a cause rather than `ReadFailed`.
fn read_err(stream_reader: *net.Stream.Reader, err: error{ ReadFailed, EndOfStream }) ReadError {
    if (err == error.EndOfStream) return error.EndOfStream;
    assert(err == error.ReadFailed);
    return stream_reader.err orelse error.ReadFailed;
}

const WriteError = net.Stream.Writer.Error || error{WriteFailed};

fn write_err(stream_writer: *net.Stream.Writer) WriteError {
    return stream_writer.err orelse error.WriteFailed;
}

fn write_message(
    stream_writer: *net.Stream.Writer,
    magic: u32,
    command: []const u8,
    payload: []const u8,
) WriteError!void {
    assert(magic != 0);
    assert(command.len > 0);
    assert(command.len <= command_len);
    assert(payload.len <= message_payload_max);

    var header: [header_len]u8 = undefined;
    std.mem.writeInt(u32, header[magic_offset..][0..magic_len], magic, .little);
    @memset(header[command_offset..][0..command_len], 0);
    @memcpy(header[command_offset..][0..command.len], command);
    std.mem.writeInt(u32, header[length_offset..][0..length_len], @intCast(payload.len), .little);
    @memcpy(header[checksum_offset..][0..checksum_len], &double_sha256_prefix(payload));

    const writer = &stream_writer.interface;
    writer.writeAll(&header) catch return write_err(stream_writer);
    writer.writeAll(payload) catch return write_err(stream_writer);
    writer.flush() catch return write_err(stream_writer);
}

/// Serialize our `version` payload into `buffer` and return the written prefix.
/// `buffer` must hold at least `version_payload_max` bytes; the writes below
/// then cannot overflow, hence `catch unreachable`.
fn build_version(io: std.Io, buffer: []u8, peer_port: u16, options: Options) []const u8 {
    assert(buffer.len >= version_payload_max);
    assert(options.user_agent.len > 0);
    assert(options.user_agent.len <= max_user_agent_len);

    var writer = std.Io.Writer.fixed(buffer);
    const timestamp_seconds: i64 = std.Io.Timestamp.now(io, .real).toSeconds();

    // Non-cryptographic randomness is fine: the nonce only lets a node detect a
    // connection to itself.
    var nonce: [8]u8 = undefined;
    io.random(&nonce);

    writer.writeInt(i32, options.protocol_version, .little) catch unreachable;
    writer.writeInt(u64, options.services, .little) catch unreachable;
    writer.writeInt(i64, timestamp_seconds, .little) catch unreachable;

    // addr_recv: the peer's address. Services and IP zeroed (the peer ignores
    // them here); port is the one we dialed, in network byte order.
    writer.writeInt(u64, 0, .little) catch unreachable;
    writer.splatByteAll(0, 16) catch unreachable;
    writer.writeInt(u16, peer_port, .big) catch unreachable;

    // addr_from: our address. Unroutable, all zero.
    writer.writeInt(u64, 0, .little) catch unreachable;
    writer.splatByteAll(0, 16) catch unreachable;
    writer.writeInt(u16, 0, .big) catch unreachable;

    writer.writeAll(&nonce) catch unreachable;
    write_compact_size(&writer, options.user_agent.len) catch unreachable;
    writer.writeAll(options.user_agent) catch unreachable;
    writer.writeInt(i32, 0, .little) catch unreachable; // start_height
    writer.writeByte(0) catch unreachable; // relay (BIP-37)

    const payload = writer.buffered();
    assert(payload.len >= version_payload_min);
    assert(payload.len <= version_payload_max);
    return payload;
}

const ParseError = error{MalformedVersion};

/// Parse a `version` payload into `peer`. `peer` is fully overwritten.
fn parse_version(peer: *PeerInfo, payload: []const u8) ParseError!void {
    assert(payload.len <= version_payload_max);
    peer.* = std.mem.zeroes(PeerInfo);

    if (payload.len < version_prefix_len) return error.MalformedVersion;

    peer.protocol_version = std.mem.readInt(i32, payload[0..4], .little);
    peer.services = std.mem.readInt(u64, payload[4..12], .little);
    peer.timestamp = std.mem.readInt(i64, payload[12..20], .little);

    var offset: u32 = version_prefix_len;
    const claimed_len = read_compact_size(payload, &offset) orelse return error.MalformedVersion;
    if (claimed_len > max_user_agent_len) return error.MalformedVersion;
    if (offset + claimed_len > payload.len) return error.MalformedVersion;

    const copy_len: u32 = @intCast(@min(claimed_len, peer.user_agent_buffer.len));
    @memcpy(peer.user_agent_buffer[0..copy_len], payload[offset..][0..copy_len]);
    peer.user_agent_len = copy_len;

    assert(peer.user_agent_len <= peer.user_agent_buffer.len);
}

fn write_compact_size(writer: *std.Io.Writer, value: u64) std.Io.Writer.Error!void {
    switch (value) {
        0...0xfc => try writer.writeByte(@intCast(value)),
        0xfd...0xffff => {
            try writer.writeByte(0xfd);
            try writer.writeInt(u16, @intCast(value), .little);
        },
        0x1_0000...0xffff_ffff => {
            try writer.writeByte(0xfe);
            try writer.writeInt(u32, @intCast(value), .little);
        },
        else => {
            try writer.writeByte(0xff);
            try writer.writeInt(u64, value, .little);
        },
    }
}

/// Decode a CompactSize at `buffer[offset.*]`, advancing `offset.*` past it.
/// Returns null if `buffer` is too short for the encoded form.
fn read_compact_size(buffer: []const u8, offset: *u32) ?u64 {
    const len: u32 = @intCast(buffer.len);
    assert(offset.* <= len);
    if (offset.* == len) return null;

    const first = buffer[offset.*];
    offset.* += 1;
    switch (first) {
        0xfd => {
            if (offset.* + 2 > len) return null;
            defer offset.* += 2;
            return std.mem.readInt(u16, buffer[offset.*..][0..2], .little);
        },
        0xfe => {
            if (offset.* + 4 > len) return null;
            defer offset.* += 4;
            return std.mem.readInt(u32, buffer[offset.*..][0..4], .little);
        },
        0xff => {
            if (offset.* + 8 > len) return null;
            defer offset.* += 8;
            return std.mem.readInt(u64, buffer[offset.*..][0..8], .little);
        },
        else => return first,
    }
}

/// First `checksum_len` bytes of SHA-256(SHA-256(data)) — the Bitcoin message
/// checksum.
fn double_sha256_prefix(data: []const u8) [checksum_len]u8 {
    const Sha256 = std.crypto.hash.sha2.Sha256;
    comptime assert(Sha256.digest_length == 32);

    var round1: [Sha256.digest_length]u8 = undefined;
    Sha256.hash(data, &round1, .{});
    var round2: [Sha256.digest_length]u8 = undefined;
    Sha256.hash(&round1, &round2, .{});
    return round2[0..checksum_len].*;
}

/// True if `command` (NUL-padded to 12 bytes) names exactly `name`.
fn command_eql(command: *const [command_len]u8, name: []const u8) bool {
    assert(name.len > 0);
    if (name.len > command_len) return false;
    if (!std.mem.eql(u8, command[0..name.len], name)) return false;
    for (command[name.len..]) |byte| {
        if (byte != 0) return false;
    }
    return true;
}

/// `command` without its trailing NUL padding, for logging.
fn command_name(command: *const [command_len]u8) []const u8 {
    const end = std.mem.indexOfScalar(u8, command, 0) orelse command_len;
    assert(end <= command_len);
    return command[0..end];
}

test "compact size: encode then decode round-trips across size-class boundaries" {
    // For each value on or beside a size-class boundary: encode it, decode the
    // bytes back, and check both the value and that decoding consumed exactly
    // the bytes encoding produced.
    const cases = [_]u64{ 0, 1, 0xfc, 0xfd, 0xff, 0xffff, 0x1_0000, 0xffff_ffff, 0x1_0000_0000 };
    for (cases) |value| {
        var buffer: [9]u8 = undefined;
        var writer = std.Io.Writer.fixed(&buffer);
        try write_compact_size(&writer, value);

        var offset: u32 = 0;
        const decoded = read_compact_size(writer.buffered(), &offset) orelse return error.Truncated;
        try std.testing.expectEqual(value, decoded);
        try std.testing.expectEqual(@as(u32, @intCast(writer.buffered().len)), offset);
    }
}

test "compact size: decode returns null on a truncated multi-byte value" {
    var offset: u32 = 0;
    try std.testing.expectEqual(@as(?u64, null), read_compact_size(&[_]u8{0xfd}, &offset));
}

test "double sha256 prefix: empty-payload checksum is 5df6e0e2" {
    try std.testing.expectEqualSlices(
        u8,
        &.{ 0x5d, 0xf6, 0xe0, 0xe2 },
        &double_sha256_prefix(&.{}),
    );
}

test "command matching: exact name, NUL padding tolerated, mismatch rejected" {
    var command = [_]u8{0} ** command_len;
    @memcpy(command[0..7], "version");
    try std.testing.expect(command_eql(&command, "version"));
    try std.testing.expect(!command_eql(&command, "verack"));
    try std.testing.expect(!command_eql(&command, "versio"));
    try std.testing.expectEqualStrings("version", command_name(&command));
}

test "parse_version: extracts fields from a well-formed payload" {
    var buffer: [version_payload_max]u8 = undefined;
    var writer = std.Io.Writer.fixed(&buffer);
    const ua = "/Satoshi:27.0.0/";

    try writer.writeInt(i32, 70016, .little);
    try writer.writeInt(u64, 0x409, .little);
    try writer.writeInt(i64, 1_700_000_000, .little);
    try writer.splatByteAll(0, 26); // addr_recv
    try writer.splatByteAll(0, 26); // addr_from
    try writer.writeInt(u64, 0xdead_beef, .little); // nonce
    try writer.writeByte(@intCast(ua.len));
    try writer.writeAll(ua);
    try writer.writeInt(i32, 850_000, .little); // start_height
    try writer.writeByte(1); // relay

    var peer: PeerInfo = undefined;
    try parse_version(&peer, writer.buffered());
    try std.testing.expectEqual(@as(i32, 70016), peer.protocol_version);
    try std.testing.expectEqual(@as(u64, 0x409), peer.services);
    try std.testing.expectEqual(@as(i64, 1_700_000_000), peer.timestamp);
    try std.testing.expectEqualStrings(ua, peer.user_agent());
}

test "parse_version: rejects a payload shorter than the fixed prefix" {
    var peer: PeerInfo = undefined;
    try std.testing.expectError(error.MalformedVersion, parse_version(&peer, &[_]u8{0} ** 40));
}
