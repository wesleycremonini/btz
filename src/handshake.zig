//! Bitcoin P2P version/verack handshake, driven by the io_uring event loop.
//!
//! `connect` opens a socket, then runs a small state machine off `IO`
//! completions: connect -> send our `version` -> receive the peer's `version`
//! (reply `verack`) and `verack` -> done. It writes what the peer advertised
//! into a caller-owned `PeerInfo`. Nothing is allocated: the send frame and the
//! receive buffer live in the `Handshake` state struct.
//!
//! The wire format is a 24-byte header (magic, 12-byte command, payload length,
//! truncated double-SHA256 checksum) followed by the payload.

const std = @import("std");
const assert = std.debug.assert;

const linux = std.os.linux;
const net = std.Io.net;
const io_uring = @import("io.zig");
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
/// handshake never approaches it.
const message_payload_max = 4 * 1024 * 1024;

/// `MAX_SUBVERSION_LENGTH` in Bitcoin Core.
const max_user_agent_len = 256;

/// Byte offset of the user-agent var_str within a `version` payload:
/// version(4) + services(8) + timestamp(8) + addr_recv(26) + addr_from(26) + nonce(8).
const version_prefix_len = 4 + 8 + 8 + 26 + 26 + 8;

/// Smallest and largest `version` payload we produce or accept.
const version_payload_min = version_prefix_len + 1 + 0 + 4 + 1;
const version_payload_max = version_prefix_len + 3 + max_user_agent_len + 4 + 1;

/// Receive buffer. Must hold the largest single message we parse (a `version`)
/// plus its header; other messages are consumed and dropped from the front.
const recv_buffer_len = 4 * 1024;

/// Send buffer: one framed message at a time (our `version` is the largest).
const frame_buffer_len = header_len + version_payload_max;

/// Upper bound on completions processed during one handshake. connect + our
/// version send + a handful of recvs + our verack send + the peer's trailing
/// messages fit comfortably; this only bounds a pathological peer.
const completions_max = 64;

// `user_data` tags distinguishing the two SQEs a handshake keeps in flight.
const user_data_io: u64 = 1;
const user_data_timeout: u64 = 2;

comptime {
    assert(header_len == 24);
    assert(command_offset == magic_len);
    assert(length_offset == magic_len + command_len);
    assert(checksum_offset == magic_len + command_len + length_len);
    assert(version_payload_min <= version_payload_max);
    assert(version_payload_max <= message_payload_max);
    assert(recv_buffer_len >= header_len + version_payload_max);
    assert(frame_buffer_len >= header_len + version_payload_max);
    assert(user_data_io != 0);
    assert(user_data_timeout != 0);
    assert(user_data_io != user_data_timeout);
}

pub const Options = struct {
    /// Protocol version to advertise (70016 = wtxid relay, BIP-339).
    protocol_version: i32 = 70016,
    /// Service bits to advertise. 0 = NODE_NONE: we serve nothing, we crawl.
    services: u64 = 0,
    /// User agent string (BIP-14).
    user_agent: []const u8 = "/btz:0.1.0/",
    /// Network magic.
    magic: u32 = mainnet_magic,
    /// Whole-handshake deadline in nanoseconds.
    timeout_ns: u63 = 10 * std.time.ns_per_s,
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
    /// A length field, or a `version`, exceeded what we will buffer.
    MessageTooLarge,
    /// The peer's `version` payload was too short or internally inconsistent.
    MalformedVersion,
    /// The peer closed the connection mid-handshake.
    EndOfStream,
    /// The handshake did not finish within `Options.timeout_ns`.
    Timeout,
    /// `completions_max` completions passed without finishing (hostile peer).
    TooManyCompletions,
};

/// Open a socket to `address`, run the handshake on `io`, and write the peer's
/// advertised details into `peer`. `address` must already be resolved.
pub fn connect(peer: *PeerInfo, io: *io_uring.IO, address: net.IpAddress, options: Options) !void {
    assert(options.magic != 0);
    assert(options.user_agent.len > 0);
    assert(options.user_agent.len <= max_user_agent_len);
    assert(options.timeout_ns > 0);

    const fd = try io_uring.open_socket(address);
    defer io_uring.close_socket(fd);

    var handshake: Handshake = undefined;
    try handshake.init(peer, io, fd, address, options);
    try handshake.run();
}

const Handshake = struct {
    io: *io_uring.IO,
    fd: linux.fd_t,
    options: Options,
    address: net.IpAddress,
    peer: *PeerInfo,

    /// Stable storage the connect SQE points at.
    sockaddr: io_uring.SockAddr,
    /// Stable storage the timeout SQE points at.
    deadline: linux.kernel_timespec,

    send_buffer: [frame_buffer_len]u8,
    /// The not-yet-sent tail of the current frame (a slice into `send_buffer`).
    send_frame: []const u8,

    recv_buffer: [recv_buffer_len]u8,
    recv_len: u32,

    version_received: bool,
    verack_received: bool,
    phase: Phase,

    const Phase = enum { connecting, sending, receiving, complete };
    const PumpResult = enum { awaiting_more, send_verack, complete };

    fn init(
        handshake: *Handshake,
        peer: *PeerInfo,
        io: *io_uring.IO,
        fd: linux.fd_t,
        address: net.IpAddress,
        options: Options,
    ) !void {
        handshake.* = .{
            .io = io,
            .fd = fd,
            .options = options,
            .address = address,
            .peer = peer,
            .sockaddr = try io_uring.SockAddr.from(address),
            .deadline = .{
                .sec = @intCast(options.timeout_ns / std.time.ns_per_s),
                .nsec = @intCast(options.timeout_ns % std.time.ns_per_s),
            },
            .send_buffer = undefined,
            .send_frame = &.{},
            .recv_buffer = undefined,
            .recv_len = 0,
            .version_received = false,
            .verack_received = false,
            .phase = .connecting,
        };
    }

    fn run(handshake: *Handshake) !void {
        try handshake.io.prep_timeout(user_data_timeout, &handshake.deadline);
        try handshake.io.prep_connect(user_data_io, handshake.fd, &handshake.sockaddr);
        log.info("connecting to {f}", .{handshake.address});

        var completions: u32 = 0;
        while (handshake.phase != .complete) : (completions += 1) {
            if (completions >= completions_max) return error.TooManyCompletions;

            const cqe = try handshake.io.next_completion();
            if (cqe.user_data == user_data_timeout) return error.Timeout;
            assert(cqe.user_data == user_data_io);

            try handshake.on_completion(cqe);
        }

        assert(handshake.version_received);
        assert(handshake.verack_received);
        log.info("handshake complete with {f}", .{handshake.address});
    }

    fn on_completion(handshake: *Handshake, cqe: linux.io_uring_cqe) !void {
        switch (handshake.phase) {
            .connecting => {
                try check_completion(cqe);
                assert(cqe.res == 0);
                log.info("tcp connected", .{});
                try handshake.send_version();
            },
            .sending => {
                try check_completion(cqe);
                const sent: u32 = @intCast(cqe.res);
                assert(sent <= handshake.send_frame.len);
                handshake.send_frame = handshake.send_frame[sent..];
                if (handshake.send_frame.len > 0) {
                    // Rare short send: push the remainder before advancing.
                    try handshake.io.prep_send(user_data_io, handshake.fd, handshake.send_frame);
                    return;
                }
                try handshake.advance();
            },
            .receiving => {
                try check_completion(cqe);
                const received: u32 = @intCast(cqe.res);
                if (received == 0) return error.EndOfStream;
                handshake.recv_len += received;
                assert(handshake.recv_len <= recv_buffer_len);
                try handshake.advance();
            },
            .complete => unreachable,
        }
    }

    /// Drain whatever full messages are buffered, then arm the next SQE.
    fn advance(handshake: *Handshake) !void {
        switch (try handshake.pump()) {
            .complete => handshake.phase = .complete,
            .awaiting_more => {
                assert(handshake.recv_len < recv_buffer_len);
                try handshake.io.prep_recv(
                    user_data_io,
                    handshake.fd,
                    handshake.recv_buffer[handshake.recv_len..],
                );
                handshake.phase = .receiving;
            },
            .send_verack => {
                const frame = frame_in_place(&handshake.send_buffer, handshake.options.magic, "verack", 0);
                try handshake.arm_send(frame);
                log.info("-> verack", .{});
            },
        }
    }

    fn send_version(handshake: *Handshake) !void {
        const payload = build_version(
            handshake.send_buffer[header_len..],
            handshake.address,
            handshake.options,
        );
        const frame = frame_in_place(
            &handshake.send_buffer,
            handshake.options.magic,
            "version",
            @intCast(payload.len),
        );
        try handshake.arm_send(frame);
        log.info("-> version (protocol={d}, user_agent={s})", .{
            handshake.options.protocol_version, handshake.options.user_agent,
        });
    }

    fn arm_send(handshake: *Handshake, frame: []const u8) !void {
        assert(frame.len >= header_len);
        handshake.send_frame = frame;
        try handshake.io.prep_send(user_data_io, handshake.fd, frame);
        handshake.phase = .sending;
    }

    fn pump(handshake: *Handshake) !PumpResult {
        while (true) {
            if (handshake.recv_len < header_len) return .awaiting_more;

            const header = try parse_header(
                handshake.recv_buffer[0..header_len],
                handshake.options.magic,
            );
            const total = header_len + header.payload_len;
            if (total > recv_buffer_len) return error.MessageTooLarge;
            if (handshake.recv_len < total) return .awaiting_more;

            const payload = handshake.recv_buffer[header_len..total];
            var reply_with_verack = false;

            if (command_eql(&header.command, "version")) {
                if (header.payload_len > version_payload_max) return error.MessageTooLarge;
                if (!std.mem.eql(u8, &double_sha256_prefix(payload), &header.checksum)) {
                    return error.ChecksumMismatch;
                }
                try parse_version(handshake.peer, payload);
                handshake.version_received = true;
                reply_with_verack = true;
                log.info("<- version (protocol={d}, services=0x{x}, user_agent={s})", .{
                    handshake.peer.protocol_version,
                    handshake.peer.services,
                    handshake.peer.user_agent(),
                });
            } else if (command_eql(&header.command, "verack")) {
                handshake.verack_received = true;
                log.info("<- verack", .{});
            } else {
                log.debug("<- {s} ({d} bytes, ignored)", .{
                    command_name(&header.command), header.payload_len,
                });
            }

            // Drop the consumed message from the front of the buffer.
            const rest = handshake.recv_len - total;
            std.mem.copyForwards(
                u8,
                handshake.recv_buffer[0..rest],
                handshake.recv_buffer[total..handshake.recv_len],
            );
            handshake.recv_len = rest;

            if (reply_with_verack) return .send_verack;
            if (handshake.version_received and handshake.verack_received) return .complete;
        }
    }
};

const Header = struct {
    command: [command_len]u8,
    payload_len: u32,
    checksum: [checksum_len]u8,
};

const HeaderError = error{ MagicMismatch, MessageTooLarge };

/// Parse a 24-byte message header from `bytes`.
fn parse_header(bytes: *const [header_len]u8, magic: u32) HeaderError!Header {
    assert(magic != 0);

    const magic_found = std.mem.readInt(u32, bytes[magic_offset..][0..magic_len], .little);
    if (magic_found != magic) return error.MagicMismatch;

    const payload_len = std.mem.readInt(u32, bytes[length_offset..][0..length_len], .little);
    if (payload_len > message_payload_max) return error.MessageTooLarge;
    assert(payload_len <= message_payload_max);

    var header: Header = .{ .command = undefined, .payload_len = payload_len, .checksum = undefined };
    @memcpy(&header.command, bytes[command_offset..][0..command_len]);
    @memcpy(&header.checksum, bytes[checksum_offset..][0..checksum_len]);
    return header;
}

/// Write a 24-byte header into `buffer[0..header_len]` for a payload already
/// sitting at `buffer[header_len..][0..payload_len]`. Returns the framed message.
fn frame_in_place(buffer: []u8, magic: u32, command: []const u8, payload_len: u32) []const u8 {
    assert(magic != 0);
    assert(command.len > 0);
    assert(command.len <= command_len);
    assert(payload_len <= message_payload_max);
    assert(buffer.len >= header_len + @as(usize, payload_len));

    const payload = buffer[header_len..][0..payload_len];
    std.mem.writeInt(u32, buffer[magic_offset..][0..magic_len], magic, .little);
    @memset(buffer[command_offset..][0..command_len], 0);
    @memcpy(buffer[command_offset..][0..command.len], command);
    std.mem.writeInt(u32, buffer[length_offset..][0..length_len], payload_len, .little);
    @memcpy(buffer[checksum_offset..][0..checksum_len], &double_sha256_prefix(payload));

    return buffer[0 .. header_len + @as(usize, payload_len)];
}

/// Serialize our `version` payload into `buffer` and return the written prefix.
/// `buffer` must hold at least `version_payload_max` bytes; the writes below
/// then cannot overflow, hence `catch unreachable`.
fn build_version(buffer: []u8, address: net.IpAddress, options: Options) []const u8 {
    assert(buffer.len >= version_payload_max);
    assert(options.user_agent.len > 0);
    assert(options.user_agent.len <= max_user_agent_len);

    var writer = std.Io.Writer.fixed(buffer);
    var nonce: [8]u8 = undefined;
    fill_nonce(&nonce);
    const peer_port = net.IpAddress.getPort(address);

    writer.writeInt(i32, options.protocol_version, .little) catch unreachable;
    writer.writeInt(u64, options.services, .little) catch unreachable;
    writer.writeInt(i64, unix_seconds(), .little) catch unreachable;

    // addr_recv: the peer. Services and IP zeroed (the peer ignores them here);
    // port is the one we dialed, in network byte order.
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

fn unix_seconds() i64 {
    var now: linux.timespec = undefined;
    const rc = linux.clock_gettime(.REALTIME, &now);
    assert(linux.errno(rc) == .SUCCESS);
    return @intCast(now.sec);
}

fn fill_nonce(nonce: *[8]u8) void {
    const rc = linux.getrandom(nonce, nonce.len, 0);
    if (linux.errno(rc) == .SUCCESS and rc == nonce.len) return;

    // getrandom unavailable (old kernel or seccomp). The nonce only lets a node
    // notice a connection to itself, so a clock-seeded PRNG is sufficient.
    var seed: linux.timespec = undefined;
    _ = linux.clock_gettime(.REALTIME, &seed);
    var prng = std.Random.DefaultPrng.init(
        @as(u64, @bitCast(@as(i64, seed.sec))) ^
            (@as(u64, @bitCast(@as(i64, seed.nsec))) *% 0x9e37_79b9_7f4a_7c15),
    );
    prng.random().bytes(nonce);
}

/// Map a failed CQE (`res` < 0) to an error.
fn check_completion(cqe: linux.io_uring_cqe) !void {
    if (cqe.res >= 0) return;
    switch (cqe.err()) {
        .CONNREFUSED => return error.ConnectionRefused,
        .TIMEDOUT => return error.Timeout,
        .NETUNREACH, .NETDOWN => return error.NetworkUnreachable,
        .HOSTUNREACH => return error.HostUnreachable,
        .CONNRESET, .PIPE => return error.ConnectionResetByPeer,
        .CANCELED => return error.Canceled,
        else => |errno| {
            log.err("io_uring op failed: {t}", .{errno});
            return error.Unexpected;
        },
    }
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

test "frame_in_place then parse_header round-trips a verack" {
    var buffer: [frame_buffer_len]u8 = undefined;
    const frame = frame_in_place(&buffer, mainnet_magic, "verack", 0);
    try std.testing.expectEqual(@as(usize, header_len), frame.len);

    const header = try parse_header(frame[0..header_len], mainnet_magic);
    try std.testing.expectEqual(@as(u32, 0), header.payload_len);
    try std.testing.expect(command_eql(&header.command, "verack"));
    try std.testing.expectEqualSlices(u8, &.{ 0x5d, 0xf6, 0xe0, 0xe2 }, &header.checksum);
}

test "parse_header rejects the wrong network magic" {
    var buffer: [frame_buffer_len]u8 = undefined;
    const frame = frame_in_place(&buffer, mainnet_magic, "verack", 0);
    try std.testing.expectError(
        error.MagicMismatch,
        parse_header(frame[0..header_len], testnet3_magic),
    );
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
