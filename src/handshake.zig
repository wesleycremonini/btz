//! Bitcoin P2P version/verack handshake over TCP.
//!
//! `connect` opens a stream to a peer, sends a `version` message, exchanges
//! `verack`, and logs each step. It returns what the peer advertised in its
//! own `version`. Wire format follows the Bitcoin protocol message structure:
//! a 24-byte header (magic, 12-byte command, payload length, truncated
//! double-SHA256 checksum) followed by the payload.

const std = @import("std");
const net = std.Io.net;

const log = std.log.scoped(.p2p);

/// Network magic prefixing every message. Mainnet by default.
pub const mainnet_magic: u32 = 0xd9b4bef9;
pub const testnet3_magic: u32 = 0x0709110b;
pub const signet_magic: u32 = 0x40cf030a;

/// Reject any message claiming a payload larger than this. The protocol max is
/// 32 MiB; nothing exchanged during a handshake comes close.
const max_message_payload = 4 * 1024 * 1024;

pub const Options = struct {
    /// Protocol version to advertise (70016 = wtxid relay, BIP-339).
    protocol_version: i32 = 70016,
    /// Service bits to advertise. 0 = NODE_NONE (we serve nothing; we crawl).
    services: u64 = 0,
    /// User agent string (BIP-14).
    user_agent: []const u8 = "/btc-crawler:0.1.0/",
    /// Network magic.
    magic: u32 = mainnet_magic,
    /// Restrict a DNS name's resolved addresses to one family before dialing.
    /// Defaults to IPv4: `std.Io.Threaded` (0.16.0) has no connect timeout, so a
    /// black-holed IPv6 address would hang forever on a host without IPv6.
    /// Set to `null` to try both, or `.ip6` to force IPv6.
    address_family: ?net.IpAddress.Family = .ip4,
};

/// What the peer told us about itself in its `version` message.
pub const PeerInfo = struct {
    protocol_version: i32 = 0,
    services: u64 = 0,
    timestamp: i64 = 0,
    user_agent_buf: [256]u8 = undefined,
    user_agent_len: usize = 0,

    pub fn userAgent(self: *const PeerInfo) []const u8 {
        return self.user_agent_buf[0..self.user_agent_len];
    }
};

pub const HandshakeError = error{
    /// A message did not begin with the expected network magic.
    MagicMismatch,
    /// A message's checksum did not match its payload.
    ChecksumMismatch,
    /// Peer claimed a payload larger than `max_message_payload`.
    MessageTooLarge,
};

/// Connect to `host:port` and complete the version/verack handshake.
///
/// `host` may be a literal IPv4/IPv6 address or a DNS name; a name is resolved
/// via `io` and its addresses are dialed in order until one connects. `gpa`
/// backs transient per-message payload buffers, all freed before returning.
/// Returns what the peer advertised in its own `version`.
pub fn connect(
    io: std.Io,
    gpa: std.mem.Allocator,
    host: []const u8,
    port: u16,
    options: Options,
) !PeerInfo {
    log.info("connecting to {s}:{d}", .{ host, port });

    const stream = try dial(io, host, port, options.address_family);
    defer stream.close(io);
    log.info("tcp connected", .{});

    var read_buf: [8192]u8 = undefined;
    var write_buf: [4096]u8 = undefined;
    var stream_reader = stream.reader(io, &read_buf);
    var stream_writer = stream.writer(io, &write_buf);

    // Send our version.
    var version_buf: [512]u8 = undefined;
    const version_payload = try buildVersion(io, &version_buf, port, options);
    try writeMessage(&stream_writer, options.magic, "version", version_payload);
    log.info("-> version (protocol={d}, user_agent={s})", .{
        options.protocol_version, options.user_agent,
    });

    var peer: PeerInfo = .{};
    var got_version = false;
    var got_verack = false;

    while (!got_version or !got_verack) {
        const msg = try readMessage(gpa, &stream_reader, options.magic);
        defer gpa.free(msg.payload);

        if (commandEql(&msg.command, "version")) {
            peer = parseVersion(msg.payload);
            got_version = true;
            log.info("<- version (protocol={d}, services=0x{x}, user_agent={s})", .{
                peer.protocol_version, peer.services, peer.userAgent(),
            });
            try writeMessage(&stream_writer, options.magic, "verack", &.{});
            log.info("-> verack", .{});
        } else if (commandEql(&msg.command, "verack")) {
            got_verack = true;
            log.info("<- verack", .{});
        } else {
            log.debug("<- {s} ({d} bytes, ignored)", .{ commandName(&msg.command), msg.payload.len });
        }
    }

    log.info("handshake complete with {s}:{d}", .{ host, port });
    return peer;
}

/// Open a TCP stream to `host:port`. `host` is a literal IPv4/IPv6 address if it
/// parses as one, otherwise a DNS name: it is resolved via `io` and the
/// resulting addresses are tried in order until one connects.
///
/// No connect timeout: `std.Io.Threaded` in Zig 0.16.0 panics on a non-`.none`
/// `ConnectOptions.timeout`, and `HostName.connect`'s happy-eyeballs race can
/// hang on an unroutable address. Resolving here and dialing sequentially keeps
/// the failure modes predictable.
fn dial(io: std.Io, host: []const u8, port: u16, family: ?net.IpAddress.Family) !net.Stream {
    const opts: net.IpAddress.ConnectOptions = .{ .mode = .stream, .timeout = .none };

    if (net.IpAddress.parse(host, port)) |address| {
        return address.connect(io, opts);
    } else |_| {}

    const name = try net.HostName.init(host);
    var results_buf: [32]net.HostName.LookupResult = undefined;
    var results: std.Io.Queue(net.HostName.LookupResult) = .init(&results_buf);
    try name.lookup(io, &results, .{ .port = port, .family = family });

    var last_err: ?anyerror = null;
    var tried: usize = 0;
    while (results.getOneUncancelable(io)) |result| switch (result) {
        .canonical_name => {},
        .address => |address| {
            tried += 1;
            log.debug("dialing {f}", .{address});
            return address.connect(io, opts) catch |err| {
                last_err = err;
                continue;
            };
        },
    } else |_| {}

    if (tried == 0) return error.UnknownHostName;
    return last_err orelse error.ConnectionRefused;
}

const Message = struct {
    command: [12]u8,
    /// Owned by the caller's allocator.
    payload: []u8,
};

fn readMessage(
    gpa: std.mem.Allocator,
    sr: *net.Stream.Reader,
    magic: u32,
) !Message {
    const r = &sr.interface;

    const magic_read = r.takeInt(u32, .little) catch |e| return readErr(sr, e);
    if (magic_read != magic) return error.MagicMismatch;

    const command = (r.takeArray(12) catch |e| return readErr(sr, e)).*;
    const len = r.takeInt(u32, .little) catch |e| return readErr(sr, e);
    const checksum = (r.takeArray(4) catch |e| return readErr(sr, e)).*;

    if (len > max_message_payload) return error.MessageTooLarge;

    const payload = r.readAlloc(gpa, len) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return readErr(sr, e),
    };
    errdefer gpa.free(payload);

    if (!std.mem.eql(u8, &doubleSha256Prefix(payload), &checksum)) {
        return error.ChecksumMismatch;
    }
    return .{ .command = command, .payload = payload };
}

/// Translate the reader interface's opaque `ReadFailed` into the concrete
/// socket error the stream recorded, so callers get a useful message.
fn readErr(sr: *net.Stream.Reader, e: anyerror) anyerror {
    if (e == error.ReadFailed) if (sr.err) |concrete| return concrete;
    return e;
}

fn writeMessage(
    sw: *net.Stream.Writer,
    magic: u32,
    command: []const u8,
    payload: []const u8,
) !void {
    std.debug.assert(command.len <= 12);

    var header: [24]u8 = undefined;
    std.mem.writeInt(u32, header[0..4], magic, .little);
    @memset(header[4..16], 0);
    @memcpy(header[4..][0..command.len], command);
    std.mem.writeInt(u32, header[16..20], @intCast(payload.len), .little);
    @memcpy(header[20..24], &doubleSha256Prefix(payload));

    const w = &sw.interface;
    w.writeAll(&header) catch |e| return writeErr(sw, e);
    w.writeAll(payload) catch |e| return writeErr(sw, e);
    w.flush() catch |e| return writeErr(sw, e);
}

fn writeErr(sw: *net.Stream.Writer, e: anyerror) anyerror {
    if (e == error.WriteFailed) if (sw.err) |concrete| return concrete;
    return e;
}

/// Build a `version` payload into `buf` and return the written slice.
/// Fails with `error.WriteFailed` only if `buf` is too small for the user agent.
fn buildVersion(io: std.Io, buf: []u8, peer_port: u16, options: Options) ![]u8 {
    var w = std.Io.Writer.fixed(buf);
    const now_s: i64 = std.Io.Timestamp.now(io, .real).toSeconds();
    var nonce: [8]u8 = undefined;
    io.random(&nonce);

    try w.writeInt(i32, options.protocol_version, .little);
    try w.writeInt(u64, options.services, .little);
    try w.writeInt(i64, now_s, .little);

    // addr_recv: services (u64 LE) + 16-byte IP + port (u16 BE). Zeroed IP/port
    // is standard for the initial version message.
    try w.writeInt(u64, 0, .little);
    try w.splatByteAll(0, 16);
    try w.writeInt(u16, peer_port, .big);

    // addr_from: unroutable, all zero.
    try w.writeInt(u64, 0, .little);
    try w.splatByteAll(0, 16);
    try w.writeInt(u16, 0, .big);

    try w.writeAll(&nonce);

    try writeCompactSize(&w, options.user_agent.len);
    try w.writeAll(options.user_agent);

    try w.writeInt(i32, 0, .little); // start_height
    try w.writeByte(0); // relay (BIP-37)

    return w.buffered();
}

fn parseVersion(payload: []const u8) PeerInfo {
    var info: PeerInfo = .{};
    if (payload.len < 20) return info;

    info.protocol_version = std.mem.readInt(i32, payload[0..4], .little);
    info.services = std.mem.readInt(u64, payload[4..12], .little);
    info.timestamp = std.mem.readInt(i64, payload[12..20], .little);

    // version(4) services(8) timestamp(8) addr_recv(26) addr_from(26) nonce(8)
    var off: usize = 80;
    const ua_len = readCompactSize(payload, &off) orelse return info;
    if (off + ua_len > payload.len) return info;

    const n = @min(ua_len, info.user_agent_buf.len);
    @memcpy(info.user_agent_buf[0..n], payload[off..][0..n]);
    info.user_agent_len = n;
    return info;
}

fn writeCompactSize(w: *std.Io.Writer, n: u64) !void {
    if (n < 0xfd) {
        try w.writeByte(@intCast(n));
    } else if (n <= 0xffff) {
        try w.writeByte(0xfd);
        try w.writeInt(u16, @intCast(n), .little);
    } else if (n <= 0xffff_ffff) {
        try w.writeByte(0xfe);
        try w.writeInt(u32, @intCast(n), .little);
    } else {
        try w.writeByte(0xff);
        try w.writeInt(u64, n, .little);
    }
}

/// Returns the decoded value and advances `off.*` past it, or null if the
/// buffer is too short.
fn readCompactSize(buf: []const u8, off: *usize) ?u64 {
    if (off.* >= buf.len) return null;
    const first = buf[off.*];
    off.* += 1;
    switch (first) {
        0xfd => {
            if (off.* + 2 > buf.len) return null;
            defer off.* += 2;
            return std.mem.readInt(u16, buf[off.*..][0..2], .little);
        },
        0xfe => {
            if (off.* + 4 > buf.len) return null;
            defer off.* += 4;
            return std.mem.readInt(u32, buf[off.*..][0..4], .little);
        },
        0xff => {
            if (off.* + 8 > buf.len) return null;
            defer off.* += 8;
            return std.mem.readInt(u64, buf[off.*..][0..8], .little);
        },
        else => return first,
    }
}

fn doubleSha256Prefix(data: []const u8) [4]u8 {
    const Sha256 = std.crypto.hash.sha2.Sha256;
    var a: [Sha256.digest_length]u8 = undefined;
    Sha256.hash(data, &a, .{});
    var b: [Sha256.digest_length]u8 = undefined;
    Sha256.hash(&a, &b, .{});
    return b[0..4].*;
}

fn commandEql(cmd: *const [12]u8, name: []const u8) bool {
    if (name.len > 12) return false;
    if (!std.mem.eql(u8, cmd[0..name.len], name)) return false;
    for (cmd[name.len..]) |c| if (c != 0) return false;
    return true;
}

fn commandName(cmd: *const [12]u8) []const u8 {
    const end = std.mem.indexOfScalar(u8, cmd, 0) orelse cmd.len;
    return cmd[0..end];
}

test "compact size round trip" {
    const cases = [_]u64{ 0, 1, 0xfc, 0xfd, 0xffff, 0x1_0000, 0xffff_ffff, 0x1_0000_0000 };
    for (cases) |want| {
        var buf: [9]u8 = undefined;
        var w = std.Io.Writer.fixed(&buf);
        try writeCompactSize(&w, want);
        var off: usize = 0;
        const got = readCompactSize(w.buffered(), &off) orelse return error.Truncated;
        try std.testing.expectEqual(want, got);
        try std.testing.expectEqual(w.buffered().len, off);
    }
}

test "double sha256 checksum of empty payload" {
    // Well-known: checksum of an empty payload (e.g. verack) is 5df6e0e2.
    try std.testing.expectEqualSlices(u8, &.{ 0x5d, 0xf6, 0xe0, 0xe2 }, &doubleSha256Prefix(&.{}));
}

test "command matching" {
    var cmd = [_]u8{0} ** 12;
    @memcpy(cmd[0..7], "version");
    try std.testing.expect(commandEql(&cmd, "version"));
    try std.testing.expect(!commandEql(&cmd, "verack"));
    try std.testing.expectEqualStrings("version", commandName(&cmd));
}

test "parseVersion extracts fields" {
    var buf: [128]u8 = undefined;
    var w = std.Io.Writer.fixed(&buf);
    const ua = "/Satoshi:27.0.0/";

    try w.writeInt(i32, 70016, .little);
    try w.writeInt(u64, 0x409, .little); // services
    try w.writeInt(i64, 1_700_000_000, .little); // timestamp
    try w.splatByteAll(0, 26); // addr_recv
    try w.splatByteAll(0, 26); // addr_from
    try w.writeInt(u64, 0xdead_beef, .little); // nonce
    try w.writeByte(@intCast(ua.len));
    try w.writeAll(ua);
    try w.writeInt(i32, 850_000, .little); // start_height
    try w.writeByte(1); // relay

    const info = parseVersion(w.buffered());
    try std.testing.expectEqual(@as(i32, 70016), info.protocol_version);
    try std.testing.expectEqual(@as(u64, 0x409), info.services);
    try std.testing.expectEqual(@as(i64, 1_700_000_000), info.timestamp);
    try std.testing.expectEqualStrings(ua, info.userAgent());
}
