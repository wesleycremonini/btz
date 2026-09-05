//! The Bitcoin P2P `version` message: what we advertise and what we accept.
//!
//! `build_version` serializes our `version` payload; `parse_version` reads a
//! peer's back into a caller-owned `PeerInfo`. Both work through fixed buffers
//! and never allocate. Header framing lives in `message.zig`.

const std = @import("std");
const assert = std.debug.assert;

const linux = std.os.linux;
const net = std.Io.net;
const message = @import("message.zig");
const PeerInfo = @import("peer.zig").PeerInfo;
const max_user_agent_len = @import("peer.zig").max_user_agent_len;

/// Byte offset of the user-agent var_str within a `version` payload:
/// version(4) + services(8) + timestamp(8) + addr_recv(26) + addr_from(26) + nonce(8).
const version_prefix_len = 4 + 8 + 8 + 26 + 26 + 8;

/// Smallest and largest `version` payload we produce or accept.
pub const version_payload_min = version_prefix_len + 1 + 0 + 4 + 1;
pub const version_payload_max = version_prefix_len + 3 + max_user_agent_len + 4 + 1;

comptime {
    assert(version_payload_min <= version_payload_max);
    assert(version_payload_max <= message.message_payload_max);
}

/// Parameters for one dial. Named for the `version` message it mostly shapes,
/// but also carries the transport deadline and one crawl knob, since this is
/// the struct threaded to every conversation.
pub const Options = struct {
    /// Protocol version to advertise (70016 = wtxid relay, BIP-339).
    protocol_version: i32 = 70016,
    /// Service bits to advertise. 0 = NODE_NONE: we serve nothing, we crawl.
    services: u64 = 0,
    /// User agent string (BIP-14).
    user_agent: []const u8 = "/btz:0.1.0/",
    /// Network magic.
    magic: u32 = message.mainnet_magic,
    /// Whole-conversation deadline in nanoseconds. Connect and handshake take
    /// well under a second on a reachable node, but Bitcoin Core answers
    /// `getaddr` on a delayed relay timer, so the window must be wide enough to
    /// catch that reply. A dead host still costs the full deadline — high
    /// `concurrency` is what keeps those from stalling the crawl.
    timeout_ns: u63 = 10 * std.time.ns_per_s,
    /// `addr` entries older than this many seconds are dropped rather than
    /// dialed. Bitcoin Core keeps an address ~30 days and only re-times it on
    /// reconnect, so the cutoff must be lenient.
    addr_max_age_s: u32 = 10 * 24 * 60 * 60,
};

/// Serialize our `version` payload into `buffer` and return the written prefix.
/// `buffer` must hold at least `version_payload_max` bytes; the writes below
/// then cannot overflow, hence `catch unreachable`.
pub fn build_version(buffer: []u8, address: net.IpAddress, options: Options) []const u8 {
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
    message.write_compact_size(&writer, options.user_agent.len) catch unreachable;
    writer.writeAll(options.user_agent) catch unreachable;
    writer.writeInt(i32, 0, .little) catch unreachable; // start_height
    writer.writeByte(0) catch unreachable; // relay (BIP-37)

    const payload = writer.buffered();
    assert(payload.len >= version_payload_min);
    assert(payload.len <= version_payload_max);
    return payload;
}

pub const ParseError = error{MalformedVersion};

/// Parse a `version` payload into `peer`. `peer` is fully overwritten.
pub fn parse_version(peer: *PeerInfo, payload: []const u8) ParseError!void {
    assert(payload.len <= version_payload_max);
    peer.* = std.mem.zeroes(PeerInfo);

    if (payload.len < version_prefix_len) return error.MalformedVersion;

    peer.protocol_version = std.mem.readInt(i32, payload[0..4], .little);
    peer.services = std.mem.readInt(u64, payload[4..12], .little);
    peer.timestamp = std.mem.readInt(i64, payload[12..20], .little);

    var offset: u32 = version_prefix_len;
    const claimed_len = message.read_compact_size(payload, &offset) orelse return error.MalformedVersion;
    if (claimed_len > max_user_agent_len) return error.MalformedVersion;
    if (offset + claimed_len > payload.len) return error.MalformedVersion;

    const copy_len: u32 = @intCast(@min(claimed_len, peer.user_agent_buffer.len));
    @memcpy(peer.user_agent_buffer[0..copy_len], payload[offset..][0..copy_len]);
    peer.user_agent_len = copy_len;

    assert(peer.user_agent_len <= peer.user_agent_buffer.len);
}

/// Wall-clock seconds since the Unix epoch. `std.time` in 0.16 has no
/// timestamp helper, so read the clock directly.
pub fn unix_seconds() i64 {
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
