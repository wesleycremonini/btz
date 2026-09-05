//! Parse the Bitcoin `addr` message payload into IPv4 socket addresses.
//!
//! `addr`: a CompactSize count, then that many 30-byte entries — uint32 time,
//! uint64 services, 16-byte IP, uint16 port (big-endian). An IPv4 address
//! rides as an IPv4-mapped IPv6 address (`::ffff:a.b.c.d`); anything else is
//! skipped, since the dialer is IPv4-only. Pure: no I/O, no allocation.
//!
//! `addrv2` (BIP-155) is not parsed: we never send `sendaddrv2`, so a peer
//! replies to `getaddr` with legacy `addr`.

const std = @import("std");
const assert = std.debug.assert;

const net = std.Io.net;
const message = @import("message.zig");

/// `MAX_ADDR_TO_SEND` in Bitcoin Core: the most entries one `addr` carries.
pub const entries_max = 1000;

/// One entry: time(4) + services(8) + ip(16) + port(2).
const entry_len = 30;

/// Widest `addr` payload: the CompactSize for `entries_max` (a `0xfd`-prefixed
/// three-byte form) followed by that many entries.
pub const addr_payload_max = 3 + entries_max * entry_len;

comptime {
    assert(addr_payload_max <= message.message_payload_max);
}

/// Parse an `addr` payload, writing the IPv4 addresses it names into `out`.
/// Returns the count written (`<= out.len`). Best-effort: a count over
/// `entries_max` yields none, and a truncated tail yields the entries read so
/// far.
pub fn parse_addr(payload: []const u8, out: []net.IpAddress) u32 {
    assert(out.len >= 1);
    assert(out.len <= std.math.maxInt(u32));
    const out_len: u32 = @intCast(out.len);

    var offset: u32 = 0;
    const count = message.read_compact_size(payload, &offset) orelse return 0;
    if (count > entries_max) return 0;
    assert(offset <= payload.len);

    var written: u32 = 0;
    var index: u64 = 0;
    while (index < count) : (index += 1) {
        if (written == out_len) break;
        if (payload.len - offset < entry_len) break;

        const entry = payload[offset..][0..entry_len];
        offset += entry_len;

        const ipv4 = ipv4_of(entry[12..28]) orelse continue;
        const port = std.mem.readInt(u16, entry[28..30], .big);
        out[written] = .{ .ip4 = .{ .bytes = ipv4, .port = port } };
        written += 1;
    }

    assert(written <= out_len);
    return written;
}

/// The IPv4 address inside a 16-byte IPv4-mapped IPv6 address, else null.
fn ipv4_of(bytes: *const [16]u8) ?[4]u8 {
    const v4_mapped_prefix = [_]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff };
    if (!std.mem.eql(u8, bytes[0..12], &v4_mapped_prefix)) return null;
    return bytes[12..16].*;
}

const testing = std.testing;

/// Build one 30-byte `addr` entry into `out` with `ip` (16 bytes) and `port`.
fn write_entry(out: *[entry_len]u8, ip: [16]u8, port: u16) void {
    @memset(out[0..12], 0); // time + services, unused
    @memcpy(out[12..28], &ip);
    std.mem.writeInt(u16, out[28..30], port, .big);
}

fn v4_mapped(a: u8, b: u8, c: u8, d: u8) [16]u8 {
    return .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, a, b, c, d };
}

test "parse_addr: keeps IPv4-mapped entries and skips a native IPv6 one" {
    var payload: [1 + 3 * entry_len]u8 = undefined;
    payload[0] = 3; // CompactSize count
    write_entry(payload[1..][0..entry_len], v4_mapped(1, 2, 3, 4), 8333);
    write_entry(payload[1 + entry_len ..][0..entry_len], .{ 0x20, 0x01 } ++ .{0} ** 14, 8333);
    write_entry(payload[1 + 2 * entry_len ..][0..entry_len], v4_mapped(9, 9, 9, 9), 18333);

    var out: [8]net.IpAddress = undefined;
    const written = parse_addr(&payload, &out);
    try testing.expectEqual(@as(u32, 2), written);
    try testing.expectEqual(net.IpAddress{ .ip4 = .{ .bytes = .{ 1, 2, 3, 4 }, .port = 8333 } }, out[0]);
    try testing.expectEqual(net.IpAddress{ .ip4 = .{ .bytes = .{ 9, 9, 9, 9 }, .port = 18333 } }, out[1]);
}

test "parse_addr: stops when out is full" {
    var payload: [1 + 3 * entry_len]u8 = undefined;
    payload[0] = 3;
    for (0..3) |i| write_entry(payload[1 + i * entry_len ..][0..entry_len], v4_mapped(10, 0, 0, @intCast(i)), 8333);

    var out: [2]net.IpAddress = undefined;
    try testing.expectEqual(@as(u32, 2), parse_addr(&payload, &out));
}

test "parse_addr: rejects an over-large count" {
    var payload: [3]u8 = .{ 0xfd, 0xe9, 0x03 }; // CompactSize 1001
    var out: [4]net.IpAddress = undefined;
    try testing.expectEqual(@as(u32, 0), parse_addr(&payload, &out));
}

test "parse_addr: a truncated tail yields the entries already read" {
    var payload: [1 + entry_len + 5]u8 = undefined;
    payload[0] = 2; // claims two, only one entry's worth of bytes follows
    write_entry(payload[1..][0..entry_len], v4_mapped(7, 7, 7, 7), 8333);
    @memset(payload[1 + entry_len ..], 0);

    var out: [4]net.IpAddress = undefined;
    try testing.expectEqual(@as(u32, 1), parse_addr(&payload, &out));
}
