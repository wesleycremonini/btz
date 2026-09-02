//! Bitcoin P2P message framing.
//!
//! Every message on the wire is a 24-byte header (network magic, 12-byte
//! NUL-padded command, payload length, truncated double-SHA256 checksum)
//! followed by the payload. This module parses and builds that header, and
//! carries the CompactSize integer codec and checksum helper the payloads need.
//! It performs no I/O and depends on nothing but `std`.

const std = @import("std");
const assert = std.debug.assert;

/// Network magic prefixing every message on each network.
pub const mainnet_magic: u32 = 0xd9b4bef9;
pub const testnet3_magic: u32 = 0x0709110b;
pub const signet_magic: u32 = 0x40cf030a;

// Message-header layout, in bytes.
pub const magic_len = 4;
pub const command_len = 12;
pub const length_len = 4;
pub const checksum_len = 4;
pub const header_len = magic_len + command_len + length_len + checksum_len;
pub const magic_offset = 0;
pub const command_offset = magic_offset + magic_len;
pub const length_offset = command_offset + command_len;
pub const checksum_offset = length_offset + length_len;

/// Sanity bound on a message's length field. The protocol maximum is 32 MiB; a
/// handshake never approaches it.
pub const message_payload_max = 4 * 1024 * 1024;

comptime {
    assert(header_len == 24);
    assert(command_offset == magic_len);
    assert(length_offset == magic_len + command_len);
    assert(checksum_offset == magic_len + command_len + length_len);
}

pub const Header = struct {
    command: [command_len]u8,
    payload_len: u32,
    checksum: [checksum_len]u8,
};

pub const HeaderError = error{ MagicMismatch, MessageTooLarge };

/// Parse a 24-byte message header from `bytes`.
pub fn parse_header(bytes: *const [header_len]u8, magic: u32) HeaderError!Header {
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
pub fn frame_in_place(buffer: []u8, magic: u32, command: []const u8, payload_len: u32) []const u8 {
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

pub fn write_compact_size(writer: *std.Io.Writer, value: u64) std.Io.Writer.Error!void {
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
pub fn read_compact_size(buffer: []const u8, offset: *u32) ?u64 {
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
pub fn double_sha256_prefix(data: []const u8) [checksum_len]u8 {
    const Sha256 = std.crypto.hash.sha2.Sha256;
    comptime assert(Sha256.digest_length == 32);

    var round1: [Sha256.digest_length]u8 = undefined;
    Sha256.hash(data, &round1, .{});
    var round2: [Sha256.digest_length]u8 = undefined;
    Sha256.hash(&round1, &round2, .{});
    return round2[0..checksum_len].*;
}

/// True if `command` (NUL-padded to 12 bytes) names exactly `name`.
pub fn command_eql(command: *const [command_len]u8, name: []const u8) bool {
    assert(name.len > 0);
    if (name.len > command_len) return false;
    if (!std.mem.eql(u8, command[0..name.len], name)) return false;
    for (command[name.len..]) |byte| {
        if (byte != 0) return false;
    }
    return true;
}

/// `command` without its trailing NUL padding, for logging.
pub fn command_name(command: *const [command_len]u8) []const u8 {
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

test "frame_in_place then parse_header round-trips a verack" {
    var buffer: [header_len]u8 = undefined;
    const frame = frame_in_place(&buffer, mainnet_magic, "verack", 0);
    try std.testing.expectEqual(@as(usize, header_len), frame.len);

    const header = try parse_header(frame[0..header_len], mainnet_magic);
    try std.testing.expectEqual(@as(u32, 0), header.payload_len);
    try std.testing.expect(command_eql(&header.command, "verack"));
    try std.testing.expectEqualSlices(u8, &.{ 0x5d, 0xf6, 0xe0, 0xe2 }, &header.checksum);
}

test "parse_header rejects the wrong network magic" {
    var buffer: [header_len]u8 = undefined;
    const frame = frame_in_place(&buffer, mainnet_magic, "verack", 0);
    try std.testing.expectError(
        error.MagicMismatch,
        parse_header(frame[0..header_len], testnet3_magic),
    );
}
