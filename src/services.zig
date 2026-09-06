//! Bitcoin P2P service flags — the bits a node sets in `version.services` to
//! advertise which parts of the protocol it will serve. Names and positions
//! from Bitcoin Core's `ServiceFlags`.

const std = @import("std");
const assert = std.debug.assert;

pub const Flag = struct {
    bit: u6,
    name: []const u8,
};

/// Recognised flags, in bit order. A node may also set bits outside this set
/// (experimental or vendor-specific); those fold into one "other bits" row.
pub const known = [_]Flag{
    .{ .bit = 0, .name = "NODE_NETWORK" },
    .{ .bit = 1, .name = "NODE_GETUTXO" },
    .{ .bit = 2, .name = "NODE_BLOOM" },
    .{ .bit = 3, .name = "NODE_WITNESS" },
    .{ .bit = 4, .name = "NODE_XTHIN" },
    .{ .bit = 6, .name = "NODE_COMPACT_FILTERS" },
    .{ .bit = 10, .name = "NODE_NETWORK_LIMITED" },
    .{ .bit = 11, .name = "NODE_P2P_V2" },
};

/// Row label for any set bit `known` does not name.
pub const other_label = "(other bits)";

/// Mask of every bit `known` covers.
pub const known_mask: u64 = mask: {
    var m: u64 = 0;
    for (known) |flag| m |= @as(u64, 1) << flag.bit;
    break :mask m;
};

comptime {
    assert(@popCount(known_mask) == known.len); // no duplicate bit positions
}

/// True if `services` sets any bit that `known` does not name.
pub fn has_other(services: u64) bool {
    return services & ~known_mask != 0;
}

/// True if `services` has the flag at `bit` set.
pub fn is_set(services: u64, bit: u6) bool {
    return services & (@as(u64, 1) << bit) != 0;
}

test "flag decoding" {
    const testing = std.testing;
    // 0xc09 = NODE_NETWORK | NODE_WITNESS | NODE_NETWORK_LIMITED | NODE_P2P_V2.
    try testing.expect(is_set(0xc09, 0));
    try testing.expect(is_set(0xc09, 3));
    try testing.expect(is_set(0xc09, 10));
    try testing.expect(is_set(0xc09, 11));
    try testing.expect(!is_set(0xc09, 2));
    try testing.expect(!has_other(0xc09));
    try testing.expect(has_other(0x8000c09)); // bit 27 is not named
}
