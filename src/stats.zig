//! In-memory crawl tallies and the end-of-run summary.
//!
//! `connect_all` calls `record` once per dial instead of writing a per-node
//! line; `write` emits the aggregate as one line of JSON — outcomes, client
//! software, advertised protocol versions and service flags, and discovery
//! totals. Each breakdown is a `{ "<value>": <count> }` object, most frequent
//! first; a `Tally` that filled past capacity adds an `"(other)"` key. Fixed
//! capacity, no allocation.

const std = @import("std");
const assert = std.debug.assert;

const DialError = @import("peer.zig").DialError;
const PeerInfo = @import("peer.zig").PeerInfo;
const client = @import("client.zig");
const services = @import("services.zig");

/// A small fixed-capacity frequency map. `Key` is `[]const u8` or an integer.
fn Tally(comptime Key: type, comptime capacity: u32) type {
    return struct {
        const Self = @This();
        const Entry = struct { key: Key, count: u32 };

        entries: [capacity]Entry = undefined,
        len: u32 = 0,
        /// Bumps that did not fit — the map was full with all-new keys.
        overflow: u32 = 0,

        fn bump(self: *Self, key: Key) void {
            for (self.entries[0..self.len]) |*entry| {
                if (key_eql(Key, entry.key, key)) {
                    entry.count += 1;
                    return;
                }
            }
            if (self.len == capacity) {
                self.overflow += 1;
                return;
            }
            self.entries[self.len] = .{ .key = key, .count = 1 };
            self.len += 1;
        }

        /// Emit `{"key":count,...}`, most frequent first. Integer keys are
        /// stringified (JSON object keys are always strings).
        fn write_json(self: *Self, writer: *std.Io.Writer) std.Io.Writer.Error!void {
            std.mem.sort(Entry, self.entries[0..self.len], {}, more_frequent);
            try writer.writeByte('{');
            var written: u32 = 0;
            for (self.entries[0..self.len]) |entry| {
                if (written > 0) try writer.writeByte(',');
                written += 1;
                switch (@typeInfo(Key)) {
                    .pointer => try write_json_string(writer, entry.key),
                    else => {
                        var buffer: [20]u8 = undefined;
                        const text = std.fmt.bufPrint(&buffer, "{d}", .{entry.key}) catch unreachable;
                        try write_json_string(writer, text);
                    },
                }
                try writer.print(":{d}", .{entry.count});
            }
            if (self.overflow > 0) {
                if (written > 0) try writer.writeByte(',');
                try write_json_string(writer, "(other)");
                try writer.print(":{d}", .{self.overflow});
            }
            try writer.writeByte('}');
        }

        fn more_frequent(_: void, a: Entry, b: Entry) bool {
            return a.count > b.count;
        }
    };
}

/// Write `text` as a JSON string literal, escaping what the grammar requires.
fn write_json_string(writer: *std.Io.Writer, text: []const u8) std.Io.Writer.Error!void {
    try writer.writeByte('"');
    for (text) |byte| {
        switch (byte) {
            '"' => try writer.writeAll("\\\""),
            '\\' => try writer.writeAll("\\\\"),
            0...0x1f => try writer.print("\\u{x:0>4}", .{byte}),
            else => try writer.writeByte(byte),
        }
    }
    try writer.writeByte('"');
}

fn key_eql(comptime Key: type, a: Key, b: Key) bool {
    return switch (@typeInfo(Key)) {
        .pointer => std.mem.eql(u8, a, b),
        else => a == b,
    };
}

pub const Stats = struct {
    /// Dial attempts (a conversation started, or the socket failed to open).
    dialed: u32 = 0,
    /// Attempts that completed the version/verack handshake.
    ok: u32 = 0,
    /// Unique addresses newly enqueued from `addr` replies; set by `connect_all`.
    discovered: u32 = 0,
    /// Total addresses disclosed across reachable peers.
    addresses_disclosed: u64 = 0,
    /// Reachable peers that shared at least one address.
    peers_sharing: u32 = 0,

    failures: Tally([]const u8, 24) = .{},
    clients: Tally([]const u8, 16) = .{},
    protocol_versions: Tally(i32, 24) = .{},
    /// One count per advertised service flag — a peer bumps every flag it sets.
    features: Tally([]const u8, services.known.len + 4) = .{},

    /// Fold one dial's outcome into the tallies. `peer` is read only on success.
    pub fn record(stats: *Stats, outcome: DialError!void, peer: ?*const PeerInfo, disclosed: u32) void {
        stats.dialed += 1;
        if (outcome) |_| {
            assert(peer != null);
            const info = peer.?;
            stats.ok += 1;
            stats.clients.bump(client.classify(info.user_agent()).label());
            stats.protocol_versions.bump(info.protocol_version);
            inline for (services.known) |flag| {
                if (services.is_set(info.services, flag.bit)) stats.features.bump(flag.name);
            }
            if (services.has_other(info.services)) stats.features.bump(services.other_label);
            stats.addresses_disclosed += disclosed;
            if (disclosed > 0) stats.peers_sharing += 1;
        } else |err| {
            stats.failures.bump(@errorName(err));
        }
    }

    /// Emit the whole summary as one line of JSON.
    pub fn write(stats: *Stats, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        const reachable_pct: f64 = if (stats.dialed == 0) 0 else 100 *
            @as(f64, @floatFromInt(stats.ok)) / @as(f64, @floatFromInt(stats.dialed));

        try writer.print(
            "{{\"dialed\":{d},\"reachable\":{d},\"reachable_pct\":{d:.1},\"failures\":",
            .{ stats.dialed, stats.ok, reachable_pct },
        );
        try stats.failures.write_json(writer);
        try writer.writeAll(",\"clients\":");
        try stats.clients.write_json(writer);
        try writer.writeAll(",\"protocol_versions\":");
        try stats.protocol_versions.write_json(writer);
        try writer.writeAll(",\"features\":");
        try stats.features.write_json(writer);
        try writer.print(
            ",\"discovery\":{{\"unique_addresses_found\":{d}," ++
                "\"addresses_disclosed\":{d},\"peers_sharing\":{d}}}",
            .{ stats.discovered, stats.addresses_disclosed, stats.peers_sharing },
        );
        try writer.writeAll("}\n");
    }
};

test "record and write: outcomes, clients, versions, discovery" {
    const testing = std.testing;
    var stats: Stats = .{};

    var core: PeerInfo = std.mem.zeroes(PeerInfo);
    core.protocol_version = 70016;
    core.services = 0x409;
    @memcpy(core.user_agent_buffer[0.."/Satoshi:27.0.0/".len], "/Satoshi:27.0.0/");
    core.user_agent_len = "/Satoshi:27.0.0/".len;

    stats.record({}, &core, 128);
    stats.record({}, &core, 0);
    stats.record(error.ConnectTimeout, null, 0);
    stats.record(error.ConnectTimeout, null, 0);
    stats.record(error.ConnectionRefused, null, 0);
    stats.discovered = 5;

    try testing.expectEqual(@as(u32, 5), stats.dialed);
    try testing.expectEqual(@as(u32, 2), stats.ok);
    try testing.expectEqual(@as(u64, 128), stats.addresses_disclosed);
    try testing.expectEqual(@as(u32, 1), stats.peers_sharing);

    var buffer: [4096]u8 = undefined;
    var writer = std.Io.Writer.fixed(&buffer);
    try stats.write(&writer);
    const text = writer.buffered();
    try testing.expect(text[0] == '{');
    try testing.expect(std.mem.endsWith(u8, text, "}\n"));
    try testing.expect(std.mem.indexOf(u8, text, "\"reachable\":2,\"reachable_pct\":40.0") != null);
    try testing.expect(std.mem.indexOf(u8, text, "\"failures\":{\"ConnectTimeout\":2,") != null);
    try testing.expect(std.mem.indexOf(u8, text, "\"clients\":{\"Core\":2}") != null);
    try testing.expect(std.mem.indexOf(u8, text, "\"protocol_versions\":{\"70016\":2}") != null);
    // 0x409 = NODE_NETWORK | NODE_WITNESS | NODE_NETWORK_LIMITED, on two peers.
    try testing.expect(std.mem.indexOf(u8, text, "\"NODE_WITNESS\":2") != null);
    try testing.expect(std.mem.indexOf(u8, text, "NODE_BLOOM") == null);
    try testing.expect(std.mem.indexOf(u8, text, "\"peers_sharing\":1}") != null);
}
