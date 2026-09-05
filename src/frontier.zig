//! The crawl's work queue: addresses still to dial, plus a set of every
//! address ever queued so a peer's `addr` reply never re-queues a node we
//! have already handled. Caller-owned, fixed-capacity, no allocation.

const std = @import("std");
const assert = std.debug.assert;
const net = std.Io.net;

pub const Frontier = struct {
    /// Ring of addresses waiting to be dialed.
    queue: []net.IpAddress,
    /// Open-addressing set of seen IPv4 addresses (the four bytes `@bitCast` to
    /// a `u32`); `0` marks an empty slot. Length must be a power of two.
    seen: []u32,
    head: u32,
    len: u32,
    /// Unique addresses ever enqueued (seeds included).
    enqueued: u32,
    /// Pushes refused because `queue` was full.
    dropped: u32,

    pub fn init(queue: []net.IpAddress, seen: []u32) Frontier {
        assert(queue.len >= 1);
        assert(queue.len <= std.math.maxInt(u32));
        assert(seen.len >= 2);
        assert(std.math.isPowerOfTwo(seen.len));
        for (seen) |slot| assert(slot == 0);
        return .{
            .queue = queue,
            .seen = seen,
            .head = 0,
            .len = 0,
            .enqueued = 0,
            .dropped = 0,
        };
    }

    /// Enqueue `address` unless it is not IPv4, is `0.0.0.0`, has been seen
    /// before, or `queue` is full. Returns true only when it was enqueued.
    pub fn push(frontier: *Frontier, address: net.IpAddress) bool {
        const key: u32 = switch (address) {
            .ip4 => |ip4_address| @bitCast(ip4_address.bytes),
            .ip6 => return false,
        };
        if (key == 0) return false;
        if (!frontier.mark_seen(key)) return false;

        if (frontier.len == frontier.queue.len) {
            frontier.dropped += 1;
            return false;
        }
        const capacity: u32 = @intCast(frontier.queue.len);
        const tail = (frontier.head + frontier.len) % capacity;
        frontier.queue[tail] = address;
        frontier.len += 1;
        frontier.enqueued += 1;
        return true;
    }

    /// Remove and return the oldest queued address, or null when the queue is
    /// empty. A popped address stays in the seen-set, so it is never re-queued.
    pub fn pop(frontier: *Frontier) ?net.IpAddress {
        if (frontier.len == 0) return null;
        const capacity: u32 = @intCast(frontier.queue.len);
        const address = frontier.queue[frontier.head];
        frontier.head = (frontier.head + 1) % capacity;
        frontier.len -= 1;
        return address;
    }

    /// Insert `key` into the seen-set by linear probing. Returns true if it was
    /// absent (and is now inserted), false if already present or the table is
    /// full (size `seen` for the dial budget so this does not happen).
    fn mark_seen(frontier: *Frontier, key: u32) bool {
        assert(key != 0);
        const mask: u32 = @intCast(frontier.seen.len - 1);
        var probe: u32 = key & mask;
        var step: u32 = 0;
        while (step <= mask) : (step += 1) {
            const slot = frontier.seen[probe];
            if (slot == 0) {
                frontier.seen[probe] = key;
                return true;
            }
            if (slot == key) return false;
            probe = (probe + 1) & mask;
        }
        return false;
    }
};

const testing = std.testing;

fn ip4(a: u8, b: u8, c: u8, d: u8) net.IpAddress {
    return .{ .ip4 = .{ .bytes = .{ a, b, c, d }, .port = 8333 } };
}

test "Frontier: dedups, keeps FIFO order, refuses IPv6" {
    var queue: [4]net.IpAddress = undefined;
    var seen: [8]u32 = @splat(0);
    var frontier = Frontier.init(&queue, &seen);

    try testing.expect(frontier.push(ip4(1, 1, 1, 1)));
    try testing.expect(frontier.push(ip4(2, 2, 2, 2)));
    try testing.expect(!frontier.push(ip4(1, 1, 1, 1))); // dup
    try testing.expect(!frontier.push(.{ .ip6 = .{ .bytes = @splat(0), .port = 8333 } }));
    try testing.expectEqual(@as(u32, 2), frontier.enqueued);

    try testing.expectEqual(ip4(1, 1, 1, 1), frontier.pop().?);
    try testing.expectEqual(ip4(2, 2, 2, 2), frontier.pop().?);
    try testing.expectEqual(@as(?net.IpAddress, null), frontier.pop());
    try testing.expect(!frontier.push(ip4(1, 1, 1, 1))); // still seen after pop
}

test "Frontier: refuses pushes past queue capacity" {
    var queue: [2]net.IpAddress = undefined;
    var seen: [16]u32 = @splat(0);
    var frontier = Frontier.init(&queue, &seen);

    try testing.expect(frontier.push(ip4(1, 0, 0, 1)));
    try testing.expect(frontier.push(ip4(1, 0, 0, 2)));
    try testing.expect(!frontier.push(ip4(1, 0, 0, 3)));
    try testing.expectEqual(@as(u32, 1), frontier.dropped);
}
