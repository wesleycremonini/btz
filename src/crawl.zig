//! Crawl the network from a frontier of addresses, on one shared io_uring ring.
//!
//! `connect_all` keeps up to `slots.len` `Peer` conversations in flight, pulling
//! the next address from the `Frontier` as each slot frees and pushing every
//! address a settled peer disclosed in its `addr` reply back onto the frontier,
//! until `dial_max` dials have started, `ok_target` succeed, or the frontier
//! drains. A slot stays alive until its outstanding completions drain, so
//! nothing needs a synchronous ring scrub between dials. Each dial's outcome is
//! folded into `Stats` — nothing is written per node. Nothing is allocated: the
//! caller owns the slot pool and the frontier buffers.

const std = @import("std");
const assert = std.debug.assert;

const io_uring = @import("io.zig");
const session = @import("session.zig");
const version = @import("version.zig");
const Peer = session.Peer;
const Stats = @import("stats.zig").Stats;
const max_user_agent_len = @import("peer.zig").max_user_agent_len;
const log = std.log.scoped(.p2p);

pub const Frontier = @import("frontier.zig").Frontier;

/// Dials started so far — throttles against `dial_max` while conversations are
/// still in flight (`Stats.dialed` only counts a dial once it settles).
const Progress = struct { dialed: u32 };

/// Upper bound on CQEs one dial can produce: a full conversation's completions.
/// `connect_all`'s loop bound is built from this so a stuck loop trips an assert
/// rather than spinning forever.
const cqes_per_dial_max = 128;

pub fn connect_all(
    io: *io_uring.IO,
    frontier: *Frontier,
    slots: []Peer,
    stats: *Stats,
    dial_max: u32,
    ok_target: u32,
    options: version.Options,
) void {
    assert(slots.len >= 1);
    assert(dial_max >= 1);
    assert(options.magic != 0);
    assert(options.user_agent.len > 0);
    assert(options.user_agent.len <= max_user_agent_len);
    assert(options.connect_timeout_ns > 0);
    assert(options.getaddr_timeout_ns > 0);

    for (slots) |*slot| slot.status = .idle;
    var progress: Progress = .{ .dialed = 0 };
    const enqueued_seeds = frontier.enqueued;

    const iteration_max: u64 = cqes_per_dial_max * @as(u64, dial_max) + 64;
    var iteration: u64 = 0;
    while (true) {
        iteration += 1;
        assert(iteration <= iteration_max); // event loop: the bound must hold

        for (slots) |*slot| {
            if (slot.status == .settled) reap_slot(slot, stats, frontier);
            if (slot.status == .idle) {
                fill_slot(io, slot, frontier, stats, &progress, dial_max, ok_target, options);
            }
        }

        if (all_idle(slots) and io.in_flight == 0) break;

        io.tick(1) catch |err| {
            log.err("io_uring tick failed: {t}; abandoning {d} dial(s)", .{ err, busy_count(slots) });
            break;
        };
    }

    stats.discovered = frontier.enqueued - enqueued_seeds;
}

/// A settled slot: fold its outcome into `stats`, push what it disclosed onto
/// the frontier, and free it.
fn reap_slot(slot: *Peer, stats: *Stats, frontier: *Frontier) void {
    assert(slot.status == .settled);
    const protocol = &slot.protocol;
    stats.record(slot.outcome, &protocol.peer_info, protocol.discovered_len);

    if (slot.outcome) |_| {
        assert(protocol.discovered_len <= protocol.discovered.len);
        for (protocol.discovered[0..protocol.discovered_len]) |disclosed| {
            _ = frontier.push(disclosed);
        }
    } else |_| {}

    slot.status = .idle;
}

/// Pull addresses off the frontier until one conversation starts on `slot`, or
/// the frontier is empty, the dial budget is spent, or `ok_target` is reached —
/// leaving the slot `.idle`. A socket that will not open or start is recorded
/// as a `SocketUnavailable` failure and still counts as dialed.
fn fill_slot(
    io: *io_uring.IO,
    slot: *Peer,
    frontier: *Frontier,
    stats: *Stats,
    progress: *Progress,
    dial_max: u32,
    ok_target: u32,
    options: version.Options,
) void {
    assert(slot.status == .idle);
    while (progress.dialed < dial_max) {
        if (ok_target != 0 and stats.ok >= ok_target) return;
        const address = frontier.pop() orelse return;
        progress.dialed += 1;

        const fd = io_uring.open_socket(address) catch |err| {
            log.warn("open socket for {f}: {t}", .{ address, err });
            stats.record(error.SocketUnavailable, null, 0);
            continue;
        };
        slot.start(io, fd, address, options) catch |err| {
            log.warn("start dial with {f}: {t}", .{ address, err });
            io_uring.close_socket(fd); // no SQE armed yet: synchronous close
            stats.record(error.SocketUnavailable, null, 0);
            continue;
        };
        return;
    }
}

fn all_idle(slots: []const Peer) bool {
    for (slots) |*slot| {
        if (slot.status != .idle) return false;
    }
    return true;
}

fn busy_count(slots: []const Peer) u32 {
    var count: u32 = 0;
    for (slots) |*slot| {
        switch (slot.status) {
            .dialing, .winding, .closing, .settled => count += 1,
            .idle => {},
        }
    }
    return count;
}
