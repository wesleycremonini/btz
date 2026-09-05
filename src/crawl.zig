//! Crawl the network from a frontier of addresses, on one shared io_uring ring.
//!
//! `connect_all` keeps up to `slots.len` `Peer` conversations in flight, pulling
//! the next address from the `Frontier` as each slot frees and pushing every
//! address a settled peer disclosed in its `addr` reply back onto the frontier,
//! until `dial_max` dials have started or the frontier drains. A slot stays
//! alive until its outstanding completions drain, so nothing needs a
//! synchronous ring scrub between dials. As each dial settles, `connect_all`
//! queues one `IORING_OP_WRITE` on the same ring appending that peer's one-line
//! record to `peer_log`, and keeps ticking until every queued write has
//! drained. Nothing is allocated: the caller owns the slot pool, the frontier
//! buffers, and the `PeerLog` line buffers.

const std = @import("std");
const assert = std.debug.assert;

const net = std.Io.net;
const io_uring = @import("io.zig");
const session = @import("session.zig");
const version = @import("version.zig");
const Peer = session.Peer;
const PeerLog = @import("peer_log.zig").PeerLog;
const max_user_agent_len = @import("peer.zig").max_user_agent_len;
const log = std.log.scoped(.p2p);

pub const Frontier = @import("frontier.zig").Frontier;

/// Tally returned by `connect_all`. The per-peer detail is in the `PeerLog`.
pub const Summary = struct {
    /// Addresses actually dialed (a conversation started, or the socket failed).
    dialed: u32,
    /// Of those, how many completed the version/verack exchange.
    succeeded: u32,
    /// Addresses newly enqueued from peers' `addr` replies.
    discovered: u32,
    /// Record lines that could not be written (a write CQE failed).
    dropped: u32,
};

/// Mutable dialing progress shared between `connect_all` and `fill_slot`.
const Progress = struct {
    dialed: u32,
    succeeded: u32,
};

/// Upper bound on CQEs one dialed address can produce: a full conversation's
/// completions plus its record write(s). `connect_all`'s loop bound is built
/// from this so a stuck loop trips an assert rather than spinning forever.
const cqes_per_dial_max = 128;

/// Dial addresses from `frontier`, keeping up to `slots.len` conversations in
/// flight on the shared `io` ring, feeding each peer's disclosed addresses back
/// onto `frontier`. Stops starting new dials once any of: `dial_max` have
/// started, `ok_target` have succeeded (`0` = no success limit), or the
/// frontier is empty. Queues exactly one `peer_log` record per dialed peer as
/// it settles and drains those writes before returning. `slots`, `frontier`,
/// and the `peer_log` buffers are caller-owned; nothing is allocated.
pub fn connect_all(
    io: *io_uring.IO,
    peer_log: *PeerLog,
    frontier: *Frontier,
    slots: []Peer,
    dial_max: u32,
    ok_target: u32,
    options: version.Options,
) Summary {
    assert(slots.len >= 1);
    assert(dial_max >= 1);
    // The line pool is recycled, so it need only cover the writes in flight at
    // once — one per settling slot, plus headroom for those still draining.
    assert(peer_log.lines.len >= slots.len);
    assert(options.magic != 0);
    assert(options.user_agent.len > 0);
    assert(options.user_agent.len <= max_user_agent_len);
    assert(options.connect_timeout_ns > 0);
    assert(options.getaddr_timeout_ns > 0);

    for (slots) |*slot| slot.status = .idle;
    var progress: Progress = .{ .dialed = 0, .succeeded = 0 };
    const enqueued_seeds = frontier.enqueued;

    const iteration_max: u64 = cqes_per_dial_max * @as(u64, dial_max) + 64;
    var iteration: u64 = 0;
    while (true) {
        iteration += 1;
        assert(iteration <= iteration_max); // event loop: the bound must hold

        for (slots) |*slot| {
            if (slot.status == .settled) reap_slot(slot, peer_log, frontier, &progress);
            if (slot.status == .idle) {
                fill_slot(io, peer_log, slot, frontier, &progress, dial_max, ok_target, options);
            }
        }

        if (all_idle(slots) and io.in_flight == 0) break;

        io.tick(1) catch |err| {
            log.err("io_uring tick failed: {t}; abandoning {d} dial(s)", .{
                err, busy_count(slots),
            });
            break;
        };
    }

    return .{
        .dialed = progress.dialed,
        .succeeded = progress.succeeded,
        .discovered = frontier.enqueued - enqueued_seeds,
        .dropped = peer_log.dropped,
    };
}

/// A settled slot: write its record, push what it disclosed onto the frontier,
/// fold it into the tally, and free it.
fn reap_slot(slot: *Peer, peer_log: *PeerLog, frontier: *Frontier, progress: *Progress) void {
    assert(slot.status == .settled);
    const protocol = &slot.protocol;
    peer_log.emit(slot.address, slot.outcome, &protocol.peer_info, protocol.discovered_len);

    if (slot.outcome) |_| {
        progress.succeeded += 1;
        assert(protocol.discovered_len <= protocol.discovered.len);
        for (protocol.discovered[0..protocol.discovered_len]) |disclosed| {
            _ = frontier.push(disclosed);
        }
    } else |_| {}

    slot.status = .idle;
}

/// Pull addresses off the frontier until one conversation starts on `slot`, or
/// the frontier is empty or the dial budget is spent, leaving the slot `.idle`.
/// A socket that will not open or start gets its one `peer_log` record here and
/// counts as dialed.
fn fill_slot(
    io: *io_uring.IO,
    peer_log: *PeerLog,
    slot: *Peer,
    frontier: *Frontier,
    progress: *Progress,
    dial_max: u32,
    ok_target: u32,
    options: version.Options,
) void {
    assert(slot.status == .idle);
    while (progress.dialed < dial_max) {
        if (ok_target != 0 and progress.succeeded >= ok_target) return;
        const address = frontier.pop() orelse return;

        const fd = io_uring.open_socket(address) catch |err| {
            log.warn("open socket for {f}: {t}", .{ address, err });
            peer_log.emit(address, error.SocketUnavailable, null, 0);
            progress.dialed += 1;
            continue;
        };
        slot.start(io, fd, address, options) catch |err| {
            log.warn("start dial with {f}: {t}", .{ address, err });
            io_uring.close_socket(fd); // no SQE armed yet: synchronous close
            peer_log.emit(address, error.SocketUnavailable, null, 0);
            progress.dialed += 1;
            continue;
        };
        progress.dialed += 1;
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
