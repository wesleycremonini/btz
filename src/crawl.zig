//! Run many handshakes at once on one shared io_uring ring.
//!
//! `connect_all` keeps up to `slots.len` `Peer`s in flight, stepping each
//! one off `IO` callbacks and starting a fresh dial into the slot as soon as the
//! last settles, until `target` succeed or the address list runs out. A slot
//! stays alive until its outstanding completions drain, so nothing needs a
//! synchronous ring scrub between handshakes. As each handshake settles,
//! `connect_all` queues one `IORING_OP_WRITE` on the same ring appending that
//! peer's one-line record to `peer_log`, and keeps ticking until every queued
//! write has drained. Nothing is allocated: the caller owns the slot pool and
//! the `PeerLog` line buffers.

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

/// Tally returned by `connect_all`. The per-peer detail is in the `PeerLog`.
pub const Summary = struct {
    /// Addresses actually dialed (a handshake started, or the socket failed).
    dialed: u32,
    /// Of those, how many completed the version/verack exchange.
    succeeded: u32,
    /// Record lines that could not be written (a write CQE failed).
    dropped: u32,
};

/// Mutable dialing progress shared between `connect_all` and `fill_slot`.
const Progress = struct {
    /// Index of the next address to dial.
    next: u32,
    dialed: u32,
    succeeded: u32,
};

/// Upper bound on CQEs one dialed address can produce: a full handshake's
/// completions plus its record write(s). `connect_all`'s loop bound is built
/// from this so a stuck loop trips an assert rather than spinning forever.
const cqes_per_dial_max = 128;

/// Peer addresses from `addresses`, keeping up to `slots.len` in flight at
/// once on the shared `io` ring, and stop starting new ones once `target` have
/// succeeded. Queues exactly one `peer_log` record write per dialed peer, at the
/// moment that peer's handshake settles, and drains those writes before
/// returning. `slots` and the `peer_log` buffers are caller-owned; nothing is
/// allocated.
pub fn connect_all(
    io: *io_uring.IO,
    peer_log: *PeerLog,
    addresses: []const net.IpAddress,
    slots: []Peer,
    target: u32,
    options: version.Options,
) Summary {
    assert(addresses.len >= 1);
    assert(addresses.len <= std.math.maxInt(u32));
    assert(addresses.len <= peer_log.lines.len);
    assert(slots.len >= 1);
    assert(target >= 1);
    assert(options.magic != 0);
    assert(options.user_agent.len > 0);
    assert(options.user_agent.len <= max_user_agent_len);
    assert(options.timeout_ns > 0);

    for (slots) |*slot| slot.status = .idle;
    var progress: Progress = .{ .next = 0, .dialed = 0, .succeeded = 0 };

    const iteration_max: u64 = cqes_per_dial_max * @as(u64, addresses.len) + 64;
    var iteration: u64 = 0;
    while (true) {
        iteration += 1;
        assert(iteration <= iteration_max); // event loop: the bound must hold

        for (slots) |*slot| {
            if (slot.status == .settled) reap_slot(slot, peer_log, &progress);
            if (slot.status == .idle) {
                fill_slot(io, peer_log, slot, addresses, &progress, target, options);
            }
        }

        if (all_idle(slots) and io.in_flight == 0) break;

        io.tick(1) catch |err| {
            log.err("io_uring tick failed: {t}; abandoning {d} handshake(s)", .{
                err, busy_count(slots),
            });
            break;
        };
    }

    return .{
        .dialed = progress.dialed,
        .succeeded = progress.succeeded,
        .dropped = peer_log.dropped,
    };
}

/// A settled slot: write its record, fold it into the tally, and free it.
fn reap_slot(slot: *Peer, peer_log: *PeerLog, progress: *Progress) void {
    assert(slot.status == .settled);
    peer_log.emit(slot.address, slot.outcome, &slot.protocol.peer_info);
    progress.dialed += 1;
    if (slot.outcome) |_| {
        progress.succeeded += 1;
    } else |_| {}
    slot.status = .idle;
}

/// Take addresses off the front of the queue until one handshake starts on
/// `slot`, or there is nothing left to dial (`target` reached or list
/// exhausted), leaving the slot `.idle`. A socket that will not open or start
/// gets its one `peer_log` record here and counts as dialed.
fn fill_slot(
    io: *io_uring.IO,
    peer_log: *PeerLog,
    slot: *Peer,
    addresses: []const net.IpAddress,
    progress: *Progress,
    target: u32,
    options: version.Options,
) void {
    assert(slot.status == .idle);
    const address_count: u32 = @intCast(addresses.len);
    while (progress.succeeded < target and progress.next < address_count) {
        const address = addresses[progress.next];
        progress.next += 1;

        const fd = io_uring.open_socket(address) catch |err| {
            log.warn("open socket for {f}: {t}", .{ address, err });
            peer_log.emit(address, error.SocketUnavailable, null);
            progress.dialed += 1;
            continue;
        };
        slot.start(io, fd, address, options.timeout_ns, options) catch |err| {
            log.warn("start handshake with {f}: {t}", .{ address, err });
            io_uring.close_socket(fd); // no SQE armed yet: synchronous close
            peer_log.emit(address, error.SocketUnavailable, null);
            progress.dialed += 1;
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
