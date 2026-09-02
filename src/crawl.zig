//! Run many handshakes at once on one shared io_uring ring.
//!
//! `connect_all` keeps up to `slots.len` `Handshake`s in flight, stepping each
//! one off `IO` completions and starting a fresh dial into the slot as soon as
//! the last settles, until `target` succeed or the address list runs out. Every
//! SQE carries a pointer to a `Completion` as its `user_data`, so a CQE names
//! both the handshake (or the record log) and which op finished; a slot stays
//! alive until its outstanding completions drain, so nothing needs a synchronous
//! ring scrub between handshakes. As each handshake settles, `connect_all`
//! queues one `IORING_OP_WRITE` on the same ring appending that peer's one-line
//! record to `peer_log`, so the crawl loop never blocks on the log. Nothing is
//! allocated: the caller owns the slot pool and the `PeerLog` line buffers.

const std = @import("std");
const assert = std.debug.assert;

const linux = std.os.linux;
const net = std.Io.net;
const io_uring = @import("io.zig");
const handshake = @import("handshake.zig");
const version = @import("version.zig");
const Handshake = handshake.Handshake;
const DialError = handshake.DialError;
const log = std.log.scoped(.p2p);

pub const PeerLog = @import("peer_log.zig").PeerLog;

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

/// CQEs `connect_all` copies out of the ring per loop iteration.
const reap_batch = 32;

/// Smallest shared-ring SQ depth `connect_all` is safe to run on: every SQE it
/// can queue before the next submit. Per reaped CQE it may queue a new I/O op, a
/// cancel, a socket close, and a record write, so budget `4 * reap_batch`; the
/// pool's own timer/connect/cancel/close identities add `completion_count` per
/// slot; and a run in which every socket fails to open queues one record write
/// per address before the first submit, so budget `address_count` for those.
pub fn min_ring_entries(pool_slots: usize, address_count: usize) usize {
    return 4 * reap_batch + handshake.completion_count * pool_slots + address_count;
}

/// Handshake every address in `addresses`, keeping up to `slots.len` in flight
/// at once on the shared `io` ring, and stop starting new ones once `target`
/// have succeeded. Queues exactly one `peer_log` record write per dialed peer,
/// at the moment that peer's handshake settles, and drains those writes before
/// returning. `slots` and the `peer_log` buffers are caller-owned; nothing is
/// allocated.
pub fn connect_all(
    io: *io_uring.IO,
    peer_log: *PeerLog,
    addresses: []const net.IpAddress,
    slots: []Handshake,
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
    assert(options.user_agent.len <= version.max_user_agent_len);
    assert(options.timeout_ns > 0);

    for (slots) |*slot| slot.status = .idle;

    var progress: Progress = .{ .next = 0, .dialed = 0, .succeeded = 0 };
    for (slots) |*slot| fill_slot(io, peer_log, slot, addresses, &progress, target, options);

    var cqes: [reap_batch]linux.io_uring_cqe = undefined;
    while (any_busy(slots)) {
        const count = io.submit_and_reap(&cqes) catch |err| {
            log.err("io_uring reap failed: {t}; {d} handshake(s) abandoned", .{ err, busy_count(slots) });
            break;
        };
        for (cqes[0..count]) |cqe| {
            const completion: *handshake.Completion = @ptrFromInt(@as(usize, @intCast(cqe.user_data)));
            if (completion.kind == .log_write) {
                peer_log.on_write_complete(completion, cqe);
                continue;
            }

            const slot = completion.slot.?;
            slot.on_completion(completion.kind, cqe);
            if (slot.status != .settled) continue;

            peer_log.emit(slot.address, slot.outcome, &slot.peer);
            progress.dialed += 1;
            if (slot.outcome) |_| {
                progress.succeeded += 1;
            } else |_| {}
            slot.status = .idle;
            fill_slot(io, peer_log, slot, addresses, &progress, target, options);
        }
    }

    drain_peer_log(io, peer_log, &cqes);

    return .{
        .dialed = progress.dialed,
        .succeeded = progress.succeeded,
        .dropped = peer_log.dropped,
    };
}

/// Every handshake has settled; keep submitting until the last queued record
/// write has completed, so the caller may safely close the log file.
fn drain_peer_log(io: *io_uring.IO, peer_log: *PeerLog, cqes: []linux.io_uring_cqe) void {
    // Each pass reaps >= 1 CQE and only a short write re-adds one; the bound is
    // generous cover for that.
    const pass_max = 1024;
    var pass: u32 = 0;
    while (peer_log.in_flight > 0) {
        pass += 1;
        assert(pass <= pass_max);
        const count = io.submit_and_reap(cqes) catch |err| {
            log.err("peer-log drain failed: {t}; {d} write(s) abandoned", .{ err, peer_log.in_flight });
            return;
        };
        for (cqes[0..count]) |cqe| {
            const completion: *handshake.Completion = @ptrFromInt(@as(usize, @intCast(cqe.user_data)));
            assert(completion.kind == .log_write); // every slot settled before draining
            peer_log.on_write_complete(completion, cqe);
        }
    }
}

fn any_busy(slots: []const Handshake) bool {
    for (slots) |*slot| switch (slot.status) {
        .dialing, .winding, .closing => return true,
        .idle, .settled => {},
    };
    return false;
}

fn busy_count(slots: []const Handshake) u32 {
    var n: u32 = 0;
    for (slots) |*slot| switch (slot.status) {
        .dialing, .winding, .closing => n += 1,
        .idle, .settled => {},
    };
    return n;
}

/// Take addresses off the front of the queue until one handshake starts on
/// `slot`, or there is nothing left to dial (`target` reached or list
/// exhausted), leaving the slot `.idle`. A socket that will not open or start
/// gets its one `peer_log` record here and counts as dialed.
fn fill_slot(
    io: *io_uring.IO,
    peer_log: *PeerLog,
    slot: *Handshake,
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
        slot.start(io, fd, address, options) catch |err| {
            log.warn("start handshake with {f}: {t}", .{ address, err });
            io_uring.close_socket(fd); // no SQE armed yet: synchronous close
            peer_log.emit(address, error.SocketUnavailable, null);
            progress.dialed += 1;
            continue;
        };
        return;
    }
}
