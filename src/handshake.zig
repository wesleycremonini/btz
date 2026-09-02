//! One Bitcoin P2P version/verack handshake, driven by the io_uring event loop.
//!
//! A `Handshake` is a single slot whose state machine steps off `IO`
//! completions — connect -> send our `version` -> receive the peer's `version`
//! (reply `verack`) and `verack` -> done. Every SQE it queues carries a pointer
//! to one of the slot's `Completion`s as its `user_data`, so a CQE names both
//! the handshake and which op finished; a slot stays alive until its outstanding
//! completions drain. Nothing is allocated: the caller owns the slot.
//!
//! `connect_all` in `crawl.zig` runs many of these at once on one shared ring.
//! Message framing lives in `message.zig`; the `version` payload in `version.zig`.

const std = @import("std");
const assert = std.debug.assert;

const linux = std.os.linux;
const net = std.Io.net;
const io_uring = @import("io.zig");
const message = @import("message.zig");
const version = @import("version.zig");
const Options = version.Options;
const PeerInfo = version.PeerInfo;
const header_len = message.header_len;
const log = std.log.scoped(.p2p);

/// Receive buffer. Must hold the largest single message we parse (a `version`)
/// plus its header; other messages are consumed and dropped from the front.
const recv_buffer_len = 4 * 1024;

/// Send buffer: one framed message at a time (our `version` is the largest).
const frame_buffer_len = header_len + version.version_payload_max;

/// Upper bound on completions one handshake may process: connect + our version
/// send + a handful of recvs + our verack send + the peer's trailing messages
/// fit comfortably. Only a pathological peer reaches this before the deadline.
const completions_max = 64;

/// Per-handshake SQE identities. Each is a distinct `user_data` (a pointer into
/// `Handshake.completions`) so a CQE names both the handshake and which of its
/// SQEs completed: the in-flight I/O op, the deadline timer, the cancel/remove
/// op that retires whichever of those outlives the handshake, and the socket
/// close that runs once the outcome is final.
const completion_io = 0;
const completion_timeout = 1;
const completion_cancel = 2;
const completion_close = 3;

/// Per-slot `Completion` count. `crawl.min_ring_entries` budgets SQEs against it.
pub const completion_count = 4;

comptime {
    assert(recv_buffer_len >= header_len + version.version_payload_max);
    assert(frame_buffer_len >= header_len + version.version_payload_max);
    assert(completion_count == 4);
}

pub const DialError = error{
    /// A message did not begin with the expected network magic.
    MagicMismatch,
    /// The peer's `version` checksum did not match its payload.
    ChecksumMismatch,
    /// A length field, or a `version`, exceeded what we will buffer.
    MessageTooLarge,
    /// The peer's `version` payload was too short or internally inconsistent.
    MalformedVersion,
    /// The peer closed the connection mid-handshake.
    EndOfStream,
    /// The handshake did not finish within `Options.timeout_ns`.
    Timeout,
    /// `completions_max` completions passed without the handshake finishing.
    TooManyCompletions,
    /// The connect / send / recv SQE failed at the transport layer.
    ConnectionRefused,
    ConnectionResetByPeer,
    NetworkUnreachable,
    HostUnreachable,
    /// The kernel cancelled the operation.
    Canceled,
    /// The socket could not be created or started for this address.
    SocketUnavailable,
    /// The address was never dialed: `target` was reached, or the run ended.
    Skipped,
    /// An unclassified io_uring failure; see the log.
    Unexpected,
};

/// Per-SQE identity carried in `user_data`. A pointer to one of these names both
/// the issuer of the SQE and which of its ops finished. `slot` is the issuing
/// handshake; it is `null` for a `PeerLog` record write, which `connect_all`
/// routes by `kind` alone and never dereferences.
pub const Completion = struct {
    slot: ?*Handshake,
    kind: Kind,

    pub const Kind = enum { io, timeout, cancel, close, log_write };
};

pub const Handshake = struct {
    io: *io_uring.IO,
    fd: linux.fd_t,
    options: Options,
    address: net.IpAddress,

    outcome: DialError!void,
    peer: PeerInfo,

    /// One stable `user_data` identity per SQE kind, each pointing back here so
    /// a CQE names both the handshake and which SQE completed. The slot must not
    /// move while any completion is outstanding.
    completions: [completion_count]Completion,
    /// SQEs submitted for this slot and not yet reaped. The slot is done only
    /// once this reaches zero, so a cancelled deadline timer keeps the slot
    /// alive until its `-ECANCELED` CQE is drained.
    in_flight: u32,
    /// CQEs dispatched to this slot, bounded by `completions_max`.
    seen: u32,

    status: Status,
    phase: Phase,

    /// Stable storage the connect / timeout SQEs point at.
    sockaddr: io_uring.SockAddr,
    deadline: linux.kernel_timespec,

    send_buffer: [frame_buffer_len]u8,
    /// The not-yet-sent tail of the current frame (a slice into `send_buffer`).
    send_frame: []const u8,

    recv_buffer: [recv_buffer_len]u8,
    recv_len: u32,

    version_received: bool,
    verack_received: bool,

    /// Slot lifecycle, distinct from `Phase`:
    /// - `idle`    unused, ready for `fill_slot`
    /// - `dialing` handshake running, outcome not yet known
    /// - `winding` outcome decided; still draining the cancelled SQE(s)
    /// - `closing` outcome final; the socket close is in flight on the ring
    /// - `settled` `in_flight == 0`, `outcome` / `peer` final, ready to recycle
    pub const Status = enum { idle, dialing, winding, closing, settled };
    const Phase = enum { connecting, sending, receiving, complete };
    const PumpResult = enum { awaiting_more, send_verack, complete };
    const ArmOp = enum { timeout, connect, send, recv };

    pub fn start(
        slot: *Handshake,
        io: *io_uring.IO,
        fd: linux.fd_t,
        address: net.IpAddress,
        options: Options,
    ) io_uring.SockAddr.FromError!void {
        assert(slot.status == .idle);
        assert(options.magic != 0);

        const sockaddr = try io_uring.SockAddr.from(address);
        slot.* = .{
            .io = io,
            .fd = fd,
            .options = options,
            .address = address,
            .outcome = {},
            .peer = undefined,
            .completions = .{
                .{ .slot = slot, .kind = .io },
                .{ .slot = slot, .kind = .timeout },
                .{ .slot = slot, .kind = .cancel },
                .{ .slot = slot, .kind = .close },
            },
            .in_flight = 0,
            .seen = 0,
            .status = .dialing,
            .phase = .connecting,
            .sockaddr = sockaddr,
            .deadline = .{
                .sec = @intCast(options.timeout_ns / std.time.ns_per_s),
                .nsec = @intCast(options.timeout_ns % std.time.ns_per_s),
            },
            .send_buffer = undefined,
            .send_frame = &.{},
            .recv_buffer = undefined,
            .recv_len = 0,
            .version_received = false,
            .verack_received = false,
        };

        slot.arm(.timeout);
        slot.arm(.connect);
        log.debug("connecting to {f}", .{address});
    }

    /// Queue one SQE and count it against `in_flight`. The shared ring is sized
    /// (`min_ring_entries`) so the SQ can never be full here.
    fn arm(slot: *Handshake, comptime op: ArmOp) void {
        switch (op) {
            .timeout => slot.io.prep_timeout(slot.tag(completion_timeout), &slot.deadline) catch unreachable,
            .connect => slot.io.prep_connect(slot.tag(completion_io), slot.fd, &slot.sockaddr) catch unreachable,
            .send => slot.io.prep_send(slot.tag(completion_io), slot.fd, slot.send_frame) catch unreachable,
            .recv => slot.io.prep_recv(
                slot.tag(completion_io),
                slot.fd,
                slot.recv_buffer[slot.recv_len..],
            ) catch unreachable,
        }
        slot.in_flight += 1;
    }

    fn tag(slot: *Handshake, comptime index: usize) u64 {
        comptime assert(index < completion_count);
        return @intCast(@intFromPtr(&slot.completions[index]));
    }

    pub fn on_completion(slot: *Handshake, kind: Completion.Kind, cqe: linux.io_uring_cqe) void {
        assert(slot.in_flight > 0);
        slot.in_flight -= 1;
        slot.seen += 1;

        switch (slot.status) {
            .idle, .settled => unreachable,
            .winding => {
                // Outcome already decided; drain the cancelled SQE(s), then
                // hand the socket close to the ring and wait on its CQE too.
                if (slot.in_flight == 0) {
                    slot.io.prep_close(slot.tag(completion_close), slot.fd) catch unreachable;
                    slot.in_flight = 1;
                    slot.status = .closing;
                }
            },
            .closing => {
                assert(kind == .close);
                assert(slot.in_flight == 0);
                slot.status = .settled;
            },
            .dialing => slot.step(kind, cqe),
        }
    }

    /// Advance a running handshake by one completion.
    fn step(slot: *Handshake, kind: Completion.Kind, cqe: linux.io_uring_cqe) void {
        assert(slot.status == .dialing);

        if (slot.seen > completions_max) return slot.finish(error.TooManyCompletions, kind);
        switch (kind) {
            .cancel => unreachable, // only issued once status is .winding
            .close => unreachable, // only issued once status is .closing
            .log_write => unreachable, // owned by PeerLog, never a handshake
            .timeout => return slot.finish(error.Timeout, kind),
            .io => {},
        }

        slot.on_io(cqe) catch |err| return slot.finish(err, kind);
        if (slot.phase == .complete) {
            assert(slot.version_received and slot.verack_received);
            slot.finish({}, kind);
        }
    }

    /// Record the outcome, cancel whichever SQE this handshake still has armed
    /// (the timer, unless we are finishing *because* the timer fired), and move
    /// to `.winding` until that cancellation's CQEs drain. No synchronous reap:
    /// the event loop picks those CQEs up while other handshakes run.
    fn finish(slot: *Handshake, outcome: DialError!void, trigger: Completion.Kind) void {
        assert(slot.status == .dialing);
        slot.outcome = outcome;

        // Whichever SQE we did not just reap is still armed.
        if (trigger == .timeout) {
            slot.io.prep_cancel(slot.tag(completion_cancel), slot.tag(completion_io)) catch unreachable;
        } else {
            slot.io.prep_timeout_remove(slot.tag(completion_cancel), slot.tag(completion_timeout)) catch unreachable;
        }
        slot.in_flight += 1; // the cancel / remove op's own CQE
        slot.status = .winding;
        assert(slot.in_flight >= 2); // that CQE, plus the still-armed target's
    }

    fn on_io(slot: *Handshake, cqe: linux.io_uring_cqe) DialError!void {
        switch (slot.phase) {
            .connecting => {
                try check_completion(cqe);
                assert(cqe.res == 0);
                log.debug("tcp connected", .{});
                try slot.send_version();
            },
            .sending => {
                try check_completion(cqe);
                const sent: u32 = @intCast(cqe.res);
                assert(sent <= slot.send_frame.len);
                slot.send_frame = slot.send_frame[sent..];
                if (slot.send_frame.len > 0) {
                    slot.arm(.send); // rare short send: push the remainder
                    return;
                }
                try slot.advance();
            },
            .receiving => {
                try check_completion(cqe);
                const received: u32 = @intCast(cqe.res);
                if (received == 0) return error.EndOfStream;
                slot.recv_len += received;
                assert(slot.recv_len <= recv_buffer_len);
                try slot.advance();
            },
            .complete => unreachable,
        }
    }

    /// Process whatever whole messages are buffered, then arm the next SQE.
    fn advance(slot: *Handshake) DialError!void {
        switch (try slot.pump()) {
            .complete => slot.phase = .complete,
            .awaiting_more => {
                assert(slot.recv_len < recv_buffer_len);
                slot.arm(.recv);
                slot.phase = .receiving;
            },
            .send_verack => {
                const frame = message.frame_in_place(&slot.send_buffer, slot.options.magic, "verack", 0);
                assert(frame.len >= header_len);
                slot.send_frame = frame;
                slot.arm(.send);
                slot.phase = .sending;
                log.debug("-> verack", .{});
            },
        }
    }

    fn send_version(slot: *Handshake) DialError!void {
        const payload = version.build_version(
            slot.send_buffer[header_len..],
            slot.address,
            slot.options,
        );
        const frame = message.frame_in_place(
            &slot.send_buffer,
            slot.options.magic,
            "version",
            @intCast(payload.len),
        );
        assert(frame.len >= header_len);
        slot.send_frame = frame;
        slot.arm(.send);
        slot.phase = .sending;
        log.debug("-> version (protocol={d}, user_agent={s})", .{
            slot.options.protocol_version, slot.options.user_agent,
        });
    }

    fn pump(slot: *Handshake) !PumpResult {
        while (true) {
            if (slot.recv_len < header_len) return .awaiting_more;

            const header = try message.parse_header(
                slot.recv_buffer[0..header_len],
                slot.options.magic,
            );
            const total = header_len + header.payload_len;
            if (total > recv_buffer_len) return error.MessageTooLarge;
            if (slot.recv_len < total) return .awaiting_more;

            const payload = slot.recv_buffer[header_len..total];
            var reply_with_verack = false;

            if (message.command_eql(&header.command, "version")) {
                if (header.payload_len > version.version_payload_max) return error.MessageTooLarge;
                if (!std.mem.eql(u8, &message.double_sha256_prefix(payload), &header.checksum)) {
                    return error.ChecksumMismatch;
                }
                try version.parse_version(&slot.peer, payload);
                slot.version_received = true;
                reply_with_verack = true;
                log.debug("<- version (protocol={d}, services=0x{x}, user_agent={s})", .{
                    slot.peer.protocol_version,
                    slot.peer.services,
                    slot.peer.user_agent(),
                });
            } else if (message.command_eql(&header.command, "verack")) {
                slot.verack_received = true;
                log.debug("<- verack", .{});
            } else {
                log.debug("<- {s} ({d} bytes, ignored)", .{
                    message.command_name(&header.command), header.payload_len,
                });
            }

            // Drop the consumed message from the front of the buffer.
            const rest = slot.recv_len - total;
            std.mem.copyForwards(
                u8,
                slot.recv_buffer[0..rest],
                slot.recv_buffer[total..slot.recv_len],
            );
            slot.recv_len = rest;

            if (reply_with_verack) return .send_verack;
            if (slot.version_received and slot.verack_received) return .complete;
        }
    }
};

/// Map a failed CQE (`res` < 0) to an error.
fn check_completion(cqe: linux.io_uring_cqe) DialError!void {
    if (cqe.res >= 0) return;
    switch (cqe.err()) {
        .CONNREFUSED => return error.ConnectionRefused,
        .TIMEDOUT => return error.Timeout,
        .NETUNREACH, .NETDOWN => return error.NetworkUnreachable,
        .HOSTUNREACH => return error.HostUnreachable,
        .CONNRESET, .PIPE => return error.ConnectionResetByPeer,
        .CANCELED => return error.Canceled,
        else => |errno| {
            log.err("io_uring op failed: {t}", .{errno});
            return error.Unexpected;
        },
    }
}
