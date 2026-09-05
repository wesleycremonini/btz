//! Generic request/response transport over one io_uring-driven TCP socket.
//!
//! `Connection(Protocol)` owns a socket fd, five `io_uring.Completion`s, and a
//! single re-armable deadline. It runs `connect`, then hands the wire to
//! `Protocol` — a pure state machine that, fed received bytes and send /
//! deadline events, returns a `Directive` for what to do next. The
//! `idle -> dialing -> winding -> closing -> settled` lifecycle, the timer, and
//! the cancel / close wind-down live here; not one protocol byte is parsed here.
//!
//! The deadline is one `IORING_OP_TIMEOUT` re-armed in place (via
//! `timeout_update`) whenever `Protocol.deadline_ns` reports a new budget — so a
//! protocol can run a short connect deadline and then a longer one for a later
//! phase without a second timer.
//!
//! `Protocol` must provide (no I/O, no allocation):
//!
//!   pub const Options = ...;                                   // dial parameters
//!   fn reset(protocol: *Protocol, address: net.IpAddress, options: Options) void
//!   fn deadline_ns(protocol: *const Protocol) u63              // budget for the current phase
//!   fn connected(protocol: *Protocol) Directive                // TCP connect done
//!   fn recv_buffer(protocol: *Protocol) []u8                   // where to read (non-empty)
//!   fn on_recv(protocol: *Protocol, byte_count: u32) Directive // bytes appended
//!   fn on_send(protocol: *Protocol) Directive                  // current frame flushed
//!   fn on_deadline(protocol: *Protocol) Directive              // deadline fired
//!   fn outcome_for(protocol: *Protocol, err: DialError) DialError!void // classify a transport error
//!
//! Nothing is allocated: the caller owns the `Connection` slot, which must not
//! move while any of its completions is outstanding.

const std = @import("std");
const assert = std.debug.assert;

const linux = std.os.linux;
const net = std.Io.net;
const io_uring = @import("io.zig");
const DialError = @import("peer.zig").DialError;
const log = std.log.scoped(.p2p);

/// Upper bound on completions one conversation may process before it is failed:
/// connect + our sends + a handful of recvs + the peer's trailing messages fit
/// comfortably. Only a pathological peer reaches this before the deadline.
const steps_max = 64;

/// Indices into `completions`; each a distinct `user_data` so a CQE names which
/// SQE finished. `deadline_update` is the ack for an in-place timer re-arm;
/// `cancel` retires the surviving op when the conversation ends.
const completion_io = 0;
const completion_timeout = 1;
const completion_deadline_update = 2;
const completion_cancel = 3;
const completion_close = 4;
const completion_count = 5;

comptime {
    assert(completion_count == 5);
}

/// What the protocol wants the connection to do after an event.
pub const Directive = union(enum) {
    /// Read more peer bytes into `recv_buffer`.
    recv,
    /// Send `frame` (a slice into the protocol's own storage, stable until the
    /// send completes), then report back through `on_send`.
    send: []const u8,
    /// The conversation reached a usable end; wind down with success.
    done,
    /// Abort the conversation with this outcome.
    fail: DialError,
};

/// Slot lifecycle:
/// - `idle`    unused, ready for `start`
/// - `dialing` conversation running, outcome not yet known
/// - `winding` outcome decided; still draining the cancelled SQE(s)
/// - `closing` outcome final; the socket close is in flight on the ring
/// - `settled` `in_flight == 0`, `outcome` final, ready to recycle
pub const Status = enum { idle, dialing, winding, closing, settled };

pub fn Connection(comptime Protocol: type) type {
    return struct {
        const Self = @This();
        pub const Options = Protocol.Options;

        io: *io_uring.IO,
        fd: linux.fd_t,
        address: net.IpAddress,

        outcome: DialError!void,
        protocol: Protocol,

        /// One stable `io_uring.Completion` per SQE kind (see the `completion_*`
        /// indices). The slot must not move while any is outstanding.
        completions: [completion_count]io_uring.Completion,
        /// SQEs submitted for this slot and not yet reaped. The slot is done
        /// only once this reaches zero, so a cancelled timer keeps it alive
        /// until its `-ECANCELED` CQE is drained.
        in_flight: u32,
        /// Completions dispatched to this slot, bounded by `steps_max`.
        steps: u32,

        status: Status,
        phase: Phase,

        /// Stable storage the connect SQE points at.
        sockaddr: io_uring.SockAddr,
        /// The deadline currently armed on the timer, and the `kernel_timespec`
        /// the timeout / update SQEs point at. `refresh_deadline` re-arms when
        /// `Protocol.deadline_ns` returns something else.
        armed_deadline_ns: u63,
        deadline_spec: linux.kernel_timespec,
        /// The not-yet-sent tail of the current frame.
        send_frame: []const u8,

        /// I/O direction of the live op, distinct from `Status`.
        const Phase = enum { connecting, sending, receiving, done };
        /// Which of the slot's completions a callback is reporting.
        const Kind = enum { io, timeout, deadline_update, cancel, close };
        const ArmOp = enum { timeout, connect, send, recv };

        pub fn start(
            connection: *Self,
            io: *io_uring.IO,
            fd: linux.fd_t,
            address: net.IpAddress,
            options: Options,
        ) io_uring.SockAddr.FromError!void {
            assert(connection.status == .idle);

            const sockaddr = try io_uring.SockAddr.from(address);
            connection.* = .{
                .io = io,
                .fd = fd,
                .address = address,
                .outcome = {},
                .protocol = undefined,
                .completions = undefined,
                .in_flight = 0,
                .steps = 0,
                .status = .dialing,
                .phase = .connecting,
                .sockaddr = sockaddr,
                .armed_deadline_ns = 0,
                .deadline_spec = undefined,
                .send_frame = &.{},
            };
            connection.protocol.reset(address, options);
            connection.set_deadline(connection.protocol.deadline_ns());

            connection.arm(.timeout);
            connection.arm(.connect);
            assert(connection.in_flight == 2);
            log.debug("connecting to {f}", .{address});
        }

        /// Record `ns` as the armed budget and render it into `deadline_spec`.
        fn set_deadline(connection: *Self, ns: u63) void {
            assert(ns > 0);
            connection.armed_deadline_ns = ns;
            connection.deadline_spec = .{
                .sec = @intCast(ns / std.time.ns_per_s),
                .nsec = @intCast(ns % std.time.ns_per_s),
            };
        }

        /// Queue one SQE and count it against `in_flight`. The shared ring is
        /// sized so the SQ is not normally full; if it is, `IO` parks the
        /// completion and retries it on the next tick.
        fn arm(connection: *Self, comptime op: ArmOp) void {
            switch (op) {
                .timeout => connection.io.timeout(
                    &connection.completions[completion_timeout],
                    connection.deadline_spec,
                    connection,
                    on_timeout_completion,
                ),
                .connect => connection.io.connect(
                    &connection.completions[completion_io],
                    connection.fd,
                    connection.sockaddr,
                    connection,
                    on_io_completion,
                ),
                .send => connection.io.send(
                    &connection.completions[completion_io],
                    connection.fd,
                    connection.send_frame,
                    connection,
                    on_io_completion,
                ),
                .recv => connection.io.recv(
                    &connection.completions[completion_io],
                    connection.fd,
                    connection.protocol.recv_buffer(),
                    connection,
                    on_io_completion,
                ),
            }
            connection.in_flight += 1;
            // io op + timer, plus a `deadline_update` ack that may still be
            // draining from a phase change.
            assert(connection.in_flight <= 3);
        }

        /// If the protocol has moved to a phase with a different deadline
        /// budget, re-arm the timer in place. One extra CQE (the update ack).
        fn refresh_deadline(connection: *Self) void {
            assert(connection.status == .dialing);
            const want = connection.protocol.deadline_ns();
            if (want == connection.armed_deadline_ns) return;

            connection.set_deadline(want);
            connection.io.timeout_update(
                &connection.completions[completion_deadline_update],
                &connection.completions[completion_timeout],
                connection.deadline_spec,
                connection,
                on_deadline_update_completion,
            );
            connection.in_flight += 1;
            assert(connection.in_flight <= 3);
        }

        fn on_completion(connection: *Self, kind: Kind, result: i32) void {
            assert(connection.in_flight > 0);
            connection.in_flight -= 1;
            connection.steps += 1;

            switch (connection.status) {
                .idle, .settled => unreachable,
                .winding => {
                    // Outcome already decided; drain the cancelled SQE(s) and
                    // the deadline-update ack, then hand the socket close to the
                    // ring and wait on its CQE too.
                    if (connection.in_flight == 0) {
                        connection.io.close(
                            &connection.completions[completion_close],
                            connection.fd,
                            connection,
                            on_close_completion,
                        );
                        connection.in_flight = 1;
                        connection.status = .closing;
                    }
                },
                .closing => {
                    assert(kind == .close);
                    assert(connection.in_flight == 0);
                    connection.status = .settled;
                },
                .dialing => connection.step(kind, result),
            }
        }

        fn step(connection: *Self, kind: Kind, result: i32) void {
            assert(connection.status == .dialing);

            switch (kind) {
                .cancel => unreachable, // only armed once .winding
                .close => unreachable, // only armed once .closing
                .deadline_update => return, // the in-place timer re-arm's ack; nothing to do
                .timeout => return connection.apply(connection.protocol.on_deadline(), .timeout),
                .io => {},
            }

            // Only the I/O op can run away (a message flood); the timer and the
            // update ack fire at most once each.
            if (connection.steps > steps_max) {
                return connection.finish(connection.protocol.outcome_for(error.TooManyCompletions), .io);
            }

            const directive = connection.io_progress(result) catch |err| {
                return connection.finish(connection.protocol.outcome_for(err), .io);
            };
            if (directive) |next| connection.apply(next, .io);
            if (connection.status == .dialing) connection.refresh_deadline();
        }

        /// Advance the transport by one I/O completion. Returns the protocol's
        /// next directive, or null when the completion only continued a
        /// partially-sent frame.
        fn io_progress(connection: *Self, result: i32) DialError!?Directive {
            switch (connection.phase) {
                .connecting => {
                    try check_result(result);
                    assert(result == 0);
                    log.debug("tcp connected", .{});
                    return connection.protocol.connected();
                },
                .sending => {
                    try check_result(result);
                    const sent: u32 = @intCast(result);
                    assert(sent <= connection.send_frame.len);
                    connection.send_frame = connection.send_frame[sent..];
                    if (connection.send_frame.len > 0) {
                        connection.arm(.send); // rare short send: push the remainder
                        return null;
                    }
                    return connection.protocol.on_send();
                },
                .receiving => {
                    try check_result(result);
                    const received: u32 = @intCast(result);
                    if (received == 0) return error.EndOfStream;
                    return connection.protocol.on_recv(received);
                },
                .done => unreachable,
            }
        }

        fn apply(connection: *Self, directive: Directive, trigger: Kind) void {
            assert(connection.status == .dialing);
            switch (directive) {
                .recv => {
                    connection.arm(.recv);
                    connection.phase = .receiving;
                },
                .send => |frame| {
                    assert(frame.len > 0);
                    connection.send_frame = frame;
                    connection.arm(.send);
                    connection.phase = .sending;
                },
                .done => connection.finish({}, trigger),
                .fail => |err| connection.finish(err, trigger),
            }
        }

        /// Record the outcome, retire whichever SQE is still armed (the timer,
        /// unless we are finishing *because* it fired), and move to `.winding`
        /// until that retirement's CQEs drain. The event loop reaps them while
        /// other connections run.
        fn finish(connection: *Self, outcome: DialError!void, trigger: Kind) void {
            assert(connection.status == .dialing);
            assert(trigger == .io or trigger == .timeout);
            connection.outcome = outcome;
            connection.phase = .done;

            if (trigger == .timeout) {
                connection.io.cancel(
                    &connection.completions[completion_cancel],
                    &connection.completions[completion_io],
                    connection,
                    on_cancel_completion,
                );
            } else {
                connection.io.timeout_remove(
                    &connection.completions[completion_cancel],
                    &connection.completions[completion_timeout],
                    connection,
                    on_cancel_completion,
                );
            }
            connection.in_flight += 1; // the cancel / remove op's own CQE
            connection.status = .winding;
            assert(connection.in_flight >= 2); // that CQE, plus the still-armed target's
        }

        // --- `IO` callbacks. Each recovers the connection from `context` and
        //     reports which of its completions fired. ---

        fn on_io_completion(context: ?*anyopaque, completion: *io_uring.Completion, result: i32) void {
            _ = completion;
            assert(context != null);
            const connection: *Self = @ptrCast(@alignCast(context.?));
            connection.on_completion(.io, result);
        }
        fn on_timeout_completion(context: ?*anyopaque, completion: *io_uring.Completion, result: i32) void {
            _ = completion;
            assert(context != null);
            const connection: *Self = @ptrCast(@alignCast(context.?));
            connection.on_completion(.timeout, result);
        }
        fn on_deadline_update_completion(context: ?*anyopaque, completion: *io_uring.Completion, result: i32) void {
            _ = completion;
            assert(context != null);
            const connection: *Self = @ptrCast(@alignCast(context.?));
            connection.on_completion(.deadline_update, result);
        }
        fn on_cancel_completion(context: ?*anyopaque, completion: *io_uring.Completion, result: i32) void {
            _ = completion;
            assert(context != null);
            const connection: *Self = @ptrCast(@alignCast(context.?));
            connection.on_completion(.cancel, result);
        }
        fn on_close_completion(context: ?*anyopaque, completion: *io_uring.Completion, result: i32) void {
            _ = completion;
            assert(context != null);
            const connection: *Self = @ptrCast(@alignCast(context.?));
            connection.on_completion(.close, result);
        }
    };
}

/// Map a failed completion `result` (`result` < 0) to a transport error.
fn check_result(result: i32) DialError!void {
    if (result >= 0) return;
    switch (io_uring.errno_from(result)) {
        .CONNREFUSED => return error.ConnectionRefused,
        .TIMEDOUT => return error.ConnectTimeout,
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
