//! Bitcoin P2P version/verack handshake, driven by the io_uring event loop.
//!
//! `connect_all` runs many handshakes at once on one shared ring: each is a
//! `Handshake` slot whose state machine steps off `IO` completions — connect ->
//! send our `version` -> receive the peer's `version` (reply `verack`) and
//! `verack` -> done. Every SQE carries a pointer to one of the slot's
//! `Completion`s as its `user_data`, so a CQE names both the handshake and which
//! op finished; a slot stays alive until its outstanding completions drain, so
//! nothing needs a synchronous ring scrub between handshakes. Nothing is
//! allocated: the caller owns the slot pool and the `PeerLog` line buffers. As
//! each handshake settles, `connect_all` queues one `IORING_OP_WRITE` on the
//! same ring appending that peer's one-line record to the caller's log file, so
//! the crawl loop never blocks on the log.
//!
//! The wire format is a 24-byte header (magic, 12-byte command, payload length,
//! truncated double-SHA256 checksum) followed by the payload.

const std = @import("std");
const assert = std.debug.assert;

const linux = std.os.linux;
const net = std.Io.net;
const io_uring = @import("io.zig");
const log = std.log.scoped(.p2p);

/// Network magic prefixing every message on each network.
pub const mainnet_magic: u32 = 0xd9b4bef9;
pub const testnet3_magic: u32 = 0x0709110b;
pub const signet_magic: u32 = 0x40cf030a;

// Message-header layout, in bytes.
const magic_len = 4;
const command_len = 12;
const length_len = 4;
const checksum_len = 4;
const header_len = magic_len + command_len + length_len + checksum_len;
const magic_offset = 0;
const command_offset = magic_offset + magic_len;
const length_offset = command_offset + command_len;
const checksum_offset = length_offset + length_len;

/// Sanity bound on a message's length field. The protocol maximum is 32 MiB; a
/// handshake never approaches it.
const message_payload_max = 4 * 1024 * 1024;

/// `MAX_SUBVERSION_LENGTH` in Bitcoin Core.
const max_user_agent_len = 256;

/// Byte offset of the user-agent var_str within a `version` payload:
/// version(4) + services(8) + timestamp(8) + addr_recv(26) + addr_from(26) + nonce(8).
const version_prefix_len = 4 + 8 + 8 + 26 + 26 + 8;

/// Smallest and largest `version` payload we produce or accept.
const version_payload_min = version_prefix_len + 1 + 0 + 4 + 1;
const version_payload_max = version_prefix_len + 3 + max_user_agent_len + 4 + 1;

/// Receive buffer. Must hold the largest single message we parse (a `version`)
/// plus its header; other messages are consumed and dropped from the front.
const recv_buffer_len = 4 * 1024;

/// Send buffer: one framed message at a time (our `version` is the largest).
const frame_buffer_len = header_len + version_payload_max;

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
const completion_count = 4;

comptime {
    assert(header_len == 24);
    assert(command_offset == magic_len);
    assert(length_offset == magic_len + command_len);
    assert(checksum_offset == magic_len + command_len + length_len);
    assert(version_payload_min <= version_payload_max);
    assert(version_payload_max <= message_payload_max);
    assert(recv_buffer_len >= header_len + version_payload_max);
    assert(frame_buffer_len >= header_len + version_payload_max);
    assert(completion_count == 4);
}

pub const Options = struct {
    /// Protocol version to advertise (70016 = wtxid relay, BIP-339).
    protocol_version: i32 = 70016,
    /// Service bits to advertise. 0 = NODE_NONE: we serve nothing, we crawl.
    services: u64 = 0,
    /// User agent string (BIP-14).
    user_agent: []const u8 = "/btz:0.1.0/",
    /// Network magic.
    magic: u32 = mainnet_magic,
    /// Whole-handshake deadline in nanoseconds.
    timeout_ns: u63 = 10 * std.time.ns_per_s,
};

/// What the peer advertised in its own `version`. Filled in by the handshake.
pub const PeerInfo = struct {
    protocol_version: i32,
    services: u64,
    timestamp: i64,
    user_agent_len: u32,
    user_agent_buffer: [max_user_agent_len]u8,

    pub fn user_agent(peer: *const PeerInfo) []const u8 {
        assert(peer.user_agent_len <= peer.user_agent_buffer.len);
        return peer.user_agent_buffer[0..peer.user_agent_len];
    }
};

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

/// The IPv4 text form is the widest address we print: `255.255.255.255:65535`.
const ip_text_max = "255.255.255.255:65535".len;

/// Bytes one record line can occupy. The `ok` form is the widest: address, the
/// literal fields, and a user agent in which every byte escaped to `\xNN`.
const line_bytes_max =
    ip_text_max + "\tok\t".len + "-2147483648".len + "\t0x".len +
    "ffffffffffffffff".len + "\t".len + 4 * max_user_agent_len + "\n".len;

comptime {
    // The `fail` form must fit too: address, tag, the longest error name, `\n`.
    assert(line_bytes_max >= ip_text_max + "\tfail\t".len + "ConnectionResetByPeer".len + 1);
}

/// One-line-per-peer record file, written straight onto the shared ring so the
/// crawl loop never blocks on it. Each queued line keeps its own buffer and SQE
/// identity reserved until its write CQE drains; `connect_all` drains them all
/// before returning so the caller may close `fd`. Caller-owned, no allocation:
/// `lines` is backed by a caller array sized to the address count, so a free
/// slot is always available (no line is ever recycled).
pub const PeerLog = struct {
    io: *io_uring.IO,
    fd: linux.fd_t,
    lines: []Line,
    /// Absolute file offset the next queued line writes at. Advanced at submit
    /// time, so lines land in settle order though writes complete out of order.
    offset: u64,
    /// Lines handed out of `lines` so far.
    used: u32,
    /// Writes queued on the ring and not yet reaped.
    in_flight: u32,
    /// Lines a failed write CQE lost.
    dropped: u32,

    /// One framed record line: its rendered bytes and the SQE identity for its
    /// write. `written` tracks progress so a short write re-arms only the tail.
    pub const Line = struct {
        completion: Completion,
        offset: u64,
        len: u32,
        written: u32,
        buffer: [line_bytes_max]u8,
    };

    pub fn init(io: *io_uring.IO, fd: linux.fd_t, lines: []Line) PeerLog {
        assert(lines.len >= 1);
        return .{
            .io = io,
            .fd = fd,
            .lines = lines,
            .offset = 0,
            .used = 0,
            .in_flight = 0,
            .dropped = 0,
        };
    }

    /// Render the record for `address` into a fresh line and queue its write.
    /// `peer` is required for (and only read on) a successful `outcome`.
    fn emit(
        peer_log: *PeerLog,
        address: net.IpAddress,
        outcome: DialError!void,
        peer: ?*const PeerInfo,
    ) void {
        assert(peer_log.used < peer_log.lines.len);
        const line = &peer_log.lines[peer_log.used];
        peer_log.used += 1;

        var writer = std.Io.Writer.fixed(&line.buffer);
        format_peer_line(&writer, address, outcome, peer) catch |err| {
            // `buffer` is sized for the widest line; a failure here is a bug.
            log.err("render record for {f}: {t}", .{ address, err });
            peer_log.dropped += 1;
            return;
        };

        const rendered = writer.buffered();
        assert(rendered.len > 0);
        assert(rendered.len <= line_bytes_max);

        line.completion = .{ .owner = .{ .peer_log = peer_log }, .kind = .log_write };
        line.offset = peer_log.offset;
        line.len = @intCast(rendered.len);
        line.written = 0;
        peer_log.offset += line.len;

        // The ring is sized (`min_ring_entries`) so the SQ can never be full.
        peer_log.io.prep_write(
            user_data_of(&line.completion),
            peer_log.fd,
            line.buffer[0..line.len],
            line.offset,
        ) catch unreachable;
        peer_log.in_flight += 1;
    }

    /// One write CQE landed: advance the line, re-arming its tail on a short
    /// write and counting a failed write as a dropped line.
    fn on_write_complete(peer_log: *PeerLog, completion: *Completion, cqe: linux.io_uring_cqe) void {
        assert(peer_log.in_flight > 0);
        peer_log.in_flight -= 1;

        const line: *Line = @fieldParentPtr("completion", completion);
        assert(line.written < line.len);

        if (cqe.res <= 0) {
            log.err("record write at offset {d} failed: {t}", .{ line.offset, cqe.err() });
            peer_log.dropped += 1;
            return;
        }

        const wrote: u32 = @intCast(cqe.res);
        assert(wrote <= line.len - line.written);
        line.written += wrote;
        if (line.written == line.len) return;

        peer_log.io.prep_write(
            user_data_of(&line.completion),
            peer_log.fd,
            line.buffer[line.written..line.len],
            line.offset + line.written,
        ) catch unreachable;
        peer_log.in_flight += 1;
    }
};

fn user_data_of(completion: *const Completion) u64 {
    return @intCast(@intFromPtr(completion));
}

/// Render one record line to `writer`: `<addr>\tok\t<version>\t0x<services>\t<ua>`
/// or `<addr>\tfail\t<error>`, newline-terminated.
fn format_peer_line(
    writer: *std.Io.Writer,
    address: net.IpAddress,
    outcome: DialError!void,
    peer: ?*const PeerInfo,
) std.Io.Writer.Error!void {
    if (outcome) |_| {
        assert(peer != null);
        const info = peer.?;
        try writer.print("{f}\tok\t{d}\t0x{x}\t", .{ address, info.protocol_version, info.services });
        try write_escaped(writer, info.user_agent());
        try writer.writeByte('\n');
    } else |err| {
        try writer.print("{f}\tfail\t{s}\n", .{ address, @errorName(err) });
    }
}

/// Write `text` with every byte that is not printable ASCII (backslash included)
/// replaced by a `\xNN` escape. The user agent is peer-supplied and untrusted;
/// this keeps a hostile peer from injecting tabs, newlines, or control bytes
/// into the tab-separated record.
fn write_escaped(writer: *std.Io.Writer, text: []const u8) std.Io.Writer.Error!void {
    assert(text.len <= max_user_agent_len);
    for (text) |byte| {
        if (byte >= 0x20 and byte < 0x7f and byte != '\\') {
            try writer.writeByte(byte);
        } else {
            try writer.print("\\x{x:0>2}", .{byte});
        }
    }
}

/// CQEs `connect_all` copies out of the ring per loop iteration.
const reap_batch = 32;

/// Smallest shared-ring SQ depth `connect_all` is safe to run on: every SQE it
/// can queue before the next submit. Per reaped CQE it may queue a new I/O op, a
/// cancel, a socket close, and a record write, so budget `4 * reap_batch`; the
/// pool's own timer/connect/cancel/close identities add `completion_count` per
/// slot; and a run in which every socket fails to open queues one record write
/// per address before the first submit, so budget `address_count` for those.
pub fn min_ring_entries(pool_slots: usize, address_count: usize) usize {
    return 4 * reap_batch + completion_count * pool_slots + address_count;
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
    options: Options,
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
    for (slots) |*slot| fill_slot(io, peer_log, slot, addresses, &progress, target, options);

    var cqes: [reap_batch]linux.io_uring_cqe = undefined;
    while (any_busy(slots)) {
        const count = io.submit_and_reap(&cqes) catch |err| {
            log.err("io_uring reap failed: {t}; {d} handshake(s) abandoned", .{ err, busy_count(slots) });
            break;
        };
        for (cqes[0..count]) |cqe| {
            const completion: *Completion = @ptrFromInt(@as(usize, @intCast(cqe.user_data)));
            switch (completion.owner) {
                .peer_log => |sink| sink.on_write_complete(completion, cqe),
                .handshake => |slot| {
                    slot.on_completion(completion.kind, cqe);
                    if (slot.status != .settled) continue;

                    peer_log.emit(slot.address, slot.outcome, &slot.peer);
                    progress.dialed += 1;
                    if (slot.outcome) |_| {
                        progress.succeeded += 1;
                    } else |_| {}
                    slot.status = .idle;
                    fill_slot(io, peer_log, slot, addresses, &progress, target, options);
                },
            }
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
            const completion: *Completion = @ptrFromInt(@as(usize, @intCast(cqe.user_data)));
            switch (completion.owner) {
                .peer_log => |sink| sink.on_write_complete(completion, cqe),
                .handshake => unreachable, // every slot settled before draining
            }
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
    options: Options,
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

const Completion = struct {
    owner: Owner,
    kind: Kind,

    const Owner = union(enum) {
        handshake: *Handshake,
        peer_log: *PeerLog,
    };
    const Kind = enum { io, timeout, cancel, close, log_write };
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
    const Status = enum { idle, dialing, winding, closing, settled };
    const Phase = enum { connecting, sending, receiving, complete };
    const PumpResult = enum { awaiting_more, send_verack, complete };
    const ArmOp = enum { timeout, connect, send, recv };

    fn start(
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
                .{ .owner = .{ .handshake = slot }, .kind = .io },
                .{ .owner = .{ .handshake = slot }, .kind = .timeout },
                .{ .owner = .{ .handshake = slot }, .kind = .cancel },
                .{ .owner = .{ .handshake = slot }, .kind = .close },
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

    fn on_completion(slot: *Handshake, kind: Completion.Kind, cqe: linux.io_uring_cqe) void {
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
                const frame = frame_in_place(&slot.send_buffer, slot.options.magic, "verack", 0);
                assert(frame.len >= header_len);
                slot.send_frame = frame;
                slot.arm(.send);
                slot.phase = .sending;
                log.debug("-> verack", .{});
            },
        }
    }

    fn send_version(slot: *Handshake) DialError!void {
        const payload = build_version(
            slot.send_buffer[header_len..],
            slot.address,
            slot.options,
        );
        const frame = frame_in_place(
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

            const header = try parse_header(
                slot.recv_buffer[0..header_len],
                slot.options.magic,
            );
            const total = header_len + header.payload_len;
            if (total > recv_buffer_len) return error.MessageTooLarge;
            if (slot.recv_len < total) return .awaiting_more;

            const payload = slot.recv_buffer[header_len..total];
            var reply_with_verack = false;

            if (command_eql(&header.command, "version")) {
                if (header.payload_len > version_payload_max) return error.MessageTooLarge;
                if (!std.mem.eql(u8, &double_sha256_prefix(payload), &header.checksum)) {
                    return error.ChecksumMismatch;
                }
                try parse_version(&slot.peer, payload);
                slot.version_received = true;
                reply_with_verack = true;
                log.debug("<- version (protocol={d}, services=0x{x}, user_agent={s})", .{
                    slot.peer.protocol_version,
                    slot.peer.services,
                    slot.peer.user_agent(),
                });
            } else if (command_eql(&header.command, "verack")) {
                slot.verack_received = true;
                log.debug("<- verack", .{});
            } else {
                log.debug("<- {s} ({d} bytes, ignored)", .{
                    command_name(&header.command), header.payload_len,
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

const Header = struct {
    command: [command_len]u8,
    payload_len: u32,
    checksum: [checksum_len]u8,
};

const HeaderError = error{ MagicMismatch, MessageTooLarge };

/// Parse a 24-byte message header from `bytes`.
fn parse_header(bytes: *const [header_len]u8, magic: u32) HeaderError!Header {
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
fn frame_in_place(buffer: []u8, magic: u32, command: []const u8, payload_len: u32) []const u8 {
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

/// Serialize our `version` payload into `buffer` and return the written prefix.
/// `buffer` must hold at least `version_payload_max` bytes; the writes below
/// then cannot overflow, hence `catch unreachable`.
fn build_version(buffer: []u8, address: net.IpAddress, options: Options) []const u8 {
    assert(buffer.len >= version_payload_max);
    assert(options.user_agent.len > 0);
    assert(options.user_agent.len <= max_user_agent_len);

    var writer = std.Io.Writer.fixed(buffer);
    var nonce: [8]u8 = undefined;
    fill_nonce(&nonce);
    const peer_port = net.IpAddress.getPort(address);

    writer.writeInt(i32, options.protocol_version, .little) catch unreachable;
    writer.writeInt(u64, options.services, .little) catch unreachable;
    writer.writeInt(i64, unix_seconds(), .little) catch unreachable;

    // addr_recv: the peer. Services and IP zeroed (the peer ignores them here);
    // port is the one we dialed, in network byte order.
    writer.writeInt(u64, 0, .little) catch unreachable;
    writer.splatByteAll(0, 16) catch unreachable;
    writer.writeInt(u16, peer_port, .big) catch unreachable;

    // addr_from: our address. Unroutable, all zero.
    writer.writeInt(u64, 0, .little) catch unreachable;
    writer.splatByteAll(0, 16) catch unreachable;
    writer.writeInt(u16, 0, .big) catch unreachable;

    writer.writeAll(&nonce) catch unreachable;
    write_compact_size(&writer, options.user_agent.len) catch unreachable;
    writer.writeAll(options.user_agent) catch unreachable;
    writer.writeInt(i32, 0, .little) catch unreachable; // start_height
    writer.writeByte(0) catch unreachable; // relay (BIP-37)

    const payload = writer.buffered();
    assert(payload.len >= version_payload_min);
    assert(payload.len <= version_payload_max);
    return payload;
}

const ParseError = error{MalformedVersion};

/// Parse a `version` payload into `peer`. `peer` is fully overwritten.
fn parse_version(peer: *PeerInfo, payload: []const u8) ParseError!void {
    assert(payload.len <= version_payload_max);
    peer.* = std.mem.zeroes(PeerInfo);

    if (payload.len < version_prefix_len) return error.MalformedVersion;

    peer.protocol_version = std.mem.readInt(i32, payload[0..4], .little);
    peer.services = std.mem.readInt(u64, payload[4..12], .little);
    peer.timestamp = std.mem.readInt(i64, payload[12..20], .little);

    var offset: u32 = version_prefix_len;
    const claimed_len = read_compact_size(payload, &offset) orelse return error.MalformedVersion;
    if (claimed_len > max_user_agent_len) return error.MalformedVersion;
    if (offset + claimed_len > payload.len) return error.MalformedVersion;

    const copy_len: u32 = @intCast(@min(claimed_len, peer.user_agent_buffer.len));
    @memcpy(peer.user_agent_buffer[0..copy_len], payload[offset..][0..copy_len]);
    peer.user_agent_len = copy_len;

    assert(peer.user_agent_len <= peer.user_agent_buffer.len);
}

fn write_compact_size(writer: *std.Io.Writer, value: u64) std.Io.Writer.Error!void {
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
fn read_compact_size(buffer: []const u8, offset: *u32) ?u64 {
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
fn double_sha256_prefix(data: []const u8) [checksum_len]u8 {
    const Sha256 = std.crypto.hash.sha2.Sha256;
    comptime assert(Sha256.digest_length == 32);

    var round1: [Sha256.digest_length]u8 = undefined;
    Sha256.hash(data, &round1, .{});
    var round2: [Sha256.digest_length]u8 = undefined;
    Sha256.hash(&round1, &round2, .{});
    return round2[0..checksum_len].*;
}

/// True if `command` (NUL-padded to 12 bytes) names exactly `name`.
fn command_eql(command: *const [command_len]u8, name: []const u8) bool {
    assert(name.len > 0);
    if (name.len > command_len) return false;
    if (!std.mem.eql(u8, command[0..name.len], name)) return false;
    for (command[name.len..]) |byte| {
        if (byte != 0) return false;
    }
    return true;
}

/// `command` without its trailing NUL padding, for logging.
fn command_name(command: *const [command_len]u8) []const u8 {
    const end = std.mem.indexOfScalar(u8, command, 0) orelse command_len;
    assert(end <= command_len);
    return command[0..end];
}

fn unix_seconds() i64 {
    var now: linux.timespec = undefined;
    const rc = linux.clock_gettime(.REALTIME, &now);
    assert(linux.errno(rc) == .SUCCESS);
    return @intCast(now.sec);
}

fn fill_nonce(nonce: *[8]u8) void {
    const rc = linux.getrandom(nonce, nonce.len, 0);
    if (linux.errno(rc) == .SUCCESS and rc == nonce.len) return;

    // getrandom unavailable (old kernel or seccomp). The nonce only lets a node
    // notice a connection to itself, so a clock-seeded PRNG is sufficient.
    var seed: linux.timespec = undefined;
    _ = linux.clock_gettime(.REALTIME, &seed);
    var prng = std.Random.DefaultPrng.init(
        @as(u64, @bitCast(@as(i64, seed.sec))) ^
            (@as(u64, @bitCast(@as(i64, seed.nsec))) *% 0x9e37_79b9_7f4a_7c15),
    );
    prng.random().bytes(nonce);
}

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
    var buffer: [frame_buffer_len]u8 = undefined;
    const frame = frame_in_place(&buffer, mainnet_magic, "verack", 0);
    try std.testing.expectEqual(@as(usize, header_len), frame.len);

    const header = try parse_header(frame[0..header_len], mainnet_magic);
    try std.testing.expectEqual(@as(u32, 0), header.payload_len);
    try std.testing.expect(command_eql(&header.command, "verack"));
    try std.testing.expectEqualSlices(u8, &.{ 0x5d, 0xf6, 0xe0, 0xe2 }, &header.checksum);
}

test "parse_header rejects the wrong network magic" {
    var buffer: [frame_buffer_len]u8 = undefined;
    const frame = frame_in_place(&buffer, mainnet_magic, "verack", 0);
    try std.testing.expectError(
        error.MagicMismatch,
        parse_header(frame[0..header_len], testnet3_magic),
    );
}

test "parse_version: extracts fields from a well-formed payload" {
    var buffer: [version_payload_max]u8 = undefined;
    var writer = std.Io.Writer.fixed(&buffer);
    const ua = "/Satoshi:27.0.0/";

    try writer.writeInt(i32, 70016, .little);
    try writer.writeInt(u64, 0x409, .little);
    try writer.writeInt(i64, 1_700_000_000, .little);
    try writer.splatByteAll(0, 26); // addr_recv
    try writer.splatByteAll(0, 26); // addr_from
    try writer.writeInt(u64, 0xdead_beef, .little); // nonce
    try writer.writeByte(@intCast(ua.len));
    try writer.writeAll(ua);
    try writer.writeInt(i32, 850_000, .little); // start_height
    try writer.writeByte(1); // relay

    var peer: PeerInfo = undefined;
    try parse_version(&peer, writer.buffered());
    try std.testing.expectEqual(@as(i32, 70016), peer.protocol_version);
    try std.testing.expectEqual(@as(u64, 0x409), peer.services);
    try std.testing.expectEqual(@as(i64, 1_700_000_000), peer.timestamp);
    try std.testing.expectEqualStrings(ua, peer.user_agent());
}

test "parse_version: rejects a payload shorter than the fixed prefix" {
    var peer: PeerInfo = undefined;
    try std.testing.expectError(error.MalformedVersion, parse_version(&peer, &[_]u8{0} ** 40));
}

test "write_escaped: neutralises tab, newline, and backslash in a user agent" {
    var buffer: [64]u8 = undefined;
    var writer = std.Io.Writer.fixed(&buffer);
    try write_escaped(&writer, "/ok\t\n\\\x7f/");
    try std.testing.expectEqualStrings("/ok\\x09\\x0a\\x5c\\x7f/", writer.buffered());
}

test "format_peer_line: ok record is one escaped tab-separated line" {
    var peer: PeerInfo = std.mem.zeroes(PeerInfo);
    peer.protocol_version = 70016;
    peer.services = 0x409;
    const ua = "/Satoshi:27.0.0/\t/evil/";
    @memcpy(peer.user_agent_buffer[0..ua.len], ua);
    peer.user_agent_len = ua.len;

    var buffer: [line_bytes_max]u8 = undefined;
    var writer = std.Io.Writer.fixed(&buffer);
    const address: net.IpAddress = .{ .ip4 = .{ .bytes = .{ 1, 2, 3, 4 }, .port = 8333 } };
    try format_peer_line(&writer, address, {}, &peer);
    try std.testing.expectEqualStrings(
        "1.2.3.4:8333\tok\t70016\t0x409\t/Satoshi:27.0.0/\\x09/evil/\n",
        writer.buffered(),
    );
}

test "format_peer_line: failed dial records the error name" {
    var buffer: [line_bytes_max]u8 = undefined;
    var writer = std.Io.Writer.fixed(&buffer);
    const address: net.IpAddress = .{ .ip4 = .{ .bytes = .{ 10, 0, 0, 1 }, .port = 8333 } };
    try format_peer_line(&writer, address, error.ConnectionRefused, null);
    try std.testing.expectEqualStrings("10.0.0.1:8333\tfail\tConnectionRefused\n", writer.buffered());
}
