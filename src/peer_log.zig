//! One-line-per-peer record file, written straight onto the shared io_uring so
//! the crawl loop never blocks on it.
//!
//! `connect_all` hands `PeerLog` one dialed peer at a time as its dial settles;
//! `emit` renders the record into a free line buffer and queues its
//! `IORING_OP_WRITE`. A line stays reserved from `emit` until its write CQE
//! drains, then returns to a free list for the next record — so the caller
//! sizes `lines` to the peak in-flight write count (a few per concurrent dial),
//! not to the whole dial budget. Nothing is allocated.

const std = @import("std");
const assert = std.debug.assert;

const linux = std.os.linux;
const net = std.Io.net;
const io_uring = @import("io.zig");
const client = @import("client.zig");
const DialError = @import("peer.zig").DialError;
const PeerInfo = @import("peer.zig").PeerInfo;
const max_user_agent_len = @import("peer.zig").max_user_agent_len;
const log = std.log.scoped(.p2p);

/// The IPv4 text form is the widest address we print: `255.255.255.255:65535`.
const ip_text_max = "255.255.255.255:65535".len;

/// Bytes one record line can occupy. The `ok` form is the widest: address, the
/// literal fields, a user agent in which every byte escaped to `\xNN`, the
/// client label, and the trailing discovered-address count.
const line_bytes_max =
    ip_text_max + "\tok\t".len + "-2147483648".len + "\t0x".len +
    "ffffffffffffffff".len + "\t".len + 4 * max_user_agent_len +
    "\t".len + client.label_bytes_max +
    "\t".len + "4294967295".len + "\n".len;

comptime {
    // The `fail` form must fit too: address, tag, the longest error name, `\n`.
    assert(line_bytes_max >= ip_text_max + "\tfail\t".len + "ConnectionResetByPeer".len + 1);
}

/// Sentinel for "no line": the end of the free list, and an exhausted pool.
const no_line = std.math.maxInt(u32);

/// One framed record file. Caller-owned, no allocation: see the module comment.
pub const PeerLog = struct {
    io: *io_uring.IO,
    fd: linux.fd_t,
    lines: []Line,
    /// Absolute file offset the next queued line writes at. Advanced at submit
    /// time, so lines land in settle order though writes complete out of order.
    offset: u64,
    /// Head of the free-line list (`Line.next_free` links it), or `no_line`.
    free_head: u32,
    /// Writes queued on the ring and not yet reaped.
    in_flight: u32,
    /// Records lost: a render or write failure, or the line pool was exhausted.
    dropped: u32,

    /// One framed record line: its rendered bytes and the completion for its
    /// write. `written` tracks progress so a short write re-arms only the tail;
    /// `next_free` links it on `PeerLog.free_head` while idle.
    pub const Line = struct {
        completion: io_uring.Completion,
        index: u32,
        next_free: u32,
        offset: u64,
        len: u32,
        written: u32,
        buffer: [line_bytes_max]u8,
    };

    pub fn init(io: *io_uring.IO, fd: linux.fd_t, lines: []Line) PeerLog {
        assert(lines.len >= 1);
        assert(lines.len < no_line);
        for (lines, 0..) |*line, index| {
            line.index = @intCast(index);
            line.next_free = if (index + 1 < lines.len) @intCast(index + 1) else no_line;
        }
        return .{
            .io = io,
            .fd = fd,
            .lines = lines,
            .offset = 0,
            .free_head = 0,
            .in_flight = 0,
            .dropped = 0,
        };
    }

    /// Render the record for `address` into a free line and queue its write.
    /// `peer` and `discovered` are required for (and only read on) a successful
    /// `outcome`. A record is dropped if the line pool is momentarily empty.
    pub fn emit(
        peer_log: *PeerLog,
        address: net.IpAddress,
        outcome: DialError!void,
        peer: ?*const PeerInfo,
        discovered: u32,
    ) void {
        if (peer_log.free_head == no_line) {
            log.warn("record for {f} dropped: line pool exhausted", .{address});
            peer_log.dropped += 1;
            return;
        }
        const line = &peer_log.lines[peer_log.free_head];
        assert(line.index == peer_log.free_head);
        peer_log.free_head = line.next_free;
        line.next_free = no_line;

        var writer = std.Io.Writer.fixed(&line.buffer);
        format_peer_line(&writer, address, outcome, peer, discovered) catch |err| {
            // `buffer` is sized for the widest line; a failure here is a bug.
            log.err("render record for {f}: {t}", .{ address, err });
            peer_log.dropped += 1;
            peer_log.release(line);
            return;
        };

        const rendered = writer.buffered();
        assert(rendered.len > 0);
        assert(rendered.len <= line_bytes_max);

        line.offset = peer_log.offset;
        line.len = @intCast(rendered.len);
        line.written = 0;
        peer_log.offset += line.len;

        peer_log.io.write(
            &line.completion,
            peer_log.fd,
            line.buffer[0..line.len],
            line.offset,
            peer_log,
            on_write_completion,
        );
        peer_log.in_flight += 1;
    }

    /// One write CQE landed: return a fully-written line to the pool, re-arm the
    /// tail on a short write, or count a failed write as a dropped line.
    pub fn on_write_complete(peer_log: *PeerLog, completion: *io_uring.Completion, result: i32) void {
        assert(peer_log.in_flight > 0);
        peer_log.in_flight -= 1;

        const line: *Line = @fieldParentPtr("completion", completion);
        assert(line.written < line.len);
        assert(line.next_free == no_line);

        if (result <= 0) {
            if (result < 0) {
                log.err("record write at offset {d} failed: {t}", .{
                    line.offset, io_uring.errno_from(result),
                });
            } else {
                log.err("record write at offset {d} returned 0", .{line.offset});
            }
            peer_log.dropped += 1;
            peer_log.release(line);
            return;
        }

        const wrote: u32 = @intCast(result);
        assert(wrote <= line.len - line.written);
        line.written += wrote;
        if (line.written == line.len) {
            peer_log.release(line);
            return;
        }

        peer_log.io.write(
            &line.completion,
            peer_log.fd,
            line.buffer[line.written..line.len],
            line.offset + line.written,
            peer_log,
            on_write_completion,
        );
        peer_log.in_flight += 1;
    }

    /// Return `line` to the head of the free list.
    fn release(peer_log: *PeerLog, line: *Line) void {
        assert(line.next_free == no_line);
        assert(line.index < peer_log.lines.len);
        line.next_free = peer_log.free_head;
        peer_log.free_head = line.index;
    }
};

fn on_write_completion(context: ?*anyopaque, completion: *io_uring.Completion, result: i32) void {
    assert(context != null);
    const peer_log: *PeerLog = @ptrCast(@alignCast(context.?));
    peer_log.on_write_complete(completion, result);
}

/// Render one record line to `writer`, newline-terminated:
/// `<addr>\tok\t<version>\t0x<services>\t<ua>\t<client>\t<discovered>` on
/// success, or `<addr>\tfail\t<error>` otherwise.
fn format_peer_line(
    writer: *std.Io.Writer,
    address: net.IpAddress,
    outcome: DialError!void,
    peer: ?*const PeerInfo,
    discovered: u32,
) std.Io.Writer.Error!void {
    if (outcome) |_| {
        assert(peer != null);
        const info = peer.?;
        const user_agent = info.user_agent();
        try writer.print("{f}\tok\t{d}\t0x{x}\t", .{ address, info.protocol_version, info.services });
        try write_escaped(writer, user_agent);
        try writer.print("\t{s}\t{d}\n", .{ client.classify(user_agent).label(), discovered });
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
    try format_peer_line(&writer, address, {}, &peer, 42);
    try std.testing.expectEqualStrings(
        "1.2.3.4:8333\tok\t70016\t0x409\t/Satoshi:27.0.0/\\x09/evil/\tCore\t42\n",
        writer.buffered(),
    );
}

test "format_peer_line: failed dial records the error name" {
    var buffer: [line_bytes_max]u8 = undefined;
    var writer = std.Io.Writer.fixed(&buffer);
    const address: net.IpAddress = .{ .ip4 = .{ .bytes = .{ 10, 0, 0, 1 }, .port = 8333 } };
    try format_peer_line(&writer, address, error.ConnectionRefused, null, 0);
    try std.testing.expectEqualStrings("10.0.0.1:8333\tfail\tConnectionRefused\n", writer.buffered());
}
