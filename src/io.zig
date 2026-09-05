//! Single-threaded io_uring event loop with callback dispatch.
//!
//! Every request is a caller-owned `Completion`: an `Operation` naming the
//! syscall, a `context` pointer, and a `callback` the loop runs with the raw
//! result once the CQE lands. There are no threads and no `std.Io`
//! implementation; concurrency is many completions in flight on one ring, not
//! parallelism.
//!
//! Submitting a completion queues one SQE, or parks the completion on the
//! intrusive `unqueued` list when the submission queue is full. `tick` flushes
//! that list, submits, waits for completions, then runs each ready callback. A
//! completion, and every buffer or address it refers to, must stay put and
//! valid from submission until its callback runs; `connect` and `timeout` copy
//! their kernel arguments inline so the completion is self-contained.

const std = @import("std");
const builtin = @import("builtin");
const assert = std.debug.assert;

const linux = std.os.linux;
const posix = std.posix;
const net = std.Io.net;

comptime {
    if (builtin.os.tag != .linux) @compileError("the io_uring backend is Linux-only");
}

/// CQEs `tick` copies out of the ring at once: enough to amortise the syscall
/// without a large stack frame. `tick` loops when the ring holds more.
const cqe_batch = 64;

/// Run by `tick` when a completion's CQE is reaped. `result` is the raw
/// io_uring result: `>= 0` on success (often a byte count), else the negated
/// errno, which `errno_from` turns back into a `linux.E`.
pub const Callback = *const fn (context: ?*anyopaque, completion: *Completion, result: i32) void;

/// The syscall a `Completion` performs. Buffers are borrowed and must outlive
/// the completion; `connect` and `timeout` hold their arguments by value.
pub const Operation = union(enum) {
    connect: struct { socket: posix.socket_t, address: SockAddr },
    send: struct { socket: posix.socket_t, buffer: []const u8 },
    recv: struct { socket: posix.socket_t, buffer: []u8 },
    write: struct { fd: posix.fd_t, buffer: []const u8, offset: u64 },
    close: struct { fd: posix.fd_t },
    /// Relative one-shot timer; its CQE result is `-ETIME` when it fires.
    timeout: struct { deadline: linux.kernel_timespec },
    /// Retire a pending `timeout`, named by its completion's address.
    timeout_remove: struct { target: u64 },
    /// Retire any other pending operation, named by its completion's address.
    cancel: struct { target: u64 },
};

/// One queued or in-flight request. Caller-owned; immovable from submission
/// until `callback` runs.
pub const Completion = struct {
    operation: Operation,
    context: ?*anyopaque,
    callback: Callback,
    /// Intrusive `IO.unqueued` link; `null` unless the completion is parked.
    next: ?*Completion,
};

/// A `sockaddr` rendered from a resolved `net.IpAddress`, held by value inside
/// the `connect` operation so its bytes stay put while the SQE points at them.
/// IPv4 only for now: `from` and `open_socket` reject IPv6.
pub const SockAddr = struct {
    bytes: [bytes_max]u8 align(4),
    len: posix.socklen_t,

    const bytes_max = @sizeOf(linux.sockaddr.in6);

    pub const FromError = error{Ipv6Unsupported};

    comptime {
        assert(bytes_max >= @sizeOf(linux.sockaddr.in));
        assert(@alignOf(linux.sockaddr.in) <= 4);
    }

    pub fn from(address: net.IpAddress) FromError!SockAddr {
        var result: SockAddr = .{ .bytes = @splat(0), .len = 0 };
        switch (address) {
            .ip4 => |ip4| {
                const sockaddr: *linux.sockaddr.in = @ptrCast(&result.bytes);
                sockaddr.* = .{
                    .port = std.mem.nativeToBig(u16, ip4.port),
                    .addr = @bitCast(ip4.bytes),
                };
                result.len = @sizeOf(linux.sockaddr.in);
            },
            .ip6 => return error.Ipv6Unsupported,
        }
        assert(result.len > 0);
        assert(result.len <= bytes_max);
        return result;
    }

    pub fn ptr(sock_addr: *const SockAddr) *const linux.sockaddr {
        assert(sock_addr.len > 0);
        assert(sock_addr.len <= bytes_max);
        return @ptrCast(&sock_addr.bytes);
    }
};

/// Failures surfaced by `tick`: the `io_uring_enter` error set minus
/// `SignalInterrupt`, which `tick` retries internally. Named rather than
/// inferred so a `std` change shows up here at compile time.
pub const TickError = error{
    SystemResources,
    FileDescriptorInvalid,
    FileDescriptorInBadState,
    CompletionQueueOvercommitted,
    SubmissionQueueEntryInvalid,
    BufferInvalid,
    RingShuttingDown,
    OpcodeNotSupported,
    InvalidThread,
    Unexpected,
};

pub const IO = struct {
    ring: linux.IoUring,
    /// FIFO of completions still waiting for an SQE (the submission queue was
    /// full), linked through `Completion.next`. `tick` drains it head-first.
    unqueued_head: ?*Completion,
    unqueued_tail: ?*Completion,
    /// Completions submitted and not yet handed to their callback, parked ones
    /// included. The event loop runs while this is non-zero.
    in_flight: u32,

    /// `entries` is the SQ depth and must be a power of two, else the kernel
    /// rounds it up and this accounting drifts. `flags` reaches `io_uring_setup`
    /// verbatim; pass `0` for a plain interrupt-driven ring.
    pub fn init(entries: u16, flags: u32) !IO {
        assert(entries > 0);
        assert(std.math.isPowerOfTwo(entries));
        return .{
            .ring = try linux.IoUring.init(entries, flags),
            .unqueued_head = null,
            .unqueued_tail = null,
            .in_flight = 0,
        };
    }

    pub fn deinit(io: *IO) void {
        io.ring.deinit();
    }

    // --- Submission. Each call queues (or parks) one SQE; nothing reaches the
    //     kernel until the next `tick`, which then runs `callback`. ---

    pub fn connect(
        io: *IO,
        completion: *Completion,
        socket: posix.socket_t,
        address: SockAddr,
        context: ?*anyopaque,
        callback: Callback,
    ) void {
        assert(socket >= 0);
        assert(address.len > 0);
        const operation: Operation = .{ .connect = .{ .socket = socket, .address = address } };
        io.submit(completion, operation, context, callback);
    }

    pub fn send(
        io: *IO,
        completion: *Completion,
        socket: posix.socket_t,
        buffer: []const u8,
        context: ?*anyopaque,
        callback: Callback,
    ) void {
        assert(socket >= 0);
        assert(buffer.len > 0);
        const operation: Operation = .{ .send = .{ .socket = socket, .buffer = buffer } };
        io.submit(completion, operation, context, callback);
    }

    pub fn recv(
        io: *IO,
        completion: *Completion,
        socket: posix.socket_t,
        buffer: []u8,
        context: ?*anyopaque,
        callback: Callback,
    ) void {
        assert(socket >= 0);
        assert(buffer.len > 0);
        const operation: Operation = .{ .recv = .{ .socket = socket, .buffer = buffer } };
        io.submit(completion, operation, context, callback);
    }

    pub fn write(
        io: *IO,
        completion: *Completion,
        fd: posix.fd_t,
        buffer: []const u8,
        offset: u64,
        context: ?*anyopaque,
        callback: Callback,
    ) void {
        assert(fd >= 0);
        assert(buffer.len > 0);
        const operation: Operation = .{ .write = .{ .fd = fd, .buffer = buffer, .offset = offset } };
        io.submit(completion, operation, context, callback);
    }

    pub fn close(
        io: *IO,
        completion: *Completion,
        fd: posix.fd_t,
        context: ?*anyopaque,
        callback: Callback,
    ) void {
        assert(fd >= 0);
        const operation: Operation = .{ .close = .{ .fd = fd } };
        io.submit(completion, operation, context, callback);
    }

    pub fn timeout(
        io: *IO,
        completion: *Completion,
        deadline: linux.kernel_timespec,
        context: ?*anyopaque,
        callback: Callback,
    ) void {
        assert(deadline.sec >= 0);
        assert(deadline.nsec >= 0);
        const operation: Operation = .{ .timeout = .{ .deadline = deadline } };
        io.submit(completion, operation, context, callback);
    }

    pub fn timeout_remove(
        io: *IO,
        completion: *Completion,
        target: *const Completion,
        context: ?*anyopaque,
        callback: Callback,
    ) void {
        assert(target != completion);
        const operation: Operation = .{ .timeout_remove = .{ .target = @intFromPtr(target) } };
        io.submit(completion, operation, context, callback);
    }

    pub fn cancel(
        io: *IO,
        completion: *Completion,
        target: *const Completion,
        context: ?*anyopaque,
        callback: Callback,
    ) void {
        assert(target != completion);
        const operation: Operation = .{ .cancel = .{ .target = @intFromPtr(target) } };
        io.submit(completion, operation, context, callback);
    }

    fn submit(
        io: *IO,
        completion: *Completion,
        operation: Operation,
        context: ?*anyopaque,
        callback: Callback,
    ) void {
        completion.* = .{
            .operation = operation,
            .context = context,
            .callback = callback,
            .next = null,
        };
        io.in_flight += 1;
        const sqe = io.ring.get_sqe() catch |err| switch (err) {
            error.SubmissionQueueFull => return io.unqueued_append(completion),
        };
        prep(completion, sqe);
    }

    /// Submit every queued SQE, block until at least `wait_count` completions
    /// are ready (`0` polls without blocking), then run each ready callback. A
    /// callback may submit further completions; those wait for the next `tick`.
    pub fn tick(io: *IO, wait_count: u32) TickError!void {
        io.unqueued_flush();

        while (true) {
            _ = io.ring.submit_and_wait(wait_count) catch |err| switch (err) {
                error.SignalInterrupt => continue,
                else => |other| return other,
            };
            break;
        }

        var cqes: [cqe_batch]linux.io_uring_cqe = undefined;
        while (true) {
            const reaped = io.ring.copy_cqes(&cqes, 0) catch |err| switch (err) {
                error.SignalInterrupt => continue,
                else => |other| return other,
            };
            assert(reaped <= cqes.len);
            for (cqes[0..reaped]) |cqe| {
                assert(io.in_flight > 0);
                io.in_flight -= 1;
                const completion: *Completion = @ptrFromInt(cqe.user_data);
                completion.callback(completion.context, completion, cqe.res);
            }
            if (reaped < cqes.len) break;
        }
    }

    /// Move parked completions into the SQ, oldest first, until it is full or
    /// the list is empty.
    fn unqueued_flush(io: *IO) void {
        while (io.unqueued_head) |completion| {
            const sqe = io.ring.get_sqe() catch |err| switch (err) {
                error.SubmissionQueueFull => break,
            };
            io.unqueued_head = completion.next;
            if (io.unqueued_head == null) io.unqueued_tail = null;
            completion.next = null;
            prep(completion, sqe);
        }
    }

    fn unqueued_append(io: *IO, completion: *Completion) void {
        assert(completion.next == null);
        if (io.unqueued_tail) |tail| {
            assert(io.unqueued_head != null);
            tail.next = completion;
        } else {
            assert(io.unqueued_head == null);
            io.unqueued_head = completion;
        }
        io.unqueued_tail = completion;
    }
};

/// Fill `sqe` from `completion.operation` and stamp the completion's address as
/// `user_data` so `tick` can route the CQE back. `connect` and `timeout` need a
/// pointer capture so the SQE points into the (stable) completion, not a copy.
fn prep(completion: *Completion, sqe: *linux.io_uring_sqe) void {
    switch (completion.operation) {
        .connect => |*operation| sqe.prep_connect(
            operation.socket,
            operation.address.ptr(),
            operation.address.len,
        ),
        .send => |operation| sqe.prep_send(operation.socket, operation.buffer, posix.MSG.NOSIGNAL),
        .recv => |operation| sqe.prep_recv(operation.socket, operation.buffer, posix.MSG.NOSIGNAL),
        .write => |operation| sqe.prep_write(operation.fd, operation.buffer, operation.offset),
        .close => |operation| sqe.prep_close(operation.fd),
        .timeout => |*operation| sqe.prep_timeout(&operation.deadline, 0, 0),
        .timeout_remove => |operation| sqe.prep_timeout_remove(operation.target, 0),
        .cancel => |operation| sqe.prep_cancel(operation.target, 0),
    }
    sqe.user_data = @intFromPtr(completion);
}

/// Recover the `linux.E` behind a failed completion `result`. Mirrors
/// `io_uring_cqe.err`: only meaningful when `result` is a negated errno.
pub fn errno_from(result: i32) linux.E {
    assert(result < 0);
    assert(result > -4096);
    return @enumFromInt(-result);
}

pub const OpenSocketError = error{
    SystemFdQuotaExceeded,
    AccessDenied,
    Unexpected,
};

/// Create a blocking TCP socket for `address`'s family; io_uring drives it
/// asynchronously regardless of the socket's blocking mode. Teardown is
/// `IO.close` on the ring — `close_socket` is only the synchronous fallback for
/// a socket abandoned before any SQE armed.
pub fn open_socket(address: net.IpAddress) (OpenSocketError || SockAddr.FromError)!posix.socket_t {
    const domain: u32 = switch (address) {
        .ip4 => linux.AF.INET,
        .ip6 => return error.Ipv6Unsupported,
    };
    assert(domain == linux.AF.INET);

    const return_code = linux.socket(domain, linux.SOCK.STREAM | linux.SOCK.CLOEXEC, 0);
    switch (linux.errno(return_code)) {
        .SUCCESS => {},
        .MFILE, .NFILE => return error.SystemFdQuotaExceeded,
        .ACCES => return error.AccessDenied,
        else => |errno| {
            std.log.scoped(.io).err("socket() failed: {t}", .{errno});
            return error.Unexpected;
        },
    }
    const socket: posix.socket_t = @intCast(return_code);
    assert(socket >= 0);
    return socket;
}

pub fn close_socket(socket: posix.socket_t) void {
    assert(socket >= 0);
    _ = linux.close(socket);
}

test "SockAddr.from renders an IPv4 sockaddr_in" {
    const address: net.IpAddress = .{ .ip4 = .{ .bytes = .{ 93, 184, 216, 34 }, .port = 8333 } };
    const sock_addr = try SockAddr.from(address);
    try std.testing.expectEqual(@as(posix.socklen_t, @sizeOf(linux.sockaddr.in)), sock_addr.len);

    const sockaddr: *const linux.sockaddr.in = @ptrCast(@alignCast(sock_addr.ptr()));
    try std.testing.expectEqual(linux.AF.INET, sockaddr.family);
    try std.testing.expectEqual(std.mem.nativeToBig(u16, 8333), sockaddr.port);
    try std.testing.expectEqual(@as(u32, @bitCast([4]u8{ 93, 184, 216, 34 })), sockaddr.addr);
}

test "SockAddr.from rejects IPv6" {
    const address: net.IpAddress = .{ .ip6 = .{ .bytes = @splat(0), .port = 8333 } };
    try std.testing.expectError(error.Ipv6Unsupported, SockAddr.from(address));
}

test "errno_from maps a negated errno back to linux.E" {
    try std.testing.expectEqual(linux.E.CONNREFUSED, errno_from(-@as(i32, @intFromEnum(linux.E.CONNREFUSED))));
}
