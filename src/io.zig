//! Single-threaded io_uring event loop.
//!
//! All I/O is expressed as SQEs submitted to one ring and reaped one CQE at a
//! time; there are no threads and no `std.Io` implementation. Concurrency, when
//! the crawler has many peers, comes from having many SQEs in flight on this
//! one ring, not from parallelism.

const std = @import("std");
const builtin = @import("builtin");
const assert = std.debug.assert;

const linux = std.os.linux;
const posix = std.posix;
const net = std.Io.net;

comptime {
    if (builtin.os.tag != .linux) @compileError("the io_uring backend is Linux-only");
}

pub const IO = struct {
    ring: linux.IoUring,

    /// `entries` is the ring depth; it must be a power of two. The caller sizes
    /// it for its whole workload: every SQE that can sit unsubmitted at once.
    pub fn init(entries: u16) !IO {
        assert(std.math.isPowerOfTwo(entries));
        return .{ .ring = try linux.IoUring.init(entries, 0) };
    }

    pub fn deinit(io: *IO) void {
        io.ring.deinit();
    }

    // --- SQE preparation. Each call queues one SQE; nothing reaches the kernel
    //     until `next_completion` submits. ---

    pub fn prep_connect(io: *IO, user_data: u64, fd: linux.fd_t, address: *const SockAddr) !void {
        assert(user_data != 0);
        _ = try io.ring.connect(user_data, fd, address.ptr(), address.len);
    }

    pub fn prep_send(io: *IO, user_data: u64, fd: linux.fd_t, buffer: []const u8) !void {
        assert(user_data != 0);
        assert(buffer.len > 0);
        _ = try io.ring.send(user_data, fd, buffer, 0);
    }

    pub fn prep_recv(io: *IO, user_data: u64, fd: linux.fd_t, buffer: []u8) !void {
        assert(user_data != 0);
        assert(buffer.len > 0);
        _ = try io.ring.recv(user_data, fd, .{ .buffer = buffer }, 0);
    }

    /// `deadline` must stay valid until the timeout completes or the ring is
    /// torn down; the kernel reads it after submission.
    pub fn prep_timeout(io: *IO, user_data: u64, deadline: *const linux.kernel_timespec) !void {
        assert(user_data != 0);
        _ = try io.ring.timeout(user_data, deadline, 0, 0);
    }

    /// Cancel a pending `prep_timeout` identified by `target_user_data`. Both the
    /// timer and this removal complete with their own CQE.
    pub fn prep_timeout_remove(io: *IO, user_data: u64, target_user_data: u64) !void {
        assert(user_data != 0);
        _ = try io.ring.timeout_remove(user_data, target_user_data, 0);
    }

    /// Cancel any pending op identified by `target_user_data`. Both the target
    /// and this cancellation complete with their own CQE.
    pub fn prep_cancel(io: *IO, user_data: u64, target_user_data: u64) !void {
        assert(user_data != 0);
        _ = try io.ring.cancel(user_data, target_user_data, 0);
    }

    /// Submit every queued SQE, block until at least one completion is ready,
    /// then copy every ready completion into `cqes`. Returns the count (>= 1).
    pub fn submit_and_reap(io: *IO, cqes: []linux.io_uring_cqe) !usize {
        assert(cqes.len > 0);
        _ = try io.ring.submit_and_wait(1);
        const count = try io.ring.copy_cqes(cqes, 0);
        assert(count >= 1);
        assert(count <= cqes.len);
        return count;
    }
};

/// A `sockaddr` built from a resolved `net.IpAddress`, kept in a fixed buffer so
/// its address is stable while a connect SQE references it.
pub const SockAddr = struct {
    bytes: [max_len]u8 align(4),
    len: posix.socklen_t,

    const max_len = @sizeOf(linux.sockaddr.in6);

    pub const FromError = error{Ipv6Unsupported};

    /// IPv6 is not wired up yet: `open_socket` and this function only handle
    /// `AF_INET`.
    pub fn from(address: net.IpAddress) FromError!SockAddr {
        var self: SockAddr = .{ .bytes = @splat(0), .len = 0 };
        switch (address) {
            .ip4 => |ip4| {
                const sockaddr: *linux.sockaddr.in = @ptrCast(&self.bytes);
                sockaddr.* = .{
                    .family = linux.AF.INET,
                    .port = std.mem.nativeToBig(u16, ip4.port),
                    .addr = @bitCast(ip4.bytes),
                };
                self.len = @sizeOf(linux.sockaddr.in);
            },
            .ip6 => return error.Ipv6Unsupported,
        }
        assert(self.len > 0);
        return self;
    }

    pub fn ptr(self: *const SockAddr) *const posix.sockaddr {
        return @ptrCast(&self.bytes);
    }
};

pub const SocketError = error{
    SystemFdQuotaExceeded,
    AccessDenied,
    Unexpected,
};

/// Create a blocking TCP socket for `address`'s family. io_uring makes the
/// operations on it asynchronous regardless of the socket's blocking mode.
pub fn open_socket(address: net.IpAddress) (SocketError || SockAddr.FromError)!linux.fd_t {
    const domain: u32 = switch (address) {
        .ip4 => linux.AF.INET,
        .ip6 => return error.Ipv6Unsupported,
    };
    const return_code = linux.socket(domain, linux.SOCK.STREAM | linux.SOCK.CLOEXEC, 0);
    return switch (linux.errno(return_code)) {
        .SUCCESS => @intCast(return_code),
        .MFILE, .NFILE => error.SystemFdQuotaExceeded,
        .ACCES => error.AccessDenied,
        else => |errno| {
            std.log.scoped(.io).err("socket() failed: {t}", .{errno});
            return error.Unexpected;
        },
    };
}

pub fn close_socket(fd: linux.fd_t) void {
    // Best-effort: nothing actionable if close fails on a socket we are done with.
    _ = linux.close(fd);
}
