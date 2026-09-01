const std = @import("std");
const Io = std.Io;

const seeds = @import("seeds.zig");
const handshake = @import("handshake.zig");

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const gpa = init.arena.allocator();

    // Bootstrap: resolve the first mainnet DNS seed to a live node and shake
    // hands with it.
    const seed = seeds.mainnet_dns_seeds[0].host;
    const peer = handshake.connect(io, gpa, seed, seeds.mainnet_port, .{}) catch |err| {
        std.log.err("handshake with {s} failed: {t}", .{ seed, err });
        return err;
    };

    var stdout_buffer: [1024]u8 = undefined;
    var stdout_file_writer: Io.File.Writer = .init(.stdout(), io, &stdout_buffer);
    const stdout = &stdout_file_writer.interface;
    try stdout.print("peer {s} speaks protocol {d}, services 0x{x}\n", .{
        peer.userAgent(), peer.protocol_version, peer.services,
    });
    try stdout.flush();
}

test {
    _ = @import("seeds.zig");
    _ = @import("handshake.zig");
}
