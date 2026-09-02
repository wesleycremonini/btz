const std = @import("std");
const Io = std.Io;

const handshake = @import("handshake.zig");
const seeds = @import("seeds.zig");

pub fn main(init: std.process.Init) !void {
    const io = init.io;

    // Bootstrap: dial the first mainnet DNS seed and complete a handshake.
    const seed = seeds.mainnet_dns_seeds[0].host;

    var peer: handshake.PeerInfo = undefined;
    handshake.connect(&peer, io, seed, seeds.mainnet_port, .{
        .protocol_version = 70016,
        .services = 0,
        .user_agent = "/btc-crawler:0.1.0/",
        .magic = handshake.mainnet_magic,
        .address_family = .ip4,
    }) catch |err| {
        std.log.err("handshake with {s} failed: {t}", .{ seed, err });
        return err;
    };

    var stdout_buffer: [256]u8 = undefined;
    var stdout_writer: Io.File.Writer = .init(.stdout(), io, &stdout_buffer);
    const stdout = &stdout_writer.interface;
    try stdout.print("peer {s} speaks protocol {d}, services 0x{x}\n", .{
        peer.user_agent(), peer.protocol_version, peer.services,
    });
    try stdout.flush();
}

test {
    _ = @import("handshake.zig");
    _ = @import("io.zig");
    _ = @import("seeds.zig");
}
