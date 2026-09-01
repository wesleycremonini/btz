const std = @import("std");
const Io = std.Io;

const seeds = @import("seeds.zig");

pub fn main(init: std.process.Init) !void {
    const io = init.io;

    // Stdout is the real output of the program; buffer it and flush before exit.
    var stdout_buffer: [1024]u8 = undefined;
    var stdout_file_writer: Io.File.Writer = .init(.stdout(), io, &stdout_buffer);
    const stdout = &stdout_file_writer.interface;

    try stdout.print("btc-crawler: {d} mainnet DNS seeds (p2p port {d})\n", .{
        seeds.mainnet_dns_seeds.len,
        seeds.mainnet_port,
    });
    for (seeds.mainnet_dns_seeds) |s| {
        try stdout.print("  {s}\n", .{s.host});
    }

    try stdout.flush();
}

test {
    _ = @import("seeds.zig");
}
