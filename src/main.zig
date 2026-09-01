// SPDX-License-Identifier: MIT

const std = @import("std");
const Io = std.Io;

pub fn main(init: std.process.Init) !void {
    const io = init.io;

    // Stdout is the real output of the program; buffer it and flush before exit.
    var stdout_buffer: [1024]u8 = undefined;
    var stdout_file_writer: Io.File.Writer = .init(.stdout(), io, &stdout_buffer);
    const stdout = &stdout_file_writer.interface;

    try stdout.print("Hello, world!\n", .{});

    try stdout.flush();
}

test "hello" {
    try std.testing.expect(std.mem.eql(u8, "Hello, world!", "Hello, world!"));
}
