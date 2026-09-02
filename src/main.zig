const std = @import("std");
const Io = std.Io;
const net = std.Io.net;

const handshake = @import("handshake.zig");
const io_uring = @import("io.zig");
const seeds = @import("seeds.zig");

/// io_uring ring depth. A single handshake keeps at most two SQEs in flight.
const ring_entries = 8;
/// Addresses a startup DNS lookup may yield before we give up.
const dns_addresses_max = 32;

pub fn main(init: std.process.Init) !void {
    const host = seeds.mainnet_dns_seeds[0].host;
    const port = seeds.mainnet_port;

    // `init.io` (the runtime's threaded std.Io) is used only for startup DNS and
    // the closing report. The handshake itself runs entirely on `io`.
    const address = try resolve(init.io, host, port);

    var io: io_uring.IO = try .init(ring_entries);
    defer io.deinit();

    var peer: handshake.PeerInfo = undefined;
    handshake.connect(&peer, &io, address, .{
        .protocol_version = 70016,
        .services = 0,
        .user_agent = "/btz:0.1.0/",
        .magic = handshake.mainnet_magic,
        .timeout_ns = 10 * std.time.ns_per_s,
    }) catch |err| {
        std.log.err("handshake with {s}:{d} failed: {t}", .{ host, port, err });
        return err;
    };

    var stdout_buffer: [256]u8 = undefined;
    var stdout_writer: Io.File.Writer = .init(.stdout(), init.io, &stdout_buffer);
    const stdout = &stdout_writer.interface;
    try stdout.print("peer {s} speaks protocol {d}, services 0x{x}\n", .{
        peer.user_agent(), peer.protocol_version, peer.services,
    });
    try stdout.flush();
}

/// One-shot address resolution at startup. A literal IP is parsed directly; a
/// hostname is resolved via `io`, the runtime's threaded backend. TODO: move
/// DNS onto the ring so the program never touches a thread pool.
fn resolve(io: std.Io, host: []const u8, port: u16) !net.IpAddress {
    if (net.IpAddress.parse(host, port)) |literal| return literal else |_| {}

    const name = try net.HostName.init(host);
    var buffer: [dns_addresses_max]net.HostName.LookupResult = undefined;
    var results: std.Io.Queue(net.HostName.LookupResult) = .init(&buffer);
    try name.lookup(io, &results, .{ .port = port, .family = .ip4 });

    while (results.getOneUncancelable(io)) |result| {
        switch (result) {
            .address => |address| return address,
            .canonical_name => {},
        }
    } else |_| {}
    return error.UnknownHostName;
}

test {
    _ = @import("handshake.zig");
    _ = @import("io.zig");
    _ = @import("seeds.zig");
}
