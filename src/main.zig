const std = @import("std");
const assert = std.debug.assert;
const Io = std.Io;
const net = std.Io.net;

const handshake = @import("handshake.zig");
const io_uring = @import("io.zig");
const seeds = @import("seeds.zig");
const log = std.log.scoped(.main);

/// Handshakes kept in flight on the ring at once.
const concurrency = 8;
/// Successful handshakes to reach before we stop dialing new addresses.
const handshake_target = 4;
/// Resolved peer addresses gathered from the seed list before dialing.
const seed_addresses_max = 32;
/// Addresses a single DNS-seed lookup may contribute.
const dns_addresses_max = 32;
/// io_uring SQ depth, sized so `connect_all` never fills the queue.
const ring_entries = 128;

comptime {
    assert(std.math.isPowerOfTwo(ring_entries));
    assert(ring_entries >= handshake.min_ring_entries(concurrency));
    assert(concurrency >= 1);
    assert(handshake_target >= 1);
    assert(handshake_target <= seed_addresses_max);
    assert(dns_addresses_max >= 1);
}

pub fn main(init: std.process.Init) !void {
    const port = seeds.mainnet_port;

    var address_buffer: [seed_addresses_max]net.IpAddress = undefined;
    const addresses = collect_seed_addresses(
        init.io,
        &address_buffer,
        &seeds.mainnet_dns_seeds,
        port,
    );
    if (addresses.len == 0) {
        log.err("no seed addresses resolved", .{});
        return error.NoSeedAddresses;
    }
    log.info("resolved {d} seed address(es); want {d} handshake(s), {d} in flight", .{
        addresses.len, handshake_target, concurrency,
    });

    var io: io_uring.IO = try .init(ring_entries);
    defer io.deinit();

    // Every handshake runs on this one ring, identified by a pointer stored in
    // its SQE `user_data`; `connect_all` returns with the ring drained.
    var slots: [concurrency]handshake.Handshake = undefined;
    var results: [seed_addresses_max]handshake.Result = undefined;
    handshake.connect_all(&io, addresses, slots[0..], results[0..addresses.len], handshake_target, .{});

    var stdout_buffer: [512]u8 = undefined;
    var stdout_writer: Io.File.Writer = .init(.stdout(), init.io, &stdout_buffer);
    const stdout = &stdout_writer.interface;

    var succeeded: u32 = 0;
    for (addresses, results[0..addresses.len]) |address, result| {
        if (result.outcome) |_| {
            succeeded += 1;
            try stdout.print("[ok]   {f}  protocol {d}  services 0x{x}  {s}\n", .{
                address,              result.peer.protocol_version,
                result.peer.services, result.peer.user_agent(),
            });
        } else |err| switch (err) {
            error.Skipped => {},
            else => log.warn("[fail] {f}: {t}", .{ address, err }),
        }
    }
    try stdout.flush();

    log.info("handshakes: {d} ok", .{succeeded});
    if (succeeded == 0) return error.AllHandshakesFailed;
    if (succeeded < handshake_target) {
        log.warn("only {d} of {d} target handshakes succeeded", .{ succeeded, handshake_target });
    }
}

/// Resolve seed hostnames into `buffer` (IPv4, `port`), stopping when it fills
/// or the seed list is exhausted. Returns the filled prefix. A seed that fails
/// to resolve is logged and skipped rather than aborting the run.
fn collect_seed_addresses(
    io: std.Io,
    buffer: []net.IpAddress,
    seed_list: []const seeds.Seed,
    port: u16,
) []net.IpAddress {
    assert(buffer.len > 0);
    assert(seed_list.len > 0);
    assert(port != 0);

    var count: u32 = 0;
    for (seed_list) |seed| {
        if (count == buffer.len) break;

        const name = net.HostName.init(seed.host) catch |err| {
            log.warn("seed {s}: bad hostname: {t}", .{ seed.host, err });
            continue;
        };
        var results_buffer: [dns_addresses_max]net.HostName.LookupResult = undefined;
        var results: std.Io.Queue(net.HostName.LookupResult) = .init(&results_buffer);
        name.lookup(io, &results, .{ .port = port, .family = .ip4 }) catch |err| {
            log.warn("seed {s}: lookup failed: {t}", .{ seed.host, err });
            continue;
        };

        var from_seed: u32 = 0;
        while (results.getOneUncancelable(io)) |result| {
            switch (result) {
                .canonical_name => {},
                .address => |address| {
                    assert(count < buffer.len);
                    buffer[count] = address;
                    count += 1;
                    from_seed += 1;
                    if (count == buffer.len) break;
                },
            }
        } else |_| {}
        log.debug("seed {s}: {d} address(es)", .{ seed.host, from_seed });
    }

    assert(count <= buffer.len);
    return buffer[0..count];
}

test {
    _ = @import("handshake.zig");
    _ = @import("io.zig");
    _ = @import("seeds.zig");
}
