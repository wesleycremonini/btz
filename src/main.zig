const std = @import("std");
const assert = std.debug.assert;
const Io = std.Io;
const net = std.Io.net;

const config_mod = @import("config.zig");
const message = @import("message.zig");
const session = @import("session.zig");
const crawl = @import("crawl.zig");
const io_uring = @import("io.zig");
const seeds = @import("seeds.zig");
const version = @import("version.zig");
const Stats = @import("stats.zig").Stats;
const Frontier = @import("frontier.zig").Frontier;
const log = std.log.scoped(.main);

/// The conversation narrates each step on the `.p2p` scope at `debug`; the run
/// prints an aggregate summary, so keep that scope quiet by default.
pub const std_options: std.Options = .{
    .log_scope_levels = &.{
        .{ .scope = .p2p, .level = .warn },
    },
};

/// Seed addresses resolved from DNS before the crawl starts.
const seed_addresses_max = 128;
/// Addresses a single DNS-seed lookup may contribute.
const dns_addresses_max = 64;
/// Rendered-summary buffer. Comfortably above the widest report the fixed-size
/// `Stats` tallies can produce.
const summary_bytes_max = 32 * 1024;

// Static storage: allocated at startup, never grown (TigerStyle). Each array is
// sized to its compile-time ceiling in `config.zig`; a run touches only the
// prefix its flags select, and the untouched pages cost nothing.
var slots: [config_mod.concurrency_max]session.Peer = undefined;
var frontier_queue: [config_mod.frontier_capacity_max]net.IpAddress = undefined;
var seen_table: [config_mod.seen_capacity_max]u32 = @splat(0);

pub fn main(init: std.process.Init) !void {
    var args = std.process.Args.Iterator.init(init.minimal.args);
    defer args.deinit();
    _ = args.skip(); // the program name

    const config = config_mod.parse(&args) catch |err| {
        if (err == error.HelpRequested) {
            config_mod.usage();
            return;
        }
        // `parse` already printed the specific reason.
        std.debug.print("btz: run 'btz --help' for options\n", .{});
        std.process.exit(2);
    };

    const network = config.network;
    var address_buffer: [seed_addresses_max]net.IpAddress = undefined;
    const seed_addresses = collect_seed_addresses(
        init.io,
        &address_buffer,
        seeds.seeds_for(network),
        seeds.port_for(network),
    );
    if (seed_addresses.len == 0) {
        log.err("no seed addresses resolved", .{});
        return error.NoSeedAddresses;
    }

    var frontier = Frontier.init(
        frontier_queue[0..config.frontier_capacity],
        seen_table[0..config.seen_capacity],
    );
    for (seed_addresses) |seed_address| _ = frontier.push(seed_address);
    log.info("network {t}: seeded {d}, dialing up to {d}, {d} in flight", .{
        network, frontier.enqueued, config.dials, config.concurrency,
    });

    var io: io_uring.IO = try .init(@intCast(config.ring_entries), 0);
    defer io.deinit();

    const options: version.Options = .{
        .protocol_version = config.protocol_version,
        .services = config.services,
        .user_agent = config.user_agent,
        .magic = message.magic_for(network),
        .connect_timeout_ns = @as(u63, config.connect_timeout_ms) * std.time.ns_per_ms,
        .getaddr_timeout_ns = @as(u63, config.getaddr_timeout_ms) * std.time.ns_per_ms,
        .addr_max_age_s = config.addr_max_age_s,
    };

    // Every conversation runs on this one ring, identified by a completion
    // pointer in its SQE `user_data`. `connect_all` returns with the ring
    // drained, having folded every dial's outcome into `stats`.
    var stats: Stats = .{};
    crawl.connect_all(
        &io,
        &frontier,
        slots[0..config.concurrency],
        &stats,
        config.dials,
        config.ok_target,
        options,
    );

    var summary_buffer: [summary_bytes_max]u8 = undefined;
    var summary_writer = std.Io.Writer.fixed(&summary_buffer);
    stats.write(&summary_writer) catch |err| log.err("render summary: {t}", .{err});
    const summary = summary_writer.buffered();

    var summary_file = Io.Dir.cwd().createFile(init.io, config.out_path, .{}) catch |err| {
        log.err("create {s}: {t}", .{ config.out_path, err });
        return err;
    };
    defer summary_file.close(init.io);
    summary_file.writeStreamingAll(init.io, summary) catch |err| {
        log.err("write {s}: {t}", .{ config.out_path, err });
    };
    std.debug.print("{s}", .{summary});

    if (stats.ok == 0) return error.AllHandshakesFailed;
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
    _ = @import("message.zig");
    _ = @import("version.zig");
    _ = @import("peer.zig");
    _ = @import("client.zig");
    _ = @import("services.zig");
    _ = @import("config.zig");
    _ = @import("addr.zig");
    _ = @import("frontier.zig");
    _ = @import("connection.zig");
    _ = @import("session.zig");
    _ = @import("stats.zig");
    _ = @import("crawl.zig");
    _ = @import("io.zig");
    _ = @import("seeds.zig");
}
