const std = @import("std");
const assert = std.debug.assert;
const Io = std.Io;
const net = std.Io.net;

const session = @import("session.zig");
const crawl = @import("crawl.zig");
const io_uring = @import("io.zig");
const seeds = @import("seeds.zig");
const PeerLog = @import("peer_log.zig").PeerLog;
const Frontier = @import("frontier.zig").Frontier;
const log = std.log.scoped(.main);

/// One line per dialed peer is written here; truncated at the start of each run.
const log_path = "btz.log";

/// The conversation narrates each step on the `.p2p` scope at `debug`; the peer
/// record lives in `log_path`, so keep that scope quiet by default.
pub const std_options: std.Options = .{
    .log_scope_levels = &.{
        .{ .scope = .p2p, .level = .warn },
    },
};

/// Conversations kept in flight on the ring at once.
const concurrency = 8;
/// Dials to start before the crawl stops (the frontier may still hold more).
const dial_max = 128;
/// Seed addresses resolved from DNS before the crawl starts.
const seed_addresses_max = 32;
/// Addresses a single DNS-seed lookup may contribute.
const dns_addresses_max = 32;
/// Frontier queue capacity: addresses discovered but not yet dialed.
const frontier_capacity = 4096;
/// Seen-set capacity (a power of two): every address ever enqueued. Sized well
/// above `dial_max` plus the discoveries it can turn up so the set never fills.
const seen_capacity = 1 << 16;
/// io_uring SQ depth. Each conversation holds only a few SQEs and each settling
/// one queues a record write, so 256 is roomy; an undersized ring only makes
/// `IO` park the overflow on its unqueued list, never fail.
const ring_entries = 256;

comptime {
    assert(std.math.isPowerOfTwo(ring_entries));
    assert(std.math.isPowerOfTwo(seen_capacity));
    assert(concurrency >= 1);
    assert(dial_max >= 1);
    assert(seed_addresses_max >= 1);
    assert(dns_addresses_max >= 1);
    assert(frontier_capacity >= seed_addresses_max);
}

// Static storage: allocated at startup, never grown (TigerStyle).
var slots: [concurrency]session.Peer = undefined;
var log_lines: [dial_max]PeerLog.Line = undefined;
var frontier_queue: [frontier_capacity]net.IpAddress = undefined;
var seen_table: [seen_capacity]u32 = @splat(0);

pub fn main(init: std.process.Init) !void {
    const port = seeds.mainnet_port;

    var address_buffer: [seed_addresses_max]net.IpAddress = undefined;
    const seed_addresses = collect_seed_addresses(
        init.io,
        &address_buffer,
        &seeds.mainnet_dns_seeds,
        port,
    );
    if (seed_addresses.len == 0) {
        log.err("no seed addresses resolved", .{});
        return error.NoSeedAddresses;
    }

    var frontier = Frontier.init(&frontier_queue, &seen_table);
    for (seed_addresses) |seed_address| _ = frontier.push(seed_address);
    log.info("seeded {d} address(es); dialing up to {d}, {d} in flight", .{
        frontier.enqueued, dial_max, concurrency,
    });

    var io: io_uring.IO = try .init(ring_entries, 0);
    defer io.deinit();

    var log_file = Io.Dir.cwd().createFile(init.io, log_path, .{}) catch |err| {
        log.err("create {s}: {t}", .{ log_path, err });
        return err;
    };
    defer log_file.close(init.io);

    // One record line per dialed address, written onto `io` as `IORING_OP_WRITE`s
    // so the crawl loop never blocks on the log file.
    var peer_log = PeerLog.init(&io, log_file.handle, &log_lines);

    // Every conversation runs on this one ring, identified by a completion
    // pointer in its SQE `user_data`; `connect_all` returns with the ring
    // drained, having written one `btz.log` line per dialed peer as it settled.
    const summary = crawl.connect_all(&io, &peer_log, &frontier, &slots, dial_max, .{});

    log.info("wrote {s}: {d} ok / {d} dialed, {d} discovered, {d} record(s) dropped", .{
        log_path, summary.succeeded, summary.dialed, summary.discovered, summary.dropped,
    });
    if (summary.succeeded == 0) return error.AllHandshakesFailed;
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
    _ = @import("addr.zig");
    _ = @import("frontier.zig");
    _ = @import("connection.zig");
    _ = @import("session.zig");
    _ = @import("peer_log.zig");
    _ = @import("crawl.zig");
    _ = @import("io.zig");
    _ = @import("seeds.zig");
}
