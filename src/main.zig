const std = @import("std");
const assert = std.debug.assert;
const Io = std.Io;
const net = std.Io.net;

const handshake = @import("handshake.zig");
const crawl = @import("crawl.zig");
const io_uring = @import("io.zig");
const seeds = @import("seeds.zig");
const PeerLog = crawl.PeerLog;
const log = std.log.scoped(.main);

/// One line per dialed peer is written here; truncated at the start of each run.
const log_path = "btz.log";

/// The handshake narrates each step on the `.p2p` scope at `debug`; the peer
/// record now lives in `log_path`, so keep that scope quiet by default.
pub const std_options: std.Options = .{
    .log_scope_levels = &.{
        .{ .scope = .p2p, .level = .warn },
    },
};

/// Handshakes kept in flight on the ring at once.
const concurrency = 8;
/// Successful handshakes to reach before we stop dialing new addresses.
const handshake_target = 4;
/// Resolved peer addresses gathered from the seed list before dialing.
const seed_addresses_max = 32;
/// Addresses a single DNS-seed lookup may contribute.
const dns_addresses_max = 32;
/// io_uring SQ depth, sized so `connect_all` never fills the queue.
const ring_entries = 256;

comptime {
    assert(std.math.isPowerOfTwo(ring_entries));
    assert(ring_entries >= crawl.min_ring_entries(concurrency, seed_addresses_max));
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

    var log_file = Io.Dir.cwd().createFile(init.io, log_path, .{}) catch |err| {
        log.err("create {s}: {t}", .{ log_path, err });
        return err;
    };
    defer log_file.close(init.io);

    // One record line per dialed address, written onto `io` as `IORING_OP_WRITE`s
    // so the crawl loop never blocks on the log file.
    var log_lines: [seed_addresses_max]PeerLog.Line = undefined;
    var peer_log = PeerLog.init(&io, log_file.handle, log_lines[0..addresses.len]);

    // Every handshake runs on this one ring, identified by a pointer stored in
    // its SQE `user_data`; `connect_all` returns with the ring drained, having
    // written one `btz.log` line per dialed peer as each settled.
    var slots: [concurrency]handshake.Handshake = undefined;
    const summary = crawl.connect_all(
        &io,
        &peer_log,
        addresses,
        slots[0..],
        handshake_target,
        .{},
    );

    log.info("wrote {s}: {d} ok / {d} dialed, {d} record(s) dropped", .{
        log_path, summary.succeeded, summary.dialed, summary.dropped,
    });
    if (summary.succeeded == 0) return error.AllHandshakesFailed;
    if (summary.succeeded < handshake_target) {
        log.warn("only {d} of {d} target handshakes succeeded", .{ summary.succeeded, handshake_target });
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
    _ = @import("message.zig");
    _ = @import("version.zig");
    _ = @import("handshake.zig");
    _ = @import("peer_log.zig");
    _ = @import("crawl.zig");
    _ = @import("io.zig");
    _ = @import("seeds.zig");
}
