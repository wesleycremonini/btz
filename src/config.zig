//! Command-line configuration for the crawler.
//!
//! `parse` turns `--flag value` / `--flag=value` arguments into a `Config`,
//! validating each against a compile-time ceiling — the values that size the
//! static storage in `main` — and printing a diagnostic to stderr for anything
//! it rejects. No allocation: string options borrow the argv slices, which live
//! for the whole process.

const std = @import("std");
const builtin = @import("builtin");
const assert = std.debug.assert;
const Network = @import("message.zig").Network;
const max_user_agent_len = @import("peer.zig").max_user_agent_len;

/// A rejected flag prints one line to stderr — via `std.debug.print`, not
/// `std.log`, whose error level would fail the test step — then `parse` returns
/// the error. Silent under `zig test` so the negative-path cases stay quiet.
fn report(comptime fmt: []const u8, args: anytype) void {
    if (builtin.is_test) return;
    std.debug.print("btz: " ++ fmt ++ "\n", args);
}

// Compile-time ceilings. `main` sizes its static arrays to these; a flag may
// not exceed its ceiling. Raising one costs only virtual address space (the
// pages are demand-zeroed), so they are set generously.
pub const concurrency_max = 2048;
pub const dials_max = 10_000_000;
pub const timeout_ms_max = 600_000;
pub const frontier_capacity_max = 1 << 18;
pub const seen_capacity_max = 1 << 21;
pub const ring_entries_max = 1 << 15;

comptime {
    assert(std.math.isPowerOfTwo(frontier_capacity_max));
    assert(std.math.isPowerOfTwo(seen_capacity_max));
    assert(std.math.isPowerOfTwo(ring_entries_max));
}

pub const Config = struct {
    /// Conversations in flight at once.
    concurrency: u32 = 512,
    /// Addresses to dial before the crawl stops.
    dials: u32 = 2000,
    /// Whole-conversation deadline, milliseconds.
    timeout_ms: u32 = 10_000,
    /// Record file path.
    out_path: []const u8 = "btz.log",
    /// `version` user agent (BIP-14).
    user_agent: []const u8 = "/btz:0.1.0/",
    /// Which Bitcoin network to crawl.
    network: Network = .mainnet,
    /// Protocol version to advertise.
    protocol_version: i32 = 70016,
    /// Service bits to advertise.
    services: u64 = 0,
    /// Drop `addr` entries older than this (seconds).
    addr_max_age_s: u32 = 10 * 24 * 60 * 60,
    /// Frontier queue capacity.
    frontier_capacity: u32 = 16384,
    /// Dedup-set capacity (a power of two).
    seen_capacity: u32 = 1 << 18,
    /// io_uring SQ depth (a power of two).
    ring_entries: u32 = 8192,
};

pub const Error = error{ UnknownFlag, MissingValue, BadValue, HelpRequested };

/// Parse `args` — anything with `fn next(...) ?[]const u8`, positioned past the
/// program name — into a `Config`.
pub fn parse(args: anytype) Error!Config {
    var config: Config = .{};
    while (args.next()) |arg| {
        if (eql(arg, "-h") or eql(arg, "--help")) return error.HelpRequested;
        if (!std.mem.startsWith(u8, arg, "--")) {
            report("unexpected argument: {s}", .{arg});
            return error.UnknownFlag;
        }

        const body = arg[2..];
        const split = split_eq(body);
        if (!is_known(split.name)) {
            report("unknown flag: --{s}", .{split.name});
            return error.UnknownFlag;
        }
        const value = split.value orelse args.next() orelse {
            report("--{s} requires a value", .{split.name});
            return error.MissingValue;
        };
        try apply(&config, split.name, value);
    }
    try validate(&config);
    return config;
}

/// Write the flag reference to stderr.
pub fn usage() void {
    std.debug.print(
        \\btz — a Bitcoin P2P network crawler
        \\
        \\Usage: btz [options]
        \\
        \\  --network <name>          mainnet | testnet3 | signet    (mainnet)
        \\  --concurrency <n>         conversations in flight        (512, max 2048)
        \\  --dials <n>               addresses to dial, total       (2000)
        \\  --timeout-ms <n>          per-conversation deadline      (10000)
        \\  --out <path>              record file                    (btz.log)
        \\  --user-agent <string>     version user agent             (/btz:0.1.0/)
        \\  --protocol-version <n>    version protocol number        (70016)
        \\  --services <n|0xHEX>      advertised service bits        (0)
        \\  --addr-max-age-days <n>   drop older addr entries        (10)
        \\  --frontier-capacity <n>   discovered-address queue       (16384, max 262144)
        \\  --seen-capacity <n>       dedup table, power of two      (262144, max 2097152)
        \\  --ring-entries <n>        io_uring SQ depth, power of 2  (8192, max 32768)
        \\  -h, --help               show this and exit
        \\
    , .{});
}

/// Every accepted flag name (without the `--`). Kept beside `apply` so the two
/// stay in step: `is_known` gates on this list, `apply`'s `else` is a backstop.
const flag_names = [_][]const u8{
    "concurrency",       "dials",         "timeout-ms",
    "out",               "user-agent",    "network",
    "protocol-version",  "services",      "addr-max-age-days",
    "frontier-capacity", "seen-capacity", "ring-entries",
};

fn is_known(name: []const u8) bool {
    for (flag_names) |flag| {
        if (eql(name, flag)) return true;
    }
    return false;
}

const Split = struct { name: []const u8, value: ?[]const u8 };

/// Split `flag=value` on the first `=`; without one, `value` is null.
fn split_eq(body: []const u8) Split {
    if (std.mem.indexOfScalar(u8, body, '=')) |eq| {
        return .{ .name = body[0..eq], .value = body[eq + 1 ..] };
    }
    return .{ .name = body, .value = null };
}

fn apply(config: *Config, name: []const u8, value: []const u8) Error!void {
    if (eql(name, "concurrency")) {
        config.concurrency = try to_u32(name, value);
    } else if (eql(name, "dials")) {
        config.dials = try to_u32(name, value);
    } else if (eql(name, "timeout-ms")) {
        config.timeout_ms = try to_u32(name, value);
    } else if (eql(name, "out")) {
        config.out_path = value;
    } else if (eql(name, "user-agent")) {
        config.user_agent = value;
    } else if (eql(name, "network")) {
        config.network = to_network(value) orelse {
            report("--network must be mainnet, testnet3, or signet (got {s})", .{value});
            return error.BadValue;
        };
    } else if (eql(name, "protocol-version")) {
        config.protocol_version = std.fmt.parseInt(i32, value, 10) catch {
            report("--protocol-version must be an integer (got {s})", .{value});
            return error.BadValue;
        };
    } else if (eql(name, "services")) {
        config.services = to_u64(value) orelse {
            report("--services must be a number, 0x-prefixed for hex (got {s})", .{value});
            return error.BadValue;
        };
    } else if (eql(name, "addr-max-age-days")) {
        const days = try to_u32(name, value);
        config.addr_max_age_s = days *| std.time.s_per_day;
    } else if (eql(name, "frontier-capacity")) {
        config.frontier_capacity = try to_u32(name, value);
    } else if (eql(name, "seen-capacity")) {
        config.seen_capacity = try to_u32(name, value);
    } else if (eql(name, "ring-entries")) {
        config.ring_entries = try to_u32(name, value);
    } else {
        report("unknown flag: --{s}", .{name});
        return error.UnknownFlag;
    }
}

fn validate(config: *const Config) Error!void {
    try in_range("concurrency", config.concurrency, 1, concurrency_max);
    try in_range("dials", config.dials, 1, dials_max);
    try in_range("timeout-ms", config.timeout_ms, 1, timeout_ms_max);
    try in_range("frontier-capacity", config.frontier_capacity, 1, frontier_capacity_max);
    try power_of_two("seen-capacity", config.seen_capacity, 2, seen_capacity_max);
    try power_of_two("ring-entries", config.ring_entries, 1, ring_entries_max);

    if (config.user_agent.len == 0 or config.user_agent.len > max_user_agent_len) {
        report("--user-agent must be 1..{d} bytes (got {d})", .{ max_user_agent_len, config.user_agent.len });
        return error.BadValue;
    }
}

fn eql(a: []const u8, b: []const u8) bool {
    return std.mem.eql(u8, a, b);
}

fn to_u32(name: []const u8, value: []const u8) Error!u32 {
    return std.fmt.parseInt(u32, value, 10) catch {
        report("--{s} must be a non-negative integer (got {s})", .{ name, value });
        return error.BadValue;
    };
}

fn to_u64(value: []const u8) ?u64 {
    if (std.mem.startsWith(u8, value, "0x") or std.mem.startsWith(u8, value, "0X")) {
        return std.fmt.parseInt(u64, value[2..], 16) catch null;
    }
    return std.fmt.parseInt(u64, value, 10) catch null;
}

fn to_network(value: []const u8) ?Network {
    if (eql(value, "mainnet")) return .mainnet;
    if (eql(value, "testnet3")) return .testnet3;
    if (eql(value, "signet")) return .signet;
    return null;
}

fn in_range(name: []const u8, got: u32, low: u32, high: u32) Error!void {
    if (got >= low and got <= high) return;
    report("--{s} must be {d}..{d} (got {d})", .{ name, low, high, got });
    return error.BadValue;
}

fn power_of_two(name: []const u8, got: u32, low: u32, high: u32) Error!void {
    try in_range(name, got, low, high);
    if (std.math.isPowerOfTwo(got)) return;
    report("--{s} must be a power of two (got {d})", .{ name, got });
    return error.BadValue;
}

const testing = std.testing;

/// A minimal `args.next()` source for tests.
const SliceArgs = struct {
    items: []const []const u8,
    index: usize = 0,
    fn next(self: *SliceArgs) ?[]const u8 {
        if (self.index == self.items.len) return null;
        defer self.index += 1;
        return self.items[self.index];
    }
};

fn parse_slice(items: []const []const u8) Error!Config {
    var args: SliceArgs = .{ .items = items };
    return parse(&args);
}

test "parse: defaults with no arguments" {
    const config = try parse_slice(&.{});
    try testing.expectEqual(@as(u32, 512), config.concurrency);
    try testing.expectEqual(Network.mainnet, config.network);
    try testing.expectEqualStrings("btz.log", config.out_path);
}

test "parse: separate and inline values" {
    const a = try parse_slice(&.{ "--concurrency", "100" });
    try testing.expectEqual(@as(u32, 100), a.concurrency);
    const b = try parse_slice(&.{"--concurrency=100"});
    try testing.expectEqual(@as(u32, 100), b.concurrency);
}

test "parse: network, services hex, addr age in days" {
    const config = try parse_slice(&.{
        "--network",           "testnet3",
        "--services",          "0x409",
        "--addr-max-age-days", "2",
    });
    try testing.expectEqual(Network.testnet3, config.network);
    try testing.expectEqual(@as(u64, 0x409), config.services);
    try testing.expectEqual(@as(u32, 2 * 24 * 60 * 60), config.addr_max_age_s);
}

test "parse: rejects bad input" {
    try testing.expectError(error.UnknownFlag, parse_slice(&.{"--nope"}));
    try testing.expectError(error.UnknownFlag, parse_slice(&.{"positional"}));
    try testing.expectError(error.MissingValue, parse_slice(&.{"--concurrency"}));
    try testing.expectError(error.BadValue, parse_slice(&.{ "--concurrency", "0" }));
    try testing.expectError(error.BadValue, parse_slice(&.{ "--concurrency", "99999" }));
    try testing.expectError(error.BadValue, parse_slice(&.{ "--ring-entries", "1000" }));
    try testing.expectError(error.BadValue, parse_slice(&.{ "--network", "regtest" }));
    try testing.expectError(error.HelpRequested, parse_slice(&.{"--help"}));
}
