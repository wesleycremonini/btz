//! Bootstrap peers for reaching the Bitcoin P2P network.
//!
//! These mirror the mainnet DNS seeds hardcoded in Bitcoin Core
//! (`src/kernel/chainparams.cpp`). Each hostname resolves to a rotating set of
//! reachable full-node addresses, which is why a crawler bootstraps from these
//! rather than from a fixed list of IPs (raw peer IPs go stale within days).
//!
//! Source of truth, re-check periodically:
//! https://github.com/bitcoin/bitcoin/blob/master/src/kernel/chainparams.cpp

const std = @import("std");

/// Default TCP port for the mainnet P2P protocol.
pub const mainnet_port: u16 = 8333;

/// Mainnet DNS seeds, each paired with the operator it belongs to.
pub const Seed = struct {
    host: []const u8,
    operator: []const u8,
};

pub const mainnet_dns_seeds = [_]Seed{
    .{ .host = "seed.bitcoin.sipa.be", .operator = "Pieter Wuille" },
    .{ .host = "dnsseed.bluematt.me", .operator = "Matt Corallo" },
    .{ .host = "dnsseed.bitcoin.dashjr-list-of-p2p-nodes.us", .operator = "Luke Dashjr" },
    .{ .host = "seed.bitcoinstats.com", .operator = "Christian Decker" },
    .{ .host = "seed.bitcoin.jonasschnelli.ch", .operator = "Jonas Schnelli" },
    .{ .host = "seed.bitcoin.sprovoost.nl", .operator = "Sjors Provoost" },
    .{ .host = "dnsseed.emzy.de", .operator = "Stephan Oeste" },
    .{ .host = "seed.bitcoin.wiz.biz", .operator = "Jason Maurice" },
};

test "seed list is non-empty and every host is a bare hostname" {
    // `main.collect_seed_addresses` passes each `host` straight to the resolver,
    // so a stray scheme ("tcp://") or ":port" suffix would silently fail to
    // resolve. Guard against that at compile-test time rather than at runtime.
    try std.testing.expect(mainnet_dns_seeds.len > 0);
    for (mainnet_dns_seeds) |seed| {
        try std.testing.expect(seed.host.len > 0);
        try std.testing.expect(seed.operator.len > 0);
        try std.testing.expect(std.mem.indexOfScalar(u8, seed.host, '/') == null);
        try std.testing.expect(std.mem.indexOfScalar(u8, seed.host, ':') == null);
    }
}
