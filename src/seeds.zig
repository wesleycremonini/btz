//! Bootstrap peers for reaching the Bitcoin P2P network.
//!
//! These mirror the DNS seeds hardcoded in Bitcoin Core
//! (`src/kernel/chainparams.cpp`). Each hostname resolves to a rotating set of
//! reachable full-node addresses, which is why a crawler bootstraps from these
//! rather than from a fixed list of IPs (raw peer IPs go stale within days).
//!
//! Source of truth, re-check periodically:
//! https://github.com/bitcoin/bitcoin/blob/master/src/kernel/chainparams.cpp

const std = @import("std");
const Network = @import("message.zig").Network;

/// Default TCP port for each network's P2P protocol.
pub const mainnet_port: u16 = 8333;
pub const testnet3_port: u16 = 18333;
pub const signet_port: u16 = 38333;

/// The default P2P port for `network`.
pub fn port_for(network: Network) u16 {
    return switch (network) {
        .mainnet => mainnet_port,
        .testnet3 => testnet3_port,
        .signet => signet_port,
    };
}

/// The DNS seed list for `network`.
pub fn seeds_for(network: Network) []const Seed {
    return switch (network) {
        .mainnet => &mainnet_dns_seeds,
        .testnet3 => &testnet3_dns_seeds,
        .signet => &signet_dns_seeds,
    };
}

/// A DNS seed, paired with the operator it belongs to.
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

pub const testnet3_dns_seeds = [_]Seed{
    .{ .host = "testnet-seed.bitcoin.jonasschnelli.ch", .operator = "Jonas Schnelli" },
    .{ .host = "seed.tbtc.petertodd.net", .operator = "Peter Todd" },
    .{ .host = "seed.testnet.bitcoin.sprovoost.nl", .operator = "Sjors Provoost" },
    .{ .host = "testnet-seed.bluematt.me", .operator = "Matt Corallo" },
};

pub const signet_dns_seeds = [_]Seed{
    .{ .host = "seed.signet.bitcoin.sprovoost.nl", .operator = "Sjors Provoost" },
    .{ .host = "seed.signet.achownodes.xyz", .operator = "Ava Chow" },
};

test "every seed list is non-empty and every host is a bare hostname" {
    // Each `host` is passed straight to the resolver, so a stray scheme
    // ("tcp://") or ":port" suffix would silently fail to resolve. Guard
    // against that at compile-test time rather than at runtime.
    for ([_][]const Seed{ &mainnet_dns_seeds, &testnet3_dns_seeds, &signet_dns_seeds }) |list| {
        try std.testing.expect(list.len > 0);
        for (list) |seed| {
            try std.testing.expect(seed.host.len > 0);
            try std.testing.expect(seed.operator.len > 0);
            try std.testing.expect(std.mem.indexOfScalar(u8, seed.host, '/') == null);
            try std.testing.expect(std.mem.indexOfScalar(u8, seed.host, ':') == null);
        }
    }
}

test "port_for and seeds_for cover every network" {
    for (std.enums.values(Network)) |network| {
        try std.testing.expect(port_for(network) != 0);
        try std.testing.expect(seeds_for(network).len > 0);
    }
}
