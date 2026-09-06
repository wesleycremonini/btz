//! Classify a peer's BIP-14 user agent into a known implementation.
//!
//! Bitcoin user agents look like `/Name:version/`, sometimes stacked
//! (`/btcwire:0.5.0/btcd:0.24.2/`) or carrying a parenthetical comment
//! (`/Satoshi:27.1.0(Knots:20240801)/`). We match on distinctive substrings,
//! checking the Core-derived clients — which still say "Satoshi" — before Core
//! itself. Pure: no I/O, no allocation.

const std = @import("std");
const assert = std.debug.assert;

pub const Client = enum {
    core,
    knots,
    btcd,
    bitcore,
    libbitcoin,
    unlimited,
    uasf,
    bcoin,
    classic,
    ckcoind,
    utreexo,
    unknown,

    /// The token written to the record file.
    pub fn label(client: Client) []const u8 {
        return switch (client) {
            .core => "Core",
            .knots => "Knots",
            .btcd => "btcd",
            .bitcore => "Bitcore",
            .libbitcoin => "libbitcoin",
            .unlimited => "Unlimited",
            .uasf => "UASF",
            .bcoin => "bcoin",
            .classic => "Classic",
            .ckcoind => "CKCoinD",
            .utreexo => "Utreexo",
            .unknown => "Unknown",
        };
    }
};

/// Widest `Client.label`, for record-line buffer sizing.
pub const label_bytes_max = "libbitcoin".len;

comptime {
    for (@typeInfo(Client).@"enum".fields) |field| {
        const client: Client = @enumFromInt(field.value);
        assert(client.label().len >= 1);
        assert(client.label().len <= label_bytes_max);
    }
}

/// Classify `user_agent`. The order matters: a Core fork that still carries
/// "Satoshi" in its agent (Knots, UASF, Classic, Unlimited, Utreexo, Bitcore)
/// must be matched before plain Core.
pub fn classify(user_agent: []const u8) Client {
    const rules = .{
        .{ "knots", Client.knots },
        .{ "uasf", Client.uasf },
        .{ "utreexo", Client.utreexo },
        .{ "bitcoinunlimited", Client.unlimited },
        .{ "bucash", Client.unlimited },
        .{ "classic", Client.classic },
        .{ "bitcore", Client.bitcore },
        .{ "libbitcoin", Client.libbitcoin },
        .{ "btcd", Client.btcd },
        .{ "bcoin", Client.bcoin },
        .{ "ckcoind", Client.ckcoind },
        .{ "satoshi", Client.core },
    };
    inline for (rules) |rule| {
        if (std.ascii.indexOfIgnoreCase(user_agent, rule[0]) != null) return rule[1];
    }
    return .unknown;
}

test "classify: known user agents" {
    const testing = std.testing;
    try testing.expectEqual(Client.core, classify("/Satoshi:27.0.0/"));
    try testing.expectEqual(Client.knots, classify("/Satoshi:27.1.0(Knots:20240801)/"));
    try testing.expectEqual(Client.uasf, classify("/Satoshi:0.14.2(UASF-SegWit-BIP148)/"));
    try testing.expectEqual(Client.utreexo, classify("/btcwire:0.5.0/utreexod:0.4.1/"));
    try testing.expectEqual(Client.btcd, classify("/btcwire:0.5.0/btcd:0.24.2/"));
    try testing.expectEqual(Client.bcoin, classify("/bcoin:2.2.0/"));
    try testing.expectEqual(Client.libbitcoin, classify("/libbitcoin:3.8.0/"));
    try testing.expectEqual(Client.bitcore, classify("/bitcore:0.14.1/"));
    try testing.expectEqual(Client.classic, classify("/Classic:1.3.6/"));
    try testing.expectEqual(Client.unlimited, classify("/BitcoinUnlimited:1.10.3(EB16; AD4)/"));
    try testing.expectEqual(Client.unknown, classify("/mystery-node:1.0/"));
    try testing.expectEqual(Client.unknown, classify(""));
}

test "classify: forks are matched before Core" {
    const testing = std.testing;
    // All still carry "Satoshi"; the fork name must win.
    try testing.expectEqual(Client.classic, classify("/Satoshi:0.11.2(bitcoinclassic 1.1.0)/"));
    try testing.expectEqual(Client.unlimited, classify("/Satoshi:1.0.3.1(EB16; AD4)/BUCash:1.0.3.1/"));
}
