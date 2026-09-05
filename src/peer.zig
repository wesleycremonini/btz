//! What a dial attempt produces: its `DialError` outcome and the `PeerInfo`
//! the peer advertised about itself.
//!
//! A leaf module — no I/O, `std` only — so the record sink (`peer_log`) and
//! the scheduler (`crawl`) can name these without importing the `handshake`
//! state machine that fills them.

const std = @import("std");
const assert = std.debug.assert;

/// `MAX_SUBVERSION_LENGTH` in Bitcoin Core: the widest user agent we store,
/// and the widest we send or accept in a `version` message.
pub const max_user_agent_len = 256;

/// Why a dial did not end in a completed version/verack exchange.
pub const DialError = error{
    /// A message did not begin with the expected network magic.
    MagicMismatch,
    /// The peer's `version` checksum did not match its payload.
    ChecksumMismatch,
    /// A length field, or a `version`, exceeded what we will buffer.
    MessageTooLarge,
    /// The peer's `version` payload was too short or internally inconsistent.
    MalformedVersion,
    /// The peer closed the connection mid-handshake.
    EndOfStream,
    /// The handshake did not finish within its deadline.
    Timeout,
    /// The handshake ran through too many I/O steps without finishing.
    TooManyCompletions,
    /// The connect / send / recv operation failed at the transport layer.
    ConnectionRefused,
    ConnectionResetByPeer,
    NetworkUnreachable,
    HostUnreachable,
    /// The kernel cancelled the operation.
    Canceled,
    /// The socket could not be created or started for this address.
    SocketUnavailable,
    /// The address was never dialed: the success target was reached, or the
    /// run ended first.
    Skipped,
    /// An unclassified io_uring failure; see the log.
    Unexpected,
};

/// What the peer advertised in its own `version`. Filled in by the handshake,
/// rendered into the record file by `peer_log`.
pub const PeerInfo = struct {
    protocol_version: i32,
    services: u64,
    timestamp: i64,
    user_agent_len: u32,
    user_agent_buffer: [max_user_agent_len]u8,

    pub fn user_agent(peer: *const PeerInfo) []const u8 {
        assert(peer.user_agent_len <= peer.user_agent_buffer.len);
        return peer.user_agent_buffer[0..peer.user_agent_len];
    }
};

test "PeerInfo.user_agent returns the recorded prefix" {
    var peer: PeerInfo = std.mem.zeroes(PeerInfo);
    const user_agent = "/Satoshi:27.0.0/";
    @memcpy(peer.user_agent_buffer[0..user_agent.len], user_agent);
    peer.user_agent_len = user_agent.len;
    try std.testing.expectEqualStrings(user_agent, peer.user_agent());
}
