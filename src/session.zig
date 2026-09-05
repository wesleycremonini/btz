//! The Bitcoin P2P peer conversation, as a `connection.Connection` protocol.
//!
//! `Protocol` is a pure state machine: fed peer bytes and send / deadline
//! events by the connection, it returns `Directive`s. It runs the `version` /
//! `verack` handshake, records the peer's `version` into `PeerInfo`, then sends
//! `getaddr` and collects the IPv4 addresses from the peer's first `addr`
//! reply. No I/O, no allocation.
//!
//! `Peer` is `Connection(Protocol)` — the type `crawl.zig` pools.

const std = @import("std");
const assert = std.debug.assert;

const net = std.Io.net;
const connection = @import("connection.zig");
const message = @import("message.zig");
const version = @import("version.zig");
const addr = @import("addr.zig");
const peer_types = @import("peer.zig");
const Directive = connection.Directive;
const PeerInfo = peer_types.PeerInfo;
const DialError = peer_types.DialError;
const header_len = message.header_len;
const log = std.log.scoped(.p2p);

/// `Connection(Protocol)` — the crawler's per-peer slot. `Peer.Options` is
/// `Protocol.Options` is `version.Options`.
pub const Peer = connection.Connection(Protocol);

/// Addresses kept from one peer's `getaddr` reply. An `addr` may carry up to
/// `addr.entries_max`; a few hundred per peer keeps the crawl frontier fed
/// without an outsized slot.
pub const discovered_max = 256;

/// `addr` entries older than this are skipped. Bitcoin Core keeps an address
/// in its tables for ~30 days and only re-times it when it reconnects, so the
/// cutoff must be lenient: this just drops the genuinely ancient ones that are
/// nearly always offline, without gutting a `getaddr` reply.
const addr_max_age_s = 10 * 24 * 60 * 60;

/// Receive buffer. Must hold the largest single message we parse whole — a
/// full `addr` — plus its header; other messages are consumed and dropped.
const recv_buffer_len = header_len + addr.addr_payload_max;

/// Send buffer: one framed message at a time; our `version` is the largest.
const frame_buffer_len = header_len + version.version_payload_max;

/// Bound on `pump` turns: each consumes at least one buffered message or emits
/// one directive, so the buffer capacity caps it.
const pump_turns_max = recv_buffer_len / header_len + 4;

comptime {
    assert(recv_buffer_len >= header_len + version.version_payload_max);
    assert(recv_buffer_len <= message.message_payload_max);
    assert(frame_buffer_len >= header_len + version.version_payload_max);
    assert(discovered_max >= 1);
}

pub const Protocol = struct {
    /// Dial parameters. `connection.Connection` requires this decl.
    pub const Options = version.Options;

    options: Options,
    address: net.IpAddress,

    peer_info: PeerInfo,
    discovered: [discovered_max]net.IpAddress,
    discovered_len: u32,

    send_buffer: [frame_buffer_len]u8,
    recv_bytes: [recv_buffer_len]u8,
    recv_len: u32,

    version_received: bool,
    verack_sent: bool,
    verack_received: bool,
    getaddr_sent: bool,
    addr_received: bool,

    pub fn reset(protocol: *Protocol, address: net.IpAddress, options: Options) void {
        assert(options.magic != 0);
        assert(options.user_agent.len > 0);
        assert(options.user_agent.len <= peer_types.max_user_agent_len);
        protocol.* = .{
            .options = options,
            .address = address,
            .peer_info = undefined,
            .discovered = undefined,
            .discovered_len = 0,
            .send_buffer = undefined,
            .recv_bytes = undefined,
            .recv_len = 0,
            .version_received = false,
            .verack_sent = false,
            .verack_received = false,
            .getaddr_sent = false,
            .addr_received = false,
        };
    }

    pub fn connected(protocol: *Protocol) Directive {
        assert(!protocol.version_received);
        const payload = version.build_version(
            protocol.send_buffer[header_len..],
            protocol.address,
            protocol.options,
        );
        const frame = message.frame_in_place(
            &protocol.send_buffer,
            protocol.options.magic,
            "version",
            @intCast(payload.len),
        );
        assert(frame.len >= header_len);
        log.debug("-> version (protocol={d}, user_agent={s})", .{
            protocol.options.protocol_version, protocol.options.user_agent,
        });
        return .{ .send = frame };
    }

    pub fn recv_buffer(protocol: *Protocol) []u8 {
        assert(protocol.recv_len < recv_buffer_len);
        return protocol.recv_bytes[protocol.recv_len..];
    }

    pub fn on_recv(protocol: *Protocol, byte_count: u32) Directive {
        assert(byte_count > 0);
        assert(protocol.recv_len + byte_count <= recv_buffer_len);
        protocol.recv_len += byte_count;
        return protocol.pump();
    }

    pub fn on_send(protocol: *Protocol) Directive {
        return protocol.pump();
    }

    pub fn on_deadline(protocol: *Protocol) Directive {
        // Past verack the record is already usable: a slow or silent `getaddr`
        // is not a failure, just zero discovered addresses.
        if (protocol.verack_received) return .done;
        return .{ .fail = error.Timeout };
    }

    /// Consume whole buffered messages, advancing the conversation. Returns the
    /// next directive: send our reply, read more, done, or fail.
    fn pump(protocol: *Protocol) Directive {
        var turn: u32 = 0;
        while (true) {
            turn += 1;
            assert(turn <= pump_turns_max);

            // A message we owe the peer takes priority over parsing theirs.
            if (protocol.version_received and !protocol.verack_sent) {
                protocol.verack_sent = true;
                log.debug("-> verack", .{});
                const frame = message.frame_in_place(&protocol.send_buffer, protocol.options.magic, "verack", 0);
                return .{ .send = frame };
            }
            if (protocol.handshake_done() and !protocol.getaddr_sent) {
                protocol.getaddr_sent = true;
                log.debug("-> getaddr", .{});
                const frame = message.frame_in_place(&protocol.send_buffer, protocol.options.magic, "getaddr", 0);
                return .{ .send = frame };
            }

            if (protocol.recv_len < header_len) return .recv;
            const header = message.parse_header(
                protocol.recv_bytes[0..header_len],
                protocol.options.magic,
            ) catch |err| return .{ .fail = err };

            const total = header_len + header.payload_len;
            if (total > recv_buffer_len) return .{ .fail = error.MessageTooLarge };
            if (protocol.recv_len < total) return .recv;

            protocol.handle_message(
                &header.command,
                &header.checksum,
                protocol.recv_bytes[header_len..total],
            ) catch |err| return .{ .fail = err };
            protocol.consume(total);

            if (protocol.addr_received) {
                log.debug("<- addr ({d} address(es))", .{protocol.discovered_len});
                return .done;
            }
        }
    }

    fn handshake_done(protocol: *const Protocol) bool {
        return protocol.version_received and protocol.verack_sent and protocol.verack_received;
    }

    fn handle_message(
        protocol: *Protocol,
        command: *const [message.command_len]u8,
        checksum: *const [message.checksum_len]u8,
        payload: []const u8,
    ) DialError!void {
        assert(payload.len <= recv_buffer_len - header_len);

        if (message.command_eql(command, "version")) {
            if (payload.len > version.version_payload_max) return error.MessageTooLarge;
            if (!std.mem.eql(u8, &message.double_sha256_prefix(payload), checksum)) {
                return error.ChecksumMismatch;
            }
            try version.parse_version(&protocol.peer_info, payload);
            protocol.version_received = true;
            log.debug("<- version (protocol={d}, services=0x{x}, user_agent={s})", .{
                protocol.peer_info.protocol_version,
                protocol.peer_info.services,
                protocol.peer_info.user_agent(),
            });
        } else if (message.command_eql(command, "verack")) {
            protocol.verack_received = true;
            log.debug("<- verack", .{});
        } else if (protocol.getaddr_sent and message.command_eql(command, "addr")) {
            protocol.discovered_len = addr.parse_addr(payload, &protocol.discovered, min_addr_time());
            protocol.addr_received = true;
        } else {
            log.debug("<- {s} ({d} bytes, ignored)", .{
                message.command_name(command), payload.len,
            });
        }
    }

    /// Drop the consumed `total` bytes from the front of the receive buffer.
    fn consume(protocol: *Protocol, total: u32) void {
        assert(total >= header_len);
        assert(total <= protocol.recv_len);
        const rest = protocol.recv_len - total;
        std.mem.copyForwards(
            u8,
            protocol.recv_bytes[0..rest],
            protocol.recv_bytes[total..protocol.recv_len],
        );
        protocol.recv_len = rest;
    }
};

/// The oldest `addr` timestamp we will keep: now minus `addr_max_age_s`, or 0
/// if the clock is somehow before that.
fn min_addr_time() u32 {
    const now = version.unix_seconds();
    if (now <= addr_max_age_s) return 0;
    return @intCast(now - addr_max_age_s);
}
