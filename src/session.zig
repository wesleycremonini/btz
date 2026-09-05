//! The Bitcoin P2P peer conversation, as a `connection.Connection` protocol.
//!
//! `Protocol` is a pure state machine: fed peer bytes and send / deadline
//! events by the connection, it returns `Directive`s. For now it runs the
//! `version` / `verack` handshake and records the peer's `version` into
//! `PeerInfo`; `getaddr` discovery lands on top of this. No I/O, no allocation.
//!
//! `Peer` is `Connection(Protocol)` — the type `crawl.zig` pools.

const std = @import("std");
const assert = std.debug.assert;

const net = std.Io.net;
const connection = @import("connection.zig");
const message = @import("message.zig");
const version = @import("version.zig");
const peer_types = @import("peer.zig");
const Directive = connection.Directive;
const PeerInfo = peer_types.PeerInfo;
const DialError = peer_types.DialError;
const header_len = message.header_len;
const log = std.log.scoped(.p2p);

/// `Connection(Protocol)` — the crawler's per-peer slot. `Peer.Options` is
/// `Protocol.Options` is `version.Options`.
pub const Peer = connection.Connection(Protocol);

/// Receive buffer. Must hold the largest single message we parse whole (a
/// `version`) plus its header; other messages are consumed and dropped.
const recv_buffer_len = 4 * 1024;

/// Send buffer: one framed message at a time; our `version` is the largest.
const frame_buffer_len = header_len + version.version_payload_max;

/// Bound on `pump` turns: each consumes at least one buffered message or emits
/// one directive, so the buffer capacity caps it.
const pump_turns_max = recv_buffer_len / header_len + 4;

comptime {
    assert(recv_buffer_len >= header_len + version.version_payload_max);
    assert(frame_buffer_len >= header_len + version.version_payload_max);
}

pub const Protocol = struct {
    /// Dial parameters. `connection.Connection` requires this decl.
    pub const Options = version.Options;

    options: Options,
    address: net.IpAddress,

    peer_info: PeerInfo,

    send_buffer: [frame_buffer_len]u8,
    recv_bytes: [recv_buffer_len]u8,
    recv_len: u32,

    version_received: bool,
    verack_sent: bool,
    verack_received: bool,

    pub fn reset(protocol: *Protocol, address: net.IpAddress, options: Options) void {
        assert(options.magic != 0);
        assert(options.user_agent.len > 0);
        assert(options.user_agent.len <= peer_types.max_user_agent_len);
        protocol.* = .{
            .options = options,
            .address = address,
            .peer_info = undefined,
            .send_buffer = undefined,
            .recv_bytes = undefined,
            .recv_len = 0,
            .version_received = false,
            .verack_sent = false,
            .verack_received = false,
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
        _ = protocol;
        return .{ .fail = error.Timeout };
    }

    /// Consume whole buffered messages, advancing the handshake. Returns the
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
            if (protocol.version_received and protocol.verack_sent and protocol.verack_received) {
                return .done;
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
        }
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
