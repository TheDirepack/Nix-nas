//! Diagnostics. Formatting a `Secret` is a compile error (see secret.zig),
//! so nothing printed here can contain secret bytes.

const std = @import("std");
const sys = @import("sys.zig");

pub fn err(comptime fmt: []const u8, args: anytype) void {
    var buf: [4096]u8 = undefined;
    const text = std.fmt.bufPrint(&buf, fmt ++ "\n", args) catch blk: {
        buf[buf.len - 4 ..][0..4].* = "...\n".*;
        break :blk buf[0..];
    };
    sys.writeAll(2, text) catch {};
}

pub fn out(comptime fmt: []const u8, args: anytype) void {
    var buf: [4096]u8 = undefined;
    const text = std.fmt.bufPrint(&buf, fmt ++ "\n", args) catch return;
    sys.writeAll(1, text) catch {};
}

/// Test-harness builds may redirect syslog lines to a file descriptor.
pub var syslog_test_fd: ?sys.fd_t = null;

/// RFC 3164 datagram to /dev/log with facility user, severity notice, like
/// Python's `syslog.syslog(LOG_NOTICE, ...)` after `openlog(ident)`.
pub fn syslog(comptime ident: []const u8, comptime fmt: []const u8, args: anytype) void {
    var buf: [2048]u8 = undefined;
    if (syslog_test_fd) |fd| {
        const line = std.fmt.bufPrint(&buf, fmt ++ "\n", args) catch return;
        sys.writeAll(fd, line) catch {};
        return;
    }
    const text = std.fmt.bufPrint(&buf, "<13>" ++ ident ++ ": " ++ fmt, args) catch return;
    sys.syslogDatagram(text);
}

/// Bytes from a child's stderr are untrusted: keep printable ASCII only.
pub fn sanitize(out_buf: []u8, text: []const u8) []const u8 {
    const n = @min(out_buf.len, text.len);
    for (text[0..n], 0..) |c, i| out_buf[i] = if (c >= 0x20 and c < 0x7f) c else '?';
    return out_buf[0..n];
}
