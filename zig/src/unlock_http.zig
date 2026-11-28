//! Pure request parsing and policy for nas-unlock-api. Nothing here does I/O,
//! so every parser is fuzzed directly.

const std = @import("std");
const secret = @import("secret.zig");
const validate = @import("validate.zig");
const Secret = secret.Secret;

pub const max_body_bytes = 8192;
pub const max_head_bytes = 32 * 1024;
pub const max_headers = 100;
pub const admin_group = "nas_admin";

// --------------------------------------------------------------- outcomes

/// Every way a request can be refused. It is a closed error set, so the
/// exhaustive switch in `rejectionResponse` must name each one.
pub const Rejection = error{
    not_found,
    method_not_allowed,
    bad_request_line,
    headers_too_large,
    forbidden_origin,
    forbidden_session,
    transfer_encoding,
    not_json,
    length_required,
    body_too_large,
    truncated,
    invalid_json,
    bad_shape,
    password_missing,
    password_too_long,
    password_control,
    setup_incomplete,
    busy,
    throttled,
};

pub const Activation = union(enum) {
    unlocked,
    wrong_password,
    rolled_back: u8,
    timed_out,
    spawn_failed,
};

pub const Response = struct {
    status: u16,
    reason: []const u8,
    message: []const u8,
    retry_after: ?u32 = null,
};

pub fn rejectionResponse(r: Rejection, retry_after: u32) Response {
    return switch (r) {
        error.not_found => .{ .status = 404, .reason = "Not Found", .message = "Not found" },
        error.method_not_allowed => .{ .status = 501, .reason = "Not Implemented", .message = "Unsupported method" },
        error.bad_request_line => .{ .status = 400, .reason = "Bad Request", .message = "Bad request" },
        error.headers_too_large => .{ .status = 431, .reason = "Request Header Fields Too Large", .message = "Request headers are too large" },
        error.forbidden_origin => .{ .status = 403, .reason = "Forbidden", .message = "Unlock requests must come from the unlock page." },
        error.forbidden_session => .{ .status = 403, .reason = "Forbidden", .message = "Unlocking requires an Authentik nas_admin session." },
        error.transfer_encoding => .{ .status = 400, .reason = "Bad Request", .message = "Transfer-Encoding is not supported." },
        error.not_json => .{ .status = 415, .reason = "Unsupported Media Type", .message = "Unlock requests must be JSON." },
        error.length_required => .{ .status = 411, .reason = "Length Required", .message = "Unlock requests require one Content-Length header." },
        error.body_too_large => .{ .status = 413, .reason = "Payload Too Large", .message = "Unlock request is too large." },
        error.truncated => .{ .status = 400, .reason = "Bad Request", .message = "Unlock request was truncated." },
        error.invalid_json => .{ .status = 400, .reason = "Bad Request", .message = "Unlock request is not valid JSON." },
        error.bad_shape => .{ .status = 400, .reason = "Bad Request", .message = "Unlock request must contain only the password." },
        error.password_missing => .{ .status = 400, .reason = "Bad Request", .message = "Enter the KeePass database password." },
        error.password_too_long => .{ .status = 400, .reason = "Bad Request", .message = "The KeePass database password is too long." },
        error.password_control => .{ .status = 400, .reason = "Bad Request", .message = "The KeePass database password must be a single line without control characters." },
        error.setup_incomplete => .{ .status = 409, .reason = "Conflict", .message = "First-start setup is not complete." },
        error.busy => .{ .status = 409, .reason = "Conflict", .message = "An unlock attempt is already running." },
        error.throttled => .{ .status = 429, .reason = "Too Many Requests", .message = "Too many failed unlock attempts; retry later.", .retry_after = retry_after },
    };
}

pub fn activationResponse(a: Activation) ?Response {
    return switch (a) {
        .unlocked => null,
        .wrong_password => .{ .status = 401, .reason = "Unauthorized", .message = "The KeePass database password was not accepted." },
        .rolled_back => .{ .status = 500, .reason = "Internal Server Error", .message = "Activation failed and was rolled back; the NAS stays locked. Inspect `journalctl -t nas-unlock-api` or unlock from the recovery console." },
        .timed_out => .{ .status = 504, .reason = "Gateway Timeout", .message = "Unlock timed out; inspect the appliance journal." },
        .spawn_failed => .{ .status = 500, .reason = "Internal Server Error", .message = "Activation could not start; the NAS stays locked. Unlock from the recovery console." },
    };
}

/// Whether the throttle counts the attempt as a failure.
pub fn activationSucceeded(a: Activation) bool {
    return switch (a) {
        .unlocked => true,
        .wrong_password, .rolled_back, .timed_out, .spawn_failed => false,
    };
}

// ------------------------------------------------------------------ head

pub const Method = enum { GET, POST, other };

pub const Header = struct { name: []const u8, value: []const u8 };

pub const Head = struct {
    method: Method,
    target: []const u8,
    headers: [max_headers]Header = undefined,
    count: usize = 0,

    pub fn all(self: *const Head, name: []const u8, out: [][]const u8) usize {
        var n: usize = 0;
        for (self.headers[0..self.count]) |h| {
            if (std.ascii.eqlIgnoreCase(h.name, name)) {
                if (n < out.len) out[n] = h.value;
                n += 1;
            }
        }
        return n;
    }

    pub fn first(self: *const Head, name: []const u8) ?[]const u8 {
        var one: [1][]const u8 = undefined;
        return if (self.all(name, &one) > 0) one[0] else null;
    }

    /// Exactly one occurrence, else null.
    pub fn single(self: *const Head, name: []const u8) ?[]const u8 {
        var one: [1][]const u8 = undefined;
        return if (self.all(name, &one) == 1) one[0] else null;
    }
};

/// Parses everything before the blank line. `bytes` excludes the final CRLFCRLF.
pub fn parseHead(bytes: []const u8) Rejection!Head {
    var lines = std.mem.splitSequence(u8, bytes, "\r\n");
    const request_line = lines.next() orelse return error.bad_request_line;
    var parts = std.mem.splitScalar(u8, request_line, ' ');
    const method_text = parts.next() orelse return error.bad_request_line;
    const target = parts.next() orelse return error.bad_request_line;
    const version = parts.next() orelse return error.bad_request_line;
    if (parts.next() != null or target.len == 0 or !std.mem.startsWith(u8, version, "HTTP/1.")) return error.bad_request_line;
    for (target) |c| if (c <= 0x20 or c == 0x7f) return error.bad_request_line;
    var head: Head = .{
        .method = if (std.mem.eql(u8, method_text, "GET")) .GET else if (std.mem.eql(u8, method_text, "POST")) .POST else .other,
        .target = target,
    };
    while (lines.next()) |line| {
        if (line.len == 0) return error.bad_request_line;
        if (line[0] == ' ' or line[0] == '\t') return error.bad_request_line;
        const colon = std.mem.indexOfScalar(u8, line, ':') orelse return error.bad_request_line;
        const name = line[0..colon];
        if (name.len == 0) return error.bad_request_line;
        for (name) |c| if (c <= 0x20 or c >= 0x7f) return error.bad_request_line;
        if (head.count == max_headers) return error.headers_too_large;
        head.headers[head.count] = .{ .name = name, .value = std.mem.trim(u8, line[colon + 1 ..], " \t") };
        head.count += 1;
    }
    return head;
}

// ------------------------------------------------------------- policy

/// Proof that the request came from the unlock page of this host and carries
/// an Authentik `nas_admin` session. `activate` requires one.
pub const AdminSession = struct {
    user: []const u8,

    pub fn authorize(head: *const Head) Rejection!AdminSession {
        try requireSameOrigin(head);
        var users: [2][]const u8 = undefined;
        var groups: [2][]const u8 = undefined;
        if (head.all("Remote-User", &users) != 1 or users[0].len == 0) return error.forbidden_session;
        if (head.all("Remote-Groups", &groups) != 1 or !groupsIncludeAdmin(groups[0])) return error.forbidden_session;
        return .{ .user = users[0] };
    }
};

pub fn groupsIncludeAdmin(header: []const u8) bool {
    var it = std.mem.tokenizeAny(u8, header, "|,");
    while (it.next()) |raw| {
        if (std.mem.eql(u8, std.mem.trim(u8, raw, " \t\r\n\x0b\x0c"), admin_group)) return true;
    }
    return false;
}

fn requireSameOrigin(head: *const Head) Rejection!void {
    var origins: [2][]const u8 = undefined;
    var hosts: [2][]const u8 = undefined;
    if (head.all("Origin", &origins) != 1 or head.all("Host", &hosts) != 1) return error.forbidden_origin;
    var host_buf: [256]u8 = undefined;
    var origin_buf: [300]u8 = undefined;
    if (hosts[0].len > host_buf.len or origins[0].len > origin_buf.len) return error.forbidden_origin;
    const host = std.ascii.lowerString(&host_buf, hosts[0]);
    const origin = std.ascii.lowerString(&origin_buf, origins[0]);
    const authority = parseAuthority(host) orelse return error.forbidden_origin;
    if (!std.mem.startsWith(u8, origin, "https://")) return error.forbidden_origin;
    const rest = origin["https://".len..];
    if (!std.mem.startsWith(u8, rest, authority.hostname)) return error.forbidden_origin;
    const tail = rest[authority.hostname.len..];
    const default_port = authority.port == null or std.mem.eql(u8, authority.port.?, "443");
    if (default_port) {
        if (tail.len == 0 or std.mem.eql(u8, tail, ":443")) return;
        return error.forbidden_origin;
    }
    if (tail.len == authority.port.?.len + 1 and tail[0] == ':' and std.mem.eql(u8, tail[1..], authority.port.?)) return;
    return error.forbidden_origin;
}

const Authority = struct { hostname: []const u8, port: ?[]const u8 };

/// `([a-z0-9_.-]+|\[[0-9a-f:.]+\])(?::([0-9]+))?` over the lowercased Host.
fn parseAuthority(host: []const u8) ?Authority {
    var end: usize = 0;
    if (host.len > 0 and host[0] == '[') {
        const close = std.mem.indexOfScalar(u8, host, ']') orelse return null;
        if (close < 2) return null;
        for (host[1..close]) |c| switch (c) {
            '0'...'9', 'a'...'f', ':', '.' => {},
            else => return null,
        };
        end = close + 1;
    } else {
        while (end < host.len) : (end += 1) switch (host[end]) {
            'a'...'z', '0'...'9', '_', '.', '-' => {},
            else => break,
        };
        if (end == 0) return null;
    }
    const hostname = host[0..end];
    if (end == host.len) return .{ .hostname = hostname, .port = null };
    if (host[end] != ':' or end + 1 == host.len) return null;
    const port = host[end + 1 ..];
    for (port) |c| if (!std.ascii.isDigit(c)) return null;
    return .{ .hostname = hostname, .port = port };
}

pub const BodyFraming = struct { length: usize };

/// Header checks that come before reading any body byte.
pub fn bodyFraming(head: *const Head) Rejection!BodyFraming {
    if (head.first("Transfer-Encoding") != null) return error.transfer_encoding;
    const ct_raw = head.first("Content-Type") orelse "";
    const ct_main = std.mem.trim(u8, if (std.mem.indexOfScalar(u8, ct_raw, ';')) |i| ct_raw[0..i] else ct_raw, " \t");
    if (!std.ascii.eqlIgnoreCase(ct_main, "application/json")) return error.not_json;
    const cl = std.mem.trim(u8, head.single("Content-Length") orelse return error.length_required, " \t");
    if (cl.len == 0) return error.length_required;
    for (cl) |c| if (!std.ascii.isDigit(c)) return error.length_required;
    const length = std.fmt.parseInt(usize, cl, 10) catch return error.body_too_large;
    if (length > max_body_bytes) return error.body_too_large;
    return .{ .length = length };
}

/// A validated KeePass password taken from the request body.
pub const UnlockRequest = struct {
    password: Secret,

    pub fn deinit(self: *UnlockRequest) void {
        self.password.deinit();
    }

    /// `body` holds secret bytes and must come from `z`.
    pub fn parse(z: *secret.ZeroingAllocator, body: []const u8) Rejection!UnlockRequest {
        var arena: std.heap.ArenaAllocator = .init(z.allocator());
        defer arena.deinit();
        const value = std.json.parseFromSliceLeaky(std.json.Value, arena.allocator(), body, .{
            .duplicate_field_behavior = .use_last,
            .allocate = .alloc_always,
        }) catch return error.invalid_json;
        const object = switch (value) {
            .object => |o| o,
            else => return error.bad_shape,
        };
        if (object.count() != 1) return error.bad_shape;
        const field = object.get("password") orelse return error.bad_shape;
        const text = switch (field) {
            .string => |s| s,
            else => return error.password_missing,
        };
        if (text.len == 0) return error.password_missing;
        const cps = std.unicode.utf8CountCodepoints(text) catch return error.invalid_json;
        if (cps > validate.max_secret_codepoints) return error.password_too_long;
        for (text) |c| if (c < 0x20 or c == 0x7f) return error.password_control;
        return .{ .password = Secret.copyOf(z, text) catch return error.invalid_json };
    }
};

// ------------------------------------------------------------- throttle

pub const backoff_base_seconds = 5;
pub const backoff_max_seconds = 300;

/// Single-flight activation with exponential delay after failures. KDBX key
/// derivation already slows each guess; this bounds how fast one session
/// can drive guesses through the root process. Generic over the clock so
/// tests control time.
pub fn Throttle(comptime Clock: type) type {
    return struct {
        const Self = @This();
        clock: Clock,
        running: bool = false,
        failures: u32 = 0,
        not_before_ns: i96 = 0,
        mutex: std.atomic.Mutex = .unlocked,

        pub const Ticket = struct { throttle: *Self };

        fn lock(self: *Self) void {
            while (!self.mutex.tryLock()) std.atomic.spinLoopHint();
        }

        fn unlock(self: *Self) void {
            self.mutex.unlock();
        }

        pub fn retryAfter(self: *Self) u32 {
            self.lock();
            defer self.unlock();
            return self.retryAfterLocked();
        }

        fn retryAfterLocked(self: *Self) u32 {
            const wait = self.not_before_ns - self.clock.nowNs();
            if (wait <= 0) return 0;
            // Python: int(wait + 0.999)
            return @intCast(@divFloor(wait + 999_000_000, std.time.ns_per_s));
        }

        pub fn busy(self: *Self) bool {
            self.lock();
            defer self.unlock();
            return self.running;
        }

        /// The returned ticket is the only way to call `release`.
        pub fn acquire(self: *Self, retry_after: *u32) error{ busy, throttled }!Ticket {
            self.lock();
            defer self.unlock();
            if (self.running) return error.busy;
            const seconds = self.retryAfterLocked();
            retry_after.* = seconds;
            if (seconds > 0) return error.throttled;
            self.running = true;
            return .{ .throttle = self };
        }

        pub fn release(ticket: Ticket, succeeded: bool) void {
            const self = ticket.throttle;
            self.lock();
            defer self.unlock();
            self.running = false;
            if (succeeded) {
                self.failures = 0;
                self.not_before_ns = 0;
                return;
            }
            self.failures +|= 1;
            const shift: u6 = @intCast(@min(self.failures - 1, 16));
            const delay: i96 = @min(@as(i96, backoff_base_seconds) << shift, backoff_max_seconds);
            self.not_before_ns = self.clock.nowNs() + delay * std.time.ns_per_s;
        }
    };
}

// ------------------------------------------------------------------ JSON

/// `json.dumps(payload, sort_keys=True)` for the fixed response shapes.
pub fn errorBody(buf: []u8, message: []const u8) []const u8 {
    return std.fmt.bufPrint(buf, "{{\"error\": \"{s}\"}}", .{message}) catch unreachable;
}

pub fn statusBody(buf: []u8, s: struct { busy: bool, locked: bool, retry: u32, setup: bool }) []const u8 {
    return std.fmt.bufPrint(buf, "{{\"busy\": {}, \"locked\": {}, \"retryAfterSeconds\": {d}, \"setupComplete\": {}}}", .{ s.busy, s.locked, s.retry, s.setup }) catch unreachable;
}

pub const unlocked_body = "{\"locked\": false, \"unlocked\": true}";

// ----------------------------------------------------------------- tests

const testing = std.testing;

fn headOf(comptime text: []const u8) !Head {
    return parseHead(text);
}

test "same origin follows the Python contract" {
    const ok = [_][2][]const u8{
        .{ "nas.local:8443", "https://nas.local:8443" },
        .{ "nas.local", "https://nas.local" },
        .{ "nas.local", "https://nas.local:443" },
        .{ "NAS.local:443", "https://nas.local" },
        .{ "[::1]:8443", "https://[::1]:8443" },
    };
    for (ok) |case| {
        var buf: [256]u8 = undefined;
        const text = try std.fmt.bufPrint(&buf, "POST / HTTP/1.1\r\nHost: {s}\r\nOrigin: {s}", .{ case[0], case[1] });
        const head = try parseHead(text);
        try requireSameOrigin(&head);
    }
    const bad = [_][2][]const u8{
        .{ "nas.local:8443", "https://evil.example" },
        .{ "nas.local:8443", "http://nas.local:8443" },
        .{ "nas.local:8443", "null" },
        .{ "nas.local:8443", "https://nas.local" },
        .{ "nas.local", "https://nas.local.evil" },
        .{ "nas.local:", "https://nas.local:" },
        .{ "bad host", "https://bad host" },
    };
    for (bad) |case| {
        var buf: [256]u8 = undefined;
        const text = try std.fmt.bufPrint(&buf, "POST / HTTP/1.1\r\nHost: {s}\r\nOrigin: {s}", .{ case[0], case[1] });
        const head = parseHead(text) catch continue;
        try testing.expectError(error.forbidden_origin, requireSameOrigin(&head));
    }
}

test "group header parsing" {
    try testing.expect(groupsIncludeAdmin("users|nas_admin"));
    try testing.expect(groupsIncludeAdmin("nas_admin, users"));
    try testing.expect(!groupsIncludeAdmin("nas_admins|users"));
    try testing.expect(!groupsIncludeAdmin(""));
}

test "admin session requires exactly one user and group header" {
    const good = try headOf("POST / HTTP/1.1\r\nHost: a\r\nOrigin: https://a\r\nRemote-User: alice\r\nRemote-Groups: users|nas_admin");
    const session = try AdminSession.authorize(&good);
    try testing.expectEqualStrings("alice", session.user);
    const twice = try headOf("POST / HTTP/1.1\r\nHost: a\r\nOrigin: https://a\r\nRemote-User: alice\r\nRemote-User: bob\r\nRemote-Groups: nas_admin");
    try testing.expectError(error.forbidden_session, AdminSession.authorize(&twice));
}

test "body framing" {
    const te = try headOf("POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\nContent-Type: application/json");
    try testing.expectError(error.transfer_encoding, bodyFraming(&te));
    const form = try headOf("POST / HTTP/1.1\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 3");
    try testing.expectError(error.not_json, bodyFraming(&form));
    const two = try headOf("POST / HTTP/1.1\r\nContent-Type: application/json; charset=utf-8\r\nContent-Length: 3\r\nContent-Length: 3");
    try testing.expectError(error.length_required, bodyFraming(&two));
    const big = try headOf("POST / HTTP/1.1\r\nContent-Type: application/json\r\nContent-Length: 8193");
    try testing.expectError(error.body_too_large, bodyFraming(&big));
    const ok = try headOf("POST / HTTP/1.1\r\nContent-Type: Application/JSON\r\nContent-Length: 12");
    try testing.expectEqual(@as(usize, 12), (try bodyFraming(&ok)).length);
}

test "unlock request contract" {
    var z: secret.ZeroingAllocator = .init(testing.allocator);
    var ok = try UnlockRequest.parse(&z, "{\"password\": \"correct horse\"}");
    defer ok.deinit();
    try testing.expect(ok.password.eqlPublic("correct horse"));
    const cases = .{
        .{ "{not json", error.invalid_json },
        .{ "{\"password\": \"x\", \"extra\": 1}", error.bad_shape },
        .{ "[\"password\"]", error.bad_shape },
        .{ "{\"password\": \"\"}", error.password_missing },
        .{ "{\"password\": 5}", error.password_missing },
        .{ "{\"password\": \"a\\nb\"}", error.password_control },
    };
    inline for (cases) |case| try testing.expectError(case[1], UnlockRequest.parse(&z, case[0]));
    var dup = try UnlockRequest.parse(&z, "{\"password\": \"a\", \"password\": \"b\"}");
    defer dup.deinit();
    try testing.expect(dup.password.eqlPublic("b"));
    const long = "{\"password\": \"" ++ @as([5000]u8, @splat('x')) ++ "\"}";
    try testing.expectError(error.password_too_long, UnlockRequest.parse(&z, long));
}

const FakeClock = struct {
    now: *i96,
    pub fn nowNs(self: FakeClock) i96 {
        return self.now.*;
    }
};

test "backoff doubles, caps and resets" {
    var now: i96 = 100 * std.time.ns_per_s;
    var t: Throttle(FakeClock) = .{ .clock = .{ .now = &now } };
    var retry: u32 = 0;
    const first = try t.acquire(&retry);
    try testing.expectError(error.busy, t.acquire(&retry));
    Throttle(FakeClock).release(first, false);
    try testing.expectEqual(@as(u32, backoff_base_seconds), t.retryAfter());
    try testing.expectError(error.throttled, t.acquire(&retry));
    try testing.expectEqual(@as(u32, backoff_base_seconds), retry);
    now += backoff_base_seconds * std.time.ns_per_s;
    Throttle(FakeClock).release(try t.acquire(&retry), false);
    try testing.expectEqual(@as(u32, 2 * backoff_base_seconds), t.retryAfter());
    now += 10_000 * std.time.ns_per_s;
    for (0..20) |_| {
        Throttle(FakeClock).release(try t.acquire(&retry), false);
        now += backoff_max_seconds * std.time.ns_per_s;
    }
    try testing.expect(t.retryAfter() <= backoff_max_seconds);
    Throttle(FakeClock).release(try t.acquire(&retry), true);
    try testing.expectEqual(@as(u32, 0), t.retryAfter());
}

test "every outcome maps to a response" {
    inline for (@typeInfo(Activation).@"union".field_names) |name| {
        const a: Activation = if (comptime std.mem.eql(u8, name, "rolled_back")) .{ .rolled_back = 1 } else @unionInit(Activation, name, {});
        const r = activationResponse(a);
        try testing.expectEqual(r == null, activationSucceeded(a));
    }
    try testing.expectEqual(@as(u16, 401), activationResponse(.wrong_password).?.status);
    try testing.expectEqual(@as(u16, 500), activationResponse(.{ .rolled_back = 71 }).?.status);
    try testing.expectEqual(@as(u16, 504), activationResponse(.timed_out).?.status);
}

test "fuzz: head parser and policy are total" {
    try testing.fuzz({}, struct {
        fn one(_: void, smith: *testing.Smith) anyerror!void {
            var buf: [512]u8 = undefined;
            const n = smith.slice(&buf);
            const head = parseHead(buf[0..n]) catch return;
            _ = AdminSession.authorize(&head) catch {};
            _ = bodyFraming(&head) catch {};
        }
    }.one, .{ .corpus = &.{
        "POST /unlock/api/activate HTTP/1.1\r\nHost: nas.local:8443\r\nOrigin: https://nas.local:8443\r\nRemote-User: alice\r\nRemote-Groups: users|nas_admin\r\nContent-Type: application/json\r\nContent-Length: 10",
    } });
}

test "fuzz: unlock request parser never accepts an invalid password" {
    try testing.fuzz({}, struct {
        fn one(_: void, smith: *testing.Smith) anyerror!void {
            var buf: [256]u8 = undefined;
            const n = smith.slice(&buf);
            var z: secret.ZeroingAllocator = .init(testing.allocator);
            var req = UnlockRequest.parse(&z, buf[0..n]) catch return;
            defer req.deinit();
            try testing.expect(req.password.len() > 0);
            try testing.expect(req.password.satisfies(struct {
                fn f(b: []const u8) bool {
                    for (b) |c| if (c < 0x20 or c == 0x7f) return false;
                    return std.unicode.utf8ValidateSlice(b);
                }
            }.f));
        }
    }.one, .{ .corpus = &.{ "{\"password\": \"correct horse battery staple\"}", "{\"password\": \"\\u0000\"}" } });
}
