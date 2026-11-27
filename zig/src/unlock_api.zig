//! nas-unlock-api: Authentik-gated browser unlock for a locked appliance.
//!
//! The locked Caddy configuration routes /unlock/api/* here only after
//! forward authentication and a `nas_admin` check. This process runs as root
//! because `nas-secrets activate-stdin` loads ZFS keys and restarts the
//! protected target; it accepts nothing but the KeePass password and passes it
//! on stdin.
//!
//!   nas-unlock-api --socket-path /run/nas-unlock/unlock.sock
//!
//! Environment (non-secret): NAS_SECRET_READY, NAS_SETUP_STATE,
//! NAS_SECRETS_BIN, NAS_SYSTEMCTL, NAS_CADDY_USER, NAS_CADDY_GROUP.

const std = @import("std");
const Io = std.Io;
const build_options = @import("build_options");
const http = @import("unlock_http.zig");
const command = @import("command.zig");
const secret = @import("secret.zig");
const validate = @import("validate.zig");
const keepass = @import("keepass.zig");
const log = @import("log.zig");
const sys = @import("sys.zig");

const socket_timeout_seconds = 30;
const max_connections = 8;
const default_activation_timeout: Io.Duration = .fromSeconds(900);
const restore_timeout: Io.Duration = .fromSeconds(180);
const locked_identity_units = [_][]const u8{ "authentik-worker.service", "authentik.service", "nas-authentik-proxy-outpost.service" };

fn syslog(comptime fmt: []const u8, args: anytype) void {
    log.syslog("nas-unlock-api", fmt, args);
}

const MonotonicClock = struct {
    io: Io,
    pub fn nowNs(self: MonotonicClock) i96 {
        return Io.Clock.now(.awake, self.io).nanoseconds;
    }
};

const Server = struct {
    io: Io,
    gpa: std.mem.Allocator,
    z: *secret.ZeroingAllocator,
    secret_ready: [:0]const u8,
    setup_state: [:0]const u8,
    nas_secrets: []const u8,
    systemctl: []const u8,
    allowed_uids: []const sys.uid_t,
    activation_timeout: Io.Duration,
    throttle: http.Throttle(MonotonicClock),
    connections: std.atomic.Value(u32) = .init(0),

    fn isLocked(self: *Server) bool {
        const st = sys.stat(self.secret_ready) catch return true;
        return st.kind != .regular;
    }

    fn setupComplete(self: *Server) bool {
        const st = sys.stat(self.setup_state) catch return false;
        return st.kind == .regular;
    }

    fn runner(self: *Server) command.Runner {
        return .{ .io = self.io, .gpa = self.gpa, .z = self.z, .privilege = .direct };
    }

    /// Requires both proofs: an authorised session and a validated password.
    fn activate(self: *Server, session: http.AdminSession, request: *const http.UnlockRequest) http.Activation {
        _ = session;
        var out = self.runner().run(
            .{ self.nas_secrets, "activate-stdin" },
            secret.Payload.lines(1, .{&request.password}),
            .{ .stdout = .capture, .stderr = .capture, .timeout = self.activation_timeout },
        ) catch |err| switch (err) {
            error.Timeout => {
                syslog("nas-unlock-api: nas-secrets activate-stdin timed out", .{});
                return .timed_out;
            },
            else => {
                syslog("nas-unlock-api: nas-secrets could not be started: {t}", .{err});
                return .spawn_failed;
            },
        };
        defer out.deinit();
        if (out.exit.ok()) return .unlocked;
        // nas-secrets never prints secret values; keep the tail for the journal only.
        logTail(out.stderr);
        if (std.mem.indexOf(u8, out.stderr, keepass.wrong_password_marker) != null) return .wrong_password;
        return .{ .rolled_back = out.exit.status() };
    }

    /// Rollback stops nas-protected-services.target, which also stops Authentik
    /// through PartOf=. Without this the browser unlock path would disappear
    /// until the next boot.
    fn restoreLockedIdentity(self: *Server) void {
        if (!self.isLocked()) return;
        var out = self.runner().run(.{ self.systemctl, "start", @as([]const []const u8, &locked_identity_units) }, null, .{
            .stderr = .capture,
            .timeout = restore_timeout,
            .grace = .fromSeconds(5),
        }) catch return;
        out.deinit();
    }
};

fn logTail(stderr: []const u8) void {
    const trimmed = std.mem.trim(u8, stderr, " \t\r\n");
    var count: usize = 0;
    var it = std.mem.splitBackwardsScalar(u8, trimmed, '\n');
    while (it.next()) |_| count += 1;
    var skip = if (count > 20) count - 20 else 0;
    var lines = std.mem.splitScalar(u8, trimmed, '\n');
    while (lines.next()) |line| {
        if (skip > 0) {
            skip -= 1;
            continue;
        }
        var buf: [500]u8 = undefined;
        syslog("nas-unlock-api: nas-secrets: {s}", .{log.sanitize(&buf, line)});
    }
}

// --------------------------------------------------------------- per request

const Conn = struct {
    server: *Server,
    fd: sys.fd_t,

    fn respond(self: Conn, r: http.Response, body: []const u8) void {
        var head: [512]u8 = undefined;
        var retry: [48]u8 = undefined;
        const retry_line = if (r.retry_after) |s| (if (s > 0) std.fmt.bufPrint(&retry, "Retry-After: {d}\r\n", .{s}) catch "" else "") else "";
        const text = std.fmt.bufPrint(&head, "HTTP/1.0 {d} {s}\r\nServer: nas-unlock-api/1\r\nContent-Type: application/json\r\nContent-Length: {d}\r\nCache-Control: no-store\r\n{s}Connection: close\r\n\r\n", .{ r.status, r.reason, body.len, retry_line }) catch return;
        sys.writeAll(self.fd, text) catch return;
        sys.writeAll(self.fd, body) catch return;
    }

    fn ok(self: Conn, body: []const u8) void {
        self.respond(.{ .status = 200, .reason = "OK", .message = "" }, body);
    }

    fn reject(self: Conn, err: http.Rejection, retry_after: u32) void {
        var r = http.rejectionResponse(err, retry_after);
        var msg: [128]u8 = undefined;
        if (err == error.throttled) r.message = std.fmt.bufPrint(&msg, "Too many failed unlock attempts; retry in {d} seconds.", .{retry_after}) catch r.message;
        var body: [512]u8 = undefined;
        self.respond(r, http.errorBody(&body, r.message));
        sys.shutdownWrite(self.fd);
        // A client may be writing its body in a separate syscall. Give it a
        // bounded opportunity to finish so closing the socket delivers the rejection.
        sys.setReadTimeout(self.fd, 100) catch return;
        var discard: [http.max_body_bytes]u8 = undefined;
        defer std.crypto.secureZero(u8, &discard);
        _ = sys.read(self.fd, &discard) catch return;
    }

    fn handle(self: Conn) void {
        var buf: [http.max_head_bytes + 4]u8 = undefined;
        // A read can include password bytes before the request head is validated.
        defer std.crypto.secureZero(u8, &buf);
        var len: usize = 0;
        const head_end = while (true) {
            if (std.mem.indexOf(u8, buf[0..len], "\r\n\r\n")) |i| break i;
            if (len == buf.len) return self.reject(error.headers_too_large, 0);
            const n = sys.read(self.fd, buf[len..]) catch return;
            if (n == 0) return;
            len += n;
        };
        const head = http.parseHead(buf[0..head_end]) catch |err| return self.reject(err, 0);
        const leftover = buf[head_end + 4 .. len];
        switch (head.method) {
            .GET => self.handleGet(&head),
            .POST => self.handlePost(&head, leftover),
            .other => self.reject(error.method_not_allowed, 0),
        }
    }

    fn handleGet(self: Conn, head: *const http.Head) void {
        if (!std.mem.eql(u8, head.target, "/unlock/api/status")) return self.reject(error.not_found, 0);
        const s = self.server;
        var body: [256]u8 = undefined;
        self.ok(http.statusBody(&body, .{ .busy = s.throttle.busy(), .locked = s.isLocked(), .retry = s.throttle.retryAfter(), .setup = s.setupComplete() }));
    }

    fn handlePost(self: Conn, head: *const http.Head, leftover: []const u8) void {
        var retry: u32 = 0;
        self.post(head, leftover, &retry) catch |err| self.reject(err, retry);
    }

    fn post(self: Conn, head: *const http.Head, leftover: []const u8, retry: *u32) http.Rejection!void {
        const s = self.server;
        if (!std.mem.eql(u8, head.target, "/unlock/api/activate")) return error.not_found;
        const session = try http.AdminSession.authorize(head);
        const framing = try http.bodyFraming(head);

        const body = s.z.allocator().alloc(u8, framing.length) catch return error.truncated;
        defer s.z.allocator().free(body);
        const have = @min(leftover.len, body.len);
        @memcpy(body[0..have], leftover[0..have]);
        var filled = have;
        while (filled < body.len) {
            const n = sys.read(self.fd, body[filled..]) catch return error.truncated;
            if (n == 0) return error.truncated;
            filled += n;
        }
        var request = try http.UnlockRequest.parse(s.z, body);
        defer request.deinit();

        if (!s.setupComplete()) return error.setup_incomplete;
        if (!s.isLocked()) return self.ok(http.unlocked_body);

        const ticket = try s.throttle.acquire(retry);
        syslog("nas-unlock-api: unlock attempt by Authentik user '{s}'", .{sanitizeUser(session.user)});
        const outcome = s.activate(session, &request);
        const succeeded = http.activationSucceeded(outcome);
        http.Throttle(MonotonicClock).release(ticket, succeeded);
        if (!succeeded) s.restoreLockedIdentity();

        switch (outcome) {
            .unlocked => {
                syslog("nas-unlock-api: unlocked by Authentik user '{s}'", .{sanitizeUser(session.user)});
                self.ok(http.unlocked_body);
            },
            .rolled_back => |status| {
                var msg: [256]u8 = undefined;
                var r = http.activationResponse(outcome).?;
                r.message = std.fmt.bufPrint(&msg, "Activation failed (status {d}) and was rolled back; the NAS stays locked. Inspect `journalctl -t nas-unlock-api` or unlock from the recovery console.", .{status}) catch r.message;
                var b: [512]u8 = undefined;
                self.respond(r, http.errorBody(&b, r.message));
            },
            .wrong_password, .timed_out, .spawn_failed => {
                const r = http.activationResponse(outcome).?;
                var b: [512]u8 = undefined;
                self.respond(r, http.errorBody(&b, r.message));
            },
        }
    }
};

threadlocal var user_buf: [128]u8 = undefined;

fn sanitizeUser(user: []const u8) []const u8 {
    return log.sanitize(&user_buf, user);
}

fn serveConnection(server: *Server, fd: sys.fd_t) void {
    defer {
        sys.close(fd);
        _ = server.connections.fetchSub(1, .seq_cst);
    }
    const conn: Conn = .{ .server = server, .fd = fd };
    conn.handle();
}

fn peerAllowed(server: *Server, fd: sys.fd_t) bool {
    const cred = sys.peerCredentials(fd) catch return false;
    return std.mem.indexOfScalar(sys.uid_t, server.allowed_uids, cred.uid) != null;
}

fn serveForever(server: *Server, listener: sys.fd_t) noreturn {
    while (true) {
        const fd = sys.accept(listener) catch continue;
        if (!peerAllowed(server, fd)) {
            sys.close(fd);
            continue;
        }
        if (server.connections.fetchAdd(1, .seq_cst) >= max_connections) {
            _ = server.connections.fetchSub(1, .seq_cst);
            sys.close(fd);
            continue;
        }
        sys.setTimeouts(fd, socket_timeout_seconds) catch {};
        const thread = std.Thread.spawn(.{ .stack_size = 1024 * 1024 }, serveConnection, .{ server, fd }) catch {
            _ = server.connections.fetchSub(1, .seq_cst);
            sys.close(fd);
            continue;
        };
        thread.detach();
    }
}

// ------------------------------------------------------------------ main

fn envOr(environ: *const std.process.Environ.Map, name: []const u8, default: []const u8) []const u8 {
    return environ.get(name) orelse default;
}

pub fn main(init: std.process.Init) u8 {
    const io = init.io;
    const arena = init.arena.allocator();
    const environ = init.environ_map;
    sys.disableCoreDumps();
    const args = init.minimal.args.toSlice(arena) catch return 1;

    var socket_arg: ?[]const u8 = null;
    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        const a: []const u8 = args[i];
        if (std.mem.eql(u8, a, "--help") or std.mem.eql(u8, a, "-h")) {
            log.out("usage: nas-unlock-api --socket-path SOCKET_PATH", .{});
            return 0;
        }
        if (std.mem.eql(u8, a, "--socket-path") and i + 1 < args.len) {
            i += 1;
            socket_arg = args[i];
        } else if (std.mem.startsWith(u8, a, "--socket-path=")) {
            socket_arg = a["--socket-path=".len..];
        } else {
            log.err("usage: nas-unlock-api --socket-path SOCKET_PATH", .{});
            return 2;
        }
    }
    const socket_text = socket_arg orelse {
        log.err("usage: nas-unlock-api --socket-path SOCKET_PATH", .{});
        log.err("nas-unlock-api: error: the following arguments are required: --socket-path", .{});
        return 2;
    };

    const allow_nonroot = build_options.test_harness and environ.get("NAS_UNLOCK_TEST_ALLOW_NONROOT") != null;
    if (sys.geteuid() != 0 and !allow_nonroot) {
        log.err("nas-unlock-api must run as root", .{});
        return 1;
    }
    const socket_path = validate.AbsSocketPath.parse(socket_text) catch {
        log.err("nas-unlock-api requires an absolute socket path", .{});
        return 1;
    };

    var allowed: std.ArrayList(sys.uid_t) = .empty;
    allowed.append(arena, 0) catch return 1;
    if (sys.lookupUid(envOr(environ, "NAS_CADDY_USER", "caddy"))) |uid| allowed.append(arena, uid) catch return 1;
    if (comptime build_options.test_harness) {
        if (environ.get("NAS_UNLOCK_TEST_ALLOWED_UID")) |text| {
            allowed.clearRetainingCapacity();
            allowed.append(arena, std.fmt.parseInt(sys.uid_t, text, 10) catch return 1) catch return 1;
        }
    }

    var timeout = default_activation_timeout;
    if (comptime build_options.test_harness) {
        if (environ.get("NAS_UNLOCK_TEST_LOG")) |path| {
            const pz = arena.dupeSentinel(u8, path, 0) catch return 1;
            log.syslog_test_fd = sys.open(pz, .{ .ACCMODE = .WRONLY, .CREAT = true, .APPEND = true }, 0o600) catch return 1;
        }
        if (environ.get("NAS_UNLOCK_TEST_ACTIVATION_TIMEOUT_MS")) |text| timeout = .fromMilliseconds(std.fmt.parseInt(i64, text, 10) catch return 1);
    }

    var server: Server = .{
        .io = io,
        .gpa = init.gpa,
        .z = &secret.process_zeroing,
        .secret_ready = arena.dupeSentinel(u8, envOr(environ, "NAS_SECRET_READY", "/run/nas-secret-runtime/live/ready"), 0) catch return 1,
        .setup_state = arena.dupeSentinel(u8, envOr(environ, "NAS_SETUP_STATE", "/var/lib/nas-setup/state.json"), 0) catch return 1,
        .nas_secrets = envOr(environ, "NAS_SECRETS_BIN", "nas-secrets"),
        .systemctl = envOr(environ, "NAS_SYSTEMCTL", "systemctl"),
        .allowed_uids = allowed.items,
        .activation_timeout = timeout,
        .throttle = .{ .clock = .{ .io = io } },
    };

    const path_z = arena.dupeSentinel(u8, socket_path.path, 0) catch return 1;
    if (sys.lstat(path_z)) |st| {
        if (st.kind == .socket) sys.unlink(path_z) catch {};
    } else |_| {}
    const listener = sys.unixListen(socket_path.path, 16) catch |err| {
        log.err("nas-unlock-api: unable to listen on {s}: {t}", .{ socket_path.path, err });
        return 1;
    };
    const group = envOr(environ, "NAS_CADDY_GROUP", "");
    if (group.len > 0) {
        const gid = sys.lookupGid(group) orelse {
            log.err("nas-unlock-api: unknown group {s}", .{group});
            return 1;
        };
        sys.chown(path_z, 0, gid) catch |err| {
            log.err("nas-unlock-api: unable to set the socket group: {t}", .{err});
            return 1;
        };
    }
    sys.chmod(path_z, 0o660) catch |err| {
        log.err("nas-unlock-api: unable to set the socket mode: {t}", .{err});
        return 1;
    };
    syslog("nas-unlock-api listening on unix:{s}", .{socket_path.path});
    if (comptime build_options.test_harness) {
        // Lets tests wait for readiness without polling the socket.
        if (environ.get("NAS_UNLOCK_TEST_READY_FD")) |text| {
            const fd = std.fmt.parseInt(sys.fd_t, text, 10) catch return 1;
            sys.writeAll(fd, "ready\n") catch {};
            sys.close(fd);
        }
    }
    serveForever(&server, listener);
}
