//! Child processes with a compile-time-checked argv.
//!
//! `argv` elements are inspected at compile time: any type that is, points
//! to, or contains a `Secret` is a compile error, so secrets can only reach a
//! child through `secret.Payload` on stdin. `Runner.privileged` (sudo) takes
//! no payload at all and always gives the child /dev/null, so sudo can never
//! consume payload stdin.

const std = @import("std");
const Io = std.Io;
const secret = @import("secret.zig");
const validate = @import("validate.zig");
const Secret = secret.Secret;

pub const max_args = 48;

// ------------------------------------------------------- argv checking

fn containsSecret(comptime T: type) bool {
    if (T == Secret or T == secret.Payload or T == secret.Part or T == validate.StrongKeePassPassword) return true;
    return switch (@typeInfo(T)) {
        .pointer => |p| p.child != u8 and containsSecret(p.child),
        .optional => |o| containsSecret(o.child),
        .array => |a| a.child != u8 and containsSecret(a.child),
        .@"struct" => |s| inline for (s.field_types) |F| {
            if (containsSecret(F)) break true;
        } else false,
        .@"union" => |u| inline for (u.field_types) |F| {
            if (containsSecret(F)) break true;
        } else false,
        else => false,
    };
}

const ArgKind = enum { text, optional_text, list, unit, target };

fn argKind(comptime T: type) ArgKind {
    if (comptime containsSecret(T))
        @compileError("nas: " ++ @typeName(T) ++ " carries secret material and can never be a command-line argument; send it on stdin with secret.Payload");
    if (T == validate.UnitName) return .unit;
    if (T == validate.TargetName) return .target;
    if (T == []const []const u8) return .list;
    switch (@typeInfo(T)) {
        .pointer => |p| {
            if (p.size == .slice and p.child == u8) return .text;
            if (p.size == .one) switch (@typeInfo(p.child)) {
                .array => |a| if (a.child == u8) return .text,
                else => {},
            };
        },
        .optional => |o| if (argKind(o.child) == .text) return .optional_text,
        else => {},
    }
    @compileError("nas: unsupported argv element type " ++ @typeName(T));
}

pub const Argv = struct {
    items: [max_args][]const u8 = undefined,
    len: usize = 0,

    fn push(self: *Argv, value: []const u8) error{TooManyArguments}!void {
        if (self.len == max_args) return error.TooManyArguments;
        self.items[self.len] = value;
        self.len += 1;
    }

    pub fn slice(self: *const Argv) []const []const u8 {
        return self.items[0..self.len];
    }
};

/// Flattens a tuple of argv elements. Null optionals are omitted and
/// `[]const []const u8` lists are spliced in place.
pub fn argv(args: anytype) error{TooManyArguments}!Argv {
    var out: Argv = .{};
    const info = @typeInfo(@TypeOf(args)).@"struct";
    inline for (info.field_names, info.field_types) |name, T| {
        const value = @field(args, name);
        switch (comptime argKind(T)) {
            .text => try out.push(value),
            .optional_text => if (value) |v| try out.push(v),
            .list => for (value) |v| try out.push(v),
            .unit => try out.push(value.name),
            .target => try out.push(value.name),
        }
    }
    return out;
}

// --------------------------------------------------------------- running

pub const Stream = enum { capture, discard, inherit };

pub const Options = struct {
    stdout: Stream = .discard,
    stderr: Stream = .discard,
    /// Applies only while output is being captured.
    timeout: ?Io.Duration = null,
    /// Signal sent first when the timeout expires, so the child can roll back.
    grace: Io.Duration = .fromSeconds(60),
};

pub const Exit = union(enum) {
    code: u8,
    signal: u32,
    other,

    pub fn ok(self: Exit) bool {
        return switch (self) {
            .code => |c| c == 0,
            .signal, .other => false,
        };
    }

    /// Shell-style status (`128 + signal`).
    pub fn status(self: Exit) u8 {
        return switch (self) {
            .code => |c| c,
            .signal => |s| @intCast(@min(255, 128 + s)),
            .other => 255,
        };
    }
};

pub const Output = struct {
    exit: Exit,
    stdout: []u8,
    stderr: []u8,
    allocator: std.mem.Allocator,

    pub fn deinit(self: *Output) void {
        self.allocator.free(self.stdout);
        self.allocator.free(self.stderr);
    }
};

pub const SecretOutput = struct {
    exit: Exit,
    value: Secret,
    stderr: []u8,
    allocator: std.mem.Allocator,

    pub fn deinit(self: *SecretOutput) void {
        self.value.deinit();
        self.allocator.free(self.stderr);
    }
};

pub const Error = error{
    TooManyArguments,
    SpawnFailed,
    PayloadWriteFailed,
    OutputFailed,
    Timeout,
    OutOfMemory,
};

pub const Privilege = enum {
    /// Already root, or a test with privilege disabled.
    direct,
    sudo,
};

pub const Runner = struct {
    io: Io,
    gpa: std.mem.Allocator,
    z: *secret.ZeroingAllocator,
    privilege: Privilege,
    sudo: []const u8 = "sudo",
    /// Environment for children; null inherits.
    environ: ?*const std.process.Environ.Map = null,

    /// Unprivileged child. `payload` is the only way to give it secret input.
    pub fn run(self: Runner, args: anytype, payload: ?secret.Payload, options: Options) Error!Output {
        const list = try argv(args);
        return self.spawnCollect(list.slice(), payload, options, self.gpa);
    }

    /// Unprivileged child whose stdout is secret (for example `keepassxc-cli show`).
    /// One trailing newline is removed, matching `$(...)`.
    pub fn runSecret(self: Runner, args: anytype, payload: secret.Payload, options: Options) Error!SecretOutput {
        const list = try argv(args);
        var opts = options;
        opts.stdout = .capture;
        opts.stderr = .capture;
        var out = try self.spawnCollectSplit(list.slice(), payload, opts);
        errdefer out.deinit();
        var value_bytes = out.stdout;
        out.stdout = &.{};
        while (value_bytes.len > 0 and value_bytes[value_bytes.len - 1] == '\n') {
            const trimmed = self.z.allocator().realloc(value_bytes, value_bytes.len - 1) catch return error.OutOfMemory;
            value_bytes = trimmed;
        }
        const value = Secret.adopt(self.z, value_bytes) catch return error.OutOfMemory;
        return .{ .exit = out.exit, .value = value, .stderr = out.stderr, .allocator = self.gpa };
    }

    /// Root-privileged child via sudo when not already root. There is no
    /// payload parameter: stdin is always /dev/null.
    pub fn privileged(self: Runner, args: anytype, options: Options) Error!Output {
        const list = try argv(args);
        var full: Argv = .{};
        if (self.privilege == .sudo) {
            try full.push(self.sudo);
            try full.push("--");
        }
        for (list.slice()) |a| try full.push(a);
        return self.spawnCollect(full.slice(), null, options, self.gpa);
    }

    pub fn privilegedOk(self: Runner, args: anytype) Error!bool {
        var out = try self.privileged(args, .{});
        defer out.deinit();
        return out.exit.ok();
    }

    fn spawnCollectSplit(self: Runner, list: []const []const u8, payload: ?secret.Payload, options: Options) Error!Output {
        // Stdout may hold a secret; stderr never does.
        return self.spawnWith(list, payload, options, self.z.allocator(), self.gpa);
    }

    fn spawnCollect(self: Runner, list: []const []const u8, payload: ?secret.Payload, options: Options, a: std.mem.Allocator) Error!Output {
        return self.spawnWith(list, payload, options, a, a);
    }

    fn spawnWith(self: Runner, list: []const []const u8, payload: ?secret.Payload, options: Options, out_alloc: std.mem.Allocator, err_alloc: std.mem.Allocator) Error!Output {
        const io = self.io;
        const stdio = struct {
            fn map(s: Stream) std.process.SpawnOptions.StdIo {
                return switch (s) {
                    .capture => .pipe,
                    .discard => .ignore,
                    .inherit => .inherit,
                };
            }
        };
        var child = std.process.spawn(io, .{
            .argv = list,
            .environ_map = self.environ,
            .stdin = if (payload != null) .pipe else .ignore,
            .stdout = stdio.map(options.stdout),
            .stderr = stdio.map(options.stderr),
        }) catch return error.SpawnFailed;
        defer child.kill(io);

        if (payload) |p| {
            p.writeToChild(io, &child) catch {
                // A child that exits early (wrong-password paths) closes its
                // pipe; its exit status is the meaningful result.
            };
            if (child.stdin) |f| f.close(io);
            child.stdin = null;
        }

        var stdout_buf: []u8 = &.{};
        var stderr_buf: []u8 = &.{};
        errdefer out_alloc.free(stdout_buf);
        errdefer err_alloc.free(stderr_buf);

        if (child.stdout != null or child.stderr != null) {
            try self.drain(&child, options, out_alloc, err_alloc, &stdout_buf, &stderr_buf);
        }

        const term = child.wait(io) catch return error.OutputFailed;
        const exit: Exit = switch (term) {
            .exited => |c| .{ .code = c },
            .signal => |s| .{ .signal = @backingInt(s) },
            .stopped, .unknown => .other,
        };
        return .{
            .exit = exit,
            .stdout = stdout_buf,
            .stderr = stderr_buf,
            .allocator = if (out_alloc.ptr == err_alloc.ptr) out_alloc else err_alloc,
        };
    }

    fn drain(self: Runner, child: *std.process.Child, options: Options, out_alloc: std.mem.Allocator, err_alloc: std.mem.Allocator, stdout_buf: *[]u8, stderr_buf: *[]u8) Error!void {
        const io = self.io;
        const timeout: Io.Timeout = if (options.timeout) |d| (Io.Timeout{ .duration = .{ .raw = d, .clock = .awake } }).toDeadline(io) else .none;
        // Separate readers keep secret stdout and public stderr in different allocators.
        if (child.stdout) |f| {
            if (child.stderr) |g| {
                var bufs: Io.File.MultiReader.Buffer(2) = undefined;
                var mr: Io.File.MultiReader = undefined;
                mr.init(out_alloc, io, bufs.toStreams(), &.{ f, g });
                defer mr.deinit();
                fillAll(&mr, timeout) catch |err| return self.onDrainError(child, options, err);
                stdout_buf.* = mr.toOwnedSlice(0) catch return error.OutOfMemory;
                const err_bytes = mr.toOwnedSlice(1) catch return error.OutOfMemory;
                defer out_alloc.free(err_bytes);
                stderr_buf.* = err_alloc.dupe(u8, err_bytes) catch return error.OutOfMemory;
                return;
            }
            stdout_buf.* = try readOne(io, out_alloc, f, timeout, self, child, options);
            return;
        }
        if (child.stderr) |g| stderr_buf.* = try readOne(io, err_alloc, g, timeout, self, child, options);
    }

    fn readOne(io: Io, a: std.mem.Allocator, f: Io.File, timeout: Io.Timeout, self: Runner, child: *std.process.Child, options: Options) Error![]u8 {
        var bufs: Io.File.MultiReader.Buffer(1) = undefined;
        var mr: Io.File.MultiReader = undefined;
        mr.init(a, io, bufs.toStreams(), &.{f});
        defer mr.deinit();
        fillAll(&mr, timeout) catch |err| return self.onDrainError(child, options, err);
        return mr.toOwnedSlice(0) catch error.OutOfMemory;
    }

    fn fillAll(mr: *Io.File.MultiReader, timeout: Io.Timeout) DrainError!void {
        while (true) {
            mr.fill(4096, timeout) catch |err| switch (err) {
                error.EndOfStream => break,
                error.Timeout => return error.Timeout,
                else => return error.OutputFailed,
            };
        }
        mr.checkAnyError() catch return error.OutputFailed;
    }

    const DrainError = error{ Timeout, OutputFailed };

    fn onDrainError(self: Runner, child: *std.process.Child, options: Options, err: DrainError) Error {
        if (err == error.Timeout) {
            terminateGracefully(self.io, child, options.grace);
            return error.Timeout;
        }
        return error.OutputFailed;
    }
};

/// SIGTERM lets `nas-secrets` run its rollback; SIGKILL follows after `grace`.
fn terminateGracefully(io: Io, child: *std.process.Child, grace: Io.Duration) void {
    const pid = child.id orelse return;
    _ = std.os.linux.kill(pid, .TERM);
    const deadline = Io.Clock.Timestamp.fromNow(io, .{ .raw = grace, .clock = .awake });
    while (true) {
        var status: i32 = 0;
        const rc = std.os.linux.wait4(pid, &status, std.os.linux.W.NOHANG, null);
        if (std.os.linux.errno(rc) != .SUCCESS or rc == @as(usize, @intCast(pid))) {
            // Reaped here; stop std from waiting on a pid that no longer exists.
            child.id = null;
            closeStreams(io, child);
            return;
        }
        if (deadline.durationFromNow(io).raw.nanoseconds <= 0) break;
        io.sleep(.fromMilliseconds(100), .awake) catch break;
    }
    // `child.kill` in the caller's defer sends SIGKILL and reaps.
}

fn closeStreams(io: Io, child: *std.process.Child) void {
    if (child.stdin) |f| f.close(io);
    if (child.stdout) |f| f.close(io);
    if (child.stderr) |f| f.close(io);
    child.stdin = null;
    child.stdout = null;
    child.stderr = null;
}

// ----------------------------------------------------------------- tests

const testing = std.testing;

test "argv flattens optionals, lists and unit names" {
    const key: ?[]const u8 = null;
    const extra: []const []const u8 = &.{ "--key-file", "/k" };
    const a = try argv(.{ "keepassxc-cli", "ls", key, extra, validate.UnitName.lit("caddy.service") });
    try testing.expectEqual(@as(usize, 5), a.len);
    try testing.expectEqualStrings("caddy.service", a.slice()[4]);
}

test "payload reaches only stdin" {
    var z: secret.ZeroingAllocator = .init(testing.allocator);
    var pw = try Secret.copyOf(&z, "pass word");
    defer pw.deinit();
    const r: Runner = .{ .io = testing.io, .gpa = testing.allocator, .z = &z, .privilege = .direct };
    var out = try r.run(.{ "sh", "-c", "read -r x; printf '%s|%s' \"$x\" \"$#\"" }, secret.Payload.lines(1, .{&pw}), .{ .stdout = .capture });
    defer out.deinit();
    try testing.expect(out.exit.ok());
    try testing.expectEqualStrings("pass word|0", out.stdout);
}

test "secret stdout is captured into zeroing memory and trimmed" {
    var z: secret.ZeroingAllocator = .init(testing.allocator);
    const r: Runner = .{ .io = testing.io, .gpa = testing.allocator, .z = &z, .privilege = .direct };
    var out = try r.runSecret(.{ "printf", "abc\\n\\n" }, .empty, .{});
    defer out.deinit();
    try testing.expect(out.value.eqlPublic("abc"));
}

test "privileged children never see stdin" {
    var z: secret.ZeroingAllocator = .init(testing.allocator);
    const r: Runner = .{ .io = testing.io, .gpa = testing.allocator, .z = &z, .privilege = .direct };
    var out = try r.privileged(.{ "sh", "-c", "cat; echo done" }, .{ .stdout = .capture });
    defer out.deinit();
    try testing.expectEqualStrings("done\n", out.stdout);
}

test "timeouts terminate the child" {
    var z: secret.ZeroingAllocator = .init(testing.allocator);
    const r: Runner = .{ .io = testing.io, .gpa = testing.allocator, .z = &z, .privilege = .direct };
    try testing.expectError(error.Timeout, r.run(.{ "sh", "-c", "sleep 5" }, null, .{
        .stderr = .capture,
        .timeout = .fromMilliseconds(200),
        .grace = .fromMilliseconds(500),
    }));
}

test "exit status mapping" {
    try testing.expectEqual(@as(u8, 143), (Exit{ .signal = 15 }).status());
    try testing.expect(!(Exit{ .code = 1 }).ok());
}
