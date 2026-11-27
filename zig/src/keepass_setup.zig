//! nas-keepass-setup: the KeePass part of first-start setup.
//!
//!   nas-keepass-setup check-strength [--with-administrator]
//!       stdin: password\n [administrator password\n]
//!   nas-keepass-setup verifier-create
//!       stdin: keepass\0 (username\0password\0)*
//!       stdout: {"algorithm": ..., "digest": ..., "salt": ...}
//!   nas-keepass-setup verifier-match
//!       stdin: algorithm\0salt\0digest\0 keepass\0 (username\0password\0)*
//!       exit 0 on match, 1 on mismatch
//!   nas-keepass-setup legacy-authenticators
//!       stdin: as verifier-create; stdout: {"user": "hex", ...}
//!   nas-keepass-setup database {verify|create} --database PATH [--key-file PATH]
//!                     [--managed-dataset {plain|encrypted}]
//!       stdin: password\n
//!
//! Exit 2 is a refusal whose reason is the only line on stderr. Everything
//! secret arrives on stdin; argv holds only paths and modes.

const std = @import("std");
const Io = std.Io;
const secret = @import("secret.zig");
const validate = @import("validate.zig");
const command = @import("command.zig");
const log = @import("log.zig");
const sys = @import("sys.zig");
const Secret = secret.Secret;

pub const verifier_algorithm = "scrypt-n32768-r8-p1";
const scrypt_params: std.crypto.pwhash.scrypt.Params = .{ .ln = 15, .r = 8, .p = 1 };
const legacy_prefix = "nixos-nas/setup-password-fingerprint/v2\x00";
pub const decryption_time_ms = "1000";
const max_stdin = 1024 * 1024;

const Refusal = error{Refused};

fn refuse(comptime fmt: []const u8, args: anytype) Refusal {
    log.err(fmt, args);
    return error.Refused;
}

// ------------------------------------------------------------------ input

/// NUL-separated secret fields read from stdin into zeroing memory.
const Fields = struct {
    data: Secret,
    z: *secret.ZeroingAllocator,

    fn read(z: *secret.ZeroingAllocator, reader: *Io.Reader) Refusal!Fields {
        var list: std.ArrayList(u8) = .empty;
        errdefer list.deinit(z.allocator());
        while (true) {
            const b = reader.takeByte() catch break;
            if (list.items.len == max_stdin) return refuse("Setup secret input is too large", .{});
            list.append(z.allocator(), b) catch return refuse("Out of memory", .{});
        }
        const owned = list.toOwnedSlice(z.allocator()) catch return refuse("Out of memory", .{});
        return .{ .data = Secret.adopt(z, owned) catch return refuse("Out of memory", .{}), .z = z };
    }

    fn deinit(self: *Fields) void {
        self.data.deinit();
    }
};

/// Splits `Fields` into owned secrets; the split happens inside a predicate
/// so the raw buffer never leaves the secret module's view.
fn splitFields(z: *secret.ZeroingAllocator, fields: *const Fields, out: *std.ArrayList(Secret), a: std.mem.Allocator) Refusal!void {
    const Split = struct { z: *secret.ZeroingAllocator, out: *std.ArrayList(Secret), a: std.mem.Allocator, failed: bool = false };
    var ctx: Split = .{ .z = z, .out = out, .a = a };
    _ = fields.data.satisfiesWith(struct {
        fn f(bytes: []const u8, c: *Split) bool {
            if (bytes.len == 0) return true;
            if (bytes[bytes.len - 1] != 0) {
                c.failed = true;
                return false;
            }
            var it = std.mem.splitScalar(u8, bytes[0 .. bytes.len - 1], 0);
            while (it.next()) |field| {
                const s = Secret.copyOf(c.z, field) catch {
                    c.failed = true;
                    return false;
                };
                c.out.append(c.a, s) catch {
                    var t = s;
                    t.deinit();
                    c.failed = true;
                    return false;
                };
            }
            return true;
        }
    }.f, &ctx);
    if (ctx.failed) return refuse("Setup secret input must be NUL-terminated fields", .{});
}

const Account = struct { username: Secret, password: Secret };

/// Python `sorted((username, password))` over code points, which for UTF-8 is
/// byte order.
fn lessThan(_: void, x: Account, y: Account) bool {
    const first = x.username.order(y.username);
    if (first != .eq) return first == .lt;
    return x.password.order(y.password) == .lt;
}

const Plan = struct {
    keepass: Secret,
    accounts: []Account,
    all: std.ArrayList(Secret),
    a: std.mem.Allocator,

    fn deinit(self: *Plan) void {
        for (self.all.items) |*s| s.deinit();
        self.all.deinit(self.a);
        self.a.free(self.accounts);
    }
};

fn parsePlan(z: *secret.ZeroingAllocator, a: std.mem.Allocator, items: std.ArrayList(Secret)) Refusal!Plan {
    var all = items;
    if (all.items.len == 0 or (all.items.len - 1) % 2 != 0) {
        for (all.items) |*s| s.deinit();
        all.deinit(a);
        return refuse("Account plan is invalid", .{});
    }
    _ = z;
    const n = (all.items.len - 1) / 2;
    const accounts = a.alloc(Account, n) catch return refuse("Out of memory", .{});
    for (accounts, 0..) |*acc, i| acc.* = .{ .username = all.items[1 + 2 * i], .password = all.items[2 + 2 * i] };
    std.mem.sort(Account, accounts, {}, lessThan);
    return .{ .keepass = all.items[0], .accounts = accounts, .all = all, .a = a };
}

/// `json.dumps({"keepass": ..., "accounts": [[u, p], ...]}, sort_keys=True,
/// separators=(",", ":"))`, byte for byte.
fn canonicalMaterial(z: *secret.ZeroingAllocator, plan: *const Plan) Refusal!Secret {
    var b: secret.Builder = .init(z);
    defer b.deinit();
    const oom = "Out of memory";
    b.appendPublic("{\"accounts\":[") catch return refuse(oom, .{});
    for (plan.accounts, 0..) |acc, i| {
        if (i > 0) b.appendPublic(",") catch return refuse(oom, .{});
        b.appendPublic("[") catch return refuse(oom, .{});
        b.appendJsonString(acc.username) catch return refuse("Account plan is invalid", .{});
        b.appendPublic(",") catch return refuse(oom, .{});
        b.appendJsonString(acc.password) catch return refuse("Account plan is invalid", .{});
        b.appendPublic("]") catch return refuse(oom, .{});
    }
    b.appendPublic("],\"keepass\":") catch return refuse(oom, .{});
    b.appendJsonString(plan.keepass) catch return refuse("KeePass database password must be valid UTF-8", .{});
    b.appendPublic("}") catch return refuse(oom, .{});
    return b.finish() catch refuse(oom, .{});
}

fn digestHex(z: *secret.ZeroingAllocator, plan: *const Plan, salt: []const u8) Refusal![64]u8 {
    var material = try canonicalMaterial(z, plan);
    defer material.deinit();
    var out: [32]u8 = undefined;
    secret.scrypt(material, z, salt, scrypt_params, &out) catch return refuse("scrypt failed", .{});
    return std.fmt.bytesToHex(out, .lower);
}

// --------------------------------------------------------------- commands

const Ctx = struct {
    io: Io,
    gpa: std.mem.Allocator,
    z: *secret.ZeroingAllocator,
    stdin: *Io.Reader,
};

fn readPlan(c: Ctx, skip: usize, header: []Secret) Refusal!Plan {
    var fields = try Fields.read(c.z, c.stdin);
    defer fields.deinit();
    var items: std.ArrayList(Secret) = .empty;
    try splitFields(c.z, &fields, &items, c.gpa);
    if (items.items.len < skip) {
        for (items.items) |*s| s.deinit();
        items.deinit(c.gpa);
        return refuse("Account plan is invalid", .{});
    }
    for (header, items.items[0..skip]) |*h, s| h.* = s;
    const rest: std.ArrayList(Secret) = blk: {
        var r: std.ArrayList(Secret) = .empty;
        r.appendSlice(c.gpa, items.items[skip..]) catch return refuse("Out of memory", .{});
        items.deinit(c.gpa);
        break :blk r;
    };
    return parsePlan(c.z, c.gpa, rest);
}

fn verifierCreate(c: Ctx) Refusal!void {
    var plan = try readPlan(c, 0, &.{});
    defer plan.deinit();
    var salt: [16]u8 = undefined;
    c.io.randomSecure(&salt) catch return refuse("Unable to read OS randomness", .{});
    const digest = try digestHex(c.z, &plan, &salt);
    const salt_hex = std.fmt.bytesToHex(salt, .lower);
    log.out("{{\"algorithm\": \"" ++ verifier_algorithm ++ "\", \"digest\": \"{s}\", \"salt\": \"{s}\"}}", .{ &digest, &salt_hex });
}

fn isLowerHex(bytes: []const u8, width: usize) bool {
    if (bytes.len != width) return false;
    for (bytes) |ch| switch (ch) {
        '0'...'9', 'a'...'f' => {},
        else => return false,
    };
    return true;
}

/// Exit 0 on match, 1 on any mismatch or malformed verifier.
fn verifierMatch(c: Ctx) Refusal!bool {
    var header: [3]Secret = undefined;
    var plan = try readPlan(c, 3, &header);
    defer plan.deinit();
    defer for (&header) |*h| h.deinit();
    if (!header[0].eqlPublic(verifier_algorithm)) return false;
    var salt_hex: [32]u8 = undefined;
    const SaltCopy = struct {
        fn f(bytes: []const u8, dest: *[32]u8) bool {
            if (!isLowerHex(bytes, 32)) return false;
            @memcpy(dest, bytes);
            return true;
        }
    };
    if (!header[1].satisfiesWith(SaltCopy.f, &salt_hex)) return false;
    var salt: [16]u8 = undefined;
    _ = std.fmt.hexToBytes(&salt, &salt_hex) catch return false;
    const expected = try digestHex(c.z, &plan, &salt);
    return header[2].eqlPublic(&expected);
}

fn legacyAuthenticators(c: Ctx) Refusal!void {
    var plan = try readPlan(c, 0, &.{});
    defer plan.deinit();
    var key = secret.sha256Prefixed(legacy_prefix, plan.keepass) catch return refuse("Out of memory", .{});
    defer key.deinit();
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(c.gpa);
    out.append(c.gpa, '{') catch return refuse("Out of memory", .{});
    // Python builds a dict from the sorted list, so a repeated username keeps
    // its last (greatest) password; emit each username once.
    var emitted: usize = 0;
    for (plan.accounts, 0..) |acc, i| {
        if (i + 1 < plan.accounts.len and plan.accounts[i + 1].username.eql(acc.username)) continue;
        var b: secret.Builder = .init(c.z);
        defer b.deinit();
        b.appendSecret(acc.username) catch return refuse("Out of memory", .{});
        b.appendPublic("\x00") catch return refuse("Out of memory", .{});
        b.appendSecret(acc.password) catch return refuse("Out of memory", .{});
        var message = b.finish() catch return refuse("Out of memory", .{});
        defer message.deinit();
        const mac = secret.hmacSha256Secret(key, message);
        if (emitted > 0) out.appendSlice(c.gpa, ", ") catch return refuse("Out of memory", .{});
        // Usernames are public identifiers; they leave as JSON keys.
        var name: std.ArrayList(u8) = .empty;
        defer name.deinit(c.gpa);
        const Dump = struct {
            a: std.mem.Allocator,
            list: *std.ArrayList(u8),
            fn f(bytes: []const u8, ctx: @This()) bool {
                secret.appendPythonJsonString(ctx.a, ctx.list, bytes) catch return false;
                return true;
            }
        };
        if (!acc.username.satisfiesWith(Dump.f, Dump{ .a = c.gpa, .list = &name })) return refuse("Account plan is invalid", .{});
        out.appendSlice(c.gpa, name.items) catch return refuse("Out of memory", .{});
        const hex = std.fmt.bytesToHex(mac, .lower);
        out.print(c.gpa, ": \"{s}\"", .{&hex}) catch return refuse("Out of memory", .{});
        emitted += 1;
    }
    out.append(c.gpa, '}') catch return refuse("Out of memory", .{});
    log.out("{s}", .{out.items});
}

fn checkStrength(c: Ctx, with_admin: bool) Refusal!void {
    var password = validate.readSecretLine(c.z, c.stdin) catch return refuse("KeePass database password must contain exactly one non-empty line without control characters", .{});
    var admin: ?Secret = null;
    defer if (admin) |*a| a.deinit();
    if (with_admin) admin = validate.readSecretLine(c.z, c.stdin) catch return refuse("Administrator password must contain exactly one non-empty line without control characters", .{});
    var strong = validate.StrongKeePassPassword.init(password, admin) catch |err| {
        password.deinit();
        return refuse("{s}", .{validate.StrongKeePassPassword.message(err)});
    };
    strong.deinit();
}

// ------------------------------------------------------------- database

const DatasetState = enum { plain, encrypted };

const DatabaseArgs = struct {
    create: bool,
    database: []const u8,
    key_file: ?[]const u8 = null,
    /// Unknown counts as encrypted: a fresh database would orphan its key.
    dataset: DatasetState = .encrypted,
    keepassxc: []const u8 = "keepassxc-cli",
};

const DatabaseResult = enum { existing, created };

/// Never replace a database once the managed dataset is encrypted; otherwise
/// move an existing one aside with an atomic no-clobber rename.
fn database(c: Ctx, args: DatabaseArgs) Refusal!DatabaseResult {
    var password = validate.readSecretLine(c.z, c.stdin) catch return refuse("KeePass database password must contain exactly one non-empty line without control characters", .{});
    defer password.deinit();
    const runner: command.Runner = .{ .io = c.io, .gpa = c.gpa, .z = c.z, .privilege = .direct };
    const key_args: []const []const u8 = if (args.key_file) |kf| &.{ "--key-file", kf } else &.{};
    const once = secret.Payload.lines(1, .{&password});
    const twice = secret.Payload.lines(2, .{ &password, &password });

    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const path_z = std.fmt.bufPrintSentinel(&path_buf, "{s}", .{args.database}, 0) catch return refuse("KeePass database path is too long", .{});
    const existing = sys.lstat(path_z) catch |err| switch (err) {
        error.FileNotFound => null,
        else => return refuse("Unable to inspect the KeePass database path {s}: {t}", .{ args.database, err }),
    };
    if (existing) |st| if (st.kind != .regular) return refuse("KeePass database path is not a regular file: {s}", .{args.database});

    const Verify = struct {
        fn run(r: command.Runner, cli: []const u8, k: []const []const u8, db: []const u8, p: secret.Payload) bool {
            var out = r.run(.{ cli, "db-info", "--quiet", k, db }, p, .{ .stderr = .inherit }) catch return false;
            defer out.deinit();
            return out.exit.ok();
        }
    };

    if (existing != null and !args.create) {
        if (!Verify.run(runner, args.keepassxc, key_args, args.database, once)) return refuse("Unable to unlock the KeePassXC database.", .{});
        return .existing;
    }
    if (existing != null) {
        switch (args.dataset) {
            .encrypted => {
                // The encrypted dataset's only key lives in this database.
                if (!Verify.run(runner, args.keepassxc, key_args, args.database, once))
                    return refuse("The managed ZFS dataset is already encrypted with a key held in {s}. Setup never replaces that database; retry with its password.", .{args.database});
                return .existing;
            },
            .plain => {
                var stamp: [32]u8 = undefined;
                const preserved = preservedName(c.io, &path_buf, args.database, &stamp) catch return refuse("KeePass database path is too long", .{});
                var old_buf: [std.fs.max_path_bytes]u8 = undefined;
                const old_z = std.fmt.bufPrintSentinel(&old_buf, "{s}", .{args.database}, 0) catch return refuse("KeePass database path is too long", .{});
                sys.renameNoReplace(old_z, preserved) catch |err|
                    return refuse("Unable to move the existing KeePassXC database aside to {s}: {t}", .{ preserved, err });
                if (sys.lexists(old_z) catch true) return refuse("Unable to move the existing KeePassXC database aside to {s}", .{preserved});
                log.out("kept the previous KeePassXC database as {s}", .{preserved});
            },
        }
    }
    if (!args.create) return refuse("KeePass database does not exist: {s}", .{args.database});
    var create = runner.run(.{
        args.keepassxc,                                                      "db-create",   "--quiet",     "--set-password", "--decryption-time", decryption_time_ms,
        if (args.key_file) |_| @as(?[]const u8, "--set-key-file") else null, args.key_file, args.database,
    }, twice, .{ .stderr = .inherit }) catch return refuse("Unable to run keepassxc-cli db-create", .{});
    defer create.deinit();
    if (!create.exit.ok()) return refuse("keepassxc-cli db-create failed (status {d})", .{create.exit.status()});
    var new_buf: [std.fs.max_path_bytes]u8 = undefined;
    const new_z = std.fmt.bufPrintSentinel(&new_buf, "{s}", .{args.database}, 0) catch unreachable;
    if (!(sys.lexists(new_z) catch false)) return refuse("KeePassXC did not create {s}", .{args.database});
    if (!Verify.run(runner, args.keepassxc, key_args, args.database, once)) return refuse("Unable to unlock the newly created KeePassXC database.", .{});
    return .created;
}

fn preservedName(io: Io, buf: []u8, db: []const u8, stamp: []u8) error{NoSpaceLeft}![:0]const u8 {
    const now = Io.Clock.now(.real, io);
    const secs: u64 = @intCast(@divFloor(now.nanoseconds, std.time.ns_per_s));
    const es: std.time.epoch.EpochSeconds = .{ .secs = secs };
    const day = es.getEpochDay().calculateYearDay();
    const md = day.calculateMonthDay();
    const ds = es.getDaySeconds();
    const s = try std.fmt.bufPrint(stamp, "{d:0>4}{d:0>2}{d:0>2}T{d:0>2}{d:0>2}{d:0>2}Z", .{
        day.year, md.month.numeric(), md.day_index + 1, ds.getHoursIntoDay(), ds.getMinutesIntoHour(), ds.getSecondsIntoMinute(),
    });
    return std.fmt.bufPrintSentinel(buf, "{s}.replaced-{s}", .{ db, s }, 0);
}

// ------------------------------------------------------------------ main

const usage_text = "usage: nas-keepass-setup {check-strength [--with-administrator]|verifier-create|verifier-match|legacy-authenticators|database (verify|create) --database PATH [--key-file PATH] [--managed-dataset plain|encrypted]}";

fn usage() u8 {
    log.err("{s}", .{usage_text});
    return 2;
}

pub fn main(init: std.process.Init) u8 {
    sys.disableCoreDumps();
    const arena = init.arena.allocator();
    const args = init.minimal.args.toSlice(arena) catch return 1;
    if (args.len < 2) return usage();
    var stdin_buf: [4096]u8 = undefined;
    defer std.crypto.secureZero(u8, &stdin_buf);
    var reader = Io.File.stdin().readerStreaming(init.io, &stdin_buf);
    const c: Ctx = .{ .io = init.io, .gpa = init.gpa, .z = &secret.process_zeroing, .stdin = &reader.interface };
    const verb: []const u8 = args[1];
    if (std.mem.eql(u8, verb, "--help") or std.mem.eql(u8, verb, "-h")) {
        log.out("{s}", .{usage_text});
        return 0;
    }

    if (std.mem.eql(u8, verb, "check-strength")) {
        const with_admin = args.len == 3 and std.mem.eql(u8, args[2], "--with-administrator");
        if (args.len > 3 or (args.len == 3 and !with_admin)) return usage();
        checkStrength(c, with_admin) catch return 2;
        return 0;
    }
    if (std.mem.eql(u8, verb, "verifier-create")) {
        verifierCreate(c) catch return 2;
        return 0;
    }
    if (std.mem.eql(u8, verb, "verifier-match")) {
        const matched = verifierMatch(c) catch return 2;
        return if (matched) 0 else 1;
    }
    if (std.mem.eql(u8, verb, "legacy-authenticators")) {
        legacyAuthenticators(c) catch return 2;
        return 0;
    }
    if (std.mem.eql(u8, verb, "database")) {
        if (args.len < 3) return usage();
        var dbargs: DatabaseArgs = .{ .create = undefined, .database = "" };
        if (std.mem.eql(u8, args[2], "create")) dbargs.create = true else if (std.mem.eql(u8, args[2], "verify")) dbargs.create = false else return usage();
        var i: usize = 3;
        while (i + 1 < args.len) : (i += 2) {
            const flag: []const u8 = args[i];
            const value: []const u8 = args[i + 1];
            if (std.mem.eql(u8, flag, "--database")) dbargs.database = value else if (std.mem.eql(u8, flag, "--key-file")) dbargs.key_file = if (value.len == 0) null else value else if (std.mem.eql(u8, flag, "--keepassxc-cli")) dbargs.keepassxc = value else if (std.mem.eql(u8, flag, "--managed-dataset")) {
                dbargs.dataset = std.meta.stringToEnum(DatasetState, value) orelse return usage();
            } else return usage();
        }
        if (i != args.len or dbargs.database.len == 0 or dbargs.database[0] != '/') return usage();
        const result = database(c, dbargs) catch return 2;
        log.out("{t}", .{result});
        return 0;
    }
    return usage();
}

// ----------------------------------------------------------------- tests

const testing = std.testing;

fn planOf(z: *secret.ZeroingAllocator, keepass: []const u8, accounts: []const [2][]const u8) !Plan {
    var items: std.ArrayList(Secret) = .empty;
    try items.append(testing.allocator, try Secret.copyOf(z, keepass));
    for (accounts) |acc| {
        try items.append(testing.allocator, try Secret.copyOf(z, acc[0]));
        try items.append(testing.allocator, try Secret.copyOf(z, acc[1]));
    }
    return parsePlan(z, testing.allocator, items) catch error.TestUnexpectedResult;
}

test "canonical material matches Python json.dumps" {
    var z: secret.ZeroingAllocator = .init(testing.allocator);
    var plan = try planOf(&z, "keepass \u{e9}", &.{ .{ "nasadmin", "pw\"1" }, .{ "alice", "x" } });
    defer plan.deinit();
    var m = try canonicalMaterial(&z, &plan);
    defer m.deinit();
    try testing.expect(m.eqlPublic("{\"accounts\":[[\"alice\",\"x\"],[\"nasadmin\",\"pw\\\"1\"]],\"keepass\":\"keepass \\u00e9\"}"));
}

test "scrypt digest is deterministic for a salt" {
    var z: secret.ZeroingAllocator = .init(testing.allocator);
    var plan = try planOf(&z, "keepass database passphrase", &.{.{ "nasadmin", "administrator-password" }});
    defer plan.deinit();
    const salt: [16]u8 = @splat(0);
    const a = try digestHex(&z, &plan, &salt);
    const b = try digestHex(&z, &plan, &salt);
    try testing.expectEqualStrings(&a, &b);
}

test "preserved name is a sibling with a UTC stamp" {
    var buf: [256]u8 = undefined;
    var stamp: [32]u8 = undefined;
    const name = try preservedName(testing.io, &buf, "/var/lib/x/NAS.kdbx", &stamp);
    try testing.expect(std.mem.startsWith(u8, name, "/var/lib/x/NAS.kdbx.replaced-"));
    try testing.expect(std.mem.endsWith(u8, name, "Z"));
}
