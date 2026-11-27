//! `nas-secrets`: KeePassXC-backed secret activation for the appliance.
//!
//! Command-line contract (unchanged from the shell implementation):
//!   nas-secrets {init|adopt-authentik-bootstrap-stdin|activate|activate-stdin|
//!                activate-setup-stdin|status|stop|set-authentik-token|
//!                set-authentik-token-stdin|set-authentik-runtime-stdin|
//!                retire-authentik-bootstrap-stdin|check-authentik-token|
//!                show-ntfy-password|show-zfs-key|show-zfs-key-stdin|
//!                show-authentik-bootstrap}
//! Secret input is one bounded line per value on stdin. Exit 125 means the
//! activation rollback was incomplete; 70–74 are activation refusals.

const std = @import("std");
const Io = std.Io;
const build_options = @import("build_options");
const config = @import("config.zig");
const command = @import("command.zig");
const secret = @import("secret.zig");
const validate = @import("validate.zig");
const keepass = @import("keepass.zig");
const transaction = @import("transaction.zig");
const log = @import("log.zig");
const sys = @import("sys.zig");

const cfg = config.value;
const Secret = secret.Secret;
const Entry = keepass.Entry;
const UnitName = validate.UnitName;

const Command = enum {
    init,
    @"adopt-authentik-bootstrap-stdin",
    activate,
    @"activate-stdin",
    @"activate-setup-stdin",
    status,
    stop,
    @"set-authentik-token",
    @"set-authentik-token-stdin",
    @"set-authentik-runtime-stdin",
    @"retire-authentik-bootstrap-stdin",
    @"check-authentik-token",
    @"show-ntfy-password",
    @"show-zfs-key",
    @"show-zfs-key-stdin",
    @"show-authentik-bootstrap",

    /// Mutating commands run under the appliance operation coordinator.
    fn coordinated(self: Command) bool {
        return switch (self) {
            .init,
            .@"adopt-authentik-bootstrap-stdin",
            .activate,
            .@"activate-stdin",
            .@"activate-setup-stdin",
            .stop,
            .@"set-authentik-token",
            .@"set-authentik-token-stdin",
            .@"set-authentik-runtime-stdin",
            .@"retire-authentik-bootstrap-stdin",
            => true,
            .status,
            .@"check-authentik-token",
            .@"show-ntfy-password",
            .@"show-zfs-key",
            .@"show-zfs-key-stdin",
            .@"show-authentik-bootstrap",
            => false,
        };
    }

    fn passwordFromStdin(self: Command) bool {
        return switch (self) {
            .@"adopt-authentik-bootstrap-stdin",
            .@"activate-stdin",
            .@"activate-setup-stdin",
            .@"set-authentik-token-stdin",
            .@"set-authentik-runtime-stdin",
            .@"retire-authentik-bootstrap-stdin",
            .@"show-zfs-key-stdin",
            => true,
            .init,
            .activate,
            .status,
            .stop,
            .@"set-authentik-token",
            .@"check-authentik-token",
            .@"show-ntfy-password",
            .@"show-zfs-key",
            .@"show-authentik-bootstrap",
            => false,
        };
    }
};

const usage = "Usage: nas-secrets {init|adopt-authentik-bootstrap-stdin|activate|activate-stdin|status|stop|set-authentik-token|set-authentik-token-stdin|set-authentik-runtime-stdin|retire-authentik-bootstrap-stdin|check-authentik-token|show-ntfy-password|show-zfs-key|show-zfs-key-stdin|show-authentik-bootstrap}";

/// Every failure path sets `App.status` and returns this.
const Exit = error{Exit};

// --------------------------------------------------------------- signals

var pending_signal: std.atomic.Value(u32) = .init(0);

fn onSignal(sig: std.posix.SIG) callconv(.c) void {
    pending_signal.store(@backingInt(sig), .seq_cst);
}

fn installSignalHandlers() void {
    const action: std.posix.Sigaction = .{
        .handler = .{ .handler = onSignal },
        .mask = std.posix.sigemptyset(),
        .flags = 0,
    };
    for ([_]std.posix.SIG{ .HUP, .INT, .TERM }) |sig| std.posix.sigaction(sig, &action, null);
}

// ------------------------------------------------------------------- app

const App = struct {
    io: Io,
    gpa: std.mem.Allocator,
    arena: std.mem.Allocator,
    z: *secret.ZeroingAllocator,
    environ: *std.process.Environ.Map,
    paths: config.Paths,
    user: command.Runner,
    root: command.Runner,
    stdin: *Io.Reader,
    password_from_stdin: bool = false,
    status: u8 = 0,
    lock_fd: ?sys.fd_t = null,

    fn fail(self: *App, status: u8, comptime fmt: []const u8, args: anytype) Exit {
        log.err(fmt, args);
        self.status = status;
        return error.Exit;
    }

    fn checkInterrupted(self: *App) Exit!void {
        const sig = pending_signal.load(.seq_cst);
        if (sig == 0) return;
        self.status = @intCast(@min(255, 128 + sig));
        return error.Exit;
    }

    fn join(self: *App, parts: []const []const u8) Exit![]const u8 {
        return std.mem.concat(self.arena, u8, parts) catch self.fail(1, "Out of memory.", .{});
    }

    fn joinZ(self: *App, parts: []const []const u8) Exit![:0]const u8 {
        return std.mem.concatWithSentinel(self.arena, u8, parts, 0) catch self.fail(1, "Out of memory.", .{});
    }

    // ------------------------------------------------------------ root ops

    fn rootStep(self: *App, args: anytype) Exit!void {
        var out = self.root.privileged(args, .{ .stderr = .inherit }) catch return self.fail(1, "Unable to run a privileged command.", .{});
        defer out.deinit();
        if (!out.exit.ok()) {
            self.status = out.exit.status();
            return error.Exit;
        }
    }

    fn rootTest(self: *App, flag: []const u8, path: []const u8) bool {
        return self.root.privilegedOk(.{ cfg.tools.test_, flag, path }) catch false;
    }

    fn systemctl(self: *App, args: anytype) bool {
        var out = self.root.privileged(.{cfg.tools.systemctl} ++ args, .{ .stderr = .inherit }) catch return false;
        defer out.deinit();
        return out.exit.ok();
    }

    fn systemctlQuiet(self: *App, args: anytype) bool {
        return self.root.privilegedOk(.{cfg.tools.systemctl} ++ args) catch false;
    }

    // --------------------------------------------------------------- lock

    fn acquireLock(self: *App) Exit!void {
        const path = try self.joinZ(&.{self.paths.lock_file});
        const fd = sys.open(path, .{ .ACCMODE = .WRONLY, .CREAT = true }, 0o600) catch |err|
            return self.fail(1, "Unable to open the NAS secret lock {s}: {t}", .{ self.paths.lock_file, err });
        sys.flockExclusiveNonBlocking(fd) catch {
            sys.close(fd);
            return self.fail(1, "Another NAS secret operation is already running.", .{});
        };
        self.lock_fd = fd;
    }

    // ------------------------------------------------------------- unlock

    fn requireDatabase(self: *App) Exit!void {
        const db = try self.joinZ(&.{self.paths.database});
        const st = sys.stat(db) catch null;
        if (st == null or st.?.kind != .regular) {
            log.err("KeePassXC database not found: {s}", .{self.paths.database});
            return self.fail(1, "Create or restore the KDBX database, then configure nas.secrets.keepassDatabase.", .{});
        }
        if (self.paths.key_file) |kf| {
            const kz = try self.joinZ(&.{kf});
            const kst = sys.stat(kz) catch null;
            if (kst == null or kst.?.kind != .regular) return self.fail(1, "KeePassXC key file not found: {s}", .{kf});
        }
    }

    fn readLine(self: *App) validate.LineError!Secret {
        return validate.readSecretLine(self.z, self.stdin);
    }

    /// Interactive input reads from the same stdin with echo disabled.
    fn promptLine(self: *App, comptime prompt: []const u8) validate.LineError!Secret {
        sys.writeAll(2, prompt) catch {};
        const saved = sys.disableEcho(0);
        defer {
            if (saved) |s| sys.restoreEcho(0, s);
            sys.writeAll(2, "\n") catch {};
        }
        return self.readLine();
    }

    fn promptUnlock(self: *App) Exit!keepass.Unlocked {
        try self.requireDatabase();
        const line = if (self.password_from_stdin) self.readLine() else self.promptLine("KeePass database password: ");
        var password = line catch |err| return switch (err) {
            error.Unreadable => self.fail(1, "Unable to read the KeePass database password from standard input.", .{}),
            error.Empty => self.fail(1, "The KeePass database password cannot be empty.", .{}),
            error.TooLong => self.fail(1, "The KeePass database password exceeds 4096 characters.", .{}),
            error.InvalidUtf8 => self.fail(1, "The KeePass database password must be valid UTF-8.", .{}),
            error.OutOfMemory => self.fail(1, "Out of memory.", .{}),
        };
        const locked: keepass.Locked = .{
            .runner = self.user,
            .cli = cfg.tools.keepassxc_cli,
            .database = self.paths.database,
            .key_file = self.paths.key_file,
            .group = cfg.secret_group,
        };
        return locked.unlock(password) catch {
            password.deinit();
            return self.fail(1, keepass.wrong_password_marker, .{});
        };
    }

    /// Reads one more secret line after the password (adopt/set commands).
    fn readValue(self: *App, comptime what: []const u8) Exit!Secret {
        return self.readLine() catch |err| switch (err) {
            error.Empty => Secret.copyOf(self.z, "") catch self.fail(1, "Out of memory.", .{}),
            error.Unreadable, error.TooLong, error.InvalidUtf8 => self.fail(1, "Unable to read the " ++ what ++ " from standard input.", .{}),
            error.OutOfMemory => self.fail(1, "Out of memory.", .{}),
        };
    }

    /// A further complete line is an error; trailing bytes without `\n` are ignored.
    fn rejectExtraInput(self: *App, comptime context: []const u8) Exit!void {
        var seen: usize = 0;
        while (seen < 65536) : (seen += 1) {
            const byte = self.stdin.takeByte() catch return;
            if (byte == '\n') break;
        }
        return self.fail(1, "Unexpected extra input while " ++ context ++ ".", .{});
    }
};

fn requireHex(app: *App, value: Secret, comptime width: usize, comptime label: []const u8) Exit!void {
    if (!value.satisfiesWith(validate.isHex, width)) return app.fail(1, label ++ " has an unsafe or unexpected format in KeePassXC.", .{});
}

fn requireAtom(app: *App, value: Secret, comptime label: []const u8, comptime min: usize, comptime max: usize) Exit!void {
    const ok = value.satisfiesWith(struct {
        fn f(bytes: []const u8, b: [2]usize) bool {
            return validate.isAtom(bytes, .{ .min = b[0], .max = b[1] });
        }
    }.f, [2]usize{ min, max });
    if (!ok) return app.fail(1, label ++ " has an unsafe or unexpected format in KeePassXC.", .{});
}

fn kp(app: *App, result: anytype) Exit!@typeInfo(@TypeOf(result)).error_union.payload {
    return result catch |err| switch (err) {
        error.KeePassFailed => {
            app.status = 1;
            return error.Exit;
        },
        error.OutOfMemory => app.fail(1, "Out of memory.", .{}),
    };
}

fn randomHex(app: *App, comptime nbytes: usize) Exit!Secret {
    return Secret.randomHex(app.z, app.io, nbytes) catch app.fail(1, "Unable to generate random secret material.", .{});
}

// ------------------------------------------------------------ init/adopt

fn storeRandomIfMissing(app: *App, db: *const keepass.Unlocked, entry: Entry, comptime label: []const u8, comptime nbytes: usize) Exit!void {
    if (try kp(app, db.has(entry))) {
        log.out("KeePassXC item already exists: " ++ label, .{});
        return;
    }
    var value = try randomHex(app, nbytes);
    defer value.deinit();
    try kp(app, db.store(entry, value));
    log.out("Created KeePassXC item: " ++ label, .{});
}

fn commandInit(app: *App) Exit!void {
    try app.acquireLock();
    var db = try app.promptUnlock();
    defer db.deinit();
    try kp(app, db.ensureGroup());
    try storeRandomIfMissing(app, &db, .@"authentik-secret-key", "Authentik secret key", 64);
    try storeRandomIfMissing(app, &db, .@"authentik-bootstrap-token", "Authentik bootstrap token", 32);
    if (!try kp(app, db.has(.@"authentik-api-token"))) {
        var token = try kp(app, db.get(.@"authentik-bootstrap-token"));
        defer token.deinit();
        try kp(app, db.store(.@"authentik-api-token", token));
        log.out("Created KeePassXC item: Authentik NAS API token (initially the bootstrap token)", .{});
    }
    try storeRandomIfMissing(app, &db, .@"authentik-bootstrap-password", "Authentik bootstrap administrator password", 24);
    try storeRandomIfMissing(app, &db, .@"state-bundle-signing-key", "NAS state bundle HMAC signing key", 32);
    if (comptime cfg.features.grafana) try storeRandomIfMissing(app, &db, .@"grafana-secret-key", "Grafana signing and data-source secret key", 32);
    if (comptime cfg.features.ntfy) {
        try storeRandomIfMissing(app, &db, .@"ntfy-admin-password", "ntfy administrator password", 24);
        try storeRandomIfMissing(app, &db, .@"ntfy-alert-topic", "ntfy private alert topic", 16);
    }
    if (comptime cfg.features.nut_webgui) try storeRandomIfMissing(app, &db, .@"nut-webgui-server-key", "NUT Web GUI session signing key", 32);
    if (comptime cfg.features.zfs_encryption) try storeRandomIfMissing(app, &db, .@"zfs-dataset-key", "ZFS native encryption key", 32);
    if (comptime cfg.features.vaultwarden) {
        try storeRandomIfMissing(app, &db, .@"vaultwarden-oidc-client-secret", "Vaultwarden Authentik OIDC client secret", 32);
        try storeRandomIfMissing(app, &db, .@"vaultwarden-admin", "Vaultwarden admin token", 32);
    }
    log.out("", .{});
    log.out("Secret initialization complete. Human identity and access policy remain in Authentik.", .{});
    log.out("Run: nas-secrets activate", .{});
}

fn commandAdopt(app: *App) Exit!void {
    try app.acquireLock();
    var db = try app.promptUnlock();
    defer db.deinit();
    try kp(app, db.ensureGroup());
    var key = app.readLine() catch return app.fail(1, "Unable to read the Authentik bootstrap secret key.", .{});
    defer key.deinit();
    var token = app.readLine() catch return app.fail(1, "Unable to read the Authentik bootstrap token.", .{});
    defer token.deinit();
    var password = app.readLine() catch return app.fail(1, "Unable to read the Authentik bootstrap password.", .{});
    defer password.deinit();
    try app.rejectExtraInput("adopting Authentik bootstrap authority");
    try requireHex(app, key, 128, "Authentik bootstrap secret key");
    try requireHex(app, token, 64, "Authentik bootstrap token");
    try requireHex(app, password, 48, "Authentik bootstrap password");
    try kp(app, db.store(.@"authentik-secret-key", key));
    try kp(app, db.store(.@"authentik-bootstrap-token", token));
    try kp(app, db.store(.@"authentik-api-token", token));
    try kp(app, db.store(.@"authentik-bootstrap-password", password));
    log.out("Adopted the running first-boot Authentik authority.", .{});
}

// -------------------------------------------------------------- activate

const modes = @import("modes.zig");
const Mode = modes.Mode;
const PostSetup = modes.PostSetup;
const PostSetupSlot = modes.PostSetupSlot;
const Rotated = modes.Rotated;

fn detectPostSetup(app: *App, comptime mode: Mode) PostSetupSlot(mode) {
    return switch (mode) {
        .setup => {},
        .runtime => if (app.rootTest("-e", app.paths.setup_state)) PostSetup{ .boot_dir = app.paths.bootstrap_authentik_dir } else null,
    };
}

/// Setup adopted the first-boot key from a plaintext file that may also be in
/// backups. Replace it in KeePass before that file is retired. A symlinked
/// runtime environment means this boot still uses that file.
fn rotateAuthentikKey(app: *App, db: *const keepass.Unlocked, post: PostSetup) Exit!?Rotated {
    const boot_env = try app.join(&.{ post.boot_dir, "/environment" });
    if (!app.rootTest("-e", boot_env) or app.rootTest("-L", app.paths.authentik_runtime_environment_file)) return null;
    const dbz = try app.joinZ(&.{app.paths.database});
    const before = sys.stat(dbz) catch return app.fail(1, "Unable to inspect the KeePassXC database owner.", .{});
    try kp(app, db.ensureGroup());
    var fresh = try randomHex(app, 64);
    defer fresh.deinit();
    try kp(app, db.store(.@"authentik-secret-key", fresh));
    // KeePassXC saves by replacing the file; a root activation must not take
    // the database away from its administrator owner.
    var owner_buf: [32]u8 = undefined;
    const owner = std.fmt.bufPrint(&owner_buf, "{d}:{d}", .{ before.uid, before.gid }) catch unreachable;
    var mode_buf: [8]u8 = undefined;
    const mode = std.fmt.bufPrint(&mode_buf, "{o}", .{before.mode}) catch unreachable;
    try app.rootStep(.{ cfg.tools.chown, "--", owner, app.paths.database });
    try app.rootStep(.{ cfg.tools.chmod, "--", mode, app.paths.database });
    log.out("Rotated the Authentik secret key held in KeePassXC; the first-boot copy will be removed.", .{});
    return .{};
}

fn linkUnlockedEnvironment(app: *App, post: PostSetup) Exit!void {
    _ = post;
    const source = try app.join(&.{ app.paths.secret_root, "/authentik/environment" });
    try app.rootStep(.{ cfg.tools.ln, "-sfn", "--", source, app.paths.authentik_unlocked_environment_file });
}

/// Locked boots need only the least-privilege outpost token on disk; the
/// superuser API token now resolves through the KeePass tree.
fn installBootOutpostToken(app: *App, post: PostSetup, committed: transaction.Committed, have_outpost: bool) Exit!void {
    _ = committed;
    const source = try app.join(&.{ app.paths.secret_root, "/authentik/outpost-token" });
    const boot_token = try app.join(&.{ post.boot_dir, "/outpost-token" });
    const installed = have_outpost and (app.root.privilegedOk(.{ cfg.tools.install, "-m", "0400", "-o", "root", "-g", "root", source, boot_token }) catch false);
    if (!installed) {
        log.err("WARNING: the boot-side Authentik outpost token was not refreshed; browser unlock may be unavailable after reboot.", .{});
        return;
    }
    try app.rootStep(.{ cfg.tools.rm, "-f", "--", try app.join(&.{ post.boot_dir, "/api-token" }) });
    try app.rootStep(.{ cfg.tools.ln, "-sfn", "--", boot_token, app.paths.authentik_runtime_outpost_token_file });
    try app.rootStep(.{ cfg.tools.ln, "-sfn", "--", app.paths.authentik_api_token_file, app.paths.authentik_runtime_api_token_file });
}

fn retireBootEnvironment(app: *App, post: PostSetup, rotated: Rotated, committed: transaction.Committed) Exit!void {
    _ = rotated;
    _ = committed;
    try app.rootStep(.{ cfg.tools.rm, "-f", "--", try app.join(&.{ post.boot_dir, "/environment" }) });
}

/// Secrets read for one activation; wiped on every exit path.
const Material = struct {
    authentik_secret: ?Secret = null,
    bootstrap_token: ?Secret = null,
    bootstrap_password: ?Secret = null,
    api_token: ?Secret = null,
    outpost_token: ?Secret = null,
    bundle_key: ?Secret = null,
    grafana: ?Secret = null,
    ntfy_password: ?Secret = null,
    ntfy_topic: ?Secret = null,
    ntfy_hash: ?Secret = null,
    nut_key: ?Secret = null,
    zfs_key: ?Secret = null,
    vw_client_secret: ?Secret = null,
    vw_admin_hash: ?Secret = null,

    fn deinit(self: *Material) void {
        const info = @typeInfo(Material).@"struct";
        inline for (info.field_names) |name| {
            if (@field(self, name)) |*s| s.deinit();
        }
    }
};

const FilePart = union(enum) { text: []const u8, secret: Secret };

fn writeStaged(app: *App, dir: []const u8, name: []const u8, parts: []const FilePart) Exit!void {
    const dir_z = try app.joinZ(&.{dir});
    var pdir = secret.PrivateDir.open(dir_z) catch return app.fail(70, "Refusing to stage secrets: {s} is not a private directory.", .{dir});
    defer pdir.close();
    const name_z = try app.joinZ(&.{name});
    var file = secret.PrivateFile.create(pdir, name_z) catch |err| return app.fail(1, "Unable to stage {s}/{s}: {t}", .{ dir, name, err });
    defer file.close();
    for (parts) |part| switch (part) {
        .text => |t| file.writePublic(t) catch |err| return app.fail(1, "Unable to stage {s}/{s}: {t}", .{ dir, name, err }),
        .secret => |s| file.writeSecret(s) catch |err| return app.fail(1, "Unable to stage {s}/{s}: {t}", .{ dir, name, err }),
    };
}

fn installSecret(app: *App, source: []const u8, target: []const u8, owner: []const u8, group: []const u8) Exit!void {
    const sz = try app.joinZ(&.{source});
    const st = sys.lstat(sz) catch null;
    if (st == null or st.?.kind != .regular)
        return app.fail(1, "Refusing to install a non-regular or symlink secret source: {s}", .{source});
    try app.rootStep(.{ cfg.tools.install, "-m", "0400", "-o", owner, "-g", group, "--", source, target });
}

const RootDir = struct { path: []const u8, mode: []const u8, group: []const u8 };

/// Root-stage directories, filtered at compile time by enabled features.
const root_dirs = blk: {
    var list: []const RootDir = &.{
        .{ .path = "authentik", .mode = "0750", .group = "authentik" },
        .{ .path = "state", .mode = "0700", .group = "root" },
    };
    if (cfg.features.vaultwarden) list = list ++ &[_]RootDir{.{ .path = "vaultwarden", .mode = "0700", .group = "root" }};
    if (cfg.features.zfs_encryption) list = list ++ &[_]RootDir{.{ .path = "zfs", .mode = "0700", .group = "root" }};
    if (cfg.features.observability_dir) list = list ++ &[_]RootDir{.{ .path = "observability", .mode = "0750", .group = "nas-observability" }};
    if (cfg.features.nut_webgui) list = list ++ &[_]RootDir{.{ .path = "power", .mode = "0700", .group = "root" }};
    break :blk list;
};

fn readV2StartUnits(app: *App) Exit![]const UnitName {
    if (!app.rootTest("-f", app.paths.v2_systemd_state)) return &.{};
    var out = app.root.privileged(.{ cfg.tools.cat, "--", app.paths.v2_systemd_state }, .{ .stdout = .capture }) catch
        return app.fail(70, "Refusing to activate secrets: Managed Services V2 runtime state is malformed.", .{});
    defer out.deinit();
    if (!out.exit.ok()) return app.fail(70, "Refusing to activate secrets: Managed Services V2 runtime state is malformed.", .{});
    const State = struct { schemaVersion: i64, startUnits: []const []const u8 };
    const parsed = std.json.parseFromSliceLeaky(State, app.arena, out.stdout, .{ .ignore_unknown_fields = true, .allocate = .alloc_always }) catch
        return app.fail(70, "Refusing to activate secrets: Managed Services V2 runtime state is malformed.", .{});
    if (parsed.schemaVersion != 1) return app.fail(70, "Refusing to activate secrets: Managed Services V2 runtime state is malformed.", .{});
    const units = app.arena.alloc(UnitName, parsed.startUnits.len) catch return app.fail(1, "Out of memory.", .{});
    for (parsed.startUnits, units) |name, *unit| {
        unit.* = UnitName.parse(name) catch {
            var safe: [256]u8 = undefined;
            return app.fail(70, "Refusing to activate secrets: invalid V2 unit name: {s}", .{log.sanitize(&safe, name)});
        };
    }
    return units;
}

const failed_units = [_]UnitName{ UnitName.lit("authentik.service"), UnitName.lit("authentik-worker.service"), UnitName.lit("caddy.service") };

fn commandActivate(app: *App, comptime mode: Mode) Exit!void {
    try app.acquireLock();
    var db = try app.promptUnlock();
    defer db.deinit();

    const uid = sys.getuid();
    const gid = sys.getgid();
    var idbuf: [2][16]u8 = undefined;
    const uid_s = std.fmt.bufPrint(&idbuf[0], "{d}", .{uid}) catch unreachable;
    const gid_s = std.fmt.bufPrint(&idbuf[1], "{d}", .{gid}) catch unreachable;
    const staging = try app.join(&.{ app.paths.runtime_root, "/staging" });
    try app.rootStep(.{ cfg.tools.install, "-d", "-m", "0711", "-o", "root", "-g", "root", staging });
    const runtime_base = try app.join(&.{ staging, "/", uid_s });
    try app.rootStep(.{ cfg.tools.install, "-d", "-m", "0700", "-o", uid_s, "-g", gid_s, runtime_base });
    const base_z = try app.joinZ(&.{runtime_base});
    const base_st = sys.lstat(base_z) catch null;
    if (base_st == null or base_st.?.kind != .directory or base_st.?.uid != uid or base_st.?.mode & 0o077 != 0) {
        if (base_st) |s| return app.fail(70, "Refusing to stage secrets: a private user runtime directory is unavailable: {s} ({o}:{d}:{d})", .{ runtime_base, s.mode, s.uid, s.gid });
        return app.fail(70, "Refusing to stage secrets: a private user runtime directory is unavailable: {s} (missing)", .{runtime_base});
    }
    const local_stage = try makePrivateTemp(app, runtime_base);
    defer {
        var rm = app.user.run(.{ cfg.tools.rm, "-rf", "--", local_stage }, null, .{}) catch null;
        if (rm) |*r| r.deinit();
    }
    const transactions = try app.join(&.{ app.paths.runtime_root, "/transactions" });
    try app.rootStep(.{ cfg.tools.install, "-d", "-m", "0700", "-o", "root", "-g", "root", transactions });
    var mk = app.root.privileged(.{ cfg.tools.mktemp, "-d", try app.join(&.{ transactions, "/transaction.XXXXXX" }) }, .{ .stdout = .capture, .stderr = .inherit }) catch
        return app.fail(1, "Unable to create the secret transaction directory.", .{});
    defer mk.deinit();
    if (!mk.exit.ok()) return app.fail(1, "Unable to create the secret transaction directory.", .{});
    const transaction_dir = try app.join(&.{std.mem.trimEnd(u8, mk.stdout, "\n")});
    const root_stage = try app.join(&.{ transaction_dir, "/new" });
    const previous = try app.join(&.{ transaction_dir, "/previous" });

    var ctx: transaction.Context = undefined;
    const staged = transaction.init(&ctx, app.root, .{
        .systemctl = cfg.tools.systemctl,
        .mv = cfg.tools.mv,
        .rm = cfg.tools.rm,
        .test_ = cfg.tools.test_,
        .realpath = cfg.tools.realpath,
    }, .{
        .root = app.paths.secret_root,
        .stage = root_stage,
        .previous = previous,
        .directory = transaction_dir,
    }) catch {
        _ = app.root.privilegedOk(.{ cfg.tools.rm, "-rf", "--", transaction_dir }) catch false;
        app.status = 1;
        return error.Exit;
    };

    var material: Material = .{};
    defer material.deinit();
    const post_setup = detectPostSetup(app, mode);

    const prepared = prepare(app, mode, &db, post_setup, &material, local_stage, root_stage);
    const prep = prepared catch return finishRollback(app, staged.rollback());

    const swapped = switch (staged.swap()) {
        .swapped => |s| s,
        .failed => |f| {
            app.status = f.status;
            return finishRollback(app, f.rollback());
        },
    };

    bringUp(app, mode, post_setup, prep.v2_units) catch return finishRollback(app, swapped.rollback());

    const committed = switch (swapped.commit()) {
        .committed => |c| c,
        .cleanup_failed, .rejected => {
            log.err("Secret activation failed and rollback was incomplete.", .{});
            app.status = transaction.manual_recovery_status;
            return error.Exit;
        },
    };

    if (comptime mode == .runtime) {
        if (post_setup) |post| {
            try installBootOutpostToken(app, post, committed, material.outpost_token != null);
            if (prep.rotated) |rotated| try retireBootEnvironment(app, post, rotated, committed);
        }
    }
    log.out("Runtime service secrets activated. Authentik remains the identity source of truth.", .{});
}

fn finishRollback(app: *App, outcome: transaction.RollbackOutcome) Exit {
    if (app.status == 0) app.status = 1;
    const status = transaction.statusAfterRollback(outcome, app.status);
    if (status == transaction.manual_recovery_status) log.err("Secret activation failed and rollback was incomplete.", .{});
    app.status = status;
    return error.Exit;
}

fn makePrivateTemp(app: *App, base: []const u8) Exit![]const u8 {
    const alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    var attempt: usize = 0;
    while (attempt < 16) : (attempt += 1) {
        var raw: [6]u8 = undefined;
        app.io.random(&raw);
        var suffix: [6]u8 = undefined;
        for (raw, &suffix) |r, *s| s.* = alphabet[r % alphabet.len];
        const path = try app.joinZ(&.{ base, "/nas-secrets.", &suffix });
        sys.mkdir(path, 0o700) catch |err| switch (err) {
            error.PathAlreadyExists => continue,
            else => return app.fail(70, "Refusing to stage secrets: unable to create a private temporary directory: {t}", .{err}),
        };
        const st = sys.lstat(path) catch return app.fail(70, "Refusing to stage secrets: temporary directory is not mode 0700.", .{});
        if (st.kind != .directory or st.mode != 0o700) return app.fail(70, "Refusing to stage secrets: temporary directory is not mode 0700.", .{});
        return path;
    }
    return app.fail(70, "Refusing to stage secrets: unable to create a private temporary directory.", .{});
}

const Prepared = struct {
    v2_units: []const UnitName,
    rotated: ?Rotated,
};

/// Everything before the swap: read KeePass, render the staged tree,
/// validate V2 state. Failure here leaves the live tree untouched.
fn prepare(
    app: *App,
    comptime mode: Mode,
    db: *const keepass.Unlocked,
    post_setup: PostSetupSlot(mode),
    m: *Material,
    local: []const u8,
    root_stage: []const u8,
) Exit!Prepared {
    for ([_][]const u8{ "authentik", "vaultwarden", "zfs", "observability", "power", "state" }) |sub| {
        const p = try app.joinZ(&.{ local, "/", sub });
        sys.mkdir(p, 0o700) catch |err| return app.fail(1, "Unable to create {s}: {t}", .{ p, err });
    }

    var rotated: ?Rotated = null;
    if (comptime mode == .runtime) {
        if (post_setup) |post| rotated = try rotateAuthentikKey(app, db, post);
    }
    try app.checkInterrupted();

    m.authentik_secret = try kp(app, db.get(.@"authentik-secret-key"));
    m.bootstrap_token = try kp(app, db.getOptional(.@"authentik-bootstrap-token"));
    m.bootstrap_password = try kp(app, db.getOptional(.@"authentik-bootstrap-password"));
    m.api_token = try kp(app, db.get(.@"authentik-api-token"));
    m.outpost_token = try kp(app, db.getOptional(.@"authentik-outpost-token"));
    try requireHex(app, m.authentik_secret.?, 128, "Authentik secret key");
    try requireAtom(app, m.api_token.?, "Authentik API token", 20, 4096);
    if (m.outpost_token) |t| try requireAtom(app, t, "Authentik outpost token", 20, 4096);
    if (m.bootstrap_token != null or m.bootstrap_password != null) {
        if (m.bootstrap_token == null or m.bootstrap_password == null) return app.fail(1, "Authentik bootstrap token has an unsafe or unexpected format in KeePassXC.", .{});
        try requireHex(app, m.bootstrap_token.?, 64, "Authentik bootstrap token");
        try requireAtom(app, m.bootstrap_password.?, "Authentik bootstrap password", 20, 4096);
    }

    const authentik_dir = try app.join(&.{ local, "/authentik" });
    if (m.bootstrap_token) |token| {
        try writeStaged(app, authentik_dir, "environment", &.{
            .{ .text = "AUTHENTIK_SECRET_KEY=" },                                         .{ .secret = m.authentik_secret.? },
            .{ .text = "\nAUTHENTIK_BOOTSTRAP_TOKEN=" },                                  .{ .secret = token },
            .{ .text = "\nAUTHENTIK_BOOTSTRAP_PASSWORD=" },                               .{ .secret = m.bootstrap_password.? },
            .{ .text = "\nAUTHENTIK_BOOTSTRAP_EMAIL='" ++ cfg.bootstrap_email ++ "'\n" },
        });
        try writeStaged(app, authentik_dir, "bootstrap-token", &.{.{ .secret = token }});
    } else {
        try writeStaged(app, authentik_dir, "environment", &.{ .{ .text = "AUTHENTIK_SECRET_KEY=" }, .{ .secret = m.authentik_secret.? }, .{ .text = "\n" } });
    }
    try writeStaged(app, authentik_dir, "api-token", &.{.{ .secret = m.api_token.? }});
    if (m.outpost_token) |t| try writeStaged(app, authentik_dir, "outpost-token", &.{.{ .secret = t }});

    m.bundle_key = try kp(app, db.get(.@"state-bundle-signing-key"));
    try requireHex(app, m.bundle_key.?, 64, "State bundle signing key");
    try writeStaged(app, try app.join(&.{ local, "/state" }), "bundle-signing-key", &.{.{ .secret = m.bundle_key.? }});

    const reused = if (m.bootstrap_token) |t| t.eql(m.api_token.?) else false;
    if (reused) {
        try writeStaged(app, local, "authentik-token-warning", &.{.{ .text = "The Authentik runtime API token is still the bootstrap token. Create a scoped service-account token, store it with `nas-secrets set-authentik-token`, and activate secrets again.\n" }});
        log.err("WARNING: Authentik runtime API token is still the bootstrap token.", .{});
    }

    const observability = try app.join(&.{ local, "/observability" });
    if (comptime cfg.features.grafana) {
        m.grafana = try kp(app, db.get(.@"grafana-secret-key"));
        try requireAtom(app, m.grafana.?, "Grafana secret key", 20, 4096);
        try writeStaged(app, observability, "grafana-secret-key", &.{.{ .secret = m.grafana.? }});
    }
    if (comptime cfg.features.ntfy) {
        m.ntfy_password = try kp(app, db.get(.@"ntfy-admin-password"));
        m.ntfy_topic = try kp(app, db.get(.@"ntfy-alert-topic"));
        try requireAtom(app, m.ntfy_password.?, "ntfy administrator password", 20, 4096);
        if (!m.ntfy_topic.?.satisfies(validate.isNtfyTopic)) return app.fail(1, "ntfy alert topic has an unsafe or unexpected format in KeePassXC.", .{});
        m.ntfy_hash = secret.bcryptCrypt(m.ntfy_password.?, app.z, app.io) catch return app.fail(1, "Unable to hash the ntfy administrator password.", .{});
        try writeStaged(app, observability, "ntfy-environment", &.{
            .{ .text = "NTFY_AUTH_USERS=admin:" },                                              .{ .secret = m.ntfy_hash.? },
            .{ .text = ":admin\nNTFY_AUTH_DEFAULT_ACCESS=deny-all\nNTFY_ENABLE_LOGIN=true\n" },
        });
        try writeStaged(app, observability, "ntfy-topic", &.{.{ .secret = m.ntfy_topic.? }});
        try writeStaged(app, observability, "ntfy-admin-password", &.{.{ .secret = m.ntfy_password.? }});
    }
    if (comptime cfg.features.nut_webgui) {
        m.nut_key = try kp(app, db.get(.@"nut-webgui-server-key"));
        try writeStaged(app, try app.join(&.{ local, "/power" }), "nut-webgui-server-key", &.{.{ .secret = m.nut_key.? }});
    }
    if (comptime cfg.features.zfs_encryption) {
        m.zfs_key = try kp(app, db.get(.@"zfs-dataset-key"));
        try writeStaged(app, try app.join(&.{ local, "/zfs" }), "dataset-key", &.{.{ .secret = m.zfs_key.? }});
    }
    if (comptime cfg.features.vaultwarden) {
        m.vw_client_secret = try kp(app, db.get(.@"vaultwarden-oidc-client-secret"));
        var admin = try kp(app, db.get(.@"vaultwarden-admin"));
        defer admin.deinit();
        try requireAtom(app, m.vw_client_secret.?, "Vaultwarden OIDC client secret", 8, 4096);
        try requireAtom(app, admin, "Vaultwarden administrator token", 8, 4096);
        m.vw_admin_hash = secret.argon2idPhc(admin, app.z, app.io) catch return app.fail(1, "Argon2 did not return an encoded Argon2id digest.", .{});
        try writeStaged(app, try app.join(&.{ local, "/vaultwarden" }), "environment", &.{
            .{ .text = "ADMIN_TOKEN='" },          .{ .secret = m.vw_admin_hash.? },
            .{ .text = "'\nSSO_CLIENT_SECRET='" }, .{ .secret = m.vw_client_secret.? },
            .{ .text = "'\n" },
        });
    }
    try app.checkInterrupted();

    if (app.root.privilege == .sudo) {
        var refresh = app.user.run(.{ cfg.tools.sudo, "-v" }, null, .{ .stderr = .inherit }) catch return app.fail(1, "Unable to refresh sudo authorization.", .{});
        defer refresh.deinit();
        if (!refresh.exit.ok()) {
            app.status = refresh.exit.status();
            return error.Exit;
        }
    }
    try app.rootStep(.{ cfg.tools.install, "-d", "-m", "0711", "-o", "root", "-g", "root", root_stage });
    inline for (root_dirs) |dir| {
        try app.rootStep(.{ cfg.tools.install, "-d", "-m", dir.mode, "-o", "root", "-g", dir.group, try app.join(&.{ root_stage, "/" ++ dir.path }) });
    }

    const files = [_]struct { rel: []const u8, owner: []const u8, group: []const u8, present: bool }{
        .{ .rel = "authentik/environment", .owner = "authentik", .group = "authentik", .present = true },
        .{ .rel = "authentik/api-token", .owner = "root", .group = "root", .present = true },
        .{ .rel = "authentik/outpost-token", .owner = "root", .group = "root", .present = m.outpost_token != null },
        .{ .rel = "authentik/bootstrap-token", .owner = "root", .group = "root", .present = m.bootstrap_token != null },
        .{ .rel = "state/bundle-signing-key", .owner = "root", .group = "root", .present = true },
        .{ .rel = "authentik-token-warning", .owner = "root", .group = "root", .present = reused },
        .{ .rel = "vaultwarden/environment", .owner = "root", .group = "root", .present = cfg.features.vaultwarden },
        .{ .rel = "zfs/dataset-key", .owner = "root", .group = "root", .present = cfg.features.zfs_encryption },
        .{ .rel = "observability/grafana-secret-key", .owner = "grafana", .group = "grafana", .present = cfg.features.grafana },
        .{ .rel = "observability/ntfy-environment", .owner = "root", .group = "root", .present = cfg.features.ntfy },
        .{ .rel = "observability/ntfy-topic", .owner = "nas-observability", .group = "nas-observability", .present = cfg.features.ntfy },
        .{ .rel = "observability/ntfy-admin-password", .owner = "nas-observability", .group = "nas-observability", .present = cfg.features.ntfy },
        .{ .rel = "power/nut-webgui-server-key", .owner = "root", .group = "root", .present = cfg.features.nut_webgui },
    };
    for (files) |f| {
        if (!f.present) continue;
        try installSecret(app, try app.join(&.{ local, "/", f.rel }), try app.join(&.{ root_stage, "/", f.rel }), f.owner, f.group);
    }
    try app.rootStep(.{ cfg.tools.install, "-m", "0400", "-o", "root", "-g", "root", "/dev/null", try app.join(&.{ root_stage, "/ready" }) });

    const units = try readV2StartUnits(app);
    try app.checkInterrupted();
    return .{ .v2_units = units, .rotated = rotated };
}

/// After the swap: restart identity services and gate on readiness.
fn bringUp(app: *App, comptime mode: Mode, post_setup: PostSetupSlot(mode), v2_units: []const UnitName) Exit!void {
    if (comptime mode == .runtime) {
        if (post_setup) |post| try linkUnlockedEnvironment(app, post);
    }
    _ = app.systemctl(.{ "reset-failed", "postgresql.service", "postgresql-setup.service", "authentik-migrate.service", "authentik-worker.service", "authentik.service", "caddy.service" });
    switch (mode) {
        .setup => {
            if (!app.systemctl(.{ "start", "postgresql.service" }) or
                !app.systemctl(.{ "start", "authentik-migrate.service" }) or
                !app.systemctl(.{ "start", "--job-mode=ignore-dependencies", "authentik.service" }) or
                !app.systemctl(.{ "start", "--job-mode=ignore-dependencies", "authentik-worker.service" }) or
                !app.systemctl(.{ "start", "--job-mode=ignore-dependencies", "caddy.service" }))
                return app.fail(71, "Setup identity services failed to start; inspect systemctl --failed.", .{});
        },
        .runtime => {
            if (!app.systemctl(.{ "try-restart", "authentik-worker.service", "authentik.service" }))
                return app.fail(71, "Authentik failed to restart with the KeePassXC environment; inspect systemctl --failed.", .{});
            if (!app.systemctl(.{ "start", "nas-protected-services.target" }))
                return app.fail(71, "Protected service target failed to start; inspect systemctl --failed.", .{});
            // Target activation does not pull V2-owned units. Restore only units
            // selected by the current V2 projection after their secret gates hold.
            for (v2_units) |unit| if (!app.systemctl(.{ "start", unit })) {
                app.status = 71;
                return error.Exit;
            };
        },
    }
    try app.checkInterrupted();
    for (failed_units) |unit| {
        if (app.systemctlQuiet(.{ "is-failed", "--quiet", unit })) return app.fail(72, "Protected service entered the failed state: {s}", .{unit.name});
    }

    var probe = app.user.run(.{
        cfg.tools.timeout,   "90s", cfg.tools.curl,        "--fail",             "--silent",              "--show-error",
        "--connect-timeout", "1",   "--max-time",          "2",                  "--retry",               "90",
        "--retry-delay",     "1",   "--retry-connrefused", "--retry-all-errors", cfg.authentik_ready_url,
    }, null, .{ .stderr = .inherit }) catch return app.fail(73, "Authentik readiness probe could not be started.", .{});
    defer probe.deinit();
    if (!probe.exit.ok()) {
        if (app.systemctlQuiet(.{ "is-failed", "--quiet", UnitName.lit("authentik.service") }))
            return app.fail(72, "Authentik failed while waiting for API readiness.", .{});
        const status = probe.exit.status();
        if (status == 124) return app.fail(73, "Authentik remained active but did not become API-ready within 90 seconds.", .{});
        return app.fail(73, "Authentik readiness probe failed with curl/timeout status {d}.", .{status});
    }
    try app.checkInterrupted();
    for (failed_units) |unit| {
        if (!app.systemctlQuiet(.{ "is-active", "--quiet", unit })) return app.fail(74, "Protected service is not active after readiness validation: {s}", .{unit.name});
    }
    if (comptime mode == .runtime) {
        // Restarting Authentik stops its required outpost; the boot target does
        // not pull that unit back in during runtime activation.
        if (!app.systemctl(.{ "start", "nas-authentik-proxy-outpost.service" }))
            return app.fail(71, "Authentik proxy outpost failed to restart after activation.", .{});
    }
    try app.checkInterrupted();
}

// ----------------------------------------------------- remaining commands

fn commandStatus(app: *App) Exit!void {
    const ready = try app.joinZ(&.{ app.paths.secret_root, "/ready" });
    const is_ready = if (sys.stat(ready)) |s| s.kind == .regular else |_| false;
    log.out("Runtime secrets: {s}", .{if (is_ready) "active" else "inactive"});
    const db = try app.joinZ(&.{app.paths.database});
    const has_db = if (sys.stat(db)) |s| s.kind == .regular else |_| false;
    log.out("KeePassXC database: {s}", .{if (has_db) "configured" else "missing"});
    for ([_][]const u8{ "authentik.service", "nas-v2-timer-identity-sync-0.timer" }) |unit| {
        var out = app.user.run(.{ cfg.tools.systemctl, "is-active", unit }, null, .{ .stdout = .inherit }) catch continue;
        out.deinit();
    }
    const warning = try app.joinZ(&.{ app.paths.secret_root, "/authentik-token-warning" });
    const warned = if (sys.stat(warning)) |s| s.kind == .regular else |_| false;
    if (warned) log.out("Authentik API token: WARNING — bootstrap token still in use", .{}) else log.out("Authentik API token: scoped-token warning not present", .{});
}

fn commandStop(app: *App) Exit!void {
    try app.acquireLock();
    // Path-triggered Caddy selection must see the locked state before stopping
    // units can publish changes that trigger reconciliation.
    try app.rootStep(.{ cfg.tools.rm, "-f", try app.join(&.{ app.paths.secret_root, "/ready" }) });
    try app.rootStep(.{ cfg.tools.systemctl, "stop", "nas-protected-services.target" });
    try app.rootStep(.{ cfg.tools.rm, "-rf", app.paths.secret_root });
    log.out("Protected services stopped and runtime secrets removed. KeePassXC was not modified.", .{});
}

fn commandCheckToken(app: *App) Exit!void {
    try app.acquireLock();
    var db = try app.promptUnlock();
    defer db.deinit();
    var api = try kp(app, db.get(.@"authentik-api-token"));
    defer api.deinit();
    if (!try kp(app, db.has(.@"authentik-bootstrap-token"))) {
        log.out("Authentik bootstrap token is retired; runtime API token is separate.", .{});
        return;
    }
    var bootstrap = try kp(app, db.get(.@"authentik-bootstrap-token"));
    defer bootstrap.deinit();
    if (bootstrap.eql(api)) return app.fail(1, "WARNING: Authentik runtime API token is still the bootstrap token.", .{});
    log.out("Authentik runtime API token differs from the bootstrap token.", .{});
}

fn readToken(app: *App, comptime interactive: bool, comptime what: []const u8) Exit!Secret {
    const line = if (interactive) app.promptLine("Authentik API token: ") else app.readLine();
    return line catch |err| switch (err) {
        error.Empty => Secret.copyOf(app.z, "") catch app.fail(1, "Out of memory.", .{}),
        error.Unreadable, error.TooLong, error.InvalidUtf8 => app.fail(1, "Unable to read the " ++ what ++ " from standard input.", .{}),
        error.OutOfMemory => app.fail(1, "Out of memory.", .{}),
    };
}

fn commandSetToken(app: *App, comptime interactive: bool) Exit!void {
    try app.acquireLock();
    var db = try app.promptUnlock();
    defer db.deinit();
    try kp(app, db.ensureGroup());
    var token = try readToken(app, interactive, "Authentik API token");
    defer token.deinit();
    if (!interactive) try app.rejectExtraInput("setting the Authentik API token");
    if (!token.satisfies(validate.isAuthentikToken)) return app.fail(1, "Authentik API token format is invalid.", .{});
    try kp(app, db.store(.@"authentik-api-token", token));
    if (interactive) log.out("Authentik API token stored. Run nas-secrets activate to stage it.", .{}) else log.out("Authentik API token stored.", .{});
}

fn commandSetRuntime(app: *App) Exit!void {
    try app.acquireLock();
    var db = try app.promptUnlock();
    defer db.deinit();
    try kp(app, db.ensureGroup());
    var token = try readToken(app, false, "Authentik API token");
    defer token.deinit();
    var outpost = try readToken(app, false, "Authentik outpost token");
    defer outpost.deinit();
    try app.rejectExtraInput("setting the Authentik runtime tokens");
    if (!token.satisfies(validate.isAuthentikToken)) return app.fail(1, "Authentik API token format is invalid.", .{});
    if (!outpost.satisfies(validate.isAuthentikToken)) return app.fail(1, "Authentik outpost token format is invalid.", .{});
    try kp(app, db.store(.@"authentik-outpost-token", outpost));
    try kp(app, db.store(.@"authentik-api-token", token));
    log.out("Authentik runtime tokens stored.", .{});
}

fn commandRetireBootstrap(app: *App) Exit!void {
    try app.acquireLock();
    var db = try app.promptUnlock();
    defer db.deinit();
    try kp(app, db.remove(.@"authentik-bootstrap-token"));
    try kp(app, db.remove(.@"authentik-bootstrap-password"));
    log.out("Authentik bootstrap credentials removed. Run nas-secrets activate to remove runtime artifacts.", .{});
}

fn reveal(app: *App, s: Secret, comptime grant: secret.RevealGrant) Exit!void {
    secret.revealToStdout(s, grant) catch return app.fail(1, "Unable to write to standard output.", .{});
}

fn commandShow(app: *App, comptime which: enum { ntfy, zfs, zfs_stdin, bootstrap }) Exit!void {
    var db = try app.promptUnlock();
    defer db.deinit();
    switch (which) {
        .ntfy => {
            var v = try kp(app, db.get(.@"ntfy-admin-password"));
            defer v.deinit();
            try reveal(app, v, .show_ntfy_password);
            sys.writeAll(1, "\n") catch {};
        },
        .zfs => {
            var v = try kp(app, db.get(.@"zfs-dataset-key"));
            defer v.deinit();
            try reveal(app, v, .show_zfs_key);
            sys.writeAll(2, "\n") catch {};
        },
        .zfs_stdin => {
            try app.rejectExtraInput("showing the ZFS dataset key");
            var v = try kp(app, db.get(.@"zfs-dataset-key"));
            defer v.deinit();
            try reveal(app, v, .show_zfs_key);
        },
        .bootstrap => {
            var v = try kp(app, db.get(.@"authentik-bootstrap-password"));
            defer v.deinit();
            sys.writeAll(1, "Username: akadmin\nPassword: ") catch {};
            try reveal(app, v, .show_authentik_bootstrap_password);
            sys.writeAll(1, "\n") catch {};
        },
    }
}

// ------------------------------------------------------------ coordinator

fn enterOperationCoordinator(app: *App, cmd: Command, args: []const []const u8) Exit!void {
    if (!cmd.coordinated()) return;
    const runner = app.environ.get("NAS_OPERATION_RUNNER") orelse cfg.operation_runner;
    const rz = try app.joinZ(&.{runner});
    if (std.os.linux.access(rz, std.os.linux.X_OK) != 0) return app.fail(1, "NAS operation coordinator is unavailable: {s}", .{runner});
    const token = app.environ.get("NAS_OPERATION_COORDINATION_TOKEN") orelse "";
    if (token.len > 0) {
        var out = app.user.run(.{ runner, "--validate-current", "--class", "secrets", "--class", "runtime" }, null, .{ .stdout = .inherit, .stderr = .inherit }) catch
            return app.fail(1, "NAS operation coordinator is unavailable: {s}", .{runner});
        defer out.deinit();
        if (!out.exit.ok()) {
            app.status = out.exit.status();
            return error.Exit;
        }
        return;
    }
    const self_exe = std.process.executablePathAlloc(app.io, app.arena) catch return app.fail(1, "Unable to resolve the nas-secrets executable.", .{});
    var argv: command.Argv = command.argv(.{ runner, "--action", try app.join(&.{ "nas-secrets:", @tagName(cmd) }), "--class", "secrets", "--class", "runtime", "--", self_exe, args }) catch
        return app.fail(1, "Too many arguments.", .{});
    const err = std.process.replace(app.io, .{ .argv = argv.slice() });
    return app.fail(1, "Unable to execute the NAS operation coordinator {s}: {t}", .{ runner, err });
}

// ------------------------------------------------------------------ main

pub fn main(init: std.process.Init) u8 {
    const io = init.io;
    const arena = init.arena.allocator();
    const args = init.minimal.args.toSlice(arena) catch return 1;
    // umask 0077 before any file is created.
    _ = std.os.linux.syscall1(.umask, 0o077);
    sys.disableCoreDumps();
    installSignalHandlers();

    const cmd: Command = if (args.len >= 2) std.meta.stringToEnum(Command, args[1]) orelse {
        log.err("{s}", .{usage});
        return 2;
    } else {
        log.err("{s}", .{usage});
        return 2;
    };

    var stdin_buf: [4096]u8 = undefined;
    defer std.crypto.secureZero(u8, &stdin_buf);
    var stdin_reader = Io.File.stdin().readerStreaming(io, &stdin_buf);

    const paths = config.Paths.resolve(arena, init.environ_map) catch return 1;
    const privilege: command.Privilege = if (sys.geteuid() == 0) .direct else .sudo;
    var app: App = .{
        .io = io,
        .gpa = init.gpa,
        .arena = arena,
        .z = &secret.process_zeroing,
        .environ = init.environ_map,
        .paths = paths,
        .user = .{ .io = io, .gpa = init.gpa, .z = &secret.process_zeroing, .privilege = .direct },
        .root = .{ .io = io, .gpa = init.gpa, .z = &secret.process_zeroing, .privilege = privilege, .sudo = cfg.tools.sudo },
        .stdin = &stdin_reader.interface,
        .password_from_stdin = cmd.passwordFromStdin(),
    };

    const result = blk: {
        const passthrough: []const []const u8 = args[1..];
        enterOperationCoordinator(&app, cmd, passthrough) catch break :blk error.Exit;
        break :blk switch (cmd) {
            .init => commandInit(&app),
            .@"adopt-authentik-bootstrap-stdin" => commandAdopt(&app),
            .activate, .@"activate-stdin" => commandActivate(&app, .runtime),
            .@"activate-setup-stdin" => commandActivate(&app, .setup),
            .status => commandStatus(&app),
            .stop => commandStop(&app),
            .@"set-authentik-token" => commandSetToken(&app, true),
            .@"set-authentik-token-stdin" => commandSetToken(&app, false),
            .@"set-authentik-runtime-stdin" => commandSetRuntime(&app),
            .@"retire-authentik-bootstrap-stdin" => commandRetireBootstrap(&app),
            .@"check-authentik-token" => commandCheckToken(&app),
            .@"show-ntfy-password" => commandShow(&app, .ntfy),
            .@"show-zfs-key" => commandShow(&app, .zfs),
            .@"show-zfs-key-stdin" => commandShow(&app, .zfs_stdin),
            .@"show-authentik-bootstrap" => commandShow(&app, .bootstrap),
        };
    };
    if (app.lock_fd) |fd| sys.close(fd);
    result catch return if (app.status == 0) 1 else app.status;
    return 0;
}
