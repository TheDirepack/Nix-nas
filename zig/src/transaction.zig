//! Secret-tree activation transaction as a typestate.
//!
//!   init ─▶ Staged ─swap─▶ Swapped ─commit─▶ Committed | CommitCleanupFailed
//!             │              │
//!             └─rollback─┐   └─rollback─┐      SwapFailed ─rollback─┐
//!                        ▼              ▼                            ▼
//!                    RolledBack | RollbackIncomplete
//!
//! Each state is a distinct type that exposes only its legal transitions, so
//! `staged.commit()` or `committed.rollback()` does not compile. Zig has no
//! affine types, so a copied handle could be used twice; `Context.phase`
//! keeps the runtime guard of the shell library for that case.
//!
//! Every privileged step runs as an external command through
//! `Runner.privileged`, which keeps the administrator-plus-sudo model of
//! `nas-secrets` and lets black-box tests inject faults on PATH.

const std = @import("std");
const command = @import("command.zig");
const validate = @import("validate.zig");
const log = @import("log.zig");

pub const Phase = enum {
    initialized,
    observing,
    stopping,
    stopped,
    old_moved,
    new_installed,
    committing,
    committed,
    commit_cleanup_failed,
    rolled_back,
    rollback_incomplete,

    pub fn label(self: Phase) []const u8 {
        return switch (self) {
            .initialized => "initialized",
            .observing => "observing",
            .stopping => "stopping",
            .stopped => "stopped",
            .old_moved => "old-moved",
            .new_installed => "new-installed",
            .committing => "committing",
            .committed => "committed",
            .commit_cleanup_failed => "commit-cleanup-failed",
            .rolled_back => "rolled-back",
            .rollback_incomplete => "rollback-incomplete",
        };
    }
};

pub const WasActive = enum {
    unknown,
    yes,
    no,

    pub fn label(self: WasActive) []const u8 {
        return switch (self) {
            .unknown => "unknown",
            .yes => "true",
            .no => "false",
        };
    }
};

const PathBuf = struct {
    buf: [std.fs.max_path_bytes]u8 = undefined,
    len: usize = 0,

    fn set(self: *PathBuf, value: []const u8) void {
        @memcpy(self.buf[0..value.len], value);
        self.len = value.len;
    }

    fn get(self: *const PathBuf) []const u8 {
        return self.buf[0..self.len];
    }
};

/// Executables for the privileged steps (absolute store paths in production).
pub const Tools = struct {
    systemctl: []const u8 = "systemctl",
    mv: []const u8 = "mv",
    rm: []const u8 = "rm",
    test_: []const u8 = "test",
    realpath: []const u8 = "realpath",
};

/// Shared transaction state; the typestate handles point at it.
pub const Context = struct {
    runner: command.Runner,
    tools: Tools,
    root: PathBuf = .{},
    stage: PathBuf = .{},
    previous: PathBuf = .{},
    directory: ?PathBuf = null,
    target: PathBuf = .{},
    phase: Phase = .initialized,
    swap_started: bool = false,
    old_moved: bool = false,
    new_installed: bool = false,
    committed: bool = false,
    was_active: WasActive = .unknown,

    fn rootPath(self: *const Context) []const u8 {
        return self.root.get();
    }
    fn stagePath(self: *const Context) []const u8 {
        return self.stage.get();
    }
    fn previousPath(self: *const Context) []const u8 {
        return self.previous.get();
    }
    fn targetName(self: *const Context) validate.TargetName {
        return .{ .name = self.target.get() };
    }

    fn privOk(self: *const Context, args: anytype) bool {
        return self.runner.privilegedOk(args) catch false;
    }

    /// Exit status of a privileged command (1 when it could not be run).
    fn privStatus(self: *const Context, args: anytype) u8 {
        var out = self.runner.privileged(args, .{ .stderr = .inherit }) catch return 1;
        defer out.deinit();
        return out.exit.status();
    }

    fn systemctl_(self: *const Context, args: anytype) command.Error!command.Output {
        return self.runner.privileged(.{self.tools.systemctl} ++ args, .{ .stdout = .capture, .stderr = .inherit });
    }

    const Observed = enum { active, inactive, failed };

    fn observeTarget(self: *const Context) ?Observed {
        var out = self.systemctl_(.{ "show", "--all", "--property=LoadState", "--property=ActiveState", "--property=Job", self.targetName() }) catch {
            log.err("nas-secret-transaction: protected target status is unavailable", .{});
            return null;
        };
        defer out.deinit();
        if (!out.exit.ok()) {
            log.err("nas-secret-transaction: protected target status is unavailable", .{});
            return null;
        }
        var load: []const u8 = "";
        var active: []const u8 = "";
        var job: ?[]const u8 = null;
        var lines = std.mem.splitScalar(u8, out.stdout, '\n');
        while (lines.next()) |line| {
            if (std.mem.startsWith(u8, line, "LoadState=")) load = line["LoadState=".len..];
            if (std.mem.startsWith(u8, line, "ActiveState=")) active = line["ActiveState=".len..];
            if (std.mem.startsWith(u8, line, "Job=")) job = line["Job=".len..];
        }
        if (std.mem.eql(u8, load, "loaded") and job != null and job.?.len == 0) {
            if (std.mem.eql(u8, active, "active")) return .active;
            if (std.mem.eql(u8, active, "inactive")) return .inactive;
            if (std.mem.eql(u8, active, "failed")) return .failed;
        }
        var safe: [3][128]u8 = undefined;
        log.err("nas-secret-transaction: protected target has no stable loaded state (load={s}, active={s}, job={s})", .{
            log.sanitize(&safe[0], load), log.sanitize(&safe[1], active), log.sanitize(&safe[2], job orelse "unavailable"),
        });
        return null;
    }

    fn stopTarget(self: *const Context) bool {
        var stop_status: u8 = 0;
        if (self.systemctl_(.{ "stop", self.targetName() })) |o| {
            var out = o;
            defer out.deinit();
            stop_status = out.exit.status();
        } else |_| stop_status = 1;
        // Neither stop success nor a failed status query proves consumers are stopped.
        const state = self.observeTarget() orelse return false;
        switch (state) {
            .inactive, .failed => return true,
            .active => {},
        }
        log.err("nas-secret-transaction: protected target remains active after stop (status {d})", .{stop_status});
        return false;
    }

    fn removeDirectory(self: *const Context) bool {
        const dir = self.directory orelse return true;
        return self.privOk(.{ self.tools.rm, "-rf", "--", dir.get() });
    }

    fn exists(self: *const Context, path: []const u8) bool {
        return self.privOk(.{ self.tools.test_, "-e", path }) or self.privOk(.{ self.tools.test_, "-L", path });
    }

    fn isRealDir(self: *const Context, path: []const u8) bool {
        return self.privOk(.{ self.tools.test_, "-d", path }) and !self.privOk(.{ self.tools.test_, "-L", path });
    }

    fn hasReadyMarker(self: *const Context, dir: []const u8) bool {
        var buf: [std.fs.max_path_bytes]u8 = undefined;
        const ready = std.fmt.bufPrint(&buf, "{s}/ready", .{dir}) catch return false;
        return self.privOk(.{ self.tools.test_, "-f", ready }) and !self.privOk(.{ self.tools.test_, "-L", ready });
    }

    fn rollback(self: *Context) RollbackOutcome {
        if (self.committed) {
            log.err("nas-secret-transaction: refusing rollback after commit", .{});
            return .{ .incomplete = .{ .ctx = self } };
        }
        var failed = false;
        if (!self.swap_started) {
            if (!self.privOk(.{ self.tools.rm, "-rf", "--", self.stagePath() })) failed = true;
            // Deleting the transaction directory also deletes the stage; do it
            // only after the stage is gone so a failed removal keeps every copy.
            if (!failed and !self.removeDirectory()) failed = true;
            if (failed) {
                self.phase = .rollback_incomplete;
                const recovery = if (self.directory) |d| d.get() else self.stagePath();
                log.err("nas-secret-transaction: pre-swap cleanup was incomplete; retained recovery tree {s}; staged tree {s}", .{ recovery, self.stagePath() });
                return .{ .incomplete = .{ .ctx = self } };
            }
            self.phase = .rolled_back;
            return .{ .rolled_back = .{ .ctx = self } };
        }

        // An unknown prior state or unconfirmed stop must preserve every secret tree.
        if (self.was_active == .unknown or !self.stopTarget()) {
            failed = true;
        } else {
            if (self.new_installed and !self.privOk(.{ self.tools.rm, "-rf", "--", self.rootPath() })) failed = true;
            if (self.old_moved) {
                if (self.isRealDir(self.previousPath())) {
                    if (!failed) {
                        if (!self.privOk(.{ self.tools.mv, "-T", "--", self.previousPath(), self.rootPath() })) failed = true;
                    }
                } else {
                    log.err("nas-secret-transaction: previous secret tree disappeared or became unsafe during rollback: {s}", .{self.previousPath()});
                    failed = true;
                }
            }
            // Starting the target before the restore is known good would run
            // consumers against a half-rolled-back tree.
            if (self.was_active == .yes and !failed) {
                if (self.hasReadyMarker(self.rootPath())) {
                    if (self.systemctl_(.{ "start", self.targetName() })) |o| {
                        var out = o;
                        defer out.deinit();
                        if (!out.exit.ok()) failed = true;
                    } else |_| failed = true;
                } else {
                    log.err("nas-secret-transaction: restored secret tree is not ready; protected target remains stopped", .{});
                    failed = true;
                }
            }
            if (!self.privOk(.{ self.tools.rm, "-rf", "--", self.stagePath() })) failed = true;
            if (!failed and !self.removeDirectory()) failed = true;
        }
        if (failed) {
            self.phase = .rollback_incomplete;
            log.err("nas-secret-transaction: rollback was incomplete; inspect systemd and {s}", .{self.rootPath()});
            // Retention is the only recovery path once rollback fails, so name
            // every tree the operator still has.
            const candidates = [_]?[]const u8{ if (self.directory) |*d| d.get() else null, self.stagePath(), self.previousPath() };
            for (candidates) |candidate| {
                const path = candidate orelse continue;
                if (self.exists(path)) log.err("nas-secret-transaction: retained recovery tree {s}", .{path});
            }
            return .{ .incomplete = .{ .ctx = self } };
        }
        self.phase = .rolled_back;
        return .{ .rolled_back = .{ .ctx = self } };
    }
};

// ------------------------------------------------------------ typestates

pub const Staged = struct {
    ctx: *Context,

    pub fn swap(self: Staged) SwapOutcome {
        const c = self.ctx;
        if (c.phase != .initialized) {
            log.err("nas-secret-transaction: invalid swap phase: {s}", .{c.phase.label()});
            return .{ .failed = .{ .ctx = c, .status = 1 } };
        }
        const fail = SwapFailed{ .ctx = c, .status = 1 };
        if (!c.privOk(.{ c.tools.test_, "-d", c.stagePath() })) {
            log.err("nas-secret-transaction: staged tree is unavailable: {s}", .{c.stagePath()});
            return .{ .failed = fail };
        }
        if (c.privOk(.{ c.tools.test_, "-L", c.stagePath() })) {
            log.err("nas-secret-transaction: staged tree must not be a symlink: {s}", .{c.stagePath()});
            return .{ .failed = fail };
        }
        var ready_buf: [std.fs.max_path_bytes]u8 = undefined;
        const ready = std.fmt.bufPrint(&ready_buf, "{s}/ready", .{c.stagePath()}) catch return .{ .failed = fail };
        if (!c.privOk(.{ c.tools.test_, "-f", ready })) {
            log.err("nas-secret-transaction: staged tree is missing its ready marker", .{});
            return .{ .failed = fail };
        }
        if (c.privOk(.{ c.tools.test_, "-L", ready })) {
            log.err("nas-secret-transaction: staged ready marker must not be a symlink", .{});
            return .{ .failed = fail };
        }
        if (c.privOk(.{ c.tools.test_, "-e", c.rootPath() })) {
            if (!c.privOk(.{ c.tools.test_, "-d", c.rootPath() })) {
                log.err("nas-secret-transaction: live secret root is not a directory: {s}", .{c.rootPath()});
                return .{ .failed = fail };
            }
            if (c.privOk(.{ c.tools.test_, "-L", c.rootPath() })) {
                log.err("nas-secret-transaction: live secret root must not be a symlink: {s}", .{c.rootPath()});
                return .{ .failed = fail };
            }
        }
        if (c.privOk(.{ c.tools.test_, "-e", c.previousPath() })) {
            log.err("nas-secret-transaction: previous tree already exists: {s}", .{c.previousPath()});
            return .{ .failed = fail };
        }
        c.swap_started = true;
        c.phase = .observing;
        const state = c.observeTarget() orelse return .{ .failed = fail };
        c.was_active = switch (state) {
            .active => .yes,
            .inactive, .failed => .no,
        };

        c.phase = .stopping;
        if (!c.stopTarget()) return .{ .failed = fail };
        c.phase = .stopped;
        if (c.privOk(.{ c.tools.test_, "-d", c.rootPath() })) {
            const status = c.privStatus(.{ c.tools.mv, "-T", "--", c.rootPath(), c.previousPath() });
            if (status != 0) return .{ .failed = .{ .ctx = c, .status = status } };
            c.old_moved = true;
        }
        c.phase = .old_moved;
        const status = c.privStatus(.{ c.tools.mv, "-T", "--", c.stagePath(), c.rootPath() });
        if (status != 0) return .{ .failed = .{ .ctx = c, .status = status } };
        c.new_installed = true;
        c.phase = .new_installed;
        if (!c.isRealDir(c.rootPath()) or !c.hasReadyMarker(c.rootPath())) {
            log.err("nas-secret-transaction: installed secret tree failed post-swap validation", .{});
            return .{ .failed = fail };
        }
        return .{ .swapped = .{ .ctx = c } };
    }

    pub fn rollback(self: Staged) RollbackOutcome {
        return self.ctx.rollback();
    }
};

pub const SwapOutcome = union(enum) {
    swapped: Swapped,
    failed: SwapFailed,
};

/// A swap that stopped part-way; only rollback is possible.
pub const SwapFailed = struct {
    ctx: *Context,
    status: u8,

    pub fn rollback(self: SwapFailed) RollbackOutcome {
        return self.ctx.rollback();
    }
};

pub const Swapped = struct {
    ctx: *Context,

    pub fn commit(self: Swapped) CommitOutcome {
        const c = self.ctx;
        if (c.phase != .new_installed or !c.new_installed) {
            log.err("nas-secret-transaction: invalid commit phase: {s}", .{c.phase.label()});
            return .{ .rejected = self };
        }
        if (c.committed) {
            log.err("nas-secret-transaction: transaction is already committed", .{});
            return .{ .rejected = self };
        }
        // Rollback is unsafe from here: cleanup may delete the prior tree.
        c.committed = true;
        c.phase = .committing;
        if (!c.privOk(.{ c.tools.rm, "-rf", "--", c.previousPath() })) {
            c.phase = .commit_cleanup_failed;
            log.err("nas-secret-transaction: committed new tree but could not remove previous tree", .{});
            return .{ .cleanup_failed = .{ .ctx = c } };
        }
        if (!c.removeDirectory()) {
            c.phase = .commit_cleanup_failed;
            log.err("nas-secret-transaction: committed new tree but could not remove transaction directory", .{});
            return .{ .cleanup_failed = .{ .ctx = c } };
        }
        c.phase = .committed;
        return .{ .committed = .{ .ctx = c } };
    }

    pub fn rollback(self: Swapped) RollbackOutcome {
        return self.ctx.rollback();
    }
};

pub const CommitOutcome = union(enum) {
    committed: Committed,
    /// The new tree is authoritative but stale material remains (status 125).
    cleanup_failed: CommitCleanupFailed,
    /// A copied handle was reused after the transaction moved on.
    rejected: Swapped,
};

pub const Committed = struct { ctx: *Context };
pub const CommitCleanupFailed = struct { ctx: *Context };
pub const RolledBack = struct { ctx: *Context };
pub const RollbackIncomplete = struct { ctx: *Context };

pub const RollbackOutcome = union(enum) {
    rolled_back: RolledBack,
    incomplete: RollbackIncomplete,
};

/// Status 125 means "manual recovery required" throughout nas-secrets.
pub const manual_recovery_status: u8 = 125;

/// Exit status after a failure with primary status `rc`, mirroring
/// `nas_secret_tx_cleanup`: an incomplete rollback is 125, and a "successful"
/// exit without commit is treated as a programming error (also 125).
pub fn statusAfterRollback(outcome: RollbackOutcome, rc: u8) u8 {
    switch (outcome) {
        .incomplete => {
            log.err("nas-secret-transaction: manual recovery required; primary status {d}", .{rc});
            return manual_recovery_status;
        },
        .rolled_back => {
            if (rc == 0) {
                log.err("nas-secret-transaction: transaction exited successfully without commit; rolled back", .{});
                return manual_recovery_status;
            }
            return rc;
        },
    }
}

// ------------------------------------------------------------------ init

pub const Request = struct {
    root: []const u8,
    stage: []const u8,
    previous: []const u8,
    target: []const u8 = "nas-protected-services.target",
    directory: ?[]const u8 = null,
};

pub const InitError = error{InvalidTransaction};

pub fn init(ctx: *Context, runner: command.Runner, tools: Tools, req: Request) InitError!Staged {
    ctx.* = .{ .runner = runner, .tools = tools };
    var bufs: [4][std.fs.max_path_bytes]u8 = undefined;
    const root = validate.lexicalNormalize(&bufs[0], req.root) catch {
        log.err("nas-secret-transaction: secret root must be an absolute path: {s}", .{req.root});
        return error.InvalidTransaction;
    };
    const stage = validate.lexicalNormalize(&bufs[1], req.stage) catch {
        log.err("nas-secret-transaction: staged tree must be an absolute path: {s}", .{req.stage});
        return error.InvalidTransaction;
    };
    const previous = validate.lexicalNormalize(&bufs[2], req.previous) catch {
        log.err("nas-secret-transaction: previous tree must be an absolute path: {s}", .{req.previous});
        return error.InvalidTransaction;
    };
    var directory: ?[]const u8 = null;
    if (req.directory) |d| {
        if (d.len > 0) directory = validate.lexicalNormalize(&bufs[3], d) catch {
            log.err("nas-secret-transaction: transaction directory must be an absolute path: {s}", .{d});
            return error.InvalidTransaction;
        };
    }
    for ([_][]const u8{ root, stage, previous }) |value| {
        if (std.mem.eql(u8, value, "/")) {
            log.err("nas-secret-transaction: refusing to operate on filesystem root", .{});
            return error.InvalidTransaction;
        }
        if (!parentIsPhysical(ctx, value)) {
            log.err("nas-secret-transaction: parent path is missing or traverses a symlink: {s}", .{value});
            return error.InvalidTransaction;
        }
    }
    if (validate.pathsOverlap(root, stage)) {
        log.err("nas-secret-transaction: secret root and staged tree must be disjoint", .{});
        return error.InvalidTransaction;
    }
    if (validate.pathsOverlap(root, previous)) {
        log.err("nas-secret-transaction: secret root and previous tree must be disjoint", .{});
        return error.InvalidTransaction;
    }
    if (validate.pathsOverlap(stage, previous)) {
        log.err("nas-secret-transaction: staged and previous trees must be disjoint", .{});
        return error.InvalidTransaction;
    }
    if (directory) |dir| {
        if (std.mem.eql(u8, dir, "/")) {
            log.err("nas-secret-transaction: refusing filesystem root as transaction directory", .{});
            return error.InvalidTransaction;
        }
        if (!ctx.isRealDir(dir)) {
            log.err("nas-secret-transaction: transaction directory must be a real directory: {s}", .{dir});
            return error.InvalidTransaction;
        }
        var physical = ctx.runner.privileged(.{ ctx.tools.realpath, "-e", "--", dir }, .{ .stdout = .capture }) catch {
            log.err("nas-secret-transaction: transaction directory cannot be resolved safely: {s}", .{dir});
            return error.InvalidTransaction;
        };
        defer physical.deinit();
        if (!physical.exit.ok()) {
            log.err("nas-secret-transaction: transaction directory cannot be resolved safely: {s}", .{dir});
            return error.InvalidTransaction;
        }
        if (!std.mem.eql(u8, std.mem.trimEnd(u8, physical.stdout, "\n"), dir)) {
            log.err("nas-secret-transaction: transaction directory traverses a symlink: {s}", .{dir});
            return error.InvalidTransaction;
        }
        // The directory may contain stage/previous but never the live root.
        if (validate.pathsOverlap(root, dir)) {
            log.err("nas-secret-transaction: transaction directory must be disjoint from the live secret root", .{});
            return error.InvalidTransaction;
        }
        if (!std.mem.eql(u8, validate.dirname(stage), dir) or !std.mem.eql(u8, validate.dirname(previous), dir)) {
            log.err("nas-secret-transaction: staged and previous trees must be direct children of the transaction directory", .{});
            return error.InvalidTransaction;
        }
    }
    _ = validate.TargetName.parse(req.target) catch {
        var safe: [256]u8 = undefined;
        log.err("nas-secret-transaction: invalid protected target name: {s}", .{log.sanitize(&safe, req.target)});
        return error.InvalidTransaction;
    };
    ctx.root.set(root);
    ctx.stage.set(stage);
    ctx.previous.set(previous);
    if (directory) |d| {
        ctx.directory = .{};
        ctx.directory.?.set(d);
    }
    ctx.target.set(req.target);
    return .{ .ctx = ctx };
}

fn parentIsPhysical(ctx: *Context, value: []const u8) bool {
    const parent = validate.dirname(value);
    // The physical resolution must observe the filesystem the privileged swap
    // operates on; transaction trees sit under root-owned 0700 directories.
    var out = ctx.runner.privileged(.{ ctx.tools.realpath, "-e", "--", parent }, .{ .stdout = .capture }) catch return false;
    defer out.deinit();
    if (!out.exit.ok()) return false;
    return std.mem.eql(u8, std.mem.trimEnd(u8, out.stdout, "\n"), parent);
}

test "phase labels match the shell library" {
    try std.testing.expectEqualStrings("rollback-incomplete", Phase.rollback_incomplete.label());
    try std.testing.expectEqualStrings("new-installed", Phase.new_installed.label());
}

test "typestates expose only legal transitions" {
    try std.testing.expect(@hasDecl(Staged, "swap") and !@hasDecl(Staged, "commit"));
    try std.testing.expect(@hasDecl(Swapped, "commit") and @hasDecl(Swapped, "rollback") and !@hasDecl(Swapped, "swap"));
    try std.testing.expect(!@hasDecl(SwapFailed, "commit"));
    inline for (.{ Committed, CommitCleanupFailed, RolledBack, RollbackIncomplete }) |Terminal| {
        try std.testing.expect(!@hasDecl(Terminal, "rollback") and !@hasDecl(Terminal, "commit") and !@hasDecl(Terminal, "swap"));
    }
}
