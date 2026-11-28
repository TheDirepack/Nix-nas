//! `keepassxc-cli` client. The database password travels only in a stdin
//! payload; entry names are a closed enum, so no caller can address an
//! arbitrary KDBX path.
//!
//! `Locked.unlock` verifies the password with `db-info` before returning an
//! `Unlocked` handle, and every read or write is a method of `Unlocked`.

const std = @import("std");
const command = @import("command.zig");
const secret = @import("secret.zig");
const log = @import("log.zig");
const Secret = secret.Secret;

pub const Entry = enum {
    @"authentik-secret-key",
    @"authentik-bootstrap-token",
    @"authentik-bootstrap-password",
    @"authentik-api-token",
    @"authentik-outpost-token",
    @"state-bundle-signing-key",
    @"grafana-secret-key",
    @"ntfy-admin-password",
    @"ntfy-alert-topic",
    @"nut-webgui-server-key",
    @"zfs-dataset-key",
    @"vaultwarden-oidc-client-secret",
    @"vaultwarden-admin",

    pub fn name(self: Entry) []const u8 {
        return @tagName(self);
    }
};

/// The wrong-password diagnostic is a contract: nas-unlock-api maps it to 401.
pub const wrong_password_marker = "Unable to unlock the KeePassXC database.";

pub const Error = error{ KeePassFailed, OutOfMemory };

pub const Locked = struct {
    runner: command.Runner,
    cli: []const u8,
    database: []const u8,
    key_file: ?[]const u8,
    group: []const u8,

    fn keyArgs(self: *const Locked) []const []const u8 {
        return if (self.key_file) |kf| &[_][]const u8{ "--key-file", kf } else &.{};
    }

    /// Takes ownership of `password` on success.
    pub fn unlock(self: Locked, password: Secret) error{WrongPassword}!Unlocked {
        var out = self.runner.run(
            .{ self.cli, "db-info", "--quiet", self.keyArgs(), self.database },
            secret.Payload.lines(1, .{&password}),
            .{},
        ) catch return error.WrongPassword;
        defer out.deinit();
        if (!out.exit.ok()) return error.WrongPassword;
        return .{ .db = self, .password = password };
    }
};

pub const Unlocked = struct {
    db: Locked,
    password: Secret,

    pub fn deinit(self: *Unlocked) void {
        self.password.deinit();
    }

    fn pw(self: *const Unlocked) secret.Payload {
        return secret.Payload.lines(1, .{&self.password});
    }

    fn entryPath(self: *const Unlocked, buf: []u8, entry: Entry) []const u8 {
        return std.fmt.bufPrint(buf, "{s}/{s}", .{ self.db.group, entry.name() }) catch unreachable;
    }

    pub fn ensureGroup(self: *const Unlocked) Error!void {
        const d = &self.db;
        if (self.quiet(.{ d.cli, "ls", "--quiet", d.keyArgs(), d.database, d.group })) return;
        if (!self.quiet(.{ d.cli, "mkdir", "--quiet", d.keyArgs(), d.database, d.group })) {
            log.err("Unable to ensure KeePassXC group: {s}", .{d.group});
            return error.KeePassFailed;
        }
    }

    fn quiet(self: *const Unlocked, args: anytype) bool {
        var out = self.db.runner.run(args, self.pw(), .{}) catch return false;
        defer out.deinit();
        return out.exit.ok();
    }

    pub fn has(self: *const Unlocked, entry: Entry) Error!bool {
        const d = &self.db;
        var out = d.runner.run(.{ d.cli, "ls", "--quiet", d.keyArgs(), "--flatten", d.database, d.group }, self.pw(), .{ .stdout = .capture }) catch {
            log.err("Unable to inspect the KeePassXC secret group.", .{});
            return error.KeePassFailed;
        };
        defer out.deinit();
        if (!out.exit.ok()) {
            log.err("Unable to inspect the KeePassXC secret group.", .{});
            return error.KeePassFailed;
        }
        var lines = std.mem.splitScalar(u8, out.stdout, '\n');
        while (lines.next()) |line| if (std.mem.eql(u8, line, entry.name())) return true;
        return false;
    }

    pub fn store(self: *const Unlocked, entry: Entry, value: Secret) Error!void {
        const d = &self.db;
        var buf: [512]u8 = undefined;
        const path = self.entryPath(&buf, entry);
        const verb: []const u8 = if (try self.has(entry)) "edit" else "add";
        var out = d.runner.run(
            .{ d.cli, verb, "--quiet", d.keyArgs(), "-p", d.database, path },
            secret.Payload.lines(2, .{ &self.password, &value }),
            .{ .stderr = .inherit },
        ) catch return error.KeePassFailed;
        defer out.deinit();
        if (!out.exit.ok()) {
            log.err("Unable to store KeePassXC entry: {s}", .{path});
            return error.KeePassFailed;
        }
    }

    pub fn remove(self: *const Unlocked, entry: Entry) Error!void {
        if (!try self.has(entry)) return;
        const d = &self.db;
        var buf: [512]u8 = undefined;
        const path = self.entryPath(&buf, entry);
        if (!self.quiet(.{ d.cli, "rm", "--quiet", d.keyArgs(), d.database, path })) {
            log.err("Unable to remove KeePassXC entry: {s}", .{path});
            return error.KeePassFailed;
        }
    }

    pub fn get(self: *const Unlocked, entry: Entry) Error!Secret {
        const d = &self.db;
        var buf: [512]u8 = undefined;
        const path = self.entryPath(&buf, entry);
        var out = d.runner.runSecret(
            .{ d.cli, "show", "--quiet", d.keyArgs(), "--show-protected", "-a", "Password", d.database, path },
            self.pw(),
            .{},
        ) catch {
            log.err("Unable to retrieve KeePassXC entry: {s}", .{path});
            return error.KeePassFailed;
        };
        defer d.runner.gpa.free(out.stderr);
        if (!out.exit.ok()) {
            out.value.deinit();
            log.err("Unable to retrieve KeePassXC entry: {s}", .{path});
            return error.KeePassFailed;
        }
        if (out.value.isEmpty()) {
            out.value.deinit();
            log.err("KeePassXC returned an empty password for: {s}", .{path});
            return error.KeePassFailed;
        }
        return out.value;
    }

    pub fn getOptional(self: *const Unlocked, entry: Entry) Error!?Secret {
        if (!try self.has(entry)) return null;
        return try self.get(entry);
    }
};

test "entry names are the KDBX contract" {
    try std.testing.expectEqualStrings("zfs-dataset-key", Entry.@"zfs-dataset-key".name());
}
