//! Compile-time configuration of `nas-secrets`.
//!
//! NixOS renders a ZON file from module options and passes it with
//! `-Dconfig=`. Feature flags are comptime, so a disabled service's secret
//! staging is not compiled in at all (the role `lib.optionalString` played in
//! the shell script), and malformed paths fail the build.

const std = @import("std");
const build_options = @import("build_options");

pub const Features = struct {
    grafana: bool = false,
    ntfy: bool = false,
    nut_webgui: bool = false,
    zfs_encryption: bool = false,
    vaultwarden: bool = false,
    /// `observability.enable || observability.ntfy.enable`.
    observability_dir: bool = false,
};

pub const Tools = struct {
    keepassxc_cli: []const u8 = "keepassxc-cli",
    sudo: []const u8 = "sudo",
    systemctl: []const u8 = "systemctl",
    install: []const u8 = "install",
    mktemp: []const u8 = "mktemp",
    ln: []const u8 = "ln",
    rm: []const u8 = "rm",
    mv: []const u8 = "mv",
    realpath: []const u8 = "realpath",
    chown: []const u8 = "chown",
    chmod: []const u8 = "chmod",
    cat: []const u8 = "cat",
    test_: []const u8 = "test",
    curl: []const u8 = "curl",
    timeout: []const u8 = "timeout",
};

pub const Config = struct {
    database: []const u8,
    key_file: ?[]const u8 = null,
    secret_group: []const u8,
    secret_root: []const u8,
    runtime_root: []const u8 = "/run/nas-secret-runtime",
    lock_file: []const u8 = "/run/lock/nas-secrets.lock",
    setup_state: []const u8 = "/var/lib/nas-setup/state.json",
    v2_systemd_state: []const u8 = "/run/nas-control/systemd-reconciled.json",
    bootstrap_authentik_dir: []const u8,
    authentik_runtime_environment_file: []const u8,
    authentik_unlocked_environment_file: []const u8,
    authentik_runtime_outpost_token_file: []const u8,
    authentik_api_token_file: []const u8,
    authentik_runtime_api_token_file: []const u8,
    authentik_ready_url: []const u8,
    bootstrap_email: []const u8,
    operation_runner: []const u8 = "/run/current-system/sw/bin/nas-operation-run",
    features: Features = .{},
    tools: Tools = .{},
};

pub const value: Config = @import("nas_config");

/// Paths that the test harness may relocate under a temporary root.
pub const relocatable = [_][]const u8{
    "database",                            "secret_root",
    "runtime_root",                        "lock_file",
    "setup_state",                         "v2_systemd_state",
    "bootstrap_authentik_dir",             "authentik_runtime_environment_file",
    "authentik_unlocked_environment_file", "authentik_runtime_outpost_token_file",
    "authentik_api_token_file",            "authentik_runtime_api_token_file",
};

comptime {
    @setEvalBranchQuota(100_000);
    for (relocatable) |field| requireAbsolute(field, @field(value, field));
    if (value.key_file) |kf| requireAbsolute("key_file", kf);
    requirePlain("secret_group", value.secret_group);
    requirePlain("bootstrap_email", value.bootstrap_email);
    if (std.mem.indexOfScalar(u8, value.bootstrap_email, '\'') != null)
        @compileError("nas config: bootstrap_email must not contain a single quote");
    if (!std.mem.startsWith(u8, value.authentik_ready_url, "http://127.0.0.1:"))
        @compileError("nas config: the Authentik readiness probe must stay on loopback");
}

fn requireAbsolute(comptime name: []const u8, comptime path: []const u8) void {
    if (path.len == 0 or path[0] != '/') @compileError("nas config: " ++ name ++ " must be an absolute path");
    if (std.mem.indexOf(u8, path, "/../") != null or std.mem.endsWith(u8, path, "/.."))
        @compileError("nas config: " ++ name ++ " must not contain '..'");
    requirePlain(name, path);
}

fn requirePlain(comptime name: []const u8, comptime text: []const u8) void {
    for (text) |c| if (c < 0x20 or c == 0x7f) @compileError("nas config: " ++ name ++ " contains a control character");
}

/// Runtime view of the configured paths. Production builds use the
/// comptime values verbatim; only `-Dtest-harness` builds honour
/// `NAS_SECRETS_TEST_ROOT`.
pub const Paths = struct {
    database: []const u8,
    key_file: ?[]const u8,
    secret_root: []const u8,
    runtime_root: []const u8,
    lock_file: []const u8,
    setup_state: []const u8,
    v2_systemd_state: []const u8,
    bootstrap_authentik_dir: []const u8,
    authentik_runtime_environment_file: []const u8,
    authentik_unlocked_environment_file: []const u8,
    authentik_runtime_outpost_token_file: []const u8,
    authentik_api_token_file: []const u8,
    authentik_runtime_api_token_file: []const u8,

    pub fn resolve(arena: std.mem.Allocator, environ: *const std.process.Environ.Map) error{OutOfMemory}!Paths {
        var p: Paths = undefined;
        p.key_file = value.key_file;
        const prefix: []const u8 = if (comptime build_options.test_harness) environ.get("NAS_SECRETS_TEST_ROOT") orelse "" else "";
        inline for (relocatable) |field| {
            @field(p, field) = if (prefix.len == 0) @field(value, field) else try std.mem.concat(arena, u8, &.{ prefix, @field(value, field) });
        }
        return p;
    }
};
