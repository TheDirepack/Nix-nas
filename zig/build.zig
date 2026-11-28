const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{ .preferred_optimize_mode = .safe });
    const config_path = b.option([]const u8, "config", "nas-secrets configuration (ZON)") orelse "config/default.zon";
    const test_harness = b.option(bool, "test-harness", "Build test-only hooks and the transaction harness") orelse false;

    const options = b.addOptions();
    options.addOption(bool, "test_harness", test_harness);

    // Nix passes an absolute store path; local builds use the repository default.
    const config_file: std.Build.LazyPath = if (std.fs.path.isAbsolute(config_path)) .{ .cwd_relative = config_path } else b.path(config_path);
    const nas_config = b.createModule(.{ .root_source_file = config_file });

    const Bin = struct { name: []const u8, root: []const u8, harness_only: bool = false };
    const bins = [_]Bin{
        .{ .name = "nas-secrets", .root = "src/nas_secrets.zig" },
        .{ .name = "nas-unlock-api", .root = "src/unlock_api.zig" },
        .{ .name = "nas-keepass-setup", .root = "src/keepass_setup.zig" },
        .{ .name = "nas-secret-tx-harness", .root = "src/tx_harness.zig", .harness_only = true },
    };

    const test_step = b.step("test", "Run Zig unit and fuzz tests (leak-checked)");
    for (bins) |bin| {
        const mod = b.createModule(.{
            .root_source_file = b.path(bin.root),
            .target = target,
            .optimize = optimize,
            .link_libc = false,
            .strip = optimize != .debug,
        });
        mod.addOptions("build_options", options);
        mod.addImport("nas_config", nas_config);

        if (!bin.harness_only or test_harness) {
            const exe = b.addExecutable(.{ .name = bin.name, .root_module = mod });
            b.installArtifact(exe);
        }
    }

    const test_mod = b.createModule(.{
        .root_source_file = b.path("src/tests.zig"),
        .target = target,
        .optimize = .debug,
    });
    test_mod.addOptions("build_options", options);
    test_mod.addImport("nas_config", nas_config);
    const tests = b.addTest(.{ .root_module = test_mod });
    test_step.dependOn(&b.addRunArtifact(tests).step);

    // Each snippet must fail to compile with the named diagnostic.
    const compile_errors = b.step("compile-errors", "Check that secret misuse and illegal transitions do not compile");
    const CompileFail = struct { file: []const u8, needle: []const u8 };
    const cases = [_]CompileFail{
        .{ .file = "tests/compile_errors/secret_format.zig", .needle = "a Secret cannot be formatted" },
        .{ .file = "tests/compile_errors/secret_argv.zig", .needle = "can never be a command-line argument" },
        .{ .file = "tests/compile_errors/password_argv.zig", .needle = "can never be a command-line argument" },
        .{ .file = "tests/compile_errors/secret_json.zig", .needle = "a Secret cannot be serialised" },
        .{ .file = "tests/compile_errors/staged_commit.zig", .needle = "no field or member function named 'commit'" },
        .{ .file = "tests/compile_errors/committed_rollback.zig", .needle = "no field or member function named 'rollback'" },
        .{ .file = "tests/compile_errors/setup_mode_link.zig", .needle = "expected type" },
        .{ .file = "tests/compile_errors/outcome_exhaustive.zig", .needle = "unhandled enumeration value: 'spawn_failed'" },
        .{ .file = "tests/compile_errors/privileged_payload.zig", .needle = "member function expected 2 argument(s), found 3" },
    };
    for (cases) |case| {
        const run = b.addSystemCommand(&.{ b.graph.zig_exe, "test", "--test-no-exec", "--dep", "nas" });
        run.addPrefixedFileArg("-Mroot=", b.path(case.file));
        run.addPrefixedFileArg("-Mnas=", b.path("src/lib.zig"));
        run.expectExitCode(1);
        run.addCheck(.{ .expect_stderr_match = case.needle });
        compile_errors.dependOn(&run.step);
    }
}
