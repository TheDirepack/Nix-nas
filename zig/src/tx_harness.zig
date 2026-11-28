//! Test-only driver for the activation transaction (built with -Dtest-harness).
//!
//! Reads one tab-separated command per line from stdin and prints
//! `<command> <status>`:
//!   init ROOT STAGE PREVIOUS [TARGET [DIRECTORY]]
//!   swap | commit | cleanup RC | phase | was-active
//!   sh SHELL-COMMAND...        (filesystem mutation between steps)
//!   setenv NAME VALUE | unsetenv NAME
//! Illegal transitions are reported the way the runtime guard would, because
//! the typestate API itself offers no method to call.

const std = @import("std");
const Io = std.Io;
const build_options = @import("build_options");
const command = @import("command.zig");
const secret = @import("secret.zig");
const transaction = @import("transaction.zig");
const log = @import("log.zig");

comptime {
    if (!build_options.test_harness) @compileError("nas-secret-tx-harness exists only in -Dtest-harness builds");
}

const State = union(enum) {
    none,
    staged: transaction.Staged,
    swapped: transaction.Swapped,
    failed: transaction.SwapFailed,
    committed,
    commit_dirty,
    finished,
};

pub fn main(init: std.process.Init) u8 {
    const io = init.io;
    const gpa = init.gpa;
    const env = init.environ_map;
    var z: secret.ZeroingAllocator = .init(gpa);

    const privilege_value = env.get("NAS_SECRET_TX_PRIVILEGE") orelse "";
    const systemctl = env.get("NAS_SECRET_TX_SYSTEMCTL") orelse "systemctl";
    const runner: command.Runner = .{
        .io = io,
        .gpa = gpa,
        .z = &z,
        .privilege = if (privilege_value.len == 0) .direct else .sudo,
        .sudo = privilege_value,
        .environ = env,
    };

    var ctx: transaction.Context = undefined;
    var initialized = false;
    var state: State = .none;

    var buf: [8192]u8 = undefined;
    var reader = Io.File.stdin().readerStreaming(io, &buf);
    while (reader.interface.takeDelimiter('\n') catch null) |raw| {
        const line = std.mem.trim(u8, raw, "\r");
        if (line.len == 0) continue;
        var words = std.mem.tokenizeScalar(u8, line, '\t');
        const verb = words.next().?;
        var status: u8 = 0;
        if (std.mem.eql(u8, verb, "init")) {
            var parts: [5][]const u8 = undefined;
            var n: usize = 0;
            while (words.next()) |w| : (n += 1) {
                if (n == parts.len) break;
                parts[n] = w;
            }
            if (n < 3) {
                status = 2;
            } else if (transaction.init(&ctx, runner, .{ .systemctl = systemctl }, .{
                .root = parts[0],
                .stage = parts[1],
                .previous = parts[2],
                .target = if (n > 3) parts[3] else "nas-protected-services.target",
                .directory = if (n > 4) parts[4] else null,
            })) |staged| {
                initialized = true;
                state = .{ .staged = staged };
            } else |_| status = 1;
        } else if (std.mem.eql(u8, verb, "swap")) {
            switch (state) {
                .staged => |s| switch (s.swap()) {
                    .swapped => |sw| state = .{ .swapped = sw },
                    .failed => |f| {
                        status = f.status;
                        state = .{ .failed = f };
                    },
                },
                else => {
                    log.err("nas-secret-transaction: invalid swap phase: {s}", .{if (initialized) ctx.phase.label() else "unset"});
                    status = 1;
                },
            }
        } else if (std.mem.eql(u8, verb, "commit")) {
            switch (state) {
                .swapped => |s| switch (s.commit()) {
                    .committed => state = .committed,
                    .cleanup_failed => {
                        state = .commit_dirty;
                        status = transaction.manual_recovery_status;
                    },
                    .rejected => status = 1,
                },
                else => {
                    log.err("nas-secret-transaction: invalid commit phase: {s}", .{if (initialized) ctx.phase.label() else "unset"});
                    status = 1;
                },
            }
        } else if (std.mem.eql(u8, verb, "cleanup")) {
            const text = words.next() orelse "";
            const rc = std.fmt.parseInt(u8, text, 10) catch {
                log.err("nas-secret-transaction: cleanup status must be an exit status from 0 through 255", .{});
                print("cleanup 125");
                continue;
            };
            status = switch (state) {
                .committed, .commit_dirty, .none, .finished => rc,
                .staged => |s| transaction.statusAfterRollback(s.rollback(), rc),
                .swapped => |s| transaction.statusAfterRollback(s.rollback(), rc),
                .failed => |f| transaction.statusAfterRollback(f.rollback(), rc),
            };
            if (state != .committed and state != .commit_dirty and state != .none) state = .finished;
        } else if (std.mem.eql(u8, verb, "phase")) {
            printKv("phase", if (initialized) ctx.phase.label() else "unset");
            continue;
        } else if (std.mem.eql(u8, verb, "was-active")) {
            printKv("was-active", if (initialized) ctx.was_active.label() else "unknown");
            continue;
        } else if (std.mem.eql(u8, verb, "sh")) {
            const rest = std.mem.trim(u8, line["sh".len..], "\t ");
            var out = runner.run(.{ "sh", "-c", rest }, null, .{ .stdout = .inherit, .stderr = .inherit }) catch {
                print("sh 127");
                continue;
            };
            status = out.exit.status();
            out.deinit();
        } else if (std.mem.eql(u8, verb, "setenv")) {
            const name = words.next() orelse "";
            const value = words.rest();
            env.put(name, value) catch return 1;
        } else if (std.mem.eql(u8, verb, "unsetenv")) {
            _ = env.swapRemove(words.next() orelse "");
        } else {
            status = 2;
        }
        var msg: [64]u8 = undefined;
        print(std.fmt.bufPrint(&msg, "{s} {d}", .{ verb, status }) catch "?");
    }
    return 0;
}

fn print(text: []const u8) void {
    log.out("{s}", .{text});
}

fn printKv(k: []const u8, v: []const u8) void {
    log.out("{s} {s}", .{ k, v });
}
