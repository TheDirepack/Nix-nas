//! Thin Linux syscall layer with closed error sets.
//!
//! The 0.16+ standard library moved most POSIX wrappers behind `std.Io`.
//! Privileged appliance code needs lstat-style checks, `RENAME_NOREPLACE`,
//! `SO_PEERCRED` and `flock`, so it talks to `std.os.linux` directly.

const std = @import("std");
const linux = std.os.linux;

pub const fd_t = linux.fd_t;
pub const uid_t = linux.uid_t;
pub const gid_t = linux.gid_t;
pub const pid_t = linux.pid_t;

pub const Error = error{
    AccessDenied,
    FileNotFound,
    PathAlreadyExists,
    NotDir,
    IsDir,
    SymLinkLoop,
    NameTooLong,
    NoSpaceLeft,
    ReadOnlyFileSystem,
    Busy,
    WouldBlock,
    InvalidArgument,
    BadFileDescriptor,
    SystemResources,
    ConnectionReset,
    BrokenPipe,
    CrossDevice,
    DirNotEmpty,
    TimedOut,
    Unexpected,
};

fn check(rc: usize) Error!usize {
    return switch (linux.errno(rc)) {
        .SUCCESS => rc,
        .ACCES, .PERM => error.AccessDenied,
        .NOENT => error.FileNotFound,
        .EXIST => error.PathAlreadyExists,
        .NOTDIR => error.NotDir,
        .ISDIR => error.IsDir,
        .LOOP => error.SymLinkLoop,
        .NAMETOOLONG => error.NameTooLong,
        .NOSPC, .DQUOT => error.NoSpaceLeft,
        .ROFS => error.ReadOnlyFileSystem,
        .BUSY, .TXTBSY => error.Busy,
        .AGAIN => error.WouldBlock,
        .INVAL => error.InvalidArgument,
        .BADF => error.BadFileDescriptor,
        .NOMEM, .NFILE, .MFILE, .NOBUFS => error.SystemResources,
        .CONNRESET => error.ConnectionReset,
        .PIPE => error.BrokenPipe,
        .XDEV => error.CrossDevice,
        .NOTEMPTY => error.DirNotEmpty,
        .TIMEDOUT => error.TimedOut,
        else => error.Unexpected,
    };
}

/// Retries a syscall interrupted by a signal; every caller here is idempotent
/// until it succeeds.
fn retry(comptime f: anytype, args: anytype) Error!usize {
    while (true) {
        const rc = @call(.auto, f, args);
        if (linux.errno(rc) == .INTR) continue;
        return check(rc);
    }
}

pub const Kind = enum { regular, directory, symlink, socket, other };

pub const Stat = struct {
    kind: Kind,
    /// Permission bits only (`mode & 0o7777`).
    mode: u32,
    uid: uid_t,
    gid: gid_t,
    size: u64,
};

fn statAt(dir: fd_t, path: [*:0]const u8, flags: u32) Error!Stat {
    var buf: linux.Statx = undefined;
    _ = try retry(linux.statx, .{ dir, path, flags, linux.STATX{ .TYPE = true, .MODE = true, .UID = true, .GID = true, .SIZE = true }, &buf });
    const fmt = buf.mode & linux.S.IFMT;
    const kind: Kind = switch (fmt) {
        linux.S.IFREG => .regular,
        linux.S.IFDIR => .directory,
        linux.S.IFLNK => .symlink,
        linux.S.IFSOCK => .socket,
        else => .other,
    };
    return .{ .kind = kind, .mode = buf.mode & 0o7777, .uid = buf.uid, .gid = buf.gid, .size = buf.size };
}

/// Does not follow a final symlink.
pub fn lstat(path: [*:0]const u8) Error!Stat {
    return statAt(linux.AT.FDCWD, path, linux.AT.SYMLINK_NOFOLLOW);
}

pub fn stat(path: [*:0]const u8) Error!Stat {
    return statAt(linux.AT.FDCWD, path, 0);
}

pub fn fstat(fd: fd_t) Error!Stat {
    return statAt(fd, "", linux.AT.EMPTY_PATH);
}

/// Absence is a normal answer; other failures are not.
pub fn lexists(path: [*:0]const u8) Error!bool {
    _ = lstat(path) catch |err| switch (err) {
        error.FileNotFound, error.NotDir => return false,
        else => return err,
    };
    return true;
}

pub fn open(path: [*:0]const u8, flags: linux.O, mode: u32) Error!fd_t {
    var f = flags;
    f.CLOEXEC = true;
    const rc = try retry(linux.openat, .{ linux.AT.FDCWD, path, f, @as(linux.mode_t, @intCast(mode)) });
    return @intCast(rc);
}

pub fn openAt(dir: fd_t, path: [*:0]const u8, flags: linux.O, mode: u32) Error!fd_t {
    var f = flags;
    f.CLOEXEC = true;
    const rc = try retry(linux.openat, .{ dir, path, f, @as(linux.mode_t, @intCast(mode)) });
    return @intCast(rc);
}

pub fn close(fd: fd_t) void {
    _ = linux.close(fd);
}

pub fn read(fd: fd_t, buf: []u8) Error!usize {
    return retry(linux.read, .{ fd, buf.ptr, buf.len });
}

pub fn writeAll(fd: fd_t, bytes: []const u8) Error!void {
    var rest = bytes;
    while (rest.len > 0) {
        const n = try retry(linux.write, .{ fd, rest.ptr, rest.len });
        if (n == 0) return error.Unexpected;
        rest = rest[n..];
    }
}

pub fn fchmod(fd: fd_t, mode: u32) Error!void {
    _ = try retry(linux.fchmod, .{ fd, @as(linux.mode_t, @intCast(mode)) });
}

pub fn chmod(path: [*:0]const u8, mode: u32) Error!void {
    _ = try retry(linux.fchmodat, .{ linux.AT.FDCWD, path, @as(linux.mode_t, @intCast(mode)) });
}

pub fn chown(path: [*:0]const u8, uid: uid_t, gid: gid_t) Error!void {
    _ = try retry(linux.fchownat, .{ linux.AT.FDCWD, path, uid, gid, @as(u32, 0) });
}

pub fn mkdir(path: [*:0]const u8, mode: u32) Error!void {
    _ = try retry(linux.mkdirat, .{ linux.AT.FDCWD, path, @as(linux.mode_t, @intCast(mode)) });
}

pub fn unlink(path: [*:0]const u8) Error!void {
    _ = try retry(linux.unlinkat, .{ linux.AT.FDCWD, path, @as(u32, 0) });
}

/// Atomic rename that fails with `PathAlreadyExists` instead of replacing.
pub fn renameNoReplace(old: [*:0]const u8, new: [*:0]const u8) Error!void {
    _ = try retry(linux.renameat2, .{ linux.AT.FDCWD, old, linux.AT.FDCWD, new, linux.RENAME{ .NOREPLACE = true } });
}

const lock_ex = 2;
const lock_nb = 4;

pub fn flockExclusiveNonBlocking(fd: fd_t) Error!void {
    _ = try retry(linux.flock, .{ fd, @as(i32, lock_ex | lock_nb) });
}

pub fn geteuid() uid_t {
    return linux.geteuid();
}

pub fn getuid() uid_t {
    return linux.getuid();
}

pub fn getgid() gid_t {
    return linux.getgid();
}

pub fn getpid() pid_t {
    return linux.getpid();
}

/// Secret-holding processes are not dumpable: no core file, and no ptrace by
/// other processes of the same user.
pub fn disableCoreDumps() void {
    _ = linux.prctl(@backingInt(linux.PR.SET_DUMPABLE), 0, 0, 0, 0);
}

pub fn isatty(fd: fd_t) bool {
    var t: linux.termios = undefined;
    return linux.errno(linux.tcgetattr(fd, &t)) == .SUCCESS;
}

/// Disables terminal echo and returns the previous settings for `restoreEcho`.
pub fn disableEcho(fd: fd_t) ?linux.termios {
    var t: linux.termios = undefined;
    if (linux.errno(linux.tcgetattr(fd, &t)) != .SUCCESS) return null;
    const saved = t;
    t.lflag.ECHO = false;
    if (linux.errno(linux.tcsetattr(fd, .FLUSH, &t)) != .SUCCESS) return null;
    return saved;
}

pub fn restoreEcho(fd: fd_t, saved: linux.termios) void {
    _ = linux.tcsetattr(fd, .FLUSH, &saved);
}

// ---------------------------------------------------------------- sockets

pub const Credentials = struct { pid: pid_t, uid: uid_t, gid: gid_t };

pub fn unixListen(path: []const u8, backlog: u31) Error!fd_t {
    var addr: linux.sockaddr.un = .{ .family = linux.AF.UNIX, .path = undefined };
    @memset(&addr.path, 0);
    if (path.len >= addr.path.len) return error.NameTooLong;
    @memcpy(addr.path[0..path.len], path);
    const fd: fd_t = @intCast(try retry(linux.socket, .{ @as(u32, linux.AF.UNIX), @as(u32, linux.SOCK.STREAM | linux.SOCK.CLOEXEC), @as(u32, 0) }));
    errdefer close(fd);
    _ = try retry(linux.bind, .{ fd, @as(*const linux.sockaddr, @ptrCast(&addr)), @as(linux.socklen_t, @sizeOf(linux.sockaddr.un)) });
    _ = try retry(linux.listen, .{ fd, @as(u32, backlog) });
    return fd;
}

pub fn unixConnect(path: []const u8) Error!fd_t {
    var addr: linux.sockaddr.un = .{ .family = linux.AF.UNIX, .path = undefined };
    @memset(&addr.path, 0);
    if (path.len >= addr.path.len) return error.NameTooLong;
    @memcpy(addr.path[0..path.len], path);
    const fd: fd_t = @intCast(try retry(linux.socket, .{ @as(u32, linux.AF.UNIX), @as(u32, linux.SOCK.STREAM | linux.SOCK.CLOEXEC), @as(u32, 0) }));
    errdefer close(fd);
    _ = try retry(linux.connect, .{ fd, @as(*const anyopaque, @ptrCast(&addr)), @as(linux.socklen_t, @sizeOf(linux.sockaddr.un)) });
    return fd;
}

pub fn accept(fd: fd_t) Error!fd_t {
    return @intCast(try retry(linux.accept4, .{ fd, null, null, @as(u32, linux.SOCK.CLOEXEC) }));
}

const Ucred = extern struct { pid: pid_t, uid: uid_t, gid: gid_t };

pub fn peerCredentials(fd: fd_t) Error!Credentials {
    var cred: Ucred = undefined;
    var len: linux.socklen_t = @sizeOf(Ucred);
    _ = try retry(linux.getsockopt, .{ fd, @as(i32, linux.SOL.SOCKET), @as(u32, linux.SO.PEERCRED), @as([*]u8, @ptrCast(&cred)), &len });
    if (len != @sizeOf(Ucred)) return error.Unexpected;
    return .{ .pid = cred.pid, .uid = cred.uid, .gid = cred.gid };
}

pub fn setTimeouts(fd: fd_t, seconds: u32) Error!void {
    const tv: linux.timeval = .{ .sec = @intCast(seconds), .usec = 0 };
    const bytes: [*]const u8 = @ptrCast(&tv);
    _ = try retry(linux.setsockopt, .{ fd, @as(i32, linux.SOL.SOCKET), @as(u32, linux.SO.RCVTIMEO), bytes, @as(linux.socklen_t, @sizeOf(linux.timeval)) });
    _ = try retry(linux.setsockopt, .{ fd, @as(i32, linux.SOL.SOCKET), @as(u32, linux.SO.SNDTIMEO), bytes, @as(linux.socklen_t, @sizeOf(linux.timeval)) });
}

pub fn shutdownWrite(fd: fd_t) void {
    _ = linux.shutdown(fd, linux.SHUT.WR);
}

/// Sends one datagram to the journal's syslog socket. Logging must never fail
/// a security decision, so errors are swallowed.
pub fn syslogDatagram(message: []const u8) void {
    var addr: linux.sockaddr.un = .{ .family = linux.AF.UNIX, .path = undefined };
    @memset(&addr.path, 0);
    const path = "/dev/log";
    @memcpy(addr.path[0..path.len], path);
    const rc = linux.socket(linux.AF.UNIX, linux.SOCK.DGRAM | linux.SOCK.CLOEXEC, 0);
    if (linux.errno(rc) != .SUCCESS) return;
    const fd: fd_t = @intCast(rc);
    defer close(fd);
    _ = linux.sendto(fd, message.ptr, message.len, 0, @ptrCast(&addr), @sizeOf(linux.sockaddr.un));
}

/// Look up a user's uid in /etc/passwd without NSS. NixOS declares system
/// users statically, so the file is authoritative for `caddy`.
pub fn lookupUid(name: []const u8) ?uid_t {
    return lookupId("/etc/passwd", name);
}

pub fn lookupGid(name: []const u8) ?gid_t {
    return lookupId("/etc/group", name);
}

fn lookupId(path: [*:0]const u8, name: []const u8) ?u32 {
    if (name.len == 0) return null;
    const fd = open(path, .{}, 0) catch return null;
    defer close(fd);
    var buf: [64 * 1024]u8 = undefined;
    var len: usize = 0;
    while (len < buf.len) {
        const n = read(fd, buf[len..]) catch return null;
        if (n == 0) break;
        len += n;
    }
    var lines = std.mem.splitScalar(u8, buf[0..len], '\n');
    while (lines.next()) |line| {
        var fields = std.mem.splitScalar(u8, line, ':');
        const user = fields.next() orelse continue;
        if (!std.mem.eql(u8, user, name)) continue;
        _ = fields.next() orelse continue;
        const id = fields.next() orelse continue;
        return std.fmt.parseInt(u32, id, 10) catch null;
    }
    return null;
}

test "passwd lookup" {
    try std.testing.expectEqual(@as(?uid_t, 0), lookupUid("root"));
    try std.testing.expectEqual(@as(?uid_t, null), lookupUid("nas-unlock-test-missing-user"));
    try std.testing.expectEqual(@as(?uid_t, null), lookupUid(""));
}

test "lstat distinguishes symlinks" {
    try std.testing.expectError(error.FileNotFound, lstat("/nonexistent/nas-zig-test"));
    const st = try lstat("/");
    try std.testing.expectEqual(Kind.directory, st.kind);
    try std.testing.expect(!(try lexists("/nonexistent/nas-zig-test")));
}
