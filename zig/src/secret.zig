//! Secret material and the only places it may flow.
//!
//! Zig has no private fields, so `Secret` holds an opaque pointer: code
//! outside this file cannot name the storage type, `{any}` prints an address,
//! and `{f}`/JSON serialisation are compile errors. The bytes leave through
//! the closed set of sinks declared below: a child's stdin, a private staged
//! file, a KDF, or an explicitly granted stdout reveal. `tests/zig_boundary`
//! rejects `@ptrCast` of a Secret's handle anywhere else.

const std = @import("std");
const sys = @import("sys.zig");
const Io = std.Io;

// ------------------------------------------------------------ allocator

/// Wraps a child allocator and wipes every byte before it is returned.
/// It is a distinct type so that secret constructors cannot be handed an
/// ordinary allocator by mistake.
pub const ZeroingAllocator = struct {
    child: std.mem.Allocator,

    pub fn init(child: std.mem.Allocator) ZeroingAllocator {
        return .{ .child = child };
    }

    pub fn allocator(self: *ZeroingAllocator) std.mem.Allocator {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable: std.mem.Allocator.VTable = .{
        .alloc = alloc,
        .resize = resize,
        .remap = remap,
        .free = free,
    };

    fn alloc(ctx: *anyopaque, len: usize, alignment: std.mem.Alignment, ra: usize) ?[*]u8 {
        const self: *ZeroingAllocator = @ptrCast(@alignCast(ctx));
        return self.child.rawAlloc(len, alignment, ra);
    }

    fn resize(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, ra: usize) bool {
        const self: *ZeroingAllocator = @ptrCast(@alignCast(ctx));
        if (new_len < memory.len) std.crypto.secureZero(u8, memory[new_len..]);
        return self.child.rawResize(memory, alignment, new_len, ra);
    }

    /// Refusing remap forces alloc+copy+free, so a moved buffer is wiped by `free`.
    fn remap(_: *anyopaque, _: []u8, _: std.mem.Alignment, _: usize, _: usize) ?[*]u8 {
        return null;
    }

    fn free(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, ra: usize) void {
        const self: *ZeroingAllocator = @ptrCast(@alignCast(ctx));
        std.crypto.secureZero(u8, memory);
        self.child.rawFree(memory, alignment, ra);
    }
};

/// Process-wide zeroing allocator for production binaries.
pub var process_zeroing: ZeroingAllocator = .init(std.heap.page_allocator);

// --------------------------------------------------------------- secret

const Box = struct {
    bytes: []u8,
    z: *ZeroingAllocator,
};

pub const Secret = struct {
    handle: *anyopaque,

    pub const Error = error{OutOfMemory};

    fn box(self: Secret) *Box {
        return @ptrCast(@alignCast(self.handle));
    }

    fn bytes(self: Secret) []const u8 {
        return self.box().bytes;
    }

    /// Takes ownership of `owned`, which must come from `z`.
    pub fn adopt(z: *ZeroingAllocator, owned: []u8) Error!Secret {
        const b = z.allocator().create(Box) catch {
            z.allocator().free(owned);
            return error.OutOfMemory;
        };
        b.* = .{ .bytes = owned, .z = z };
        return .{ .handle = b };
    }

    pub fn copyOf(z: *ZeroingAllocator, source: []const u8) Error!Secret {
        const owned = try z.allocator().dupe(u8, source);
        return adopt(z, owned);
    }

    pub fn dupe(self: Secret) Error!Secret {
        return copyOf(self.box().z, self.bytes());
    }

    /// `nbytes` of OS randomness, hex encoded (the `openssl rand -hex` contract).
    pub fn randomHex(z: *ZeroingAllocator, io: Io, comptime nbytes: usize) (Error || Io.RandomSecureError)!Secret {
        var raw: [nbytes]u8 = undefined;
        defer std.crypto.secureZero(u8, &raw);
        try io.randomSecure(&raw);
        const out = try z.allocator().alloc(u8, nbytes * 2);
        const hex = "0123456789abcdef";
        for (raw, 0..) |byte, i| {
            out[2 * i] = hex[byte >> 4];
            out[2 * i + 1] = hex[byte & 0xf];
        }
        return adopt(z, out);
    }

    pub fn deinit(self: *Secret) void {
        const b = self.box();
        const z = b.z;
        z.allocator().free(b.bytes);
        z.allocator().destroy(b);
        self.* = undefined;
    }

    pub fn len(self: Secret) usize {
        return self.bytes().len;
    }

    pub fn isEmpty(self: Secret) bool {
        return self.bytes().len == 0;
    }

    /// Answers a yes/no question about the bytes without exposing them.
    pub fn satisfies(self: Secret, comptime predicate: fn ([]const u8) bool) bool {
        return predicate(self.bytes());
    }

    /// Like `satisfies` with one extra argument passed through.
    pub fn satisfiesWith(self: Secret, comptime predicate: anytype, arg: anytype) bool {
        return predicate(self.bytes(), arg);
    }

    /// A yes/no question about two secrets together.
    pub fn satisfiesPair(a: Secret, b: Secret, comptime predicate: fn ([]const u8, []const u8) bool) bool {
        return predicate(a.bytes(), b.bytes());
    }

    /// Lexicographic byte order (Python code-point order for UTF-8). Not
    /// constant time; only used to canonicalise inputs before a KDF.
    pub fn order(a: Secret, b: Secret) std.math.Order {
        return std.mem.order(u8, a.bytes(), b.bytes());
    }

    /// Length-revealing but otherwise constant-time comparison.
    pub fn eql(a: Secret, b: Secret) bool {
        const x = a.bytes();
        const y = b.bytes();
        if (x.len != y.len) return false;
        var diff: u8 = 0;
        for (x, y) |p, q| diff |= p ^ q;
        return diff == 0;
    }

    pub fn eqlPublic(a: Secret, other: []const u8) bool {
        const x = a.bytes();
        if (x.len != other.len) return false;
        var diff: u8 = 0;
        for (x, other) |p, q| diff |= p ^ q;
        return diff == 0;
    }

    /// Never printable: a format specifier on a Secret is a compile error.
    pub fn format(self: Secret, writer: *Io.Writer) Io.Writer.Error!void {
        _ = self;
        _ = writer;
        @compileError("nas: a Secret cannot be formatted; pass it to a stdin payload or private file sink");
    }

    /// Never serialisable.
    pub fn jsonStringify(self: Secret, jw: anytype) !void {
        _ = self;
        _ = jw;
        @compileError("nas: a Secret cannot be serialised");
    }

    /// Stops `std.zon` / `std.json` from parsing directly into a Secret.
    pub fn jsonParse(a: std.mem.Allocator, source: anytype, options: anytype) !Secret {
        _ = a;
        _ = source;
        _ = options;
        @compileError("nas: parse into a ZeroingAllocator buffer and adopt it instead");
    }
};

// ----------------------------------------------------------- builders

/// Accumulates secret material (for example a canonical KDF input) in
/// zeroing memory.
pub const Builder = struct {
    list: std.ArrayList(u8) = .empty,
    z: *ZeroingAllocator,

    pub fn init(z: *ZeroingAllocator) Builder {
        return .{ .z = z };
    }

    pub fn appendPublic(self: *Builder, text: []const u8) Secret.Error!void {
        try self.list.appendSlice(self.z.allocator(), text);
    }

    pub fn appendSecret(self: *Builder, s: Secret) Secret.Error!void {
        try self.list.appendSlice(self.z.allocator(), s.bytes());
    }

    /// Appends `s` as a JSON string with Python `json.dumps(ensure_ascii=True)`
    /// escaping, so digests match those already stored in setup journals.
    pub fn appendJsonString(self: *Builder, s: Secret) (Secret.Error || error{InvalidUtf8})!void {
        try appendPythonJsonString(self.z.allocator(), &self.list, s.bytes());
    }

    pub fn finish(self: *Builder) Secret.Error!Secret {
        const owned = try self.list.toOwnedSlice(self.z.allocator());
        return Secret.adopt(self.z, owned);
    }

    pub fn deinit(self: *Builder) void {
        self.list.deinit(self.z.allocator());
    }
};

pub fn appendPythonJsonString(a: std.mem.Allocator, list: *std.ArrayList(u8), text: []const u8) (std.mem.Allocator.Error || error{InvalidUtf8})!void {
    try list.append(a, '"');
    var view = std.unicode.Utf8View.init(text) catch return error.InvalidUtf8;
    var it = view.iterator();
    var esc: [12]u8 = undefined;
    while (it.nextCodepoint()) |cp| {
        switch (cp) {
            '"' => try list.appendSlice(a, "\\\""),
            '\\' => try list.appendSlice(a, "\\\\"),
            '\n' => try list.appendSlice(a, "\\n"),
            '\r' => try list.appendSlice(a, "\\r"),
            '\t' => try list.appendSlice(a, "\\t"),
            0x08 => try list.appendSlice(a, "\\b"),
            0x0c => try list.appendSlice(a, "\\f"),
            0x20...0x21, 0x23...0x5b, 0x5d...0x7e => try list.append(a, @intCast(cp)),
            else => {
                if (cp >= 0x10000) {
                    const v = cp - 0x10000;
                    const hi: u16 = @intCast(0xd800 + (v >> 10));
                    const lo: u16 = @intCast(0xdc00 + (v & 0x3ff));
                    try list.appendSlice(a, std.fmt.bufPrint(&esc, "\\u{x:0>4}\\u{x:0>4}", .{ hi, lo }) catch unreachable);
                } else {
                    try list.appendSlice(a, std.fmt.bufPrint(&esc, "\\u{x:0>4}", .{@as(u16, @intCast(cp))}) catch unreachable);
                }
            },
        }
    }
    try list.append(a, '"');
}

// ---------------------------------------------------------------- sinks

/// One element of a child's stdin.
pub const Part = union(enum) {
    secret: *const Secret,
    newline,
};

/// The only way secret bytes reach another process: its stdin pipe.
///
/// Parts are stored by value. A slice field would let a helper return a
/// payload pointing into its own stack frame, which Zig does not diagnose.
pub const Payload = struct {
    parts: [max_parts]Part = undefined,
    len: usize = 0,

    pub const max_parts = 4;
    pub const empty: Payload = .{};

    /// Each secret on its own line: `Payload.lines(2, .{ &password, &value })`.
    pub fn lines(comptime n: usize, secrets: [n]*const Secret) Payload {
        if (2 * n > max_parts) @compileError("nas: a stdin payload holds at most 2 secret lines");
        var out: Payload = .{ .len = 2 * n };
        for (secrets, 0..) |s, i| {
            out.parts[2 * i] = .{ .secret = s };
            out.parts[2 * i + 1] = .newline;
        }
        return out;
    }

    /// Written by `command.zig` into the pipe of a child it spawned. The pipe
    /// is the only `Io.File` the caller can obtain for a child's stdin.
    pub fn writeToChild(self: *const Payload, io: Io, child: *std.process.Child) (Io.File.Writer.Error || error{NoPipe})!void {
        const stdin = child.stdin orelse return error.NoPipe;
        var buf: [512]u8 = undefined;
        defer std.crypto.secureZero(u8, &buf);
        var w = stdin.writer(io, &buf);
        for (self.parts[0..self.len]) |part| switch (part) {
            .secret => |s| w.interface.writeAll(s.bytes()) catch return w.err.?,
            .newline => w.interface.writeByte('\n') catch return w.err.?,
        };
        w.interface.flush() catch return w.err.?;
    }
};

/// A directory verified to be a real (non-symlink) directory, owned by the
/// effective user and inaccessible to group/other.
pub const PrivateDir = struct {
    fd: sys.fd_t,

    pub const OpenError = sys.Error || error{NotPrivate};

    pub fn open(path: [*:0]const u8) OpenError!PrivateDir {
        const fd = try sys.open(path, .{ .DIRECTORY = true, .NOFOLLOW = true }, 0);
        errdefer sys.close(fd);
        const st = try sys.fstat(fd);
        if (st.kind != .directory or st.uid != sys.geteuid() or st.mode & 0o077 != 0) return error.NotPrivate;
        return .{ .fd = fd };
    }

    pub fn close(self: *PrivateDir) void {
        sys.close(self.fd);
    }
};

/// A newly created 0600 file inside a `PrivateDir`.
pub const PrivateFile = struct {
    fd: sys.fd_t,

    pub fn create(dir: PrivateDir, name: [*:0]const u8) sys.Error!PrivateFile {
        const fd = try sys.openAt(dir.fd, name, .{ .ACCMODE = .WRONLY, .CREAT = true, .EXCL = true, .NOFOLLOW = true }, 0o600);
        return .{ .fd = fd };
    }

    pub fn writePublic(self: PrivateFile, text: []const u8) sys.Error!void {
        try sys.writeAll(self.fd, text);
    }

    pub fn writeSecret(self: PrivateFile, s: Secret) sys.Error!void {
        try sys.writeAll(self.fd, s.bytes());
    }

    pub fn close(self: *PrivateFile) void {
        sys.close(self.fd);
    }
};

/// Explicit, enumerable grants for commands whose contract is to print a
/// secret (recovery and the ZFS key helper read it from a pipe).
pub const RevealGrant = enum { show_zfs_key, show_ntfy_password, show_authentik_bootstrap_password };

pub fn revealToStdout(s: Secret, comptime grant: RevealGrant) sys.Error!void {
    _ = grant;
    try sys.writeAll(1, s.bytes());
}

// ----------------------------------------------------------------- KDFs

pub const KdfError = error{ OutOfMemory, KdfFailed };

pub fn scrypt(s: Secret, z: *ZeroingAllocator, salt: []const u8, params: std.crypto.pwhash.scrypt.Params, out: []u8) KdfError!void {
    std.crypto.pwhash.scrypt.kdf(z.allocator(), out, s.bytes(), salt, params) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.KdfFailed,
    };
}

pub fn hmacSha256(key: []const u8, message: Secret) [32]u8 {
    var out: [32]u8 = undefined;
    std.crypto.auth.hmac.sha2.HmacSha256.create(&out, message.bytes(), key);
    return out;
}

/// HMAC of secret material keyed by a secret (legacy journal authenticators).
pub fn hmacSha256Secret(key: Secret, message: Secret) [32]u8 {
    var out: [32]u8 = undefined;
    std.crypto.auth.hmac.sha2.HmacSha256.create(&out, message.bytes(), key.bytes());
    return out;
}

/// HMAC keyed by a secret.
pub fn hmacSha256Keyed(key: Secret, message: []const u8) [32]u8 {
    var out: [32]u8 = undefined;
    std.crypto.auth.hmac.sha2.HmacSha256.create(&out, message, key.bytes());
    return out;
}

pub fn sha256Prefixed(prefix: []const u8, s: Secret) Secret.Error!Secret {
    var h = std.crypto.hash.sha2.Sha256.init(.{});
    h.update(prefix);
    h.update(s.bytes());
    var digest: [32]u8 = undefined;
    h.final(&digest);
    defer std.crypto.secureZero(u8, &digest);
    return Secret.copyOf(s.box().z, &digest);
}

/// Argon2id PHC string with the parameters of the former `argon2 -id -t 3 -m 16 -p 4`.
pub fn argon2idPhc(s: Secret, z: *ZeroingAllocator, io: Io) KdfError!Secret {
    var buf: [128]u8 = undefined;
    defer std.crypto.secureZero(u8, &buf);
    const encoded = std.crypto.pwhash.argon2.strHash(s.bytes(), .{
        .allocator = z.allocator(),
        .params = .{ .t = 3, .m = 1 << 16, .p = 4 },
        .mode = .argon2id,
    }, &buf, io) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.KdfFailed,
    };
    return Secret.copyOf(z, encoded) catch error.OutOfMemory;
}

/// Modular-crypt bcrypt (cost 12), the former `htpasswd -nBiC 12` output without the user.
pub fn bcryptCrypt(s: Secret, z: *ZeroingAllocator, io: Io) KdfError!Secret {
    var buf: [std.crypto.pwhash.bcrypt.hash_length * 2]u8 = undefined;
    defer std.crypto.secureZero(u8, &buf);
    const encoded = std.crypto.pwhash.bcrypt.strHash(s.bytes(), .{
        .params = .{ .rounds_log = 12, .silently_truncate_password = false },
        .encoding = .crypt,
    }, &buf, io) catch return error.KdfFailed;
    return Secret.copyOf(z, encoded) catch error.OutOfMemory;
}

// ---------------------------------------------------------------- tests

const testing = std.testing;

test "secret buffers are released through the zeroing allocator without leaks" {
    var z: ZeroingAllocator = .init(testing.allocator);
    var s = try Secret.copyOf(&z, "hunter2-hunter2");
    defer s.deinit();
    var d = try s.dupe();
    defer d.deinit();
    try testing.expect(s.eql(d));
    try testing.expect(s.eqlPublic("hunter2-hunter2"));
    try testing.expect(!s.eqlPublic("hunter2-hunter3"));
    try testing.expectEqual(@as(usize, 15), s.len());
}

test "zeroing allocator wipes freed memory" {
    var backing_buf: [256]u8 = undefined;
    var fba: std.heap.FixedBufferAllocator = .init(&backing_buf);
    var z: ZeroingAllocator = .init(fba.allocator());
    const a = z.allocator();
    const mem = try a.alloc(u8, 32);
    @memcpy(mem, "0123456789abcdef0123456789abcdef");
    const view = backing_buf[0..32];
    a.free(mem);
    for (view) |byte| try testing.expectEqual(@as(u8, 0), byte);
}

test "random hex has the requested width" {
    var z: ZeroingAllocator = .init(testing.allocator);
    var s = try Secret.randomHex(&z, testing.io, 16);
    defer s.deinit();
    try testing.expectEqual(@as(usize, 32), s.len());
    try testing.expect(s.satisfies(struct {
        fn f(b: []const u8) bool {
            for (b) |c| if (!std.ascii.isHex(c)) return false;
            return true;
        }
    }.f));
}

test "python ensure_ascii json escaping" {
    const a = testing.allocator;
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(a);
    try appendPythonJsonString(a, &list, "a\"b\\c\u{e9}\u{1f600}\x01");
    try testing.expectEqualStrings("\"a\\\"b\\\\c\\u00e9\\ud83d\\ude00\\u0001\"", list.items);
}

test "builder output is a secret" {
    var z: ZeroingAllocator = .init(testing.allocator);
    var pw = try Secret.copyOf(&z, "p\u{e9}");
    defer pw.deinit();
    var b: Builder = .init(&z);
    defer b.deinit();
    try b.appendPublic("{\"k\":");
    try b.appendJsonString(pw);
    try b.appendPublic("}");
    var out = try b.finish();
    defer out.deinit();
    try testing.expect(out.eqlPublic("{\"k\":\"p\\u00e9\"}"));
}

test "fuzz: python json escaping round-trips through std.json" {
    try testing.fuzz({}, struct {
        fn one(_: void, smith: *testing.Smith) anyerror!void {
            var buf: [64]u8 = undefined;
            const n = smith.slice(&buf);
            const input = buf[0..n];
            if (!std.unicode.utf8ValidateSlice(input)) return;
            const a = testing.allocator;
            var list: std.ArrayList(u8) = .empty;
            defer list.deinit(a);
            try appendPythonJsonString(a, &list, input);
            for (list.items) |c| try testing.expect(c >= 0x20 and c < 0x7f);
            const parsed = try std.json.parseFromSlice([]const u8, a, list.items, .{});
            defer parsed.deinit();
            try testing.expectEqualStrings(input, parsed.value);
        }
    }.one, .{});
}
