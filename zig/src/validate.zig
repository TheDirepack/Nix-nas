//! Validated value types. Each is produced only by a constructor that
//! returns an error union; downstream code takes the validated type and so
//! cannot receive an unchecked value. Zig has no field privacy, so direct
//! struct-literal construction outside this file is rejected by
//! `tests/zig_boundary` instead of the compiler.

const std = @import("std");
const secret = @import("secret.zig");
const casefold = @import("casefold.zig");
const Secret = secret.Secret;

pub const max_secret_codepoints = 4096;

// ------------------------------------------------------ secret stdin line

pub const LineError = error{ Unreadable, Empty, TooLong, InvalidUtf8, OutOfMemory };

/// Reads one `\n`-terminated line into zeroing memory without reading past it,
/// so later lines remain for the caller. EOF before `\n` is `Unreadable`.
pub fn readSecretLine(z: *secret.ZeroingAllocator, reader: *std.Io.Reader) LineError!Secret {
    const limit = max_secret_codepoints * 4;
    var list: std.ArrayList(u8) = .empty;
    errdefer list.deinit(z.allocator());
    while (true) {
        const byte = reader.takeByte() catch return error.Unreadable;
        if (byte == '\n') break;
        if (list.items.len >= limit) return error.TooLong;
        list.append(z.allocator(), byte) catch return error.OutOfMemory;
    }
    if (list.items.len == 0) return error.Empty;
    const count = std.unicode.utf8CountCodepoints(list.items) catch return error.InvalidUtf8;
    if (count > max_secret_codepoints) return error.TooLong;
    const owned = list.toOwnedSlice(z.allocator()) catch return error.OutOfMemory;
    return Secret.adopt(z, owned) catch error.OutOfMemory;
}

// ------------------------------------------------- KeePass password floor

pub const strength_min_codepoints = 16;
pub const strength_min_distinct = 6;

pub const StrengthError = error{ TooShort, TooFewDistinct, SameAsAdministrator, InvalidUtf8 };

/// The only secret protecting the KDBX (and with it the ZFS key) after setup.
pub const StrongKeePassPassword = struct {
    secret: Secret,

    /// Takes ownership of `password` on success.
    pub fn init(password: Secret, administrator: ?Secret) StrengthError!StrongKeePassPassword {
        try checkStrength(password, administrator);
        return .{ .secret = password };
    }

    pub fn deinit(self: *StrongKeePassPassword) void {
        self.secret.deinit();
    }

    pub fn message(err: StrengthError) []const u8 {
        return switch (err) {
            error.TooShort => std.fmt.comptimePrint("KeePass database password must contain at least {d} characters", .{strength_min_codepoints}),
            error.TooFewDistinct => std.fmt.comptimePrint("KeePass database password must use at least {d} different characters", .{strength_min_distinct}),
            error.SameAsAdministrator => "KeePass database password must differ from the administrator password",
            error.InvalidUtf8 => "KeePass database password must be valid UTF-8",
        };
    }
};

fn countAndDistinct(bytes: []const u8) error{InvalidUtf8}!struct { count: usize, distinct: usize } {
    const view = std.unicode.Utf8View.init(bytes) catch return error.InvalidUtf8;
    var seen: [strength_min_distinct]u21 = undefined;
    var distinct: usize = 0;
    var count: usize = 0;
    var it = view.iterator();
    while (it.nextCodepoint()) |cp| {
        count += 1;
        if (distinct < strength_min_distinct and std.mem.indexOfScalar(u21, seen[0..distinct], cp) == null) {
            seen[distinct] = cp;
            distinct += 1;
        }
    }
    return .{ .count = count, .distinct = distinct };
}

fn checkStrength(password: Secret, administrator: ?Secret) StrengthError!void {
    const shape = Shape.of(password) orelse return error.InvalidUtf8;
    if (shape.count < strength_min_codepoints) return error.TooShort;
    if (shape.distinct < strength_min_distinct) return error.TooFewDistinct;
    if (administrator) |admin| {
        if (foldedEqual(password, admin)) return error.SameAsAdministrator;
    }
}

const Shape = struct {
    count: usize,
    distinct: usize,

    fn of(s: Secret) ?Shape {
        var out: ?Shape = null;
        _ = s.satisfiesWith(struct {
            fn f(bytes: []const u8, dest: *?Shape) bool {
                const r = countAndDistinct(bytes) catch return false;
                dest.* = .{ .count = r.count, .distinct = r.distinct };
                return true;
            }
        }.f, &out);
        return out;
    }
};

fn foldedEqual(a: Secret, b: Secret) bool {
    return Secret.satisfiesPair(a, b, struct {
        fn f(x: []const u8, y: []const u8) bool {
            return casefold.eqlFolded(x, y) catch false;
        }
    }.f);
}

// ------------------------------------------------------ KeePass secrets

/// `require_secret_atom`: printable token alphabet with length bounds.
pub fn isAtom(bytes: []const u8, bounds: struct { min: usize, max: usize }) bool {
    if (bytes.len < bounds.min or bytes.len > bounds.max) return false;
    for (bytes) |c| switch (c) {
        'A'...'Z', 'a'...'z', '0'...'9', '.', '_', '~', '+', '/', '=', ':', '@', '-' => {},
        else => return false,
    };
    return true;
}

/// `require_secret_hex`: exactly `width` hexadecimal digits.
pub fn isHex(bytes: []const u8, width: usize) bool {
    if (bytes.len != width) return false;
    for (bytes) |c| if (!std.ascii.isHex(c)) return false;
    return true;
}

pub fn isNtfyTopic(bytes: []const u8) bool {
    if (bytes.len < 8 or bytes.len > 128) return false;
    for (bytes) |c| switch (c) {
        'A'...'Z', 'a'...'z', '0'...'9', '_', '-' => {},
        else => return false,
    };
    return true;
}

/// Authentik API/outpost tokens as accepted by `set-authentik-*`.
pub fn isAuthentikToken(bytes: []const u8) bool {
    if (bytes.len < 20) return false;
    for (bytes) |c| switch (c) {
        'A'...'Z', 'a'...'z', '0'...'9', '.', '_', '~', '-' => {},
        else => return false,
    };
    return true;
}

// ------------------------------------------------------- systemd names

fn isUnitChar(c: u8) bool {
    return switch (c) {
        'A'...'Z', 'a'...'z', '0'...'9', '_', '.', '@', ':', '-' => true,
        else => false,
    };
}

pub const UnitError = error{InvalidUnitName};

/// A unit name safe to pass as one argv element to systemctl.
pub const UnitName = struct {
    name: []const u8,

    const suffixes = [_][]const u8{ ".service", ".socket", ".timer", ".path", ".target", ".mount" };

    pub fn parse(text: []const u8) UnitError!UnitName {
        if (text.len == 0 or text[0] == '-') return error.InvalidUnitName;
        for (text) |c| if (!isUnitChar(c)) return error.InvalidUnitName;
        for (suffixes) |suffix| {
            if (text.len > suffix.len and std.mem.endsWith(u8, text, suffix)) return .{ .name = text };
        }
        return error.InvalidUnitName;
    }

    /// Compile-time checked literal.
    pub fn lit(comptime text: []const u8) UnitName {
        comptime {
            _ = parse(text) catch @compileError("invalid unit literal: " ++ text);
        }
        return .{ .name = text };
    }
};

pub const TargetName = struct {
    name: []const u8,

    pub fn parse(text: []const u8) UnitError!TargetName {
        const unit = try UnitName.parse(text);
        if (!std.mem.endsWith(u8, unit.name, ".target")) return error.InvalidUnitName;
        return .{ .name = unit.name };
    }
};

// -------------------------------------------------------------- paths

pub const PathError = error{ NotAbsolute, ParentReference, TooLong, ControlCharacter };

/// An absolute Unix socket path that fits `sockaddr_un` and has no `..`.
pub const AbsSocketPath = struct {
    path: []const u8,

    pub const max_len = 107;

    pub fn parse(text: []const u8) PathError!AbsSocketPath {
        if (text.len == 0 or text[0] != '/') return error.NotAbsolute;
        if (text.len > max_len) return error.TooLong;
        for (text) |c| if (c < 0x20 or c == 0x7f) return error.ControlCharacter;
        var parts = std.mem.splitScalar(u8, text, '/');
        while (parts.next()) |part| if (std.mem.eql(u8, part, "..")) return error.ParentReference;
        return .{ .path = text };
    }
};

/// Lexical `realpath -m -s`: absolute, `.`/`..` resolved without touching the filesystem.
pub fn lexicalNormalize(out: []u8, text: []const u8) error{ NotAbsolute, TooLong }![]const u8 {
    if (text.len == 0 or text[0] != '/') return error.NotAbsolute;
    var len: usize = 0;
    var parts = std.mem.tokenizeScalar(u8, text, '/');
    while (parts.next()) |part| {
        if (std.mem.eql(u8, part, ".")) continue;
        if (std.mem.eql(u8, part, "..")) {
            while (len > 0 and out[len - 1] != '/') len -= 1;
            if (len > 0) len -= 1;
            continue;
        }
        if (len + 1 + part.len > out.len) return error.TooLong;
        out[len] = '/';
        @memcpy(out[len + 1 ..][0..part.len], part);
        len += 1 + part.len;
    }
    if (len == 0) {
        if (out.len == 0) return error.TooLong;
        out[0] = '/';
        len = 1;
    }
    return out[0..len];
}

pub fn dirname(path: []const u8) []const u8 {
    const i = std.mem.lastIndexOfScalar(u8, path, '/') orelse return ".";
    return if (i == 0) "/" else path[0..i];
}

pub fn pathsOverlap(a: []const u8, b: []const u8) bool {
    if (std.mem.eql(u8, a, b)) return true;
    return isStrictlyBeneath(a, b) or isStrictlyBeneath(b, a);
}

fn isStrictlyBeneath(child: []const u8, parent: []const u8) bool {
    return child.len > parent.len and std.mem.startsWith(u8, child, parent) and child[parent.len] == '/';
}

// -------------------------------------------------------------- tests

const testing = std.testing;

fn mk(z: *secret.ZeroingAllocator, text: []const u8) !Secret {
    return Secret.copyOf(z, text);
}

test "strength floor matches nas_setup_config" {
    var z: secret.ZeroingAllocator = .init(testing.allocator);
    var ok = try StrongKeePassPassword.init(try mk(&z, "correct horse battery staple"), null);
    ok.deinit();

    const cases = .{
        .{ "short-pass", error.TooShort },
        .{ "aaaaabbbbbaaaaabbbbb", error.TooFewDistinct },
    };
    inline for (cases) |case| {
        var s = try mk(&z, case[0]);
        defer s.deinit();
        try testing.expectError(case[1], StrongKeePassPassword.init(s, null));
    }
    var pw = try mk(&z, "Same Password For Both");
    defer pw.deinit();
    var admin = try mk(&z, "same password for both");
    defer admin.deinit();
    try testing.expectError(error.SameAsAdministrator, StrongKeePassPassword.init(pw, admin));
    try testing.expectEqualStrings("KeePass database password must contain at least 16 characters", StrongKeePassPassword.message(error.TooShort));
}

test "strength counts code points, not bytes" {
    var z: secret.ZeroingAllocator = .init(testing.allocator);
    // 15 code points, 30 bytes.
    var s = try mk(&z, "\u{e9}\u{e8}\u{ea}\u{eb}\u{e0}\u{e2}\u{e9}\u{e8}\u{ea}\u{eb}\u{e0}\u{e2}\u{e9}\u{e8}\u{ea}");
    defer s.deinit();
    try testing.expectError(error.TooShort, StrongKeePassPassword.init(s, null));
    var folded = try mk(&z, "Stra\u{df}e-and-more-text");
    defer folded.deinit();
    var admin = try mk(&z, "STRASSE-AND-MORE-TEXT");
    defer admin.deinit();
    try testing.expectError(error.SameAsAdministrator, StrongKeePassPassword.init(folded, admin));
}

test "secret line reader is bounded and keeps following lines" {
    var z: secret.ZeroingAllocator = .init(testing.allocator);
    var r: std.Io.Reader = .fixed("first\nsecond\n");
    var a = try readSecretLine(&z, &r);
    defer a.deinit();
    try testing.expect(a.eqlPublic("first"));
    var b = try readSecretLine(&z, &r);
    defer b.deinit();
    try testing.expect(b.eqlPublic("second"));
    try testing.expectError(error.Unreadable, readSecretLine(&z, &r));
    var empty: std.Io.Reader = .fixed("\n");
    try testing.expectError(error.Empty, readSecretLine(&z, &empty));
    var unterminated: std.Io.Reader = .fixed("abc");
    try testing.expectError(error.Unreadable, readSecretLine(&z, &unterminated));
    const long: [4098]u8 = @as([4097]u8, @splat('x')) ++ "\n".*;
    var too_long: std.Io.Reader = .fixed(&long);
    try testing.expectError(error.TooLong, readSecretLine(&z, &too_long));
    const max: [4097]u8 = @as([4096]u8, @splat('x')) ++ "\n".*;
    var at_max: std.Io.Reader = .fixed(&max);
    var m = try readSecretLine(&z, &at_max);
    m.deinit();
}

test "unit and target names" {
    _ = try UnitName.parse("nas-v2-app@x.service");
    try testing.expectError(error.InvalidUnitName, UnitName.parse("--root=/tmp.target"));
    try testing.expectError(error.InvalidUnitName, UnitName.parse("bad.target\nnext"));
    try testing.expectError(error.InvalidUnitName, TargetName.parse("bad.service"));
    _ = try TargetName.parse("nas-protected-services.target");
    try testing.expectError(error.InvalidUnitName, UnitName.parse(".service"));
}

test "socket paths" {
    _ = try AbsSocketPath.parse("/run/nas-unlock/unlock.sock");
    try testing.expectError(error.NotAbsolute, AbsSocketPath.parse("relative.sock"));
    try testing.expectError(error.ParentReference, AbsSocketPath.parse("/run/../tmp/unlock.sock"));
    try testing.expectError(error.TooLong, AbsSocketPath.parse("/" ++ @as([200]u8, @splat('a'))));
}

test "lexical normalisation" {
    var buf: [256]u8 = undefined;
    try testing.expectEqualStrings("/a/c", try lexicalNormalize(&buf, "/a/b/../c/./"));
    try testing.expectEqualStrings("/", try lexicalNormalize(&buf, "/.."));
    try testing.expectError(error.NotAbsolute, lexicalNormalize(&buf, "root"));
    try testing.expect(pathsOverlap("/a", "/a/b"));
    try testing.expect(!pathsOverlap("/a", "/ab"));
}

test "fuzz: secret line reader never exceeds the bound" {
    try testing.fuzz({}, struct {
        fn one(_: void, smith: *testing.Smith) anyerror!void {
            var buf: [256]u8 = undefined;
            const n = smith.slice(&buf);
            var z: secret.ZeroingAllocator = .init(testing.allocator);
            var r: std.Io.Reader = .fixed(buf[0..n]);
            var s = readSecretLine(&z, &r) catch return;
            defer s.deinit();
            try testing.expect(s.len() > 0 and s.len() <= max_secret_codepoints * 4);
            try testing.expect(s.satisfies(struct {
                fn f(b: []const u8) bool {
                    return std.mem.indexOfScalar(u8, b, '\n') == null;
                }
            }.f));
        }
    }.one, .{});
}

test "fuzz: strength check is total" {
    try testing.fuzz({}, struct {
        fn one(_: void, smith: *testing.Smith) anyerror!void {
            var buf: [64]u8 = undefined;
            const n = smith.slice(&buf);
            var z: secret.ZeroingAllocator = .init(testing.allocator);
            var s = try Secret.copyOf(&z, buf[0..n]);
            defer s.deinit();
            var admin = try Secret.copyOf(&z, buf[0 .. n / 2]);
            defer admin.deinit();
            _ = StrongKeePassPassword.init(s, admin) catch {};
        }
    }.one, .{});
}

test "fuzz: accepted unit names are single safe argv elements" {
    try testing.fuzz({}, struct {
        fn one(_: void, smith: *testing.Smith) anyerror!void {
            var buf: [96]u8 = undefined;
            const n = smith.slice(&buf);
            const unit = UnitName.parse(buf[0..n]) catch return;
            try testing.expect(unit.name[0] != '-');
            for (unit.name) |c| try testing.expect(isUnitChar(c));
            if (TargetName.parse(buf[0..n])) |t| {
                try testing.expect(std.mem.endsWith(u8, t.name, ".target"));
            } else |_| {}
        }
    }.one, .{ .corpus = &.{ "nas-protected-services.target", "--root=/tmp.target", "bad.target\nnext.target" } });
}

test "fuzz: lexical normalisation is absolute and free of dot segments" {
    try testing.fuzz({}, struct {
        fn one(_: void, smith: *testing.Smith) anyerror!void {
            var in: [128]u8 = undefined;
            const n = smith.slice(&in);
            var out: [256]u8 = undefined;
            const norm = lexicalNormalize(&out, in[0..n]) catch return;
            try testing.expect(norm.len > 0 and norm[0] == '/');
            var parts = std.mem.splitScalar(u8, norm[1..], '/');
            while (parts.next()) |part| {
                if (norm.len == 1) break;
                try testing.expect(part.len > 0 and !std.mem.eql(u8, part, ".") and !std.mem.eql(u8, part, ".."));
            }
            try testing.expect(pathsOverlap(norm, norm));
        }
    }.one, .{ .corpus = &.{ "/a/../b", "/run/nas-secret-runtime/transactions/./transaction.1/new" } });
}

test "secret validators reject configuration injection" {
    const atom: struct { min: usize, max: usize } = .{ .min = 8, .max = 4096 };
    for ([_][]const u8{ "safe-token_123", "abc.DEF~ghi+/=:@-0" }) |ok| try testing.expect(isAtom(ok, .{ .min = atom.min, .max = atom.max }));
    for ([_][]const u8{ "bad\nvalue-here", "value'with-quote", "$(touch /tmp/x)", "a b c d e f g", "short" }) |bad|
        try testing.expect(!isAtom(bad, .{ .min = atom.min, .max = atom.max }));
    try testing.expect(isHex("abcdef0123456789", 16));
    try testing.expect(!isHex("xyz", 3));
    try testing.expect(!isHex("abcdef012345678", 16));
    for ([_][]const u8{ "deadbeefcafebabe", "private_topic-123" }) |ok| try testing.expect(isNtfyTopic(ok));
    for ([_][]const u8{ "topic\"\nuser = \"attacker:password\"", "topic/../../admin", "topic?x=1", "topic with space" }) |bad|
        try testing.expect(!isNtfyTopic(bad));
}
