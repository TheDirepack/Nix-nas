//! Unicode full case folding (`str.casefold()` semantics), built at compile
//! time from the vendored `data/CaseFolding.txt` (C and F entries).

const std = @import("std");

const Entry = struct {
    cp: u21,
    len: u2,
    map: [3]u21,
};

const table: []const Entry = blk: {
    @setEvalBranchQuota(4_000_000);
    const text = @embedFile("data/CaseFolding.txt");
    var entries: [1600]Entry = undefined;
    var count: usize = 0;
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |raw| {
        const line = if (std.mem.indexOfScalar(u8, raw, '#')) |i| raw[0..i] else raw;
        var fields = std.mem.splitScalar(u8, line, ';');
        const code = std.mem.trim(u8, fields.next() orelse continue, " ");
        if (code.len == 0) continue;
        const status = std.mem.trim(u8, fields.next() orelse continue, " ");
        if (!std.mem.eql(u8, status, "C") and !std.mem.eql(u8, status, "F")) continue;
        const mapping = std.mem.trim(u8, fields.next() orelse continue, " ");
        var e: Entry = .{ .cp = std.fmt.parseInt(u21, code, 16) catch unreachable, .len = 0, .map = .{ 0, 0, 0 } };
        var parts = std.mem.tokenizeScalar(u8, mapping, ' ');
        while (parts.next()) |p| {
            e.map[e.len] = std.fmt.parseInt(u21, p, 16) catch unreachable;
            e.len += 1;
        }
        entries[count] = e;
        count += 1;
    }
    // The file is ordered by code point; binary search relies on it.
    for (1..count) |i| if (entries[i - 1].cp >= entries[i].cp) @compileError("CaseFolding.txt is not sorted");
    const final = entries[0..count].*;
    break :blk &final;
};

comptime {
    if (table.len < 1400) @compileError("CaseFolding table is unexpectedly small");
}

/// Folded form of one code point (1 to 3 code points).
pub fn fold(cp: u21) []const u21 {
    var lo: usize = 0;
    var hi: usize = table.len;
    while (lo < hi) {
        const mid = (lo + hi) / 2;
        const e = &table[mid];
        if (e.cp == cp) return e.map[0..e.len];
        if (e.cp < cp) lo = mid + 1 else hi = mid;
    }
    return &[_]u21{};
}

const Folder = struct {
    it: std.unicode.Utf8Iterator,
    pending: []const u21 = &.{},
    single: [1]u21 = undefined,

    fn next(self: *Folder) ?u21 {
        while (self.pending.len == 0) {
            const cp = self.it.nextCodepoint() orelse return null;
            const f = fold(cp);
            if (f.len == 0) {
                self.single[0] = cp;
                self.pending = &self.single;
            } else self.pending = f;
        }
        const cp = self.pending[0];
        self.pending = self.pending[1..];
        return cp;
    }
};

/// `a.casefold() == b.casefold()` for valid UTF-8 inputs, without allocating.
pub fn eqlFolded(a: []const u8, b: []const u8) error{InvalidUtf8}!bool {
    const va = std.unicode.Utf8View.init(a) catch return error.InvalidUtf8;
    const vb = std.unicode.Utf8View.init(b) catch return error.InvalidUtf8;
    var fa: Folder = .{ .it = va.iterator() };
    var fb: Folder = .{ .it = vb.iterator() };
    while (true) {
        const x = fa.next();
        const y = fb.next();
        if (x == null and y == null) return true;
        if (x == null or y == null or x.? != y.?) return false;
    }
}

const testing = std.testing;

test "case folding follows str.casefold" {
    try testing.expect(try eqlFolded("Same Password For Both", "same password for both"));
    try testing.expect(try eqlFolded("STRASSE", "stra\u{df}e"));
    try testing.expect(try eqlFolded("\u{212a}elvin", "kelvin"));
    try testing.expect(try eqlFolded("\u{3a3}\u{3c2}", "\u{3c3}\u{3c3}"));
    try testing.expect(try eqlFolded("\u{fb00}", "FF"));
    try testing.expect(!(try eqlFolded("abc", "abd")));
    try testing.expect(!(try eqlFolded("abc", "abcd")));
    try testing.expectError(error.InvalidUtf8, eqlFolded("\xff", "a"));
}
