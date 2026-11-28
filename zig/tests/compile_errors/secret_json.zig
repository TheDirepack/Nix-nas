const std = @import("std");
const nas = @import("nas");
test {
    var z = nas.secret.ZeroingAllocator.init(std.testing.allocator);
    var s = try nas.secret.Secret.copyOf(&z, "hunter2");
    defer s.deinit();
    const out = try std.json.Stringify.valueAlloc(std.testing.allocator, .{ .password = s }, .{});
    std.testing.allocator.free(out);
}
