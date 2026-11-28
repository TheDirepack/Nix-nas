const std = @import("std");
const nas = @import("nas");
test {
    var z = nas.secret.ZeroingAllocator.init(std.testing.allocator);
    var s = try nas.secret.Secret.copyOf(&z, "hunter2");
    defer s.deinit();
    const r: nas.command.Runner = .{ .io = std.testing.io, .gpa = std.testing.allocator, .z = &z, .privilege = .sudo };
    _ = try r.privileged(.{ "keepassxc-cli", "db-info" }, nas.secret.Payload.lines(1, .{&s}), .{});
}
