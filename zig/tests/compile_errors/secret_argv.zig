const std = @import("std");
const nas = @import("nas");
test {
    var z = nas.secret.ZeroingAllocator.init(std.testing.allocator);
    var s = try nas.secret.Secret.copyOf(&z, "hunter2");
    defer s.deinit();
    _ = try nas.command.argv(.{ "keepassxc-cli", "--pw", &s });
}
