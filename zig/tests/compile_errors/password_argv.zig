const std = @import("std");
const nas = @import("nas");
test {
    var z = nas.secret.ZeroingAllocator.init(std.testing.allocator);
    var p = try nas.validate.StrongKeePassPassword.init(try nas.secret.Secret.copyOf(&z, "correct horse battery staple"), null);
    defer p.deinit();
    _ = try nas.command.argv(.{ "nas-secrets", p });
}
