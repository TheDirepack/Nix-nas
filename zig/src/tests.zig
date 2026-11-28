//! Test root: pulls every module's tests into one leak-checked run.
//! (`std.testing.refAllDecls` is deliberately not used: it would analyse
//! `Secret.format`, whose body is a compile error by design.)
test {
    _ = @import("sys.zig");
    _ = @import("secret.zig");
    _ = @import("casefold.zig");
    _ = @import("validate.zig");
    _ = @import("command.zig");
    _ = @import("log.zig");
    _ = @import("transaction.zig");
    _ = @import("keepass.zig");
    _ = @import("modes.zig");
    _ = @import("config.zig");
    _ = @import("unlock_http.zig");
    _ = @import("unlock_api.zig");
    _ = @import("keepass_setup.zig");
    _ = @import("nas_secrets.zig");
}
