//! Module root for compile-fail checks (`zig build compile-errors`).
pub const secret = @import("secret.zig");
pub const command = @import("command.zig");
pub const validate = @import("validate.zig");
pub const transaction = @import("transaction.zig");
pub const keepass = @import("keepass.zig");
pub const unlock_http = @import("unlock_http.zig");
pub const modes = @import("modes.zig");
