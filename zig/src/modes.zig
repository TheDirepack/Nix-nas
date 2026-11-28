//! Activation modes and the witnesses that gate post-setup operations.

/// First-start activation keeps the regenerated boot environment
/// authoritative; runtime activation may discover that setup is complete.
pub const Mode = enum { setup, runtime };

/// Proof that this activation runs after setup completed. Only a runtime
/// activation can produce one; in setup mode the slot type is `void`, so a
/// post-setup operation called from setup code does not compile.
pub const PostSetup = struct { boot_dir: []const u8 };

pub fn PostSetupSlot(comptime mode: Mode) type {
    return switch (mode) {
        .runtime => ?PostSetup,
        .setup => void,
    };
}

/// Proof that the KeePass Authentik key was rotated in this activation, the
/// precondition for deleting the first-boot plaintext copy.
pub const Rotated = struct {};
