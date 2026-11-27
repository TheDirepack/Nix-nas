const nas = @import("nas");
fn linkUnlockedEnvironment(post: nas.modes.PostSetup) void {
    _ = post;
}
test {
    const slot: nas.modes.PostSetupSlot(.setup) = {};
    linkUnlockedEnvironment(slot);
}
