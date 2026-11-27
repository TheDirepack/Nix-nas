const nas = @import("nas");
fn status(outcome: nas.unlock_http.Activation) u16 {
    return switch (outcome) {
        .unlocked => 200,
        .wrong_password => 401,
        .rolled_back => 500,
        .timed_out => 504,
    };
}
test {
    _ = status(.unlocked);
}
