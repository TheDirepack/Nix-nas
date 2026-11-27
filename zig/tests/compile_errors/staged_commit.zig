const nas = @import("nas");
test {
    const staged: nas.transaction.Staged = undefined;
    _ = staged.commit();
}
