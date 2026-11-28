const nas = @import("nas");
test {
    const committed: nas.transaction.Committed = undefined;
    _ = committed.rollback();
}
