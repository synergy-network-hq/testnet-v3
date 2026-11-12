#[test]
fn restart_before_persist() {
    crate::support::consensus_safety("consensus/restart_before_persist");
}
