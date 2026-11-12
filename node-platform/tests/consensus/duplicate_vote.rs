#[test]
fn duplicate_vote() {
    crate::support::consensus_safety("consensus/duplicate_vote");
}
