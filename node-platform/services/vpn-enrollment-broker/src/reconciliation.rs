use std::collections::BTreeSet;
pub fn stale_peers(expected: &BTreeSet<String>, actual: &BTreeSet<String>) -> Vec<String> {
    actual.difference(expected).cloned().collect()
}
