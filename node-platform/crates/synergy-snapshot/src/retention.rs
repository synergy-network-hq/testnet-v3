use synergy_crypto::Hash32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetainedSnapshot {
    pub height: u64,
    pub state_root: Hash32,
}

pub fn retained_snapshots(
    snapshots: impl IntoIterator<Item = RetainedSnapshot>,
    retain: usize,
) -> Vec<RetainedSnapshot> {
    let mut snapshots = snapshots.into_iter().collect::<Vec<_>>();
    snapshots.sort_unstable_by_key(|snapshot| snapshot.height);
    snapshots.dedup_by_key(|snapshot| snapshot.height);
    let start = snapshots.len().saturating_sub(retain);
    snapshots.drain(..start);
    snapshots
}
