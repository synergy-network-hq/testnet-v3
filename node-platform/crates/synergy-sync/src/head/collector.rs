use std::collections::{BTreeMap, BTreeSet};

use super::VerifiedHead;

/// Conflict detected while collecting already PoSy-verified heads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HeadCollectionError {
    EmptyPeer,
    Regression { current: u64, received: u64 },
    ConflictingBlock { height: u64 },
}

/// Result of adding a verified head to the collector.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeadUpdate {
    Inserted,
    Advanced,
    Unchanged,
}

/// Maintains one monotonic, non-conflicting verified head per peer.
#[derive(Debug, Clone, Default)]
pub struct VerifiedHeadCollector {
    heads: BTreeMap<String, VerifiedHead>,
}

impl VerifiedHeadCollector {
    /// Creates an empty verified-head collection.
    pub fn new() -> Self {
        Self::default()
    }

    /// Records a head that has already passed [`super::VerifiedHeadVerifier`].
    ///
    /// # Errors
    /// Rejects empty peer IDs, per-peer regressions, and conflicting blocks at
    /// the same finalized height.
    pub fn record(&mut self, head: VerifiedHead) -> Result<HeadUpdate, HeadCollectionError> {
        if head.peer_id.trim().is_empty() {
            return Err(HeadCollectionError::EmptyPeer);
        }
        let Some(current) = self.heads.get(&head.peer_id) else {
            self.heads.insert(head.peer_id.clone(), head);
            return Ok(HeadUpdate::Inserted);
        };
        if head.finalized_height < current.finalized_height {
            return Err(HeadCollectionError::Regression {
                current: current.finalized_height,
                received: head.finalized_height,
            });
        }
        if head.finalized_height == current.finalized_height {
            if head.finalized_hash != current.finalized_hash {
                return Err(HeadCollectionError::ConflictingBlock {
                    height: head.finalized_height,
                });
            }
            return Ok(HeadUpdate::Unchanged);
        }
        self.heads.insert(head.peer_id.clone(), head);
        Ok(HeadUpdate::Advanced)
    }

    /// Removes sources whose authenticated session is no longer live.
    pub fn retain_authenticated(&mut self, peers: &BTreeSet<String>) {
        self.heads.retain(|peer_id, _| peers.contains(peer_id));
    }

    /// Returns verified heads in deterministic peer-ID order.
    pub fn heads(&self) -> impl ExactSizeIterator<Item = &VerifiedHead> {
        self.heads.values()
    }

    /// Returns the number of peers with collected verified evidence.
    pub fn len(&self) -> usize {
        self.heads.len()
    }

    /// Reports whether no verified heads have been collected.
    pub fn is_empty(&self) -> bool {
        self.heads.is_empty()
    }
}
