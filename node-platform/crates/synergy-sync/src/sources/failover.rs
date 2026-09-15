use std::collections::{BTreeMap, BTreeSet};

use crate::{BlockRequest, SyncPeerCandidate, SyncPlan, VerifiedHead};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SupportSourceFailoverError {
    InvalidRequest,
    NoEligibleSupportSource,
}

/// A single block request may try each already-selected authenticated support
/// source once. Candidate membership is frozen when the request starts: a
/// timeout cannot silently widen the request to canonical validators or an
/// unverified newly discovered peer.
#[derive(Debug, Clone)]
pub struct SupportSourceFailover {
    eligible: Vec<VerifiedHead>,
    attempted: BTreeSet<String>,
}

impl SupportSourceFailover {
    pub fn new(
        plan: &SyncPlan,
        candidates: &[SyncPeerCandidate],
        request: &BlockRequest,
    ) -> Result<Self, SupportSourceFailoverError> {
        if !request.validate() || request.through_height > plan.target_height {
            return Err(SupportSourceFailoverError::InvalidRequest);
        }
        let peers = candidates
            .iter()
            .map(|peer| (peer.peer_id.as_str(), peer))
            .collect::<BTreeMap<_, _>>();
        let mut seen = BTreeSet::new();
        let eligible = plan
            .sources
            .iter()
            .filter(|head| {
                let Some(peer) = peers.get(head.peer_id.as_str()) else {
                    return false;
                };
                peer.authenticated
                    && peer.protocol_compatible
                    && !peer.quarantined
                    && peer.designated_support
                    && head.finalized_height == plan.target_height
                    && head.finalized_hash == plan.target_block_id
                    && head.finalized_height >= request.through_height
                    && seen.insert(head.peer_id.clone())
            })
            .cloned()
            .collect::<Vec<_>>();
        if eligible.is_empty() {
            return Err(SupportSourceFailoverError::NoEligibleSupportSource);
        }
        Ok(Self {
            eligible,
            attempted: BTreeSet::new(),
        })
    }

    pub fn next_source(&mut self) -> Option<&VerifiedHead> {
        let source = self
            .eligible
            .iter()
            .find(|head| !self.attempted.contains(&head.peer_id))?;
        self.attempted.insert(source.peer_id.clone());
        Some(source)
    }

    pub fn attempted_count(&self) -> usize {
        self.attempted.len()
    }

    pub fn remaining_count(&self) -> usize {
        self.eligible.len().saturating_sub(self.attempted.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer(id: &str, support: bool) -> SyncPeerCandidate {
        SyncPeerCandidate {
            peer_id: id.into(),
            authenticated: true,
            protocol_compatible: true,
            genesis_hash: "genesis".into(),
            quarantined: false,
            consensus_duties_disabled: false,
            designated_support: support,
            advertised_height: 1_000_000,
        }
    }

    fn head(id: &str, height: u64) -> VerifiedHead {
        VerifiedHead {
            peer_id: id.into(),
            finalized_height: height,
            finalized_hash: format!("h{height}"),
            finality_evidence_id: format!("e{height}"),
        }
    }

    #[test]
    fn freezes_support_sources_and_checks_verified_target_coverage() {
        let plan = SyncPlan {
            target_height: 12,
            target_block_id: "h12".into(),
            sources: vec![
                head("support-a", 12),
                head("canonical", 12),
                head("support-b", 10),
                head("support-c", 12),
                VerifiedHead {
                    finalized_hash: "conflict".into(),
                    ..head("support-d", 12)
                },
            ],
        };
        let candidates = vec![
            peer("support-a", true),
            peer("canonical", false),
            peer("support-b", true),
            peer("support-c", true),
            peer("support-d", true),
        ];
        let request = BlockRequest {
            from_height: 11,
            through_height: 12,
            expected_parent_id: "h10".into(),
        };
        let mut failover = SupportSourceFailover::new(&plan, &candidates, &request).unwrap();
        assert_eq!(failover.next_source().unwrap().peer_id, "support-a");
        assert_eq!(failover.next_source().unwrap().peer_id, "support-c");
        assert!(failover.next_source().is_none());
        assert_eq!(failover.attempted_count(), 2);
    }
}
