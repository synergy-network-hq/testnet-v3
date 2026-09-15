use std::collections::{BTreeMap, BTreeSet};

use super::{SyncPeerCandidate, VerifiedHead};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SourceSelectionError {
    NoEligibleVerifiedSource,
    UnknownPeerEvidence(String),
    CandidateIneligible(String),
}

#[derive(Debug, Clone)]
pub struct VerifiedSourceSelector {
    local_genesis_hash: String,
    support_sources_only: bool,
}

impl VerifiedSourceSelector {
    pub fn new(local_genesis_hash: impl Into<String>) -> Self {
        Self {
            local_genesis_hash: local_genesis_hash.into(),
            support_sources_only: false,
        }
    }

    pub fn support_sources_only(&mut self, enabled: bool) {
        self.support_sources_only = enabled;
    }

    pub fn select(
        &self,
        candidates: &[SyncPeerCandidate],
        evidence: &[VerifiedHead],
    ) -> Result<Vec<VerifiedHead>, SourceSelectionError> {
        let peers = candidates
            .iter()
            .map(|peer| (peer.peer_id.as_str(), peer))
            .collect::<BTreeMap<_, _>>();
        let mut seen = BTreeSet::new();
        let mut eligible = Vec::new();
        for head in evidence {
            if !seen.insert(head.peer_id.clone()) {
                continue;
            }
            let peer = peers
                .get(head.peer_id.as_str())
                .ok_or_else(|| SourceSelectionError::UnknownPeerEvidence(head.peer_id.clone()))?;
            if !self.eligible(peer) {
                continue;
            }
            eligible.push(head.clone());
        }
        eligible.sort_by(|left, right| {
            right
                .finalized_height
                .cmp(&left.finalized_height)
                .then_with(|| left.peer_id.cmp(&right.peer_id))
        });
        if eligible.is_empty() {
            Err(SourceSelectionError::NoEligibleVerifiedSource)
        } else {
            Ok(eligible)
        }
    }

    fn eligible(&self, peer: &SyncPeerCandidate) -> bool {
        peer.authenticated
            && peer.protocol_compatible
            && !peer.quarantined
            && (!self.support_sources_only || peer.designated_support)
            && (self.local_genesis_hash.is_empty() || peer.genesis_hash == self.local_genesis_hash)
    }
}
