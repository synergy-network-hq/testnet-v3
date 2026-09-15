use crate::{SyncPeerCandidate, VerifiedHead, VerifiedSourceSelector};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncReadiness {
    pub local_finalized_height: u64,
    pub verified_network_finalized_height: u64,
    pub is_synchronized: bool,
    /// This is only the synchronization gate. PoSy still owns signing authority.
    pub may_sign: bool,
}

impl VerifiedSourceSelector {
    /// A peer advertisement is never evidence of finality. Callers must first
    /// verify the head through PoSy; source eligibility is checked again here.
    /// Missing eligible evidence fails closed rather than granting signing.
    pub fn readiness(
        &self,
        local_finalized_height: u64,
        candidates: &[SyncPeerCandidate],
        verified_heads: &[VerifiedHead],
    ) -> SyncReadiness {
        let sources = self.select(candidates, verified_heads).ok();
        let target = sources
            .as_ref()
            .and_then(|heads| heads.iter().map(|head| head.finalized_height).max());
        let synchronized = target.is_some_and(|height| local_finalized_height >= height);
        SyncReadiness {
            local_finalized_height,
            verified_network_finalized_height: target.unwrap_or(local_finalized_height),
            is_synchronized: synchronized,
            may_sign: synchronized,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn candidate(id: &str, advertised_height: u64) -> SyncPeerCandidate {
        SyncPeerCandidate {
            peer_id: id.into(),
            authenticated: true,
            protocol_compatible: true,
            genesis_hash: "genesis".into(),
            quarantined: false,
            consensus_duties_disabled: false,
            designated_support: false,
            advertised_height,
        }
    }

    #[test]
    fn unsigned_or_ineligible_advertisements_never_grant_readiness() {
        let selector = VerifiedSourceSelector::new("genesis");
        let liar = candidate("liar", 1_000_000);
        assert!(!selector.readiness(0, &[liar.clone()], &[]).may_sign);
        let untrusted = SyncPeerCandidate {
            authenticated: false,
            ..liar
        };
        let alleged = VerifiedHead {
            peer_id: "liar".into(),
            finalized_height: 0,
            finalized_hash: "genesis".into(),
            finality_evidence_id: "evidence".into(),
        };
        assert!(!selector.readiness(0, &[untrusted], &[alleged]).may_sign);
    }

    #[test]
    fn signing_gate_stays_closed_while_behind_eligible_verified_head() {
        let selector = VerifiedSourceSelector::new("genesis");
        let peer = candidate("support", 1_000_000);
        let head = VerifiedHead {
            peer_id: "support".into(),
            finalized_height: 12,
            finalized_hash: "h12".into(),
            finality_evidence_id: "e12".into(),
        };
        assert!(
            !selector
                .readiness(11, &[peer.clone()], &[head.clone()])
                .may_sign
        );
        assert!(selector.readiness(12, &[peer], &[head]).may_sign);
    }
}
