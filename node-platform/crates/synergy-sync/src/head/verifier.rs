use serde::{Deserialize, Serialize};

use super::{SyncPeerCandidate, VerifiedHead};

/// A transport-supplied finalized-head claim. It is not trusted until PoSy
/// verifies the referenced finality evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeadClaim {
    pub peer_id: String,
    pub chain_id: u64,
    pub genesis_hash: String,
    pub finalized_height: u64,
    pub finalized_hash: String,
    pub finality_evidence_id: String,
    /// Opaque three-QC proof bytes consumed and verified only by PoSy.
    #[serde(default)]
    pub finality_witness: Option<Vec<u8>>,
}

/// Adapter implemented by the PoSy boundary that owns finality verification.
///
/// Sync calls this adapter but never counts votes, constructs a QC, or grants
/// consensus authority.
pub trait PosyFinalityVerifier {
    type Error;

    /// Verifies that the claim's evidence finalizes exactly the claimed block.
    fn verify_finalized_head(&self, claim: &HeadClaim) -> Result<(), Self::Error>;
}

/// Failure returned while converting an untrusted head claim into sync input.
#[derive(Debug)]
pub enum HeadVerificationError<E> {
    InvalidClaim,
    PeerMismatch,
    IneligiblePeer,
    ChainMismatch,
    GenesisMismatch,
    AdvertisementBehindClaim,
    Finality(E),
}

/// Verifies transport and chain bindings before delegating finality to PoSy.
#[derive(Debug, Clone)]
pub struct VerifiedHeadVerifier {
    chain_id: u64,
    genesis_hash: String,
}

impl VerifiedHeadVerifier {
    /// Creates a verifier pinned to one chain incarnation.
    pub fn new(chain_id: u64, genesis_hash: impl Into<String>) -> Self {
        Self {
            chain_id,
            genesis_hash: genesis_hash.into(),
        }
    }

    /// Produces a sync-only verified head after caller-owned PoSy verification.
    ///
    /// # Errors
    /// Returns an error for invalid peer/chain bindings, stale advertisements,
    /// empty commitments, or rejection by the PoSy finality verifier.
    pub fn verify<V: PosyFinalityVerifier>(
        &self,
        candidate: &SyncPeerCandidate,
        claim: &HeadClaim,
        finality: &V,
    ) -> Result<VerifiedHead, HeadVerificationError<V::Error>> {
        if claim.peer_id.trim().is_empty()
            || claim.finalized_height == 0
            || claim.finalized_hash.trim().is_empty()
            || claim.finality_evidence_id.trim().is_empty()
        {
            return Err(HeadVerificationError::InvalidClaim);
        }
        if claim.peer_id != candidate.peer_id {
            return Err(HeadVerificationError::PeerMismatch);
        }
        if !candidate.authenticated || !candidate.protocol_compatible || candidate.quarantined {
            return Err(HeadVerificationError::IneligiblePeer);
        }
        if claim.chain_id != self.chain_id {
            return Err(HeadVerificationError::ChainMismatch);
        }
        if claim.genesis_hash != self.genesis_hash || candidate.genesis_hash != self.genesis_hash {
            return Err(HeadVerificationError::GenesisMismatch);
        }
        if candidate.advertised_height < claim.finalized_height {
            return Err(HeadVerificationError::AdvertisementBehindClaim);
        }
        finality
            .verify_finalized_head(claim)
            .map_err(HeadVerificationError::Finality)?;
        Ok(VerifiedHead {
            peer_id: claim.peer_id.clone(),
            finalized_height: claim.finalized_height,
            finalized_hash: claim.finalized_hash.clone(),
            finality_evidence_id: claim.finality_evidence_id.clone(),
        })
    }

    /// Sync never determines PoSy finality.
    pub const fn may_determine_finality(&self) -> bool {
        false
    }
}
