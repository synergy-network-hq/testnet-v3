use serde::{Deserialize, Serialize};

use super::epoch::V3EpochTransitionAnchor;
use crate::{
    canonical_hash, parse_hash_bytes, ConsensusSignatureVerifier, FinalitySyncWitness,
    FinalizedBlockRecord, FrozenValidatorRegistry, PosyError, PosyResult, SimplifiedEpochContext,
    SimplifiedFinalityParent, SimplifiedQuorumCertificate, ThreeQcFinality,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EpochTransitionAuthorization {
    pub previous_epoch: u64,
    pub previous_epoch_context_root: String,
    pub finalized_height: u64,
    pub next_epoch: u64,
    pub next_epoch_start_height: u64,
    pub next_epoch_end_height: u64,
    pub next_consensus_parameter_root: String,
    pub next_active_validator_set_root: String,
    pub next_validator_consensus_key_root: String,
    pub next_frozen_voting_weight_root: String,
}

impl EpochTransitionAuthorization {
    /// Prepare the acyclic execution subject before E−2 is proposed. The
    /// caller owns the governed registry/parameters; this function only
    /// freezes the canonical successor coordinates and their commitments.
    pub fn for_governed_successor(
        previous: &SimplifiedEpochContext,
        next_registry: &FrozenValidatorRegistry,
        next_consensus_parameter_root: String,
    ) -> PosyResult<Self> {
        let next_epoch = previous
            .epoch
            .checked_add(1)
            .ok_or_else(|| PosyError::invalid("epoch number overflow"))?;
        if next_registry.epoch() != next_epoch {
            return Err(PosyError::invalid("next registry has the wrong epoch"));
        }
        let start = previous
            .epoch_end_height
            .checked_add(1)
            .ok_or_else(|| PosyError::invalid("successor start height overflow"))?;
        let end = start
            .checked_add(999)
            .ok_or_else(|| PosyError::invalid("successor end height overflow"))?;
        let finalized_height = previous
            .epoch_end_height
            .checked_sub(2)
            .filter(|height| previous.contains_height(*height))
            .ok_or_else(|| {
                PosyError::invalid("predecessor cannot contain a closing three-QC tail")
            })?;
        let subject = Self {
            previous_epoch: previous.epoch,
            previous_epoch_context_root: previous.root()?,
            finalized_height,
            next_epoch,
            next_epoch_start_height: start,
            next_epoch_end_height: end,
            next_consensus_parameter_root,
            next_active_validator_set_root: next_registry.active_set_root()?,
            next_validator_consensus_key_root: next_registry.consensus_key_root()?,
            next_frozen_voting_weight_root: next_registry.frozen_weight_root()?,
        };
        subject.subject_root_v2()?;
        Ok(subject)
    }

    pub fn validate(
        &self,
        previous: &SimplifiedEpochContext,
        next: &SimplifiedEpochContext,
        next_registry: &FrozenValidatorRegistry,
    ) -> PosyResult<()> {
        next.validate_against(next_registry)?;
        if previous.chain_id != next.chain_id
            || previous.network_id != next.network_id
            || previous.protocol_version != next.protocol_version
            || self.previous_epoch != previous.epoch
            || Some(self.next_epoch) != previous.epoch.checked_add(1)
            || self.next_epoch != next.epoch
            || self.previous_epoch_context_root != previous.root()?
            || self.finalized_height.checked_add(2) != Some(previous.epoch_end_height)
            || Some(self.next_epoch_start_height) != previous.epoch_end_height.checked_add(1)
            || self.next_epoch_start_height != next.epoch_start_height
            || self.next_epoch_end_height != next.epoch_end_height
            || self.next_consensus_parameter_root != next.consensus_parameter_root
            || self.next_active_validator_set_root != next.active_validator_set_root
            || self.next_validator_consensus_key_root != next.validator_consensus_key_root
            || self.next_frozen_voting_weight_root != next.frozen_voting_weight_root
            || next_registry.epoch() != next.epoch
            || self.finalized_height == 0
        {
            return Err(PosyError::invalid(
                "invalid finalized epoch transition authority",
            ));
        }
        Ok(())
    }

    /// The canonical POSY-00E §3 subject. Its hash types use the protocol's
    /// original 32-byte JSON arrays; parameter roots remain canonical hex.
    /// Neither the closing block ID nor any QC ID is part of this preimage.
    pub fn subject_root_v2(&self) -> PosyResult<String> {
        #[derive(Serialize)]
        struct Subject<'a> {
            schema_version: u32,
            previous_epoch: u64,
            previous_epoch_context_root: [u8; 32],
            finalized_height: u64,
            next_epoch: u64,
            next_epoch_start_height: u64,
            next_epoch_end_height: u64,
            next_consensus_parameter_root: &'a str,
            next_active_validator_set_root: [u8; 32],
            next_validator_consensus_key_root: [u8; 32],
            next_frozen_voting_weight_root: [u8; 32],
        }
        fn nonzero_hash(value: &str) -> PosyResult<[u8; 32]> {
            let hash = parse_hash_bytes(value)?;
            if hash == [0; 32] {
                return Err(PosyError::invalid("epoch subject has a zero commitment"));
            }
            Ok(hash)
        }
        if self.previous_epoch.checked_add(1) != Some(self.next_epoch)
            || self.finalized_height == 0
            || self.finalized_height.checked_add(3) != Some(self.next_epoch_start_height)
            || self.next_epoch_start_height.checked_add(999) != Some(self.next_epoch_end_height)
        {
            return Err(PosyError::invalid(
                "invalid PoSy epoch transition subject coordinates",
            ));
        }
        nonzero_hash(&self.next_consensus_parameter_root)?;
        canonical_hash(
            "SYNERGY_POSY_SIMPLIFIED_EPOCH_TRANSITION_SUBJECT_V2",
            &Subject {
                schema_version: 2,
                previous_epoch: self.previous_epoch,
                previous_epoch_context_root: nonzero_hash(&self.previous_epoch_context_root)?,
                finalized_height: self.finalized_height,
                next_epoch: self.next_epoch,
                next_epoch_start_height: self.next_epoch_start_height,
                next_epoch_end_height: self.next_epoch_end_height,
                next_consensus_parameter_root: &self.next_consensus_parameter_root,
                next_active_validator_set_root: nonzero_hash(&self.next_active_validator_set_root)?,
                next_validator_consensus_key_root: nonzero_hash(
                    &self.next_validator_consensus_key_root,
                )?,
                next_frozen_voting_weight_root: nonzero_hash(&self.next_frozen_voting_weight_root)?,
            },
        )
    }

    /// Derive the next PoSy context and exact certified parent without any
    /// authority signing key. The caller must obtain the subject commitment
    /// from the authenticated protected execution at `finalized.height`, and
    /// must derive the registry from governed finalized membership state.
    /// A supplied next epoch context or locally generated seed is never used.
    #[allow(clippy::too_many_arguments)]
    pub fn derive_from_finalized_subject(
        &self,
        previous: &SimplifiedEpochContext,
        previous_registry: &FrozenValidatorRegistry,
        next_registry: &FrozenValidatorRegistry,
        finalized: &FinalizedBlockRecord,
        witness: &FinalitySyncWitness,
        finalized_subject_root: &str,
        verifier: &impl ConsensusSignatureVerifier,
    ) -> PosyResult<(SimplifiedEpochContext, SimplifiedFinalityParent)> {
        if self.subject_root_v2()? != finalized_subject_root {
            return Err(PosyError::invalid(
                "epoch subject differs from the finalized execution commitment",
            ));
        }
        let [seed, _, boundary] = &witness.quorum_certificates;
        let next = SimplifiedEpochContext::from_frozen_registry(
            previous.chain_id,
            previous.network_id.clone(),
            self.next_epoch,
            self.next_epoch_start_height,
            self.next_epoch_end_height,
            seed.id()?,
            self.next_consensus_parameter_root.clone(),
            next_registry,
        )?;
        self.verify_finality(
            previous,
            previous_registry,
            &next,
            next_registry,
            finalized,
            &witness.quorum_certificates,
            verifier,
        )?;
        witness.verify_exact_timeout_closure(previous, previous_registry, verifier)?;
        let parent = boundary.reference()?;
        let seed = seed.reference()?;
        let next = next.with_verified_transition_anchor(
            V3EpochTransitionAnchor {
                previous_epoch: self.previous_epoch,
                previous_epoch_context_root: parse_hash_bytes(&self.previous_epoch_context_root)?,
                certified_parent_height: parent.height,
                certified_parent_block_id: parent.block_id.clone(),
                certified_parent_qc_id: parse_hash_bytes(&parent.qc_id)?,
                finalized_seed_height: seed.height,
                finalized_seed_block_id: seed.block_id,
                finalized_seed_qc_id: parse_hash_bytes(&seed.qc_id)?,
                transition_subject_root: parse_hash_bytes(finalized_subject_root)?,
            },
            next_registry,
        )?;
        Ok((
            next,
            SimplifiedFinalityParent::QuorumCertificate {
                height: parent.height,
                block_id: parent.block_id,
                qc_id: parent.qc_id,
            },
        ))
    }

    /// Verify the closing witness under its original authority, never the new
    /// epoch's keys or weights. This authenticates closure, not the provenance
    /// of a proposed membership assignment or randomness seed; callers must
    /// independently derive/admit the next context from governed state.
    #[allow(clippy::too_many_arguments)]
    pub fn verify_finality(
        &self,
        previous: &SimplifiedEpochContext,
        previous_registry: &FrozenValidatorRegistry,
        next: &SimplifiedEpochContext,
        next_registry: &FrozenValidatorRegistry,
        finalized: &FinalizedBlockRecord,
        certificates: &[SimplifiedQuorumCertificate; 3],
        verifier: &impl ConsensusSignatureVerifier,
    ) -> PosyResult<()> {
        previous.validate_against(previous_registry)?;
        self.validate(previous, next, next_registry)?;
        if finalized.height != self.finalized_height
            || certificates[2].context.height != previous.epoch_end_height
        {
            return Err(PosyError::invalid(
                "epoch closure is not the terminal three-QC witness",
            ));
        }
        let mut projection = ThreeQcFinality::default();
        for certificate in certificates {
            certificate.verify(previous, previous_registry, verifier)?;
            projection.accept(certificate.clone())?;
        }
        if projection.last_finalized() != Some(finalized) {
            return Err(PosyError::invalid(
                "epoch closure differs from finalized record",
            ));
        }
        Ok(())
    }
}
