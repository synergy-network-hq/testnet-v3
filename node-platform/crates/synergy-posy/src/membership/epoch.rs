use serde::{Deserialize, Serialize};

use crate::{
    canonical_hash, parse_hash_bytes, require_nonempty, FrozenValidatorRegistry, PosyError,
    PosyResult, SimplifiedFinalityParent, ValidatorId,
    POSY_LEADER_LEASE_BLOCKS, POSY_SIMPLIFIED_PROTOCOL_VERSION,
};

/// Exact POSY-00E certified parent and finalized seed, with the execution
/// subject that authorized their successor. This evidence is carried once
/// per epoch; historical externally signed contexts have no such field.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct V3EpochTransitionAnchor {
    pub previous_epoch: u64,
    pub previous_epoch_context_root: [u8; 32],
    pub certified_parent_height: u64,
    pub certified_parent_block_id: String,
    pub certified_parent_qc_id: [u8; 32],
    pub finalized_seed_height: u64,
    pub finalized_seed_block_id: String,
    pub finalized_seed_qc_id: [u8; 32],
    pub transition_subject_root: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SimplifiedEpochContext {
    pub chain_id: u64,
    pub network_id: String,
    pub protocol_version: String,
    pub epoch: u64,
    pub epoch_start_height: u64,
    pub epoch_end_height: u64,
    pub finalized_epoch_seed_root: String,
    pub consensus_parameter_root: String,
    pub active_validator_set_root: String,
    pub validator_consensus_key_root: String,
    pub frozen_voting_weight_root: String,
    pub leader_lease_blocks: u64,
    pub leader_ring: Vec<ValidatorId>,
    pub leader_ring_root: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    v3_transition_anchor: Option<V3EpochTransitionAnchor>,
}

impl SimplifiedEpochContext {
    #[allow(clippy::too_many_arguments)]
    pub fn from_frozen_registry(
        chain_id: u64,
        network_id: String,
        epoch: u64,
        epoch_start_height: u64,
        epoch_end_height: u64,
        finalized_epoch_seed_root: String,
        consensus_parameter_root: String,
        registry: &FrozenValidatorRegistry,
    ) -> PosyResult<Self> {
        if registry.epoch() != epoch {
            return Err(PosyError::invalid(
                "registry epoch differs from context epoch",
            ));
        }
        let leader_ring = crate::derive_epoch_leader_ring(&finalized_epoch_seed_root, registry)?;
        let context = Self {
            chain_id,
            network_id,
            protocol_version: POSY_SIMPLIFIED_PROTOCOL_VERSION.into(),
            epoch,
            epoch_start_height,
            epoch_end_height,
            finalized_epoch_seed_root,
            consensus_parameter_root,
            active_validator_set_root: registry.active_set_root()?,
            validator_consensus_key_root: registry.consensus_key_root()?,
            frozen_voting_weight_root: registry.frozen_weight_root()?,
            leader_lease_blocks: POSY_LEADER_LEASE_BLOCKS,
            leader_ring_root: canonical_hash(
                "SYNERGY_POSY_SIMPLIFIED_LEADER_RING_V3",
                &leader_ring,
            )?,
            leader_ring,
            v3_transition_anchor: None,
        };
        context.validate_against(registry)?;
        Ok(context)
    }

    pub fn validate_against(&self, registry: &FrozenValidatorRegistry) -> PosyResult<()> {
        if self.chain_id == 0
            || self.protocol_version != POSY_SIMPLIFIED_PROTOCOL_VERSION
            || self.epoch_start_height == 0
            || self.epoch_end_height < self.epoch_start_height
            || self.leader_lease_blocks != POSY_LEADER_LEASE_BLOCKS
            || registry.epoch() != self.epoch
        {
            return Err(PosyError::invalid("invalid simplified epoch context"));
        }
        require_nonempty(&self.network_id, "network id")?;
        require_nonempty(&self.finalized_epoch_seed_root, "finalized epoch seed root")?;
        require_nonempty(&self.consensus_parameter_root, "consensus parameter root")?;
        if self.leader_ring.len() != registry.active_count()
            || self.leader_ring_root
                != canonical_hash("SYNERGY_POSY_SIMPLIFIED_LEADER_RING_V3", &self.leader_ring)?
            || self.active_validator_set_root != registry.active_set_root()?
            || self.validator_consensus_key_root != registry.consensus_key_root()?
            || self.frozen_voting_weight_root != registry.frozen_weight_root()?
        {
            return Err(PosyError::invalid("frozen epoch context root mismatch"));
        }
        if let Some(anchor) = &self.v3_transition_anchor {
            if anchor.previous_epoch.checked_add(1) != Some(self.epoch)
                || anchor.certified_parent_height.checked_add(1) != Some(self.epoch_start_height)
                || anchor.finalized_seed_height.checked_add(2)
                    != Some(anchor.certified_parent_height)
                || anchor.finalized_seed_qc_id
                    != parse_hash_bytes(&self.finalized_epoch_seed_root)?
                || anchor.finalized_seed_qc_id == anchor.certified_parent_qc_id
                || [
                    anchor.previous_epoch_context_root,
                    anchor.certified_parent_qc_id,
                    anchor.finalized_seed_qc_id,
                    anchor.transition_subject_root,
                ]
                .contains(&[0; 32])
                || self.leader_ring
                    != crate::derive_epoch_leader_ring(&self.finalized_epoch_seed_root, registry)?
            {
                return Err(PosyError::invalid("invalid derived epoch context anchor"));
            }
            require_nonempty(&anchor.certified_parent_block_id, "certified parent block ID")?;
            require_nonempty(&anchor.finalized_seed_block_id, "finalized seed block ID")?;
        }
        Ok(())
    }

    pub(super) fn with_verified_transition_anchor(
        mut self,
        anchor: V3EpochTransitionAnchor,
        registry: &FrozenValidatorRegistry,
    ) -> PosyResult<Self> {
        self.v3_transition_anchor = Some(anchor);
        self.validate_against(registry)?;
        Ok(self)
    }

    pub(crate) fn is_consensus_derived(&self) -> bool {
        self.v3_transition_anchor.is_some()
    }

    pub(crate) fn verify_transition_parent(
        &self,
        parent: &SimplifiedFinalityParent,
    ) -> PosyResult<()> {
        if let Some(anchor) = &self.v3_transition_anchor {
            let parent = parent.quorum_certificate_reference().ok_or_else(|| {
                PosyError::invalid("derived epoch requires its certified predecessor")
            })?;
            if anchor.certified_parent_height != parent.height
                || anchor.certified_parent_block_id != parent.block_id
                || anchor.certified_parent_qc_id != parse_hash_bytes(&parent.qc_id)?
            {
                return Err(PosyError::invalid("derived epoch parent differs from its context"));
            }
        }
        Ok(())
    }

    pub fn contains_height(&self, height: u64) -> bool {
        (self.epoch_start_height..=self.epoch_end_height).contains(&height)
    }

    pub fn lease_index(&self, height: u64) -> PosyResult<u64> {
        if !self.contains_height(height) {
            return Err(PosyError::invalid("height is outside the epoch"));
        }
        Ok((height - self.epoch_start_height) / self.leader_lease_blocks)
    }

    pub fn authorized_proposer(&self, height: u64, takeover_offset: u64) -> PosyResult<&str> {
        let index = self
            .lease_index(height)?
            .checked_add(takeover_offset)
            .ok_or_else(|| PosyError::invalid("leader index overflow"))?
            % u64::try_from(self.leader_ring.len())
                .map_err(|_| PosyError::invalid("leader ring length exceeds u64"))?;
        self.leader_ring
            .get(index as usize)
            .map(String::as_str)
            .ok_or_else(|| PosyError::invalid("leader ring is empty"))
    }

    pub fn root(&self) -> PosyResult<String> {
        canonical_hash("SYNERGY_POSY_SIMPLIFIED_EPOCH_CONTEXT_V1", self)
    }
}
