use serde::{Deserialize, Serialize};

use crate::{
    canonical_hash, require_nonempty, FrozenValidatorRegistry, PosyError, PosyResult, ValidatorId,
    POSY_LEADER_LEASE_BLOCKS, POSY_SIMPLIFIED_PROTOCOL_VERSION,
};

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
}

impl SimplifiedEpochContext {
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
        };
        context.validate_against(registry)?;
        Ok(context)
    }

    pub fn validate_against(&self, registry: &FrozenValidatorRegistry) -> PosyResult<()> {
        if self.chain_id != 1266
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
