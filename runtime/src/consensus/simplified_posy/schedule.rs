use crate::consensus_parameters::ConsensusParameterRoot;
use crate::synergy_types::{
    BlockId, CanonicalSerialize, ChainId, Epoch, Hash, Height, NetworkId, Round, ValidatorId,
    ValidatorSet,
};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_512};
use std::collections::BTreeSet;

pub const POSY_SIMPLIFIED_PROTOCOL_VERSION: &str = "posy/3.0";
pub const POSY_SIMPLIFIED_CONTEXT_SCHEMA_VERSION: u32 = 1;
pub const POSY_SIMPLIFIED_LEADER_LEASE_BLOCKS: u64 = 10;
/// Hardware-backed validator count proposed for the first v3 epoch. This is
/// activation data, not a protocol-wide membership constant.
pub const POSY_SIMPLIFIED_INITIAL_VALIDATOR_COUNT: usize = 5;
/// Simplified PoSy starts at the existing Testnet cluster minimum. Later
/// finalized epoch transitions may freeze any larger validator set.
pub const POSY_SIMPLIFIED_MIN_VALIDATOR_COUNT: usize = 5;
pub const POSY_SIMPLIFIED_LEADER_SCHEDULE_DOMAIN: &str = "PoSy/LeaderSchedule/v3";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SimplifiedEpochAnchor {
    pub height: Height,
    pub round: Round,
    pub block_id: BlockId,
    /// Signer-independent finality subject root of the exact boundary QC.
    pub qc_finality_context_root: Hash,
}

/// Cross-epoch safety pointers for every v3-to-v3 transition.
///
/// A certified parent is not automatically finalized.  The separate
/// `finalized_seed_*` fields name the grandparent finalized by the exact
/// three-QC tail retained in the durable transition proof.  Keeping these
/// pointers distinct prevents the first QC of a new epoch from silently
/// upgrading a merely certified boundary block to finality.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SimplifiedV3EpochTransitionAnchor {
    pub previous_epoch: Epoch,
    pub previous_epoch_context_root: Hash,
    pub certified_parent_height: Height,
    pub certified_parent_block_id: BlockId,
    pub certified_parent_qc_id: Hash,
    pub finalized_seed_height: Height,
    pub finalized_seed_block_id: BlockId,
    pub finalized_seed_qc_id: Hash,
    /// Signer-independent root of the verified transition subject.  It binds
    /// the next frozen validator/key/weight roots and parameter root to the
    /// prior epoch's finalized execution authority.
    pub transition_subject_root: Hash,
}

impl SimplifiedV3EpochTransitionAnchor {
    pub fn validate_for_start_height(
        &self,
        epoch: Epoch,
        start_height: Height,
    ) -> Result<(), String> {
        let expected_previous_epoch = epoch
            .0
            .checked_sub(1)
            .map(Epoch)
            .ok_or_else(|| "v3 epoch transition cannot precede epoch zero".to_string())?;
        let latest_finalizable_height = self
            .certified_parent_height
            .0
            .checked_sub(2)
            .ok_or_else(|| "v3 transition certified parent is too low".to_string())?;
        if self.previous_epoch != expected_previous_epoch
            || self.certified_parent_height.0.checked_add(1) != Some(start_height.0)
            || self.finalized_seed_height.0 != latest_finalizable_height
            || self.certified_parent_block_id.0.trim().is_empty()
            || self.finalized_seed_block_id.0.trim().is_empty()
            || self.previous_epoch_context_root.is_zero()
            || self.certified_parent_qc_id.is_zero()
            || self.finalized_seed_qc_id.is_zero()
            || self.transition_subject_root.is_zero()
        {
            return Err(
                "invalid v3 epoch transition: certified parent and three-QC finalized seed must remain distinct"
                    .to_string(),
            );
        }
        Ok(())
    }
}

impl SimplifiedEpochAnchor {
    pub fn validate_for_start_height(&self, start_height: Height) -> Result<(), String> {
        if self.height.0.checked_add(1) != Some(start_height.0)
            || self.block_id.0.trim().is_empty()
            || self.qc_finality_context_root.is_zero()
        {
            return Err(
                "simplified epoch anchor is not the exact preceding finalized QC".to_string(),
            );
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SimplifiedEpochContext {
    pub schema_version: u32,
    pub chain_id: ChainId,
    pub network_id: NetworkId,
    pub protocol_version: String,
    pub epoch: Epoch,
    pub epoch_start_height: Height,
    pub epoch_end_height: Height,
    pub finalized_epoch_seed_root: Hash,
    /// Historical typed-PoSy boundary evidence retained only for strict
    /// decoding and audit of older durable records. Fresh Genesis P3 startup
    /// requires this to be absent, and the production driver rejects it;
    /// later P3 epochs use `v3_transition_anchor` instead.
    #[serde(default)]
    pub v2_boundary_anchor: Option<SimplifiedEpochAnchor>,
    /// Present only after a fully verified v3-to-v3 transition proof.  This
    /// is deliberately separate from the one-time v2 activation anchor.
    #[serde(default)]
    pub v3_transition_anchor: Option<SimplifiedV3EpochTransitionAnchor>,
    pub consensus_parameter_root: String,
    pub active_validator_set_root: Hash,
    pub validator_consensus_key_root: Hash,
    pub frozen_voting_weight_root: Hash,
    pub leader_lease_blocks: u64,
    pub leader_ring: Vec<ValidatorId>,
    pub leader_ring_root: Hash,
}

impl SimplifiedEpochContext {
    pub fn derive(
        epoch: Epoch,
        epoch_start_height: Height,
        epoch_end_height: Height,
        finalized_epoch_seed_root: Hash,
        consensus_parameter_root: ConsensusParameterRoot,
        validator_set: &ValidatorSet,
    ) -> Result<Self, String> {
        Self::derive_internal(
            epoch,
            epoch_start_height,
            epoch_end_height,
            finalized_epoch_seed_root,
            None,
            consensus_parameter_root,
            validator_set,
        )
    }

    #[cfg(test)]
    pub(crate) fn derive_from_v2_boundary(
        epoch: Epoch,
        epoch_start_height: Height,
        epoch_end_height: Height,
        boundary_anchor: SimplifiedEpochAnchor,
        consensus_parameter_root: ConsensusParameterRoot,
        validator_set: &ValidatorSet,
    ) -> Result<Self, String> {
        boundary_anchor.validate_for_start_height(epoch_start_height)?;
        Self::derive_internal(
            epoch,
            epoch_start_height,
            epoch_end_height,
            boundary_anchor.qc_finality_context_root,
            Some(boundary_anchor),
            consensus_parameter_root,
            validator_set,
        )
    }

    fn derive_internal(
        epoch: Epoch,
        epoch_start_height: Height,
        epoch_end_height: Height,
        finalized_epoch_seed_root: Hash,
        v2_boundary_anchor: Option<SimplifiedEpochAnchor>,
        consensus_parameter_root: ConsensusParameterRoot,
        validator_set: &ValidatorSet,
    ) -> Result<Self, String> {
        if validator_set.epoch != epoch {
            return Err("validator set epoch does not match simplified epoch context".to_string());
        }
        let active_set = validator_set.active_for_epoch(epoch);
        active_set.validate_unique_validator_and_key_ids()?;
        validate_dynamic_validator_topology(&active_set)?;
        let leader_ring = derive_epoch_leader_ring(finalized_epoch_seed_root, &active_set)?;
        let leader_ring_root = leader_ring_root(&leader_ring)?;
        let context = Self {
            schema_version: POSY_SIMPLIFIED_CONTEXT_SCHEMA_VERSION,
            chain_id: ChainId::synergy_testnet_v3(),
            network_id: NetworkId::fresh_posy_testnet_v3(),
            protocol_version: POSY_SIMPLIFIED_PROTOCOL_VERSION.to_string(),
            epoch,
            epoch_start_height,
            epoch_end_height,
            finalized_epoch_seed_root,
            v2_boundary_anchor,
            v3_transition_anchor: None,
            consensus_parameter_root: consensus_parameter_root.to_hex(),
            active_validator_set_root: active_set.hash()?,
            validator_consensus_key_root: active_set.consensus_key_root()?,
            frozen_voting_weight_root: active_set.frozen_bonded_weight_root()?,
            leader_lease_blocks: POSY_SIMPLIFIED_LEADER_LEASE_BLOCKS,
            leader_ring,
            leader_ring_root,
        };
        context.validate_against(&active_set)?;
        Ok(context)
    }

    pub fn validate(&self) -> Result<(), String> {
        self.chain_id.require_fresh_posy_testnet_v3()?;
        self.network_id.require_fresh_posy_testnet_v3()?;
        if self.schema_version != POSY_SIMPLIFIED_CONTEXT_SCHEMA_VERSION {
            return Err(format!(
                "unsupported simplified context schema {}, expected {}",
                self.schema_version, POSY_SIMPLIFIED_CONTEXT_SCHEMA_VERSION
            ));
        }
        if self.protocol_version != POSY_SIMPLIFIED_PROTOCOL_VERSION {
            return Err(format!(
                "wrong simplified PoSy protocol version {}, expected {}",
                self.protocol_version, POSY_SIMPLIFIED_PROTOCOL_VERSION
            ));
        }
        if self.epoch_start_height.0 == 0 || self.epoch_end_height.0 < self.epoch_start_height.0 {
            return Err("invalid simplified epoch height range".to_string());
        }
        if self.finalized_epoch_seed_root.is_zero() {
            return Err("simplified epoch seed root is missing".to_string());
        }
        if let Some(anchor) = &self.v2_boundary_anchor {
            anchor.validate_for_start_height(self.epoch_start_height)?;
            if anchor.qc_finality_context_root != self.finalized_epoch_seed_root {
                return Err("simplified epoch anchor and schedule seed root differ".to_string());
            }
        }
        if self.v2_boundary_anchor.is_some() && self.v3_transition_anchor.is_some() {
            return Err("simplified epoch context carries two transition authorities".to_string());
        }
        if let Some(anchor) = &self.v3_transition_anchor {
            anchor.validate_for_start_height(self.epoch, self.epoch_start_height)?;
            if anchor.finalized_seed_qc_id != self.finalized_epoch_seed_root {
                return Err(
                    "v3 transition finalized seed and leader-schedule seed differ".to_string(),
                );
            }
        }
        let parameter_root = ConsensusParameterRoot::from_hex(&self.consensus_parameter_root)?;
        if parameter_root.is_zero() {
            return Err("simplified consensus parameter root is missing".to_string());
        }
        for (name, root) in [
            ("active validator set", self.active_validator_set_root),
            ("validator consensus key", self.validator_consensus_key_root),
            ("frozen voting weight", self.frozen_voting_weight_root),
            ("leader ring", self.leader_ring_root),
        ] {
            if root.is_zero() {
                return Err(format!("simplified {name} root is missing"));
            }
        }
        if self.leader_lease_blocks != POSY_SIMPLIFIED_LEADER_LEASE_BLOCKS {
            return Err(format!(
                "leader lease must be exactly {} blocks",
                POSY_SIMPLIFIED_LEADER_LEASE_BLOCKS
            ));
        }
        if self.leader_ring.len() < POSY_SIMPLIFIED_MIN_VALIDATOR_COUNT {
            return Err(format!(
                "simplified Testnet-v3 requires at least {} leaders, found {}",
                POSY_SIMPLIFIED_MIN_VALIDATOR_COUNT,
                self.leader_ring.len()
            ));
        }
        if self.leader_ring.iter().collect::<BTreeSet<_>>().len() != self.leader_ring.len() {
            return Err("simplified leader ring contains duplicate validators".to_string());
        }
        if leader_ring_root(&self.leader_ring)? != self.leader_ring_root {
            return Err("simplified leader ring root mismatch".to_string());
        }
        Ok(())
    }

    pub fn validate_against(&self, validator_set: &ValidatorSet) -> Result<(), String> {
        self.validate()?;
        if validator_set.epoch != self.epoch {
            return Err("simplified context and validator-set epochs differ".to_string());
        }
        let active_set = validator_set.active_for_epoch(self.epoch);
        active_set.validate_unique_validator_and_key_ids()?;
        validate_dynamic_validator_topology(&active_set)?;
        if self.leader_ring.len() != active_set.validators.len() {
            return Err(
                "simplified leader ring size does not match the frozen epoch set".to_string(),
            );
        }
        if self.active_validator_set_root != active_set.hash()?
            || self.validator_consensus_key_root != active_set.consensus_key_root()?
            || self.frozen_voting_weight_root != active_set.frozen_bonded_weight_root()?
        {
            return Err("simplified context validator/key/weight roots do not match".to_string());
        }
        let expected_ring = derive_epoch_leader_ring(self.finalized_epoch_seed_root, &active_set)?;
        if self.leader_ring != expected_ring {
            return Err("simplified leader ring is not the deterministic epoch ring".to_string());
        }
        validate_single_validator_failure_liveness(&active_set)?;
        Ok(())
    }

    pub fn root(&self) -> Result<Hash, String> {
        self.validate()?;
        Ok(Hash::from_domain_bytes(
            "SYNERGY_POSY_SIMPLIFIED_EPOCH_CONTEXT_V1",
            &self.canonical_bytes()?,
        ))
    }

    pub(crate) fn derive_from_verified_v3_transition_anchor(
        epoch: Epoch,
        epoch_start_height: Height,
        epoch_end_height: Height,
        anchor: SimplifiedV3EpochTransitionAnchor,
        consensus_parameter_root: ConsensusParameterRoot,
        validator_set: &ValidatorSet,
    ) -> Result<Self, String> {
        anchor.validate_for_start_height(epoch, epoch_start_height)?;
        let mut context = Self::derive_internal(
            epoch,
            epoch_start_height,
            epoch_end_height,
            anchor.finalized_seed_qc_id,
            None,
            consensus_parameter_root,
            validator_set,
        )?;
        context.v3_transition_anchor = Some(anchor);
        context.validate_against(validator_set)?;
        Ok(context)
    }

    pub fn contains_height(&self, height: Height) -> bool {
        (self.epoch_start_height.0..=self.epoch_end_height.0).contains(&height.0)
    }

    pub fn lease_index(&self, height: Height) -> Result<u64, String> {
        self.validate()?;
        if !self.contains_height(height) {
            return Err(format!(
                "height {} is outside epoch range {}..={}",
                height.0, self.epoch_start_height.0, self.epoch_end_height.0
            ));
        }
        height
            .0
            .checked_sub(self.epoch_start_height.0)
            .ok_or_else(|| "lease height subtraction underflow".to_string())
            .map(|offset| offset / self.leader_lease_blocks)
    }

    pub fn scheduled_owner(&self, height: Height) -> Result<&ValidatorId, String> {
        self.authorized_proposer(height, 0)
    }

    pub fn authorized_proposer(
        &self,
        height: Height,
        takeover_offset: u64,
    ) -> Result<&ValidatorId, String> {
        let lease_index = self.lease_index(height)?;
        let ring_len = u64::try_from(self.leader_ring.len())
            .map_err(|_| "leader ring length exceeds u64".to_string())?;
        let index = lease_index
            .checked_add(takeover_offset)
            .ok_or_else(|| "leader index overflow".to_string())?
            % ring_len;
        self.leader_ring
            .get(index as usize)
            .ok_or_else(|| "authorized proposer missing from leader ring".to_string())
    }
}

pub fn derive_epoch_leader_ring(
    finalized_epoch_seed_root: Hash,
    validator_set: &ValidatorSet,
) -> Result<Vec<ValidatorId>, String> {
    if finalized_epoch_seed_root.is_zero() {
        return Err("cannot derive leader ring from a zero epoch seed root".to_string());
    }
    validator_set.validate_unique_validator_and_key_ids()?;
    let mut ranked = validator_set
        .validators
        .iter()
        .map(|validator| {
            let mut hasher = Sha3_512::new();
            hasher.update(POSY_SIMPLIFIED_LEADER_SCHEDULE_DOMAIN.as_bytes());
            hasher.update(finalized_epoch_seed_root.0);
            hasher.update(validator.validator_id.0.as_bytes());
            let rank: [u8; 64] = hasher.finalize().into();
            (rank, validator.validator_id.clone())
        })
        .collect::<Vec<_>>();
    ranked.sort_by(|left, right| left.0.cmp(&right.0).then(left.1.cmp(&right.1)));
    Ok(ranked
        .into_iter()
        .map(|(_, validator_id)| validator_id)
        .collect())
}

pub fn leader_ring_root(leader_ring: &[ValidatorId]) -> Result<Hash, String> {
    let bytes = serde_json::to_vec(leader_ring)
        .map_err(|error| format!("serialize canonical leader ring: {error}"))?;
    Ok(Hash::from_domain_bytes(
        "SYNERGY_POSY_SIMPLIFIED_LEADER_RING_V3",
        &bytes,
    ))
}

pub fn validate_dynamic_validator_topology(validator_set: &ValidatorSet) -> Result<(), String> {
    if validator_set.validators.len() < POSY_SIMPLIFIED_MIN_VALIDATOR_COUNT {
        return Err(format!(
            "simplified Testnet-v3 requires at least {} active validators, found {}",
            POSY_SIMPLIFIED_MIN_VALIDATOR_COUNT,
            validator_set.validators.len()
        ));
    }
    let clusters = validator_set
        .validators
        .iter()
        .map(|validator| validator.cluster_id)
        .collect::<BTreeSet<_>>();
    if clusters.len() != 1 {
        return Err("simplified PoSy requires one frozen consensus cluster per epoch".to_string());
    }
    Ok(())
}

pub fn validate_single_validator_failure_liveness(
    validator_set: &ValidatorSet,
) -> Result<(), String> {
    let total_weight = validator_set
        .validators
        .iter()
        .try_fold(0u128, |total, validator| {
            total
                .checked_add(u128::from(validator.voting_weight))
                .ok_or_else(|| "total frozen voting weight overflow".to_string())
        })?;
    if total_weight == 0 {
        return Err("total frozen voting weight is zero".to_string());
    }
    let two_total = total_weight
        .checked_mul(2)
        .ok_or_else(|| "two-thirds total-weight multiplication overflow".to_string())?;
    for validator in &validator_set.validators {
        let remaining = total_weight
            .checked_sub(u128::from(validator.voting_weight))
            .ok_or_else(|| "remaining frozen voting weight underflow".to_string())?;
        let three_remaining = remaining
            .checked_mul(3)
            .ok_or_else(|| "leave-one-out weight multiplication overflow".to_string())?;
        if three_remaining <= two_total {
            return Err(format!(
                "single-validator-failure liveness fails: {} controls at least one third of frozen voting weight",
                validator.validator_id.0
            ));
        }
    }
    Ok(())
}
