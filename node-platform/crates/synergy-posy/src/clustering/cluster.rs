use crate::{FrozenValidatorRegistry, PosyResult, ValidatorId};

/// Simplified PoSy v3 has one consensus cluster; this is not a Synergy Pod.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsensusCluster {
    pub cluster_id: u64,
    pub validator_ids: Vec<ValidatorId>,
}

impl ConsensusCluster {
    pub fn from_frozen_registry(registry: &FrozenValidatorRegistry) -> PosyResult<Self> {
        Ok(Self {
            cluster_id: 0,
            validator_ids: registry
                .active()
                .map(|validator| validator.validator_id.clone())
                .collect(),
        })
    }
}
