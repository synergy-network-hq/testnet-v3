use crate::{ConsensusCluster, FrozenValidatorRegistry, PosyError, PosyResult, ValidatorId};

/// Verified projection of the frozen active validator set into the sole PoSy
/// consensus cluster. This type never creates or changes validator authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedClusterMembership {
    cluster_id: u64,
    validator_ids: Vec<ValidatorId>,
}

impl VerifiedClusterMembership {
    pub fn from_frozen_registry(
        registry: &FrozenValidatorRegistry,
        cluster: &ConsensusCluster,
    ) -> PosyResult<Self> {
        if cluster.cluster_id != 0 {
            return Err(PosyError::invalid(
                "simplified PoSy supports only consensus cluster zero",
            ));
        }
        let expected = registry
            .active()
            .map(|validator| validator.validator_id.clone())
            .collect::<Vec<_>>();
        if cluster.validator_ids != expected {
            return Err(PosyError::invalid(
                "cluster membership does not match the frozen active validator set",
            ));
        }
        Ok(Self {
            cluster_id: cluster.cluster_id,
            validator_ids: expected,
        })
    }

    pub const fn cluster_id(&self) -> u64 {
        self.cluster_id
    }

    pub fn contains(&self, validator_id: &str) -> bool {
        self.validator_ids
            .binary_search_by(|candidate| candidate.as_str().cmp(validator_id))
            .is_ok()
    }

    pub fn validator_ids(&self) -> &[ValidatorId] {
        &self.validator_ids
    }
}
