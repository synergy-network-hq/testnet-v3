use crate::{ConsensusCluster, FrozenValidatorRegistry, PosyResult};

pub fn assign_height_to_consensus_cluster(
    _height: u64,
    registry: &FrozenValidatorRegistry,
) -> PosyResult<ConsensusCluster> {
    ConsensusCluster::from_frozen_registry(registry)
}
