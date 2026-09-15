use crate::{
    ConsensusCluster, FrozenValidatorRegistry, PosyError, PosyResult, VerifiedClusterMembership,
};

/// Verifies that a height assignment uses the canonical single cluster and that
/// the cluster remains an exact view of the epoch-frozen validator registry.
pub fn verify_cluster_assignment(
    registry: &FrozenValidatorRegistry,
    cluster: &ConsensusCluster,
    assigned_cluster_id: u64,
) -> PosyResult<VerifiedClusterMembership> {
    if assigned_cluster_id != cluster.cluster_id {
        return Err(PosyError::invalid(
            "height was assigned to a different consensus cluster",
        ));
    }
    VerifiedClusterMembership::from_frozen_registry(registry, cluster)
}
