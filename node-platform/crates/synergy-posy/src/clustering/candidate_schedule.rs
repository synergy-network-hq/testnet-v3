//! Inactive qualification of POSY-00C's shuffle/sizing, with the owner's
//! minimum-three proposal. No epoch activation, entropy creation, height
//! rotation, admission policy or consensus commitment is defined here.
use crate::{
    parse_hash_bytes, verify_strict_dual_quorum, ConsensusCluster, FrozenValidatorRegistry,
    PosyError, PosyResult,
};
use sha3::{Digest, Sha3_512};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CandidateClusterSchedule {
    epoch: u64,
    clusters: Vec<ConsensusCluster>,
    registry: FrozenValidatorRegistry,
}
impl CandidateClusterSchedule {
    /// Input is the finalized epoch seed bytes, never an online peer set or a
    /// new randomness source. Finalized provenance is the future caller's duty.
    pub fn derive(registry: &FrozenValidatorRegistry, finalized_seed: &str) -> PosyResult<Self> {
        let seed = parse_hash_bytes(finalized_seed)?;
        if seed == [0; 32] {
            return Err(PosyError::invalid("zero finalized cluster seed"));
        }
        registry.active_weight()?;
        let n = registry.active_count();
        let count = match n {
            0..=2 => return Err(PosyError::invalid("candidate cluster minimum is three")),
            3..=9 => 1,
            10..=20 => 2,
            21..=150 => 3,
            _ => n.div_ceil(50),
        };
        // Exact POSY-00C §0C.8 rank preimage and full 512-bit ascending rank.
        let mut ranked = registry
            .active()
            .map(|v| {
                let mut h = Sha3_512::new();
                h.update(b"PoSy/ClusterShuffle/v2.1");
                h.update(seed);
                h.update(v.validator_id.as_bytes());
                (h.finalize().to_vec(), v.validator_id.clone())
            })
            .collect::<Vec<_>>();
        ranked.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));
        let mut clusters = (0..count)
            .map(|id| ConsensusCluster {
                cluster_id: id as u64,
                validator_ids: vec![],
            })
            .collect::<Vec<_>>();
        for (position, (_, id)) in ranked.into_iter().enumerate() {
            clusters[position % count].validator_ids.push(id);
        }
        // Canonical ID order for membership lookup; rank determines placement.
        for cluster in &mut clusters {
            cluster.validator_ids.sort();
        }
        Ok(Self {
            epoch: registry.epoch(),
            clusters,
            registry: registry.clone(),
        })
    }
    pub fn epoch(&self) -> u64 {
        self.epoch
    }
    pub fn clusters(&self) -> &[ConsensusCluster] {
        &self.clusters
    }
    /// Applicable cluster is supplied by a future authenticated height schedule,
    /// not inferred here. Exact map equality precedes existing dual quorum.
    pub fn verify_cluster_quorum(
        &self,
        cluster: &ConsensusCluster,
        signers: &[String],
    ) -> PosyResult<()> {
        let expected = usize::try_from(cluster.cluster_id)
            .ok()
            .and_then(|id| self.clusters.get(id))
            .filter(|expected| *expected == cluster)
            .ok_or_else(|| {
                PosyError::invalid("candidate cluster differs from deterministic map")
            })?;
        let validators = self
            .registry
            .quorum_validators()
            .into_iter()
            .filter(|v| {
                expected
                    .validator_ids
                    .binary_search(&v.validator_id)
                    .is_ok()
            })
            .collect::<Vec<_>>();
        verify_strict_dual_quorum(&validators, signers)
            .map_err(|_| PosyError::invalid("candidate cluster lacks strict frozen dual quorum"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ValidatorRecord, ValidatorStatus};
    fn records(n: usize) -> Vec<ValidatorRecord> {
        (0..n)
            .map(|i| ValidatorRecord {
                validator_id: format!("v{i:03}"),
                consensus_key_id: format!("k{i:03}"),
                frozen_voting_weight: 100,
                status: ValidatorStatus::Active,
            })
            .collect()
    }
    fn registry(n: usize) -> FrozenValidatorRegistry {
        FrozenValidatorRegistry::new_candidate_cluster_profile(7, records(n)).unwrap()
    }
    #[test]
    fn candidate_boundaries_are_balanced_complete_and_input_order_independent() {
        for (n, k) in [
            (3, 1),
            (4, 1),
            (5, 1),
            (9, 1),
            (10, 2),
            (20, 2),
            (21, 3),
            (36, 3),
            (150, 3),
            (151, 4),
            (200, 4),
            (201, 5),
        ] {
            let r = registry(n);
            let map = CandidateClusterSchedule::derive(&r, &"01".repeat(32)).unwrap();
            assert_eq!(map.epoch(), 7);
            assert_eq!(map.clusters.len(), k);
            let mut union = map
                .clusters
                .iter()
                .flat_map(|c| c.validator_ids.clone())
                .collect::<Vec<_>>();
            union.sort();
            assert_eq!(
                union,
                records(n)
                    .into_iter()
                    .map(|v| v.validator_id)
                    .collect::<Vec<_>>()
            );
            let min = map
                .clusters
                .iter()
                .map(|c| c.validator_ids.len())
                .min()
                .unwrap();
            let max = map
                .clusters
                .iter()
                .map(|c| c.validator_ids.len())
                .max()
                .unwrap();
            assert!(max - min <= 1);
            let mut reversed = records(n);
            reversed.reverse();
            assert_eq!(
                map,
                CandidateClusterSchedule::derive(
                    &FrozenValidatorRegistry::new_candidate_cluster_profile(7, reversed).unwrap(),
                    &"01".repeat(32)
                )
                .unwrap()
            );
        }
        assert!(FrozenValidatorRegistry::new(7, records(3)).is_err());
        assert!(FrozenValidatorRegistry::new_candidate_cluster_profile(7, records(2)).is_err());
        assert!(CandidateClusterSchedule::derive(&registry(5), &"00".repeat(32)).is_err());
        assert!(CandidateClusterSchedule::derive(&registry(5), "foreign").is_err());
    }
    #[test]
    fn candidate_shuffle_vector_and_minimum_do_not_activate_runtime() {
        let map = CandidateClusterSchedule::derive(&registry(10), &"01".repeat(32)).unwrap();
        assert_eq!(
            map.clusters[0].validator_ids,
            ["v000", "v001", "v004", "v005", "v008"]
        );
        assert_eq!(
            map.clusters[1].validator_ids,
            ["v002", "v003", "v006", "v007", "v009"]
        );
        let three = CandidateClusterSchedule::derive(&registry(21), &"01".repeat(32)).unwrap();
        assert_eq!(
            three.clusters[0].validator_ids,
            ["v001", "v002", "v003", "v008", "v012", "v017", "v018"]
        );
        assert_eq!(
            three.clusters[1].validator_ids,
            ["v000", "v004", "v009", "v013", "v014", "v016", "v019"]
        );
        assert_eq!(
            three.clusters[2].validator_ids,
            ["v005", "v006", "v007", "v010", "v011", "v015", "v020"]
        );
        assert_ne!(
            map,
            CandidateClusterSchedule::derive(&registry(10), &"02".repeat(32)).unwrap()
        );
        // Existing cluster owner still rejects multi-cluster assignment.
        assert!(crate::verify_cluster_assignment(&registry(10), &map.clusters[0], 0).is_err());
        let mut duplicate = records(3);
        duplicate[1].consensus_key_id = duplicate[0].consensus_key_id.clone();
        assert!(FrozenValidatorRegistry::new_candidate_cluster_profile(7, duplicate).is_err());
        let mut inactive = records(3);
        inactive[0].status = ValidatorStatus::Shadow;
        assert!(FrozenValidatorRegistry::new_candidate_cluster_profile(7, inactive).is_err());
        let mut overflow = records(3);
        overflow[0].frozen_voting_weight = u128::MAX;
        assert!(CandidateClusterSchedule::derive(
            &FrozenValidatorRegistry::new_candidate_cluster_profile(7, overflow).unwrap(),
            &"01".repeat(32)
        )
        .is_err());
    }
    #[test]
    fn candidate_quorum_is_frozen_cluster_scoped_and_weighted() {
        let map = CandidateClusterSchedule::derive(&registry(10), &"01".repeat(32)).unwrap();
        let c = &map.clusters[0];
        assert!(map.verify_cluster_quorum(c, &c.validator_ids[..4]).is_ok());
        assert!(map.verify_cluster_quorum(c, &c.validator_ids[..3]).is_err());
        let mut foreign = c.clone();
        foreign.validator_ids[0] = map.clusters[1].validator_ids[0].clone();
        assert!(map
            .verify_cluster_quorum(&foreign, &c.validator_ids)
            .is_err());
        let mut signers = c.validator_ids[..3].to_vec();
        signers.push(signers[0].clone());
        assert!(map.verify_cluster_quorum(c, &signers).is_err());
        signers = c.validator_ids[..3].to_vec();
        signers.push(map.clusters[1].validator_ids[0].clone());
        assert!(map.verify_cluster_quorum(c, &signers).is_err());
        let mut rs = records(5);
        rs[0].frozen_voting_weight = 1000;
        let weighted = CandidateClusterSchedule::derive(
            &FrozenValidatorRegistry::new_candidate_cluster_profile(7, rs).unwrap(),
            &"01".repeat(32),
        )
        .unwrap();
        assert!(weighted
            .verify_cluster_quorum(
                &weighted.clusters[0],
                &weighted.clusters[0].validator_ids[1..]
            )
            .is_err());
    }
}
