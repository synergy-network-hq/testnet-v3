//! Inactive qualification of POSY-00C's shuffle/sizing, with the owner's
//! minimum-three proposal. It checks supplied height assignments without
//! defining rotation, epoch activation, admission policy or consensus commitments.
use crate::{
    parse_hash_bytes, verify_strict_dual_quorum, ConsensusCluster, FrozenValidatorRegistry,
    PosyError, PosyResult,
};
use sha3::{Digest, Sha3_512};
use std::collections::BTreeMap;

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
        let weights = registry
            .active()
            .map(|v| (v.validator_id.as_str(), v.frozen_voting_weight))
            .collect::<BTreeMap<_, _>>();
        // Canonical ID order for membership lookup; rank determines placement.
        for cluster in &mut clusters {
            cluster.validator_ids.sort();
            // POSY-00C §0C.10: even the largest possible fault cohort
            // must have strictly less than one third of its cluster's weight.
            let mut assigned = cluster
                .validator_ids
                .iter()
                .map(|id| weights[id.as_str()])
                .collect::<Vec<_>>();
            assigned.sort_unstable_by(|a, b| b.cmp(a));
            let total = assigned.iter().sum::<u128>();
            let fault_count = (assigned.len() - 1) / 3;
            let top_fault_weight = assigned[..fault_count].iter().sum::<u128>();
            if top_fault_weight > (total - 1) / 3 {
                return Err(PosyError::invalid(format!(
                    "candidate cluster {} fails the top-f frozen-weight bound",
                    cluster.cluster_id
                )));
            }
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
    /// Bind the candidate map to the exact-height assignments already
    /// authenticated by the caller. Indices are offsets from first_height.
    pub fn bind_height_assignments<'a>(
        &'a self,
        epoch: u64,
        first_height: u64,
        last_height: u64,
        assignments: &'a [u64],
    ) -> PosyResult<CandidateHeightAssignments<'a>> {
        let count = last_height
            .checked_sub(first_height)
            .and_then(|delta| delta.checked_add(1))
            .and_then(|count| usize::try_from(count).ok());
        if epoch != self.epoch || first_height == 0 || count != Some(assignments.len()) {
            return Err(PosyError::invalid(
                "candidate assignment epoch or height range differs",
            ));
        }
        let cluster_count = self.clusters.len() as u64;
        if assignments.iter().any(|id| *id >= cluster_count) {
            return Err(PosyError::invalid(
                "candidate height selects an unknown cluster",
            ));
        }
        Ok(CandidateHeightAssignments {
            schedule: self,
            first_height,
            assignments,
        })
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

/// Inactive verifier input for one contiguous epoch assignment. Construction
/// checks structural consistency. The caller authenticates the input schedule.
pub struct CandidateHeightAssignments<'a> {
    schedule: &'a CandidateClusterSchedule,
    first_height: u64,
    assignments: &'a [u64],
}

impl CandidateHeightAssignments<'_> {
    /// Check the certificate's assigned cluster before counting any signer.
    pub fn verify_height_quorum(
        &self,
        height: u64,
        cluster: &ConsensusCluster,
        signers: &[String],
    ) -> PosyResult<()> {
        let assigned = height
            .checked_sub(self.first_height)
            .and_then(|offset| usize::try_from(offset).ok())
            .and_then(|offset| self.assignments.get(offset));
        if assigned != Some(&cluster.cluster_id) {
            return Err(PosyError::invalid(
                "candidate certificate is outside its assigned cluster or height",
            ));
        }
        self.schedule.verify_cluster_quorum(cluster, signers)
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
    fn candidate_quorum_is_frozen_and_cluster_scoped() {
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
    }

    #[test]
    fn only_the_assigned_cluster_can_form_quorum_at_a_height() {
        for (n, assignments, threshold) in [(10, vec![0, 1], 4), (21, vec![2, 0, 1], 5)] {
            let map = CandidateClusterSchedule::derive(&registry(n), &"01".repeat(32)).unwrap();
            let first = 6001;
            let last = first + assignments.len() as u64 - 1;
            assert!(map
                .bind_height_assignments(8, first, last, &assignments)
                .is_err());
            assert!(map
                .bind_height_assignments(7, first, last + 1, &assignments)
                .is_err());
            assert!(map
                .bind_height_assignments(7, first, first, &[n as u64])
                .is_err());
            let bound = map
                .bind_height_assignments(7, first, last, &assignments)
                .unwrap();
            for (offset, &id) in assignments.iter().enumerate() {
                let height = first + offset as u64;
                let cluster = &map.clusters[id as usize];
                let other = &map.clusters[(id as usize + 1) % map.clusters.len()];
                let signers = &cluster.validator_ids[..threshold];
                assert!(bound.verify_height_quorum(height, cluster, signers).is_ok());
                assert!(bound
                    .verify_height_quorum(height, cluster, &signers[..threshold - 1])
                    .is_err());
                assert!(bound
                    .verify_height_quorum(height, other, &other.validator_ids)
                    .is_err());
                assert!(bound
                    .verify_height_quorum(first - 1, cluster, signers)
                    .is_err());
                assert!(bound
                    .verify_height_quorum(last + 1, cluster, signers)
                    .is_err());
            }
        }
    }

    #[test]
    fn candidate_rejects_weight_concentration_at_both_split_points() {
        // Each offending cohort is below one third of global weight, yet
        // reaches exactly one third within its deterministic assigned cluster.
        for (n, at_limit) in [(10, vec![(0, 200)]), (21, vec![(1, 125), (2, 125)])] {
            let mut rs = records(n);
            for &(index, weight) in &at_limit {
                rs[index].frozen_voting_weight = weight;
            }
            let seed = "01".repeat(32);
            let registry =
                FrozenValidatorRegistry::new_candidate_cluster_profile(7, rs.clone()).unwrap();
            assert!(CandidateClusterSchedule::derive(&registry, &seed)
                .unwrap_err()
                .to_string()
                .contains("top-f frozen-weight bound"));

            rs[at_limit[0].0].frozen_voting_weight -= 1;
            let registry = FrozenValidatorRegistry::new_candidate_cluster_profile(7, rs).unwrap();
            assert!(CandidateClusterSchedule::derive(&registry, &seed).is_ok());
        }
    }
}
