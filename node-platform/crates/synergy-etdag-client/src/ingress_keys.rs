use std::collections::BTreeSet;

use synergy_etdag::{EtdagDigest, IngressKemKeyRecord, IngressKemKeyRegistry};

use crate::VerifiedTargetContext;

/// Resolves exact assigned cluster membership from the target's governed binding.
pub trait ClusterMembershipVerifier {
    fn verify_membership(
        &self,
        target: &VerifiedTargetContext,
        members: &BTreeSet<String>,
    ) -> Result<(), IngressKeyError>;
}

#[derive(Debug, Clone)]
pub struct ActiveIngressKeys {
    context_root: EtdagDigest,
    records: Vec<IngressKemKeyRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IngressKeyError {
    ContextMismatch,
    InvalidRegistry(String),
    NoActiveKeys,
}

impl ActiveIngressKeys {
    pub fn from_registry(
        target: &VerifiedTargetContext,
        registry: IngressKemKeyRegistry,
        cluster_members: &BTreeSet<String>,
        membership_verifier: &impl ClusterMembershipVerifier,
    ) -> Result<Self, IngressKeyError> {
        registry
            .validate_protected_profile()
            .map_err(|error| IngressKeyError::InvalidRegistry(format!("{error:?}")))?;
        let context_root = target
            .context_root()
            .map_err(|error| IngressKeyError::InvalidRegistry(format!("{error:?}")))?;
        membership_verifier.verify_membership(target, cluster_members)?;
        if cluster_members.len() as u64 != target.inner().assigned_cluster_validator_count
            || cluster_members.is_empty()
            || cluster_members.iter().any(|id| id.trim().is_empty())
            || registry
                .root()
                .map_err(|error| IngressKeyError::InvalidRegistry(format!("{error:?}")))?
                != target.inner().ingress_kem_registry_root
        {
            return Err(IngressKeyError::ContextMismatch);
        }
        let mut records = registry
            .records
            .into_iter()
            .filter(|record| {
                cluster_members.contains(&record.validator_id)
                    && record.activation_height <= target.target_height()
                    && record
                        .retirement_height
                        .is_none_or(|height| target.target_height() < height)
            })
            .collect::<Vec<_>>();
        records.sort_by(|a, b| a.validator_id.cmp(&b.validator_id));
        if records.len() != cluster_members.len() {
            return Err(IngressKeyError::NoActiveKeys);
        }
        Ok(Self {
            context_root,
            records,
        })
    }

    pub fn context_root(&self) -> &EtdagDigest {
        &self.context_root
    }

    pub fn records(&self) -> &[IngressKemKeyRecord] {
        &self.records
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use synergy_etdag::{IngressKemPublicKey, TargetAdmissionContextV3};

    struct Membership;
    impl ClusterMembershipVerifier for Membership {
        fn verify_membership(
            &self,
            target: &VerifiedTargetContext,
            members: &BTreeSet<String>,
        ) -> Result<(), IngressKeyError> {
            if target.inner().assigned_cluster_membership_root == "governed-val2"
                && members == &BTreeSet::from(["val2".into()])
            {
                Ok(())
            } else {
                Err(IngressKeyError::ContextMismatch)
            }
        }
    }

    fn target(registry: &IngressKemKeyRegistry) -> VerifiedTargetContext {
        VerifiedTargetContext::new(TargetAdmissionContextV3 {
            context_version: 1,
            chain_id: 1266,
            network_id: "testnet-v3".into(),
            protocol_version: "v3".into(),
            epoch: 1,
            target_height: 3,
            target_height_offset: 5,
            source_finalized_height: 0,
            source_finality_context_root: "root".into(),
            active_validator_set_root: "root".into(),
            validator_consensus_key_root: "root".into(),
            frozen_voting_weight_root: "root".into(),
            cluster_schedule_version: "v1".into(),
            finalized_epoch_seed_root: "root".into(),
            assigned_height_schedule_root: "root".into(),
            cluster_map_root: "root".into(),
            assigned_cluster_id: 1,
            assigned_cluster_membership_root: "governed-val2".into(),
            assigned_cluster_validator_count: 1,
            assigned_cluster_total_voting_weight: 1,
            consensus_parameter_root: "root".into(),
            cryptographic_profile_root: "root".into(),
            ingress_kem_registry_root: registry.root().unwrap(),
        })
        .unwrap()
    }

    #[test]
    fn static_registry_binds_by_root_and_exact_cluster_membership() {
        let registry = IngressKemKeyRegistry {
            context_root: EtdagDigest::from_domain_bytes("governance", b"static"),
            records: vec![IngressKemKeyRecord {
                key_id: "kem-val2".into(),
                validator_id: "val2".into(),
                public_key: IngressKemPublicKey {
                    algorithm: "ML-KEM-1024".into(),
                    public_key: vec![1; 1568],
                },
                activation_height: 1,
                retirement_height: None,
            }],
        };
        let target = target(&registry);
        let members = BTreeSet::from(["val2".into()]);
        assert_ne!(registry.context_root, target.context_root().unwrap());
        assert!(
            ActiveIngressKeys::from_registry(&target, registry.clone(), &members, &Membership)
                .is_ok()
        );
        assert!(ActiveIngressKeys::from_registry(
            &target,
            registry.clone(),
            &BTreeSet::from(["val3".into()]),
            &Membership
        )
        .is_err());
        let mut changed = registry.clone();
        changed.records[0].public_key.public_key[0] ^= 1;
        assert!(ActiveIngressKeys::from_registry(&target, changed, &members, &Membership).is_err());
        let mut overlap = registry.clone();
        let mut successor = overlap.records[0].clone();
        successor.key_id = "successor".into();
        successor.activation_height = 2;
        overlap.records.push(successor);
        assert!(ActiveIngressKeys::from_registry(&target, overlap, &members, &Membership).is_err());
        let mut weaker = registry;
        weaker.records[0].public_key.algorithm = "ML-KEM-768".into();
        assert!(ActiveIngressKeys::from_registry(&target, weaker, &members, &Membership).is_err());
    }
}
