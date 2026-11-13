//! Unactivated empty-registry epoch handoff proposal.
//!
//! This pure write-set builder is NOT an epoch authorization API. Before any
//! runtime integration, the native owner must authenticate the exact predecessor
//! candidate/World and sequential successor authority, and the rule must be
//! approved. No runtime caller, network route or default feature enables it.
//! Historical World, custody and journals are never modified by this builder.
use std::sync::Arc;

use synergy_etdag::EtdagDigest;
use synergy_state::world_resources::{WorldResourceBudget, WorldResourcePermit};
use synergy_state::{StateDiff, WorldState};

use crate::ProcessingRegistryError;

pub struct ProcessingEpochTransition {
    diff: StateDiff,
    _permit: WorldResourcePermit,
}
impl ProcessingEpochTransition {
    pub fn diff(&self) -> &StateDiff {
        &self.diff
    }
}

/// Propose exactly two conditional metadata writes. Outstanding, unknown,
/// malformed or foreign-scoped records fail closed. Application must be part of
/// an ordinary deterministic candidate, never an offline finalized-state edit.
pub fn propose_empty_processing_epoch_transition(
    parent: &WorldState,
    previous: &EtdagDigest,
    next: &EtdagDigest,
    budget: &Arc<WorldResourceBudget>,
) -> Result<ProcessingEpochTransition, ProcessingRegistryError> {
    previous.validate()?;
    next.validate()?;
    if previous.is_zero() || next.is_zero() || previous == next {
        return Err(ProcessingRegistryError::Corrupt(
            "epoch proposal requires distinct nonzero namespaces".into(),
        ));
    }
    // Both bounded metadata decodes, encodings and retained write buffers are
    // covered before allocation. The ready reader charges its own index too.
    let permit = budget.reserve(96 * 1024)?;
    let groups = crate::processing_groups::propose_empty_epoch_metadata(parent, previous, next)?;
    let ready =
        crate::processing_registry::propose_empty_epoch_metadata(parent, previous, next, budget)?;
    Ok(ProcessingEpochTransition {
        diff: StateDiff {
            changes: vec![],
            protocol_changes: vec![groups, ready],
        },
        _permit: permit,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{processing_order_tip, ParentProcessingRegistry};
    use synergy_state::{state_root, AccountState};

    const GROUPS: &str = "etdag-processing-groups-v1/meta";
    const READY: &str = "etdag-processing-ready-v1/meta";
    const OLD: &str = "eb98d9273246e8d081d692ef500fde5e319b3cc044a20dc600fe8c7e611f45eac09fd01f425a1475e1df2744d209f3ea239cfecc720d2d1d070b73ef7f04744e";
    const NEXT: &str = "1530a4ecbe6da86cc15d9593faf4aa9e857b97f1acfb1d0c0d3ca1e1e3fc31ab7b88d9679c0831889fa54ca89c1635b5787fbedbf895035844b6488f0d041369";

    fn namespaces() -> (EtdagDigest, EtdagDigest) {
        (EtdagDigest(OLD.into()), EtdagDigest(NEXT.into()))
    }
    // Public protocol metadata observed identically at finalized H9998 on
    // Val2–Val6. No private material or transaction payload is used.
    fn boundary_world() -> WorldState {
        let mut world = WorldState::default();
        world.protocol.insert(GROUPS.into(), serde_json::to_vec(&serde_json::json!({
            "namespace_root": OLD, "last_number": 4,
            "last_root": "7f4b5e25a28683c2e2814be5c2e0de1028674514410b9fb1f109aecbeff98e81e4a00134ff3eee2e07f2dd035a73e17b38b7ea0d8cf45ae0b0e5a52cbb4f523f",
            "groups": 0, "claims": 0
        })).unwrap());
        world.protocol.insert(
            READY.into(),
            serde_json::to_vec(&serde_json::json!({
                "namespace_root": OLD, "generation": 4, "count": 0
            }))
            .unwrap(),
        );
        world
            .accounts
            .insert("preserved-account".into(), AccountState::default());
        world
            .protocol
            .insert("unrelated-policy".into(), b"unchanged".to_vec());
        world
    }

    #[test]
    fn epoch_proposal_reproduces_boundary_and_preserves_parent_and_other_state() {
        let budget = WorldResourceBudget::new(2 * 1024 * 1024);
        let (previous, next) = namespaces();
        let parent = boundary_world();
        let root = state_root(&parent).unwrap();
        assert!(ParentProcessingRegistry::read(&parent, &previous, &budget).is_ok());
        assert!(processing_order_tip(&parent, &previous).is_ok());
        assert!(ParentProcessingRegistry::read(&parent, &next, &budget).is_err());
        assert!(processing_order_tip(&parent, &next).is_err());
        let proposed =
            propose_empty_processing_epoch_transition(&parent, &previous, &next, &budget).unwrap();
        let duplicate =
            propose_empty_processing_epoch_transition(&parent, &previous, &next, &budget).unwrap();
        assert_eq!(proposed.diff(), duplicate.diff());
        drop(duplicate);
        assert!(proposed.diff().changes.is_empty());
        assert_eq!(proposed.diff().protocol_changes.len(), 2);
        assert_eq!(state_root(&parent).unwrap(), root);
        let mut candidate = parent.clone();
        proposed.diff().apply(&mut candidate).unwrap();
        assert_eq!(parent.accounts, candidate.accounts);
        assert_eq!(
            candidate.protocol.get("unrelated-policy"),
            parent.protocol.get("unrelated-policy")
        );
        assert!(ParentProcessingRegistry::read(&candidate, &next, &budget)
            .unwrap()
            .records()
            .is_empty());
        assert_eq!(
            processing_order_tip(&candidate, &next).unwrap(),
            (
                1,
                synergy_etdag::execution::processing_genesis_group_root(&next).unwrap(),
                false
            )
        );
        let encoded = serde_json::to_vec(&candidate).unwrap();
        let restored: WorldState = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(
            state_root(&restored).unwrap(),
            state_root(&candidate).unwrap()
        );
        assert!(ParentProcessingRegistry::read(&restored, &next, &budget).is_ok());
        assert!(proposed.diff().apply(&mut candidate).is_err()); // No replay.
        assert!(
            propose_empty_processing_epoch_transition(&candidate, &previous, &next, &budget)
                .is_err()
        );
        assert_eq!(state_root(&parent).unwrap(), root);
        drop(proposed);
        assert_eq!(budget.used(), 0);
    }

    #[test]
    fn epoch_proposal_rejects_nonempty_corrupt_foreign_and_insufficient_budget_atomically() {
        let budget = WorldResourceBudget::new(2 * 1024 * 1024);
        let (previous, next) = namespaces();
        for key in [
            "etdag-processing-groups-v1/group/00000000000000000001",
            "etdag-processing-groups-v1/claim/unknown",
            "etdag-processing-ready-v1/item/unknown",
            "etdag-processing-ready-v1/unknown",
        ] {
            let mut parent = boundary_world();
            parent.protocol.insert(key.into(), b"unconsumed".to_vec());
            let root = state_root(&parent).unwrap();
            assert!(
                propose_empty_processing_epoch_transition(&parent, &previous, &next, &budget)
                    .is_err()
            );
            assert_eq!(state_root(&parent).unwrap(), root);
            assert_eq!(budget.used(), 0);
        }
        for key in [GROUPS, READY] {
            let mut parent = boundary_world();
            let mut value: serde_json::Value =
                serde_json::from_slice(&parent.protocol[key]).unwrap();
            value["namespace_root"] = serde_json::json!(NEXT);
            parent
                .protocol
                .insert(key.into(), serde_json::to_vec(&value).unwrap());
            assert!(
                propose_empty_processing_epoch_transition(&parent, &previous, &next, &budget)
                    .is_err()
            );
            parent.protocol.insert(key.into(), b"corrupt".to_vec());
            assert!(
                propose_empty_processing_epoch_transition(&parent, &previous, &next, &budget)
                    .is_err()
            );
            assert_eq!(budget.used(), 0);
        }
        let parent = boundary_world();
        let tiny = WorldResourceBudget::new(1024);
        assert!(
            propose_empty_processing_epoch_transition(&parent, &previous, &next, &tiny).is_err()
        );
        assert_eq!(tiny.used(), 0);
        assert!(
            propose_empty_processing_epoch_transition(&parent, &previous, &previous, &budget)
                .is_err()
        );
        for invalid in [EtdagDigest("0".repeat(128)), EtdagDigest("invalid".into())] {
            assert!(propose_empty_processing_epoch_transition(
                &parent, &previous, &invalid, &budget
            )
            .is_err());
            assert!(
                propose_empty_processing_epoch_transition(&parent, &invalid, &next, &budget)
                    .is_err()
            );
        }
        for key in [GROUPS, READY] {
            let mut oversize = parent.clone();
            oversize.protocol.insert(key.into(), vec![b' '; 32 * 1024]);
            assert!(propose_empty_processing_epoch_transition(
                &oversize, &previous, &next, &budget
            )
            .is_err());
            assert_eq!(budget.used(), 0);
        }
        let proposed =
            propose_empty_processing_epoch_transition(&parent, &previous, &next, &budget).unwrap();
        let mut drifted = parent.clone();
        drifted
            .protocol
            .insert(READY.into(), b"changed after construction".to_vec());
        let before = state_root(&drifted).unwrap();
        assert!(proposed.diff().apply(&mut drifted).is_err());
        assert_eq!(state_root(&drifted).unwrap(), before); // No partial first write.
    }

    #[test]
    fn epoch_proposal_is_universal_across_empty_successor_scopes() {
        let budget = WorldResourceBudget::new(2 * 1024 * 1024);
        let (previous, next) = namespaces();
        let final_namespace = EtdagDigest::from_domain_bytes("epoch-candidate-test", b"third");
        let mut candidate = WorldState::default();
        let first =
            propose_empty_processing_epoch_transition(&candidate, &previous, &next, &budget)
                .unwrap();
        first.diff().apply(&mut candidate).unwrap();
        drop(first);
        let restored: WorldState =
            serde_json::from_slice(&serde_json::to_vec(&candidate).unwrap()).unwrap();
        let second =
            propose_empty_processing_epoch_transition(&restored, &next, &final_namespace, &budget)
                .unwrap();
        second.diff().apply(&mut candidate).unwrap();
        assert!(ParentProcessingRegistry::read(&candidate, &final_namespace, &budget).is_ok());
        assert!(processing_order_tip(&candidate, &final_namespace).is_ok());
        assert!(
            propose_empty_processing_epoch_transition(&candidate, &previous, &next, &budget)
                .is_err()
        );
        drop(second);
        assert_eq!(budget.used(), 0);
    }
}
