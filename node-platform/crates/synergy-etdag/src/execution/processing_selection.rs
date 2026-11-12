//! Deterministic selection from the canonical parent's processing-ready view.
//!
//! This module supplies no admission, reveal, availability or finality authority.
//! The PoSy candidate owner must independently verify and commit the view and
//! its payload references before using it. Local worker completion is never a
//! substitute for that parent state. Pending work is absent from this view.
//! The owner must derive the view using canonical identity validity and nonce
//! eligibility at inclusion, including virtual nonce advancement within the
//! candidate. This helper covers dependency/order/capacity selection only; it
//! cannot turn a future nonce or revoked authorization into eligible work.
use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::{EtdagDigest, EtdagError};

// Decoder/resident reservations remain the shared runtime owner's responsibility.
// These hard bounds also precede this helper's index/selection allocations.
const MAX_READY_ITEMS: usize = 4096;
const MAX_DEPENDENCIES_PER_ITEM: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessingReadyItem {
    pub group_number: u64,
    pub group_root: EtdagDigest,
    pub order_position: u32,
    pub envelope_id: EtdagDigest,
    pub payload_root: EtdagDigest,
    pub readiness_root: EtdagDigest,
    pub gas_class_units: u64,
    pub encoded_bytes: u64,
    /// Only dependencies not yet consumed in this canonical parent. Resolved
    /// dependencies must be removed by the verified parent-state transition,
    /// never by the proposer consulting its local cache.
    pub remaining_dependencies: Vec<EtdagDigest>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessingReadyView {
    /// Governed chain-incarnation/profile scope, not a moving inclusion height.
    pub namespace_root: EtdagDigest,
    /// Canonical (ordering-group number, certified order position) order.
    pub items: Vec<ProcessingReadyItem>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessingSelection {
    pub parent_ready_root: EtdagDigest,
    pub maximum_gas: u64,
    pub maximum_bytes: u64,
    pub item_indices: Vec<u32>,
    pub protected_gas: u64,
    pub protected_bytes: u64,
}

/// Canonical parent-state eligibility, supplied by the native execution owner.
/// Both methods must use verified parent state and governed execution time;
/// worker completion, wall-clock time and local cache contents are not inputs.
/// `selected` runs only after dependency and capacity checks, so virtual nonce
/// advancement cannot be caused by an item that will not execute.
pub trait ProcessingSelectionPolicy {
    fn eligible(&self, index: usize, item: &ProcessingReadyItem) -> Result<bool, EtdagError>;
    fn selected(&mut self, index: usize, item: &ProcessingReadyItem) -> Result<(), EtdagError>;
}

struct AllReady;
impl ProcessingSelectionPolicy for AllReady {
    fn eligible(&self, _: usize, _: &ProcessingReadyItem) -> Result<bool, EtdagError> {
        Ok(true)
    }
    fn selected(&mut self, _: usize, _: &ProcessingReadyItem) -> Result<(), EtdagError> {
        Ok(())
    }
}

impl ProcessingReadyView {
    pub fn validate(&self) -> Result<(), EtdagError> {
        nonzero(&self.namespace_root)?;
        if self.items.len() > MAX_READY_ITEMS {
            return Err(EtdagError::InvalidCapacity);
        }
        let mut positions = BTreeMap::new();
        let mut group_roots = BTreeMap::new();
        let mut group_numbers = BTreeMap::new();
        let mut previous = None;
        for (index, item) in self.items.iter().enumerate() {
            for root in [
                &item.group_root,
                &item.envelope_id,
                &item.payload_root,
                &item.readiness_root,
            ] {
                nonzero(root)?;
            }
            let order = (item.group_number, item.order_position);
            if item.group_number == 0
                || item.gas_class_units == 0
                || item.encoded_bytes == 0
                || item.remaining_dependencies.len() > MAX_DEPENDENCIES_PER_ITEM
                || previous.is_some_and(|value| value >= order)
            {
                return Err(EtdagError::InvalidExecutionInput);
            }
            previous = Some(order);
            if positions.insert(&item.envelope_id, index).is_some() {
                return Err(EtdagError::DuplicateEnvelope);
            }
            if group_roots
                .insert(item.group_number, &item.group_root)
                .is_some_and(|root| root != &item.group_root)
                || group_numbers
                    .insert(&item.group_root, item.group_number)
                    .is_some_and(|number| number != item.group_number)
            {
                return Err(EtdagError::ContextMismatch);
            }
        }
        for (index, item) in self.items.iter().enumerate() {
            let mut previous_dependency = None;
            for dependency in &item.remaining_dependencies {
                nonzero(dependency)?;
                if previous_dependency.is_some_and(|previous| previous >= dependency)
                    || positions
                        .get(dependency)
                        .is_some_and(|position| *position >= index)
                {
                    return Err(EtdagError::InvalidExecutionInput);
                }
                previous_dependency = Some(dependency);
            }
        }
        Ok(())
    }

    pub fn root(&self) -> Result<EtdagDigest, EtdagError> {
        self.validate()?;
        EtdagDigest::from_canonical("SYNERGY_ETDAG_PROCESSING_READY_VIEW_V1", self)
    }

    /// Mandatory capacity prefix after excluding items with unresolved
    /// dependencies. Independent ready work may pass an unfinished group.
    /// A newly published ready item is considered by a descendant using its
    /// parent view, never inserted into this selection from a local worker.
    pub fn select(
        &self,
        maximum_gas: u64,
        maximum_bytes: u64,
    ) -> Result<ProcessingSelection, EtdagError> {
        self.select_with_policy(maximum_gas, maximum_bytes, &mut AllReady)
    }

    /// The native owner supplies current identity/nonce eligibility. An
    /// ineligible item blocks its certified group prefix and dependants, while
    /// independent groups can proceed. The commitment still covers the FULL
    /// parent view, including deferred items; filtering cannot change its root.
    pub fn select_with_policy(
        &self,
        maximum_gas: u64,
        maximum_bytes: u64,
        policy: &mut impl ProcessingSelectionPolicy,
    ) -> Result<ProcessingSelection, EtdagError> {
        let parent_ready_root = self.root()?;
        if maximum_gas == 0 || maximum_bytes == 0 {
            return Err(EtdagError::InvalidCapacity);
        }
        // An item that can never fit is invalid publication, not a permanent
        // head-of-line stall. Publication verification must enforce this too.
        if self
            .items
            .iter()
            .any(|item| item.gas_class_units > maximum_gas || item.encoded_bytes > maximum_bytes)
        {
            return Err(EtdagError::InvalidCapacity);
        }
        let mut selection = ProcessingSelection {
            parent_ready_root,
            maximum_gas,
            maximum_bytes,
            item_indices: Vec::new(),
            protected_gas: 0,
            protected_bytes: 0,
        };
        let mut selected = BTreeSet::new();
        // Preserve the certified per-group prefix even if metadata from a
        // malformed publication omitted an explicit predecessor dependency.
        let mut blocked_groups = BTreeSet::new();
        for (index, item) in self.items.iter().enumerate() {
            if blocked_groups.contains(&item.group_number)
                || item
                    .remaining_dependencies
                    .iter()
                    .any(|dependency| !selected.contains(dependency))
                || !policy.eligible(index, item)?
            {
                blocked_groups.insert(item.group_number);
                continue;
            }
            let gas = selection.protected_gas.checked_add(item.gas_class_units);
            let bytes = selection.protected_bytes.checked_add(item.encoded_bytes);
            let (Some(gas), Some(bytes)) = (gas, bytes) else {
                break;
            };
            if gas > maximum_gas || bytes > maximum_bytes {
                break;
            }
            selection.item_indices.push(index as u32);
            selection.protected_gas = gas;
            selection.protected_bytes = bytes;
            policy.selected(index, item)?;
            selected.insert(&item.envelope_id);
        }
        Ok(selection)
    }

    /// Recompute the mandatory selection; a proposer cannot omit an eligible
    /// item, reorder it, forge totals or supply another branch's ready root.
    pub fn verify_selection(
        &self,
        selection: &ProcessingSelection,
        maximum_gas: u64,
        maximum_bytes: u64,
    ) -> Result<(), EtdagError> {
        if self.select(maximum_gas, maximum_bytes)? != *selection {
            return Err(EtdagError::InvalidExecutionInput);
        }
        Ok(())
    }
}

fn nonzero(root: &EtdagDigest) -> Result<(), EtdagError> {
    root.validate()?;
    if root.is_zero() {
        return Err(EtdagError::InvalidDigest);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn root(label: &str) -> EtdagDigest {
        EtdagDigest::from_domain_bytes("processing-selection-fixture", label.as_bytes())
    }
    fn item(group: u64, position: u32) -> ProcessingReadyItem {
        ProcessingReadyItem {
            group_number: group,
            group_root: root(&format!("group-{group}")),
            order_position: position,
            envelope_id: root(&format!("envelope-{group}-{position}")),
            payload_root: root("payload"),
            readiness_root: root("readiness"),
            gas_class_units: 21_000,
            encoded_bytes: 1024,
            remaining_dependencies: vec![],
        }
    }
    fn view(items: Vec<ProcessingReadyItem>) -> ProcessingReadyView {
        ProcessingReadyView {
            namespace_root: root("fresh-governed-scope"),
            items,
        }
    }

    #[test]
    fn no_ready_work_allows_empty_selection_without_a_height_deadline() {
        let view = view(vec![]);
        let selected = view.select(30_000_000, 8 * 1024 * 1024).unwrap();
        assert!(selected.item_indices.is_empty());
        assert_eq!((selected.protected_gas, selected.protected_bytes), (0, 0));
        assert_eq!(serde_json::to_value(selected).unwrap().get("height"), None);
    }

    #[test]
    fn pending_dependencies_block_only_their_group_and_dependants() {
        let mut blocked = item(1, 0);
        blocked.remaining_dependencies = vec![root("still-processing")];
        let same_group = item(1, 1);
        let independent = item(2, 0);
        let mut dependent = item(3, 0);
        dependent.remaining_dependencies = vec![blocked.envelope_id.clone()];
        let view = view(vec![blocked, same_group, independent, dependent]);
        assert_eq!(view.select(100_000, 4096).unwrap().item_indices, vec![2]);
    }

    #[test]
    fn canonical_dependency_closed_capacity_prefix_cannot_be_skipped() {
        let first = item(1, 0);
        let mut second = item(2, 0);
        second.remaining_dependencies = vec![first.envelope_id.clone()];
        let view = view(vec![first, second, item(3, 0)]);
        let selected = view.select(42_000, 4096).unwrap();
        assert_eq!(selected.item_indices, vec![0, 1]);
        assert_eq!(
            (selected.protected_gas, selected.protected_bytes),
            (42_000, 2048)
        );
        view.verify_selection(&selected, 42_000, 4096).unwrap();
        let mut omitted = selected.clone();
        omitted.item_indices.remove(0);
        assert!(view.verify_selection(&omitted, 42_000, 4096).is_err());
        let mut wrong_scope = view.clone();
        wrong_scope.namespace_root = root("another-branch-scope");
        assert!(wrong_scope
            .verify_selection(&selected, 42_000, 4096)
            .is_err());
        assert!(view.verify_selection(&selected, 100_000, 4096).is_err());
    }

    #[test]
    fn malformed_order_duplicates_cycles_and_unbounded_entries_fail_closed() {
        let first = item(1, 0);
        assert!(view(vec![first.clone(), first.clone()]).validate().is_err());
        assert!(view(vec![item(2, 0), first.clone()]).validate().is_err());
        let mut self_dependency = first.clone();
        self_dependency.remaining_dependencies = vec![first.envelope_id.clone()];
        assert!(view(vec![self_dependency]).validate().is_err());
        let mut cycle = first.clone();
        cycle.remaining_dependencies = vec![item(2, 0).envelope_id];
        assert!(view(vec![cycle, item(2, 0)]).validate().is_err());
        assert!(view(vec![first.clone()]).select(20_999, 4096).is_err());
        let mut duplicate_group = item(2, 0);
        duplicate_group.group_root = first.group_root.clone();
        assert!(view(vec![first.clone(), duplicate_group])
            .validate()
            .is_err());
        assert!(view(vec![first; MAX_READY_ITEMS + 1]).validate().is_err());
    }

    #[test]
    fn local_new_completion_cannot_change_an_existing_parent_selection() {
        let parent = view(vec![item(1, 0)]);
        let selected = parent.select(100_000, 4096).unwrap();
        let mut local_completion = parent.clone();
        local_completion.items.push(item(2, 0));
        assert!(local_completion
            .verify_selection(&selected, 100_000, 4096)
            .is_err());
        parent.verify_selection(&selected, 100_000, 4096).unwrap();
    }
}
