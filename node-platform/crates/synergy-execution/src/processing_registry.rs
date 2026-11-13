//! Processing-ready metadata in the ordinary PoSy candidate World.
//!
//! Payloads and proofs are immutable, separately durable objects. This module
//! stores only references and emits per-entry World diffs, so publishing one
//! completion does not rewrite other payloads. It creates no admission, reveal,
//! availability, quorum or finality authority. The native owner must implement
//! `ProcessingReadinessVerifier` before this can be used by a governed profile.
//! Legacy exact-height execution does not call these APIs.
use std::collections::{BTreeMap, BTreeSet};
use std::ops::Bound;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use synergy_etdag::execution::{
    ProcessingProposalMaterial, ProcessingReadyItem, ProcessingReadyView, ProcessingSelection,
    ProcessingSelectionPolicy,
};
use synergy_etdag::{EtdagDigest, EtdagError};
use synergy_state::world_resources::{
    WorldResourceBudget, WorldResourceError, WorldResourcePermit,
};
use synergy_state::{ProtocolChange, StateDiff, WorldState};

const META_KEY: &str = "etdag-processing-ready-v1/meta";
const ITEM_PREFIX: &str = "etdag-processing-ready-v1/item/";
const MAX_READY_RECORDS: usize = 4096;
const MAX_RECORD_BYTES: usize = 16 * 1024;
const MAX_SENDER_BYTES: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessingReadyRecord {
    pub item: ProcessingReadyItem,
    pub processing_context_root: EtdagDigest,
    pub authorization_root: EtdagDigest,
    pub sender_wallet: String,
    pub sender_nonce: u64,
}

impl ProcessingReadyRecord {
    fn validate(&self) -> Result<(), ProcessingRegistryError> {
        for root in [&self.processing_context_root, &self.authorization_root] {
            root.validate()?;
            if root.is_zero() {
                return Err(EtdagError::InvalidDigest.into());
            }
        }
        if self.sender_wallet.is_empty()
            || self.sender_wallet.len() > MAX_SENDER_BYTES
            || self.sender_wallet.contains(char::is_control)
            || self.sender_nonce == u64::MAX
        {
            return Err(EtdagError::InvalidExecutionInput.into());
        }
        // Fixed field/string/dependency bounds precede serialization. The
        // aggregate view additionally checks ordering, duplicates and cycles.
        if self.item.remaining_dependencies.len() > 64 {
            return Err(EtdagError::InvalidCapacity.into());
        }
        for root in self.item.remaining_dependencies.iter().chain([
            &self.item.group_root,
            &self.item.envelope_id,
            &self.item.payload_root,
            &self.item.readiness_root,
        ]) {
            root.validate()?;
            if root.is_zero() {
                return Err(EtdagError::InvalidDigest.into());
            }
        }
        Ok(())
    }
}

/// Native authenticated boundary, NOT a new certificate or a local-ready flag.
/// Publication must verify the original signed processing request, committed
/// order and authorized reveal against PoSy ancestry, exact metadata/payload
/// bindings, and durable availability of every referenced object before return.
/// Identity eligibility uses the actual canonical parent and governed inclusion
/// time. A storage/verification failure is Err, never identity=false.
pub trait ProcessingReadinessVerifier {
    /// Native group state supplies the first unconsumed certified position.
    /// Isolated ready-registry fixtures may omit a group lifecycle entirely.
    fn first_unconsumed_position(
        &self,
        _: &ProcessingReadyRecord,
        _: &WorldState,
    ) -> Result<Option<u32>, String> {
        Ok(None)
    }

    /// Authenticate original encrypted DAG members and their durable
    /// availability. The default rejects all order publication; legacy/test
    /// readiness implementations cannot silently activate ordering authority.
    fn verify_ordered_group(
        &self,
        _: &synergy_etdag::execution::ProcessingOrderGroup,
        _: &WorldState,
    ) -> Result<(), String> {
        Err("native processing ordering verifier is absent".into())
    }
    fn verify_publication(
        &self,
        record: &ProcessingReadyRecord,
        parent: &WorldState,
    ) -> Result<(), String>;

    fn identity_is_current(
        &self,
        record: &ProcessingReadyRecord,
        parent: &WorldState,
    ) -> Result<bool, String>;
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RegistryMetadata {
    namespace_root: EtdagDigest,
    generation: u64,
    count: usize,
}

pub(crate) fn propose_empty_epoch_metadata(
    parent: &WorldState,
    previous: &EtdagDigest,
    next: &EtdagDigest,
    budget: &Arc<WorldResourceBudget>,
) -> Result<ProtocolChange, ProcessingRegistryError> {
    let registry = ParentProcessingRegistry::read(parent, previous, budget)?;
    if !registry.records().is_empty()
        || parent
            .protocol
            .range::<str, _>((
                Bound::Included("etdag-processing-ready-v1/"),
                Bound::Unbounded,
            ))
            .take_while(|(key, _)| key.starts_with("etdag-processing-ready-v1/"))
            .any(|(key, _)| key != META_KEY)
    {
        return Err(ProcessingRegistryError::Corrupt(
            "epoch proposal cannot retire outstanding processing-ready entries".into(),
        ));
    }
    Ok(ProtocolChange {
        key: META_KEY.into(),
        expected_value: parent.protocol.get(META_KEY).cloned(),
        value: Some(
            serde_json::to_vec(&RegistryMetadata {
                namespace_root: next.clone(),
                generation: 0,
                count: 0,
            })
            .map_err(|e| ProcessingRegistryError::Corrupt(e.to_string()))?,
        ),
    })
}

#[derive(Debug)]
pub enum ProcessingRegistryError {
    Resource(WorldResourceError),
    Invalid(EtdagError),
    Corrupt(String),
    Verification(String),
}
impl From<WorldResourceError> for ProcessingRegistryError {
    fn from(value: WorldResourceError) -> Self {
        Self::Resource(value)
    }
}
impl From<EtdagError> for ProcessingRegistryError {
    fn from(value: EtdagError) -> Self {
        Self::Invalid(value)
    }
}
impl std::fmt::Display for ProcessingRegistryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for ProcessingRegistryError {}

/// A borrowed, charged view of exactly one canonical parent. Local worker
/// queues cannot insert entries in this view. Its lifetime includes selection
/// and transition construction, including all temporary indexes and encoding.
pub struct ParentProcessingRegistry<'a> {
    parent: &'a WorldState,
    metadata: RegistryMetadata,
    records: Vec<ProcessingReadyRecord>,
    encoded_bytes: usize,
    view: ProcessingReadyView,
    budget: Arc<WorldResourceBudget>,
    _permit: WorldResourcePermit,
}

/// Constructed exclusively by selection on a borrowed parent registry. There
/// is no public constructor, mutation or deserialization for a claimed result.
pub struct ParentProcessingSelection<'a, 'world> {
    registry: &'a ParentProcessingRegistry<'world>,
    selection: ProcessingSelection,
    _permit: WorldResourcePermit,
}
impl ParentProcessingSelection<'_, '_> {
    pub fn selection(&self) -> &ProcessingSelection {
        &self.selection
    }

    pub fn records(&self) -> impl Iterator<Item = &ProcessingReadyRecord> {
        self.selection
            .item_indices
            .iter()
            .map(|index| &self.registry.records[*index as usize])
    }

    /// Binds the verified parent selection to the exact candidate registry
    /// delta. This material is carried by the existing candidate protected root;
    /// native validation must still verify publications and execution replay.
    pub fn proposal_material(
        &self,
        height: u64,
        transition: &ProcessingRegistryTransition,
    ) -> Result<ProcessingProposalMaterial, ProcessingRegistryError> {
        let selection_root =
            EtdagDigest::from_canonical("SYNERGY_POSY_PROCESSING_SELECTION_V1", &self.selection)?;
        if selection_root != transition.selection_root
            || self.registry.metadata.namespace_root != transition.namespace_root
        {
            return Err(EtdagError::ContextMismatch.into());
        }
        let material = ProcessingProposalMaterial {
            material_version: 1,
            profile_id: synergy_etdag::PROCESSING_PROFILE_ID.into(),
            height,
            namespace_root: transition.namespace_root.clone(),
            selection: self.selection.clone(),
            transition_root: EtdagDigest::from_canonical(
                "SYNERGY_POSY_PROCESSING_REGISTRY_TRANSITION_V1",
                &transition.diff,
            )?,
            ordered_group: None,
        };
        material.validate()?;
        Ok(material)
    }

    /// Consume only work selected from the OLD parent, then publish verified
    /// completions for descendants. Newly published work cannot execute in the
    /// same candidate. Apply this diff in the same candidate transition as the
    /// selected transaction effects; do not apply it to another parent/branch.
    /// Physical payload retirement is authorized only by durable PoSy finality,
    /// not by this speculative deletion from a candidate World.
    pub fn transition(
        &self,
        publications: &[ProcessingReadyRecord],
        verifier: &impl ProcessingReadinessVerifier,
        maximum_gas: u64,
        maximum_bytes: u64,
    ) -> Result<ProcessingRegistryTransition, ProcessingRegistryError> {
        let registry = self.registry;
        if maximum_gas != self.selection.maximum_gas
            || maximum_bytes != self.selection.maximum_bytes
            || publications.len() > MAX_READY_RECORDS
        {
            return Err(EtdagError::InvalidCapacity.into());
        }
        for record in publications {
            record.validate()?;
        }
        if self.selection.item_indices.is_empty() && publications.is_empty() {
            let permit = registry.budget.reserve(2048)?;
            return Ok(ProcessingRegistryTransition {
                diff: StateDiff::default(),
                namespace_root: registry.metadata.namespace_root.clone(),
                selection_root: EtdagDigest::from_canonical(
                    "SYNERGY_POSY_PROCESSING_SELECTION_V1",
                    &self.selection,
                )?,
                _permit: permit,
            });
        }
        let next_count = registry.records.len() - self.selection.item_indices.len();
        if next_count
            .checked_add(publications.len())
            .is_none_or(|n| n > MAX_READY_RECORDS)
        {
            return Err(EtdagError::InvalidCapacity.into());
        }
        // Covers old/new record graphs, serialization buffers, diffs, sparse
        // BTree indexes and checked-capacity vector growth before any allocation.
        let charge = registry_charge(
            registry
                .records
                .len()
                .checked_add(publications.len())
                .ok_or(WorldResourceError::ArithmeticOverflow)?,
            registry
                .encoded_bytes
                .checked_add(publications.iter().try_fold(0usize, |total, record| {
                    total
                        .checked_add(record_encoded_bound(record))
                        .ok_or(WorldResourceError::ArithmeticOverflow)
                })?)
                .ok_or(WorldResourceError::ArithmeticOverflow)?,
        )?;
        let permit = registry.budget.reserve(charge)?;
        let consumed: BTreeSet<_> = self
            .records()
            .map(|record| &record.item.envelope_id)
            .collect();
        let mut records = Vec::new();
        for record in &registry.records {
            if consumed.contains(&record.item.envelope_id) {
                continue;
            }
            let mut remaining = record.clone();
            remaining
                .item
                .remaining_dependencies
                .retain(|id| !consumed.contains(id));
            records.push(remaining);
        }
        for record in publications {
            // No replacement/downgrade of an existing ready entry and no
            // republishing an item consumed by this very candidate.
            if registry.records.iter().any(|old| {
                old.item.envelope_id == record.item.envelope_id
                    || (old.sender_wallet == record.sender_wallet
                        && old.sender_nonce == record.sender_nonce)
            }) {
                return Err(EtdagError::DuplicateEnvelope.into());
            }
            verifier
                .verify_publication(record, registry.parent)
                .map_err(ProcessingRegistryError::Verification)?;
            // Already-spent authorizations cannot create permanent records.
            let nonce = registry
                .parent
                .accounts
                .get(&record.sender_wallet)
                .map_or(0, |account| account.nonce);
            if record.sender_nonce < nonce {
                return Err(EtdagError::Replay(record.item.envelope_id.0.clone()).into());
            }
            records.push(record.clone());
        }
        validate_records(&registry.metadata.namespace_root, &mut records)?;
        let view = ready_view(&registry.metadata.namespace_root, &records);
        // Reject an individually impossible publication now, instead of
        // permanently blocking subsequent block selection.
        if view
            .items
            .iter()
            .any(|item| item.gas_class_units > maximum_gas || item.encoded_bytes > maximum_bytes)
        {
            return Err(EtdagError::InvalidCapacity.into());
        }
        let mut changes = Vec::new();
        for old in &registry.records {
            let next = records
                .iter()
                .find(|next| next.item.envelope_id == old.item.envelope_id);
            if next == Some(old) {
                continue;
            }
            let key = item_key(&old.item.envelope_id);
            changes.push(ProtocolChange {
                expected_value: registry.parent.protocol.get(&key).cloned(),
                key,
                value: next.map(encode_record).transpose()?,
            });
        }
        for record in &records {
            if !registry
                .records
                .iter()
                .any(|old| old.item.envelope_id == record.item.envelope_id)
            {
                changes.push(ProtocolChange {
                    key: item_key(&record.item.envelope_id),
                    expected_value: None,
                    value: Some(encode_record(record)?),
                });
            }
        }
        // An unchanged empty block produces NO registry writes. The fixed-size
        // generation marker guards conflicting/stale transitions without a
        // growing set of consumed-envelope tombstones.
        if !changes.is_empty() {
            let metadata = RegistryMetadata {
                namespace_root: registry.metadata.namespace_root.clone(),
                generation: registry
                    .metadata
                    .generation
                    .checked_add(1)
                    .ok_or(WorldResourceError::ArithmeticOverflow)?,
                count: records.len(),
            };
            changes.push(ProtocolChange {
                key: META_KEY.into(),
                expected_value: registry.parent.protocol.get(META_KEY).cloned(),
                value: Some(
                    serde_json::to_vec(&metadata)
                        .map_err(|e| ProcessingRegistryError::Corrupt(e.to_string()))?,
                ),
            });
        }
        Ok(ProcessingRegistryTransition {
            diff: StateDiff {
                changes: vec![],
                protocol_changes: changes,
            },
            namespace_root: registry.metadata.namespace_root.clone(),
            selection_root: EtdagDigest::from_canonical(
                "SYNERGY_POSY_PROCESSING_SELECTION_V1",
                &self.selection,
            )?,
            _permit: permit,
        })
    }
}

/// Keep the reservation alive until the native owner has applied the World
/// diff. Do not clone this diff into an uncharged queue.
pub struct ProcessingRegistryTransition {
    diff: StateDiff,
    namespace_root: EtdagDigest,
    selection_root: EtdagDigest,
    _permit: WorldResourcePermit,
}
impl ProcessingRegistryTransition {
    pub fn diff(&self) -> &StateDiff {
        &self.diff
    }
}

impl<'a> ParentProcessingRegistry<'a> {
    pub fn records(&self) -> &[ProcessingReadyRecord] {
        &self.records
    }
    pub fn view(&self) -> &ProcessingReadyView {
        &self.view
    }
    pub fn read(
        parent: &'a WorldState,
        namespace_root: &EtdagDigest,
        budget: &Arc<WorldResourceBudget>,
    ) -> Result<Self, ProcessingRegistryError> {
        namespace_root.validate()?;
        if namespace_root.is_zero() {
            return Err(EtdagError::InvalidDigest.into());
        }
        let metadata_bytes = parent.protocol.get(META_KEY);
        if metadata_bytes.is_some_and(|bytes| bytes.len() > MAX_RECORD_BYTES) {
            return Err(EtdagError::InvalidCapacity.into());
        }
        // Count/size-only walk before allocating or decoding any records.
        let mut count = 0usize;
        let mut encoded_bytes = 0usize;
        for (key, bytes) in parent
            .protocol
            .range::<str, _>((Bound::Included(ITEM_PREFIX), Bound::Unbounded))
            .take_while(|(key, _)| key.starts_with(ITEM_PREFIX))
        {
            count += 1;
            if count > MAX_READY_RECORDS
                || key.len() != ITEM_PREFIX.len() + 128
                || bytes.len() > MAX_RECORD_BYTES
            {
                return Err(EtdagError::InvalidCapacity.into());
            }
            encoded_bytes = encoded_bytes
                .checked_add(bytes.len())
                .ok_or(WorldResourceError::ArithmeticOverflow)?;
        }
        let permit = budget.reserve(registry_charge(count, encoded_bytes)?)?;
        let metadata: RegistryMetadata = metadata_bytes
            .map(|bytes| serde_json::from_slice(bytes))
            .transpose()
            .map_err(|e| ProcessingRegistryError::Corrupt(e.to_string()))?
            .unwrap_or_else(|| RegistryMetadata {
                namespace_root: namespace_root.clone(),
                generation: 0,
                count: 0,
            });
        if &metadata.namespace_root != namespace_root
            || metadata.count != count
            || (count != 0 && metadata_bytes.is_none())
            || (count != 0 && metadata.generation == 0)
        {
            return Err(EtdagError::ContextMismatch.into());
        }
        let mut records = Vec::with_capacity(count);
        for (key, bytes) in parent
            .protocol
            .range::<str, _>((Bound::Included(ITEM_PREFIX), Bound::Unbounded))
            .take_while(|(key, _)| key.starts_with(ITEM_PREFIX))
        {
            let record: ProcessingReadyRecord = serde_json::from_slice(bytes)
                .map_err(|e| ProcessingRegistryError::Corrupt(e.to_string()))?;
            record.validate()?;
            if *key != item_key(&record.item.envelope_id) {
                return Err(EtdagError::ContextMismatch.into());
            }
            records.push(record);
        }
        validate_records(namespace_root, &mut records)?;
        let view = ready_view(namespace_root, &records);
        Ok(Self {
            parent,
            metadata,
            records,
            encoded_bytes,
            view,
            budget: Arc::clone(budget),
            _permit: permit,
        })
    }

    pub fn select<'registry>(
        &'registry self,
        verifier: &impl ProcessingReadinessVerifier,
        maximum_gas: u64,
        maximum_bytes: u64,
    ) -> Result<ParentProcessingSelection<'registry, 'a>, ProcessingRegistryError> {
        // Includes the bounded virtual-nonce index and selection allocation.
        let permit = self.budget.reserve(
            self.records
                .len()
                .checked_mul(2048)
                .and_then(|n| n.checked_add(16 * 1024))
                .ok_or(WorldResourceError::ArithmeticOverflow)?,
        )?;
        let mut policy = ParentEligibility {
            registry: self,
            verifier,
            nonces: BTreeMap::new(),
            group_selected: BTreeMap::new(),
        };
        let selection = self
            .view
            .select_with_policy(maximum_gas, maximum_bytes, &mut policy)?;
        Ok(ParentProcessingSelection {
            registry: self,
            selection,
            _permit: permit,
        })
    }
}

struct ParentEligibility<'a, 'world, V> {
    registry: &'a ParentProcessingRegistry<'world>,
    verifier: &'a V,
    nonces: BTreeMap<&'a str, u64>,
    group_selected: BTreeMap<u64, u32>,
}
impl<V: ProcessingReadinessVerifier> ProcessingSelectionPolicy for ParentEligibility<'_, '_, V> {
    fn eligible(&self, index: usize, _: &ProcessingReadyItem) -> Result<bool, EtdagError> {
        let record = &self.registry.records[index];
        if let Some(first) = self
            .verifier
            .first_unconsumed_position(record, self.registry.parent)
            .map_err(EtdagError::Governance)?
        {
            if first.checked_add(
                self.group_selected
                    .get(&record.item.group_number)
                    .copied()
                    .unwrap_or(0),
            ) != Some(record.item.order_position)
            {
                return Ok(false);
            }
        }
        let current = self
            .nonces
            .get(record.sender_wallet.as_str())
            .copied()
            .unwrap_or_else(|| {
                self.registry
                    .parent
                    .accounts
                    .get(&record.sender_wallet)
                    .map_or(0, |a| a.nonce)
            });
        Ok(record.sender_nonce <= current
            && self
                .verifier
                .identity_is_current(record, self.registry.parent)
                .map_err(EtdagError::Governance)?)
    }

    fn selected(&mut self, index: usize, _: &ProcessingReadyItem) -> Result<(), EtdagError> {
        let record = &self.registry.records[index];
        let selected = self
            .group_selected
            .entry(record.item.group_number)
            .or_default();
        *selected = selected.checked_add(1).ok_or(EtdagError::InvalidCapacity)?;
        let nonce = self.nonces.entry(&record.sender_wallet).or_insert_with(|| {
            self.registry
                .parent
                .accounts
                .get(&record.sender_wallet)
                .map_or(0, |a| a.nonce)
        });
        // A stale signed request is selected for a deterministic zero-effect
        // rejection/retirement; it must never increment the current nonce.
        if record.sender_nonce == *nonce {
            *nonce = nonce
                .checked_add(1)
                .ok_or(EtdagError::InvalidExecutionInput)?;
        }
        Ok(())
    }
}

fn ready_view(namespace: &EtdagDigest, records: &[ProcessingReadyRecord]) -> ProcessingReadyView {
    ProcessingReadyView {
        namespace_root: namespace.clone(),
        items: records.iter().map(|record| record.item.clone()).collect(),
    }
}
fn validate_records(
    namespace: &EtdagDigest,
    records: &mut [ProcessingReadyRecord],
) -> Result<(), ProcessingRegistryError> {
    if records.len() > MAX_READY_RECORDS {
        return Err(EtdagError::InvalidCapacity.into());
    }
    records.sort_by_key(|r| (r.item.group_number, r.item.order_position));
    let mut claims = BTreeSet::new();
    for record in records.iter() {
        record.validate()?;
        if !claims.insert((&record.sender_wallet, record.sender_nonce)) {
            return Err(EtdagError::DuplicateEnvelope.into());
        }
    }
    ready_view(namespace, records).validate()?;
    Ok(())
}
fn registry_charge(count: usize, encoded_bytes: usize) -> Result<usize, WorldResourceError> {
    // Each record's bounded encoded size covers both cloned metadata graphs,
    // serde scratch, hash encoding and sparse indexing, with fixed overhead.
    encoded_bytes
        .checked_mul(8)
        .and_then(|n| {
            count
                .checked_mul(4096)
                .and_then(|overhead| n.checked_add(overhead))
        })
        .and_then(|n| n.checked_add(16 * 1024))
        .ok_or(WorldResourceError::ArithmeticOverflow)
}
fn record_encoded_bound(record: &ProcessingReadyRecord) -> usize {
    // Validated digests are 128-character hex; integers have fixed bounds.
    // Six bytes per sender byte covers all possible JSON string escaping.
    4096 + record.sender_wallet.len() * 6 + record.item.remaining_dependencies.len() * 132
}
fn item_key(envelope: &EtdagDigest) -> String {
    format!("{ITEM_PREFIX}{}", envelope.0)
}
fn encode_record(record: &ProcessingReadyRecord) -> Result<Vec<u8>, ProcessingRegistryError> {
    let bytes =
        serde_json::to_vec(record).map_err(|e| ProcessingRegistryError::Corrupt(e.to_string()))?;
    if bytes.len() > MAX_RECORD_BYTES {
        return Err(EtdagError::InvalidCapacity.into());
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use synergy_state::world_resources::BudgetedWorld;

    // These tests verify registry/state/resource contracts. This deliberately
    // limited fixture is NOT cryptographic readiness or a running PoSy profile.
    struct FixtureVerifier;
    impl ProcessingReadinessVerifier for FixtureVerifier {
        fn verify_publication(
            &self,
            record: &ProcessingReadyRecord,
            _: &WorldState,
        ) -> Result<(), String> {
            if record.authorization_root == digest("verified-fixture-authorization") {
                Ok(())
            } else {
                Err("unverified fixture publication".into())
            }
        }
        fn identity_is_current(
            &self,
            record: &ProcessingReadyRecord,
            _: &WorldState,
        ) -> Result<bool, String> {
            Ok(record.sender_wallet != "revoked")
        }
    }
    fn digest(value: &str) -> EtdagDigest {
        EtdagDigest::from_domain_bytes("processing-registry-fixture", value.as_bytes())
    }
    fn record(group: u64, nonce: u64, sender: &str) -> ProcessingReadyRecord {
        ProcessingReadyRecord {
            item: ProcessingReadyItem {
                group_number: group,
                group_root: digest(&format!("group-{group}")),
                order_position: 0,
                envelope_id: digest(&format!("{group}-{sender}-{nonce}")),
                payload_root: digest("separately-durable-payload"),
                readiness_root: digest("authenticated-readiness"),
                gas_class_units: 100,
                encoded_bytes: 100,
                remaining_dependencies: vec![],
            },
            processing_context_root: digest("original-frozen-authorization-context"),
            authorization_root: digest("verified-fixture-authorization"),
            sender_wallet: sender.into(),
            sender_nonce: nonce,
        }
    }
    fn publish(
        parent: &WorldState,
        records: &[ProcessingReadyRecord],
        budget: &Arc<WorldResourceBudget>,
    ) -> ProcessingRegistryTransition {
        let registry = ParentProcessingRegistry::read(parent, &digest("scope"), budget).unwrap();
        let selected = registry.select(&FixtureVerifier, 10_000, 10_000).unwrap();
        selected
            .transition(records, &FixtureVerifier, 10_000, 10_000)
            .unwrap()
    }

    #[test]
    fn processing_registry_publication_is_parent_derived_and_writes_only_changed_records() {
        let budget = WorldResourceBudget::new(16 * 1024 * 1024);
        let parent = WorldState::default();
        let first = record(1, 2, "alice"); // Future nonce: remains pending eligibility.
        let publication = publish(&parent, std::slice::from_ref(&first), &budget);
        assert_eq!(publication.diff.protocol_changes.len(), 2);
        assert!(parent.protocol.is_empty());
        let before = ParentProcessingRegistry::read(&parent, &digest("scope"), &budget).unwrap();
        assert!(before
            .select(&FixtureVerifier, 1000, 1000)
            .unwrap()
            .selection
            .item_indices
            .is_empty());
        let mut branch = parent.clone();
        publication.diff.apply(&mut branch).unwrap();
        assert!(ParentProcessingRegistry::read(&branch, &digest("wrong-scope"), &budget).is_err());
        let restored: WorldState =
            serde_json::from_slice(&serde_json::to_vec(&branch).unwrap()).unwrap();
        let registry =
            ParentProcessingRegistry::read(&restored, &digest("scope"), &budget).unwrap();
        let selection = registry.select(&FixtureVerifier, 1000, 1000).unwrap();
        assert!(selection.records().next().is_none());
        let unchanged = selection
            .transition(&[], &FixtureVerifier, 1000, 1000)
            .unwrap();
        assert!(unchanged.diff.protocol_changes.is_empty());
        let second = record(2, 1, "bob");
        let append = selection
            .transition(&[second], &FixtureVerifier, 1000, 1000)
            .unwrap();
        assert_eq!(append.diff.protocol_changes.len(), 2);
        assert!(append
            .diff
            .protocol_changes
            .iter()
            .all(|change| change.key != item_key(&first.item.envelope_id)));
        append.diff.apply(&mut branch).unwrap();
        let original = branch.clone();
        assert!(append.diff.apply(&mut branch).is_err()); // Generation/precondition conflict.
        assert_eq!(branch, original);
    }

    #[test]
    fn processing_registry_selection_advances_only_selected_nonces_and_skips_blocked_groups() {
        let budget = WorldResourceBudget::new(16 * 1024 * 1024);
        let parent = WorldState::default();
        let mut dependent = record(1, 0, "alice");
        dependent.item.remaining_dependencies = vec![digest("unfinished-work")];
        let records = [
            dependent,
            record(2, 1, "alice"), // Must NOT be enabled by the blocked nonce 0.
            record(3, 0, "bob"),
            record(4, 1, "bob"), // Virtual advancement by selected nonce 0.
            record(5, 0, "revoked"),
        ];
        let publication = publish(&parent, &records, &budget);
        let mut branch = parent.clone();
        publication.diff.apply(&mut branch).unwrap();
        let registry = ParentProcessingRegistry::read(&branch, &digest("scope"), &budget).unwrap();
        let selected = registry.select(&FixtureVerifier, 1000, 1000).unwrap();
        assert_eq!(selected.selection.item_indices, vec![2, 3]);
        assert_eq!(
            selected
                .records()
                .map(|r| r.sender_nonce)
                .collect::<Vec<_>>(),
            vec![0, 1]
        );
        let small = registry.select(&FixtureVerifier, 100, 1000).unwrap();
        assert_eq!(small.selection.item_indices, vec![2]);
        let transition = selected
            .transition(&[], &FixtureVerifier, 1000, 1000)
            .unwrap();
        assert_eq!(transition.diff.protocol_changes.len(), 3); // Two deletes + fixed metadata.
        let mut consumed = branch.clone();
        transition.diff.apply(&mut consumed).unwrap();
        assert_eq!(registry.records.len(), 5); // Speculative sibling is unchanged.
        let recovered =
            ParentProcessingRegistry::read(&consumed, &digest("scope"), &budget).unwrap();
        assert_eq!(recovered.records.len(), 3);
    }

    #[test]
    fn processing_registry_rejects_bad_publications_and_releases_all_failed_reservations() {
        let budget = WorldResourceBudget::new(2 * 1024 * 1024);
        let parent = WorldState::default();
        let registry = ParentProcessingRegistry::read(&parent, &digest("scope"), &budget).unwrap();
        let selected = registry.select(&FixtureVerifier, 1000, 1000).unwrap();
        let charged = budget.used();
        let first = record(1, 0, "alice");
        let mut duplicate = record(2, 0, "alice");
        assert!(selected
            .transition(
                &[first.clone(), duplicate.clone()],
                &FixtureVerifier,
                1000,
                1000
            )
            .is_err());
        duplicate.sender_nonce = 1;
        duplicate.authorization_root = digest("unverified");
        assert!(matches!(
            selected.transition(&[first.clone(), duplicate], &FixtureVerifier, 1000, 1000),
            Err(ProcessingRegistryError::Verification(_))
        ));
        assert_eq!(budget.used(), charged);
        let pressure = budget.reserve(budget.available()).unwrap();
        assert!(matches!(
            selected.transition(std::slice::from_ref(&first), &FixtureVerifier, 1000, 1000),
            Err(ProcessingRegistryError::Resource(
                WorldResourceError::Capacity { .. }
            ))
        ));
        assert!(parent.protocol.is_empty());
        drop(pressure);
        assert!(selected
            .transition(std::slice::from_ref(&first), &FixtureVerifier, 1000, 1000)
            .is_ok());
        assert_eq!(budget.used(), charged);
        drop(selected);
        drop(registry);
        assert_eq!(budget.used(), 0);
    }

    #[test]
    fn processing_registry_budgeted_world_application_is_atomic_and_survives_recovery() {
        let budget = WorldResourceBudget::new(4 * 1024 * 1024);
        let parent = WorldState::default();
        let transition = publish(&parent, &[record(1, 0, "alice")], &budget);
        let mut world = BudgetedWorld::try_clone_world(&parent, &budget).unwrap();
        let original = world.as_ref().clone();
        let charged = budget.used();
        let pressure = budget.reserve(budget.available()).unwrap();
        assert!(world.try_apply(transition.diff()).is_err());
        assert_eq!(world.as_ref(), &original);
        drop(pressure);
        assert_eq!(budget.used(), charged);
        world.try_apply(transition.diff()).unwrap();
        let registry =
            ParentProcessingRegistry::read(world.as_ref(), &digest("scope"), &budget).unwrap();
        let selected = registry.select(&FixtureVerifier, 1000, 1000).unwrap();
        assert_eq!(selected.selection.item_indices, vec![0]);
        let consume = selected
            .transition(&[], &FixtureVerifier, 1000, 1000)
            .unwrap();
        drop(selected);
        drop(registry);
        world.try_apply(consume.diff()).unwrap();
        assert_eq!(world.protocol.len(), 1); // Fixed-size marker, no consumed-ID tombstone.
        let empty =
            ParentProcessingRegistry::read(world.as_ref(), &digest("scope"), &budget).unwrap();
        assert!(empty
            .select(&FixtureVerifier, 1000, 1000)
            .unwrap()
            .selection
            .item_indices
            .is_empty());
    }

    #[test]
    fn processing_registry_recovery_rejects_oversize_or_mismatched_metadata_before_decode() {
        let budget = WorldResourceBudget::new(2 * 1024 * 1024);
        let mut parent = WorldState::default();
        parent
            .protocol
            .insert(item_key(&digest("oversize")), vec![0; MAX_RECORD_BYTES + 1]);
        assert!(matches!(
            ParentProcessingRegistry::read(&parent, &digest("scope"), &budget),
            Err(ProcessingRegistryError::Invalid(
                EtdagError::InvalidCapacity
            ))
        ));
        assert_eq!(budget.used(), 0);
        parent.protocol.clear();
        parent.protocol.insert(
            item_key(&digest("wrong-id")),
            encode_record(&record(1, 0, "alice")).unwrap(),
        );
        parent.protocol.insert(
            META_KEY.into(),
            serde_json::to_vec(&RegistryMetadata {
                namespace_root: digest("scope"),
                generation: 1,
                count: 1,
            })
            .unwrap(),
        );
        assert!(ParentProcessingRegistry::read(&parent, &digest("scope"), &budget).is_err());
        assert_eq!(budget.used(), 0);
    }

    #[test]
    fn processing_registry_maximum_count_is_charged_and_empty_progress_does_not_accumulate() {
        let budget = WorldResourceBudget::new(256 * 1024 * 1024);
        let mut parent = WorldState::default();
        for group in 1..=MAX_READY_RECORDS as u64 {
            let entry = record(group, 1, &format!("sender-{group}"));
            parent.protocol.insert(
                item_key(&entry.item.envelope_id),
                encode_record(&entry).unwrap(),
            );
        }
        parent.protocol.insert(
            META_KEY.into(),
            serde_json::to_vec(&RegistryMetadata {
                namespace_root: digest("scope"),
                generation: 1,
                count: MAX_READY_RECORDS,
            })
            .unwrap(),
        );
        let original_bytes: usize = parent.protocol.values().map(Vec::len).sum();
        let registry = ParentProcessingRegistry::read(&parent, &digest("scope"), &budget).unwrap();
        let charged = budget.used();
        assert!(charged > original_bytes);
        for _ in 0..16 {
            let selected = registry
                .select(&FixtureVerifier, 1_000_000, 1_000_000)
                .unwrap();
            assert!(selected.records().next().is_none()); // All are future nonces.
            let unchanged = selected
                .transition(&[], &FixtureVerifier, 1_000_000, 1_000_000)
                .unwrap();
            assert!(unchanged.diff.protocol_changes.is_empty());
        }
        assert_eq!(budget.used(), charged);
        assert_eq!(
            parent.protocol.values().map(Vec::len).sum::<usize>(),
            original_bytes
        );
        let selected = registry
            .select(&FixtureVerifier, 1_000_000, 1_000_000)
            .unwrap();
        assert!(matches!(
            selected.transition(
                &[record(MAX_READY_RECORDS as u64 + 1, 1, "extra")],
                &FixtureVerifier,
                1_000_000,
                1_000_000
            ),
            Err(ProcessingRegistryError::Invalid(
                EtdagError::InvalidCapacity
            ))
        ));
        drop(selected);
        drop(registry);
        assert_eq!(budget.used(), 0);
    }

    #[test]
    fn processing_registry_recovers_via_existing_candidate_world_delta_store() {
        use crate::{BudgetedCandidateStore, BudgetedExecutionCandidate};
        use std::sync::atomic::{AtomicU64, Ordering};
        use synergy_state::{state_root, AccountChange};
        static SEQUENCE: AtomicU64 = AtomicU64::new(0);
        let directory = std::env::temp_dir().join(format!(
            "processing-registry-candidate-{}-{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        let budget = WorldResourceBudget::new(16 * 1024 * 1024);
        let genesis = WorldState::default();
        let mut published = genesis.clone();
        let publication = publish(&genesis, &[record(1, 0, "alice")], &budget);
        publication.diff.apply(&mut published).unwrap();
        let empty_registry =
            ParentProcessingRegistry::read(&genesis, &digest("scope"), &budget).unwrap();
        let empty_selection = empty_registry
            .select(&FixtureVerifier, 10_000, 10_000)
            .unwrap();
        let first_material = empty_selection.proposal_material(1, &publication).unwrap();

        // Tests new candidate material and World metadata persistence, using
        // fixture readiness only. It does NOT prove activation or PoSy finality.
        let snapshot = |material: ProcessingProposalMaterial, parent: &str, state: &WorldState| {
            let mut candidate = BudgetedExecutionCandidate {
                resource_permit: Some(Arc::new(
                    crate::reserve_execution_metadata(std::iter::empty(), &budget).unwrap(),
                )),
                height: material.height,
                block_id: String::new(),
                parent_block_id: parent.into(),
                protected_execution_root: synergy_block::hash_block_bytes(
                    &material.commitment_bytes().unwrap(),
                ),
                protected_material: material.into(),
                state_root: state_root(state).unwrap(),
                transactions: vec![],
                receipts: vec![],
                state: Arc::new(BudgetedWorld::try_clone_world(state, &budget).unwrap()),
            };
            candidate.block_id = candidate.commitment_id().unwrap();
            candidate
        };
        let first = snapshot(first_material, "genesis", &published);
        let mut writer =
            BudgetedCandidateStore::new_budgeted(&directory, Arc::clone(&budget)).unwrap();
        writer.put_budgeted(&first, &genesis).unwrap();
        let registry = ParentProcessingRegistry::read(
            first.state.as_ref().as_ref(),
            &digest("scope"),
            &budget,
        )
        .unwrap();
        let selected = registry.select(&FixtureVerifier, 1000, 1000).unwrap();
        let consumption = selected
            .transition(&[], &FixtureVerifier, 1000, 1000)
            .unwrap();
        let nonce = StateDiff {
            changes: vec![AccountChange {
                account: "alice".into(),
                debit_nwei: 0,
                credit_nwei: 0,
                expected_nonce: Some(0),
                code_hash: None,
            }],
            protocol_changes: vec![],
        };
        let mut consumed = BudgetedWorld::try_clone_world(&published, &budget).unwrap();
        consumed
            .try_apply_ordered_atomic(&[&nonce, consumption.diff()])
            .unwrap();
        let second_material = selected.proposal_material(2, &consumption).unwrap();
        assert!(selected.proposal_material(2, &publication).is_err());
        let second = snapshot(second_material, &first.block_id, consumed.as_ref());
        writer.put_budgeted(&second, &published).unwrap();
        drop(writer);
        let reader = BudgetedCandidateStore::new_budgeted(&directory, Arc::clone(&budget)).unwrap();
        let recovered_first = reader.get_budgeted(1).unwrap().unwrap();
        assert_eq!(recovered_first.state.as_ref().as_ref(), &published);
        let recovered = reader.get_budgeted(2).unwrap().unwrap();
        assert_eq!(recovered.protected_material, second.protected_material);
        assert!(recovered.protected_material.as_legacy().is_none());
        assert_eq!(recovered.state.as_ref().as_ref(), consumed.as_ref());
        assert_eq!(recovered.state.accounts["alice"].nonce, 1);
        let ready = ParentProcessingRegistry::read(
            recovered.state.as_ref().as_ref(),
            &digest("scope"),
            &budget,
        )
        .unwrap();
        assert!(ready
            .select(&FixtureVerifier, 1000, 1000)
            .unwrap()
            .records()
            .next()
            .is_none());
        let original = ParentProcessingRegistry::read(
            recovered_first.state.as_ref().as_ref(),
            &digest("scope"),
            &budget,
        )
        .unwrap();
        assert_eq!(
            original
                .select(&FixtureVerifier, 1000, 1000)
                .unwrap()
                .records()
                .count(),
            1
        );
        std::fs::remove_dir_all(directory).unwrap();
    }
}
