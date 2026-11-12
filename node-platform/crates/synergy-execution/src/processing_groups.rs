//! Canonical processing group/nonce ownership in the ordinary candidate World.
//! No timer, leader, vote or finality authority lives here. A group is optional
//! candidate material; its successor closes before prior members can reveal.
use std::collections::BTreeMap;
use std::ops::Bound;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use synergy_etdag::execution::{
    processing_genesis_group_root, ProcessingGroupMember, ProcessingOrderGroup,
};
use synergy_etdag::EtdagDigest;
use synergy_state::world_resources::{WorldResourceBudget, WorldResourcePermit};
use synergy_state::{ProtocolChange, StateDiff, WorldState};

use crate::{ProcessingReadinessVerifier, ProcessingReadyRecord, ProcessingRegistryError};

const META: &str = "etdag-processing-groups-v1/meta";
const GROUP: &str = "etdag-processing-groups-v1/group/";
const CLAIM: &str = "etdag-processing-groups-v1/claim/";
const MAX_ITEMS: usize = 4096;
const MAX_CLAIM_BYTES: usize = 16 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Metadata {
    namespace_root: EtdagDigest,
    last_number: u64,
    last_root: EtdagDigest,
    groups: usize,
    claims: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessingGroupState {
    pub namespace_root: EtdagDigest,
    pub group_number: u64,
    pub group_root: EtdagDigest,
    pub remaining: usize,
    pub next_position: u32,
    /// Written only by the verified successor's ordinary candidate transition.
    /// It is reveal permission only once that candidate is PoSy-authenticated.
    pub closed_by_successor: Option<EtdagDigest>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessingMemberClaim {
    pub group_number: u64,
    pub group_root: EtdagDigest,
    pub order_position: u32,
    pub member: ProcessingGroupMember,
}

pub struct ProcessingGroupTransition {
    diff: StateDiff,
    _permit: WorldResourcePermit,
}
impl ProcessingGroupTransition {
    pub fn diff(&self) -> &StateDiff {
        &self.diff
    }
}
fn invalid(message: &str) -> ProcessingRegistryError {
    ProcessingRegistryError::Corrupt(message.into())
}
fn encode(value: &impl Serialize) -> Result<Vec<u8>, ProcessingRegistryError> {
    serde_json::to_vec(value).map_err(|e| ProcessingRegistryError::Corrupt(e.to_string()))
}
fn group_key(number: u64) -> String {
    format!("{GROUP}{number:020}")
}
fn claim_key(sender: &str, nonce: u64) -> Result<String, ProcessingRegistryError> {
    Ok(format!(
        "{CLAIM}{}",
        EtdagDigest::from_canonical("SYNERGY_ETDAG_PROCESSING_NONCE_CLAIM_V1", &(sender, nonce))?.0
    ))
}
fn decode<T: serde::de::DeserializeOwned>(
    bytes: &[u8],
    maximum: usize,
) -> Result<T, ProcessingRegistryError> {
    if bytes.len() > maximum {
        return Err(invalid("oversize processing group metadata"));
    }
    serde_json::from_slice(bytes).map_err(|e| ProcessingRegistryError::Corrupt(e.to_string()))
}
fn metadata(
    parent: &WorldState,
    namespace: &EtdagDigest,
) -> Result<Metadata, ProcessingRegistryError> {
    let meta = match parent.protocol.get(META) {
        None => Metadata {
            namespace_root: namespace.clone(),
            last_number: 0,
            last_root: processing_genesis_group_root(namespace)?,
            groups: 0,
            claims: 0,
        },
        Some(bytes) => decode(bytes, 2048)?,
    };
    meta.last_root.validate()?;
    if meta.namespace_root != *namespace
        || meta.last_root.is_zero()
        || meta.groups > MAX_ITEMS
        || meta.claims > MAX_ITEMS
    {
        return Err(invalid("processing group metadata scope/capacity mismatch"));
    }
    let groups = parent
        .protocol
        .range::<str, _>((Bound::Included(GROUP), Bound::Unbounded))
        .take_while(|(key, _)| key.starts_with(GROUP))
        .take(MAX_ITEMS + 1)
        .count();
    let claims = parent
        .protocol
        .range::<str, _>((Bound::Included(CLAIM), Bound::Unbounded))
        .take_while(|(key, _)| key.starts_with(CLAIM))
        .take(MAX_ITEMS + 1)
        .count();
    if (meta.last_number == 0
        && (meta.last_root != processing_genesis_group_root(namespace)?
            || meta.groups != 0
            || meta.claims != 0))
        || groups != meta.groups
        || claims != meta.claims
    {
        return Err(invalid("processing group metadata count mismatch"));
    }
    Ok(meta)
}

/// Caller retains its native proof/decoder reservation. This read grants no
/// authority until the exact parent candidate has been PoSy-authenticated.
pub fn processing_group_state(
    parent: &WorldState,
    namespace: &EtdagDigest,
    number: u64,
) -> Result<ProcessingGroupState, ProcessingRegistryError> {
    let bytes = parent
        .protocol
        .get(&group_key(number))
        .ok_or_else(|| invalid("processing group is absent"))?;
    let group: ProcessingGroupState = decode(bytes, 2048)?;
    group.group_root.validate()?;
    if let Some(root) = &group.closed_by_successor {
        root.validate()?;
        if root.is_zero() {
            return Err(invalid("zero processing successor"));
        }
    }
    if group.namespace_root != *namespace
        || group.group_number != number
        || group.remaining == 0
        || group.remaining > MAX_ITEMS
        || (group.next_position as usize).saturating_add(group.remaining) > MAX_ITEMS
        || group.group_root.is_zero()
    {
        return Err(invalid("invalid processing group ownership"));
    }
    Ok(group)
}

pub fn processing_member_claim(
    parent: &WorldState,
    sender: &str,
    nonce: u64,
) -> Result<ProcessingMemberClaim, ProcessingRegistryError> {
    processing_member_claim_optional(parent, sender, nonce)?
        .ok_or_else(|| invalid("processing member claim is absent"))
}

/// Absence is distinct from a corrupt existing claim. The proposer cannot
/// silently reinterpret malformed canonical ownership as unassigned work.
pub fn processing_member_claim_optional(
    parent: &WorldState,
    sender: &str,
    nonce: u64,
) -> Result<Option<ProcessingMemberClaim>, ProcessingRegistryError> {
    let Some(bytes) = parent.protocol.get(&claim_key(sender, nonce)?) else {
        return Ok(None);
    };
    let claim: ProcessingMemberClaim = decode(bytes, MAX_CLAIM_BYTES)?;
    for root in [
        &claim.group_root,
        &claim.member.processing_context_root,
        &claim.member.authorization_root,
    ] {
        root.validate()?;
        if root.is_zero() {
            return Err(invalid("zero processing claim root"));
        }
    }
    claim.member.envelope.validate()?;
    if claim.group_number == 0
        || claim.order_position as usize >= MAX_ITEMS
        || claim.member.envelope.sender_id != sender
        || claim.member.envelope.nonce_slot != nonce
    {
        return Err(invalid("processing member claim key mismatch"));
    }
    Ok(Some(claim))
}

/// Canonical successor coordinates, with no dependency on unfinished work.
/// An empty successor is useful only to close a nonempty open predecessor.
pub fn processing_order_tip(
    parent: &WorldState,
    namespace: &EtdagDigest,
) -> Result<(u64, EtdagDigest, bool), ProcessingRegistryError> {
    let meta = metadata(parent, namespace)?;
    let open = if parent.protocol.contains_key(&group_key(meta.last_number)) {
        processing_group_state(parent, namespace, meta.last_number)?
            .closed_by_successor
            .is_none()
    } else {
        false
    };
    Ok((
        meta.last_number
            .checked_add(1)
            .ok_or_else(|| invalid("processing group number overflow"))?,
        meta.last_root,
        open,
    ))
}

/// The original encrypted assignment must already be closed in the OLD parent.
/// Newly assigned or newly closed work cannot publish plaintext in this block.
/// This checks state coherence; the native verifier authenticates that parent.
pub fn verify_processing_record_assignment(
    parent: &WorldState,
    namespace: &EtdagDigest,
    record: &ProcessingReadyRecord,
) -> Result<ProcessingMemberClaim, ProcessingRegistryError> {
    let claim = processing_member_claim(parent, &record.sender_wallet, record.sender_nonce)?;
    let item = &record.item;
    let envelope = &claim.member.envelope;
    let group = processing_group_state(parent, namespace, item.group_number)?;
    if group.closed_by_successor.is_none()
        || group.group_root != item.group_root
        || claim.group_number != item.group_number
        || claim.group_root != item.group_root
        || claim.order_position != item.order_position
        || envelope.tx_commitment != item.envelope_id
        || envelope.gas_class_units != item.gas_class_units
        || claim.member.processing_context_root != record.processing_context_root
        || claim.member.authorization_root != record.authorization_root
        || item
            .remaining_dependencies
            .iter()
            .any(|dependency| !envelope.protocol_dependencies.contains(dependency))
    {
        return Err(invalid(
            "ready record differs from closed processing assignment",
        ));
    }
    Ok(claim)
}

/// Selected consumption, successor closure and new encrypted assignments form
/// one per-entry diff, applied atomically with execution and ready-state changes.
/// New assignment never authorizes same-block plaintext publication/execution.
pub fn processing_group_transition<'a>(
    parent: &WorldState,
    namespace: &EtdagDigest,
    consumed: impl Iterator<Item = &'a ProcessingReadyRecord>,
    new_group: Option<&ProcessingOrderGroup>,
    verifier: &impl ProcessingReadinessVerifier,
    budget: &Arc<WorldResourceBudget>,
) -> Result<ProcessingGroupTransition, ProcessingRegistryError> {
    // Charge the index before even collecting references; all decoded claims,
    // graph indexes, serialized roots and diff clones live under this permit.
    let mut permit = budget.reserve(8192)?;
    let mut records = Vec::new();
    for record in consumed {
        if records.len() == MAX_ITEMS {
            return Err(invalid("too many processing consumptions"));
        }
        let key = claim_key(&record.sender_wallet, record.sender_nonce)?;
        let bytes = parent
            .protocol
            .get(&key)
            .ok_or_else(|| invalid("processing member claim is absent"))?;
        if bytes.len() > MAX_CLAIM_BYTES {
            return Err(invalid("oversize processing member claim"));
        }
        permit.grow(
            bytes
                .len()
                .checked_mul(16)
                .and_then(|n| n.checked_add(16 * 1024))
                .ok_or(synergy_state::world_resources::WorldResourceError::ArithmeticOverflow)?,
        )?;
        records.push(record);
    }
    let members = new_group.map_or(0, |group| group.members.len());
    if members > MAX_ITEMS {
        return Err(invalid("too many processing assignments"));
    }
    if let Some(group) = new_group {
        // Measure without allocating a serialization buffer. The input already
        // belongs to the charged native owner; reserve all derived work here.
        struct Counter(usize);
        impl std::io::Write for Counter {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                self.0 = self
                    .0
                    .checked_add(bytes.len())
                    .ok_or_else(|| std::io::Error::other("processing group size overflow"))?;
                Ok(bytes.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let mut counter = Counter(0);
        serde_json::to_writer(&mut counter, group).map_err(|e| invalid(&e.to_string()))?;
        permit.grow(
            counter
                .0
                .checked_mul(16)
                .and_then(|n| {
                    members
                        .checked_mul(16 * 1024)
                        .and_then(|index| n.checked_add(index))
                })
                .ok_or(synergy_state::world_resources::WorldResourceError::ArithmeticOverflow)?,
        )?;
    }
    if records.is_empty() && new_group.is_none() {
        return Ok(ProcessingGroupTransition {
            diff: StateDiff::default(),
            _permit: permit,
        });
    }
    let mut meta = metadata(parent, namespace)?;
    let mut changes = BTreeMap::<String, (Option<Vec<u8>>, Option<Vec<u8>>)>::new();
    let mut touched = BTreeMap::<u64, ProcessingGroupState>::new();
    for record in records {
        let claim = verify_processing_record_assignment(parent, namespace, record)?;
        let item = &record.item;
        if claim.group_number != item.group_number
            || claim.group_root != item.group_root
            || claim.order_position != item.order_position
            || claim.member.envelope.tx_commitment != item.envelope_id
            || claim.member.processing_context_root != record.processing_context_root
            || claim.member.authorization_root != record.authorization_root
        {
            return Err(invalid(
                "consumption differs from assigned processing member",
            ));
        }
        let group = match touched.entry(item.group_number) {
            std::collections::btree_map::Entry::Occupied(entry) => entry.into_mut(),
            std::collections::btree_map::Entry::Vacant(entry) => entry.insert(
                processing_group_state(parent, namespace, item.group_number)?,
            ),
        };
        if group.closed_by_successor.is_none() || group.group_root != item.group_root {
            return Err(invalid("processing consumption precedes successor closure"));
        }
        if item.order_position != group.next_position {
            return Err(invalid(
                "processing consumption skips certified group prefix",
            ));
        }
        group.next_position = group
            .next_position
            .checked_add(1)
            .ok_or_else(|| invalid("processing position overflow"))?;
        group.remaining = group
            .remaining
            .checked_sub(1)
            .ok_or_else(|| invalid("processing group consumption underflow"))?;
        meta.claims = meta
            .claims
            .checked_sub(1)
            .ok_or_else(|| invalid("processing claim count underflow"))?;
        let key = claim_key(&record.sender_wallet, record.sender_nonce)?;
        if changes
            .insert(key.clone(), (parent.protocol.get(&key).cloned(), None))
            .is_some()
        {
            return Err(invalid("duplicate processing consumption"));
        }
    }
    if let Some(group) = new_group {
        group.validate()?;
        if group.namespace_root != *namespace
            || meta.last_number.checked_add(1) != Some(group.group_number)
            || group.previous_group_root != meta.last_root
            || meta.claims.saturating_add(members) > MAX_ITEMS
        {
            return Err(invalid("nonsequential/oversize processing assignment"));
        }
        verifier
            .verify_ordered_group(group, parent)
            .map_err(ProcessingRegistryError::Verification)?;
        let root = group.root()?;
        if meta.last_number != 0 && parent.protocol.contains_key(&group_key(meta.last_number)) {
            let previous = match touched.entry(meta.last_number) {
                std::collections::btree_map::Entry::Occupied(entry) => entry.into_mut(),
                std::collections::btree_map::Entry::Vacant(entry) => {
                    entry.insert(processing_group_state(parent, namespace, meta.last_number)?)
                }
            };
            if previous.closed_by_successor.is_some()
                || previous.group_root != group.previous_group_root
            {
                return Err(invalid("conflicting processing successor closure"));
            }
            previous.closed_by_successor = Some(root.clone());
        }
        for (position, member) in group.members.iter().enumerate() {
            let item = &member.envelope;
            if item.nonce_slot < parent.accounts.get(&item.sender_id).map_or(0, |a| a.nonce) {
                return Err(invalid("processing assignment nonce already consumed"));
            }
            let key = claim_key(&item.sender_id, item.nonce_slot)?;
            // Old claims stay exclusive throughout this candidate, even when
            // selected for consumption. No same-block reservation recycling.
            if parent.protocol.contains_key(&key) || changes.contains_key(&key) {
                return Err(invalid("processing nonce already assigned"));
            }
            let claim = ProcessingMemberClaim {
                group_number: group.group_number,
                group_root: root.clone(),
                order_position: position as u32,
                member: member.clone(),
            };
            let bytes = encode(&claim)?;
            if bytes.len() > MAX_CLAIM_BYTES {
                return Err(invalid("processing assignment record too large"));
            }
            changes.insert(key, (None, Some(bytes)));
        }
        if !group.members.is_empty() {
            if meta.groups == MAX_ITEMS {
                return Err(invalid("processing group capacity exhausted"));
            }
            touched.insert(
                group.group_number,
                ProcessingGroupState {
                    namespace_root: namespace.clone(),
                    group_number: group.group_number,
                    group_root: root.clone(),
                    remaining: members,
                    next_position: 0,
                    closed_by_successor: None,
                },
            );
            meta.groups += 1;
        }
        meta.claims += members;
        meta.last_number = group.group_number;
        meta.last_root = root;
    }
    for (number, group) in touched {
        let key = group_key(number);
        let value = if group.remaining == 0 {
            meta.groups = meta
                .groups
                .checked_sub(1)
                .ok_or_else(|| invalid("processing group count underflow"))?;
            None
        } else {
            Some(encode(&group)?)
        };
        changes.insert(key.clone(), (parent.protocol.get(&key).cloned(), value));
    }
    changes.insert(
        META.into(),
        (parent.protocol.get(META).cloned(), Some(encode(&meta)?)),
    );
    let diff = StateDiff {
        protocol_changes: changes
            .into_iter()
            .map(|(key, (expected, next))| ProtocolChange {
                key,
                expected_value: expected,
                value: next,
            })
            .collect(),
        ..StateDiff::default()
    };
    Ok(ProcessingGroupTransition {
        diff,
        _permit: permit,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use synergy_etdag::{execution::ProcessingReadyItem, CertifiedEnvelopeRef};
    struct VerifiedFixture;
    impl ProcessingReadinessVerifier for VerifiedFixture {
        fn verify_ordered_group(
            &self,
            _: &ProcessingOrderGroup,
            _: &WorldState,
        ) -> Result<(), String> {
            Ok(())
        }
        fn verify_publication(
            &self,
            _: &ProcessingReadyRecord,
            _: &WorldState,
        ) -> Result<(), String> {
            Ok(())
        }
        fn identity_is_current(
            &self,
            _: &ProcessingReadyRecord,
            _: &WorldState,
        ) -> Result<bool, String> {
            Ok(true)
        }
    }
    fn digest(label: &str) -> EtdagDigest {
        EtdagDigest::from_domain_bytes("processing-groups-state-fixture", label.as_bytes())
    }
    fn group(number: u64, previous: EtdagDigest, nonce: Option<u64>) -> ProcessingOrderGroup {
        ProcessingOrderGroup {
            group_version: 1,
            namespace_root: digest("namespace"),
            group_number: number,
            previous_group_root: previous,
            order_seed: digest("seed"),
            members: nonce
                .map(|nonce| ProcessingGroupMember {
                    processing_context_root: digest("context"),
                    authorization_root: digest("authority"),
                    envelope: CertifiedEnvelopeRef {
                        tx_commitment: digest(&format!("envelope-{nonce}")),
                        sender_id: "alice".into(),
                        nonce_slot: nonce,
                        certified_dag_round: 0,
                        gas_class_units: 21_000,
                        ciphertext_bytes: 1024,
                        fee_class: 1,
                        protocol_dependencies: vec![],
                    },
                })
                .into_iter()
                .collect(),
        }
    }
    fn record(group: &ProcessingOrderGroup) -> ProcessingReadyRecord {
        let member = &group.members[0];
        ProcessingReadyRecord {
            processing_context_root: member.processing_context_root.clone(),
            authorization_root: member.authorization_root.clone(),
            sender_wallet: member.envelope.sender_id.clone(),
            sender_nonce: member.envelope.nonce_slot,
            item: ProcessingReadyItem {
                group_number: group.group_number,
                group_root: group.root().unwrap(),
                order_position: 0,
                envelope_id: member.envelope.tx_commitment.clone(),
                payload_root: digest("plaintext"),
                readiness_root: digest("readiness"),
                gas_class_units: 21_000,
                encoded_bytes: 1000,
                remaining_dependencies: vec![],
            },
        }
    }
    fn apply(
        world: &mut WorldState,
        group: &ProcessingOrderGroup,
        budget: &Arc<WorldResourceBudget>,
    ) {
        let transition = processing_group_transition(
            world,
            &digest("namespace"),
            std::iter::empty(),
            Some(group),
            &VerifiedFixture,
            budget,
        )
        .unwrap();
        transition.diff().apply(world).unwrap();
    }
    #[test]
    fn processing_groups_require_old_parent_successor_closure_then_retire_only_consumed_entries() {
        let budget = WorldResourceBudget::new(256 * 1024 * 1024);
        let mut world = WorldState::default();
        world.protocol.insert("unrelated".into(), vec![9; 65536]);
        let pointer = world.protocol["unrelated"].as_ptr();
        let first = group(
            1,
            processing_genesis_group_root(&digest("namespace")).unwrap(),
            Some(0),
        );
        let ready = record(&first);
        apply(&mut world, &first, &budget);
        let original = world.clone();
        assert!(verify_processing_record_assignment(&world, &digest("namespace"), &ready).is_err());
        assert!(processing_group_transition(
            &world,
            &digest("namespace"),
            std::iter::once(&ready),
            None,
            &VerifiedFixture,
            &budget
        )
        .is_err());
        assert_eq!(world, original);
        assert_eq!(budget.used(), 0);
        let successor = group(2, first.root().unwrap(), None);
        // Closure is speculative until its ordinary candidate is authenticated
        // by PoSy. This test deliberately checks only the state transition.
        let transition = processing_group_transition(
            &world,
            &digest("namespace"),
            std::iter::empty(),
            Some(&successor),
            &VerifiedFixture,
            &budget,
        )
        .unwrap();
        assert!(verify_processing_record_assignment(&world, &digest("namespace"), &ready).is_err());
        transition.diff().apply(&mut world).unwrap();
        drop(transition);
        verify_processing_record_assignment(&world, &digest("namespace"), &ready).unwrap();
        let consumed = processing_group_transition(
            &world,
            &digest("namespace"),
            std::iter::once(&ready),
            None,
            &VerifiedFixture,
            &budget,
        )
        .unwrap();
        assert_eq!(consumed.diff().protocol_changes.len(), 3); // claim, group, small metadata
        consumed.diff().apply(&mut world).unwrap();
        drop(consumed);
        assert!(processing_member_claim(&world, "alice", 0).is_err());
        assert!(processing_group_state(&world, &digest("namespace"), 1).is_err());
        assert_eq!(world.protocol["unrelated"].as_ptr(), pointer);
        assert_eq!(budget.used(), 0);
    }
    #[test]
    fn processing_groups_enforce_global_nonce_ownership_and_retry_without_leaked_reservations() {
        let budget = WorldResourceBudget::new(256 * 1024 * 1024);
        let mut world = WorldState::default();
        let first = group(
            1,
            processing_genesis_group_root(&digest("namespace")).unwrap(),
            Some(0),
        );
        apply(&mut world, &first, &budget);
        let original = world.clone();
        let duplicate = group(2, first.root().unwrap(), Some(0));
        assert!(processing_group_transition(
            &world,
            &digest("namespace"),
            std::iter::empty(),
            Some(&duplicate),
            &VerifiedFixture,
            &budget
        )
        .is_err());
        assert_eq!(world, original);
        assert_eq!(budget.used(), 0);
        let pressure = budget.reserve(budget.available()).unwrap();
        let valid = group(2, first.root().unwrap(), Some(1));
        assert!(matches!(
            processing_group_transition(
                &world,
                &digest("namespace"),
                std::iter::empty(),
                Some(&valid),
                &VerifiedFixture,
                &budget
            ),
            Err(ProcessingRegistryError::Resource(_))
        ));
        drop(pressure);
        apply(&mut world, &valid, &budget);
        assert_eq!(budget.used(), 0);
        let mut forged = record(&first);
        forged.item.order_position = 1;
        assert!(
            verify_processing_record_assignment(&world, &digest("namespace"), &forged).is_err()
        );
        assert_eq!(budget.used(), 0);
    }
    #[test]
    fn processing_groups_empty_successors_keep_constant_state_without_pending_history() {
        let budget = WorldResourceBudget::new(256 * 1024 * 1024);
        let mut world = WorldState::default();
        let mut previous = processing_genesis_group_root(&digest("namespace")).unwrap();
        for number in 1..=64 {
            let next = group(number, previous, None);
            apply(&mut world, &next, &budget);
            previous = next.root().unwrap();
            assert_eq!(world.protocol.len(), 1);
            assert_eq!(budget.used(), 0);
        }
        assert_eq!(metadata(&world, &digest("namespace")).unwrap().claims, 0);
    }
    #[test]
    fn processing_groups_maximum_assignment_reserves_before_graph_work_and_rejects_pressure_cleanly(
    ) {
        let namespace = digest("namespace");
        let mut maximum = group(1, processing_genesis_group_root(&namespace).unwrap(), None);
        let members = (0..MAX_ITEMS)
            .map(|index| {
                let mut member = group(1, maximum.previous_group_root.clone(), Some(index as u64))
                    .members
                    .remove(0);
                member.envelope.sender_id = format!("sender-{index}");
                (member.envelope.tx_commitment.clone(), member)
            })
            .collect::<BTreeMap<_, _>>();
        let eligible = members
            .values()
            .map(|member| member.envelope.clone())
            .collect::<Vec<_>>();
        let order = synergy_etdag::canonical_content_blind_order(
            &eligible,
            &maximum.order_seed,
            u64::MAX,
            u64::MAX,
        )
        .unwrap();
        let mut members = members;
        maximum.members = order
            .into_iter()
            .map(|item| members.remove(&item.tx_commitment).unwrap())
            .collect();
        let original = WorldState::default();
        let tiny = WorldResourceBudget::new(1024 * 1024);
        assert!(matches!(
            processing_group_transition(
                &original,
                &namespace,
                std::iter::empty(),
                Some(&maximum),
                &VerifiedFixture,
                &tiny
            ),
            Err(ProcessingRegistryError::Resource(_))
        ));
        assert_eq!(tiny.used(), 0);
        assert!(original.protocol.is_empty());
        let budget = WorldResourceBudget::new(256 * 1024 * 1024);
        let transition = processing_group_transition(
            &original,
            &namespace,
            std::iter::empty(),
            Some(&maximum),
            &VerifiedFixture,
            &budget,
        )
        .unwrap();
        assert_eq!(transition.diff().protocol_changes.len(), MAX_ITEMS + 2);
        assert!(budget.used() < budget.limit());
        eprintln!(
            "processing maximum group: members={} transition_reservation={} pool_limit={}",
            MAX_ITEMS,
            budget.used(),
            budget.limit()
        );
        let mut world = original.clone();
        transition.diff().apply(&mut world).unwrap();
        assert_eq!(metadata(&world, &namespace).unwrap().claims, MAX_ITEMS);
        drop(transition);
        assert_eq!(budget.used(), 0);
    }
    #[test]
    fn processing_groups_later_ready_member_cannot_skip_unfinished_certified_predecessor() {
        struct PrefixVerifier;
        impl ProcessingReadinessVerifier for PrefixVerifier {
            fn verify_publication(
                &self,
                _: &ProcessingReadyRecord,
                _: &WorldState,
            ) -> Result<(), String> {
                Ok(())
            }
            fn identity_is_current(
                &self,
                _: &ProcessingReadyRecord,
                _: &WorldState,
            ) -> Result<bool, String> {
                Ok(true)
            }
            fn first_unconsumed_position(
                &self,
                record: &ProcessingReadyRecord,
                parent: &WorldState,
            ) -> Result<Option<u32>, String> {
                Ok(Some(
                    processing_group_state(parent, &digest("namespace"), record.item.group_number)
                        .map_err(|e| e.to_string())?
                        .next_position,
                ))
            }
        }
        let budget = WorldResourceBudget::new(256 * 1024 * 1024);
        let namespace = digest("namespace");
        let mut world = WorldState::default();
        let mut first = group(
            1,
            processing_genesis_group_root(&namespace).unwrap(),
            Some(0),
        );
        let mut second = group(1, first.previous_group_root.clone(), Some(1))
            .members
            .remove(0);
        second.envelope.sender_id = "bob".into();
        second.envelope.nonce_slot = 0;
        first.members.push(second);
        let order = synergy_etdag::canonical_content_blind_order(
            &first
                .members
                .iter()
                .map(|m| m.envelope.clone())
                .collect::<Vec<_>>(),
            &first.order_seed,
            u64::MAX,
            u64::MAX,
        )
        .unwrap();
        first.members.sort_by_key(|m| {
            order
                .iter()
                .position(|e| e.tx_commitment == m.envelope.tx_commitment)
                .unwrap()
        });
        apply(&mut world, &first, &budget);
        apply(&mut world, &group(2, first.root().unwrap(), None), &budget);
        let early = record(&first);
        let mut late = early.clone();
        late.sender_wallet = first.members[1].envelope.sender_id.clone();
        late.sender_nonce = first.members[1].envelope.nonce_slot;
        late.item.envelope_id = first.members[1].envelope.tx_commitment.clone();
        late.item.order_position = 1;
        let publish = |world: &mut WorldState, item: &ProcessingReadyRecord| {
            let registry =
                crate::ParentProcessingRegistry::read(world, &namespace, &budget).unwrap();
            let selected = registry.select(&PrefixVerifier, 100_000, 10_000).unwrap();
            let transition = selected
                .transition(std::slice::from_ref(item), &PrefixVerifier, 100_000, 10_000)
                .unwrap();
            // Drop the borrowed parent views before applying the owned diff.
            drop(selected);
            drop(registry);
            transition.diff().apply(world).unwrap();
        };
        publish(&mut world, &late);
        {
            let registry =
                crate::ParentProcessingRegistry::read(&world, &namespace, &budget).unwrap();
            assert!(registry
                .select(&PrefixVerifier, 100_000, 10_000)
                .unwrap()
                .selection()
                .item_indices
                .is_empty());
            assert!(processing_group_transition(
                &world,
                &namespace,
                std::iter::once(&late),
                None,
                &VerifiedFixture,
                &budget
            )
            .is_err());
        }
        publish(&mut world, &early);
        {
            let registry =
                crate::ParentProcessingRegistry::read(&world, &namespace, &budget).unwrap();
            let selected = registry.select(&PrefixVerifier, 100_000, 10_000).unwrap();
            assert_eq!(selected.selection().item_indices, vec![0, 1]);
            let transition = processing_group_transition(
                &world,
                &namespace,
                selected.records(),
                None,
                &VerifiedFixture,
                &budget,
            )
            .unwrap();
            assert!(transition
                .diff()
                .protocol_changes
                .iter()
                .any(|change| change.key == group_key(1) && change.value.is_none()));
        }
        assert_eq!(budget.used(), 0);
    }
}
