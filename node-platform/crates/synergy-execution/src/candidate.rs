use std::sync::Arc;

use serde::{Deserialize, Serialize};
use synergy_block::hash_block_bytes;
#[cfg(test)]
use synergy_state::state_root;
use synergy_state::world_resources::{
    preflight_world_json, BudgetedWorld, WorldResourceBudget, WorldResourceError,
    WorldResourceFormat,
};
use synergy_state::{state_root_with_size, WorldState};
use synergy_transaction::{SignedTransaction, TransactionReceipt};

/// Complete deterministic execution material committed by a candidate block.
///
/// PoSy certifies the block and protected-execution commitments; execution
/// remains responsible for recomputing this structure before state import.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionCandidate<W = WorldState> {
    pub height: u64,
    pub block_id: String,
    pub parent_block_id: String,
    pub protected_execution_root: String,
    pub protected_material: synergy_etdag::execution::CandidateProtectedMaterial,
    pub state_root: String,
    pub transactions: Vec<SignedTransaction>,
    pub receipts: Vec<TransactionReceipt>,
    /// Immutable state is shared across execution, ingress and candidate readers.
    /// Serde preserves the existing world-state JSON and signed commitments.
    pub state: Arc<W>,
    /// Lifetime charge for retained candidate metadata. Runtime handoffs share
    /// the complete candidate through Arc; they never deep-clone this graph.
    #[serde(skip)]
    pub resource_permit: Option<Arc<synergy_state::world_resources::WorldResourcePermit>>,
}

pub type BudgetedExecutionCandidate = ExecutionCandidate<BudgetedWorld>;

impl<W: Clone> Clone for ExecutionCandidate<W> {
    fn clone(&self) -> Self {
        Self {
            height: self.height,
            block_id: self.block_id.clone(),
            parent_block_id: self.parent_block_id.clone(),
            protected_execution_root: self.protected_execution_root.clone(),
            protected_material: self.protected_material.clone(),
            state_root: self.state_root.clone(),
            transactions: self.transactions.clone(),
            receipts: self.receipts.clone(),
            state: Arc::clone(&self.state),
            resource_permit: self.resource_permit.clone(),
        }
    }
}

impl<W: PartialEq> PartialEq for ExecutionCandidate<W> {
    fn eq(&self, other: &Self) -> bool {
        self.height == other.height
            && self.block_id == other.block_id
            && self.parent_block_id == other.parent_block_id
            && self.protected_execution_root == other.protected_execution_root
            && self.protected_material == other.protected_material
            && self.state_root == other.state_root
            && self.transactions == other.transactions
            && self.receipts == other.receipts
            && self.state == other.state
    }
}
impl<W: Eq> Eq for ExecutionCandidate<W> {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CandidateResourceError {
    Resource(WorldResourceError),
    Decode(String),
    Invalid(String),
    Storage(String),
}
impl From<String> for CandidateResourceError {
    fn from(value: String) -> Self {
        Self::Storage(value)
    }
}
impl From<&str> for CandidateResourceError {
    fn from(value: &str) -> Self {
        Self::Storage(value.into())
    }
}
impl From<WorldResourceError> for CandidateResourceError {
    fn from(value: WorldResourceError) -> Self {
        Self::Resource(value)
    }
}
impl std::fmt::Display for CandidateResourceError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{self:?}")
    }
}
impl std::error::Error for CandidateResourceError {}

/// Explicit shared-pool boundary. No World or candidate metadata is decoded
/// until scanner scratch and the complete prospective decode peak are reserved.
/// Both the World and retained candidate metadata keep their reservations.
/// Budgeted candidates are shared by Arc; deep Clone is limited to plain Worlds.
pub fn decode_budgeted_candidate(
    bytes: &[u8],
    budget: &Arc<WorldResourceBudget>,
) -> Result<BudgetedExecutionCandidate, CandidateResourceError> {
    let scanner = bytes
        .len()
        .checked_mul(3)
        .and_then(|n| n.checked_add(4096))
        .ok_or(WorldResourceError::ArithmeticOverflow)?;
    let mut permit = budget.reserve(scanner)?;
    let estimate =
        preflight_world_json(bytes, WorldResourceFormat::LegacyCandidate, budget.limit())?;
    let metadata = candidate_metadata_charge(bytes)?;
    permit.resize(
        estimate
            .peak_decode_bytes
            .checked_sub(estimate.decoded_owned_bytes)
            .and_then(|bytes| bytes.checked_add(metadata))
            .ok_or(WorldResourceError::ArithmeticOverflow)?,
    )?;
    // Keep metadata/input/serde scratch charged through native validation;
    // ownership of the separately reserved World charge moves into the Arc.
    let world_permit = budget.reserve(estimate.decoded_owned_bytes)?;
    let candidate: ExecutionCandidate =
        serde_json::from_slice(bytes).map_err(|e| CandidateResourceError::Decode(e.to_string()))?;
    let ExecutionCandidate {
        resource_permit: _,
        height,
        block_id,
        parent_block_id,
        protected_execution_root,
        protected_material,
        state_root,
        transactions,
        receipts,
        state,
    } = candidate;
    let world = Arc::try_unwrap(state).map_err(|_| {
        CandidateResourceError::Invalid("new candidate World unexpectedly shared".into())
    })?;
    let state = Arc::new(BudgetedWorld::from_reserved(world, world_permit)?);
    let candidate = ExecutionCandidate {
        resource_permit: None,
        height,
        block_id,
        parent_block_id,
        protected_execution_root,
        protected_material,
        state_root,
        transactions,
        receipts,
        state,
    };
    let _root_scratch = budget.reserve(8192)?;
    candidate
        .validate()
        .map_err(CandidateResourceError::Invalid)?;
    permit.shrink(metadata)?;
    let mut candidate = candidate;
    candidate.resource_permit = Some(Arc::new(permit));
    Ok(candidate)
}

/// Reserve native transaction metadata before the execution owner decodes
/// ETDAG plaintext. Input bytes remain charged by the protected batch owner.
/// Two native graphs cover the body/committed candidate handoff; fixed room
/// covers roots, receipts and empty/bootstrap candidates. The resulting guard
/// transfers into the complete shared candidate on successful execution.
pub fn reserve_execution_metadata<'a>(
    plaintexts: impl IntoIterator<Item = &'a [u8]>,
    budget: &Arc<WorldResourceBudget>,
) -> Result<synergy_state::world_resources::WorldResourcePermit, CandidateResourceError> {
    let mut retained = budget.reserve(16 * 1024)?;
    for bytes in plaintexts {
        let scratch = bytes
            .len()
            .checked_mul(3)
            .and_then(|n| n.checked_add(4096))
            .ok_or(WorldResourceError::ArithmeticOverflow)?;
        let _scanner = budget.reserve(scratch)?;
        let native = candidate_metadata_charge(bytes)?
            .checked_mul(2)
            .ok_or(WorldResourceError::ArithmeticOverflow)?;
        retained.grow(native)?;
    }
    Ok(retained)
}

// Allocation-free shape walk. Native object allocations fit within 2048 bytes
// per JSON object; vectors reserve at most twice their elements. Scalar charge
// covers numeric/enum vector elements; escaped strings have separate capacity.
pub(crate) fn candidate_metadata_charge(bytes: &[u8]) -> Result<usize, CandidateResourceError> {
    use serde::de::{DeserializeSeed, MapAccess, SeqAccess, Visitor};
    struct Seed<'a> {
        charge: &'a mut usize,
        root: bool,
    }
    impl Seed<'_> {
        fn add<E: serde::de::Error>(&mut self, n: usize) -> Result<(), E> {
            *self.charge = self
                .charge
                .checked_add(n)
                .ok_or_else(|| E::custom("candidate metadata resource overflow"))?;
            Ok(())
        }
    }
    impl<'de> DeserializeSeed<'de> for Seed<'_> {
        type Value = ();
        fn deserialize<D: serde::Deserializer<'de>>(self, d: D) -> Result<(), D::Error> {
            d.deserialize_any(self)
        }
    }
    impl<'de> Visitor<'de> for Seed<'_> {
        type Value = ();
        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            f.write_str("candidate metadata")
        }
        fn visit_map<A: MapAccess<'de>>(mut self, mut map: A) -> Result<(), A::Error> {
            self.add(4096)?;
            while let Some(key) = map.next_key::<BorrowedField>()? {
                if self.root && key.0 {
                    map.next_value::<serde::de::IgnoredAny>()?;
                } else {
                    map.next_value_seed(Seed {
                        charge: self.charge,
                        root: false,
                    })?;
                }
            }
            Ok(())
        }
        fn visit_seq<A: SeqAccess<'de>>(mut self, mut seq: A) -> Result<(), A::Error> {
            self.add(128)?;
            while seq
                .next_element_seed(Seed {
                    charge: self.charge,
                    root: false,
                })?
                .is_some()
            {}
            Ok(())
        }
        fn visit_str<E: serde::de::Error>(mut self, v: &str) -> Result<(), E> {
            self.add(v.len().saturating_mul(2).saturating_add(64))
        }
        fn visit_string<E: serde::de::Error>(self, v: String) -> Result<(), E> {
            self.visit_str(&v)
        }
        fn visit_u64<E: serde::de::Error>(mut self, _: u64) -> Result<(), E> {
            self.add(16)
        }
        fn visit_i64<E: serde::de::Error>(mut self, _: i64) -> Result<(), E> {
            self.add(16)
        }
        fn visit_f64<E: serde::de::Error>(mut self, _: f64) -> Result<(), E> {
            self.add(16)
        }
        fn visit_bool<E: serde::de::Error>(mut self, _: bool) -> Result<(), E> {
            self.add(16)
        }
        fn visit_unit<E: serde::de::Error>(mut self) -> Result<(), E> {
            self.add(16)
        }
    }
    struct BorrowedField(bool);
    impl<'de> Deserialize<'de> for BorrowedField {
        fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
            struct FieldVisitor;
            impl Visitor<'_> for FieldVisitor {
                type Value = BorrowedField;
                fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                    f.write_str("field")
                }
                fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Self::Value, E> {
                    Ok(BorrowedField(v == "state"))
                }
            }
            d.deserialize_identifier(FieldVisitor)
        }
    }
    let mut charge = 0;
    let mut de = serde_json::Deserializer::from_slice(bytes);
    Seed {
        charge: &mut charge,
        root: true,
    }
    .deserialize(&mut de)
    .map_err(|e| CandidateResourceError::Decode(e.to_string()))?;
    de.end()
        .map_err(|e| CandidateResourceError::Decode(e.to_string()))?;
    Ok(charge)
}

impl<W: AsRef<WorldState>> ExecutionCandidate<W> {
    /// Verifies structural, account-root, and canonical block commitments.
    pub fn validate(&self) -> Result<(), String> {
        self.validate_with_world_size().map(|_| ())
    }

    pub(crate) fn validate_with_world_size(&self) -> Result<usize, String> {
        self.protected_material
            .validate()
            .map_err(|e| format!("invalid protected candidate material: {e:?}"))?;
        let protected_root = hash_block_bytes(
            &self
                .protected_material
                .commitment_bytes()
                .map_err(|e| format!("encode protected candidate material: {e:?}"))?,
        );
        if self.height == 0
            || self.protected_material.height() != self.height
            || protected_root != self.protected_execution_root
            || self.parent_block_id.trim().is_empty()
            || self.protected_execution_root.trim().is_empty()
            || self.transactions.len() != self.receipts.len()
        {
            return Err("execution candidate has invalid shape or account root".into());
        }
        let (root, size) = state_root_with_size(self.state.as_ref().as_ref())
            .map_err(|error| format!("root candidate state: {error:?}"))?;
        if root != self.state_root {
            return Err("execution candidate has invalid shape or account root".into());
        }
        if self.commitment_id()? != self.block_id {
            return Err("execution candidate block commitment mismatch".into());
        }
        Ok(size)
    }

    /// Recomputes the canonical block identifier from committed execution data.
    pub fn commitment_id(&self) -> Result<String, String> {
        serde_json::to_vec(&(
            self.height,
            &self.parent_block_id,
            &self.protected_execution_root,
            &self.state_root,
            &self.transactions,
            &self.receipts,
        ))
        .map(|bytes| hash_block_bytes(&bytes))
        .map_err(|error| format!("encode execution candidate commitment: {error}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn budgeted_candidate_decode_rejects_before_serde_and_releases_on_bad_commitment() {
        let malformed = b"not candidate JSON";
        let tiny = WorldResourceBudget::new(1);
        assert!(matches!(
            decode_budgeted_candidate(malformed, &tiny),
            Err(CandidateResourceError::Resource(
                WorldResourceError::Capacity { .. }
            ))
        ));
        assert_eq!(tiny.used(), 0);
        let mut world = WorldState::default();
        world.protocol.insert("x".into(), vec![9; 4096]);
        let material = synergy_etdag::execution::ProtectedProposalMaterial {
            material_version: 2,
            height: 1,
            execution_root: synergy_etdag::EtdagDigest::from_domain_bytes("x", b"a"),
            next_batch_root: synergy_etdag::EtdagDigest::from_domain_bytes("x", b"b"),
            cutoff_boundary_root: synergy_etdag::EtdagDigest::from_domain_bytes("x", b"c"),
        };
        let bad = ExecutionCandidate {
            resource_permit: None,
            height: 1,
            block_id: "bad".into(),
            parent_block_id: "parent".into(),
            protected_execution_root: hash_block_bytes(&material.commitment_bytes().unwrap()),
            protected_material: material.into(),
            state_root: state_root(&world).unwrap(),
            transactions: vec![],
            receipts: vec![],
            state: Arc::new(world),
        };
        let budget = WorldResourceBudget::new(1024 * 1024);
        assert!(matches!(
            decode_budgeted_candidate(&serde_json::to_vec(&bad).unwrap(), &budget),
            Err(CandidateResourceError::Invalid(_))
        ));
        assert_eq!(budget.used(), 0);
        // Fixed native object-size bounds used by the allocation-free scanner.
        assert!(std::mem::size_of::<synergy_transaction::SignedTransaction>() <= 2048);
        assert!(std::mem::size_of::<synergy_transaction::TransactionReceipt>() <= 2048);
    }

    #[test]
    fn candidate_handoffs_share_world_and_preserve_canonical_json_and_commitments() {
        let mut world = WorldState::default();
        world
            .protocol
            .insert("large-value".into(), vec![7; 1024 * 1024]);
        let material = synergy_etdag::execution::ProtectedProposalMaterial {
            material_version: 2,
            height: 1,
            execution_root: synergy_etdag::EtdagDigest::from_domain_bytes("test", b"execution"),
            next_batch_root: synergy_etdag::EtdagDigest::from_domain_bytes("test", b"batch"),
            cutoff_boundary_root: synergy_etdag::EtdagDigest::from_domain_bytes("test", b"cutoff"),
        };
        let mut candidate = ExecutionCandidate {
            resource_permit: None,
            height: 1,
            block_id: String::new(),
            parent_block_id: "a".repeat(64),
            protected_execution_root: hash_block_bytes(&material.commitment_bytes().unwrap()),
            protected_material: material.into(),
            state_root: state_root(&world).unwrap(),
            transactions: vec![],
            receipts: vec![],
            state: Arc::new(world),
        };
        candidate.block_id = candidate.commitment_id().unwrap();
        candidate.validate().unwrap();
        let clone = candidate.clone();
        assert!(Arc::ptr_eq(&candidate.state, &clone.state));
        let bytes = serde_json::to_vec(&candidate).unwrap();
        let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            value["state"],
            serde_json::to_value(candidate.state.as_ref()).unwrap()
        );
        let decoded: ExecutionCandidate = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(decoded, candidate);
        decoded.validate().unwrap();
        assert_eq!(decoded.commitment_id().unwrap(), candidate.block_id);
        assert!(!Arc::ptr_eq(&decoded.state, &candidate.state));
    }
}
