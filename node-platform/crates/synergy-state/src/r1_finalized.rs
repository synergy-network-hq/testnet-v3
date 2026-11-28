//! Immutable R1 execution projections and read-only, incarnation-bound queries.
//! Stored proofs are original public bytes; storage does not authenticate PoSy.
//! Production publication requires the native verified-finality owner. The only
//! writer exposed here currently rejects production coordinates before any I/O.
use crate::r1::{
    R1StateDomain, R1StateError, R1StateKey, R1StateMap, R1StateValue, MAX_STATE_ENTRIES,
};
use crate::world_resources::{WorldResourceBudget, WorldResourcePermit};
use serde::{Deserialize, Serialize};
use std::{
    cell::Cell,
    collections::BTreeSet,
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant},
};
use synergy_address::r1_public::{NativeIdentityPresentation, TransactionIdentifierPresentation};
use synergy_protocol_types::{
    R1GenesisReference, R1NetworkCoordinate, R1NetworkRef, R1ProfileRef, R1ProfileSetReference,
};
use synergy_storage::{
    AtomicStore, AtomicStoreReader, RequiredRecord, StoragePrecondition, StorageTransaction,
};

const MAX_RECORD: usize = 128 * 1024 * 1024;
// Existing AtomicStore cap is1024 writes. Head+snapshot+block index consume3;
// this projection backend refuses larger blocks instead of publishing partially.
const MAX_TRANSACTIONS: usize = 1021;
const MAX_PROOF: usize = 4 * 1024 * 1024;
const HEAD: &str = "r1/current.json";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum R1TransactionStatus {
    Applied,
    Reverted,
    ResourceExhausted,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct R1FinalizedAnchor {
    pub coordinate: R1NetworkCoordinate,
    pub height: u64,
    pub block_digest: [u8; 48],
    pub state_root: [u8; 48],
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct R1AccountRead {
    pub anchor: R1FinalizedAnchor,
    pub identity: String,
    pub balance_nwei: u128,
    pub nonce: u64,
    pub policy_epoch: Option<u64>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct R1TransactionRead {
    pub anchor: R1FinalizedAnchor,
    pub transaction_id: String,
    pub status: R1TransactionStatus,
    pub gas_used: u64,
    pub fee_paid_nwei: u128,
    pub events_commitment: [u8; 48],
    pub error_code: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct R1BlockRead {
    pub anchor: R1FinalizedAnchor,
    pub parent_block_digest: [u8; 48],
    pub epoch: u64,
    pub transactions: Vec<String>,
    pub receipts_root: [u8; 48],
    pub public_finality_proof: Vec<u8>,
    pub block_profile: R1ProfileRef,
    pub receipt_profile: R1ProfileRef,
}

// This strict local storage codec is not a consensus codec or an RPC envelope.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Profile {
    name: String,
    revision: u32,
}
impl From<&R1ProfileRef> for Profile {
    fn from(p: &R1ProfileRef) -> Self {
        Self {
            name: p.name.clone(),
            revision: p.revision,
        }
    }
}
impl Profile {
    fn typed(&self) -> Result<R1ProfileRef, R1StateError> {
        let p = R1ProfileRef {
            name: self.name.clone(),
            revision: self.revision,
        };
        p.validate().map_err(|_| R1StateError::InvalidProfile)?;
        Ok(p)
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Coordinate {
    chain_id: u64,
    nic: Vec<u8>,
    genesis_profile: Profile,
    genesis_digest: Vec<u8>,
    profiles_profile: Profile,
    profiles_commitment: Vec<u8>,
}
impl From<&R1NetworkCoordinate> for Coordinate {
    fn from(c: &R1NetworkCoordinate) -> Self {
        Self {
            chain_id: c.network.chain_id,
            nic: c.network.nic.to_vec(),
            genesis_profile: (&c.genesis.profile).into(),
            genesis_digest: c.genesis.digest.to_vec(),
            profiles_profile: (&c.activated_profiles.profile).into(),
            profiles_commitment: c.activated_profiles.commitment.to_vec(),
        }
    }
}
impl Coordinate {
    fn typed(&self) -> Result<R1NetworkCoordinate, R1StateError> {
        let c = R1NetworkCoordinate {
            network: R1NetworkRef {
                chain_id: self.chain_id,
                nic: fixed(&self.nic)?,
            },
            genesis: R1GenesisReference {
                profile: self.genesis_profile.typed()?,
                digest: fixed(&self.genesis_digest)?,
            },
            activated_profiles: R1ProfileSetReference {
                profile: self.profiles_profile.typed()?,
                commitment: fixed(&self.profiles_commitment)?,
            },
        };
        c.validate().map_err(|_| R1StateError::Context)?;
        Ok(c)
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Head {
    schema: u16,
    coordinate: Coordinate,
    height: u64,
    block_digest: Vec<u8>,
    state_root: Vec<u8>,
}
impl From<&R1FinalizedAnchor> for Head {
    fn from(a: &R1FinalizedAnchor) -> Self {
        Self {
            schema: 1,
            coordinate: (&a.coordinate).into(),
            height: a.height,
            block_digest: a.block_digest.to_vec(),
            state_root: a.state_root.to_vec(),
        }
    }
}
impl Head {
    fn typed(&self, expected: &R1NetworkCoordinate) -> Result<R1FinalizedAnchor, R1StateError> {
        if self.schema != 1 {
            return Err(R1StateError::Corrupt);
        }
        let coordinate = self.coordinate.typed()?;
        coordinate
            .ensure_matches(expected)
            .map_err(|_| R1StateError::Context)?;
        Ok(R1FinalizedAnchor {
            coordinate,
            height: self.height,
            block_digest: fixed(&self.block_digest)?,
            state_root: fixed(&self.state_root)?,
        })
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Transaction {
    id: String,
    status: R1TransactionStatus,
    gas_used: u64,
    #[serde(with = "crate::r1::decimal_u128")]
    fee_paid_nwei: u128,
    events_commitment: Vec<u8>,
    error_code: Option<String>,
}
impl Transaction {
    fn validate(&self) -> Result<(), R1StateError> {
        TransactionIdentifierPresentation::parse(&self.id).map_err(|_| R1StateError::Corrupt)?;
        let _: [u8; 48] = fixed(&self.events_commitment)?;
        if self.error_code.as_ref().is_some_and(|s| {
            s.is_empty() || s.len() > 128 || !s.bytes().all(|b| b.is_ascii_graphic())
        }) {
            return Err(R1StateError::Corrupt);
        }
        if self.status == R1TransactionStatus::Applied && self.error_code.is_some() {
            return Err(R1StateError::Corrupt);
        }
        Ok(())
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Snapshot {
    head: Head,
    parent: Vec<u8>,
    epoch: u64,
    block_profile: Profile,
    receipt_profile: Profile,
    receipts_root: Vec<u8>,
    proof: Vec<u8>,
    state: Vec<(R1StateKey, R1StateValue)>,
    transactions: Vec<Transaction>,
}
impl Snapshot {
    fn validate(
        &self,
        expected: &R1NetworkCoordinate,
    ) -> Result<(R1FinalizedAnchor, R1StateMap), R1StateError> {
        self.validate_with(expected, |s| s.root(), || Ok(()))
    }
    fn validate_with(
        &self,
        expected: &R1NetworkCoordinate,
        root: impl FnOnce(&R1StateMap) -> Result<[u8; 48], R1StateError>,
        mut check: impl FnMut() -> Result<(), R1StateError>,
    ) -> Result<(R1FinalizedAnchor, R1StateMap), R1StateError> {
        let anchor = self.head.typed(expected)?;
        let _: [u8; 48] = fixed(&self.parent)?;
        let _: [u8; 48] = fixed(&self.receipts_root)?;
        self.block_profile.typed()?;
        self.receipt_profile.typed()?;
        if self.state.len() > MAX_STATE_ENTRIES
            || self.transactions.len() > MAX_TRANSACTIONS
            || self.proof.len() > MAX_PROOF
            || (anchor.height > 0 && self.proof.is_empty())
        {
            return Err(R1StateError::ResourceLimit);
        }
        let mut state = R1StateMap::new();
        for (k, v) in &self.state {
            check()?;
            if state.insert(k.clone(), v.clone())?.is_some() {
                return Err(R1StateError::Duplicate);
            }
        }
        if root(&state)? != anchor.state_root {
            return Err(R1StateError::Corrupt);
        }
        let mut ids = BTreeSet::new();
        for t in &self.transactions {
            check()?;
            t.validate()?;
            if !ids.insert(&t.id) {
                return Err(R1StateError::Duplicate);
            }
        }
        Ok((anchor, state))
    }
    fn block(&self, anchor: R1FinalizedAnchor) -> Result<R1BlockRead, R1StateError> {
        Ok(R1BlockRead {
            anchor,
            parent_block_digest: fixed(&self.parent)?,
            epoch: self.epoch,
            transactions: self.transactions.iter().map(|t| t.id.clone()).collect(),
            receipts_root: fixed(&self.receipts_root)?,
            public_finality_proof: self.proof.clone(),
            block_profile: self.block_profile.typed()?,
            receipt_profile: self.receipt_profile.typed()?,
        })
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Index {
    height: u64,
}
fn fixed<const N: usize>(b: &[u8]) -> Result<[u8; N], R1StateError> {
    b.try_into().map_err(|_| R1StateError::Corrupt)
}
fn encode<T: Serialize>(v: &T) -> Result<Vec<u8>, R1StateError> {
    let bytes = serde_json::to_vec(v).map_err(|_| R1StateError::Corrupt)?;
    if bytes.len() > MAX_RECORD {
        return Err(R1StateError::ResourceLimit);
    }
    Ok(bytes)
}
fn decode<T: serde::de::DeserializeOwned>(b: &[u8]) -> Result<T, R1StateError> {
    if b.len() > MAX_RECORD {
        return Err(R1StateError::ResourceLimit);
    }
    serde_json::from_slice(b).map_err(|_| R1StateError::Corrupt)
}
fn storage(e: synergy_storage::StorageError) -> R1StateError {
    R1StateError::Storage(e.to_string())
}
fn hex(b: &[u8]) -> String {
    const C: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(b.len() * 2);
    for v in b {
        s.push(C[(v >> 4) as usize] as char);
        s.push(C[(v & 15) as usize] as char)
    }
    s
}
fn snapshot_path(height: u64) -> String {
    format!("r1/blocks/{height:020}.json")
}
fn digest_path(d: &[u8; 48]) -> String {
    format!("r1/block-index/{}.json", hex(d))
}
fn tx_path(id: &TransactionIdentifierPresentation) -> String {
    format!(
        "r1/tx-index/{}-{}.json",
        &id.to_text()[..6],
        hex(id.digest48())
    )
}
fn read<T: serde::de::DeserializeOwned>(
    r: &AtomicStoreReader<'_>,
    path: &str,
) -> Result<Option<T>, R1StateError> {
    r.with_maximum_bytes(8192)
        .read_optional_bounded(path)
        .map_err(storage)?
        .map(|b| decode(&b))
        .transpose()
}

/// A captured read coordinate. Every query reads immutable records under the
/// producer's storage lock and refuses a different incarnation or a future row.
pub struct R1FinalizedStore {
    root: PathBuf,
    expected: R1NetworkCoordinate,
    anchor: Option<R1FinalizedAnchor>,
    budget: Arc<WorldResourceBudget>,
    deadline: Instant,
    remaining_hashes: Cell<u64>,
}
struct ChargedSnapshot {
    snapshot: Snapshot,
    state_map: R1StateMap,
    anchor: R1FinalizedAnchor,
    _permit: WorldResourcePermit,
}
impl std::ops::Deref for ChargedSnapshot {
    type Target = Snapshot;
    fn deref(&self) -> &Snapshot {
        &self.snapshot
    }
}
impl R1FinalizedStore {
    /// Isolated fixture convenience only. Runtime MUST use its shared budget.
    pub fn open(
        root: impl AsRef<Path>,
        expected: &R1NetworkCoordinate,
    ) -> Result<Self, R1StateError> {
        synergy_address::r1_public::require_nonproduction_fixture(expected.network.chain_id)
            .map_err(|_| R1StateError::CeremonyRequired)?;
        Self::open_with_budget(
            root,
            expected,
            WorldResourceBudget::new(64 * 1024 * 1024),
            Instant::now() + Duration::from_secs(30),
            1_000_000,
        )
    }
    pub fn open_with_budget(
        root: impl AsRef<Path>,
        expected: &R1NetworkCoordinate,
        budget: Arc<WorldResourceBudget>,
        deadline: Instant,
        maximum_hashes: u64,
    ) -> Result<Self, R1StateError> {
        if Instant::now() >= deadline || maximum_hashes == 0 {
            return Err(R1StateError::ResourceLimit);
        }
        let _meta = budget
            .reserve(128 * 1024)
            .map_err(|_| R1StateError::ResourceLimit)?;
        expected.validate().map_err(|_| R1StateError::Context)?;
        let root = root.as_ref().to_path_buf();
        let anchor = AtomicStore::inspect_existing_read_only(
            &root,
            MAX_RECORD,
            |r| -> Result<_, R1StateError> {
                let h: Option<Head> = read(r, HEAD)?;
                h.map(|h| h.typed(expected)).transpose()
            },
        )
        .map_err(storage)?
        .transpose()?
        .flatten();
        Ok(Self {
            root,
            expected: expected.clone(),
            anchor,
            budget,
            deadline,
            remaining_hashes: Cell::new(maximum_hashes),
        })
    }
    pub fn current_anchor(&self) -> Option<&R1FinalizedAnchor> {
        self.anchor.as_ref()
    }
    fn inspect<T>(
        &self,
        f: impl FnOnce(&AtomicStoreReader<'_>) -> Result<Option<T>, R1StateError>,
    ) -> Result<Option<T>, R1StateError> {
        self.check_deadline()?;
        let _meta = self
            .budget
            .reserve(128 * 1024)
            .map_err(|_| R1StateError::ResourceLimit)?;
        AtomicStore::inspect_existing_read_only(&self.root, MAX_RECORD, f)
            .map_err(storage)?
            .transpose()
            .map(Option::flatten)
    }
    fn check_deadline(&self) -> Result<(), R1StateError> {
        if Instant::now() >= self.deadline {
            Err(R1StateError::ResourceLimit)
        } else {
            Ok(())
        }
    }
    fn snapshot(
        &self,
        r: &AtomicStoreReader<'_>,
        height: u64,
    ) -> Result<Option<ChargedSnapshot>, R1StateError> {
        if self.anchor.as_ref().is_none_or(|a| height > a.height) {
            return Ok(None);
        }
        self.check_deadline()?;
        let path = snapshot_path(height);
        let Some(bytes) = r.optional_record_bytes(&path).map_err(storage)? else {
            return Ok(None);
        };
        // Covers encoded bytes, serde growth/escape scratch, retained typed
        // records, duplicate authenticated map, sort/root scratch and result
        // projection cloning. Reserve BEFORE the bounded file read/decode.
        let charge = bytes
            .checked_mul(512)
            .and_then(|n| n.checked_add(256 * 1024))
            .ok_or(R1StateError::ResourceLimit)?;
        let permit = self
            .budget
            .reserve(charge)
            .map_err(|_| R1StateError::ResourceLimit)?;
        let payload = r
            .read_optional_bounded(&path)
            .map_err(storage)?
            .ok_or(R1StateError::Unavailable)?;
        let s: Snapshot = decode(&payload)?;
        drop(payload);
        let (a, state_map) = s.validate_with(
            &self.expected,
            |state| {
                let mut remaining = self.remaining_hashes.get();
                let result = crate::r1_smt::root_with_limits(state, self.deadline, &mut remaining);
                self.remaining_hashes.set(remaining);
                result
            },
            || self.check_deadline(),
        )?;
        if a.height != height {
            return Err(R1StateError::Corrupt);
        }
        if let Some(head) = &self.anchor {
            if height == head.height && &a != head {
                return Err(R1StateError::Corrupt);
            }
        }
        Ok(Some(ChargedSnapshot {
            snapshot: s,
            state_map,
            anchor: a,
            _permit: permit,
        }))
    }
    pub fn account(
        &self,
        id: &NativeIdentityPresentation,
        height: Option<u64>,
    ) -> Result<Option<R1AccountRead>, R1StateError> {
        let Some(h) = height.or_else(|| self.anchor.as_ref().map(|a| a.height)) else {
            return Ok(None);
        };
        let identity = id.to_text();
        let key = R1StateKey::native(R1StateDomain::NativeBalance, &identity)?;
        self.inspect(|r| {
            let Some(s) = self.snapshot(r, h)? else {
                return Ok(None);
            };
            let anchor = s.anchor.clone();
            let state = &s.state_map;
            let Some(R1StateValue::NativeBalance { amount_nwei }) = state.get(&key) else {
                return Ok(None);
            };
            let replay = R1StateKey::native(R1StateDomain::ReplayCoordinate, &identity)?;
            let Some(R1StateValue::ReplayNonce { nonce }) = state.get(&replay) else {
                return Err(R1StateError::Corrupt);
            };
            let policy_epoch = if id.namespace() == "synq" {
                None
            } else {
                let policy = R1StateKey::native(R1StateDomain::AccountAuthorization, &identity)?;
                match state.get(&policy) {
                    Some(R1StateValue::AccountPolicy { policy_epoch, .. }) => Some(*policy_epoch),
                    _ => return Err(R1StateError::Corrupt),
                }
            };
            Ok(Some(R1AccountRead {
                anchor,
                identity,
                balance_nwei: *amount_nwei,
                nonce: *nonce,
                policy_epoch,
            }))
        })
    }
    pub fn block(&self, height: u64) -> Result<Option<R1BlockRead>, R1StateError> {
        self.inspect(|r| {
            self.snapshot(r, height)?
                .map(|s| {
                    let a = s.head.typed(&self.expected)?;
                    s.block(a)
                })
                .transpose()
        })
    }
    pub fn block_by_digest(&self, digest: [u8; 48]) -> Result<Option<R1BlockRead>, R1StateError> {
        self.inspect(|r| {
            let Some(i): Option<Index> = read(r, &digest_path(&digest))? else {
                return Ok(None);
            };
            let Some(s) = self.snapshot(r, i.height)? else {
                return Ok(None);
            };
            let a = s.head.typed(&self.expected)?;
            if a.block_digest != digest {
                return Err(R1StateError::Corrupt);
            }
            Ok(Some(s.block(a)?))
        })
    }
    pub fn transaction(
        &self,
        id: &TransactionIdentifierPresentation,
    ) -> Result<Option<R1TransactionRead>, R1StateError> {
        self.inspect(|r| {
            let Some(i): Option<Index> = read(r, &tx_path(id))? else {
                return Ok(None);
            };
            let Some(s) = self.snapshot(r, i.height)? else {
                return Ok(None);
            };
            let text = id.to_text();
            let Some(t) = s.transactions.iter().find(|t| t.id == text) else {
                return Err(R1StateError::Corrupt);
            };
            Ok(Some(R1TransactionRead {
                anchor: s.head.typed(&self.expected)?,
                transaction_id: text,
                status: t.status,
                gas_used: t.gas_used,
                fee_paid_nwei: t.fee_paid_nwei,
                events_commitment: fixed(&t.events_commitment)?,
                error_code: t.error_code.clone(),
            }))
        })
    }
}

/// Atomic synthetic projection qualification. This is deliberately not a
/// production-finality API; caller-supplied proof bytes convey no authority.
pub fn publish_nonproduction_projection(
    root: impl AsRef<Path>,
    block: &R1BlockRead,
    state: &R1StateMap,
    transactions: &[R1TransactionRead],
) -> Result<bool, R1StateError> {
    synergy_address::r1_public::require_nonproduction_fixture(
        block.anchor.coordinate.network.chain_id,
    )
    .map_err(|_| R1StateError::CeremonyRequired)?;
    if transactions.len() > MAX_TRANSACTIONS || block.transactions.len() > MAX_TRANSACTIONS {
        return Err(R1StateError::ResourceLimit);
    }
    if transactions.len() != block.transactions.len() {
        return Err(R1StateError::Corrupt);
    }
    let mut txs = Vec::new();
    for (id, t) in block.transactions.iter().zip(transactions) {
        if id != &t.transaction_id || t.anchor != block.anchor {
            return Err(R1StateError::Context);
        }
        txs.push(Transaction {
            id: id.clone(),
            status: t.status,
            gas_used: t.gas_used,
            fee_paid_nwei: t.fee_paid_nwei,
            events_commitment: t.events_commitment.to_vec(),
            error_code: t.error_code.clone(),
        })
    }
    let s = Snapshot {
        head: (&block.anchor).into(),
        parent: block.parent_block_digest.to_vec(),
        epoch: block.epoch,
        block_profile: (&block.block_profile).into(),
        receipt_profile: (&block.receipt_profile).into(),
        receipts_root: block.receipts_root.to_vec(),
        proof: block.public_finality_proof.clone(),
        state: state
            .entries()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect(),
        transactions: txs,
    };
    s.validate(&block.anchor.coordinate)?;
    let payload = encode(&s)?;
    let new_head = encode(&s.head)?;
    // Read old generation and verify monotonic parent continuity before constructing
    // any writer. CAS below checks the identical bytes under its commit lock.
    let old = AtomicStore::inspect_existing_read_only(
        root.as_ref(),
        MAX_RECORD,
        |r| -> Result<_, R1StateError> {
            let old = r.read_optional_bounded(HEAD).map_err(storage)?;
            let existing = r
                .read_optional_bounded(snapshot_path(block.anchor.height))
                .map_err(storage)?;
            Ok((old, existing))
        },
    )
    .map_err(storage)?
    .transpose()?
    .unwrap_or((None, None));
    if let Some(existing) = old.1 {
        if existing != payload {
            return Err(R1StateError::Corrupt);
        }
        return Ok(false);
    }
    match &old.0 {
        Some(b) => {
            let h: Head = decode(b)?;
            let a = h.typed(&block.anchor.coordinate)?;
            if a.height.checked_add(1) != Some(block.anchor.height)
                || a.block_digest != block.parent_block_digest
            {
                return Err(R1StateError::Context);
            }
        }
        None => {
            if block.anchor.height != 0 || block.parent_block_digest != [0; 48] {
                return Err(R1StateError::Context);
            }
        }
    }
    let mut transaction =
        StorageTransaction::new(MAX_RECORD.checked_mul(2).ok_or(R1StateError::Overflow)?)
            .map_err(storage)?;
    let mut guards = vec![StoragePrecondition {
        relative_path: HEAD.into(),
        required: old
            .0
            .map(RequiredRecord::Exact)
            .unwrap_or(RequiredRecord::Missing),
    }];
    transaction.put(HEAD, new_head).map_err(storage)?;
    let mut immutable = vec![
        (snapshot_path(block.anchor.height), payload),
        (
            digest_path(&block.anchor.block_digest),
            encode(&Index {
                height: block.anchor.height,
            })?,
        ),
    ];
    for id in &block.transactions {
        let id = TransactionIdentifierPresentation::parse(id).map_err(|_| R1StateError::Corrupt)?;
        immutable.push((
            tx_path(&id),
            encode(&Index {
                height: block.anchor.height,
            })?,
        ))
    }
    for (path, bytes) in immutable {
        guards.push(StoragePrecondition {
            relative_path: path.clone().into(),
            required: RequiredRecord::MissingOrSameWrite,
        });
        transaction.put(path, bytes).map_err(storage)?
    }
    let mut store = AtomicStore::new(root.as_ref(), MAX_RECORD).map_err(storage)?;
    transaction
        .commit_guarded(&mut store, &guards)
        .map_err(storage)?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQ: AtomicU64 = AtomicU64::new(0);
    #[test]
    fn shared_read_memory_work_and_deadline_limits_release_on_every_failure() {
        let temp = Temp::new();
        let expected = coordinate();
        let tiny = WorldResourceBudget::new(1);
        assert!(matches!(
            R1FinalizedStore::open_with_budget(
                &temp.0,
                &expected,
                tiny.clone(),
                Instant::now() + Duration::from_secs(5),
                1000
            ),
            Err(R1StateError::ResourceLimit)
        ));
        assert_eq!(tiny.used(), 0);
        assert!(!temp.0.exists());
        let (block, state, tx) = fixture(0, [0; 48]);
        publish_nonproduction_projection(&temp.0, &block, &state, &tx).unwrap();
        let small = WorldResourceBudget::new(128 * 1024);
        let reader = R1FinalizedStore::open_with_budget(
            &temp.0,
            &expected,
            small.clone(),
            Instant::now() + Duration::from_secs(5),
            1_000_000,
        )
        .unwrap();
        assert_eq!(reader.block(0), Err(R1StateError::ResourceLimit));
        assert_eq!(small.used(), 0);
        let budget = WorldResourceBudget::new(64 * 1024 * 1024);
        let exhausted = R1FinalizedStore::open_with_budget(
            &temp.0,
            &expected,
            budget.clone(),
            Instant::now() + Duration::from_secs(5),
            1,
        )
        .unwrap();
        assert_eq!(exhausted.block(0), Err(R1StateError::ResourceLimit));
        assert_eq!(budget.used(), 0);
        assert!(matches!(
            R1FinalizedStore::open_with_budget(
                &temp.0,
                &expected,
                budget.clone(),
                Instant::now(),
                1000
            ),
            Err(R1StateError::ResourceLimit)
        ));
        let pressure = budget.reserve(budget.limit()).unwrap();
        assert!(matches!(
            R1FinalizedStore::open_with_budget(
                &temp.0,
                &expected,
                budget.clone(),
                Instant::now() + Duration::from_secs(5),
                1000
            ),
            Err(R1StateError::ResourceLimit)
        ));
        assert_eq!(budget.used(), pressure.bytes());
        drop(pressure);
        assert_eq!(budget.used(), 0);
        let reader = R1FinalizedStore::open_with_budget(
            &temp.0,
            &expected,
            budget.clone(),
            Instant::now() + Duration::from_secs(5),
            1_000_000,
        )
        .unwrap();
        assert_eq!(reader.block(0).unwrap(), Some(block));
        assert_eq!(budget.used(), 0);
    }
    struct Temp(PathBuf);
    impl Temp {
        fn new() -> Self {
            Self(std::env::temp_dir().join(format!(
                "synergy-r1-projection-{}-{}",
                std::process::id(),
                SEQ.fetch_add(1, Ordering::Relaxed)
            )))
        }
    }
    impl Drop for Temp {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    fn profile(name: &str) -> R1ProfileRef {
        R1ProfileRef {
            name: name.into(),
            revision: 1,
        }
    }
    fn coordinate() -> R1NetworkCoordinate {
        R1NetworkCoordinate {
            network: R1NetworkRef {
                chain_id: u64::MAX - 1,
                nic: [1; 64],
            },
            genesis: R1GenesisReference {
                profile: profile("SYNTHETIC-GENESIS"),
                digest: [2; 48],
            },
            activated_profiles: R1ProfileSetReference {
                profile: profile("SYNTHETIC-PROFILES"),
                commitment: [3; 64],
            },
        }
    }
    fn fixture(height: u64, parent: [u8; 48]) -> (R1BlockRead, R1StateMap, Vec<R1TransactionRead>) {
        let id = NativeIdentityPresentation::from_raw("synq", [42; 48])
            .unwrap()
            .to_text();
        let mut state = R1StateMap::new();
        state
            .insert(
                R1StateKey::native(R1StateDomain::NativeBalance, &id).unwrap(),
                R1StateValue::NativeBalance {
                    amount_nwei: u128::MAX - u128::from(height),
                },
            )
            .unwrap();
        state
            .insert(
                R1StateKey::native(R1StateDomain::ReplayCoordinate, &id).unwrap(),
                R1StateValue::ReplayNonce { nonce: height },
            )
            .unwrap();
        let anchor = R1FinalizedAnchor {
            coordinate: coordinate(),
            height,
            block_digest: [height as u8 + 10; 48],
            state_root: state.root().unwrap(),
        };
        let txid =
            TransactionIdentifierPresentation::from_digest("syntxn", [height as u8 + 20; 48])
                .unwrap()
                .to_text();
        let tx = R1TransactionRead {
            anchor: anchor.clone(),
            transaction_id: txid.clone(),
            status: R1TransactionStatus::Applied,
            gas_used: 7,
            fee_paid_nwei: 9,
            events_commitment: [31; 48],
            error_code: None,
        };
        let block = R1BlockRead {
            anchor,
            parent_block_digest: parent,
            epoch: 0,
            transactions: vec![txid],
            receipts_root: [32; 48],
            public_finality_proof: vec![0x53, 0x59, 0x4e],
            block_profile: profile("SYNTHETIC-BLOCK"),
            receipt_profile: profile("SYNTHETIC-RECEIPT"),
        };
        (block, state, vec![tx])
    }
    #[test]
    fn atomic_projection_reads_historical_state_and_exact_indexes() {
        let temp = Temp::new();
        let expected = coordinate();
        assert!(R1FinalizedStore::open(&temp.0, &expected)
            .unwrap()
            .current_anchor()
            .is_none());
        assert!(!temp.0.exists());
        let (block, state, tx) = fixture(0, [0; 48]);
        assert!(publish_nonproduction_projection(&temp.0, &block, &state, &tx).unwrap());
        assert!(!publish_nonproduction_projection(&temp.0, &block, &state, &tx).unwrap());
        let captured = R1FinalizedStore::open(&temp.0, &expected).unwrap();
        assert_eq!(captured.block(0).unwrap(), Some(block.clone()));
        assert_eq!(
            captured.block_by_digest(block.anchor.block_digest).unwrap(),
            Some(block.clone())
        );
        let id = TransactionIdentifierPresentation::parse(&tx[0].transaction_id).unwrap();
        assert_eq!(captured.transaction(&id).unwrap(), Some(tx[0].clone()));
        let account = NativeIdentityPresentation::from_raw("synq", [42; 48]).unwrap();
        let read = captured.account(&account, None).unwrap().unwrap();
        assert_eq!(read.balance_nwei, u128::MAX);
        assert_eq!(read.policy_epoch, None);
        let (next, next_state, next_tx) = fixture(1, block.anchor.block_digest);
        assert!(publish_nonproduction_projection(&temp.0, &next, &next_state, &next_tx).unwrap());
        assert!(captured.block(1).unwrap().is_none()); // captured snapshot never changes
        let current = R1FinalizedStore::open(&temp.0, &expected).unwrap();
        assert_eq!(current.current_anchor(), Some(&next.anchor));
        assert_eq!(
            current
                .account(&account, Some(0))
                .unwrap()
                .unwrap()
                .balance_nwei,
            u128::MAX
        );
        assert_eq!(current.account(&account, None).unwrap().unwrap().nonce, 1);
        assert!(current.block(2).unwrap().is_none());
        let mut wrong = expected.clone();
        wrong.network.nic[63] ^= 1;
        assert!(matches!(
            R1FinalizedStore::open(&temp.0, &wrong),
            Err(R1StateError::Context)
        ));
    }
    #[test]
    fn publication_rejects_conflicts_partial_state_and_production_before_io() {
        let temp = Temp::new();
        let (mut block, state, mut tx) = fixture(0, [0; 48]);
        block.anchor.coordinate.network.chain_id = 9969;
        tx[0].anchor = block.anchor.clone();
        assert_eq!(
            publish_nonproduction_projection(&temp.0, &block, &state, &tx),
            Err(R1StateError::CeremonyRequired)
        );
        assert!(!temp.0.exists());
        let (block, state, tx) = fixture(0, [0; 48]);
        publish_nonproduction_projection(&temp.0, &block, &state, &tx).unwrap();
        let mut conflict = block.clone();
        conflict.epoch = 1;
        assert!(publish_nonproduction_projection(&temp.0, &conflict, &state, &tx).is_err());
        let (mut next, state, mut tx) = fixture(1, [99; 48]);
        assert!(publish_nonproduction_projection(&temp.0, &next, &state, &tx).is_err());
        next.parent_block_digest = block.anchor.block_digest;
        next.anchor.state_root[47] ^= 1;
        tx[0].anchor = next.anchor.clone();
        assert!(publish_nonproduction_projection(&temp.0, &next, &state, &tx).is_err());
        let store = R1FinalizedStore::open(&temp.0, &coordinate()).unwrap();
        assert_eq!(store.current_anchor(), Some(&block.anchor));
        assert!(store.block(1).unwrap().is_none());
    }
    #[test]
    fn corrupted_immutable_state_never_becomes_an_authoritative_zero() {
        let temp = Temp::new();
        let (block, state, tx) = fixture(0, [0; 48]);
        publish_nonproduction_projection(&temp.0, &block, &state, &tx).unwrap();
        let path = temp.0.join(snapshot_path(0));
        let mut s: Snapshot = decode(&std::fs::read(&path).unwrap()).unwrap();
        s.state.clear();
        std::fs::write(path, encode(&s).unwrap()).unwrap();
        let store = R1FinalizedStore::open(&temp.0, &coordinate()).unwrap();
        assert_eq!(store.block(0), Err(R1StateError::Corrupt));
    }
}
