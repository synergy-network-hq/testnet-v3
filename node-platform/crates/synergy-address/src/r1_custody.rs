//! Native custody durability adapter. This owns no cryptosystem or issuer.
//! Reserve before provider/RNG, fence ambiguous attempts, seal before publication.
//! The public preparation constructor is isolated to nonproduction coordinates;
//! actual managed authorization must enter through the existing native lifecycle.
use serde::{Deserialize, Serialize};
use std::{fs, path::Path};
use synergy_address_engine::{
    apqe::{custody_binding_r1::CustodyBinding, r1_framing::NetworkRef},
    encrypt::{bound_envelope_commitment, EncryptedEnvelope},
};
use synergy_storage::{
    AtomicStore, RequiredRecord, StoragePrecondition, StorageTransaction, StorageWrite,
};

const MAX_RECORD: usize = 2 * 1024 * 1024;
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CustodyJournalError {
    CeremonyRequired,
    PlatformUnqualified,
    InvalidIntent,
    Conflict,
    AmbiguousGeneration,
    InvalidStage,
    InvalidSeal,
    Storage,
    Corrupt,
}
impl std::fmt::Display for CustodyJournalError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "native R1 custody {:?}", self)
    }
}
impl std::error::Error for CustodyJournalError {}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CustodyStage {
    Reserved,
    Generating,
    SealedPending,
    Retired,
}
/// This contains only exact public request bindings, never private key material.
/// Scope commitment is produced by APQE before key generation and recomputed
/// from the final typed binding. A digest alone never supplies owner authority.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CustodyCreationIntent {
    pub slot_ref: String,
    pub role: String,
    pub algorithm: String,
    pub key_generation: u64,
    pub operation_nonce: [u8; 32],
    pub native_request_digest: [u8; 32],
    pub creation_scope_commitment: [u8; 64],
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    schema: u16,
    chain_id: Option<u64>,
    nic: Option<Vec<u8>>,
    slot_ref: String,
    role: String,
    algorithm: String,
    key_generation: u64,
    operation_nonce: Vec<u8>,
    native_request_digest: Vec<u8>,
    creation_scope_commitment: Vec<u8>,
    journal_generation: u64,
    stage: CustodyStage,
    full_binding_aad: Option<Vec<u8>>,
    envelope_commitment: Option<Vec<u8>>,
    envelope: Option<EncryptedEnvelope>,
}
impl Record {
    fn intent(&self) -> Result<CustodyCreationIntent, CustodyJournalError> {
        Ok(CustodyCreationIntent {
            slot_ref: self.slot_ref.clone(),
            role: self.role.clone(),
            algorithm: self.algorithm.clone(),
            key_generation: self.key_generation,
            operation_nonce: self
                .operation_nonce
                .as_slice()
                .try_into()
                .map_err(|_| CustodyJournalError::Corrupt)?,
            native_request_digest: self
                .native_request_digest
                .as_slice()
                .try_into()
                .map_err(|_| CustodyJournalError::Corrupt)?,
            creation_scope_commitment: self
                .creation_scope_commitment
                .as_slice()
                .try_into()
                .map_err(|_| CustodyJournalError::Corrupt)?,
        })
    }
    fn validate(&self, network: Option<NetworkRef>) -> Result<(), CustodyJournalError> {
        let matches = match (network, self.chain_id, &self.nic) {
            (None, None, None) => true,
            (Some(n), Some(chain), Some(nic)) => chain == n.chain_id && nic.as_slice() == n.nic,
            _ => false,
        };
        if self.schema != 1 || !matches || self.journal_generation == 0 {
            return Err(CustodyJournalError::Corrupt);
        }
        validate_intent(&self.intent()?)?;
        match self.stage {
            CustodyStage::Reserved | CustodyStage::Generating => {
                if self.full_binding_aad.is_some()
                    || self.envelope_commitment.is_some()
                    || self.envelope.is_some()
                {
                    return Err(CustodyJournalError::Corrupt);
                }
            }
            CustodyStage::SealedPending => {
                if self
                    .full_binding_aad
                    .as_ref()
                    .is_none_or(|v| v.is_empty() || v.len() > 1024 * 1024)
                    || self
                        .envelope_commitment
                        .as_ref()
                        .is_none_or(|v| v.len() != 64)
                    || self.envelope.as_ref().is_none_or(|e| e.version != 5)
                {
                    return Err(CustodyJournalError::Corrupt);
                }
            }
            CustodyStage::Retired => {
                if self.full_binding_aad.is_some()
                    || self.envelope_commitment.is_some()
                    || self.envelope.is_some()
                {
                    return Err(CustodyJournalError::Corrupt);
                }
            }
        }
        Ok(())
    }
}
fn text(s: &str) -> bool {
    !s.is_empty() && s.len() <= 128 && s.bytes().all(|b| b.is_ascii_graphic())
}
fn validate_intent(i: &CustodyCreationIntent) -> Result<(), CustodyJournalError> {
    if !text(&i.slot_ref)
        || i.slot_ref.len() > 120
        || !text(&i.role)
        || !matches!(
            i.algorithm.as_str(),
            "ML-DSA-65" | "ML-DSA-87" | "ML-KEM-1024"
        )
        || i.key_generation == 0
        || i.operation_nonce == [0; 32]
        || i.native_request_digest == [0; 32]
        || i.creation_scope_commitment == [0; 64]
    {
        Err(CustodyJournalError::InvalidIntent)
    } else {
        Ok(())
    }
}
fn hex(b: &[u8]) -> String {
    b.iter().map(|b| format!("{b:02x}")).collect()
}
fn slot_path(slot: &str) -> String {
    format!("slots/{}.json", hex(slot.as_bytes()))
}
fn operation_path(nonce: &[u8; 32]) -> String {
    format!("operations/{}.json", hex(nonce))
}
fn encode<T: Serialize>(v: &T) -> Result<Vec<u8>, CustodyJournalError> {
    let b = serde_json::to_vec(v).map_err(|_| CustodyJournalError::Corrupt)?;
    if b.len() > MAX_RECORD {
        return Err(CustodyJournalError::InvalidIntent);
    }
    Ok(b)
}
fn decode(b: &[u8]) -> Result<Record, CustodyJournalError> {
    serde_json::from_slice(b).map_err(|_| CustodyJournalError::Corrupt)
}

/// Opaque CAS snapshots cannot be constructed from a renderer boolean or a
/// caller's claim that a prior operation succeeded.
pub struct CustodyReservation {
    record: Record,
    bytes: Vec<u8>,
}
pub struct CustodyGenerationLease {
    record: Record,
    bytes: Vec<u8>,
}
pub struct SealedPendingCustody {
    record: Record,
    bytes: Vec<u8>,
}
impl SealedPendingCustody {
    pub fn key_generation(&self) -> u64 {
        self.record.key_generation
    }
    pub fn journal_generation(&self) -> u64 {
        self.record.journal_generation
    }
    pub fn envelope_commitment(&self) -> [u8; 64] {
        self.record
            .envelope_commitment
            .as_ref()
            .unwrap()
            .as_slice()
            .try_into()
            .unwrap()
    }
}
pub enum CustodyReservationResult {
    Reserved(CustodyReservation),
    AlreadySealed(SealedPendingCustody),
}
pub struct NativeCustodyJournal {
    store: AtomicStore,
    network: Option<NetworkRef>,
}
impl NativeCustodyJournal {
    /// Tests use a caller-owned private temporary root. This does not commission
    /// a platform or authorize the actual generation phase.
    pub fn for_nonproduction(
        root: impl AsRef<Path>,
        network: NetworkRef,
    ) -> Result<Self, CustodyJournalError> {
        synergy_address_engine::apqe::preparation::require_nonproduction_fixture(network.chain_id)
            .map_err(|_| CustodyJournalError::CeremonyRequired)?;
        if network.nic == [0; 64] {
            return Err(CustodyJournalError::InvalidIntent);
        }
        Self::open_fixture(root, Some(network))
    }
    /// Explicit pre-NIC public-fixture scope. No invented zero-NIC network or
    /// dependency on a root-set commitment before the first root is protected.
    pub fn for_public_bootstrap_fixture(
        root: impl AsRef<Path>,
    ) -> Result<Self, CustodyJournalError> {
        Self::open_fixture(root, None)
    }
    fn open_fixture(
        root: impl AsRef<Path>,
        network: Option<NetworkRef>,
    ) -> Result<Self, CustodyJournalError> {
        #[cfg(not(unix))]
        {
            let _ = root;
            return Err(CustodyJournalError::PlatformUnqualified);
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
            let root = root.as_ref();
            match fs::symlink_metadata(root) {
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    let parent = root.parent().ok_or(CustodyJournalError::Storage)?;
                    let m =
                        fs::symlink_metadata(parent).map_err(|_| CustodyJournalError::Storage)?;
                    if m.file_type().is_symlink() || !m.is_dir() {
                        return Err(CustodyJournalError::Storage);
                    }
                    fs::DirBuilder::new()
                        .mode(0o700)
                        .create(root)
                        .map_err(|_| CustodyJournalError::Storage)?;
                }
                Err(_) => return Err(CustodyJournalError::Storage),
                Ok(_) => {}
            }
            let m = fs::symlink_metadata(root).map_err(|_| CustodyJournalError::Storage)?;
            // SAFETY:geteuid reads process identity; it does not mutate credentials.
            if m.file_type().is_symlink()
                || !m.is_dir()
                || m.uid() != unsafe { libc::geteuid() }
                || m.permissions().mode() & 0o777 != 0o700
            {
                return Err(CustodyJournalError::Storage);
            }
            let store =
                AtomicStore::new(root, MAX_RECORD).map_err(|_| CustodyJournalError::Storage)?;
            let context = encode(&(
                1u16,
                "PUBLIC-SYNTHETIC-CUSTODY-JOURNAL",
                network.map(|n| (n.chain_id, n.nic.to_vec())),
            ))?;
            store
                .put_once_atomic(&[StorageWrite {
                    relative_path: "context.json".into(),
                    bytes: context,
                }])
                .map_err(|_| CustodyJournalError::Conflict)?;
            Ok(Self { store, network })
        }
    }
    fn current(&self, slot: &str) -> Result<Option<(Record, Vec<u8>)>, CustodyJournalError> {
        self.store
            .read_optional_bounded(slot_path(slot))
            .map_err(|_| CustodyJournalError::Storage)?
            .map(|bytes| {
                let r = decode(&bytes)?;
                r.validate(self.network)?;
                if r.slot_ref != slot {
                    return Err(CustodyJournalError::Corrupt);
                }
                Ok((r, bytes))
            })
            .transpose()
    }
    pub fn reserve(
        &mut self,
        intent: &CustodyCreationIntent,
        expected_key_generation: u64,
    ) -> Result<CustodyReservationResult, CustodyJournalError> {
        validate_intent(intent)?;
        if expected_key_generation.checked_add(1) != Some(intent.key_generation) {
            return Err(CustodyJournalError::Conflict);
        }
        let old = self.current(&intent.slot_ref)?;
        if let Some((r, bytes)) = &old {
            if r.intent()? == *intent {
                return match r.stage {
                    CustodyStage::Reserved => {
                        Ok(CustodyReservationResult::Reserved(CustodyReservation {
                            record: r.clone(),
                            bytes: bytes.clone(),
                        }))
                    }
                    CustodyStage::SealedPending => Ok(CustodyReservationResult::AlreadySealed(
                        SealedPendingCustody {
                            record: r.clone(),
                            bytes: bytes.clone(),
                        },
                    )),
                    CustodyStage::Generating => Err(CustodyJournalError::AmbiguousGeneration),
                    CustodyStage::Retired => Err(CustodyJournalError::Conflict),
                };
            }
            if r.stage != CustodyStage::Retired
                || r.key_generation != expected_key_generation
                || r.role != intent.role
            {
                return Err(CustodyJournalError::Conflict);
            }
        } else if expected_key_generation != 0 {
            return Err(CustodyJournalError::Conflict);
        }
        let r = Record {
            schema: 1,
            chain_id: self.network.map(|n| n.chain_id),
            nic: self.network.map(|n| n.nic.to_vec()),
            slot_ref: intent.slot_ref.clone(),
            role: intent.role.clone(),
            algorithm: intent.algorithm.clone(),
            key_generation: intent.key_generation,
            operation_nonce: intent.operation_nonce.to_vec(),
            native_request_digest: intent.native_request_digest.to_vec(),
            creation_scope_commitment: intent.creation_scope_commitment.to_vec(),
            journal_generation: old
                .as_ref()
                .map_or(Some(1), |(r, _)| r.journal_generation.checked_add(1))
                .ok_or(CustodyJournalError::Conflict)?,
            stage: CustodyStage::Reserved,
            full_binding_aad: None,
            envelope_commitment: None,
            envelope: None,
        };
        let bytes = encode(&r)?;
        let mut tx =
            StorageTransaction::new(2 * MAX_RECORD).map_err(|_| CustodyJournalError::Storage)?;
        tx.put(slot_path(&r.slot_ref), bytes.clone())
            .map_err(|_| CustodyJournalError::Storage)?;
        tx.put(operation_path(&intent.operation_nonce), bytes.clone())
            .map_err(|_| CustodyJournalError::Storage)?;
        let guards = [
            StoragePrecondition {
                relative_path: slot_path(&r.slot_ref).into(),
                required: old
                    .map(|(_, b)| RequiredRecord::Exact(b))
                    .unwrap_or(RequiredRecord::Missing),
            },
            StoragePrecondition {
                relative_path: operation_path(&intent.operation_nonce).into(),
                required: RequiredRecord::Missing,
            },
        ];
        tx.commit_guarded(&mut self.store, &guards)
            .map_err(|_| CustodyJournalError::Conflict)?;
        Ok(CustodyReservationResult::Reserved(CustodyReservation {
            record: r,
            bytes,
        }))
    }
    fn advance(
        &mut self,
        old: &[u8],
        mut record: Record,
        stage: CustodyStage,
    ) -> Result<(Record, Vec<u8>), CustodyJournalError> {
        record.stage = stage;
        record.journal_generation = record
            .journal_generation
            .checked_add(1)
            .ok_or(CustodyJournalError::Conflict)?;
        record.validate(self.network)?;
        let bytes = encode(&record)?;
        let mut tx =
            StorageTransaction::new(MAX_RECORD).map_err(|_| CustodyJournalError::Storage)?;
        tx.put(slot_path(&record.slot_ref), bytes.clone())
            .map_err(|_| CustodyJournalError::Storage)?;
        tx.commit_guarded(
            &mut self.store,
            &[StoragePrecondition {
                relative_path: slot_path(&record.slot_ref).into(),
                required: RequiredRecord::Exact(old.to_vec()),
            }],
        )
        .map_err(|_| CustodyJournalError::Conflict)?;
        Ok((record, bytes))
    }
    /// A second call, including after an ambiguous process exit, cannot begin RNG
    /// again under the same reservation. The generation remains burned.
    pub fn begin_generation(
        &mut self,
        reservation: &CustodyReservation,
    ) -> Result<CustodyGenerationLease, CustodyJournalError> {
        if reservation.record.stage != CustodyStage::Reserved {
            return Err(CustodyJournalError::InvalidStage);
        }
        let (record, bytes) = self.advance(
            &reservation.bytes,
            reservation.record.clone(),
            CustodyStage::Generating,
        )?;
        Ok(CustodyGenerationLease { record, bytes })
    }
    pub fn seal_generated(
        &mut self,
        lease: &CustodyGenerationLease,
        envelope: &EncryptedEnvelope,
        binding: &CustodyBinding<'_>,
    ) -> Result<SealedPendingCustody, CustodyJournalError> {
        if lease.record.stage != CustodyStage::Generating
            || binding.key.role != lease.record.role
            || binding.key.algorithm != lease.record.algorithm
            || binding.key.key_generation != lease.record.key_generation
        {
            return Err(CustodyJournalError::InvalidSeal);
        }
        use synergy_address_engine::apqe::custody_binding_r1::CustodyScope;
        match (&binding.scope, self.network) {
            (CustodyScope::BootstrapRoot { .. }, None)
                if binding.trust_domain == "PUBLIC-SYNTHETIC-ONLY" => {}
            (
                CustodyScope::Formation { network, .. } | CustodyScope::Runtime { network, .. },
                Some(expected),
            ) if network == &expected => {}
            _ => return Err(CustodyJournalError::InvalidSeal),
        }
        // APQE alone owns construction/validation of this pre-key scope commitment.
        let scope = binding
            .creation_scope_commitment()
            .map_err(|_| CustodyJournalError::InvalidSeal)?;
        if scope.as_slice() != lease.record.creation_scope_commitment {
            return Err(CustodyJournalError::InvalidSeal);
        }
        let aad = binding
            .canonical_aad()
            .map_err(|_| CustodyJournalError::InvalidSeal)?;
        let commit = bound_envelope_commitment(envelope, binding)
            .map_err(|_| CustodyJournalError::InvalidSeal)?;
        let mut record = lease.record.clone();
        record.full_binding_aad = Some(aad);
        record.envelope_commitment = Some(commit.to_vec());
        record.envelope = Some(envelope.clone());
        let (record, bytes) = self.advance(&lease.bytes, record, CustodyStage::SealedPending)?;
        Ok(SealedPendingCustody { record, bytes })
    }
    /// Deliberately destroys only this failed pending generation. Signing history
    /// and monotonically consumed operation/generation records are retained.
    pub fn retire_failed_generation(
        &mut self,
        lease: &CustodyGenerationLease,
    ) -> Result<(), CustodyJournalError> {
        let mut record = lease.record.clone();
        record.full_binding_aad = None;
        record.envelope_commitment = None;
        record.envelope = None;
        self.advance(&lease.bytes, record, CustodyStage::Retired)?;
        Ok(())
    }
    pub fn retained_sealed_bytes(&self, pending: &SealedPendingCustody) -> usize {
        pending.bytes.len()
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::{
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
    };
    static SEQUENCE: AtomicU64 = AtomicU64::new(0);
    struct Temp(PathBuf);
    impl Temp {
        fn new() -> Self {
            Self(std::env::temp_dir().join(format!(
                "synergy-r1-custody-journal-{}-{}",
                std::process::id(),
                SEQUENCE.fetch_add(1, Ordering::Relaxed)
            )))
        }
    }
    impl Drop for Temp {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    fn network() -> NetworkRef {
        NetworkRef {
            chain_id: u64::MAX - 1,
            nic: [13; 64],
        }
    }
    fn intent() -> CustodyCreationIntent {
        CustodyCreationIntent {
            slot_ref: "PUBLIC-SYNTHETIC-SLOT".into(),
            role: "consensus".into(),
            algorithm: "ML-DSA-65".into(),
            key_generation: 1,
            operation_nonce: [21; 32],
            native_request_digest: [22; 32],
            creation_scope_commitment: [23; 64],
        }
    }
    #[test]
    fn genuine_public_native_v5_fixture_is_sealed_atomically_and_resumes_without_rng() {
        use synergy_address_engine::apqe::{
            custody_binding_r1::CustodyScope,
            network_birth_r1::{BootstrapKeyRecord, ProfileRef},
        };
        let v:serde_json::Value=serde_json::from_str(include_str!("../../../../../21-Aegis-Engine/synergy-address-engine/tests/fixtures/r1_bound_custody_public.json")).unwrap();
        assert_eq!(v["production_import_permitted"], false);
        let public = hex::decode(v["full_public_key_hex"].as_str().unwrap()).unwrap();
        let envelope: EncryptedEnvelope = serde_json::from_value(v["envelope"].clone()).unwrap();
        let scope = CustodyScope::BootstrapRoot {
            custody_policy: ProfileRef {
                name: v["custody_policy"][0].as_str().unwrap(),
                revision: 1,
            },
            custody_object_ref: v["custody_object_ref"].as_str().unwrap(),
        };
        let binding = CustodyBinding {
            scope,
            key: BootstrapKeyRecord {
                role: v["role"].as_str().unwrap(),
                algorithm: "ML-DSA-87",
                key_generation: 1,
                full_public_key: &public,
            },
            trust_domain: "PUBLIC-SYNTHETIC-ONLY",
        };
        let mut i = intent();
        i.role = "root".into();
        i.algorithm = "ML-DSA-87".into();
        i.creation_scope_commitment = binding.creation_scope_commitment().unwrap();
        assert_eq!(
            hex::encode(i.creation_scope_commitment),
            v["creation_scope_commitment_hex"].as_str().unwrap()
        );
        let temp = Temp::new();
        let mut journal = NativeCustodyJournal::for_public_bootstrap_fixture(&temp.0).unwrap();
        let reserved = reserve(&mut journal, &i, 0);
        let lease = journal.begin_generation(&reserved).unwrap();
        let wrong = CustodyBinding {
            scope: CustodyScope::BootstrapRoot {
                custody_policy: ProfileRef {
                    name: "PUBLIC-TEST-CUSTODY",
                    revision: 1,
                },
                custody_object_ref: "DIFFERENT-PUBLIC-SLOT",
            },
            key: binding.key,
            trust_domain: binding.trust_domain,
        };
        assert!(matches!(
            journal.seal_generated(&lease, &envelope, &wrong),
            Err(CustodyJournalError::InvalidSeal)
        ));
        let pending = journal.seal_generated(&lease, &envelope, &binding).unwrap();
        assert_eq!(
            hex::encode(pending.envelope_commitment()),
            v["envelope_commitment_hex"].as_str().unwrap()
        );
        assert!(matches!(
            journal.seal_generated(&lease, &envelope, &binding),
            Err(CustodyJournalError::Conflict)
        ));
        drop(journal);
        let mut restarted = NativeCustodyJournal::for_public_bootstrap_fixture(&temp.0).unwrap();
        let resumed = match restarted.reserve(&i, 0).unwrap() {
            CustodyReservationResult::AlreadySealed(p) => p,
            _ => panic!("must not repeat RNG"),
        };
        assert_eq!(resumed.envelope_commitment(), pending.envelope_commitment());
        assert_eq!(resumed.journal_generation(), 3);
    }
    fn reserve(
        j: &mut NativeCustodyJournal,
        i: &CustodyCreationIntent,
        old: u64,
    ) -> CustodyReservation {
        match j.reserve(i, old).unwrap() {
            CustodyReservationResult::Reserved(r) => r,
            _ => panic!("not sealed"),
        }
    }
    #[test]
    fn durable_reserve_before_generation_is_one_use_and_crash_ambiguous() {
        let temp = Temp::new();
        let mut first = NativeCustodyJournal::for_nonproduction(&temp.0, network()).unwrap();
        let i = intent();
        let reserved = reserve(&mut first, &i, 0);
        let mut second = NativeCustodyJournal::for_nonproduction(&temp.0, network()).unwrap();
        let concurrent = reserve(&mut second, &i, 0);
        let lease = first.begin_generation(&reserved).unwrap();
        assert!(matches!(
            second.begin_generation(&concurrent),
            Err(CustodyJournalError::Conflict)
        ));
        drop(first);
        drop(second);
        let mut restarted = NativeCustodyJournal::for_nonproduction(&temp.0, network()).unwrap();
        assert!(matches!(
            restarted.reserve(&i, 0),
            Err(CustodyJournalError::AmbiguousGeneration)
        ));
        restarted.retire_failed_generation(&lease).unwrap();
        let mut next = i.clone();
        next.key_generation = 2;
        next.operation_nonce = [24; 32];
        next.native_request_digest = [25; 32];
        let next = reserve(&mut restarted, &next, 1);
        assert_eq!(next.record.journal_generation, 4);
        assert!(matches!(
            restarted.begin_generation(&reserved),
            Err(CustodyJournalError::Conflict)
        ));
        let mut other = i;
        other.slot_ref = "ANOTHER-PUBLIC-SLOT".into();
        assert!(matches!(
            restarted.reserve(&other, 0),
            Err(CustodyJournalError::Conflict)
        ));
    }
    #[test]
    fn actual_network_and_mixed_incarnation_refuse_without_material_generation() {
        let temp = Temp::new();
        let mut live = network();
        live.chain_id = 9969;
        assert!(matches!(
            NativeCustodyJournal::for_nonproduction(&temp.0, live),
            Err(CustodyJournalError::CeremonyRequired)
        ));
        assert!(!temp.0.exists());
        let _journal = NativeCustodyJournal::for_nonproduction(&temp.0, network()).unwrap();
        let before = fs::read(temp.0.join("context.json")).unwrap();
        let mut wrong = network();
        wrong.nic[63] ^= 1;
        assert!(matches!(
            NativeCustodyJournal::for_nonproduction(&temp.0, wrong),
            Err(CustodyJournalError::Conflict)
        ));
        assert_eq!(fs::read(temp.0.join("context.json")).unwrap(), before);
        assert!(matches!(
            NativeCustodyJournal::for_public_bootstrap_fixture(&temp.0),
            Err(CustodyJournalError::Conflict)
        ));
    }
    #[test]
    fn pre_nic_scope_is_explicit_and_invalid_intents_cannot_consume_a_slot() {
        use std::os::unix::fs::PermissionsExt;
        let temp = Temp::new();
        let mut journal = NativeCustodyJournal::for_public_bootstrap_fixture(&temp.0).unwrap();
        let mut i = intent();
        i.algorithm = "ML-DSA-87".into();
        i.role = "bootstrap-root".into();
        let mut invalid = i.clone();
        invalid.operation_nonce = [0; 32];
        assert!(matches!(
            journal.reserve(&invalid, 0),
            Err(CustodyJournalError::InvalidIntent)
        ));
        let reserved = reserve(&mut journal, &i, 0);
        assert!(reserved.record.chain_id.is_none());
        assert!(reserved.record.nic.is_none());
        assert_eq!(
            fs::metadata(&temp.0).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(
            fs::metadata(temp.0.join(slot_path(&i.slot_ref)))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
}
