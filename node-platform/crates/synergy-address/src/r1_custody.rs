//! Native custody durability adapter. This owns no cryptosystem or issuer.
//! Reserve before provider/RNG, fence ambiguous attempts, seal before publication.
//! The public preparation constructor is isolated to nonproduction coordinates;
//! actual managed authorization must enter through the existing native lifecycle.
use serde::{Deserialize, Serialize};
use std::{
    fs,
    path::{Path, PathBuf},
};
use synergy_address_engine::{
    apqe::{custody_binding_r1::CustodyBinding, r1_framing::NetworkRef},
    encrypt::{bound_envelope_commitment, EncryptedEnvelope},
};
use synergy_storage::{
    AtomicStore, RequiredRecord, StoragePrecondition, StorageTransaction, StorageWrite,
};
#[path = "r1_custody_rebind.rs"]
mod rebind;
#[path = "r1_custody_runtime.rs"]
mod runtime_use;
#[path = "r1_custody_formation.rs"]
mod formation_use;
pub use rebind::{CompletedIdentityRebind, CustodyRebindLease};

const MAX_RECORD: usize = 2 * 1024 * 1024;
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CustodyJournalError {
    CeremonyRequired,
    PlatformUnqualified,
    InvalidIntent,
    Conflict,
    AmbiguousGeneration,
    AmbiguousProof,
    AmbiguousRebind,
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
    Proving,
    Rebinding,
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
struct PublicCustodyKey {
    role: String,
    algorithm: String,
    key_generation: u64,
    full_public_key: Vec<u8>,
}
impl PublicCustodyKey {
    fn from_key(k: synergy_address_engine::apqe::network_birth_r1::BootstrapKeyRecord<'_>) -> Self {
        Self {
            role: k.role.into(),
            algorithm: k.algorithm.into(),
            key_generation: k.key_generation,
            full_public_key: k.full_public_key.to_vec(),
        }
    }
    fn borrowed(&self) -> synergy_address_engine::apqe::network_birth_r1::BootstrapKeyRecord<'_> {
        synergy_address_engine::apqe::network_birth_r1::BootstrapKeyRecord {
            role: &self.role,
            algorithm: &self.algorithm,
            key_generation: self.key_generation,
            full_public_key: &self.full_public_key,
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProofReservation {
    native_request_digest: Vec<u8>,
    operation_nonce: Vec<u8>,
    proof_plan_commitment: Vec<u8>,
    birth_plan_commitment: Vec<u8>,
    expected_envelope_commitment: Vec<u8>,
    source_journal_generation: u64,
}
impl ProofReservation {
    fn validate(&self) -> Result<(), CustodyJournalError> {
        if self.native_request_digest.len() != 32
            || self.operation_nonce.len() != 32
            || self.proof_plan_commitment.len() != 64
            || self.birth_plan_commitment.len() != 64
            || self.expected_envelope_commitment.len() != 64
            || self.source_journal_generation == 0
            || self.source_journal_generation.checked_add(2).is_none()
            || [
                &self.native_request_digest,
                &self.operation_nonce,
                &self.proof_plan_commitment,
                &self.birth_plan_commitment,
                &self.expected_envelope_commitment,
            ]
            .iter()
            .any(|v| v.iter().all(|b| *b == 0))
        {
            return Err(CustodyJournalError::InvalidIntent);
        }
        Ok(())
    }
}
struct ProofSpec<'a> {
    slot: &'a str,
    key_generation: u64,
    reservation: ProofReservation,
}
/// An opaque durable signing fence, never a signing capability or secret.
pub struct CustodyProofLease {
    record: Record,
    bytes: Vec<u8>,
    marker: Vec<u8>,
}
/// Public proof bytes released only after the journal/result CAS has committed.
pub struct CompletedIdentityProof {
    bytes: Vec<u8>,
}
impl CompletedIdentityProof {
    pub fn canonical_public_bytes(&self) -> &[u8] {
        &self.bytes
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CompletedProofMarker {
    schema: u16,
    reservation: ProofReservation,
    completion_record_commitment: Vec<u8>,
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
    public_key: Option<PublicCustodyKey>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    birth_plan_commitment: Option<Vec<u8>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    proof_reservation: Option<ProofReservation>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    rebind_reservation: Option<rebind::RebindReservation>,
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
        if self
            .birth_plan_commitment
            .as_ref()
            .is_some_and(|b| b.len() != 64 || b.iter().all(|v| *v == 0))
        {
            return Err(CustodyJournalError::Corrupt);
        }
        if self.stage == CustodyStage::Proving {
            let r = self
                .proof_reservation
                .as_ref()
                .ok_or(CustodyJournalError::Corrupt)?;
            r.validate()?;
            if self.birth_plan_commitment.as_ref() != Some(&r.birth_plan_commitment)
                || self.envelope_commitment.as_ref() != Some(&r.expected_envelope_commitment)
                || r.source_journal_generation.checked_add(1) != Some(self.journal_generation)
            {
                return Err(CustodyJournalError::Corrupt);
            }
        } else if self.proof_reservation.is_some() {
            return Err(CustodyJournalError::Corrupt);
        }
        if self.stage == CustodyStage::Rebinding {
            let r = self
                .rebind_reservation
                .as_ref()
                .ok_or(CustodyJournalError::Corrupt)?;
            r.validate()?;
            if self.birth_plan_commitment.as_ref() != Some(&r.birth_plan_commitment)
                || self.envelope_commitment.as_ref() != Some(&r.expected_envelope_commitment)
                || r.source_journal_generation.checked_add(1) != Some(self.journal_generation)
            {
                return Err(CustodyJournalError::Corrupt);
            }
        } else if self.rebind_reservation.is_some() {
            return Err(CustodyJournalError::Corrupt);
        }
        match self.stage {
            CustodyStage::Reserved | CustodyStage::Generating => {
                if self.full_binding_aad.is_some()
                    || self.envelope_commitment.is_some()
                    || self.envelope.is_some()
                    || self.public_key.is_some()
                {
                    return Err(CustodyJournalError::Corrupt);
                }
            }
            CustodyStage::SealedPending | CustodyStage::Proving | CustodyStage::Rebinding => {
                let key = self
                    .public_key
                    .as_ref()
                    .ok_or(CustodyJournalError::Corrupt)?;
                let size = match key.algorithm.as_str() {
                    "ML-DSA-65" => 1952,
                    "ML-DSA-87" => 2592,
                    "ML-KEM-1024" => 1568,
                    _ => return Err(CustodyJournalError::Corrupt),
                };
                if key.role != self.role
                    || key.algorithm != self.algorithm
                    || key.key_generation != self.key_generation
                    || key.full_public_key.len() != size
                {
                    return Err(CustodyJournalError::Corrupt);
                }
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
                    || self.public_key.is_some()
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
    pub fn public_key_record(
        &self,
    ) -> synergy_address_engine::apqe::network_birth_r1::BootstrapKeyRecord<'_> {
        self.record
            .public_key
            .as_ref()
            .expect("validated sealed record")
            .borrowed()
    }
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
    root: PathBuf,
    network: Option<NetworkRef>,
    admission: Admission,
}
#[derive(Clone, Copy)]
enum Admission {
    PublicFixture,
    NativeManaged,
}
impl NativeCustodyJournal {
    /// Reconcile public sealed state without consuming another grant or RNG.
    /// The encrypted envelope stays private in the opaque returned value.
    pub fn inspect_managed_pending(
        platform_root: &Path,
        slot: &str,
        original_request: &[u8; 32],
    ) -> Result<Option<SealedPendingCustody>, CustodyJournalError> {
        Self::inspect_managed_pending_in_network(platform_root, slot, original_request, None)
    }
    /// Exact read-only context selection. None means pre-NIC bootstrap, never a
    /// wildcard. A runtime caller obtains Some(N) from its authenticated bundle.
    /// Matching these data supplies no generation, unlock or role authority.
    pub fn inspect_managed_pending_in_network(
        platform_root: &Path,
        slot: &str,
        original_request: &[u8; 32],
        expected_network: Option<NetworkRef>,
    ) -> Result<Option<SealedPendingCustody>, CustodyJournalError> {
        if !text(slot) || slot.len() > 120 || !platform_root.is_absolute() {
            return Err(CustodyJournalError::InvalidIntent);
        }
        if expected_network.is_some_and(|n| n.chain_id == 0) {
            return Err(CustodyJournalError::InvalidIntent);
        }
        let root = platform_root.join(
            synergy_address_engine::apqe::managed_creation::managed_journal_relative_root(
                expected_network,
            ),
        );
        match fs::symlink_metadata(&root) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(CustodyJournalError::Storage),
            Ok(_) => {}
        }
        #[cfg(not(unix))]
        {
            return Err(CustodyJournalError::PlatformUnqualified);
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::{MetadataExt, PermissionsExt};
            if root.canonicalize().ok().as_deref() != Some(root.as_path()) {
                return Err(CustodyJournalError::Storage);
            }
            for path in root
                .ancestors()
                .take_while(|p| p.starts_with(platform_root))
            {
                let m = fs::symlink_metadata(path).map_err(|_| CustodyJournalError::Storage)?;
                if m.file_type().is_symlink()
                    || !m.is_dir()
                    || m.uid() != 0
                    || m.permissions().mode() & 0o022 != 0
                {
                    return Err(CustodyJournalError::Storage);
                }
            }
            AtomicStore::inspect_existing_read_only(
                &root,
                MAX_RECORD,
                |reader| -> Result<Option<SealedPendingCustody>, CustodyJournalError> {
                    let expected = encode(&(
                        1u16,
                        "NATIVE-MANAGED-CUSTODY-JOURNAL",
                        expected_network.map(|n| (n.chain_id, n.nic.to_vec())),
                    ))?;
                    if reader
                        .with_maximum_bytes(4096)
                        .read_optional_bounded("context.json")
                        .map_err(|_| CustodyJournalError::Storage)?
                        .as_deref()
                        != Some(expected.as_slice())
                    {
                        return Err(CustodyJournalError::Conflict);
                    }
                    let Some(bytes) = reader
                        .read_optional_bounded(slot_path(slot))
                        .map_err(|_| CustodyJournalError::Storage)?
                    else {
                        return Ok(None);
                    };
                    let record = decode(&bytes)?;
                    record.validate(expected_network)?;
                    if record.slot_ref != slot
                        || record.native_request_digest.as_slice() != original_request
                    {
                        return Err(CustodyJournalError::Conflict);
                    }
                    match record.stage {
                        CustodyStage::SealedPending => {
                            Ok(Some(SealedPendingCustody { record, bytes }))
                        }
                        CustodyStage::Generating => Err(CustodyJournalError::AmbiguousGeneration),
                        CustodyStage::Proving => Err(CustodyJournalError::AmbiguousProof),
                        CustodyStage::Rebinding => Err(CustodyJournalError::AmbiguousRebind),
                        _ => Err(CustodyJournalError::InvalidStage),
                    }
                },
            )
            .map_err(|_| CustodyJournalError::Storage)?
            .transpose()
            .map(Option::flatten)
        }
    }
    /// Uses the exact independently verified native root, never a caller path.
    /// The capability owner has already checked/consumed the protected receipt;
    /// key generation still cannot begin until `begin_generation` commits.
    pub fn from_managed_creation(
        auth: &synergy_address_engine::apqe::managed_creation::VerifiedManagedCreationAuthorization,
    ) -> Result<Self, CustodyJournalError> {
        #[cfg(not(unix))]
        {
            let _ = auth;
            return Err(CustodyJournalError::PlatformUnqualified);
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
            let selected = auth.journal_root();
            let relative = selected
                .strip_prefix(auth.platform_root())
                .map_err(|_| CustodyJournalError::Storage)?;
            let mut root = auth.platform_root().to_path_buf();
            for leaf in relative.components() {
                let std::path::Component::Normal(leaf) = leaf else {
                    return Err(CustodyJournalError::Storage);
                };
                root.push(leaf);
                match fs::symlink_metadata(&root) {
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                        fs::DirBuilder::new()
                            .mode(0o700)
                            .create(&root)
                            .map_err(|_| CustodyJournalError::Storage)?;
                    }
                    Err(_) => return Err(CustodyJournalError::Storage),
                    Ok(_) => {}
                }
                let m = fs::symlink_metadata(&root).map_err(|_| CustodyJournalError::Storage)?;
                if m.file_type().is_symlink()
                    || !m.is_dir()
                    || m.uid() != 0
                    || m.permissions().mode() & 0o022 != 0
                {
                    return Err(CustodyJournalError::Storage);
                }
            }
            Self::open_private(&root, auth.network(), Admission::NativeManaged)
        }
    }
    pub fn reserve_managed(
        &mut self,
        auth: &synergy_address_engine::apqe::managed_creation::VerifiedManagedCreationAuthorization,
    ) -> Result<CustodyReservationResult, CustodyJournalError> {
        if self.network != auth.network() || !matches!(self.admission, Admission::NativeManaged) {
            return Err(CustodyJournalError::Conflict);
        }
        let intent = CustodyCreationIntent {
            slot_ref: auth.slot_ref().into(),
            role: auth.role().into(),
            algorithm: auth.algorithm().into(),
            key_generation: auth.key_generation(),
            operation_nonce: auth.operation_nonce(),
            native_request_digest: auth.native_request_digest(),
            creation_scope_commitment: auth.creation_scope_commitment(),
        };
        let old = intent
            .key_generation
            .checked_sub(1)
            .ok_or(CustodyJournalError::InvalidIntent)?;
        self.reserve_checked(&intent, old)
    }
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
        Self::open_private(root, Some(network), Admission::PublicFixture)
    }
    /// Explicit pre-NIC public-fixture scope. No invented zero-NIC network or
    /// dependency on a root-set commitment before the first root is protected.
    pub fn for_public_bootstrap_fixture(
        root: impl AsRef<Path>,
    ) -> Result<Self, CustodyJournalError> {
        Self::open_private(root, None, Admission::PublicFixture)
    }
    fn open_private(
        root: impl AsRef<Path>,
        network: Option<NetworkRef>,
        admission: Admission,
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
                match admission {
                    Admission::PublicFixture => "PUBLIC-SYNTHETIC-CUSTODY-JOURNAL",
                    Admission::NativeManaged => "NATIVE-MANAGED-CUSTODY-JOURNAL",
                },
                network.map(|n| (n.chain_id, n.nic.to_vec())),
            ))?;
            store
                .put_once_atomic(&[StorageWrite {
                    relative_path: "context.json".into(),
                    bytes: context,
                }])
                .map_err(|_| CustodyJournalError::Conflict)?;
            Ok(Self {
                store,
                root: root.to_path_buf(),
                network,
                admission,
            })
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
        if !matches!(self.admission, Admission::PublicFixture) {
            return Err(CustodyJournalError::CeremonyRequired);
        }
        self.reserve_checked(intent, expected_key_generation)
    }
    fn reserve_checked(
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
                    CustodyStage::Proving => Err(CustodyJournalError::AmbiguousProof),
                    CustodyStage::Rebinding => Err(CustodyJournalError::AmbiguousRebind),
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
            public_key: None,
            birth_plan_commitment: None,
            proof_reservation: None,
            rebind_reservation: None,
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
    // Actual callers enter only through the opaque admitted proof capability.
    fn reserve_proof_checked(
        &mut self,
        spec: ProofSpec<'_>,
    ) -> Result<CustodyProofLease, CustodyJournalError> {
        spec.reservation.validate()?;
        let Some((mut record, old)) = self.current(spec.slot)? else {
            return Err(CustodyJournalError::Conflict);
        };
        if record.stage == CustodyStage::Proving {
            return Err(CustodyJournalError::AmbiguousProof);
        }
        if record.stage != CustodyStage::SealedPending
            || record.key_generation != spec.key_generation
            || record.journal_generation != spec.reservation.source_journal_generation
            || record.envelope_commitment.as_ref()
                != Some(&spec.reservation.expected_envelope_commitment)
            || record
                .birth_plan_commitment
                .as_ref()
                .is_some_and(|b| b != &spec.reservation.birth_plan_commitment)
        {
            return Err(CustodyJournalError::Conflict);
        }
        let marker = encode(&(
            1u16,
            "PENDING-IDENTITY-PROOF",
            &record.slot_ref,
            record.key_generation,
            &spec.reservation,
        ))?;
        let operation = format!(
            "proof-operations/{}.json",
            hex(&spec.reservation.operation_nonce)
        );
        record.birth_plan_commitment = Some(spec.reservation.birth_plan_commitment.clone());
        record.proof_reservation = Some(spec.reservation);
        record.stage = CustodyStage::Proving;
        record.journal_generation = record
            .journal_generation
            .checked_add(1)
            .ok_or(CustodyJournalError::Conflict)?;
        record.validate(self.network)?;
        let bytes = encode(&record)?;
        let mut tx =
            StorageTransaction::new(2 * MAX_RECORD).map_err(|_| CustodyJournalError::Storage)?;
        tx.put(slot_path(spec.slot), bytes.clone())
            .map_err(|_| CustodyJournalError::Storage)?;
        tx.put(&operation, marker.clone())
            .map_err(|_| CustodyJournalError::Storage)?;
        tx.commit_guarded(
            &mut self.store,
            &[
                StoragePrecondition {
                    relative_path: slot_path(spec.slot).into(),
                    required: RequiredRecord::Exact(old),
                },
                StoragePrecondition {
                    relative_path: operation.into(),
                    required: RequiredRecord::Missing,
                },
            ],
        )
        .map_err(|_| CustodyJournalError::Conflict)?;
        Ok(CustodyProofLease {
            record,
            bytes,
            marker,
        })
    }
    pub fn from_managed_proof(
        auth: &synergy_address_engine::apqe::managed_creation::identity_proof::VerifiedManagedProofAuthorization,
    ) -> Result<Self, CustodyJournalError> {
        #[cfg(not(unix))]
        {
            let _ = auth;
            return Err(CustodyJournalError::PlatformUnqualified);
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::{MetadataExt, PermissionsExt};
            let root = auth.journal_root();
            if !root.starts_with(auth.platform_root())
                || root.canonicalize().ok().as_deref() != Some(root.as_path())
            {
                return Err(CustodyJournalError::Storage);
            }
            // Proof/rebind must never initialize a missing custody installation.
            for path in root
                .ancestors()
                .take_while(|p| p.starts_with(auth.platform_root()))
            {
                let m = fs::symlink_metadata(path).map_err(|_| CustodyJournalError::Storage)?;
                if m.file_type().is_symlink()
                    || !m.is_dir()
                    || m.uid() != 0
                    || m.permissions().mode() & 0o022 != 0
                {
                    return Err(CustodyJournalError::Storage);
                }
            }
            if !root.join("context.json").is_file() {
                return Err(CustodyJournalError::Storage);
            }
            Self::open_private(root, Some(auth.network()), Admission::NativeManaged)
        }
    }
    pub fn reserve_managed_proof(
        &mut self,
        auth: &synergy_address_engine::apqe::managed_creation::identity_proof::VerifiedManagedProofAuthorization,
    ) -> Result<CustodyProofLease, CustodyJournalError> {
        if !matches!(self.admission, Admission::NativeManaged)
            || self.network != Some(auth.network())
            || self.root != auth.journal_root()
        {
            return Err(CustodyJournalError::Conflict);
        }
        let Some((record, _)) = self.current(auth.slot_ref())? else {
            return Err(CustodyJournalError::Conflict);
        };
        let key = record
            .public_key
            .as_ref()
            .ok_or(CustodyJournalError::Corrupt)?;
        let expected = auth.public_key_record();
        if key.role != expected.role
            || key.algorithm != expected.algorithm
            || key.key_generation != expected.key_generation
            || key.full_public_key != expected.full_public_key
            || record.creation_scope_commitment.as_slice() != auth.creation_scope_commitment()
        {
            return Err(CustodyJournalError::Conflict);
        }
        self.reserve_proof_checked(ProofSpec {
            slot: auth.slot_ref(),
            key_generation: auth.key_generation(),
            reservation: ProofReservation {
                native_request_digest: auth.native_request_digest().to_vec(),
                operation_nonce: auth.operation_nonce().to_vec(),
                proof_plan_commitment: auth.proof_plan_commitment().to_vec(),
                birth_plan_commitment: auth.birth_plan_commitment().to_vec(),
                expected_envelope_commitment: auth.expected_envelope_commitment().to_vec(),
                source_journal_generation: auth.expected_journal_generation(),
            },
        })
    }
    pub fn managed_proof_record(
        &self,
        lease: &CustodyProofLease,
    ) -> Result<(PathBuf, fs::File), CustodyJournalError> {
        if !matches!(self.admission, Admission::NativeManaged)
            || lease.record.stage != CustodyStage::Proving
        {
            return Err(CustodyJournalError::InvalidStage);
        }
        if self
            .current(&lease.record.slot_ref)?
            .is_none_or(|(_, b)| b != lease.bytes)
        {
            return Err(CustodyJournalError::Conflict);
        }
        let path = self.root.join(slot_path(&lease.record.slot_ref));
        #[cfg(not(unix))]
        {
            let _ = path;
            return Err(CustodyJournalError::PlatformUnqualified);
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            let file = fs::OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
                .open(&path)
                .map_err(|_| CustodyJournalError::Storage)?;
            Ok((path, file))
        }
    }
    pub fn complete_managed_proof(
        &mut self,
        lease: &CustodyProofLease,
        receipt: synergy_address_engine::apqe::managed_creation::identity_proof::ManagedIdentityProofReceipt,
    ) -> Result<CompletedIdentityProof, CustodyJournalError> {
        if !matches!(self.admission, Admission::NativeManaged)
            || self.root != receipt.journal_root()
            || self.network != Some(receipt.network())
            || receipt.slot_ref() != lease.record.slot_ref
            || receipt.key_generation() != lease.record.key_generation
            || receipt.creation_scope_commitment().as_slice()
                != lease.record.creation_scope_commitment
            || receipt.original_creation_request_digest().as_slice()
                != lease.record.native_request_digest
        {
            return Err(CustodyJournalError::Conflict);
        }
        let expected = ProofReservation {
            native_request_digest: receipt.native_request_digest().to_vec(),
            operation_nonce: receipt.operation_nonce().to_vec(),
            proof_plan_commitment: receipt.proof_plan_commitment().to_vec(),
            birth_plan_commitment: receipt.birth_plan_commitment().to_vec(),
            expected_envelope_commitment: receipt.expected_envelope_commitment().to_vec(),
            source_journal_generation: receipt.expected_journal_generation(),
        };
        let key = lease
            .record
            .public_key
            .as_ref()
            .ok_or(CustodyJournalError::Corrupt)?;
        let public = receipt.public_key_record();
        if lease.record.proof_reservation.as_ref() != Some(&expected)
            || key.role != public.role
            || key.algorithm != public.algorithm
            || key.key_generation != public.key_generation
            || key.full_public_key != public.full_public_key
        {
            return Err(CustodyJournalError::Conflict);
        }
        self.complete_proof_checked(
            lease,
            receipt.canonical_public_bytes(),
            receipt.completion_record_commitment(),
        )
    }
    fn complete_proof_checked(
        &mut self,
        lease: &CustodyProofLease,
        public: &[u8],
        commitment: [u8; 64],
    ) -> Result<CompletedIdentityProof, CustodyJournalError> {
        use crate::r1_public::{HashAlgorithm, Primitives};
        if public.is_empty() || public.len() > synergy_address_engine::apqe::managed_creation::identity_proof::MAX_PROOF_RECEIPT_BYTES
            || Primitives.hash(HashAlgorithm::Sha3512, public).map_err(|_| CustodyJournalError::Corrupt)?.as_slice() != commitment {
            return Err(CustodyJournalError::Corrupt);
        }
        let r = lease
            .record
            .proof_reservation
            .as_ref()
            .ok_or(CustodyJournalError::InvalidStage)?;
        let mut record = lease.record.clone();
        record.stage = CustodyStage::SealedPending;
        record.proof_reservation = None;
        record.journal_generation = record
            .journal_generation
            .checked_add(1)
            .ok_or(CustodyJournalError::Conflict)?;
        record.validate(self.network)?;
        let bytes = encode(&record)?;
        let op = format!("proof-operations/{}.json", hex(&r.operation_nonce));
        let result = format!("proof-results/{}.bin", hex(&r.operation_nonce));
        let marker = encode(&CompletedProofMarker {
            schema: 1,
            reservation: r.clone(),
            completion_record_commitment: commitment.to_vec(),
        })?;
        let mut tx =
            StorageTransaction::new(3 * MAX_RECORD).map_err(|_| CustodyJournalError::Storage)?;
        tx.put(slot_path(&record.slot_ref), bytes)
            .map_err(|_| CustodyJournalError::Storage)?;
        tx.put(&op, marker)
            .map_err(|_| CustodyJournalError::Storage)?;
        tx.put(&result, public.to_vec())
            .map_err(|_| CustodyJournalError::Storage)?;
        tx.commit_guarded(
            &mut self.store,
            &[
                StoragePrecondition {
                    relative_path: slot_path(&record.slot_ref).into(),
                    required: RequiredRecord::Exact(lease.bytes.clone()),
                },
                StoragePrecondition {
                    relative_path: op.into(),
                    required: RequiredRecord::Exact(lease.marker.clone()),
                },
                StoragePrecondition {
                    relative_path: result.into(),
                    required: RequiredRecord::Missing,
                },
            ],
        )
        .map_err(|_| CustodyJournalError::Conflict)?;
        Ok(CompletedIdentityProof {
            bytes: public.to_vec(),
        })
    }
    /// Exact persisted public result; never decrypts, signs or reissues a proof.
    pub fn completed_proof(
        &self,
        operation_nonce: &[u8; 32],
        request_digest: &[u8; 32],
    ) -> Result<Option<CompletedIdentityProof>, CustodyJournalError> {
        use crate::r1_public::{HashAlgorithm, Primitives};
        self.store.inspect_consistent(|reader| {
            let Some(marker) = reader.read_optional_bounded(format!("proof-operations/{}.json",hex(operation_nonce))).map_err(|_|CustodyJournalError::Storage)? else { return Ok(None); };
            let marker:CompletedProofMarker=serde_json::from_slice(&marker).map_err(|_|CustodyJournalError::AmbiguousProof)?;
            marker.reservation.validate()?;
            if marker.schema!=1 || marker.reservation.operation_nonce.as_slice()!=operation_nonce
                || marker.reservation.native_request_digest.as_slice()!=request_digest || marker.completion_record_commitment.len()!=64 {
                return Err(CustodyJournalError::Conflict);
            }
            let bytes=reader.with_maximum_bytes(synergy_address_engine::apqe::managed_creation::identity_proof::MAX_PROOF_RECEIPT_BYTES)
                .read_optional_bounded(format!("proof-results/{}.bin",hex(operation_nonce))).map_err(|_|CustodyJournalError::Storage)?
                .ok_or(CustodyJournalError::Corrupt)?;
            if bytes.is_empty() || Primitives.hash(HashAlgorithm::Sha3512,&bytes).map_err(|_|CustodyJournalError::Corrupt)?!=marker.completion_record_commitment {
                return Err(CustodyJournalError::Corrupt);
            }
            Ok(Some(CompletedIdentityProof {bytes}))
        }).map_err(|_|CustodyJournalError::Storage)?
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
    pub fn managed_generation_record(
        &self,
        lease: &CustodyGenerationLease,
    ) -> Result<(PathBuf, fs::File), CustodyJournalError> {
        if !matches!(self.admission, Admission::NativeManaged)
            || lease.record.stage != CustodyStage::Generating
        {
            return Err(CustodyJournalError::InvalidStage);
        }
        let Some((_, bytes)) = self.current(&lease.record.slot_ref)? else {
            return Err(CustodyJournalError::Conflict);
        };
        if bytes != lease.bytes {
            return Err(CustodyJournalError::Conflict);
        }
        let path = self.root.join(slot_path(&lease.record.slot_ref));
        #[cfg(not(unix))]
        {
            let _ = path;
            return Err(CustodyJournalError::PlatformUnqualified);
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            let file = fs::OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
                .open(&path)
                .map_err(|_| CustodyJournalError::Storage)?;
            Ok((path, file))
        }
    }
    /// Only APQE's private admitted/roundtripped result can enter managed custody.
    pub fn seal_managed_generated(
        &mut self,
        lease: &CustodyGenerationLease,
        material: synergy_address_engine::apqe::managed_creation::ManagedSealedKey,
    ) -> Result<SealedPendingCustody, CustodyJournalError> {
        if !matches!(self.admission, Admission::NativeManaged)
            || lease.record.stage != CustodyStage::Generating
        {
            return Err(CustodyJournalError::InvalidStage);
        }
        let key = material.public_key_record();
        if key.role != lease.record.role
            || key.algorithm != lease.record.algorithm
            || key.key_generation != lease.record.key_generation
            || material.native_request_digest().as_slice() != lease.record.native_request_digest
            || material.operation_nonce().as_slice() != lease.record.operation_nonce
            || material.creation_scope_commitment().as_slice()
                != lease.record.creation_scope_commitment
        {
            return Err(CustodyJournalError::InvalidSeal);
        }
        let mut record = lease.record.clone();
        record.public_key = Some(PublicCustodyKey::from_key(key));
        record.full_binding_aad = Some(material.full_binding_aad().to_vec());
        record.envelope_commitment = Some(material.envelope_commitment().to_vec());
        record.envelope = Some(material.encrypted_envelope().clone());
        let (record, bytes) = self.advance(&lease.bytes, record, CustodyStage::SealedPending)?;
        Ok(SealedPendingCustody { record, bytes })
    }
    pub fn seal_generated(
        &mut self,
        lease: &CustodyGenerationLease,
        envelope: &EncryptedEnvelope,
        binding: &CustodyBinding<'_>,
    ) -> Result<SealedPendingCustody, CustodyJournalError> {
        if !matches!(self.admission, Admission::PublicFixture) {
            return Err(CustodyJournalError::InvalidSeal);
        }
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
        record.public_key = Some(PublicCustodyKey::from_key(binding.key));
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
        record.public_key = None;
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
    fn pre_nic_and_distinct_network_journals_keep_independent_durable_fences() {
        use synergy_address_engine::apqe::managed_creation::managed_journal_relative_root;
        let temp = Temp::new();
        let boot = temp.0.join(managed_journal_relative_root(None));
        assert_eq!(boot, temp.0.join("keys/apqe/r1/journal"));
        let n = network();
        let mut other = n;
        other.nic[63] ^= 1;
        let runtime = temp.0.join(managed_journal_relative_root(Some(n)));
        let different = temp.0.join(managed_journal_relative_root(Some(other)));
        assert_ne!(boot, runtime);
        assert_ne!(runtime, different);
        fs::create_dir_all(boot.parent().unwrap()).unwrap();
        let mut bootstrap = NativeCustodyJournal::for_public_bootstrap_fixture(&boot).unwrap();
        let i = intent();
        let reserved = reserve(&mut bootstrap, &i, 0);
        bootstrap.begin_generation(&reserved).unwrap();
        fs::create_dir_all(runtime.parent().unwrap()).unwrap();
        let mut current = NativeCustodyJournal::for_nonproduction(&runtime, n).unwrap();
        let reserved = reserve(&mut current, &i, 0);
        current.begin_generation(&reserved).unwrap();
        NativeCustodyJournal::for_nonproduction(&different, other).unwrap();
        // Reopening either exact context retains its original ambiguity fence;
        // creating another incarnation never resets or imports that history.
        let mut bootstrap = NativeCustodyJournal::for_public_bootstrap_fixture(&boot).unwrap();
        assert!(matches!(
            bootstrap.reserve(&i, 0),
            Err(CustodyJournalError::AmbiguousGeneration)
        ));
        let mut current = NativeCustodyJournal::for_nonproduction(&runtime, n).unwrap();
        assert!(matches!(
            current.reserve(&i, 0),
            Err(CustodyJournalError::AmbiguousGeneration)
        ));
        assert!(matches!(
            NativeCustodyJournal::for_nonproduction(&runtime, other),
            Err(CustodyJournalError::Conflict)
        ));
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
        // Storage-only proof lifecycle test; synthetic public bytes are NOT
        // engine-validated identity proofs and never cross the managed wrapper.
        let reservation = ProofReservation {
            native_request_digest: vec![31; 32],
            operation_nonce: vec![32; 32],
            proof_plan_commitment: vec![33; 64],
            birth_plan_commitment: vec![34; 64],
            expected_envelope_commitment: pending.envelope_commitment().to_vec(),
            source_journal_generation: 3,
        };
        let proving = restarted
            .reserve_proof_checked(ProofSpec {
                slot: &i.slot_ref,
                key_generation: 1,
                reservation: reservation.clone(),
            })
            .unwrap();
        assert_eq!(proving.record.journal_generation, 4);
        assert_eq!(
            proving.record.native_request_digest,
            i.native_request_digest
        );
        assert_eq!(
            proving.record.creation_scope_commitment,
            i.creation_scope_commitment
        );
        assert_eq!(
            proving.record.birth_plan_commitment.as_deref(),
            Some(&[34u8; 64][..])
        );
        assert!(matches!(
            restarted.reserve(&i, 0),
            Err(CustodyJournalError::AmbiguousProof)
        ));
        assert!(matches!(
            restarted.completed_proof(&[32; 32], &[31; 32]),
            Err(CustodyJournalError::AmbiguousProof)
        ));
        drop(restarted);
        let mut restarted = NativeCustodyJournal::for_public_bootstrap_fixture(&temp.0).unwrap();
        assert!(matches!(
            restarted.reserve_proof_checked(ProofSpec {
                slot: &i.slot_ref,
                key_generation: 1,
                reservation: reservation.clone()
            }),
            Err(CustodyJournalError::AmbiguousProof)
        ));
        let public = b"PUBLIC-SYNTHETIC-STORAGE-LIFECYCLE-ONLY";
        use crate::r1_public::{HashAlgorithm, Primitives};
        let digest: [u8; 64] = Primitives
            .hash(HashAlgorithm::Sha3512, public)
            .unwrap()
            .try_into()
            .unwrap();
        let mut bad = digest;
        bad[63] ^= 1;
        assert!(restarted
            .complete_proof_checked(&proving, public, bad)
            .is_err());
        assert_eq!(
            restarted.current(&i.slot_ref).unwrap().unwrap().0.stage,
            CustodyStage::Proving
        );
        let completed = restarted
            .complete_proof_checked(&proving, public, digest)
            .unwrap();
        assert_eq!(completed.canonical_public_bytes(), public);
        assert!(restarted
            .complete_proof_checked(&proving, public, digest)
            .is_err());
        assert_eq!(
            restarted
                .completed_proof(&[32; 32], &[31; 32])
                .unwrap()
                .unwrap()
                .canonical_public_bytes(),
            public
        );
        assert!(restarted.completed_proof(&[32; 32], &[30; 32]).is_err());
        let current = restarted.current(&i.slot_ref).unwrap().unwrap().0;
        assert_eq!(current.stage, CustodyStage::SealedPending);
        assert_eq!(current.journal_generation, 5);
        assert_eq!(current.key_generation, 1);
        assert_eq!(current.native_request_digest, i.native_request_digest);
        assert_eq!(
            current.creation_scope_commitment,
            i.creation_scope_commitment
        );
        let mut other_birth = reservation;
        other_birth.source_journal_generation = 5;
        other_birth.operation_nonce = vec![35; 32];
        other_birth.birth_plan_commitment = vec![36; 64];
        assert!(matches!(
            restarted.reserve_proof_checked(ProofSpec {
                slot: &i.slot_ref,
                key_generation: 1,
                reservation: other_birth
            }),
            Err(CustodyJournalError::Conflict)
        ));
        assert_eq!(
            restarted
                .current(&i.slot_ref)
                .unwrap()
                .unwrap()
                .0
                .journal_generation,
            5
        );
        rebind::test_public_storage_transition(&mut restarted, &i.slot_ref);
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
