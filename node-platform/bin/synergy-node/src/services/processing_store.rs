//! Durable pending ownership for the explicit processing profile.
//!
//! One fixed slot contains one immutable signed request. Mutations replace only
//! that slot and a small compare-and-commit generation, never the whole queue.
//! This is storage, not ordering, reveal, eligibility or finality authority. The
//! existing ETDAG owner must authenticate intake/recovery and PoSy retirement.
#![cfg_attr(not(test), allow(dead_code))] // Explicit profile activation is not wired yet.

#[path = "processing_progress.rs"]
mod progress;

use std::path::Path;
use std::sync::Arc;

use super::processing_pipeline::{ProcessingCompletionEvidence, ProcessingProgressEvidence};
use serde::{Deserialize, Serialize};
use synergy_etdag::{EtdagDigest, ProcessingContext, WalletProcessingAdmission};
use synergy_state::world_resources::{
    WorldResourceBudget, WorldResourceError, WorldResourcePermit,
};
use synergy_storage::{
    AtomicStore, RequiredRecord, StorageError, StoragePrecondition, StorageTransaction,
};

const HEADER: &str = "pending-v1.json";
const MAX_SLOTS: usize = 4096;
const MAX_REQUEST_BYTES: usize = 1024 * 1024;
const MAX_CONTEXT_BYTES: usize = 16 * 1024;
const MAX_SLOT_BYTES: usize = 2 * MAX_REQUEST_BYTES + MAX_CONTEXT_BYTES + 1024;

// Preserve one native frame decode and encode at the established 32x graph
// charge, including their fixed scratch and the existing 16KiB measurement.
// This is a local new-work floor; it changes neither the pool limit nor PoSy.
pub(crate) const PROCESSING_INTAKE_HEADROOM_BYTES: usize =
    2 * (32 * synergy_network::protocol::DEFAULT_MAX_FRAME_BYTES + 64 * 1024) + 16 * 1024;

/// Necessary capacity for the existing intake reservation and one accepted
/// maximum-size RPC request, before unrelated worlds or pending work consume it.
/// This is a startup feasibility check, not an admission or readiness grant.
pub(crate) fn validate_processing_world_capacity(capacity: usize) -> Result<(), String> {
    let intake = super::protected_admission::maximum_processing_admission_owned_byte_charge();
    let minimum = PROCESSING_INTAKE_HEADROOM_BYTES
        .checked_add(intake)
        .ok_or("processing intake capacity calculation overflow")?;
    if capacity < minimum {
        return Err(format!(
            "storage.world_memory_budget_bytes={capacity} cannot support the signed processing profile: requires at least {minimum} bytes for existing intake headroom ({PROCESSING_INTAKE_HEADROOM_BYTES}) plus one maximum accepted request ({intake}); configure sufficient capacity before starting"
        ));
    }
    Ok(())
}

#[cfg(test)]
#[test]
fn processing_startup_capacity_matches_actual_intake_reservation() {
    let intake = super::protected_admission::maximum_processing_admission_owned_byte_charge();
    let minimum = PROCESSING_INTAKE_HEADROOM_BYTES + intake;
    assert!(
        validate_processing_world_capacity(synergy_config::default_world_memory_budget_bytes())
            .is_err()
    );
    assert!(validate_processing_world_capacity(minimum - 1).is_err());
    validate_processing_world_capacity(minimum).unwrap();
    let budget = WorldResourceBudget::new(minimum);
    let permit = budget
        .reserve_with_headroom(intake, PROCESSING_INTAKE_HEADROOM_BYTES)
        .unwrap();
    assert_eq!(permit.bytes(), intake);
    assert_eq!(budget.available(), PROCESSING_INTAKE_HEADROOM_BYTES);
    drop(permit);
    assert_eq!(budget.available(), minimum);
    assert!(WorldResourceBudget::new(minimum - 1)
        .reserve_with_headroom(intake, PROCESSING_INTAKE_HEADROOM_BYTES)
        .is_err());
}

/// Local allocation limits, not consensus admission/expiry policy. Completion
/// bytes must be computed by the native ETDAG owner for the governed witnesses.
/// The reservation is held before acknowledgement, and remains available to
/// this item's serial worker even when unrelated allocations fill the pool.
#[derive(Clone, Copy, Debug)]
pub(crate) struct ProcessingStoreLimits {
    pub slots: usize,
    pub completion_bytes_per_item: usize,
}

/// Must resolve the frozen context and authorization timestamp from verified
/// authority/finality, then verify the original native wallet signature against
/// that snapshot. Disk contents are inputs to verification, never authority.
pub(crate) trait ProcessingAdmissionAuthenticator {
    fn verify(
        &self,
        context: &ProcessingContext,
        authorization_timestamp_unix: u64,
        admission: &WalletProcessingAdmission,
    ) -> Result<(), String>;
    /// Only used after an exact length/hash match against an original accepted
    /// by this open store. Mutable authenticators keep full verification. A
    /// frozen native owner may reuse its earlier authentication in that scope.
    fn verify_retained(
        &self,
        context: &ProcessingContext,
        timestamp: u64,
        admission: &WalletProcessingAdmission,
    ) -> Result<(), String> {
        self.verify(context, timestamp, admission)
    }
    /// The caller has checked the accepted in-memory progress index against
    /// the exact disk bytes. Recovery and every new update use verify_progress.
    fn verify_retained_progress(
        &self,
        context: &ProcessingContext,
        admission: &WalletProcessingAdmission,
        evidence: &ProcessingProgressEvidence,
        budget: &Arc<WorldResourceBudget>,
    ) -> Result<(), String> {
        self.verify_progress(context, admission, evidence, budget)
    }
    fn verify_finalized(
        &self,
        _: &PendingProcessingIdentity,
        _: u64,
        _: &str,
        _: &str,
        _: &Arc<WorldResourceBudget>,
    ) -> Result<(), String> {
        Err("native finalized processing recovery is unavailable".into())
    }
    fn verify_progress(
        &self,
        _: &ProcessingContext,
        _: &WalletProcessingAdmission,
        _: &ProcessingProgressEvidence,
        _: &Arc<WorldResourceBudget>,
    ) -> Result<(), String> {
        Err("native processing progress recovery is unavailable".into())
    }
    fn verify_completion(
        &self,
        _: &ProcessingContext,
        _: &WalletProcessingAdmission,
        _: &ProcessingCompletionEvidence,
        _: &Arc<WorldResourceBudget>,
    ) -> Result<(), String> {
        Err("native processing completion recovery is unavailable".into())
    }
}

/// Only the sole native PoSy owner may provide this boundary. Verify durable
/// finalized consumption (or governed cancellation) of this exact envelope and
/// replay identity, plus required recovery retention, before returning success.
pub(crate) trait ProcessingRetirementVerifier {
    fn verify_retirement(&self, item: &PendingProcessingIdentity) -> Result<(), String>;
    fn finalized_subject(&self) -> Option<(u64, &str)> {
        None
    }
    fn finalized_state_root(&self) -> Option<&str> {
        None
    }
}

#[derive(Debug)]
pub(crate) enum ProcessingStoreError {
    Resource(WorldResourceError),
    Storage(StorageError),
    Invalid(String),
    Verification(String),
    NonceClaimed,
    Full,
}
impl From<WorldResourceError> for ProcessingStoreError {
    fn from(value: WorldResourceError) -> Self {
        Self::Resource(value)
    }
}
impl From<StorageError> for ProcessingStoreError {
    fn from(value: StorageError) -> Self {
        Self::Storage(value)
    }
}
impl std::fmt::Display for ProcessingStoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Resource(error) => write!(f, "pending processing resource pressure: {error}"),
            Self::Storage(error) => write!(f, "pending processing storage: {error}"),
            Self::Invalid(message) => write!(f, "invalid pending processing record: {message}"),
            Self::Verification(message) => write!(f, "pending processing verification: {message}"),
            Self::NonceClaimed => f.write_str("pending processing nonce already claimed"),
            Self::Full => f.write_str("pending processing slots full"),
        }
    }
}
impl std::error::Error for ProcessingStoreError {}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Header {
    version: u32,
    namespace_root: EtdagDigest,
    slots: usize,
    generation: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredPending {
    version: u32,
    namespace_root: EtdagDigest,
    context: ProcessingContext,
    authorization_timestamp_unix: u64,
    admission_json: String,
}

#[derive(Serialize)]
struct PendingWrite<'a> {
    version: u32,
    namespace_root: &'a EtdagDigest,
    context: &'a ProcessingContext,
    authorization_timestamp_unix: u64,
    admission_json: &'a str,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PendingProcessingIdentity {
    pub envelope_id: EtdagDigest,
    pub context_root: EtdagDigest,
    pub sender_wallet: String,
    pub sender_nonce: u64,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredCompletion {
    version: u32,
    namespace_root: EtdagDigest,
    identity: PendingProcessingIdentity,
    admission_record_root: EtdagDigest,
    evidence: ProcessingCompletionEvidence,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CompletionIndex {
    root: EtdagDigest,
    bytes: usize,
    record_root: EtdagDigest,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredFinalized {
    version: u32,
    namespace_root: EtdagDigest,
    identity: PendingProcessingIdentity,
    admission_record_root: EtdagDigest,
    height: u64,
    block_id: String,
    state_root: String,
    completion: Option<CompletionIndex>,
    progress: Option<progress::ProgressIndex>,
}

struct PendingEntry {
    historical_kem_recovery: bool,
    identity: PendingProcessingIdentity,
    encoded_root: EtdagDigest,
    encoded_bytes: usize,
    context: ProcessingContext,
    authorization_timestamp_unix: u64,
    admission_wire_root: EtdagDigest,
    completion: Option<CompletionIndex>,
    progress: Option<progress::ProgressIndex>,
    finalized: Option<(u64, String)>,
    finalized_record_root: Option<EtdagDigest>,
    finalized_state_root: Option<String>,
    // Includes this index and all serial decode/verify/transaction scratch.
    // No second global reservation is acquired to finish already owned work.
    workspace: Arc<WorldResourceBudget>,
}

pub(crate) struct PendingProcessingStore {
    store: AtomicStore,
    header: Header,
    slots: Vec<Option<PendingEntry>>,
    limits: ProcessingStoreLimits,
    budget: Arc<WorldResourceBudget>,
    _index_permit: WorldResourcePermit,
}

fn invalid(message: impl Into<String>) -> ProcessingStoreError {
    ProcessingStoreError::Invalid(message.into())
}
fn encode(value: &impl Serialize) -> Result<Vec<u8>, ProcessingStoreError> {
    serde_json::to_vec(value).map_err(|e| invalid(format!("encode pending record: {e}")))
}
/// Measure the exact escaped record encoding without constructing a second
/// request-sized buffer or decoding any untrusted request graph. Serialization
/// visits borrowed context/request bytes and the writer enforces the disk cap.
fn encoded_length(value: &impl Serialize, maximum: usize) -> Result<usize, ProcessingStoreError> {
    struct Counter {
        bytes: usize,
        maximum: usize,
    }
    impl std::io::Write for Counter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.bytes = self
                .bytes
                .checked_add(bytes.len())
                .filter(|total| *total <= self.maximum)
                .ok_or_else(|| std::io::Error::other("pending processing record too large"))?;
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut counter = Counter { bytes: 0, maximum };
    serde_json::to_writer(&mut counter, value)
        .map_err(|e| invalid(format!("measure pending record: {e}")))?;
    Ok(counter.bytes)
}
fn slot_path(index: usize) -> String {
    format!("slots/{index:04}.json")
}
fn completion_path(index: usize) -> String {
    format!("completions/{index:04}.json")
}
fn finalized_path(index: usize) -> String {
    format!("finalized/{index:04}.json")
}
fn quiescent_reservation(
    bytes: usize,
    completion: Option<&CompletionIndex>,
    progress: Option<&progress::ProgressIndex>,
) -> Result<usize, ProcessingStoreError> {
    let sideband = completion
        .map_or(0, |index| index.bytes)
        .max(progress.map_or(0, |index| index.bytes));
    // Finalized operations hash the immutable original and sidebands as bytes;
    // they cannot enter admission decoding or cryptographic worker callbacks.
    // Startup still reserves the full read/decode envelope before authenticating
    // the original and native finality, and only then shrinks to this allowance.
    bytes
        .checked_mul(2)
        .ok_or(WorldResourceError::ArithmeticOverflow)?
        .checked_add(
            sideband
                .checked_mul(2)
                .ok_or(WorldResourceError::ArithmeticOverflow)?,
        )
        .and_then(|n| n.checked_add(128 * 1024))
        .ok_or_else(|| WorldResourceError::ArithmeticOverflow.into())
}
fn validate_finalized(
    record: &StoredFinalized,
    namespace: &EtdagDigest,
) -> Result<(), ProcessingStoreError> {
    if record.version != 1
        || &record.namespace_root != namespace
        || record.height == 0
        || record.state_root.len() != 64
        || !record
            .state_root
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        || record.block_id.len() != 64
        || !record
            .block_id
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        || record.completion.is_none()
        || record
            .completion
            .as_ref()
            .is_some_and(|index| index.bytes == 0 || index.bytes > MAX_SLOT_BYTES)
        || record
            .progress
            .as_ref()
            .is_some_and(|index| index.bytes == 0 || index.bytes > MAX_SLOT_BYTES)
    {
        return Err(invalid("invalid finalized processing marker"));
    }
    record
        .admission_record_root
        .validate()
        .map_err(|e| invalid(format!("finalized original root: {e:?}")))?;
    if let Some(index) = &record.completion {
        index
            .root
            .validate()
            .map_err(|e| invalid(format!("finalized completion root: {e:?}")))?;
        index
            .record_root
            .validate()
            .map_err(|e| invalid(format!("finalized ready root: {e:?}")))?;
    }
    if let Some(index) = &record.progress {
        index
            .root
            .validate()
            .map_err(|e| invalid(format!("finalized progress root: {e:?}")))?;
    }
    Ok(())
}
fn read_finalized(
    reader: &synergy_storage::AtomicStoreReader<'_>,
    slot: usize,
    namespace: &EtdagDigest,
) -> Result<Option<(StoredFinalized, EtdagDigest)>, ProcessingStoreError> {
    let Some(bytes) = reader
        .with_maximum_bytes(16 * 1024)
        .read_optional_bounded(finalized_path(slot))?
    else {
        return Ok(None);
    };
    if bytes == b"null" {
        return Ok(None);
    }
    let record: StoredFinalized =
        serde_json::from_slice(&bytes).map_err(|e| invalid(format!("finalized marker: {e}")))?;
    validate_finalized(&record, namespace)?;
    Ok(Some((record, encoded_root(&bytes))))
}
fn completion_reservation(bytes: usize) -> Result<usize, ProcessingStoreError> {
    bytes
        .checked_mul(16)
        .and_then(|n| n.checked_add(64 * 1024))
        .ok_or_else(|| WorldResourceError::ArithmeticOverflow.into())
}
fn completion_record_root(
    evidence: &ProcessingCompletionEvidence,
) -> Result<EtdagDigest, ProcessingStoreError> {
    EtdagDigest::from_canonical("SYNERGY_ETDAG_PENDING_READY_RECORD_V1", &evidence.record)
        .map_err(|e| invalid(format!("processing completion identity: {e:?}")))
}
fn encoded_root(bytes: &[u8]) -> EtdagDigest {
    EtdagDigest::from_domain_bytes("SYNERGY_ETDAG_PENDING_PROCESSING_RECORD_V1", bytes)
}

fn reservation(bytes: usize, limits: ProcessingStoreLimits) -> Result<usize, ProcessingStoreError> {
    // Decoded request/identity graphs, canonical signature JSON, serialization,
    // AtomicStore staging/precondition/recovery copies and compact index. This
    // intentionally charges each JSON byte as a sparse native allocation; no
    // untrusted length is used for an allocation before this reservation.
    read_reservation(bytes)?
        .checked_add(limits.completion_bytes_per_item)
        .ok_or_else(|| WorldResourceError::ArithmeticOverflow.into())
}
fn read_reservation(bytes: usize) -> Result<usize, ProcessingStoreError> {
    bytes
        .checked_mul(128)
        .and_then(|n| n.checked_add(128 * 1024))
        .ok_or_else(|| WorldResourceError::ArithmeticOverflow.into())
}

fn identity(admission: &WalletProcessingAdmission) -> PendingProcessingIdentity {
    PendingProcessingIdentity {
        envelope_id: admission.request.envelope.envelope_id.clone(),
        context_root: admission.request.context_root.clone(),
        sender_wallet: admission.request.sender_wallet.clone(),
        sender_nonce: admission.request.sender_nonce,
    }
}

fn verify_stored(
    record: &StoredPending,
    namespace: &EtdagDigest,
    verifier: &impl ProcessingAdmissionAuthenticator,
) -> Result<WalletProcessingAdmission, ProcessingStoreError> {
    let admission = decode_stored(record, namespace)?;
    verifier
        .verify(
            &record.context,
            record.authorization_timestamp_unix,
            &admission,
        )
        .map_err(ProcessingStoreError::Verification)?;
    Ok(admission)
}

fn verify_retained_stored(
    record: &StoredPending,
    namespace: &EtdagDigest,
    verifier: &impl ProcessingAdmissionAuthenticator,
) -> Result<WalletProcessingAdmission, ProcessingStoreError> {
    let admission = decode_stored(record, namespace)?;
    verifier
        .verify_retained(
            &record.context,
            record.authorization_timestamp_unix,
            &admission,
        )
        .map_err(ProcessingStoreError::Verification)?;
    Ok(admission)
}

fn decode_stored(
    record: &StoredPending,
    namespace: &EtdagDigest,
) -> Result<WalletProcessingAdmission, ProcessingStoreError> {
    if !matches!(record.version, 1 | 2)
        || &record.namespace_root != namespace
        || record.authorization_timestamp_unix == 0
    {
        return Err(invalid("wrong pending processing scope/version/time"));
    }
    if record.admission_json.is_empty() || record.admission_json.len() > MAX_REQUEST_BYTES {
        return Err(invalid("invalid stored processing request length"));
    }
    let admission: WalletProcessingAdmission = serde_json::from_str(&record.admission_json)
        .map_err(|e| invalid(format!("stored processing request: {e}")))?;
    admission
        .request
        .validate_context(&record.context)
        .map_err(|e| invalid(format!("pending processing context: {e:?}")))?;
    Ok(admission)
}

fn verify_completion(
    bytes: &[u8],
    namespace: &EtdagDigest,
    original_root: &EtdagDigest,
    context: &ProcessingContext,
    admission: &WalletProcessingAdmission,
    verifier: &impl ProcessingAdmissionAuthenticator,
    budget: &Arc<WorldResourceBudget>,
) -> Result<StoredCompletion, ProcessingStoreError> {
    let record: StoredCompletion = serde_json::from_slice(bytes)
        .map_err(|e| invalid(format!("processing completion: {e}")))?;
    if record.version != 1
        || &record.namespace_root != namespace
        || record.identity != identity(admission)
        || &record.admission_record_root != original_root
    {
        return Err(invalid(
            "completion differs from original immutable admission",
        ));
    }
    verifier
        .verify_completion(context, admission, &record.evidence, budget)
        .map_err(ProcessingStoreError::Verification)?;
    Ok(record)
}

impl PendingProcessingStore {
    /// One consistent recovery snapshot. Failure preserves every durable byte
    /// and drops all partially restored reservations. Payloads are read and
    /// authenticated one at a time; only compact indexes remain resident.
    pub(crate) fn open(
        root: &Path,
        namespace: EtdagDigest,
        limits: ProcessingStoreLimits,
        budget: &Arc<WorldResourceBudget>,
        verifier: &impl ProcessingAdmissionAuthenticator,
    ) -> Result<Self, ProcessingStoreError> {
        namespace
            .validate()
            .map_err(|e| invalid(format!("pending namespace: {e:?}")))?;
        if namespace.is_zero()
            || limits.slots == 0
            || limits.slots > MAX_SLOTS
            || limits.completion_bytes_per_item == 0
        {
            return Err(invalid("invalid pending processing limits/namespace"));
        }
        // Also retain bounded AtomicStore recovery/header scratch. Its I/O may
        // replay an interrupted transaction before an item can be identified.
        let index_permit = budget.reserve(limits.slots * 2048 + 8 * MAX_SLOT_BYTES + 64 * 1024)?;
        let mut store = AtomicStore::new(root, MAX_SLOT_BYTES)?;
        let initial = Header {
            version: 1,
            namespace_root: namespace.clone(),
            slots: limits.slots,
            generation: 0,
        };
        let initial_bytes = encode(&initial)?;
        if !store.exists(HEADER)? {
            store.inspect_consistent(|reader| -> Result<(), ProcessingStoreError> {
                for index in 0..limits.slots {
                    if reader
                        .optional_record_bytes(finalized_path(index))?
                        .is_some()
                        || reader.optional_record_bytes(slot_path(index))?.is_some()
                        || reader
                            .optional_record_bytes(progress::path(index))?
                            .is_some()
                        || reader
                            .optional_record_bytes(completion_path(index))?
                            .is_some()
                    {
                        return Err(invalid(
                            "pending slots exist without their authority header",
                        ));
                    }
                }
                Ok(())
            })??;
            let mut transaction = StorageTransaction::new(4096)?;
            transaction.put(HEADER, initial_bytes.clone())?;
            transaction.commit_guarded(
                &mut store,
                &[StoragePrecondition {
                    relative_path: HEADER.into(),
                    required: RequiredRecord::MissingOrSameWrite,
                }],
            )?;
        }
        let (header, slots) =
            store.inspect_consistent(|reader| -> Result<_, ProcessingStoreError> {
                let bytes = reader
                    .with_maximum_bytes(4096)
                    .read_optional_bounded(HEADER)?
                    .ok_or_else(|| invalid("missing pending header"))?;
                let header: Header = serde_json::from_slice(&bytes)
                    .map_err(|e| invalid(format!("pending header: {e}")))?;
                if header.version != 1
                    || header.namespace_root != namespace
                    || header.slots != limits.slots
                {
                    return Err(invalid("pending processing namespace/capacity mismatch"));
                }
                let mut slots: Vec<Option<PendingEntry>> =
                    (0..limits.slots).map(|_| None).collect();
                for index in 0..limits.slots {
                    let path = slot_path(index);
                    let Some(length) = reader.optional_record_bytes(&path)? else {
                        if reader
                            .optional_record_bytes(finalized_path(index))?
                            .is_some()
                        {
                            return Err(invalid("finalized marker without original pending slot"));
                        }
                        if reader
                            .optional_record_bytes(progress::path(index))?
                            .is_some()
                            || reader
                                .optional_record_bytes(completion_path(index))?
                                .is_some()
                        {
                            return Err(invalid("completion exists without original pending slot"));
                        }
                        continue;
                    };
                    if length == 0 || length > MAX_SLOT_BYTES {
                        return Err(invalid("oversize/empty pending slot"));
                    }
                    // Retired slots are canonical `null`, retaining no payload or
                    // unbounded history. Guard even this read before allocation.
                    if length == 4 {
                        let bytes = reader
                            .read_optional_bounded(&path)?
                            .ok_or_else(|| invalid("missing pending slot"))?;
                        if bytes == b"null" {
                            if reader
                                .read_optional_bounded(finalized_path(index))?
                                .is_some_and(|bytes| bytes != b"null")
                            {
                                return Err(invalid("finalized marker for retired pending slot"));
                            }
                            if reader
                                .read_optional_bounded(progress::path(index))?
                                .is_some_and(|bytes| bytes != b"null")
                            {
                                return Err(invalid("progress exists for retired pending slot"));
                            }
                            if let Some(completion) =
                                reader.read_optional_bounded(completion_path(index))?
                            {
                                if completion != b"null" {
                                    return Err(invalid(
                                        "completion exists for retired pending slot",
                                    ));
                                }
                            }
                            continue;
                        }
                        return Err(invalid("noncanonical empty pending slot"));
                    }
                    // Fixed bounded marker parsing is covered by the retained
                    // recovery/index scratch before any per-item allocation.
                    let finalized = read_finalized(reader, index, &namespace)?;
                    // Restore one native proof from this item's original
                    // prepaid worker envelope, then immediately quiesce it.
                    // Only one terminal proof peak is live during this scan.
                    let permit = budget.reserve(reservation(length, limits)?)?;
                    let bytes = reader
                        .read_optional_bounded(&path)?
                        .ok_or_else(|| invalid("missing pending slot"))?;
                    let record: StoredPending = serde_json::from_slice(&bytes)
                        .map_err(|e| invalid(format!("pending slot: {e}")))?;
                    let admission = verify_stored(&record, &namespace, verifier)?;
                    let identity = identity(&admission);
                    for other in slots.iter().flatten() {
                        if other.identity.envelope_id == identity.envelope_id
                            || (other.identity.sender_wallet == identity.sender_wallet
                                && other.identity.sender_nonce == identity.sender_nonce)
                        {
                            return Err(invalid("duplicate pending envelope/nonce claim"));
                        }
                    }
                    let root = encoded_root(&bytes);
                    let mut workspace = permit.into_budget();
                    let _read = workspace.reserve(read_reservation(length)?)?;
                    if let Some((marker, _)) = &finalized {
                        if marker.identity != identity || marker.admission_record_root != root {
                            return Err(invalid(
                                "finalized marker differs from immutable original",
                            ));
                        }
                        verifier
                            .verify_finalized(
                                &identity,
                                marker.height,
                                &marker.block_id,
                                &marker.state_root,
                                &workspace,
                            )
                            .map_err(ProcessingStoreError::Verification)?;
                    }
                    let completion = if let Some((marker, _)) = &finalized {
                        if let Some(completion) = &marker.completion {
                            let _bytes = workspace.reserve(completion.bytes)?;
                            let bytes = reader
                                .with_maximum_bytes(completion.bytes)
                                .read_optional_bounded(completion_path(index))?
                                .ok_or_else(|| invalid("missing finalized completion"))?;
                            if bytes.len() != completion.bytes
                                || encoded_root(&bytes) != completion.root
                            {
                                return Err(invalid("finalized completion bytes changed"));
                            }
                        }
                        marker.completion.clone()
                    } else {
                        match reader.optional_record_bytes(completion_path(index))? {
                            None => None,
                            Some(4) => {
                                if reader
                                    .read_optional_bounded(completion_path(index))?
                                    .as_deref()
                                    != Some(b"null")
                                {
                                    return Err(invalid("noncanonical absent completion"));
                                }
                                None
                            }
                            Some(size) => {
                                if size > MAX_SLOT_BYTES || size == 0 {
                                    return Err(invalid("oversize/empty processing completion"));
                                }
                                let _decode = workspace.reserve(completion_reservation(size)?)?;
                                let completion_bytes = reader
                                    .read_optional_bounded(completion_path(index))?
                                    .ok_or_else(|| invalid("missing processing completion"))?;
                                let verified = verify_completion(
                                    &completion_bytes,
                                    &namespace,
                                    &root,
                                    &record.context,
                                    &admission,
                                    verifier,
                                    &workspace,
                                )?;
                                Some(CompletionIndex {
                                    root: encoded_root(&completion_bytes),
                                    bytes: size,
                                    record_root: completion_record_root(&verified.evidence)?,
                                })
                            }
                        }
                    };
                    let progress = if let Some((marker, _)) = &finalized {
                        if let Some(progress) = &marker.progress {
                            let _bytes = workspace.reserve(progress.bytes)?;
                            let bytes = reader
                                .with_maximum_bytes(progress.bytes)
                                .read_optional_bounded(progress::path(index))?
                                .ok_or_else(|| invalid("missing finalized progress"))?;
                            if bytes.len() != progress.bytes
                                || encoded_root(&bytes) != progress.root
                            {
                                return Err(invalid("finalized progress bytes changed"));
                            }
                        } else if reader
                            .read_optional_bounded(progress::path(index))?
                            .is_some_and(|bytes| bytes != b"null")
                        {
                            return Err(invalid("unexpected finalized progress"));
                        }
                        marker.progress.clone()
                    } else {
                        progress::recover(
                            reader,
                            index,
                            &namespace,
                            &root,
                            &record.context,
                            &admission,
                            verifier,
                            &workspace,
                        )?
                    };
                    drop(_read);
                    if finalized.is_some()
                        && !WorldResourceBudget::try_shrink_idle_child(
                            &mut workspace,
                            quiescent_reservation(length, completion.as_ref(), progress.as_ref())?,
                        )?
                    {
                        return Err(invalid(
                            "finalized recovery retained a native worker borrower",
                        ));
                    }
                    slots[index] = Some(PendingEntry {
                        historical_kem_recovery: record.version == 1,
                        identity,
                        encoded_root: root,
                        encoded_bytes: length,
                        admission_wire_root: encoded_root(record.admission_json.as_bytes()),
                        context: record.context,
                        authorization_timestamp_unix: record.authorization_timestamp_unix,
                        workspace,
                        completion,
                        progress,
                        finalized: finalized
                            .as_ref()
                            .map(|(record, _)| (record.height, record.block_id.clone())),
                        finalized_state_root: finalized
                            .as_ref()
                            .map(|(record, _)| record.state_root.clone()),
                        finalized_record_root: finalized.map(|(_, root)| root),
                    });
                }
                Ok((header, slots))
            })??;
        Ok(Self {
            store,
            header,
            slots,
            limits,
            budget: Arc::clone(budget),
            _index_permit: index_permit,
        })
    }

    pub(crate) fn identities(&self) -> impl Iterator<Item = &PendingProcessingIdentity> {
        self.slots.iter().flatten().map(|entry| &entry.identity)
    }
    pub(crate) fn source_heights(&self) -> impl Iterator<Item = u64> + '_ {
        self.slots
            .iter()
            .flatten()
            .map(|entry| entry.context.authority.source_finalized_height)
    }

    /// The owner may verify retirement from capacity already held for this
    /// item, including under aggregate pool pressure. A clone intentionally
    /// prevents workspace shrinking until native proof verification finishes.
    pub(crate) fn retirement_budget(
        &self,
        envelope: &EtdagDigest,
    ) -> Option<Arc<WorldResourceBudget>> {
        self.slots
            .iter()
            .flatten()
            .find(|entry| &entry.identity.envelope_id == envelope)
            .map(|entry| Arc::clone(&entry.workspace))
    }

    pub(crate) fn pending_identities(&self) -> impl Iterator<Item = &PendingProcessingIdentity> {
        self.slots
            .iter()
            .flatten()
            .filter(|entry| entry.finalized.is_none())
            .map(|entry| &entry.identity)
    }
    pub(crate) fn finalized_identities(
        &self,
    ) -> impl Iterator<Item = (&PendingProcessingIdentity, u64, &str)> {
        self.slots.iter().flatten().filter_map(|entry| {
            entry
                .finalized
                .as_ref()
                .map(|(height, id)| (&entry.identity, *height, id.as_str()))
        })
    }
    pub(crate) fn mark_finalized(
        &mut self,
        envelope: &EtdagDigest,
        height: u64,
        block_id: &str,
        verifier: &impl ProcessingRetirementVerifier,
    ) -> Result<(), ProcessingStoreError> {
        if verifier.finalized_subject() != Some((height, block_id)) {
            return Err(invalid("finalized marker lacks exact native subject"));
        }
        let slot = self
            .slots
            .iter()
            .position(|entry| {
                entry
                    .as_ref()
                    .is_some_and(|entry| &entry.identity.envelope_id == envelope)
            })
            .ok_or_else(|| invalid("unknown finalized processing envelope"))?;
        let entry = self.slots[slot].as_ref().expect("located finalized slot");
        if let Some((old_height, old_id)) = &entry.finalized {
            if (*old_height, old_id.as_str()) != (height, block_id) {
                return Err(invalid("conflicting finalized processing subject"));
            }
            self.verify_finalized_record(slot, entry)?;
            return Ok(());
        }
        let _read = entry.workspace.reserve(quiescent_reservation(
            entry.encoded_bytes,
            entry.completion.as_ref(),
            entry.progress.as_ref(),
        )?)?;
        self.read_entry(slot, entry)?;
        if let Some(completion) = &entry.completion {
            self.read_completion(slot, completion)?;
        }
        if let Some(progress) = &entry.progress {
            self.read_progress(slot, progress)?;
        }
        verifier
            .verify_retirement(&entry.identity)
            .map_err(ProcessingStoreError::Verification)?;
        let marker = StoredFinalized {
            version: 1,
            namespace_root: self.header.namespace_root.clone(),
            identity: entry.identity.clone(),
            admission_record_root: entry.encoded_root.clone(),
            height,
            block_id: block_id.into(),
            state_root: verifier
                .finalized_state_root()
                .ok_or_else(|| invalid("native finality lacks exact state root"))?
                .into(),
            completion: entry.completion.clone(),
            progress: entry.progress.clone(),
        };
        validate_finalized(&marker, &self.header.namespace_root)?;
        let bytes = encode(&marker)?;
        if bytes.len() > 16 * 1024 {
            return Err(invalid("finalized marker exceeds bound"));
        }
        let root = encoded_root(&bytes);
        self.replace_records(vec![(finalized_path(slot), bytes)])?;
        let entry = self.slots[slot].as_mut().expect("located finalized slot");
        entry.finalized = Some((height, block_id.into()));
        entry.finalized_record_root = Some(root);
        entry.finalized_state_root = Some(marker.state_root);
        Ok(())
    }
    /// Native consumption was verified when this marker was installed or
    /// recovered. Recheck its exact durable state and configured retention
    /// before physical retirement, without rebuilding historical Worlds.
    pub(crate) fn retire_finalized(
        &mut self,
        envelope: &EtdagDigest,
        states: &synergy_state::FinalizedStateStore,
        retain: u64,
    ) -> Result<(), ProcessingStoreError> {
        struct FinalizedRetirement<'a> {
            identity: &'a PendingProcessingIdentity,
        }
        impl ProcessingRetirementVerifier for FinalizedRetirement<'_> {
            fn verify_retirement(&self, item: &PendingProcessingIdentity) -> Result<(), String> {
                if item != self.identity {
                    return Err("finalized retirement identity differs".into());
                }
                Ok(())
            }
        }
        let entry = self
            .slots
            .iter()
            .flatten()
            .find(|entry| &entry.identity.envelope_id == envelope)
            .ok_or_else(|| invalid("unknown finalized retirement"))?;
        let (height, block_id) = entry
            .finalized
            .as_ref()
            .ok_or_else(|| invalid("processing consumption is not finalized"))?;
        let state = states
            .history_at(*height)
            .map_err(|e| invalid(format!("finalized retirement history: {e:?}")))?
            .ok_or_else(|| invalid("finalized retirement lacks durable state"))?;
        let tip = states
            .current()
            .ok_or_else(|| invalid("finalized retirement lacks state tip"))?;
        if &state.finalized_block_id != block_id
            || Some(&state.state_root) != entry.finalized_state_root.as_ref()
            || tip.finalized_height
                < height
                    .checked_add(retain)
                    .ok_or(WorldResourceError::ArithmeticOverflow)?
        {
            return Err(invalid(
                "finalized retirement differs from state/retention fence",
            ));
        }
        // Small exact identity clone is covered by the retained slot index
        // allocation; the untrusted original is still hash-checked in retire.
        let identity = entry.identity.clone();
        self.retire(
            envelope,
            &FinalizedRetirement {
                identity: &identity,
            },
        )
    }

    pub(crate) fn try_quiesce_finalized(
        &mut self,
        envelope: &EtdagDigest,
    ) -> Result<bool, ProcessingStoreError> {
        let entry = self
            .slots
            .iter_mut()
            .flatten()
            .find(|entry| &entry.identity.envelope_id == envelope)
            .ok_or_else(|| invalid("unknown finalized processing envelope"))?;
        if entry.finalized.is_none() {
            return Err(invalid("processing work is not finalized"));
        }
        let retain = quiescent_reservation(
            entry.encoded_bytes,
            entry.completion.as_ref(),
            entry.progress.as_ref(),
        )?;
        Ok(WorldResourceBudget::try_shrink_idle_child(
            &mut entry.workspace,
            retain,
        )?)
    }
    fn verify_finalized_record(
        &self,
        slot: usize,
        entry: &PendingEntry,
    ) -> Result<(), ProcessingStoreError> {
        if let Some(root) = &entry.finalized_record_root {
            self.store
                .inspect_consistent(|reader| -> Result<(), ProcessingStoreError> {
                    let bytes = reader
                        .with_maximum_bytes(16 * 1024)
                        .read_optional_bounded(finalized_path(slot))?
                        .ok_or_else(|| invalid("missing finalized processing marker"))?;
                    if encoded_root(&bytes) != *root {
                        return Err(invalid("finalized processing marker changed"));
                    }
                    Ok(())
                })??;
        }
        Ok(())
    }

    /// Reserve and authenticate before durable acknowledgement. Global nonce
    /// claims include all pending contexts; no height deadline retires a claim.
    /// Identical retransmission is idempotent. A stale second owner fails the
    /// header compare-and-commit instead of creating a conflicting durable slot.
    pub(crate) fn admit(
        &mut self,
        context: &ProcessingContext,
        authorization_timestamp_unix: u64,
        admission_bytes: &[u8],
        verifier: &impl ProcessingAdmissionAuthenticator,
    ) -> Result<PendingProcessingIdentity, ProcessingStoreError> {
        if admission_bytes.is_empty()
            || admission_bytes.len() > MAX_REQUEST_BYTES
            || authorization_timestamp_unix == 0
        {
            return Err(invalid("invalid processing request length/time"));
        }
        let wire_root = encoded_root(admission_bytes);
        // Exact-wire retransmission uses its existing trusted reservation. The
        // index was populated only after original/recovery authentication.
        if let Some(entry) = self.slots.iter().flatten().find(|entry| {
            entry.admission_wire_root == wire_root
                && entry.context == *context
                && entry.authorization_timestamp_unix == authorization_timestamp_unix
        }) {
            return Ok(entry.identity.clone());
        }
        context
            .validate()
            .map_err(|e| invalid(format!("processing context: {e:?}")))?;
        let headroom = PROCESSING_INTAKE_HEADROOM_BYTES.max(self.limits.completion_bytes_per_item);
        let _context_scratch = self
            .budget
            .reserve_with_headroom(MAX_CONTEXT_BYTES * 2, headroom)?;
        encoded_length(context, MAX_CONTEXT_BYTES - 1024)?;
        let admission_json = std::str::from_utf8(admission_bytes)
            .map_err(|e| invalid(format!("processing request UTF-8: {e}")))?;
        let pending = PendingWrite {
            version: 2,
            namespace_root: &self.header.namespace_root,
            context,
            authorization_timestamp_unix,
            admission_json,
        };
        // Count the actual JSON escaping/framing before decoding. The original
        // request remains borrowed; the same conservative 128x worker allowance
        // is retained, without charging an unnecessary worst-case second copy.
        let measured_length = encoded_length(&pending, MAX_SLOT_BYTES)?;
        let mut permit = self
            .budget
            .reserve_with_headroom(reservation(measured_length, self.limits)?, headroom)?;
        let admission: WalletProcessingAdmission = serde_json::from_slice(admission_bytes)
            .map_err(|e| invalid(format!("processing request: {e}")))?;
        admission
            .request
            .validate_context(context)
            .map_err(|e| invalid(format!("processing request binding: {e:?}")))?;
        verifier
            .verify(context, authorization_timestamp_unix, &admission)
            .map_err(ProcessingStoreError::Verification)?;
        let identity = identity(&admission);
        let bytes = encode(&pending)?;
        if bytes.len() != measured_length {
            return Err(invalid(
                "pending processing encoding changed after measurement",
            ));
        }
        let root = encoded_root(&bytes);
        for entry in self.slots.iter().flatten() {
            if entry.identity.envelope_id == identity.envelope_id {
                return if entry.encoded_root == root {
                    Ok(identity)
                } else {
                    Err(invalid("conflicting immutable processing request"))
                };
            }
            if entry.identity.sender_wallet == identity.sender_wallet
                && entry.identity.sender_nonce == identity.sender_nonce
            {
                return Err(ProcessingStoreError::NonceClaimed);
            }
        }
        let slot = self
            .slots
            .iter()
            .position(Option::is_none)
            .ok_or(ProcessingStoreError::Full)?;
        let length = bytes.len();
        // Grow before commit if a future encoding change requires more. Never
        // report a reservation rejection after durably accepting the request.
        if reservation(length, self.limits)? > permit.bytes() {
            permit.resize_with_headroom(reservation(length, self.limits)?, headroom)?;
        }
        self.replace_slot(slot, bytes)?;
        drop(admission);
        permit.resize(reservation(length, self.limits)?)?;
        self.slots[slot] = Some(PendingEntry {
            historical_kem_recovery: false,
            identity: identity.clone(),
            encoded_root: root,
            encoded_bytes: length,
            context: context.clone(),
            authorization_timestamp_unix,
            admission_wire_root: wire_root,
            completion: None,
            progress: None,
            finalized: None,
            finalized_record_root: None,
            finalized_state_root: None,
            workspace: permit.into_budget(),
        });
        Ok(identity)
    }

    /// Loaded only after immutable bytes and native admission authentication.
    /// Version 1 predates the FIPS 203 link correction; no records are rewritten.
    /// Every newly admitted request is version 2 and remains FIPS-only on restart.
    pub(crate) fn allows_historical_kem_recovery(
        &self,
        envelope: &EtdagDigest,
    ) -> Result<bool, ProcessingStoreError> {
        self.slots
            .iter()
            .flatten()
            .find(|entry| &entry.identity.envelope_id == envelope)
            .map(|entry| entry.historical_kem_recovery)
            .ok_or_else(|| invalid("unknown pending processing envelope"))
    }

    /// Reuse the item's retained reservation instead of reserving a second
    /// decode peak. The serial owner cannot run two operations on the same
    /// item concurrently. The borrowed decoded payload cannot escape callback.
    pub(crate) fn with_admission<T>(
        &mut self,
        envelope: &EtdagDigest,
        verifier: &impl ProcessingAdmissionAuthenticator,
        action: impl FnOnce(
            &ProcessingContext,
            u64,
            &WalletProcessingAdmission,
        ) -> Result<T, ProcessingStoreError>,
    ) -> Result<T, ProcessingStoreError> {
        self.with_worker(envelope, verifier, |context, timestamp, admission, _| {
            action(context, timestamp, admission)
        })
    }

    /// The worker allocates only from capacity held before intake ack. Results
    /// may retain child permits; those retain the parent charge independently
    /// of slot retirement, so no allocation becomes unaccounted on handoff.
    pub(crate) fn with_worker<T>(
        &mut self,
        envelope: &EtdagDigest,
        verifier: &impl ProcessingAdmissionAuthenticator,
        action: impl FnOnce(
            &ProcessingContext,
            u64,
            &WalletProcessingAdmission,
            &Arc<WorldResourceBudget>,
        ) -> Result<T, ProcessingStoreError>,
    ) -> Result<T, ProcessingStoreError> {
        let slot = self
            .slots
            .iter()
            .position(|entry| {
                entry
                    .as_ref()
                    .is_some_and(|entry| &entry.identity.envelope_id == envelope)
            })
            .ok_or_else(|| invalid("unknown pending processing envelope"))?;
        let entry = self.slots[slot].as_ref().expect("located occupied slot");
        if entry.finalized.is_some() {
            return Err(invalid("finalized processing work is quiescent"));
        }
        let _read = entry
            .workspace
            .reserve(read_reservation(entry.encoded_bytes)?)?;
        let bytes = self.read_entry(slot, entry)?;
        let record: StoredPending =
            serde_json::from_slice(&bytes).map_err(|e| invalid(format!("pending slot: {e}")))?;
        let admission = verify_retained_stored(&record, &self.header.namespace_root, verifier)?;
        action(
            &record.context,
            record.authorization_timestamp_unix,
            &admission,
            &entry.workspace,
        )
    }

    pub(crate) fn retire(
        &mut self,
        envelope: &EtdagDigest,
        verifier: &impl ProcessingRetirementVerifier,
    ) -> Result<(), ProcessingStoreError> {
        let slot = self
            .slots
            .iter()
            .position(|entry| {
                entry
                    .as_ref()
                    .is_some_and(|entry| &entry.identity.envelope_id == envelope)
            })
            .ok_or_else(|| invalid("unknown pending retirement"))?;
        let entry = self.slots[slot].as_ref().expect("located occupied slot");
        let _read = entry.workspace.reserve(quiescent_reservation(
            entry.encoded_bytes,
            entry.completion.as_ref(),
            entry.progress.as_ref(),
        )?)?;
        self.read_entry(slot, entry)?;
        self.verify_finalized_record(slot, entry)?;
        if let Some(completion) = &entry.completion {
            self.read_completion(slot, completion)?;
        }
        if let Some(progress) = &entry.progress {
            self.read_progress(slot, progress)?;
        }
        verifier
            .verify_retirement(&entry.identity)
            .map_err(ProcessingStoreError::Verification)?;
        self.replace_records(vec![
            (slot_path(slot), b"null".to_vec()),
            (completion_path(slot), b"null".to_vec()),
            (progress::path(slot), b"null".to_vec()),
            (finalized_path(slot), b"null".to_vec()),
        ])?;
        self.slots[slot] = None; // Release only after durable retirement succeeds.
        Ok(())
    }

    /// Verify and persist only this completion witness. Original signed intake
    /// bytes are never rewritten. A failed verification/CAS leaves both files
    /// intact and the item's prepaid worker capacity immediately reusable.
    pub(crate) fn complete(
        &mut self,
        envelope: &EtdagDigest,
        evidence: &ProcessingCompletionEvidence,
        verifier: &impl ProcessingAdmissionAuthenticator,
    ) -> Result<(), ProcessingStoreError> {
        let slot = self
            .slots
            .iter()
            .position(|entry| {
                entry
                    .as_ref()
                    .is_some_and(|entry| &entry.identity.envelope_id == envelope)
            })
            .ok_or_else(|| invalid("unknown pending completion"))?;
        let entry = self.slots[slot].as_ref().expect("located occupied slot");
        if entry.finalized.is_some() {
            return Err(invalid("finalized processing work is quiescent"));
        }
        let workspace = Arc::clone(&entry.workspace);
        let _read = workspace.reserve(read_reservation(entry.encoded_bytes)?)?;
        let original = self.read_entry(slot, entry)?;
        let pending: StoredPending = serde_json::from_slice(&original)
            .map_err(|e| invalid(format!("pending completion source: {e}")))?;
        let admission = verify_retained_stored(&pending, &self.header.namespace_root, verifier)?;
        // Measure without allocating the witness serialization first.
        struct Counter(usize);
        impl std::io::Write for Counter {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                self.0 = self
                    .0
                    .checked_add(bytes.len())
                    .ok_or_else(|| std::io::Error::other("completion size overflow"))?;
                Ok(bytes.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let _measure = workspace.reserve(16 * 1024)?;
        let mut count = Counter(0);
        serde_json::to_writer(&mut count, evidence).map_err(|e| invalid(e.to_string()))?;
        let encoded_bound = count
            .0
            .checked_add(4096)
            .ok_or(WorldResourceError::ArithmeticOverflow)?;
        if encoded_bound > MAX_SLOT_BYTES {
            return Err(invalid("completion witness too large"));
        }
        verifier
            .verify_completion(&pending.context, &admission, evidence, &workspace)
            .map_err(ProcessingStoreError::Verification)?;
        // Verification has its own charged decode/crypto workspace. No encoded
        // completion exists yet: reserve its serialization immediately before
        // allocating it, after the verifier's temporary reconstruction drops.
        let _encode = workspace.reserve(completion_reservation(encoded_bound)?)?;
        let bytes = encode(&StoredCompletion {
            version: 1,
            namespace_root: self.header.namespace_root.clone(),
            identity: entry.identity.clone(),
            admission_record_root: entry.encoded_root.clone(),
            evidence: evidence.clone(),
        })?;
        if bytes.len() > encoded_bound {
            return Err(invalid("completion framing exceeded bound"));
        }
        let index = CompletionIndex {
            root: encoded_root(&bytes),
            bytes: bytes.len(),
            record_root: completion_record_root(evidence)?,
        };
        if let Some(existing) = &entry.completion {
            self.read_completion(slot, existing)?;
            // Different valid signer/share subsets are the same completion.
            // Preserve the first durable witness instead of rewriting it.
            return if existing.record_root == index.record_root {
                Ok(())
            } else {
                Err(invalid("conflicting immutable processing completion"))
            };
        }
        self.replace_records(vec![(completion_path(slot), bytes)])?;
        self.slots[slot]
            .as_mut()
            .expect("occupied completion slot")
            .completion = Some(index);
        Ok(())
    }

    /// Reconstruct/verify from original authority and existing PoSy evidence
    /// before exposing a completion, including after interruption or restart.
    pub(crate) fn with_completion<T>(
        &mut self,
        envelope: &EtdagDigest,
        verifier: &impl ProcessingAdmissionAuthenticator,
        action: impl FnOnce(
            &WalletProcessingAdmission,
            &ProcessingCompletionEvidence,
            &Arc<WorldResourceBudget>,
        ) -> Result<T, ProcessingStoreError>,
    ) -> Result<T, ProcessingStoreError> {
        let slot = self
            .slots
            .iter()
            .position(|entry| {
                entry
                    .as_ref()
                    .is_some_and(|entry| &entry.identity.envelope_id == envelope)
            })
            .ok_or_else(|| invalid("unknown pending completion"))?;
        let entry = self.slots[slot].as_ref().expect("located occupied slot");
        if entry.finalized.is_some() {
            return Err(invalid("finalized processing work is quiescent"));
        }
        let index = entry
            .completion
            .as_ref()
            .ok_or_else(|| invalid("completion not durable"))?;
        let _read = entry
            .workspace
            .reserve(read_reservation(entry.encoded_bytes)?)?;
        let _decode = entry
            .workspace
            .reserve(completion_reservation(index.bytes)?)?;
        let original = self.read_entry(slot, entry)?;
        let pending: StoredPending = serde_json::from_slice(&original)
            .map_err(|e| invalid(format!("pending completion source: {e}")))?;
        let admission = verify_retained_stored(&pending, &self.header.namespace_root, verifier)?;
        let bytes = self.read_completion(slot, index)?;
        let completion = verify_completion(
            &bytes,
            &self.header.namespace_root,
            &entry.encoded_root,
            &pending.context,
            &admission,
            verifier,
            &entry.workspace,
        )?;
        action(&admission, &completion.evidence, &entry.workspace)
    }

    fn read_completion(
        &self,
        slot: usize,
        index: &CompletionIndex,
    ) -> Result<Vec<u8>, ProcessingStoreError> {
        self.store
            .inspect_consistent(|reader| -> Result<_, ProcessingStoreError> {
                let bytes = reader
                    .with_maximum_bytes(index.bytes)
                    .read_optional_bounded(completion_path(slot))?
                    .ok_or_else(|| invalid("missing immutable completion"))?;
                if bytes.len() != index.bytes || encoded_root(&bytes) != index.root {
                    return Err(invalid("immutable processing completion changed"));
                }
                Ok(bytes)
            })?
    }

    fn read_entry(
        &self,
        slot: usize,
        entry: &PendingEntry,
    ) -> Result<Vec<u8>, ProcessingStoreError> {
        self.store
            .inspect_consistent(|reader| -> Result<Vec<u8>, ProcessingStoreError> {
                let path = slot_path(slot);
                if reader.optional_record_bytes(&path)? != Some(entry.encoded_bytes) {
                    return Err(invalid("immutable pending record length changed"));
                }
                let bytes = reader
                    .with_maximum_bytes(entry.encoded_bytes)
                    .read_optional_bounded(&path)?
                    .ok_or_else(|| invalid("missing pending slot"))?;
                if encoded_root(&bytes) != entry.encoded_root {
                    return Err(invalid("immutable pending record changed"));
                }
                Ok(bytes)
            })?
    }

    fn replace_slot(&mut self, slot: usize, bytes: Vec<u8>) -> Result<(), ProcessingStoreError> {
        self.replace_records(vec![(slot_path(slot), bytes)])
    }
    fn replace_records(
        &mut self,
        records: Vec<(String, Vec<u8>)>,
    ) -> Result<(), ProcessingStoreError> {
        let mut next = self.header.clone();
        next.generation = next
            .generation
            .checked_add(1)
            .ok_or_else(|| invalid("pending generation exhausted"))?;
        let expected = encode(&self.header)?;
        let mut transaction = StorageTransaction::new(2 * MAX_SLOT_BYTES + 4096)?;
        transaction.put(HEADER, encode(&next)?)?;
        for (path, bytes) in records {
            transaction.put(path, bytes)?;
        }
        transaction.commit_guarded(
            &mut self.store,
            &[StoragePrecondition {
                relative_path: HEADER.into(),
                required: RequiredRecord::Exact(expected),
            }],
        )?;
        self.header = next;
        Ok(())
    }
}

#[cfg(test)]
mod measurement_tests {
    use super::*;

    #[test]
    fn pending_record_count_matches_json_escaping_and_enforces_exact_bound() {
        #[derive(Serialize)]
        struct Borrowed<'a> {
            context: &'a str,
            admission_json: &'a str,
        }
        let request = "{\"request\":\"\\\\\\n\\u0000é\"}";
        let record = Borrowed {
            context: "frozen\ncontext",
            admission_json: request,
        };
        let expected = encode(&record).unwrap();
        assert_eq!(
            encoded_length(&record, expected.len()).unwrap(),
            expected.len()
        );
        assert!(encoded_length(&record, expected.len() - 1).is_err());
        assert!(encoded_length(&record, 0).is_err());
    }
}
