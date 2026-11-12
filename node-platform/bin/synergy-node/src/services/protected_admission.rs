//! Bounded RPC-to-ETDAG handoff. Queuing is not admission or finality.
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, VecDeque};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{json, Value};
#[cfg(test)]
use synergy_aegis::AegisPolicy;
use synergy_aegis::{
    AegisVerifier, KeyId, PqvmVerifier, Signature, SignatureAlgorithm, SigningContext,
};
pub use synergy_etdag::WalletAdmission;
use synergy_etdag::{EtdagDigest, ProcessingContext, WalletProcessingAdmission};
use synergy_identity::authorization::IdentityAuthorizationCarrier;

const MAX_PENDING: usize = 16;
const MAX_PENDING_BYTES: usize = 8 * 1024 * 1024;
const MAX_REQUEST_BYTES: usize = 1024 * 1024;
const MAX_RECEIPTS: usize = 256;
const RECEIPT_TTL: Duration = Duration::from_secs(120);

/// Resolve an existing binding or a verified first-use root/key carrier, then
/// verify the unchanged canonical outer admission signature. This does not
/// decrypt, order, finalize, or authorize an execution state transition.
pub fn verify_wallet_admission_with_authority(
    admission: &WalletAdmission,
    world: &synergy_state::WorldState,
    chain_id: u64,
    network_id: &str,
    consensus_timestamp_unix: u64,
    authority: Option<&super::authority::VerifiedAuthority>,
) -> Result<(), String> {
    let request = &admission.request;
    request
        .validate_shape()
        .map_err(|e| format!("invalid admission: {e:?}"))?;
    if request.chain_id != chain_id
        || request.network_id != network_id
        || request.envelope.aad.sender_id != request.sender_wallet
        || request.envelope.aad.nonce_slot != request.sender_nonce
        || request.signature_algorithm != "ML-DSA-87"
    {
        return Err("admission sender, nonce, algorithm or network mismatch".into());
    }
    verify_wallet_admission_binding(
        &request.sender_wallet,
        &request.signer_public_key,
        &admission.identity_authorization,
        world,
        (chain_id, network_id),
        consensus_timestamp_unix,
        authority.and_then(|a| a.identity_verifier()),
    )?;
    verify_native_admission_signature_using(
        authority.map(|a| a.wallet_verifier()),
        chain_id,
        &request.signer_public_key,
        &request.signature,
        &request
            .signing_bytes()
            .map_err(|e| format!("admission signing bytes: {e:?}"))?,
    )
}

/// Native verification of original asynchronous processing authorization.
/// The caller independently authenticates the frozen context, supplies its
/// authoritative account state and derives its consensus authorization time.
/// This grants no queue, group, reveal, inclusion or finality authority.
#[cfg_attr(not(test), allow(dead_code))] // Governed runtime profile wiring is a separate step.
#[cfg(test)]
pub fn verify_wallet_processing_admission(
    admission: &WalletProcessingAdmission,
    expected_context: &ProcessingContext,
    world: &synergy_state::WorldState,
    consensus_authorization_timestamp_unix: u64,
) -> Result<(), String> {
    verify_wallet_processing_admission_with_authority(
        admission,
        expected_context,
        world,
        consensus_authorization_timestamp_unix,
        None,
    )
}
pub fn verify_wallet_processing_admission_with_authority(
    admission: &WalletProcessingAdmission,
    expected_context: &ProcessingContext,
    world: &synergy_state::WorldState,
    consensus_authorization_timestamp_unix: u64,
    verification_authority: Option<&super::authority::VerifiedAuthority>,
) -> Result<(), String> {
    let request = &admission.request;
    request
        .validate_context(expected_context)
        .map_err(|e| format!("invalid processing admission context: {e:?}"))?;
    let authority = &expected_context.authority;
    verify_wallet_admission_binding(
        &request.sender_wallet,
        &request.signer_public_key,
        &admission.identity_authorization,
        world,
        (authority.chain_id, &authority.network_id),
        consensus_authorization_timestamp_unix,
        verification_authority.and_then(|a| a.identity_verifier()),
    )?;
    verify_native_admission_signature_using(
        verification_authority.map(|a| a.wallet_verifier()),
        authority.chain_id,
        &request.signer_public_key,
        &request.signature,
        &request
            .signing_bytes()
            .map_err(|e| format!("processing admission signing bytes: {e:?}"))?,
    )
}

/// Shared canonical Aegis identity path. Keeping the profile transcript outside
/// this helper prevents reinterpretation of either profile's signed bytes.
fn verify_wallet_admission_binding(
    sender_wallet: &str,
    signer_public_key: &[u8],
    identity_authorization: &IdentityAuthorizationCarrier,
    world: &synergy_state::WorldState,
    network: (u64, &str),
    consensus_timestamp_unix: u64,
    verifier: Option<&dyn synergy_identity::authorization::AuthorizationSignatureVerifier>,
) -> Result<(), String> {
    let (chain_id, network_id) = network;
    synergy_identity::authorization::resolve_transaction_binding_with_verifier(
        &world.protocol,
        sender_wallet,
        identity_authorization,
        signer_public_key,
        chain_id,
        network_id,
        consensus_timestamp_unix,
        verifier,
    )?;
    Ok(())
}

#[cfg(test)]
fn verify_native_admission_signature(
    chain_id: u64,
    signer_public_key: &[u8],
    signature: &[u8],
    signing_bytes: &[u8],
) -> Result<(), String> {
    verify_native_admission_signature_using(
        None,
        chain_id,
        signer_public_key,
        signature,
        signing_bytes,
    )
}
fn verify_native_admission_signature_using(
    injected: Option<&PqvmVerifier>,
    chain_id: u64,
    signer_public_key: &[u8],
    signature: &[u8],
    signing_bytes: &[u8],
) -> Result<(), String> {
    #[cfg(test)]
    let fallback;
    let verifier = match injected {
        Some(verifier) => verifier,
        None => {
            #[cfg(not(test))]
            return Err("explicit APQE admission verification context required".into());
            #[cfg(test)]
            {
                fallback = PqvmVerifier::new(AegisPolicy {
                    allowed_algorithms: vec![SignatureAlgorithm::MlDsa87],
                    maximum_message_bytes: MAX_REQUEST_BYTES,
                    maximum_signature_bytes: 16 * 1024,
                })
                .map_err(|e| format!("construct admission verifier: {e}"))?;
                &fallback
            }
        }
    };
    verifier
        .verify(
            &SigningContext {
                domain: "SYNERGY-TRANSACTION-SIGNING-V1".into(),
                chain_id,
                epoch: None,
                height: None,
            },
            signing_bytes,
            &Signature {
                algorithm: SignatureAlgorithm::MlDsa87,
                key_id: KeyId::new("admission-presented-key").map_err(|e| e.to_string())?,
                bytes: signature.to_vec(),
            },
            signer_public_key,
        )
        .map_err(|e| format!("verify governed admission signature: {e}"))?;
    Ok(())
}

pub struct PendingAdmission {
    pub id: String,
    pub admission: WalletAdmission,
    bytes: usize,
}
impl PendingAdmission {
    pub fn owned_byte_charge(&self) -> usize {
        self.bytes.saturating_mul(2).saturating_add(64 * 1024)
    }
}

/// Original authorization is passed unchanged to the sole ETDAG owner.
pub struct PendingProcessingAdmission {
    pub id: String,
    pub admission: WalletProcessingAdmission,
    bytes: usize,
}
pub(crate) fn processing_admission_owned_byte_charge(bytes: usize) -> usize {
    bytes.saturating_mul(2).saturating_add(64 * 1024)
}

pub(crate) fn maximum_processing_admission_owned_byte_charge() -> usize {
    processing_admission_owned_byte_charge(MAX_REQUEST_BYTES)
}

impl PendingProcessingAdmission {
    pub fn owned_byte_charge(&self) -> usize {
        processing_admission_owned_byte_charge(self.bytes)
    }
}

struct PublishedProcessingContext {
    context: ProcessingContext,
    response: Value,
}

fn bounded_json_bytes(value: &impl Serialize, maximum: usize) -> Result<usize, String> {
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
                .ok_or_else(|| std::io::Error::other("admission request exceeds byte bound"))?;
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut counter = Counter { bytes: 0, maximum };
    serde_json::to_writer(&mut counter, value).map_err(|e| e.to_string())?;
    Ok(counter.bytes)
}

const MAX_DURABLE_RECEIPT_BYTES: usize = 16 * 1024;

pub fn rejection_code(reason: &str) -> &'static str {
    if reason.contains("closed") {
        "closed_target"
    } else if reason.contains("full")
        || reason.contains("capacity")
        || reason.contains("byte bound")
    {
        "overload"
    } else if reason.contains("persistence") || reason.contains("poisoned") {
        "safety_failure"
    } else if reason.contains("unavailable") {
        "unavailable"
    } else {
        "invalid_authority"
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DurableReceipt {
    version: u16,
    namespace: String,
    receipt_id: String,
    value: Value,
    retained_at_unix_ms: u64,
    checksum: EtdagDigest,
}
impl DurableReceipt {
    fn checksum(&self) -> Result<EtdagDigest, String> {
        EtdagDigest::from_canonical(
            "SYNERGY_ADMISSION_OBSERVATION_JOURNAL_V1",
            &(
                self.version,
                &self.namespace,
                &self.receipt_id,
                &self.value,
                self.retained_at_unix_ms,
            ),
        )
        .map_err(|e| format!("receipt observation checksum: {e:?}"))
    }
    fn validate(&self, namespace: &str) -> Result<(), String> {
        validate_receipt_id(&self.receipt_id)?;
        if self.version != 1
            || self.namespace != namespace
            || self.checksum()? != self.checksum
            || self.value.get("receipt_id").and_then(Value::as_str)
                != Some(self.receipt_id.as_str())
            || !matches!(
                self.value.get("status").and_then(Value::as_str),
                Some("accepted" | "rejected")
            )
        {
            return Err("corrupt or wrong-authority admission observation".into());
        }
        match self.value.get("status").and_then(Value::as_str) {
            Some("accepted")
                if self.value.get("admitted").and_then(Value::as_bool) == Some(true)
                    && matches!(
                        self.value.get("lifecycle_status").and_then(Value::as_str),
                        Some("accepted" | "certified" | "ordered")
                    )
                    && self
                        .value
                        .pointer("/evidence/finalized")
                        .and_then(Value::as_bool)
                        == Some(false) => {}
            Some("accepted")
                if self.value.get("admitted").and_then(Value::as_bool) == Some(true)
                    // The original admission evidence never confers finality.
                    // Processing milestones are separate observations, written
                    // only after their native authenticated transitions.
                    && self.value.pointer("/evidence/finalized").and_then(Value::as_bool)
                        == Some(false)
                    && match self.value.get("lifecycle_status").and_then(Value::as_str) {
                        Some("reveal_authorized" | "execution_completed") =>
                            self.value.pointer("/stage_evidence/finalized").and_then(Value::as_bool)
                                == Some(false),
                        Some("finalized") =>
                            self.value.pointer("/stage_evidence/finalized").and_then(Value::as_bool)
                                == Some(true)
                            && self.value.pointer("/stage_evidence/finalized_height").and_then(Value::as_u64)
                                .is_some_and(|height| height > 0)
                            && self.value.pointer("/stage_evidence/finalized_block_id").and_then(Value::as_str)
                                .is_some_and(|id| id.len() == 64 && id.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))),
                        _ => false,
                    } => {}
            Some("rejected")
                if self.value.get("admitted").and_then(Value::as_bool) == Some(false) => {}
            _ => return Err("receipt observation claims unsupported authority".into()),
        }
        Ok(())
    }
}

struct ReceiptJournal {
    root: PathBuf,
    namespace: String,
    store: synergy_storage::AtomicStore,
    retained: Mutex<BTreeMap<String, u64>>,
}
fn validate_receipt_id(id: &str) -> Result<(), String> {
    if id.len() != 128
        || !id
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("invalid receipt id".into());
    }
    Ok(())
}
impl ReceiptJournal {
    fn open(root: &Path, namespace: String) -> Result<(Self, BTreeMap<String, Receipt>), String> {
        validate_receipt_id(&namespace)?;
        for ancestor in root.ancestors() {
            if fs::symlink_metadata(ancestor).is_ok_and(|m| m.file_type().is_symlink()) {
                return Err("receipt observation path cannot contain symlink".into());
            }
        }
        let root = root.join(&namespace);
        if fs::symlink_metadata(&root).is_ok_and(|m| m.file_type().is_symlink()) {
            return Err("receipt namespace cannot be symlink".into());
        }
        let store = synergy_storage::AtomicStore::new(&root, MAX_DURABLE_RECEIPT_BYTES)
            .map_err(|e| format!("open receipt observations: {e}"))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&root, fs::Permissions::from_mode(0o700))
                .map_err(|e| e.to_string())?;
        }
        let mut retained = BTreeMap::new();
        let mut restored = BTreeMap::new();
        for entry in fs::read_dir(&root).map_err(|e| e.to_string())? {
            let entry = entry.map_err(|e| e.to_string())?;
            let name = entry.file_name().to_string_lossy().into_owned();
            if !name.starts_with("receipt-") {
                continue;
            }
            if retained.len() >= MAX_RECEIPTS {
                return Err("durable receipt observation capacity exceeded".into());
            }
            let id = name
                .strip_prefix("receipt-")
                .and_then(|s| s.strip_suffix(".json"))
                .ok_or("corrupt receipt observation filename")?;
            validate_receipt_id(id)?;
            let record: DurableReceipt = serde_json::from_slice(
                &store
                    .read_bounded(&name)
                    .map_err(|e| format!("read receipt observation: {e}"))?,
            )
            .map_err(|e| e.to_string())?;
            record.validate(&namespace)?;
            if record.receipt_id != id {
                return Err("receipt filename binding mismatch".into());
            }
            retained.insert(id.to_owned(), record.retained_at_unix_ms);
            restored.insert(
                id.to_owned(),
                Receipt {
                    value: record.value,
                    completed_at: Some(Instant::now()),
                },
            );
        }
        Ok((
            Self {
                root,
                namespace,
                store,
                retained: Mutex::new(retained),
            },
            restored,
        ))
    }
    fn persist(&self, id: &str, value: &Value) -> Result<(), String> {
        validate_receipt_id(id)?;
        let mut record = DurableReceipt {
            version: 1,
            namespace: self.namespace.clone(),
            receipt_id: id.into(),
            value: value.clone(),
            retained_at_unix_ms: u64::try_from(
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map_err(|e| e.to_string())?
                    .as_millis(),
            )
            .map_err(|e| e.to_string())?,
            checksum: EtdagDigest::from_domain_bytes("pending", b"receipt"),
        };
        record.checksum = record.checksum()?;
        record.validate(&self.namespace)?;
        let retired = {
            let retained = self
                .retained
                .lock()
                .map_err(|_| "receipt journal lock poisoned")?;
            if retained.len() >= MAX_RECEIPTS && !retained.contains_key(id) {
                retained
                    .iter()
                    .min_by_key(|(_, at)| *at)
                    .map(|(id, _)| id.clone())
            } else {
                None
            }
        };
        // Only bounded observation records are retired. No consensus/availability safety record is touched.
        if let Some(retired) = &retired {
            fs::remove_file(self.root.join(format!("receipt-{retired}.json")))
                .map_err(|e| e.to_string())?;
        }
        self.store
            .write_atomic(
                format!("receipt-{id}.json"),
                &serde_json::to_vec(&record).map_err(|e| e.to_string())?,
            )
            .map_err(|e| format!("persist receipt observation: {e}"))?;
        let mut retained = self
            .retained
            .lock()
            .map_err(|_| "receipt journal lock poisoned")?;
        if let Some(retired) = retired {
            retained.remove(&retired);
        }
        retained.insert(id.into(), record.retained_at_unix_ms);
        Ok(())
    }
}

struct Receipt {
    value: Value,
    completed_at: Option<Instant>,
}

#[derive(Default)]
struct State {
    context: Option<Value>,
    context_v2: Option<Value>,
    processing_context: Option<PublishedProcessingContext>,
    journal: Option<Arc<ReceiptJournal>>,
    ingress: Option<super::ingress::AuthenticatedIngress>,
    pending: VecDeque<PendingAdmission>,
    processing_pending: VecDeque<PendingProcessingAdmission>,
    pending_bytes: usize,
    inflight: BTreeMap<String, usize>,
    receipts: BTreeMap<String, Receipt>,
    accepted_total: u64,
    rejected_total: u64,
    ordered_total: u64,
    ordered_targets: BTreeMap<u64, EtdagDigest>,
}

#[derive(Clone, Default)]
pub struct AdmissionHandle(Arc<Mutex<State>>);

#[cfg(feature = "qualification-timing")]
pub(super) struct AdmissionTimingSpan {
    target: u64,
    subject: String,
}
#[cfg(feature = "qualification-timing")]
impl AdmissionTimingSpan {
    pub(super) fn start(admission: &WalletAdmission, stage: &'static str) -> Option<Self> {
        use super::qualification_timing::{self as timing, Classification, Kind, Phase, Role};
        if !timing::enabled() {
            return None;
        }
        // Only a public ciphertext commitment and bounded static stage enter the trace hash.
        let subject = format!("{}:{stage}", admission.request.envelope.envelope_id.0);
        let span = Self {
            target: admission.request.target_height,
            subject,
        };
        timing::emit_subject_once(
            Kind::Runtime,
            Phase::Start,
            span.target,
            0,
            0,
            &span.subject,
            Role::Participant,
            Classification::Observed,
            None,
            None,
        );
        Some(span)
    }
}
#[cfg(feature = "qualification-timing")]
impl Drop for AdmissionTimingSpan {
    fn drop(&mut self) {
        use super::qualification_timing::{self as timing, Classification, Kind, Phase, Role};
        timing::emit_subject_once(
            Kind::Runtime,
            Phase::End,
            self.target,
            0,
            0,
            &self.subject,
            Role::Participant,
            Classification::Observed,
            None,
            None,
        );
    }
}

impl AdmissionHandle {
    pub fn bind_ingress(
        &self,
        ingress: super::ingress::AuthenticatedIngress,
    ) -> Result<(), String> {
        self.0
            .lock()
            .map_err(|_| "admission lock poisoned")?
            .ingress = Some(ingress);
        Ok(())
    }

    /// ETDAG owner only: restore observations before publishing any admission context.
    pub fn bind_receipt_journal(&self, root: &Path, namespace: String) -> Result<(), String> {
        let (journal, restored) = ReceiptJournal::open(root, namespace)?;
        let mut state = self.0.lock().map_err(|_| "admission lock poisoned")?;
        if !state.pending.is_empty()
            || !state.processing_pending.is_empty()
            || state.journal.is_some()
        {
            return Err("receipt journal already active".into());
        }
        state.receipts = restored;
        state.journal = Some(Arc::new(journal));
        Ok(())
    }

    pub fn publish_context_v2(&self, context: Option<Value>) -> Result<(), String> {
        self.0
            .lock()
            .map_err(|_| "admission lock poisoned")?
            .context_v2 = context;
        Ok(())
    }
    /// Only the signed epoch policy activates this versioned API. The owner
    /// supplies the finalized-source context; this publication is no inclusion
    /// promise and has no legacy target-height cutoff.
    pub fn publish_processing_context(
        &self,
        authority: &super::authority::VerifiedAuthority,
        response: Option<Value>,
    ) -> Result<(), String> {
        let published = match response {
            None => None,
            Some(response) => {
                if !authority.processing_profile_enabled() {
                    return Err("signed asynchronous processing profile is unavailable".into());
                }
                let context: ProcessingContext = serde_json::from_value(
                    response
                        .get("context")
                        .cloned()
                        .ok_or("processing context missing")?,
                )
                .map_err(|e| format!("decode processing context: {e}"))?;
                context
                    .validate()
                    .map_err(|e| format!("processing context: {e:?}"))?;
                let frozen = &context.authority;
                let epoch = &authority.epoch;
                let registry_root = authority
                    .protected_ingress_registry()?
                    .root()
                    .map_err(|e| format!("processing registry root: {e:?}"))?;
                if frozen.chain_id != epoch.chain_id
                    || frozen.network_id != epoch.network_id
                    || frozen.protocol_version != epoch.protocol_version
                    || frozen.epoch != epoch.epoch
                    || frozen.active_validator_set_root != epoch.active_validator_set_root
                    || frozen.validator_consensus_key_root != epoch.validator_consensus_key_root
                    || frozen.frozen_voting_weight_root != epoch.frozen_voting_weight_root
                    || frozen.finalized_epoch_seed_root != epoch.finalized_epoch_seed_root
                    || frozen.consensus_parameter_root != epoch.consensus_parameter_root
                    || frozen.ingress_kem_registry_root != registry_root
                    || frozen.assigned_cluster_validator_count
                        != authority.registry.active_count() as u64
                {
                    return Err("processing context differs from signed authority".into());
                }
                let registry: synergy_etdag::crypto::IngressKemKeyRegistry =
                    serde_json::from_value(
                        response
                            .get("ingress_kem_registry")
                            .cloned()
                            .ok_or("processing ingress registry missing")?,
                    )
                    .map_err(|e| format!("decode processing ingress registry: {e}"))?;
                if registry
                    .root()
                    .map_err(|e| format!("published processing registry: {e:?}"))?
                    != registry_root
                {
                    return Err(
                        "published processing registry differs from signed authority".into(),
                    );
                }
                if bounded_json_bytes(&response, MAX_REQUEST_BYTES)? > MAX_REQUEST_BYTES {
                    return Err("processing context exceeds byte bound".into());
                }
                Some(PublishedProcessingContext { context, response })
            }
        };
        self.0
            .lock()
            .map_err(|_| "admission lock poisoned")?
            .processing_context = published;
        Ok(())
    }

    pub fn processing_context(&self) -> Result<Value, String> {
        self.0
            .lock()
            .map_err(|_| "admission lock poisoned")?
            .processing_context
            .as_ref()
            .map(|p| p.response.clone())
            .ok_or_else(|| "asynchronous processing admission is unavailable".into())
    }

    pub fn enqueue_processing(
        &self,
        admission: WalletProcessingAdmission,
    ) -> Result<Value, String> {
        admission
            .request
            .validate_shape()
            .map_err(|e| format!("invalid processing admission: {e:?}"))?;
        let bytes = bounded_json_bytes(&admission, MAX_REQUEST_BYTES)?;
        let id = EtdagDigest::from_canonical(
            "SYNERGY_LOCAL_PROCESSING_ADMISSION_RECEIPT_V1",
            &admission,
        )
        .map_err(|e| format!("derive processing admission receipt: {e:?}"))?
        .0;
        let mut state = self.0.lock().map_err(|_| "admission lock poisoned")?;
        let published = &state
            .processing_context
            .as_ref()
            .ok_or("asynchronous processing admission is unavailable")?
            .context
            .authority;
        let aad = &admission.request.envelope.aad;
        if aad.chain_id != published.chain_id
            || aad.network_id != published.network_id
            || aad.protocol_version != published.protocol_version
            || aad.epoch != published.epoch
        {
            return Err("processing admission differs from signed network authority".into());
        }
        // Do not substitute the latest published context root: the owner verifies
        // this original frozen context independently, even after later blocks.
        let now = Instant::now();
        state.receipts.retain(|_, receipt| {
            receipt.completed_at.is_none_or(|at| {
                receipt.value.get("admitted").and_then(Value::as_bool) == Some(true)
                    || now.duration_since(at) < RECEIPT_TTL
            })
        });
        if let Some(receipt) = state.receipts.get(&id) {
            return Ok(receipt.value.clone());
        }
        if state.pending.len() + state.processing_pending.len() + state.inflight.len()
            >= MAX_PENDING
            || bytes > MAX_PENDING_BYTES.saturating_sub(state.pending_bytes)
        {
            return Err("protected admission queue is full".into());
        }
        if state.receipts.len() >= MAX_RECEIPTS {
            let oldest = state
                .receipts
                .iter()
                .filter_map(|(id, r)| r.completed_at.map(|at| (id.clone(), at)))
                .min_by_key(|(_, at)| *at)
                .map(|(id, _)| id)
                .ok_or("protected admission receipt capacity reached")?;
            state.receipts.remove(&oldest);
        }
        let value = json!({"receipt_id":id,"status":"queued","profile_id":synergy_etdag::PROCESSING_PROFILE_ID,
            "processing_context_root":admission.request.context_root,
            "envelope_id":admission.request.envelope.envelope_id,"admitted":false,
            "lifecycle_status":"queued","durable":false});
        state.receipts.insert(
            id.clone(),
            Receipt {
                value: value.clone(),
                completed_at: None,
            },
        );
        state.pending_bytes += bytes;
        state
            .processing_pending
            .push_back(PendingProcessingAdmission {
                id,
                admission,
                bytes,
            });
        Ok(value)
    }

    pub fn take_processing(&self) -> Result<Option<PendingProcessingAdmission>, String> {
        let mut state = self.0.lock().map_err(|_| "admission lock poisoned")?;
        let request = state.processing_pending.pop_front();
        if let Some(request) = &request {
            state.inflight.insert(request.id.clone(), request.bytes);
        }
        Ok(request)
    }

    pub fn return_processing_pending(
        &self,
        request: PendingProcessingAdmission,
    ) -> Result<(), String> {
        let mut state = self.0.lock().map_err(|_| "admission lock poisoned")?;
        if state.inflight.remove(&request.id) != Some(request.bytes) {
            return Err("admission reservation mismatch".into());
        }
        state.processing_pending.push_front(request);
        Ok(())
    }

    pub fn transport_observations(&self) -> Result<Value, String> {
        let ingress = self
            .0
            .lock()
            .map_err(|_| "admission lock poisoned")?
            .ingress
            .clone()
            .ok_or("protected admission ingress unavailable")?;
        ingress.transport_observations()
    }

    pub fn chain_observations(&self) -> Result<Value, String> {
        let ingress = self
            .0
            .lock()
            .map_err(|_| "admission lock poisoned")?
            .ingress
            .clone()
            .ok_or("protected admission ingress unavailable")?;
        ingress.chain_observations()
    }

    pub fn context_v2(&self) -> Result<Value, String> {
        let value = self
            .0
            .lock()
            .map_err(|_| "admission lock poisoned")?
            .context_v2
            .clone()
            .ok_or("protected admission context unavailable")?;
        let target = value
            .pointer("/signing_context/context/target_height")
            .and_then(Value::as_u64)
            .ok_or("protected admission context target unavailable")?;
        self.check_live_cutoff(target)?;
        Ok(value)
    }

    fn check_live_cutoff(&self, target: u64) -> Result<(), String> {
        // Never hold the admission mutex while acquiring the runtime ingress mutex.
        let ingress = self
            .0
            .lock()
            .map_err(|_| "admission lock poisoned")?
            .ingress
            .clone()
            .ok_or("protected admission ingress unavailable")?;
        if ingress.protected_cutoff_authority(target)?.is_some() {
            return Err("fresh local protected admission is closed".into());
        }
        Ok(())
    }

    pub fn context(&self) -> Result<Value, String> {
        let context = self
            .0
            .lock()
            .map_err(|_| "admission lock poisoned")?
            .context
            .clone()
            .ok_or("protected admission context unavailable")?;
        let target = context
            .pointer("/context/target_height")
            .and_then(Value::as_u64)
            .ok_or("protected admission context target unavailable")?;
        self.check_live_cutoff(target)?;
        Ok(context)
    }

    pub fn publish_context(&self, context: Option<Value>) -> Result<(), String> {
        if context.is_none() {
            self.publish_context_v2(None)?;
        }
        self.0
            .lock()
            .map_err(|_| "admission lock poisoned")?
            .context = context;
        Ok(())
    }

    pub fn enqueue(&self, admission: WalletAdmission) -> Result<Value, String> {
        #[cfg(feature = "qualification-timing")]
        let shape_span = AdmissionTimingSpan::start(&admission, "enqueue-shape");
        admission
            .request
            .validate_shape()
            .map_err(|e| format!("invalid admission: {e:?}"))?;
        #[cfg(feature = "qualification-timing")]
        drop(shape_span);
        #[cfg(feature = "qualification-timing")]
        let serialization_span = AdmissionTimingSpan::start(&admission, "enqueue-serialization");
        let bytes = serde_json::to_vec(&admission)
            .map_err(|e| e.to_string())?
            .len();
        #[cfg(feature = "qualification-timing")]
        drop(serialization_span);
        if bytes > MAX_REQUEST_BYTES {
            return Err("admission request exceeds byte bound".into());
        }
        #[cfg(feature = "qualification-timing")]
        let receipt_hash_span = AdmissionTimingSpan::start(&admission, "enqueue-receipt-hash");
        let id = EtdagDigest::from_canonical("SYNERGY_LOCAL_ADMISSION_RECEIPT_V1", &admission)
            .map_err(|e| format!("derive admission receipt: {e:?}"))?
            .0;
        #[cfg(feature = "qualification-timing")]
        drop(receipt_hash_span);
        // Previously queued receipts remain observable after cutoff closure.
        if let Some(receipt) = self
            .0
            .lock()
            .map_err(|_| "admission lock poisoned")?
            .receipts
            .get(&id)
        {
            if receipt.completed_at.is_none_or(|at| {
                receipt.value.get("admitted").and_then(Value::as_bool) == Some(true)
                    || at.elapsed() < RECEIPT_TTL
            }) {
                return Ok(receipt.value.clone());
            }
        }
        #[cfg(feature = "qualification-timing")]
        let live_cutoff_span = AdmissionTimingSpan::start(&admission, "enqueue-live-cutoff");
        self.check_live_cutoff(admission.request.target_height)?;
        #[cfg(feature = "qualification-timing")]
        drop(live_cutoff_span);
        let mut state = self.0.lock().map_err(|_| "admission lock poisoned")?;
        let now = Instant::now();
        state.receipts.retain(|_, receipt| {
            receipt.completed_at.is_none_or(|at| {
                receipt.value.get("admitted").and_then(Value::as_bool) == Some(true)
                    || now.duration_since(at) < RECEIPT_TTL
            })
        });
        if let Some(receipt) = state.receipts.get(&id) {
            return Ok(receipt.value.clone());
        }
        if state.context.is_none() {
            return Err("protected admission is unavailable".into());
        }
        if state.pending.len() + state.processing_pending.len() + state.inflight.len()
            >= MAX_PENDING
            || bytes > MAX_PENDING_BYTES.saturating_sub(state.pending_bytes)
        {
            return Err("protected admission queue is full".into());
        }
        if state.receipts.len() >= MAX_RECEIPTS {
            let oldest = state
                .receipts
                .iter()
                .filter_map(|(id, r)| r.completed_at.map(|at| (id.clone(), at)))
                .min_by_key(|(_, at)| *at)
                .map(|(id, _)| id);
            if let Some(oldest) = oldest {
                state.receipts.remove(&oldest);
            } else {
                return Err("protected admission receipt capacity reached".into());
            }
        }
        let value = json!({"receipt_id":id,"status":"queued","target_height":admission.request.target_height,
                           "envelope_id":admission.request.envelope.envelope_id,"admitted":false,"lifecycle_status":"queued","durable":false});
        state.receipts.insert(
            id.clone(),
            Receipt {
                value: value.clone(),
                completed_at: None,
            },
        );
        #[cfg(feature = "qualification-timing")]
        let observation = (
            admission.request.target_height,
            admission.request.envelope.envelope_id.0.clone(),
        );
        state.pending_bytes += bytes;
        state.pending.push_back(PendingAdmission {
            id,
            admission,
            bytes,
        });
        #[cfg(feature = "qualification-timing")]
        {
            drop(state);
            observe_admission(
                super::qualification_timing::Phase::RpcEnqueue,
                observation.0,
                &observation.1,
            );
        }
        Ok(value)
    }

    pub fn take(&self) -> Result<Option<PendingAdmission>, String> {
        let mut state = self.0.lock().map_err(|_| "admission lock poisoned")?;
        let request = state.pending.pop_front();
        if let Some(request) = &request {
            state.inflight.insert(request.id.clone(), request.bytes);
        }
        Ok(request)
    }

    /// A native peer or quorum reconciliation may already have completed this queued request.
    /// Release only the outstanding work reservation, preserving its higher receipt stage.
    pub fn finish_observed_duplicate(&self, id: &str) -> Result<bool, String> {
        let mut state = self.0.lock().map_err(|_| "admission lock poisoned")?;
        if !state
            .receipts
            .get(id)
            .is_some_and(|r| r.value.get("admitted").and_then(Value::as_bool) == Some(true))
        {
            return Ok(false);
        }
        if let Some(bytes) = state.inflight.remove(id) {
            state.pending_bytes = state.pending_bytes.saturating_sub(bytes);
        }
        Ok(true)
    }

    pub fn return_pending(&self, request: PendingAdmission) -> Result<(), String> {
        let mut state = self.0.lock().map_err(|_| "admission lock poisoned")?;
        if state.inflight.remove(&request.id) != Some(request.bytes) {
            return Err("admission reservation mismatch".into());
        }
        state.pending.push_front(request);
        Ok(())
    }
    pub fn cancel_uncommitted(&self) -> Result<(), String> {
        let ids = {
            let mut state = self.0.lock().map_err(|_| "admission lock poisoned")?;
            let ids = state
                .pending
                .iter()
                .map(|p| p.id.clone())
                .chain(state.processing_pending.iter().map(|p| p.id.clone()))
                .chain(state.inflight.keys().cloned())
                .collect::<Vec<_>>();
            state.pending.clear();
            state.processing_pending.clear();
            state.inflight.clear();
            state.pending_bytes = 0;
            ids
        };
        for id in ids {
            self.complete(
                &id,
                Err("admission owner stopped before local admission".into()),
            )?;
        }
        Ok(())
    }

    /// Sole ETDAG owner completion; persistence finishes before RPC can observe acceptance.
    pub fn complete(&self, id: &str, result: Result<Value, String>) -> Result<(), String> {
        let journal = {
            let state = self.0.lock().map_err(|_| "admission lock poisoned")?;
            if !state.receipts.contains_key(id) {
                return Err("admission receipt disappeared".into());
            }
            state.journal.clone()
        };
        let value = match &result {
            Ok(evidence) => {
                json!({"receipt_id":id,"status":"accepted","lifecycle_status":"accepted",
                "admitted":true,"durable":journal.is_some(),"evidence":evidence})
            }
            Err(reason) => {
                json!({"receipt_id":id,"status":"rejected","lifecycle_status":"rejected",
                "admitted":false,"durable":journal.is_some(),"reason":reason.chars().take(4096).collect::<String>(),
                "reason_code":rejection_code(reason)})
            }
        };
        if let Some(journal) = journal {
            journal.persist(id, &value)?;
        }
        let mut state = self.0.lock().map_err(|_| "admission lock poisoned")?;
        match result {
            Ok(evidence)
                if evidence.get("newly_admitted").and_then(Value::as_bool) == Some(true) =>
            {
                state.accepted_total = state.accepted_total.saturating_add(1)
            }
            Err(_) => state.rejected_total = state.rejected_total.saturating_add(1),
            _ => {}
        }
        if let Some(bytes) = state.inflight.remove(id) {
            state.pending_bytes = state.pending_bytes.saturating_sub(bytes);
        }
        let receipt = state
            .receipts
            .get_mut(id)
            .ok_or("admission receipt disappeared")?;
        receipt.value = value;
        receipt.completed_at = Some(Instant::now());
        Ok(())
    }

    /// Observation of an earlier durable admission; never inferred from a staged graph vertex.
    pub fn was_durably_admitted(
        &self,
        admission: &synergy_etdag::WalletAdmission,
    ) -> Result<bool, String> {
        let id = EtdagDigest::from_canonical("SYNERGY_LOCAL_ADMISSION_RECEIPT_V1", admission)
            .map_err(|e| format!("derive admission receipt: {e:?}"))?
            .0;
        let state = self.0.lock().map_err(|_| "admission lock poisoned")?;
        Ok(state
            .receipts
            .get(&id)
            .is_some_and(|r| r.value.get("admitted").and_then(Value::as_bool) == Some(true)))
    }

    /// Call only after the native durable graph and wallet authorization are reverified.
    pub fn recover_verified_vertex(
        &self,
        vertex: &synergy_etdag::TransactionVertex,
    ) -> Result<(), String> {
        let Some(admission) = &vertex.wallet_admission else {
            return Ok(());
        };
        let id = EtdagDigest::from_canonical("SYNERGY_LOCAL_ADMISSION_RECEIPT_V1", admission)
            .map_err(|e| format!("recover receipt id: {e:?}"))?
            .0;
        {
            let mut state = self.0.lock().map_err(|_| "admission lock poisoned")?;
            if state
                .receipts
                .get(&id)
                .is_some_and(|r| r.value.get("admitted").and_then(Value::as_bool) == Some(true))
            {
                return Ok(());
            }
            if state.receipts.len() >= MAX_RECEIPTS {
                let retired = state
                    .receipts
                    .iter()
                    .filter_map(|(id, r)| r.completed_at.map(|at| (id.clone(), at)))
                    .min_by_key(|(_, at)| *at)
                    .map(|(id, _)| id)
                    .ok_or("receipt capacity reached")?;
                state.receipts.remove(&retired);
            }
            state.receipts.insert(
                id.clone(),
                Receipt {
                    value: json!({"receipt_id":id,"status":"queued"}),
                    completed_at: None,
                },
            );
        }
        self.complete(
            &id,
            Ok(
                json!({"vertex_id":vertex.vertex_id,"envelope_id":vertex.envelope.envelope_id,
            "target_height":vertex.target_height,"newly_admitted":false,"finalized":false,
            "reconstructed_from_verified_durable_graph":true}),
            ),
        )
    }

    /// Updates observation only after native certificate or deterministic cut membership verification.
    pub fn record_verified_stage(
        &self,
        envelope: &EtdagDigest,
        stage: &str,
        proof: Value,
    ) -> Result<(), String> {
        let rank = |s: &str| match s {
            "accepted" => 0,
            "certified" => 1,
            // Processing uses these independently authenticated milestones.
            // They are receipt observations only; none authorizes execution,
            // finality, or a new reveal.
            "ordered" | "reveal_authorized" => 2,
            "execution_completed" => 3,
            "finalized" => 4,
            _ => 3,
        };
        if !matches!(
            stage,
            "certified" | "ordered" | "reveal_authorized" | "execution_completed" | "finalized"
        ) {
            return Err("unsupported receipt observation stage".into());
        }
        let (journal, updates) = {
            let state = self.0.lock().map_err(|_| "admission lock poisoned")?;
            let updates = state
                .receipts
                .iter()
                .filter_map(|(id, r)| {
                    if r.value
                        .pointer("/evidence/envelope_id")
                        .and_then(Value::as_str)
                        != Some(envelope.0.as_str())
                        || r.value.get("admitted").and_then(Value::as_bool) != Some(true)
                        || rank(
                            r.value
                                .get("lifecycle_status")
                                .and_then(Value::as_str)
                                .unwrap_or("accepted"),
                        ) >= rank(stage)
                    {
                        return None;
                    }
                    let mut value = r.value.clone();
                    value["lifecycle_status"] = json!(stage);
                    value["stage_evidence"] = proof.clone();
                    Some((id.clone(), value))
                })
                .collect::<Vec<_>>();
            (state.journal.clone(), updates)
        };
        for (id, value) in updates {
            if let Some(journal) = &journal {
                journal.persist(&id, &value)?;
            }
            if let Some(receipt) = self
                .0
                .lock()
                .map_err(|_| "admission lock poisoned")?
                .receipts
                .get_mut(&id)
            {
                receipt.value = value;
            }
        }
        Ok(())
    }

    /// RAM observations only; neither counters nor receipts confer finality.
    pub fn stats(&self) -> Result<Value, String> {
        let state = self.0.lock().map_err(|_| "admission lock poisoned")?;
        Ok(
            json!({"scope":"process_lifetime","accepted_total":state.accepted_total,
            "rejected_total":state.rejected_total,"etdag_ordered_total":state.ordered_total,
            "queued_requests":state.pending.len()+state.processing_pending.len()+state.inflight.len(),"queued_bytes":state.pending_bytes}),
        )
    }

    pub fn record_ordered(
        &self,
        height: u64,
        root: EtdagDigest,
        count: usize,
    ) -> Result<(), String> {
        let mut state = self.0.lock().map_err(|_| "admission lock poisoned")?;
        if let Some(previous) = state.ordered_targets.get(&height) {
            if previous != &root {
                return Err("ordered observation conflicts with certified target".into());
            }
            return Ok(());
        }
        // Live protected successors span five heights. Keep extra headroom;
        // this bounded observation map is not an authority cache.
        state.ordered_targets.insert(height, root);
        state.ordered_total = state.ordered_total.saturating_add(count as u64);
        let maximum = state
            .ordered_targets
            .keys()
            .next_back()
            .copied()
            .unwrap_or(height);
        state
            .ordered_targets
            .retain(|h, _| *h >= maximum.saturating_sub(16));
        Ok(())
    }

    pub fn receipt(&self, id: &str) -> Result<Value, String> {
        validate_receipt_id(id)?;
        self.0
            .lock()
            .map_err(|_| "admission lock poisoned")?
            .receipts
            .get(id)
            .map(|receipt| receipt.value.clone())
            .ok_or_else(|| {
                "admission receipt unavailable; verify finalized transaction before retry".into()
            })
    }
}

#[cfg(feature = "qualification-timing")]
fn observe_admission(phase: super::qualification_timing::Phase, target: u64, envelope: &str) {
    use super::qualification_timing::{self as timing, Classification, Kind, Role};
    timing::emit_subject_once(
        Kind::Admission,
        phase,
        target,
        0,
        0,
        envelope,
        Role::Participant,
        Classification::Observed,
        None,
        None,
    );
}

#[cfg(test)]
mod native_processing_signature_tests {
    use super::*;
    use aegis_pqvm::pqc::signatures::mldsa::mldsa87;
    use pqrust_traits::sign::{DetachedSignature as _, PublicKey as _};

    #[test]
    fn native_verifier_preserves_transcript_domain_and_rejects_wrong_key_or_bytes() {
        let (public, secret) = mldsa87::keypair();
        let (other_public, _) = mldsa87::keypair();
        let payload = json!({"fixture":"native-transcript-boundary"});
        let processing = synergy_etdag::crypto::canonical_signing_bytes(
            "SYNERGY_ETDAG_PROCESSING_ADMISSION_V1",
            &payload,
        )
        .unwrap();
        let legacy = synergy_etdag::crypto::canonical_signing_bytes(
            "SYNERGY_ETDAG_ADMISSION_REQUEST_V1",
            &payload,
        )
        .unwrap();
        let signature = mldsa87::detached_sign(&processing, &secret);
        verify_native_admission_signature(
            1266,
            public.as_bytes(),
            signature.as_bytes(),
            &processing,
        )
        .unwrap();
        assert!(verify_native_admission_signature(
            1266,
            public.as_bytes(),
            signature.as_bytes(),
            &legacy,
        )
        .is_err());
        assert!(verify_native_admission_signature(
            1266,
            other_public.as_bytes(),
            signature.as_bytes(),
            &processing,
        )
        .is_err());
        let mut corrupted = signature.as_bytes().to_vec();
        corrupted[0] ^= 1;
        assert!(verify_native_admission_signature(
            1266,
            public.as_bytes(),
            &corrupted,
            &processing
        )
        .is_err());
    }
}

#[cfg(test)]
mod live_cutoff_tests {
    use super::*;

    #[test]
    fn cached_admission_context_observes_new_verified_cutoff_without_republication() {
        let mut fleet = crate::services::posy::qualification::Fleet::new();
        let ingress = fleet.qualification_ingress();
        let handle = AdmissionHandle::default();
        handle.bind_ingress(ingress.clone()).unwrap();
        let context = json!({"context":{"target_height":3}});
        handle.publish_context(Some(context.clone())).unwrap();
        assert_eq!(handle.context().unwrap(), context);
        assert!(handle.check_live_cutoff(3).is_ok());
        let digest =
            |s: &str| EtdagDigest::from_domain_bytes("admission-live-cutoff-test", s.as_bytes());
        let certificate =
            fleet.validate_protected_parent(&synergy_etdag::execution::ProtectedProposalMaterial {
                material_version: 2,
                height: 1,
                execution_root: digest("H1"),
                next_batch_root: digest("H2"),
                cutoff_boundary_root: digest("H3"),
            });
        // Fleet uses real validator signatures and native durable VC verification.
        ingress.submit_proposal_validation(certificate).unwrap();
        assert!(handle.context().unwrap_err().contains("closed"));
        assert!(handle.check_live_cutoff(3).unwrap_err().contains("closed"));
        let state = handle.0.lock().unwrap();
        assert_eq!(state.context.as_ref(), Some(&context));
        assert!(state.pending.is_empty());
        assert!(state.receipts.is_empty());
    }

    #[test]
    fn unbound_live_admission_handle_fails_closed() {
        let handle = AdmissionHandle::default();
        handle
            .publish_context(Some(json!({"context":{"target_height":5}})))
            .unwrap();
        assert!(handle
            .context()
            .unwrap_err()
            .contains("ingress unavailable"));
    }
}

#[cfg(test)]
mod durable_receipt_tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);
    fn root() -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "posy-receipt-observation-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        fs::canonicalize(path).unwrap()
    }
    fn digest(name: &str) -> String {
        EtdagDigest::from_domain_bytes("receipt-test", name.as_bytes()).0
    }
    fn accepted(id: &str) -> Value {
        json!({"receipt_id":id,"status":"accepted","lifecycle_status":"accepted","admitted":true,
            "durable":true,"evidence":{"finalized":false,"target_height":8,"envelope_id":digest("envelope")}})
    }
    #[test]
    fn durable_observation_restores_without_conferring_finality() {
        let root = root();
        let namespace = digest("authority");
        let id = digest("receipt");
        let (journal, restored) = ReceiptJournal::open(&root, namespace.clone()).unwrap();
        assert!(restored.is_empty());
        journal.persist(&id, &accepted(&id)).unwrap();
        let (_, restored) = ReceiptJournal::open(&root, namespace).unwrap();
        assert_eq!(restored[&id].value, accepted(&id));
        assert_eq!(
            restored[&id].value.pointer("/evidence/finalized"),
            Some(&json!(false))
        );
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn corrupt_or_wrong_authority_observation_fails_closed() {
        let root = root();
        let namespace = digest("authority");
        let id = digest("receipt");
        let (journal, _) = ReceiptJournal::open(&root, namespace.clone()).unwrap();
        journal.persist(&id, &accepted(&id)).unwrap();
        let filename = format!("receipt-{id}.json");
        let mut record: DurableReceipt =
            serde_json::from_slice(&journal.store.read_bounded(&filename).unwrap()).unwrap();
        record.value["lifecycle_status"] = json!("finalized");
        record.checksum = record.checksum().unwrap();
        journal
            .store
            .write_atomic(&filename, &serde_json::to_vec(&record).unwrap())
            .unwrap();
        assert!(ReceiptJournal::open(&root, namespace.clone()).is_err());
        record.value = accepted(&id);
        record.namespace = digest("wrong-authority");
        record.checksum = record.checksum().unwrap();
        journal
            .store
            .write_atomic(&filename, &serde_json::to_vec(&record).unwrap())
            .unwrap();
        assert!(ReceiptJournal::open(&root, namespace).is_err());
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn failed_observation_persistence_does_not_publish_accepted_receipt() {
        let root = root();
        let handle = AdmissionHandle::default();
        let id = digest("receipt");
        handle
            .bind_receipt_journal(&root, digest("authority"))
            .unwrap();
        handle.0.lock().unwrap().receipts.insert(
            id.clone(),
            Receipt {
                value: json!({"receipt_id":id,"status":"queued"}),
                completed_at: None,
            },
        );
        assert!(handle
            .complete(
                &id,
                Ok(json!({"finalized":false,"blob":"x".repeat(MAX_DURABLE_RECEIPT_BYTES)}))
            )
            .is_err());
        assert_eq!(handle.receipt(&id).unwrap()["status"], "queued");
        assert_eq!(handle.stats().unwrap()["accepted_total"], 0);
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn peer_reconciliation_releases_duplicate_reservation_without_downgrading_stage() {
        let handle = AdmissionHandle::default();
        let id = digest("peer-accepted-duplicate");
        let mut value = accepted(&id);
        value["lifecycle_status"] = json!("certified");
        {
            let mut state = handle.0.lock().unwrap();
            state.receipts.insert(
                id.clone(),
                Receipt {
                    value: value.clone(),
                    completed_at: Some(Instant::now()),
                },
            );
            state.inflight.insert(id.clone(), 1024);
            state.pending_bytes = 1024;
        }
        assert!(handle.finish_observed_duplicate(&id).unwrap());
        assert!(handle.finish_observed_duplicate(&id).unwrap());
        assert_eq!(handle.receipt(&id).unwrap(), value);
        assert_eq!(handle.stats().unwrap()["queued_bytes"], 0);
        assert_eq!(handle.stats().unwrap()["queued_requests"], 0);
    }

    #[test]
    fn processing_receipt_stages_only_advance_after_verified_observations() {
        let root = root();
        let namespace = digest("authority");
        let handle = AdmissionHandle::default();
        handle
            .bind_receipt_journal(&root, namespace.clone())
            .unwrap();
        let id = digest("processing-stage");
        let envelope = EtdagDigest(digest("envelope"));
        let mut value = accepted(&id);
        value["evidence"]["envelope_id"] = json!(envelope.0);
        handle.0.lock().unwrap().receipts.insert(
            id.clone(),
            Receipt {
                value,
                completed_at: Some(Instant::now()),
            },
        );
        for stage in [
            "certified",
            "reveal_authorized",
            "execution_completed",
            "finalized",
        ] {
            let proof = if stage == "finalized" {
                json!({"finalized":true,"finalized_height":8,"finalized_block_id":"ab".repeat(32)})
            } else {
                json!({"finalized":false})
            };
            handle
                .record_verified_stage(&envelope, stage, proof)
                .unwrap();
            assert_eq!(handle.receipt(&id).unwrap()["lifecycle_status"], stage);
            let (_, restored) = ReceiptJournal::open(&root, namespace.clone()).unwrap();
            assert_eq!(restored[&id].value, handle.receipt(&id).unwrap());
            assert_eq!(
                restored[&id].value.pointer("/evidence/finalized"),
                Some(&json!(false))
            );
        }
        handle
            .record_verified_stage(&envelope, "certified", json!({"stale":true}))
            .unwrap();
        assert_eq!(
            handle.receipt(&id).unwrap()["lifecycle_status"],
            "finalized"
        );
        assert!(handle
            .record_verified_stage(&envelope, "unverified", json!({}))
            .is_err());
        fs::remove_dir_all(root).unwrap();
    }
}
