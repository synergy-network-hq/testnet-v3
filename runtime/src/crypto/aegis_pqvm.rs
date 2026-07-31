use crate::consensus::signing_authority::{
    ConsensusSigningAuthorization, DurableConsensusSigningAuthority,
};
use crate::crypto::pqc::{PQCAlgorithm, PQCManager, PQCPrivateKey, PQCPublicKey, PQCSignature};
use crate::synergy_types::{
    AegisPqKeyId, AegisPqKeyRole, AegisPqPublicKey, AegisPqSignature, BlockId, ChainId, ClusterMap,
    Epoch, EpochTransition, Hash, Height, HeightConsensusContext, NetworkId, PeerHello,
    QuorumCertificate, TimeoutCertificate, TxId, ValidationCertificate, ValidatorRecord,
    ValidatorSet, ValidatorStatus, Vote, VotePhase,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender, TrySendError};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread;
use std::time::Instant;

pub const SYNERGY_TX_V1: &str = "SYNERGY_TX_V1";
pub const SYNERGY_BLOCK_V1: &str = "SYNERGY_BLOCK_V1";
pub const SYNERGY_VOTE_V1: &str = "SYNERGY_VOTE_V1";
pub const SYNERGY_VALIDATE_VOTE_V1: &str = "SYNERGY_VALIDATE_VOTE_V1";
pub const SYNERGY_FINALITY_VOTE_V1: &str = "SYNERGY_FINALITY_VOTE_V1";
pub const SYNERGY_TIMEOUT_VOTE_V1: &str = "SYNERGY_TIMEOUT_VOTE_V1";
pub const SYNERGY_VALIDATION_CERTIFICATE_V1: &str = "SYNERGY_VALIDATION_CERTIFICATE_V1";
pub const SYNERGY_TIMEOUT_CERTIFICATE_V1: &str = "SYNERGY_TIMEOUT_CERTIFICATE_V1";
pub const SYNERGY_QC_V1: &str = "SYNERGY_QC_V1";
pub const SYNERGY_EPOCH_TRANSITION_V1: &str = "SYNERGY_EPOCH_TRANSITION_V1";
pub const SYNERGY_VALIDATOR_REGISTRATION_V1: &str = "SYNERGY_VALIDATOR_REGISTRATION_V1";
pub const SYNERGY_VALIDATOR_READINESS_V1: &str = "SYNERGY_VALIDATOR_READINESS_V1";
pub const SYNERGY_P2P_HANDSHAKE_V1: &str = "SYNERGY_P2P_HANDSHAKE_V1";
pub const SYNERGY_DAG_NODE_V1: &str = "SYNERGY_DAG_NODE_V1";
pub const SYNERGY_STATE_ROOT_V1: &str = "SYNERGY_STATE_ROOT_V1";
pub const SYNERGY_RECEIPT_ROOT_V1: &str = "SYNERGY_RECEIPT_ROOT_V1";
pub const SYNERGY_ARCHIVE_SNAPSHOT_MANIFEST_V1: &str = "SYNERGY_ARCHIVE_SNAPSHOT_MANIFEST_V1";
pub const SYNERGY_ARCHIVE_SNAPSHOT_CATALOG_V1: &str = "SYNERGY_ARCHIVE_SNAPSHOT_CATALOG_V1";
pub const SYNERGY_ARCHIVE_P2P_HANDSHAKE_V1: &str = "SYNERGY_ARCHIVE_P2P_HANDSHAKE_V1";

#[derive(Debug, Clone)]
pub struct AegisPqvmError(pub String);

impl std::fmt::Display for AegisPqvmError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for AegisPqvmError {}

impl From<String> for AegisPqvmError {
    fn from(value: String) -> Self {
        Self(value)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AegisPqKeyLifecycleRecord {
    pub uma_id: String,
    pub key_id: AegisPqKeyId,
    pub roles: Vec<AegisPqKeyRole>,
    pub active_from_epoch: Epoch,
    pub active_until_epoch: Option<Epoch>,
    pub revoked_from_epoch: Option<Epoch>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct AegisPqvmKeyLifecycle {
    pub records: Vec<AegisPqKeyLifecycleRecord>,
}

impl AegisPqvmKeyLifecycle {
    pub fn add_record(&mut self, mut record: AegisPqKeyLifecycleRecord) {
        record
            .roles
            .sort_by(|a, b| format!("{a:?}").cmp(&format!("{b:?}")));
        self.records.retain(|existing| {
            !(existing.uma_id == record.uma_id && existing.key_id == record.key_id)
        });
        self.records.push(record);
        self.records.sort_by(|a, b| {
            a.uma_id
                .cmp(&b.uma_id)
                .then_with(|| a.key_id.cmp(&b.key_id))
        });
    }

    pub fn record_for(
        &self,
        uma_id: &str,
        key_id: &AegisPqKeyId,
    ) -> Option<&AegisPqKeyLifecycleRecord> {
        self.records
            .iter()
            .find(|record| record.uma_id == uma_id && &record.key_id == key_id)
    }

    pub fn key_is_active_for_epoch(
        &self,
        uma_id: &str,
        key_id: &AegisPqKeyId,
        epoch: Epoch,
        role: &AegisPqKeyRole,
    ) -> bool {
        let Some(record) = self.record_for(uma_id, key_id) else {
            return false;
        };
        if record.active_from_epoch.0 > epoch.0 {
            return false;
        }
        if record
            .active_until_epoch
            .map(|until| epoch.0 > until.0)
            .unwrap_or(false)
        {
            return false;
        }
        if self.key_is_revoked(uma_id, key_id, epoch) {
            return false;
        }
        record.roles.iter().any(|candidate| candidate == role)
    }

    pub fn key_is_authorized_for_role(
        &self,
        uma_id: &str,
        key_id: &AegisPqKeyId,
        role: &AegisPqKeyRole,
    ) -> bool {
        self.record_for(uma_id, key_id)
            .map(|record| record.roles.iter().any(|candidate| candidate == role))
            .unwrap_or(false)
    }

    pub fn key_is_revoked(&self, uma_id: &str, key_id: &AegisPqKeyId, epoch: Epoch) -> bool {
        self.record_for(uma_id, key_id)
            .and_then(|record| record.revoked_from_epoch)
            .map(|revoked| epoch.0 >= revoked.0)
            .unwrap_or(false)
    }

    pub fn root(&self, epoch: Epoch) -> Result<Hash, AegisPqvmError> {
        let mut records = self
            .records
            .iter()
            .filter(|record| {
                record.active_from_epoch.0 <= epoch.0
                    && record
                        .active_until_epoch
                        .map(|until| epoch.0 <= until.0)
                        .unwrap_or(true)
            })
            .cloned()
            .collect::<Vec<_>>();
        records.sort_by(|a, b| {
            a.uma_id
                .cmp(&b.uma_id)
                .then_with(|| a.key_id.cmp(&b.key_id))
        });
        let bytes = serde_json::to_vec(&records)
            .map_err(|error| AegisPqvmError(format!("key lifecycle root serialize: {error}")))?;
        Ok(Hash::from_domain_bytes(
            "SYNERGY_AEGIS_KEY_LIFECYCLE_V1",
            &bytes,
        ))
    }
}

#[derive(Debug, Clone, Default)]
pub struct AegisPqvmKeyRegistry {
    public_keys: BTreeMap<AegisPqKeyId, PQCPublicKey>,
    private_keys: BTreeMap<AegisPqKeyId, PQCPrivateKey>,
    pub lifecycle: AegisPqvmKeyLifecycle,
}

impl AegisPqvmKeyRegistry {
    pub fn register_keypair(
        &mut self,
        uma_id: &str,
        public_key: PQCPublicKey,
        private_key: PQCPrivateKey,
        roles: Vec<AegisPqKeyRole>,
        active_from_epoch: Epoch,
    ) -> AegisPqKeyId {
        let key_id = AegisPqKeyId(public_key.key_id.clone());
        self.public_keys.insert(key_id.clone(), public_key);
        self.private_keys.insert(key_id.clone(), private_key);
        self.lifecycle.add_record(AegisPqKeyLifecycleRecord {
            uma_id: uma_id.to_string(),
            key_id: key_id.clone(),
            roles,
            active_from_epoch,
            active_until_epoch: None,
            revoked_from_epoch: None,
        });
        key_id
    }

    pub fn register_public_key(
        &mut self,
        uma_id: &str,
        public_key: PQCPublicKey,
        roles: Vec<AegisPqKeyRole>,
        active_from_epoch: Epoch,
    ) -> AegisPqKeyId {
        let key_id = AegisPqKeyId(public_key.key_id.clone());
        self.public_keys.insert(key_id.clone(), public_key);
        self.lifecycle.add_record(AegisPqKeyLifecycleRecord {
            uma_id: uma_id.to_string(),
            key_id: key_id.clone(),
            roles,
            active_from_epoch,
            active_until_epoch: None,
            revoked_from_epoch: None,
        });
        key_id
    }

    pub fn register_public_key_with_lifecycle(
        &mut self,
        public_key: PQCPublicKey,
        lifecycle_record: AegisPqKeyLifecycleRecord,
    ) -> Result<AegisPqKeyId, AegisPqvmError> {
        let key_id = AegisPqKeyId(public_key.key_id.clone());
        if key_id != lifecycle_record.key_id {
            return Err(AegisPqvmError(
                "Aegis public key id does not match lifecycle record".to_string(),
            ));
        }
        self.public_keys.insert(key_id.clone(), public_key);
        self.lifecycle.add_record(lifecycle_record);
        Ok(key_id)
    }

    pub fn public_key(&self, key_id: &AegisPqKeyId) -> Option<&PQCPublicKey> {
        self.public_keys.get(key_id)
    }

    pub fn private_key(&self, key_id: &AegisPqKeyId) -> Option<&PQCPrivateKey> {
        self.private_keys.get(key_id)
    }

    pub fn revoke_key(&mut self, uma_id: &str, key_id: &AegisPqKeyId, epoch: Epoch) {
        if let Some(record) = self
            .lifecycle
            .records
            .iter_mut()
            .find(|record| record.uma_id == uma_id && &record.key_id == key_id)
        {
            record.revoked_from_epoch = Some(epoch);
        }
    }

    pub fn key_is_active_for_epoch(
        &self,
        uma_id: &str,
        key_id: &AegisPqKeyId,
        epoch: Epoch,
        role: AegisPqKeyRole,
    ) -> bool {
        self.lifecycle
            .key_is_active_for_epoch(uma_id, key_id, epoch, &role)
    }

    pub fn key_is_authorized_for_role(
        &self,
        uma_id: &str,
        key_id: &AegisPqKeyId,
        role: AegisPqKeyRole,
    ) -> bool {
        self.lifecycle
            .key_is_authorized_for_role(uma_id, key_id, &role)
    }

    pub fn key_is_revoked(&self, uma_id: &str, key_id: &AegisPqKeyId, epoch: Epoch) -> bool {
        self.lifecycle.key_is_revoked(uma_id, key_id, epoch)
    }

    pub fn key_lifecycle_root(&self, epoch: Epoch) -> Result<Hash, AegisPqvmError> {
        self.lifecycle.root(epoch)
    }
}

pub struct AegisPqvmDomainSeparatedHash;

impl AegisPqvmDomainSeparatedHash {
    pub fn hash_transaction(
        domain: &str,
        chain_id: ChainId,
        network_id: &NetworkId,
        canonical_tx_bytes: &[u8],
    ) -> TxId {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&chain_id.0.to_be_bytes());
        bytes.extend_from_slice(&(network_id.0.len() as u64).to_be_bytes());
        bytes.extend_from_slice(network_id.0.as_bytes());
        bytes.extend_from_slice(canonical_tx_bytes);
        TxId::from_hash(Hash::from_domain_bytes(domain, &bytes))
    }

    pub fn hash_block_header(domain: &str, canonical_header_bytes: &[u8]) -> BlockId {
        BlockId::from_hash(Hash::from_domain_bytes(domain, canonical_header_bytes))
    }

    pub fn hash_vote(domain: &str, canonical_vote_bytes: &[u8]) -> Hash {
        Hash::from_domain_bytes(domain, canonical_vote_bytes)
    }

    pub fn hash_qc(domain: &str, canonical_qc_bytes: &[u8]) -> Hash {
        Hash::from_domain_bytes(domain, canonical_qc_bytes)
    }
}

pub struct AegisPqvmSigner {
    manager: PQCManager,
    pub registry: AegisPqvmKeyRegistry,
    initialized: bool,
}

static AEGIS_PQVM_SIGNER_SMOKE: OnceLock<Result<(), String>> = OnceLock::new();
static AEGIS_PQVM_VERIFIER_SMOKE: OnceLock<Result<(), String>> = OnceLock::new();

fn run_aegis_pqvm_mldsa65_smoke(message: &[u8], context: &str) -> Result<(), String> {
    let mut manager = PQCManager::new();
    let (public_key, private_key) = manager
        .generate_keypair(PQCAlgorithm::MLDSA65)
        .map_err(|error| format!("{context} key generation failed: {error}"))?;
    let signature = manager
        .sign(&private_key, message)
        .map_err(|error| format!("{context} signing failed: {error}"))?;
    let verified = manager
        .verify(&public_key, &signature, message)
        .map_err(|error| format!("{context} verification failed: {error}"))?;
    if verified {
        Ok(())
    } else {
        Err(format!("{context} verification returned false"))
    }
}

fn ensure_cached_aegis_pqvm_smoke(
    cache: &'static OnceLock<Result<(), String>>,
    message: &'static [u8],
    context: &'static str,
) -> Result<(), AegisPqvmError> {
    cache
        .get_or_init(|| run_aegis_pqvm_mldsa65_smoke(message, context))
        .clone()
        .map_err(AegisPqvmError)
}

impl AegisPqvmSigner {
    pub fn initialize_required() -> Result<Self, AegisPqvmError> {
        ensure_cached_aegis_pqvm_smoke(
            &AEGIS_PQVM_SIGNER_SMOKE,
            b"aegis-pqvm-required-smoke-test",
            "aegis-pqvm smoke",
        )?;
        Ok(Self {
            manager: PQCManager::new(),
            registry: AegisPqvmKeyRegistry::default(),
            initialized: true,
        })
    }

    pub fn generate_and_register_key(
        &mut self,
        uma_id: &str,
        roles: Vec<AegisPqKeyRole>,
        active_from_epoch: Epoch,
    ) -> Result<AegisPqKeyId, AegisPqvmError> {
        self.ensure_initialized()?;
        let (mut public_key, mut private_key) = self
            .manager
            .generate_keypair(PQCAlgorithm::MLDSA65)
            .map_err(|error| {
                AegisPqvmError(format!("aegis-pqvm key generation failed: {error}"))
            })?;
        if self
            .registry
            .public_keys
            .contains_key(&AegisPqKeyId(public_key.key_id.clone()))
        {
            let unique_key_id = format!(
                "{}_{}",
                public_key.key_id,
                self.registry.public_keys.len().saturating_add(1)
            );
            public_key.key_id = unique_key_id.clone();
            private_key.public_key_id = unique_key_id;
        }
        Ok(self.registry.register_keypair(
            uma_id,
            public_key,
            private_key,
            roles,
            active_from_epoch,
        ))
    }

    /// Generates the non-consensus peer identity used by downstream support
    /// roles. Validator identities are registered separately from their
    /// Genesis-assigned ML-DSA-65 custody key and must never call this path.
    pub fn generate_and_register_fndsa_peer_identity(
        &mut self,
        uma_id: &str,
        active_from_epoch: Epoch,
    ) -> Result<AegisPqKeyId, AegisPqvmError> {
        self.ensure_initialized()?;
        let (mut public_key, mut private_key) = self
            .manager
            .generate_keypair(PQCAlgorithm::FNDSA)
            .map_err(|error| {
                AegisPqvmError(format!("FN-DSA peer identity generation failed: {error}"))
            })?;
        if self
            .registry
            .public_keys
            .contains_key(&AegisPqKeyId(public_key.key_id.clone()))
        {
            let unique_key_id = format!(
                "{}_{}",
                public_key.key_id,
                self.registry.public_keys.len().saturating_add(1)
            );
            public_key.key_id = unique_key_id.clone();
            private_key.public_key_id = unique_key_id;
        }
        Ok(self.registry.register_keypair(
            uma_id,
            public_key,
            private_key,
            vec![AegisPqKeyRole::PeerIdentity],
            active_from_epoch,
        ))
    }

    pub fn register_existing_keypair(
        &mut self,
        uma_id: &str,
        public_key: PQCPublicKey,
        private_key: PQCPrivateKey,
        roles: Vec<AegisPqKeyRole>,
        active_from_epoch: Epoch,
    ) -> Result<AegisPqKeyId, AegisPqvmError> {
        self.ensure_initialized()?;
        if public_key.key_id != private_key.public_key_id {
            return Err(AegisPqvmError(
                "Aegis public/private key identifiers do not match".to_string(),
            ));
        }
        Ok(self.registry.register_keypair(
            uma_id,
            public_key,
            private_key,
            roles,
            active_from_epoch,
        ))
    }

    pub fn verifier(&self) -> AegisPqvmVerifier {
        AegisPqvmVerifier {
            registry: self.registry.clone(),
            initialized: self.initialized,
            verified_signature_cache: Arc::new(Mutex::new(VerifiedSignatureCache::default())),
            verification_pool: PqcVerificationPool::initialize(),
        }
    }

    pub fn public_key_record(
        &self,
        key_id: &AegisPqKeyId,
    ) -> Result<AegisPqPublicKey, AegisPqvmError> {
        let key = self
            .registry
            .public_key(key_id)
            .ok_or_else(|| AegisPqvmError(format!("missing public key {}", key_id.0)))?;
        Ok(AegisPqPublicKey {
            key_id: key_id.clone(),
            algorithm: algorithm_name(&key.algorithm).to_string(),
            key_bytes: key.key_data.clone(),
        })
    }

    pub fn sign_transaction(
        &mut self,
        tx_signing_payload: &[u8],
        key_id: &AegisPqKeyId,
    ) -> Result<AegisPqSignature, AegisPqvmError> {
        self.sign_domain(SYNERGY_TX_V1, tx_signing_payload, key_id)
    }

    pub fn sign_vote(
        &mut self,
        vote_signing_payload: &[u8],
        key_id: &AegisPqKeyId,
    ) -> Result<AegisPqSignature, AegisPqvmError> {
        self.sign_domain(SYNERGY_FINALITY_VOTE_V1, vote_signing_payload, key_id)
    }

    pub fn sign_consensus_vote(
        &mut self,
        vote: &Vote,
        authority: &DurableConsensusSigningAuthority,
    ) -> Result<AegisPqSignature, AegisPqvmError> {
        let domain = match vote.phase {
            VotePhase::Validate => SYNERGY_VALIDATE_VOTE_V1,
            VotePhase::Finality => SYNERGY_FINALITY_VOTE_V1,
            VotePhase::Timeout => SYNERGY_TIMEOUT_VOTE_V1,
        };
        let authorization =
            ConsensusSigningAuthorization::from_vote(vote).map_err(AegisPqvmError)?;
        authority
            .authorize_before_signature(&authorization)
            .map_err(AegisPqvmError)?;
        if let Some(recorded) = authority
            .recorded_signed_vote_for_slot(&authorization)
            .map_err(AegisPqvmError)?
        {
            if recorded.signing_bytes().map_err(AegisPqvmError)?
                != vote.signing_bytes().map_err(AegisPqvmError)?
            {
                return Err(AegisPqvmError(
                    "durable signed vote envelope does not match the authorized subject"
                        .to_string(),
                ));
            }
            return Ok(recorded.aegis_pq_signature);
        }
        let signature = self.sign_domain(
            domain,
            &vote.signing_bytes().map_err(AegisPqvmError)?,
            &vote.key_id,
        )?;
        let mut signed_vote = vote.clone();
        signed_vote.aegis_pq_signature = signature.clone();
        authority
            .record_signed_vote(&signed_vote)
            .map_err(AegisPqvmError)?;
        Ok(signature)
    }

    pub fn sign_epoch_transition(
        &mut self,
        epoch_transition_payload: &[u8],
        key_id: &AegisPqKeyId,
    ) -> Result<AegisPqSignature, AegisPqvmError> {
        self.sign_domain(
            SYNERGY_EPOCH_TRANSITION_V1,
            epoch_transition_payload,
            key_id,
        )
    }

    pub fn sign_peer_hello(
        &mut self,
        peer_hello_payload: &[u8],
        key_id: &AegisPqKeyId,
    ) -> Result<AegisPqSignature, AegisPqvmError> {
        self.sign_domain(SYNERGY_P2P_HANDSHAKE_V1, peer_hello_payload, key_id)
    }

    pub fn sign_domain(
        &mut self,
        domain: &str,
        payload: &[u8],
        key_id: &AegisPqKeyId,
    ) -> Result<AegisPqSignature, AegisPqvmError> {
        self.ensure_initialized()?;
        let private_key = self.registry.private_key(key_id).cloned().ok_or_else(|| {
            AegisPqvmError(format!("validator signing key {} is unavailable", key_id.0))
        })?;
        if domain_requires_mldsa65(domain) && private_key.algorithm != PQCAlgorithm::MLDSA65 {
            return Err(AegisPqvmError(format!(
                "Testnet-v3 consensus domain {domain} requires ML-DSA-65"
            )));
        }
        let domain_payload = domain_payload(domain, payload)?;
        let signature = self
            .manager
            .sign(&private_key, &domain_payload)
            .map_err(|error| AegisPqvmError(format!("aegis-pqvm signing failed: {error}")))?;
        Ok(AegisPqSignature {
            algorithm: algorithm_name(&signature.algorithm).to_string(),
            signature_bytes: signature.signature_data,
        })
    }

    fn ensure_initialized(&self) -> Result<(), AegisPqvmError> {
        if self.initialized {
            Ok(())
        } else {
            Err(AegisPqvmError(
                "aegis-pqvm is not initialized; fail closed".to_string(),
            ))
        }
    }
}

#[derive(Debug, Clone)]
pub struct AegisPqvmVerifier {
    pub registry: AegisPqvmKeyRegistry,
    initialized: bool,
    verified_signature_cache: Arc<Mutex<VerifiedSignatureCache>>,
    verification_pool: Arc<PqcVerificationPool>,
}

const VERIFIED_SIGNATURE_CACHE_CAPACITY: usize = 4_096;
const VERIFIED_SIGNATURE_CACHE_HEIGHT_WINDOW: u64 = 2;
const PQC_VERIFICATION_QUEUE_CAPACITY: usize = 64;
const DEFAULT_PQC_VERIFICATION_WORKERS: usize = 2;
const MAX_PQC_VERIFICATION_WORKERS: usize = 4;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PqcVerificationMetricsSnapshot {
    pub requests: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub cache_evictions: u64,
    pub verification_duration_micros: u64,
    pub queue_depth: usize,
    pub queue_rejections: u64,
}

#[derive(Debug, Default)]
struct PqcVerificationMetrics {
    requests: AtomicU64,
    cache_hits: AtomicU64,
    cache_misses: AtomicU64,
    cache_evictions: AtomicU64,
    verification_duration_micros: AtomicU64,
    queue_depth: AtomicUsize,
    queue_rejections: AtomicU64,
}

impl PqcVerificationMetrics {
    fn snapshot(&self) -> PqcVerificationMetricsSnapshot {
        PqcVerificationMetricsSnapshot {
            requests: self.requests.load(Ordering::Relaxed),
            cache_hits: self.cache_hits.load(Ordering::Relaxed),
            cache_misses: self.cache_misses.load(Ordering::Relaxed),
            cache_evictions: self.cache_evictions.load(Ordering::Relaxed),
            verification_duration_micros: self.verification_duration_micros.load(Ordering::Relaxed),
            queue_depth: self.queue_depth.load(Ordering::Relaxed),
            queue_rejections: self.queue_rejections.load(Ordering::Relaxed),
        }
    }
}

struct PqcVerificationRequest {
    public_key: PQCPublicKey,
    signature: PQCSignature,
    message: Vec<u8>,
    result: mpsc::Sender<Result<bool, String>>,
}

struct PqcVerificationPool {
    sender: SyncSender<PqcVerificationRequest>,
    metrics: Arc<PqcVerificationMetrics>,
}

impl std::fmt::Debug for PqcVerificationPool {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PqcVerificationPool")
            .field("metrics", &self.metrics.snapshot())
            .finish_non_exhaustive()
    }
}

impl PqcVerificationPool {
    fn initialize() -> Arc<Self> {
        static POOL: OnceLock<Arc<PqcVerificationPool>> = OnceLock::new();
        Arc::clone(POOL.get_or_init(|| {
            let worker_count = std::env::var("SYNERGY_PQC_VERIFY_WORKERS")
                .ok()
                .and_then(|value| value.parse::<usize>().ok())
                .unwrap_or(DEFAULT_PQC_VERIFICATION_WORKERS)
                .clamp(1, MAX_PQC_VERIFICATION_WORKERS);
            let (sender, receiver) = mpsc::sync_channel(PQC_VERIFICATION_QUEUE_CAPACITY);
            let receiver = Arc::new(Mutex::new(receiver));
            let metrics = Arc::new(PqcVerificationMetrics::default());
            for index in 0..worker_count {
                let worker_receiver = Arc::clone(&receiver);
                let worker_metrics = Arc::clone(&metrics);
                thread::Builder::new()
                    .name(format!("pqc-verify-{index}"))
                    .spawn(move || pqc_verification_worker(worker_receiver, worker_metrics))
                    .expect("spawn bounded PQC verification worker");
            }
            Arc::new(Self { sender, metrics })
        }))
    }

    fn verify(
        &self,
        public_key: PQCPublicKey,
        signature: PQCSignature,
        message: Vec<u8>,
    ) -> Result<bool, AegisPqvmError> {
        let (result_sender, result_receiver) = mpsc::channel();
        self.metrics.requests.fetch_add(1, Ordering::Relaxed);
        self.metrics.queue_depth.fetch_add(1, Ordering::Relaxed);
        match self.sender.try_send(PqcVerificationRequest {
            public_key,
            signature,
            message,
            result: result_sender,
        }) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => {
                self.metrics.queue_depth.fetch_sub(1, Ordering::Relaxed);
                self.metrics
                    .queue_rejections
                    .fetch_add(1, Ordering::Relaxed);
                return Err(AegisPqvmError(
                    "bounded PQC verification pool is saturated".to_string(),
                ));
            }
            Err(TrySendError::Disconnected(_)) => {
                self.metrics.queue_depth.fetch_sub(1, Ordering::Relaxed);
                self.metrics
                    .queue_rejections
                    .fetch_add(1, Ordering::Relaxed);
                return Err(AegisPqvmError(
                    "bounded PQC verification pool is unavailable".to_string(),
                ));
            }
        }
        result_receiver
            .recv()
            .map_err(|_| AegisPqvmError("bounded PQC verification worker stopped".to_string()))?
            .map_err(AegisPqvmError)
    }
}

pub fn pqc_verification_metrics_snapshot() -> PqcVerificationMetricsSnapshot {
    PqcVerificationPool::initialize().metrics.snapshot()
}

fn pqc_verification_worker(
    receiver: Arc<Mutex<Receiver<PqcVerificationRequest>>>,
    metrics: Arc<PqcVerificationMetrics>,
) {
    loop {
        let request = {
            let receiver = receiver
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            receiver.recv()
        };
        let Ok(request) = request else {
            break;
        };
        metrics.queue_depth.fetch_sub(1, Ordering::Relaxed);
        let started = Instant::now();
        let result = PQCManager::new()
            .verify(&request.public_key, &request.signature, &request.message)
            .map_err(|error| format!("aegis-pqvm verification failed: {error}"));
        metrics.verification_duration_micros.fetch_add(
            started.elapsed().as_micros().min(u64::MAX as u128) as u64,
            Ordering::Relaxed,
        );
        let _ = request.result.send(result);
    }
}

/// A bounded positive-result cache for exact domain-signature transcripts.
///
/// Typed consensus first verifies each individual ML-DSA vote and then embeds
/// those exact signatures in validation, finality, and timeout certificates.
/// Re-running the same post-quantum primitive for certificate assembly and
/// verification consumed the entire healthy-path deadline. The cache key
/// commits to every verification input, including the public key bytes, and
/// lifecycle/role checks still run before every lookup. Invalid or altered
/// signatures are never inserted.
#[derive(Debug, Default)]
struct VerifiedSignatureCache {
    entries: BTreeMap<Hash, VerifiedSignatureCacheEntry>,
    insertion_order: VecDeque<Hash>,
}

#[derive(Debug, Clone, Copy)]
struct VerifiedSignatureCacheEntry {
    epoch: Epoch,
    height: Option<u64>,
}

impl VerifiedSignatureCache {
    fn contains(&self, key: &Hash, epoch: Epoch, height: Option<Height>) -> bool {
        self.entries.get(key).is_some_and(|entry| {
            entry.epoch == epoch && entry.height == height.map(|height| height.0)
        })
    }

    fn prune(&mut self, epoch: Epoch, height: Option<Height>) -> usize {
        let minimum_height = height.map(|height| {
            height
                .0
                .saturating_sub(VERIFIED_SIGNATURE_CACHE_HEIGHT_WINDOW)
        });
        let before = self.entries.len();
        self.entries.retain(|_, entry| {
            entry.epoch == epoch
                && match (minimum_height, entry.height) {
                    (Some(minimum), Some(entry_height)) => entry_height >= minimum,
                    _ => true,
                }
        });
        self.insertion_order
            .retain(|key| self.entries.contains_key(key));
        before.saturating_sub(self.entries.len())
    }

    fn insert(&mut self, key: Hash, epoch: Epoch, height: Option<Height>) -> usize {
        let mut evicted = self.prune(epoch, height);
        if self
            .entries
            .insert(
                key,
                VerifiedSignatureCacheEntry {
                    epoch,
                    height: height.map(|height| height.0),
                },
            )
            .is_some()
        {
            return evicted;
        }
        self.insertion_order.push_back(key);
        while self.entries.len() > VERIFIED_SIGNATURE_CACHE_CAPACITY {
            if let Some(expired) = self.insertion_order.pop_front() {
                if self.entries.remove(&expired).is_some() {
                    evicted = evicted.saturating_add(1);
                }
            }
        }
        evicted
    }
}

impl AegisPqvmVerifier {
    pub fn initialize_required(registry: AegisPqvmKeyRegistry) -> Result<Self, AegisPqvmError> {
        ensure_cached_aegis_pqvm_smoke(
            &AEGIS_PQVM_VERIFIER_SMOKE,
            b"aegis-pqvm-verifier-smoke-test",
            "aegis-pqvm verifier smoke",
        )?;
        Ok(Self {
            registry,
            initialized: true,
            verified_signature_cache: Arc::new(Mutex::new(VerifiedSignatureCache::default())),
            verification_pool: PqcVerificationPool::initialize(),
        })
    }

    pub fn unavailable_for_startup_tests() -> Self {
        Self {
            registry: AegisPqvmKeyRegistry::default(),
            initialized: false,
            verified_signature_cache: Arc::new(Mutex::new(VerifiedSignatureCache::default())),
            verification_pool: PqcVerificationPool::initialize(),
        }
    }

    pub fn initialize_required_for_public_key(
        public_key: AegisPqPublicKey,
        lifecycle_record: AegisPqKeyLifecycleRecord,
    ) -> Result<Self, AegisPqvmError> {
        if public_key.key_id != lifecycle_record.key_id {
            return Err(AegisPqvmError(
                "Aegis public key id does not match lifecycle record".to_string(),
            ));
        }
        let pqc_public_key = PQCPublicKey {
            algorithm: parse_algorithm(&public_key.algorithm)?,
            key_data: public_key.key_bytes,
            key_id: public_key.key_id.0.clone(),
            created_at: 0,
        };
        let mut registry = AegisPqvmKeyRegistry::default();
        registry.register_public_key_with_lifecycle(pqc_public_key, lifecycle_record)?;
        Self::initialize_required(registry)
    }

    pub fn public_key_record(
        &self,
        key_id: &AegisPqKeyId,
    ) -> Result<AegisPqPublicKey, AegisPqvmError> {
        let key = self
            .registry
            .public_key(key_id)
            .ok_or_else(|| AegisPqvmError(format!("missing public key {}", key_id.0)))?;
        Ok(AegisPqPublicKey {
            key_id: key_id.clone(),
            algorithm: algorithm_name(&key.algorithm).to_string(),
            key_bytes: key.key_data.clone(),
        })
    }

    pub fn verify_transaction_signature(&self, tx: &crate::synergy_types::Transaction) -> bool {
        self.verify_transaction_signature_checked(tx).is_ok()
    }

    pub fn verify_transaction_signature_checked(
        &self,
        tx: &crate::synergy_types::Transaction,
    ) -> Result<(), AegisPqvmError> {
        self.ensure_initialized()?;
        tx.chain_id.require_testnet_v3().map_err(AegisPqvmError)?;
        tx.network_id.require_testnet_v3().map_err(AegisPqvmError)?;
        if !tx.aegis_pq_signature.is_present() {
            return Err(AegisPqvmError(
                "missing transaction Aegis PQC signature".to_string(),
            ));
        }
        if !self.registry.key_is_active_for_epoch(
            &tx.signer_uma_id.0,
            &tx.aegis_pq_key_id,
            tx.epoch,
            AegisPqKeyRole::Transaction,
        ) {
            return Err(AegisPqvmError(
                "transaction key is not active for epoch/role".to_string(),
            ));
        }
        self.verify_domain_signature(
            SYNERGY_TX_V1,
            &tx.signing_bytes().map_err(AegisPqvmError)?,
            &tx.signer_uma_id.0,
            &tx.aegis_pq_key_id,
            tx.epoch,
            AegisPqKeyRole::Transaction,
            &tx.aegis_pq_signature,
        )
    }

    pub fn verify_vote_signature(
        &self,
        vote: &Vote,
        validator_record: &ValidatorRecord,
        expected_height_context_root: Hash,
    ) -> bool {
        self.verify_vote_signature_checked(vote, validator_record, expected_height_context_root)
            .is_ok()
    }

    pub fn verify_vote_signature_checked(
        &self,
        vote: &Vote,
        validator_record: &ValidatorRecord,
        expected_height_context_root: Hash,
    ) -> Result<(), AegisPqvmError> {
        self.ensure_initialized()?;
        vote.chain_id.require_testnet_v3().map_err(AegisPqvmError)?;
        vote.network_id
            .require_testnet_v3()
            .map_err(AegisPqvmError)?;
        if expected_height_context_root.is_zero()
            || vote.height_context_root != expected_height_context_root
        {
            return Err(AegisPqvmError(
                "vote height context root is missing or mismatched".to_string(),
            ));
        }
        if !vote.aegis_pq_signature.is_present() {
            return Err(AegisPqvmError(
                "missing vote Aegis PQC signature".to_string(),
            ));
        }
        if validator_record.validator_id != vote.validator_id {
            return Err(AegisPqvmError(
                "vote validator_id does not match validator record".to_string(),
            ));
        }
        if validator_record.validator_uma_id != vote.validator_uma_id {
            return Err(AegisPqvmError(
                "vote UMA id does not match validator record".to_string(),
            ));
        }
        if validator_record.status != ValidatorStatus::Active {
            return Err(AegisPqvmError("vote signer is not ACTIVE".to_string()));
        }
        if validator_record.consensus_public_key.key_id != vote.key_id {
            return Err(AegisPqvmError(
                "vote key id is not the validator consensus key".to_string(),
            ));
        }
        let domain = match vote.phase {
            VotePhase::Validate => SYNERGY_VALIDATE_VOTE_V1,
            VotePhase::Finality => SYNERGY_FINALITY_VOTE_V1,
            VotePhase::Timeout => SYNERGY_TIMEOUT_VOTE_V1,
        };
        self.verify_domain_signature_scoped(
            domain,
            &vote.signing_bytes().map_err(AegisPqvmError)?,
            &vote.validator_uma_id.0,
            &vote.key_id,
            vote.epoch,
            Some(vote.height),
            AegisPqKeyRole::ConsensusVote,
            &vote.aegis_pq_signature,
        )
    }

    pub fn verify_qc(
        &self,
        qc: &QuorumCertificate,
        validator_set: &ValidatorSet,
        cluster_map: &ClusterMap,
        height_context: &HeightConsensusContext,
    ) -> bool {
        self.verify_qc_checked(qc, validator_set, cluster_map, height_context)
            .is_ok()
    }

    pub fn verify_qc_checked(
        &self,
        qc: &QuorumCertificate,
        validator_set: &ValidatorSet,
        cluster_map: &ClusterMap,
        height_context: &HeightConsensusContext,
    ) -> Result<(), AegisPqvmError> {
        self.verify_consensus_certificate_checked(
            qc,
            VotePhase::Finality,
            validator_set,
            cluster_map,
            height_context,
            None,
        )
    }

    pub fn verify_validation_certificate_checked(
        &self,
        certificate: &ValidationCertificate,
        validator_set: &ValidatorSet,
        cluster_map: &ClusterMap,
        height_context: &HeightConsensusContext,
    ) -> Result<(), AegisPqvmError> {
        self.verify_consensus_certificate_checked(
            &certificate.as_verification_certificate(),
            VotePhase::Validate,
            validator_set,
            cluster_map,
            height_context,
            None,
        )
    }

    pub fn verify_timeout_certificate_checked(
        &self,
        certificate: &TimeoutCertificate,
        validator_set: &ValidatorSet,
        cluster_map: &ClusterMap,
        height_context: &HeightConsensusContext,
    ) -> Result<(), AegisPqvmError> {
        if certificate.next_round.0 != certificate.closing_round.0.saturating_add(1) {
            return Err(AegisPqvmError(
                "TC next round must be exactly closing round plus one".to_string(),
            ));
        }
        if certificate.highest_prepared_vc_root.is_some()
            != certificate.carry_forward_candidate_id.is_some()
        {
            return Err(AegisPqvmError(
                "TC prepared VC root and carry-forward candidate must appear together".to_string(),
            ));
        }
        let timeout_vote_subjects = if certificate.timeout_vote_subjects.is_empty() {
            None
        } else {
            if certificate.certificate_version < 2 {
                return Err(AegisPqvmError(
                    "heterogeneous timeout subjects require TC version 2".to_string(),
                ));
            }
            if certificate.timeout_vote_subjects.len() != certificate.aegis_pq_signatures.len() {
                return Err(AegisPqvmError(
                    "TC timeout-subject/signature vector length mismatch".to_string(),
                ));
            }
            let mut prepared_subject = None;
            for subject in &certificate.timeout_vote_subjects {
                if subject.highest_prepared_vc_root.is_some() != !subject.block_id.0.is_empty() {
                    return Err(AegisPqvmError(
                        "TC signer prepared root and candidate must appear together".to_string(),
                    ));
                }
                if let Some(root) = subject.highest_prepared_vc_root {
                    match prepared_subject.as_mut() {
                        None => {
                            prepared_subject = Some((subject.block_id.clone(), root));
                        }
                        Some((candidate, _)) if candidate != &subject.block_id => {
                            return Err(AegisPqvmError(
                                "TC contains conflicting prepared candidates".to_string(),
                            ));
                        }
                        Some((_, selected_root)) if root < *selected_root => {
                            *selected_root = root;
                        }
                        Some(_) => {}
                    }
                }
            }
            let declared = certificate
                .carry_forward_candidate_id
                .clone()
                .zip(certificate.highest_prepared_vc_root);
            if prepared_subject != declared {
                return Err(AegisPqvmError(
                    "TC declared carry-forward subject does not match signed timeout subjects"
                        .to_string(),
                ));
            }
            Some(certificate.timeout_vote_subjects.as_slice())
        };
        self.verify_consensus_certificate_checked(
            &certificate.as_verification_certificate(),
            VotePhase::Timeout,
            validator_set,
            cluster_map,
            height_context,
            timeout_vote_subjects,
        )
    }

    fn verify_consensus_certificate_checked(
        &self,
        qc: &QuorumCertificate,
        expected_phase: VotePhase,
        validator_set: &ValidatorSet,
        cluster_map: &ClusterMap,
        height_context: &HeightConsensusContext,
        timeout_vote_subjects: Option<&[crate::synergy_types::TimeoutVoteSubject]>,
    ) -> Result<(), AegisPqvmError> {
        self.ensure_initialized()?;
        if qc.phase != expected_phase {
            return Err(AegisPqvmError(format!(
                "wrong certificate phase: expected {expected_phase:?}, found {:?}",
                qc.phase
            )));
        }
        height_context
            .validate_validator_and_cluster_bindings(validator_set, cluster_map)
            .map_err(AegisPqvmError)?;
        let expected_height_context_root = height_context.root().map_err(AegisPqvmError)?;
        qc.chain_id.require_testnet_v3().map_err(AegisPqvmError)?;
        qc.network_id.require_testnet_v3().map_err(AegisPqvmError)?;
        if qc.protocol_version != height_context.protocol_version
            || qc.height != height_context.height
            || qc.epoch != height_context.epoch
            || qc.cluster_id != height_context.assigned_cluster_id
            || qc.height_context_root != expected_height_context_root
        {
            return Err(AegisPqvmError(
                "QC height context is missing, stale, future, or mismatched".to_string(),
            ));
        }
        if qc.active_validator_set_hash != height_context.active_validator_set_root {
            return Err(AegisPqvmError("QC validator set hash mismatch".to_string()));
        }
        if qc.cluster_map_hash != height_context.cluster_map_root {
            return Err(AegisPqvmError("QC cluster map hash mismatch".to_string()));
        }

        let validators = validator_set
            .active_for_epoch(qc.epoch)
            .canonicalized()
            .validators;
        let signer_indexes = bitmap_signer_indexes(&qc.signer_bitmap, validators.len())?;
        if signer_indexes.len() != qc.aegis_pq_signatures.len()
            || signer_indexes.len() != qc.aegis_pq_key_ids.len()
        {
            return Err(AegisPqvmError(
                "QC signer bitmap/signature/key vector length mismatch".to_string(),
            ));
        }

        let mut signed_weight = 0u64;
        let mut seen_validators = BTreeSet::new();
        let mut seen_keys = BTreeSet::new();
        let mut certificate_votes = Vec::with_capacity(signer_indexes.len());
        for (position, signer_index) in signer_indexes.iter().enumerate() {
            let validator = validators.get(*signer_index).ok_or_else(|| {
                AegisPqvmError("QC signer bitmap references missing validator".to_string())
            })?;
            if !seen_validators.insert(validator.validator_id.clone()) {
                return Err(AegisPqvmError("duplicate signer in QC".to_string()));
            }
            let key_id = qc.aegis_pq_key_ids[position].clone();
            if !seen_keys.insert(key_id.clone()) {
                return Err(AegisPqvmError("duplicate signer key in QC".to_string()));
            }
            if validator.status != ValidatorStatus::Active
                || !validator.is_active_for_epoch(qc.epoch)
            {
                return Err(AegisPqvmError(
                    "QC signer is not ACTIVE for epoch".to_string(),
                ));
            }
            if !cluster_map.contains(qc.cluster_id, &validator.validator_id) {
                return Err(AegisPqvmError(
                    "QC signer is not in the QC cluster".to_string(),
                ));
            }
            let timeout_subject = timeout_vote_subjects.and_then(|subjects| subjects.get(position));
            let vote = Vote {
                chain_id: qc.chain_id,
                network_id: qc.network_id.clone(),
                height: qc.height,
                round: qc.round,
                epoch: qc.epoch,
                cluster_id: qc.cluster_id,
                phase: qc.phase.clone(),
                block_id: timeout_subject
                    .map(|subject| subject.block_id.clone())
                    .unwrap_or_else(|| qc.block_id.clone()),
                highest_prepared_vc_root: timeout_subject
                    .map(|subject| subject.highest_prepared_vc_root)
                    .unwrap_or(qc.highest_prepared_vc_root),
                validator_id: validator.validator_id.clone(),
                validator_uma_id: validator.validator_uma_id.clone(),
                key_id,
                active_validator_set_hash: qc.active_validator_set_hash,
                cluster_map_hash: qc.cluster_map_hash,
                protocol_version: qc.protocol_version.clone(),
                height_context_root: qc.height_context_root,
                aegis_pq_signature: qc.aegis_pq_signatures[position].clone(),
            };
            certificate_votes.push((vote, validator.clone()));
            signed_weight = signed_weight
                .checked_add(validator.voting_weight)
                .ok_or_else(|| AegisPqvmError("QC signed-weight overflow".to_string()))?;
        }

        // Certificate evidence is independent per signer. Submit every
        // uncached ML-DSA transcript concurrently to the bounded verification
        // pool; the coordinator thread waits only for the bounded batch result
        // and never performs the post-quantum primitive itself.
        thread::scope(|scope| -> Result<(), AegisPqvmError> {
            let verification_results = certificate_votes
                .iter()
                .map(|(vote, validator)| {
                    scope.spawn(|| {
                        self.verify_vote_signature_checked(
                            vote,
                            validator,
                            expected_height_context_root,
                        )
                    })
                })
                .collect::<Vec<_>>();
            for result in verification_results {
                result.join().map_err(|_| {
                    AegisPqvmError("PQC certificate verification worker panicked".to_string())
                })??;
            }
            Ok(())
        })?;

        if signed_weight != qc.signed_weight {
            return Err(AegisPqvmError(format!(
                "QC signed_weight mismatch: computed {signed_weight}, declared {}",
                qc.signed_weight
            )));
        }
        let required_count = height_context
            .strict_count_quorum()
            .map_err(AegisPqvmError)?;
        if (signer_indexes.len() as u64) < required_count
            || 3u128 * signer_indexes.len() as u128
                <= 2u128 * height_context.assigned_cluster_validator_count as u128
        {
            return Err(AegisPqvmError(
                "QC strict distinct-signer quorum failed".to_string(),
            ));
        }
        let required_weight = height_context
            .strict_weight_quorum()
            .map_err(AegisPqvmError)?;
        if qc.threshold_weight_required != required_weight {
            return Err(AegisPqvmError(format!(
                "QC threshold mismatch: expected {required_weight}, declared {}",
                qc.threshold_weight_required
            )));
        }
        if signed_weight < required_weight
            || 3u128 * signed_weight as u128
                <= 2u128 * height_context.assigned_cluster_total_voting_weight as u128
        {
            return Err(AegisPqvmError(
                "QC strict frozen-weight quorum failed".to_string(),
            ));
        }
        Ok(())
    }

    pub fn verify_epoch_transition_signature(
        &self,
        epoch_transition: &EpochTransition,
        validator_set: &ValidatorSet,
    ) -> bool {
        self.verify_epoch_transition_signature_checked(epoch_transition, validator_set)
            .is_ok()
    }

    pub fn verify_epoch_transition_signature_checked(
        &self,
        epoch_transition: &EpochTransition,
        validator_set: &ValidatorSet,
    ) -> Result<(), AegisPqvmError> {
        self.ensure_initialized()?;
        epoch_transition
            .validate_structure()
            .map_err(AegisPqvmError)?;
        let payload = epoch_transition.signing_bytes().map_err(AegisPqvmError)?;
        let mut signed_weight = 0u64;
        let mut seen = BTreeSet::new();
        for (key_id, signature) in epoch_transition
            .signer_key_ids
            .iter()
            .zip(epoch_transition.signatures.iter())
        {
            let validator = validator_set
                .validators
                .iter()
                .find(|record| &record.consensus_public_key.key_id == key_id)
                .ok_or_else(|| {
                    AegisPqvmError("epoch transition signer not in validator set".to_string())
                })?;
            if !seen.insert(validator.validator_id.clone()) {
                return Err(AegisPqvmError(
                    "duplicate epoch transition signer".to_string(),
                ));
            }
            self.verify_domain_signature(
                SYNERGY_EPOCH_TRANSITION_V1,
                &payload,
                &validator.validator_uma_id.0,
                key_id,
                epoch_transition.from_epoch,
                AegisPqKeyRole::EpochTransition,
                signature,
            )?;
            signed_weight = signed_weight.saturating_add(validator.voting_weight);
        }
        if signed_weight < validator_set.threshold_weight() {
            return Err(AegisPqvmError(
                "epoch transition signatures below threshold".to_string(),
            ));
        }
        Ok(())
    }

    pub fn key_is_active_for_epoch(
        &self,
        uma_id: &str,
        key_id: &AegisPqKeyId,
        epoch: Epoch,
        role: AegisPqKeyRole,
    ) -> bool {
        if !self.initialized {
            return false;
        }
        self.registry
            .key_is_active_for_epoch(uma_id, key_id, epoch, role)
    }

    pub fn key_is_authorized_for_role(
        &self,
        uma_id: &str,
        key_id: &AegisPqKeyId,
        role: AegisPqKeyRole,
    ) -> bool {
        if !self.initialized {
            return false;
        }
        self.registry
            .key_is_authorized_for_role(uma_id, key_id, role)
    }

    pub fn key_is_revoked(&self, uma_id: &str, key_id: &AegisPqKeyId, epoch: Epoch) -> bool {
        if !self.initialized {
            return true;
        }
        self.registry.key_is_revoked(uma_id, key_id, epoch)
    }

    pub fn key_lifecycle_root(&self, epoch: Epoch) -> Result<Hash, AegisPqvmError> {
        self.ensure_initialized()?;
        self.registry.key_lifecycle_root(epoch)
    }

    pub fn verify_peer_identity(
        &self,
        peer_hello: &PeerHello,
        signature: &AegisPqSignature,
    ) -> bool {
        self.verify_peer_identity_checked(peer_hello, signature)
            .is_ok()
    }

    pub fn verify_peer_identity_checked(
        &self,
        peer_hello: &PeerHello,
        signature: &AegisPqSignature,
    ) -> Result<(), AegisPqvmError> {
        self.ensure_initialized()?;
        peer_hello
            .chain_id
            .require_testnet_v3()
            .map_err(AegisPqvmError)?;
        peer_hello
            .network_id
            .require_testnet_v3()
            .map_err(AegisPqvmError)?;
        let uma_id = peer_hello
            .validator_id_optional
            .as_ref()
            .map(|validator_id| validator_id.0.as_str())
            .unwrap_or(peer_hello.node_id.as_str());
        self.verify_domain_signature(
            SYNERGY_P2P_HANDSHAKE_V1,
            &serde_json::to_vec(peer_hello).map_err(|error| {
                AegisPqvmError(format!("peer hello canonical serialize: {error}"))
            })?,
            uma_id,
            &peer_hello.aegis_pq_public_key_id,
            Epoch(0),
            AegisPqKeyRole::PeerIdentity,
            signature,
        )
    }

    pub fn verify_domain_signature(
        &self,
        domain: &str,
        payload: &[u8],
        uma_id: &str,
        key_id: &AegisPqKeyId,
        epoch: Epoch,
        role: AegisPqKeyRole,
        signature: &AegisPqSignature,
    ) -> Result<(), AegisPqvmError> {
        self.verify_domain_signature_scoped(
            domain, payload, uma_id, key_id, epoch, None, role, signature,
        )
    }

    fn verify_domain_signature_scoped(
        &self,
        domain: &str,
        payload: &[u8],
        uma_id: &str,
        key_id: &AegisPqKeyId,
        epoch: Epoch,
        height: Option<Height>,
        role: AegisPqKeyRole,
        signature: &AegisPqSignature,
    ) -> Result<(), AegisPqvmError> {
        self.ensure_initialized()?;
        if !signature.is_present() {
            return Err(AegisPqvmError("missing Aegis PQC signature".to_string()));
        }
        if !self
            .registry
            .key_is_active_for_epoch(uma_id, key_id, epoch, role.clone())
        {
            return Err(AegisPqvmError(format!(
                "key {} is not active for role {:?} at epoch {}",
                key_id.0, role, epoch.0
            )));
        }
        let public_key = self
            .registry
            .public_key(key_id)
            .ok_or_else(|| AegisPqvmError(format!("missing public key {}", key_id.0)))?;
        let algorithm = parse_algorithm(&signature.algorithm)?;
        if algorithm != public_key.algorithm {
            return Err(AegisPqvmError(
                "signature algorithm does not match public key".to_string(),
            ));
        }
        if domain_requires_mldsa65(domain) && algorithm != PQCAlgorithm::MLDSA65 {
            return Err(AegisPqvmError(format!(
                "Testnet-v3 consensus domain {domain} requires ML-DSA-65"
            )));
        }
        let cache_key = verified_signature_cache_key(
            domain,
            payload,
            uma_id,
            key_id,
            epoch,
            &role,
            signature,
            &public_key.key_data,
        )?;
        {
            let cache = self
                .verified_signature_cache
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if cache.contains(&cache_key, epoch, height) {
                self.verification_pool
                    .metrics
                    .cache_hits
                    .fetch_add(1, Ordering::Relaxed);
                return Ok(());
            }
        }
        self.verification_pool
            .metrics
            .cache_misses
            .fetch_add(1, Ordering::Relaxed);
        let pqc_signature = PQCSignature {
            algorithm,
            signature_data: signature.signature_bytes.clone(),
            message_hash: payload.to_vec(),
            public_key_id: key_id.0.clone(),
            created_at: 0,
        };
        let verified = self.verification_pool.verify(
            public_key.clone(),
            pqc_signature,
            domain_payload(domain, payload)?,
        )?;
        if verified {
            let evicted = self
                .verified_signature_cache
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .insert(cache_key, epoch, height);
            self.verification_pool
                .metrics
                .cache_evictions
                .fetch_add(evicted as u64, Ordering::Relaxed);
            Ok(())
        } else {
            Err(AegisPqvmError(
                "aegis-pqvm verification returned false".to_string(),
            ))
        }
    }

    fn ensure_initialized(&self) -> Result<(), AegisPqvmError> {
        if self.initialized {
            Ok(())
        } else {
            Err(AegisPqvmError(
                "aegis-pqvm is unavailable or not initialized; fail closed".to_string(),
            ))
        }
    }

    #[cfg(test)]
    fn verified_signature_cache_snapshot(&self) -> (usize, u64) {
        let cache = self
            .verified_signature_cache
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        (
            cache.entries.len(),
            self.verification_pool
                .metrics
                .cache_hits
                .load(Ordering::Relaxed),
        )
    }

    pub fn verification_metrics_snapshot(&self) -> PqcVerificationMetricsSnapshot {
        self.verification_pool.metrics.snapshot()
    }
}

fn verified_signature_cache_key(
    domain: &str,
    payload: &[u8],
    uma_id: &str,
    key_id: &AegisPqKeyId,
    epoch: Epoch,
    role: &AegisPqKeyRole,
    signature: &AegisPqSignature,
    public_key_bytes: &[u8],
) -> Result<Hash, AegisPqvmError> {
    fn push_component(material: &mut Vec<u8>, component: &[u8]) {
        material.extend_from_slice(&(component.len() as u64).to_be_bytes());
        material.extend_from_slice(component);
    }

    let role_bytes = serde_json::to_vec(role)
        .map_err(|error| AegisPqvmError(format!("cache key role serialize failed: {error}")))?;
    let mut material = Vec::with_capacity(
        domain.len()
            + payload.len()
            + uma_id.len()
            + key_id.0.len()
            + signature.algorithm.len()
            + signature.signature_bytes.len()
            + public_key_bytes.len()
            + role_bytes.len()
            + 72,
    );
    push_component(&mut material, domain.as_bytes());
    push_component(&mut material, &domain_payload(domain, payload)?);
    push_component(&mut material, uma_id.as_bytes());
    push_component(&mut material, key_id.0.as_bytes());
    push_component(&mut material, &epoch.0.to_be_bytes());
    push_component(&mut material, &role_bytes);
    push_component(&mut material, signature.algorithm.as_bytes());
    push_component(&mut material, &signature.signature_bytes);
    push_component(&mut material, public_key_bytes);
    Ok(Hash::from_domain_bytes(
        "AEGIS_PQVM_VERIFIED_SIGNATURE_CACHE_V1",
        &material,
    ))
}

pub struct AegisPqvmPeerAuthenticator {
    verifier: AegisPqvmVerifier,
}

impl AegisPqvmPeerAuthenticator {
    pub fn new(verifier: AegisPqvmVerifier) -> Self {
        Self { verifier }
    }

    pub fn verify_peer_identity(
        &self,
        peer_hello: &PeerHello,
        signature: &AegisPqSignature,
    ) -> bool {
        self.verifier.verify_peer_identity(peer_hello, signature)
    }
}

fn bitmap_signer_indexes(
    bitmap: &[u8],
    validator_count: usize,
) -> Result<Vec<usize>, AegisPqvmError> {
    let mut indexes = Vec::new();
    for validator_index in 0..validator_count {
        let byte = validator_index / 8;
        let bit = validator_index % 8;
        if bitmap
            .get(byte)
            .map(|value| value & (1u8 << bit) != 0)
            .unwrap_or(false)
        {
            indexes.push(validator_index);
        }
    }
    let unused_bits_start = validator_count;
    for bit_index in unused_bits_start..bitmap.len() * 8 {
        let byte = bit_index / 8;
        let bit = bit_index % 8;
        if bitmap[byte] & (1u8 << bit) != 0 {
            return Err(AegisPqvmError(
                "QC signer bitmap has bits beyond validator set".to_string(),
            ));
        }
    }
    Ok(indexes)
}

fn domain_payload(domain: &str, payload: &[u8]) -> Result<Vec<u8>, AegisPqvmError> {
    let consensus_domain = if domain_requires_chain_incarnation(domain) {
        Some(
            crate::synergy_types::current_consensus_domain()
                .and_then(|domain| domain.canonical_bytes())
                .map_err(AegisPqvmError)?,
        )
    } else {
        None
    };
    let mut out = Vec::with_capacity(
        domain.len() + consensus_domain.as_ref().map_or(0, Vec::len) + 24 + payload.len(),
    );
    out.extend_from_slice(&(domain.len() as u64).to_be_bytes());
    out.extend_from_slice(domain.as_bytes());
    if let Some(consensus_domain) = consensus_domain {
        out.extend_from_slice(&(consensus_domain.len() as u64).to_be_bytes());
        out.extend_from_slice(&consensus_domain);
    } else {
        out.extend_from_slice(&0_u64.to_be_bytes());
    }
    out.extend_from_slice(&(payload.len() as u64).to_be_bytes());
    out.extend_from_slice(payload);
    Ok(out)
}

fn parse_algorithm(value: &str) -> Result<PQCAlgorithm, AegisPqvmError> {
    match value {
        "mldsa65" | "ml-dsa-65" | "ML-DSA-65" => Ok(PQCAlgorithm::MLDSA65),
        "mldsa87" | "ml-dsa-87" | "ML-DSA-87" => Ok(PQCAlgorithm::MLDSA87),
        "fndsa" => Ok(PQCAlgorithm::FNDSA),
        other => Err(AegisPqvmError(format!(
            "unsupported Aegis PQC signature algorithm: {other}; use mldsa65"
        ))),
    }
}

fn algorithm_name(algorithm: &PQCAlgorithm) -> &'static str {
    match algorithm {
        PQCAlgorithm::MLDSA65 => "mldsa65",
        PQCAlgorithm::MLDSA87 => "mldsa87",
        PQCAlgorithm::FNDSA => "fndsa",
        PQCAlgorithm::SLHDSA => "slhdsa",
        PQCAlgorithm::MLKEM1024 => "mlkem1024",
        PQCAlgorithm::HQCKEM => "hqckem",
    }
}

fn domain_requires_mldsa65(domain: &str) -> bool {
    matches!(
        domain,
        SYNERGY_BLOCK_V1
            | SYNERGY_VOTE_V1
            | SYNERGY_VALIDATE_VOTE_V1
            | SYNERGY_FINALITY_VOTE_V1
            | SYNERGY_TIMEOUT_VOTE_V1
            | SYNERGY_VALIDATION_CERTIFICATE_V1
            | SYNERGY_TIMEOUT_CERTIFICATE_V1
            | SYNERGY_QC_V1
            | SYNERGY_EPOCH_TRANSITION_V1
    ) || domain.starts_with("PoSy/ETDAG/")
}

fn domain_requires_chain_incarnation(domain: &str) -> bool {
    domain_requires_mldsa65(domain) || domain == SYNERGY_P2P_HANDSHAKE_V1
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::synergy_types::{
        deterministic_test_height_context, AegisPqKeyRole, BlockId, ChainId, ClusterAssignment,
        ClusterId, Height, NetworkId, ProtocolConfig, QuorumCertificate, Round, UmaId, ValidatorId,
        VotePhase, POSY_PROTOCOL_VERSION,
    };

    fn validator_record(
        signer: &AegisPqvmSigner,
        validator_id: &str,
        uma_id: &str,
        key_id: &AegisPqKeyId,
        status: ValidatorStatus,
    ) -> ValidatorRecord {
        let public_key = signer.public_key_record(key_id).expect("public key record");
        ValidatorRecord {
            validator_id: ValidatorId::from(validator_id),
            validator_uma_id: UmaId::from(uma_id),
            consensus_public_key: public_key.clone(),
            peer_public_key: public_key.clone(),
            operator_public_key: public_key,
            voting_weight: 1,
            status,
            cluster_id: ClusterId(0),
            activation_epoch: Epoch(0),
        }
    }

    fn signed_vote(
        signer: &mut AegisPqvmSigner,
        key_id: &AegisPqKeyId,
        validator_id: &str,
        uma_id: &str,
        block_id: &str,
        validator_set_hash: Hash,
        cluster_map_hash: Hash,
        height_context_root: Hash,
    ) -> Vote {
        let mut vote = Vote {
            chain_id: ChainId::synergy_testnet_v3(),
            network_id: NetworkId::synergy_testnet_v3(),
            protocol_version: POSY_PROTOCOL_VERSION.to_string(),
            height: Height(1),
            round: Round(0),
            epoch: Epoch(0),
            cluster_id: ClusterId(0),
            height_context_root,
            phase: VotePhase::Finality,
            block_id: BlockId::from(block_id),
            highest_prepared_vc_root: None,
            validator_id: ValidatorId::from(validator_id),
            validator_uma_id: UmaId::from(uma_id),
            key_id: key_id.clone(),
            active_validator_set_hash: validator_set_hash,
            cluster_map_hash,
            aegis_pq_signature: AegisPqSignature {
                algorithm: String::new(),
                signature_bytes: Vec::new(),
            },
        };
        vote.aegis_pq_signature = signer
            .sign_vote(&vote.signing_bytes().expect("vote bytes"), key_id)
            .expect("real Aegis PQC vote signature");
        vote
    }

    #[test]
    fn real_vote_signature_verifies_and_tampering_fails() {
        let mut signer = AegisPqvmSigner::initialize_required().expect("aegis signer");
        let key_id = signer
            .generate_and_register_key("uma-1", vec![AegisPqKeyRole::ConsensusVote], Epoch(0))
            .expect("key");
        let record = validator_record(
            &signer,
            "validator-1",
            "uma-1",
            &key_id,
            ValidatorStatus::Active,
        );
        let set = ValidatorSet {
            epoch: Epoch(0),
            validators: vec![record.clone()],
        };
        let cluster = ClusterMap {
            epoch: Epoch(0),
            assignments: vec![ClusterAssignment {
                cluster_id: ClusterId(0),
                validator_id: record.validator_id.clone(),
            }],
        };
        let vote = signed_vote(
            &mut signer,
            &key_id,
            "validator-1",
            "uma-1",
            "block-a",
            set.hash().unwrap(),
            cluster.hash().unwrap(),
            Hash::from_domain_bytes("SYNERGY_TEST_HEIGHT_CONTEXT_V1", b"vote"),
        );
        let verifier = signer.verifier();
        assert!(verifier.verify_vote_signature(&vote, &record, vote.height_context_root));
        assert_eq!(verifier.verified_signature_cache_snapshot(), (1, 0));

        let cloned_verifier = verifier.clone();
        assert!(
            cloned_verifier.verify_vote_signature(&vote, &record, vote.height_context_root),
            "the exact previously verified transcript remains valid"
        );
        assert_eq!(
            verifier.verified_signature_cache_snapshot(),
            (1, 1),
            "verifier clones must share one bounded positive-result cache"
        );

        let mut altered = vote.clone();
        altered.block_id = BlockId::from("block-b");
        assert!(!verifier.verify_vote_signature(&altered, &record, vote.height_context_root));

        let mut altered_sig = vote.clone();
        altered_sig.aegis_pq_signature.signature_bytes[0] ^= 0x01;
        assert!(!verifier.verify_vote_signature(&altered_sig, &record, vote.height_context_root));
        assert_eq!(
            verifier.verified_signature_cache_snapshot(),
            (1, 1),
            "changed payloads and signatures must never enter or hit the cache"
        );
    }

    #[test]
    fn consensus_vote_restart_replays_the_exact_durable_randomized_signature() {
        let mut signer = AegisPqvmSigner::initialize_required().expect("aegis signer");
        let key_id = signer
            .generate_and_register_key("uma-replay", vec![AegisPqKeyRole::ConsensusVote], Epoch(0))
            .expect("key");
        let record = validator_record(
            &signer,
            "validator-replay",
            "uma-replay",
            &key_id,
            ValidatorStatus::Active,
        );
        let set = ValidatorSet {
            epoch: Epoch(0),
            validators: vec![record.clone()],
        };
        let cluster = ClusterMap {
            epoch: Epoch(0),
            assignments: vec![ClusterAssignment {
                cluster_id: ClusterId(0),
                validator_id: record.validator_id.clone(),
            }],
        };
        let context_root =
            Hash::from_domain_bytes("SYNERGY_TEST_HEIGHT_CONTEXT_V1", b"exact-replay");
        let vote = Vote {
            chain_id: ChainId::synergy_testnet_v3(),
            network_id: NetworkId::synergy_testnet_v3(),
            protocol_version: POSY_PROTOCOL_VERSION.to_string(),
            height: Height(1),
            round: Round(0),
            epoch: Epoch(0),
            cluster_id: ClusterId(0),
            height_context_root: context_root,
            phase: VotePhase::Finality,
            block_id: BlockId::from("block-exact-replay"),
            highest_prepared_vc_root: None,
            validator_id: record.validator_id.clone(),
            validator_uma_id: record.validator_uma_id.clone(),
            key_id: key_id.clone(),
            active_validator_set_hash: set.hash().unwrap(),
            cluster_map_hash: cluster.hash().unwrap(),
            aegis_pq_signature: AegisPqSignature {
                algorithm: String::new(),
                signature_bytes: Vec::new(),
            },
        };
        let journal = crate::utils::test_temp_root(format!(
            "synergy-exact-vote-replay-{}-{}.json",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let authority = DurableConsensusSigningAuthority::at_path(journal.clone());
        let first = signer
            .sign_consensus_vote(&vote, &authority)
            .expect("first signature is durably committed");

        let restarted = DurableConsensusSigningAuthority::at_path(journal.clone());
        let replay = signer
            .sign_consensus_vote(&vote, &restarted)
            .expect("restart returns the exact stored envelope");
        assert_eq!(
            replay, first,
            "restart must never create a second randomized signature for one subject"
        );
        let authorization = ConsensusSigningAuthorization::from_vote(&vote).unwrap();
        let recorded = restarted
            .recorded_signed_vote_for_slot(&authorization)
            .unwrap()
            .expect("exact envelope remains durable");
        assert_eq!(recorded.aegis_pq_signature, first);
        let _ = std::fs::remove_file(journal);
    }

    #[test]
    fn testnet_v3_consensus_domains_reject_fndsa_keys_before_signature_release() {
        let mut signer = AegisPqvmSigner::initialize_required().expect("aegis signer");
        let mut legacy_manager = PQCManager::new();
        let (public_key, private_key) = legacy_manager
            .generate_keypair(PQCAlgorithm::FNDSA)
            .expect("legacy FN-DSA fixture");
        let key_id = signer
            .register_existing_keypair(
                "uma-legacy",
                public_key,
                private_key,
                vec![
                    AegisPqKeyRole::ConsensusVote,
                    AegisPqKeyRole::ConsensusProposer,
                ],
                Epoch(0),
            )
            .expect("register legacy fixture");

        let error = signer
            .sign_domain(SYNERGY_FINALITY_VOTE_V1, b"candidate", &key_id)
            .expect_err("FN-DSA must not sign Testnet-v3 consensus transcripts");
        assert!(error.to_string().contains("requires ML-DSA-65"));
    }

    #[test]
    fn wrong_role_and_revoked_key_fail_closed() {
        let mut signer = AegisPqvmSigner::initialize_required().expect("aegis signer");
        let key_id = signer
            .generate_and_register_key("uma-1", vec![AegisPqKeyRole::PeerIdentity], Epoch(0))
            .expect("key");
        let record = validator_record(
            &signer,
            "validator-1",
            "uma-1",
            &key_id,
            ValidatorStatus::Active,
        );
        let set = ValidatorSet {
            epoch: Epoch(0),
            validators: vec![record.clone()],
        };
        let cluster = ClusterMap {
            epoch: Epoch(0),
            assignments: vec![ClusterAssignment {
                cluster_id: ClusterId(0),
                validator_id: record.validator_id.clone(),
            }],
        };
        let vote = signed_vote(
            &mut signer,
            &key_id,
            "validator-1",
            "uma-1",
            "block-a",
            set.hash().unwrap(),
            cluster.hash().unwrap(),
            Hash::from_domain_bytes("SYNERGY_TEST_HEIGHT_CONTEXT_V1", b"wrong-role"),
        );
        let verifier = signer.verifier();
        assert!(!verifier.verify_vote_signature(&vote, &record, vote.height_context_root));

        let mut signer = AegisPqvmSigner::initialize_required().expect("aegis signer");
        let key_id = signer
            .generate_and_register_key("uma-1", vec![AegisPqKeyRole::ConsensusVote], Epoch(0))
            .expect("key");
        signer.registry.revoke_key("uma-1", &key_id, Epoch(0));
        let record = validator_record(
            &signer,
            "validator-1",
            "uma-1",
            &key_id,
            ValidatorStatus::Active,
        );
        let vote = signed_vote(
            &mut signer,
            &key_id,
            "validator-1",
            "uma-1",
            "block-a",
            Hash::zero(),
            Hash::zero(),
            Hash::from_domain_bytes("SYNERGY_TEST_HEIGHT_CONTEXT_V1", b"revoked"),
        );
        assert!(!signer
            .verifier()
            .verify_vote_signature(&vote, &record, vote.height_context_root));
    }

    #[test]
    fn verifier_initialize_reuses_required_smoke_check() {
        for _ in 0..3 {
            let verifier = AegisPqvmVerifier::initialize_required(AegisPqvmKeyRegistry::default())
                .expect("cached verifier smoke check should initialize");
            assert!(verifier.initialized);
        }
    }

    #[test]
    fn qc_rejects_duplicate_inactive_and_requires_threshold() {
        let mut signer = AegisPqvmSigner::initialize_required().expect("aegis signer");
        let mut records = Vec::new();
        let mut key_ids = Vec::new();
        for index in 0..5 {
            let uma = format!("uma-{index}");
            let key_id = signer
                .generate_and_register_key(&uma, vec![AegisPqKeyRole::ConsensusVote], Epoch(0))
                .expect("key");
            records.push(validator_record(
                &signer,
                &format!("validator-{index}"),
                &uma,
                &key_id,
                ValidatorStatus::Active,
            ));
            key_ids.push(key_id);
        }
        let set = ValidatorSet {
            epoch: Epoch(0),
            validators: records.clone(),
        };
        let cluster = ClusterMap {
            epoch: Epoch(0),
            assignments: records
                .iter()
                .map(|record| ClusterAssignment {
                    cluster_id: ClusterId(0),
                    validator_id: record.validator_id.clone(),
                })
                .collect(),
        };
        let set_hash = set.hash().unwrap();
        let cluster_hash = cluster.hash().unwrap();
        let protocol = ProtocolConfig::testnet_v3();
        let height_context =
            deterministic_test_height_context(&set, &cluster, &protocol, Height(1), ClusterId(0));
        let height_context_root = height_context.root().unwrap();
        let votes = (0..4)
            .map(|index| {
                signed_vote(
                    &mut signer,
                    &key_ids[index],
                    &format!("validator-{index}"),
                    &format!("uma-{index}"),
                    "block-a",
                    set_hash,
                    cluster_hash,
                    height_context_root,
                )
            })
            .collect::<Vec<_>>();
        let qc = QuorumCertificate {
            qc_version: 1,
            chain_id: ChainId::synergy_testnet_v3(),
            network_id: NetworkId::synergy_testnet_v3(),
            protocol_version: POSY_PROTOCOL_VERSION.to_string(),
            height: Height(1),
            round: Round(0),
            epoch: Epoch(0),
            cluster_id: ClusterId(0),
            height_context_root,
            phase: VotePhase::Finality,
            block_id: BlockId::from("block-a"),
            highest_prepared_vc_root: None,
            active_validator_set_hash: set_hash,
            cluster_map_hash: cluster_hash,
            threshold_weight_required: 4,
            signed_weight: 4,
            signer_bitmap: vec![0b0000_1111],
            aegis_pq_signatures: votes
                .iter()
                .map(|vote| vote.aegis_pq_signature.clone())
                .collect(),
            aegis_pq_key_ids: key_ids[0..4].to_vec(),
        };
        assert!(signer
            .verifier()
            .verify_qc(&qc, &set, &cluster, &height_context));

        let mut below_threshold = qc.clone();
        below_threshold.signer_bitmap = vec![0b0000_0111];
        below_threshold.aegis_pq_signatures.pop();
        below_threshold.aegis_pq_key_ids.pop();
        below_threshold.signed_weight = 3;
        assert!(!signer
            .verifier()
            .verify_qc(&below_threshold, &set, &cluster, &height_context));

        let mut duplicate_key = qc.clone();
        duplicate_key.aegis_pq_key_ids[1] = duplicate_key.aegis_pq_key_ids[0].clone();
        assert!(!signer
            .verifier()
            .verify_qc(&duplicate_key, &set, &cluster, &height_context));

        let mut inactive_set = set.clone();
        inactive_set.validators[0].status = ValidatorStatus::Shadow;
        assert!(!signer
            .verifier()
            .verify_qc(&qc, &inactive_set, &cluster, &height_context));
    }

    #[test]
    fn unavailable_aegis_prevents_verification() {
        let verifier = AegisPqvmVerifier::unavailable_for_startup_tests();
        assert!(verifier.key_lifecycle_root(Epoch(0)).is_err());
        let hello = PeerHello {
            node_id: "node-1".to_string(),
            validator_id_optional: None,
            role: "VALIDATOR".to_string(),
            chain_id: ChainId::synergy_testnet_v3(),
            network_id: NetworkId::synergy_testnet_v3(),
            genesis_hash: Hash::zero(),
            protocol_version: "1".to_string(),
            consensus_version: "1".to_string(),
            execution_version: "1".to_string(),
            dag_version: "1".to_string(),
            aegis_pqvm_version: "aegis-pqvm".to_string(),
            latest_finalized_height: Height(0),
            latest_finalized_hash: Hash::zero(),
            latest_state_root: Hash::zero(),
            active_validator_set_hash: Hash::zero(),
            cluster_map_hash: Hash::zero(),
            protocol_config_hash: crate::consensus_parameters::ConsensusParameterRoot::zero(),
            aegis_pq_public_key_id: AegisPqKeyId::from("missing"),
        };
        assert!(!verifier.verify_peer_identity(
            &hello,
            &AegisPqSignature {
                algorithm: "fndsa".to_string(),
                signature_bytes: vec![1],
            }
        ));
    }
}
