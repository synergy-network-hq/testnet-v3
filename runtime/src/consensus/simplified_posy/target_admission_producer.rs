//! Durable schedule-neutral H+3 target-admission production for simplified PoSy.

#[cfg(test)]
use super::QuorumCertificateReference;
use super::{
    simplified_protected_finality_context_digest_from_state_root,
    DurableSimplifiedProtectedMaterialAuthority, FinalizedBlockRecord, SimplifiedEpochContext,
    POSY_SIMPLIFIED_PROTOCOL_VERSION,
};
use crate::consensus_parameters::ConsensusParameterRoot;
use crate::crypto::aegis_pqvm::{AegisPqvmSigner, AegisPqvmVerifier};
use crate::etdag::{
    form_target_admission_certificate, sign_target_admission_vote,
    target_admission_source_finality_root, verify_target_admission_vote,
    EtdagAuthenticatedIngressPeer, EtdagDigest, EtdagProtectedInputCoordinator, EtdagSafetyJournal,
    EtdagSignedVote, IngressKemKeyRegistry, TargetAdmissionContext, TargetAdmissionContextSpec,
    TargetAdmissionPackage,
};
use crate::synergy_types::{
    CanonicalSerialize, ClusterId, ClusterMap, Hash, Height, ValidatorId, ValidatorRecord,
    ValidatorSet, ValidatorStatus, TESTNET_V3_CLUSTER_SCHEDULE_VERSION,
};
use serde::{Deserialize, Serialize};
use sha3::{Digest as _, Sha3_512};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::TryLockError;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

pub const SIMPLIFIED_TARGET_ADMISSION_STORE_FORMAT: &str =
    "synergy-posy-simplified-target-admission-producer-v1";
pub const MAX_SIMPLIFIED_TARGET_ADMISSION_ENTRIES: usize = 4;
pub const MAX_SIMPLIFIED_TARGET_ADMISSION_STORE_BYTES: usize = 16 * 1024 * 1024;
const SIMPLIFIED_TARGET_ADMISSION_STORE_DIRECTORY: &str = "data/posy-v3-target-admission";
const SIMPLIFIED_INGRESS_KEM_REGISTRY_DIRECTORY: &str = "data/posy-v3-ingress-kem-registries";
pub const SIMPLIFIED_INGRESS_KEM_REGISTRY_ARTIFACT_FORMAT: &str =
    "synergy-posy-simplified-ingress-kem-registry-v1";
pub const MAX_SIMPLIFIED_INGRESS_KEM_REGISTRY_ARTIFACT_BYTES: usize = 4 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SimplifiedTargetAdmissionFinalitySnapshot {
    pub epoch_context_root: Hash,
    pub consensus_parameter_root: ConsensusParameterRoot,
    pub finalized: FinalizedBlockRecord,
    pub finalized_execution_state_root: Hash,
    pub canonical_finality_context_digest: EtdagDigest,
}

pub trait SimplifiedTargetAdmissionFinalityAuthority: Send {
    fn current_finalized_authority(
        &mut self,
    ) -> Result<SimplifiedTargetAdmissionFinalitySnapshot, String>;
}

impl SimplifiedTargetAdmissionFinalityAuthority for DurableSimplifiedProtectedMaterialAuthority {
    fn current_finalized_authority(
        &mut self,
    ) -> Result<SimplifiedTargetAdmissionFinalitySnapshot, String> {
        let epoch_context = self.epoch_context().clone();
        let (finalized, finalized_execution_state_root, canonical_finality_context_digest) =
            DurableSimplifiedProtectedMaterialAuthority::current_finalized_authority_with_state_root(
                self,
            )?;
        Ok(SimplifiedTargetAdmissionFinalitySnapshot {
            epoch_context_root: epoch_context.root()?,
            consensus_parameter_root: ConsensusParameterRoot::from_hex(
                &epoch_context.consensus_parameter_root,
            )?,
            finalized,
            finalized_execution_state_root,
            canonical_finality_context_digest,
        })
    }
}

pub trait SimplifiedIngressKemRegistrySource: Send {
    fn registry_for_target(
        &mut self,
        epoch: crate::synergy_types::Epoch,
        target_height: Height,
        assigned_cluster_id: ClusterId,
    ) -> Result<Option<IngressKemKeyRegistry>, String>;
}

/// Public, externally provisioned ML-KEM registry artifact for one exact
/// frozen epoch/height/cluster. Private KEM custody never enters this file.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SimplifiedIngressKemRegistryArtifact {
    pub format: String,
    pub epoch_context_root: Hash,
    pub epoch: crate::synergy_types::Epoch,
    pub target_height: Height,
    pub assigned_cluster_id: ClusterId,
    pub registry_root: EtdagDigest,
    pub registry: IngressKemKeyRegistry,
}

impl SimplifiedIngressKemRegistryArtifact {
    pub fn validate(&self, expected_epoch_context_root: Hash) -> Result<(), String> {
        if self.format != SIMPLIFIED_INGRESS_KEM_REGISTRY_ARTIFACT_FORMAT
            || self.epoch_context_root != expected_epoch_context_root
            || self.epoch_context_root.is_zero()
            || self.registry.epoch != self.epoch
            || self.registry.target_height != self.target_height
            || self.registry.assigned_cluster_id != self.assigned_cluster_id
            || self.registry_root != self.registry.root()?
        {
            return Err("invalid simplified ingress KEM registry artifact".to_string());
        }
        Ok(())
    }
}

/// Publish the exact canonical public ML-KEM registry artifact consumed by
/// [`DurableSimplifiedIngressKemRegistrySource`]. The destination is strictly
/// no-clobber: an existing artifact is never replaced, and an incomplete new
/// file is removed if publication fails.
pub fn write_simplified_ingress_kem_registry_artifact(
    path: &Path,
    epoch_context_root: Hash,
    registry: &IngressKemKeyRegistry,
) -> Result<SimplifiedIngressKemRegistryArtifact, String> {
    if path.exists() {
        return Err(format!(
            "refusing to overwrite simplified ingress KEM registry artifact {}",
            path.display()
        ));
    }
    let artifact = SimplifiedIngressKemRegistryArtifact {
        format: SIMPLIFIED_INGRESS_KEM_REGISTRY_ARTIFACT_FORMAT.to_string(),
        epoch_context_root,
        epoch: registry.epoch,
        target_height: registry.target_height,
        assigned_cluster_id: registry.assigned_cluster_id,
        registry_root: registry.root()?,
        registry: registry.clone(),
    };
    artifact.validate(epoch_context_root)?;
    let bytes = serde_json::to_vec(&artifact)
        .map_err(|error| format!("serialize simplified ingress KEM registry: {error}"))?;
    if bytes.is_empty() || bytes.len() > MAX_SIMPLIFIED_INGRESS_KEM_REGISTRY_ARTIFACT_BYTES {
        return Err(
            "simplified ingress KEM registry artifact violates its encode bound".to_string(),
        );
    }
    let parent = path.parent().ok_or_else(|| {
        format!(
            "simplified ingress KEM registry output has no parent: {}",
            path.display()
        )
    })?;
    if !parent.is_dir() {
        return Err(format!(
            "simplified ingress KEM registry output directory does not exist: {}",
            parent.display()
        ));
    }
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o644);
    }
    let mut file = options.open(path).map_err(|error| {
        format!(
            "create simplified ingress KEM registry artifact {}: {error}",
            path.display()
        )
    })?;
    let result = (|| {
        file.write_all(&bytes)
            .map_err(|error| format!("write simplified ingress KEM registry: {error}"))?;
        file.sync_all()
            .map_err(|error| format!("fsync simplified ingress KEM registry: {error}"))?;
        OpenOptions::new()
            .read(true)
            .open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|error| format!("fsync simplified ingress KEM registry directory: {error}"))
    })();
    if result.is_err() {
        let _ = fs::remove_file(path);
    }
    result?;
    Ok(artifact)
}

/// Deterministic, read-only source for public ML-KEM registries issued by the
/// identity/custody workstream. Missing artifacts return `None`; malformed,
/// noncanonical, substituted, or oversized artifacts fail closed.
#[derive(Debug, Clone)]
pub struct DurableSimplifiedIngressKemRegistrySource {
    directory: PathBuf,
    epoch_context_root: Hash,
}

impl DurableSimplifiedIngressKemRegistrySource {
    pub fn process_wide(epoch_context_root: Hash) -> Result<Self, String> {
        Self::at_directory(
            crate::utils::resolve_data_path(SIMPLIFIED_INGRESS_KEM_REGISTRY_DIRECTORY),
            epoch_context_root,
        )
    }

    pub fn at_directory(
        directory: impl Into<PathBuf>,
        epoch_context_root: Hash,
    ) -> Result<Self, String> {
        if epoch_context_root.is_zero() {
            return Err("ingress KEM registry source epoch root is missing".to_string());
        }
        Ok(Self {
            directory: directory.into(),
            epoch_context_root,
        })
    }

    pub fn artifact_path(
        &self,
        epoch: crate::synergy_types::Epoch,
        target_height: Height,
        assigned_cluster_id: ClusterId,
    ) -> PathBuf {
        self.directory
            .join(self.epoch_context_root.to_hex())
            .join(format!(
                "epoch-{}-height-{}-cluster-{}.json",
                epoch.0, target_height.0, assigned_cluster_id.0
            ))
    }
}

impl SimplifiedIngressKemRegistrySource for DurableSimplifiedIngressKemRegistrySource {
    fn registry_for_target(
        &mut self,
        epoch: crate::synergy_types::Epoch,
        target_height: Height,
        assigned_cluster_id: ClusterId,
    ) -> Result<Option<IngressKemKeyRegistry>, String> {
        let path = self.artifact_path(epoch, target_height, assigned_cluster_id);
        if !path.exists() {
            return Ok(None);
        }
        let bytes = fs::read(&path)
            .map_err(|error| format!("read ingress KEM registry {}: {error}", path.display()))?;
        if bytes.is_empty() || bytes.len() > MAX_SIMPLIFIED_INGRESS_KEM_REGISTRY_ARTIFACT_BYTES {
            return Err(
                "simplified ingress KEM registry artifact violates its decode bound".to_string(),
            );
        }
        let artifact: SimplifiedIngressKemRegistryArtifact = serde_json::from_slice(&bytes)
            .map_err(|error| format!("parse simplified ingress KEM registry: {error}"))?;
        if serde_json::to_vec(&artifact)
            .map_err(|error| format!("canonicalize simplified ingress KEM registry: {error}"))?
            != bytes
        {
            return Err("simplified ingress KEM registry artifact is not canonical".to_string());
        }
        artifact.validate(self.epoch_context_root)?;
        if artifact.epoch != epoch
            || artifact.target_height != target_height
            || artifact.assigned_cluster_id != assigned_cluster_id
        {
            return Err(
                "simplified ingress KEM registry artifact names another target".to_string(),
            );
        }
        Ok(Some(artifact.registry))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SimplifiedTargetAdmissionVoteRequest {
    pub context: TargetAdmissionContext,
    pub ingress_kem_registry: IngressKemKeyRegistry,
    pub vote: EtdagSignedVote,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum SimplifiedTargetAdmissionOutput {
    Vote(SimplifiedTargetAdmissionVoteRequest),
    CertifiedPackage(TargetAdmissionPackage),
}

#[derive(Clone)]
pub struct SimplifiedTargetAdmissionConfiguration {
    pub epoch_context: SimplifiedEpochContext,
    pub validator_set: ValidatorSet,
    pub cluster_map: ClusterMap,
    pub verifier: AegisPqvmVerifier,
    pub cryptographic_profile_root: Hash,
}

impl SimplifiedTargetAdmissionConfiguration {
    fn validate(&self) -> Result<(), String> {
        let active = self
            .validator_set
            .active_for_epoch(self.epoch_context.epoch);
        self.epoch_context.validate_against(&active)?;
        if self.validator_set.epoch != self.epoch_context.epoch
            || self.cluster_map.epoch != self.epoch_context.epoch
            || self.cryptographic_profile_root.is_zero()
            || self.cluster_map
                != ClusterMap::derive_from_finalized_epoch_seed(
                    &active,
                    self.epoch_context.finalized_epoch_seed_root,
                )?
        {
            return Err("invalid simplified target-admission configuration".to_string());
        }
        self.cluster_map
            .validate_complete_balanced_assignment(&active)
    }

    fn parameter_root(&self) -> Result<ConsensusParameterRoot, String> {
        ConsensusParameterRoot::from_hex(&self.epoch_context.consensus_parameter_root)
    }
}

/// Deterministically assign the ETDAG cluster for a target height without
/// importing simplified consensus proposer scheduling.
pub fn simplified_target_admission_assignment(
    epoch_context: &SimplifiedEpochContext,
    target_height: Height,
    cluster_map: &ClusterMap,
) -> Result<(ClusterId, Hash), String> {
    if target_height.0 < epoch_context.epoch_start_height.0
        || target_height.0 > epoch_context.epoch_end_height.0
        || cluster_map.epoch != epoch_context.epoch
    {
        return Err("simplified target-admission height is outside its frozen epoch".to_string());
    }
    let cluster_ids = cluster_map
        .assignments
        .iter()
        .map(|assignment| assignment.cluster_id)
        .collect::<BTreeSet<_>>();
    if cluster_ids.is_empty() {
        return Err("simplified target-admission cluster map is empty".to_string());
    }
    let cluster_ids = cluster_ids.into_iter().collect::<Vec<_>>();
    let epoch_root = epoch_context.root()?;
    let map_root = cluster_map.hash()?;
    let mut hasher = Sha3_512::new();
    hasher.update(b"PoSy/Simplified/ETDAG/HeightCluster/v1");
    hasher.update(epoch_root.0);
    hasher.update(map_root.0);
    hasher.update(target_height.0.to_be_bytes());
    let rank = hasher.finalize();
    let modulus = u128::try_from(cluster_ids.len())
        .map_err(|_| "simplified ETDAG cluster count exceeds u128".to_string())?;
    let remainder = rank.iter().fold(0u128, |remainder, byte| {
        (remainder * 256 + u128::from(*byte)) % modulus
    });
    let position = usize::try_from(remainder)
        .map_err(|_| "simplified ETDAG cluster position exceeds usize".to_string())?;
    let assigned_cluster_id = cluster_ids[position];
    let schedule_root = Hash::from_domain_bytes(
        "SYNERGY_POSY_SIMPLIFIED_ETDAG_HEIGHT_SCHEDULE_V1",
        &(epoch_root, map_root, target_height, assigned_cluster_id).canonical_bytes()?,
    );
    Ok((assigned_cluster_id, schedule_root))
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct DurableTargetAdmissionEntry {
    context: TargetAdmissionContext,
    ingress_kem_registry: IngressKemKeyRegistry,
    votes: Vec<EtdagSignedVote>,
    certified_package: Option<TargetAdmissionPackage>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct DurableTargetAdmissionFile {
    format: String,
    entries: BTreeMap<Height, DurableTargetAdmissionEntry>,
}

impl Default for DurableTargetAdmissionFile {
    fn default() -> Self {
        Self {
            format: SIMPLIFIED_TARGET_ADMISSION_STORE_FORMAT.to_string(),
            entries: BTreeMap::new(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct DurableSimplifiedTargetAdmissionStore {
    path: PathBuf,
}

static TARGET_ADMISSION_STORE_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

impl DurableSimplifiedTargetAdmissionStore {
    pub fn for_epoch(epoch_context_root: Hash) -> Result<Self, String> {
        if epoch_context_root.is_zero() {
            return Err("target-admission store epoch root is missing".to_string());
        }
        Ok(Self::at_path(
            crate::utils::resolve_data_path(SIMPLIFIED_TARGET_ADMISSION_STORE_DIRECTORY)
                .join(format!("{}.json", epoch_context_root.to_hex())),
        ))
    }

    pub fn at_path(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    fn with_store<T>(
        &self,
        operation: impl FnOnce(&mut DurableTargetAdmissionFile) -> Result<(T, bool), String>,
    ) -> Result<T, String> {
        let _guard = TARGET_ADMISSION_STORE_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .map_err(|_| "simplified target-admission store lock poisoned".to_string())?;
        let mut store = self.load_unlocked()?;
        let (result, changed) = operation(&mut store)?;
        if changed {
            self.persist_unlocked(&store)?;
        }
        Ok(result)
    }

    fn install_context(
        &self,
        finalized_height: Height,
        context: &TargetAdmissionContext,
        registry: &IngressKemKeyRegistry,
    ) -> Result<DurableTargetAdmissionEntry, String> {
        self.with_store(|store| {
            let prior_len = store.entries.len();
            store
                .entries
                .retain(|target_height, _| target_height.0 > finalized_height.0);
            let pruned = store.entries.len() != prior_len;
            if let Some(existing) = store.entries.get(&context.target_height) {
                if existing.context == *context && existing.ingress_kem_registry == *registry {
                    return Ok((existing.clone(), pruned));
                }
                return Err("SIMPLIFIED_TARGET_ADMISSION_CONTEXT_CONFLICT".to_string());
            }
            if store.entries.len() >= MAX_SIMPLIFIED_TARGET_ADMISSION_ENTRIES {
                return Err("SIMPLIFIED_TARGET_ADMISSION_STORE_FULL".to_string());
            }
            let entry = DurableTargetAdmissionEntry {
                context: context.clone(),
                ingress_kem_registry: registry.clone(),
                votes: Vec::new(),
                certified_package: None,
            };
            store.entries.insert(context.target_height, entry.clone());
            Ok((entry, true))
        })
    }

    fn entry(&self, target_height: Height) -> Result<Option<DurableTargetAdmissionEntry>, String> {
        self.with_store(|store| Ok((store.entries.get(&target_height).cloned(), false)))
    }

    fn install_vote(
        &self,
        target_height: Height,
        vote: &EtdagSignedVote,
    ) -> Result<DurableTargetAdmissionEntry, String> {
        self.with_store(|store| {
            let entry = store
                .entries
                .get_mut(&target_height)
                .ok_or_else(|| "SIMPLIFIED_TARGET_ADMISSION_CONTEXT_NOT_READY".to_string())?;
            if let Some(existing) = entry
                .votes
                .iter()
                .find(|existing| existing.signer_validator_id == vote.signer_validator_id)
            {
                if existing == vote {
                    return Ok((entry.clone(), false));
                }
                return Err("SIMPLIFIED_TARGET_ADMISSION_VOTE_CONFLICT".to_string());
            }
            if entry.votes.len() as u64 >= entry.context.assigned_cluster_validator_count {
                return Err("SIMPLIFIED_TARGET_ADMISSION_VOTE_SET_FULL".to_string());
            }
            entry.votes.push(vote.clone());
            entry
                .votes
                .sort_by(|left, right| left.signer_validator_id.cmp(&right.signer_validator_id));
            Ok((entry.clone(), true))
        })
    }

    fn install_package(
        &self,
        package: &TargetAdmissionPackage,
    ) -> Result<TargetAdmissionPackage, String> {
        self.with_store(|store| {
            let entry = store
                .entries
                .get_mut(&package.context.target_height)
                .ok_or_else(|| "SIMPLIFIED_TARGET_ADMISSION_CONTEXT_NOT_READY".to_string())?;
            if entry.context != package.context
                || entry.ingress_kem_registry != package.ingress_kem_registry
            {
                return Err("SIMPLIFIED_TARGET_ADMISSION_PACKAGE_CONFLICT".to_string());
            }
            if let Some(existing) = &entry.certified_package {
                if existing == package {
                    return Ok((existing.clone(), false));
                }
                return Err("SIMPLIFIED_TARGET_ADMISSION_PACKAGE_CONFLICT".to_string());
            }
            entry.certified_package = Some(package.clone());
            Ok((package.clone(), true))
        })
    }

    fn load_unlocked(&self) -> Result<DurableTargetAdmissionFile, String> {
        if !self.path.exists() {
            return Ok(DurableTargetAdmissionFile::default());
        }
        let bytes = fs::read(&self.path).map_err(|error| {
            format!(
                "read simplified target-admission store {}: {error}",
                self.path.display()
            )
        })?;
        if bytes.is_empty() || bytes.len() > MAX_SIMPLIFIED_TARGET_ADMISSION_STORE_BYTES {
            return Err("simplified target-admission store violates its decode bound".to_string());
        }
        let store: DurableTargetAdmissionFile = serde_json::from_slice(&bytes)
            .map_err(|error| format!("parse simplified target-admission store: {error}"))?;
        if store.format != SIMPLIFIED_TARGET_ADMISSION_STORE_FORMAT
            || store.entries.len() > MAX_SIMPLIFIED_TARGET_ADMISSION_ENTRIES
            || serde_json::to_vec(&store)
                .map_err(|error| format!("canonicalize target-admission store: {error}"))?
                != bytes
        {
            return Err("invalid simplified target-admission store".to_string());
        }
        for (height, entry) in &store.entries {
            if *height != entry.context.target_height
                || entry.votes.len() as u64 > entry.context.assigned_cluster_validator_count
                || entry
                    .votes
                    .windows(2)
                    .any(|votes| votes[0].signer_validator_id >= votes[1].signer_validator_id)
            {
                return Err("corrupt simplified target-admission store entry".to_string());
            }
        }
        Ok(store)
    }

    fn persist_unlocked(&self, store: &DurableTargetAdmissionFile) -> Result<(), String> {
        let bytes = serde_json::to_vec(store)
            .map_err(|error| format!("serialize simplified target-admission store: {error}"))?;
        if bytes.len() > MAX_SIMPLIFIED_TARGET_ADMISSION_STORE_BYTES {
            return Err("simplified target-admission store exceeds its bound".to_string());
        }
        let parent = self
            .path
            .parent()
            .ok_or_else(|| "simplified target-admission store has no parent".to_string())?;
        fs::create_dir_all(parent)
            .map_err(|error| format!("create simplified target-admission directory: {error}"))?;
        let name = self
            .path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| "simplified target-admission store has no filename".to_string())?;
        let temp = parent.join(format!(
            ".{name}.tmp-{}-{}",
            std::process::id(),
            current_unix_nanos()
        ));
        let result = (|| {
            let mut file = OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&temp)
                .map_err(|error| format!("create target-admission temp file: {error}"))?;
            file.write_all(&bytes)
                .map_err(|error| format!("write target-admission store: {error}"))?;
            file.sync_all()
                .map_err(|error| format!("fsync target-admission store: {error}"))?;
            fs::rename(&temp, &self.path)
                .map_err(|error| format!("replace target-admission store: {error}"))?;
            OpenOptions::new()
                .read(true)
                .open(parent)
                .and_then(|directory| directory.sync_all())
                .map_err(|error| format!("fsync target-admission directory: {error}"))
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temp);
        }
        result
    }
}

pub struct SimplifiedTargetAdmissionProducer {
    configuration: SimplifiedTargetAdmissionConfiguration,
    local_validator_id: ValidatorId,
    signer: Arc<Mutex<AegisPqvmSigner>>,
    signing_journal: EtdagSafetyJournal,
    store: DurableSimplifiedTargetAdmissionStore,
    protected_inputs: EtdagProtectedInputCoordinator,
    finality_authority: Box<dyn SimplifiedTargetAdmissionFinalityAuthority>,
    registry_source: Box<dyn SimplifiedIngressKemRegistrySource>,
}

static SIMPLIFIED_TARGET_ADMISSION_HANDLER: OnceLock<
    Mutex<Option<SimplifiedTargetAdmissionProducer>>,
> = OnceLock::new();

fn target_admission_handler_slot() -> &'static Mutex<Option<SimplifiedTargetAdmissionProducer>> {
    SIMPLIFIED_TARGET_ADMISSION_HANDLER.get_or_init(|| Mutex::new(None))
}

/// Installs exactly one process-wide target-admission handler. Ingress is
/// handled under a nonblocking mutex rather than queued, so authenticated peers
/// cannot create an unbounded backlog of signature verification or disk work.
pub fn install_simplified_target_admission_producer_handler(
    producer: SimplifiedTargetAdmissionProducer,
) -> Result<(), String> {
    let mut slot = try_lock_target_admission_handler()?;
    if slot.is_some() {
        return Err("simplified target-admission producer is already installed".to_string());
    }
    *slot = Some(producer);
    Ok(())
}

/// Removes and returns the installed producer so runtime shutdown can retain
/// ownership of its exact durable authority and signer resources.
pub fn remove_simplified_target_admission_producer_handler(
) -> Result<Option<SimplifiedTargetAdmissionProducer>, String> {
    Ok(try_lock_target_admission_handler()?.take())
}

/// Advances the installed producer to the exact H+3 target derived from its
/// durable finalized authority. Runtime calls this on a bounded cadence and
/// broadcasts the returned vote/package artifacts to the frozen epoch set.
pub fn prepare_simplified_target_admission_h3(
) -> Result<Vec<SimplifiedTargetAdmissionOutput>, String> {
    let mut slot = try_lock_target_admission_handler()?;
    slot.as_mut()
        .ok_or_else(|| {
            "simplified target-admission producer is not installed; refusing prepare".to_string()
        })?
        .prepare_h3()
}

pub fn dispatch_simplified_target_admission_vote(
    authenticated_peer: Option<EtdagAuthenticatedIngressPeer>,
    request: SimplifiedTargetAdmissionVoteRequest,
) -> Result<Option<SimplifiedTargetAdmissionOutput>, String> {
    crate::p2p::messages::validate_simplified_target_admission_message_size(
        &crate::p2p::messages::SimplifiedTargetAdmissionMessage::Vote {
            request: request.clone(),
        },
    )?;
    let authenticated_peer = authenticated_peer.ok_or_else(|| {
        "simplified target-admission vote requires an authenticated validator peer".to_string()
    })?;
    let mut slot = try_lock_target_admission_handler()?;
    let producer = slot.as_mut().ok_or_else(|| {
        "simplified target-admission producer is not installed; refusing vote".to_string()
    })?;
    producer.handle_authenticated_vote(&authenticated_peer, &request)
}

pub fn dispatch_simplified_target_admission_package(
    authenticated_peer: Option<EtdagAuthenticatedIngressPeer>,
    package: TargetAdmissionPackage,
) -> Result<SimplifiedTargetAdmissionOutput, String> {
    crate::p2p::messages::validate_simplified_target_admission_message_size(
        &crate::p2p::messages::SimplifiedTargetAdmissionMessage::CertifiedPackage {
            package: package.clone(),
        },
    )?;
    let authenticated_peer = authenticated_peer.ok_or_else(|| {
        "simplified target-admission package requires an authenticated validator peer".to_string()
    })?;
    let mut slot = try_lock_target_admission_handler()?;
    let producer = slot.as_mut().ok_or_else(|| {
        "simplified target-admission producer is not installed; refusing package".to_string()
    })?;
    producer.handle_authenticated_package(&authenticated_peer, &package)
}

fn try_lock_target_admission_handler(
) -> Result<std::sync::MutexGuard<'static, Option<SimplifiedTargetAdmissionProducer>>, String> {
    target_admission_handler_slot()
        .try_lock()
        .map_err(|error| match error {
            TryLockError::WouldBlock => {
                "simplified target-admission producer is busy; ingress rejected".to_string()
            }
            TryLockError::Poisoned(_) => {
                "simplified target-admission producer lock is poisoned".to_string()
            }
        })
}

impl SimplifiedTargetAdmissionProducer {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        configuration: SimplifiedTargetAdmissionConfiguration,
        local_validator_id: ValidatorId,
        signer: Arc<Mutex<AegisPqvmSigner>>,
        signing_journal: EtdagSafetyJournal,
        store: DurableSimplifiedTargetAdmissionStore,
        protected_inputs: EtdagProtectedInputCoordinator,
        finality_authority: Box<dyn SimplifiedTargetAdmissionFinalityAuthority>,
        registry_source: Box<dyn SimplifiedIngressKemRegistrySource>,
    ) -> Result<Self, String> {
        configuration.validate()?;
        let local = configuration
            .validator_set
            .validators
            .iter()
            .find(|validator| validator.validator_id == local_validator_id)
            .ok_or_else(|| {
                "simplified target-admission local validator is outside the frozen set".to_string()
            })?;
        if local.status != ValidatorStatus::Active
            || !local.is_active_for_epoch(configuration.epoch_context.epoch)
        {
            return Err("simplified target-admission local validator is inactive".to_string());
        }
        Ok(Self {
            configuration,
            local_validator_id,
            signer,
            signing_journal,
            store,
            protected_inputs,
            finality_authority,
            registry_source,
        })
    }

    /// Narrow production handoff for later role-runtime wiring.
    pub fn new_process_wide(
        configuration: SimplifiedTargetAdmissionConfiguration,
        local_validator_id: ValidatorId,
        signer: Arc<Mutex<AegisPqvmSigner>>,
        finality_authority: Box<dyn SimplifiedTargetAdmissionFinalityAuthority>,
        registry_source: Box<dyn SimplifiedIngressKemRegistrySource>,
    ) -> Result<Self, String> {
        let epoch_root = configuration.epoch_context.root()?;
        Self::new(
            configuration,
            local_validator_id,
            signer,
            EtdagSafetyJournal::process_wide(),
            DurableSimplifiedTargetAdmissionStore::for_epoch(epoch_root)?,
            EtdagProtectedInputCoordinator::process_wide(),
            finality_authority,
            registry_source,
        )
    }

    pub fn prepare_h3(&mut self) -> Result<Vec<SimplifiedTargetAdmissionOutput>, String> {
        let authority = self.finality_authority.current_finalized_authority()?;
        self.validate_finality_authority(&authority)?;
        let target_height = authority
            .finalized
            .height
            .0
            .checked_add(3)
            .map(Height)
            .ok_or_else(|| "simplified target-admission H+3 height overflows".to_string())?;
        if target_height.0 > self.configuration.epoch_context.epoch_end_height.0 {
            // Three-chain finality naturally reaches E-2 while the certified
            // head is E. H+3 is then the next epoch's first height, whose
            // membership, topology, parameter root, and KEM registry are not
            // authoritative until the verified transition is installed.
            return Ok(Vec::new());
        }
        let (assigned_cluster_id, assigned_height_schedule_root) =
            simplified_target_admission_assignment(
                &self.configuration.epoch_context,
                target_height,
                &self.configuration.cluster_map,
            )?;
        let registry = self
            .registry_source
            .registry_for_target(
                self.configuration.epoch_context.epoch,
                target_height,
                assigned_cluster_id,
            )?
            .ok_or_else(|| "SIMPLIFIED_TARGET_ADMISSION_MISSING_INGRESS_REGISTRY".to_string())?;
        let context = TargetAdmissionContext::derive_schedule_neutral(
            TargetAdmissionContextSpec {
                protocol_version: POSY_SIMPLIFIED_PROTOCOL_VERSION.to_string(),
                epoch: self.configuration.epoch_context.epoch,
                target_height,
                source_finalized_height: authority.finalized.height,
                source_finality_context_root: target_admission_source_finality_root(
                    &authority.canonical_finality_context_digest,
                )?,
                assigned_cluster_id,
                cluster_schedule_version: TESTNET_V3_CLUSTER_SCHEDULE_VERSION.to_string(),
                finalized_epoch_seed_root: self
                    .configuration
                    .epoch_context
                    .finalized_epoch_seed_root,
                assigned_height_schedule_root,
                cryptographic_profile_root: self.configuration.cryptographic_profile_root,
                ingress_kem_registry_root: registry.root()?,
            },
            &self.configuration.validator_set,
            &self.configuration.cluster_map,
            self.configuration.parameter_root()?,
        )?;
        registry.validate_against(&context, &self.configuration.validator_set)?;
        let mut entry =
            self.store
                .install_context(authority.finalized.height, &context, &registry)?;
        self.validate_entry(&entry)?;
        if let Some(package) = entry.certified_package {
            self.install_certified_package(&package)?;
            return Ok(vec![SimplifiedTargetAdmissionOutput::CertifiedPackage(
                package,
            )]);
        }

        let mut outputs = Vec::new();
        if let Some(local) = self.local_cluster_member(&context) {
            let vote = match entry
                .votes
                .iter()
                .find(|vote| vote.signer_validator_id == self.local_validator_id)
            {
                Some(vote) => vote.clone(),
                None => {
                    let mut signer = self
                        .signer
                        .lock()
                        .map_err(|_| "target-admission signer lock poisoned".to_string())?;
                    let vote = sign_target_admission_vote(
                        &mut signer,
                        &self.signing_journal,
                        &context,
                        &local,
                    )?;
                    verify_target_admission_vote(
                        &vote,
                        &self.configuration.verifier,
                        &context,
                        &self.configuration.validator_set,
                        &self.configuration.cluster_map,
                    )?;
                    entry = self.store.install_vote(target_height, &vote)?;
                    vote
                }
            };
            outputs.push(SimplifiedTargetAdmissionOutput::Vote(
                SimplifiedTargetAdmissionVoteRequest {
                    context: context.clone(),
                    ingress_kem_registry: registry,
                    vote,
                },
            ));
        }
        if let Some(package) = self.try_certify(entry)? {
            outputs.push(SimplifiedTargetAdmissionOutput::CertifiedPackage(package));
        }
        Ok(outputs)
    }

    pub fn handle_authenticated_vote(
        &mut self,
        peer: &EtdagAuthenticatedIngressPeer,
        request: &SimplifiedTargetAdmissionVoteRequest,
    ) -> Result<Option<SimplifiedTargetAdmissionOutput>, String> {
        self.authorize_peer_for_vote(peer, &request.vote)?;
        let entry = self
            .store
            .entry(request.context.target_height)?
            .ok_or_else(|| "SIMPLIFIED_TARGET_ADMISSION_CONTEXT_NOT_READY".to_string())?;
        if entry.context != request.context
            || entry.ingress_kem_registry != request.ingress_kem_registry
        {
            return Err("SIMPLIFIED_TARGET_ADMISSION_REMOTE_CONTEXT_MISMATCH".to_string());
        }
        self.validate_entry(&entry)?;
        verify_target_admission_vote(
            &request.vote,
            &self.configuration.verifier,
            &entry.context,
            &self.configuration.validator_set,
            &self.configuration.cluster_map,
        )?;
        let entry = self
            .store
            .install_vote(entry.context.target_height, &request.vote)?;
        Ok(self
            .try_certify(entry)?
            .map(SimplifiedTargetAdmissionOutput::CertifiedPackage))
    }

    pub fn handle_authenticated_package(
        &mut self,
        peer: &EtdagAuthenticatedIngressPeer,
        package: &TargetAdmissionPackage,
    ) -> Result<SimplifiedTargetAdmissionOutput, String> {
        self.authorize_active_peer(peer)?;
        let entry = self
            .store
            .entry(package.context.target_height)?
            .ok_or_else(|| "SIMPLIFIED_TARGET_ADMISSION_CONTEXT_NOT_READY".to_string())?;
        if entry.context != package.context
            || entry.ingress_kem_registry != package.ingress_kem_registry
        {
            return Err("SIMPLIFIED_TARGET_ADMISSION_REMOTE_CONTEXT_MISMATCH".to_string());
        }
        self.install_certified_package(package)?;
        let package = self.store.install_package(package)?;
        Ok(SimplifiedTargetAdmissionOutput::CertifiedPackage(package))
    }

    fn validate_finality_authority(
        &self,
        authority: &SimplifiedTargetAdmissionFinalitySnapshot,
    ) -> Result<(), String> {
        authority
            .canonical_finality_context_digest
            .validate("simplified target-admission finality digest")?;
        let expected_finality_digest =
            simplified_protected_finality_context_digest_from_state_root(
                &self.configuration.epoch_context,
                &authority.finalized,
                authority.finalized_execution_state_root,
                &self.configuration.validator_set,
                &self.configuration.cluster_map,
            )?;
        if authority.epoch_context_root != self.configuration.epoch_context.root()?
            || authority.consensus_parameter_root != self.configuration.parameter_root()?
            || authority.canonical_finality_context_digest.is_zero()
            || authority.canonical_finality_context_digest != expected_finality_digest
        {
            return Err("SIMPLIFIED_TARGET_ADMISSION_FINALITY_AUTHORITY_MISMATCH".to_string());
        }
        Ok(())
    }

    fn validate_entry(&self, entry: &DurableTargetAdmissionEntry) -> Result<(), String> {
        entry.context.validate_against_parameter_root(
            &self.configuration.validator_set,
            &self.configuration.cluster_map,
            self.configuration.parameter_root()?,
        )?;
        entry
            .ingress_kem_registry
            .validate_against(&entry.context, &self.configuration.validator_set)?;
        for vote in &entry.votes {
            verify_target_admission_vote(
                vote,
                &self.configuration.verifier,
                &entry.context,
                &self.configuration.validator_set,
                &self.configuration.cluster_map,
            )?;
        }
        if let Some(package) = &entry.certified_package {
            package.verify_against_parameter_root(
                &self.configuration.verifier,
                &self.configuration.validator_set,
                &self.configuration.cluster_map,
                self.configuration.parameter_root()?,
            )?;
        }
        Ok(())
    }

    fn local_cluster_member(&self, context: &TargetAdmissionContext) -> Option<ValidatorRecord> {
        self.configuration
            .validator_set
            .active_for_epoch(context.epoch)
            .active_for_cluster(context.assigned_cluster_id)
            .into_iter()
            .find(|validator| validator.validator_id == self.local_validator_id)
    }

    fn try_certify(
        &self,
        entry: DurableTargetAdmissionEntry,
    ) -> Result<Option<TargetAdmissionPackage>, String> {
        self.validate_entry(&entry)?;
        if !has_strict_target_admission_quorum(
            &entry.context,
            &entry.votes,
            &self.configuration.validator_set,
        )? {
            return Ok(None);
        }
        let certificate = form_target_admission_certificate(
            &entry.context,
            entry.votes,
            &self.configuration.verifier,
            &self.configuration.validator_set,
            &self.configuration.cluster_map,
        )?;
        let package = TargetAdmissionPackage {
            context: entry.context,
            ingress_kem_registry: entry.ingress_kem_registry,
            certificate,
        };
        self.install_certified_package(&package)?;
        Ok(Some(self.store.install_package(&package)?))
    }

    fn install_certified_package(&self, package: &TargetAdmissionPackage) -> Result<(), String> {
        self.protected_inputs
            .install_certified_admission_package_schedule_neutral(
                package,
                &self.configuration.verifier,
                &self.configuration.validator_set,
                &self.configuration.cluster_map,
                self.configuration.parameter_root()?,
            )?;
        Ok(())
    }

    fn authorize_peer_for_vote(
        &self,
        peer: &EtdagAuthenticatedIngressPeer,
        vote: &EtdagSignedVote,
    ) -> Result<(), String> {
        if peer.validator_id != vote.signer_validator_id
            || peer.consensus_key_id != vote.signer_key_id
        {
            return Err("SIMPLIFIED_TARGET_ADMISSION_UNTRUSTED_PEER".to_string());
        }
        self.authorize_active_peer(peer)
    }

    fn authorize_active_peer(&self, peer: &EtdagAuthenticatedIngressPeer) -> Result<(), String> {
        let validator = self
            .configuration
            .validator_set
            .validators
            .iter()
            .find(|validator| validator.validator_id == peer.validator_id)
            .ok_or_else(|| "SIMPLIFIED_TARGET_ADMISSION_UNTRUSTED_PEER".to_string())?;
        if validator.status != ValidatorStatus::Active
            || !validator.is_active_for_epoch(self.configuration.epoch_context.epoch)
            || validator.validator_uma_id != peer.validator_uma_id
            || validator.consensus_public_key.key_id != peer.consensus_key_id
        {
            return Err("SIMPLIFIED_TARGET_ADMISSION_UNTRUSTED_PEER".to_string());
        }
        Ok(())
    }
}

fn has_strict_target_admission_quorum(
    context: &TargetAdmissionContext,
    votes: &[EtdagSignedVote],
    validator_set: &ValidatorSet,
) -> Result<bool, String> {
    let members = validator_set
        .active_for_epoch(context.epoch)
        .active_for_cluster(context.assigned_cluster_id);
    let mut signers = BTreeSet::new();
    let mut signed_weight = 0u64;
    for vote in votes {
        if !signers.insert(vote.signer_validator_id.clone()) {
            return Err("duplicate simplified target-admission signer".to_string());
        }
        let member = members
            .iter()
            .find(|member| member.validator_id == vote.signer_validator_id)
            .ok_or_else(|| "simplified target-admission signer is outside cluster".to_string())?;
        signed_weight = signed_weight
            .checked_add(member.voting_weight)
            .ok_or_else(|| "simplified target-admission signed weight overflow".to_string())?;
    }
    let total_weight = members.iter().try_fold(0u64, |total, member| {
        total
            .checked_add(member.voting_weight)
            .ok_or_else(|| "simplified target-admission total weight overflow".to_string())
    })?;
    Ok((votes.len() as u128) * 3 > (members.len() as u128) * 2
        && u128::from(signed_weight) * 3 > u128::from(total_weight) * 2)
}

fn current_unix_nanos() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::aegis_pqvm::AegisPqvmSigner;
    use crate::etdag::tests::fixture;
    use crate::etdag::{IngressKemKeyRecord, INGRESS_KEM_REGISTRY_VERSION};
    use crate::synergy_types::{BlockId, Epoch, NetworkId};
    use pqcrypto_mlkem::mlkem1024;
    use pqcrypto_traits::kem::PublicKey as _;

    static TARGET_ADMISSION_HANDLER_TEST_LOCK: Mutex<()> = Mutex::new(());

    #[derive(Clone)]
    struct ExactFinalityAuthority {
        snapshot: SimplifiedTargetAdmissionFinalitySnapshot,
    }

    impl SimplifiedTargetAdmissionFinalityAuthority for ExactFinalityAuthority {
        fn current_finalized_authority(
            &mut self,
        ) -> Result<SimplifiedTargetAdmissionFinalitySnapshot, String> {
            Ok(self.snapshot.clone())
        }
    }

    #[derive(Clone)]
    struct ExactRegistrySource {
        registry: Option<IngressKemKeyRegistry>,
    }

    impl SimplifiedIngressKemRegistrySource for ExactRegistrySource {
        fn registry_for_target(
            &mut self,
            epoch: Epoch,
            target_height: Height,
            assigned_cluster_id: ClusterId,
        ) -> Result<Option<IngressKemKeyRegistry>, String> {
            let Some(registry) = &self.registry else {
                return Ok(None);
            };
            if registry.epoch != epoch
                || registry.target_height != target_height
                || registry.assigned_cluster_id != assigned_cluster_id
            {
                return Err("test registry request mismatch".to_string());
            }
            Ok(Some(registry.clone()))
        }
    }

    struct TestEnvironment {
        configuration: SimplifiedTargetAdmissionConfiguration,
        local_validator_id: ValidatorId,
        signer: Arc<Mutex<AegisPqvmSigner>>,
        snapshot: SimplifiedTargetAdmissionFinalitySnapshot,
        registry: IngressKemKeyRegistry,
        store_path: PathBuf,
        journal_path: PathBuf,
        remote_journal: EtdagSafetyJournal,
        coordinator: EtdagProtectedInputCoordinator,
    }

    impl TestEnvironment {
        fn producer(
            &self,
            snapshot: SimplifiedTargetAdmissionFinalitySnapshot,
            registry: Option<IngressKemKeyRegistry>,
        ) -> SimplifiedTargetAdmissionProducer {
            SimplifiedTargetAdmissionProducer::new(
                self.configuration.clone(),
                self.local_validator_id.clone(),
                Arc::clone(&self.signer),
                EtdagSafetyJournal::at_path(self.journal_path.clone()),
                DurableSimplifiedTargetAdmissionStore::at_path(self.store_path.clone()),
                self.coordinator.clone(),
                Box::new(ExactFinalityAuthority { snapshot }),
                Box::new(ExactRegistrySource { registry }),
            )
            .unwrap()
        }
    }

    fn temp_root(label: &str) -> PathBuf {
        crate::utils::test_temp_root(format!(
            "simplified-target-admission-{label}-{}-{}",
            std::process::id(),
            current_unix_nanos()
        ))
    }

    fn environment(count: usize, label: &str) -> TestEnvironment {
        let etdag_fixture = fixture(count, None);
        let parameter_root = etdag_fixture.context.consensus_parameter_root;
        let epoch_context = SimplifiedEpochContext::derive(
            Epoch(0),
            Height(6),
            Height(100),
            etdag_fixture.context.finalized_epoch_seed_root,
            parameter_root,
            &etdag_fixture.validator_set,
        )
        .unwrap();
        let finalized = FinalizedBlockRecord::from_quorum_certificate(QuorumCertificateReference {
            height: Height(5),
            block_id: BlockId::from_hash(Hash::from_domain_bytes(
                "simplified-target-admission-test",
                b"finalized-five",
            )),
            qc_id: Hash::from_domain_bytes(
                "simplified-target-admission-test",
                b"finalized-five-qc",
            ),
        })
        .unwrap();
        let finalized_execution_state_root = Hash::from_domain_bytes(
            "simplified-target-admission-test",
            b"finalized-five-execution-state",
        );
        let canonical_finality_context_digest =
            simplified_protected_finality_context_digest_from_state_root(
                &epoch_context,
                &finalized,
                finalized_execution_state_root,
                &etdag_fixture.validator_set,
                &etdag_fixture.cluster_map,
            )
            .unwrap();
        let snapshot = SimplifiedTargetAdmissionFinalitySnapshot {
            epoch_context_root: epoch_context.root().unwrap(),
            consensus_parameter_root: parameter_root,
            finalized,
            finalized_execution_state_root,
            canonical_finality_context_digest,
        };
        let target_height = Height(8);
        let (assigned_cluster_id, _) = simplified_target_admission_assignment(
            &epoch_context,
            target_height,
            &etdag_fixture.cluster_map,
        )
        .unwrap();
        let members = etdag_fixture
            .validator_set
            .active_for_epoch(Epoch(0))
            .active_for_cluster(assigned_cluster_id);
        let records = members
            .iter()
            .enumerate()
            .map(|(index, member)| {
                let (public, _) = mlkem1024::keypair();
                IngressKemKeyRecord {
                    validator_id: member.validator_id.clone(),
                    ingress_key_id: format!("producer-ingress-{}", member.validator_id.0),
                    share_index: u8::try_from(index + 1).unwrap(),
                    key_bytes: public.as_bytes().to_vec(),
                }
            })
            .collect();
        let registry = IngressKemKeyRegistry {
            registry_version: INGRESS_KEM_REGISTRY_VERSION,
            chain_id: crate::synergy_types::ChainId::synergy_testnet_v3(),
            network_id: NetworkId::fresh_posy_testnet_v3(),
            protocol_version: POSY_SIMPLIFIED_PROTOCOL_VERSION.to_string(),
            epoch: Epoch(0),
            target_height,
            assigned_cluster_id,
            records,
        };
        registry.validate_shape().unwrap();
        let root = temp_root(label);
        TestEnvironment {
            configuration: SimplifiedTargetAdmissionConfiguration {
                epoch_context,
                validator_set: etdag_fixture.validator_set,
                cluster_map: etdag_fixture.cluster_map,
                verifier: etdag_fixture.signer.verifier(),
                cryptographic_profile_root: etdag_fixture.context.cryptographic_profile_root,
            },
            local_validator_id: members[0].validator_id.clone(),
            signer: Arc::new(Mutex::new(etdag_fixture.signer)),
            snapshot,
            registry,
            store_path: root.join("producer.json"),
            journal_path: root.join("local-journal.json"),
            remote_journal: EtdagSafetyJournal::at_path(root.join("remote-journal.json")),
            coordinator: EtdagProtectedInputCoordinator::at_paths(
                root.join("admission.json"),
                root.join("protected.json"),
            ),
        }
    }

    fn vote_request(
        outputs: &[SimplifiedTargetAdmissionOutput],
    ) -> SimplifiedTargetAdmissionVoteRequest {
        outputs
            .iter()
            .find_map(|output| match output {
                SimplifiedTargetAdmissionOutput::Vote(request) => Some(request.clone()),
                SimplifiedTargetAdmissionOutput::CertifiedPackage(_) => None,
            })
            .expect("local target-admission vote")
    }

    fn drive_to_certificate(
        environment: &TestEnvironment,
        producer: &mut SimplifiedTargetAdmissionProducer,
        initial: SimplifiedTargetAdmissionVoteRequest,
    ) -> TargetAdmissionPackage {
        let members = environment
            .configuration
            .validator_set
            .active_for_epoch(initial.context.epoch)
            .active_for_cluster(initial.context.assigned_cluster_id);
        for member in members
            .iter()
            .filter(|member| member.validator_id != environment.local_validator_id)
        {
            let vote = sign_target_admission_vote(
                &mut environment.signer.lock().unwrap(),
                &environment.remote_journal,
                &initial.context,
                member,
            )
            .unwrap();
            let request = SimplifiedTargetAdmissionVoteRequest {
                context: initial.context.clone(),
                ingress_kem_registry: initial.ingress_kem_registry.clone(),
                vote,
            };
            let peer = EtdagAuthenticatedIngressPeer {
                validator_id: member.validator_id.clone(),
                validator_uma_id: member.validator_uma_id.clone(),
                consensus_key_id: member.consensus_public_key.key_id.clone(),
            };
            if let Some(SimplifiedTargetAdmissionOutput::CertifiedPackage(package)) =
                producer.handle_authenticated_vote(&peer, &request).unwrap()
            {
                return package;
            }
        }
        panic!("dynamic target-admission quorum did not form")
    }

    #[test]
    fn producer_forms_authenticated_dynamic_certificate_and_installs_it() {
        for count in [5usize, 7usize] {
            let environment = environment(count, &format!("happy-{count}"));
            let mut producer = environment.producer(
                environment.snapshot.clone(),
                Some(environment.registry.clone()),
            );
            let initial = vote_request(&producer.prepare_h3().unwrap());
            let package = drive_to_certificate(&environment, &mut producer, initial.clone());
            package
                .verify_against_parameter_root(
                    &environment.configuration.verifier,
                    &environment.configuration.validator_set,
                    &environment.configuration.cluster_map,
                    environment.configuration.parameter_root().unwrap(),
                )
                .unwrap();
            let expected_quorum = initial
                .context
                .assigned_cluster_validator_count
                .checked_mul(2)
                .unwrap()
                / 3
                + 1;
            assert_eq!(package.certificate.signer_count, expected_quorum);
            assert_eq!(
                environment
                    .coordinator
                    .load_verified_target_admission_context_schedule_neutral(
                        Height(8),
                        &environment.configuration.verifier,
                        &environment.configuration.validator_set,
                        &environment.configuration.cluster_map,
                        environment.configuration.parameter_root().unwrap(),
                    )
                    .unwrap(),
                package.context
            );
        }
    }

    #[test]
    fn producer_rejects_wrong_target_parameter_and_finality_authority() {
        let environment = environment(5, "wrong-authority");
        let mut wrong_parameter = environment.snapshot.clone();
        wrong_parameter.consensus_parameter_root = ConsensusParameterRoot::zero();
        assert!(environment
            .producer(wrong_parameter, Some(environment.registry.clone()))
            .prepare_h3()
            .unwrap_err()
            .contains("FINALITY_AUTHORITY_MISMATCH"));

        let mut wrong_finality = environment.snapshot.clone();
        wrong_finality.canonical_finality_context_digest = EtdagDigest::from_domain_bytes(
            "simplified-target-admission-test-wrong-finality",
            b"valid-but-substituted-digest",
        );
        assert!(environment
            .producer(wrong_finality, Some(environment.registry.clone()))
            .prepare_h3()
            .unwrap_err()
            .contains("FINALITY_AUTHORITY_MISMATCH"));

        let mut wrong_finalized_record = environment.snapshot.clone();
        wrong_finalized_record.finalized =
            FinalizedBlockRecord::from_quorum_certificate(QuorumCertificateReference {
                height: wrong_finalized_record.finalized.height,
                block_id: wrong_finalized_record.finalized.block_id.clone(),
                qc_id: Hash::from_domain_bytes(
                    "simplified-target-admission-test-wrong-finality",
                    b"substituted-qc",
                ),
            })
            .unwrap();
        assert!(environment
            .producer(wrong_finalized_record, Some(environment.registry.clone()),)
            .prepare_h3()
            .unwrap_err()
            .contains("FINALITY_AUTHORITY_MISMATCH"));

        let mut producer = environment.producer(
            environment.snapshot.clone(),
            Some(environment.registry.clone()),
        );
        let mut request = vote_request(&producer.prepare_h3().unwrap());
        request.context.target_height = Height(9);
        let member = environment
            .configuration
            .validator_set
            .validators
            .iter()
            .find(|validator| validator.validator_id == request.vote.signer_validator_id)
            .unwrap();
        let peer = EtdagAuthenticatedIngressPeer {
            validator_id: member.validator_id.clone(),
            validator_uma_id: member.validator_uma_id.clone(),
            consensus_key_id: member.consensus_public_key.key_id.clone(),
        };
        assert!(producer
            .handle_authenticated_vote(&peer, &request)
            .unwrap_err()
            .contains("CONTEXT_NOT_READY"));
    }

    #[test]
    fn producer_restart_reuses_exact_vote_and_completed_package() {
        let environment = environment(5, "restart");
        let mut first = environment.producer(
            environment.snapshot.clone(),
            Some(environment.registry.clone()),
        );
        let first_vote = vote_request(&first.prepare_h3().unwrap());
        drop(first);

        let mut restarted = environment.producer(
            environment.snapshot.clone(),
            Some(environment.registry.clone()),
        );
        assert_eq!(vote_request(&restarted.prepare_h3().unwrap()), first_vote);
        let package = drive_to_certificate(&environment, &mut restarted, first_vote);
        drop(restarted);

        let mut completed = environment.producer(
            environment.snapshot.clone(),
            Some(environment.registry.clone()),
        );
        assert_eq!(
            completed.prepare_h3().unwrap(),
            vec![SimplifiedTargetAdmissionOutput::CertifiedPackage(package)]
        );
    }

    #[test]
    fn producer_fails_closed_without_exact_public_ingress_registry() {
        let environment = environment(5, "missing-registry");
        let mut producer = environment.producer(environment.snapshot.clone(), None);
        assert!(producer
            .prepare_h3()
            .unwrap_err()
            .contains("MISSING_INGRESS_REGISTRY"));
        assert!(!environment.store_path.exists());
    }

    #[test]
    fn durable_public_registry_source_is_exact_canonical_and_target_bound() {
        let environment = environment(5, "durable-registry-source");
        let root = temp_root("durable-registry-artifacts");
        let epoch_root = environment.configuration.epoch_context.root().unwrap();
        let mut source =
            DurableSimplifiedIngressKemRegistrySource::at_directory(&root, epoch_root).unwrap();
        let epoch = environment.registry.epoch;
        let target_height = environment.registry.target_height;
        let assigned_cluster_id = environment.registry.assigned_cluster_id;
        assert!(source
            .registry_for_target(epoch, target_height, assigned_cluster_id)
            .unwrap()
            .is_none());

        let artifact = SimplifiedIngressKemRegistryArtifact {
            format: SIMPLIFIED_INGRESS_KEM_REGISTRY_ARTIFACT_FORMAT.to_string(),
            epoch_context_root: epoch_root,
            epoch,
            target_height,
            assigned_cluster_id,
            registry_root: environment.registry.root().unwrap(),
            registry: environment.registry.clone(),
        };
        let path = source.artifact_path(epoch, target_height, assigned_cluster_id);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        let canonical = serde_json::to_vec(&artifact).unwrap();
        fs::write(&path, &canonical).unwrap();
        assert_eq!(
            source
                .registry_for_target(epoch, target_height, assigned_cluster_id)
                .unwrap(),
            Some(environment.registry.clone())
        );

        let mut noncanonical = canonical.clone();
        noncanonical.push(b'\n');
        fs::write(&path, noncanonical).unwrap();
        assert!(source
            .registry_for_target(epoch, target_height, assigned_cluster_id)
            .unwrap_err()
            .contains("not canonical"));

        let mut substituted = artifact;
        substituted.epoch_context_root = Hash::from_domain_bytes(
            "simplified-target-admission-test",
            b"substituted-epoch-root",
        );
        fs::write(&path, serde_json::to_vec(&substituted).unwrap()).unwrap();
        assert!(source
            .registry_for_target(epoch, target_height, assigned_cluster_id)
            .unwrap_err()
            .contains("invalid simplified ingress KEM registry artifact"));
    }

    #[test]
    fn durable_public_registry_writer_is_canonical_and_no_clobber() {
        let environment = environment(5, "durable-registry-writer");
        let root = temp_root("durable-registry-writer");
        let epoch_root = environment.configuration.epoch_context.root().unwrap();
        let mut source =
            DurableSimplifiedIngressKemRegistrySource::at_directory(&root, epoch_root).unwrap();
        let path = source.artifact_path(
            environment.registry.epoch,
            environment.registry.target_height,
            environment.registry.assigned_cluster_id,
        );
        fs::create_dir_all(path.parent().unwrap()).unwrap();

        let artifact = write_simplified_ingress_kem_registry_artifact(
            &path,
            epoch_root,
            &environment.registry,
        )
        .unwrap();
        assert_eq!(
            fs::read(&path).unwrap(),
            serde_json::to_vec(&artifact).unwrap()
        );
        assert_eq!(
            source
                .registry_for_target(
                    environment.registry.epoch,
                    environment.registry.target_height,
                    environment.registry.assigned_cluster_id,
                )
                .unwrap(),
            Some(environment.registry.clone())
        );
        assert!(write_simplified_ingress_kem_registry_artifact(
            &path,
            epoch_root,
            &environment.registry,
        )
        .unwrap_err()
        .contains("refusing to overwrite"));

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn producer_defers_next_epoch_h3_until_transition_authority_exists() {
        let environment = environment(5, "next-epoch-h3");
        let mut snapshot = environment.snapshot.clone();
        snapshot.finalized =
            FinalizedBlockRecord::from_quorum_certificate(QuorumCertificateReference {
                height: Height(98),
                block_id: BlockId::from_hash(Hash::from_domain_bytes(
                    "simplified-target-admission-test",
                    b"finalized-ninety-eight",
                )),
                qc_id: Hash::from_domain_bytes(
                    "simplified-target-admission-test",
                    b"finalized-ninety-eight-qc",
                ),
            })
            .unwrap();
        snapshot.canonical_finality_context_digest =
            simplified_protected_finality_context_digest_from_state_root(
                &environment.configuration.epoch_context,
                &snapshot.finalized,
                snapshot.finalized_execution_state_root,
                &environment.configuration.validator_set,
                &environment.configuration.cluster_map,
            )
            .unwrap();
        let mut producer = environment.producer(snapshot, None);
        assert!(producer.prepare_h3().unwrap().is_empty());
        assert!(!environment.store_path.exists());
    }

    #[test]
    fn process_wide_handler_routes_authenticated_ingress_and_cleans_up() {
        let _guard = TARGET_ADMISSION_HANDLER_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let _ = remove_simplified_target_admission_producer_handler();
        let environment = environment(5, "process-handler");
        let mut producer = environment.producer(
            environment.snapshot.clone(),
            Some(environment.registry.clone()),
        );
        let initial = vote_request(&producer.prepare_h3().unwrap());
        install_simplified_target_admission_producer_handler(producer).unwrap();

        let members = environment
            .configuration
            .validator_set
            .active_for_epoch(initial.context.epoch)
            .active_for_cluster(initial.context.assigned_cluster_id);
        let remote = members
            .iter()
            .find(|member| member.validator_id != environment.local_validator_id)
            .unwrap();
        let remote_vote = sign_target_admission_vote(
            &mut environment.signer.lock().unwrap(),
            &environment.remote_journal,
            &initial.context,
            remote,
        )
        .unwrap();
        let request = SimplifiedTargetAdmissionVoteRequest {
            context: initial.context.clone(),
            ingress_kem_registry: initial.ingress_kem_registry.clone(),
            vote: remote_vote,
        };
        let remote_peer = EtdagAuthenticatedIngressPeer {
            validator_id: remote.validator_id.clone(),
            validator_uma_id: remote.validator_uma_id.clone(),
            consensus_key_id: remote.consensus_public_key.key_id.clone(),
        };

        assert!(
            dispatch_simplified_target_admission_vote(None, request.clone())
                .unwrap_err()
                .contains("authenticated validator peer")
        );
        let wrong_member = members
            .iter()
            .find(|member| {
                member.validator_id != environment.local_validator_id
                    && member.validator_id != remote.validator_id
            })
            .unwrap();
        let wrong_peer = EtdagAuthenticatedIngressPeer {
            validator_id: wrong_member.validator_id.clone(),
            validator_uma_id: wrong_member.validator_uma_id.clone(),
            consensus_key_id: wrong_member.consensus_public_key.key_id.clone(),
        };
        assert!(
            dispatch_simplified_target_admission_vote(Some(wrong_peer), request.clone(),)
                .unwrap_err()
                .contains("UNTRUSTED_PEER")
        );

        let mut bad_signature = request.clone();
        bad_signature.vote.signature.signature_bytes[0] ^= 0x01;
        assert!(dispatch_simplified_target_admission_vote(
            Some(remote_peer.clone()),
            bad_signature,
        )
        .is_err());
        assert!(
            dispatch_simplified_target_admission_vote(Some(remote_peer), request,)
                .unwrap()
                .is_none()
        );

        let mut certified = None;
        for member in members.iter().filter(|member| {
            member.validator_id != environment.local_validator_id
                && member.validator_id != remote.validator_id
        }) {
            let vote = sign_target_admission_vote(
                &mut environment.signer.lock().unwrap(),
                &environment.remote_journal,
                &initial.context,
                member,
            )
            .unwrap();
            let output = dispatch_simplified_target_admission_vote(
                Some(EtdagAuthenticatedIngressPeer {
                    validator_id: member.validator_id.clone(),
                    validator_uma_id: member.validator_uma_id.clone(),
                    consensus_key_id: member.consensus_public_key.key_id.clone(),
                }),
                SimplifiedTargetAdmissionVoteRequest {
                    context: initial.context.clone(),
                    ingress_kem_registry: initial.ingress_kem_registry.clone(),
                    vote,
                },
            )
            .unwrap();
            if let Some(SimplifiedTargetAdmissionOutput::CertifiedPackage(package)) = output {
                certified = Some(package);
                break;
            }
        }
        let package = certified.expect("authenticated global routing must form a certificate");
        let relay = &members[0];
        assert_eq!(
            dispatch_simplified_target_admission_package(
                Some(EtdagAuthenticatedIngressPeer {
                    validator_id: relay.validator_id.clone(),
                    validator_uma_id: relay.validator_uma_id.clone(),
                    consensus_key_id: relay.consensus_public_key.key_id.clone(),
                }),
                package.clone(),
            )
            .unwrap(),
            SimplifiedTargetAdmissionOutput::CertifiedPackage(package.clone())
        );

        assert!(remove_simplified_target_admission_producer_handler()
            .unwrap()
            .is_some());
        assert!(dispatch_simplified_target_admission_package(
            Some(EtdagAuthenticatedIngressPeer {
                validator_id: relay.validator_id.clone(),
                validator_uma_id: relay.validator_uma_id.clone(),
                consensus_key_id: relay.consensus_public_key.key_id.clone(),
            }),
            package,
        )
        .unwrap_err()
        .contains("not installed"));
    }
}
