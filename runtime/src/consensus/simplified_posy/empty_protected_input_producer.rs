//! Distributed, restart-safe production of certified empty ETDAG inputs.
//!
//! This worker exists only for a target that already has a fully verified
//! target-admission package. It never creates a core/plaintext fallback and it
//! never bypasses VAC, DCC, BVC, BOC, ML-DSA-65, or safety-journal checks.

use super::{
    SimplifiedEpochContext, SimplifiedTargetAdmissionFinalityAuthority,
    SimplifiedTargetAdmissionFinalitySnapshot, POSY_SIMPLIFIED_PROTOCOL_VERSION,
};
use crate::consensus_parameters::ConsensusParameterRoot;
use crate::crypto::aegis_pqvm::{AegisPqvmSigner, AegisPqvmVerifier};
use crate::etdag::{
    build_batch_candidate, build_dag_cut_candidate, certificate_quorum,
    decrypt_share_transcript_root, form_etdag_certificate, sign_etdag_vote, sign_vac_vote,
    sign_vertex, verify_etdag_vote, BatchCandidate, BatchOrderCertificate,
    BatchValidationCertificate, CertifiedProtectedInputArtifact, CertifiedVertex, DagCutCandidate,
    DagCutCertificate, EtdagAuthenticatedIngressPeer, EtdagDigest, EtdagParameters, EtdagPhase,
    EtdagProtectedInputCoordinator, EtdagSafetyJournal, EtdagSignedVote, EtdagVoteTranscript,
    ProtectedBlockInput, PublicOrderedReveal, TargetAdmissionPackage, TransactionVertex,
    VertexKind,
};
use crate::synergy_types::{
    ClusterMap, Hash, Height, Round, ValidatorId, ValidatorRecord, ValidatorSet, ValidatorStatus,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

pub const SIMPLIFIED_EMPTY_ETDAG_STORE_FORMAT: &str =
    "synergy-posy-simplified-empty-etdag-producer-v1";
pub const MAX_SIMPLIFIED_EMPTY_ETDAG_ENTRIES: usize = 4;
pub const MAX_SIMPLIFIED_EMPTY_ETDAG_STORE_BYTES: usize = 16 * 1024 * 1024;
const SIMPLIFIED_EMPTY_ETDAG_STORE_DIRECTORY: &str = "data/posy-v3-empty-etdag";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub enum SimplifiedEmptyEtdagMessage {
    Marker {
        target_height: Height,
        admission_binding_digest: EtdagDigest,
        vertex: TransactionVertex,
    },
    VacVote {
        target_height: Height,
        admission_binding_digest: EtdagDigest,
        vertex_digest: EtdagDigest,
        vote: EtdagSignedVote,
    },
    DccCandidate {
        target_height: Height,
        admission_binding_digest: EtdagDigest,
        certified_vertices: BTreeMap<EtdagDigest, CertifiedVertex>,
        marker_digests: Vec<EtdagDigest>,
        candidate: DagCutCandidate,
    },
    DccVote {
        target_height: Height,
        admission_binding_digest: EtdagDigest,
        candidate_digest: EtdagDigest,
        vote: EtdagSignedVote,
    },
    BvcCandidate {
        target_height: Height,
        admission_binding_digest: EtdagDigest,
        certified_vertices: BTreeMap<EtdagDigest, CertifiedVertex>,
        dcc: DagCutCertificate,
        batch_candidate: BatchCandidate,
    },
    BvcVote {
        target_height: Height,
        admission_binding_digest: EtdagDigest,
        candidate_digest: EtdagDigest,
        vote: EtdagSignedVote,
    },
    BocCandidate {
        target_height: Height,
        admission_binding_digest: EtdagDigest,
        certified_vertices: BTreeMap<EtdagDigest, CertifiedVertex>,
        dcc: DagCutCertificate,
        bvc: BatchValidationCertificate,
    },
    BocVote {
        target_height: Height,
        admission_binding_digest: EtdagDigest,
        candidate_digest: EtdagDigest,
        vote: EtdagSignedVote,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SimplifiedEmptyEtdagOutput {
    Assembly(SimplifiedEmptyEtdagMessage),
    CertifiedInput(CertifiedProtectedInputArtifact),
}

#[derive(Clone)]
pub struct SimplifiedEmptyEtdagConfiguration {
    pub epoch_context: SimplifiedEpochContext,
    pub validator_set: ValidatorSet,
    pub cluster_map: ClusterMap,
    pub verifier: AegisPqvmVerifier,
    pub etdag_parameters: EtdagParameters,
    pub consensus_parameter_root: ConsensusParameterRoot,
}

impl SimplifiedEmptyEtdagConfiguration {
    fn validate(&self) -> Result<(), String> {
        let active = self
            .validator_set
            .active_for_epoch(self.epoch_context.epoch);
        self.epoch_context.validate_against(&active)?;
        self.etdag_parameters.validate()?;
        if self.validator_set.epoch != self.epoch_context.epoch
            || self.cluster_map.epoch != self.epoch_context.epoch
            || self.consensus_parameter_root.is_zero()
            || self.consensus_parameter_root.to_hex() != self.epoch_context.consensus_parameter_root
            || self.cluster_map
                != ClusterMap::derive_from_finalized_epoch_seed(
                    &active,
                    self.epoch_context.finalized_epoch_seed_root,
                )?
        {
            return Err("invalid simplified empty-ETDAG configuration".to_string());
        }
        self.cluster_map
            .validate_complete_balanced_assignment(&active)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct EmptyEtdagEntry {
    admission_package: TargetAdmissionPackage,
    source_finality_context_digest: EtdagDigest,
    markers: BTreeMap<EtdagDigest, TransactionVertex>,
    vac_votes: BTreeMap<EtdagDigest, Vec<EtdagSignedVote>>,
    certified_vertices: BTreeMap<EtdagDigest, CertifiedVertex>,
    dcc_candidate: Option<DagCutCandidate>,
    dcc_votes: Vec<EtdagSignedVote>,
    dcc: Option<DagCutCertificate>,
    batch_candidate: Option<BatchCandidate>,
    bvc_votes: Vec<EtdagSignedVote>,
    bvc: Option<BatchValidationCertificate>,
    boc_votes: Vec<EtdagSignedVote>,
    boc: Option<BatchOrderCertificate>,
    certified_artifact: Option<CertifiedProtectedInputArtifact>,
}

impl EmptyEtdagEntry {
    fn new(
        admission_package: TargetAdmissionPackage,
        source_finality_context_digest: EtdagDigest,
    ) -> Self {
        Self {
            admission_package,
            source_finality_context_digest,
            markers: BTreeMap::new(),
            vac_votes: BTreeMap::new(),
            certified_vertices: BTreeMap::new(),
            dcc_candidate: None,
            dcc_votes: Vec::new(),
            dcc: None,
            batch_candidate: None,
            bvc_votes: Vec::new(),
            bvc: None,
            boc_votes: Vec::new(),
            boc: None,
            certified_artifact: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct EmptyEtdagFile {
    format: String,
    entries: BTreeMap<Height, EmptyEtdagEntry>,
}

impl Default for EmptyEtdagFile {
    fn default() -> Self {
        Self {
            format: SIMPLIFIED_EMPTY_ETDAG_STORE_FORMAT.to_string(),
            entries: BTreeMap::new(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct DurableSimplifiedEmptyEtdagStore {
    path: PathBuf,
}

static EMPTY_ETDAG_STORE_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

impl DurableSimplifiedEmptyEtdagStore {
    pub fn for_epoch(epoch_context_root: Hash) -> Result<Self, String> {
        if epoch_context_root.is_zero() {
            return Err("empty-ETDAG store epoch root is missing".to_string());
        }
        Ok(Self::at_path(
            crate::utils::resolve_data_path(SIMPLIFIED_EMPTY_ETDAG_STORE_DIRECTORY)
                .join(format!("{}.json", epoch_context_root.to_hex())),
        ))
    }

    pub fn at_path(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    fn load(&self) -> Result<EmptyEtdagFile, String> {
        let _guard = EMPTY_ETDAG_STORE_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .map_err(|_| "empty-ETDAG store lock poisoned".to_string())?;
        self.load_unlocked()
    }

    fn persist(&self, state: &EmptyEtdagFile) -> Result<(), String> {
        let _guard = EMPTY_ETDAG_STORE_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .map_err(|_| "empty-ETDAG store lock poisoned".to_string())?;
        self.persist_unlocked(state)
    }

    fn load_unlocked(&self) -> Result<EmptyEtdagFile, String> {
        if !self.path.exists() {
            return Ok(EmptyEtdagFile::default());
        }
        let bytes = fs::read(&self.path)
            .map_err(|error| format!("read empty-ETDAG store {}: {error}", self.path.display()))?;
        if bytes.is_empty() || bytes.len() > MAX_SIMPLIFIED_EMPTY_ETDAG_STORE_BYTES {
            return Err("empty-ETDAG store violates its decode bound".to_string());
        }
        let state: EmptyEtdagFile = serde_json::from_slice(&bytes)
            .map_err(|error| format!("parse empty-ETDAG store: {error}"))?;
        if state.format != SIMPLIFIED_EMPTY_ETDAG_STORE_FORMAT
            || state.entries.len() > MAX_SIMPLIFIED_EMPTY_ETDAG_ENTRIES
            || serde_json::to_vec(&state)
                .map_err(|error| format!("canonicalize empty-ETDAG store: {error}"))?
                != bytes
        {
            return Err("invalid empty-ETDAG store".to_string());
        }
        Ok(state)
    }

    fn persist_unlocked(&self, state: &EmptyEtdagFile) -> Result<(), String> {
        if state.format != SIMPLIFIED_EMPTY_ETDAG_STORE_FORMAT
            || state.entries.len() > MAX_SIMPLIFIED_EMPTY_ETDAG_ENTRIES
        {
            return Err("invalid empty-ETDAG store state".to_string());
        }
        let bytes = serde_json::to_vec(state)
            .map_err(|error| format!("serialize empty-ETDAG store: {error}"))?;
        if bytes.len() > MAX_SIMPLIFIED_EMPTY_ETDAG_STORE_BYTES {
            return Err("empty-ETDAG store exceeds its bound".to_string());
        }
        let parent = self
            .path
            .parent()
            .ok_or_else(|| "empty-ETDAG store has no parent".to_string())?;
        fs::create_dir_all(parent)
            .map_err(|error| format!("create empty-ETDAG store directory: {error}"))?;
        let name = self
            .path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| "empty-ETDAG store has no filename".to_string())?;
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
                .map_err(|error| format!("create empty-ETDAG temp file: {error}"))?;
            file.write_all(&bytes)
                .map_err(|error| format!("write empty-ETDAG store: {error}"))?;
            file.sync_all()
                .map_err(|error| format!("fsync empty-ETDAG store: {error}"))?;
            fs::rename(&temp, &self.path)
                .map_err(|error| format!("replace empty-ETDAG store: {error}"))?;
            OpenOptions::new()
                .read(true)
                .open(parent)
                .and_then(|directory| directory.sync_all())
                .map_err(|error| format!("fsync empty-ETDAG directory: {error}"))
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temp);
        }
        result
    }
}

fn current_unix_nanos() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default()
}

pub struct SimplifiedEmptyEtdagProducer {
    configuration: SimplifiedEmptyEtdagConfiguration,
    local_validator_id: ValidatorId,
    signer: Arc<Mutex<AegisPqvmSigner>>,
    safety_journal: EtdagSafetyJournal,
    store: DurableSimplifiedEmptyEtdagStore,
    coordinator: EtdagProtectedInputCoordinator,
    finality_authority: Box<dyn SimplifiedTargetAdmissionFinalityAuthority>,
    pending_outputs: Vec<SimplifiedEmptyEtdagOutput>,
}

impl SimplifiedEmptyEtdagProducer {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        configuration: SimplifiedEmptyEtdagConfiguration,
        local_validator_id: ValidatorId,
        signer: Arc<Mutex<AegisPqvmSigner>>,
        safety_journal: EtdagSafetyJournal,
        store: DurableSimplifiedEmptyEtdagStore,
        coordinator: EtdagProtectedInputCoordinator,
        finality_authority: Box<dyn SimplifiedTargetAdmissionFinalityAuthority>,
    ) -> Result<Self, String> {
        configuration.validate()?;
        let local = configuration
            .validator_set
            .validators
            .iter()
            .find(|validator| validator.validator_id == local_validator_id)
            .ok_or_else(|| "empty-ETDAG local validator is outside the frozen set".to_string())?;
        if local.status != ValidatorStatus::Active
            || !local.is_active_for_epoch(configuration.epoch_context.epoch)
        {
            return Err("empty-ETDAG local validator is inactive".to_string());
        }
        Ok(Self {
            configuration,
            local_validator_id,
            signer,
            safety_journal,
            store,
            coordinator,
            finality_authority,
            pending_outputs: Vec::new(),
        })
    }

    pub fn new_process_wide(
        configuration: SimplifiedEmptyEtdagConfiguration,
        local_validator_id: ValidatorId,
        signer: Arc<Mutex<AegisPqvmSigner>>,
        finality_authority: Box<dyn SimplifiedTargetAdmissionFinalityAuthority>,
    ) -> Result<Self, String> {
        let epoch_root = configuration.epoch_context.root()?;
        Self::new(
            configuration,
            local_validator_id,
            signer,
            EtdagSafetyJournal::process_wide(),
            DurableSimplifiedEmptyEtdagStore::for_epoch(epoch_root)?,
            EtdagProtectedInputCoordinator::process_wide(),
            finality_authority,
        )
    }

    pub fn prepare(&mut self) -> Result<(), String> {
        let authority = self.finality_authority.current_finalized_authority()?;
        self.validate_authority(&authority)?;
        let targets = if authority.finalized.height == Height(0)
            && authority.finalized.quorum_certificate_reference().is_none()
            && self.configuration.epoch_context.epoch_start_height == Height(1)
        {
            vec![Height(1), Height(2), Height(3)]
        } else {
            vec![Height(
                authority
                    .finalized
                    .height
                    .0
                    .checked_add(3)
                    .ok_or_else(|| "empty-ETDAG H+3 height overflow".to_string())?,
            )]
        };
        let mut state = self.store.load()?;
        state
            .entries
            .retain(|height, _| height.0 > authority.finalized.height.0);
        for target_height in targets {
            if target_height.0 > self.configuration.epoch_context.epoch_end_height.0 {
                continue;
            }
            let package = match self
                .coordinator
                .load_verified_admission_package_schedule_neutral(
                    target_height,
                    &self.configuration.verifier,
                    &self.configuration.validator_set,
                    &self.configuration.cluster_map,
                    self.configuration.consensus_parameter_root,
                ) {
                Ok(package) => package,
                Err(error) if error.contains("ETDAG_PROTECTED_INPUT_NOT_READY") => continue,
                Err(error) => return Err(error),
            };
            self.validate_package_authority(&package, &authority)?;
            Self::ensure_entry(
                &mut state,
                package,
                authority.canonical_finality_context_digest.clone(),
            )?;
            self.prepare_local_marker(&mut state, target_height)?;
            self.advance(&mut state, target_height, &authority)?;
        }
        self.store.persist(&state)
    }

    pub fn drain_outputs(&mut self) -> Vec<SimplifiedEmptyEtdagOutput> {
        std::mem::take(&mut self.pending_outputs)
    }

    pub fn handle_authenticated_message(
        &mut self,
        peer: &EtdagAuthenticatedIngressPeer,
        message: SimplifiedEmptyEtdagMessage,
    ) -> Result<(), String> {
        self.authorize_active_peer(peer)?;
        let authority = self.finality_authority.current_finalized_authority()?;
        self.validate_authority(&authority)?;
        let mut state = self.store.load()?;
        match message {
            SimplifiedEmptyEtdagMessage::Marker {
                target_height,
                admission_binding_digest,
                vertex,
            } => self.handle_marker(
                &mut state,
                peer,
                target_height,
                &admission_binding_digest,
                vertex,
            )?,
            SimplifiedEmptyEtdagMessage::VacVote {
                target_height,
                admission_binding_digest,
                vertex_digest,
                vote,
            } => self.handle_vac_vote(
                &mut state,
                peer,
                target_height,
                &admission_binding_digest,
                &vertex_digest,
                vote,
            )?,
            SimplifiedEmptyEtdagMessage::DccCandidate {
                target_height,
                admission_binding_digest,
                certified_vertices,
                marker_digests,
                candidate,
            } => self.handle_dcc_candidate(
                &mut state,
                peer,
                target_height,
                &admission_binding_digest,
                certified_vertices,
                marker_digests,
                candidate,
            )?,
            SimplifiedEmptyEtdagMessage::DccVote {
                target_height,
                admission_binding_digest,
                candidate_digest,
                vote,
            } => self.handle_phase_vote(
                &mut state,
                peer,
                target_height,
                &admission_binding_digest,
                EtdagPhase::Dcc,
                &candidate_digest,
                vote,
            )?,
            SimplifiedEmptyEtdagMessage::BvcCandidate {
                target_height,
                admission_binding_digest,
                certified_vertices,
                dcc,
                batch_candidate,
            } => self.handle_bvc_candidate(
                &mut state,
                peer,
                target_height,
                &admission_binding_digest,
                certified_vertices,
                dcc,
                batch_candidate,
                &authority,
            )?,
            SimplifiedEmptyEtdagMessage::BvcVote {
                target_height,
                admission_binding_digest,
                candidate_digest,
                vote,
            } => self.handle_phase_vote(
                &mut state,
                peer,
                target_height,
                &admission_binding_digest,
                EtdagPhase::BatchValidate,
                &candidate_digest,
                vote,
            )?,
            SimplifiedEmptyEtdagMessage::BocCandidate {
                target_height,
                admission_binding_digest,
                certified_vertices,
                dcc,
                bvc,
            } => self.handle_boc_candidate(
                &mut state,
                peer,
                target_height,
                &admission_binding_digest,
                certified_vertices,
                dcc,
                bvc,
            )?,
            SimplifiedEmptyEtdagMessage::BocVote {
                target_height,
                admission_binding_digest,
                candidate_digest,
                vote,
            } => self.handle_phase_vote(
                &mut state,
                peer,
                target_height,
                &admission_binding_digest,
                EtdagPhase::BatchFinality,
                &candidate_digest,
                vote,
            )?,
        }
        let heights = state.entries.keys().copied().collect::<Vec<_>>();
        for height in heights {
            self.advance(&mut state, height, &authority)?;
        }
        self.store.persist(&state)
    }

    fn validate_authority(
        &self,
        authority: &SimplifiedTargetAdmissionFinalitySnapshot,
    ) -> Result<(), String> {
        authority.finalized.validate()?;
        authority
            .canonical_finality_context_digest
            .validate("empty-ETDAG finality digest")?;
        if authority.epoch_context_root != self.configuration.epoch_context.root()?
            || authority.consensus_parameter_root != self.configuration.consensus_parameter_root
            || authority.canonical_finality_context_digest.is_zero()
        {
            return Err("EMPTY_ETDAG_FINALITY_AUTHORITY_MISMATCH".to_string());
        }
        Ok(())
    }

    fn validate_package_authority(
        &self,
        package: &TargetAdmissionPackage,
        authority: &SimplifiedTargetAdmissionFinalitySnapshot,
    ) -> Result<(), String> {
        package.verify_against_parameter_root(
            &self.configuration.verifier,
            &self.configuration.validator_set,
            &self.configuration.cluster_map,
            self.configuration.consensus_parameter_root,
        )?;
        if package.context.source_finalized_height != authority.finalized.height
            || package.context.source_finality_context_root
                != crate::etdag::target_admission_source_finality_root(
                    &authority.canonical_finality_context_digest,
                )?
        {
            return Err("EMPTY_ETDAG_ADMISSION_FINALITY_MISMATCH".to_string());
        }
        Ok(())
    }

    fn ensure_entry(
        state: &mut EmptyEtdagFile,
        package: TargetAdmissionPackage,
        source_finality_context_digest: EtdagDigest,
    ) -> Result<(), String> {
        source_finality_context_digest.validate("empty-ETDAG source finality digest")?;
        if crate::etdag::target_admission_source_finality_root(&source_finality_context_digest)?
            != package.context.source_finality_context_root
        {
            return Err("EMPTY_ETDAG_ADMISSION_FINALITY_MISMATCH".to_string());
        }
        let height = package.context.target_height;
        if let Some(existing) = state.entries.get(&height) {
            if existing.admission_package.admission_binding_digest()?
                == package.admission_binding_digest()?
                && existing.source_finality_context_digest == source_finality_context_digest
            {
                return Ok(());
            }
            return Err("EMPTY_ETDAG_ADMISSION_CONFLICT".to_string());
        }
        if state.entries.len() >= MAX_SIMPLIFIED_EMPTY_ETDAG_ENTRIES {
            return Err("EMPTY_ETDAG_STORE_FULL".to_string());
        }
        state.entries.insert(
            height,
            EmptyEtdagEntry::new(package, source_finality_context_digest),
        );
        Ok(())
    }

    fn entry_mut<'a>(
        state: &'a mut EmptyEtdagFile,
        target_height: Height,
        binding: &EtdagDigest,
    ) -> Result<&'a mut EmptyEtdagEntry, String> {
        let entry = state
            .entries
            .get_mut(&target_height)
            .ok_or_else(|| "EMPTY_ETDAG_ADMISSION_NOT_READY".to_string())?;
        if &entry.admission_package.admission_binding_digest()? != binding {
            return Err("EMPTY_ETDAG_ADMISSION_BINDING_MISMATCH".to_string());
        }
        Ok(entry)
    }

    fn authorize_active_peer(&self, peer: &EtdagAuthenticatedIngressPeer) -> Result<(), String> {
        let validator = self
            .configuration
            .validator_set
            .validators
            .iter()
            .find(|validator| validator.validator_id == peer.validator_id)
            .ok_or_else(|| "EMPTY_ETDAG_UNTRUSTED_PEER".to_string())?;
        if validator.status != ValidatorStatus::Active
            || !validator.is_active_for_epoch(self.configuration.epoch_context.epoch)
            || validator.validator_uma_id != peer.validator_uma_id
            || validator.consensus_public_key.key_id != peer.consensus_key_id
        {
            return Err("EMPTY_ETDAG_UNTRUSTED_PEER".to_string());
        }
        Ok(())
    }

    fn authorize_vote_peer(
        &self,
        peer: &EtdagAuthenticatedIngressPeer,
        vote: &EtdagSignedVote,
    ) -> Result<(), String> {
        if peer.validator_id != vote.signer_validator_id
            || peer.consensus_key_id != vote.signer_key_id
        {
            return Err("EMPTY_ETDAG_UNTRUSTED_VOTE_PEER".to_string());
        }
        self.authorize_active_peer(peer)
    }

    fn assembler_for(&self, height: Height) -> Result<&ValidatorId, String> {
        self.configuration.epoch_context.scheduled_owner(height)
    }

    fn local_member(
        &self,
        context: &crate::etdag::TargetAdmissionContext,
    ) -> Option<ValidatorRecord> {
        self.configuration
            .validator_set
            .active_for_epoch(context.epoch)
            .active_for_cluster(context.assigned_cluster_id)
            .into_iter()
            .find(|validator| validator.validator_id == self.local_validator_id)
    }

    fn empty_capsule_root(
        context: &crate::etdag::TargetAdmissionContext,
        author: &ValidatorId,
    ) -> Result<EtdagDigest, String> {
        EtdagDigest::from_canonical(
            "PoSy/ETDAG/EmptyCapsuleRoot/v3",
            &(context.root()?, author.clone()),
        )
    }

    fn vote_transcript(
        context: &crate::etdag::TargetAdmissionContext,
        phase: EtdagPhase,
        candidate_digest: EtdagDigest,
    ) -> Result<EtdagVoteTranscript, String> {
        let transcript = EtdagVoteTranscript {
            phase,
            chain_id: context.chain_id,
            network_id: context.network_id.clone(),
            protocol_version: POSY_SIMPLIFIED_PROTOCOL_VERSION.to_string(),
            profile_id: crate::etdag::ETDAG_PROFILE_ID.to_string(),
            epoch: context.epoch,
            target_height: context.target_height,
            target_context_root: context.root()?,
            assigned_cluster_id: context.assigned_cluster_id,
            lane_id: crate::etdag::ETDAG_LANE_ID.to_string(),
            round: Round(0),
            candidate_digest,
            highest_prepared_bvc_digest: None,
        };
        transcript.validate_against(context)?;
        Ok(transcript)
    }

    fn install_vote(votes: &mut Vec<EtdagSignedVote>, vote: EtdagSignedVote) -> Result<(), String> {
        if let Some(existing) = votes
            .iter()
            .find(|existing| existing.signer_validator_id == vote.signer_validator_id)
        {
            if existing == &vote {
                return Ok(());
            }
            return Err("EMPTY_ETDAG_VOTE_CONFLICT".to_string());
        }
        votes.push(vote);
        votes.sort_by(|left, right| left.signer_validator_id.cmp(&right.signer_validator_id));
        Ok(())
    }

    fn validate_empty_marker(
        &self,
        context: &crate::etdag::TargetAdmissionContext,
        vertex: &TransactionVertex,
    ) -> Result<(), String> {
        vertex.validate(
            &self.configuration.verifier,
            context,
            &self.configuration.validator_set,
        )?;
        if vertex.kind != VertexKind::CutoffMarker
            || vertex.dag_round != 0
            || !vertex.parent_certified_vertex_digests.is_empty()
            || !vertex.envelopes.is_empty()
            || vertex.cutoff_vc_context_root != Some(context.source_finality_context_root)
            || vertex.capsule_root
                != Self::empty_capsule_root(context, &vertex.author_validator_id)?
        {
            return Err("EMPTY_ETDAG_NONCANONICAL_MARKER".to_string());
        }
        Ok(())
    }

    fn prepare_local_marker(
        &mut self,
        state: &mut EmptyEtdagFile,
        target_height: Height,
    ) -> Result<(), String> {
        let (context, binding) = {
            let entry = state
                .entries
                .get(&target_height)
                .ok_or_else(|| "EMPTY_ETDAG_ADMISSION_NOT_READY".to_string())?;
            (
                entry.admission_package.context.clone(),
                entry.admission_package.admission_binding_digest()?,
            )
        };
        let Some(local) = self.local_member(&context) else {
            return Ok(());
        };
        let existing = state.entries[&target_height]
            .markers
            .values()
            .find(|vertex| vertex.author_validator_id == self.local_validator_id)
            .cloned();
        let vertex = match existing {
            Some(vertex) => vertex,
            None => {
                let mut signer = self
                    .signer
                    .lock()
                    .map_err(|_| "empty-ETDAG signer lock poisoned".to_string())?;
                let vertex = sign_vertex(
                    &mut signer,
                    &context,
                    &local,
                    VertexKind::CutoffMarker,
                    0,
                    target_height.0,
                    Vec::new(),
                    Vec::new(),
                    Self::empty_capsule_root(&context, &local.validator_id)?,
                    Some(context.source_finality_context_root),
                )?;
                drop(signer);
                self.validate_empty_marker(&context, &vertex)?;
                let digest = vertex.digest()?;
                state
                    .entries
                    .get_mut(&target_height)
                    .unwrap()
                    .markers
                    .insert(digest, vertex.clone());
                vertex
            }
        };
        self.pending_outputs
            .push(SimplifiedEmptyEtdagOutput::Assembly(
                SimplifiedEmptyEtdagMessage::Marker {
                    target_height,
                    admission_binding_digest: binding.clone(),
                    vertex: vertex.clone(),
                },
            ));
        self.ensure_local_vac_vote(state, target_height, &binding, vertex.digest()?)
    }

    fn ensure_local_vac_vote(
        &mut self,
        state: &mut EmptyEtdagFile,
        target_height: Height,
        binding: &EtdagDigest,
        vertex_digest: EtdagDigest,
    ) -> Result<(), String> {
        let context = Self::entry_mut(state, target_height, binding)?
            .admission_package
            .context
            .clone();
        let Some(local) = self.local_member(&context) else {
            return Ok(());
        };
        let transcript = Self::vote_transcript(&context, EtdagPhase::Vac, vertex_digest.clone())?;
        let existing = Self::entry_mut(state, target_height, binding)?
            .vac_votes
            .get(&vertex_digest)
            .and_then(|votes| {
                votes
                    .iter()
                    .find(|vote| vote.signer_validator_id == self.local_validator_id)
            })
            .cloned();
        let vote = match existing {
            Some(vote) => vote,
            None => {
                let mut signer = self
                    .signer
                    .lock()
                    .map_err(|_| "empty-ETDAG signer lock poisoned".to_string())?;
                let vote = sign_vac_vote(
                    &mut signer,
                    &self.safety_journal,
                    &context,
                    &local,
                    &[],
                    &transcript,
                )?;
                verify_etdag_vote(
                    &vote,
                    &transcript,
                    &self.configuration.verifier,
                    &context,
                    &self.configuration.validator_set,
                    &self.configuration.cluster_map,
                )?;
                Self::install_vote(
                    Self::entry_mut(state, target_height, binding)?
                        .vac_votes
                        .entry(vertex_digest.clone())
                        .or_default(),
                    vote.clone(),
                )?;
                vote
            }
        };
        self.pending_outputs
            .push(SimplifiedEmptyEtdagOutput::Assembly(
                SimplifiedEmptyEtdagMessage::VacVote {
                    target_height,
                    admission_binding_digest: binding.clone(),
                    vertex_digest,
                    vote,
                },
            ));
        Ok(())
    }

    fn handle_marker(
        &mut self,
        state: &mut EmptyEtdagFile,
        peer: &EtdagAuthenticatedIngressPeer,
        target_height: Height,
        binding: &EtdagDigest,
        vertex: TransactionVertex,
    ) -> Result<(), String> {
        if peer.validator_id != vertex.author_validator_id
            || peer.consensus_key_id != vertex.author_key_id
        {
            return Err("EMPTY_ETDAG_UNTRUSTED_MARKER_PEER".to_string());
        }
        let context = Self::entry_mut(state, target_height, binding)?
            .admission_package
            .context
            .clone();
        self.validate_empty_marker(&context, &vertex)?;
        let digest = vertex.digest()?;
        let entry = Self::entry_mut(state, target_height, binding)?;
        if let Some(existing) = entry
            .markers
            .values()
            .find(|existing| existing.author_validator_id == vertex.author_validator_id)
        {
            if existing.digest()? != digest {
                return Err("EMPTY_ETDAG_MARKER_AUTHOR_CONFLICT".to_string());
            }
        } else {
            entry.markers.insert(digest.clone(), vertex);
        }
        self.ensure_local_vac_vote(state, target_height, binding, digest)
    }

    fn handle_vac_vote(
        &self,
        state: &mut EmptyEtdagFile,
        peer: &EtdagAuthenticatedIngressPeer,
        target_height: Height,
        binding: &EtdagDigest,
        vertex_digest: &EtdagDigest,
        vote: EtdagSignedVote,
    ) -> Result<(), String> {
        self.authorize_vote_peer(peer, &vote)?;
        let entry = Self::entry_mut(state, target_height, binding)?;
        let context = entry.admission_package.context.clone();
        let vertex = entry
            .markers
            .get(vertex_digest)
            .cloned()
            .ok_or_else(|| "EMPTY_ETDAG_MARKER_NOT_READY".to_string())?;
        let transcript = Self::vote_transcript(&context, EtdagPhase::Vac, vertex_digest.clone())?;
        verify_etdag_vote(
            &vote,
            &transcript,
            &self.configuration.verifier,
            &context,
            &self.configuration.validator_set,
            &self.configuration.cluster_map,
        )?;
        let votes = entry.vac_votes.entry(vertex_digest.clone()).or_default();
        Self::install_vote(votes, vote)?;
        if votes.len() >= certificate_quorum(context.assigned_cluster_validator_count as usize)?
            && !entry.certified_vertices.contains_key(vertex_digest)
        {
            let certificate = form_etdag_certificate(
                transcript,
                votes.clone(),
                &self.configuration.verifier,
                &context,
                &self.configuration.validator_set,
                &self.configuration.cluster_map,
            )?;
            let certified = CertifiedVertex {
                vertex,
                availability_certificate: certificate,
            };
            certified.verify(
                &self.configuration.verifier,
                &context,
                &self.configuration.validator_set,
                &self.configuration.cluster_map,
            )?;
            entry
                .certified_vertices
                .insert(vertex_digest.clone(), certified);
        }
        Ok(())
    }

    fn handle_dcc_candidate(
        &mut self,
        state: &mut EmptyEtdagFile,
        peer: &EtdagAuthenticatedIngressPeer,
        target_height: Height,
        binding: &EtdagDigest,
        certified_vertices: BTreeMap<EtdagDigest, CertifiedVertex>,
        marker_digests: Vec<EtdagDigest>,
        candidate: DagCutCandidate,
    ) -> Result<(), String> {
        if &peer.validator_id != self.assembler_for(target_height)? {
            return Err("EMPTY_ETDAG_UNAUTHORIZED_ASSEMBLER".to_string());
        }
        let context = Self::entry_mut(state, target_height, binding)?
            .admission_package
            .context
            .clone();
        let rebuilt = build_dag_cut_candidate(
            &context,
            &certified_vertices,
            &marker_digests,
            &self.configuration.verifier,
            &self.configuration.validator_set,
            &self.configuration.cluster_map,
        )?;
        if rebuilt != candidate || !candidate.eligible_envelopes.is_empty() {
            return Err("EMPTY_ETDAG_DCC_CANDIDATE_MISMATCH".to_string());
        }
        let entry = Self::entry_mut(state, target_height, binding)?;
        if let Some(existing) = &entry.dcc_candidate {
            if existing.digest()? != candidate.digest()? {
                return Err("EMPTY_ETDAG_DCC_CANDIDATE_CONFLICT".to_string());
            }
        } else {
            entry.certified_vertices = certified_vertices;
            entry.dcc_candidate = Some(candidate.clone());
        }
        self.ensure_local_phase_vote(
            state,
            target_height,
            binding,
            EtdagPhase::Dcc,
            candidate.digest()?,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn handle_bvc_candidate(
        &mut self,
        state: &mut EmptyEtdagFile,
        peer: &EtdagAuthenticatedIngressPeer,
        target_height: Height,
        binding: &EtdagDigest,
        certified_vertices: BTreeMap<EtdagDigest, CertifiedVertex>,
        dcc: DagCutCertificate,
        batch_candidate: BatchCandidate,
        authority: &SimplifiedTargetAdmissionFinalitySnapshot,
    ) -> Result<(), String> {
        if &peer.validator_id != self.assembler_for(target_height)? {
            return Err("EMPTY_ETDAG_UNAUTHORIZED_ASSEMBLER".to_string());
        }
        let context = Self::entry_mut(state, target_height, binding)?
            .admission_package
            .context
            .clone();
        dcc.verify(
            &self.configuration.verifier,
            &context,
            &self.configuration.validator_set,
            &self.configuration.cluster_map,
        )?;
        let rebuilt_dcc = build_dag_cut_candidate(
            &context,
            &certified_vertices,
            &dcc.candidate.cutoff_marker_digests,
            &self.configuration.verifier,
            &self.configuration.validator_set,
            &self.configuration.cluster_map,
        )?;
        let rebuilt_batch = build_batch_candidate(
            &rebuilt_dcc,
            authority.canonical_finality_context_digest.clone(),
            self.configuration.epoch_context.finalized_epoch_seed_root,
            &self.configuration.etdag_parameters,
        )?;
        if rebuilt_dcc != dcc.candidate
            || rebuilt_batch != batch_candidate
            || !batch_candidate.ordered_commitments.is_empty()
        {
            return Err("EMPTY_ETDAG_BVC_CANDIDATE_MISMATCH".to_string());
        }
        let entry = Self::entry_mut(state, target_height, binding)?;
        if entry
            .dcc
            .as_ref()
            .is_some_and(|existing| existing.candidate != dcc.candidate)
            || entry
                .batch_candidate
                .as_ref()
                .is_some_and(|existing| existing != &batch_candidate)
        {
            return Err("EMPTY_ETDAG_BVC_CANDIDATE_CONFLICT".to_string());
        }
        entry.certified_vertices = certified_vertices;
        entry.dcc_candidate = Some(dcc.candidate.clone());
        entry.dcc = Some(dcc);
        entry.batch_candidate = Some(batch_candidate.clone());
        self.ensure_local_phase_vote(
            state,
            target_height,
            binding,
            EtdagPhase::BatchValidate,
            batch_candidate.digest()?,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn handle_boc_candidate(
        &mut self,
        state: &mut EmptyEtdagFile,
        peer: &EtdagAuthenticatedIngressPeer,
        target_height: Height,
        binding: &EtdagDigest,
        certified_vertices: BTreeMap<EtdagDigest, CertifiedVertex>,
        dcc: DagCutCertificate,
        bvc: BatchValidationCertificate,
    ) -> Result<(), String> {
        if &peer.validator_id != self.assembler_for(target_height)? {
            return Err("EMPTY_ETDAG_UNAUTHORIZED_ASSEMBLER".to_string());
        }
        let context = Self::entry_mut(state, target_height, binding)?
            .admission_package
            .context
            .clone();
        dcc.verify(
            &self.configuration.verifier,
            &context,
            &self.configuration.validator_set,
            &self.configuration.cluster_map,
        )?;
        bvc.verify(
            &self.configuration.verifier,
            &context,
            &self.configuration.validator_set,
            &self.configuration.cluster_map,
        )?;
        let rebuilt_dcc = build_dag_cut_candidate(
            &context,
            &certified_vertices,
            &dcc.candidate.cutoff_marker_digests,
            &self.configuration.verifier,
            &self.configuration.validator_set,
            &self.configuration.cluster_map,
        )?;
        if rebuilt_dcc != dcc.candidate
            || bvc.batch_candidate.dcc_digest != dcc.candidate.digest()?
            || !bvc.batch_candidate.ordered_commitments.is_empty()
        {
            return Err("EMPTY_ETDAG_BOC_CANDIDATE_MISMATCH".to_string());
        }
        let entry = Self::entry_mut(state, target_height, binding)?;
        if entry
            .bvc
            .as_ref()
            .is_some_and(|existing| existing.batch_candidate != bvc.batch_candidate)
        {
            return Err("EMPTY_ETDAG_BOC_CANDIDATE_CONFLICT".to_string());
        }
        entry.certified_vertices = certified_vertices;
        entry.dcc_candidate = Some(dcc.candidate.clone());
        entry.dcc = Some(dcc);
        entry.batch_candidate = Some(bvc.batch_candidate.clone());
        entry.bvc = Some(bvc.clone());
        self.ensure_local_phase_vote(
            state,
            target_height,
            binding,
            EtdagPhase::BatchFinality,
            bvc.batch_candidate.digest()?,
        )
    }

    fn handle_phase_vote(
        &self,
        state: &mut EmptyEtdagFile,
        peer: &EtdagAuthenticatedIngressPeer,
        target_height: Height,
        binding: &EtdagDigest,
        phase: EtdagPhase,
        candidate_digest: &EtdagDigest,
        vote: EtdagSignedVote,
    ) -> Result<(), String> {
        self.authorize_vote_peer(peer, &vote)?;
        let entry = Self::entry_mut(state, target_height, binding)?;
        let context = entry.admission_package.context.clone();
        let expected = match phase {
            EtdagPhase::Dcc => entry
                .dcc_candidate
                .as_ref()
                .ok_or_else(|| "EMPTY_ETDAG_DCC_NOT_READY".to_string())?
                .digest()?,
            EtdagPhase::BatchValidate | EtdagPhase::BatchFinality => entry
                .batch_candidate
                .as_ref()
                .ok_or_else(|| "EMPTY_ETDAG_BATCH_NOT_READY".to_string())?
                .digest()?,
            _ => return Err("EMPTY_ETDAG_WRONG_PHASE".to_string()),
        };
        if &expected != candidate_digest {
            return Err("EMPTY_ETDAG_VOTE_CANDIDATE_MISMATCH".to_string());
        }
        let transcript = Self::vote_transcript(&context, phase, expected)?;
        verify_etdag_vote(
            &vote,
            &transcript,
            &self.configuration.verifier,
            &context,
            &self.configuration.validator_set,
            &self.configuration.cluster_map,
        )?;
        let votes = match phase {
            EtdagPhase::Dcc => &mut entry.dcc_votes,
            EtdagPhase::BatchValidate => &mut entry.bvc_votes,
            EtdagPhase::BatchFinality => &mut entry.boc_votes,
            _ => unreachable!(),
        };
        Self::install_vote(votes, vote)
    }

    fn ensure_local_phase_vote(
        &mut self,
        state: &mut EmptyEtdagFile,
        target_height: Height,
        binding: &EtdagDigest,
        phase: EtdagPhase,
        candidate_digest: EtdagDigest,
    ) -> Result<(), String> {
        let context = Self::entry_mut(state, target_height, binding)?
            .admission_package
            .context
            .clone();
        let Some(local) = self.local_member(&context) else {
            return Ok(());
        };
        let transcript = Self::vote_transcript(&context, phase, candidate_digest.clone())?;
        let existing = {
            let entry = Self::entry_mut(state, target_height, binding)?;
            let votes = match phase {
                EtdagPhase::Dcc => &entry.dcc_votes,
                EtdagPhase::BatchValidate => &entry.bvc_votes,
                EtdagPhase::BatchFinality => &entry.boc_votes,
                _ => return Err("EMPTY_ETDAG_WRONG_PHASE".to_string()),
            };
            votes
                .iter()
                .find(|vote| vote.signer_validator_id == self.local_validator_id)
                .cloned()
        };
        let vote = match existing {
            Some(vote) => vote,
            None => {
                let mut signer = self
                    .signer
                    .lock()
                    .map_err(|_| "empty-ETDAG signer lock poisoned".to_string())?;
                let vote = sign_etdag_vote(
                    &mut signer,
                    &self.safety_journal,
                    &context,
                    &local,
                    &transcript,
                )?;
                verify_etdag_vote(
                    &vote,
                    &transcript,
                    &self.configuration.verifier,
                    &context,
                    &self.configuration.validator_set,
                    &self.configuration.cluster_map,
                )?;
                let entry = Self::entry_mut(state, target_height, binding)?;
                let votes = match phase {
                    EtdagPhase::Dcc => &mut entry.dcc_votes,
                    EtdagPhase::BatchValidate => &mut entry.bvc_votes,
                    EtdagPhase::BatchFinality => &mut entry.boc_votes,
                    _ => unreachable!(),
                };
                Self::install_vote(votes, vote.clone())?;
                vote
            }
        };
        let message = match phase {
            EtdagPhase::Dcc => SimplifiedEmptyEtdagMessage::DccVote {
                target_height,
                admission_binding_digest: binding.clone(),
                candidate_digest,
                vote,
            },
            EtdagPhase::BatchValidate => SimplifiedEmptyEtdagMessage::BvcVote {
                target_height,
                admission_binding_digest: binding.clone(),
                candidate_digest,
                vote,
            },
            EtdagPhase::BatchFinality => SimplifiedEmptyEtdagMessage::BocVote {
                target_height,
                admission_binding_digest: binding.clone(),
                candidate_digest,
                vote,
            },
            _ => return Err("EMPTY_ETDAG_WRONG_PHASE".to_string()),
        };
        self.pending_outputs
            .push(SimplifiedEmptyEtdagOutput::Assembly(message));
        Ok(())
    }

    fn advance(
        &mut self,
        state: &mut EmptyEtdagFile,
        target_height: Height,
        _current_authority: &SimplifiedTargetAdmissionFinalitySnapshot,
    ) -> Result<(), String> {
        let (context, binding, source_finality_digest) = {
            let entry = state
                .entries
                .get(&target_height)
                .ok_or_else(|| "EMPTY_ETDAG_ADMISSION_NOT_READY".to_string())?;
            (
                entry.admission_package.context.clone(),
                entry.admission_package.admission_binding_digest()?,
                entry.source_finality_context_digest.clone(),
            )
        };
        let is_assembler = self.assembler_for(target_height)? == &self.local_validator_id;
        if !is_assembler {
            // Assembly messages are intentionally accepted through a
            // non-blocking ingress handler.  A peer can therefore miss a
            // one-shot broadcast while the local durable producer is doing a
            // short store operation.  Re-emit this member's already-signed
            // phase vote from durable state until the phase certificate is
            // present; never sign a second vote or change a candidate.
            self.replay_local_phase_votes(state, target_height, &binding)?;
            return Ok(());
        }

        let quorum = certificate_quorum(context.assigned_cluster_validator_count as usize)?;
        if state.entries[&target_height].dcc_candidate.is_none() {
            let entry = &state.entries[&target_height];
            let mut certified_by_author = entry
                .certified_vertices
                .iter()
                .map(|(digest, vertex)| {
                    (
                        vertex.vertex.author_validator_id.clone(),
                        digest.clone(),
                        vertex.clone(),
                    )
                })
                .collect::<Vec<_>>();
            certified_by_author.sort_by(|left, right| left.0.cmp(&right.0));
            certified_by_author.dedup_by(|left, right| left.0 == right.0);
            if certified_by_author.len() < quorum {
                return Ok(());
            }
            // Only the frozen scheduled assembler chooses a marker quorum.
            // Its first durable choice is retained, so message arrival order
            // at other validators cannot create competing semantic candidates.
            let selected = certified_by_author
                .into_iter()
                .take(quorum)
                .collect::<Vec<_>>();
            let marker_digests = selected
                .iter()
                .map(|(_, digest, _)| digest.clone())
                .collect::<Vec<_>>();
            let certified_vertices = selected
                .into_iter()
                .map(|(_, digest, vertex)| (digest, vertex))
                .collect::<BTreeMap<_, _>>();
            let candidate = build_dag_cut_candidate(
                &context,
                &certified_vertices,
                &marker_digests,
                &self.configuration.verifier,
                &self.configuration.validator_set,
                &self.configuration.cluster_map,
            )?;
            if !candidate.eligible_envelopes.is_empty() {
                return Err("EMPTY_ETDAG_DCC_CONTAINS_TRANSACTIONS".to_string());
            }
            let entry = state.entries.get_mut(&target_height).unwrap();
            entry.certified_vertices = certified_vertices.clone();
            entry.dcc_candidate = Some(candidate.clone());
            self.pending_outputs
                .push(SimplifiedEmptyEtdagOutput::Assembly(
                    SimplifiedEmptyEtdagMessage::DccCandidate {
                        target_height,
                        admission_binding_digest: binding.clone(),
                        certified_vertices,
                        marker_digests,
                        candidate: candidate.clone(),
                    },
                ));
            self.ensure_local_phase_vote(
                state,
                target_height,
                &binding,
                EtdagPhase::Dcc,
                candidate.digest()?,
            )?;
        }

        if state.entries[&target_height].dcc.is_none() {
            self.replay_dcc_candidate(state, target_height, &binding)?;
            self.replay_local_phase_votes(state, target_height, &binding)?;
            let entry = &state.entries[&target_height];
            if entry.dcc_votes.len() < quorum {
                return Ok(());
            }
            let candidate = entry
                .dcc_candidate
                .clone()
                .ok_or_else(|| "EMPTY_ETDAG_DCC_NOT_READY".to_string())?;
            let transcript = Self::vote_transcript(&context, EtdagPhase::Dcc, candidate.digest()?)?;
            let certificate = form_etdag_certificate(
                transcript,
                entry.dcc_votes.clone(),
                &self.configuration.verifier,
                &context,
                &self.configuration.validator_set,
                &self.configuration.cluster_map,
            )?;
            state.entries.get_mut(&target_height).unwrap().dcc = Some(DagCutCertificate {
                candidate,
                certificate,
            });
        }

        if state.entries[&target_height].batch_candidate.is_none() {
            let entry = &state.entries[&target_height];
            let dcc = entry.dcc.clone().unwrap();
            let batch_candidate = build_batch_candidate(
                &dcc.candidate,
                source_finality_digest.clone(),
                self.configuration.epoch_context.finalized_epoch_seed_root,
                &self.configuration.etdag_parameters,
            )?;
            if !batch_candidate.ordered_commitments.is_empty() {
                return Err("EMPTY_ETDAG_BATCH_CONTAINS_TRANSACTIONS".to_string());
            }
            let certified_vertices = entry.certified_vertices.clone();
            let entry = state.entries.get_mut(&target_height).unwrap();
            entry.batch_candidate = Some(batch_candidate.clone());
            self.pending_outputs
                .push(SimplifiedEmptyEtdagOutput::Assembly(
                    SimplifiedEmptyEtdagMessage::BvcCandidate {
                        target_height,
                        admission_binding_digest: binding.clone(),
                        certified_vertices,
                        dcc,
                        batch_candidate: batch_candidate.clone(),
                    },
                ));
            self.ensure_local_phase_vote(
                state,
                target_height,
                &binding,
                EtdagPhase::BatchValidate,
                batch_candidate.digest()?,
            )?;
        }

        if state.entries[&target_height].bvc.is_none() {
            self.replay_bvc_candidate(state, target_height, &binding)?;
            self.replay_local_phase_votes(state, target_height, &binding)?;
            let entry = &state.entries[&target_height];
            if entry.bvc_votes.len() < quorum {
                return Ok(());
            }
            let batch_candidate = entry.batch_candidate.clone().unwrap();
            let transcript = Self::vote_transcript(
                &context,
                EtdagPhase::BatchValidate,
                batch_candidate.digest()?,
            )?;
            let certificate = form_etdag_certificate(
                transcript,
                entry.bvc_votes.clone(),
                &self.configuration.verifier,
                &context,
                &self.configuration.validator_set,
                &self.configuration.cluster_map,
            )?;
            state.entries.get_mut(&target_height).unwrap().bvc = Some(BatchValidationCertificate {
                batch_candidate,
                certificate,
            });
        }

        if state.entries[&target_height].boc.is_none() {
            self.replay_boc_candidate(state, target_height, &binding)?;
            self.replay_local_phase_votes(state, target_height, &binding)?;
            let entry = &state.entries[&target_height];
            let bvc = entry.bvc.clone().unwrap();
            let dcc = entry.dcc.clone().unwrap();
            let certified_vertices = entry.certified_vertices.clone();
            self.pending_outputs
                .push(SimplifiedEmptyEtdagOutput::Assembly(
                    SimplifiedEmptyEtdagMessage::BocCandidate {
                        target_height,
                        admission_binding_digest: binding.clone(),
                        certified_vertices,
                        dcc,
                        bvc: bvc.clone(),
                    },
                ));
            self.ensure_local_phase_vote(
                state,
                target_height,
                &binding,
                EtdagPhase::BatchFinality,
                bvc.batch_candidate.digest()?,
            )?;
            let entry = &state.entries[&target_height];
            if entry.boc_votes.len() < quorum {
                return Ok(());
            }
            let transcript = Self::vote_transcript(
                &context,
                EtdagPhase::BatchFinality,
                bvc.batch_candidate.digest()?,
            )?;
            let finality_certificate = form_etdag_certificate(
                transcript,
                entry.boc_votes.clone(),
                &self.configuration.verifier,
                &context,
                &self.configuration.validator_set,
                &self.configuration.cluster_map,
            )?;
            state.entries.get_mut(&target_height).unwrap().boc = Some(BatchOrderCertificate {
                bvc,
                finality_certificate,
            });
        }

        if state.entries[&target_height].certified_artifact.is_none() {
            let entry = &state.entries[&target_height];
            let batch = entry.boc.as_ref().unwrap().bvc.batch_candidate.clone();
            let empty_shares = BTreeMap::new();
            let protected_input = ProtectedBlockInput {
                dcc: entry.dcc.clone().unwrap(),
                boc: entry.boc.clone().unwrap(),
                reveal: PublicOrderedReveal {
                    target_height,
                    batch_candidate_digest: batch.digest()?,
                    ordered_transactions: Vec::new(),
                    decrypt_share_transcript_root: decrypt_share_transcript_root(&empty_shares)?,
                },
                epoch_randomness: self.configuration.epoch_context.finalized_epoch_seed_root,
                certified_vertices: entry.certified_vertices.clone(),
                envelopes: BTreeMap::new(),
                decrypt_shares: empty_shares,
            };
            self.coordinator
                .admit_certified_public_input_schedule_neutral(
                    &entry.admission_package,
                    &protected_input,
                    &source_finality_digest,
                    &self.configuration.verifier,
                    &self.configuration.validator_set,
                    &self.configuration.cluster_map,
                    self.configuration.consensus_parameter_root,
                    &self.configuration.etdag_parameters,
                )?;
            let artifact = CertifiedProtectedInputArtifact {
                admission_package: entry.admission_package.clone(),
                protected_input,
            };
            artifact.validate_wire_size()?;
            state
                .entries
                .get_mut(&target_height)
                .unwrap()
                .certified_artifact = Some(artifact.clone());
            self.pending_outputs
                .push(SimplifiedEmptyEtdagOutput::CertifiedInput(artifact));
        }
        Ok(())
    }

    fn replay_dcc_candidate(
        &mut self,
        state: &EmptyEtdagFile,
        target_height: Height,
        binding: &EtdagDigest,
    ) -> Result<(), String> {
        let entry = state
            .entries
            .get(&target_height)
            .ok_or_else(|| "EMPTY_ETDAG_ADMISSION_NOT_READY".to_string())?;
        if entry.dcc.is_some() {
            return Ok(());
        }
        let Some(candidate) = entry.dcc_candidate.clone() else {
            return Ok(());
        };
        self.pending_outputs
            .push(SimplifiedEmptyEtdagOutput::Assembly(
                SimplifiedEmptyEtdagMessage::DccCandidate {
                    target_height,
                    admission_binding_digest: binding.clone(),
                    certified_vertices: entry.certified_vertices.clone(),
                    marker_digests: candidate.cutoff_marker_digests.clone(),
                    candidate,
                },
            ));
        Ok(())
    }

    fn replay_bvc_candidate(
        &mut self,
        state: &EmptyEtdagFile,
        target_height: Height,
        binding: &EtdagDigest,
    ) -> Result<(), String> {
        let entry = state
            .entries
            .get(&target_height)
            .ok_or_else(|| "EMPTY_ETDAG_ADMISSION_NOT_READY".to_string())?;
        if entry.bvc.is_some() {
            return Ok(());
        }
        let (Some(dcc), Some(batch_candidate)) = (entry.dcc.clone(), entry.batch_candidate.clone())
        else {
            return Ok(());
        };
        self.pending_outputs
            .push(SimplifiedEmptyEtdagOutput::Assembly(
                SimplifiedEmptyEtdagMessage::BvcCandidate {
                    target_height,
                    admission_binding_digest: binding.clone(),
                    certified_vertices: entry.certified_vertices.clone(),
                    dcc,
                    batch_candidate,
                },
            ));
        Ok(())
    }

    fn replay_boc_candidate(
        &mut self,
        state: &EmptyEtdagFile,
        target_height: Height,
        binding: &EtdagDigest,
    ) -> Result<(), String> {
        let entry = state
            .entries
            .get(&target_height)
            .ok_or_else(|| "EMPTY_ETDAG_ADMISSION_NOT_READY".to_string())?;
        if entry.boc.is_some() {
            return Ok(());
        }
        let (Some(dcc), Some(bvc)) = (entry.dcc.clone(), entry.bvc.clone()) else {
            return Ok(());
        };
        self.pending_outputs
            .push(SimplifiedEmptyEtdagOutput::Assembly(
                SimplifiedEmptyEtdagMessage::BocCandidate {
                    target_height,
                    admission_binding_digest: binding.clone(),
                    certified_vertices: entry.certified_vertices.clone(),
                    dcc,
                    bvc,
                },
            ));
        Ok(())
    }

    fn replay_local_phase_votes(
        &mut self,
        state: &mut EmptyEtdagFile,
        target_height: Height,
        binding: &EtdagDigest,
    ) -> Result<(), String> {
        let (dcc, bvc, boc) = {
            let entry = state
                .entries
                .get(&target_height)
                .ok_or_else(|| "EMPTY_ETDAG_ADMISSION_NOT_READY".to_string())?;
            (
                entry
                    .dcc_candidate
                    .as_ref()
                    .filter(|_| entry.dcc.is_none())
                    .map(DagCutCandidate::digest)
                    .transpose()?,
                entry
                    .batch_candidate
                    .as_ref()
                    .filter(|_| entry.bvc.is_none())
                    .map(BatchCandidate::digest)
                    .transpose()?,
                entry
                    .bvc
                    .as_ref()
                    .filter(|_| entry.boc.is_none())
                    .map(|certificate| certificate.batch_candidate.digest())
                    .transpose()?,
            )
        };
        if let Some(candidate_digest) = dcc {
            self.ensure_local_phase_vote(
                state,
                target_height,
                binding,
                EtdagPhase::Dcc,
                candidate_digest,
            )?;
        }
        if let Some(candidate_digest) = bvc {
            self.ensure_local_phase_vote(
                state,
                target_height,
                binding,
                EtdagPhase::BatchValidate,
                candidate_digest,
            )?;
        }
        if let Some(candidate_digest) = boc {
            self.ensure_local_phase_vote(
                state,
                target_height,
                binding,
                EtdagPhase::BatchFinality,
                candidate_digest,
            )?;
        }
        Ok(())
    }
}

static SIMPLIFIED_EMPTY_ETDAG_HANDLER: OnceLock<Mutex<Option<SimplifiedEmptyEtdagProducer>>> =
    OnceLock::new();

fn empty_etdag_handler_slot() -> &'static Mutex<Option<SimplifiedEmptyEtdagProducer>> {
    SIMPLIFIED_EMPTY_ETDAG_HANDLER.get_or_init(|| Mutex::new(None))
}

fn try_lock_empty_etdag_handler(
) -> Result<std::sync::MutexGuard<'static, Option<SimplifiedEmptyEtdagProducer>>, String> {
    empty_etdag_handler_slot()
        .lock()
        .map_err(|_| "simplified empty-ETDAG producer lock poisoned".to_string())
}

pub fn install_simplified_empty_etdag_producer_handler(
    producer: SimplifiedEmptyEtdagProducer,
) -> Result<(), String> {
    let mut slot = try_lock_empty_etdag_handler()?;
    if slot.is_some() {
        return Err("simplified empty-ETDAG producer is already installed".to_string());
    }
    *slot = Some(producer);
    Ok(())
}

pub fn remove_simplified_empty_etdag_producer_handler(
) -> Result<Option<SimplifiedEmptyEtdagProducer>, String> {
    Ok(try_lock_empty_etdag_handler()?.take())
}

pub fn prepare_simplified_empty_etdag() -> Result<Vec<SimplifiedEmptyEtdagOutput>, String> {
    let mut slot = try_lock_empty_etdag_handler()?;
    let producer = slot.as_mut().ok_or_else(|| {
        "simplified empty-ETDAG producer is not installed; refusing prepare".to_string()
    })?;
    producer.prepare()?;
    Ok(producer.drain_outputs())
}

pub fn drain_simplified_empty_etdag_outputs() -> Result<Vec<SimplifiedEmptyEtdagOutput>, String> {
    let mut slot = try_lock_empty_etdag_handler()?;
    Ok(slot
        .as_mut()
        .ok_or_else(|| "simplified empty-ETDAG producer is not installed".to_string())?
        .drain_outputs())
}

pub fn dispatch_simplified_empty_etdag_message(
    authenticated_peer: Option<EtdagAuthenticatedIngressPeer>,
    message: SimplifiedEmptyEtdagMessage,
) -> Result<(), String> {
    let peer = authenticated_peer.ok_or_else(|| {
        "simplified empty-ETDAG ingress requires an authenticated validator peer".to_string()
    })?;
    let mut slot = try_lock_empty_etdag_handler()?;
    slot.as_mut()
        .ok_or_else(|| "simplified empty-ETDAG producer is not installed".to_string())?
        .handle_authenticated_message(&peer, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::simplified_posy::{
        FinalizedBlockRecord, GenesisFinalityReference, SimplifiedTargetAdmissionFinalitySnapshot,
    };
    use crate::consensus_parameters::ConsensusParameterRoot;
    use crate::etdag::{
        sign_etdag_vote, sign_vac_vote, sign_vertex, target_admission_source_finality_root,
        TargetAdmissionContext, TargetAdmissionContextSpec,
    };
    use crate::synergy_types::{
        Epoch, Hash, Height, ValidatorRecord, TESTNET_V3_CLUSTER_SCHEDULE_VERSION,
    };

    #[derive(Clone)]
    struct StaticFinalityAuthority(SimplifiedTargetAdmissionFinalitySnapshot);

    impl SimplifiedTargetAdmissionFinalityAuthority for StaticFinalityAuthority {
        fn current_finalized_authority(
            &mut self,
        ) -> Result<SimplifiedTargetAdmissionFinalitySnapshot, String> {
            Ok(self.0.clone())
        }
    }

    fn peer(member: &ValidatorRecord) -> EtdagAuthenticatedIngressPeer {
        EtdagAuthenticatedIngressPeer {
            validator_id: member.validator_id.clone(),
            validator_uma_id: member.validator_uma_id.clone(),
            consensus_key_id: member.consensus_public_key.key_id.clone(),
        }
    }

    fn temp_path(label: &str, file: &str) -> PathBuf {
        crate::utils::test_temp_root(format!(
            "simplified-empty-etdag-{label}-{}-{}/{}",
            std::process::id(),
            current_unix_nanos(),
            file
        ))
    }

    #[test]
    fn five_validator_empty_proof_reaches_certified_input_and_survives_restart() {
        let mut fixture = crate::etdag::tests::fixture(5, None);
        let source_digest =
            EtdagDigest::from_domain_bytes("PoSy/Test/GenesisFinalityDigest/v3", b"empty-etdag-h1");
        fixture.ingress_registry.target_height = Height(1);
        let consensus_parameter_root = fixture.context.consensus_parameter_root;
        let context = TargetAdmissionContext::derive_schedule_neutral(
            TargetAdmissionContextSpec {
                protocol_version: POSY_SIMPLIFIED_PROTOCOL_VERSION.to_string(),
                epoch: Epoch(0),
                target_height: Height(1),
                source_finalized_height: Height(0),
                source_finality_context_root: target_admission_source_finality_root(&source_digest)
                    .unwrap(),
                assigned_cluster_id: fixture.context.assigned_cluster_id,
                cluster_schedule_version: TESTNET_V3_CLUSTER_SCHEDULE_VERSION.to_string(),
                finalized_epoch_seed_root: fixture.context.finalized_epoch_seed_root,
                assigned_height_schedule_root: fixture.context.assigned_height_schedule_root,
                cryptographic_profile_root: fixture.context.cryptographic_profile_root,
                ingress_kem_registry_root: fixture.ingress_registry.root().unwrap(),
            },
            &fixture.validator_set,
            &fixture.cluster_map,
            consensus_parameter_root,
        )
        .unwrap();
        let package = crate::etdag::tests::target_admission_package(&mut fixture, context.clone());
        let epoch_context = SimplifiedEpochContext::derive(
            Epoch(0),
            Height(1),
            Height(100),
            context.finalized_epoch_seed_root,
            consensus_parameter_root,
            &fixture.validator_set,
        )
        .unwrap();
        let finalized = FinalizedBlockRecord::from_genesis(
            GenesisFinalityReference::from_canonical_genesis_hash(Hash::from_domain_bytes(
                "PoSy/Test/Genesis/v3",
                b"empty-etdag-h1",
            )),
        )
        .unwrap();
        let authority = SimplifiedTargetAdmissionFinalitySnapshot {
            epoch_context_root: epoch_context.root().unwrap(),
            consensus_parameter_root,
            finalized,
            finalized_execution_state_root: Hash::from_domain_bytes(
                "PoSy/Test/GenesisExecution/v3",
                b"empty-etdag-h1",
            ),
            canonical_finality_context_digest: source_digest.clone(),
        };
        let admission_path = temp_path("happy", "admission.json");
        let protected_path = temp_path("happy", "protected.json");
        let assembly_path = temp_path("happy", "assembly.json");
        let journal_path = temp_path("happy", "journal.json");
        let coordinator = EtdagProtectedInputCoordinator::at_paths(
            admission_path.clone(),
            protected_path.clone(),
        );
        coordinator
            .install_certified_admission_package_schedule_neutral(
                &package,
                &fixture.signer.verifier(),
                &fixture.validator_set,
                &fixture.cluster_map,
                consensus_parameter_root,
            )
            .unwrap();
        let members = fixture
            .validator_set
            .active_for_epoch(Epoch(0))
            .active_for_cluster(context.assigned_cluster_id);
        assert_eq!(members.len(), 5);
        let local_id = epoch_context.scheduled_owner(Height(1)).unwrap().clone();
        let signer = Arc::new(Mutex::new(fixture.signer));
        let journal = EtdagSafetyJournal::at_path(journal_path.clone());
        let configuration = SimplifiedEmptyEtdagConfiguration {
            epoch_context: epoch_context.clone(),
            validator_set: fixture.validator_set.clone(),
            cluster_map: fixture.cluster_map.clone(),
            verifier: signer.lock().unwrap().verifier(),
            etdag_parameters: EtdagParameters::default(),
            consensus_parameter_root,
        };
        let mut producer = SimplifiedEmptyEtdagProducer::new(
            configuration.clone(),
            local_id.clone(),
            Arc::clone(&signer),
            journal.clone(),
            DurableSimplifiedEmptyEtdagStore::at_path(assembly_path.clone()),
            coordinator.clone(),
            Box::new(StaticFinalityAuthority(authority.clone())),
        )
        .unwrap();
        producer.prepare().unwrap();
        let mut markers = producer
            .drain_outputs()
            .into_iter()
            .filter_map(|output| match output {
                SimplifiedEmptyEtdagOutput::Assembly(SimplifiedEmptyEtdagMessage::Marker {
                    vertex,
                    ..
                }) => Some(vertex),
                _ => None,
            })
            .collect::<Vec<_>>();
        for member in &members {
            if member.validator_id == local_id {
                continue;
            }
            let vertex = sign_vertex(
                &mut signer.lock().unwrap(),
                &context,
                member,
                VertexKind::CutoffMarker,
                0,
                1,
                Vec::new(),
                Vec::new(),
                SimplifiedEmptyEtdagProducer::empty_capsule_root(&context, &member.validator_id)
                    .unwrap(),
                Some(context.source_finality_context_root),
            )
            .unwrap();
            producer
                .handle_authenticated_message(
                    &peer(member),
                    SimplifiedEmptyEtdagMessage::Marker {
                        target_height: Height(1),
                        admission_binding_digest: package.admission_binding_digest().unwrap(),
                        vertex: vertex.clone(),
                    },
                )
                .unwrap();
            markers.push(vertex);
        }
        let quorum = certificate_quorum(members.len()).unwrap();
        for marker in &markers {
            let digest = marker.digest().unwrap();
            let transcript = SimplifiedEmptyEtdagProducer::vote_transcript(
                &context,
                EtdagPhase::Vac,
                digest.clone(),
            )
            .unwrap();
            for member in members
                .iter()
                .filter(|member| member.validator_id != local_id)
                .take(quorum - 1)
            {
                let vote = sign_vac_vote(
                    &mut signer.lock().unwrap(),
                    &journal,
                    &context,
                    member,
                    &[],
                    &transcript,
                )
                .unwrap();
                producer
                    .handle_authenticated_message(
                        &peer(member),
                        SimplifiedEmptyEtdagMessage::VacVote {
                            target_height: Height(1),
                            admission_binding_digest: package.admission_binding_digest().unwrap(),
                            vertex_digest: digest.clone(),
                            vote,
                        },
                    )
                    .unwrap();
            }
        }

        // Drain the initial one-shot DCC broadcast as though every peer was
        // busy, then prove the durable producer re-emits the exact candidate
        // and its existing local vote on the next worker pass.
        producer.prepare().unwrap();
        let mut replayed_dcc_outputs = producer.drain_outputs();
        assert!(replayed_dcc_outputs.iter().any(|output| matches!(
            output,
            SimplifiedEmptyEtdagOutput::Assembly(SimplifiedEmptyEtdagMessage::DccCandidate { .. })
        )));
        assert!(replayed_dcc_outputs.iter().any(|output| matches!(
            output,
            SimplifiedEmptyEtdagOutput::Assembly(SimplifiedEmptyEtdagMessage::DccVote {
                vote,
                ..
            }) if vote.signer_validator_id == local_id
        )));

        for phase in [
            EtdagPhase::Dcc,
            EtdagPhase::BatchValidate,
            EtdagPhase::BatchFinality,
        ] {
            let outputs = if phase == EtdagPhase::Dcc {
                std::mem::take(&mut replayed_dcc_outputs)
            } else {
                producer.drain_outputs()
            };
            let candidate_digest = outputs
                .iter()
                .find_map(|output| match (phase, output) {
                    (
                        EtdagPhase::Dcc,
                        SimplifiedEmptyEtdagOutput::Assembly(
                            SimplifiedEmptyEtdagMessage::DccCandidate { candidate, .. },
                        ),
                    ) => candidate.digest().ok(),
                    (
                        EtdagPhase::BatchValidate,
                        SimplifiedEmptyEtdagOutput::Assembly(
                            SimplifiedEmptyEtdagMessage::BvcCandidate {
                                batch_candidate, ..
                            },
                        ),
                    ) => batch_candidate.digest().ok(),
                    (
                        EtdagPhase::BatchFinality,
                        SimplifiedEmptyEtdagOutput::Assembly(
                            SimplifiedEmptyEtdagMessage::BocCandidate { bvc, .. },
                        ),
                    ) => bvc.batch_candidate.digest().ok(),
                    _ => None,
                })
                .expect("scheduled assembler must emit the next certified phase candidate");
            let transcript = SimplifiedEmptyEtdagProducer::vote_transcript(
                &context,
                phase,
                candidate_digest.clone(),
            )
            .unwrap();
            for member in members
                .iter()
                .filter(|member| member.validator_id != local_id)
                .take(quorum - 1)
            {
                let vote = sign_etdag_vote(
                    &mut signer.lock().unwrap(),
                    &journal,
                    &context,
                    member,
                    &transcript,
                )
                .unwrap();
                let message = match phase {
                    EtdagPhase::Dcc => SimplifiedEmptyEtdagMessage::DccVote {
                        target_height: Height(1),
                        admission_binding_digest: package.admission_binding_digest().unwrap(),
                        candidate_digest: candidate_digest.clone(),
                        vote,
                    },
                    EtdagPhase::BatchValidate => SimplifiedEmptyEtdagMessage::BvcVote {
                        target_height: Height(1),
                        admission_binding_digest: package.admission_binding_digest().unwrap(),
                        candidate_digest: candidate_digest.clone(),
                        vote,
                    },
                    EtdagPhase::BatchFinality => SimplifiedEmptyEtdagMessage::BocVote {
                        target_height: Height(1),
                        admission_binding_digest: package.admission_binding_digest().unwrap(),
                        candidate_digest: candidate_digest.clone(),
                        vote,
                    },
                    _ => unreachable!(),
                };
                producer
                    .handle_authenticated_message(&peer(member), message)
                    .unwrap();
            }
        }
        let artifact = producer
            .drain_outputs()
            .into_iter()
            .find_map(|output| match output {
                SimplifiedEmptyEtdagOutput::CertifiedInput(artifact) => Some(artifact),
                _ => None,
            })
            .expect("strict 4-of-5 phase evidence must produce a certified input");
        assert!(artifact
            .protected_input
            .verify_and_extract_transactions(
                &configuration.verifier,
                &context,
                &configuration.validator_set,
                &configuration.cluster_map,
                &configuration.etdag_parameters,
            )
            .unwrap()
            .is_empty());

        drop(producer);
        let mut restarted = SimplifiedEmptyEtdagProducer::new(
            configuration,
            local_id,
            signer,
            journal,
            DurableSimplifiedEmptyEtdagStore::at_path(assembly_path.clone()),
            coordinator,
            Box::new(StaticFinalityAuthority(authority)),
        )
        .unwrap();
        restarted.prepare().unwrap();
        let state = restarted.store.load().unwrap();
        assert_eq!(
            state.entries[&Height(1)].certified_artifact.as_ref(),
            Some(&artifact)
        );
        let _ = fs::remove_file(admission_path);
        let _ = fs::remove_file(protected_path);
        let _ = fs::remove_file(assembly_path);
        let _ = fs::remove_file(journal_path);
    }
}
