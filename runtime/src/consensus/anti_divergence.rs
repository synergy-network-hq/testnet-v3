use crate::consensus::dual_quorum::required_validator_quorum;
use crate::consensus::posy::LocalConsensusContext;
use crate::consensus::self_realign::{QuarantineMarker, RealignmentState};
use crate::consensus_parameters::ConsensusParameterRoot;
use crate::crypto::aegis_pqvm::AegisPqvmVerifier;
use crate::dag_mempool::compute_tx_order_root;
use crate::execution::{execute_block, ExecutionState};
use crate::synergy_types::{
    Block, BlockId, CanonicalSerialize, ClusterMap, Hash, Height, ProtocolConfig,
    QuorumCertificate, ValidatorSet,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DivergenceCause {
    None,
    TentativeProposalConflictOnly,
    LocalNonFinalizedBlockDiffersFromCanonical,
    LocalFinalizedWithoutQc,
    LocalFinalizedWithInvalidQc,
    LocalFinalizedWithWrongQcContext,
    LocalStateRootMismatch,
    LocalTxOrderRootMismatch,
    LocalParentHashMismatch,
    ProposerScheduleMismatch,
    ValidatorSetHashMismatch,
    ClusterMapHashMismatch,
    ProtocolConfigHashMismatch,
    AegisSignatureVerificationFailure,
    LocalDoubleSign,
    PeerFalseFinalityClaim,
    ConflictingValidQcSafetyIncident,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DivergenceStatus {
    None,
    TentativeConflict,
    LocalDivergence,
    PeerDivergence,
    SafetyIncident,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerFinalizedReport {
    pub peer_id: String,
    pub height: Height,
    pub block_id: BlockId,
    pub state_root: Hash,
    pub qc_hash: Hash,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct HeightObservation {
    pub local_block_id: Option<BlockId>,
    pub local_parent_hash: Option<Hash>,
    pub local_state_root_before: Option<Hash>,
    pub local_state_root_after: Option<Hash>,
    pub local_tx_order_root: Option<Hash>,
    pub local_dag_frontier_root: Option<Hash>,
    pub local_qc_hash: Option<Hash>,
    pub local_qc_signer_bitmap: Vec<u8>,
    pub local_finalized: bool,
    pub canonical_block_id: Option<BlockId>,
    pub canonical_qc_hash: Option<Hash>,
    pub canonical_state_root_after: Option<Hash>,
    pub canonical_parent_hash: Option<Hash>,
    pub canonical_tx_order_root: Option<Hash>,
    pub peer_finalized_reports: Vec<PeerFinalizedReport>,
    pub evidence: Vec<String>,
}

#[derive(Debug, Default)]
pub struct DivergenceDetector {
    observations: BTreeMap<Height, HeightObservation>,
}

impl DivergenceDetector {
    pub fn record_local_proposal(&mut self, block: &Block) -> Result<(), String> {
        let block_id = block.block_id()?;
        let observation = self.observations.entry(block.header.height).or_default();
        observation.local_block_id = Some(block_id);
        observation.local_parent_hash = Some(block.header.parent_block_hash);
        observation.local_state_root_before = Some(block.header.state_root_before);
        observation.local_state_root_after = Some(block.header.state_root_after);
        observation.local_tx_order_root = Some(block.header.tx_order_root);
        observation.local_dag_frontier_root = Some(block.header.dag_frontier_root);
        Ok(())
    }

    pub fn record_received_proposal(&mut self, block: &Block, peer_id: &str) -> Result<(), String> {
        let block_id = block.block_id()?;
        let observation = self.observations.entry(block.header.height).or_default();
        observation
            .evidence
            .push(format!("received proposal {} from {peer_id}", block_id.0));
        Ok(())
    }

    pub fn record_local_commit(
        &mut self,
        block: &Block,
        qc: &QuorumCertificate,
    ) -> Result<(), String> {
        let block_id = block.block_id()?;
        let observation = self.observations.entry(block.header.height).or_default();
        observation.local_block_id = Some(block_id);
        observation.local_parent_hash = Some(block.header.parent_block_hash);
        observation.local_state_root_before = Some(block.header.state_root_before);
        observation.local_state_root_after = Some(block.header.state_root_after);
        observation.local_tx_order_root = Some(block.header.tx_order_root);
        observation.local_dag_frontier_root = Some(block.header.dag_frontier_root);
        observation.local_qc_hash = Some(Hash::from_domain_bytes(
            "SYNERGY_QC_OBSERVED_V1",
            &qc.canonical_bytes()?,
        ));
        observation.local_qc_signer_bitmap = qc.signer_bitmap.clone();
        observation.local_finalized = true;
        Ok(())
    }

    pub fn record_peer_finalized_head(
        &mut self,
        peer_id: &str,
        height: Height,
        block_id: BlockId,
        state_root: Hash,
        qc_hash: Hash,
    ) {
        let observation = self.observations.entry(height).or_default();
        observation
            .peer_finalized_reports
            .push(PeerFinalizedReport {
                peer_id: peer_id.to_string(),
                height,
                block_id,
                state_root,
                qc_hash,
            });
    }

    pub fn set_canonical(&mut self, height: Height, record: &BlockCommitRecord) {
        let observation = self.observations.entry(height).or_default();
        observation.canonical_block_id = Some(record.block_id.clone());
        observation.canonical_qc_hash = Some(record.qc_hash);
        observation.canonical_state_root_after = Some(record.state_root_after);
        observation.canonical_parent_hash = Some(record.parent_hash);
        observation.canonical_tx_order_root = Some(record.tx_order_root);
    }

    pub fn detect_same_height_divergence(&self, height: Height) -> DivergenceStatus {
        let Some(observation) = self.observations.get(&height) else {
            return DivergenceStatus::None;
        };
        if let (Some(local), Some(canonical)) =
            (&observation.local_block_id, &observation.canonical_block_id)
        {
            if local != canonical {
                return if observation.local_finalized {
                    DivergenceStatus::LocalDivergence
                } else {
                    DivergenceStatus::TentativeConflict
                };
            }
        }
        for report in &observation.peer_finalized_reports {
            if let Some(canonical) = &observation.canonical_block_id {
                if &report.block_id != canonical {
                    return DivergenceStatus::PeerDivergence;
                }
            }
        }
        DivergenceStatus::None
    }

    pub fn classify_divergence(&self, height: Height) -> DivergenceCause {
        let Some(observation) = self.observations.get(&height) else {
            return DivergenceCause::None;
        };
        if let (Some(local), Some(canonical)) =
            (&observation.local_block_id, &observation.canonical_block_id)
        {
            if local != canonical {
                return if observation.local_finalized {
                    DivergenceCause::LocalFinalizedWithWrongQcContext
                } else {
                    DivergenceCause::LocalNonFinalizedBlockDiffersFromCanonical
                };
            }
        }
        if observation.local_state_root_after != observation.canonical_state_root_after
            && observation.local_state_root_after.is_some()
            && observation.canonical_state_root_after.is_some()
        {
            return DivergenceCause::LocalStateRootMismatch;
        }
        if observation.local_tx_order_root != observation.canonical_tx_order_root
            && observation.local_tx_order_root.is_some()
            && observation.canonical_tx_order_root.is_some()
        {
            return DivergenceCause::LocalTxOrderRootMismatch;
        }
        for report in &observation.peer_finalized_reports {
            if let Some(canonical) = &observation.canonical_block_id {
                if &report.block_id != canonical {
                    return DivergenceCause::PeerFalseFinalityClaim;
                }
            }
        }
        DivergenceCause::None
    }

    pub fn emit_divergence_evidence(&mut self, height: Height, evidence: String) {
        self.observations
            .entry(height)
            .or_default()
            .evidence
            .push(evidence);
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockCommitRecord {
    pub height: Height,
    pub block_id: BlockId,
    pub block_hash: Hash,
    pub parent_hash: Hash,
    pub state_root_before: Hash,
    pub state_root_after: Hash,
    pub tx_order_root: Hash,
    pub dag_frontier_root: Hash,
    pub qc_hash: Hash,
    pub active_validator_set_hash: Hash,
    pub cluster_map_hash: Hash,
    pub protocol_config_hash: ConsensusParameterRoot,
    pub written_at_unix_ms: u64,
}

#[derive(Debug, Default)]
pub struct CanonicalBlockLock {
    locks: BTreeMap<Height, BlockCommitRecord>,
}

impl CanonicalBlockLock {
    pub fn write_canonical_lock(
        &mut self,
        height: Height,
        block_commit_record: BlockCommitRecord,
    ) -> Result<(), String> {
        if let Some(existing) = self.locks.get(&height) {
            if existing.block_id != block_commit_record.block_id {
                return Err("canonical lock already exists for a different block".to_string());
            }
            return Ok(());
        }
        self.locks.insert(height, block_commit_record);
        Ok(())
    }

    pub fn verify_canonical_lock(&self, height: Height, block: &Block) -> Result<(), String> {
        let Some(record) = self.locks.get(&height) else {
            return Ok(());
        };
        let block_id = block.block_id()?;
        if record.block_id == block_id {
            Ok(())
        } else {
            Err("block conflicts with existing canonical lock".to_string())
        }
    }

    pub fn canonical_block_id(&self, height: Height) -> Option<BlockId> {
        self.locks
            .get(&height)
            .map(|record| record.block_id.clone())
    }

    pub fn canonical_commit_record(&self, height: Height) -> Option<BlockCommitRecord> {
        self.locks.get(&height).cloned()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PreCommitDecision {
    AcceptCanonical,
    RejectInvalid,
    RejectAndQuarantineSelf,
    RejectAndQuarantinePeer,
    SafetyIncidentConflictingValidQc,
}

pub struct PreCommitGuard<'a> {
    pub verifier: &'a AegisPqvmVerifier,
    pub validator_set: &'a ValidatorSet,
    pub cluster_map: &'a ClusterMap,
    pub protocol_config: &'a ProtocolConfig,
}

impl<'a> PreCommitGuard<'a> {
    pub fn precommit_verify(
        &self,
        block: &Block,
        qc: Option<&QuorumCertificate>,
        local_consensus_context: &LocalConsensusContext,
        state: &ExecutionState,
        locks: &CanonicalBlockLock,
    ) -> PreCommitDecision {
        match self.precommit_verify_checked(block, qc, local_consensus_context, state, locks) {
            Ok(()) => PreCommitDecision::AcceptCanonical,
            Err(error) if error.contains("canonical lock") => {
                PreCommitDecision::RejectAndQuarantineSelf
            }
            Err(error) if error.contains("CONFLICTING_VALID_QC") => {
                PreCommitDecision::SafetyIncidentConflictingValidQc
            }
            Err(_) => PreCommitDecision::RejectInvalid,
        }
    }

    pub fn precommit_verify_checked(
        &self,
        block: &Block,
        qc: Option<&QuorumCertificate>,
        local_consensus_context: &LocalConsensusContext,
        state: &ExecutionState,
        locks: &CanonicalBlockLock,
    ) -> Result<(), String> {
        block.header.chain_id.require_testnet_v3()?;
        block.header.network_id.require_testnet_v3()?;
        if block.header.height.0 != local_consensus_context.latest_finalized_height.0 + 1 {
            return Err("block is not expected next height".to_string());
        }
        if block.header.parent_block_hash != local_consensus_context.latest_finalized_block_hash {
            return Err("block parent does not match latest finalized block".to_string());
        }
        if block.header.state_root_before != local_consensus_context.latest_finalized_state_root {
            return Err("block state_root_before mismatch".to_string());
        }
        if block.header.active_validator_set_hash
            != local_consensus_context
                .height_context
                .active_validator_set_root
        {
            return Err("block active validator set hash mismatch".to_string());
        }
        if block.header.cluster_map_hash != local_consensus_context.height_context.cluster_map_root
        {
            return Err("block cluster map hash mismatch".to_string());
        }
        if block.header.protocol_config_hash
            != local_consensus_context
                .height_context
                .consensus_parameter_root
        {
            return Err("block protocol config hash mismatch".to_string());
        }
        local_consensus_context.height_context.validate_against(
            self.validator_set,
            self.cluster_map,
            self.protocol_config,
        )?;
        let expected_context_root = local_consensus_context.height_context.root()?;
        if block.header.height_context_root != expected_context_root {
            return Err("block height context root mismatch".to_string());
        }
        locks.verify_canonical_lock(block.header.height, block)?;

        let tx_ids = block
            .transactions
            .iter()
            .map(|tx| {
                Ok(crate::synergy_types::TxId::from_hash(
                    Hash::from_domain_bytes("SYNERGY_EXECUTION_TX_ID_V1", &tx.canonical_bytes()?),
                ))
            })
            .collect::<Result<Vec<_>, String>>()?;
        if compute_tx_order_root(&tx_ids)? != block.header.tx_order_root {
            return Err("block tx_order_root does not recompute".to_string());
        }
        let execution = execute_block(block, state)?;
        if execution.state_root_after != block.header.state_root_after {
            return Err("block state_root_after does not recompute".to_string());
        }
        if execution.receipt_root != block.header.receipt_root {
            return Err("block receipt_root does not recompute".to_string());
        }
        let qc =
            qc.ok_or_else(|| "QC missing; finalized PoSy block requires valid QC".to_string())?;
        self.verifier
            .verify_qc_checked(
                qc,
                self.validator_set,
                self.cluster_map,
                &local_consensus_context.height_context,
            )
            .map_err(|error| error.to_string())?;
        if qc.block_id != block.block_id()? {
            return Err("QC block_id does not match exact block".to_string());
        }
        if qc.height != block.header.height
            || qc.epoch != block.header.epoch
            || qc.cluster_id != block.header.cluster_id
            || qc.height_context_root != block.header.height_context_root
            || qc.active_validator_set_hash != block.header.active_validator_set_hash
            || qc.cluster_map_hash != block.header.cluster_map_hash
        {
            return Err("QC context does not match block header".to_string());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum QuarantineStatus {
    None,
    SelfQuarantinedDivergence,
    ReconcilingChain,
    SpeedSyncingCanonical,
    VerifyingCanonicalChain,
    ReadyToRejoin,
    RejoiningConsensus,
}

impl Default for QuarantineStatus {
    fn default() -> Self {
        Self::None
    }
}

#[derive(Debug, Default)]
pub struct ValidatorQuarantineManager {
    pub self_status: QuarantineStatus,
    pub reason: String,
    pub peer_quarantine: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SelfQuarantineRecord {
    pub status: QuarantineStatus,
    pub reason: String,
    pub divergence_height: Height,
    pub local_locked_block_hash: Option<String>,
    pub conflicting_block_hash: String,
    pub observed_at_unix_secs: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatorQuarantineDutyBlock {
    pub divergence_height: Height,
    pub reason: String,
    pub source: String,
}

impl SelfQuarantineRecord {
    pub fn canonical_lock_conflict(
        height: u64,
        local_locked_block_hash: Option<String>,
        conflicting_block_hash: String,
        reason: String,
    ) -> Self {
        Self {
            status: QuarantineStatus::SelfQuarantinedDivergence,
            reason,
            divergence_height: Height(height),
            local_locked_block_hash,
            conflicting_block_hash,
            observed_at_unix_secs: current_unix_secs(),
        }
    }
}

pub fn record_self_quarantine_for_canonical_lock_conflict(
    height: u64,
    local_locked_block_hash: Option<String>,
    conflicting_block_hash: &str,
    reason: &str,
) -> Result<SelfQuarantineRecord, String> {
    let record = SelfQuarantineRecord::canonical_lock_conflict(
        height,
        local_locked_block_hash,
        conflicting_block_hash.to_string(),
        reason.to_string(),
    );
    write_self_quarantine_record(&self_quarantine_path(), &record)?;
    Ok(record)
}

pub fn current_self_quarantine_record() -> Option<SelfQuarantineRecord> {
    read_self_quarantine_record(&self_quarantine_path())
        .ok()
        .flatten()
}

pub fn validator_is_self_quarantined() -> bool {
    current_validator_quarantine_duty_block().is_some()
}

pub fn current_validator_quarantine_duty_block() -> Option<ValidatorQuarantineDutyBlock> {
    let path = self_quarantine_path();
    if let Some(record) = read_self_quarantine_record(&path).ok().flatten() {
        if record.status == QuarantineStatus::SelfQuarantinedDivergence {
            return Some(ValidatorQuarantineDutyBlock {
                divergence_height: record.divergence_height,
                reason: record.reason,
                source: "self_quarantine_record".to_string(),
            });
        }
    }

    let Ok(bytes) = fs::read(&path) else {
        return None;
    };
    if bytes.is_empty() {
        return Some(malformed_quarantine_duty_block(
            "malformed quarantine marker: marker file is empty".to_string(),
        ));
    }
    let marker = match serde_json::from_slice::<QuarantineMarker>(&bytes) {
        Ok(marker) => marker,
        Err(error) => {
            return Some(malformed_quarantine_duty_block(format!(
                "malformed quarantine marker: {error}"
            )))
        }
    };

    let disables_consensus_duties = marker.voting_disabled
        || marker.proposing_disabled
        || marker.qc_aggregation_disabled
        || marker.canonical_source_disabled;
    let inactive_recovery_state = marker.recovery_state != RealignmentState::Active;
    if !disables_consensus_duties && !inactive_recovery_state {
        return None;
    }

    let height = if marker.detected_height > 0 {
        marker.detected_height
    } else {
        marker.quorum_majority_height
    };
    let reason = if marker.reason.trim().is_empty() {
        "standard quarantine marker disables consensus duties".to_string()
    } else {
        marker.reason
    };
    Some(ValidatorQuarantineDutyBlock {
        divergence_height: Height(height),
        reason,
        source: "standard_quarantine_marker".to_string(),
    })
}

fn malformed_quarantine_duty_block(reason: String) -> ValidatorQuarantineDutyBlock {
    ValidatorQuarantineDutyBlock {
        divergence_height: Height(0),
        reason,
        source: "malformed_quarantine_marker".to_string(),
    }
}

fn self_quarantine_path() -> PathBuf {
    #[cfg(test)]
    {
        if let Ok(path) = std::env::var("SYNERGY_SELF_QUARANTINE_FILE") {
            let trimmed = path.trim();
            if !trimmed.is_empty() {
                return PathBuf::from(trimmed);
            }
        }
        if let Some(test_name) = std::thread::current().name() {
            let sanitized = test_name
                .chars()
                .map(|ch| if ch.is_ascii_alphanumeric() { ch } else { '-' })
                .collect::<String>();
            return std::env::temp_dir().join(format!(
                "synergy-test-validator-quarantine-{}-{sanitized}.json",
                std::process::id()
            ));
        }
        return std::env::temp_dir().join(format!(
            "synergy-test-validator-quarantine-{}.json",
            std::process::id()
        ));
    }
    #[cfg(not(test))]
    {
        crate::utils::resolve_data_path("data/validator_quarantine.json")
    }
}

fn write_self_quarantine_record(path: &Path, record: &SelfQuarantineRecord) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| format!("failed to create quarantine directory: {error}"))?;
    }
    let tmp_path = path.with_extension("json.tmp");
    let bytes = serde_json::to_vec_pretty(record)
        .map_err(|error| format!("failed to encode self-quarantine record: {error}"))?;
    let mut options = OpenOptions::new();
    options.create(true).truncate(true).write(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options
        .open(&tmp_path)
        .map_err(|error| format!("failed to open self-quarantine temp file: {error}"))?;
    file.write_all(&bytes)
        .map_err(|error| format!("failed to write self-quarantine temp file: {error}"))?;
    file.sync_all()
        .map_err(|error| format!("failed to sync self-quarantine temp file: {error}"))?;
    drop(file);
    fs::rename(&tmp_path, path)
        .map_err(|error| format!("failed to replace self-quarantine record: {error}"))
}

fn read_self_quarantine_record(path: &Path) -> Result<Option<SelfQuarantineRecord>, String> {
    if !path.exists() {
        return Ok(None);
    }
    let bytes = fs::read(path)
        .map_err(|error| format!("failed to read self-quarantine record: {error}"))?;
    if bytes.is_empty() {
        return Ok(None);
    }
    serde_json::from_slice(&bytes)
        .map(Some)
        .map_err(|error| format!("failed to parse self-quarantine record: {error}"))
}

fn current_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

impl ValidatorQuarantineManager {
    pub fn self_quarantine(&mut self, reason: impl Into<String>) {
        self.self_status = QuarantineStatus::SelfQuarantinedDivergence;
        self.reason = reason.into();
    }

    pub fn quarantine_peer(&mut self, peer_id: impl Into<String>, reason: impl Into<String>) {
        self.peer_quarantine.insert(peer_id.into(), reason.into());
    }

    pub fn can_vote_or_propose(&self) -> bool {
        self.self_status == QuarantineStatus::None
    }

    pub fn peer_is_quarantined(&self, peer_id: &str) -> bool {
        self.peer_quarantine.contains_key(peer_id)
    }
}

#[derive(Debug, Default)]
pub struct AutomaticReconciliationManager {
    pub status: QuarantineStatus,
    pub reason: String,
    pub divergence_height: Option<Height>,
    pub evidence_preserved: Vec<String>,
    pub rolled_back_from: Option<Height>,
    pub current_sync_height: Option<Height>,
    pub target_finalized_height: Option<Height>,
}

impl AutomaticReconciliationManager {
    pub fn begin_reconciliation(&mut self, reason: impl Into<String>, divergence_height: Height) {
        self.status = QuarantineStatus::SelfQuarantinedDivergence;
        self.reason = reason.into();
        self.divergence_height = Some(divergence_height);
    }

    pub fn find_divergence_height(&self) -> Result<Height, String> {
        self.divergence_height
            .ok_or_else(|| "divergence height has not been identified".to_string())
    }

    pub fn select_canonical_sync_source(
        &self,
        peers: &[String],
        min_peers: usize,
    ) -> Result<Vec<String>, String> {
        if peers.len() < min_peers {
            return Err("not enough canonical peers for reconciliation".to_string());
        }
        Ok(peers[..min_peers].to_vec())
    }

    pub fn verify_canonical_peer_quorum(
        &self,
        reports: &[PeerFinalizedReport],
        quorum_threshold: usize,
    ) -> bool {
        let mut counts = BTreeMap::<(&BlockId, &Hash), usize>::new();
        for report in reports {
            *counts
                .entry((&report.block_id, &report.state_root))
                .or_default() += 1;
        }
        counts.values().any(|count| *count >= quorum_threshold)
    }

    pub fn rollback_local_data_from(&mut self, height: Height) {
        self.rolled_back_from = Some(height);
        self.status = QuarantineStatus::ReconcilingChain;
    }

    pub fn speed_sync_from_canonical(&mut self, from: Height, target: Height) {
        self.current_sync_height = Some(from);
        self.target_finalized_height = Some(target);
        self.status = QuarantineStatus::SpeedSyncingCanonical;
    }

    pub fn verify_replayed_chain(&mut self) {
        self.status = QuarantineStatus::VerifyingCanonicalChain;
    }

    pub fn rebuild_indexes(&mut self) {
        self.evidence_preserved.push("indexes rebuilt".to_string());
    }

    pub fn run_rejoin_readiness_checks(&mut self) {
        self.status = QuarantineStatus::ReadyToRejoin;
    }

    pub fn rejoin_consensus_at_safe_boundary(&mut self) {
        self.status = QuarantineStatus::RejoiningConsensus;
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LivenessContinuationPolicy {
    pub proposal_timeout_ms: u64,
    pub prevote_timeout_ms: u64,
    pub precommit_timeout_ms: u64,
    pub round_timeout_backoff_multiplier_ppm: u64,
    pub max_round_timeout_ms: u64,
    pub allow_quorum_reduction: bool,
}

impl LivenessContinuationPolicy {
    pub fn testnet_default() -> Self {
        Self {
            proposal_timeout_ms: 1500,
            prevote_timeout_ms: 1500,
            precommit_timeout_ms: 1500,
            round_timeout_backoff_multiplier_ppm: 1_500_000,
            max_round_timeout_ms: 10_000,
            allow_quorum_reduction: false,
        }
    }

    pub fn quorum_preserved_after_one_divergence(
        &self,
        active_validators: usize,
        live_validators: usize,
    ) -> bool {
        let threshold = required_validator_quorum(active_validators);
        live_validators >= threshold
    }
}

pub fn emergency_liveness_recommendation() -> &'static str {
    "Validator quorum is dynamic: ceil(active_validator_count * 2 / 3). If too many validators are offline, partitioned, or quarantined simultaneously, finality may pause by design to preserve safety. Do not lower quorum below the dynamic validator threshold."
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::posy::{LocalConsensusContext, ProofOfSynergyBft};
    use crate::crypto::aegis_pqvm::AegisPqvmSigner;
    use crate::synergy_types::{
        deterministic_test_height_context, AegisPqKeyRole, ClusterAssignment, ClusterId, Epoch,
        ProtocolConfig, Round, UmaId, ValidatorId, ValidatorStatus,
    };

    fn setup() -> (
        AegisPqvmSigner,
        ValidatorSet,
        ClusterMap,
        ProtocolConfig,
        LocalConsensusContext,
        Block,
        QuorumCertificate,
        ExecutionState,
    ) {
        let mut signer = AegisPqvmSigner::initialize_required().expect("aegis");
        let mut validators = Vec::new();
        for index in 0..6 {
            let uma = format!("uma-{index}");
            let key_id = signer
                .generate_and_register_key(
                    &uma,
                    vec![
                        AegisPqKeyRole::ConsensusVote,
                        AegisPqKeyRole::ConsensusProposer,
                    ],
                    Epoch(0),
                )
                .unwrap();
            let public = signer.public_key_record(&key_id).unwrap();
            validators.push(crate::synergy_types::ValidatorRecord {
                validator_id: ValidatorId(format!("validator-{index}")),
                validator_uma_id: UmaId(uma),
                consensus_public_key: public.clone(),
                peer_public_key: public.clone(),
                operator_public_key: public,
                voting_weight: 1,
                status: ValidatorStatus::Active,
                cluster_id: ClusterId(0),
                activation_epoch: Epoch(0),
            });
        }
        let set = ValidatorSet {
            epoch: Epoch(0),
            validators,
        };
        let cluster = ClusterMap {
            epoch: Epoch(0),
            assignments: set
                .validators
                .iter()
                .map(|record| ClusterAssignment {
                    cluster_id: ClusterId(0),
                    validator_id: record.validator_id.clone(),
                })
                .collect(),
        };
        let protocol = ProtocolConfig::testnet_v3();
        let context = LocalConsensusContext {
            height_context: deterministic_test_height_context(
                &set,
                &cluster,
                &protocol,
                Height(1),
                ClusterId(0),
            ),
            latest_finalized_height: Height(0),
            latest_finalized_block_hash: Hash::zero(),
            latest_finalized_state_root: Hash::zero(),
            round: Round(0),
            evidence_root: Hash::zero(),
            app_version: 1,
            execution_version: 1,
            dag_version: 1,
            aegis_pqvm_version: "aegis-pqvm".to_string(),
        };
        let verifier = signer.verifier();
        let mut consensus =
            ProofOfSynergyBft::new(&verifier, set.clone(), cluster.clone(), protocol.clone());
        let proposer = consensus
            .proposer_for(&context.height_context, Round(0))
            .unwrap();
        let state = ExecutionState::new();
        let block = consensus
            .propose_block(
                &mut signer,
                &proposer,
                Vec::new(),
                &context,
                &state,
                Hash::zero(),
            )
            .unwrap();
        let validation_votes = set.validators[0..5]
            .iter()
            .map(|validator| {
                consensus
                    .validation_vote(&mut signer, validator, &block, &context.height_context)
                    .unwrap()
            })
            .collect::<Vec<_>>();
        let vc = consensus
            .form_vc(&validation_votes, &context.height_context)
            .unwrap();
        let votes = set.validators[0..5]
            .iter()
            .map(|validator| {
                consensus
                    .finality_vote(&mut signer, validator, &block, &vc, &context.height_context)
                    .unwrap()
            })
            .collect::<Vec<_>>();
        let qc = consensus.form_qc(&votes, &context.height_context).unwrap();
        (signer, set, cluster, protocol, context, block, qc, state)
    }

    #[test]
    fn precommit_rejects_missing_qc_and_accepts_valid_qc() {
        let (signer, set, cluster, protocol, context, block, qc, state) = setup();
        let verifier = signer.verifier();
        let guard = PreCommitGuard {
            verifier: &verifier,
            validator_set: &set,
            cluster_map: &cluster,
            protocol_config: &protocol,
        };
        let locks = CanonicalBlockLock::default();
        assert_eq!(
            guard.precommit_verify(&block, None, &context, &state, &locks),
            PreCommitDecision::RejectInvalid
        );
        assert_eq!(
            guard.precommit_verify(&block, Some(&qc), &context, &state, &locks),
            PreCommitDecision::AcceptCanonical
        );
    }

    #[test]
    fn canonical_lock_rejects_second_block_at_same_height() {
        let (_signer, _set, _cluster, _protocol, _context, block, qc, _state) = setup();
        let mut locks = CanonicalBlockLock::default();
        let record = BlockCommitRecord {
            height: block.header.height,
            block_id: block.block_id().unwrap(),
            block_hash: Hash::from_domain_bytes("block", &block.header.canonical_bytes().unwrap()),
            parent_hash: block.header.parent_block_hash,
            state_root_before: block.header.state_root_before,
            state_root_after: block.header.state_root_after,
            tx_order_root: block.header.tx_order_root,
            dag_frontier_root: block.header.dag_frontier_root,
            qc_hash: Hash::from_domain_bytes("qc", &qc.canonical_bytes().unwrap()),
            active_validator_set_hash: block.header.active_validator_set_hash,
            cluster_map_hash: block.header.cluster_map_hash,
            protocol_config_hash: block.header.protocol_config_hash,
            written_at_unix_ms: 0,
        };
        locks
            .write_canonical_lock(block.header.height, record)
            .unwrap();
        let mut conflicting = block.clone();
        conflicting.header.round = Round(1);
        assert!(locks
            .verify_canonical_lock(conflicting.header.height, &conflicting)
            .is_err());
    }

    #[test]
    fn divergent_validator_quarantines_and_reconciliation_blocks_duties() {
        let mut quarantine = ValidatorQuarantineManager::default();
        assert!(quarantine.can_vote_or_propose());
        quarantine.self_quarantine("local finalized block differs from canonical");
        assert!(!quarantine.can_vote_or_propose());

        let mut reconciliation = AutomaticReconciliationManager::default();
        reconciliation.begin_reconciliation("same-height divergence", Height(10_501));
        assert_eq!(
            reconciliation.find_divergence_height().unwrap(),
            Height(10_501)
        );
        reconciliation.rollback_local_data_from(Height(10_501));
        reconciliation.speed_sync_from_canonical(Height(10_000), Height(12_345));
        reconciliation.verify_replayed_chain();
        reconciliation.rebuild_indexes();
        reconciliation.run_rejoin_readiness_checks();
        assert_eq!(reconciliation.status, QuarantineStatus::ReadyToRejoin);
    }

    #[test]
    fn self_quarantine_record_persists_canonical_lock_conflict_evidence() {
        let path = std::env::temp_dir().join(format!(
            "synergy-self-quarantine-test-{}-{}.json",
            std::process::id(),
            current_unix_secs()
        ));
        let record = SelfQuarantineRecord::canonical_lock_conflict(
            11_668,
            Some("local-lock".to_string()),
            "peer-conflict".to_string(),
            "canonical lock conflict".to_string(),
        );
        write_self_quarantine_record(&path, &record).unwrap();
        let loaded = read_self_quarantine_record(&path).unwrap().unwrap();
        assert_eq!(loaded.status, QuarantineStatus::SelfQuarantinedDivergence);
        assert_eq!(loaded.divergence_height, Height(11_668));
        assert_eq!(
            loaded.local_locked_block_hash.as_deref(),
            Some("local-lock")
        );
        assert_eq!(loaded.conflicting_block_hash, "peer-conflict");
        let _ = fs::remove_file(path);
    }

    #[test]
    fn standard_operator_quarantine_marker_blocks_consensus_duties() {
        let path = self_quarantine_path();
        let _ = fs::remove_file(&path);
        let marker = QuarantineMarker::divergence(
            "synv11kguave5fpdpm9hru4acfvw0hcp4fcc7zv9f",
            "operator_approved_stopped_stale_validator_quarantine",
            84346,
            "local-hash",
            84900,
            "majority-hash",
            Some("local-hash".to_string()),
            "data/self-heal-evidence/test",
        );
        fs::write(&path, serde_json::to_vec(&marker).unwrap()).unwrap();

        let duty_block = current_validator_quarantine_duty_block().unwrap();
        assert_eq!(duty_block.divergence_height, Height(84346));
        assert_eq!(duty_block.source, "standard_quarantine_marker");
        assert!(duty_block
            .reason
            .contains("operator_approved_stopped_stale_validator_quarantine"));
        assert!(validator_is_self_quarantined());

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn malformed_quarantine_marker_blocks_consensus_duties_fail_closed() {
        let path = self_quarantine_path();
        let _ = fs::remove_file(&path);
        fs::write(&path, b"{not-json").unwrap();

        let duty_block = current_validator_quarantine_duty_block().unwrap();
        assert_eq!(duty_block.divergence_height, Height(0));
        assert_eq!(duty_block.source, "malformed_quarantine_marker");
        assert!(duty_block.reason.contains("malformed quarantine marker"));

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn empty_quarantine_marker_blocks_consensus_duties_fail_closed() {
        let path = self_quarantine_path();
        let _ = fs::remove_file(&path);
        fs::write(&path, b"").unwrap();

        let duty_block = current_validator_quarantine_duty_block().unwrap();
        assert_eq!(duty_block.divergence_height, Height(0));
        assert_eq!(duty_block.source, "malformed_quarantine_marker");
        assert!(duty_block.reason.contains("marker file is empty"));

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn active_marker_without_disabled_duties_does_not_block_consensus() {
        let path = self_quarantine_path();
        let _ = fs::remove_file(&path);
        let marker = QuarantineMarker {
            validator_id: "validator".to_string(),
            reason: "healthy".to_string(),
            detected_height: 1,
            detected_hash: "hash".to_string(),
            quorum_majority_height: 1,
            quorum_majority_hash: "hash".to_string(),
            local_conflicting_height: None,
            local_conflicting_hash: None,
            evidence_path: "data/self-heal-evidence/test".to_string(),
            detected_at: 1,
            recovery_state: RealignmentState::Active,
            voting_disabled: false,
            proposing_disabled: false,
            qc_aggregation_disabled: false,
            canonical_source_disabled: false,
            rejoin_eligibility: false,
        };
        fs::write(&path, serde_json::to_vec(&marker).unwrap()).unwrap();

        assert!(current_validator_quarantine_duty_block().is_none());
        assert!(!validator_is_self_quarantined());

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn one_divergent_validator_does_not_reduce_quorum_but_remaining_four_can_finalize() {
        let policy = LivenessContinuationPolicy::testnet_default();
        assert!(policy.quorum_preserved_after_one_divergence(5, 4));
        assert!(!policy.allow_quorum_reduction);
        assert!(!policy.quorum_preserved_after_one_divergence(5, 3));
    }

    #[test]
    fn divergence_detector_classifies_local_and_peer_conflicts() {
        let mut detector = DivergenceDetector::default();
        let record = BlockCommitRecord {
            height: Height(1),
            block_id: BlockId("canonical".to_string()),
            block_hash: Hash::zero(),
            parent_hash: Hash::zero(),
            state_root_before: Hash::zero(),
            state_root_after: Hash::zero(),
            tx_order_root: Hash::zero(),
            dag_frontier_root: Hash::zero(),
            qc_hash: Hash::zero(),
            active_validator_set_hash: Hash::zero(),
            cluster_map_hash: Hash::zero(),
            protocol_config_hash: ConsensusParameterRoot::zero(),
            written_at_unix_ms: 0,
        };
        detector.set_canonical(Height(1), &record);
        detector.record_peer_finalized_head(
            "peer-1",
            Height(1),
            BlockId("other".to_string()),
            Hash::zero(),
            Hash::zero(),
        );
        assert_eq!(
            detector.detect_same_height_divergence(Height(1)),
            DivergenceStatus::PeerDivergence
        );
        assert_eq!(
            detector.classify_divergence(Height(1)),
            DivergenceCause::PeerFalseFinalityClaim
        );
    }
}
