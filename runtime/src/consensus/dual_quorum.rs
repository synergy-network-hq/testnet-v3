use super::timing_trace;
use crate::block::Block;
use crate::consensus::anti_divergence::current_validator_quarantine_duty_block;
use crate::consensus::legacy_canonical_lock::{
    latest_legacy_canonical_commit_record, legacy_canonical_commit_record,
};
use crate::consensus::validator_keys::{
    sign_with_local_validator_key_for_height, verify_block_proposer_key_matches_validator,
    verify_signer_key_matches_validator_at_height,
};
use crate::crypto::pqc::{PQCCiphertext, PQCManager, PQCPrivateKey, PQCPublicKey, PQCSignature};
use crate::token::TOKEN_MANAGER;
use crate::validator::{
    assert_epoch_validator_set_compatible_for_height, canonical_validator_clusters_for_epoch,
    consensus_membership_validators, consensus_membership_validators_for_height,
    is_validator_activation_transaction, validate_validator_activation_transaction, Validator,
    ValidatorManager, ValidatorPerformanceUpdate, TESTNET_VALIDATOR_CLUSTER_SIZE,
    VALIDATOR_MANAGER,
};
use crate::{debug, warn};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_512};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::env;
use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom, Write};
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
#[cfg(test)]
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, Once};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

lazy_static::lazy_static! {
    static ref NETWORK_VOTE_MAILBOX: Arc<Mutex<HashMap<String, Vec<Vote>>>> =
        Arc::new(Mutex::new(HashMap::new()));
    static ref COMMITTED_QC_STORE: Arc<Mutex<HashMap<String, QuorumCertificate>>> =
        Arc::new(Mutex::new(HashMap::new()));
    static ref COMMITTED_QC_LOG_LOOKUP_INDEX: Mutex<CommittedQcLogLookupIndex> =
        Mutex::new(CommittedQcLogLookupIndex::default());
    static ref OBSERVED_VOTES: Arc<Mutex<HashMap<String, Vote>>> = Arc::new(Mutex::new(HashMap::new()));
    static ref EQUIVOCATION_EVIDENCE_LOG: Arc<Mutex<HashMap<String, VoteEquivocationEvidence>>> =
        Arc::new(Mutex::new(HashMap::new()));
    static ref PROCESSED_EQUIVOCATION_EVIDENCE: Arc<Mutex<BTreeSet<String>>> =
        Arc::new(Mutex::new(BTreeSet::new()));
    static ref LOCAL_VOTE_LOCK_FILE_MUTEX: Mutex<()> = Mutex::new(());
}

static COMMITTED_QC_STORE_INIT: Once = Once::new();

const COMMITTED_QC_HISTORICAL_INDEX_MAX_ENTRIES: usize = 4096;

#[cfg(test)]
static COMMITTED_QC_LOG_PARSE_COUNT: AtomicUsize = AtomicUsize::new(0);

pub const VALIDATOR_QUORUM_NUMERATOR: usize = 2;
pub const VALIDATOR_QUORUM_DENOMINATOR: usize = 3;
pub const VALIDATOR_QUORUM_RATIO: f64 =
    VALIDATOR_QUORUM_NUMERATOR as f64 / VALIDATOR_QUORUM_DENOMINATOR as f64;
pub const FAST_CONSENSUS_VOTE_TIMEOUT_SECS: u64 = 1;
pub const MAX_FAST_CONSENSUS_VOTE_TIMEOUT_SECS: u64 = 2;
pub const RECOVERY_FIRST_RETRY_VOTE_TIMEOUT_SECS: u64 = 4;
pub const RECOVERY_MAX_VOTE_TIMEOUT_SECS: u64 = 8;
pub const MIN_LAUNCH_VOTE_TIMEOUT_SECS: u64 = FAST_CONSENSUS_VOTE_TIMEOUT_SECS;
const LOCAL_VOTE_LOCK_COMPACTION_MIN_LOCKS: usize = 1024;
const LOCAL_VOTE_LOCK_FINALIZED_RETENTION_DEPTH: u64 = 16;
const COMMITTED_QC_HOT_RETENTION_BLOCKS_ENV: &str = "SYNERGY_COMMITTED_QC_HOT_RETENTION_BLOCKS";
const COMMITTED_QC_HOT_LOAD_MAX_BYTES_ENV: &str = "SYNERGY_COMMITTED_QC_HOT_LOAD_MAX_BYTES";
const DEFAULT_COMMITTED_QC_HOT_LOAD_MAX_BYTES: u64 = 64 * 1024 * 1024;
const HARD_MAX_COMMITTED_QC_HOT_LOAD_BYTES: u64 = 64 * 1024 * 1024;
const COMMITTED_QC_RETENTION_PRUNE_INTERVAL: usize = 1024;

#[derive(Debug, Clone, Default)]
pub struct ConsensusRuntimeMetrics {
    pub current_height: u64,
    pub current_round: u64,
    pub timeout_mode: String,
    pub effective_vote_timeout_secs: u64,
    pub votes_collected: u64,
    pub votes_required: u64,
    pub leader: String,
    pub retry_reason: String,
}

lazy_static::lazy_static! {
    static ref CONSENSUS_RUNTIME_METRICS: Mutex<ConsensusRuntimeMetrics> =
        Mutex::new(ConsensusRuntimeMetrics::default());
}

#[derive(Debug, Clone)]
struct SameHeightVoteParent {
    height: u64,
    block_hash: String,
    source: &'static str,
    checkpoint_fork_parent: bool,
}

#[cfg(test)]
lazy_static::lazy_static! {
    static ref TEST_LOCAL_VOTE_LOCK_PATH: Mutex<Option<PathBuf>> = Mutex::new(None);
    static ref TEST_VOTE_TRACKING_MUTEX: Mutex<()> = Mutex::new(());
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vote {
    pub validator_address: String,
    pub block_hash: String,
    #[serde(default)]
    pub block_index: u64,
    pub epoch_number: u64,
    #[serde(default)]
    pub round_number: u64,
    pub signature: PQCSignature,
    #[serde(default)]
    pub signer_public_key: Vec<u8>,
    pub timestamp: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VoteEquivocationEvidence {
    pub validator_address: String,
    pub epoch_number: u64,
    pub block_index: u64,
    pub round_number: u64,
    pub first_vote: Vote,
    pub conflicting_vote: Vote,
    pub detected_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SupersededLocalVoteLock {
    block_hash: String,
    first_round_number: u64,
    latest_round_number: u64,
    proposer: String,
    superseded_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct LocalVoteLock {
    validator_address: String,
    block_hash: String,
    block_index: u64,
    epoch_number: u64,
    first_round_number: u64,
    latest_round_number: u64,
    proposer: String,
    created_at: u64,
    updated_at: u64,
    #[serde(default)]
    superseded: Vec<SupersededLocalVoteLock>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalLockedVote {
    pub validator_address: String,
    pub block_hash: String,
    pub block_index: u64,
    pub epoch_number: u64,
    pub first_round_number: u64,
    pub latest_round_number: u64,
    pub proposer: String,
    pub created_at: u64,
    pub updated_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveredTransientVoteLock {
    pub validator_address: String,
    pub block_hash: String,
    pub block_index: u64,
    pub epoch_number: u64,
    pub first_round_number: u64,
    pub latest_round_number: u64,
    pub proposer: String,
    pub created_at: u64,
    pub updated_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransientVoteLockRecoveryReport {
    pub action: String,
    pub reason: String,
    pub finalized_height: u64,
    pub min_age_secs: u64,
    pub vote_lock_path: String,
    pub evidence_path: String,
    pub before_count: usize,
    pub kept_count: usize,
    pub removed_count: usize,
    pub removed: Vec<RecoveredTransientVoteLock>,
    pub mutated: bool,
    pub timestamp: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuorumCertificate {
    pub block_hash: String,
    #[serde(default)]
    pub cluster_id: Option<u64>,
    pub epoch_number: u64,
    pub round_number: u64,
    pub aggregate_signature: Vec<u8>,
    pub participant_bitmap: Vec<u8>,
    pub cumulative_weight: f64,
    pub validation_quorum_met: bool,
    pub cooperation_quorum_met: bool,
    pub timestamp: u64,
    #[serde(default)]
    pub votes: Vec<Vote>,
}

#[derive(Debug, Clone)]
struct ConsensusClusterContext {
    cluster_id: Option<u64>,
    validators: Vec<Validator>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CommittedQcLogEntry {
    block_hash: String,
    qc: QuorumCertificate,
}

#[derive(Default)]
struct CommittedQcLogLookupIndex {
    path: Option<PathBuf>,
    initialized: bool,
    indexed_file_len: u64,
    indexed_end: u64,
    forward_scan_offset: u64,
    offsets: HashMap<String, u64>,
    order: VecDeque<String>,
}

impl CommittedQcLogLookupIndex {
    fn reset_for_path(&mut self, path: &Path) {
        if self.path.as_deref() == Some(path) {
            return;
        }

        *self = Self {
            path: Some(path.to_path_buf()),
            ..Self::default()
        };
    }

    fn clear_entries(&mut self) {
        self.offsets.clear();
        self.order.clear();
    }

    fn reset_after_truncation(&mut self) {
        self.initialized = false;
        self.indexed_file_len = 0;
        self.indexed_end = 0;
        self.forward_scan_offset = 0;
        self.clear_entries();
    }

    fn insert(&mut self, block_hash: String, offset: u64) {
        if self.offsets.contains_key(&block_hash) {
            self.order.retain(|hash| hash != &block_hash);
        }
        self.offsets.insert(block_hash.clone(), offset);
        self.order.push_back(block_hash);

        while self.order.len() > COMMITTED_QC_HISTORICAL_INDEX_MAX_ENTRIES {
            if let Some(oldest) = self.order.pop_front() {
                self.offsets.remove(&oldest);
            }
        }
    }

    fn remove_if_matches(&mut self, block_hash: &str, offset: u64) {
        if self.offsets.get(block_hash) != Some(&offset) {
            return;
        }
        self.offsets.remove(block_hash);
        self.order.retain(|hash| hash != block_hash);
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AggregateSignature {
    pub combined_signature: Vec<u8>,
    pub participation_bitmap: Vec<u8>,
    pub message_hash: Vec<u8>,
    pub participant_count: usize,
}

#[derive(Debug)]
pub struct DualQuorumConsensus {
    pub validator_manager: Arc<ValidatorManager>,
    pub pqc_manager: Arc<Mutex<PQCManager>>,
    pub penalization_enabled: bool,
    pub minimum_validator_count: usize,
    pub validator_vote_threshold: usize,
    pub vote_timeout: u64,
    pub block_timeout: u64,
    pub current_epoch: u64,
    pub current_round_by_height: HashMap<u64, u64>,
    pub votes: HashMap<String, Vec<Vote>>, // block_hash -> votes
    pub quorum_certificates: HashMap<String, QuorumCertificate>, // block_hash -> QC
    verified_vote_signatures: Mutex<HashSet<String>>,
}

impl DualQuorumConsensus {
    pub fn new(
        validator_manager: Arc<ValidatorManager>,
        pqc_manager: Arc<Mutex<PQCManager>>,
        penalization_enabled: bool,
        minimum_validator_count: usize,
        validator_vote_threshold: usize,
        vote_timeout_secs: u64,
        block_timeout_secs: u64,
    ) -> Self {
        DualQuorumConsensus {
            validator_manager,
            pqc_manager,
            penalization_enabled,
            minimum_validator_count: minimum_validator_count.max(1),
            validator_vote_threshold,
            vote_timeout: vote_timeout_secs
                .max(FAST_CONSENSUS_VOTE_TIMEOUT_SECS)
                .min(MAX_FAST_CONSENSUS_VOTE_TIMEOUT_SECS),
            block_timeout: block_timeout_secs.max(1),
            current_epoch: 0,
            current_round_by_height: HashMap::new(),
            votes: HashMap::new(),
            quorum_certificates: HashMap::new(),
            verified_vote_signatures: Mutex::new(HashSet::new()),
        }
    }

    pub fn start_consensus_round(
        &mut self,
        proposed_block: &Block,
        minimum_round_number: u64,
    ) -> Result<QuorumCertificate, String> {
        self.start_consensus_round_with_recovery(proposed_block, minimum_round_number, u64::MAX)
    }

    pub fn consensus_runtime_metrics_snapshot() -> ConsensusRuntimeMetrics {
        CONSENSUS_RUNTIME_METRICS
            .lock()
            .map(|metrics| metrics.clone())
            .unwrap_or_default()
    }

    fn timeout_mode_for_round(round_number: u64) -> &'static str {
        if round_number <= 1 {
            "fast"
        } else {
            "recovery"
        }
    }

    fn effective_vote_timeout_secs(&self, round_number: u64) -> u64 {
        if round_number <= 1 {
            self.vote_timeout
                .max(FAST_CONSENSUS_VOTE_TIMEOUT_SECS)
                .min(MAX_FAST_CONSENSUS_VOTE_TIMEOUT_SECS)
        } else if round_number == 2 {
            RECOVERY_FIRST_RETRY_VOTE_TIMEOUT_SECS
                .max(self.vote_timeout)
                .min(RECOVERY_MAX_VOTE_TIMEOUT_SECS)
        } else {
            RECOVERY_MAX_VOTE_TIMEOUT_SECS
        }
    }

    fn record_consensus_runtime_metrics(
        proposed_block: &Block,
        round_number: u64,
        timeout_mode: &str,
        effective_vote_timeout_secs: u64,
        votes_collected: usize,
        votes_required: usize,
        retry_reason: &str,
    ) {
        if let Ok(mut metrics) = CONSENSUS_RUNTIME_METRICS.lock() {
            metrics.current_height = proposed_block.block_index;
            metrics.current_round = round_number;
            metrics.timeout_mode = timeout_mode.to_string();
            metrics.effective_vote_timeout_secs = effective_vote_timeout_secs;
            metrics.votes_collected = votes_collected as u64;
            metrics.votes_required = votes_required as u64;
            metrics.leader = proposed_block.validator_id.clone();
            metrics.retry_reason = retry_reason.to_string();
        }
    }

    pub fn start_consensus_round_with_recovery(
        &mut self,
        proposed_block: &Block,
        minimum_round_number: u64,
        transient_vote_recovery_min_age_secs: u64,
    ) -> Result<QuorumCertificate, String> {
        if let Some(record) = current_validator_quarantine_duty_block() {
            return Err(format!(
                "validator is quarantined at divergence height {} by {} and cannot propose, vote, or aggregate QCs: {}",
                record.divergence_height.0, record.source, record.reason
            ));
        }
        let block_hash = proposed_block.hash.clone();
        let epoch_number = self.current_epoch;
        let local_validator_address = self
            .resolve_local_validator_address_for_round()
            .ok_or_else(|| "Local validator address is not configured".to_string())?;
        let round_number = self.allocate_round_number(
            proposed_block.block_index,
            epoch_number,
            &local_validator_address,
            minimum_round_number,
        );

        // Phase 1: Proposal validation
        self.validate_block_proposal(proposed_block)?;

        // Phase 2: Voting
        let votes = self.collect_votes(
            proposed_block,
            &block_hash,
            epoch_number,
            round_number,
            transient_vote_recovery_min_age_secs,
        )?;

        // Phase 3: Commitment
        self.check_quorums_and_commit(proposed_block, epoch_number, round_number, &votes)
    }

    fn validate_block_proposal(&self, block: &Block) -> Result<(), String> {
        Self::validate_block_proposal_static(block)?;
        verify_block_proposer_key_matches_validator(block, &self.validator_manager)?;
        Self::validate_validator_activations(block, &self.validator_manager)
    }

    pub fn validate_block_proposal_static(block: &Block) -> Result<(), String> {
        if !Self::is_block_hash_valid(block) {
            return Err("Invalid block hash payload".to_string());
        }

        block.verify_proposer_signature()?;

        // Verify all transactions in the block
        for tx in &block.transactions {
            Self::verify_transaction_static(tx)?;
        }

        Ok(())
    }

    fn validate_validator_activations(
        block: &Block,
        validator_manager: &Arc<ValidatorManager>,
    ) -> Result<(), String> {
        for tx in &block.transactions {
            if !is_validator_activation_transaction(tx) {
                continue;
            }
            validate_validator_activation_transaction(
                tx,
                TOKEN_MANAGER.as_ref(),
                validator_manager,
            )
            .map_err(|error| {
                format!(
                    "validator activation preflight failed at height {} for transaction {}: {error}",
                    block.block_index,
                    tx.hash()
                )
            })?;
        }
        Ok(())
    }

    fn collect_votes(
        &mut self,
        proposed_block: &Block,
        block_hash: &str,
        epoch_number: u64,
        round_number: u64,
        transient_vote_recovery_min_age_secs: u64,
    ) -> Result<Vec<Vote>, String> {
        let active_validators = self.consensus_membership_for_height(proposed_block.block_index)?;
        if active_validators.len() < self.minimum_validator_count {
            return Err(format!(
                "Insufficient active validators: {} active in consensus membership, {} required",
                active_validators.len(),
                self.minimum_validator_count
            ));
        }

        let cluster_context = self.cluster_context_for_proposal(proposed_block, epoch_number)?;
        let consensus_validators = &cluster_context.validators;

        let expected_validators = consensus_validators
            .iter()
            .map(|validator| validator.address.clone())
            .collect::<BTreeSet<_>>();
        let local_validator_address = self
            .resolve_local_validator_address_for_round()
            .ok_or_else(|| "Local validator address is not configured".to_string())?;
        if !expected_validators.contains(&local_validator_address) {
            return Err(format!(
                "Local validator {} is not eligible for this consensus round",
                local_validator_address
            ));
        }

        Self::recover_stale_conflicting_vote_lock_before_vote(
            &local_validator_address,
            proposed_block,
            epoch_number,
            round_number,
            transient_vote_recovery_min_age_secs,
            "local proposer pre-vote transient lock reconciliation",
        )?;

        Self::register_local_vote_intent(
            &local_validator_address,
            proposed_block,
            epoch_number,
            round_number,
        )?;
        let local_vote = Self::create_vote_for_validator_with_manager(
            &local_validator_address,
            proposed_block,
            epoch_number,
            round_number,
            &self.validator_manager,
        )?;
        self.register_local_vote_or_slash(&local_vote)?;
        let mut votes = vec![local_vote];

        Self::reset_network_vote_mailbox(block_hash, epoch_number, round_number);

        let remote_validators = expected_validators
            .iter()
            .filter(|address| *address != &local_validator_address)
            .count();
        let collection_started = Instant::now();
        let effective_vote_timeout_secs = self.effective_vote_timeout_secs(round_number);
        let timeout_mode = Self::timeout_mode_for_round(round_number);
        let retry_number = round_number.saturating_sub(1);
        let required_validator_votes =
            self.required_validator_votes_for_cluster_context(&cluster_context);
        Self::record_consensus_runtime_metrics(
            proposed_block,
            round_number,
            timeout_mode,
            effective_vote_timeout_secs,
            votes.len(),
            required_validator_votes,
            if retry_number == 0 {
                "initial_round"
            } else {
                "missed_quorum_retry"
            },
        );
        timing_trace::emit(
            "vote_collection_start",
            serde_json::json!({
                "height": proposed_block.block_index,
                "block_hash": block_hash.to_string(),
                "previous_hash": proposed_block.previous_hash.clone(),
                "proposer": proposed_block.validator_id.clone(),
                "epoch": epoch_number,
                "round": round_number,
                "local_validator": local_validator_address.clone(),
                "expected_validators": expected_validators.iter().cloned().collect::<Vec<_>>(),
                "remote_validators": remote_validators,
                "votes_required": required_validator_votes,
                "leader": proposed_block.validator_id.clone(),
                "retry_number": retry_number,
                "timeout_mode": timeout_mode,
                "initial_vote_count": votes.len(),
                "effective_vote_timeout_secs": effective_vote_timeout_secs
            }),
        );
        if remote_validators > 0 {
            if let Some(network) = crate::p2p::get_p2p_network() {
                let notified =
                    network.broadcast_vote_request(proposed_block, epoch_number, round_number);
                timing_trace::emit(
                    "proposal_sent",
                    serde_json::json!({
                        "height": proposed_block.block_index,
                        "block_hash": block_hash.to_string(),
                        "previous_hash": proposed_block.previous_hash.clone(),
                        "proposer": proposed_block.validator_id.clone(),
                        "epoch": epoch_number,
                        "round": round_number,
                        "local_validator": local_validator_address.clone(),
                        "notified_peers": notified,
                        "network_peer_count": network.get_peer_count()
                    }),
                );
                timing_trace::emit(
                    "vote_request_sent",
                    serde_json::json!({
                        "height": proposed_block.block_index,
                        "block_hash": block_hash.to_string(),
                        "previous_hash": proposed_block.previous_hash.clone(),
                        "proposer": proposed_block.validator_id.clone(),
                        "epoch": epoch_number,
                        "round": round_number,
                        "local_validator": local_validator_address.clone(),
                        "remote_validators": remote_validators,
                        "notified_peers": notified,
                        "network_peer_count": network.get_peer_count()
                    }),
                );
                debug!(
                    "consensus",
                    "Broadcasted vote request",
                    "block_hash" => block_hash.to_string(),
                    "epoch" => epoch_number,
                    "round" => round_number,
                    "remote_validators" => remote_validators as u64,
                    "notified_peers" => notified as u64
                );
            } else {
                warn!(
                    "consensus",
                    "Consensus round has remote validators but no active P2P network",
                    "block_hash" => block_hash.to_string(),
                    "epoch" => epoch_number,
                    "round" => round_number
                );
                timing_trace::emit(
                    "vote_request_send_skipped",
                    serde_json::json!({
                        "height": proposed_block.block_index,
                        "block_hash": block_hash.to_string(),
                        "previous_hash": proposed_block.previous_hash.clone(),
                        "proposer": proposed_block.validator_id.clone(),
                        "epoch": epoch_number,
                        "round": round_number,
                        "local_validator": local_validator_address.clone(),
                        "remote_validators": remote_validators,
                        "reason": "no_active_p2p_network"
                    }),
                );
            }
        }

        let deadline = Instant::now() + Duration::from_secs(effective_vote_timeout_secs);
        let mut qc_threshold_reported = false;
        while Instant::now() < deadline {
            self.apply_recorded_equivocations();
            votes.retain(|vote| {
                self.vote_is_eligible_for_collection_for_cluster(
                    vote,
                    block_hash,
                    epoch_number,
                    round_number,
                    cluster_context.cluster_id,
                )
            });

            let pending_votes =
                Self::snapshot_network_votes(block_hash, epoch_number, round_number);
            self.merge_remote_votes_for_cluster(
                &mut votes,
                &expected_validators,
                block_hash,
                epoch_number,
                round_number,
                cluster_context.cluster_id,
                pending_votes,
            );

            if self.has_commit_quorum_for_cluster(&cluster_context, &votes) {
                if !qc_threshold_reported {
                    timing_trace::emit(
                        "qc_threshold_reached",
                        serde_json::json!({
                            "height": proposed_block.block_index,
                            "block_hash": block_hash.to_string(),
                            "previous_hash": proposed_block.previous_hash.clone(),
                            "proposer": proposed_block.validator_id.clone(),
                            "epoch": epoch_number,
                            "round": round_number,
                            "local_validator": local_validator_address.clone(),
                            "vote_count": votes.len(),
                            "elapsed_ms": timing_trace::duration_ms(collection_started.elapsed())
                        }),
                    );
                    qc_threshold_reported = true;
                }
                break;
            }

            thread::sleep(Duration::from_millis(100));
        }

        // Drain the mailbox one final time after the wait window closes so votes
        // that arrive right on the timeout edge still count toward this round.
        let pending_votes = Self::snapshot_network_votes(block_hash, epoch_number, round_number);
        self.merge_remote_votes_for_cluster(
            &mut votes,
            &expected_validators,
            block_hash,
            epoch_number,
            round_number,
            cluster_context.cluster_id,
            pending_votes,
        );

        self.apply_recorded_equivocations();
        votes.retain(|vote| {
            self.vote_is_eligible_for_collection_for_cluster(
                vote,
                block_hash,
                epoch_number,
                round_number,
                cluster_context.cluster_id,
            )
        });
        let final_quorum_met = self.has_commit_quorum_for_cluster(&cluster_context, &votes);
        if final_quorum_met && !qc_threshold_reported {
            timing_trace::emit(
                "qc_threshold_reached",
                serde_json::json!({
                    "height": proposed_block.block_index,
                    "block_hash": block_hash.to_string(),
                    "previous_hash": proposed_block.previous_hash.clone(),
                    "proposer": proposed_block.validator_id.clone(),
                    "epoch": epoch_number,
                    "round": round_number,
                    "local_validator": local_validator_address.clone(),
                    "vote_count": votes.len(),
                    "elapsed_ms": timing_trace::duration_ms(collection_started.elapsed()),
                    "after_deadline_drain": true
                }),
            );
        }
        self.record_vote_participation(&votes);
        if self.penalization_enabled {
            self.record_missed_vote_timeouts(consensus_validators, &votes);
        }

        if !final_quorum_met {
            let received_validators = votes
                .iter()
                .map(|vote| vote.validator_address.clone())
                .collect::<BTreeSet<_>>();
            let missing_validators = expected_validators
                .iter()
                .filter(|validator| !received_validators.contains(*validator))
                .cloned()
                .collect::<Vec<_>>();
            warn!(
            "consensus",
            "Vote collection ended without quorum",
            "height" => proposed_block.block_index,
            "block_hash" => block_hash.to_string(),
            "epoch" => epoch_number,
            "round" => round_number,
            "vote_count" => votes.len() as u64,
                "required_validator_votes" => required_validator_votes as u64,
                "missing_validators" => serde_json::to_string(&missing_validators).unwrap_or_default(),
                "elapsed_ms" => timing_trace::duration_ms(collection_started.elapsed()),
                "leader" => proposed_block.validator_id.clone(),
                "retry_number" => retry_number,
                "timeout_mode" => timeout_mode.to_string(),
                "reason" => "missed_quorum",
                "effective_vote_timeout_secs" => effective_vote_timeout_secs
            );
        }

        Self::reset_network_vote_mailbox(block_hash, epoch_number, round_number);
        self.votes.insert(block_hash.to_string(), votes.clone());
        Self::record_consensus_runtime_metrics(
            proposed_block,
            round_number,
            timeout_mode,
            effective_vote_timeout_secs,
            votes.len(),
            required_validator_votes,
            if final_quorum_met {
                "quorum_reached"
            } else {
                "missed_quorum"
            },
        );
        timing_trace::emit(
            "vote_collection_end",
            serde_json::json!({
                "height": proposed_block.block_index,
                "block_hash": block_hash.to_string(),
                "previous_hash": proposed_block.previous_hash.clone(),
                "proposer": proposed_block.validator_id.clone(),
                "epoch": epoch_number,
                "round": round_number,
                "vote_count": votes.len(),
                "required_validator_votes": required_validator_votes,
                "missing_validators": expected_validators
                    .iter()
                    .filter(|validator| {
                        !votes
                            .iter()
                            .any(|vote| &vote.validator_address == *validator)
                    })
                    .cloned()
                    .collect::<Vec<_>>(),
                "quorum_met": final_quorum_met,
                "leader": proposed_block.validator_id.clone(),
                "retry_number": retry_number,
                "timeout_mode": timeout_mode,
                "reason": if final_quorum_met { "quorum_reached" } else { "missed_quorum" },
                "elapsed_ms": timing_trace::duration_ms(collection_started.elapsed()),
                "effective_vote_timeout_secs": effective_vote_timeout_secs
            }),
        );
        Ok(votes)
    }

    pub fn build_local_vote_for_proposal(
        proposed_block: &Block,
        epoch_number: u64,
        round_number: u64,
    ) -> Result<Vote, String> {
        Self::build_local_vote_for_proposal_with_recovery(
            proposed_block,
            epoch_number,
            round_number,
            u64::MAX,
        )
    }

    pub fn build_local_vote_for_proposal_with_recovery(
        proposed_block: &Block,
        epoch_number: u64,
        round_number: u64,
        transient_vote_recovery_min_age_secs: u64,
    ) -> Result<Vote, String> {
        Self::validate_block_proposal_static(proposed_block)?;
        verify_block_proposer_key_matches_validator(proposed_block, &VALIDATOR_MANAGER)?;
        Self::validate_validator_activations(proposed_block, &VALIDATOR_MANAGER)?;

        let active_validators = consensus_membership_validators_for_height(
            VALIDATOR_MANAGER.get_all_validators(),
            proposed_block.block_index,
        )?;
        let cluster_context = Self::cluster_context_for_validators(
            &VALIDATOR_MANAGER,
            &active_validators,
            epoch_number,
            &proposed_block.validator_id,
        )?;
        if cluster_context.cluster_id.is_some()
            && VALIDATOR_MANAGER.get_current_epoch() != epoch_number
        {
            return Err(format!(
                "multi-cluster vote epoch {} does not match validator registry epoch {}",
                epoch_number,
                VALIDATOR_MANAGER.get_current_epoch()
            ));
        }

        let local_validator_address = Self::resolve_local_validator_address()
            .ok_or_else(|| "Local validator address is not configured for voting".to_string())?;
        if !cluster_context
            .validators
            .iter()
            .any(|validator| validator.address == local_validator_address)
        {
            return Err(format!(
                "Local validator {} is not in the canonical proposal cluster",
                local_validator_address
            ));
        }

        Self::recover_stale_conflicting_vote_lock_before_vote(
            &local_validator_address,
            proposed_block,
            epoch_number,
            round_number,
            transient_vote_recovery_min_age_secs,
            "remote vote-request transient lock reconciliation",
        )?;

        Self::register_local_vote_intent(
            &local_validator_address,
            proposed_block,
            epoch_number,
            round_number,
        )?;
        let vote = Self::create_vote_for_validator_with_manager(
            &local_validator_address,
            proposed_block,
            epoch_number,
            round_number,
            &VALIDATOR_MANAGER,
        )?;
        if let Some(evidence) = Self::register_local_vote_attempt(&vote) {
            return Err(format!(
                "Refusing to double-sign for validator {} at height {} in epoch {} round {}",
                evidence.validator_address,
                evidence.block_index,
                evidence.epoch_number,
                evidence.round_number
            ));
        }

        Ok(vote)
    }

    pub fn record_network_vote(vote: Vote) {
        if vote.validator_address.trim().is_empty() || vote.block_hash.trim().is_empty() {
            return;
        }

        if let Some(evidence) = Self::register_vote_observation(&vote) {
            warn!(
                "consensus",
                "Network vote conflicts with prior observation; retaining evidence and storing for recovery evaluation",
                "validator" => evidence.validator_address,
                "height" => evidence.block_index,
                "epoch" => evidence.epoch_number,
                "round" => evidence.round_number,
                "first_block_hash" => evidence.first_vote.block_hash,
                "conflicting_block_hash" => evidence.conflicting_vote.block_hash
            );
        }
        timing_trace::emit(
            "vote_response_received_by_proposer",
            serde_json::json!({
                "height": vote.block_index,
                "block_hash": vote.block_hash.clone(),
                "validator": vote.validator_address.clone(),
                "epoch": vote.epoch_number,
                "round": vote.round_number,
                "vote_timestamp": vote.timestamp
            }),
        );

        let key = Self::vote_mailbox_key(&vote.block_hash, vote.epoch_number, vote.round_number);
        if let Ok(mut mailbox) = NETWORK_VOTE_MAILBOX.lock() {
            let entry = mailbox.entry(key).or_default();
            if entry
                .iter()
                .all(|existing| existing.validator_address != vote.validator_address)
            {
                entry.push(vote);
            }
        }
    }

    pub fn record_committed_qc(qc: QuorumCertificate) {
        if let Err(error) = Self::record_committed_qc_checked(qc) {
            warn!(
                "consensus",
                "Failed to append committed quorum certificate",
                "error" => error
            );
        }
    }

    pub fn record_committed_qc_checked(qc: QuorumCertificate) -> Result<(), String> {
        Self::ensure_committed_qc_store_loaded();
        let mut store = COMMITTED_QC_STORE
            .lock()
            .map_err(|_| "failed to lock committed QC store".to_string())?;
        if store.contains_key(&qc.block_hash) {
            return Ok(());
        }

        Self::append_committed_qc_to_log(&qc)?;
        store.insert(qc.block_hash.clone(), qc);
        Self::prune_committed_qc_store_for_retention(&mut store);
        Ok(())
    }

    pub fn record_committed_qcs_checked(qcs: &[QuorumCertificate]) -> Result<(), String> {
        if qcs.is_empty() {
            return Ok(());
        }

        Self::ensure_committed_qc_store_loaded();
        let mut store = COMMITTED_QC_STORE
            .lock()
            .map_err(|_| "failed to lock committed QC store".to_string())?;
        let mut pending = Vec::new();
        let mut pending_hashes = HashSet::new();
        for qc in qcs {
            if !store.contains_key(&qc.block_hash) && pending_hashes.insert(qc.block_hash.clone()) {
                pending.push(qc.clone());
            }
        }
        if pending.is_empty() {
            return Ok(());
        }

        Self::append_committed_qcs_to_log(&pending)?;
        for qc in pending {
            store.insert(qc.block_hash.clone(), qc);
        }
        Self::prune_committed_qc_store_for_retention(&mut store);
        Ok(())
    }

    pub fn committed_qc_for_block_hash(block_hash: &str) -> Option<QuorumCertificate> {
        Self::ensure_committed_qc_store_loaded();
        COMMITTED_QC_STORE
            .lock()
            .ok()
            .and_then(|store| store.get(block_hash).cloned())
    }

    pub fn committed_qcs_for_block_hashes<I, S>(block_hashes: I) -> Vec<QuorumCertificate>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut missing = block_hashes
            .into_iter()
            .map(|hash| hash.as_ref().trim().to_string())
            .filter(|hash| !hash.is_empty())
            .collect::<HashSet<_>>();
        if missing.is_empty() {
            return Vec::new();
        }

        Self::ensure_committed_qc_store_loaded();
        let mut found = Vec::new();
        if let Ok(store) = COMMITTED_QC_STORE.lock() {
            let hot_matches = missing
                .iter()
                .filter_map(|hash| store.get(hash).cloned())
                .collect::<Vec<_>>();
            for qc in hot_matches {
                missing.remove(&qc.block_hash);
                found.push(qc);
            }
        }
        if missing.is_empty() {
            return found;
        }

        match Self::committed_qcs_from_log_for_block_hashes(&missing) {
            Ok(mut historical) => {
                found.append(&mut historical);
            }
            Err(error) => {
                warn!(
                    "consensus",
                    "Failed to load historical committed quorum certificates",
                    "error" => error
                );
            }
        }
        found
    }

    fn committed_qcs_from_log_for_block_hashes(
        block_hashes: &HashSet<String>,
    ) -> Result<Vec<QuorumCertificate>, String> {
        if block_hashes.is_empty() {
            return Ok(Vec::new());
        }

        let log_path = Self::committed_qc_log_path();
        let mut file = fs::File::open(&log_path)
            .map_err(|err| format!("failed to open committed QC log {:?}: {err}", log_path))?;
        let file_len = file
            .metadata()
            .map_err(|err| format!("failed to stat committed QC log {:?}: {err}", log_path))?
            .len();
        let mut index = COMMITTED_QC_LOG_LOOKUP_INDEX
            .lock()
            .map_err(|_| "failed to lock committed QC log lookup index".to_string())?;
        Self::refresh_committed_qc_log_lookup_index(&mut index, &mut file, &log_path, file_len)?;

        let mut remaining = block_hashes.clone();
        let mut found = Vec::new();
        Self::load_committed_qcs_from_log_index(
            &mut index,
            &mut file,
            &log_path,
            &mut remaining,
            &mut found,
        )?;

        if !remaining.is_empty() {
            let scan_start = index.forward_scan_offset;
            let scan_end = Self::scan_committed_qc_log_forward(
                &mut index,
                &mut file,
                &log_path,
                scan_start,
                file_len,
                &mut remaining,
                &mut found,
            )?;
            index.forward_scan_offset = scan_end;

            // A request can move backwards after the cursor has advanced. The
            // bounded index may have evicted that older entry, so fall back to
            // a complete forward scan to preserve historical correctness.
            if !remaining.is_empty() && scan_start > 0 {
                let fallback_end = Self::scan_committed_qc_log_forward(
                    &mut index,
                    &mut file,
                    &log_path,
                    0,
                    file_len,
                    &mut remaining,
                    &mut found,
                )?;
                index.forward_scan_offset = fallback_end;
            }
        }
        Ok(found)
    }

    fn refresh_committed_qc_log_lookup_index(
        index: &mut CommittedQcLogLookupIndex,
        file: &mut fs::File,
        log_path: &Path,
        file_len: u64,
    ) -> Result<(), String> {
        index.reset_for_path(log_path);
        if index.initialized && file_len < index.indexed_file_len {
            index.reset_after_truncation();
        }

        if !index.initialized {
            if file_len > 0 {
                Self::index_committed_qc_log_tail(index, file, log_path, file_len)?;
            }
            index.initialized = true;
            index.indexed_file_len = file_len;
            index.indexed_end = file_len;
            return Ok(());
        }

        if file_len == index.indexed_file_len {
            return Ok(());
        }

        let append_start = index.indexed_end;
        let append_is_line_aligned = append_start <= file_len
            && (append_start == 0
                || Self::committed_qc_log_byte_is_newline(file, append_start - 1)?);
        if !append_is_line_aligned {
            index.reset_after_truncation();
            if file_len > 0 {
                Self::index_committed_qc_log_tail(index, file, log_path, file_len)?;
            }
            index.initialized = true;
            index.indexed_file_len = file_len;
            index.indexed_end = file_len;
            return Ok(());
        }

        Self::index_committed_qc_log_range(index, file, log_path, append_start, file_len, false)?;
        index.indexed_file_len = file_len;
        index.indexed_end = file_len;
        Ok(())
    }

    fn index_committed_qc_log_tail(
        index: &mut CommittedQcLogLookupIndex,
        file: &mut fs::File,
        log_path: &Path,
        file_len: u64,
    ) -> Result<(), String> {
        index.clear_entries();
        index.forward_scan_offset = 0;
        let start = file_len.saturating_sub(Self::configured_committed_qc_hot_load_max_bytes());
        let skip_partial_first_line =
            start > 0 && !Self::committed_qc_log_byte_is_newline(file, start - 1)?;
        Self::index_committed_qc_log_range(
            index,
            file,
            log_path,
            start,
            file_len,
            skip_partial_first_line,
        )?;
        index.initialized = true;
        index.indexed_file_len = file_len;
        index.indexed_end = file_len;
        Ok(())
    }

    fn index_committed_qc_log_range(
        index: &mut CommittedQcLogLookupIndex,
        file: &mut fs::File,
        log_path: &Path,
        start: u64,
        end: u64,
        skip_partial_first_line: bool,
    ) -> Result<(), String> {
        if start >= end {
            return Ok(());
        }

        file.seek(SeekFrom::Start(start)).map_err(|err| {
            format!(
                "failed to seek committed QC log {:?} to byte {}: {err}",
                log_path, start
            )
        })?;
        let mut reader = BufReader::new(file.take(end.saturating_sub(start)));
        let mut offset = start;
        let mut line = String::new();

        if skip_partial_first_line {
            let bytes_read = reader.read_line(&mut line).map_err(|err| {
                format!(
                    "failed to read committed QC log {:?} at byte offset {}: {err}",
                    log_path, offset
                )
            })?;
            offset = offset.saturating_add(bytes_read as u64);
            line.clear();
        }

        loop {
            let line_start = offset;
            let bytes_read = reader.read_line(&mut line).map_err(|err| {
                format!(
                    "failed to read committed QC log {:?} at byte offset {}: {err}",
                    log_path, line_start
                )
            })?;
            if bytes_read == 0 {
                break;
            }
            offset = offset.saturating_add(bytes_read as u64);
            if let Some(entry) = Self::parse_committed_qc_log_line(&line, log_path, line_start)? {
                index.insert(entry.block_hash, line_start);
            }
            line.clear();
        }
        Ok(())
    }

    fn scan_committed_qc_log_forward(
        index: &mut CommittedQcLogLookupIndex,
        file: &mut fs::File,
        log_path: &Path,
        start: u64,
        end: u64,
        remaining: &mut HashSet<String>,
        found: &mut Vec<QuorumCertificate>,
    ) -> Result<u64, String> {
        if start >= end {
            return Ok(start);
        }

        file.seek(SeekFrom::Start(start)).map_err(|err| {
            format!(
                "failed to seek committed QC log {:?} to byte {}: {err}",
                log_path, start
            )
        })?;
        let mut reader = BufReader::new(file.take(end.saturating_sub(start)));
        let mut offset = start;
        let mut line = String::new();

        loop {
            let line_start = offset;
            let bytes_read = reader.read_line(&mut line).map_err(|err| {
                format!(
                    "failed to read committed QC log {:?} at byte offset {}: {err}",
                    log_path, line_start
                )
            })?;
            if bytes_read == 0 {
                break;
            }
            offset = offset.saturating_add(bytes_read as u64);
            if let Some(entry) = Self::parse_committed_qc_log_line(&line, log_path, line_start)? {
                let block_hash = entry.block_hash.clone();
                index.insert(block_hash.clone(), line_start);
                if remaining.remove(&block_hash) {
                    found.push(entry.qc);
                    if remaining.is_empty() {
                        return Ok(offset);
                    }
                }
            }
            line.clear();
        }
        Ok(offset)
    }

    fn load_committed_qcs_from_log_index(
        index: &mut CommittedQcLogLookupIndex,
        file: &mut fs::File,
        log_path: &Path,
        remaining: &mut HashSet<String>,
        found: &mut Vec<QuorumCertificate>,
    ) -> Result<(), String> {
        let indexed_offsets = remaining
            .iter()
            .filter_map(|block_hash| {
                index
                    .offsets
                    .get(block_hash)
                    .copied()
                    .map(|offset| (block_hash.clone(), offset))
            })
            .collect::<Vec<_>>();

        for (requested_hash, offset) in indexed_offsets {
            let entry = Self::read_committed_qc_log_entry_at_offset(file, log_path, offset)?;
            if entry.block_hash != requested_hash {
                index.remove_if_matches(&requested_hash, offset);
                continue;
            }
            if remaining.remove(&requested_hash) {
                found.push(entry.qc);
            }
        }
        Ok(())
    }

    fn read_committed_qc_log_entry_at_offset(
        file: &fs::File,
        log_path: &Path,
        offset: u64,
    ) -> Result<CommittedQcLogEntry, String> {
        let mut reader = BufReader::new(file.try_clone().map_err(|err| {
            format!(
                "failed to clone committed QC log {:?} for byte offset {}: {err}",
                log_path, offset
            )
        })?);
        reader.seek(SeekFrom::Start(offset)).map_err(|err| {
            format!(
                "failed to seek committed QC log {:?} to byte {}: {err}",
                log_path, offset
            )
        })?;
        let mut line = String::new();
        let bytes_read = reader.read_line(&mut line).map_err(|err| {
            format!(
                "failed to read committed QC log {:?} at byte offset {}: {err}",
                log_path, offset
            )
        })?;
        if bytes_read == 0 {
            return Err(format!(
                "committed QC log {:?} offset {} is past EOF",
                log_path, offset
            ));
        }
        Self::parse_committed_qc_log_line(&line, log_path, offset)?.ok_or_else(|| {
            format!(
                "committed QC log {:?} offset {} points to an empty line",
                log_path, offset
            )
        })
    }

    fn parse_committed_qc_log_line(
        line: &str,
        log_path: &Path,
        offset: u64,
    ) -> Result<Option<CommittedQcLogEntry>, String> {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            return Ok(None);
        }
        #[cfg(test)]
        COMMITTED_QC_LOG_PARSE_COUNT.fetch_add(1, Ordering::Relaxed);
        serde_json::from_str::<CommittedQcLogEntry>(trimmed)
            .map(Some)
            .map_err(|err| {
                format!(
                    "failed to parse committed QC log {:?} at byte offset {}: {err}",
                    log_path, offset
                )
            })
    }

    fn committed_qc_log_byte_is_newline(file: &mut fs::File, offset: u64) -> Result<bool, String> {
        file.seek(SeekFrom::Start(offset))
            .map_err(|err| format!("failed to inspect committed QC log byte {}: {err}", offset))?;
        let mut byte = [0_u8; 1];
        file.read_exact(&mut byte)
            .map_err(|err| format!("failed to read committed QC log byte {}: {err}", offset))?;
        Ok(byte[0] == b'\n')
    }

    fn ensure_committed_qc_store_loaded() {
        COMMITTED_QC_STORE_INIT.call_once(|| match Self::load_committed_qc_store_from_disk() {
            Ok(loaded) => {
                if let Ok(mut store) = COMMITTED_QC_STORE.lock() {
                    for (block_hash, qc) in loaded {
                        store.entry(block_hash).or_insert(qc);
                    }
                }
            }
            Err(error) => {
                warn!(
                    "consensus",
                    "Failed to load committed quorum certificate store",
                    "error" => error
                );
            }
        });
    }

    fn committed_qc_store_path() -> PathBuf {
        if let Ok(path) = std::env::var("SYNERGY_COMMITTED_QC_STORE_FILE") {
            let trimmed = path.trim();
            if !trimmed.is_empty() {
                return PathBuf::from(trimmed);
            }
        }

        #[cfg(test)]
        {
            return crate::utils::test_temp_root(format!(
                "synergy-test-committed-qcs-{}.json",
                std::process::id()
            ));
        }

        #[cfg(not(test))]
        {
            crate::utils::resolve_data_path("data/committed_qcs.json")
        }
    }

    fn committed_qc_log_path() -> PathBuf {
        let mut path = Self::committed_qc_store_path();
        path.set_extension("jsonl");
        path
    }

    fn load_committed_qc_store_from_disk() -> Result<HashMap<String, QuorumCertificate>, String> {
        // The JSONL journal is archival. Only its bounded tail is materialized into the hot store.
        let path = Self::committed_qc_store_path();
        let mut loaded = HashMap::new();
        let retention_blocks = Self::configured_committed_qc_hot_retention_blocks();
        let max_load_bytes = Self::configured_committed_qc_hot_load_max_bytes();
        let mut latest_height = 0_u64;
        let mut seen_log_entries = 0_usize;

        if path.exists() {
            let legacy_size = fs::metadata(&path)
                .map_err(|err| format!("failed to stat committed QC store {:?}: {err}", path))?
                .len();
            if legacy_size <= max_load_bytes {
                let data = fs::read(&path).map_err(|err| {
                    format!("failed to read committed QC store {:?}: {err}", path)
                })?;
                if !data.is_empty() {
                    let legacy =
                        serde_json::from_slice::<BTreeMap<String, QuorumCertificate>>(&data)
                            .map_err(|err| {
                                format!("failed to parse committed QC store {:?}: {err}", path)
                            })?;
                    for (block_hash, qc) in legacy {
                        Self::insert_committed_qc_with_retention(
                            &mut loaded,
                            block_hash,
                            qc,
                            retention_blocks,
                            &mut latest_height,
                        );
                    }
                    Self::prune_committed_qc_store_for_retention_with_latest(
                        &mut loaded,
                        retention_blocks,
                        latest_height,
                    );
                }
            } else {
                warn!(
                    "consensus",
                    "Skipping oversized legacy committed QC snapshot during bounded startup load",
                    "path" => path.display().to_string(),
                    "bytes" => legacy_size,
                    "max_load_bytes" => max_load_bytes
                );
            }
        }

        let log_path = Self::committed_qc_log_path();
        if log_path.exists() {
            let tail = Self::read_committed_qc_log_tail(&log_path, max_load_bytes)?;
            for entry in tail {
                Self::insert_committed_qc_with_retention(
                    &mut loaded,
                    entry.block_hash,
                    entry.qc,
                    retention_blocks,
                    &mut latest_height,
                );
                seen_log_entries = seen_log_entries.saturating_add(1);
                if retention_blocks.is_some()
                    && seen_log_entries % COMMITTED_QC_RETENTION_PRUNE_INTERVAL == 0
                {
                    Self::prune_committed_qc_store_for_retention_with_latest(
                        &mut loaded,
                        retention_blocks,
                        latest_height,
                    );
                }
            }
        }

        Self::prune_committed_qc_store_for_retention_with_latest(
            &mut loaded,
            retention_blocks,
            latest_height,
        );
        Self::trim_allocator_after_hot_retention();
        Ok(loaded)
    }

    fn read_committed_qc_log_tail(
        log_path: &Path,
        max_load_bytes: u64,
    ) -> Result<Vec<CommittedQcLogEntry>, String> {
        let mut file = fs::File::open(log_path)
            .map_err(|err| format!("failed to open committed QC log {:?}: {err}", log_path))?;
        let file_len = file
            .metadata()
            .map_err(|err| format!("failed to stat committed QC log {:?}: {err}", log_path))?
            .len();
        if file_len == 0 {
            return Ok(Vec::new());
        }

        let start = file_len.saturating_sub(max_load_bytes);
        let starts_mid_line = if start == 0 {
            false
        } else {
            file.seek(SeekFrom::Start(start - 1)).map_err(|err| {
                format!(
                    "failed to inspect bounded committed QC log boundary {:?}: {err}",
                    log_path
                )
            })?;
            let mut previous = [0_u8; 1];
            file.read_exact(&mut previous).map_err(|err| {
                format!(
                    "failed to read bounded committed QC log boundary {:?}: {err}",
                    log_path
                )
            })?;
            previous[0] != b'\n'
        };
        file.seek(SeekFrom::Start(start)).map_err(|err| {
            format!(
                "failed to seek to bounded committed QC log tail {:?}: {err}",
                log_path
            )
        })?;
        let read_len = file_len.saturating_sub(start);
        let mut tail = Vec::with_capacity(read_len.min(usize::MAX as u64) as usize);
        file.take(read_len).read_to_end(&mut tail).map_err(|err| {
            format!(
                "failed to read bounded committed QC log tail {:?}: {err}",
                log_path
            )
        })?;

        let mut entries = Vec::new();
        for (index, line) in tail.split(|byte| *byte == b'\n').enumerate() {
            if starts_mid_line && index == 0 {
                continue;
            }
            let trimmed = Self::trim_ascii_whitespace(line);
            if trimmed.is_empty() {
                continue;
            }
            let entry = serde_json::from_slice::<CommittedQcLogEntry>(trimmed).map_err(|err| {
                format!(
                    "failed to parse bounded committed QC log tail {:?} segment {}: {err}",
                    log_path,
                    index + 1
                )
            })?;
            entries.push(entry);
        }
        Ok(entries)
    }

    fn trim_ascii_whitespace(bytes: &[u8]) -> &[u8] {
        let start = bytes
            .iter()
            .position(|byte| !byte.is_ascii_whitespace())
            .unwrap_or(bytes.len());
        let end = bytes
            .iter()
            .rposition(|byte| !byte.is_ascii_whitespace())
            .map(|index| index + 1)
            .unwrap_or(start);
        &bytes[start..end]
    }

    fn insert_committed_qc_with_retention(
        store: &mut HashMap<String, QuorumCertificate>,
        block_hash: String,
        qc: QuorumCertificate,
        retention_blocks: Option<u64>,
        latest_height: &mut u64,
    ) {
        let qc_height = Self::committed_qc_height(&qc);
        if let Some(height) = qc_height {
            *latest_height = (*latest_height).max(height);
        }

        if Self::committed_qc_is_within_retention(qc_height, retention_blocks, *latest_height) {
            store.insert(block_hash, qc);
        }
    }

    fn committed_qc_height(qc: &QuorumCertificate) -> Option<u64> {
        qc.votes
            .iter()
            .map(|vote| vote.block_index)
            .filter(|height| *height > 0)
            .max()
    }

    fn configured_committed_qc_hot_retention_blocks() -> Option<u64> {
        env::var(COMMITTED_QC_HOT_RETENTION_BLOCKS_ENV)
            .ok()
            .and_then(|value| value.trim().parse::<u64>().ok())
            .filter(|value| *value > 0)
    }

    fn configured_committed_qc_hot_load_max_bytes() -> u64 {
        env::var(COMMITTED_QC_HOT_LOAD_MAX_BYTES_ENV)
            .ok()
            .and_then(|value| value.trim().parse::<u64>().ok())
            .filter(|value| *value > 0)
            .unwrap_or(DEFAULT_COMMITTED_QC_HOT_LOAD_MAX_BYTES)
            .min(HARD_MAX_COMMITTED_QC_HOT_LOAD_BYTES)
    }

    fn committed_qc_is_within_retention(
        qc_height: Option<u64>,
        retention_blocks: Option<u64>,
        latest_height: u64,
    ) -> bool {
        let Some(retention_blocks) = retention_blocks else {
            return true;
        };
        let Some(qc_height) = qc_height else {
            return true;
        };
        if latest_height < retention_blocks {
            return true;
        }
        qc_height
            >= latest_height
                .saturating_sub(retention_blocks)
                .saturating_add(1)
    }

    fn prune_committed_qc_store_for_retention(
        store: &mut HashMap<String, QuorumCertificate>,
    ) -> usize {
        let retention_blocks = Self::configured_committed_qc_hot_retention_blocks();
        let latest_height = store
            .values()
            .filter_map(Self::committed_qc_height)
            .max()
            .unwrap_or(0);
        Self::prune_committed_qc_store_for_retention_with_latest(
            store,
            retention_blocks,
            latest_height,
        )
    }

    fn prune_committed_qc_store_for_retention_with_latest(
        store: &mut HashMap<String, QuorumCertificate>,
        retention_blocks: Option<u64>,
        latest_height: u64,
    ) -> usize {
        if retention_blocks.is_none() || latest_height == 0 {
            return 0;
        }
        let before = store.len();
        store.retain(|_, qc| {
            Self::committed_qc_is_within_retention(
                Self::committed_qc_height(qc),
                retention_blocks,
                latest_height,
            )
        });
        let removed = before.saturating_sub(store.len());
        if removed > 0 {
            Self::trim_allocator_after_hot_retention();
        }
        removed
    }

    fn trim_allocator_after_hot_retention() {
        #[cfg(target_os = "linux")]
        unsafe {
            libc::malloc_trim(0);
        }
    }

    fn append_committed_qc_to_log(qc: &QuorumCertificate) -> Result<(), String> {
        Self::append_committed_qcs_to_log(std::slice::from_ref(qc))
    }

    fn append_committed_qcs_to_log(qcs: &[QuorumCertificate]) -> Result<(), String> {
        if qcs.is_empty() {
            return Ok(());
        }

        let path = Self::committed_qc_log_path();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .map_err(|err| format!("failed to create committed QC log directory: {err}"))?;
        }

        let mut options = OpenOptions::new();
        options.create(true).append(true);
        #[cfg(unix)]
        options.mode(0o600);
        let mut file = options
            .open(&path)
            .map_err(|err| format!("failed to open committed QC log file: {err}"))?;
        for qc in qcs {
            let entry = CommittedQcLogEntry {
                block_hash: qc.block_hash.clone(),
                qc: qc.clone(),
            };
            let serialized = serde_json::to_vec(&entry)
                .map_err(|err| format!("failed to encode committed QC log entry: {err}"))?;
            file.write_all(&serialized)
                .map_err(|err| format!("failed to write committed QC log entry: {err}"))?;
            file.write_all(b"\n")
                .map_err(|err| format!("failed to write committed QC log newline: {err}"))?;
        }
        file.sync_all()
            .map_err(|err| format!("failed to sync committed QC log file: {err}"))
    }

    pub(crate) fn create_vote_for_validator(
        validator_address: &str,
        proposed_block: &Block,
        epoch_number: u64,
        round_number: u64,
    ) -> Result<Vote, String> {
        Self::create_vote_for_validator_with_manager(
            validator_address,
            proposed_block,
            epoch_number,
            round_number,
            &VALIDATOR_MANAGER,
        )
    }

    pub(crate) fn create_vote_for_validator_with_manager(
        validator_address: &str,
        proposed_block: &Block,
        epoch_number: u64,
        round_number: u64,
        validator_manager: &Arc<ValidatorManager>,
    ) -> Result<Vote, String> {
        Self::validate_validator_activations(proposed_block, validator_manager)?;
        assert_epoch_validator_set_compatible_for_height(proposed_block.block_index).map_err(
            |error| {
                format!("refusing vote because validator-set snapshot is incompatible: {error}")
            },
        )?;
        let active_validators = consensus_membership_validators_for_height(
            validator_manager.get_all_validators(),
            proposed_block.block_index,
        )?;
        let cluster_context = Self::cluster_context_for_validators(
            validator_manager,
            &active_validators,
            epoch_number,
            &proposed_block.validator_id,
        )?;
        if cluster_context.cluster_id.is_some()
            && validator_manager.get_current_epoch() != epoch_number
        {
            return Err(format!(
                "multi-cluster vote epoch {} does not match validator registry epoch {}",
                epoch_number,
                validator_manager.get_current_epoch()
            ));
        }
        if !cluster_context
            .validators
            .iter()
            .any(|validator| validator.address == validator_address)
        {
            return Err(format!(
                "validator {} is not in the canonical proposal cluster",
                validator_address
            ));
        }
        let timestamp = Self::current_timestamp();
        let message = Self::vote_signature_payload(
            validator_address,
            &proposed_block.hash,
            proposed_block.block_index,
            epoch_number,
            round_number,
            cluster_context.cluster_id,
        );

        let sign_started = Instant::now();
        timing_trace::emit(
            "pqc_vote_sign_start",
            serde_json::json!({
                "height": proposed_block.block_index,
                "block_hash": proposed_block.hash.clone(),
                "previous_hash": proposed_block.previous_hash.clone(),
                "proposer": proposed_block.validator_id.clone(),
                "validator": validator_address,
                "epoch": epoch_number,
                "round": round_number
            }),
        );
        let sign_result = sign_with_local_validator_key_for_height(
            proposed_block.block_index,
            validator_address,
            message.as_bytes(),
            validator_manager,
        );
        let sign_duration_ms = timing_trace::duration_ms(sign_started.elapsed());
        let (public_key, signature) = match sign_result {
            Ok(result) => {
                timing_trace::emit(
                    "pqc_vote_sign_end",
                    serde_json::json!({
                        "height": proposed_block.block_index,
                        "block_hash": proposed_block.hash.clone(),
                        "previous_hash": proposed_block.previous_hash.clone(),
                        "proposer": proposed_block.validator_id.clone(),
                        "validator": validator_address,
                        "epoch": epoch_number,
                        "round": round_number,
                        "duration_ms": sign_duration_ms,
                        "status": "ok"
                    }),
                );
                result
            }
            Err(error) => {
                timing_trace::emit(
                    "pqc_vote_sign_end",
                    serde_json::json!({
                        "height": proposed_block.block_index,
                        "block_hash": proposed_block.hash.clone(),
                        "previous_hash": proposed_block.previous_hash.clone(),
                        "proposer": proposed_block.validator_id.clone(),
                        "validator": validator_address,
                        "epoch": epoch_number,
                        "round": round_number,
                        "duration_ms": sign_duration_ms,
                        "status": "error",
                        "error": error
                    }),
                );
                return Err(error);
            }
        };

        Ok(Vote {
            validator_address: validator_address.to_string(),
            block_hash: proposed_block.hash.clone(),
            block_index: proposed_block.block_index,
            epoch_number,
            round_number,
            signature,
            signer_public_key: public_key.key_data,
            timestamp,
        })
    }

    fn merge_remote_votes(
        &self,
        votes: &mut Vec<Vote>,
        expected_validators: &BTreeSet<String>,
        block_hash: &str,
        epoch_number: u64,
        round_number: u64,
        pending_votes: Vec<Vote>,
    ) {
        self.merge_remote_votes_for_cluster(
            votes,
            expected_validators,
            block_hash,
            epoch_number,
            round_number,
            None,
            pending_votes,
        );
    }

    fn merge_remote_votes_for_cluster(
        &self,
        votes: &mut Vec<Vote>,
        expected_validators: &BTreeSet<String>,
        block_hash: &str,
        epoch_number: u64,
        round_number: u64,
        expected_cluster_id: Option<u64>,
        pending_votes: Vec<Vote>,
    ) {
        let mut seen_validators = votes
            .iter()
            .map(|vote| vote.validator_address.clone())
            .collect::<BTreeSet<_>>();
        let mut cached_votes = Vec::new();
        let mut uncached_votes = Vec::new();

        for vote in pending_votes {
            if vote.block_hash != block_hash
                || vote.epoch_number != epoch_number
                || vote.round_number > round_number
            {
                continue;
            }
            if Self::has_equivocation_evidence(
                &vote.validator_address,
                vote.epoch_number,
                vote.block_index,
                vote.round_number,
            ) {
                if vote.round_number < round_number {
                    warn!(
                        "consensus",
                        "Accepting prior-round same-block recovery vote despite retained equivocation evidence",
                        "validator" => vote.validator_address.clone(),
                        "block_hash" => vote.block_hash.clone(),
                        "height" => vote.block_index,
                        "epoch" => vote.epoch_number,
                        "vote_round" => vote.round_number,
                        "collection_round" => round_number
                    );
                } else {
                    warn!(
                        "consensus",
                        "Discarding equivocating vote",
                        "validator" => vote.validator_address.clone(),
                        "block_hash" => vote.block_hash.clone(),
                        "height" => vote.block_index,
                        "epoch" => vote.epoch_number,
                        "round" => vote.round_number
                    );
                    continue;
                }
            }
            if !expected_validators.contains(&vote.validator_address) {
                continue;
            }
            if !self.vote_is_eligible_for_collection_for_cluster(
                &vote,
                block_hash,
                epoch_number,
                round_number,
                expected_cluster_id,
            ) {
                continue;
            }
            if seen_validators.contains(&vote.validator_address) {
                continue;
            }

            let cache_key = Self::vote_signature_cache_key(&vote);
            if self.vote_signature_cache_contains(&cache_key) {
                cached_votes.push(vote);
            } else {
                uncached_votes.push((vote, cache_key));
            }
        }

        for vote in cached_votes {
            if seen_validators.insert(vote.validator_address.clone()) {
                votes.push(vote);
            }
        }

        let mut handles = Vec::new();
        for (vote, cache_key) in uncached_votes {
            handles.push(Self::spawn_vote_signature_verification_with_key(
                vote,
                cache_key,
                Arc::clone(&self.validator_manager),
            ));
        }

        for handle in handles {
            let Ok((vote, cache_key, verification)) = handle.join() else {
                warn!(
                    "consensus",
                    "Remote vote verification worker panicked",
                    "block_hash" => block_hash.to_string(),
                    "epoch" => epoch_number,
                    "round" => round_number
                );
                continue;
            };

            if let Err(error) = verification {
                warn!(
                    "consensus",
                    "Discarding invalid remote vote",
                    "validator" => vote.validator_address.clone(),
                    "block_hash" => vote.block_hash.clone(),
                    "epoch" => vote.epoch_number,
                    "round" => vote.round_number,
                    "error" => error
                );
                continue;
            }

            if !seen_validators.insert(vote.validator_address.clone()) {
                continue;
            }
            self.cache_verified_vote_signature(cache_key);
            votes.push(vote);
        }
    }

    fn spawn_vote_signature_verification_with_key(
        vote: Vote,
        cache_key: String,
        validator_manager: Arc<ValidatorManager>,
    ) -> thread::JoinHandle<(Vote, String, Result<(), String>)> {
        thread::spawn(move || {
            let verify_started = Instant::now();
            timing_trace::emit(
                "pqc_vote_verify_start",
                serde_json::json!({
                    "height": vote.block_index,
                    "block_hash": vote.block_hash.clone(),
                    "validator": vote.validator_address.clone(),
                    "epoch": vote.epoch_number,
                    "round": vote.round_number
                }),
            );
            let verification = Self::verify_vote_signature_uncached(&vote, &validator_manager);
            timing_trace::emit(
                "pqc_vote_verify_end",
                serde_json::json!({
                    "height": vote.block_index,
                    "block_hash": vote.block_hash.clone(),
                    "validator": vote.validator_address.clone(),
                    "epoch": vote.epoch_number,
                    "round": vote.round_number,
                    "duration_ms": timing_trace::duration_ms(verify_started.elapsed()),
                    "status": if verification.is_ok() { "ok" } else { "error" },
                    "error": verification.as_ref().err().cloned()
                }),
            );
            (vote, cache_key, verification)
        })
    }

    fn check_quorums_and_commit(
        &mut self,
        proposed_block: &Block,
        epoch_number: u64,
        round_number: u64,
        votes: &[Vote],
    ) -> Result<QuorumCertificate, String> {
        let cluster_context = self.cluster_context_for_proposal(proposed_block, epoch_number)?;
        let (validator_count, signed_voting_weight, total_voting_weight) = self
            .cluster_vote_summary(&cluster_context.validators, votes)
            .map_err(|error| format!("invalid cluster vote set: {error}"))?;

        let consensus_membership =
            self.consensus_membership_for_height(proposed_block.block_index)?;
        if consensus_membership.len() < self.minimum_validator_count {
            return Err(format!(
                "Insufficient active validators: {} active, {} required",
                consensus_membership.len(),
                self.minimum_validator_count
            ));
        }

        let required_validator_votes =
            self.required_validator_votes_for_cluster_context(&cluster_context);
        if validator_count < required_validator_votes {
            return Err(format!(
                "Insufficient validator votes: {} votes, {} required for quorum",
                validator_count, required_validator_votes
            ));
        }
        if !strict_voting_weight_quorum(signed_voting_weight, total_voting_weight) {
            return Err(format!(
                "Insufficient frozen voting weight: signed_weight={signed_voting_weight}, total_weight={total_voting_weight}; strict greater-than-two-thirds required"
            ));
        }

        // Consensus vote power is one active validator, one vote. Synergy Score
        // affects rewards and rotation policy, never finality.
        let validation_quorum_met = validator_count >= required_validator_votes;
        let cooperation_quorum_met = validator_count >= required_validator_votes;

        if validation_quorum_met && cooperation_quorum_met {
            let qc = self.create_quorum_certificate(
                &proposed_block.hash,
                epoch_number,
                round_number,
                votes,
                &cluster_context,
            )?;
            self.quorum_certificates
                .insert(proposed_block.hash.clone(), qc.clone());
            Ok(qc)
        } else {
            Err("Quorum thresholds not met".to_string())
        }
    }

    fn required_validator_votes(&self, total_validators: usize) -> usize {
        required_validator_quorum(total_validators).max(1)
    }

    fn required_validator_votes_for_cluster_context(
        &self,
        cluster_context: &ConsensusClusterContext,
    ) -> usize {
        if cluster_context.cluster_id.is_some() {
            required_cluster_quorum(cluster_context.validators.len()).max(1)
        } else {
            self.required_validator_votes(cluster_context.validators.len())
        }
    }

    #[cfg(test)]
    fn has_commit_quorum(&self, live_validators: &[Validator], votes: &[Vote]) -> bool {
        if live_validators.is_empty() {
            return false;
        }

        let Ok((validator_count, signed_voting_weight, total_voting_weight)) =
            self.cluster_vote_summary(live_validators, votes)
        else {
            return false;
        };
        let required_validator_votes = self.required_validator_votes(live_validators.len());
        validator_count >= required_validator_votes
            && strict_voting_weight_quorum(signed_voting_weight, total_voting_weight)
    }

    fn cluster_vote_summary(
        &self,
        cluster_validators: &[Validator],
        votes: &[Vote],
    ) -> Result<(usize, u128, u128), String> {
        let weights = cluster_validators
            .iter()
            .map(|validator| {
                if validator.stake_amount == 0 {
                    return Err(format!(
                        "validator {} has zero bonded voting weight",
                        validator.address
                    ));
                }
                Ok((
                    validator.address.clone(),
                    u128::from(validator.stake_amount),
                ))
            })
            .collect::<Result<HashMap<_, _>, String>>()?;
        let total_voting_weight = weights
            .values()
            .try_fold(0u128, |total, weight| total.checked_add(*weight))
            .ok_or_else(|| "canonical validator voting weight overflow".to_string())?;
        let mut seen = BTreeSet::new();
        let mut signed_voting_weight = 0u128;

        for vote in votes {
            let Some(weight) = weights.get(&vote.validator_address) else {
                return Err(format!(
                    "vote from {} is outside the canonical target cluster",
                    vote.validator_address
                ));
            };
            if !seen.insert(vote.validator_address.clone()) {
                return Err(format!(
                    "duplicate vote from {} in canonical target cluster",
                    vote.validator_address
                ));
            }
            signed_voting_weight = signed_voting_weight
                .checked_add(*weight)
                .ok_or_else(|| "signed validator voting weight overflow".to_string())?;
        }

        Ok((seen.len(), signed_voting_weight, total_voting_weight))
    }

    fn has_commit_quorum_for_cluster(
        &self,
        cluster_context: &ConsensusClusterContext,
        votes: &[Vote],
    ) -> bool {
        if cluster_context.validators.is_empty() {
            return false;
        }

        let Ok((validator_count, signed_voting_weight, total_voting_weight)) =
            self.cluster_vote_summary(&cluster_context.validators, votes)
        else {
            return false;
        };
        let required_validator_votes =
            self.required_validator_votes_for_cluster_context(cluster_context);
        validator_count >= required_validator_votes
            && strict_voting_weight_quorum(signed_voting_weight, total_voting_weight)
    }

    fn record_missed_vote_timeouts(&self, live_validators: &[Validator], votes: &[Vote]) {
        if !self.penalization_enabled {
            return;
        }

        let received_votes = votes
            .iter()
            .map(|vote| vote.validator_address.clone())
            .collect::<BTreeSet<_>>();

        for validator in live_validators {
            if received_votes.contains(&validator.address) {
                continue;
            }

            self.validator_manager
                .update_performance(ValidatorPerformanceUpdate {
                    validator_address: validator.address.clone(),
                    update_type: "block_missed".to_string(),
                    value: None,
                    timestamp: Self::current_timestamp(),
                });

            warn!(
                "consensus",
                "Validator missed vote deadline",
                "validator" => validator.address.clone()
            );
        }
    }

    fn record_vote_participation(&self, votes: &[Vote]) {
        for vote in votes {
            self.validator_manager
                .update_performance(ValidatorPerformanceUpdate {
                    validator_address: vote.validator_address.clone(),
                    update_type: "vote_cast".to_string(),
                    value: None,
                    timestamp: Self::current_timestamp(),
                });
        }
    }

    fn create_quorum_certificate(
        &self,
        block_hash: &str,
        epoch_number: u64,
        round_number: u64,
        votes: &[Vote],
        cluster_context: &ConsensusClusterContext,
    ) -> Result<QuorumCertificate, String> {
        // Aggregate signatures
        let aggregate_sig = self.aggregate_signatures(votes, &cluster_context.validators)?;

        // Create participation bitmap
        let participant_bitmap =
            self.create_participant_bitmap_for_validators(votes, &cluster_context.validators);

        // Calculate cumulative weight
        let (_, signed_voting_weight, _) =
            self.cluster_vote_summary(&cluster_context.validators, votes)?;

        let qc = QuorumCertificate {
            block_hash: block_hash.to_string(),
            cluster_id: cluster_context.cluster_id,
            epoch_number,
            round_number,
            aggregate_signature: aggregate_sig.combined_signature,
            participant_bitmap,
            cumulative_weight: signed_voting_weight as f64,
            validation_quorum_met: true,
            cooperation_quorum_met: true,
            timestamp: Self::current_timestamp(),
            votes: {
                let mut sorted_votes = votes.to_vec();
                sorted_votes.sort_by(|a, b| a.validator_address.cmp(&b.validator_address));
                sorted_votes
            },
        };
        Ok(qc)
    }

    fn aggregate_signatures(
        &self,
        votes: &[Vote],
        cluster_validators: &[Validator],
    ) -> Result<AggregateSignature, String> {
        // Sort votes by validator address for deterministic ordering
        let mut sorted_votes = votes.to_vec();
        sorted_votes.sort_by(|a, b| a.validator_address.cmp(&b.validator_address));

        // Create participation bitmap
        let participant_bitmap =
            self.create_participant_bitmap_for_validators(&sorted_votes, cluster_validators);

        // Collect all individual signatures and verify each one before aggregation.
        let mut signatures = Vec::new();

        for vote in &sorted_votes {
            self.verify_vote_signature(vote)?;
            signatures.push(vote.signature.signature_data.clone());
        }

        // Deterministically bind all individual signatures into a compact attestation digest.
        let mut hasher = Sha3_512::new();
        for sig in &signatures {
            hasher.update((sig.len() as u64).to_be_bytes());
            hasher.update(sig);
        }
        let combined_signature = hasher.finalize().to_vec();

        // Use first vote's message hash as common message hash
        let message_hash = if let Some(first_vote) = sorted_votes.first() {
            first_vote.signature.message_hash.clone()
        } else {
            Vec::new()
        };

        Ok(AggregateSignature {
            combined_signature,
            participation_bitmap: participant_bitmap.clone(),
            message_hash,
            participant_count: sorted_votes.len(),
        })
    }

    fn create_participant_bitmap_for_validators(
        &self,
        votes: &[Vote],
        validators: &[Validator],
    ) -> Vec<u8> {
        Self::participant_bitmap_for_validators_static(votes, validators)
    }

    fn participant_bitmap_for_validators_static(
        votes: &[Vote],
        validators: &[Validator],
    ) -> Vec<u8> {
        let mut bitmap = vec![0u8; (validators.len() + 7) / 8];

        for (i, validator) in validators.iter().enumerate() {
            let byte_index = i / 8;
            let bit_index = i % 8;

            if votes
                .iter()
                .any(|v| v.validator_address == validator.address)
            {
                bitmap[byte_index] |= 1 << bit_index;
            }
        }

        bitmap
    }

    fn cluster_context_for_validators(
        validator_manager: &Arc<ValidatorManager>,
        active_validators: &[Validator],
        epoch: u64,
        target_validator: &str,
    ) -> Result<ConsensusClusterContext, String> {
        if active_validators.is_empty() {
            return Err("cannot resolve cluster context without active validators".to_string());
        }

        let canonical_clusters = canonical_validator_clusters_for_epoch(active_validators, epoch);
        let expected_cluster_count = canonical_clusters.len();
        if expected_cluster_count == 0 {
            return Err("canonical validator cluster assignment is empty".to_string());
        }

        if expected_cluster_count == 1 {
            return Ok(ConsensusClusterContext {
                cluster_id: None,
                validators: active_validators.to_vec(),
            });
        }

        if !active_validators
            .iter()
            .any(|validator| validator.address == target_validator)
        {
            return Err(format!(
                "validator {} is not in the canonical active validator set",
                target_validator
            ));
        }

        let has_scheduled_activation = active_validators
            .iter()
            .any(|validator| validator.status == crate::validator::ValidatorStatus::Shadow);
        if validator_manager.get_current_epoch() == epoch && !has_scheduled_activation {
            if validator_manager.get_cluster_count() != expected_cluster_count {
                return Err(format!(
                    "validator registry cluster count {} does not match canonical count {}",
                    validator_manager.get_cluster_count(),
                    expected_cluster_count
                ));
            }

            for validator in active_validators {
                let (expected_cluster_id, expected_members) = canonical_clusters
                    .iter()
                    .find(|(_, members)| {
                        members
                            .iter()
                            .any(|member| member.address == validator.address)
                    })
                    .ok_or_else(|| {
                        format!(
                            "validator {} is missing from canonical epoch {} clusters",
                            validator.address, epoch
                        )
                    })?;
                let Some(actual_cluster_id) = validator.cluster_id else {
                    return Err(format!(
                        "validator {} is missing canonical cluster context",
                        validator.address
                    ));
                };
                if actual_cluster_id != *expected_cluster_id {
                    return Err(format!(
                        "validator {} has cluster {} but canonical epoch {} assignment is {}",
                        validator.address, actual_cluster_id, epoch, expected_cluster_id
                    ));
                }

                let cluster = validator_manager
                    .get_validator_cluster(&validator.address)
                    .ok_or_else(|| {
                        format!(
                            "validator {} has no persisted canonical cluster record",
                            validator.address
                        )
                    })?;
                let mut actual_members = cluster.validators.clone();
                actual_members.sort();
                let mut expected_addresses = expected_members
                    .iter()
                    .map(|member| member.address.clone())
                    .collect::<Vec<_>>();
                expected_addresses.sort();
                if cluster.id != *expected_cluster_id
                    || actual_members != expected_addresses
                    || validator.cluster_address.as_deref() != Some(cluster.address.as_str())
                {
                    return Err(format!(
                        "validator {} has malformed persisted cluster membership",
                        validator.address
                    ));
                }
            }
        }

        let (cluster_id, validators) = canonical_clusters
            .into_iter()
            .find(|(_, members)| {
                members
                    .iter()
                    .any(|member| member.address == target_validator)
            })
            .ok_or_else(|| {
                format!(
                    "validator {} has no canonical cluster assignment for epoch {}",
                    target_validator, epoch
                )
            })?;

        Ok(ConsensusClusterContext {
            cluster_id: Some(cluster_id),
            validators,
        })
    }

    fn cluster_context_for_proposal(
        &self,
        proposed_block: &Block,
        epoch: u64,
    ) -> Result<ConsensusClusterContext, String> {
        let active_validators = self.consensus_membership_for_height(proposed_block.block_index)?;
        let context = Self::cluster_context_for_validators(
            &self.validator_manager,
            &active_validators,
            epoch,
            &proposed_block.validator_id,
        )?;
        if context.cluster_id.is_some() && self.validator_manager.get_current_epoch() != epoch {
            return Err(format!(
                "multi-cluster proposal epoch {} does not match validator registry epoch {}",
                epoch,
                self.validator_manager.get_current_epoch()
            ));
        }
        Ok(context)
    }

    fn cluster_context_for_vote(
        vote: &Vote,
        validator_manager: &Arc<ValidatorManager>,
    ) -> Result<ConsensusClusterContext, String> {
        let active_validators = consensus_membership_validators_for_height(
            validator_manager.get_all_validators(),
            vote.block_index,
        )?;
        Self::cluster_context_for_validators(
            validator_manager,
            &active_validators,
            vote.epoch_number,
            &vote.validator_address,
        )
    }

    fn validate_qc_cluster_context(
        context: &ConsensusClusterContext,
        qc_cluster_id: Option<u64>,
    ) -> Result<(), String> {
        if let Some(cluster_id) = context.cluster_id {
            if qc_cluster_id != Some(cluster_id) {
                return Err(format!(
                    "QC cluster context is missing or does not match canonical cluster {}",
                    cluster_id
                ));
            }
        }
        Ok(())
    }

    fn consensus_membership_for_height(&self, height: u64) -> Result<Vec<Validator>, String> {
        consensus_membership_validators_for_height(
            self.validator_manager.get_all_validators(),
            height,
        )
    }

    fn resolve_local_validator_address() -> Option<String> {
        let from_env = crate::config::resolve_runtime_validator_address();

        if from_env.is_some() {
            return from_env;
        }

        let active_validators =
            consensus_membership_validators(VALIDATOR_MANAGER.get_active_validators());
        if active_validators.len() == 1 {
            active_validators
                .first()
                .map(|validator| validator.address.clone())
        } else {
            None
        }
    }

    fn resolve_local_validator_address_for_round(&self) -> Option<String> {
        Self::resolve_local_validator_address().or_else(|| {
            let active_validators =
                consensus_membership_validators(self.validator_manager.get_active_validators());
            if active_validators.len() == 1 {
                active_validators
                    .first()
                    .map(|validator| validator.address.clone())
            } else {
                None
            }
        })
    }

    fn is_block_hash_valid(block: &Block) -> bool {
        let expected = format!(
            "{:?}{}{}{}{}{}",
            block.block_index,
            block.previous_hash,
            block.validator_id,
            block.nonce,
            block.timestamp,
            block.transactions_root
        );
        blake3::hash(expected.as_bytes()).to_hex().to_string() == block.hash
    }

    fn verify_transaction_static(tx: &crate::transaction::Transaction) -> Result<(), String> {
        let validation = tx.validate_for_admission();
        if validation.is_valid {
            Ok(())
        } else {
            Err(validation
                .error_message
                .unwrap_or_else(|| "transaction failed admission validation".to_string()))
        }
    }

    fn verify_vote_signature(&self, vote: &Vote) -> Result<(), String> {
        let cache_key = Self::vote_signature_cache_key(vote);
        if self.vote_signature_cache_contains(&cache_key) {
            return Ok(());
        }

        Self::verify_vote_signature_uncached(vote, &self.validator_manager)?;
        self.cache_verified_vote_signature(cache_key);
        Ok(())
    }

    fn verify_vote_signature_uncached(
        vote: &Vote,
        validator_manager: &Arc<ValidatorManager>,
    ) -> Result<(), String> {
        let cluster_context = Self::cluster_context_for_vote(vote, validator_manager)?;
        let message = Self::vote_signature_payload(
            &vote.validator_address,
            &vote.block_hash,
            vote.block_index,
            vote.epoch_number,
            vote.round_number,
            cluster_context.cluster_id,
        );
        let public_key = verify_signer_key_matches_validator_at_height(
            vote.block_index,
            &vote.validator_address,
            &vote.signer_public_key,
            validator_manager,
        )?;
        if vote.signature.algorithm != public_key.algorithm {
            return Err(format!(
                "vote signature algorithm does not match canonical consensus key for validator {}",
                vote.validator_address
            ));
        }

        let pqc_manager = PQCManager::new();
        let valid = pqc_manager
            .verify(&public_key, &vote.signature, message.as_bytes())
            .map_err(|err| format!("vote signature verify error: {err}"))?;

        if valid {
            Ok(())
        } else {
            Err(format!(
                "invalid vote signature from validator {}",
                vote.validator_address
            ))
        }
    }

    pub fn verify_commit_certificate_for_block_static(
        block: &Block,
        qc: &QuorumCertificate,
        validator_manager: &Arc<ValidatorManager>,
    ) -> Result<(), String> {
        block.verify_proposer_signature()?;
        verify_block_proposer_key_matches_validator(block, validator_manager)?;

        if qc.block_hash != block.hash {
            return Err("QC block hash does not match exact block".to_string());
        }
        if qc.aggregate_signature.is_empty() {
            return Err("QC aggregate signature is missing".to_string());
        }
        if qc.participant_bitmap.is_empty() {
            return Err("QC signer bitmap is missing".to_string());
        }
        if !qc.validation_quorum_met || !qc.cooperation_quorum_met {
            return Err("QC does not prove both validation and cooperation quorum".to_string());
        }
        if qc.votes.is_empty() {
            return Err("QC does not include individually verifiable Aegis PQC votes".to_string());
        }

        let active_validators = consensus_membership_validators_for_height(
            validator_manager.get_all_validators(),
            block.block_index,
        )
        .map_err(|error| {
            format!(
                "QC verification cannot resolve validator set for height {}: {error}",
                block.block_index
            )
        })?;
        if active_validators.is_empty() {
            return Err(format!(
                "QC verification has no active validator set for height {}",
                block.block_index
            ));
        }
        let cluster_context = Self::cluster_context_for_validators(
            validator_manager,
            &active_validators,
            qc.epoch_number,
            &block.validator_id,
        )?;
        Self::validate_qc_cluster_context(&cluster_context, qc.cluster_id)?;
        let active_by_address = cluster_context
            .validators
            .iter()
            .map(|validator| (validator.address.clone(), validator))
            .collect::<HashMap<_, _>>();

        let mut seen = BTreeSet::new();
        for vote in &qc.votes {
            if vote.block_hash != block.hash {
                return Err("QC vote signs a different block hash".to_string());
            }
            if vote.block_index != block.block_index {
                return Err("QC vote signs a different block height".to_string());
            }
            if vote.epoch_number != qc.epoch_number || vote.round_number > qc.round_number {
                return Err("QC vote context does not match QC epoch/round".to_string());
            }
            if !seen.insert(vote.validator_address.clone()) {
                return Err("QC contains duplicate signer".to_string());
            }
            let Some(_validator) = active_by_address.get(&vote.validator_address) else {
                return Err(if cluster_context.cluster_id.is_some() {
                    "QC contains signer outside the canonical proposal cluster".to_string()
                } else {
                    "QC contains signer outside active validator set".to_string()
                });
            };
            Self::verify_vote_signature_uncached(vote, validator_manager)?;
        }

        if cluster_context.cluster_id.is_some() {
            let expected_bitmap = Self::participant_bitmap_for_validators_static(
                &qc.votes,
                &cluster_context.validators,
            );
            if qc.participant_bitmap != expected_bitmap {
                return Err(
                    "QC signer bitmap does not match canonical cluster membership".to_string(),
                );
            }
        }

        let required_votes = Self::required_qc_validator_votes(
            cluster_context.validators.len(),
            cluster_context.cluster_id.is_some(),
        );
        if seen.len() < required_votes {
            return Err(format!(
                "QC has {} signer(s), {} required for dynamic validator quorum",
                seen.len(),
                required_votes,
            ));
        }

        let total_voting_weight =
            cluster_context
                .validators
                .iter()
                .try_fold(0u128, |total, validator| {
                    if validator.stake_amount == 0 {
                        return Err(format!(
                            "QC validator {} has zero bonded voting weight",
                            validator.address
                        ));
                    }
                    total
                        .checked_add(u128::from(validator.stake_amount))
                        .ok_or_else(|| "QC total voting weight overflow".to_string())
                })?;
        let signed_voting_weight = seen.iter().try_fold(0u128, |total, address| {
            let validator = active_by_address
                .get(address)
                .ok_or_else(|| "QC signer disappeared from canonical cluster".to_string())?;
            total
                .checked_add(u128::from(validator.stake_amount))
                .ok_or_else(|| "QC signed voting weight overflow".to_string())
        })?;
        if !strict_voting_weight_quorum(signed_voting_weight, total_voting_weight) {
            return Err(format!(
                "QC signed voting weight {signed_voting_weight} does not exceed two-thirds of frozen total voting weight {total_voting_weight}"
            ));
        }
        let declared_weight = signed_voting_weight as f64;
        if !qc.cumulative_weight.is_finite()
            || (qc.cumulative_weight - declared_weight).abs() > 0.000_001
        {
            return Err(format!(
                "QC cumulative_weight mismatch: computed bonded weight {declared_weight}, declared {}",
                qc.cumulative_weight
            ));
        }

        Ok(())
    }

    fn required_qc_validator_votes(total_validators: usize, clustered: bool) -> usize {
        if clustered {
            required_cluster_quorum(total_validators).max(1)
        } else {
            required_validator_quorum(total_validators).max(1)
        }
    }

    fn vote_signature_cache_contains(&self, cache_key: &str) -> bool {
        self.verified_vote_signatures
            .lock()
            .map(|cache| cache.contains(cache_key))
            .unwrap_or(false)
    }

    fn cache_verified_vote_signature(&self, cache_key: String) {
        if let Ok(mut cache) = self.verified_vote_signatures.lock() {
            if cache.len() > 8192 {
                cache.clear();
            }
            cache.insert(cache_key);
        }
    }

    fn vote_signature_cache_key(vote: &Vote) -> String {
        let mut hasher = Sha3_512::new();
        hasher.update(vote.validator_address.as_bytes());
        hasher.update(vote.block_hash.as_bytes());
        hasher.update(vote.block_index.to_be_bytes());
        hasher.update(vote.epoch_number.to_be_bytes());
        hasher.update(vote.round_number.to_be_bytes());
        hasher.update(format!("{:?}", vote.signature.algorithm).as_bytes());
        hasher.update((vote.signer_public_key.len() as u64).to_be_bytes());
        hasher.update(&vote.signer_public_key);
        hasher.update((vote.signature.signature_data.len() as u64).to_be_bytes());
        hasher.update(&vote.signature.signature_data);
        hex::encode(hasher.finalize())
    }

    fn vote_signature_payload(
        validator_address: &str,
        block_hash: &str,
        block_index: u64,
        epoch_number: u64,
        round_number: u64,
        cluster_id: Option<u64>,
    ) -> String {
        let payload = format!(
            "{}:{}:{}:{}:{}",
            validator_address, block_index, round_number, block_hash, epoch_number
        );
        match cluster_id {
            Some(cluster_id) => format!("{payload}:{cluster_id}"),
            None => payload,
        }
    }

    fn scoped_local_vote_lock_key(
        validator_address: &str,
        epoch_number: u64,
        block_index: u64,
        round_number: u64,
        block_hash: &str,
    ) -> String {
        format!("{epoch_number}:{block_index}:{round_number}:{block_hash}:{validator_address}")
    }

    fn local_vote_lock_path() -> PathBuf {
        #[cfg(test)]
        {
            if let Ok(path) = TEST_LOCAL_VOTE_LOCK_PATH.lock() {
                if let Some(path) = path.clone() {
                    return path;
                }
            }

            return crate::utils::test_temp_root(format!(
                "synergy-test-local-vote-locks-{}.json",
                std::process::id()
            ));
        }

        #[cfg(not(test))]
        {
            crate::utils::resolve_data_path("data/consensus_vote_locks.json")
        }
    }

    fn load_local_vote_locks_unlocked() -> Result<HashMap<String, LocalVoteLock>, String> {
        let path = Self::local_vote_lock_path();
        if !path.exists() {
            return Ok(HashMap::new());
        }

        let data = fs::read(&path)
            .map_err(|err| format!("failed to read local vote lock file {:?}: {err}", path))?;
        if data.is_empty() {
            return Ok(HashMap::new());
        }

        serde_json::from_slice::<HashMap<String, LocalVoteLock>>(&data)
            .map_err(|err| format!("failed to parse local vote lock file {:?}: {err}", path))
    }

    fn persist_local_vote_locks_unlocked(
        locks: &HashMap<String, LocalVoteLock>,
    ) -> Result<(), String> {
        let path = Self::local_vote_lock_path();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .map_err(|err| format!("failed to create local vote lock directory: {err}"))?;
        }

        let tmp_path = path.with_extension("json.tmp");
        let serialized = serde_json::to_vec_pretty(locks)
            .map_err(|err| format!("failed to encode local vote locks: {err}"))?;

        let mut options = OpenOptions::new();
        options.create(true).truncate(true).write(true);
        #[cfg(unix)]
        options.mode(0o600);
        let mut file = options
            .open(&tmp_path)
            .map_err(|err| format!("failed to open local vote lock temp file: {err}"))?;
        file.write_all(&serialized)
            .map_err(|err| format!("failed to write local vote lock temp file: {err}"))?;
        file.sync_all()
            .map_err(|err| format!("failed to sync local vote lock temp file: {err}"))?;
        drop(file);

        fs::rename(&tmp_path, &path)
            .map_err(|err| format!("failed to replace local vote lock file: {err}"))
    }

    fn local_vote_lock_to_recovered(lock: &LocalVoteLock) -> RecoveredTransientVoteLock {
        RecoveredTransientVoteLock {
            validator_address: lock.validator_address.clone(),
            block_hash: lock.block_hash.clone(),
            block_index: lock.block_index,
            epoch_number: lock.epoch_number,
            first_round_number: lock.first_round_number,
            latest_round_number: lock.latest_round_number,
            proposer: lock.proposer.clone(),
            created_at: lock.created_at,
            updated_at: lock.updated_at,
        }
    }

    fn vote_lock_evidence_root_for_path(path: &Path) -> PathBuf {
        path.parent()
            .map(|data_dir| data_dir.join("consensus_recovery_evidence"))
            .unwrap_or_else(|| crate::utils::resolve_data_path("data/consensus_recovery_evidence"))
    }

    fn preserve_vote_lock_compaction_evidence_unlocked(
        path: &PathBuf,
        locks: &HashMap<String, LocalVoteLock>,
        removed: &[(String, RecoveredTransientVoteLock)],
        finalized_height: u64,
        finalized_hash: &str,
        prune_cutoff_height: u64,
        reason: &str,
        now: u64,
    ) -> Result<PathBuf, String> {
        let evidence_root = Self::vote_lock_evidence_root_for_path(path);
        fs::create_dir_all(&evidence_root)
            .map_err(|err| format!("failed to create vote-lock evidence directory: {err}"))?;
        let evidence_nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let evidence_path = evidence_root.join(format!(
            "{}-{}-finalized-vote-lock-compaction-through-{}.json",
            now, evidence_nonce, prune_cutoff_height
        ));
        let removed_locks = removed
            .iter()
            .map(|(_, lock)| lock.clone())
            .collect::<Vec<_>>();
        let evidence = serde_json::json!({
            "action": "compact_finalized_vote_locks_for_hot_path",
            "reason": reason,
            "vote_lock_path": path.to_string_lossy(),
            "finalized_height": finalized_height,
            "finalized_hash": finalized_hash,
            "retention_depth": LOCAL_VOTE_LOCK_FINALIZED_RETENTION_DEPTH,
            "prune_cutoff_height": prune_cutoff_height,
            "before_count": locks.len(),
            "removed_count": removed_locks.len(),
            "kept_count": locks.len().saturating_sub(removed_locks.len()),
            "removed": removed_locks,
            "timestamp": now,
        });
        let serialized = serde_json::to_vec_pretty(&evidence).map_err(|err| {
            format!("failed to encode finalized vote-lock compaction evidence: {err}")
        })?;
        let mut options = OpenOptions::new();
        options.create_new(true).write(true);
        #[cfg(unix)]
        options.mode(0o600);
        let mut file = options
            .open(&evidence_path)
            .map_err(|err| format!("failed to create finalized vote-lock evidence file: {err}"))?;
        file.write_all(&serialized)
            .map_err(|err| format!("failed to write finalized vote-lock evidence file: {err}"))?;
        file.sync_all()
            .map_err(|err| format!("failed to sync finalized vote-lock evidence file: {err}"))?;
        Ok(evidence_path)
    }

    fn compact_finalized_vote_locks_for_hot_path_unlocked(
        locks: &mut HashMap<String, LocalVoteLock>,
        now: u64,
        reason: &str,
    ) -> Result<Option<(usize, PathBuf)>, String> {
        if locks.len() < LOCAL_VOTE_LOCK_COMPACTION_MIN_LOCKS {
            return Ok(None);
        }

        let Some(canonical) = latest_legacy_canonical_commit_record()? else {
            return Ok(None);
        };
        let prune_cutoff_height = canonical
            .height
            .saturating_sub(LOCAL_VOTE_LOCK_FINALIZED_RETENTION_DEPTH);
        let path = Self::local_vote_lock_path();
        let mut removed = locks
            .iter()
            .filter_map(|(key, lock)| {
                (lock.block_index <= prune_cutoff_height)
                    .then(|| (key.clone(), Self::local_vote_lock_to_recovered(lock)))
            })
            .collect::<Vec<_>>();
        removed.sort_by(|(_, left), (_, right)| {
            (
                left.block_index,
                left.epoch_number,
                left.latest_round_number,
                left.block_hash.as_str(),
            )
                .cmp(&(
                    right.block_index,
                    right.epoch_number,
                    right.latest_round_number,
                    right.block_hash.as_str(),
                ))
        });

        if removed.is_empty() {
            return Ok(None);
        }

        let evidence_path = Self::preserve_vote_lock_compaction_evidence_unlocked(
            &path,
            locks,
            &removed,
            canonical.height,
            &canonical.block_hash,
            prune_cutoff_height,
            reason,
            now,
        )?;

        for (key, _) in &removed {
            locks.remove(key);
        }

        Ok(Some((removed.len(), evidence_path)))
    }

    pub fn local_locked_vote_for_height(
        validator_address: &str,
        epoch_number: u64,
        block_index: u64,
    ) -> Result<Option<LocalLockedVote>, String> {
        let _guard = LOCAL_VOTE_LOCK_FILE_MUTEX
            .lock()
            .map_err(|_| "local vote lock file mutex is poisoned".to_string())?;
        let locks = Self::load_local_vote_locks_unlocked()?;
        let latest_lock = Self::latest_local_vote_lock_for_height_unlocked(
            &locks,
            validator_address,
            epoch_number,
            block_index,
        );

        Ok(latest_lock.map(|lock| LocalLockedVote {
            validator_address: lock.validator_address.clone(),
            block_hash: lock.block_hash.clone(),
            block_index: lock.block_index,
            epoch_number: lock.epoch_number,
            first_round_number: lock.first_round_number,
            latest_round_number: lock.latest_round_number,
            proposer: lock.proposer.clone(),
            created_at: lock.created_at,
            updated_at: lock.updated_at,
        }))
    }

    pub fn recover_transient_vote_locks_above_finalized_height(
        finalized_height: u64,
        min_age_secs: u64,
        reason: &str,
    ) -> Result<TransientVoteLockRecoveryReport, String> {
        let _guard = LOCAL_VOTE_LOCK_FILE_MUTEX
            .lock()
            .map_err(|_| "local vote lock file mutex is poisoned".to_string())?;
        let path = Self::local_vote_lock_path();
        let locks = Self::load_local_vote_locks_unlocked()?;
        let now = Self::current_timestamp();
        let before_count = locks.len();

        // PoSy v2.1 forbids timeout, restart, operator recovery, or view-change
        // code from deleting a signing authorization above the finalized head.
        // Keep this API read-only so older diagnostics remain compatible while
        // every caller fails closed on the still-present lock.
        Ok(TransientVoteLockRecoveryReport {
            action: "inspect_preserved_vote_locks_above_finalized_height".to_string(),
            reason: format!("PoSy v2.1 fail-closed preservation: {reason}"),
            finalized_height,
            min_age_secs,
            vote_lock_path: path.to_string_lossy().to_string(),
            evidence_path: String::new(),
            before_count,
            kept_count: locks.len(),
            removed_count: 0,
            removed: Vec::new(),
            mutated: false,
            timestamp: now,
        })
    }

    fn validate_same_height_vote_supersede(
        proposed_block: &Block,
        round_number: u64,
        latest_conflicting_round: u64,
    ) -> Result<(), String> {
        if round_number <= latest_conflicting_round {
            return Err(format!(
                "same-height vote supersede requires a higher consensus round: requested_round={round_number}, latest_conflicting_round={latest_conflicting_round}"
            ));
        }

        if let Some(existing) = legacy_canonical_commit_record(proposed_block.block_index)? {
            return Err(format!(
                "height {} is already finalized by canonical lock {}; refusing transient vote supersede for {}",
                proposed_block.block_index, existing.block_hash, proposed_block.hash
            ));
        }

        let latest_lock =
            Self::same_height_vote_parent_for_proposal(proposed_block)?.ok_or_else(|| {
                "same-height vote supersede requires a durable finalized canonical parent lock"
                    .to_string()
            })?;
        if proposed_block.block_index != latest_lock.height + 1 {
            return Err(format!(
                "same-height vote supersede target height {} must be the direct child of finalized canonical height {}",
                proposed_block.block_index, latest_lock.height
            ));
        }
        if proposed_block.previous_hash != latest_lock.block_hash {
            return Err(format!(
                "same-height vote supersede proposal does not extend latest canonical lock: expected_parent={}, proposed_parent={}",
                latest_lock.block_hash, proposed_block.previous_hash
            ));
        }
        Err(format!(
            "PoSy v2.1 fail-closed signer journal forbids same-height candidate supersede without an implemented and verified exact prepared-certificate carry-forward: height={} locked_round={} requested_round={} requested_hash={} requested_proposer={} canonical_parent_height={} canonical_parent_hash={} canonical_parent_source={} checkpoint_fork_parent={}",
            proposed_block.block_index,
            latest_conflicting_round,
            round_number,
            proposed_block.hash,
            proposed_block.validator_id,
            latest_lock.height,
            latest_lock.block_hash,
            latest_lock.source,
            latest_lock.checkpoint_fork_parent
        ))
    }

    fn same_height_vote_parent_for_proposal(
        proposed_block: &Block,
    ) -> Result<Option<SameHeightVoteParent>, String> {
        if let Some(migration) =
            crate::consensus::consensus_fork::active_consensus_fork_migration()?
        {
            if proposed_block.block_index == migration.fork_height {
                if proposed_block.previous_hash != migration.parent_hash {
                    return Err(format!(
                        "checkpoint fork proposal at height {} does not extend configured fork parent {}",
                        proposed_block.block_index, migration.parent_hash
                    ));
                }
                return Ok(Some(SameHeightVoteParent {
                    height: migration.parent_height,
                    block_hash: migration.parent_hash,
                    source: "checkpoint_consensus_fork",
                    checkpoint_fork_parent: true,
                }));
            }
        }

        Ok(
            latest_legacy_canonical_commit_record()?.map(|record| SameHeightVoteParent {
                height: record.height,
                block_hash: record.block_hash,
                source: "legacy_canonical_lock",
                checkpoint_fork_parent: false,
            }),
        )
    }

    fn latest_local_vote_lock_for_height_unlocked(
        locks: &HashMap<String, LocalVoteLock>,
        validator_address: &str,
        epoch_number: u64,
        block_index: u64,
    ) -> Option<LocalVoteLock> {
        locks
            .values()
            .filter(|lock| {
                lock.validator_address == validator_address
                    && lock.epoch_number == epoch_number
                    && lock.block_index == block_index
            })
            .max_by_key(|lock| (lock.latest_round_number, lock.updated_at))
            .cloned()
    }

    fn recover_stale_conflicting_vote_lock_before_vote(
        validator_address: &str,
        proposed_block: &Block,
        epoch_number: u64,
        round_number: u64,
        min_age_secs: u64,
        reason: &str,
    ) -> Result<(), String> {
        if min_age_secs == u64::MAX {
            return Ok(());
        }

        let latest_lock = {
            let _guard = LOCAL_VOTE_LOCK_FILE_MUTEX
                .lock()
                .map_err(|_| "local vote lock file mutex is poisoned".to_string())?;
            let locks = Self::load_local_vote_locks_unlocked()?;
            Self::latest_local_vote_lock_for_height_unlocked(
                &locks,
                validator_address,
                epoch_number,
                proposed_block.block_index,
            )
        };

        let Some(latest_lock) = latest_lock else {
            return Ok(());
        };
        if latest_lock.block_hash == proposed_block.hash {
            return Ok(());
        }

        if legacy_canonical_commit_record(proposed_block.block_index)?.is_some() {
            return Ok(());
        }

        let Some(canonical_parent) = Self::same_height_vote_parent_for_proposal(proposed_block)?
        else {
            return Ok(());
        };
        if proposed_block.block_index != canonical_parent.height.saturating_add(1)
            || proposed_block.previous_hash != canonical_parent.block_hash
        {
            return Ok(());
        }
        let now = Self::current_timestamp();
        let effective_min_age_secs = if canonical_parent.checkpoint_fork_parent {
            0
        } else {
            min_age_secs
        };
        if now.saturating_sub(latest_lock.updated_at) < effective_min_age_secs {
            return Ok(());
        }

        let recovery_reason = format!(
            "{reason}: validator={validator_address} height={} requested_hash={} requested_proposer={} requested_round={} stale_locked_hash={} stale_locked_proposer={} stale_latest_round={} canonical_parent_height={} canonical_parent_hash={} canonical_parent_source={}",
            proposed_block.block_index,
            proposed_block.hash,
            proposed_block.validator_id,
            round_number,
            latest_lock.block_hash,
            latest_lock.proposer,
            latest_lock.latest_round_number,
            canonical_parent.height,
            canonical_parent.block_hash,
            canonical_parent.source
        );
        let report = Self::recover_transient_vote_locks_above_finalized_height(
            canonical_parent.height,
            effective_min_age_secs,
            &recovery_reason,
        )?;

        if report.mutated {
            timing_trace::emit(
                "stale_transient_lock_recovery",
                serde_json::json!({
                    "height": proposed_block.block_index,
                    "block_hash": proposed_block.hash.clone(),
                    "previous_hash": proposed_block.previous_hash.clone(),
                    "proposer": proposed_block.validator_id.clone(),
                    "validator": validator_address,
                    "epoch": epoch_number,
                    "round": round_number,
                    "removed_count": report.removed_count,
                    "evidence_path": report.evidence_path.clone()
                }),
            );
            warn!(
                "consensus",
                "Recovered stale transient vote locks before signing higher-round view-change proposal",
                "validator" => validator_address.to_string(),
                "height" => proposed_block.block_index,
                "requested_hash" => proposed_block.hash.clone(),
                "requested_proposer" => proposed_block.validator_id.clone(),
                "requested_round" => round_number,
                "removed_count" => report.removed_count as u64,
                "evidence_path" => report.evidence_path.clone()
            );
        }

        Ok(())
    }

    pub(crate) fn recover_stale_transient_vote_locks_for_leader_selection(
        finalized_height: u64,
        min_age_secs: u64,
        reason: &str,
    ) -> Result<bool, String> {
        let report = Self::recover_transient_vote_locks_above_finalized_height(
            finalized_height,
            min_age_secs,
            reason,
        )?;

        if report.mutated {
            timing_trace::emit(
                "stale_transient_lock_recovery_leader_selection",
                serde_json::json!({
                    "finalized_height": finalized_height,
                    "removed_count": report.removed_count,
                    "evidence_path": report.evidence_path.clone(),
                    "reason": reason
                }),
            );
            warn!(
                "consensus",
                "Recovered stale transient vote locks before scheduled leader handoff",
                "finalized_height" => finalized_height,
                "removed_count" => report.removed_count as u64,
                "evidence_path" => report.evidence_path.clone(),
                "reason" => reason.to_string()
            );
        }

        Ok(report.mutated)
    }

    fn register_local_vote_intent(
        validator_address: &str,
        proposed_block: &Block,
        epoch_number: u64,
        round_number: u64,
    ) -> Result<(), String> {
        let _guard = LOCAL_VOTE_LOCK_FILE_MUTEX
            .lock()
            .map_err(|_| "local vote lock file mutex is poisoned".to_string())?;
        let mut locks = Self::load_local_vote_locks_unlocked()?;
        let now = Self::current_timestamp();
        if let Some((removed_count, evidence_path)) =
            Self::compact_finalized_vote_locks_for_hot_path_unlocked(
                &mut locks,
                now,
                "automatic finalized vote-lock compaction before local vote persistence",
            )?
        {
            warn!(
                "consensus",
                "Compacted finalized local vote locks before signing vote",
                "validator" => validator_address.to_string(),
                "height" => proposed_block.block_index,
                "epoch" => epoch_number,
                "round" => round_number,
                "removed_count" => removed_count as u64,
                "evidence_path" => evidence_path.to_string_lossy().to_string()
            );
        }

        let matching_keys = locks
            .iter()
            .filter_map(|(key, lock)| {
                if lock.validator_address == validator_address
                    && lock.epoch_number == epoch_number
                    && lock.block_index == proposed_block.block_index
                {
                    Some(key.clone())
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();

        if let Some(existing_key) = matching_keys.iter().find(|key| {
            locks
                .get(*key)
                .map(|lock| lock.block_hash == proposed_block.hash)
                .unwrap_or(false)
        }) {
            if let Some(existing) = locks.get_mut(existing_key) {
                existing.latest_round_number = existing.latest_round_number.max(round_number);
                existing.updated_at = now;
                Self::persist_local_vote_locks_unlocked(&locks)?;
                return Ok(());
            }
        }

        if !matching_keys.is_empty() {
            let latest_conflicting = matching_keys
                .iter()
                .filter_map(|key| locks.get(key))
                .max_by_key(|lock| (lock.latest_round_number, lock.updated_at))
                .cloned()
                .ok_or_else(|| "failed to load matching local vote lock".to_string())?;

            if round_number <= latest_conflicting.latest_round_number {
                return Err(format!(
                    "already locally voted for different block at height {} in this or a later round: locked_hash={}, locked_proposer={}, locked_epoch={}, locked_first_round={}, locked_latest_round={}, requested_hash={}, requested_proposer={}, requested_epoch={}, requested_round={}",
                    proposed_block.block_index,
                    latest_conflicting.block_hash,
                    latest_conflicting.proposer,
                    latest_conflicting.epoch_number,
                    latest_conflicting.first_round_number,
                    latest_conflicting.latest_round_number,
                    proposed_block.hash,
                    proposed_block.validator_id,
                    epoch_number,
                    round_number
                ));
            }

            Self::validate_same_height_vote_supersede(
                proposed_block,
                round_number,
                latest_conflicting.latest_round_number,
            )?;

            warn!(
                "consensus",
                "Advancing local same-height transient vote lock after higher-round view change",
                "validator" => validator_address.to_string(),
                "height" => proposed_block.block_index,
                "epoch" => epoch_number,
                "previous_hash" => latest_conflicting.block_hash.clone(),
                "previous_proposer" => latest_conflicting.proposer.clone(),
                "previous_first_round" => latest_conflicting.first_round_number,
                "previous_latest_round" => latest_conflicting.latest_round_number,
                "new_hash" => proposed_block.hash.clone(),
                "new_proposer" => proposed_block.validator_id.clone(),
                "new_round" => round_number
            );
        }

        let key = Self::scoped_local_vote_lock_key(
            validator_address,
            epoch_number,
            proposed_block.block_index,
            round_number,
            &proposed_block.hash,
        );
        let superseded = matching_keys
            .iter()
            .filter_map(|key| locks.get(key))
            .filter(|lock| lock.block_hash != proposed_block.hash)
            .map(|lock| SupersededLocalVoteLock {
                block_hash: lock.block_hash.clone(),
                first_round_number: lock.first_round_number,
                latest_round_number: lock.latest_round_number,
                proposer: lock.proposer.clone(),
                superseded_at: now,
            })
            .collect();

        locks.insert(
            key,
            LocalVoteLock {
                validator_address: validator_address.to_string(),
                block_hash: proposed_block.hash.clone(),
                block_index: proposed_block.block_index,
                epoch_number,
                first_round_number: round_number,
                latest_round_number: round_number,
                proposer: proposed_block.validator_id.clone(),
                created_at: now,
                updated_at: now,
                superseded,
            },
        );

        Self::persist_local_vote_locks_unlocked(&locks)
    }

    fn vote_observation_key(
        validator_address: &str,
        epoch_number: u64,
        block_index: u64,
        round_number: u64,
    ) -> String {
        format!("{epoch_number}:{block_index}:{round_number}:{validator_address}")
    }

    fn observe_vote(
        vote: &Vote,
        persist_equivocation_evidence: bool,
    ) -> Option<VoteEquivocationEvidence> {
        let key = Self::vote_observation_key(
            &vote.validator_address,
            vote.epoch_number,
            vote.block_index,
            vote.round_number,
        );

        let mut observed_votes = OBSERVED_VOTES.lock().ok()?;
        match observed_votes.get(&key) {
            // Idempotent replays of the exact same vote are allowed.
            Some(existing) if existing.block_hash == vote.block_hash => None,
            Some(existing) => {
                let evidence = VoteEquivocationEvidence {
                    validator_address: vote.validator_address.clone(),
                    block_index: vote.block_index,
                    epoch_number: vote.epoch_number,
                    round_number: vote.round_number,
                    first_vote: existing.clone(),
                    conflicting_vote: vote.clone(),
                    detected_at: Self::current_timestamp(),
                };

                if persist_equivocation_evidence {
                    if let Ok(mut evidence_log) = EQUIVOCATION_EVIDENCE_LOG.lock() {
                        evidence_log.insert(key, evidence.clone());
                    }
                }

                Some(evidence)
            }
            None => {
                observed_votes.insert(key, vote.clone());
                None
            }
        }
    }

    fn register_vote_observation(vote: &Vote) -> Option<VoteEquivocationEvidence> {
        Self::observe_vote(vote, true)
    }

    fn register_local_vote_attempt(vote: &Vote) -> Option<VoteEquivocationEvidence> {
        Self::observe_vote(vote, false)
    }

    fn has_equivocation_evidence(
        validator_address: &str,
        epoch_number: u64,
        block_index: u64,
        round_number: u64,
    ) -> bool {
        let key =
            Self::vote_observation_key(validator_address, epoch_number, block_index, round_number);
        EQUIVOCATION_EVIDENCE_LOG
            .lock()
            .ok()
            .map(|log| log.contains_key(&key))
            .unwrap_or(false)
    }

    fn register_local_vote_or_slash(&self, vote: &Vote) -> Result<(), String> {
        if let Some(evidence) = Self::register_local_vote_attempt(vote) {
            return Err(format!(
                "Validator {} attempted conflicting votes at height {} in epoch {} round {}",
                evidence.validator_address,
                evidence.block_index,
                evidence.epoch_number,
                evidence.round_number
            ));
        }

        Ok(())
    }

    fn pending_equivocation_evidence(&self) -> Vec<VoteEquivocationEvidence> {
        let processed = PROCESSED_EQUIVOCATION_EVIDENCE
            .lock()
            .ok()
            .map(|entries| entries.clone())
            .unwrap_or_default();

        EQUIVOCATION_EVIDENCE_LOG
            .lock()
            .ok()
            .map(|entries| {
                entries
                    .iter()
                    .filter(|(key, _)| !processed.contains(*key))
                    .map(|(_, evidence)| evidence.clone())
                    .collect()
            })
            .unwrap_or_default()
    }

    fn apply_recorded_equivocations(&self) {
        for evidence in self.pending_equivocation_evidence() {
            self.apply_equivocation_evidence(&evidence);
        }
    }

    fn apply_equivocation_evidence(&self, evidence: &VoteEquivocationEvidence) {
        let key = Self::vote_observation_key(
            &evidence.validator_address,
            evidence.epoch_number,
            evidence.block_index,
            evidence.round_number,
        );

        let should_process = if let Ok(mut processed) = PROCESSED_EQUIVOCATION_EVIDENCE.lock() {
            processed.insert(key)
        } else {
            false
        };
        if !should_process {
            return;
        }

        match self
            .validator_manager
            .slash_validator(&evidence.validator_address, "double_sign")
        {
            Ok(_) => {
                warn!(
                    "consensus",
                    "Slashed validator for vote equivocation",
                    "validator" => evidence.validator_address.clone(),
                    "height" => evidence.block_index,
                    "epoch" => evidence.epoch_number,
                    "round" => evidence.round_number
                );
            }
            Err(error) => {
                warn!(
                    "consensus",
                    "Failed to slash equivocating validator",
                    "validator" => evidence.validator_address.clone(),
                    "height" => evidence.block_index,
                    "epoch" => evidence.epoch_number,
                    "round" => evidence.round_number,
                    "error" => error
                );
            }
        }
    }

    fn vote_is_eligible(&self, vote: &Vote) -> bool {
        if Self::has_equivocation_evidence(
            &vote.validator_address,
            vote.epoch_number,
            vote.block_index,
            vote.round_number,
        ) {
            return false;
        }

        self.vote_validator_is_active(vote)
    }

    fn vote_is_eligible_for_collection(
        &self,
        vote: &Vote,
        block_hash: &str,
        epoch_number: u64,
        round_number: u64,
    ) -> bool {
        self.vote_is_eligible_for_collection_for_cluster(
            vote,
            block_hash,
            epoch_number,
            round_number,
            None,
        )
    }

    fn vote_is_eligible_for_collection_for_cluster(
        &self,
        vote: &Vote,
        block_hash: &str,
        epoch_number: u64,
        round_number: u64,
        expected_cluster_id: Option<u64>,
    ) -> bool {
        if vote.block_hash != block_hash
            || vote.epoch_number != epoch_number
            || vote.round_number > round_number
        {
            return false;
        }

        if !self.vote_validator_is_active(vote) {
            return false;
        }

        if let Some(expected_cluster_id) = expected_cluster_id {
            let Ok(active_validators) = consensus_membership_validators_for_height(
                self.validator_manager.get_all_validators(),
                vote.block_index,
            ) else {
                return false;
            };
            let Ok(cluster_context) = Self::cluster_context_for_validators(
                &self.validator_manager,
                &active_validators,
                epoch_number,
                &vote.validator_address,
            ) else {
                return false;
            };
            if cluster_context.cluster_id != Some(expected_cluster_id) {
                return false;
            }
        }

        if Self::has_equivocation_evidence(
            &vote.validator_address,
            vote.epoch_number,
            vote.block_index,
            vote.round_number,
        ) {
            return vote.round_number < round_number;
        }

        self.vote_is_eligible(vote)
    }

    fn vote_validator_is_active(&self, vote: &Vote) -> bool {
        consensus_membership_validators_for_height(
            self.validator_manager.get_all_validators(),
            vote.block_index,
        )
        .map(|validators| {
            validators
                .into_iter()
                .any(|validator| validator.address == vote.validator_address)
        })
        .unwrap_or(false)
    }

    fn vote_mailbox_key(block_hash: &str, epoch_number: u64, round_number: u64) -> String {
        format!("{epoch_number}:{round_number}:{block_hash}")
    }

    fn reset_network_vote_mailbox(block_hash: &str, epoch_number: u64, round_number: u64) {
        let key = Self::vote_mailbox_key(block_hash, epoch_number, round_number);
        if let Ok(mut mailbox) = NETWORK_VOTE_MAILBOX.lock() {
            mailbox.remove(&key);
        }
    }

    fn snapshot_network_votes(block_hash: &str, epoch_number: u64, round_number: u64) -> Vec<Vote> {
        let prefix = format!("{epoch_number}:");
        let suffix = format!(":{block_hash}");
        NETWORK_VOTE_MAILBOX
            .lock()
            .ok()
            .map(|mailbox| {
                mailbox
                    .iter()
                    .filter_map(|(key, votes)| {
                        let vote_round = key
                            .strip_prefix(&prefix)
                            .and_then(|round_and_hash| round_and_hash.strip_suffix(&suffix))
                            .and_then(|round| round.parse::<u64>().ok())?;
                        (vote_round <= round_number).then_some(votes.clone())
                    })
                    .flatten()
                    .collect()
            })
            .unwrap_or_default()
    }

    fn allocate_round_number(
        &mut self,
        block_index: u64,
        epoch_number: u64,
        validator_address: &str,
        minimum_round_number: u64,
    ) -> u64 {
        let persisted_lock_floor =
            Self::local_locked_vote_for_height(validator_address, epoch_number, block_index)
                .ok()
                .flatten()
                .map(|lock| lock.latest_round_number.saturating_add(1))
                .unwrap_or(1);
        let round_number = minimum_round_number.max(persisted_lock_floor).max(1);
        self.current_round_by_height
            .insert(block_index, round_number);
        round_number
    }

    fn current_timestamp() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    #[cfg(test)]
    pub(crate) fn test_vote_tracking_guard() -> std::sync::MutexGuard<'static, ()> {
        TEST_VOTE_TRACKING_MUTEX
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    #[cfg(test)]
    pub(crate) fn reset_test_vote_tracking() {
        if let Ok(mut mailbox) = NETWORK_VOTE_MAILBOX.lock() {
            mailbox.clear();
        }
        if let Ok(mut observed) = OBSERVED_VOTES.lock() {
            observed.clear();
        }
        if let Ok(mut evidence) = EQUIVOCATION_EVIDENCE_LOG.lock() {
            evidence.clear();
        }
        if let Ok(mut processed) = PROCESSED_EQUIVOCATION_EVIDENCE.lock() {
            processed.clear();
        }
        if let Ok(mut qcs) = COMMITTED_QC_STORE.lock() {
            qcs.clear();
        }
        if let Ok(mut index) = COMMITTED_QC_LOG_LOOKUP_INDEX.lock() {
            *index = CommittedQcLogLookupIndex::default();
        }
        COMMITTED_QC_LOG_PARSE_COUNT.store(0, Ordering::Relaxed);
        let qc_store_path = Self::committed_qc_store_path();
        let _ = fs::remove_file(qc_store_path.with_extension("json.tmp"));
        let _ = fs::remove_file(qc_store_path);
        let _ = fs::remove_file(Self::committed_qc_log_path());
        if let Ok(_guard) = LOCAL_VOTE_LOCK_FILE_MUTEX.lock() {
            let path = Self::local_vote_lock_path();
            let _ = fs::remove_file(path.with_extension("json.tmp"));
            let _ = fs::remove_file(path);
        }
    }

    #[cfg(test)]
    pub(crate) fn set_test_local_vote_lock_path(path: Option<PathBuf>) {
        if let Ok(mut test_path) = TEST_LOCAL_VOTE_LOCK_PATH.lock() {
            *test_path = path;
        }
    }
}

pub fn required_validator_quorum(total_validators: usize) -> usize {
    if total_validators == 0 {
        0
    } else {
        (total_validators * VALIDATOR_QUORUM_NUMERATOR) / VALIDATOR_QUORUM_DENOMINATOR + 1
    }
}

pub fn required_cluster_quorum(cluster_size: usize) -> usize {
    required_validator_quorum(cluster_size)
}

pub fn strict_voting_weight_quorum(signed_weight: u128, total_weight: u128) -> bool {
    total_weight > 0
        && signed_weight <= total_weight
        && signed_weight
            .checked_mul(VALIDATOR_QUORUM_DENOMINATOR as u128)
            .zip(total_weight.checked_mul(VALIDATOR_QUORUM_NUMERATOR as u128))
            .is_some_and(|(signed_scaled, total_scaled)| signed_scaled > total_scaled)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::validator_keys::{
        consensus_algorithm_label, register_test_validator_signing_key,
        sign_with_local_validator_key_for_height,
    };
    use crate::crypto::pqc::PQCAlgorithm;
    use crate::validator::{
        Validator, ValidatorRegistration, ValidatorStatus, EPOCH_VALIDATOR_SETS_ENV,
    };
    use base64::{engine::general_purpose, Engine as _};
    use std::fs;
    use std::path::PathBuf;

    fn epoch_set_env_test_lock() -> &'static Mutex<()> {
        crate::validator::epoch_validator_sets_env_lock()
    }

    struct EnvVarGuard {
        key: &'static str,
        previous: Option<String>,
    }

    impl EnvVarGuard {
        fn set(key: &'static str, value: &str) -> Self {
            let previous = env::var(key).ok();
            env::set_var(key, value);
            Self { key, previous }
        }
    }

    impl Drop for EnvVarGuard {
        fn drop(&mut self) {
            if let Some(previous) = self.previous.as_ref() {
                env::set_var(self.key, previous);
            } else {
                env::remove_var(self.key);
            }
        }
    }

    fn approved_validator_manager(addresses: &[&str]) -> Arc<ValidatorManager> {
        let manager = Arc::new(ValidatorManager::new());
        for address in addresses {
            let mut pqc_manager = PQCManager::new();
            let (public_key, private_key) = pqc_manager
                .generate_keypair(PQCAlgorithm::MLDSA65)
                .expect("test validator consensus key should generate");
            register_test_validator_signing_key(address, public_key.clone(), private_key);
            let encoded_public_key = format!(
                "{}:{}",
                consensus_algorithm_label(&public_key.algorithm),
                general_purpose::STANDARD.encode(&public_key.key_data)
            );
            manager
                .register_validator(ValidatorRegistration {
                    address: (*address).to_string(),
                    public_key: encoded_public_key,
                    name: format!("{address} validator"),
                    stake_amount: 1_000,
                    submitted_at: 0,
                    registration_tx_hash: format!("{address}-registration"),
                })
                .expect("validator registration should succeed");
            manager
                .approve_validator(address)
                .expect("validator approval should succeed");

            if let Ok(mut registry) = VALIDATOR_MANAGER.registry.lock() {
                let mut validator = Validator::new(
                    (*address).to_string(),
                    manager
                        .get_validator(address)
                        .expect("test validator should be registered")
                        .public_key,
                    format!("{address} validator"),
                    1_000,
                );
                validator.status = ValidatorStatus::Active;
                validator.activation_tx_hash = Some(format!("syntxn-test-{address}"));
                registry
                    .validators
                    .insert((*address).to_string(), validator);
                registry.pending_registrations.remove(*address);
            }
        }
        manager
    }

    fn equal_weight_validator_manager(count: usize) -> Arc<ValidatorManager> {
        let manager = Arc::new(ValidatorManager::new());
        let mut registry = manager
            .registry
            .lock()
            .expect("test validator registry should lock");
        registry.validators.clear();
        registry.pending_registrations.clear();
        for index in 1..=count {
            let address = format!("validator{index:03}");
            let mut validator = Validator::new(
                address.clone(),
                format!("test-public-key-{index}"),
                format!("Validator {index}"),
                1_000,
            );
            validator.status = ValidatorStatus::Active;
            validator.synergy_score = 100.0;
            registry.validators.insert(address, validator);
        }
        drop(registry);
        manager
    }

    fn test_qc(block_hash: &str) -> QuorumCertificate {
        QuorumCertificate {
            block_hash: block_hash.to_string(),
            cluster_id: None,
            epoch_number: 0,
            round_number: 1,
            aggregate_signature: vec![1, 2, 3],
            participant_bitmap: vec![0x0f],
            cumulative_weight: 4.0,
            validation_quorum_met: true,
            cooperation_quorum_met: true,
            timestamp: 1_700_000_000,
            votes: Vec::new(),
        }
    }

    fn signed_block_for_manager(
        height: u64,
        nonce: u64,
        validator_id: &str,
        validator_manager: &Arc<ValidatorManager>,
    ) -> Block {
        let mut block = Block::new(
            height,
            Vec::new(),
            "parent-hash".to_string(),
            validator_id.to_string(),
            nonce,
        );
        let (public_key, signature) = sign_with_local_validator_key_for_height(
            height,
            validator_id,
            block.hash.as_bytes(),
            validator_manager,
        )
        .expect("test proposer should sign block");
        block.proposer_public_key = public_key.key_data;
        block.block_signature = signature.signature_data;
        block.block_signature_algorithm = "ml-dsa-65".to_string();
        block
    }

    fn signed_vote_with_explicit_cluster_context(
        validator: &Validator,
        block: &Block,
        epoch_number: u64,
        round_number: u64,
        validator_manager: &Arc<ValidatorManager>,
    ) -> Vote {
        let message = DualQuorumConsensus::vote_signature_payload(
            &validator.address,
            &block.hash,
            block.block_index,
            epoch_number,
            round_number,
            validator.cluster_id,
        );
        let (public_key, signature) = sign_with_local_validator_key_for_height(
            block.block_index,
            &validator.address,
            message.as_bytes(),
            validator_manager,
        )
        .expect("test validator should sign its cluster-scoped vote");

        Vote {
            validator_address: validator.address.clone(),
            block_hash: block.hash.clone(),
            block_index: block.block_index,
            epoch_number,
            round_number,
            signature,
            signer_public_key: public_key.key_data,
            timestamp: DualQuorumConsensus::current_timestamp(),
        }
    }

    #[test]
    fn multi_cluster_quorum_finalizes_each_cluster_and_rejects_other_cluster_votes() {
        let _vote_tracking_guard = DualQuorumConsensus::test_vote_tracking_guard();
        DualQuorumConsensus::reset_test_vote_tracking();

        let validator_manager = approved_validator_manager(&[
            "validator1",
            "validator2",
            "validator3",
            "validator4",
            "validator5",
            "validator6",
            "validator7",
            "validator8",
            "validator9",
            "validator10",
        ]);
        validator_manager.reorganize_clusters_for_epoch(0);
        let active_validators =
            consensus_membership_validators(validator_manager.get_active_validators());
        let clusters = canonical_validator_clusters_for_epoch(&active_validators, 0);
        assert_eq!(clusters.len(), 2);
        assert_eq!(
            clusters
                .iter()
                .map(|(_, members)| members.len())
                .collect::<Vec<_>>(),
            vec![5, 5]
        );

        let pqc_manager = Arc::new(Mutex::new(PQCManager::new()));
        let mut consensus = DualQuorumConsensus::new(
            Arc::clone(&validator_manager),
            Arc::clone(&pqc_manager),
            false,
            1,
            1,
            1,
            2,
        );

        for (cluster_index, (cluster_id, members)) in clusters.iter().enumerate() {
            let proposer = members
                .first()
                .expect("canonical cluster should have a proposer")
                .address
                .clone();
            let block = signed_block_for_manager(
                42,
                100 + cluster_index as u64,
                &proposer,
                &validator_manager,
            );
            let own_votes = members
                .iter()
                .take(4)
                .map(|validator| {
                    DualQuorumConsensus::create_vote_for_validator_with_manager(
                        &validator.address,
                        &block,
                        0,
                        1,
                        &validator_manager,
                    )
                    .expect("cluster validator should sign its proposal vote")
                })
                .collect::<Vec<_>>();
            let context = ConsensusClusterContext {
                cluster_id: Some(*cluster_id),
                validators: members.clone(),
            };
            assert!(
                consensus.has_commit_quorum_for_cluster(&context, &own_votes),
                "cluster {} should reach quorum with four of its five validators",
                cluster_id
            );
            let insufficient_votes = own_votes.iter().take(3).cloned().collect::<Vec<_>>();
            assert!(
                !consensus.has_commit_quorum_for_cluster(&context, &insufficient_votes),
                "cluster {} must not reach quorum with only three of its five validators",
                cluster_id
            );
            let qc = consensus
                .check_quorums_and_commit(&block, 0, 1, &own_votes)
                .expect("cluster quorum should finalize its proposal");
            assert_eq!(qc.cluster_id, Some(*cluster_id));
            DualQuorumConsensus::verify_commit_certificate_for_block_static(
                &block,
                &qc,
                &validator_manager,
            )
            .expect("finalized cluster QC should verify against canonical membership");

            let other_members = clusters
                .iter()
                .find(|(other_id, _)| other_id != cluster_id)
                .map(|(_, other_members)| other_members)
                .expect("two-cluster fixture should have another cluster");
            let cross_cluster_votes = other_members
                .iter()
                .take(4)
                .map(|validator| {
                    signed_vote_with_explicit_cluster_context(
                        validator,
                        &block,
                        0,
                        1,
                        &validator_manager,
                    )
                })
                .collect::<Vec<_>>();
            assert!(
                !consensus.has_commit_quorum_for_cluster(&context, &cross_cluster_votes),
                "votes from cluster {} must not satisfy cluster {}",
                other_members
                    .first()
                    .and_then(|validator| validator.cluster_id)
                    .expect("other cluster id should be present"),
                cluster_id
            );
            assert!(
                consensus
                    .check_quorums_and_commit(&block, 0, 1, &cross_cluster_votes)
                    .is_err(),
                "finality must reject a QC assembled from the other cluster"
            );
        }
    }

    #[test]
    fn multi_cluster_context_fails_closed_for_missing_assignment_and_qc_context() {
        let validator_manager = equal_weight_validator_manager(10);
        validator_manager.reorganize_clusters_for_epoch(0);
        let active_validators =
            consensus_membership_validators(validator_manager.get_active_validators());
        let proposer = active_validators
            .first()
            .expect("multi-cluster fixture should have an active validator")
            .address
            .clone();
        let context = DualQuorumConsensus::cluster_context_for_validators(
            &validator_manager,
            &active_validators,
            0,
            &proposer,
        )
        .expect("canonical multi-cluster context should resolve");
        assert!(context.cluster_id.is_some());
        assert!(DualQuorumConsensus::validate_qc_cluster_context(&context, None).is_err());

        {
            let mut registry = validator_manager
                .registry
                .lock()
                .expect("test validator registry should lock");
            registry
                .validators
                .get_mut(&proposer)
                .expect("proposer should exist")
                .cluster_id = None;
        }
        let malformed_active =
            consensus_membership_validators(validator_manager.get_active_validators());
        let error = DualQuorumConsensus::cluster_context_for_validators(
            &validator_manager,
            &malformed_active,
            0,
            &proposer,
        )
        .expect_err("missing persisted cluster assignment must fail closed");
        assert!(error.contains("missing canonical cluster context"));
    }

    fn test_qc_at_height(block_hash: &str, height: u64) -> QuorumCertificate {
        let mut qc = test_qc(block_hash);
        qc.votes = vec![Vote {
            validator_address: "validator1".to_string(),
            block_hash: block_hash.to_string(),
            block_index: height,
            epoch_number: 0,
            round_number: 1,
            signature: PQCSignature {
                algorithm: PQCAlgorithm::FNDSA,
                signature_data: Vec::new(),
                message_hash: Vec::new(),
                public_key_id: String::new(),
                created_at: 0,
            },
            signer_public_key: Vec::new(),
            timestamp: height,
        }];
        qc
    }

    #[test]
    fn qc_verification_requires_strict_four_of_five_cluster_quorum() {
        let _vote_tracking_guard = DualQuorumConsensus::test_vote_tracking_guard();

        let required = DualQuorumConsensus::required_qc_validator_votes(5, true);

        assert_eq!(required, 4);
    }

    #[test]
    fn qc_verification_requires_strict_five_of_six_quorum() {
        let _vote_tracking_guard = DualQuorumConsensus::test_vote_tracking_guard();

        let required = DualQuorumConsensus::required_qc_validator_votes(6, true);

        assert_eq!(required, 5);
        assert_eq!(required, required_validator_quorum(6));
    }

    #[test]
    fn qc_verification_requires_dynamic_quorum_for_expanded_set() {
        let _vote_tracking_guard = DualQuorumConsensus::test_vote_tracking_guard();

        let required = DualQuorumConsensus::required_qc_validator_votes(10, false);

        assert_eq!(required, required_validator_quorum(10));
    }

    #[test]
    fn qc_verification_requires_five_of_seven_cluster_quorum() {
        let _vote_tracking_guard = DualQuorumConsensus::test_vote_tracking_guard();

        let required = DualQuorumConsensus::required_qc_validator_votes(7, true);

        assert_eq!(required, 5);
    }

    #[test]
    fn frozen_voting_weight_quorum_is_strictly_greater_than_two_thirds() {
        assert!(!strict_voting_weight_quorum(0, 0));
        assert!(!strict_voting_weight_quorum(2, 3));
        assert!(strict_voting_weight_quorum(3, 4));
        assert!(!strict_voting_weight_quorum(4, 6));
        assert!(strict_voting_weight_quorum(5, 6));
        assert!(!strict_voting_weight_quorum(11, 10));
    }

    #[test]
    fn historical_qc_verification_uses_epoch_validator_set_for_block_height() {
        let _epoch_set_env_guard = epoch_set_env_test_lock()
            .lock()
            .expect("epoch validator set env test lock should succeed");
        let _vote_tracking_guard = DualQuorumConsensus::test_vote_tracking_guard();
        let validator_manager = approved_validator_manager(&[
            "validator1",
            "validator2",
            "validator3",
            "validator4",
            "validator5",
            "validator6",
            "validator7",
        ]);
        {
            let mut registry = validator_manager
                .registry
                .lock()
                .expect("transition test registry should lock");
            let validator = registry
                .validators
                .get_mut("validator7")
                .expect("transition validator should be registered");
            validator.status = ValidatorStatus::Shadow;
            validator.activation_recorded_height = Some(99);
            validator.activation_effective_height = Some(100);
        }
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let temp_dir = crate::utils::test_temp_root(format!("synergy-qc-epoch-set-{unique}"));
        fs::create_dir_all(&temp_dir).unwrap();
        let snapshot_path = temp_dir.join("epoch-validator-sets.json");
        fs::write(
            &snapshot_path,
            serde_json::json!({
                "epoch_validator_sets": [{
                    "chain_id": 1266,
                    "epoch_id": 0,
                    "validator_set_version": 1,
                    "effective_from_height": 1,
                    "effective_to_height": 99,
                    "active_validators": [
                        "validator1",
                        "validator2",
                        "validator3",
                        "validator4",
                        "validator5",
                        "validator6"
                    ],
                    "pending_validators": ["validator7"],
                    "quorum_threshold": 5,
                    "validator_set_hash": "historical-dynamic-validator-set"
                }]
            })
            .to_string(),
        )
        .unwrap();
        let _snapshot_path =
            EnvVarGuard::set(EPOCH_VALIDATOR_SETS_ENV, &snapshot_path.to_string_lossy());

        let mut block = Block::new(
            1,
            vec![],
            "parent-hash".to_string(),
            "validator1".to_string(),
            1,
        );
        let (proposer_public_key, proposer_signature) = sign_with_local_validator_key_for_height(
            block.block_index,
            "validator1",
            block.hash.as_bytes(),
            &validator_manager,
        )
        .expect("validator1 proposer key should sign test block");
        block.proposer_public_key = proposer_public_key.key_data;
        block.block_signature = proposer_signature.signature_data;
        block.block_signature_algorithm = "ml-dsa-65".to_string();
        let mut qc = test_qc(&block.hash);
        qc.votes = vec![Vote {
            validator_address: "validator7".to_string(),
            block_hash: block.hash.clone(),
            block_index: block.block_index,
            epoch_number: qc.epoch_number,
            round_number: qc.round_number,
            signature: PQCSignature {
                algorithm: PQCAlgorithm::FNDSA,
                signature_data: Vec::new(),
                message_hash: Vec::new(),
                public_key_id: String::new(),
                created_at: 0,
            },
            signer_public_key: Vec::new(),
            timestamp: block.timestamp,
        }];

        let result = DualQuorumConsensus::verify_commit_certificate_for_block_static(
            &block,
            &qc,
            &validator_manager,
        );

        fs::remove_dir_all(temp_dir).ok();

        let error = result.expect_err("validator7 is pending in the historical epoch set");
        assert!(
            error.contains("outside active validator set"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn vote_creation_and_qc_verification_agree_at_validator_set_transition() {
        let _epoch_set_env_guard = epoch_set_env_test_lock()
            .lock()
            .expect("epoch validator set env test lock should succeed");
        let _vote_tracking_guard = DualQuorumConsensus::test_vote_tracking_guard();
        let validator_manager = approved_validator_manager(&[
            "validator1",
            "validator2",
            "validator3",
            "validator4",
            "validator5",
            "validator6",
            "validator7",
        ]);
        {
            let mut registry = validator_manager
                .registry
                .lock()
                .expect("transition test registry should lock");
            let validator = registry
                .validators
                .get_mut("validator7")
                .expect("transition validator should be registered");
            validator.status = ValidatorStatus::Shadow;
            validator.activation_recorded_height = Some(99);
            validator.activation_effective_height = Some(100);
        }
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let temp_dir =
            crate::utils::test_temp_root(format!("synergy-membership-transition-{unique}"));
        fs::create_dir_all(&temp_dir).unwrap();
        let snapshot_path = temp_dir.join("epoch-validator-sets.json");
        fs::write(
            &snapshot_path,
            serde_json::json!({
                "epoch_validator_sets": [
                    {
                        "chain_id": 1266,
                        "epoch_id": 0,
                        "validator_set_version": 1,
                        "effective_from_height": 1,
                        "effective_to_height": 99,
                        "active_validators": [
                            "validator1",
                            "validator2",
                            "validator3",
                            "validator4",
                            "validator5",
                            "validator6"
                        ],
                        "pending_validators": ["validator7"],
                        "quorum_threshold": 5,
                        "validator_set_hash": "pre-transition-set"
                    },
                    {
                        "chain_id": 1266,
                        "epoch_id": 1,
                        "validator_set_version": 2,
                        "effective_from_height": 100,
                        "active_validators": [
                            "validator1",
                            "validator2",
                            "validator3",
                            "validator4",
                            "validator5",
                            "validator6",
                            "validator7"
                        ],
                        "quorum_threshold": 5,
                        "validator_set_hash": "post-transition-set"
                    }
                ]
            })
            .to_string(),
        )
        .unwrap();
        let _snapshot_guard =
            EnvVarGuard::set(EPOCH_VALIDATOR_SETS_ENV, &snapshot_path.to_string_lossy());

        let mut before_boundary = Block::new(
            99,
            vec![],
            "parent-hash".to_string(),
            "validator1".to_string(),
            1,
        );
        let (proposer_public_key, proposer_signature) = sign_with_local_validator_key_for_height(
            before_boundary.block_index,
            "validator1",
            before_boundary.hash.as_bytes(),
            &validator_manager,
        )
        .expect("validator1 proposer key should sign pre-transition block");
        before_boundary.proposer_public_key = proposer_public_key.key_data;
        before_boundary.block_signature = proposer_signature.signature_data;
        before_boundary.block_signature_algorithm = "ml-dsa-65".to_string();

        let vote_error = DualQuorumConsensus::create_vote_for_validator_with_manager(
            "validator7",
            &before_boundary,
            0,
            1,
            &validator_manager,
        )
        .expect_err("pending validator must not create a pre-transition vote");
        assert!(
            vote_error.contains("not in the canonical proposal cluster"),
            "unexpected vote error: {vote_error}"
        );

        let mut pre_transition_qc = test_qc(&before_boundary.hash);
        pre_transition_qc.votes = vec![Vote {
            validator_address: "validator7".to_string(),
            block_hash: before_boundary.hash.clone(),
            block_index: before_boundary.block_index,
            epoch_number: 0,
            round_number: 1,
            signature: PQCSignature {
                algorithm: PQCAlgorithm::FNDSA,
                signature_data: Vec::new(),
                message_hash: Vec::new(),
                public_key_id: String::new(),
                created_at: 0,
            },
            signer_public_key: Vec::new(),
            timestamp: before_boundary.timestamp,
        }];
        let qc_error = DualQuorumConsensus::verify_commit_certificate_for_block_static(
            &before_boundary,
            &pre_transition_qc,
            &validator_manager,
        )
        .expect_err("the QC verifier must reject the same pending signer");
        assert!(
            qc_error.contains("outside active validator set"),
            "unexpected QC error: {qc_error}"
        );

        let after_boundary = Block::new(
            100,
            vec![],
            "parent-hash".to_string(),
            "validator1".to_string(),
            1,
        );
        assert_eq!(
            validator_manager
                .get_validator("validator7")
                .expect("validator7 should remain registered")
                .status,
            ValidatorStatus::Shadow,
            "the height-scoped membership resolver must not require an early registry mutation"
        );
        let vote = DualQuorumConsensus::create_vote_for_validator_with_manager(
            "validator7",
            &after_boundary,
            1,
            1,
            &validator_manager,
        )
        .expect("validator7 must create a vote at its effective height");
        assert_eq!(vote.block_index, 100);
        assert_eq!(
            validator_manager
                .get_validator("validator7")
                .expect("validator7 should remain registered")
                .status,
            ValidatorStatus::Shadow,
            "vote construction must not mutate finalized validator state"
        );

        fs::remove_dir_all(temp_dir).ok();
    }

    #[test]
    fn incompatible_epoch_validator_set_blocks_vote_signing() {
        let _epoch_set_env_guard = epoch_set_env_test_lock()
            .lock()
            .expect("epoch validator set env test lock should succeed");
        let validator_manager = approved_validator_manager(&["validator1"]);
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let temp_dir = crate::utils::test_temp_root(format!("synergy-vote-epoch-compat-{unique}"));
        fs::create_dir_all(&temp_dir).unwrap();
        let snapshot_path = temp_dir.join("epoch-validator-sets.json");
        fs::write(
            &snapshot_path,
            serde_json::json!({
                "epoch_validator_sets": [{
                    "snapshot_format_version": crate::validator::SUPPORTED_EPOCH_VALIDATOR_SET_FORMAT_VERSION,
                    "chain_id": 1266,
                    "epoch_id": 0,
                    "validator_set_version": 1,
                    "effective_from_height": 1,
                    "active_validators": ["validator1"],
                    "quorum_threshold": 1,
                    "validator_set_hash": "wrong-runtime-set",
                    "required_binary_version": "0.0.0-incompatible"
                }]
            })
            .to_string(),
        )
        .unwrap();
        let _snapshot_path =
            EnvVarGuard::set(EPOCH_VALIDATOR_SETS_ENV, &snapshot_path.to_string_lossy());
        let block = Block::new(
            1,
            vec![],
            "parent-hash".to_string(),
            "validator1".to_string(),
            1,
        );

        let error = DualQuorumConsensus::create_vote_for_validator_with_manager(
            "validator1",
            &block,
            0,
            1,
            &validator_manager,
        )
        .expect_err("wrong binary version must prevent local vote signing");

        fs::remove_dir_all(temp_dir).ok();
        assert!(
            error.contains("refusing vote because validator-set snapshot is incompatible"),
            "unexpected error: {error}"
        );
        assert!(
            error.contains("requires binary version 0.0.0-incompatible"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn committed_qc_store_is_persisted_incrementally() {
        let _guard = DualQuorumConsensus::test_vote_tracking_guard();
        DualQuorumConsensus::reset_test_vote_tracking();

        let later = test_qc("block-z");
        let earlier = test_qc("block-a");
        DualQuorumConsensus::record_committed_qc(later.clone());
        DualQuorumConsensus::record_committed_qc(earlier.clone());

        assert_eq!(
            DualQuorumConsensus::committed_qc_for_block_hash("block-a").map(|qc| qc.block_hash),
            Some("block-a".to_string())
        );

        let loaded = DualQuorumConsensus::load_committed_qc_store_from_disk()
            .expect("committed QC store should reload from disk");
        assert_eq!(loaded.get("block-z").map(|qc| qc.round_number), Some(1));

        let raw =
            fs::read_to_string(DualQuorumConsensus::committed_qc_log_path()).unwrap_or_default();
        let lines = raw.lines().collect::<Vec<_>>();
        assert_eq!(lines.len(), 2);
        assert!(lines[0].contains("\"block-z\""));
        assert!(lines[1].contains("\"block-a\""));
    }

    #[test]
    fn committed_qc_hot_load_reads_only_a_bounded_tail_and_preserves_archive() {
        let _guard = DualQuorumConsensus::test_vote_tracking_guard();
        DualQuorumConsensus::reset_test_vote_tracking();
        let _retention = EnvVarGuard::set(COMMITTED_QC_HOT_RETENTION_BLOCKS_ENV, "100");

        let first_qc = test_qc_at_height("block-1", 1);
        let line_size = serde_json::to_vec(&CommittedQcLogEntry {
            block_hash: first_qc.block_hash.clone(),
            qc: first_qc.clone(),
        })
        .unwrap()
        .len()
        .saturating_add(1);
        let _max_load =
            EnvVarGuard::set(COMMITTED_QC_HOT_LOAD_MAX_BYTES_ENV, &line_size.to_string());

        for height in 1..=8 {
            DualQuorumConsensus::append_committed_qc_to_log(&test_qc_at_height(
                &format!("block-{height}"),
                height,
            ))
            .unwrap();
        }
        let archive_before = fs::read(DualQuorumConsensus::committed_qc_log_path()).unwrap();

        let loaded = DualQuorumConsensus::load_committed_qc_store_from_disk()
            .expect("bounded committed QC tail should load");

        assert!(!loaded.contains_key("block-1"));
        assert!(loaded.contains_key("block-8"));
        assert_eq!(
            fs::read(DualQuorumConsensus::committed_qc_log_path()).unwrap(),
            archive_before,
            "hot loading must not rewrite or truncate the archival journal"
        );
    }

    #[test]
    fn committed_qc_hot_load_skips_oversized_legacy_snapshot() {
        let _guard = DualQuorumConsensus::test_vote_tracking_guard();
        DualQuorumConsensus::reset_test_vote_tracking();
        let _retention = EnvVarGuard::set(COMMITTED_QC_HOT_RETENTION_BLOCKS_ENV, "100");
        let journal_qc = test_qc_at_height("journal-current", 8);
        let journal_line_size = serde_json::to_vec(&CommittedQcLogEntry {
            block_hash: journal_qc.block_hash.clone(),
            qc: journal_qc.clone(),
        })
        .unwrap()
        .len()
        .saturating_add(1);
        let _max_load = EnvVarGuard::set(
            COMMITTED_QC_HOT_LOAD_MAX_BYTES_ENV,
            &journal_line_size.to_string(),
        );

        let mut legacy = BTreeMap::new();
        for index in 0..16 {
            let legacy_qc = test_qc(&format!("legacy-{index}"));
            legacy.insert(legacy_qc.block_hash.clone(), legacy_qc);
        }
        fs::write(
            DualQuorumConsensus::committed_qc_store_path(),
            serde_json::to_vec(&legacy).unwrap(),
        )
        .unwrap();
        assert!(
            fs::metadata(DualQuorumConsensus::committed_qc_store_path())
                .unwrap()
                .len()
                > journal_line_size as u64
        );

        DualQuorumConsensus::append_committed_qc_to_log(&journal_qc).unwrap();
        let loaded = DualQuorumConsensus::load_committed_qc_store_from_disk()
            .expect("oversized legacy snapshot must not prevent journal tail load");

        assert!(!loaded.contains_key("legacy-0"));
        assert!(loaded.contains_key("journal-current"));
    }

    #[test]
    fn committed_qc_store_does_not_append_duplicate_qc() {
        let _guard = DualQuorumConsensus::test_vote_tracking_guard();
        DualQuorumConsensus::reset_test_vote_tracking();

        let qc = test_qc("block-once");
        DualQuorumConsensus::record_committed_qc(qc.clone());
        DualQuorumConsensus::record_committed_qc(qc);

        let raw =
            fs::read_to_string(DualQuorumConsensus::committed_qc_log_path()).unwrap_or_default();
        assert_eq!(raw.lines().count(), 1);
    }

    #[test]
    fn committed_qc_store_load_honors_hot_retention_env() {
        let _guard = DualQuorumConsensus::test_vote_tracking_guard();
        DualQuorumConsensus::reset_test_vote_tracking();
        let previous = env::var(COMMITTED_QC_HOT_RETENTION_BLOCKS_ENV).ok();
        env::set_var(COMMITTED_QC_HOT_RETENTION_BLOCKS_ENV, "3");

        for height in 1..=8 {
            DualQuorumConsensus::append_committed_qc_to_log(&test_qc_at_height(
                &format!("block-{height}"),
                height,
            ))
            .unwrap();
        }

        let loaded = DualQuorumConsensus::load_committed_qc_store_from_disk()
            .expect("committed QC log should load");

        assert!(!loaded.contains_key("block-5"));
        assert!(loaded.contains_key("block-6"));
        assert!(loaded.contains_key("block-7"));
        assert!(loaded.contains_key("block-8"));

        match previous {
            Some(value) => env::set_var(COMMITTED_QC_HOT_RETENTION_BLOCKS_ENV, value),
            None => env::remove_var(COMMITTED_QC_HOT_RETENTION_BLOCKS_ENV),
        }
    }

    #[test]
    fn committed_qc_batch_lookup_reads_historical_log_entries_outside_hot_retention() {
        let _guard = DualQuorumConsensus::test_vote_tracking_guard();
        DualQuorumConsensus::reset_test_vote_tracking();
        let previous = env::var(COMMITTED_QC_HOT_RETENTION_BLOCKS_ENV).ok();
        env::set_var(COMMITTED_QC_HOT_RETENTION_BLOCKS_ENV, "3");

        for height in 1..=8 {
            DualQuorumConsensus::append_committed_qc_to_log(&test_qc_at_height(
                &format!("block-{height}"),
                height,
            ))
            .unwrap();
        }

        let qcs = DualQuorumConsensus::committed_qcs_for_block_hashes([
            "block-2",
            "block-8",
            "missing-block",
        ]);
        let hashes = qcs
            .iter()
            .map(|qc| qc.block_hash.as_str())
            .collect::<HashSet<_>>();

        assert_eq!(hashes.len(), 2);
        assert!(hashes.contains("block-2"));
        assert!(hashes.contains("block-8"));

        match previous {
            Some(value) => env::set_var(COMMITTED_QC_HOT_RETENTION_BLOCKS_ENV, value),
            None => env::remove_var(COMMITTED_QC_HOT_RETENTION_BLOCKS_ENV),
        }
    }

    #[test]
    fn committed_qc_historical_lookup_uses_bounded_tail_index() {
        let _guard = DualQuorumConsensus::test_vote_tracking_guard();
        DualQuorumConsensus::reset_test_vote_tracking();

        for height in 1..=64 {
            DualQuorumConsensus::append_committed_qc_to_log(&test_qc_at_height(
                &format!("block-{height}"),
                height,
            ))
            .unwrap();
        }
        let raw = fs::read(DualQuorumConsensus::committed_qc_log_path()).unwrap();
        let line_size = raw.lines().next().unwrap().unwrap().len() + 1;
        let _max_load = EnvVarGuard::set(
            COMMITTED_QC_HOT_LOAD_MAX_BYTES_ENV,
            &(line_size.saturating_mul(2)).to_string(),
        );
        COMMITTED_QC_LOG_PARSE_COUNT.store(0, Ordering::Relaxed);

        let requested = HashSet::from(["block-64".to_string()]);
        let qcs = DualQuorumConsensus::committed_qcs_from_log_for_block_hashes(&requested)
            .expect("near-tail historical lookup should succeed");

        assert_eq!(
            qcs.iter()
                .map(|qc| qc.block_hash.as_str())
                .collect::<Vec<_>>(),
            vec!["block-64"]
        );
        let parsed = COMMITTED_QC_LOG_PARSE_COUNT.load(Ordering::Relaxed);
        assert!(
            parsed < 64,
            "near-tail lookup parsed the full prefix: {parsed} entries"
        );
    }

    #[test]
    fn committed_qc_historical_lookup_reuses_forward_cursor_for_catch_up_batches() {
        let _guard = DualQuorumConsensus::test_vote_tracking_guard();
        DualQuorumConsensus::reset_test_vote_tracking();

        for height in 1..=32 {
            DualQuorumConsensus::append_committed_qc_to_log(&test_qc_at_height(
                &format!("block-{height}"),
                height,
            ))
            .unwrap();
        }
        let raw = fs::read(DualQuorumConsensus::committed_qc_log_path()).unwrap();
        let line_size = raw.lines().next().unwrap().unwrap().len() + 1;
        let _max_load = EnvVarGuard::set(
            COMMITTED_QC_HOT_LOAD_MAX_BYTES_ENV,
            &(line_size.saturating_mul(2)).to_string(),
        );
        COMMITTED_QC_LOG_PARSE_COUNT.store(0, Ordering::Relaxed);

        let lookup = |first: u64, last: u64| {
            let requested = (first..=last)
                .map(|height| format!("block-{height}"))
                .collect::<HashSet<_>>();
            DualQuorumConsensus::committed_qcs_from_log_for_block_hashes(&requested)
                .expect("forward historical lookup should succeed")
        };

        let first = lookup(1, 2);
        assert_eq!(first.len(), 2);
        let after_first = COMMITTED_QC_LOG_PARSE_COUNT.load(Ordering::Relaxed);

        let second = lookup(3, 4);
        assert_eq!(second.len(), 2);
        let after_second = COMMITTED_QC_LOG_PARSE_COUNT.load(Ordering::Relaxed);

        let third = lookup(5, 6);
        assert_eq!(third.len(), 2);
        let after_third = COMMITTED_QC_LOG_PARSE_COUNT.load(Ordering::Relaxed);

        assert!(after_first < 32, "initial lookup parsed the full log");
        assert!(
            after_second.saturating_sub(after_first) <= 2,
            "second catch-up batch rescanned the prefix: {} entries",
            after_second.saturating_sub(after_first)
        );
        assert!(
            after_third.saturating_sub(after_second) <= 2,
            "third catch-up batch rescanned the prefix: {} entries",
            after_third.saturating_sub(after_second)
        );
    }

    #[test]
    fn committed_qc_historical_lookup_fails_closed_on_malformed_tail() {
        let _guard = DualQuorumConsensus::test_vote_tracking_guard();
        DualQuorumConsensus::reset_test_vote_tracking();

        DualQuorumConsensus::append_committed_qc_to_log(&test_qc_at_height("block-1", 1)).unwrap();
        let log_path = DualQuorumConsensus::committed_qc_log_path();
        let mut file = OpenOptions::new().append(true).open(&log_path).unwrap();
        file.write_all(b"{not-json}\n").unwrap();
        file.sync_all().unwrap();
        let _max_load = EnvVarGuard::set(COMMITTED_QC_HOT_LOAD_MAX_BYTES_ENV, "4096");

        let requested = HashSet::from(["block-1".to_string()]);
        let error = DualQuorumConsensus::committed_qcs_from_log_for_block_hashes(&requested)
            .expect_err("malformed historical log data must fail closed");
        assert!(
            error.contains("failed to parse committed QC log"),
            "unexpected error: {error}"
        );
    }

    fn signed_block(block_index: u64, nonce: u64, validator_id: &str) -> Block {
        let mut block = Block::new(
            block_index,
            vec![],
            "parent-hash".to_string(),
            validator_id.to_string(),
            nonce,
        );

        let mut pqc_manager = PQCManager::new();
        let (public_key, private_key) = pqc_manager
            .generate_keypair(PQCAlgorithm::MLDSA65)
            .expect("FN-DSA key generation should succeed");
        let signature = pqc_manager
            .sign(&private_key, block.hash.as_bytes())
            .expect("block signing should succeed");
        block.proposer_public_key = public_key.key_data;
        block.block_signature = signature.signature_data;
        block.block_signature_algorithm = "ml-dsa-65".to_string();
        block
    }

    fn signed_test_transaction() -> crate::transaction::Transaction {
        let mut tx = crate::transaction::Transaction::new(
            "synw1sender".to_string(),
            "synw1receiver".to_string(),
            1,
            0,
            Vec::new(),
            1,
            21_000,
            None,
            "mldsa87".to_string(),
        );
        let mut pqc_manager = PQCManager::new();
        let (public_key, private_key) = pqc_manager
            .generate_keypair(PQCAlgorithm::MLDSA87)
            .expect("ML-DSA-87 transaction key generation should succeed");
        tx.sign_with_public_key(&public_key, &private_key, &mut pqc_manager)
            .expect("transaction signing should succeed");
        tx
    }

    #[test]
    fn block_proposal_rejects_transaction_without_valid_pqc_admission() {
        let mut block = signed_block(1, 1, "validator1");
        block.transactions = vec![signed_test_transaction()];
        block.transactions[0].signature.clear();
        block.transactions_root = crate::block::compute_merkle_root(&block.transactions);
        block.hash = block.recompute_hash();
        let mut pqc_manager = PQCManager::new();
        let (public_key, private_key) = pqc_manager
            .generate_keypair(PQCAlgorithm::MLDSA65)
            .expect("FN-DSA block key generation should succeed");
        let signature = pqc_manager
            .sign(&private_key, block.hash.as_bytes())
            .expect("block signing should succeed");
        block.proposer_public_key = public_key.key_data;
        block.block_signature = signature.signature_data;

        assert!(DualQuorumConsensus::validate_block_proposal_static(&block).is_err());
    }

    fn temp_vote_lock_path(test_name: &str) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time should be valid")
            .as_nanos();
        crate::utils::test_temp_root(format!("synergy-{test_name}-{unique}"))
            .join("data")
            .join("consensus_vote_locks.json")
    }

    #[test]
    fn configured_vote_timeout_keeps_first_round_fast() {
        let validator_manager = approved_validator_manager(&["validator1", "validator2"]);
        let pqc_manager = Arc::new(Mutex::new(PQCManager::new()));
        let consensus = DualQuorumConsensus::new(
            Arc::clone(&validator_manager),
            Arc::clone(&pqc_manager),
            true,
            2,
            2,
            0,
            6,
        );

        assert_eq!(consensus.vote_timeout, FAST_CONSENSUS_VOTE_TIMEOUT_SECS);
        assert_eq!(
            consensus.effective_vote_timeout_secs(1),
            FAST_CONSENSUS_VOTE_TIMEOUT_SECS
        );
        assert_eq!(consensus.validator_vote_threshold, 2);
        assert_eq!(consensus.minimum_validator_count, 2);
    }

    #[test]
    fn adaptive_vote_timeout_only_extends_retries_and_stays_bounded() {
        let validator_manager = approved_validator_manager(&["validator1", "validator2"]);
        let pqc_manager = Arc::new(Mutex::new(PQCManager::new()));
        let consensus = DualQuorumConsensus::new(
            Arc::clone(&validator_manager),
            Arc::clone(&pqc_manager),
            true,
            2,
            2,
            2,
            6,
        );

        assert_eq!(consensus.effective_vote_timeout_secs(1), 2);
        assert_eq!(
            consensus.effective_vote_timeout_secs(2),
            RECOVERY_FIRST_RETRY_VOTE_TIMEOUT_SECS
        );
        assert_eq!(
            consensus.effective_vote_timeout_secs(42),
            RECOVERY_MAX_VOTE_TIMEOUT_SECS
        );
        assert_eq!(DualQuorumConsensus::timeout_mode_for_round(1), "fast");
        assert_eq!(DualQuorumConsensus::timeout_mode_for_round(2), "recovery");
    }

    #[test]
    fn same_height_same_round_double_vote_rejected() {
        let _vote_tracking_guard = DualQuorumConsensus::test_vote_tracking_guard();
        DualQuorumConsensus::reset_test_vote_tracking();

        let validator_manager = approved_validator_manager(&["validator1", "validator2"]);
        let pqc_manager = Arc::new(Mutex::new(PQCManager::new()));
        let consensus = DualQuorumConsensus::new(
            Arc::clone(&validator_manager),
            Arc::clone(&pqc_manager),
            true,
            1,
            1,
            8,
            5,
        );

        let first_block = signed_block(7, 1, "validator1");
        let conflicting_block = signed_block(7, 2, "validator1");

        let first_vote = DualQuorumConsensus::create_vote_for_validator_with_manager(
            "validator2",
            &first_block,
            12,
            1,
            &validator_manager,
        )
        .expect("first vote should be created");
        assert!(DualQuorumConsensus::register_vote_observation(&first_vote).is_none());

        let conflicting_vote = DualQuorumConsensus::create_vote_for_validator_with_manager(
            "validator2",
            &conflicting_block,
            12,
            1,
            &validator_manager,
        )
        .expect("conflicting vote should be created");
        let evidence = DualQuorumConsensus::register_vote_observation(&conflicting_vote)
            .expect("conflicting vote should emit equivocation evidence");

        consensus.apply_recorded_equivocations();

        let validator = validator_manager
            .get_validator("validator2")
            .expect("validator should still exist");
        assert_eq!(validator.status, ValidatorStatus::Slashed);
        assert_eq!(validator.double_signs, 1);
        assert_eq!(validator.equivocation_evidence_count, 1);
        assert_eq!(evidence.block_index, 7);
        assert_eq!(evidence.epoch_number, 12);
        assert_eq!(evidence.round_number, 1);
    }

    #[test]
    fn validator_can_repeat_same_block_vote_in_new_round() {
        let _vote_tracking_guard = DualQuorumConsensus::test_vote_tracking_guard();
        DualQuorumConsensus::reset_test_vote_tracking();

        let validator_manager = approved_validator_manager(&["validator1", "validator2"]);
        let block = signed_block(9, 1, "validator1");

        let first_vote = DualQuorumConsensus::create_vote_for_validator_with_manager(
            "validator2",
            &block,
            21,
            1,
            &validator_manager,
        )
        .expect("round one vote should be created");
        assert!(DualQuorumConsensus::register_vote_observation(&first_vote).is_none());

        let next_round_vote = DualQuorumConsensus::create_vote_for_validator_with_manager(
            "validator2",
            &block,
            21,
            2,
            &validator_manager,
        )
        .expect("round two vote should be created");
        assert!(DualQuorumConsensus::register_vote_observation(&next_round_vote).is_none());

        let validator = validator_manager
            .get_validator("validator2")
            .expect("validator should still exist");
        assert_eq!(validator.status, ValidatorStatus::Active);
        assert_eq!(validator.double_signs, 0);
    }

    #[test]
    fn vote_observation_for_conflicting_higher_round_is_round_scoped() {
        let _vote_tracking_guard = DualQuorumConsensus::test_vote_tracking_guard();
        DualQuorumConsensus::reset_test_vote_tracking();

        let validator_manager = approved_validator_manager(&["validator1", "validator2"]);
        let pqc_manager = Arc::new(Mutex::new(PQCManager::new()));
        let consensus = DualQuorumConsensus::new(
            Arc::clone(&validator_manager),
            Arc::clone(&pqc_manager),
            true,
            1,
            1,
            8,
            5,
        );
        let first_block = signed_block(10, 1, "validator1");
        let conflicting_block = signed_block(10, 2, "validator1");

        let first_vote = DualQuorumConsensus::create_vote_for_validator_with_manager(
            "validator2",
            &first_block,
            22,
            1,
            &validator_manager,
        )
        .expect("round one vote should be created");
        assert!(DualQuorumConsensus::register_vote_observation(&first_vote).is_none());

        let conflicting_vote = DualQuorumConsensus::create_vote_for_validator_with_manager(
            "validator2",
            &conflicting_block,
            22,
            2,
            &validator_manager,
        )
        .expect("round two vote should be created");
        assert!(
            DualQuorumConsensus::register_vote_observation(&conflicting_vote).is_none(),
            "vote observation is round-scoped; local vote intent enforces supersede safety before signing"
        );

        consensus.apply_recorded_equivocations();

        let validator = validator_manager
            .get_validator("validator2")
            .expect("validator should still exist");
        assert_eq!(validator.status, ValidatorStatus::Active);
        assert_eq!(validator.double_signs, 0);
        assert_eq!(validator.equivocation_evidence_count, 0);
    }

    #[test]
    fn local_vote_intent_rejects_same_height_conflict_without_canonical_parent() {
        let _vote_tracking_guard = DualQuorumConsensus::test_vote_tracking_guard();
        DualQuorumConsensus::reset_test_vote_tracking();
        crate::consensus::legacy_canonical_lock::clear_legacy_canonical_locks_for_tests();

        let path = temp_vote_lock_path("local-vote-intent");
        DualQuorumConsensus::set_test_local_vote_lock_path(Some(path.clone()));

        let block = signed_block(13, 1, "validator1");
        let conflicting_block = signed_block(13, 2, "validator1");

        DualQuorumConsensus::register_local_vote_intent("validator2", &block, 40, 1)
            .expect("first local vote intent should persist");
        DualQuorumConsensus::register_local_vote_intent("validator2", &block, 40, 2)
            .expect("same block hash may be repeated in a later round");

        let locked = DualQuorumConsensus::local_locked_vote_for_height("validator2", 40, 13)
            .expect("local vote lock lookup should succeed")
            .expect("local vote lock should exist");
        assert_eq!(locked.block_hash, block.hash);
        assert_eq!(locked.first_round_number, 1);
        assert_eq!(locked.latest_round_number, 2);

        let same_round_error = DualQuorumConsensus::register_local_vote_intent(
            "validator2",
            &conflicting_block,
            40,
            2,
        )
        .expect_err("conflicting local vote intent in the same round should be rejected");
        assert!(
            same_round_error.contains("already locally voted for different block"),
            "unexpected local vote lock error: {same_round_error}"
        );

        let higher_round_error = DualQuorumConsensus::register_local_vote_intent(
            "validator2",
            &conflicting_block,
            40,
            3,
        )
        .expect_err("higher-round conflicting local vote intent needs durable view-change proof");
        assert!(
            higher_round_error.contains("durable finalized canonical parent lock"),
            "unexpected higher-round local vote lock error: {higher_round_error}"
        );

        let locked = DualQuorumConsensus::local_locked_vote_for_height("validator2", 40, 13)
            .expect("local vote lock lookup should succeed")
            .expect("vote lock should remain on the original same-height block");
        assert_eq!(locked.block_hash, block.hash);
        assert_eq!(locked.first_round_number, 1);
        assert_eq!(locked.latest_round_number, 2);
        assert_eq!(locked.proposer, "validator1");

        DualQuorumConsensus::set_test_local_vote_lock_path(None);
        crate::consensus::legacy_canonical_lock::clear_legacy_canonical_locks_for_tests();
        if let Some(root) = path.parent().and_then(|data| data.parent()) {
            let _ = fs::remove_dir_all(root);
        }
    }

    #[test]
    fn ordinary_same_height_higher_round_extending_canonical_parent_is_rejected() {
        let _vote_tracking_guard = DualQuorumConsensus::test_vote_tracking_guard();
        DualQuorumConsensus::reset_test_vote_tracking();
        crate::consensus::legacy_canonical_lock::clear_legacy_canonical_locks_for_tests();

        let path = temp_vote_lock_path("local-vote-intent-view-change");
        DualQuorumConsensus::set_test_local_vote_lock_path(Some(path.clone()));

        let parent = signed_block(12, 1, "validator0");
        crate::consensus::legacy_canonical_lock::write_legacy_canonical_lock(
            &parent,
            &test_qc(&parent.hash),
        )
        .expect("canonical parent lock should be written");

        let mut block = signed_block(13, 1, "validator1");
        block.previous_hash = parent.hash.clone();
        let mut conflicting_block = signed_block(13, 2, "validator3");
        conflicting_block.previous_hash = parent.hash.clone();

        DualQuorumConsensus::register_local_vote_intent("validator2", &block, 40, 1)
            .expect("first local vote intent should persist");
        let same_round_error = DualQuorumConsensus::register_local_vote_intent(
            "validator2",
            &conflicting_block,
            40,
            1,
        )
        .expect_err("same-round conflicting vote remains unsafe");
        assert!(
            same_round_error.contains("already locally voted for different block"),
            "unexpected same-round error: {same_round_error}"
        );

        let higher_round_error = DualQuorumConsensus::register_local_vote_intent(
            "validator2",
            &conflicting_block,
            40,
            2,
        )
        .expect_err("ordinary higher-round same-height conflict must stay fail-closed");
        assert!(
            higher_round_error.contains("PoSy v2.1 fail-closed signer journal forbids"),
            "unexpected higher-round error: {higher_round_error}"
        );

        let locked = DualQuorumConsensus::local_locked_vote_for_height("validator2", 40, 13)
            .expect("local vote lock lookup should succeed")
            .expect("latest local vote lock should remain on the first block");
        assert_eq!(locked.block_hash, block.hash);
        assert_eq!(locked.first_round_number, 1);
        assert_eq!(locked.latest_round_number, 1);
        assert_eq!(locked.proposer, "validator1");

        let locks = DualQuorumConsensus::load_local_vote_locks_unlocked()
            .expect("persisted vote locks should load");
        assert!(
            locks.values().any(|lock| lock.block_hash == block.hash),
            "original unfinalized vote lock should remain as evidence"
        );
        assert!(
            locks
                .values()
                .all(|lock| lock.block_hash != conflicting_block.hash),
            "conflicting higher-round vote lock must not be persisted"
        );

        DualQuorumConsensus::set_test_local_vote_lock_path(None);
        crate::consensus::legacy_canonical_lock::clear_legacy_canonical_locks_for_tests();
        if let Some(root) = path.parent().and_then(|data| data.parent()) {
            let _ = fs::remove_dir_all(root);
        }
    }

    #[test]
    fn stale_higher_round_vote_lock_cannot_be_erased_for_lower_round_retry() {
        let _vote_tracking_guard = DualQuorumConsensus::test_vote_tracking_guard();
        DualQuorumConsensus::reset_test_vote_tracking();
        crate::consensus::legacy_canonical_lock::clear_legacy_canonical_locks_for_tests();

        let path = temp_vote_lock_path("local-vote-intent-lower-round-recovery");
        DualQuorumConsensus::set_test_local_vote_lock_path(Some(path.clone()));

        let parent = signed_block(12, 1, "validator0");
        crate::consensus::legacy_canonical_lock::write_legacy_canonical_lock(
            &parent,
            &test_qc(&parent.hash),
        )
        .expect("canonical parent lock should be written");

        let mut stale_block = signed_block(13, 1, "validator1");
        stale_block.previous_hash = parent.hash.clone();
        let mut recovery_block = signed_block(13, 2, "validator3");
        recovery_block.previous_hash = parent.hash.clone();

        DualQuorumConsensus::register_local_vote_intent("validator2", &stale_block, 40, 172)
            .expect("stale high-round vote intent should persist");

        DualQuorumConsensus::recover_stale_conflicting_vote_lock_before_vote(
            "validator2",
            &recovery_block,
            40,
            84,
            0,
            "lower-round clean retry after stale transient lock",
        )
        .expect("stale lock inspection should remain read-only");

        let error =
            DualQuorumConsensus::register_local_vote_intent("validator2", &recovery_block, 40, 84)
                .expect_err("lower-round retry must not erase a prior same-height signing slot");
        assert!(error.contains("already locally voted for different block"));

        let locks = DualQuorumConsensus::load_local_vote_locks_unlocked()
            .expect("persisted vote locks should load");
        assert!(locks
            .values()
            .any(|lock| lock.block_hash == stale_block.hash
                && lock.block_index == stale_block.block_index
                && lock.latest_round_number == 172));
        assert!(locks
            .values()
            .all(|lock| lock.block_hash != recovery_block.hash));

        DualQuorumConsensus::set_test_local_vote_lock_path(None);
        crate::consensus::legacy_canonical_lock::clear_legacy_canonical_locks_for_tests();
        if let Some(root) = path.parent().and_then(|data| data.parent()) {
            let _ = fs::remove_dir_all(root);
        }
    }

    #[test]
    fn stale_unfinalized_vote_locks_are_preserved_fail_closed() {
        let _vote_tracking_guard = DualQuorumConsensus::test_vote_tracking_guard();
        DualQuorumConsensus::reset_test_vote_tracking();

        let path = temp_vote_lock_path("transient-recovery");
        DualQuorumConsensus::set_test_local_vote_lock_path(Some(path.clone()));

        let finalized = signed_block(12, 1, "validator1");
        let transient = signed_block(13, 1, "validator1");
        DualQuorumConsensus::register_local_vote_intent("validator2", &finalized, 40, 1)
            .expect("finalized-height vote lock should persist");
        DualQuorumConsensus::register_local_vote_intent("validator2", &transient, 40, 1)
            .expect("transient vote lock should persist");

        let report = DualQuorumConsensus::recover_transient_vote_locks_above_finalized_height(
            12,
            0,
            "test stale transient recovery",
        )
        .expect("vote lock inspection should succeed");

        assert!(!report.mutated);
        assert_eq!(report.removed_count, 0);
        assert!(report.removed.is_empty());
        assert!(report.evidence_path.is_empty());
        assert_eq!(
            report.action,
            "inspect_preserved_vote_locks_above_finalized_height"
        );

        let locks = DualQuorumConsensus::load_local_vote_locks_unlocked()
            .expect("remaining vote locks should load");
        assert!(locks
            .values()
            .any(|lock| lock.block_hash == finalized.hash && lock.block_index == 12));
        assert!(locks
            .values()
            .any(|lock| lock.block_hash == transient.hash && lock.block_index == 13));

        DualQuorumConsensus::set_test_local_vote_lock_path(None);
        if let Some(root) = path.parent().and_then(|data| data.parent()) {
            let _ = fs::remove_dir_all(root);
        }
    }

    #[test]
    fn finalized_vote_lock_compaction_preserves_evidence_and_keeps_recent_locks() {
        let _vote_tracking_guard = DualQuorumConsensus::test_vote_tracking_guard();
        DualQuorumConsensus::reset_test_vote_tracking();

        let path = temp_vote_lock_path("finalized-lock-compaction");
        let root = path
            .parent()
            .and_then(|data| data.parent())
            .expect("vote lock path has test root")
            .to_path_buf();
        let previous_root = std::env::var("SYNERGY_PROJECT_ROOT").ok();
        std::env::set_var("SYNERGY_PROJECT_ROOT", &root);
        crate::consensus::legacy_canonical_lock::clear_legacy_canonical_locks_for_tests();
        fs::create_dir_all(path.parent().expect("vote lock path has parent"))
            .expect("vote lock parent should be created");
        DualQuorumConsensus::set_test_local_vote_lock_path(Some(path.clone()));

        let finalized = signed_block(2_000, 1, "validator1");
        crate::consensus::legacy_canonical_lock::write_legacy_canonical_lock(
            &finalized,
            &test_qc(&finalized.hash),
        )
        .expect("canonical finalized lock should be written");

        let now = DualQuorumConsensus::current_timestamp();
        let mut locks = HashMap::new();
        for height in 1..=LOCAL_VOTE_LOCK_COMPACTION_MIN_LOCKS as u64 {
            let hash = format!("old-hash-{height}");
            let key =
                DualQuorumConsensus::scoped_local_vote_lock_key("validator2", 40, height, 1, &hash);
            locks.insert(
                key,
                LocalVoteLock {
                    validator_address: "validator2".to_string(),
                    block_hash: hash,
                    block_index: height,
                    epoch_number: 40,
                    first_round_number: 1,
                    latest_round_number: 1,
                    proposer: "validator1".to_string(),
                    created_at: now.saturating_sub(60),
                    updated_at: now.saturating_sub(60),
                    superseded: Vec::new(),
                },
            );
        }
        let recent_hash = "recent-finalized-lock".to_string();
        let recent_key = DualQuorumConsensus::scoped_local_vote_lock_key(
            "validator2",
            40,
            1_990,
            1,
            &recent_hash,
        );
        locks.insert(
            recent_key,
            LocalVoteLock {
                validator_address: "validator2".to_string(),
                block_hash: recent_hash.clone(),
                block_index: 1_990,
                epoch_number: 40,
                first_round_number: 1,
                latest_round_number: 1,
                proposer: "validator1".to_string(),
                created_at: now.saturating_sub(60),
                updated_at: now.saturating_sub(60),
                superseded: Vec::new(),
            },
        );
        fs::write(&path, serde_json::to_vec(&locks).unwrap())
            .expect("large vote lock file should be seeded");

        let mut next = signed_block(2_001, 2, "validator1");
        next.previous_hash = finalized.hash.clone();
        DualQuorumConsensus::register_local_vote_intent("validator2", &next, 40, 1)
            .expect("vote intent should compact finalized locks and persist new lock");

        let compacted = DualQuorumConsensus::load_local_vote_locks_unlocked()
            .expect("compacted vote locks should load");
        assert!(
            compacted.values().all(|lock| lock.block_index > 1_984),
            "locks at or below finalized retention cutoff should be pruned"
        );
        assert!(compacted
            .values()
            .any(|lock| lock.block_hash == recent_hash && lock.block_index == 1_990));
        assert!(compacted
            .values()
            .any(|lock| lock.block_hash == next.hash && lock.block_index == 2_001));

        let evidence_root = DualQuorumConsensus::vote_lock_evidence_root_for_path(&path);
        let evidence_found = fs::read_dir(&evidence_root)
            .ok()
            .into_iter()
            .flat_map(|entries| entries.flatten())
            .any(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .contains("finalized-vote-lock-compaction-through-1984")
            });
        assert!(
            evidence_found,
            "compaction must preserve removed lock evidence"
        );

        DualQuorumConsensus::set_test_local_vote_lock_path(None);
        crate::consensus::legacy_canonical_lock::clear_legacy_canonical_locks_for_tests();
        match previous_root {
            Some(value) => std::env::set_var("SYNERGY_PROJECT_ROOT", value),
            None => std::env::remove_var("SYNERGY_PROJECT_ROOT"),
        }
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn stale_ordinary_conflicting_vote_lock_is_preserved_across_higher_round_view_change() {
        let _vote_tracking_guard = DualQuorumConsensus::test_vote_tracking_guard();
        DualQuorumConsensus::reset_test_vote_tracking();
        crate::consensus::legacy_canonical_lock::clear_legacy_canonical_locks_for_tests();

        let path = temp_vote_lock_path("pre-vote-transient-recovery");
        DualQuorumConsensus::set_test_local_vote_lock_path(Some(path.clone()));

        let parent = signed_block(12, 1, "validator0");
        crate::consensus::legacy_canonical_lock::write_legacy_canonical_lock(
            &parent,
            &test_qc(&parent.hash),
        )
        .expect("canonical parent lock should be written");

        let mut first_block = signed_block(13, 1, "validator1");
        first_block.previous_hash = parent.hash.clone();
        let mut recovery_block = signed_block(13, 2, "validator3");
        recovery_block.previous_hash = parent.hash.clone();

        DualQuorumConsensus::register_local_vote_intent("validator2", &first_block, 40, 1)
            .expect("first local vote intent should persist");

        DualQuorumConsensus::recover_stale_conflicting_vote_lock_before_vote(
            "validator2",
            &recovery_block,
            40,
            2,
            0,
            "test higher-round transient recovery",
        )
        .expect("ordinary stale conflicting lock inspection should remain read-only");

        let error =
            DualQuorumConsensus::register_local_vote_intent("validator2", &recovery_block, 40, 2)
                .expect_err("higher-round proposal must not replace a signed candidate");
        assert!(error.contains("PoSy v2.1 fail-closed signer journal forbids"));

        let locks = DualQuorumConsensus::load_local_vote_locks_unlocked()
            .expect("persisted vote locks should load");
        assert!(locks
            .values()
            .any(|lock| lock.block_hash == first_block.hash
                && lock.block_index == 13
                && lock.latest_round_number == 1));
        assert!(
            locks
                .values()
                .all(|lock| lock.block_hash != recovery_block.hash),
            "conflicting higher-round candidate must not be persisted"
        );

        DualQuorumConsensus::set_test_local_vote_lock_path(None);
        crate::consensus::legacy_canonical_lock::clear_legacy_canonical_locks_for_tests();
        if let Some(root) = path.parent().and_then(|data| data.parent()) {
            let _ = fs::remove_dir_all(root);
        }
    }

    #[test]
    fn checkpoint_fork_parent_cannot_erase_same_height_vote_lock() {
        let _vote_tracking_guard = DualQuorumConsensus::test_vote_tracking_guard();
        DualQuorumConsensus::reset_test_vote_tracking();

        let path = temp_vote_lock_path("checkpoint-fork-transient-recovery");
        let root = path
            .parent()
            .and_then(|data| data.parent())
            .expect("vote lock path has test root")
            .to_path_buf();
        fs::create_dir_all(path.parent().expect("vote lock path has parent"))
            .expect("vote lock parent should be created");
        crate::consensus::legacy_canonical_lock::clear_legacy_canonical_locks_for_tests();
        DualQuorumConsensus::set_test_local_vote_lock_path(Some(path.clone()));

        let parent = signed_block(204_215, 1, "validator0");
        let mut pqc_manager = PQCManager::new();
        let (public_key, _) = pqc_manager
            .generate_keypair(PQCAlgorithm::MLDSA65)
            .expect("FN-DSA key generation should succeed");
        let fork = serde_json::json!({
            "fork_height": 204_216,
            "parent_height": 204_215,
            "parent_hash": parent.hash,
            "state_root": "checkpoint-v1:test",
            "old_consensus_algorithm": "FN-DSA",
            "new_consensus_algorithm": "FN-DSA",
            "new_validator_registry": [{
                "validator_address": "validator2",
                "consensus_key_type": "FN-DSA",
                "consensus_public_key": general_purpose::STANDARD.encode(&public_key.key_data),
            }],
            "migration_reason": "test checkpointed FN-DSA fork",
            "parser_mode": "fail_closed"
        });
        let migration: crate::consensus::consensus_fork::ConsensusForkMigration =
            serde_json::from_value(fork.clone()).expect("test fork config should decode");
        let _fork_guard =
            crate::consensus::consensus_fork::set_test_active_consensus_fork_migration(migration);

        let mut first_block = signed_block(204_216, 1, "validator1");
        first_block.previous_hash = fork["parent_hash"]
            .as_str()
            .expect("fork parent hash should be a string")
            .to_string();
        let mut recovery_block = signed_block(204_216, 2, "validator3");
        recovery_block.previous_hash = first_block.previous_hash.clone();

        DualQuorumConsensus::register_local_vote_intent("validator2", &first_block, 204, 1)
            .expect("pre-fork transient vote intent should persist");

        DualQuorumConsensus::recover_stale_conflicting_vote_lock_before_vote(
            "validator2",
            &recovery_block,
            204,
            2,
            u64::MAX - 1,
            "checkpoint fork transient lock recovery",
        )
        .expect("checkpoint fork lock inspection should remain read-only");

        let error =
            DualQuorumConsensus::register_local_vote_intent("validator2", &recovery_block, 204, 2)
                .expect_err("checkpoint fork must not bypass the durable signing slot");
        assert!(error.contains("PoSy v2.1 fail-closed signer journal forbids"));

        let locks = DualQuorumConsensus::load_local_vote_locks_unlocked()
            .expect("persisted vote locks should load");
        assert!(locks
            .values()
            .any(|lock| lock.block_hash == first_block.hash
                && lock.block_index == 204_216
                && lock.latest_round_number == 1));
        assert!(locks
            .values()
            .all(|lock| lock.block_hash != recovery_block.hash));

        DualQuorumConsensus::set_test_local_vote_lock_path(None);
        crate::consensus::legacy_canonical_lock::clear_legacy_canonical_locks_for_tests();
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn fresh_conflicting_vote_lock_rejects_higher_round_without_checkpoint_fork() {
        let _vote_tracking_guard = DualQuorumConsensus::test_vote_tracking_guard();
        DualQuorumConsensus::reset_test_vote_tracking();
        crate::consensus::legacy_canonical_lock::clear_legacy_canonical_locks_for_tests();

        let path = temp_vote_lock_path("fresh-pre-vote-transient-recovery");
        DualQuorumConsensus::set_test_local_vote_lock_path(Some(path.clone()));

        let parent = signed_block(12, 1, "validator0");
        crate::consensus::legacy_canonical_lock::write_legacy_canonical_lock(
            &parent,
            &test_qc(&parent.hash),
        )
        .expect("canonical parent lock should be written");

        let mut first_block = signed_block(13, 1, "validator1");
        first_block.previous_hash = parent.hash.clone();
        let mut recovery_block = signed_block(13, 2, "validator3");
        recovery_block.previous_hash = parent.hash.clone();

        DualQuorumConsensus::register_local_vote_intent("validator2", &first_block, 40, 1)
            .expect("first local vote intent should persist");

        DualQuorumConsensus::recover_stale_conflicting_vote_lock_before_vote(
            "validator2",
            &recovery_block,
            40,
            2,
            u64::MAX - 1,
            "test fresh transient lock remains locked",
        )
        .expect("fresh lock check should fail closed without mutation");

        let err =
            DualQuorumConsensus::register_local_vote_intent("validator2", &recovery_block, 40, 2)
                .expect_err("ordinary higher-round same-height conflict must stay locked");
        assert!(
            err.contains("PoSy v2.1 fail-closed signer journal forbids"),
            "unexpected higher-round conflict error: {err}"
        );

        let locked = DualQuorumConsensus::local_locked_vote_for_height("validator2", 40, 13)
            .expect("local vote lock lookup should succeed")
            .expect("original lock should remain latest");
        assert_eq!(locked.block_hash, first_block.hash);
        assert_eq!(locked.latest_round_number, 1);
        let locks = DualQuorumConsensus::load_local_vote_locks_unlocked()
            .expect("persisted vote locks should load");
        assert!(locks
            .values()
            .all(|lock| lock.block_hash != recovery_block.hash));

        DualQuorumConsensus::set_test_local_vote_lock_path(None);
        crate::consensus::legacy_canonical_lock::clear_legacy_canonical_locks_for_tests();
        if let Some(root) = path.parent().and_then(|data| data.parent()) {
            let _ = fs::remove_dir_all(root);
        }
    }

    #[test]
    fn finalized_canonical_lock_same_height_conflict_rejected_for_vote_supersede() {
        let _vote_tracking_guard = DualQuorumConsensus::test_vote_tracking_guard();
        DualQuorumConsensus::reset_test_vote_tracking();
        crate::consensus::legacy_canonical_lock::clear_legacy_canonical_locks_for_tests();

        let path = temp_vote_lock_path("local-vote-intent-finalized-conflict");
        DualQuorumConsensus::set_test_local_vote_lock_path(Some(path.clone()));

        let finalized = signed_block(13, 1, "validator1");
        let conflicting_block = signed_block(13, 2, "validator3");
        crate::consensus::legacy_canonical_lock::write_legacy_canonical_lock(
            &finalized,
            &test_qc(&finalized.hash),
        )
        .expect("finalized canonical lock should be written");

        DualQuorumConsensus::register_local_vote_intent("validator2", &finalized, 40, 1)
            .expect("first local vote intent should persist");
        let err = DualQuorumConsensus::register_local_vote_intent(
            "validator2",
            &conflicting_block,
            40,
            2,
        )
        .expect_err("finalized same-height canonical conflict must be rejected");
        assert!(
            err.contains("already finalized by canonical lock"),
            "unexpected finalized conflict error: {err}"
        );

        DualQuorumConsensus::set_test_local_vote_lock_path(None);
        crate::consensus::legacy_canonical_lock::clear_legacy_canonical_locks_for_tests();
        if let Some(root) = path.parent().and_then(|data| data.parent()) {
            let _ = fs::remove_dir_all(root);
        }
    }

    #[test]
    fn local_locked_vote_for_height_returns_persisted_same_height_lock() {
        let _vote_tracking_guard = DualQuorumConsensus::test_vote_tracking_guard();
        DualQuorumConsensus::reset_test_vote_tracking();

        let path = temp_vote_lock_path("local-locked-vote-read");
        DualQuorumConsensus::set_test_local_vote_lock_path(Some(path.clone()));

        let block = signed_block(14, 1, "validator1");
        DualQuorumConsensus::register_local_vote_intent("validator2", &block, 41, 3)
            .expect("local vote intent should persist");

        let locked_vote = DualQuorumConsensus::local_locked_vote_for_height("validator2", 41, 14)
            .expect("local vote lock lookup should succeed")
            .expect("local vote lock should exist");

        assert_eq!(locked_vote.validator_address, "validator2");
        assert_eq!(locked_vote.block_hash, block.hash);
        assert_eq!(locked_vote.block_index, 14);
        assert_eq!(locked_vote.epoch_number, 41);
        assert_eq!(locked_vote.first_round_number, 3);
        assert_eq!(locked_vote.latest_round_number, 3);
        assert_eq!(locked_vote.proposer, "validator1");

        let missing = DualQuorumConsensus::local_locked_vote_for_height("validator2", 41, 15)
            .expect("missing local vote lock lookup should succeed");
        assert!(missing.is_none());

        DualQuorumConsensus::set_test_local_vote_lock_path(None);
        if let Some(root) = path.parent().and_then(|data| data.parent()) {
            let _ = fs::remove_dir_all(root);
        }
    }

    #[test]
    fn verified_vote_signature_cache_key_binds_signature_material() {
        let _vote_tracking_guard = DualQuorumConsensus::test_vote_tracking_guard();
        DualQuorumConsensus::reset_test_vote_tracking();

        let validator_manager = approved_validator_manager(&["validator1", "validator2"]);
        let pqc_manager = Arc::new(Mutex::new(PQCManager::new()));
        let consensus = DualQuorumConsensus::new(
            Arc::clone(&validator_manager),
            Arc::clone(&pqc_manager),
            true,
            1,
            1,
            8,
            5,
        );

        let block = signed_block(8, 1, "validator1");
        let vote = DualQuorumConsensus::create_vote_for_validator_with_manager(
            "validator2",
            &block,
            12,
            1,
            &validator_manager,
        )
        .expect("vote should be created");

        consensus
            .verify_vote_signature(&vote)
            .expect("first verification should succeed");
        let cache_key = DualQuorumConsensus::vote_signature_cache_key(&vote);
        assert!(consensus
            .verified_vote_signatures
            .lock()
            .expect("cache lock")
            .contains(&cache_key));

        let mut tampered_vote = vote.clone();
        tampered_vote.signature.signature_data.push(0);
        assert_ne!(
            cache_key,
            DualQuorumConsensus::vote_signature_cache_key(&tampered_vote)
        );
    }

    #[test]
    fn merge_remote_votes_accepts_verified_votes_and_caches_signatures() {
        let _vote_tracking_guard = DualQuorumConsensus::test_vote_tracking_guard();
        DualQuorumConsensus::reset_test_vote_tracking();

        let validator_manager =
            approved_validator_manager(&["validator1", "validator2", "validator3", "validator4"]);
        let pqc_manager = Arc::new(Mutex::new(PQCManager::new()));
        let consensus = DualQuorumConsensus::new(
            Arc::clone(&validator_manager),
            Arc::clone(&pqc_manager),
            true,
            1,
            1,
            8,
            5,
        );

        let block = signed_block(9, 1, "validator1");
        let local_vote = DualQuorumConsensus::create_vote_for_validator_with_manager(
            "validator1",
            &block,
            12,
            1,
            &validator_manager,
        )
        .expect("local vote should be created");
        let remote_vote_a = DualQuorumConsensus::create_vote_for_validator_with_manager(
            "validator2",
            &block,
            12,
            1,
            &validator_manager,
        )
        .expect("remote vote should be created");
        let remote_vote_b = DualQuorumConsensus::create_vote_for_validator_with_manager(
            "validator3",
            &block,
            12,
            1,
            &validator_manager,
        )
        .expect("remote vote should be created");

        let expected_validators = ["validator1", "validator2", "validator3", "validator4"]
            .into_iter()
            .map(String::from)
            .collect::<BTreeSet<_>>();
        let remote_cache_key = DualQuorumConsensus::vote_signature_cache_key(&remote_vote_a);
        let mut votes = vec![local_vote];

        consensus.merge_remote_votes(
            &mut votes,
            &expected_validators,
            &block.hash,
            12,
            1,
            vec![remote_vote_a, remote_vote_b],
        );

        assert_eq!(votes.len(), 3);
        assert!(consensus.vote_signature_cache_contains(&remote_cache_key));
    }

    #[test]
    fn merge_remote_votes_accepts_prior_round_same_block_recovery_votes() {
        let _vote_tracking_guard = DualQuorumConsensus::test_vote_tracking_guard();
        DualQuorumConsensus::reset_test_vote_tracking();

        let validator_manager =
            approved_validator_manager(&["validator1", "validator2", "validator3"]);
        let pqc_manager = Arc::new(Mutex::new(PQCManager::new()));
        let consensus = DualQuorumConsensus::new(
            Arc::clone(&validator_manager),
            Arc::clone(&pqc_manager),
            true,
            1,
            1,
            8,
            5,
        );

        let block = signed_block(10, 1, "validator1");
        let local_vote = DualQuorumConsensus::create_vote_for_validator_with_manager(
            "validator1",
            &block,
            12,
            4,
            &validator_manager,
        )
        .expect("local vote should be created");
        let prior_round_vote = DualQuorumConsensus::create_vote_for_validator_with_manager(
            "validator2",
            &block,
            12,
            2,
            &validator_manager,
        )
        .expect("prior round vote should be created");
        let conflicting_block = signed_block(10, 1, "validator3");
        let conflicting_prior_round_vote =
            DualQuorumConsensus::create_vote_for_validator_with_manager(
                "validator2",
                &conflicting_block,
                12,
                2,
                &validator_manager,
            )
            .expect("conflicting prior round vote should be created");
        assert!(
            DualQuorumConsensus::register_vote_observation(&conflicting_prior_round_vote).is_none()
        );
        assert!(DualQuorumConsensus::register_vote_observation(&prior_round_vote).is_some());

        let expected_validators = ["validator1", "validator2", "validator3"]
            .into_iter()
            .map(String::from)
            .collect::<BTreeSet<_>>();
        let mut votes = vec![local_vote];

        consensus.merge_remote_votes(
            &mut votes,
            &expected_validators,
            &block.hash,
            12,
            4,
            vec![prior_round_vote],
        );

        assert_eq!(votes.len(), 2);
        votes.retain(|vote| consensus.vote_is_eligible_for_collection(&vote, &block.hash, 12, 4));
        assert_eq!(votes.len(), 2);
        assert!(votes
            .iter()
            .any(|vote| { vote.validator_address == "validator2" && vote.round_number == 2 }));
    }

    #[test]
    fn merge_remote_votes_does_not_let_invalid_duplicate_block_valid_vote() {
        let _vote_tracking_guard = DualQuorumConsensus::test_vote_tracking_guard();
        DualQuorumConsensus::reset_test_vote_tracking();

        let validator_manager =
            approved_validator_manager(&["validator1", "validator2", "validator3"]);
        let pqc_manager = Arc::new(Mutex::new(PQCManager::new()));
        let consensus = DualQuorumConsensus::new(
            Arc::clone(&validator_manager),
            Arc::clone(&pqc_manager),
            true,
            1,
            1,
            8,
            5,
        );

        let block = signed_block(10, 1, "validator1");
        let local_vote = DualQuorumConsensus::create_vote_for_validator_with_manager(
            "validator1",
            &block,
            12,
            4,
            &validator_manager,
        )
        .expect("local vote should be created");
        let mut invalid_vote = DualQuorumConsensus::create_vote_for_validator_with_manager(
            "validator2",
            &block,
            12,
            2,
            &validator_manager,
        )
        .expect("invalid candidate vote should be created");
        invalid_vote.signature.signature_data = b"invalid".to_vec();
        let valid_vote = DualQuorumConsensus::create_vote_for_validator_with_manager(
            "validator2",
            &block,
            12,
            3,
            &validator_manager,
        )
        .expect("valid duplicate candidate vote should be created");

        let expected_validators = ["validator1", "validator2", "validator3"]
            .into_iter()
            .map(String::from)
            .collect::<BTreeSet<_>>();
        let mut votes = vec![local_vote];

        consensus.merge_remote_votes(
            &mut votes,
            &expected_validators,
            &block.hash,
            12,
            4,
            vec![invalid_vote, valid_vote],
        );

        assert_eq!(votes.len(), 2);
        assert!(votes
            .iter()
            .any(|vote| { vote.validator_address == "validator2" && vote.round_number == 3 }));
    }

    #[test]
    fn round_allocation_respects_view_floor() {
        let _vote_tracking_guard = DualQuorumConsensus::test_vote_tracking_guard();
        DualQuorumConsensus::reset_test_vote_tracking();

        let validator_manager = approved_validator_manager(&["validator1"]);
        let pqc_manager = Arc::new(Mutex::new(PQCManager::new()));
        let mut consensus = DualQuorumConsensus::new(
            Arc::clone(&validator_manager),
            Arc::clone(&pqc_manager),
            true,
            1,
            1,
            8,
            5,
        );

        assert_eq!(consensus.allocate_round_number(4, 1, "validator1", 3), 3);
        assert_eq!(consensus.allocate_round_number(4, 1, "validator1", 3), 3);
        assert_eq!(consensus.allocate_round_number(4, 1, "validator1", 1), 1);
        assert_eq!(consensus.allocate_round_number(5, 1, "validator1", 1), 1);
    }

    #[test]
    fn round_allocation_resumes_above_persisted_lock_after_restart() {
        let _vote_tracking_guard = DualQuorumConsensus::test_vote_tracking_guard();
        DualQuorumConsensus::reset_test_vote_tracking();

        let validator_manager = approved_validator_manager(&["validator1", "validator2"]);
        let pqc_manager = Arc::new(Mutex::new(PQCManager::new()));
        let mut consensus = DualQuorumConsensus::new(
            Arc::clone(&validator_manager),
            Arc::clone(&pqc_manager),
            true,
            1,
            1,
            8,
            5,
        );

        let path = temp_vote_lock_path("round-allocation-resume");
        DualQuorumConsensus::set_test_local_vote_lock_path(Some(path.clone()));

        let remote_leader_block = signed_block(14, 1, "validator1");
        DualQuorumConsensus::register_local_vote_intent("validator2", &remote_leader_block, 41, 41)
            .expect("prior local vote intent should be persisted");

        assert_eq!(
            consensus.allocate_round_number(14, 41, "validator2", 2),
            42,
            "round allocation must resume above a persisted same-height vote lock after restart"
        );

        DualQuorumConsensus::set_test_local_vote_lock_path(None);
        if let Some(root) = path.parent().and_then(|data| data.parent()) {
            let _ = fs::remove_dir_all(root);
        }
    }

    #[test]
    fn missed_vote_timeouts_are_ignored_when_penalization_is_disabled() {
        let _vote_tracking_guard = DualQuorumConsensus::test_vote_tracking_guard();
        DualQuorumConsensus::reset_test_vote_tracking();

        let validator_manager = approved_validator_manager(&["validator1", "validator2"]);
        let pqc_manager = Arc::new(Mutex::new(PQCManager::new()));
        let consensus = DualQuorumConsensus::new(
            Arc::clone(&validator_manager),
            Arc::clone(&pqc_manager),
            false,
            1,
            1,
            8,
            5,
        );

        let before = validator_manager
            .get_validator("validator2")
            .expect("validator should exist")
            .clone();

        consensus.record_missed_vote_timeouts(std::slice::from_ref(&before), &[]);

        let after = validator_manager
            .get_validator("validator2")
            .expect("validator should exist");
        assert_eq!(after.uptime_percentage, before.uptime_percentage);
        assert_eq!(after.task_accuracy, before.task_accuracy);
        assert_eq!(after.reputation_score, before.reputation_score);
        assert_eq!(after.missed_vote_window, before.missed_vote_window);
        assert_eq!(
            after.consecutive_missed_votes,
            before.consecutive_missed_votes
        );
        assert_eq!(after.status, ValidatorStatus::Active);
    }

    #[test]
    fn below_dynamic_two_thirds_equal_weight_votes_do_not_commit() {
        let validator_manager = approved_validator_manager(&[
            "validator1",
            "validator2",
            "validator3",
            "validator4",
            "validator5",
            "validator6",
        ]);
        let pqc_manager = Arc::new(Mutex::new(PQCManager::new()));
        let consensus = DualQuorumConsensus::new(
            Arc::clone(&validator_manager),
            Arc::clone(&pqc_manager),
            false,
            3,
            4,
            2,
            6,
        );
        let active_validators =
            consensus_membership_validators(validator_manager.get_active_validators());
        let votes = ["validator1", "validator2", "validator3"]
            .into_iter()
            .map(|validator_address| Vote {
                validator_address: validator_address.to_string(),
                block_hash: "block-hash".to_string(),
                block_index: 42,
                epoch_number: 1,
                round_number: 1,
                signature: PQCSignature {
                    algorithm: PQCAlgorithm::FNDSA,
                    signature_data: Vec::new(),
                    message_hash: Vec::new(),
                    public_key_id: String::new(),
                    created_at: 0,
                },
                signer_public_key: Vec::new(),
                timestamp: 0,
            })
            .collect::<Vec<_>>();

        assert_eq!(
            consensus.required_validator_votes(active_validators.len()),
            5
        );
        assert!(
            !consensus.has_commit_quorum(&active_validators, &votes),
            "3 collected votes across six active validators must not satisfy two-thirds quorum"
        );

        let four_votes = ["validator1", "validator2", "validator3", "validator4"]
            .into_iter()
            .map(|validator_address| Vote {
                validator_address: validator_address.to_string(),
                block_hash: "block-hash".to_string(),
                block_index: 42,
                epoch_number: 1,
                round_number: 1,
                signature: PQCSignature {
                    algorithm: PQCAlgorithm::FNDSA,
                    signature_data: Vec::new(),
                    message_hash: Vec::new(),
                    public_key_id: String::new(),
                    created_at: 0,
                },
                signer_public_key: Vec::new(),
                timestamp: 0,
            })
            .collect::<Vec<_>>();
        assert!(
            !consensus.has_commit_quorum(&active_validators, &four_votes),
            "4 of 6 equal-weight votes must not satisfy strict greater-than-two-thirds quorum"
        );

        let five_votes = [
            "validator1",
            "validator2",
            "validator3",
            "validator4",
            "validator5",
        ]
        .into_iter()
        .map(|validator_address| Vote {
            validator_address: validator_address.to_string(),
            block_hash: "block-hash".to_string(),
            block_index: 42,
            epoch_number: 1,
            round_number: 1,
            signature: PQCSignature {
                algorithm: PQCAlgorithm::FNDSA,
                signature_data: Vec::new(),
                message_hash: Vec::new(),
                public_key_id: String::new(),
                created_at: 0,
            },
            signer_public_key: Vec::new(),
            timestamp: 0,
        })
        .collect::<Vec<_>>();
        assert!(
            consensus.has_commit_quorum(&active_validators, &five_votes),
            "5 of 6 equal-weight votes must satisfy strict greater-than-two-thirds quorum"
        );
    }

    #[test]
    fn count_quorum_cannot_override_insufficient_bonded_voting_weight() {
        let validator_manager = approved_validator_manager(&[
            "validator1",
            "validator2",
            "validator3",
            "validator4",
            "validator5",
            "validator6",
        ]);
        {
            let mut registry = validator_manager
                .registry
                .lock()
                .expect("weighted quorum registry should lock");
            registry
                .validators
                .get_mut("validator6")
                .expect("heavy validator should exist")
                .stake_amount = 10_000;
        }
        let pqc_manager = Arc::new(Mutex::new(PQCManager::new()));
        let consensus = DualQuorumConsensus::new(
            Arc::clone(&validator_manager),
            Arc::clone(&pqc_manager),
            false,
            3,
            4,
            2,
            6,
        );
        let active_validators =
            consensus_membership_validators(validator_manager.get_active_validators());
        let votes = [
            "validator1",
            "validator2",
            "validator3",
            "validator4",
            "validator5",
        ]
        .into_iter()
        .map(|validator_address| Vote {
            validator_address: validator_address.to_string(),
            block_hash: "weighted-block-hash".to_string(),
            block_index: 42,
            epoch_number: 1,
            round_number: 1,
            signature: PQCSignature {
                algorithm: PQCAlgorithm::FNDSA,
                signature_data: Vec::new(),
                message_hash: Vec::new(),
                public_key_id: String::new(),
                created_at: 0,
            },
            signer_public_key: Vec::new(),
            timestamp: 0,
        })
        .collect::<Vec<_>>();

        assert_eq!(
            consensus.required_validator_votes(active_validators.len()),
            5
        );
        assert!(
            !consensus.has_commit_quorum(&active_validators, &votes),
            "five signers satisfy count quorum but only carry 5,000 of 15,000 bonded weight"
        );
    }

    #[test]
    fn synergy_score_does_not_change_single_cluster_vote_power() {
        let _vote_tracking_guard = DualQuorumConsensus::test_vote_tracking_guard();
        DualQuorumConsensus::reset_test_vote_tracking();

        let validator_manager = approved_validator_manager(&[
            "validator1",
            "validator2",
            "validator3",
            "validator4",
            "validator5",
            "validator6",
        ]);
        {
            let mut registry = validator_manager
                .registry
                .lock()
                .expect("score-divergence registry should lock");
            for (address, score) in [
                ("validator1", 100.0),
                ("validator2", 100.0),
                ("validator3", 1.0),
                ("validator4", 1.0),
                ("validator5", 1.0),
                ("validator6", 1.0),
            ] {
                registry
                    .validators
                    .get_mut(address)
                    .expect("validator should be registered")
                    .synergy_score = score;
            }
        }

        let pqc_manager = Arc::new(Mutex::new(PQCManager::new()));
        let mut consensus = DualQuorumConsensus::new(
            Arc::clone(&validator_manager),
            Arc::clone(&pqc_manager),
            false,
            3,
            4,
            2,
            6,
        );
        let block = signed_block_for_manager(42, 1, "validator1", &validator_manager);
        let votes = [
            "validator1",
            "validator3",
            "validator4",
            "validator5",
            "validator6",
        ]
        .into_iter()
        .map(|address| {
            DualQuorumConsensus::create_vote_for_validator_with_manager(
                address,
                &block,
                1,
                1,
                &validator_manager,
            )
            .expect("active validator should sign a vote")
        })
        .collect::<Vec<_>>();
        let active_validators =
            consensus_membership_validators(validator_manager.get_active_validators());

        assert_eq!(
            consensus.required_validator_votes(active_validators.len()),
            5
        );
        assert!(
            consensus.has_commit_quorum(&active_validators, &votes),
            "the required dynamic quorum must be independent of Synergy Score"
        );

        let qc = consensus
            .check_quorums_and_commit(&block, 1, 1, &votes)
            .expect("five valid signers must produce a single-cluster QC");
        assert_eq!(qc.cumulative_weight, 5_000.0);
        DualQuorumConsensus::verify_commit_certificate_for_block_static(
            &block,
            &qc,
            &validator_manager,
        )
        .expect("QC verification must use frozen bonded weight rather than Synergy Score");
    }

    #[test]
    fn exact_two_thirds_equal_weight_votes_commit() {
        let validator_manager = equal_weight_validator_manager(100);
        let pqc_manager = Arc::new(Mutex::new(PQCManager::new()));
        let consensus = DualQuorumConsensus::new(
            Arc::clone(&validator_manager),
            Arc::clone(&pqc_manager),
            false,
            1,
            0,
            2,
            6,
        );
        let active_validators =
            consensus_membership_validators(validator_manager.get_active_validators());
        let votes = active_validators
            .iter()
            .take(67)
            .map(|validator| Vote {
                validator_address: validator.address.clone(),
                block_hash: "block-hash".to_string(),
                block_index: 42,
                epoch_number: 1,
                round_number: 1,
                signature: PQCSignature {
                    algorithm: PQCAlgorithm::FNDSA,
                    signature_data: Vec::new(),
                    message_hash: Vec::new(),
                    public_key_id: String::new(),
                    created_at: 0,
                },
                signer_public_key: Vec::new(),
                timestamp: 0,
            })
            .collect::<Vec<_>>();

        assert_eq!(
            consensus.required_validator_votes(active_validators.len()),
            67
        );
        assert!(
            consensus.has_commit_quorum(&active_validators, &votes),
            "exactly 67 of 100 equal-weight votes must satisfy dynamic two-thirds quorum"
        );
    }

    #[test]
    fn validator_quorum_follows_active_validator_count_not_static_config() {
        let validator_manager =
            approved_validator_manager(&["validator1", "validator2", "validator3"]);
        let pqc_manager = Arc::new(Mutex::new(PQCManager::new()));
        let consensus = DualQuorumConsensus::new(
            Arc::clone(&validator_manager),
            Arc::clone(&pqc_manager),
            false,
            1,
            4,
            2,
            6,
        );
        let active_validators =
            consensus_membership_validators(validator_manager.get_active_validators());
        let votes = ["validator1", "validator2", "validator3"]
            .into_iter()
            .map(|validator_address| Vote {
                validator_address: validator_address.to_string(),
                block_hash: "block-hash".to_string(),
                block_index: 42,
                epoch_number: 1,
                round_number: 1,
                signature: PQCSignature {
                    algorithm: PQCAlgorithm::FNDSA,
                    signature_data: Vec::new(),
                    message_hash: Vec::new(),
                    public_key_id: String::new(),
                    created_at: 0,
                },
                signer_public_key: Vec::new(),
                timestamp: 0,
            })
            .collect::<Vec<_>>();

        assert_eq!(
            consensus.required_validator_votes(active_validators.len()),
            required_validator_quorum(active_validators.len())
        );
        assert!(
            consensus.has_commit_quorum(&active_validators, &votes),
            "dynamic quorum must come from the active validator set, not a stale configured value"
        );
    }

    #[test]
    fn configured_quorum_does_not_override_bft_for_five_validators() {
        let validator_manager = approved_validator_manager(&[
            "validator1",
            "validator2",
            "validator3",
            "validator4",
            "validator5",
        ]);
        let pqc_manager = Arc::new(Mutex::new(PQCManager::new()));
        let consensus = DualQuorumConsensus::new(
            Arc::clone(&validator_manager),
            Arc::clone(&pqc_manager),
            false,
            1,
            3,
            2,
            6,
        );
        let active_validators =
            consensus_membership_validators(validator_manager.get_active_validators());
        let votes = ["validator1", "validator2", "validator3"]
            .into_iter()
            .map(|validator_address| Vote {
                validator_address: validator_address.to_string(),
                block_hash: "block-hash".to_string(),
                block_index: 42,
                epoch_number: 1,
                round_number: 1,
                signature: PQCSignature {
                    algorithm: PQCAlgorithm::FNDSA,
                    signature_data: Vec::new(),
                    message_hash: Vec::new(),
                    public_key_id: String::new(),
                    created_at: 0,
                },
                signer_public_key: Vec::new(),
                timestamp: 0,
            })
            .collect::<Vec<_>>();

        assert_eq!(
            consensus.required_validator_votes(active_validators.len()),
            4
        );
        assert!(
            !consensus.has_commit_quorum(&active_validators, &votes),
            "configured quorum must not allow 3 collected votes across five active validators"
        );
    }

    #[test]
    fn local_conflicting_vote_attempt_is_rejected_without_self_slashing() {
        let _vote_tracking_guard = DualQuorumConsensus::test_vote_tracking_guard();
        DualQuorumConsensus::reset_test_vote_tracking();

        let validator_manager = approved_validator_manager(&["validator1", "validator2"]);
        let pqc_manager = Arc::new(Mutex::new(PQCManager::new()));
        let consensus = DualQuorumConsensus::new(
            Arc::clone(&validator_manager),
            Arc::clone(&pqc_manager),
            true,
            1,
            1,
            8,
            5,
        );

        let first_block = signed_block(11, 1, "validator1");
        let conflicting_block = signed_block(11, 2, "validator1");

        let first_vote = DualQuorumConsensus::create_vote_for_validator_with_manager(
            "validator2",
            &first_block,
            30,
            1,
            &validator_manager,
        )
        .expect("first local vote should be created");
        consensus
            .register_local_vote_or_slash(&first_vote)
            .expect("first local vote should be accepted");

        let conflicting_vote = DualQuorumConsensus::create_vote_for_validator_with_manager(
            "validator2",
            &conflicting_block,
            30,
            1,
            &validator_manager,
        )
        .expect("conflicting local vote should be created");
        let error = consensus
            .register_local_vote_or_slash(&conflicting_vote)
            .expect_err("conflicting local vote should be rejected");
        assert!(
            error.contains("attempted conflicting votes"),
            "unexpected local conflict error: {error}"
        );

        let validator = validator_manager
            .get_validator("validator2")
            .expect("validator should still exist");
        assert_eq!(validator.status, ValidatorStatus::Active);
        assert_eq!(validator.double_signs, 0);
        assert_eq!(validator.equivocation_evidence_count, 0);

        let evidence = EQUIVOCATION_EVIDENCE_LOG.lock().expect("evidence log lock");
        let local_key = DualQuorumConsensus::vote_observation_key("validator2", 30, 11, 1);
        assert!(
            !evidence.contains_key(&local_key),
            "local conflicting vote should not persist slashable evidence"
        );
    }

    #[test]
    fn identical_vote_replay_is_idempotent() {
        let _vote_tracking_guard = DualQuorumConsensus::test_vote_tracking_guard();
        DualQuorumConsensus::reset_test_vote_tracking();

        let validator_manager = approved_validator_manager(&["validator1", "validator2"]);
        let pqc_manager = Arc::new(Mutex::new(PQCManager::new()));
        let consensus = DualQuorumConsensus::new(
            Arc::clone(&validator_manager),
            Arc::clone(&pqc_manager),
            true,
            1,
            1,
            8,
            5,
        );

        let block = signed_block(12, 1, "validator1");
        let vote = DualQuorumConsensus::create_vote_for_validator_with_manager(
            "validator2",
            &block,
            31,
            1,
            &validator_manager,
        )
        .expect("vote should be created");

        consensus
            .register_local_vote_or_slash(&vote)
            .expect("first local vote should be accepted");
        consensus
            .register_local_vote_or_slash(&vote)
            .expect("replaying the same vote should be idempotent");

        let validator = validator_manager
            .get_validator("validator2")
            .expect("validator should still exist");
        assert_eq!(validator.status, ValidatorStatus::Active);
        assert_eq!(validator.double_signs, 0);
        assert_eq!(validator.equivocation_evidence_count, 0);

        let evidence = EQUIVOCATION_EVIDENCE_LOG.lock().expect("evidence log lock");
        let local_key = DualQuorumConsensus::vote_observation_key("validator2", 31, 12, 1);
        assert!(
            !evidence.contains_key(&local_key),
            "idempotent replay should not persist slashable evidence"
        );
    }

    #[test]
    fn epoch_randomness_is_deterministic_for_shared_qc() {
        let previous_qc = QuorumCertificate {
            block_hash: "shared-block-hash".to_string(),
            cluster_id: None,
            epoch_number: 7,
            round_number: 3,
            aggregate_signature: vec![1, 2, 3],
            participant_bitmap: vec![0x1f],
            cumulative_weight: 5.0,
            validation_quorum_met: true,
            cooperation_quorum_met: true,
            timestamp: 1_777_000_000,
            votes: Vec::new(),
        };
        let mut beacon_a = EntropyBeacon::new(Arc::new(Mutex::new(PQCManager::new())));
        let mut beacon_b = EntropyBeacon::new(Arc::new(Mutex::new(PQCManager::new())));

        let randomness_a = beacon_a.generate_epoch_randomness(&previous_qc);
        let randomness_b = beacon_b.generate_epoch_randomness(&previous_qc);

        assert_eq!(randomness_a, randomness_b);
    }

    #[test]
    fn epoch_randomness_ignores_qc_timestamp_differences() {
        let previous_qc_a = QuorumCertificate {
            block_hash: "shared-block-hash".to_string(),
            cluster_id: None,
            epoch_number: 7,
            round_number: 3,
            aggregate_signature: vec![1, 2, 3],
            participant_bitmap: vec![0x1f],
            cumulative_weight: 5.0,
            validation_quorum_met: true,
            cooperation_quorum_met: true,
            timestamp: 1_777_000_000,
            votes: Vec::new(),
        };
        let mut previous_qc_b = previous_qc_a.clone();
        previous_qc_b.timestamp += 42;

        let mut beacon_a = EntropyBeacon::new(Arc::new(Mutex::new(PQCManager::new())));
        let mut beacon_b = EntropyBeacon::new(Arc::new(Mutex::new(PQCManager::new())));

        let randomness_a = beacon_a.generate_epoch_randomness(&previous_qc_a);
        let randomness_b = beacon_b.generate_epoch_randomness(&previous_qc_b);

        assert_eq!(randomness_a, randomness_b);
    }

    #[test]
    fn epoch_randomness_ignores_local_beacon_epoch_drift() {
        let previous_qc = QuorumCertificate {
            block_hash: "shared-block-hash".to_string(),
            cluster_id: None,
            epoch_number: 7,
            round_number: 3,
            aggregate_signature: vec![1, 2, 3],
            participant_bitmap: vec![0x1f],
            cumulative_weight: 5.0,
            validation_quorum_met: true,
            cooperation_quorum_met: true,
            timestamp: 1_777_000_000,
            votes: Vec::new(),
        };
        let mut beacon_a = EntropyBeacon::new(Arc::new(Mutex::new(PQCManager::new())));
        let mut beacon_b = EntropyBeacon::new(Arc::new(Mutex::new(PQCManager::new())));

        // Simulate nodes that have taken a different number of local transition
        // attempts before observing the same epoch-boundary QC.
        beacon_a.current_epoch = 2;
        beacon_b.current_epoch = 19;

        let randomness_a = beacon_a.generate_epoch_randomness(&previous_qc);
        let randomness_b = beacon_b.generate_epoch_randomness(&previous_qc);

        assert_eq!(randomness_a, randomness_b);
        assert_eq!(beacon_a.current_epoch, 8);
        assert_eq!(beacon_b.current_epoch, 8);
    }
}

#[derive(Debug, Clone)]
pub struct EntropyBeacon {
    pub current_epoch: u64,
    pub epoch_randomness: Vec<u8>,
    pub previous_qc_hash: String,
    pub nonce: u64,
    pub pqc_manager: Arc<Mutex<PQCManager>>,
    pub mlkem_keypairs: HashMap<u64, (PQCPublicKey, PQCPrivateKey)>, // Store keypairs per epoch
}

impl EntropyBeacon {
    pub fn new(pqc_manager: Arc<Mutex<PQCManager>>) -> Self {
        EntropyBeacon {
            current_epoch: 0,
            epoch_randomness: Vec::new(),
            previous_qc_hash: String::new(),
            nonce: 0,
            pqc_manager,
            mlkem_keypairs: HashMap::new(),
        }
    }

    pub fn generate_epoch_randomness(&mut self, previous_qc: &QuorumCertificate) -> Vec<u8> {
        let next_epoch = previous_qc.epoch_number.saturating_add(1);
        self.current_epoch = next_epoch;
        self.previous_qc_hash = self.hash_qc(previous_qc);
        self.nonce += 1;

        // Epoch randomness must be identical across validators at the same chain
        // tip. Only use deterministic inputs derived from the previous QC. Do
        // not generate KEM material in the live consensus epoch-transition path:
        // validator consensus signing is FN-DSA, while ML-KEM is a separate
        // encapsulation primitive and is not required to produce the next block.
        let mut input = Vec::new();
        input.extend(next_epoch.to_be_bytes());
        input.extend(self.previous_qc_hash.as_bytes());

        let mut hasher = Sha3_512::new();
        hasher.update(&input);
        let hash = hasher.finalize();

        // Store the computed randomness
        self.epoch_randomness = hash.to_vec();

        self.epoch_randomness.clone()
    }

    // Method to decapsulate and verify the shared secret (for cross-validation between validators)
    pub fn decapsulate_epoch_randomness(
        &self,
        epoch: u64,
        ciphertext: &PQCCiphertext,
    ) -> Result<Vec<u8>, String> {
        if let Some((_, priv_key)) = self.mlkem_keypairs.get(&epoch) {
            let pqc_manager = self.pqc_manager.lock().unwrap();
            let shared_secret = pqc_manager
                .decapsulate(priv_key, ciphertext)
                .map_err(|e| format!("Failed to decapsulate epoch randomness: {}", e))?;
            Ok(shared_secret.secret)
        } else {
            Err("No keypair found for epoch".to_string())
        }
    }

    fn hash_qc(&self, qc: &QuorumCertificate) -> String {
        let mut hasher = Sha3_512::new();
        hasher.update(qc.block_hash.as_bytes());
        hasher.update(qc.epoch_number.to_be_bytes());
        hasher.update(qc.round_number.to_be_bytes());
        hasher.update([qc.cluster_id.is_some() as u8]);
        if let Some(cluster_id) = qc.cluster_id {
            hasher.update(cluster_id.to_be_bytes());
        }
        hasher.update(&qc.aggregate_signature);
        hasher.update(&qc.participant_bitmap);
        hasher.update([qc.validation_quorum_met as u8]);
        hasher.update([qc.cooperation_quorum_met as u8]);
        let hash = hasher.finalize();
        hex::encode(hash)
    }

    fn current_timestamp() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }
}

#[derive(Debug, Clone)]
pub struct ValidatorRotation {
    pub validator_manager: Arc<ValidatorManager>,
    pub entropy_beacon: Arc<Mutex<EntropyBeacon>>,
    pub target_cluster_size: usize,
}

impl ValidatorRotation {
    pub fn new(
        validator_manager: Arc<ValidatorManager>,
        entropy_beacon: Arc<Mutex<EntropyBeacon>>,
    ) -> Self {
        ValidatorRotation {
            validator_manager,
            entropy_beacon,
            target_cluster_size: TESTNET_VALIDATOR_CLUSTER_SIZE,
        }
    }

    pub fn rotate_validators(&self) {
        let epoch = self
            .entropy_beacon
            .lock()
            .map(|beacon| beacon.current_epoch)
            .unwrap_or_else(|_| self.validator_manager.get_current_epoch());
        self.validator_manager.reorganize_clusters_for_epoch(epoch);
    }
}
