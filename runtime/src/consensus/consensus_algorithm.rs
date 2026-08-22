use super::cartel_detection::{CartelDetectionEngine, VoteRecord};
use super::chain_durability::append_committed_block_body;
use super::dao_governance::{DAOGovernance, GovernanceProposal, ProposalStatus};
use super::dual_quorum::{
    required_validator_quorum, DualQuorumConsensus, EntropyBeacon, QuorumCertificate,
    ValidatorRotation, Vote, FAST_CONSENSUS_VOTE_TIMEOUT_SECS, MIN_LAUNCH_VOTE_TIMEOUT_SECS,
};
use super::legacy_canonical_lock::{verify_legacy_canonical_lock, write_legacy_canonical_lock};
use super::synergy_score::SynergyScoreCalculator;
use super::timing_trace;
use super::validator_keys::{consensus_algorithm_label, load_local_validator_keypair_for_height};
use super::vrf::{VRFConsensus, VRFSeed};
use crate::block::{Block, BlockChain};
use crate::crypto::pqc::{PQCAlgorithm, PQCManager, PQCPublicKey};
use crate::epoch::{
    block_position_in_epoch, epoch_end_height, epoch_for_block_height, epoch_start_height,
};
use crate::genesis::canonical_genesis;
use crate::p2p::networking::P2PNetwork;
use crate::rpc::rpc_server::{
    cache_last_known_good_chain_tip, prune_transaction_hashes_from_pool, transaction_hashes,
    SHARED_CHAIN, SYNC_MANAGER, TX_POOL,
};
use crate::token::TOKEN_MANAGER;
use crate::validator::{
    apply_validator_activation_transaction, consensus_membership_validators,
    consensus_membership_validators_for_height, effective_cluster_epoch_for_height,
    is_validator_activation_transaction, replay_validator_activation_transactions,
    validate_validator_activation_transaction, Validator, ValidatorManager, ValidatorStatus,
    TESTNET_VALIDATOR_CLUSTER_SIZE, VALIDATOR_MANAGER,
};
use crate::wallet::WALLET_MANAGER;
use crate::{debug, info, warn};
use base64::{engine::general_purpose, Engine as _};
use hex;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_512};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

// CHAIN_PATH will be resolved at runtime using project root
fn get_chain_path() -> String {
    crate::utils::resolve_data_path("data/chain.json")
        .to_str()
        .unwrap_or("data/chain.json")
        .to_string()
}
const VALIDATOR_REGISTRY_PATH: &str = "data/validator_registry.json";
const VERBOSE_CONSENSUS_LOGS: bool = false;
const POST_COMMIT_PARENT_PROPAGATION_GRACE_MILLIS: u64 = 250;
const SAFE_HEAD_CATCHUP_WITHOUT_MESH_RESET_BLOCKS: u64 = 1;
const DEFAULT_MAX_CHAIN_SNAPSHOT_CLONE_HEIGHT: u64 = 50_000;
const PROPOSAL_TRANSACTION_MAX_AGE_SECS: u64 = 3_600;
// v19.0.15 used height / 1000 in committed QC metadata at every exact epoch
// boundary. The QC remains hash-bound and dual-quorum finalized; normalize only
// that metadata through this frozen cutover window. Later off-by-one QCs fail closed.
const CANONICAL_TESTNET_EPOCH_LENGTH: u64 = 1_000;
const ONE_BASED_EPOCH_MIGRATION_CUTOFF_HEIGHT: u64 = 1_052_000;
// Cluster assignment moves first, after a fixed rollout window. Leader selection retains the
// longer compatibility window because mixing leader schedules can stop finality. These are
// protocol heights, not wall-clock timers, so restarts cannot move either cutover.
pub(crate) const CLUSTER_RANDOMNESS_V3_ACTIVATION_EPOCH: u64 = 1_150;
pub(crate) const CLUSTER_RANDOMNESS_V3_ACTIVATION_HEIGHT: u64 = 1_150_001;
pub(crate) const EPOCH_RANDOMNESS_V3_ACTIVATION_EPOCH: u64 = 1_200;
pub(crate) const EPOCH_RANDOMNESS_V3_ACTIVATION_HEIGHT: u64 = 1_200_001;
const LEGACY_QC_HASH_RANDOMNESS_SCHEME: &str = "legacy-qc-hash-v2";
const LEGACY_CLUSTER_QC_HASH_RANDOMNESS_SCHEME: &str = "legacy-cluster-qc-hash-v2";
const LEGACY_PERSISTED_CLUSTER_RANDOMNESS_SCHEME: &str = "legacy-persisted-cluster-seed-v2";
const LEGACY_GENESIS_RANDOMNESS_SCHEME: &str = "legacy-genesis-v2";
const LEGACY_EPOCH_ZERO_RANDOMNESS_DOMAIN: &str = "synergy-epoch-zero-randomness-v2";
const BOUNDARY_HASH_RANDOMNESS_SCHEME: &str = "boundary-hash-v3";
const BOUNDARY_HASH_CLUSTER_RANDOMNESS_SCHEME: &str = "boundary-hash-cluster-v3";
const BOUNDARY_HASH_LEADER_RANDOMNESS_DOMAIN: &[u8] = b"synergy-testnet-epoch-leader-randomness-v3";
const BOUNDARY_HASH_CLUSTER_RANDOMNESS_DOMAIN: &[u8] =
    b"synergy-testnet-epoch-cluster-randomness-v3";

macro_rules! consensus_log {
    ($($arg:tt)*) => {
        if VERBOSE_CONSENSUS_LOGS {
            println!($($arg)*);
        }
    };
}

fn staking_payload(tx: &crate::transaction::Transaction) -> Option<serde_json::Value> {
    let data = tx.data.as_deref()?;
    let payload = data.strip_prefix("stake:")?;
    serde_json::from_str::<serde_json::Value>(payload).ok()
}

fn staking_validator_address(tx: &crate::transaction::Transaction) -> Option<String> {
    staking_payload(tx)?
        .get("validator")
        .and_then(|value| value.as_str())
        .map(str::to_string)
}

fn staking_amount_nwei(tx: &crate::transaction::Transaction) -> Option<u64> {
    staking_payload(tx)?
        .get("amount")
        .and_then(|value| value.as_u64())
}

fn snrg_balance_required_for_transaction(tx: &crate::transaction::Transaction) -> u64 {
    let fee = tx.get_total_network_fee_u64().unwrap_or(u64::MAX);
    if tx
        .data
        .as_deref()
        .map(|data| data.starts_with("stake:"))
        .unwrap_or(false)
    {
        return staking_amount_nwei(tx)
            .unwrap_or(tx.amount)
            .saturating_add(fee);
    }

    tx.amount.saturating_add(fee)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SynergyScores {
    pub scores: HashMap<String, f64>,
    pub last_updated: u64,
}

#[derive(Debug)]
pub struct ProofOfSynergy {
    pub chain: Arc<Mutex<BlockChain>>,
    pub validator_manager: Arc<ValidatorManager>,
    pub synergy_scores: SynergyScores,
    pub block_time: u64,
    pub epoch_length: u64,
    pub min_validators: usize,
    pub cluster_size: usize,
    pub status_ready_gate_enabled: bool,
    pub status_ready_min_validators: usize,
    pub status_ready_genesis_grace_secs: u64,
    pub allow_genesis_status_bypass: bool,
    pub mesh_settle_secs: u64,
    pub leader_timeout_secs: u64,
    pub vote_timeout_secs: u64,
    pub block_timeout_secs: u64,
    pub penalization_enabled: bool,
    pub vrf_enabled: bool,
    pub vrf_seed_interval: u64,
    pub max_synergy_points: u64,
    pub reward_weights: RewardWeights,
    pub vrf_consensus: VRFConsensus,
    pub current_vrf_seed: Option<VRFSeed>,

    // New PoSy components
    pub synergy_calculator: Arc<SynergyScoreCalculator>,
    pub dual_quorum_consensus: Arc<Mutex<DualQuorumConsensus>>,
    pub entropy_beacon: Arc<Mutex<EntropyBeacon>>,
    pub validator_rotation: Arc<ValidatorRotation>,
    pub dao_governance: Arc<Mutex<DAOGovernance>>,
    pub cartel_detection: Arc<Mutex<CartelDetectionEngine>>,
    pub pqc_manager: Arc<Mutex<PQCManager>>,

    // State tracking
    pub current_epoch: u64,
    pub epoch_votes: HashMap<u64, Vec<Vote>>,
    pub quorum_certificates: HashMap<u64, QuorumCertificate>,
    pub governance_proposals: HashMap<String, GovernanceProposal>,
}

#[derive(Debug, Clone)]
pub struct RewardWeights {
    pub task_accuracy: f64,
    pub uptime: f64,
    pub collaboration: f64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CatchupReadinessDecision {
    preserve_mesh_readiness: bool,
    reset_pacing_anchor_to_now: bool,
    reason: &'static str,
}

impl CatchupReadinessDecision {
    const fn preserve(reason: &'static str) -> Self {
        Self {
            preserve_mesh_readiness: true,
            reset_pacing_anchor_to_now: false,
            reason,
        }
    }

    const fn reset(reason: &'static str) -> Self {
        Self {
            preserve_mesh_readiness: false,
            reset_pacing_anchor_to_now: true,
            reason,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArchivedConsensusProposal {
    pub source_path: String,
    pub evidence_path: String,
    pub block_index: u64,
    pub block_hash: String,
    pub parent_hash: String,
    pub proposer: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProposalCacheRecoveryReport {
    pub action: String,
    pub reason: String,
    pub finalized_height: u64,
    pub proposal_cache_dir: String,
    pub evidence_dir: String,
    pub scanned_count: usize,
    pub archived_count: usize,
    pub archived: Vec<ArchivedConsensusProposal>,
    pub mutated: bool,
    pub timestamp: u64,
}

// Track leader rotation within epochs
lazy_static::lazy_static! {
    static ref EPOCH_LEADER_ROTATION: Arc<Mutex<(u64, Vec<String>, usize, Vec<String>)>> =
        Arc::new(Mutex::new((0, Vec::new(), 0, Vec::new()))); // (epoch, top_k_validators, current_index, candidate_set)
    static ref PROPOSAL_CACHE_LOCK: Arc<Mutex<()>> = Arc::new(Mutex::new(()));
    static ref LAST_CONSENSUS_CHAIN_PERSIST: Arc<Mutex<Option<(u64, Instant)>>> =
        Arc::new(Mutex::new(None));
    static ref CONSENSUS_CHAIN_PERSIST_IN_FLIGHT: AtomicBool = AtomicBool::new(false);
}

static PROPOSAL_CACHE_DISCARD_COUNT: AtomicU64 = AtomicU64::new(0);
static EXPIRED_PROPOSAL_TRANSACTION_DROP_COUNT: AtomicU64 = AtomicU64::new(0);

#[cfg(test)]
lazy_static::lazy_static! {
    static ref TEST_PROPOSAL_CACHE_DIR: Arc<Mutex<Option<PathBuf>>> = Arc::new(Mutex::new(None));
}

#[cfg(test)]
pub(crate) fn reconcile_validator_registry_clusters_for_height(
    validator_manager: &Arc<ValidatorManager>,
    height: u64,
) -> Result<bool, String> {
    let mut registry = validator_manager
        .registry
        .lock()
        .map_err(|_| "failed to lock validator registry for cluster reconciliation".to_string())?;
    let epoch = epoch_for_block_height(height, registry.epoch_length.max(1));
    registry.reconcile_clusters_for_height(epoch, height)
}

pub(crate) fn reconcile_validator_registry_clusters_from_finalized_chain(
    validator_manager: &Arc<ValidatorManager>,
    chain: &BlockChain,
    height: u64,
) -> Result<bool, String> {
    let epoch_length = CANONICAL_TESTNET_EPOCH_LENGTH;
    let supplied_epoch = epoch_for_block_height(height, epoch_length);
    let effective_epoch = effective_cluster_epoch_for_height(supplied_epoch, height)?;
    let evidence = ProofOfSynergy::cluster_epoch_randomness_evidence(
        chain,
        effective_epoch,
        epoch_length,
        validator_manager,
    )?;
    let randomness_source = hex::encode(&evidence.randomness);
    let mut registry = validator_manager
        .registry
        .lock()
        .map_err(|_| "failed to lock validator registry for cluster reconciliation".to_string())?;
    let epoch_contract_normalized = registry.normalize_testnet_epoch_contract();
    let mut epoch_contract_changed = evidence.registry_migrated || epoch_contract_normalized;
    let canonical_effective_height = epoch_start_height(effective_epoch, epoch_length);
    let cutover_rebuild_required = registry.current_epoch < CLUSTER_RANDOMNESS_V3_ACTIVATION_EPOCH
        && effective_epoch >= CLUSTER_RANDOMNESS_V3_ACTIVATION_EPOCH;
    let same_epoch_metadata_conflict = registry.validators.values().any(|validator| {
        validator.status == ValidatorStatus::Active
            && validator.cluster_assignment_epoch == Some(effective_epoch)
            && (validator.cluster_assignment_seed.as_deref() != Some(randomness_source.as_str())
                || validator.cluster_assignment_effective_height
                    != Some(canonical_effective_height))
    });
    if cutover_rebuild_required || same_epoch_metadata_conflict {
        registry.clear_cluster_assignments();
        epoch_contract_changed = true;
    }
    if registry.current_epoch != effective_epoch {
        registry.current_epoch = effective_epoch;
        epoch_contract_changed = true;
    }
    let clusters_changed = registry.reconcile_clusters_for_height_with_seed(
        effective_epoch,
        height,
        &randomness_source,
    )?;
    Ok(epoch_contract_changed || clusters_changed)
}

#[derive(Debug, Clone)]
pub(crate) struct EpochRandomnessEvidence {
    pub next_epoch: u64,
    pub boundary_height: Option<u64>,
    pub boundary_block_hash: Option<String>,
    pub boundary_qc_verified: bool,
    pub scheme: &'static str,
    pub assignment_effective_height: u64,
    pub randomness: Vec<u8>,
    pub registry_migrated: bool,
}

#[derive(Debug, Clone)]
pub(crate) struct CanonicalEpochBoundaryEvidence {
    pub next_epoch: u64,
    pub boundary_height: u64,
    pub boundary_block_hash: String,
    pub assignment_effective_height: u64,
    pub randomness: Vec<u8>,
}

impl ProofOfSynergy {
    pub fn proposal_cache_discard_count() -> u64 {
        PROPOSAL_CACHE_DISCARD_COUNT.load(Ordering::Relaxed)
    }

    pub fn expired_proposal_transaction_drop_count() -> u64 {
        EXPIRED_PROPOSAL_TRANSACTION_DROP_COUNT.load(Ordering::Relaxed)
    }

    pub fn new() -> Self {
        // Use the global shared chain instance
        let chain = Arc::clone(&SHARED_CHAIN);

        // Use global validator manager
        let validator_manager = Arc::clone(&VALIDATOR_MANAGER);

        // Initialize PQC manager
        let pqc_manager = Arc::new(Mutex::new(PQCManager::new()));

        // Initialize synergy score calculator
        let synergy_calculator = Arc::new(SynergyScoreCalculator::new(
            Arc::clone(&validator_manager),
            Arc::clone(&pqc_manager),
        ));

        // Initialize entropy beacon
        let entropy_beacon = Arc::new(Mutex::new(EntropyBeacon::new(Arc::clone(&pqc_manager))));

        // Initialize validator rotation
        let validator_rotation = Arc::new(ValidatorRotation::new(
            Arc::clone(&validator_manager),
            Arc::clone(&entropy_beacon),
        ));

        // Initialize DAO governance
        let dao_governance = Arc::new(Mutex::new(DAOGovernance::new(
            Arc::clone(&validator_manager),
            Arc::clone(&synergy_calculator),
            Arc::clone(&pqc_manager),
        )));

        // Initialize cartel detection
        let cartel_detection = Arc::new(Mutex::new(CartelDetectionEngine::new(
            Arc::clone(&validator_manager),
            Arc::clone(&synergy_calculator),
        )));

        // Load validator registry from file or initialize baseline validators
        if let Err(e) = validator_manager.load_registry(VALIDATOR_REGISTRY_PATH) {
            println!(
                "🔧 No validator registry found — initializing with baseline validators: {}",
                e
            );
            Self::initialize_baseline_validators(&validator_manager);

            // Save the registry after initializing baseline validators
            if let Err(save_err) = validator_manager.save_registry(VALIDATOR_REGISTRY_PATH) {
                println!(
                    "⚠️ Failed to save validator registry after baseline validator initialization: {}",
                    save_err
                );
            } else {
                println!("✅ Validator registry saved to {}", VALIDATOR_REGISTRY_PATH);
            }
        } else {
            // Registry exists.  Re-read genesis.json so any validators that were
            // added after the node's first run (e.g. multi-node setups where the
            // genesis.json was populated after initial launch) are registered and
            // approved, not just staked.
            println!(
                "🔧 Validator registry loaded, ensuring baseline validators have baseline stakes"
            );
            Self::ensure_baseline_validator_stakes(&validator_manager);

            // Persist any newly-registered validators back to disk.
            if let Err(save_err) = validator_manager.save_registry(VALIDATOR_REGISTRY_PATH) {
                println!(
                    "⚠️ Failed to save validator registry after baseline stake check: {}",
                    save_err
                );
            } else {
                println!("✅ Validator registry saved after genesis stake check");
            }
        }

        let chain_snapshot = {
            let chain_guard = chain.lock().unwrap();
            chain_guard.clone()
        };
        let token_manager = TOKEN_MANAGER.clone();
        let (activation_replayed, activation_failed) = replay_validator_activation_transactions(
            &chain_snapshot,
            &token_manager,
            &validator_manager,
        );
        if activation_replayed > 0 || activation_failed > 0 {
            info!(
                "consensus",
                "Replayed validator activation transactions into registry",
                "replayed" => activation_replayed,
                "failed" => activation_failed
            );
        }
        if activation_replayed > 0 {
            if let Err(error) = validator_manager.save_registry(VALIDATOR_REGISTRY_PATH) {
                warn!(
                    "consensus",
                    "Failed to persist replayed validator activations",
                    "error" => error.to_string()
                );
            }
        }

        let chain_height = chain_snapshot
            .last()
            .map(|block| block.block_index)
            .unwrap_or(0);
        match reconcile_validator_registry_clusters_from_finalized_chain(
            &validator_manager,
            &chain_snapshot,
            chain_height,
        ) {
            Ok(true) => {
                if let Err(error) = validator_manager.save_registry(VALIDATOR_REGISTRY_PATH) {
                    warn!(
                        "consensus",
                        "Failed to persist startup validator cluster reconciliation",
                        "height" => chain_height,
                        "error" => error.to_string()
                    );
                }
            }
            Ok(false) => {}
            Err(error) => {
                warn!(
                    "consensus",
                    "Failed to reconcile validator clusters at startup",
                    "height" => chain_height,
                    "error" => error
                );
            }
        }

        let synergy_scores = Self::load_synergy_scores().unwrap_or_else(|| {
            println!("🔧 No synergy scores found — initializing empty scores.");
            SynergyScores {
                scores: HashMap::new(),
                last_updated: Self::current_timestamp(),
            }
        });

        let consensus_cfg = crate::config::load_node_config(None)
            .ok()
            .map(|cfg| cfg.consensus);

        // Load consensus timing from env/config for deterministic testnet tuning.
        let block_time = std::env::var("SYNERGY_CONSENSUS_BLOCK_TIME_SECS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .or_else(|| consensus_cfg.as_ref().map(|c| c.block_time_secs))
            .unwrap_or(5)
            .max(1);

        let epoch_length = std::env::var("SYNERGY_CONSENSUS_EPOCH_LENGTH")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .or_else(|| consensus_cfg.as_ref().map(|c| c.epoch_length))
            .unwrap_or(1000)
            .max(1);

        let min_validators = std::env::var("SYNERGY_CONSENSUS_MIN_VALIDATORS")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .or_else(|| consensus_cfg.as_ref().map(|c| c.min_validators))
            .unwrap_or(3)
            .max(1);

        let validator_vote_threshold = 0;

        let status_ready_gate_enabled = consensus_cfg
            .as_ref()
            .map(|c| c.status_ready_gate_enabled)
            .unwrap_or(true);
        let status_ready_min_validators = consensus_cfg
            .as_ref()
            .map(|c| c.status_ready_min_validators)
            .unwrap_or(0);
        let status_ready_genesis_grace_secs = consensus_cfg
            .as_ref()
            .map(|c| c.status_ready_genesis_grace_secs)
            .unwrap_or(15);
        let allow_genesis_status_bypass = consensus_cfg
            .as_ref()
            .map(|c| c.allow_genesis_status_bypass)
            .unwrap_or(true);
        let mesh_settle_secs = consensus_cfg
            .as_ref()
            .map(|c| c.mesh_settle_secs)
            .unwrap_or(3);
        let leader_timeout_secs = consensus_cfg
            .as_ref()
            .map(|c| c.leader_timeout_secs)
            .unwrap_or(0);
        let vote_timeout_secs = consensus_cfg
            .as_ref()
            .map(|c| c.vote_timeout_secs)
            .unwrap_or(8)
            .max(1);
        let block_timeout_secs = consensus_cfg
            .as_ref()
            .map(|c| c.block_timeout_secs)
            .unwrap_or(5)
            .max(1);
        let penalization_enabled = consensus_cfg
            .as_ref()
            .map(|c| c.penalization_enabled)
            .unwrap_or(true);

        // Initialize dual quorum consensus after loading the minimum validator requirement.
        let dual_quorum_consensus = Arc::new(Mutex::new(DualQuorumConsensus::new(
            Arc::clone(&validator_manager),
            Arc::clone(&pqc_manager),
            penalization_enabled,
            min_validators,
            validator_vote_threshold,
            vote_timeout_secs,
            block_timeout_secs,
        )));

        let cluster_size = consensus_cfg
            .as_ref()
            .map(|c| c.validator_cluster_size)
            .unwrap_or(TESTNET_VALIDATOR_CLUSTER_SIZE);
        let vrf_enabled = consensus_cfg
            .as_ref()
            .map(|c| c.vrf_enabled)
            .unwrap_or(true);
        let vrf_seed_interval = consensus_cfg
            .as_ref()
            .map(|c| c.vrf_seed_epoch_interval)
            .unwrap_or(1000);
        let max_synergy_points = consensus_cfg
            .as_ref()
            .map(|c| c.max_synergy_points_per_epoch)
            .unwrap_or(100);

        let reward_weights = RewardWeights {
            task_accuracy: consensus_cfg
                .as_ref()
                .map(|c| c.reward_weighting.task_accuracy)
                .unwrap_or(0.5),
            uptime: consensus_cfg
                .as_ref()
                .map(|c| c.reward_weighting.uptime)
                .unwrap_or(0.3),
            collaboration: consensus_cfg
                .as_ref()
                .map(|c| c.reward_weighting.collaboration)
                .unwrap_or(0.2),
        };

        let vrf_consensus = VRFConsensus::new();
        let current_vrf_seed = if vrf_enabled {
            Some(VRFSeed::generate())
        } else {
            None
        };

        ProofOfSynergy {
            chain,
            validator_manager,
            synergy_scores,
            block_time,
            epoch_length,
            min_validators,
            cluster_size,
            status_ready_gate_enabled,
            status_ready_min_validators,
            status_ready_genesis_grace_secs,
            allow_genesis_status_bypass,
            mesh_settle_secs,
            leader_timeout_secs,
            vote_timeout_secs,
            block_timeout_secs,
            penalization_enabled,
            vrf_enabled,
            vrf_seed_interval,
            max_synergy_points,
            reward_weights,
            vrf_consensus,
            current_vrf_seed,
            synergy_calculator,
            dual_quorum_consensus,
            entropy_beacon,
            validator_rotation,
            dao_governance,
            cartel_detection,
            pqc_manager,
            current_epoch: 0,
            epoch_votes: HashMap::new(),
            quorum_certificates: HashMap::new(),
            governance_proposals: HashMap::new(),
        }
    }

    pub fn initialize(&mut self) {
        let active_validators =
            consensus_membership_validators(self.validator_manager.get_active_validators());
        let live_validator_addresses =
            Self::collect_live_validator_addresses(&self.validator_manager);
        let chain = self.chain.lock().unwrap();
        println!(
            "🔧 Chain loaded. Latest height: {}",
            chain.last().map_or(0, |b| b.block_index)
        );
        println!(
            "🔧 Validator registry loaded. Active validators: {}",
            active_validators.len()
        );
        println!(
            "🔧 Synergy scores loaded. Total entries: {}",
            self.synergy_scores.scores.len()
        );
        println!(
            "🔧 Live validator participants currently visible: {}",
            live_validator_addresses.len()
        );
        println!(
            "🔧 Minimum active validators required for block production: {}",
            self.min_validators
        );
        println!(
            "🔧 Status-ready gate: enabled={}, required={}, genesis_grace_secs={}, allow_genesis_bypass={}",
            self.status_ready_gate_enabled,
            if self.status_ready_min_validators == 0 {
                self.min_validators
            } else {
                self.status_ready_min_validators.max(1)
            },
            self.status_ready_genesis_grace_secs,
            false
        );
        println!(
            "🔧 Mesh settle/window timeouts: settle_secs={}, leader_timeout_secs={}, vote_timeout_secs={}, block_timeout_secs={}",
            self.mesh_settle_secs,
            self.effective_leader_timeout_secs(),
            self.vote_timeout_secs,
            self.block_timeout_secs
        );
        println!(
            "🔧 Validator penalization enabled: {}",
            self.penalization_enabled
        );
    }

    pub fn execute(&mut self) {
        info!("consensus", "Starting Proof of Synergy consensus engine");

        let chain = Arc::clone(&self.chain);
        let validator_manager = Arc::clone(&self.validator_manager);
        let synergy_calculator = Arc::clone(&self.synergy_calculator);
        let dual_quorum_consensus = Arc::clone(&self.dual_quorum_consensus);
        let entropy_beacon = Arc::clone(&self.entropy_beacon);
        let validator_rotation = Arc::clone(&self.validator_rotation);
        let dao_governance = Arc::clone(&self.dao_governance);
        let cartel_detection = Arc::clone(&self.cartel_detection);
        let pqc_manager = Arc::clone(&self.pqc_manager);
        let block_time_secs = self.block_time.max(1);
        let epoch_length = self.epoch_length.max(1);
        let configured_min_validators = self.min_validators.max(1);
        let status_ready_gate_enabled = self.status_ready_gate_enabled;
        let configured_status_ready_min_validators = if self.status_ready_min_validators == 0 {
            configured_min_validators
        } else {
            self.status_ready_min_validators.max(1)
        };
        let status_ready_genesis_grace_secs = self.status_ready_genesis_grace_secs;
        let allow_genesis_status_bypass = false;
        let mesh_settle_secs = self.mesh_settle_secs;
        let penalization_enabled = self.penalization_enabled;
        let leader_timeout_secs = self.effective_leader_timeout_secs();
        let vote_timeout_secs = self.vote_timeout_secs.max(MIN_LAUNCH_VOTE_TIMEOUT_SECS);

        thread::Builder::new()
            .name("posy-consensus".to_string())
            .spawn(move || {
            let mut last_block_time = chain
                .lock()
                .unwrap()
                .last()
                .map(|block| Self::next_block_pacing_anchor(block.timestamp, block_time_secs))
                .unwrap_or_else(SystemTime::now);
            let mut last_tip_observed_at = SystemTime::now();
            let mut consecutive_failures = 0;
            let mut current_epoch = chain
                .lock()
                .unwrap()
                .last()
                .map(|block| Self::epoch_for_block(block.block_index, epoch_length))
                .unwrap_or(0);
            if let Ok(mut consensus) = dual_quorum_consensus.lock() {
                consensus.current_epoch = current_epoch;
            }
            info!(
                "consensus",
                "Proof of Synergy consensus worker started",
                "current_epoch" => current_epoch,
                "epoch_length" => epoch_length,
                "block_time_secs" => block_time_secs,
                "leader_timeout_secs" => leader_timeout_secs
            );
            let mut mesh_ready_since: Option<Instant> = None;
            let mut status_sync_grace_since: Option<Instant> = None;
            let mut genesis_status_gate_bypassed = false;
            let mut last_committed_height: u64 = 0;
            let mut last_logged_view_timeout: Option<(u64, usize)> = None;
            let mut missed_quorum_view_override: Option<(u64, usize)> = None;

            loop {
                let current_time = SystemTime::now();
                let elapsed = current_time
                    .duration_since(last_block_time)
                    .unwrap_or_default();

                if elapsed >= Duration::from_secs(block_time_secs) {
                    let pool = TX_POOL.lock().unwrap();
                    let chain_guard = chain.lock().unwrap();

                    if let Some(latest_block) = chain_guard.last() {
                        if latest_block.block_index != last_committed_height {
                            last_committed_height = latest_block.block_index;
                            last_logged_view_timeout = None;
                            missed_quorum_view_override = None;
                            last_tip_observed_at = SystemTime::now();
                            last_block_time = Self::next_block_pacing_anchor_for_time(
                                latest_block.timestamp,
                                block_time_secs,
                                last_tip_observed_at,
                            );
                            drop(chain_guard);
                            drop(pool);
                            thread::sleep(Duration::from_millis(100));
                            continue;
                        }

                        let target_epoch =
                            Self::epoch_for_next_block(latest_block.block_index, epoch_length);
                        if current_epoch < target_epoch {
                            let next_epoch = current_epoch.saturating_add(1);
                            info!(
                                "consensus",
                                "Preparing pending epoch transition before block production",
                                "current_epoch" => current_epoch,
                                "next_epoch" => next_epoch,
                                "target_epoch" => target_epoch,
                                "latest_height" => latest_block.block_index
                            );
                            let previous_qc = match Self::get_previous_quorum_certificate(
                                &chain_guard,
                                next_epoch,
                                epoch_length,
                                &validator_manager,
                            ) {
                                Ok(qc) => qc,
                                Err(error) => {
                                    warn!(
                                        "consensus",
                                        "Refusing epoch transition without the finalized boundary QC",
                                        "current_epoch" => current_epoch,
                                        "next_epoch" => next_epoch,
                                        "latest_height" => latest_block.block_index,
                                        "error" => error
                                    );
                                    drop(chain_guard);
                                    drop(pool);
                                    thread::sleep(Duration::from_millis(250));
                                    continue;
                                }
                            };
                            let closing_epoch_validators = validator_manager.get_active_validators();
                            let closing_epoch_randomness =
                                match Self::deterministic_epoch_randomness_for_epoch(
                                    &chain_guard,
                                    current_epoch,
                                    epoch_length,
                                    &validator_manager,
                                ) {
                                    Ok(randomness) => randomness,
                                    Err(error) => {
                                        warn!(
                                            "consensus",
                                            "Refusing epoch transition without canonical closing-epoch randomness",
                                            "current_epoch" => current_epoch,
                                            "next_epoch" => next_epoch,
                                            "latest_height" => latest_block.block_index,
                                            "error" => error
                                        );
                                        drop(chain_guard);
                                        drop(pool);
                                        thread::sleep(Duration::from_millis(250));
                                        continue;
                                    }
                                };
                            let finalized_scores = match Self::finalized_synergy_scores_for_epoch(
                                &chain_guard,
                                current_epoch,
                                epoch_length,
                                &closing_epoch_validators,
                                &closing_epoch_randomness,
                            ) {
                                Ok(scores) => scores,
                                Err(error) => {
                                    warn!(
                                        "consensus",
                                        "Refusing epoch transition without a complete finalized Synergy score snapshot",
                                        "current_epoch" => current_epoch,
                                        "next_epoch" => next_epoch,
                                        "latest_height" => latest_block.block_index,
                                        "error" => error
                                    );
                                    drop(chain_guard);
                                    drop(pool);
                                    thread::sleep(Duration::from_millis(250));
                                    continue;
                                }
                            };
                            if let Err(error) = validator_manager
                                .apply_finalized_synergy_scores(&finalized_scores)
                            {
                                warn!(
                                    "consensus",
                                    "Refusing epoch transition because finalized Synergy scores could not be applied",
                                    "current_epoch" => current_epoch,
                                    "next_epoch" => next_epoch,
                                    "error" => error
                                );
                                drop(chain_guard);
                                drop(pool);
                                thread::sleep(Duration::from_millis(250));
                                continue;
                            }
                            info!(
                                "consensus",
                                "Applying pending epoch transition before block production",
                                "current_epoch" => current_epoch,
                                "next_epoch" => next_epoch,
                                "target_epoch" => target_epoch,
                                "latest_height" => latest_block.block_index,
                                "previous_qc_block_hash" => previous_qc.block_hash.clone()
                            );
                            let latest_height = latest_block.block_index;
                            drop(pool);
                            if Self::emergency_stable_committee_mode_enabled() {
                                drop(chain_guard);
                                let closing_epoch = current_epoch;
                                let closing_epoch_validators =
                                    validator_manager.get_active_validators();
                                current_epoch = next_epoch;
                                if let Ok(mut consensus) = dual_quorum_consensus.lock() {
                                    consensus.current_epoch = current_epoch;
                                }
                                Self::run_epoch_reward_lifecycle_for_boundary(
                                    closing_epoch,
                                    current_epoch,
                                    latest_height,
                                    &closing_epoch_validators,
                                );
                                info!(
                                    "consensus",
                                    "Emergency stable committee mode held validator set fixed across epoch boundary",
                                    "current_epoch" => current_epoch,
                                    "latest_height" => latest_height,
                                    "previous_qc_block_hash" => previous_qc.block_hash.clone()
                                );
                            } else {
                                Self::handle_epoch_transition(
                                    &mut current_epoch,
                                    previous_qc,
                                    &validator_manager,
                                    &synergy_calculator,
                                    &dual_quorum_consensus,
                                    &entropy_beacon,
                                    &validator_rotation,
                                    &dao_governance,
                                    &cartel_detection,
                                    latest_height,
                                    &chain_guard,
                                );
                                drop(chain_guard);
                            }
                            thread::sleep(Duration::from_millis(100));
                            continue;
                        }

                        let next_block_index = latest_block.block_index.saturating_add(1);

                        // Get active validators, then reduce them to the authoritative
                        // height-specific consensus membership before leader or quorum
                        // math uses the set.
                        let registry_active_count = validator_manager.get_active_validators().len();
                        let active_validators = match Self::consensus_membership_for_next_block(
                            validator_manager.get_all_validators(),
                            latest_block.block_index,
                        ) {
                            Ok(validators) => validators,
                            Err(error) => {
                                warn!(
                                    "consensus",
                                    "Refusing block production because authoritative validator set for next height is unavailable",
                                    "next_block_height" => next_block_index,
                                    "error" => error
                                );
                                drop(chain_guard);
                                drop(pool);
                                thread::sleep(Duration::from_millis(250));
                                continue;
                            }
                        };
                        let consensus_active_count = active_validators.len();
                        let live_validator_addresses =
                            Self::collect_live_validator_addresses(&validator_manager);
                        let live_validator_address_set = live_validator_addresses
                            .iter()
                            .cloned()
                            .collect::<HashSet<_>>();
                        let live_active_validators: Vec<Validator> = active_validators
                            .iter()
                            .cloned()
                            .filter(|validator| {
                                live_validator_address_set.contains(&validator.address)
                            })
                            .collect();
                        consensus_log!(
                            "🔍 Found {} registry-active validators, {} consensus members, and {} live validator participants",
                            registry_active_count,
                            consensus_active_count,
                            live_active_validators.len()
                        );
                        let dynamic_quorum_validators =
                            required_validator_quorum(consensus_active_count).max(1);
                        let required_live_validators =
                            dynamic_quorum_validators.max(configured_min_validators);
                        let status_ready_required_validators = dynamic_quorum_validators
                            .max(configured_status_ready_min_validators);

                        if live_active_validators.len() < required_live_validators {
                            mesh_ready_since = None;
                            status_sync_grace_since = None;
                            genesis_status_gate_bypassed = false;
                            println!(
                                "⏳ Insufficient live validators for block production: {} live, {} consensus-active, {} registry-active, {} required by dynamic quorum.",
                                live_active_validators.len(),
                                consensus_active_count,
                                registry_active_count,
                                required_live_validators
                            );
                            drop(chain_guard);
                            drop(pool);
                            thread::sleep(Duration::from_secs(1));
                            continue;
                        }

                        if let Some(network) = crate::p2p::get_p2p_network() {
                            let status_ready_validators = live_active_validators.len();
                            if status_ready_gate_enabled {
                                let is_genesis_height = latest_block.block_index == 0;
                                if !is_genesis_height {
                                    genesis_status_gate_bypassed = false;
                                }
                                if status_ready_validators < status_ready_required_validators
                                    && !(is_genesis_height && genesis_status_gate_bypassed)
                                {
                                    match status_sync_grace_since {
                                        Some(grace_since)
                                            if allow_genesis_status_bypass
                                                && is_genesis_height
                                                && grace_since.elapsed()
                                                    >= Duration::from_secs(
                                                        status_ready_genesis_grace_secs,
                                                    ) =>
                                        {
                                            genesis_status_gate_bypassed = true;
                                            warn!(
                                                "consensus",
                                                "Bypassing validator mesh status gate at genesis after grace window",
                                                "live_validators" => live_active_validators.len() as u64,
                                                "status_ready_validators" => status_ready_validators as u64,
                                                "required_validators" => status_ready_required_validators as u64,
                                                "grace_secs" => status_ready_genesis_grace_secs
                                            );
                                            status_sync_grace_since = Some(grace_since);
                                        }
                                        Some(_) => {
                                            mesh_ready_since = None;
                                            info!(
                                                "consensus",
                                                "Waiting for validator mesh status sync before block production",
                                                "status_ready_validators" => status_ready_validators as u64,
                                                "required_validators" => status_ready_required_validators as u64,
                                                "grace_secs" => status_ready_genesis_grace_secs
                                            );
                                            drop(chain_guard);
                                            drop(pool);
                                            thread::sleep(Duration::from_secs(1));
                                            continue;
                                        }
                                        None => {
                                            status_sync_grace_since = Some(Instant::now());
                                            mesh_ready_since = None;
                                            info!(
                                                "consensus",
                                                "Waiting for validator mesh status sync before block production",
                                                "status_ready_validators" => status_ready_validators as u64,
                                                "required_validators" => status_ready_required_validators as u64,
                                                "grace_secs" => status_ready_genesis_grace_secs
                                            );
                                            drop(chain_guard);
                                            drop(pool);
                                            thread::sleep(Duration::from_secs(1));
                                            continue;
                                        }
                                    }
                                } else {
                                    status_sync_grace_since = None;
                                }
                            } else {
                                status_sync_grace_since = None;
                                genesis_status_gate_bypassed = false;
                            }

                            let required_sync_support =
                                status_ready_required_validators.saturating_sub(1).max(1);
                            let best_validator_height = network
                                .get_best_validator_peer_height_with_support(required_sync_support);
                            let local_height = latest_block.block_index;
                            if best_validator_height > local_height {
                                let mesh_was_ready = mesh_ready_since.is_some();
                                let live_active_validator_count = live_active_validators.len();
                                drop(chain_guard);
                                drop(pool);
                                let final_height = Self::sync_validator_to_network_tip(
                                    &network,
                                    local_height,
                                    best_validator_height,
                                    required_sync_support,
                                )
                                .ok();
                                let readiness_decision = Self::catchup_mesh_readiness_after_sync(
                                    local_height,
                                    best_validator_height,
                                    final_height,
                                    mesh_was_ready,
                                    live_active_validator_count,
                                    required_live_validators,
                                    status_ready_validators,
                                    status_ready_required_validators,
                                );
                                timing_trace::emit(
                                    "catchup_mesh_readiness_decision",
                                    serde_json::json!({
                                        "local_height": local_height,
                                        "best_validator_height": best_validator_height,
                                        "final_height": final_height,
                                        "catchup_depth": best_validator_height.saturating_sub(local_height),
                                        "mesh_was_ready": mesh_was_ready,
                                        "preserve_mesh_readiness": readiness_decision.preserve_mesh_readiness,
                                        "reset_pacing_anchor_to_now": readiness_decision.reset_pacing_anchor_to_now,
                                        "reason": readiness_decision.reason,
                                        "live_active_validators": live_active_validator_count as u64,
                                        "configured_min_validators": configured_min_validators as u64,
                                        "dynamic_quorum_validators": dynamic_quorum_validators as u64,
                                        "required_live_validators": required_live_validators as u64,
                                        "status_ready_validators": status_ready_validators as u64,
                                        "status_ready_required_validators": status_ready_required_validators as u64,
                                        "required_sync_support": required_sync_support as u64,
                                    }),
                                );
                                if readiness_decision.preserve_mesh_readiness {
                                    info!(
                                        "consensus",
                                        "Preserving validator mesh readiness after safe head catch-up",
                                        "local_height" => local_height,
                                        "best_validator_height" => best_validator_height,
                                        "final_height" => final_height.unwrap_or(0),
                                        "reason" => readiness_decision.reason
                                    );
                                } else {
                                    mesh_ready_since = None;
                                    status_sync_grace_since = None;
                                    if readiness_decision.reset_pacing_anchor_to_now {
                                        last_block_time = SystemTime::now();
                                    }
                                    info!(
                                        "consensus",
                                        "Resetting validator mesh readiness after catch-up",
                                        "local_height" => local_height,
                                        "best_validator_height" => best_validator_height,
                                        "final_height" => final_height.unwrap_or(0),
                                        "reason" => readiness_decision.reason
                                    );
                                }
                                continue;
                            }

                            match mesh_ready_since {
                                Some(ready_since)
                                    if ready_since.elapsed()
                                        >= Duration::from_secs(mesh_settle_secs) => {}
                                Some(_) => {
                                    info!(
                                        "consensus",
                                        "Validator mesh is settling before block production",
                                        "settle_secs" => mesh_settle_secs
                                    );
                                    drop(chain_guard);
                                    drop(pool);
                                    thread::sleep(Duration::from_millis(500));
                                    continue;
                                }
                                None => {
                                    mesh_ready_since = Some(Instant::now());
                                    info!(
                                        "consensus",
                                        "Validator mesh reached quorum; beginning settle window",
                                        "settle_secs" => mesh_settle_secs
                                    );
                                    drop(chain_guard);
                                    drop(pool);
                                    thread::sleep(Duration::from_millis(500));
                                    continue;
                                }
                            }
                        } else {
                            mesh_ready_since = None;
                            status_sync_grace_since = None;
                            drop(chain_guard);
                            drop(pool);
                            thread::sleep(Duration::from_secs(1));
                            continue;
                        }

                        consensus_log!(
                            "🎯 Selecting leader for block {}",
                            latest_block.block_index + 1
                        );

                        // Clone latest_block before we might need to drop the guard
                        let latest_block_clone = latest_block.clone();
                        // View changes must be derived from shared canonical state. Using
                        // each node's local tip-observation time lets validators pick
                        // different same-height leaders after a restart or partition, which
                        // recreates transient vote-lock splits at H+1.
                        let view_anchor_timestamp = latest_block_clone.timestamp;
                        let shared_view_offset =
                            Self::deterministic_view_offset_for_next_block_slot(
                                latest_block_clone.block_index,
                                view_anchor_timestamp,
                                block_time_secs,
                                leader_timeout_secs,
                                Self::current_timestamp(),
                            );
                        let calculated_view_offset = Self::cap_view_offset_by_tip_observation(
                            shared_view_offset,
                            last_tip_observed_at,
                            leader_timeout_secs,
                            current_time,
                        );
                        // The canonical timestamp supplies a fleet-shared timeout schedule, while
                        // the local tip-observation cap prevents a freshly caught-up validator
                        // from skipping views immediately. Do not pin this to zero: a scheduled
                        // leader can remain status-live while it is unable to propose, and a fixed
                        // primary view turns that condition into an unbounded chain stall.
                        let next_block_height = latest_block_clone.block_index.saturating_add(1);
                        let forced_view_offset = missed_quorum_view_override
                            .filter(|(height, _)| *height == next_block_height)
                            .map(|(_, offset)| offset)
                            .unwrap_or(0);
                        let view_offset = calculated_view_offset.max(forced_view_offset);
                        let transient_recovery_min_age_secs =
                            Self::transient_vote_recovery_min_age_secs(
                                leader_timeout_secs,
                                block_time_secs,
                            );

                        // Phase 1: Leader selection using entropy beacon and synergy scores
                        // Use next block index for leader selection (current block + 1)
                        // Rebuild leader rotation from the shared duty-active set. Quarantined
                        // and shadow validators remain registered/history-known, but they must
                        // not be scheduled as live proposers while their duties are disabled.
                        let epoch_randomness = match Self::deterministic_epoch_randomness(
                            &chain_guard,
                            next_block_index,
                            epoch_length,
                            &validator_manager,
                        ) {
                            Ok(randomness) => randomness,
                            Err(error) => {
                                warn!(
                                    "consensus",
                                    "Refusing leader selection without finalized epoch randomness",
                                    "next_block_height" => next_block_index,
                                    "error" => error
                                );
                                drop(chain_guard);
                                drop(pool);
                                thread::sleep(Duration::from_millis(250));
                                continue;
                            }
                        };
                        let local_validator_address = Self::resolve_local_validator_address();
                        // Leader scheduling must use the canonical consensus membership, not
                        // each node's locally visible peer subset. The live subset is still
                        // used above as a readiness gate; using it here lets nodes with 4 vs 5
                        // visible peers compute different proposer rotations for the same
                        // height and wait through avoidable leader timeouts.
                        let selected_validator = Self::select_leader_for_block(
                            &active_validators,
                            next_block_index,
                            &synergy_calculator,
                            &epoch_randomness,
                            epoch_length,
                            view_offset,
                        );
                        let selected_validator_live = live_active_validators
                            .iter()
                            .any(|validator| validator.address == selected_validator.address);
                        if !selected_validator_live {
                            warn!(
                                "consensus",
                                "Scheduled leader is not locally visible; preserving canonical leader selection",
                                "scheduled_leader" => selected_validator.address.clone(),
                                "live_validators" => live_active_validators.len() as u64,
                                "active_validators" => active_validators.len() as u64,
                                "block_height" => next_block_index,
                                "view_offset" => view_offset
                            );
                        }
                        let selected_validator = Self::select_live_leader_after_view_timeout(
                            selected_validator,
                            &active_validators,
                            &live_active_validators,
                            next_block_index,
                            &synergy_calculator,
                            &epoch_randomness,
                            epoch_length,
                            view_offset,
                        );
                        let selected_validator = Self::prefer_local_vote_lock_leader(
                            selected_validator,
                            &active_validators,
                            &live_active_validators,
                            local_validator_address.as_deref(),
                            current_epoch,
                            next_block_index,
                            next_block_index.saturating_sub(1),
                            transient_recovery_min_age_secs,
                        );

                        if local_validator_address.as_deref()
                            != Some(selected_validator.address.as_str())
                        {
                            if let Some(network) = crate::p2p::get_p2p_network() {
                                let required_sync_support =
                                    status_ready_required_validators.saturating_sub(1).max(1);
                                let local_height = latest_block_clone.block_index;
                                let fresh_best_validator_height = network
                                    .get_best_validator_peer_height_with_support(
                                        required_sync_support,
                                    );
                                if fresh_best_validator_height > local_height {
                                    info!(
                                        "consensus",
                                        "Skipping non-leader wait because validator peers advanced tip",
                                        "local_height" => local_height,
                                        "best_validator_height" => fresh_best_validator_height,
                                        "required_sync_support" => required_sync_support as u64,
                                        "leader" => selected_validator.address.clone(),
                                        "local_validator" => local_validator_address.clone().unwrap_or_default(),
                                        "block_height" => next_block_index
                                    );
                                    drop(chain_guard);
                                    drop(pool);
                                    let _ = Self::sync_validator_to_network_tip(
                                        &network,
                                        local_height,
                                        fresh_best_validator_height,
                                        required_sync_support,
                                    );
                                    thread::sleep(Duration::from_millis(100));
                                    continue;
                                }
                            }

                            let wait_elapsed =
                                Self::leader_wait_elapsed_since_tip_observed(last_tip_observed_at);

                            if wait_elapsed >= Duration::from_secs(leader_timeout_secs) {
                                let timeout_marker = (next_block_index, view_offset);
                                if last_logged_view_timeout != Some(timeout_marker) {
                                    warn!(
                                        "consensus",
                                        "Leader proposal timeout — following shared leader rotation",
                                        "timed_out_leader" => selected_validator.address.clone(),
                                        "shared_view_offset" => view_offset,
                                        "waited_secs" => wait_elapsed.as_secs(),
                                        "block_height" => next_block_index
                                    );
                                    // Timeout penalties are intentionally skipped here.
                                    // They mutate validator-local health state, and applying
                                    // them independently on each node causes the validator
                                    // set to drift while the chain is stalled.
                                    let _ = penalization_enabled;
                                    last_logged_view_timeout = Some(timeout_marker);
                                }
                            } else {
                                debug!(
                                    "consensus",
                                    "Local validator is not the scheduled leader; waiting for remote proposal",
                                    "leader" => selected_validator.address.clone(),
                                    "local_validator" => local_validator_address.unwrap_or_default(),
                                    "visible_validators" => live_active_validators.len() as u64
                                );
                            }
                            drop(chain_guard);
                            drop(pool);
                            thread::sleep(Duration::from_millis(250));
                            continue;
                        }

                        consensus_log!("LEADER SELECTED: {}", selected_validator.address);
                        consensus_log!("Getting transactions from pool...");
                        let proposal_build_started = Instant::now();
                        let target_next_slot_timestamp =
                            latest_block_clone.timestamp.saturating_add(block_time_secs);
                        let network_peer_count = crate::p2p::get_p2p_network()
                            .map(|network| network.get_peer_count())
                            .unwrap_or(0);
                        let quarantine_block =
                            crate::consensus::anti_divergence::current_validator_quarantine_duty_block();
                        let vote_only_rejoin = Self::local_vote_only_rejoin_active();
                        let self_quarantined = quarantine_block.is_some() || vote_only_rejoin;
                        if let Some(quarantine_block) = quarantine_block {
                            warn!(
                                "consensus",
                                "Local validator is quarantined; skipping proposer duties",
                                "chosen_proposer" => selected_validator.address.clone(),
                                "local_validator" => local_validator_address.clone().unwrap_or_default(),
                                "height" => next_block_index,
                                "local_view_round" => view_offset,
                                "quarantine_height" => quarantine_block.divergence_height.0,
                                "quarantine_source" => quarantine_block.source.clone(),
                                "reason" => quarantine_block.reason.clone()
                            );
                            timing_trace::emit(
                                "proposal_build_blocked_by_self_quarantine",
                                serde_json::json!({
                                    "previous_block_height": latest_block_clone.block_index,
                                    "previous_block_hash": latest_block_clone.hash.clone(),
                                    "height": next_block_index,
                                    "chosen_proposer": selected_validator.address.clone(),
                                    "local_validator": local_validator_address.clone(),
                                    "local_view_round": view_offset,
                                    "effective_leader_timeout_secs": leader_timeout_secs,
                                    "effective_vote_timeout_secs": vote_timeout_secs,
                                    "proposer_quarantined": true,
                                    "duties_disabled": true,
                                    "quarantine_height": quarantine_block.divergence_height.0,
                                    "quarantine_source": quarantine_block.source,
                                    "quarantine_reason": quarantine_block.reason
                                }),
                            );
                            drop(chain_guard);
                            drop(pool);
                            thread::sleep(Duration::from_millis(250));
                            continue;
                        }
                        if vote_only_rejoin {
                            warn!(
                                "consensus",
                                "Local validator is in vote-only probation; skipping proposer duties",
                                "chosen_proposer" => selected_validator.address.clone(),
                                "local_validator" => local_validator_address.clone().unwrap_or_default(),
                                "height" => next_block_index,
                                "local_view_round" => view_offset
                            );
                            timing_trace::emit(
                                "proposal_build_blocked_by_vote_only_rejoin",
                                serde_json::json!({
                                    "previous_block_height": latest_block_clone.block_index,
                                    "previous_block_hash": latest_block_clone.hash.clone(),
                                    "height": next_block_index,
                                    "chosen_proposer": selected_validator.address.clone(),
                                    "local_validator": local_validator_address.clone(),
                                    "local_view_round": view_offset,
                                    "effective_leader_timeout_secs": leader_timeout_secs,
                                    "effective_vote_timeout_secs": vote_timeout_secs,
                                    "proposer_quarantined": false,
                                    "duties_disabled": false,
                                    "vote_only_rejoin": true
                                }),
                            );
                            drop(chain_guard);
                            drop(pool);
                            thread::sleep(Duration::from_millis(250));
                            continue;
                        }
                        timing_trace::emit(
                            "proposal_build_start",
                            serde_json::json!({
                                "previous_block_height": latest_block_clone.block_index,
                                "previous_block_hash": latest_block_clone.hash.clone(),
                                "previous_block_timestamp": latest_block_clone.timestamp,
                                "height": next_block_index,
                                "target_next_slot_timestamp": target_next_slot_timestamp,
                                "chosen_proposer": selected_validator.address.clone(),
                                "local_validator": local_validator_address.clone(),
                                "local_view_round": view_offset,
                                "effective_leader_timeout_secs": leader_timeout_secs,
                                "effective_vote_timeout_secs": vote_timeout_secs,
                                "network_peer_count": network_peer_count,
                                "proposer_online": live_validator_address_set.contains(&selected_validator.address),
                                "proposer_current": local_validator_address.as_deref() == Some(selected_validator.address.as_str()),
                                "proposer_quarantined": self_quarantined,
                                "relayer_rpc_lag": serde_json::Value::Null,
                                "relayer_rpc_lag_unavailable_reason": "not_available_inside_validator_consensus_loop"
                            }),
                        );

                        let confirmed_hashes = chain_guard
                            .chain
                            .iter()
                            .flat_map(|block| {
                                block
                                    .transactions
                                    .iter()
                                    .map(|transaction| transaction.hash())
                            })
                            .collect::<HashSet<_>>();
                        let transactions = if pool.is_empty() {
                            consensus_log!("Pool is empty");
                            vec![]
                        } else {
                            let pending = pool
                                .iter()
                                .filter(|transaction| {
                                    !confirmed_hashes.contains(&transaction.hash())
                                })
                                .cloned()
                                .collect::<Vec<_>>();
                            consensus_log!(
                                "Pool has {} transactions ({} eligible after confirmed-tx pruning)",
                                pool.len(),
                                pending.len()
                            );
                            pending
                        };
                        drop(pool);
                        drop(chain_guard);

                        consensus_log!("Creating processed transactions vec...");
                        let mut processed_transactions = Vec::new();
                        let mut rejected_transaction_hashes = HashSet::new();

                        consensus_log!("Processing {} transactions...", transactions.len());
                        // Process transactions with full validation
                        for tx in &transactions {
                            if Self::validate_transaction(tx, &pqc_manager) {
                                processed_transactions.push(tx.clone());

                                // Update wallet nonce
                            } else {
                                rejected_transaction_hashes.insert(tx.hash());
                                println!(
                                    "❌ Invalid transaction from {}: failed validation",
                                    tx.sender
                                );
                            }
                        }
                        if !rejected_transaction_hashes.is_empty() {
                            let pruned_rejected_transactions =
                                prune_transaction_hashes_from_pool(&rejected_transaction_hashes);
                            warn!(
                                "consensus",
                                "Pruned consensus-rejected transactions from pool",
                                "rejected_count" => rejected_transaction_hashes.len() as u64,
                                "pruned_count" => pruned_rejected_transactions as u64
                            );
                        }

                        consensus_log!(
                            "Creating block proposal with {} processed transactions...",
                            processed_transactions.len()
                        );
                        use std::io::{self, Write};
                        io::stdout().flush().unwrap();

                        let dag_vertex_hash = crate::dag::create_proposal_vertex_for_transactions(
                            &processed_transactions,
                            &selected_validator.address,
                            next_block_index,
                        );
                        if let Some(hash) = &dag_vertex_hash {
                            info!(
                                "consensus",
                                "Created DAG proposal vertex",
                                "height" => next_block_index,
                                "vertex_hash" => hash.clone(),
                                "transactions" => processed_transactions.len() as u64,
                                "validator" => selected_validator.address.clone()
                            );
                        }

                        // Phase 2: Block proposal
                        consensus_log!("Calling create_block_proposal...");
                        io::stdout().flush().unwrap();
                        let new_block = Self::create_block_proposal(
                            &latest_block_clone,
                            &selected_validator,
                            processed_transactions,
                            block_time_secs,
                            &pqc_manager,
                        );
                        timing_trace::emit(
                            "proposal_built",
                            serde_json::json!({
                                "previous_block_height": latest_block_clone.block_index,
                                "previous_block_hash": latest_block_clone.hash.clone(),
                                "previous_block_timestamp": latest_block_clone.timestamp,
                                "height": new_block.block_index,
                                "block_hash": new_block.hash.clone(),
                                "block_timestamp": new_block.timestamp,
                                "target_next_slot_timestamp": target_next_slot_timestamp,
                                "chosen_proposer": selected_validator.address.clone(),
                                "local_validator": local_validator_address.clone(),
                                "local_view_round": view_offset,
                                "transactions": new_block.transactions.len(),
                                "duration_ms": timing_trace::duration_ms(proposal_build_started.elapsed())
                            }),
                        );
                        consensus_log!("Block proposal created!");
                        io::stdout().flush().unwrap();

                        // Phase 3: Dual-quorum consensus
                        consensus_log!("Starting dual-quorum consensus...");
                        io::stdout().flush().unwrap();

                        info!("consensus", "Starting dual-quorum consensus",
                              "block_height" => new_block.block_index,
                              "block_hash" => new_block.hash.clone(),
                              "epoch" => current_epoch,
                              "validator" => selected_validator.address.clone());

                        let dual_quorum_started = Instant::now();
                        timing_trace::emit(
                            "dual_quorum_start",
                            serde_json::json!({
                                "previous_block_height": latest_block_clone.block_index,
                                "previous_block_hash": latest_block_clone.hash.clone(),
                                "previous_block_timestamp": latest_block_clone.timestamp,
                                "height": new_block.block_index,
                                "block_hash": new_block.hash.clone(),
                                "block_timestamp": new_block.timestamp,
                                "target_next_slot_timestamp": target_next_slot_timestamp,
                                "chosen_proposer": selected_validator.address.clone(),
                                "local_validator": local_validator_address.clone(),
                                "local_view_round": view_offset,
                                "effective_leader_timeout_secs": leader_timeout_secs,
                                "effective_vote_timeout_secs": vote_timeout_secs,
                                "network_peer_count": crate::p2p::get_p2p_network().map(|network| network.get_peer_count()).unwrap_or(0)
                            }),
                        );
                        let quorum_certificate = Self::execute_dual_quorum_consensus(
                            &new_block,
                            &validator_manager,
                            &dual_quorum_consensus,
                            current_epoch,
                            view_offset,
                            transient_recovery_min_age_secs,
                        );

                        consensus_log!("Dual-quorum consensus complete!");
                        io::stdout().flush().unwrap();

                        consensus_log!("Matching on quorum_certificate result...");
                        io::stdout().flush().unwrap();

                        match quorum_certificate {
                            Ok(qc) => {
                                timing_trace::emit(
                                    "dual_quorum_end",
                                    serde_json::json!({
                                        "previous_block_height": latest_block_clone.block_index,
                                        "previous_block_hash": latest_block_clone.hash.clone(),
                                        "previous_block_timestamp": latest_block_clone.timestamp,
                                        "height": new_block.block_index,
                                        "block_hash": new_block.hash.clone(),
                                        "block_timestamp": new_block.timestamp,
                                        "target_next_slot_timestamp": target_next_slot_timestamp,
                                        "chosen_proposer": selected_validator.address.clone(),
                                        "local_validator": local_validator_address.clone(),
                                        "local_view_round": view_offset,
                                        "vote_count": qc.votes.len(),
                                        "signature_count": qc.votes.len(),
                                        "qc_timestamp": qc.timestamp,
                                        "duration_ms": timing_trace::duration_ms(dual_quorum_started.elapsed()),
                                        "status": "ok"
                                    }),
                                );
                                if let Err(error) =
                                    Self::verify_legacy_precommit(&new_block, &qc, current_epoch)
                                {
                                    timing_trace::emit(
                                        "rejected_proposal",
                                        serde_json::json!({
                                            "height": new_block.block_index,
                                            "block_hash": new_block.hash.clone(),
                                            "previous_hash": new_block.previous_hash.clone(),
                                            "chosen_proposer": selected_validator.address.clone(),
                                            "local_validator": local_validator_address.clone(),
                                            "local_view_round": view_offset,
                                            "reason": error.clone()
                                        }),
                                    );
                                    warn!(
                                        "consensus",
                                        "Rejecting committed block before local finalization",
                                        "height" => new_block.block_index,
                                        "hash" => new_block.hash.clone(),
                                        "error" => error
                                    );
                                    continue;
                                }
                                if let Err(error) = verify_legacy_canonical_lock(&new_block) {
                                    timing_trace::emit(
                                        "rejected_proposal",
                                        serde_json::json!({
                                            "height": new_block.block_index,
                                            "block_hash": new_block.hash.clone(),
                                            "previous_hash": new_block.previous_hash.clone(),
                                            "chosen_proposer": selected_validator.address.clone(),
                                            "local_validator": local_validator_address.clone(),
                                            "local_view_round": view_offset,
                                            "reason": error.clone()
                                        }),
                                    );
                                    warn!(
                                        "consensus",
                                        "Rejecting committed block because it conflicts with canonical lock",
                                        "height" => new_block.block_index,
                                        "hash" => new_block.hash.clone(),
                                        "error" => error
                                    );
                                    continue;
                                }
                                if let Err(error) =
                                    Self::validate_finalized_validator_activations(
                                        &new_block,
                                        TOKEN_MANAGER.as_ref(),
                                        &validator_manager,
                                    )
                                {
                                    timing_trace::emit(
                                        "rejected_proposal",
                                        serde_json::json!({
                                            "height": new_block.block_index,
                                            "block_hash": new_block.hash.clone(),
                                            "previous_hash": new_block.previous_hash.clone(),
                                            "chosen_proposer": selected_validator.address.clone(),
                                            "local_validator": local_validator_address.clone(),
                                            "local_view_round": view_offset,
                                            "reason": error.clone(),
                                            "validator_activation_preflight": true
                                        }),
                                    );
                                    warn!(
                                        "consensus",
                                        "Rejecting committed block before durable finalization because validator activation preflight failed",
                                        "height" => new_block.block_index,
                                        "hash" => new_block.hash.clone(),
                                        "error" => error
                                    );
                                    continue;
                                }

                                // Block committed - update chain.
                                // Reset view-change state: the chain has advanced, so the next
                                // block starts with the primary scheduled leader again.
                                last_logged_view_timeout = None;
                                missed_quorum_view_override = None;

                                let mut block_appended_to_local_tip = false;
                                let commit_started = Instant::now();
                                timing_trace::emit(
                                    "block_commit_start",
                                    serde_json::json!({
                                        "previous_block_height": latest_block_clone.block_index,
                                        "previous_block_hash": latest_block_clone.hash.clone(),
                                        "previous_block_timestamp": latest_block_clone.timestamp,
                                        "height": new_block.block_index,
                                        "block_hash": new_block.hash.clone(),
                                        "block_timestamp": new_block.timestamp,
                                        "target_next_slot_timestamp": target_next_slot_timestamp,
                                        "chosen_proposer": selected_validator.address.clone(),
                                        "local_validator": local_validator_address.clone(),
                                        "local_view_round": view_offset,
                                        "vote_count": qc.votes.len(),
                                        "signature_count": qc.votes.len(),
                                        "qc_timestamp": qc.timestamp
                                    }),
                                );
                                let persist_snapshot = {
                                    let mut chain_guard = chain.lock().unwrap();
                                    match chain_guard.add_block_extending_tip(new_block.clone()) {
                                        Ok(true) => {
                                            if let Err(error) =
                                                append_committed_block_body(&new_block)
                                            {
                                                warn!(
                                                    "consensus",
                                                    "Durable committed block body write failed before canonical lock",
                                                    "height" => new_block.block_index,
                                                    "hash" => new_block.hash.clone(),
                                                    "error" => error
                                                );
                                                process::exit(1);
                                            }
                                            if let Err(error) =
                                                DualQuorumConsensus::record_committed_qc_checked(
                                                    qc.clone(),
                                                )
                                            {
                                                warn!(
                                                    "consensus",
                                                    "Durable committed QC write failed before canonical lock",
                                                    "height" => new_block.block_index,
                                                    "hash" => new_block.hash.clone(),
                                                    "error" => error
                                                );
                                                process::exit(1);
                                            }
                                            if let Err(error) =
                                                write_legacy_canonical_lock(&new_block, &qc)
                                            {
                                                warn!(
                                                    "consensus",
                                                    "Canonical lock write failed after local commit",
                                                    "height" => new_block.block_index,
                                                    "hash" => new_block.hash.clone(),
                                                    "error" => error
                                                );
                                                process::exit(1);
                                            }
                                            cache_last_known_good_chain_tip(&new_block);
                                            block_appended_to_local_tip = true;
                                        }
                                        Ok(false) => {
                                            info!(
                                                "consensus",
                                                "Committed block was already applied to local tip",
                                                "height" => new_block.block_index,
                                                "hash" => new_block.hash.clone()
                                            );
                                        }
                                        Err(error) => {
                                            timing_trace::emit(
                                                "rejected_proposal",
                                                serde_json::json!({
                                                    "height": new_block.block_index,
                                                    "block_hash": new_block.hash.clone(),
                                                    "previous_hash": new_block.previous_hash.clone(),
                                                    "chosen_proposer": selected_validator.address.clone(),
                                                    "local_validator": local_validator_address.clone(),
                                                    "local_view_round": view_offset,
                                                    "reason": error.clone(),
                                                    "fail_closed_same_height_supersede": true
                                                }),
                                            );
                                            warn!(
                                                "consensus",
                                                "Skipping stale committed block that no longer extends local tip",
                                                "height" => new_block.block_index,
                                                "hash" => new_block.hash.clone(),
                                                "error" => error
                                            );
                                        }
                                    }

                                    if !block_appended_to_local_tip {
                                        None
                                    } else {
                                        let tip_height = chain_guard
                                            .last()
                                            .map(|block| block.block_index)
                                            .unwrap_or(new_block.block_index);
                                        if Self::should_persist_consensus_chain_tip(tip_height) {
                                            Self::note_consensus_chain_persist(tip_height);
                                            if Self::can_clone_consensus_chain_for_snapshot(
                                                tip_height,
                                            ) {
                                                let snapshot = chain_guard.clone();
                                                Some((snapshot, tip_height))
                                            } else {
                                                None
                                            }
                                        } else {
                                            None
                                        }
                                    }
                                };
                                if !block_appended_to_local_tip {
                                    continue;
                                }
                                if let Some((snapshot, tip_height)) = persist_snapshot {
                                    Self::persist_consensus_chain_tip_async(snapshot, tip_height);
                                }
                                let committed_dag_vertices = crate::dag::commit_block(&new_block);
                                Self::prune_cached_block_proposals(new_block.block_index);

                                // Apply state transitions for included transactions (token transfers, staking, etc.)
                                let token_manager = TOKEN_MANAGER.clone();
                                let mut applied_txs = 0u64;
                                let mut failed_txs = 0u64;
                                for tx in &new_block.transactions {
                                    match token_manager
                                        .process_transaction_in_finalized_block_with_fee_market(
                                            tx,
                                            new_block.block_index,
                                            &new_block.hash,
                                            new_block.applied_fee_market_base_fee(),
                                        )
                                    {
                                        Ok(_) => applied_txs += 1,
                                        Err(e) => {
                                            failed_txs += 1;
                                            warn!(
                                                "consensus",
                                                "Failed to apply transaction state",
                                                "tx_hash" => tx.hash(),
                                                "error" => e
                                            );
                                        }
                                    }
                                }

                                let applied_validator_activations =
                                    match Self::apply_finalized_validator_activations(
                                        &new_block,
                                        &token_manager,
                                        &validator_manager,
                                    ) {
                                        Ok(activations) => {
                                            for (tx_hash, message) in &activations {
                                                info!(
                                                    "consensus",
                                                    "Applied validator activation",
                                                    "tx_hash" => tx_hash.clone(),
                                                    "message" => message.clone()
                                                );
                                            }
                                            activations.len() as u64
                                        }
                                        Err(error) => {
                                            let quarantine_reason = format!(
                                                "fail-closed validator activation application: {error}"
                                            );
                                            match crate::consensus::anti_divergence::
                                                record_self_quarantine_for_canonical_lock_conflict(
                                                    new_block.block_index,
                                                    Some(new_block.hash.clone()),
                                                    &new_block.hash,
                                                    &quarantine_reason,
                                                ) {
                                                Ok(record) => {
                                                    warn!(
                                                        "consensus",
                                                        "Validator activation application failed after finalization; self-quarantined and terminating",
                                                        "height" => new_block.block_index,
                                                        "tx_hash" => new_block.hash.clone(),
                                                        "quarantine_height" => record.divergence_height.0,
                                                        "error" => error
                                                    );
                                                    process::exit(1);
                                                }
                                                Err(quarantine_error) => {
                                                    warn!(
                                                        "consensus",
                                                        "Validator activation failure could not be persisted as quarantine; terminating",
                                                        "height" => new_block.block_index,
                                                        "error" => error,
                                                        "quarantine_error" => quarantine_error
                                                    );
                                                    process::exit(1);
                                                }
                                            }
                                        }
                                    };

                                if let Err(e) = crate::sts::note_finalized_sts_block(
                                    new_block.block_index,
                                    &new_block.hash,
                                ) {
                                    warn!("consensus", "Failed to persist finalized STS state", "error" => e.to_string());
                                }

                                // Persist token state for explorer continuity across restarts (best-effort).
                                if let Err(e) =
                                    token_manager.save_state(crate::token::token_state_path())
                                {
                                    warn!("consensus", "Failed to persist token state", "error" => e.to_string());
                                }
                                let activated_validators = validator_manager
                                    .apply_pending_shadow_activations(new_block.block_index);
                                if applied_validator_activations > 0
                                    || !activated_validators.is_empty()
                                {
                                    if let Err(e) =
                                        validator_manager.save_registry(VALIDATOR_REGISTRY_PATH)
                                    {
                                        let error = format!(
                                            "validator registry persistence failed after finalized activation at height {}: {}",
                                            new_block.block_index,
                                            e
                                        );
                                        let quarantine_reason =
                                            format!("fail-closed validator state persistence: {error}");
                                        match crate::consensus::anti_divergence::
                                            record_self_quarantine_for_canonical_lock_conflict(
                                                new_block.block_index,
                                                Some(new_block.hash.clone()),
                                                &new_block.hash,
                                                &quarantine_reason,
                                            ) {
                                            Ok(record) => {
                                                warn!(
                                                    "consensus",
                                                    "Validator registry persistence failed after finalization; self-quarantined and terminating",
                                                    "height" => new_block.block_index,
                                                    "quarantine_height" => record.divergence_height.0,
                                                    "error" => error
                                                );
                                                process::exit(1);
                                            }
                                            Err(quarantine_error) => {
                                                warn!(
                                                    "consensus",
                                                    "Validator registry persistence failure could not be quarantined; terminating",
                                                    "height" => new_block.block_index,
                                                    "error" => error,
                                                    "quarantine_error" => quarantine_error
                                                );
                                                process::exit(1);
                                            }
                                        }
                                    }
                                    if !activated_validators.is_empty() {
                                        info!(
                                            "consensus",
                                            "Activated shadow validators after finalized boundary",
                                            "height" => new_block.block_index,
                                            "activated_validators" => activated_validators.join(",")
                                        );
                                    }
                                }

                                // Broadcast the committed block to peers (best-effort).
                                if let Some(p2p) = crate::p2p::get_p2p_network() {
                                    p2p.broadcast_committed_block(&new_block, &qc);
                                }

                                // Validator health metrics and reward payouts are currently
                                // node-local bookkeeping. Mutating
                                // them here makes persisted state diverge even when every
                                // validator commits the same block hash. Keep them out of
                                // the live validator path until they are applied through a
                                // shared state transition.
                                info!("consensus", "Skipped local validator bookkeeping",
                                      "validator" => selected_validator.address.clone(),
                                      "mode" => "shared-state-only");

                                // Record vote for cartel detection
                                Self::record_vote_for_cartel_detection(
                                    &cartel_detection,
                                    &selected_validator.address,
                                    new_block.block_index,
                                    true,
                                    Self::current_timestamp(),
                                    epoch_length,
                                );

                                // Check for governance proposals
                                Self::check_governance_proposals(
                                    &dao_governance,
                                    new_block.block_index,
                                );

                                let confirmed_hashes = transaction_hashes(&new_block.transactions);
                                let pruned_transactions =
                                    prune_transaction_hashes_from_pool(&confirmed_hashes);

                                last_tip_observed_at = SystemTime::now();
                                last_block_time = Self::next_block_pacing_anchor_for_time(
                                    new_block.timestamp,
                                    block_time_secs,
                                    last_tip_observed_at,
                                );
                                let next_proposal_eligibility =
                                    last_block_time + Duration::from_secs(block_time_secs);
                                timing_trace::emit(
                                    "block_committed_timing",
                                    serde_json::json!({
                                        "previous_block_height": latest_block_clone.block_index,
                                        "previous_block_hash": latest_block_clone.hash.clone(),
                                        "previous_block_timestamp": latest_block_clone.timestamp,
                                        "height": new_block.block_index,
                                        "block_hash": new_block.hash.clone(),
                                        "block_timestamp": new_block.timestamp,
                                        "target_next_slot_timestamp": target_next_slot_timestamp,
                                        "chosen_proposer": selected_validator.address.clone(),
                                        "local_validator": local_validator_address.clone(),
                                        "local_view_round": view_offset,
                                        "effective_leader_timeout_secs": leader_timeout_secs,
                                        "effective_vote_timeout_secs": vote_timeout_secs,
                                        "vote_count": qc.votes.len(),
                                        "signature_count": qc.votes.len(),
                                        "qc_timestamp": qc.timestamp,
                                        "commit_duration_ms": timing_trace::duration_ms(commit_started.elapsed()),
                                        "elapsed_since_proposal_build_start_ms": timing_trace::duration_ms(proposal_build_started.elapsed()),
                                        "block_commit_time_ms": timing_trace::now_unix_ms(),
                                        "next_proposal_eligibility_time_ms": timing_trace::system_time_ms(next_proposal_eligibility),
                                        "network_peer_count": crate::p2p::get_p2p_network().map(|network| network.get_peer_count()).unwrap_or(0),
                                        "relayer_rpc_lag": serde_json::Value::Null,
                                        "relayer_rpc_lag_unavailable_reason": "not_available_inside_validator_consensus_loop"
                                    }),
                                );
                                timing_trace::emit(
                                    "block_commit_end",
                                    serde_json::json!({
                                        "previous_block_height": latest_block_clone.block_index,
                                        "previous_block_hash": latest_block_clone.hash.clone(),
                                        "previous_block_timestamp": latest_block_clone.timestamp,
                                        "height": new_block.block_index,
                                        "block_hash": new_block.hash.clone(),
                                        "block_timestamp": new_block.timestamp,
                                        "target_next_slot_timestamp": target_next_slot_timestamp,
                                        "chosen_proposer": selected_validator.address.clone(),
                                        "local_validator": local_validator_address.clone(),
                                        "local_view_round": view_offset,
                                        "vote_count": qc.votes.len(),
                                        "signature_count": qc.votes.len(),
                                        "qc_timestamp": qc.timestamp,
                                        "commit_duration_ms": timing_trace::duration_ms(commit_started.elapsed()),
                                        "elapsed_since_proposal_build_start_ms": timing_trace::duration_ms(proposal_build_started.elapsed()),
                                        "next_proposal_eligibility_time_ms": timing_trace::system_time_ms(next_proposal_eligibility)
                                    }),
                                );
                                consecutive_failures = 0;

                                // Get synergy score components for detailed logging
                                let synergy_components =
                                    synergy_calculator.calculate_synergy_score(&selected_validator);

                                // Get cluster info if available
                                let cluster_info = validator_manager
                                    .get_validator_cluster(&selected_validator.address)
                                    .map(|c| {
                                        serde_json::json!({
                                            "cluster_id": c.id,
                                            "cluster_size": c.validators.len(),
                                            "total_stake": c.total_stake,
                                            "average_synergy_score": c.average_synergy_score
                                        })
                                    });

                                info!(
                                    "consensus",
                                    "Block committed",
                                    "height" => new_block.block_index,
                                    "hash" => new_block.hash.clone(),
                                    "previous_hash" => new_block.previous_hash.clone(),
                                    "timestamp" => new_block.timestamp,
                                    "epoch" => current_epoch,
                                    "block_in_epoch" => block_position_in_epoch(new_block.block_index, epoch_length),
                                    "validator" => selected_validator.address.clone(),
                                    "validator_name" => selected_validator.name.clone(),
                                    "synergy_score" => format!("{:.2}", selected_validator.synergy_score),
                                    "synergy_score_components" => serde_json::json!({
                                        "stake_weight": synergy_components.stake_weight,
                                        "reputation": synergy_components.reputation,
                                        "contribution_index": synergy_components.contribution_index,
                                        "cartelization_penalty": synergy_components.cartelization_penalty,
                                        "normalized_score": synergy_components.normalized_score
                                    }).to_string(),
                                    "cluster_info" => cluster_info.as_ref().map(|c| c.to_string()).unwrap_or_default(),
                                    "txs" => new_block.transactions.len() as u64,
                                    "dag_vertices_committed" => committed_dag_vertices.len() as u64,
                                    "txs_pruned_from_pool" => pruned_transactions as u64,
                                    "txs_applied" => applied_txs,
                                    "txs_failed" => failed_txs,
                                    "qc_validation_quorum_met" => qc.validation_quorum_met,
                                    "qc_cooperation_quorum_met" => qc.cooperation_quorum_met,
                                    "qc_epoch_number" => qc.epoch_number,
                                    "qc_cumulative_weight" => qc.cumulative_weight,
                                    "qc_timestamp" => qc.timestamp
                                );
                            }
                            Err(e) => {
                                timing_trace::emit(
                                    "dual_quorum_end",
                                    serde_json::json!({
                                        "previous_block_height": latest_block_clone.block_index,
                                        "previous_block_hash": latest_block_clone.hash.clone(),
                                        "previous_block_timestamp": latest_block_clone.timestamp,
                                        "height": new_block.block_index,
                                        "block_hash": new_block.hash.clone(),
                                        "block_timestamp": new_block.timestamp,
                                        "target_next_slot_timestamp": target_next_slot_timestamp,
                                        "chosen_proposer": selected_validator.address.clone(),
                                        "local_validator": local_validator_address.clone(),
                                        "local_view_round": view_offset,
                                        "duration_ms": timing_trace::duration_ms(dual_quorum_started.elapsed()),
                                        "status": "error",
                                        "error": e.clone()
                                    }),
                                );
                                warn!("consensus", "QC error - block proposal failed", "error" => e.clone());
                                use std::io::{self, Write};
                                io::stdout().flush().unwrap();
                                println!("⚠️ Block proposal failed: {}", e);
                                consecutive_failures += 1;

                                let needs_missed_quorum_view_change =
                                    Self::consensus_failure_needs_missed_quorum_view_change(&e);
                                if Self::consensus_failure_needs_transient_lock_recovery(&e) {
                                    let finalized_height = new_block.block_index.saturating_sub(1);
                                    let min_age_secs = Self::transient_vote_recovery_min_age_secs(
                                        leader_timeout_secs,
                                        block_time_secs,
                                    );
                                    let reason = format!(
                                        "automatic consensus liveness recovery after transient same-height vote conflict at proposed_height={} proposed_hash={} consecutive_failures={consecutive_failures}: {e}",
                                        new_block.block_index, new_block.hash
                                    );
                                    match (
                                        DualQuorumConsensus::recover_transient_vote_locks_above_finalized_height(
                                            finalized_height,
                                            min_age_secs,
                                            &reason,
                                        ),
                                        Self::recover_cached_block_proposals_above_finalized_height(
                                            finalized_height,
                                            &reason,
                                        ),
                                    ) {
                                        (Ok(vote_report), Ok(proposal_report))
                                            if vote_report.mutated || proposal_report.mutated =>
                                        {
                                            warn!(
                                                "consensus",
                                                "Recovered stale transient consensus state above finalized head",
                                                "finalized_height" => finalized_height,
                                                "vote_locks_removed" => vote_report.removed_count as u64,
                                                "proposal_cache_archived" => proposal_report.archived_count as u64,
                                                "vote_lock_evidence" => vote_report.evidence_path.clone(),
                                                "proposal_evidence" => proposal_report.evidence_dir.clone()
                                            );
                                            last_logged_view_timeout = None;
                                            if needs_missed_quorum_view_change {
                                                let next_view_offset = view_offset.saturating_add(1);
                                                missed_quorum_view_override =
                                                    Some((new_block.block_index, next_view_offset));
                                                last_tip_observed_at = SystemTime::now()
                                                    .checked_sub(Duration::from_secs(
                                                        leader_timeout_secs.max(1),
                                                    ))
                                                    .unwrap_or_else(SystemTime::now);
                                                last_block_time = SystemTime::now()
                                                    .checked_sub(Duration::from_secs(
                                                        block_time_secs.max(1),
                                                    ))
                                                    .unwrap_or_else(SystemTime::now);
                                                warn!(
                                                    "consensus",
                                                    "Advancing same-height view after missed quorum",
                                                    "height" => new_block.block_index,
                                                    "failed_view_offset" => view_offset as u64,
                                                    "next_view_offset" => next_view_offset as u64,
                                                    "error" => e.clone()
                                                );
                                            } else {
                                                last_tip_observed_at = SystemTime::now();
                                                last_block_time = SystemTime::now();
                                            }
                                            consecutive_failures = 0;
                                            thread::sleep(Duration::from_millis(500));
                                            continue;
                                        }
                                        (Ok(vote_report), Ok(proposal_report)) => {
                                            info!(
                                                "consensus",
                                                "Transient consensus recovery checked but no stale mutable state was eligible",
                                                "finalized_height" => finalized_height,
                                                "min_age_secs" => min_age_secs,
                                                "vote_locks_removed" => vote_report.removed_count as u64,
                                                "proposal_cache_archived" => proposal_report.archived_count as u64
                                            );
                                        }
                                        (Err(error), _) | (_, Err(error)) => {
                                            warn!(
                                                "consensus",
                                                "Automatic transient consensus recovery failed closed",
                                                "finalized_height" => finalized_height,
                                                "error" => error
                                            );
                                        }
                                    }
                                }
                                if needs_missed_quorum_view_change {
                                    let next_view_offset = view_offset.saturating_add(1);
                                    missed_quorum_view_override =
                                        Some((new_block.block_index, next_view_offset));
                                    last_tip_observed_at = SystemTime::now()
                                        .checked_sub(Duration::from_secs(leader_timeout_secs.max(1)))
                                        .unwrap_or_else(SystemTime::now);
                                    last_block_time = SystemTime::now()
                                        .checked_sub(Duration::from_secs(block_time_secs.max(1)))
                                        .unwrap_or_else(SystemTime::now);
                                    warn!(
                                        "consensus",
                                        "Advancing same-height view after missed quorum",
                                        "height" => new_block.block_index,
                                        "failed_view_offset" => view_offset as u64,
                                        "next_view_offset" => next_view_offset as u64,
                                        "error" => e.clone()
                                    );
                                    thread::sleep(Duration::from_millis(100));
                                    continue;
                                }

                                // Apply penalty to proposer for failed block
                                Self::maybe_apply_proposer_penalty(
                                    penalization_enabled,
                                    &validator_manager,
                                    &selected_validator.address,
                                );
                            }
                        }
                    } else {
                        consecutive_failures += 1;
                        if consecutive_failures > 10 {
                            println!("⚠️ No genesis block found. Please check blockchain initialization.");
                            thread::sleep(Duration::from_secs(block_time_secs));
                        }
                    }
                }

                thread::sleep(Duration::from_millis(100));
            }
            })
            .expect("failed to spawn Proof of Synergy consensus worker");
    }

    fn sync_validator_to_network_tip(
        network: &Arc<P2PNetwork>,
        local_height: u64,
        best_validator_height: u64,
        required_sync_support: usize,
    ) -> Result<u64, String> {
        info!(
            "consensus",
            "Starting validator catch-up sync before block production",
            "local_height" => local_height,
            "best_validator_height" => best_validator_height,
            "required_sync_support" => required_sync_support as u64
        );

        let sync_result = {
            let mut manager = SYNC_MANAGER.lock().unwrap();
            manager.attach_network(Arc::clone(network));
            manager
                .start_sync()
                .map(|_| manager.local_height)
                .map_err(|error| error.to_string())
        };

        match &sync_result {
            Ok(final_height) => {
                info!(
                    "consensus",
                    "Validator catch-up sync completed",
                    "starting_height" => local_height,
                    "best_validator_height" => best_validator_height,
                    "final_height" => *final_height
                );
            }
            Err(error) => {
                warn!(
                    "consensus",
                    "Validator catch-up sync failed",
                    "local_height" => local_height,
                    "best_validator_height" => best_validator_height,
                    "error" => error.clone()
                );
            }
        }

        sync_result
    }

    fn catchup_mesh_readiness_after_sync(
        local_height: u64,
        best_validator_height: u64,
        final_height: Option<u64>,
        mesh_was_ready: bool,
        live_active_validators: usize,
        required_live_validators: usize,
        status_ready_validators: usize,
        status_ready_required_validators: usize,
    ) -> CatchupReadinessDecision {
        if best_validator_height <= local_height {
            return CatchupReadinessDecision::reset("no_catchup_required");
        }

        if !mesh_was_ready {
            return CatchupReadinessDecision::reset("mesh_not_previously_ready");
        }

        let catchup_depth = best_validator_height.saturating_sub(local_height);
        if catchup_depth > SAFE_HEAD_CATCHUP_WITHOUT_MESH_RESET_BLOCKS {
            return CatchupReadinessDecision::reset("deep_catchup");
        }

        let Some(final_height) = final_height else {
            return CatchupReadinessDecision::reset("catchup_failed_or_unverified");
        };

        if final_height < best_validator_height {
            return CatchupReadinessDecision::reset("catchup_did_not_reach_verified_head");
        }

        if live_active_validators < required_live_validators {
            return CatchupReadinessDecision::reset("insufficient_live_validators");
        }

        if status_ready_validators < status_ready_required_validators {
            return CatchupReadinessDecision::reset("insufficient_status_ready_validators");
        }

        CatchupReadinessDecision::preserve("safe_one_block_head_catchup")
    }

    fn initialize_baseline_validators(validator_manager: &Arc<ValidatorManager>) {
        println!("🔧 INITIALIZE_BASELINE_VALIDATORS CALLED - START");
        match canonical_genesis() {
            Ok(genesis) => {
                println!(
                    "🔧 Found {} baseline validators",
                    genesis.validators().len()
                );
                for validator in genesis.validators() {
                    let address = validator.operator_address.as_str();
                    let registration = crate::validator::ValidatorRegistration {
                        address: validator.operator_address.clone(),
                        public_key: validator.consensus_public_key.clone(),
                        name: validator.moniker.clone(),
                        stake_amount: validator.stake_nwei,
                        submitted_at: Self::current_timestamp(),
                        registration_tx_hash: "genesis".to_string(),
                    };

                    if validator_manager.get_validator(address).is_none() {
                        match validator_manager.register_validator(registration) {
                            Ok(_) => {
                                if let Err(error) = validator_manager.approve_validator(address) {
                                    println!(
                                        "⚠️ Failed to approve baseline validator {}: {}",
                                        address, error
                                    );
                                    continue;
                                }
                                println!(
                                    "✅ Baseline validator {} registered and approved",
                                    address
                                );
                            }
                            Err(error) => {
                                println!(
                                    "⚠️ Failed to register baseline validator {}: {}",
                                    address, error
                                );
                                continue;
                            }
                        }
                    }

                    validator_manager.update_validator_stake(address, validator.stake_nwei);
                }
            }
            Err(error) => {
                println!(
                    "⚠️ Failed to load baseline validators from canonical genesis: {}",
                    error
                );
            }
        }
        println!("🔧 INITIALIZE_BASELINE_VALIDATORS CALLED - END");
    }

    fn resolve_local_validator_address() -> Option<String> {
        crate::config::resolve_runtime_validator_address()
    }

    fn consensus_membership_for_next_block(
        registry_active_validators: Vec<Validator>,
        latest_block_height: u64,
    ) -> Result<Vec<Validator>, String> {
        consensus_membership_validators_for_height(
            registry_active_validators,
            latest_block_height.saturating_add(1),
        )
    }

    fn collect_live_validator_addresses(validator_manager: &Arc<ValidatorManager>) -> Vec<String> {
        let active_validator_addresses =
            consensus_membership_validators(validator_manager.get_active_validators())
                .into_iter()
                .map(|validator| validator.address)
                .collect::<HashSet<_>>();
        let mut live_validator_addresses = HashSet::new();

        let local_duties_disabled =
            crate::consensus::anti_divergence::current_validator_quarantine_duty_block().is_some();
        if !local_duties_disabled {
            if let Some(local_validator_address) = Self::resolve_local_validator_address() {
                if active_validator_addresses.contains(&local_validator_address) {
                    live_validator_addresses.insert(local_validator_address);
                }
            }
        }

        if let Some(network) = crate::p2p::get_p2p_network() {
            for validator_address in network.get_status_ready_validator_addresses() {
                if active_validator_addresses.contains(&validator_address) {
                    live_validator_addresses.insert(validator_address);
                }
            }
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|duration| duration.as_secs())
                .unwrap_or(0);
            for peer in network.collect_peer_snapshots() {
                if peer.quarantined || peer.consensus_duties_disabled {
                    continue;
                }
                if peer.genesis_hash.trim().is_empty() || peer.status_received_at.is_none() {
                    continue;
                }
                if now.saturating_sub(peer.last_seen) > 30 {
                    continue;
                }
                let Some(validator_address) = peer
                    .validator_address
                    .as_deref()
                    .map(str::trim)
                    .filter(|address| !address.is_empty())
                else {
                    continue;
                };
                if active_validator_addresses.contains(validator_address) {
                    live_validator_addresses.insert(validator_address.to_string());
                }
            }
        }

        let mut live_validator_addresses = live_validator_addresses.into_iter().collect::<Vec<_>>();
        live_validator_addresses.sort();
        live_validator_addresses
    }

    fn emergency_stable_committee_mode_enabled() -> bool {
        if let Ok(value) = std::env::var("SYNERGY_EMERGENCY_STABLE_COMMITTEE_MODE") {
            return matches!(
                value.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "y" | "on"
            );
        }
        crate::config::load_node_config(None)
            .ok()
            .map(|config| {
                config.consensus.emergency_stable_committee_mode
                    && config.consensus.freeze_validator_set
                    && config.consensus.freeze_score_weighted_proposer_order
            })
            .unwrap_or(true)
    }

    fn local_vote_only_rejoin_active() -> bool {
        let path = crate::utils::resolve_data_path("data/self_heal_status.json");
        let Ok(bytes) = fs::read(path) else {
            return false;
        };
        let Ok(value) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
            return false;
        };
        ["typed_status", "new_state", "recovery_state", "status"]
            .iter()
            .filter_map(|key| value.get(*key).and_then(|item| item.as_str()))
            .any(|state| {
                matches!(
                    state.trim().to_ascii_uppercase().as_str(),
                    "VOTE_ONLY" | "VOTEONLY"
                )
            })
            || value
                .get("vote_only_rejoin")
                .and_then(|item| item.as_bool())
                .unwrap_or(false)
    }

    fn ensure_baseline_validator_stakes(validator_manager: &Arc<ValidatorManager>) {
        println!("🔧 ENSURING_BASELINE_VALIDATOR_STAKES - START");
        match canonical_genesis() {
            Ok(genesis) => {
                for validator in genesis.validators() {
                    let address = validator.operator_address.as_str();
                    if validator_manager.get_validator(address).is_none() {
                        let registration = crate::validator::ValidatorRegistration {
                            address: validator.operator_address.clone(),
                            public_key: validator.consensus_public_key.clone(),
                            name: validator.moniker.clone(),
                            stake_amount: validator.stake_nwei,
                            submitted_at: Self::current_timestamp(),
                            registration_tx_hash: "genesis".to_string(),
                        };

                        match validator_manager.register_validator(registration) {
                            Ok(_) => {
                                if let Err(error) = validator_manager.approve_validator(address) {
                                    println!(
                                        "⚠️ Failed to approve late-joined baseline validator {}: {}",
                                        address, error
                                    );
                                    continue;
                                }
                                println!(
                                    "✅ Late-joined baseline validator {} registered and approved",
                                    address
                                );
                            }
                            Err(error) => {
                                println!(
                                    "⚠️ Failed to register late-joined baseline validator {}: {}",
                                    address, error
                                );
                                continue;
                            }
                        }
                    }

                    validator_manager.update_validator_stake(address, validator.stake_nwei);
                }
            }
            Err(error) => {
                println!("⚠️ Failed to ensure baseline validator stakes: {}", error);
            }
        }
        println!("🔧 ENSURING_BASELINE_VALIDATOR_STAKES - END");
    }

    fn load_synergy_scores() -> Option<SynergyScores> {
        let scores_path = "data/synergy_scores.json";
        if std::path::Path::new(scores_path).exists() {
            if let Ok(contents) = std::fs::read_to_string(scores_path) {
                if let Ok(scores) = serde_json::from_str::<SynergyScores>(&contents) {
                    return Some(scores);
                }
            }
        }
        None
    }

    fn current_timestamp() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    fn system_time_from_unix_timestamp(timestamp: u64) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(timestamp)
    }

    fn bounded_consensus_timestamp(
        previous_block_timestamp_secs: u64,
        block_time_secs: u64,
        current_timestamp_secs: u64,
    ) -> u64 {
        let target_timestamp = previous_block_timestamp_secs.saturating_add(block_time_secs.max(1));

        // The block timestamp is user-facing launch metadata as well as a
        // consensus input. Preserve normal cadence when production is healthy,
        // but reanchor to wall time after stalls or recovery work. Stepping by
        // a synthetic catch-up chunk (for example 300 seconds per block) makes
        // wall-clock block production look broken even after consensus has
        // recovered.
        target_timestamp.max(current_timestamp_secs)
    }

    fn next_block_pacing_anchor(block_timestamp_secs: u64, block_time_secs: u64) -> SystemTime {
        Self::next_block_pacing_anchor_for_time(
            block_timestamp_secs,
            block_time_secs,
            SystemTime::now(),
        )
    }

    fn next_block_pacing_anchor_for_time(
        block_timestamp_secs: u64,
        block_time_secs: u64,
        current_time: SystemTime,
    ) -> SystemTime {
        let block_time = Duration::from_secs(block_time_secs.max(1));
        let block_anchor = Self::system_time_from_unix_timestamp(block_timestamp_secs);
        let desired_next_proposal = block_anchor + block_time;
        let earliest_safe_next_proposal =
            current_time + Duration::from_millis(POST_COMMIT_PARENT_PROPAGATION_GRACE_MILLIS);

        if desired_next_proposal >= earliest_safe_next_proposal {
            return block_anchor;
        }

        earliest_safe_next_proposal
            .checked_sub(block_time)
            .unwrap_or(current_time)
    }

    fn leader_wait_elapsed_since_tip_observed(last_tip_observed_at: SystemTime) -> Duration {
        Self::leader_wait_elapsed_since_tip_observed_at(last_tip_observed_at, SystemTime::now())
    }

    fn leader_wait_elapsed_since_tip_observed_at(
        last_tip_observed_at: SystemTime,
        current_time: SystemTime,
    ) -> Duration {
        current_time
            .duration_since(last_tip_observed_at)
            .unwrap_or_default()
    }

    fn cap_view_offset_by_tip_observation(
        shared_view_offset: usize,
        last_tip_observed_at: SystemTime,
        leader_timeout_secs: u64,
        current_time: SystemTime,
    ) -> usize {
        let local_elapsed =
            Self::leader_wait_elapsed_since_tip_observed_at(last_tip_observed_at, current_time);
        let local_view_offset = (local_elapsed.as_secs() / leader_timeout_secs.max(1)) as usize;
        shared_view_offset.min(local_view_offset)
    }

    fn should_persist_consensus_chain_tip(tip_height: u64) -> bool {
        if tip_height <= 32 {
            return true;
        }

        let gap_blocks = Self::consensus_chain_persist_gap_blocks();
        let elapsed_secs = Self::consensus_chain_persist_elapsed_secs();
        let state = LAST_CONSENSUS_CHAIN_PERSIST.lock().unwrap();
        match *state {
            Some((last_height, last_at)) => {
                tip_height.saturating_sub(last_height) >= gap_blocks
                    || last_at.elapsed() >= Duration::from_secs(elapsed_secs)
            }
            None => tip_height % gap_blocks == 0,
        }
    }

    fn consensus_chain_persist_gap_blocks() -> u64 {
        std::env::var("SYNERGY_CHAIN_PERSIST_GAP_BLOCKS")
            .ok()
            .and_then(|value| value.trim().parse::<u64>().ok())
            .filter(|value| *value > 0)
            .unwrap_or(250)
    }

    fn consensus_chain_persist_elapsed_secs() -> u64 {
        std::env::var("SYNERGY_CHAIN_PERSIST_MIN_SECS")
            .ok()
            .and_then(|value| value.trim().parse::<u64>().ok())
            .filter(|value| *value > 0)
            .unwrap_or(600)
    }

    fn consensus_chain_snapshot_max_clone_height() -> u64 {
        std::env::var("SYNERGY_CHAIN_SNAPSHOT_MAX_CLONE_HEIGHT")
            .ok()
            .and_then(|value| value.trim().parse::<u64>().ok())
            .filter(|value| *value > 0)
            .unwrap_or(DEFAULT_MAX_CHAIN_SNAPSHOT_CLONE_HEIGHT)
    }

    fn consensus_chain_snapshot_clone_allowed(tip_height: u64, max_clone_height: u64) -> bool {
        tip_height <= max_clone_height
    }

    fn can_clone_consensus_chain_for_snapshot(tip_height: u64) -> bool {
        let max_clone_height = Self::consensus_chain_snapshot_max_clone_height();
        if Self::consensus_chain_snapshot_clone_allowed(tip_height, max_clone_height) {
            return true;
        }

        warn!(
            "consensus",
            "Skipping full-chain snapshot persistence because chain height exceeds clone safety limit",
            "height" => tip_height,
            "max_clone_height" => max_clone_height,
            "override_env" => "SYNERGY_CHAIN_SNAPSHOT_MAX_CLONE_HEIGHT"
        );
        false
    }

    fn note_consensus_chain_persist(tip_height: u64) {
        let mut state = LAST_CONSENSUS_CHAIN_PERSIST.lock().unwrap();
        *state = Some((tip_height, Instant::now()));
    }

    fn persist_consensus_chain_tip_async(snapshot: BlockChain, tip_height: u64) {
        if CONSENSUS_CHAIN_PERSIST_IN_FLIGHT
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            debug!(
                "consensus",
                "Skipping chain persistence because a previous save is still running",
                "height" => tip_height
            );
            return;
        }

        let chain_path = get_chain_path();
        thread::Builder::new()
            .name("chain-persist".to_string())
            .spawn(move || {
                snapshot.save_to_file(&chain_path);
                CONSENSUS_CHAIN_PERSIST_IN_FLIGHT.store(false, Ordering::SeqCst);
            })
            .expect("failed to spawn chain persistence worker");
    }

    fn effective_leader_timeout_secs(&self) -> u64 {
        Self::effective_leader_timeout_secs_for_config(
            self.block_time,
            self.leader_timeout_secs,
            self.vote_timeout_secs,
        )
    }

    fn effective_leader_timeout_secs_for_config(
        block_time_secs: u64,
        configured_leader_timeout_secs: u64,
        configured_vote_timeout_secs: u64,
    ) -> u64 {
        let block_time_secs = block_time_secs.max(1);
        let vote_timeout_secs = configured_vote_timeout_secs
            .max(1)
            .max(MIN_LAUNCH_VOTE_TIMEOUT_SECS);
        let min_timeout_covering_vote_window = vote_timeout_secs
            .saturating_add(block_time_secs)
            .max(block_time_secs.saturating_mul(2).max(2));

        if configured_leader_timeout_secs == 0 {
            min_timeout_covering_vote_window
        } else {
            configured_leader_timeout_secs.max(min_timeout_covering_vote_window)
        }
    }

    // New PoSy Helper Methods

    fn epoch_for_block(block_index: u64, epoch_length: u64) -> u64 {
        epoch_for_block_height(block_index, epoch_length)
    }

    fn epoch_for_next_block(last_block_index: u64, epoch_length: u64) -> u64 {
        Self::epoch_for_block(last_block_index.saturating_add(1), epoch_length)
    }

    fn deterministic_view_offset_for_next_block_slot(
        last_block_index: u64,
        last_block_timestamp: u64,
        block_time_secs: u64,
        leader_timeout_secs: u64,
        current_timestamp: u64,
    ) -> usize {
        // Genesis has no committed in-network clock yet. Deriving the initial view
        // offset from each node's wall clock causes different validators to rotate to
        // different leaders before block 1 exists, so keep the primary leader fixed
        // until the first block commits and provides a fresh shared timestamp anchor.
        if last_block_index == 0 {
            return 0;
        }

        // View timeout starts when the next block is actually due, not at the
        // previous block timestamp. Otherwise normal target cadence plus PQC
        // vote propagation consumes the primary leader's timeout budget and
        // causes unnecessary same-height view changes on a healthy chain.
        let next_block_slot_timestamp = last_block_timestamp.saturating_add(block_time_secs.max(1));
        Self::deterministic_view_offset_for_time(
            next_block_slot_timestamp,
            leader_timeout_secs,
            current_timestamp,
        )
    }

    fn deterministic_view_offset_for_time(
        last_block_timestamp: u64,
        leader_timeout_secs: u64,
        current_timestamp: u64,
    ) -> usize {
        let timeout_secs = leader_timeout_secs.max(1);
        let elapsed_secs = current_timestamp.saturating_sub(last_block_timestamp);

        (elapsed_secs / timeout_secs) as usize
    }

    fn run_epoch_reward_lifecycle_for_boundary(
        closing_epoch: u64,
        next_epoch: u64,
        transition_block_height: u64,
        closing_epoch_validators: &[Validator],
    ) {
        match TOKEN_MANAGER.run_epoch_reward_lifecycle(
            closing_epoch,
            next_epoch,
            transition_block_height,
            closing_epoch_validators,
        ) {
            Ok(summary) => {
                info!(
                    "consensus",
                    "Epoch rewards lifecycle completed",
                    "closing_epoch" => summary.closing_epoch,
                    "next_epoch" => summary.next_epoch,
                    "settled_unlock_epoch" => summary.settled_unlock_epoch,
                    "transition_block_height" => summary.transition_block_height,
                    "total_fees_collected_nwei" => summary.total_fees_collected_nwei.to_string(),
                    "reward_allocation_recorded" => summary.reward_allocation.is_some(),
                    "settlement_count" => summary.settlements.len() as u64,
                    "skipped_reasons" => summary.skipped_reasons.join("; ")
                );
            }
            Err(error) => {
                warn!(
                    "consensus",
                    "Epoch rewards lifecycle failed",
                    "closing_epoch" => closing_epoch,
                    "next_epoch" => next_epoch,
                    "transition_block_height" => transition_block_height,
                    "error" => error
                );
            }
        }
    }

    fn handle_epoch_transition(
        current_epoch: &mut u64,
        previous_qc: QuorumCertificate,
        validator_manager: &Arc<ValidatorManager>,
        _synergy_calculator: &Arc<SynergyScoreCalculator>,
        dual_quorum_consensus: &Arc<Mutex<DualQuorumConsensus>>,
        _entropy_beacon: &Arc<Mutex<EntropyBeacon>>,
        _validator_rotation: &Arc<ValidatorRotation>,
        dao_governance: &Arc<Mutex<DAOGovernance>>,
        cartel_detection: &Arc<Mutex<CartelDetectionEngine>>,
        transition_block_height: u64,
        chain: &BlockChain,
    ) {
        let closing_epoch = *current_epoch;
        let closing_epoch_validators = validator_manager.get_active_validators();
        let next_epoch = current_epoch.saturating_add(1);

        // Before the fixed activation boundary, a new epoch transition must remain
        // v2-compatible with the existing fleet: verify/load the finalized boundary QC,
        // derive the legacy QC-hash seed, and persist it with the new epoch assignment.
        // Current-epoch reads use the persisted seed and never repeat this derivation.
        let leader_randomness = match Self::epoch_randomness_evidence_for_transition(
            chain,
            next_epoch,
            CANONICAL_TESTNET_EPOCH_LENGTH,
            validator_manager,
        ) {
            Ok(evidence) => evidence.randomness,
            Err(error) => {
                warn!(
                    "consensus",
                    "Refusing epoch transition without canonical boundary evidence",
                    "next_epoch" => next_epoch,
                    "transition_block_height" => transition_block_height,
                    "previous_qc_block_hash" => previous_qc.block_hash,
                    "error" => error
                );
                return;
            }
        };
        if let Err(error) =
            Self::persist_epoch_leader_randomness(validator_manager, next_epoch, &leader_randomness)
        {
            warn!(
                "consensus",
                "Refusing epoch transition because leader randomness could not be persisted",
                "next_epoch" => next_epoch,
                "transition_block_height" => transition_block_height,
                "error" => error
            );
            return;
        }
        let cluster_randomness = match Self::cluster_epoch_randomness_evidence(
            chain,
            next_epoch,
            CANONICAL_TESTNET_EPOCH_LENGTH,
            validator_manager,
        ) {
            Ok(evidence) => evidence.randomness,
            Err(error) => {
                warn!(
                    "consensus",
                    "Refusing epoch transition without canonical cluster boundary evidence",
                    "next_epoch" => next_epoch,
                    "transition_block_height" => transition_block_height,
                    "error" => error
                );
                return;
            }
        };

        *current_epoch = next_epoch;
        println!("🔄 Epoch Transition: Starting epoch {}", current_epoch);

        // Rebalance validator clusters from the canonical finalized-boundary seed.
        let cluster_randomness_source = hex::encode(cluster_randomness);
        if next_epoch == CLUSTER_RANDOMNESS_V3_ACTIVATION_EPOCH {
            match validator_manager.registry.lock() {
                Ok(mut registry) => registry.clear_cluster_assignments(),
                Err(_) => {
                    warn!(
                        "consensus",
                        "Refusing cluster-randomness cutover because the validator registry is unavailable",
                        "next_epoch" => next_epoch,
                        "transition_block_height" => transition_block_height
                    );
                    return;
                }
            }
        }
        validator_manager.reorganize_clusters_for_epoch_with_seed(
            *current_epoch,
            &cluster_randomness_source,
            epoch_start_height(*current_epoch, CANONICAL_TESTNET_EPOCH_LENGTH),
        );
        if let Err(error) = validator_manager.save_registry(VALIDATOR_REGISTRY_PATH) {
            warn!(
                "consensus",
                "Failed to save validator registry after epoch cluster shuffle",
                "epoch" => *current_epoch,
                "error" => error.to_string()
            );
        }

        Self::run_epoch_reward_lifecycle_for_boundary(
            closing_epoch,
            *current_epoch,
            transition_block_height,
            &closing_epoch_validators,
        );

        // 5. Detect cartels and apply penalties
        let mut cartel_engine = cartel_detection.lock().unwrap();
        let cartel_penalties = cartel_engine.detect_cartels(*current_epoch);
        cartel_engine.apply_cartel_penalties(&cartel_penalties);

        // 6. Update governance proposals
        let mut governance = dao_governance.lock().unwrap();
        Self::update_governance_proposals(&mut governance, *current_epoch);

        // 7. Reset dual quorum consensus state
        let mut consensus = dual_quorum_consensus.lock().unwrap();
        consensus.current_epoch = *current_epoch;

        println!("🔄 Epoch Transition: Completed epoch {}", current_epoch);
    }

    fn get_previous_quorum_certificate(
        chain: &BlockChain,
        current_epoch: u64,
        epoch_length: u64,
        validator_manager: &Arc<ValidatorManager>,
    ) -> Result<QuorumCertificate, String> {
        Self::finalized_boundary_block_and_qc(chain, current_epoch, epoch_length, validator_manager)
            .map(|(_block, qc)| qc)
    }

    fn finalized_boundary_block_and_qc(
        chain: &BlockChain,
        current_epoch: u64,
        epoch_length: u64,
        validator_manager: &Arc<ValidatorManager>,
    ) -> Result<(Block, QuorumCertificate), String> {
        let epoch_length = epoch_length.max(1);
        let boundary_height = current_epoch
            .checked_sub(1)
            .map(|closing_epoch| epoch_end_height(closing_epoch, epoch_length))
            .unwrap_or(0);

        let block = chain
            .chain
            .iter()
            .rev()
            .find(|block| block.block_index == boundary_height)
            .cloned()
            .ok_or_else(|| {
                format!("epoch {current_epoch} boundary block {boundary_height} is unavailable")
            })?;
        let mut qc = DualQuorumConsensus::committed_qcs_for_block_hashes([block.hash.as_str()])
            .into_iter()
            .next()
            .ok_or_else(|| {
                format!(
                    "finalized QC for epoch {current_epoch} boundary block {boundary_height} ({}) is unavailable",
                    block.hash
                )
            })?;
        let expected_epoch = epoch_for_block_height(block.block_index, epoch_length);
        let normalize_legacy_epoch = qc.epoch_number != expected_epoch;
        if normalize_legacy_epoch
            && !Self::is_migratable_legacy_boundary_epoch(
                block.block_index,
                epoch_length,
                qc.epoch_number,
            )
        {
            return Err(format!(
                "boundary QC epoch {} does not match block {} epoch {expected_epoch}",
                qc.epoch_number, block.block_index
            ));
        }

        DualQuorumConsensus::verify_commit_certificate_for_block_static(
            &block,
            &qc,
            validator_manager,
        )
        .map_err(|error| {
            format!(
                "boundary QC for block {} failed Aegis dual-quorum verification: {error}",
                block.block_index
            )
        })?;

        if normalize_legacy_epoch {
            qc.epoch_number = expected_epoch;
        }
        Ok((block, qc))
    }

    fn is_migratable_legacy_boundary_epoch(
        block_height: u64,
        epoch_length: u64,
        qc_epoch: u64,
    ) -> bool {
        let expected_epoch = epoch_for_block_height(block_height, epoch_length);
        block_height > 0
            && epoch_length == CANONICAL_TESTNET_EPOCH_LENGTH
            && block_height <= ONE_BASED_EPOCH_MIGRATION_CUTOFF_HEIGHT
            && block_height % CANONICAL_TESTNET_EPOCH_LENGTH == 0
            && qc_epoch == expected_epoch.saturating_add(1)
    }

    fn finalized_synergy_scores_for_epoch(
        chain: &BlockChain,
        epoch: u64,
        epoch_length: u64,
        validators: &[Validator],
        epoch_randomness: &[u8],
    ) -> Result<HashMap<String, u64>, String> {
        if validators.is_empty() {
            return Ok(HashMap::new());
        }
        let epoch_length = epoch_length.max(1);
        let epoch_start = epoch_start_height(epoch, epoch_length);
        let epoch_end = epoch_end_height(epoch, epoch_length);
        let mut blocks = chain
            .chain
            .iter()
            .filter(|block| block.block_index >= epoch_start && block.block_index <= epoch_end)
            .collect::<Vec<_>>();
        blocks.sort_by_key(|block| block.block_index);
        let expected_block_count = epoch_end.saturating_sub(epoch_start).saturating_add(1);
        if blocks.len() as u64 != expected_block_count {
            return Err(format!(
                "finalized score window {epoch_start}..={epoch_end} has {} block(s), expected {expected_block_count}",
                blocks.len()
            ));
        }
        for (offset, block) in blocks.iter().enumerate() {
            let expected_height = epoch_start.saturating_add(offset as u64);
            if block.block_index != expected_height {
                return Err(format!(
                    "finalized score window is missing block {expected_height}"
                ));
            }
        }

        let qcs = DualQuorumConsensus::committed_qcs_for_block_hashes(
            blocks.iter().map(|block| block.hash.as_str()),
        )
        .into_iter()
        .map(|qc| (qc.block_hash.clone(), qc))
        .collect::<HashMap<_, _>>();
        let mut opportunities = validators
            .iter()
            .map(|validator| (validator.address.clone(), 0u64))
            .collect::<HashMap<_, _>>();
        let mut successful_duties = opportunities.clone();

        for block in blocks {
            let qc = qcs.get(&block.hash).ok_or_else(|| {
                format!(
                    "finalized score window is missing the committed QC for block {} ({})",
                    block.block_index, block.hash
                )
            })?;
            if !qc.validation_quorum_met || !qc.cooperation_quorum_met {
                return Err(format!(
                    "block {} QC is not a finalized dual-quorum certificate",
                    block.block_index
                ));
            }
            let eligible =
                consensus_membership_validators_for_height(validators.to_vec(), block.block_index)?;
            if eligible.is_empty() {
                return Err(format!(
                    "block {} has no height-scoped consensus membership",
                    block.block_index
                ));
            }
            if !eligible
                .iter()
                .any(|validator| validator.address == block.validator_id)
            {
                return Err(format!(
                    "block {} proposer {} is outside the height-scoped consensus membership",
                    block.block_index, block.validator_id
                ));
            }
            let primary_leaders =
                Self::canonical_primary_leader_addresses(&eligible, epoch_randomness);
            let leader_index = block_position_in_epoch(block.block_index, epoch_length)
                .saturating_sub(1) as usize
                % primary_leaders.len();
            let assigned_leader = &primary_leaders[leader_index];
            *opportunities.entry(assigned_leader.clone()).or_default() += 1;
            if block.validator_id == *assigned_leader {
                *successful_duties
                    .entry(assigned_leader.clone())
                    .or_default() += 1;
            }
        }

        validators
            .iter()
            .map(|validator| {
                let assigned = opportunities[&validator.address];
                let score_bps = if assigned == 0 {
                    10_000
                } else {
                    ((successful_duties[&validator.address] as u128 * 10_000u128)
                        / assigned as u128) as u64
                };
                Ok((validator.address.clone(), score_bps))
            })
            .collect()
    }

    fn deterministic_epoch_randomness(
        chain: &BlockChain,
        block_height: u64,
        epoch_length: u64,
        validator_manager: &Arc<ValidatorManager>,
    ) -> Result<Vec<u8>, String> {
        let epoch_length = epoch_length.max(1);
        let current_epoch = epoch_for_block_height(block_height, epoch_length);
        Self::deterministic_epoch_randomness_for_epoch(
            chain,
            current_epoch,
            epoch_length,
            validator_manager,
        )
    }

    fn deterministic_epoch_randomness_for_epoch(
        chain: &BlockChain,
        next_epoch: u64,
        epoch_length: u64,
        validator_manager: &Arc<ValidatorManager>,
    ) -> Result<Vec<u8>, String> {
        Ok(Self::epoch_randomness_evidence_for_epoch(
            chain,
            next_epoch,
            epoch_length,
            validator_manager,
        )?
        .randomness)
    }

    fn boundary_hash_v3_active_for_epoch(next_epoch: u64, epoch_length: u64) -> bool {
        epoch_start_height(next_epoch, epoch_length.max(1)) >= EPOCH_RANDOMNESS_V3_ACTIVATION_HEIGHT
    }

    fn boundary_hash_cluster_v3_active_for_epoch(next_epoch: u64, epoch_length: u64) -> bool {
        epoch_start_height(next_epoch, epoch_length.max(1))
            >= CLUSTER_RANDOMNESS_V3_ACTIVATION_HEIGHT
    }

    pub(crate) fn epoch_randomness_evidence_for_epoch(
        chain: &BlockChain,
        next_epoch: u64,
        epoch_length: u64,
        validator_manager: &Arc<ValidatorManager>,
    ) -> Result<EpochRandomnessEvidence, String> {
        let epoch_length = epoch_length.max(1);
        let assignment_effective_height = epoch_start_height(next_epoch, epoch_length);

        if !Self::boundary_hash_v3_active_for_epoch(next_epoch, epoch_length) {
            if next_epoch == 0 {
                let genesis_hash = canonical_genesis()?.hash().to_string();
                let mut hasher = Sha3_512::new();
                hasher.update(LEGACY_EPOCH_ZERO_RANDOMNESS_DOMAIN.as_bytes());
                hasher.update(genesis_hash.as_bytes());
                return Ok(EpochRandomnessEvidence {
                    next_epoch,
                    boundary_height: Some(0),
                    boundary_block_hash: Some(genesis_hash),
                    boundary_qc_verified: false,
                    scheme: LEGACY_GENESIS_RANDOMNESS_SCHEME,
                    assignment_effective_height,
                    randomness: hasher.finalize().to_vec(),
                    registry_migrated: false,
                });
            }

            return Self::legacy_epoch_randomness_evidence_from_boundary(
                chain,
                next_epoch,
                epoch_length,
                assignment_effective_height,
                validator_manager,
            );
        }

        let boundary = Self::canonical_epoch_boundary_evidence(
            chain,
            next_epoch,
            epoch_length,
            validator_manager,
        )?;
        Ok(EpochRandomnessEvidence {
            next_epoch,
            boundary_height: Some(boundary.boundary_height),
            boundary_block_hash: Some(boundary.boundary_block_hash),
            boundary_qc_verified: true,
            scheme: BOUNDARY_HASH_RANDOMNESS_SCHEME,
            assignment_effective_height: boundary.assignment_effective_height,
            randomness: boundary.randomness,
            registry_migrated: false,
        })
    }

    pub(crate) fn cluster_epoch_randomness_evidence(
        chain: &BlockChain,
        next_epoch: u64,
        epoch_length: u64,
        validator_manager: &Arc<ValidatorManager>,
    ) -> Result<EpochRandomnessEvidence, String> {
        let epoch_length = epoch_length.max(1);
        if !Self::boundary_hash_cluster_v3_active_for_epoch(next_epoch, epoch_length) {
            if next_epoch == 0 {
                return Self::epoch_randomness_evidence_for_epoch(
                    chain,
                    next_epoch,
                    epoch_length,
                    validator_manager,
                );
            }
            return Self::legacy_cluster_epoch_randomness_evidence_from_boundary(
                chain,
                next_epoch,
                epoch_length,
                validator_manager,
            );
        }

        let boundary = Self::canonical_epoch_boundary_evidence(
            chain,
            next_epoch,
            epoch_length,
            validator_manager,
        )?;
        let randomness = Self::deterministic_epoch_randomness_from_boundary_with_domain(
            BOUNDARY_HASH_CLUSTER_RANDOMNESS_DOMAIN,
            1266,
            next_epoch,
            &boundary.boundary_block_hash,
        );
        Ok(EpochRandomnessEvidence {
            next_epoch,
            boundary_height: Some(boundary.boundary_height),
            boundary_block_hash: Some(boundary.boundary_block_hash),
            boundary_qc_verified: next_epoch > 0,
            scheme: BOUNDARY_HASH_CLUSTER_RANDOMNESS_SCHEME,
            assignment_effective_height: boundary.assignment_effective_height,
            randomness,
            registry_migrated: false,
        })
    }

    fn epoch_randomness_evidence_for_transition(
        chain: &BlockChain,
        next_epoch: u64,
        epoch_length: u64,
        validator_manager: &Arc<ValidatorManager>,
    ) -> Result<EpochRandomnessEvidence, String> {
        let epoch_length = epoch_length.max(1);
        let assignment_effective_height = epoch_start_height(next_epoch, epoch_length);
        if !Self::boundary_hash_v3_active_for_epoch(next_epoch, epoch_length) {
            if next_epoch == 0 {
                return Self::epoch_randomness_evidence_for_epoch(
                    chain,
                    next_epoch,
                    epoch_length,
                    validator_manager,
                );
            }

            return Self::legacy_epoch_randomness_evidence_from_boundary(
                chain,
                next_epoch,
                epoch_length,
                assignment_effective_height,
                validator_manager,
            );
        }

        let boundary = Self::canonical_epoch_boundary_evidence(
            chain,
            next_epoch,
            epoch_length,
            validator_manager,
        )?;
        Ok(EpochRandomnessEvidence {
            next_epoch,
            boundary_height: Some(boundary.boundary_height),
            boundary_block_hash: Some(boundary.boundary_block_hash),
            boundary_qc_verified: true,
            scheme: BOUNDARY_HASH_RANDOMNESS_SCHEME,
            assignment_effective_height: boundary.assignment_effective_height,
            randomness: boundary.randomness,
            registry_migrated: false,
        })
    }

    fn legacy_epoch_randomness_evidence_from_boundary(
        chain: &BlockChain,
        next_epoch: u64,
        epoch_length: u64,
        assignment_effective_height: u64,
        validator_manager: &Arc<ValidatorManager>,
    ) -> Result<EpochRandomnessEvidence, String> {
        let previous_qc = Self::get_previous_quorum_certificate(
            chain,
            next_epoch,
            epoch_length,
            validator_manager,
        )?;
        let randomness = Self::legacy_deterministic_epoch_randomness_from_qc(&previous_qc);
        let seed = hex::encode(&randomness);
        let registry_migrated = {
            let mut registry = validator_manager.registry.lock().map_err(|_| {
                "failed to lock validator registry while recovering the pre-activation epoch seed"
                    .to_string()
            })?;
            let changed = registry.leader_randomness_epoch != Some(next_epoch)
                || registry.leader_randomness_seed.as_deref() != Some(seed.as_str());
            if changed {
                registry.leader_randomness_epoch = Some(next_epoch);
                registry.leader_randomness_seed = Some(seed.clone());
            }
            changed
        };

        Ok(EpochRandomnessEvidence {
            next_epoch,
            boundary_height: Some(epoch_end_height(next_epoch.saturating_sub(1), epoch_length)),
            boundary_block_hash: Some(previous_qc.block_hash),
            boundary_qc_verified: true,
            scheme: LEGACY_QC_HASH_RANDOMNESS_SCHEME,
            assignment_effective_height,
            randomness,
            registry_migrated,
        })
    }

    fn legacy_cluster_epoch_randomness_evidence_from_boundary(
        chain: &BlockChain,
        next_epoch: u64,
        epoch_length: u64,
        validator_manager: &Arc<ValidatorManager>,
    ) -> Result<EpochRandomnessEvidence, String> {
        let previous_qc = match Self::get_previous_quorum_certificate(
            chain,
            next_epoch,
            epoch_length,
            validator_manager,
        ) {
            Ok(qc) => qc,
            Err(boundary_error) => {
                return Self::persisted_legacy_cluster_randomness_evidence(
                    next_epoch,
                    epoch_length,
                    validator_manager,
                )
                .map_err(|persisted_error| {
                    format!(
                        "{boundary_error}; persisted legacy cluster evidence is unavailable: {persisted_error}"
                    )
                });
            }
        };
        Ok(EpochRandomnessEvidence {
            next_epoch,
            boundary_height: Some(epoch_end_height(next_epoch.saturating_sub(1), epoch_length)),
            boundary_block_hash: Some(previous_qc.block_hash.clone()),
            boundary_qc_verified: true,
            scheme: LEGACY_CLUSTER_QC_HASH_RANDOMNESS_SCHEME,
            assignment_effective_height: epoch_start_height(next_epoch, epoch_length),
            randomness: Self::legacy_cluster_randomness_from_qc(&previous_qc),
            registry_migrated: false,
        })
    }

    fn persisted_legacy_cluster_randomness_evidence(
        next_epoch: u64,
        epoch_length: u64,
        validator_manager: &Arc<ValidatorManager>,
    ) -> Result<EpochRandomnessEvidence, String> {
        let assignment_effective_height = epoch_start_height(next_epoch, epoch_length);
        let registry = validator_manager.registry.lock().map_err(|_| {
            "failed to lock validator registry while reading persisted cluster evidence".to_string()
        })?;
        let active = registry
            .validators
            .values()
            .filter(|validator| validator.status == ValidatorStatus::Active)
            .collect::<Vec<_>>();
        if active.is_empty() {
            return Err("no active validators are persisted".to_string());
        }
        if active.iter().any(|validator| {
            validator.cluster_assignment_epoch != Some(next_epoch)
                || validator.cluster_assignment_effective_height
                    != Some(assignment_effective_height)
        }) {
            return Err(format!(
                "active validator assignments do not all match epoch {next_epoch} at height {assignment_effective_height}"
            ));
        }
        let seeds = active
            .iter()
            .filter_map(|validator| validator.cluster_assignment_seed.as_deref())
            .filter(|seed| !seed.trim().is_empty())
            .collect::<HashSet<_>>();
        if seeds.len() != 1 {
            return Err(format!(
                "active validator assignments contain {} distinct non-empty seeds, expected one",
                seeds.len()
            ));
        }
        let seed = seeds.into_iter().next().unwrap_or_default();
        let randomness = hex::decode(seed)
            .map_err(|error| format!("persisted cluster seed is malformed: {error}"))?;
        if randomness.len() != 64 {
            return Err(format!(
                "persisted cluster seed has {} bytes, expected 64",
                randomness.len()
            ));
        }
        Ok(EpochRandomnessEvidence {
            next_epoch,
            boundary_height: None,
            boundary_block_hash: None,
            boundary_qc_verified: false,
            scheme: LEGACY_PERSISTED_CLUSTER_RANDOMNESS_SCHEME,
            assignment_effective_height,
            randomness,
            registry_migrated: false,
        })
    }

    fn persist_epoch_leader_randomness(
        validator_manager: &Arc<ValidatorManager>,
        epoch: u64,
        randomness: &[u8],
    ) -> Result<(), String> {
        if randomness.len() != 64 {
            return Err(format!(
                "epoch {epoch} leader randomness has {} bytes, expected 64",
                randomness.len()
            ));
        }
        let mut registry = validator_manager.registry.lock().map_err(|_| {
            "failed to lock validator registry while persisting leader randomness".to_string()
        })?;
        registry.leader_randomness_epoch = Some(epoch);
        registry.leader_randomness_seed = Some(hex::encode(randomness));
        Ok(())
    }

    pub(crate) fn canonical_epoch_boundary_evidence(
        chain: &BlockChain,
        next_epoch: u64,
        epoch_length: u64,
        validator_manager: &Arc<ValidatorManager>,
    ) -> Result<CanonicalEpochBoundaryEvidence, String> {
        let epoch_length = epoch_length.max(1);
        let genesis = canonical_genesis()?;
        let chain_id = genesis.chain_id();
        if chain_id != 1266 {
            return Err(format!(
                "canonical epoch randomness requires testnet chain id 1266, found {chain_id}"
            ));
        }

        let (boundary_height, boundary_block_hash) = if next_epoch == 0 {
            (0, genesis.hash().to_string())
        } else {
            let boundary_height = epoch_end_height(next_epoch - 1, epoch_length);
            let (block, _qc) = Self::finalized_boundary_block_and_qc(
                chain,
                next_epoch,
                epoch_length,
                validator_manager,
            )?;
            if block.block_index != boundary_height {
                return Err(format!(
                    "canonical epoch boundary block height {} does not match expected {boundary_height}",
                    block.block_index
                ));
            }
            (boundary_height, block.hash)
        };

        let randomness = Self::deterministic_epoch_randomness_from_boundary(
            chain_id,
            next_epoch,
            &boundary_block_hash,
        );
        Ok(CanonicalEpochBoundaryEvidence {
            next_epoch,
            boundary_height,
            boundary_block_hash,
            assignment_effective_height: epoch_start_height(next_epoch, epoch_length),
            randomness,
        })
    }

    fn deterministic_epoch_randomness_from_boundary(
        chain_id: u64,
        next_epoch: u64,
        boundary_block_hash: &str,
    ) -> Vec<u8> {
        Self::deterministic_epoch_randomness_from_boundary_with_domain(
            BOUNDARY_HASH_LEADER_RANDOMNESS_DOMAIN,
            chain_id,
            next_epoch,
            boundary_block_hash,
        )
    }

    fn deterministic_epoch_randomness_from_boundary_with_domain(
        domain: &[u8],
        chain_id: u64,
        next_epoch: u64,
        boundary_block_hash: &str,
    ) -> Vec<u8> {
        let mut hasher = Sha3_512::new();
        hasher.update(domain);
        hasher.update(chain_id.to_be_bytes());
        hasher.update(next_epoch.to_be_bytes());
        hasher.update((boundary_block_hash.len() as u64).to_be_bytes());
        hasher.update(boundary_block_hash.as_bytes());
        hasher.finalize().to_vec()
    }

    fn legacy_deterministic_epoch_randomness_from_qc(previous_qc: &QuorumCertificate) -> Vec<u8> {
        let next_epoch = previous_qc.epoch_number.saturating_add(1);
        let qc_hash = Self::legacy_hash_quorum_certificate(previous_qc);
        let mut input = Vec::new();
        input.extend(next_epoch.to_be_bytes());
        input.extend(qc_hash.as_bytes());
        let mut hasher = Sha3_512::new();
        hasher.update(&input);
        hasher.finalize().to_vec()
    }

    fn legacy_cluster_randomness_from_qc(previous_qc: &QuorumCertificate) -> Vec<u8> {
        let next_epoch = previous_qc.epoch_number.saturating_add(1);
        let qc_hash = Self::legacy_cluster_hash_quorum_certificate(previous_qc);
        let mut input = Vec::new();
        input.extend(next_epoch.to_be_bytes());
        input.extend(qc_hash.as_bytes());
        let mut hasher = Sha3_512::new();
        hasher.update(&input);
        hasher.finalize().to_vec()
    }

    fn legacy_hash_quorum_certificate(qc: &QuorumCertificate) -> String {
        let mut hasher = Sha3_512::new();
        hasher.update(qc.block_hash.as_bytes());
        hasher.update(qc.epoch_number.to_be_bytes());
        hasher.update(qc.round_number.to_be_bytes());
        hasher.update(&qc.aggregate_signature);
        hasher.update(&qc.participant_bitmap);
        hasher.update([qc.validation_quorum_met as u8]);
        hasher.update([qc.cooperation_quorum_met as u8]);
        hex::encode(hasher.finalize())
    }

    fn legacy_cluster_hash_quorum_certificate(qc: &QuorumCertificate) -> String {
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
        hex::encode(hasher.finalize())
    }

    fn select_leader_for_block(
        validators: &[Validator],
        block_height: u64,
        _synergy_calculator: &Arc<SynergyScoreCalculator>,
        epoch_randomness: &[u8],
        epoch_length: u64,
        view_offset: usize,
    ) -> Validator {
        consensus_log!(
            "🔍 [select_leader_for_block] START - block_height: {}, validators: {}",
            block_height,
            validators.len()
        );

        if validators.is_empty() {
            println!("⚠️ [select_leader_for_block] No validators, returning bootstrap validator");
            return Validator::new(
                "synv1a2b3c4d5e6f7g8h9i0j1k2l3m4n5o6p7q8r9s0t1".to_string(),
                "genesis_key".to_string(),
                "Bootstrap Validator".to_string(),
                1000,
            );
        }

        // Calculate current epoch from configured epoch length.
        let current_epoch = epoch_for_block_height(block_height, epoch_length);
        let block_in_epoch = block_height.saturating_sub(1) % epoch_length;
        let mut candidate_addresses = validators
            .iter()
            .map(|validator| validator.address.clone())
            .collect::<Vec<_>>();
        candidate_addresses.sort();
        candidate_addresses.dedup();

        // Check if we need to recalculate leader priorities (at epoch start or if not initialized)
        let mut rotation = EPOCH_LEADER_ROTATION.lock().unwrap();
        let needs_recalculation = rotation.0 != current_epoch
            || rotation.1.is_empty()
            || rotation.3 != candidate_addresses;

        if needs_recalculation {
            consensus_log!(
                "🔄 [select_leader_for_block] Recalculating leader priorities for epoch {}",
                current_epoch
            );

            let stable_committee_mode = Self::emergency_stable_committee_mode_enabled();
            let top_k_addresses: Vec<String> = if stable_committee_mode {
                candidate_addresses.clone()
            } else {
                consensus_log!(
                    "🔄 [select_leader_for_block] Calculating priorities for {} validators",
                    validators.len()
                );
                Self::canonical_primary_leader_addresses(validators, epoch_randomness)
            };
            let k = top_k_addresses.len();

            info!("consensus", "Selected top K validators for epoch", 
                  "k" => k, 
                  "epoch" => current_epoch, 
                  "validators" => format!("{:?}", top_k_addresses));
            println!(
                "🏆 [select_leader_for_block] Selected top {} validators for epoch {}: {:?}",
                k, current_epoch, top_k_addresses
            );
            consensus_log!(
                "🏆 [select_leader_for_block] Selected top {} validators for epoch {}: {:?}",
                k,
                current_epoch,
                top_k_addresses
            );

            // Update rotation state
            rotation.0 = current_epoch;
            rotation.1 = top_k_addresses;
            rotation.2 = 0; // Reset index for new epoch
            rotation.3 = candidate_addresses;
        }

        // Use round-robin within epoch (PoSy: top K validators rotate).
        // view_offset is added so that when the primary leader times out, the next
        // candidate in the sorted list is tried without waiting for the next block.
        let rotation_index = (block_in_epoch as usize + view_offset) % rotation.1.len();
        let leader_address = rotation.1[rotation_index].clone();
        // Update stored index for logging/debugging.
        rotation.2 = rotation_index + 1;
        drop(rotation);

        // Find and return the selected validator
        let selected_validator = validators.iter()
            .find(|v| v.address == leader_address)
            .cloned()
            .unwrap_or_else(|| {
                // Fallback if validator not found (shouldn't happen)
                println!("⚠️ [select_leader_for_block] Selected leader {} not found, using first validator", leader_address);
                consensus_log!("⚠️ [select_leader_for_block] Selected leader {} not found, using first validator", leader_address);
                validators[0].clone()
            });

        info!("consensus", "Selected leader for block",
              "block_height" => block_height,
              "epoch" => current_epoch,
              "block_in_epoch" => block_in_epoch,
              "rotation_index" => rotation_index,
              "view_offset" => view_offset,
              "leader" => selected_validator.address.clone());
        println!("🏆 [select_leader_for_block] Selected leader for block {} (epoch {}, block_in_epoch {}, rotation_index {}): {}", 
                      block_height, current_epoch, block_in_epoch, rotation_index, selected_validator.address);
        consensus_log!(
            "🏆 [select_leader_for_block] Selected leader for block {} (epoch {}, block {}): {}",
            block_height,
            current_epoch,
            block_in_epoch,
            selected_validator.address
        );
        selected_validator
    }

    fn select_live_leader_after_view_timeout(
        selected_validator: Validator,
        active_validators: &[Validator],
        live_validators: &[Validator],
        block_height: u64,
        synergy_calculator: &Arc<SynergyScoreCalculator>,
        epoch_randomness: &[u8],
        epoch_length: u64,
        view_offset: usize,
    ) -> Validator {
        if view_offset == 0
            || live_validators.is_empty()
            || live_validators
                .iter()
                .any(|validator| validator.address == selected_validator.address)
        {
            return selected_validator;
        }

        for extra_offset in 1..=active_validators.len() {
            let candidate_view_offset = view_offset.saturating_add(extra_offset);
            let candidate = Self::select_leader_for_block(
                active_validators,
                block_height,
                synergy_calculator,
                epoch_randomness,
                epoch_length,
                candidate_view_offset,
            );
            if live_validators
                .iter()
                .any(|validator| validator.address == candidate.address)
            {
                warn!(
                    "consensus",
                    "Skipping non-live scheduled leader after shared view timeout",
                    "offline_scheduled_leader" => selected_validator.address.clone(),
                    "fallback_leader" => candidate.address.clone(),
                    "block_height" => block_height,
                    "view_offset" => view_offset,
                    "fallback_view_offset" => candidate_view_offset,
                    "live_validators" => live_validators.len() as u64,
                    "active_validators" => active_validators.len() as u64
                );
                return candidate;
            }
        }

        selected_validator
    }

    fn stable_leader_weight(validators: &[Validator], validator: &Validator) -> f64 {
        let total_stake = validators
            .iter()
            .map(|candidate| candidate.stake_amount)
            .sum::<u64>()
            .max(1);
        let weight = validator.stake_amount as f64 / total_stake as f64;

        if weight > 0.0 {
            weight
        } else {
            f64::EPSILON
        }
    }

    fn canonical_primary_leader_addresses(
        validators: &[Validator],
        epoch_randomness: &[u8],
    ) -> Vec<String> {
        let mut validator_priorities = validators
            .iter()
            .map(|validator| {
                let mut hasher = Sha3_512::new();
                hasher.update(epoch_randomness);
                hasher.update(validator.address.as_bytes());
                let hash = hasher.finalize();
                let raw_hash = u64::from_be_bytes(hash[..8].try_into().unwrap());
                let consensus_weight = Self::stable_leader_weight(validators, validator);
                let priority_value = raw_hash as f64 * consensus_weight;
                (validator.address.clone(), priority_value, raw_hash)
            })
            .collect::<Vec<_>>();

        validator_priorities.sort_by(|left, right| {
            right
                .1
                .partial_cmp(&left.1)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| right.2.cmp(&left.2))
                .then_with(|| left.0.cmp(&right.0))
        });
        validator_priorities
            .into_iter()
            .take(std::cmp::min(10, validators.len()))
            .map(|(address, _, _)| address)
            .collect()
    }

    fn prefer_local_vote_lock_leader(
        selected_validator: Validator,
        active_validators: &[Validator],
        live_validators: &[Validator],
        local_validator_address: Option<&str>,
        current_epoch: u64,
        next_block_index: u64,
        finalized_height: u64,
        transient_recovery_min_age_secs: u64,
    ) -> Validator {
        let Some(local_validator_address) = local_validator_address else {
            return selected_validator;
        };

        let locked_vote = match DualQuorumConsensus::local_locked_vote_for_height(
            local_validator_address,
            current_epoch,
            next_block_index,
        ) {
            Ok(Some(locked_vote)) => locked_vote,
            Ok(None) => return selected_validator,
            Err(error) => {
                warn!(
                    "consensus",
                    "Unable to inspect local same-height vote lock before leader selection",
                    "local_validator" => local_validator_address.to_string(),
                    "epoch" => current_epoch,
                    "height" => next_block_index,
                    "error" => error
                );
                return selected_validator;
            }
        };

        if !active_validators
            .iter()
            .any(|validator| validator.address == locked_vote.proposer)
        {
            warn!(
                "consensus",
                "Ignoring local same-height vote lock because its proposer is no longer active",
                "local_validator" => local_validator_address.to_string(),
                "locked_proposer" => locked_vote.proposer,
                "locked_block_hash" => locked_vote.block_hash,
                "epoch" => current_epoch,
                "height" => next_block_index
            );
            return selected_validator;
        }

        let Some(locked_proposer) = live_validators
            .iter()
            .find(|validator| validator.address == locked_vote.proposer)
            .cloned()
        else {
            warn!(
                "consensus",
                "Ignoring local same-height vote lock because its proposer is not live",
                "local_validator" => local_validator_address.to_string(),
                "locked_proposer" => locked_vote.proposer,
                "locked_block_hash" => locked_vote.block_hash,
                "locked_first_round" => locked_vote.first_round_number,
                "locked_latest_round" => locked_vote.latest_round_number,
                "epoch" => current_epoch,
                "height" => next_block_index
            );
            return selected_validator;
        };

        if locked_vote.proposer != selected_validator.address {
            let lock_age_secs = Self::current_timestamp().saturating_sub(locked_vote.updated_at);
            let selected_validator_is_live = live_validators
                .iter()
                .any(|validator| validator.address == selected_validator.address);

            if locked_proposer.address != selected_validator.address {
                if selected_validator_is_live {
                    let recovery_reason = format!(
                        "live scheduled leader superseded local same-height vote lock: local_validator={} height={} finalized_height={} scheduled_leader={} locked_proposer={} locked_hash={} locked_latest_round={}",
                        local_validator_address,
                        next_block_index,
                        finalized_height,
                        selected_validator.address,
                        locked_vote.proposer,
                        locked_vote.block_hash,
                        locked_vote.latest_round_number
                    );
                    match DualQuorumConsensus::recover_stale_transient_vote_locks_for_leader_selection(
                        finalized_height,
                        0,
                        &recovery_reason,
                    ) {
                        Ok(recovered) => {
                            warn!(
                                "consensus",
                                "Using live scheduled leader over local same-height vote lock",
                                "local_validator" => local_validator_address.to_string(),
                                "scheduled_leader" => selected_validator.address.clone(),
                                "locked_proposer" => locked_vote.proposer.clone(),
                                "locked_block_hash" => locked_vote.block_hash.clone(),
                                "locked_first_round" => locked_vote.first_round_number,
                                "locked_latest_round" => locked_vote.latest_round_number,
                                "lock_age_secs" => lock_age_secs,
                                "transient_locks_recovered" => recovered,
                                "epoch" => current_epoch,
                                "height" => next_block_index
                            );
                        }
                        Err(error) => {
                            warn!(
                                "consensus",
                                "Using live scheduled leader over local same-height vote lock without local transient recovery",
                                "local_validator" => local_validator_address.to_string(),
                                "scheduled_leader" => selected_validator.address.clone(),
                                "locked_proposer" => locked_vote.proposer.clone(),
                                "locked_block_hash" => locked_vote.block_hash.clone(),
                                "locked_first_round" => locked_vote.first_round_number,
                                "locked_latest_round" => locked_vote.latest_round_number,
                                "lock_age_secs" => lock_age_secs,
                                "recovery_error" => error,
                                "epoch" => current_epoch,
                                "height" => next_block_index
                            );
                        }
                    }
                    return selected_validator;
                }

                if Self::should_supersede_same_height_vote_lock_with_scheduled_leader(
                    selected_validator_is_live,
                    lock_age_secs,
                    transient_recovery_min_age_secs,
                ) {
                    let recovery_reason = format!(
                        "scheduled leader superseded stale same-height vote lock: local_validator={} height={} finalized_height={} scheduled_leader={} locked_proposer={} locked_hash={} locked_latest_round={}",
                        local_validator_address,
                        next_block_index,
                        finalized_height,
                        selected_validator.address,
                        locked_vote.proposer,
                        locked_vote.block_hash,
                        locked_vote.latest_round_number
                    );
                    match DualQuorumConsensus::recover_stale_transient_vote_locks_for_leader_selection(
                        finalized_height,
                        transient_recovery_min_age_secs,
                        &recovery_reason,
                    ) {
                        Ok(recovered) => {
                            warn!(
                                "consensus",
                                "Allowing live scheduled leader to supersede stale same-height vote lock",
                                "local_validator" => local_validator_address.to_string(),
                                "scheduled_leader" => selected_validator.address.clone(),
                                "locked_proposer" => locked_vote.proposer.clone(),
                                "locked_block_hash" => locked_vote.block_hash.clone(),
                                "locked_first_round" => locked_vote.first_round_number,
                                "locked_latest_round" => locked_vote.latest_round_number,
                                "lock_age_secs" => lock_age_secs,
                                "min_age_secs" => transient_recovery_min_age_secs,
                                "transient_locks_recovered" => recovered,
                                "epoch" => current_epoch,
                                "height" => next_block_index
                            );
                        }
                        Err(error) => {
                            warn!(
                                "consensus",
                                "Allowing live scheduled leader to supersede stale same-height vote lock without local transient recovery",
                                "local_validator" => local_validator_address.to_string(),
                                "scheduled_leader" => selected_validator.address.clone(),
                                "locked_proposer" => locked_vote.proposer.clone(),
                                "locked_block_hash" => locked_vote.block_hash.clone(),
                                "locked_first_round" => locked_vote.first_round_number,
                                "locked_latest_round" => locked_vote.latest_round_number,
                                "lock_age_secs" => lock_age_secs,
                                "min_age_secs" => transient_recovery_min_age_secs,
                                "recovery_error" => error,
                                "epoch" => current_epoch,
                                "height" => next_block_index
                            );
                        }
                    }
                    return selected_validator;
                }
                info!(
                    "consensus",
                    "Preserving live same-height vote lock leader because scheduled leader is not live",
                    "local_validator" => local_validator_address.to_string(),
                    "scheduled_leader" => selected_validator.address.clone(),
                    "scheduled_leader_live" => selected_validator_is_live,
                    "locked_proposer" => locked_vote.proposer.clone(),
                    "locked_block_hash" => locked_vote.block_hash.clone(),
                    "locked_first_round" => locked_vote.first_round_number,
                    "locked_latest_round" => locked_vote.latest_round_number,
                    "lock_age_secs" => lock_age_secs,
                    "min_age_secs" => transient_recovery_min_age_secs,
                    "epoch" => current_epoch,
                    "height" => next_block_index
                );
                return locked_proposer;
            }
        }

        selected_validator
    }

    fn should_supersede_same_height_vote_lock_with_scheduled_leader(
        selected_validator_is_live: bool,
        lock_age_secs: u64,
        transient_recovery_min_age_secs: u64,
    ) -> bool {
        selected_validator_is_live && lock_age_secs >= transient_recovery_min_age_secs
    }

    fn create_block_proposal(
        previous_block: &Block,
        leader: &Validator,
        transactions: Vec<crate::transaction::Transaction>,
        block_time_secs: u64,
        pqc_manager: &Arc<Mutex<PQCManager>>,
    ) -> Block {
        if let Some(block) = Self::load_cached_block_proposal(previous_block, leader) {
            info!(
                "consensus",
                "Reusing cached block proposal for retry",
                "height" => block.block_index,
                "hash" => block.hash.clone(),
                "validator" => leader.address.clone()
            );
            return block;
        }

        let now = Self::current_timestamp();
        let transactions = Self::filter_expired_proposal_transactions(
            transactions,
            previous_block.block_index + 1,
            &leader.address,
            now,
        );

        // Create block and attach the consensus signature required for this height.
        let consensus_timestamp =
            Self::bounded_consensus_timestamp(previous_block.timestamp, block_time_secs, now);
        let mut block = Block::new_with_timestamp(
            previous_block.block_index + 1,
            transactions,
            previous_block.hash.clone(),
            leader.address.clone(),
            previous_block.nonce + 1, // Simple nonce increment
            consensus_timestamp,
        );
        block
            .apply_fee_market_from_parent(previous_block)
            .unwrap_or_else(|error| panic!("legacy fee-market proposal construction failed: {error}"));

        let (leader_public_key, leader_private_key) = load_local_validator_keypair_for_height(
            block.block_index,
            &leader.address,
            &VALIDATOR_MANAGER,
        )
        .unwrap_or_else(|error| panic!("Aegis PQC leader signing key unavailable: {error}"));

        let mut pqc = pqc_manager.lock().unwrap();
        let signature = pqc
            .sign(&leader_private_key, block.hash.as_bytes())
            .unwrap_or_else(|error| panic!("Aegis PQC block signing failed: {error}"));
        block.proposer_public_key = leader_public_key.key_data;
        block.block_signature = signature.signature_data;
        block.block_signature_algorithm =
            consensus_algorithm_label(&leader_public_key.algorithm).to_string();

        if let Err(error) = Self::persist_cached_block_proposal(&block) {
            warn!(
                "consensus",
                "Failed to persist block proposal for retry",
                "height" => block.block_index,
                "hash" => block.hash.clone(),
                "error" => error.to_string()
            );
        }

        block
    }

    fn verify_legacy_precommit(
        block: &Block,
        qc: &QuorumCertificate,
        expected_epoch: u64,
    ) -> Result<(), String> {
        DualQuorumConsensus::verify_commit_certificate_for_block_static(
            block,
            qc,
            &VALIDATOR_MANAGER,
        )?;
        if qc.block_hash != block.hash {
            return Err("QC block hash does not match exact block".to_string());
        }
        if qc.epoch_number != expected_epoch {
            return Err("QC epoch does not match block epoch".to_string());
        }
        if !qc.validation_quorum_met || !qc.cooperation_quorum_met {
            return Err("QC does not prove both validation and cooperation quorum".to_string());
        }
        if qc.aggregate_signature.is_empty() {
            return Err("QC aggregate signature is missing".to_string());
        }
        if qc.participant_bitmap.is_empty() {
            return Err("QC signer bitmap is missing".to_string());
        }
        if qc.cumulative_weight <= 0.0 {
            return Err("QC signed weight is zero".to_string());
        }
        Ok(())
    }

    fn proposal_cache_dir() -> PathBuf {
        #[cfg(test)]
        if let Some(path) = TEST_PROPOSAL_CACHE_DIR
            .lock()
            .expect("test proposal cache lock should succeed")
            .clone()
        {
            return path;
        }

        crate::utils::resolve_data_path("data/consensus_proposals")
    }

    fn proposal_cache_key(block_index: u64, previous_hash: &str, leader_address: &str) -> String {
        let input = format!("{block_index}:{previous_hash}:{leader_address}");
        blake3::hash(input.as_bytes()).to_hex().to_string()
    }

    fn proposal_cache_path(block_index: u64, previous_hash: &str, leader_address: &str) -> PathBuf {
        Self::proposal_cache_dir().join(format!(
            "{}.json",
            Self::proposal_cache_key(block_index, previous_hash, leader_address)
        ))
    }

    fn load_cached_block_proposal(previous_block: &Block, leader: &Validator) -> Option<Block> {
        let _guard = PROPOSAL_CACHE_LOCK
            .lock()
            .expect("proposal cache lock should succeed");
        let path = Self::proposal_cache_path(
            previous_block.block_index + 1,
            &previous_block.hash,
            &leader.address,
        );
        let contents = fs::read_to_string(&path).ok()?;
        let block = serde_json::from_str::<Block>(&contents).ok()?;
        if !Self::block_matches_proposal_context(&block, previous_block, leader) {
            return None;
        }
        let now = Self::current_timestamp();
        let expired_transactions = block
            .transactions
            .iter()
            .filter(|tx| Self::transaction_is_expired_for_proposal(tx, now))
            .collect::<Vec<_>>();
        let expired_transaction_count = expired_transactions.len();
        if expired_transaction_count > 0 {
            let oldest_transaction_timestamp = expired_transactions
                .iter()
                .map(|tx| tx.timestamp)
                .min()
                .unwrap_or(0);
            PROPOSAL_CACHE_DISCARD_COUNT.fetch_add(1, Ordering::Relaxed);
            warn!(
                "consensus",
                "Discarding cached block proposal with expired transaction timestamps",
                "height" => block.block_index,
                "hash" => block.hash.clone(),
                "validator" => leader.address.clone(),
                "expired_transactions" => expired_transaction_count as u64,
                "oldest_transaction_timestamp" => oldest_transaction_timestamp
            );
            if let Err(error) = fs::remove_file(&path) {
                warn!(
                    "consensus",
                    "Failed to remove expired cached block proposal",
                    "height" => block.block_index,
                    "hash" => block.hash.clone(),
                    "path" => path.display().to_string(),
                    "error" => error.to_string()
                );
            }
            return None;
        }
        if let Err(error) = block.verify_proposer_signature() {
            warn!(
                "consensus",
                "Discarding cached block proposal with invalid Aegis PQC signature",
                "height" => block.block_index,
                "hash" => block.hash.clone(),
                "error" => error
            );
            return None;
        }
        Some(block)
    }

    fn transaction_is_expired_for_proposal(
        tx: &crate::transaction::Transaction,
        current_time_secs: u64,
    ) -> bool {
        current_time_secs.saturating_sub(tx.timestamp) > PROPOSAL_TRANSACTION_MAX_AGE_SECS
    }

    fn filter_expired_proposal_transactions(
        transactions: Vec<crate::transaction::Transaction>,
        block_index: u64,
        leader_address: &str,
        current_time_secs: u64,
    ) -> Vec<crate::transaction::Transaction> {
        let original_len = transactions.len();
        let filtered = transactions
            .into_iter()
            .filter(|tx| !Self::transaction_is_expired_for_proposal(tx, current_time_secs))
            .collect::<Vec<_>>();
        let dropped = original_len.saturating_sub(filtered.len());
        if dropped > 0 {
            EXPIRED_PROPOSAL_TRANSACTION_DROP_COUNT.fetch_add(dropped as u64, Ordering::Relaxed);
            warn!(
                "consensus",
                "Dropping expired transactions from block proposal",
                "height" => block_index,
                "validator" => leader_address.to_string(),
                "dropped_transactions" => dropped as u64
            );
        }
        filtered
    }

    fn persist_cached_block_proposal(block: &Block) -> Result<(), std::io::Error> {
        let _guard = PROPOSAL_CACHE_LOCK
            .lock()
            .expect("proposal cache lock should succeed");
        let dir = Self::proposal_cache_dir();
        fs::create_dir_all(&dir)?;
        let path = dir.join(format!(
            "{}.json",
            Self::proposal_cache_key(block.block_index, &block.previous_hash, &block.validator_id)
        ));
        let tmp_path = path.with_extension("json.tmp");
        let payload = serde_json::to_vec_pretty(block)
            .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
        fs::write(&tmp_path, payload)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&tmp_path, fs::Permissions::from_mode(0o600))?;
        }
        fs::rename(tmp_path, path)?;
        Ok(())
    }

    fn prune_cached_block_proposals(committed_height: u64) {
        let _guard = PROPOSAL_CACHE_LOCK
            .lock()
            .expect("proposal cache lock should succeed");
        let dir = Self::proposal_cache_dir();
        let Ok(entries) = fs::read_dir(dir) else {
            return;
        };

        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|value| value.to_str()) != Some("json") {
                continue;
            }
            let should_remove = fs::read_to_string(&path)
                .ok()
                .and_then(|contents| serde_json::from_str::<Block>(&contents).ok())
                .map(|block| block.block_index <= committed_height)
                .unwrap_or(false);
            if should_remove {
                let _ = fs::remove_file(path);
            }
        }
    }

    fn archive_proposal_cache_file(source: &Path, target: &Path) -> Result<(), std::io::Error> {
        match fs::rename(source, target) {
            Ok(()) => Ok(()),
            Err(error) if error.raw_os_error() == Some(18) => {
                fs::copy(source, target)?;
                if let Ok(metadata) = fs::metadata(source) {
                    let _ = fs::set_permissions(target, metadata.permissions());
                }
                fs::remove_file(source)
            }
            Err(error) => Err(error),
        }
    }

    pub fn recover_cached_block_proposals_above_finalized_height(
        finalized_height: u64,
        reason: &str,
    ) -> Result<ProposalCacheRecoveryReport, String> {
        let _guard = PROPOSAL_CACHE_LOCK
            .lock()
            .map_err(|_| "proposal cache lock is poisoned".to_string())?;
        let dir = Self::proposal_cache_dir();
        let now = Self::current_timestamp();
        let evidence_nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let mut evidence_dir: Option<PathBuf> = None;

        let mut scanned_count = 0usize;
        let mut archived = Vec::new();
        if let Ok(entries) = fs::read_dir(&dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().and_then(|value| value.to_str()) != Some("json") {
                    continue;
                }
                scanned_count += 1;
                let Some(block) = fs::read_to_string(&path)
                    .ok()
                    .and_then(|contents| serde_json::from_str::<Block>(&contents).ok())
                else {
                    continue;
                };
                if block.block_index <= finalized_height {
                    continue;
                }

                let file_name = path
                    .file_name()
                    .map(|value| value.to_owned())
                    .unwrap_or_else(|| format!("proposal-{}.json", block.hash).into());
                let evidence_dir = match evidence_dir.as_ref() {
                    Some(evidence_dir) => evidence_dir.clone(),
                    None => {
                        let evidence_dir_relative = format!(
                            "data/consensus_recovery_evidence/{}-{}-proposals-above-{}",
                            now, evidence_nonce, finalized_height
                        );
                        let created = crate::utils::resolve_data_path(&evidence_dir_relative);
                        fs::create_dir_all(&created).map_err(|error| {
                            format!("failed to create proposal evidence directory: {error}")
                        })?;
                        evidence_dir = Some(created.clone());
                        created
                    }
                };
                let target = evidence_dir.join(file_name);
                Self::archive_proposal_cache_file(&path, &target).map_err(|error| {
                    format!(
                        "failed to archive proposal cache file {:?} to {:?}: {error}",
                        path, target
                    )
                })?;
                archived.push(ArchivedConsensusProposal {
                    source_path: path.to_string_lossy().to_string(),
                    evidence_path: target.to_string_lossy().to_string(),
                    block_index: block.block_index,
                    block_hash: block.hash,
                    parent_hash: block.previous_hash,
                    proposer: block.validator_id,
                });
            }
        }

        let report = ProposalCacheRecoveryReport {
            action: "recover_cached_block_proposals_above_finalized_height".to_string(),
            reason: reason.to_string(),
            finalized_height,
            proposal_cache_dir: dir.to_string_lossy().to_string(),
            evidence_dir: evidence_dir
                .as_ref()
                .map(|path| path.to_string_lossy().to_string())
                .unwrap_or_default(),
            scanned_count,
            archived_count: archived.len(),
            mutated: !archived.is_empty(),
            archived,
            timestamp: now,
        };
        if let Some(evidence_dir) = evidence_dir {
            let manifest_path = evidence_dir.join("manifest.json");
            let manifest = serde_json::to_vec_pretty(&report)
                .map_err(|error| format!("failed to encode proposal evidence manifest: {error}"))?;
            fs::write(&manifest_path, manifest)
                .map_err(|error| format!("failed to write proposal evidence manifest: {error}"))?;
        }
        Ok(report)
    }

    fn block_matches_proposal_context(
        block: &Block,
        previous_block: &Block,
        leader: &Validator,
    ) -> bool {
        if block.block_index != previous_block.block_index + 1
            || block.previous_hash != previous_block.hash
            || block.validator_id != leader.address
        {
            return false;
        }

        let mut recalculated = block.clone();
        recalculated.hash = recalculated.recompute_hash();
        recalculated.hash == block.hash && recalculated.transactions_root == block.transactions_root
    }

    #[cfg(test)]
    fn set_test_proposal_cache_dir(path: Option<PathBuf>) {
        *TEST_PROPOSAL_CACHE_DIR
            .lock()
            .expect("test proposal cache lock should succeed") = path;
    }

    fn validate_finalized_validator_activations(
        block: &Block,
        token_manager: &crate::token::TokenManager,
        validator_manager: &Arc<ValidatorManager>,
    ) -> Result<(), String> {
        for tx in &block.transactions {
            if !is_validator_activation_transaction(tx) {
                continue;
            }
            validate_validator_activation_transaction(tx, token_manager, validator_manager)
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

    fn apply_finalized_validator_activations(
        block: &Block,
        token_manager: &crate::token::TokenManager,
        validator_manager: &Arc<ValidatorManager>,
    ) -> Result<Vec<(String, String)>, String> {
        let mut applied = Vec::new();
        for tx in &block.transactions {
            if !is_validator_activation_transaction(tx) {
                continue;
            }

            let message = apply_validator_activation_transaction(
                tx,
                token_manager,
                validator_manager,
                block.block_index,
            )
            .map_err(|error| {
                format!(
                    "validator activation application failed at finalized height {} for transaction {}: {error}",
                    block.block_index,
                    tx.hash()
                )
            })?;
            applied.push((tx.hash(), message));
        }
        Ok(applied)
    }

    fn execute_dual_quorum_consensus(
        block: &Block,
        _validator_manager: &Arc<ValidatorManager>,
        dual_quorum_consensus: &Arc<Mutex<DualQuorumConsensus>>,
        current_epoch: u64,
        view_offset: usize,
        transient_recovery_min_age_secs: u64,
    ) -> Result<QuorumCertificate, String> {
        consensus_log!(
            "🔒 [execute_dual_quorum_consensus] Attempting to lock dual_quorum_consensus..."
        );
        use std::io::{self, Write};
        io::stdout().flush().unwrap();
        let mut consensus = dual_quorum_consensus.lock().unwrap();
        consensus_log!(
            "✅ [execute_dual_quorum_consensus] Locked! Setting current_epoch to {}",
            current_epoch
        );
        io::stdout().flush().unwrap();
        consensus.current_epoch = current_epoch;
        let minimum_round_number = (view_offset as u64).saturating_add(1);

        consensus_log!("📞 [execute_dual_quorum_consensus] Calling start_consensus_round...");
        io::stdout().flush().unwrap();
        // Execute the dual-quorum consensus process
        let result = consensus.start_consensus_round_with_recovery(
            block,
            minimum_round_number,
            transient_recovery_min_age_secs,
        );
        consensus_log!("✅ [execute_dual_quorum_consensus] start_consensus_round returned!");
        io::stdout().flush().unwrap();
        result
    }

    fn consensus_failure_needs_transient_lock_recovery(error: &str) -> bool {
        Self::consensus_failure_needs_missed_quorum_view_change(error)
            || error.contains("same-height vote supersede requires")
            || error.contains("already locally voted for different block")
    }

    fn consensus_failure_needs_missed_quorum_view_change(error: &str) -> bool {
        error.contains("Insufficient validator votes")
    }

    fn transient_vote_recovery_min_age_secs(leader_timeout_secs: u64, block_time_secs: u64) -> u64 {
        leader_timeout_secs
            .min(block_time_secs.max(FAST_CONSENSUS_VOTE_TIMEOUT_SECS))
            .max(FAST_CONSENSUS_VOTE_TIMEOUT_SECS)
    }

    pub(crate) fn validate_transaction_for_mempool(
        tx: &crate::transaction::Transaction,
    ) -> Result<(), String> {
        let pqc_manager = Arc::new(Mutex::new(PQCManager::new()));
        Self::validate_transaction_detailed(tx, &pqc_manager)
    }

    fn validate_transaction(
        tx: &crate::transaction::Transaction,
        pqc_manager: &Arc<Mutex<PQCManager>>,
    ) -> bool {
        match Self::validate_transaction_detailed(tx, pqc_manager) {
            Ok(()) => true,
            Err(reason) => {
                warn!(
                    "consensus",
                    "Rejecting transaction during consensus validation",
                    "tx_hash" => tx.hash(),
                    "sender" => tx.sender.clone(),
                    "reason" => reason
                );
                false
            }
        }
    }

    fn validate_transaction_detailed(
        tx: &crate::transaction::Transaction,
        _pqc_manager: &Arc<Mutex<PQCManager>>,
    ) -> Result<(), String> {
        if !crate::address::is_valid_address(&tx.sender) {
            return Err("invalid sender address".to_string());
        }

        if !tx.receiver.trim().is_empty()
            && !tx.receiver.starts_with("contract_")
            && !crate::address::is_valid_address(&tx.receiver)
        {
            return Err("invalid receiver address".to_string());
        }

        if let Some(validator) = staking_validator_address(tx) {
            if !crate::address::is_valid_address(&validator) {
                return Err(format!("invalid staking validator address: {validator}"));
            }
        }

        // 1. Verify transaction signature. Aegis DAG carrier transactions verify
        // through the typed Aegis PQVM transaction-key path; legacy wallet
        // transactions require an on-node public key.
        if crate::aegis_tx_tool::is_legacy_aegis_carrier_transaction(tx) {
            if let Err(error) = crate::aegis_tx_tool::validate_legacy_aegis_carrier_transaction(tx)
            {
                return Err(format!(
                    "Aegis PQVM transaction carrier validation failed: {error}"
                ));
            }
        } else {
            tx.verify_embedded_signature()
                .map_err(|error| format!("transaction signature verification failed: {error}"))?;
            if let Some(public_key) = Self::get_transaction_public_key(&tx.sender) {
                if tx.signer_public_key != public_key.key_data {
                    return Err(
                        "signer public key does not match registered sender public key".to_string(),
                    );
                }
            }
        }

        Self::validate_transaction_nonce_for_mempool(tx)?;

        // 2. Verify sender balance via token manager to reflect on-chain state
        let token_manager = TOKEN_MANAGER.clone();
        let required = snrg_balance_required_for_transaction(tx);
        if token_manager.get_balance(&tx.sender, "SNRG") < required {
            return Err(format!(
                "insufficient SNRG balance for transaction; required {required}"
            ));
        }

        // 3. Execute contract if applicable (simplified)
        if tx.receiver.starts_with("contract_") {
            // Execute contract in sandboxed environment
            // Verify state changes
            // For now, assume valid
        }

        Ok(())
    }

    pub(crate) fn validate_transaction_nonce_for_mempool(
        tx: &crate::transaction::Transaction,
    ) -> Result<(), String> {
        let mut committed_sender_nonces = {
            let chain = SHARED_CHAIN.lock().unwrap();
            chain
                .chain
                .iter()
                .flat_map(|block| block.transactions.iter())
                .filter(|committed| committed.sender.eq_ignore_ascii_case(&tx.sender))
                .map(|committed| committed.nonce)
                .collect::<Vec<_>>()
        };
        committed_sender_nonces.extend(crate::dag::committed_sender_nonces(&tx.sender));
        committed_sender_nonces.sort_unstable();
        committed_sender_nonces.dedup();
        let pending_sender_nonces = {
            let tx_hash = tx.hash();
            let pool = TX_POOL.lock().unwrap();
            pool.iter()
                .filter(|pending| pending.sender.eq_ignore_ascii_case(&tx.sender))
                .filter(|pending| pending.hash() != tx_hash)
                .map(|pending| (pending.hash(), pending.nonce))
                .collect::<Vec<_>>()
        };

        Self::validate_transaction_nonce_for_ordering(
            tx.nonce,
            &committed_sender_nonces,
            &pending_sender_nonces,
        )
    }

    pub(crate) fn validate_transaction_nonce_for_ordering(
        tx_nonce: u64,
        committed_sender_nonces: &[u64],
        pending_sender_nonces: &[(String, u64)],
    ) -> Result<(), String> {
        let mut expected_nonce = committed_sender_nonces
            .iter()
            .copied()
            .max()
            .map(|nonce| nonce.saturating_add(1))
            .unwrap_or(0);

        let mut pending_lower_nonces = HashSet::new();
        for (_, pending_nonce) in pending_sender_nonces {
            if *pending_nonce == tx_nonce {
                return Err(format!(
                    "duplicate nonce; nonce {tx_nonce} is already pending"
                ));
            }
            if *pending_nonce >= expected_nonce && *pending_nonce < tx_nonce {
                pending_lower_nonces.insert(*pending_nonce);
            }
        }

        while pending_lower_nonces.remove(&expected_nonce) {
            expected_nonce = expected_nonce.saturating_add(1);
        }

        if tx_nonce < expected_nonce {
            return Err(format!(
                "stale nonce; expected {expected_nonce}, got {tx_nonce}"
            ));
        }
        if tx_nonce > expected_nonce {
            return Err(format!(
                "future nonce gap; expected {expected_nonce}, got {tx_nonce}"
            ));
        }

        Ok(())
    }

    fn update_synergy_scores(
        validator_manager: &Arc<ValidatorManager>,
        _synergy_calculator: &Arc<SynergyScoreCalculator>,
        validator_address: &str,
    ) {
        let _ = validator_manager;
        let _ = validator_address;
    }

    fn record_vote_for_cartel_detection(
        cartel_detection: &Arc<Mutex<CartelDetectionEngine>>,
        validator_address: &str,
        block_height: u64,
        voted_for_winner: bool,
        timestamp: u64,
        epoch_length: u64,
    ) {
        let mut engine = cartel_detection.lock().unwrap();
        let current_epoch = epoch_for_block_height(block_height, epoch_length);

        let vote_record = VoteRecord {
            validator_address: validator_address.to_string(),
            block_height,
            voted_for_winner,
            vote_timestamp: timestamp,
            signature: Vec::new(), // Simplified
        };

        engine.record_vote(current_epoch, vote_record);
    }

    fn check_governance_proposals(dao_governance: &Arc<Mutex<DAOGovernance>>, block_index: u64) {
        let mut governance = dao_governance.lock().unwrap();

        // Collect proposals that need transition (to avoid borrow checker issues)
        let proposals_to_transition: Vec<(String, ProposalStatus, u64, u64, u64)> = governance
            .proposals
            .iter()
            .map(|(id, p)| {
                (
                    id.clone(),
                    p.status.clone(),
                    p.discussion_end,
                    p.voting_end,
                    p.execution_timestamp,
                )
            })
            .collect();

        // Check if any proposals need transition
        for (proposal_id, status, discussion_end, voting_end, execution_timestamp) in
            proposals_to_transition
        {
            if status == ProposalStatus::Discussion && block_index >= discussion_end {
                governance.transition_proposal_to_voting(&proposal_id).ok();
            }

            if status == ProposalStatus::Voting && block_index >= voting_end {
                governance.finalize_voting(&proposal_id).ok();
            }

            if status == ProposalStatus::Approved && block_index >= execution_timestamp {
                governance.execute_approved_proposal(&proposal_id).ok();
            }
        }
    }

    fn maybe_apply_proposer_penalty(
        penalization_enabled: bool,
        validator_manager: &Arc<ValidatorManager>,
        validator_address: &str,
    ) {
        if !penalization_enabled {
            return;
        }
        Self::apply_proposer_penalty(validator_manager, validator_address);
    }

    fn apply_proposer_penalty(validator_manager: &Arc<ValidatorManager>, validator_address: &str) {
        // Must mutate through the registry lock so the change is actually persisted.
        if let Ok(mut registry) = validator_manager.registry.lock() {
            if let Some(validator) = registry.validators.get_mut(validator_address) {
                validator.reputation_score = (validator.reputation_score * 0.99).max(0.0);
                validator.calculate_synergy_score();
                println!(
                    "⚠️ Applied proposer penalty to {}: reputation reduced to {:.2}, synergy score now {:.2}",
                    validator_address, validator.reputation_score, validator.synergy_score
                );
            }
        }
    }

    /// Called when the view-change timer fires because the scheduled leader failed to
    /// broadcast a block proposal within the timeout window.  Uses the existing
    /// `record_missed_block` path so that uptime, accuracy, reputation, and slashing
    /// penalty are all updated consistently with the rest of the PoSy rules.
    fn maybe_apply_leader_timeout_penalty(
        penalization_enabled: bool,
        validator_manager: &Arc<ValidatorManager>,
        validator_address: &str,
        block_height: u64,
        view_offset: usize,
    ) {
        if !penalization_enabled {
            return;
        }
        Self::apply_leader_timeout_penalty(
            validator_manager,
            validator_address,
            block_height,
            view_offset,
        );
    }

    fn apply_leader_timeout_penalty(
        validator_manager: &Arc<ValidatorManager>,
        validator_address: &str,
        block_height: u64,
        view_offset: usize,
    ) {
        if let Ok(mut registry) = validator_manager.registry.lock() {
            if let Some(validator) = registry.validators.get_mut(validator_address) {
                // record_missed_block → record_missed_vote: decrements uptime/accuracy/reputation
                // and increments slashing_penalty + missed_vote_window atomically.
                validator.record_missed_block();

                let new_score = validator.synergy_score;
                let new_rep = validator.reputation_score;
                let new_penalty = validator.slashing_penalty;
                let missed_window = validator.missed_vote_window;

                warn!(
                    "consensus",
                    "Leader timeout penalty applied",
                    "validator" => validator_address,
                    "block_height" => block_height,
                    "view_offset" => view_offset,
                    "synergy_score" => format!("{:.4}", new_score),
                    "reputation_score" => format!("{:.4}", new_rep),
                    "slashing_penalty" => format!("{:.4}", new_penalty),
                    "missed_vote_window" => missed_window
                );
            }
        }
    }

    fn recalculate_all_synergy_scores(
        validator_manager: &Arc<ValidatorManager>,
        _synergy_calculator: &Arc<SynergyScoreCalculator>,
    ) {
        if let Ok(mut registry) = validator_manager.registry.lock() {
            for validator in registry.validators.values_mut() {
                // Keep the persisted validator health score aligned with the
                // intrinsic validator metrics. The synergy calculator's
                // normalized score is a comparative ranking for leader
                // selection, and persisting it here can wrongly evict healthy
                // validators at epoch boundaries when one proposer has more
                // proposal history than the rest of the set.
                validator.calculate_synergy_score();
            }
        }

        println!("📊 Recalculated validator health scores for all validators");
    }

    fn update_governance_proposals(governance: &mut DAOGovernance, current_epoch: u64) {
        // Check for expired proposals
        let expired_proposals: Vec<String> = governance
            .proposals
            .iter()
            .filter(|(_, proposal)| {
                proposal.status != ProposalStatus::Executed
                    && proposal.status != ProposalStatus::Rejected
                    && current_epoch > (proposal.execution_timestamp / 1000) as u64 + 1
            })
            .map(|(id, _)| id.clone())
            .collect();

        for proposal_id in expired_proposals {
            governance
                .update_proposal_status(&proposal_id, ProposalStatus::Expired)
                .ok();
        }
    }

    fn get_transaction_public_key(address: &str) -> Option<crate::crypto::pqc::PQCPublicKey> {
        if let Ok(wallet_manager) = WALLET_MANAGER.lock() {
            if let Some(wallet) = wallet_manager.get_wallet(address) {
                // Public keys are stored as base64 in identity.json; support both hex and base64.
                let key_bytes = hex::decode(&wallet.public_key)
                    .or_else(|_| general_purpose::STANDARD.decode(wallet.public_key.as_bytes()));
                if let Ok(key_bytes) = key_bytes {
                    return Some(PQCPublicKey {
                        algorithm: PQCAlgorithm::FNDSA,
                        key_data: key_bytes,
                        key_id: format!("wallet_{}", address),
                        created_at: wallet.created_at,
                    });
                }
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::{Block, BlockChain};
    use crate::consensus::dual_quorum::required_validator_quorum;
    use crate::consensus::validator_keys::{
        consensus_algorithm_label, register_test_validator_signing_key,
    };
    use crate::transaction::Transaction;
    use crate::validator::{ValidatorStatus, EPOCH_VALIDATOR_SETS_ENV};
    use base64::engine::general_purpose;
    use std::sync::OnceLock;

    fn proposal_cache_test_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    fn unique_proposal_cache_dir(test_name: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock should be after epoch")
            .as_nanos();
        let dir = crate::utils::test_temp_root(format!(
            "synergy-{test_name}-{}-{nanos}",
            std::process::id()
        ));
        fs::create_dir_all(&dir).expect("test proposal cache dir should be created");
        dir
    }

    fn unique_vote_lock_path(test_name: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock should be after epoch")
            .as_nanos();
        crate::utils::test_temp_root(format!(
            "synergy-{test_name}-{}-{nanos}",
            std::process::id()
        ))
        .join("data")
        .join("consensus_vote_locks.json")
    }

    struct EnvVarGuard {
        key: &'static str,
        previous: Option<String>,
    }

    impl EnvVarGuard {
        fn set(key: &'static str, value: &str) -> Self {
            let previous = std::env::var(key).ok();
            std::env::set_var(key, value);
            Self { key, previous }
        }
    }

    impl Drop for EnvVarGuard {
        fn drop(&mut self) {
            if let Some(previous) = &self.previous {
                std::env::set_var(self.key, previous);
            } else {
                std::env::remove_var(self.key);
            }
        }
    }

    fn epoch_set_env_test_lock() -> &'static Mutex<()> {
        crate::validator::epoch_validator_sets_env_lock()
    }

    fn test_validator(address: &str) -> Validator {
        let mut validator = Validator::new(
            address.to_string(),
            format!("{address}-public-key"),
            "Validator".to_string(),
            50_000_000_000_000,
        );
        validator.status = ValidatorStatus::Active;
        validator
    }

    fn test_validator_addresses(start: usize, end_inclusive: usize) -> Vec<String> {
        (start..=end_inclusive)
            .map(|index| format!("validator-{index}"))
            .collect()
    }

    fn test_validators(start: usize, end_inclusive: usize) -> Vec<Validator> {
        test_validator_addresses(start, end_inclusive)
            .iter()
            .map(|address| test_validator(address))
            .collect()
    }

    #[test]
    fn startup_cluster_reconciliation_repairs_six_validator_registry_and_is_idempotent() {
        let manager = Arc::new(ValidatorManager::new());
        {
            let mut registry = manager
                .registry
                .lock()
                .expect("validator registry lock should succeed");
            for mut validator in test_validators(0, 5) {
                validator.cluster_id = Some(99);
                validator.cluster_address = Some("stale-cluster-address".to_string());
                validator.cluster_assignment_epoch = Some(99);
                validator.cluster_assignment_seed = Some("stale-cluster-seed".to_string());
                validator.cluster_assignment_effective_height = Some(1);
                registry
                    .validators
                    .insert(validator.address.clone(), validator);
            }
            registry.clusters.clear();
        }

        assert!(
            reconcile_validator_registry_clusters_for_height(&manager, 42)
                .expect("startup cluster reconciliation should repair stale metadata")
        );

        {
            let registry = manager
                .registry
                .lock()
                .expect("validator registry lock should succeed");
            let cluster = registry
                .clusters
                .get(&0)
                .expect("six validators should have one canonical cluster");
            assert_eq!(registry.clusters.len(), 1);
            assert_eq!(cluster.validators.len(), 6);
            assert!(registry.validators.values().all(|validator| {
                validator.cluster_id == Some(0)
                    && validator.cluster_address.as_deref() == Some(cluster.address.as_str())
                    && validator.cluster_assignment_epoch == Some(0)
                    && validator
                        .cluster_assignment_seed
                        .as_deref()
                        .is_some_and(|seed| !seed.is_empty())
                    && validator.cluster_assignment_effective_height == Some(1)
            }));
        }

        {
            let mut registry = manager
                .registry
                .lock()
                .expect("validator registry lock should succeed");
            let cluster = registry
                .clusters
                .get_mut(&0)
                .expect("canonical cluster should exist");
            cluster.created_at = 11;
            cluster.last_rotation = 29;
        }
        let stable_before_reconcile = {
            let registry = manager
                .registry
                .lock()
                .expect("validator registry lock should succeed");
            serde_json::to_string_pretty(&*registry).expect("timestamped registry should serialize")
        };
        assert!(
            !reconcile_validator_registry_clusters_for_height(&manager, 99)
                .expect("canonical startup reconciliation should succeed")
        );
        let stable_after_reconcile = {
            let registry = manager
                .registry
                .lock()
                .expect("validator registry lock should succeed");
            serde_json::to_string_pretty(&*registry).expect("timestamped registry should serialize")
        };
        assert_eq!(stable_after_reconcile, stable_before_reconcile);

        let state_dir = unique_proposal_cache_dir("startup-cluster-reconciliation");
        let registry_path = state_dir.join("validator_registry.json");
        manager
            .registry
            .lock()
            .expect("validator registry lock should succeed")
            .save_to_file(&registry_path)
            .expect("repaired validator registry should persist");

        let restarted = Arc::new(ValidatorManager::new());
        restarted
            .load_registry(
                registry_path
                    .to_str()
                    .expect("registry path should be UTF-8"),
            )
            .expect("restarted validator registry should load");
        assert!(
            !reconcile_validator_registry_clusters_for_height(&restarted, 99)
                .expect("restart reconciliation should succeed")
        );
        let after_restart = {
            let registry = restarted
                .registry
                .lock()
                .expect("validator registry lock should succeed");
            serde_json::to_value(&*registry).expect("restarted registry should serialize")
        };

        assert_eq!(
            after_restart,
            serde_json::from_str::<serde_json::Value>(&stable_before_reconcile)
                .expect("timestamped registry snapshot should parse")
        );
        std::fs::remove_dir_all(state_dir).ok();
    }

    #[test]
    fn startup_cluster_reconciliation_repairs_mixed_and_future_effective_heights() {
        let manager = Arc::new(ValidatorManager::new());
        {
            let mut registry = manager
                .registry
                .lock()
                .expect("validator registry lock should succeed");
            for validator in test_validators(0, 5) {
                registry
                    .validators
                    .insert(validator.address.clone(), validator);
            }
        }

        assert!(
            reconcile_validator_registry_clusters_for_height(&manager, 42)
                .expect("initial cluster reconciliation should succeed")
        );
        {
            let mut registry = manager
                .registry
                .lock()
                .expect("validator registry lock should succeed");
            registry
                .validators
                .get_mut("validator-0")
                .expect("validator-0 should exist")
                .cluster_assignment_effective_height = Some(43);
        }
        assert!(
            reconcile_validator_registry_clusters_for_height(&manager, 99)
                .expect("mixed effective heights should be repaired")
        );
        {
            let registry = manager
                .registry
                .lock()
                .expect("validator registry lock should succeed");
            assert!(registry
                .validators
                .values()
                .all(|validator| validator.cluster_assignment_effective_height == Some(1)));
        }

        {
            let mut registry = manager
                .registry
                .lock()
                .expect("validator registry lock should succeed");
            registry
                .validators
                .get_mut("validator-1")
                .expect("validator-1 should exist")
                .cluster_assignment_effective_height = Some(100);
        }
        assert!(
            reconcile_validator_registry_clusters_for_height(&manager, 99)
                .expect("future effective height should be repaired")
        );
        let registry = manager
            .registry
            .lock()
            .expect("validator registry lock should succeed");
        assert!(registry
            .validators
            .values()
            .all(|validator| validator.cluster_assignment_effective_height == Some(1)));
    }

    #[test]
    fn startup_cluster_reconciliation_preserves_shadow_activation_boundary() {
        let _env_lock = epoch_set_env_test_lock().lock().unwrap();
        let manager = Arc::new(ValidatorManager::new());
        {
            let mut registry = manager
                .registry
                .lock()
                .expect("validator registry lock should succeed");
            for mut validator in test_validators(0, 5) {
                if validator.address == "validator-5" {
                    validator.status = ValidatorStatus::Shadow;
                    validator.activation_recorded_height = Some(1_000);
                    validator.activation_effective_height = Some(1_001);
                }
                registry
                    .validators
                    .insert(validator.address.clone(), validator);
            }
        }

        assert!(
            reconcile_validator_registry_clusters_for_height(&manager, 1_000)
                .expect("pre-activation reconciliation should succeed"),
            "pre-activation reconciliation should repair the height-scoped membership"
        );
        {
            let registry = manager
                .registry
                .lock()
                .expect("validator registry lock should succeed");
            assert_eq!(registry.clusters.len(), 1);
            assert_eq!(registry.clusters[&0].validators.len(), 5);
            assert_eq!(registry.validators["validator-5"].cluster_id, None);
        }

        assert!(
            reconcile_validator_registry_clusters_for_height(&manager, 1_001)
                .expect("effective-height reconciliation should succeed")
        );
        let registry = manager
            .registry
            .lock()
            .expect("validator registry lock should succeed");
        assert_eq!(registry.clusters[&0].validators.len(), 6);
        assert_eq!(registry.validators["validator-5"].cluster_id, Some(0));
        assert_eq!(
            registry.validators["validator-5"].status,
            ValidatorStatus::Shadow
        );
    }

    fn finalized_score_vote(address: &str, block_hash: &str, block_index: u64) -> Vote {
        Vote {
            validator_address: address.to_string(),
            block_hash: block_hash.to_string(),
            block_index,
            epoch_number: 0,
            round_number: 1,
            signature: crate::crypto::pqc::PQCSignature {
                algorithm: PQCAlgorithm::FNDSA,
                signature_data: Vec::new(),
                message_hash: Vec::new(),
                public_key_id: String::new(),
                created_at: block_index,
            },
            signer_public_key: Vec::new(),
            timestamp: block_index,
        }
    }

    #[test]
    fn finalized_synergy_scores_ignore_noncanonical_qc_vote_subsets() {
        // Resolves the epoch validator set path, so it must exclude the tests
        // that override SYNERGY_EPOCH_VALIDATOR_SETS_FILE. Without this it
        // intermittently picked up another test's temp snapshot path and failed
        // with "epoch validator set file ... does not exist".
        let _env_lock = epoch_set_env_test_lock()
            .lock()
            .expect("epoch set env test lock should succeed");
        let _guard = DualQuorumConsensus::test_vote_tracking_guard();
        DualQuorumConsensus::reset_test_vote_tracking();
        let mut chain = BlockChain::new();
        let mut validators = test_validators(1, 3);
        for validator in &mut validators {
            validator.cluster_id = Some(0);
            validator.cluster_assignment_effective_height = Some(1);
        }
        let epoch_randomness = vec![42u8; 64];
        let primary_leaders =
            ProofOfSynergy::canonical_primary_leader_addresses(&validators, &epoch_randomness);
        let mut first_qcs = Vec::new();
        let mut alternate_qcs = Vec::new();

        for height in 1..=3 {
            let block_hash = format!("score-block-{height}");
            let expected_leader = primary_leaders[(height - 1) as usize].clone();
            let proposer = if height == 3 {
                primary_leaders[0].clone()
            } else {
                expected_leader
            };
            chain.add_block(Block {
                block_index: height,
                timestamp: height,
                transactions: Vec::new(),
                previous_hash: format!("score-block-{}", height.saturating_sub(1)),
                validator_id: proposer,
                nonce: height,
                hash: block_hash.clone(),
                transactions_root: String::new(),
                proposer_public_key: Vec::new(),
                block_signature: Vec::new(),
                block_signature_algorithm: "fndsa".to_string(),
                base_fee_per_gas_nwei: 0,
                gas_used: 0,
                gas_limit: 0,
                fee_market_version: 0,
            });
            let qc = QuorumCertificate {
                block_hash: block_hash.clone(),
                cluster_id: Some(0),
                epoch_number: 0,
                round_number: 1,
                aggregate_signature: Vec::new(),
                participant_bitmap: Vec::new(),
                cumulative_weight: 3.0,
                validation_quorum_met: true,
                cooperation_quorum_met: true,
                timestamp: height,
                votes: ["validator-1", "validator-2", "validator-3"]
                    .into_iter()
                    .map(|address| finalized_score_vote(address, &block_hash, height))
                    .collect(),
            };
            let mut alternate_qc = qc.clone();
            alternate_qc.round_number = 2;
            alternate_qc.aggregate_signature = vec![9, height as u8];
            alternate_qc.cumulative_weight = 2.0;
            alternate_qc.votes = ["validator-1", "validator-3"]
                .into_iter()
                .map(|address| finalized_score_vote(address, &block_hash, height))
                .collect();
            first_qcs.push(qc);
            alternate_qcs.push(alternate_qc);
        }

        for qc in first_qcs {
            DualQuorumConsensus::record_committed_qc_checked(qc).unwrap();
        }
        let first = ProofOfSynergy::finalized_synergy_scores_for_epoch(
            &chain,
            0,
            3,
            &validators,
            &epoch_randomness,
        )
        .unwrap();

        DualQuorumConsensus::reset_test_vote_tracking();
        for qc in alternate_qcs {
            DualQuorumConsensus::record_committed_qc_checked(qc).unwrap();
        }
        for (index, validator) in validators.iter_mut().enumerate() {
            validator.finalized_synergy_score_bps = 500 + index as u64;
        }
        let alternate = ProofOfSynergy::finalized_synergy_scores_for_epoch(
            &chain,
            0,
            3,
            &validators,
            &epoch_randomness,
        )
        .unwrap();

        assert_eq!(first, alternate);
        assert_eq!(first[&primary_leaders[0]], 10_000);
        assert_eq!(first[&primary_leaders[1]], 10_000);
        assert_eq!(first[&primary_leaders[2]], 0);
    }

    fn validator_membership_addresses(validators: &[Validator]) -> Vec<String> {
        validators
            .iter()
            .map(|validator| validator.address.clone())
            .collect()
    }

    #[test]
    fn next_block_membership_uses_replayed_registry_over_stale_manifest() {
        let _env_lock = epoch_set_env_test_lock()
            .lock()
            .expect("epoch set env test lock should succeed");
        let temp_dir = unique_proposal_cache_dir("next-block-epoch-validator-set");
        let snapshot_path = temp_dir.join("epoch-validator-sets.json");
        std::fs::write(
            &snapshot_path,
            serde_json::json!({
                "epoch_validator_sets": [
                    {
                        "chain_id": 1266,
                        "epoch_id": 7,
                        "validator_set_version": 3,
                        "effective_from_height": 100,
                        "effective_to_height": 199,
                        "active_validators": test_validator_addresses(1, 6),
                        "pending_validators": ["validator-7"],
                        "quorum_threshold": 5,
                        "validator_set_hash": "dynamic-validator-set-a"
                    },
                    {
                        "chain_id": 1266,
                        "epoch_id": 8,
                        "validator_set_version": 4,
                        "effective_from_height": 200,
                        "active_validators": test_validator_addresses(1, 7),
                        "pending_validators": [],
                        "quorum_threshold": 5,
                        "previous_set_hash": "dynamic-validator-set-a",
                        "validator_set_hash": "seven-validator-set"
                    }
                ]
            })
            .to_string(),
        )
        .expect("epoch validator set snapshot should be written");
        let _snapshot_guard =
            EnvVarGuard::set(EPOCH_VALIDATOR_SETS_ENV, &snapshot_path.to_string_lossy());

        let before_boundary =
            ProofOfSynergy::consensus_membership_for_next_block(test_validators(1, 7), 198)
                .expect("next height 199 should resolve to first epoch validator set");
        let at_boundary =
            ProofOfSynergy::consensus_membership_for_next_block(test_validators(1, 7), 199)
                .expect("next height 200 should resolve to seven-validator set");

        std::fs::remove_dir_all(temp_dir).ok();
        assert_eq!(
            validator_membership_addresses(&before_boundary),
            test_validator_addresses(1, 7),
            "replayed active registry membership must not be reduced by stale manifest evidence"
        );
        assert_eq!(
            validator_membership_addresses(&at_boundary),
            test_validator_addresses(1, 7),
            "replayed active registry membership must remain authoritative at the boundary"
        );
        assert_eq!(required_validator_quorum(before_boundary.len()), 5);
        assert_eq!(required_validator_quorum(at_boundary.len()), 5);
    }

    #[test]
    fn finalized_activation_application_fails_closed_without_fabricating_success() {
        let validator_manager = Arc::new(ValidatorManager::new());
        let token_manager = crate::token::TokenManager::new();
        let tx = Transaction::new(
            "validator-activation-failure".to_string(),
            "validator-activation-failure".to_string(),
            0,
            0,
            Vec::new(),
            1,
            21_000,
            Some(
                "validator_activation:{\"validator\":\"validator-activation-failure\"}".to_string(),
            ),
            "fndsa".to_string(),
        );
        let tx_hash = tx.hash();
        let block = Block::new(
            42,
            vec![tx],
            "parent-hash".to_string(),
            "validator-1".to_string(),
            1,
        );

        let error = ProofOfSynergy::apply_finalized_validator_activations(
            &block,
            &token_manager,
            &validator_manager,
        )
        .expect_err("malformed activation must fail closed");

        assert_eq!(
            error,
            format!(
                "validator activation application failed at finalized height 42 for transaction {tx_hash}: Validator activation is missing public key."
            )
        );
        assert!(
            validator_manager
                .get_validator("validator-activation-failure")
                .is_none(),
            "failed activation must not fabricate a registry entry"
        );
    }

    #[test]
    fn proposer_membership_fails_closed_for_incompatible_height_manifest() {
        let _env_lock = epoch_set_env_test_lock()
            .lock()
            .expect("epoch validator set env test lock should succeed");
        let temp_dir = unique_proposal_cache_dir("incompatible-proposer-membership");
        let snapshot_path = temp_dir.join("epoch-validator-sets.json");
        std::fs::write(
            &snapshot_path,
            serde_json::json!({
                "epoch_validator_sets": [{
                    "chain_id": 1266,
                    "epoch_id": 9,
                    "validator_set_version": 1,
                    "effective_from_height": 100,
                    "active_validators": ["validator-1"],
                    "quorum_threshold": 1,
                    "validator_set_hash": "incompatible-proposer-set",
                    "required_binary_version": "0.0.0-incompatible"
                }]
            })
            .to_string(),
        )
        .expect("incompatible epoch validator set should be written");
        let _snapshot_guard =
            EnvVarGuard::set(EPOCH_VALIDATOR_SETS_ENV, &snapshot_path.to_string_lossy());

        let error = ProofOfSynergy::consensus_membership_for_next_block(test_validators(1, 1), 99)
            .expect_err("incompatible height manifest must block proposer membership");

        std::fs::remove_dir_all(temp_dir).ok();
        assert!(
            error.contains("requires binary version 0.0.0-incompatible"),
            "unexpected error: {error}"
        );
    }

    fn catchup_decision(
        local_height: u64,
        best_validator_height: u64,
        final_height: Option<u64>,
        mesh_was_ready: bool,
        live_active_validators: usize,
        status_ready_validators: usize,
    ) -> CatchupReadinessDecision {
        ProofOfSynergy::catchup_mesh_readiness_after_sync(
            local_height,
            best_validator_height,
            final_height,
            mesh_was_ready,
            live_active_validators,
            4,
            status_ready_validators,
            4,
        )
    }

    #[test]
    fn ordinary_one_block_catchup_preserves_mesh_readiness() {
        let decision = catchup_decision(100, 101, Some(101), true, 5, 5);

        assert!(decision.preserve_mesh_readiness);
        assert!(!decision.reset_pacing_anchor_to_now);
        assert_eq!(decision.reason, "safe_one_block_head_catchup");
    }

    #[test]
    fn consensus_snapshot_clone_guard_blocks_large_live_chains() {
        assert!(ProofOfSynergy::consensus_chain_snapshot_clone_allowed(
            50_000, 50_000
        ));
        assert!(!ProofOfSynergy::consensus_chain_snapshot_clone_allowed(
            50_001, 50_000
        ));
    }

    #[test]
    fn deep_or_unverified_catchup_resets_mesh_readiness() {
        let deep = catchup_decision(100, 105, Some(105), true, 5, 5);
        assert!(!deep.preserve_mesh_readiness);
        assert!(deep.reset_pacing_anchor_to_now);
        assert_eq!(deep.reason, "deep_catchup");

        let unverified = catchup_decision(100, 101, None, true, 5, 5);
        assert!(!unverified.preserve_mesh_readiness);
        assert!(unverified.reset_pacing_anchor_to_now);
        assert_eq!(unverified.reason, "catchup_failed_or_unverified");
    }

    #[test]
    fn catchup_does_not_lower_quorum() {
        let insufficient_live = catchup_decision(100, 101, Some(101), true, 3, 5);
        assert!(!insufficient_live.preserve_mesh_readiness);
        assert!(insufficient_live.reset_pacing_anchor_to_now);
        assert_eq!(insufficient_live.reason, "insufficient_live_validators");

        let insufficient_status_ready = catchup_decision(100, 101, Some(101), true, 5, 3);
        assert!(!insufficient_status_ready.preserve_mesh_readiness);
        assert!(insufficient_status_ready.reset_pacing_anchor_to_now);
        assert_eq!(
            insufficient_status_ready.reason,
            "insufficient_status_ready_validators"
        );
    }

    #[test]
    fn catchup_does_not_allow_stale_proposal() {
        let stale = catchup_decision(100, 101, Some(100), true, 5, 5);

        assert!(!stale.preserve_mesh_readiness);
        assert!(stale.reset_pacing_anchor_to_now);
        assert_eq!(stale.reason, "catchup_did_not_reach_verified_head");
    }

    #[test]
    fn proposal_eligibility_gap_after_safe_catchup_under_launch_threshold() {
        let mesh_settle_secs = 3;
        let safe = catchup_decision(100, 101, Some(101), true, 5, 5);
        let unsafe_deep = catchup_decision(100, 104, Some(104), true, 5, 5);

        let safe_extra_settle_secs = if safe.preserve_mesh_readiness {
            0
        } else {
            mesh_settle_secs
        };
        let unsafe_extra_settle_secs = if unsafe_deep.preserve_mesh_readiness {
            0
        } else {
            mesh_settle_secs
        };

        assert_eq!(safe_extra_settle_secs, 0);
        assert!(
            safe_extra_settle_secs < 4,
            "safe catch-up must not add a full launch-failing settle interval"
        );
        assert_eq!(unsafe_extra_settle_secs, mesh_settle_secs);
    }

    fn active_validator_manager(address: &str) -> Arc<ValidatorManager> {
        let manager = Arc::new(ValidatorManager::new());
        let mut pqc_manager = PQCManager::new();
        let (public_key, private_key) = pqc_manager
            .generate_keypair(PQCAlgorithm::MLDSA65)
            .expect("test validator Aegis PQC key should generate");
        register_test_validator_signing_key(address, public_key.clone(), private_key);
        let encoded_public_key = format!(
            "{}:{}",
            consensus_algorithm_label(&public_key.algorithm),
            general_purpose::STANDARD.encode(&public_key.key_data)
        );
        let mut validator = Validator::new(
            address.to_string(),
            encoded_public_key,
            "Validator".to_string(),
            1_000,
        );
        validator.status = ValidatorStatus::Active;
        validator.activation_tx_hash = Some(format!("syntxn-test-{address}"));
        manager
            .registry
            .lock()
            .expect("registry lock should succeed")
            .validators
            .insert(address.to_string(), validator);
        if let Ok(mut registry) = VALIDATOR_MANAGER.registry.lock() {
            registry
                .validators
                .insert(address.to_string(), manager.get_validator(address).unwrap());
        }
        manager
    }

    fn signed_boundary_fixture(
        block_height: u64,
        qc_epoch: u64,
    ) -> (Arc<ValidatorManager>, Block, QuorumCertificate) {
        let validator_address = format!("validator-boundary-{block_height}-{qc_epoch}");
        let manager = active_validator_manager(&validator_address);
        let mut block = Block::new_with_timestamp(
            block_height,
            Vec::new(),
            format!("parent-{block_height}"),
            validator_address.clone(),
            block_height,
            1_784_000_000u64.saturating_add(block_height),
        );
        let (public_key, private_key) =
            load_local_validator_keypair_for_height(block_height, &validator_address, &manager)
                .expect("test proposer key should load");
        let signature = PQCManager::new()
            .sign(&private_key, block.hash.as_bytes())
            .expect("test proposer signature should be created");
        block.proposer_public_key = public_key.key_data;
        block.block_signature = signature.signature_data;
        block.block_signature_algorithm =
            consensus_algorithm_label(&public_key.algorithm).to_string();

        let vote = DualQuorumConsensus::create_vote_for_validator_with_manager(
            &validator_address,
            &block,
            qc_epoch,
            1,
            &manager,
        )
        .expect("test boundary vote should be created");
        let qc = QuorumCertificate {
            block_hash: block.hash.clone(),
            cluster_id: None,
            epoch_number: qc_epoch,
            round_number: 1,
            aggregate_signature: vec![1],
            participant_bitmap: vec![1],
            cumulative_weight: 1_000.0,
            validation_quorum_met: true,
            cooperation_quorum_met: true,
            timestamp: block.timestamp,
            votes: vec![vote],
        };
        DualQuorumConsensus::verify_commit_certificate_for_block_static(&block, &qc, &manager)
            .expect("test boundary QC should pass full Aegis verification");

        (manager, block, qc)
    }

    #[test]
    fn next_block_pacing_anchor_preserves_normal_block_timestamp_cadence() {
        let current_time = UNIX_EPOCH + Duration::from_millis(1_000_500);
        let anchor = ProofOfSynergy::next_block_pacing_anchor_for_time(1_000, 2, current_time);

        assert_eq!(
            anchor
                .duration_since(UNIX_EPOCH)
                .expect("anchor should be after epoch")
                .as_millis(),
            1_000_000
        );
    }

    #[test]
    fn next_block_pacing_anchor_adds_grace_after_delayed_commit() {
        let current_time = UNIX_EPOCH + Duration::from_millis(1_003_000);
        let anchor = ProofOfSynergy::next_block_pacing_anchor_for_time(1_000, 2, current_time);

        assert_eq!(
            anchor
                .duration_since(UNIX_EPOCH)
                .expect("anchor should be after epoch")
                .as_millis(),
            1_001_250
        );
    }

    #[test]
    fn post_commit_pacing_does_not_add_full_block_interval_after_vote_collection() {
        let block_time_secs = 2;
        let proposal_timestamp = 1_000;
        let commit_after_vote_collection = UNIX_EPOCH + Duration::from_millis(1_003_000);
        let anchor = ProofOfSynergy::next_block_pacing_anchor_for_time(
            proposal_timestamp,
            block_time_secs,
            commit_after_vote_collection,
        );

        let next_proposal_at = anchor + Duration::from_secs(block_time_secs);
        assert_eq!(
            next_proposal_at
                .duration_since(commit_after_vote_collection)
                .expect("next proposal should be after the delayed commit")
                .as_millis(),
            POST_COMMIT_PARENT_PROPAGATION_GRACE_MILLIS as u128,
            "post-commit pacing must wait only parent propagation grace, not another full block interval"
        );
    }

    #[test]
    fn bounded_consensus_timestamp_preserves_target_cadence_when_on_time() {
        assert_eq!(
            ProofOfSynergy::bounded_consensus_timestamp(1_000, 2, 1_001),
            1_002
        );
    }

    #[test]
    fn bounded_consensus_timestamp_catches_up_when_production_is_late() {
        assert_eq!(
            ProofOfSynergy::bounded_consensus_timestamp(1_000, 2, 1_030),
            1_030
        );
    }

    #[test]
    fn bounded_consensus_timestamp_reanchors_large_wall_clock_gap() {
        let previous_timestamp = 1_000;
        let next_timestamp =
            ProofOfSynergy::bounded_consensus_timestamp(previous_timestamp, 4, 2_000);

        assert_eq!(next_timestamp, 2_000);
    }

    #[test]
    fn bounded_consensus_timestamp_does_not_repeat_synthetic_catchup_steps() {
        let first_after_recovery = ProofOfSynergy::bounded_consensus_timestamp(1_000, 2, 2_000);
        let next_block =
            ProofOfSynergy::bounded_consensus_timestamp(first_after_recovery, 2, 2_002);

        assert_eq!(first_after_recovery, 2_000);
        assert_eq!(next_block.saturating_sub(first_after_recovery), 2);
    }

    #[test]
    fn bounded_consensus_timestamp_reanchors_catastrophically_stale_header_time() {
        let wall_clock_timestamp = 1_782_703_600;

        assert_eq!(
            ProofOfSynergy::bounded_consensus_timestamp(31_200, 2, wall_clock_timestamp),
            wall_clock_timestamp
        );
    }

    #[test]
    fn proposer_penalty_is_skipped_when_penalization_is_disabled() {
        let validator_address = "synv1proposer";
        let manager = active_validator_manager(validator_address);
        let before = manager
            .get_validator(validator_address)
            .expect("validator should exist");

        ProofOfSynergy::maybe_apply_proposer_penalty(false, &manager, validator_address);

        let after = manager
            .get_validator(validator_address)
            .expect("validator should exist");
        assert_eq!(after.reputation_score, before.reputation_score);
        assert_eq!(after.synergy_score, before.synergy_score);
    }

    #[test]
    fn leader_timeout_penalty_is_skipped_when_penalization_is_disabled() {
        let validator_address = "synv1leader";
        let manager = active_validator_manager(validator_address);
        let before = manager
            .get_validator(validator_address)
            .expect("validator should exist");

        ProofOfSynergy::maybe_apply_leader_timeout_penalty(
            false,
            &manager,
            validator_address,
            7,
            1,
        );

        let after = manager
            .get_validator(validator_address)
            .expect("validator should exist");
        assert_eq!(after.missed_blocks, before.missed_blocks);
        assert_eq!(after.missed_vote_window, before.missed_vote_window);
        assert_eq!(after.uptime_percentage, before.uptime_percentage);
    }

    #[test]
    fn effective_leader_timeout_covers_enforced_vote_window() {
        assert_eq!(
            ProofOfSynergy::effective_leader_timeout_secs_for_config(2, 4, 2),
            4,
            "configured leader timeout must not expire while the enforced vote window is still open"
        );
        assert_eq!(
            ProofOfSynergy::effective_leader_timeout_secs_for_config(2, 0, 2),
            4,
            "auto leader timeout must include the block slot and vote window"
        );
        assert_eq!(
            ProofOfSynergy::effective_leader_timeout_secs_for_config(1, 2, 1),
            2,
            "one-second launch vote windows must allow sub-five-second missed-slot recovery"
        );
        assert_eq!(
            ProofOfSynergy::effective_leader_timeout_secs_for_config(2, 12, 2),
            12,
            "operator-configured longer leader timeout should be preserved"
        );
    }

    #[test]
    fn view_offset_does_not_advance_during_active_vote_window() {
        let last_block_height = 56_353;
        let last_block_timestamp = 1_779_619_000;
        let block_time_secs = 2;
        let effective_leader_timeout_secs =
            ProofOfSynergy::effective_leader_timeout_secs_for_config(block_time_secs, 4, 2);

        assert_eq!(
            ProofOfSynergy::deterministic_view_offset_for_next_block_slot(
                last_block_height,
                last_block_timestamp,
                block_time_secs,
                effective_leader_timeout_secs,
                last_block_timestamp + block_time_secs + MIN_LAUNCH_VOTE_TIMEOUT_SECS
            ),
            0,
            "peers must not rotate away while the scheduled proposer can still gather launch-quorum votes"
        );
        assert_eq!(
            ProofOfSynergy::deterministic_view_offset_for_next_block_slot(
                last_block_height,
                last_block_timestamp,
                block_time_secs,
                effective_leader_timeout_secs,
                last_block_timestamp + block_time_secs + effective_leader_timeout_secs
            ),
            1
        );
    }

    #[test]
    fn next_block_epoch_transitions_at_boundary_only_once() {
        assert_eq!(ProofOfSynergy::epoch_for_next_block(998, 1000), 0);
        assert_eq!(ProofOfSynergy::epoch_for_next_block(999, 1000), 0);
        assert_eq!(ProofOfSynergy::epoch_for_next_block(1000, 1000), 1);

        let mut current_epoch = 0;
        let target_epoch = ProofOfSynergy::epoch_for_next_block(1000, 1000);
        while current_epoch < target_epoch {
            current_epoch += 1;
        }
        assert_eq!(current_epoch, 1);

        let same_boundary_epoch = ProofOfSynergy::epoch_for_next_block(1001, 1000);
        while current_epoch < same_boundary_epoch {
            current_epoch += 1;
        }
        assert_eq!(current_epoch, 1);
    }

    #[test]
    fn deterministic_view_offset_advances_after_leader_timeout() {
        assert_eq!(
            ProofOfSynergy::deterministic_view_offset_for_time(4_983, 20, 4_983),
            0
        );
        assert_eq!(
            ProofOfSynergy::deterministic_view_offset_for_time(4_983, 20, 5_002),
            0
        );
        assert_eq!(
            ProofOfSynergy::deterministic_view_offset_for_time(4_983, 20, 5_003),
            1
        );
        assert_eq!(
            ProofOfSynergy::deterministic_view_offset_for_time(4_983, 20, 5_044),
            3
        );
    }

    #[test]
    fn deterministic_view_offset_keeps_genesis_on_primary_leader() {
        assert_eq!(
            ProofOfSynergy::deterministic_view_offset_for_next_block_slot(0, 4_983, 2, 20, 4_983),
            0
        );
        assert_eq!(
            ProofOfSynergy::deterministic_view_offset_for_next_block_slot(0, 4_983, 2, 20, 5_500),
            0
        );
        assert_eq!(
            ProofOfSynergy::deterministic_view_offset_for_next_block_slot(1, 4_983, 2, 20, 5_500),
            ProofOfSynergy::deterministic_view_offset_for_time(4_985, 20, 5_500)
        );
    }

    #[test]
    fn view_timeout_starts_at_next_block_slot_not_previous_block_timestamp() {
        let last_block_height = 54_443;
        let last_block_timestamp = 1_779_611_545;
        let block_time_secs = 2;
        let leader_timeout_secs = 4;

        assert_eq!(
            ProofOfSynergy::deterministic_view_offset_for_time(
                last_block_timestamp,
                leader_timeout_secs,
                last_block_timestamp + leader_timeout_secs
            ),
            1,
            "anchoring at the previous block timestamp rotates exactly when a healthy next block is due"
        );
        assert_eq!(
            ProofOfSynergy::deterministic_view_offset_for_next_block_slot(
                last_block_height,
                last_block_timestamp,
                block_time_secs,
                leader_timeout_secs,
                last_block_timestamp + leader_timeout_secs
            ),
            0,
            "the primary leader must keep its full timeout after the next block slot opens"
        );
        assert_eq!(
            ProofOfSynergy::deterministic_view_offset_for_next_block_slot(
                last_block_height,
                last_block_timestamp,
                block_time_secs,
                leader_timeout_secs,
                last_block_timestamp + block_time_secs + leader_timeout_secs
            ),
            1
        );
    }

    #[test]
    fn same_height_view_offset_uses_shared_canonical_timestamp() {
        let current_timestamp = 10_061;
        let leader_timeout_secs = 20;
        let canonical_tip_timestamp = 9_500;

        let local_observed_a = 10_000;
        let local_observed_b = 10_047;
        let unsafe_local_offset_a = ProofOfSynergy::deterministic_view_offset_for_time(
            local_observed_a,
            leader_timeout_secs,
            current_timestamp,
        );
        let unsafe_local_offset_b = ProofOfSynergy::deterministic_view_offset_for_time(
            local_observed_b,
            leader_timeout_secs,
            current_timestamp,
        );
        assert_ne!(
            unsafe_local_offset_a, unsafe_local_offset_b,
            "local tip-observation anchors can diverge across validators"
        );

        let shared_offset_a = ProofOfSynergy::deterministic_view_offset_for_next_block_slot(
            40_536,
            canonical_tip_timestamp,
            2,
            leader_timeout_secs,
            current_timestamp,
        );
        let shared_offset_b = ProofOfSynergy::deterministic_view_offset_for_next_block_slot(
            40_536,
            canonical_tip_timestamp,
            2,
            leader_timeout_secs,
            current_timestamp,
        );

        assert_eq!(shared_offset_a, shared_offset_b);
    }

    #[test]
    fn same_height_view_offset_advances_after_shared_and_local_timeout() {
        let leader_timeout_secs = 4;
        let canonical_tip_timestamp = 1_000;
        let block_time_secs = 2;
        let current_timestamp = canonical_tip_timestamp + block_time_secs + leader_timeout_secs;
        let shared_view_offset = ProofOfSynergy::deterministic_view_offset_for_next_block_slot(
            40_536,
            canonical_tip_timestamp,
            block_time_secs,
            leader_timeout_secs,
            current_timestamp,
        );
        let current_time = UNIX_EPOCH + Duration::from_secs(current_timestamp);
        let observed_tip_at = current_time - Duration::from_secs(leader_timeout_secs);

        assert_eq!(shared_view_offset, 1);
        assert_eq!(
            ProofOfSynergy::cap_view_offset_by_tip_observation(
                shared_view_offset,
                observed_tip_at,
                leader_timeout_secs,
                current_time,
            ),
            1,
            "leader selection must rotate after both the canonical view timeout and the local observation timeout have elapsed"
        );
    }

    #[test]
    fn leader_timeout_wait_uses_tip_observation_time_not_header_timestamp() {
        let current_time = UNIX_EPOCH + Duration::from_secs(10_000);
        let observed_tip_at = current_time - Duration::from_millis(750);
        let stale_header_timestamp = 9_100u64;

        let elapsed = ProofOfSynergy::leader_wait_elapsed_since_tip_observed_at(
            observed_tip_at,
            current_time,
        );

        assert_eq!(elapsed, Duration::from_millis(750));
        assert!(
            current_time
                .duration_since(UNIX_EPOCH + Duration::from_secs(stale_header_timestamp))
                .unwrap()
                > Duration::from_secs(800)
        );
    }

    #[test]
    fn shared_view_offset_is_capped_by_local_tip_observation_window() {
        let now = UNIX_EPOCH + Duration::from_secs(10_100);
        let observed_tip_at = now - Duration::from_secs(1);

        assert_eq!(
            ProofOfSynergy::cap_view_offset_by_tip_observation(4, observed_tip_at, 4, now),
            0,
            "a locally fresh tip must not skip through leaders just because its block timestamp is stale"
        );

        let observed_tip_at = now - Duration::from_secs(4);
        assert_eq!(
            ProofOfSynergy::cap_view_offset_by_tip_observation(4, observed_tip_at, 4, now),
            1
        );
    }

    #[test]
    fn previous_qc_uses_epoch_boundary_block_on_mid_epoch_restart() {
        let _guard = DualQuorumConsensus::test_vote_tracking_guard();
        DualQuorumConsensus::reset_test_vote_tracking();
        let mut chain = BlockChain::new();
        let (manager, boundary_block, qc) = signed_boundary_fixture(1_000, 0);
        let boundary_hash = boundary_block.hash.clone();
        chain.add_block(boundary_block);
        DualQuorumConsensus::record_committed_qc_checked(qc).unwrap();
        chain.add_block(Block {
            block_index: 1026,
            timestamp: 1026,
            transactions: Vec::new(),
            previous_hash: "1025".to_string(),
            validator_id: "validator-b".to_string(),
            nonce: 1026,
            hash: "mid-epoch-1026".to_string(),
            transactions_root: String::new(),
            proposer_public_key: Vec::new(),
            block_signature: vec![1, 2, 6],
            block_signature_algorithm: "fndsa".to_string(),
            base_fee_per_gas_nwei: 0,
            gas_used: 0,
            gas_limit: 0,
            fee_market_version: 0,
        });

        let previous_qc =
            ProofOfSynergy::get_previous_quorum_certificate(&chain, 1, 1000, &manager).unwrap();

        assert_eq!(previous_qc.block_hash, boundary_hash);
        assert_eq!(previous_qc.epoch_number, 0);
        assert_eq!(previous_qc.aggregate_signature, vec![1]);
    }

    #[test]
    fn previous_qc_loads_epoch_boundary_from_archive_after_hot_retention() {
        let _guard = DualQuorumConsensus::test_vote_tracking_guard();
        DualQuorumConsensus::reset_test_vote_tracking();
        let _retention = EnvVarGuard::set("SYNERGY_COMMITTED_QC_HOT_RETENTION_BLOCKS", "3");
        let mut chain = BlockChain::new();
        let (manager, boundary_block, boundary_qc) = signed_boundary_fixture(1_000, 0);
        let boundary_hash = boundary_block.hash.clone();
        chain.add_block(boundary_block);
        DualQuorumConsensus::record_committed_qc_checked(boundary_qc.clone()).unwrap();

        for height in 1_001..=1_004 {
            let mut later_qc = boundary_qc.clone();
            let later_hash = format!("post-boundary-{height}");
            later_qc.block_hash = later_hash.clone();
            later_qc.votes[0].block_hash = later_hash;
            later_qc.votes[0].block_index = height;
            DualQuorumConsensus::record_committed_qc_checked(later_qc).unwrap();
        }

        assert!(
            DualQuorumConsensus::committed_qc_for_block_hash(&boundary_hash).is_none(),
            "fixture must evict the boundary QC from the hot store"
        );

        let previous_qc =
            ProofOfSynergy::get_previous_quorum_certificate(&chain, 1, 1_000, &manager).unwrap();

        assert_eq!(previous_qc.block_hash, boundary_hash);
        assert_eq!(previous_qc.epoch_number, 0);
    }

    #[test]
    fn previous_qc_normalizes_historical_legacy_epoch_boundaries_through_cutoff() {
        let _guard = DualQuorumConsensus::test_vote_tracking_guard();
        DualQuorumConsensus::reset_test_vote_tracking();
        let mut chain = BlockChain::new();
        let boundary_height = 1_048_000;
        let (manager, boundary_block, qc) = signed_boundary_fixture(boundary_height, 1_048);
        let boundary_hash = boundary_block.hash.clone();
        chain.add_block(boundary_block);
        DualQuorumConsensus::record_committed_qc_checked(qc).unwrap();

        let previous_qc =
            ProofOfSynergy::get_previous_quorum_certificate(&chain, 1_048, 1_000, &manager)
                .unwrap();

        assert_eq!(previous_qc.block_hash, boundary_hash.as_str());
        assert_eq!(previous_qc.epoch_number, 1_047);
    }

    #[test]
    fn legacy_epoch_migration_accepts_only_positive_canonical_boundaries_through_cutoff() {
        assert!(!ProofOfSynergy::is_migratable_legacy_boundary_epoch(
            0, 1_000, 1
        ));
        assert!(!ProofOfSynergy::is_migratable_legacy_boundary_epoch(
            999, 1_000, 1
        ));
        assert!(ProofOfSynergy::is_migratable_legacy_boundary_epoch(
            1_000, 1_000, 1
        ));
        assert!(ProofOfSynergy::is_migratable_legacy_boundary_epoch(
            ONE_BASED_EPOCH_MIGRATION_CUTOFF_HEIGHT,
            1_000,
            1_052,
        ));
        assert!(!ProofOfSynergy::is_migratable_legacy_boundary_epoch(
            ONE_BASED_EPOCH_MIGRATION_CUTOFF_HEIGHT + 1_000,
            1_000,
            1_053,
        ));
        assert!(!ProofOfSynergy::is_migratable_legacy_boundary_epoch(
            1_000, 500, 2
        ));
    }

    #[test]
    fn previous_qc_rejects_future_legacy_epoch_boundary_labels() {
        let _guard = DualQuorumConsensus::test_vote_tracking_guard();
        DualQuorumConsensus::reset_test_vote_tracking();
        let manager = active_validator_manager("validator-future-boundary");
        let mut chain = BlockChain::new();
        let future_boundary_height = ONE_BASED_EPOCH_MIGRATION_CUTOFF_HEIGHT + 1_000;
        chain.add_block(Block {
            block_index: future_boundary_height,
            timestamp: 1_784_030_631,
            transactions: Vec::new(),
            previous_hash: "future-parent".to_string(),
            validator_id: "validator-a".to_string(),
            nonce: future_boundary_height,
            hash: "future-boundary-after-cutoff".to_string(),
            transactions_root: String::new(),
            proposer_public_key: Vec::new(),
            block_signature: vec![9, 9, 9],
            block_signature_algorithm: "fndsa".to_string(),
            base_fee_per_gas_nwei: 0,
            gas_used: 0,
            gas_limit: 0,
            fee_market_version: 0,
        });
        DualQuorumConsensus::record_committed_qc_checked(QuorumCertificate {
            block_hash: "future-boundary-after-cutoff".to_string(),
            cluster_id: None,
            epoch_number: 1_053,
            round_number: 1,
            aggregate_signature: vec![9, 9, 9],
            participant_bitmap: Vec::new(),
            cumulative_weight: 4.0,
            validation_quorum_met: true,
            cooperation_quorum_met: true,
            timestamp: 1_784_030_631,
            votes: Vec::new(),
        })
        .unwrap();

        let error = ProofOfSynergy::get_previous_quorum_certificate(&chain, 1_053, 1_000, &manager)
            .expect_err("future off-by-one boundary QC must fail closed");

        assert!(error.contains("boundary QC epoch 1053"));
        assert!(error.contains("block 1053000 epoch 1052"));
    }

    #[test]
    fn pre_activation_transition_uses_legacy_qc_hash_v2_without_next_epoch_seed() {
        let _guard = DualQuorumConsensus::test_vote_tracking_guard();
        DualQuorumConsensus::reset_test_vote_tracking();
        let mut chain = BlockChain::new();
        let (manager, boundary_block, qc) = signed_boundary_fixture(1_000, 0);
        chain.add_block(boundary_block);
        DualQuorumConsensus::record_committed_qc_checked(qc).unwrap();
        chain.add_block(Block {
            block_index: 1026,
            timestamp: 1026,
            transactions: Vec::new(),
            previous_hash: "1025".to_string(),
            validator_id: "validator-b".to_string(),
            nonce: 1026,
            hash: "mid-epoch-1026".to_string(),
            transactions_root: String::new(),
            proposer_public_key: Vec::new(),
            block_signature: vec![1, 2, 6],
            block_signature_algorithm: "fndsa".to_string(),
            base_fee_per_gas_nwei: 0,
            gas_used: 0,
            gas_limit: 0,
            fee_market_version: 0,
        });

        let evidence =
            ProofOfSynergy::epoch_randomness_evidence_for_transition(&chain, 1, 1_000, &manager)
                .expect("an uninterrupted pre-activation transition must derive the v2 seed");
        let boundary_qc =
            ProofOfSynergy::get_previous_quorum_certificate(&chain, 1, 1_000, &manager)
                .expect("the finalized boundary QC should be available");
        let expected = ProofOfSynergy::legacy_deterministic_epoch_randomness_from_qc(&boundary_qc);
        assert_eq!(evidence.scheme, LEGACY_QC_HASH_RANDOMNESS_SCHEME);
        assert!(evidence.boundary_qc_verified);
        assert_eq!(evidence.assignment_effective_height, 1_001);
        assert_eq!(
            evidence.randomness, expected,
            "pre-cutover randomness must exactly match the v19.0.42-v19.0.44 leader schedule"
        );
        let restarted =
            ProofOfSynergy::epoch_randomness_evidence_for_epoch(&chain, 1, 1_000, &manager)
                .expect("a current-epoch restart must reproduce the boundary-QC seed");
        assert_eq!(restarted.randomness, expected);
    }

    #[test]
    fn legacy_pre_cutover_rotation_matches_the_live_six_validator_fleet() {
        let qc = QuorumCertificate {
            block_hash: "epoch-1143-boundary".to_string(),
            cluster_id: Some(0),
            epoch_number: 1_142,
            round_number: 1,
            aggregate_signature: vec![0x00, 0x00, 0x03, 0x90],
            participant_bitmap: vec![0x3f],
            cumulative_weight: 6.0,
            validation_quorum_met: true,
            cooperation_quorum_met: true,
            timestamp: 1_784_286_428,
            votes: Vec::new(),
        };
        let randomness = ProofOfSynergy::legacy_deterministic_epoch_randomness_from_qc(&qc);
        assert_eq!(
            hex::encode(&randomness),
            "0bd3ecc622aa0d52bde097a023574f69c5b0499709565912db09b432a6e0bd68e2e5c36e117c054fcc5205460c780c185fc7ef8074b13681c5f107f2906d337c"
        );

        let addresses = [
            "synv11qen9x0g9p0f2pqznpqzfrwkrgnsussdwmvs",
            "synv11mka64uz049aekwhdvfrq6dvh75d0k7kmdp5",
            "synv11zghr6nsm3ajl57ywxasw9mr5f844slq4mwx",
            "synv11kguave5fpdpm9hru4acfvw0hcp4fcc7zv9f",
            "synv11e3ephsarcw6mey0fx5xtnygg2ewegnum4re",
            "synv11s4wc6l4kg4jr0k5meg42cyzxa03cf863srt",
        ];
        let validators = addresses
            .iter()
            .map(|address| test_validator(address))
            .collect::<Vec<_>>();
        assert_eq!(
            ProofOfSynergy::canonical_primary_leader_addresses(&validators, &randomness),
            vec![
                addresses[1].to_string(),
                addresses[3].to_string(),
                addresses[0].to_string(),
                addresses[4].to_string(),
                addresses[2].to_string(),
                addresses[5].to_string(),
            ]
        );
    }

    #[test]
    fn canonical_boundary_seed_ignores_valid_qc_encoding_and_restart_height() {
        let _guard = DualQuorumConsensus::test_vote_tracking_guard();
        DualQuorumConsensus::reset_test_vote_tracking();
        let (manager, boundary_block, qc) = signed_boundary_fixture(1_000, 0);
        let mut alternate_qc = qc.clone();
        alternate_qc.round_number = 2;
        alternate_qc.timestamp = alternate_qc.timestamp.saturating_add(17);
        alternate_qc.aggregate_signature = vec![9, 8, 7, 6];

        DualQuorumConsensus::verify_commit_certificate_for_block_static(
            &boundary_block,
            &qc,
            &manager,
        )
        .expect("first valid QC encoding should verify");
        DualQuorumConsensus::verify_commit_certificate_for_block_static(
            &boundary_block,
            &alternate_qc,
            &manager,
        )
        .expect("alternate valid QC encoding should verify");

        let seed_a = ProofOfSynergy::deterministic_epoch_randomness_from_boundary(
            1_264,
            1,
            &boundary_block.hash,
        );
        let seed_b = ProofOfSynergy::deterministic_epoch_randomness_from_boundary(
            1_264,
            1,
            &alternate_qc.block_hash,
        );
        assert_eq!(seed_a, seed_b);

        let mut chain = BlockChain::new();
        chain.add_block(boundary_block);
        DualQuorumConsensus::record_committed_qc_checked(qc).unwrap();
        let first =
            ProofOfSynergy::canonical_epoch_boundary_evidence(&chain, 1, 1_000, &manager).unwrap();
        let second =
            ProofOfSynergy::canonical_epoch_boundary_evidence(&chain, 1, 1_000, &manager).unwrap();
        assert_eq!(first.randomness, second.randomness);
        assert_eq!(first.assignment_effective_height, 1_001);
        assert_eq!(first.boundary_height, 1_000);
    }

    #[test]
    fn pre_activation_current_epoch_restart_repairs_the_v19_0_45_cluster_seed() {
        let _guard = DualQuorumConsensus::test_vote_tracking_guard();
        DualQuorumConsensus::reset_test_vote_tracking();
        let mut chain = BlockChain::new();
        let (manager, boundary_block, qc) = signed_boundary_fixture(1_000, 0);
        chain.add_block(boundary_block);
        DualQuorumConsensus::record_committed_qc_checked(qc.clone()).unwrap();

        let expected = ProofOfSynergy::legacy_deterministic_epoch_randomness_from_qc(&qc);
        let expected_seed = hex::encode(&expected);
        let mut entropy_beacon = EntropyBeacon::new(Arc::new(Mutex::new(PQCManager::new())));
        let incompatible_cluster_seed = hex::encode(entropy_beacon.generate_epoch_randomness(&qc));
        assert_eq!(
            incompatible_cluster_seed,
            hex::encode(ProofOfSynergy::legacy_cluster_randomness_from_qc(&qc)),
            "cluster assignments must retain the v19.0.44 entropy-beacon seed"
        );
        {
            let mut registry = manager
                .registry
                .lock()
                .expect("validator registry lock should succeed");
            registry.leader_randomness_epoch = Some(1);
            registry.leader_randomness_seed = Some(incompatible_cluster_seed.clone());
            for validator in registry.validators.values_mut() {
                validator.cluster_assignment_epoch = Some(1);
                validator.cluster_assignment_seed = Some(incompatible_cluster_seed.clone());
            }
        }

        let first = ProofOfSynergy::epoch_randomness_evidence_for_epoch(&chain, 1, 1_000, &manager)
            .expect("current-epoch restart should recover the exact boundary-QC leader seed");
        let second = ProofOfSynergy::deterministic_epoch_randomness(&chain, 1_999, 1_000, &manager)
            .expect("a later restart in the same epoch should reproduce the boundary-QC seed");
        assert_eq!(first.scheme, LEGACY_QC_HASH_RANDOMNESS_SCHEME);
        assert!(first.boundary_qc_verified);
        assert!(first.registry_migrated);
        assert_ne!(expected_seed, incompatible_cluster_seed);
        assert_eq!(first.randomness, expected);
        assert_eq!(first.randomness, second);
        let registry = manager
            .registry
            .lock()
            .expect("validator registry lock should succeed");
        assert_eq!(registry.leader_randomness_epoch, Some(1));
        assert_eq!(
            registry.leader_randomness_seed.as_deref(),
            Some(expected_seed.as_str())
        );
    }

    #[test]
    fn pre_activation_cluster_reconciliation_preserves_legacy_seed_compatibility() {
        let _guard = DualQuorumConsensus::test_vote_tracking_guard();
        DualQuorumConsensus::reset_test_vote_tracking();
        let mut chain = BlockChain::new();
        let (manager, boundary_block, qc) = signed_boundary_fixture(1_000, 0);
        chain.add_block(boundary_block);
        DualQuorumConsensus::record_committed_qc_checked(qc.clone()).unwrap();

        let legacy_seed =
            hex::encode(ProofOfSynergy::legacy_deterministic_epoch_randomness_from_qc(&qc));
        let legacy_cluster_seed =
            hex::encode(ProofOfSynergy::legacy_cluster_randomness_from_qc(&qc));
        {
            let mut registry = manager
                .registry
                .lock()
                .expect("validator registry lock should succeed");
            for validator in registry.validators.values_mut() {
                validator.cluster_assignment_epoch = Some(1);
                validator.cluster_assignment_seed = Some(legacy_cluster_seed.clone());
            }
        }

        reconcile_validator_registry_clusters_from_finalized_chain(&manager, &chain, 1_001)
            .expect("cluster reconciliation should migrate the old leader seed first");

        let leader =
            ProofOfSynergy::epoch_randomness_evidence_for_epoch(&chain, 1, 1_000, &manager)
                .expect("leader schedule should retain the pre-activation v2 seed");
        let cluster = ProofOfSynergy::cluster_epoch_randomness_evidence(&chain, 1, 1_000, &manager)
            .expect("cluster assignment should remain legacy-compatible before cutover");
        assert_eq!(leader.scheme, LEGACY_QC_HASH_RANDOMNESS_SCHEME);
        assert_eq!(hex::encode(&leader.randomness), legacy_seed);
        assert_eq!(cluster.scheme, LEGACY_CLUSTER_QC_HASH_RANDOMNESS_SCHEME);
        assert_eq!(hex::encode(&cluster.randomness), legacy_cluster_seed);
        assert_ne!(leader.randomness, cluster.randomness);
        let cluster_seed = hex::encode(&cluster.randomness);

        let registry = manager
            .registry
            .lock()
            .expect("validator registry lock should succeed");
        assert_eq!(registry.leader_randomness_epoch, Some(1));
        assert_eq!(
            registry.leader_randomness_seed.as_deref(),
            Some(legacy_seed.as_str())
        );
        assert!(registry.validators.values().all(|validator| {
            validator.cluster_assignment_seed.as_deref() == Some(cluster_seed.as_str())
        }));
    }

    #[test]
    fn pre_activation_leader_seed_repair_is_reported_for_persistence() {
        let _guard = DualQuorumConsensus::test_vote_tracking_guard();
        DualQuorumConsensus::reset_test_vote_tracking();
        let mut chain = BlockChain::new();
        let (manager, boundary_block, qc) = signed_boundary_fixture(1_000, 0);
        chain.add_block(boundary_block);
        DualQuorumConsensus::record_committed_qc_checked(qc.clone()).unwrap();

        let legacy_seed =
            hex::encode(ProofOfSynergy::legacy_deterministic_epoch_randomness_from_qc(&qc));
        let legacy_cluster_seed =
            hex::encode(ProofOfSynergy::legacy_cluster_randomness_from_qc(&qc));
        {
            let mut registry = manager
                .registry
                .lock()
                .expect("validator registry lock should succeed");
            registry.reorganize_clusters_for_epoch_with_seed(1, &legacy_cluster_seed, 1_001);
            registry.leader_randomness_epoch = None;
            registry.leader_randomness_seed = None;
        }

        let evidence =
            ProofOfSynergy::epoch_randomness_evidence_for_epoch(&chain, 1, 1_000, &manager)
                .expect("legacy leader seed should be repaired from the boundary QC");
        assert!(evidence.registry_migrated);
        let registry = manager
            .registry
            .lock()
            .expect("validator registry lock should succeed");
        assert_eq!(registry.leader_randomness_epoch, Some(1));
        assert_eq!(
            registry.leader_randomness_seed.as_deref(),
            Some(legacy_seed.as_str())
        );
    }

    #[test]
    fn cluster_cutover_is_fixed_and_domain_separated_from_leader_randomness() {
        assert_eq!(
            epoch_start_height(CLUSTER_RANDOMNESS_V3_ACTIVATION_EPOCH, 1_000),
            1_150_001
        );
        assert!(!ProofOfSynergy::boundary_hash_cluster_v3_active_for_epoch(
            1_149, 1_000
        ));
        assert!(ProofOfSynergy::boundary_hash_cluster_v3_active_for_epoch(
            1_150, 1_000
        ));
        assert!(!ProofOfSynergy::boundary_hash_v3_active_for_epoch(
            1_150, 1_000
        ));

        let _guard = DualQuorumConsensus::test_vote_tracking_guard();
        DualQuorumConsensus::reset_test_vote_tracking();
        let (manager, boundary_block, qc) = signed_boundary_fixture(1_150_000, 1_149);
        let mut chain = BlockChain::new();
        chain.add_block(boundary_block.clone());
        DualQuorumConsensus::record_committed_qc_checked(qc.clone()).unwrap();
        let legacy_leader_seed =
            hex::encode(ProofOfSynergy::legacy_deterministic_epoch_randomness_from_qc(&qc));
        {
            let mut registry = manager
                .registry
                .lock()
                .expect("validator registry lock should succeed");
            registry.leader_randomness_epoch = Some(1_150);
            registry.leader_randomness_seed = Some(legacy_leader_seed.clone());
        }

        let leader =
            ProofOfSynergy::epoch_randomness_evidence_for_epoch(&chain, 1_150, 1_000, &manager)
                .expect("leader schedule should remain legacy before its later cutover");
        let cluster =
            ProofOfSynergy::cluster_epoch_randomness_evidence(&chain, 1_150, 1_000, &manager)
                .expect("cluster assignment should use verified boundary evidence at cutover");
        assert_eq!(leader.scheme, LEGACY_QC_HASH_RANDOMNESS_SCHEME);
        assert_eq!(hex::encode(&leader.randomness), legacy_leader_seed);
        assert_eq!(cluster.scheme, BOUNDARY_HASH_CLUSTER_RANDOMNESS_SCHEME);
        assert!(cluster.boundary_qc_verified);
        assert_eq!(cluster.boundary_height, Some(1_150_000));
        assert_eq!(cluster.boundary_block_hash, Some(boundary_block.hash));
        assert_ne!(leader.randomness, cluster.randomness);

        let leader_v3 = ProofOfSynergy::deterministic_epoch_randomness_from_boundary(
            1266,
            1_150,
            cluster.boundary_block_hash.as_deref().unwrap(),
        );
        assert_ne!(leader_v3, cluster.randomness);
    }

    #[test]
    fn stale_registry_after_pre_activation_boundary_is_repaired_from_the_qc() {
        let _guard = DualQuorumConsensus::test_vote_tracking_guard();
        DualQuorumConsensus::reset_test_vote_tracking();
        let boundary_height = 1_132_000;
        let current_height = 1_132_143;
        let (manager, boundary_block, qc) = signed_boundary_fixture(boundary_height, 1_131);
        let mut chain = BlockChain::new();
        chain.add_block(boundary_block);
        DualQuorumConsensus::record_committed_qc_checked(qc.clone()).unwrap();

        {
            let mut registry = manager
                .registry
                .lock()
                .expect("validator registry lock should succeed");
            registry.epoch_length = 30_000;
            registry.current_epoch = 650;
            for validator in registry.validators.values_mut() {
                validator.cluster_assignment_epoch = Some(650);
            }
        }

        assert!(reconcile_validator_registry_clusters_from_finalized_chain(
            &manager,
            &chain,
            current_height,
        )
        .expect("stale pre-activation registry state must be repaired from the boundary QC"));
        let expected_cluster_seed =
            hex::encode(ProofOfSynergy::legacy_cluster_randomness_from_qc(&qc));
        let registry = manager
            .registry
            .lock()
            .expect("validator registry lock should succeed");
        assert_eq!(registry.current_epoch, 1_132);
        assert!(registry.validators.values().all(|validator| {
            validator.cluster_assignment_seed.as_deref() == Some(expected_cluster_seed.as_str())
        }));
    }

    #[test]
    fn activation_boundary_switches_to_v3_at_one_based_epoch_start() {
        assert_eq!(
            epoch_start_height(EPOCH_RANDOMNESS_V3_ACTIVATION_EPOCH, 1_000),
            1_200_001
        );
        assert!(!ProofOfSynergy::boundary_hash_v3_active_for_epoch(
            1_199, 1_000
        ));
        assert!(ProofOfSynergy::boundary_hash_v3_active_for_epoch(
            1_200, 1_000
        ));

        let _guard = DualQuorumConsensus::test_vote_tracking_guard();
        DualQuorumConsensus::reset_test_vote_tracking();
        let (manager, boundary_block, qc) = signed_boundary_fixture(1_200_000, 1_199);
        let mut chain = BlockChain::new();
        chain.add_block(boundary_block.clone());
        DualQuorumConsensus::record_committed_qc_checked(qc).unwrap();

        let current =
            ProofOfSynergy::epoch_randomness_evidence_for_epoch(&chain, 1_200, 1_000, &manager)
                .expect("post-activation current epoch must use verified boundary evidence");
        let transition = ProofOfSynergy::epoch_randomness_evidence_for_transition(
            &chain, 1_200, 1_000, &manager,
        )
        .expect("post-activation transition must use verified boundary evidence");
        assert_eq!(current.scheme, BOUNDARY_HASH_RANDOMNESS_SCHEME);
        assert!(current.boundary_qc_verified);
        assert_eq!(current.boundary_height, Some(1_200_000));
        assert_eq!(current.boundary_block_hash, Some(boundary_block.hash));
        assert_eq!(current.assignment_effective_height, 1_200_001);
        assert_eq!(current.randomness, transition.randomness);
    }

    #[test]
    fn previous_qc_revalidates_persisted_aegis_vote_evidence() {
        let _guard = DualQuorumConsensus::test_vote_tracking_guard();
        DualQuorumConsensus::reset_test_vote_tracking();
        let (manager, boundary_block, mut qc) = signed_boundary_fixture(2_000, 1);
        qc.votes.clear();
        let mut chain = BlockChain::new();
        chain.add_block(boundary_block);
        DualQuorumConsensus::record_committed_qc_checked(qc).unwrap();

        let error = ProofOfSynergy::get_previous_quorum_certificate(&chain, 2, 1_000, &manager)
            .expect_err("persisted QC without Aegis vote evidence must fail closed");

        assert!(error.contains("failed Aegis dual-quorum verification"));
        assert!(error.contains("individually verifiable Aegis PQC votes"));
    }

    #[test]
    fn stopped_validator_does_not_permanently_block_proposer_schedule() {
        let _guard = proposal_cache_test_lock()
            .lock()
            .expect("leader rotation test lock should succeed");
        let manager = Arc::new(ValidatorManager::new());
        let pqc_manager = Arc::new(Mutex::new(PQCManager::new()));
        let synergy_calculator = Arc::new(SynergyScoreCalculator::new(
            Arc::clone(&manager),
            Arc::clone(&pqc_manager),
        ));
        let epoch_randomness = vec![17; 32];
        let build_validator = |address: &str| {
            let mut validator = Validator::new(
                address.to_string(),
                format!("{address}-pubkey"),
                address.to_string(),
                1_000,
            );
            validator.status = ValidatorStatus::Active;
            validator
        };
        let validators = vec![
            build_validator("synv1offline"),
            build_validator("synv1active1"),
            build_validator("synv1active2"),
            build_validator("synv1active3"),
            build_validator("synv1active4"),
        ];

        *EPOCH_LEADER_ROTATION
            .lock()
            .expect("rotation lock should succeed") = (0, Vec::new(), 0, Vec::new());
        let primary = ProofOfSynergy::select_leader_for_block(
            &validators,
            126,
            &synergy_calculator,
            &epoch_randomness,
            1_000,
            0,
        );

        let view_advanced_to_different_active_validator =
            (1..validators.len()).any(|view_offset| {
                let selected = ProofOfSynergy::select_leader_for_block(
                    &validators,
                    126,
                    &synergy_calculator,
                    &epoch_randomness,
                    1_000,
                    view_offset,
                );
                selected.address != primary.address
            });

        assert!(
            view_advanced_to_different_active_validator,
            "deterministic view advance must move past an unresponsive scheduled proposer"
        );
    }

    #[test]
    fn view_timeout_falls_forward_to_live_leader_when_scheduled_leader_is_offline() {
        let _guard = proposal_cache_test_lock()
            .lock()
            .expect("leader rotation test lock should succeed");
        let manager = Arc::new(ValidatorManager::new());
        let pqc_manager = Arc::new(Mutex::new(PQCManager::new()));
        let synergy_calculator = Arc::new(SynergyScoreCalculator::new(
            Arc::clone(&manager),
            Arc::clone(&pqc_manager),
        ));
        let epoch_randomness = vec![17; 32];
        let build_validator = |address: &str| {
            let mut validator = Validator::new(
                address.to_string(),
                format!("{address}-pubkey"),
                address.to_string(),
                1_000,
            );
            validator.status = ValidatorStatus::Active;
            validator
        };
        let validators = vec![
            build_validator("synv1active0"),
            build_validator("synv1active1"),
            build_validator("synv1active2"),
            build_validator("synv1active3"),
            build_validator("synv1active4"),
        ];

        *EPOCH_LEADER_ROTATION
            .lock()
            .expect("rotation lock should succeed") = (0, Vec::new(), 0, Vec::new());
        let offline_scheduled = ProofOfSynergy::select_leader_for_block(
            &validators,
            126,
            &synergy_calculator,
            &epoch_randomness,
            1_000,
            1,
        );
        let live_validators = validators
            .iter()
            .filter(|validator| validator.address != offline_scheduled.address)
            .cloned()
            .collect::<Vec<_>>();

        let selected = ProofOfSynergy::select_live_leader_after_view_timeout(
            offline_scheduled.clone(),
            &validators,
            &live_validators,
            126,
            &synergy_calculator,
            &epoch_randomness,
            1_000,
            1,
        );

        assert_ne!(selected.address, offline_scheduled.address);
        assert!(
            live_validators
                .iter()
                .any(|validator| validator.address == selected.address),
            "fallback leader must come from the locally live active validator set"
        );
    }

    #[test]
    fn stale_same_height_vote_lock_does_not_permanently_override_live_scheduled_leader() {
        assert!(
            ProofOfSynergy::should_supersede_same_height_vote_lock_with_scheduled_leader(
                true, 8, 8
            ),
            "a live scheduled leader must supersede a stale same-height lock at recovery age"
        );
        assert!(
            !ProofOfSynergy::should_supersede_same_height_vote_lock_with_scheduled_leader(
                true, 7, 8
            ),
            "fresh same-height locks should still protect normal deterministic retry"
        );
        assert!(
            !ProofOfSynergy::should_supersede_same_height_vote_lock_with_scheduled_leader(
                false, 30, 8
            ),
            "an offline scheduled leader should not displace a live locked proposer"
        );
    }

    #[test]
    fn leader_selection_ignores_local_performance_metrics() {
        let _guard = proposal_cache_test_lock()
            .lock()
            .expect("leader rotation test lock should succeed");
        let manager = Arc::new(ValidatorManager::new());
        let pqc_manager = Arc::new(Mutex::new(PQCManager::new()));
        let synergy_calculator = Arc::new(SynergyScoreCalculator::new(
            Arc::clone(&manager),
            Arc::clone(&pqc_manager),
        ));
        let epoch_randomness = vec![42; 32];

        let build_validator = |address: &str, stake_amount: u64| {
            let mut validator = Validator::new(
                address.to_string(),
                format!("{address}-pubkey"),
                address.to_string(),
                stake_amount,
            );
            validator.status = ValidatorStatus::Active;
            validator
        };

        let validators_a = vec![
            build_validator("synv1a", 3_000),
            build_validator("synv1b", 2_000),
            build_validator("synv1c", 1_000),
        ];

        let mut validators_b = validators_a.clone();
        validators_b[0].total_blocks_produced = 10_000;
        validators_b[0].total_transactions_validated = 10_000;
        validators_b[0].collaboration_score = 500.0;
        validators_b[0].average_block_time = 1.0;
        validators_b[0].reputation_score = 15.0;
        validators_b[0].slashing_penalty = 0.75;
        validators_b[0].calculate_synergy_score();
        validators_b[1].missed_blocks = 250;
        validators_b[1].reputation_score = 1.0;
        validators_b[1].calculate_synergy_score();

        *EPOCH_LEADER_ROTATION
            .lock()
            .expect("rotation lock should succeed") = (0, Vec::new(), 0, Vec::new());
        let leader_a = ProofOfSynergy::select_leader_for_block(
            &validators_a,
            1_000,
            &synergy_calculator,
            &epoch_randomness,
            1_000,
            0,
        );

        *EPOCH_LEADER_ROTATION
            .lock()
            .expect("rotation lock should succeed") = (0, Vec::new(), 0, Vec::new());
        let leader_b = ProofOfSynergy::select_leader_for_block(
            &validators_b,
            1_000,
            &synergy_calculator,
            &epoch_randomness,
            1_000,
            0,
        );

        assert_eq!(leader_a.address, leader_b.address);
    }

    #[test]
    fn epoch_recalculation_keeps_healthy_validators_eligible() {
        let manager = Arc::new(ValidatorManager::new());
        let pqc_manager = Arc::new(Mutex::new(PQCManager::new()));
        let synergy_calculator = Arc::new(SynergyScoreCalculator::new(
            Arc::clone(&manager),
            pqc_manager,
        ));

        {
            let mut registry = manager
                .registry
                .lock()
                .expect("registry lock should succeed");

            for index in 0..5 {
                let address = format!("synv1epoch{index}");
                let mut validator = Validator::new(
                    address.clone(),
                    format!("{address}-pubkey"),
                    format!("Validator {index}"),
                    1_000,
                );
                validator.status = ValidatorStatus::Active;
                validator.total_blocks_produced = u64::from(index == 0) * 1_000;
                validator.total_transactions_validated = u64::from(index == 0) * 1_000;
                registry.validators.insert(address, validator);
            }
        }

        ProofOfSynergy::recalculate_all_synergy_scores(&manager, &synergy_calculator);

        let active_validators = manager.get_active_validators();
        assert_eq!(active_validators.len(), 5);
        assert!(active_validators
            .iter()
            .all(|validator| validator.synergy_score >= 50.0));
    }

    #[test]
    fn leader_rotation_recalculates_when_candidate_set_changes_mid_epoch() {
        let _guard = proposal_cache_test_lock()
            .lock()
            .expect("leader rotation test lock should succeed");
        let pqc_manager = Arc::new(Mutex::new(PQCManager::new()));
        let synergy_calculator = Arc::new(SynergyScoreCalculator::new(
            Arc::new(ValidatorManager::new()),
            pqc_manager,
        ));
        let epoch_randomness = vec![9u8; 64];
        let build_validator = |address: &str, stake_amount: u64| {
            let mut validator = Validator::new(
                address.to_string(),
                format!("{address}-pubkey"),
                address.to_string(),
                stake_amount,
            );
            validator.status = ValidatorStatus::Active;
            validator
        };
        let validators_full = vec![
            build_validator("synv1a", 5_000),
            build_validator("synv1b", 4_000),
            build_validator("synv1c", 3_000),
            build_validator("synv1d", 2_000),
        ];
        let validators_reduced = vec![
            validators_full[0].clone(),
            validators_full[1].clone(),
            validators_full[3].clone(),
        ];

        *EPOCH_LEADER_ROTATION
            .lock()
            .expect("rotation lock should succeed") = (0, Vec::new(), 0, Vec::new());

        let _ = ProofOfSynergy::select_leader_for_block(
            &validators_full,
            1_005,
            &synergy_calculator,
            &epoch_randomness,
            1_000,
            0,
        );
        let cached_full = EPOCH_LEADER_ROTATION
            .lock()
            .expect("rotation lock should succeed")
            .clone();
        assert_eq!(cached_full.3.len(), 4);
        assert!(cached_full.1.iter().any(|address| address == "synv1c"));

        let _ = ProofOfSynergy::select_leader_for_block(
            &validators_reduced,
            1_006,
            &synergy_calculator,
            &epoch_randomness,
            1_000,
            0,
        );
        let cached_reduced = EPOCH_LEADER_ROTATION
            .lock()
            .expect("rotation lock should succeed")
            .clone();
        assert_eq!(
            cached_reduced.3,
            vec![
                "synv1a".to_string(),
                "synv1b".to_string(),
                "synv1d".to_string(),
            ]
        );
        assert!(!cached_reduced.1.iter().any(|address| address == "synv1c"));
    }

    #[test]
    fn quarantined_validator_is_not_in_duty_active_leader_rotation() {
        let _guard = proposal_cache_test_lock()
            .lock()
            .expect("leader rotation test lock should succeed");
        let pqc_manager = Arc::new(Mutex::new(PQCManager::new()));
        let synergy_calculator = Arc::new(SynergyScoreCalculator::new(
            Arc::new(ValidatorManager::new()),
            pqc_manager,
        ));
        let epoch_randomness = vec![11u8; 64];
        let build_validator = |address: &str| {
            let mut validator = Validator::new(
                address.to_string(),
                format!("{address}-pubkey"),
                address.to_string(),
                1_000,
            );
            validator.status = ValidatorStatus::Active;
            validator.synergy_score = 100.0;
            validator
        };
        let registered_validators = vec![
            build_validator("synv1a"),
            build_validator("synv1b"),
            build_validator("synv1c-quarantined"),
            build_validator("synv1d"),
            build_validator("synv1e"),
        ];
        let duty_active_validators = registered_validators
            .iter()
            .filter(|validator| validator.address != "synv1c-quarantined")
            .cloned()
            .collect::<Vec<_>>();

        *EPOCH_LEADER_ROTATION
            .lock()
            .expect("rotation lock should succeed") = (0, Vec::new(), 0, Vec::new());

        for height in 94_000..94_025 {
            let selected = ProofOfSynergy::select_leader_for_block(
                &duty_active_validators,
                height,
                &synergy_calculator,
                &epoch_randomness,
                1_000,
                0,
            );
            assert_ne!(selected.address, "synv1c-quarantined");
        }

        let cached = EPOCH_LEADER_ROTATION
            .lock()
            .expect("rotation lock should succeed")
            .clone();
        assert_eq!(cached.3.len(), 4);
        assert!(!cached
            .3
            .iter()
            .any(|address| address == "synv1c-quarantined"));
    }

    #[test]
    fn leader_reuses_cached_proposal_for_same_height_retry() {
        let _guard = proposal_cache_test_lock()
            .lock()
            .expect("proposal cache test lock should succeed");
        let cache_dir = unique_proposal_cache_dir("leader-retry");
        ProofOfSynergy::set_test_proposal_cache_dir(Some(cache_dir.clone()));

        let previous = Block::new_with_timestamp(
            772,
            vec![],
            "previous-parent".to_string(),
            "synv1previous".to_string(),
            772,
            1_777_426_405,
        );
        let mut leader = Validator::new(
            "synv1leader-retry".to_string(),
            "leader-pubkey".to_string(),
            "Leader Retry".to_string(),
            1_000,
        );
        leader.status = ValidatorStatus::Active;
        let registered_leaders = active_validator_manager(&leader.address);
        leader.public_key = registered_leaders
            .get_validator(&leader.address)
            .expect("test leader should be registered")
            .public_key;
        let pqc_manager = Arc::new(Mutex::new(PQCManager::new()));

        let first =
            ProofOfSynergy::create_block_proposal(&previous, &leader, vec![], 2, &pqc_manager);
        let late_transaction = Transaction::new(
            "synw1sender".to_string(),
            "synw1receiver".to_string(),
            1,
            0,
            vec![1, 2, 3],
            1,
            21_000,
            Some("late-mempool-transaction".to_string()),
            "test".to_string(),
        );
        let retry = ProofOfSynergy::create_block_proposal(
            &previous,
            &leader,
            vec![late_transaction],
            2,
            &pqc_manager,
        );

        assert_eq!(retry.hash, first.hash);
        assert!(first.timestamp >= previous.timestamp + 2);
        assert_eq!(retry.transactions.len(), first.transactions.len());
        assert!(retry.transactions.is_empty());

        ProofOfSynergy::prune_cached_block_proposals(first.block_index);
        assert!(fs::read_dir(&cache_dir)
            .expect("cache dir should remain readable")
            .next()
            .is_none());

        ProofOfSynergy::set_test_proposal_cache_dir(None);
        let _ = fs::remove_dir_all(cache_dir);
    }

    #[test]
    fn leader_discards_cached_proposal_with_expired_transactions() {
        let _guard = proposal_cache_test_lock()
            .lock()
            .expect("proposal cache test lock should succeed");
        let cache_dir = unique_proposal_cache_dir("leader-expired-retry");
        ProofOfSynergy::set_test_proposal_cache_dir(Some(cache_dir.clone()));

        let previous = Block::new_with_timestamp(
            760_975,
            vec![],
            "stalled-parent".to_string(),
            "synv1previous".to_string(),
            760_975,
            ProofOfSynergy::current_timestamp().saturating_sub(10),
        );
        let mut leader = Validator::new(
            "synv1leader-expired-retry".to_string(),
            "leader-pubkey".to_string(),
            "Leader Expired Retry".to_string(),
            1_000,
        );
        leader.status = ValidatorStatus::Active;
        let registered_leaders = active_validator_manager(&leader.address);
        leader.public_key = registered_leaders
            .get_validator(&leader.address)
            .expect("test leader should be registered")
            .public_key;
        let pqc_manager = Arc::new(Mutex::new(PQCManager::new()));

        let fresh_transaction = Transaction::new(
            "synw1sender".to_string(),
            "synw1receiver".to_string(),
            1,
            0,
            vec![1, 2, 3],
            1,
            21_000,
            Some("fresh-mempool-transaction".to_string()),
            "test".to_string(),
        );
        let first = ProofOfSynergy::create_block_proposal(
            &previous,
            &leader,
            vec![fresh_transaction],
            2,
            &pqc_manager,
        );
        assert_eq!(first.transactions.len(), 1);

        let cache_path = ProofOfSynergy::proposal_cache_path(
            first.block_index,
            &first.previous_hash,
            &first.validator_id,
        );
        let mut cached_block = serde_json::from_str::<Block>(
            &fs::read_to_string(&cache_path).expect("cached proposal should exist"),
        )
        .expect("cached proposal should deserialize");
        cached_block.transactions[0].timestamp = ProofOfSynergy::current_timestamp()
            .saturating_sub(PROPOSAL_TRANSACTION_MAX_AGE_SECS + 1);
        fs::write(
            &cache_path,
            serde_json::to_vec_pretty(&cached_block).expect("cached proposal should serialize"),
        )
        .expect("cached proposal should be overwritten for regression setup");

        let mut expired_mempool_transaction = Transaction::new(
            "synw1sender".to_string(),
            "synw1receiver".to_string(),
            1,
            0,
            vec![9, 9, 9],
            1,
            21_000,
            Some("expired-mempool-transaction".to_string()),
            "test".to_string(),
        );
        expired_mempool_transaction.timestamp = ProofOfSynergy::current_timestamp()
            .saturating_sub(PROPOSAL_TRANSACTION_MAX_AGE_SECS + 1);
        let fresh_mempool_transaction = Transaction::new(
            "synw1sender".to_string(),
            "synw1receiver".to_string(),
            1,
            0,
            vec![4, 5, 6],
            1,
            21_000,
            Some("fresh-mempool-transaction-after-discard".to_string()),
            "test".to_string(),
        );
        let retry = ProofOfSynergy::create_block_proposal(
            &previous,
            &leader,
            vec![expired_mempool_transaction, fresh_mempool_transaction],
            2,
            &pqc_manager,
        );

        assert_ne!(retry.hash, first.hash);
        assert_eq!(retry.transactions.len(), 1);
        assert_eq!(
            retry.transactions[0].data.as_deref(),
            Some("fresh-mempool-transaction-after-discard")
        );

        ProofOfSynergy::prune_cached_block_proposals(retry.block_index);
        ProofOfSynergy::set_test_proposal_cache_dir(None);
        let _ = fs::remove_dir_all(cache_dir);
    }

    #[test]
    fn transaction_nonce_ordering_accepts_next_committed_nonce() {
        let pending = Vec::<(String, u64)>::new();
        assert!(
            ProofOfSynergy::validate_transaction_nonce_for_ordering(4, &[1, 3], &pending).is_ok()
        );
    }

    #[test]
    fn transaction_nonce_ordering_rejects_stale_duplicate_and_gap() {
        let pending = vec![("pending-a".to_string(), 4)];

        let stale = ProofOfSynergy::validate_transaction_nonce_for_ordering(3, &[1, 3], &[]);
        assert!(stale.unwrap_err().contains("stale nonce"));

        let duplicate =
            ProofOfSynergy::validate_transaction_nonce_for_ordering(4, &[1, 3], &pending);
        assert!(duplicate.unwrap_err().contains("duplicate nonce"));

        let future_gap =
            ProofOfSynergy::validate_transaction_nonce_for_ordering(6, &[1, 3], &pending);
        assert!(future_gap.unwrap_err().contains("future nonce gap"));
    }

    #[test]
    fn transaction_nonce_ordering_accepts_sequential_pending_nonce() {
        let pending = vec![("pending-a".to_string(), 4)];
        assert!(
            ProofOfSynergy::validate_transaction_nonce_for_ordering(5, &[1, 3], &pending).is_ok()
        );
    }

    #[test]
    fn stale_unfinalized_proposal_cache_is_archived_after_evidence() {
        let _guard = proposal_cache_test_lock()
            .lock()
            .expect("proposal cache test lock should succeed");
        let cache_dir = unique_proposal_cache_dir("proposal-recovery");
        ProofOfSynergy::set_test_proposal_cache_dir(Some(cache_dir.clone()));

        let previous = Block::new_with_timestamp(
            38481,
            vec![],
            "canonical-parent".to_string(),
            "synv1previous".to_string(),
            38481,
            1_779_540_000,
        );
        let mut leader = Validator::new(
            "synv1proposal-recovery".to_string(),
            "leader-pubkey".to_string(),
            "Proposal Recovery".to_string(),
            1_000,
        );
        leader.status = ValidatorStatus::Active;
        let registered_leaders = active_validator_manager(&leader.address);
        leader.public_key = registered_leaders
            .get_validator(&leader.address)
            .expect("test leader should be registered")
            .public_key;
        let pqc_manager = Arc::new(Mutex::new(PQCManager::new()));

        let proposal =
            ProofOfSynergy::create_block_proposal(&previous, &leader, vec![], 2, &pqc_manager);
        assert!(fs::read_dir(&cache_dir)
            .expect("cache dir should be readable")
            .next()
            .is_some());

        let report = ProofOfSynergy::recover_cached_block_proposals_above_finalized_height(
            previous.block_index,
            "test stale proposal recovery",
        )
        .expect("proposal cache recovery should succeed");

        assert!(report.mutated);
        assert_eq!(report.archived_count, 1);
        assert_eq!(report.archived[0].block_hash, proposal.hash);
        assert!(PathBuf::from(&report.archived[0].evidence_path).exists());
        assert!(fs::read_dir(&cache_dir)
            .expect("cache dir should remain readable")
            .next()
            .is_none());

        ProofOfSynergy::set_test_proposal_cache_dir(None);
        let _ = fs::remove_dir_all(cache_dir);
        let _ = fs::remove_dir_all(report.evidence_dir);
    }

    #[test]
    fn insufficient_votes_trigger_transient_liveness_recovery() {
        let required_quorum = required_validator_quorum(6);
        assert!(
            ProofOfSynergy::consensus_failure_needs_transient_lock_recovery(&format!(
                "Insufficient validator votes: 2 votes, {required_quorum} required for quorum"
            ))
        );
        assert!(
            ProofOfSynergy::consensus_failure_needs_transient_lock_recovery(
                "same-height vote supersede requires a durable finalized canonical parent lock"
            )
        );
        assert!(
            ProofOfSynergy::consensus_failure_needs_transient_lock_recovery(
                "already locally voted for different block at height 256039"
            )
        );
    }

    #[test]
    fn transient_vote_recovery_age_tracks_fast_proposal_path() {
        assert_eq!(
            ProofOfSynergy::transient_vote_recovery_min_age_secs(4, 1),
            1
        );
        assert_eq!(
            ProofOfSynergy::transient_vote_recovery_min_age_secs(2, 3),
            2
        );
        assert_eq!(
            ProofOfSynergy::transient_vote_recovery_min_age_secs(0, 0),
            1
        );
    }

    #[test]
    fn leader_selection_preserves_same_height_vote_lock_for_live_scheduled_leader() {
        let _vote_tracking_guard = DualQuorumConsensus::test_vote_tracking_guard();
        DualQuorumConsensus::reset_test_vote_tracking();

        let path = unique_vote_lock_path("leader-lock-preference");
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("vote lock test directory should be created");
        }
        let locks = serde_json::json!({
            "55:810:validator-local": {
                "validator_address": "validator-local",
                "block_hash": "locked-block-hash",
                "block_index": 810,
                "epoch_number": 55,
                "first_round_number": 1,
                "latest_round_number": 4,
                "proposer": "validator-locked",
                "created_at": 1_777_426_401u64,
                "updated_at": 1_777_426_404u64
            }
        });
        fs::write(
            &path,
            serde_json::to_vec(&locks).expect("vote lock JSON should encode"),
        )
        .expect("vote lock file should be written");
        DualQuorumConsensus::set_test_local_vote_lock_path(Some(path.clone()));

        let mut scheduled = Validator::new(
            "validator-scheduled".to_string(),
            "scheduled-pubkey".to_string(),
            "Scheduled".to_string(),
            1_000,
        );
        scheduled.status = ValidatorStatus::Active;
        let mut locked = Validator::new(
            "validator-locked".to_string(),
            "locked-pubkey".to_string(),
            "Locked".to_string(),
            1_000,
        );
        locked.status = ValidatorStatus::Active;
        let active_validators = vec![scheduled.clone(), locked.clone()];

        let selected = ProofOfSynergy::prefer_local_vote_lock_leader(
            scheduled.clone(),
            &active_validators,
            &active_validators,
            Some("validator-local"),
            55,
            810,
            809,
            u64::MAX,
        );

        assert_eq!(selected.address, scheduled.address);
        let lock = DualQuorumConsensus::local_locked_vote_for_height("validator-local", 55, 810)
            .expect("vote lock lookup should succeed")
            .expect("PoSy signer journal must preserve the same-height lock");
        assert!(
            lock.block_hash == "locked-block-hash",
            "leader selection must not erase a prior same-height signing authorization"
        );

        DualQuorumConsensus::set_test_local_vote_lock_path(None);
        if let Some(root) = path.parent().and_then(|data| data.parent()) {
            let _ = fs::remove_dir_all(root);
        }
    }

    #[test]
    fn leader_selection_prefers_live_vote_lock_when_scheduled_leader_is_offline() {
        let _vote_tracking_guard = DualQuorumConsensus::test_vote_tracking_guard();
        DualQuorumConsensus::reset_test_vote_tracking();

        let path = unique_vote_lock_path("offline-scheduled-leader-lock-preference");
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("vote lock test directory should be created");
        }
        let locks = serde_json::json!({
            "55:810:validator-local": {
                "validator_address": "validator-local",
                "block_hash": "locked-block-hash",
                "block_index": 810,
                "epoch_number": 55,
                "first_round_number": 1,
                "latest_round_number": 4,
                "proposer": "validator-locked",
                "created_at": 1_777_426_401u64,
                "updated_at": 1_777_426_404u64
            }
        });
        fs::write(
            &path,
            serde_json::to_vec(&locks).expect("vote lock JSON should encode"),
        )
        .expect("vote lock file should be written");
        DualQuorumConsensus::set_test_local_vote_lock_path(Some(path.clone()));

        let mut scheduled = Validator::new(
            "validator-scheduled".to_string(),
            "scheduled-pubkey".to_string(),
            "Scheduled".to_string(),
            1_000,
        );
        scheduled.status = ValidatorStatus::Active;
        let mut locked = Validator::new(
            "validator-locked".to_string(),
            "locked-pubkey".to_string(),
            "Locked".to_string(),
            1_000,
        );
        locked.status = ValidatorStatus::Active;
        let active_validators = vec![scheduled.clone(), locked.clone()];
        let live_validators = vec![locked.clone()];

        let selected = ProofOfSynergy::prefer_local_vote_lock_leader(
            scheduled,
            &active_validators,
            &live_validators,
            Some("validator-local"),
            55,
            810,
            809,
            u64::MAX,
        );

        assert_eq!(selected.address, locked.address);

        DualQuorumConsensus::set_test_local_vote_lock_path(None);
        if let Some(root) = path.parent().and_then(|data| data.parent()) {
            let _ = fs::remove_dir_all(root);
        }
    }

    #[test]
    fn leader_selection_does_not_pin_to_offline_local_same_height_vote_lock() {
        let _vote_tracking_guard = DualQuorumConsensus::test_vote_tracking_guard();
        DualQuorumConsensus::reset_test_vote_tracking();

        let path = unique_vote_lock_path("offline-leader-lock-preference");
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("vote lock test directory should be created");
        }
        let locks = serde_json::json!({
            "55:810:validator-local": {
                "validator_address": "validator-local",
                "block_hash": "locked-block-hash",
                "block_index": 810,
                "epoch_number": 55,
                "first_round_number": 1,
                "latest_round_number": 4,
                "proposer": "validator-locked",
                "created_at": 1_777_426_401u64,
                "updated_at": 1_777_426_404u64
            }
        });
        fs::write(
            &path,
            serde_json::to_vec(&locks).expect("vote lock JSON should encode"),
        )
        .expect("vote lock file should be written");
        DualQuorumConsensus::set_test_local_vote_lock_path(Some(path.clone()));

        let mut scheduled = Validator::new(
            "validator-scheduled".to_string(),
            "scheduled-pubkey".to_string(),
            "Scheduled".to_string(),
            1_000,
        );
        scheduled.status = ValidatorStatus::Active;
        let mut locked = Validator::new(
            "validator-locked".to_string(),
            "locked-pubkey".to_string(),
            "Locked".to_string(),
            1_000,
        );
        locked.status = ValidatorStatus::Active;
        let active_validators = vec![scheduled.clone(), locked];
        let live_validators = vec![scheduled.clone()];

        let selected = ProofOfSynergy::prefer_local_vote_lock_leader(
            scheduled.clone(),
            &active_validators,
            &live_validators,
            Some("validator-local"),
            55,
            810,
            809,
            u64::MAX,
        );

        assert_eq!(selected.address, scheduled.address);

        DualQuorumConsensus::set_test_local_vote_lock_path(None);
        if let Some(root) = path.parent().and_then(|data| data.parent()) {
            let _ = fs::remove_dir_all(root);
        }
    }

    #[test]
    fn leader_selection_preserves_stale_live_local_vote_lock_at_recovery_age() {
        let _vote_tracking_guard = DualQuorumConsensus::test_vote_tracking_guard();
        DualQuorumConsensus::reset_test_vote_tracking();

        let path = unique_vote_lock_path("stale-leader-lock-recovery");
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("vote lock test directory should be created");
        }
        let locks = serde_json::json!({
            "55:810:validator-local": {
                "validator_address": "validator-local",
                "block_hash": "locked-block-hash",
                "block_index": 810,
                "epoch_number": 55,
                "first_round_number": 1,
                "latest_round_number": 4,
                "proposer": "validator-locked",
                "created_at": 1u64,
                "updated_at": 1u64
            }
        });
        fs::write(
            &path,
            serde_json::to_vec(&locks).expect("vote lock JSON should encode"),
        )
        .expect("vote lock file should be written");
        DualQuorumConsensus::set_test_local_vote_lock_path(Some(path.clone()));

        let mut scheduled = Validator::new(
            "validator-scheduled".to_string(),
            "scheduled-pubkey".to_string(),
            "Scheduled".to_string(),
            1_000,
        );
        scheduled.status = ValidatorStatus::Active;
        let mut locked = Validator::new(
            "validator-locked".to_string(),
            "locked-pubkey".to_string(),
            "Locked".to_string(),
            1_000,
        );
        locked.status = ValidatorStatus::Active;
        let active_validators = vec![scheduled.clone(), locked.clone()];

        let selected = ProofOfSynergy::prefer_local_vote_lock_leader(
            scheduled.clone(),
            &active_validators,
            &active_validators,
            Some("validator-local"),
            55,
            810,
            809,
            1,
        );

        assert_eq!(selected.address, scheduled.address);
        let lock = DualQuorumConsensus::local_locked_vote_for_height("validator-local", 55, 810)
            .expect("vote lock lookup should succeed")
            .expect("time must not erase a PoSy signing authorization");
        assert_eq!(lock.block_hash, "locked-block-hash");

        DualQuorumConsensus::set_test_local_vote_lock_path(None);
        if let Some(root) = path.parent().and_then(|data| data.parent()) {
            let _ = fs::remove_dir_all(root);
        }
    }
}
