//! Autonomous five-process qualification for the simplified PoSy driver.
//!
//! Each child process owns the production driver loop, real timers, an
//! ML-DSA-65 signer, durable signer journal, safety store, proposal-material
//! store/source, and replay-verifying finality WAL. The parent is only a
//! bounded authenticated frame router and fault injector. It never requests a
//! vote or timeout vote and never constructs a QC or TC.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashSet};
use std::env;
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};
use std::thread;
use std::time::{Duration, Instant};
use synergy_testnet::consensus::signing_authority::DurableConsensusSigningAuthority;
use synergy_testnet::consensus::simplified_posy::{
    run_simplified_posy_driver_with_peer_rejection_observer, AuthenticatedSimplifiedConsensusPeer,
    DurableSimplifiedFinalitySink, DurableSimplifiedPosyStore,
    DurableSimplifiedProposalMaterialStore, DurableVerifiedSimplifiedProposalSource,
    FinalizedBlockRecord, GenesisBoundSimplifiedActivation, GenesisFinalityReference,
    SimplifiedConsensusEgress, SimplifiedConsensusEnvelope, SimplifiedConsensusMessage,
    SimplifiedCoreMaterialAdapter, SimplifiedCoreMaterialConfiguration, SimplifiedDriverTiming,
    SimplifiedEpochContext, SimplifiedFinalityEnvironment, SimplifiedFinalityParent,
    SimplifiedPosyDriver, SimplifiedSafetyState, POSY_SIMPLIFIED_ACTIVATION_BINDING_SCHEMA_VERSION,
    POSY_SIMPLIFIED_ACTIVATION_BINDING_STATUS, POSY_SIMPLIFIED_PROTOCOL_VERSION,
};
use synergy_testnet::crypto::aegis_pqvm::{
    AegisPqvmKeyRegistry, AegisPqvmSigner, AegisPqvmVerifier,
};
use synergy_testnet::crypto::pqc::{PQCPrivateKey, PQCPublicKey};
use synergy_testnet::etdag::EtdagParameters;
use synergy_testnet::execution::ExecutionState;
use synergy_testnet::p2p::messages::validate_simplified_consensus_message_size;
use synergy_testnet::posy_simplified_parameters::{
    SimplifiedConsensusParameterManifest, SimplifiedPerformanceTargets,
    POSY_SIMPLIFIED_ETDAG_GOVERNED_GENESIS_BINDING_REQUIRED,
    POSY_SIMPLIFIED_FRESH_GENESIS_BOUNDARY, POSY_SIMPLIFIED_PARAMETER_FINALIZED_STATUS,
};
use synergy_testnet::synergy_types::{
    AegisPqKeyRole, ChainId, ClusterId, ClusterMap, Epoch, Hash, Height, NetworkId, Round, UmaId,
    ValidatorId, ValidatorRecord, ValidatorSet, ValidatorStatus,
    TESTNET_V3_CONSENSUS_SIGNATURE_ALGORITHM,
};

const VALIDATOR_COUNT: usize = 5;
const ACTIVATION_EPOCH: u64 = 0;
const EPOCH_LENGTH: u64 = 1_000;
const EPOCH_START_HEIGHT: u64 = 1;
const ROUTER_CAPACITY: usize = 4_096;
const DRIVER_INGRESS_CAPACITY: usize = 512;
const MAX_ROUTED_FRAME_BYTES: usize = 1024 * 1024;
/// The harness asserts the Testnet-v3 block interval contract without
/// inheriting the 2s release-manifest value.  This is intentionally local to
/// the qualification process; changing a governed release binding requires
/// its own authorization.
const HARNESS_TARGET_BLOCK_TIME_MS: u64 = 500;
// The autonomous harness runs five concurrent ML-DSA-65 signers and the
// authenticated ECHO/READY delivery phase before the one ordinary block vote.
// Keep these finalized, harness-local timings long enough to qualify that
// production path on a contended test host without turning scheduler latency
// into artificial takeover churn.
const PROPOSAL_TIMEOUT_MS: u64 = 8_000;
const VOTE_TIMEOUT_MS: u64 = 8_000;
const MAX_ROUND_TIMEOUT_MS: u64 = 16_000;

/// The worker currently constructs `SimplifiedCoreMaterialAdapter` directly.
/// Keep the qualification boundary explicit until the harness is supplied the
/// canonical Genesis bootstrap, authenticated ingress-KEM registry, ETDAG
/// producer, and production protected-lifecycle wiring.  In particular, the
/// parent must never turn the ordinary-driver checks below into an R11 claim.
const R11_PROTECTED_QUALIFICATION_UNAVAILABLE: &str =
    "R11_PROTECTED_QUALIFICATION_UNAVAILABLE: autonomous workers use SimplifiedCoreMaterialAdapter; no canonical protected lifecycle or normal ETDAG producer is installed";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PublicConfiguration {
    activation: GenesisBoundSimplifiedActivation,
    epoch_context: SimplifiedEpochContext,
    /// Fresh-chain block one extends this distinct Genesis reference.  It is
    /// intentionally not a fabricated quorum certificate.
    genesis_finality_reference: GenesisFinalityReference,
    pqc_public_keys: Vec<PQCPublicKey>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PrivateKeyRecord {
    validator_index: usize,
    public_key: PQCPublicKey,
    private_key: PQCPrivateKey,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "command", rename_all = "snake_case")]
enum ParentCommand {
    Deliver {
        from: usize,
        message: SimplifiedConsensusMessage,
    },
    Stop,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
enum WorkerEvent {
    Ready {
        validator_index: usize,
        generation: u64,
    },
    Broadcast {
        validator_index: usize,
        generation: u64,
        message: SimplifiedConsensusMessage,
    },
    Send {
        validator_index: usize,
        generation: u64,
        expected_validator_id: ValidatorId,
        message: SimplifiedConsensusMessage,
    },
    Fatal {
        validator_index: usize,
        generation: u64,
        message: String,
    },
    PeerRejected {
        validator_index: usize,
        generation: u64,
        message: String,
    },
    Stopped {
        validator_index: usize,
        generation: u64,
    },
}

#[derive(Debug)]
struct ObservedEvent {
    validator_index: usize,
    generation: u64,
    result: Result<WorkerEvent, String>,
}

struct WorkerHandle {
    index: usize,
    child: Child,
    stdin: ChildStdin,
}

impl WorkerHandle {
    fn send(&mut self, command: &ParentCommand) -> Result<(), String> {
        let mut bytes = serde_json::to_vec(command)
            .map_err(|error| format!("serialize validator-{} command: {error}", self.index))?;
        if bytes.len() > MAX_ROUTED_FRAME_BYTES {
            return Err(format!(
                "validator-{} command exceeds bounded router frame",
                self.index
            ));
        }
        bytes.push(b'\n');
        self.stdin
            .write_all(&bytes)
            .and_then(|()| self.stdin.flush())
            .map_err(|error| format!("write validator-{} command: {error}", self.index))
    }
}

#[derive(Debug, Default)]
struct RouterCounters {
    proposals: u64,
    votes: u64,
    quorum_certificates: u64,
    timeout_votes: u64,
    timeout_certificates: u64,
    material_requests: u64,
    material_chunks: u64,
    state_sync_requests: u64,
    state_sync_chunks: u64,
    delivered_frames: u64,
    dropped_frames: u64,
}

struct NetworkPolicy {
    links: [[bool; VALIDATOR_COUNT]; VALIDATOR_COUNT],
    lagger: usize,
    material_height: Option<u64>,
    sync_source: Option<usize>,
    freeze_at_qc_height: Option<u64>,
    freeze_triggered: bool,
    captured_sync_qc: Option<(usize, SimplifiedConsensusMessage)>,
    allowed_fatal: HashSet<usize>,
    unavailable: HashSet<usize>,
    counters: RouterCounters,
}

impl NetworkPolicy {
    fn all_connected(lagger: usize) -> Self {
        let mut links = [[true; VALIDATOR_COUNT]; VALIDATOR_COUNT];
        for (index, row) in links.iter_mut().enumerate() {
            row[index] = false;
        }
        Self {
            links,
            lagger,
            material_height: None,
            sync_source: None,
            freeze_at_qc_height: None,
            freeze_triggered: false,
            captured_sync_qc: None,
            allowed_fatal: HashSet::new(),
            unavailable: HashSet::new(),
            counters: RouterCounters::default(),
        }
    }

    fn isolate(&mut self, index: usize) {
        for peer in 0..VALIDATOR_COUNT {
            self.links[index][peer] = false;
            self.links[peer][index] = false;
        }
    }

    fn connect_all(&mut self) {
        for from in 0..VALIDATOR_COUNT {
            for to in 0..VALIDATOR_COUNT {
                self.links[from][to] = from != to
                    && !self.unavailable.contains(&from)
                    && !self.unavailable.contains(&to);
            }
        }
    }

    fn freeze_all(&mut self) {
        self.links = [[false; VALIDATOR_COUNT]; VALIDATOR_COUNT];
    }

    fn permit_special(&self, from: usize, to: usize, message: &SimplifiedConsensusMessage) -> bool {
        match message {
            SimplifiedConsensusMessage::Proposal { proposal } => {
                to == self.lagger && self.material_height == Some(proposal.context.height.0)
            }
            SimplifiedConsensusMessage::MaterialRequest { .. } => from == self.lagger,
            SimplifiedConsensusMessage::MaterialChunk { .. } => to == self.lagger,
            SimplifiedConsensusMessage::StateSyncRequest { .. } => from == self.lagger,
            SimplifiedConsensusMessage::StateSyncChunk { .. } => to == self.lagger,
            _ => false,
        }
    }

    fn permits(&self, from: usize, to: usize, message: &SimplifiedConsensusMessage) -> bool {
        !self.unavailable.contains(&from)
            && !self.unavailable.contains(&to)
            && (self.links[from][to] || self.permit_special(from, to, message))
    }
}

#[derive(Clone)]
struct ProcessEgress {
    validator_index: usize,
    generation: u64,
    events: mpsc::SyncSender<WorkerEvent>,
}

impl SimplifiedConsensusEgress for ProcessEgress {
    fn broadcast(&mut self, message: &SimplifiedConsensusMessage) -> Result<usize, String> {
        validate_simplified_consensus_message_size(message)?;
        self.events
            .send(WorkerEvent::Broadcast {
                validator_index: self.validator_index,
                generation: self.generation,
                message: message.clone(),
            })
            .map_err(|_| "bounded harness router disconnected".to_string())?;
        Ok(VALIDATOR_COUNT - 1)
    }

    fn send_to(
        &mut self,
        _peer_address: &str,
        expected_validator_id: &ValidatorId,
        message: &SimplifiedConsensusMessage,
    ) -> Result<usize, String> {
        validate_simplified_consensus_message_size(message)?;
        self.events
            .send(WorkerEvent::Send {
                validator_index: self.validator_index,
                generation: self.generation,
                expected_validator_id: expected_validator_id.clone(),
                message: message.clone(),
            })
            .map_err(|_| "bounded harness router disconnected".to_string())?;
        Ok(1)
    }
}

fn main() {
    if let Err(error) = run() {
        eprintln!("POSY_SIMPLIFIED_AUTONOMOUS_HARNESS_FAILED: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let args = env::args().collect::<Vec<_>>();
    match args.get(1).map(String::as_str) {
        Some("worker") => run_worker(
            parse_arg(&args, "--validator-index")?
                .parse()
                .map_err(|error| format!("invalid validator index: {error}"))?,
            parse_arg(&args, "--generation")?
                .parse()
                .map_err(|error| format!("invalid generation: {error}"))?,
            Path::new(&parse_arg(&args, "--work-dir")?),
        ),
        Some("run") => {
            let work_dir = optional_arg(&args, "--work-dir")
                .map(PathBuf::from)
                .unwrap_or_else(|| {
                    env::temp_dir().join(format!("posy-five-driver-{}", std::process::id()))
                });
            let require_r11 = args.iter().any(|argument| argument == "--require-r11");
            run_parent(&work_dir, require_r11)
        }
        _ => Err(
            "usage: posy-simplified-five-driver-harness run [--work-dir PATH] [--require-r11]"
                .to_string(),
        ),
    }
}

fn run_parent(work_dir: &Path, require_r11: bool) -> Result<(), String> {
    // Fail before creating ephemeral identities or starting workers.  The
    // autonomous harness has useful ordinary-PoSy coverage, but cannot
    // honestly assert any protected R11 milestone until its worker setup
    // follows the same canonical protected path as the validator role.
    if require_r11 {
        return Err(R11_PROTECTED_QUALIFICATION_UNAVAILABLE.to_string());
    }
    fs::create_dir_all(work_dir)
        .map_err(|error| format!("create harness directory {}: {error}", work_dir.display()))?;
    let configuration = provision_configuration(work_dir)?;
    let initial_leader = validator_index(
        &configuration.activation.frozen_validator_set,
        configuration
            .epoch_context
            .authorized_proposer(Height(EPOCH_START_HEIGHT), 0)?,
    )?;
    let lagger = (0..VALIDATOR_COUNT)
        .find(|index| *index != initial_leader)
        .ok_or_else(|| "harness could not select a non-leader lagging validator".to_string())?;

    let executable = env::current_exe().map_err(|error| format!("resolve harness: {error}"))?;
    let (event_tx, event_rx) = mpsc::channel::<ObservedEvent>();
    let mut generations = [0u64; VALIDATOR_COUNT];
    let mut workers = (0..VALIDATOR_COUNT)
        .map(|index| spawn_worker(&executable, work_dir, index, 0, event_tx.clone()))
        .collect::<Result<Vec<_>, _>>()?;
    let mut policy = NetworkPolicy::all_connected(lagger);
    policy.isolate(lagger);
    policy.material_height = Some(EPOCH_START_HEIGHT);
    policy.freeze_at_qc_height = Some(EPOCH_START_HEIGHT + 2);

    let qualification = run_qualification(
        &executable,
        work_dir,
        &configuration,
        &event_tx,
        &event_rx,
        &mut generations,
        &mut workers,
        &mut policy,
    );
    stop_all(&mut workers);
    let cleanup = remove_private_material(work_dir);
    match (qualification, cleanup) {
        (Ok(report), Ok(())) => {
            println!(
                "{}",
                serde_json::to_string_pretty(&report)
                    .map_err(|error| format!("serialize harness report: {error}"))?
            );
            Ok(())
        }
        (Err(error), Ok(())) => Err(error),
        (Ok(_), Err(error)) => Err(error),
        (Err(error), Err(cleanup)) => {
            Err(format!("{error}; private cleanup also failed: {cleanup}"))
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn run_qualification(
    executable: &Path,
    work_dir: &Path,
    configuration: &PublicConfiguration,
    event_tx: &mpsc::Sender<ObservedEvent>,
    event_rx: &mpsc::Receiver<ObservedEvent>,
    generations: &mut [u64; VALIDATOR_COUNT],
    workers: &mut [WorkerHandle],
    policy: &mut NetworkPolicy,
) -> Result<serde_json::Value, String> {
    let validators = &configuration.activation.frozen_validator_set;
    let context = &configuration.epoch_context;
    let mut ready = BTreeSet::new();
    wait_until(
        Duration::from_secs(20),
        event_rx,
        workers,
        generations,
        validators,
        policy,
        |event, _| {
            if let WorkerEvent::Ready {
                validator_index, ..
            } = event
            {
                ready.insert(*validator_index);
            }
            ready.len() == VALIDATOR_COUNT
        },
    )?;

    // One process is partitioned. The other four run real proposal and vote
    // timers, exchange authenticated driver artifacts, and form a three-QC
    // chain. The lagger is allowed only proposal material for the first height
    // so later state sync can cross the execution/finality boundary honestly.
    wait_until(
        Duration::from_secs(60),
        event_rx,
        workers,
        generations,
        validators,
        policy,
        |_, current_policy| current_policy.freeze_triggered,
    )?;
    let (sync_source, sync_qc) = policy
        .captured_sync_qc
        .clone()
        .ok_or_else(|| "router froze without capturing the third QC".to_string())?;
    let active = (0..VALIDATOR_COUNT)
        .filter(|index| *index != policy.lagger)
        .collect::<Vec<_>>();
    wait_until(
        Duration::from_secs(20),
        event_rx,
        workers,
        generations,
        validators,
        policy,
        |_, _| {
            let states = active
                .iter()
                .map(|index| load_state(work_dir, *index, context))
                .collect::<Result<Vec<_>, _>>();
            states.is_ok_and(|states| {
                states.iter().all(|state| {
                    state.highest_parent.height().0 >= EPOCH_START_HEIGHT + 2
                        && state.finalized.height.0 >= EPOCH_START_HEIGHT
                })
            })
        },
    )?;
    require_same_view(work_dir, context, &active)?;
    let active_state = load_state(work_dir, sync_source, context)?;
    if active_state.highest_parent.height().0 < EPOCH_START_HEIGHT + 2
        || active_state.finalized.height.0 < EPOCH_START_HEIGHT
    {
        return Err("four-of-five drivers did not produce three-chain finality".to_string());
    }
    wait_until(
        Duration::from_secs(10),
        event_rx,
        workers,
        generations,
        validators,
        policy,
        |_, current_policy| material_record_count(work_dir, current_policy.lagger).unwrap_or(0) > 0,
    )?;
    if policy.counters.material_requests == 0 || policy.counters.material_chunks == 0 {
        return Err("partitioned worker did not exercise bounded material sync".to_string());
    }

    // A future QC is delayed and then delivered to the lagger. The driver,
    // not the parent, generates the state-sync request. Only one authenticated
    // sources are allowed to respond, matching the production broadcast. The
    // stager independently keys each bounded session by authenticated peer
    // and accepts the first fully verified transcript.
    policy.sync_source = Some(sync_source);
    deliver(workers, validators, sync_source, policy.lagger, sync_qc)?;
    if let Err(error) = wait_until(
        Duration::from_secs(40),
        event_rx,
        workers,
        generations,
        validators,
        policy,
        |_, current_policy| {
            load_state(work_dir, current_policy.lagger, context).is_ok_and(|state| {
                state.highest_parent.height() == active_state.highest_parent.height()
                    && state.finalized == active_state.finalized
            })
        },
    ) {
        return Err(format!(
            "state-sync healing failed: {error}; observed {} requests and {} chunks",
            policy.counters.state_sync_requests, policy.counters.state_sync_chunks
        ));
    }
    if policy.counters.state_sync_requests == 0 || policy.counters.state_sync_chunks == 0 {
        return Err("future evidence did not trigger bounded driver state sync".to_string());
    }

    // Restart the healed process from its durable state and signer journal.
    let before_restart = load_state(work_dir, policy.lagger, context)?;
    let signer_journal_path = worker_signer_journal_path(work_dir, policy.lagger);
    let signer_journal_before = fs::read(&signer_journal_path)
        .map_err(|error| format!("read signer journal before restart: {error}"))?;
    let signer_journal_root = Hash::from_domain_bytes(
        "SYNERGY_POSY_AUTONOMOUS_HARNESS_SIGNER_JOURNAL_BYTES_V1",
        &signer_journal_before,
    );
    let material_authority_root =
        durable_tree_root(&worker_material_directory(work_dir, policy.lagger))?;
    let finality_authority_root =
        durable_tree_root(&worker_finality_directory(work_dir, policy.lagger))?;
    restart_worker(
        executable,
        work_dir,
        policy.lagger,
        event_tx,
        event_rx,
        workers,
        generations,
        validators,
        policy,
    )?;
    let after_restart = load_state(work_dir, policy.lagger, context)?;
    let signer_journal_after = fs::read(&signer_journal_path)
        .map_err(|error| format!("read signer journal after restart: {error}"))?;
    if after_restart.consensus_authority_root()? != before_restart.consensus_authority_root()?
        || signer_journal_after != signer_journal_before
        || Hash::from_domain_bytes(
            "SYNERGY_POSY_AUTONOMOUS_HARNESS_SIGNER_JOURNAL_BYTES_V1",
            &signer_journal_after,
        ) != signer_journal_root
        || durable_tree_root(&worker_material_directory(work_dir, policy.lagger))?
            != material_authority_root
        || durable_tree_root(&worker_finality_directory(work_dir, policy.lagger))?
            != finality_authority_root
    {
        return Err(
            "driver restart changed consensus, signer-journal, material, or finality authority"
                .to_string(),
        );
    }

    // Heal the cluster, then isolate the exact currently authorized leader.
    // Four remaining drivers must form a TC from their own real timers and
    // progress under inherited lease authority.
    policy.material_height = None;
    policy.sync_source = None;
    policy.connect_all();
    let source_state = load_state(work_dir, sync_source, context)?;
    let next_height = source_state.next_height()?;
    let (round, _) = source_state.takeover_for_height(context, next_height)?;
    let failed_leader =
        validator_index(validators, context.authorized_proposer(next_height, round)?)?;
    policy.isolate(failed_leader);
    let prior_highest = source_state.highest_parent.height();
    let takeover_observed = Arc::new(AtomicBool::new(false));
    let takeover_flag = Arc::clone(&takeover_observed);
    wait_until(
        Duration::from_secs(60),
        event_rx,
        workers,
        generations,
        validators,
        policy,
        |event, current_policy| {
            if matches!(
                event,
                WorkerEvent::Broadcast {
                    message: SimplifiedConsensusMessage::TimeoutCertificate { .. },
                    ..
                }
            ) {
                takeover_flag.store(true, Ordering::Release);
            }
            (0..VALIDATOR_COUNT)
                .filter(|index| *index != failed_leader && *index != current_policy.lagger)
                .any(|index| {
                    load_state(work_dir, index, context)
                        .is_ok_and(|state| state.highest_parent.height().0 > prior_highest.0)
                })
        },
    )?;
    if !takeover_observed.load(Ordering::Acquire)
        || policy.counters.timeout_votes < 4
        || policy.counters.timeout_certificates == 0
    {
        return Err("real-timer leader takeover did not form a four-of-five TC".to_string());
    }

    // Leave exactly three mutually connected, caught-up drivers. Over more
    // than one maximum timeout interval they may sign timeout votes, but they
    // must not form a QC/TC or advance durable consensus state.
    let mut three = (0..VALIDATOR_COUNT)
        .filter(|index| {
            *index != failed_leader
                && *index != policy.lagger
                && !policy.unavailable.contains(index)
        })
        .collect::<Vec<_>>();
    if three.len() < 3 {
        return Err("leader-takeover phase left fewer than three healthy drivers".to_string());
    }
    three.truncate(3);
    let before_three = three
        .iter()
        .map(|index| load_state(work_dir, *index, context))
        .collect::<Result<Vec<_>, _>>()?;
    policy.freeze_all();
    for from in &three {
        for to in &three {
            policy.links[*from][*to] = from != to;
        }
    }
    pump_for(
        Duration::from_millis(MAX_ROUND_TIMEOUT_MS * 2 + 500),
        event_rx,
        workers,
        generations,
        validators,
        policy,
    )?;
    let after_three = three
        .iter()
        .map(|index| load_state(work_dir, *index, context))
        .collect::<Result<Vec<_>, _>>()?;
    for (before, after) in before_three.iter().zip(&after_three) {
        if before.highest_parent != after.highest_parent
            || before.finalized != after.finalized
            || before.takeover != after.takeover
        {
            return Err("three-of-five partition advanced consensus authority".to_string());
        }
    }

    let private_modes_secure = private_material_is_mode_0600(work_dir)?;
    if !private_modes_secure {
        return Err("one or more ephemeral private-key files are not mode 0600".to_string());
    }
    Ok(serde_json::json!({
        "status": "passed",
        "scope": "five_os_process_autonomous_simplified_driver",
        "parent_constructed_votes_qcs_tcs": false,
        "real_driver_timers": true,
        "real_mldsa65_signing": true,
        "bounded_authenticated_router": true,
        "initial_validator_count": VALIDATOR_COUNT,
        "one_unavailable_finalized_height": active_state.finalized.height.0,
        "state_sync_healed_height": after_restart.highest_parent.height().0,
        "restart_authority": {
            "signer_journal_byte_root": signer_journal_root.to_hex(),
            "proposal_material_tree_root": material_authority_root.to_hex(),
            "finality_wal_tree_root": finality_authority_root.to_hex(),
            "exact_bytes_unchanged": true
        },
        "failed_leader": failed_leader,
        "three_of_five_fail_closed_height": after_three[0].highest_parent.height().0,
        "router_counters": {
            "proposals": policy.counters.proposals,
            "votes": policy.counters.votes,
            "quorum_certificates": policy.counters.quorum_certificates,
            "timeout_votes": policy.counters.timeout_votes,
            "timeout_certificates": policy.counters.timeout_certificates,
            "material_requests": policy.counters.material_requests,
            "material_chunks": policy.counters.material_chunks,
            "state_sync_requests": policy.counters.state_sync_requests,
            "state_sync_chunks": policy.counters.state_sync_chunks,
            "delivered_frames": policy.counters.delivered_frames,
            "dropped_frames": policy.counters.dropped_frames
        },
        "scenarios": [
            "four_of_five_autonomous_progress",
            "three_of_five_fail_closed",
            "real_timer_leader_takeover",
            "partition_material_sync",
            "future_qc_state_sync_heal",
            "durable_process_restart",
            "three_chain_finalization"
        ],
        "remaining_node_only_gaps": [
            "canonical protected R11 worker construction: Genesis bootstrap, authenticated ingress-KEM registry, ETDAG producer, production lifecycle observer, and durable replay",
            "real_synergy_node_role_runtime_and_socket_stack",
            "production_identity_and_deployment_bundles",
            "soak_performance_and_byzantine_qualification"
        ],
        "r11_protected_qualification": {
            "qualified": false,
            "failure_code": "R11_PROTECTED_QUALIFICATION_UNAVAILABLE",
            "reason": R11_PROTECTED_QUALIFICATION_UNAVAILABLE,
            "h1_bootstrap_finalized": false,
            "h2_bootstrap_finalized": false,
            "h3_normal_etdag_finalized": false,
            "h4_steady_state_finalized": false,
            "twenty_block_pass": false,
            "protected_validator_restart_pass": false,
            "block_time_target_ms": HARNESS_TARGET_BLOCK_TIME_MS,
            "block_time_target_range_ms": [100, 1100]
        },
        "work_dir": work_dir
    }))
}

fn run_worker(validator_index: usize, generation: u64, work_dir: &Path) -> Result<(), String> {
    if validator_index >= VALIDATOR_COUNT {
        return Err("worker validator index is out of range".to_string());
    }
    let configuration: PublicConfiguration =
        read_message_pack(&public_configuration_path(work_dir))?;
    let private_key: PrivateKeyRecord =
        read_message_pack(&worker_private_key_path(work_dir, validator_index))?;
    let validators = configuration.activation.frozen_validator_set.clone();
    let signer = harness_signer(validator_index, &validators, private_key)?;
    let verifier = harness_verifier(&configuration)?;
    let context = configuration.epoch_context.clone();
    let cluster_map = ClusterMap::derive_from_finalized_epoch_seed(
        &validators.active_for_epoch(context.epoch),
        context.finalized_epoch_seed_root,
    )?;
    let execution_state = ExecutionState::new();
    let material_store = DurableSimplifiedProposalMaterialStore::at_directory(
        worker_material_directory(work_dir, validator_index),
        context.root()?,
    )?;
    let core_adapter = SimplifiedCoreMaterialAdapter::new(
        context.clone(),
        SimplifiedCoreMaterialConfiguration {
            validator_set: validators.clone(),
            cluster_map: cluster_map.clone(),
            execution_state: execution_state.clone(),
            parent_fee_market: None,
            cryptographic_profile_root: Hash::from_domain_bytes(
                "SYNERGY_POSY_AUTONOMOUS_HARNESS_CRYPTO_PROFILE_V1",
                b"mldsa65-core",
            ),
            epoch_start_timestamp_ms: 1_000_000,
            target_block_time_ms: HARNESS_TARGET_BLOCK_TIME_MS,
            app_version: 1,
            execution_version: 1,
            dag_version: 2,
            aegis_pqvm_version: "aegis-pqvm-autonomous-harness-v1".to_string(),
        },
    )?;
    let proposal_source = DurableVerifiedSimplifiedProposalSource::new(
        context.clone(),
        material_store.clone(),
        core_adapter,
    )?;
    let genesis_parent =
        SimplifiedFinalityParent::genesis(configuration.genesis_finality_reference.clone())?;
    genesis_parent.validate_for_child_height(Height(EPOCH_START_HEIGHT))?;
    let anchor_finalized =
        FinalizedBlockRecord::from_genesis(configuration.genesis_finality_reference.clone())?;
    let finalization_sink = DurableSimplifiedFinalitySink::at_directory(
        worker_finality_directory(work_dir, validator_index),
        material_store,
        SimplifiedFinalityEnvironment {
            epoch_context: context.clone(),
            validator_set: validators.clone(),
            cluster_map,
            etdag_parameters: EtdagParameters::default(),
            consensus_verifier: verifier.clone(),
            etdag_verifier: verifier.clone(),
            anchor_finalized,
            anchor_finalized_fee_market: None,
            boundary_execution_state: execution_state,
        },
    )?;
    let (event_tx, event_rx) = mpsc::sync_channel::<WorkerEvent>(ROUTER_CAPACITY);
    let writer = thread::spawn(move || write_worker_events(event_rx));
    let egress = ProcessEgress {
        validator_index,
        generation,
        events: event_tx.clone(),
    };
    let timing = SimplifiedDriverTiming::from_activation(&configuration.activation)?;
    let local = validators
        .validators
        .get(validator_index)
        .ok_or_else(|| "local validator is absent".to_string())?;
    let mut driver = SimplifiedPosyDriver::new(
        context,
        validators.clone(),
        local.validator_id.clone(),
        local.consensus_public_key.key_id.clone(),
        DurableSimplifiedPosyStore::at_path(worker_state_path(work_dir, validator_index)),
        genesis_parent,
        DurableConsensusSigningAuthority::at_path(worker_signer_journal_path(
            work_dir,
            validator_index,
        )),
        signer,
        verifier,
        proposal_source,
        egress,
        finalization_sink,
        timing,
    )?;
    let (ingress_tx, ingress_rx) =
        mpsc::sync_channel::<SimplifiedConsensusEnvelope>(DRIVER_INGRESS_CAPACITY);
    let running = Arc::new(AtomicBool::new(true));
    event_tx
        .send(WorkerEvent::Ready {
            validator_index,
            generation,
        })
        .map_err(|_| "worker event writer stopped before ready".to_string())?;
    let driver_running = Arc::clone(&running);
    let (driver_result_tx, driver_result_rx) = mpsc::channel();
    let rejection_events = event_tx.clone();
    let driver_thread = thread::spawn(move || {
        let result = run_simplified_posy_driver_with_peer_rejection_observer(
            &mut driver,
            &ingress_rx,
            &driver_running,
            |message| {
                let _ = rejection_events.send(WorkerEvent::PeerRejected {
                    validator_index,
                    generation,
                    message: message.to_string(),
                });
            },
        )
        .map(|_| ());
        let _ = driver_result_tx.send(result);
    });
    let (command_tx, command_rx) = mpsc::channel();
    // The reader owns blocking stdin; dropping its handle lets process exit
    // after the driver stops without waiting for the parent pipe to close.
    let _command_reader = thread::spawn(move || read_parent_commands(command_tx));
    let mut fatal = None;
    loop {
        if let Ok(result) = driver_result_rx.try_recv() {
            if let Err(error) = result {
                fatal = Some(error);
            }
            break;
        }
        match command_rx.recv_timeout(Duration::from_millis(25)) {
            Ok(Ok(ParentCommand::Deliver { from, message })) => {
                validate_simplified_consensus_message_size(&message)?;
                let peer = authenticated_peer(&validators, from)?;
                ingress_tx
                    .try_send(SimplifiedConsensusEnvelope {
                        peer_address: format!("validator-{from}"),
                        authenticated_peer: peer,
                        message,
                    })
                    .map_err(|error| format!("bounded driver ingress rejected frame: {error}"))?;
            }
            Ok(Ok(ParentCommand::Stop)) | Err(mpsc::RecvTimeoutError::Disconnected) => {
                running.store(false, Ordering::Release);
                break;
            }
            Ok(Err(error)) => {
                fatal = Some(error);
                running.store(false, Ordering::Release);
                break;
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
        }
    }
    running.store(false, Ordering::Release);
    driver_thread
        .join()
        .map_err(|_| "simplified driver thread panicked".to_string())?;
    if fatal.is_none() {
        if let Ok(Err(error)) = driver_result_rx.try_recv() {
            fatal = Some(error);
        }
    }
    if let Some(message) = fatal {
        let _ = event_tx.send(WorkerEvent::Fatal {
            validator_index,
            generation,
            message,
        });
    }
    let _ = event_tx.send(WorkerEvent::Stopped {
        validator_index,
        generation,
    });
    drop(event_tx);
    let _ = writer.join();
    Ok(())
}

fn write_worker_events(receiver: mpsc::Receiver<WorkerEvent>) {
    let mut stdout = std::io::stdout().lock();
    for event in receiver {
        let Ok(mut bytes) = serde_json::to_vec(&event) else {
            break;
        };
        if bytes.len() > MAX_ROUTED_FRAME_BYTES {
            break;
        }
        bytes.push(b'\n');
        if stdout
            .write_all(&bytes)
            .and_then(|()| stdout.flush())
            .is_err()
        {
            break;
        }
    }
}

fn read_parent_commands(sender: mpsc::Sender<Result<ParentCommand, String>>) {
    let stdin = std::io::stdin();
    for line in stdin.lock().lines() {
        let result = line
            .map_err(|error| format!("read parent command: {error}"))
            .and_then(|line| {
                if line.len() > MAX_ROUTED_FRAME_BYTES {
                    return Err("parent command exceeds bounded router frame".to_string());
                }
                serde_json::from_str(&line)
                    .map_err(|error| format!("parse parent command: {error}"))
            });
        if sender.send(result).is_err() {
            return;
        }
    }
}

fn spawn_worker(
    executable: &Path,
    work_dir: &Path,
    index: usize,
    generation: u64,
    events: mpsc::Sender<ObservedEvent>,
) -> Result<WorkerHandle, String> {
    let mut child = Command::new(executable)
        .arg("worker")
        .arg("--validator-index")
        .arg(index.to_string())
        .arg("--generation")
        .arg(generation.to_string())
        .arg("--work-dir")
        .arg(work_dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|error| format!("spawn validator-{index}: {error}"))?;
    let stdin = child
        .stdin
        .take()
        .ok_or_else(|| format!("validator-{index} stdin unavailable"))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| format!("validator-{index} stdout unavailable"))?;
    thread::spawn(move || {
        let reader = BufReader::new(stdout);
        for line in reader.lines() {
            let result = line
                .map_err(|error| format!("read validator-{index} event: {error}"))
                .and_then(|line| {
                    if line.len() > MAX_ROUTED_FRAME_BYTES {
                        return Err(format!("validator-{index} event exceeds frame bound"));
                    }
                    serde_json::from_str::<WorkerEvent>(&line)
                        .map_err(|error| format!("parse validator-{index} event: {error}"))
                });
            if events
                .send(ObservedEvent {
                    validator_index: index,
                    generation,
                    result,
                })
                .is_err()
            {
                return;
            }
        }
    });
    Ok(WorkerHandle {
        index,
        child,
        stdin,
    })
}

#[allow(clippy::too_many_arguments)]
fn restart_worker(
    executable: &Path,
    work_dir: &Path,
    index: usize,
    event_tx: &mpsc::Sender<ObservedEvent>,
    event_rx: &mpsc::Receiver<ObservedEvent>,
    workers: &mut [WorkerHandle],
    generations: &mut [u64; VALIDATOR_COUNT],
    validators: &ValidatorSet,
    policy: &mut NetworkPolicy,
) -> Result<(), String> {
    let _ = workers[index].send(&ParentCommand::Stop);
    let _ = workers[index].child.wait();
    generations[index] = generations[index].saturating_add(1);
    workers[index] = spawn_worker(
        executable,
        work_dir,
        index,
        generations[index],
        event_tx.clone(),
    )?;
    let expected_generation = generations[index];
    wait_until(
        Duration::from_secs(15),
        event_rx,
        workers,
        generations,
        validators,
        policy,
        |event, _| {
            matches!(
                event,
                WorkerEvent::Ready {
                    validator_index,
                    generation
                } if *validator_index == index && *generation == expected_generation
            )
        },
    )
}

fn stop_all(workers: &mut [WorkerHandle]) {
    for worker in workers.iter_mut() {
        let _ = worker.send(&ParentCommand::Stop);
    }
    for worker in workers.iter_mut() {
        let _ = worker.child.wait();
    }
}

fn route_event(
    observed: ObservedEvent,
    workers: &mut [WorkerHandle],
    generations: &[u64; VALIDATOR_COUNT],
    validators: &ValidatorSet,
    policy: &mut NetworkPolicy,
) -> Result<Option<WorkerEvent>, String> {
    if observed.generation != generations[observed.validator_index] {
        return Ok(None);
    }
    let event = observed.result?;
    match &event {
        WorkerEvent::Broadcast {
            validator_index,
            generation,
            message,
        } if *generation == generations[*validator_index] => {
            count_message(&mut policy.counters, message);
            let recipients = (0..VALIDATOR_COUNT)
                .filter(|to| *to != *validator_index)
                .collect::<Vec<_>>();
            for to in recipients {
                route_delivery(
                    workers,
                    validators,
                    policy,
                    *validator_index,
                    to,
                    message.clone(),
                )?;
            }
            if !policy.freeze_triggered
                && matches!(
                    message,
                    SimplifiedConsensusMessage::QuorumCertificate { certificate }
                        if policy.freeze_at_qc_height == Some(certificate.context.height.0)
                )
            {
                policy.captured_sync_qc = Some((*validator_index, message.clone()));
                policy.freeze_triggered = true;
                policy.freeze_all();
            }
        }
        WorkerEvent::Send {
            validator_index: from,
            generation,
            expected_validator_id,
            message,
        } if *generation == generations[*from] => {
            count_message(&mut policy.counters, message);
            let to = validator_index(validators, expected_validator_id)?;
            route_delivery(workers, validators, policy, *from, to, message.clone())?;
        }
        WorkerEvent::Fatal {
            validator_index,
            message,
            ..
        } => {
            policy.unavailable.insert(*validator_index);
            policy.isolate(*validator_index);
            if !policy.allowed_fatal.contains(validator_index) {
                return Err(format!(
                    "validator-{validator_index} driver failed: {message}"
                ));
            }
        }
        WorkerEvent::PeerRejected {
            validator_index,
            message,
            ..
        } if message.contains("state-sync") => {
            return Err(format!(
                "validator-{validator_index} rejected state-sync traffic: {message}"
            ));
        }
        _ => {}
    }
    Ok(Some(event))
}

fn route_delivery(
    workers: &mut [WorkerHandle],
    validators: &ValidatorSet,
    policy: &mut NetworkPolicy,
    from: usize,
    to: usize,
    message: SimplifiedConsensusMessage,
) -> Result<(), String> {
    if policy.permits(from, to, &message) {
        deliver(workers, validators, from, to, message)?;
        policy.counters.delivered_frames = policy.counters.delivered_frames.saturating_add(1);
    } else {
        policy.counters.dropped_frames = policy.counters.dropped_frames.saturating_add(1);
    }
    Ok(())
}

fn deliver(
    workers: &mut [WorkerHandle],
    validators: &ValidatorSet,
    from: usize,
    to: usize,
    message: SimplifiedConsensusMessage,
) -> Result<(), String> {
    if from >= VALIDATOR_COUNT || to >= VALIDATOR_COUNT || from == to {
        return Err("invalid harness route".to_string());
    }
    validate_simplified_consensus_message_size(&message)?;
    authenticated_peer(validators, from)?;
    workers[to].send(&ParentCommand::Deliver { from, message })
}

fn count_message(counters: &mut RouterCounters, message: &SimplifiedConsensusMessage) {
    match message {
        SimplifiedConsensusMessage::Proposal { .. } => {
            counters.proposals = counters.proposals.saturating_add(1)
        }
        SimplifiedConsensusMessage::Vote { .. } => {
            counters.votes = counters.votes.saturating_add(1)
        }
        SimplifiedConsensusMessage::QuorumCertificate { .. } => {
            counters.quorum_certificates = counters.quorum_certificates.saturating_add(1)
        }
        SimplifiedConsensusMessage::TimeoutVote { .. } => {
            counters.timeout_votes = counters.timeout_votes.saturating_add(1)
        }
        SimplifiedConsensusMessage::TimeoutCertificate { .. } => {
            counters.timeout_certificates = counters.timeout_certificates.saturating_add(1)
        }
        SimplifiedConsensusMessage::MaterialRequest { .. } => {
            counters.material_requests = counters.material_requests.saturating_add(1)
        }
        SimplifiedConsensusMessage::MaterialChunk { .. } => {
            counters.material_chunks = counters.material_chunks.saturating_add(1)
        }
        SimplifiedConsensusMessage::StateSyncRequest { .. } => {
            counters.state_sync_requests = counters.state_sync_requests.saturating_add(1)
        }
        SimplifiedConsensusMessage::StateSyncChunk { .. } => {
            counters.state_sync_chunks = counters.state_sync_chunks.saturating_add(1)
        }
        _ => {}
    }
}

#[allow(clippy::too_many_arguments)]
fn wait_until<F>(
    timeout: Duration,
    event_rx: &mpsc::Receiver<ObservedEvent>,
    workers: &mut [WorkerHandle],
    generations: &[u64; VALIDATOR_COUNT],
    validators: &ValidatorSet,
    policy: &mut NetworkPolicy,
    mut predicate: F,
) -> Result<(), String>
where
    F: FnMut(&WorkerEvent, &NetworkPolicy) -> bool,
{
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        match event_rx.recv_timeout(Duration::from_millis(25)) {
            Ok(observed) => {
                if let Some(event) =
                    route_event(observed, workers, generations, validators, policy)?
                {
                    if predicate(&event, policy) {
                        return Ok(());
                    }
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                let synthetic = WorkerEvent::Stopped {
                    validator_index: usize::MAX,
                    generation: 0,
                };
                if predicate(&synthetic, policy) {
                    return Ok(());
                }
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                return Err("all worker event readers disconnected".to_string())
            }
        }
    }
    Err(format!(
        "qualification condition timed out after {timeout:?}"
    ))
}

fn pump_for(
    duration: Duration,
    event_rx: &mpsc::Receiver<ObservedEvent>,
    workers: &mut [WorkerHandle],
    generations: &[u64; VALIDATOR_COUNT],
    validators: &ValidatorSet,
    policy: &mut NetworkPolicy,
) -> Result<(), String> {
    let deadline = Instant::now() + duration;
    while Instant::now() < deadline {
        match event_rx.recv_timeout(Duration::from_millis(25)) {
            Ok(observed) => {
                let _ = route_event(observed, workers, generations, validators, policy)?;
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                return Err("all worker event readers disconnected".to_string())
            }
        }
    }
    Ok(())
}

fn provision_configuration(work_dir: &Path) -> Result<PublicConfiguration, String> {
    if public_configuration_path(work_dir).exists() {
        return Err("refusing to reuse an existing autonomous harness directory".to_string());
    }
    let mut provisioner = AegisPqvmSigner::initialize_required().map_err(|e| e.to_string())?;
    let mut validators = Vec::with_capacity(VALIDATOR_COUNT);
    let mut public_keys = Vec::with_capacity(VALIDATOR_COUNT);
    for index in 0..VALIDATOR_COUNT {
        let uma = UmaId(format!("uma:autonomous-validator-{index}"));
        let key_id = provisioner
            .generate_and_register_key(
                &uma.0,
                vec![
                    AegisPqKeyRole::ConsensusProposer,
                    AegisPqKeyRole::ConsensusVote,
                ],
                Epoch(ACTIVATION_EPOCH),
            )
            .map_err(|error| error.to_string())?;
        let public_record = provisioner
            .public_key_record(&key_id)
            .map_err(|e| e.to_string())?;
        let public_key = provisioner
            .registry
            .public_key(&key_id)
            .cloned()
            .ok_or_else(|| "generated public key is unavailable".to_string())?;
        let private_key = provisioner
            .registry
            .private_key(&key_id)
            .cloned()
            .ok_or_else(|| "generated private key is unavailable".to_string())?;
        write_message_pack(
            &worker_private_key_path(work_dir, index),
            &PrivateKeyRecord {
                validator_index: index,
                public_key: public_key.clone(),
                private_key,
            },
            true,
        )?;
        validators.push(ValidatorRecord {
            validator_id: ValidatorId(format!("autonomous-validator-{index}")),
            validator_uma_id: uma,
            consensus_public_key: public_record.clone(),
            peer_public_key: public_record.clone(),
            operator_public_key: public_record,
            voting_weight: 1,
            status: ValidatorStatus::Active,
            cluster_id: ClusterId(0),
            activation_epoch: Epoch(ACTIVATION_EPOCH),
        });
        public_keys.push(public_key);
    }
    let validator_set = ValidatorSet {
        epoch: Epoch(ACTIVATION_EPOCH),
        validators,
    }
    .canonicalized();
    let manifest = finalized_manifest();
    let activation = GenesisBoundSimplifiedActivation {
        binding_schema_version: POSY_SIMPLIFIED_ACTIVATION_BINDING_SCHEMA_VERSION,
        binding_status: POSY_SIMPLIFIED_ACTIVATION_BINDING_STATUS.to_string(),
        governance_decision_id: manifest
            .governance_approval_id
            .clone()
            .ok_or_else(|| "harness manifest lacks approval".to_string())?,
        parameter_root_sha3_512: manifest.root()?.to_hex(),
        activation_epoch: ACTIVATION_EPOCH,
        activation_height: EPOCH_START_HEIGHT,
        manifest,
        frozen_validator_set: validator_set,
    };
    activation.validate()?;
    let genesis_finality_reference = harness_genesis_finality_reference(&activation)?;
    let epoch_context = activation.derive_fresh_genesis_epoch_context()?;
    let configuration = PublicConfiguration {
        activation,
        epoch_context,
        genesis_finality_reference,
        pqc_public_keys: public_keys,
    };
    write_message_pack(&public_configuration_path(work_dir), &configuration, false)?;
    Ok(configuration)
}

fn finalized_manifest() -> SimplifiedConsensusParameterManifest {
    SimplifiedConsensusParameterManifest {
        schema_version: 4,
        release_id: "testnet-v3".to_string(),
        status: POSY_SIMPLIFIED_PARAMETER_FINALIZED_STATUS.to_string(),
        governance_approval_id: Some("POSY-V3-AUTONOMOUS-HARNESS".to_string()),
        chain_id: ChainId::synergy_testnet_v3(),
        network_id: NetworkId::synergy_testnet_v3(),
        protocol_version: POSY_SIMPLIFIED_PROTOCOL_VERSION.to_string(),
        activation_boundary: POSY_SIMPLIFIED_FRESH_GENESIS_BOUNDARY.to_string(),
        activation_epoch: Some(0),
        activation_height: Some(1),
        epoch_length_blocks: EPOCH_LENGTH,
        active_validator_count: VALIDATOR_COUNT as u64,
        consensus_cluster_count: 1,
        healthy_path: vec!["PROPOSAL".into(), "VOTE".into(), "QC".into()],
        ordinary_vote_phases: 1,
        normal_qc_types: 1,
        exceptional_certificate: "TC".to_string(),
        chained_qc_commit_depth: 3,
        leader_schedule_domain: "PoSy/LeaderSchedule/v3".to_string(),
        leader_schedule_rank_bits: 512,
        leader_schedule_weighted: false,
        leader_lease_blocks: 10,
        takeover_rule: "sequential_strict_dual_quorum_tc_for_current_lease".to_string(),
        count_quorum_rule: "3*signed_count>2*active_validator_count".to_string(),
        required_distinct_signers: 4,
        weight_quorum_rule: "3*signed_weight>2*total_frozen_weight".to_string(),
        consensus_signature_algorithm: TESTNET_V3_CONSENSUS_SIGNATURE_ALGORITHM.to_string(),
        allow_quorum_reduction: false,
        allow_local_leader_election: false,
        require_single_validator_failure_liveness: true,
        signer_journal_required: true,
        safety_halt_on_conflicting_valid_qcs: true,
        etdag_finality_separation_required: true,
        protected_execution_binding_required: true,
        initial_etdag_activation: POSY_SIMPLIFIED_ETDAG_GOVERNED_GENESIS_BINDING_REQUIRED
            .to_string(),
        target_block_time_ms: HARNESS_TARGET_BLOCK_TIME_MS,
        proposal_timeout_ms: PROPOSAL_TIMEOUT_MS,
        vote_timeout_ms: VOTE_TIMEOUT_MS,
        max_round_timeout_ms: MAX_ROUND_TIMEOUT_MS,
        performance_targets: SimplifiedPerformanceTargets {
            proposal_latency_ms: PROPOSAL_TIMEOUT_MS,
            qc_formation_latency_ms: 1_500,
            chained_finality_latency_ms: 5_000,
            tc_recovery_latency_ms: 2_500,
            finality_p95_ms: 7_500,
            finality_p99_ms: 9_000,
        },
    }
}

fn harness_genesis_finality_reference(
    activation: &GenesisBoundSimplifiedActivation,
) -> Result<GenesisFinalityReference, String> {
    // This models the canonical fresh-Genesis binding the production runtime
    // receives from GenesisDocument.  It deliberately creates a tagged
    // Genesis parent rather than treating the block-zero hash as a QC.
    if activation.activation_epoch != 0 || activation.activation_height != 1 {
        return Err(
            "fresh Genesis harness activation must start at epoch zero, height one".to_string(),
        );
    }
    let genesis_hash = Hash::from_domain_bytes(
        "SYNERGY_POSY_AUTONOMOUS_HARNESS_CANONICAL_GENESIS_V1",
        &serde_json::to_vec(activation)
            .map_err(|error| format!("serialize harness fresh Genesis anchor: {error}"))?,
    );
    let reference = GenesisFinalityReference::from_canonical_genesis_hash(genesis_hash);
    reference.validate()?;
    Ok(reference)
}

fn harness_signer(
    index: usize,
    validators: &ValidatorSet,
    private: PrivateKeyRecord,
) -> Result<AegisPqvmSigner, String> {
    let validator = validators
        .validators
        .get(index)
        .ok_or_else(|| "private signer index is out of range".to_string())?;
    if private.validator_index != index
        || private.public_key.key_id != validator.consensus_public_key.key_id.0
        || private.private_key.public_key_id != private.public_key.key_id
        || private.public_key.key_data != validator.consensus_public_key.key_bytes
    {
        return Err("private key does not match frozen validator identity".to_string());
    }
    let mut signer = AegisPqvmSigner::initialize_required().map_err(|e| e.to_string())?;
    let key = signer
        .register_existing_keypair(
            &validator.validator_uma_id.0,
            private.public_key,
            private.private_key,
            vec![
                AegisPqKeyRole::ConsensusProposer,
                AegisPqKeyRole::ConsensusVote,
            ],
            Epoch(ACTIVATION_EPOCH),
        )
        .map_err(|e| e.to_string())?;
    if key != validator.consensus_public_key.key_id {
        return Err("registered signer key differs from frozen key".to_string());
    }
    Ok(signer)
}

fn harness_verifier(configuration: &PublicConfiguration) -> Result<AegisPqvmVerifier, String> {
    let validators = &configuration.activation.frozen_validator_set.validators;
    if validators.len() != configuration.pqc_public_keys.len() {
        return Err("public verifier registry length mismatch".to_string());
    }
    let mut registry = AegisPqvmKeyRegistry::default();
    for (validator, key) in validators.iter().zip(&configuration.pqc_public_keys) {
        if key.key_id != validator.consensus_public_key.key_id.0
            || key.key_data != validator.consensus_public_key.key_bytes
        {
            return Err("public verifier key differs from frozen validator".to_string());
        }
        registry.register_public_key(
            &validator.validator_uma_id.0,
            key.clone(),
            vec![
                AegisPqKeyRole::ConsensusProposer,
                AegisPqKeyRole::ConsensusVote,
            ],
            Epoch(ACTIVATION_EPOCH),
        );
    }
    AegisPqvmVerifier::initialize_required(registry).map_err(|e| e.to_string())
}

fn authenticated_peer(
    validators: &ValidatorSet,
    index: usize,
) -> Result<AuthenticatedSimplifiedConsensusPeer, String> {
    let validator = validators
        .validators
        .get(index)
        .ok_or_else(|| "authenticated peer index is out of range".to_string())?;
    Ok(AuthenticatedSimplifiedConsensusPeer {
        validator_id: validator.validator_id.clone(),
        validator_uma_id: validator.validator_uma_id.clone(),
        consensus_key_id: validator.consensus_public_key.key_id.clone(),
    })
}

fn validator_index(validators: &ValidatorSet, id: &ValidatorId) -> Result<usize, String> {
    validators
        .validators
        .iter()
        .position(|validator| &validator.validator_id == id)
        .ok_or_else(|| format!("validator {} is absent from frozen set", id.0))
}

fn require_same_view(
    work_dir: &Path,
    context: &SimplifiedEpochContext,
    indexes: &[usize],
) -> Result<(), String> {
    let states = indexes
        .iter()
        .map(|index| load_state(work_dir, *index, context))
        .collect::<Result<Vec<_>, _>>()?;
    let first = states
        .first()
        .ok_or_else(|| "cannot compare empty driver view".to_string())?;
    let first_root = first.consensus_authority_root()?;
    for state in states.iter().skip(1) {
        if state.consensus_authority_root()? != first_root {
            return Err("autonomous drivers disagree on consensus authority".to_string());
        }
    }
    Ok(())
}

fn load_state(
    work_dir: &Path,
    index: usize,
    context: &SimplifiedEpochContext,
) -> Result<SimplifiedSafetyState, String> {
    DurableSimplifiedPosyStore::at_path(worker_state_path(work_dir, index)).load(context)
}

fn material_record_count(work_dir: &Path, index: usize) -> Result<usize, String> {
    let path = worker_material_directory(work_dir, index);
    if !path.exists() {
        return Ok(0);
    }
    fs::read_dir(&path)
        .map_err(|error| format!("read material directory {}: {error}", path.display()))?
        .try_fold(0usize, |count, entry| {
            entry
                .map(|entry| count + usize::from(entry.path().is_file()))
                .map_err(|error| format!("read material entry: {error}"))
        })
}

fn durable_tree_root(root: &Path) -> Result<Hash, String> {
    let mut files = Vec::new();
    collect_durable_file_roots(root, root, &mut files)?;
    let subject = serde_json::to_vec(&files)
        .map_err(|error| format!("serialize durable tree {}: {error}", root.display()))?;
    Ok(Hash::from_domain_bytes(
        "SYNERGY_POSY_AUTONOMOUS_HARNESS_DURABLE_TREE_V1",
        &subject,
    ))
}

fn collect_durable_file_roots(
    root: &Path,
    current: &Path,
    files: &mut Vec<(String, u64, Hash)>,
) -> Result<(), String> {
    let mut entries = fs::read_dir(current)
        .map_err(|error| format!("read durable directory {}: {error}", current.display()))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| format!("read durable directory entry: {error}"))?;
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        let path = entry.path();
        let file_type = entry
            .file_type()
            .map_err(|error| format!("read durable file type {}: {error}", path.display()))?;
        if file_type.is_dir() {
            collect_durable_file_roots(root, &path, files)?;
        } else if file_type.is_file() {
            let bytes = fs::read(&path)
                .map_err(|error| format!("read durable file {}: {error}", path.display()))?;
            let relative = path
                .strip_prefix(root)
                .map_err(|error| format!("relativize durable file {}: {error}", path.display()))?
                .to_string_lossy()
                .into_owned();
            files.push((
                relative,
                u64::try_from(bytes.len())
                    .map_err(|_| "durable file length exceeds u64".to_string())?,
                Hash::from_domain_bytes("SYNERGY_POSY_AUTONOMOUS_HARNESS_DURABLE_FILE_V1", &bytes),
            ));
        } else {
            return Err(format!(
                "durable tree contains unsupported entry {}",
                path.display()
            ));
        }
    }
    Ok(())
}

fn write_message_pack<T: Serialize>(path: &Path, value: &T, private: bool) -> Result<(), String> {
    let bytes = rmp_serde::to_vec_named(value)
        .map_err(|error| format!("serialize {}: {error}", path.display()))?;
    let mut options = fs::OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(if private { 0o600 } else { 0o644 });
    }
    let mut file = options
        .open(path)
        .map_err(|error| format!("create {}: {error}", path.display()))?;
    file.write_all(&bytes)
        .and_then(|()| file.sync_all())
        .map_err(|error| format!("persist {}: {error}", path.display()))
}

fn read_message_pack<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T, String> {
    let bytes = fs::read(path).map_err(|error| format!("read {}: {error}", path.display()))?;
    rmp_serde::from_slice(&bytes).map_err(|error| format!("parse {}: {error}", path.display()))
}

fn private_material_is_mode_0600(work_dir: &Path) -> Result<bool, String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for index in 0..VALIDATOR_COUNT {
            let mode = fs::metadata(worker_private_key_path(work_dir, index))
                .map_err(|error| format!("stat private key: {error}"))?
                .permissions()
                .mode()
                & 0o777;
            if mode != 0o600 {
                return Ok(false);
            }
        }
    }
    Ok(true)
}

fn remove_private_material(work_dir: &Path) -> Result<(), String> {
    for index in 0..VALIDATOR_COUNT {
        let path = worker_private_key_path(work_dir, index);
        if path.exists() {
            fs::remove_file(&path)
                .map_err(|error| format!("remove private key {}: {error}", path.display()))?;
        }
    }
    Ok(())
}

fn public_configuration_path(work_dir: &Path) -> PathBuf {
    work_dir.join("autonomous-public-config.msgpack")
}

fn worker_private_key_path(work_dir: &Path, index: usize) -> PathBuf {
    work_dir.join(format!("validator-{index}-private-key.msgpack"))
}

fn worker_state_path(work_dir: &Path, index: usize) -> PathBuf {
    work_dir.join(format!("validator-{index}/safety-state.json"))
}

fn worker_signer_journal_path(work_dir: &Path, index: usize) -> PathBuf {
    work_dir.join(format!("validator-{index}/signer-journal.json"))
}

fn worker_material_directory(work_dir: &Path, index: usize) -> PathBuf {
    work_dir.join(format!("validator-{index}/material"))
}

fn worker_finality_directory(work_dir: &Path, index: usize) -> PathBuf {
    work_dir.join(format!("validator-{index}/finality"))
}

fn parse_arg(args: &[String], name: &str) -> Result<String, String> {
    optional_arg(args, name).ok_or_else(|| format!("missing required argument {name}"))
}

fn optional_arg(args: &[String], name: &str) -> Option<String> {
    args.windows(2)
        .find(|pair| pair[0] == name)
        .map(|pair| pair[1].clone())
}
