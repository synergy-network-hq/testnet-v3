//! Five-process qualification harness for the epoch-gated simplified PoSy
//! state machine.
//!
//! Every worker owns an ephemeral ML-DSA-65 key and invokes the production
//! proposal, block-vote, timeout-vote, QC, TC, signer-journal, and state-sync
//! paths. Private material is created mode-0600 under the caller's temporary
//! work directory and is never printed or committed.

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::env;
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use synergy_testnet::consensus::signing_authority::{
    ConsensusSigningAuthorization, ConsensusSigningPhase, DurableConsensusSigningAuthority,
};
use synergy_testnet::consensus::simplified_posy::{
    BlockVote, CertifiedCandidateSubject, ConsensusObjectContext, FinalizedBlockRecord,
    LastVoteRecord, MetricSummary, QuorumCertificateReference, ReliableDeliveryPhase,
    ReliableDeliveryState, ReliableDeliveryStatement, SimplifiedConsensusStateMachine,
    SimplifiedEpochContext, SimplifiedFinalityParent, SimplifiedProposal,
    SimplifiedQuorumCertificate, SimplifiedStateSyncBundle, SimplifiedTimeoutCertificate,
    TimeoutVote, POSY_SIMPLIFIED_PROPOSAL_ECHO_DOMAIN, POSY_SIMPLIFIED_PROPOSAL_READY_DOMAIN,
    POSY_SIMPLIFIED_TIMEOUT_VOTE_DOMAIN,
};
use synergy_testnet::consensus_parameters::ConsensusParameterRoot;
use synergy_testnet::crypto::aegis_pqvm::{
    AegisPqvmKeyRegistry, AegisPqvmSigner, AegisPqvmVerifier,
};
use synergy_testnet::crypto::pqc::{PQCPrivateKey, PQCPublicKey};
use synergy_testnet::synergy_types::{
    AegisPqKeyRole, AegisPqSignature, BlockId, ClusterId, Epoch, Hash, Height, Round, UmaId,
    ValidatorId, ValidatorRecord, ValidatorSet, ValidatorStatus,
};

const VALIDATOR_COUNT: usize = 5;
const EPOCH_START_HEIGHT: u64 = 1_000;
const EPOCH_END_HEIGHT: u64 = 1_099;
const QUORUM_SIGNERS: [usize; 4] = [0, 1, 2, 4];
const PARTITIONED_VALIDATOR: usize = 3;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct HarnessPublicConfiguration {
    validator_set: ValidatorSet,
    pqc_public_keys: Vec<PQCPublicKey>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct HarnessPrivateKey {
    validator_index: usize,
    public_key: PQCPublicKey,
    private_key: PQCPrivateKey,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "command", rename_all = "snake_case")]
enum Request {
    Snapshot {
        observed_live_validators: Vec<usize>,
        local_unix_ms: u64,
    },
    SignProposal {
        proposal: SimplifiedProposal,
    },
    BuildVote {
        proposal: SimplifiedProposal,
    },
    SignReliableDelivery {
        statement: ReliableDeliveryStatement,
    },
    BuildTimeoutVote,
    /// Produces cryptographically valid adversarial evidence for negative
    /// verification tests; never used by the healthy signing path.
    AdversarialSignTimeoutVote {
        vote: TimeoutVote,
    },
    AcceptQc {
        certificate: SimplifiedQuorumCertificate,
    },
    AcceptTc {
        certificate: SimplifiedTimeoutCertificate,
    },
    ExportStateSync,
    InstallStateSync {
        /// Opaque peer bytes. The parent relays but never interprets them;
        /// only the receiving worker deserializes and verifies the bundle.
        bundle_bytes: Vec<u8>,
    },
    Shutdown,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "result", rename_all = "snake_case")]
enum Response {
    Snapshot {
        snapshot: WorkerSnapshot,
    },
    Proposal {
        validator_index: usize,
        proposal: SimplifiedProposal,
    },
    Vote {
        validator_index: usize,
        vote: BlockVote,
    },
    ReliableDelivery {
        validator_index: usize,
        statement: ReliableDeliveryStatement,
    },
    TimeoutVote {
        validator_index: usize,
        vote: TimeoutVote,
    },
    AcceptedQc {
        snapshot: WorkerSnapshot,
        newly_finalized: Option<FinalizedBlockRecord>,
    },
    AcceptedTc {
        snapshot: WorkerSnapshot,
    },
    StateSync {
        validator_index: usize,
        bundle_bytes: Vec<u8>,
    },
    InstalledStateSync {
        snapshot: WorkerSnapshot,
    },
    Error {
        validator_index: usize,
        message: String,
    },
    Shutdown,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct WorkerSnapshot {
    validator_index: usize,
    epoch_context_root: String,
    leader_ring: Vec<String>,
    next_height: u64,
    highest_parent: SimplifiedFinalityParent,
    locked_qc: Option<QuorumCertificateReference>,
    finalized: FinalizedBlockRecord,
    takeover_offset: u64,
    takeover_tc_id: Option<Hash>,
    mandatory_carry_candidate: Option<CertifiedCandidateSubject>,
    authorized_proposer: String,
    safety_halt: bool,
    consensus_authority_root: String,
    last_vote: Option<LastVoteRecord>,
    signer_journal_root: Option<String>,
    metrics: Vec<MetricSummary>,
}

struct WorkerProcess {
    index: usize,
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
}

impl WorkerProcess {
    fn request(&mut self, request: &Request) -> Result<Response, String> {
        serde_json::to_writer(&mut self.stdin, request)
            .map_err(|error| format!("serialize harness request: {error}"))?;
        self.stdin
            .write_all(b"\n")
            .and_then(|_| self.stdin.flush())
            .map_err(|error| format!("write harness request: {error}"))?;
        let mut line = String::new();
        self.stdout
            .read_line(&mut line)
            .map_err(|error| format!("read harness response: {error}"))?;
        if line.is_empty() {
            return Err(format!(
                "validator-{} exited without a harness response",
                self.index
            ));
        }
        serde_json::from_str(&line)
            .map_err(|error| format!("parse harness response {line:?}: {error}"))
    }
}

fn main() {
    if let Err(error) = run() {
        eprintln!("POSY_SIMPLIFIED_HARNESS_FAILED: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let args = env::args().collect::<Vec<_>>();
    if args.get(1).map(String::as_str) == Some("worker") {
        let validator_index = parse_arg(&args, "--validator-index")?
            .parse::<usize>()
            .map_err(|error| format!("invalid validator index: {error}"))?;
        let state_path = PathBuf::from(parse_arg(&args, "--state")?);
        let public_configuration_path = PathBuf::from(parse_arg(&args, "--public-config")?);
        let private_key_path = PathBuf::from(parse_arg(&args, "--private-key")?);
        return run_worker(
            validator_index,
            &state_path,
            &public_configuration_path,
            &private_key_path,
        );
    }
    if args.get(1).map(String::as_str) != Some("run") {
        return Err("usage: posy-simplified-five-node-harness run [--work-dir PATH]".to_string());
    }
    let work_dir = optional_arg(&args, "--work-dir")
        .map(PathBuf::from)
        .unwrap_or_else(|| env::temp_dir().join(format!("posy-five-node-{}", std::process::id())));
    run_parent(&work_dir)
}

fn run_parent(work_dir: &Path) -> Result<(), String> {
    fs::create_dir_all(work_dir)
        .map_err(|error| format!("create harness directory {}: {error}", work_dir.display()))?;
    for path in std::iter::once(public_configuration_path(work_dir)).chain(
        (0..VALIDATOR_COUNT).flat_map(|index| {
            [
                worker_state_path(work_dir, index),
                worker_private_key_path(work_dir, index),
            ]
        }),
    ) {
        if path.exists() {
            return Err(format!(
                "refusing to reuse existing harness material {}; choose a fresh --work-dir",
                path.display()
            ));
        }
    }

    let executable =
        env::current_exe().map_err(|error| format!("resolve harness executable: {error}"))?;
    let public_configuration = provision_harness_keys(work_dir)?;
    let validators = public_configuration.validator_set.clone();
    let context = harness_context(&validators)?;
    let verifier = harness_verifier(&public_configuration)?;
    let mut workers = (0..VALIDATOR_COUNT)
        .map(|index| spawn_worker(&executable, work_dir, index))
        .collect::<Result<Vec<_>, _>>()?;
    let qualification = run_qualification(
        &executable,
        work_dir,
        &context,
        &validators,
        &verifier,
        &mut workers,
    );
    shutdown_all(&mut workers);
    let private_key_cleanup = remove_ephemeral_private_keys(work_dir);
    let report = qualification?;
    private_key_cleanup?;
    println!(
        "{}",
        serde_json::to_string_pretty(&report)
            .map_err(|error| format!("serialize harness summary: {error}"))?
    );
    Ok(())
}

fn run_qualification(
    executable: &Path,
    work_dir: &Path,
    context: &SimplifiedEpochContext,
    validators: &ValidatorSet,
    verifier: &AegisPqvmVerifier,
    workers: &mut [WorkerProcess],
) -> Result<serde_json::Value, String> {
    let mut qc_proofs = Vec::new();
    let observations = [
        (vec![0, 1, 2, 3, 4], 1_000),
        (vec![0, 1, 2, 3], 90_000),
        (vec![0, 2, 4], 5),
        (vec![3], 4_000_000),
        (Vec::new(), 999_999_999),
    ];
    let mut initial = Vec::new();
    for (worker, (observed_live_validators, local_unix_ms)) in workers.iter_mut().zip(observations)
    {
        initial.push(snapshot_from(worker.request(&Request::Snapshot {
            observed_live_validators,
            local_unix_ms,
        })?)?);
    }
    require_same_consensus_view(&initial)?;

    // One unavailable validator: four independent workers form and verify a
    // real QC chain. The fifth process is left at the anchor as a partitioned
    // peer, and three QCs prove actual chained finality at height 1000.
    for height in EPOCH_START_HEIGHT..=EPOCH_START_HEIGHT + 2 {
        let source_view = initial_or_live(workers, 0)?;
        let proposal = proposal_from_snapshot(workers, context, validators, &source_view, height)?;
        let signer_arrival_order: &[usize] = if height == EPOCH_START_HEIGHT + 1 {
            &[4, 1, 0, 2]
        } else {
            &QUORUM_SIGNERS
        };
        let qc = collect_qc(
            workers,
            context,
            validators,
            verifier,
            &proposal,
            signer_arrival_order,
        )?;
        accept_qc_on(workers, &qc, &QUORUM_SIGNERS)?;
        qc_proofs.push(qc);
    }
    let four_node_view = initial_or_live(workers, 0)?;
    if four_node_view.finalized.height != Height(EPOCH_START_HEIGHT) {
        return Err(format!(
            "three-QC chain finalized height {}, expected {EPOCH_START_HEIGHT}",
            four_node_view.finalized.height.0
        ));
    }
    let partitioned_view = initial_or_live(workers, PARTITIONED_VALIDATOR)?;
    if partitioned_view.highest_parent.height() != Height(EPOCH_START_HEIGHT - 1) {
        return Err(
            "partitioned worker unexpectedly learned an uncertified local view".to_string(),
        );
    }

    // Two unavailable validators: three correctly signed votes still fail
    // closed in SimplifiedQuorumCertificate::verify (exact count and weight).
    let proposal = proposal_from_snapshot(
        workers,
        context,
        validators,
        &four_node_view,
        EPOCH_START_HEIGHT + 3,
    )?;
    let three_vote_qc = collect_unverified_qc(
        workers,
        context,
        validators,
        verifier,
        &proposal,
        &[0, 1, 2],
    )?;
    expect_error(
        workers[0].request(&Request::AcceptQc {
            certificate: three_vote_qc,
        })?,
        "strict distinct-signer quorum failed",
    )?;
    if initial_or_live(workers, 0)?.highest_parent != four_node_view.highest_parent {
        return Err("rejected three-of-five QC mutated durable safety state".to_string());
    }
    let mut invalid_signature_qc = collect_unverified_qc(
        workers,
        context,
        validators,
        verifier,
        &proposal,
        &QUORUM_SIGNERS,
    )?;
    invalid_signature_qc.participants[0]
        .signature
        .signature_bytes[0] ^= 0xff;
    expect_error(
        workers[0].request(&Request::AcceptQc {
            certificate: invalid_signature_qc,
        })?,
        "verification",
    )?;

    // Heal the partition exclusively through the verified, anchored state-sync
    // bundle. No cached highest/lock/finality fields are trusted from the peer.
    let bundle = export_state_sync(&mut workers[0])?;
    install_state_sync(&mut workers[PARTITIONED_VALIDATOR], bundle)?;
    require_same_consensus_view(&snapshots_for(workers, &[0, PARTITIONED_VALIDATOR])?)?;

    // Form two sequential TCs on four workers. The lagging worker is
    // partitioned again, then learns the verified takeover chain through state
    // sync and survives a full process restart with the same authority.
    let first_tc = collect_tc(workers, &QUORUM_SIGNERS, &qc_proofs)?;
    accept_tc_on(workers, &first_tc, &QUORUM_SIGNERS)?;
    expect_error(
        workers[0].request(&Request::AcceptTc {
            certificate: first_tc.clone(),
        })?,
        "stale, skipped, or non-sequential timeout certificate",
    )?;

    let second_tc = collect_tc(workers, &QUORUM_SIGNERS, &qc_proofs)?;
    let mut wrong_highest = second_tc.clone();
    for report in &mut wrong_highest.reports {
        report.highest_parent = anchor_parent()?;
    }
    wrong_highest.highest_qc_proofs.clear();
    resign_tc(workers, &mut wrong_highest, validators)?;
    expect_error(
        workers[0].request(&Request::AcceptTc {
            certificate: wrong_highest,
        })?,
        "stale, skipped, or non-sequential timeout certificate",
    )?;
    accept_tc_on(workers, &second_tc, &QUORUM_SIGNERS)?;
    let takeover_source = initial_or_live(workers, 0)?;
    if takeover_source.takeover_offset != 2 {
        return Err("two certified timeouts did not advance to takeover offset 2".to_string());
    }

    let takeover_bundle = export_state_sync(&mut workers[0])?;
    install_state_sync(&mut workers[PARTITIONED_VALIDATOR], takeover_bundle)?;
    let learned_takeover = initial_or_live(workers, PARTITIONED_VALIDATOR)?;
    if consensus_view(&learned_takeover) != consensus_view(&takeover_source) {
        return Err("partition heal did not reconstruct verified takeover authority".to_string());
    }
    restart_worker(executable, work_dir, workers, PARTITIONED_VALIDATOR)?;
    let restarted_takeover = initial_or_live(workers, PARTITIONED_VALIDATOR)?;
    if consensus_view(&restarted_takeover) != consensus_view(&takeover_source) {
        return Err("restarted worker forgot verified takeover authority".to_string());
    }

    // Certify three blocks under inherited lease authority. This proves the
    // actual state machine finalizes a takeover branch with the three-chain
    // rule, rather than merely changing a toy leader counter.
    for height in EPOCH_START_HEIGHT + 3..=EPOCH_START_HEIGHT + 5 {
        let view = initial_or_live(workers, 0)?;
        let proposal = proposal_from_snapshot(workers, context, validators, &view, height)?;
        let qc = collect_qc(
            workers,
            context,
            validators,
            verifier,
            &proposal,
            &QUORUM_SIGNERS,
        )?;
        accept_qc_on(workers, &qc, &[0, 1, 2, 3, 4])?;
        qc_proofs.push(qc);
    }
    let takeover_finality = initial_or_live(workers, 0)?;
    if takeover_finality.finalized.height != Height(EPOCH_START_HEIGHT + 3) {
        return Err(format!(
            "takeover three-chain finalized {}, expected {}",
            takeover_finality.finalized.height.0,
            EPOCH_START_HEIGHT + 3
        ));
    }

    // Finish the first 10-block lease under the inherited owner. The next
    // predetermined lease resets the TC offset to zero without an operator or
    // local-health election.
    for height in EPOCH_START_HEIGHT + 6..=EPOCH_START_HEIGHT + 10 {
        let view = initial_or_live(workers, 0)?;
        if height < EPOCH_START_HEIGHT + 10 && view.takeover_offset != 2 {
            return Err("takeover did not persist through the remainder of its lease".to_string());
        }
        if height == EPOCH_START_HEIGHT + 10 && view.takeover_offset != 0 {
            return Err("takeover did not reset at the predetermined lease boundary".to_string());
        }
        let proposal = proposal_from_snapshot(workers, context, validators, &view, height)?;
        let qc = collect_qc(
            workers,
            context,
            validators,
            verifier,
            &proposal,
            &QUORUM_SIGNERS,
        )?;
        accept_qc_on(workers, &qc, &[0, 1, 2, 3, 4])?;
        qc_proofs.push(qc);
    }

    // Repeated single-leader failures: forty sequential, real TC objects are
    // built from four timeout votes, signature/quorum verified, durably stored,
    // and installed by all five processes. A subsequent QC demonstrates
    // recovery after the adversarial timeout sequence.
    let repeated_failure_rounds = 40u64;
    for expected_offset in 1..=repeated_failure_rounds {
        let tc = collect_tc(workers, &QUORUM_SIGNERS, &qc_proofs)?;
        accept_tc_on(workers, &tc, &[0, 1, 2, 3, 4])?;
        let view = initial_or_live(workers, 0)?;
        if view.takeover_offset != expected_offset {
            return Err(format!(
                "repeated failure offset {}, expected {expected_offset}",
                view.takeover_offset
            ));
        }
    }
    let recovered_height = EPOCH_START_HEIGHT + 11;
    let recovered_view = initial_or_live(workers, 0)?;
    let recovered_proposal = proposal_from_snapshot(
        workers,
        context,
        validators,
        &recovered_view,
        recovered_height,
    )?;
    let mut recovered_qc = collect_qc(
        workers,
        context,
        validators,
        verifier,
        &recovered_proposal,
        &QUORUM_SIGNERS,
    )?;
    let before_signer_restart = initial_or_live(workers, 2)?;
    if before_signer_restart
        .last_vote
        .as_ref()
        .is_none_or(|last_vote| last_vote.height != Height(recovered_height))
        || before_signer_restart.signer_journal_root.is_none()
    {
        return Err(
            "production vote did not durably record last-vote and journal state".to_string(),
        );
    }
    restart_worker(executable, work_dir, workers, 2)?;
    let after_signer_restart = initial_or_live(workers, 2)?;
    if after_signer_restart.last_vote != before_signer_restart.last_vote
        || after_signer_restart.signer_journal_root != before_signer_restart.signer_journal_root
    {
        return Err("OS-process restart lost last-vote or signer-journal authority".to_string());
    }
    let repeated_vote = match workers[2].request(&Request::BuildVote {
        proposal: recovered_proposal.clone(),
    })? {
        Response::Vote { vote, .. } => vote,
        Response::Error { message, .. } => return Err(message),
        other => {
            return Err(format!(
                "expected repeated post-restart vote, found {other:?}"
            ))
        }
    };
    let participant = recovered_qc
        .participants
        .iter_mut()
        .find(|participant| participant.validator_id == repeated_vote.validator_id)
        .ok_or_else(|| "restarted validator is absent from recovery QC".to_string())?;
    participant.signature = repeated_vote.signature;
    accept_qc_on(workers, &recovered_qc, &[0, 1, 2, 3, 4])?;
    require_same_consensus_view(&snapshots_for(workers, &[0, 1, 2, 3, 4])?)?;

    let final_view = initial_or_live(workers, 0)?;
    let metric_names = final_view
        .metrics
        .iter()
        .map(|summary| summary.name.clone())
        .collect::<BTreeSet<_>>();
    for required in [
        "posy_v3_pqc_verification_us",
        "posy_v3_certificate_size_bytes",
        "posy_v3_tc_recovery_latency_us",
        "posy_v3_leader_takeover_latency_us",
    ] {
        if !metric_names.contains(required) {
            return Err(format!("worker metrics omitted required sample {required}"));
        }
    }

    Ok(serde_json::json!({
        "status": "PASS",
        "processes": VALIDATOR_COUNT,
        "execution": "five independent OS worker processes",
        "state_machine": "SimplifiedConsensusStateMachine",
        "signature_mode": "per-worker ephemeral ML-DSA-65 through production proposal/vote/timeout signing and Aegis verification",
        "ephemeral_private_keys_removed": true,
        "durable_signer_restart_verified": true,
        "quorum": "exact 4-of-5 and strict 3*signed_weight > 2*total_weight",
        "highest_certified_height": final_view.highest_parent.height().0,
        "finalized_height": final_view.finalized.height.0,
        "repeated_failure_rounds": repeated_failure_rounds,
        "final_takeover_offset": final_view.takeover_offset,
        "scenarios": [
            "immutable_epoch_ring_despite_clock_and_health_divergence",
            "one_unavailable_four_of_five_qc_progress",
            "two_unavailable_three_of_five_fail_closed",
            "invalid_certificate_signature_fail_closed",
            "three_qc_chained_finality",
            "stale_tc_rejection",
            "wrong_highest_parent_tc_rejection",
            "two_sequential_tc_lease_inheritance",
            "verified_state_sync_partition_heal",
            "restart_preserves_verified_takeover",
            "restart_preserves_last_vote_and_signer_journal",
            "authenticated_echo_ready_delivery_before_block_vote",
            "takeover_three_chain_finality",
            "ten_block_lease_and_boundary_reset",
            "forty_repeated_single_leader_failures_and_recovery",
            "real_qc_tc_canonicalization_signature_and_metric_paths"
        ],
        "work_dir": work_dir,
    }))
}

fn run_worker(
    validator_index: usize,
    state_path: &Path,
    public_configuration_path: &Path,
    private_key_path: &Path,
) -> Result<(), String> {
    if validator_index >= VALIDATOR_COUNT {
        return Err(format!(
            "worker validator index must be in 0..{VALIDATOR_COUNT}"
        ));
    }
    let public_configuration: HarnessPublicConfiguration =
        read_message_pack(public_configuration_path)?;
    let private_key: HarnessPrivateKey = read_message_pack(private_key_path)?;
    if private_key.validator_index != validator_index {
        return Err("worker private-key index does not match process identity".to_string());
    }
    let validators = public_configuration.validator_set.clone();
    let context = harness_context(&validators)?;
    let mut signer = harness_signer(validator_index, &validators, private_key)?;
    let verifier = harness_verifier(&public_configuration)?;
    let store = synergy_testnet::consensus::simplified_posy::DurableSimplifiedPosyStore::at_path(
        state_path,
    );
    let signer_journal =
        DurableConsensusSigningAuthority::at_path(state_path.with_extension("signer-journal.json"));
    let mut machine = SimplifiedConsensusStateMachine::open(
        context.clone(),
        validators.clone(),
        store,
        anchor_parent()?,
    )?;
    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout();
    for line in stdin.lock().lines() {
        let line = line.map_err(|error| format!("read worker request: {error}"))?;
        let request: Request = serde_json::from_str(&line)
            .map_err(|error| format!("parse worker request: {error}"))?;
        let response = handle_worker_request(
            validator_index,
            &context,
            &validators,
            &signer_journal,
            &mut signer,
            &verifier,
            &mut machine,
            request,
        );
        serde_json::to_writer(&mut stdout, &response)
            .map_err(|error| format!("serialize worker response: {error}"))?;
        stdout
            .write_all(b"\n")
            .and_then(|_| stdout.flush())
            .map_err(|error| format!("write worker response: {error}"))?;
        if response == Response::Shutdown {
            return Ok(());
        }
    }
    Ok(())
}

fn handle_worker_request(
    validator_index: usize,
    context: &SimplifiedEpochContext,
    validators: &ValidatorSet,
    signer_journal: &DurableConsensusSigningAuthority,
    signer: &mut AegisPqvmSigner,
    verifier: &AegisPqvmVerifier,
    machine: &mut SimplifiedConsensusStateMachine,
    request: Request,
) -> Response {
    let result = match request {
        Request::Snapshot {
            observed_live_validators: _,
            local_unix_ms: _,
        } => snapshot(machine, context, signer_journal, validator_index)
            .map(|snapshot| Response::Snapshot { snapshot }),
        Request::SignProposal { proposal } => machine
            .sign_proposal(proposal, signer_journal, signer)
            .map(|proposal| Response::Proposal {
                validator_index,
                proposal,
            }),
        Request::BuildVote { proposal } => build_vote(
            machine,
            validators,
            validator_index,
            proposal,
            signer_journal,
            signer,
            verifier,
        )
        .map(|vote| Response::Vote {
            validator_index,
            vote,
        }),
        Request::SignReliableDelivery { statement } => sign_reliable_delivery_statement(
            context,
            validators,
            validator_index,
            statement,
            signer_journal,
            signer,
        )
        .map(|statement| Response::ReliableDelivery {
            validator_index,
            statement,
        }),
        Request::BuildTimeoutVote => {
            build_timeout_vote(machine, validators, validator_index, signer_journal, signer).map(
                |vote| Response::TimeoutVote {
                    validator_index,
                    vote,
                },
            )
        }
        Request::AdversarialSignTimeoutVote { mut vote } => vote
            .signing_bytes()
            .and_then(|bytes| {
                signer
                    .sign_domain(POSY_SIMPLIFIED_TIMEOUT_VOTE_DOMAIN, &bytes, &vote.key_id)
                    .map_err(|error| error.to_string())
            })
            .map(|signature| {
                vote.signature = signature;
                Response::TimeoutVote {
                    validator_index,
                    vote,
                }
            }),
        Request::AcceptQc { certificate } => machine
            .accept_quorum_certificate(certificate, verifier, signer_journal)
            .and_then(|newly_finalized| {
                snapshot(machine, context, signer_journal, validator_index).map(|snapshot| {
                    Response::AcceptedQc {
                        snapshot,
                        newly_finalized,
                    }
                })
            }),
        Request::AcceptTc { certificate } => machine
            .accept_timeout_certificate(certificate, verifier)
            .and_then(|()| {
                snapshot(machine, context, signer_journal, validator_index)
                    .map(|snapshot| Response::AcceptedTc { snapshot })
            }),
        Request::ExportStateSync => machine.export_state_sync_bundle().and_then(|bundle| {
            rmp_serde::to_vec_named(&bundle)
                .map(|bundle_bytes| Response::StateSync {
                    validator_index,
                    bundle_bytes,
                })
                .map_err(|error| format!("serialize state-sync peer payload: {error}"))
        }),
        Request::InstallStateSync { bundle_bytes } => rmp_serde::from_slice::<
            SimplifiedStateSyncBundle,
        >(&bundle_bytes)
        .map_err(|error| format!("parse untrusted state-sync peer payload: {error}"))
        .and_then(|bundle| machine.install_state_sync_bundle(&bundle, verifier, signer_journal))
        .and_then(|()| {
            snapshot(machine, context, signer_journal, validator_index)
                .map(|snapshot| Response::InstalledStateSync { snapshot })
        }),
        Request::Shutdown => return Response::Shutdown,
    };
    result.unwrap_or_else(|message| Response::Error {
        validator_index,
        message,
    })
}

fn snapshot(
    machine: &SimplifiedConsensusStateMachine,
    context: &SimplifiedEpochContext,
    signer_journal: &DurableConsensusSigningAuthority,
    validator_index: usize,
) -> Result<WorkerSnapshot, String> {
    let state = machine.state();
    let next_height = state.next_height()?;
    let (takeover_offset, takeover_tc_id) = state.takeover_for_height(context, next_height)?;
    let mandatory_carry_candidate = state
        .takeover
        .as_ref()
        .and_then(|takeover| takeover.certificates.last())
        .map(SimplifiedTimeoutCertificate::mandatory_carry_candidate)
        .transpose()?
        .flatten()
        .filter(|candidate| candidate.context.height == next_height);
    Ok(WorkerSnapshot {
        validator_index,
        epoch_context_root: context.root()?.to_hex(),
        leader_ring: context
            .leader_ring
            .iter()
            .map(|validator| validator.0.clone())
            .collect(),
        next_height: next_height.0,
        highest_parent: state.highest_parent.clone(),
        locked_qc: state.locked_qc.clone(),
        finalized: state.finalized.clone(),
        takeover_offset,
        takeover_tc_id,
        mandatory_carry_candidate,
        authorized_proposer: context
            .authorized_proposer(next_height, takeover_offset)?
            .0
            .clone(),
        safety_halt: state.safety_halt.is_some(),
        consensus_authority_root: state.consensus_authority_root()?.to_hex(),
        last_vote: state.last_vote.clone(),
        signer_journal_root: journal_file_root(signer_journal.path())?,
        metrics: machine.metrics().summaries(),
    })
}

fn build_vote(
    machine: &mut SimplifiedConsensusStateMachine,
    validators: &ValidatorSet,
    validator_index: usize,
    proposal: SimplifiedProposal,
    signer_journal: &DurableConsensusSigningAuthority,
    signer: &mut AegisPqvmSigner,
    verifier: &AegisPqvmVerifier,
) -> Result<BlockVote, String> {
    let validator = validators
        .validators
        .get(validator_index)
        .ok_or_else(|| "harness validator index is out of range".to_string())?;
    machine.sign_block_vote(
        &proposal,
        verifier,
        validator.validator_id.clone(),
        validator.consensus_public_key.key_id.clone(),
        signer_journal,
        signer,
    )
}

fn sign_reliable_delivery_statement(
    context: &SimplifiedEpochContext,
    validators: &ValidatorSet,
    validator_index: usize,
    mut statement: ReliableDeliveryStatement,
    signer_journal: &DurableConsensusSigningAuthority,
    signer: &mut AegisPqvmSigner,
) -> Result<ReliableDeliveryStatement, String> {
    statement.context.validate_against(context)?;
    statement.candidate.validate()?;
    let validator = validators
        .validators
        .get(validator_index)
        .ok_or_else(|| "harness validator index is out of range".to_string())?;
    if statement.validator_id != validator.validator_id
        || statement.key_id != validator.consensus_public_key.key_id
    {
        return Err("reliable-delivery request does not match worker identity".to_string());
    }
    let candidate_id = statement.candidate_id()?;
    let (phase, domain) = match statement.phase {
        ReliableDeliveryPhase::Echo => (
            ConsensusSigningPhase::ProposalEcho,
            POSY_SIMPLIFIED_PROPOSAL_ECHO_DOMAIN,
        ),
        ReliableDeliveryPhase::Ready => (
            ConsensusSigningPhase::ProposalReady,
            POSY_SIMPLIFIED_PROPOSAL_READY_DOMAIN,
        ),
    };
    signer_journal.authorize_before_signature(&ConsensusSigningAuthorization {
        chain_id: statement.context.chain_id,
        network_id: statement.context.network_id.clone(),
        protocol_version: statement.context.protocol_version.clone(),
        epoch: statement.context.epoch,
        height: statement.context.height,
        round: statement.context.round,
        cluster_id: ClusterId(0),
        height_context_root: statement.context.epoch_context_root,
        validator_id: statement.validator_id.clone(),
        key_id: statement.key_id.clone(),
        phase,
        candidate_id: Some(BlockId(format!(
            "posy-v3-delivery:{}",
            candidate_id.to_hex()
        ))),
        highest_prepared_vc_root: None,
        conflict_unlock_tc_id: None,
    })?;
    statement.signature = signer
        .sign_domain(domain, &statement.signing_bytes()?, &statement.key_id)
        .map_err(|error| error.to_string())?;
    Ok(statement)
}

fn build_timeout_vote(
    machine: &mut SimplifiedConsensusStateMachine,
    validators: &ValidatorSet,
    validator_index: usize,
    signer_journal: &DurableConsensusSigningAuthority,
    signer: &mut AegisPqvmSigner,
) -> Result<TimeoutVote, String> {
    let validator = validators
        .validators
        .get(validator_index)
        .ok_or_else(|| "harness validator index is out of range".to_string())?;
    machine.sign_timeout_vote(
        validator.validator_id.clone(),
        validator.consensus_public_key.key_id.clone(),
        signer_journal,
        signer,
    )
}

fn proposal_from_snapshot(
    workers: &mut [WorkerProcess],
    context: &SimplifiedEpochContext,
    validators: &ValidatorSet,
    view: &WorkerSnapshot,
    expected_height: u64,
) -> Result<SimplifiedProposal, String> {
    if view.next_height != expected_height {
        return Err(format!(
            "proposal expected height {expected_height}, worker is at {}",
            view.next_height
        ));
    }
    let proposer_id = ValidatorId(view.authorized_proposer.clone());
    let proposer = validators
        .validators
        .iter()
        .find(|validator| validator.validator_id == proposer_id)
        .ok_or_else(|| "authorized proposer is absent from validator set".to_string())?;
    // A TC changes proposer authority, never the already-voted candidate. If
    // a pre-TC attempt gathered fewer than four votes, its successor safely
    // re-proposes the same block/protected-execution outcome at the certified
    // takeover round. This keeps the durable one-vote-per-height invariant.
    let block_id = view.mandatory_carry_candidate.as_ref().map_or_else(
        || BlockId(format!("harness-block-{expected_height}")),
        |candidate| candidate.block_id.clone(),
    );
    let parent_block_id = view.mandatory_carry_candidate.as_ref().map_or_else(
        || view.highest_parent.block_id().clone(),
        |candidate| candidate.parent_block_id.clone(),
    );
    let parent = view.mandatory_carry_candidate.as_ref().map_or_else(
        || view.highest_parent.clone(),
        |candidate| candidate.parent.clone(),
    );
    let protected_execution_root = view.mandatory_carry_candidate.as_ref().map_or_else(
        || {
            Hash::from_domain_bytes(
                "SYNERGY_POSY_HARNESS_PROTECTED_EXECUTION_V1",
                block_id.0.as_bytes(),
            )
        },
        |candidate| candidate.protected_execution_root,
    );
    let proposal = SimplifiedProposal {
        context: ConsensusObjectContext::for_height(
            context,
            Height(expected_height),
            Round(view.takeover_offset),
        )?,
        proposer_id,
        block_id,
        parent_block_id,
        parent,
        takeover_tc_id: view.takeover_tc_id,
        protected_execution_root,
        proposer_key_id: proposer.consensus_public_key.key_id.clone(),
        proposer_signature: empty_signature(),
    };
    let proposer_index = validators
        .validators
        .iter()
        .position(|validator| validator.validator_id == proposal.proposer_id)
        .ok_or_else(|| "authorized proposer index is unavailable".to_string())?;
    match workers[proposer_index].request(&Request::SignProposal { proposal })? {
        Response::Proposal { proposal, .. } => Ok(proposal),
        Response::Error { message, .. } => Err(message),
        other => Err(format!("expected signed proposal, found {other:?}")),
    }
}

fn collect_qc(
    workers: &mut [WorkerProcess],
    context: &SimplifiedEpochContext,
    validators: &ValidatorSet,
    verifier: &AegisPqvmVerifier,
    proposal: &SimplifiedProposal,
    signer_indexes: &[usize],
) -> Result<SimplifiedQuorumCertificate, String> {
    collect_unverified_qc(
        workers,
        context,
        validators,
        verifier,
        proposal,
        signer_indexes,
    )
}

fn collect_unverified_qc(
    workers: &mut [WorkerProcess],
    context: &SimplifiedEpochContext,
    validators: &ValidatorSet,
    verifier: &AegisPqvmVerifier,
    proposal: &SimplifiedProposal,
    signer_indexes: &[usize],
) -> Result<SimplifiedQuorumCertificate, String> {
    exercise_reliable_delivery(workers, context, validators, verifier, proposal)?;
    let mut votes = Vec::new();
    for index in signer_indexes {
        match workers[*index].request(&Request::BuildVote {
            proposal: proposal.clone(),
        })? {
            Response::Vote { vote, .. } => votes.push(vote),
            Response::Error { message, .. } => return Err(message),
            other => return Err(format!("expected block vote, found {other:?}")),
        }
    }
    SimplifiedQuorumCertificate::from_votes(votes)
}

fn exercise_reliable_delivery(
    workers: &mut [WorkerProcess],
    context: &SimplifiedEpochContext,
    validators: &ValidatorSet,
    verifier: &AegisPqvmVerifier,
    proposal: &SimplifiedProposal,
) -> Result<(), String> {
    let candidate = CertifiedCandidateSubject::new(
        proposal.context.clone(),
        proposal.block_id.clone(),
        proposal.parent_block_id.clone(),
        proposal.parent.clone(),
        proposal.protected_execution_root,
    )?;
    let mut delivery = ReliableDeliveryState::new(proposal.context.clone(), context)?;
    delivery.observe_candidate(candidate.clone())?;
    for index in QUORUM_SIGNERS {
        let statement = request_reliable_delivery_signature(
            workers,
            validators,
            index,
            proposal,
            &candidate,
            ReliableDeliveryPhase::Echo,
        )?;
        delivery.accept_statement(statement, context, validators, verifier)?;
    }
    let ready_signers = &QUORUM_SIGNERS[..3];
    let mut delivered = None;
    for index in ready_signers {
        let statement = request_reliable_delivery_signature(
            workers,
            validators,
            *index,
            proposal,
            &candidate,
            ReliableDeliveryPhase::Ready,
        )?;
        delivered = delivery
            .accept_statement(statement, context, validators, verifier)?
            .delivered_candidate;
    }
    if delivered.as_ref() != Some(&candidate) {
        return Err(
            "three authenticated READY statements did not deliver the proposal".to_string(),
        );
    }
    delivery.validate_authenticated(context, validators, verifier)
}

fn request_reliable_delivery_signature(
    workers: &mut [WorkerProcess],
    validators: &ValidatorSet,
    validator_index: usize,
    proposal: &SimplifiedProposal,
    candidate: &CertifiedCandidateSubject,
    phase: ReliableDeliveryPhase,
) -> Result<ReliableDeliveryStatement, String> {
    let validator = validators
        .validators
        .get(validator_index)
        .ok_or_else(|| "reliable-delivery signer index is out of range".to_string())?;
    let statement = ReliableDeliveryStatement {
        context: proposal.context.clone(),
        phase,
        candidate: candidate.clone(),
        validator_id: validator.validator_id.clone(),
        key_id: validator.consensus_public_key.key_id.clone(),
        signature: empty_signature(),
    };
    match workers[validator_index].request(&Request::SignReliableDelivery { statement })? {
        Response::ReliableDelivery { statement, .. } => Ok(statement),
        Response::Error { message, .. } => Err(message),
        other => Err(format!(
            "expected signed reliable-delivery statement, found {other:?}"
        )),
    }
}

fn collect_tc(
    workers: &mut [WorkerProcess],
    signer_indexes: &[usize],
    known_qc_proofs: &[SimplifiedQuorumCertificate],
) -> Result<SimplifiedTimeoutCertificate, String> {
    let mut votes = Vec::new();
    for index in signer_indexes {
        match workers[*index].request(&Request::BuildTimeoutVote)? {
            Response::TimeoutVote { vote, .. } => votes.push(vote),
            Response::Error { message, .. } => return Err(message),
            other => return Err(format!("expected timeout vote, found {other:?}")),
        }
    }
    let anchor = anchor_parent()?;
    let mut proof_ids = BTreeSet::new();
    let mut proofs = Vec::new();
    for report in &votes {
        if report.highest_parent == anchor {
            continue;
        }
        let reference = report
            .highest_parent
            .quorum_certificate_reference()
            .ok_or_else(|| {
                "late-epoch harness timeout report unexpectedly used a Genesis parent".to_string()
            })?;
        let proof = known_qc_proofs
            .iter()
            .find(|proof| proof.reference().ok().as_ref() == Some(reference))
            .cloned()
            .ok_or_else(|| {
                format!(
                    "timeout report references unresolved non-anchor QC {} at height {}",
                    reference.qc_id.to_hex(),
                    reference.height.0
                )
            })?;
        if proof_ids.insert(proof.id()?) {
            proofs.push(proof);
        }
    }
    SimplifiedTimeoutCertificate::from_votes_with_qc_proofs(votes, proofs)
}

fn accept_qc_on(
    workers: &mut [WorkerProcess],
    certificate: &SimplifiedQuorumCertificate,
    indexes: &[usize],
) -> Result<Vec<WorkerSnapshot>, String> {
    let mut snapshots = Vec::new();
    for index in indexes {
        match workers[*index].request(&Request::AcceptQc {
            certificate: certificate.clone(),
        })? {
            Response::AcceptedQc { snapshot, .. } => snapshots.push(snapshot),
            Response::Error { message, .. } => return Err(message),
            other => return Err(format!("expected accepted QC, found {other:?}")),
        }
    }
    require_same_consensus_view(&snapshots)?;
    Ok(snapshots)
}

fn accept_tc_on(
    workers: &mut [WorkerProcess],
    certificate: &SimplifiedTimeoutCertificate,
    indexes: &[usize],
) -> Result<Vec<WorkerSnapshot>, String> {
    let mut snapshots = Vec::new();
    for index in indexes {
        match workers[*index].request(&Request::AcceptTc {
            certificate: certificate.clone(),
        })? {
            Response::AcceptedTc { snapshot } => snapshots.push(snapshot),
            Response::Error { message, .. } => return Err(message),
            other => return Err(format!("expected accepted TC, found {other:?}")),
        }
    }
    require_same_consensus_view(&snapshots)?;
    Ok(snapshots)
}

fn export_state_sync(worker: &mut WorkerProcess) -> Result<Vec<u8>, String> {
    match worker.request(&Request::ExportStateSync)? {
        Response::StateSync { bundle_bytes, .. } => Ok(bundle_bytes),
        Response::Error { message, .. } => Err(message),
        other => Err(format!("expected state-sync bundle, found {other:?}")),
    }
}

fn install_state_sync(
    worker: &mut WorkerProcess,
    bundle_bytes: Vec<u8>,
) -> Result<WorkerSnapshot, String> {
    match worker.request(&Request::InstallStateSync { bundle_bytes })? {
        Response::InstalledStateSync { snapshot } => Ok(snapshot),
        Response::Error { message, .. } => Err(message),
        other => Err(format!("expected installed state sync, found {other:?}")),
    }
}

fn resign_tc(
    workers: &mut [WorkerProcess],
    certificate: &mut SimplifiedTimeoutCertificate,
    validators: &ValidatorSet,
) -> Result<(), String> {
    for report_index in 0..certificate.reports.len() {
        let mut vote = certificate.reports[report_index].clone();
        vote.context = certificate.context.clone();
        vote.lease_index = certificate.lease_index;
        vote.timed_out_proposer = certificate.timed_out_proposer.clone();
        vote.previous_tc_id = certificate.previous_tc_id;
        vote.signature = empty_signature();
        let validator_index = validators
            .validators
            .iter()
            .position(|validator| validator.validator_id == vote.validator_id)
            .ok_or_else(|| "TC participant is absent from validator set".to_string())?;
        let signed = match workers[validator_index]
            .request(&Request::AdversarialSignTimeoutVote { vote })?
        {
            Response::TimeoutVote { vote, .. } => vote,
            Response::Error { message, .. } => return Err(message),
            other => {
                return Err(format!(
                    "expected adversarial timeout vote, found {other:?}"
                ))
            }
        };
        certificate.reports[report_index] = signed;
    }
    Ok(())
}

fn empty_signature() -> AegisPqSignature {
    AegisPqSignature {
        algorithm: String::new(),
        signature_bytes: Vec::new(),
    }
}

fn provision_harness_keys(work_dir: &Path) -> Result<HarnessPublicConfiguration, String> {
    let mut provisioner =
        AegisPqvmSigner::initialize_required().map_err(|error| error.to_string())?;
    let mut validator_records = Vec::with_capacity(VALIDATOR_COUNT);
    let mut pqc_public_keys = Vec::with_capacity(VALIDATOR_COUNT);
    for index in 0..VALIDATOR_COUNT {
        let uma_id = UmaId(format!("uma:validator-{index}"));
        let key_id = provisioner
            .generate_and_register_key(
                &uma_id.0,
                vec![
                    AegisPqKeyRole::ConsensusProposer,
                    AegisPqKeyRole::ConsensusVote,
                ],
                Epoch(7),
            )
            .map_err(|error| error.to_string())?;
        let aegis_public_key = provisioner
            .public_key_record(&key_id)
            .map_err(|error| error.to_string())?;
        let pqc_public_key = provisioner
            .registry
            .public_key(&key_id)
            .cloned()
            .ok_or_else(|| "generated harness public key is unavailable".to_string())?;
        let pqc_private_key = provisioner
            .registry
            .private_key(&key_id)
            .cloned()
            .ok_or_else(|| "generated harness private key is unavailable".to_string())?;
        write_message_pack(
            &worker_private_key_path(work_dir, index),
            &HarnessPrivateKey {
                validator_index: index,
                public_key: pqc_public_key.clone(),
                private_key: pqc_private_key,
            },
            true,
        )?;
        pqc_public_keys.push(pqc_public_key);
        validator_records.push(ValidatorRecord {
            validator_id: ValidatorId(format!("validator-{index}")),
            validator_uma_id: uma_id,
            consensus_public_key: aegis_public_key.clone(),
            peer_public_key: aegis_public_key.clone(),
            operator_public_key: aegis_public_key,
            voting_weight: 1,
            status: ValidatorStatus::Active,
            cluster_id: ClusterId(0),
            activation_epoch: Epoch(7),
        });
    }
    let configuration = HarnessPublicConfiguration {
        validator_set: ValidatorSet {
            epoch: Epoch(7),
            validators: validator_records,
        },
        pqc_public_keys,
    };
    write_message_pack(&public_configuration_path(work_dir), &configuration, false)?;
    Ok(configuration)
}

fn harness_signer(
    validator_index: usize,
    validators: &ValidatorSet,
    private_key: HarnessPrivateKey,
) -> Result<AegisPqvmSigner, String> {
    let validator = validators
        .validators
        .get(validator_index)
        .ok_or_else(|| "worker validator is absent from public configuration".to_string())?;
    if private_key.public_key.key_id != validator.consensus_public_key.key_id.0
        || private_key.private_key.public_key_id != private_key.public_key.key_id
        || private_key.public_key.key_data != validator.consensus_public_key.key_bytes
    {
        return Err(
            "worker private key does not match the frozen public validator set".to_string(),
        );
    }
    let mut signer = AegisPqvmSigner::initialize_required().map_err(|error| error.to_string())?;
    let registered = signer
        .register_existing_keypair(
            &validator.validator_uma_id.0,
            private_key.public_key,
            private_key.private_key,
            vec![
                AegisPqKeyRole::ConsensusProposer,
                AegisPqKeyRole::ConsensusVote,
            ],
            Epoch(7),
        )
        .map_err(|error| error.to_string())?;
    if registered != validator.consensus_public_key.key_id {
        return Err("worker registered a different consensus key id".to_string());
    }
    Ok(signer)
}

fn harness_verifier(
    configuration: &HarnessPublicConfiguration,
) -> Result<AegisPqvmVerifier, String> {
    if configuration.validator_set.validators.len() != configuration.pqc_public_keys.len() {
        return Err("public harness key registry length mismatch".to_string());
    }
    let mut registry = AegisPqvmKeyRegistry::default();
    for (validator, public_key) in configuration
        .validator_set
        .validators
        .iter()
        .zip(&configuration.pqc_public_keys)
    {
        if public_key.key_id != validator.consensus_public_key.key_id.0
            || public_key.key_data != validator.consensus_public_key.key_bytes
        {
            return Err("public harness key does not match validator record".to_string());
        }
        registry.register_public_key(
            &validator.validator_uma_id.0,
            public_key.clone(),
            vec![
                AegisPqKeyRole::ConsensusProposer,
                AegisPqKeyRole::ConsensusVote,
            ],
            Epoch(7),
        );
    }
    AegisPqvmVerifier::initialize_required(registry).map_err(|error| error.to_string())
}

fn write_message_pack<T: Serialize>(path: &Path, value: &T, private: bool) -> Result<(), String> {
    let bytes = rmp_serde::to_vec_named(value)
        .map_err(|error| format!("serialize harness material {}: {error}", path.display()))?;
    let mut options = fs::OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(if private { 0o600 } else { 0o644 });
    }
    let mut file = options
        .open(path)
        .map_err(|error| format!("create harness material {}: {error}", path.display()))?;
    file.write_all(&bytes)
        .and_then(|()| file.sync_all())
        .map_err(|error| format!("persist harness material {}: {error}", path.display()))
}

fn read_message_pack<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T, String> {
    let bytes = fs::read(path)
        .map_err(|error| format!("read harness material {}: {error}", path.display()))?;
    rmp_serde::from_slice(&bytes)
        .map_err(|error| format!("parse harness material {}: {error}", path.display()))
}

fn journal_file_root(path: &Path) -> Result<Option<String>, String> {
    if !path.exists() {
        return Ok(None);
    }
    let bytes = fs::read(path)
        .map_err(|error| format!("read signer journal {}: {error}", path.display()))?;
    if bytes.is_empty() {
        return Err("signer journal exists but is empty".to_string());
    }
    Ok(Some(
        Hash::from_domain_bytes("SYNERGY_POSY_HARNESS_SIGNER_JOURNAL_V1", &bytes).to_hex(),
    ))
}

fn harness_context(validators: &ValidatorSet) -> Result<SimplifiedEpochContext, String> {
    SimplifiedEpochContext::derive(
        Epoch(7),
        Height(EPOCH_START_HEIGHT),
        Height(EPOCH_END_HEIGHT),
        Hash::from_domain_bytes("harness-epoch-seed", b"epoch-7"),
        ConsensusParameterRoot::from_canonical_manifest_bytes(b"harness-posy-v3-parameters"),
        validators,
    )
}

fn anchor_qc() -> QuorumCertificateReference {
    QuorumCertificateReference {
        height: Height(EPOCH_START_HEIGHT - 1),
        block_id: BlockId(format!("harness-block-{}", EPOCH_START_HEIGHT - 1)),
        qc_id: Hash::from_domain_bytes(
            "SYNERGY_POSY_HARNESS_ANCHOR_QC_V1",
            &(EPOCH_START_HEIGHT - 1).to_be_bytes(),
        ),
    }
}

/// This qualification starts at a later epoch height, so its pre-existing
/// parent is a real QC.  Fresh block one is exercised separately by the
/// autonomous-driver harness using `GenesisFinalityReference`.
fn anchor_parent() -> Result<SimplifiedFinalityParent, String> {
    SimplifiedFinalityParent::quorum_certificate(anchor_qc())
}

fn worker_state_path(work_dir: &Path, index: usize) -> PathBuf {
    work_dir.join(format!("validator-{index}-state.json"))
}

fn worker_private_key_path(work_dir: &Path, index: usize) -> PathBuf {
    work_dir.join(format!("validator-{index}-private-key.msgpack"))
}

fn public_configuration_path(work_dir: &Path) -> PathBuf {
    work_dir.join("public-validator-configuration.msgpack")
}

fn remove_ephemeral_private_keys(work_dir: &Path) -> Result<(), String> {
    for index in 0..VALIDATOR_COUNT {
        let path = worker_private_key_path(work_dir, index);
        fs::remove_file(&path)
            .map_err(|error| format!("remove ephemeral key {}: {error}", path.display()))?;
    }
    Ok(())
}

fn spawn_worker(executable: &Path, work_dir: &Path, index: usize) -> Result<WorkerProcess, String> {
    let mut child = Command::new(executable)
        .arg("worker")
        .arg("--validator-index")
        .arg(index.to_string())
        .arg("--state")
        .arg(worker_state_path(work_dir, index))
        .arg("--public-config")
        .arg(public_configuration_path(work_dir))
        .arg("--private-key")
        .arg(worker_private_key_path(work_dir, index))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|error| format!("spawn validator-{index} harness process: {error}"))?;
    let stdin = child
        .stdin
        .take()
        .ok_or_else(|| "harness worker stdin is unavailable".to_string())?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| "harness worker stdout is unavailable".to_string())?;
    Ok(WorkerProcess {
        index,
        child,
        stdin,
        stdout: BufReader::new(stdout),
    })
}

fn restart_worker(
    executable: &Path,
    work_dir: &Path,
    workers: &mut [WorkerProcess],
    index: usize,
) -> Result<(), String> {
    let response = workers[index].request(&Request::Shutdown)?;
    if response != Response::Shutdown {
        return Err(format!("validator-{index} refused clean restart"));
    }
    workers[index]
        .child
        .wait()
        .map_err(|error| format!("wait for validator-{index} restart: {error}"))?;
    workers[index] = spawn_worker(executable, work_dir, index)?;
    Ok(())
}

fn shutdown_all(workers: &mut [WorkerProcess]) {
    for worker in workers {
        let _ = worker.request(&Request::Shutdown);
        let _ = worker.child.wait();
    }
}

fn initial_or_live(workers: &mut [WorkerProcess], index: usize) -> Result<WorkerSnapshot, String> {
    snapshot_from(workers[index].request(&Request::Snapshot {
        observed_live_validators: Vec::new(),
        local_unix_ms: 0,
    })?)
}

fn snapshots_for(
    workers: &mut [WorkerProcess],
    indexes: &[usize],
) -> Result<Vec<WorkerSnapshot>, String> {
    indexes
        .iter()
        .map(|index| initial_or_live(workers, *index))
        .collect()
}

fn snapshot_from(response: Response) -> Result<WorkerSnapshot, String> {
    match response {
        Response::Snapshot { snapshot } => Ok(snapshot),
        Response::Error { message, .. } => Err(message),
        other => Err(format!("expected worker snapshot, found {other:?}")),
    }
}

fn consensus_view(
    snapshot: &WorkerSnapshot,
) -> (
    &str,
    &[String],
    u64,
    &SimplifiedFinalityParent,
    &Option<QuorumCertificateReference>,
    &FinalizedBlockRecord,
    u64,
    Option<Hash>,
    &str,
    bool,
    &str,
) {
    (
        &snapshot.epoch_context_root,
        &snapshot.leader_ring,
        snapshot.next_height,
        &snapshot.highest_parent,
        &snapshot.locked_qc,
        &snapshot.finalized,
        snapshot.takeover_offset,
        snapshot.takeover_tc_id,
        &snapshot.authorized_proposer,
        snapshot.safety_halt,
        &snapshot.consensus_authority_root,
    )
}

fn require_same_consensus_view(snapshots: &[WorkerSnapshot]) -> Result<(), String> {
    if snapshots.is_empty() {
        return Err("cannot compare an empty worker snapshot set".to_string());
    }
    if snapshots
        .windows(2)
        .any(|pair| consensus_view(&pair[0]) != consensus_view(&pair[1]))
    {
        return Err("worker processes disagree on verified consensus state".to_string());
    }
    Ok(())
}

fn expect_error(response: Response, expected: &str) -> Result<(), String> {
    match response {
        Response::Error { message, .. } if message.contains(expected) => Ok(()),
        Response::Error { message, .. } => Err(format!(
            "harness rejection mismatch: expected {expected:?}, found {message:?}"
        )),
        other => Err(format!("expected fail-closed response, found {other:?}")),
    }
}

fn parse_arg(args: &[String], name: &str) -> Result<String, String> {
    optional_arg(args, name).ok_or_else(|| format!("missing required argument {name}"))
}

fn optional_arg(args: &[String], name: &str) -> Option<String> {
    args.windows(2)
        .find(|pair| pair[0] == name)
        .map(|pair| pair[1].clone())
}
