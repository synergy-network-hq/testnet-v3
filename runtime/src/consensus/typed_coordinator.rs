//! Typed PoSy v2.2 coordinator ingress boundary.
//!
//! The inherited P2P block/vote protocol intentionally cannot reach this
//! mailbox. Production startup installs a single coordinator receiver before
//! validator duties are enabled; until then typed messages are rejected rather
//! than being queued, replayed, or interpreted by a legacy handler.

use crate::consensus::posy::{LocalConsensusContext, ProofOfSynergyBft, VerifiedVote};
use crate::consensus::signing_authority::DurableConsensusRecoveryCheckpoint;
use crate::consensus::testnet_v3_bootstrap::TestnetV3GenesisBootstrap;
use crate::consensus::typed_finality_store::{
    TypedEpochTransitionRecord, TypedFinalityRecord, TypedFinalityStore,
};
use crate::consensus::typed_prepared_store::{
    TypedPreparedRecord, TypedPreparedStore, TYPED_PREPARED_RECORD_VERSION,
};
use crate::consensus_parameters::EtdagActivationPermit;
use crate::crypto::aegis_pqvm::{AegisPqKeyLifecycleRecord, AegisPqvmSigner, AegisPqvmVerifier};
use crate::crypto::pqc::{PQCAlgorithm, PQCManager, PQCPrivateKey, PQCPublicKey};
use crate::etdag::{
    EtdagDigest, EtdagParameters, EtdagProtectedInputCoordinator, ProtectedBlockInput,
    TargetAdmissionContext,
};
use crate::execution::{
    compute_state_root_after, execute_block, publish_finalized_execution_state_snapshot,
    ExecutionState,
};
use crate::p2p::messages::{validate_typed_consensus_message_size, TypedConsensusMessage};
use crate::synergy_types::{
    AegisPqKeyRole, Block, BlockId, ClusterMap, EpochTransition, Hash, QuorumCertificate,
    TimeoutCertificate, UmaId, ValidationCertificate, ValidatorId, ValidatorSet, ValidatorStatus,
    Vote, VotePhase,
};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender, TrySendError};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Bounded inbound work item whose sender is authenticated by the P2P layer.
#[derive(Debug, Clone)]
pub struct TypedConsensusEnvelope {
    pub peer_address: String,
    /// Identity derived from a verified Genesis-bound P2P handshake. It is
    /// intentionally distinct from the socket address, which is mutable and
    /// cannot authorize validator consensus traffic.
    pub authenticated_peer: Option<AuthenticatedTypedConsensusPeer>,
    pub message: TypedConsensusMessage,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedTypedConsensusPeer {
    pub validator_id: ValidatorId,
    pub validator_uma_id: UmaId,
    pub consensus_key_id: crate::synergy_types::AegisPqKeyId,
}

/// The P2P implementation must bind every typed message to its authenticated
/// remote peer before it reaches consensus.  This deliberately remains an
/// injected boundary: a socket address alone is not validator identity.
pub trait TypedConsensusPeerAuthorizer: Send + Sync {
    fn authorize(
        &self,
        peer: &AuthenticatedTypedConsensusPeer,
        message: &TypedConsensusMessage,
    ) -> Result<(), String>;
}

/// Authorizes typed traffic against a frozen validator-set snapshot. The P2P
/// layer supplies the peer identity only after it has verified possession of
/// the exact Genesis ML-DSA-65 key; this layer additionally prevents that peer
/// from claiming a different validator on proposal or vote messages.
#[derive(Debug, Clone)]
pub struct FrozenTypedConsensusPeerAuthorizer {
    validator_set: ValidatorSet,
}

impl FrozenTypedConsensusPeerAuthorizer {
    pub fn new(validator_set: ValidatorSet) -> Result<Self, String> {
        validator_set.validate_unique_validator_and_key_ids()?;
        Ok(Self { validator_set })
    }

    fn validator_for_peer(
        &self,
        peer: &AuthenticatedTypedConsensusPeer,
    ) -> Result<&crate::synergy_types::ValidatorRecord, String> {
        let validator = self
            .validator_set
            .validators
            .iter()
            .find(|validator| validator.validator_id == peer.validator_id)
            .ok_or_else(|| "typed peer validator is absent from the frozen set".to_string())?;
        if validator.status != ValidatorStatus::Active
            || validator.validator_uma_id != peer.validator_uma_id
            || validator.consensus_public_key.key_id != peer.consensus_key_id
        {
            return Err(
                "typed peer identity does not match an active frozen validator".to_string(),
            );
        }
        Ok(validator)
    }
}

impl TypedConsensusPeerAuthorizer for FrozenTypedConsensusPeerAuthorizer {
    fn authorize(
        &self,
        peer: &AuthenticatedTypedConsensusPeer,
        message: &TypedConsensusMessage,
    ) -> Result<(), String> {
        let validator = self.validator_for_peer(peer)?;
        match message {
            TypedConsensusMessage::CoreProposal { block, .. }
            | TypedConsensusMessage::Proposal { block, .. } => {
                if block.header.proposer_validator_id != validator.validator_id
                    || block.header.proposer_uma_id != validator.validator_uma_id
                    || block.header.proposer_key_id != validator.consensus_public_key.key_id
                {
                    return Err(
                        "typed proposal sender does not match its authenticated validator identity"
                            .to_string(),
                    );
                }
            }
            TypedConsensusMessage::Vote { vote } => {
                if vote.validator_id != validator.validator_id
                    || vote.validator_uma_id != validator.validator_uma_id
                    || vote.key_id != validator.consensus_public_key.key_id
                {
                    return Err(
                        "typed vote sender does not match its authenticated validator identity"
                            .to_string(),
                    );
                }
            }
            // Certificates may be relayed by any authenticated active
            // validator; their signer set is independently verified by PoSy.
            TypedConsensusMessage::ValidationCertificate { .. }
            | TypedConsensusMessage::QuorumCertificate { .. }
            | TypedConsensusMessage::TimeoutCertificate { .. }
            | TypedConsensusMessage::PreparedCertificateRequest { .. }
            | TypedConsensusMessage::PreparedCertificateResponse { .. }
            | TypedConsensusMessage::FinalityCheckpointRequest { .. }
            | TypedConsensusMessage::FinalityCheckpoint { .. } => {}
        }
        Ok(())
    }
}

/// A stateful typed PoSy worker for one immutable height context.
///
/// It accepts no legacy messages, revalidates every typed object against its
/// locally derived context, and updates persistent typed finality only after a
/// valid finality QC has committed the exact locally validated proposal.
pub struct TypedPosyCoordinator {
    consensus: ProofOfSynergyBft,
    signer: AegisPqvmSigner,
    local_validator_id: ValidatorId,
    local_context: LocalConsensusContext,
    execution_state: ExecutionState,
    etdag_parameters: EtdagParameters,
    proposal_mode: TypedProposalMode,
    finality_store: TypedFinalityStore,
    accepted_proposals: BTreeMap<BlockId, Block>,
}

/// The finalized schema-v2 release runs the typed core without transaction
/// admission.  A protected ETDAG proposal becomes available only after the
/// role runtime presents the unforgeable activation permit derived from a
/// future finalized manifest at its declared epoch boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TypedProposalMode {
    CoreOnly,
    EtdagActivated,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TypedCoordinatorEvent {
    /// An authenticated artifact from an already finalized height is an
    /// idempotent network retry. It is discarded before PQ verification and
    /// cannot alter the durable successor context.
    StaleFinalizedHeightIgnored {
        height: u64,
    },
    ProposalAccepted {
        candidate_id: BlockId,
    },
    VoteAccepted {
        phase: VotePhase,
        candidate_id: BlockId,
    },
    ValidationCertificateAccepted {
        candidate_id: BlockId,
    },
    TimeoutCertificateAccepted {
        next_round: u64,
    },
    Finalized {
        record: TypedFinalityRecord,
    },
    FinalityCheckpointRequestAccepted,
    FinalityCheckpointApplied {
        imported_records: usize,
    },
    PreparedCertificateRequestAccepted,
    PreparedCertificateRecovered {
        candidate_id: BlockId,
    },
}

/// Bounded-ingress accounting for the production coordinator worker.  Invalid
/// peer input is deliberately counted and discarded rather than terminating a
/// validator process or allowing a malformed message into a legacy path.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TypedCoordinatorIngressMetrics {
    pub accepted_messages: u64,
    pub rejected_messages: u64,
}

/// Authenticated outbound path for typed consensus artifacts.
///
/// The scheduler has no authority to turn a local state transition into a
/// network action when the transport is unavailable.  Implementations must
/// return an error for a failed fan-out and the driver treats an empty fan-out
/// as a failure as well: signing into an isolated validator is not a valid
/// Testnet-v3 consensus action.
pub trait TypedConsensusEgress: Send {
    fn broadcast(&mut self, message: &TypedConsensusMessage) -> Result<usize, String>;
}

/// P2P adapter for the only supported production egress path.  It deliberately
/// wraps the existing typed P2P fan-out rather than opening a second socket or
/// legacy-consensus path.  The underlying P2P API reports the number of
/// authenticated eligible peers that accepted the send; zero is rejected by
/// the driver.
pub struct P2pTypedConsensusEgress {
    network: Arc<crate::p2p::networking::P2PNetwork>,
}

impl P2pTypedConsensusEgress {
    pub fn new(network: Arc<crate::p2p::networking::P2PNetwork>) -> Self {
        Self { network }
    }
}

impl TypedConsensusEgress for P2pTypedConsensusEgress {
    fn broadcast(&mut self, message: &TypedConsensusMessage) -> Result<usize, String> {
        self.network.broadcast_typed_consensus(message)
    }
}

/// Supplies the exact digest to which ETDAG public proof packages are bound.
///
/// This is an intentionally injected, finalized-consensus boundary.  The
/// scheduler must not invent a digest from a timer, local mempool state, or an
/// unverified peer claim.  Production wiring must derive it from the
/// finalized-QC/epoch-transition transcript that produced `local_context`.
pub trait TypedFinalityContextDigestSource: Send {
    fn expected_digest(&self, local_context: &LocalConsensusContext)
        -> Result<EtdagDigest, String>;
}

/// An already persisted, finalized-chain authority for exactly one height
/// after a durable typed QC.  A topology change carries the signed transition
/// record plus the deterministic topology it commits to; it is never decoded
/// from a P2P message at this boundary.
#[derive(Debug, Clone)]
pub enum TypedNextHeightAuthority {
    UnchangedTopology {
        context: LocalConsensusContext,
    },
    VerifiedEpochTransition {
        transition: TypedEpochTransitionRecord,
        next_validator_set: ValidatorSet,
        next_cluster_map: ClusterMap,
        context: LocalConsensusContext,
    },
}

/// Supplies the next immutable height authority after durable finality.
///
/// The provider is intentionally separate from the scheduler: height and
/// epoch authority belongs to the finalized-chain/epoch-transition layer, not
/// to a timer.  The coordinator independently validates the returned authority
/// before it becomes signing authority.  In particular, a persisted epoch
/// transition is not permitted to degrade into an unchanged-topology advance.
pub trait TypedNextHeightContextSource: Send {
    fn next_authority(
        &mut self,
        finalized: &TypedFinalityRecord,
        current: &LocalConsensusContext,
    ) -> Result<TypedNextHeightAuthority, String>;
}

/// Immutable, verified state needed to validate certified ETDAG inputs for
/// exactly one typed consensus height.  It is obtained only from the active
/// typed coordinator after its Genesis/QC/epoch authority checks complete.
///
/// The values are public verification material.  In particular, this contains
/// no private ML-KEM share or local consensus signer material.
#[derive(Debug, Clone)]
pub struct TypedEtdagIngressAuthority {
    pub height_context: crate::synergy_types::HeightConsensusContext,
    pub verifier: AegisPqvmVerifier,
    pub validator_set: ValidatorSet,
    pub cluster_map: ClusterMap,
    pub protocol_config: crate::synergy_types::ProtocolConfig,
    pub parameters: EtdagParameters,
}

/// Rotates the authenticated certified-ETDAG ingress in lockstep with the
/// typed finality lifecycle.  The production implementation owns the global
/// P2P ingress slot; test implementations may be no-ops, but a production
/// role must install the initial authority before it starts typed ingress.
///
/// A successor is supplied only after the coordinator durably accepted its
/// finality QC and installed the matching next local context.  The rotator
/// must reject overlap or a non-successor authority rather than accepting a
/// package under two height/finality contexts.
pub trait TypedEtdagIngressRotator: Send {
    fn install_initial(
        &mut self,
        protected_inputs: &EtdagProtectedInputCoordinator,
        authority: &TypedEtdagIngressAuthority,
        finality_context_digest: &EtdagDigest,
    ) -> Result<(), String>;

    fn rotate_successor(
        &mut self,
        protected_inputs: &EtdagProtectedInputCoordinator,
        authority: &TypedEtdagIngressAuthority,
        finality_context_digest: &EtdagDigest,
    ) -> Result<(), String>;

    fn remove(&mut self) -> Result<(), String>;
}

/// Test-only-in-effect default used by unit-level driver tests.  It deliberately
/// never becomes a production lifecycle because the role runtime constructs a
/// concrete rotator before exposing typed P2P ingress.
#[derive(Debug, Default)]
pub struct NoopTypedEtdagIngressRotator;

impl TypedEtdagIngressRotator for NoopTypedEtdagIngressRotator {
    fn install_initial(
        &mut self,
        _protected_inputs: &EtdagProtectedInputCoordinator,
        _authority: &TypedEtdagIngressAuthority,
        _finality_context_digest: &EtdagDigest,
    ) -> Result<(), String> {
        Ok(())
    }

    fn rotate_successor(
        &mut self,
        _protected_inputs: &EtdagProtectedInputCoordinator,
        _authority: &TypedEtdagIngressAuthority,
        _finality_context_digest: &EtdagDigest,
    ) -> Result<(), String> {
        Ok(())
    }

    fn remove(&mut self) -> Result<(), String> {
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TypedRoundStage {
    Proposal,
    Validation,
    Finality,
    WaitingForCertificate,
}

// One retry still occurs before the canonical 1,500 ms stage deadline, but a
// healthy six-validator round must not spend most of one CPU core repeatedly
// verifying identical ML-DSA artifacts.
const PROPOSAL_REBROADCAST_INTERVAL: Duration = Duration::from_millis(750);
const VOTE_REBROADCAST_INTERVAL: Duration = Duration::from_millis(750);

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TypedCoordinatorDriverMetrics {
    pub accepted_messages: u64,
    pub rejected_messages: u64,
    pub emitted_proposals: u64,
    pub emitted_validation_votes: u64,
    pub emitted_finality_votes: u64,
    pub emitted_timeout_votes: u64,
    pub emitted_validation_certificates: u64,
    pub emitted_finality_certificates: u64,
    pub emitted_timeout_certificates: u64,
    pub finalized_blocks: u64,
    pub deduplicated_replays: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TypedConsensusTelemetrySnapshot {
    pub finalized_height: u64,
    pub finalized_block_id: String,
    pub finalized_round: u64,
    pub finality_interval_millis: u64,
    pub finality_intervals_millis: VecDeque<u64>,
    pub finalized_blocks: u64,
    pub round_zero_finalized_blocks: u64,
    pub current_height: u64,
    pub current_round: u64,
    pub prepared_height: u64,
    pub prepared_candidate: String,
    pub prepared_round: u64,
    pub highest_qc_height: u64,
    pub highest_qc_block_id: String,
    pub highest_qc_root: String,
    pub highest_tc_round: u64,
    pub highest_tc_root: String,
    pub mailbox_depth: usize,
    pub phase_duration_millis: BTreeMap<String, u64>,
    pub messages_received: BTreeMap<String, u64>,
    pub messages_deduplicated: BTreeMap<String, u64>,
    pub messages_rejected_precrypto: BTreeMap<String, u64>,
    pub rebroadcasts: BTreeMap<String, u64>,
    pub restarts: u64,
    pub startup_phase: String,
}

#[derive(Debug, Default)]
struct TypedConsensusTelemetry {
    snapshot: TypedConsensusTelemetrySnapshot,
    last_finalized_unix_ms: Option<u64>,
}

static TYPED_CONSENSUS_TELEMETRY: OnceLock<Mutex<TypedConsensusTelemetry>> = OnceLock::new();

fn typed_consensus_telemetry() -> &'static Mutex<TypedConsensusTelemetry> {
    TYPED_CONSENSUS_TELEMETRY.get_or_init(|| Mutex::new(TypedConsensusTelemetry::default()))
}

fn typed_message_kind(message: &TypedConsensusMessage) -> &'static str {
    match message {
        TypedConsensusMessage::CoreProposal { .. } => "core_proposal",
        TypedConsensusMessage::Proposal { .. } => "proposal",
        TypedConsensusMessage::Vote { vote } => match vote.phase {
            VotePhase::Validate => "validation_vote",
            VotePhase::Finality => "finality_vote",
            VotePhase::Timeout => "timeout_vote",
        },
        TypedConsensusMessage::ValidationCertificate { .. } => "validation_certificate",
        TypedConsensusMessage::QuorumCertificate { .. } => "quorum_certificate",
        TypedConsensusMessage::TimeoutCertificate { .. } => "timeout_certificate",
        TypedConsensusMessage::PreparedCertificateRequest { .. } => "prepared_certificate_request",
        TypedConsensusMessage::PreparedCertificateResponse { .. } => {
            "prepared_certificate_response"
        }
        TypedConsensusMessage::FinalityCheckpointRequest { .. } => "finality_checkpoint_request",
        TypedConsensusMessage::FinalityCheckpoint { .. } => "finality_checkpoint",
    }
}

fn typed_message_height(message: &TypedConsensusMessage) -> Option<u64> {
    match message {
        TypedConsensusMessage::CoreProposal { height_context, .. }
        | TypedConsensusMessage::Proposal { height_context, .. } => Some(height_context.height.0),
        TypedConsensusMessage::Vote { vote } => Some(vote.height.0),
        TypedConsensusMessage::ValidationCertificate { certificate } => Some(certificate.height.0),
        TypedConsensusMessage::QuorumCertificate { certificate } => Some(certificate.height.0),
        TypedConsensusMessage::TimeoutCertificate { certificate }
        | TypedConsensusMessage::PreparedCertificateRequest {
            timeout_certificate: certificate,
        }
        | TypedConsensusMessage::PreparedCertificateResponse {
            timeout_certificate: certificate,
            ..
        } => Some(certificate.height.0),
        TypedConsensusMessage::FinalityCheckpointRequest { .. }
        | TypedConsensusMessage::FinalityCheckpoint { .. } => None,
    }
}

fn increment_typed_metric(
    select: impl FnOnce(&mut TypedConsensusTelemetrySnapshot) -> &mut BTreeMap<String, u64>,
    label: &str,
) {
    if let Ok(mut telemetry) = typed_consensus_telemetry().lock() {
        let value = select(&mut telemetry.snapshot)
            .entry(label.to_string())
            .or_default();
        *value = value.saturating_add(1);
    }
}

fn typed_round_stage_label(stage: TypedRoundStage) -> &'static str {
    match stage {
        TypedRoundStage::Proposal => "proposal",
        TypedRoundStage::Validation => "validation",
        TypedRoundStage::Finality => "finality",
        TypedRoundStage::WaitingForCertificate => "waiting_for_certificate",
    }
}

fn record_typed_phase_duration(stage: TypedRoundStage, elapsed: Duration) {
    if let Ok(mut telemetry) = typed_consensus_telemetry().lock() {
        telemetry.snapshot.phase_duration_millis.insert(
            typed_round_stage_label(stage).to_string(),
            elapsed.as_millis().min(u64::MAX as u128) as u64,
        );
    }
}

fn record_typed_finality(height: u64, block_id: &BlockId, round: u64) {
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(u64::MAX as u128) as u64;
    if let Ok(mut telemetry) = typed_consensus_telemetry().lock() {
        telemetry.snapshot.finalized_height = height;
        telemetry.snapshot.finalized_block_id = block_id.0.clone();
        telemetry.snapshot.finalized_round = round;
        telemetry.snapshot.finalized_blocks = telemetry.snapshot.finalized_blocks.saturating_add(1);
        if round == 0 {
            telemetry.snapshot.round_zero_finalized_blocks = telemetry
                .snapshot
                .round_zero_finalized_blocks
                .saturating_add(1);
        }
        telemetry.snapshot.finality_interval_millis = telemetry
            .last_finalized_unix_ms
            .map(|previous| now_ms.saturating_sub(previous))
            .unwrap_or_default();
        if telemetry.snapshot.finality_interval_millis > 0 {
            let interval = telemetry.snapshot.finality_interval_millis;
            telemetry
                .snapshot
                .finality_intervals_millis
                .push_back(interval);
            while telemetry.snapshot.finality_intervals_millis.len() > 10_000 {
                telemetry.snapshot.finality_intervals_millis.pop_front();
            }
        }
        telemetry.last_finalized_unix_ms = Some(now_ms);
    }
}

fn restore_typed_finality_telemetry(records: &[TypedFinalityRecord]) {
    let Some(latest) = records.last() else {
        return;
    };
    let retained_start = records.len().saturating_sub(10_001);
    let retained = &records[retained_start..];
    let mut intervals = retained
        .windows(2)
        .filter_map(|pair| {
            pair[1]
                .block
                .header
                .timestamp_ms_consensus_bounded
                .checked_sub(pair[0].block.header.timestamp_ms_consensus_bounded)
                .filter(|interval| *interval > 0)
        })
        .collect::<VecDeque<_>>();
    while intervals.len() > 10_000 {
        intervals.pop_front();
    }
    let latest_timestamp = latest.block.header.timestamp_ms_consensus_bounded;
    let latest_interval = intervals.back().copied().unwrap_or_default();
    if let Ok(mut telemetry) = typed_consensus_telemetry().lock() {
        telemetry.snapshot.finalized_height = latest.height.0;
        telemetry.snapshot.finalized_block_id = latest.block_id.0.clone();
        telemetry.snapshot.finalized_round = latest.quorum_certificate.round.0;
        telemetry.snapshot.finalized_blocks = records.len() as u64;
        telemetry.snapshot.round_zero_finalized_blocks = records
            .iter()
            .filter(|record| record.quorum_certificate.round.0 == 0)
            .count() as u64;
        telemetry.snapshot.finality_interval_millis = latest_interval;
        telemetry.snapshot.finality_intervals_millis = intervals;
        telemetry.last_finalized_unix_ms = Some(latest_timestamp);
    }
}

pub fn typed_consensus_telemetry_snapshot() -> TypedConsensusTelemetrySnapshot {
    let mut snapshot = typed_consensus_telemetry()
        .lock()
        .map(|telemetry| telemetry.snapshot.clone())
        .unwrap_or_default();
    let queued_votes = typed_vote_queue_depths()
        .lock()
        .map(|depths| depths.values().copied().sum::<usize>())
        .unwrap_or_default();
    let startup_messages = startup_buffer()
        .lock()
        .map(|buffer| buffer.messages.len())
        .unwrap_or_default();
    snapshot.mailbox_depth = queued_votes.saturating_add(startup_messages);
    snapshot
}

pub fn set_typed_consensus_startup_phase(phase: &str) {
    if let Ok(mut telemetry) = typed_consensus_telemetry().lock() {
        telemetry.snapshot.startup_phase = phase.to_string();
    }
}

/// Operational typed PoSy driver.  It is the only component that schedules
/// proposal, vote, timeout, certificate, carry-forward, and next-height work.
/// The coordinator still owns all cryptographic and state-transition checks;
/// this layer serializes already-verified operations immediately on the
/// healthy path. The finalized 1,500 ms stage values remain failure
/// deadlines; they are never mandatory sleeps before a valid vote.
pub struct TypedPosyDriver<E, D, H, R = NoopTypedEtdagIngressRotator>
where
    E: TypedConsensusEgress,
    D: TypedFinalityContextDigestSource,
    H: TypedNextHeightContextSource,
    R: TypedEtdagIngressRotator,
{
    coordinator: TypedPosyCoordinator,
    protected_inputs: EtdagProtectedInputCoordinator,
    egress: E,
    finality_digest_source: D,
    next_height_source: H,
    ingress_rotator: R,
    round_started_at: Instant,
    stage_started_at: Instant,
    last_proposal_broadcast_at: Option<Instant>,
    local_vote_rebroadcasts: Vec<(Vote, Instant)>,
    stage: TypedRoundStage,
    emitted_validation_vote: bool,
    emitted_finality_vote: bool,
    emitted_timeout_vote: bool,
    emitted_proposal: bool,
    validation_votes: BTreeMap<BlockId, BTreeMap<ValidatorId, VerifiedVote>>,
    finality_votes: BTreeMap<BlockId, BTreeMap<ValidatorId, VerifiedVote>>,
    timeout_votes: BTreeMap<ValidatorId, VerifiedVote>,
    observed_validation_votes: BTreeMap<ValidatorId, Vote>,
    observed_finality_votes: BTreeMap<ValidatorId, Vote>,
    observed_timeout_votes: BTreeMap<ValidatorId, Vote>,
    prepared_certificate: Option<ValidationCertificate>,
    pending_validation_certificates: BTreeMap<BlockId, ValidationCertificate>,
    finality_certificate: Option<QuorumCertificate>,
    timeout_certificate: Option<TimeoutCertificate>,
    proposal_material: BTreeMap<BlockId, (TargetAdmissionContext, ProtectedBlockInput)>,
    prepared_store: TypedPreparedStore,
    last_finality_progress_at: Instant,
    last_finality_recovery_request_at: Option<Instant>,
    metrics: TypedCoordinatorDriverMetrics,
}

/// Complete, finalized input set required to construct a Testnet-v3 typed
/// PoSy coordinator for height one.
///
/// The caller is responsible for obtaining these values from the approved
/// Genesis deployment and governed parameter records.  In particular, this
/// type does not deserialize a candidate Genesis file, create a key, or
/// synthesize a contract deployment: the supplied execution state must hash
/// to the independently committed post-deployment Genesis state root.
pub struct TypedPosyCoordinatorStartup {
    pub genesis_bootstrap: TestnetV3GenesisBootstrap,
    pub consensus_parameters: crate::consensus_parameters::LoadedConsensusParameters,
    pub signer: AegisPqvmSigner,
    pub local_validator_id: ValidatorId,
    pub genesis_anchor: Hash,
    pub deployed_genesis_state_root: Hash,
    pub execution_state: ExecutionState,
    pub etdag_parameters: EtdagParameters,
    pub finality_store: TypedFinalityStore,
}

/// Imports the one locally held consensus key that is already committed by
/// finalized Genesis into the typed coordinator signer.
///
/// This is deliberately an import, never a key-generation path.  The caller
/// obtains the keypair through the canonical validator-key loader, which
/// verifies the private key against the canonical local validator record
/// without exposing its material.  This function then requires an exact
/// match with the frozen Testnet-v3 validator set before registering the key
/// for the three Genesis-authorized consensus roles.
pub fn import_local_genesis_bound_typed_signer(
    genesis_bootstrap: &TestnetV3GenesisBootstrap,
    local_validator_operator_address: &str,
    public_key: PQCPublicKey,
    private_key: PQCPrivateKey,
) -> Result<(AegisPqvmSigner, ValidatorId), String> {
    let operator = local_validator_operator_address.trim();
    if operator.is_empty() {
        return Err("typed PoSy local validator operator address is empty".to_string());
    }
    let validator = genesis_bootstrap
        .validator_set
        .validators
        .iter()
        .find(|validator| validator.validator_uma_id.0 == operator)
        .ok_or_else(|| {
            "local validator operator address is absent from finalized Testnet-v3 Genesis"
                .to_string()
        })?;
    if validator.status != ValidatorStatus::Active || validator.activation_epoch.0 != 0 {
        return Err(
            "local validator is not active for the finalized Testnet-v3 Genesis epoch".to_string(),
        );
    }
    if public_key.algorithm != PQCAlgorithm::MLDSA65
        || private_key.algorithm != PQCAlgorithm::MLDSA65
    {
        return Err("typed PoSy local consensus key must use ML-DSA-65".to_string());
    }
    if public_key.key_id != validator.consensus_public_key.key_id.0
        || private_key.public_key_id != public_key.key_id
        || public_key.key_data != validator.consensus_public_key.key_bytes
    {
        return Err(
            "local consensus key does not exactly match the finalized Genesis validator key"
                .to_string(),
        );
    }

    // Check the imported private material against the exact frozen public key
    // before it is registered for signing.  Neither the key nor the signature
    // is logged or returned from this boundary.
    let mut key_check = PQCManager::new();
    let challenge = b"SYNERGY_TESTNET_V3_TYPED_POSY_LOCAL_KEY_BINDING_V1";
    let signature = key_check
        .sign(&private_key, challenge)
        .map_err(|_| "local consensus private key self-test failed".to_string())?;
    if !key_check
        .verify(&public_key, &signature, challenge)
        .map_err(|_| "local consensus private key verification failed".to_string())?
    {
        return Err("local consensus private key does not match finalized Genesis".to_string());
    }

    let mut signer = AegisPqvmSigner::initialize_required()
        .map_err(|error| format!("initialize typed PoSy Aegis signer: {error}"))?;
    let registered_key_id = signer
        .register_existing_keypair(
            &validator.validator_uma_id.0,
            public_key,
            private_key,
            vec![
                AegisPqKeyRole::ConsensusProposer,
                AegisPqKeyRole::ConsensusVote,
                AegisPqKeyRole::EpochTransition,
            ],
            validator.activation_epoch,
        )
        .map_err(|error| format!("import canonical local consensus key: {error}"))?;
    if registered_key_id != validator.consensus_public_key.key_id {
        return Err(
            "typed PoSy signer assigned a key identifier different from finalized Genesis"
                .to_string(),
        );
    }
    for role in [
        AegisPqKeyRole::ConsensusProposer,
        AegisPqKeyRole::ConsensusVote,
        AegisPqKeyRole::EpochTransition,
    ] {
        if !signer.registry.key_is_active_for_epoch(
            &validator.validator_uma_id.0,
            &registered_key_id,
            validator.activation_epoch,
            role,
        ) {
            return Err("typed PoSy signer lifecycle disagrees with finalized Genesis".to_string());
        }
    }
    Ok((signer, validator.validator_id.clone()))
}

impl TypedPosyCoordinatorStartup {
    /// Builds height-one signing authority only after every final input has
    /// been supplied and mutually bound.  This is deliberately a constructor,
    /// not a fallback: callers lacking the post-deployment state root or a
    /// final Genesis anchor cannot start a validator coordinator.
    pub fn build(self) -> Result<TypedPosyCoordinator, String> {
        let local_context = self.genesis_bootstrap.initial_local_consensus_context(
            &self.consensus_parameters.protocol_config,
            self.genesis_anchor,
            self.deployed_genesis_state_root,
        )?;
        self.build_with_finalized_context(local_context)
    }

    /// Builds the coordinator from a context deterministically recovered from
    /// the finalized typed-QC store.  The supplied context is not a restart
    /// override: `TypedPosyCoordinator::new` rebinds it to the exact frozen
    /// topology, protocol configuration, execution root, and durable finality
    /// sequence before any signing authority is returned.
    pub fn build_with_finalized_context(
        self,
        local_context: LocalConsensusContext,
    ) -> Result<TypedPosyCoordinator, String> {
        self.consensus_parameters
            .require_genesis_binding()
            .map_err(|error| format!("typed PoSy startup refuses unbound parameters: {error}"))?;
        self.consensus_parameters.manifest.validate_finalized()?;
        if self.consensus_parameters.root
            != self
                .consensus_parameters
                .protocol_config
                .consensus_parameter_root
        {
            return Err(
                "typed PoSy startup parameter root disagrees with the loaded protocol configuration"
                    .to_string(),
            );
        }
        if self.genesis_anchor.is_zero() || self.deployed_genesis_state_root.is_zero() {
            return Err(
                "typed PoSy startup requires final non-zero Genesis anchor and deployed state root"
                    .to_string(),
            );
        }
        if self.finality_store.genesis_anchor() != self.genesis_anchor {
            return Err(
                "typed PoSy finality store Genesis anchor does not match finalized startup input"
                    .to_string(),
            );
        }
        let computed_state_root = compute_state_root_after(&self.execution_state)?;
        if computed_state_root != self.deployed_genesis_state_root {
            return Err(
                "typed PoSy startup execution state does not match the committed deployed Genesis state root"
                    .to_string(),
            );
        }
        let protocol_config = self.consensus_parameters.protocol_config;
        let consensus = ProofOfSynergyBft::new(
            &self.genesis_bootstrap.verifier,
            self.genesis_bootstrap.validator_set,
            self.genesis_bootstrap.cluster_map,
            protocol_config,
        );
        TypedPosyCoordinator::new(
            consensus,
            self.signer,
            self.local_validator_id,
            local_context,
            self.execution_state,
            self.etdag_parameters,
            self.finality_store,
        )
    }
}

const COORDINATOR_INGRESS_POLL_INTERVAL: Duration = Duration::from_millis(100);
const MAX_QUEUED_TYPED_VOTES_PER_PEER_CONTEXT: usize = 64;
/// A replay response is capped, so a prolonged outage recovers in sequential
/// verified segments instead of allocating an unbounded peer-supplied history.
const MAX_TYPED_FINALITY_CHECKPOINT_RECORDS: usize = 32;
/// A healthy Testnet-v3 round finalizes well within this interval. Reaching it
/// means the local node may have missed a certificate and should request its
/// exact durable successor rather than sign stale rounds indefinitely.
const FINALITY_RECOVERY_REQUEST_INTERVAL: Duration = Duration::from_secs(3);

/// Runs the sole typed-consensus mailbox consumer for a validator process.
///
/// The caller must construct the coordinator from final Genesis and governed
/// parameter inputs before installing this worker.  This function never
/// enables legacy consensus and never treats a rejected network message as a
/// reason to release signing authority.  A disconnected mailbox while the
/// runtime remains marked live is fatal, because continuing without its only
/// authenticated ingress would create an ambiguous operational state.
pub fn run_typed_coordinator_ingress(
    coordinator: &mut TypedPosyCoordinator,
    receiver: &Receiver<TypedConsensusEnvelope>,
    running: &AtomicBool,
) -> Result<TypedCoordinatorIngressMetrics, String> {
    let authorizer =
        FrozenTypedConsensusPeerAuthorizer::new(coordinator.consensus.validator_set.clone())?;
    let mut metrics = TypedCoordinatorIngressMetrics::default();
    while running.load(Ordering::Acquire) {
        match receiver.recv_timeout(COORDINATOR_INGRESS_POLL_INTERVAL) {
            Ok(envelope) => {
                release_typed_vote_queue_slot(&envelope);
                match coordinator.handle_envelope(envelope, &authorizer) {
                    Ok(_) => {
                        metrics.accepted_messages = metrics.accepted_messages.saturating_add(1)
                    }
                    Err(_) => {
                        metrics.rejected_messages = metrics.rejected_messages.saturating_add(1)
                    }
                }
            }
            Err(RecvTimeoutError::Timeout) => continue,
            Err(RecvTimeoutError::Disconnected) if !running.load(Ordering::Acquire) => break,
            Err(RecvTimeoutError::Disconnected) => {
                return Err(
                    "typed PoSy coordinator ingress disconnected while validator runtime is live"
                        .to_string(),
                )
            }
        }
    }
    Ok(metrics)
}

impl TypedPosyCoordinator {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        consensus: ProofOfSynergyBft,
        signer: AegisPqvmSigner,
        local_validator_id: ValidatorId,
        local_context: LocalConsensusContext,
        execution_state: ExecutionState,
        etdag_parameters: EtdagParameters,
        finality_store: TypedFinalityStore,
    ) -> Result<Self, String> {
        local_context.height_context.validate_against(
            &consensus.validator_set,
            &consensus.cluster_map,
            &consensus.protocol_config,
        )?;
        if local_context.height_context.height.0
            != local_context.latest_finalized_height.0.saturating_add(1)
        {
            return Err(
                "typed coordinator context is not for the next finalized height".to_string(),
            );
        }
        if local_context
            .height_context
            .prior_finalized_qc_or_transition_root
            .is_zero()
        {
            return Err(
                "typed coordinator context is missing finalized transition evidence".to_string(),
            );
        }
        etdag_parameters.validate()?;
        let local_validator = consensus
            .validator_set
            .validators
            .iter()
            .find(|validator| validator.validator_id == local_validator_id)
            .ok_or_else(|| {
                "typed coordinator local validator is absent from the frozen set".to_string()
            })?;
        if !signer.registry.key_is_active_for_epoch(
            &local_validator.validator_uma_id.0,
            &local_validator.consensus_public_key.key_id,
            local_context.height_context.epoch,
            crate::synergy_types::AegisPqKeyRole::ConsensusVote,
        ) {
            return Err("typed coordinator local consensus vote key is not active".to_string());
        }
        let signer_key = signer
            .public_key_record(&local_validator.consensus_public_key.key_id)
            .map_err(|error| {
                format!("typed coordinator local signer key is unavailable: {error}")
            })?;
        if signer_key != local_validator.consensus_public_key {
            return Err(
                "typed coordinator local signer key does not match frozen validator key"
                    .to_string(),
            );
        }
        bind_recovered_finality(&finality_store, &local_context)?;
        Ok(Self {
            consensus,
            signer,
            local_validator_id,
            local_context,
            execution_state,
            etdag_parameters,
            proposal_mode: TypedProposalMode::CoreOnly,
            finality_store,
            accepted_proposals: BTreeMap::new(),
        })
    }

    pub fn local_context(&self) -> &LocalConsensusContext {
        &self.local_context
    }

    /// A role-runtime-only copy used to initialize the read-only RPC snapshot
    /// before the coordinator worker is made live.
    pub(crate) fn finalized_execution_state_snapshot(&self) -> ExecutionState {
        self.execution_state.clone()
    }

    fn etdag_ingress_authority(&self) -> TypedEtdagIngressAuthority {
        TypedEtdagIngressAuthority {
            height_context: self.local_context.height_context.clone(),
            verifier: self.consensus.verifier.clone(),
            validator_set: self.consensus.validator_set.clone(),
            cluster_map: self.consensus.cluster_map.clone(),
            protocol_config: self.consensus.protocol_config.clone(),
            parameters: self.etdag_parameters.clone(),
        }
    }

    /// Installs the locally derived authority for the height immediately after
    /// a persisted finality record.  This path deliberately supports only an
    /// unchanged frozen topology; a validator-set or epoch change requires the
    /// separately verified transition path and cannot be smuggled through a
    /// normal next-height update.
    pub fn advance_to_next_height(
        &mut self,
        next_context: LocalConsensusContext,
    ) -> Result<(), String> {
        let latest = self.finality_store.latest()?.ok_or_else(|| {
            "cannot advance typed coordinator without persisted finality".to_string()
        })?;
        let latest_block_hash = Hash::from_hex(&latest.block_id.0)
            .map_err(|error| format!("persisted typed block ID is not a hash: {error}"))?;
        if self.local_context.latest_finalized_height != latest.height
            || self.local_context.latest_finalized_block_hash != latest_block_hash
            || self.local_context.latest_finalized_state_root
                != latest.block.header.state_root_after
        {
            return Err(
                "typed coordinator local finalized state does not match persisted finality"
                    .to_string(),
            );
        }
        if next_context.height_context.height.0 != latest.height.0.saturating_add(1)
            || next_context.latest_finalized_height != latest.height
            || next_context.latest_finalized_block_hash != latest_block_hash
            || next_context.latest_finalized_state_root != latest.block.header.state_root_after
            || next_context.round.0 != 0
            || next_context
                .height_context
                .prior_finalized_qc_or_transition_root
                != latest.quorum_certificate.finality_context_root()?
        {
            return Err("next typed height context is not bound to persisted finality".to_string());
        }
        next_context.height_context.validate_against(
            &self.consensus.validator_set,
            &self.consensus.cluster_map,
            &self.consensus.protocol_config,
        )?;
        if next_context.height_context.epoch != self.local_context.height_context.epoch
            || next_context.height_context.active_validator_set_root
                != self.local_context.height_context.active_validator_set_root
            || next_context.height_context.cluster_map_root
                != self.local_context.height_context.cluster_map_root
            || next_context.height_context.consensus_parameter_root
                != self.local_context.height_context.consensus_parameter_root
        {
            return Err(
                "typed coordinator topology or parameters changed; verified epoch transition is required"
                    .to_string(),
            );
        }
        self.local_context = next_context;
        self.accepted_proposals.clear();
        Ok(())
    }

    /// Installs exactly one authenticated next-epoch topology after a typed
    /// finality record has been durably written.  This path is deliberately
    /// stricter than a normal height advance: the active epoch quorum must
    /// sign the transition, the preconfigured validator population is
    /// immutable, and the next cluster layout must be derived from the signed
    /// transition root rather than supplied by a peer.
    pub fn apply_verified_epoch_transition(
        &mut self,
        transition: &EpochTransition,
        next_validator_set: ValidatorSet,
        next_cluster_map: ClusterMap,
        next_context: LocalConsensusContext,
    ) -> Result<TypedEpochTransitionRecord, String> {
        transition.validate_structure()?;
        let latest = self.finality_store.latest()?.ok_or_else(|| {
            "cannot apply epoch transition without persisted typed finality".to_string()
        })?;
        let latest_block_hash = Hash::from_hex(&latest.block_id.0)
            .map_err(|error| format!("persisted typed block ID is not a hash: {error}"))?;
        if self.local_context.latest_finalized_height != latest.height
            || self.local_context.latest_finalized_block_hash != latest_block_hash
            || self.local_context.latest_finalized_state_root
                != latest.block.header.state_root_after
        {
            return Err(
                "typed coordinator local finalized state does not match persisted finality"
                    .to_string(),
            );
        }
        let current_epoch = self.local_context.height_context.epoch;
        let current_active_set = self.consensus.validator_set.active_for_epoch(current_epoch);
        let current_active_root = current_active_set.hash()?;
        if transition.from_epoch != current_epoch
            || transition.to_epoch.0 != current_epoch.0.saturating_add(1)
            || transition.finalized_height != latest.height
            || transition.finalized_block_id != latest.block_id
            || transition.height_context_root != latest.block.header.height_context_root
            || transition.active_validator_set_hash != current_active_root
            || latest.block.header.active_validator_set_hash != current_active_root
            || self.local_context.height_context.active_validator_set_root != current_active_root
        {
            return Err(
                "epoch transition is not bound to the current typed finality and active set"
                    .to_string(),
            );
        }
        self.consensus
            .verifier
            .verify_epoch_transition_signature_checked(transition, &current_active_set)
            .map_err(|error| format!("epoch transition signature verification failed: {error}"))?;

        validate_immutable_epoch_topology(
            &self.consensus.validator_set,
            &next_validator_set,
            transition,
            &next_cluster_map,
        )?;
        let next_active_set = next_validator_set.active_for_epoch(transition.to_epoch);
        if transition.next_validator_set_hash != next_active_set.hash()?
            || transition.cluster_map_hash != next_cluster_map.hash()?
        {
            return Err(
                "epoch transition next validator or cluster root does not match supplied topology"
                    .to_string(),
            );
        }
        let transition_root = transition.root()?;
        if next_context.height_context.height.0 != latest.height.0.saturating_add(1)
            || next_context.height_context.epoch != transition.to_epoch
            || next_context.latest_finalized_height != latest.height
            || next_context.latest_finalized_block_hash != latest_block_hash
            || next_context.latest_finalized_state_root != latest.block.header.state_root_after
            || next_context.round.0 != 0
            || next_context.height_context.finalized_epoch_seed_root
                != transition.finalized_epoch_seed_root()?
            || next_context
                .height_context
                .prior_finalized_qc_or_transition_root
                != transition_root
        {
            return Err(
                "next typed epoch context is not bound to the finalized transition".to_string(),
            );
        }
        next_context.height_context.validate_against(
            &next_validator_set,
            &next_cluster_map,
            &self.consensus.protocol_config,
        )?;
        let next_verifier = verifier_for_verified_epoch_transition(
            &self.consensus.verifier,
            &self.consensus.validator_set,
            &next_validator_set,
            transition.to_epoch,
        )?;
        let local_validator = next_validator_set
            .validators
            .iter()
            .find(|validator| validator.validator_id == self.local_validator_id)
            .ok_or_else(|| "epoch transition removes the local validator identity".to_string())?;
        if !local_validator.is_active_for_epoch(transition.to_epoch)
            || !self.signer.registry.key_is_active_for_epoch(
                &local_validator.validator_uma_id.0,
                &local_validator.consensus_public_key.key_id,
                transition.to_epoch,
                AegisPqKeyRole::ConsensusVote,
            )
        {
            return Err(
                "local validator is not an active consensus voter in the transitioned epoch"
                    .to_string(),
            );
        }

        // All transition and topology checks complete before the durable
        // append.  The store is the restart boundary; it is never written for
        // an invalid or partly-derived epoch.
        // A startup recovery may already have the exact verified transition
        // persisted with the finalized block.  Re-checking its signatures and
        // topology above remains mandatory, but duplicating the durable
        // record would turn a safe restart into a fork-like append failure.
        let record =
            match self.finality_store.epoch_transition_for_finality(&latest)? {
                Some(existing) if existing.transition == *transition => existing,
                Some(_) => return Err(
                    "persisted epoch transition conflicts with the verified topology installation"
                        .to_string(),
                ),
                None => self
                    .finality_store
                    .append_verified_epoch_transition(transition)?,
            };
        self.consensus.install_verified_epoch_topology(
            next_verifier,
            next_validator_set,
            next_cluster_map,
        )?;
        self.local_context = next_context;
        self.accepted_proposals.clear();
        Ok(record)
    }

    pub fn handle_envelope(
        &mut self,
        envelope: TypedConsensusEnvelope,
        peer_authorizer: &dyn TypedConsensusPeerAuthorizer,
    ) -> Result<TypedCoordinatorEvent, String> {
        let authenticated_peer = envelope.authenticated_peer.as_ref().ok_or_else(|| {
            "typed consensus message has no Genesis-bound authenticated peer identity".to_string()
        })?;
        peer_authorizer.authorize(authenticated_peer, &envelope.message)?;
        self.handle_message(envelope.message)
    }

    pub fn handle_message(
        &mut self,
        message: TypedConsensusMessage,
    ) -> Result<TypedCoordinatorEvent, String> {
        match message {
            TypedConsensusMessage::CoreProposal {
                height_context,
                block,
            } => {
                self.require_core_only_mode()?;
                self.accept_core_proposal(height_context, block)
            }
            TypedConsensusMessage::Proposal {
                height_context,
                target_context,
                protected_block,
                block,
            } => {
                self.require_etdag_mode()?;
                self.accept_proposal(height_context, target_context, protected_block, block)
            }
            TypedConsensusMessage::Vote { vote } => self.accept_vote(vote),
            TypedConsensusMessage::ValidationCertificate { certificate } => {
                self.accept_validation_certificate(certificate)
            }
            TypedConsensusMessage::QuorumCertificate { certificate } => {
                self.accept_finality_certificate(certificate)
            }
            TypedConsensusMessage::TimeoutCertificate { certificate } => {
                self.accept_timeout_certificate(certificate)
            }
            TypedConsensusMessage::PreparedCertificateRequest { .. }
            | TypedConsensusMessage::PreparedCertificateResponse { .. } => Err(
                "typed prepared-certificate recovery messages must be handled by the authenticated driver"
                    .to_string(),
            ),
            TypedConsensusMessage::FinalityCheckpointRequest { .. }
            | TypedConsensusMessage::FinalityCheckpoint { .. } => Err(
                "typed finality checkpoint messages must be handled by the authenticated driver"
                    .to_string(),
            ),
        }
    }

    pub fn propose_protected_block(
        &mut self,
        protected_block: &ProtectedBlockInput,
        target_context: &TargetAdmissionContext,
    ) -> Result<Block, String> {
        self.require_etdag_mode()?;
        self.require_local_target_context(target_context)?;
        let proposer = self.local_validator()?.clone();
        let block = self.consensus.propose_protected_block(
            &mut self.signer,
            &proposer,
            protected_block,
            target_context,
            &self.local_context,
            &self.execution_state,
            &self.etdag_parameters,
        )?;
        self.record_accepted_proposal(&block)?;
        Ok(block)
    }

    /// Creates a deterministic empty core proposal while the finalized
    /// manifest has not activated ETDAG.  This method deliberately exposes no
    /// transaction input, so it cannot become a plaintext transaction path.
    pub fn propose_core_block(&mut self) -> Result<Block, String> {
        self.require_core_only_mode()?;
        let proposer = self.local_validator()?.clone();
        let block = self.consensus.propose_core_block(
            &mut self.signer,
            &proposer,
            &self.local_context,
            &self.execution_state,
        )?;
        self.record_accepted_proposal(&block)?;
        Ok(block)
    }

    pub fn validation_vote_for(&mut self, block: &Block) -> Result<Vote, String> {
        let validator = self.local_validator()?.clone();
        self.consensus.validation_vote(
            &mut self.signer,
            &validator,
            block,
            &self.local_context.height_context,
        )
    }

    pub fn finality_vote_for(
        &mut self,
        block: &Block,
        certificate: &ValidationCertificate,
    ) -> Result<Vote, String> {
        let validator = self.local_validator()?.clone();
        self.consensus.finality_vote(
            &mut self.signer,
            &validator,
            block,
            certificate,
            &self.local_context.height_context,
        )
    }

    pub fn timeout_vote(
        &mut self,
        highest_prepared: Option<&ValidationCertificate>,
    ) -> Result<Vote, String> {
        let validator = self.local_validator()?.clone();
        self.consensus.timeout_vote(
            &mut self.signer,
            &validator,
            &self.local_context.height_context,
            self.local_context.round,
            highest_prepared,
        )
    }

    pub fn form_validation_certificate(
        &mut self,
        votes: &[Vote],
    ) -> Result<ValidationCertificate, String> {
        self.consensus
            .form_vc(votes, &self.local_context.height_context)
    }

    pub fn form_finality_certificate(
        &mut self,
        votes: &[Vote],
    ) -> Result<QuorumCertificate, String> {
        self.consensus
            .form_qc(votes, &self.local_context.height_context)
    }

    pub fn form_timeout_certificate(
        &mut self,
        votes: &[Vote],
    ) -> Result<TimeoutCertificate, String> {
        self.consensus
            .form_tc(votes, &self.local_context.height_context)
    }

    fn form_validation_certificate_from_verified(
        &mut self,
        votes: &[VerifiedVote],
    ) -> Result<ValidationCertificate, String> {
        self.consensus
            .form_vc_from_verified(votes, &self.local_context.height_context)
    }

    fn form_finality_certificate_from_verified(
        &mut self,
        votes: &[VerifiedVote],
    ) -> Result<QuorumCertificate, String> {
        self.consensus
            .form_qc_from_verified(votes, &self.local_context.height_context)
    }

    fn form_timeout_certificate_from_verified(
        &mut self,
        votes: &[VerifiedVote],
    ) -> Result<TimeoutCertificate, String> {
        self.consensus
            .form_tc_from_verified(votes, &self.local_context.height_context)
    }

    /// Re-signs the exact prepared candidate for the TC-authorized next round.
    /// The underlying PoSy implementation verifies the VC, TC, scheduled
    /// proposer, and stable candidate identity before releasing the signature.
    pub fn carry_forward_prepared_block(
        &mut self,
        original: &Block,
        certificate: &ValidationCertificate,
        timeout_certificate: &TimeoutCertificate,
    ) -> Result<Block, String> {
        let proposer = self.local_validator()?.clone();
        let block = self.consensus.carry_forward_prepared_candidate(
            &mut self.signer,
            original,
            certificate,
            timeout_certificate,
            &proposer,
            &self.local_context.height_context,
        )?;
        self.record_accepted_proposal(&block)?;
        Ok(block)
    }

    fn accept_proposal(
        &mut self,
        height_context: crate::synergy_types::HeightConsensusContext,
        target_context: TargetAdmissionContext,
        protected_block: ProtectedBlockInput,
        block: Block,
    ) -> Result<TypedCoordinatorEvent, String> {
        if height_context != self.local_context.height_context {
            return Err(
                "typed proposal height context does not equal the local immutable context"
                    .to_string(),
            );
        }
        self.require_local_target_context(&target_context)?;
        self.consensus.validate_protected_proposal(
            &block,
            &protected_block,
            &target_context,
            &self.local_context,
            &self.execution_state,
            &self.etdag_parameters,
        )?;
        let candidate_id = self.record_accepted_proposal(&block)?;
        Ok(TypedCoordinatorEvent::ProposalAccepted { candidate_id })
    }

    fn accept_core_proposal(
        &mut self,
        height_context: crate::synergy_types::HeightConsensusContext,
        block: Block,
    ) -> Result<TypedCoordinatorEvent, String> {
        if height_context != self.local_context.height_context {
            return Err(
                "typed core proposal height context does not equal the local immutable context"
                    .to_string(),
            );
        }
        self.consensus.validate_core_proposal(
            &block,
            &self.local_context,
            &self.execution_state,
        )?;
        let candidate_id = self.record_accepted_proposal(&block)?;
        Ok(TypedCoordinatorEvent::ProposalAccepted { candidate_id })
    }

    /// Accepts a core-only proposal carried by a verified finality checkpoint.
    ///
    /// A lagging replica may have missed many ephemeral timeout certificates,
    /// so its live round authority cannot validate a later finalized proposal
    /// envelope. The supplied finality QC is the durable authority for that
    /// exact candidate and round. Verify it first, then use the finalized-only
    /// proposal path before installing the block for the normal commit path.
    fn accept_finalized_core_proposal(
        &mut self,
        block: Block,
        finality_certificate: &QuorumCertificate,
    ) -> Result<TypedCoordinatorEvent, String> {
        self.require_core_only_mode()?;
        self.consensus
            .verify_qc(finality_certificate, &self.local_context.height_context)?;
        let candidate_id = block.candidate_id()?;
        if finality_certificate.block_id != candidate_id
            || finality_certificate.height != block.header.height
            || finality_certificate.round != block.header.round
        {
            return Err(
                "typed finality checkpoint QC does not certify its supplied core proposal"
                    .to_string(),
            );
        }
        self.consensus.validate_finalized_core_record(
            &block,
            &self.local_context,
            &self.execution_state,
        )?;
        // The verified QC is also the durable authority for the block's
        // finalized round. Align the post-commit context with that round so
        // the next-height provider can prove the exact predecessor context.
        self.local_context.round = block.header.round;
        let candidate_id = self.record_accepted_proposal(&block)?;
        Ok(TypedCoordinatorEvent::ProposalAccepted { candidate_id })
    }

    /// Installs a prepared core candidate recovered from durable local state
    /// or an authenticated validator peer. The VC and TC provide the missing
    /// round authority; the block still passes the complete core proposal,
    /// execution, proposer-schedule, and ML-DSA verification path.
    fn recover_core_prepared(
        &mut self,
        block: Block,
        validation_certificate: &ValidationCertificate,
        timeout_certificate: &TimeoutCertificate,
    ) -> Result<BlockId, String> {
        self.require_core_only_mode()?;
        self.consensus
            .verify_vc(validation_certificate, &self.local_context.height_context)?;
        self.consensus
            .verify_tc(timeout_certificate, &self.local_context.height_context)?;
        let candidate_id = block.candidate_id()?;
        let carries_prepared = timeout_certificate.carry_forward_candidate_id.as_ref()
            == Some(&candidate_id)
            && timeout_certificate.highest_prepared_vc_root == Some(validation_certificate.root()?);
        let authorizes_prepared_round = timeout_certificate.carry_forward_candidate_id.is_none()
            && timeout_certificate.highest_prepared_vc_root.is_none()
            && timeout_certificate.next_round == block.header.round
            && validation_certificate.round == block.header.round;
        if validation_certificate.candidate_id != candidate_id
            || (!carries_prepared && !authorizes_prepared_round)
        {
            return Err(
                "typed prepared recovery does not bind one exact block, VC, and TC".to_string(),
            );
        }
        self.consensus.validate_finalized_core_record(
            &block,
            &self.local_context,
            &self.execution_state,
        )?;
        if self.local_context.round.0 > timeout_certificate.next_round.0 {
            return Err("typed prepared recovery TC is older than the local round".to_string());
        }
        if self.local_context.round != timeout_certificate.next_round {
            self.local_context.round = self
                .consensus
                .recover_round_after_tc(timeout_certificate, &self.local_context.height_context)?;
        }
        self.record_accepted_proposal(&block)
    }

    fn require_core_only_mode(&self) -> Result<(), String> {
        if self.proposal_mode != TypedProposalMode::CoreOnly {
            return Err(
                "core-only typed proposals are unavailable after ETDAG activation".to_string(),
            );
        }
        Ok(())
    }

    fn require_etdag_mode(&self) -> Result<(), String> {
        if self.proposal_mode != TypedProposalMode::EtdagActivated {
            return Err(
                "protected ETDAG proposals require a finalized activation permit".to_string(),
            );
        }
        Ok(())
    }

    fn accept_vote(&mut self, vote: Vote) -> Result<TypedCoordinatorEvent, String> {
        let phase = vote.phase.clone();
        let candidate_id = vote.block_id.clone();
        self.consensus
            .collect_votes(&[vote], &self.local_context.height_context, phase.clone())?;
        Ok(TypedCoordinatorEvent::VoteAccepted {
            phase,
            candidate_id,
        })
    }

    fn accept_validation_certificate(
        &mut self,
        certificate: ValidationCertificate,
    ) -> Result<TypedCoordinatorEvent, String> {
        let candidate_id = certificate.candidate_id.clone();
        self.consensus
            .verify_vc(&certificate, &self.local_context.height_context)?;
        Ok(TypedCoordinatorEvent::ValidationCertificateAccepted { candidate_id })
    }

    fn accept_finality_certificate(
        &mut self,
        certificate: QuorumCertificate,
    ) -> Result<TypedCoordinatorEvent, String> {
        self.consensus
            .verify_qc(&certificate, &self.local_context.height_context)?;
        let block = self
            .accepted_proposals
            .get(&certificate.block_id)
            .cloned()
            .ok_or_else(|| "finality QC has no locally validated typed proposal".to_string())?;
        self.consensus
            .commit_block(&block, &certificate, &self.local_context.height_context)?;
        let next_state = execute_finalized_block(&self.execution_state, &block)?;
        let record = self
            .finality_store
            .append_verified_finality(&block, &certificate)?;
        self.execution_state = next_state;
        // The process-local RPC cache is updated only after both execution
        // and durable finality have succeeded.  When no typed runtime owns
        // the cache (for example in isolated unit tests), it remains absent
        // and public contract reads fail closed.
        let _ = publish_finalized_execution_state_snapshot(&self.execution_state);
        self.local_context.latest_finalized_height = block.header.height;
        self.local_context.latest_finalized_block_hash = Hash::from_hex(&record.block_id.0)
            .map_err(|error| format!("finalized typed block ID is not a hash: {error}"))?;
        self.local_context.latest_finalized_state_root = block.header.state_root_after;
        self.local_context.latest_finalized_timestamp_ms =
            block.header.timestamp_ms_consensus_bounded;
        Ok(TypedCoordinatorEvent::Finalized { record })
    }

    fn accept_timeout_certificate(
        &mut self,
        certificate: TimeoutCertificate,
    ) -> Result<TypedCoordinatorEvent, String> {
        let next_round = if certificate.next_round == self.local_context.round {
            // Multiple eligible replicas can form the same TC subject with
            // different valid strict-quorum subsets. Re-verification is
            // mandatory, but replay of the already-installed transition is
            // idempotent.
            self.consensus
                .verify_tc(&certificate, &self.local_context.height_context)?;
            self.local_context.round
        } else if certificate.closing_round == self.local_context.round {
            self.consensus.advance_round_after_tc(
                &certificate,
                &self.local_context.height_context,
                self.local_context.round,
            )?
        } else if certificate.closing_round.0 > self.local_context.round.0 {
            // A restarted validator may have only finalized state while its
            // peers are already in a later round. A valid strict-quorum TC is
            // sufficient authority to join its successor directly; requiring
            // every process-local intermediate TC makes restarts permanent
            // liveness failures.
            self.consensus
                .recover_round_after_tc(&certificate, &self.local_context.height_context)?
        } else {
            return Err("TC closes a round older than the local current round".to_string());
        };
        self.local_context.round = next_round;
        Ok(TypedCoordinatorEvent::TimeoutCertificateAccepted {
            next_round: next_round.0,
        })
    }

    fn require_local_target_context(
        &self,
        target_context: &TargetAdmissionContext,
    ) -> Result<(), String> {
        target_context.validate_against(
            &self.consensus.validator_set,
            &self.consensus.cluster_map,
            &self.consensus.protocol_config,
        )?;
        target_context.validate_height_context_compatibility(&self.local_context.height_context)
    }

    fn local_validator(&self) -> Result<&crate::synergy_types::ValidatorRecord, String> {
        self.consensus
            .validator_set
            .validators
            .iter()
            .find(|validator| validator.validator_id == self.local_validator_id)
            .ok_or_else(|| {
                "typed coordinator local validator is absent from frozen set".to_string()
            })
    }

    fn record_accepted_proposal(&mut self, block: &Block) -> Result<BlockId, String> {
        let candidate_id = block.candidate_id()?;
        for (existing_id, existing) in &self.accepted_proposals {
            if existing.header.round == block.header.round && existing_id != &candidate_id {
                return Err(format!(
                    "TYPED_DRIVER_SOURCE_CONFLICT: two stable candidates were accepted for one height/round ({} versus {})",
                    existing_id.0, candidate_id.0
                ));
            }
        }
        if let Some(existing) = self.accepted_proposals.get(&candidate_id) {
            // `candidate_id` intentionally excludes only the three envelope
            // fields that a verified TC carry-forward changes.  A verified
            // proposal check has already authenticated those fields, so
            // replacing the current envelope retains the stable candidate
            // while allowing the next authorized proposer to carry it.
            if existing.candidate_id()? != candidate_id {
                return Err(
                    "typed proposal candidate ID maps to different block contents".to_string(),
                );
            }
            self.accepted_proposals
                .insert(candidate_id.clone(), block.clone());
        } else {
            self.accepted_proposals
                .insert(candidate_id.clone(), block.clone());
        }
        Ok(candidate_id)
    }
}

impl<E, D, H> TypedPosyDriver<E, D, H, NoopTypedEtdagIngressRotator>
where
    E: TypedConsensusEgress,
    D: TypedFinalityContextDigestSource,
    H: TypedNextHeightContextSource,
{
    pub fn new(
        coordinator: TypedPosyCoordinator,
        protected_inputs: EtdagProtectedInputCoordinator,
        egress: E,
        finality_digest_source: D,
        next_height_source: H,
    ) -> Result<Self, String> {
        Self::new_with_ingress_rotator(
            coordinator,
            protected_inputs,
            egress,
            finality_digest_source,
            next_height_source,
            NoopTypedEtdagIngressRotator,
        )
    }
}

impl<E, D, H, R> TypedPosyDriver<E, D, H, R>
where
    E: TypedConsensusEgress,
    D: TypedFinalityContextDigestSource,
    H: TypedNextHeightContextSource,
    R: TypedEtdagIngressRotator,
{
    pub(crate) fn required_remote_validator_count(&self) -> usize {
        self.coordinator
            .consensus
            .validator_set
            .active_for_epoch(self.coordinator.local_context.height_context.epoch)
            .validators
            .len()
            .saturating_sub(1)
    }

    pub fn new_with_ingress_rotator(
        coordinator: TypedPosyCoordinator,
        protected_inputs: EtdagProtectedInputCoordinator,
        egress: E,
        finality_digest_source: D,
        next_height_source: H,
        ingress_rotator: R,
    ) -> Result<Self, String> {
        validate_canonical_driver_timeouts(&coordinator.consensus.protocol_config)?;
        let recovered_finality = coordinator.finality_store.recover()?;
        restore_typed_finality_telemetry(&recovered_finality);
        let prepared_store = TypedPreparedStore::for_finality_store(&coordinator.finality_store)?;
        let recovered_prepared = prepared_store.recover()?;
        let mut driver = Self {
            coordinator,
            protected_inputs,
            egress,
            finality_digest_source,
            next_height_source,
            ingress_rotator,
            round_started_at: Instant::now(),
            stage_started_at: Instant::now(),
            last_proposal_broadcast_at: None,
            local_vote_rebroadcasts: Vec::new(),
            stage: TypedRoundStage::Proposal,
            emitted_validation_vote: false,
            emitted_finality_vote: false,
            emitted_timeout_vote: false,
            emitted_proposal: false,
            validation_votes: BTreeMap::new(),
            finality_votes: BTreeMap::new(),
            timeout_votes: BTreeMap::new(),
            observed_validation_votes: BTreeMap::new(),
            observed_finality_votes: BTreeMap::new(),
            observed_timeout_votes: BTreeMap::new(),
            prepared_certificate: None,
            pending_validation_certificates: BTreeMap::new(),
            finality_certificate: None,
            timeout_certificate: None,
            proposal_material: BTreeMap::new(),
            prepared_store,
            last_finality_progress_at: Instant::now(),
            last_finality_recovery_request_at: None,
            metrics: TypedCoordinatorDriverMetrics::default(),
        };
        if let Some(record) = recovered_prepared {
            if record.height.0 <= driver.coordinator.local_context.latest_finalized_height.0 {
                driver.prepared_store.clear_after_finality(
                    driver.coordinator.local_context.latest_finalized_height,
                )?;
            } else {
                driver.install_recovered_prepared_record(record, false)?;
            }
        }
        driver.commit_atomic_recovery_checkpoint()?;
        let durable_restarts = driver
            .coordinator
            .consensus
            .signing_authority
            .record_coordinator_start()?;
        if let Ok(mut telemetry) = typed_consensus_telemetry().lock() {
            telemetry.snapshot.restarts = durable_restarts;
            telemetry.snapshot.current_height =
                driver.coordinator.local_context.height_context.height.0;
            telemetry.snapshot.current_round = driver.coordinator.local_context.round.0;
        }
        Ok(driver)
    }

    pub fn coordinator(&self) -> &TypedPosyCoordinator {
        &self.coordinator
    }

    pub fn metrics(&self) -> TypedCoordinatorDriverMetrics {
        self.metrics
    }

    /// Enables protected ETDAG proposal handling only after the role runtime
    /// has obtained an activation capability from the finalized manifest.
    ///
    /// The capability is deliberately borrowed: the role runtime consumes the
    /// same one to install the process-wide certified-input ingress.  This
    /// keeps the two activation boundaries coupled without duplicating a
    /// constructible boolean authority.  Configuration is forbidden once a
    /// proposal has been scheduled, so a running height cannot switch between
    /// core and ETDAG proposal semantics.
    pub(crate) fn configure_etdag_activation(
        &mut self,
        _activation_permit: &EtdagActivationPermit,
    ) -> Result<(), String> {
        if self.emitted_proposal
            || !self.coordinator.accepted_proposals.is_empty()
            || self.stage != TypedRoundStage::Proposal
        {
            return Err(
                "cannot activate ETDAG after typed proposal scheduling has begun".to_string(),
            );
        }
        self.coordinator.proposal_mode = TypedProposalMode::EtdagActivated;
        Ok(())
    }

    /// Reports whether this driver is permitted to construct or accept a
    /// protected ETDAG proposal at the current immutable height context.
    pub fn etdag_is_active(&self) -> bool {
        self.coordinator.proposal_mode == TypedProposalMode::EtdagActivated
    }

    /// Installs the immutable certified-ETDAG ingress authority for the
    /// current recovered Genesis/QC height.  Role startup calls this before it
    /// exposes typed P2P ingress; errors leave the driver unscheduled and no
    /// synthetic protected input is produced.
    pub fn install_certified_etdag_ingress(&mut self) -> Result<(), String> {
        if !self.etdag_is_active() {
            return Err(
                "ETDAG certified-input ingress requires a finalized activation permit".to_string(),
            );
        }
        let local_context = self.coordinator.local_context().clone();
        let finality_context_digest = self
            .finality_digest_source
            .expected_digest(&local_context)?;
        let authority = self.coordinator.etdag_ingress_authority();
        self.ingress_rotator.install_initial(
            &self.protected_inputs,
            &authority,
            &finality_context_digest,
        )
    }

    /// Removes the process-local ETDAG ingress once the typed worker has
    /// stopped.  This is exposed only for the role-runtime lifecycle owner;
    /// P2P and RPC handlers have no route to remove or replace it.
    pub fn remove_certified_etdag_ingress(&mut self) -> Result<(), String> {
        self.ingress_rotator.remove()
    }

    /// Advances the local stage machine at a supplied monotonic instant.  This
    /// separate time input makes the exact deadline behavior testable without
    /// a wall-clock dependency.
    pub fn tick_at(&mut self, now: Instant) -> Result<(), String> {
        let elapsed = now
            .checked_duration_since(self.round_started_at)
            .ok_or_else(|| "typed PoSy driver monotonic clock moved backwards".to_string())?;
        let config = &self.coordinator.consensus.protocol_config;
        let proposal_deadline = Duration::from_millis(config.proposal_timeout_ms);
        let validation_deadline = proposal_deadline
            .checked_add(Duration::from_millis(config.prevote_timeout_ms))
            .ok_or_else(|| "typed PoSy validation deadline overflow".to_string())?;
        let finality_deadline = validation_deadline
            .checked_add(Duration::from_millis(config.precommit_timeout_ms))
            .ok_or_else(|| "typed PoSy finality deadline overflow".to_string())?;
        let round_cap = Duration::from_millis(config.max_round_timeout_ms);

        let proposal_rebroadcast_due = self.last_proposal_broadcast_at.map_or(true, |last| {
            now.checked_duration_since(last)
                .map(|elapsed| elapsed >= PROPOSAL_REBROADCAST_INTERVAL)
                .unwrap_or(false)
        });
        if self.stage != TypedRoundStage::WaitingForCertificate
            && elapsed < proposal_deadline
            && !self
                .prepared_certificate
                .as_ref()
                .is_some_and(|certificate| {
                    certificate.round == self.coordinator.local_context.round
                })
            && (!self.emitted_proposal || proposal_rebroadcast_due)
        {
            self.try_emit_scheduled_proposal()?;
            self.emitted_proposal = true;
            self.last_proposal_broadcast_at = Some(now);
        }
        self.rebroadcast_local_vote_if_due(now)?;

        if elapsed >= round_cap && !self.emitted_timeout_vote {
            self.emit_timeout_vote(now)?;
            self.transition_stage(TypedRoundStage::WaitingForCertificate, now);
            return Ok(());
        }

        // Authenticated proposal and certificate arrival drives the healthy
        // path. Governed timeout values below are failure deadlines only.
        self.advance_healthy_path(now)?;

        if self.stage == TypedRoundStage::Proposal && elapsed >= proposal_deadline {
            self.emit_timeout_vote(now)?;
            self.transition_stage(TypedRoundStage::WaitingForCertificate, now);
        }

        if self.stage == TypedRoundStage::Validation && elapsed >= validation_deadline {
            self.emit_timeout_vote(now)?;
            self.transition_stage(TypedRoundStage::WaitingForCertificate, now);
        }

        if self.stage == TypedRoundStage::Finality && elapsed >= finality_deadline {
            if self.finality_certificate.is_none() {
                self.emit_timeout_vote(now)?;
                self.transition_stage(TypedRoundStage::WaitingForCertificate, now);
            }
        }
        self.request_finality_recovery_if_stalled(now)?;
        Ok(())
    }

    pub fn tick(&mut self) -> Result<(), String> {
        self.tick_at(Instant::now())
    }

    /// Handles one authenticated inbound message and reacts with only the
    /// stage-authorized local actions.  Invalid peer input remains rejectable
    /// by the caller; an internally conflicting certified source is returned
    /// as a fatal `TYPED_DRIVER_SOURCE_CONFLICT` error.
    pub fn handle_envelope(
        &mut self,
        envelope: TypedConsensusEnvelope,
        peer_authorizer: &dyn TypedConsensusPeerAuthorizer,
    ) -> Result<TypedCoordinatorEvent, String> {
        validate_typed_consensus_message_size(&envelope.message)?;
        let message = envelope.message.clone();
        if let Some(message_height) = typed_message_height(&message) {
            let current_height = self.coordinator.local_context.height_context.height.0;
            if message_height < current_height {
                let authenticated_peer = envelope.authenticated_peer.as_ref().ok_or_else(|| {
                    "typed consensus message has no Genesis-bound authenticated peer identity"
                        .to_string()
                })?;
                peer_authorizer.authorize(authenticated_peer, &message)?;
                increment_typed_metric(
                    |snapshot| &mut snapshot.messages_rejected_precrypto,
                    typed_message_kind(&message),
                );
                self.metrics.deduplicated_replays =
                    self.metrics.deduplicated_replays.saturating_add(1);
                return Ok(TypedCoordinatorEvent::StaleFinalizedHeightIgnored {
                    height: message_height,
                });
            }
        }
        if matches!(
            message,
            TypedConsensusMessage::FinalityCheckpointRequest { .. }
                | TypedConsensusMessage::FinalityCheckpoint { .. }
                | TypedConsensusMessage::PreparedCertificateRequest { .. }
                | TypedConsensusMessage::PreparedCertificateResponse { .. }
        ) {
            let authenticated_peer = envelope.authenticated_peer.as_ref().ok_or_else(|| {
                "typed consensus message has no Genesis-bound authenticated peer identity"
                    .to_string()
            })?;
            peer_authorizer.authorize(authenticated_peer, &message)?;
            let event = match message {
                TypedConsensusMessage::FinalityCheckpointRequest { next_height } => {
                    self.respond_to_finality_checkpoint_request(next_height)?;
                    TypedCoordinatorEvent::FinalityCheckpointRequestAccepted
                }
                TypedConsensusMessage::FinalityCheckpoint { records } => {
                    let imported_records = self.import_finality_checkpoint(records)?;
                    TypedCoordinatorEvent::FinalityCheckpointApplied { imported_records }
                }
                TypedConsensusMessage::PreparedCertificateRequest {
                    timeout_certificate,
                } => {
                    self.respond_to_prepared_certificate_request(timeout_certificate)?;
                    TypedCoordinatorEvent::PreparedCertificateRequestAccepted
                }
                TypedConsensusMessage::PreparedCertificateResponse {
                    timeout_certificate,
                    block,
                    validation_certificate,
                } => {
                    let candidate_id = self.install_recovered_prepared_record(
                        TypedPreparedRecord {
                            record_version: TYPED_PREPARED_RECORD_VERSION,
                            height: block.header.height,
                            epoch: block.header.epoch,
                            current_round: timeout_certificate.next_round,
                            height_context_root: block.header.height_context_root,
                            active_validator_set_hash: block.header.active_validator_set_hash,
                            prepared_round: validation_certificate.round,
                            prepared_candidate_id: block.candidate_id()?,
                            block,
                            validation_certificate,
                            timeout_certificate: Some(timeout_certificate),
                        },
                        true,
                    )?;
                    TypedCoordinatorEvent::PreparedCertificateRecovered { candidate_id }
                }
                _ => unreachable!("authenticated driver-only message match was checked above"),
            };
            self.metrics.accepted_messages = self.metrics.accepted_messages.saturating_add(1);
            return Ok(event);
        }
        if let Some(event) = self.accept_exact_authenticated_replay(&envelope, peer_authorizer)? {
            increment_typed_metric(
                |snapshot| &mut snapshot.messages_deduplicated,
                typed_message_kind(&message),
            );
            self.metrics.accepted_messages = self.metrics.accepted_messages.saturating_add(1);
            self.metrics.deduplicated_replays = self.metrics.deduplicated_replays.saturating_add(1);
            return Ok(event);
        }
        let finalized_context = self.coordinator.local_context.height_context.clone();
        let event = self
            .coordinator
            .handle_envelope(envelope, peer_authorizer)?;
        match (message, &event) {
            (
                TypedConsensusMessage::CoreProposal { block, .. },
                TypedCoordinatorEvent::ProposalAccepted { candidate_id },
            ) => {
                if block.candidate_id()? != *candidate_id {
                    return Err(
                        "typed core proposal accepted under a different candidate ID".to_string(),
                    );
                }
                self.install_pending_validation_certificate(candidate_id, block.header.round)?;
                self.persist_prepared_if_complete()?;
            }
            (
                TypedConsensusMessage::Proposal {
                    target_context,
                    protected_block,
                    block,
                    ..
                },
                TypedCoordinatorEvent::ProposalAccepted { candidate_id },
            ) => {
                self.record_proposal_material(
                    candidate_id,
                    target_context,
                    protected_block,
                    &block,
                )?;
                self.install_pending_validation_certificate(candidate_id, block.header.round)?;
            }
            (TypedConsensusMessage::Vote { vote }, TypedCoordinatorEvent::VoteAccepted { .. }) => {
                self.record_verified_vote(vote)?;
            }
            (
                TypedConsensusMessage::ValidationCertificate { certificate },
                TypedCoordinatorEvent::ValidationCertificateAccepted { .. },
            ) => self.record_validation_certificate(certificate)?,
            (
                TypedConsensusMessage::QuorumCertificate { certificate },
                TypedCoordinatorEvent::Finalized { record },
            ) => self.finalize_after_verified_qc(certificate, finalized_context, record.clone())?,
            (
                TypedConsensusMessage::TimeoutCertificate { certificate },
                TypedCoordinatorEvent::TimeoutCertificateAccepted { .. },
            ) => self.install_verified_timeout_certificate(certificate)?,
            _ => {
                return Err(
                    "typed coordinator event does not match its authenticated message".to_string(),
                )
            }
        }
        self.advance_healthy_path(Instant::now())?;
        self.metrics.accepted_messages = self.metrics.accepted_messages.saturating_add(1);
        Ok(event)
    }

    /// Returns a no-op event for an exact vote replay whose complete driver
    /// effects have already been recorded in this height/round.
    ///
    /// Replays are common because proposal and vote retries deliberately
    /// overlap lossy network delivery. Sending every exact retry back through
    /// ML-DSA verification lets six honest validators create a self-inflicted
    /// CPU queue. The authenticated peer binding is still checked here, and
    /// any changed byte follows the normal full-verification path.
    fn accept_exact_authenticated_replay(
        &self,
        envelope: &TypedConsensusEnvelope,
        peer_authorizer: &dyn TypedConsensusPeerAuthorizer,
    ) -> Result<Option<TypedCoordinatorEvent>, String> {
        let authenticated_peer = envelope.authenticated_peer.as_ref().ok_or_else(|| {
            "typed consensus message has no Genesis-bound authenticated peer identity".to_string()
        })?;
        peer_authorizer.authorize(authenticated_peer, &envelope.message)?;

        match &envelope.message {
            TypedConsensusMessage::Vote { vote } => {
                let context = &self.coordinator.local_context.height_context;
                if vote.height != context.height
                    || vote.round != self.coordinator.local_context.round
                    || vote.epoch != context.epoch
                    || vote.cluster_id != context.assigned_cluster_id
                    || vote.height_context_root != context.root()?
                {
                    // Installed timeout certificates deliberately allow a
                    // fully verified late timeout vote from their closing
                    // round. It cannot use this exact-replay shortcut, but it
                    // must retain the normal recovery path below.
                    return Ok(None);
                }
                let observed = match vote.phase {
                    VotePhase::Validate => &self.observed_validation_votes,
                    VotePhase::Finality => &self.observed_finality_votes,
                    VotePhase::Timeout => &self.observed_timeout_votes,
                };
                if observed
                    .get(&vote.validator_id)
                    .is_some_and(|accepted| accepted == vote)
                {
                    return Ok(Some(TypedCoordinatorEvent::VoteAccepted {
                        phase: vote.phase.clone(),
                        candidate_id: vote.block_id.clone(),
                    }));
                }
            }
            TypedConsensusMessage::CoreProposal { .. }
            | TypedConsensusMessage::Proposal { .. }
            | TypedConsensusMessage::ValidationCertificate { .. }
            | TypedConsensusMessage::TimeoutCertificate { .. }
            | TypedConsensusMessage::QuorumCertificate { .. }
            | TypedConsensusMessage::PreparedCertificateRequest { .. }
            | TypedConsensusMessage::PreparedCertificateResponse { .. }
            | TypedConsensusMessage::FinalityCheckpointRequest { .. }
            | TypedConsensusMessage::FinalityCheckpoint { .. } => {}
        }
        Ok(None)
    }

    /// Requests the exact next missing finalized height after bounded lack of
    /// progress. The core-only launch runtime can replay its deterministic
    /// blocks and QCs safely; a future ETDAG epoch must provide equivalent
    /// protected-input recovery before it enables this path.
    fn request_finality_recovery_if_stalled(&mut self, now: Instant) -> Result<(), String> {
        if self.etdag_is_active()
            || now
                .checked_duration_since(self.last_finality_progress_at)
                .map(|elapsed| elapsed < FINALITY_RECOVERY_REQUEST_INTERVAL)
                .unwrap_or(true)
        {
            return Ok(());
        }
        if self
            .last_finality_recovery_request_at
            .and_then(|last| now.checked_duration_since(last))
            .map(|elapsed| elapsed < FINALITY_RECOVERY_REQUEST_INTERVAL)
            .unwrap_or(false)
        {
            return Ok(());
        }
        let next_height = self
            .coordinator
            .local_context
            .latest_finalized_height
            .0
            .saturating_add(1);
        self.broadcast(TypedConsensusMessage::FinalityCheckpointRequest {
            next_height: crate::synergy_types::Height(next_height),
        })?;
        self.last_finality_recovery_request_at = Some(now);
        Ok(())
    }

    fn request_prepared_certificate(
        &mut self,
        timeout_certificate: &TimeoutCertificate,
    ) -> Result<(), String> {
        self.broadcast(TypedConsensusMessage::PreparedCertificateRequest {
            timeout_certificate: timeout_certificate.clone(),
        })
    }

    fn respond_to_prepared_certificate_request(
        &mut self,
        timeout_certificate: TimeoutCertificate,
    ) -> Result<(), String> {
        self.coordinator.consensus.verify_tc(
            &timeout_certificate,
            &self.coordinator.local_context.height_context,
        )?;
        let Some(candidate_id) = timeout_certificate.carry_forward_candidate_id.as_ref() else {
            return Err("prepared recovery request TC carries no candidate".to_string());
        };
        let Some(validation_certificate) = self.prepared_certificate.as_ref() else {
            return Ok(());
        };
        if validation_certificate.candidate_id != *candidate_id
            || timeout_certificate.highest_prepared_vc_root != Some(validation_certificate.root()?)
        {
            return Ok(());
        }
        let Some(block) = self
            .coordinator
            .accepted_proposals
            .get(candidate_id)
            .cloned()
        else {
            return Ok(());
        };
        self.broadcast(TypedConsensusMessage::PreparedCertificateResponse {
            timeout_certificate,
            block,
            validation_certificate: validation_certificate.clone(),
        })
    }

    /// Returns only persisted records, which have already passed structural
    /// continuity checks. The recipient independently re-verifies all crypto,
    /// execution, and successor-context rules before accepting them.
    fn respond_to_finality_checkpoint_request(
        &mut self,
        next_height: crate::synergy_types::Height,
    ) -> Result<(), String> {
        if self.etdag_is_active() {
            return Err(
                "typed finality checkpoint recovery is unavailable after ETDAG activation"
                    .to_string(),
            );
        }
        let records = self
            .coordinator
            .finality_store
            .recover()?
            .into_iter()
            .filter(|record| record.height.0 >= next_height.0)
            .take(MAX_TYPED_FINALITY_CHECKPOINT_RECORDS)
            .collect::<Vec<_>>();
        if !records.is_empty() {
            self.broadcast(TypedConsensusMessage::FinalityCheckpoint { records })?;
        }
        Ok(())
    }

    /// Replays a peer checkpoint through the normal core proposal, QC,
    /// execution, durable-persistence, and successor-authority path. A
    /// redundant matching prefix is harmless; a fork, gap, or rewrite is a
    /// source conflict and fails closed.
    fn import_finality_checkpoint(
        &mut self,
        records: Vec<TypedFinalityRecord>,
    ) -> Result<usize, String> {
        if self.etdag_is_active() {
            return Err(
                "typed finality checkpoint recovery is unavailable after ETDAG activation"
                    .to_string(),
            );
        }
        if records.is_empty() || records.len() > MAX_TYPED_FINALITY_CHECKPOINT_RECORDS {
            return Err("typed finality checkpoint has an invalid record count".to_string());
        }
        let persisted = self.coordinator.finality_store.recover()?;
        let mut imported = 0usize;
        for supplied in records {
            let local_height = self.coordinator.local_context.latest_finalized_height.0;
            if supplied.height.0 <= local_height {
                let index =
                    supplied.height.0.checked_sub(1).ok_or_else(|| {
                        "typed finality checkpoint contains a zero height".to_string()
                    })? as usize;
                let existing = persisted.get(index).ok_or_else(|| {
                    "typed finality checkpoint claims a local height absent from durable state"
                        .to_string()
                })?;
                if !same_typed_finality_record_subject(existing, &supplied)? {
                    return Err(
                        "TYPED_DRIVER_SOURCE_CONFLICT: typed finality checkpoint conflicts with durable finality"
                            .to_string(),
                    );
                }
                continue;
            }
            if supplied.height.0 != local_height.saturating_add(1) {
                return Err(
                    "typed finality checkpoint is not an exact successor of the local durable tip"
                        .to_string(),
                );
            }
            let finalized_context = self.coordinator.local_context.height_context.clone();
            match self.coordinator.accept_finalized_core_proposal(
                supplied.block.clone(),
                &supplied.quorum_certificate,
            )? {
                TypedCoordinatorEvent::ProposalAccepted { .. } => {}
                _ => {
                    return Err(
                        "typed finality checkpoint core proposal produced an unexpected event"
                            .to_string(),
                    )
                }
            }
            let accepted = match self
                .coordinator
                .accept_finality_certificate(supplied.quorum_certificate.clone())?
            {
                TypedCoordinatorEvent::Finalized { record } => record,
                _ => {
                    return Err("typed finality checkpoint QC did not produce finality".to_string())
                }
            };
            if accepted != supplied {
                return Err(
                    "TYPED_DRIVER_SOURCE_CONFLICT: typed finality checkpoint replay differs from supplied evidence"
                        .to_string(),
                );
            }
            self.finalize_after_verified_qc(
                supplied.quorum_certificate,
                finalized_context,
                accepted,
            )?;
            imported = imported.saturating_add(1);
        }
        if imported > 0 {
            self.last_finality_progress_at = Instant::now();
            self.last_finality_recovery_request_at = None;
        }
        Ok(imported)
    }

    fn advance_healthy_path(&mut self, now: Instant) -> Result<(), String> {
        if self.stage == TypedRoundStage::Proposal {
            if let Some(block) = self.current_round_proposal().cloned() {
                self.emit_validation_vote(&block, now)?;
                self.transition_stage(TypedRoundStage::Validation, now);
            }
        }

        if self.stage == TypedRoundStage::Validation {
            let prepared = self.prepared_certificate.clone();
            let prepared_block = prepared.as_ref().and_then(|certificate| {
                self.coordinator
                    .accepted_proposals
                    .get(&certificate.candidate_id)
                    .filter(|block| {
                        block.header.round == self.coordinator.local_context.round
                            && certificate.round.0 <= block.header.round.0
                    })
                    .cloned()
            });
            if let (Some(block), Some(certificate)) = (prepared_block, prepared) {
                let height = self.coordinator.local_context.height_context.height;
                let round = self.coordinator.local_context.round;
                self.emit_finality_vote(&block, &certificate, now)?;
                // The local vote can itself complete the QC and reset the
                // driver for the successor height. Do not overwrite that
                // reset with the prior height's Finality stage.
                if self.coordinator.local_context.height_context.height == height
                    && self.coordinator.local_context.round == round
                {
                    self.transition_stage(TypedRoundStage::Finality, now);
                }
            }
        }
        Ok(())
    }

    fn try_emit_scheduled_proposal(&mut self) -> Result<(), String> {
        let scheduled = self.coordinator.consensus.proposer_for(
            &self.coordinator.local_context.height_context,
            self.coordinator.local_context.round,
        )?;
        if scheduled.validator_id != self.coordinator.local_validator_id {
            return Ok(());
        }

        // Re-broadcast the exact proposal already accepted for this
        // height/round. This remains necessary after the local node advances
        // to Validation or Finality because a remote mailbox can come online
        // after the first healthy-path broadcast.
        if let Some(block) = self.current_round_proposal().cloned() {
            increment_typed_metric(
                |snapshot| &mut snapshot.rebroadcasts,
                if self.etdag_is_active() {
                    "proposal"
                } else {
                    "core_proposal"
                },
            );
            if self.etdag_is_active() {
                let candidate_id = block.candidate_id()?;
                let (target_context, protected_block) = self
                    .proposal_material
                    .get(&candidate_id)
                    .cloned()
                    .ok_or_else(|| {
                        "typed protected proposal has no retained certified input material"
                            .to_string()
                    })?;
                return self.broadcast_proposal(target_context, protected_block, block);
            }
            return self.broadcast_core_proposal(block);
        }

        if let Some(timeout_certificate) = self.timeout_certificate.clone() {
            if let Some(candidate_id) = timeout_certificate.carry_forward_candidate_id.clone() {
                // A timeout certificate carries forward the highest prepared
                // candidate across the whole timeout quorum. This node may
                // legitimately be unable to reconstruct that candidate: it may
                // never have observed that validation certificate, it may have
                // prepared a different candidate in the same round, it may not
                // hold the proposal body, or it may have lost in-memory prepared
                // state across a restart. None of those is evidence of a fault.
                //
                // The carry-forward rule forbids proposing anything other than
                // the carried candidate, so the only correct action is to not
                // propose this round and let it time out; another scheduled
                // proposer that does hold the material will carry it forward.
                // Treating these gaps as TYPED_DRIVER_SOURCE_CONFLICT killed the
                // process on an ordinary liveness gap and stalled the chain.
                let Some(certificate) = self.prepared_certificate.clone() else {
                    self.request_prepared_certificate(&timeout_certificate)?;
                    return Ok(());
                };
                if certificate.candidate_id != candidate_id {
                    self.request_prepared_certificate(&timeout_certificate)?;
                    return Ok(());
                }
                if timeout_certificate.highest_prepared_vc_root != Some(certificate.root()?) {
                    // A candidate can have more than one valid strict-quorum
                    // VC proof (different signer subsets). The TC binds the
                    // exact proof root, so a locally held VC for the same
                    // candidate is insufficient authority for carry-forward.
                    // Recover the exact proof instead of treating this normal
                    // quorum-subset difference as a fatal protocol conflict.
                    self.request_prepared_certificate(&timeout_certificate)?;
                    return Ok(());
                }
                let Some(original) = self
                    .coordinator
                    .accepted_proposals
                    .get(&candidate_id)
                    .cloned()
                else {
                    self.request_prepared_certificate(&timeout_certificate)?;
                    return Ok(());
                };
                let carried = self.coordinator.carry_forward_prepared_block(
                    &original,
                    &certificate,
                    &timeout_certificate,
                )?;
                if self.etdag_is_active() {
                    // Same liveness gap as above: missing local ETDAG material
                    // means this node cannot propose the carried candidate, not
                    // that the network is faulty.
                    let Some((target_context, protected_block)) =
                        self.proposal_material.get(&candidate_id).cloned()
                    else {
                        return Ok(());
                    };
                    self.broadcast_proposal(target_context, protected_block, carried)?;
                } else {
                    self.broadcast_core_proposal(carried)?;
                }
                return Ok(());
            }
        }

        if !self.etdag_is_active() {
            // P2P may be up before a remote process has installed its typed
            // mailbox. Re-broadcast the exact, already signed core proposal
            // until the first proposal deadline; never create a second
            // candidate for the same height and round.
            let block = self
                .current_round_proposal()
                .cloned()
                .map(Ok)
                .unwrap_or_else(|| self.coordinator.propose_core_block())?;
            return self.broadcast_core_proposal(block);
        }

        let height_context = self.coordinator.local_context.height_context.clone();
        let expected_finality_context = self
            .finality_digest_source
            .expected_digest(&self.coordinator.local_context)?;
        expected_finality_context.validate("typed scheduler finality context digest")?;
        if expected_finality_context.is_zero() {
            return Err("typed scheduler finality context digest is empty".to_string());
        }
        let target_context = self
            .protected_inputs
            .load_verified_target_admission_context(
                &height_context,
                &self.coordinator.consensus.verifier,
                &self.coordinator.consensus.validator_set,
                &self.coordinator.consensus.cluster_map,
                &self.coordinator.consensus.protocol_config,
            )?;
        let protected_block = self.protected_inputs.load_ready_protected_input(
            &height_context,
            &expected_finality_context,
            &self.coordinator.consensus.verifier,
            &self.coordinator.consensus.validator_set,
            &self.coordinator.consensus.cluster_map,
            &self.coordinator.consensus.protocol_config,
            &self.coordinator.etdag_parameters,
        )?;
        let block = self
            .coordinator
            .propose_protected_block(&protected_block, &target_context)?;
        self.broadcast_proposal(target_context, protected_block, block)
    }

    fn broadcast_core_proposal(&mut self, block: Block) -> Result<(), String> {
        if !block.transactions.is_empty()
            || block.header.tx_count != 0
            || block.header.protected_batch.is_some()
        {
            return Err("refusing to broadcast a non-empty core-only typed proposal".to_string());
        }
        self.broadcast(TypedConsensusMessage::CoreProposal {
            height_context: self.coordinator.local_context.height_context.clone(),
            block,
        })?;
        self.metrics.emitted_proposals = self.metrics.emitted_proposals.saturating_add(1);
        Ok(())
    }

    fn broadcast_proposal(
        &mut self,
        target_context: TargetAdmissionContext,
        protected_block: ProtectedBlockInput,
        block: Block,
    ) -> Result<(), String> {
        let candidate_id = block.candidate_id()?;
        self.record_proposal_material(
            &candidate_id,
            target_context.clone(),
            protected_block.clone(),
            &block,
        )?;
        self.broadcast(TypedConsensusMessage::Proposal {
            height_context: self.coordinator.local_context.height_context.clone(),
            target_context,
            protected_block,
            block,
        })?;
        self.metrics.emitted_proposals = self.metrics.emitted_proposals.saturating_add(1);
        Ok(())
    }

    fn emit_validation_vote(&mut self, block: &Block, now: Instant) -> Result<(), String> {
        if self.emitted_validation_vote {
            return Ok(());
        }
        let vote = self.coordinator.validation_vote_for(block)?;
        self.broadcast(TypedConsensusMessage::Vote { vote: vote.clone() })?;
        self.local_vote_rebroadcasts.push((vote.clone(), now));
        self.emitted_validation_vote = true;
        self.metrics.emitted_validation_votes =
            self.metrics.emitted_validation_votes.saturating_add(1);
        self.record_verified_vote(vote)
    }

    fn emit_finality_vote(
        &mut self,
        block: &Block,
        certificate: &ValidationCertificate,
        now: Instant,
    ) -> Result<(), String> {
        if self.emitted_finality_vote {
            return Ok(());
        }
        let vote = self.coordinator.finality_vote_for(block, certificate)?;
        self.broadcast(TypedConsensusMessage::Vote { vote: vote.clone() })?;
        // A verified VC proves that a strict quorum already received and
        // validated the proposal. Continuing to flood validation votes after
        // entering Finality only delays the finality votes that matter now.
        self.local_vote_rebroadcasts
            .retain(|(local, _)| local.phase != VotePhase::Validate);
        self.local_vote_rebroadcasts.push((vote.clone(), now));
        self.emitted_finality_vote = true;
        self.metrics.emitted_finality_votes = self.metrics.emitted_finality_votes.saturating_add(1);
        self.record_verified_vote(vote)
    }

    fn emit_timeout_vote(&mut self, now: Instant) -> Result<(), String> {
        if self.emitted_timeout_vote {
            return Ok(());
        }
        let vote = self
            .coordinator
            .timeout_vote(self.prepared_certificate.as_ref())?;
        self.broadcast(TypedConsensusMessage::Vote { vote: vote.clone() })?;
        // Once the round times out, only the timeout vote can advance it.
        self.local_vote_rebroadcasts.clear();
        self.local_vote_rebroadcasts.push((vote.clone(), now));
        self.emitted_timeout_vote = true;
        self.metrics.emitted_timeout_votes = self.metrics.emitted_timeout_votes.saturating_add(1);
        self.record_verified_vote(vote)
    }

    fn rebroadcast_local_vote_if_due(&mut self, now: Instant) -> Result<(), String> {
        let due = self
            .local_vote_rebroadcasts
            .iter()
            .enumerate()
            .filter_map(|(index, (_, last_broadcast))| {
                now.checked_duration_since(*last_broadcast)
                    .filter(|elapsed| *elapsed >= VOTE_REBROADCAST_INTERVAL)
                    .map(|_| index)
            })
            .collect::<Vec<_>>();
        for index in due {
            let vote = self.local_vote_rebroadcasts[index].0.clone();
            increment_typed_metric(
                |snapshot| &mut snapshot.rebroadcasts,
                typed_message_kind(&TypedConsensusMessage::Vote { vote: vote.clone() }),
            );
            self.broadcast(TypedConsensusMessage::Vote { vote })?;
            self.local_vote_rebroadcasts[index].1 = now;
        }
        Ok(())
    }

    fn broadcast(&mut self, message: TypedConsensusMessage) -> Result<(), String> {
        let delivered = self.egress.broadcast(&message)?;
        if delivered == 0 {
            return Err(
                "typed PoSy transport delivered to zero authenticated validator peers".to_string(),
            );
        }
        Ok(())
    }
}

impl<E, D, H, R> TypedPosyDriver<E, D, H, R>
where
    E: TypedConsensusEgress,
    D: TypedFinalityContextDigestSource,
    H: TypedNextHeightContextSource,
    R: TypedEtdagIngressRotator,
{
    fn current_round_proposal(&self) -> Option<&Block> {
        self.coordinator
            .accepted_proposals
            .values()
            .find(|block| block.header.round == self.coordinator.local_context.round)
    }

    fn record_proposal_material(
        &mut self,
        candidate_id: &BlockId,
        target_context: TargetAdmissionContext,
        protected_block: ProtectedBlockInput,
        block: &Block,
    ) -> Result<(), String> {
        if block.candidate_id()? != *candidate_id {
            return Err("typed proposal material does not match its candidate ID".to_string());
        }
        if let Some((existing_context, existing_protected)) =
            self.proposal_material.get(candidate_id)
        {
            if existing_context != &target_context || existing_protected != &protected_block {
                return Err(
                    "TYPED_DRIVER_SOURCE_CONFLICT: stable candidate maps to conflicting verified ETDAG material"
                        .to_string(),
                );
            }
            return Ok(());
        }
        self.proposal_material
            .insert(candidate_id.clone(), (target_context, protected_block));
        Ok(())
    }

    fn record_verified_vote(&mut self, vote: Vote) -> Result<(), String> {
        let context = &self.coordinator.local_context.height_context;
        if vote.phase == VotePhase::Timeout
            && vote.height == context.height
            && vote.epoch == context.epoch
            && vote.cluster_id == context.assigned_cluster_id
            && vote.height_context_root == context.root()?
            && self
                .timeout_certificate
                .as_ref()
                .is_some_and(|certificate| certificate.closing_round == vote.round)
            && vote.round.0 < self.coordinator.local_context.round.0
        {
            // Another replica may form and broadcast the TC before every
            // authenticated timeout vote reaches this process.  Once that
            // exact round transition is cryptographically installed, a late
            // individually verified vote for its closing round is redundant,
            // not conflicting current-round input.
            return Ok(());
        }
        if vote.height != context.height
            || vote.round != self.coordinator.local_context.round
            || vote.epoch != context.epoch
            || vote.cluster_id != context.assigned_cluster_id
            || vote.height_context_root != context.root()?
        {
            return Err("typed vote is not for the current local height/round context".to_string());
        }
        let phase = vote.phase.clone();
        let observations = match phase {
            VotePhase::Validate => &mut self.observed_validation_votes,
            VotePhase::Finality => &mut self.observed_finality_votes,
            VotePhase::Timeout => &mut self.observed_timeout_votes,
        };
        if let Some(existing) = observations.get(&vote.validator_id) {
            if existing.consensus_subject()? != vote.consensus_subject()? {
                return Err(
                    "TYPED_DRIVER_SOURCE_CONFLICT: validator supplied conflicting votes for one height/round/phase"
                        .to_string(),
                );
            }
            return Ok(());
        }
        observations.insert(vote.validator_id.clone(), vote.clone());
        let verified_vote = VerifiedVote::from_coordinator_acceptance(vote.clone())?;

        match phase {
            VotePhase::Validate => {
                if !self
                    .coordinator
                    .accepted_proposals
                    .contains_key(&vote.block_id)
                {
                    return Err(
                        "typed validation vote has no locally validated proposal".to_string()
                    );
                }
                insert_distinct_verified_vote(
                    self.validation_votes
                        .entry(vote.block_id.clone())
                        .or_default(),
                    verified_vote,
                )?;
                self.maybe_form_validation_certificate(&vote.block_id)
            }
            VotePhase::Finality => {
                if !self
                    .coordinator
                    .accepted_proposals
                    .contains_key(&vote.block_id)
                {
                    return Err("typed finality vote has no locally validated proposal".to_string());
                }
                let prepared = self.prepared_certificate.as_ref().ok_or_else(|| {
                    "typed finality vote arrived before a matching validation certificate"
                        .to_string()
                })?;
                if prepared.candidate_id != vote.block_id {
                    return Err(
                        "TYPED_DRIVER_SOURCE_CONFLICT: finality vote conflicts with the prepared candidate"
                            .to_string(),
                    );
                }
                insert_distinct_verified_vote(
                    self.finality_votes
                        .entry(vote.block_id.clone())
                        .or_default(),
                    verified_vote,
                )?;
                self.maybe_form_finality_certificate(&vote.block_id)
            }
            VotePhase::Timeout => {
                insert_distinct_verified_vote(&mut self.timeout_votes, verified_vote)?;
                self.maybe_form_timeout_certificate()
            }
        }
    }

    fn maybe_form_validation_certificate(&mut self, candidate_id: &BlockId) -> Result<(), String> {
        let votes = self
            .validation_votes
            .get(candidate_id)
            .ok_or_else(|| "typed validation vote collector disappeared".to_string())?
            .values()
            .cloned()
            .collect::<Vec<_>>();
        if !self.has_exact_quorum(&votes)? {
            return Ok(());
        }
        let certificate = self
            .coordinator
            .form_validation_certificate_from_verified(&votes)?;
        self.broadcast(TypedConsensusMessage::ValidationCertificate {
            certificate: certificate.clone(),
        })?;
        self.metrics.emitted_validation_certificates = self
            .metrics
            .emitted_validation_certificates
            .saturating_add(1);
        self.record_validation_certificate(certificate)
    }

    fn maybe_form_finality_certificate(&mut self, candidate_id: &BlockId) -> Result<(), String> {
        if self.finality_certificate.is_some() {
            return Ok(());
        }
        let votes = self
            .finality_votes
            .get(candidate_id)
            .ok_or_else(|| "typed finality vote collector disappeared".to_string())?
            .values()
            .cloned()
            .collect::<Vec<_>>();
        if !self.has_exact_quorum(&votes)? {
            return Ok(());
        }
        let certificate = self
            .coordinator
            .form_finality_certificate_from_verified(&votes)?;
        let finalized_context = self.coordinator.local_context.height_context.clone();
        self.broadcast(TypedConsensusMessage::QuorumCertificate {
            certificate: certificate.clone(),
        })?;
        self.metrics.emitted_finality_certificates =
            self.metrics.emitted_finality_certificates.saturating_add(1);
        let record = match self
            .coordinator
            .accept_finality_certificate(certificate.clone())?
        {
            TypedCoordinatorEvent::Finalized { record } => record,
            _ => return Err("local finality QC did not produce typed finality".to_string()),
        };
        self.finalize_after_verified_qc(certificate, finalized_context, record)
    }

    fn maybe_form_timeout_certificate(&mut self) -> Result<(), String> {
        let votes = self.timeout_votes.values().cloned().collect::<Vec<_>>();
        if !self.has_exact_quorum(&votes)? {
            return Ok(());
        }
        let certificate = self
            .coordinator
            .form_timeout_certificate_from_verified(&votes)?;
        self.broadcast(TypedConsensusMessage::TimeoutCertificate {
            certificate: certificate.clone(),
        })?;
        self.metrics.emitted_timeout_certificates =
            self.metrics.emitted_timeout_certificates.saturating_add(1);
        match self
            .coordinator
            .accept_timeout_certificate(certificate.clone())?
        {
            TypedCoordinatorEvent::TimeoutCertificateAccepted { .. } => {
                self.install_verified_timeout_certificate(certificate)
            }
            _ => Err("local timeout certificate did not advance the typed round".to_string()),
        }
    }

    fn has_exact_quorum(&self, votes: &[VerifiedVote]) -> Result<bool, String> {
        let context = &self.coordinator.local_context.height_context;
        if (votes.len() as u64) < context.strict_count_quorum()? {
            return Ok(false);
        }
        let signed_weight = votes.iter().try_fold(0u64, |total, vote| {
            let validator = self
                .coordinator
                .consensus
                .validator_set
                .validators
                .iter()
                .find(|validator| validator.validator_id == vote.validator_id)
                .ok_or_else(|| {
                    "verified vote signer disappeared from frozen validator set".to_string()
                })?;
            total
                .checked_add(validator.voting_weight)
                .ok_or_else(|| "typed vote signed-weight overflow".to_string())
        })?;
        Ok(signed_weight >= context.strict_weight_quorum()?)
    }

    fn record_validation_certificate(
        &mut self,
        certificate: ValidationCertificate,
    ) -> Result<(), String> {
        let Some(accepted_proposal) = self
            .coordinator
            .accepted_proposals
            .get(&certificate.candidate_id)
        else {
            return Err(
                "typed validation certificate has no locally validated proposal".to_string(),
            );
        };
        if certificate.round.0 > accepted_proposal.header.round.0 {
            if let Some(existing) = self
                .pending_validation_certificates
                .get(&certificate.candidate_id)
            {
                if certificate.round == existing.round {
                    if !same_validation_certificate_subject(existing, &certificate) {
                        return Err(
                            "TYPED_DRIVER_SOURCE_CONFLICT: pending validation certificates disagree on the certified candidate"
                                .to_string(),
                        );
                    }
                    if certificate.root()? < existing.root()? {
                        self.pending_validation_certificates
                            .insert(certificate.candidate_id.clone(), certificate);
                    }
                    return Ok(());
                }
                if certificate.round.0 < existing.round.0 {
                    return Ok(());
                }
            }
            // Authenticated P2P delivery can place a verified VC ahead of its
            // matching carried proposal envelope. Keep the highest verified
            // certificate pending instead of pairing it with an older round.
            self.pending_validation_certificates
                .insert(certificate.candidate_id.clone(), certificate);
            return Ok(());
        }
        // The prepared certificate is intentionally retained across a round
        // change by `install_verified_timeout_certificate`, because carry-forward
        // needs it. It follows that a later round legitimately produces a
        // *different* certified candidate whenever the timeout certificate
        // carried no candidate forward, and the driver must adopt the highest
        // prepared certificate rather than treat that as evidence of a fault.
        //
        // Comparing subjects without first comparing rounds made every ordinary
        // round change fatal: the node failed closed with
        // TYPED_DRIVER_SOURCE_CONFLICT, exited, and could not reproduce its
        // signing authorizations afterwards, which stalled Testnet-v3 at the
        // first round change on both the pre-reset and post-reset chains.
        //
        // Only two certificates for the *same* round are evidence of a fault.
        // This mirrors the round comparison `install_verified_timeout_certificate`
        // already performs for timeout certificates.
        if let Some(existing) = &self.prepared_certificate {
            if certificate.round == existing.round {
                if !same_validation_certificate_subject(existing, &certificate) {
                    return Err(
                        "TYPED_DRIVER_SOURCE_CONFLICT: validation certificates disagree on the certified candidate"
                            .to_string(),
                    );
                }
                if certificate.root()? < existing.root()? {
                    self.prepared_certificate = Some(certificate);
                    self.persist_prepared_if_complete()?;
                }
                return Ok(());
            }
            if certificate.round.0 < existing.round.0 {
                // A delayed certificate from an earlier round can no longer
                // describe the prepared candidate for the current round.
                return Ok(());
            }
        }
        let prepared_candidate = certificate.candidate_id.0.clone();
        self.prepared_certificate = Some(certificate);
        if let Ok(mut telemetry) = typed_consensus_telemetry().lock() {
            telemetry.snapshot.prepared_height =
                self.coordinator.local_context.height_context.height.0;
            telemetry.snapshot.prepared_candidate = prepared_candidate;
            telemetry.snapshot.prepared_round = self
                .prepared_certificate
                .as_ref()
                .map(|prepared| prepared.round.0)
                .unwrap_or_default();
        }
        self.persist_prepared_if_complete()?;
        Ok(())
    }

    fn install_pending_validation_certificate(
        &mut self,
        candidate_id: &BlockId,
        proposal_round: crate::synergy_types::Round,
    ) -> Result<(), String> {
        let Some(certificate) = self
            .pending_validation_certificates
            .get(candidate_id)
            .filter(|certificate| certificate.round.0 <= proposal_round.0)
            .cloned()
        else {
            return Ok(());
        };
        self.pending_validation_certificates.remove(candidate_id);
        self.record_validation_certificate(certificate)
    }

    fn persist_prepared_if_complete(&mut self) -> Result<(), String> {
        let Some(certificate) = self.prepared_certificate.as_ref() else {
            return Ok(());
        };
        let Some(block) = self
            .coordinator
            .accepted_proposals
            .get(&certificate.candidate_id)
        else {
            return Ok(());
        };
        let timeout_certificate =
            if let Some(timeout_certificate) = self.timeout_certificate.as_ref() {
                let carries_prepared = timeout_certificate.carry_forward_candidate_id.as_ref()
                    == Some(&certificate.candidate_id)
                    && timeout_certificate.highest_prepared_vc_root == Some(certificate.root()?);
                let authorizes_prepared_round =
                    timeout_certificate.carry_forward_candidate_id.is_none()
                        && timeout_certificate.highest_prepared_vc_root.is_none()
                        && timeout_certificate.next_round == block.header.round
                        && certificate.round == block.header.round;
                if !carries_prepared && !authorizes_prepared_round {
                    // Do not overwrite a valid durable prepared record by
                    // combining it with an unrelated later TC. This occurs when
                    // the TC selected another valid VC proof root for the same
                    // candidate, or when a no-carry TC supersedes a locally known
                    // prior-round VC. Exact prepared-certificate recovery will
                    // replace the record once matching authority is available.
                    return Ok(());
                }
                Some(timeout_certificate)
            } else {
                None
            };
        self.prepared_store
            .persist_verified(block, certificate, timeout_certificate)?;
        self.commit_atomic_recovery_checkpoint()?;
        Ok(())
    }

    fn install_recovered_prepared_record(
        &mut self,
        record: TypedPreparedRecord,
        persist: bool,
    ) -> Result<BlockId, String> {
        let current_height = self.coordinator.local_context.height_context.height;
        if record.height.0 <= self.coordinator.local_context.latest_finalized_height.0 {
            self.prepared_store
                .clear_after_finality(self.coordinator.local_context.latest_finalized_height)?;
            return Err("typed prepared recovery record is already finalized".to_string());
        }
        if record.height != current_height
            || record.height_context_root != self.coordinator.local_context.height_context.root()?
        {
            return Err(
                "typed prepared recovery record is not for the active height context".to_string(),
            );
        }
        let candidate_id = if let Some(timeout_certificate) = record.timeout_certificate.as_ref() {
            self.coordinator.recover_core_prepared(
                record.block.clone(),
                &record.validation_certificate,
                timeout_certificate,
            )?
        } else {
            self.coordinator.consensus.verify_vc(
                &record.validation_certificate,
                &self.coordinator.local_context.height_context,
            )?;
            if record.validation_certificate.candidate_id != record.block.candidate_id()? {
                return Err("typed prepared recovery VC does not certify its proposal".to_string());
            }
            match self.coordinator.accept_core_proposal(
                self.coordinator.local_context.height_context.clone(),
                record.block.clone(),
            )? {
                TypedCoordinatorEvent::ProposalAccepted { candidate_id } => candidate_id,
                _ => {
                    return Err(
                        "typed prepared recovery proposal produced an unexpected event".to_string(),
                    )
                }
            }
        };
        if persist {
            self.prepared_store.persist_verified(
                &record.block,
                &record.validation_certificate,
                record.timeout_certificate.as_ref(),
            )?;
        }
        self.prepared_certificate = Some(record.validation_certificate);
        self.timeout_certificate = record.timeout_certificate;
        self.stage = if self.timeout_certificate.is_some() {
            TypedRoundStage::Proposal
        } else {
            TypedRoundStage::Validation
        };
        self.round_started_at = Instant::now();
        self.stage_started_at = self.round_started_at;
        self.last_proposal_broadcast_at = None;
        self.local_vote_rebroadcasts.clear();
        self.emitted_proposal = false;
        self.emitted_validation_vote = false;
        self.emitted_finality_vote = false;
        self.emitted_timeout_vote = false;
        self.commit_atomic_recovery_checkpoint()?;
        Ok(candidate_id)
    }

    fn finalize_after_verified_qc(
        &mut self,
        certificate: QuorumCertificate,
        finalized_context: crate::synergy_types::HeightConsensusContext,
        record: TypedFinalityRecord,
    ) -> Result<(), String> {
        if let Some(existing) = &self.finality_certificate {
            if !same_quorum_certificate_subject(existing, &certificate) {
                return Err(
                    "TYPED_DRIVER_SOURCE_CONFLICT: finality certificates disagree on the certified candidate"
                        .to_string(),
                );
            }
        }
        self.finality_certificate = Some(certificate.clone());
        self.last_finality_progress_at = Instant::now();
        self.last_finality_recovery_request_at = None;
        self.protected_inputs.prune_finalized_input(
            &certificate,
            &finalized_context,
            &self.coordinator.consensus.verifier,
            &self.coordinator.consensus.validator_set,
            &self.coordinator.consensus.cluster_map,
        )?;
        let next_authority = self
            .next_height_source
            .next_authority(&record, &self.coordinator.local_context)?;
        match next_authority {
            TypedNextHeightAuthority::UnchangedTopology { context } => {
                if self
                    .coordinator
                    .finality_store
                    .epoch_transition_for_finality(&record)?
                    .is_some()
                {
                    return Err(
                        "TYPED_DRIVER_SOURCE_CONFLICT: persisted epoch transition requires a verified topology installation payload"
                            .to_string(),
                    );
                }
                self.coordinator.advance_to_next_height(context)?;
            }
            TypedNextHeightAuthority::VerifiedEpochTransition {
                transition,
                next_validator_set,
                next_cluster_map,
                context,
            } => {
                let persisted = self
                    .coordinator
                    .finality_store
                    .epoch_transition_for_finality(&record)?
                    .ok_or_else(|| {
                        "TYPED_DRIVER_SOURCE_CONFLICT: epoch topology installation lacks a persisted verified transition"
                            .to_string()
                    })?;
                if persisted != transition {
                    return Err(
                        "TYPED_DRIVER_SOURCE_CONFLICT: epoch topology installation does not match the persisted verified transition"
                            .to_string(),
                    );
                }
                self.coordinator.apply_verified_epoch_transition(
                    &transition.transition,
                    next_validator_set,
                    next_cluster_map,
                    context,
                )?;
            }
        }
        // The coordinator has now durably accepted the QC and installed the
        // exact successor authority.  Only at this point may P2P certified
        // ETDAG input move to the successor context.  A rotator failure is
        // fatal to the driver, preventing a validator from signing a new
        // height while network ingress remains bound to the old one.
        let successor_context = self.coordinator.local_context().clone();
        let successor_finality_digest = self
            .finality_digest_source
            .expected_digest(&successor_context)?;
        let successor_authority = self.coordinator.etdag_ingress_authority();
        self.ingress_rotator.rotate_successor(
            &self.protected_inputs,
            &successor_authority,
            &successor_finality_digest,
        )?;
        self.metrics.finalized_blocks = self.metrics.finalized_blocks.saturating_add(1);
        if let Some(elapsed) = Instant::now().checked_duration_since(self.stage_started_at) {
            record_typed_phase_duration(self.stage, elapsed);
        }
        record_typed_finality(record.height.0, &record.block_id, certificate.round.0);
        self.prepared_store.clear_after_finality(record.height)?;
        self.reset_for_new_height();
        self.commit_atomic_recovery_checkpoint()?;
        Ok(())
    }

    fn install_verified_timeout_certificate(
        &mut self,
        certificate: TimeoutCertificate,
    ) -> Result<(), String> {
        if let Some(existing) = self.timeout_certificate.clone() {
            if certificate.closing_round == existing.closing_round {
                if !same_timeout_transition_context(&existing, &certificate) {
                    return Err("TYPED_DRIVER_SOURCE_CONFLICT: timeout certificates disagree on the consensus transition context".to_string());
                }
                match (
                    existing.carry_forward_candidate_id.as_ref(),
                    certificate.carry_forward_candidate_id.as_ref(),
                ) {
                    (Some(existing_candidate), Some(incoming_candidate))
                        if existing_candidate != incoming_candidate =>
                    {
                        return Err(
                            "TYPED_DRIVER_SOURCE_CONFLICT: timeout certificates carry different prepared candidates"
                                .to_string(),
                        );
                    }
                    (Some(_), None) => {
                        // A timeout proof may be assembled from any valid
                        // strict-quorum subset. One subset can omit the sole
                        // prepared report that another subset includes, and
                        // the same candidate can be reported with different
                        // valid VC proof roots. Neither changes the closed
                        // round. Retain the stronger already-installed carry
                        // requirement.
                        return Ok(());
                    }
                    (None, None) => {
                        // Deterministically retain one evidence representation
                        // so arrival order cannot choose the durable TC.
                        if certificate.root()? < existing.root()? {
                            self.timeout_certificate = Some(certificate);
                            self.persist_prepared_if_complete()?;
                        }
                        return Ok(());
                    }
                    (Some(_), Some(_)) => {
                        let existing_prepared_root = existing.highest_prepared_vc_root;
                        let incoming_prepared_root = certificate.highest_prepared_vc_root;
                        let local_prepared_root = self
                            .prepared_certificate
                            .as_ref()
                            .map(ValidationCertificate::root)
                            .transpose()?;
                        let incoming_is_known_highest = incoming_prepared_root.is_some()
                            && incoming_prepared_root == local_prepared_root;
                        let existing_is_known_highest = existing_prepared_root.is_some()
                            && existing_prepared_root == local_prepared_root;
                        let select_incoming =
                            match (incoming_is_known_highest, existing_is_known_highest) {
                                (true, false) => true,
                                (false, true) => false,
                                _ => certificate.root()? < existing.root()?,
                            };
                        if select_incoming {
                            self.timeout_certificate = Some(certificate.clone());
                            self.persist_prepared_if_complete()?;
                            if incoming_prepared_root != local_prepared_root {
                                self.request_prepared_certificate(&certificate)?;
                            }
                        }
                        return Ok(());
                    }
                    (None, Some(_)) => {
                        // Upgrade a no-carry transition when another verified
                        // strict quorum proves a prepared candidate. The
                        // coordinator already advanced to `next_round`; replay
                        // the independently verified TC through recovery so
                        // the consensus core records the stronger carry rule.
                        let height_context = self.coordinator.local_context.height_context.clone();
                        self.coordinator
                            .consensus
                            .recover_round_after_tc(&certificate, &height_context)?;
                    }
                }
            }
            if certificate.closing_round.0 < existing.closing_round.0 {
                // The coordinator already cryptographically accepted this
                // delayed prior-round proof before the driver reaches this
                // point.  It can no longer authorize the current round, so it
                // must not overwrite the newer transition state.
                return Ok(());
            }
            if certificate.next_round != self.coordinator.local_context.round {
                return Err(
                    "TYPED_DRIVER_SOURCE_CONFLICT: timeout certificate was not installed by the coordinator"
                        .to_string(),
                );
            }
            // A restarted or temporarily disconnected replica can receive a
            // later strict-quorum TC without having observed every ephemeral
            // intermediate TC. `TypedPosyCoordinator::accept_timeout_certificate`
            // has already verified the certificate and recovered the local
            // round to its successor. Requiring adjacency to the driver's
            // last process-local TC made that valid recovery path fatal and
            // trapped the replica in a restart loop.
        }
        self.timeout_certificate = Some(certificate.clone());
        self.validation_votes.clear();
        self.finality_votes.clear();
        self.timeout_votes.clear();
        self.observed_validation_votes.clear();
        self.observed_finality_votes.clear();
        self.observed_timeout_votes.clear();
        self.round_started_at = Instant::now();
        self.stage_started_at = self.round_started_at;
        self.last_proposal_broadcast_at = None;
        self.local_vote_rebroadcasts.clear();
        self.stage = TypedRoundStage::Proposal;
        if let Ok(mut telemetry) = typed_consensus_telemetry().lock() {
            telemetry.snapshot.current_round = certificate.next_round.0;
        }
        self.emitted_proposal = false;
        self.emitted_validation_vote = false;
        self.emitted_finality_vote = false;
        self.emitted_timeout_vote = false;
        self.persist_prepared_if_complete()?;
        if certificate.carry_forward_candidate_id.is_some()
            && (self
                .prepared_certificate
                .as_ref()
                .map(|prepared| &prepared.candidate_id)
                != certificate.carry_forward_candidate_id.as_ref()
                || certificate
                    .carry_forward_candidate_id
                    .as_ref()
                    .and_then(|candidate| self.coordinator.accepted_proposals.get(candidate))
                    .is_none())
        {
            self.request_prepared_certificate(&certificate)?;
        }
        self.commit_atomic_recovery_checkpoint()?;
        Ok(())
    }

    fn reset_for_new_height(&mut self) {
        self.round_started_at = Instant::now();
        self.stage_started_at = self.round_started_at;
        self.last_proposal_broadcast_at = None;
        self.local_vote_rebroadcasts.clear();
        self.stage = TypedRoundStage::Proposal;
        self.emitted_proposal = false;
        self.emitted_validation_vote = false;
        self.emitted_finality_vote = false;
        self.emitted_timeout_vote = false;
        self.validation_votes.clear();
        self.finality_votes.clear();
        self.timeout_votes.clear();
        self.observed_validation_votes.clear();
        self.observed_finality_votes.clear();
        self.observed_timeout_votes.clear();
        self.prepared_certificate = None;
        self.pending_validation_certificates.clear();
        self.finality_certificate = None;
        self.timeout_certificate = None;
        self.proposal_material.clear();
        if let Ok(mut telemetry) = typed_consensus_telemetry().lock() {
            telemetry.snapshot.current_round = 0;
            telemetry.snapshot.current_height =
                self.coordinator.local_context.height_context.height.0;
            telemetry.snapshot.prepared_height = 0;
            telemetry.snapshot.prepared_candidate.clear();
            telemetry.snapshot.prepared_round = 0;
        }
    }

    fn transition_stage(&mut self, next: TypedRoundStage, now: Instant) {
        if self.stage != next {
            if let Some(elapsed) = now.checked_duration_since(self.stage_started_at) {
                record_typed_phase_duration(self.stage, elapsed);
            }
            self.stage = next;
            self.stage_started_at = now;
        }
    }

    fn commit_atomic_recovery_checkpoint(&self) -> Result<(), String> {
        let latest = self.coordinator.finality_store.latest()?;
        let (finalized_block, highest_qc) = latest
            .map(|record| (Some(record.block), Some(record.quorum_certificate)))
            .unwrap_or((None, None));
        let prepared_block = self.prepared_certificate.as_ref().and_then(|certificate| {
            self.coordinator
                .accepted_proposals
                .get(&certificate.candidate_id)
                .cloned()
        });
        let prepared_certificate = prepared_block
            .as_ref()
            .and(self.prepared_certificate.clone());
        let context = &self.coordinator.local_context;
        let highest_qc_height = highest_qc
            .as_ref()
            .map(|certificate| certificate.height.0)
            .unwrap_or_default();
        let highest_qc_block_id = highest_qc
            .as_ref()
            .map(|certificate| certificate.block_id.0.clone())
            .unwrap_or_default();
        let highest_qc_root = highest_qc
            .as_ref()
            .map(|certificate| certificate.root().map(|root| root.to_hex()))
            .transpose()?
            .unwrap_or_default();
        let highest_tc_round = self
            .timeout_certificate
            .as_ref()
            .map(|certificate| certificate.next_round.0)
            .unwrap_or_default();
        let highest_tc_root = self
            .timeout_certificate
            .as_ref()
            .map(|certificate| certificate.root().map(|root| root.to_hex()))
            .transpose()?
            .unwrap_or_default();
        self.coordinator
            .consensus
            .signing_authority
            .commit_recovery_checkpoint(&DurableConsensusRecoveryCheckpoint {
                checkpoint_version: 2,
                genesis_anchor: self.coordinator.finality_store.genesis_anchor(),
                chain_id: context.height_context.chain_id,
                chain_incarnation: crate::synergy_types::TESTNET_V3_CHAIN_INCARNATION,
                network_id: context.height_context.network_id.clone(),
                protocol_version: context.height_context.protocol_version.clone(),
                epoch: context.height_context.epoch,
                finalized_height: context.latest_finalized_height,
                finalized_block,
                highest_qc,
                current_height: context.height_context.height,
                current_round: context.round,
                height_context_root: context.height_context.root()?,
                active_validator_set_hash: context.height_context.active_validator_set_root,
                prepared_block,
                prepared_certificate,
                highest_tc: self.timeout_certificate.clone(),
            })?;
        if let Ok(mut telemetry) = typed_consensus_telemetry().lock() {
            telemetry.snapshot.highest_qc_height = highest_qc_height;
            telemetry.snapshot.highest_qc_block_id = highest_qc_block_id;
            telemetry.snapshot.highest_qc_root = highest_qc_root;
            telemetry.snapshot.highest_tc_round = highest_tc_round;
            telemetry.snapshot.highest_tc_root = highest_tc_root;
        }
        Ok(())
    }

    fn note_rejected_message(&mut self) {
        self.metrics.rejected_messages = self.metrics.rejected_messages.saturating_add(1);
    }
}

fn insert_distinct_verified_vote(
    votes: &mut BTreeMap<ValidatorId, VerifiedVote>,
    vote: VerifiedVote,
) -> Result<(), String> {
    if let Some(existing) = votes.get(&vote.validator_id) {
        if existing.subject_digest() != vote.subject_digest() {
            return Err(
                "TYPED_DRIVER_SOURCE_CONFLICT: validator supplied conflicting votes for one consensus phase"
                    .to_string(),
            );
        }
        return Ok(());
    }
    votes.insert(vote.validator_id.clone(), vote);
    Ok(())
}

/// A certificate proof may use any strict-quorum signer subset.  Its signer
/// bitmap, signatures, and signed weight therefore identify the evidence, not
/// a second consensus source.  Source conflicts are determined only by the
/// certified subject.
fn same_quorum_certificate_subject(left: &QuorumCertificate, right: &QuorumCertificate) -> bool {
    matches!(
        (left.consensus_subject(), right.consensus_subject()),
        (Ok(left_subject), Ok(right_subject))
            if left_subject == right_subject
                && left.qc_version == right.qc_version
                && left.active_validator_set_hash == right.active_validator_set_hash
                && left.cluster_map_hash == right.cluster_map_hash
                && left.threshold_weight_required == right.threshold_weight_required
    )
}

/// Finality evidence may contain different valid strict-quorum signer subsets
/// for one certified block. Durable evidence remains immutable on each node,
/// while replay accepts only the same block and deterministic QC subject so a
/// late proof cannot rewrite history or choose a different successor context.
fn same_typed_finality_record_subject(
    left: &TypedFinalityRecord,
    right: &TypedFinalityRecord,
) -> Result<bool, String> {
    Ok(left.height == right.height
        && left.block_id == right.block_id
        && left.block.header == right.block.header
        && left.block.transactions == right.block.transactions
        && left.block.proposer_signature.algorithm == right.block.proposer_signature.algorithm
        && left.quorum_certificate.finality_context_root()?
            == right.quorum_certificate.finality_context_root()?)
}

fn same_validation_certificate_subject(
    left: &ValidationCertificate,
    right: &ValidationCertificate,
) -> bool {
    same_quorum_certificate_subject(
        &left.as_verification_certificate(),
        &right.as_verification_certificate(),
    )
}

#[cfg(test)]
fn same_timeout_certificate_subject(left: &TimeoutCertificate, right: &TimeoutCertificate) -> bool {
    left.next_round == right.next_round
        && same_quorum_certificate_subject(
            &left.as_verification_certificate(),
            &right.as_verification_certificate(),
        )
}

/// Compares the immutable round transition independently of the timeout
/// quorum's local prepared knowledge and signer subset.
///
/// Two valid strict-quorum subsets can close the same round while only one
/// includes a validator that observed a prepared VC. That is not a second
/// consensus transition; the driver must retain or adopt the stronger carry
/// requirement instead of terminating every validator process.
fn same_timeout_transition_context(left: &TimeoutCertificate, right: &TimeoutCertificate) -> bool {
    let normalized = |certificate: &TimeoutCertificate| {
        certificate.consensus_subject().map(|mut subject| {
            subject.candidate_id = None;
            subject.prepared_round = None;
            subject
        })
    };
    matches!(
        (normalized(left), normalized(right)),
        (Ok(left_subject), Ok(right_subject))
            if left_subject == right_subject
                && left.certificate_version == right.certificate_version
                && left.next_round == right.next_round
                && left.active_validator_set_hash == right.active_validator_set_hash
                && left.cluster_map_hash == right.cluster_map_hash
                && left.threshold_weight_required == right.threshold_weight_required
    )
}

fn validate_canonical_driver_timeouts(
    config: &crate::synergy_types::ProtocolConfig,
) -> Result<(), String> {
    if config.proposal_timeout_ms != 1_500
        || config.prevote_timeout_ms != 1_500
        || config.precommit_timeout_ms != 1_500
        || config.max_round_timeout_ms != 10_000
    {
        return Err(
            "typed PoSy driver refuses non-finalized timeout values; Testnet-v3 requires 1500/1500/1500/10000 ms"
                .to_string(),
        );
    }
    let staged = config
        .proposal_timeout_ms
        .checked_add(config.prevote_timeout_ms)
        .and_then(|value| value.checked_add(config.precommit_timeout_ms))
        .ok_or_else(|| "typed PoSy stage-timeout total overflows".to_string())?;
    if staged > config.max_round_timeout_ms {
        return Err("typed PoSy stage windows exceed the finalized round cap".to_string());
    }
    Ok(())
}

/// Runs the only operational typed-consensus mailbox consumer.  It evaluates
/// the scheduler before waiting for ingress and at bounded intervals
/// thereafter, so a missing protected input, conflicting certified source, or
/// outbound transport failure halts validator signing instead of degrading to
/// legacy consensus or an unscheduled local loop.
pub fn run_typed_posy_driver<E, D, H, R>(
    driver: &mut TypedPosyDriver<E, D, H, R>,
    receiver: &Receiver<TypedConsensusEnvelope>,
    running: &AtomicBool,
) -> Result<TypedCoordinatorDriverMetrics, String>
where
    E: TypedConsensusEgress,
    D: TypedFinalityContextDigestSource,
    H: TypedNextHeightContextSource,
    R: TypedEtdagIngressRotator,
{
    let authorizer = FrozenTypedConsensusPeerAuthorizer::new(
        driver.coordinator.consensus.validator_set.clone(),
    )?;
    while running.load(Ordering::Acquire) {
        driver.tick()?;
        match receiver.recv_timeout(COORDINATOR_INGRESS_POLL_INTERVAL) {
            Ok(envelope) => {
                release_typed_vote_queue_slot(&envelope);
                match driver.handle_envelope(envelope, &authorizer) {
                    Ok(_) => {}
                    Err(error) if driver_error_is_fatal(&error) => return Err(error),
                    Err(_) => driver.note_rejected_message(),
                }
            }
            Err(RecvTimeoutError::Timeout) => continue,
            Err(RecvTimeoutError::Disconnected) if !running.load(Ordering::Acquire) => break,
            Err(RecvTimeoutError::Disconnected) => {
                return Err(
                    "typed PoSy driver ingress disconnected while validator runtime is live"
                        .to_string(),
                )
            }
        }
    }
    Ok(driver.metrics())
}

fn driver_error_is_fatal(error: &str) -> bool {
    error.contains("TYPED_DRIVER_SOURCE_CONFLICT")
        || error.contains("typed PoSy transport")
        || error.contains("typed coordinator event does not match")
}

pub(crate) fn execute_finalized_block(
    state: &ExecutionState,
    block: &Block,
) -> Result<ExecutionState, String> {
    if compute_state_root_after(state)? != block.header.state_root_before {
        return Err(
            "typed finalized block does not extend the supplied execution-state root".to_string(),
        );
    }
    let mut authorized = state.clone();
    for transaction in &block.transactions {
        authorized.mark_authorized_at(
            transaction,
            block
                .header
                .timestamp_ms_consensus_bounded
                .saturating_div(1_000),
        )?;
    }
    let execution = execute_block(block, &authorized)?;
    if execution.state_root_after != block.header.state_root_after
        || execution.receipt_root != block.header.receipt_root
    {
        return Err(
            "typed finalized block execution roots do not match proposal header".to_string(),
        );
    }
    Ok(execution.state)
}

/// Deterministically reconstruct the only execution snapshot a restarted
/// typed node may expose.  Every persisted block is replayed from the
/// finalized Genesis snapshot and must reproduce both committed roots; a
/// recovered consensus context alone is never enough to answer contract
/// reads.
pub(crate) fn replay_finalized_execution_state(
    genesis_state: ExecutionState,
    records: &[TypedFinalityRecord],
) -> Result<ExecutionState, String> {
    let mut state = genesis_state;
    for record in records {
        state = execute_finalized_block(&state, &record.block).map_err(|error| {
            format!(
                "replay finalized execution state at typed height {}: {error}",
                record.height.0
            )
        })?;
    }
    Ok(state)
}

fn bind_recovered_finality(
    finality_store: &TypedFinalityStore,
    local_context: &LocalConsensusContext,
) -> Result<(), String> {
    let Some(latest) = finality_store.latest()? else {
        if local_context.latest_finalized_height.0 != 0
            || local_context.latest_finalized_block_hash != finality_store.genesis_anchor()
        {
            return Err(
                "empty typed finality store does not match local Genesis boundary".to_string(),
            );
        }
        return Ok(());
    };
    let block_hash = Hash::from_hex(&latest.block_id.0)
        .map_err(|error| format!("persisted typed block ID is not a hash: {error}"))?;
    if local_context.latest_finalized_height != latest.height
        || local_context.latest_finalized_block_hash != block_hash
        || local_context.latest_finalized_state_root != latest.block.header.state_root_after
        || local_context
            .height_context
            .prior_finalized_qc_or_transition_root
            != latest.quorum_certificate.finality_context_root()?
    {
        return Err(
            "typed coordinator local context does not match recovered typed finality".to_string(),
        );
    }
    Ok(())
}

fn validate_immutable_epoch_topology(
    current_validator_set: &ValidatorSet,
    next_validator_set: &ValidatorSet,
    transition: &EpochTransition,
    next_cluster_map: &ClusterMap,
) -> Result<(), String> {
    if current_validator_set.epoch != transition.from_epoch
        || next_validator_set.epoch != transition.to_epoch
        || current_validator_set.validators.len() != next_validator_set.validators.len()
    {
        return Err("epoch transition validator population or epoch is invalid".to_string());
    }
    current_validator_set.validate_unique_validator_and_key_ids()?;
    next_validator_set.validate_unique_validator_and_key_ids()?;
    let current_by_id = current_validator_set
        .validators
        .iter()
        .map(|validator| (validator.validator_id.clone(), validator))
        .collect::<BTreeMap<_, _>>();
    let mut seen = BTreeSet::new();
    for next in &next_validator_set.validators {
        let current = current_by_id.get(&next.validator_id).ok_or_else(|| {
            format!(
                "epoch transition introduces validator identity {}",
                next.validator_id.0
            )
        })?;
        if !seen.insert(next.validator_id.clone())
            || current.validator_uma_id != next.validator_uma_id
            || current.consensus_public_key != next.consensus_public_key
            || current.peer_public_key != next.peer_public_key
            || current.operator_public_key != next.operator_public_key
            || current.voting_weight != next.voting_weight
        {
            return Err(
                "epoch transition mutates an immutable validator identity or key".to_string(),
            );
        }
        match (&current.status, &next.status) {
            (ValidatorStatus::Active, ValidatorStatus::Active)
                if current.activation_epoch == next.activation_epoch => {}
            (ValidatorStatus::PendingActivation, ValidatorStatus::PendingActivation)
                if current.activation_epoch == next.activation_epoch
                    && current.cluster_id == next.cluster_id => {}
            (ValidatorStatus::PendingActivation, ValidatorStatus::Active)
                if next.activation_epoch == transition.to_epoch => {}
            _ => {
                return Err(
                    "epoch transition attempts an unsupported validator lifecycle change"
                        .to_string(),
                )
            }
        }
    }
    if seen.len() != current_by_id.len() {
        return Err("epoch transition removes a preconfigured validator identity".to_string());
    }
    let next_active_set = next_validator_set.active_for_epoch(transition.to_epoch);
    if next_active_set.validators.len() < 6 {
        return Err("epoch transition would violate the six-validator minimum".to_string());
    }
    let expected_map = ClusterMap::derive_from_finalized_epoch_seed(
        &next_active_set,
        transition.finalized_epoch_seed_root()?,
    )?;
    if next_cluster_map.canonicalized() != expected_map {
        return Err(
            "epoch transition cluster map is not derived from the finalized transition seed"
                .to_string(),
        );
    }
    for validator in &next_active_set.validators {
        let assignment = next_cluster_map
            .assignments
            .iter()
            .find(|assignment| assignment.validator_id == validator.validator_id)
            .ok_or_else(|| {
                "epoch transition omits an active validator cluster assignment".to_string()
            })?;
        if assignment.cluster_id != validator.cluster_id {
            return Err(
                "epoch transition active validator cluster field is inconsistent".to_string(),
            );
        }
    }
    next_cluster_map.validate_complete_balanced_assignment(&next_active_set)
}

fn verifier_for_verified_epoch_transition(
    current_verifier: &AegisPqvmVerifier,
    current_validator_set: &ValidatorSet,
    next_validator_set: &ValidatorSet,
    next_epoch: crate::synergy_types::Epoch,
) -> Result<AegisPqvmVerifier, String> {
    let mut registry = current_verifier.registry.clone();
    let current_active_ids = current_validator_set
        .active_for_epoch(current_validator_set.epoch)
        .validators
        .into_iter()
        .map(|validator| validator.validator_id)
        .collect::<BTreeSet<_>>();
    for validator in next_validator_set.active_for_epoch(next_epoch).validators {
        if !current_active_ids.contains(&validator.validator_id) {
            registry
                .register_public_key_with_lifecycle(
                    PQCPublicKey {
                        algorithm: PQCAlgorithm::MLDSA65,
                        key_data: validator.consensus_public_key.key_bytes.clone(),
                        key_id: validator.consensus_public_key.key_id.0.clone(),
                        created_at: 0,
                    },
                    AegisPqKeyLifecycleRecord {
                        uma_id: validator.validator_uma_id.0.clone(),
                        key_id: validator.consensus_public_key.key_id.clone(),
                        roles: vec![
                            AegisPqKeyRole::ConsensusProposer,
                            AegisPqKeyRole::ConsensusVote,
                            AegisPqKeyRole::EpochTransition,
                        ],
                        active_from_epoch: next_epoch,
                        active_until_epoch: None,
                        revoked_from_epoch: None,
                    },
                )
                .map_err(|error| format!("register activated validator Aegis key: {error}"))?;
        }
    }
    let verifier = AegisPqvmVerifier::initialize_required(registry)
        .map_err(|error| format!("initialize transitioned Aegis verifier: {error}"))?;
    for validator in next_validator_set.active_for_epoch(next_epoch).validators {
        for role in [
            AegisPqKeyRole::ConsensusProposer,
            AegisPqKeyRole::ConsensusVote,
            AegisPqKeyRole::EpochTransition,
        ] {
            if !verifier.registry.key_is_active_for_epoch(
                &validator.validator_uma_id.0,
                &validator.consensus_public_key.key_id,
                next_epoch,
                role,
            ) {
                return Err("transitioned validator verifier lifecycle is incomplete".to_string());
            }
        }
    }
    Ok(verifier)
}

static COORDINATOR_INGRESS: OnceLock<Mutex<Option<SyncSender<TypedConsensusEnvelope>>>> =
    OnceLock::new();
static COORDINATOR_STARTUP_BUFFER: OnceLock<Mutex<TypedCoordinatorStartupBuffer>> = OnceLock::new();
type TypedVoteQueueKey = (ValidatorId, Hash);
static TYPED_VOTE_QUEUE_DEPTHS: OnceLock<Mutex<BTreeMap<TypedVoteQueueKey, usize>>> =
    OnceLock::new();

fn ingress_slot() -> &'static Mutex<Option<SyncSender<TypedConsensusEnvelope>>> {
    COORDINATOR_INGRESS.get_or_init(|| Mutex::new(None))
}

#[derive(Debug, Default)]
struct TypedCoordinatorStartupBuffer {
    accepting: bool,
    capacity: usize,
    messages: VecDeque<TypedConsensusEnvelope>,
}

fn startup_buffer() -> &'static Mutex<TypedCoordinatorStartupBuffer> {
    COORDINATOR_STARTUP_BUFFER.get_or_init(|| Mutex::new(TypedCoordinatorStartupBuffer::default()))
}

/// Enables bounded authenticated P2P buffering before the coordinator mailbox
/// is installed. The role runtime calls this before opening the P2P listener;
/// unbound socket traffic still cannot enter because the P2P handshake must
/// first produce `AuthenticatedTypedConsensusPeer`.
pub fn begin_typed_consensus_startup_buffer(capacity: usize) -> Result<(), String> {
    if capacity == 0 {
        return Err("typed coordinator startup buffer capacity must be non-zero".to_string());
    }
    if ingress_slot()
        .lock()
        .map_err(|_| "typed coordinator ingress lock is poisoned".to_string())?
        .is_some()
    {
        return Err("typed coordinator is already live; startup buffering is invalid".to_string());
    }
    let mut buffer = startup_buffer()
        .lock()
        .map_err(|_| "typed coordinator startup buffer lock is poisoned".to_string())?;
    if buffer.accepting {
        return Err("typed coordinator startup buffer is already active".to_string());
    }
    clear_typed_vote_queue_slots();
    buffer.accepting = true;
    buffer.capacity = capacity;
    buffer.messages.clear();
    Ok(())
}

fn typed_vote_queue_depths() -> &'static Mutex<BTreeMap<TypedVoteQueueKey, usize>> {
    TYPED_VOTE_QUEUE_DEPTHS.get_or_init(|| Mutex::new(BTreeMap::new()))
}

fn typed_vote_queue_key(
    authenticated_peer: Option<&AuthenticatedTypedConsensusPeer>,
    message: &TypedConsensusMessage,
) -> Option<TypedVoteQueueKey> {
    let (authenticated_peer, TypedConsensusMessage::Vote { vote }) = (authenticated_peer?, message)
    else {
        return None;
    };
    Some((
        authenticated_peer.validator_id.clone(),
        vote.height_context_root,
    ))
}

fn reserve_typed_vote_queue_slot(
    authenticated_peer: Option<&AuthenticatedTypedConsensusPeer>,
    message: &TypedConsensusMessage,
) -> Result<bool, String> {
    let Some(key) = typed_vote_queue_key(authenticated_peer, message) else {
        return Ok(false);
    };
    let mut depths = typed_vote_queue_depths()
        .lock()
        .map_err(|_| "typed vote queue depth lock is poisoned".to_string())?;
    let depth = depths.entry(key).or_default();
    if *depth >= MAX_QUEUED_TYPED_VOTES_PER_PEER_CONTEXT {
        return Err(format!(
            "typed vote queue has reached the Testnet-v3 per-peer-per-context limit of {MAX_QUEUED_TYPED_VOTES_PER_PEER_CONTEXT}"
        ));
    }
    *depth += 1;
    Ok(true)
}

fn release_typed_vote_queue_slot(envelope: &TypedConsensusEnvelope) {
    let Some(key) = typed_vote_queue_key(envelope.authenticated_peer.as_ref(), &envelope.message)
    else {
        return;
    };
    let Ok(mut depths) = typed_vote_queue_depths().lock() else {
        return;
    };
    let Some(depth) = depths.get_mut(&key) else {
        return;
    };
    if *depth <= 1 {
        depths.remove(&key);
    } else {
        *depth -= 1;
    }
}

fn clear_typed_vote_queue_slots() {
    if let Ok(mut depths) = typed_vote_queue_depths().lock() {
        depths.clear();
    }
}

/// Installs the sole typed coordinator mailbox for this process.
///
/// A bounded queue is mandatory: untrusted peers cannot consume unbounded
/// memory while consensus work is delayed. Replacing a running coordinator is
/// prohibited because it could split the signing-authority lifecycle.
pub fn install_typed_coordinator_ingress(
    queue_capacity: usize,
) -> Result<Receiver<TypedConsensusEnvelope>, String> {
    if queue_capacity == 0 {
        return Err("typed coordinator ingress queue capacity must be non-zero".to_string());
    }
    let (sender, receiver) = mpsc::sync_channel(queue_capacity);
    let mut slot = ingress_slot()
        .lock()
        .map_err(|_| "typed coordinator ingress lock is poisoned".to_string())?;
    if slot.is_some() {
        return Err("typed coordinator ingress is already installed".to_string());
    }
    let mut buffer = startup_buffer()
        .lock()
        .map_err(|_| "typed coordinator startup buffer lock is poisoned".to_string())?;
    if buffer.messages.len() > queue_capacity {
        return Err(
            "typed coordinator startup buffer exceeds the installed mailbox capacity".to_string(),
        );
    }
    while let Some(envelope) = buffer.messages.pop_front() {
        sender.try_send(envelope).map_err(|_| {
            "typed coordinator startup buffer could not drain into the mailbox".to_string()
        })?;
    }
    buffer.accepting = false;
    buffer.capacity = 0;
    *slot = Some(sender);
    Ok(receiver)
}

/// Removes the process-local ingress after the coordinator has stopped.
///
/// This is intentionally not exposed to network or administrative handlers;
/// role-runtime shutdown is the only valid lifecycle owner.
pub fn remove_typed_coordinator_ingress() -> Result<(), String> {
    let mut slot = ingress_slot()
        .lock()
        .map_err(|_| "typed coordinator ingress lock is poisoned".to_string())?;
    *slot = None;
    let mut buffer = startup_buffer()
        .lock()
        .map_err(|_| "typed coordinator startup buffer lock is poisoned".to_string())?;
    for envelope in buffer.messages.drain(..) {
        release_typed_vote_queue_slot(&envelope);
    }
    buffer.accepting = false;
    buffer.capacity = 0;
    clear_typed_vote_queue_slots();
    Ok(())
}

/// Delivers a typed consensus message to the active coordinator without any
/// legacy fallback. Saturation and an absent coordinator are fail-closed.
pub fn dispatch_typed_consensus_message(
    peer_address: &str,
    authenticated_peer: Option<AuthenticatedTypedConsensusPeer>,
    message: TypedConsensusMessage,
) -> Result<(), String> {
    let message_kind = typed_message_kind(&message);
    increment_typed_metric(|snapshot| &mut snapshot.messages_received, message_kind);
    if let Err(error) = validate_typed_consensus_message_size(&message) {
        increment_typed_metric(
            |snapshot| &mut snapshot.messages_rejected_precrypto,
            "oversized",
        );
        return Err(error);
    }
    let sender = ingress_slot()
        .lock()
        .map_err(|_| "typed coordinator ingress lock is poisoned".to_string())?
        .clone();
    let vote_slot_reserved =
        match reserve_typed_vote_queue_slot(authenticated_peer.as_ref(), &message) {
            Ok(reserved) => reserved,
            Err(error) => {
                increment_typed_metric(
                    |snapshot| &mut snapshot.messages_rejected_precrypto,
                    "per_validator_vote_quota",
                );
                return Err(error);
            }
        };
    if sender.is_none() {
        let mut buffer = startup_buffer()
            .lock()
            .map_err(|_| "typed coordinator startup buffer lock is poisoned".to_string())?;
        if buffer.accepting {
            if authenticated_peer.is_none() {
                increment_typed_metric(
                    |snapshot| &mut snapshot.messages_rejected_precrypto,
                    "unauthenticated",
                );
                if vote_slot_reserved {
                    let envelope = TypedConsensusEnvelope {
                        peer_address: peer_address.to_string(),
                        authenticated_peer,
                        message,
                    };
                    release_typed_vote_queue_slot(&envelope);
                }
                return Err(
                    "typed startup buffer refuses a message without authenticated validator identity"
                        .to_string(),
                );
            }
            if buffer.messages.len() >= buffer.capacity {
                increment_typed_metric(
                    |snapshot| &mut snapshot.messages_rejected_precrypto,
                    "startup_buffer_saturated",
                );
                let envelope = TypedConsensusEnvelope {
                    peer_address: peer_address.to_string(),
                    authenticated_peer,
                    message,
                };
                if vote_slot_reserved {
                    release_typed_vote_queue_slot(&envelope);
                }
                return Err("typed PoSy startup buffer is saturated".to_string());
            }
            buffer.messages.push_back(TypedConsensusEnvelope {
                peer_address: peer_address.to_string(),
                authenticated_peer,
                message,
            });
            return Ok(());
        }
        let envelope = TypedConsensusEnvelope {
            peer_address: peer_address.to_string(),
            authenticated_peer,
            message,
        };
        if vote_slot_reserved {
            release_typed_vote_queue_slot(&envelope);
        }
        increment_typed_metric(
            |snapshot| &mut snapshot.messages_rejected_precrypto,
            "coordinator_unavailable",
        );
        return Err(
            "typed PoSy coordinator is not running; refusing consensus message".to_string(),
        );
    }
    let sender = sender.expect("checked above");
    let send_result = sender.try_send(TypedConsensusEnvelope {
        peer_address: peer_address.to_string(),
        authenticated_peer,
        message,
    });
    match send_result {
        Ok(()) => Ok(()),
        Err(error) => {
            if vote_slot_reserved {
                let envelope = match &error {
                    TrySendError::Full(envelope) | TrySendError::Disconnected(envelope) => envelope,
                };
                release_typed_vote_queue_slot(envelope);
            }
            Err(match error {
                TrySendError::Full(_) => {
                    increment_typed_metric(
                        |snapshot| &mut snapshot.messages_rejected_precrypto,
                        "mailbox_saturated",
                    );
                    "typed PoSy coordinator ingress is saturated; refusing consensus message"
                        .to_string()
                }
                TrySendError::Disconnected(_) => {
                    increment_typed_metric(
                        |snapshot| &mut snapshot.messages_rejected_precrypto,
                        "mailbox_disconnected",
                    );
                    "typed PoSy coordinator ingress is disconnected; refusing consensus message"
                        .to_string()
                }
            })
        }
    }
}

#[cfg(test)]
pub fn reset_typed_coordinator_ingress_for_test() {
    let _ = remove_typed_coordinator_ingress();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::posy::ProofOfSynergyBft;
    use crate::consensus::testnet_v3_bootstrap::load_testnet_v3_genesis_bootstrap;
    use crate::consensus::testnet_v3_finality_context::FinalizedTypedContextProvider;
    use crate::consensus_parameters::{
        load_genesis_bound_consensus_parameters, EtdagActivationPermit,
    };
    use crate::crypto::aegis_pqvm::AegisPqvmSigner;
    use crate::etdag::EtdagParameters;
    use crate::execution::ExecutionState;
    use crate::genesis::load_genesis_from_path_for_test;
    use crate::p2p::messages::NetworkMessage;
    use crate::synergy_types::{
        deterministic_test_height_context, AegisPqKeyId, AegisPqKeyRole, AegisPqSignature,
        BlockHeader, BlockId, ChainId, ClusterAssignment, ClusterId, ClusterMap, Epoch,
        EpochTransition, Hash, Height, HeightConsensusContext, HeightConsensusContextSpec,
        NetworkId, ProtocolConfig, QuorumCertificate, Round, UmaId, ValidatorId, ValidatorRecord,
        ValidatorSet, ValidatorStatus, Vote, VotePhase, POSY_PROTOCOL_VERSION,
    };
    use std::collections::BTreeSet;
    use std::path::PathBuf;

    static COORDINATOR_FIXTURE_SEQUENCE: std::sync::atomic::AtomicU64 =
        std::sync::atomic::AtomicU64::new(0);
    static INGRESS_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn vote() -> TypedConsensusMessage {
        TypedConsensusMessage::Vote {
            vote: Vote {
                chain_id: ChainId::synergy_testnet_v3(),
                network_id: NetworkId::synergy_testnet_v3(),
                protocol_version: "posy/2.2".to_string(),
                height: Height(1),
                round: Round(0),
                epoch: Epoch(0),
                cluster_id: ClusterId(0),
                height_context_root: Hash::from_domain_bytes("test", b"context"),
                phase: VotePhase::Validate,
                block_id: BlockId("candidate".to_string()),
                highest_prepared_vc_root: None,
                validator_id: ValidatorId("validator-1".to_string()),
                validator_uma_id: UmaId("uma-1".to_string()),
                key_id: AegisPqKeyId("key-1".to_string()),
                active_validator_set_hash: Hash::from_domain_bytes("test", b"set"),
                cluster_map_hash: Hash::from_domain_bytes("test", b"cluster"),
                aegis_pq_signature: AegisPqSignature {
                    algorithm: "mldsa65".to_string(),
                    signature_bytes: vec![1],
                },
            },
        }
    }

    #[test]
    fn typed_messages_fail_closed_without_a_running_coordinator() {
        let _guard = INGRESS_TEST_LOCK.lock().unwrap();
        reset_typed_coordinator_ingress_for_test();
        let error = dispatch_typed_consensus_message("peer-a", None, vote()).unwrap_err();
        assert!(error.contains("coordinator is not running"));
    }

    #[test]
    fn randomized_signature_replay_keeps_one_vote_subject() {
        let TypedConsensusMessage::Vote { vote: first } = vote() else {
            unreachable!("vote fixture")
        };
        let mut votes = BTreeMap::new();
        insert_distinct_verified_vote(
            &mut votes,
            VerifiedVote::from_coordinator_acceptance(first.clone())
                .expect("verified vote fixture"),
        )
        .expect("first verified vote");

        let mut randomized_replay = first.clone();
        randomized_replay.aegis_pq_signature.signature_bytes = vec![2, 3, 4];
        insert_distinct_verified_vote(
            &mut votes,
            VerifiedVote::from_coordinator_acceptance(randomized_replay)
                .expect("verified replay fixture"),
        )
        .expect("a randomized signature over the same payload is idempotent");
        assert_eq!(votes.len(), 1);

        let mut conflict = first;
        conflict.block_id = BlockId("conflicting-candidate".to_string());
        assert!(insert_distinct_verified_vote(
            &mut votes,
            VerifiedVote::from_coordinator_acceptance(conflict).expect("verified conflict fixture"),
        )
        .unwrap_err()
        .contains("TYPED_DRIVER_SOURCE_CONFLICT"));
    }

    #[test]
    fn typed_messages_use_the_bounded_dedicated_mailbox() {
        let _guard = INGRESS_TEST_LOCK.lock().unwrap();
        reset_typed_coordinator_ingress_for_test();
        let receiver = install_typed_coordinator_ingress(1).unwrap();
        dispatch_typed_consensus_message("peer-a", None, vote()).unwrap();
        let envelope = receiver.try_recv().unwrap();
        assert_eq!(envelope.peer_address, "peer-a");
        assert!(matches!(
            envelope.message,
            TypedConsensusMessage::Vote { .. }
        ));
        remove_typed_coordinator_ingress().unwrap();
    }

    #[test]
    fn authenticated_messages_buffer_before_mailbox_install_and_drain_in_order() {
        let _guard = INGRESS_TEST_LOCK.lock().unwrap();
        reset_typed_coordinator_ingress_for_test();
        begin_typed_consensus_startup_buffer(2).expect("enable bounded startup buffering");
        let authenticated = AuthenticatedTypedConsensusPeer {
            validator_id: ValidatorId("validator-1".to_string()),
            validator_uma_id: UmaId("uma-1".to_string()),
            consensus_key_id: AegisPqKeyId("key-1".to_string()),
        };
        assert!(
            dispatch_typed_consensus_message("unauthenticated", None, vote())
                .unwrap_err()
                .contains("authenticated")
        );
        dispatch_typed_consensus_message(
            "authenticated-validator",
            Some(authenticated.clone()),
            vote(),
        )
        .expect("authenticated pre-mailbox message is buffered");

        let receiver = install_typed_coordinator_ingress(2)
            .expect("mailbox installation atomically drains startup traffic");
        let envelope = receiver
            .recv_timeout(Duration::from_millis(100))
            .expect("buffered message reaches the installed coordinator");
        assert_eq!(envelope.authenticated_peer.as_ref(), Some(&authenticated));
        assert!(matches!(
            envelope.message,
            TypedConsensusMessage::Vote { .. }
        ));
        release_typed_vote_queue_slot(&envelope);
        reset_typed_coordinator_ingress_for_test();
    }

    #[test]
    fn typed_vote_queue_is_capped_per_authenticated_peer_and_height_context() {
        let _guard = INGRESS_TEST_LOCK.lock().unwrap();
        reset_typed_coordinator_ingress_for_test();
        let receiver =
            install_typed_coordinator_ingress(MAX_QUEUED_TYPED_VOTES_PER_PEER_CONTEXT + 1).unwrap();
        let peer = AuthenticatedTypedConsensusPeer {
            validator_id: ValidatorId("validator-1".to_string()),
            validator_uma_id: UmaId("uma-1".to_string()),
            consensus_key_id: AegisPqKeyId("key-1".to_string()),
        };

        for _ in 0..MAX_QUEUED_TYPED_VOTES_PER_PEER_CONTEXT {
            dispatch_typed_consensus_message("peer-a", Some(peer.clone()), vote()).unwrap();
        }
        let error = dispatch_typed_consensus_message("peer-a", Some(peer.clone()), vote())
            .expect_err("the 65th queued vote for one authenticated peer/context must fail");
        assert!(error.contains("per-peer-per-context limit of 64"));

        let dequeued = receiver.try_recv().unwrap();
        release_typed_vote_queue_slot(&dequeued);
        dispatch_typed_consensus_message("peer-a", Some(peer), vote())
            .expect("dequeueing a vote must free its per-peer/context slot");
        remove_typed_coordinator_ingress().unwrap();
    }

    struct RejectAllPeers;

    impl TypedConsensusPeerAuthorizer for RejectAllPeers {
        fn authorize(
            &self,
            _peer: &AuthenticatedTypedConsensusPeer,
            _message: &TypedConsensusMessage,
        ) -> Result<(), String> {
            Err("peer is not bound to active typed validator identity".to_string())
        }
    }

    fn coordinator_fixture() -> TypedPosyCoordinator {
        let mut signer = AegisPqvmSigner::initialize_required().unwrap();
        let mut validators = Vec::new();
        for index in 0..6 {
            let uma = format!("uma-{index}");
            let key_id = signer
                .generate_and_register_key(
                    &uma,
                    vec![
                        AegisPqKeyRole::ConsensusVote,
                        AegisPqKeyRole::ConsensusProposer,
                        AegisPqKeyRole::EpochTransition,
                    ],
                    Epoch(0),
                )
                .unwrap();
            let public = signer.public_key_record(&key_id).unwrap();
            validators.push(ValidatorRecord {
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
                .map(|validator| ClusterAssignment {
                    cluster_id: ClusterId(0),
                    validator_id: validator.validator_id.clone(),
                })
                .collect(),
        };
        let protocol = ProtocolConfig::testnet_v3();
        let anchor = Hash::from_domain_bytes("typed-coordinator-test", b"genesis");
        let local_context = LocalConsensusContext {
            height_context: deterministic_test_height_context(
                &set,
                &cluster,
                &protocol,
                Height(1),
                ClusterId(0),
            ),
            latest_finalized_height: Height(0),
            latest_finalized_block_hash: anchor,
            latest_finalized_state_root: Hash::from_domain_bytes(
                "typed-coordinator-test",
                b"state-zero",
            ),
            latest_finalized_timestamp_ms: 0,
            round: Round(0),
            evidence_root: Hash::from_domain_bytes("typed-coordinator-test", b"evidence"),
            app_version: 1,
            execution_version: 1,
            dag_version: 1,
            aegis_pqvm_version: "aegis-pqvm".to_string(),
        };
        let verifier = signer.verifier();
        let consensus = ProofOfSynergyBft::new(&verifier, set, cluster, protocol);
        let path = crate::utils::test_temp_root(format!(
            "synergy-typed-coordinator-{}-{}.json",
            std::process::id(),
            COORDINATOR_FIXTURE_SEQUENCE.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        let store = TypedFinalityStore::at_path(path, anchor).unwrap();
        TypedPosyCoordinator::new(
            consensus,
            signer,
            ValidatorId("validator-0".to_string()),
            local_context,
            ExecutionState::new(),
            EtdagParameters::default(),
            store,
        )
        .unwrap()
    }

    #[test]
    fn local_signer_import_requires_the_exact_finalized_validator_key() {
        let coordinator = coordinator_fixture();
        let TypedPosyCoordinator {
            consensus,
            signer,
            local_validator_id,
            ..
        } = coordinator;
        let local = consensus
            .validator_set
            .validators
            .iter()
            .find(|validator| validator.validator_id == local_validator_id)
            .unwrap()
            .clone();
        let public_key = signer
            .registry
            .public_key(&local.consensus_public_key.key_id)
            .unwrap()
            .clone();
        let private_key = signer
            .registry
            .private_key(&local.consensus_public_key.key_id)
            .unwrap()
            .clone();
        let bootstrap = TestnetV3GenesisBootstrap {
            validator_set: consensus.validator_set,
            cluster_map: consensus.cluster_map,
            verifier: consensus.verifier,
            finalized_epoch_seed_root: Hash::from_domain_bytes(
                "typed-coordinator-test",
                b"finalized-genesis-epoch-seed",
            ),
            genesis_transition_root: Hash::from_domain_bytes(
                "typed-coordinator-test",
                b"finalized-genesis-transition",
            ),
            cryptographic_profile_root: Hash::from_domain_bytes(
                "typed-coordinator-test",
                b"finalized-genesis-crypto-profile",
            ),
        };

        let (imported, imported_validator_id) = import_local_genesis_bound_typed_signer(
            &bootstrap,
            &local.validator_uma_id.0,
            public_key.clone(),
            private_key,
        )
        .expect("the canonical locally held test key must import");
        assert_eq!(imported_validator_id, local.validator_id);
        assert_eq!(
            imported
                .public_key_record(&local.consensus_public_key.key_id)
                .unwrap(),
            local.consensus_public_key
        );

        let mut wrong_public_key = public_key;
        wrong_public_key.key_data[0] ^= 0x01;
        let result = import_local_genesis_bound_typed_signer(
            &bootstrap,
            &local.validator_uma_id.0,
            wrong_public_key,
            signer
                .registry
                .private_key(&local.consensus_public_key.key_id)
                .unwrap()
                .clone(),
        );
        let error = match result {
            Ok(_) => panic!("a public key that disagrees with Genesis must be rejected"),
            Err(error) => error,
        };
        assert!(error.contains("does not exactly match"));
    }

    fn genesis_bound_parameters() -> crate::consensus_parameters::LoadedConsensusParameters {
        let genesis_path = identity_assigned_genesis_path();
        let genesis: serde_json::Value =
            serde_json::from_slice(&std::fs::read(genesis_path).unwrap()).unwrap();
        load_genesis_bound_consensus_parameters(&genesis["consensus_parameters"]).unwrap()
    }

    fn identity_assigned_genesis_path() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../genesis.testnet-v3.identity-assigned.json")
    }

    fn canonical_release_bootstrap() -> TestnetV3GenesisBootstrap {
        let genesis = load_genesis_from_path_for_test(identity_assigned_genesis_path())
            .expect("load canonical Testnet-v3 Genesis");
        load_testnet_v3_genesis_bootstrap(&genesis)
            .expect("derive canonical Testnet-v3 Genesis bootstrap")
    }

    fn six_validator_startup_fixture(
        parameters: crate::consensus_parameters::LoadedConsensusParameters,
    ) -> (
        TestnetV3GenesisBootstrap,
        Hash,
        Hash,
        Vec<TypedPosyCoordinator>,
        Vec<PathBuf>,
    ) {
        let mut genesis_signer = AegisPqvmSigner::initialize_required().expect("Aegis signer");
        let mut validators = Vec::new();
        let mut local_key_material = Vec::new();
        for index in 0..6 {
            let uma = format!("e2e-uma-{index}");
            let key_id = genesis_signer
                .generate_and_register_key(
                    &uma,
                    vec![
                        AegisPqKeyRole::ConsensusVote,
                        AegisPqKeyRole::ConsensusProposer,
                        AegisPqKeyRole::EpochTransition,
                    ],
                    Epoch(0),
                )
                .expect("generate isolated validator key");
            let public_record = genesis_signer
                .public_key_record(&key_id)
                .expect("public validator record");
            let public_key = genesis_signer
                .registry
                .public_key(&key_id)
                .expect("registered public key")
                .clone();
            let private_key = genesis_signer
                .registry
                .private_key(&key_id)
                .expect("registered private key")
                .clone();
            let validator_id = ValidatorId(format!("e2e-validator-{index}"));
            validators.push(ValidatorRecord {
                validator_id: validator_id.clone(),
                validator_uma_id: UmaId(uma.clone()),
                consensus_public_key: public_record.clone(),
                peer_public_key: public_record.clone(),
                operator_public_key: public_record,
                voting_weight: 1,
                status: ValidatorStatus::Active,
                cluster_id: ClusterId(0),
                activation_epoch: Epoch(0),
            });
            local_key_material.push((uma, validator_id, public_key, private_key));
        }

        let finalized_epoch_seed_root =
            Hash::from_domain_bytes("typed-consensus-e2e", b"finalized-epoch-seed");
        let mut validator_set = ValidatorSet {
            epoch: Epoch(0),
            validators,
        };
        let cluster_map =
            ClusterMap::derive_from_finalized_epoch_seed(&validator_set, finalized_epoch_seed_root)
                .expect("derive six-validator cluster map");
        for validator in &mut validator_set.validators {
            validator.cluster_id = cluster_map
                .assignments
                .iter()
                .find(|assignment| assignment.validator_id == validator.validator_id)
                .expect("each validator receives a cluster assignment")
                .cluster_id;
        }
        let cluster_map =
            ClusterMap::derive_from_finalized_epoch_seed(&validator_set, finalized_epoch_seed_root)
                .expect("rederive canonical six-validator cluster map");
        let bootstrap = TestnetV3GenesisBootstrap {
            validator_set,
            cluster_map,
            verifier: genesis_signer.verifier(),
            finalized_epoch_seed_root,
            genesis_transition_root: Hash::from_domain_bytes(
                "typed-consensus-e2e",
                b"genesis-transition",
            ),
            cryptographic_profile_root: Hash::from_domain_bytes(
                "typed-consensus-e2e",
                b"cryptographic-profile",
            ),
        };
        let execution_state = ExecutionState::new();
        let deployed_genesis_state_root =
            compute_state_root_after(&execution_state).expect("empty execution root");
        let genesis_anchor = Hash::from_domain_bytes("typed-consensus-e2e", b"genesis-anchor");
        let mut coordinators = Vec::new();
        let mut store_paths = Vec::new();
        for (index, (uma, _validator_id, public_key, private_key)) in
            local_key_material.into_iter().enumerate()
        {
            let (signer, local_validator_id) =
                import_local_genesis_bound_typed_signer(&bootstrap, &uma, public_key, private_key)
                    .expect("import exactly one canonical local consensus key");
            let store_path = crate::utils::test_temp_root(format!(
                "typed-consensus-e2e-finality-{}-{}.json",
                std::process::id(),
                COORDINATOR_FIXTURE_SEQUENCE.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            ));
            let store = TypedFinalityStore::at_path(store_path.clone(), genesis_anchor)
                .expect("create isolated finality store");
            let coordinator = TypedPosyCoordinatorStartup {
                genesis_bootstrap: bootstrap.clone(),
                consensus_parameters: parameters.clone(),
                signer,
                local_validator_id,
                genesis_anchor,
                deployed_genesis_state_root,
                execution_state: ExecutionState::new(),
                etdag_parameters: EtdagParameters::default(),
                finality_store: store,
            }
            .build()
            .unwrap_or_else(|error| panic!("node {index} startup must be Genesis-bound: {error}"));
            coordinators.push(coordinator);
            store_paths.push(store_path);
        }
        (
            bootstrap,
            genesis_anchor,
            deployed_genesis_state_root,
            coordinators,
            store_paths,
        )
    }

    #[test]
    fn six_validator_release_gate_requires_genesis_bound_manifest_exact_quorum_and_recovery() {
        let _ingress_guard = INGRESS_TEST_LOCK.lock().unwrap();
        reset_typed_coordinator_ingress_for_test();

        let parameters = genesis_bound_parameters();
        parameters
            .require_genesis_binding()
            .expect("release parameters must be bound in Genesis");
        parameters
            .manifest
            .validate_finalized()
            .expect("release parameter manifest must be finalized");
        let canonical_bootstrap = canonical_release_bootstrap();
        let canonical_active = canonical_bootstrap.validator_set.active_for_epoch(Epoch(0));
        canonical_bootstrap
            .cluster_map
            .validate_complete_balanced_assignment(&canonical_active)
            .expect("canonical Genesis cluster map");
        assert_eq!(
            canonical_active.validators.len() as u64,
            parameters.manifest.initial_cluster_validator_count,
            "the finalized release must start with its six canonical validators"
        );
        assert_eq!(parameters.manifest.initial_availability_quorum, 5);

        let (bootstrap, genesis_anchor, deployed_genesis_state_root, mut coordinators, store_paths) =
            six_validator_startup_fixture(parameters.clone());
        let height_context = coordinators[0].local_context().height_context.clone();
        assert_eq!(height_context.assigned_cluster_validator_count, 6);
        assert_eq!(height_context.strict_count_quorum().unwrap(), 5);
        assert_eq!(height_context.strict_weight_quorum().unwrap(), 5);

        let proposer_index = coordinators
            .iter()
            .position(|coordinator| {
                coordinator
                    .consensus
                    .proposer_for(&height_context, Round(0))
                    .expect("scheduled proposer")
                    .validator_id
                    == coordinator.local_validator_id
            })
            .expect("one of six coordinators is the height-one proposer");
        let block = {
            let proposer_coordinator = &mut coordinators[proposer_index];
            let local_context = proposer_coordinator.local_context.clone();
            let proposer = proposer_coordinator
                .consensus
                .proposer_for(&local_context.height_context, local_context.round)
                .expect("scheduled proposer record");
            proposer_coordinator
                .consensus
                .propose_block(
                    &mut proposer_coordinator.signer,
                    &proposer,
                    Vec::new(),
                    &local_context,
                    &proposer_coordinator.execution_state,
                    Hash::from_domain_bytes("typed-consensus-e2e", b"dag-frontier"),
                )
                .expect("scheduled node must sign the height-one proposal")
        };

        let validation_votes = coordinators
            .iter_mut()
            .map(|coordinator| {
                coordinator
                    .validation_vote_for(&block)
                    .expect("each independently imported validator signs its own validation vote")
            })
            .collect::<Vec<_>>();

        let inbound_vote = validation_votes[1].clone();
        let peer_record = coordinators[1]
            .consensus
            .validator_set
            .validators
            .iter()
            .find(|validator| validator.validator_id == inbound_vote.validator_id)
            .expect("inbound signer remains in frozen validator set");
        let authenticated_peer = AuthenticatedTypedConsensusPeer {
            validator_id: peer_record.validator_id.clone(),
            validator_uma_id: peer_record.validator_uma_id.clone(),
            consensus_key_id: peer_record.consensus_public_key.key_id.clone(),
        };
        let wire = serde_json::to_vec(&NetworkMessage::TypedConsensus {
            chain_incarnation: crate::synergy_types::TESTNET_V3_CHAIN_INCARNATION,
            genesis_hash: crate::genesis::canonical_genesis()
                .unwrap()
                .hash()
                .to_string(),
            message: TypedConsensusMessage::Vote {
                vote: inbound_vote.clone(),
            },
        })
        .expect("serialize exact typed P2P message");
        let decoded: NetworkMessage =
            serde_json::from_slice(&wire).expect("decode exact typed P2P message");
        let NetworkMessage::TypedConsensus { message, .. } = decoded else {
            panic!("typed consensus artifact must not be decoded as legacy traffic");
        };
        let receiver = install_typed_coordinator_ingress(1).expect("install bounded ingress");
        dispatch_typed_consensus_message("six-validator-p2p", Some(authenticated_peer), message)
            .expect("authenticated typed P2P vote reaches the dedicated mailbox");
        let envelope = receiver.recv().expect("typed mailbox delivery");
        release_typed_vote_queue_slot(&envelope);
        let authorizer = FrozenTypedConsensusPeerAuthorizer::new(
            coordinators[proposer_index].consensus.validator_set.clone(),
        )
        .expect("freeze P2P validator identity authority");
        assert!(matches!(
            coordinators[proposer_index]
                .handle_envelope(envelope, &authorizer)
                .expect("authenticated typed P2P vote is verified"),
            TypedCoordinatorEvent::VoteAccepted {
                phase: VotePhase::Validate,
                ..
            }
        ));
        remove_typed_coordinator_ingress().expect("remove test-only ingress");

        let proposer_coordinator = &mut coordinators[proposer_index];
        let four_validation_error = proposer_coordinator
            .form_validation_certificate(&validation_votes[..4])
            .expect_err("four of six validators must never form a validation certificate");
        assert!(four_validation_error.contains("strict distinct-signer quorum failed"));
        let validation_certificate = proposer_coordinator
            .form_validation_certificate(&validation_votes[..5])
            .expect("exactly five of six validation votes form a certificate");
        assert_eq!(validation_certificate.signed_weight, 5);

        let finality_votes = coordinators
            .iter_mut()
            .map(|coordinator| {
                coordinator
                    .finality_vote_for(&block, &validation_certificate)
                    .expect("each independently imported validator signs its finality vote")
            })
            .collect::<Vec<_>>();
        let proposer_coordinator = &mut coordinators[proposer_index];
        let four_finality_error = proposer_coordinator
            .form_finality_certificate(&finality_votes[..4])
            .expect_err("four of six validators must never form a finality QC");
        assert!(four_finality_error.contains("strict distinct-signer quorum failed"));
        let finality_qc = proposer_coordinator
            .form_finality_certificate(&finality_votes[..5])
            .expect("exactly five of six finality votes form a QC");
        assert_eq!(finality_qc.threshold_weight_required, 5);
        assert_eq!(finality_qc.signed_weight, 5);
        proposer_coordinator
            .consensus
            .commit_block(&block, &finality_qc, &height_context)
            .expect("five-of-six QC commits only its exact candidate");
        let finality_store = proposer_coordinator.finality_store.clone();
        let record = finality_store
            .append_verified_finality(&block, &finality_qc)
            .expect("persist verified five-of-six finality evidence");

        let first_provider = FinalizedTypedContextProvider::new(
            bootstrap.clone(),
            parameters.protocol_config.clone(),
            finality_store.clone(),
            deployed_genesis_state_root,
        )
        .expect("construct finalized context provider");
        let recovered = first_provider
            .recover_next_context()
            .expect("recover successor context from durable five-of-six QC");
        assert_eq!(recovered.latest_finalized_height, record.height);
        let restarted_provider = FinalizedTypedContextProvider::new(
            bootstrap.clone(),
            parameters.protocol_config.clone(),
            finality_store.clone(),
            deployed_genesis_state_root,
        )
        .expect("restart finalized context provider");
        assert_eq!(
            restarted_provider
                .recover_next_context()
                .expect("restart must rebuild the same durable successor context")
                .height_context,
            recovered.height_context
        );

        let mut mismatched_recovery = recovered.clone();
        mismatched_recovery.latest_finalized_state_root =
            Hash::from_domain_bytes("typed-consensus-e2e", b"mismatched-recovery-state");
        let mismatch_node = coordinators
            .pop()
            .expect("retain a node signer for fail-closed restart");
        let TypedPosyCoordinator {
            signer,
            local_validator_id,
            ..
        } = mismatch_node;
        let mismatch = match (TypedPosyCoordinatorStartup {
            genesis_bootstrap: bootstrap.clone(),
            consensus_parameters: parameters.clone(),
            signer,
            local_validator_id,
            genesis_anchor,
            deployed_genesis_state_root,
            execution_state: ExecutionState::new(),
            etdag_parameters: EtdagParameters::default(),
            finality_store: finality_store.clone(),
        }
        .build_with_finalized_context(mismatched_recovery))
        {
            Ok(_) => panic!("restart must reject a context that disagrees with durable finality"),
            Err(error) => error,
        };
        assert!(mismatch.contains("does not match recovered typed finality"));

        drop(coordinators);
        for path in store_paths {
            let _ = std::fs::remove_file(path);
        }
    }

    #[test]
    fn finalized_startup_builds_only_from_a_state_root_bound_to_execution_state() {
        let coordinator = coordinator_fixture();
        let TypedPosyCoordinator {
            consensus,
            signer,
            local_validator_id,
            execution_state,
            etdag_parameters,
            finality_store,
            ..
        } = coordinator;
        let genesis_anchor = finality_store.genesis_anchor();
        let deployed_genesis_state_root = compute_state_root_after(&execution_state).unwrap();
        let bootstrap = TestnetV3GenesisBootstrap {
            validator_set: consensus.validator_set,
            cluster_map: consensus.cluster_map,
            verifier: consensus.verifier,
            finalized_epoch_seed_root: Hash::from_domain_bytes(
                "typed-coordinator-test",
                b"finalized-genesis-epoch-seed",
            ),
            genesis_transition_root: Hash::from_domain_bytes(
                "typed-coordinator-test",
                b"finalized-genesis-transition",
            ),
            cryptographic_profile_root: Hash::from_domain_bytes(
                "typed-coordinator-test",
                b"finalized-genesis-crypto-profile",
            ),
        };
        let coordinator = TypedPosyCoordinatorStartup {
            genesis_bootstrap: bootstrap,
            consensus_parameters: genesis_bound_parameters(),
            signer,
            local_validator_id,
            genesis_anchor,
            deployed_genesis_state_root,
            execution_state,
            etdag_parameters,
            finality_store,
        }
        .build()
        .expect("finalized startup inputs must construct height one authority");
        assert_eq!(coordinator.local_context().height_context.height, Height(1));
        assert_eq!(
            coordinator.local_context().latest_finalized_state_root,
            deployed_genesis_state_root
        );
        let _ = std::fs::remove_file(coordinator.finality_store.path());
    }

    #[test]
    fn finalized_startup_rejects_an_unbound_deployed_state_claim() {
        let coordinator = coordinator_fixture();
        let TypedPosyCoordinator {
            consensus,
            signer,
            local_validator_id,
            execution_state,
            etdag_parameters,
            finality_store,
            ..
        } = coordinator;
        let genesis_anchor = finality_store.genesis_anchor();
        let bootstrap = TestnetV3GenesisBootstrap {
            validator_set: consensus.validator_set,
            cluster_map: consensus.cluster_map,
            verifier: consensus.verifier,
            finalized_epoch_seed_root: Hash::from_domain_bytes(
                "typed-coordinator-test",
                b"finalized-genesis-epoch-seed",
            ),
            genesis_transition_root: Hash::from_domain_bytes(
                "typed-coordinator-test",
                b"finalized-genesis-transition",
            ),
            cryptographic_profile_root: Hash::from_domain_bytes(
                "typed-coordinator-test",
                b"finalized-genesis-crypto-profile",
            ),
        };
        let result = TypedPosyCoordinatorStartup {
            genesis_bootstrap: bootstrap,
            consensus_parameters: genesis_bound_parameters(),
            signer,
            local_validator_id,
            genesis_anchor,
            deployed_genesis_state_root: Hash::from_domain_bytes(
                "typed-coordinator-test",
                b"wrong-deployed-state-root",
            ),
            execution_state,
            etdag_parameters,
            finality_store: finality_store.clone(),
        }
        .build();
        assert!(matches!(
            result,
            Err(error) if error.contains("does not match the committed deployed Genesis state root")
        ));
        let _ = std::fs::remove_file(finality_store.path());
    }

    fn finalized_block(
        context: &HeightConsensusContext,
        parent: Hash,
        state_before: Hash,
        state_after: Hash,
    ) -> Block {
        Block {
            header: BlockHeader {
                version: 2,
                chain_id: ChainId::synergy_testnet_v3(),
                network_id: NetworkId::synergy_testnet_v3(),
                protocol_version: POSY_PROTOCOL_VERSION.to_string(),
                height: context.height,
                round: Round(0),
                epoch: context.epoch,
                cluster_id: context.assigned_cluster_id,
                height_context_root: context.root().unwrap(),
                parent_block_hash: parent,
                parent_state_root: state_before,
                last_finalized_qc_hash: context.prior_finalized_qc_or_transition_root,
                proposer_validator_id: context.leader_schedule[0].clone(),
                proposer_uma_id: UmaId("test-proposer".to_string()),
                proposer_key_id: AegisPqKeyId("test-proposer-key".to_string()),
                active_validator_set_hash: context.active_validator_set_root,
                eligible_validator_set_hash: context.active_validator_set_root,
                validator_consensus_key_root: context.validator_consensus_key_root,
                frozen_bonded_weight_root: context.frozen_bonded_weight_root,
                cluster_schedule_version: context.cluster_schedule_version.clone(),
                cluster_map_hash: context.cluster_map_root,
                assigned_cluster_membership_root: context.assigned_cluster_membership_root,
                assigned_cluster_validator_count: context.assigned_cluster_validator_count,
                assigned_cluster_total_voting_weight: context.assigned_cluster_total_voting_weight,
                proposer_schedule_hash: context.leader_schedule_root,
                protocol_config_hash: context.consensus_parameter_root,
                cryptographic_profile_root: context.cryptographic_profile_root,
                dag_frontier_root: Hash::from_domain_bytes("typed-coordinator-test", b"dag"),
                tx_order_root: Hash::from_domain_bytes("typed-coordinator-test", b"tx-order"),
                tx_count: 0,
                protected_batch: None,
                evidence_root: Hash::from_domain_bytes("typed-coordinator-test", b"evidence"),
                state_root_before: state_before,
                state_root_after: state_after,
                receipt_root: Hash::from_domain_bytes("typed-coordinator-test", b"receipts"),
                app_version: 1,
                execution_version: 1,
                dag_version: 1,
                aegis_pqvm_version: "aegis-pqvm".to_string(),
                timestamp_ms_consensus_bounded: 1,
            },
            transactions: Vec::new(),
            proposer_signature: AegisPqSignature {
                algorithm: "mldsa65".to_string(),
                signature_bytes: vec![1],
            },
        }
    }

    fn finality_qc(block: &Block) -> QuorumCertificate {
        QuorumCertificate {
            qc_version: 1,
            chain_id: block.header.chain_id,
            network_id: block.header.network_id.clone(),
            protocol_version: block.header.protocol_version.clone(),
            height: block.header.height,
            round: block.header.round,
            epoch: block.header.epoch,
            cluster_id: block.header.cluster_id,
            height_context_root: block.header.height_context_root,
            phase: VotePhase::Finality,
            block_id: block.candidate_id().unwrap(),
            highest_prepared_vc_root: None,
            active_validator_set_hash: block.header.active_validator_set_hash,
            cluster_map_hash: block.header.cluster_map_hash,
            threshold_weight_required: 5,
            signed_weight: 5,
            signer_bitmap: vec![0b0001_1111],
            aegis_pq_signatures: vec![AegisPqSignature {
                algorithm: "mldsa65".to_string(),
                signature_bytes: vec![1],
            }],
            aegis_pq_key_ids: vec![AegisPqKeyId("test-qc-key".to_string())],
        }
    }

    #[test]
    fn coordinator_requires_authenticated_peer_binding_before_message_validation() {
        let mut coordinator = coordinator_fixture();
        let error = coordinator
            .handle_envelope(
                TypedConsensusEnvelope {
                    peer_address: "unbound-peer".to_string(),
                    authenticated_peer: None,
                    message: vote(),
                },
                &RejectAllPeers,
            )
            .unwrap_err();
        assert!(error.contains("Genesis-bound authenticated peer identity"));
    }

    #[test]
    fn ingress_worker_rejects_unbound_input_and_stops_only_on_runtime_shutdown() {
        let mut coordinator = coordinator_fixture();
        let (sender, receiver) = std::sync::mpsc::sync_channel(1);
        sender
            .send(TypedConsensusEnvelope {
                peer_address: "unbound-peer".to_string(),
                authenticated_peer: None,
                message: vote(),
            })
            .unwrap();
        let running = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
        let shutdown = std::sync::Arc::clone(&running);
        let shutdown_thread = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(10));
            // Keep the test's lifecycle explicit: the worker must observe a
            // false flag, not a disconnected sender, to exit cleanly.
            shutdown.store(false, std::sync::atomic::Ordering::Release);
        });
        let metrics = run_typed_coordinator_ingress(&mut coordinator, &receiver, &running)
            .expect("explicit runtime shutdown must stop the typed ingress cleanly");
        shutdown_thread.join().unwrap();
        assert_eq!(metrics.accepted_messages, 0);
        assert_eq!(metrics.rejected_messages, 1);
    }

    #[test]
    fn frozen_peer_authorizer_rejects_a_vote_claiming_another_validator() {
        let coordinator = coordinator_fixture();
        let validator = coordinator
            .consensus
            .validator_set
            .validators
            .iter()
            .find(|validator| validator.validator_id == ValidatorId("validator-0".to_string()))
            .unwrap();
        let peer = AuthenticatedTypedConsensusPeer {
            validator_id: validator.validator_id.clone(),
            validator_uma_id: validator.validator_uma_id.clone(),
            consensus_key_id: validator.consensus_public_key.key_id.clone(),
        };
        let authorizer =
            FrozenTypedConsensusPeerAuthorizer::new(coordinator.consensus.validator_set.clone())
                .unwrap();
        let mut message = vote();
        {
            let TypedConsensusMessage::Vote { vote } = &mut message else {
                unreachable!();
            };
            vote.validator_id = peer.validator_id.clone();
            vote.validator_uma_id = peer.validator_uma_id.clone();
            vote.key_id = peer.consensus_key_id.clone();
        }
        authorizer.authorize(&peer, &message).unwrap();

        let TypedConsensusMessage::Vote { vote } = &mut message else {
            unreachable!();
        };
        vote.validator_id = ValidatorId("validator-1".to_string());
        let error = authorizer.authorize(&peer, &message).unwrap_err();
        assert!(error.contains("does not match"));
    }

    #[test]
    fn observer_identity_cannot_advertise_a_validator_recovery_checkpoint() {
        let coordinator = coordinator_fixture();
        let authorizer =
            FrozenTypedConsensusPeerAuthorizer::new(coordinator.consensus.validator_set.clone())
                .expect("freeze validator-only recovery authority");
        let observer = AuthenticatedTypedConsensusPeer {
            validator_id: ValidatorId("rpc-observer".to_string()),
            validator_uma_id: UmaId("rpc-observer".to_string()),
            consensus_key_id: AegisPqKeyId("observer-key".to_string()),
        };
        let message = TypedConsensusMessage::FinalityCheckpointRequest {
            next_height: Height(1),
        };
        assert!(authorizer
            .authorize(&observer, &message)
            .unwrap_err()
            .contains("absent from the frozen set"));
    }

    #[test]
    fn signed_transition_activates_validators_seven_through_ten_and_derives_two_clusters() {
        let mut coordinator = coordinator_fixture();
        for index in 6..10 {
            let uma = format!("uma-{index}");
            let key_id = coordinator
                .signer
                .generate_and_register_key(
                    &uma,
                    vec![
                        AegisPqKeyRole::ConsensusVote,
                        AegisPqKeyRole::ConsensusProposer,
                        AegisPqKeyRole::EpochTransition,
                    ],
                    Epoch(1),
                )
                .unwrap();
            let public = coordinator.signer.public_key_record(&key_id).unwrap();
            coordinator
                .consensus
                .validator_set
                .validators
                .push(ValidatorRecord {
                    validator_id: ValidatorId(format!("validator-{index}")),
                    validator_uma_id: UmaId(uma),
                    consensus_public_key: public.clone(),
                    peer_public_key: public.clone(),
                    operator_public_key: public,
                    voting_weight: 1,
                    status: ValidatorStatus::PendingActivation,
                    cluster_id: ClusterId(0),
                    activation_epoch: Epoch(0),
                });
        }

        let epoch_zero_context = coordinator.local_context.height_context.clone();
        let state_after = Hash::from_domain_bytes("typed-coordinator-test", b"state-one");
        let finalized = finalized_block(
            &epoch_zero_context,
            coordinator.finality_store.genesis_anchor(),
            coordinator.local_context.latest_finalized_state_root,
            state_after,
        );
        let finality_record = coordinator
            .finality_store
            .append_verified_finality(&finalized, &finality_qc(&finalized))
            .unwrap();
        let finality_hash = Hash::from_hex(&finality_record.block_id.0).unwrap();
        coordinator.local_context.height_context = HeightConsensusContext::derive(
            HeightConsensusContextSpec {
                protocol_version: POSY_PROTOCOL_VERSION.to_string(),
                height: Height(2),
                epoch: Epoch(0),
                assigned_cluster_id: ClusterId(0),
                cluster_schedule_version: epoch_zero_context.cluster_schedule_version.clone(),
                finalized_epoch_seed_root: epoch_zero_context.finalized_epoch_seed_root,
                assigned_height_schedule_root: Hash::from_domain_bytes(
                    "typed-coordinator-test",
                    b"height-two-epoch-zero",
                ),
                cryptographic_profile_root: epoch_zero_context.cryptographic_profile_root,
                prior_finalized_qc_or_transition_root: finality_record
                    .quorum_certificate
                    .finality_context_root()
                    .unwrap(),
            },
            &coordinator.consensus.validator_set,
            &coordinator.consensus.cluster_map,
            &coordinator.consensus.protocol_config,
        )
        .unwrap();
        coordinator.local_context.latest_finalized_height = Height(1);
        coordinator.local_context.latest_finalized_block_hash = finality_hash;
        coordinator.local_context.latest_finalized_state_root = state_after;

        let mut next_validator_set = coordinator.consensus.validator_set.clone();
        next_validator_set.epoch = Epoch(1);
        for validator in next_validator_set.validators.iter_mut().skip(6) {
            validator.status = ValidatorStatus::Active;
            validator.activation_epoch = Epoch(1);
        }
        let mut transition = EpochTransition {
            chain_id: ChainId::synergy_testnet_v3(),
            network_id: NetworkId::synergy_testnet_v3(),
            from_epoch: Epoch(0),
            to_epoch: Epoch(1),
            finalized_height: Height(1),
            finalized_block_id: finality_record.block_id.clone(),
            active_validator_set_hash: finalized.header.active_validator_set_hash,
            next_validator_set_hash: Hash::zero(),
            cluster_map_hash: Hash::zero(),
            height_context_root: finalized.header.height_context_root,
            signer_key_ids: Vec::new(),
            signatures: Vec::new(),
        };
        let next_cluster_map = ClusterMap::derive_from_finalized_epoch_seed(
            &next_validator_set.active_for_epoch(Epoch(1)),
            transition.finalized_epoch_seed_root().unwrap(),
        )
        .unwrap();
        transition.cluster_map_hash = next_cluster_map.hash().unwrap();
        for validator in &mut next_validator_set.validators {
            if let Some(assignment) = next_cluster_map
                .assignments
                .iter()
                .find(|assignment| assignment.validator_id == validator.validator_id)
            {
                validator.cluster_id = assignment.cluster_id;
            }
        }
        transition.next_validator_set_hash = next_validator_set
            .active_for_epoch(Epoch(1))
            .hash()
            .unwrap();
        let mut signing_keys = coordinator
            .consensus
            .validator_set
            .active_for_epoch(Epoch(0))
            .validators
            .into_iter()
            .map(|validator| validator.consensus_public_key.key_id)
            .collect::<Vec<_>>();
        signing_keys.sort();
        let signing_bytes = transition.signing_bytes().unwrap();
        transition.signatures = signing_keys
            .iter()
            .map(|key_id| {
                coordinator
                    .signer
                    .sign_epoch_transition(&signing_bytes, key_id)
                    .unwrap()
            })
            .collect();
        transition.signer_key_ids = signing_keys;

        let local_cluster = next_cluster_map
            .assignments
            .iter()
            .find(|assignment| assignment.validator_id == coordinator.local_validator_id)
            .unwrap()
            .cluster_id;
        let next_context = LocalConsensusContext {
            height_context: HeightConsensusContext::derive(
                HeightConsensusContextSpec {
                    protocol_version: POSY_PROTOCOL_VERSION.to_string(),
                    height: Height(2),
                    epoch: Epoch(1),
                    assigned_cluster_id: local_cluster,
                    cluster_schedule_version: epoch_zero_context.cluster_schedule_version,
                    finalized_epoch_seed_root: transition.finalized_epoch_seed_root().unwrap(),
                    assigned_height_schedule_root: Hash::from_domain_bytes(
                        "typed-coordinator-test",
                        b"height-two-epoch-one",
                    ),
                    cryptographic_profile_root: epoch_zero_context.cryptographic_profile_root,
                    prior_finalized_qc_or_transition_root: transition.root().unwrap(),
                },
                &next_validator_set,
                &next_cluster_map,
                &coordinator.consensus.protocol_config,
            )
            .unwrap(),
            latest_finalized_height: Height(1),
            latest_finalized_block_hash: finality_hash,
            latest_finalized_state_root: state_after,
            latest_finalized_timestamp_ms: 0,
            round: Round(0),
            evidence_root: Hash::from_domain_bytes("typed-coordinator-test", b"evidence-two"),
            app_version: 1,
            execution_version: 1,
            dag_version: 1,
            aegis_pqvm_version: "aegis-pqvm".to_string(),
        };

        coordinator
            .apply_verified_epoch_transition(
                &transition,
                next_validator_set,
                next_cluster_map,
                next_context,
            )
            .unwrap();
        assert_eq!(coordinator.local_context.height_context.epoch, Epoch(1));
        assert_eq!(
            coordinator
                .consensus
                .validator_set
                .active_for_epoch(Epoch(1))
                .validators
                .len(),
            10
        );
        assert_eq!(
            coordinator
                .consensus
                .cluster_map
                .assignments
                .iter()
                .map(|assignment| assignment.cluster_id)
                .collect::<BTreeSet<_>>()
                .len(),
            2
        );
        assert_eq!(
            coordinator
                .finality_store
                .recover_epoch_transitions()
                .unwrap()
                .len(),
            1
        );
        let _ = std::fs::remove_file(coordinator.finality_store.path());
    }

    #[derive(Default)]
    struct RecordingEgress {
        deliveries: usize,
        messages: Vec<TypedConsensusMessage>,
    }

    impl TypedConsensusEgress for RecordingEgress {
        fn broadcast(&mut self, message: &TypedConsensusMessage) -> Result<usize, String> {
            self.messages.push(message.clone());
            Ok(self.deliveries)
        }
    }

    struct FixedFinalityDigest;

    impl TypedFinalityContextDigestSource for FixedFinalityDigest {
        fn expected_digest(
            &self,
            _local_context: &LocalConsensusContext,
        ) -> Result<crate::etdag::EtdagDigest, String> {
            Ok(crate::etdag::EtdagDigest::from_domain_bytes(
                "typed-driver-test-finality-context",
                b"finalized",
            ))
        }
    }

    struct NoNextHeight;

    impl TypedNextHeightContextSource for NoNextHeight {
        fn next_authority(
            &mut self,
            _finalized: &TypedFinalityRecord,
            _current: &LocalConsensusContext,
        ) -> Result<TypedNextHeightAuthority, String> {
            Err("test next-height source must not be used".to_string())
        }
    }

    fn driver_with(
        coordinator: TypedPosyCoordinator,
        deliveries: usize,
    ) -> TypedPosyDriver<RecordingEgress, FixedFinalityDigest, NoNextHeight> {
        let root = crate::utils::test_temp_root(format!(
            "synergy-typed-driver-{}-{}",
            std::process::id(),
            COORDINATOR_FIXTURE_SEQUENCE.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        TypedPosyDriver::new(
            coordinator,
            EtdagProtectedInputCoordinator::at_paths(
                root.join("admission.json"),
                root.join("protected.json"),
            ),
            RecordingEgress {
                deliveries,
                messages: Vec::new(),
            },
            FixedFinalityDigest,
            NoNextHeight,
        )
        .unwrap()
    }

    type ReleaseDriver = TypedPosyDriver<
        RecordingEgress,
        FinalizedTypedContextProvider,
        FinalizedTypedContextProvider,
    >;

    fn release_driver_with(
        coordinator: TypedPosyCoordinator,
        bootstrap: TestnetV3GenesisBootstrap,
        protocol_config: ProtocolConfig,
        deployed_genesis_state_root: Hash,
    ) -> ReleaseDriver {
        let finality_store = coordinator.finality_store.clone();
        let finality_digest_source = FinalizedTypedContextProvider::new(
            bootstrap.clone(),
            protocol_config.clone(),
            finality_store.clone(),
            deployed_genesis_state_root,
        )
        .expect("release driver needs a Genesis-bound finalized-context digest source");
        let next_height_source = FinalizedTypedContextProvider::new(
            bootstrap,
            protocol_config,
            finality_store,
            deployed_genesis_state_root,
        )
        .expect("release driver needs a Genesis-bound next-height authority source");
        let root = crate::utils::test_temp_root(format!(
            "synergy-release-driver-{}-{}",
            std::process::id(),
            COORDINATOR_FIXTURE_SEQUENCE.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        TypedPosyDriver::new(
            coordinator,
            EtdagProtectedInputCoordinator::at_paths(
                root.join("admission.json"),
                root.join("protected.json"),
            ),
            RecordingEgress {
                deliveries: 1,
                messages: Vec::new(),
            },
            finality_digest_source,
            next_height_source,
        )
        .expect("release driver must accept the finalized Genesis authority")
    }

    fn authenticated_peer_for_release_driver(
        driver: &ReleaseDriver,
    ) -> AuthenticatedTypedConsensusPeer {
        let validator = driver
            .coordinator
            .consensus
            .validator_set
            .validators
            .iter()
            .find(|validator| validator.validator_id == driver.coordinator.local_validator_id)
            .expect("release driver local signer remains in frozen Genesis validator set");
        AuthenticatedTypedConsensusPeer {
            validator_id: validator.validator_id.clone(),
            validator_uma_id: validator.validator_uma_id.clone(),
            consensus_key_id: validator.consensus_public_key.key_id.clone(),
        }
    }

    fn relay_release_messages(
        drivers: &mut [ReleaseDriver],
        authorizer: &FrozenTypedConsensusPeerAuthorizer,
        include: impl Fn(&TypedConsensusMessage) -> bool,
    ) -> Vec<String> {
        relay_release_messages_with_delivery(drivers, authorizer, include, |_, _, _| true)
    }

    fn relay_release_messages_with_delivery(
        drivers: &mut [ReleaseDriver],
        authorizer: &FrozenTypedConsensusPeerAuthorizer,
        include: impl Fn(&TypedConsensusMessage) -> bool,
        should_deliver: impl Fn(usize, usize, &TypedConsensusMessage) -> bool,
    ) -> Vec<String> {
        let mut rejected = Vec::new();
        loop {
            let mut outbound = Vec::new();
            for (sender_index, driver) in drivers.iter_mut().enumerate() {
                for message in std::mem::take(&mut driver.egress.messages) {
                    if include(&message) {
                        outbound.push((sender_index, message));
                    }
                }
            }
            if outbound.is_empty() {
                return rejected;
            }
            for (sender_index, message) in outbound {
                let authenticated_peer =
                    authenticated_peer_for_release_driver(&drivers[sender_index]);
                for (recipient_index, recipient) in drivers.iter_mut().enumerate() {
                    if recipient_index == sender_index
                        || !should_deliver(sender_index, recipient_index, &message)
                    {
                        continue;
                    }
                    if let Err(error) = recipient.handle_envelope(
                        TypedConsensusEnvelope {
                            peer_address: format!("release-driver-{sender_index}"),
                            authenticated_peer: Some(authenticated_peer.clone()),
                            message: message.clone(),
                        },
                        authorizer,
                    ) {
                        assert!(
                            !driver_error_is_fatal(&error),
                            "release replica {recipient_index} rejected a fatal message from {sender_index}: {error}"
                        );
                        rejected.push(error);
                    }
                }
            }
        }
    }

    #[test]
    fn driver_refuses_any_noncanonical_timeout_projection() {
        let mut coordinator = coordinator_fixture();
        coordinator.consensus.protocol_config.precommit_timeout_ms = 1_501;
        let result = TypedPosyDriver::new(
            coordinator,
            EtdagProtectedInputCoordinator::at_paths(
                crate::utils::test_temp_root("typed-driver-timeout-admission"),
                crate::utils::test_temp_root("typed-driver-timeout-protected"),
            ),
            RecordingEgress::default(),
            FixedFinalityDigest,
            NoNextHeight,
        );
        let error = match result {
            Ok(_) => panic!("driver must reject a noncanonical timeout projection"),
            Err(error) => error,
        };
        assert!(error.contains("1500/1500/1500/10000"));
    }

    #[test]
    fn driver_etdag_path_requires_activation_permit_and_ready_certified_input() {
        let mut coordinator = coordinator_fixture();
        let scheduled = coordinator
            .consensus
            .proposer_for(
                &coordinator.local_context.height_context,
                coordinator.local_context.round,
            )
            .unwrap();
        coordinator.local_validator_id = scheduled.validator_id;
        let mut driver = driver_with(coordinator, 1);
        assert!(!driver.etdag_is_active());
        driver
            .configure_etdag_activation(&EtdagActivationPermit::test_only())
            .expect("a test-only activation permit enables the protected path");
        assert!(driver.etdag_is_active());
        let error = driver.tick().unwrap_err();
        assert!(error.contains("ETDAG_PROTECTED_INPUT_NOT_READY"));
    }

    #[test]
    fn driver_scheduled_proposer_egresses_deterministic_empty_core_proposal_when_etdag_inactive() {
        let mut coordinator = coordinator_fixture();
        let scheduled = coordinator
            .consensus
            .proposer_for(
                &coordinator.local_context.height_context,
                coordinator.local_context.round,
            )
            .unwrap();
        coordinator.local_validator_id = scheduled.validator_id;
        let mut driver = driver_with(coordinator, 1);

        driver
            .tick()
            .expect("deferred ETDAG must not halt core liveness");
        assert!(!driver.etdag_is_active());
        assert_eq!(driver.metrics().emitted_proposals, 1);
        let (height_context, block) = driver
            .egress
            .messages
            .iter()
            .find_map(|message| match message {
                TypedConsensusMessage::CoreProposal {
                    height_context,
                    block,
                } => Some((height_context.clone(), block.clone())),
                _ => None,
            })
            .expect("deferred ETDAG scheduler must emit the core-only wire variant");
        assert_eq!(block.header.version, 1);
        assert!(block.transactions.is_empty());
        assert_eq!(block.header.tx_count, 0);
        assert!(block.header.protected_batch.is_none());
        assert_eq!(
            driver.metrics().emitted_validation_votes,
            1,
            "the proposer must validate immediately instead of sleeping until its timeout"
        );

        // The first wire delivery can race a remote node's typed-mailbox
        // installation.  A scheduled proposer must retransmit the exact same
        // signed candidate, never mint a second proposal for this round.
        let rebroadcast_at = driver
            .last_proposal_broadcast_at
            .expect("first proposal must record its broadcast time")
            + PROPOSAL_REBROADCAST_INTERVAL;
        driver
            .tick_at(rebroadcast_at)
            .expect("the exact core proposal must be safe to retransmit");
        assert_eq!(driver.metrics().emitted_proposals, 2);
        let retransmitted = driver
            .egress
            .messages
            .iter()
            .rev()
            .find_map(|message| match message {
                TypedConsensusMessage::CoreProposal { block, .. } => Some(block.clone()),
                _ => None,
            })
            .expect("proposal retransmission must retain the core-only wire variant");
        assert_eq!(retransmitted.candidate_id(), block.candidate_id());
        assert_eq!(retransmitted, block);

        let proposal_deadline = driver.round_started_at + Duration::from_millis(1_500);
        driver
            .tick_at(proposal_deadline)
            .expect("the proposal deadline remains a fallback after the healthy-path vote");
        assert_eq!(driver.metrics().emitted_validation_votes, 1);
        assert!(matches!(
            driver.egress.messages.last(),
            Some(TypedConsensusMessage::Vote { vote }) if vote.phase == VotePhase::Validate
        ));

        let mut stale_context = height_context.clone();
        stale_context.height = Height(height_context.height.0.saturating_add(1));
        let stale_error = driver
            .coordinator
            .handle_message(TypedConsensusMessage::CoreProposal {
                height_context: stale_context,
                block: block.clone(),
            })
            .expect_err("a prior-height core proposal must not replay into the current context");
        assert!(stale_error.contains("height context"));

        let mut payload_attempt = block;
        payload_attempt.header.tx_count = 1;
        let payload_error = driver
            .coordinator
            .handle_message(TypedConsensusMessage::CoreProposal {
                height_context,
                block: payload_attempt,
            })
            .expect_err("core-only wire path must reject any transaction payload marker");
        assert!(payload_error.contains("must not contain user transactions"));
    }

    #[test]
    fn driver_deduplicates_only_exact_authenticated_vote_replays() {
        let mut coordinator = coordinator_fixture();
        let scheduled = coordinator
            .consensus
            .proposer_for(
                &coordinator.local_context.height_context,
                coordinator.local_context.round,
            )
            .expect("round-zero proposer");
        coordinator.local_validator_id = scheduled.validator_id;
        let authorizer =
            FrozenTypedConsensusPeerAuthorizer::new(coordinator.consensus.validator_set.clone())
                .expect("freeze fixture validator identities");
        let mut driver = driver_with(coordinator, 1);
        driver
            .tick()
            .expect("emit and accept local healthy proposal");
        let local_validator = driver
            .coordinator
            .consensus
            .validator_set
            .validators
            .iter()
            .find(|validator| validator.validator_id == driver.coordinator.local_validator_id)
            .expect("local signer remains in the frozen fixture set");
        let authenticated_peer = AuthenticatedTypedConsensusPeer {
            validator_id: local_validator.validator_id.clone(),
            validator_uma_id: local_validator.validator_uma_id.clone(),
            consensus_key_id: local_validator.consensus_public_key.key_id.clone(),
        };
        let validation_vote = driver
            .egress
            .messages
            .iter()
            .find(|message| {
                matches!(
                    message,
                    TypedConsensusMessage::Vote { vote }
                        if vote.phase == VotePhase::Validate
                )
            })
            .cloned()
            .expect("capture exact validation vote");

        driver
            .handle_envelope(
                TypedConsensusEnvelope {
                    peer_address: "authenticated-replay".to_string(),
                    authenticated_peer: Some(authenticated_peer.clone()),
                    message: validation_vote.clone(),
                },
                &authorizer,
            )
            .expect("an exact authenticated vote replay is an idempotent no-op");
        assert_eq!(driver.metrics().deduplicated_replays, 1);

        let mut changed_vote = validation_vote;
        let TypedConsensusMessage::Vote { vote } = &mut changed_vote else {
            unreachable!("selected message was a validation vote");
        };
        vote.aegis_pq_signature.signature_bytes[0] ^= 0x01;
        driver
            .handle_envelope(
                TypedConsensusEnvelope {
                    peer_address: "changed-replay".to_string(),
                    authenticated_peer: Some(authenticated_peer),
                    message: changed_vote,
                },
                &authorizer,
            )
            .expect_err("a changed signature must take the full verification path");
        assert_eq!(
            driver.metrics().deduplicated_replays,
            1,
            "changed bytes must never enter the replay fast path"
        );
    }

    #[test]
    fn authenticated_finalized_height_retries_are_ignored_before_pq_verification() {
        let parameters = genesis_bound_parameters();
        let (bootstrap, _genesis_anchor, deployed_genesis_state_root, coordinators, store_paths) =
            six_validator_startup_fixture(parameters.clone());
        let authorizer = FrozenTypedConsensusPeerAuthorizer::new(bootstrap.validator_set.clone())
            .expect("freeze the six Genesis-bound P2P identities");
        let mut drivers = coordinators
            .into_iter()
            .map(|coordinator| {
                release_driver_with(
                    coordinator,
                    bootstrap.clone(),
                    parameters.protocol_config.clone(),
                    deployed_genesis_state_root,
                )
            })
            .collect::<Vec<_>>();

        for driver in &mut drivers {
            driver
                .tick_at(driver.round_started_at)
                .expect("emit the first healthy proposal");
        }
        let (vote_sender, stale_vote) = drivers
            .iter()
            .enumerate()
            .find_map(|(index, driver)| {
                driver
                    .egress
                    .messages
                    .iter()
                    .find_map(|message| match message {
                        TypedConsensusMessage::Vote { vote } => Some((index, vote.clone())),
                        _ => None,
                    })
            })
            .expect("capture a height-one signed vote");
        let authenticated_peer = authenticated_peer_for_release_driver(&drivers[vote_sender]);
        let relay_errors = relay_release_messages(&mut drivers, &authorizer, |_| true);
        assert!(relay_errors.is_empty(), "{relay_errors:?}");
        assert!(drivers.iter().all(|driver| driver
            .coordinator
            .local_context
            .height_context
            .height
            == Height(2)));

        let mut corrupt_stale_vote = stale_vote;
        corrupt_stale_vote.aegis_pq_signature.signature_bytes[0] ^= 0x01;
        let event = drivers[1]
            .handle_envelope(
                TypedConsensusEnvelope {
                    peer_address: "authenticated-finalized-retry".to_string(),
                    authenticated_peer: Some(authenticated_peer),
                    message: TypedConsensusMessage::Vote {
                        vote: corrupt_stale_vote,
                    },
                },
                &authorizer,
            )
            .expect("a finalized-height retry cannot alter successor state");
        assert_eq!(
            event,
            TypedCoordinatorEvent::StaleFinalizedHeightIgnored { height: 1 }
        );
        assert_eq!(
            drivers[1].coordinator.local_context.height_context.height,
            Height(2)
        );

        drop(drivers);
        for path in store_paths {
            let _ = std::fs::remove_file(path);
        }
    }

    #[test]
    fn six_validator_driver_finalizes_healthy_round_without_waiting_for_deadlines() {
        let parameters = genesis_bound_parameters();
        let (bootstrap, _genesis_anchor, deployed_genesis_state_root, coordinators, store_paths) =
            six_validator_startup_fixture(parameters.clone());
        let authorizer = FrozenTypedConsensusPeerAuthorizer::new(bootstrap.validator_set.clone())
            .expect("freeze the six Genesis-bound P2P identities");
        let mut drivers = coordinators
            .into_iter()
            .map(|coordinator| {
                release_driver_with(
                    coordinator,
                    bootstrap.clone(),
                    parameters.protocol_config.clone(),
                    deployed_genesis_state_root,
                )
            })
            .collect::<Vec<_>>();

        for driver in &mut drivers {
            let now = driver.round_started_at;
            driver
                .tick_at(now)
                .expect("healthy-path scheduling must not require elapsed time");
        }
        let relay_errors = relay_release_messages(&mut drivers, &authorizer, |_| true);

        for (index, driver) in drivers.iter().enumerate() {
            assert_eq!(
                driver.coordinator.local_context.height_context.height,
                Height(2),
                "replica {index} did not finalize before any stage deadline: {relay_errors:?}"
            );
            assert_eq!(driver.metrics().finalized_blocks, 1);
            assert_eq!(driver.metrics().emitted_validation_votes, 1);
            assert_eq!(driver.metrics().emitted_finality_votes, 1);
            assert_eq!(driver.metrics().emitted_timeout_votes, 0);
            assert!(
                driver.local_vote_rebroadcasts.is_empty(),
                "successor reset must discard every prior-height retry"
            );
            let journal: serde_json::Value = serde_json::from_slice(
                &std::fs::read(driver.coordinator.consensus.signing_authority.path())
                    .expect("read compact signing journal"),
            )
            .expect("parse compact signing journal");
            assert_eq!(journal["retired_through_height"], 1);
            assert_eq!(
                journal["records"].as_array().map(Vec::len),
                Some(0),
                "exact envelopes must remain durable only until their height finalizes"
            );
        }

        drop(drivers);
        for path in store_paths {
            let _ = std::fs::remove_file(path);
        }
    }

    #[test]
    fn six_validator_actual_mldsa_multi_height_burn_in_preserves_round_zero_liveness() {
        const BURN_IN_HEIGHTS: u64 = 100;

        let parameters = genesis_bound_parameters();
        let (bootstrap, _genesis_anchor, deployed_genesis_state_root, coordinators, store_paths) =
            six_validator_startup_fixture(parameters.clone());
        let authorizer = FrozenTypedConsensusPeerAuthorizer::new(bootstrap.validator_set.clone())
            .expect("freeze the six Genesis-bound P2P identities");
        let mut drivers = coordinators
            .into_iter()
            .map(|coordinator| {
                release_driver_with(
                    coordinator,
                    bootstrap.clone(),
                    parameters.protocol_config.clone(),
                    deployed_genesis_state_root,
                )
            })
            .collect::<Vec<_>>();

        for finalized_height in 1..=BURN_IN_HEIGHTS {
            for driver in &mut drivers {
                let now = driver.round_started_at;
                driver
                    .tick_at(now)
                    .expect("healthy-path scheduling must remain event driven");
            }
            let relay_errors = relay_release_messages(&mut drivers, &authorizer, |_| true);
            assert!(
                relay_errors.is_empty(),
                "height {finalized_height} produced relay errors: {relay_errors:?}"
            );

            for (index, driver) in drivers.iter().enumerate() {
                assert_eq!(
                    driver.coordinator.local_context.latest_finalized_height,
                    Height(finalized_height),
                    "replica {index} diverged during burn-in"
                );
                assert_eq!(
                    driver.coordinator.local_context.height_context.height,
                    Height(finalized_height + 1),
                    "replica {index} did not install the durable successor context"
                );
                assert_eq!(
                    driver.coordinator.local_context.round,
                    Round(0),
                    "replica {index} left the healthy round-zero path"
                );
                assert_eq!(driver.metrics().emitted_timeout_votes, 0);
            }
        }

        for (index, driver) in drivers.iter().enumerate() {
            assert_eq!(
                driver.metrics().finalized_blocks,
                BURN_IN_HEIGHTS,
                "replica {index} did not finalize every burn-in height"
            );
        }

        drop(drivers);
        for path in store_paths {
            let _ = std::fs::remove_file(path);
        }
    }

    #[test]
    fn equivalent_timeout_certificates_with_different_strict_quorum_subsets_are_not_conflicts() {
        let mut driver = driver_with(coordinator_fixture(), 1);
        let height_context = driver.coordinator.local_context.height_context.clone();
        let validators = driver
            .coordinator
            .consensus
            .validator_set
            .validators
            .clone();
        let votes = {
            let (consensus, signer) = (
                &mut driver.coordinator.consensus,
                &mut driver.coordinator.signer,
            );
            validators
                .iter()
                .map(|validator| {
                    consensus.timeout_vote(signer, validator, &height_context, Round(0), None)
                })
                .collect::<Result<Vec<_>, _>>()
                .expect("fixture validators must form timeout votes")
        };
        let strict_quorum_certificate = driver
            .coordinator
            .form_timeout_certificate(&votes[..5])
            .expect("five of six active validators is the strict quorum");
        let full_quorum_certificate = driver
            .coordinator
            .form_timeout_certificate(&votes)
            .expect("all active validators may also form valid timeout evidence");

        assert_ne!(
            strict_quorum_certificate.root().unwrap(),
            full_quorum_certificate.root().unwrap(),
            "proof roots intentionally differ because their signer subsets differ"
        );
        assert!(same_timeout_certificate_subject(
            &strict_quorum_certificate,
            &full_quorum_certificate
        ));

        driver
            .coordinator
            .accept_timeout_certificate(strict_quorum_certificate.clone())
            .expect("the coordinator must verify and install the first transition");
        driver
            .install_verified_timeout_certificate(strict_quorum_certificate)
            .expect("first verified timeout certificate installs");
        driver
            .coordinator
            .accept_timeout_certificate(full_quorum_certificate.clone())
            .expect("the coordinator accepts equivalent strict-quorum replay");
        driver
            .install_verified_timeout_certificate(full_quorum_certificate)
            .expect("equivalent strict-quorum evidence must not halt liveness");

        // A timeout certificate authorizes its immediate successor round.  It
        // must be replaced, rather than treated as a conflicting source, when
        // the next verified timeout certificate closes that successor round.
        let next_round_votes = {
            let (consensus, signer) = (
                &mut driver.coordinator.consensus,
                &mut driver.coordinator.signer,
            );
            validators
                .iter()
                .map(|validator| {
                    consensus.timeout_vote(signer, validator, &height_context, Round(1), None)
                })
                .collect::<Result<Vec<_>, _>>()
                .expect("fixture validators must form the successor-round timeout votes")
        };
        let successor_round_certificate = driver
            .coordinator
            .form_timeout_certificate(&next_round_votes[..5])
            .expect("a verified successor-round timeout certificate must form");
        driver
            .coordinator
            .accept_timeout_certificate(successor_round_certificate.clone())
            .expect("the coordinator must verify and install the successor transition");
        driver
            .install_verified_timeout_certificate(successor_round_certificate.clone())
            .expect("the next sequential timeout certificate must replace the prior-round authorization");
        assert_eq!(
            driver
                .timeout_certificate
                .as_ref()
                .expect("new timeout authorization must remain installed")
                .closing_round,
            Round(1)
        );
    }

    #[test]
    fn same_round_prepared_timeout_upgrades_an_installed_no_carry_transition() {
        let mut coordinator = coordinator_fixture();
        let height_context = coordinator.local_context.height_context.clone();
        let validators = coordinator.consensus.validator_set.validators.clone();
        let scheduled = coordinator
            .consensus
            .proposer_for(&height_context, Round(0))
            .expect("round-zero proposer");
        coordinator.local_validator_id = scheduled.validator_id;
        let block = coordinator
            .propose_core_block()
            .expect("deterministic prepared candidate");
        let validation_votes = validators
            .iter()
            .map(|validator| {
                coordinator.consensus.validation_vote(
                    &mut coordinator.signer,
                    validator,
                    &block,
                    &height_context,
                )
            })
            .collect::<Result<Vec<_>, _>>()
            .expect("validation votes");
        let prepared = coordinator
            .form_validation_certificate(&validation_votes[..5])
            .expect("prepared VC");
        // Five validators report no prepared proof. The sixth reports the
        // valid VC, so two different five-of-six quorums form a no-carry and
        // a carry TC for the exact same round transition.
        let timeout_votes = validators
            .iter()
            .enumerate()
            .map(|(index, validator)| {
                coordinator.consensus.timeout_vote(
                    &mut coordinator.signer,
                    validator,
                    &height_context,
                    Round(0),
                    (index == validators.len() - 1).then_some(&prepared),
                )
            })
            .collect::<Result<Vec<_>, _>>()
            .expect("mixed timeout votes");
        let no_carry = coordinator
            .form_timeout_certificate(&timeout_votes[..5])
            .expect("no-carry strict-quorum TC");
        let carry = coordinator
            .form_timeout_certificate(&timeout_votes[1..])
            .expect("carry strict-quorum TC");

        assert!(same_timeout_transition_context(&no_carry, &carry));
        assert!(no_carry.carry_forward_candidate_id.is_none());
        assert_eq!(
            carry.carry_forward_candidate_id.as_ref(),
            Some(&prepared.candidate_id)
        );

        let mut driver = driver_with(coordinator, 1);
        driver
            .coordinator
            .accept_timeout_certificate(no_carry.clone())
            .expect("install no-carry transition in the coordinator");
        driver
            .install_verified_timeout_certificate(no_carry)
            .expect("install no-carry transition in the driver");
        driver
            .coordinator
            .accept_timeout_certificate(carry.clone())
            .expect("verify stronger same-round timeout evidence");
        driver
            .install_verified_timeout_certificate(carry.clone())
            .expect("stronger carry evidence must upgrade without terminating");

        assert_eq!(
            driver
                .timeout_certificate
                .as_ref()
                .and_then(|certificate| certificate.carry_forward_candidate_id.as_ref()),
            Some(&prepared.candidate_id)
        );
        assert_eq!(driver.coordinator.local_context.round, carry.next_round);
    }

    #[test]
    fn verified_later_timeout_certificate_recovers_a_missed_round_transition() {
        let mut driver = driver_with(coordinator_fixture(), 1);
        let height_context = driver.coordinator.local_context.height_context.clone();
        let validators = driver
            .coordinator
            .consensus
            .validator_set
            .validators
            .clone();

        let first_round_votes = {
            let (consensus, signer) = (
                &mut driver.coordinator.consensus,
                &mut driver.coordinator.signer,
            );
            validators
                .iter()
                .map(|validator| {
                    consensus.timeout_vote(signer, validator, &height_context, Round(0), None)
                })
                .collect::<Result<Vec<_>, _>>()
                .expect("fixture validators must form first-round timeout votes")
        };
        let first_certificate = driver
            .coordinator
            .form_timeout_certificate(&first_round_votes[..5])
            .expect("first-round strict quorum certificate");
        driver
            .coordinator
            .accept_timeout_certificate(first_certificate.clone())
            .expect("coordinator installs first transition");
        driver
            .install_verified_timeout_certificate(first_certificate)
            .expect("driver installs first transition");
        assert_eq!(driver.coordinator.local_context.round, Round(1));

        let later_round_votes = {
            let (consensus, signer) = (
                &mut driver.coordinator.consensus,
                &mut driver.coordinator.signer,
            );
            validators
                .iter()
                .map(|validator| {
                    consensus.timeout_vote(signer, validator, &height_context, Round(2), None)
                })
                .collect::<Result<Vec<_>, _>>()
                .expect("fixture validators must form later-round timeout votes")
        };
        let later_certificate = driver
            .coordinator
            .form_timeout_certificate(&later_round_votes[..5])
            .expect("later-round strict quorum certificate");
        driver
            .coordinator
            .accept_timeout_certificate(later_certificate.clone())
            .expect("verified later TC recovers the coordinator");
        driver
            .install_verified_timeout_certificate(later_certificate)
            .expect("driver accepts the coordinator-authorized recovery");

        assert_eq!(driver.coordinator.local_context.round, Round(3));
        assert_eq!(
            driver
                .timeout_certificate
                .as_ref()
                .expect("latest timeout authorization remains installed")
                .closing_round,
            Round(2)
        );
    }

    #[test]
    fn verified_round_one_hundred_timeout_recovers_and_persists_round_authority() {
        let mut driver = driver_with(coordinator_fixture(), 1);
        let height_context = driver.coordinator.local_context.height_context.clone();
        let validators = driver
            .coordinator
            .consensus
            .validator_set
            .validators
            .clone();
        let votes = {
            let (consensus, signer) = (
                &mut driver.coordinator.consensus,
                &mut driver.coordinator.signer,
            );
            validators
                .iter()
                .map(|validator| {
                    consensus.timeout_vote(signer, validator, &height_context, Round(100), None)
                })
                .collect::<Result<Vec<_>, _>>()
                .expect("actual ML-DSA timeout votes form at high round")
        };
        let certificate = driver
            .coordinator
            .form_timeout_certificate(&votes[..5])
            .expect("strict-quorum high-round TC");
        driver
            .coordinator
            .accept_timeout_certificate(certificate.clone())
            .expect("verified high-round TC recovers missed transitions");
        driver
            .install_verified_timeout_certificate(certificate.clone())
            .expect("high-round authority becomes atomic durable state");

        assert_eq!(driver.coordinator.local_context.round, Round(101));
        let recovered = driver
            .coordinator
            .consensus
            .signing_authority
            .recovery_checkpoint()
            .unwrap()
            .expect("atomic recovery checkpoint");
        assert_eq!(recovered.current_round, Round(101));
        assert_eq!(recovered.highest_tc.as_ref(), Some(&certificate));
    }

    #[test]
    fn mixed_prepared_and_plain_timeout_votes_advance_one_round() {
        let mut coordinator = coordinator_fixture();
        let scheduled = coordinator
            .consensus
            .proposer_for(&coordinator.local_context.height_context, Round(0))
            .expect("round-zero proposer");
        coordinator.local_validator_id = scheduled.validator_id;
        let mut driver = driver_with(coordinator, 1);
        driver.tick().expect("emit deterministic core proposal");
        let block = driver
            .current_round_proposal()
            .expect("local proposal is accepted")
            .clone();
        let validators = driver
            .coordinator
            .consensus
            .validator_set
            .validators
            .clone();
        let height_context = driver.coordinator.local_context.height_context.clone();
        let validation_votes = validators
            .iter()
            .map(|validator| {
                driver.coordinator.consensus.validation_vote(
                    &mut driver.coordinator.signer,
                    validator,
                    &block,
                    &height_context,
                )
            })
            .collect::<Result<Vec<_>, _>>()
            .expect("fixture validation votes");
        let prepared = driver
            .coordinator
            .form_validation_certificate(&validation_votes[..5])
            .expect("strict-quorum VC");
        let timeout_votes = validators
            .iter()
            .enumerate()
            .map(|(index, validator)| {
                driver.coordinator.consensus.timeout_vote(
                    &mut driver.coordinator.signer,
                    validator,
                    &height_context,
                    Round(0),
                    (index >= 3).then_some(&prepared),
                )
            })
            .collect::<Result<Vec<_>, _>>()
            .expect("mixed timeout subjects remain individually valid");

        for vote in timeout_votes.into_iter().take(5) {
            driver
                .record_verified_vote(vote)
                .expect("same-round timeout votes must share one quorum collector");
        }

        let certificate = driver
            .timeout_certificate
            .as_ref()
            .expect("three plain plus two prepared timeouts form a strict-quorum TC");
        assert_eq!(certificate.certificate_version, 2);
        assert_eq!(certificate.closing_round, Round(0));
        assert_eq!(certificate.next_round, Round(1));
        assert_eq!(
            certificate.carry_forward_candidate_id.as_ref(),
            Some(&prepared.candidate_id)
        );
        assert_eq!(
            certificate.highest_prepared_vc_root,
            Some(prepared.root().unwrap())
        );
        assert_eq!(certificate.timeout_vote_subjects.len(), 5);
        assert_eq!(driver.coordinator.local_context.round, Round(1));
    }

    #[test]
    fn timeout_split_extremes_and_serialization_order_preserve_safety_and_liveness() {
        for carry_start in [5usize, 3usize] {
            let mut coordinator = coordinator_fixture();
            let scheduled = coordinator
                .consensus
                .proposer_for(&coordinator.local_context.height_context, Round(0))
                .expect("round-zero proposer");
            coordinator.local_validator_id = scheduled.validator_id;
            let mut driver = driver_with(coordinator, 1);
            driver.tick().expect("emit deterministic core proposal");
            let block = driver
                .current_round_proposal()
                .expect("local proposal is accepted")
                .clone();
            let validators = driver
                .coordinator
                .consensus
                .validator_set
                .validators
                .clone();
            let height_context = driver.coordinator.local_context.height_context.clone();
            let validation_votes = validators
                .iter()
                .map(|validator| {
                    driver.coordinator.consensus.validation_vote(
                        &mut driver.coordinator.signer,
                        validator,
                        &block,
                        &height_context,
                    )
                })
                .collect::<Result<Vec<_>, _>>()
                .expect("fixture validation votes");
            let prepared = driver
                .coordinator
                .form_validation_certificate(&validation_votes[..5])
                .expect("strict-quorum VC");
            let timeout_votes = validators
                .iter()
                .enumerate()
                .map(|(index, validator)| {
                    driver.coordinator.consensus.timeout_vote(
                        &mut driver.coordinator.signer,
                        validator,
                        &height_context,
                        Round(0),
                        (index >= carry_start).then_some(&prepared),
                    )
                })
                .collect::<Result<Vec<_>, _>>()
                .expect("plain and carry reports are individually valid");
            let forward = driver
                .coordinator
                .form_timeout_certificate(&timeout_votes)
                .expect("the six timeout reports form one transition");
            let mut reversed_votes = timeout_votes.clone();
            reversed_votes.reverse();
            let reversed = driver
                .coordinator
                .form_timeout_certificate(&reversed_votes)
                .expect("arrival order cannot change a valid transition");

            assert_eq!(forward.root().unwrap(), reversed.root().unwrap());
            assert_eq!(
                forward.carry_forward_candidate_id.as_ref(),
                Some(&prepared.candidate_id),
                "both 5/1 and 3/3 splits preserve the strongest prepared evidence"
            );
            driver
                .coordinator
                .accept_timeout_certificate(forward.clone())
                .expect("canonical timeout transition verifies");
            driver
                .install_verified_timeout_certificate(forward)
                .expect("canonical timeout transition installs");
            assert_eq!(driver.coordinator.local_context.round, Round(1));
        }
    }

    #[test]
    fn timeout_certificate_canonicalizes_vc_roots_for_one_prepared_candidate() {
        let mut coordinator = coordinator_fixture();
        let scheduled = coordinator
            .consensus
            .proposer_for(&coordinator.local_context.height_context, Round(0))
            .expect("round-zero proposer");
        coordinator.local_validator_id = scheduled.validator_id;
        let mut driver = driver_with(coordinator, 1);
        driver.tick().expect("emit deterministic core proposal");
        let block = driver
            .current_round_proposal()
            .expect("local proposal is accepted")
            .clone();
        let validators = driver
            .coordinator
            .consensus
            .validator_set
            .validators
            .clone();
        let height_context = driver.coordinator.local_context.height_context.clone();
        let validation_votes = validators
            .iter()
            .map(|validator| {
                driver.coordinator.consensus.validation_vote(
                    &mut driver.coordinator.signer,
                    validator,
                    &block,
                    &height_context,
                )
            })
            .collect::<Result<Vec<_>, _>>()
            .expect("fixture validation votes");
        let prepared_a = driver
            .coordinator
            .form_validation_certificate(&validation_votes[..5])
            .expect("first strict-quorum VC");
        let prepared_b = driver
            .coordinator
            .form_validation_certificate(&validation_votes[1..])
            .expect("second strict-quorum VC");
        let root_a = prepared_a.root().expect("first VC root");
        let root_b = prepared_b.root().expect("second VC root");
        assert_ne!(root_a, root_b);
        assert_eq!(prepared_a.candidate_id, prepared_b.candidate_id);

        let timeout_votes = validators
            .iter()
            .enumerate()
            .map(|(index, validator)| {
                driver.coordinator.consensus.timeout_vote(
                    &mut driver.coordinator.signer,
                    validator,
                    &height_context,
                    Round(0),
                    Some(if index < 3 { &prepared_a } else { &prepared_b }),
                )
            })
            .collect::<Result<Vec<_>, _>>()
            .expect("same-candidate timeout votes remain individually valid");
        let certificate = driver
            .coordinator
            .form_timeout_certificate(&timeout_votes[..5])
            .expect("different VC roots for one candidate form a TC");

        assert_eq!(
            certificate.carry_forward_candidate_id.as_ref(),
            Some(&prepared_a.candidate_id)
        );
        assert_eq!(
            certificate.highest_prepared_vc_root,
            Some(std::cmp::min(root_a, root_b))
        );
        assert_eq!(certificate.timeout_vote_subjects.len(), 5);
    }

    #[test]
    fn different_valid_vc_root_for_same_candidate_requests_exact_recovery() {
        let mut coordinator = coordinator_fixture();
        let scheduled = coordinator
            .consensus
            .proposer_for(&coordinator.local_context.height_context, Round(0))
            .expect("round-zero proposer");
        coordinator.local_validator_id = scheduled.validator_id;
        let mut driver = driver_with(coordinator, 1);
        driver.tick().expect("emit deterministic core proposal");
        let block = driver
            .current_round_proposal()
            .expect("local proposal is accepted")
            .clone();
        let validators = driver
            .coordinator
            .consensus
            .validator_set
            .validators
            .clone();
        let height_context = driver.coordinator.local_context.height_context.clone();
        let validation_votes = validators
            .iter()
            .map(|validator| {
                driver.coordinator.consensus.validation_vote(
                    &mut driver.coordinator.signer,
                    validator,
                    &block,
                    &height_context,
                )
            })
            .collect::<Result<Vec<_>, _>>()
            .expect("fixture validation votes");
        let local_certificate = driver
            .coordinator
            .form_validation_certificate(&validation_votes[..5])
            .expect("first valid strict-quorum VC");
        let tc_certificate = driver
            .coordinator
            .form_validation_certificate(&validation_votes[1..])
            .expect("second valid strict-quorum VC");
        assert_eq!(local_certificate.candidate_id, tc_certificate.candidate_id);
        assert_ne!(
            local_certificate.root().unwrap(),
            tc_certificate.root().unwrap()
        );
        driver
            .record_validation_certificate(local_certificate.clone())
            .expect("persist the locally observed VC");

        let timeout_votes = validators
            .iter()
            .map(|validator| {
                driver.coordinator.consensus.timeout_vote(
                    &mut driver.coordinator.signer,
                    validator,
                    &height_context,
                    Round(0),
                    Some(&tc_certificate),
                )
            })
            .collect::<Result<Vec<_>, _>>()
            .expect("fixture timeout votes");
        let timeout_certificate = driver
            .coordinator
            .form_timeout_certificate(&timeout_votes[..5])
            .expect("TC binds the other valid VC root");
        driver
            .coordinator
            .accept_timeout_certificate(timeout_certificate.clone())
            .expect("coordinator accepts the TC");
        driver
            .install_verified_timeout_certificate(timeout_certificate.clone())
            .expect("VC-root disagreement is a recoverable proof gap");

        let persisted = driver
            .prepared_store
            .recover()
            .expect("read prepared record")
            .expect("local prepared record remains durable");
        assert_eq!(
            persisted.validation_certificate.root().unwrap(),
            local_certificate.root().unwrap()
        );
        assert!(persisted.timeout_certificate.is_none());

        let round_one_proposer = driver
            .coordinator
            .consensus
            .proposer_for(&height_context, Round(1))
            .expect("round-one proposer");
        driver.coordinator.local_validator_id = round_one_proposer.validator_id;
        driver.egress.messages.clear();
        driver
            .try_emit_scheduled_proposal()
            .expect("mismatched proof root requests exact recovery without halting");
        assert!(driver.egress.messages.iter().any(|message| matches!(
            message,
            TypedConsensusMessage::PreparedCertificateRequest {
                timeout_certificate: requested
            } if requested == &timeout_certificate
        )));
        assert!(!driver.egress.messages.iter().any(|message| matches!(
            message,
            TypedConsensusMessage::CoreProposal { .. } | TypedConsensusMessage::Proposal { .. }
        )));
    }

    #[test]
    fn no_carry_timeout_does_not_corrupt_local_prepared_record() {
        let mut coordinator = coordinator_fixture();
        let scheduled = coordinator
            .consensus
            .proposer_for(&coordinator.local_context.height_context, Round(0))
            .expect("round-zero proposer");
        coordinator.local_validator_id = scheduled.validator_id;
        let mut driver = driver_with(coordinator, 1);
        driver.tick().expect("emit deterministic core proposal");
        let block = driver
            .current_round_proposal()
            .expect("local proposal is accepted")
            .clone();
        let validators = driver
            .coordinator
            .consensus
            .validator_set
            .validators
            .clone();
        let height_context = driver.coordinator.local_context.height_context.clone();
        let validation_votes = validators
            .iter()
            .map(|validator| {
                driver.coordinator.consensus.validation_vote(
                    &mut driver.coordinator.signer,
                    validator,
                    &block,
                    &height_context,
                )
            })
            .collect::<Result<Vec<_>, _>>()
            .expect("fixture validation votes");
        let local_certificate = driver
            .coordinator
            .form_validation_certificate(&validation_votes[..5])
            .expect("strict-quorum VC");
        driver
            .record_validation_certificate(local_certificate.clone())
            .expect("persist the locally observed VC");

        let timeout_votes = validators
            .iter()
            .map(|validator| {
                driver.coordinator.consensus.timeout_vote(
                    &mut driver.coordinator.signer,
                    validator,
                    &height_context,
                    Round(0),
                    None,
                )
            })
            .collect::<Result<Vec<_>, _>>()
            .expect("fixture plain timeout votes");
        let timeout_certificate = driver
            .coordinator
            .form_timeout_certificate(&timeout_votes[..5])
            .expect("no-carry TC");
        driver
            .coordinator
            .accept_timeout_certificate(timeout_certificate.clone())
            .expect("coordinator accepts the TC");
        driver
            .install_verified_timeout_certificate(timeout_certificate)
            .expect("unrelated TC must not make prepared persistence fatal");

        let persisted = driver
            .prepared_store
            .recover()
            .expect("read prepared record")
            .expect("local prepared record remains durable");
        assert_eq!(
            persisted.validation_certificate.root().unwrap(),
            local_certificate.root().unwrap()
        );
        assert!(persisted.timeout_certificate.is_none());
    }

    #[test]
    fn future_round_validation_certificate_waits_for_its_proposal_envelope() {
        let mut coordinator = coordinator_fixture();
        let scheduled = coordinator
            .consensus
            .proposer_for(&coordinator.local_context.height_context, Round(0))
            .expect("round-zero proposer");
        coordinator.local_validator_id = scheduled.validator_id;
        let mut driver = driver_with(coordinator, 1);
        driver.tick().expect("emit deterministic core proposal");
        let current_block = driver
            .current_round_proposal()
            .expect("local proposal is accepted")
            .clone();
        let validators = driver
            .coordinator
            .consensus
            .validator_set
            .validators
            .clone();
        let height_context = driver.coordinator.local_context.height_context.clone();
        let round_zero_votes = validators
            .iter()
            .map(|validator| {
                driver.coordinator.consensus.validation_vote(
                    &mut driver.coordinator.signer,
                    validator,
                    &current_block,
                    &height_context,
                )
            })
            .collect::<Result<Vec<_>, _>>()
            .expect("fixture round-zero validation votes");
        let round_zero_certificate = driver
            .coordinator
            .form_validation_certificate(&round_zero_votes[..5])
            .expect("round-zero strict-quorum VC");
        let timeout_votes = validators
            .iter()
            .map(|validator| {
                driver.coordinator.consensus.timeout_vote(
                    &mut driver.coordinator.signer,
                    validator,
                    &height_context,
                    Round(0),
                    Some(&round_zero_certificate),
                )
            })
            .collect::<Result<Vec<_>, _>>()
            .expect("fixture round-zero timeout votes");
        let timeout_certificate = driver
            .coordinator
            .form_timeout_certificate(&timeout_votes[..5])
            .expect("strict-quorum TC authorizes round one");
        driver
            .coordinator
            .accept_timeout_certificate(timeout_certificate.clone())
            .expect("advance the verified fixture to round one");
        driver
            .install_verified_timeout_certificate(timeout_certificate.clone())
            .expect("install the same verified round authority in durable driver recovery");
        let round_one_proposer = driver
            .coordinator
            .consensus
            .proposer_for(&height_context, Round(1))
            .expect("round-one proposer");
        driver.coordinator.local_validator_id = round_one_proposer.validator_id;
        let future_block = driver
            .coordinator
            .carry_forward_prepared_block(
                &current_block,
                &round_zero_certificate,
                &timeout_certificate,
            )
            .expect("construct the verified round-one carried envelope");
        let candidate_id = future_block.candidate_id().expect("future candidate ID");
        assert_eq!(
            candidate_id,
            current_block.candidate_id().expect("current candidate ID")
        );

        let validation_votes = validators
            .iter()
            .map(|validator| {
                driver.coordinator.consensus.validation_vote(
                    &mut driver.coordinator.signer,
                    validator,
                    &future_block,
                    &height_context,
                )
            })
            .collect::<Result<Vec<_>, _>>()
            .expect("fixture future-round validation votes");
        let future_certificate = driver
            .coordinator
            .form_validation_certificate(&validation_votes[..5])
            .expect("future-round strict-quorum VC");

        // Reproduce authenticated delivery ordering: the future VC reaches
        // this replica before the matching carried proposal envelope.
        driver
            .coordinator
            .accepted_proposals
            .insert(candidate_id.clone(), current_block);
        driver
            .record_validation_certificate(future_certificate.clone())
            .expect("verified future VC is retained pending its proposal");
        assert!(driver.prepared_certificate.is_none());
        assert_eq!(
            driver.pending_validation_certificates.get(&candidate_id),
            Some(&future_certificate)
        );

        driver
            .coordinator
            .record_accepted_proposal(&future_block)
            .expect("matching future proposal replaces the older envelope");
        driver
            .install_pending_validation_certificate(&candidate_id, Round(1))
            .expect("matching proposal installs the pending VC");
        assert_eq!(
            driver.prepared_certificate.as_ref(),
            Some(&future_certificate)
        );
        assert!(!driver
            .pending_validation_certificates
            .contains_key(&candidate_id));
    }

    #[test]
    fn prepared_candidate_and_round_authority_survive_driver_restart() {
        let mut coordinator = coordinator_fixture();
        let scheduled = coordinator
            .consensus
            .proposer_for(&coordinator.local_context.height_context, Round(0))
            .expect("round-zero proposer");
        coordinator.local_validator_id = scheduled.validator_id;
        let mut driver = driver_with(coordinator, 1);
        driver.tick().expect("emit deterministic core proposal");
        let block = driver
            .current_round_proposal()
            .expect("local proposal is accepted")
            .clone();
        let validators = driver
            .coordinator
            .consensus
            .validator_set
            .validators
            .clone();
        let height_context = driver.coordinator.local_context.height_context.clone();
        let validation_votes = validators
            .iter()
            .map(|validator| {
                driver.coordinator.consensus.validation_vote(
                    &mut driver.coordinator.signer,
                    validator,
                    &block,
                    &height_context,
                )
            })
            .collect::<Result<Vec<_>, _>>()
            .expect("fixture validation votes");
        let validation_certificate = driver
            .coordinator
            .form_validation_certificate(&validation_votes[..5])
            .expect("strict-quorum VC");
        driver
            .record_validation_certificate(validation_certificate.clone())
            .expect("prepared VC becomes durable");
        let timeout_votes = validators
            .iter()
            .map(|validator| {
                driver.coordinator.consensus.timeout_vote(
                    &mut driver.coordinator.signer,
                    validator,
                    &height_context,
                    Round(0),
                    Some(&validation_certificate),
                )
            })
            .collect::<Result<Vec<_>, _>>()
            .expect("fixture timeout votes");
        let timeout_certificate = driver
            .coordinator
            .form_timeout_certificate(&timeout_votes[..5])
            .expect("strict-quorum TC");
        driver
            .coordinator
            .accept_timeout_certificate(timeout_certificate.clone())
            .expect("TC advances live round");
        driver
            .install_verified_timeout_certificate(timeout_certificate.clone())
            .expect("TC and prepared state become durable together");
        assert!(driver.prepared_store.recover().unwrap().is_some());

        let coordinator = driver.coordinator;
        let finality_path = coordinator.finality_store.path().to_path_buf();
        let TypedPosyCoordinator {
            consensus,
            signer,
            local_validator_id,
            mut local_context,
            execution_state,
            etdag_parameters,
            finality_store,
            ..
        } = coordinator;
        local_context.round = Round(0);
        let mut restarted_consensus = ProofOfSynergyBft::new(
            &consensus.verifier,
            consensus.validator_set,
            consensus.cluster_map,
            consensus.protocol_config,
        );
        restarted_consensus.signing_authority = consensus.signing_authority;
        let restarted_coordinator = TypedPosyCoordinator::new(
            restarted_consensus,
            signer,
            local_validator_id,
            local_context,
            execution_state,
            etdag_parameters,
            finality_store,
        )
        .expect("rebuild coordinator from finalized state");
        let restarted = driver_with(restarted_coordinator, 1);
        assert_eq!(restarted.coordinator.local_context.round, Round(1));
        assert_eq!(
            restarted
                .prepared_certificate
                .as_ref()
                .expect("restart restored the prepared VC"),
            &validation_certificate
        );
        assert_eq!(
            restarted
                .timeout_certificate
                .as_ref()
                .expect("restart restored round authority"),
            &timeout_certificate
        );
        assert!(restarted
            .coordinator
            .accepted_proposals
            .contains_key(&validation_certificate.candidate_id));

        drop(restarted);
        let _ = std::fs::remove_file(finality_path.with_extension("prepared.json"));
        let _ = std::fs::remove_file(finality_path);
    }

    #[test]
    fn six_validator_driver_survives_startup_loss_two_timeout_rounds_and_first_finality() {
        let parameters = genesis_bound_parameters();
        let (bootstrap, _genesis_anchor, deployed_genesis_state_root, coordinators, store_paths) =
            six_validator_startup_fixture(parameters.clone());
        let authorizer = FrozenTypedConsensusPeerAuthorizer::new(bootstrap.validator_set.clone())
            .expect("freeze the six Genesis-bound P2P identities");
        let mut drivers = coordinators
            .into_iter()
            .map(|coordinator| {
                release_driver_with(
                    coordinator,
                    bootstrap.clone(),
                    parameters.protocol_config.clone(),
                    deployed_genesis_state_root,
                )
            })
            .collect::<Vec<_>>();

        // Model the actual startup race: the scheduled height-one proposal is
        // emitted before any remote typed mailbox is ready, so every initial
        // proposal delivery is lost.  No live node is involved in this test.
        for driver in &mut drivers {
            let now = driver.round_started_at;
            driver
                .tick_at(now)
                .expect("initial scheduler tick must be safe");
        }
        for driver in &mut drivers {
            driver.egress.messages.clear();
        }

        // Exercise two complete no-proposal timeout transitions.  Relay only
        // timeout evidence so the test proves that sequential certificates
        // replace their predecessor authorization and that distinct valid
        // signer subsets never create a fatal driver source conflict.
        for expected_round in [Round(1), Round(2)] {
            for driver in &mut drivers {
                let round_cap = Duration::from_millis(
                    driver
                        .coordinator
                        .consensus
                        .protocol_config
                        .max_round_timeout_ms,
                );
                driver
                    .tick_at(driver.round_started_at + round_cap)
                    .expect("timeout scheduling must emit a vote without halting");
            }
            let _ = relay_release_messages(&mut drivers, &authorizer, |message| {
                matches!(
                    message,
                    TypedConsensusMessage::Vote { vote } if vote.phase == VotePhase::Timeout
                ) || matches!(message, TypedConsensusMessage::TimeoutCertificate { .. })
            });
            for driver in &drivers {
                assert_eq!(driver.coordinator.local_context.round, expected_round);
                assert_eq!(
                    driver
                        .timeout_certificate
                        .as_ref()
                        .expect("the sequential timeout authorization remains available")
                        .next_round,
                    expected_round
                );
            }
        }

        // Restore delivery at round two and prove the exact driver path can
        // form the height-one validation certificate, finality QC, persist
        // finality, and derive the next Genesis-bound height authority.
        for driver in &mut drivers {
            let now = driver.round_started_at;
            driver
                .tick_at(now)
                .expect("round-two scheduled proposal must be emitted");
        }
        let mut relay_errors = relay_release_messages(&mut drivers, &authorizer, |_| true);
        for driver in &mut drivers {
            driver
                .tick_at(driver.round_started_at + Duration::from_millis(1_500))
                .expect("validated proposal must emit its local validation vote");
        }
        relay_errors.extend(relay_release_messages(&mut drivers, &authorizer, |_| true));
        for driver in &mut drivers {
            driver
                .tick_at(driver.round_started_at + Duration::from_millis(3_000))
                .expect("prepared proposal must emit its local finality vote");
        }
        relay_errors.extend(relay_release_messages(&mut drivers, &authorizer, |_| true));

        for (replica_index, driver) in drivers.iter().enumerate() {
            assert_eq!(
                driver.metrics().finalized_blocks,
                1,
                "replica {replica_index} did not finalize after startup loss recovery: metrics={:?}, round={:?}, stage={:?}, prepared={}, finality={}, relay_errors={:?}",
                driver.metrics(),
                driver.coordinator.local_context.round,
                driver.stage,
                driver.prepared_certificate.is_some(),
                driver.finality_certificate.is_some(),
                relay_errors,
            );
            assert_eq!(
                driver.coordinator.local_context.height_context.height,
                Height(2)
            );
            assert_eq!(
                driver
                    .coordinator
                    .finality_store
                    .latest()
                    .expect("read durable typed finality")
                    .expect("first block must be durable")
                    .height,
                Height(1)
            );
        }
        drop(drivers);
        for path in store_paths {
            let _ = std::fs::remove_file(path);
        }
    }

    #[test]
    fn six_validator_driver_recovers_carried_candidate_for_missing_next_proposer() {
        let parameters = genesis_bound_parameters();
        let (bootstrap, _genesis_anchor, deployed_genesis_state_root, coordinators, store_paths) =
            six_validator_startup_fixture(parameters.clone());
        let authorizer = FrozenTypedConsensusPeerAuthorizer::new(bootstrap.validator_set.clone())
            .expect("freeze the six Genesis-bound P2P identities");
        let mut drivers = coordinators
            .into_iter()
            .map(|coordinator| {
                release_driver_with(
                    coordinator,
                    bootstrap.clone(),
                    parameters.protocol_config.clone(),
                    deployed_genesis_state_root,
                )
            })
            .collect::<Vec<_>>();
        let round_one_proposer = drivers[0]
            .coordinator
            .consensus
            .proposer_for(
                &drivers[0].coordinator.local_context.height_context,
                Round(1),
            )
            .expect("round-one proposer");
        let missing_index = drivers
            .iter()
            .position(|driver| {
                driver.coordinator.local_validator_id == round_one_proposer.validator_id
            })
            .expect("round-one proposer has a release driver");

        for driver in &mut drivers {
            let now = driver.round_started_at;
            driver.tick_at(now).expect("round-zero scheduling");
        }
        let _ = relay_release_messages_with_delivery(
            &mut drivers,
            &authorizer,
            |message| {
                matches!(message, TypedConsensusMessage::CoreProposal { .. })
                    || matches!(
                        message,
                        TypedConsensusMessage::Vote { vote }
                            if vote.phase == VotePhase::Validate
                    )
                    || matches!(message, TypedConsensusMessage::ValidationCertificate { .. })
            },
            |_, recipient, _| recipient != missing_index,
        );

        assert!(drivers[missing_index].prepared_certificate.is_none());
        assert_eq!(
            drivers
                .iter()
                .filter(|driver| driver.prepared_certificate.is_some())
                .count(),
            5
        );

        for driver in &mut drivers {
            let cap = Duration::from_millis(
                driver
                    .coordinator
                    .consensus
                    .protocol_config
                    .max_round_timeout_ms,
            );
            driver
                .tick_at(driver.round_started_at + cap)
                .expect("prepared replicas must time out without finality delivery");
        }
        let relay_errors = relay_release_messages(&mut drivers, &authorizer, |message| {
            matches!(
                message,
                TypedConsensusMessage::Vote { vote } if vote.phase == VotePhase::Timeout
            ) || matches!(
                message,
                TypedConsensusMessage::TimeoutCertificate { .. }
                    | TypedConsensusMessage::PreparedCertificateRequest { .. }
                    | TypedConsensusMessage::PreparedCertificateResponse { .. }
            )
        });
        assert!(
            relay_errors.is_empty(),
            "authenticated prepared recovery must not be rejected: {relay_errors:?}"
        );
        assert_eq!(
            drivers[missing_index].coordinator.local_context.round,
            Round(1)
        );
        assert!(drivers[missing_index].prepared_certificate.is_some());
        assert!(drivers[missing_index]
            .coordinator
            .accepted_proposals
            .contains_key(
                &drivers[missing_index]
                    .prepared_certificate
                    .as_ref()
                    .expect("recovered VC")
                    .candidate_id
            ));

        for driver in &mut drivers {
            let now = driver.round_started_at;
            driver
                .tick_at(now)
                .expect("the recovered round-one proposer must carry the candidate");
        }
        let mut relay_errors = relay_release_messages(&mut drivers, &authorizer, |_| true);
        for driver in &mut drivers {
            driver
                .tick_at(driver.round_started_at + Duration::from_millis(1_500))
                .expect("carried proposal validation");
        }
        relay_errors.extend(relay_release_messages(&mut drivers, &authorizer, |_| true));
        for driver in &mut drivers {
            driver
                .tick_at(driver.round_started_at + Duration::from_millis(3_000))
                .expect("carried proposal finality");
        }
        relay_errors.extend(relay_release_messages(&mut drivers, &authorizer, |_| true));
        for (index, driver) in drivers.iter().enumerate() {
            assert_eq!(
                driver.metrics().finalized_blocks,
                1,
                "replica {index} did not finalize recovered carry-forward: {relay_errors:?}"
            );
            assert_eq!(
                driver.coordinator.local_context.height_context.height,
                Height(2)
            );
        }

        drop(drivers);
        for path in store_paths {
            let _ = std::fs::remove_file(path.with_extension("prepared.json"));
            let _ = std::fs::remove_file(path);
        }
    }

    #[test]
    fn six_validator_driver_recovers_a_missed_finality_qc_then_continues_together() {
        let parameters = genesis_bound_parameters();
        let (bootstrap, _genesis_anchor, deployed_genesis_state_root, coordinators, store_paths) =
            six_validator_startup_fixture(parameters.clone());
        let authorizer = FrozenTypedConsensusPeerAuthorizer::new(bootstrap.validator_set.clone())
            .expect("freeze the six Genesis-bound P2P identities");
        let mut drivers = coordinators
            .into_iter()
            .map(|coordinator| {
                release_driver_with(
                    coordinator,
                    bootstrap.clone(),
                    parameters.protocol_config.clone(),
                    deployed_genesis_state_root,
                )
            })
            .collect::<Vec<_>>();

        // Validator zero misses two entire timeout transitions while the
        // other five form the exact strict quorum and finalize in round two.
        // This reproduces a restarted replica holding only an older local
        // round while its peers have durable finality from a much later round.
        for driver in &mut drivers[1..] {
            let now = driver.round_started_at;
            driver
                .tick_at(now)
                .expect("initial proposal scheduling remains local");
        }
        for driver in &mut drivers {
            driver.egress.messages.clear();
        }
        let mut relay_errors = Vec::new();
        let mut final_round = Round(0);
        loop {
            final_round = Round(final_round.0.saturating_add(1));
            for driver in &mut drivers[1..] {
                let round_cap = Duration::from_millis(
                    driver
                        .coordinator
                        .consensus
                        .protocol_config
                        .max_round_timeout_ms,
                );
                driver
                    .tick_at(driver.round_started_at + round_cap)
                    .expect("caught-up replicas emit timeout votes");
            }
            relay_errors.extend(relay_release_messages_with_delivery(
                &mut drivers,
                &authorizer,
                |message| {
                    matches!(
                        message,
                        TypedConsensusMessage::Vote { vote } if vote.phase == VotePhase::Timeout
                    ) || matches!(message, TypedConsensusMessage::TimeoutCertificate { .. })
                },
                |_, recipient, _| recipient != 0,
            ));
            assert_eq!(drivers[0].coordinator.local_context.round, Round(0));
            for driver in &drivers[1..] {
                assert_eq!(driver.coordinator.local_context.round, final_round);
            }
            let scheduled = drivers[1]
                .coordinator
                .consensus
                .proposer_for(
                    &drivers[1].coordinator.local_context.height_context,
                    final_round,
                )
                .expect("finalized-round proposer");
            if final_round.0 >= 2
                && scheduled.validator_id != drivers[0].coordinator.local_validator_id
            {
                break;
            }
            assert!(
                final_round.0 < 6,
                "fixture must schedule a caught-up proposer"
            );
        }

        for driver in &mut drivers[1..] {
            let now = driver.round_started_at;
            driver
                .tick_at(now)
                .expect("round-two scheduled proposal is emitted");
        }
        relay_errors.extend(relay_release_messages_with_delivery(
            &mut drivers,
            &authorizer,
            |_| true,
            |_, recipient, _| recipient != 0,
        ));

        assert_eq!(
            drivers[0].coordinator.local_context.latest_finalized_height,
            Height(0)
        );
        for driver in &drivers[1..] {
            assert_eq!(
                driver.coordinator.local_context.latest_finalized_height,
                Height(1)
            );
        }

        // The lagging validator emits a bounded request for exactly height
        // one. Deliver the request to a caught-up peer and one authenticated
        // checkpoint response back to the lagging driver.
        let request_at = drivers[0].last_finality_progress_at + FINALITY_RECOVERY_REQUEST_INTERVAL;
        drivers[0]
            .tick_at(request_at)
            .expect("lagging validator must request verified finality recovery");
        let request = drivers[0]
            .egress
            .messages
            .iter()
            .find(|message| matches!(message, TypedConsensusMessage::FinalityCheckpointRequest { next_height } if *next_height == Height(1)))
            .cloned()
            .expect("lagging validator must request its exact successor height");
        let lagging_peer = authenticated_peer_for_release_driver(&drivers[0]);
        drivers[1]
            .handle_envelope(
                TypedConsensusEnvelope {
                    peer_address: "lagging-validator".to_string(),
                    authenticated_peer: Some(lagging_peer),
                    message: request,
                },
                &authorizer,
            )
            .expect("caught-up validator accepts an authenticated recovery request");
        let checkpoint = drivers[1]
            .egress
            .messages
            .iter()
            .find(|message| matches!(message, TypedConsensusMessage::FinalityCheckpoint { records } if records.len() == 1 && records[0].height == Height(1)))
            .cloned()
            .expect("caught-up validator returns only the requested certified record");
        assert!(matches!(
            &checkpoint,
            TypedConsensusMessage::FinalityCheckpoint { records }
                if records[0].block.header.round == final_round
                    && records[0].quorum_certificate.round == final_round
        ));
        let checkpoint_replay = checkpoint.clone();
        let caught_up_peer = authenticated_peer_for_release_driver(&drivers[1]);
        drivers[0]
            .handle_envelope(
                TypedConsensusEnvelope {
                    peer_address: "caught-up-validator".to_string(),
                    authenticated_peer: Some(caught_up_peer),
                    message: checkpoint,
                },
                &authorizer,
            )
            .expect("lagging validator replays the checkpoint through normal QC verification");

        // ML-DSA proposal signatures are randomized. Two validators can
        // durably retain different valid signature bytes for the identical
        // header and transaction payload. A redundant checkpoint prefix must
        // compare the certified block subject, not raw randomized bytes.
        let mut randomized_checkpoint = checkpoint_replay;
        let TypedConsensusMessage::FinalityCheckpoint { records } = &mut randomized_checkpoint
        else {
            unreachable!("the cloned message is the checkpoint selected above");
        };
        records[0].block.proposer_signature.signature_bytes[0] ^= 0x01;
        let replay_peer = authenticated_peer_for_release_driver(&drivers[1]);
        let replay_event = drivers[0]
            .handle_envelope(
                TypedConsensusEnvelope {
                    peer_address: "caught-up-validator".to_string(),
                    authenticated_peer: Some(replay_peer),
                    message: randomized_checkpoint,
                },
                &authorizer,
            )
            .expect("randomized signature replay is an idempotent checkpoint prefix");
        assert!(matches!(
            replay_event,
            TypedCoordinatorEvent::FinalityCheckpointApplied {
                imported_records: 0
            }
        ));
        for driver in &drivers {
            assert_eq!(
                driver.coordinator.local_context.latest_finalized_height,
                Height(1)
            );
            assert_eq!(
                driver.coordinator.local_context.height_context.height,
                Height(2)
            );
            assert_eq!(
                driver.coordinator.local_context.round,
                Round(0),
                "recovered and directly finalized replicas must all enter successor round zero"
            );
        }
        // RecordingEgress retains already-delivered height-one traffic,
        // unlike the live transport. Do not replay that stale test-fixture
        // backlog into the height-two healthy-path assertion.
        for driver in &mut drivers {
            driver.egress.messages.clear();
        }
        relay_errors.clear();

        // All six then participate in the next height. This is the release
        // gate: delayed worker recovery must restore six-validator liveness,
        // not merely repair a local display or persisted-height counter.
        for driver in &mut drivers {
            let now = driver.round_started_at;
            driver.tick_at(now).expect("height-two proposal scheduling");
        }
        relay_errors.extend(relay_release_messages(&mut drivers, &authorizer, |_| true));
        assert!(
            !relay_errors
                .iter()
                .any(|error| driver_error_is_fatal(error)),
            "recovery replay must not emit a fatal source conflict: {relay_errors:?}"
        );
        for (index, driver) in drivers.iter().enumerate() {
            assert_eq!(
                driver.coordinator.local_context.latest_finalized_height,
                Height(2),
                "replica {index} did not finalize height two: stage={:?}, round={:?}, metrics={:?}, prepared={}, qc={}, relay_errors={relay_errors:?}",
                driver.stage,
                driver.coordinator.local_context.round,
                driver.metrics(),
                driver.prepared_certificate.is_some(),
                driver.finality_certificate.is_some(),
            );
            assert_eq!(
                driver.coordinator.local_context.height_context.height,
                Height(3)
            );
        }
        drop(drivers);
        for path in store_paths {
            let _ = std::fs::remove_file(path);
        }
    }

    #[test]
    fn driver_timeout_vote_fails_closed_when_p2p_fanout_is_empty() {
        let mut coordinator = coordinator_fixture();
        let scheduled = coordinator
            .consensus
            .proposer_for(
                &coordinator.local_context.height_context,
                coordinator.local_context.round,
            )
            .unwrap()
            .validator_id;
        let local = coordinator
            .consensus
            .validator_set
            .validators
            .iter()
            .find(|validator| validator.validator_id != scheduled)
            .unwrap()
            .validator_id
            .clone();
        coordinator.local_validator_id = local;
        let mut driver = driver_with(coordinator, 0);
        let now = driver.round_started_at + Duration::from_millis(1_500);
        let error = driver.tick_at(now).unwrap_err();
        assert!(error.contains("transport delivered to zero"));
    }

    #[test]
    fn driver_rebroadcasts_identical_vote_after_remote_mailbox_startup_loss() {
        let mut coordinator = coordinator_fixture();
        let scheduled = coordinator
            .consensus
            .proposer_for(
                &coordinator.local_context.height_context,
                coordinator.local_context.round,
            )
            .unwrap()
            .validator_id;
        coordinator.local_validator_id = coordinator
            .consensus
            .validator_set
            .validators
            .iter()
            .find(|validator| validator.validator_id != scheduled)
            .unwrap()
            .validator_id
            .clone();
        let mut driver = driver_with(coordinator, 1);
        let first_deadline = driver.round_started_at + Duration::from_millis(1_500);
        driver
            .tick_at(first_deadline)
            .expect("the first timeout vote is emitted");
        let first_vote = driver
            .egress
            .messages
            .iter()
            .find_map(|message| match message {
                TypedConsensusMessage::Vote { vote } => Some(vote.clone()),
                _ => None,
            })
            .expect("capture the first timeout vote");
        driver.egress.messages.clear();

        driver
            .tick_at(first_deadline + VOTE_REBROADCAST_INTERVAL)
            .expect("the same signed vote is rebroadcast after startup loss");
        let rebroadcast = driver
            .egress
            .messages
            .iter()
            .find_map(|message| match message {
                TypedConsensusMessage::Vote { vote } => Some(vote.clone()),
                _ => None,
            })
            .expect("capture the rebroadcast timeout vote");
        assert_eq!(first_vote, rebroadcast);
        assert_eq!(driver.metrics().emitted_timeout_votes, 1);
    }
}
