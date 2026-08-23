//! Authenticated operational driver for the simplified PoSy v3 state machine.
//!
//! This module owns a wire protocol and bounded mailbox distinct from both
//! inherited consensus and typed PoSy v2.2. It never constructs an execution
//! result: an injected protected-execution source must provide the exact
//! proposal commitment before the scheduled leader can sign anything.

use super::{
    build_material_chunks, build_state_sync_chunks, BlockVote, CertifiedCandidateSubject,
    ConsensusSignatureVerifier, DurableSimplifiedPosyStore, FinalizedBlockRecord,
    GenesisBoundSimplifiedActivation, QuorumCertificateReference, ReliableDeliveryPhase,
    ReliableDeliveryState, ReliableDeliveryStatement, SimplifiedConsensusStateMachine,
    SimplifiedEpochContext, SimplifiedMaterialChunk, SimplifiedMaterialStager, SimplifiedProposal,
    SimplifiedQuorumCertificate, SimplifiedSafetyState, SimplifiedStateSyncChunk,
    SimplifiedStateSyncStager, SimplifiedTimeoutCertificate, TimeoutVote,
    VerifiedSimplifiedEpochTransition, VerifiedSimplifiedProposalMaterial,
    POSY_SIMPLIFIED_BLOCK_VOTE_DOMAIN, POSY_SIMPLIFIED_PROPOSAL_ECHO_DOMAIN,
    POSY_SIMPLIFIED_PROPOSAL_READY_DOMAIN, POSY_SIMPLIFIED_TIMEOUT_VOTE_DOMAIN,
};
use crate::consensus::signing_authority::{
    ConsensusSigningAuthorization, ConsensusSigningPhase, DurableConsensusSigningAuthority,
};
use crate::crypto::aegis_pqvm::{AegisPqvmSigner, AegisPqvmVerifier};
use crate::p2p::messages::validate_simplified_consensus_message_size;
use crate::synergy_types::{
    AegisPqKeyId, BlockId, Hash, Height, ValidatorId, ValidatorRecord, ValidatorSet,
    ValidatorStatus,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender, TrySendError};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

pub const SIMPLIFIED_POSY_INGRESS_CAPACITY: usize = 512;
pub const MAX_SIMPLIFIED_VOTE_SUBJECTS: usize = 8;
const SIMPLIFIED_STATE_SYNC_SERVE_WINDOW: Duration = Duration::from_secs(30);
const MAX_SIMPLIFIED_STATE_SYNC_SERVES_PER_PEER_WINDOW: usize = 2;
const SIMPLIFIED_MATERIAL_SERVE_WINDOW: Duration = Duration::from_secs(30);
// One authenticated peer may legitimately need the proposal it first saw plus
// the finalized block and two certified tail blocks needed to resume a
// three-chain state-sync boundary. Keep that complete recovery bounded.
const MAX_SIMPLIFIED_MATERIAL_SERVES_PER_PEER_WINDOW: usize = 4;

#[derive(Debug, Clone, PartialEq, Eq)]
enum SimplifiedEnvelopeFailure {
    PeerRejected(String),
    FatalLocal(String),
}

/// The state-machine APIs predate a typed operational error enum. Keep the
/// network loop's trust decision centralized and narrowly classify only
/// unmistakable local durability, signing, safety-halt, finalization-adapter,
/// and egress failures as fatal. All ordinary malformed/stale/byzantine peer
/// artifacts are rejected and counted without becoming a remote kill switch.
fn classify_simplified_envelope_failure(error: String) -> SimplifiedEnvelopeFailure {
    const FATAL_MARKERS: &[&str] = &[
        "CONSENSUS_SAFETY_HALT",
        "SIMPLIFIED_FINALIZATION_SINK_NOT_INSTALLED",
        "SIMPLIFIED_LOCAL_FINALIZATION_FAILURE",
        "SIMPLIFIED_LOCAL_DRIVER_FAILURE",
        "simplified PoSy broadcast reached no",
        "create simplified state directory",
        "simplified state path has no",
        "serialize simplified consensus state",
        "create temporary state",
        "write temporary state",
        "fsync temporary state",
        "atomically replace state",
        "fsync state directory",
        "simplified material store lock poisoned",
        "create simplified material directory",
        "create material temp",
        "write material temp",
        "sync material temp",
        "atomically install material",
        "sync material directory",
        "encode simplified material record",
        "clock failure for material persistence",
        "remove linked material temp",
        "remove idempotent material temp",
        "read simplified material",
        "parse simplified material",
        "canonicalize simplified material",
        "simplified material record exceeds its decode bound",
        "simplified material record is not canonical",
        "simplified material filename and candidate disagree",
        "SIMPLIFIED_PROTECTED_MATERIAL_CONFLICT",
        "signing authority",
        "signer journal",
    ];
    if FATAL_MARKERS.iter().any(|marker| error.contains(marker)) {
        SimplifiedEnvelopeFailure::FatalLocal(error)
    } else {
        SimplifiedEnvelopeFailure::PeerRejected(error)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SimplifiedDriverTiming {
    proposal_timeout: Duration,
    vote_timeout: Duration,
    max_round_timeout: Duration,
}

impl SimplifiedDriverTiming {
    pub fn from_activation(activation: &GenesisBoundSimplifiedActivation) -> Result<Self, String> {
        activation.validate()?;
        let timing = Self {
            proposal_timeout: Duration::from_millis(activation.manifest.proposal_timeout_ms),
            vote_timeout: Duration::from_millis(activation.manifest.vote_timeout_ms),
            max_round_timeout: Duration::from_millis(activation.manifest.max_round_timeout_ms),
        };
        if timing.proposal_timeout.is_zero()
            || timing.vote_timeout.is_zero()
            || timing.max_round_timeout.is_zero()
            || timing.proposal_timeout > timing.max_round_timeout
            || timing.vote_timeout > timing.max_round_timeout
        {
            return Err("simplified driver timing is outside the finalized bounds".to_string());
        }
        Ok(timing)
    }

    fn deadline_for(self, proposal_accepted: bool) -> Duration {
        if proposal_accepted {
            self.vote_timeout
        } else {
            self.proposal_timeout
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SimplifiedConsensusMessage {
    Proposal {
        proposal: SimplifiedProposal,
    },
    ReliableDelivery {
        statement: ReliableDeliveryStatement,
    },
    Vote {
        vote: BlockVote,
    },
    QuorumCertificate {
        certificate: SimplifiedQuorumCertificate,
    },
    TimeoutVote {
        vote: TimeoutVote,
    },
    TimeoutCertificate {
        certificate: SimplifiedTimeoutCertificate,
    },
    StateSyncRequest {
        epoch_context_root: Hash,
        request_id: Hash,
    },
    StateSyncChunk {
        chunk: SimplifiedStateSyncChunk,
    },
    MaterialRequest {
        epoch_context_root: Hash,
        stable_candidate_id: Hash,
        request_id: Hash,
    },
    MaterialChunk {
        chunk: SimplifiedMaterialChunk,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedSimplifiedConsensusPeer {
    pub validator_id: ValidatorId,
    pub validator_uma_id: crate::synergy_types::UmaId,
    pub consensus_key_id: AegisPqKeyId,
}

#[derive(Debug, Clone)]
pub struct SimplifiedConsensusEnvelope {
    pub peer_address: String,
    pub authenticated_peer: AuthenticatedSimplifiedConsensusPeer,
    pub message: SimplifiedConsensusMessage,
}

#[derive(Debug, Clone)]
pub struct FrozenSimplifiedPeerAuthorizer {
    validators: BTreeMap<ValidatorId, ValidatorRecord>,
}

impl FrozenSimplifiedPeerAuthorizer {
    pub fn new(
        epoch_context: &SimplifiedEpochContext,
        validator_set: &ValidatorSet,
    ) -> Result<Self, String> {
        epoch_context.validate_against(validator_set)?;
        Ok(Self {
            validators: validator_set
                .active_for_epoch(epoch_context.epoch)
                .validators
                .into_iter()
                .map(|validator| (validator.validator_id.clone(), validator))
                .collect(),
        })
    }

    pub fn authorize(
        &self,
        peer: &AuthenticatedSimplifiedConsensusPeer,
        message: &SimplifiedConsensusMessage,
    ) -> Result<(), String> {
        let validator = self
            .validators
            .get(&peer.validator_id)
            .ok_or_else(|| "simplified consensus peer is absent from the frozen set".to_string())?;
        if validator.status != ValidatorStatus::Active
            || validator.validator_uma_id != peer.validator_uma_id
            || validator.consensus_public_key.key_id != peer.consensus_key_id
        {
            return Err(
                "simplified consensus peer identity does not match the frozen validator record"
                    .to_string(),
            );
        }
        match message {
            SimplifiedConsensusMessage::Proposal { proposal }
                if proposal.proposer_id != peer.validator_id
                    || proposal.proposer_key_id != peer.consensus_key_id =>
            {
                Err("simplified proposal sender does not match authenticated peer".to_string())
            }
            SimplifiedConsensusMessage::ReliableDelivery { statement }
                if statement.validator_id != peer.validator_id
                    || statement.key_id != peer.consensus_key_id =>
            {
                Err("reliable-delivery sender does not match authenticated peer".to_string())
            }
            SimplifiedConsensusMessage::Vote { vote }
                if vote.validator_id != peer.validator_id
                    || vote.key_id != peer.consensus_key_id =>
            {
                Err("simplified vote sender does not match authenticated peer".to_string())
            }
            SimplifiedConsensusMessage::TimeoutVote { vote }
                if vote.validator_id != peer.validator_id
                    || vote.key_id != peer.consensus_key_id =>
            {
                Err("simplified timeout-vote sender does not match authenticated peer".to_string())
            }
            _ => Ok(()),
        }
    }
}

pub trait SimplifiedConsensusEgress: Send {
    fn broadcast(&mut self, message: &SimplifiedConsensusMessage) -> Result<usize, String>;

    fn send_to(
        &mut self,
        peer_address: &str,
        expected_validator_id: &ValidatorId,
        message: &SimplifiedConsensusMessage,
    ) -> Result<usize, String>;
}

pub struct P2pSimplifiedConsensusEgress {
    network: Arc<crate::p2p::networking::P2PNetwork>,
    frozen_validator_ids: BTreeSet<ValidatorId>,
}

impl P2pSimplifiedConsensusEgress {
    pub fn new(
        network: Arc<crate::p2p::networking::P2PNetwork>,
        epoch_context: &SimplifiedEpochContext,
        validator_set: &ValidatorSet,
    ) -> Result<Self, String> {
        epoch_context.validate_against(validator_set)?;
        Ok(Self {
            network,
            frozen_validator_ids: validator_set
                .active_for_epoch(epoch_context.epoch)
                .validators
                .into_iter()
                .map(|validator| validator.validator_id)
                .collect(),
        })
    }
}

impl SimplifiedConsensusEgress for P2pSimplifiedConsensusEgress {
    fn broadcast(&mut self, message: &SimplifiedConsensusMessage) -> Result<usize, String> {
        self.network
            .broadcast_simplified_consensus(message, &self.frozen_validator_ids)
    }

    fn send_to(
        &mut self,
        peer_address: &str,
        expected_validator_id: &ValidatorId,
        message: &SimplifiedConsensusMessage,
    ) -> Result<usize, String> {
        self.network.send_simplified_consensus_to_peer(
            peer_address,
            expected_validator_id,
            message,
            &self.frozen_validator_ids,
        )
    }
}

/// Supplies a proposal whose block and protected-execution root have already
/// passed the canonical execution/ETDAG boundary. Returning `None` means the
/// source is not ready; the driver never manufactures an empty substitute.
pub trait SimplifiedProtectedProposalSource: Send {
    fn proposal_for(
        &mut self,
        epoch_context: &SimplifiedEpochContext,
        directive: &SimplifiedProposalDirective,
    ) -> Result<Option<SimplifiedProposal>, String>;

    /// Independently obtains and verifies the canonical block body, ETDAG/BOC
    /// input, reveal result, and protected execution outcome for a remote
    /// proposal. The returned root is recomputed locally; trusting the root in
    /// the proposal is forbidden.
    fn recompute_received_protected_execution_root(
        &mut self,
        proposal: &SimplifiedProposal,
        expected_finalized: &FinalizedBlockRecord,
    ) -> Result<Option<Hash>, String>;

    fn install_received_material(
        &mut self,
        _proposal: &SimplifiedProposal,
        _expected_finalized: &FinalizedBlockRecord,
        _material: VerifiedSimplifiedProposalMaterial,
    ) -> Result<Hash, String> {
        Err("simplified proposal source does not accept streamed material".to_string())
    }

    fn material_for_serving(
        &mut self,
        _stable_candidate_id: Hash,
    ) -> Result<Option<VerifiedSimplifiedProposalMaterial>, String> {
        Ok(None)
    }

    /// Confirms that the receiver owns independently verified durable
    /// material for a certified candidate. Operational sources inherit the
    /// exact store lookup; test or external adapters may implement an
    /// equivalent authoritative registry without exposing the record here.
    fn has_verified_material(&mut self, stable_candidate_id: Hash) -> Result<bool, String> {
        Ok(self.material_for_serving(stable_candidate_id)?.is_some())
    }
}

/// Exact proposal-authority input supplied to protected execution.
///
/// A source must not infer takeover carry from clocks, local health, or a
/// cached proposal. The driver derives it from the verified durable TC chain
/// and scopes it to the TC's effective height.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SimplifiedProposalDirective {
    pub context: super::ConsensusObjectContext,
    pub highest_qc: QuorumCertificateReference,
    pub finalized: FinalizedBlockRecord,
    pub proposer_id: ValidatorId,
    pub proposer_key_id: AegisPqKeyId,
    pub takeover_tc_id: Option<Hash>,
    pub mandatory_carry_candidate: Option<CertifiedCandidateSubject>,
}

/// One protected block/application commitment covered by a finalization
/// transaction.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SimplifiedFinalizedCommitment {
    pub height: Height,
    pub block_id: BlockId,
    pub parent_block_id: BlockId,
    pub qc_id: Hash,
    pub protected_execution_root: Hash,
    /// Complete certificate evidence retained by the durable application log.
    pub certificate: SimplifiedQuorumCertificate,
}

pub const MAX_SIMPLIFIED_FINALIZATION_COMMITMENTS_PER_TRANSACTION: usize = 16;

/// Recoverable atomic boundary between protected execution and consensus.
///
/// Implementations must durably commit the complete consecutive path as one
/// transaction and return the same receipt when the same `transaction_id` is
/// retried after a crash. No production no-op sink is provided.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SimplifiedFinalizationTransaction {
    pub format: String,
    pub transaction_id: Hash,
    pub epoch_context_root: Hash,
    pub expected_previous_finalized: FinalizedBlockRecord,
    pub commitments: Vec<SimplifiedFinalizedCommitment>,
    pub target_finalized: FinalizedBlockRecord,
    /// The target QC and its two consecutive certified descendants.
    pub finality_witness: Vec<SimplifiedQuorumCertificate>,
}

#[derive(Debug, Clone, Serialize)]
struct SimplifiedFinalizationTransactionSubject<'a> {
    format: &'a str,
    epoch_context_root: Hash,
    expected_previous_finalized: &'a FinalizedBlockRecord,
    commitments: &'a [SimplifiedFinalizedCommitment],
    target_finalized: &'a FinalizedBlockRecord,
    finality_witness: &'a [SimplifiedQuorumCertificate],
}

impl SimplifiedFinalizationTransaction {
    pub fn validate(&self) -> Result<(), String> {
        const FORMAT: &str = "synergy-posy-simplified-finalization-transaction-v3";
        if self.format != FORMAT
            || self.epoch_context_root.is_zero()
            || self.commitments.is_empty()
            || self.commitments.len() > MAX_SIMPLIFIED_FINALIZATION_COMMITMENTS_PER_TRANSACTION
            || self.finality_witness.len() != 3
            || self.target_finalized.height.0 <= self.expected_previous_finalized.height.0
        {
            return Err("invalid simplified finalization transaction header".to_string());
        }
        let mut expected_height = self
            .expected_previous_finalized
            .height
            .0
            .checked_add(1)
            .ok_or_else(|| "finalization transaction height overflowed".to_string())?;
        let mut expected_parent = &self.expected_previous_finalized.block_id;
        let mut expected_parent_qc = QuorumCertificateReference {
            height: self.expected_previous_finalized.height,
            block_id: self.expected_previous_finalized.block_id.clone(),
            qc_id: self.expected_previous_finalized.qc_id,
        };
        for commitment in &self.commitments {
            if commitment.height.0 != expected_height
                || &commitment.parent_block_id != expected_parent
                || commitment.block_id.0.trim().is_empty()
                || commitment.qc_id.is_zero()
                || commitment.protected_execution_root.is_zero()
                || commitment.certificate.context.height != commitment.height
                || commitment.certificate.block_id != commitment.block_id
                || commitment.certificate.parent_block_id != commitment.parent_block_id
                || commitment.certificate.protected_execution_root
                    != commitment.protected_execution_root
                || commitment.certificate.id()? != commitment.qc_id
                || commitment.certificate.parent_qc != expected_parent_qc
            {
                return Err(
                    "simplified finalization commitments are not consecutive and protected"
                        .to_string(),
                );
            }
            expected_height = expected_height
                .checked_add(1)
                .ok_or_else(|| "finalization transaction height overflowed".to_string())?;
            expected_parent = &commitment.block_id;
            expected_parent_qc = QuorumCertificateReference {
                height: commitment.height,
                block_id: commitment.block_id.clone(),
                qc_id: commitment.qc_id,
            };
        }
        let last = self
            .commitments
            .last()
            .ok_or_else(|| "finalization transaction path is empty".to_string())?;
        if last.height != self.target_finalized.height
            || last.block_id != self.target_finalized.block_id
            || last.qc_id != self.target_finalized.qc_id
            || self.transaction_id != self.recompute_id()?
        {
            return Err("simplified finalization target or transaction id is invalid".to_string());
        }
        let target = &self.finality_witness[0];
        let child = &self.finality_witness[1];
        let grandchild = &self.finality_witness[2];
        if target.context.height != self.target_finalized.height
            || target.block_id != self.target_finalized.block_id
            || target.id()? != self.target_finalized.qc_id
            || child.parent_qc != target.reference()?
            || grandchild.parent_qc != child.reference()?
            || target.context.height.0.checked_add(1) != Some(child.context.height.0)
            || child.context.height.0.checked_add(1) != Some(grandchild.context.height.0)
        {
            return Err(
                "simplified finalization witness is not a consecutive three-chain".to_string(),
            );
        }
        let mut previous_epoch_context_root = None;
        let mut entered_current_epoch = false;
        for certificate in &self.finality_witness {
            let root = certificate.context.epoch_context_root;
            if root == self.epoch_context_root {
                entered_current_epoch = true;
            } else if entered_current_epoch
                || previous_epoch_context_root.is_some_and(|previous| previous != root)
            {
                return Err(
                    "simplified finalization witness crosses an unpinned epoch sequence"
                        .to_string(),
                );
            } else {
                previous_epoch_context_root = Some(root);
            }
        }
        if !entered_current_epoch {
            return Err(
                "simplified finalization witness has no current-epoch descendant".to_string(),
            );
        }
        Ok(())
    }

    pub fn recompute_id(&self) -> Result<Hash, String> {
        let subject = SimplifiedFinalizationTransactionSubject {
            format: &self.format,
            epoch_context_root: self.epoch_context_root,
            expected_previous_finalized: &self.expected_previous_finalized,
            commitments: &self.commitments,
            target_finalized: &self.target_finalized,
            finality_witness: &self.finality_witness,
        };
        Ok(Hash::from_domain_bytes(
            "SYNERGY_POSY_SIMPLIFIED_FINALIZATION_TRANSACTION_V3",
            &serde_json::to_vec(&subject)
                .map_err(|error| format!("serialize finalization transaction: {error}"))?,
        ))
    }
}

/// Durable acknowledgement returned by a finalization sink.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SimplifiedFinalizationReceipt {
    pub transaction_id: Hash,
    pub target_finalized: FinalizedBlockRecord,
}

/// Typed local failure from the protected finalization transaction boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SimplifiedFinalizationSinkError {
    Unavailable(String),
    CommitRejected(String),
}

impl fmt::Display for SimplifiedFinalizationSinkError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unavailable(message) => write!(formatter, "sink unavailable: {message}"),
            Self::CommitRejected(message) => write!(formatter, "commit rejected: {message}"),
        }
    }
}

impl std::error::Error for SimplifiedFinalizationSinkError {}

/// Commits protected block, application, and finality state atomically.
pub trait SimplifiedFinalizationSink: Send {
    fn commit_finalization(
        &mut self,
        transaction: &SimplifiedFinalizationTransaction,
    ) -> Result<SimplifiedFinalizationReceipt, SimplifiedFinalizationSinkError>;
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SimplifiedDriverMetrics {
    pub accepted_messages: u64,
    pub rejected_messages: u64,
    pub proposals_broadcast: u64,
    pub reliable_delivery_broadcast: u64,
    pub votes_broadcast: u64,
    pub quorum_certificates_broadcast: u64,
    pub timeout_votes_broadcast: u64,
    pub timeout_certificates_broadcast: u64,
    pub state_sync_chunks_broadcast: u64,
    pub material_requests_sent: u64,
    pub material_chunks_sent: u64,
}

pub struct SimplifiedPosyDriver<S, E, F> {
    epoch_context: SimplifiedEpochContext,
    validator_set: ValidatorSet,
    local_validator_id: ValidatorId,
    local_key_id: AegisPqKeyId,
    local_cluster_id: crate::synergy_types::ClusterId,
    state_machine: SimplifiedConsensusStateMachine,
    signing_authority: DurableConsensusSigningAuthority,
    signer: AegisPqvmSigner,
    verifier: AegisPqvmVerifier,
    proposal_source: S,
    egress: E,
    finalization_sink: F,
    /// Receiver-owned transition capability. Peer messages and state sync can
    /// never install or replace this authority.
    epoch_transition: Option<VerifiedSimplifiedEpochTransition>,
    peer_authorizer: FrozenSimplifiedPeerAuthorizer,
    timing: SimplifiedDriverTiming,
    votes: BTreeMap<Hash, BTreeMap<ValidatorId, BlockVote>>,
    timeout_votes: BTreeMap<Hash, BTreeMap<ValidatorId, TimeoutVote>>,
    locally_voted_subjects: BTreeSet<Hash>,
    locally_proposed_slot: Option<(Height, u64)>,
    locally_timed_out_slot: Option<(Height, u64)>,
    accepted_proposal_subject: Option<(Height, u64, Hash)>,
    reliable_delivery: Option<ReliableDeliveryState>,
    pending_delivery_retransmission: Vec<ReliableDeliveryStatement>,
    validated_proposals: BTreeMap<Hash, SimplifiedProposal>,
    last_state_sync_request: Option<Instant>,
    state_sync_request_sequence: u64,
    state_sync_stager: SimplifiedStateSyncStager,
    state_sync_peer_serves: BTreeMap<ValidatorId, VecDeque<Instant>>,
    state_sync_global_serves: VecDeque<Instant>,
    pending_material_proposals: BTreeMap<Hash, (SimplifiedProposal, String)>,
    pending_certified_material: BTreeMap<Hash, PendingCertifiedMaterial>,
    pending_state_sync_install: Option<PendingStateSyncInstall>,
    material_request_ids: BTreeMap<Hash, Hash>,
    material_request_sequence: u64,
    material_stager: SimplifiedMaterialStager,
    material_peer_serves: BTreeMap<ValidatorId, VecDeque<Instant>>,
    material_global_serves: VecDeque<Instant>,
    metrics: SimplifiedDriverMetrics,
}

#[derive(Clone)]
struct PendingCertifiedMaterial {
    proposal: SimplifiedProposal,
    expected_finalized: FinalizedBlockRecord,
    certificate: Option<SimplifiedQuorumCertificate>,
}

#[derive(Clone)]
struct PendingStateSyncInstall {
    request_id: Hash,
    peer_address: String,
    peer_validator_id: ValidatorId,
    bundle: super::SimplifiedStateSyncBundle,
    reconstructed: SimplifiedSafetyState,
}

impl<
        S: SimplifiedProtectedProposalSource,
        E: SimplifiedConsensusEgress,
        F: SimplifiedFinalizationSink,
    > SimplifiedPosyDriver<S, E, F>
{
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        epoch_context: SimplifiedEpochContext,
        validator_set: ValidatorSet,
        local_validator_id: ValidatorId,
        local_key_id: AegisPqKeyId,
        state_store: DurableSimplifiedPosyStore,
        anchor_qc: QuorumCertificateReference,
        signing_authority: DurableConsensusSigningAuthority,
        signer: AegisPqvmSigner,
        verifier: AegisPqvmVerifier,
        proposal_source: S,
        egress: E,
        finalization_sink: F,
        timing: SimplifiedDriverTiming,
    ) -> Result<Self, String> {
        Self::new_internal(
            epoch_context,
            validator_set,
            local_validator_id,
            local_key_id,
            state_store,
            Some(anchor_qc),
            None,
            signing_authority,
            signer,
            verifier,
            proposal_source,
            egress,
            finalization_sink,
            timing,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_from_verified_v3_transition(
        transition: VerifiedSimplifiedEpochTransition,
        local_validator_id: ValidatorId,
        local_key_id: AegisPqKeyId,
        state_store: DurableSimplifiedPosyStore,
        signing_authority: DurableConsensusSigningAuthority,
        signer: AegisPqvmSigner,
        verifier: AegisPqvmVerifier,
        proposal_source: S,
        egress: E,
        finalization_sink: F,
        timing: SimplifiedDriverTiming,
    ) -> Result<Self, String> {
        let epoch_context = transition.next_epoch_context().clone();
        let validator_set = transition.next_validator_set().clone();
        Self::new_internal(
            epoch_context,
            validator_set,
            local_validator_id,
            local_key_id,
            state_store,
            None,
            Some(transition),
            signing_authority,
            signer,
            verifier,
            proposal_source,
            egress,
            finalization_sink,
            timing,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn new_internal(
        epoch_context: SimplifiedEpochContext,
        validator_set: ValidatorSet,
        local_validator_id: ValidatorId,
        local_key_id: AegisPqKeyId,
        state_store: DurableSimplifiedPosyStore,
        anchor_qc: Option<QuorumCertificateReference>,
        epoch_transition: Option<VerifiedSimplifiedEpochTransition>,
        signing_authority: DurableConsensusSigningAuthority,
        signer: AegisPqvmSigner,
        verifier: AegisPqvmVerifier,
        proposal_source: S,
        egress: E,
        finalization_sink: F,
        timing: SimplifiedDriverTiming,
    ) -> Result<Self, String> {
        epoch_context.validate_against(&validator_set)?;
        if let Some(transition) = &epoch_transition {
            if epoch_context != *transition.next_epoch_context()
                || validator_set != *transition.next_validator_set()
                || anchor_qc.is_some()
            {
                return Err(
                    "simplified driver inputs do not match the verified v3 transition".to_string(),
                );
            }
        } else if epoch_context.v3_transition_anchor.is_some() {
            return Err(
                "v3-to-v3 driver startup requires a receiver-owned verified transition capability"
                    .to_string(),
            );
        }
        let local = validator_set
            .active_for_epoch(epoch_context.epoch)
            .validators
            .into_iter()
            .find(|validator| validator.validator_id == local_validator_id)
            .ok_or_else(|| "local validator is absent from the frozen v3 set".to_string())?;
        if local.consensus_public_key.key_id != local_key_id {
            return Err("local v3 signer is not bound to its frozen ML-DSA-65 key".to_string());
        }
        for role in [
            crate::synergy_types::AegisPqKeyRole::ConsensusProposer,
            crate::synergy_types::AegisPqKeyRole::ConsensusVote,
        ] {
            if !signer.registry.key_is_active_for_epoch(
                &local.validator_uma_id.0,
                &local_key_id,
                epoch_context.epoch,
                role.clone(),
            ) {
                return Err(format!(
                    "local v3 signer key is not active for required role {role:?}"
                ));
            }
        }
        let peer_authorizer = FrozenSimplifiedPeerAuthorizer::new(&epoch_context, &validator_set)?;
        let mut state_machine = match &epoch_transition {
            Some(transition) => SimplifiedConsensusStateMachine::open_from_verified_v3_transition(
                transition,
                state_store,
            )?,
            None => SimplifiedConsensusStateMachine::open(
                epoch_context.clone(),
                validator_set.clone(),
                state_store,
                anchor_qc.ok_or_else(|| {
                    "simplified driver startup lacks its certified anchor".to_string()
                })?,
            )?,
        };
        state_machine.reconcile_local_signing_journal(
            &local_validator_id,
            &local_key_id,
            &signing_authority,
        )?;
        if let Some(delivery) = &state_machine.state().reliable_delivery {
            delivery.validate_authenticated(&epoch_context, &validator_set, &verifier)?;
        }
        let reliable_delivery = state_machine.state().reliable_delivery.clone();
        let mut pending_delivery_retransmission = Vec::with_capacity(2);
        if let Some(delivery) = &reliable_delivery {
            for phase in [ReliableDeliveryPhase::Echo, ReliableDeliveryPhase::Ready] {
                if let Some(statement) = delivery.local_statement(phase, &local_validator_id)? {
                    pending_delivery_retransmission.push(statement);
                }
            }
        }
        let state_sync_stager = match &epoch_transition {
            Some(transition) => {
                SimplifiedStateSyncStager::new_from_verified_v3_transition(transition)?
            }
            None => SimplifiedStateSyncStager::new(
                epoch_context.clone(),
                state_machine.state().anchor_qc.clone(),
            )?,
        };
        let material_stager = SimplifiedMaterialStager::new(epoch_context.root()?)?;
        Ok(Self {
            epoch_context,
            validator_set,
            local_validator_id,
            local_key_id,
            local_cluster_id: local.cluster_id,
            state_machine,
            signing_authority,
            signer,
            verifier,
            proposal_source,
            egress,
            finalization_sink,
            epoch_transition,
            peer_authorizer,
            timing,
            votes: BTreeMap::new(),
            timeout_votes: BTreeMap::new(),
            locally_voted_subjects: BTreeSet::new(),
            locally_proposed_slot: None,
            locally_timed_out_slot: None,
            accepted_proposal_subject: None,
            reliable_delivery,
            pending_delivery_retransmission,
            validated_proposals: BTreeMap::new(),
            last_state_sync_request: None,
            state_sync_request_sequence: 0,
            state_sync_stager,
            state_sync_peer_serves: BTreeMap::new(),
            state_sync_global_serves: VecDeque::new(),
            pending_material_proposals: BTreeMap::new(),
            pending_certified_material: BTreeMap::new(),
            pending_state_sync_install: None,
            material_request_ids: BTreeMap::new(),
            material_request_sequence: 0,
            material_stager,
            material_peer_serves: BTreeMap::new(),
            material_global_serves: VecDeque::new(),
            metrics: SimplifiedDriverMetrics::default(),
        })
    }

    pub fn metrics(&self) -> SimplifiedDriverMetrics {
        self.metrics
    }

    pub fn state_machine(&self) -> &SimplifiedConsensusStateMachine {
        &self.state_machine
    }

    pub fn drive_scheduled_proposal(&mut self) -> Result<bool, String> {
        self.retransmit_restored_delivery()?;
        let height = self.state_machine.state().next_height()?;
        let (round, tc_id) = self
            .state_machine
            .state()
            .takeover_for_height(&self.epoch_context, height)?;
        if self.epoch_context.authorized_proposer(height, round)? != &self.local_validator_id {
            return Ok(false);
        }
        if self.locally_proposed_slot == Some((height, round)) {
            return Ok(false);
        }
        let mandatory_carry_candidate = if let Some(expected_tc_id) = tc_id {
            let latest_tc = self
                .state_machine
                .state()
                .takeover
                .as_ref()
                .and_then(|takeover| takeover.certificates.last())
                .ok_or_else(|| "active takeover lacks its latest TC".to_string())?;
            if latest_tc.id()? != expected_tc_id {
                return Err("active takeover TC pointer is inconsistent".to_string());
            }
            latest_tc
                .mandatory_carry_candidate()?
                .filter(|candidate| candidate.context.height == height)
        } else {
            None
        };
        let directive = SimplifiedProposalDirective {
            context: super::ConsensusObjectContext::for_height(
                &self.epoch_context,
                height,
                crate::synergy_types::Round(round),
            )?,
            highest_qc: self.state_machine.state().highest_qc.clone(),
            finalized: self.state_machine.state().finalized.clone(),
            proposer_id: self.local_validator_id.clone(),
            proposer_key_id: self.local_key_id.clone(),
            takeover_tc_id: tc_id,
            mandatory_carry_candidate,
        };
        let Some(unsigned) = self
            .proposal_source
            .proposal_for(&self.epoch_context, &directive)?
        else {
            return Ok(false);
        };
        let proposal = self.state_machine.sign_proposal(
            unsigned,
            &self.signing_authority,
            &mut self.signer,
        )?;
        self.accept_validated_proposal(proposal.clone())?;
        self.broadcast(SimplifiedConsensusMessage::Proposal {
            proposal: proposal.clone(),
        })?;
        self.locally_proposed_slot = Some((height, round));
        self.metrics.proposals_broadcast = self.metrics.proposals_broadcast.saturating_add(1);
        Ok(true)
    }

    pub fn on_proposal_timeout(&mut self) -> Result<bool, String> {
        self.retransmit_restored_delivery()?;
        let (height, round, _) = self.current_progress()?;
        if self.locally_timed_out_slot == Some((height, round)) {
            return Ok(false);
        }
        let vote = self.state_machine.sign_timeout_vote(
            self.local_validator_id.clone(),
            self.local_key_id.clone(),
            &self.signing_authority,
            &mut self.signer,
        )?;
        self.collect_timeout_vote(vote.clone())?;
        self.broadcast(SimplifiedConsensusMessage::TimeoutVote { vote })?;
        self.locally_timed_out_slot = Some((height, round));
        self.metrics.timeout_votes_broadcast =
            self.metrics.timeout_votes_broadcast.saturating_add(1);
        Ok(true)
    }

    pub fn handle_envelope(&mut self, envelope: SimplifiedConsensusEnvelope) -> Result<(), String> {
        self.retransmit_restored_delivery()?;
        validate_simplified_consensus_message_size(&envelope.message)?;
        self.peer_authorizer
            .authorize(&envelope.authenticated_peer, &envelope.message)?;
        let peer_validator_id = envelope.authenticated_peer.validator_id.clone();
        let peer_address = envelope.peer_address.clone();
        let result = match envelope.message {
            SimplifiedConsensusMessage::Proposal { proposal } => {
                self.state_machine
                    .validate_proposal(&proposal, &self.verifier)?;
                let recomputed = self
                    .proposal_source
                    .recompute_received_protected_execution_root(
                        &proposal,
                        &self.state_machine.state().finalized,
                    )?;
                match recomputed {
                    Some(root) if !root.is_zero() && root == proposal.protected_execution_root => {
                        self.accept_validated_proposal(proposal)
                    }
                    Some(_) => Err(
                        "remote proposal protected execution root was not reproduced locally"
                            .to_string(),
                    ),
                    None => {
                        self.request_proposal_material(proposal, peer_address, peer_validator_id)
                    }
                }
            }
            SimplifiedConsensusMessage::ReliableDelivery { statement } => {
                self.accept_reliable_delivery_statement(statement)
            }
            SimplifiedConsensusMessage::Vote { vote } => self.collect_block_vote(vote),
            SimplifiedConsensusMessage::QuorumCertificate { certificate } => {
                if certificate.context.height.0 > self.state_machine.state().next_height()?.0 {
                    self.request_state_sync_for_future_evidence()?;
                    Ok(())
                } else {
                    self.accept_or_request_quorum_certificate_material(
                        certificate,
                        peer_address,
                        peer_validator_id,
                    )
                }
            }
            SimplifiedConsensusMessage::TimeoutVote { vote } => self.collect_timeout_vote(vote),
            SimplifiedConsensusMessage::TimeoutCertificate { certificate } => {
                if certificate.context.height.0 > self.state_machine.state().next_height()?.0 {
                    self.request_state_sync_for_future_evidence()?;
                    Ok(())
                } else {
                    self.accept_timeout_certificate(certificate)
                }
            }
            SimplifiedConsensusMessage::StateSyncRequest {
                epoch_context_root,
                request_id,
            } => {
                if epoch_context_root != self.epoch_context.root()? || request_id.is_zero() {
                    return Err("state-sync request names another v3 epoch context".to_string());
                }
                self.admit_state_sync_serve(&peer_validator_id, Instant::now())?;
                let bundle = self.state_machine.export_state_sync_bundle()?;
                let chunks = build_state_sync_chunks(&bundle, request_id)?;
                for chunk in chunks {
                    self.send_to(
                        &peer_address,
                        &peer_validator_id,
                        SimplifiedConsensusMessage::StateSyncChunk { chunk },
                    )?;
                    self.metrics.state_sync_chunks_broadcast =
                        self.metrics.state_sync_chunks_broadcast.saturating_add(1);
                }
                Ok(())
            }
            SimplifiedConsensusMessage::StateSyncChunk { chunk } => {
                let completed =
                    self.state_sync_stager
                        .accept(&peer_validator_id, chunk, Instant::now())?;
                if let Some(completed) = completed {
                    if self
                        .pending_state_sync_install
                        .as_ref()
                        .is_some_and(|pending| pending.request_id == completed.request_id)
                    {
                        // A broadcast request may yield several independently
                        // valid peer transcripts. Once one verified transcript
                        // owns the material-recovery continuation, redundant
                        // completions cannot replace it and are harmless.
                        return Ok(());
                    }
                    if self.pending_state_sync_install.is_some() {
                        return Err(
                            "another verified state-sync install is awaiting material".to_string()
                        );
                    }
                    let bundle = completed.bundle;
                    let reconstructed = match &self.epoch_transition {
                        Some(transition) => bundle
                            .verify_and_reconstruct_from_verified_v3_transition(
                                transition,
                                &self.verifier,
                                self.state_machine.state().last_vote.clone(),
                                self.state_machine.state().safety_halt.clone(),
                            )?,
                        None => bundle.verify_and_reconstruct(
                            &self.epoch_context,
                            &self.validator_set,
                            &self.state_machine.state().anchor_qc,
                            &self.verifier,
                            self.state_machine.state().last_vote.clone(),
                            self.state_machine.state().safety_halt.clone(),
                        )?,
                    };
                    self.pending_state_sync_install = Some(PendingStateSyncInstall {
                        request_id: completed.request_id,
                        peer_address,
                        peer_validator_id: completed.peer,
                        bundle,
                        reconstructed,
                    });
                    self.continue_pending_state_sync_install()?;
                }
                Ok(())
            }
            SimplifiedConsensusMessage::MaterialRequest {
                epoch_context_root,
                stable_candidate_id,
                request_id,
            } => {
                if epoch_context_root != self.epoch_context.root()?
                    || stable_candidate_id.is_zero()
                    || request_id.is_zero()
                {
                    return Err("proposal-material request is not for this epoch".to_string());
                }
                self.admit_material_serve(&peer_validator_id, Instant::now())?;
                let material = self
                    .proposal_source
                    .material_for_serving(stable_candidate_id)?
                    .ok_or_else(|| {
                        "requested proposal material is unavailable locally".to_string()
                    })?;
                if material.epoch_context_root != epoch_context_root
                    || material.stable_candidate_id != stable_candidate_id
                {
                    return Err("proposal source returned different requested material".to_string());
                }
                for chunk in build_material_chunks(&material, request_id)? {
                    self.send_to(
                        &peer_address,
                        &peer_validator_id,
                        SimplifiedConsensusMessage::MaterialChunk { chunk },
                    )?;
                    self.metrics.material_chunks_sent =
                        self.metrics.material_chunks_sent.saturating_add(1);
                }
                Ok(())
            }
            SimplifiedConsensusMessage::MaterialChunk { chunk } => {
                let completed =
                    self.material_stager
                        .accept(&peer_validator_id, chunk, Instant::now())?;
                if let Some(material) = completed {
                    let candidate_id = material.stable_candidate_id;
                    let (proposal, expected_finalized, certified, proposal_consumer) =
                        if let Some((proposal, _)) =
                            self.pending_material_proposals.get(&candidate_id)
                        {
                            (
                                proposal.clone(),
                                self.state_machine.state().finalized.clone(),
                                None,
                                true,
                            )
                        } else if let Some(pending) =
                            self.pending_certified_material.get(&candidate_id)
                        {
                            (
                                pending.proposal.clone(),
                                pending.expected_finalized.clone(),
                                pending.certificate.clone(),
                                false,
                            )
                        } else {
                            return Err(
                                "completed proposal material has no pending consumer".to_string()
                            );
                        };
                    let root = self.proposal_source.install_received_material(
                        &proposal,
                        &expected_finalized,
                        material,
                    )?;
                    if root.is_zero() || root != proposal.protected_execution_root {
                        return Err(
                            "streamed proposal material did not reproduce its protected root"
                                .to_string(),
                        );
                    }
                    self.pending_material_proposals.remove(&candidate_id);
                    self.pending_certified_material.remove(&candidate_id);
                    self.material_request_ids.remove(&candidate_id);
                    if let Some(certificate) = certified {
                        self.accept_quorum_certificate(certificate)?;
                    } else if proposal_consumer {
                        self.accept_validated_proposal(proposal)?;
                    } else {
                        self.continue_pending_state_sync_install()?;
                    }
                }
                Ok(())
            }
        };
        match result {
            Ok(()) => {
                self.metrics.accepted_messages = self.metrics.accepted_messages.saturating_add(1);
                Ok(())
            }
            Err(error) => {
                self.metrics.rejected_messages = self.metrics.rejected_messages.saturating_add(1);
                Err(error)
            }
        }
    }

    fn accept_validated_proposal(&mut self, proposal: SimplifiedProposal) -> Result<(), String> {
        self.accept_proposal_subject(&proposal)?;
        let candidate = candidate_for_proposal(&proposal)?;
        let candidate_id = candidate.id()?;
        if !self.validated_proposals.contains_key(&candidate_id)
            && self.validated_proposals.len() >= self.epoch_context.leader_ring.len()
        {
            return Err("validated reliable-delivery proposal pool is full".to_string());
        }
        self.validated_proposals
            .entry(candidate_id)
            .or_insert(proposal.clone());
        let should_echo = self
            .reliable_delivery
            .as_ref()
            .is_none_or(|delivery| delivery.local_echo_candidate_id.is_none());
        if should_echo {
            self.ensure_reliable_delivery_slot(proposal.context.clone())?
                .observe_candidate(candidate.clone())?;
            self.persist_reliable_delivery()?;
            self.emit_reliable_delivery_statement(
                proposal.context.clone(),
                ReliableDeliveryPhase::Echo,
                candidate,
            )?;
        } else if self
            .reliable_delivery
            .as_ref()
            .is_some_and(|delivery| delivery.local_echo_candidate_id == Some(candidate_id))
        {
            self.ensure_reliable_delivery_slot(proposal.context.clone())?
                .observe_candidate(candidate)?;
            self.persist_reliable_delivery()?;
        }
        self.vote_if_delivered(candidate_id)
    }

    fn retransmit_restored_delivery(&mut self) -> Result<(), String> {
        while let Some(statement) = self.pending_delivery_retransmission.first().cloned() {
            self.broadcast(SimplifiedConsensusMessage::ReliableDelivery { statement })?;
            self.pending_delivery_retransmission.remove(0);
            self.metrics.reliable_delivery_broadcast =
                self.metrics.reliable_delivery_broadcast.saturating_add(1);
        }
        Ok(())
    }

    fn accept_reliable_delivery_statement(
        &mut self,
        statement: ReliableDeliveryStatement,
    ) -> Result<(), String> {
        let candidate_id = statement.candidate_id()?;
        let context = statement.context.clone();
        let epoch_context = self.epoch_context.clone();
        let validator_set = self.validator_set.clone();
        let verifier = self.verifier.clone();
        let decision = self
            .ensure_reliable_delivery_slot(context.clone())?
            .accept_statement(statement, &epoch_context, &validator_set, &verifier)?;
        self.persist_reliable_delivery()?;
        if let Some(candidate) = decision.ready_candidate {
            self.emit_reliable_delivery_statement(
                context,
                ReliableDeliveryPhase::Ready,
                candidate,
            )?;
        }
        if decision.delivered_candidate.is_some() {
            self.vote_if_delivered(candidate_id)?;
        }
        Ok(())
    }

    fn ensure_reliable_delivery_slot(
        &mut self,
        context: super::ConsensusObjectContext,
    ) -> Result<&mut ReliableDeliveryState, String> {
        if self
            .reliable_delivery
            .as_ref()
            .is_some_and(|delivery| delivery.context != context)
        {
            return Err("reliable-delivery statement is not for the active slot".to_string());
        }
        if self.reliable_delivery.is_none() {
            self.reliable_delivery =
                Some(ReliableDeliveryState::new(context, &self.epoch_context)?);
        }
        self.reliable_delivery
            .as_mut()
            .ok_or_else(|| "reliable-delivery state was not initialized".to_string())
    }

    fn emit_reliable_delivery_statement(
        &mut self,
        context: super::ConsensusObjectContext,
        phase: ReliableDeliveryPhase,
        candidate: CertifiedCandidateSubject,
    ) -> Result<(), String> {
        let already_signed = self
            .reliable_delivery
            .as_ref()
            .is_some_and(|delivery| match phase {
                ReliableDeliveryPhase::Echo => delivery.local_echo_candidate_id.is_some(),
                ReliableDeliveryPhase::Ready => delivery.local_ready_candidate_id.is_some(),
            });
        if already_signed {
            return Ok(());
        }
        let candidate_id = candidate.id()?;
        let (signing_phase, domain) = match phase {
            ReliableDeliveryPhase::Echo => (
                ConsensusSigningPhase::ProposalEcho,
                POSY_SIMPLIFIED_PROPOSAL_ECHO_DOMAIN,
            ),
            ReliableDeliveryPhase::Ready => (
                ConsensusSigningPhase::ProposalReady,
                POSY_SIMPLIFIED_PROPOSAL_READY_DOMAIN,
            ),
        };
        let mut statement = ReliableDeliveryStatement {
            context: context.clone(),
            phase,
            candidate,
            validator_id: self.local_validator_id.clone(),
            key_id: self.local_key_id.clone(),
            signature: crate::synergy_types::AegisPqSignature {
                algorithm: String::new(),
                signature_bytes: Vec::new(),
            },
        };
        self.signing_authority
            .authorize_before_signature(&ConsensusSigningAuthorization {
                chain_id: context.chain_id,
                network_id: context.network_id.clone(),
                protocol_version: context.protocol_version.clone(),
                epoch: context.epoch,
                height: context.height,
                round: context.round,
                cluster_id: self.local_cluster_id,
                height_context_root: context.epoch_context_root,
                validator_id: self.local_validator_id.clone(),
                key_id: self.local_key_id.clone(),
                phase: signing_phase,
                candidate_id: Some(crate::synergy_types::BlockId(format!(
                    "posy-v3-delivery:{}",
                    candidate_id.to_hex()
                ))),
                highest_prepared_vc_root: None,
                conflict_unlock_tc_id: None,
            })?;
        statement.signature = self
            .signer
            .sign_domain(domain, &statement.signing_bytes()?, &self.local_key_id)
            .map_err(|error| error.to_string())?;
        self.ensure_reliable_delivery_slot(context.clone())?
            .record_local_statement(&statement)?;
        let epoch_context = self.epoch_context.clone();
        let validator_set = self.validator_set.clone();
        let verifier = self.verifier.clone();
        let decision = self
            .reliable_delivery
            .as_mut()
            .ok_or_else(|| "reliable-delivery state was not initialized".to_string())?
            .accept_statement(statement.clone(), &epoch_context, &validator_set, &verifier)?;
        self.persist_reliable_delivery()?;
        self.broadcast(SimplifiedConsensusMessage::ReliableDelivery { statement })?;
        self.metrics.reliable_delivery_broadcast =
            self.metrics.reliable_delivery_broadcast.saturating_add(1);
        if let Some(ready_candidate) = decision.ready_candidate {
            self.emit_reliable_delivery_statement(
                context,
                ReliableDeliveryPhase::Ready,
                ready_candidate,
            )?;
        }
        if let Some(delivered) = decision.delivered_candidate {
            self.vote_if_delivered(delivered.id()?)?;
        }
        Ok(())
    }

    fn vote_if_delivered(&mut self, candidate_id: Hash) -> Result<(), String> {
        let is_delivered = self
            .reliable_delivery
            .as_ref()
            .and_then(|delivery| delivery.delivered_candidate.as_ref())
            .map(CertifiedCandidateSubject::id)
            .transpose()?
            == Some(candidate_id);
        if !is_delivered {
            return Ok(());
        }
        let Some(proposal) = self.validated_proposals.get(&candidate_id).cloned() else {
            // READY can arrive before the signed proposal/body. Delivery is
            // retained, but a block vote is forbidden until local protected
            // execution validation completes.
            return Ok(());
        };
        self.vote_for_proposal(&proposal)
    }

    fn persist_reliable_delivery(&mut self) -> Result<(), String> {
        let delivery = self
            .reliable_delivery
            .clone()
            .ok_or_else(|| "reliable-delivery state was not initialized".to_string())?;
        self.state_machine.persist_reliable_delivery(delivery)
    }

    fn vote_for_proposal(&mut self, proposal: &SimplifiedProposal) -> Result<(), String> {
        let subject = proposal_subject_root(proposal)?;
        if !self.locally_voted_subjects.insert(subject) {
            return Ok(());
        }
        let vote = self.state_machine.sign_block_vote(
            proposal,
            &self.verifier,
            self.local_validator_id.clone(),
            self.local_key_id.clone(),
            &self.signing_authority,
            &mut self.signer,
        )?;
        self.collect_block_vote(vote.clone())?;
        self.broadcast(SimplifiedConsensusMessage::Vote { vote })?;
        self.metrics.votes_broadcast = self.metrics.votes_broadcast.saturating_add(1);
        Ok(())
    }

    fn collect_block_vote(&mut self, vote: BlockVote) -> Result<(), String> {
        self.validate_block_vote_admission(&vote)?;
        verify_block_vote(
            &vote,
            &self.epoch_context,
            &self.validator_set,
            &self.verifier,
        )?;
        let active_set = self
            .validator_set
            .active_for_epoch(self.epoch_context.epoch);
        let subject = SimplifiedQuorumCertificate::from_votes(vec![vote.clone()])?.id()?;
        enforce_pool_bound(&self.votes, subject)?;
        let pool = self.votes.entry(subject).or_default();
        if let Some(existing) = pool.get(&vote.validator_id) {
            return if existing == &vote {
                Ok(())
            } else {
                Err("validator supplied conflicting votes for one QC subject".to_string())
            };
        }
        pool.insert(vote.validator_id.clone(), vote);
        if signer_pool_has_strict_dual_quorum(pool.keys(), &active_set)? {
            let certificate =
                SimplifiedQuorumCertificate::from_votes(pool.values().cloned().collect())?;
            self.accept_quorum_certificate(certificate.clone())?;
            self.broadcast(SimplifiedConsensusMessage::QuorumCertificate { certificate })?;
            self.metrics.quorum_certificates_broadcast =
                self.metrics.quorum_certificates_broadcast.saturating_add(1);
        }
        Ok(())
    }

    fn collect_timeout_vote(&mut self, vote: TimeoutVote) -> Result<(), String> {
        self.validate_timeout_vote_admission(&vote)?;
        verify_timeout_vote(
            &vote,
            &self.epoch_context,
            &self.validator_set,
            &self.verifier,
        )?;
        let active_set = self
            .validator_set
            .active_for_epoch(self.epoch_context.epoch);
        let subject = SimplifiedTimeoutCertificate::from_votes(vec![vote.clone()])?.id()?;
        enforce_pool_bound(&self.timeout_votes, subject)?;
        let pool = self.timeout_votes.entry(subject).or_default();
        if let Some(existing) = pool.get(&vote.validator_id) {
            return if existing == &vote {
                Ok(())
            } else {
                Err("validator supplied conflicting timeout votes for one TC subject".to_string())
            };
        }
        pool.insert(vote.validator_id.clone(), vote);
        if signer_pool_has_strict_dual_quorum(pool.keys(), &active_set)? {
            let reports = pool.values().cloned().collect::<Vec<_>>();
            let mut proof_ids = BTreeSet::new();
            let mut proofs = Vec::new();
            for report in &reports {
                if report.highest_qc == self.state_machine.state().anchor_qc {
                    continue;
                }
                let proof = self
                    .state_machine
                    .state()
                    .certified_qcs
                    .get(&report.highest_qc.height.0)
                    .filter(|proof| proof.reference().ok().as_ref() == Some(&report.highest_qc))
                    .cloned()
                    .ok_or_else(|| {
                        "timeout report highest QC lacks a verified local proof".to_string()
                    })?;
                if proof_ids.insert(proof.id()?) {
                    proofs.push(proof);
                }
            }
            let certificate =
                SimplifiedTimeoutCertificate::from_votes_with_qc_proofs(reports, proofs)?;
            self.accept_timeout_certificate(certificate.clone())?;
            self.broadcast(SimplifiedConsensusMessage::TimeoutCertificate { certificate })?;
            self.metrics.timeout_certificates_broadcast = self
                .metrics
                .timeout_certificates_broadcast
                .saturating_add(1);
        }
        Ok(())
    }

    fn accept_proposal_subject(&mut self, proposal: &SimplifiedProposal) -> Result<(), String> {
        let subject = proposal_subject_root(proposal)?;
        let slot = (proposal.context.height, proposal.context.round.0);
        if self
            .accepted_proposal_subject
            .is_none_or(|(height, round, _)| (height, round) != slot)
        {
            self.accepted_proposal_subject = Some((slot.0, slot.1, subject));
        }
        Ok(())
    }

    fn validate_block_vote_admission(&self, vote: &BlockVote) -> Result<(), String> {
        let (height, round, _) = self.current_progress()?;
        if vote.context.height != height || vote.context.round.0 != round {
            return Err("block vote is not for the active simplified slot".to_string());
        }
        let subject = SimplifiedQuorumCertificate::from_votes(vec![vote.clone()])?.id()?;
        let delivered_subject = self
            .reliable_delivery
            .as_ref()
            .and_then(|delivery| delivery.delivered_candidate.as_ref())
            .map(CertifiedCandidateSubject::id)
            .transpose()?;
        if !self.validated_proposals.contains_key(&subject) || delivered_subject != Some(subject) {
            return Err(
                "block vote has no reliably delivered, locally validated protected proposal"
                    .to_string(),
            );
        }
        Ok(())
    }

    fn validate_timeout_vote_admission(&self, vote: &TimeoutVote) -> Result<(), String> {
        let height = self.state_machine.state().next_height()?;
        let (round, previous_tc_id) = self
            .state_machine
            .state()
            .takeover_for_height(&self.epoch_context, height)?;
        let expected_proposer = self.epoch_context.authorized_proposer(height, round)?;
        if vote.context.height != height
            || vote.context.round.0 != round
            || vote.lease_index != self.epoch_context.lease_index(height)?
            || &vote.timed_out_proposer != expected_proposer
            || vote.previous_tc_id != previous_tc_id
        {
            return Err("timeout vote is not the active canonical timeout statement".to_string());
        }
        let known_highest_qc = vote.highest_qc == self.state_machine.state().anchor_qc
            || self
                .state_machine
                .state()
                .certified_qcs
                .get(&vote.highest_qc.height.0)
                .map(SimplifiedQuorumCertificate::reference)
                .transpose()?
                .is_some_and(|reference| reference == vote.highest_qc);
        if !known_highest_qc || vote.highest_qc.height.0 >= height.0 {
            return Err("timeout vote highest QC is not verified local evidence".to_string());
        }
        Ok(())
    }

    fn accept_quorum_certificate(
        &mut self,
        certificate: SimplifiedQuorumCertificate,
    ) -> Result<(), String> {
        certificate.verify(&self.epoch_context, &self.validator_set, &self.verifier)?;
        if let Some(target) = self.state_machine.preview_finalized_with_qc(&certificate)? {
            let transaction = build_finalization_transaction(
                self.epoch_context.root()?,
                &self.state_machine.state().finalized,
                &target,
                self.state_machine.state(),
                Some(&certificate),
                self.epoch_transition.as_ref(),
            )?;
            self.commit_finalization(&transaction)?;
        }
        self.state_machine.accept_quorum_certificate(
            certificate,
            &self.verifier,
            &self.signing_authority,
        )?;
        self.reset_slot_tracking()?;
        Ok(())
    }

    fn commit_finalization(
        &mut self,
        transaction: &SimplifiedFinalizationTransaction,
    ) -> Result<(), String> {
        transaction.validate().map_err(|error| {
            format!("SIMPLIFIED_LOCAL_FINALIZATION_FAILURE: invalid transaction: {error}")
        })?;
        let receipt = self
            .finalization_sink
            .commit_finalization(transaction)
            .map_err(|error| format!("SIMPLIFIED_LOCAL_FINALIZATION_FAILURE: {error}"))?;
        if receipt.transaction_id != transaction.transaction_id
            || receipt.target_finalized != transaction.target_finalized
        {
            return Err(
                "SIMPLIFIED_LOCAL_FINALIZATION_FAILURE: sink returned a mismatched durable receipt"
                    .to_string(),
            );
        }
        Ok(())
    }

    fn accept_timeout_certificate(
        &mut self,
        certificate: SimplifiedTimeoutCertificate,
    ) -> Result<(), String> {
        self.state_machine
            .accept_timeout_certificate(certificate, &self.verifier)?;
        self.reset_slot_tracking()
    }

    fn accept_or_request_quorum_certificate_material(
        &mut self,
        certificate: SimplifiedQuorumCertificate,
        peer_address: String,
        peer_validator_id: ValidatorId,
    ) -> Result<(), String> {
        certificate.verify(&self.epoch_context, &self.validator_set, &self.verifier)?;
        let candidate_id = certificate.id()?;
        if self.proposal_source.has_verified_material(candidate_id)? {
            return self.accept_quorum_certificate(certificate);
        }
        let expected_finalized = expected_finalized_before_candidate(
            self.state_machine.state(),
            certificate.context.height,
        )?;
        let proposal = self.proposal_for_certificate(&certificate)?;
        self.pending_certified_material.insert(
            candidate_id,
            PendingCertifiedMaterial {
                proposal,
                expected_finalized,
                certificate: Some(certificate),
            },
        );
        self.request_material(candidate_id, peer_address, peer_validator_id)
    }

    fn proposal_for_certificate(
        &self,
        certificate: &SimplifiedQuorumCertificate,
    ) -> Result<SimplifiedProposal, String> {
        let proposer_id = self
            .epoch_context
            .authorized_proposer(certificate.context.height, certificate.context.round.0)?
            .clone();
        let proposer_key_id =
            active_validator(&self.epoch_context, &self.validator_set, &proposer_id)?
                .consensus_public_key
                .key_id
                .clone();
        Ok(SimplifiedProposal {
            context: certificate.context.clone(),
            block_id: certificate.block_id.clone(),
            parent_block_id: certificate.parent_block_id.clone(),
            parent_qc: certificate.parent_qc.clone(),
            takeover_tc_id: certificate.takeover_tc_id,
            protected_execution_root: certificate.protected_execution_root,
            proposer_id,
            proposer_key_id,
            // The QC already authenticates the stable candidate. This
            // reconstructed envelope exists only to drive the independent
            // material adapter; it is never admitted as a signed proposal.
            proposer_signature: crate::synergy_types::AegisPqSignature {
                algorithm: String::new(),
                signature_bytes: Vec::new(),
            },
        })
    }

    fn continue_pending_state_sync_install(&mut self) -> Result<(), String> {
        let pending = self
            .pending_state_sync_install
            .clone()
            .ok_or_else(|| "state-sync material continuation has no pending install".to_string())?;
        if state_sync_has_known_conflict(self.state_machine.state(), &pending.reconstructed)? {
            let conflict_result = self.state_machine.install_state_sync_bundle(
                &pending.bundle,
                &self.verifier,
                &self.signing_authority,
            );
            return match conflict_result {
                Err(error) => Err(error),
                Ok(()) => Err(
                    "CONSENSUS_SAFETY_HALT: conflicting state-sync preview was unexpectedly installed"
                        .to_string(),
                ),
            };
        }
        if pending.reconstructed.highest_qc.height.0
            < self.state_machine.state().highest_qc.height.0
            || pending.reconstructed.finalized.height.0
                < self.state_machine.state().finalized.height.0
        {
            return Err(
                "state-sync bundle would roll consensus safety state backwards".to_string(),
            );
        }
        for certificate in pending.reconstructed.certified_qcs.values() {
            let candidate_id = certificate.id()?;
            if self.proposal_source.has_verified_material(candidate_id)? {
                continue;
            }
            if !self.pending_certified_material.contains_key(&candidate_id) {
                let proposal = self.proposal_for_certificate(certificate)?;
                let expected_finalized = expected_finalized_before_candidate(
                    &pending.reconstructed,
                    certificate.context.height,
                )?;
                self.pending_certified_material.insert(
                    candidate_id,
                    PendingCertifiedMaterial {
                        proposal,
                        expected_finalized,
                        certificate: None,
                    },
                );
            }
            return self.request_material(
                candidate_id,
                pending.peer_address,
                pending.peer_validator_id,
            );
        }
        if pending.reconstructed.finalized.height.0 > self.state_machine.state().finalized.height.0
        {
            let transactions = build_finalization_transactions(
                self.epoch_context.root()?,
                &self.state_machine.state().finalized,
                &pending.reconstructed.finalized,
                &pending.reconstructed,
                None,
                self.epoch_transition.as_ref(),
            )?;
            for transaction in &transactions {
                self.commit_finalization(transaction)?;
            }
        }
        self.state_machine.install_state_sync_bundle(
            &pending.bundle,
            &self.verifier,
            &self.signing_authority,
        )?;
        self.state_sync_stager
            .finish_request(pending.request_id, Instant::now());
        self.pending_state_sync_install = None;
        self.reset_slot_tracking()
    }

    fn request_proposal_material(
        &mut self,
        proposal: SimplifiedProposal,
        peer_address: String,
        peer_validator_id: ValidatorId,
    ) -> Result<(), String> {
        let candidate_id = candidate_for_proposal(&proposal)?.id()?;
        if let Some((existing, _)) = self.pending_material_proposals.get(&candidate_id) {
            if existing != &proposal {
                return Err(
                    "one stable candidate arrived with conflicting proposal envelopes".to_string(),
                );
            }
        } else {
            if self.pending_material_proposals.len() >= self.epoch_context.leader_ring.len() {
                return Err("pending proposal-material pool is full".to_string());
            }
            self.pending_material_proposals
                .insert(candidate_id, (proposal.clone(), peer_address.clone()));
        }
        self.request_material(candidate_id, peer_address, peer_validator_id)
    }

    fn request_material(
        &mut self,
        candidate_id: Hash,
        peer_address: String,
        peer_validator_id: ValidatorId,
    ) -> Result<(), String> {
        let now = Instant::now();
        if let Some(request_id) = self.material_request_ids.get(&candidate_id).copied() {
            if self.material_stager.has_outstanding(request_id, now) {
                return Ok(());
            }
            self.material_request_ids.remove(&candidate_id);
        }
        let next_sequence = self
            .material_request_sequence
            .checked_add(1)
            .ok_or_else(|| "proposal-material request sequence overflowed".to_string())?;
        let epoch_context_root = self.epoch_context.root()?;
        let subject = serde_json::to_vec(&(
            epoch_context_root,
            &self.local_validator_id,
            candidate_id,
            &peer_address,
            &peer_validator_id,
            next_sequence,
        ))
        .map_err(|error| format!("serialize proposal-material request identity: {error}"))?;
        let request_id =
            Hash::from_domain_bytes("SYNERGY_POSY_SIMPLIFIED_MATERIAL_REQUEST_V1", &subject);
        self.material_stager
            .register_request(request_id, candidate_id, &peer_validator_id, now)?;
        if let Err(error) = self.send_to(
            &peer_address,
            &peer_validator_id,
            SimplifiedConsensusMessage::MaterialRequest {
                epoch_context_root,
                stable_candidate_id: candidate_id,
                request_id,
            },
        ) {
            self.material_stager.finish_request(request_id);
            return Err(error);
        }
        self.material_request_ids.insert(candidate_id, request_id);
        self.material_request_sequence = next_sequence;
        self.metrics.material_requests_sent = self.metrics.material_requests_sent.saturating_add(1);
        Ok(())
    }

    fn request_state_sync_for_future_evidence(&mut self) -> Result<(), String> {
        const MIN_STATE_SYNC_REQUEST_INTERVAL: Duration = Duration::from_secs(1);
        let now = Instant::now();
        if self.last_state_sync_request.is_some_and(|last| {
            now.saturating_duration_since(last) < MIN_STATE_SYNC_REQUEST_INTERVAL
        }) {
            return Ok(());
        }
        let epoch_context_root = self.epoch_context.root()?;
        let next_sequence = self
            .state_sync_request_sequence
            .checked_add(1)
            .ok_or_else(|| "state-sync request sequence overflowed".to_string())?;
        let request_subject = serde_json::to_vec(&(
            epoch_context_root,
            &self.local_validator_id,
            self.state_machine.state().next_height()?,
            next_sequence,
        ))
        .map_err(|error| format!("serialize state-sync request identity: {error}"))?;
        let request_id = Hash::from_domain_bytes(
            "SYNERGY_POSY_SIMPLIFIED_STATE_SYNC_REQUEST_V1",
            &request_subject,
        );
        self.state_sync_stager.register_request(request_id, now)?;
        if let Err(error) = self.broadcast(SimplifiedConsensusMessage::StateSyncRequest {
            epoch_context_root,
            request_id,
        }) {
            self.state_sync_stager.finish_request(request_id, now);
            return Err(error);
        }
        self.state_sync_request_sequence = next_sequence;
        self.last_state_sync_request = Some(now);
        Ok(())
    }

    fn admit_state_sync_serve(&mut self, peer: &ValidatorId, now: Instant) -> Result<(), String> {
        let within_window = |timestamp: &Instant| {
            now.saturating_duration_since(*timestamp) < SIMPLIFIED_STATE_SYNC_SERVE_WINDOW
        };
        self.state_sync_global_serves.retain(within_window);
        self.state_sync_peer_serves.retain(|_, timestamps| {
            timestamps.retain(within_window);
            !timestamps.is_empty()
        });
        let peer_serves = self.state_sync_peer_serves.entry(peer.clone()).or_default();
        if peer_serves.len() >= MAX_SIMPLIFIED_STATE_SYNC_SERVES_PER_PEER_WINDOW {
            return Err("state-sync peer serving budget exhausted".to_string());
        }
        let global_limit = self
            .epoch_context
            .leader_ring
            .len()
            .checked_mul(MAX_SIMPLIFIED_STATE_SYNC_SERVES_PER_PEER_WINDOW)
            .ok_or_else(|| "state-sync global serving budget overflowed".to_string())?;
        if self.state_sync_global_serves.len() >= global_limit {
            return Err("state-sync global serving budget exhausted".to_string());
        }
        peer_serves.push_back(now);
        self.state_sync_global_serves.push_back(now);
        Ok(())
    }

    fn admit_material_serve(&mut self, peer: &ValidatorId, now: Instant) -> Result<(), String> {
        let within_window = |timestamp: &Instant| {
            now.saturating_duration_since(*timestamp) < SIMPLIFIED_MATERIAL_SERVE_WINDOW
        };
        self.material_global_serves.retain(within_window);
        self.material_peer_serves.retain(|_, timestamps| {
            timestamps.retain(within_window);
            !timestamps.is_empty()
        });
        let peer_serves = self.material_peer_serves.entry(peer.clone()).or_default();
        if peer_serves.len() >= MAX_SIMPLIFIED_MATERIAL_SERVES_PER_PEER_WINDOW {
            return Err("proposal-material peer serving budget exhausted".to_string());
        }
        let global_limit = self
            .epoch_context
            .leader_ring
            .len()
            .checked_mul(MAX_SIMPLIFIED_MATERIAL_SERVES_PER_PEER_WINDOW)
            .ok_or_else(|| "proposal-material global serving budget overflowed".to_string())?;
        if self.material_global_serves.len() >= global_limit {
            return Err("proposal-material global serving budget exhausted".to_string());
        }
        peer_serves.push_back(now);
        self.material_global_serves.push_back(now);
        Ok(())
    }

    fn reset_slot_tracking(&mut self) -> Result<(), String> {
        let (height, round, _) = self.current_progress()?;
        self.votes.clear();
        self.timeout_votes.clear();
        self.locally_voted_subjects.clear();
        if self
            .locally_proposed_slot
            .is_some_and(|slot| slot != (height, round))
        {
            self.locally_proposed_slot = None;
        }
        if self
            .locally_timed_out_slot
            .is_some_and(|slot| slot != (height, round))
        {
            self.locally_timed_out_slot = None;
        }
        if self
            .accepted_proposal_subject
            .is_some_and(|(accepted_height, accepted_round, _)| {
                (accepted_height, accepted_round) != (height, round)
            })
        {
            self.accepted_proposal_subject = None;
        }
        if self.reliable_delivery.as_ref().is_some_and(|delivery| {
            (delivery.context.height, delivery.context.round.0) != (height, round)
        }) {
            self.reliable_delivery = None;
            self.validated_proposals.clear();
        }
        if self
            .pending_material_proposals
            .values()
            .any(|(proposal, _)| {
                (proposal.context.height, proposal.context.round.0) != (height, round)
            })
        {
            self.pending_material_proposals.clear();
            self.material_request_ids.clear();
            self.material_stager = SimplifiedMaterialStager::new(self.epoch_context.root()?)?;
        }
        Ok(())
    }

    fn current_progress(&self) -> Result<(Height, u64, bool), String> {
        let height = self.state_machine.state().next_height()?;
        let (round, _) = self
            .state_machine
            .state()
            .takeover_for_height(&self.epoch_context, height)?;
        let proposal_accepted =
            self.accepted_proposal_subject
                .is_some_and(|(accepted_height, accepted_round, _)| {
                    (accepted_height, accepted_round) == (height, round)
                });
        Ok((height, round, proposal_accepted))
    }

    fn broadcast(&mut self, message: SimplifiedConsensusMessage) -> Result<(), String> {
        validate_simplified_consensus_message_size(&message)?;
        let sent = self
            .egress
            .broadcast(&message)
            .map_err(|error| format!("SIMPLIFIED_LOCAL_DRIVER_FAILURE: egress failed: {error}"))?;
        if sent == 0 {
            return Err(
                "simplified PoSy broadcast reached no authenticated frozen validators".to_string(),
            );
        }
        Ok(())
    }

    fn send_to(
        &mut self,
        peer_address: &str,
        expected_validator_id: &ValidatorId,
        message: SimplifiedConsensusMessage,
    ) -> Result<(), String> {
        validate_simplified_consensus_message_size(&message)?;
        let sent = self
            .egress
            .send_to(peer_address, expected_validator_id, &message)
            .map_err(|error| {
                format!("SIMPLIFIED_LOCAL_DRIVER_FAILURE: targeted egress failed: {error}")
            })?;
        if sent != 1 {
            return Err(
                "SIMPLIFIED_LOCAL_DRIVER_FAILURE: targeted simplified-consensus egress reached no authenticated requester"
                    .to_string(),
            );
        }
        Ok(())
    }
}

fn enforce_pool_bound<T>(pool: &BTreeMap<Hash, T>, subject: Hash) -> Result<(), String> {
    if !pool.contains_key(&subject) && pool.len() >= MAX_SIMPLIFIED_VOTE_SUBJECTS {
        return Err("simplified consensus vote-subject pool is full".to_string());
    }
    Ok(())
}

fn signer_pool_has_strict_dual_quorum<'a>(
    signers: impl Iterator<Item = &'a ValidatorId>,
    active_set: &ValidatorSet,
) -> Result<bool, String> {
    let signer_ids = signers.collect::<BTreeSet<_>>();
    let signer_count =
        u128::try_from(signer_ids.len()).map_err(|_| "signer count exceeds u128".to_string())?;
    let validator_count = u128::try_from(active_set.validators.len())
        .map_err(|_| "validator count exceeds u128".to_string())?;
    if validator_count == 0 {
        return Err("frozen active validator set is empty".to_string());
    }
    let mut signed_weight = 0_u128;
    let mut total_weight = 0_u128;
    for validator in &active_set.validators {
        let weight = u128::from(validator.voting_weight);
        total_weight = total_weight
            .checked_add(weight)
            .ok_or_else(|| "frozen validator weight overflowed".to_string())?;
        if signer_ids.contains(&validator.validator_id) {
            signed_weight = signed_weight
                .checked_add(weight)
                .ok_or_else(|| "signed validator weight overflowed".to_string())?;
        }
    }
    if total_weight == 0 {
        return Err("frozen active validator weight is zero".to_string());
    }
    Ok(signer_count
        .checked_mul(3)
        .ok_or_else(|| "signer quorum multiplication overflowed".to_string())?
        > validator_count
            .checked_mul(2)
            .ok_or_else(|| "validator quorum multiplication overflowed".to_string())?
        && signed_weight
            .checked_mul(3)
            .ok_or_else(|| "signed-weight quorum multiplication overflowed".to_string())?
            > total_weight
                .checked_mul(2)
                .ok_or_else(|| "total-weight quorum multiplication overflowed".to_string())?)
}

/// Detects overlap conflicts before a state-sync bundle is allowed to reach
/// the injected finalization transaction. The state machine performs the same
/// comparison while entering SafetyHalt; this preview only establishes the
/// safe order between peer verification, conflict handling, and local I/O.
fn state_sync_has_known_conflict(
    local: &SimplifiedSafetyState,
    reconstructed: &SimplifiedSafetyState,
) -> Result<bool, String> {
    for (height, local_qc) in &local.certified_qcs {
        if let Some(peer_qc) = reconstructed.certified_qcs.get(height) {
            if local_qc.id()? != peer_qc.id()? {
                return Ok(true);
            }
        }
    }
    let mut local_tcs = BTreeMap::new();
    for certificates in local.certified_tcs.values() {
        for certificate in certificates {
            local_tcs.insert(
                (certificate.context.height.0, certificate.context.round.0),
                certificate.id()?,
            );
        }
    }
    for certificates in reconstructed.certified_tcs.values() {
        for certificate in certificates {
            let slot = (certificate.context.height.0, certificate.context.round.0);
            if let Some(local_id) = local_tcs.get(&slot) {
                if *local_id != certificate.id()? {
                    return Ok(true);
                }
            }
        }
    }
    Ok(false)
}

fn build_finalization_transaction(
    epoch_context_root: Hash,
    expected_previous_finalized: &FinalizedBlockRecord,
    target_finalized: &FinalizedBlockRecord,
    evidence: &SimplifiedSafetyState,
    newest: Option<&SimplifiedQuorumCertificate>,
    epoch_transition: Option<&VerifiedSimplifiedEpochTransition>,
) -> Result<SimplifiedFinalizationTransaction, String> {
    const FORMAT: &str = "synergy-posy-simplified-finalization-transaction-v3";
    if epoch_context_root.is_zero()
        || target_finalized.height.0 <= expected_previous_finalized.height.0
    {
        return Err("finalization transaction does not advance a pinned context".to_string());
    }
    validate_finalization_transition_capability(epoch_context_root, evidence, epoch_transition)?;
    let first_height = expected_previous_finalized
        .height
        .0
        .checked_add(1)
        .ok_or_else(|| "finalization transaction height overflowed".to_string())?;
    let mut commitments = Vec::new();
    let mut expected_parent = expected_previous_finalized.block_id.clone();
    for height in first_height..=target_finalized.height.0 {
        let certificate = finalization_certificate_at(height, evidence, None, epoch_transition)
            .ok_or_else(|| format!("finalization transaction lacks certified height {height}"))?;
        if certificate.context.height.0 != height
            || certificate.parent_block_id != expected_parent
            || certificate.protected_execution_root.is_zero()
        {
            return Err(
                "finalization transaction path is not consecutive and protected".to_string(),
            );
        }
        let qc_id = certificate.id()?;
        commitments.push(SimplifiedFinalizedCommitment {
            height: certificate.context.height,
            block_id: certificate.block_id.clone(),
            parent_block_id: certificate.parent_block_id.clone(),
            qc_id,
            protected_execution_root: certificate.protected_execution_root,
            certificate: certificate.clone(),
        });
        expected_parent = certificate.block_id.clone();
    }
    let last = commitments
        .last()
        .ok_or_else(|| "finalization transaction path is empty".to_string())?;
    if last.height != target_finalized.height
        || last.block_id != target_finalized.block_id
        || last.qc_id != target_finalized.qc_id
    {
        return Err("finalization target does not match its certified commitment".to_string());
    }
    let mut finality_witness = Vec::with_capacity(3);
    for height in target_finalized.height.0
        ..=target_finalized
            .height
            .0
            .checked_add(2)
            .ok_or_else(|| "finalization witness height overflowed".to_string())?
    {
        let certificate = finalization_certificate_at(height, evidence, newest, epoch_transition)
            .ok_or_else(|| {
            format!("finalization transaction lacks three-chain height {height}")
        })?;
        finality_witness.push(certificate.clone());
    }
    let subject = SimplifiedFinalizationTransactionSubject {
        format: FORMAT,
        epoch_context_root,
        expected_previous_finalized,
        commitments: &commitments,
        target_finalized,
        finality_witness: &finality_witness,
    };
    let transaction_id = Hash::from_domain_bytes(
        "SYNERGY_POSY_SIMPLIFIED_FINALIZATION_TRANSACTION_V3",
        &serde_json::to_vec(&subject)
            .map_err(|error| format!("serialize finalization transaction: {error}"))?,
    );
    let transaction = SimplifiedFinalizationTransaction {
        format: FORMAT.to_string(),
        transaction_id,
        epoch_context_root,
        expected_previous_finalized: expected_previous_finalized.clone(),
        commitments,
        target_finalized: target_finalized.clone(),
        finality_witness,
    };
    transaction.validate()?;
    Ok(transaction)
}

fn build_finalization_transactions(
    epoch_context_root: Hash,
    expected_previous_finalized: &FinalizedBlockRecord,
    target_finalized: &FinalizedBlockRecord,
    evidence: &SimplifiedSafetyState,
    newest: Option<&SimplifiedQuorumCertificate>,
    epoch_transition: Option<&VerifiedSimplifiedEpochTransition>,
) -> Result<Vec<SimplifiedFinalizationTransaction>, String> {
    if target_finalized.height.0 <= expected_previous_finalized.height.0 {
        return Err("finalization transaction sequence does not advance".to_string());
    }
    validate_finalization_transition_capability(epoch_context_root, evidence, epoch_transition)?;
    let mut transactions = Vec::new();
    let mut previous = expected_previous_finalized.clone();
    while previous.height.0 < target_finalized.height.0 {
        let batch_target_height = previous
            .height
            .0
            .checked_add(
                u64::try_from(MAX_SIMPLIFIED_FINALIZATION_COMMITMENTS_PER_TRANSACTION)
                    .map_err(|_| "finalization batch size exceeds u64".to_string())?,
            )
            .unwrap_or(u64::MAX)
            .min(target_finalized.height.0);
        let certificate =
            finalization_certificate_at(batch_target_height, evidence, newest, epoch_transition)
                .ok_or_else(|| {
                    format!(
                        "finalization transaction sequence lacks target QC {batch_target_height}"
                    )
                })?;
        let batch_target = FinalizedBlockRecord {
            height: certificate.context.height,
            block_id: certificate.block_id.clone(),
            qc_id: certificate.id()?,
        };
        let transaction = build_finalization_transaction(
            epoch_context_root,
            &previous,
            &batch_target,
            evidence,
            newest,
            epoch_transition,
        )?;
        previous = batch_target;
        transactions.push(transaction);
    }
    if previous != *target_finalized {
        return Err("finalization transaction sequence ended at another target".to_string());
    }
    Ok(transactions)
}

fn validate_finalization_transition_capability(
    epoch_context_root: Hash,
    evidence: &SimplifiedSafetyState,
    epoch_transition: Option<&VerifiedSimplifiedEpochTransition>,
) -> Result<(), String> {
    match (
        evidence.epoch_transition_tail_qcs.is_empty(),
        epoch_transition,
    ) {
        (true, None) => Ok(()),
        (false, Some(transition))
            if transition.next_epoch_context().root()? == epoch_context_root
                && evidence.epoch_context_root == epoch_context_root
                && evidence.anchor_qc == *transition.certified_parent()
                && evidence.epoch_transition_tail_qcs == transition.transition_tail() =>
        {
            Ok(())
        }
        _ => Err(
            "cross-epoch finalization requires the exact receiver-owned verified transition"
                .to_string(),
        ),
    }
}

fn finalization_certificate_at<'a>(
    height: u64,
    evidence: &'a SimplifiedSafetyState,
    newest: Option<&'a SimplifiedQuorumCertificate>,
    epoch_transition: Option<&'a VerifiedSimplifiedEpochTransition>,
) -> Option<&'a SimplifiedQuorumCertificate> {
    newest
        .filter(|certificate| certificate.context.height.0 == height)
        .or_else(|| evidence.certified_qcs.get(&height))
        .or_else(|| {
            epoch_transition.and_then(|transition| {
                transition
                    .transition_tail()
                    .iter()
                    .find(|certificate| certificate.context.height.0 == height)
            })
        })
}

fn proposal_subject_root(proposal: &SimplifiedProposal) -> Result<Hash, String> {
    candidate_for_proposal(proposal)?.id()
}

fn candidate_for_proposal(
    proposal: &SimplifiedProposal,
) -> Result<CertifiedCandidateSubject, String> {
    CertifiedCandidateSubject::new(
        proposal.context.clone(),
        proposal.block_id.clone(),
        proposal.parent_block_id.clone(),
        proposal.parent_qc.clone(),
        proposal.protected_execution_root,
    )
}

/// Returns the deterministic three-chain finality pointer that was current
/// when a candidate at `height` was proposed. This lets a state-sync receiver
/// independently replay old material instead of trusting the serving peer to
/// describe the proposal-time application boundary.
fn expected_finalized_before_candidate(
    evidence: &SimplifiedSafetyState,
    height: Height,
) -> Result<FinalizedBlockRecord, String> {
    let base = if let Some(seed) = evidence.epoch_transition_tail_qcs.first() {
        FinalizedBlockRecord {
            height: seed.context.height,
            block_id: seed.block_id.clone(),
            qc_id: seed.id()?,
        }
    } else {
        FinalizedBlockRecord {
            height: evidence.anchor_qc.height,
            block_id: evidence.anchor_qc.block_id.clone(),
            qc_id: evidence.anchor_qc.qc_id,
        }
    };
    if height.0 <= base.height.0 {
        return Err("candidate height does not follow the epoch finality seed".to_string());
    }
    let target_height = height.0.saturating_sub(3);
    if target_height <= base.height.0 {
        return Ok(base);
    }
    let certificate = evidence
        .certified_qcs
        .get(&target_height)
        .or_else(|| {
            evidence
                .epoch_transition_tail_qcs
                .iter()
                .find(|certificate| certificate.context.height.0 == target_height)
        })
        .ok_or_else(|| {
            format!("proposal-time finality evidence lacks certified height {target_height}")
        })?;
    Ok(FinalizedBlockRecord {
        height: certificate.context.height,
        block_id: certificate.block_id.clone(),
        qc_id: certificate.id()?,
    })
}

fn active_validator<'a>(
    epoch_context: &SimplifiedEpochContext,
    validator_set: &'a ValidatorSet,
    validator_id: &ValidatorId,
) -> Result<&'a ValidatorRecord, String> {
    validator_set
        .validators
        .iter()
        .find(|validator| {
            &validator.validator_id == validator_id
                && validator.is_active_for_epoch(epoch_context.epoch)
        })
        .ok_or_else(|| "vote signer is absent from the frozen active set".to_string())
}

fn verify_block_vote<V: ConsensusSignatureVerifier>(
    vote: &BlockVote,
    epoch_context: &SimplifiedEpochContext,
    validator_set: &ValidatorSet,
    verifier: &V,
) -> Result<(), String> {
    vote.context.validate_against(epoch_context)?;
    let validator = active_validator(epoch_context, validator_set, &vote.validator_id)?;
    if vote.key_id != validator.consensus_public_key.key_id {
        return Err("block vote uses the wrong frozen consensus key".to_string());
    }
    verifier.verify_consensus_signature(
        POSY_SIMPLIFIED_BLOCK_VOTE_DOMAIN,
        &vote.signing_bytes()?,
        validator,
        &vote.key_id,
        vote.context.epoch,
        &vote.signature,
    )
}

fn verify_timeout_vote<V: ConsensusSignatureVerifier>(
    vote: &TimeoutVote,
    epoch_context: &SimplifiedEpochContext,
    validator_set: &ValidatorSet,
    verifier: &V,
) -> Result<(), String> {
    vote.context.validate_against(epoch_context)?;
    let validator = active_validator(epoch_context, validator_set, &vote.validator_id)?;
    if vote.key_id != validator.consensus_public_key.key_id {
        return Err("timeout vote uses the wrong frozen consensus key".to_string());
    }
    verifier.verify_consensus_signature(
        POSY_SIMPLIFIED_TIMEOUT_VOTE_DOMAIN,
        &vote.signing_bytes()?,
        validator,
        &vote.key_id,
        vote.context.epoch,
        &vote.signature,
    )
}

static SIMPLIFIED_INGRESS: OnceLock<Mutex<Option<SyncSender<SimplifiedConsensusEnvelope>>>> =
    OnceLock::new();

fn ingress_slot() -> &'static Mutex<Option<SyncSender<SimplifiedConsensusEnvelope>>> {
    SIMPLIFIED_INGRESS.get_or_init(|| Mutex::new(None))
}

pub fn install_simplified_consensus_ingress(
    capacity: usize,
) -> Result<Receiver<SimplifiedConsensusEnvelope>, String> {
    if capacity == 0 {
        return Err("simplified consensus ingress capacity must be nonzero".to_string());
    }
    let (sender, receiver) = mpsc::sync_channel(capacity);
    let mut slot = ingress_slot()
        .lock()
        .map_err(|_| "simplified consensus ingress lock is poisoned".to_string())?;
    if slot.is_some() {
        return Err("simplified consensus ingress is already installed".to_string());
    }
    *slot = Some(sender);
    Ok(receiver)
}

pub fn remove_simplified_consensus_ingress() -> Result<(), String> {
    *ingress_slot()
        .lock()
        .map_err(|_| "simplified consensus ingress lock is poisoned".to_string())? = None;
    Ok(())
}

pub fn dispatch_simplified_consensus_message(
    peer_address: &str,
    authenticated_peer: Option<AuthenticatedSimplifiedConsensusPeer>,
    message: SimplifiedConsensusMessage,
) -> Result<(), String> {
    validate_simplified_consensus_message_size(&message)?;
    let authenticated_peer = authenticated_peer.ok_or_else(|| {
        "simplified consensus requires an authenticated frozen-validator peer".to_string()
    })?;
    let sender = ingress_slot()
        .lock()
        .map_err(|_| "simplified consensus ingress lock is poisoned".to_string())?
        .clone()
        .ok_or_else(|| {
            "simplified PoSy driver is not running; refusing consensus message".to_string()
        })?;
    sender
        .try_send(SimplifiedConsensusEnvelope {
            peer_address: peer_address.to_string(),
            authenticated_peer,
            message,
        })
        .map_err(|error| match error {
            TrySendError::Full(_) => "simplified consensus ingress is full".to_string(),
            TrySendError::Disconnected(_) => {
                "simplified consensus ingress is disconnected".to_string()
            }
        })
}

pub fn run_simplified_posy_driver<S, E, F>(
    driver: &mut SimplifiedPosyDriver<S, E, F>,
    receiver: &Receiver<SimplifiedConsensusEnvelope>,
    running: &AtomicBool,
) -> Result<SimplifiedDriverMetrics, String>
where
    S: SimplifiedProtectedProposalSource,
    E: SimplifiedConsensusEgress,
    F: SimplifiedFinalizationSink,
{
    run_simplified_posy_driver_with_peer_rejection_observer(driver, receiver, running, |_| {})
}

/// Runs the production driver while reporting rejected peer artifacts to a
/// caller-owned telemetry hook. The hook is observational only: it cannot
/// change admission, suppress fatal local failures, or inject messages.
pub fn run_simplified_posy_driver_with_peer_rejection_observer<S, E, F, O>(
    driver: &mut SimplifiedPosyDriver<S, E, F>,
    receiver: &Receiver<SimplifiedConsensusEnvelope>,
    running: &AtomicBool,
    mut observe_peer_rejection: O,
) -> Result<SimplifiedDriverMetrics, String>
where
    S: SimplifiedProtectedProposalSource,
    E: SimplifiedConsensusEgress,
    F: SimplifiedFinalizationSink,
    O: FnMut(&str),
{
    let mut observed_progress = driver.current_progress()?;
    let mut progress_deadline = Instant::now() + driver.timing.deadline_for(observed_progress.2);
    while running.load(Ordering::Acquire) {
        driver.drive_scheduled_proposal()?;
        let progress = driver.current_progress()?;
        if progress != observed_progress {
            observed_progress = progress;
            progress_deadline = Instant::now() + driver.timing.deadline_for(observed_progress.2);
        }
        if Instant::now() >= progress_deadline {
            driver.on_proposal_timeout()?;
            progress_deadline = Instant::now() + driver.timing.max_round_timeout;
        }
        let receive_wait = progress_deadline
            .saturating_duration_since(Instant::now())
            .min(Duration::from_millis(50));
        match receiver.recv_timeout(receive_wait) {
            Ok(envelope) => {
                if let Err(error) = driver.handle_envelope(envelope) {
                    match classify_simplified_envelope_failure(error) {
                        SimplifiedEnvelopeFailure::PeerRejected(error) => {
                            observe_peer_rejection(&error)
                        }
                        SimplifiedEnvelopeFailure::FatalLocal(error) => return Err(error),
                    }
                }
            }
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => {
                return Err("simplified consensus ingress disconnected".to_string())
            }
        }
    }
    Ok(driver.metrics())
}

/// Checks that a driver startup context exactly matches its activation
/// authority. Used by role startup before any mailbox or signer is exposed.
pub fn validate_simplified_driver_activation(
    activation: &GenesisBoundSimplifiedActivation,
    epoch_context: &SimplifiedEpochContext,
    validator_set: &ValidatorSet,
) -> Result<(), String> {
    activation.validate()?;
    epoch_context.validate_against(validator_set)?;
    if &activation.frozen_validator_set != validator_set
        || epoch_context.consensus_parameter_root != activation.parameter_root_sha3_512
        || epoch_context.epoch.0 != activation.activation_epoch
        || epoch_context.epoch_start_height.0 != activation.activation_height
        || epoch_context.v2_boundary_anchor.is_none()
    {
        return Err("simplified driver inputs do not match the finalized activation".to_string());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::simplified_posy::{
        ConsensusObjectContext, DurableSimplifiedProposalMaterialStore,
        DurableVerifiedSimplifiedProposalSource, FinalizedBlockRecord, ParticipantSignature,
        SimplifiedCoreMaterialAdapter, SimplifiedCoreMaterialConfiguration,
        SimplifiedEpochTransitionAuthorization, SimplifiedEpochTransitionProof,
        SimplifiedTransitionAuthorityVerifier, POSY_SIMPLIFIED_EPOCH_TRANSITION_FORMAT,
        POSY_SIMPLIFIED_EPOCH_TRANSITION_SCHEMA_VERSION, POSY_SIMPLIFIED_PROPOSAL_DOMAIN,
        POSY_SIMPLIFIED_PROTOCOL_VERSION,
    };
    use crate::consensus_parameters::ConsensusParameterRoot;
    use crate::execution::ExecutionState;
    use crate::synergy_types::{
        AegisPqKeyRole, AegisPqPublicKey, AegisPqSignature, BlockId, CanonicalSerialize,
        ClusterAssignment, ClusterId, ClusterMap, Epoch, Height, Round, UmaId, ValidatorStatus,
        TESTNET_V3_CONSENSUS_SIGNATURE_ALGORITHM, TESTNET_V3_MLDSA65_PUBLIC_KEY_BYTES,
    };
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[derive(Clone)]
    struct TestProposalSource {
        block_id: BlockId,
        protected_execution_root: Hash,
        directives: Arc<Mutex<Vec<SimplifiedProposalDirective>>>,
        remote_material_available: bool,
    }

    impl TestProposalSource {
        fn new(label: &str) -> Self {
            Self {
                block_id: BlockId(format!("driver-protected-block-{label}")),
                protected_execution_root: Hash::from_domain_bytes(
                    "driver-protected-execution",
                    label.as_bytes(),
                ),
                directives: Arc::new(Mutex::new(Vec::new())),
                remote_material_available: true,
            }
        }
    }

    impl SimplifiedProtectedProposalSource for TestProposalSource {
        fn proposal_for(
            &mut self,
            _epoch_context: &SimplifiedEpochContext,
            directive: &SimplifiedProposalDirective,
        ) -> Result<Option<SimplifiedProposal>, String> {
            self.directives
                .lock()
                .expect("proposal directive lock")
                .push(directive.clone());
            let (block_id, parent_block_id, parent_qc, protected_execution_root) = directive
                .mandatory_carry_candidate
                .as_ref()
                .map(|candidate| {
                    (
                        candidate.block_id.clone(),
                        candidate.parent_block_id.clone(),
                        candidate.parent_qc.clone(),
                        candidate.protected_execution_root,
                    )
                })
                .unwrap_or_else(|| {
                    (
                        BlockId(format!(
                            "{}-{}",
                            self.block_id.0, directive.context.height.0
                        )),
                        directive.highest_qc.block_id.clone(),
                        directive.highest_qc.clone(),
                        self.protected_execution_root,
                    )
                });
            Ok(Some(SimplifiedProposal {
                context: directive.context.clone(),
                proposer_id: directive.proposer_id.clone(),
                block_id,
                parent_block_id,
                parent_qc,
                takeover_tc_id: directive.takeover_tc_id,
                protected_execution_root,
                proposer_key_id: directive.proposer_key_id.clone(),
                proposer_signature: AegisPqSignature {
                    algorithm: String::new(),
                    signature_bytes: Vec::new(),
                },
            }))
        }

        fn recompute_received_protected_execution_root(
            &mut self,
            proposal: &SimplifiedProposal,
            _expected_finalized: &FinalizedBlockRecord,
        ) -> Result<Option<Hash>, String> {
            Ok(self
                .remote_material_available
                .then_some(proposal.protected_execution_root))
        }

        fn has_verified_material(&mut self, _stable_candidate_id: Hash) -> Result<bool, String> {
            Ok(self.remote_material_available)
        }
    }

    #[derive(Debug, Clone, Default)]
    struct RecordingEgress {
        messages: Arc<Mutex<Vec<SimplifiedConsensusMessage>>>,
    }

    impl SimplifiedConsensusEgress for RecordingEgress {
        fn broadcast(&mut self, message: &SimplifiedConsensusMessage) -> Result<usize, String> {
            self.messages
                .lock()
                .expect("recording egress lock")
                .push(message.clone());
            Ok(5)
        }

        fn send_to(
            &mut self,
            _peer_address: &str,
            _expected_validator_id: &ValidatorId,
            message: &SimplifiedConsensusMessage,
        ) -> Result<usize, String> {
            self.messages
                .lock()
                .expect("recording egress lock")
                .push(message.clone());
            Ok(1)
        }
    }

    #[derive(Debug, Clone, Default)]
    struct RecordingFinalizationSink {
        state: Arc<Mutex<RecordingFinalizationState>>,
    }

    #[derive(Debug, Clone, Default)]
    struct RecordingFinalizationState {
        committed: BTreeMap<Hash, SimplifiedFinalizationTransaction>,
        attempts: Vec<Hash>,
        fail_before_commit_once: bool,
        fail_after_commit_once: bool,
    }

    impl SimplifiedFinalizationSink for RecordingFinalizationSink {
        fn commit_finalization(
            &mut self,
            transaction: &SimplifiedFinalizationTransaction,
        ) -> Result<SimplifiedFinalizationReceipt, SimplifiedFinalizationSinkError> {
            let mut state = self.state.lock().expect("finalization sink lock");
            state.attempts.push(transaction.transaction_id);
            if std::mem::take(&mut state.fail_before_commit_once) {
                return Err(SimplifiedFinalizationSinkError::Unavailable(
                    "injected pre-commit failure".to_string(),
                ));
            }
            if let Some(existing) = state.committed.get(&transaction.transaction_id) {
                if existing != transaction {
                    return Err(SimplifiedFinalizationSinkError::CommitRejected(
                        "transaction id was reused for different contents".to_string(),
                    ));
                }
                return Ok(SimplifiedFinalizationReceipt {
                    transaction_id: transaction.transaction_id,
                    target_finalized: transaction.target_finalized.clone(),
                });
            }
            state
                .committed
                .insert(transaction.transaction_id, transaction.clone());
            if std::mem::take(&mut state.fail_after_commit_once) {
                return Err(SimplifiedFinalizationSinkError::Unavailable(
                    "injected crash after durable commit".to_string(),
                ));
            }
            Ok(SimplifiedFinalizationReceipt {
                transaction_id: transaction.transaction_id,
                target_finalized: transaction.target_finalized.clone(),
            })
        }
    }

    struct TestTransitionAuthorityVerifier;

    impl SimplifiedTransitionAuthorityVerifier for TestTransitionAuthorityVerifier {
        fn verify_finalized_transition_authority(
            &self,
            finalized_qc: &SimplifiedQuorumCertificate,
            transition_subject_root: Hash,
            authority_evidence: &[u8],
        ) -> Result<(), String> {
            let expected = (
                transition_subject_root,
                finalized_qc.protected_execution_root,
            )
                .canonical_bytes()?;
            if authority_evidence != expected.as_slice() {
                return Err("test transition authority evidence mismatch".to_string());
            }
            Ok(())
        }
    }

    type TestDriver =
        SimplifiedPosyDriver<TestProposalSource, RecordingEgress, RecordingFinalizationSink>;

    struct DriverFixture {
        driver: TestDriver,
        state_path: PathBuf,
        signer_journal_path: PathBuf,
    }

    struct TransitionDriverFixture {
        driver: TestDriver,
        transition: VerifiedSimplifiedEpochTransition,
        first_current_qc: SimplifiedQuorumCertificate,
        state_path: PathBuf,
        signer_journal_path: PathBuf,
    }

    type DurableMaterialSource =
        DurableVerifiedSimplifiedProposalSource<SimplifiedCoreMaterialAdapter>;
    type DurableMaterialDriver =
        SimplifiedPosyDriver<DurableMaterialSource, RecordingEgress, RecordingFinalizationSink>;

    struct DurableMaterialDriverFixture {
        driver: DurableMaterialDriver,
        serving_source: DurableMaterialSource,
        proposal: SimplifiedProposal,
        proposer_index: usize,
        epoch_context: SimplifiedEpochContext,
        validator_set: ValidatorSet,
        material_configuration: SimplifiedCoreMaterialConfiguration,
        finalized: FinalizedBlockRecord,
        serving_directory: PathBuf,
        receiving_directory: PathBuf,
    }

    fn validators() -> ValidatorSet {
        ValidatorSet {
            epoch: Epoch(3),
            validators: (0..5)
                .map(|index| {
                    let key = AegisPqPublicKey {
                        key_id: AegisPqKeyId(format!("driver-key-{index}")),
                        algorithm: TESTNET_V3_CONSENSUS_SIGNATURE_ALGORITHM.to_string(),
                        key_bytes: vec![index as u8 + 1; TESTNET_V3_MLDSA65_PUBLIC_KEY_BYTES],
                    };
                    ValidatorRecord {
                        validator_id: ValidatorId(format!("driver-validator-{index}")),
                        validator_uma_id: UmaId(format!("uma:driver-validator-{index}")),
                        consensus_public_key: key.clone(),
                        peer_public_key: key.clone(),
                        operator_public_key: key,
                        voting_weight: 1,
                        status: ValidatorStatus::Active,
                        cluster_id: ClusterId(0),
                        activation_epoch: Epoch(3),
                    }
                })
                .collect(),
        }
    }

    fn context(validators: &ValidatorSet) -> SimplifiedEpochContext {
        SimplifiedEpochContext::derive(
            Epoch(3),
            Height(3_001),
            Height(4_000),
            Hash::from_domain_bytes("driver-test-seed", b"epoch-3"),
            ConsensusParameterRoot::from_canonical_manifest_bytes(b"driver-test-parameters"),
            validators,
        )
        .unwrap()
    }

    fn anchor() -> QuorumCertificateReference {
        QuorumCertificateReference {
            height: Height(3_000),
            block_id: BlockId("driver-block-3000".to_string()),
            qc_id: Hash::from_domain_bytes("driver-anchor", b"block-3000"),
        }
    }

    fn unique_driver_paths(label: &str) -> (PathBuf, PathBuf) {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let state_path = crate::utils::test_temp_root(format!(
            "posy-simplified-driver-{label}-{}-{stamp}/state.json",
            std::process::id()
        ));
        let signer_journal_path = state_path.with_file_name("signer-journal.json");
        (state_path, signer_journal_path)
    }

    fn durable_material_configuration(
        validator_set: &ValidatorSet,
    ) -> SimplifiedCoreMaterialConfiguration {
        SimplifiedCoreMaterialConfiguration {
            validator_set: validator_set.clone(),
            cluster_map: ClusterMap {
                epoch: validator_set.epoch,
                assignments: validator_set
                    .validators
                    .iter()
                    .map(|validator| ClusterAssignment {
                        cluster_id: validator.cluster_id,
                        validator_id: validator.validator_id.clone(),
                    })
                    .collect(),
            }
            .canonicalized(),
            execution_state: ExecutionState::new(),
            cryptographic_profile_root: Hash::from_domain_bytes(
                "driver-material-test",
                b"cryptographic-profile",
            ),
            epoch_start_timestamp_ms: 1_900_000_000_000,
            target_block_time_ms: 1_000,
            app_version: 1,
            execution_version: 1,
            dag_version: 2,
            aegis_pqvm_version: "aegis-pqvm-material-test".to_string(),
        }
    }

    fn provision_durable_material_driver(label: &str) -> DurableMaterialDriverFixture {
        let mut signer =
            AegisPqvmSigner::initialize_required().expect("initialize material signer");
        let mut records = Vec::with_capacity(5);
        for index in 0..5 {
            let uma_id = UmaId(format!("uma:durable-material-validator-{index}"));
            let key_id = signer
                .generate_and_register_key(
                    &uma_id.0,
                    vec![
                        AegisPqKeyRole::ConsensusProposer,
                        AegisPqKeyRole::ConsensusVote,
                    ],
                    Epoch(3),
                )
                .expect("generate durable material test key");
            let public_key = signer
                .public_key_record(&key_id)
                .expect("read durable material public key");
            records.push(ValidatorRecord {
                validator_id: ValidatorId(format!("durable-material-validator-{index}")),
                validator_uma_id: uma_id,
                consensus_public_key: public_key.clone(),
                peer_public_key: public_key.clone(),
                operator_public_key: public_key,
                voting_weight: 1,
                status: ValidatorStatus::Active,
                cluster_id: ClusterId(0),
                activation_epoch: Epoch(3),
            });
        }
        let validator_set = ValidatorSet {
            epoch: Epoch(3),
            validators: records,
        };
        let epoch_context = context(&validator_set);
        let anchor_hash = Hash::from_domain_bytes("driver-material-test", b"anchor-block");
        let finalized = FinalizedBlockRecord {
            height: Height(3_000),
            block_id: BlockId::from_hash(anchor_hash),
            qc_id: Hash::from_domain_bytes("driver-material-test", b"anchor-qc"),
        };
        let anchor_qc = QuorumCertificateReference {
            height: finalized.height,
            block_id: finalized.block_id.clone(),
            qc_id: finalized.qc_id,
        };
        let proposer_id = epoch_context
            .authorized_proposer(Height(3_001), 0)
            .expect("scheduled durable material proposer")
            .clone();
        let proposer_index = validator_set
            .validators
            .iter()
            .position(|validator| validator.validator_id == proposer_id)
            .expect("material proposer index");
        let proposer_key_id = validator_set.validators[proposer_index]
            .consensus_public_key
            .key_id
            .clone();
        let directive = SimplifiedProposalDirective {
            context: ConsensusObjectContext::for_height(&epoch_context, Height(3_001), Round(0))
                .expect("durable material proposal context"),
            highest_qc: anchor_qc.clone(),
            finalized: finalized.clone(),
            proposer_id,
            proposer_key_id,
            takeover_tc_id: None,
            mandatory_carry_candidate: None,
        };
        let material_configuration = durable_material_configuration(&validator_set);
        let serving_directory = unique_driver_paths(&format!("{label}-serving-material"))
            .0
            .with_extension("material");
        let serving_store = DurableSimplifiedProposalMaterialStore::at_directory(
            &serving_directory,
            epoch_context.root().expect("durable material epoch root"),
        )
        .expect("serving material store");
        let mut serving_source = DurableVerifiedSimplifiedProposalSource::new(
            epoch_context.clone(),
            serving_store,
            SimplifiedCoreMaterialAdapter::new(
                epoch_context.clone(),
                material_configuration.clone(),
            )
            .expect("serving core material adapter"),
        )
        .expect("serving durable material source");
        let mut proposal = serving_source
            .proposal_for(&epoch_context, &directive)
            .expect("build serving proposal")
            .expect("core adapter supplies proposal");
        proposal.proposer_signature = signer
            .sign_domain(
                POSY_SIMPLIFIED_PROPOSAL_DOMAIN,
                &proposal
                    .signing_bytes()
                    .expect("material proposal signing bytes"),
                &proposal.proposer_key_id,
            )
            .expect("sign material proposal");

        let receiving_directory = unique_driver_paths(&format!("{label}-receiving-material"))
            .0
            .with_extension("material");
        let receiving_store = DurableSimplifiedProposalMaterialStore::at_directory(
            &receiving_directory,
            epoch_context.root().expect("receiving material epoch root"),
        )
        .expect("receiving material store");
        let receiving_source = DurableVerifiedSimplifiedProposalSource::new(
            epoch_context.clone(),
            receiving_store,
            SimplifiedCoreMaterialAdapter::new(
                epoch_context.clone(),
                material_configuration.clone(),
            )
            .expect("receiving core material adapter"),
        )
        .expect("receiving durable material source");
        let local = validator_set
            .validators
            .iter()
            .find(|validator| validator.validator_id != proposal.proposer_id)
            .expect("non-proposer material receiver");
        let (state_path, signer_journal_path) = unique_driver_paths(label);
        let verifier = signer.verifier();
        let driver = SimplifiedPosyDriver::new(
            epoch_context.clone(),
            validator_set.clone(),
            local.validator_id.clone(),
            local.consensus_public_key.key_id.clone(),
            DurableSimplifiedPosyStore::at_path(state_path),
            anchor_qc,
            DurableConsensusSigningAuthority::at_path(signer_journal_path),
            signer,
            verifier,
            receiving_source,
            RecordingEgress::default(),
            RecordingFinalizationSink::default(),
            SimplifiedDriverTiming {
                proposal_timeout: Duration::from_millis(100),
                vote_timeout: Duration::from_millis(100),
                max_round_timeout: Duration::from_millis(500),
            },
        )
        .expect("construct durable material receiver driver");
        DurableMaterialDriverFixture {
            driver,
            serving_source,
            proposal,
            proposer_index,
            epoch_context,
            validator_set,
            material_configuration,
            finalized,
            serving_directory,
            receiving_directory,
        }
    }

    fn provision_driver(label: &str) -> DriverFixture {
        provision_driver_for_round(label, 0)
    }

    fn provision_driver_for_round(label: &str, local_round: u64) -> DriverFixture {
        let mut signer = AegisPqvmSigner::initialize_required().expect("initialize test signer");
        let mut records = Vec::with_capacity(5);
        for index in 0..5 {
            let uma_id = UmaId(format!("uma:real-driver-validator-{index}"));
            let key_id = signer
                .generate_and_register_key(
                    &uma_id.0,
                    vec![
                        AegisPqKeyRole::ConsensusProposer,
                        AegisPqKeyRole::ConsensusVote,
                    ],
                    Epoch(3),
                )
                .expect("generate driver test key");
            let public_key = signer
                .public_key_record(&key_id)
                .expect("read generated driver test public key");
            records.push(ValidatorRecord {
                validator_id: ValidatorId(format!("real-driver-validator-{index}")),
                validator_uma_id: uma_id,
                consensus_public_key: public_key.clone(),
                peer_public_key: public_key.clone(),
                operator_public_key: public_key,
                voting_weight: 1,
                status: ValidatorStatus::Active,
                cluster_id: ClusterId(0),
                activation_epoch: Epoch(3),
            });
        }
        let validators = ValidatorSet {
            epoch: Epoch(3),
            validators: records,
        };
        let context = context(&validators);
        let local_validator_id = context
            .authorized_proposer(Height(3_001), local_round)
            .expect("scheduled driver test proposer")
            .clone();
        let local = validators
            .validators
            .iter()
            .find(|validator| validator.validator_id == local_validator_id)
            .expect("scheduled proposer is in driver test set");
        let local_key_id = local.consensus_public_key.key_id.clone();
        let verifier = signer.verifier();
        let (state_path, signer_journal_path) = unique_driver_paths(label);
        let driver = SimplifiedPosyDriver::new(
            context,
            validators,
            local_validator_id,
            local_key_id,
            DurableSimplifiedPosyStore::at_path(state_path.clone()),
            anchor(),
            DurableConsensusSigningAuthority::at_path(signer_journal_path.clone()),
            signer,
            verifier,
            TestProposalSource::new(label),
            RecordingEgress::default(),
            RecordingFinalizationSink::default(),
            SimplifiedDriverTiming {
                proposal_timeout: Duration::from_millis(100),
                vote_timeout: Duration::from_millis(100),
                max_round_timeout: Duration::from_millis(500),
            },
        )
        .expect("construct real five-validator driver fixture");
        DriverFixture {
            driver,
            state_path,
            signer_journal_path,
        }
    }

    fn signed_transition_certificate(
        signer: &mut AegisPqvmSigner,
        epoch_context: &SimplifiedEpochContext,
        validator_set: &ValidatorSet,
        height: Height,
        parent_qc: QuorumCertificateReference,
        label: &str,
    ) -> SimplifiedQuorumCertificate {
        let context = ConsensusObjectContext::for_height(epoch_context, height, Round(0))
            .expect("transition certificate context");
        let block_id = BlockId::from_hash(Hash::from_domain_bytes(
            "driver-transition-block",
            format!("{label}-{}", height.0).as_bytes(),
        ));
        let protected_execution_root = Hash::from_domain_bytes(
            "driver-transition-execution",
            format!("{label}-{}", height.0).as_bytes(),
        );
        let votes = validator_set
            .active_for_epoch(epoch_context.epoch)
            .validators
            .into_iter()
            .map(|validator| {
                let mut vote = BlockVote {
                    context: context.clone(),
                    block_id: block_id.clone(),
                    parent_block_id: parent_qc.block_id.clone(),
                    parent_qc: parent_qc.clone(),
                    takeover_tc_id: None,
                    protected_execution_root,
                    validator_id: validator.validator_id,
                    key_id: validator.consensus_public_key.key_id,
                    signature: AegisPqSignature {
                        algorithm: String::new(),
                        signature_bytes: Vec::new(),
                    },
                };
                vote.signature = signer
                    .sign_domain(
                        POSY_SIMPLIFIED_BLOCK_VOTE_DOMAIN,
                        &vote.signing_bytes().expect("transition vote signing bytes"),
                        &vote.key_id,
                    )
                    .expect("sign transition vote");
                vote
            })
            .collect();
        SimplifiedQuorumCertificate::from_votes(votes)
            .expect("assemble transition quorum certificate")
    }

    fn provision_transition_driver(label: &str) -> TransitionDriverFixture {
        let mut signer =
            AegisPqvmSigner::initialize_required().expect("initialize transition driver signer");
        let mut records = Vec::with_capacity(5);
        for index in 0..5 {
            let uma_id = UmaId(format!("uma:transition-driver-validator-{index}"));
            let key_id = signer
                .generate_and_register_key(
                    &uma_id.0,
                    vec![
                        AegisPqKeyRole::ConsensusProposer,
                        AegisPqKeyRole::ConsensusVote,
                    ],
                    Epoch(3),
                )
                .expect("generate transition driver key");
            let public_key = signer
                .public_key_record(&key_id)
                .expect("read transition driver public key");
            records.push(ValidatorRecord {
                validator_id: ValidatorId(format!("transition-driver-validator-{index}")),
                validator_uma_id: uma_id,
                consensus_public_key: public_key.clone(),
                peer_public_key: public_key.clone(),
                operator_public_key: public_key,
                voting_weight: 1,
                status: ValidatorStatus::Active,
                cluster_id: ClusterId(0),
                activation_epoch: Epoch(3),
            });
        }
        let previous_validator_set = ValidatorSet {
            epoch: Epoch(3),
            validators: records,
        }
        .canonicalized();
        let previous_seed = Hash::from_domain_bytes("driver-transition-seed", label.as_bytes());
        let previous_context = SimplifiedEpochContext::derive(
            Epoch(3),
            Height(3_001),
            Height(4_000),
            previous_seed,
            ConsensusParameterRoot::from_canonical_manifest_bytes(
                b"driver-transition-previous-parameters",
            ),
            &previous_validator_set,
        )
        .expect("derive previous transition epoch");
        let preceding_anchor = QuorumCertificateReference {
            height: Height(3_997),
            block_id: BlockId::from_hash(Hash::from_domain_bytes(
                "driver-transition-anchor",
                label.as_bytes(),
            )),
            qc_id: Hash::from_domain_bytes("driver-transition-anchor-qc", label.as_bytes()),
        };
        let qc_3998 = signed_transition_certificate(
            &mut signer,
            &previous_context,
            &previous_validator_set,
            Height(3_998),
            preceding_anchor,
            label,
        );
        let qc_3999 = signed_transition_certificate(
            &mut signer,
            &previous_context,
            &previous_validator_set,
            Height(3_999),
            qc_3998.reference().expect("transition finalized reference"),
            label,
        );
        let qc_4000 = signed_transition_certificate(
            &mut signer,
            &previous_context,
            &previous_validator_set,
            Height(4_000),
            qc_3999.reference().expect("transition parent reference"),
            label,
        );

        let next_validator_set = ValidatorSet {
            epoch: Epoch(4),
            validators: previous_validator_set.validators.clone(),
        }
        .canonicalized();
        let next_active = next_validator_set.active_for_epoch(Epoch(4));
        let next_parameter_root = ConsensusParameterRoot::from_canonical_manifest_bytes(
            b"driver-transition-next-parameters",
        );
        let authorization = SimplifiedEpochTransitionAuthorization {
            schema_version: POSY_SIMPLIFIED_EPOCH_TRANSITION_SCHEMA_VERSION,
            previous_epoch: Epoch(3),
            previous_epoch_context_root: previous_context
                .root()
                .expect("previous transition context root"),
            finalized_height: Height(3_998),
            next_epoch: Epoch(4),
            next_epoch_start_height: Height(4_001),
            next_epoch_end_height: Height(5_000),
            next_consensus_parameter_root: next_parameter_root.to_hex(),
            next_active_validator_set_root: next_active
                .hash()
                .expect("next transition validator root"),
            next_validator_consensus_key_root: next_active
                .consensus_key_root()
                .expect("next transition key root"),
            next_frozen_voting_weight_root: next_active
                .frozen_bonded_weight_root()
                .expect("next transition weight root"),
        };
        let authority_evidence = (
            authorization.root().expect("transition authorization root"),
            qc_3998.protected_execution_root,
        )
            .canonical_bytes()
            .expect("transition authority evidence");
        let transition = SimplifiedEpochTransitionProof {
            format: POSY_SIMPLIFIED_EPOCH_TRANSITION_FORMAT.to_string(),
            previous_epoch_context: previous_context,
            previous_validator_set,
            next_validator_set,
            authorization,
            finality_witness: vec![qc_3998, qc_3999, qc_4000.clone()],
            authority_evidence,
        }
        .verify(&signer.verifier(), &TestTransitionAuthorityVerifier)
        .expect("verify transition driver capability");
        let first_current_qc = signed_transition_certificate(
            &mut signer,
            transition.next_epoch_context(),
            transition.next_validator_set(),
            Height(4_001),
            qc_4000.reference().expect("transition certified parent"),
            label,
        );
        let local_validator_id = transition
            .next_epoch_context()
            .authorized_proposer(Height(4_001), 0)
            .expect("transition driver scheduled proposer")
            .clone();
        let local_key_id = transition
            .next_validator_set()
            .validators
            .iter()
            .find(|validator| validator.validator_id == local_validator_id)
            .expect("transition driver local validator")
            .consensus_public_key
            .key_id
            .clone();
        let verifier = signer.verifier();
        let (state_path, signer_journal_path) = unique_driver_paths(label);
        let driver = SimplifiedPosyDriver::new_from_verified_v3_transition(
            transition.clone(),
            local_validator_id,
            local_key_id,
            DurableSimplifiedPosyStore::at_path(state_path.clone()),
            DurableConsensusSigningAuthority::at_path(signer_journal_path.clone()),
            signer,
            verifier,
            TestProposalSource::new(label),
            RecordingEgress::default(),
            RecordingFinalizationSink::default(),
            SimplifiedDriverTiming {
                proposal_timeout: Duration::from_millis(100),
                vote_timeout: Duration::from_millis(100),
                max_round_timeout: Duration::from_millis(500),
            },
        )
        .expect("construct transition-aware driver");
        TransitionDriverFixture {
            driver,
            transition,
            first_current_qc,
            state_path,
            signer_journal_path,
        }
    }

    fn recorded_messages(driver: &TestDriver) -> Vec<SimplifiedConsensusMessage> {
        driver
            .egress
            .messages
            .lock()
            .expect("recording egress lock")
            .clone()
    }

    fn durable_material_messages(
        driver: &DurableMaterialDriver,
    ) -> Vec<SimplifiedConsensusMessage> {
        driver
            .egress
            .messages
            .lock()
            .expect("durable material egress lock")
            .clone()
    }

    fn material_proposal_envelope(
        fixture: &DurableMaterialDriverFixture,
    ) -> SimplifiedConsensusEnvelope {
        SimplifiedConsensusEnvelope {
            peer_address: "durable-material-proposer-peer".to_string(),
            authenticated_peer: peer(&fixture.validator_set.validators[fixture.proposer_index]),
            message: SimplifiedConsensusMessage::Proposal {
                proposal: fixture.proposal.clone(),
            },
        }
    }

    fn requested_material_identity(driver: &DurableMaterialDriver) -> (Hash, Hash) {
        durable_material_messages(driver)
            .into_iter()
            .rev()
            .find_map(|message| match message {
                SimplifiedConsensusMessage::MaterialRequest {
                    stable_candidate_id,
                    request_id,
                    ..
                } => Some((stable_candidate_id, request_id)),
                _ => None,
            })
            .expect("durable material request")
    }

    fn drive_proposal(driver: &mut TestDriver) -> SimplifiedProposal {
        assert!(driver
            .drive_scheduled_proposal()
            .expect("drive scheduled proposal"));
        recorded_messages(driver)
            .into_iter()
            .rev()
            .find_map(|message| match message {
                SimplifiedConsensusMessage::Proposal { proposal } => Some(proposal),
                _ => None,
            })
            .expect("scheduled proposal was broadcast")
    }

    fn other_validator_indexes(driver: &TestDriver) -> Vec<usize> {
        driver
            .validator_set
            .validators
            .iter()
            .enumerate()
            .filter_map(|(index, validator)| {
                (validator.validator_id != driver.local_validator_id).then_some(index)
            })
            .collect()
    }

    fn signed_delivery_statement(
        driver: &mut TestDriver,
        validator_index: usize,
        phase: ReliableDeliveryPhase,
        candidate: &CertifiedCandidateSubject,
    ) -> ReliableDeliveryStatement {
        let validator = driver.validator_set.validators[validator_index].clone();
        let context = driver
            .reliable_delivery
            .as_ref()
            .expect("proposal initialized reliable delivery")
            .context
            .clone();
        let mut statement = ReliableDeliveryStatement {
            context,
            phase,
            candidate: candidate.clone(),
            validator_id: validator.validator_id,
            key_id: validator.consensus_public_key.key_id,
            signature: AegisPqSignature {
                algorithm: String::new(),
                signature_bytes: Vec::new(),
            },
        };
        let domain = match phase {
            ReliableDeliveryPhase::Echo => POSY_SIMPLIFIED_PROPOSAL_ECHO_DOMAIN,
            ReliableDeliveryPhase::Ready => POSY_SIMPLIFIED_PROPOSAL_READY_DOMAIN,
        };
        statement.signature = driver
            .signer
            .sign_domain(
                domain,
                &statement.signing_bytes().expect("delivery signing bytes"),
                &statement.key_id,
            )
            .expect("sign peer delivery statement");
        statement
    }

    fn deliver_statement(
        driver: &mut TestDriver,
        validator_index: usize,
        statement: ReliableDeliveryStatement,
    ) -> Result<(), String> {
        let authenticated_peer = peer(&driver.validator_set.validators[validator_index]);
        driver.handle_envelope(SimplifiedConsensusEnvelope {
            peer_address: format!("driver-peer-{validator_index}"),
            authenticated_peer,
            message: SimplifiedConsensusMessage::ReliableDelivery { statement },
        })
    }

    fn complete_reliable_delivery(driver: &mut TestDriver, proposal: &SimplifiedProposal) {
        let candidate = candidate_for_proposal(proposal).expect("proposal candidate");
        let other_indexes = other_validator_indexes(driver);
        for validator_index in other_indexes.iter().take(3).copied() {
            let statement = signed_delivery_statement(
                driver,
                validator_index,
                ReliableDeliveryPhase::Echo,
                &candidate,
            );
            deliver_statement(driver, validator_index, statement).expect("deliver peer ECHO");
        }
        for validator_index in other_indexes.iter().take(2).copied() {
            let statement = signed_delivery_statement(
                driver,
                validator_index,
                ReliableDeliveryPhase::Ready,
                &candidate,
            );
            deliver_statement(driver, validator_index, statement).expect("deliver peer READY");
        }
    }

    fn signed_block_vote(
        driver: &mut TestDriver,
        validator_index: usize,
        proposal: &SimplifiedProposal,
    ) -> BlockVote {
        let validator = driver.validator_set.validators[validator_index].clone();
        let mut vote = BlockVote {
            context: proposal.context.clone(),
            block_id: proposal.block_id.clone(),
            parent_block_id: proposal.parent_block_id.clone(),
            parent_qc: proposal.parent_qc.clone(),
            takeover_tc_id: proposal.takeover_tc_id,
            protected_execution_root: proposal.protected_execution_root,
            validator_id: validator.validator_id,
            key_id: validator.consensus_public_key.key_id,
            signature: AegisPqSignature {
                algorithm: String::new(),
                signature_bytes: Vec::new(),
            },
        };
        vote.signature = driver
            .signer
            .sign_domain(
                POSY_SIMPLIFIED_BLOCK_VOTE_DOMAIN,
                &vote.signing_bytes().expect("block-vote signing bytes"),
                &vote.key_id,
            )
            .expect("sign peer block vote");
        vote
    }

    fn certify_proposal(driver: &mut TestDriver, proposal: &SimplifiedProposal) {
        let votes_before = driver.metrics().votes_broadcast;
        complete_reliable_delivery(driver, proposal);
        assert_eq!(driver.metrics().votes_broadcast, votes_before + 1);
        for validator_index in other_validator_indexes(driver).into_iter().take(3) {
            let vote = signed_block_vote(driver, validator_index, proposal);
            let authenticated_peer = peer(&driver.validator_set.validators[validator_index]);
            driver
                .handle_envelope(SimplifiedConsensusEnvelope {
                    peer_address: format!("block-vote-peer-{validator_index}"),
                    authenticated_peer,
                    message: SimplifiedConsensusMessage::Vote { vote },
                })
                .expect("collect peer block vote");
        }
    }

    fn certificate_for_delivered_proposal(
        driver: &mut TestDriver,
        proposal: &SimplifiedProposal,
    ) -> SimplifiedQuorumCertificate {
        complete_reliable_delivery(driver, proposal);
        let local_vote = recorded_messages(driver)
            .into_iter()
            .rev()
            .find_map(|message| match message {
                SimplifiedConsensusMessage::Vote { vote } if vote.block_id == proposal.block_id => {
                    Some(vote)
                }
                _ => None,
            })
            .expect("local delivered-candidate vote");
        let mut votes = vec![local_vote];
        for validator_index in other_validator_indexes(driver).into_iter().take(3) {
            votes.push(signed_block_vote(driver, validator_index, proposal));
        }
        SimplifiedQuorumCertificate::from_votes(votes).expect("four-vote certificate")
    }

    fn signed_timeout_vote(
        driver: &mut TestDriver,
        validator_index: usize,
        last_voted_candidate: Option<CertifiedCandidateSubject>,
    ) -> TimeoutVote {
        let validator = driver.validator_set.validators[validator_index].clone();
        let height = driver
            .state_machine
            .state()
            .next_height()
            .expect("timeout height");
        let (round, previous_tc_id) = driver
            .state_machine
            .state()
            .takeover_for_height(&driver.epoch_context, height)
            .expect("timeout round");
        let mut vote = TimeoutVote {
            context: ConsensusObjectContext::for_height(
                &driver.epoch_context,
                height,
                Round(round),
            )
            .expect("timeout context"),
            lease_index: driver
                .epoch_context
                .lease_index(height)
                .expect("timeout lease"),
            timed_out_proposer: driver
                .epoch_context
                .authorized_proposer(height, round)
                .expect("timed-out proposer")
                .clone(),
            previous_tc_id,
            highest_qc: driver.state_machine.state().highest_qc.clone(),
            last_voted_candidate,
            validator_id: validator.validator_id,
            key_id: validator.consensus_public_key.key_id,
            signature: AegisPqSignature {
                algorithm: String::new(),
                signature_bytes: Vec::new(),
            },
        };
        vote.signature = driver
            .signer
            .sign_domain(
                POSY_SIMPLIFIED_TIMEOUT_VOTE_DOMAIN,
                &vote.signing_bytes().expect("timeout signing bytes"),
                &vote.key_id,
            )
            .expect("sign timeout vote");
        vote
    }

    fn prepare_finalizing_certificate(driver: &mut TestDriver) -> SimplifiedQuorumCertificate {
        for _ in 0..2 {
            let proposal = drive_proposal(driver);
            let certificate = certificate_for_delivered_proposal(driver, &proposal);
            driver
                .accept_quorum_certificate(certificate)
                .expect("accept non-finalizing QC");
        }
        let proposal = drive_proposal(driver);
        certificate_for_delivered_proposal(driver, &proposal)
    }

    fn clone_registered_signer(driver: &TestDriver) -> AegisPqvmSigner {
        let mut cloned = AegisPqvmSigner::initialize_required().expect("initialize restart signer");
        for validator in &driver.validator_set.validators {
            let key_id = &validator.consensus_public_key.key_id;
            let public_key = driver
                .signer
                .registry
                .public_key(key_id)
                .cloned()
                .expect("driver fixture public key");
            let private_key = driver
                .signer
                .registry
                .private_key(key_id)
                .cloned()
                .expect("driver fixture private key");
            let registered = cloned
                .register_existing_keypair(
                    &validator.validator_uma_id.0,
                    public_key,
                    private_key,
                    vec![
                        AegisPqKeyRole::ConsensusProposer,
                        AegisPqKeyRole::ConsensusVote,
                    ],
                    Epoch(3),
                )
                .expect("register restart key");
            assert_eq!(&registered, key_id);
        }
        cloned
    }

    fn vote(context: &SimplifiedEpochContext, validator: &ValidatorRecord) -> BlockVote {
        BlockVote {
            context: ConsensusObjectContext::for_height(context, Height(3_001), Round(0)).unwrap(),
            block_id: BlockId("driver-block-3001".to_string()),
            parent_block_id: BlockId("driver-block-3000".to_string()),
            parent_qc: anchor(),
            takeover_tc_id: None,
            protected_execution_root: Hash::from_domain_bytes(
                "driver-protected-execution",
                b"block-3001",
            ),
            validator_id: validator.validator_id.clone(),
            key_id: validator.consensus_public_key.key_id.clone(),
            signature: AegisPqSignature {
                algorithm: TESTNET_V3_CONSENSUS_SIGNATURE_ALGORITHM.to_string(),
                signature_bytes: vec![1],
            },
        }
    }

    fn peer(validator: &ValidatorRecord) -> AuthenticatedSimplifiedConsensusPeer {
        AuthenticatedSimplifiedConsensusPeer {
            validator_id: validator.validator_id.clone(),
            validator_uma_id: validator.validator_uma_id.clone(),
            consensus_key_id: validator.consensus_public_key.key_id.clone(),
        }
    }

    #[test]
    fn ingress_and_peer_authority_are_separate_bounded_and_fail_closed() {
        let validators = validators();
        let context = context(&validators);
        assert_eq!(context.protocol_version, POSY_SIMPLIFIED_PROTOCOL_VERSION);
        let authorizer = FrozenSimplifiedPeerAuthorizer::new(&context, &validators).unwrap();
        let first = &validators.validators[0];
        let second = &validators.validators[1];
        let vote_message = SimplifiedConsensusMessage::Vote {
            vote: vote(&context, first),
        };
        let mut oversized_vote = vote(&context, first);
        oversized_vote.signature.signature_bytes = vec![7; 128 * 1024];
        assert!(
            validate_simplified_consensus_message_size(&SimplifiedConsensusMessage::Vote {
                vote: oversized_vote
            })
            .is_err()
        );
        authorizer.authorize(&peer(first), &vote_message).unwrap();
        assert!(authorizer.authorize(&peer(second), &vote_message).is_err());

        let relay = SimplifiedConsensusMessage::QuorumCertificate {
            certificate: SimplifiedQuorumCertificate {
                context: ConsensusObjectContext::for_height(&context, Height(3_001), Round(0))
                    .unwrap(),
                block_id: BlockId("driver-block-3001".to_string()),
                parent_block_id: BlockId("driver-block-3000".to_string()),
                parent_qc: vote(&context, first).parent_qc,
                takeover_tc_id: None,
                protected_execution_root: Hash::from_domain_bytes(
                    "driver-protected-execution",
                    b"block-3001",
                ),
                participants: vec![ParticipantSignature {
                    validator_id: first.validator_id.clone(),
                    key_id: first.consensus_public_key.key_id.clone(),
                    signature: AegisPqSignature {
                        algorithm: TESTNET_V3_CONSENSUS_SIGNATURE_ALGORITHM.to_string(),
                        signature_bytes: vec![1],
                    },
                }],
            },
        };
        authorizer
            .authorize(&peer(second), &relay)
            .expect("an active authenticated peer may relay independently verified evidence");

        let _ = remove_simplified_consensus_ingress();
        assert!(dispatch_simplified_consensus_message(
            "peer-a",
            Some(peer(first)),
            vote_message.clone()
        )
        .is_err());
        let receiver = install_simplified_consensus_ingress(1).unwrap();
        assert!(
            dispatch_simplified_consensus_message("peer-a", None, vote_message.clone()).is_err()
        );
        dispatch_simplified_consensus_message("peer-a", Some(peer(first)), vote_message).unwrap();
        assert!(matches!(
            receiver.try_recv().unwrap().message,
            SimplifiedConsensusMessage::Vote { .. }
        ));
        remove_simplified_consensus_ingress().unwrap();
    }

    #[test]
    fn proposal_alone_broadcasts_echo_but_no_block_vote() {
        let mut fixture = provision_driver("proposal-without-delivery");

        let _proposal = drive_proposal(&mut fixture.driver);
        let messages = recorded_messages(&fixture.driver);

        assert!(messages.iter().any(|message| matches!(
            message,
            SimplifiedConsensusMessage::ReliableDelivery { statement }
                if statement.phase == ReliableDeliveryPhase::Echo
        )));
        assert!(!messages
            .iter()
            .any(|message| matches!(message, SimplifiedConsensusMessage::Vote { .. })));
        assert_eq!(fixture.driver.metrics().votes_broadcast, 0);
    }

    #[test]
    fn proposal_without_material_requests_it_once_before_reliable_delivery() {
        let mut fixture = provision_driver("proposal-material-request");
        fixture.driver.proposal_source.remote_material_available = false;
        let height = fixture.driver.state_machine.state().next_height().unwrap();
        let (round, takeover_tc_id) = fixture
            .driver
            .state_machine
            .state()
            .takeover_for_height(&fixture.driver.epoch_context, height)
            .unwrap();
        let directive = SimplifiedProposalDirective {
            context: ConsensusObjectContext::for_height(
                &fixture.driver.epoch_context,
                height,
                Round(round),
            )
            .unwrap(),
            highest_qc: fixture.driver.state_machine.state().highest_qc.clone(),
            finalized: fixture.driver.state_machine.state().finalized.clone(),
            proposer_id: fixture.driver.local_validator_id.clone(),
            proposer_key_id: fixture.driver.local_key_id.clone(),
            takeover_tc_id,
            mandatory_carry_candidate: None,
        };
        let mut remote_source = TestProposalSource::new("remote-material-request");
        let unsigned = remote_source
            .proposal_for(&fixture.driver.epoch_context, &directive)
            .unwrap()
            .unwrap();
        let proposal = fixture
            .driver
            .state_machine
            .sign_proposal(
                unsigned,
                &fixture.driver.signing_authority,
                &mut fixture.driver.signer,
            )
            .unwrap();
        let proposer = fixture
            .driver
            .validator_set
            .validators
            .iter()
            .find(|validator| validator.validator_id == proposal.proposer_id)
            .unwrap()
            .clone();
        let envelope = SimplifiedConsensusEnvelope {
            peer_address: "material-proposer-peer".to_string(),
            authenticated_peer: peer(&proposer),
            message: SimplifiedConsensusMessage::Proposal {
                proposal: proposal.clone(),
            },
        };
        fixture.driver.handle_envelope(envelope.clone()).unwrap();
        fixture.driver.handle_envelope(envelope).unwrap();

        let messages = recorded_messages(&fixture.driver);
        assert_eq!(fixture.driver.metrics().material_requests_sent, 1);
        assert!(messages
            .iter()
            .any(|message| matches!(message, SimplifiedConsensusMessage::MaterialRequest { .. })));
        assert!(!messages.iter().any(|message| matches!(
            message,
            SimplifiedConsensusMessage::ReliableDelivery { .. }
                | SimplifiedConsensusMessage::Vote { .. }
        )));
    }

    #[test]
    fn durable_material_exchange_verifies_persists_and_recovers_before_echo() {
        let mut fixture = provision_durable_material_driver("durable-material-exchange");
        let proposal_envelope = material_proposal_envelope(&fixture);
        fixture
            .driver
            .handle_envelope(proposal_envelope.clone())
            .expect("request missing proposal material");
        fixture
            .driver
            .handle_envelope(proposal_envelope)
            .expect("duplicate proposal is request-idempotent");
        assert_eq!(fixture.driver.metrics().material_requests_sent, 1);
        assert!(!durable_material_messages(&fixture.driver)
            .iter()
            .any(|message| matches!(
                message,
                SimplifiedConsensusMessage::ReliableDelivery { .. }
                    | SimplifiedConsensusMessage::Vote { .. }
            )));

        let (candidate_id, request_id) = requested_material_identity(&fixture.driver);
        let material = fixture
            .serving_source
            .material_for_serving(candidate_id)
            .expect("read source material")
            .expect("source persisted material before proposal");
        let chunks = build_material_chunks(&material, request_id).expect("build material response");
        for chunk in chunks {
            fixture
                .driver
                .handle_envelope(SimplifiedConsensusEnvelope {
                    peer_address: "durable-material-proposer-peer".to_string(),
                    authenticated_peer: peer(
                        &fixture.validator_set.validators[fixture.proposer_index],
                    ),
                    message: SimplifiedConsensusMessage::MaterialChunk { chunk },
                })
                .expect("independently verify and persist material chunk stream");
        }
        assert!(durable_material_messages(&fixture.driver)
            .iter()
            .any(|message| matches!(
                message,
                SimplifiedConsensusMessage::ReliableDelivery { statement }
                    if statement.phase == ReliableDeliveryPhase::Echo
            )));
        assert!(!durable_material_messages(&fixture.driver)
            .iter()
            .any(|message| matches!(message, SimplifiedConsensusMessage::Vote { .. })));

        drop(fixture.driver);
        let receiving_store = DurableSimplifiedProposalMaterialStore::at_directory(
            &fixture.receiving_directory,
            fixture
                .epoch_context
                .root()
                .expect("restart receiving epoch root"),
        )
        .expect("reopen receiving material store");
        let mut restarted_receiver = DurableVerifiedSimplifiedProposalSource::new(
            fixture.epoch_context.clone(),
            receiving_store,
            SimplifiedCoreMaterialAdapter::new(
                fixture.epoch_context.clone(),
                fixture.material_configuration.clone(),
            )
            .expect("restart receiving adapter"),
        )
        .expect("restart receiving source");
        assert_eq!(
            restarted_receiver
                .recompute_received_protected_execution_root(&fixture.proposal, &fixture.finalized,)
                .expect("consume restarted durable material"),
            Some(fixture.proposal.protected_execution_root)
        );
        assert_eq!(
            restarted_receiver
                .material_for_serving(candidate_id)
                .expect("serve restarted durable material"),
            Some(material.clone())
        );

        drop(fixture.serving_source);
        let serving_store = DurableSimplifiedProposalMaterialStore::at_directory(
            &fixture.serving_directory,
            fixture
                .epoch_context
                .root()
                .expect("restart serving epoch root"),
        )
        .expect("reopen serving material store");
        let mut restarted_server = DurableVerifiedSimplifiedProposalSource::new(
            fixture.epoch_context.clone(),
            serving_store,
            SimplifiedCoreMaterialAdapter::new(
                fixture.epoch_context,
                fixture.material_configuration,
            )
            .expect("restart serving adapter"),
        )
        .expect("restart serving source");
        assert_eq!(
            restarted_server
                .material_for_serving(candidate_id)
                .expect("serve source material after restart"),
            Some(material)
        );
        let _ = std::fs::remove_dir_all(fixture.receiving_directory);
        let _ = std::fs::remove_dir_all(fixture.serving_directory);
    }

    #[test]
    fn malformed_material_chunks_are_peer_local_and_do_not_block_valid_retry() {
        let mut fixture = provision_durable_material_driver("durable-material-adversarial");
        let proposal_envelope = material_proposal_envelope(&fixture);
        fixture
            .driver
            .handle_envelope(proposal_envelope)
            .expect("request missing proposal material");
        let (candidate_id, request_id) = requested_material_identity(&fixture.driver);
        let material = fixture
            .serving_source
            .material_for_serving(candidate_id)
            .expect("read source material")
            .expect("source material");
        let chunks = build_material_chunks(&material, request_id).expect("build material chunks");
        let proposer_peer = peer(&fixture.validator_set.validators[fixture.proposer_index]);
        let wrong_peer_index =
            (fixture.proposer_index + 1) % fixture.validator_set.validators.len();
        let wrong_peer = peer(&fixture.validator_set.validators[wrong_peer_index]);

        let mut unsolicited = chunks[0].clone();
        unsolicited.request_id =
            Hash::from_domain_bytes("driver-material-test", b"unsolicited-request");
        unsolicited.chunk_root = unsolicited
            .computed_root()
            .expect("recompute unsolicited chunk root");
        let unsolicited_error = fixture
            .driver
            .handle_envelope(SimplifiedConsensusEnvelope {
                peer_address: "durable-material-proposer-peer".to_string(),
                authenticated_peer: proposer_peer.clone(),
                message: SimplifiedConsensusMessage::MaterialChunk { chunk: unsolicited },
            })
            .expect_err("unsolicited material must be rejected");
        assert!(matches!(
            classify_simplified_envelope_failure(unsolicited_error),
            SimplifiedEnvelopeFailure::PeerRejected(_)
        ));

        let wrong_peer_error = fixture
            .driver
            .handle_envelope(SimplifiedConsensusEnvelope {
                peer_address: "wrong-durable-material-peer".to_string(),
                authenticated_peer: wrong_peer,
                message: SimplifiedConsensusMessage::MaterialChunk {
                    chunk: chunks[0].clone(),
                },
            })
            .expect_err("unrequested peer material must be rejected");
        assert!(matches!(
            classify_simplified_envelope_failure(wrong_peer_error),
            SimplifiedEnvelopeFailure::PeerRejected(_)
        ));

        let mut oversized = chunks[0].clone();
        oversized.payload.resize(
            super::super::MAX_SIMPLIFIED_MATERIAL_CHUNK_PAYLOAD_BYTES + 1,
            0x5a,
        );
        oversized.chunk_root = oversized
            .computed_root()
            .expect("recompute oversized chunk root");
        let oversized_error = fixture
            .driver
            .handle_envelope(SimplifiedConsensusEnvelope {
                peer_address: "durable-material-proposer-peer".to_string(),
                authenticated_peer: proposer_peer.clone(),
                message: SimplifiedConsensusMessage::MaterialChunk { chunk: oversized },
            })
            .expect_err("oversized material must be rejected");
        assert!(matches!(
            classify_simplified_envelope_failure(oversized_error),
            SimplifiedEnvelopeFailure::PeerRejected(_)
        ));

        for chunk in &chunks[..chunks.len() - 1] {
            fixture
                .driver
                .handle_envelope(SimplifiedConsensusEnvelope {
                    peer_address: "durable-material-proposer-peer".to_string(),
                    authenticated_peer: proposer_peer.clone(),
                    message: SimplifiedConsensusMessage::MaterialChunk {
                        chunk: chunk.clone(),
                    },
                })
                .expect("stage valid material prefix");
        }
        let mut truncated = chunks.last().expect("material final chunk").clone();
        truncated.payload.pop();
        truncated.chunk_root = truncated
            .computed_root()
            .expect("recompute truncated chunk root");
        let truncation_error = fixture
            .driver
            .handle_envelope(SimplifiedConsensusEnvelope {
                peer_address: "durable-material-proposer-peer".to_string(),
                authenticated_peer: proposer_peer.clone(),
                message: SimplifiedConsensusMessage::MaterialChunk { chunk: truncated },
            })
            .expect_err("truncated material must be rejected");
        assert!(matches!(
            classify_simplified_envelope_failure(truncation_error),
            SimplifiedEnvelopeFailure::PeerRejected(_)
        ));

        for chunk in chunks.iter().cloned() {
            fixture
                .driver
                .handle_envelope(SimplifiedConsensusEnvelope {
                    peer_address: "durable-material-proposer-peer".to_string(),
                    authenticated_peer: proposer_peer.clone(),
                    message: SimplifiedConsensusMessage::MaterialChunk { chunk },
                })
                .expect("valid retry succeeds after peer-local rejection");
        }
        let replay_error = fixture
            .driver
            .handle_envelope(SimplifiedConsensusEnvelope {
                peer_address: "durable-material-proposer-peer".to_string(),
                authenticated_peer: proposer_peer,
                message: SimplifiedConsensusMessage::MaterialChunk {
                    chunk: chunks.last().expect("replay chunk").clone(),
                },
            })
            .expect_err("completed material replay must be rejected");
        assert!(matches!(
            classify_simplified_envelope_failure(replay_error),
            SimplifiedEnvelopeFailure::PeerRejected(_)
        ));
        assert!(durable_material_messages(&fixture.driver)
            .iter()
            .any(|message| matches!(
                message,
                SimplifiedConsensusMessage::ReliableDelivery { statement }
                    if statement.phase == ReliableDeliveryPhase::Echo
            )));
        let _ = std::fs::remove_dir_all(fixture.receiving_directory);
        let _ = std::fs::remove_dir_all(fixture.serving_directory);
    }

    #[test]
    fn echo_and_ready_thresholds_emit_exactly_one_delivered_candidate_vote() {
        let mut fixture = provision_driver("delivery-thresholds");
        let proposal = drive_proposal(&mut fixture.driver);
        let candidate = candidate_for_proposal(&proposal).expect("proposal candidate");
        let other_indexes = other_validator_indexes(&fixture.driver);

        for validator_index in other_indexes.iter().take(3).copied() {
            let statement = signed_delivery_statement(
                &mut fixture.driver,
                validator_index,
                ReliableDeliveryPhase::Echo,
                &candidate,
            );
            deliver_statement(&mut fixture.driver, validator_index, statement)
                .expect("deliver peer ECHO");
        }
        for validator_index in other_indexes.iter().take(2).copied() {
            let statement = signed_delivery_statement(
                &mut fixture.driver,
                validator_index,
                ReliableDeliveryPhase::Ready,
                &candidate,
            );
            deliver_statement(&mut fixture.driver, validator_index, statement.clone())
                .expect("deliver peer READY");
            if validator_index == other_indexes[1] {
                deliver_statement(&mut fixture.driver, validator_index, statement)
                    .expect("duplicate READY is idempotent");
            }
        }

        let votes = recorded_messages(&fixture.driver)
            .into_iter()
            .filter_map(|message| match message {
                SimplifiedConsensusMessage::Vote { vote } => Some(vote),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(votes.len(), 1);
        assert_eq!(votes[0].block_id, proposal.block_id);
        assert_eq!(fixture.driver.metrics().votes_broadcast, 1);
    }

    #[test]
    fn byzantine_two_two_echo_split_cannot_make_driver_vote() {
        let mut fixture = provision_driver("two-two-split");
        let proposal = drive_proposal(&mut fixture.driver);
        let candidate_a = candidate_for_proposal(&proposal).expect("proposal candidate");
        let mut candidate_b = candidate_a.clone();
        candidate_b.block_id = BlockId("driver-protected-block-split-b".to_string());
        candidate_b.protected_execution_root =
            Hash::from_domain_bytes("driver-protected-execution", b"split-b");
        let other_indexes = other_validator_indexes(&fixture.driver);

        let echo_a = signed_delivery_statement(
            &mut fixture.driver,
            other_indexes[0],
            ReliableDeliveryPhase::Echo,
            &candidate_a,
        );
        deliver_statement(&mut fixture.driver, other_indexes[0], echo_a)
            .expect("deliver second candidate-A ECHO");
        for validator_index in other_indexes.iter().skip(1).take(2).copied() {
            let echo_b = signed_delivery_statement(
                &mut fixture.driver,
                validator_index,
                ReliableDeliveryPhase::Echo,
                &candidate_b,
            );
            deliver_statement(&mut fixture.driver, validator_index, echo_b)
                .expect("deliver candidate-B ECHO");
        }

        assert!(fixture
            .driver
            .reliable_delivery
            .as_ref()
            .expect("delivery state")
            .delivered_candidate
            .is_none());
        assert_eq!(fixture.driver.metrics().votes_broadcast, 0);
        assert!(!recorded_messages(&fixture.driver)
            .iter()
            .any(|message| matches!(message, SimplifiedConsensusMessage::Vote { .. })));
    }

    #[test]
    fn first_echo_does_not_block_later_delivered_candidate_vote() {
        let mut fixture = provision_driver("first-echo-later-delivery");
        let proposal_a = drive_proposal(&mut fixture.driver);
        let mut proposal_b = proposal_a.clone();
        proposal_b.block_id = BlockId("driver-protected-block-later-b".to_string());
        proposal_b.protected_execution_root =
            Hash::from_domain_bytes("driver-protected-execution", b"later-b");
        proposal_b.proposer_signature = fixture
            .driver
            .signer
            .sign_domain(
                POSY_SIMPLIFIED_PROPOSAL_DOMAIN,
                &proposal_b
                    .signing_bytes()
                    .expect("proposal-B signing bytes"),
                &proposal_b.proposer_key_id,
            )
            .expect("Byzantine proposer signs candidate B");
        let candidate_b = candidate_for_proposal(&proposal_b).expect("candidate B");
        let other_indexes = other_validator_indexes(&fixture.driver);

        for validator_index in other_indexes.iter().copied() {
            let echo_b = signed_delivery_statement(
                &mut fixture.driver,
                validator_index,
                ReliableDeliveryPhase::Echo,
                &candidate_b,
            );
            deliver_statement(&mut fixture.driver, validator_index, echo_b)
                .expect("deliver candidate-B ECHO");
        }
        for validator_index in other_indexes.iter().take(2).copied() {
            let ready_b = signed_delivery_statement(
                &mut fixture.driver,
                validator_index,
                ReliableDeliveryPhase::Ready,
                &candidate_b,
            );
            deliver_statement(&mut fixture.driver, validator_index, ready_b)
                .expect("deliver candidate-B READY");
        }
        assert_eq!(fixture.driver.metrics().votes_broadcast, 0);

        let proposer_index = fixture
            .driver
            .validator_set
            .validators
            .iter()
            .position(|validator| validator.validator_id == proposal_b.proposer_id)
            .expect("proposal B proposer in validator set");
        let proposer_peer = peer(&fixture.driver.validator_set.validators[proposer_index]);
        fixture
            .driver
            .handle_envelope(SimplifiedConsensusEnvelope {
                peer_address: "byzantine-scheduled-proposer".to_string(),
                authenticated_peer: proposer_peer,
                message: SimplifiedConsensusMessage::Proposal {
                    proposal: proposal_b.clone(),
                },
            })
            .expect("locally validate delivered proposal B");

        let votes = recorded_messages(&fixture.driver)
            .into_iter()
            .filter_map(|message| match message {
                SimplifiedConsensusMessage::Vote { vote } => Some(vote),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(votes.len(), 1);
        assert_eq!(votes[0].block_id, proposal_b.block_id);
    }

    #[test]
    fn bad_reliable_delivery_signature_is_peer_rejection_not_worker_failure() {
        let mut fixture = provision_driver("bad-delivery-signature");
        let proposal = drive_proposal(&mut fixture.driver);
        let candidate = candidate_for_proposal(&proposal).expect("proposal candidate");
        let validator_index = other_validator_indexes(&fixture.driver)[0];
        let mut statement = signed_delivery_statement(
            &mut fixture.driver,
            validator_index,
            ReliableDeliveryPhase::Echo,
            &candidate,
        );
        statement.signature.signature_bytes[0] ^= 0x80;

        let error = deliver_statement(&mut fixture.driver, validator_index, statement)
            .expect_err("bad delivery signature must be rejected");
        assert!(matches!(
            classify_simplified_envelope_failure(error),
            SimplifiedEnvelopeFailure::PeerRejected(_)
        ));
        assert!(fixture
            .driver
            .finalization_sink
            .state
            .lock()
            .expect("finalization sink lock")
            .attempts
            .is_empty());
    }

    #[test]
    fn delivery_state_reloads_and_wrong_authenticated_sender_is_rejected() {
        let mut fixture = provision_driver("delivery-restart");
        let proposal = drive_proposal(&mut fixture.driver);
        let candidate = candidate_for_proposal(&proposal).expect("proposal candidate");
        let persisted_delivery = fixture
            .driver
            .state_machine()
            .state()
            .reliable_delivery
            .clone()
            .expect("delivery progress persisted before broadcast");
        let restart_signer = clone_registered_signer(&fixture.driver);
        let restart_verifier = restart_signer.verifier();
        let context = fixture.driver.epoch_context.clone();
        let validators = fixture.driver.validator_set.clone();
        let local_validator_id = fixture.driver.local_validator_id.clone();
        let local_key_id = fixture.driver.local_key_id.clone();
        drop(fixture.driver);

        let mut restarted = SimplifiedPosyDriver::new(
            context,
            validators,
            local_validator_id,
            local_key_id,
            DurableSimplifiedPosyStore::at_path(fixture.state_path),
            anchor(),
            DurableConsensusSigningAuthority::at_path(fixture.signer_journal_path),
            restart_signer,
            restart_verifier,
            TestProposalSource::new("delivery-restart"),
            RecordingEgress::default(),
            RecordingFinalizationSink::default(),
            SimplifiedDriverTiming {
                proposal_timeout: Duration::from_millis(100),
                vote_timeout: Duration::from_millis(100),
                max_round_timeout: Duration::from_millis(500),
            },
        )
        .expect("reload driver with durable delivery progress");
        assert_eq!(restarted.reliable_delivery, Some(persisted_delivery));
        let restored_echo = restarted
            .reliable_delivery
            .as_ref()
            .expect("restored delivery state")
            .local_statement(ReliableDeliveryPhase::Echo, &restarted.local_validator_id)
            .expect("read restored local ECHO")
            .expect("restored local ECHO exists");
        restarted
            .retransmit_restored_delivery()
            .expect("retransmit restored delivery statement");
        assert_eq!(
            recorded_messages(&restarted),
            vec![SimplifiedConsensusMessage::ReliableDelivery {
                statement: restored_echo,
            }]
        );
        assert!(restarted.pending_delivery_retransmission.is_empty());

        let other_indexes = other_validator_indexes(&restarted);
        let statement = signed_delivery_statement(
            &mut restarted,
            other_indexes[0],
            ReliableDeliveryPhase::Echo,
            &candidate,
        );
        let before = restarted.reliable_delivery.clone();
        let wrong_peer = peer(&restarted.validator_set.validators[other_indexes[1]]);
        let error = restarted
            .handle_envelope(SimplifiedConsensusEnvelope {
                peer_address: "wrong-authenticated-driver-peer".to_string(),
                authenticated_peer: wrong_peer,
                message: SimplifiedConsensusMessage::ReliableDelivery { statement },
            })
            .expect_err("authenticated sender mismatch must be rejected");
        assert!(error.contains("sender does not match authenticated peer"));
        assert_eq!(restarted.reliable_delivery, before);
    }

    #[test]
    fn state_sync_request_broadcasts_only_bounded_chunks() {
        let mut fixture = provision_driver("chunked-state-sync");
        let request_peer = peer(&fixture.driver.validator_set.validators[0]);
        let request_id = Hash::from_domain_bytes("driver-state-sync-request", b"bounded-chunks");
        fixture
            .driver
            .handle_envelope(SimplifiedConsensusEnvelope {
                peer_address: "state-sync-requester".to_string(),
                authenticated_peer: request_peer,
                message: SimplifiedConsensusMessage::StateSyncRequest {
                    epoch_context_root: fixture.driver.epoch_context.root().unwrap(),
                    request_id,
                },
            })
            .expect("serve chunked state sync");

        let messages = recorded_messages(&fixture.driver);
        assert!(!messages.is_empty());
        assert!(messages
            .iter()
            .all(|message| matches!(message, SimplifiedConsensusMessage::StateSyncChunk { chunk } if chunk.request_id == request_id)));
        assert_eq!(
            fixture.driver.metrics().state_sync_chunks_broadcast as usize,
            messages.len()
        );
    }

    #[test]
    fn takeover_proposal_source_receives_exact_height_scoped_carry_directive() {
        let mut fixture = provision_driver_for_round("takeover-carry-directive", 1);
        let proposal_context = ConsensusObjectContext::for_height(
            &fixture.driver.epoch_context,
            Height(3_001),
            Round(0),
        )
        .expect("takeover candidate context");
        let mandatory_candidate = CertifiedCandidateSubject::new(
            proposal_context,
            BlockId("takeover-carried-block".to_string()),
            anchor().block_id,
            anchor(),
            Hash::from_domain_bytes("driver-protected-execution", b"takeover-carried-block"),
        )
        .expect("mandatory carry candidate");
        for validator_index in 0..4 {
            let reported_candidate = (validator_index < 2).then(|| mandatory_candidate.clone());
            let vote =
                signed_timeout_vote(&mut fixture.driver, validator_index, reported_candidate);
            let authenticated_peer =
                peer(&fixture.driver.validator_set.validators[validator_index]);
            fixture
                .driver
                .handle_envelope(SimplifiedConsensusEnvelope {
                    peer_address: format!("takeover-vote-peer-{validator_index}"),
                    authenticated_peer,
                    message: SimplifiedConsensusMessage::TimeoutVote { vote },
                })
                .expect("collect takeover timeout vote");
        }

        let proposal = drive_proposal(&mut fixture.driver);
        let directive = fixture
            .driver
            .proposal_source
            .directives
            .lock()
            .expect("proposal directive lock")
            .last()
            .cloned()
            .expect("takeover proposal directive");
        assert_eq!(
            directive.mandatory_carry_candidate,
            Some(mandatory_candidate.clone())
        );
        assert_eq!(directive.context.height, mandatory_candidate.context.height);
        assert_eq!(directive.context.round, Round(1));
        assert_eq!(proposal.block_id, mandatory_candidate.block_id);
        assert_eq!(
            proposal.protected_execution_root,
            mandatory_candidate.protected_execution_root
        );
    }

    #[test]
    fn cross_epoch_finalization_builder_rejects_prior_tail_without_verified_capability() {
        let fixture = provision_transition_driver("transition-finality-no-capability");
        let target = fixture
            .driver
            .state_machine
            .preview_finalized_with_qc(&fixture.first_current_qc)
            .expect("preview first current-epoch QC")
            .expect("first current-epoch QC finalizes the prior parent");
        let error = build_finalization_transaction(
            fixture
                .driver
                .epoch_context
                .root()
                .expect("transition driver epoch root"),
            &fixture.driver.state_machine.state().finalized,
            &target,
            fixture.driver.state_machine.state(),
            Some(&fixture.first_current_qc),
            None,
        )
        .expect_err("prior tail must not be consumed without the local transition capability");

        assert!(error.contains("receiver-owned verified transition"));
    }

    #[test]
    fn first_current_qc_finalizes_prior_parent_and_retries_deterministically_after_restart() {
        let mut fixture = provision_transition_driver("transition-finality-restart");
        let restart_signer = clone_registered_signer(&fixture.driver);
        let restart_verifier = restart_signer.verifier();
        let local_validator_id = fixture.driver.local_validator_id.clone();
        let local_key_id = fixture.driver.local_key_id.clone();
        let restart_sink = fixture.driver.finalization_sink.clone();
        let state_path = fixture.state_path.clone();
        let signer_journal_path = fixture.signer_journal_path.clone();
        let transition = fixture.transition.clone();
        let first_current_qc = fixture.first_current_qc.clone();
        let finalized_before = fixture.driver.state_machine.state().finalized.clone();
        fixture
            .driver
            .finalization_sink
            .state
            .lock()
            .expect("transition finalization sink lock")
            .fail_after_commit_once = true;

        let error = fixture
            .driver
            .accept_quorum_certificate(first_current_qc.clone())
            .expect_err("injected post-commit crash must precede consensus mutation");
        assert!(error.contains("SIMPLIFIED_LOCAL_FINALIZATION_FAILURE"));
        assert_eq!(
            fixture.driver.state_machine.state().finalized,
            finalized_before
        );
        let first_transaction = {
            let sink_state = restart_sink
                .state
                .lock()
                .expect("read transition finalization sink");
            assert_eq!(sink_state.committed.len(), 1);
            sink_state
                .committed
                .values()
                .next()
                .expect("durable transition finalization")
                .clone()
        };
        assert_eq!(first_transaction.target_finalized.height, Height(3_999));
        assert_eq!(first_transaction.commitments.len(), 1);
        assert_eq!(
            first_transaction
                .finality_witness
                .iter()
                .map(|certificate| certificate.context.height)
                .collect::<Vec<_>>(),
            vec![Height(3_999), Height(4_000), Height(4_001)]
        );
        let transaction_id = first_transaction.transaction_id;
        drop(fixture.driver);

        let mut restarted = SimplifiedPosyDriver::new_from_verified_v3_transition(
            transition,
            local_validator_id,
            local_key_id,
            DurableSimplifiedPosyStore::at_path(state_path),
            DurableConsensusSigningAuthority::at_path(signer_journal_path),
            restart_signer,
            restart_verifier,
            TestProposalSource::new("transition-finality-restart"),
            RecordingEgress::default(),
            restart_sink.clone(),
            SimplifiedDriverTiming {
                proposal_timeout: Duration::from_millis(100),
                vote_timeout: Duration::from_millis(100),
                max_round_timeout: Duration::from_millis(500),
            },
        )
        .expect("restart transition-aware driver");
        assert_eq!(restarted.state_machine.state().finalized, finalized_before);
        restarted
            .accept_quorum_certificate(first_current_qc)
            .expect("idempotently retry first current-epoch QC");

        let sink_state = restart_sink
            .state
            .lock()
            .expect("read retried transition finalization sink");
        assert_eq!(sink_state.committed.len(), 1);
        assert_eq!(sink_state.attempts, vec![transaction_id, transaction_id]);
        assert_eq!(
            restarted.state_machine.state().finalized.height,
            Height(3_999)
        );
        assert_eq!(
            restarted.state_machine.state().highest_qc.height,
            Height(4_001)
        );
    }

    #[test]
    fn finalization_sink_failure_does_not_advance_consensus_and_retry_commits_once() {
        let mut fixture = provision_driver("finalization-precommit-retry");
        let finalizing_qc = prepare_finalizing_certificate(&mut fixture.driver);
        let highest_before = fixture.driver.state_machine.state().highest_qc.clone();
        let finalized_before = fixture.driver.state_machine.state().finalized.clone();
        fixture
            .driver
            .finalization_sink
            .state
            .lock()
            .expect("finalization sink lock")
            .fail_before_commit_once = true;

        let error = fixture
            .driver
            .accept_quorum_certificate(finalizing_qc.clone())
            .expect_err("injected sink failure must stop QC admission");
        assert!(matches!(
            classify_simplified_envelope_failure(error),
            SimplifiedEnvelopeFailure::FatalLocal(_)
        ));
        assert_eq!(
            fixture.driver.state_machine.state().highest_qc,
            highest_before
        );
        assert_eq!(
            fixture.driver.state_machine.state().finalized,
            finalized_before
        );
        assert!(fixture
            .driver
            .finalization_sink
            .state
            .lock()
            .expect("finalization sink lock")
            .committed
            .is_empty());

        fixture
            .driver
            .accept_quorum_certificate(finalizing_qc)
            .expect("retry finalization transaction");
        let sink_state = fixture
            .driver
            .finalization_sink
            .state
            .lock()
            .expect("finalization sink lock");
        assert_eq!(sink_state.committed.len(), 1);
        assert_eq!(sink_state.attempts.len(), 2);
        assert_eq!(sink_state.attempts[0], sink_state.attempts[1]);
        assert_eq!(
            fixture.driver.state_machine.state().finalized.height,
            Height(3_001)
        );
    }

    #[test]
    fn crash_after_sink_commit_retries_same_transaction_without_duplicate_commit() {
        let mut fixture = provision_driver("finalization-postcommit-crash");
        let finalizing_qc = prepare_finalizing_certificate(&mut fixture.driver);
        let highest_before = fixture.driver.state_machine.state().highest_qc.clone();
        fixture
            .driver
            .finalization_sink
            .state
            .lock()
            .expect("finalization sink lock")
            .fail_after_commit_once = true;

        let error = fixture
            .driver
            .accept_quorum_certificate(finalizing_qc.clone())
            .expect_err("injected post-commit crash must stop consensus mutation");
        assert!(error.contains("SIMPLIFIED_LOCAL_FINALIZATION_FAILURE"));
        assert_eq!(
            fixture.driver.state_machine.state().highest_qc,
            highest_before
        );
        {
            let sink_state = fixture
                .driver
                .finalization_sink
                .state
                .lock()
                .expect("finalization sink lock");
            assert_eq!(sink_state.committed.len(), 1);
            assert_eq!(sink_state.attempts.len(), 1);
        }

        fixture
            .driver
            .accept_quorum_certificate(finalizing_qc)
            .expect("idempotent post-crash retry");
        let sink_state = fixture
            .driver
            .finalization_sink
            .state
            .lock()
            .expect("finalization sink lock");
        assert_eq!(sink_state.committed.len(), 1);
        assert_eq!(sink_state.attempts.len(), 2);
        assert_eq!(sink_state.attempts[0], sink_state.attempts[1]);
        assert_eq!(
            fixture.driver.state_machine.state().finalized.height,
            Height(3_001)
        );
    }

    #[test]
    fn verified_state_sync_commits_finalization_sink_before_consensus_install() {
        let mut source = provision_driver("state-sync-finalization-source");
        let target_signer = clone_registered_signer(&source.driver);
        let target_verifier = target_signer.verifier();
        let target_context = source.driver.epoch_context.clone();
        let target_validators = source.driver.validator_set.clone();
        let target_validator_id = source.driver.local_validator_id.clone();
        let target_key_id = source.driver.local_key_id.clone();
        let (target_state_path, target_journal_path) =
            unique_driver_paths("state-sync-finalization-target");
        let target_sink = RecordingFinalizationSink::default();
        let target_sink_state = target_sink.state.clone();
        let mut target = SimplifiedPosyDriver::new(
            target_context,
            target_validators,
            target_validator_id,
            target_key_id,
            DurableSimplifiedPosyStore::at_path(target_state_path),
            anchor(),
            DurableConsensusSigningAuthority::at_path(target_journal_path),
            target_signer,
            target_verifier,
            TestProposalSource::new("state-sync-finalization-target"),
            RecordingEgress::default(),
            target_sink,
            SimplifiedDriverTiming {
                proposal_timeout: Duration::from_millis(100),
                vote_timeout: Duration::from_millis(100),
                max_round_timeout: Duration::from_millis(500),
            },
        )
        .expect("construct state-sync target driver");

        let finalizing_qc = prepare_finalizing_certificate(&mut source.driver);
        source
            .driver
            .accept_quorum_certificate(finalizing_qc)
            .expect("source commits finalizing QC");
        let bundle = source
            .driver
            .state_machine
            .export_state_sync_bundle()
            .expect("export finalized source bundle");
        let source_peer = peer(&target.validator_set.validators[0]);
        let request_id =
            Hash::from_domain_bytes("driver-state-sync-request", b"finalization-target");
        target
            .state_sync_stager
            .register_request(request_id, Instant::now())
            .expect("register finalized state-sync request");
        for chunk in
            build_state_sync_chunks(&bundle, request_id).expect("chunk finalized source bundle")
        {
            target
                .handle_envelope(SimplifiedConsensusEnvelope {
                    peer_address: "finalized-state-sync-source".to_string(),
                    authenticated_peer: source_peer.clone(),
                    message: SimplifiedConsensusMessage::StateSyncChunk { chunk },
                })
                .expect("install verified finalized state sync");
        }

        let sink_state = target_sink_state
            .lock()
            .expect("target finalization sink lock");
        assert_eq!(sink_state.committed.len(), 1);
        let transaction = sink_state
            .committed
            .values()
            .next()
            .expect("target finalization transaction");
        assert_eq!(
            transaction.expected_previous_finalized.height,
            Height(3_000)
        );
        assert_eq!(transaction.target_finalized.height, Height(3_001));
        assert_eq!(transaction.commitments.len(), 1);
        assert_eq!(target.state_machine.state().finalized.height, Height(3_001));
    }

    #[test]
    fn invalid_finalizing_qc_is_peer_rejection_before_finalization_sink() {
        let mut fixture = provision_driver("invalid-finalizing-qc");
        let proposal_3001 = drive_proposal(&mut fixture.driver);
        certify_proposal(&mut fixture.driver, &proposal_3001);
        let proposal_3002 = drive_proposal(&mut fixture.driver);
        certify_proposal(&mut fixture.driver, &proposal_3002);

        let parent_qc = fixture.driver.state_machine.state().highest_qc.clone();
        let context = ConsensusObjectContext::for_height(
            &fixture.driver.epoch_context,
            Height(3_003),
            Round(0),
        )
        .expect("height-3003 context");
        let mut invalid_votes = Vec::new();
        for validator in fixture.driver.validator_set.validators.iter().take(4) {
            invalid_votes.push(BlockVote {
                context: context.clone(),
                block_id: BlockId("invalid-finalizing-block-3003".to_string()),
                parent_block_id: parent_qc.block_id.clone(),
                parent_qc: parent_qc.clone(),
                takeover_tc_id: None,
                protected_execution_root: Hash::from_domain_bytes(
                    "driver-protected-execution",
                    b"invalid-finalizing-block-3003",
                ),
                validator_id: validator.validator_id.clone(),
                key_id: validator.consensus_public_key.key_id.clone(),
                signature: AegisPqSignature {
                    algorithm: TESTNET_V3_CONSENSUS_SIGNATURE_ALGORITHM.to_string(),
                    signature_bytes: vec![0x55],
                },
            });
        }
        let invalid_qc = SimplifiedQuorumCertificate::from_votes(invalid_votes)
            .expect("structurally coherent invalid-signature QC");
        assert!(fixture
            .driver
            .state_machine
            .would_finalize_with_qc(&invalid_qc)
            .expect("preview finalization shape"));
        let relay_peer = peer(&fixture.driver.validator_set.validators[0]);
        let error = fixture
            .driver
            .handle_envelope(SimplifiedConsensusEnvelope {
                peer_address: "invalid-qc-relay".to_string(),
                authenticated_peer: relay_peer,
                message: SimplifiedConsensusMessage::QuorumCertificate {
                    certificate: invalid_qc,
                },
            })
            .expect_err("invalid finalizing QC must be rejected");

        assert!(!error.contains("SIMPLIFIED_FINALIZATION_SINK_NOT_INSTALLED"));
        assert!(matches!(
            classify_simplified_envelope_failure(error),
            SimplifiedEnvelopeFailure::PeerRejected(_)
        ));
        assert!(fixture
            .driver
            .finalization_sink
            .state
            .lock()
            .expect("finalization sink lock")
            .attempts
            .is_empty());
    }

    #[test]
    fn underived_state_sync_finality_is_peer_rejection_before_finalization_sink() {
        let mut fixture = provision_driver("invalid-state-sync-finality");
        let proposal_3001 = drive_proposal(&mut fixture.driver);
        certify_proposal(&mut fixture.driver, &proposal_3001);
        let proposal_3002 = drive_proposal(&mut fixture.driver);
        certify_proposal(&mut fixture.driver, &proposal_3002);

        let mut bundle = fixture
            .driver
            .state_machine
            .export_state_sync_bundle()
            .expect("export verified state sync");
        let qc_3001 = fixture
            .driver
            .state_machine
            .state()
            .certified_qcs
            .get(&3_001)
            .expect("height-3001 QC");
        bundle.claimed_finalized = FinalizedBlockRecord {
            height: qc_3001.context.height,
            block_id: qc_3001.block_id.clone(),
            qc_id: qc_3001.id().expect("height-3001 QC id"),
        };
        let request_id =
            Hash::from_domain_bytes("driver-state-sync-request", b"underived-finality");
        fixture
            .driver
            .state_sync_stager
            .register_request(request_id, Instant::now())
            .expect("register underived state-sync request");
        let chunks = build_state_sync_chunks(&bundle, request_id)
            .expect("chunk structurally valid but underived finality claim");
        let source_peer = peer(&fixture.driver.validator_set.validators[0]);
        let mut final_error = None;
        for chunk in chunks {
            match fixture.driver.handle_envelope(SimplifiedConsensusEnvelope {
                peer_address: "malicious-state-sync-peer".to_string(),
                authenticated_peer: source_peer.clone(),
                message: SimplifiedConsensusMessage::StateSyncChunk { chunk },
            }) {
                Ok(()) => {}
                Err(error) => final_error = Some(error),
            }
        }
        let error = final_error.expect("underived finality claim must be rejected");
        assert!(error.contains("claimed finalized head is not derivable"));
        assert!(!error.contains("SIMPLIFIED_FINALIZATION_SINK_NOT_INSTALLED"));
        assert!(matches!(
            classify_simplified_envelope_failure(error),
            SimplifiedEnvelopeFailure::PeerRejected(_)
        ));
        assert!(fixture
            .driver
            .finalization_sink
            .state
            .lock()
            .expect("finalization sink lock")
            .attempts
            .is_empty());
    }

    #[test]
    fn byzantine_peer_rejection_is_not_a_remote_worker_kill_switch() {
        assert!(matches!(
            classify_simplified_envelope_failure(
                "block vote is not for the active simplified slot".to_string()
            ),
            SimplifiedEnvelopeFailure::PeerRejected(_)
        ));
        assert!(matches!(
            classify_simplified_envelope_failure(
                "CONSENSUS_SAFETY_HALT: conflicting valid QCs".to_string()
            ),
            SimplifiedEnvelopeFailure::FatalLocal(_)
        ));
        assert!(matches!(
            classify_simplified_envelope_failure(
                "write temporary state /tmp/state: disk full".to_string()
            ),
            SimplifiedEnvelopeFailure::FatalLocal(_)
        ));
    }

    #[test]
    fn durable_material_read_failure_is_a_fatal_local_error() {
        let failure = classify_simplified_envelope_failure(
            "read simplified material /data/material.json: input/output error".to_string(),
        );

        assert!(matches!(failure, SimplifiedEnvelopeFailure::FatalLocal(_)));
    }

    #[test]
    fn malformed_material_transcript_remains_a_peer_rejection() {
        let failure = classify_simplified_envelope_failure(
            "proposal-material record transcript root mismatch".to_string(),
        );

        assert!(matches!(
            failure,
            SimplifiedEnvelopeFailure::PeerRejected(_)
        ));
    }

    #[test]
    fn driver_quorum_assembly_derives_threshold_from_frozen_epoch_size_and_weight() {
        let mut four_validators = validators();
        four_validators.validators.truncate(4);
        let three_signers = four_validators.validators[..3]
            .iter()
            .map(|validator| &validator.validator_id);
        assert!(signer_pool_has_strict_dual_quorum(three_signers, &four_validators).unwrap());
        let two_signers = four_validators.validators[..2]
            .iter()
            .map(|validator| &validator.validator_id);
        assert!(!signer_pool_has_strict_dual_quorum(two_signers, &four_validators).unwrap());

        four_validators.validators[3].voting_weight = 10;
        let three_light_signers = four_validators.validators[..3]
            .iter()
            .map(|validator| &validator.validator_id);
        assert!(
            !signer_pool_has_strict_dual_quorum(three_light_signers, &four_validators).unwrap()
        );
    }
}
