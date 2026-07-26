//! Typed PoSy v2.2 coordinator ingress boundary.
//!
//! The inherited P2P block/vote protocol intentionally cannot reach this
//! mailbox. Production startup installs a single coordinator receiver before
//! validator duties are enabled; until then typed messages are rejected rather
//! than being queued, replayed, or interpreted by a legacy handler.

use crate::consensus::posy::{LocalConsensusContext, ProofOfSynergyBft};
use crate::consensus::testnet_v3_bootstrap::TestnetV3GenesisBootstrap;
use crate::consensus::typed_finality_store::{
    TypedEpochTransitionRecord, TypedFinalityRecord, TypedFinalityStore,
};
use crate::crypto::aegis_pqvm::{AegisPqKeyLifecycleRecord, AegisPqvmSigner, AegisPqvmVerifier};
use crate::crypto::pqc::{PQCAlgorithm, PQCPublicKey};
use crate::etdag::{EtdagParameters, ProtectedBlockInput, TargetAdmissionContext};
use crate::execution::{compute_state_root_after, execute_block, ExecutionState};
use crate::p2p::messages::TypedConsensusMessage;
use crate::synergy_types::{
    AegisPqKeyRole, Block, BlockId, ClusterMap, EpochTransition, Hash, QuorumCertificate,
    TimeoutCertificate, UmaId, ValidationCertificate, ValidatorId, ValidatorSet, ValidatorStatus,
    Vote, VotePhase,
};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender, TrySendError};
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

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
            TypedConsensusMessage::Proposal { block, .. } => {
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
            | TypedConsensusMessage::TimeoutCertificate { .. } => {}
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
    finality_store: TypedFinalityStore,
    accepted_proposals: BTreeMap<BlockId, Block>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TypedCoordinatorEvent {
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
}

/// Bounded-ingress accounting for the production coordinator worker.  Invalid
/// peer input is deliberately counted and discarded rather than terminating a
/// validator process or allowing a malformed message into a legacy path.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TypedCoordinatorIngressMetrics {
    pub accepted_messages: u64,
    pub rejected_messages: u64,
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
    pub protocol_config: crate::synergy_types::ProtocolConfig,
    pub signer: AegisPqvmSigner,
    pub local_validator_id: ValidatorId,
    pub genesis_anchor: Hash,
    pub deployed_genesis_state_root: Hash,
    pub execution_state: ExecutionState,
    pub etdag_parameters: EtdagParameters,
    pub finality_store: TypedFinalityStore,
}

impl TypedPosyCoordinatorStartup {
    /// Builds height-one signing authority only after every final input has
    /// been supplied and mutually bound.  This is deliberately a constructor,
    /// not a fallback: callers lacking the post-deployment state root or a
    /// final Genesis anchor cannot start a validator coordinator.
    pub fn build(self) -> Result<TypedPosyCoordinator, String> {
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
        let local_context = self.genesis_bootstrap.initial_local_consensus_context(
            &self.protocol_config,
            self.genesis_anchor,
            self.deployed_genesis_state_root,
        )?;
        let consensus = ProofOfSynergyBft::new(
            &self.genesis_bootstrap.verifier,
            self.genesis_bootstrap.validator_set,
            self.genesis_bootstrap.cluster_map,
            self.protocol_config,
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
            Ok(envelope) => match coordinator.handle_envelope(envelope, &authorizer) {
                Ok(_) => metrics.accepted_messages = metrics.accepted_messages.saturating_add(1),
                Err(_) => metrics.rejected_messages = metrics.rejected_messages.saturating_add(1),
            },
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
            finality_store,
            accepted_proposals: BTreeMap::new(),
        })
    }

    pub fn local_context(&self) -> &LocalConsensusContext {
        &self.local_context
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
                != latest.quorum_certificate_root
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
        let record = self
            .finality_store
            .append_verified_epoch_transition(transition)?;
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
            TypedConsensusMessage::Proposal {
                height_context,
                target_context,
                protected_block,
                block,
            } => self.accept_proposal(height_context, target_context, protected_block, block),
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
        }
    }

    pub fn propose_protected_block(
        &mut self,
        protected_block: &ProtectedBlockInput,
        target_context: &TargetAdmissionContext,
    ) -> Result<Block, String> {
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
        self.local_context.latest_finalized_height = block.header.height;
        self.local_context.latest_finalized_block_hash = Hash::from_hex(&record.block_id.0)
            .map_err(|error| format!("finalized typed block ID is not a hash: {error}"))?;
        self.local_context.latest_finalized_state_root = block.header.state_root_after;
        Ok(TypedCoordinatorEvent::Finalized { record })
    }

    fn accept_timeout_certificate(
        &mut self,
        certificate: TimeoutCertificate,
    ) -> Result<TypedCoordinatorEvent, String> {
        let next_round = self.consensus.advance_round_after_tc(
            &certificate,
            &self.local_context.height_context,
            self.local_context.round,
        )?;
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
        if let Some(existing) = self.accepted_proposals.get(&candidate_id) {
            if existing != block {
                return Err(
                    "typed proposal candidate ID maps to different block contents".to_string(),
                );
            }
        } else {
            self.accepted_proposals
                .insert(candidate_id.clone(), block.clone());
        }
        Ok(candidate_id)
    }
}

fn execute_finalized_block(
    state: &ExecutionState,
    block: &Block,
) -> Result<ExecutionState, String> {
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
            != latest.quorum_certificate_root
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

fn ingress_slot() -> &'static Mutex<Option<SyncSender<TypedConsensusEnvelope>>> {
    COORDINATOR_INGRESS.get_or_init(|| Mutex::new(None))
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
    Ok(())
}

/// Delivers a typed consensus message to the active coordinator without any
/// legacy fallback. Saturation and an absent coordinator are fail-closed.
pub fn dispatch_typed_consensus_message(
    peer_address: &str,
    authenticated_peer: Option<AuthenticatedTypedConsensusPeer>,
    message: TypedConsensusMessage,
) -> Result<(), String> {
    let sender = ingress_slot()
        .lock()
        .map_err(|_| "typed coordinator ingress lock is poisoned".to_string())?
        .clone()
        .ok_or_else(|| {
            "typed PoSy coordinator is not running; refusing consensus message".to_string()
        })?;
    sender
        .try_send(TypedConsensusEnvelope {
            peer_address: peer_address.to_string(),
            authenticated_peer,
            message,
        })
        .map_err(|error| match error {
            TrySendError::Full(_) => {
                "typed PoSy coordinator ingress is saturated; refusing consensus message"
                    .to_string()
            }
            TrySendError::Disconnected(_) => {
                "typed PoSy coordinator ingress is disconnected; refusing consensus message"
                    .to_string()
            }
        })
}

#[cfg(test)]
pub fn reset_typed_coordinator_ingress_for_test() {
    let _ = remove_typed_coordinator_ingress();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::posy::ProofOfSynergyBft;
    use crate::crypto::aegis_pqvm::AegisPqvmSigner;
    use crate::etdag::EtdagParameters;
    use crate::execution::ExecutionState;
    use crate::synergy_types::{
        deterministic_test_height_context, AegisPqKeyId, AegisPqKeyRole, AegisPqSignature,
        BlockHeader, BlockId, ChainId, ClusterAssignment, ClusterId, ClusterMap, Epoch,
        EpochTransition, Hash, Height, HeightConsensusContext, HeightConsensusContextSpec,
        NetworkId, ProtocolConfig, QuorumCertificate, Round, UmaId, ValidatorId, ValidatorRecord,
        ValidatorSet, ValidatorStatus, Vote, VotePhase, POSY_PROTOCOL_VERSION,
    };
    use std::collections::BTreeSet;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

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
        reset_typed_coordinator_ingress_for_test();
        let error = dispatch_typed_consensus_message("peer-a", None, vote()).unwrap_err();
        assert!(error.contains("coordinator is not running"));
    }

    #[test]
    fn typed_messages_use_the_bounded_dedicated_mailbox() {
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
            round: Round(0),
            evidence_root: Hash::from_domain_bytes("typed-coordinator-test", b"evidence"),
            app_version: 1,
            execution_version: 1,
            dag_version: 1,
            aegis_pqvm_version: "aegis-pqvm".to_string(),
        };
        let verifier = signer.verifier();
        let consensus = ProofOfSynergyBft::new(&verifier, set, cluster, protocol);
        let path = PathBuf::from(std::env::temp_dir()).join(format!(
            "synergy-typed-coordinator-{}-{}.json",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
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
            protocol_config: consensus.protocol_config,
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
            protocol_config: consensus.protocol_config,
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
                prior_finalized_qc_or_transition_root: finality_record.quorum_certificate_root,
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
}
