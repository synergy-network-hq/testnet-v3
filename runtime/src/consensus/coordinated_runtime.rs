//! Stateful runtime core for `coordinated_round_robin_v1`.
//!
//! This module owns the temporary mode's lifecycle only: signed assignments,
//! producer-package verification, deterministic execution, Val1's one commit,
//! and separate durable finality. It intentionally exposes no vote, QC, VC,
//! TC, aggregation, or coordinator-election operation.

use crate::aegis_tx_tool::AegisTxSubmissionEnvelope;
use crate::consensus::coordinated_admission::{
    coordinated_dag_frontier_root, coordinated_transaction_ids,
    verify_coordinated_transaction_admissions,
};
use crate::consensus::coordinated_finality_store::{
    CoordinatedFinalityRecord, CoordinatedFinalityStore,
};
use crate::consensus::coordinated_round_robin::{
    AuthenticatedCoordinatedConsensusPeer, CoordinatedConsensusVerifier, CoordinatedProposal,
    CoordinatedRoundRobinConfig, CoordinatorCommit, CoordinatorState, CoordinatorStateStore,
    ProducerAssignment, COORDINATED_ASSIGNMENT_DOMAIN, COORDINATED_COMMIT_DOMAIN,
};
use crate::consensus::signing_authority::{
    CoordinatedSigningAuthorization, CoordinatedSigningPhase, DurableConsensusSigningAuthority,
};
use crate::consensus_parameters::ConsensusParameterRoot;
use crate::crypto::aegis_pqvm::{AegisPqvmSigner, SYNERGY_BLOCK_V1};
use crate::execution::{
    compute_receipt_root, compute_state_root_after, execute_block, ExecutionState,
};
use crate::p2p::messages::{
    CoordinatedCommittedBlockPackage, CoordinatedConsensusMessage,
    MAX_COORDINATED_CONSENSUS_SYNC_RANGE_BLOCKS,
};
use crate::synergy_types::{
    AegisPqKeyId, AegisPqSignature, Block, BlockHeader, CanonicalSerialize, ChainId, ClusterId,
    Epoch, Hash, Height, NetworkId, Round, ValidatorId, ValidatorSet,
};

/// Immutable, Genesis-bound data required to construct a P1 coordinated
/// block.  It is deliberately smaller than the retired PoSy height context:
/// it provides metadata and deterministic timing only, not an inherited
/// proposer schedule, QC, VC, TC, or vote authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoordinatedBlockBuildContext {
    pub genesis_anchor: Hash,
    pub genesis_timestamp_ms: u64,
    pub protocol_config_hash: ConsensusParameterRoot,
    pub cryptographic_profile_root: Hash,
}

impl CoordinatedBlockBuildContext {
    pub fn validate(&self) -> Result<(), String> {
        if self.genesis_anchor.is_zero()
            || self.genesis_timestamp_ms == 0
            || self.protocol_config_hash.is_zero()
            || self.cryptographic_profile_root.is_zero()
        {
            return Err("coordinated block build context is incomplete".to_string());
        }
        Ok(())
    }

    fn timestamp_for(
        &self,
        config: &CoordinatedRoundRobinConfig,
        height: u64,
        producer_round: u64,
    ) -> Result<u64, String> {
        self.validate()?;
        if height == 0 {
            return Err(
                "coordinated block timestamp cannot target genesis height zero".to_string(),
            );
        }
        let height_offset = height
            .saturating_sub(1)
            .checked_mul(config.target_block_interval_ms)
            .ok_or_else(|| "coordinated block timestamp height offset overflow".to_string())?;
        let round_offset = producer_round
            .checked_mul(config.producer_turn_timeout_ms)
            .ok_or_else(|| {
                "coordinated block timestamp producer-round offset overflow".to_string()
            })?;
        self.genesis_timestamp_ms
            .checked_add(height_offset)
            .and_then(|timestamp| timestamp.checked_add(round_offset))
            .ok_or_else(|| "coordinated block timestamp overflow".to_string())
    }
}

/// The outcome of applying one fully verified coordinated finality package.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoordinatedRuntimeFinality {
    pub record: CoordinatedFinalityRecord,
    pub block_hash: Hash,
}

/// The caller owns transport egress; this runtime core owns only the exact
/// authenticated response or broadcast artifact. It deliberately returns no
/// vote, QC, VC, TC, or aggregation artifact because none exist in this mode.
#[derive(Debug, Clone)]
pub enum CoordinatedRuntimeAction {
    None,
    BroadcastCommitted(CoordinatedCommittedBlockPackage),
    Respond(CoordinatedConsensusMessage),
}

/// A no-QC, no-vote consensus lifecycle.  The role runtime supplies canonical
/// block construction and P2P egress around this core; neither is allowed to
/// bypass the journal or finality-store operations below.
pub struct CoordinatedRuntime {
    config: CoordinatedRoundRobinConfig,
    verifier: CoordinatedConsensusVerifier,
    local_validator_id: ValidatorId,
    local_consensus_key_id: AegisPqKeyId,
    signer: AegisPqvmSigner,
    signing_authority: DurableConsensusSigningAuthority,
    coordinator_state_store: CoordinatorStateStore,
    coordinator_state: CoordinatorState,
    finality_store: CoordinatedFinalityStore,
    execution_state: ExecutionState,
}

impl CoordinatedRuntime {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        config: CoordinatedRoundRobinConfig,
        validator_set: &ValidatorSet,
        verifier: crate::crypto::aegis_pqvm::AegisPqvmVerifier,
        local_validator_id: ValidatorId,
        signer: AegisPqvmSigner,
        signing_authority: DurableConsensusSigningAuthority,
        coordinator_state_store: CoordinatorStateStore,
        migration_state: CoordinatorState,
        finality_store: CoordinatedFinalityStore,
        execution_state: ExecutionState,
    ) -> Result<Self, String> {
        let coordinated_verifier =
            CoordinatedConsensusVerifier::new(config.clone(), validator_set, verifier)?;
        let local_validator = coordinated_verifier.validator_record(&local_validator_id.0)?;
        let local_consensus_key = signer
            .public_key_record(&local_validator.consensus_public_key.key_id)
            .map_err(|error| format!("load local coordinated consensus key: {error}"))?;
        if local_consensus_key != local_validator.consensus_public_key {
            return Err(
                "local coordinated signing key does not match the finalized validator key"
                    .to_string(),
            );
        }
        let mut coordinator_state = match coordinator_state_store.load(&config)? {
            Some(state) => state,
            None => {
                migration_state.validate(&config)?;
                coordinator_state_store.persist(&config, &migration_state)?;
                migration_state
            }
        };
        let finality_records = finality_store.recover(&config)?;
        for record in &finality_records {
            coordinated_verifier.verify_committed_block_package(&record.package)?;
        }
        reconcile_coordinator_state(
            &config,
            &coordinated_verifier,
            &coordinator_state_store,
            &mut coordinator_state,
            &finality_records,
            finality_store.first_coordinated_height(),
        )?;
        let execution_state = replay_finality_from_execution_state(
            execution_state,
            &finality_records,
            finality_store.migration_parent_state_root(),
        )?;
        let expected_execution_tip = finality_records
            .last()
            .map(|record| record.package.block.header.state_root_after)
            .unwrap_or_else(|| finality_store.migration_parent_state_root());
        if compute_state_root_after(&execution_state)? != expected_execution_tip {
            return Err(
                "coordinated runtime execution state does not match the finalized durable tip"
                    .to_string(),
            );
        }
        Ok(Self {
            config,
            verifier: coordinated_verifier,
            local_validator_id,
            local_consensus_key_id: local_consensus_key.key_id,
            signer,
            signing_authority,
            coordinator_state_store,
            coordinator_state,
            finality_store,
            execution_state,
        })
    }

    pub fn coordinator_state(&self) -> &CoordinatorState {
        &self.coordinator_state
    }

    pub fn execution_state(&self) -> &ExecutionState {
        &self.execution_state
    }

    pub fn is_local_coordinator(&self) -> bool {
        self.local_validator_id.0 == self.config.coordinator_id
    }

    pub fn pending_assignment(&self) -> Option<&ProducerAssignment> {
        self.coordinator_state.pending_assignment.as_ref()
    }

    pub fn local_validator_id(&self) -> &ValidatorId {
        &self.local_validator_id
    }

    /// Derives the only timestamp Val1 may use for the current durable next
    /// assignment.  The result is a Genesis-bound height/round coordinate,
    /// not a local clock reading, so restart replay has the exact same signing
    /// subject.
    pub fn next_assignment_timestamp(
        &self,
        context: &CoordinatedBlockBuildContext,
    ) -> Result<u64, String> {
        context.timestamp_for(
            &self.config,
            self.coordinator_state.next_height(),
            self.coordinator_state.pending_round,
        )
    }

    /// Derives the timestamp for the replacement assignment that follows a
    /// producer timeout. The height remains unchanged while the durable
    /// producer round advances exactly once.
    pub fn timeout_replacement_assignment_timestamp(
        &self,
        context: &CoordinatedBlockBuildContext,
    ) -> Result<u64, String> {
        if self.coordinator_state.pending_assignment.is_none() {
            return Err(
                "cannot derive a coordinated timeout replacement without a pending assignment"
                    .to_string(),
            );
        }
        let replacement_round = self
            .coordinator_state
            .pending_round
            .checked_add(1)
            .ok_or_else(|| "coordinated producer round overflow".to_string())?;
        context.timestamp_for(
            &self.config,
            self.coordinator_state.next_height(),
            replacement_round,
        )
    }

    /// Creates or safely replays Val1's next assignment. The supplied time is
    /// the canonical context-derived timestamp, never a local wall-clock read.
    pub fn issue_signed_assignment(
        &mut self,
        intended_block_timestamp_ms: u64,
    ) -> Result<ProducerAssignment, String> {
        self.require_local_coordinator()?;
        let template = self.coordinator_state.assignment_template(
            &self.config,
            self.verifier.epoch().0,
            intended_block_timestamp_ms,
        )?;
        let authorization = self.signing_authorization(
            CoordinatedSigningPhase::Assignment,
            template.producer_round,
            template.signing_hash()?,
        )?;
        let assignment = if let Some(recorded) = self
            .signing_authority
            .recorded_coordinated_envelope(&authorization)?
        {
            let assignment: ProducerAssignment = serde_json::from_slice(&recorded.signed_envelope)
                .map_err(|error| format!("decode durable coordinated assignment: {error}"))?;
            if assignment.signing_hash()? != authorization.subject_hash
                || assignment.coordinator_signature != recorded.signature
            {
                return Err(
                    "durable coordinated assignment envelope does not match its authorization"
                        .to_string(),
                );
            }
            assignment
        } else {
            let mut assignment = template;
            assignment.coordinator_signature = self
                .signer
                .sign_domain(
                    COORDINATED_ASSIGNMENT_DOMAIN,
                    &assignment.signing_hash()?.0,
                    &self.local_consensus_key_id,
                )
                .map_err(|error| format!("sign coordinated assignment: {error}"))?;
            let envelope = serde_json::to_vec(&assignment)
                .map_err(|error| format!("serialize coordinated assignment: {error}"))?;
            self.signing_authority.record_coordinated_envelope(
                &authorization,
                &assignment.coordinator_signature,
                &envelope,
            )?;
            assignment
        };
        self.verifier.verify_assignment(&assignment)?;
        self.install_assignment(&assignment)?;
        Ok(assignment)
    }

    /// Persists a timeout-driven producer skip at the same block height, then
    /// issues the next signed assignment in the strict Val2--Val6 rotation.
    pub fn skip_producer_turn_and_issue_assignment(
        &mut self,
        reason: impl Into<String>,
        intended_block_timestamp_ms: u64,
    ) -> Result<ProducerAssignment, String> {
        self.require_local_coordinator()?;
        let mut candidate = self.coordinator_state.clone();
        candidate.mark_producer_turn_missed(&self.config, reason)?;
        self.coordinator_state_store
            .persist(&self.config, &candidate)?;
        self.coordinator_state = candidate;
        self.issue_signed_assignment(intended_block_timestamp_ms)
    }

    /// Applies a Val1 assignment on every validator. This installs only the
    /// canonical current subject; stale or alternate assignments never update
    /// a local rotation cursor.
    pub fn accept_assignment(&mut self, assignment: &ProducerAssignment) -> Result<(), String> {
        self.verifier.verify_assignment(assignment)?;
        if assignment.height <= self.coordinator_state.last_finalized_height {
            // A durable finalized block proves that this assignment can no
            // longer affect local rotation. It was still signature-checked
            // above, so duplicated or stale traffic is harmless.
            return Ok(());
        }
        if assignment.height > self.coordinator_state.next_height() {
            // The signature is authentic but its finalized predecessor is not
            // local yet. Defer it without moving the cursor; the role driver
            // requests the bounded committed-finality range before retrying.
            return Ok(());
        }

        if let Some(pending) = self.coordinator_state.pending_assignment.as_ref() {
            if assignment.height == pending.height
                && assignment.producer_round < pending.producer_round
            {
                return Ok(());
            }
        }
        self.install_assignment(assignment)
    }

    /// Signs the exact canonical block authorized for the local producer turn.
    ///
    /// The producer signature is journaled with the assignment's height and
    /// round before the proposal can leave the process. A restart therefore
    /// reuses the original randomized ML-DSA envelope rather than signing a
    /// second representation of the same block subject. This method does not
    /// finalize or mutate execution state; only Val1's later commit does that.
    pub fn sign_assigned_producer_block(
        &mut self,
        assignment: &ProducerAssignment,
        mut block: Block,
        transaction_admissions: Vec<AegisTxSubmissionEnvelope>,
    ) -> Result<(CoordinatedProposal, Block), String> {
        self.accept_assignment(assignment)?;
        if self.local_validator_id.0 != assignment.assigned_producer_id {
            return Err(
                "only the signed assigned producer may create a coordinated block".to_string(),
            );
        }
        if assignment.height != self.coordinator_state.next_height()
            || self.coordinator_state.pending_assignment.as_ref() != Some(assignment)
        {
            return Err(
                "coordinated producer assignment is not the durable current block subject"
                    .to_string(),
            );
        }
        if block.proposer_signature.is_present() {
            return Err(
                "coordinated producer block must be unsigned before its durable signing boundary"
                    .to_string(),
            );
        }

        let transaction_admission_root = verify_coordinated_transaction_admissions(
            &block.transactions,
            &transaction_admissions,
            block.header.height,
            block
                .header
                .timestamp_ms_consensus_bounded
                .saturating_div(1_000),
        )?;
        if block.header.dag_frontier_root
            != coordinated_dag_frontier_root(
                block.header.parent_block_hash,
                block.header.tx_order_root,
                transaction_admission_root,
            )
        {
            return Err(
                "coordinated producer block does not bind its transaction-admission witnesses"
                    .to_string(),
            );
        }

        // Deterministic execution is required before signing so the producer
        // never authorizes header state or receipt roots it cannot reproduce.
        let _next_execution_state = execute_coordinated_block(&self.execution_state, &block)?;
        let block_hash = Hash::from_hex(&block.block_id()?.0)
            .map_err(|error| format!("coordinated block ID is not a hash: {error}"))?;
        let authorization = CoordinatedSigningAuthorization {
            chain_id: ChainId::synergy_testnet_v3(),
            network_id: NetworkId::synergy_testnet_v3(),
            consensus_version: self.config.consensus_version.clone(),
            epoch: self.verifier.epoch(),
            height: Height(assignment.height),
            producer_round: Round(assignment.producer_round),
            // This pre-existing field names the signing validator for the
            // durable record. For ProducerBlock it is the assigned producer;
            // Assignment and Commit remain restricted to Val1 below.
            coordinator_id: self.local_validator_id.clone(),
            key_id: self.local_consensus_key_id.clone(),
            phase: CoordinatedSigningPhase::ProducerBlock,
            subject_hash: block_hash,
        };
        if let Some(recorded) = self
            .signing_authority
            .recorded_coordinated_envelope(&authorization)?
        {
            block = serde_json::from_slice(&recorded.signed_envelope)
                .map_err(|error| format!("decode durable coordinated producer block: {error}"))?;
            let recovered_hash = Hash::from_hex(&block.block_id()?.0).map_err(|error| {
                format!("durable coordinated producer block ID is not a hash: {error}")
            })?;
            if recovered_hash != authorization.subject_hash
                || block.proposer_signature != recorded.signature
            {
                return Err(
                    "durable coordinated producer block does not match its authorization"
                        .to_string(),
                );
            }
        } else {
            let producer = self
                .verifier
                .validator_record(&assignment.assigned_producer_id)?;
            block.proposer_signature = self
                .signer
                .sign_domain(
                    SYNERGY_BLOCK_V1,
                    &block.header.canonical_bytes()?,
                    &producer.consensus_public_key.key_id,
                )
                .map_err(|error| format!("sign coordinated producer block: {error}"))?;
            let envelope = serde_json::to_vec(&block)
                .map_err(|error| format!("serialize coordinated producer block: {error}"))?;
            self.signing_authority.record_coordinated_envelope(
                &authorization,
                &block.proposer_signature,
                &envelope,
            )?;
        }

        let transaction_ids = coordinated_transaction_ids(&block.transactions)?;
        let proposal = CoordinatedProposal {
            epoch: assignment.epoch,
            height: assignment.height,
            producer_round: assignment.producer_round,
            parent_block_hash: assignment.parent_block_hash,
            prior_finality_reference: assignment.prior_finality_reference,
            block_hash: Hash::from_hex(&block.block_id()?.0)
                .map_err(|error| format!("coordinated block ID is not a hash: {error}"))?,
            transaction_root: crate::dag_mempool::compute_tx_order_root(&transaction_ids)?,
            transaction_admission_root,
            transaction_admissions,
            receipt_root: block.header.receipt_root,
            state_root: block.header.state_root_after,
            producer_id: assignment.assigned_producer_id.clone(),
            assignment_hash: assignment.signing_hash()?,
            producer_signature: block.proposer_signature.clone(),
        };
        self.verifier
            .verify_producer_block(assignment, &proposal, &block)?;
        Ok((proposal, block))
    }

    /// Builds the canonical block for the local assigned producer from the
    /// exact ordered Aegis admission witnesses selected for this turn.
    pub fn build_assigned_block(
        &self,
        assignment: &ProducerAssignment,
        context: &CoordinatedBlockBuildContext,
        transaction_admissions: &[AegisTxSubmissionEnvelope],
    ) -> Result<Block, String> {
        context.validate()?;
        if self.local_validator_id.0 != assignment.assigned_producer_id {
            return Err("only the assigned producer may build a coordinated block".to_string());
        }
        if self.coordinator_state.pending_assignment.as_ref() != Some(assignment) {
            return Err(
                "coordinated block build does not match the durable pending assignment".to_string(),
            );
        }
        let expected_timestamp =
            context.timestamp_for(&self.config, assignment.height, assignment.producer_round)?;
        if assignment.intended_block_timestamp_ms != expected_timestamp {
            return Err(
                "coordinated assignment timestamp does not match the Genesis-bound height/round schedule"
                    .to_string(),
            );
        }
        let transactions = transaction_admissions
            .iter()
            .map(|admission| admission.transaction.clone())
            .collect::<Vec<_>>();
        let transaction_admission_root = verify_coordinated_transaction_admissions(
            &transactions,
            transaction_admissions,
            Height(assignment.height),
            assignment.intended_block_timestamp_ms.saturating_div(1_000),
        )?;

        let active_validators = self
            .verifier
            .validator_set()
            .active_for_epoch(Epoch(assignment.epoch));
        if active_validators.validators.len() != 6 {
            return Err(
                "coordinated block requires the finalized six-validator active set".to_string(),
            );
        }
        let producer = self
            .verifier
            .validator_record(&assignment.assigned_producer_id)?;
        let state_root = compute_state_root_after(&self.execution_state)?;
        let transaction_ids = coordinated_transaction_ids(&transactions)?;
        let tx_order_root = crate::dag_mempool::compute_tx_order_root(&transaction_ids)?;
        let validator_set_root = active_validators.hash()?;
        let consensus_key_root = active_validators.consensus_key_root()?;
        let frozen_weight_root = active_validators.frozen_bonded_weight_root()?;
        let total_weight =
            active_validators
                .validators
                .iter()
                .try_fold(0u64, |total, validator| {
                    total
                        .checked_add(validator.voting_weight)
                        .ok_or_else(|| "coordinated validator weight total overflow".to_string())
                })?;
        let mut membership_material = Vec::new();
        for validator in &active_validators.validators {
            membership_material.extend_from_slice(validator.validator_id.0.as_bytes());
            membership_material.push(0);
            membership_material.extend_from_slice(&validator.voting_weight.to_be_bytes());
        }
        let membership_root = Hash::from_domain_bytes(
            "SYNERGY_COORDINATED_SINGLE_CLUSTER_MEMBERSHIP_V1",
            &membership_material,
        );
        let cluster_map_root = Hash::from_domain_bytes(
            "SYNERGY_COORDINATED_SINGLE_CLUSTER_MAP_V1",
            &membership_root.0,
        );
        let producer_schedule_root = Hash::from_domain_bytes(
            "SYNERGY_COORDINATED_PRODUCER_ROTATION_V1",
            &serde_json::to_vec(&self.config.producer_ids)
                .map_err(|error| format!("serialize coordinated producer schedule: {error}"))?,
        );
        let assignment_hash = assignment.signing_hash()?;
        let mut height_context_material = Vec::new();
        for root in [
            context.genesis_anchor,
            assignment_hash,
            validator_set_root,
            consensus_key_root,
            frozen_weight_root,
            membership_root,
            context.cryptographic_profile_root,
        ] {
            height_context_material.extend_from_slice(&root.0);
        }
        height_context_material.extend_from_slice(&assignment.height.to_be_bytes());
        height_context_material.extend_from_slice(&assignment.producer_round.to_be_bytes());
        let height_context_root = Hash::from_domain_bytes(
            "SYNERGY_COORDINATED_BLOCK_CONTEXT_V1",
            &height_context_material,
        );
        let dag_frontier_root = coordinated_dag_frontier_root(
            assignment.parent_block_hash,
            tx_order_root,
            transaction_admission_root,
        );
        let mut block = Block {
            header: BlockHeader {
                version: 1,
                chain_id: ChainId::synergy_testnet_v3(),
                network_id: NetworkId::synergy_testnet_v3(),
                protocol_version: self.config.consensus_version.clone(),
                height: Height(assignment.height),
                round: Round(assignment.producer_round),
                epoch: Epoch(assignment.epoch),
                cluster_id: ClusterId(0),
                height_context_root,
                parent_block_hash: assignment.parent_block_hash,
                parent_state_root: state_root,
                last_finalized_qc_hash: Hash::zero(),
                proposer_validator_id: producer.validator_id.clone(),
                proposer_uma_id: producer.validator_uma_id.clone(),
                proposer_key_id: producer.consensus_public_key.key_id.clone(),
                active_validator_set_hash: validator_set_root,
                eligible_validator_set_hash: membership_root,
                validator_consensus_key_root: consensus_key_root,
                frozen_bonded_weight_root: frozen_weight_root,
                cluster_schedule_version: "coordinated-round-robin-v1".to_string(),
                cluster_map_hash: cluster_map_root,
                assigned_cluster_membership_root: membership_root,
                assigned_cluster_validator_count: 6,
                assigned_cluster_total_voting_weight: total_weight,
                proposer_schedule_hash: producer_schedule_root,
                protocol_config_hash: context.protocol_config_hash.clone(),
                cryptographic_profile_root: context.cryptographic_profile_root,
                dag_frontier_root,
                tx_order_root,
                tx_count: u64::try_from(transactions.len())
                    .map_err(|_| "coordinated block transaction count exceeds u64".to_string())?,
                protected_batch: None,
                evidence_root: assignment.prior_finality_reference,
                state_root_before: state_root,
                state_root_after: state_root,
                receipt_root: compute_receipt_root(&[])?,
                app_version: 1,
                execution_version: 1,
                dag_version: 1,
                aegis_pqvm_version: "aegis-pqvm".to_string(),
                timestamp_ms_consensus_bounded: assignment.intended_block_timestamp_ms,
            },
            transactions,
            proposer_signature: AegisPqSignature {
                algorithm: String::new(),
                signature_bytes: Vec::new(),
            },
        };
        let mut authorized = self.execution_state.clone();
        for transaction in &block.transactions {
            authorized.mark_authorized_at(
                transaction,
                assignment.intended_block_timestamp_ms.saturating_div(1_000),
            )?;
        }
        let execution = execute_block(&block, &authorized)?;
        block.header.state_root_after = execution.state_root_after;
        block.header.receipt_root = execution.receipt_root;
        Ok(block)
    }

    /// Builds the canonical empty block only when the P1 admission source has
    /// no ready user transaction. Callers with any admitted work must use
    /// [`Self::build_assigned_block`] so it is executed and signed in order.
    pub fn build_empty_assigned_block(
        &self,
        assignment: &ProducerAssignment,
        context: &CoordinatedBlockBuildContext,
    ) -> Result<Block, String> {
        self.build_assigned_block(assignment, context, &[])
    }

    /// Verifies, executes, and finalizes a producer block on Val1. The exact
    /// commit is journaled before either finality state or outbound transport
    /// may observe it. Callers broadcast only the returned package.
    pub fn commit_executed_proposal(
        &mut self,
        assignment: &ProducerAssignment,
        proposal: &CoordinatedProposal,
        block: &Block,
    ) -> Result<CoordinatedCommittedBlockPackage, String> {
        self.require_local_coordinator()?;
        self.accept_assignment(assignment)?;
        self.verifier
            .verify_producer_block(assignment, proposal, block)?;
        let next_execution_state = execute_coordinated_block(&self.execution_state, block)?;
        let template = self
            .coordinator_state
            .commit_template(&self.config, proposal)?;
        let authorization = self.signing_authorization(
            CoordinatedSigningPhase::Commit,
            template.producer_round,
            template.signing_hash()?,
        )?;
        let commit = if let Some(recorded) = self
            .signing_authority
            .recorded_coordinated_envelope(&authorization)?
        {
            let commit: CoordinatorCommit = serde_json::from_slice(&recorded.signed_envelope)
                .map_err(|error| format!("decode durable coordinated commit: {error}"))?;
            if commit.signing_hash()? != authorization.subject_hash
                || commit.coordinator_signature != recorded.signature
            {
                return Err(
                    "durable coordinated commit envelope does not match its authorization"
                        .to_string(),
                );
            }
            commit
        } else {
            let mut commit = template;
            commit.coordinator_signature = self
                .signer
                .sign_domain(
                    COORDINATED_COMMIT_DOMAIN,
                    &commit.signing_hash()?.0,
                    &self.local_consensus_key_id,
                )
                .map_err(|error| format!("sign coordinated commit: {error}"))?;
            let envelope = serde_json::to_vec(&commit)
                .map_err(|error| format!("serialize coordinated commit: {error}"))?;
            self.signing_authority.record_coordinated_envelope(
                &authorization,
                &commit.coordinator_signature,
                &envelope,
            )?;
            commit
        };
        let package = CoordinatedCommittedBlockPackage {
            block: block.clone(),
            assignment: assignment.clone(),
            proposal: proposal.clone(),
            coordinator_commit: commit,
        };
        self.finalize_verified_package(package, next_execution_state)?;
        Ok(self
            .finality_store
            .latest(&self.config)?
            .expect("just persisted coordinated finality")
            .package)
    }

    /// Validates and applies a package broadcast by Val1 or relayed by another
    /// authenticated validator. No local signing occurs on this path.
    pub fn accept_committed_package(
        &mut self,
        package: CoordinatedCommittedBlockPackage,
    ) -> Result<CoordinatedRuntimeFinality, String> {
        if package.block.header.height.0 <= self.coordinator_state.last_finalized_height {
            let existing = self
                .finality_store
                .at_height(&self.config, package.block.header.height)?
                .ok_or_else(|| {
                    "coordinated runtime state is finalized beyond a missing durable package"
                        .to_string()
                })?;
            if existing.package != package {
                return Err(
                    "coordinated finality replay conflicts with persisted evidence".to_string(),
                );
            }
            let block_hash = Hash::from_hex(&existing.block_id.0)
                .map_err(|error| format!("coordinated finality block ID is not a hash: {error}"))?;
            return Ok(CoordinatedRuntimeFinality {
                record: existing,
                block_hash,
            });
        }
        self.accept_assignment(&package.assignment)?;
        self.verifier.verify_committed_block_package(&package)?;
        let next_execution_state =
            execute_coordinated_block(&self.execution_state, &package.block)?;
        self.finalize_verified_package(package, next_execution_state)
    }

    /// Handles exactly one authenticated coordinated P2P message. The role
    /// runtime broadcasts or responds with the returned action only after this
    /// method has completed all required signature, execution, and durable
    /// persistence steps.
    pub fn handle_authenticated_message(
        &mut self,
        peer: &AuthenticatedCoordinatedConsensusPeer,
        message: CoordinatedConsensusMessage,
    ) -> Result<CoordinatedRuntimeAction, String> {
        self.verifier.verify_message_sender(peer, &message)?;
        match message {
            CoordinatedConsensusMessage::ProducerAssignment { assignment } => {
                self.accept_assignment(&assignment)?;
                Ok(CoordinatedRuntimeAction::None)
            }
            CoordinatedConsensusMessage::ProposedBlock {
                assignment,
                proposal,
                block,
            } => {
                if !self.is_local_coordinator()
                    || proposal.height <= self.coordinator_state.last_finalized_height
                    // A delayed proposal can only be accepted for Val1's exact
                    // current signed assignment; stale proposals are dropped.
                    || self.pending_assignment() != Some(&assignment)
                {
                    return Ok(CoordinatedRuntimeAction::None);
                }
                let package = self.commit_executed_proposal(&assignment, &proposal, &block)?;
                Ok(CoordinatedRuntimeAction::BroadcastCommitted(package))
            }
            CoordinatedConsensusMessage::CoordinatorCommit { package }
            | CoordinatedConsensusMessage::CommittedBlock { package } => {
                self.accept_committed_package(package)?;
                Ok(CoordinatedRuntimeAction::None)
            }
            CoordinatedConsensusMessage::GetCommittedBlock { height } => {
                let response = match self
                    .finality_store
                    .at_height(&self.config, Height(height))?
                {
                    Some(record) => CoordinatedConsensusMessage::CommittedBlock {
                        package: record.package,
                    },
                    // A requester can legitimately reach the Val1 current tip.
                    // Return an authenticated empty range rather than making
                    // the coordinator fail because no successor is final yet.
                    None => CoordinatedConsensusMessage::CommittedBlockRange {
                        packages: Vec::new(),
                    },
                };
                Ok(CoordinatedRuntimeAction::Respond(response))
            }
            CoordinatedConsensusMessage::GetCommittedBlockRange {
                start_height,
                end_height,
            } => {
                let requested = end_height
                    .checked_sub(start_height)
                    .and_then(|span| span.checked_add(1))
                    .ok_or_else(|| "coordinated finality range overflows".to_string())?;
                if requested > MAX_COORDINATED_CONSENSUS_SYNC_RANGE_BLOCKS as u64 {
                    return Ok(CoordinatedRuntimeAction::None);
                }
                let mut packages = Vec::new();
                for height in start_height..=end_height {
                    let Some(record) = self
                        .finality_store
                        .at_height(&self.config, Height(height))?
                    else {
                        break;
                    };
                    packages.push(record.package);
                }
                Ok(CoordinatedRuntimeAction::Respond(
                    CoordinatedConsensusMessage::CommittedBlockRange { packages },
                ))
            }
            CoordinatedConsensusMessage::CommittedBlockRange { packages } => {
                for package in packages {
                    self.accept_committed_package(package)?;
                }
                Ok(CoordinatedRuntimeAction::None)
            }
        }
    }

    fn finalize_verified_package(
        &mut self,
        package: CoordinatedCommittedBlockPackage,
        next_execution_state: ExecutionState,
    ) -> Result<CoordinatedRuntimeFinality, String> {
        // Durable finality is written before mutating the local in-memory
        // execution tip. A failure leaves nothing eligible for broadcast.
        let record = self
            .finality_store
            .append_verified_finality(&self.config, &package)?;
        let mut candidate_state = self.coordinator_state.clone();
        candidate_state.record_commit(&self.config, package.coordinator_commit.clone())?;
        self.coordinator_state_store
            .persist(&self.config, &candidate_state)?;
        self.coordinator_state = candidate_state;
        self.execution_state = next_execution_state;
        let block_hash = Hash::from_hex(&record.block_id.0)
            .map_err(|error| format!("coordinated finality block ID is not a hash: {error}"))?;
        Ok(CoordinatedRuntimeFinality { record, block_hash })
    }

    fn install_assignment(&mut self, assignment: &ProducerAssignment) -> Result<(), String> {
        let mut candidate_state = self.coordinator_state.clone();
        candidate_state.install_verified_assignment(&self.config, assignment)?;
        self.coordinator_state_store
            .persist(&self.config, &candidate_state)?;
        self.coordinator_state = candidate_state;
        Ok(())
    }

    fn signing_authorization(
        &self,
        phase: CoordinatedSigningPhase,
        producer_round: u64,
        subject_hash: Hash,
    ) -> Result<CoordinatedSigningAuthorization, String> {
        Ok(CoordinatedSigningAuthorization {
            chain_id: ChainId::synergy_testnet_v3(),
            network_id: NetworkId::synergy_testnet_v3(),
            consensus_version: self.config.consensus_version.clone(),
            epoch: self.verifier.epoch(),
            height: Height(self.coordinator_state.next_height()),
            producer_round: Round(producer_round),
            coordinator_id: self.local_validator_id.clone(),
            key_id: self.local_consensus_key_id.clone(),
            phase,
            subject_hash,
        })
    }

    fn require_local_coordinator(&self) -> Result<(), String> {
        if self.is_local_coordinator() {
            Ok(())
        } else {
            Err("only the configured Val1 coordinator may issue or commit blocks".to_string())
        }
    }
}

/// Reconstructs a lagging coordinator-state file from separately durable,
/// cryptographically verified finality packages. Each package carries the
/// signed assignment that proves any skipped producer turns, so recovery
/// never invents a coordinator decision or recreates a signature.
fn reconcile_coordinator_state(
    config: &CoordinatedRoundRobinConfig,
    verifier: &CoordinatedConsensusVerifier,
    state_store: &CoordinatorStateStore,
    state: &mut CoordinatorState,
    records: &[CoordinatedFinalityRecord],
    first_coordinated_height: Height,
) -> Result<(), String> {
    let Some(latest) = records.last() else {
        if state.last_finalized_height >= first_coordinated_height.0 {
            return Err(
                "coordinated state is ahead of its separate finality store; refusing recovery"
                    .to_string(),
            );
        }
        return Ok(());
    };
    let state_height = state.last_finalized_height;
    if state_height > latest.height.0 {
        return Err(
            "coordinated state is ahead of its separate finality store; refusing recovery"
                .to_string(),
        );
    }
    let latest_hash = Hash::from_hex(&latest.block_id.0)
        .map_err(|error| format!("coordinated finality block ID is not a hash: {error}"))?;
    let latest_reference = latest.package.coordinator_commit.signing_hash()?;
    if state.last_finalized_height == latest.height.0 {
        if state.last_finalized_block_hash != latest_hash
            || state.last_finality_reference != latest_reference
        {
            return Err(
                "coordinated state and separate finality store disagree; refusing recovery"
                    .to_string(),
            );
        }
        return Ok(());
    }
    let mut repaired = state.clone();
    let mut expected_height = repaired.next_height();
    let first_missing = records
        .iter()
        .position(|record| record.height.0 == expected_height)
        .ok_or_else(|| {
            "coordinated finality recovery has no record for the local successor height".to_string()
        })?;
    for record in &records[first_missing..] {
        if record.height.0 != expected_height {
            return Err(
                "coordinated finality recovery has a gap after the local coordinator state"
                    .to_string(),
            );
        }
        verifier.verify_committed_block_package(&record.package)?;
        repaired.install_verified_assignment(config, &record.package.assignment)?;
        if !repaired.record_commit(config, record.package.coordinator_commit.clone())? {
            return Err(
                "coordinated recovery found an already-recorded commit with an inconsistent finality tip"
                    .to_string(),
            );
        }
        expected_height = repaired.next_height();
    }
    if repaired.last_finalized_block_hash != latest_hash
        || repaired.last_finality_reference != latest_reference
    {
        return Err("coordinated recovery produced an unexpected finality tip".to_string());
    }
    state_store.persist(config, &repaired)?;
    *state = repaired;
    Ok(())
}

/// Replays already cryptographically verified finality records only when the
/// supplied execution snapshot matches a durable boundary. This makes a
/// restart catch up from the migration anchor or a previous durable tip while
/// refusing a snapshot whose provenance cannot be proven from the finality
/// store.
fn replay_finality_from_execution_state(
    mut execution_state: ExecutionState,
    records: &[CoordinatedFinalityRecord],
    migration_parent_state_root: Hash,
) -> Result<ExecutionState, String> {
    let supplied_root = compute_state_root_after(&execution_state)?;
    let start_index = if supplied_root == migration_parent_state_root {
        0
    } else if let Some(index) = records
        .iter()
        .rposition(|record| record.package.block.header.state_root_after == supplied_root)
    {
        index.saturating_add(1)
    } else {
        return Err(
            "coordinated runtime execution state is not anchored in durable coordinated finality"
                .to_string(),
        );
    };
    for record in records.iter().skip(start_index) {
        execution_state = execute_coordinated_block(&execution_state, &record.package.block)?;
    }
    Ok(execution_state)
}

fn execute_coordinated_block(
    state: &ExecutionState,
    block: &Block,
) -> Result<ExecutionState, String> {
    if compute_state_root_after(state)? != block.header.state_root_before {
        return Err(
            "coordinated block does not extend the supplied execution-state root".to_string(),
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
        return Err("coordinated block execution roots do not match its header".to_string());
    }
    Ok(execution.state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::coordinated_round_robin::{CoordinatorState, COORDINATED_ROUND_ROBIN_V1};
    use crate::consensus_parameters::ConsensusParameterRoot;
    use crate::crypto::aegis_pqvm::SYNERGY_BLOCK_V1;
    use crate::dag_mempool::compute_tx_order_root;
    use crate::execution::compute_receipt_root;
    use crate::synergy_types::{
        CanonicalSerialize, ClusterId, UmaId, ValidatorRecord, ValidatorStatus,
    };
    use std::time::{SystemTime, UNIX_EPOCH};

    fn hash(label: &str) -> Hash {
        Hash::from_domain_bytes("SYNERGY_COORDINATED_RUNTIME_TEST_V1", label.as_bytes())
    }

    fn config() -> CoordinatedRoundRobinConfig {
        CoordinatedRoundRobinConfig {
            chain_id: 1266,
            network_id: "synergy-testnet-v3".to_string(),
            consensus_version: COORDINATED_ROUND_ROBIN_V1.to_string(),
            coordinator_id: "validator-1".to_string(),
            producer_ids: (2..=6).map(|index| format!("validator-{index}")).collect(),
            target_block_interval_ms: 2_000,
            producer_turn_timeout_ms: 4_000,
        }
    }

    fn fixture() -> CoordinatedRuntime {
        fixture_for_local("validator-1")
    }

    fn fixture_for_local(local_validator_id: &str) -> CoordinatedRuntime {
        let mut signer = AegisPqvmSigner::initialize_required().expect("Aegis signer");
        let mut validators = Vec::new();
        for index in 1..=6 {
            let validator_id = ValidatorId(format!("validator-{index}"));
            let uma_id = UmaId(format!("uma-validator-{index}"));
            let key_id = signer
                .generate_and_register_key(
                    &uma_id.0,
                    vec![crate::synergy_types::AegisPqKeyRole::ConsensusProposer],
                    Epoch(0),
                )
                .expect("register consensus key");
            let public_key = signer.public_key_record(&key_id).expect("public key");
            validators.push(ValidatorRecord {
                validator_id,
                validator_uma_id: uma_id,
                consensus_public_key: public_key.clone(),
                peer_public_key: public_key.clone(),
                operator_public_key: public_key,
                voting_weight: 1,
                status: ValidatorStatus::Active,
                cluster_id: ClusterId(0),
                activation_epoch: Epoch(0),
            });
        }
        let validator_set = ValidatorSet {
            epoch: Epoch(0),
            validators,
        };
        let execution_state = ExecutionState::new();
        let state_root = compute_state_root_after(&execution_state).expect("state root");
        let state = CoordinatorState::from_migration_anchor(
            41,
            hash("migration-parent"),
            hash("migration-proof"),
        )
        .expect("migration state");
        let unique = format!(
            "coordinated-runtime-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        );
        let state_store = CoordinatorStateStore::at_path(crate::utils::test_temp_root(format!(
            "{unique}/coordinator-state.json"
        )))
        .expect("state store");
        let finality_store = CoordinatedFinalityStore::at_path(
            crate::utils::test_temp_root(format!("{unique}/finality.json")),
            state.last_finalized_block_hash,
            state_root,
            Height(42),
        )
        .expect("finality store");
        let authority = DurableConsensusSigningAuthority::at_path(crate::utils::test_temp_root(
            format!("{unique}/signing-authority.json"),
        ));
        CoordinatedRuntime::new(
            config(),
            &validator_set,
            signer.verifier(),
            ValidatorId(local_validator_id.to_string()),
            signer,
            authority,
            state_store,
            state,
            finality_store,
            execution_state,
        )
        .expect("coordinated runtime")
    }

    fn signed_empty_proposal(
        runtime: &mut CoordinatedRuntime,
        assignment: &ProducerAssignment,
    ) -> (CoordinatedProposal, Block) {
        let producer = runtime
            .verifier
            .validator_record(&assignment.assigned_producer_id)
            .expect("configured producer")
            .clone();
        let state_root = compute_state_root_after(runtime.execution_state()).expect("state root");
        let transaction_root = compute_tx_order_root(&[]).expect("empty transaction root");
        let receipt_root = compute_receipt_root(&[]).expect("empty receipt root");
        let mut block = Block {
            header: crate::synergy_types::BlockHeader {
                version: 1,
                chain_id: ChainId::synergy_testnet_v3(),
                network_id: NetworkId::synergy_testnet_v3(),
                protocol_version: COORDINATED_ROUND_ROBIN_V1.to_string(),
                height: Height(assignment.height),
                round: Round(assignment.producer_round),
                epoch: Epoch(assignment.epoch),
                cluster_id: ClusterId(0),
                height_context_root: hash("coordinated-height-context"),
                parent_block_hash: assignment.parent_block_hash,
                parent_state_root: state_root,
                last_finalized_qc_hash: Hash::zero(),
                proposer_validator_id: producer.validator_id.clone(),
                proposer_uma_id: producer.validator_uma_id.clone(),
                proposer_key_id: producer.consensus_public_key.key_id.clone(),
                active_validator_set_hash: hash("active-validators"),
                eligible_validator_set_hash: hash("eligible-validators"),
                validator_consensus_key_root: hash("consensus-keys"),
                frozen_bonded_weight_root: hash("bonded-weight"),
                cluster_schedule_version: "coordinated-round-robin-v1".to_string(),
                cluster_map_hash: hash("cluster-map"),
                assigned_cluster_membership_root: hash("cluster-membership"),
                assigned_cluster_validator_count: 6,
                assigned_cluster_total_voting_weight: 6,
                proposer_schedule_hash: hash("strict-rotation"),
                protocol_config_hash: ConsensusParameterRoot::from_canonical_manifest_bytes(
                    b"coordinated-runtime-test",
                ),
                cryptographic_profile_root: hash("cryptographic-profile"),
                dag_frontier_root: coordinated_dag_frontier_root(
                    assignment.parent_block_hash,
                    transaction_root,
                    Hash::zero(),
                ),
                tx_order_root: transaction_root,
                tx_count: 0,
                protected_batch: None,
                evidence_root: assignment.prior_finality_reference,
                state_root_before: state_root,
                state_root_after: state_root,
                receipt_root,
                app_version: 1,
                execution_version: 1,
                dag_version: 1,
                aegis_pqvm_version: "aegis-pqvm".to_string(),
                timestamp_ms_consensus_bounded: assignment.intended_block_timestamp_ms,
            },
            transactions: Vec::new(),
            proposer_signature: crate::synergy_types::AegisPqSignature {
                algorithm: String::new(),
                signature_bytes: Vec::new(),
            },
        };
        block.proposer_signature = runtime
            .signer
            .sign_domain(
                SYNERGY_BLOCK_V1,
                &block
                    .header
                    .canonical_bytes()
                    .expect("canonical block header"),
                &producer.consensus_public_key.key_id,
            )
            .expect("producer signs block");
        let proposal = CoordinatedProposal {
            epoch: assignment.epoch,
            height: assignment.height,
            producer_round: assignment.producer_round,
            parent_block_hash: assignment.parent_block_hash,
            prior_finality_reference: assignment.prior_finality_reference,
            block_hash: Hash::from_hex(&block.block_id().expect("block ID").0).expect("block hash"),
            transaction_root,
            transaction_admission_root: Hash::zero(),
            transaction_admissions: Vec::new(),
            receipt_root,
            state_root,
            producer_id: assignment.assigned_producer_id.clone(),
            assignment_hash: assignment.signing_hash().expect("assignment hash"),
            producer_signature: block.proposer_signature.clone(),
        };
        (proposal, block)
    }

    fn block_build_context() -> CoordinatedBlockBuildContext {
        CoordinatedBlockBuildContext {
            genesis_anchor: hash("genesis-anchor"),
            genesis_timestamp_ms: 1_000,
            protocol_config_hash: ConsensusParameterRoot::from_canonical_manifest_bytes(
                b"coordinated-runtime-test-parameters",
            ),
            cryptographic_profile_root: hash("cryptographic-profile"),
        }
    }

    fn authenticated_peer(
        runtime: &CoordinatedRuntime,
        validator_id: &str,
    ) -> AuthenticatedCoordinatedConsensusPeer {
        let validator = runtime
            .verifier
            .validator_record(validator_id)
            .expect("configured validator");
        AuthenticatedCoordinatedConsensusPeer {
            validator_id: validator.validator_id.clone(),
            validator_uma_id: validator.validator_uma_id.clone(),
            consensus_key_id: validator.consensus_public_key.key_id.clone(),
        }
    }

    #[test]
    fn coordinator_signs_and_persists_the_first_assignment() {
        let mut runtime = fixture();
        let assignment = runtime
            .issue_signed_assignment(2_000)
            .expect("Val1 signs assignment");
        assert_eq!(assignment.height, 42);
        assert_eq!(assignment.assigned_producer_id, "validator-2");
        assert!(assignment.coordinator_signature.is_present());
        assert_eq!(
            runtime.coordinator_state().pending_assignment.as_ref(),
            Some(&assignment)
        );
    }

    #[test]
    fn assigned_producer_journals_and_replays_the_exact_signed_block() {
        let mut producer = fixture_for_local("validator-2");
        let mut assignment = producer
            .coordinator_state
            .assignment_template(&producer.config, producer.verifier.epoch().0, 2_000)
            .expect("build Val1 assignment subject");
        let coordinator_key = producer
            .verifier
            .validator_record("validator-1")
            .expect("configured coordinator")
            .consensus_public_key
            .key_id
            .clone();
        assignment.coordinator_signature = producer
            .signer
            .sign_domain(
                COORDINATED_ASSIGNMENT_DOMAIN,
                &assignment.signing_hash().expect("assignment hash").0,
                &coordinator_key,
            )
            .expect("Val1 signs the assignment with the finalized key");
        let (_, mut unsigned_block) = signed_empty_proposal(&mut producer, &assignment);
        unsigned_block.proposer_signature = crate::synergy_types::AegisPqSignature {
            algorithm: String::new(),
            signature_bytes: Vec::new(),
        };

        let (proposal, signed_block) = producer
            .sign_assigned_producer_block(&assignment, unsigned_block.clone(), Vec::new())
            .expect("assigned producer signs through the durable journal");
        assert_eq!(proposal.producer_id, "validator-2");
        assert!(signed_block.proposer_signature.is_present());
        producer
            .verifier
            .verify_producer_block(&assignment, &proposal, &signed_block)
            .expect("journaled producer block remains independently verifiable");

        let (replayed_proposal, replayed_block) = producer
            .sign_assigned_producer_block(&assignment, unsigned_block, Vec::new())
            .expect("producer restart path reuses the exact durable block");
        assert_eq!(replayed_proposal, proposal);
        assert_eq!(replayed_block, signed_block);
    }

    #[test]
    fn assigned_producer_builds_the_genesis_scheduled_empty_block() {
        let mut producer = fixture_for_local("validator-2");
        let context = block_build_context();
        let timestamp = producer
            .next_assignment_timestamp(&context)
            .expect("derive Genesis-bound assignment timestamp");
        let mut assignment = producer
            .coordinator_state
            .assignment_template(&producer.config, producer.verifier.epoch().0, timestamp)
            .expect("build Val1 assignment subject");
        let coordinator_key = producer
            .verifier
            .validator_record("validator-1")
            .expect("configured coordinator")
            .consensus_public_key
            .key_id
            .clone();
        assignment.coordinator_signature = producer
            .signer
            .sign_domain(
                COORDINATED_ASSIGNMENT_DOMAIN,
                &assignment.signing_hash().expect("assignment hash").0,
                &coordinator_key,
            )
            .expect("Val1 signs the assignment with the finalized key");
        producer
            .accept_assignment(&assignment)
            .expect("install signed producer assignment");

        let block = producer
            .build_empty_assigned_block(&assignment, &context)
            .expect("build canonical empty block only after an empty admission source");
        assert_eq!(block.header.height, Height(42));
        assert_eq!(block.header.round, Round(0));
        assert_eq!(block.header.timestamp_ms_consensus_bounded, timestamp);
        assert_eq!(block.header.tx_count, 0);
        assert!(block.transactions.is_empty());
        assert!(block.header.last_finalized_qc_hash.is_zero());

        let (proposal, signed) = producer
            .sign_assigned_producer_block(&assignment, block, Vec::new())
            .expect("sign the exact built block through the durable producer journal");
        producer
            .verifier
            .verify_producer_block(&assignment, &proposal, &signed)
            .expect("every validator can verify the built producer block");
    }

    #[test]
    fn assigned_producer_builds_and_all_validators_verify_an_admitted_user_transaction() {
        let mut producer = fixture_for_local("validator-2");
        let context = block_build_context();
        let timestamp = producer
            .next_assignment_timestamp(&context)
            .expect("derive Genesis-bound assignment timestamp");
        let mut assignment = producer
            .coordinator_state
            .assignment_template(&producer.config, producer.verifier.epoch().0, timestamp)
            .expect("build Val1 assignment subject");
        let coordinator_key = producer
            .verifier
            .validator_record("validator-1")
            .expect("configured coordinator")
            .consensus_public_key
            .key_id
            .clone();
        assignment.coordinator_signature = producer
            .signer
            .sign_domain(
                COORDINATED_ASSIGNMENT_DOMAIN,
                &assignment.signing_hash().expect("assignment hash").0,
                &coordinator_key,
            )
            .expect("Val1 signs the assignment with the finalized key");
        producer
            .accept_assignment(&assignment)
            .expect("install signed producer assignment");

        let report = crate::aegis_tx_tool::sign_with_new_aegis_transaction_key(
            crate::aegis_tx_tool::AegisTxBuildOptions {
                ttl_height: assignment.height.saturating_add(10),
                ..crate::aegis_tx_tool::AegisTxBuildOptions::default()
            },
        )
        .expect("create a signed user transaction");
        producer.execution_state = ExecutionState::new()
            .with_balance(&report.transaction.sender_uma_or_account, 1_000_000);
        let admissions = vec![report.submission_envelope];

        let block = producer
            .build_assigned_block(&assignment, &context, &admissions)
            .expect("build an admitted coordinated user block");
        assert_eq!(block.header.tx_count, 1);
        assert_eq!(block.transactions, vec![report.transaction]);
        let (proposal, signed) = producer
            .sign_assigned_producer_block(&assignment, block, admissions)
            .expect("sign the admitted block through the durable producer journal");
        assert!(!proposal.transaction_admission_root.is_zero());
        producer
            .verifier
            .verify_producer_block(&assignment, &proposal, &signed)
            .expect("every validator independently verifies the user witness and block");
    }

    #[test]
    fn lagging_validator_defers_future_assignment_until_finality_catches_up() {
        let mut coordinator = fixture();
        let first = coordinator
            .issue_signed_assignment(2_000)
            .expect("Val1 signs the initial assignment");
        let (proposal, block) = signed_empty_proposal(&mut coordinator, &first);
        let producer_peer = authenticated_peer(&coordinator, "validator-2");
        let action = coordinator
            .handle_authenticated_message(
                &producer_peer,
                CoordinatedConsensusMessage::ProposedBlock {
                    assignment: first,
                    proposal,
                    block,
                },
            )
            .expect("Val1 commits the initial package");
        let CoordinatedRuntimeAction::BroadcastCommitted(package) = action else {
            panic!("Val1 must broadcast the committed package");
        };
        let future = coordinator
            .issue_signed_assignment(4_000)
            .expect("Val1 signs the successor assignment");

        coordinator.coordinator_state = CoordinatorState::from_migration_anchor(
            41,
            hash("migration-parent"),
            hash("migration-proof"),
        )
        .expect("recreate the lagging durable state");
        coordinator
            .accept_assignment(&future)
            .expect("a verified future assignment is deferred while finality catches up");
        assert_eq!(coordinator.coordinator_state().last_finalized_height, 41);
        assert!(coordinator.coordinator_state().pending_assignment.is_none());

        let mut repaired = CoordinatorState::from_migration_anchor(
            41,
            hash("migration-parent"),
            hash("migration-proof"),
        )
        .expect("recreate the signed predecessor state");
        repaired
            .install_verified_assignment(&coordinator.config, &package.assignment)
            .expect("install the exact signed predecessor assignment");
        assert!(repaired
            .record_commit(&coordinator.config, package.coordinator_commit.clone())
            .expect("commit the exact signed predecessor finality"));
        coordinator.coordinator_state = repaired;
        coordinator
            .accept_assignment(&future)
            .expect("the deferred assignment installs after its predecessor finality");
        assert_eq!(
            coordinator.coordinator_state().pending_assignment.as_ref(),
            Some(&future)
        );
    }

    #[test]
    fn timeout_replacement_uses_the_same_height_and_next_scheduled_round() {
        let mut coordinator = fixture();
        let context = block_build_context();
        let first_timestamp = coordinator
            .next_assignment_timestamp(&context)
            .expect("derive first assignment timestamp");
        let first = coordinator
            .issue_signed_assignment(first_timestamp)
            .expect("issue the initial assignment");
        let replacement_timestamp = coordinator
            .timeout_replacement_assignment_timestamp(&context)
            .expect("derive the next producer-round timestamp before advancing state");
        let replacement = coordinator
            .skip_producer_turn_and_issue_assignment("producer timeout", replacement_timestamp)
            .expect("replace the missed producer without advancing height");

        assert_eq!(replacement.height, first.height);
        assert_eq!(replacement.producer_round, first.producer_round + 1);
        assert_eq!(replacement.assigned_producer_id, "validator-3");
        assert!(replacement.intended_block_timestamp_ms > first.intended_block_timestamp_ms);
        assert_eq!(
            replacement.intended_block_timestamp_ms,
            replacement_timestamp
        );
    }

    #[test]
    fn coordinator_finalizes_signed_block_and_repairs_a_persisted_finality_gap() {
        let mut runtime = fixture();
        let assignment = runtime
            .issue_signed_assignment(2_000)
            .expect("Val1 signs assignment");
        let pending_state = runtime.coordinator_state().clone();
        let (proposal, block) = signed_empty_proposal(&mut runtime, &assignment);
        let producer_peer = authenticated_peer(&runtime, "validator-2");
        let action = runtime
            .handle_authenticated_message(
                &producer_peer,
                CoordinatedConsensusMessage::ProposedBlock {
                    assignment: assignment.clone(),
                    proposal,
                    block,
                },
            )
            .expect("Val1 verifies, executes, and commits the producer block");
        let CoordinatedRuntimeAction::BroadcastCommitted(package) = action else {
            panic!("coordinator must return the durable committed package for broadcast");
        };
        assert_eq!(package.block.header.height, Height(42));
        assert_eq!(runtime.coordinator_state().last_finalized_height, 42);
        assert!(runtime.coordinator_state().pending_assignment.is_none());
        let replay = runtime
            .accept_committed_package(package.clone())
            .expect("the exact committed package is idempotent");
        assert_eq!(replay.record.package, package);
        let requester = authenticated_peer(&runtime, "validator-3");
        let response = runtime
            .handle_authenticated_message(
                &requester,
                CoordinatedConsensusMessage::GetCommittedBlock { height: 42 },
            )
            .expect("any authenticated validator can request durable finality");
        assert!(matches!(
            response,
            CoordinatedRuntimeAction::Respond(CoordinatedConsensusMessage::CommittedBlock {
                package: response_package
            }) if response_package == package
        ));
        let unavailable = runtime
            .handle_authenticated_message(
                &requester,
                CoordinatedConsensusMessage::GetCommittedBlock { height: 43 },
            )
            .expect("a request at the finalized tip is not fatal");
        assert!(matches!(
            unavailable,
            CoordinatedRuntimeAction::Respond(CoordinatedConsensusMessage::CommittedBlockRange {
                packages
            }) if packages.is_empty()
        ));
        let next_assignment = runtime
            .issue_signed_assignment(4_000)
            .expect("Val1 signs the successor assignment");
        assert_eq!(next_assignment.assigned_producer_id, "validator-3");
        let (next_proposal, next_block) = signed_empty_proposal(&mut runtime, &next_assignment);
        let next_producer_peer = authenticated_peer(&runtime, "validator-3");
        let next_action = runtime
            .handle_authenticated_message(
                &next_producer_peer,
                CoordinatedConsensusMessage::ProposedBlock {
                    assignment: next_assignment,
                    proposal: next_proposal,
                    block: next_block,
                },
            )
            .expect("Val1 commits the successor block");
        let CoordinatedRuntimeAction::BroadcastCommitted(next_package) = next_action else {
            panic!("coordinator must return the second durable package for broadcast");
        };
        assert_eq!(runtime.coordinator_state().last_finalized_height, 43);

        // Model a crash after separate finality was fsynced but before the
        // coordinator state replacement. The pending signed assignment gives
        // recovery the exact, non-invented subject needed to repair one tip.
        runtime
            .coordinator_state_store
            .persist(&runtime.config, &pending_state)
            .expect("restore pre-commit state for recovery test");
        let CoordinatedRuntime {
            config,
            verifier,
            local_validator_id,
            signer,
            signing_authority,
            coordinator_state_store,
            finality_store,
            ..
        } = runtime;
        let validator_set = verifier.validator_set();
        let migration_state = CoordinatorState::from_migration_anchor(
            pending_state.last_finalized_height,
            pending_state.last_finalized_block_hash,
            pending_state.last_finality_reference,
        )
        .expect("migration anchor");
        let restored_verifier = signer.verifier();
        let restored = CoordinatedRuntime::new(
            config,
            &validator_set,
            restored_verifier,
            local_validator_id,
            signer,
            signing_authority,
            coordinator_state_store,
            migration_state,
            finality_store,
            ExecutionState::new(),
        )
        .expect("recover one persisted coordinated finality record");
        assert_eq!(restored.coordinator_state().last_finalized_height, 43);
        assert_eq!(
            restored.coordinator_state().last_finalized_block_hash,
            next_package.coordinator_commit.block_hash
        );
    }
}
