use crate::consensus::signing_authority::{
    ConsensusSigningAuthorization, ConsensusSigningPhase, DurableConsensusSigningAuthority,
    SafetyHaltIncident, SafetyHaltKind,
};
use crate::crypto::aegis_pqvm::{AegisPqvmSigner, AegisPqvmVerifier, SYNERGY_BLOCK_V1};
use crate::dag_mempool::compute_tx_order_root;
#[cfg(test)]
use crate::dag_mempool::DagMempool;
use crate::etdag::{EtdagDigest, EtdagParameters, ProtectedBlockInput, TargetAdmissionContext};
use crate::execution::{execute_block, ExecutionState};
#[cfg(test)]
use crate::synergy_types::Transaction;
use crate::synergy_types::{
    AegisPqKeyRole, AegisPqSignature, Block, BlockHeader, BlockId, CanonicalSerialize, ClusterId,
    ClusterMap, Epoch, Hash, Height, HeightConsensusContext, ProtocolConfig, QuorumCertificate,
    Round, TimeoutCertificate, ValidationCertificate, ValidatorRecord, ValidatorSet,
    ValidatorStatus, Vote, VotePhase,
};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ConsensusPhase {
    Idle,
    WaitingForProposal,
    ProposingBlock,
    ReceivedProposal,
    ValidatingProposal,
    Voting,
    CollectingVotes,
    FormingQc,
    FinalizingBlock,
    Finalized,
    ViewChange,
    TimeoutWaitingForProposer,
}

#[derive(Debug, Clone)]
pub struct LocalConsensusContext {
    pub height_context: HeightConsensusContext,
    pub latest_finalized_height: Height,
    pub latest_finalized_block_hash: Hash,
    pub latest_finalized_state_root: Hash,
    pub round: Round,
    pub evidence_root: Hash,
    pub app_version: u32,
    pub execution_version: u32,
    pub dag_version: u32,
    pub aegis_pqvm_version: String,
}

pub struct ProofOfSynergyBft {
    /// The coordinator owns a verifier snapshot built from the finalized
    /// validator lifecycle.  This prevents a long-lived consensus worker from
    /// borrowing mutable/global key state and makes its cryptographic authority
    /// explicit at startup.
    pub verifier: AegisPqvmVerifier,
    pub validator_set: ValidatorSet,
    pub cluster_map: ClusterMap,
    pub protocol_config: ProtocolConfig,
    pub phase: ConsensusPhase,
    pub signing_authority: DurableConsensusSigningAuthority,
    observed_qcs: BTreeMap<(Height, Epoch, ClusterId, Hash), (BlockId, Hash)>,
    observed_bocs: BTreeMap<(Height, Epoch, ClusterId, Hash), (EtdagDigest, Hash)>,
    authorized_rounds: BTreeMap<(Height, Hash), Round>,
    required_carry_forward: BTreeMap<(Height, Hash, Round), BlockId>,
}

/// Selects which evidence authorizes a core proposal's `header.round`.
///
/// `authorized_rounds` is live, process-local consensus state: it is only ever
/// written by [`ProofOfSynergyBft::advance_round_after_tc`]. A timeout
/// certificate is an ephemeral liveness artifact and is deliberately not part
/// of a durable [`crate::consensus::typed_finality_store::TypedFinalityRecord`],
/// so a non-signing observer replaying finalized history can never populate it.
/// Applying the live check to a durable record therefore rejects every record
/// whose round is greater than zero, regardless of validity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoundAuthoritySource {
    /// A round transition must already have been authorized locally by a
    /// verified timeout certificate. Required on every signing path.
    LiveTimeoutCertificate,
    /// The round is authorized transitively by the finalized quorum
    /// certificate that the caller verifies for this same record.
    ///
    /// This is sound only because every other round-dependent binding is still
    /// enforced against `header.round` by
    /// [`ProofOfSynergyBft::validate_finalized_core_record`]:
    ///
    /// * the header's proposer must be the scheduled proposer *for that exact
    ///   round* (`proposer_for(height_context, block.header.round)`);
    /// * the proposer's `ConsensusProposer` signature covers
    ///   `block.header.canonical_bytes()`, which includes `round`, so a forged
    ///   round requires forging that validator's ML-DSA-65 signature;
    /// * a supermajority `VotePhase::Finality` quorum certificate exists for the
    ///   candidate, meaning an honest supermajority each ran the live
    ///   `LiveTimeoutCertificate` check before voting;
    /// * the successor record's `parent_block_hash` commits to this header's
    ///   full hash, so a tampered round breaks forward chain linkage.
    ///
    /// Note that `candidate_id()` intentionally zeroes `round`, so the quorum
    /// certificate alone does not bind it. The proposer-schedule and proposer
    /// signature checks above are what make this variant safe.
    FinalizedQuorumCertificate,
}

impl ProofOfSynergyBft {
    pub fn new(
        verifier: &AegisPqvmVerifier,
        validator_set: ValidatorSet,
        cluster_map: ClusterMap,
        protocol_config: ProtocolConfig,
    ) -> Self {
        // `cfg!(test)` is a runtime boolean: both arms are compiled in every
        // build, so the non-test library still had to resolve the
        // `#[cfg(test)]`-only `utils::test_temp_root` and did not compile at
        // all. Conditional *compilation* is what was meant here.
        #[cfg(test)]
        let signing_authority =
            DurableConsensusSigningAuthority::at_path(crate::utils::test_temp_root(format!(
                "synergy-posy-signing-{}-{:p}.json",
                std::process::id(),
                verifier
            )));
        #[cfg(not(test))]
        let signing_authority = DurableConsensusSigningAuthority::process_wide();
        Self::new_with_signing_authority(
            verifier.clone(),
            validator_set,
            cluster_map,
            protocol_config,
            signing_authority,
        )
    }

    pub fn new_with_signing_authority(
        verifier: AegisPqvmVerifier,
        validator_set: ValidatorSet,
        cluster_map: ClusterMap,
        protocol_config: ProtocolConfig,
        signing_authority: DurableConsensusSigningAuthority,
    ) -> Self {
        Self {
            verifier,
            validator_set,
            cluster_map,
            protocol_config,
            phase: ConsensusPhase::Idle,
            signing_authority,
            observed_qcs: BTreeMap::new(),
            observed_bocs: BTreeMap::new(),
            authorized_rounds: BTreeMap::new(),
            required_carry_forward: BTreeMap::new(),
        }
    }

    /// Replaces consensus authority only after a separately verified epoch
    /// transition.  All height-local vote/QC observations are invalid across
    /// a topology change and must not survive into the new epoch.
    pub fn install_verified_epoch_topology(
        &mut self,
        verifier: AegisPqvmVerifier,
        validator_set: ValidatorSet,
        cluster_map: ClusterMap,
    ) -> Result<(), String> {
        validator_set.validate_unique_validator_and_key_ids()?;
        let active_set = validator_set.active_for_epoch(validator_set.epoch);
        if active_set.validators.is_empty() {
            return Err("verified epoch topology has no active validators".to_string());
        }
        cluster_map.validate_complete_balanced_assignment(&active_set)?;
        self.verifier = verifier;
        self.validator_set = validator_set;
        self.cluster_map = cluster_map;
        self.phase = ConsensusPhase::Idle;
        self.observed_qcs.clear();
        self.observed_bocs.clear();
        self.authorized_rounds.clear();
        self.required_carry_forward.clear();
        Ok(())
    }

    pub fn proposer_for(
        &self,
        context: &HeightConsensusContext,
        round: Round,
    ) -> Result<ValidatorRecord, String> {
        context.validate_against(
            &self.validator_set,
            &self.cluster_map,
            &self.protocol_config,
        )?;
        let proposer_id = context.authorized_proposer(round)?;
        self.validator_set
            .validators
            .iter()
            .find(|validator| &validator.validator_id == proposer_id)
            .cloned()
            .ok_or_else(|| "authorized proposer is missing from validator set".to_string())
    }

    #[cfg(test)]
    pub fn propose_block(
        &mut self,
        signer: &mut AegisPqvmSigner,
        proposer: &ValidatorRecord,
        transactions: Vec<Transaction>,
        context: &LocalConsensusContext,
        state: &ExecutionState,
        dag_frontier_root: Hash,
    ) -> Result<Block, String> {
        self.phase = ConsensusPhase::ProposingBlock;
        self.ensure_testnet_context(context)?;
        self.require_authorized_round(&context.height_context, context.round)?;
        let scheduled = self.proposer_for(&context.height_context, context.round)?;
        if scheduled.validator_id != proposer.validator_id {
            return Err("wrong proposer for height/round/cluster".to_string());
        }
        if proposer.status != ValidatorStatus::Active {
            return Err("proposer is not ACTIVE".to_string());
        }
        if !signer.registry.key_is_active_for_epoch(
            &proposer.validator_uma_id.0,
            &proposer.consensus_public_key.key_id,
            context.height_context.epoch,
            AegisPqKeyRole::ConsensusProposer,
        ) {
            return Err("proposer key is not active for consensus proposer role".to_string());
        }
        let ordered_tx_ids = transactions
            .iter()
            .map(|tx| {
                Ok(crate::synergy_types::TxId::from_hash(
                    Hash::from_domain_bytes("SYNERGY_EXECUTION_TX_ID_V1", &tx.canonical_bytes()?),
                ))
            })
            .collect::<Result<Vec<_>, String>>()?;
        let tx_order_root = compute_tx_order_root(&ordered_tx_ids)?;
        let mut block = Block {
            header: BlockHeader {
                version: 1,
                chain_id: context.height_context.chain_id,
                network_id: context.height_context.network_id.clone(),
                protocol_version: context.height_context.protocol_version.clone(),
                height: context.height_context.height,
                round: context.round,
                epoch: context.height_context.epoch,
                cluster_id: context.height_context.assigned_cluster_id,
                height_context_root: context.height_context.root()?,
                parent_block_hash: context.latest_finalized_block_hash,
                parent_state_root: context.latest_finalized_state_root,
                last_finalized_qc_hash: context
                    .height_context
                    .prior_finalized_qc_or_transition_root,
                proposer_validator_id: proposer.validator_id.clone(),
                proposer_uma_id: proposer.validator_uma_id.clone(),
                proposer_key_id: proposer.consensus_public_key.key_id.clone(),
                active_validator_set_hash: context.height_context.active_validator_set_root,
                eligible_validator_set_hash: context
                    .height_context
                    .assigned_cluster_membership_root,
                validator_consensus_key_root: context.height_context.validator_consensus_key_root,
                frozen_bonded_weight_root: context.height_context.frozen_bonded_weight_root,
                cluster_schedule_version: context.height_context.cluster_schedule_version.clone(),
                cluster_map_hash: context.height_context.cluster_map_root,
                assigned_cluster_membership_root: context
                    .height_context
                    .assigned_cluster_membership_root,
                assigned_cluster_validator_count: context
                    .height_context
                    .assigned_cluster_validator_count,
                assigned_cluster_total_voting_weight: context
                    .height_context
                    .assigned_cluster_total_voting_weight,
                proposer_schedule_hash: context.height_context.leader_schedule_root,
                protocol_config_hash: context.height_context.consensus_parameter_root,
                cryptographic_profile_root: context.height_context.cryptographic_profile_root,
                dag_frontier_root,
                tx_order_root,
                tx_count: transactions.len() as u64,
                protected_batch: None,
                evidence_root: context.evidence_root,
                state_root_before: context.latest_finalized_state_root,
                state_root_after: Hash::zero(),
                receipt_root: Hash::zero(),
                app_version: context.app_version,
                execution_version: context.execution_version,
                dag_version: context.dag_version,
                aegis_pqvm_version: context.aegis_pqvm_version.clone(),
                timestamp_ms_consensus_bounded: 0,
            },
            transactions,
            proposer_signature: AegisPqSignature {
                algorithm: String::new(),
                signature_bytes: Vec::new(),
            },
        };
        let mut authorized_state = state.clone();
        for transaction in &block.transactions {
            authorized_state.mark_authorized_at(
                transaction,
                block
                    .header
                    .timestamp_ms_consensus_bounded
                    .saturating_div(1_000),
            )?;
        }
        let execution = execute_block(&block, &authorized_state)?;
        block.header.state_root_after = execution.state_root_after;
        block.header.receipt_root = execution.receipt_root;
        self.require_candidate_carry_forward(&context.height_context, context.round, &block)?;
        self.authorize_proposal_before_signature(&block, proposer, &context.height_context)?;
        let header_bytes = block.header.canonical_bytes()?;
        block.proposer_signature = signer
            .sign_domain(
                SYNERGY_BLOCK_V1,
                &header_bytes,
                &proposer.consensus_public_key.key_id,
            )
            .map_err(|error| error.to_string())?;
        Ok(block)
    }

    /// Constructs the only proposal permitted while ETDAG is deferred: an
    /// authenticated, deterministic empty core block.  There is deliberately
    /// no transaction argument here, so no caller can turn this lifecycle
    /// path into a plaintext user-transaction fallback.
    pub fn propose_core_block(
        &mut self,
        signer: &mut AegisPqvmSigner,
        proposer: &ValidatorRecord,
        context: &LocalConsensusContext,
        state: &ExecutionState,
    ) -> Result<Block, String> {
        self.phase = ConsensusPhase::ProposingBlock;
        self.ensure_testnet_context(context)?;
        self.require_authorized_round(&context.height_context, context.round)?;
        let scheduled = self.proposer_for(&context.height_context, context.round)?;
        if scheduled.validator_id != proposer.validator_id {
            return Err("wrong proposer for core height/round/cluster".to_string());
        }
        if proposer.status != ValidatorStatus::Active {
            return Err("core proposal proposer is not ACTIVE".to_string());
        }
        if !signer.registry.key_is_active_for_epoch(
            &proposer.validator_uma_id.0,
            &proposer.consensus_public_key.key_id,
            context.height_context.epoch,
            AegisPqKeyRole::ConsensusProposer,
        ) {
            return Err("core proposal proposer key is not active".to_string());
        }

        let ordered_tx_ids = Vec::<crate::synergy_types::TxId>::new();
        let tx_order_root = compute_tx_order_root(&ordered_tx_ids)?;
        let mut block = Block {
            header: BlockHeader {
                version: 1,
                chain_id: context.height_context.chain_id,
                network_id: context.height_context.network_id.clone(),
                protocol_version: context.height_context.protocol_version.clone(),
                height: context.height_context.height,
                round: context.round,
                epoch: context.height_context.epoch,
                cluster_id: context.height_context.assigned_cluster_id,
                height_context_root: context.height_context.root()?,
                parent_block_hash: context.latest_finalized_block_hash,
                parent_state_root: context.latest_finalized_state_root,
                last_finalized_qc_hash: context
                    .height_context
                    .prior_finalized_qc_or_transition_root,
                proposer_validator_id: proposer.validator_id.clone(),
                proposer_uma_id: proposer.validator_uma_id.clone(),
                proposer_key_id: proposer.consensus_public_key.key_id.clone(),
                active_validator_set_hash: context.height_context.active_validator_set_root,
                eligible_validator_set_hash: context
                    .height_context
                    .assigned_cluster_membership_root,
                validator_consensus_key_root: context.height_context.validator_consensus_key_root,
                frozen_bonded_weight_root: context.height_context.frozen_bonded_weight_root,
                cluster_schedule_version: context.height_context.cluster_schedule_version.clone(),
                cluster_map_hash: context.height_context.cluster_map_root,
                assigned_cluster_membership_root: context
                    .height_context
                    .assigned_cluster_membership_root,
                assigned_cluster_validator_count: context
                    .height_context
                    .assigned_cluster_validator_count,
                assigned_cluster_total_voting_weight: context
                    .height_context
                    .assigned_cluster_total_voting_weight,
                proposer_schedule_hash: context.height_context.leader_schedule_root,
                protocol_config_hash: context.height_context.consensus_parameter_root,
                cryptographic_profile_root: context.height_context.cryptographic_profile_root,
                dag_frontier_root: Self::core_only_dag_frontier(context)?,
                tx_order_root,
                tx_count: 0,
                protected_batch: None,
                evidence_root: context.evidence_root,
                state_root_before: context.latest_finalized_state_root,
                state_root_after: Hash::zero(),
                receipt_root: Hash::zero(),
                app_version: context.app_version,
                execution_version: context.execution_version,
                dag_version: context.dag_version,
                aegis_pqvm_version: context.aegis_pqvm_version.clone(),
                timestamp_ms_consensus_bounded: 0,
            },
            transactions: Vec::new(),
            proposer_signature: AegisPqSignature {
                algorithm: String::new(),
                signature_bytes: Vec::new(),
            },
        };
        let execution = execute_block(&block, state)?;
        block.header.state_root_after = execution.state_root_after;
        block.header.receipt_root = execution.receipt_root;
        self.require_candidate_carry_forward(&context.height_context, context.round, &block)?;
        self.authorize_proposal_before_signature(&block, proposer, &context.height_context)?;
        block.proposer_signature = signer
            .sign_domain(
                SYNERGY_BLOCK_V1,
                &block.header.canonical_bytes()?,
                &proposer.consensus_public_key.key_id,
            )
            .map_err(|error| error.to_string())?;
        Ok(block)
    }

    /// Revalidates the core-only block shape before any vote can be emitted.
    /// This check explicitly rejects all transaction payloads, protected
    /// batches, and ETDAG frontier substitutions.
    pub fn validate_core_proposal(
        &mut self,
        block: &Block,
        context: &LocalConsensusContext,
        state: &ExecutionState,
    ) -> Result<(), String> {
        self.validate_core_proposal_with_round_authority(
            block,
            context,
            state,
            RoundAuthoritySource::LiveTimeoutCertificate,
        )
    }

    /// Validates a durably finalized core record during non-signing recovery.
    ///
    /// This is the same single validation algorithm as
    /// [`Self::validate_core_proposal`] with exactly one difference: the round is
    /// authorized by the record's finalized quorum certificate rather than by
    /// live timeout-certificate state that a replaying observer cannot hold. See
    /// [`RoundAuthoritySource::FinalizedQuorumCertificate`] for the full
    /// soundness argument. Callers **must** independently verify the finality
    /// quorum certificate for the same record.
    pub fn validate_finalized_core_record(
        &mut self,
        block: &Block,
        context: &LocalConsensusContext,
        state: &ExecutionState,
    ) -> Result<(), String> {
        self.validate_core_proposal_with_round_authority(
            block,
            context,
            state,
            RoundAuthoritySource::FinalizedQuorumCertificate,
        )
    }

    fn validate_core_proposal_with_round_authority(
        &mut self,
        block: &Block,
        context: &LocalConsensusContext,
        state: &ExecutionState,
        round_authority: RoundAuthoritySource,
    ) -> Result<(), String> {
        self.phase = ConsensusPhase::ValidatingProposal;
        self.ensure_testnet_context(context)?;
        if round_authority == RoundAuthoritySource::LiveTimeoutCertificate {
            self.require_authorized_round(&context.height_context, block.header.round)?;
        }
        block.header.chain_id.require_testnet_v3()?;
        block.header.network_id.require_testnet_v3()?;
        if block.header.version != 1 {
            return Err("core proposal requires block header version 1".to_string());
        }
        if !block.transactions.is_empty()
            || block.header.tx_count != 0
            || block.header.protected_batch.is_some()
        {
            return Err(
                "core-only proposal must not contain user transactions or a protected batch"
                    .to_string(),
            );
        }
        let height_context = &context.height_context;
        let expected_context_root = height_context.root()?;
        if block.header.height != height_context.height
            || block.header.parent_block_hash != context.latest_finalized_block_hash
            || block.header.state_root_before != context.latest_finalized_state_root
        {
            return Err("core proposal parent/height/state context mismatch".to_string());
        }
        self.require_candidate_carry_forward(height_context, block.header.round, block)?;
        if block.header.protocol_version != height_context.protocol_version
            || block.header.epoch != height_context.epoch
            || block.header.cluster_id != height_context.assigned_cluster_id
            || block.header.height_context_root != expected_context_root
            || block.header.active_validator_set_hash != height_context.active_validator_set_root
            || block.header.eligible_validator_set_hash
                != height_context.assigned_cluster_membership_root
            || block.header.validator_consensus_key_root
                != height_context.validator_consensus_key_root
            || block.header.frozen_bonded_weight_root != height_context.frozen_bonded_weight_root
            || block.header.cluster_schedule_version != height_context.cluster_schedule_version
            || block.header.cluster_map_hash != height_context.cluster_map_root
            || block.header.assigned_cluster_membership_root
                != height_context.assigned_cluster_membership_root
            || block.header.assigned_cluster_validator_count
                != height_context.assigned_cluster_validator_count
            || block.header.assigned_cluster_total_voting_weight
                != height_context.assigned_cluster_total_voting_weight
            || block.header.proposer_schedule_hash != height_context.leader_schedule_root
            || block.header.protocol_config_hash != height_context.consensus_parameter_root
            || block.header.cryptographic_profile_root != height_context.cryptographic_profile_root
            || block.header.last_finalized_qc_hash
                != height_context.prior_finalized_qc_or_transition_root
        {
            return Err("core proposal consensus context mismatch".to_string());
        }
        if block.header.tx_order_root != compute_tx_order_root(&[])?
            || block.header.dag_frontier_root != Self::core_only_dag_frontier(context)?
        {
            return Err("core-only proposal has noncanonical empty-block commitments".to_string());
        }
        let proposer = self
            .validator_set
            .validators
            .iter()
            .find(|record| record.validator_id == block.header.proposer_validator_id)
            .cloned()
            .ok_or_else(|| "core proposal proposer not in validator set".to_string())?;
        let scheduled = self.proposer_for(height_context, block.header.round)?;
        if scheduled.validator_id != proposer.validator_id
            || proposer.status != ValidatorStatus::Active
            || !proposer.is_active_for_epoch(block.header.epoch)
        {
            return Err("core proposal proposer is not authorized".to_string());
        }
        let execution = execute_block(block, state)?;
        if execution.state_root_after != block.header.state_root_after
            || execution.receipt_root != block.header.receipt_root
        {
            return Err("core-only proposal execution roots mismatch".to_string());
        }
        self.verifier
            .verify_domain_signature(
                SYNERGY_BLOCK_V1,
                &block.header.canonical_bytes()?,
                &proposer.validator_uma_id.0,
                &block.header.proposer_key_id,
                block.header.epoch,
                AegisPqKeyRole::ConsensusProposer,
                &block.proposer_signature,
            )
            .map_err(|error| error.to_string())
    }

    fn core_only_dag_frontier(context: &LocalConsensusContext) -> Result<Hash, String> {
        Ok(Hash::from_domain_bytes(
            "SYNERGY_TESTNET_V3_CORE_ONLY_DAG_FRONTIER_V1",
            &context.height_context.root()?.0,
        ))
    }

    pub fn propose_protected_block(
        &mut self,
        signer: &mut AegisPqvmSigner,
        proposer: &ValidatorRecord,
        protected: &ProtectedBlockInput,
        target_context: &TargetAdmissionContext,
        context: &LocalConsensusContext,
        state: &ExecutionState,
        parameters: &EtdagParameters,
    ) -> Result<Block, String> {
        self.phase = ConsensusPhase::ProposingBlock;
        self.ensure_testnet_context(context)?;
        target_context.validate_height_context_compatibility(&context.height_context)?;
        self.require_authorized_round(&context.height_context, context.round)?;
        let scheduled = self.proposer_for(&context.height_context, context.round)?;
        if scheduled.validator_id != proposer.validator_id {
            return Err("wrong proposer for height/round/cluster".to_string());
        }
        if proposer.status != ValidatorStatus::Active {
            return Err("proposer is not ACTIVE".to_string());
        }
        if !signer.registry.key_is_active_for_epoch(
            &proposer.validator_uma_id.0,
            &proposer.consensus_public_key.key_id,
            context.height_context.epoch,
            AegisPqKeyRole::ConsensusProposer,
        ) {
            return Err("proposer key is not active for consensus proposer role".to_string());
        }
        let transactions = protected.verify_and_extract_transactions(
            &self.verifier,
            target_context,
            &self.validator_set,
            &self.cluster_map,
            parameters,
        )?;
        self.observe_valid_boc(protected, target_context)?;
        let ordered_tx_ids = transactions
            .iter()
            .map(|transaction| {
                Ok(crate::synergy_types::TxId::from_hash(
                    Hash::from_domain_bytes(
                        "SYNERGY_EXECUTION_TX_ID_V1",
                        &transaction.canonical_bytes()?,
                    ),
                ))
            })
            .collect::<Result<Vec<_>, String>>()?;
        let tx_order_root = compute_tx_order_root(&ordered_tx_ids)?;
        let dag_frontier_root = Hash::from_domain_bytes(
            "SYNERGY_ETDAG_DAG_CUT_ROOT_V2",
            protected.dcc.candidate.causal_closure_root.0.as_bytes(),
        );
        let mut block = Block {
            header: BlockHeader {
                version: 2,
                chain_id: context.height_context.chain_id,
                network_id: context.height_context.network_id.clone(),
                protocol_version: context.height_context.protocol_version.clone(),
                height: context.height_context.height,
                round: context.round,
                epoch: context.height_context.epoch,
                cluster_id: context.height_context.assigned_cluster_id,
                height_context_root: context.height_context.root()?,
                parent_block_hash: context.latest_finalized_block_hash,
                parent_state_root: context.latest_finalized_state_root,
                last_finalized_qc_hash: context
                    .height_context
                    .prior_finalized_qc_or_transition_root,
                proposer_validator_id: proposer.validator_id.clone(),
                proposer_uma_id: proposer.validator_uma_id.clone(),
                proposer_key_id: proposer.consensus_public_key.key_id.clone(),
                active_validator_set_hash: context.height_context.active_validator_set_root,
                eligible_validator_set_hash: context
                    .height_context
                    .assigned_cluster_membership_root,
                validator_consensus_key_root: context.height_context.validator_consensus_key_root,
                frozen_bonded_weight_root: context.height_context.frozen_bonded_weight_root,
                cluster_schedule_version: context.height_context.cluster_schedule_version.clone(),
                cluster_map_hash: context.height_context.cluster_map_root,
                assigned_cluster_membership_root: context
                    .height_context
                    .assigned_cluster_membership_root,
                assigned_cluster_validator_count: context
                    .height_context
                    .assigned_cluster_validator_count,
                assigned_cluster_total_voting_weight: context
                    .height_context
                    .assigned_cluster_total_voting_weight,
                proposer_schedule_hash: context.height_context.leader_schedule_root,
                protocol_config_hash: context.height_context.consensus_parameter_root,
                cryptographic_profile_root: context.height_context.cryptographic_profile_root,
                dag_frontier_root,
                tx_order_root,
                tx_count: transactions.len() as u64,
                protected_batch: None,
                evidence_root: context.evidence_root,
                state_root_before: context.latest_finalized_state_root,
                state_root_after: Hash::zero(),
                receipt_root: Hash::zero(),
                app_version: context.app_version,
                execution_version: context.execution_version,
                dag_version: context.dag_version,
                aegis_pqvm_version: context.aegis_pqvm_version.clone(),
                timestamp_ms_consensus_bounded: 0,
            },
            transactions,
            proposer_signature: AegisPqSignature {
                algorithm: String::new(),
                signature_bytes: Vec::new(),
            },
        };
        let mut authorized_state = state.clone();
        for transaction in &block.transactions {
            authorized_state.mark_authorized_at(
                transaction,
                block
                    .header
                    .timestamp_ms_consensus_bounded
                    .saturating_div(1_000),
            )?;
        }
        let execution = execute_block(&block, &authorized_state)?;
        let manifest =
            protected.build_execution_manifest(&block.transactions, &execution.receipts)?;
        let protected_commitment =
            protected.protected_batch_commitment(&manifest, &execution.receipts)?;
        if protected_commitment.protected_count != block.header.tx_count {
            return Err("protected batch count does not match block transaction count".to_string());
        }
        block.header.protected_batch = Some(protected_commitment);
        block.header.state_root_after = execution.state_root_after;
        block.header.receipt_root = execution.receipt_root;
        self.require_candidate_carry_forward(&context.height_context, context.round, &block)?;
        self.authorize_proposal_before_signature(&block, proposer, &context.height_context)?;
        block.proposer_signature = signer
            .sign_domain(
                SYNERGY_BLOCK_V1,
                &block.header.canonical_bytes()?,
                &proposer.consensus_public_key.key_id,
            )
            .map_err(|error| error.to_string())?;
        Ok(block)
    }

    pub fn validate_protected_proposal(
        &mut self,
        block: &Block,
        protected: &ProtectedBlockInput,
        target_context: &TargetAdmissionContext,
        context: &LocalConsensusContext,
        state: &ExecutionState,
        parameters: &EtdagParameters,
    ) -> Result<(), String> {
        self.phase = ConsensusPhase::ValidatingProposal;
        self.ensure_testnet_context(context)?;
        target_context.validate_height_context_compatibility(&context.height_context)?;
        self.require_authorized_round(&context.height_context, block.header.round)?;
        block.header.chain_id.require_testnet_v3()?;
        block.header.network_id.require_testnet_v3()?;
        if block.header.version != 2 {
            return Err("protected proposal requires block header version 2".to_string());
        }
        let height_context = &context.height_context;
        let expected_context_root = height_context.root()?;
        if block.header.height != height_context.height
            || block.header.parent_block_hash != context.latest_finalized_block_hash
            || block.header.state_root_before != context.latest_finalized_state_root
        {
            return Err("protected proposal parent/height/state context mismatch".to_string());
        }
        self.require_candidate_carry_forward(height_context, block.header.round, block)?;
        if block.header.protocol_version != height_context.protocol_version
            || block.header.epoch != height_context.epoch
            || block.header.cluster_id != height_context.assigned_cluster_id
            || block.header.height_context_root != expected_context_root
            || block.header.active_validator_set_hash != height_context.active_validator_set_root
            || block.header.eligible_validator_set_hash
                != height_context.assigned_cluster_membership_root
            || block.header.validator_consensus_key_root
                != height_context.validator_consensus_key_root
            || block.header.frozen_bonded_weight_root != height_context.frozen_bonded_weight_root
            || block.header.cluster_schedule_version != height_context.cluster_schedule_version
            || block.header.cluster_map_hash != height_context.cluster_map_root
            || block.header.assigned_cluster_membership_root
                != height_context.assigned_cluster_membership_root
            || block.header.assigned_cluster_validator_count
                != height_context.assigned_cluster_validator_count
            || block.header.assigned_cluster_total_voting_weight
                != height_context.assigned_cluster_total_voting_weight
            || block.header.proposer_schedule_hash != height_context.leader_schedule_root
            || block.header.protocol_config_hash != height_context.consensus_parameter_root
            || block.header.cryptographic_profile_root != height_context.cryptographic_profile_root
            || block.header.last_finalized_qc_hash
                != height_context.prior_finalized_qc_or_transition_root
        {
            return Err("protected proposal consensus context mismatch".to_string());
        }
        let proposer = self
            .validator_set
            .validators
            .iter()
            .find(|record| record.validator_id == block.header.proposer_validator_id)
            .cloned()
            .ok_or_else(|| "proposal proposer not in validator set".to_string())?;
        let scheduled = self.proposer_for(height_context, block.header.round)?;
        if scheduled.validator_id != proposer.validator_id
            || proposer.status != ValidatorStatus::Active
            || !proposer.is_active_for_epoch(block.header.epoch)
        {
            return Err("protected proposal proposer is not authorized".to_string());
        }
        let transactions = protected.verify_and_extract_transactions(
            &self.verifier,
            target_context,
            &self.validator_set,
            &self.cluster_map,
            parameters,
        )?;
        self.observe_valid_boc(protected, target_context)?;
        if block.transactions != transactions || block.header.tx_count != transactions.len() as u64
        {
            return Err("block transaction list is not the exact BOC public reveal".to_string());
        }
        let tx_ids = transactions
            .iter()
            .map(|transaction| {
                Ok(crate::synergy_types::TxId::from_hash(
                    Hash::from_domain_bytes(
                        "SYNERGY_EXECUTION_TX_ID_V1",
                        &transaction.canonical_bytes()?,
                    ),
                ))
            })
            .collect::<Result<Vec<_>, String>>()?;
        if block.header.tx_order_root != compute_tx_order_root(&tx_ids)? {
            return Err("protected proposal application transaction root mismatch".to_string());
        }
        let expected_dag_frontier = Hash::from_domain_bytes(
            "SYNERGY_ETDAG_DAG_CUT_ROOT_V2",
            protected.dcc.candidate.causal_closure_root.0.as_bytes(),
        );
        if block.header.dag_frontier_root != expected_dag_frontier {
            return Err("protected proposal DAG cut root mismatch".to_string());
        }
        let mut authorized_state = state.clone();
        for transaction in &transactions {
            authorized_state.mark_authorized_at(
                transaction,
                block
                    .header
                    .timestamp_ms_consensus_bounded
                    .saturating_div(1_000),
            )?;
        }
        let execution = execute_block(block, &authorized_state)?;
        if execution.state_root_after != block.header.state_root_after
            || execution.receipt_root != block.header.receipt_root
        {
            return Err("protected proposal execution roots mismatch".to_string());
        }
        let manifest = protected.build_execution_manifest(&transactions, &execution.receipts)?;
        let expected_commitment =
            protected.protected_batch_commitment(&manifest, &execution.receipts)?;
        if block.header.protected_batch.as_ref() != Some(&expected_commitment) {
            return Err("protected proposal ETDAG header commitment mismatch".to_string());
        }
        self.verifier
            .verify_domain_signature(
                SYNERGY_BLOCK_V1,
                &block.header.canonical_bytes()?,
                &proposer.validator_uma_id.0,
                &block.header.proposer_key_id,
                block.header.epoch,
                AegisPqKeyRole::ConsensusProposer,
                &block.proposer_signature,
            )
            .map_err(|error| error.to_string())
    }

    #[cfg(test)]
    pub fn validate_proposal(
        &mut self,
        block: &Block,
        context: &LocalConsensusContext,
        state: &ExecutionState,
        dag: &DagMempool<'_>,
    ) -> Result<(), String> {
        self.phase = ConsensusPhase::ValidatingProposal;
        self.ensure_testnet_context(context)?;
        self.require_authorized_round(&context.height_context, block.header.round)?;
        block.header.chain_id.require_testnet_v3()?;
        block.header.network_id.require_testnet_v3()?;
        let height_context = &context.height_context;
        let expected_context_root = height_context.root()?;
        if block.header.height != height_context.height {
            return Err("proposal height is not the expected next height".to_string());
        }
        if block.header.parent_block_hash != context.latest_finalized_block_hash {
            return Err("proposal parent hash does not match latest finalized block".to_string());
        }
        if block.header.state_root_before != context.latest_finalized_state_root {
            return Err(
                "proposal state_root_before does not match latest finalized state".to_string(),
            );
        }
        self.require_candidate_carry_forward(height_context, block.header.round, block)?;
        if block.header.protocol_version != height_context.protocol_version
            || block.header.epoch != height_context.epoch
            || block.header.cluster_id != height_context.assigned_cluster_id
            || block.header.height_context_root != expected_context_root
            || block.header.active_validator_set_hash != height_context.active_validator_set_root
            || block.header.eligible_validator_set_hash
                != height_context.assigned_cluster_membership_root
            || block.header.validator_consensus_key_root
                != height_context.validator_consensus_key_root
            || block.header.frozen_bonded_weight_root != height_context.frozen_bonded_weight_root
            || block.header.cluster_schedule_version != height_context.cluster_schedule_version
            || block.header.cluster_map_hash != height_context.cluster_map_root
            || block.header.assigned_cluster_membership_root
                != height_context.assigned_cluster_membership_root
            || block.header.assigned_cluster_validator_count
                != height_context.assigned_cluster_validator_count
            || block.header.assigned_cluster_total_voting_weight
                != height_context.assigned_cluster_total_voting_weight
            || block.header.proposer_schedule_hash != height_context.leader_schedule_root
            || block.header.protocol_config_hash != height_context.consensus_parameter_root
            || block.header.cryptographic_profile_root != height_context.cryptographic_profile_root
            || block.header.last_finalized_qc_hash
                != height_context.prior_finalized_qc_or_transition_root
        {
            return Err("proposal consensus context hash mismatch".to_string());
        }
        let proposer = self
            .validator_set
            .validators
            .iter()
            .find(|record| record.validator_id == block.header.proposer_validator_id)
            .ok_or_else(|| "proposal proposer not in validator set".to_string())?;
        let scheduled = self.proposer_for(height_context, block.header.round)?;
        if scheduled.validator_id != proposer.validator_id {
            return Err("proposal was not made by scheduled proposer".to_string());
        }
        if proposer.status != ValidatorStatus::Active
            || !proposer.is_active_for_epoch(block.header.epoch)
        {
            return Err("proposal proposer is not active for epoch".to_string());
        }
        self.verifier
            .verify_domain_signature(
                SYNERGY_BLOCK_V1,
                &block.header.canonical_bytes()?,
                &proposer.validator_uma_id.0,
                &block.header.proposer_key_id,
                block.header.epoch,
                AegisPqKeyRole::ConsensusProposer,
                &block.proposer_signature,
            )
            .map_err(|error| error.to_string())?;
        for tx in &block.transactions {
            self.verifier
                .verify_transaction_signature_checked(tx)
                .map_err(|error| error.to_string())?;
        }
        let tx_ids = block
            .transactions
            .iter()
            .map(|tx| {
                Ok(crate::synergy_types::TxId::from_hash(
                    Hash::from_domain_bytes("SYNERGY_EXECUTION_TX_ID_V1", &tx.canonical_bytes()?),
                ))
            })
            .collect::<Result<Vec<_>, String>>()?;
        if block.header.tx_order_root != compute_tx_order_root(&tx_ids)? {
            return Err("proposal tx_order_root mismatch".to_string());
        }
        let sorted = dag.deterministic_topological_sort(&tx_ids)?;
        if sorted != tx_ids {
            return Err(
                "proposal transaction order is not deterministic topological order".to_string(),
            );
        }
        let execution = execute_block(block, state)?;
        if execution.state_root_after != block.header.state_root_after {
            return Err("proposal state_root_after mismatch".to_string());
        }
        if execution.receipt_root != block.header.receipt_root {
            return Err("proposal receipt_root mismatch".to_string());
        }
        Ok(())
    }

    fn sign_vote_for_phase(
        &mut self,
        signer: &mut AegisPqvmSigner,
        validator: &ValidatorRecord,
        block: &Block,
        height_context: &HeightConsensusContext,
        phase: VotePhase,
        highest_prepared_vc_root: Option<Hash>,
    ) -> Result<Vote, String> {
        self.phase = ConsensusPhase::Voting;
        height_context.validate_against(
            &self.validator_set,
            &self.cluster_map,
            &self.protocol_config,
        )?;
        self.require_authorized_round(height_context, block.header.round)?;
        let expected_context_root = height_context.root()?;
        if block.header.height_context_root != expected_context_root
            || block.header.height != height_context.height
            || block.header.epoch != height_context.epoch
            || block.header.cluster_id != height_context.assigned_cluster_id
        {
            return Err("proposal height context mismatch rejected before signing".to_string());
        }
        if validator.status != ValidatorStatus::Active
            || !validator.is_active_for_epoch(block.header.epoch)
        {
            return Err("validator cannot vote before ACTIVE epoch".to_string());
        }
        if !self
            .cluster_map
            .contains(block.header.cluster_id, &validator.validator_id)
        {
            return Err("validator is not assigned to proposal cluster".to_string());
        }
        let mut vote = Vote {
            chain_id: block.header.chain_id,
            network_id: block.header.network_id.clone(),
            protocol_version: block.header.protocol_version.clone(),
            height: block.header.height,
            round: block.header.round,
            epoch: block.header.epoch,
            cluster_id: block.header.cluster_id,
            height_context_root: expected_context_root,
            phase,
            block_id: block.candidate_id()?,
            highest_prepared_vc_root,
            validator_id: validator.validator_id.clone(),
            validator_uma_id: validator.validator_uma_id.clone(),
            key_id: validator.consensus_public_key.key_id.clone(),
            active_validator_set_hash: block.header.active_validator_set_hash,
            cluster_map_hash: block.header.cluster_map_hash,
            aegis_pq_signature: AegisPqSignature {
                algorithm: String::new(),
                signature_bytes: Vec::new(),
            },
        };
        vote.aegis_pq_signature = signer
            .sign_consensus_vote(&vote, &self.signing_authority)
            .map_err(|error| error.to_string())?;
        Ok(vote)
    }

    pub fn validation_vote(
        &mut self,
        signer: &mut AegisPqvmSigner,
        validator: &ValidatorRecord,
        block: &Block,
        height_context: &HeightConsensusContext,
    ) -> Result<Vote, String> {
        self.sign_vote_for_phase(
            signer,
            validator,
            block,
            height_context,
            VotePhase::Validate,
            None,
        )
    }

    pub fn finality_vote(
        &mut self,
        signer: &mut AegisPqvmSigner,
        validator: &ValidatorRecord,
        block: &Block,
        validation_certificate: &ValidationCertificate,
        height_context: &HeightConsensusContext,
    ) -> Result<Vote, String> {
        self.verify_vc(validation_certificate, height_context)?;
        if validation_certificate.candidate_id != block.candidate_id()? {
            return Err("VC does not prepare the exact proposal candidate".to_string());
        }
        if validation_certificate.round.0 > block.header.round.0 {
            return Err("VC round is later than proposal envelope round".to_string());
        }
        self.sign_vote_for_phase(
            signer,
            validator,
            block,
            height_context,
            VotePhase::Finality,
            None,
        )
    }

    pub fn timeout_vote(
        &mut self,
        signer: &mut AegisPqvmSigner,
        validator: &ValidatorRecord,
        height_context: &HeightConsensusContext,
        closing_round: Round,
        highest_prepared_vc: Option<&ValidationCertificate>,
    ) -> Result<Vote, String> {
        height_context.validate_against(
            &self.validator_set,
            &self.cluster_map,
            &self.protocol_config,
        )?;
        if validator.status != ValidatorStatus::Active
            || !validator.is_active_for_epoch(height_context.epoch)
            || !self
                .cluster_map
                .contains(height_context.assigned_cluster_id, &validator.validator_id)
        {
            return Err("validator is not eligible to sign timeout".to_string());
        }
        let (mut candidate_id, mut highest_prepared_vc_root) = if let Some(vc) = highest_prepared_vc
        {
            self.verify_vc(vc, height_context)?;
            if vc.round.0 > closing_round.0 {
                return Err("highest prepared VC is from a future round".to_string());
            }
            (vc.candidate_id.clone(), Some(vc.root()?))
        } else {
            (BlockId(String::new()), None)
        };

        // This timeout slot may already be durably authorized by a previous
        // process. The prepared `ValidationCertificate` that determined the
        // recorded candidate is in-memory only, so after a restart the value
        // above is derived from state this process no longer has, and would be a
        // second, different authorization for a slot that can only be authorized
        // once. `authorize_before_signature` would correctly reject it with
        // `CONSENSUS_SIGNING_CONFLICT`, the typed worker would fail closed, and
        // systemd would replay the identical failure forever — a deterministic
        // liveness deadlock with no equivocation and no safety halt.
        //
        // Re-emit exactly what this validator already committed to. That is the
        // safest available value: it reproduces the durable record byte-for-byte
        // and takes the idempotent path in the signing authority.
        let recorded = self.signing_authority.recorded_authorization_for_slot(
            &ConsensusSigningAuthorization {
                chain_id: height_context.chain_id,
                network_id: height_context.network_id.clone(),
                protocol_version: height_context.protocol_version.clone(),
                epoch: height_context.epoch,
                height: height_context.height,
                round: closing_round,
                height_context_root: height_context.root()?,
                validator_id: validator.validator_id.clone(),
                key_id: validator.consensus_public_key.key_id.clone(),
                phase: ConsensusSigningPhase::Timeout,
                candidate_id: None,
                highest_prepared_vc_root: None,
                conflict_unlock_tc_id: None,
            },
        )?;
        if let Some(recorded) = recorded {
            candidate_id = recorded
                .candidate_id
                .unwrap_or_else(|| BlockId(String::new()));
            highest_prepared_vc_root = recorded.highest_prepared_vc_root;
        }
        let mut vote = Vote {
            chain_id: height_context.chain_id,
            network_id: height_context.network_id.clone(),
            protocol_version: height_context.protocol_version.clone(),
            height: height_context.height,
            round: closing_round,
            epoch: height_context.epoch,
            cluster_id: height_context.assigned_cluster_id,
            height_context_root: height_context.root()?,
            phase: VotePhase::Timeout,
            block_id: candidate_id,
            highest_prepared_vc_root,
            validator_id: validator.validator_id.clone(),
            validator_uma_id: validator.validator_uma_id.clone(),
            key_id: validator.consensus_public_key.key_id.clone(),
            active_validator_set_hash: height_context.active_validator_set_root,
            cluster_map_hash: height_context.cluster_map_root,
            aegis_pq_signature: AegisPqSignature {
                algorithm: String::new(),
                signature_bytes: Vec::new(),
            },
        };
        vote.aegis_pq_signature = signer
            .sign_consensus_vote(&vote, &self.signing_authority)
            .map_err(|error| error.to_string())?;
        self.phase = ConsensusPhase::TimeoutWaitingForProposer;
        Ok(vote)
    }

    pub fn collect_votes(
        &self,
        votes: &[Vote],
        height_context: &HeightConsensusContext,
        expected_phase: VotePhase,
    ) -> Result<Vec<Vote>, String> {
        height_context.validate_against(
            &self.validator_set,
            &self.cluster_map,
            &self.protocol_config,
        )?;
        let expected_context_root = height_context.root()?;
        let mut verified = Vec::new();
        let mut seen = BTreeSet::new();
        for vote in votes {
            if vote.phase != expected_phase {
                return Err(format!(
                    "wrong-phase signature rejected: expected {expected_phase:?}, found {:?}",
                    vote.phase
                ));
            }
            if vote.height_context_root != expected_context_root
                || vote.height != height_context.height
                || vote.epoch != height_context.epoch
                || vote.cluster_id != height_context.assigned_cluster_id
                || vote.protocol_version != height_context.protocol_version
            {
                return Err(
                    "vote height context mismatch rejected before signature verification"
                        .to_string(),
                );
            }
            if !seen.insert(vote.validator_id.clone()) {
                return Err("duplicate vote signer".to_string());
            }
            let validator = self
                .validator_set
                .validators
                .iter()
                .find(|record| record.validator_id == vote.validator_id)
                .ok_or_else(|| "vote signer not in validator set".to_string())?;
            if !self
                .cluster_map
                .contains(height_context.assigned_cluster_id, &validator.validator_id)
            {
                return Err("non-assigned-cluster vote is consensus-ineligible".to_string());
            }
            self.verifier
                .verify_vote_signature_checked(vote, validator, expected_context_root)
                .map_err(|error| error.to_string())?;
            verified.push(vote.clone());
        }
        Ok(verified)
    }

    fn build_certificate(
        &mut self,
        votes: &[Vote],
        height_context: &HeightConsensusContext,
        expected_phase: VotePhase,
    ) -> Result<QuorumCertificate, String> {
        self.phase = ConsensusPhase::FormingQc;
        let verified = self.collect_votes(votes, height_context, expected_phase)?;
        if verified.is_empty() {
            return Err("cannot form QC without votes".to_string());
        }
        let first = &verified[0];
        match first.phase {
            VotePhase::Validate | VotePhase::Finality
                if first.highest_prepared_vc_root.is_some() =>
            {
                return Err("validate/finality vote cannot carry a prepared VC root".to_string());
            }
            VotePhase::Timeout
                if first.highest_prepared_vc_root.is_some() != !first.block_id.0.is_empty() =>
            {
                return Err(
                    "timeout vote prepared VC root and candidate must appear together".to_string(),
                );
            }
            _ => {}
        }
        let mut timeout_prepared_subject: Option<(BlockId, Hash)> = None;
        if first.phase == VotePhase::Timeout {
            for vote in &verified {
                if vote.highest_prepared_vc_root.is_some() != !vote.block_id.0.is_empty() {
                    return Err(
                        "timeout vote prepared VC root and candidate must appear together"
                            .to_string(),
                    );
                }
                if let Some(root) = vote.highest_prepared_vc_root {
                    match timeout_prepared_subject.as_mut() {
                        None => {
                            timeout_prepared_subject = Some((vote.block_id.clone(), root));
                        }
                        Some((candidate, _)) if candidate != &vote.block_id => {
                            return Err(
                                "timeout votes report conflicting prepared candidates".to_string()
                            );
                        }
                        Some((_, selected_root)) if root < *selected_root => {
                            // A single prepared candidate may have multiple valid VCs
                            // assembled from different strict-quorum signer subsets.
                            // Select one proof root deterministically; replicas that
                            // hold another valid proof for the same candidate recover
                            // the selected proof before carrying the candidate forward.
                            *selected_root = root;
                        }
                        Some(_) => {}
                    }
                }
            }
        }
        let required_count = height_context.strict_count_quorum()?;
        if (verified.len() as u64) < required_count {
            return Err(format!(
                "strict distinct-signer quorum failed: found {}, required {}",
                verified.len(),
                required_count
            ));
        }
        // QC bitmap positions are defined by the canonical *active* validator
        // set for the certificate epoch.  Pre-provisioned validators that are
        // inactive at genesis must not shift a live signer's bitmap position:
        // verification uses this same active set.
        let validators = self
            .validator_set
            .active_for_epoch(height_context.epoch)
            .canonicalized()
            .validators;
        let mut signer_bitmap = vec![0u8; (validators.len() + 7) / 8];
        let mut signatures = Vec::new();
        let mut key_ids = Vec::new();
        let mut signed_weight = 0u64;
        for vote in &verified {
            if (vote.phase != VotePhase::Timeout && vote.block_id != first.block_id)
                || vote.height != first.height
                || vote.round != first.round
                || vote.epoch != first.epoch
                || vote.cluster_id != first.cluster_id
                || vote.height_context_root != first.height_context_root
                || vote.phase != first.phase
                || (vote.phase != VotePhase::Timeout
                    && vote.highest_prepared_vc_root != first.highest_prepared_vc_root)
            {
                return Err(
                    "votes do not target the exact same block/height/round/epoch/cluster"
                        .to_string(),
                );
            }
            let index = validators
                .iter()
                .position(|validator| validator.validator_id == vote.validator_id)
                .ok_or_else(|| "vote signer missing from canonical validator set".to_string())?;
            signer_bitmap[index / 8] |= 1u8 << (index % 8);
            let validator = &validators[index];
            signed_weight = signed_weight
                .checked_add(validator.voting_weight)
                .ok_or_else(|| "QC signed-weight overflow".to_string())?;
            signatures.push(vote.aegis_pq_signature.clone());
            key_ids.push(vote.key_id.clone());
        }
        let (certificate_block_id, certificate_prepared_root) = timeout_prepared_subject
            .map(|(candidate, root)| (candidate, Some(root)))
            .unwrap_or_else(|| (first.block_id.clone(), first.highest_prepared_vc_root));
        let qc = QuorumCertificate {
            qc_version: 1,
            chain_id: first.chain_id,
            network_id: first.network_id.clone(),
            protocol_version: first.protocol_version.clone(),
            height: first.height,
            round: first.round,
            epoch: first.epoch,
            cluster_id: first.cluster_id,
            height_context_root: first.height_context_root,
            phase: first.phase.clone(),
            block_id: certificate_block_id,
            highest_prepared_vc_root: certificate_prepared_root,
            active_validator_set_hash: first.active_validator_set_hash,
            cluster_map_hash: first.cluster_map_hash,
            threshold_weight_required: height_context.strict_weight_quorum()?,
            signed_weight,
            signer_bitmap,
            aegis_pq_signatures: signatures,
            aegis_pq_key_ids: key_ids,
        };
        Ok(qc)
    }

    pub fn form_vc(
        &mut self,
        votes: &[Vote],
        height_context: &HeightConsensusContext,
    ) -> Result<ValidationCertificate, String> {
        let certificate = self.build_certificate(votes, height_context, VotePhase::Validate)?;
        let vc = ValidationCertificate {
            certificate_version: certificate.qc_version,
            chain_id: certificate.chain_id,
            network_id: certificate.network_id,
            protocol_version: certificate.protocol_version,
            height: certificate.height,
            round: certificate.round,
            epoch: certificate.epoch,
            cluster_id: certificate.cluster_id,
            height_context_root: certificate.height_context_root,
            candidate_id: certificate.block_id,
            active_validator_set_hash: certificate.active_validator_set_hash,
            cluster_map_hash: certificate.cluster_map_hash,
            threshold_weight_required: certificate.threshold_weight_required,
            signed_weight: certificate.signed_weight,
            signer_bitmap: certificate.signer_bitmap,
            aegis_pq_signatures: certificate.aegis_pq_signatures,
            aegis_pq_key_ids: certificate.aegis_pq_key_ids,
        };
        self.verify_vc(&vc, height_context)?;
        Ok(vc)
    }

    pub fn form_qc(
        &mut self,
        votes: &[Vote],
        height_context: &HeightConsensusContext,
    ) -> Result<QuorumCertificate, String> {
        let qc = self.build_certificate(votes, height_context, VotePhase::Finality)?;
        self.verify_qc(&qc, height_context)?;
        Ok(qc)
    }

    pub fn form_tc(
        &mut self,
        votes: &[Vote],
        height_context: &HeightConsensusContext,
    ) -> Result<TimeoutCertificate, String> {
        let certificate = self.build_certificate(votes, height_context, VotePhase::Timeout)?;
        let carry_forward_candidate_id = if certificate.block_id.0.is_empty() {
            None
        } else {
            Some(certificate.block_id)
        };
        let tc = TimeoutCertificate {
            certificate_version: 2,
            chain_id: certificate.chain_id,
            network_id: certificate.network_id,
            protocol_version: certificate.protocol_version,
            height: certificate.height,
            closing_round: certificate.round,
            next_round: Round(certificate.round.0.saturating_add(1)),
            epoch: certificate.epoch,
            cluster_id: certificate.cluster_id,
            height_context_root: certificate.height_context_root,
            highest_prepared_vc_root: certificate.highest_prepared_vc_root,
            carry_forward_candidate_id,
            active_validator_set_hash: certificate.active_validator_set_hash,
            cluster_map_hash: certificate.cluster_map_hash,
            threshold_weight_required: certificate.threshold_weight_required,
            signed_weight: certificate.signed_weight,
            signer_bitmap: certificate.signer_bitmap,
            aegis_pq_signatures: certificate.aegis_pq_signatures,
            aegis_pq_key_ids: certificate.aegis_pq_key_ids,
            timeout_vote_subjects: votes
                .iter()
                .map(|vote| crate::synergy_types::TimeoutVoteSubject {
                    block_id: vote.block_id.clone(),
                    highest_prepared_vc_root: vote.highest_prepared_vc_root,
                })
                .collect(),
        };
        self.verify_tc(&tc, height_context)?;
        Ok(tc)
    }

    pub fn verify_vc(
        &self,
        vc: &ValidationCertificate,
        height_context: &HeightConsensusContext,
    ) -> Result<(), String> {
        self.verifier
            .verify_validation_certificate_checked(
                vc,
                &self.validator_set,
                &self.cluster_map,
                height_context,
            )
            .map_err(|error| error.to_string())
    }

    pub fn verify_tc(
        &self,
        tc: &TimeoutCertificate,
        height_context: &HeightConsensusContext,
    ) -> Result<(), String> {
        self.verifier
            .verify_timeout_certificate_checked(
                tc,
                &self.validator_set,
                &self.cluster_map,
                height_context,
            )
            .map_err(|error| error.to_string())
    }

    pub fn verify_qc(
        &self,
        qc: &QuorumCertificate,
        height_context: &HeightConsensusContext,
    ) -> Result<(), String> {
        self.verifier
            .verify_qc_checked(qc, &self.validator_set, &self.cluster_map, height_context)
            .map_err(|error| error.to_string())
    }

    pub fn commit_block(
        &mut self,
        block: &Block,
        qc: &QuorumCertificate,
        height_context: &HeightConsensusContext,
    ) -> Result<(), String> {
        self.phase = ConsensusPhase::FinalizingBlock;
        let expected_context_root = height_context.root()?;
        if block.header.height_context_root != expected_context_root
            || qc.height_context_root != expected_context_root
        {
            return Err("block/QC height context mismatch".to_string());
        }
        if qc.phase != VotePhase::Finality || qc.block_id != block.candidate_id()? {
            return Err("QC does not certify the exact stable candidate".to_string());
        }
        self.verify_qc(qc, height_context)?;
        let key = (qc.height, qc.epoch, qc.cluster_id, expected_context_root);
        let qc_root = qc.root()?;
        if let Some((existing_candidate, existing_qc_root)) = self.observed_qcs.get(&key) {
            if existing_candidate != &qc.block_id {
                self.signing_authority
                    .enter_safety_halt(&SafetyHaltIncident {
                        incident_version: 1,
                        kind: SafetyHaltKind::ConflictingFinalityCertificates,
                        chain_id: qc.chain_id,
                        network_id: qc.network_id.clone(),
                        protocol_version: qc.protocol_version.clone(),
                        epoch: qc.epoch,
                        height: qc.height,
                        context_root: expected_context_root,
                        first_evidence_root: *existing_qc_root,
                        second_evidence_root: qc_root,
                    })?;
                return Err("SAFETY_INCIDENT_CONFLICTING_VALID_QC".to_string());
            }
        }
        self.observed_qcs
            .insert(key, (qc.block_id.clone(), qc_root));
        self.phase = ConsensusPhase::Finalized;
        Ok(())
    }

    pub fn advance_round_after_tc(
        &mut self,
        tc: &TimeoutCertificate,
        height_context: &HeightConsensusContext,
        current_round: Round,
    ) -> Result<Round, String> {
        self.verify_tc(tc, height_context)?;
        if tc.closing_round != current_round {
            return Err("TC does not close the local current round".to_string());
        }
        let key = (height_context.height, height_context.root()?);
        let authorized_round = self.authorized_rounds.entry(key).or_insert(Round(0));
        if *authorized_round != current_round {
            return Err("TC closing round is not the currently authorized round".to_string());
        }
        *authorized_round = tc.next_round;
        if let Some(candidate_id) = &tc.carry_forward_candidate_id {
            self.required_carry_forward.insert(
                (height_context.height, height_context.root()?, tc.next_round),
                candidate_id.clone(),
            );
        }
        self.phase = ConsensusPhase::WaitingForProposal;
        Ok(tc.next_round)
    }

    /// Restores the live round authority from one independently verified TC.
    ///
    /// A TC is itself a strict-quorum proof that its closing round completed,
    /// so a restarted validator does not need every earlier process-local TC
    /// to safely rejoin at `next_round`. The carried candidate remains bound
    /// exactly as on the ordinary sequential transition path.
    pub fn recover_round_after_tc(
        &mut self,
        tc: &TimeoutCertificate,
        height_context: &HeightConsensusContext,
    ) -> Result<Round, String> {
        self.verify_tc(tc, height_context)?;
        if tc.height != height_context.height
            || tc.height_context_root != height_context.root()?
            || tc.next_round.0 != tc.closing_round.0.saturating_add(1)
        {
            return Err("recovered TC is not bound to the active height/round".to_string());
        }
        let key = (height_context.height, height_context.root()?);
        let authorized_round = self.authorized_rounds.entry(key).or_insert(Round(0));
        if authorized_round.0 > tc.next_round.0 {
            return Err("recovered TC is older than the locally authorized round".to_string());
        }
        *authorized_round = tc.next_round;
        if let Some(candidate_id) = &tc.carry_forward_candidate_id {
            self.required_carry_forward.insert(
                (height_context.height, height_context.root()?, tc.next_round),
                candidate_id.clone(),
            );
        }
        self.phase = ConsensusPhase::WaitingForProposal;
        Ok(tc.next_round)
    }

    pub fn carry_forward_prepared_candidate(
        &mut self,
        signer: &mut AegisPqvmSigner,
        original: &Block,
        validation_certificate: &ValidationCertificate,
        timeout_certificate: &TimeoutCertificate,
        next_proposer: &ValidatorRecord,
        height_context: &HeightConsensusContext,
    ) -> Result<Block, String> {
        self.verify_vc(validation_certificate, height_context)?;
        self.verify_tc(timeout_certificate, height_context)?;
        let candidate_id = original.candidate_id()?;
        if validation_certificate.candidate_id != candidate_id
            || timeout_certificate.highest_prepared_vc_root != Some(validation_certificate.root()?)
            || timeout_certificate.carry_forward_candidate_id.as_ref() != Some(&candidate_id)
        {
            return Err(
                "TC does not require carry-forward of the exact prepared candidate".to_string(),
            );
        }
        let scheduled = self.proposer_for(height_context, timeout_certificate.next_round)?;
        if scheduled.validator_id != next_proposer.validator_id {
            return Err("carry-forward proposer is not authorized for next round".to_string());
        }
        let mut carried = original.clone();
        carried.header.round = timeout_certificate.next_round;
        carried.header.proposer_validator_id = next_proposer.validator_id.clone();
        carried.header.proposer_uma_id = next_proposer.validator_uma_id.clone();
        carried.header.proposer_key_id = next_proposer.consensus_public_key.key_id.clone();
        self.authorize_proposal_before_signature(&carried, next_proposer, height_context)?;
        carried.proposer_signature = signer
            .sign_domain(
                SYNERGY_BLOCK_V1,
                &carried.header.canonical_bytes()?,
                &next_proposer.consensus_public_key.key_id,
            )
            .map_err(|error| error.to_string())?;
        if carried.candidate_id()? != candidate_id {
            return Err("prepared candidate changed during carry-forward".to_string());
        }
        Ok(carried)
    }

    pub fn enter_view_change(&mut self) {
        self.phase = ConsensusPhase::ViewChange;
    }

    pub fn handle_timeout(&mut self) {
        self.phase = ConsensusPhase::TimeoutWaitingForProposer;
    }

    pub fn detect_equivocation(&self, proposals: &[Block]) -> bool {
        let mut seen = BTreeMap::<(Height, Round, Epoch, ClusterId), BlockId>::new();
        for block in proposals {
            let key = (
                block.header.height,
                block.header.round,
                block.header.epoch,
                block.header.cluster_id,
            );
            let Ok(block_id) = block.block_id() else {
                return true;
            };
            if let Some(existing) = seen.insert(key, block_id.clone()) {
                if existing != block_id {
                    return true;
                }
            }
        }
        false
    }

    fn authorize_proposal_before_signature(
        &self,
        block: &Block,
        proposer: &ValidatorRecord,
        height_context: &HeightConsensusContext,
    ) -> Result<Hash, String> {
        let candidate_id = block.candidate_id()?;
        self.signing_authority
            .authorize_before_signature(&ConsensusSigningAuthorization {
                chain_id: height_context.chain_id,
                network_id: height_context.network_id.clone(),
                protocol_version: height_context.protocol_version.clone(),
                epoch: height_context.epoch,
                height: height_context.height,
                round: block.header.round,
                height_context_root: height_context.root()?,
                validator_id: proposer.validator_id.clone(),
                key_id: proposer.consensus_public_key.key_id.clone(),
                phase: ConsensusSigningPhase::Proposal,
                candidate_id: Some(candidate_id),
                highest_prepared_vc_root: None,
                conflict_unlock_tc_id: None,
            })
    }

    fn observe_valid_boc(
        &mut self,
        protected: &ProtectedBlockInput,
        target_context: &TargetAdmissionContext,
    ) -> Result<(), String> {
        let boc_digest = protected.boc.digest()?;
        let evidence_root =
            Hash::from_domain_bytes("SYNERGY_ETDAG_BOC_EVIDENCE_V2", boc_digest.0.as_bytes());
        let target_root = target_context.root()?;
        let key = (
            target_context.target_height,
            target_context.epoch,
            target_context.assigned_cluster_id,
            target_root,
        );
        if let Some((existing_digest, existing_root)) = self.observed_bocs.get(&key) {
            if existing_digest != &boc_digest {
                self.signing_authority
                    .enter_safety_halt(&SafetyHaltIncident {
                        incident_version: 1,
                        kind: SafetyHaltKind::ConflictingBatchOrderCertificates,
                        chain_id: target_context.chain_id,
                        network_id: target_context.network_id.clone(),
                        protocol_version: target_context.protocol_version.clone(),
                        epoch: target_context.epoch,
                        height: target_context.target_height,
                        context_root: target_root,
                        first_evidence_root: *existing_root,
                        second_evidence_root: evidence_root,
                    })?;
                return Err("SAFETY_INCIDENT_CONFLICTING_VALID_BOC".to_string());
            }
        }
        self.observed_bocs.insert(key, (boc_digest, evidence_root));
        Ok(())
    }

    fn ensure_testnet_context(&self, context: &LocalConsensusContext) -> Result<(), String> {
        context.height_context.validate_against(
            &self.validator_set,
            &self.cluster_map,
            &self.protocol_config,
        )?;
        if context.height_context.height.0 != context.latest_finalized_height.0 + 1 {
            return Err("height context is not derived for the next finalized height".to_string());
        }
        if context
            .height_context
            .prior_finalized_qc_or_transition_root
            .is_zero()
        {
            return Err("height context prior finalized reference is missing".to_string());
        }
        Ok(())
    }

    fn require_authorized_round(
        &self,
        height_context: &HeightConsensusContext,
        round: Round,
    ) -> Result<(), String> {
        let key = (height_context.height, height_context.root()?);
        let authorized = self
            .authorized_rounds
            .get(&key)
            .copied()
            .unwrap_or(Round(0));
        if round != authorized {
            return Err(format!(
                "round {} is not authorized; valid TC is required to advance from round {}",
                round.0, authorized.0
            ));
        }
        Ok(())
    }

    fn require_candidate_carry_forward(
        &self,
        height_context: &HeightConsensusContext,
        round: Round,
        block: &Block,
    ) -> Result<(), String> {
        let key = (height_context.height, height_context.root()?, round);
        if let Some(required_candidate) = self.required_carry_forward.get(&key) {
            if &block.candidate_id()? != required_candidate {
                return Err(
                    "prepared candidate must be carried forward exactly after TC".to_string(),
                );
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::aegis_pqvm::AegisPqvmSigner;
    use crate::synergy_types::{
        deterministic_test_height_context, ChainId, ClusterAssignment, UmaId, ValidatorId,
    };
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_signing_authority(label: &str) -> DurableConsensusSigningAuthority {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        DurableConsensusSigningAuthority::at_path(crate::utils::test_temp_root(format!(
            "synergy-posy-{label}-{}-{nonce}.json",
            std::process::id()
        )))
    }

    fn setup_validators() -> (AegisPqvmSigner, ValidatorSet, ClusterMap, ProtocolConfig) {
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
                .expect("key");
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
                .map(|record| ClusterAssignment {
                    cluster_id: ClusterId(0),
                    validator_id: record.validator_id.clone(),
                })
                .collect(),
        };
        (signer, set, cluster, ProtocolConfig::testnet_v3())
    }

    fn context(
        set: &ValidatorSet,
        cluster: &ClusterMap,
        protocol: &ProtocolConfig,
    ) -> LocalConsensusContext {
        LocalConsensusContext {
            height_context: deterministic_test_height_context(
                set,
                cluster,
                protocol,
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
        }
    }

    fn empty_state() -> ExecutionState {
        ExecutionState::new()
    }

    #[test]
    fn validators_require_dynamic_pqc_quorum_to_commit() {
        let (mut signer, set, cluster, protocol) = setup_validators();
        let verifier = signer.verifier();
        let mut consensus =
            ProofOfSynergyBft::new(&verifier, set.clone(), cluster.clone(), protocol.clone());
        let ctx = context(&set, &cluster, &protocol);
        let proposer = consensus
            .proposer_for(&ctx.height_context, Round(0))
            .unwrap();
        let block = consensus
            .propose_block(
                &mut signer,
                &proposer,
                Vec::new(),
                &ctx,
                &empty_state(),
                Hash::zero(),
            )
            .unwrap();
        let required_votes = set.threshold_weight() as usize;
        let validation_votes = set
            .validators
            .iter()
            .take(required_votes)
            .map(|validator| {
                consensus
                    .validation_vote(&mut signer, validator, &block, &ctx.height_context)
                    .unwrap()
            })
            .collect::<Vec<_>>();
        let vc = consensus
            .form_vc(&validation_votes, &ctx.height_context)
            .unwrap();
        let finality_votes = set
            .validators
            .iter()
            .take(required_votes)
            .map(|validator| {
                consensus
                    .finality_vote(&mut signer, validator, &block, &vc, &ctx.height_context)
                    .unwrap()
            })
            .collect::<Vec<_>>();
        let qc = consensus
            .form_qc(&finality_votes, &ctx.height_context)
            .unwrap();
        assert!(consensus
            .commit_block(&block, &qc, &ctx.height_context)
            .is_ok());

        let few_votes = set.validators[0..3]
            .iter()
            .map(|validator| {
                consensus
                    .finality_vote(&mut signer, validator, &block, &vc, &ctx.height_context)
                    .unwrap()
            })
            .collect::<Vec<_>>();
        assert!(consensus.form_qc(&few_votes, &ctx.height_context).is_err());
    }

    #[test]
    fn certificate_bitmap_excludes_inactive_preprovisioned_validators() {
        let (mut signer, mut set, cluster, protocol) = setup_validators();
        let verifier = signer.verifier();
        let inactive_key = signer
            .generate_and_register_key(
                "preprovisioned-validator",
                vec![
                    AegisPqKeyRole::ConsensusVote,
                    AegisPqKeyRole::ConsensusProposer,
                ],
                Epoch(1),
            )
            .expect("inactive validator key");
        let inactive_public = signer.public_key_record(&inactive_key).expect("public key");
        set.validators.push(ValidatorRecord {
            // Sort before the active validator ids so a full-set bitmap would
            // expose the off-by-one encoding immediately.
            validator_id: ValidatorId("preprovisioned-validator".to_string()),
            validator_uma_id: UmaId("preprovisioned-validator".to_string()),
            consensus_public_key: inactive_public.clone(),
            peer_public_key: inactive_public.clone(),
            operator_public_key: inactive_public,
            voting_weight: 1,
            status: ValidatorStatus::Registered,
            cluster_id: ClusterId(0),
            activation_epoch: Epoch(1),
        });
        let mut consensus =
            ProofOfSynergyBft::new(&verifier, set.clone(), cluster.clone(), protocol.clone());
        let active_set = set.active_for_epoch(Epoch(0));
        let ctx = context(&active_set, &cluster, &protocol);
        let proposer = consensus
            .proposer_for(&ctx.height_context, Round(0))
            .expect("active proposer");
        let block = consensus
            .propose_block(
                &mut signer,
                &proposer,
                Vec::new(),
                &ctx,
                &empty_state(),
                Hash::zero(),
            )
            .expect("proposal");
        let votes = active_set.validators[0..5]
            .iter()
            .map(|validator| {
                consensus
                    .validation_vote(&mut signer, validator, &block, &ctx.height_context)
                    .expect("active validator vote")
            })
            .collect::<Vec<_>>();
        let vc = consensus
            .form_vc(&votes, &ctx.height_context)
            .expect("active-only certificate");

        assert_eq!(vc.signer_bitmap, vec![0b0001_1111]);
        consensus
            .verify_vc(&vc, &ctx.height_context)
            .expect("certificate verifies against active-set bitmap");
    }

    #[test]
    fn conflicting_verified_qc_enters_durable_safety_halt_before_more_signing() {
        let (mut signer, set, cluster, protocol) = setup_validators();
        let verifier = signer.verifier();
        let mut consensus = ProofOfSynergyBft::new_with_signing_authority(
            verifier.clone(),
            set.clone(),
            cluster.clone(),
            protocol.clone(),
            temp_signing_authority("qc-safety-halt"),
        );
        let ctx = context(&set, &cluster, &protocol);
        let proposer = consensus
            .proposer_for(&ctx.height_context, Round(0))
            .unwrap();
        let block = consensus
            .propose_block(
                &mut signer,
                &proposer,
                Vec::new(),
                &ctx,
                &empty_state(),
                Hash::zero(),
            )
            .unwrap();
        let validation_votes = set.validators[0..5]
            .iter()
            .map(|validator| {
                consensus
                    .validation_vote(&mut signer, validator, &block, &ctx.height_context)
                    .unwrap()
            })
            .collect::<Vec<_>>();
        let vc = consensus
            .form_vc(&validation_votes, &ctx.height_context)
            .unwrap();
        let finality_votes = set.validators[0..5]
            .iter()
            .map(|validator| {
                consensus
                    .finality_vote(&mut signer, validator, &block, &vc, &ctx.height_context)
                    .unwrap()
            })
            .collect::<Vec<_>>();
        let qc = consensus
            .form_qc(&finality_votes, &ctx.height_context)
            .unwrap();
        let context_root = ctx.height_context.root().unwrap();
        consensus.observed_qcs.insert(
            (
                ctx.height_context.height,
                ctx.height_context.epoch,
                ctx.height_context.assigned_cluster_id,
                context_root,
            ),
            (
                BlockId("different-valid-candidate".to_string()),
                Hash::from_domain_bytes("prior-valid-qc", b"different-valid-candidate"),
            ),
        );
        assert!(consensus
            .commit_block(&block, &qc, &ctx.height_context)
            .unwrap_err()
            .contains("CONFLICTING_VALID_QC"));
        assert_eq!(
            consensus
                .signing_authority
                .safety_halt_incidents()
                .unwrap()
                .len(),
            1
        );
        assert!(consensus
            .validation_vote(&mut signer, &set.validators[0], &block, &ctx.height_context,)
            .unwrap_err()
            .contains("CONSENSUS_SAFETY_HALT"));
    }

    #[test]
    fn conflicting_verified_boc_enters_durable_safety_halt_before_more_signing() {
        let mut fixture = crate::etdag::tests::fixture(6, None);
        let first = crate::etdag::tests::complete_protected_input(&mut fixture);
        let second = crate::etdag::tests::complete_protected_input(&mut fixture);
        assert_ne!(first.boc.digest().unwrap(), second.boc.digest().unwrap());

        let verifier = fixture.signer.verifier();
        let protocol = ProtocolConfig::testnet_v3();
        let mut consensus = ProofOfSynergyBft::new_with_signing_authority(
            verifier.clone(),
            fixture.validator_set.clone(),
            fixture.cluster_map.clone(),
            protocol,
            temp_signing_authority("boc-safety-halt"),
        );
        let parameters = EtdagParameters::default();
        first
            .verify_and_extract_transactions(
                &verifier,
                &fixture.context,
                &fixture.validator_set,
                &fixture.cluster_map,
                &parameters,
            )
            .unwrap();
        second
            .verify_and_extract_transactions(
                &verifier,
                &fixture.context,
                &fixture.validator_set,
                &fixture.cluster_map,
                &parameters,
            )
            .unwrap();

        consensus
            .observe_valid_boc(&first, &fixture.context)
            .unwrap();
        assert!(consensus
            .observe_valid_boc(&second, &fixture.context)
            .unwrap_err()
            .contains("CONFLICTING_VALID_BOC"));
        assert_eq!(
            consensus
                .signing_authority
                .safety_halt_incidents()
                .unwrap()
                .len(),
            1
        );
        assert!(consensus
            .signing_authority
            .require_signing_allowed()
            .unwrap_err()
            .contains("CONSENSUS_SAFETY_HALT"));
    }

    #[test]
    fn wrong_chain_network_proposer_and_roots_are_rejected() {
        let (mut signer, set, cluster, protocol) = setup_validators();
        let verifier = signer.verifier();
        let mut consensus =
            ProofOfSynergyBft::new(&verifier, set.clone(), cluster.clone(), protocol.clone());
        let ctx = context(&set, &cluster, &protocol);
        let wrong_proposer = set.validators[0].clone();
        assert!(consensus
            .propose_block(
                &mut signer,
                &wrong_proposer,
                Vec::new(),
                &ctx,
                &empty_state(),
                Hash::zero()
            )
            .is_err());

        let proposer = consensus
            .proposer_for(&ctx.height_context, Round(0))
            .unwrap();
        let mut block = consensus
            .propose_block(
                &mut signer,
                &proposer,
                Vec::new(),
                &ctx,
                &empty_state(),
                Hash::zero(),
            )
            .unwrap();
        block.header.tx_order_root = Hash::from_domain_bytes("bad", b"root");
        let dag = DagMempool::new(&verifier, Epoch(0), Height(0));
        assert!(consensus
            .validate_proposal(&block, &ctx, &empty_state(), &dag)
            .is_err());

        let mut bad_ctx = ctx.clone();
        bad_ctx.height_context.chain_id = ChainId(999);
        assert!(consensus
            .propose_block(
                &mut signer,
                &proposer,
                Vec::new(),
                &bad_ctx,
                &empty_state(),
                Hash::zero()
            )
            .is_err());
    }

    #[test]
    fn shadow_validator_signature_cannot_form_qc() {
        let (mut signer, mut set, cluster, protocol) = setup_validators();
        let verifier = signer.verifier();
        let ctx = context(&set, &cluster, &protocol);
        let mut active_consensus =
            ProofOfSynergyBft::new(&verifier, set.clone(), cluster.clone(), protocol.clone());
        let proposer = active_consensus
            .proposer_for(&ctx.height_context, Round(0))
            .unwrap();
        let block = active_consensus
            .propose_block(
                &mut signer,
                &proposer,
                Vec::new(),
                &ctx,
                &empty_state(),
                Hash::zero(),
            )
            .unwrap();

        set.validators[0].status = ValidatorStatus::Shadow;
        let mut consensus = ProofOfSynergyBft::new(&verifier, set.clone(), cluster, protocol);
        assert!(consensus
            .validation_vote(&mut signer, &set.validators[0], &block, &ctx.height_context,)
            .is_err());
    }

    #[test]
    fn wrong_phase_signature_is_rejected() {
        let (mut signer, set, cluster, protocol) = setup_validators();
        let verifier = signer.verifier();
        let mut consensus =
            ProofOfSynergyBft::new(&verifier, set.clone(), cluster, protocol.clone());
        let ctx = context(&set, &consensus.cluster_map, &protocol);
        let proposer = consensus
            .proposer_for(&ctx.height_context, Round(0))
            .unwrap();
        let block = consensus
            .propose_block(
                &mut signer,
                &proposer,
                Vec::new(),
                &ctx,
                &empty_state(),
                Hash::zero(),
            )
            .unwrap();
        let mut validation_vote = consensus
            .validation_vote(&mut signer, &set.validators[0], &block, &ctx.height_context)
            .unwrap();
        validation_vote.phase = VotePhase::Finality;
        assert!(consensus
            .collect_votes(&[validation_vote], &ctx.height_context, VotePhase::Finality,)
            .unwrap_err()
            .contains("signature"));
    }

    #[test]
    fn finality_slot_rejects_sibling_after_tc_and_leader_change() {
        let (mut signer, set, cluster, protocol) = setup_validators();
        let verifier = signer.verifier();
        let mut consensus =
            ProofOfSynergyBft::new(&verifier, set.clone(), cluster.clone(), protocol.clone());
        let ctx0 = context(&set, &cluster, &protocol);
        let proposer0 = consensus
            .proposer_for(&ctx0.height_context, Round(0))
            .unwrap();
        let block_a = consensus
            .propose_block(
                &mut signer,
                &proposer0,
                Vec::new(),
                &ctx0,
                &empty_state(),
                Hash::zero(),
            )
            .unwrap();
        let validation_a = set.validators[0..5]
            .iter()
            .map(|validator| {
                consensus
                    .validation_vote(&mut signer, validator, &block_a, &ctx0.height_context)
                    .unwrap()
            })
            .collect::<Vec<_>>();
        let vc_a = consensus
            .form_vc(&validation_a, &ctx0.height_context)
            .unwrap();
        consensus
            .finality_vote(
                &mut signer,
                &set.validators[0],
                &block_a,
                &vc_a,
                &ctx0.height_context,
            )
            .unwrap();

        let timeout_votes = set.validators[0..5]
            .iter()
            .map(|validator| {
                consensus
                    .timeout_vote(&mut signer, validator, &ctx0.height_context, Round(0), None)
                    .unwrap()
            })
            .collect::<Vec<_>>();
        let tc = consensus
            .form_tc(&timeout_votes, &ctx0.height_context)
            .unwrap();
        assert_eq!(
            consensus
                .advance_round_after_tc(&tc, &ctx0.height_context, Round(0))
                .unwrap(),
            Round(1)
        );

        let mut ctx1 = ctx0.clone();
        ctx1.round = Round(1);
        ctx1.evidence_root = Hash::from_domain_bytes("sibling", b"candidate-b");
        let proposer1 = consensus
            .proposer_for(&ctx1.height_context, Round(1))
            .unwrap();
        let block_b = consensus
            .propose_block(
                &mut signer,
                &proposer1,
                Vec::new(),
                &ctx1,
                &empty_state(),
                Hash::zero(),
            )
            .unwrap();
        assert_ne!(
            block_a.candidate_id().unwrap(),
            block_b.candidate_id().unwrap()
        );
        let validation_b = set.validators[0..5]
            .iter()
            .map(|validator| {
                consensus
                    .validation_vote(&mut signer, validator, &block_b, &ctx1.height_context)
                    .unwrap()
            })
            .collect::<Vec<_>>();
        let vc_b = consensus
            .form_vc(&validation_b, &ctx1.height_context)
            .unwrap();
        let conflict = consensus
            .finality_vote(
                &mut signer,
                &set.validators[0],
                &block_b,
                &vc_b,
                &ctx1.height_context,
            )
            .unwrap_err();
        assert!(conflict.contains("CONSENSUS_SIGNING_CONFLICT"));
    }

    #[test]
    fn prepared_candidate_is_carried_forward_exactly_after_tc() {
        let (mut signer, set, cluster, protocol) = setup_validators();
        let verifier = signer.verifier();
        let mut consensus =
            ProofOfSynergyBft::new(&verifier, set.clone(), cluster.clone(), protocol.clone());
        let ctx0 = context(&set, &cluster, &protocol);
        let proposer0 = consensus
            .proposer_for(&ctx0.height_context, Round(0))
            .unwrap();
        let block = consensus
            .propose_block(
                &mut signer,
                &proposer0,
                Vec::new(),
                &ctx0,
                &empty_state(),
                Hash::zero(),
            )
            .unwrap();
        let validation_votes = set.validators[0..5]
            .iter()
            .map(|validator| {
                consensus
                    .validation_vote(&mut signer, validator, &block, &ctx0.height_context)
                    .unwrap()
            })
            .collect::<Vec<_>>();
        let vc = consensus
            .form_vc(&validation_votes, &ctx0.height_context)
            .unwrap();
        let timeout_votes = set.validators[0..5]
            .iter()
            .map(|validator| {
                consensus
                    .timeout_vote(
                        &mut signer,
                        validator,
                        &ctx0.height_context,
                        Round(0),
                        Some(&vc),
                    )
                    .unwrap()
            })
            .collect::<Vec<_>>();
        let tc = consensus
            .form_tc(&timeout_votes, &ctx0.height_context)
            .unwrap();
        consensus
            .advance_round_after_tc(&tc, &ctx0.height_context, Round(0))
            .unwrap();

        let next_proposer = consensus
            .proposer_for(&ctx0.height_context, Round(1))
            .unwrap();
        let carried = consensus
            .carry_forward_prepared_candidate(
                &mut signer,
                &block,
                &vc,
                &tc,
                &next_proposer,
                &ctx0.height_context,
            )
            .unwrap();
        assert_eq!(carried.header.round, Round(1));
        assert_eq!(
            carried.candidate_id().unwrap(),
            block.candidate_id().unwrap()
        );

        let mut sibling_context = ctx0.clone();
        sibling_context.round = Round(1);
        sibling_context.evidence_root = Hash::from_domain_bytes("sibling", b"forbidden");
        assert!(consensus
            .propose_block(
                &mut signer,
                &next_proposer,
                Vec::new(),
                &sibling_context,
                &empty_state(),
                Hash::zero(),
            )
            .unwrap_err()
            .contains("carried forward exactly"));
    }

    #[test]
    fn protected_proposal_is_exactly_boc_reveal_and_manifest_bound() {
        let mut fixture = crate::etdag::tests::fixture(6, None);
        let protected = crate::etdag::tests::complete_protected_input(&mut fixture);
        let verifier = fixture.signer.verifier();
        let protocol = ProtocolConfig::testnet_v3();
        let mut consensus = ProofOfSynergyBft::new(
            &verifier,
            fixture.validator_set.clone(),
            fixture.cluster_map.clone(),
            protocol,
        );
        let context = LocalConsensusContext {
            height_context: fixture.height_context.clone(),
            latest_finalized_height: Height(fixture.height_context.height.0 - 1),
            latest_finalized_block_hash: Hash::from_domain_bytes(
                "test-finalized-block",
                b"protected-parent",
            ),
            latest_finalized_state_root: Hash::zero(),
            round: Round(0),
            evidence_root: Hash::from_domain_bytes("test-evidence", b"protected"),
            app_version: 2,
            execution_version: 2,
            dag_version: 2,
            aegis_pqvm_version: "aegis-pqvm-etdag-v2".to_string(),
        };
        let proposer = consensus
            .proposer_for(&context.height_context, context.round)
            .unwrap();
        let block = consensus
            .propose_protected_block(
                &mut fixture.signer,
                &proposer,
                &protected,
                &fixture.context,
                &context,
                &ExecutionState::new(),
                &EtdagParameters::default(),
            )
            .unwrap();
        assert_eq!(block.header.version, 2);
        assert!(block.header.protected_batch.is_some());
        consensus
            .validate_protected_proposal(
                &block,
                &protected,
                &fixture.context,
                &context,
                &ExecutionState::new(),
                &EtdagParameters::default(),
            )
            .unwrap();

        let mut substituted = block.clone();
        substituted.transactions[0].receiver_uma_or_account = "attacker".to_string();
        assert!(consensus
            .validate_protected_proposal(
                &substituted,
                &protected,
                &fixture.context,
                &context,
                &ExecutionState::new(),
                &EtdagParameters::default(),
            )
            .unwrap_err()
            .contains("exact BOC public reveal"));

        let mut wrong_manifest = block.clone();
        wrong_manifest
            .header
            .protected_batch
            .as_mut()
            .unwrap()
            .execution_manifest_root =
            EtdagDigest::from_domain_bytes("wrong-manifest", b"replacement").0;
        assert!(consensus
            .validate_protected_proposal(
                &wrong_manifest,
                &protected,
                &fixture.context,
                &context,
                &ExecutionState::new(),
                &EtdagParameters::default(),
            )
            .unwrap_err()
            .contains("ETDAG header commitment mismatch"));
    }
}
