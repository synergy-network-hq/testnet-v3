//! Stateful runtime core for `coordinated_round_robin_v1`.
//!
//! This module owns the temporary mode's lifecycle only: signed assignments,
//! producer-package verification, deterministic execution, Val1's one commit,
//! and separate durable finality. It intentionally exposes no vote, QC, VC,
//! TC, aggregation, or coordinator-election operation.

use crate::consensus::coordinated_finality_store::{
    CoordinatedFinalityRecord, CoordinatedFinalityStore,
};
use crate::consensus::coordinated_round_robin::{
    CoordinatedConsensusVerifier, CoordinatedProposal, CoordinatedRoundRobinConfig,
    CoordinatorCommit, CoordinatorState, CoordinatorStateStore, ProducerAssignment,
    COORDINATED_ASSIGNMENT_DOMAIN, COORDINATED_COMMIT_DOMAIN,
};
use crate::consensus::signing_authority::{
    CoordinatedSigningAuthorization, CoordinatedSigningPhase, DurableConsensusSigningAuthority,
};
use crate::crypto::aegis_pqvm::AegisPqvmSigner;
use crate::execution::{compute_state_root_after, execute_block, ExecutionState};
use crate::p2p::messages::CoordinatedCommittedBlockPackage;
use crate::synergy_types::{
    AegisPqKeyId, Block, ChainId, Epoch, Hash, Height, NetworkId, Round, ValidatorId, ValidatorSet,
};

/// The outcome of applying one fully verified coordinated finality package.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoordinatedRuntimeFinality {
    pub record: CoordinatedFinalityRecord,
    pub block_hash: Hash,
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
        self.install_assignment(assignment)
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
        self.accept_assignment(&package.assignment)?;
        self.verifier.verify_committed_block_package(&package)?;
        let next_execution_state =
            execute_coordinated_block(&self.execution_state, &package.block)?;
        self.finalize_verified_package(package, next_execution_state)
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
        let template = self.coordinator_state.assignment_template(
            &self.config,
            assignment.epoch,
            assignment.intended_block_timestamp_ms,
        )?;
        if template.signing_hash()? != assignment.signing_hash()? {
            return Err(
                "coordinated assignment does not match the local persistent rotation state"
                    .to_string(),
            );
        }
        let mut candidate_state = self.coordinator_state.clone();
        let installed = candidate_state.issue_assignment(
            &self.config,
            assignment.epoch,
            assignment.intended_block_timestamp_ms,
            assignment.coordinator_signature.clone(),
        )?;
        if installed != *assignment {
            return Err(
                "coordinated assignment persistence returned different durable evidence"
                    .to_string(),
            );
        }
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

/// Repairs only the safe, one-record persistence gap where separate finality
/// was fsynced but the already-pending coordinator state was not. Anything
/// broader is ambiguous (for example, it could omit locally recorded timeout
/// skips) and therefore remains a startup failure instead of inventing state.
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
    if state.last_finalized_height.saturating_add(1) != latest.height.0 {
        return Err(
            "coordinated state does not have the one safe finality record needed for recovery"
                .to_string(),
        );
    }
    if let Some(previous) = records.iter().rev().nth(1) {
        let previous_hash = Hash::from_hex(&previous.block_id.0).map_err(|error| {
            format!("coordinated finality predecessor block ID is not a hash: {error}")
        })?;
        if state.last_finalized_block_hash != previous_hash
            || state.last_finality_reference
                != previous.package.coordinator_commit.signing_hash()?
        {
            return Err(
                "coordinated recovery state does not match the persisted predecessor".to_string(),
            );
        }
    } else if state.last_finalized_height >= first_coordinated_height.0 {
        return Err(
            "coordinated recovery has no persisted predecessor for its coordinator state"
                .to_string(),
        );
    }
    verifier.verify_committed_block_package(&latest.package)?;
    let mut repaired = state.clone();
    if !repaired.record_commit(config, latest.package.coordinator_commit.clone())? {
        return Err(
            "coordinated recovery found an already-recorded commit with an inconsistent finality tip"
                .to_string(),
        );
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
            ValidatorId("validator-1".to_string()),
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
                dag_frontier_root: hash("empty-dag-frontier"),
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
            receipt_root,
            state_root,
            producer_id: assignment.assigned_producer_id.clone(),
            assignment_hash: assignment.signing_hash().expect("assignment hash"),
            producer_signature: block.proposer_signature.clone(),
        };
        (proposal, block)
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
    fn coordinator_finalizes_signed_block_and_repairs_a_persisted_finality_gap() {
        let mut runtime = fixture();
        let assignment = runtime
            .issue_signed_assignment(2_000)
            .expect("Val1 signs assignment");
        let pending_state = runtime.coordinator_state().clone();
        let (proposal, block) = signed_empty_proposal(&mut runtime, &assignment);
        let package = runtime
            .commit_executed_proposal(&assignment, &proposal, &block)
            .expect("Val1 verifies, executes, and commits the producer block");
        assert_eq!(package.block.header.height, Height(42));
        assert_eq!(runtime.coordinator_state().last_finalized_height, 42);
        assert!(runtime.coordinator_state().pending_assignment.is_none());

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
        assert_eq!(restored.coordinator_state().last_finalized_height, 42);
        assert_eq!(
            restored.coordinator_state().last_finalized_block_hash,
            package.coordinator_commit.block_hash
        );
    }
}
