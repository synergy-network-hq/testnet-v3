//! Verified, non-signing `coordinated_round_robin_v1` finality replication.
//!
//! Relayers, RPC gateways, and indexers need the same finalized-chain
//! evidence as validators, but they must not receive a validator key, a
//! coordinator state file, a producer assignment mailbox, or any ability to
//! produce a P1 signature. This module accepts only a bounded sequence of
//! already-finalized coordinator packages, independently verifies Val1 and
//! producer signatures, deterministically executes every block, and persists
//! the exact package only after those checks pass.

use crate::consensus::coordinated_finality_store::{
    CoordinatedFinalityRecord, CoordinatedFinalityStore,
};
use crate::consensus::coordinated_round_robin::{
    CoordinatedConsensusVerifier, CoordinatedRoundRobinConfig,
};
use crate::consensus::testnet_v3_bootstrap::load_testnet_v3_genesis_bootstrap;
use crate::execution::{
    compute_state_root_after, execute_block, install_finalized_execution_state_snapshot,
    publish_finalized_execution_state_snapshot, remove_finalized_execution_state_snapshot,
    ExecutionState,
};
use crate::synergy_types::{Hash, Height, ValidatorSet};
use std::sync::{Mutex, OnceLock};

/// Maximum number of independently verified P1 finality records accepted or
/// returned in a single service-observer segment. Larger histories must be
/// transferred as exact consecutive segments.
pub const MAX_COORDINATED_FINALITY_OBSERVER_RECORDS: usize = 32;

/// Public, finalized-only dependencies for a non-signing P1 observer.
///
/// There is deliberately no validator ID, private key, signing authority, or
/// coordinator state in this structure. The constructor binds all verification
/// to the finalized six-validator set and the immutable migration anchor.
#[derive(Debug, Clone)]
pub struct CoordinatedFinalityObserverInputs {
    pub config: CoordinatedRoundRobinConfig,
    pub validator_set: ValidatorSet,
    pub verifier: crate::crypto::aegis_pqvm::AegisPqvmVerifier,
    pub migration_parent_block_hash: Hash,
    pub migration_parent_state_root: Hash,
    pub first_coordinated_height: Height,
    pub execution_state: ExecutionState,
    pub finality_store: CoordinatedFinalityStore,
}

/// Finalized-only P1 replica for a relayer or public service role.
#[derive(Debug)]
pub struct CoordinatedFinalityObserver {
    config: CoordinatedRoundRobinConfig,
    verifier: CoordinatedConsensusVerifier,
    execution_state: ExecutionState,
    finality_store: CoordinatedFinalityStore,
    next_missing_height: Height,
}

// A public support process owns at most one finalized observer. Installing it
// before P2P startup makes malformed durable finality fail closed rather than
// exposing a misleading public height or admitting any signing path.
static COORDINATED_FINALITY_OBSERVER_INGRESS: OnceLock<Mutex<Option<CoordinatedFinalityObserver>>> =
    OnceLock::new();

fn observer_ingress() -> &'static Mutex<Option<CoordinatedFinalityObserver>> {
    COORDINATED_FINALITY_OBSERVER_INGRESS.get_or_init(|| Mutex::new(None))
}

/// Installs the sole P1 support-role finality observer for this process.
pub fn install_coordinated_finality_observer(
    observer: CoordinatedFinalityObserver,
) -> Result<(), String> {
    let execution_state = observer.finalized_execution_state_snapshot();
    let mut slot = observer_ingress()
        .lock()
        .map_err(|_| "coordinated finality observer ingress lock is poisoned".to_string())?;
    if slot.is_some() {
        return Err("coordinated finality observer ingress is already installed".to_string());
    }
    install_finalized_execution_state_snapshot(execution_state).map_err(|error| {
        format!("coordinated finality observer cannot install execution snapshot: {error}")
    })?;
    *slot = Some(observer);
    Ok(())
}

/// Removes the public support observer during a controlled role shutdown.
pub fn remove_coordinated_finality_observer() -> Result<(), String> {
    let mut slot = observer_ingress()
        .lock()
        .map_err(|_| "coordinated finality observer ingress lock is poisoned".to_string())?;
    *slot = None;
    remove_finalized_execution_state_snapshot();
    Ok(())
}

/// Returns the exact next P1 height required by the installed observer.
pub fn coordinated_finality_observer_next_missing_height() -> Option<Height> {
    observer_ingress().lock().ok().and_then(|slot| {
        slot.as_ref()
            .map(CoordinatedFinalityObserver::next_missing_height)
    })
}

/// Imports a bounded P1 finality segment into the installed support observer.
/// Execution state becomes publicly visible only after each package has passed
/// independent signature, structure, successor, execution, and durable-store
/// verification.
pub fn import_coordinated_finality_observer_records(
    records: &[CoordinatedFinalityRecord],
) -> Result<usize, String> {
    let mut slot = observer_ingress()
        .lock()
        .map_err(|_| "coordinated finality observer ingress lock is poisoned".to_string())?;
    let observer = slot
        .as_mut()
        .ok_or_else(|| "coordinated finality observer ingress is not installed".to_string())?;
    let imported = observer.import_records(records)?;
    if !publish_finalized_execution_state_snapshot(&observer.execution_state) {
        return Err(
            "coordinated finality observer finalized execution snapshot is unexpectedly unavailable"
                .to_string(),
        );
    }
    Ok(imported)
}

/// Returns a bounded segment from this support role's independently replayed
/// durable prefix. This is only a relayer-to-public-service synchronization
/// surface; it cannot construct or authorize consensus messages.
pub fn coordinated_finality_observer_snapshot_from(
    next_height: Height,
) -> Result<Vec<CoordinatedFinalityRecord>, String> {
    let slot = observer_ingress()
        .lock()
        .map_err(|_| "coordinated finality observer ingress lock is poisoned".to_string())?;
    let observer = slot
        .as_ref()
        .ok_or_else(|| "coordinated finality observer ingress is not installed".to_string())?;
    observer.bounded_snapshot_from(next_height)
}

/// Creates a P1 support observer from the process's canonical finalized
/// Genesis and the release-validated P1 configuration. The finality path is
/// fixed under the controller-managed data root so a controlled reset cannot
/// accidentally retain observer block evidence elsewhere.
pub fn coordinated_finality_observer_from_canonical_finalized_genesis(
    config: CoordinatedRoundRobinConfig,
) -> Result<CoordinatedFinalityObserver, String> {
    let (
        validator_set,
        verifier,
        migration_parent_block_hash,
        migration_parent_state_root,
        execution_state,
    ) = canonical_observer_inputs()?;
    let finality_store = CoordinatedFinalityStore::at_path(
        crate::utils::resolve_data_path("data/coordinated-round-robin-finality.json"),
        migration_parent_block_hash,
        migration_parent_state_root,
        Height(1),
    )?;
    CoordinatedFinalityObserver::from_finalized_inputs(CoordinatedFinalityObserverInputs {
        config,
        validator_set,
        verifier,
        migration_parent_block_hash,
        migration_parent_state_root,
        first_coordinated_height: Height(1),
        execution_state,
        finality_store,
    })
}

/// Returns a bounded P1 finality segment directly from a validator's canonical
/// durable journal. It has no signing side effect and is intended only for an
/// authenticated validator-VPN relayer request.
pub fn canonical_coordinated_finality_snapshot_from(
    config: &CoordinatedRoundRobinConfig,
    next_height: Height,
) -> Result<Vec<CoordinatedFinalityRecord>, String> {
    let (_, _, migration_parent_block_hash, migration_parent_state_root, _) =
        canonical_observer_inputs()?;
    let store = CoordinatedFinalityStore::at_path(
        crate::utils::resolve_data_path("data/coordinated-round-robin-finality.json"),
        migration_parent_block_hash,
        migration_parent_state_root,
        Height(1),
    )?;
    store.recover(config).map(|records| {
        records
            .into_iter()
            .filter(|record| record.height.0 >= next_height.0)
            .take(MAX_COORDINATED_FINALITY_OBSERVER_RECORDS)
            .collect()
    })
}

fn canonical_observer_inputs() -> Result<
    (
        ValidatorSet,
        crate::crypto::aegis_pqvm::AegisPqvmVerifier,
        Hash,
        Hash,
        ExecutionState,
    ),
    String,
> {
    let genesis = crate::genesis::canonical_genesis().map_err(|error| {
        format!("coordinated finality observer cannot load canonical Genesis: {error}")
    })?;
    let bootstrap = load_testnet_v3_genesis_bootstrap(genesis).map_err(|error| {
        format!("coordinated finality observer cannot derive finalized Genesis bootstrap: {error}")
    })?;
    let migration_parent_block_hash = Hash::from_hex(genesis.hash()).map_err(|error| {
        format!("coordinated finality observer Genesis hash is invalid: {error}")
    })?;
    let migration_parent_state_root = genesis
        .value()
        .get("execution")
        .and_then(|execution| execution.get("genesis_execution_state_root"))
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| {
            "coordinated finality observer Genesis omits execution.genesis_execution_state_root"
                .to_string()
        })
        .and_then(|root| {
            Hash::from_hex(root).map_err(|error| {
                format!("coordinated finality observer Genesis execution root is invalid: {error}")
            })
        })?;
    let execution_state =
        crate::testnet_v3_execution_bootstrap::load_finalized_testnet_v3_genesis_execution_state(
            genesis,
        )
        .map_err(|error| {
            format!(
                "coordinated finality observer requires finalized Genesis execution state: {error}"
            )
        })?;
    Ok((
        bootstrap.validator_set,
        bootstrap.verifier,
        migration_parent_block_hash,
        migration_parent_state_root,
        execution_state,
    ))
}

impl CoordinatedFinalityObserver {
    /// Constructs a non-signing observer solely from finalized public inputs.
    /// Existing durable finality is replayed before startup completes.
    pub fn from_finalized_inputs(
        inputs: CoordinatedFinalityObserverInputs,
    ) -> Result<Self, String> {
        inputs.config.validate()?;
        if inputs.migration_parent_block_hash.is_zero()
            || inputs.migration_parent_state_root.is_zero()
            || inputs.first_coordinated_height.0 == 0
        {
            return Err(
                "coordinated finality observer requires immutable non-zero migration anchors"
                    .to_string(),
            );
        }
        if inputs.finality_store.migration_parent_block_hash() != inputs.migration_parent_block_hash
            || inputs.finality_store.migration_parent_state_root()
                != inputs.migration_parent_state_root
            || inputs.finality_store.first_coordinated_height() != inputs.first_coordinated_height
        {
            return Err(
                "coordinated finality observer store anchor disagrees with finalized inputs"
                    .to_string(),
            );
        }
        let verifier = CoordinatedConsensusVerifier::new(
            inputs.config.clone(),
            &inputs.validator_set,
            inputs.verifier,
        )?;
        let initial_root = compute_state_root_after(&inputs.execution_state)?;
        if initial_root != inputs.migration_parent_state_root {
            return Err(
                "coordinated finality observer execution state disagrees with the migration anchor"
                    .to_string(),
            );
        }

        let records = inputs.finality_store.recover(&inputs.config)?;
        let mut execution_state = inputs.execution_state;
        let mut next_missing_height = inputs.first_coordinated_height;
        for record in &records {
            verify_record(&verifier, &execution_state, record, next_missing_height)?;
            execution_state = execute_coordinated_block(&execution_state, &record.package.block)?;
            next_missing_height = Height(
                next_missing_height
                    .0
                    .checked_add(1)
                    .ok_or_else(|| "coordinated finality observer height overflow".to_string())?,
            );
        }
        Ok(Self {
            config: inputs.config,
            verifier,
            execution_state,
            finality_store: inputs.finality_store,
            next_missing_height,
        })
    }

    /// Returns the first immutable P1 height not yet locally finalized.
    pub fn next_missing_height(&self) -> Height {
        self.next_missing_height
    }

    /// Returns this observer's durable finality store.
    pub fn finality_store(&self) -> &CoordinatedFinalityStore {
        &self.finality_store
    }

    /// Reads at most [`MAX_COORDINATED_FINALITY_OBSERVER_RECORDS`] records from
    /// the already independently replayed durable prefix.
    pub fn bounded_snapshot_from(
        &self,
        next_height: Height,
    ) -> Result<Vec<CoordinatedFinalityRecord>, String> {
        self.finality_store.recover(&self.config).map(|records| {
            records
                .into_iter()
                .filter(|record| record.height.0 >= next_height.0)
                .take(MAX_COORDINATED_FINALITY_OBSERVER_RECORDS)
                .collect()
        })
    }

    /// Independently verifies and imports one bounded, consecutive segment.
    /// Exact prior records are idempotent; gaps, rewrites, alternative
    /// coordinator evidence, wrong signatures, and execution divergence fail
    /// closed before the durable store changes.
    pub fn import_records(
        &mut self,
        records: &[CoordinatedFinalityRecord],
    ) -> Result<usize, String> {
        if records.is_empty() || records.len() > MAX_COORDINATED_FINALITY_OBSERVER_RECORDS {
            return Err(
                "coordinated finality observer segment has an invalid record count".to_string(),
            );
        }

        let mut imported = 0usize;
        for record in records {
            if record.height.0 < self.next_missing_height.0 {
                let existing = self
                    .finality_store
                    .at_height(&self.config, record.height)?
                    .ok_or_else(|| {
                        "coordinated finality observer record is absent from its claimed durable prefix"
                            .to_string()
                    })?;
                if existing != *record {
                    return Err(
                        "COORDINATED_FINALITY_OBSERVER_SOURCE_CONFLICT: supplied record conflicts with durable finality"
                            .to_string(),
                    );
                }
                continue;
            }
            verify_record(
                &self.verifier,
                &self.execution_state,
                record,
                self.next_missing_height,
            )?;
            let next_execution_state =
                execute_coordinated_block(&self.execution_state, &record.package.block)?;
            let durable = self
                .finality_store
                .append_verified_finality(&self.config, &record.package)?;
            if durable != *record {
                return Err(
                    "COORDINATED_FINALITY_OBSERVER_SOURCE_CONFLICT: durable record differs from independently verified finality"
                        .to_string(),
                );
            }
            self.execution_state = next_execution_state;
            self.next_missing_height = Height(
                self.next_missing_height
                    .0
                    .checked_add(1)
                    .ok_or_else(|| "coordinated finality observer height overflow".to_string())?,
            );
            imported = imported.saturating_add(1);
        }
        Ok(imported)
    }

    fn finalized_execution_state_snapshot(&self) -> ExecutionState {
        self.execution_state.clone()
    }
}

fn verify_record(
    verifier: &CoordinatedConsensusVerifier,
    execution_state: &ExecutionState,
    record: &CoordinatedFinalityRecord,
    expected_height: Height,
) -> Result<(), String> {
    if record.height != expected_height || record.package.block.header.height != expected_height {
        return Err(
            "coordinated finality observer segment is not an exact successor of the durable tip"
                .to_string(),
        );
    }
    let block_id = record.package.block.block_id()?;
    let block_hash = Hash::from_hex(&block_id.0).map_err(|error| {
        format!("coordinated finality observer block ID is not a hash: {error}")
    })?;
    if record.block_id != block_id
        || record.coordinator_commit_hash != record.package.coordinator_commit.signing_hash()?
        || record.package.coordinator_commit.block_hash != block_hash
    {
        return Err(
            "coordinated finality observer record does not bind its coordinator commitment"
                .to_string(),
        );
    }
    verifier.verify_committed_block_package(&record.package)?;
    let current_root = compute_state_root_after(execution_state)?;
    if current_root != record.package.block.header.state_root_before {
        return Err(
            "coordinated finality observer block does not extend the supplied execution-state root"
                .to_string(),
        );
    }
    Ok(())
}

fn execute_coordinated_block(
    state: &ExecutionState,
    block: &crate::synergy_types::Block,
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
            "coordinated finality observer finalized block execution roots do not match the header"
                .to_string(),
        );
    }
    Ok(execution.state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::coordinated_round_robin::{
        CoordinatorState, CoordinatorStateStore, COORDINATED_ROUND_ROBIN_V1,
    };
    use crate::consensus::coordinated_runtime::CoordinatedRuntime;
    use crate::consensus::signing_authority::DurableConsensusSigningAuthority;
    use crate::consensus_parameters::ConsensusParameterRoot;
    use crate::crypto::aegis_pqvm::{AegisPqvmSigner, SYNERGY_BLOCK_V1};
    use crate::dag_mempool::compute_tx_order_root;
    use crate::execution::{compute_receipt_root, compute_state_root_after};
    use crate::p2p::messages::CoordinatedConsensusMessage;
    use crate::synergy_types::{
        AegisPqKeyRole, AegisPqSignature, Block, CanonicalSerialize, ChainId, ClusterId, Epoch,
        Hash, NetworkId, Round, UmaId, ValidatorId, ValidatorRecord, ValidatorStatus,
    };
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn hash(label: &str) -> Hash {
        Hash::from_domain_bytes(
            "SYNERGY_COORDINATED_FINALITY_OBSERVER_TEST_V1",
            label.as_bytes(),
        )
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

    struct SourceFixture {
        validator_set: ValidatorSet,
        verifier: crate::crypto::aegis_pqvm::AegisPqvmVerifier,
        migration_parent_block_hash: Hash,
        migration_parent_state_root: Hash,
        source_store: CoordinatedFinalityStore,
        work_root: PathBuf,
    }

    fn source_fixture() -> SourceFixture {
        let mut signer = AegisPqvmSigner::initialize_required().expect("Aegis signer");
        let mut validators = Vec::new();
        for index in 1..=6 {
            let validator_id = ValidatorId(format!("validator-{index}"));
            let uma_id = UmaId(format!("coordinated-observer-uma-{index}"));
            let key_id = signer
                .generate_and_register_key(
                    &uma_id.0,
                    vec![AegisPqKeyRole::ConsensusProposer],
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
        let migration_parent_block_hash = hash("migration-parent");
        let execution_state = ExecutionState::new();
        let migration_parent_state_root =
            compute_state_root_after(&execution_state).expect("state root");
        let migration_state = CoordinatorState::from_migration_anchor(
            0,
            migration_parent_block_hash,
            hash("migration-finality-reference"),
        )
        .expect("migration state");
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let work_root = crate::utils::test_temp_root(format!(
            "coordinated-finality-observer-{}-{nonce}",
            std::process::id()
        ));
        let source_store = CoordinatedFinalityStore::at_path(
            work_root.join("source-finality.json"),
            migration_parent_block_hash,
            migration_parent_state_root,
            Height(1),
        )
        .expect("source finality store");
        let verifier = signer.verifier();
        let mut assignment = migration_state
            .assignment_template(&config(), 0, 2_000)
            .expect("assignment template");
        let coordinator_key = validator_set
            .validators
            .iter()
            .find(|validator| validator.validator_id.0 == "validator-1")
            .expect("coordinator")
            .consensus_public_key
            .key_id
            .clone();
        assignment.coordinator_signature = signer
            .sign_domain(
                crate::consensus::coordinated_round_robin::COORDINATED_ASSIGNMENT_DOMAIN,
                &assignment.signing_hash().expect("assignment hash").0,
                &coordinator_key,
            )
            .expect("sign assignment");
        let producer = validator_set
            .validators
            .iter()
            .find(|validator| validator.validator_id.0 == assignment.assigned_producer_id)
            .expect("producer")
            .clone();
        let tx_root = compute_tx_order_root(&[]).expect("empty transaction root");
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
                height_context_root: hash("height-context"),
                parent_block_hash: assignment.parent_block_hash,
                parent_state_root: migration_parent_state_root,
                last_finalized_qc_hash: Hash::zero(),
                proposer_validator_id: producer.validator_id.clone(),
                proposer_uma_id: producer.validator_uma_id.clone(),
                proposer_key_id: producer.consensus_public_key.key_id.clone(),
                active_validator_set_hash: hash("active-set"),
                eligible_validator_set_hash: hash("eligible-set"),
                validator_consensus_key_root: hash("key-set"),
                frozen_bonded_weight_root: hash("weight-set"),
                cluster_schedule_version: "coordinated-round-robin-v1".to_string(),
                cluster_map_hash: hash("cluster-map"),
                assigned_cluster_membership_root: hash("cluster-membership"),
                assigned_cluster_validator_count: 6,
                assigned_cluster_total_voting_weight: 6,
                proposer_schedule_hash: hash("producer-schedule"),
                protocol_config_hash: ConsensusParameterRoot::from_canonical_manifest_bytes(
                    b"coordinated-finality-observer-test",
                ),
                cryptographic_profile_root: hash("cryptographic-profile"),
                dag_frontier_root:
                    crate::consensus::coordinated_admission::coordinated_dag_frontier_root(
                        assignment.parent_block_hash,
                        tx_root,
                        Hash::zero(),
                    ),
                tx_order_root: tx_root,
                tx_count: 0,
                protected_batch: None,
                evidence_root: assignment.prior_finality_reference,
                state_root_before: migration_parent_state_root,
                state_root_after: migration_parent_state_root,
                receipt_root,
                app_version: 1,
                execution_version: 1,
                dag_version: 1,
                aegis_pqvm_version: "aegis-pqvm".to_string(),
                timestamp_ms_consensus_bounded: assignment.intended_block_timestamp_ms,
            },
            transactions: Vec::new(),
            proposer_signature: AegisPqSignature {
                algorithm: String::new(),
                signature_bytes: Vec::new(),
            },
        };
        block.proposer_signature = signer
            .sign_domain(
                SYNERGY_BLOCK_V1,
                &block.header.canonical_bytes().expect("canonical header"),
                &producer.consensus_public_key.key_id,
            )
            .expect("sign producer block");
        let proposal = crate::consensus::coordinated_round_robin::CoordinatedProposal {
            epoch: assignment.epoch,
            height: assignment.height,
            producer_round: assignment.producer_round,
            parent_block_hash: assignment.parent_block_hash,
            prior_finality_reference: assignment.prior_finality_reference,
            block_hash: Hash::from_hex(&block.block_id().expect("block ID").0).expect("block hash"),
            transaction_root: tx_root,
            transaction_admission_root: Hash::zero(),
            transaction_admissions: Vec::new(),
            receipt_root,
            state_root: migration_parent_state_root,
            producer_id: assignment.assigned_producer_id.clone(),
            assignment_hash: assignment.signing_hash().expect("assignment hash"),
            producer_signature: block.proposer_signature.clone(),
        };
        let mut runtime = CoordinatedRuntime::new(
            config(),
            &validator_set,
            signer.verifier(),
            ValidatorId("validator-1".to_string()),
            signer,
            DurableConsensusSigningAuthority::at_path(work_root.join("signing.json")),
            CoordinatorStateStore::at_path(work_root.join("state.json")).expect("state store"),
            migration_state,
            source_store.clone(),
            execution_state,
        )
        .expect("source runtime");
        let action = runtime
            .handle_authenticated_message(
                &crate::consensus::coordinated_round_robin::AuthenticatedCoordinatedConsensusPeer {
                    validator_id: producer.validator_id,
                    validator_uma_id: producer.validator_uma_id,
                    consensus_key_id: producer.consensus_public_key.key_id,
                },
                CoordinatedConsensusMessage::ProposedBlock {
                    assignment,
                    proposal,
                    block,
                },
            )
            .expect("Val1 commits valid producer package");
        assert!(matches!(
            action,
            crate::consensus::coordinated_runtime::CoordinatedRuntimeAction::BroadcastCommitted(_)
        ));
        SourceFixture {
            verifier,
            validator_set,
            migration_parent_block_hash,
            migration_parent_state_root,
            source_store,
            work_root,
        }
    }

    fn observer_for_source(source: &SourceFixture) -> CoordinatedFinalityObserver {
        let store = CoordinatedFinalityStore::at_path(
            source.work_root.join("observer-finality.json"),
            source.migration_parent_block_hash,
            source.migration_parent_state_root,
            Height(1),
        )
        .expect("observer store");
        CoordinatedFinalityObserver::from_finalized_inputs(CoordinatedFinalityObserverInputs {
            config: config(),
            validator_set: source.validator_set.clone(),
            verifier: source.verifier.clone(),
            migration_parent_block_hash: source.migration_parent_block_hash,
            migration_parent_state_root: source.migration_parent_state_root,
            first_coordinated_height: Height(1),
            execution_state: ExecutionState::new(),
            finality_store: store,
        })
        .expect("non-signing observer startup")
    }

    #[test]
    fn imports_a_verified_finalized_package_without_signing_authority() {
        let source = source_fixture();
        let record = source
            .source_store
            .latest(&config())
            .expect("source finality")
            .expect("source record");
        let mut observer = observer_for_source(&source);

        assert_eq!(observer.next_missing_height(), Height(1));
        assert_eq!(
            observer
                .import_records(&[record.clone()])
                .expect("verified import"),
            1
        );
        assert_eq!(observer.next_missing_height(), Height(2));
        assert_eq!(
            observer
                .finality_store()
                .at_height(&config(), Height(1))
                .expect("observer durable record"),
            Some(record.clone())
        );
        assert_eq!(
            observer
                .import_records(&[record])
                .expect("exact replay is idempotent"),
            0
        );
    }

    #[test]
    fn rejects_a_gap_before_mutating_the_observer_store() {
        let source = source_fixture();
        let mut gap = source
            .source_store
            .latest(&config())
            .expect("source finality")
            .expect("source record");
        gap.height = Height(2);
        let mut observer = observer_for_source(&source);

        let error = observer
            .import_records(&[gap])
            .expect_err("a non-successor package must fail closed");
        assert!(error.contains("exact successor"));
        assert!(observer
            .finality_store()
            .recover(&config())
            .expect("observer store remains readable")
            .is_empty());
    }

    #[test]
    fn rejects_store_anchor_that_differs_from_finalized_inputs() {
        let store = CoordinatedFinalityStore::at_path(
            crate::utils::test_temp_root(format!(
                "coordinated-finality-observer-anchor-{}-{}.json",
                std::process::id(),
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .expect("clock")
                    .as_nanos()
            )),
            hash("store-parent"),
            hash("store-state"),
            Height(1),
        )
        .expect("store");
        let mut signer = AegisPqvmSigner::initialize_required().expect("Aegis signer");
        let mut validators = Vec::new();
        for index in 1..=6 {
            let uma = format!("coordinated-observer-anchor-uma-{index}");
            let key_id = signer
                .generate_and_register_key(&uma, vec![AegisPqKeyRole::ConsensusProposer], Epoch(0))
                .expect("key");
            let key = signer.public_key_record(&key_id).expect("public key");
            validators.push(ValidatorRecord {
                validator_id: ValidatorId(format!("validator-{index}")),
                validator_uma_id: UmaId(uma),
                consensus_public_key: key.clone(),
                peer_public_key: key.clone(),
                operator_public_key: key,
                voting_weight: 1,
                status: ValidatorStatus::Active,
                cluster_id: ClusterId(0),
                activation_epoch: Epoch(0),
            });
        }
        let error =
            CoordinatedFinalityObserver::from_finalized_inputs(CoordinatedFinalityObserverInputs {
                config: config(),
                validator_set: ValidatorSet {
                    epoch: Epoch(0),
                    validators,
                },
                verifier: signer.verifier(),
                migration_parent_block_hash: hash("other-parent"),
                migration_parent_state_root: hash("other-state"),
                first_coordinated_height: Height(1),
                execution_state: ExecutionState::new(),
                finality_store: store,
            })
            .expect_err("anchor mismatch must fail before observer startup");
        assert!(error.contains("store anchor"));
    }
}
