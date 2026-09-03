//! Read-only Testnet-v3 SynQ genesis execution-state bootstrap.
//!
//! A fresh chain must not treat the presence of a `.synq` file as a deployed
//! contract. The legacy pre-approval adapter proves eight identity-assigned
//! artifacts while leaving `synq_contracts` empty. The finalized adapter
//! replays the complete public, signed ceremony operation list embedded in
//! Genesis and verifies its execution root, AIVM root, balances, artifacts,
//! and deployed addresses before returning any state to consensus. A legacy
//! snapshot reader remains only for historical finalized Genesis evidence.

use crate::execution::{compute_state_root_after, ExecutionState, GenesisExecutionSnapshot};
use crate::genesis::GenesisDocument;
use crate::genesis_deployment::{
    compute_genesis_receipt_root, replay_genesis_deployment_from_signed_operations,
    GenesisReplayOperation,
};
use crate::synq_execution::{
    derive_synergy_contract_address_from_deploy_with_identity_address, register_synq_artifact,
    SynQAivmReceiptSummary, SynQArtifactKey, SynQContractArtifact,
};
use crate::testnet_v3_release_approval::{
    TestnetV3GenesisExecutionBundle, TESTNET_V3_GENESIS_EXECUTION_BUNDLE_ARTIFACT_TYPE,
    TESTNET_V3_GENESIS_EXECUTION_BUNDLE_SCHEMA_VERSION,
};
use pqsynq::ContractDeployEnvelope;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Component, Path, PathBuf};

const NATIVE_GENESIS_CONTRACTS: [(&str, &str); 8] = [
    ("validator_registry", "ValidatorRegistry"),
    ("staking", "Staking"),
    ("reward_distributor", "RewardDistributor"),
    ("governance", "Governance"),
    ("treasury", "Treasury"),
    ("synergy_oracle", "SynergyOracle"),
    ("identity", "Identity"),
    ("slashing", "Slashing"),
];

const FINALIZED_NATIVE_GENESIS_CONTRACTS: [(&str, &str); 9] = [
    ("identity", "Identity"),
    ("validator_registry", "ValidatorRegistry"),
    ("staking", "Staking"),
    ("governance", "Governance"),
    ("treasury", "Treasury"),
    ("slashing", "Slashing"),
    ("reward_distributor", "RewardDistributor"),
    ("synergy_oracle", "SynergyOracle"),
    ("team_vesting", "TeamVesting"),
];

const PRE_APPROVAL_STATUS: &str = "address_assigned_artifact_bound_pending_genesis_approval";
const FINALIZED_STATUS: &str = "deployed_initialized_genesis_bound";

/// Artifact-validated, but deliberately *not deployed*, Genesis execution
/// input.  `state_root` is a pre-deployment preparation root and cannot be
/// used as the Genesis block state root.
#[derive(Debug, Clone)]
pub struct PreparedTestnetV3ExecutionState {
    pub execution_state: ExecutionState,
    pub artifact_keys: BTreeMap<String, SynQArtifactKey>,
    pub pre_deployment_state_root: crate::synergy_types::Hash,
}

impl PreparedTestnetV3ExecutionState {
    /// Makes accidental launch-time use of the prepared state explicit.  A
    /// final deployment manifest must bind each address, deployment receipt,
    /// constructor result, and the post-deployment state root before this can
    /// become a live execution state.
    pub fn reject_as_finalized_genesis_state(&self) -> Result<(), String> {
        Err(
            "Testnet-v3 SynQ artifacts are prepared but not deployed: a signed Genesis deployment manifest and post-deployment AIVM state-root binding are required"
                .to_string(),
        )
    }
}

/// Loads and verifies the eight native SynQ Genesis artifacts committed by an
/// identity-assigned Testnet-v3 Genesis candidate.  It neither generates
/// identities nor mutates Genesis, contract, or execution-state files.
pub fn prepare_testnet_v3_genesis_execution_state(
    genesis: &GenesisDocument,
) -> Result<PreparedTestnetV3ExecutionState, String> {
    if genesis.chain_id() != 1266 || genesis.network_id() != 1266 {
        return Err("SynQ Genesis artifact preparation requires chain ID 1266".to_string());
    }
    require_supported_execution_genesis_protocol(genesis, "SynQ Genesis artifact preparation")?;

    let contracts = required_object(genesis.value(), "contracts")?;
    let root = genesis
        .path()
        .parent()
        .ok_or_else(|| "Genesis path has no parent directory".to_string())?;
    let (required_network_id, required_signature_algorithm) =
        contract_artifact_requirements(genesis.consensus_version());
    let mut execution_state = ExecutionState::new();
    for balance in genesis.balances() {
        if execution_state
            .balances_nwei
            .insert(balance.address.clone(), u128::from(balance.balance_nwei))
            .is_some()
        {
            return Err("Genesis balance table contains duplicate address".to_string());
        }
    }

    let mut artifact_keys = BTreeMap::new();
    for (genesis_key, contract_name) in NATIVE_GENESIS_CONTRACTS {
        let contract = contracts
            .get(genesis_key)
            .ok_or_else(|| format!("Genesis contracts.{genesis_key} is missing"))?;
        verify_pre_approval_contract_record(
            contract,
            genesis_key,
            contract_name,
            required_network_id,
            required_signature_algorithm,
        )?;
        let artifact = load_committed_artifact(
            root,
            contract,
            contract_name,
            required_network_id,
            required_signature_algorithm,
        )?;
        let artifact_key = register_synq_artifact(&mut execution_state.synq_artifacts, artifact)
            .map_err(|error| format!("validate Genesis SynQ artifact {contract_name}: {error}"))?;
        artifact_keys.insert(genesis_key.to_string(), artifact_key);
    }

    if execution_state.synq_artifacts.len() != NATIVE_GENESIS_CONTRACTS.len()
        || !execution_state.synq_contracts.is_empty()
    {
        return Err("Genesis SynQ preparation produced an invalid deployment boundary".to_string());
    }
    let pre_deployment_state_root = compute_state_root_after(&execution_state)?;
    Ok(PreparedTestnetV3ExecutionState {
        execution_state,
        artifact_keys,
        pre_deployment_state_root,
    })
}

fn contract_artifact_requirements(consensus_version: &str) -> (&'static str, &'static str) {
    if consensus_version == crate::consensus::simplified_posy::POSY_SIMPLIFIED_PROTOCOL_VERSION {
        ("synergy-testnet", "ML-DSA-87")
    } else {
        ("synergy-testnet-v3", "ML-DSA-65")
    }
}

/// Initializes the exact post-ceremony execution state from finalized Genesis.
/// New canonical Genesis documents contain signed H0 operations and are
/// replayed from empty state. No external artifact path, private authority key,
/// or serialized state snapshot is consulted.
pub fn load_finalized_testnet_v3_genesis_execution_state(
    genesis: &GenesisDocument,
) -> Result<ExecutionState, String> {
    validate_execution_genesis_domain(genesis)?;
    load_finalized_execution_state_from_value(genesis, genesis.value())
}

/// Restores the separately stored execution bundle authenticated by the
/// installed local-R11 approval. Qualification never falls back to an
/// unapproved or embedded state. Existing production V4 Genesis documents
/// retain their original embedded-snapshot path until their byte-compatible
/// approval profile adopts the external bundle contract.
pub fn load_verified_testnet_v3_release_execution_state(
    genesis: &GenesisDocument,
) -> Result<ExecutionState, String> {
    validate_execution_genesis_domain(genesis)?;
    let verified = crate::desired_state::verified_desired_state_identity().ok_or_else(|| {
        "release execution state requires verified desired-state identity".to_string()
    })?;
    if verified.genesis_hash != genesis.hash() {
        return Err("verified desired state disagrees with canonical Genesis hash".to_string());
    }
    let Some(approval) = verified.genesis_execution_approval.as_ref() else {
        if genesis.value().get("env").and_then(Value::as_str)
            == Some("chain1266-private-qualification")
        {
            return Err(
                "local R11 qualification approval omits the Genesis execution bundle binding"
                    .to_string(),
            );
        }
        return load_finalized_testnet_v3_genesis_execution_state(genesis);
    };
    let path = crate::desired_state::configured_genesis_execution_snapshot_path()?;
    let bytes = read_genesis_execution_bundle_bytes(&path)?;
    verify_genesis_execution_bundle(
        genesis,
        &bytes,
        approval,
        &verified.testnet_v3_revision,
        &verified.synq_revision,
        &verified.aegis_revision,
        &verified.binary_sha256,
    )
}

fn read_genesis_execution_bundle_bytes(path: &Path) -> Result<Vec<u8>, String> {
    fs::read(path).map_err(|error| {
        format!(
            "read approved Genesis execution bundle {}: {error}",
            path.display()
        )
    })
}

fn verify_genesis_execution_bundle(
    genesis: &GenesisDocument,
    bytes: &[u8],
    approval: &crate::desired_state::VerifiedGenesisExecutionApproval,
    expected_testnet_v3_revision: &str,
    expected_synq_revision: &str,
    expected_aegis_revision: &str,
    expected_validator_binary_sha256: &str,
) -> Result<ExecutionState, String> {
    verify_sha256(bytes, &approval.snapshot_sha256, "Genesis execution bundle")?;
    let bundle: TestnetV3GenesisExecutionBundle = serde_json::from_slice(bytes)
        .map_err(|error| format!("decode approved Genesis execution bundle: {error}"))?;

    if bundle.schema_version != TESTNET_V3_GENESIS_EXECUTION_BUNDLE_SCHEMA_VERSION
        || bundle.schema_version != approval.snapshot_schema_version
        || bundle.artifact_type != TESTNET_V3_GENESIS_EXECUTION_BUNDLE_ARTIFACT_TYPE
        || bundle.artifact_type != approval.snapshot_artifact_type
    {
        return Err("approved Genesis execution bundle has an unsupported schema".to_string());
    }
    if bundle.chain_id != 1266
        || bundle.chain_id != genesis.chain_id()
        || bundle.chain_id != approval.chain_id
        || bundle.network_id != "testnet"
        || bundle.network_id != approval.network_id
        || bundle.release_id != "testnet-v3"
        || bundle.release_id != approval.release_id
        || bundle.protocol_version != genesis.consensus_version()
        || bundle.canonical_genesis_hash != genesis.hash()
        || bundle.canonical_genesis_hash != approval.genesis_hash
    {
        return Err(
            "approved Genesis execution bundle has a wrong chain/network/release/Genesis binding"
                .to_string(),
        );
    }
    if bundle.testnet_v3_revision != expected_testnet_v3_revision
        || bundle.synq_revision != expected_synq_revision
        || bundle.aegis_revision != expected_aegis_revision
        || bundle.validator_binary_sha256 != expected_validator_binary_sha256
    {
        return Err("approved Genesis execution bundle has stale release provenance".to_string());
    }
    if bundle.deployment_count != 9
        || bundle.initialization_count != 27
        || bundle.deployment_receipts.len() != bundle.deployment_count as usize
        || bundle.initialization_receipts.len() != bundle.initialization_count as usize
    {
        return Err(
            "approved Genesis execution bundle has incomplete receipt evidence".to_string(),
        );
    }

    let canonical_snapshot = serde_json::to_vec(&bundle.execution_state)
        .map_err(|error| format!("canonicalize approved Genesis execution snapshot: {error}"))?;
    verify_sha256(
        &canonical_snapshot,
        &approval.snapshot_canonical_sha256,
        "canonical Genesis execution snapshot",
    )?;
    if bundle.execution_state.schema_version
        != crate::execution::TESTNET_V3_GENESIS_SNAPSHOT_SCHEMA_VERSION
    {
        return Err("approved execution snapshot has an unsupported state schema".to_string());
    }

    // `restore_testnet_v3` reconstructs ExecutionState and independently
    // recomputes both roots. A correct-looking declared root cannot conceal a
    // byte edit to balances, contract storage, artifacts, or deployments.
    let state = bundle.execution_state.restore_testnet_v3()?;
    if bundle.execution_state_root != bundle.execution_state.state_root
        || bundle.execution_state_root != approval.execution_state_root
        || bundle.aivm_state_root != bundle.execution_state.aivm_state_root
        || bundle.aivm_state_root != approval.aivm_state_root
    {
        return Err("approved Genesis execution bundle root binding mismatch".to_string());
    }
    let computed_receipt_root =
        compute_genesis_receipt_root(&bundle.deployment_receipts, &bundle.initialization_receipts)?
            .to_hex();
    if bundle.receipt_root != computed_receipt_root || bundle.receipt_root != approval.receipt_root
    {
        return Err("approved Genesis execution bundle receipt root mismatch".to_string());
    }

    validate_restored_execution_state(genesis, &state)?;
    validate_bundle_receipts(&bundle, &state)?;
    Ok(state)
}

fn validate_execution_genesis_domain(genesis: &GenesisDocument) -> Result<(), String> {
    if genesis.chain_id() != 1266 || genesis.network_id() != 1266 {
        return Err("finalized SynQ Genesis state requires chain ID 1266".to_string());
    }
    require_supported_execution_genesis_protocol(genesis, "finalized SynQ Genesis state")
}

fn validate_restored_execution_state(
    genesis: &GenesisDocument,
    state: &ExecutionState,
) -> Result<(), String> {
    if state.synq_artifacts.len() != FINALIZED_NATIVE_GENESIS_CONTRACTS.len()
        || state.synq_contracts.len() != FINALIZED_NATIVE_GENESIS_CONTRACTS.len()
        || state.balances_nwei.len() != genesis.balances().len()
    {
        return Err("finalized Genesis execution snapshot has invalid cardinality".to_string());
    }
    for balance in genesis.balances() {
        let finalized_address = finalized_balance_address(genesis, state, &balance.address)?;
        if state.balances_nwei.get(&finalized_address).copied()
            != Some(u128::from(balance.balance_nwei))
        {
            return Err(format!(
                "finalized Genesis execution balance mismatch for {}",
                finalized_address
            ));
        }
    }
    Ok(())
}

/// TEM-A01 is a custody identity in the canonical Genesis input, but its
/// allocation is held by the deterministically deployed TeamVesting contract
/// in finalized execution state. All other Genesis balances remain at their
/// declared addresses. Resolve that one governed relocation from the frozen
/// TeamVesting artifact hash rather than trusting a mutable address overlay.
fn finalized_balance_address(
    genesis: &GenesisDocument,
    state: &ExecutionState,
    genesis_address: &str,
) -> Result<String, String> {
    let source_balance = genesis
        .value()
        .get("balances")
        .and_then(Value::as_array)
        .and_then(|balances| {
            balances.iter().find(|balance| {
                balance.get("address").and_then(Value::as_str) == Some(genesis_address)
            })
        })
        .ok_or_else(|| format!("finalized Genesis is missing balance {genesis_address}"))?;
    if source_balance.get("account_id").and_then(Value::as_str) != Some("TEM-A01") {
        return Ok(genesis_address.to_string());
    }

    let contracts = required_object(genesis.value(), "contracts")?;
    let team_vesting = contracts
        .get("team_vesting")
        .ok_or_else(|| "finalized Genesis is missing TeamVesting contract metadata".to_string())?;
    let expected_hash = hex::decode(required_string(team_vesting, "bytecode_hash")?)
        .map_err(|error| format!("decode TeamVesting bytecode hash: {error}"))?;
    let expected_hash: [u8; 32] = expected_hash
        .try_into()
        .map_err(|_| "TeamVesting bytecode hash has an invalid length".to_string())?;
    let addresses = state
        .synq_contracts
        .iter()
        .filter_map(|(address, deployment)| {
            (deployment.artifact_key.bytecode_hash == expected_hash).then_some(address.as_str())
        })
        .collect::<Vec<_>>();
    match addresses.as_slice() {
        [address] => Ok((*address).to_string()),
        _ => Err("finalized execution state has no unique TeamVesting deployment".to_string()),
    }
}

fn validate_bundle_receipts(
    bundle: &TestnetV3GenesisExecutionBundle,
    state: &ExecutionState,
) -> Result<(), String> {
    let mut deployed_addresses = BTreeSet::new();
    for receipt in &bundle.deployment_receipts {
        if receipt.operation != "deploy"
            || receipt.status != "succeeded"
            || receipt.error_code.is_some()
            || receipt.error_message.is_some()
            || !state.synq_contracts.contains_key(&receipt.contract_address)
            || !deployed_addresses.insert(receipt.contract_address.clone())
        {
            return Err(
                "Genesis execution bundle contains an invalid deployment receipt".to_string(),
            );
        }
    }
    for receipt in &bundle.initialization_receipts {
        if receipt.operation != "call"
            || receipt.status != "succeeded"
            || receipt.error_code.is_some()
            || receipt.error_message.is_some()
            || !state.synq_contracts.contains_key(&receipt.contract_address)
        {
            return Err(
                "Genesis execution bundle contains an invalid initialization receipt".to_string(),
            );
        }
    }
    let receipts: Vec<&SynQAivmReceiptSummary> = bundle
        .deployment_receipts
        .iter()
        .chain(bundle.initialization_receipts.iter())
        .collect();
    if receipts
        .windows(2)
        .any(|pair| pair[0].post_state_root != pair[1].pre_state_root)
    {
        return Err(
            "Genesis execution bundle receipt state transitions are discontinuous".to_string(),
        );
    }
    Ok(())
}

fn load_finalized_execution_state_from_value(
    genesis: &GenesisDocument,
    finalized: &Value,
) -> Result<ExecutionState, String> {
    let deployment = finalized
        .get("genesis_deployment")
        .filter(|value| value.is_object())
        .ok_or_else(|| "finalized Genesis is missing genesis_deployment".to_string())?;
    // The signed SGEN reconstructs its exact 9-deploy/27-initialization H0
    // operation list in memory. That authenticated replay is the finalized
    // boundary for the live PoSy v3 chain; it is not the retired snapshot
    // profile below, which used a 25-call initialization count.
    if let Some(operations_value) = deployment.get("signed_replay_operations") {
        return replay_finalized_execution_state_from_operations(
            genesis,
            finalized,
            deployment,
            operations_value,
        );
    }
    if required_string(deployment, "status")? != "EXECUTED_AND_BOUND"
        || deployment.get("deployment_count").and_then(Value::as_u64) != Some(9)
        || deployment
            .get("initialization_count")
            .and_then(Value::as_u64)
            != Some(25)
        || required_string(deployment, "genesis_deployer_lifecycle")? != "PermanentlyRetired"
    {
        return Err("finalized Genesis deployment boundary is incomplete".to_string());
    }

    // Historical finalized documents can still be audited from their embedded
    // state evidence. New canonical Genesis must take the replay branch above.
    let snapshot_value = deployment
        .get("execution_state")
        .ok_or_else(|| "finalized Genesis is missing embedded execution_state".to_string())?;
    let snapshot: GenesisExecutionSnapshot = serde_json::from_value(snapshot_value.clone())
        .map_err(|error| format!("decode finalized Genesis execution snapshot: {error}"))?;
    let canonical_snapshot = serde_json::to_vec(&snapshot)
        .map_err(|error| format!("encode finalized Genesis execution snapshot: {error}"))?;
    verify_sha256(
        &canonical_snapshot,
        required_string(deployment, "execution_state_snapshot_canonical_sha256")?,
        "execution-state snapshot",
    )?;
    let state = snapshot.restore_testnet_v3()?;

    if required_string(deployment, "post_deployment_execution_state_root")? != snapshot.state_root
        || required_string(deployment, "post_deployment_aivm_state_root")?
            != snapshot.aivm_state_root
        || required_string(
            finalized
                .get("execution")
                .ok_or_else(|| "finalized Genesis is missing execution metadata".to_string())?,
            "genesis_execution_state_root",
        )? != snapshot.state_root
        || required_string(
            finalized
                .get("execution")
                .ok_or_else(|| "finalized Genesis is missing execution metadata".to_string())?,
            "genesis_aivm_state_root",
        )? != snapshot.aivm_state_root
    {
        return Err(
            "finalized Genesis execution roots do not match the embedded snapshot".to_string(),
        );
    }

    validate_restored_execution_state(genesis, &state)?;

    let contracts = required_object(finalized, "contracts")?;
    for (genesis_key, contract_name) in FINALIZED_NATIVE_GENESIS_CONTRACTS {
        let contract = contracts
            .get(genesis_key)
            .ok_or_else(|| format!("finalized Genesis contracts.{genesis_key} is missing"))?;
        if required_string(contract, "status")? != FINALIZED_STATUS {
            return Err(format!(
                "finalized Genesis contracts.{genesis_key} has not completed deployment"
            ));
        }
        let address = required_string(contract, "address")?;
        if !state.synq_contracts.contains_key(address) {
            return Err(format!(
                "finalized Genesis snapshot is missing deployed {contract_name} at {address}"
            ));
        }
    }

    Ok(state)
}

fn replay_finalized_execution_state_from_operations(
    genesis: &GenesisDocument,
    finalized: &Value,
    deployment: &Value,
    operations_value: &Value,
) -> Result<ExecutionState, String> {
    let operations: Vec<GenesisReplayOperation> = serde_json::from_value(operations_value.clone())
        .map_err(|error| format!("decode finalized Genesis signed replay operations: {error}"))?;
    let team_vesting_operation = operations.get(8).ok_or_else(|| {
        "finalized Genesis replay operations omit TeamVesting deployment".to_string()
    })?;
    let deploy: ContractDeployEnvelope = serde_json::from_slice(
        &team_vesting_operation
            .admission_envelope
            .encoded_pqsynq_envelope,
    )
    .map_err(|error| format!("decode TeamVesting replay deployment envelope: {error}"))?;
    let team_vesting_address = derive_synergy_contract_address_from_deploy_with_identity_address(
        &deploy,
        &team_vesting_operation.admission_envelope.signer,
    )?;
    let mut state = genesis_execution_state_before_h0(finalized, &team_vesting_address)?;
    let manifest_hash = crate::synergy_types::Hash::from_hex(required_string(
        deployment,
        "deployment_manifest_hash",
    )?)
    .map_err(|error| format!("decode finalized Genesis deployment manifest hash: {error}"))?;
    let replay =
        replay_genesis_deployment_from_signed_operations(&mut state, manifest_hash, &operations)?;

    let expected_state_root = required_string(deployment, "post_deployment_execution_state_root")?;
    let expected_aivm_root = required_string(deployment, "post_deployment_aivm_state_root")?;
    let expected_receipt_root = required_string(deployment, "receipt_root")?;
    if replay.post_deployment_state_root.to_hex() != expected_state_root
        || hex::encode(state.synq_aivm_state.state_root()) != expected_aivm_root
        || replay.receipt_root.to_hex() != expected_receipt_root
        || required_string(
            finalized
                .get("execution")
                .ok_or_else(|| "finalized Genesis is missing execution metadata".to_string())?,
            "genesis_execution_state_root",
        )? != expected_state_root
        || required_string(
            finalized
                .get("execution")
                .ok_or_else(|| "finalized Genesis is missing execution metadata".to_string())?,
            "genesis_aivm_state_root",
        )? != expected_aivm_root
    {
        return Err("replayed Genesis execution roots do not match canonical Genesis".to_string());
    }
    let expected_deployments: Vec<SynQAivmReceiptSummary> = serde_json::from_value(
        deployment
            .get("deployment_receipts")
            .cloned()
            .ok_or_else(|| "finalized Genesis is missing deployment receipts".to_string())?,
    )
    .map_err(|error| format!("decode finalized Genesis deployment receipts: {error}"))?;
    let expected_initializations: Vec<SynQAivmReceiptSummary> = serde_json::from_value(
        deployment
            .get("initialization_receipts")
            .cloned()
            .ok_or_else(|| "finalized Genesis is missing initialization receipts".to_string())?,
    )
    .map_err(|error| format!("decode finalized Genesis initialization receipts: {error}"))?;
    if replay.deployment_receipts != expected_deployments
        || replay.initialization_receipts != expected_initializations
    {
        return Err("replayed Genesis receipts do not match canonical Genesis".to_string());
    }
    validate_restored_execution_state(genesis, &state)?;
    Ok(state)
}

fn genesis_execution_state_before_h0(
    finalized: &Value,
    team_vesting_address: &str,
) -> Result<ExecutionState, String> {
    let balances = finalized
        .get("balances")
        .and_then(Value::as_array)
        .ok_or_else(|| "finalized Genesis balances must be an array".to_string())?;
    let mut state = ExecutionState::new();
    for balance in balances {
        let source_address = required_string(balance, "address")?;
        let address = if balance.get("account_id").and_then(Value::as_str) == Some("TEM-A01") {
            team_vesting_address
        } else {
            source_address
        };
        let amount = required_string(balance, "balance_nwei")?
            .parse::<u128>()
            .map_err(|error| format!("parse finalized Genesis balance: {error}"))?;
        if state
            .balances_nwei
            .insert(address.to_string(), amount)
            .is_some()
        {
            return Err(format!(
                "finalized Genesis repeats balance address {address}"
            ));
        }
    }
    Ok(state)
}

fn require_supported_execution_genesis_protocol(
    genesis: &GenesisDocument,
    context: &str,
) -> Result<(), String> {
    if genesis.protocol_version() != "1.0.0" {
        return Err(format!("{context} has invalid protocol binding"));
    }
    match genesis.consensus_version() {
        "posy/2.2" => Ok(()),
        crate::consensus_parameters::COORDINATED_ROUND_ROBIN_V1_PROTOCOL_VERSION => genesis
            .consensus_parameters()
            .ok_or_else(|| format!("{context} requires a finalized coordinated P1 manifest"))?
            .require_coordinated_round_robin_manifest()
            .map(|_| ()),
        crate::consensus::simplified_posy::POSY_SIMPLIFIED_PROTOCOL_VERSION => {
            // Fresh PoSy v3 binds its final manifest directly in the
            // Genesis activation record. It deliberately does not carry the
            // retired `consensus_parameters` compatibility wrapper.
            crate::consensus::simplified_posy::load_genesis_bound_simplified_activation(
                genesis.value(),
            )?
            .ok_or_else(|| format!("{context} requires a finalized simplified PoSy v3 activation"))?
            .validate()
        }
        _ => Err(format!("{context} has invalid protocol binding")),
    }
}

fn verify_pre_approval_contract_record(
    contract: &Value,
    genesis_key: &str,
    contract_name: &str,
    required_network_id: &str,
    required_signature_algorithm: &str,
) -> Result<(), String> {
    if required_string(contract, "status")? != PRE_APPROVAL_STATUS {
        return Err(format!(
            "Genesis contracts.{genesis_key} is not the expected pre-approval artifact-bound record"
        ));
    }
    let address = required_string(contract, "address")?;
    if address.is_empty() {
        return Err(format!("Genesis contracts.{genesis_key}.address is empty"));
    }
    let artifact = required_value_object(contract, "artifact")?;
    if required_string(artifact, "contract_name")? != contract_name {
        return Err(format!(
            "Genesis contracts.{genesis_key}.artifact.contract_name does not match {contract_name}"
        ));
    }
    if artifact.get("required_chain_id").and_then(Value::as_u64) != Some(1266)
        || required_string(artifact, "required_network_id")? != required_network_id
        || required_string(artifact, "required_signature_algorithm")?
            != required_signature_algorithm
    {
        return Err(format!(
            "Genesis contracts.{genesis_key} artifact is not bound to Chain 1266 {required_network_id} {required_signature_algorithm}"
        ));
    }
    Ok(())
}

fn load_committed_artifact(
    root: &Path,
    contract: &Value,
    contract_name: &str,
    required_network_id: &str,
    required_signature_algorithm: &str,
) -> Result<SynQContractArtifact, String> {
    let artifact = required_value_object(contract, "artifact")?;
    let base = format!("genesis-contracts/contracts/{contract_name}");
    let bytecode = read_committed_file(
        root,
        required_string(artifact, "bytecode_path")?,
        &format!("{base}.compiled.synq"),
    )?;
    let abi = read_committed_file(
        root,
        required_string(artifact, "abi_path")?,
        &format!("{base}.abi.json"),
    )?;
    let manifest = read_committed_file(
        root,
        required_string(artifact, "manifest_path")?,
        &format!("{base}.manifest.json"),
    )?;
    let source = read_committed_file(root, &format!("{base}.synq"), &format!("{base}.synq"))?;

    verify_sha256(
        &bytecode,
        required_string(artifact, "bytecode_hash")?,
        "bytecode",
    )?;
    verify_sha256(&abi, required_string(artifact, "abi_hash")?, "ABI")?;
    verify_sha256(
        &manifest,
        required_string(artifact, "manifest_sha256")?,
        "manifest",
    )?;
    verify_sha256(&source, required_string(artifact, "source_hash")?, "source")?;

    let manifest_value: Value = serde_json::from_slice(&manifest)
        .map_err(|error| format!("parse {contract_name} SynQ manifest: {error}"))?;
    if required_string(&manifest_value, "contract_name")? != contract_name
        || required_string(&manifest_value, "artifact_format")? != "synq-stateful-ir-v2"
        || manifest_value
            .get("bytecode_version")
            .and_then(Value::as_u64)
            != Some(2)
        || manifest_value
            .get("required_chain_id")
            .and_then(Value::as_u64)
            != Some(1266)
        || required_string(&manifest_value, "required_network_id")? != required_network_id
        || required_string(&manifest_value, "required_signature_algorithm")?
            != required_signature_algorithm
    {
        return Err(format!(
            "{contract_name} SynQ manifest is not Testnet-v3 compatible"
        ));
    }
    for field in ["bytecode_hash", "abi_hash", "source_hash"] {
        if required_string(&manifest_value, field)? != required_string(artifact, field)? {
            return Err(format!(
                "{contract_name} SynQ manifest {field} is not the Genesis-committed value"
            ));
        }
    }
    Ok(SynQContractArtifact::new(
        bytecode,
        String::from_utf8(abi)
            .map_err(|error| format!("{contract_name} ABI is not UTF-8: {error}"))?,
        String::from_utf8(manifest)
            .map_err(|error| format!("{contract_name} manifest is not UTF-8: {error}"))?,
    ))
}

fn read_committed_file(root: &Path, declared: &str, expected: &str) -> Result<Vec<u8>, String> {
    if declared != expected {
        return Err(format!(
            "Genesis artifact path {declared} must be {expected}"
        ));
    }
    let relative = Path::new(declared);
    if relative.is_absolute()
        || relative.components().any(|component| {
            matches!(
                component,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        })
    {
        return Err("Genesis artifact path must be a safe relative path".to_string());
    }
    let path: PathBuf = root.join(relative);
    fs::read(&path).map_err(|error| {
        format!(
            "read committed Genesis artifact {}: {error}",
            path.display()
        )
    })
}

fn verify_sha256(bytes: &[u8], expected: &str, label: &str) -> Result<(), String> {
    let actual = hex::encode(Sha256::digest(bytes));
    if actual != expected {
        return Err(format!(
            "Genesis SynQ {label} hash does not match committed value"
        ));
    }
    Ok(())
}

fn required_object<'a>(
    value: &'a Value,
    key: &str,
) -> Result<&'a serde_json::Map<String, Value>, String> {
    value
        .get(key)
        .and_then(Value::as_object)
        .ok_or_else(|| format!("Genesis {key} must be an object"))
}

fn required_value_object<'a>(value: &'a Value, key: &str) -> Result<&'a Value, String> {
    value
        .get(key)
        .filter(|entry| entry.is_object())
        .ok_or_else(|| format!("Genesis {key} must be an object"))
}

fn required_string<'a>(value: &'a Value, key: &str) -> Result<&'a str, String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .filter(|entry| !entry.trim().is_empty())
        .ok_or_else(|| format!("Genesis {key} must be a non-empty string"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::desired_state::VerifiedGenesisExecutionApproval;
    use crate::synergy_types::TxId;
    use crate::synq_execution::{
        execute_synq_static_call, SynQContractArtifact, SynQDeploymentRecord, SynQExecutionContext,
    };
    use aivm_core::execution::{ExecutionContext, ExecutionStatus};
    use aivm_core::state::ContractState;
    use aivm_core::synq_runtime::{deploy_synq_contract, synq_execution_request};

    const STATIC_COUNTER_ADDRESS: &str = "sync1p3staticcounterfixture00000000000000000";
    const TEST_TESTNET_REVISION: &str = "1111111111111111111111111111111111111111";
    const TEST_SYNQ_REVISION: &str = "2222222222222222222222222222222222222222";
    const TEST_AEGIS_REVISION: &str = "3333333333333333333333333333333333333333";
    const TEST_VALIDATOR_BINARY_SHA256: &str =
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    fn finalized_bundle_fixture(
        genesis: &GenesisDocument,
    ) -> (
        TestnetV3GenesisExecutionBundle,
        VerifiedGenesisExecutionApproval,
        Vec<u8>,
    ) {
        // The checked-in finalized deployment fixture supplies a real state
        // and real deterministic receipts. The envelope is freshly bound to
        // the current P3 unit-test Genesis so this test exercises the external
        // artifact contract instead of the legacy embedded loader.
        let finalized: Value = serde_json::from_str(include_str!(
            "../../launch/production-node-configs/canonical-genesis/genesis.json"
        ))
        .expect("checked-in finalized Genesis fixture");
        let deployment = finalized
            .get("genesis_deployment")
            .expect("fixture deployment");
        let mut source_execution_value = deployment
            .get("execution_state")
            .expect("fixture execution state")
            .clone();
        // This frozen production fixture predates the strict snapshot schema
        // and calls the required network field `runtime_network_id`. Normalize
        // that legacy spelling before recreating the canonical test-only
        // snapshot from restored state.
        let source_execution_object = source_execution_value
            .as_object_mut()
            .expect("fixture execution state object");
        source_execution_object
            .remove("runtime_network_id")
            .expect("fixture runtime network id");
        source_execution_object.insert(
            "network_id".to_string(),
            Value::String("testnet".to_string()),
        );
        source_execution_object.insert(
            "release_id".to_string(),
            Value::String("testnet-v3".to_string()),
        );
        source_execution_object.insert(
            "identity_authorization_bindings".to_string(),
            Value::Object(serde_json::Map::new()),
        );
        source_execution_object.insert(
            "schema_version".to_string(),
            Value::from(crate::execution::TESTNET_V3_GENESIS_SNAPSHOT_SCHEMA_VERSION),
        );
        // The strict snapshot verifier checks the declared root before the
        // fixture can be recaptured. The value is the deterministic root of
        // this normalized legacy fixture (network spelling, release ID, and
        // empty binding map above), not a production qualification root.
        source_execution_object.insert(
            "state_root".to_string(),
            Value::String(
                "87318d45987425b0528bf4e7be525ca6db71acb50eb138698e5d00a954b7a916".to_string(),
            ),
        );
        let source_execution_state: GenesisExecutionSnapshot =
            serde_json::from_value(source_execution_value).expect("fixture execution snapshot");
        let mut fixture_state = source_execution_state
            .restore_testnet_v3()
            .expect("restore checked-in execution snapshot");
        fixture_state.balances_nwei = genesis
            .balances()
            .iter()
            .map(|balance| (balance.address.clone(), u128::from(balance.balance_nwei)))
            .collect();
        let execution_state = GenesisExecutionSnapshot::capture_testnet_v3(&fixture_state)
            .expect("capture P3-bound execution fixture");
        let deployment_receipts = serde_json::from_value(
            deployment
                .get("deployment_receipts")
                .expect("fixture deployment receipts")
                .clone(),
        )
        .expect("decode deployment receipts");
        let initialization_receipts = serde_json::from_value(
            deployment
                .get("initialization_receipts")
                .expect("fixture initialization receipts")
                .clone(),
        )
        .expect("decode initialization receipts");
        let bundle = TestnetV3GenesisExecutionBundle {
            schema_version: TESTNET_V3_GENESIS_EXECUTION_BUNDLE_SCHEMA_VERSION,
            artifact_type: TESTNET_V3_GENESIS_EXECUTION_BUNDLE_ARTIFACT_TYPE.to_string(),
            chain_id: 1266,
            network_id: "testnet".to_string(),
            release_id: "testnet-v3".to_string(),
            protocol_version: genesis.consensus_version().to_string(),
            canonical_genesis_hash: genesis.hash().to_string(),
            testnet_v3_revision: TEST_TESTNET_REVISION.to_string(),
            synq_revision: TEST_SYNQ_REVISION.to_string(),
            aegis_revision: TEST_AEGIS_REVISION.to_string(),
            validator_binary_sha256: TEST_VALIDATOR_BINARY_SHA256.to_string(),
            execution_state_root: execution_state.state_root.clone(),
            aivm_state_root: execution_state.aivm_state_root.clone(),
            receipt_root: required_string(deployment, "receipt_root")
                .expect("fixture receipt root")
                .to_string(),
            deployment_count: 9,
            initialization_count: 27,
            deployment_receipts,
            initialization_receipts,
            execution_state,
        };
        let bytes = serde_json::to_vec(&bundle).expect("serialize execution bundle");
        let canonical_snapshot =
            serde_json::to_vec(&bundle.execution_state).expect("canonical execution snapshot");
        let approval = VerifiedGenesisExecutionApproval {
            candidate_sha256: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                .to_string(),
            snapshot_schema_version: TESTNET_V3_GENESIS_EXECUTION_BUNDLE_SCHEMA_VERSION,
            snapshot_artifact_type: TESTNET_V3_GENESIS_EXECUTION_BUNDLE_ARTIFACT_TYPE.to_string(),
            snapshot_sha256: hex::encode(Sha256::digest(&bytes)),
            snapshot_canonical_sha256: hex::encode(Sha256::digest(&canonical_snapshot)),
            genesis_hash: genesis.hash().to_string(),
            chain_id: 1266,
            network_id: "testnet".to_string(),
            release_id: "testnet-v3".to_string(),
            execution_state_root: bundle.execution_state_root.clone(),
            aivm_state_root: bundle.aivm_state_root.clone(),
            receipt_root: bundle.receipt_root.clone(),
        };
        (bundle, approval, bytes)
    }

    fn verify_fixture(
        genesis: &GenesisDocument,
        bytes: &[u8],
        approval: &VerifiedGenesisExecutionApproval,
    ) -> Result<ExecutionState, String> {
        verify_genesis_execution_bundle(
            genesis,
            bytes,
            approval,
            TEST_TESTNET_REVISION,
            TEST_SYNQ_REVISION,
            TEST_AEGIS_REVISION,
            TEST_VALIDATOR_BINARY_SHA256,
        )
    }

    fn deployed_fresh_p3_static_counter() -> (
        ContractState,
        BTreeMap<SynQArtifactKey, SynQContractArtifact>,
        BTreeMap<String, SynQDeploymentRecord>,
    ) {
        let artifact_root =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../synq-language/contracts");
        let artifact = SynQContractArtifact::new(
            fs::read(artifact_root.join("Counter.compiled.synq"))
                .expect("checked-in P3 Counter bytecode must exist"),
            fs::read_to_string(artifact_root.join("Counter.abi.json"))
                .expect("checked-in P3 Counter ABI must exist"),
            fs::read_to_string(artifact_root.join("Counter.manifest.json"))
                .expect("checked-in P3 Counter manifest must exist"),
        );
        let artifact_key = artifact.key();
        let request = synq_execution_request(
            STATIC_COUNTER_ADDRESS,
            artifact.to_aivm_artifact(),
            ExecutionContext::testnet_1266_for_contract(STATIC_COUNTER_ADDRESS, 1_000_000),
            Vec::new(),
        );
        let mut state = ContractState::default();
        let deployment = deploy_synq_contract(&request, &mut state);
        assert_eq!(deployment.status, ExecutionStatus::Succeeded);

        let mut artifacts = BTreeMap::new();
        artifacts.insert(artifact_key.clone(), artifact);
        let mut deployments = BTreeMap::new();
        deployments.insert(
            STATIC_COUNTER_ADDRESS.to_string(),
            SynQDeploymentRecord {
                contract_address: STATIC_COUNTER_ADDRESS.to_string(),
                deployer: "fresh-p3-static-test".to_string(),
                artifact_key,
                deploy_tx_id: TxId::from("fresh-p3-static-test-deployment"),
                deploy_receipt_hash: "fresh-p3-static-test-receipt".to_string(),
            },
        );
        (state, artifacts, deployments)
    }

    #[test]
    fn artifact_bindings_follow_genesis_consensus_generation() {
        assert_eq!(
            contract_artifact_requirements(
                crate::consensus::simplified_posy::POSY_SIMPLIFIED_PROTOCOL_VERSION,
            ),
            ("synergy-testnet", "ML-DSA-87")
        );
        assert_eq!(
            contract_artifact_requirements("posy/2.2"),
            ("synergy-testnet-v3", "ML-DSA-65")
        );
    }

    #[test]
    fn fresh_predeployment_candidate_cannot_be_loaded_as_finalized_execution_state() {
        let genesis = crate::genesis::canonical_genesis()
            .expect("canonical unit-test Genesis must be the fresh P3 public input");
        assert_eq!(
            genesis.consensus_version(),
            crate::consensus::simplified_posy::POSY_SIMPLIFIED_PROTOCOL_VERSION
        );
        let error = load_finalized_testnet_v3_genesis_execution_state(genesis).expect_err(
            "a fresh predeployment candidate must not be accepted as finalized Genesis",
        );
        assert!(error.contains("missing genesis_deployment"));
    }

    #[test]
    fn approved_external_genesis_execution_bundle_fails_closed_on_every_binding_edge() {
        let genesis = crate::genesis::canonical_genesis()
            .expect("canonical unit-test Genesis must be fresh P3");
        let (bundle, approval, bytes) = finalized_bundle_fixture(genesis);
        let restored = verify_fixture(genesis, &bytes, &approval)
            .expect("matching Genesis and approved execution bundle must restore");
        assert_eq!(
            compute_state_root_after(&restored)
                .expect("restored execution root")
                .to_hex(),
            approval.execution_state_root
        );

        let mut byte_tamper = bytes.clone();
        byte_tamper.push(b'\n');
        assert!(verify_fixture(genesis, &byte_tamper, &approval)
            .expect_err("byte tamper must fail")
            .contains("does not match committed value"));

        let mut wrong_genesis = bundle.clone();
        wrong_genesis.canonical_genesis_hash = "00".repeat(32);
        let wrong_genesis_bytes = serde_json::to_vec(&wrong_genesis).expect("wrong Genesis bundle");
        let mut wrong_genesis_approval = approval.clone();
        wrong_genesis_approval.snapshot_sha256 = hex::encode(Sha256::digest(&wrong_genesis_bytes));
        assert!(
            verify_fixture(genesis, &wrong_genesis_bytes, &wrong_genesis_approval)
                .expect_err("snapshot from another Genesis must fail")
                .contains("wrong chain/network/release/Genesis")
        );

        let mut altered_state = bundle.clone();
        *altered_state
            .execution_state
            .balances_nwei
            .values_mut()
            .next()
            .expect("fixture balance") += 1;
        let altered_state_bytes = serde_json::to_vec(&altered_state).expect("altered state bundle");
        let mut altered_state_approval = approval.clone();
        altered_state_approval.snapshot_sha256 = hex::encode(Sha256::digest(&altered_state_bytes));
        altered_state_approval.snapshot_canonical_sha256 = hex::encode(Sha256::digest(
            &serde_json::to_vec(&altered_state.execution_state)
                .expect("canonical altered execution snapshot"),
        ));
        assert!(
            verify_fixture(genesis, &altered_state_bytes, &altered_state_approval)
                .expect_err("right claimed root over altered state must fail")
                .contains("state root mismatch")
        );

        let mut wrong_domain = bundle.clone();
        wrong_domain.network_id = "mainnet".to_string();
        let wrong_domain_bytes = serde_json::to_vec(&wrong_domain).expect("wrong-domain bundle");
        let mut wrong_domain_approval = approval.clone();
        wrong_domain_approval.snapshot_sha256 = hex::encode(Sha256::digest(&wrong_domain_bytes));
        assert!(
            verify_fixture(genesis, &wrong_domain_bytes, &wrong_domain_approval)
                .expect_err("wrong chain/network must fail")
                .contains("wrong chain/network/release/Genesis")
        );

        let mut stale = bundle.clone();
        stale.testnet_v3_revision = "44".repeat(20);
        let stale_bytes = serde_json::to_vec(&stale).expect("stale bundle");
        let mut stale_approval = approval.clone();
        stale_approval.snapshot_sha256 = hex::encode(Sha256::digest(&stale_bytes));
        assert!(verify_fixture(genesis, &stale_bytes, &stale_approval)
            .expect_err("stale release must fail")
            .contains("stale release provenance"));

        let mut altered_receipt = bundle;
        altered_receipt.deployment_receipts[0]
            .return_data_hex
            .push_str("00");
        let altered_receipt_bytes =
            serde_json::to_vec(&altered_receipt).expect("altered receipt bundle");
        let mut altered_receipt_approval = approval;
        altered_receipt_approval.snapshot_sha256 =
            hex::encode(Sha256::digest(&altered_receipt_bytes));
        assert!(
            verify_fixture(genesis, &altered_receipt_bytes, &altered_receipt_approval)
                .expect_err("altered receipt must fail")
                .contains("receipt root mismatch")
        );

        assert!(read_genesis_execution_bundle_bytes(Path::new(
            "/missing/synergy-testnet-v3-genesis-execution-bundle.json"
        ))
        .expect_err("missing snapshot must fail closed")
        .contains("read approved Genesis execution bundle"));
    }

    #[test]
    fn prepared_artifacts_cannot_be_mistaken_for_deployed_genesis_contracts() {
        let execution_state = ExecutionState::new();
        let prepared = PreparedTestnetV3ExecutionState {
            pre_deployment_state_root: compute_state_root_after(&execution_state)
                .expect("pre-deployment root"),
            execution_state,
            artifact_keys: BTreeMap::new(),
        };
        assert!(prepared.reject_as_finalized_genesis_state().is_err());
    }

    #[test]
    fn fresh_p3_static_synq_view_calls_do_not_mutate_state() {
        let (state, artifacts, deployments) = deployed_fresh_p3_static_counter();
        let state_root_before = state.state_root();

        let receipt = execute_synq_static_call(
            STATIC_COUNTER_ADDRESS,
            "synq-static-test-caller",
            &hex::decode("75b70457").expect("Counter get selector must be hex"),
            &state,
            &artifacts,
            &deployments,
            SynQExecutionContext {
                runtime_block_height: 1,
                runtime_block_timestamp_unix: 1_785_000_000,
                sts_host: None,
                applied_fee_market: None,
            },
        )
        .expect("public P3 Counter view selector must execute against deployed state");

        assert_eq!(receipt.status, "succeeded");
        assert!(!receipt.return_data_hex.is_empty());
        assert_eq!(state.state_root(), state_root_before);
    }

    #[test]
    fn fresh_p3_static_synq_rejects_write_selector_before_execution() {
        let (state, artifacts, deployments) = deployed_fresh_p3_static_counter();
        let state_root_before = state.state_root();
        let error = execute_synq_static_call(
            STATIC_COUNTER_ADDRESS,
            "synq-static-test-caller",
            &hex::decode("5842f1be").expect("Counter increment selector must be hex"),
            &state,
            &artifacts,
            &deployments,
            SynQExecutionContext::default(),
        )
        .expect_err("static boundary must reject a public write selector");
        assert!(error.contains("view ABI methods"));
        assert_eq!(state.state_root(), state_root_before);
    }
}
