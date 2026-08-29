//! Read-only Testnet-v3 SynQ genesis execution-state bootstrap.
//!
//! A fresh chain must not treat the presence of a `.synq` file as a deployed
//! contract. The legacy pre-approval adapter proves eight identity-assigned
//! artifacts while leaving `synq_contracts` empty. The finalized adapter
//! restores the complete public ceremony snapshot embedded in Genesis and
//! verifies its execution root, AIVM root, balances, artifacts, and deployed
//! addresses before returning any state to consensus.

use crate::execution::{compute_state_root_after, ExecutionState, GenesisExecutionSnapshot};
use crate::genesis::GenesisDocument;
use crate::synq_execution::{register_synq_artifact, SynQArtifactKey, SynQContractArtifact};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
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

/// Restores the exact post-ceremony execution state embedded in a finalized
/// Testnet-v3 Genesis document. No external artifact path and no authority key
/// is consulted; the canonical Genesis hash binds the embedded snapshot.
pub fn load_finalized_testnet_v3_genesis_execution_state(
    genesis: &GenesisDocument,
) -> Result<ExecutionState, String> {
    if genesis.chain_id() != 1266 || genesis.network_id() != 1266 {
        return Err("finalized SynQ Genesis state requires chain ID 1266".to_string());
    }
    require_supported_execution_genesis_protocol(genesis, "finalized SynQ Genesis state")?;

    let deployment = genesis
        .value()
        .get("genesis_deployment")
        .filter(|value| value.is_object())
        .ok_or_else(|| "finalized Genesis is missing genesis_deployment".to_string())?;
    if required_string(deployment, "status")? != "EXECUTED_AND_BOUND"
        || deployment.get("deployment_count").and_then(Value::as_u64) != Some(9)
        || deployment
            .get("initialization_count")
            .and_then(Value::as_u64)
            != Some(27)
        || required_string(deployment, "genesis_deployer_lifecycle")? != "PermanentlyRetired"
    {
        return Err("finalized Genesis deployment boundary is incomplete".to_string());
    }

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
            genesis
                .value()
                .get("execution")
                .ok_or_else(|| "finalized Genesis is missing execution metadata".to_string())?,
            "genesis_execution_state_root",
        )? != snapshot.state_root
        || required_string(
            genesis
                .value()
                .get("execution")
                .ok_or_else(|| "finalized Genesis is missing execution metadata".to_string())?,
            "genesis_aivm_state_root",
        )? != snapshot.aivm_state_root
    {
        return Err(
            "finalized Genesis execution roots do not match the embedded snapshot".to_string(),
        );
    }

    if state.synq_artifacts.len() != FINALIZED_NATIVE_GENESIS_CONTRACTS.len()
        || state.synq_contracts.len() != FINALIZED_NATIVE_GENESIS_CONTRACTS.len()
        || state.balances_nwei.len() != genesis.balances().len()
    {
        return Err("finalized Genesis execution snapshot has invalid cardinality".to_string());
    }
    for balance in genesis.balances() {
        if state.balances_nwei.get(&balance.address).copied()
            != Some(u128::from(balance.balance_nwei))
        {
            return Err(format!(
                "finalized Genesis execution balance mismatch for {}",
                balance.address
            ));
        }
    }

    let contracts = required_object(genesis.value(), "contracts")?;
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
        crate::consensus::simplified_posy::POSY_SIMPLIFIED_PROTOCOL_VERSION => genesis
            .consensus_parameters()
            .ok_or_else(|| format!("{context} requires a finalized simplified PoSy v3 manifest"))?
            .require_simplified_posy_manifest()
            .map(|_| ()),
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
    use crate::synergy_types::TxId;
    use crate::synq_execution::{
        execute_synq_static_call, SynQContractArtifact, SynQDeploymentRecord, SynQExecutionContext,
    };
    use aivm_core::execution::{ExecutionContext, ExecutionStatus};
    use aivm_core::state::ContractState;
    use aivm_core::synq_runtime::{deploy_synq_contract, synq_execution_request};

    const STATIC_COUNTER_ADDRESS: &str = "sync1p3staticcounterfixture00000000000000000";

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
