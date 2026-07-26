//! Read-only Testnet-v3 SynQ genesis-artifact preparation.
//!
//! A fresh chain must not treat the presence of a `.synq` file as a deployed
//! contract.  This adapter proves that the eight Genesis artifacts committed
//! by the identity-assigned Genesis candidate are the exact local SynQ/AIVM
//! inputs, while deliberately leaving `synq_contracts` empty until a signed
//! Genesis deployment manifest supplies the canonical deployments and initial
//! AIVM state root.

use crate::execution::{compute_state_root_after, ExecutionState};
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

const PRE_APPROVAL_STATUS: &str = "address_assigned_artifact_bound_pending_genesis_approval";

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
    if genesis.protocol_version() != "1.0.0" || genesis.consensus_version() != "posy/2.2" {
        return Err("SynQ Genesis artifact preparation has invalid protocol binding".to_string());
    }

    let contracts = required_object(genesis.value(), "contracts")?;
    let root = genesis
        .path()
        .parent()
        .ok_or_else(|| "Genesis path has no parent directory".to_string())?;
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
        verify_pre_approval_contract_record(contract, genesis_key, contract_name)?;
        let artifact = load_committed_artifact(root, contract, contract_name)?;
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

fn verify_pre_approval_contract_record(
    contract: &Value,
    genesis_key: &str,
    contract_name: &str,
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
        || required_string(artifact, "required_network_id")? != "synergy-testnet-v3"
        || required_string(artifact, "required_signature_algorithm")? != "ML-DSA-65"
    {
        return Err(format!(
            "Genesis contracts.{genesis_key} artifact is not bound to Testnet-v3 ML-DSA-65"
        ));
    }
    Ok(())
}

fn load_committed_artifact(
    root: &Path,
    contract: &Value,
    contract_name: &str,
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
        || required_string(&manifest_value, "required_network_id")? != "synergy-testnet-v3"
        || required_string(&manifest_value, "required_signature_algorithm")? != "ML-DSA-65"
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
    use crate::genesis::load_genesis_from_path_for_test;

    fn identity_assigned_candidate() -> GenesisDocument {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join("genesis.testnet-v3.identity-assigned.json");
        load_genesis_from_path_for_test(path).expect("identity-assigned candidate must validate")
    }

    #[test]
    fn identity_assigned_genesis_prepares_all_eight_native_synq_artifacts() {
        let prepared = prepare_testnet_v3_genesis_execution_state(&identity_assigned_candidate())
            .expect("all committed native SynQ artifacts must validate through AIVM admission");
        assert_eq!(prepared.artifact_keys.len(), 8);
        assert_eq!(prepared.execution_state.synq_artifacts.len(), 8);
        assert!(prepared.execution_state.synq_contracts.is_empty());
        assert_ne!(
            prepared.pre_deployment_state_root,
            crate::synergy_types::Hash::zero()
        );
    }

    #[test]
    fn prepared_artifacts_cannot_be_mistaken_for_deployed_genesis_contracts() {
        let prepared = prepare_testnet_v3_genesis_execution_state(&identity_assigned_candidate())
            .expect("artifact preparation");
        assert!(prepared.reject_as_finalized_genesis_state().is_err());
    }
}
