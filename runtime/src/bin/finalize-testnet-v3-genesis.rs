//! Builds the Phase-7 Testnet-v3 genesis candidate from executed ceremony
//! evidence and public inputs only.
//!
//! This command never decrypts custody material and never signs. It verifies
//! the executed ceremony record, independently reproduces every deployment
//! address and constructor hash, binds the receipts and AIVM roots, and writes
//! a staged candidate. Canonical replacement is deliberately a separate
//! `--apply` step so the staged candidate can pass the runtime loader and test
//! gates first.

use base64::Engine as _;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use synergy_testnet::consensus_parameters::{
    load_finalized_consensus_parameters, LoadedConsensusParameters,
};
use synergy_testnet::execution::GenesisExecutionSnapshot;
use synergy_testnet::genesis::{
    bind_testnet_v3_genesis_consensus_parameters, load_genesis_from_path,
    recompute_testnet_v3_candidate_integrity,
};
use synergy_testnet::genesis_deployment::{
    compute_genesis_receipt_root, constructor_arguments, derive_genesis_addresses,
    GenesisAuthorities, GenesisContract, GenesisDeploymentPlan, GenesisParameters, GenesisSigner,
    GenesisValidator,
};
use synergy_testnet::synq_execution::{SynQAivmReceiptSummary, SynQContractArtifact};
use synergy_testnet::testnet_v3_release_approval::{
    load_frozen_governance_authority, verify_release_approval_file,
    TestnetV3GenesisReleaseApprovalRequest,
};

const EXECUTION_STATUS: &str = "launch/production-genesis-ceremony/execution-status.json";
const DEPLOYMENT_RECEIPTS: &str = "launch/production-genesis-ceremony/deployment-receipts.json";
const INITIALIZATION_RECEIPTS: &str =
    "launch/production-genesis-ceremony/initialization-receipts.json";
const EXECUTION_STATE: &str = "launch/production-genesis-ceremony/execution-state.json";
/// Superseded authority input retained only for historical ceremony replay.
/// Fresh P3 callers must pass their dated V4 authority record with
/// `--authorities`; this file is reachable only through `--legacy-authorities`.
const LEGACY_AUTHORITIES_FILE: &str = "launch/TESTNET_V3_PRODUCTION_AUTHORITIES.json";
const CONTRACTS_FILE: &str = "launch/TESTNET_V3_PRODUCTION_CONTRACT_ADDRESSES.json";
const CONSENSUS_PARAMETERS_FILE: &str = "launch/TESTNET_V3_CONSENSUS_PARAMETERS.json";
const CONSENSUS_PARAMETER_DECISION_FILE: &str =
    "launch/TESTNET_V3_CONSENSUS_PARAMETER_RELEASE_DECISION.md";
const SOURCE_GENESIS: &str = "genesis.testnet-v3.identity-assigned.json";
const SOURCE_GENESIS_ARCHIVE: &str =
    "launch/production-genesis-ceremony/source-genesis.identity-assigned.json";
const DEFAULT_OUTPUT: &str =
    "launch/production-genesis-ceremony/genesis.testnet-v3.final-candidate.json";
const DEFAULT_RELEASE_APPROVAL: &str =
    "launch/production-genesis-ceremony/testnet-v3-genesis-release-approval.json";

fn fail(message: impl AsRef<str>) -> ! {
    eprintln!("finalize-testnet-v3-genesis: {}", message.as_ref());
    std::process::exit(1);
}

fn repo() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read_bytes(path: &Path) -> Vec<u8> {
    fs::read(path).unwrap_or_else(|error| fail(format!("read {}: {error}", path.display())))
}

fn read_json(path: &Path) -> Value {
    serde_json::from_slice(&read_bytes(path))
        .unwrap_or_else(|error| fail(format!("parse {}: {error}", path.display())))
}

fn sha256_bytes(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn sha256_file(path: &Path) -> String {
    sha256_bytes(&read_bytes(path))
}

fn source_genesis_path(root: &Path) -> PathBuf {
    let archive = root.join(SOURCE_GENESIS_ARCHIVE);
    if archive.exists() {
        archive
    } else {
        root.join(SOURCE_GENESIS)
    }
}

fn require_string<'a>(value: &'a Value, key: &str) -> &'a str {
    value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_else(|| fail(format!("missing string field {key}")))
}

fn base64_public_key(root: &Path, role: &str) -> Vec<u8> {
    let path = root
        .join("testnet-v3-identity-files")
        .join(role)
        .join("identity.pub.json");
    let value = read_json(&path);
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(require_string(&value, "public_key"))
        .unwrap_or_else(|error| fail(format!("decode {} public key: {error}", role)));
    if bytes.len() != 2_592 {
        fail(format!(
            "{role} public key is {} bytes, expected ML-DSA-87 length 2592",
            bytes.len()
        ));
    }
    bytes
}

/// Loads the role's public, Genesis-scoped dual-key authorization binding.
///
/// The finalizer only needs the public binding to derive the canonical
/// identity address for each signer.  It intentionally never reads an
/// encrypted envelope or any other private custody material.
fn role_identity_authorization(
    root: &Path,
    role: &str,
) -> synergy_testnet::identity_auth::IdentityAuthorizationCarrier {
    let path = root
        .join("testnet-v3-identity-files")
        .join(role)
        .join("genesis-authorization-binding.json");
    let binding = serde_json::from_slice(&read_bytes(&path))
        .unwrap_or_else(|error| fail(format!("parse {}: {error}", path.display())));
    synergy_testnet::identity_auth::IdentityAuthorizationCarrier::new(
        synergy_testnet::identity_auth::GENESIS_CEREMONY_AUTHORIZATION_DOMAIN,
        binding,
    )
    .unwrap_or_else(|error| {
        fail(format!(
            "construct canonical Genesis identity authorization carrier for {role}: {error}"
        ))
    })
}

fn authority_record<'a>(authorities: &'a Value, role: &str) -> &'a Value {
    authorities["authorities"]
        .as_array()
        .unwrap_or_else(|| fail("authorities array is missing"))
        .iter()
        .find(|entry| entry["role_id"] == role)
        .unwrap_or_else(|| fail(format!("authority record missing {role}")))
}

fn authority_address(authorities: &Value, role: &str) -> String {
    require_string(
        authority_record(authorities, role),
        "standard_account_address",
    )
    .to_string()
}

fn staged_artifact(root: &Path, contract: GenesisContract) -> SynQContractArtifact {
    let dir = root.join("genesis-contracts/staged-governance-v1");
    let name = contract.name();
    SynQContractArtifact::new(
        read_bytes(&dir.join(format!("{name}.compiled.synq"))),
        String::from_utf8(read_bytes(&dir.join(format!("{name}.abi.json"))))
            .unwrap_or_else(|error| fail(format!("{name} ABI is not UTF-8: {error}"))),
        String::from_utf8(read_bytes(&dir.join(format!("{name}.manifest.json"))))
            .unwrap_or_else(|error| fail(format!("{name} manifest is not UTF-8: {error}"))),
    )
}

fn production_parameters(genesis: &Value) -> GenesisParameters {
    let contracts = &genesis["contracts"];
    let s = |value: &Value| {
        value
            .as_str()
            .unwrap_or_else(|| fail("expected genesis string"))
            .to_string()
    };
    let n = |value: &Value| {
        value
            .as_u64()
            .unwrap_or_else(|| fail("expected genesis u64"))
            .to_string()
    };
    let validators = contracts["validator_registry"]["init_params"]["validators"]
        .as_array()
        .unwrap_or_else(|| fail("validator registry validators are missing"))
        .iter()
        .map(|validator| GenesisValidator {
            id_hash: format!("0x{}", s(&validator["validator_id_hash"])),
            operator_address: s(&validator["operator_address"]),
            reward_address: s(&validator["reward_address"]),
            voting_power: n(&validator["voting_power"]),
            self_stake_nwei: s(&validator["stake_nwei"]),
            metadata_hash: format!("0x{}", s(&validator["metadata_hash"])),
            key_bundle_hash: format!("0x{}", s(&validator["key_bundle_hash"])),
            activation_height: n(&validator["activation_height"]),
        })
        .collect();

    GenesisParameters {
        identity_registration_fee_nwei: s(
            &contracts["identity"]["init_params"]["registration_fee_nwei"]
        ),
        identity_reserved_names: contracts["identity"]["init_params"]["reserved_names"]
            .as_array()
            .unwrap()
            .iter()
            .map(s)
            .collect(),
        validator_max_count: n(
            &contracts["validator_registry"]["init_params"]["max_validator_count"]
        ),
        validator_min_count: n(
            &contracts["validator_registry"]["init_params"]["min_validator_count"]
        ),
        validator_min_self_stake_nwei: s(
            &contracts["validator_registry"]["init_params"]["min_self_stake_nwei"]
        ),
        validators,
        staking_min_stake_nwei: s(&contracts["staking"]["init_params"]["min_stake_nwei"]),
        staking_max_stake_nwei: s(&contracts["staking"]["init_params"]["max_stake_nwei"]),
        staking_unbonding_blocks: "302400".to_string(),
        governance_quorum_bps: "6000".to_string(),
        governance_approval_bps: "5000".to_string(),
        governance_veto_bps: "3300".to_string(),
        governance_min_deposit_nwei: s(&contracts["governance"]["init_params"]["min_deposit_nwei"]),
        governance_voting_blocks: "302400".to_string(),
        governance_timelock_blocks: "43200".to_string(),
        treasury_required_signers: n(&contracts["treasury"]["init_params"]["required_signers"]),
        treasury_signers: contracts["treasury"]["init_params"]["signers"]
            .as_array()
            .unwrap()
            .iter()
            .map(s)
            .collect(),
        slashing_double_sign_bps: "500".to_string(),
        slashing_downtime_bps: "100".to_string(),
        slashing_invalid_block_bps: "500".to_string(),
        slashing_missed_blocks_threshold: n(
            &contracts["slashing"]["init_params"]["downtime_missed_blocks_threshold"]
        ),
        slashing_jail_blocks: "43200".to_string(),
        oracle_quorum_threshold: n(&contracts["synergy_oracle"]["init_params"]["quorum_threshold"]),
        oracle_replay_protection: true,
        oracle_source_domains: contracts["synergy_oracle"]["init_params"]
            ["accepted_source_domains"]
            .as_array()
            .unwrap()
            .iter()
            .map(s)
            .collect(),
        team_vesting_start_time: "1775044800".to_string(),
        team_allocation_nwei: "60000000000000000".to_string(),
        support_allocation_nwei: "10000000000000000".to_string(),
        team_count: "5".to_string(),
        support_count: "4".to_string(),
    }
}

fn authorities(root: &Path, frozen: &Value) -> GenesisAuthorities {
    GenesisAuthorities {
        genesis_deployer: GenesisSigner {
            public_key: base64_public_key(root, "SNRG-TESTNET-V3-GENESIS-DEPLOYER"),
            private_key: Vec::new(),
            identity_authorization: Some(role_identity_authorization(
                root,
                "SNRG-TESTNET-V3-GENESIS-DEPLOYER",
            )),
        },
        governance: GenesisSigner {
            public_key: base64_public_key(root, "SNRG-TESTNET-V3-GOVERNANCE-AUTHORITY"),
            private_key: Vec::new(),
            identity_authorization: Some(role_identity_authorization(
                root,
                "SNRG-TESTNET-V3-GOVERNANCE-AUTHORITY",
            )),
        },
        emergency_slashing_authority: authority_address(
            frozen,
            "SNRG-TESTNET-V3-EMERGENCY-SLASHING",
        ),
        validator_registry_authority: authority_address(
            frozen,
            "SNRG-TESTNET-V3-VALIDATOR-REGISTRY-AUTHORITY",
        ),
        validator_registry_authority_key: GenesisSigner {
            public_key: base64_public_key(root, "SNRG-TESTNET-V3-VALIDATOR-REGISTRY-AUTHORITY"),
            private_key: Vec::new(),
            identity_authorization: Some(role_identity_authorization(
                root,
                "SNRG-TESTNET-V3-VALIDATOR-REGISTRY-AUTHORITY",
            )),
        },
        reward_distributor_authority: authority_address(
            frozen,
            "SNRG-TESTNET-V3-REWARD-DISTRIBUTOR-AUTHORITY",
        ),
        identity_fee_collector: "synf1pnchsrnyral0u9r65xusjrexuctfh465h06l".to_string(),
        team_vesting_admin: "synu18tmdavp9yskftz4lldshrxvzwyg0tpnu23n9".to_string(),
        oracle_publisher: authority_address(frozen, "SNRG-TESTNET-V3-EMERGENCY-PAUSE-AUTHORITY"),
    }
}

fn contract_key(contract: GenesisContract) -> &'static str {
    match contract {
        GenesisContract::Identity => "identity",
        GenesisContract::ValidatorRegistry => "validator_registry",
        GenesisContract::Staking => "staking",
        GenesisContract::Governance => "governance",
        GenesisContract::Treasury => "treasury",
        GenesisContract::Slashing => "slashing",
        GenesisContract::RewardDistributor => "reward_distributor",
        GenesisContract::SynergyOracle => "synergy_oracle",
        GenesisContract::TeamVesting => "team_vesting",
    }
}

fn update_init_params(record: &mut Value, contract: GenesisContract, auth: &GenesisAuthorities) {
    let init = record["init_params"]
        .as_object_mut()
        .unwrap_or_else(|| fail(format!("{} init_params is not an object", contract.name())));
    match contract {
        GenesisContract::ValidatorRegistry => {
            init.insert(
                "authority_address".to_string(),
                Value::String(auth.validator_registry_authority.clone()),
            );
        }
        GenesisContract::Staking => {
            init.insert("delegation_enabled".to_string(), Value::Bool(false));
            init.insert(
                "minimum_delegation_nwei".to_string(),
                Value::String("0".to_string()),
            );
            init.insert(
                "maximum_delegation_nwei".to_string(),
                Value::String("0".to_string()),
            );
        }
        GenesisContract::Treasury => {
            init.remove("initial_balance_nwei");
            init.remove("vault_address");
            init.insert(
                "custody_model".to_string(),
                Value::String(
                    "non-custodial approval and accounting; TRE-A01 remains the sole reserve holder"
                        .to_string(),
                ),
            );
        }
        GenesisContract::Slashing => {
            init.insert(
                "initial_slashing_authority".to_string(),
                Value::String(auth.emergency_slashing_authority.clone()),
            );
        }
        GenesisContract::RewardDistributor => {
            init.remove("pool_address");
            init.remove("funding_model");
            init.insert(
                "distributor_authority".to_string(),
                Value::String(auth.reward_distributor_authority.clone()),
            );
            init.insert(
                "authority_semantics".to_string(),
                Value::String("distribution authorization only; not token custody".to_string()),
            );
        }
        GenesisContract::SynergyOracle => {
            init.insert(
                "authority_address".to_string(),
                Value::String(auth.oracle_publisher.clone()),
            );
            init.insert(
                "oracle_set".to_string(),
                Value::Array(vec![Value::String(auth.oracle_publisher.clone())]),
            );
        }
        _ => {}
    }
}

fn artifact_record(root: &Path, contract: GenesisContract, expected: &Value) -> Value {
    let name = contract.name();
    let staged = root.join("genesis-contracts/staged-governance-v1");
    let bytecode = read_bytes(&staged.join(format!("{name}.compiled.synq")));
    let abi = read_bytes(&staged.join(format!("{name}.abi.json")));
    let manifest_bytes = read_bytes(&staged.join(format!("{name}.manifest.json")));
    let source = read_bytes(&staged.join(format!("{name}.synq")));
    let manifest: Value = serde_json::from_slice(&manifest_bytes)
        .unwrap_or_else(|error| fail(format!("parse staged {name} manifest: {error}")));

    for (field, actual) in [
        ("bytecode_hash", sha256_bytes(&bytecode)),
        ("abi_hash", sha256_bytes(&abi)),
        ("manifest_hash", sha256_bytes(&manifest_bytes)),
    ] {
        if require_string(expected, field) != actual {
            fail(format!(
                "{name} {field} does not match the frozen derivation record"
            ));
        }
    }
    if manifest["required_chain_id"] != 1266
        || manifest["required_network_id"] != "synergy-testnet"
        || manifest["required_signature_algorithm"] != "ML-DSA-87"
    {
        fail(format!(
            "{name} staged manifest has an invalid chain/network/algorithm binding"
        ));
    }

    json!({
        "contract_name": name,
        "source_path": format!("genesis-contracts/contracts/{name}.synq"),
        "bytecode_path": format!("genesis-contracts/contracts/{name}.compiled.synq"),
        "abi_path": format!("genesis-contracts/contracts/{name}.abi.json"),
        "manifest_path": format!("genesis-contracts/contracts/{name}.manifest.json"),
        "source_hash": sha256_bytes(&source),
        "bytecode_hash": sha256_bytes(&bytecode),
        "abi_hash": sha256_bytes(&abi),
        "manifest_sha256": sha256_bytes(&manifest_bytes),
        "storage_schema_hash": manifest["storage_schema_hash"],
        "artifact_format": manifest["artifact_format"],
        "bytecode_version": manifest["bytecode_version"],
        "compiler_version": manifest["compiler_version"],
        "required_chain_id": 1266,
        "runtime_network_id": "testnet",
        "required_network_id": "synergy-testnet",
        "network_id_normalization": "runtime testnet binds to the canonical SynQ domain synergy-testnet",
        "required_signature_algorithm": "ML-DSA-87"
    })
}

fn validate_receipt_chain(receipts: &[SynQAivmReceiptSummary], label: &str) {
    if receipts.is_empty() {
        fail(format!("{label} receipts are empty"));
    }
    for receipt in receipts {
        if receipt.status != "succeeded" || receipt.error_code.is_some() {
            fail(format!(
                "{label} receipt for {} did not succeed",
                receipt.contract_address
            ));
        }
    }
    for pair in receipts.windows(2) {
        if pair[0].post_state_root != pair[1].pre_state_root {
            fail(format!("{label} receipt state chain is discontinuous"));
        }
    }
}

fn validate_supply_unchanged(before: &Value, after: &Value) {
    for key in ["allocation_sum_check", "token"] {
        if before[key] != after[key] {
            fail(format!(
                "finalization attempted to change supply-bearing field {key}"
            ));
        }
    }
    for table in ["allocations", "balances"] {
        let before_entries = before[table]
            .as_array()
            .unwrap_or_else(|| fail(format!("source genesis {table} must be an array")));
        let after_entries = after[table]
            .as_array()
            .unwrap_or_else(|| fail(format!("final genesis {table} must be an array")));
        if before_entries.len() != after_entries.len() {
            fail(format!("finalization changed {table} cardinality"));
        }
        for (before_entry, after_entry) in before_entries.iter().zip(after_entries) {
            if before_entry["account_id"] != after_entry["account_id"]
                || before_entry["balance_nwei"] != after_entry["balance_nwei"]
                    && table == "balances"
                || before_entry["amount_nwei"] != after_entry["amount_nwei"]
                    && table == "allocations"
            {
                fail(format!(
                    "finalization changed {table} account identity or amount"
                ));
            }
            if before_entry["address"] != after_entry["address"]
                && before_entry["account_id"] != "TEM-A01"
            {
                fail(format!(
                    "finalization changed a non-TeamVesting {table} address"
                ));
            }
        }
    }
}

fn migrate_finalized_consumer_addresses(
    candidate: &mut Value,
    resolved: &BTreeMap<GenesisContract, String>,
) {
    candidate["modules"]["identity"]["contract_address"] =
        Value::String(resolved[&GenesisContract::Identity].clone());
    candidate["modules"]["treasury"]["contract_address"] =
        Value::String(resolved[&GenesisContract::Treasury].clone());
    candidate["vesting"][0]["contract_address"] =
        Value::String(resolved[&GenesisContract::TeamVesting].clone());

    let team_vesting_address = &resolved[&GenesisContract::TeamVesting];
    for table in ["accounts", "allocations", "balances"] {
        let entries = candidate[table]
            .as_array_mut()
            .unwrap_or_else(|| fail(format!("genesis {table} must be an array")));
        let entry = entries
            .iter_mut()
            .find(|entry| entry["account_id"] == "TEM-A01")
            .unwrap_or_else(|| fail(format!("genesis {table} is missing TEM-A01")));
        entry["address"] = Value::String(team_vesting_address.clone());
        entry["address_role"] = Value::String("deployed TeamVesting contract instance".to_string());
    }

    let register = candidate["address_assignment_register"]
        .as_array_mut()
        .unwrap_or_else(|| fail("address_assignment_register must be an array"));
    let team_identity = register
        .iter_mut()
        .find(|entry| entry["account_id"] == "TEM-A01")
        .unwrap_or_else(|| fail("address_assignment_register is missing TEM-A01"));
    team_identity["assignment_role"] =
        Value::String("administrative and custody identity only".to_string());
    team_identity["deployed_contract_address"] = Value::String(team_vesting_address.clone());

    let sale_identity = register
        .iter_mut()
        .find(|entry| entry["account_id"] == "SAL-A01")
        .unwrap_or_else(|| fail("address_assignment_register is missing SAL-A01"));
    sale_identity["assignment_role"] =
        Value::String("sale reserve custody identity; SaleClaim not deployed".to_string());
    sale_identity["deployed_contract_address"] = Value::Null;
}

fn finalized_consensus_parameters(root: &Path) -> (LoadedConsensusParameters, String, String) {
    let parameters_path = root.join(CONSENSUS_PARAMETERS_FILE);
    let loaded = load_finalized_consensus_parameters(&parameters_path)
        .unwrap_or_else(|error| fail(format!("load finalized consensus parameters: {error}")));
    let decision_path = root.join(CONSENSUS_PARAMETER_DECISION_FILE);
    let decision_bytes = read_bytes(&decision_path);
    let decision_sha256 = sha256_bytes(&decision_bytes);
    let manifest = loaded.manifest.as_posy().unwrap_or_else(|error| {
        fail(format!(
            "legacy finalization requires PoSy parameters: {error}"
        ))
    });
    let decision_id = manifest.governance_approval_id.clone();
    let decision_marker = format!("Decision ID: `{decision_id}`");
    if !decision_bytes
        .windows(decision_marker.len())
        .any(|window| window == decision_marker.as_bytes())
    {
        fail(format!(
            "{} does not contain the manifest Decision ID {}",
            decision_path.display(),
            decision_id
        ));
    }
    if manifest.epoch_length_slots != Some(1_000)
        || manifest.target_block_time_ms != 2_000
        || manifest.proposal_timeout_ms != 1_500
        || manifest.prevote_timeout_ms != 1_500
        || manifest.precommit_timeout_ms != 1_500
        || manifest.max_round_timeout_ms != 10_000
    {
        fail("finalized consensus manifest does not contain the approved launch timing profile");
    }
    (loaded, decision_sha256, decision_id)
}

fn build_candidate(root: &Path, authorities_path: &Path) -> Value {
    let source_path = source_genesis_path(root);
    let mut candidate = read_json(&source_path);
    let original = candidate.clone();
    let frozen_authorities = read_json(authorities_path);
    let frozen_contracts = read_json(&root.join(CONTRACTS_FILE));
    let execution = read_json(&root.join(EXECUTION_STATUS));
    let deployment_values = read_json(&root.join(DEPLOYMENT_RECEIPTS));
    let initialization_values = read_json(&root.join(INITIALIZATION_RECEIPTS));
    let execution_state_value = read_json(&root.join(EXECUTION_STATE));
    let (consensus_parameters, decision_sha256, decision_id) = finalized_consensus_parameters(root);
    let execution_snapshot: GenesisExecutionSnapshot =
        serde_json::from_value(execution_state_value.clone())
            .unwrap_or_else(|error| fail(format!("decode execution-state snapshot: {error}")));
    let restored_execution_state = execution_snapshot
        .restore_testnet_v3()
        .unwrap_or_else(|error| fail(format!("validate execution-state snapshot: {error}")));
    let deployments: Vec<SynQAivmReceiptSummary> =
        serde_json::from_value(deployment_values.clone())
            .unwrap_or_else(|error| fail(format!("decode deployment receipts: {error}")));
    let initializations: Vec<SynQAivmReceiptSummary> =
        serde_json::from_value(initialization_values.clone())
            .unwrap_or_else(|error| fail(format!("decode initialization receipts: {error}")));

    if execution["status"] != "EXECUTION_PASSED"
        || execution["mode"] != "execute"
        || execution["address_mismatches"] != json!([])
        || execution["deployment_receipts"] != 9
        || execution["initialization_receipts"] != 27
        || execution["execution_state_balance_count"] != 36
        || execution["execution_state_contract_count"] != 9
        || execution["execution_state_artifact_count"] != 9
        || execution["genesis_deployer_retirement"] != "PermanentlyRetired"
    {
        fail("execution-status.json is not a completed, mismatch-free execute record");
    }
    if execution["execution_state_snapshot"] != "execution-state.json"
        || execution["execution_state_snapshot_sha256"] != sha256_file(&root.join(EXECUTION_STATE))
        || execution["execution_state_snapshot_canonical_sha256"]
            != sha256_bytes(
                &serde_json::to_vec(&execution_snapshot)
                    .unwrap_or_else(|error| fail(format!("encode execution snapshot: {error}"))),
            )
    {
        fail("execution-state snapshot is missing or does not match execution evidence");
    }
    if execution_snapshot.state_root
        != execution["post_deployment_execution_state_root"]
            .as_str()
            .unwrap_or_default()
        || execution_snapshot.aivm_state_root
            != execution["post_deployment_aivm_state_root"]
                .as_str()
                .unwrap_or_default()
    {
        fail("execution-state snapshot roots do not match execution evidence");
    }
    if restored_execution_state.synq_contracts.len() != 9
        || restored_execution_state.synq_artifacts.len() != 9
        || restored_execution_state.balances_nwei.len() != 36
        || !restored_execution_state.verified_authorizations.is_empty()
        || !restored_execution_state.synq_verifications.is_empty()
        || !restored_execution_state.synq_errors.is_empty()
    {
        fail("execution-state snapshot has an invalid finalized-state boundary");
    }
    let source_balances = candidate["balances"]
        .as_array()
        .unwrap_or_else(|| fail("source genesis balances must be an array"));
    let team_vesting_address = frozen_contracts["contracts"]
        .as_array()
        .and_then(|entries| {
            entries
                .iter()
                .find(|entry| entry["contract"] == "TeamVesting")
        })
        .and_then(|entry| entry["contract_address"].as_str())
        .unwrap_or_else(|| fail("frozen TeamVesting contract address is missing"));
    for balance in source_balances {
        let source_address = require_string(balance, "address");
        let address = if balance["account_id"] == "TEM-A01" {
            team_vesting_address
        } else {
            source_address
        };
        let amount = require_string(balance, "balance_nwei")
            .parse::<u128>()
            .unwrap_or_else(|error| fail(format!("parse source balance: {error}")));
        if restored_execution_state.balances_nwei.get(address).copied() != Some(amount) {
            fail(format!(
                "execution-state snapshot balance does not match source genesis for {address}"
            ));
        }
    }
    if deployments.len() != 9 || initializations.len() != 27 {
        fail("ceremony receipt counts do not match 9 deployments and 27 initializations");
    }
    validate_receipt_chain(&deployments, "deployment");
    validate_receipt_chain(&initializations, "initialization");
    if deployments.last().unwrap().post_state_root != initializations[0].pre_state_root {
        fail("deployment and initialization receipt chains are discontinuous");
    }
    let receipt_root = compute_genesis_receipt_root(&deployments, &initializations)
        .unwrap_or_else(|error| fail(format!("recompute receipt root: {error}")))
        .to_hex();
    if execution["deployment_receipt_root"] != receipt_root {
        fail("recomputed combined receipt root does not match execution evidence");
    }
    let declared_authorities_sha = execution["inputs"]["authorities_file_sha256"]
        .as_str()
        .unwrap_or_else(|| fail("execution evidence has no authorities file SHA-256"));
    if sha256_file(authorities_path) != declared_authorities_sha {
        fail(format!(
            "{} changed after the ceremony",
            authorities_path.display()
        ));
    }
    let contracts_path = root.join(CONTRACTS_FILE);
    let declared_contracts_sha = execution["inputs"]["contracts_file_sha256"]
        .as_str()
        .unwrap_or_else(|| fail("execution evidence has no contracts file SHA-256"));
    if sha256_file(&contracts_path) != declared_contracts_sha {
        fail(format!(
            "{} changed after the ceremony",
            contracts_path.display()
        ));
    }
    let declared_source_sha = execution["inputs"]["source_genesis_file_sha256"]
        .as_str()
        .unwrap();
    if sha256_file(&source_path) != declared_source_sha {
        fail(format!(
            "{} changed after the ceremony",
            source_path.display()
        ));
    }

    let auth = authorities(root, &frozen_authorities);
    let params = production_parameters(&candidate);
    let artifacts: BTreeMap<GenesisContract, SynQContractArtifact> =
        GenesisContract::APPROVED_ORDER
            .iter()
            .map(|contract| (*contract, staged_artifact(root, *contract)))
            .collect();
    let plan = GenesisDeploymentPlan::new(&artifacts)
        .unwrap_or_else(|error| fail(format!("build deployment plan: {error}")));
    plan.validate()
        .unwrap_or_else(|error| fail(format!("validate deployment plan: {error}")));
    let derived =
        derive_genesis_addresses(&plan, &auth.genesis_deployer.public_key, &auth, &params)
            .unwrap_or_else(|error| fail(format!("derive production addresses: {error}")));
    let frozen_entries = frozen_contracts["contracts"]
        .as_array()
        .unwrap_or_else(|| fail("frozen contracts array is missing"));
    if serde_json::to_value(&derived).unwrap() != Value::Array(frozen_entries.clone()) {
        fail("independent address derivation no longer matches the frozen record");
    }

    let old_contracts = candidate["contracts"]
        .as_object()
        .unwrap_or_else(|| fail("genesis contracts is not an object"))
        .clone();
    let mut active_contracts = Map::new();
    let mut resolved = BTreeMap::new();
    let mut deployment_bindings = Vec::new();
    let mut address_migrations = Vec::new();
    for (index, contract) in GenesisContract::APPROVED_ORDER.iter().enumerate() {
        let key = contract_key(*contract);
        let expected = &frozen_entries[index];
        let address = require_string(expected, "contract_address").to_string();
        let mut record = old_contracts
            .get(key)
            .cloned()
            .unwrap_or_else(|| fail(format!("source genesis is missing contracts.{key}")));
        let identity_address = record["address"].clone();
        let constructor_bytes = constructor_arguments(*contract, &auth, &params, &resolved)
            .unwrap_or_else(|error| fail(format!("{} constructor: {error}", contract.name())));
        let constructor_hash = sha256_bytes(&constructor_bytes);
        if constructor_hash != require_string(expected, "constructor_args_hash") {
            fail(format!("{} constructor hash changed", contract.name()));
        }
        let constructor_value: Value =
            serde_json::from_slice(&constructor_bytes).unwrap_or_else(|error| {
                fail(format!("decode {} constructor: {error}", contract.name()))
            });
        let artifact = artifact_record(root, *contract, expected);
        let receipt = &deployment_values[index];
        if receipt["contract_address"] != address {
            fail(format!(
                "{} deployment receipt address mismatch",
                contract.name()
            ));
        }

        record["address"] = Value::String(address.clone());
        record["bytecode_hash"] = artifact["bytecode_hash"].clone();
        record["artifact"] = artifact;
        record["status"] = Value::String("deployed_initialized_genesis_bound".to_string());
        record["contract_identity"] = json!({
            "address": identity_address,
            "relationship": "administrative and custody identity only; not the deployed instance address"
        });
        record["constructor"] = json!({
            "encoding": "canonical JSON typed argument array",
            "arguments": constructor_value,
            "arguments_sha256": constructor_hash
        });
        record["deployment"] = json!({
            "nonce": expected["nonce"],
            "deployer_address": expected["deployer_address"],
            "payload_hash": expected["payload_hash"],
            "synq_contract_address": expected["synq_contract_address"],
            "receipt": receipt,
            "receipt_hash": receipt["receipt_hash"]
        });
        update_init_params(&mut record, *contract, &auth);
        address_migrations.push(json!({
            "contract": contract.name(),
            "identity_or_custody_address": identity_address.clone(),
            "deployed_contract_address": address.clone(),
            "migration_rule": "runtime consumers use deployed_contract_address; identity and custody registries preserve identity_or_custody_address"
        }));
        active_contracts.insert(key.to_string(), record);
        resolved.insert(*contract, address.clone());
        deployment_bindings.push(json!({
            "nonce": expected["nonce"],
            "contract": contract.name(),
            "contract_address": address,
            "constructor_args_hash": expected["constructor_args_hash"],
            "bytecode_hash": expected["bytecode_hash"],
            "abi_hash": expected["abi_hash"],
            "manifest_hash": expected["manifest_hash"],
            "deployment_receipt_hash": receipt["receipt_hash"]
        }));
    }
    candidate["contracts"] = Value::Object(active_contracts);
    migrate_finalized_consumer_addresses(&mut candidate, &resolved);
    address_migrations.push(json!({
        "contract": "SaleClaim",
        "identity_or_custody_address": old_contracts["sale_claim"]["address"],
        "deployed_contract_address": Value::Null,
        "migration_rule": "preserve SAL-A01 as the sale reserve custody identity; no Testnet-v3 contract consumer and no reserved deployment nonce"
    }));
    candidate["contract_address_migration"] = json!({
        "schema_version": 1,
        "status": "APPLIED",
        "active_contract_count": 9,
        "sale_claim": "DEFERRED_TO_MAINNET_BETA_NOT_DEPLOYED",
        "entries": address_migrations
    });
    bind_testnet_v3_genesis_consensus_parameters(
        &mut candidate,
        &consensus_parameters,
        &decision_sha256,
    )
    .unwrap_or_else(|error| fail(format!("bind finalized consensus parameters: {error}")));

    let active_names = GenesisContract::APPROVED_ORDER
        .iter()
        .map(|contract| contract_key(*contract))
        .collect::<BTreeSet<_>>();
    let identities = candidate["contract_identities"]
        .as_array_mut()
        .unwrap_or_else(|| fail("contract_identities is not an array"));
    for identity in identities {
        let name = identity["contract_name"].as_str().unwrap_or_default();
        if active_names.contains(name) {
            let deployed = &resolved[&GenesisContract::APPROVED_ORDER
                .iter()
                .copied()
                .find(|contract| contract_key(*contract) == name)
                .unwrap()];
            identity["status"] = Value::String("identity_record_only_not_deployed".to_string());
            identity["deployed_contract_address"] = Value::String(deployed.clone());
            identity.as_object_mut().unwrap().remove("artifact");
        } else if name == "sale_claim" {
            identity["status"] =
                Value::String("deferred_to_mainnet_beta_not_deployed_on_testnet_v3".to_string());
            identity.as_object_mut().unwrap().remove("artifact");
        }
    }

    let mut hash_inputs = candidate["canonicalization"]["genesis_hash_inputs"]
        .as_array()
        .unwrap()
        .clone();
    if !hash_inputs
        .iter()
        .any(|entry| entry == "genesis_deployment")
    {
        hash_inputs.push(Value::String("genesis_deployment".to_string()));
    }
    if !hash_inputs
        .iter()
        .any(|entry| entry == "contract_address_migration")
    {
        hash_inputs.push(Value::String("contract_address_migration".to_string()));
    }
    if !hash_inputs
        .iter()
        .any(|entry| entry == "consensus_parameters")
    {
        hash_inputs.push(Value::String("consensus_parameters".to_string()));
    }
    candidate["canonicalization"]["genesis_hash_inputs"] = Value::Array(hash_inputs);
    candidate["schema_version"] = Value::String("v1.5-deployment-and-parameter-bound".to_string());
    candidate["network"]["genesis_schema_version"] = Value::String("v1.5".to_string());
    candidate["network"]["status"] =
        Value::String("contract_deployment_executed_pending_release_approval".to_string());
    candidate["network_magic_bytes"]["status"] =
        Value::String("candidate_recomputed_pending_release_approval".to_string());
    candidate["execution"]["genesis_execution_state_root"] =
        execution["post_deployment_execution_state_root"].clone();
    candidate["execution"]["genesis_aivm_state_root"] =
        execution["post_deployment_aivm_state_root"].clone();
    candidate["execution"]["genesis_receipt_root"] = Value::String(receipt_root.clone());
    candidate["execution"]["genesis_deployment_manifest_hash"] =
        execution["deployment_manifest_hash"].clone();
    candidate["genesis_deployment"] = json!({
        "schema_version": 1,
        "status": "EXECUTED_AND_BOUND",
        "chain_id": 1266,
        "runtime_network_id": "testnet",
        "synq_network_id": "synergy-testnet",
        "candidate_input_id": execution["candidate_input_id"],
        "deployer_address": frozen_contracts["deployer_address"],
        "authority_record_sha256": sha256_file(authorities_path),
        "contract_derivation_record_sha256": sha256_file(&root.join(CONTRACTS_FILE)),
        "execution_status_sha256": sha256_file(&root.join(EXECUTION_STATUS)),
        "deployment_receipts_sha256": sha256_file(&root.join(DEPLOYMENT_RECEIPTS)),
        "initialization_receipts_sha256": sha256_file(&root.join(INITIALIZATION_RECEIPTS)),
        "execution_state_snapshot_sha256": sha256_file(&root.join(EXECUTION_STATE)),
        "execution_state_snapshot_canonical_sha256": execution["execution_state_snapshot_canonical_sha256"],
        "contracts": deployment_bindings,
        "deployment_receipts": deployment_values,
        "initialization_receipts": initialization_values,
        "execution_state": execution_state_value,
        "deployment_count": 9,
        "initialization_count": 27,
        "receipt_root": receipt_root,
        "post_deployment_execution_state_root": execution["post_deployment_execution_state_root"],
        "post_deployment_aivm_state_root": execution["post_deployment_aivm_state_root"],
        "deployment_manifest_hash": execution["deployment_manifest_hash"],
        "genesis_deployer_lifecycle": "PermanentlyRetired"
    });
    candidate["integrity"]["status"] =
        Value::String("candidate_deployment_bound_pending_release_approval".to_string());
    candidate["integrity"]["signed_by"] = json!([]);
    candidate["integrity"]["post_deployment_execution_state_root"] =
        execution["post_deployment_execution_state_root"].clone();
    candidate["integrity"]["post_deployment_aivm_state_root"] =
        execution["post_deployment_aivm_state_root"].clone();
    candidate["integrity"]["deployment_manifest_hash"] =
        execution["deployment_manifest_hash"].clone();
    candidate["integrity"]["consensus_parameter_root_sha3_512"] =
        Value::String(consensus_parameters.root.to_hex());
    candidate["integrity"]["consensus_parameter_manifest_sha256"] =
        Value::String(sha256_bytes(&consensus_parameters.canonical_bytes));
    candidate["integrity"]["consensus_parameter_decision_id"] = Value::String(decision_id);
    candidate["testnet_v3_initialization"]["finalization_status"] = Value::String(
        "production_contract_deployment_executed_and_bound_pending_release_approval".to_string(),
    );
    candidate["testnet_v3_initialization"]["native_contract_count"] = json!(9);
    candidate["testnet_v3_initialization"]["sale_claim_status"] =
        Value::String("deferred_to_mainnet_beta_not_deployed".to_string());

    validate_supply_unchanged(&original, &candidate);
    recompute_testnet_v3_candidate_integrity(&mut candidate)
        .unwrap_or_else(|error| fail(format!("recompute candidate integrity: {error}")));
    candidate
}

fn pretty_json(value: &Value) -> Vec<u8> {
    let mut bytes = serde_json::to_vec_pretty(value)
        .unwrap_or_else(|error| fail(format!("encode JSON: {error}")));
    bytes.push(b'\n');
    bytes
}

fn finalized_allocation_manifest(root: &Path, candidate: &Value) -> Value {
    let mut manifest = read_json(&root.join("runtime/testnet-allocation-manifest.json"));
    let allocations = candidate["allocations"]
        .as_array()
        .unwrap_or_else(|| fail("final candidate allocations must be an array"));
    let by_id = allocations
        .iter()
        .map(|entry| (require_string(entry, "account_id"), entry))
        .collect::<BTreeMap<_, _>>();
    let accounts = candidate["accounts"]
        .as_array()
        .unwrap_or_else(|| fail("final candidate accounts must be an array"))
        .iter()
        .map(|entry| (require_string(entry, "account_id"), entry))
        .collect::<BTreeMap<_, _>>();
    let balances = candidate["balances"]
        .as_array()
        .unwrap_or_else(|| fail("final candidate balances must be an array"))
        .iter()
        .map(|entry| (require_string(entry, "account_id"), entry))
        .collect::<BTreeMap<_, _>>();
    for entry in manifest["allocations"]
        .as_array_mut()
        .unwrap_or_else(|| fail("allocation manifest allocations must be an array"))
    {
        let account_id = require_string(entry, "account_id").to_string();
        if let Some(finalized) = by_id.get(account_id.as_str()) {
            entry["address"] = finalized["address"].clone();
            entry["amount_nwei"] = finalized["amount_nwei"].clone();
        } else if matches!(
            account_id.as_str(),
            "SYS-01" | "SYS-02" | "SYS-03" | "SYS-04"
        ) {
            // System accounts are declared in the canonical genesis account
            // and balance tables but intentionally have no token-allocation
            // entry.  They are zero-balance protocol destinations, not an
            // omitted supply allocation.  Preserve that distinction while
            // deriving the human release manifest from canonical records.
            let account = accounts.get(account_id.as_str()).unwrap_or_else(|| {
                fail(format!(
                    "final candidate is missing system account {account_id}"
                ))
            });
            let balance = balances.get(account_id.as_str()).unwrap_or_else(|| {
                fail(format!(
                    "final candidate is missing system balance {account_id}"
                ))
            });
            if require_string(balance, "balance_nwei") != "0"
                || require_string(entry, "amount_nwei") != "0"
            {
                fail(format!(
                    "system account {account_id} must remain a zero-balance non-allocation"
                ));
            }
            entry["address"] = account["address"].clone();
        } else {
            fail(format!(
                "final candidate is missing allocation {account_id}"
            ));
        }
        if account_id == "SAL-A01" {
            entry["control_reference"] = Value::String(
                "sale reserve custody identity; SaleClaim not deployed on Testnet-v3".to_string(),
            );
        } else if account_id == "TEM-A01" {
            entry["control_reference"] =
                Value::String("deployed TeamVesting contract instance".to_string());
        }
    }
    manifest["schema_version"] = json!(3);
    manifest["source_model"] = Value::String(
        "final deployment-bound Testnet-v3 genesis with Track-H address migration".to_string(),
    );
    manifest["generated_from"] = Value::String(SOURCE_GENESIS.to_string());
    manifest["allocation_hash"] = candidate["integrity"]["allocation_hash"].clone();
    manifest["address_migration_status"] = Value::String("APPLIED".to_string());
    manifest
}

fn finalized_network_identifiers(root: &Path, candidate: &Value) -> Value {
    let path = root.join("network-identifiers.testnet-v3.identity-assigned.json");
    let mut identifiers = read_json(&path);
    identifiers["schema"]["status"] = Value::String("finalized_release_candidate".to_string());
    identifiers["network"]["status"] =
        Value::String("contract_deployment_executed_pending_release_approval".to_string());
    identifiers["cryptographic_identity"]["genesis_hash"] =
        candidate["integrity"]["genesis_hash"].clone();
    identifiers["cryptographic_identity"]["genesis_hash_status"] =
        Value::String("deployment_bound_pending_release_approval".to_string());
    identifiers["cryptographic_identity"]["network_magic_bytes"]["value"] =
        candidate["network_magic_bytes"]["value"].clone();
    identifiers["cryptographic_identity"]["network_magic_bytes"]["status"] =
        Value::String("deployment_bound_pending_release_approval".to_string());
    identifiers["testnet_v3_identity_registry"]["candidate_genesis_hash"] =
        candidate["integrity"]["genesis_hash"].clone();
    identifiers["generated_identifier_policy"]["completed"]
        .as_array_mut()
        .map(|completed| {
            completed.push(Value::String(
                "Bound nine deployed contract instances and applied Track-H address migration"
                    .to_string(),
            ));
        });
    identifiers
}

fn copy_with_parent(source: &Path, destination: &Path) -> Result<(), String> {
    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| format!("create {}: {error}", parent.display()))?;
    }
    fs::copy(source, destination).map(|_| ()).map_err(|error| {
        format!(
            "copy {} to {}: {error}",
            source.display(),
            destination.display()
        )
    })
}

fn apply_finalized_release(
    root: &Path,
    candidate: &Value,
    candidate_bytes: &[u8],
    approval_path: &Path,
    approval_sha256: &str,
    approval: &TestnetV3GenesisReleaseApprovalRequest,
) {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|error| fail(format!("system clock before epoch: {error}")))
        .as_secs();
    let ceremony_dir = root.join("launch/production-genesis-ceremony");
    let backup_dir = ceremony_dir.join(format!("phase7-backup-{timestamp}"));
    if backup_dir.exists() {
        fail(format!(
            "backup path already exists: {}",
            backup_dir.display()
        ));
    }
    fs::create_dir_all(&backup_dir)
        .unwrap_or_else(|error| fail(format!("create {}: {error}", backup_dir.display())));

    let source_path = root.join(SOURCE_GENESIS);
    let archive_path = root.join(SOURCE_GENESIS_ARCHIVE);
    if !archive_path.exists() {
        copy_with_parent(&source_path, &archive_path).unwrap_or_else(|error| fail(error));
    }

    let allocation_manifest = finalized_allocation_manifest(root, candidate);
    let network_identifiers = finalized_network_identifiers(root, candidate);
    let mut replacements = vec![
        (source_path.clone(), candidate_bytes.to_vec()),
        (
            root.join("runtime/testnet-allocation-manifest.json"),
            pretty_json(&allocation_manifest),
        ),
        (
            root.join("network-identifiers.testnet-v3.identity-assigned.json"),
            pretty_json(&network_identifiers),
        ),
    ];
    for contract in GenesisContract::APPROVED_ORDER {
        for extension in ["synq", "compiled.synq", "abi.json", "manifest.json"] {
            let name = format!("{}.{}", contract.name(), extension);
            let staged = root
                .join("genesis-contracts/staged-governance-v1")
                .join(&name);
            let target = root.join("genesis-contracts/contracts").join(&name);
            replacements.push((target, read_bytes(&staged)));
        }
    }

    let mut journal = json!({
        "schema_version": 1,
        "status": "PREPARED",
        "backup_directory": backup_dir.strip_prefix(root).unwrap().display().to_string(),
        "candidate_sha256": sha256_bytes(candidate_bytes),
        "genesis_hash": candidate["integrity"]["genesis_hash"],
        "network_magic": candidate["network_magic_bytes"]["value"],
        "consensus_parameter_decision_id": candidate["consensus_parameters"]["decision_id"],
        "consensus_parameter_manifest_sha256": candidate["consensus_parameters"]["canonical_manifest_sha256"],
        "consensus_parameter_root_sha3_512": candidate["consensus_parameters"]["parameter_root_sha3_512"],
        "release_approval_artifact": approval_path.strip_prefix(root).unwrap_or(approval_path).display().to_string(),
        "release_approval_artifact_sha256": approval_sha256,
        "release_approval_governance_role": approval.governance_authority_role,
        "release_approval_governance_address": approval.governance_standard_account_address,
        "replacement_count": replacements.len()
    });
    let journal_path = ceremony_dir.join("phase7-apply-journal.json");
    fs::write(&journal_path, pretty_json(&journal))
        .unwrap_or_else(|error| fail(format!("write {}: {error}", journal_path.display())));

    let process_id = std::process::id();
    let mut prepared = Vec::new();
    for (target, bytes) in &replacements {
        let relative = target
            .strip_prefix(root)
            .unwrap_or_else(|_| fail("release target escaped repository root"));
        let backup = backup_dir.join(relative);
        let existed = target.exists();
        if existed {
            copy_with_parent(target, &backup).unwrap_or_else(|error| fail(error));
        }
        let temporary = target.with_extension(format!("phase7-new-{process_id}"));
        if let Some(parent) = temporary.parent() {
            fs::create_dir_all(parent)
                .unwrap_or_else(|error| fail(format!("create {}: {error}", parent.display())));
        }
        fs::write(&temporary, bytes)
            .unwrap_or_else(|error| fail(format!("write {}: {error}", temporary.display())));
        prepared.push((target.clone(), temporary, backup, existed));
    }

    let apply_result = (|| -> Result<(), String> {
        for (target, temporary, _, _) in &prepared {
            fs::rename(temporary, target).map_err(|error| {
                format!(
                    "publish {} from {}: {error}",
                    target.display(),
                    temporary.display()
                )
            })?;
        }
        load_genesis_from_path(&source_path)
            .map_err(|error| format!("runtime rejected applied canonical genesis: {error}"))?;
        Ok(())
    })();
    if let Err(error) = apply_result {
        for (target, temporary, backup, existed) in prepared.iter().rev() {
            let _ = fs::remove_file(temporary);
            if *existed {
                let _ = copy_with_parent(backup, target);
            } else {
                let _ = fs::remove_file(target);
            }
        }
        journal["status"] = Value::String("ROLLED_BACK".to_string());
        journal["error"] = Value::String(error.clone());
        let _ = fs::write(&journal_path, pretty_json(&journal));
        fail(format!(
            "Phase-7/8 apply failed and was rolled back: {error}"
        ));
    }

    let release_manifest = json!({
        "schema_version": 1,
        "status": "PHASE_7_8_APPLIED_PENDING_RELEASE_GATES",
        "genesis_file": SOURCE_GENESIS,
        "genesis_file_sha256": sha256_file(&source_path),
        "genesis_hash": candidate["integrity"]["genesis_hash"],
        "network_magic": candidate["network_magic_bytes"]["value"],
        "execution_state_root": candidate["genesis_deployment"]["post_deployment_execution_state_root"],
        "aivm_state_root": candidate["genesis_deployment"]["post_deployment_aivm_state_root"],
        "receipt_root": candidate["genesis_deployment"]["receipt_root"],
        "consensus_parameter_decision_id": candidate["consensus_parameters"]["decision_id"],
        "consensus_parameter_decision_sha256": candidate["consensus_parameters"]["release_decision_sha256"],
        "consensus_parameter_manifest_sha256": candidate["consensus_parameters"]["canonical_manifest_sha256"],
        "consensus_parameter_root_sha3_512": candidate["consensus_parameters"]["parameter_root_sha3_512"],
        "release_approval_artifact": approval_path.strip_prefix(root).unwrap_or(approval_path).display().to_string(),
        "release_approval_artifact_sha256": approval_sha256,
        "release_approval_governance_role": approval.governance_authority_role,
        "release_approval_governance_address": approval.governance_standard_account_address,
        "artifact_directory": "genesis-contracts/contracts",
        "artifact_file_count": 36,
        "track_h_status": "APPLIED",
        "backup_directory": backup_dir.strip_prefix(root).unwrap().display().to_string()
    });
    fs::write(
        ceremony_dir.join("phase7-release-integrity.json"),
        pretty_json(&release_manifest),
    )
    .unwrap_or_else(|error| fail(format!("write release integrity manifest: {error}")));
    journal["status"] = Value::String("APPLIED".to_string());
    journal["release_integrity_sha256"] = Value::String(sha256_file(
        &ceremony_dir.join("phase7-release-integrity.json"),
    ));
    fs::write(&journal_path, pretty_json(&journal))
        .unwrap_or_else(|error| fail(format!("write final apply journal: {error}")));
    println!("phase 7/8 applied   {}", source_path.display());
    println!("recoverable backup {}", backup_dir.display());
}

fn main() {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    let mut output = repo().join(DEFAULT_OUTPUT);
    let mut approval_path = repo().join(DEFAULT_RELEASE_APPROVAL);
    let mut authorities_path = None;
    let mut legacy_authorities = false;
    let mut apply = false;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--output" => {
                output = PathBuf::from(
                    args.get(index + 1)
                        .unwrap_or_else(|| fail("--output requires a path")),
                );
                index += 2;
            }
            "--prepare" => index += 1,
            "--approval" => {
                approval_path = PathBuf::from(
                    args.get(index + 1)
                        .unwrap_or_else(|| fail("--approval requires a path")),
                );
                index += 2;
            }
            "--authorities" => {
                if legacy_authorities || authorities_path.is_some() {
                    fail("use exactly one of --authorities PATH or --legacy-authorities");
                }
                authorities_path = Some(PathBuf::from(
                    args.get(index + 1)
                        .unwrap_or_else(|| fail("--authorities requires a path")),
                ));
                index += 2;
            }
            "--legacy-authorities" => {
                if legacy_authorities || authorities_path.is_some() {
                    fail("use exactly one of --authorities PATH or --legacy-authorities");
                }
                legacy_authorities = true;
                index += 1;
            }
            "--apply" => {
                apply = true;
                index += 1;
            }
            flag => fail(format!(
                "unknown argument {flag}; use --prepare|--apply (--authorities PATH|--legacy-authorities) [--output PATH] [--approval PATH]"
            )),
        }
    }

    let root = repo();
    let authorities_path = if legacy_authorities {
        root.join(LEGACY_AUTHORITIES_FILE)
    } else {
        authorities_path.unwrap_or_else(|| {
            fail("--authorities PATH is required for fresh P3 finalization; use --legacy-authorities only for historical replay")
        })
    };
    // Validate the explicit authority record before consuming any ceremony
    // evidence.  This pins the governance role, V4 status, custody hashes,
    // identity binding, and authorization-key fingerprint; no alternate
    // public key can be supplied through the CLI.
    load_frozen_governance_authority(&root, &authorities_path).unwrap_or_else(|error| {
        fail(format!(
            "explicit authority record failed the Testnet-v3 V4 trust gate: {error}"
        ))
    });
    let candidate = build_candidate(&root, &authorities_path);
    let bytes = pretty_json(&candidate);
    let parent = output
        .parent()
        .unwrap_or_else(|| fail("candidate output has no parent"));
    fs::create_dir_all(parent)
        .unwrap_or_else(|error| fail(format!("create {}: {error}", parent.display())));
    let temporary = output.with_extension(format!("tmp-{}", std::process::id()));
    fs::write(&temporary, &bytes)
        .unwrap_or_else(|error| fail(format!("write {}: {error}", temporary.display())));
    if let Err(error) = load_genesis_from_path(&temporary) {
        let _ = fs::remove_file(&temporary);
        fail(format!("runtime rejected staged candidate: {error}"));
    }
    fs::rename(&temporary, &output)
        .unwrap_or_else(|error| fail(format!("publish {}: {error}", output.display())));

    println!("candidate           {}", output.display());
    println!("sha256              {}", sha256_file(&output));
    println!(
        "genesis hash        {}",
        candidate["integrity"]["genesis_hash"].as_str().unwrap()
    );
    println!(
        "network magic       {}",
        candidate["network_magic_bytes"]["value"].as_str().unwrap()
    );
    println!(
        "execution root     {}",
        candidate["genesis_deployment"]["post_deployment_execution_state_root"]
            .as_str()
            .unwrap()
    );
    println!(
        "AIVM state root     {}",
        candidate["genesis_deployment"]["post_deployment_aivm_state_root"]
            .as_str()
            .unwrap()
    );
    println!(
        "receipt root        {}",
        candidate["genesis_deployment"]["receipt_root"]
            .as_str()
            .unwrap()
    );
    println!(
        "parameter decision  {}",
        candidate["consensus_parameters"]["decision_id"]
            .as_str()
            .unwrap()
    );
    println!(
        "parameter root      {}",
        candidate["consensus_parameters"]["parameter_root_sha3_512"]
            .as_str()
            .unwrap()
    );
    if apply {
        let approval =
            verify_release_approval_file(&root, &output, &authorities_path, &approval_path)
                .unwrap_or_else(|error| {
                    fail(format!("release approval gate rejected apply: {error}"))
                });
        let approval_sha256 = sha256_file(&approval_path);
        apply_finalized_release(
            &root,
            &candidate,
            &bytes,
            &approval_path,
            &approval_sha256,
            &approval,
        );
    }
}
