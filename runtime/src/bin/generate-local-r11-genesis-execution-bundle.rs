//! Generates the isolated LOCAL_R11 qualification Genesis execution bundle.
//!
//! This is deliberately not a second Genesis deployment algorithm.  It feeds
//! the supplied, already-finalized qualification Genesis and canonical contract
//! artifacts into `execute_local_r11_genesis_deployment`, captures the resulting
//! state, and emits the strict external bundle consumed by the release gate.
//! The only private-key operation is an interactive `Aegis decrypt --stdout`;
//! plaintext never reaches a file or this program's standard output.

use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use sha3::Sha3_512;
use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use synergy_testnet::address::derive_standard_account_address;
use synergy_testnet::execution::{ExecutionState, GenesisExecutionSnapshot};
use synergy_testnet::genesis::load_genesis_from_path;
use synergy_testnet::genesis_deployment::{
    execute_local_r11_genesis_deployment, GenesisAuthorities, GenesisContract,
    GenesisDeploymentPlan, GenesisParameters, GenesisSigner, GenesisValidator,
    LocalR11GenesisExecutionAuthorization, LOCAL_R11_GENESIS_AUTHORITY_ID,
    LOCAL_R11_GENESIS_EXECUTION_AUTHORIZATION_DOMAIN,
};
use synergy_testnet::synq_execution::SynQContractArtifact;
use synergy_testnet::testnet_v3_release_approval::{
    TestnetV3GenesisExecutionBundle, TESTNET_V3_GENESIS_EXECUTION_BUNDLE_ARTIFACT_TYPE,
    TESTNET_V3_GENESIS_EXECUTION_BUNDLE_SCHEMA_VERSION,
};
use zeroize::Zeroize;

const LOCAL_ENVIRONMENT: &str = "LOCAL_R11_QUALIFICATION";
const EXPECTED_CHAIN_ID: u64 = 1266;
const EXPECTED_NETWORK_ID: &str = "testnet";
const EXPECTED_RELEASE_ID: &str = "testnet-v3";
const EXPECTED_PROTOCOL: &str = "posy/3.0";
const MLDSA87_PUBLIC_BYTES: usize = 2_592;
const MLDSA87_PRIVATE_BYTES: usize = 4_896;
const FNDSA1024_PUBLIC_BYTES: usize = 1_793;

fn usage() -> ! {
    eprintln!(
        "usage: generate-local-r11-genesis-execution-bundle \\\n+  --genesis PATH --contracts-dir DIR --authority-public PATH --authority-custody PATH \\\n+  --aegis-binary PATH --output PATH --testnet-v3-revision SHA \\\n+  --synq-revision SHA --aegis-revision SHA --validator-binary-sha256 SHA"
    );
    std::process::exit(2);
}

fn fail(message: impl AsRef<str>) -> ! {
    eprintln!(
        "generate-local-r11-genesis-execution-bundle: {}",
        message.as_ref()
    );
    std::process::exit(1);
}

#[derive(Debug)]
struct Options {
    genesis: PathBuf,
    contracts_dir: PathBuf,
    authority_public: PathBuf,
    authority_custody: PathBuf,
    aegis_binary: PathBuf,
    output: PathBuf,
    testnet_v3_revision: String,
    synq_revision: String,
    aegis_revision: String,
    validator_binary_sha256: String,
}

fn parse_options(args: &[String]) -> Result<Options, String> {
    let mut values = BTreeMap::new();
    let expected = [
        "--genesis",
        "--contracts-dir",
        "--authority-public",
        "--authority-custody",
        "--aegis-binary",
        "--output",
        "--testnet-v3-revision",
        "--synq-revision",
        "--aegis-revision",
        "--validator-binary-sha256",
    ];
    if args.len() != expected.len() * 2 {
        return Err("all arguments are mandatory and may be supplied exactly once".to_string());
    }
    let mut index = 0;
    while index < args.len() {
        let flag = args
            .get(index)
            .ok_or_else(|| "missing argument flag".to_string())?;
        let value = args
            .get(index + 1)
            .filter(|value| !value.is_empty() && !value.starts_with("--"))
            .ok_or_else(|| format!("{flag} requires a non-empty value"))?;
        if !expected.contains(&flag.as_str())
            || values.insert(flag.clone(), value.clone()).is_some()
        {
            return Err(format!("unknown or duplicate argument {flag}"));
        }
        index += 2;
    }
    if values.len() != expected.len() || expected.iter().any(|flag| !values.contains_key(*flag)) {
        return Err("missing required argument".to_string());
    }
    let mut take = |flag: &str| values.remove(flag).expect("required argument checked");
    let options = Options {
        genesis: PathBuf::from(take("--genesis")),
        contracts_dir: PathBuf::from(take("--contracts-dir")),
        authority_public: PathBuf::from(take("--authority-public")),
        authority_custody: PathBuf::from(take("--authority-custody")),
        aegis_binary: PathBuf::from(take("--aegis-binary")),
        output: PathBuf::from(take("--output")),
        testnet_v3_revision: take("--testnet-v3-revision"),
        synq_revision: take("--synq-revision"),
        aegis_revision: take("--aegis-revision"),
        validator_binary_sha256: take("--validator-binary-sha256"),
    };
    for (label, digest) in [
        ("testnet-v3 revision", &options.testnet_v3_revision),
        ("SynQ revision", &options.synq_revision),
        ("Aegis revision", &options.aegis_revision),
        ("validator binary SHA-256", &options.validator_binary_sha256),
    ] {
        require_lower_hex(digest, label, 64)?;
    }
    Ok(options)
}

fn require_lower_hex(value: &str, label: &str, length: usize) -> Result<(), String> {
    if value.len() != length
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(format!(
            "{label} must be exactly {length} lowercase hexadecimal characters"
        ));
    }
    Ok(())
}

fn read_bytes(path: &Path, label: &str) -> Result<Vec<u8>, String> {
    fs::read(path).map_err(|error| format!("read {label} {}: {error}", path.display()))
}

fn read_json(path: &Path, label: &str) -> Result<Value, String> {
    serde_json::from_slice(&read_bytes(path, label)?)
        .map_err(|error| format!("parse {label} {}: {error}", path.display()))
}

fn require_string<'a>(value: &'a Value, path: &[&str]) -> Result<&'a str, String> {
    let mut current = value;
    for key in path {
        current = current
            .get(*key)
            .ok_or_else(|| format!("missing Genesis field {}", path.join(".")))?;
    }
    current
        .as_str()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            format!(
                "Genesis field {} must be a non-empty string",
                path.join(".")
            )
        })
}

fn require_u64(value: &Value, path: &[&str]) -> Result<u64, String> {
    let mut current = value;
    for key in path {
        current = current
            .get(*key)
            .ok_or_else(|| format!("missing Genesis field {}", path.join(".")))?;
    }
    current.as_u64().ok_or_else(|| {
        format!(
            "Genesis field {} must be an unsigned integer",
            path.join(".")
        )
    })
}

fn optional_string(value: &Value, path: &[&str]) -> Option<String> {
    let mut current = value;
    for key in path {
        current = current.get(*key)?;
    }
    current
        .as_str()
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn decimal_to_bps(value: &Value, label: &str) -> Result<String, String> {
    let raw = match value {
        Value::Number(number) => number.to_string(),
        Value::String(value) => value.clone(),
        _ => return Err(format!("{label} must be a decimal number")),
    };
    let (whole, fraction) = raw
        .split_once('.')
        .map_or((raw.as_str(), ""), |parts| parts);
    if whole != "0" && whole != "1" || !whole.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(format!("{label} is outside the [0, 1] interval"));
    }
    if !fraction.bytes().all(|byte| byte.is_ascii_digit()) || fraction.len() > 4 {
        return Err(format!("{label} must have at most four decimal places"));
    }
    let whole_bps = whole
        .parse::<u64>()
        .map_err(|error| format!("parse {label}: {error}"))?
        .checked_mul(10_000)
        .ok_or_else(|| format!("{label} overflow"))?;
    let fractional = if fraction.is_empty() {
        0
    } else {
        format!("{fraction:0<4}")
            .parse::<u64>()
            .map_err(|error| format!("parse {label}: {error}"))?
    };
    let bps = whole_bps
        .checked_add(fractional)
        .ok_or_else(|| format!("{label} overflow"))?;
    if bps > 10_000 {
        return Err(format!("{label} is outside the [0, 1] interval"));
    }
    Ok(bps.to_string())
}

fn seconds_to_blocks(
    seconds: u64,
    target_block_time_ms: u64,
    label: &str,
) -> Result<String, String> {
    if target_block_time_ms == 0 || !(100..=1_100).contains(&target_block_time_ms) {
        return Err(format!(
            "{label}: target block time must be within 100..=1100 ms"
        ));
    }
    let milliseconds = seconds
        .checked_mul(1_000)
        .ok_or_else(|| format!("{label}: duration overflow"))?;
    if milliseconds % target_block_time_ms != 0 {
        return Err(format!(
            "{label}: duration is not divisible by target block time"
        ));
    }
    Ok((milliseconds / target_block_time_ms).to_string())
}

fn source_account(genesis: &Value, account_id: &str) -> Result<String, String> {
    genesis["accounts"]
        .as_array()
        .ok_or_else(|| "Genesis accounts must be an array".to_string())?
        .iter()
        .find(|account| account.get("account_id").and_then(Value::as_str) == Some(account_id))
        .and_then(|account| account.get("address").and_then(Value::as_str))
        .filter(|address| !address.is_empty())
        .map(ToOwned::to_owned)
        .ok_or_else(|| format!("Genesis account {account_id} has no canonical address"))
}

fn active_validators(genesis: &Value) -> Result<Vec<GenesisValidator>, String> {
    let validators = genesis["validators"]
        .as_array()
        .ok_or_else(|| "Genesis validators must be an array".to_string())?;
    if validators.len() != 5
        || validators.iter().any(|validator| {
            validator.get("status").and_then(Value::as_str) != Some("active_at_genesis")
        })
    {
        return Err(
            "LOCAL_R11 qualification Genesis must contain exactly five active validators"
                .to_string(),
        );
    }
    validators
        .iter()
        .map(|validator| {
            Ok(GenesisValidator {
                id_hash: format!("0x{}", require_string(validator, &["validator_id_hash"])?),
                operator_address: require_string(validator, &["operator_address"])?.to_string(),
                reward_address: require_string(validator, &["reward_address"])?.to_string(),
                voting_power: require_u64(validator, &["voting_power"])?.to_string(),
                self_stake_nwei: require_string(validator, &["stake_nwei"])?.to_string(),
                metadata_hash: format!("0x{}", require_string(validator, &["metadata_hash"])?),
                key_bundle_hash: format!("0x{}", require_string(validator, &["key_bundle_hash"])?),
                activation_height: require_u64(validator, &["activation_height"])?.to_string(),
            })
        })
        .collect()
}

fn qualification_parameters(genesis: &Value) -> Result<GenesisParameters, String> {
    let contracts = genesis
        .get("contracts")
        .ok_or_else(|| "Genesis contracts are missing".to_string())?;
    let target_ms = require_u64(genesis, &["consensus", "target_block_time_ms"]).or_else(|_| {
        require_u64(
            genesis,
            &[
                "consensus",
                "posy_v3_activation",
                "manifest",
                "target_block_time_ms",
            ],
        )
    })?;
    if target_ms != 500 {
        return Err(format!(
            "LOCAL_R11 qualification Genesis target block time must be 500 ms, got {target_ms}"
        ));
    }
    let validators = active_validators(genesis)?;
    let min_self_stake = validators
        .iter()
        .map(|validator| {
            validator
                .self_stake_nwei
                .parse::<u128>()
                .map_err(|error| format!("parse active validator stake: {error}"))
        })
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .min()
        .ok_or_else(|| "no active validators".to_string())?
        .to_string();
    let max_validators = require_u64(
        contracts,
        &[
            "validator_registry",
            "init_params",
            "preconfigured_validator_count",
        ],
    )?;
    if max_validators < validators.len() as u64 {
        return Err(
            "validator preconfigured count is smaller than the active validator set".to_string(),
        );
    }
    let vesting = genesis["vesting"]
        .as_array()
        .and_then(|entries| entries.first())
        .ok_or_else(|| "Genesis vesting plan is missing".to_string())?;
    let beneficiaries = vesting["beneficiaries"]
        .as_array()
        .ok_or_else(|| "Genesis vesting beneficiaries are missing".to_string())?;
    let mut team_count = 0u64;
    let mut support_count = 0u64;
    let mut team_total = 0u128;
    let mut support_total = 0u128;
    for beneficiary in beneficiaries {
        let allocation = require_string(beneficiary, &["total_allocation_nwei"])?
            .parse::<u128>()
            .map_err(|error| format!("parse vesting allocation: {error}"))?;
        if require_u64(beneficiary, &["initial_disposition_restriction_seconds"])? == 0 {
            support_count += 1;
            support_total = support_total
                .checked_add(allocation)
                .ok_or_else(|| "support allocation overflow".to_string())?;
        } else {
            team_count += 1;
            team_total = team_total
                .checked_add(allocation)
                .ok_or_else(|| "team allocation overflow".to_string())?;
        }
    }
    if team_count == 0 || support_count == 0 {
        return Err(
            "Genesis vesting plan must have both team and support beneficiaries".to_string(),
        );
    }
    let treasury_signers = contracts["treasury"]["init_params"]["signers"]
        .as_array()
        .ok_or_else(|| "Genesis Treasury signers are missing".to_string())?
        .iter()
        .map(|value| {
            value
                .as_str()
                .filter(|value| !value.is_empty())
                .map(ToOwned::to_owned)
                .ok_or_else(|| "Genesis Treasury signer is invalid".to_string())
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(GenesisParameters {
        identity_registration_fee_nwei: require_string(
            contracts,
            &["identity", "init_params", "registration_fee_nwei"],
        )?
        .to_string(),
        identity_reserved_names: contracts["identity"]["init_params"]["reserved_names"]
            .as_array()
            .ok_or_else(|| "Genesis Identity reserved names are missing".to_string())?
            .iter()
            .map(|value| {
                value
                    .as_str()
                    .filter(|value| !value.is_empty())
                    .map(ToOwned::to_owned)
                    .ok_or_else(|| "Genesis reserved name is invalid".to_string())
            })
            .collect::<Result<Vec<_>, _>>()?,
        validator_max_count: max_validators.to_string(),
        validator_min_count: require_u64(
            contracts,
            &["validator_registry", "init_params", "min_validator_count"],
        )?
        .to_string(),
        validator_min_self_stake_nwei: min_self_stake,
        validators,
        staking_min_stake_nwei: require_string(
            contracts,
            &["staking", "init_params", "min_stake_nwei"],
        )?
        .to_string(),
        staking_max_stake_nwei: require_string(
            contracts,
            &["staking", "init_params", "max_stake_nwei"],
        )?
        .to_string(),
        staking_unbonding_blocks: seconds_to_blocks(
            require_u64(
                contracts,
                &["staking", "init_params", "unbonding_period_seconds"],
            )?,
            target_ms,
            "staking unbonding period",
        )?,
        governance_quorum_bps: decimal_to_bps(
            &contracts["governance"]["init_params"]["quorum_pct"],
            "governance quorum",
        )?,
        governance_approval_bps: decimal_to_bps(
            &contracts["governance"]["init_params"]["approval_pct"],
            "governance approval",
        )?,
        governance_veto_bps: decimal_to_bps(
            &contracts["governance"]["init_params"]["veto_pct"],
            "governance veto",
        )?,
        governance_min_deposit_nwei: require_string(
            contracts,
            &["governance", "init_params", "min_deposit_nwei"],
        )?
        .to_string(),
        governance_voting_blocks: seconds_to_blocks(
            require_u64(
                contracts,
                &["governance", "init_params", "voting_duration_seconds"],
            )?,
            target_ms,
            "governance voting duration",
        )?,
        governance_timelock_blocks: seconds_to_blocks(
            require_u64(
                contracts,
                &["governance", "init_params", "timelock_delay_seconds"],
            )?,
            target_ms,
            "governance timelock delay",
        )?,
        treasury_required_signers: require_u64(
            contracts,
            &["treasury", "init_params", "required_signers"],
        )?
        .to_string(),
        treasury_signers,
        slashing_double_sign_bps: require_u64(
            contracts,
            &["slashing", "init_params", "double_sign_slash_pct"],
        )?
        .checked_mul(100)
        .ok_or_else(|| "double-sign slashing percentage overflow".to_string())?
        .to_string(),
        slashing_downtime_bps: require_u64(
            contracts,
            &["slashing", "init_params", "downtime_slash_pct"],
        )?
        .checked_mul(100)
        .ok_or_else(|| "downtime slashing percentage overflow".to_string())?
        .to_string(),
        slashing_invalid_block_bps: require_u64(
            contracts,
            &["slashing", "init_params", "invalid_block_slash_pct"],
        )?
        .checked_mul(100)
        .ok_or_else(|| "invalid-block slashing percentage overflow".to_string())?
        .to_string(),
        slashing_missed_blocks_threshold: require_u64(
            contracts,
            &[
                "slashing",
                "init_params",
                "downtime_missed_blocks_threshold",
            ],
        )?
        .to_string(),
        slashing_jail_blocks: seconds_to_blocks(
            require_u64(
                contracts,
                &["slashing", "init_params", "jail_duration_seconds"],
            )?,
            target_ms,
            "slashing jail duration",
        )?,
        oracle_quorum_threshold: require_u64(
            contracts,
            &["synergy_oracle", "init_params", "quorum_threshold"],
        )?
        .to_string(),
        oracle_replay_protection: contracts["synergy_oracle"]["init_params"]
            ["replay_protection_enabled"]
            .as_bool()
            .ok_or_else(|| "Genesis oracle replay protection must be a boolean".to_string())?,
        oracle_source_domains: contracts["synergy_oracle"]["init_params"]
            ["accepted_source_domains"]
            .as_array()
            .ok_or_else(|| "Genesis oracle source domains are missing".to_string())?
            .iter()
            .map(|value| {
                value
                    .as_str()
                    .filter(|value| !value.is_empty())
                    .map(ToOwned::to_owned)
                    .ok_or_else(|| "Genesis oracle source domain is invalid".to_string())
            })
            .collect::<Result<Vec<_>, _>>()?,
        team_vesting_start_time: require_u64(vesting, &["start_time"])?.to_string(),
        team_allocation_nwei: team_total.to_string(),
        support_allocation_nwei: support_total.to_string(),
        team_count: team_count.to_string(),
        support_count: support_count.to_string(),
    })
}

struct SecretGenesisAuthorities(GenesisAuthorities);

impl Drop for SecretGenesisAuthorities {
    fn drop(&mut self) {
        self.0.genesis_deployer.private_key.zeroize();
        self.0.governance.private_key.zeroize();
        self.0
            .validator_registry_authority_key
            .private_key
            .zeroize();
    }
}

fn qualification_authorities(
    genesis: &Value,
    public_key: &[u8],
    private_key: &[u8],
    address: &str,
) -> Result<SecretGenesisAuthorities, String> {
    let signer = || GenesisSigner {
        public_key: public_key.to_vec(),
        private_key: private_key.to_vec(),
        identity_authorization: None,
    };
    Ok(SecretGenesisAuthorities(GenesisAuthorities {
        genesis_deployer: signer(),
        governance: signer(),
        emergency_slashing_authority: require_string(
            genesis,
            &[
                "contracts",
                "slashing",
                "init_params",
                "initial_slashing_authority",
            ],
        )?
        .to_string(),
        validator_registry_authority: address.to_string(),
        validator_registry_authority_key: signer(),
        reward_distributor_authority: optional_string(
            genesis,
            &[
                "contracts",
                "reward_distributor",
                "init_params",
                "distributor_authority",
            ],
        )
        .or_else(|| {
            optional_string(
                genesis,
                &[
                    "contracts",
                    "reward_distributor",
                    "init_params",
                    "pool_address",
                ],
            )
        })
        .ok_or_else(|| "Genesis reward-distributor authority is missing".to_string())?,
        identity_fee_collector: source_account(genesis, "SYS-01")?,
        team_vesting_admin: require_string(
            genesis,
            &[
                "contracts",
                "team_vesting",
                "init_params",
                "admin_authority",
            ],
        )?
        .to_string(),
        oracle_publisher: require_string(
            genesis,
            &[
                "contracts",
                "synergy_oracle",
                "init_params",
                "authority_address",
            ],
        )?
        .to_string(),
    }))
}

fn contract_plan(contracts_dir: &Path) -> Result<GenesisDeploymentPlan, String> {
    let artifacts = GenesisContract::APPROVED_ORDER
        .iter()
        .map(|contract| {
            let name = contract.name();
            let read =
                |suffix: &str| read_bytes(&contracts_dir.join(format!("{name}.{suffix}")), name);
            Ok((
                *contract,
                SynQContractArtifact::new(
                    read("compiled.synq")?,
                    String::from_utf8(read("abi.json")?)
                        .map_err(|error| format!("decode {name}.abi.json: {error}"))?,
                    String::from_utf8(read("manifest.json")?)
                        .map_err(|error| format!("decode {name}.manifest.json: {error}"))?,
                ),
            ))
        })
        .collect::<Result<BTreeMap<_, _>, String>>()?;
    GenesisDeploymentPlan::new(&artifacts)
}

fn genesis_execution_state(
    genesis: &Value,
    team_vesting_address: &str,
) -> Result<ExecutionState, String> {
    let balances = genesis["balances"]
        .as_array()
        .ok_or_else(|| "Genesis balances must be an array".to_string())?;
    let mut state = ExecutionState::new();
    let mut total = 0u128;
    for balance in balances {
        let source_address = require_string(balance, &["address"])?;
        let address = if balance.get("account_id").and_then(Value::as_str) == Some("TEM-A01") {
            team_vesting_address
        } else {
            source_address
        };
        let amount = require_string(balance, &["balance_nwei"])?
            .parse::<u128>()
            .map_err(|error| format!("parse Genesis balance: {error}"))?;
        if state
            .balances_nwei
            .insert(address.to_string(), amount)
            .is_some()
        {
            return Err(format!(
                "Genesis contains duplicate balance address {address}"
            ));
        }
        total = total
            .checked_add(amount)
            .ok_or_else(|| "Genesis balance sum overflow".to_string())?;
    }
    let declared = require_string(genesis, &["allocation_sum_check", "grand_total_nwei"])?
        .parse::<u128>()
        .map_err(|error| format!("parse Genesis declared balance total: {error}"))?;
    if total != declared {
        return Err(format!(
            "Genesis balance sum {total} differs from declared total {declared}"
        ));
    }
    Ok(state)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RootPublicDocument {
    schema_version: String,
    binary_encoding: String,
    algorithm: String,
    public_key: String,
    address: String,
    address_type: String,
    identity_id: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MlPublicDocument {
    schema_version: u32,
    artifact_type: String,
    environment: String,
    chain_id: u64,
    runtime_network_id: String,
    protocol_version: String,
    algorithm: String,
    authority_id: String,
    public_key_hex: String,
    public_key_sha3_512: String,
    seed_commitment_sha3_512: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RecoveredAuthorityDocument {
    schema_version: u32,
    artifact_type: String,
    environment: String,
    chain_id: u64,
    authority_id: String,
    algorithm: String,
    private_key_hex: String,
}

struct Secret(Vec<u8>);
impl Drop for Secret {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

fn reject_noninteractive_secrets(args: &[String]) -> Result<(), String> {
    if args.iter().any(|arg| {
        let lower = arg.to_ascii_lowercase();
        lower.contains("passphrase") || lower.contains("password") || lower.contains("private-key")
    }) {
        return Err(
            "passphrases and private keys must not be supplied on the command line".to_string(),
        );
    }
    Ok(())
}

fn require_engine(path: &Path) -> Result<(), String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("inspect Aegis binary {}: {error}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
        return Err("Aegis binary must be a regular non-symlink file".to_string());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o111 == 0 || metadata.permissions().mode() & 0o022 != 0
        {
            return Err("Aegis binary must be executable and not group/world writable".to_string());
        }
    }
    Ok(())
}

fn decrypt_via_aegis(engine: &Path, custody: &Path) -> Result<Secret, String> {
    let mut output = Command::new(engine)
        .arg("decrypt")
        .arg(custody)
        .arg("--stdout")
        .stdin(Stdio::inherit())
        .stderr(Stdio::inherit())
        .stdout(Stdio::piped())
        .output()
        .map_err(|error| format!("run Aegis decrypt: {error}"))?;
    let plaintext = Secret(std::mem::take(&mut output.stdout));
    if !output.status.success() {
        return Err("Aegis custody decryption failed".to_string());
    }
    Ok(plaintext)
}

fn load_authority(
    authority_public: &Path,
    custody: &Path,
    engine: &Path,
) -> Result<(String, Vec<u8>, Secret), String> {
    let root: RootPublicDocument =
        serde_json::from_slice(&read_bytes(authority_public, "authority public root")?)
            .map_err(|error| format!("parse authority public root: {error}"))?;
    if root.algorithm != "FN-DSA-1024"
        || root.binary_encoding != "lowercase-hex"
        || root.schema_version != "synergy-native-public-identity-v3"
        || root.identity_id != "LOCAL-R11-QUALIFICATION-GOVERNANCE-AUTHORITY"
        || root.identity_id.is_empty()
        || root.address_type.is_empty()
    {
        return Err("authority public root is not an FN-DSA-1024 identity record".to_string());
    }
    require_lower_hex(
        &root.public_key,
        "authority root public key",
        FNDSA1024_PUBLIC_BYTES * 2,
    )?;
    let root_key = hex::decode(&root.public_key)
        .map_err(|error| format!("decode authority root public key: {error}"))?;
    if root_key.len() != FNDSA1024_PUBLIC_BYTES {
        return Err("authority root public key has the wrong FN-DSA-1024 length".to_string());
    }
    let address = derive_standard_account_address(&root_key)
        .map_err(|error| format!("derive authority standard address: {error}"))?;
    if address != root.address {
        return Err(
            "authority public root address does not match canonical runtime derivation".to_string(),
        );
    }
    let ml_public_path = custody
        .parent()
        .ok_or_else(|| "authority custody has no parent directory".to_string())?
        .join("authority.public.json");
    let ml_public: MlPublicDocument = serde_json::from_slice(&read_bytes(
        &ml_public_path,
        "authority ML-DSA public record",
    )?)
    .map_err(|error| format!("parse authority ML-DSA public record: {error}"))?;
    if ml_public.schema_version != 1
        || ml_public.artifact_type != "local-r11-qualification-authority"
        || ml_public.environment != LOCAL_ENVIRONMENT
        || ml_public.chain_id != EXPECTED_CHAIN_ID
        || ml_public.runtime_network_id != EXPECTED_NETWORK_ID
        || ml_public.protocol_version != EXPECTED_PROTOCOL
        || ml_public.authority_id != LOCAL_R11_GENESIS_AUTHORITY_ID
        || ml_public.algorithm != "ML-DSA-87"
        || ml_public.seed_commitment_sha3_512.len() != 128
    {
        return Err("authority ML-DSA public record is invalid".to_string());
    }
    require_lower_hex(
        &ml_public.public_key_hex,
        "authority ML-DSA public key",
        MLDSA87_PUBLIC_BYTES * 2,
    )?;
    require_lower_hex(
        &ml_public.public_key_sha3_512,
        "authority ML-DSA public fingerprint",
        128,
    )?;
    let public_key = hex::decode(&ml_public.public_key_hex)
        .map_err(|error| format!("decode authority ML-DSA public key: {error}"))?;
    if public_key.len() != MLDSA87_PUBLIC_BYTES {
        return Err("authority ML-DSA public key has the wrong length".to_string());
    }
    let plaintext = decrypt_via_aegis(engine, custody)?;
    let mut recovered: RecoveredAuthorityDocument = serde_json::from_slice(&plaintext.0)
        .map_err(|error| format!("parse decrypted Aegis authority record: {error}"))?;
    if recovered.schema_version != 1
        || recovered.artifact_type != "local-r11-qualification-authority-custody"
        || recovered.environment != LOCAL_ENVIRONMENT
        || recovered.chain_id != EXPECTED_CHAIN_ID
        || recovered.authority_id != ml_public.authority_id
        || recovered.algorithm != "ML-DSA-87"
    {
        return Err(
            "decrypted Aegis authority record is not the expected ML-DSA-87 custody".to_string(),
        );
    }
    require_lower_hex(
        &recovered.private_key_hex,
        "decrypted ML-DSA private key",
        MLDSA87_PRIVATE_BYTES * 2,
    )?;
    let private_key = Secret(
        hex::decode(&recovered.private_key_hex)
            .map_err(|error| format!("decode decrypted ML-DSA private key: {error}"))?,
    );
    recovered.private_key_hex.zeroize();
    if private_key.0.len() != MLDSA87_PRIVATE_BYTES {
        return Err("decrypted ML-DSA private key has the wrong length".to_string());
    }
    if hex::encode(Sha3_512::digest(&public_key)) != ml_public.public_key_sha3_512 {
        return Err("authority ML-DSA public fingerprint does not match its key".to_string());
    }
    Ok((address, public_key, private_key))
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| "output path has no parent directory".to_string())?;
    fs::create_dir_all(parent)
        .map_err(|error| format!("create output parent {}: {error}", parent.display()))?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| format!("create new output {}: {error}", path.display()))?;
    file.write_all(bytes)
        .map_err(|error| format!("write {}: {error}", path.display()))?;
    file.sync_all()
        .map_err(|error| format!("sync {}: {error}", path.display()))
}

fn run(options: Options, raw_args: &[String]) -> Result<(), String> {
    reject_noninteractive_secrets(raw_args)?;
    require_engine(&options.aegis_binary)?;
    if options.output.exists() {
        return Err(format!(
            "output {} already exists; refusing to overwrite evidence",
            options.output.display()
        ));
    }
    let document = load_genesis_from_path(&options.genesis)
        .map_err(|error| format!("validate supplied current Genesis: {error}"))?;
    let genesis = document.value();
    if document.chain_id() != EXPECTED_CHAIN_ID
        || genesis["network"]["network_id"] != Value::String(EXPECTED_NETWORK_ID.to_string())
        || genesis["network"]["release_id"] != Value::String(EXPECTED_RELEASE_ID.to_string())
        || genesis["network"]["consensus_version"] != Value::String(EXPECTED_PROTOCOL.to_string())
        || genesis.get("genesis_deployment").is_some()
    {
        return Err("supplied Genesis is not the unmodified current LOCAL_R11 Testnet-v3 qualification Genesis".to_string());
    }
    let plan = contract_plan(&options.contracts_dir)?;
    let parameters = qualification_parameters(genesis)?;
    let (authority_address, authority_public_key, authority_private_key) = load_authority(
        &options.authority_public,
        &options.authority_custody,
        &options.aegis_binary,
    )?;
    let authorization = LocalR11GenesisExecutionAuthorization {
        signature_domain: LOCAL_R11_GENESIS_EXECUTION_AUTHORIZATION_DOMAIN.to_string(),
        authority_id: LOCAL_R11_GENESIS_AUTHORITY_ID.to_string(),
        standard_account_address: authority_address.clone(),
        public_key_sha3_512: hex::encode(Sha3_512::digest(&authority_public_key)),
    };
    let authorities = qualification_authorities(
        genesis,
        &authority_public_key,
        &authority_private_key.0,
        &authority_address,
    )?;

    // Address derivation is intentionally obtained by an isolated execution of
    // the same production deployment path. Its state is discarded. The final
    // execution below starts from the exact Genesis balance map with TEM-A01
    // redirected to the derived TeamVesting contract, then emits the only
    // captured snapshot. This avoids an independent address-calculation path.
    let mut derivation_state =
        genesis_execution_state(genesis, &source_account(genesis, "TEM-A01")?)?;
    let derivation = execute_local_r11_genesis_deployment(
        &mut derivation_state,
        &plan,
        &authorities.0,
        &parameters,
        &authorization,
    )
    .map_err(|error| {
        format!("derive TeamVesting address through production deployment engine: {error}")
    })?;
    let team_vesting_address = derivation
        .addresses
        .get(&GenesisContract::TeamVesting)
        .ok_or_else(|| "production deployment did not return TeamVesting address".to_string())?
        .clone();
    let mut state = genesis_execution_state(genesis, &team_vesting_address)?;
    let outcome = execute_local_r11_genesis_deployment(
        &mut state,
        &plan,
        &authorities.0,
        &parameters,
        &authorization,
    )
    .map_err(|error| {
        format!("execute current LOCAL_R11 Genesis through production deployment engine: {error}")
    })?;
    if outcome.deployment_receipts.len() != 9 || outcome.initialization_receipts.len() != 27 {
        return Err(format!(
            "production execution emitted {} deployments and {} initializations; expected 9 and 27",
            outcome.deployment_receipts.len(),
            outcome.initialization_receipts.len()
        ));
    }
    let execution_state = GenesisExecutionSnapshot::capture_testnet_v3(&state)
        .map_err(|error| format!("capture finalized Genesis execution state: {error}"))?;
    if execution_state.state_root != outcome.post_deployment_state_root.to_hex()
        || execution_state.aivm_state_root.is_empty()
        || outcome.receipt_root.to_hex().is_empty()
    {
        return Err(
            "captured execution roots do not match the final production deployment outcome"
                .to_string(),
        );
    }
    let bundle = TestnetV3GenesisExecutionBundle {
        schema_version: TESTNET_V3_GENESIS_EXECUTION_BUNDLE_SCHEMA_VERSION,
        artifact_type: TESTNET_V3_GENESIS_EXECUTION_BUNDLE_ARTIFACT_TYPE.to_string(),
        chain_id: EXPECTED_CHAIN_ID,
        network_id: EXPECTED_NETWORK_ID.to_string(),
        release_id: EXPECTED_RELEASE_ID.to_string(),
        protocol_version: EXPECTED_PROTOCOL.to_string(),
        canonical_genesis_hash: document.hash().to_string(),
        testnet_v3_revision: options.testnet_v3_revision,
        synq_revision: options.synq_revision,
        aegis_revision: options.aegis_revision,
        validator_binary_sha256: options.validator_binary_sha256,
        execution_state_root: outcome.post_deployment_state_root.to_hex(),
        aivm_state_root: execution_state.aivm_state_root.clone(),
        receipt_root: outcome.receipt_root.to_hex(),
        deployment_count: outcome.deployment_receipts.len() as u64,
        initialization_count: outcome.initialization_receipts.len() as u64,
        deployment_receipts: outcome.deployment_receipts,
        initialization_receipts: outcome.initialization_receipts,
        execution_state,
    };
    let bytes = serde_json::to_vec_pretty(&bundle)
        .map_err(|error| format!("serialize execution bundle: {error}"))?;
    write_new(&options.output, &bytes)?;
    println!(
        "LOCAL_R11_GENESIS_EXECUTION_BUNDLE_WRITTEN=YES\nEXECUTION_SNAPSHOT_SHA256={}\nEXECUTION_STATE_ROOT={}\nAIVM_STATE_ROOT={}\nRECEIPT_ROOT={}\nDEPLOYMENT_RECEIPTS=9\nINITIALIZATION_RECEIPTS=27",
        hex::encode(Sha256::digest(&bytes)),
        bundle.execution_state_root,
        bundle.aivm_state_root,
        bundle.receipt_root,
    );
    Ok(())
}

fn main() {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    let options = parse_options(&args).unwrap_or_else(|error| {
        eprintln!("generate-local-r11-genesis-execution-bundle: {error}");
        usage();
    });
    run(options, &args).unwrap_or_else(fail);
}
