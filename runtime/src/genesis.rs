use chrono::{DateTime, Utc};
use lazy_static::lazy_static;
use serde_json::{json, Value};
use std::fs;
use std::path::PathBuf;

use crate::utils::resolve_data_path;

const ZERO_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Debug, Clone)]
pub struct GenesisBalance {
    pub address: String,
    pub balance_nwei: u64,
}

#[derive(Debug, Clone)]
pub struct InitialValidator {
    pub validator_id: String,
    pub operator_address: String,
    pub consensus_key_type: String,
    pub consensus_public_key: String,
    pub moniker: String,
    pub stake_nwei: u64,
}

#[derive(Debug, Clone)]
pub struct GenesisTokenConfig {
    pub name: String,
    pub symbol: String,
    pub decimals: u8,
    pub total_supply_cap_nwei: u128,
    pub initial_circulating_nwei: u128,
}

#[derive(Debug, Clone)]
pub struct GenesisDocument {
    value: Value,
    path: PathBuf,
    genesis_hash: String,
    network_magic_bytes: String,
    chain_id: u64,
    network_id: u64,
    protocol_version: String,
    consensus_version: String,
    timestamp: u64,
    balances: Vec<GenesisBalance>,
    validators: Vec<InitialValidator>,
    token: GenesisTokenConfig,
}

lazy_static! {
    static ref CANONICAL_GENESIS: Result<GenesisDocument, String> =
        load_canonical_genesis_from_disk();
}

pub fn canonical_genesis() -> Result<&'static GenesisDocument, String> {
    match &*CANONICAL_GENESIS {
        Ok(document) => Ok(document),
        Err(error) => Err(error.clone()),
    }
}

pub(crate) fn load_canonical_genesis_for_runtime() -> Result<GenesisDocument, String> {
    load_canonical_genesis_from_disk()
}

impl GenesisDocument {
    pub fn path(&self) -> &PathBuf {
        &self.path
    }

    pub fn value(&self) -> &Value {
        &self.value
    }

    pub fn hash(&self) -> &str {
        &self.genesis_hash
    }

    pub fn network_magic_bytes(&self) -> &str {
        &self.network_magic_bytes
    }

    pub fn chain_id(&self) -> u64 {
        self.chain_id
    }

    pub fn network_id(&self) -> u64 {
        self.network_id
    }

    pub fn protocol_version(&self) -> &str {
        &self.protocol_version
    }

    pub fn consensus_version(&self) -> &str {
        &self.consensus_version
    }

    pub fn timestamp(&self) -> u64 {
        self.timestamp
    }

    pub fn balances(&self) -> &[GenesisBalance] {
        &self.balances
    }

    pub fn validators(&self) -> &[InitialValidator] {
        &self.validators
    }

    pub fn token(&self) -> &GenesisTokenConfig {
        &self.token
    }
}

fn load_canonical_genesis_from_disk() -> Result<GenesisDocument, String> {
    let path = genesis_path();
    load_canonical_genesis_from_path(path)
}

fn load_canonical_genesis_from_path(path: PathBuf) -> Result<GenesisDocument, String> {
    let bytes = fs::read(&path)
        .map_err(|error| format!("read canonical genesis {}: {error}", path.display()))?;
    let value: Value = serde_json::from_slice(&bytes)
        .map_err(|error| format!("parse canonical genesis {}: {error}", path.display()))?;

    validate_no_placeholders(&value)?;

    let timestamp = parse_timestamp(required(&value, &["header", "timestamp"])?)
        .map_err(|error| format!("header.timestamp: {error}"))?;
    let chain_id = required_u64(&value, &["network", "chain_id"])?;
    let network_id = required_u64(&value, &["network", "network_id"])?;
    let protocol_version = required_string(&value, &["network", "protocol_version"])?;
    let consensus_version = required_string(&value, &["network", "consensus_version"])?;
    let balances = parse_balances(&value)?;
    let validators = parse_validators(&value)?;
    let token = parse_token_config(&value)?;

    validate_integrity_hashes(&value)?;

    let genesis_hash = required_string(&value, &["integrity", "genesis_hash"])?;
    if genesis_hash.is_empty() {
        return Err("integrity.genesis_hash must not be empty".to_string());
    }
    let network_magic_bytes = if is_testnet_v3_candidate_schema(&value) {
        required_string(&value, &["network_magic_bytes", "value"])?
    } else {
        required_string(&value, &["p2p_identity", "network_magic_bytes"])?
    };
    if network_magic_bytes.is_empty() {
        return Err("p2p_identity.network_magic_bytes must not be empty".to_string());
    }

    Ok(GenesisDocument {
        value,
        path,
        genesis_hash,
        network_magic_bytes,
        chain_id,
        network_id,
        protocol_version,
        consensus_version,
        timestamp,
        balances,
        validators,
        token,
    })
}

#[cfg(test)]
pub(crate) fn load_genesis_from_path_for_test(path: PathBuf) -> Result<GenesisDocument, String> {
    load_canonical_genesis_from_path(path)
}

fn genesis_path() -> PathBuf {
    let configured = std::env::var("SYNERGY_GENESIS_FILE")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| "config/genesis.json".to_string());
    resolve_data_path(&configured)
}

fn parse_balances(value: &Value) -> Result<Vec<GenesisBalance>, String> {
    let balances = required_array(value, &["balances"])?;
    balances
        .iter()
        .map(|entry| {
            Ok(GenesisBalance {
                address: required_string(entry, &["address"])?,
                balance_nwei: parse_u64(&required_string(entry, &["balance_nwei"])?)?,
            })
        })
        .collect()
}

fn parse_validators(value: &Value) -> Result<Vec<InitialValidator>, String> {
    let validators = required_array(value, &["validators"])?;
    if validators.is_empty() {
        return Err("validators must not be empty".to_string());
    }

    validators
        .iter()
        .map(|entry| {
            Ok(InitialValidator {
                validator_id: required_string(entry, &["validator_id"])?,
                operator_address: required_string(entry, &["operator_address"])?,
                consensus_key_type: required_string(entry, &["consensus_key_type"])?,
                consensus_public_key: required_string(entry, &["consensus_public_key"])?,
                moniker: required_string(entry, &["moniker"])?,
                stake_nwei: parse_u64(&required_string(entry, &["stake_nwei"])?)?,
            })
        })
        .collect()
}

fn parse_token_config(value: &Value) -> Result<GenesisTokenConfig, String> {
    Ok(GenesisTokenConfig {
        name: required_string(value, &["token", "name"])?,
        symbol: required_string(value, &["token", "symbol"])?,
        decimals: required_u64(value, &["token", "decimals"])? as u8,
        total_supply_cap_nwei: parse_u128(&required_string(
            value,
            &["token", "total_supply_cap_nwei"],
        )?)?,
        initial_circulating_nwei: parse_u128(&required_string(
            value,
            &["token", "initial_circulating_nwei"],
        )?)?,
    })
}

fn validate_integrity_hashes(value: &Value) -> Result<(), String> {
    if is_testnet_v3_candidate_schema(value) {
        return validate_testnet_v3_candidate_integrity_hashes(value);
    }

    let empty_hash = hash_bytes(&[]);
    let allocation_hash = hash_json(required(value, &["allocations"])?);
    let validator_hash = hash_json(required(value, &["validators"])?);
    let validator_set_hash = hash_json(required(
        value,
        &[
            "contracts",
            "validator_registry",
            "init_params",
            "validators",
        ],
    )?);
    let contract_hash = hash_json(required(value, &["contracts"])?);
    let state_root = hash_json(&json!({
        "accounts": required(value, &["accounts"])?,
        "balances": required(value, &["balances"])?,
        "allocations": required(value, &["allocations"])?,
        "contracts": required(value, &["contracts"])?,
        "consensus": required(value, &["consensus"])?,
        "genesis_message": required(value, &["genesis_message"])?,
        "governance": required(value, &["governance"])?,
        "modules": required(value, &["modules"])?,
        "network": required(value, &["network"])?,
        "network_identity": required(value, &["network_identity"])?,
        "reserved_addresses": required(value, &["system_reserved_addresses"])?,
        "security": required(value, &["security"])?,
        "synergy_state": required(value, &["synergy_state"])?,
        "token": required(value, &["token"])?,
        "validators": required(value, &["validators"])?,
    }));
    let data_root = hash_json(&json!({
        "contracts": required(value, &["contracts"])?,
        "modules": required(value, &["modules"])?,
        "precompiles": required(value, &["precompiles"])?,
    }));

    compare_hash(
        value,
        &["header", "parent_hash"],
        ZERO_HASH,
        "header.parent_hash",
    )?;
    compare_hash(
        value,
        &["header", "transactions_root"],
        &empty_hash,
        "header.transactions_root",
    )?;
    compare_hash(
        value,
        &["header", "receipts_root"],
        &empty_hash,
        "header.receipts_root",
    )?;
    compare_hash(
        value,
        &["header", "state_root"],
        &state_root,
        "header.state_root",
    )?;
    compare_hash(
        value,
        &["header", "data_root"],
        &data_root,
        "header.data_root",
    )?;
    compare_hash(
        value,
        &["integrity", "allocation_hash"],
        &allocation_hash,
        "integrity.allocation_hash",
    )?;
    compare_hash(
        value,
        &["integrity", "validator_hash"],
        &validator_hash,
        "integrity.validator_hash",
    )?;
    compare_hash(
        value,
        &[
            "contracts",
            "validator_registry",
            "init_params",
            "validator_set_hash",
        ],
        &validator_set_hash,
        "contracts.validator_registry.init_params.validator_set_hash",
    )?;
    compare_hash(
        value,
        &["integrity", "validator_set_hash"],
        &validator_set_hash,
        "integrity.validator_set_hash",
    )?;
    compare_hash(
        value,
        &["integrity", "contract_hash"],
        &contract_hash,
        "integrity.contract_hash",
    )?;
    compare_hash(
        value,
        &["integrity", "state_root"],
        &state_root,
        "integrity.state_root",
    )?;

    if required(value, &["integrity", "recompute_required"])?
        .as_bool()
        .unwrap_or(true)
    {
        return Err("integrity.recompute_required must be false".to_string());
    }

    let expected_genesis_hash = hash_json(&genesis_hash_payload(value));
    compare_hash(
        value,
        &["integrity", "genesis_hash"],
        &expected_genesis_hash,
        "integrity.genesis_hash",
    )?;
    let caip2 = required_string(value, &["network_identity", "canonical_caip2", "value"])?;
    let network_magic_bytes = network_magic_bytes_for(&caip2, &expected_genesis_hash);
    compare_hash(
        value,
        &["p2p_identity", "network_magic_bytes"],
        &network_magic_bytes,
        "p2p_identity.network_magic_bytes",
    )?;

    Ok(())
}

/// The Testnet-v3 ceremony artifact uses a deliberately smaller, fully
/// canonicalized genesis schema than the inherited runtime template.  It must
/// be validated as-is; translating it through the legacy schema would change
/// consensus bytes and invalidate every approved public binding.
fn is_testnet_v3_candidate_schema(value: &Value) -> bool {
    value
        .get("canonicalization")
        .and_then(|entry| entry.get("json_profile"))
        .and_then(Value::as_str)
        == Some("deterministic_sorted_keys_no_insignificant_whitespace")
}

fn validate_testnet_v3_candidate_integrity_hashes(value: &Value) -> Result<(), String> {
    let empty_hash = hash_bytes(&[]);
    let allocation_hash = hash_json(required(value, &["allocations"])?);
    let validator_hash = hash_json(required(value, &["validators"])?);
    let validator_set_hash = hash_json(required(
        value,
        &[
            "contracts",
            "validator_registry",
            "init_params",
            "validators",
        ],
    )?);
    let contract_hash = hash_json(required(value, &["contracts"])?);
    let state_root = hash_json(&json!({
        "accounts": required(value, &["accounts"] )?,
        "balances": required(value, &["balances"] )?,
        "allocations": required(value, &["allocations"] )?,
        "contracts": required(value, &["contracts"] )?,
        "consensus": required(value, &["consensus"] )?,
        "governance": required(value, &["governance"] )?,
        "modules": required(value, &["modules"] )?,
        "network": required(value, &["network"] )?,
        "security": required(value, &["security"] )?,
        "synergy_state": required(value, &["synergy_state"] )?,
        "token": required(value, &["token"] )?,
        "validators": required(value, &["validators"] )?,
    }));
    let data_root = hash_json(&json!({
        "contracts": required(value, &["contracts"] )?,
        "modules": required(value, &["modules"] )?,
        "precompiles": required(value, &["precompiles"] )?,
    }));

    compare_hash(
        value,
        &["header", "parent_hash"],
        ZERO_HASH,
        "header.parent_hash",
    )?;
    compare_hash(
        value,
        &["header", "transactions_root"],
        &empty_hash,
        "header.transactions_root",
    )?;
    compare_hash(
        value,
        &["header", "receipts_root"],
        &empty_hash,
        "header.receipts_root",
    )?;
    compare_hash(
        value,
        &["header", "state_root"],
        &state_root,
        "header.state_root",
    )?;
    compare_hash(
        value,
        &["header", "data_root"],
        &data_root,
        "header.data_root",
    )?;
    compare_hash(
        value,
        &["integrity", "allocation_hash"],
        &allocation_hash,
        "integrity.allocation_hash",
    )?;
    compare_hash(
        value,
        &["integrity", "validator_hash"],
        &validator_hash,
        "integrity.validator_hash",
    )?;
    compare_hash(
        value,
        &[
            "contracts",
            "validator_registry",
            "init_params",
            "validator_set_hash",
        ],
        &validator_set_hash,
        "contracts.validator_registry.init_params.validator_set_hash",
    )?;
    compare_hash(
        value,
        &["integrity", "validator_set_hash"],
        &validator_set_hash,
        "integrity.validator_set_hash",
    )?;
    compare_hash(
        value,
        &["integrity", "contract_hash"],
        &contract_hash,
        "integrity.contract_hash",
    )?;
    compare_hash(
        value,
        &["integrity", "state_root"],
        &state_root,
        "integrity.state_root",
    )?;

    let expected_genesis_hash = hash_json(&genesis_hash_payload(value));
    compare_hash(
        value,
        &["integrity", "genesis_hash"],
        &expected_genesis_hash,
        "integrity.genesis_hash",
    )?;
    let caip2 = "synergy:testnet-v3";
    let network_magic_bytes = network_magic_bytes_for(caip2, &expected_genesis_hash);
    compare_hash(
        value,
        &["network_magic_bytes", "value"],
        &network_magic_bytes,
        "network_magic_bytes.value",
    )?;
    Ok(())
}

fn genesis_hash_payload(value: &Value) -> Value {
    let mut payload = if let Some(inputs) = value
        .get("canonicalization")
        .and_then(|entry| entry.get("genesis_hash_inputs"))
        .and_then(Value::as_array)
    {
        let mut map = serde_json::Map::new();
        for input in inputs.iter().filter_map(Value::as_str) {
            if let Some(entry) = value.get(input) {
                map.insert(input.to_string(), entry.clone());
            }
        }
        Value::Object(map)
    } else {
        value.clone()
    };

    let mut excluded = value
        .get("canonicalization")
        .and_then(|entry| entry.get("excluded_from_genesis_hash"))
        .and_then(Value::as_array)
        .map(|entries| {
            entries
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    excluded.extend(
        [
            "integrity.genesis_hash",
            "integrity.signed_by",
            "integrity.draft_artifact_sha256",
            "integrity.recompute_required",
            "integrity.recompute_reason",
            "p2p_identity.network_magic_bytes",
            "p2p_identity.provisional_derivation_note",
        ]
        .iter()
        .map(|entry| entry.to_string()),
    );
    excluded.sort();
    excluded.dedup();
    for path in excluded {
        remove_dotted_path(&mut payload, &path);
    }
    payload
}

fn remove_dotted_path(value: &mut Value, dotted_path: &str) {
    let parts = dotted_path.split('.').collect::<Vec<_>>();
    let Some((last, parents)) = parts.split_last() else {
        return;
    };
    let mut current = value;
    for part in parents {
        let Some(next) = current.get_mut(*part) else {
            return;
        };
        current = next;
    }
    if let Some(map) = current.as_object_mut() {
        map.remove(*last);
    }
}

fn network_magic_bytes_for(caip2: &str, genesis_hash: &str) -> String {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"synergy-network-magic-v1");
    bytes.extend_from_slice(caip2.as_bytes());
    bytes.extend_from_slice(genesis_hash.as_bytes());
    hex::encode(&blake3::hash(&bytes).as_bytes()[0..4])
}

fn compare_hash(value: &Value, path: &[&str], expected: &str, label: &str) -> Result<(), String> {
    let actual = required_string(value, path)?;
    if actual != expected {
        return Err(format!(
            "{label} mismatch: expected {expected}, found {actual}"
        ));
    }
    Ok(())
}

fn validate_no_placeholders(value: &Value) -> Result<(), String> {
    if let Some(path) = find_placeholder_path(value, "$") {
        return Err(format!("placeholder value found at {path}"));
    }
    Ok(())
}

fn find_placeholder_path(value: &Value, path: &str) -> Option<String> {
    match value {
        Value::String(entry) => {
            if entry.contains('<') && entry.contains('>') {
                Some(path.to_string())
            } else {
                None
            }
        }
        Value::Array(entries) => entries
            .iter()
            .enumerate()
            .find_map(|(index, entry)| find_placeholder_path(entry, &format!("{path}[{index}]"))),
        Value::Object(entries) => entries
            .iter()
            .find_map(|(key, entry)| find_placeholder_path(entry, &format!("{path}.{key}"))),
        _ => None,
    }
}

fn parse_timestamp(value: &Value) -> Result<u64, String> {
    match value {
        Value::Number(number) => number
            .as_u64()
            .ok_or_else(|| "timestamp must be an unsigned integer".to_string()),
        Value::String(raw) => DateTime::parse_from_rfc3339(raw)
            .map(|timestamp| timestamp.with_timezone(&Utc).timestamp().max(0) as u64)
            .map_err(|error| format!("invalid RFC3339 timestamp: {error}")),
        _ => Err("timestamp must be an integer or RFC3339 string".to_string()),
    }
}

fn parse_u64(raw: &str) -> Result<u64, String> {
    raw.parse::<u64>()
        .map_err(|error| format!("invalid u64 value '{raw}': {error}"))
}

fn parse_u128(raw: &str) -> Result<u128, String> {
    raw.parse::<u128>()
        .map_err(|error| format!("invalid u128 value '{raw}': {error}"))
}

fn required<'a>(value: &'a Value, path: &[&str]) -> Result<&'a Value, String> {
    let mut current = value;
    for segment in path {
        current = current
            .get(*segment)
            .ok_or_else(|| format!("missing path {}", path.join(".")))?;
    }
    Ok(current)
}

fn required_array<'a>(value: &'a Value, path: &[&str]) -> Result<&'a Vec<Value>, String> {
    required(value, path)?
        .as_array()
        .ok_or_else(|| format!("path {} is not an array", path.join(".")))
}

fn required_string(value: &Value, path: &[&str]) -> Result<String, String> {
    required(value, path)?
        .as_str()
        .map(str::to_string)
        .ok_or_else(|| format!("path {} is not a string", path.join(".")))
}

fn required_u64(value: &Value, path: &[&str]) -> Result<u64, String> {
    required(value, path)?
        .as_u64()
        .ok_or_else(|| format!("path {} is not a u64", path.join(".")))
}

fn hash_json(value: &Value) -> String {
    hash_bytes(canonical_json(value).as_bytes())
}

fn hash_bytes(bytes: &[u8]) -> String {
    blake3::hash(bytes).to_hex().to_string()
}

fn canonical_json(value: &Value) -> String {
    match value {
        Value::Null => "null".to_string(),
        Value::Bool(entry) => entry.to_string(),
        Value::Number(entry) => entry.to_string(),
        Value::String(entry) => serde_json::to_string(entry).unwrap_or_else(|_| "\"\"".to_string()),
        Value::Array(entries) => {
            let rendered = entries
                .iter()
                .map(canonical_json)
                .collect::<Vec<_>>()
                .join(",");
            format!("[{rendered}]")
        }
        Value::Object(entries) => {
            let mut keys = entries.keys().cloned().collect::<Vec<_>>();
            keys.sort();
            let rendered = keys
                .iter()
                .map(|key| {
                    let key_json =
                        serde_json::to_string(key).unwrap_or_else(|_| "\"\"".to_string());
                    let value_json = canonical_json(&entries[key]);
                    format!("{key_json}:{value_json}")
                })
                .collect::<Vec<_>>()
                .join(",");
            format!("{{{rendered}}}")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;

    fn testnet_v3_candidate() -> Value {
        serde_json::from_str(include_str!(
            "../../genesis.testnet-v3.identity-assigned.json"
        ))
        .expect("checked-in Testnet-v3 candidate genesis must be valid JSON")
    }

    #[test]
    fn testnet_v3_candidate_schema_recomputes_all_bound_roots() {
        let candidate = testnet_v3_candidate();
        assert!(is_testnet_v3_candidate_schema(&candidate));
        assert_eq!(
            required_u64(&candidate, &["network", "chain_id"]).unwrap(),
            1266
        );
        assert_eq!(
            candidate["consensus"]["initial_active_validator_count"].as_u64(),
            Some(6)
        );
        assert_eq!(
            candidate["consensus"]["initial_cluster_count"].as_u64(),
            Some(1)
        );
        assert_eq!(
            candidate["consensus"]["min_validator_count"].as_u64(),
            Some(6)
        );
        assert_eq!(
            candidate["consensus"]["min_quorum_threshold"].as_u64(),
            Some(5)
        );
        let validators = candidate["validators"]
            .as_array()
            .expect("candidate validators must be an array");
        assert_eq!(validators.len(), 6);
        for validator in validators {
            assert_eq!(validator["consensus_key_type"].as_str(), Some("ML-DSA-65"));
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(
                    validator["consensus_public_key"]
                        .as_str()
                        .expect("candidate consensus public key must be a string"),
                )
                .expect("candidate consensus public key must be base64");
            assert_eq!(bytes.len(), 1_952);
        }
        assert_eq!(
            candidate["testnet_v3_initialization"]["preconfigured_validator_count"].as_u64(),
            Some(21)
        );
        validate_integrity_hashes(&candidate).unwrap();
    }

    #[test]
    fn testnet_v3_candidate_rejects_network_magic_mutation() {
        let mut candidate = testnet_v3_candidate();
        candidate["network_magic_bytes"]["value"] = Value::String("00000000".to_string());
        let error = validate_integrity_hashes(&candidate).unwrap_err();
        assert!(error.contains("network_magic_bytes.value mismatch"));
    }

    #[test]
    fn runtime_loader_accepts_the_verified_testnet_v3_candidate_schema() {
        let candidate = testnet_v3_candidate();
        let expected_magic = candidate["network_magic_bytes"]["value"]
            .as_str()
            .expect("candidate network magic must be a string");
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../genesis.testnet-v3.identity-assigned.json");
        let document = load_canonical_genesis_from_path(path).unwrap();
        assert_eq!(document.chain_id(), 1266);
        assert_eq!(document.network_id(), 1266);
        assert_eq!(document.validators().len(), 6);
        assert_eq!(document.network_magic_bytes(), expected_magic);
    }
}
