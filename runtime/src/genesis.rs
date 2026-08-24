use chrono::{DateTime, Utc};
#[cfg(not(test))]
use lazy_static::lazy_static;
use serde_json::{json, Value};
use sha2::Digest as _;
use std::fs;
use std::path::PathBuf;
#[cfg(test)]
use std::{cell::RefCell, collections::BTreeMap};

use crate::consensus_parameters::{
    load_genesis_bound_consensus_parameters, LoadedConsensusParameters,
    CONSENSUS_PARAMETER_GENESIS_BINDING_SCHEMA_VERSION, CONSENSUS_PARAMETER_GENESIS_BINDING_STATUS,
    CONSENSUS_PARAMETER_MANIFEST_RELEASE_ID,
};
use crate::etdag_governance::{EtdagGovernedGenesisBinding, EtdagGovernedMembershipAnchor};
use crate::synergy_types::{
    TESTNET_V3_CHAIN_INCARNATION, TESTNET_V3_CONSENSUS_STATE_SCHEMA_VERSION,
    TESTNET_V3_FRESH_P3_CHAIN_INCARNATION,
};
use crate::utils::resolve_data_path;

const ZERO_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";
/// The only deployed Chain 1266 Genesis record that predates the explicit
/// incarnation/schema fields. This semantic hash is immutable: the loader
/// derives the P1 state domain for this one record, but never rewrites Genesis
/// or accepts a similarly-shaped replacement.
const CHAIN_1266_PRE_P1_GENESIS_HASH: &str =
    "c087b6b7c1aae6f13f4c0140ba9a230a12dea0fa52b611777dee69369457de3d";

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

/// Runtime versions frozen into a fresh simplified PoSy Genesis.  These are
/// intentionally separate from the old typed-finality header because block
/// one has no predecessor block header to inherit from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SimplifiedGenesisRuntimeMetadata {
    pub app_version: u32,
    pub execution_version: u32,
    pub dag_version: u32,
    pub aegis_pqvm_version: String,
}

#[derive(Debug, Clone)]
pub struct GenesisDocument {
    value: Value,
    path: PathBuf,
    genesis_hash: String,
    network_magic_bytes: String,
    chain_id: u64,
    chain_incarnation: u64,
    consensus_state_schema_version: u32,
    network_id: u64,
    protocol_version: String,
    consensus_version: String,
    timestamp: u64,
    balances: Vec<GenesisBalance>,
    validators: Vec<InitialValidator>,
    token: GenesisTokenConfig,
    consensus_parameters: Option<LoadedConsensusParameters>,
}

#[cfg(not(test))]
lazy_static! {
    static ref CANONICAL_GENESIS: Result<GenesisDocument, String> =
        load_canonical_genesis_from_disk();
}

#[cfg(not(test))]
pub fn canonical_genesis() -> Result<&'static GenesisDocument, String> {
    match &*CANONICAL_GENESIS {
        Ok(document) => Ok(document),
        Err(error) => Err(error.clone()),
    }
}

#[cfg(test)]
thread_local! {
    /// Test suites select different complete Genesis documents through
    /// `SYNERGY_GENESIS_FILE`. Cache by resolved path on each test thread so
    /// one fixture cannot control another, while avoiding a full multi-megabyte
    /// Genesis parse and integrity rehash for every consensus signature.
    static TEST_CANONICAL_GENESIS: RefCell<
        BTreeMap<PathBuf, Result<&'static GenesisDocument, String>>
    > = RefCell::new(BTreeMap::new());
}

#[cfg(test)]
pub fn canonical_genesis() -> Result<&'static GenesisDocument, String> {
    // Test modules deliberately switch `SYNERGY_GENESIS_FILE` to isolated,
    // signed fixtures. A process-global Lazy result makes whichever test runs
    // first silently control every later test. A thread-local, path-keyed
    // cache preserves that isolation and keeps consensus tests representative
    // of the production cache rather than repeatedly hashing Genesis.
    let path = genesis_path();
    TEST_CANONICAL_GENESIS.with(|cache| {
        if let Some(cached) = cache.borrow().get(&path) {
            return cached.clone();
        }
        let loaded = if path == fresh_p3_unit_test_genesis_path() {
            fresh_p3_unit_test_genesis()
        } else {
            load_genesis_from_path_for_test(path.clone())
        }
        .map(|document| {
            // The test executable owns this object until process exit, which
            // preserves the established `&'static GenesisDocument` API.
            Box::leak(Box::new(document)) as &'static GenesisDocument
        });
        cache.borrow_mut().insert(path, loaded.clone());
        loaded
    })
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

    pub fn chain_incarnation(&self) -> u64 {
        self.chain_incarnation
    }

    pub fn consensus_state_schema_version(&self) -> u32 {
        self.consensus_state_schema_version
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

    pub fn consensus_parameters(&self) -> Option<&LoadedConsensusParameters> {
        self.consensus_parameters.as_ref()
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

    load_canonical_genesis_from_value(value, path)
}

/// Parse an already-decoded canonical Genesis candidate through exactly the
/// same loader and integrity gates used for on-disk Genesis.  The test-only
/// P3 fixture adapter below uses this to avoid allowing the checked-in
/// historical fixture to select an obsolete consensus profile.
fn load_canonical_genesis_from_value(
    value: Value,
    path: PathBuf,
) -> Result<GenesisDocument, String> {
    validate_no_placeholders(&value)?;
    reject_test_fixture_genesis(&value, &path)?;

    let timestamp = parse_timestamp(required(&value, &["header", "timestamp"])?)
        .map_err(|error| format!("header.timestamp: {error}"))?;
    let chain_id = required_u64(&value, &["network", "chain_id"])?;
    let is_pre_p1_chain1266_genesis = is_chain1266_pre_p1_genesis(&value);
    let is_fresh_simplified_genesis = required_string(&value, &["network", "consensus_version"])
        .as_deref()
        == Ok(crate::consensus::simplified_posy::POSY_SIMPLIFIED_PROTOCOL_VERSION);
    let expected_chain_incarnation = if is_fresh_simplified_genesis {
        crate::posy_simplified_parameters::POSY_SIMPLIFIED_CHAIN_INCARNATION
    } else {
        TESTNET_V3_CHAIN_INCARNATION
    };
    let expected_state_schema_version = if is_fresh_simplified_genesis {
        crate::posy_simplified_parameters::POSY_SIMPLIFIED_CONSENSUS_STATE_SCHEMA_VERSION
    } else {
        TESTNET_V3_CONSENSUS_STATE_SCHEMA_VERSION
    };
    let chain_incarnation = required_u64_or_derived_pre_p1_value(
        &value,
        &["network", "chain_incarnation"],
        expected_chain_incarnation,
        is_pre_p1_chain1266_genesis,
    )?;
    let consensus_state_schema_version = required_u64_or_derived_pre_p1_value(
        &value,
        &["consensus", "state_schema_version"],
        u64::from(expected_state_schema_version),
        is_pre_p1_chain1266_genesis,
    )?;
    if chain_incarnation != expected_chain_incarnation {
        return Err(format!(
            "wrong Chain 1266 incarnation: expected {}, found {chain_incarnation}",
            expected_chain_incarnation
        ));
    }
    if consensus_state_schema_version != u64::from(expected_state_schema_version) {
        return Err(format!(
            "wrong consensus state schema: expected {}, found {consensus_state_schema_version}",
            expected_state_schema_version
        ));
    }
    let expected_state_namespace = format!("chain-{chain_id}/incarnation-{chain_incarnation}");
    let state_namespace = required_string_or_derived_pre_p1_value(
        &value,
        &["consensus", "state_directory_namespace"],
        &expected_state_namespace,
        is_pre_p1_chain1266_genesis,
    )?;
    if state_namespace != expected_state_namespace {
        return Err(
            "Genesis consensus state namespace does not match its chain domain".to_string(),
        );
    }
    let network_id =
        parse_runtime_numeric_network_id(&value, chain_id, is_fresh_simplified_genesis)?;
    let protocol_version = required_string(&value, &["network", "protocol_version"])?;
    let consensus_version = required_string(&value, &["network", "consensus_version"])?;
    let balances = parse_balances(&value)?;
    let validators = parse_validators(&value)?;
    let token = parse_token_config(&value)?;
    let consensus_parameters = load_candidate_consensus_parameters(&value)?;

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

    let document = GenesisDocument {
        value,
        path,
        genesis_hash,
        network_magic_bytes,
        chain_id,
        chain_incarnation,
        consensus_state_schema_version: consensus_state_schema_version as u32,
        network_id,
        protocol_version,
        consensus_version,
        timestamp,
        balances,
        validators,
        token,
        consensus_parameters,
    };
    if document.value.get("genesis_deployment").is_some() {
        crate::testnet_v3_execution_bootstrap::load_finalized_testnet_v3_genesis_execution_state(
            &document,
        )
        .map_err(|error| format!("validate finalized Genesis execution state: {error}"))?;
    }
    Ok(document)
}

/// Validates Genesis' canonical network identity while preserving the numeric
/// compatibility value used by existing internal wire structures. Fresh P3
/// Genesis remains string-identified as `testnet`; only the in-memory legacy
/// compatibility field is derived as 1266.
fn parse_runtime_numeric_network_id(
    value: &Value,
    chain_id: u64,
    is_fresh_simplified_genesis: bool,
) -> Result<u64, String> {
    if is_fresh_simplified_genesis {
        if chain_id != crate::synergy_types::SYNERGY_TESTNET_V3_CHAIN_ID {
            return Err(format!(
                "fresh P3 network.chain_id must be {}, found {chain_id}",
                crate::synergy_types::SYNERGY_TESTNET_V3_CHAIN_ID
            ));
        }
        if required_string(value, &["network", "network_id"])?
            != crate::synergy_types::TESTNET_V3_CANONICAL_NETWORK_ID
        {
            return Err(
                "fresh P3 network.network_id must be the canonical string testnet".to_string(),
            );
        }
        if required_string(value, &["network", "release_id"])?
            != CONSENSUS_PARAMETER_MANIFEST_RELEASE_ID
        {
            return Err(
                "fresh P3 network.release_id must be the canonical string testnet-v3".to_string(),
            );
        }
        return Ok(crate::synergy_types::SYNERGY_TESTNET_V3_CHAIN_ID);
    }

    required_u64(value, &["network", "network_id"])
}

/// Loads and fully validates a genesis document from an explicit path.
///
/// Release tooling uses this entry point to validate a staged candidate before
/// any canonical file is replaced. It performs the same checks as the runtime
/// loader, including every integrity root and the derived network magic.
pub fn load_genesis_from_path(path: impl Into<PathBuf>) -> Result<GenesisDocument, String> {
    #[cfg(test)]
    {
        return load_genesis_from_path_for_test(path.into());
    }
    #[cfg(not(test))]
    {
        load_canonical_genesis_from_path(path.into())
    }
}

#[cfg(test)]
pub(crate) fn load_genesis_from_path_for_test(path: PathBuf) -> Result<GenesisDocument, String> {
    if path
        .file_name()
        .is_some_and(|name| name == "genesis.testnet-v3.test-fixture.json")
    {
        return load_canonical_genesis_from_value(fresh_posy_v3_test_fixture()?, path);
    }
    load_canonical_genesis_from_path(path)
}

/// Construct the common unit-test Genesis through the same fresh-P3 public
/// authorities used by the release path.  The file with this name predates
/// P3 and remains only as a non-production structural seed while historical
/// tests are being retired; tests must never deserialize its P2.2 binding.
///
/// This deliberately uses no private material and does not relax a single
/// validation rule: it installs a canonical P3 manifest, the exact five
/// public validator activation, and governed ETDAG parameter/fee binding
/// before invoking the ordinary Genesis integrity recomputation.
#[cfg(test)]
fn fresh_posy_v3_test_fixture() -> Result<Value, String> {
    let value: Value = serde_json::from_str(include_str!(
        "../../launch/posy-v3-genesis-inputs/fresh-p3-genesis-predeployment-public-input.json"
    ))
    .map_err(|error| format!("parse fresh P3 test fixture source: {error}"))?;
    bind_fresh_posy_v3_test_authorities(value)
}

/// Applies the public P3 authority records to any isolated test Genesis
/// seed.  Both the historical structural fixture and the fresh public source
/// input use this exact path, so consensus-domain tests never obtain a
/// partially-bound candidate.
#[cfg(test)]
fn bind_fresh_posy_v3_test_authorities(mut value: Value) -> Result<Value, String> {
    use crate::consensus::simplified_posy::GenesisBoundSimplifiedActivation;
    use crate::consensus_parameters::{
        load_finalized_consensus_parameters_from_bytes, FinalizedConsensusParameterManifest,
    };
    use crate::etdag_governance::{
        EtdagFeeScheduleArtifact, EtdagFeeScheduleManifest, EtdagGovernedGenesisBinding,
        EtdagParameterArtifact, EtdagParameterManifest,
        ETDAG_GOVERNED_GENESIS_BINDING_SCHEMA_VERSION, ETDAG_GOVERNED_GENESIS_BINDING_STATUS,
    };

    let manifest: FinalizedConsensusParameterManifest = serde_json::from_slice(include_bytes!(
        "../../launch/posy-v3-etdag-governance-inputs/posy-simplified-parameter-manifest.for-release.json"
    ))
    .map_err(|error| format!("parse fresh P3 test manifest: {error}"))?;
    let canonical_manifest = manifest.canonical_bytes()?;
    let parameters = load_finalized_consensus_parameters_from_bytes(&canonical_manifest)?;
    let activation: GenesisBoundSimplifiedActivation = serde_json::from_slice(include_bytes!(
        "../../launch/posy-v3-genesis-inputs/five-validator-genesis-activation.json"
    ))
    .map_err(|error| format!("parse fresh P3 test activation: {error}"))?;
    let parameter_manifest: EtdagParameterManifest = serde_json::from_slice(include_bytes!(
        "../../launch/posy-v3-etdag-governance-inputs/etdag-parameter-manifest.input.json"
    ))
    .map_err(|error| format!("parse governed ETDAG parameter test input: {error}"))?;
    let fee_schedule_manifest: EtdagFeeScheduleManifest = serde_json::from_slice(include_bytes!(
        "../../launch/posy-v3-etdag-governance-inputs/etdag-fee-schedule-manifest.input.json"
    ))
    .map_err(|error| format!("parse governed ETDAG fee test input: {error}"))?;
    let etdag_binding = EtdagGovernedGenesisBinding {
        schema_version: ETDAG_GOVERNED_GENESIS_BINDING_SCHEMA_VERSION,
        status: ETDAG_GOVERNED_GENESIS_BINDING_STATUS.to_string(),
        parameter_artifact: EtdagParameterArtifact::from_manifest(parameter_manifest)?,
        fee_schedule_artifact: EtdagFeeScheduleArtifact::from_manifest(fee_schedule_manifest)?,
    };
    etdag_binding.validate()?;

    let object = value
        .as_object_mut()
        .ok_or_else(|| "common Testnet-v3 test fixture seed is not an object".to_string())?;
    object.remove("genesis_deployment");
    object.remove("contract_address_migration");
    object.remove("etdag_membership_anchor");
    value["env"] = Value::String("test-fixture".to_string());
    value["network"]["chain_incarnation"] =
        json!(crate::posy_simplified_parameters::POSY_SIMPLIFIED_CHAIN_INCARNATION);
    value["network"]["network_id"] = Value::String("testnet".to_string());
    value["network"]["network_slug"] = Value::String("testnet".to_string());
    value["network"]["release_id"] =
        Value::String(CONSENSUS_PARAMETER_MANIFEST_RELEASE_ID.to_string());
    value["network"]["consensus_version"] = Value::String(
        crate::consensus::simplified_posy::POSY_SIMPLIFIED_PROTOCOL_VERSION.to_string(),
    );
    value["header"]["consensus_fields"]["engine_id"] = Value::String(
        crate::consensus::simplified_posy::POSY_SIMPLIFIED_PROTOCOL_VERSION.to_string(),
    );

    let decision_sha256 = hex::encode(sha2::Sha256::digest(&canonical_manifest));
    bind_testnet_v3_genesis_simplified_posy_authorities(
        &mut value,
        &parameters,
        &decision_sha256,
        &activation,
        &etdag_binding,
    )?;
    value["test_fixture"]["fixture_consensus_profile"] = Value::String(
        crate::consensus::simplified_posy::POSY_SIMPLIFIED_PROTOCOL_VERSION.to_string(),
    );
    Ok(value)
}

#[cfg(not(test))]
fn genesis_path() -> PathBuf {
    let configured = std::env::var("SYNERGY_GENESIS_FILE")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| "config/genesis.json".to_string());
    resolve_data_path(&configured)
}

#[cfg(test)]
fn genesis_path() -> PathBuf {
    if let Some(configured) = std::env::var("SYNERGY_GENESIS_FILE")
        .ok()
        .filter(|value| !value.trim().is_empty())
    {
        return resolve_data_path(&configured);
    }

    // Test cases that construct an isolated runtime root install their own
    // complete fresh P3 `config/genesis.json`; preserve that behavior.
    let local = resolve_data_path("config/genesis.json");
    let local_is_fresh_p3 = fs::read(&local)
        .ok()
        .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
        .is_some_and(|value| {
            value.pointer("/network/chain_id").and_then(Value::as_u64) == Some(1266)
                && value.pointer("/network/network_id").and_then(Value::as_str) == Some("testnet")
                && value
                    .pointer("/network/consensus_version")
                    .and_then(Value::as_str)
                    == Some(crate::consensus::simplified_posy::POSY_SIMPLIFIED_PROTOCOL_VERSION)
        });
    if local_is_fresh_p3 {
        local
    } else {
        fresh_p3_unit_test_genesis_path()
    }
}

#[cfg(test)]
fn fresh_p3_unit_test_genesis_path() -> PathBuf {
    PathBuf::from("<fresh-p3-unit-test-genesis>")
}

/// Builds the sole implicit test Genesis from the current fresh-P3 public
/// input. Tests which need a different Genesis still set `SYNERGY_GENESIS_FILE`
/// explicitly. This keeps P3 signature-domain tests from silently consuming
/// the retired 2.2 fixture while retaining production's on-disk-only loader.
#[cfg(test)]
fn fresh_p3_unit_test_genesis() -> Result<GenesisDocument, String> {
    let value: Value = serde_json::from_str(include_str!(
        "../../launch/posy-v3-genesis-inputs/fresh-p3-genesis-predeployment-public-input.json"
    ))
    .map_err(|error| format!("parse fresh P3 unit-test genesis input: {error}"))?;
    let mut value = bind_fresh_posy_v3_test_authorities(value)?;
    recompute_testnet_v3_candidate_integrity(&mut value)?;
    load_canonical_genesis_from_value(value, fresh_p3_unit_test_genesis_path())
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

/// Identifies precisely the deployed, immutable pre-P1 Chain 1266 Genesis.
/// The subsequent integrity validation still re-computes the bound semantic
/// hash, so neither matching metadata nor this compatibility branch can admit
/// a modified Genesis document.
fn is_chain1266_pre_p1_genesis(value: &Value) -> bool {
    required_u64(value, &["header", "block_height"]) == Ok(0)
        && required_u64(value, &["network", "chain_id"]) == Ok(1266)
        && required_u64(value, &["network", "network_id"]) == Ok(1266)
        && required_string(value, &["network", "network_slug"]).as_deref()
            == Ok("synergy-testnet-v3")
        && required_string(value, &["network", "consensus_version"]).as_deref() == Ok("posy/2.2")
        && required_string(value, &["consensus", "algorithm"]).as_deref() == Ok("ProofOfSynergy")
        && required_string(value, &["integrity", "genesis_hash"]).as_deref()
            == Ok(CHAIN_1266_PRE_P1_GENESIS_HASH)
}

fn load_candidate_consensus_parameters(
    value: &Value,
) -> Result<Option<LoadedConsensusParameters>, String> {
    let Some(binding) = value.get("consensus_parameters") else {
        if value.get("genesis_deployment").is_some() {
            return Err(
                "finalized Testnet-v3 Genesis is missing its consensus parameter binding"
                    .to_string(),
            );
        }
        return Ok(None);
    };
    let loaded = load_genesis_bound_consensus_parameters(binding)?;
    let manifest = &loaded.manifest;
    if required_string(value, &["integrity", "consensus_parameter_decision_id"])?
        != manifest.governance_approval_id()?
    {
        return Err(
            "Genesis integrity Decision ID disagrees with finalized consensus parameters"
                .to_string(),
        );
    }
    if required_string(value, &["integrity", "consensus_parameter_manifest_sha256"])?
        != required_string(binding, &["canonical_manifest_sha256"])?
    {
        return Err(
            "Genesis integrity manifest digest disagrees with the consensus parameter binding"
                .to_string(),
        );
    }
    if required_string(value, &["integrity", "consensus_parameter_root_sha3_512"])?
        != loaded.root.to_hex()
    {
        return Err(
            "Genesis integrity parameter root disagrees with finalized consensus parameters"
                .to_string(),
        );
    }
    let hash_inputs = required_array(value, &["canonicalization", "genesis_hash_inputs"])?;
    if !hash_inputs
        .iter()
        .any(|entry| entry.as_str() == Some("consensus_parameters"))
    {
        return Err(
            "Genesis hash inputs do not include the finalized consensus parameters".to_string(),
        );
    }

    if required_u64(value, &["network", "chain_id"])? != manifest.chain_id().0 {
        return Err("Genesis chain ID disagrees with finalized consensus parameters".to_string());
    }
    if required_string(value, &["network", "network_slug"])? != manifest.network_id().0 {
        return Err("Genesis network ID disagrees with finalized consensus parameters".to_string());
    }
    if required_string(value, &["network", "consensus_version"])? != manifest.protocol_version() {
        return Err(
            "Genesis consensus version disagrees with finalized consensus parameters".to_string(),
        );
    }
    if let Ok(manifest) = manifest.coordinated_round_robin() {
        validate_coordinated_p1_genesis_parameters(value, manifest)?;
        return Ok(Some(loaded));
    }
    if let Ok(manifest) = loaded.require_simplified_posy_manifest() {
        validate_simplified_v3_genesis_parameters(value, manifest)?;
        return Ok(Some(loaded));
    }
    let manifest = manifest.as_posy()?;
    if required_u64(value, &["consensus", "epoch", "length_blocks"])?
        != manifest
            .epoch_length_slots
            .ok_or_else(|| "finalized epoch length is missing".to_string())?
    {
        return Err(
            "Genesis epoch length disagrees with finalized consensus parameters".to_string(),
        );
    }
    for (path, expected) in [
        (
            &["consensus", "target_block_time_ms"][..],
            manifest.target_block_time_ms,
        ),
        (
            &["consensus", "initial_active_validator_count"][..],
            manifest.initial_cluster_validator_count,
        ),
        (
            &["consensus", "min_validator_count"][..],
            manifest.initial_cluster_validator_count,
        ),
        (
            &["consensus", "min_quorum_threshold"][..],
            manifest.initial_availability_quorum,
        ),
        (
            &["consensus", "timeouts", "proposal_ms"][..],
            manifest.proposal_timeout_ms,
        ),
        (
            &["consensus", "timeouts", "prevote_ms"][..],
            manifest.prevote_timeout_ms,
        ),
        (
            &["consensus", "timeouts", "precommit_ms"][..],
            manifest.precommit_timeout_ms,
        ),
        (
            &["consensus", "timeouts", "max_round_ms"][..],
            manifest.max_round_timeout_ms,
        ),
    ] {
        if required_u64(value, path)? != expected {
            return Err(format!(
                "Genesis {} disagrees with finalized consensus parameters",
                path.join(".")
            ));
        }
    }
    if required_string(value, &["consensus", "cluster_schedule_version"])?
        != manifest.cluster_schedule_version
    {
        return Err(
            "Genesis cluster schedule disagrees with finalized consensus parameters".to_string(),
        );
    }
    if parse_u128(&required_string(value, &["consensus", "min_stake_nwei"])?)?
        != manifest.required_validator_stake_nwei
    {
        return Err(
            "Genesis minimum validator stake disagrees with finalized consensus parameters"
                .to_string(),
        );
    }
    let timeout_keys = required(value, &["consensus", "timeouts"])?
        .as_object()
        .ok_or_else(|| "consensus.timeouts is not an object".to_string())?
        .keys()
        .map(String::as_str)
        .collect::<std::collections::BTreeSet<_>>();
    let canonical_timeout_keys = ["max_round_ms", "precommit_ms", "prevote_ms", "proposal_ms"]
        .into_iter()
        .collect::<std::collections::BTreeSet<_>>();
    if timeout_keys != canonical_timeout_keys {
        return Err(
            "Genesis consensus.timeouts contains legacy or missing competing timeout fields"
                .to_string(),
        );
    }
    for validator in required_array(value, &["validators"])? {
        if required_string(validator, &["consensus_key_type"])?
            .to_ascii_lowercase()
            .replace('-', "")
            != manifest.consensus_signature_algorithm
        {
            return Err(
                "Genesis validator consensus key algorithm disagrees with finalized consensus parameters"
                    .to_string(),
            );
        }
    }
    Ok(Some(loaded))
}

fn validate_coordinated_p1_genesis_parameters(
    value: &Value,
    manifest: &crate::consensus_parameters::CoordinatedRoundRobinParameterManifest,
) -> Result<(), String> {
    let consensus = required(value, &["consensus"])?
        .as_object()
        .ok_or_else(|| "Genesis consensus is not an object".to_string())?;
    let expected_keys = [
        "algorithm",
        "coordinator_id",
        "mode",
        "producer_ids",
        "producer_turn_timeout_ms",
        "state_directory_namespace",
        "state_schema_version",
        "target_block_time_ms",
    ]
    .into_iter()
    .collect::<std::collections::BTreeSet<_>>();
    let actual_keys = consensus
        .keys()
        .map(String::as_str)
        .collect::<std::collections::BTreeSet<_>>();
    if actual_keys != expected_keys {
        return Err(
            "coordinated P1 Genesis consensus contains legacy PoSy or missing P1 parameters"
                .to_string(),
        );
    }
    if required_string(value, &["consensus", "algorithm"])? != manifest.protocol_version
        || required_string(value, &["consensus", "mode"])? != manifest.protocol_version
        || required_u64(value, &["consensus", "target_block_time_ms"])?
            != manifest.target_block_time_ms
        || required_string(value, &["consensus", "coordinator_id"])?
            != manifest.coordinated_round_robin.coordinator_id
        || required_u64(value, &["consensus", "producer_turn_timeout_ms"])?
            != manifest.coordinated_round_robin.producer_turn_timeout_ms
    {
        return Err(
            "Genesis coordinated P1 parameters disagree with the finalized parameter binding"
                .to_string(),
        );
    }
    let producers = required_array(value, &["consensus", "producer_ids"])?
        .iter()
        .map(|entry| {
            entry
                .as_str()
                .map(str::to_string)
                .ok_or_else(|| "Genesis coordinated P1 producer ID is not a string".to_string())
        })
        .collect::<Result<Vec<_>, _>>()?;
    if producers != manifest.coordinated_round_robin.producer_ids {
        return Err(
            "Genesis coordinated P1 producer ordering disagrees with the finalized parameter binding"
                .to_string(),
        );
    }
    for validator in required_array(value, &["validators"])? {
        if required_string(validator, &["consensus_key_type"])?
            .to_ascii_lowercase()
            .replace('-', "")
            != manifest.consensus_signature_algorithm
        {
            return Err(
                "Genesis validator consensus key algorithm disagrees with finalized coordinated P1 parameters"
                    .to_string(),
            );
        }
    }
    Ok(())
}

/// Validates the narrow consensus object for a new block-zero simplified
/// PoSy chain.  All security-sensitive membership, quorum, and lease inputs
/// are carried by the finalized manifest plus the Genesis-bound activation;
/// a node-local configuration cannot add a coordinator, producer ring, or
/// compatibility field to this authority.
fn validate_simplified_v3_genesis_parameters(
    value: &Value,
    manifest: &crate::posy_simplified_parameters::SimplifiedConsensusParameterManifest,
) -> Result<(), String> {
    use crate::consensus::simplified_posy::POSY_SIMPLIFIED_PROTOCOL_VERSION;

    manifest.require_activatable()?;
    let consensus = required(value, &["consensus"])?
        .as_object()
        .ok_or_else(|| "Genesis consensus is not an object".to_string())?;
    let expected_keys = [
        "algorithm",
        "epoch",
        "initial_active_validator_count",
        "leader_lease_blocks",
        "min_validator_count",
        "minimum_distinct_signers",
        "mode",
        "posy_v3_activation",
        "runtime_versions",
        "state_directory_namespace",
        "state_schema_version",
        "target_block_time_ms",
        "timeouts",
    ]
    .into_iter()
    .collect::<std::collections::BTreeSet<_>>();
    let actual_keys = consensus
        .keys()
        .map(String::as_str)
        .collect::<std::collections::BTreeSet<_>>();
    if actual_keys != expected_keys {
        return Err(
            "fresh simplified Genesis consensus contains unknown, legacy, or missing fields"
                .to_string(),
        );
    }
    if required_string(value, &["consensus", "algorithm"])? != POSY_SIMPLIFIED_PROTOCOL_VERSION
        || required_string(value, &["consensus", "mode"])? != "posy_simplified_v3"
        || required_u64(value, &["consensus", "epoch", "length_blocks"])?
            != manifest.epoch_length_blocks
        || required_u64(value, &["consensus", "target_block_time_ms"])?
            != manifest.target_block_time_ms
        || required_u64(value, &["consensus", "initial_active_validator_count"])?
            != manifest.active_validator_count
        || required_u64(value, &["consensus", "min_validator_count"])?
            != manifest.active_validator_count
        || required_u64(value, &["consensus", "minimum_distinct_signers"])?
            != manifest.required_distinct_signers
        || required_u64(value, &["consensus", "leader_lease_blocks"])?
            != manifest.leader_lease_blocks
    {
        return Err(
            "fresh simplified Genesis consensus disagrees with its finalized manifest".to_string(),
        );
    }
    simplified_genesis_runtime_metadata(value)?;
    let timeouts = required(value, &["consensus", "timeouts"])?
        .as_object()
        .ok_or_else(|| "fresh simplified Genesis timeouts is not an object".to_string())?;
    let expected_timeout_keys = ["max_round_ms", "proposal_ms", "vote_ms"]
        .into_iter()
        .collect::<std::collections::BTreeSet<_>>();
    if timeouts
        .keys()
        .map(String::as_str)
        .collect::<std::collections::BTreeSet<_>>()
        != expected_timeout_keys
        || required_u64(value, &["consensus", "timeouts", "proposal_ms"])?
            != manifest.proposal_timeout_ms
        || required_u64(value, &["consensus", "timeouts", "vote_ms"])? != manifest.vote_timeout_ms
        || required_u64(value, &["consensus", "timeouts", "max_round_ms"])?
            != manifest.max_round_timeout_ms
    {
        return Err(
            "fresh simplified Genesis timeouts disagree with its finalized manifest".to_string(),
        );
    }

    let activation =
        crate::consensus::simplified_posy::load_genesis_bound_simplified_activation(value)?
            .ok_or_else(|| "fresh simplified Genesis has no activation binding".to_string())?;
    let manifest_root = manifest.root()?;
    if activation.manifest != *manifest
        || activation.parameter_root_sha3_512 != manifest_root.to_hex()
        || activation.frozen_validator_set.validators.len()
            != usize::try_from(manifest.active_validator_count)
                .map_err(|_| "fresh simplified validator count exceeds usize".to_string())?
    {
        return Err(
            "fresh simplified Genesis activation does not bind the finalized five-validator authority"
                .to_string(),
        );
    }
    load_genesis_bound_etdag_governance(value)?;
    load_genesis_bound_etdag_membership_anchor(value)?;
    Ok(())
}

/// Loads the block-one runtime versions from fresh PoSy Genesis.  A node must
/// not obtain them from a legacy block header, local TOML, or a build-time
/// default because those values are part of the signed Genesis authority.
pub fn simplified_genesis_runtime_metadata(
    value: &Value,
) -> Result<SimplifiedGenesisRuntimeMetadata, String> {
    if required_string(value, &["network", "consensus_version"])?
        != crate::consensus::simplified_posy::POSY_SIMPLIFIED_PROTOCOL_VERSION
    {
        return Err("simplified runtime metadata is only valid for fresh PoSy v3 Genesis".into());
    }
    let versions = required(value, &["consensus", "runtime_versions"])?
        .as_object()
        .ok_or_else(|| "fresh simplified Genesis runtime_versions is not an object".to_string())?;
    let expected_keys = [
        "aegis_pqvm_version",
        "app_version",
        "dag_version",
        "execution_version",
    ]
    .into_iter()
    .collect::<std::collections::BTreeSet<_>>();
    if versions
        .keys()
        .map(String::as_str)
        .collect::<std::collections::BTreeSet<_>>()
        != expected_keys
    {
        return Err(
            "fresh simplified Genesis runtime_versions has unknown, legacy, or missing fields"
                .to_string(),
        );
    }
    let app_version = u32::try_from(required_u64(
        value,
        &["consensus", "runtime_versions", "app_version"],
    )?)
    .map_err(|_| "fresh simplified Genesis app_version exceeds u32".to_string())?;
    let execution_version = u32::try_from(required_u64(
        value,
        &["consensus", "runtime_versions", "execution_version"],
    )?)
    .map_err(|_| "fresh simplified Genesis execution_version exceeds u32".to_string())?;
    let dag_version = u32::try_from(required_u64(
        value,
        &["consensus", "runtime_versions", "dag_version"],
    )?)
    .map_err(|_| "fresh simplified Genesis dag_version exceeds u32".to_string())?;
    let aegis_pqvm_version = required_string(
        value,
        &["consensus", "runtime_versions", "aegis_pqvm_version"],
    )?;
    if app_version != 1
        || execution_version != 1
        || dag_version != 3
        || aegis_pqvm_version != "aegis-pqvm-v3"
    {
        return Err(
            "fresh simplified Genesis runtime_versions do not match the P3 runtime profile"
                .to_string(),
        );
    }
    Ok(SimplifiedGenesisRuntimeMetadata {
        app_version,
        execution_version,
        dag_version,
        aegis_pqvm_version,
    })
}

/// Loads ETDAG's separately governed parameter and fee artifacts from a
/// fresh PoSy Genesis.  The parent Genesis release approval signs the entire
/// candidate, including this exact binding.  Nodes still recompute both
/// SHA3-512 roots locally so a root copied into a Wallet or RPC response
/// cannot silently drift from its canonical policy payload.
pub fn load_genesis_bound_etdag_governance(
    value: &Value,
) -> Result<EtdagGovernedGenesisBinding, String> {
    if required_string(value, &["network", "consensus_version"])?
        != crate::consensus::simplified_posy::POSY_SIMPLIFIED_PROTOCOL_VERSION
    {
        return Err("ETDAG governed binding is only valid for fresh PoSy v3 Genesis".to_string());
    }
    let raw = required(value, &["etdag_governance"])?;
    let binding: EtdagGovernedGenesisBinding = serde_json::from_value(raw.clone())
        .map_err(|error| format!("parse Genesis ETDAG governed binding: {error}"))?;
    binding.validate()?;
    let hash_inputs = required_array(value, &["canonicalization", "genesis_hash_inputs"])?;
    if !hash_inputs
        .iter()
        .any(|entry| entry.as_str() == Some("etdag_governance"))
    {
        return Err(
            "ETDAG governed binding is not covered by the canonical Genesis hash".to_string(),
        );
    }
    if required_string(value, &["integrity", "etdag_parameter_root_sha3_512"])?
        != binding
            .parameter_artifact
            .etdag_parameter_root_sha3_512
            .to_hex()
        || required_string(value, &["integrity", "etdag_fee_schedule_root_sha3_512"])?
            != binding
                .fee_schedule_artifact
                .etdag_fee_schedule_root_sha3_512
                .to_hex()
    {
        return Err("Genesis ETDAG integrity roots disagree with governed artifacts".to_string());
    }
    Ok(binding)
}

fn validate_testnet_v3_candidate_integrity_hashes(value: &Value) -> Result<(), String> {
    load_candidate_consensus_parameters(value)?;
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
    let mut state_components = serde_json::Map::new();
    for key in [
        "accounts",
        "balances",
        "allocations",
        "contracts",
        "consensus",
        "governance",
        "modules",
        "network",
        "security",
        "synergy_state",
        "token",
        "validators",
    ] {
        state_components.insert(key.to_string(), required(value, &[key])?.clone());
    }
    if let Some(deployment) = value.get("genesis_deployment") {
        state_components.insert(
            "execution".to_string(),
            required(value, &["execution"])?.clone(),
        );
        state_components.insert("genesis_deployment".to_string(), deployment.clone());
    }
    if let Some(migration) = value.get("contract_address_migration") {
        state_components.insert("contract_address_migration".to_string(), migration.clone());
    }
    if let Some(parameters) = value.get("consensus_parameters") {
        state_components.insert("consensus_parameters".to_string(), parameters.clone());
    }
    if let Some(etdag_governance) = value.get("etdag_governance") {
        state_components.insert("etdag_governance".to_string(), etdag_governance.clone());
    }
    let state_root = hash_json(&Value::Object(state_components));
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
    let expected_receipts_root = value
        .get("genesis_deployment")
        .and_then(|deployment| deployment.get("receipt_root"))
        .and_then(Value::as_str)
        .unwrap_or(&empty_hash);
    compare_hash(
        value,
        &["header", "receipts_root"],
        expected_receipts_root,
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
    let caip2 = required_string(value, &["network_identity", "canonical_caip2", "value"])?;
    let network_magic_bytes = network_magic_bytes_for(&caip2, &expected_genesis_hash);
    compare_hash(
        value,
        &["network_magic_bytes", "value"],
        &network_magic_bytes,
        "network_magic_bytes.value",
    )?;
    Ok(())
}

/// Recomputes every derived integrity value for the Testnet-v3 candidate
/// schema in dependency order.
///
/// The pre-deployment candidate has no `genesis_deployment` block and retains
/// the empty receipt root. A finalized candidate must bind its ceremony block
/// into both the state root and the genesis hash, and its combined deployment
/// receipt root becomes the header receipt root.
pub fn recompute_testnet_v3_candidate_integrity(value: &mut Value) -> Result<(), String> {
    if !is_testnet_v3_candidate_schema(value) {
        return Err("not a canonical Testnet-v3 candidate schema".to_string());
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
    // The validator-set digest is part of the contracts payload.  Update it
    // before deriving any root that includes that payload; qualification
    // replaces the six public consensus keys with disposable ones.
    value["contracts"]["validator_registry"]["init_params"]["validator_set_hash"] =
        Value::String(validator_set_hash.clone());
    let contract_hash = hash_json(required(value, &["contracts"])?);

    let mut state_components = serde_json::Map::new();
    for key in [
        "accounts",
        "balances",
        "allocations",
        "contracts",
        "consensus",
        "governance",
        "modules",
        "network",
        "security",
        "synergy_state",
        "token",
        "validators",
    ] {
        state_components.insert(key.to_string(), required(value, &[key])?.clone());
    }
    if let Some(deployment) = value.get("genesis_deployment") {
        state_components.insert(
            "execution".to_string(),
            required(value, &["execution"])?.clone(),
        );
        state_components.insert("genesis_deployment".to_string(), deployment.clone());
    }
    if let Some(migration) = value.get("contract_address_migration") {
        state_components.insert("contract_address_migration".to_string(), migration.clone());
    }
    if let Some(parameters) = value.get("consensus_parameters") {
        state_components.insert("consensus_parameters".to_string(), parameters.clone());
    }
    if let Some(etdag_governance) = value.get("etdag_governance") {
        state_components.insert("etdag_governance".to_string(), etdag_governance.clone());
    }
    let state_root = hash_json(&Value::Object(state_components));
    let data_root = hash_json(&json!({
        "contracts": required(value, &["contracts"] )?,
        "modules": required(value, &["modules"] )?,
        "precompiles": required(value, &["precompiles"] )?,
    }));
    let receipts_root = value
        .get("genesis_deployment")
        .and_then(|deployment| deployment.get("receipt_root"))
        .and_then(Value::as_str)
        .unwrap_or(&empty_hash)
        .to_string();

    value["header"]["parent_hash"] = Value::String(ZERO_HASH.to_string());
    value["header"]["transactions_root"] = Value::String(empty_hash);
    value["header"]["receipts_root"] = Value::String(receipts_root.clone());
    value["header"]["state_root"] = Value::String(state_root.clone());
    value["header"]["data_root"] = Value::String(data_root);
    value["integrity"]["allocation_hash"] = Value::String(allocation_hash);
    value["integrity"]["validator_hash"] = Value::String(validator_hash);
    value["integrity"]["validator_set_hash"] = Value::String(validator_set_hash);
    value["integrity"]["contract_hash"] = Value::String(contract_hash);
    value["integrity"]["state_root"] = Value::String(state_root);
    if value.get("genesis_deployment").is_some() {
        value["integrity"]["receipt_root"] = Value::String(receipts_root);
    }

    // The header roots above are inputs to the final Genesis hash.
    let genesis_hash = hash_json(&genesis_hash_payload(value));
    value["integrity"]["genesis_hash"] = Value::String(genesis_hash.clone());
    let caip2 = required_string(value, &["network_identity", "canonical_caip2", "value"])?;
    value["network_magic_bytes"]["value"] =
        Value::String(network_magic_bytes_for(&caip2, &genesis_hash));

    validate_testnet_v3_candidate_integrity_hashes(value)
}

/// Installs one finalized manifest into a pre-deployment or deployment-bound
/// Testnet-v3 Genesis document and atomically recomputes all dependent roots.
///
/// Release tools must separately verify that `release_decision_sha256`
/// identifies the operator-approved decision record. The runtime then binds
/// that digest, the exact manifest SHA-256, and its SHA3-512 parameter root
/// into Genesis.
pub fn bind_testnet_v3_genesis_consensus_parameters(
    value: &mut Value,
    loaded: &LoadedConsensusParameters,
    release_decision_sha256: &str,
) -> Result<(), String> {
    bind_testnet_v3_genesis_consensus_parameters_inner(
        value,
        loaded,
        release_decision_sha256,
        None,
        None,
    )
}

/// Atomically binds the fresh simplified PoSy consensus manifest and the
/// separately governed ETDAG parameter/fee artifacts into one Genesis
/// candidate.  P3 deliberately has no intermediate, valid "consensus-only"
/// document: both authorities are hash inputs before any integrity root is
/// recomputed.
pub fn bind_testnet_v3_genesis_simplified_posy_authorities(
    value: &mut Value,
    loaded: &LoadedConsensusParameters,
    release_decision_sha256: &str,
    activation: &crate::consensus::simplified_posy::GenesisBoundSimplifiedActivation,
    etdag_binding: &EtdagGovernedGenesisBinding,
) -> Result<(), String> {
    let manifest =
        match &loaded.manifest {
            crate::consensus_parameters::FinalizedConsensusParameterManifest::SimplifiedPoSyV3(
                manifest,
            ) => manifest,
            _ => return Err(
                "fresh simplified PoSy authority binding requires a simplified PoSy v3 manifest"
                    .to_string(),
            ),
        };
    activation.validate()?;
    if activation.manifest != *manifest
        || activation.parameter_root_sha3_512 != loaded.root.to_hex()
        || activation.governance_decision_id != manifest.finalized_governance_approval_id()?
    {
        return Err(
            "fresh simplified PoSy activation does not exactly match the finalized consensus manifest"
                .to_string(),
        );
    }
    bind_testnet_v3_genesis_consensus_parameters_inner(
        value,
        loaded,
        release_decision_sha256,
        Some(etdag_binding),
        Some(activation),
    )
}

fn bind_testnet_v3_genesis_consensus_parameters_inner(
    value: &mut Value,
    loaded: &LoadedConsensusParameters,
    release_decision_sha256: &str,
    etdag_binding: Option<&EtdagGovernedGenesisBinding>,
    simplified_activation: Option<
        &crate::consensus::simplified_posy::GenesisBoundSimplifiedActivation,
    >,
) -> Result<(), String> {
    if !is_testnet_v3_candidate_schema(value) {
        return Err("not a canonical Testnet-v3 candidate schema".to_string());
    }
    if release_decision_sha256.len() != 64
        || !release_decision_sha256
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("release decision SHA-256 must be canonical lowercase hex".to_string());
    }
    let manifest = &loaded.manifest;
    manifest.validate_finalized()?;
    match manifest {
        crate::consensus_parameters::FinalizedConsensusParameterManifest::PosyV2_2(manifest) => {
            value["consensus"]["epoch"]["length_blocks"] = json!(manifest
                .epoch_length_slots
                .ok_or_else(|| "finalized epoch length is missing".to_string())?);
            value["consensus"]["target_block_time_ms"] = json!(manifest.target_block_time_ms);
            value["consensus"]["cluster_schedule_version"] =
                Value::String(manifest.cluster_schedule_version.clone());
            value["consensus"]["initial_active_validator_count"] =
                json!(manifest.initial_cluster_validator_count);
            value["consensus"]["min_validator_count"] = json!(manifest.initial_cluster_validator_count);
            value["consensus"]["min_quorum_threshold"] = json!(manifest.initial_availability_quorum);
            value["consensus"]["min_stake_nwei"] =
                Value::String(manifest.required_validator_stake_nwei.to_string());
            value["consensus"]["timeouts"] = json!({
                "proposal_ms": manifest.proposal_timeout_ms,
                "prevote_ms": manifest.prevote_timeout_ms,
                "precommit_ms": manifest.precommit_timeout_ms,
                "max_round_ms": manifest.max_round_timeout_ms,
            });
        }
        crate::consensus_parameters::FinalizedConsensusParameterManifest::CoordinatedRoundRobinV1(
            manifest,
        ) => {
            let state_directory_namespace =
                required_string(value, &["consensus", "state_directory_namespace"])?;
            let state_schema_version = required_u64(value, &["consensus", "state_schema_version"])?;
            value["network"]["consensus_version"] = Value::String(manifest.protocol_version.clone());
            value["consensus"] = json!({
                "algorithm": manifest.protocol_version,
                "mode": manifest.protocol_version,
                "target_block_time_ms": manifest.target_block_time_ms,
                "coordinator_id": manifest.coordinated_round_robin.coordinator_id,
                "producer_ids": manifest.coordinated_round_robin.producer_ids,
                "producer_turn_timeout_ms": manifest.coordinated_round_robin.producer_turn_timeout_ms,
                "state_directory_namespace": state_directory_namespace,
                "state_schema_version": state_schema_version,
            });
        }
        crate::consensus_parameters::FinalizedConsensusParameterManifest::SimplifiedPoSyV3(
            manifest,
        ) => {
            let etdag_binding = etdag_binding.ok_or_else(|| {
                "fresh simplified PoSy Genesis requires atomic ETDAG authority binding"
                    .to_string()
            })?;
            let activation = simplified_activation.ok_or_else(|| {
                "fresh simplified PoSy Genesis requires the finalized five-validator activation binding"
                    .to_string()
            })?;
            etdag_binding.validate()?;
            activation.validate()?;
            if activation.manifest != *manifest
                || activation.parameter_root_sha3_512 != loaded.root.to_hex()
                || activation.governance_decision_id
                    != manifest.finalized_governance_approval_id()?
            {
                return Err(
                    "fresh simplified PoSy activation does not exactly match the finalized consensus manifest"
                        .to_string(),
                );
            }
            let parameter_manifest = &etdag_binding.parameter_artifact.manifest;
            if parameter_manifest.chain_id != manifest.chain_id
                || parameter_manifest.network_id != manifest.network_id
                || parameter_manifest.consensus_protocol_version != manifest.protocol_version
            {
                return Err(
                    "ETDAG authority binding does not match the simplified PoSy manifest identity"
                        .to_string(),
                );
            }
            value["network"]["network_slug"] = Value::String(manifest.network_id.0.clone());
            value["network"]["chain_incarnation"] = json!(
                crate::posy_simplified_parameters::POSY_SIMPLIFIED_CHAIN_INCARNATION
            );
            value["network"]["consensus_version"] = Value::String(manifest.protocol_version.clone());
            value["consensus"] = json!({
                "algorithm": manifest.protocol_version,
                "mode": "posy_simplified_v3",
                "state_directory_namespace": format!(
                    "chain-{}/incarnation-{}",
                    manifest.chain_id.0,
                    crate::posy_simplified_parameters::POSY_SIMPLIFIED_CHAIN_INCARNATION,
                ),
                "state_schema_version": crate::posy_simplified_parameters::POSY_SIMPLIFIED_CONSENSUS_STATE_SCHEMA_VERSION,
                "epoch": { "length_blocks": manifest.epoch_length_blocks },
                "target_block_time_ms": manifest.target_block_time_ms,
                "initial_active_validator_count": manifest.active_validator_count,
                "min_validator_count": manifest.active_validator_count,
                "minimum_distinct_signers": manifest.required_distinct_signers,
                "leader_lease_blocks": manifest.leader_lease_blocks,
                "runtime_versions": {
                    "app_version": 1,
                    "execution_version": 1,
                    "dag_version": 3,
                    "aegis_pqvm_version": "aegis-pqvm-v3",
                },
                "timeouts": {
                    "proposal_ms": manifest.proposal_timeout_ms,
                    "vote_ms": manifest.vote_timeout_ms,
                    "max_round_ms": manifest.max_round_timeout_ms,
                },
                "posy_v3_activation": activation,
            });
        }
    }

    let canonical_manifest_sha256 = hex::encode(sha2::Sha256::digest(&loaded.canonical_bytes));
    let root = loaded.root.to_hex();
    let decision_id = manifest.governance_approval_id()?.to_string();
    value["consensus_parameters"] = json!({
        "schema_version": CONSENSUS_PARAMETER_GENESIS_BINDING_SCHEMA_VERSION,
        "status": CONSENSUS_PARAMETER_GENESIS_BINDING_STATUS,
        "decision_id": decision_id,
        "release_decision_sha256": release_decision_sha256,
        "canonical_manifest_sha256": canonical_manifest_sha256,
        "parameter_root_sha3_512": root,
        "manifest": manifest,
    });
    value["integrity"]["consensus_parameter_root_sha3_512"] = Value::String(loaded.root.to_hex());
    value["integrity"]["consensus_parameter_manifest_sha256"] =
        Value::String(canonical_manifest_sha256);
    value["integrity"]["consensus_parameter_decision_id"] =
        Value::String(manifest.governance_approval_id()?.to_string());

    {
        let hash_inputs = value["canonicalization"]["genesis_hash_inputs"]
            .as_array_mut()
            .ok_or_else(|| "canonicalization.genesis_hash_inputs is not an array".to_string())?;
        if !hash_inputs
            .iter()
            .any(|entry| entry.as_str() == Some("consensus_parameters"))
        {
            hash_inputs.push(Value::String("consensus_parameters".to_string()));
        }
    }
    if let Some(etdag_binding) = etdag_binding {
        value["etdag_governance"] = serde_json::to_value(etdag_binding)
            .map_err(|error| format!("serialize Genesis ETDAG governance binding: {error}"))?;
        value["integrity"]["etdag_parameter_root_sha3_512"] = Value::String(
            etdag_binding
                .parameter_artifact
                .etdag_parameter_root_sha3_512
                .to_hex(),
        );
        value["integrity"]["etdag_fee_schedule_root_sha3_512"] = Value::String(
            etdag_binding
                .fee_schedule_artifact
                .etdag_fee_schedule_root_sha3_512
                .to_hex(),
        );
        let hash_inputs = value["canonicalization"]["genesis_hash_inputs"]
            .as_array_mut()
            .ok_or_else(|| "canonicalization.genesis_hash_inputs is not an array".to_string())?;
        if !hash_inputs
            .iter()
            .any(|entry| entry.as_str() == Some("etdag_governance"))
        {
            hash_inputs.push(Value::String("etdag_governance".to_string()));
        }
    }
    if value.get("genesis_deployment").is_none() {
        value["schema_version"] = Value::String("v1.5-parameter-bound".to_string());
        value["network"]["genesis_schema_version"] = Value::String("v1.5".to_string());
        value["network"]["status"] =
            Value::String("consensus_parameters_bound_pending_contract_deployment".to_string());
        value["integrity"]["status"] =
            Value::String("candidate_parameter_bound_pending_deployment".to_string());
        value["testnet_v3_initialization"]["finalization_status"] =
            Value::String("consensus_parameters_bound_pending_contract_deployment".to_string());
    }
    recompute_testnet_v3_candidate_integrity(value)
}

/// Compatibility guard for the former sequential ETDAG binding API.
///
/// Fresh P3 candidates must use
/// [`bind_testnet_v3_genesis_simplified_posy_authorities`], which prevents a
/// partially authorized candidate from being recomputed or published.
pub fn bind_testnet_v3_genesis_etdag_governance(
    value: &mut Value,
    binding: &EtdagGovernedGenesisBinding,
) -> Result<(), String> {
    let _ = (value, binding);
    Err(
        "fresh simplified PoSy Genesis must bind consensus and ETDAG authorities atomically"
            .to_string(),
    )
}

/// Attaches the post-Genesis public ETDAG membership anchor to a fully staged
/// fresh-P3 release candidate.  The anchor is intentionally excluded from
/// the Genesis hash because it contains that finalized hash; the subsequent
/// V4 governance approval signs the anchor digest along with the exact
/// candidate, preventing a circular signature dependency.
pub fn bind_testnet_v3_genesis_etdag_membership_anchor(
    value: &mut Value,
    anchor: &EtdagGovernedMembershipAnchor,
) -> Result<(), String> {
    if !is_testnet_v3_candidate_schema(value) {
        return Err("not a canonical Testnet-v3 candidate schema".to_string());
    }
    if required_string(value, &["network", "consensus_version"])?
        != crate::consensus::simplified_posy::POSY_SIMPLIFIED_PROTOCOL_VERSION
    {
        return Err("ETDAG membership anchor may only be bound to fresh PoSy v3 Genesis".into());
    }
    anchor.validate()?;
    let binding = load_genesis_bound_etdag_governance(value)?;
    let activation =
        crate::consensus::simplified_posy::load_genesis_bound_simplified_activation(value)?
            .ok_or_else(|| "fresh PoSy Genesis has no activation binding".to_string())?;
    let activation_bytes = serde_json::to_vec(&activation)
        .map_err(|error| format!("serialize Genesis activation for ETDAG anchor: {error}"))?;
    let expected_activation_digest =
        crate::etdag_governance::EtdagGovernedRoot::from_canonical_manifest_bytes(
            &activation_bytes,
        );
    if binding.parameter_artifact.manifest.chain_id != activation.manifest.chain_id
        || binding.parameter_artifact.manifest.network_id != activation.manifest.network_id
        || binding
            .parameter_artifact
            .manifest
            .consensus_protocol_version
            != activation.manifest.protocol_version
    {
        return Err(
            "ETDAG governed binding and Genesis activation have inconsistent P3 identities"
                .to_string(),
        );
    }
    if anchor.governance_decision_id != binding.parameter_artifact.manifest.governance_decision_id {
        return Err(
            "ETDAG membership anchor must use the same governance decision as the parameter and fee artifacts"
                .to_string(),
        );
    }
    if anchor.genesis_hash != required_string(value, &["integrity", "genesis_hash"])?
        || anchor.deployed_execution_state_root
            != required_string(
                value,
                &["genesis_deployment", "post_deployment_execution_state_root"],
            )?
        || anchor.initial_consensus_parameter_root.to_hex() != activation.parameter_root_sha3_512
        || anchor.genesis_activation_binding_digest != expected_activation_digest
    {
        return Err(
            "ETDAG membership anchor does not match the staged Genesis activation or execution state"
                .to_string(),
        );
    }
    let expected_validators = activation
        .frozen_validator_set
        .active_for_epoch(crate::synergy_types::Epoch(0))
        .validators
        .into_iter()
        .map(|validator| {
            (
                validator.validator_id.0,
                validator.consensus_public_key.key_id.0,
                validator.consensus_public_key.algorithm,
                validator.consensus_public_key.key_bytes,
                validator.voting_weight,
            )
        })
        .collect::<Vec<_>>();
    let actual_validators = anchor
        .initial_validator_set
        .validators
        .iter()
        .map(|validator| {
            (
                validator.validator_id.clone(),
                validator.consensus_public_key.key_id.clone(),
                validator.consensus_public_key.algorithm.clone(),
                validator.consensus_public_key.key_bytes.clone(),
                validator.voting_weight,
            )
        })
        .collect::<Vec<_>>();
    if actual_validators != expected_validators {
        return Err(
            "ETDAG membership anchor validator set does not equal the Genesis-frozen activation set"
                .to_string(),
        );
    }
    let hash_inputs = value["canonicalization"]["genesis_hash_inputs"]
        .as_array()
        .ok_or_else(|| "canonicalization.genesis_hash_inputs is not an array".to_string())?;
    if hash_inputs
        .iter()
        .any(|entry| entry.as_str() == Some("etdag_membership_anchor"))
    {
        return Err(
            "ETDAG membership anchor cannot be a Genesis hash input because it binds Genesis"
                .to_string(),
        );
    }
    let excluded = value["canonicalization"]["excluded_from_genesis_hash"]
        .as_array_mut()
        .ok_or_else(|| "canonicalization.excluded_from_genesis_hash is not an array".to_string())?;
    if !excluded
        .iter()
        .any(|entry| entry.as_str() == Some("etdag_membership_anchor"))
    {
        excluded.push(Value::String("etdag_membership_anchor".to_string()));
    }
    value["etdag_membership_anchor"] = serde_json::to_value(anchor)
        .map_err(|error| format!("serialize ETDAG membership anchor: {error}"))?;
    Ok(())
}

/// Validates the optional post-Genesis ETDAG membership anchor carried by a
/// fresh P3 candidate.  Pre-anchor candidates are intentionally accepted by
/// the public-input builder so their finalized Genesis hash can be used to
/// derive the anchor.  Once present, however, the anchor must be exactly the
/// one that [`bind_testnet_v3_genesis_etdag_membership_anchor`] would attach
/// to the same candidate; runtime loading never treats it as display-only
/// metadata.
pub fn load_genesis_bound_etdag_membership_anchor(
    value: &Value,
) -> Result<Option<EtdagGovernedMembershipAnchor>, String> {
    let Some(raw_anchor) = value.get("etdag_membership_anchor").cloned() else {
        return Ok(None);
    };
    let anchor: EtdagGovernedMembershipAnchor = serde_json::from_value(raw_anchor.clone())
        .map_err(|error| format!("parse Genesis ETDAG membership anchor: {error}"))?;
    anchor.validate()?;

    // Reuse the authoritative binding checks on a copy with the post-Genesis
    // field removed.  The exclusion itself is also removed first so the
    // binder must reconstruct it, rather than accepting a stale marker.
    let mut pre_anchor_candidate = value.clone();
    pre_anchor_candidate
        .as_object_mut()
        .ok_or_else(|| "Genesis candidate is not a JSON object".to_string())?
        .remove("etdag_membership_anchor");
    let excluded = pre_anchor_candidate["canonicalization"]["excluded_from_genesis_hash"]
        .as_array_mut()
        .ok_or_else(|| {
            "candidate canonicalization.excluded_from_genesis_hash is not an array".to_string()
        })?;
    excluded.retain(|entry| entry.as_str() != Some("etdag_membership_anchor"));
    bind_testnet_v3_genesis_etdag_membership_anchor(&mut pre_anchor_candidate, &anchor)?;
    if pre_anchor_candidate.get("etdag_membership_anchor") != Some(&raw_anchor) {
        return Err(
            "Genesis ETDAG membership anchor is not the canonical activation-bound payload"
                .to_string(),
        );
    }
    Ok(Some(anchor))
}

/*
 * The former sequential implementation remains intentionally unavailable.
 * A P3 candidate with only a consensus binding, or only an ETDAG binding,
 * must never become an integrity-checked public artifact.  Keep the public
 * symbol as a fail-closed compatibility guard for callers that have not yet
 * migrated to `bind_testnet_v3_genesis_simplified_posy_authorities`.
 */
#[allow(dead_code)]
fn bind_testnet_v3_genesis_etdag_governance_sequentially_unavailable(
    value: &mut Value,
    binding: &EtdagGovernedGenesisBinding,
) -> Result<(), String> {
    if !is_testnet_v3_candidate_schema(value) {
        return Err("not a canonical Testnet-v3 candidate schema".to_string());
    }
    if required_string(value, &["network", "consensus_version"])?
        != crate::consensus::simplified_posy::POSY_SIMPLIFIED_PROTOCOL_VERSION
    {
        return Err("ETDAG governance may only be bound to fresh PoSy v3 Genesis".to_string());
    }
    binding.validate()?;
    value["etdag_governance"] = serde_json::to_value(binding)
        .map_err(|error| format!("serialize Genesis ETDAG governance binding: {error}"))?;
    value["integrity"]["etdag_parameter_root_sha3_512"] = Value::String(
        binding
            .parameter_artifact
            .etdag_parameter_root_sha3_512
            .to_hex(),
    );
    value["integrity"]["etdag_fee_schedule_root_sha3_512"] = Value::String(
        binding
            .fee_schedule_artifact
            .etdag_fee_schedule_root_sha3_512
            .to_hex(),
    );
    let hash_inputs = value["canonicalization"]["genesis_hash_inputs"]
        .as_array_mut()
        .ok_or_else(|| "canonicalization.genesis_hash_inputs is not an array".to_string())?;
    if !hash_inputs
        .iter()
        .any(|entry| entry.as_str() == Some("etdag_governance"))
    {
        hash_inputs.push(Value::String("etdag_governance".to_string()));
    }
    recompute_testnet_v3_candidate_integrity(value)
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
            if contains_unresolved_placeholder(entry) {
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

/// Returns true only for unresolved configuration placeholders, not for the
/// angle-bracket generic type syntax embedded in a verified SynQ ABI (for
/// example `map<address,u8>`).  Finalized Genesis embeds the executed SynQ
/// artifact snapshot, so a broad "contains `<` and `>`" check would reject a
/// valid, hash-bound production artifact before the snapshot verifier can run.
fn contains_unresolved_placeholder(entry: &str) -> bool {
    let trimmed = entry.trim();
    if trimmed.starts_with('<') && trimmed.ends_with('>') {
        return true;
    }

    let mut remainder = entry;
    while let Some(open) = remainder.find('<') {
        let token_start = open + 1;
        let Some(close_offset) = remainder[token_start..].find('>') else {
            break;
        };
        let token = &remainder[token_start..token_start + close_offset];
        let marker = token.to_ascii_lowercase();
        let explicit_placeholder = marker.contains("placeholder")
            || marker.contains("todo")
            || marker.contains("tbd")
            || marker.contains("replace")
            || marker.contains("insert");
        let symbolic_placeholder = !token.is_empty()
            && token.chars().all(|character| {
                character.is_ascii_uppercase()
                    || character.is_ascii_digit()
                    || matches!(character, '_' | '-' | '.' | ':')
            })
            && token
                .chars()
                .any(|character| character.is_ascii_uppercase());
        if explicit_placeholder || symbolic_placeholder {
            return true;
        }
        remainder = &remainder[token_start + close_offset + 1..];
    }
    false
}

/// A genesis document marked as a unit-test fixture must never be loadable by a
/// production node. Test builds are permitted to load it; release builds refuse.
fn reject_test_fixture_genesis(value: &Value, path: &std::path::Path) -> Result<(), String> {
    let marked = value
        .get("test_fixture")
        .and_then(|entry| entry.get("is_test_fixture"))
        .and_then(Value::as_bool)
        .unwrap_or(false)
        || value
            .get("launch_status")
            .and_then(Value::as_str)
            .map(|status| status.contains("TEST_FIXTURE"))
            .unwrap_or(false)
        || value
            .get("env")
            .and_then(Value::as_str)
            .map(|env| env.eq_ignore_ascii_case("test-fixture"))
            .unwrap_or(false);
    if !marked {
        return Ok(());
    }
    if cfg!(test) {
        return Ok(());
    }
    Err(format!(
        "refusing to load test-fixture genesis {} in a production runtime",
        path.display()
    ))
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

fn required_u64_or_derived_pre_p1_value(
    value: &Value,
    path: &[&str],
    derived_value: u64,
    allow_missing_pre_p1_value: bool,
) -> Result<u64, String> {
    match optional(value, path) {
        Some(entry) => entry
            .as_u64()
            .ok_or_else(|| format!("path {} is not a u64", path.join("."))),
        None if allow_missing_pre_p1_value => Ok(derived_value),
        None => Err(format!("missing path {}", path.join("."))),
    }
}

fn required_string_or_derived_pre_p1_value(
    value: &Value,
    path: &[&str],
    derived_value: &str,
    allow_missing_pre_p1_value: bool,
) -> Result<String, String> {
    match optional(value, path) {
        Some(entry) => entry
            .as_str()
            .map(str::to_string)
            .ok_or_else(|| format!("path {} is not a string", path.join("."))),
        None if allow_missing_pre_p1_value => Ok(derived_value.to_string()),
        None => Err(format!("missing path {}", path.join("."))),
    }
}

fn required_u64(value: &Value, path: &[&str]) -> Result<u64, String> {
    required(value, path)?
        .as_u64()
        .ok_or_else(|| format!("path {} is not a u64", path.join(".")))
}

fn optional<'a>(value: &'a Value, path: &[&str]) -> Option<&'a Value> {
    let mut current = value;
    for segment in path {
        current = current.get(*segment)?;
    }
    Some(current)
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
    use sha2::{Digest, Sha256};

    fn testnet_v3_candidate() -> Value {
        let mut candidate = fresh_posy_v3_test_fixture()
            .expect("fresh P3 test fixture source must bind public authorities");
        recompute_testnet_v3_candidate_integrity(&mut candidate)
            .expect("fresh P3 test fixture must recompute deterministically");
        candidate
    }

    #[test]
    fn fresh_p3_network_identity_maps_to_numeric_runtime_compatibility() {
        let value = json!({
            "network": {
                "chain_id": 1266,
                "network_id": "testnet",
                "release_id": "testnet-v3",
                "consensus_version": "posy/3.0",
            }
        });

        assert_eq!(
            parse_runtime_numeric_network_id(&value, 1266, true).unwrap(),
            1266
        );
    }

    #[test]
    fn fresh_p3_network_identity_rejects_noncanonical_fields() {
        let canonical = json!({
            "network": {
                "chain_id": 1266,
                "network_id": "testnet",
                "release_id": "testnet-v3",
                "consensus_version": "posy/3.0",
            }
        });

        let error = parse_runtime_numeric_network_id(&canonical, 1267, true).unwrap_err();
        assert!(error.contains("network.chain_id"));

        let mut wrong_network = canonical.clone();
        wrong_network["network"]["network_id"] = Value::String("synergy-testnet-v3".to_string());
        let error = parse_runtime_numeric_network_id(&wrong_network, 1266, true).unwrap_err();
        assert!(error.contains("network.network_id"));

        let mut wrong_release = canonical;
        wrong_release["network"]["release_id"] = Value::String("testnet-v4".to_string());
        let error = parse_runtime_numeric_network_id(&wrong_release, 1266, true).unwrap_err();
        assert!(error.contains("network.release_id"));
    }

    #[test]
    fn legacy_network_identity_retains_numeric_loader_contract() {
        let value = json!({ "network": { "network_id": 1266 } });
        assert_eq!(
            parse_runtime_numeric_network_id(&value, 1266, false).unwrap(),
            1266
        );
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
            Some(5)
        );
        assert_eq!(
            candidate["consensus"]["initial_cluster_count"].as_u64(),
            Some(1)
        );
        assert_eq!(
            candidate["consensus"]["min_validator_count"].as_u64(),
            Some(5)
        );
        assert_eq!(
            candidate["consensus"]["min_quorum_threshold"].as_u64(),
            Some(4)
        );
        let validators = candidate["validators"]
            .as_array()
            .expect("candidate validators must be an array");
        assert_eq!(validators.len(), 5);
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
    fn recomputation_rebinds_validator_set_before_contract_and_state_roots() {
        let mut candidate = testnet_v3_candidate();
        candidate["contracts"]["validator_registry"]["init_params"]["validators"][0]
            ["consensus_public_key"] = Value::String("ring2-disposable-consensus-key".to_string());

        recompute_testnet_v3_candidate_integrity(&mut candidate).unwrap();
        validate_integrity_hashes(&candidate).unwrap();
    }

    #[test]
    fn placeholder_validation_accepts_synq_generic_types_but_rejects_unresolved_values() {
        let verified_abi = json!({
            "type": "map<address,map<u256,bool>>",
            "state_schema": "[address]"
        });
        validate_no_placeholders(&verified_abi).unwrap();

        for unresolved in [
            "<validator-address>",
            "synv1<TESTNET_V3_VALIDATOR_01_ADDRESS>",
            "authority <PLACEHOLDER>",
            "key <replace-me>",
        ] {
            let error = validate_no_placeholders(&json!({ "value": unresolved })).unwrap_err();
            assert_eq!(error, "placeholder value found at $.value");
        }
    }

    #[test]
    fn runtime_loader_accepts_the_verified_testnet_v3_candidate_schema() {
        let candidate = testnet_v3_candidate();
        let expected_magic = candidate["network_magic_bytes"]["value"]
            .as_str()
            .expect("candidate network magic must be a string");
        let document = load_canonical_genesis_from_value(
            candidate,
            PathBuf::from("<fresh-p3-candidate-loader-test>"),
        )
        .unwrap();
        assert_eq!(document.chain_id(), 1266);
        assert_eq!(document.network_id(), 1266);
        assert_eq!(document.validators().len(), 5);
        assert_eq!(document.network_magic_bytes(), expected_magic);
    }

    #[test]
    fn runtime_loader_accepts_only_the_fresh_p3_domain() {
        let candidate = testnet_v3_candidate();
        let document = load_canonical_genesis_from_value(
            candidate,
            PathBuf::from("<fresh-p3-domain-test-genesis>"),
        )
        .expect("the fresh P3 Genesis must load");
        assert_eq!(
            document.chain_incarnation(),
            TESTNET_V3_FRESH_P3_CHAIN_INCARNATION
        );
        assert_eq!(document.consensus_state_schema_version(), 5);
        assert_eq!(document.consensus_version(), "posy/3.0");
    }

    #[test]
    fn fresh_p3_manifest_binding_is_root_bound() {
        let parameters = load_candidate_consensus_parameters(&testnet_v3_candidate())
            .unwrap()
            .expect("fresh P3 candidate must carry finalized consensus parameters");
        let mut candidate = testnet_v3_candidate();

        assert_eq!(
            candidate["consensus"]["epoch"]["length_blocks"].as_u64(),
            Some(1_000)
        );
        assert_eq!(
            candidate["consensus"]["timeouts"],
            json!({
                "proposal_ms": 1_500,
                "vote_ms": 1_500,
                "max_round_ms": 10_000,
            })
        );
        let expected_root = parameters.root.to_hex();
        assert_eq!(
            candidate["consensus_parameters"]["parameter_root_sha3_512"].as_str(),
            Some(expected_root.as_str())
        );
        assert!(candidate["canonicalization"]["genesis_hash_inputs"]
            .as_array()
            .unwrap()
            .iter()
            .any(|entry| entry == "consensus_parameters"));
        validate_integrity_hashes(&candidate).unwrap();

        candidate["consensus"]["timeouts"]["proposal_ms"] = json!(1_499);
        assert!(load_candidate_consensus_parameters(&candidate)
            .unwrap_err()
            .contains("proposal_ms disagrees"));
    }

    #[test]
    fn coordinated_p1_binding_replaces_posy_consensus_shape_and_rejects_legacy_fields() {
        use crate::consensus_parameters::{
            CoordinatedRoundRobinParameterManifest, CoordinatedRoundRobinParameters,
            CONSENSUS_PARAMETER_ACTIVATION_BOUNDARY,
            CONSENSUS_PARAMETER_MANIFEST_COORDINATED_P1_SCHEMA_VERSION,
            CONSENSUS_PARAMETER_MANIFEST_FINALIZED_STATUS, CONSENSUS_PARAMETER_MANIFEST_RELEASE_ID,
            COORDINATED_P1_COORDINATOR_ID, COORDINATED_P1_PRODUCER_IDS,
            COORDINATED_P1_PRODUCER_TURN_TIMEOUT_MS, COORDINATED_P1_TARGET_BLOCK_TIME_MS,
            COORDINATED_ROUND_ROBIN_V1_PROTOCOL_VERSION,
        };

        let manifest = CoordinatedRoundRobinParameterManifest {
            schema_version: CONSENSUS_PARAMETER_MANIFEST_COORDINATED_P1_SCHEMA_VERSION,
            release_id: CONSENSUS_PARAMETER_MANIFEST_RELEASE_ID.to_string(),
            status: CONSENSUS_PARAMETER_MANIFEST_FINALIZED_STATUS.to_string(),
            governance_approval_id: "TV3-P1-GENESIS-UNIT-TEST".to_string(),
            chain_id: crate::synergy_types::ChainId::synergy_testnet_v3(),
            network_id: crate::synergy_types::NetworkId::synergy_testnet_v3(),
            protocol_version: COORDINATED_ROUND_ROBIN_V1_PROTOCOL_VERSION.to_string(),
            activation_boundary: CONSENSUS_PARAMETER_ACTIVATION_BOUNDARY.to_string(),
            target_block_time_ms: COORDINATED_P1_TARGET_BLOCK_TIME_MS,
            consensus_signature_algorithm:
                crate::synergy_types::TESTNET_V3_CONSENSUS_SIGNATURE_ALGORITHM.to_string(),
            coordinated_round_robin: CoordinatedRoundRobinParameters {
                coordinator_id: COORDINATED_P1_COORDINATOR_ID.to_string(),
                producer_ids: COORDINATED_P1_PRODUCER_IDS
                    .iter()
                    .map(|producer| (*producer).to_string())
                    .collect(),
                producer_turn_timeout_ms: COORDINATED_P1_PRODUCER_TURN_TIMEOUT_MS,
            },
        };
        let manifest_bytes = manifest.canonical_bytes().expect("canonical P1 manifest");
        let parameters =
            crate::consensus_parameters::load_finalized_consensus_parameters_from_bytes(
                &manifest_bytes,
            )
            .expect("load P1 manifest");
        let mut candidate = testnet_v3_candidate();
        bind_testnet_v3_genesis_consensus_parameters(&mut candidate, &parameters, &"11".repeat(32))
            .expect("bind P1 manifest into candidate");

        assert_eq!(
            candidate["network"]["consensus_version"].as_str(),
            Some(COORDINATED_ROUND_ROBIN_V1_PROTOCOL_VERSION)
        );
        assert_eq!(
            candidate["consensus"]["mode"].as_str(),
            Some(COORDINATED_ROUND_ROBIN_V1_PROTOCOL_VERSION)
        );
        validate_integrity_hashes(&candidate).expect("P1 Genesis integrity binding");

        let path = crate::utils::test_temp_root(format!(
            "synergy-p1-genesis-binding-{}-{}.json",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        fs::write(
            &path,
            serde_json::to_vec(&candidate).expect("encode P1 Genesis"),
        )
        .expect("write P1 Genesis");
        let loaded = load_canonical_genesis_from_path(path.clone()).expect("load P1 Genesis");
        fs::remove_file(path).expect("remove P1 Genesis");
        let bootstrap =
            crate::consensus::testnet_v3_bootstrap::load_coordinated_round_robin_genesis_bootstrap(
                &loaded,
            )
            .expect("bootstrap P1 Genesis");
        assert_eq!(
            bootstrap
                .validator_set
                .active_for_epoch(crate::synergy_types::Epoch(0))
                .validators
                .len(),
            6
        );

        candidate["consensus"]["timeouts"] = json!({ "proposal_ms": 1_500 });
        assert!(load_candidate_consensus_parameters(&candidate)
            .expect_err("P1 Genesis must reject an old typed timeout object")
            .contains("legacy PoSy"));
    }

    #[test]
    fn explicit_test_fixture_loads_the_complete_fresh_p3_authority_binding() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
        let fixture_path = root.join("runtime/config/genesis.testnet-v3.test-fixture.json");
        let fixture = load_genesis_from_path_for_test(fixture_path).unwrap();
        let fixture_parameters = fixture.consensus_parameters().unwrap();
        fixture_parameters.require_genesis_binding().unwrap();
        let manifest = fixture_parameters
            .require_simplified_posy_manifest()
            .unwrap();
        assert_eq!(fixture.consensus_version(), "posy/3.0");
        assert_eq!(fixture.chain_incarnation(), 5);
        assert_eq!(fixture.consensus_state_schema_version(), 5);
        assert_eq!(manifest.active_validator_count, 5);
        assert_eq!(manifest.required_distinct_signers, 4);
        assert!(load_genesis_bound_etdag_governance(fixture.value()).is_ok());
        assert!(
            crate::consensus::simplified_posy::load_genesis_bound_simplified_activation(
                fixture.value()
            )
            .unwrap()
            .is_some()
        );
    }
}
