//! Testnet-v3 genesis ceremony.
//!
//! Bridges the three encrypted production authority bundles into the completed
//! Track G deployment mechanism. It adds no cryptography of its own: decryption
//! is the Synergy Address Engine's approved reader, deployment is
//! `genesis_deployment::execute_genesis_deployment`.
//!
//! Secrets live in memory for exactly as long as the deployment needs them and
//! are zeroized on every exit path.

use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::io::Write;
use std::ops::Deref;
use std::path::{Path, PathBuf};
use synergy_testnet::execution::{ExecutionState, GenesisExecutionSnapshot};
use synergy_testnet::genesis_deployment::*;
use synergy_testnet::posy_simplified_parameters::POSY_SIMPLIFIED_FRESH_GENESIS_BOUNDARY;
use synergy_testnet::synq_execution::SynQContractArtifact;
use zeroize::Zeroize;

const DEPLOYER: &str = "SNRG-TESTNET-V3-GENESIS-DEPLOYER";
const GOVERNANCE: &str = "SNRG-TESTNET-V3-GOVERNANCE-AUTHORITY";
const REGISTRY: &str = "SNRG-TESTNET-V3-VALIDATOR-REGISTRY-AUTHORITY";
const CONFIRMATION: &str = "EXECUTE TESTNET-V3 GENESIS";
/// Best-effort wipe. Rust may still move a `Vec` before this runs, so the real
/// guarantee is scope: nothing here is ever written to disk or printed.
fn zeroize(buf: &mut Vec<u8>) {
    buf.zeroize();
    buf.clear();
    buf.shrink_to_fit();
}

struct Secret(Vec<u8>);
impl Secret {
    fn take(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.0)
    }
}
impl Drop for Secret {
    fn drop(&mut self) {
        zeroize(&mut self.0);
        #[cfg(test)]
        SECRET_DROP_COUNT.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }
}
impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Secret([redacted {} bytes])", self.0.len())
    }
}

#[derive(Deserialize)]
struct RecoveredAuthorityDocument {
    schema_version: String,
    binary_encoding: String,
    role_id: String,
    algorithm: String,
    private_key: String,
}

impl Drop for RecoveredAuthorityDocument {
    fn drop(&mut self) {
        self.private_key.zeroize();
    }
}

struct SecretGenesisAuthorities(GenesisAuthorities);

impl Deref for SecretGenesisAuthorities {
    type Target = GenesisAuthorities;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Drop for SecretGenesisAuthorities {
    fn drop(&mut self) {
        zeroize(&mut self.0.genesis_deployer.private_key);
        zeroize(&mut self.0.governance.private_key);
        zeroize(&mut self.0.validator_registry_authority_key.private_key);
    }
}

fn read_json(path: &Path) -> Result<Value, String> {
    let bytes = std::fs::read(path).map_err(|error| format!("read {}: {error}", path.display()))?;
    serde_json::from_slice(&bytes).map_err(|error| format!("parse {}: {error}", path.display()))
}

fn require_canonical_chain_tuple(value: &Value, label: &str) -> Result<(), String> {
    for retired in [
        "technical_network_id",
        "runtime_network_id",
        "network_slug",
        "network_native_id",
    ] {
        if value.get(retired).is_some() {
            return Err(format!("{label} contains retired network field {retired}"));
        }
    }
    if value["chain_id"] != json!(1266)
        || value["network_id"] != json!("testnet")
        || value["release_id"] != json!("testnet-v3")
    {
        return Err(format!(
            "{label} must bind chain_id 1266, network_id testnet, and release_id testnet-v3"
        ));
    }
    Ok(())
}

fn require_clean_genesis_launch_profile(value: &Value) -> Result<(), String> {
    let network = value
        .get("network")
        .ok_or_else(|| "source Genesis network is missing".to_string())?;
    require_canonical_chain_tuple(network, "source Genesis network")?;
    let consensus = value
        .get("consensus")
        .ok_or_else(|| "source Genesis consensus is missing".to_string())?;
    if consensus["initial_active_validator_count"] != json!(5)
        || consensus["min_validator_count"] != json!(5)
        || consensus["min_quorum_threshold"] != json!(4)
        || consensus["dynamic_validator_membership"] != json!(true)
        || !consensus
            .get("protocol_validator_count_cap")
            .is_some_and(Value::is_null)
        || consensus["initial_validator_ssh_aliases"]
            != json!([
                "synergy-val2",
                "synergy-val3",
                "synergy-val4",
                "synergy-val5",
                "synergy-val6"
            ])
    {
        return Err(
            "source Genesis is not the dynamic, uncapped, exact Val2-Val6 initial profile"
                .to_string(),
        );
    }
    let validators = value["validators"]
        .as_array()
        .ok_or_else(|| "source Genesis validators are missing".to_string())?;
    if validators.len() != 5
        || validators
            .iter()
            .any(|validator| validator["status"] != json!("active_at_genesis"))
        || validators
            .iter()
            .map(|validator| validator["validator_id"].as_str())
            .ne((2..=6).map(|slot| {
                Some(match slot {
                    2 => "validator-02",
                    3 => "validator-03",
                    4 => "validator-04",
                    5 => "validator-05",
                    6 => "validator-06",
                    _ => unreachable!(),
                })
            }))
    {
        return Err("source Genesis does not contain exactly five active validators".to_string());
    }
    if contains_retired_identifier(value) {
        return Err("source Genesis contains a retired chain identifier".to_string());
    }
    Ok(())
}

fn contains_retired_identifier(value: &Value) -> bool {
    match value {
        Value::Object(entries) => entries.iter().any(|(key, value)| {
            key.to_ascii_lowercase().starts_with("synixn") || contains_retired_identifier(value)
        }),
        Value::Array(entries) => entries.iter().any(contains_retired_identifier),
        Value::String(value) => {
            let lower = value.to_ascii_lowercase();
            lower.contains("synixn")
                || lower.contains("posy-validator")
                || matches!(value.as_str(), "posy/2.2" | "posy/v2.2" | "ProofOfSynergy")
                || matches!(value.as_str(), "38658" | "48658" | "58658")
                || value.starts_with("10.70.")
        }
        _ => false,
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(bytes))
}

fn file_checksum(path: &Path) -> Result<String, String> {
    std::fs::read(path)
        .map(|bytes| sha256_hex(&bytes))
        .map_err(|error| format!("read {}: {error}", path.display()))
}

/// Rejects any attempt to supply a passphrase other than at the prompt.
fn reject_non_interactive_passphrases(args: &[String]) -> Result<(), String> {
    for var in ["SYNERGY_PASSPHRASE", "SYNERGY_DECRYPT_PASSPHRASE"] {
        if std::env::var(var).is_ok() {
            return Err(format!(
                "{var} is set. Genesis ceremony passphrases must be entered interactively. Unset it and re-run."
            ));
        }
    }
    for arg in args {
        let lower = arg.to_ascii_lowercase();
        if lower.contains("passphrase") || lower.contains("password") {
            return Err("passphrases must never be supplied as command arguments".to_string());
        }
    }
    Ok(())
}

/// Checked immediately before the first prompt, so argument and mode errors
/// surface without needing a terminal.
fn require_terminal() -> Result<(), String> {
    if !atty_stdin() {
        return Err(
            "a terminal is required: genesis ceremony passphrases are entered without echo"
                .to_string(),
        );
    }
    Ok(())
}

fn atty_stdin() -> bool {
    #[cfg(unix)]
    unsafe {
        extern "C" {
            fn isatty(fd: i32) -> i32;
        }
        isatty(0) == 1
    }
    #[cfg(not(unix))]
    {
        true
    }
}

fn require_sha256(value: &str, label: &str) -> Result<(), String> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(format!(
            "{label} must be exactly 64 lowercase hex characters"
        ));
    }
    Ok(())
}

fn verify_engine_binary(path: &Path, expected_sha256: &str) -> Result<String, String> {
    require_sha256(expected_sha256, "approved Address Engine SHA-256")?;
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|error| format!("inspect Address Engine {}: {error}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
        return Err("approved Address Engine path must be a regular non-symlink file".to_string());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o111 == 0 {
            return Err("approved Address Engine binary is not executable".to_string());
        }
        if metadata.permissions().mode() & 0o022 != 0 {
            return Err(
                "approved Address Engine binary must not be group- or world-writable".to_string(),
            );
        }
    }

    let actual = file_checksum(path)?;
    if actual != expected_sha256 {
        return Err(format!(
            "approved Address Engine SHA-256 mismatch: expected {expected_sha256}, got {actual}"
        ));
    }
    Ok(actual)
}

/// Runs `synergy-keygen decrypt --stdout`, inheriting the terminal so the
/// passphrase prompt is the engine's own non-echoing prompt. Nothing secret is
/// written to disk and the passphrase never reaches this process.
fn decrypt_via_engine(engine: &Path, enc_path: &Path, role: &str) -> Result<Secret, String> {
    use std::process::{Command, Stdio};
    let mut output = Command::new(engine)
        .arg("decrypt")
        .arg(enc_path)
        .arg("--stdout")
        .stdin(Stdio::inherit())
        .stderr(Stdio::inherit())
        .stdout(Stdio::piped())
        .output()
        .map_err(|error| format!("{role}: could not run the Address Engine: {error}"))?;
    // Guard stdout before examining the exit status: even a failing decryptor
    // may have emitted a partial plaintext record.
    let recovered = Secret(std::mem::take(&mut output.stdout));
    if !output.status.success() {
        return Err(format!(
            "{role}: decryption failed (wrong passphrase or damaged custody file)"
        ));
    }
    Ok(recovered)
}

struct Authority {
    account_address: String,
    public_key: Vec<u8>,
    private_key: Secret,
    identity_authorization: synergy_testnet::identity_auth::IdentityAuthorizationCarrier,
}

/// Decrypts one bundle and refuses to return until every public check passes.
fn unlock(
    engine_binary: &Path,
    base: &Path,
    role: &str,
    frozen: &Value,
) -> Result<Authority, String> {
    let dir = base.join(role);
    let public_path = dir.join("identity.pub.json");
    let binding_path = dir.join("genesis-authorization-binding.json");
    let encrypted_path = dir.join("identity.enc.json");
    let pubdoc = read_json(&public_path)?;
    let binding_bytes = std::fs::read(&binding_path)
        .map_err(|error| format!("{role}: read {}: {error}", binding_path.display()))?;
    let binding: synergy_testnet::identity_auth::IdentityAuthorizationBinding =
        serde_json::from_slice(&binding_bytes).map_err(|error| {
            format!("{role}: genesis-authorization-binding.json is invalid: {error}")
        })?;
    let identity_authorization = synergy_testnet::identity_auth::IdentityAuthorizationCarrier::new(
        synergy_testnet::identity_auth::GENESIS_CEREMONY_AUTHORIZATION_DOMAIN,
        binding,
    )
    .map_err(|error| format!("{role}: authorization binding failed: {error}"))?;

    let expected_account = frozen["authorities"]
        .as_array()
        .ok_or_else(|| "frozen authority record is missing authorities array".to_string())?
        .iter()
        .find(|a| a["role_id"] == json!(role))
        .ok_or_else(|| format!("{role}: absent from the frozen authority record"))?;
    let expected_address = expected_account["identity_address"]
        .as_str()
        .ok_or_else(|| format!("{role}: frozen identity address is missing"))?;
    for (field, expected_pointer, path, actual) in [
        (
            "authorization_public",
            "/source_artifact_sha256/authorization_public",
            &public_path,
            file_checksum(&public_path)?,
        ),
        (
            "authorization_encrypted",
            "/custody_inputs/authorization_encrypted_sha256",
            &encrypted_path,
            file_checksum(&encrypted_path)?,
        ),
        (
            "binding",
            "/source_artifact_sha256/binding",
            &binding_path,
            sha256_hex(&binding_bytes),
        ),
    ] {
        let expected = expected_account
            .pointer(expected_pointer)
            .and_then(Value::as_str)
            .ok_or_else(|| format!("{role}: frozen {field} SHA-256 is missing"))?;
        if actual != expected {
            return Err(format!(
                "{role}: {} does not match frozen {field} SHA-256",
                path.display()
            ));
        }
    }
    if expected_account["identity_authorization_binding"] != json!(identity_authorization.binding) {
        return Err(format!(
            "{role}: identity authorization binding differs from the fresh authority freeze"
        ));
    }

    if expected_address.starts_with("tsynq") {
        return Err(format!("{role}: frozen record uses the retired tsynq form"));
    }

    let expected_public_schema = if role == GOVERNANCE {
        "synergy-governance-authorization-public-key-v1"
    } else {
        "synergy-authorization-public-key-v1"
    };
    if pubdoc["schema_version"] != json!(expected_public_schema)
        || pubdoc["binary_encoding"] != json!("lowercase-hex")
        || pubdoc["role_id"] != json!(role)
        || pubdoc["algorithm"] != json!("ML-DSA-87")
    {
        return Err(format!(
            "{role}: identity.pub.json is not the canonical v1.3 authorization-key record"
        ));
    }
    let public_key = decode_lowercase_hex(
        pubdoc["public_key"]
            .as_str()
            .ok_or_else(|| format!("{role}: identity.pub.json has no public_key"))?,
        &format!("{role}: public key"),
    )?;
    if public_key.len() != 2592 {
        return Err(format!(
            "{role}: public key is not ML-DSA-87 (got {} bytes)",
            public_key.len()
        ));
    }
    if expected_account["authorization_public"] != pubdoc {
        return Err(format!(
            "{role}: authorization public record differs from the fresh authority freeze"
        ));
    }
    let derived = identity_authorization
        .identity_address_for_key(
            synergy_testnet::identity_auth::GENESIS_CEREMONY_AUTHORIZATION_DOMAIN,
            "ML-DSA-87",
            &public_key,
            "genesis-signing",
        )
        .map_err(|error| format!("{role}: identity authorization failed: {error}"))?;
    if derived != expected_address {
        return Err(format!(
            "{role}: canonical syna address does not match the frozen record"
        ));
    }
    // Only now ask for the secret.
    let label = match role {
        DEPLOYER => "Genesis Deployer passphrase",
        GOVERNANCE => "Governance Authority passphrase",
        REGISTRY => "ValidatorRegistry Authority passphrase",
        other => other,
    };
    // The approved decryptor runs in its own process and prompts on the shared
    // terminal, so the passphrase never enters this process at all. Only the
    // decrypted payload crosses the pipe, in memory.
    println!("\n  {label} (entered in the Address Engine):");
    let recovered = decrypt_via_engine(engine_binary, &encrypted_path, role)?;
    let document: RecoveredAuthorityDocument = serde_json::from_slice(&recovered.0)
        .map_err(|_| format!("{role}: decrypted payload is not the expected record"))?;
    let expected_private_schema = if role == GOVERNANCE {
        "synergy-governance-authorization-private-key-v1"
    } else {
        "synergy-authorization-private-key-v1"
    };
    if document.schema_version != expected_private_schema
        || document.binary_encoding != "lowercase-hex"
        || document.role_id != role
        || document.algorithm != "ML-DSA-87"
    {
        return Err(format!(
            "{role}: decrypted payload metadata is not canonical v1.3"
        ));
    }
    let private_key = decode_lowercase_hex_secret(&document.private_key, role)?;
    drop(document);
    drop(recovered);

    if private_key.0.len() != 4896 {
        return Err(format!(
            "{role}: recovered key is not an ML-DSA-87 secret key"
        ));
    }
    // Prove the recovered secret belongs to the verified public key.
    if !signs_correctly(&private_key.0, &public_key) {
        return Err(format!(
            "{role}: recovered private key does not correspond to the bundle public key"
        ));
    }

    println!("    unlocked  {role}  {derived}");
    Ok(Authority {
        account_address: derived,
        public_key,
        private_key,
        identity_authorization,
    })
}

fn signs_correctly(private_key: &[u8], public_key: &[u8]) -> bool {
    use pqsynq::Sign;
    let probe = b"synergy-genesis-ceremony-keypair-correspondence-probe";
    match Sign::mldsa87().detached_sign(probe, private_key) {
        // Argument order is (message, signature, public_key).
        Ok(sig) => Sign::mldsa87()
            .verify_detached(probe, &sig, public_key)
            .unwrap_or(false),
        Err(_) => false,
    }
}

fn decode_lowercase_hex(input: &str, label: &str) -> Result<Vec<u8>, String> {
    if input.is_empty()
        || input.len() % 2 != 0
        || !input
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(format!("{label} is not canonical lowercase hex"));
    }
    hex::decode(input).map_err(|error| format!("decode {label}: {error}"))
}

fn decode_lowercase_hex_secret(input: &str, role: &str) -> Result<Secret, String> {
    let bytes = decode_lowercase_hex(input, &format!("{role}: private key"))?;
    Ok(Secret(bytes))
}

fn write_public(path: &Path, contents: &str) -> Result<(), String> {
    std::fs::write(path, contents).map_err(|error| format!("write {}: {error}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .map_err(|error| format!("set permissions on {}: {error}", path.display()))?;
    }
    Ok(())
}

fn genesis_execution_state(
    source_genesis: &Path,
    team_vesting_address: &str,
) -> Result<ExecutionState, String> {
    let genesis = read_json(source_genesis)?;
    let balances = genesis["balances"]
        .as_array()
        .ok_or_else(|| "source genesis balances must be an array".to_string())?;
    let mut state = ExecutionState::new();
    let mut total = 0u128;
    for balance in balances {
        let source_address = balance["address"]
            .as_str()
            .filter(|value| !value.is_empty())
            .ok_or_else(|| "source genesis balance address is missing".to_string())?;
        // TEM-A01 funds the deployed TeamVesting instance, not its separate
        // FN-DSA administrative/custody identity. SaleClaim is excluded, so
        // SAL-A01 remains at its custody identity.
        let address = if balance["account_id"] == "TEM-A01" {
            team_vesting_address
        } else {
            source_address
        };
        let amount = balance["balance_nwei"]
            .as_str()
            .ok_or_else(|| "source genesis balance_nwei must be a decimal string".to_string())?
            .parse::<u128>()
            .map_err(|error| format!("parse source genesis balance_nwei: {error}"))?;
        if state
            .balances_nwei
            .insert(address.to_string(), amount)
            .is_some()
        {
            return Err(format!(
                "source genesis contains duplicate balance address {address}"
            ));
        }
        total = total
            .checked_add(amount)
            .ok_or_else(|| "source genesis balance sum overflowed u128".to_string())?;
    }
    let declared_total = genesis["allocation_sum_check"]["grand_total_nwei"]
        .as_str()
        .ok_or_else(|| {
            "source genesis allocation_sum_check.grand_total_nwei is missing".to_string()
        })?
        .parse::<u128>()
        .map_err(|error| format!("parse source genesis grand total: {error}"))?;
    if total != declared_total {
        return Err(format!(
            "source genesis balances sum to {total}, declared total is {declared_total}"
        ));
    }
    Ok(state)
}

#[derive(Debug, PartialEq, Eq)]
struct CeremonyOptions {
    authorities_file: PathBuf,
    allocation_manifest: PathBuf,
    resolved_allocations: PathBuf,
    validator_inputs: PathBuf,
    contracts_dir: PathBuf,
    source_genesis: PathBuf,
    identity_root: PathBuf,
    output_dir: PathBuf,
    prior_dry_run_status: Option<PathBuf>,
    address_engine_binary: PathBuf,
    address_engine_sha256: String,
    execute: bool,
}

fn parse_path_argument(args: &[String], index: usize, flag: &str) -> Result<PathBuf, String> {
    let value = args
        .get(index + 1)
        .filter(|value| !value.is_empty() && !value.starts_with("--"))
        .ok_or_else(|| format!("{flag} requires a non-empty path"))?;
    Ok(PathBuf::from(value))
}

fn parse_ceremony_options(args: &[String]) -> Result<CeremonyOptions, String> {
    let mut authorities_file = None;
    let mut allocation_manifest = None;
    let mut resolved_allocations = None;
    let mut validator_inputs = None;
    let mut contracts_dir = None;
    let mut source_genesis = None;
    let mut identity_root = None;
    let mut output_dir = None;
    let mut prior_dry_run_status = None;
    let mut address_engine_binary = None;
    let mut address_engine_sha256 = None;
    let mut mode = None;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--authorities-file" => {
                if authorities_file.is_some() {
                    return Err("--authorities-file may be supplied only once".to_string());
                }
                authorities_file = Some(parse_path_argument(args, index, "--authorities-file")?);
                index += 2;
            }
            "--allocation-manifest" => {
                if allocation_manifest.is_some() {
                    return Err("--allocation-manifest may be supplied only once".to_string());
                }
                allocation_manifest =
                    Some(parse_path_argument(args, index, "--allocation-manifest")?);
                index += 2;
            }
            "--resolved-allocations" => {
                if resolved_allocations.is_some() {
                    return Err("--resolved-allocations may be supplied only once".to_string());
                }
                resolved_allocations =
                    Some(parse_path_argument(args, index, "--resolved-allocations")?);
                index += 2;
            }
            "--validator-inputs" => {
                if validator_inputs.is_some() {
                    return Err("--validator-inputs may be supplied only once".to_string());
                }
                validator_inputs = Some(parse_path_argument(args, index, "--validator-inputs")?);
                index += 2;
            }
            "--contracts-dir" => {
                if contracts_dir.is_some() {
                    return Err("--contracts-dir may be supplied only once".to_string());
                }
                contracts_dir = Some(parse_path_argument(args, index, "--contracts-dir")?);
                index += 2;
            }
            "--source-genesis" => {
                if source_genesis.is_some() {
                    return Err("--source-genesis may be supplied only once".to_string());
                }
                source_genesis = Some(parse_path_argument(args, index, "--source-genesis")?);
                index += 2;
            }
            "--identity-root" => {
                if identity_root.is_some() {
                    return Err("--identity-root may be supplied only once".to_string());
                }
                identity_root = Some(parse_path_argument(args, index, "--identity-root")?);
                index += 2;
            }
            "--output-dir" => {
                if output_dir.is_some() {
                    return Err("--output-dir may be supplied only once".to_string());
                }
                output_dir = Some(parse_path_argument(args, index, "--output-dir")?);
                index += 2;
            }
            "--prior-dry-run-status" => {
                if prior_dry_run_status.is_some() {
                    return Err("--prior-dry-run-status may be supplied only once".to_string());
                }
                prior_dry_run_status =
                    Some(parse_path_argument(args, index, "--prior-dry-run-status")?);
                index += 2;
            }
            "--address-engine-binary" => {
                if address_engine_binary.is_some() {
                    return Err("--address-engine-binary may be supplied only once".to_string());
                }
                address_engine_binary =
                    Some(parse_path_argument(args, index, "--address-engine-binary")?);
                index += 2;
            }
            "--address-engine-sha256" => {
                if address_engine_sha256.is_some() {
                    return Err("--address-engine-sha256 may be supplied only once".to_string());
                }
                let value = args
                    .get(index + 1)
                    .filter(|value| !value.is_empty() && !value.starts_with("--"))
                    .ok_or_else(|| {
                        "--address-engine-sha256 requires a lowercase-hex digest".to_string()
                    })?;
                require_sha256(value, "--address-engine-sha256")?;
                address_engine_sha256 = Some(value.clone());
                index += 2;
            }
            "--dry-run" => {
                if mode.replace(false).is_some() {
                    return Err("choose exactly one of --dry-run or --execute".to_string());
                }
                index += 1;
            }
            "--execute" => {
                if mode.replace(true).is_some() {
                    return Err("choose exactly one of --dry-run or --execute".to_string());
                }
                index += 1;
            }
            other => return Err(format!("unknown flag '{other}'")),
        }
    }

    let execute = mode.ok_or_else(|| {
        "choose exactly one of --dry-run or --execute (--dry-run is the safe default path)"
            .to_string()
    })?;
    match (
        authorities_file,
        allocation_manifest,
        resolved_allocations,
        validator_inputs,
        contracts_dir,
        source_genesis,
        identity_root,
        output_dir,
        address_engine_binary,
        address_engine_sha256,
    ) {
        (
            Some(authorities_file),
            Some(allocation_manifest),
            Some(resolved_allocations),
            Some(validator_inputs),
            Some(contracts_dir),
            Some(source_genesis),
            Some(identity_root),
            Some(output_dir),
            Some(address_engine_binary),
            Some(address_engine_sha256),
        ) => Ok(CeremonyOptions {
            authorities_file,
            allocation_manifest,
            resolved_allocations,
            validator_inputs,
            contracts_dir,
            source_genesis,
            identity_root,
            output_dir,
            prior_dry_run_status,
            address_engine_binary,
            address_engine_sha256,
            execute,
        }),
        _ => Err(
            "required: --authorities-file --allocation-manifest --resolved-allocations --validator-inputs --contracts-dir --source-genesis --identity-root --output-dir --address-engine-binary --address-engine-sha256".to_string(),
        ),
    }
}

fn ceremony_input_digest(inputs: &BTreeMap<String, String>) -> Result<String, String> {
    serde_json::to_vec(inputs)
        .map(|bytes| sha256_hex(&bytes))
        .map_err(|error| format!("serialize ceremony input digest: {error}"))
}

fn require_matching_dry_run_evidence(
    prior: &Value,
    input_digest: &str,
    address_engine_sha256: &str,
) -> Result<(), String> {
    if prior["status"] != json!("DRY_RUN_PASSED") {
        return Err("prior dry run did not pass".to_string());
    }
    if prior["candidate_input_id"] != json!(input_digest) {
        return Err("inputs changed since the dry run; re-run --dry-run".to_string());
    }
    if prior["address_engine_sha256"] != json!(address_engine_sha256) {
        return Err("Address Engine changed since the dry run; re-run --dry-run".to_string());
    }
    Ok(())
}

fn contract_artifact_inventory(contracts_dir: &Path) -> Result<(String, Vec<Value>), String> {
    let mut entries = Vec::new();
    for contract in GenesisContract::APPROVED_ORDER {
        for suffix in ["synq", "compiled.synq", "abi.json", "manifest.json"] {
            let file = format!("{}.{}", contract.name(), suffix);
            let sha256 = file_checksum(&contracts_dir.join(&file))?;
            entries.push(json!({"file": file, "sha256": sha256}));
        }
    }
    let canonical = serde_json::to_vec(&entries)
        .map_err(|error| format!("serialize contract artifact inventory: {error}"))?;
    Ok((sha256_hex(&canonical), entries))
}

fn require_new_empty_output_dir(path: &Path) -> Result<(), String> {
    if path.exists() {
        let mut entries = std::fs::read_dir(path)
            .map_err(|error| format!("inspect output directory {}: {error}", path.display()))?;
        if entries.next().is_some() {
            return Err(format!(
                "output directory {} is not empty; refusing to overwrite evidence",
                path.display()
            ));
        }
    }
    Ok(())
}

fn run() -> Result<(), String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    reject_non_interactive_passphrases(&args)?;
    let CeremonyOptions {
        authorities_file,
        allocation_manifest,
        resolved_allocations,
        validator_inputs,
        contracts_dir,
        source_genesis,
        identity_root,
        output_dir,
        prior_dry_run_status,
        address_engine_binary,
        address_engine_sha256,
        execute,
    } = parse_ceremony_options(&args)?;
    require_new_empty_output_dir(&output_dir)?;
    let address_engine_binary_sha256 =
        verify_engine_binary(&address_engine_binary, &address_engine_sha256)?;

    let frozen = read_json(&authorities_file)?;
    let source_genesis_document = read_json(&source_genesis)?;
    if !identity_root.is_dir() {
        return Err(format!(
            "identity root {} is not a directory",
            identity_root.display()
        ));
    }

    if frozen["chain_id"] != json!(1266)
        || frozen["network_id"] != json!("testnet")
        || frozen["release_id"] != json!("testnet-v3")
        || frozen["consensus_protocol"] != json!("posy/3.0")
    {
        return Err("fresh authority freeze has the wrong chain tuple".to_string());
    }
    require_clean_genesis_launch_profile(&source_genesis_document)?;
    if frozen["artifact_type"] != json!("fresh-testnet-v3-genesis-authority-public-freeze")
        || frozen["schema_version"] != json!("synergy-testnet-v3-genesis-authority-freeze-v1")
        || frozen["genesis_boundary"] != json!(POSY_SIMPLIFIED_FRESH_GENESIS_BOUNDARY)
        || frozen["authority_count"] != json!(3)
        || frozen["authorities"].as_array().map(Vec::len) != Some(3)
    {
        return Err(
            "authority record is not the fresh three-authority production freeze".to_string(),
        );
    }
    let expected_roles = [DEPLOYER, GOVERNANCE, REGISTRY];
    if frozen["authorities"]
        .as_array()
        .unwrap()
        .iter()
        .zip(expected_roles)
        .any(|(entry, role)| entry["role_id"] != json!(role))
    {
        return Err("authority record role order or membership is non-canonical".to_string());
    }

    let authorities_sha256 = file_checksum(&authorities_file)?;
    let source_genesis_sha256 = file_checksum(&source_genesis)?;
    let allocation_manifest_sha256 = file_checksum(&allocation_manifest)?;
    let resolved_allocations_sha256 = file_checksum(&resolved_allocations)?;
    let validator_inputs_sha256 = file_checksum(&validator_inputs)?;
    let (contract_artifact_set_sha256, contract_artifacts) =
        contract_artifact_inventory(&contracts_dir)?;
    let mut input_hashes = BTreeMap::new();
    input_hashes.insert("source_genesis_sha256".to_string(), source_genesis_sha256);
    input_hashes.insert(
        "allocation_manifest_sha256".to_string(),
        allocation_manifest_sha256,
    );
    input_hashes.insert(
        "resolved_allocations_sha256".to_string(),
        resolved_allocations_sha256,
    );
    input_hashes.insert(
        "validator_inputs_sha256".to_string(),
        validator_inputs_sha256,
    );
    input_hashes.insert("authority_record_sha256".to_string(), authorities_sha256);
    input_hashes.insert(
        "contract_artifact_set_sha256".to_string(),
        contract_artifact_set_sha256,
    );
    let input_digest = ceremony_input_digest(&input_hashes)?;
    let binding = &source_genesis_document["fresh_p3_public_input_binding"];
    for (field, binding_field) in [
        ("allocation_manifest_sha256", "allocation_plan_sha256"),
        ("resolved_allocations_sha256", "resolved_allocations_sha256"),
        ("validator_inputs_sha256", "validator_source_inputs_sha256"),
        ("authority_record_sha256", "fresh_authority_record_sha256"),
    ] {
        if binding[binding_field] != json!(input_hashes[field]) {
            return Err(format!(
                "source Genesis {binding_field} does not match supplied {field}"
            ));
        }
    }

    println!("\n  Synergy Testnet-v3 genesis ceremony");
    println!(
        "  mode              : {}",
        if execute { "EXECUTE" } else { "dry-run" }
    );
    println!(
        "  authorities sha256: {}",
        input_hashes["authority_record_sha256"]
    );
    println!(
        "  artifacts   sha256: {}",
        input_hashes["contract_artifact_set_sha256"]
    );
    println!(
        "  genesis     sha256: {}",
        input_hashes["source_genesis_sha256"]
    );
    println!("  address engine    : {}", address_engine_binary.display());
    println!("  engine      sha256: {address_engine_binary_sha256}");
    println!("  candidate input id: {input_digest}");

    // Production mode requires prior matching dry-run evidence and an explicit phrase.
    if execute {
        let evidence = prior_dry_run_status.as_ref().ok_or_else(|| {
            "--execute requires --prior-dry-run-status from a separate completed dry run"
                .to_string()
        })?;
        let prior = read_json(&evidence)?;
        require_matching_dry_run_evidence(&prior, &input_digest, &address_engine_binary_sha256)?;
        println!("\n  Type the confirmation phrase to proceed:");
        println!("    {CONFIRMATION}");
        print!("  > ");
        std::io::stdout()
            .flush()
            .map_err(|error| format!("write ceremony confirmation prompt: {error}"))?;
        let mut typed = String::new();
        std::io::stdin()
            .read_line(&mut typed)
            .map_err(|error| format!("could not read confirmation: {error}"))?;
        if typed.trim() != CONFIRMATION {
            return Err("confirmation phrase did not match exactly".to_string());
        }
    } else if prior_dry_run_status.is_some() {
        return Err("--prior-dry-run-status is valid only with --execute".to_string());
    }

    require_terminal()?;
    println!("\n  Unlocking three production authorities (three passphrase prompts).");
    let mut deployer = unlock(&address_engine_binary, &identity_root, DEPLOYER, &frozen)?;
    let mut governance = unlock(&address_engine_binary, &identity_root, GOVERNANCE, &frozen)?;
    let mut registry = unlock(&address_engine_binary, &identity_root, REGISTRY, &frozen)?;

    let source_account = |account_id: &str| -> Result<String, String> {
        source_genesis_document["accounts"]
            .as_array()
            .ok_or_else(|| "source Genesis accounts are missing".to_string())?
            .iter()
            .find(|account| account["account_id"] == json!(account_id))
            .and_then(|account| account["address"].as_str())
            .map(ToOwned::to_owned)
            .ok_or_else(|| format!("source Genesis account {account_id} has no address"))
    };
    let emergency_slashing_authority = source_account("SYS-03")?;
    let reward_distributor_authority = source_genesis_document["contracts"]["reward_distributor"]
        ["init_params"]["pool_address"]
        .as_str()
        .map(ToOwned::to_owned)
        .ok_or_else(|| "fresh reward-distributor pool address is missing".to_string())?;
    let identity_fee_collector = source_account("SYS-01")?;
    let team_vesting_admin = source_genesis_document["contracts"]["team_vesting"]["init_params"]
        ["admin_authority"]
        .as_str()
        .map(ToOwned::to_owned)
        .ok_or_else(|| "fresh TeamVesting admin authority is missing".to_string())?;
    let oracle_publisher = source_genesis_document["contracts"]["synergy_oracle"]["init_params"]
        ["authority_address"]
        .as_str()
        .map(ToOwned::to_owned)
        .ok_or_else(|| "fresh oracle authority is missing".to_string())?;

    let authorities = SecretGenesisAuthorities(GenesisAuthorities {
        genesis_deployer: GenesisSigner {
            public_key: std::mem::take(&mut deployer.public_key),
            private_key: deployer.private_key.take(),
            identity_authorization: Some(deployer.identity_authorization.clone()),
        },
        governance: GenesisSigner {
            public_key: std::mem::take(&mut governance.public_key),
            private_key: governance.private_key.take(),
            identity_authorization: Some(governance.identity_authorization.clone()),
        },
        emergency_slashing_authority,
        validator_registry_authority: registry.account_address.clone(),
        validator_registry_authority_key: GenesisSigner {
            public_key: std::mem::take(&mut registry.public_key),
            private_key: registry.private_key.take(),
            identity_authorization: Some(registry.identity_authorization.clone()),
        },
        reward_distributor_authority,
        identity_fee_collector,
        team_vesting_admin,
        oracle_publisher,
    });
    drop(deployer);
    drop(governance);
    drop(registry);

    let artifacts: BTreeMap<GenesisContract, SynQContractArtifact> =
        GenesisContract::APPROVED_ORDER
            .iter()
            .map(|c| -> Result<_, String> {
                let name = c.name();
                let read = |ext: &str| -> Result<Vec<u8>, String> {
                    std::fs::read(contracts_dir.join(format!("{name}.{ext}")))
                        .map_err(|error| format!("read canonical {name}.{ext}: {error}"))
                };
                Ok((
                    *c,
                    SynQContractArtifact::new(
                        read("compiled.synq")?,
                        String::from_utf8(read("abi.json")?)
                            .map_err(|error| format!("decode staged {name}.abi.json: {error}"))?,
                        String::from_utf8(read("manifest.json")?).map_err(|error| {
                            format!("decode staged {name}.manifest.json: {error}")
                        })?,
                    ),
                ))
            })
            .collect::<Result<_, _>>()?;
    let plan = GenesisDeploymentPlan::new(&artifacts)?;
    let parameters = production_parameters(&source_genesis)?;
    let derived = derive_genesis_addresses(
        &plan,
        &authorities.genesis_deployer.public_key,
        &authorities,
        &parameters,
    )?;
    let team_vesting_address = derived
        .iter()
        .find(|entry| entry.contract == "TeamVesting")
        .map(|entry| entry.contract_address.as_str())
        .ok_or_else(|| "fresh derivation omitted TeamVesting".to_string())?;

    println!("\n  Executing nine deployments and the candidate-derived initialization calls…");
    let mut state = genesis_execution_state(&source_genesis, team_vesting_address)?;
    let outcome = execute_genesis_deployment(&mut state, &plan, &authorities, &parameters);
    drop(authorities);
    let outcome = outcome.map_err(|error| format!("genesis deployment failed: {error}"))?;
    let snapshot = GenesisExecutionSnapshot::capture_testnet_v3(&state)
        .map_err(|error| format!("capture finalized execution state: {error}"))?;
    if snapshot.state_root != outcome.post_deployment_state_root.to_hex() {
        return Err("captured execution-state root does not match deployment outcome".to_string());
    }
    let snapshot_name = if execute {
        "execution-state.json"
    } else {
        "dry-run-execution-state.json"
    };
    let snapshot_contents = serde_json::to_string_pretty(&snapshot)
        .map_err(|error| format!("serialize execution state snapshot: {error}"))?
        + "\n";
    let snapshot_sha256 = sha256_hex(snapshot_contents.as_bytes());
    let snapshot_canonical_sha256 = sha256_hex(
        &serde_json::to_vec(&snapshot)
            .map_err(|error| format!("canonicalize execution state snapshot: {error}"))?,
    );

    std::fs::create_dir_all(&output_dir).map_err(|error| format!("create output dir: {error}"))?;
    let addresses: BTreeMap<String, String> = outcome
        .addresses
        .iter()
        .map(|(c, a)| (c.name().to_string(), a.clone()))
        .collect();
    let deployment_contents = serde_json::to_string_pretty(&outcome.deployment_receipts)
        .map_err(|error| format!("serialize deployment receipts: {error}"))?
        + "\n";
    let initialization_contents = serde_json::to_string_pretty(&outcome.initialization_receipts)
        .map_err(|error| format!("serialize initialization receipts: {error}"))?
        + "\n";
    let replay_operations_contents = serde_json::to_string_pretty(&outcome.replay_operations)
        .map_err(|error| format!("serialize signed genesis replay operations: {error}"))?
        + "\n";
    let evidence = if execute {
        json!({
            "schema_version": 1,
            "artifact_type": "fresh-p3-executed-deployment-evidence",
            "status": "EXECUTION_PASSED",
            "mode": "execute",
            "chain_id": 1266,
            "network_id": "testnet",
            "release_id": "testnet-v3",
            "protocol_version": "posy/3.0",
            "candidate_input_id": input_digest,
            "inputs": input_hashes,
            "contract_artifacts": contract_artifacts,
            "evidence_files": {
                "deployment_receipts_sha256": sha256_hex(deployment_contents.as_bytes()),
                "initialization_receipts_sha256": sha256_hex(initialization_contents.as_bytes()),
                "signed_replay_operations_sha256": sha256_hex(replay_operations_contents.as_bytes()),
                "execution_state_sha256": snapshot_sha256,
                "execution_state_canonical_sha256": snapshot_canonical_sha256,
            },
            "contract_addresses": addresses,
            "receipt_root": outcome.receipt_root.to_hex(),
            "post_deployment_execution_state_root": outcome.post_deployment_state_root.to_hex(),
            "post_deployment_aivm_state_root": snapshot.aivm_state_root,
            "deployment_manifest_hash": outcome.deployment_manifest_hash.to_hex(),
        })
    } else {
        json!({
            "schema_version": 1,
            "artifact_type": "fresh-p3-deployment-dry-run-evidence",
            "status": "DRY_RUN_PASSED",
            "mode": "dry-run",
            "chain_id": 1266,
            "network_id": "testnet",
            "release_id": "testnet-v3",
            "protocol_version": "posy/3.0",
            "candidate_input_id": input_digest,
            "inputs": input_hashes,
            "address_engine_sha256": address_engine_binary_sha256,
            "contract_artifacts": contract_artifacts,
            "contract_addresses": addresses,
            "receipt_root": outcome.receipt_root.to_hex(),
            "post_deployment_execution_state_root": outcome.post_deployment_state_root.to_hex(),
            "post_deployment_aivm_state_root": snapshot.aivm_state_root,
            "deployment_manifest_hash": outcome.deployment_manifest_hash.to_hex(),
        })
    };
    let name = if execute {
        "execution-status.json"
    } else {
        "dry-run-status.json"
    };
    write_public(&output_dir.join(snapshot_name), &snapshot_contents)?;
    write_public(
        &output_dir.join(name),
        &(serde_json::to_string_pretty(&evidence)
            .map_err(|error| format!("serialize ceremony evidence: {error}"))?
            + "\n"),
    )?;
    if execute {
        write_public(
            &output_dir.join("deployment-receipts.json"),
            &deployment_contents,
        )?;
        write_public(
            &output_dir.join("initialization-receipts.json"),
            &initialization_contents,
        )?;
        write_public(
            &output_dir.join("signed-replay-operations.json"),
            &replay_operations_contents,
        )?;
    }

    println!("\n  All nine addresses were freshly derived and executed.");
    println!(
        "  deployments {} / initializations {}",
        outcome.deployment_receipts.len(),
        outcome.initialization_receipts.len()
    );
    println!(
        "  post-deployment execution root  : {}",
        outcome.post_deployment_state_root.to_hex()
    );
    println!(
        "  post-deployment AIVM state root : {}",
        snapshot.aivm_state_root
    );
    println!(
        "  deployment receipt root         : {}",
        outcome.receipt_root.to_hex()
    );
    println!(
        "  genesis deployer                : {:?}",
        outcome.lifecycle
    );
    println!("  evidence written to {}", output_dir.display());
    if !execute {
        println!("\n  Dry run only. Nothing was committed to the canonical genesis.");
    }
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("\n  CEREMONY ABORTED: {error}");
        // `run` returned only after every in-scope secret guard was dropped.
        std::process::exit(1);
    }
}

fn production_parameters(source_genesis: &Path) -> Result<GenesisParameters, String> {
    let g: Value = read_json(source_genesis)?;
    let c = &g["contracts"];
    let s = |v: &Value| v.as_str().unwrap().to_string();
    let n = |v: &Value| v.as_u64().unwrap().to_string();
    let validators = c["validator_registry"]["init_params"]["validators"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| GenesisValidator {
            id_hash: format!("0x{}", s(&v["validator_id_hash"])),
            operator_address: s(&v["operator_address"]),
            reward_address: s(&v["reward_address"]),
            voting_power: n(&v["voting_power"]),
            self_stake_nwei: s(&v["stake_nwei"]),
            metadata_hash: format!("0x{}", s(&v["metadata_hash"])),
            key_bundle_hash: format!("0x{}", s(&v["key_bundle_hash"])),
            activation_height: n(&v["activation_height"]),
        })
        .collect();
    Ok(GenesisParameters {
        identity_registration_fee_nwei: s(&c["identity"]["init_params"]["registration_fee_nwei"]),
        identity_reserved_names: c["identity"]["init_params"]["reserved_names"]
            .as_array()
            .unwrap()
            .iter()
            .map(s)
            .collect(),
        validator_max_count: n(&c["validator_registry"]["init_params"]["max_validator_count"]),
        validator_min_count: n(&c["validator_registry"]["init_params"]["min_validator_count"]),
        validator_min_self_stake_nwei: s(
            &c["validator_registry"]["init_params"]["min_self_stake_nwei"]
        ),
        validators,
        staking_min_stake_nwei: s(&c["staking"]["init_params"]["min_stake_nwei"]),
        staking_max_stake_nwei: s(&c["staking"]["init_params"]["max_stake_nwei"]),
        staking_unbonding_blocks: "302400".to_string(),
        governance_quorum_bps: "6000".to_string(),
        governance_approval_bps: "5000".to_string(),
        governance_veto_bps: "3300".to_string(),
        governance_min_deposit_nwei: s(&c["governance"]["init_params"]["min_deposit_nwei"]),
        governance_voting_blocks: "302400".to_string(),
        governance_timelock_blocks: "43200".to_string(),
        treasury_required_signers: n(&c["treasury"]["init_params"]["required_signers"]),
        treasury_signers: c["treasury"]["init_params"]["signers"]
            .as_array()
            .unwrap()
            .iter()
            .map(s)
            .collect(),
        slashing_double_sign_bps: "500".to_string(),
        slashing_downtime_bps: "100".to_string(),
        slashing_invalid_block_bps: "500".to_string(),
        slashing_missed_blocks_threshold: n(
            &c["slashing"]["init_params"]["downtime_missed_blocks_threshold"]
        ),
        slashing_jail_blocks: "43200".to_string(),
        oracle_quorum_threshold: n(&c["synergy_oracle"]["init_params"]["quorum_threshold"]),
        oracle_replay_protection: true,
        oracle_source_domains: c["synergy_oracle"]["init_params"]["accepted_source_domains"]
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
    })
}
