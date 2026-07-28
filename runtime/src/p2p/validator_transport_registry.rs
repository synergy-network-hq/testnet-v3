//! Signed validator transports published by the Innernet coordinator.

use base64::{engine::general_purpose, Engine as _};
use ed25519_dalek::{Signature, VerifyingKey};
use lazy_static::lazy_static;
use reqwest::Url;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::Read;
use std::path::PathBuf;
use std::sync::RwLock;
use std::time::Duration;

const DEFAULT_SNAPSHOT_URL: &str =
    "https://vpn-coordinator.synergy-network.io/v1/mesh/transports/current";
const SNAPSHOT_URL_ENV: &str = "SYNERGY_VALIDATOR_TRANSPORT_SNAPSHOT_URL";
const PUBLIC_KEY_ENV: &str = "SYNERGY_INNERNET_COORDINATOR_PUBLIC_KEY";
const DEFAULT_PUBLIC_KEY: &str = "ed25519:0tA5eh5BHCPxXFUlHtb5+GOJFPqLhmnxDOqli39Y+iI=";
const EXPECTED_NETWORK: &str = "synergy-innernet-membership-v1";
const EXPECTED_MIGRATION_ID: &str = "synergy-testnet-innernet-v19-14450ae4d67455c7";
const EXPECTED_VERSION: u32 = 1;
const SNAPSHOT_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_SNAPSHOT_BYTES: usize = 256 * 1024;

#[derive(Debug, Clone, Deserialize, Serialize)]
struct ValidatorTransport {
    validator_address: String,
    dial_address: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct ValidatorTransportSnapshot {
    version: u32,
    network: String,
    migration_id: String,
    configuration_version: u64,
    transports: Vec<ValidatorTransport>,
    signature: String,
}

#[derive(Debug, Clone)]
struct TrustedRegistry {
    migration_id: String,
    generation: u64,
    transports: HashMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ValidatorTransportRefresh {
    pub generation: u64,
    pub changed: bool,
}

lazy_static! {
    static ref LAST_KNOWN_GOOD: RwLock<Option<TrustedRegistry>> = RwLock::new(None);
}

pub(crate) fn current_validator_transports() -> HashMap<String, String> {
    LAST_KNOWN_GOOD
        .read()
        .ok()
        .and_then(|state| state.as_ref().map(|state| state.transports.clone()))
        .unwrap_or_default()
}

pub(crate) fn validator_transport_for(address: &str) -> Option<String> {
    LAST_KNOWN_GOOD
        .read()
        .ok()
        .and_then(|state| state.as_ref()?.transports.get(address).cloned())
}

pub(crate) fn has_validator_transports() -> bool {
    LAST_KNOWN_GOOD
        .read()
        .ok()
        .and_then(|state| state.as_ref().map(|state| !state.transports.is_empty()))
        .unwrap_or(false)
}

pub(crate) fn refresh_validator_transports() -> Result<ValidatorTransportRefresh, String> {
    let snapshot_url =
        std::env::var(SNAPSHOT_URL_ENV).unwrap_or_else(|_| DEFAULT_SNAPSHOT_URL.to_string());
    let url = validate_snapshot_url(&snapshot_url)?;
    let verifying_key = configured_public_key()?;
    if !has_validator_transports() {
        load_persisted_snapshot(&verifying_key)?;
    }
    let client = reqwest::blocking::Client::builder()
        .timeout(SNAPSHOT_TIMEOUT)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|error| format!("failed to build validator transport HTTP client: {error}"))?;
    let response = client
        .get(url)
        .send()
        .map_err(|error| format!("validator transport snapshot fetch failed: {error}"))?;
    if !response.status().is_success() {
        return Err(format!(
            "validator transport snapshot fetch returned HTTP {}",
            response.status()
        ));
    }
    if response
        .content_length()
        .is_some_and(|length| length > MAX_SNAPSHOT_BYTES as u64)
    {
        return Err("validator transport snapshot exceeds the response size limit".to_string());
    }
    let mut bytes = Vec::new();
    response
        .take((MAX_SNAPSHOT_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("failed to read validator transport snapshot: {error}"))?;
    if bytes.len() > MAX_SNAPSHOT_BYTES {
        return Err("validator transport snapshot exceeds the response size limit".to_string());
    }
    let snapshot = serde_json::from_slice::<ValidatorTransportSnapshot>(&bytes)
        .map_err(|error| format!("invalid validator transport snapshot JSON: {error}"))?;
    accept_snapshot(&snapshot, &verifying_key)
}

fn validate_snapshot_url(raw: &str) -> Result<Url, String> {
    let url = Url::parse(raw.trim())
        .map_err(|error| format!("invalid validator transport snapshot URL: {error}"))?;
    let host = url
        .host_str()
        .ok_or_else(|| "validator transport snapshot URL has no host".to_string())?;
    let local_http = url.scheme() == "http" && (host == "localhost" || host == "127.0.0.1");
    if url.scheme() != "https" && !local_http {
        return Err(
            "validator transport snapshot URL must use HTTPS except localhost/127.0.0.1"
                .to_string(),
        );
    }
    Ok(url)
}

fn configured_public_key() -> Result<VerifyingKey, String> {
    let value = std::env::var(PUBLIC_KEY_ENV).unwrap_or_else(|_| DEFAULT_PUBLIC_KEY.to_string());
    decode_public_key(&value)
}

fn decode_public_key(value: &str) -> Result<VerifyingKey, String> {
    let encoded = value
        .trim()
        .strip_prefix("ed25519:")
        .ok_or_else(|| "coordinator public key must use the ed25519: prefix".to_string())?;
    let bytes: [u8; 32] = general_purpose::STANDARD
        .decode(encoded)
        .map_err(|error| format!("invalid coordinator public key base64: {error}"))?
        .try_into()
        .map_err(|_| "coordinator public key must decode to 32 bytes".to_string())?;
    VerifyingKey::from_bytes(&bytes)
        .map_err(|error| format!("invalid coordinator Ed25519 public key: {error}"))
}

fn accept_snapshot(
    snapshot: &ValidatorTransportSnapshot,
    verifying_key: &VerifyingKey,
) -> Result<ValidatorTransportRefresh, String> {
    let transports = validate_and_verify_snapshot(snapshot, verifying_key)?;
    install_snapshot(snapshot, transports)
}

fn validate_and_verify_snapshot(
    snapshot: &ValidatorTransportSnapshot,
    verifying_key: &VerifyingKey,
) -> Result<HashMap<String, String>, String> {
    if snapshot.version != EXPECTED_VERSION {
        return Err(format!(
            "unsupported validator transport snapshot version {}",
            snapshot.version
        ));
    }
    if snapshot.network != EXPECTED_NETWORK {
        return Err(format!(
            "unexpected validator transport snapshot network {}",
            snapshot.network
        ));
    }
    if snapshot.migration_id != EXPECTED_MIGRATION_ID {
        return Err(format!(
            "unexpected validator transport snapshot migration_id {}",
            snapshot.migration_id
        ));
    }
    if snapshot.configuration_version == 0 {
        return Err(
            "validator transport snapshot generation must be greater than zero".to_string(),
        );
    }
    if snapshot.transports.is_empty() {
        return Err("validator transport snapshot has no transports".to_string());
    }

    let mut map = HashMap::with_capacity(snapshot.transports.len());
    let mut dial_addresses = HashSet::with_capacity(snapshot.transports.len());
    for transport in &snapshot.transports {
        if !is_canonical_validator_address(&transport.validator_address) {
            return Err(format!(
                "invalid validator address {}",
                transport.validator_address
            ));
        }
        if !is_valid_validator_dial_address(&transport.dial_address) {
            return Err(format!(
                "invalid validator dial address {}",
                transport.dial_address
            ));
        }
        if map
            .insert(
                transport.validator_address.clone(),
                transport.dial_address.clone(),
            )
            .is_some()
        {
            return Err(format!(
                "duplicate validator address {}",
                transport.validator_address
            ));
        }
        if !dial_addresses.insert(transport.dial_address.clone()) {
            return Err(format!(
                "duplicate validator dial address {}",
                transport.dial_address
            ));
        }
    }

    let signed_payload = signed_payload_bytes(snapshot)?;
    let signature = decode_signature(&snapshot.signature)?;
    verifying_key
        .verify_strict(&signed_payload, &signature)
        .map_err(|_| "invalid validator transport snapshot signature".to_string())?;
    Ok(map)
}

fn decode_signature(value: &str) -> Result<Signature, String> {
    let encoded = value
        .trim()
        .strip_prefix("ed25519:")
        .ok_or_else(|| "validator transport signature must use the ed25519: prefix".to_string())?;
    let bytes: [u8; 64] = general_purpose::STANDARD
        .decode(encoded)
        .map_err(|error| format!("invalid validator transport signature base64: {error}"))?
        .try_into()
        .map_err(|_| "validator transport signature must decode to 64 bytes".to_string())?;
    Ok(Signature::from_bytes(&bytes))
}

fn signed_payload_bytes(snapshot: &ValidatorTransportSnapshot) -> Result<Vec<u8>, String> {
    serde_json::to_vec(&json!({
        "version": snapshot.version,
        "network": snapshot.network,
        "migration_id": snapshot.migration_id,
        "configuration_version": snapshot.configuration_version,
        "transports": snapshot.transports,
    }))
    .map_err(|error| format!("failed to serialize validator transport signed payload: {error}"))
}

fn persisted_snapshot_path() -> PathBuf {
    crate::utils::resolve_data_path("data/validator_transport_registry.json")
}

fn load_persisted_snapshot(verifying_key: &VerifyingKey) -> Result<(), String> {
    let path = persisted_snapshot_path();
    load_persisted_snapshot_from_path(verifying_key, &path)
}

fn load_persisted_snapshot_from_path(
    verifying_key: &VerifyingKey,
    path: &std::path::Path,
) -> Result<(), String> {
    if !path.is_file() {
        return Ok(());
    }
    let bytes = fs::read(&path).map_err(|error| {
        format!(
            "failed to read persisted validator transport snapshot {}: {error}",
            path.display()
        )
    })?;
    if bytes.len() > MAX_SNAPSHOT_BYTES {
        return Err(format!(
            "persisted validator transport snapshot {} exceeds the size limit",
            path.display()
        ));
    }
    let snapshot =
        serde_json::from_slice::<ValidatorTransportSnapshot>(&bytes).map_err(|error| {
            format!(
                "invalid persisted validator transport snapshot {}: {error}",
                path.display()
            )
        })?;
    let transports = validate_and_verify_snapshot(&snapshot, verifying_key)?;
    let mut state = LAST_KNOWN_GOOD
        .write()
        .map_err(|_| "validator transport registry lock is poisoned".to_string())?;
    install_snapshot_into(
        &mut state,
        &snapshot.migration_id,
        snapshot.configuration_version,
        transports,
    )?;
    Ok(())
}

fn persist_snapshot(snapshot: &ValidatorTransportSnapshot) -> Result<(), String> {
    let path = persisted_snapshot_path();
    let parent = path.parent().ok_or_else(|| {
        format!(
            "invalid validator transport registry path {}",
            path.display()
        )
    })?;
    fs::create_dir_all(parent).map_err(|error| {
        format!(
            "failed to create validator transport registry directory {}: {error}",
            parent.display()
        )
    })?;
    let bytes = serde_json::to_vec(snapshot)
        .map_err(|error| format!("failed to serialize validator transport snapshot: {error}"))?;
    let temp = path.with_extension(format!("json.tmp-{}", std::process::id()));
    fs::write(&temp, bytes).map_err(|error| {
        format!(
            "failed to write validator transport snapshot {}: {error}",
            temp.display()
        )
    })?;
    fs::rename(&temp, &path).map_err(|error| {
        let _ = fs::remove_file(&temp);
        format!(
            "failed to publish validator transport snapshot {}: {error}",
            path.display()
        )
    })
}

fn install_snapshot(
    snapshot: &ValidatorTransportSnapshot,
    transports: HashMap<String, String>,
) -> Result<ValidatorTransportRefresh, String> {
    let mut state = LAST_KNOWN_GOOD
        .write()
        .map_err(|_| "validator transport registry lock is poisoned".to_string())?;
    let previous = state.clone();
    let result = install_snapshot_into(
        &mut state,
        &snapshot.migration_id,
        snapshot.configuration_version,
        transports,
    )?;
    if result.changed {
        if let Err(error) = persist_snapshot(snapshot) {
            *state = previous;
            return Err(error);
        }
    }
    Ok(result)
}

fn install_snapshot_into(
    state: &mut Option<TrustedRegistry>,
    migration_id: &str,
    generation: u64,
    transports: HashMap<String, String>,
) -> Result<ValidatorTransportRefresh, String> {
    match state.as_ref() {
        None => {
            *state = Some(TrustedRegistry {
                migration_id: migration_id.to_string(),
                generation,
                transports,
            });
            Ok(ValidatorTransportRefresh {
                generation,
                changed: true,
            })
        }
        Some(previous) if previous.migration_id != migration_id => Err(format!(
            "validator transport snapshot migration changed from {} to {}",
            previous.migration_id, migration_id
        )),
        Some(previous) if generation < previous.generation => Err(format!(
            "validator transport snapshot rollback: generation {} is older than {}",
            generation, previous.generation
        )),
        Some(previous) if generation == previous.generation => {
            if previous.transports == transports {
                Ok(ValidatorTransportRefresh {
                    generation,
                    changed: false,
                })
            } else {
                Err(format!(
                    "validator transport snapshot equivocation at generation {}",
                    generation
                ))
            }
        }
        Some(_) => {
            *state = Some(TrustedRegistry {
                migration_id: migration_id.to_string(),
                generation,
                transports,
            });
            Ok(ValidatorTransportRefresh {
                generation,
                changed: true,
            })
        }
    }
}

fn is_canonical_validator_address(value: &str) -> bool {
    value.len() >= 8
        && value.len() <= 128
        && value.starts_with("synv1")
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
}

fn is_valid_validator_dial_address(value: &str) -> bool {
    let Some((host, port)) = value.rsplit_once(':') else {
        return false;
    };
    if port != "5622" {
        return false;
    }
    let Some(suffix) = host.strip_prefix("10.70.10.") else {
        return false;
    };
    if suffix.is_empty() || (suffix.len() > 1 && suffix.starts_with('0')) {
        return false;
    }
    suffix
        .parse::<u8>()
        .map(|octet| octet != 0)
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    const TEST_SEED: [u8; 32] = [7; 32];

    fn signed_snapshot(
        signing_key: &SigningKey,
        generation: u64,
        dial_address: &str,
    ) -> ValidatorTransportSnapshot {
        let mut snapshot = ValidatorTransportSnapshot {
            version: EXPECTED_VERSION,
            network: EXPECTED_NETWORK.to_string(),
            migration_id: EXPECTED_MIGRATION_ID.to_string(),
            configuration_version: generation,
            transports: vec![ValidatorTransport {
                validator_address: "synv1validator0001".to_string(),
                dial_address: dial_address.to_string(),
            }],
            signature: String::new(),
        };
        let payload = signed_payload_bytes(&snapshot).unwrap();
        let signature = signing_key.sign(&payload);
        snapshot.signature = format!(
            "ed25519:{}",
            general_purpose::STANDARD.encode(signature.to_bytes())
        );
        snapshot
    }

    fn keypair() -> (SigningKey, VerifyingKey) {
        let signing_key = SigningKey::from_bytes(&TEST_SEED);
        let verifying_key = signing_key.verifying_key();
        (signing_key, verifying_key)
    }

    #[test]
    fn valid_signature_is_accepted() {
        let (signing_key, verifying_key) = keypair();
        let snapshot = signed_snapshot(&signing_key, 1, "10.70.10.1:5622");
        let transports = validate_and_verify_snapshot(&snapshot, &verifying_key).unwrap();
        assert_eq!(
            transports.get("synv1validator0001"),
            Some(&"10.70.10.1:5622".to_string())
        );
    }

    #[test]
    fn tampering_rejection() {
        let (signing_key, verifying_key) = keypair();
        let mut snapshot = signed_snapshot(&signing_key, 1, "10.70.10.1:5622");
        snapshot.migration_id = "tampered".to_string();
        let error = validate_and_verify_snapshot(&snapshot, &verifying_key).unwrap_err();
        assert!(error.contains("migration_id"));
    }

    #[test]
    fn invalid_transport_is_rejected() {
        let (signing_key, verifying_key) = keypair();
        let snapshot = signed_snapshot(&signing_key, 1, "10.70.11.1:5622");
        let error = validate_and_verify_snapshot(&snapshot, &verifying_key).unwrap_err();
        assert!(error.contains("dial address"));
    }

    #[test]
    fn identical_same_generation_is_unchanged() {
        let mut state = None;
        let (signing_key, verifying_key) = keypair();
        let snapshot = signed_snapshot(&signing_key, 7, "10.70.10.7:5622");
        let transports = validate_and_verify_snapshot(&snapshot, &verifying_key).unwrap();
        assert!(
            install_snapshot_into(&mut state, EXPECTED_MIGRATION_ID, 7, transports.clone())
                .unwrap()
                .changed
        );
        let result =
            install_snapshot_into(&mut state, EXPECTED_MIGRATION_ID, 7, transports).unwrap();
        assert_eq!(result.generation, 7);
        assert!(!result.changed);
    }

    #[test]
    fn same_generation_with_different_map_is_equivocation() {
        let mut state = None;
        let (signing_key, verifying_key) = keypair();
        let first = signed_snapshot(&signing_key, 8, "10.70.10.8:5622");
        let second = signed_snapshot(&signing_key, 8, "10.70.10.9:5622");
        let first_transports = validate_and_verify_snapshot(&first, &verifying_key).unwrap();
        let second_transports = validate_and_verify_snapshot(&second, &verifying_key).unwrap();
        install_snapshot_into(&mut state, EXPECTED_MIGRATION_ID, 8, first_transports).unwrap();
        let error = install_snapshot_into(&mut state, EXPECTED_MIGRATION_ID, 8, second_transports)
            .unwrap_err();
        assert!(error.contains("equivocation"));
    }

    #[test]
    fn older_generation_is_rollback() {
        let mut state = None;
        let (signing_key, verifying_key) = keypair();
        let newer = signed_snapshot(&signing_key, 9, "10.70.10.9:5622");
        let older = signed_snapshot(&signing_key, 8, "10.70.10.8:5622");
        let newer_transports = validate_and_verify_snapshot(&newer, &verifying_key).unwrap();
        let older_transports = validate_and_verify_snapshot(&older, &verifying_key).unwrap();
        install_snapshot_into(&mut state, EXPECTED_MIGRATION_ID, 9, newer_transports).unwrap();
        let error = install_snapshot_into(&mut state, EXPECTED_MIGRATION_ID, 8, older_transports)
            .unwrap_err();
        assert!(error.contains("rollback"));
    }

    #[test]
    fn different_migration_is_rejected_even_at_newer_generation() {
        let mut state = None;
        let mut first = HashMap::new();
        first.insert(
            "synv1validator0001".to_string(),
            "10.70.10.1:5622".to_string(),
        );
        install_snapshot_into(&mut state, EXPECTED_MIGRATION_ID, 1, first.clone()).unwrap();
        let error = install_snapshot_into(&mut state, "other-migration", 2, first).unwrap_err();
        assert!(error.contains("migration changed"));
    }

    #[test]
    fn corrupted_persisted_snapshot_fails_closed() {
        let (_signing_key, verifying_key) = keypair();
        let path = crate::utils::test_temp_root(format!(
            "synergy-validator-transport-corrupt-{}-{}.json",
            std::process::id(),
            std::thread::current().name().unwrap_or("test")
        ));
        fs::write(&path, b"{not-valid-json").expect("corrupt snapshot fixture should write");

        let error = load_persisted_snapshot_from_path(&verifying_key, &path)
            .expect_err("corrupted persisted transport state must fail closed");
        assert!(error.contains("invalid persisted validator transport snapshot"));

        let _ = fs::remove_file(path);
    }
}
