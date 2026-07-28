use crate::block::Block;
use crate::consensus::consensus_fork::{
    self, normalize_consensus_key_algorithm, validate_consensus_key_algorithm_for_height,
};
use crate::crypto::pqc::{PQCAlgorithm, PQCManager, PQCPrivateKey, PQCPublicKey, PQCSignature};
use crate::genesis::canonical_genesis;
use crate::synergy_types::TESTNET_V3_MLDSA65_PUBLIC_KEY_BYTES;
use crate::validator::ValidatorManager;
use base64::{engine::general_purpose, Engine as _};
use lazy_static::lazy_static;
use serde_json::Value;
use sha3::{Digest, Sha3_256};
use std::collections::{HashMap, HashSet};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

lazy_static! {
    static ref LOCAL_VALIDATOR_SIGNING_KEYS: Mutex<HashMap<String, (PQCPublicKey, PQCPrivateKey)>> =
        Mutex::new(HashMap::new());
}

pub fn consensus_algorithm_label(algorithm: &PQCAlgorithm) -> &'static str {
    match algorithm {
        PQCAlgorithm::MLDSA65 => "ml-dsa-65",
        PQCAlgorithm::MLDSA87 => "ml-dsa-87",
        PQCAlgorithm::FNDSA => "fn-dsa",
        PQCAlgorithm::SLHDSA => "slh-dsa",
        PQCAlgorithm::MLKEM1024 => "ml-kem-1024",
        PQCAlgorithm::HQCKEM => "hqc-kem",
    }
}

pub fn expected_validator_public_key(
    validator_address: &str,
    validator_manager: &ValidatorManager,
) -> Result<PQCPublicKey, String> {
    expected_validator_public_key_from_registry_at_height(
        None,
        validator_address,
        validator_manager,
    )
}

pub fn expected_validator_public_key_for_height(
    height: u64,
    validator_address: &str,
    validator_manager: &ValidatorManager,
) -> Result<PQCPublicKey, String> {
    match consensus_fork::validator_public_key_for_height(height, validator_address) {
        Ok(Some(fork_key)) => return Ok(fork_key),
        Ok(None) => {}
        Err(error) if is_missing_from_checkpoint_fork(&error, validator_address) => {
            if is_canonical_initial_validator(validator_address)? {
                return Err(error);
            }
        }
        Err(error) => return Err(error),
    }

    let public_key = expected_validator_public_key_from_registry_at_height(
        Some(height),
        validator_address,
        validator_manager,
    )?;
    validate_consensus_key_algorithm_for_height(height, &public_key.algorithm)?;
    Ok(public_key)
}

fn is_missing_from_checkpoint_fork(error: &str, validator_address: &str) -> bool {
    error.contains("post-fork consensus registry missing validator")
        && error.contains(validator_address)
}

fn is_canonical_initial_validator(validator_address: &str) -> Result<bool, String> {
    let genesis = canonical_genesis().map_err(|error| {
        format!("load canonical genesis for checkpoint validator lookup: {error}")
    })?;
    Ok(genesis
        .validators()
        .iter()
        .any(|validator| validator.operator_address == validator_address))
}

fn expected_validator_public_key_from_registry_at_height(
    height: Option<u64>,
    validator_address: &str,
    validator_manager: &ValidatorManager,
) -> Result<PQCPublicKey, String> {
    let validator = validator_manager
        .get_validator(validator_address)
        .ok_or_else(|| format!("validator {validator_address} is not registered"))?;
    parse_validator_public_key(validator_address, &validator.public_key).or_else(|error| {
        if !error.contains("missing consensus key algorithm prefix") {
            return Err(error);
        }
        if is_canonical_initial_validator(validator_address)? {
            return parse_legacy_registry_public_key_with_genesis_algorithm(
                validator_address,
                &validator.public_key,
            );
        }
        let Some(height) = height else {
            return parse_legacy_registry_public_key_with_genesis_algorithm(
                validator_address,
                &validator.public_key,
            );
        };
        parse_onboarded_untyped_registry_public_key_for_height(
            height,
            validator_address,
            &validator.public_key,
        )
    })
}

fn parse_onboarded_untyped_registry_public_key_for_height(
    height: u64,
    validator_address: &str,
    encoded: &str,
) -> Result<PQCPublicKey, String> {
    let Some(migration) = consensus_fork::active_consensus_fork_migration()? else {
        return Err(format!(
            "validator {validator_address} has an untyped onboarded consensus key without an active consensus fork"
        ));
    };
    if !migration.applies_to_height(height) {
        return Err(format!(
            "validator {validator_address} has an untyped onboarded consensus key before consensus fork {}",
            migration.fork_height
        ));
    }
    parse_validator_public_key_with_declared_algorithm(validator_address, encoded, "FN-DSA")
}

pub fn parse_validator_public_key(
    validator_address: &str,
    encoded: &str,
) -> Result<PQCPublicKey, String> {
    parse_validator_public_key_inner(validator_address, encoded, None)
}

pub fn parse_validator_public_key_with_declared_algorithm(
    validator_address: &str,
    encoded: &str,
    algorithm_label: &str,
) -> Result<PQCPublicKey, String> {
    parse_validator_public_key_inner(validator_address, encoded, Some(algorithm_label))
}

pub fn validator_public_key_with_declared_algorithm(
    validator_address: &str,
    encoded: &str,
    algorithm_label: &str,
) -> Result<String, String> {
    let public_key = parse_validator_public_key_with_declared_algorithm(
        validator_address,
        encoded,
        algorithm_label,
    )?;
    Ok(format!(
        "{}:{}",
        consensus_algorithm_label(&public_key.algorithm),
        general_purpose::STANDARD.encode(public_key.key_data)
    ))
}

fn parse_legacy_registry_public_key_with_genesis_algorithm(
    validator_address: &str,
    encoded: &str,
) -> Result<PQCPublicKey, String> {
    let genesis = canonical_genesis()
        .map_err(|error| format!("load canonical genesis for legacy validator key: {error}"))?;
    let Some(initial_validator) = genesis
        .validators()
        .iter()
        .find(|validator| validator.operator_address == validator_address)
    else {
        return Err(format!(
            "validator {validator_address} has an untyped consensus key and is not present in canonical genesis"
        ));
    };

    let registry_key = parse_validator_public_key_with_declared_algorithm(
        validator_address,
        encoded,
        &initial_validator.consensus_key_type,
    )?;
    let canonical_key = parse_validator_public_key_with_declared_algorithm(
        validator_address,
        &initial_validator.consensus_public_key,
        &initial_validator.consensus_key_type,
    )?;
    if registry_key.key_data != canonical_key.key_data
        || registry_key.algorithm != canonical_key.algorithm
    {
        return Err(format!(
            "validator {validator_address} untyped legacy registry key does not match canonical genesis"
        ));
    }
    Ok(registry_key)
}

fn parse_validator_public_key_inner(
    validator_address: &str,
    encoded: &str,
    declared_algorithm_label: Option<&str>,
) -> Result<PQCPublicKey, String> {
    let encoded = encoded.trim();
    if encoded.is_empty() {
        return Err(format!(
            "validator {validator_address} is missing consensus public key"
        ));
    }

    let (algorithm, material) =
        split_algorithm_prefix(encoded, declared_algorithm_label).map_err(|error| {
            format!("validator {validator_address} consensus key algorithm is invalid: {error}")
        })?;
    if algorithm != PQCAlgorithm::MLDSA65 {
        return Err(format!(
            "validator {validator_address} consensus key algorithm must be ML-DSA-65"
        ));
    }
    let key_data = decode_key_material(material).map_err(|error| {
        format!("validator {validator_address} consensus public key is invalid: {error}")
    })?;
    if key_data.is_empty() {
        return Err(format!(
            "validator {validator_address} consensus public key is empty"
        ));
    }
    if key_data.len() != TESTNET_V3_MLDSA65_PUBLIC_KEY_BYTES {
        return Err(format!(
            "validator {validator_address} ML-DSA-65 consensus public key must be exactly {TESTNET_V3_MLDSA65_PUBLIC_KEY_BYTES} bytes"
        ));
    }

    Ok(PQCPublicKey {
        algorithm,
        key_data,
        key_id: format!("validator-consensus:{validator_address}"),
        created_at: 0,
    })
}

pub fn verify_signer_key_matches_validator(
    validator_address: &str,
    signer_public_key: &[u8],
    validator_manager: &ValidatorManager,
) -> Result<PQCPublicKey, String> {
    verify_signer_key_matches_validator_at_height(
        0,
        validator_address,
        signer_public_key,
        validator_manager,
    )
}

pub fn verify_signer_key_matches_validator_at_height(
    height: u64,
    validator_address: &str,
    signer_public_key: &[u8],
    validator_manager: &ValidatorManager,
) -> Result<PQCPublicKey, String> {
    let expected =
        expected_validator_public_key_for_height(height, validator_address, validator_manager)?;
    if signer_public_key != expected.key_data.as_slice() {
        return Err(format!(
            "signer public key does not match canonical consensus key for validator {validator_address}"
        ));
    }
    validate_consensus_key_algorithm_for_height(height, &expected.algorithm)?;
    Ok(expected)
}

pub fn verify_block_proposer_key_matches_validator(
    block: &Block,
    validator_manager: &ValidatorManager,
) -> Result<(), String> {
    if block.block_index == 0 {
        return Ok(());
    }

    let expected = verify_signer_key_matches_validator_at_height(
        block.block_index,
        &block.validator_id,
        &block.proposer_public_key,
        validator_manager,
    )?;
    let block_algorithm = block_signature_algorithm(&block.block_signature_algorithm)?;
    validate_consensus_key_algorithm_for_height(block.block_index, &block_algorithm)?;
    if block_algorithm != expected.algorithm {
        return Err(format!(
            "block proposer signature algorithm does not match canonical consensus key for validator {}",
            block.validator_id
        ));
    }
    Ok(())
}

pub fn sign_with_local_validator_key(
    validator_address: &str,
    message: &[u8],
    validator_manager: &ValidatorManager,
) -> Result<(PQCPublicKey, PQCSignature), String> {
    sign_with_local_validator_key_for_height(0, validator_address, message, validator_manager)
}

pub fn sign_with_local_validator_key_for_height(
    height: u64,
    validator_address: &str,
    message: &[u8],
    validator_manager: &ValidatorManager,
) -> Result<(PQCPublicKey, PQCSignature), String> {
    let expected =
        expected_validator_public_key_for_height(height, validator_address, validator_manager)?;
    validate_consensus_key_algorithm_for_height(height, &expected.algorithm)?;
    let private_key = load_local_validator_private_key(validator_address, &expected)?;
    let mut pqc_manager = PQCManager::new();
    let signature = pqc_manager.sign(&private_key, message)?;
    Ok((expected, signature))
}

pub fn load_local_validator_keypair(
    validator_address: &str,
    validator_manager: &ValidatorManager,
) -> Result<(PQCPublicKey, PQCPrivateKey), String> {
    load_local_validator_keypair_for_height(0, validator_address, validator_manager)
}

pub fn load_local_validator_keypair_for_height(
    height: u64,
    validator_address: &str,
    validator_manager: &ValidatorManager,
) -> Result<(PQCPublicKey, PQCPrivateKey), String> {
    let expected =
        expected_validator_public_key_for_height(height, validator_address, validator_manager)?;
    validate_consensus_key_algorithm_for_height(height, &expected.algorithm)?;
    let private_key = load_local_validator_private_key(validator_address, &expected)?;
    Ok((expected, private_key))
}

fn load_local_validator_private_key(
    validator_address: &str,
    expected_public_key: &PQCPublicKey,
) -> Result<PQCPrivateKey, String> {
    if let Ok(cache) = LOCAL_VALIDATOR_SIGNING_KEYS.lock() {
        if let Some((cached_public, cached_private)) = cache.get(validator_address) {
            if cached_public.key_data == expected_public_key.key_data
                && cached_public.algorithm == expected_public_key.algorithm
            {
                ensure_private_key_matches_public_key(
                    validator_address,
                    expected_public_key,
                    cached_private,
                )?;
                return Ok(cached_private.clone());
            }
        }
    }

    let private_key = load_private_key_from_config(validator_address, expected_public_key)?;
    ensure_private_key_matches_public_key(validator_address, expected_public_key, &private_key)?;

    if let Ok(mut cache) = LOCAL_VALIDATOR_SIGNING_KEYS.lock() {
        cache.insert(
            validator_address.to_string(),
            (expected_public_key.clone(), private_key.clone()),
        );
    }

    Ok(private_key)
}

fn load_private_key_from_config(
    validator_address: &str,
    expected_public_key: &PQCPublicKey,
) -> Result<PQCPrivateKey, String> {
    let mut errors = Vec::new();
    for key in [
        "SYNERGY_VALIDATOR_CONSENSUS_PRIVATE_KEY_B64",
        "SYNERGY_CONSENSUS_PRIVATE_KEY_B64",
    ] {
        if let Ok(value) = env::var(key) {
            let value = value.trim();
            if !value.is_empty() {
                match private_key_from_encoded(expected_public_key, value, format!("env:{key}"))
                    .and_then(|private_key| {
                        ensure_private_key_matches_public_key(
                            validator_address,
                            expected_public_key,
                            &private_key,
                        )?;
                        Ok(private_key)
                    }) {
                    Ok(private_key) => return Ok(private_key),
                    Err(error) => errors.push(error),
                }
            }
        }
    }

    for path in candidate_private_key_paths(expected_public_key) {
        if let Ok(encoded) = fs::read_to_string(&path) {
            let encoded = encoded.trim();
            if !encoded.is_empty() {
                match private_key_from_encoded(
                    expected_public_key,
                    encoded,
                    path.display().to_string(),
                )
                .and_then(|private_key| {
                    ensure_private_key_matches_public_key(
                        validator_address,
                        expected_public_key,
                        &private_key,
                    )?;
                    Ok(private_key)
                }) {
                    Ok(private_key) => return Ok(private_key),
                    Err(error) => errors.push(error),
                }
            }
        }
    }

    for identity_path in candidate_identity_paths() {
        if let Ok(identity) = fs::read_to_string(&identity_path) {
            if let Ok(json) = serde_json::from_str::<Value>(&identity) {
                for encoded in consensus_private_key_candidates(&json, &identity_path) {
                    if !encoded.trim().is_empty() {
                        match private_key_from_encoded(
                            expected_public_key,
                            encoded.trim(),
                            identity_path.display().to_string(),
                        )
                        .and_then(|private_key| {
                            ensure_private_key_matches_public_key(
                                validator_address,
                                expected_public_key,
                                &private_key,
                            )?;
                            Ok(private_key)
                        }) {
                            Ok(private_key) => return Ok(private_key),
                            Err(error) => errors.push(error),
                        }
                    }
                }
            }
        }
    }

    let detail = if errors.is_empty() {
        "no readable non-empty key candidates".to_string()
    } else {
        format!("candidate errors: {}", errors.join("; "))
    };
    Err(format!(
        "Aegis PQC consensus private key unavailable for validator {validator_address}; set SYNERGY_VALIDATOR_MLDSA65_CONSENSUS_PRIVATE_KEY_FILE, SYNERGY_VALIDATOR_CONSENSUS_PRIVATE_KEY_FILE, or SYNERGY_VALIDATOR_CONSENSUS_PRIVATE_KEY_B64 ({detail})"
    ))
}

fn private_key_from_encoded(
    expected_public_key: &PQCPublicKey,
    encoded: &str,
    source: String,
) -> Result<PQCPrivateKey, String> {
    let key_data = decode_key_material(encoded)
        .map_err(|error| format!("invalid Aegis PQC consensus private key in {source}: {error}"))?;
    if key_data.is_empty() {
        return Err(format!("empty Aegis PQC consensus private key in {source}"));
    }

    Ok(PQCPrivateKey {
        algorithm: expected_public_key.algorithm.clone(),
        key_data,
        public_key_id: expected_public_key.key_id.clone(),
        created_at: 0,
    })
}

fn ensure_private_key_matches_public_key(
    validator_address: &str,
    expected_public_key: &PQCPublicKey,
    private_key: &PQCPrivateKey,
) -> Result<(), String> {
    if expected_public_key.algorithm != private_key.algorithm {
        return Err(format!(
            "Aegis PQC consensus private key algorithm does not match canonical public key for validator {validator_address}"
        ));
    }

    if expected_public_key.algorithm != PQCAlgorithm::MLDSA65 {
        return Err(format!(
            "Aegis PQC consensus key self-test for validator {validator_address} requires ML-DSA-65"
        ));
    }

    let challenge = local_key_binding_challenge(validator_address, expected_public_key);
    let mut pqc_manager = PQCManager::new();
    let signature = pqc_manager.sign(private_key, &challenge).map_err(|error| {
        format!("Aegis PQC consensus key self-test signing failed for {validator_address}: {error}")
    })?;
    pqc_manager
        .verify(expected_public_key, &signature, &challenge)
        .map_err(|error| {
            format!(
                "Aegis PQC consensus key self-test verification failed for {validator_address}: {error}"
            )
        })
        .and_then(|valid| {
            if valid {
                Ok(())
            } else {
                Err(format!(
                    "Aegis PQC consensus private key does not match canonical public key for validator {validator_address}"
                ))
            }
        })
}

fn local_key_binding_challenge(
    validator_address: &str,
    expected_public_key: &PQCPublicKey,
) -> Vec<u8> {
    let mut hasher = Sha3_256::new();
    hasher.update(b"SYNERGY_CONSENSUS_KEY_BINDING_V1");
    hasher.update(validator_address.as_bytes());
    hasher.update(consensus_algorithm_label(&expected_public_key.algorithm).as_bytes());
    hasher.update(&expected_public_key.key_data);
    hasher.finalize().to_vec()
}

fn candidate_private_key_paths(expected_public_key: &PQCPublicKey) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    let mut seen = HashSet::new();
    let mut push_path = |path: PathBuf| {
        if seen.insert(path.clone()) {
            paths.push(path);
        }
    };

    if expected_public_key.algorithm == PQCAlgorithm::MLDSA65 {
        for key in [
            "SYNERGY_VALIDATOR_MLDSA65_CONSENSUS_PRIVATE_KEY_FILE",
            "SYNERGY_MLDSA65_CONSENSUS_PRIVATE_KEY_FILE",
        ] {
            if let Ok(path) = env::var(key) {
                push_private_key_path_variants(&mut push_path, path.trim());
            }
        }
        for path in [
            "config/validator/mldsa65-consensus.private.key",
            "config/validator/mldsa65.private.key",
            "keys/mldsa65-consensus/private.key",
            "keys/mldsa65.private.key",
            "keys/mldsa65_private.key",
        ] {
            push_private_key_path_variants(&mut push_path, path);
        }
    } else if expected_public_key.algorithm == PQCAlgorithm::FNDSA {
        for key in [
            "SYNERGY_VALIDATOR_FNDSA_CONSENSUS_PRIVATE_KEY_FILE",
            "SYNERGY_FNDSA_CONSENSUS_PRIVATE_KEY_FILE",
        ] {
            if let Ok(path) = env::var(key) {
                push_private_key_path_variants(&mut push_path, path.trim());
            }
        }
        if let Ok(Some(migration)) = consensus_fork::active_consensus_fork_migration() {
            for path in fork_consensus_private_key_paths(migration.fork_height) {
                push_private_key_path_variants(&mut push_path, &path);
            }
        }
        for path in [
            "config/validator/fndsa-consensus.private.key",
            "config/validator/fndsa.private.key",
            "keys/fndsa-consensus/private.key",
            "keys/fndsa.private.key",
            "keys/fndsa_private.key",
        ] {
            push_private_key_path_variants(&mut push_path, path);
        }
    }

    for key in [
        "SYNERGY_VALIDATOR_CONSENSUS_PRIVATE_KEY_FILE",
        "SYNERGY_CONSENSUS_PRIVATE_KEY_FILE",
        "SYNERGY_VALIDATOR_PRIVATE_KEY_FILE",
        "PRIVATE_KEY_FILE",
    ] {
        if let Ok(path) = env::var(key) {
            push_private_key_path_variants(&mut push_path, path.trim());
        }
    }
    for path in [
        "config/validator/consensus.private.key",
        "config/validator/consensus_private.key",
        "config/validator/private_key.txt",
        "keys/private.key",
    ] {
        push_private_key_path_variants(&mut push_path, path);
    }
    paths
}

fn fork_consensus_private_key_paths(fork_height: u64) -> [String; 2] {
    [
        format!("config/validator/fndsa-consensus-fork-{fork_height}/private.key"),
        format!("keys/fndsa-consensus-fork-{fork_height}/private.key"),
    ]
}

fn push_private_key_path_variants(push_path: &mut impl FnMut(PathBuf), raw_path: &str) {
    if raw_path.is_empty() {
        return;
    }
    let path = PathBuf::from(raw_path);
    if path.is_absolute() {
        push_path(path);
        return;
    }

    push_path(path.clone());
    for root in runtime_path_roots() {
        push_path(root.join(&path));
    }
}

fn runtime_path_roots() -> Vec<PathBuf> {
    let mut roots = Vec::new();
    let mut seen = HashSet::new();
    let mut push_root = |root: PathBuf| {
        if seen.insert(root.clone()) {
            roots.push(root);
        }
    };

    if let Ok(cwd) = env::current_dir() {
        push_root(cwd);
    }
    for root in workspace_roots_from_config_args(env::args()) {
        push_root(root);
    }
    if let Ok(exe) = env::current_exe() {
        if let Some(bin_dir) = exe.parent() {
            if bin_dir.file_name().and_then(|name| name.to_str()) == Some("bin") {
                if let Some(workspace) = bin_dir.parent() {
                    push_root(workspace.to_path_buf());
                }
            }
        }
    }
    if let Ok(root) = env::var("SYNERGY_PROJECT_ROOT") {
        let root = root.trim();
        if !root.is_empty() {
            push_root(PathBuf::from(root));
        }
    }
    if let Ok(config_path) = env::var("SYNERGY_CONFIG_PATH") {
        let config_path = config_path.trim();
        if !config_path.is_empty() {
            let path = PathBuf::from(config_path);
            if let Some(config_dir) = path.parent() {
                if let Some(root) = config_dir.parent() {
                    push_root(root.to_path_buf());
                }
            }
        }
    }
    roots
}

fn workspace_roots_from_config_args<I>(args: I) -> Vec<PathBuf>
where
    I: IntoIterator<Item = String>,
{
    let mut roots = Vec::new();
    let mut iter = args.into_iter();
    while let Some(arg) = iter.next() {
        let config_path = if arg == "--config" {
            iter.next()
        } else {
            arg.strip_prefix("--config=").map(str::to_string)
        };
        if let Some(config_path) = config_path {
            if let Some(root) = workspace_root_from_config_path(&PathBuf::from(config_path)) {
                roots.push(root);
            }
        }
    }
    roots
}

fn workspace_root_from_config_path(config_path: &Path) -> Option<PathBuf> {
    let config_dir = config_path.parent()?;
    if config_dir.file_name().and_then(|name| name.to_str()) == Some("config") {
        return config_dir.parent().map(Path::to_path_buf);
    }
    Some(config_dir.to_path_buf())
}

fn candidate_identity_paths() -> Vec<PathBuf> {
    let mut paths = Vec::new();
    for key in [
        "SYNERGY_VALIDATOR_IDENTITY_FILE",
        "SYNERGY_NODE_IDENTITY_FILE",
        "SYNERGY_IDENTITY_FILE",
    ] {
        if let Ok(path) = env::var(key) {
            let path = path.trim();
            if !path.is_empty() {
                paths.push(PathBuf::from(path));
            }
        }
    }
    paths.extend([
        PathBuf::from("config/validator/identity.json"),
        PathBuf::from("config/identity.json"),
        PathBuf::from("keys/identity.json"),
    ]);
    paths
}

fn consensus_private_key_candidates(json: &Value, identity_path: &Path) -> Vec<String> {
    let mut values = Vec::new();
    for path in [
        &["consensus_key", "private_key"][..],
        &["consensus_private_key"][..],
        &["keys", "consensus_private_key"][..],
        &["keys", "private_key"][..],
        &["private_key"][..],
    ] {
        if let Some(value) = json_path_string(json, path) {
            values.push(value);
        }
    }

    if let Some(parent) = identity_path.parent() {
        for filename in [
            "consensus.private.key",
            "consensus_private.key",
            "consensus.key",
            "private.key",
        ] {
            if let Ok(value) = fs::read_to_string(parent.join(filename)) {
                values.push(value.trim().to_string());
            }
        }
    }

    values
}

fn json_path_string(value: &Value, path: &[&str]) -> Option<String> {
    let mut current = value;
    for key in path {
        current = current.get(*key)?;
    }
    current.as_str().map(str::to_string)
}

fn split_algorithm_prefix<'a>(
    encoded: &'a str,
    declared_algorithm_label: Option<&str>,
) -> Result<(PQCAlgorithm, &'a str), String> {
    if let Some((prefix, material)) = encoded.split_once(':') {
        let encoded_algorithm = algorithm_from_label(prefix)?;
        if let Some(label) = declared_algorithm_label {
            let declared_algorithm = algorithm_from_label(label)?;
            if encoded_algorithm != declared_algorithm {
                return Err(format!(
                    "prefixed algorithm '{}' does not match declared algorithm '{}'",
                    prefix.trim(),
                    label.trim()
                ));
            }
        }
        return Ok((encoded_algorithm, material.trim()));
    }

    let Some(label) = declared_algorithm_label else {
        return Err(
            "missing consensus key algorithm prefix; expected ml-dsa-65:<base64>".to_string(),
        );
    };
    Ok((algorithm_from_label(label)?, encoded))
}

pub(crate) fn block_signature_algorithm(label: &str) -> Result<PQCAlgorithm, String> {
    algorithm_from_label(label)
        .map_err(|error| format!("unsupported block signature algorithm: {error}"))
}

fn algorithm_from_label(label: &str) -> Result<PQCAlgorithm, String> {
    match label.trim().to_ascii_lowercase().as_str() {
        "mldsa65" | "ml-dsa-65" | "ml_dsa_65" => return Ok(PQCAlgorithm::MLDSA65),
        _ => {}
    }
    // The historical migration parser stays FN-DSA-only by design.  New
    // Testnet-v3 genesis keys are parsed here before that legacy parser is
    // consulted, so they cannot be reinterpreted as an old fork key.
    normalize_consensus_key_algorithm(label)
}

fn decode_key_material(encoded: &str) -> Result<Vec<u8>, String> {
    let normalized = encoded
        .trim()
        .trim_matches('"')
        .trim_start_matches("0x")
        .trim();
    if normalized.is_empty() {
        return Err("empty key material".to_string());
    }

    if normalized.len() % 2 == 0 && normalized.chars().all(|ch| ch.is_ascii_hexdigit()) {
        if let Ok(bytes) = hex::decode(normalized) {
            return Ok(bytes);
        }
    }

    general_purpose::STANDARD
        .decode(normalized.as_bytes())
        .map_err(|error| error.to_string())
}

#[cfg(test)]
pub(crate) fn register_test_validator_signing_key(
    validator_address: &str,
    public_key: PQCPublicKey,
    private_key: PQCPrivateKey,
) {
    LOCAL_VALIDATOR_SIGNING_KEYS
        .lock()
        .expect("test validator key cache lock")
        .insert(validator_address.to_string(), (public_key, private_key));
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestConsensusForkEnv {
        previous: Option<String>,
    }

    impl Drop for TestConsensusForkEnv {
        fn drop(&mut self) {
            match self.previous.take() {
                Some(value) => env::set_var(consensus_fork::CONSENSUS_FORK_MIGRATION_ENV, value),
                None => env::remove_var(consensus_fork::CONSENSUS_FORK_MIGRATION_ENV),
            }
        }
    }

    fn install_test_consensus_fork(entries: Vec<serde_json::Value>) -> TestConsensusForkEnv {
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let dir = crate::utils::test_temp_root(format!(
            "synergy-validator-keys-fork-test-{}-{stamp}",
            std::process::id()
        ));
        fs::create_dir_all(&dir).expect("create test fork directory");
        let path = dir.join("consensus-fork-migration.json");
        let payload = serde_json::json!({
            "fork_height": 204216,
            "parent_height": 204215,
            "parent_hash": "e209bd7554a06dfb052d5ff7ffd5664efc05e6cd1c5cadc9d139fa5bb9072816",
            "state_root": "test-state-root",
            "old_consensus_algorithm": "FN-DSA",
            "new_consensus_algorithm": "FN-DSA",
            "new_validator_registry": entries,
            "migration_reason": "unit test checkpoint fork",
            "parser_mode": "fail_closed"
        });
        fs::write(&path, serde_json::to_string_pretty(&payload).unwrap())
            .expect("write test fork file");
        let previous = env::var(consensus_fork::CONSENSUS_FORK_MIGRATION_ENV).ok();
        env::set_var(consensus_fork::CONSENSUS_FORK_MIGRATION_ENV, &path);
        TestConsensusForkEnv { previous }
    }

    fn fork_entry(validator_address: &str, key_byte: u8) -> serde_json::Value {
        serde_json::json!({
            "validator_address": validator_address,
            "consensus_key_type": "FN-DSA",
            "consensus_public_key": format!(
                "fn-dsa:{}",
                general_purpose::STANDARD.encode(vec![key_byte; 128])
            )
        })
    }

    #[test]
    fn candidate_private_key_paths_include_workspace_key_file() {
        let paths = candidate_private_key_paths(&PQCPublicKey {
            algorithm: PQCAlgorithm::FNDSA,
            key_data: vec![1, 2, 3],
            key_id: "test".to_string(),
            created_at: 0,
        });

        assert!(
            paths
                .iter()
                .any(|path| path == Path::new("keys/private.key")),
            "validator startup must discover the control-panel workspace private key path"
        );
        assert!(
            paths
                .iter()
                .any(|path| path == Path::new("keys/fndsa-consensus/private.key")),
            "post-fork FN-DSA signing must prefer explicit FN-DSA consensus key material"
        );
    }

    #[test]
    fn fork_private_key_paths_include_live_migration_directory() {
        let paths = fork_consensus_private_key_paths(204_216);

        assert!(paths
            .iter()
            .any(|path| path == "keys/fndsa-consensus-fork-204216/private.key"));
    }

    #[test]
    fn workspace_roots_include_config_arg_workspace() {
        let roots = workspace_roots_from_config_args([
            "synergy-testnet-linux-amd64".to_string(),
            "start".to_string(),
            "--config".to_string(),
            "/opt/synergy/testnet/validator/config/node.toml".to_string(),
        ]);

        assert!(roots
            .iter()
            .any(|path| path == Path::new("/opt/synergy/testnet/validator")));
    }

    #[test]
    fn parses_explicit_mldsa65_validator_public_key_prefix() {
        let key_bytes = vec![1; TESTNET_V3_MLDSA65_PUBLIC_KEY_BYTES];
        let encoded = format!("mldsa65:{}", general_purpose::STANDARD.encode(&key_bytes));
        let key = parse_validator_public_key("synval1test", &encoded).unwrap();

        assert_eq!(key.algorithm, PQCAlgorithm::MLDSA65);
        assert_eq!(key.key_data, key_bytes);
    }

    #[test]
    fn rejects_unprefixed_validator_public_key_without_declared_algorithm() {
        let encoded = general_purpose::STANDARD.encode([1, 2, 3, 4]);
        let error = parse_validator_public_key("synval1test", &encoded).unwrap_err();

        assert!(error.contains("missing consensus key algorithm prefix"));
    }

    #[test]
    fn parses_unprefixed_genesis_public_key_only_with_declared_algorithm() {
        let key_bytes = vec![2; TESTNET_V3_MLDSA65_PUBLIC_KEY_BYTES];
        let encoded = general_purpose::STANDARD.encode(&key_bytes);
        let key = parse_validator_public_key_with_declared_algorithm(
            "synval1test",
            &encoded,
            "ML-DSA-65",
        )
        .unwrap();

        assert_eq!(key.algorithm, PQCAlgorithm::MLDSA65);
        assert_eq!(key.key_data, key_bytes);
    }

    #[test]
    fn parses_live_ml_dsa65_declared_genesis_public_key_as_mldsa65() {
        let key_bytes = vec![3; TESTNET_V3_MLDSA65_PUBLIC_KEY_BYTES];
        let encoded = general_purpose::STANDARD.encode(&key_bytes);
        let key = parse_validator_public_key_with_declared_algorithm(
            "synval1test",
            &encoded,
            "ml-dsa-65",
        )
        .unwrap();

        assert_eq!(key.algorithm, PQCAlgorithm::MLDSA65);
        assert_eq!(key.key_data, key_bytes);
    }

    #[test]
    fn rejects_wrong_length_mldsa65_validator_public_key() {
        let encoded = general_purpose::STANDARD.encode([1, 2, 3, 4]);
        let error = parse_validator_public_key_with_declared_algorithm(
            "synval1test",
            &encoded,
            "ML-DSA-65",
        )
        .unwrap_err();

        assert!(error.contains("must be exactly 1952 bytes"));
    }

    #[test]
    fn testnet_v3_candidate_consensus_keys_parse_as_mldsa65() {
        let candidate: Value = serde_json::from_str(include_str!(
            "../../../genesis.testnet-v3.identity-assigned.json"
        ))
        .expect("candidate genesis must be valid JSON");
        for (group_name, expected_count) in [("validators", 6), ("preconfigured_validators", 21)] {
            let validators = candidate[group_name]
                .as_array()
                .expect("candidate validators must be an array");

            assert_eq!(validators.len(), expected_count);
            for validator in validators {
                let address = validator["operator_address"]
                    .as_str()
                    .expect("candidate operator address must be a string");
                let key = validator["consensus_public_key"]
                    .as_str()
                    .expect("candidate consensus public key must be a string");
                let algorithm = validator["consensus_key_type"]
                    .as_str()
                    .expect("candidate consensus key type must be a string");
                let parsed =
                    parse_validator_public_key_with_declared_algorithm(address, key, algorithm)
                        .expect("candidate consensus key must parse");

                assert_eq!(parsed.algorithm, PQCAlgorithm::MLDSA65);
                assert_eq!(parsed.key_data.len(), 1_952);
            }
        }
    }

    #[test]
    fn rejects_mismatched_prefixed_and_declared_validator_algorithms() {
        let encoded = format!("slh-dsa:{}", general_purpose::STANDARD.encode([1, 2, 3, 4]));
        let error =
            parse_validator_public_key_with_declared_algorithm("synval1test", &encoded, "falcon")
                .unwrap_err();

        assert!(error.contains("does not match declared algorithm"));
    }

    #[test]
    fn rejects_unsupported_validator_public_key_prefix() {
        let encoded = format!(
            "unsupported-signature:{}",
            general_purpose::STANDARD.encode([1, 2, 3, 4])
        );
        let error = parse_validator_public_key("synval1test", &encoded).unwrap_err();

        assert!(
            error.contains("must be ML-DSA-65")
                || error.contains("unsupported consensus key algorithm")
        );
    }

    #[test]
    fn prefixes_declared_validator_public_key_for_registry_storage() {
        let encoded =
            general_purpose::STANDARD.encode(vec![4; TESTNET_V3_MLDSA65_PUBLIC_KEY_BYTES]);
        let prefixed =
            validator_public_key_with_declared_algorithm("synval1test", &encoded, "ML-DSA-65")
                .unwrap();

        assert_eq!(prefixed, format!("ml-dsa-65:{encoded}"));
    }
}
