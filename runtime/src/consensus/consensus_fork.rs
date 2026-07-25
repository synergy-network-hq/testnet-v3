use crate::crypto::pqc::{PQCAlgorithm, PQCPublicKey};
use base64::{engine::general_purpose, Engine as _};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
#[cfg(test)]
use std::cell::RefCell;
use std::collections::BTreeSet;
use std::env;
use std::fs;
use std::path::PathBuf;

pub const CONSENSUS_FORK_MIGRATION_ENV: &str = "SYNERGY_CONSENSUS_FORK_MIGRATION_FILE";
pub const DEFAULT_CONSENSUS_FORK_MIGRATION_PATH: &str = "config/consensus-fork-migration.json";
pub const CONSENSUS_FORK_PARSER_MODE_FAIL_CLOSED: &str = "fail_closed";
pub const LEGACY_CONSENSUS_ALGORITHM_LABEL: &str = "FN-DSA";
pub const POST_FORK_CONSENSUS_ALGORITHM_LABEL: &str = "FN-DSA";

#[cfg(test)]
thread_local! {
    static TEST_ACTIVE_CONSENSUS_FORK_MIGRATION: RefCell<Option<ConsensusForkMigration>> =
        const { RefCell::new(None) };
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsensusForkMigration {
    pub fork_height: u64,
    pub parent_height: u64,
    pub parent_hash: String,
    pub state_root: String,
    pub old_consensus_algorithm: String,
    pub new_consensus_algorithm: String,
    pub new_validator_registry: Vec<ForkValidatorConsensusKey>,
    pub migration_reason: String,
    pub parser_mode: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub migration_signature: Option<Value>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForkValidatorConsensusKey {
    #[serde(alias = "address", alias = "operator_address", alias = "validator_id")]
    pub validator_address: String,
    pub consensus_key_type: String,
    pub consensus_public_key: String,
}

#[cfg(test)]
pub struct TestConsensusForkMigrationGuard;

#[cfg(test)]
impl Drop for TestConsensusForkMigrationGuard {
    fn drop(&mut self) {
        TEST_ACTIVE_CONSENSUS_FORK_MIGRATION.with(|slot| {
            *slot.borrow_mut() = None;
        });
    }
}

#[cfg(test)]
pub fn set_test_active_consensus_fork_migration(
    migration: ConsensusForkMigration,
) -> TestConsensusForkMigrationGuard {
    TEST_ACTIVE_CONSENSUS_FORK_MIGRATION.with(|slot| {
        *slot.borrow_mut() = Some(migration);
    });
    TestConsensusForkMigrationGuard
}

impl ConsensusForkMigration {
    pub fn validate(&self) -> Result<(), String> {
        if self.fork_height != self.parent_height.saturating_add(1) {
            return Err("fork_height must equal parent_height + 1".to_string());
        }
        require_non_empty("parent_hash", &self.parent_hash)?;
        require_non_empty("state_root", &self.state_root)?;
        require_non_empty("migration_reason", &self.migration_reason)?;
        if self.parser_mode.trim() != CONSENSUS_FORK_PARSER_MODE_FAIL_CLOSED {
            return Err("consensus fork parser_mode must be fail_closed".to_string());
        }
        let old_algorithm = normalize_consensus_key_algorithm(&self.old_consensus_algorithm)?;
        if old_algorithm != PQCAlgorithm::FNDSA {
            return Err("old_consensus_algorithm must resolve to FN-DSA".to_string());
        }
        let new_algorithm = normalize_consensus_key_algorithm(&self.new_consensus_algorithm)?;
        if new_algorithm != PQCAlgorithm::FNDSA {
            return Err("new_consensus_algorithm must resolve to FN-DSA".to_string());
        }
        if self.new_validator_registry.is_empty() {
            return Err("new_validator_registry must not be empty".to_string());
        }

        let mut seen = BTreeSet::new();
        for validator in &self.new_validator_registry {
            validator.validate()?;
            if !seen.insert(validator.validator_address.clone()) {
                return Err(format!(
                    "new_validator_registry contains duplicate validator {}",
                    validator.validator_address
                ));
            }
        }
        Ok(())
    }

    pub fn applies_to_height(&self, height: u64) -> bool {
        height >= self.fork_height
    }

    pub fn validator_public_key(&self, validator_address: &str) -> Result<PQCPublicKey, String> {
        self.validate()?;
        let validator = self
            .new_validator_registry
            .iter()
            .find(|entry| entry.validator_address == validator_address)
            .ok_or_else(|| {
                format!("post-fork consensus registry missing validator {validator_address}")
            })?;
        let (algorithm, key_data) = parse_consensus_public_key_material(
            &validator.validator_address,
            &validator.consensus_public_key,
            Some(&validator.consensus_key_type),
        )?;
        if algorithm != PQCAlgorithm::FNDSA {
            return Err(format!(
                "post-fork validator {} consensus key is not FN-DSA",
                validator.validator_address
            ));
        }
        Ok(PQCPublicKey {
            algorithm,
            key_data,
            key_id: format!("validator-consensus:{validator_address}"),
            created_at: self.fork_height,
        })
    }
}

impl ForkValidatorConsensusKey {
    pub fn validate(&self) -> Result<(), String> {
        require_non_empty("validator_address", &self.validator_address)?;
        require_non_empty("consensus_key_type", &self.consensus_key_type)?;
        require_non_empty("consensus_public_key", &self.consensus_public_key)?;
        let (algorithm, key_data) = parse_consensus_public_key_material(
            &self.validator_address,
            &self.consensus_public_key,
            Some(&self.consensus_key_type),
        )?;
        if algorithm != PQCAlgorithm::FNDSA {
            return Err(format!(
                "post-fork validator {} consensus_key_type must be FN-DSA",
                self.validator_address
            ));
        }
        if key_data.is_empty() {
            return Err(format!(
                "post-fork validator {} consensus_public_key is empty",
                self.validator_address
            ));
        }
        Ok(())
    }
}

pub fn active_consensus_fork_migration() -> Result<Option<ConsensusForkMigration>, String> {
    #[cfg(test)]
    if let Some(migration) = TEST_ACTIVE_CONSENSUS_FORK_MIGRATION.with(|slot| slot.borrow().clone())
    {
        migration
            .validate()
            .map_err(|error| format!("invalid test consensus fork migration: {error}"))?;
        return Ok(Some(migration));
    }

    let env_path = env::var(CONSENSUS_FORK_MIGRATION_ENV)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());
    let path = match env_path {
        Some(value) => PathBuf::from(value),
        None => {
            let project_root_path = env::var("SYNERGY_PROJECT_ROOT")
                .ok()
                .map(|value| value.trim().to_string())
                .filter(|value| !value.is_empty())
                .map(|value| PathBuf::from(value).join(DEFAULT_CONSENSUS_FORK_MIGRATION_PATH));
            let default = project_root_path
                .filter(|path| path.is_file())
                .unwrap_or_else(|| PathBuf::from(DEFAULT_CONSENSUS_FORK_MIGRATION_PATH));
            if !default.is_file() {
                return Ok(None);
            }
            default
        }
    };

    let raw = fs::read_to_string(&path)
        .map_err(|error| format!("read consensus fork migration {}: {error}", path.display()))?;
    let migration: ConsensusForkMigration = serde_json::from_str(&raw)
        .map_err(|error| format!("parse consensus fork migration {}: {error}", path.display()))?;
    migration.validate().map_err(|error| {
        format!(
            "invalid consensus fork migration {}: {error}",
            path.display()
        )
    })?;
    Ok(Some(migration))
}

pub fn active_consensus_validator_addresses() -> Result<Option<BTreeSet<String>>, String> {
    let Some(migration) = active_consensus_fork_migration()? else {
        return Ok(None);
    };
    Ok(Some(
        migration
            .new_validator_registry
            .iter()
            .map(|validator| validator.validator_address.clone())
            .collect(),
    ))
}

pub fn validator_public_key_for_height(
    height: u64,
    validator_address: &str,
) -> Result<Option<PQCPublicKey>, String> {
    let Some(migration) = active_consensus_fork_migration()? else {
        return Ok(None);
    };
    if !migration.applies_to_height(height) {
        return Ok(None);
    }
    migration.validator_public_key(validator_address).map(Some)
}

pub fn validate_consensus_key_algorithm_for_height(
    height: u64,
    algorithm: &PQCAlgorithm,
) -> Result<(), String> {
    let Some(migration) = active_consensus_fork_migration()? else {
        return Ok(());
    };
    if migration.applies_to_height(height) && *algorithm != PQCAlgorithm::FNDSA {
        return Err(format!(
            "height {height} is at or after consensus fork {}; validator consensus signatures must use FN-DSA",
            migration.fork_height
        ));
    }
    Ok(())
}

pub fn validate_snapshot_fork_metadata(
    snapshot_height: u64,
    manifest_fork: Option<&ConsensusForkMigration>,
) -> Result<(), String> {
    if let Some(fork) = manifest_fork {
        fork.validate()?;
    }

    let Some(active) = active_consensus_fork_migration()? else {
        return Ok(());
    };
    if !active.applies_to_height(snapshot_height) {
        return Ok(());
    }
    let Some(manifest_fork) = manifest_fork else {
        return Err(format!(
            "post-fork snapshot at height {snapshot_height} is missing consensus fork metadata"
        ));
    };
    if manifest_fork != &active {
        return Err(
            "snapshot consensus fork metadata does not match active fork migration".to_string(),
        );
    }
    Ok(())
}

pub fn active_consensus_fork_status() -> Value {
    match active_consensus_fork_migration() {
        Ok(Some(migration)) => json!({
            "fork_configured": true,
            "fork_height": migration.fork_height,
            "fork_parent_height": migration.parent_height,
            "fork_parent_hash": migration.parent_hash,
            "state_root": migration.state_root,
            "old_consensus_algorithm": migration.old_consensus_algorithm,
            "new_consensus_algorithm": migration.new_consensus_algorithm,
            "parser_mode": migration.parser_mode,
            "validator_count": migration.new_validator_registry.len(),
            "validators": migration
                .new_validator_registry
                .iter()
                .map(|validator| json!({
                    "validator_address": validator.validator_address,
                    "consensus_key_type": validator.consensus_key_type,
                    "consensus_public_key_bytes": parse_consensus_public_key_material(
                        &validator.validator_address,
                        &validator.consensus_public_key,
                        Some(&validator.consensus_key_type),
                    )
                    .map(|(_, bytes)| bytes.len())
                    .unwrap_or(0),
                }))
                .collect::<Vec<_>>(),
        }),
        Ok(None) => json!({
            "fork_configured": false,
            "old_consensus_algorithm": LEGACY_CONSENSUS_ALGORITHM_LABEL,
            "new_consensus_algorithm": POST_FORK_CONSENSUS_ALGORITHM_LABEL,
            "parser_mode": CONSENSUS_FORK_PARSER_MODE_FAIL_CLOSED,
        }),
        Err(error) => json!({
            "fork_configured": false,
            "fork_config_error": error,
            "parser_mode": CONSENSUS_FORK_PARSER_MODE_FAIL_CLOSED,
        }),
    }
}

pub fn normalize_consensus_key_algorithm(label: &str) -> Result<PQCAlgorithm, String> {
    match label.trim().to_ascii_lowercase().as_str() {
        "fndsa" | "fn-dsa" | "fn-dsa-512" | "fn-dsa-1024" | "falcon" | "falcon-1024" | "mldsa"
        | "ml-dsa" | "ml-dsa-44" | "ml-dsa-65" | "ml-dsa-87" => Ok(PQCAlgorithm::FNDSA),
        "slhdsa" | "slh-dsa" => Ok(PQCAlgorithm::SLHDSA),
        "" => Err("missing consensus key algorithm".to_string()),
        "pqc" | "aegis" => Err(format!(
            "ambiguous consensus key algorithm '{label}'; use FN-DSA explicitly"
        )),
        other => Err(format!("unsupported consensus key algorithm '{other}'")),
    }
}

pub fn parse_consensus_public_key_material(
    validator_address: &str,
    encoded: &str,
    declared_algorithm_label: Option<&str>,
) -> Result<(PQCAlgorithm, Vec<u8>), String> {
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
    let key_data = decode_key_material(material).map_err(|error| {
        format!("validator {validator_address} consensus public key is invalid: {error}")
    })?;
    if key_data.is_empty() {
        return Err(format!(
            "validator {validator_address} consensus public key is empty"
        ));
    }
    Ok((algorithm, key_data))
}

fn split_algorithm_prefix<'a>(
    encoded: &'a str,
    declared_algorithm_label: Option<&str>,
) -> Result<(PQCAlgorithm, &'a str), String> {
    if let Some((prefix, material)) = encoded.split_once(':') {
        let encoded_algorithm = normalize_consensus_key_algorithm(prefix)?;
        if let Some(label) = declared_algorithm_label {
            let declared_algorithm = normalize_consensus_key_algorithm(label)?;
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
            "missing consensus key algorithm prefix; expected fn-dsa:<base64> or falcon:<base64>"
                .to_string(),
        );
    };
    Ok((normalize_consensus_key_algorithm(label)?, encoded))
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

fn require_non_empty(field: &str, value: &str) -> Result<(), String> {
    if value.trim().is_empty() {
        Err(format!("{field} must not be empty"))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encoded_key() -> String {
        general_purpose::STANDARD.encode([1, 2, 3, 4])
    }

    fn migration() -> ConsensusForkMigration {
        ConsensusForkMigration {
            fork_height: 204_216,
            parent_height: 204_215,
            parent_hash: "parent".to_string(),
            state_root: "state".to_string(),
            old_consensus_algorithm: "FN-DSA".to_string(),
            new_consensus_algorithm: "FN-DSA".to_string(),
            new_validator_registry: vec![ForkValidatorConsensusKey {
                validator_address: "synv1test".to_string(),
                consensus_key_type: "FN-DSA".to_string(),
                consensus_public_key: format!("fn-dsa:{}", encoded_key()),
            }],
            migration_reason: "checkpointed FN-DSA consensus key migration".to_string(),
            parser_mode: "fail_closed".to_string(),
            migration_signature: None,
        }
    }

    #[test]
    fn fork_migration_requires_parent_plus_one_height() {
        let mut migration = migration();
        migration.fork_height = migration.parent_height;

        let error = migration.validate().unwrap_err();

        assert!(error.contains("parent_height + 1"));
    }

    #[test]
    fn fork_migration_rejects_non_fndsa_new_validator_key() {
        let mut migration = migration();
        migration.new_validator_registry[0].consensus_key_type =
            "unsupported-signature".to_string();
        migration.new_validator_registry[0].consensus_public_key =
            format!("unsupported-signature:{}", encoded_key());

        let error = migration.validate().unwrap_err();

        assert!(
            error.contains("unsupported consensus key algorithm"),
            "{error}"
        );
    }

    #[test]
    fn consensus_algorithm_normalizer_rejects_ambiguous_labels() {
        assert!(normalize_consensus_key_algorithm("pqc").is_err());
        assert!(normalize_consensus_key_algorithm("aegis").is_err());
    }

    #[test]
    fn consensus_algorithm_normalizer_accepts_live_ml_dsa_labels_as_fndsa() {
        for label in ["ml-dsa", "ml-dsa-65", "ML-DSA-65", "mldsa"] {
            assert_eq!(
                normalize_consensus_key_algorithm(label).unwrap(),
                PQCAlgorithm::FNDSA
            );
        }
    }

    #[test]
    fn fork_migration_extracts_fndsa_validator_public_key() {
        let public_key = migration().validator_public_key("synv1test").unwrap();

        assert_eq!(public_key.algorithm, PQCAlgorithm::FNDSA);
        assert_eq!(public_key.key_data, vec![1, 2, 3, 4]);
    }
}
