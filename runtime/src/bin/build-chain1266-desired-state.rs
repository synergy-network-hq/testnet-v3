//! Deterministically builds the exact desired-state manifest later attested by
//! the tag-driven release workflow. This tool never signs or loads custody
//! material.

use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use synergy_testnet::consensus::testnet_v3_bootstrap::load_testnet_v3_genesis_bootstrap;
use synergy_testnet::desired_state::{
    validate_chain1266_p1_consensus_binding, CHAIN1266_P1_CONSENSUS_MODE,
    CHAIN1266_P1_COORDINATOR_ID, CHAIN1266_P1_PRODUCER_TURN_TIMEOUT_MS,
};
use synergy_testnet::genesis::load_genesis_from_path;
use synergy_testnet::synergy_types::{
    Epoch, SYNERGY_TESTNET_V3_CHAIN_ID, TESTNET_V3_CHAIN_INCARNATION,
    TESTNET_V3_CONSENSUS_STATE_SCHEMA_VERSION,
};

fn fail(message: impl AsRef<str>) -> ! {
    eprintln!("build-chain1266-desired-state: {}", message.as_ref());
    std::process::exit(1);
}

fn arg_value(args: &[String], flag: &str) -> String {
    args.windows(2)
        .find(|pair| pair[0] == flag)
        .map(|pair| pair[1].clone())
        .unwrap_or_else(|| fail(format!("missing {flag} <VALUE>")))
}

fn repeated_bindings(args: &[String], flag: &str) -> BTreeMap<String, PathBuf> {
    let mut bindings = BTreeMap::new();
    let mut index = 0usize;
    while index < args.len() {
        if args[index] != flag {
            index += 1;
            continue;
        }
        let value = args
            .get(index + 1)
            .unwrap_or_else(|| fail(format!("missing value after {flag}")));
        let (role, path) = value
            .split_once('=')
            .unwrap_or_else(|| fail(format!("{flag} requires ROLE=PATH")));
        if role.trim().is_empty()
            || bindings
                .insert(role.to_string(), PathBuf::from(path))
                .is_some()
        {
            fail(format!(
                "{flag} contains an empty or duplicate role: {role}"
            ));
        }
        index += 2;
    }
    if bindings.is_empty() {
        fail(format!("{flag} must be supplied at least once"));
    }
    bindings
}

fn sha256_file(path: &Path) -> String {
    let bytes =
        fs::read(path).unwrap_or_else(|error| fail(format!("read {}: {error}", path.display())));
    hex::encode(Sha256::digest(bytes))
}

fn require_revision(name: &str, value: &str) {
    if value.len() != 40
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        fail(format!("{name} must be a full lowercase Git revision"));
    }
}

const REQUIRED_CONFIGURATION_ROLES: [&str; 12] = [
    "validator-node-01",
    "validator-node-02",
    "validator-node-03",
    "validator-node-04",
    "validator-node-05",
    "validator-node-06",
    "relay1",
    "relay2",
    "relay3",
    "rpc-gateway",
    "explorer-indexer",
    "observer",
];

const RETIRED_POSY_CONSENSUS_KEYS: [&str; 23] = [
    "proposal_timeout_ms",
    "prevote_timeout_ms",
    "precommit_timeout_ms",
    "max_round_timeout_ms",
    "emergency_stable_committee_mode",
    "freeze_validator_set",
    "freeze_score_weighted_proposer_order",
    "vote_only_rejoin_enabled",
    "vote_only_probation_blocks",
    "validator_vote_threshold",
    "status_ready_gate_enabled",
    "status_ready_min_validators",
    "status_ready_genesis_grace_secs",
    "leader_timeout_secs",
    "vote_timeout_secs",
    "block_timeout_secs",
    "penalization_enabled",
    "synergy_score_decay_rate",
    "vrf_enabled",
    "vrf_seed_epoch_interval",
    "max_synergy_points_per_epoch",
    "max_tasks_per_validator",
    "reward_weighting",
];

#[derive(Debug, Clone, PartialEq, Eq)]
struct P1ConsensusBinding {
    mode: String,
    coordinator_id: String,
    producer_ids: Vec<String>,
    producer_turn_timeout_ms: u64,
}

fn required_consensus_string(
    consensus: &toml::map::Map<String, toml::Value>,
    role: &str,
    field: &str,
) -> Result<String, String> {
    consensus
        .get(field)
        .and_then(toml::Value::as_str)
        .map(ToString::to_string)
        .ok_or_else(|| format!("{role} consensus.{field} must be a string"))
}

fn parse_p1_consensus_binding(role: &str, path: &Path) -> Result<P1ConsensusBinding, String> {
    let content = fs::read_to_string(path)
        .map_err(|error| format!("read {role} configuration {}: {error}", path.display()))?;
    let document: toml::Value = toml::from_str(&content)
        .map_err(|error| format!("parse {role} configuration {}: {error}", path.display()))?;
    let consensus = document
        .get("consensus")
        .and_then(toml::Value::as_table)
        .ok_or_else(|| format!("{role} configuration omits the [consensus] table"))?;

    for key in RETIRED_POSY_CONSENSUS_KEYS {
        if consensus.contains_key(key) {
            return Err(format!(
                "{role} configuration carries retired PoSy consensus.{key}"
            ));
        }
    }

    let algorithm = required_consensus_string(consensus, role, "algorithm")?;
    let mode = required_consensus_string(consensus, role, "mode")?;
    if algorithm != CHAIN1266_P1_CONSENSUS_MODE || mode != CHAIN1266_P1_CONSENSUS_MODE {
        return Err(format!(
            "{role} configuration must select {CHAIN1266_P1_CONSENSUS_MODE}, not {algorithm}/{mode}"
        ));
    }
    let coordinator_id = required_consensus_string(consensus, role, "coordinator_id")?;
    let producer_ids = consensus
        .get("producer_ids")
        .and_then(toml::Value::as_array)
        .ok_or_else(|| format!("{role} consensus.producer_ids must be an array"))?
        .iter()
        .map(|value| {
            value
                .as_str()
                .map(ToString::to_string)
                .ok_or_else(|| format!("{role} consensus.producer_ids must contain only strings"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let producer_turn_timeout_ms = consensus
        .get("producer_turn_timeout_ms")
        .and_then(toml::Value::as_integer)
        .and_then(|value| u64::try_from(value).ok())
        .ok_or_else(|| format!("{role} consensus.producer_turn_timeout_ms must be a u64"))?;
    validate_chain1266_p1_consensus_binding(
        &mode,
        &coordinator_id,
        &producer_ids,
        producer_turn_timeout_ms,
    )
    .map_err(|error| format!("{role} configuration: {error}"))?;
    Ok(P1ConsensusBinding {
        mode,
        coordinator_id,
        producer_ids,
        producer_turn_timeout_ms,
    })
}

fn require_all_configurations_bind_the_same_p1_consensus(
    configurations: &BTreeMap<String, PathBuf>,
) -> Result<P1ConsensusBinding, String> {
    let actual_roles = configurations
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let required_roles = REQUIRED_CONFIGURATION_ROLES
        .into_iter()
        .collect::<BTreeSet<_>>();
    if actual_roles != required_roles {
        return Err(format!(
            "configuration roles must be exactly the Chain 1266 P1 fleet: expected {:?}, found {:?}",
            required_roles, actual_roles
        ));
    }

    let mut binding = None;
    for (role, path) in configurations {
        let parsed = parse_p1_consensus_binding(role, path)?;
        if let Some(expected) = &binding {
            if expected != &parsed {
                return Err(format!(
                    "{role} configuration P1 consensus binding differs from the rest of the fleet"
                ));
            }
        } else {
            binding = Some(parsed);
        }
    }
    binding.ok_or_else(|| "Chain 1266 P1 requires configuration files for every role".to_string())
}

fn main() {
    let args = env::args().collect::<Vec<_>>();
    let release_id = arg_value(&args, "--release-id");
    let release_tag = arg_value(&args, "--release-tag");
    let testnet_revision = arg_value(&args, "--testnet-revision");
    let synq_revision = arg_value(&args, "--synq-revision");
    let aegis_revision = arg_value(&args, "--aegis-revision");
    let genesis_path = PathBuf::from(arg_value(&args, "--genesis"));
    let start_authority_path = PathBuf::from(arg_value(&args, "--start-authority"));
    let output_path = PathBuf::from(arg_value(&args, "--output"));
    let artifacts = repeated_bindings(&args, "--artifact");
    let configurations = repeated_bindings(&args, "--configuration");
    for (name, revision) in [
        ("Testnet-v3 revision", &testnet_revision),
        ("SynQ revision", &synq_revision),
        ("Aegis revision", &aegis_revision),
    ] {
        require_revision(name, revision);
    }
    let p1_consensus = require_all_configurations_bind_the_same_p1_consensus(&configurations)
        .unwrap_or_else(|error| fail(error));

    let genesis = load_genesis_from_path(&genesis_path)
        .unwrap_or_else(|error| fail(format!("load canonical Genesis: {error}")));
    let bootstrap = load_testnet_v3_genesis_bootstrap(&genesis)
        .unwrap_or_else(|error| fail(format!("load Genesis validator set: {error}")));
    let validator_set_root = bootstrap
        .validator_set
        .active_for_epoch(Epoch(0))
        .hash()
        .unwrap_or_else(|error| fail(format!("derive active validator-set root: {error}")))
        .to_hex();
    let start_authority: Value =
        serde_json::from_slice(&fs::read(&start_authority_path).unwrap_or_else(|error| {
            fail(format!(
                "read start authority {}: {error}",
                start_authority_path.display()
            ))
        }))
        .unwrap_or_else(|error| fail(format!("parse start authority: {error}")));
    if start_authority["signature_algorithm"] != "ML-DSA-87"
        || start_authority["signature_domain"]
            != synergy_testnet::consensus_start::CHAIN1266_START_SIGNATURE_DOMAIN
        || !start_authority["public_key_fingerprint"]
            .as_str()
            .is_some_and(|value| value.starts_with("sha256:"))
        || !start_authority["public_key_base64"].is_string()
    {
        fail("start authority has an invalid ML-DSA-87 profile");
    }

    let artifact_hashes = artifacts
        .iter()
        .map(|(role, path)| (role.clone(), Value::String(sha256_file(path))))
        .collect::<serde_json::Map<_, _>>();
    let configuration_hashes = configurations
        .iter()
        .map(|(role, path)| (role.clone(), Value::String(sha256_file(path))))
        .collect::<serde_json::Map<_, _>>();
    let manifest = json!({
        "schema_version": 1,
        "release_id": release_id,
        "release_tag": release_tag,
        "chain": {
            "chain_id": SYNERGY_TESTNET_V3_CHAIN_ID,
            "incarnation": TESTNET_V3_CHAIN_INCARNATION,
            "genesis_hash": genesis.hash(),
            "validator_set_root": validator_set_root
        },
        "source": {
            "testnet_v3_revision": testnet_revision,
            "synq_revision": synq_revision,
            "aegis_revision": aegis_revision
        },
        "state": {
            "consensus_schema_version": TESTNET_V3_CONSENSUS_STATE_SCHEMA_VERSION,
            "directory_namespace": format!(
                "chain-{}/incarnation-{}",
                SYNERGY_TESTNET_V3_CHAIN_ID,
                TESTNET_V3_CHAIN_INCARNATION
            ),
            "mode": p1_consensus.mode,
            "coordinator_id": p1_consensus.coordinator_id,
            "producer_ids": p1_consensus.producer_ids,
            "producer_turn_timeout_ms": p1_consensus.producer_turn_timeout_ms,
        },
        "start_authority": start_authority,
        "artifacts": artifact_hashes,
        "configuration": configuration_hashes
    });
    let mut encoded = serde_json::to_vec_pretty(&manifest)
        .unwrap_or_else(|error| fail(format!("serialize desired state: {error}")));
    encoded.push(b'\n');
    if let Some(parent) = output_path.parent() {
        fs::create_dir_all(parent)
            .unwrap_or_else(|error| fail(format!("create {}: {error}", parent.display())));
    }
    fs::write(&output_path, &encoded)
        .unwrap_or_else(|error| fail(format!("write {}: {error}", output_path.display())));
    println!(
        "{}  {}",
        hex::encode(Sha256::digest(&encoded)),
        output_path.display()
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn canonical_p1_consensus_toml(extra: &str) -> String {
        format!(
            "[consensus]\nalgorithm = \"{CHAIN1266_P1_CONSENSUS_MODE}\"\nmode = \"{CHAIN1266_P1_CONSENSUS_MODE}\"\ncoordinator_id = \"{CHAIN1266_P1_COORDINATOR_ID}\"\nproducer_ids = [\"validator-2\", \"validator-3\", \"validator-4\", \"validator-5\", \"validator-6\"]\nproducer_turn_timeout_ms = {CHAIN1266_P1_PRODUCER_TURN_TIMEOUT_MS}\n{extra}"
        )
    }

    #[test]
    fn p1_consensus_parser_rejects_a_retired_posy_timeout() {
        let path = std::env::temp_dir().join(format!(
            "chain1266-p1-posy-config-{}.toml",
            std::process::id()
        ));
        fs::write(
            &path,
            canonical_p1_consensus_toml("proposal_timeout_ms = 1500\n"),
        )
        .expect("write temporary configuration");

        let error = parse_p1_consensus_binding("validator-node-01", &path)
            .expect_err("retired PoSy timeout must be rejected");
        assert!(error.contains("retired PoSy"), "{error}");
        let _ = fs::remove_file(path);
    }

    #[test]
    fn p1_consensus_parser_requires_the_exact_producer_order() {
        let path = std::env::temp_dir().join(format!(
            "chain1266-p1-order-config-{}.toml",
            std::process::id()
        ));
        fs::write(
            &path,
            canonical_p1_consensus_toml("").replace(
                "[\"validator-2\", \"validator-3\", \"validator-4\", \"validator-5\", \"validator-6\"]",
                "[\"validator-3\", \"validator-2\", \"validator-4\", \"validator-5\", \"validator-6\"]",
            ),
        )
        .expect("write temporary configuration");

        let error = parse_p1_consensus_binding("validator-node-01", &path)
            .expect_err("producer reordering must be rejected");
        assert!(error.contains("canonical Chain 1266 P1"), "{error}");
        let _ = fs::remove_file(path);
    }
}
