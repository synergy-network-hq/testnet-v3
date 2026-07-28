use serde_json::Value;
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

const TOTAL_SUPPLY_NWEI: u128 = 12_000_000_000_000_000_000;
const CHAIN_ID: u64 = 1266;
const CAIP2: &str = "synergy:testnet";

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("package dir should have repo parent")
        .to_path_buf()
}

fn read_json(path: impl AsRef<Path>) -> Value {
    let path = path.as_ref();
    serde_json::from_slice(
        &fs::read(path).unwrap_or_else(|err| panic!("read {}: {err}", path.display())),
    )
    .unwrap_or_else(|err| panic!("parse {}: {err}", path.display()))
}

fn genesis() -> Value {
    read_json(repo_root().join("genesis.testnet.json"))
}

fn network_identifiers() -> Value {
    read_json(repo_root().join("network-identifiers.testnet.json"))
}

fn canonical_json(value: &Value) -> String {
    match value {
        Value::Null => "null".to_string(),
        Value::Bool(entry) => entry.to_string(),
        Value::Number(entry) => entry.to_string(),
        Value::String(entry) => serde_json::to_string(entry).unwrap(),
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
                    format!(
                        "{}:{}",
                        serde_json::to_string(key).unwrap(),
                        canonical_json(&entries[key])
                    )
                })
                .collect::<Vec<_>>()
                .join(",");
            format!("{{{rendered}}}")
        }
    }
}

fn hash_json(value: &Value) -> String {
    blake3::hash(canonical_json(value).as_bytes())
        .to_hex()
        .to_string()
}

fn remove_dotted(value: &mut Value, path: &str) {
    let parts = path.split('.').collect::<Vec<_>>();
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

fn genesis_hash_payload(genesis: &Value) -> Value {
    let mut payload = serde_json::Map::new();
    for input in genesis["canonicalization"]["genesis_hash_inputs"]
        .as_array()
        .expect("hash inputs")
        .iter()
        .map(|entry| entry.as_str().expect("hash input string"))
    {
        payload.insert(input.to_string(), genesis[input].clone());
    }
    let mut payload = Value::Object(payload);
    let exclusions = genesis["canonicalization"]["excluded_from_genesis_hash"]
        .as_array()
        .expect("hash exclusions")
        .iter()
        .map(|entry| entry.as_str().expect("hash exclusion").to_string())
        .chain(
            [
                "integrity.genesis_hash",
                "integrity.signed_by",
                "integrity.draft_artifact_sha256",
                "integrity.recompute_required",
                "integrity.recompute_reason",
                "p2p_identity.network_magic_bytes",
                "p2p_identity.provisional_derivation_note",
            ]
            .into_iter()
            .map(String::from),
        )
        .collect::<BTreeSet<_>>();
    for exclusion in exclusions {
        remove_dotted(&mut payload, &exclusion);
    }
    payload
}

fn secret_field_paths(value: &Value, prefix: &str, out: &mut Vec<String>) {
    match value {
        Value::Object(map) => {
            for (key, item) in map {
                let lower = key.to_ascii_lowercase();
                if lower.contains("private_key")
                    || lower.contains("seed")
                    || lower.contains("mnemonic")
                    || lower.contains("phrase")
                    || lower.contains("secret")
                    || lower == "sk"
                    || lower.contains("_sk_")
                    || lower.contains("priv")
                {
                    out.push(format!("{prefix}.{key}"));
                }
                secret_field_paths(item, &format!("{prefix}.{key}"), out);
            }
        }
        Value::Array(items) => {
            for (index, item) in items.iter().enumerate() {
                secret_field_paths(item, &format!("{prefix}[{index}]"), out);
            }
        }
        _ => {}
    }
}

#[test]
fn supply_is_exact_12b_snrg() {
    let genesis = genesis();
    let token_cap = genesis["token"]["total_supply_cap_nwei"]
        .as_str()
        .unwrap()
        .parse::<u128>()
        .unwrap();
    let allocations = genesis["allocations"]
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| {
            entry["amount_nwei"]
                .as_str()
                .unwrap()
                .parse::<u128>()
                .unwrap()
        })
        .sum::<u128>();
    let balances = genesis["balances"]
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| {
            entry["balance_nwei"]
                .as_str()
                .unwrap()
                .parse::<u128>()
                .unwrap()
        })
        .sum::<u128>();
    assert_eq!(token_cap, TOTAL_SUPPLY_NWEI);
    assert_eq!(allocations, TOTAL_SUPPLY_NWEI);
    assert_eq!(balances, TOTAL_SUPPLY_NWEI);
    assert_eq!(
        genesis["allocation_sum_check"]["grand_total_nwei"]
            .as_str()
            .unwrap(),
        TOTAL_SUPPLY_NWEI.to_string()
    );
    assert_eq!(genesis["allocation_sum_check"]["matches_supply_cap"], true);
}

#[test]
fn public_artifacts_do_not_serialize_secret_fields() {
    for path in [
        repo_root().join("genesis.testnet.json"),
        repo_root().join("network-identifiers.testnet.json"),
        repo_root()
            .join("release-artifacts")
            .join("testnet")
            .join("genesis.testnet.annotated.txt"),
    ] {
        if path.extension().and_then(|ext| ext.to_str()) == Some("txt") {
            let text = fs::read_to_string(&path).unwrap();
            let lower = text.to_ascii_lowercase();
            assert!(!lower.contains("private_key"));
            assert!(!lower.contains("mnemonic"));
            assert!(!lower.contains("seed_phrase"));
            assert!(!lower.contains("secret"));
            continue;
        }
        let value = read_json(&path);
        let mut hits = Vec::new();
        secret_field_paths(&value, "$", &mut hits);
        assert!(
            hits.is_empty(),
            "{} contains secret-looking fields: {hits:?}",
            path.display()
        );
    }
}

#[test]
fn five_initial_validators_are_active_and_consistent() {
    let genesis = genesis();
    let validators = genesis["validators"].as_array().unwrap();
    assert_eq!(validators.len(), 5);
    for validator in validators {
        assert_eq!(validator["status"], "active");
        assert_eq!(validator["activation_height"], 0);
        assert_eq!(validator["voting_power"], 100);
        assert_eq!(
            validator["stake_nwei"].as_str().unwrap(),
            validator["self_stake_nwei"].as_str().unwrap()
        );
    }

    let registry = genesis["contracts"]["validator_registry"]["init_params"]["validators"]
        .as_array()
        .unwrap();
    let staking = genesis["modules"]["staking"]["validators"]
        .as_array()
        .unwrap();
    assert_eq!(registry.len(), validators.len());
    assert_eq!(staking.len(), validators.len());

    for ((top, registry), staking) in validators.iter().zip(registry).zip(staking) {
        for (top_key, registry_key) in [
            ("validator_id", "validator_id"),
            ("validator_id_hash", "validator_id_hash"),
            ("operator_address", "operator_address"),
            ("reward_address", "reward_address"),
            ("consensus_public_key", "consensus_public_key"),
            ("consensus_key_type", "consensus_key_type"),
            ("stake_nwei", "stake_nwei"),
            ("status", "status"),
            ("activation_height", "activation_height"),
            ("voting_power", "voting_power"),
        ] {
            assert_eq!(top[top_key], registry[registry_key]);
            assert_eq!(top[top_key], staking[registry_key]);
        }
    }
}

#[test]
fn network_identifiers_agree_with_genesis() {
    let genesis = genesis();
    let network = network_identifiers();
    assert_eq!(genesis["network"]["chain_id"], CHAIN_ID);
    assert_eq!(genesis["network"]["network_id"], CHAIN_ID);
    assert_eq!(
        network["chain_identifiers"]["synergy_native"]["decimal"],
        CHAIN_ID
    );
    assert_eq!(
        network["chain_identifiers"]["caip2_identifiers"]["canonical_native"]["value"],
        CAIP2
    );
    assert_eq!(
        network["chain_identifiers"]["caip2_identifiers"]["eip155"]["value"],
        "eip155:1266"
    );
    assert_eq!(
        network["chain_identifiers"]["caip2_identifiers"]["eip155"]["status"],
        "reserved_inactive"
    );
    assert_eq!(network["native_currency"]["name"], genesis["token"]["name"]);
    assert_eq!(
        network["native_currency"]["symbol"],
        genesis["token"]["symbol"]
    );
    assert_eq!(
        network["native_currency"]["decimals"],
        genesis["token"]["decimals"]
    );
    assert_eq!(
        network["cryptographic_identity"]["genesis_hash"],
        genesis["integrity"]["genesis_hash"]
    );
    assert_eq!(
        network["cryptographic_identity"]["network_magic_bytes"]["value"],
        genesis["p2p_identity"]["network_magic_bytes"]
    );
    assert_eq!(
        network["addressing"]["burn_address"],
        genesis["system_reserved_addresses"]["burn_address"]["address"]
    );
}

#[test]
fn canonical_hashes_and_exports_round_trip() {
    let genesis = genesis();
    let validator_set = &genesis["contracts"]["validator_registry"]["init_params"]["validators"];
    assert_eq!(
        hash_json(validator_set),
        genesis["integrity"]["validator_set_hash"]
    );
    assert_eq!(
        hash_json(&genesis["allocations"]),
        genesis["integrity"]["allocation_hash"]
    );
    assert_eq!(
        hash_json(&genesis["contracts"]),
        genesis["integrity"]["contract_hash"]
    );
    assert_eq!(
        hash_json(&genesis_hash_payload(&genesis)),
        genesis["integrity"]["genesis_hash"]
    );

    let bin = fs::read(repo_root().join("release-artifacts/testnet/genesis.testnet.bin")).unwrap();
    let hex = fs::read_to_string(repo_root().join("release-artifacts/testnet/genesis.testnet.hex"))
        .unwrap();
    assert_eq!(hex.trim(), hex::encode(&bin));
    assert_eq!(
        blake3::hash(&bin).to_hex().to_string(),
        genesis["integrity"]["genesis_hash"]
    );

    let png_a =
        fs::read(repo_root().join("release-artifacts/testnet/genesis.testnet.hex.png")).unwrap();
    let png_b =
        fs::read(repo_root().join("release-artifacts/testnet/genesis.testnet.hex.png")).unwrap();
    assert_eq!(blake3::hash(&png_a), blake3::hash(&png_b));
}

#[test]
fn independent_temp_dir_hash_recompute_matches() {
    let source = repo_root().join("genesis.testnet.json");
    let expected = genesis()["integrity"]["genesis_hash"]
        .as_str()
        .unwrap()
        .to_string();
    for index in 0..3 {
        let dir = crate::utils::test_temp_root(format!(
            "synergy-genesis-hash-test-{index}-{}",
            std::process::id()
        ));
        fs::create_dir_all(&dir).unwrap();
        let copy = dir.join("genesis.testnet.json");
        fs::copy(&source, &copy).unwrap();
        let copied = read_json(&copy);
        assert_eq!(hash_json(&genesis_hash_payload(&copied)), expected);
        fs::remove_dir_all(&dir).unwrap();
    }
}
