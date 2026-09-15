//! Track-H inventory and finalized-candidate address migration gate.

use serde::Serialize;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

const SOURCE_GENESIS: &str = "genesis.testnet-v3.identity-assigned.json";
const FROZEN_CONTRACTS: &str = "launch/TESTNET_V3_PRODUCTION_CONTRACT_ADDRESSES.json";

#[derive(Debug, Clone)]
struct AddressBinding {
    contract: String,
    old: String,
    new: Option<String>,
}

#[derive(Debug, Serialize)]
struct Occurrence {
    contract: String,
    identity_or_custody_address: String,
    deployed_contract_address: Option<String>,
    path: String,
    line: usize,
    classification: &'static str,
}

#[derive(Debug, Serialize)]
struct Report {
    schema_version: u32,
    status: &'static str,
    mapping_count: usize,
    occurrence_count: usize,
    active_consumer_review_count: usize,
    candidate: Option<String>,
    candidate_errors: Vec<String>,
    mappings: Vec<MappingReport>,
    occurrences: Vec<Occurrence>,
}

#[derive(Debug, Serialize)]
struct MappingReport {
    contract: String,
    identity_or_custody_address: String,
    deployed_contract_address: Option<String>,
}

fn fail(message: impl AsRef<str>) -> ! {
    eprintln!("audit-testnet-v3-address-migration: {}", message.as_ref());
    std::process::exit(1);
}

fn repo() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read_json(path: &Path) -> Value {
    let bytes =
        fs::read(path).unwrap_or_else(|error| fail(format!("read {}: {error}", path.display())));
    serde_json::from_slice(&bytes)
        .unwrap_or_else(|error| fail(format!("parse {}: {error}", path.display())))
}

fn contract_key(name: &str) -> String {
    let mut output = String::new();
    for (index, character) in name.chars().enumerate() {
        if character.is_ascii_uppercase() && index != 0 {
            output.push('_');
        }
        output.push(character.to_ascii_lowercase());
    }
    output
}

fn identity_or_custody_address(source: &Value, contract_name: &str) -> String {
    let key = contract_key(contract_name);
    if let Some(address) = source["contracts"][&key]["contract_identity"]["address"].as_str() {
        return address.to_string();
    }
    if let Some(address) = source["contracts"][&key]["address"].as_str() {
        return address.to_string();
    }
    source["contract_identities"]
        .as_array()
        .and_then(|entries| {
            entries
                .iter()
                .find(|entry| entry["contract_name"].as_str() == Some(key.as_str()))
        })
        .and_then(|entry| entry["address"].as_str())
        .unwrap_or_else(|| {
            fail(format!(
                "source genesis is missing {contract_name} identity"
            ))
        })
        .to_string()
}

fn bindings(root: &Path) -> Vec<AddressBinding> {
    let source = read_json(&root.join(SOURCE_GENESIS));
    let frozen = read_json(&root.join(FROZEN_CONTRACTS));
    let deployed = frozen["contracts"]
        .as_array()
        .unwrap_or_else(|| fail("frozen contracts array is missing"))
        .iter()
        .map(|entry| {
            (
                entry["contract"].as_str().unwrap().to_string(),
                entry["contract_address"].as_str().unwrap().to_string(),
            )
        })
        .collect::<BTreeMap<_, _>>();

    let mut result = deployed
        .iter()
        .map(|(name, address)| AddressBinding {
            contract: name.clone(),
            old: identity_or_custody_address(&source, name),
            new: Some(address.clone()),
        })
        .collect::<Vec<_>>();
    result.push(AddressBinding {
        contract: "SaleClaim".to_string(),
        old: identity_or_custody_address(&source, "SaleClaim"),
        new: None,
    });
    result.sort_by(|left, right| left.contract.cmp(&right.contract));
    result
}

fn skip_directory(name: &str) -> bool {
    matches!(name, ".git" | "target" | "node_modules" | "data")
}

fn collect_files(path: &Path, files: &mut Vec<PathBuf>) {
    let entries = match fs::read_dir(path) {
        Ok(entries) => entries,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            if !path
                .file_name()
                .and_then(|name| name.to_str())
                .map(skip_directory)
                .unwrap_or(false)
            {
                collect_files(&path, files);
            }
        } else if path.is_file() {
            files.push(path);
        }
    }
}

fn classify(path: &str) -> &'static str {
    if path == SOURCE_GENESIS {
        "source_genesis_semantic_migration"
    } else if path.starts_with("runtime/config/genesis.testnet-v3.test-fixture") {
        "historical_test_fixture"
    } else if path.starts_with("testnet-v3-identity-files/") {
        "identity_custody_registry_preserve"
    } else if path.starts_with("genesis-contracts/") {
        "artifact_source_provenance_review"
    } else if path.starts_with("launch/evidence/") || path.starts_with("launch/") {
        "historical_launch_record"
    } else {
        "active_consumer_review"
    }
}

fn inventory(root: &Path, bindings: &[AddressBinding]) -> Vec<Occurrence> {
    let mut files = Vec::new();
    collect_files(root, &mut files);
    files.sort();
    let by_old = bindings
        .iter()
        .map(|binding| (binding.old.as_str(), binding))
        .collect::<BTreeMap<_, _>>();
    let mut occurrences = Vec::new();
    for path in files {
        let metadata = match path.metadata() {
            Ok(metadata) if metadata.len() <= 20 * 1024 * 1024 => metadata,
            _ => continue,
        };
        let _ = metadata;
        let contents = match fs::read_to_string(&path) {
            Ok(contents) => contents,
            Err(_) => continue,
        };
        let relative = path
            .strip_prefix(root)
            .unwrap_or(&path)
            .to_string_lossy()
            .to_string();
        for (index, line) in contents.lines().enumerate() {
            for (old, binding) in &by_old {
                if line.contains(old) {
                    occurrences.push(Occurrence {
                        contract: binding.contract.clone(),
                        identity_or_custody_address: binding.old.clone(),
                        deployed_contract_address: binding.new.clone(),
                        path: relative.clone(),
                        line: index + 1,
                        classification: classify(&relative),
                    });
                }
            }
        }
    }
    occurrences
}

fn sanitize_allowed_identity_references(candidate: &mut Value) {
    if let Some(contracts) = candidate["contracts"].as_object_mut() {
        for contract in contracts.values_mut() {
            contract["contract_identity"]["address"] = Value::Null;
        }
    }
    for table in ["contract_identities", "address_assignment_register"] {
        if let Some(entries) = candidate[table].as_array_mut() {
            for entry in entries {
                if table == "contract_identities" {
                    entry["address"] = Value::Null;
                } else {
                    entry["assigned_address"] = Value::Null;
                }
            }
        }
    }
    if let Some(entries) = candidate["contract_address_migration"]["entries"].as_array_mut() {
        for entry in entries {
            entry["identity_or_custody_address"] = Value::Null;
        }
    }
    for table in ["accounts", "allocations", "balances"] {
        if let Some(entries) = candidate[table].as_array_mut() {
            for entry in entries {
                if entry["account_id"] == "SAL-A01" {
                    entry["address"] = Value::Null;
                }
            }
        }
    }
}

fn find_old_values(
    value: &Value,
    old: &BTreeSet<String>,
    path: &mut Vec<String>,
    errors: &mut Vec<String>,
) {
    match value {
        Value::String(text) if old.contains(text) => {
            errors.push(format!(
                "stale deployed-address consumer at {} = {}",
                path.join("."),
                text
            ));
        }
        Value::Array(entries) => {
            for (index, entry) in entries.iter().enumerate() {
                path.push(index.to_string());
                find_old_values(entry, old, path, errors);
                path.pop();
            }
        }
        Value::Object(entries) => {
            for (key, entry) in entries {
                path.push(key.clone());
                find_old_values(entry, old, path, errors);
                path.pop();
            }
        }
        _ => {}
    }
}

fn candidate_errors(candidate_path: &Path, bindings: &[AddressBinding]) -> Vec<String> {
    let mut candidate = read_json(candidate_path);
    let mut errors = Vec::new();
    let deployed = bindings
        .iter()
        .filter_map(|binding| {
            binding
                .new
                .as_ref()
                .map(|new| (binding.contract.clone(), new.clone()))
        })
        .collect::<BTreeMap<_, _>>();
    for (contract, address) in &deployed {
        let key = contract_key(contract);
        if candidate["contracts"][&key]["address"].as_str() != Some(address) {
            errors.push(format!("contracts.{key}.address is not {address}"));
        }
    }
    for (path, contract) in [
        (["modules", "identity", "contract_address"], "Identity"),
        (["modules", "treasury", "contract_address"], "Treasury"),
        (["vesting", "0", "contract_address"], "TeamVesting"),
    ] {
        let actual = if path[0] == "vesting" {
            candidate["vesting"][0]["contract_address"].as_str()
        } else {
            candidate[path[0]][path[1]][path[2]].as_str()
        };
        if actual != Some(deployed[contract].as_str()) {
            errors.push(format!(
                "{} is not the deployed {contract} address",
                path.join(".")
            ));
        }
    }
    for table in ["accounts", "allocations", "balances"] {
        let actual = candidate[table]
            .as_array()
            .and_then(|entries| {
                entries
                    .iter()
                    .find(|entry| entry["account_id"] == "TEM-A01")
            })
            .and_then(|entry| entry["address"].as_str());
        if actual != Some(deployed["TeamVesting"].as_str()) {
            errors.push(format!(
                "{table}.TEM-A01 does not fund deployed TeamVesting"
            ));
        }
    }

    sanitize_allowed_identity_references(&mut candidate);
    let old = bindings
        .iter()
        .map(|binding| binding.old.clone())
        .collect::<BTreeSet<_>>();
    find_old_values(&candidate, &old, &mut Vec::new(), &mut errors);
    errors
}

fn main() {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    let mut output = None;
    let mut candidate = None;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--output" => {
                output = Some(PathBuf::from(
                    args.get(index + 1)
                        .unwrap_or_else(|| fail("--output requires a path")),
                ));
                index += 2;
            }
            "--candidate" => {
                candidate = Some(PathBuf::from(
                    args.get(index + 1)
                        .unwrap_or_else(|| fail("--candidate requires a path")),
                ));
                index += 2;
            }
            flag => fail(format!(
                "unknown argument {flag}; use [--candidate PATH] [--output PATH]"
            )),
        }
    }

    let root = repo();
    let bindings = bindings(&root);
    let occurrences = inventory(&root, &bindings);
    let errors = candidate
        .as_deref()
        .map(|path| candidate_errors(path, &bindings))
        .unwrap_or_default();
    let active_consumer_review_count = occurrences
        .iter()
        .filter(|entry| entry.classification == "active_consumer_review")
        .count();
    let report = Report {
        schema_version: 1,
        status: if errors.is_empty() { "PASS" } else { "FAIL" },
        mapping_count: bindings.len(),
        occurrence_count: occurrences.len(),
        active_consumer_review_count,
        candidate: candidate.map(|path| path.display().to_string()),
        candidate_errors: errors,
        mappings: bindings
            .iter()
            .map(|binding| MappingReport {
                contract: binding.contract.clone(),
                identity_or_custody_address: binding.old.clone(),
                deployed_contract_address: binding.new.clone(),
            })
            .collect(),
        occurrences,
    };
    let contents = serde_json::to_string_pretty(&report).unwrap() + "\n";
    if let Some(path) = output {
        fs::write(&path, &contents)
            .unwrap_or_else(|error| fail(format!("write {}: {error}", path.display())));
    } else {
        print!("{contents}");
    }
    if report.status != "PASS" {
        std::process::exit(1);
    }
}
