use crate::address::is_valid_address;
use crate::utils::resolve_data_path;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SynIdRecord {
    pub syn_id: String,
    pub address: String,
    pub display_name: Option<String>,
    pub created_at: u64,
    pub updated_at: u64,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct SynIdRegistryFile {
    records: BTreeMap<String, SynIdRecord>,
}

fn registry_path() -> PathBuf {
    resolve_data_path("data/synid_registry.json")
}

fn current_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub fn normalize_syn_id(value: &str) -> Result<String, String> {
    let cleaned = value.trim().trim_start_matches('@').to_lowercase();
    if cleaned.is_empty() {
        return Err("SynID is required".to_string());
    }

    let normalized = if cleaned.ends_with(".syn") {
        cleaned
    } else {
        format!("{}.syn", cleaned)
    };

    let label = normalized
        .strip_suffix(".syn")
        .ok_or_else(|| "SynID must end with .syn".to_string())?;
    if !(3..=32).contains(&label.len()) {
        return Err("SynID must be 3-32 characters before .syn".to_string());
    }
    let mut chars = label.chars();
    let first = chars
        .next()
        .ok_or_else(|| "SynID must start with a letter or number".to_string())?;
    if !first.is_ascii_lowercase() && !first.is_ascii_digit() {
        return Err("SynID must start with a letter or number".to_string());
    }
    if !label
        .chars()
        .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '-')
    {
        return Err("SynID may only contain lowercase letters, numbers, and hyphens".to_string());
    }

    Ok(normalized)
}

fn normalize_display_name(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .map(|name| name.chars().take(80).collect())
}

fn load_registry() -> SynIdRegistryFile {
    let path = registry_path();
    let Ok(raw) = fs::read_to_string(path) else {
        return SynIdRegistryFile::default();
    };
    serde_json::from_str(&raw).unwrap_or_default()
}

fn save_registry(registry: &SynIdRegistryFile) -> Result<(), String> {
    let path = registry_path();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| format!("Failed to create SynID registry directory: {}", error))?;
    }

    let tmp_path = path.with_extension("json.tmp");
    let body = serde_json::to_string_pretty(registry)
        .map_err(|error| format!("Failed to encode SynID registry: {}", error))?;
    fs::write(&tmp_path, body)
        .map_err(|error| format!("Failed to write SynID registry: {}", error))?;
    fs::rename(&tmp_path, &path)
        .map_err(|error| format!("Failed to commit SynID registry: {}", error))?;
    Ok(())
}

pub fn register_syn_id(
    syn_id: &str,
    address: &str,
    display_name: Option<&str>,
) -> Result<SynIdRecord, String> {
    let normalized_syn_id = normalize_syn_id(syn_id)?;
    let normalized_address = address.trim().to_string();
    if !is_valid_address(&normalized_address) {
        return Err("Wallet address is not a valid Synergy address".to_string());
    }

    let mut registry = load_registry();
    let now = current_timestamp();

    if let Some(existing) = registry.records.get_mut(&normalized_syn_id) {
        if existing.address != normalized_address {
            return Err(format!(
                "SynID {} is already registered to a different address",
                normalized_syn_id
            ));
        }
        existing.display_name =
            normalize_display_name(display_name).or(existing.display_name.clone());
        existing.updated_at = now;
        let record = existing.clone();
        save_registry(&registry)?;
        return Ok(record);
    }

    let record = SynIdRecord {
        syn_id: normalized_syn_id.clone(),
        address: normalized_address,
        display_name: normalize_display_name(display_name),
        created_at: now,
        updated_at: now,
    };
    registry.records.insert(normalized_syn_id, record.clone());
    save_registry(&registry)?;
    Ok(record)
}

pub fn resolve_syn_id(syn_id: &str) -> Result<Option<SynIdRecord>, String> {
    let normalized_syn_id = normalize_syn_id(syn_id)?;
    Ok(load_registry().records.get(&normalized_syn_id).cloned())
}

pub fn reverse_resolve_syn_id(address: &str) -> Result<Vec<SynIdRecord>, String> {
    let normalized_address = address.trim();
    if !is_valid_address(normalized_address) {
        return Err("Wallet address is not a valid Synergy address".to_string());
    }

    let records = load_registry()
        .records
        .into_values()
        .filter(|record| record.address == normalized_address)
        .collect::<Vec<_>>();
    Ok(records)
}

pub fn list_syn_ids() -> Vec<SynIdRecord> {
    load_registry().records.into_values().collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Mutex, OnceLock};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn env_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    fn with_temp_runtime_root(test: impl FnOnce()) {
        let _guard = env_lock().lock().unwrap();
        let base = std::env::temp_dir().join(format!(
            "synergy-synid-test-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(base.join("config")).unwrap();
        std::env::set_var("SYNERGY_PROJECT_ROOT", &base);
        test();
        std::env::remove_var("SYNERGY_PROJECT_ROOT");
        let _ = fs::remove_dir_all(base);
    }

    #[test]
    fn normalizes_syn_ids() {
        assert_eq!(normalize_syn_id("@DevPup").unwrap(), "devpup.syn");
        assert_eq!(normalize_syn_id("alice.syn").unwrap(), "alice.syn");
        assert!(normalize_syn_id("bad_name").is_err());
    }

    #[test]
    fn registers_and_resolves_syn_id_records() {
        with_temp_runtime_root(|| {
            let address = crate::address::generate_wallet_address(
                "0000000000000000000000000000000000000000000000000000000000000000",
            );

            let record = register_syn_id("@devpup", &address, Some("Dev Pup")).expect("register");
            assert_eq!(record.syn_id, "devpup.syn");
            assert_eq!(record.address, address);

            let resolved = resolve_syn_id("devpup.syn")
                .expect("resolve")
                .expect("record");
            assert_eq!(resolved.address, address);

            let reverse = reverse_resolve_syn_id(&address).expect("reverse");
            assert_eq!(reverse.len(), 1);
            assert_eq!(reverse[0].syn_id, "devpup.syn");
        });
    }

    #[test]
    fn prevents_reassigning_existing_syn_id() {
        with_temp_runtime_root(|| {
            let first = crate::address::generate_wallet_address(
                "0000000000000000000000000000000000000000000000000000000000000000",
            );
            let second = crate::address::generate_wallet_address(
                "1111111111111111111111111111111111111111111111111111111111111111",
            );
            register_syn_id("devpup.syn", &first, None).expect("register first");
            let err =
                register_syn_id("devpup.syn", &second, None).expect_err("reject reassignment");
            assert!(err.contains("already registered"));
        });
    }
}
