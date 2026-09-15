use chrono::{SecondsFormat, Utc};
use serde_json::{Map, Value};
use std::fs::{self, OpenOptions};
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

lazy_static::lazy_static! {
    static ref TRACE_WRITE_MUTEX: Mutex<()> = Mutex::new(());
    static ref TRACE_PROCESS_STARTED: Instant = Instant::now();
}

const TRACE_SCHEMA: &str = "synergy_consensus_timing_v1";
const TRACE_ENABLED_ENV: &str = "SYNERGY_CONSENSUS_TIMING_TRACE";
const TRACE_PATH_ENV: &str = "SYNERGY_CONSENSUS_TIMING_TRACE_PATH";
const TRACE_LEGACY_FILE_ENV: &str = "SYNERGY_CONSENSUS_TIMING_TRACE_FILE";
static TRACE_ERROR_REPORTED: AtomicBool = AtomicBool::new(false);

pub fn enabled() -> bool {
    std::env::var(TRACE_ENABLED_ENV)
        .ok()
        .map(|value| {
            let normalized = value.trim().to_ascii_lowercase();
            matches!(normalized.as_str(), "1" | "true" | "yes" | "on")
        })
        .unwrap_or(false)
}

pub fn now_unix_ms() -> u64 {
    system_time_ms(SystemTime::now())
}

pub fn system_time_ms(time: SystemTime) -> u64 {
    duration_ms(time.duration_since(UNIX_EPOCH).unwrap_or_default())
}

pub fn duration_ms(duration: Duration) -> u64 {
    duration.as_millis().min(u64::MAX as u128) as u64
}

pub fn emit(event: &str, fields: Value) {
    if !enabled() {
        return;
    }

    let mut entry = match fields {
        Value::Object(map) => map,
        _ => Map::new(),
    };
    for (key, value) in trace_context() {
        entry.entry(key).or_insert(value);
    }
    entry.insert(
        "schema".to_string(),
        Value::String(TRACE_SCHEMA.to_string()),
    );
    entry.insert("event_type".to_string(), Value::String(event.to_string()));
    entry.insert("event".to_string(), Value::String(event.to_string()));
    entry.insert(
        "wall_time_ms".to_string(),
        Value::Number(serde_json::Number::from(now_unix_ms())),
    );
    entry.insert(
        "utc_time".to_string(),
        Value::String(Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true)),
    );
    entry.insert(
        "process_monotonic_ms".to_string(),
        Value::Number(serde_json::Number::from(duration_ms(
            TRACE_PROCESS_STARTED.elapsed(),
        ))),
    );

    let Ok(encoded) = serde_json::to_vec(&Value::Object(entry)) else {
        return;
    };

    let path = trace_path();
    if let Some(parent) = path.parent() {
        if let Err(error) = fs::create_dir_all(parent) {
            report_trace_error(format!(
                "create trace directory {}: {error}",
                parent.display()
            ));
            return;
        }
    }

    let Ok(_guard) = TRACE_WRITE_MUTEX.lock() else {
        report_trace_error("trace writer lock poisoned".to_string());
        return;
    };

    let mut options = OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = match options.open(&path) {
        Ok(file) => file,
        Err(error) => {
            report_trace_error(format!("open trace file {}: {error}", path.display()));
            return;
        }
    };
    if let Err(error) = file.write_all(&encoded) {
        report_trace_error(format!("write trace file {}: {error}", path.display()));
        return;
    }
    if let Err(error) = file.write_all(b"\n") {
        report_trace_error(format!("finish trace line {}: {error}", path.display()));
    }
}

fn trace_path() -> PathBuf {
    for key in [TRACE_PATH_ENV, TRACE_LEGACY_FILE_ENV] {
        if let Ok(path) = std::env::var(key) {
            let path = path.trim();
            if !path.is_empty() {
                return PathBuf::from(path);
            }
        }
    }
    crate::utils::resolve_data_path("data/consensus_timing_trace.jsonl")
}

fn trace_context() -> Map<String, Value> {
    let mut context = Map::new();
    match crate::genesis::canonical_genesis() {
        Ok(genesis) => {
            context.insert(
                "chain_id".to_string(),
                Value::Number(serde_json::Number::from(genesis.chain_id())),
            );
            context.insert(
                "chain_id_hex".to_string(),
                Value::String(format!("0x{:x}", genesis.chain_id())),
            );
            context.insert(
                "numeric_network_id".to_string(),
                Value::Number(serde_json::Number::from(genesis.network_id())),
            );
            context.insert(
                "genesis_hash".to_string(),
                Value::String(genesis.hash().to_string()),
            );
            context.insert("genesis_hash_unavailable_reason".to_string(), Value::Null);
        }
        Err(error) => {
            context.insert(
                "chain_id".to_string(),
                Value::Number(serde_json::Number::from(1264u64)),
            );
            context.insert(
                "chain_id_hex".to_string(),
                Value::String("0x4f0".to_string()),
            );
            context.insert("numeric_network_id".to_string(), Value::Null);
            context.insert("genesis_hash".to_string(), Value::Null);
            context.insert(
                "genesis_hash_unavailable_reason".to_string(),
                Value::String(error),
            );
        }
    }
    context.insert(
        "network_id".to_string(),
        Value::String("synergy-testnet-v3".to_string()),
    );
    context.insert(
        "runtime_version".to_string(),
        Value::String(env!("CARGO_PKG_VERSION").to_string()),
    );
    match std::env::var("SYNERGY_RUNTIME_SHA256")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
    {
        Some(value) => {
            context.insert("runtime_sha256".to_string(), Value::String(value));
            context.insert("runtime_sha256_unavailable_reason".to_string(), Value::Null);
        }
        None => {
            context.insert("runtime_sha256".to_string(), Value::Null);
            context.insert(
                "runtime_sha256_unavailable_reason".to_string(),
                Value::String("SYNERGY_RUNTIME_SHA256 not set".to_string()),
            );
        }
    }

    for (env_key, trace_key) in [
        ("SYNERGY_TIMING_TRACE_NODE_ROLE", "node_role"),
        ("SYNERGY_TIMING_TRACE_NODE_NAME", "node_name"),
        ("SYNERGY_TIMING_TRACE_VALIDATOR", "node_validator"),
    ] {
        match std::env::var(env_key)
            .ok()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
        {
            Some(value) => {
                context.insert(trace_key.to_string(), Value::String(value));
                context.insert(format!("{trace_key}_unavailable_reason"), Value::Null);
            }
            None => {
                context.insert(trace_key.to_string(), Value::Null);
                context.insert(
                    format!("{trace_key}_unavailable_reason"),
                    Value::String(format!("{env_key} not set")),
                );
            }
        }
    }
    context
}

fn report_trace_error(error: String) {
    if !TRACE_ERROR_REPORTED.swap(true, Ordering::Relaxed) {
        eprintln!("Consensus timing trace write failed (non-fatal): {error}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    lazy_static::lazy_static! {
        static ref TEST_ENV_MUTEX: Mutex<()> = Mutex::new(());
    }

    #[test]
    fn trace_emit_writes_jsonl_when_enabled() {
        let _guard = TEST_ENV_MUTEX.lock().expect("test env mutex");
        let previous_enabled = std::env::var(TRACE_ENABLED_ENV).ok();
        let previous_path = std::env::var(TRACE_PATH_ENV).ok();
        let path = crate::utils::test_temp_root(format!(
            "synergy-consensus-timing-trace-test-{}-{}.jsonl",
            std::process::id(),
            now_unix_ms()
        ));

        std::env::set_var(TRACE_ENABLED_ENV, "1");
        std::env::set_var(TRACE_PATH_ENV, &path);
        emit(
            "test_event",
            serde_json::json!({
                "height": 42,
                "block_hash": "abc"
            }),
        );

        match previous_enabled {
            Some(value) => std::env::set_var(TRACE_ENABLED_ENV, value),
            None => std::env::remove_var(TRACE_ENABLED_ENV),
        }
        match previous_path {
            Some(value) => std::env::set_var(TRACE_PATH_ENV, value),
            None => std::env::remove_var(TRACE_PATH_ENV),
        }

        let contents = fs::read_to_string(&path).expect("trace file should be written");
        let line = contents
            .lines()
            .next()
            .expect("trace file should have one line");
        let value: Value = serde_json::from_str(line).expect("trace line should be JSON");
        assert_eq!(value["schema"], TRACE_SCHEMA);
        assert_eq!(value["event_type"], "test_event");
        assert_eq!(value["event"], "test_event");
        assert_eq!(value["height"], 42);
        assert_eq!(value["block_hash"], "abc");
        assert_eq!(value["chain_id"], 1266);
        assert!(value["utc_time"].as_str().is_some());
        assert!(value["process_monotonic_ms"].as_u64().is_some());
        let _ = fs::remove_file(path);
    }
}
