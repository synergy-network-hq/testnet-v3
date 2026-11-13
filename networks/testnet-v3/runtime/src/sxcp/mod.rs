use crate::crypto::pqc::{PQCAlgorithm, PQCManager, PQCPublicKey, PQCSignature};
use base64::{engine::general_purpose, Engine as _};
use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

const DEFAULT_HEARTBEAT_TIMEOUT_SECS: u64 = 120;
const MIN_HEARTBEAT_TIMEOUT_SECS: u64 = 10;
const MAX_EVENT_HASH_LEN: usize = 512;
const DEFAULT_SLASH_PENALTY: i64 = 25;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayerInfo {
    pub address: String,
    pub public_key: String,
    pub reputation: i64,
    pub attestation_count: u64,
    pub slashed: bool,
    pub active: bool,
    pub online: bool,
    pub last_heartbeat: u64,
    pub registered_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Attestation {
    pub event_hash: String,
    pub aggregate_sig: String,
    pub metadata: serde_json::Value,
    pub submitted_by: String,
    pub participants: Vec<String>,
    pub support_count: u64,
    pub threshold: u64,
    pub timestamp: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventAttestationState {
    pub event_hash: String,
    pub metadata: serde_json::Value,
    pub supports: HashMap<String, String>,
    pub aggregate_sig: Option<String>,
    pub finalized: bool,
    pub first_seen: u64,
    pub last_updated: u64,
    pub finalized_at: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlashingEvent {
    pub relayer: String,
    pub reason: String,
    pub penalty: i64,
    pub timestamp: u64,
}

#[derive(Debug, Default)]
pub struct SxcpState {
    pub relayers: HashMap<String, RelayerInfo>,
    pub attestations: Vec<Attestation>,
    pub events: HashMap<String, EventAttestationState>,
    pub slashing_events: Vec<SlashingEvent>,
    pub threshold_t: u64,
    pub total_n: u64,
    pub heartbeat_timeout_secs: u64,
}

lazy_static! {
    pub static ref SXCP_STATE: Arc<Mutex<SxcpState>> = Arc::new(Mutex::new(SxcpState {
        relayers: HashMap::new(),
        attestations: Vec::new(),
        events: HashMap::new(),
        slashing_events: Vec::new(),
        // Default to dynamic two-thirds threshold once n is known. Until then, treat as 0.
        threshold_t: 0,
        total_n: 0,
        heartbeat_timeout_secs: DEFAULT_HEARTBEAT_TIMEOUT_SECS,
    }));
}

fn now_ts() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn relayer_is_online(relayer: &RelayerInfo, now: u64, timeout_secs: u64) -> bool {
    let timeout = timeout_secs.max(MIN_HEARTBEAT_TIMEOUT_SECS);
    relayer.active && !relayer.slashed && now.saturating_sub(relayer.last_heartbeat) <= timeout
}

fn refresh_liveness(state: &mut SxcpState, now: u64) {
    let timeout = state.heartbeat_timeout_secs.max(MIN_HEARTBEAT_TIMEOUT_SECS);
    for relayer in state.relayers.values_mut() {
        relayer.online = relayer_is_online(relayer, now, timeout);
    }
}

fn recompute_quorum(state: &mut SxcpState) {
    let ts = now_ts();
    refresh_liveness(state, ts);
    state.total_n = state
        .relayers
        .values()
        .filter(|r| r.active && !r.slashed && r.online)
        .count() as u64;

    if state.total_n == 0 {
        state.threshold_t = 0;
        return;
    }

    state.threshold_t = (state.total_n * 2).div_ceil(3);
}

fn eligible_supporters(state: &SxcpState, event_hash: &str, ts: u64) -> Vec<String> {
    let mut supporters = Vec::new();
    let timeout = state.heartbeat_timeout_secs.max(MIN_HEARTBEAT_TIMEOUT_SECS);
    let Some(event_state) = state.events.get(event_hash) else {
        return supporters;
    };

    for relayer_address in event_state.supports.keys() {
        let eligible = state
            .relayers
            .get(relayer_address)
            .map(|r| relayer_is_online(r, ts, timeout))
            .unwrap_or(false);

        if eligible {
            supporters.push(relayer_address.clone());
        }
    }

    supporters.sort();
    supporters
}

fn try_finalize_event(
    state: &mut SxcpState,
    event_hash: &str,
    aggregate_sig_hint: Option<&str>,
    submitted_by_hint: Option<&str>,
    ts: u64,
) -> Option<Attestation> {
    if state.threshold_t == 0 {
        return None;
    }

    let supporters = eligible_supporters(state, event_hash, ts);
    if (supporters.len() as u64) < state.threshold_t {
        return None;
    }

    let (already_finalized, metadata, existing_aggregate_sig) = {
        let event_state = state.events.get(event_hash)?;
        (
            event_state.finalized,
            event_state.metadata.clone(),
            event_state.aggregate_sig.clone(),
        )
    };

    if already_finalized {
        return None;
    }

    let aggregate_sig = aggregate_sig_hint
        .map(|v| v.to_string())
        .or(existing_aggregate_sig)
        .or_else(|| {
            state.events.get(event_hash).and_then(|event_state| {
                supporters
                    .iter()
                    .find_map(|relayer| event_state.supports.get(relayer).cloned())
            })
        })
        .unwrap_or_else(|| "sxcp-testnet-aggregate-signature".to_string());

    let submitted_by = submitted_by_hint
        .map(|s| s.to_string())
        .or_else(|| supporters.first().cloned())
        .unwrap_or_default();

    if let Some(event_state) = state.events.get_mut(event_hash) {
        event_state.finalized = true;
        event_state.finalized_at = Some(ts);
        event_state.last_updated = ts;
        event_state.aggregate_sig = Some(aggregate_sig.clone());
    }

    for relayer in &supporters {
        if let Some(info) = state.relayers.get_mut(relayer) {
            info.reputation = info.reputation.saturating_add(2);
        }
    }

    let finalized = Attestation {
        event_hash: event_hash.to_string(),
        aggregate_sig,
        metadata,
        submitted_by,
        participants: supporters.clone(),
        support_count: supporters.len() as u64,
        threshold: state.threshold_t,
        timestamp: ts,
    };

    state.attestations.push(finalized.clone());
    Some(finalized)
}

fn validate_event_hash(event_hash: &str) -> Result<(), String> {
    let trimmed = event_hash.trim();
    if trimmed.is_empty() {
        return Err("event_hash cannot be empty".to_string());
    }
    if trimmed.len() > MAX_EVENT_HASH_LEN {
        return Err(format!(
            "event_hash too large (max {} chars)",
            MAX_EVENT_HASH_LEN
        ));
    }
    Ok(())
}

fn parse_signature_algorithm(metadata: &serde_json::Value) -> Result<PQCAlgorithm, String> {
    let algo = metadata
        .get("signature_algorithm")
        .or_else(|| metadata.get("algorithm"))
        .and_then(|v| v.as_str())
        .unwrap_or("fndsa")
        .trim()
        .to_ascii_lowercase();

    match algo.as_str() {
        "" | "fndsa" | "fn-dsa" | "fn_dsa" | "falcon" | "falcon-1024" => Ok(PQCAlgorithm::FNDSA),
        _ => Err(format!(
            "Unsupported relayer signature algorithm: {}; use fndsa",
            algo
        )),
    }
}

fn verify_relayer_signature(
    relayer: &RelayerInfo,
    event_hash: &str,
    encoded_signature: &str,
    metadata: &serde_json::Value,
) -> Result<(), String> {
    let public_key_bytes = general_purpose::STANDARD
        .decode(relayer.public_key.trim())
        .map_err(|_| "Invalid relayer public key encoding (expected base64)".to_string())?;
    let signature_bytes = general_purpose::STANDARD
        .decode(encoded_signature.trim())
        .map_err(|_| "Invalid signature encoding (expected base64)".to_string())?;

    let algorithm = parse_signature_algorithm(metadata)?;
    let message = event_hash.as_bytes();
    let manager = PQCManager::new();
    let public_key = PQCPublicKey {
        algorithm: algorithm.clone(),
        key_data: public_key_bytes,
        key_id: relayer.address.clone(),
        created_at: relayer.registered_at,
    };
    let signature = PQCSignature {
        algorithm,
        signature_data: signature_bytes,
        message_hash: message.to_vec(),
        public_key_id: relayer.address.clone(),
        created_at: now_ts(),
    };

    match manager.verify(&public_key, &signature, message) {
        Ok(true) => Ok(()),
        Ok(false) => Err("Relayer signature verification returned false".to_string()),
        Err(err) => Err(format!("Relayer signature verification failed: {err}")),
    }
}

pub fn register_relayer(address: &str, public_key: &str) -> serde_json::Value {
    if address.trim().is_empty() || public_key.trim().is_empty() {
        return json!({
            "success": false,
            "error": "address and public_key are required"
        });
    }

    let mut state = SXCP_STATE.lock().unwrap();
    let ts = now_ts();
    let entry = state
        .relayers
        .entry(address.to_string())
        .or_insert(RelayerInfo {
            address: address.to_string(),
            public_key: public_key.to_string(),
            reputation: 0,
            attestation_count: 0,
            slashed: false,
            active: true,
            online: true,
            last_heartbeat: ts,
            registered_at: ts,
        });

    // Update key if re-registering (testnet convenience).
    entry.public_key = public_key.to_string();
    entry.active = true;
    entry.slashed = false;
    entry.online = true;
    entry.last_heartbeat = ts;

    recompute_quorum(&mut state);

    json!({
        "success": true,
        "message": "Relayer registered",
        "quorum": { "n": state.total_n, "t": state.threshold_t }
    })
}

pub fn unregister_relayer(address: &str) -> serde_json::Value {
    let mut state = SXCP_STATE.lock().unwrap();
    if let Some(relayer) = state.relayers.get_mut(address) {
        relayer.active = false;
        relayer.online = false;
        recompute_quorum(&mut state);
        return json!({
            "success": true,
            "message": "Relayer deactivated",
            "quorum": { "n": state.total_n, "t": state.threshold_t }
        });
    }
    json!({"success": false, "error": "Relayer not found"})
}

pub fn heartbeat_relayer(address: &str) -> serde_json::Value {
    let mut state = SXCP_STATE.lock().unwrap();
    if let Some(relayer) = state.relayers.get_mut(address) {
        if relayer.slashed {
            return json!({"success": false, "error": "Relayer is slashed"});
        }

        relayer.active = true;
        relayer.online = true;
        relayer.last_heartbeat = now_ts();
        relayer.reputation = relayer.reputation.saturating_add(1);
        recompute_quorum(&mut state);
        return json!({
            "success": true,
            "message": "Heartbeat recorded",
            "quorum": { "n": state.total_n, "t": state.threshold_t }
        });
    }
    json!({"success": false, "error": "Relayer not found"})
}

pub fn get_relayer_set() -> serde_json::Value {
    let mut state = SXCP_STATE.lock().unwrap();
    recompute_quorum(&mut state);
    let mut relayers: Vec<RelayerInfo> = state.relayers.values().cloned().collect();
    relayers.sort_by(|a, b| a.address.cmp(&b.address));
    json!({
        "relayers": relayers,
        "heartbeat_timeout_secs": state.heartbeat_timeout_secs,
        "quorum": { "n": state.total_n, "t": state.threshold_t }
    })
}

pub fn submit_attestation(
    submitted_by: &str,
    event_hash: &str,
    aggregate_sig: &str,
    metadata: serde_json::Value,
) -> serde_json::Value {
    if submitted_by.trim().is_empty() || aggregate_sig.trim().is_empty() {
        return json!({
            "success": false,
            "error": "submitted_by and aggregate_sig are required"
        });
    }
    if let Err(error) = validate_event_hash(event_hash) {
        return json!({"success": false, "error": error});
    }

    let mut state = SXCP_STATE.lock().unwrap();
    let ts = now_ts();
    recompute_quorum(&mut state);

    let relayer = match state.relayers.get(submitted_by) {
        Some(relayer) => relayer.clone(),
        None => return json!({"success": false, "error": "Submitting relayer is unknown"}),
    };

    if !relayer.active || relayer.slashed || !relayer.online {
        return json!({"success": false, "error": "Submitting relayer is not active"});
    }

    if let Err(error) = verify_relayer_signature(&relayer, event_hash, aggregate_sig, &metadata) {
        return json!({"success": false, "error": error});
    }

    let event_hash = event_hash.to_string();

    if state
        .events
        .get(&event_hash)
        .map(|event| event.finalized)
        .unwrap_or(false)
    {
        return json!({
            "success": false,
            "error": "event_hash already finalized"
        });
    }

    let event_state = state
        .events
        .entry(event_hash.clone())
        .or_insert(EventAttestationState {
            event_hash: event_hash.clone(),
            metadata: metadata.clone(),
            supports: HashMap::new(),
            aggregate_sig: None,
            finalized: false,
            first_seen: ts,
            last_updated: ts,
            finalized_at: None,
        });

    if event_state.supports.contains_key(submitted_by) {
        if let Some(relayer) = state.relayers.get_mut(submitted_by) {
            relayer.reputation = relayer.reputation.saturating_sub(5);
        }
        return json!({
            "success": false,
            "error": "duplicate attestation support from same relayer"
        });
    }

    if event_state.metadata.is_null() || event_state.metadata == json!({}) {
        event_state.metadata = metadata;
    }
    event_state.last_updated = ts;
    event_state
        .supports
        .insert(submitted_by.to_string(), aggregate_sig.to_string());

    if let Some(relayer) = state.relayers.get_mut(submitted_by) {
        relayer.attestation_count = relayer.attestation_count.saturating_add(1);
        relayer.reputation = relayer.reputation.saturating_add(5);
        relayer.last_heartbeat = ts;
        relayer.online = true;
    }

    if let Some(finalized) = try_finalize_event(
        &mut state,
        &event_hash,
        Some(aggregate_sig),
        Some(submitted_by),
        ts,
    ) {
        return json!({
            "success": true,
            "message": "Attestation finalized",
            "finalized": true,
            "event_hash": finalized.event_hash,
            "support_count": finalized.support_count,
            "threshold": finalized.threshold,
            "participants": finalized.participants,
            "timestamp": finalized.timestamp,
            "quorum": { "n": state.total_n, "t": state.threshold_t }
        });
    }

    let support_count = eligible_supporters(&state, &event_hash, ts).len() as u64;

    json!({
        "success": true,
        "message": "Attestation support recorded",
        "finalized": false,
        "event_hash": event_hash,
        "support_count": support_count,
        "threshold": state.threshold_t,
        "quorum": { "n": state.total_n, "t": state.threshold_t },
        "timestamp": ts
    })
}

pub fn get_attestations(limit: Option<usize>) -> serde_json::Value {
    let state = SXCP_STATE.lock().unwrap();
    let lim = limit.unwrap_or(100).min(10_000);
    let start = state.attestations.len().saturating_sub(lim);
    json!({
        "attestations": state.attestations[start..].to_vec(),
        "count": state.attestations.len()
    })
}

pub fn get_event_attestation(event_hash: &str) -> serde_json::Value {
    let mut state = SXCP_STATE.lock().unwrap();
    recompute_quorum(&mut state);
    let ts = now_ts();
    let Some(event_state) = state.events.get(event_hash).cloned() else {
        return json!({
            "success": false,
            "error": "event_hash not found"
        });
    };

    let eligible = eligible_supporters(&state, event_hash, ts);
    let mut all_supporters: Vec<String> = event_state.supports.keys().cloned().collect();
    all_supporters.sort();

    json!({
        "success": true,
        "event": event_state,
        "all_supporters": all_supporters,
        "eligible_supporters": eligible,
        "support_count": eligible.len(),
        "threshold": state.threshold_t,
        "quorum": { "n": state.total_n, "t": state.threshold_t }
    })
}

pub fn slash_relayer(address: &str, reason: &str, penalty: Option<i64>) -> serde_json::Value {
    if address.trim().is_empty() {
        return json!({"success": false, "error": "address is required"});
    }
    if reason.trim().is_empty() {
        return json!({"success": false, "error": "reason is required"});
    }

    let mut state = SXCP_STATE.lock().unwrap();
    let ts = now_ts();
    let slash_penalty = penalty.unwrap_or(DEFAULT_SLASH_PENALTY).max(1);

    let relayer = match state.relayers.get_mut(address) {
        Some(relayer) => relayer,
        None => return json!({"success": false, "error": "Relayer not found"}),
    };

    relayer.slashed = true;
    relayer.active = false;
    relayer.online = false;
    relayer.reputation = relayer.reputation.saturating_sub(slash_penalty);

    state.slashing_events.push(SlashingEvent {
        relayer: address.to_string(),
        reason: reason.to_string(),
        penalty: slash_penalty,
        timestamp: ts,
    });

    for event in state.events.values_mut() {
        if !event.finalized {
            event.supports.remove(address);
            event.last_updated = ts;
        }
    }

    recompute_quorum(&mut state);

    // Quorum may shrink after slashing; attempt to finalize pending events again.
    let pending_event_hashes: Vec<String> = state
        .events
        .iter()
        .filter_map(|(event_hash, event)| {
            if event.finalized {
                None
            } else {
                Some(event_hash.clone())
            }
        })
        .collect();

    let mut newly_finalized = Vec::new();
    for event_hash in pending_event_hashes {
        if let Some(attestation) = try_finalize_event(&mut state, &event_hash, None, None, ts) {
            newly_finalized.push(attestation.event_hash);
        }
    }

    json!({
        "success": true,
        "message": "Relayer slashed",
        "relayer": address,
        "reason": reason,
        "penalty": slash_penalty,
        "newly_finalized_events": newly_finalized,
        "quorum": { "n": state.total_n, "t": state.threshold_t }
    })
}

pub fn get_relayer_health() -> serde_json::Value {
    let mut state = SXCP_STATE.lock().unwrap();
    recompute_quorum(&mut state);
    let ts = now_ts();
    let timeout = state.heartbeat_timeout_secs.max(MIN_HEARTBEAT_TIMEOUT_SECS);

    let mut entries: Vec<serde_json::Value> = state
        .relayers
        .values()
        .map(|relayer| {
            let heartbeat_age = ts.saturating_sub(relayer.last_heartbeat);
            json!({
                "address": relayer.address,
                "active": relayer.active,
                "slashed": relayer.slashed,
                "online": relayer.online,
                "heartbeat_age_secs": heartbeat_age,
                "heartbeat_timeout_secs": timeout,
                "eligible_for_quorum": relayer_is_online(relayer, ts, timeout),
                "reputation": relayer.reputation,
                "attestation_count": relayer.attestation_count
            })
        })
        .collect();

    entries.sort_by(|a, b| {
        let a_addr = a
            .get("address")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        let b_addr = b
            .get("address")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        a_addr.cmp(b_addr)
    });

    json!({
        "relayers": entries,
        "quorum": { "n": state.total_n, "t": state.threshold_t }
    })
}

pub fn get_sxcp_status() -> serde_json::Value {
    let mut state = SXCP_STATE.lock().unwrap();
    recompute_quorum(&mut state);

    let active = state.relayers.values().filter(|r| r.active).count();
    let online = state.relayers.values().filter(|r| r.online).count();
    let slashed = state.relayers.values().filter(|r| r.slashed).count();
    let finalized_events = state.events.values().filter(|e| e.finalized).count();
    let pending_events = state.events.values().filter(|e| !e.finalized).count();

    json!({
        "quorum": { "n": state.total_n, "t": state.threshold_t },
        "heartbeat_timeout_secs": state.heartbeat_timeout_secs,
        "relayer_totals": {
            "registered": state.relayers.len(),
            "active": active,
            "online": online,
            "slashed": slashed
        },
        "event_totals": {
            "tracked": state.events.len(),
            "pending": pending_events,
            "finalized": finalized_events
        },
        "attestation_count": state.attestations.len(),
        "slashing_event_count": state.slashing_events.len()
    })
}

pub fn set_heartbeat_timeout(timeout_secs: u64) -> serde_json::Value {
    if timeout_secs < MIN_HEARTBEAT_TIMEOUT_SECS {
        return json!({
            "success": false,
            "error": format!("timeout must be >= {} seconds", MIN_HEARTBEAT_TIMEOUT_SECS)
        });
    }

    let mut state = SXCP_STATE.lock().unwrap();
    state.heartbeat_timeout_secs = timeout_secs;
    recompute_quorum(&mut state);

    json!({
        "success": true,
        "heartbeat_timeout_secs": state.heartbeat_timeout_secs,
        "quorum": { "n": state.total_n, "t": state.threshold_t }
    })
}

pub fn reset_state() -> serde_json::Value {
    let mut state = SXCP_STATE.lock().unwrap();
    state.relayers.clear();
    state.attestations.clear();
    state.events.clear();
    state.slashing_events.clear();
    state.total_n = 0;
    state.threshold_t = 0;
    state.heartbeat_timeout_secs = DEFAULT_HEARTBEAT_TIMEOUT_SECS;

    json!({
        "success": true,
        "message": "SXCP state reset"
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::pqc::{PQCAlgorithm, PQCManager, PQCPrivateKey};
    use base64::engine::general_purpose;
    use std::sync::{Mutex, MutexGuard};

    static SXCP_TEST_LOCK: Mutex<()> = Mutex::new(());

    fn test_guard() -> MutexGuard<'static, ()> {
        SXCP_TEST_LOCK.lock().unwrap()
    }

    fn reset_for_test() {
        let _ = reset_state();
    }

    fn register_test_relayer(address: &str) -> PQCPrivateKey {
        let mut manager = PQCManager::new();
        let (public_key, private_key) = manager
            .generate_keypair(PQCAlgorithm::FNDSA)
            .expect("relayer FN-DSA key generation should succeed");
        let public_b64 = general_purpose::STANDARD.encode(public_key.key_data);
        let result = register_relayer(address, &public_b64);
        assert_eq!(result["success"], true);
        private_key
    }

    fn sign_event_hash(private_key: &PQCPrivateKey, event_hash: &str) -> String {
        let mut manager = PQCManager::new();
        let signature = manager
            .sign(private_key, event_hash.as_bytes())
            .expect("FN-DSA signing should succeed");
        general_purpose::STANDARD.encode(signature.signature_data)
    }

    #[test]
    fn quorum_attestation_requires_multiple_supporters() {
        let _guard = test_guard();
        reset_for_test();

        let r1 = register_test_relayer("r1");
        let r2 = register_test_relayer("r2");
        let r3 = register_test_relayer("r3");
        let _r4 = register_test_relayer("r4");

        let event_hash = "event-a";
        let first = submit_attestation(
            "r1",
            event_hash,
            &sign_event_hash(&r1, event_hash),
            json!({"source_chain":"sepolia","signature_algorithm":"fndsa"}),
        );
        assert_eq!(first["success"], true);
        assert_eq!(first["finalized"], false);

        let second = submit_attestation(
            "r2",
            event_hash,
            &sign_event_hash(&r2, event_hash),
            json!({"signature_algorithm":"fndsa"}),
        );
        assert_eq!(second["success"], true);
        assert_eq!(second["finalized"], false);

        let third = submit_attestation(
            "r3",
            event_hash,
            &sign_event_hash(&r3, event_hash),
            json!({"signature_algorithm":"fndsa"}),
        );
        assert_eq!(third["success"], true);
        assert_eq!(third["finalized"], true);

        let attestations = get_attestations(Some(10));
        assert_eq!(attestations["count"], 1);
    }

    #[test]
    fn duplicate_support_is_rejected() {
        let _guard = test_guard();
        reset_for_test();

        let r1 = register_test_relayer("r1");
        let _r2 = register_test_relayer("r2");

        let event_hash = "event-b";
        let first = submit_attestation(
            "r1",
            event_hash,
            &sign_event_hash(&r1, event_hash),
            json!({"signature_algorithm":"fndsa"}),
        );
        assert_eq!(first["success"], true);

        let duplicate = submit_attestation(
            "r1",
            event_hash,
            &sign_event_hash(&r1, event_hash),
            json!({"signature_algorithm":"fndsa"}),
        );
        assert_eq!(duplicate["success"], false);
    }

    #[test]
    fn slashing_relayer_reduces_quorum_population() {
        let _guard = test_guard();
        reset_for_test();

        let _r1 = register_test_relayer("r1");
        let _r2 = register_test_relayer("r2");
        let _r3 = register_test_relayer("r3");
        let _r4 = register_test_relayer("r4");

        let before = get_sxcp_status();
        assert_eq!(before["quorum"]["n"], 4);
        assert_eq!(before["quorum"]["t"], 3);

        let slash = slash_relayer("r4", "malformed signatures", Some(40));
        assert_eq!(slash["success"], true);

        let after = get_sxcp_status();
        assert_eq!(after["quorum"]["n"], 3);
        assert_eq!(after["quorum"]["t"], 2);
    }

    #[test]
    fn invalid_signature_is_rejected() {
        let _guard = test_guard();
        reset_for_test();

        let _r1 = register_test_relayer("r1");
        let _r2 = register_test_relayer("r2");

        let event_hash = "event-invalid-sig";
        let invalid = submit_attestation(
            "r1",
            event_hash,
            "bm90LWEtdmFsaWQtc2lnbmF0dXJl", // base64("not-a-valid-signature")
            json!({"signature_algorithm":"fndsa"}),
        );
        assert_eq!(invalid["success"], false);
    }
}
