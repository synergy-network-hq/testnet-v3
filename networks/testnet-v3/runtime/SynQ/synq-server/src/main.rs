//! synq-server — HTTP compile + run server for the SynQ IDE
//!
//! POST /compile        — compile SynQ source, sign with ephemeral ML-DSA-65
//! POST /attest         — wrap an EVM wallet signature in a Dilithium attestation
//! POST /session/new    — load bytecode into a fresh persistent VM, return session_id
//! POST /session/run    — call a function on an existing session VM
//! DELETE /session/:id  — destroy a session
//! GET  /health

use axum::{
    extract::{Json, Path, State},
    http::{Method, StatusCode},
    response::Json as RespJson,
    routing::{delete, get, post},
    Router,
};
use ruint::aliases::U256;
use serde::Deserialize;
use serde_json::json;
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use synq_compiler::{PQCCompiler, PQCSecurityLevel};
use synq_vm::{QuantumVM, Value};
use tower_http::cors::{Any, CorsLayer};

const SIGNING_ALGORITHM: &str = "dilithium";
/// Sessions idle longer than this are evicted on the next request.
const SESSION_TTL: Duration = Duration::from_secs(30 * 60); // 30 min

// ─── Session store ────────────────────────────────────────────────────────────

struct Session {
    vm: QuantumVM,
    last_used: Instant,
    /// State variable names in address order (name, address)
    state_vars: Vec<(String, u32)>,
}

type SessionStore = Arc<Mutex<HashMap<String, Session>>>;

fn new_session_id() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let t = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    // Simple unique ID: timestamp nanos + 4 random-ish bytes from stack address
    let ptr = &t as *const _ as u64;
    format!("{:x}{:x}", t.as_nanos(), ptr)
}

fn evict_stale(store: &mut HashMap<String, Session>) {
    store.retain(|_, s| s.last_used.elapsed() < SESSION_TTL);
}

// ─── helpers ─────────────────────────────────────────────────────────────────

fn hex_encode(b: &[u8]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect()
}

fn hex_decode_lossy(s: &str) -> Vec<u8> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    (0..s.len())
        .step_by(2)
        .filter_map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

fn value_to_json(v: &Value) -> serde_json::Value {
    match v {
        Value::I32(n) => json!({"type": "I32",  "value": n}),
        Value::I64(n) => json!({"type": "I64",  "value": n.to_string()}),
        Value::U128(n) => json!({"type": "U128", "value": n.to_string()}),
        Value::U256(n) => json!({"type": "U256", "value": n.to_string()}),
        Value::Bool(b) => json!({"type": "Bool", "value": b}),
        Value::Bytes(b) => json!({"type": "Bytes","value": hex_encode(b)}),
    }
}

fn value_display(v: &Value) -> String {
    match v {
        Value::I32(n) => n.to_string(),
        Value::I64(n) => n.to_string(),
        Value::U128(n) => n.to_string(),
        Value::U256(n) => n.to_string(),
        Value::Bool(b) => b.to_string(),
        Value::Bytes(b) => format!("0x{}", hex_encode(b)),
    }
}

/// Parse a single JSON arg value (number or quoted decimal string) into a VM Value.
fn parse_arg(v: &serde_json::Value) -> Result<Value, String> {
    // UInt256 semantics: all arguments must be non-negative integers.
    // Negative values are rejected here so the VM never sees a negative
    // I32 where an unsigned quantity is expected.
    match v {
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                if i < 0 {
                    return Err(format!("UInt256 arguments must be non-negative, got {}", i));
                }
                if i <= i32::MAX as i64 {
                    return Ok(Value::I32(i as i32));
                }
                return Ok(Value::U128(i as u128));
            }
            if let Some(u) = n.as_u64() {
                return Ok(Value::U128(u as u128));
            }
            // For values > u64::MAX (e.g. full Ethereum addresses as UInt256),
            // serde_json preserves the raw decimal string — parse it directly.
            match n.to_string().parse::<u128>() {
                Ok(u) => Ok(Value::U128(u)),
                Err(_) => Err(format!("Cannot represent {} as a UInt256 (max 2^128-1)", n)),
            }
        }
        serde_json::Value::String(s) => {
            let s = s.trim();
            if s.starts_with('-') {
                return Err(format!("UInt256 arguments must be non-negative, got {}", s));
            }
            // Try u128 first (fast path), fall back to full U256 for Ethereum addresses.
            if let Ok(u) = s.parse::<u128>() {
                return Ok(if u <= i32::MAX as u128 {
                    Value::I32(u as i32)
                } else {
                    Value::U128(u)
                });
            }
            // Full UInt256 path (e.g. 160-bit Ethereum address as decimal)
            match s.parse::<U256>() {
                Ok(v) => Ok(Value::U256(v)),
                Err(_) => Err(format!("Cannot parse {:?} as a UInt256 integer", s)),
            }
        }
        other => Err(format!("Expected number or string, got {}", other)),
    }
}

// ─── /compile ────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct CompileRequest {
    source: String,
}

#[derive(serde::Serialize)]
struct CompileResponse {
    success: bool,
    bytecode: Option<String>,
    signature_sidecar: Option<serde_json::Value>,
    state_vars: Vec<(String, u32)>,
    errors: Vec<String>,
    warnings: Vec<String>,
}

async fn compile_handler(
    Json(req): Json<CompileRequest>,
) -> (StatusCode, RespJson<CompileResponse>) {
    let ast = match synq_compiler::parser::parse(&req.source) {
        Ok(a) => a,
        Err(e) => {
            return (
                StatusCode::OK,
                RespJson(CompileResponse {
                    success: false,
                    bytecode: None,
                    signature_sidecar: None,
                    state_vars: vec![],
                    errors: vec![format!("Parse error: {}", e)],
                    warnings: vec![],
                }),
            )
        }
    };

    let (bytecode, state_vars) = match synq_compiler::codegen::CodeGenerator::new().generate(&ast) {
        Ok(b) => b,
        Err(e) => {
            return (
                StatusCode::OK,
                RespJson(CompileResponse {
                    success: false,
                    bytecode: None,
                    signature_sidecar: None,
                    state_vars: vec![],
                    errors: vec![format!("Codegen error: {}", e)],
                    warnings: vec![],
                }),
            )
        }
    };

    let pqc = PQCCompiler::new(PQCSecurityLevel::Enhanced);
    let keypair = pqc.generate_keypair(SIGNING_ALGORITHM).expect("keygen");
    let sig = pqc
        .sign_message(&keypair.private_key, &bytecode, SIGNING_ALGORITHM)
        .expect("sign");

    let sidecar = json!({
        "mode": "ephemeral", "algorithm": sig.algorithm,
        "security_level": format!("{:?}", sig.security_level),
        "public_key": hex_encode(&keypair.public_key),
        "signature":  hex_encode(&sig.signature),
    });

    (
        StatusCode::OK,
        RespJson(CompileResponse {
            success: true,
            bytecode: Some(format!("0x{}", hex::encode(&bytecode))),
            signature_sidecar: Some(sidecar),
            state_vars,
            errors: vec![],
            warnings: vec![],
        }),
    )
}

// ─── /attest ─────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct AttestRequest {
    bytecode: String,
    evm_address: String,
    evm_signature: String,
    bytecode_hash: String,
}

#[derive(serde::Serialize)]
struct AttestResponse {
    success: bool,
    hybrid_sidecar: Option<serde_json::Value>,
    error: Option<String>,
}

async fn attest_handler(Json(req): Json<AttestRequest>) -> (StatusCode, RespJson<AttestResponse>) {
    let raw_bytecode = hex_decode_lossy(&req.bytecode);
    let evm_sig_bytes = hex_decode_lossy(&req.evm_signature);
    if raw_bytecode.is_empty() {
        return (
            StatusCode::OK,
            RespJson(AttestResponse {
                success: false,
                hybrid_sidecar: None,
                error: Some("bytecode empty".into()),
            }),
        );
    }
    if evm_sig_bytes.len() != 65 {
        return (
            StatusCode::OK,
            RespJson(AttestResponse {
                success: false,
                hybrid_sidecar: None,
                error: Some(format!(
                    "evm_signature must be 65 bytes, got {}",
                    evm_sig_bytes.len()
                )),
            }),
        );
    }
    let mut msg = Vec::with_capacity(evm_sig_bytes.len() + raw_bytecode.len());
    msg.extend_from_slice(&evm_sig_bytes);
    msg.extend_from_slice(&raw_bytecode);

    let pqc = PQCCompiler::new(PQCSecurityLevel::Enhanced);
    let keypair = match pqc.generate_keypair(SIGNING_ALGORITHM) {
        Ok(k) => k,
        Err(e) => {
            return (
                StatusCode::OK,
                RespJson(AttestResponse {
                    success: false,
                    hybrid_sidecar: None,
                    error: Some(format!("PQC keygen: {}", e)),
                }),
            )
        }
    };
    let pqc_sig = match pqc.sign_message(&keypair.private_key, &msg, SIGNING_ALGORITHM) {
        Ok(s) => s,
        Err(e) => {
            return (
                StatusCode::OK,
                RespJson(AttestResponse {
                    success: false,
                    hybrid_sidecar: None,
                    error: Some(format!("PQC sign: {}", e)),
                }),
            )
        }
    };

    (
        StatusCode::OK,
        RespJson(AttestResponse {
            success: true,
            error: None,
            hybrid_sidecar: Some(json!({
                "mode": "hybrid",
                "evm": { "address": req.evm_address, "signature": req.evm_signature,
                         "message_hash": req.bytecode_hash },
                "pqc": { "algorithm": pqc_sig.algorithm,
                         "security_level": format!("{:?}", pqc_sig.security_level),
                         "public_key": hex_encode(&keypair.public_key),
                         "signature":  hex_encode(&pqc_sig.signature),
                         "signed_message": "evm_signature_bytes ++ raw_bytecode_bytes" },
            })),
        }),
    )
}

// ─── POST /session/new ───────────────────────────────────────────────────────
//
// Body: { bytecode: "0x..." }
// Creates a persistent VM session, loads the bytecode, returns session_id.

#[derive(Deserialize)]
struct NewSessionRequest {
    bytecode: String,
    #[serde(default)]
    state_vars: Vec<(String, u32)>,
}

#[derive(serde::Serialize)]
struct NewSessionResponse {
    success: bool,
    session_id: Option<String>,
    error: Option<String>,
}

async fn session_new_handler(
    State(store): State<SessionStore>,
    Json(req): Json<NewSessionRequest>,
) -> (StatusCode, RespJson<NewSessionResponse>) {
    let raw = hex_decode_lossy(&req.bytecode);
    if raw.len() < 15 {
        return (
            StatusCode::OK,
            RespJson(NewSessionResponse {
                success: false,
                session_id: None,
                error: Some("bytecode too short or invalid".into()),
            }),
        );
    }

    let mut vm = QuantumVM::new();
    if let Err(e) = vm.load_bytecode(&raw) {
        return (
            StatusCode::OK,
            RespJson(NewSessionResponse {
                success: false,
                session_id: None,
                error: Some(format!("Failed to load bytecode: {}", e)),
            }),
        );
    }

    let id = new_session_id();
    {
        let mut map = store.lock().unwrap();
        evict_stale(&mut map);
        map.insert(
            id.clone(),
            Session {
                vm,
                last_used: Instant::now(),
                state_vars: req.state_vars.clone(),
            },
        );
    }

    (
        StatusCode::OK,
        RespJson(NewSessionResponse {
            success: true,
            session_id: Some(id),
            error: None,
        }),
    )
}

// ─── POST /session/run ───────────────────────────────────────────────────────
//
// Body: { session_id: "...", function: "mint", args: [1000] }
// Calls a function on the persistent VM. State is preserved between calls.

#[derive(Deserialize)]
struct SessionRunRequest {
    session_id: String,
    function: String,
    args: Option<Vec<serde_json::Value>>,
}

#[derive(serde::Serialize)]
struct RunResponse {
    success: bool,
    result: Option<serde_json::Value>,
    output: String,
    error: Option<String>,
}

async fn session_run_handler(
    State(store): State<SessionStore>,
    Json(req): Json<SessionRunRequest>,
) -> (StatusCode, RespJson<RunResponse>) {
    let mut vm_args: Vec<Value> = Vec::new();
    for (i, raw) in req.args.unwrap_or_default().iter().enumerate() {
        match parse_arg(raw) {
            Ok(v) => vm_args.push(v),
            Err(e) => {
                return (
                    StatusCode::OK,
                    RespJson(RunResponse {
                        success: false,
                        result: None,
                        output: String::new(),
                        error: Some(format!("arg[{}]: {}", i, e)),
                    }),
                )
            }
        }
    }

    let mut map = store.lock().unwrap();
    let session = match map.get_mut(&req.session_id) {
        Some(s) => s,
        None => {
            return (
                StatusCode::OK,
                RespJson(RunResponse {
                    success: false,
                    result: None,
                    output: String::new(),
                    error: Some(format!(
                        "Session '{}' not found or expired. Create a new session.",
                        req.session_id
                    )),
                }),
            )
        }
    };

    session.last_used = Instant::now();

    match session.vm.call_function(&req.function, &vm_args) {
        Ok(maybe_val) => {
            let (result_json, output) = match &maybe_val {
                Some(v) => (
                    Some(value_to_json(v)),
                    format!("Return value: {}", value_display(v)),
                ),
                None => (None, "Function completed (no return value)".to_string()),
            };
            (
                StatusCode::OK,
                RespJson(RunResponse {
                    success: true,
                    result: result_json,
                    output,
                    error: None,
                }),
            )
        }
        Err(synq_vm::VMError::Reverted(msg)) => (
            StatusCode::OK,
            RespJson(RunResponse {
                success: false,
                result: None,
                output: String::new(),
                error: Some(format!("require failed: {}", msg)),
            }),
        ),
        Err(e) => (
            StatusCode::OK,
            RespJson(RunResponse {
                success: false,
                result: None,
                output: String::new(),
                error: Some(format!("{}", e)),
            }),
        ),
    }
}

// ─── DELETE /session/:id ─────────────────────────────────────────────────────

async fn session_delete_handler(
    State(store): State<SessionStore>,
    Path(id): Path<String>,
) -> (StatusCode, RespJson<serde_json::Value>) {
    let removed = store.lock().unwrap().remove(&id).is_some();
    (StatusCode::OK, RespJson(json!({ "success": removed })))
}

// ─── /health ─────────────────────────────────────────────────────────────────

async fn health(State(store): State<SessionStore>) -> RespJson<serde_json::Value> {
    let count = store.lock().unwrap().len();
    RespJson(json!({"status": "ok", "service": "synq-compiler", "active_sessions": count}))
}

async fn session_state_handler(
    State(store): State<SessionStore>,
    Path(session_id): Path<String>,
) -> (StatusCode, RespJson<serde_json::Value>) {
    let map = store.lock().unwrap();
    let session = match map.get(&session_id) {
        Some(s) => s,
        None => {
            return (
                StatusCode::OK,
                RespJson(serde_json::json!({
                    "success": false, "error": "Session not found"
                })),
            )
        }
    };
    let mut state_map = serde_json::Map::new();
    for (name, addr) in &session.state_vars {
        let val = session.vm.memory.get(&(*addr as usize));
        let json_val = match val {
            Some(synq_vm::Value::I32(v)) => serde_json::json!(v),
            Some(synq_vm::Value::U128(v)) => serde_json::json!(v.to_string()),
            Some(synq_vm::Value::U256(v)) => serde_json::json!(v.to_string()),
            None => serde_json::json!(0),
            _ => serde_json::json!(null),
        };
        state_map.insert(name.clone(), json_val);
    }
    (
        StatusCode::OK,
        RespJson(serde_json::json!({
            "success": true,
            "state": serde_json::Value::Object(state_map)
        })),
    )
}

// ─── main ────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    let store: SessionStore = Arc::new(Mutex::new(HashMap::new()));

    let cors = CorsLayer::new()
        .allow_methods([Method::GET, Method::POST, Method::DELETE, Method::OPTIONS])
        .allow_headers(Any)
        .allow_origin(Any);

    let app = Router::new()
        .route("/health", get(health))
        .route("/compile", post(compile_handler))
        .route("/attest", post(attest_handler))
        .route("/session/new", post(session_new_handler))
        .route("/session/run", post(session_run_handler))
        .route("/session/:id", delete(session_delete_handler))
        .route("/session/:id/state", get(session_state_handler))
        .with_state(store)
        .layer(cors);

    let addr = "0.0.0.0:3030";
    println!("SynQ server listening on {} (session TTL: 30 min)", addr);
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
