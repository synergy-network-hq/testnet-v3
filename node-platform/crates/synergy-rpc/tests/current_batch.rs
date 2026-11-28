//! Framework data/accounting tests. Actual native pool/private Genesis coverage
//! lives in synergy-node's existing genuine public fixture integration.
use serde_json::{json, Value};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc, Mutex,
};
use synergy_protocol_types::{
    R1GenesisReference, R1NetworkCoordinate, R1NetworkRef, R1ProfileRef, R1ProfileSetReference,
};
use synergy_rpc::{
    auth::RpcAuthenticator,
    middleware::RpcLimits,
    provider::RpcResponseCapacity,
    rate_limit::{RateLimit, RpcRateLimiter},
    server::RpcServer,
    RpcDispatcher, RpcError,
};

#[derive(Default)]
struct State {
    events: Mutex<Vec<String>>,
    guards: AtomicUsize,
    calls: AtomicUsize,
    fail_input: bool,
    fail_method: Option<String>,
    fail_aggregate: bool,
    deny_method: Option<String>,
    expected_guards: usize,
    oversize: bool,
    sleep_ms: u64,
}
struct Guard(Arc<State>);
impl Drop for Guard {
    fn drop(&mut self) {
        self.0.guards.fetch_sub(1, Ordering::SeqCst);
    }
}
fn capacity(s: &Arc<State>, maximum: usize) -> RpcResponseCapacity {
    s.guards.fetch_add(1, Ordering::SeqCst);
    RpcResponseCapacity::new(maximum, Box::new(Guard(s.clone()))).unwrap()
}
struct Dispatcher(Arc<State>);
impl RpcDispatcher for Dispatcher {
    fn dispatch(&self, method: &str, _: Value) -> Result<Value, RpcError> {
        assert_eq!(self.0.guards.load(Ordering::SeqCst), self.0.expected_guards);
        self.0
            .events
            .lock()
            .unwrap()
            .push(format!("dispatch:{method}"));
        self.0.calls.fetch_add(1, Ordering::SeqCst);
        std::thread::sleep(std::time::Duration::from_millis(self.0.sleep_ms));
        Ok(if self.0.oversize {
            json!("x".repeat(4096))
        } else {
            json!({"method":method})
        })
    }
    fn preflight_current_read(&self, method: &str, _: &Value) -> Result<(), RpcError> {
        self.0
            .events
            .lock()
            .unwrap()
            .push(format!("preflight:{method}"));
        Ok(())
    }
    fn reserve_response_capacity_for(
        &self,
        method: &str,
    ) -> Result<Option<RpcResponseCapacity>, RpcError> {
        self.0
            .events
            .lock()
            .unwrap()
            .push(format!("method:{method}"));
        if self.0.fail_method.as_deref() == Some(method) {
            return Err(RpcError::unavailable("capacity refused"));
        }
        Ok(Some(capacity(&self.0, 512)))
    }
    fn reserve_current_read_input(&self, bytes: usize) -> Result<RpcResponseCapacity, RpcError> {
        self.0.events.lock().unwrap().push("input".into());
        if self.0.fail_input {
            return Err(RpcError::unavailable("input refused"));
        }
        Ok(capacity(&self.0, bytes.max(256)))
    }
    fn reserve_current_read_aggregate(
        &self,
        bytes: usize,
    ) -> Result<RpcResponseCapacity, RpcError> {
        self.0.events.lock().unwrap().push("aggregate".into());
        if self.0.fail_aggregate {
            return Err(RpcError::unavailable("aggregate refused"));
        }
        assert_eq!(self.0.calls.load(Ordering::SeqCst), 0);
        Ok(capacity(&self.0, bytes))
    }
}
struct Auth(Arc<State>);
impl RpcAuthenticator for Auth {
    fn authorize(&self, method: &str, _: Option<&str>) -> Result<(), RpcError> {
        self.0.events.lock().unwrap().push(format!("auth:{method}"));
        if self.0.deny_method.as_deref() == Some(method) {
            Err(RpcError::method_not_found())
        } else {
            Ok(())
        }
    }
}
fn network() -> R1NetworkCoordinate {
    let p = |name: &str| R1ProfileRef {
        name: name.into(),
        revision: 1,
    };
    R1NetworkCoordinate {
        network: R1NetworkRef {
            chain_id: u64::MAX - 1,
            nic: [0x11; 64],
        },
        genesis: R1GenesisReference {
            profile: p("SYNERGY-GENESIS-R1"),
            digest: [0x22; 48],
        },
        activated_profiles: R1ProfileSetReference {
            profile: p("APQE-PROFILE-SET"),
            commitment: [0x33; 64],
        },
    }
}
fn request(method: &str, id: Value) -> Value {
    json!({"jsonrpc":"2.0","id":id,"method":method,"params":{"api_version":1,
        "request_id":"public-synthetic-batch-only","caller_scope":"public_read","args":{},
        "network":{"chain_id":(u64::MAX-1).to_string(),
            "network_incarnation_commitment":{"algorithm":"SHA3-512","encoding":"lowercase-hex","value":"11".repeat(64)},
            "genesis_commitment":{"profile":{"name":"SYNERGY-GENESIS-R1","revision":1},"algorithm":"SHA3-384","encoding":"lowercase-hex","value":"22".repeat(48)},
            "activated_profiles":{"profile":{"name":"APQE-PROFILE-SET","revision":1},"algorithm":"SHA3-512","encoding":"lowercase-hex","value":"33".repeat(64)},
            "identity_profile":{"name":"APQE-NATIVE-ID","revision":1},"presentation_version":2}}})
}
fn pair() -> Value {
    json!([
        request("synergy_getBlockNumber", json!("second")),
        request("synergy_chainId", json!(7))
    ])
}
fn server(s: &Arc<State>, rate: u32, timeout: u64) -> RpcServer<Dispatcher, Auth> {
    RpcServer::new(
        Arc::new(Dispatcher(s.clone())),
        Arc::new(Auth(s.clone())),
        RpcLimits {
            max_body_bytes: 1_000_000,
            max_concurrent_requests: 8,
            request_timeout_ms: timeout,
        },
        RpcRateLimiter::new(
            RateLimit {
                requests: rate,
                window_ms: 1000,
            },
            4,
        )
        .unwrap(),
    )
    .unwrap()
}
fn execute(
    s: &Arc<State>,
    body: &Value,
    rate: u32,
    maximum: usize,
) -> Result<synergy_rpc::server::RpcOutput, RpcError> {
    server(s, rate, 2000).handle_current_read_document_reserved(
        "public-test",
        None,
        0,
        &serde_json::to_vec(body).unwrap(),
        &network(),
        maximum,
    )
}

#[test]
fn all_admission_and_reservations_precede_dispatch_and_guards_survive_byte_handoff() {
    let s = Arc::new(State {
        expected_guards: 4,
        ..Default::default()
    });
    let output = execute(&s, &pair(), 64, 2048).unwrap();
    assert_eq!(s.calls.load(Ordering::SeqCst), 2);
    let events = s.events.lock().unwrap().clone();
    assert_eq!(
        events,
        vec![
            "input",
            "auth:synergy_getBlockNumber",
            "auth:synergy_chainId",
            "preflight:synergy_getBlockNumber",
            "preflight:synergy_chainId",
            "method:synergy_getBlockNumber",
            "method:synergy_chainId",
            "aggregate",
            "dispatch:synergy_getBlockNumber",
            "dispatch:synergy_chainId"
        ]
    );
    let (bytes, guard) = output.into_parts();
    let v: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(v[0]["id"], "second");
    assert_eq!(v[1]["id"], 7);
    assert_eq!(guard.as_ref().unwrap().maximum_encoded_bytes(), 1027);
    assert_eq!(s.guards.load(Ordering::SeqCst), 4);
    drop(bytes);
    assert_eq!(s.guards.load(Ordering::SeqCst), 4);
    drop(guard);
    assert_eq!(s.guards.load(Ordering::SeqCst), 0);
}

#[test]
fn late_auth_rate_method_and_aggregate_refusal_never_start_any_handler() {
    for variant in 0..5 {
        let s = Arc::new(State {
            deny_method: (variant == 0).then(|| "synergy_chainId".into()),
            fail_method: (variant == 2).then(|| "synergy_chainId".into()),
            fail_aggregate: variant == 3,
            ..Default::default()
        });
        assert!(execute(
            &s,
            &pair(),
            if variant == 1 { 1 } else { 64 },
            if variant == 4 { 1024 } else { 2048 }
        )
        .is_err());
        assert_eq!(s.calls.load(Ordering::SeqCst), 0);
        assert_eq!(s.guards.load(Ordering::SeqCst), 0);
    }
}

#[test]
fn malformed_or_wrong_context_member_rejects_whole_preparation_before_auth_or_work() {
    for variant in 0..7 {
        let s = Arc::new(State::default());
        let mut body = pair();
        match variant {
            0 => body = json!([]),
            1 => body = Value::Array((0..33).map(|n| request("synergy_ping", json!(n))).collect()),
            2 => body[1]["id"] = body[0]["id"].clone(),
            3 => body[1]["method"] = json!("synergy_privateReset"),
            4 => body[1]["params"]["network"]["chain_id"] = json!("9969"),
            5 => body[1]["id"] = json!({"private":"PUBLIC_SENTINEL"}),
            _ => body[1]["params"]["private_key"] = json!("PUBLIC_SENTINEL"),
        }
        let error = execute(&s, &body, 64, 4096).err().unwrap();
        assert!(!error.message.contains("PUBLIC_SENTINEL"));
        assert_eq!(s.events.lock().unwrap().as_slice(), ["input"]);
        assert_eq!(s.calls.load(Ordering::SeqCst), 0);
        assert_eq!(s.guards.load(Ordering::SeqCst), 0);
    }
}

#[test]
fn oversize_member_is_a_complete_correlated_error_never_a_partial_success() {
    let s = Arc::new(State {
        expected_guards: 4,
        oversize: true,
        ..Default::default()
    });
    let out = execute(&s, &pair(), 64, 2048).unwrap();
    let (bytes, guard) = out.into_parts();
    let value: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(value.as_array().unwrap().len(), 2);
    for (i, id) in [json!("second"), json!(7)].into_iter().enumerate() {
        assert_eq!(value[i]["id"], id);
        assert_eq!(value[i]["error"]["code"], -32000);
        assert!(value[i].get("result").is_none());
    }
    assert!(bytes.len() <= 1027);
    drop(bytes);
    drop(guard);
    assert_eq!(s.guards.load(Ordering::SeqCst), 0);
}

#[test]
fn document_deadline_refuses_delivery_and_stops_later_handlers() {
    let s = Arc::new(State {
        expected_guards: 4,
        sleep_ms: 300,
        ..Default::default()
    });
    let result = server(&s, 64, 250).handle_current_read_document_reserved(
        "public-test",
        None,
        0,
        &serde_json::to_vec(&pair()).unwrap(),
        &network(),
        2048,
    );
    assert!(result.is_err());
    assert_eq!(s.calls.load(Ordering::SeqCst), 1);
    assert_eq!(s.guards.load(Ordering::SeqCst), 0);
}

#[test]
fn failed_input_reservation_precedes_owned_decode_and_each_registered_method_has_one_ceiling() {
    let s = Arc::new(State {
        fail_input: true,
        ..Default::default()
    });
    assert!(server(&s, 64, 2000)
        .handle_current_read_document_reserved("public-test", None, 0, b"{", &network(), 2048)
        .is_err());
    assert_eq!(s.events.lock().unwrap().as_slice(), ["input"]);
    assert_eq!(s.guards.load(Ordering::SeqCst), 0);
    for method in synergy_rpc::r1_read::METHODS {
        assert!(
            synergy_rpc::current_batch::response_ceiling(method).is_some(),
            "{method}"
        );
    }
    assert_eq!(
        synergy_rpc::current_batch::response_ceiling("eth_chainId"),
        None
    );
    assert_eq!(
        synergy_rpc::current_batch::response_ceiling("synergy_privateReset"),
        None
    );
}
