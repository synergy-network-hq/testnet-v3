use serde_json::{json, Value};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use synergy_rpc::{
    auth::PublicOnlyAuthenticator,
    middleware::RpcLimits,
    provider::RpcResponseCapacity,
    rate_limit::{RateLimit, RpcRateLimiter},
    server::RpcServer,
    RpcDispatcher, RpcError,
};

struct Guard(Arc<AtomicUsize>);
impl Drop for Guard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}
struct Dispatcher {
    live: Arc<AtomicUsize>,
    calls: Arc<AtomicUsize>,
    maximum: usize,
    deny: bool,
}
impl RpcDispatcher for Dispatcher {
    fn reserve_response_capacity(&self) -> Result<Option<RpcResponseCapacity>, RpcError> {
        if self.deny {
            return Err(RpcError::unavailable("fixture capacity exhausted"));
        }
        self.live.fetch_add(1, Ordering::SeqCst);
        RpcResponseCapacity::new(self.maximum, Box::new(Guard(self.live.clone()))).map(Some)
    }
    fn dispatch(&self, _: &str, params: Value) -> Result<Value, RpcError> {
        assert_eq!(
            self.live.load(Ordering::SeqCst),
            1,
            "response reserve must precede handler allocations"
        );
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(params)
    }
}
fn server(
    maximum: usize,
    deny: bool,
) -> (
    Arc<AtomicUsize>,
    Arc<AtomicUsize>,
    RpcServer<Dispatcher, PublicOnlyAuthenticator>,
) {
    let live = Arc::new(AtomicUsize::new(0));
    let calls = Arc::new(AtomicUsize::new(0));
    let server = RpcServer::new(
        Arc::new(Dispatcher {
            live: live.clone(),
            calls: calls.clone(),
            maximum,
            deny,
        }),
        Arc::new(PublicOnlyAuthenticator),
        RpcLimits {
            max_body_bytes: 4096,
            max_concurrent_requests: 2,
            request_timeout_ms: 1000,
        },
        RpcRateLimiter::new(
            RateLimit {
                requests: 32,
                window_ms: 1000,
            },
            4,
        )
        .unwrap(),
    )
    .unwrap();
    (live, calls, server)
}
fn request(method: &str, params: Value) -> Vec<u8> {
    serde_json::to_vec(&json!({"jsonrpc":"2.0","id":7,"method":method,"params":params})).unwrap()
}

#[test]
fn reservation_survives_serialization_and_byte_handoff_until_transport_releases_it() {
    let (live, calls, server) = server(2048, false);
    let output = server.handle_bytes_reserved(
        "fixture",
        None,
        0,
        &request("synergy_chainStatus", json!({"public":"x".repeat(512)})),
    );
    assert_eq!(live.load(Ordering::SeqCst), 1);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    let (bytes, guard) = output.into_parts();
    assert!(guard.is_some());
    let decoded: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(decoded["result"]["public"].as_str().unwrap().len(), 512);
    drop(bytes);
    assert_eq!(live.load(Ordering::SeqCst), 1);
    drop(guard);
    assert_eq!(live.load(Ordering::SeqCst), 0);
}

#[test]
fn oversize_encoded_result_becomes_bounded_error_with_guard_retained() {
    let (live, calls, server) = server(256, false);
    let (bytes, guard) = server
        .handle_bytes_reserved(
            "fixture",
            None,
            0,
            &request("synergy_chainStatus", json!({"public":"x".repeat(1024)})),
        )
        .into_parts();
    assert!(bytes.len() <= 256);
    let decoded: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(decoded["error"]["code"], -32000);
    assert!(decoded.get("result").is_none());
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(live.load(Ordering::SeqCst), 1);
    drop(guard);
    assert_eq!(live.load(Ordering::SeqCst), 0);
}

#[test]
fn capacity_failure_and_private_methods_never_start_handler_work() {
    let (live, calls, server) = server(1024, true);
    for (method, expected) in [
        ("synergy_chainStatus", -32000),
        ("synergy_privateReset", -32001),
    ] {
        let (bytes, guard) = server
            .handle_bytes_reserved("fixture", None, 0, &request(method, json!({})))
            .into_parts();
        assert!(guard.is_none());
        let decoded: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(decoded["error"]["code"], expected);
    }
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert_eq!(live.load(Ordering::SeqCst), 0);
}
