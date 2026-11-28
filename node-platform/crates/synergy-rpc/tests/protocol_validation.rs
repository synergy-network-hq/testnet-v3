use std::sync::{atomic::{AtomicUsize, Ordering}, Arc};

use serde_json::{json, Value};
use synergy_rpc::{
    auth::PublicOnlyAuthenticator,
    middleware::RpcLimits,
    rate_limit::{RateLimit, RpcRateLimiter},
    server::RpcServer,
    RpcDispatcher, RpcError,
};

#[derive(Default)]
struct Dispatcher(AtomicUsize);

impl RpcDispatcher for Dispatcher {
    fn dispatch(&self, _: &str, params: Value) -> Result<Value, RpcError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(params)
    }
}

fn server() -> (Arc<Dispatcher>, RpcServer<Dispatcher, PublicOnlyAuthenticator>) {
    let dispatcher = Arc::new(Dispatcher::default());
    let server = RpcServer::new(
        dispatcher.clone(), Arc::new(PublicOnlyAuthenticator),
        RpcLimits { max_body_bytes: 4096, max_concurrent_requests: 2, request_timeout_ms: 1000 },
        RpcRateLimiter::new(RateLimit { requests: 32, window_ms: 1000 }, 4).unwrap(),
    ).unwrap();
    (dispatcher, server)
}

#[test]
fn syntax_and_request_shape_have_distinct_standard_errors_without_dispatch() {
    let (dispatcher, server) = server();
    for (body, code) in [
        (b"{\"private_payload\":".as_slice(), -32700),
        (b"{broken}".as_slice(), -32700),
        (b"[]".as_slice(), -32600),
        (b"{\"jsonrpc\":\"2.0\",\"id\":7}".as_slice(), -32600),
    ] {
        let response: Value = serde_json::from_slice(&server.handle_bytes("client", None, 0, body)).unwrap();
        assert_eq!(response["error"]["code"], code);
        assert_eq!(response["id"], Value::Null);
        assert!(!response.to_string().contains("private_payload"));
    }
    assert_eq!(dispatcher.0.load(Ordering::SeqCst), 0);
}

#[test]
fn invalid_identifiers_and_scalar_params_cannot_reach_a_handler() {
    let (dispatcher, server) = server();
    for id in [json!({"hidden": "value"}), json!([1]), json!(true)] {
        let body = serde_json::to_vec(&json!({"jsonrpc":"2.0","id":id,"method":"synergy_chainStatus","params":{}})).unwrap();
        let response: Value = serde_json::from_slice(&server.handle_bytes("client", None, 0, &body)).unwrap();
        assert_eq!(response["error"]["code"], -32600);
        assert_eq!(response["id"], Value::Null);
    }
    for params in [json!(42), json!(false), json!("sensitive")] {
        let body = serde_json::to_vec(&json!({"jsonrpc":"2.0","id":"request","method":"synergy_chainStatus","params":params})).unwrap();
        let response: Value = serde_json::from_slice(&server.handle_bytes("client", None, 0, &body)).unwrap();
        assert_eq!(response["error"]["code"], -32602);
        assert_eq!(response["id"], "request");
    }
    assert_eq!(dispatcher.0.load(Ordering::SeqCst), 0);
}

#[test]
fn valid_calls_and_private_method_separation_are_preserved() {
    let (dispatcher, server) = server();
    for params in [json!({}), json!([])] {
        let body = serde_json::to_vec(&json!({"jsonrpc":"2.0","id":7,"method":"synergy_chainStatus","params":params})).unwrap();
        let response: Value = serde_json::from_slice(&server.handle_bytes("client", None, 0, &body)).unwrap();
        assert_eq!(response["result"], params);
        assert!(response.get("error").is_none());
    }
    let body = serde_json::to_vec(&json!({"jsonrpc":"2.0","id":8,"method":"synergy_privateReset","params":{}})).unwrap();
    let response: Value = serde_json::from_slice(&server.handle_bytes("client", None, 0, &body)).unwrap();
    assert_eq!(response["error"]["code"], -32001);
    assert_eq!(dispatcher.0.load(Ordering::SeqCst), 2);
}

