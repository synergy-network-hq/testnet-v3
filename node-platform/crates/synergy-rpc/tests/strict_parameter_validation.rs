use serde_json::{json, Value};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
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
fn server() -> (
    Arc<Dispatcher>,
    RpcServer<Dispatcher, PublicOnlyAuthenticator>,
) {
    let dispatcher = Arc::new(Dispatcher::default());
    let server = RpcServer::new(
        dispatcher.clone(),
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
    (dispatcher, server)
}

#[test]
fn duplicate_nested_coordinates_and_arguments_fail_before_authorization_or_dispatch() {
    let (dispatcher, server) = server();
    for params in [
        r#"{"network":{"chain_id":"9969","chain_id":"1266"}}"#,
        r#"{"network":{"genesis":{"value":"first","value":"SECRET_SENTINEL"}}}"#,
        r#"{"args":[{"amount":"1","amount":"2"}]}"#,
        r#"{"private_key":1,"private_\u006bey":2}"#,
    ] {
        let body = format!(
            r#"{{"jsonrpc":"2.0","id":7,"method":"synergy_chainStatus","params":{params}}}"#
        );
        let response: Value =
            serde_json::from_slice(&server.handle_bytes("client", None, 0, body.as_bytes()))
                .unwrap();
        assert_eq!(response["error"]["code"], -32600);
        assert!(!response.to_string().contains("SECRET_SENTINEL"));
    }
    assert_eq!(dispatcher.0.load(Ordering::SeqCst), 0);
}

#[test]
fn unambiguous_nested_json_preserves_exact_u64_strings_arrays_and_empty_params() {
    let (dispatcher, server) = server();
    for params in [
        json!({"integer":u64::MAX,"decimal":"18446744073709551615","values":[true,null,-1,1.5,"text",{}]}),
        json!([]),
        Value::Null,
    ] {
        let body = serde_json::to_vec(
            &json!({"jsonrpc":"2.0","id":7,"method":"synergy_chainStatus","params":params}),
        )
        .unwrap();
        let response: Value =
            serde_json::from_slice(&server.handle_bytes("client", None, 0, &body)).unwrap();
        assert_eq!(response["result"], params);
    }
    assert_eq!(dispatcher.0.load(Ordering::SeqCst), 3);
}
