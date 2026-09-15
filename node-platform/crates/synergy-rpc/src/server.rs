use std::sync::{Arc, Mutex};

use crate::{
    auth::RpcAuthenticator,
    middleware::{RpcLimits, RpcMetrics},
    rate_limit::RpcRateLimiter,
    RpcDispatcher, RpcError, RpcRequest, RpcResponse,
};

pub struct RpcServer<D, A> {
    dispatcher: Arc<D>,
    authenticator: Arc<A>,
    limits: RpcLimits,
    rate_limiter: Mutex<RpcRateLimiter>,
    metrics: Mutex<RpcMetrics>,
}

impl<D: RpcDispatcher, A: RpcAuthenticator> RpcServer<D, A> {
    pub fn new(
        dispatcher: Arc<D>,
        authenticator: Arc<A>,
        limits: RpcLimits,
        rate_limiter: RpcRateLimiter,
    ) -> Result<Self, RpcError> {
        Ok(Self {
            dispatcher,
            authenticator,
            limits: limits.validate()?,
            rate_limiter: Mutex::new(rate_limiter),
            metrics: Mutex::new(RpcMetrics::default()),
        })
    }

    pub fn handle_bytes(
        &self,
        client_id: &str,
        credential: Option<&str>,
        now_ms: u64,
        body: &[u8],
    ) -> Vec<u8> {
        if body.len() > self.limits.max_body_bytes {
            return encode_failure(
                serde_json::Value::Null,
                RpcError::invalid_request("RPC body exceeds limit"),
            );
        }
        let request = match serde_json::from_slice::<RpcRequest>(body) {
            Ok(request) => request,
            Err(error) => {
                return encode_failure(
                    serde_json::Value::Null,
                    RpcError::invalid_request(format!("invalid JSON: {error}")),
                )
            }
        };
        let id = request.id.clone();
        if let Err(error) = request.validate() {
            return encode_failure(id, error);
        }
        if let Err(error) = self.authenticator.authorize(&request.method, credential) {
            return encode_failure(id, error);
        }
        let admitted = self
            .rate_limiter
            .lock()
            .map_err(|_| RpcError::unavailable("RPC rate limiter lock poisoned"))
            .and_then(|mut limiter| limiter.admit(client_id, now_ms));
        if let Err(error) = admitted {
            return encode_failure(id, error);
        }
        let started = self.metrics.lock().map(|mut metrics| {
            if metrics.active_requests >= self.limits.max_concurrent_requests {
                metrics.reject();
                false
            } else {
                metrics.record_request(&request.method);
                true
            }
        });
        if !matches!(started, Ok(true)) {
            return encode_failure(id, RpcError::unavailable("RPC concurrency limit reached"));
        }
        let result = self.dispatcher.dispatch(&request.method, request.params);
        if let Ok(mut metrics) = self.metrics.lock() {
            metrics.finish(result.is_err());
        }
        match result {
            Ok(value) => encode_response(RpcResponse::success(id, value)),
            Err(error) => encode_failure(id, error),
        }
    }

    pub fn metrics(&self) -> Result<RpcMetrics, RpcError> {
        self.metrics
            .lock()
            .map(|metrics| metrics.clone())
            .map_err(|_| RpcError::unavailable("RPC metrics lock poisoned"))
    }
}

fn encode_failure(id: serde_json::Value, error: RpcError) -> Vec<u8> {
    encode_response(RpcResponse::failure(id, error))
}

fn encode_response(response: RpcResponse) -> Vec<u8> {
    match serde_json::to_vec(&response) {
        Ok(bytes) => bytes,
        Err(_) => b"{\"jsonrpc\":\"2.0\",\"id\":null,\"error\":{\"code\":-32000,\"message\":\"response serialization failed\"}}".to_vec(),
    }
}
