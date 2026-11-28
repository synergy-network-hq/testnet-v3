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

/// Serialized bytes and their resource lifetime. Transport owners move both
/// parts together and release the guard only after write/cancellation/drop.
pub struct RpcOutput {
    bytes: Vec<u8>,
    capacity: Option<crate::provider::RpcResponseCapacity>,
}
impl From<Vec<u8>> for RpcOutput {
    fn from(bytes: Vec<u8>) -> Self {
        Self {
            bytes,
            capacity: None,
        }
    }
}
impl RpcOutput {
    pub fn into_parts(self) -> (Vec<u8>, Option<crate::provider::RpcResponseCapacity>) {
        (self.bytes, self.capacity)
    }
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
        self.handle_bytes_reserved(client_id, credential, now_ms, body)
            .bytes
    }

    /// Use this entry point when retaining bytes for asynchronous I/O.
    pub fn handle_bytes_reserved(
        &self,
        client_id: &str,
        credential: Option<&str>,
        now_ms: u64,
        body: &[u8],
    ) -> RpcOutput {
        if body.len() > self.limits.max_body_bytes {
            return encode_failure(
                serde_json::Value::Null,
                RpcError::invalid_request("RPC body exceeds limit"),
            )
            .into();
        }
        let request = match serde_json::from_slice::<RpcRequest>(body) {
            Ok(request) => request,
            Err(error) => {
                let failure = match error.classify() {
                    serde_json::error::Category::Syntax | serde_json::error::Category::Eof => {
                        RpcError::parse_error()
                    }
                    _ => RpcError::invalid_request("invalid JSON-RPC request"),
                };
                return encode_failure(serde_json::Value::Null, failure).into();
            }
        };
        let id = request.id.clone();
        if body.iter().find(|b| !b.is_ascii_whitespace()) != Some(&b'{') {
            return encode_failure(
                serde_json::Value::Null,
                RpcError::invalid_request("JSON-RPC request must be an object"),
            )
            .into();
        }
        if let Err(error) = request.validate() {
            let response_id = if id.is_string() || id.is_number() || id.is_null() {
                id
            } else {
                serde_json::Value::Null
            };
            return encode_failure(response_id, error).into();
        }
        if let Err(error) = self.authenticator.authorize(&request.method, credential) {
            return encode_failure(id, error).into();
        }
        let admitted = self
            .rate_limiter
            .lock()
            .map_err(|_| RpcError::unavailable("RPC rate limiter lock poisoned"))
            .and_then(|mut limiter| limiter.admit(client_id, now_ms));
        if let Err(error) = admitted {
            return encode_failure(id, error).into();
        }
        let capacity = match self
            .dispatcher
            .reserve_response_capacity_for(&request.method)
        {
            Ok(capacity) => capacity,
            Err(error) => return encode_failure(id, error).into(),
        };
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
            return encode_failure(id, RpcError::unavailable("RPC concurrency limit reached"))
                .into();
        }
        let result = self.dispatcher.dispatch(&request.method, request.params);
        if let Ok(mut metrics) = self.metrics.lock() {
            metrics.finish(result.is_err());
        }
        let capacity_error_id = id.clone();
        let bytes = match result {
            Ok(value) => encode_response(RpcResponse::success(id, value)),
            Err(error) => encode_failure(id, error),
        };
        let bytes = if capacity
            .as_ref()
            .is_some_and(|cap| bytes.len() > cap.maximum_encoded_bytes())
        {
            encode_failure(
                capacity_error_id,
                RpcError::unavailable("RPC response exceeds selected capacity"),
            )
        } else {
            bytes
        };
        RpcOutput { bytes, capacity }
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
