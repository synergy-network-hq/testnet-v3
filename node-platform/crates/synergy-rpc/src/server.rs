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

struct CurrentReadGuards {
    _input: crate::provider::RpcResponseCapacity,
    _aggregate: crate::provider::RpcResponseCapacity,
    _methods: Vec<crate::provider::RpcResponseCapacity>,
}
// Field order also protects refusal/cancellation: free pending request values
// and accumulated bytes before releasing their retained allocation guards.
struct CurrentReadAccumulation {
    pending: std::vec::IntoIter<(RpcRequest, crate::provider::RpcResponseCapacity)>,
    bytes: Vec<u8>,
    guards: CurrentReadGuards,
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
        self.execute_reserved(request, capacity)
    }

    /// Current native read document execution. This does not install a route or
    /// authenticate `expected`; the native caller supplies its verified context.
    /// All calls are validated/authorized/rate-admitted and all output/scratch
    /// capacity is held BEFORE the first handler. No retry or partial truncation.
    pub fn handle_current_read_document_reserved(
        &self,
        client_id: &str,
        credential: Option<&str>,
        now_ms: u64,
        body: &[u8],
        expected: &synergy_protocol_types::R1NetworkCoordinate,
        maximum_aggregate_bytes: usize,
    ) -> Result<RpcOutput, RpcError> {
        let deadline = std::time::Instant::now()
            .checked_add(std::time::Duration::from_millis(
                self.limits.request_timeout_ms,
            ))
            .ok_or_else(|| RpcError::unavailable("current read deadline unavailable"))?;
        if body.len()
            > self
                .limits
                .max_body_bytes
                .min(crate::current_batch::MAX_DOCUMENT_BYTES)
            || !(512..=synergy_protocol_types::r1_rpc_response::MAX_TOTAL_BYTES)
                .contains(&maximum_aggregate_bytes)
        {
            return Err(RpcError::unavailable(
                "current read document exceeds native capacity",
            ));
        }
        // The request's owned JSON/strict-parse scratch is prepaid before decode.
        let input = self.dispatcher.reserve_current_read_input(body.len())?;
        let (requests, batch) = crate::current_batch::requests(body, expected)?;
        for request in &requests {
            self.authenticator.authorize(&request.method, credential)?;
        }
        for request in &requests {
            self.dispatcher
                .preflight_current_read(&request.method, &request.params)?;
        }
        {
            let mut limiter = self
                .rate_limiter
                .lock()
                .map_err(|_| RpcError::unavailable("RPC rate limiter lock poisoned"))?;
            for _ in &requests {
                limiter.admit(client_id, now_ms)?;
            }
        }
        let mut prepared = Vec::with_capacity(requests.len());
        let mut maximum = if batch { requests.len() + 1 } else { 0 };
        for request in requests {
            let capacity = self
                .dispatcher
                .reserve_response_capacity_for(&request.method)?
                .ok_or_else(|| {
                    RpcError::unavailable("current read requires native method capacity")
                })?;
            if capacity.maximum_encoded_bytes() < 512 {
                return Err(RpcError::unavailable(
                    "current read method capacity cannot hold bounded errors",
                ));
            }
            maximum = maximum
                .checked_add(capacity.maximum_encoded_bytes())
                .ok_or_else(|| RpcError::unavailable("current read aggregate capacity overflow"))?;
            if maximum > maximum_aggregate_bytes {
                return Err(RpcError::unavailable(
                    "current read aggregate exceeds selected capacity",
                ));
            }
            prepared.push((request, capacity));
        }
        let aggregate = self.dispatcher.reserve_current_read_aggregate(maximum)?;
        if aggregate.maximum_encoded_bytes() < maximum {
            return Err(RpcError::unavailable(
                "current read aggregate reservation is insufficient",
            ));
        }
        let mut accumulation = CurrentReadAccumulation {
            pending: prepared.into_iter(),
            bytes: Vec::new(),
            guards: CurrentReadGuards {
                _input: input,
                _aggregate: aggregate,
                _methods: Vec::with_capacity(crate::current_batch::MAX_BATCH_CALLS),
            },
        };
        accumulation
            .bytes
            .try_reserve_exact(maximum)
            .map_err(|_| RpcError::unavailable("current read aggregate allocation unavailable"))?;
        if batch {
            accumulation.bytes.push(b'[');
        }
        let mut index = 0;
        while let Some((request, capacity)) = accumulation.pending.next() {
            if std::time::Instant::now() >= deadline {
                return Err(RpcError::unavailable(
                    "current read document deadline exceeded",
                ));
            }
            let output = self.execute_reserved(request, Some(capacity));
            if std::time::Instant::now() >= deadline {
                return Err(RpcError::unavailable(
                    "current read document deadline exceeded",
                ));
            }
            if batch && index != 0 {
                accumulation.bytes.push(b',');
            }
            if accumulation
                .bytes
                .len()
                .checked_add(output.bytes.len())
                .and_then(|n| n.checked_add(usize::from(batch)))
                .is_none_or(|n| n > maximum)
            {
                return Err(RpcError::unavailable(
                    "current read encoded result exceeds reservation",
                ));
            }
            accumulation.bytes.extend_from_slice(&output.bytes);
            accumulation.guards._methods.push(
                output
                    .capacity
                    .expect("prepared method capacity is retained by execution"),
            );
            index += 1;
        }
        if batch {
            accumulation.bytes.push(b']');
        }
        let capacity =
            crate::provider::RpcResponseCapacity::new(maximum, Box::new(accumulation.guards))
                .expect("nonempty prepared methods each reserve at least512 encoded bytes");
        Ok(RpcOutput {
            bytes: accumulation.bytes,
            capacity: Some(capacity),
        })
    }

    fn execute_reserved(
        &self,
        request: RpcRequest,
        capacity: Option<crate::provider::RpcResponseCapacity>,
    ) -> RpcOutput {
        let id = request.id.clone();
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
            return RpcOutput {
                bytes: encode_failure(id, RpcError::unavailable("RPC concurrency limit reached")),
                capacity,
            };
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
