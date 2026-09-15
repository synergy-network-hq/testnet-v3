use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RateLimit {
    pub requests: u32,
    pub window_ms: u64,
}

#[derive(Debug, Clone, Copy)]
struct Bucket {
    start_ms: u64,
    used: u32,
}

#[derive(Debug)]
pub struct RpcRateLimiter {
    policy: RateLimit,
    max_clients: usize,
    buckets: BTreeMap<String, Bucket>,
}

impl RpcRateLimiter {
    pub fn new(policy: RateLimit, max_clients: usize) -> Result<Self, crate::RpcError> {
        if policy.requests == 0 || policy.window_ms == 0 || max_clients == 0 {
            return Err(crate::RpcError::invalid_request("invalid RPC rate limit"));
        }
        Ok(Self {
            policy,
            max_clients,
            buckets: BTreeMap::new(),
        })
    }

    pub fn admit(&mut self, client_id: &str, now_ms: u64) -> Result<(), crate::RpcError> {
        if client_id.trim().is_empty() {
            return Err(crate::RpcError::invalid_request("invalid RPC client ID"));
        }
        if !self.buckets.contains_key(client_id) && self.buckets.len() >= self.max_clients {
            self.buckets
                .retain(|_, bucket| now_ms.saturating_sub(bucket.start_ms) < self.policy.window_ms);
            if self.buckets.len() >= self.max_clients {
                return Err(crate::RpcError::unavailable("RPC client table is full"));
            }
        }
        let bucket = self.buckets.entry(client_id.to_owned()).or_insert(Bucket {
            start_ms: now_ms,
            used: 0,
        });
        if now_ms.saturating_sub(bucket.start_ms) >= self.policy.window_ms {
            *bucket = Bucket {
                start_ms: now_ms,
                used: 0,
            };
        }
        if bucket.used >= self.policy.requests {
            return Err(crate::RpcError {
                code: -32002,
                message: "RPC rate limit exceeded".into(),
            });
        }
        bucket.used = bucket.used.saturating_add(1);
        Ok(())
    }
}
