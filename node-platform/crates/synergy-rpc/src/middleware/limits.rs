#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RpcLimits {
    pub max_body_bytes: usize,
    pub max_concurrent_requests: usize,
    pub request_timeout_ms: u64,
}

impl RpcLimits {
    pub fn validate(self) -> Result<Self, crate::RpcError> {
        if self.max_body_bytes == 0
            || self.max_body_bytes > 16 * 1024 * 1024
            || self.max_concurrent_requests == 0
            || self.request_timeout_ms == 0
        {
            return Err(crate::RpcError::invalid_request("invalid RPC limits"));
        }
        Ok(self)
    }
}
