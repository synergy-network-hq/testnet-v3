#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestId(String);

impl RequestId {
    pub fn new(value: impl Into<String>) -> Result<Self, crate::RpcError> {
        let value = value.into();
        if value.trim().is_empty() || value.len() > 128 {
            return Err(crate::RpcError::invalid_request("invalid request ID"));
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}
