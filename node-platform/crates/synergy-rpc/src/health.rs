#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RpcHealth {
    pub accepting_requests: bool,
    pub active_requests: usize,
    pub capacity: usize,
    pub detail: String,
}

impl RpcHealth {
    pub fn is_ready(&self) -> bool {
        self.accepting_requests && self.capacity > 0 && self.active_requests < self.capacity
    }
}
