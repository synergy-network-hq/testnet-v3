use std::collections::BTreeMap;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RpcMetrics {
    pub active_requests: usize,
    pub total_requests: u64,
    pub rejected_requests: u64,
    pub failed_requests: u64,
    pub by_method: BTreeMap<String, u64>,
}

impl RpcMetrics {
    pub fn record_request(&mut self, method: &str) {
        self.total_requests = self.total_requests.saturating_add(1);
        self.active_requests = self.active_requests.saturating_add(1);
        let counter = self.by_method.entry(method.to_owned()).or_default();
        *counter = counter.saturating_add(1);
    }

    pub fn finish(&mut self, failed: bool) {
        self.active_requests = self.active_requests.saturating_sub(1);
        if failed {
            self.failed_requests = self.failed_requests.saturating_add(1);
        }
    }

    pub fn reject(&mut self) {
        self.rejected_requests = self.rejected_requests.saturating_add(1);
    }
}
