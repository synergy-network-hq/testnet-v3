#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AivmMetrics {
    pub executions: u64,
    pub failures: u64,
    pub fuel: u64,
}
impl AivmMetrics {
    pub fn record(&mut self, result: Result<u64, ()>) {
        match result {
            Ok(f) => {
                self.executions = self.executions.saturating_add(1);
                self.fuel = self.fuel.saturating_add(f)
            }
            Err(()) => self.failures = self.failures.saturating_add(1),
        }
    }
}
