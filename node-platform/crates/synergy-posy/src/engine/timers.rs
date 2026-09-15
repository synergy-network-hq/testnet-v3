use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub struct ConsensusTimer {
    deadline: Instant,
}

impl ConsensusTimer {
    pub fn start(timeout: Duration) -> Self {
        Self {
            deadline: Instant::now() + timeout,
        }
    }

    pub fn expired(&self) -> bool {
        Instant::now() >= self.deadline
    }
}
