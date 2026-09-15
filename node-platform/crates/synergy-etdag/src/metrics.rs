use serde::{Deserialize, Serialize};

use crate::EtdagError;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EtdagMetricsSnapshot {
    pub admitted_envelopes: u64,
    pub rejected_envelopes: u64,
    pub dag_vertices: u64,
    pub availability_certificates: u64,
    pub pending_reveal_shares: u64,
    pub completed_reveals: u64,
    pub execution_handoffs: u64,
    pub recovery_requests: u64,
}

#[derive(Debug, Default)]
pub struct EtdagMetrics {
    snapshot: EtdagMetricsSnapshot,
}

impl EtdagMetrics {
    pub fn snapshot(&self) -> EtdagMetricsSnapshot {
        self.snapshot.clone()
    }

    pub fn set_dag_vertices(&mut self, count: usize) -> Result<(), EtdagError> {
        self.snapshot.dag_vertices =
            u64::try_from(count).map_err(|_| EtdagError::InvalidCapacity)?;
        Ok(())
    }

    pub fn set_pending_reveal_shares(&mut self, count: usize) -> Result<(), EtdagError> {
        self.snapshot.pending_reveal_shares =
            u64::try_from(count).map_err(|_| EtdagError::InvalidCapacity)?;
        Ok(())
    }

    pub fn record_admission(&mut self, accepted: bool) -> Result<(), EtdagError> {
        if accepted {
            increment(&mut self.snapshot.admitted_envelopes)
        } else {
            increment(&mut self.snapshot.rejected_envelopes)
        }
    }

    pub fn record_availability_certificate(&mut self) -> Result<(), EtdagError> {
        increment(&mut self.snapshot.availability_certificates)
    }

    pub fn record_completed_reveal(&mut self) -> Result<(), EtdagError> {
        increment(&mut self.snapshot.completed_reveals)
    }

    pub fn record_execution_handoff(&mut self) -> Result<(), EtdagError> {
        increment(&mut self.snapshot.execution_handoffs)
    }

    pub fn record_recovery_request(&mut self) -> Result<(), EtdagError> {
        increment(&mut self.snapshot.recovery_requests)
    }
}

fn increment(counter: &mut u64) -> Result<(), EtdagError> {
    *counter = counter.checked_add(1).ok_or(EtdagError::InvalidCapacity)?;
    Ok(())
}
