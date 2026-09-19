use crate::{AutomaticUpdatePolicy, VerifiedRelease};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PreflightObservation {
    pub free_bytes: u64,
    pub node_ready: bool,
    pub custody_available: bool,
    pub conflicting_update: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PreflightGate;

impl PreflightGate {
    pub fn check(
        &self,
        policy: &AutomaticUpdatePolicy,
        release: &VerifiedRelease,
        observation: PreflightObservation,
    ) -> Result<(), &'static str> {
        let required = policy
            .minimum_free_bytes
            .saturating_add(release.signed.release.artifact.length.saturating_mul(2));
        if observation.free_bytes < required {
            return Err("insufficient free space for atomic update and rollback");
        }
        if !observation.node_ready || !observation.custody_available {
            return Err("node readiness or key custody preflight failed");
        }
        if observation.conflicting_update {
            return Err("another update is active");
        }
        Ok(())
    }
}
