use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SandboxPolicy {
    pub allow_network: bool,
    pub allow_clock: bool,
    pub allow_randomness: bool,
    pub readable_mount_roots: BTreeSet<String>,
    pub writable_mount_roots: BTreeSet<String>,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SandboxViolation {
    Network,
    Clock,
    Randomness,
    Filesystem,
}
impl SandboxPolicy {
    pub fn deterministic() -> Self {
        Self {
            allow_network: false,
            allow_clock: false,
            allow_randomness: false,
            readable_mount_roots: BTreeSet::new(),
            writable_mount_roots: BTreeSet::new(),
        }
    }
    pub fn validate(&self) -> Result<(), SandboxViolation> {
        if self.allow_network {
            return Err(SandboxViolation::Network);
        }
        if self.allow_clock {
            return Err(SandboxViolation::Clock);
        }
        if self.allow_randomness {
            return Err(SandboxViolation::Randomness);
        }
        if !self.writable_mount_roots.is_empty() {
            return Err(SandboxViolation::Filesystem);
        }
        Ok(())
    }
}
