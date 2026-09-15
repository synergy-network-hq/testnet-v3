//! Governed activation metadata for version changes.

use serde::{Deserialize, Serialize};

use crate::{ProtocolComponent, ProtocolVersion};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind", content = "value")]
pub enum ActivationPoint {
    Epoch(u64),
    FinalizedHeight(u64),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Activation {
    pub component: ProtocolComponent,
    pub from: ProtocolVersion,
    pub to: ProtocolVersion,
    pub point: ActivationPoint,
    pub governance_commitment: [u8; 32],
}

impl Activation {
    pub fn validate(&self) -> Result<(), ActivationError> {
        if self.to <= self.from {
            return Err(ActivationError::NonIncreasingVersion);
        }
        if self.governance_commitment.iter().all(|byte| *byte == 0) {
            return Err(ActivationError::MissingGovernanceCommitment);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActivationError {
    NonIncreasingVersion,
    MissingGovernanceCommitment,
}

impl std::fmt::Display for ActivationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NonIncreasingVersion => {
                formatter.write_str("activation must increase the component version")
            }
            Self::MissingGovernanceCommitment => {
                formatter.write_str("activation requires a governance commitment")
            }
        }
    }
}

impl std::error::Error for ActivationError {}
