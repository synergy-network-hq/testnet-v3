use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// Consensus participation requested from the runtime.
///
/// `ValidateAndVote` only enables the component. Validator authority still
/// comes from a separately verified network authority binding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConsensusMode {
    Disabled,
    Observe,
    ValidateAndVote,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsensusConfiguration {
    pub mode: ConsensusMode,
    pub authority_binding: Option<PathBuf>,
    /// Pinned public ML-DSA-65 trust root that authenticates authority bindings.
    pub authority_trust_key_path: Option<PathBuf>,
    /// Provisioned ML-DSA-65 consensus key; voting still requires frozen authority.
    #[serde(default)]
    pub signing_key_path: Option<PathBuf>,
    pub proposal_timeout_ms: u64,
    pub round_timeout_ms: u64,
    pub max_rounds_behind: u32,
}

impl Default for ConsensusConfiguration {
    fn default() -> Self {
        Self {
            mode: ConsensusMode::Disabled,
            authority_binding: None,
            authority_trust_key_path: None,
            signing_key_path: None,
            proposal_timeout_ms: 2_000,
            round_timeout_ms: 5_000,
            max_rounds_behind: 64,
        }
    }
}
