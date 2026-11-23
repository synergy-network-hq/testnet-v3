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

/// Pinned one-time protocol activation. This is independent of routine
/// successor proofs and cannot replace the selected Genesis or signed origin.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AutonomousEpochActivation {
    pub path: PathBuf,
    pub sha256: String,
}

/// Independently pinned native inputs shipped by the managed release owner.
/// The attachments reside with the signed Genesis or in the sealed software package.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedWalletDispatchReleaseConfiguration {
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub from_sealed_package: bool,
    pub attachment_sha256: String,
    pub issuer_key_id: String,
    pub issuer_sha256: String,
    pub release_verifier_artifact_sha256: String,
    pub managed_release_manifest_sha256: String,
    pub off_chain_approval_sha256: String,
    pub release_attestation_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsensusConfiguration {
    pub mode: ConsensusMode,
    pub authority_binding: Option<PathBuf>,
    /// Pinned public ML-DSA-65 trust root that authenticates authority bindings.
    pub authority_trust_key_path: Option<PathBuf>,
    /// Explicit quorum-authorized recovery certificate; never replaces the Genesis trust pin.
    #[serde(default)]
    pub authority_recovery_certificate_path: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub autonomous_epoch_activation: Option<AutonomousEpochActivation>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub managed_wallet_dispatch_release: Option<ManagedWalletDispatchReleaseConfiguration>,
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
            authority_recovery_certificate_path: None,
            autonomous_epoch_activation: None,
            managed_wallet_dispatch_release: None,
            signing_key_path: None,
            proposal_timeout_ms: 2_000,
            round_timeout_ms: 5_000,
            max_rounds_behind: 64,
        }
    }
}
