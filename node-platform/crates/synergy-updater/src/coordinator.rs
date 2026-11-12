use std::{fmt, path::PathBuf};

use synergy_aegis::{AegisVerifier, KeyId};
use synergy_version::ReleaseVersion;

use crate::{
    discover_release, stage_artifact, verify_release, ActivationDecision, ActivationGate,
    AuditEvent, AuditOutcome, AuditSink, AutomaticUpdatePolicy, CompatibilityGate,
    DrainCoordinator, HealthGate, HealthObservation, InstallCoordinator, InstallReceipt,
    PreflightGate, PreflightObservation, ReleaseCatalog, ReleaseMetadata, RollbackCoordinator,
    RuntimeVersions, StagedArtifact, StagingError, UpdateMode, UpdatePhase, VerificationError,
};

pub trait ArtifactSource: Send + Sync {
    fn fetch(&self, metadata: &ReleaseMetadata) -> Result<Vec<u8>, String>;
}

pub trait UpdateRuntime: Send + Sync {
    fn versions(&self) -> Result<RuntimeVersions, String>;
    fn preflight(&self) -> Result<PreflightObservation, String>;
    fn health_after_install(&self) -> Result<HealthObservation, String>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdateRequest {
    pub chain_id: u64,
    pub installed_sequence: u64,
    pub installed_release: ReleaseVersion,
    pub governed_signer_key_id: KeyId,
    pub governed_public_key: Vec<u8>,
    pub governed_activation_commitment: Option<String>,
    pub staging_root: PathBuf,
    pub timestamp_unix_seconds: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpdateOutcome {
    Current,
    Notified {
        release_id: String,
        activation: ActivationDecision,
    },
    Staged {
        artifact: StagedArtifact,
        activation: ActivationDecision,
    },
    Installed {
        install: InstallReceipt,
        activation: ActivationDecision,
    },
}

pub struct UpdateCoordinator<'a> {
    pub verifier: &'a dyn AegisVerifier,
    pub catalog: &'a dyn ReleaseCatalog,
    pub artifacts: &'a dyn ArtifactSource,
    pub runtime: &'a dyn UpdateRuntime,
    pub drain: &'a dyn DrainCoordinator,
    pub install: &'a dyn InstallCoordinator,
    pub rollback: &'a dyn RollbackCoordinator,
    pub audit: &'a dyn AuditSink,
}

impl UpdateCoordinator<'_> {
    pub fn run(
        &self,
        policy: &AutomaticUpdatePolicy,
        request: &UpdateRequest,
    ) -> Result<UpdateOutcome, UpdateError> {
        policy.validate().map_err(UpdateError::Policy)?;
        let Some(discovery) = discover_release(self.catalog, policy, request.installed_sequence)
            .map_err(UpdateError::Discovery)?
        else {
            return Ok(UpdateOutcome::Current);
        };
        self.audit(
            &discovery.candidate.release.release_id,
            discovery.candidate.release.sequence,
            UpdatePhase::Discovered,
            request.timestamp_unix_seconds,
        )?;
        let artifact = self
            .artifacts
            .fetch(&discovery.candidate.release)
            .map_err(UpdateError::Artifact)?;
        if artifact.len() as u64 > policy.maximum_artifact_bytes {
            return Err(UpdateError::Artifact(
                "release artifact exceeds automatic-update policy".into(),
            ));
        }
        let verified = verify_release(
            self.verifier,
            request.chain_id,
            request.installed_sequence,
            &request.governed_signer_key_id,
            &request.governed_public_key,
            discovery.candidate,
            &artifact,
        )
        .map_err(UpdateError::Verification)?;
        self.audit(
            &verified.signed.release.release_id,
            verified.signed.release.sequence,
            UpdatePhase::Verified,
            request.timestamp_unix_seconds,
        )?;
        let versions = self.runtime.versions().map_err(UpdateError::Runtime)?;
        CompatibilityGate
            .check(&verified, &versions)
            .map_err(UpdateError::Compatibility)?;
        let preflight = self.runtime.preflight().map_err(UpdateError::Runtime)?;
        PreflightGate
            .check(policy, &verified, preflight)
            .map_err(UpdateError::Preflight)?;
        let activation = ActivationGate
            .evaluate(
                &verified,
                request.installed_release,
                request.governed_activation_commitment.as_deref(),
            )
            .map_err(UpdateError::Activation)?;
        if policy.mode == UpdateMode::NotifyOnly {
            return Ok(UpdateOutcome::Notified {
                release_id: verified.signed.release.release_id,
                activation,
            });
        }
        let staged = stage_artifact(&request.staging_root, &verified, &artifact)
            .map_err(UpdateError::Staging)?;
        self.audit(
            &staged.release_id,
            verified.signed.release.sequence,
            UpdatePhase::Staged,
            request.timestamp_unix_seconds,
        )?;
        if policy.mode == UpdateMode::StageOnly {
            return Ok(UpdateOutcome::Staged {
                artifact: staged,
                activation,
            });
        }
        self.drain.drain().map_err(UpdateError::Drain)?;
        self.audit(
            &staged.release_id,
            verified.signed.release.sequence,
            UpdatePhase::Drained,
            request.timestamp_unix_seconds,
        )?;
        let install = self
            .install
            .install(&staged)
            .map_err(UpdateError::Install)?;
        self.audit(
            &staged.release_id,
            verified.signed.release.sequence,
            UpdatePhase::Installed,
            request.timestamp_unix_seconds,
        )?;
        let health = self
            .runtime
            .health_after_install()
            .map_err(UpdateError::Runtime)?;
        if let Err(reason) = HealthGate.check(health) {
            let rollback = self
                .rollback
                .rollback(&install)
                .map_err(UpdateError::Rollback)?;
            self.audit(
                &staged.release_id,
                verified.signed.release.sequence,
                UpdatePhase::RolledBack,
                request.timestamp_unix_seconds,
            )?;
            return Err(UpdateError::Unhealthy {
                reason,
                restored_release_id: rollback.restored_release_id,
            });
        }
        self.audit(
            &staged.release_id,
            verified.signed.release.sequence,
            UpdatePhase::Healthy,
            request.timestamp_unix_seconds,
        )?;
        Ok(UpdateOutcome::Installed {
            install,
            activation,
        })
    }

    fn audit(
        &self,
        release_id: &str,
        sequence: u64,
        phase: UpdatePhase,
        timestamp_unix_seconds: u64,
    ) -> Result<(), UpdateError> {
        self.audit
            .record(&AuditEvent {
                sequence,
                release_id: release_id.to_owned(),
                phase,
                outcome: AuditOutcome::Succeeded,
                timestamp_unix_seconds,
            })
            .map_err(UpdateError::Audit)
    }
}

#[derive(Debug)]
pub enum UpdateError {
    Policy(&'static str),
    Discovery(String),
    Artifact(String),
    Verification(VerificationError),
    Runtime(String),
    Compatibility(&'static str),
    Preflight(&'static str),
    Activation(&'static str),
    Staging(StagingError),
    Drain(String),
    Install(String),
    Rollback(String),
    Audit(String),
    Unhealthy {
        reason: &'static str,
        restored_release_id: String,
    },
}

impl fmt::Display for UpdateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Policy(reason)
            | Self::Compatibility(reason)
            | Self::Preflight(reason)
            | Self::Activation(reason) => formatter.write_str(reason),
            Self::Discovery(reason)
            | Self::Artifact(reason)
            | Self::Runtime(reason)
            | Self::Drain(reason)
            | Self::Install(reason)
            | Self::Rollback(reason)
            | Self::Audit(reason) => formatter.write_str(reason),
            Self::Verification(reason) => {
                write!(formatter, "release verification failed: {reason:?}")
            }
            Self::Staging(reason) => write!(formatter, "release staging failed: {reason:?}"),
            Self::Unhealthy {
                reason,
                restored_release_id,
            } => write!(
                formatter,
                "post-install health failed ({reason}); restored {restored_release_id}"
            ),
        }
    }
}

impl std::error::Error for UpdateError {}
