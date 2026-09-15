use std::fmt;
use std::fs::{self, File};
use std::io::{self, Read};
use std::path::{Path, PathBuf};

use synergy_identity::PublicNodeIdentity;
use synergy_node_core::{
    CancellationToken, Criticality, ManagedService, RestartPolicy, ServiceHealth, ServiceId,
    ServiceReadiness, ServiceSpec,
};
use synergy_protocol_types::{NodeClass, NodeRole};

const MAX_PUBLIC_IDENTITY_BYTES: u64 = 64 * 1024;

pub fn registration(
    path: &Path,
    role: NodeRole,
) -> Result<(ServiceSpec, Box<dyn ManagedService>), IdentityAdapterError> {
    let id = ServiceId::new("identity").map_err(IdentityAdapterError::InvalidServiceId)?;
    Ok((
        ServiceSpec {
            id,
            dependencies: Vec::new(),
            criticality: Criticality::Critical,
            restart_policy: RestartPolicy::OnFailure { max_attempts: 3 },
        },
        Box::new(IdentityService::new(path.to_path_buf(), role)),
    ))
}

struct IdentityService {
    path: PathBuf,
    role: NodeRole,
    loaded: Option<PublicNodeIdentity>,
    state: IdentityState,
}

impl IdentityService {
    fn new(path: PathBuf, role: NodeRole) -> Self {
        Self {
            path,
            role,
            loaded: None,
            state: IdentityState::Registered,
        }
    }

    fn load(&self) -> Result<PublicNodeIdentity, String> {
        let metadata = fs::symlink_metadata(&self.path)
            .map_err(|error| format!("inspect public identity {}: {error}", self.path.display()))?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(format!(
                "public identity must be a regular non-symlink file: {}",
                self.path.display()
            ));
        }
        if metadata.len() == 0 || metadata.len() > MAX_PUBLIC_IDENTITY_BYTES {
            return Err(format!(
                "public identity length {} is outside 1..={MAX_PUBLIC_IDENTITY_BYTES}",
                metadata.len()
            ));
        }
        let file = File::open(&self.path)
            .map_err(|error| format!("open public identity {}: {error}", self.path.display()))?;
        let mut bytes = Vec::with_capacity(metadata.len() as usize);
        file.take(MAX_PUBLIC_IDENTITY_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|error| format!("read public identity {}: {error}", self.path.display()))?;
        if bytes.len() as u64 > MAX_PUBLIC_IDENTITY_BYTES {
            return Err("public identity changed to an oversized value while loading".into());
        }
        let identity = serde_json::from_slice::<PublicNodeIdentity>(&bytes)
            .map_err(|error| format!("decode canonical public identity: {error}"))?
            .validate()
            .map_err(|error| format!("validate canonical public identity: {error:?}"))?;
        if self.role == NodeRole::Validator
            && identity.node_address.class() != NodeClass::ConsensusAndChainIntegrity
        {
            return Err("validator role requires a class-1 canonical node address".into());
        }
        Ok(identity)
    }
}

impl ManagedService for IdentityService {
    fn start(&mut self, cancellation: &CancellationToken) -> Result<(), String> {
        if cancellation.is_cancelled() {
            return Err("identity start was cancelled".into());
        }
        match self.load() {
            Ok(identity) => {
                self.loaded = Some(identity);
                self.state = IdentityState::Running;
                Ok(())
            }
            Err(error) => {
                self.loaded = None;
                self.state = IdentityState::Failed(error.clone());
                Err(error)
            }
        }
    }

    fn stop(&mut self) -> Result<(), String> {
        self.loaded = None;
        self.state = IdentityState::Stopped;
        Ok(())
    }

    fn health(&self) -> ServiceHealth {
        match (&self.state, &self.loaded) {
            (IdentityState::Running, Some(expected)) => match self.load() {
                Ok(current) if current == *expected => ServiceHealth::Healthy,
                Ok(_) => ServiceHealth::Unhealthy {
                    reason: "public identity changed after startup".into(),
                },
                Err(reason) => ServiceHealth::Unhealthy { reason },
            },
            (IdentityState::Failed(reason), _) => ServiceHealth::Unhealthy {
                reason: reason.clone(),
            },
            (IdentityState::Registered, _) => ServiceHealth::Unhealthy {
                reason: "identity service has not started".into(),
            },
            (IdentityState::Stopped, _) => ServiceHealth::Unhealthy {
                reason: "identity service is stopped".into(),
            },
            (IdentityState::Running, None) => ServiceHealth::Unhealthy {
                reason: "identity service lost its loaded public identity".into(),
            },
        }
    }

    fn readiness(&self) -> ServiceReadiness {
        match self.health() {
            ServiceHealth::Healthy => ServiceReadiness::Ready,
            ServiceHealth::Degraded { reason } => ServiceReadiness::Pending { reason },
            ServiceHealth::Unhealthy { reason } => ServiceReadiness::Blocked { reason },
        }
    }
}

enum IdentityState {
    Registered,
    Running,
    Stopped,
    Failed(String),
}

#[derive(Debug)]
pub enum IdentityAdapterError {
    InvalidServiceId(String),
    Io(io::Error),
}

impl fmt::Display for IdentityAdapterError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidServiceId(error) => {
                write!(formatter, "invalid identity service id: {error}")
            }
            Self::Io(error) => write!(formatter, "identity I/O failed: {error}"),
        }
    }
}

impl std::error::Error for IdentityAdapterError {}
