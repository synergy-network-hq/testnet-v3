use std::fmt;
use std::fs;
use std::io;

use synergy_config::{StorageConfiguration, WalSyncPolicy};
use synergy_node_core::{
    CancellationToken, Criticality, ManagedService, RestartPolicy, ServiceHealth, ServiceId,
    ServiceReadiness, ServiceSpec,
};
use synergy_storage::{
    write_schema_version, AtomicStore, DiskGuard, NodeStorageLayout, SchemaVersion,
};

const MAX_RUNTIME_RECORD_BYTES: usize = 16 * 1024 * 1024;
const STORAGE_SCHEMA_NAME: &str = "synergy-node-storage";
const STORAGE_SCHEMA_VERSION: u32 = 1;
const STORAGE_SCHEMA_MARKER: &[u8] = b"synergy-node-storage:1";

/// Creates the concrete storage service registration used by `synergy-node`.
pub fn registration(
    configuration: &StorageConfiguration,
) -> Result<(ServiceSpec, Box<dyn ManagedService>), StorageAdapterError> {
    let id = ServiceId::new("storage").map_err(StorageAdapterError::InvalidServiceId)?;
    let specification = ServiceSpec {
        id,
        dependencies: Vec::new(),
        criticality: Criticality::Critical,
        restart_policy: RestartPolicy::OnFailure { max_attempts: 3 },
    };
    Ok((
        specification,
        Box::new(StorageService::new(configuration.clone())),
    ))
}

struct StorageService {
    configuration: StorageConfiguration,
    store: Option<AtomicStore>,
    state: StorageState,
}

impl StorageService {
    fn new(configuration: StorageConfiguration) -> Self {
        Self {
            configuration,
            store: None,
            state: StorageState::Registered,
        }
    }

    fn open(&self) -> Result<AtomicStore, String> {
        if self.configuration.max_open_files < 32 {
            return Err("storage max_open_files must be at least 32".into());
        }
        match self.configuration.wal_sync {
            // AtomicStore always durably syncs every commit. Accepting the
            // bounded policy therefore strengthens, rather than weakens, its
            // requested durability until batching is a Phase 2 optimization.
            WalSyncPolicy::EveryCommit | WalSyncPolicy::BoundedBatch => {}
        }

        let layout = NodeStorageLayout::new(self.configuration.data_directory.clone())
            .map_err(|error| format!("construct canonical storage layout: {error}"))?;
        ensure_directory(layout.root())?;
        for column in layout.columns() {
            ensure_directory(&column)?;
        }
        self.check_disk(layout.root())?;
        let store = AtomicStore::new(layout.root(), MAX_RUNTIME_RECORD_BYTES)
            .map_err(|error| format!("construct canonical atomic store: {error}"))?;
        let schema = SchemaVersion {
            name: STORAGE_SCHEMA_NAME.into(),
            version: STORAGE_SCHEMA_VERSION,
        };
        if store
            .exists("metadata/schema-version")
            .map_err(|error| format!("inspect canonical storage schema: {error}"))?
        {
            verify_schema_marker(&store)?;
        } else {
            write_schema_version(&store, &schema)
                .map_err(|error| format!("persist canonical storage schema: {error}"))?;
            verify_schema_marker(&store)?;
        }
        Ok(store)
    }

    fn check_disk(&self, path: &std::path::Path) -> Result<(), String> {
        DiskGuard::new(self.configuration.minimum_free_bytes)
            .map_err(|error| format!("construct storage disk guard: {error}"))?
            .check_path(path)
            .map(|_| ())
            .map_err(|error| format!("check canonical storage capacity: {error}"))
    }
}

impl ManagedService for StorageService {
    fn start(&mut self, cancellation: &CancellationToken) -> Result<(), String> {
        if cancellation.is_cancelled() {
            return Err("storage start was cancelled".into());
        }
        if matches!(self.state, StorageState::Running) {
            return Err("storage service is already running".into());
        }
        match self.open() {
            Ok(store) => {
                self.store = Some(store);
                self.state = StorageState::Running;
                Ok(())
            }
            Err(error) => {
                self.store = None;
                self.state = StorageState::Failed(error.clone());
                Err(error)
            }
        }
    }

    fn stop(&mut self) -> Result<(), String> {
        self.store = None;
        self.state = StorageState::Stopped;
        Ok(())
    }

    fn health(&self) -> ServiceHealth {
        match (&self.state, &self.store) {
            (StorageState::Running, Some(store)) => {
                match verify_schema_marker(store)
                    .and_then(|()| self.check_disk(&self.configuration.data_directory))
                {
                    Ok(()) => ServiceHealth::Healthy,
                    Err(reason) => ServiceHealth::Unhealthy { reason },
                }
            }
            (StorageState::Failed(reason), _) => ServiceHealth::Unhealthy {
                reason: reason.clone(),
            },
            (StorageState::Registered, _) => ServiceHealth::Unhealthy {
                reason: "storage service has not started".into(),
            },
            (StorageState::Stopped, _) => ServiceHealth::Unhealthy {
                reason: "storage service is stopped".into(),
            },
            (StorageState::Running, None) => ServiceHealth::Unhealthy {
                reason: "storage service lost its active store".into(),
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

fn ensure_directory(path: &std::path::Path) -> Result<(), String> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => validate_directory_metadata(path, &metadata),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            fs::create_dir_all(path)
                .map_err(|error| format!("create storage directory {}: {error}", path.display()))?;
            let metadata = fs::symlink_metadata(path).map_err(|error| {
                format!(
                    "inspect created storage directory {}: {error}",
                    path.display()
                )
            })?;
            validate_directory_metadata(path, &metadata)
        }
        Err(error) => Err(format!(
            "inspect storage directory {}: {error}",
            path.display()
        )),
    }
}

fn validate_directory_metadata(
    path: &std::path::Path,
    metadata: &fs::Metadata,
) -> Result<(), String> {
    if metadata.file_type().is_symlink() {
        return Err(format!(
            "storage directory must not be a symbolic link: {}",
            path.display()
        ));
    }
    if !metadata.is_dir() {
        return Err(format!(
            "storage path is not a directory: {}",
            path.display()
        ));
    }
    Ok(())
}

fn verify_schema_marker(store: &AtomicStore) -> Result<(), String> {
    let marker = store
        .read_bounded("metadata/schema-version")
        .map_err(|error| format!("read canonical storage schema: {error}"))?;
    if marker == STORAGE_SCHEMA_MARKER {
        Ok(())
    } else {
        Err("canonical storage schema marker does not match this runtime".into())
    }
}

enum StorageState {
    Registered,
    Running,
    Stopped,
    Failed(String),
}

#[derive(Debug)]
pub enum StorageAdapterError {
    InvalidServiceId(String),
}

impl fmt::Display for StorageAdapterError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidServiceId(error) => {
                write!(formatter, "invalid storage service id: {error}")
            }
        }
    }
}

impl std::error::Error for StorageAdapterError {}
