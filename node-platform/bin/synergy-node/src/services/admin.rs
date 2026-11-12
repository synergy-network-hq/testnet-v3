use std::collections::BTreeSet;
use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use serde_json::json;
use synergy_admin_api::audit::AdminAuditRecord;
use synergy_admin_api::authorization::{AdminPermission, AuthorizationContext};
use synergy_admin_api::operations::{
    AdminOperation, ConfigOperation, EtdagOperation, LifecycleAction, LifecycleOperation,
    NamingOperation, OwnershipOperation, PeerOperation, RewardOperation, StorageOperation,
    SyncOperation, TelemetryOperation, UpgradeOperation, ValidatorOperation,
};
use synergy_admin_api::{AdminError, AdminRequest, AdminResponse, AdminService};
use synergy_aegis::{AegisPolicy, KeyId, SignatureAlgorithm};
use synergy_config::NodeConfiguration;
use synergy_naming::{
    is_available, resolve, reverse_resolve, NamingRegistrySnapshot, NodeId,
    PROTOCOL_STATE_KEY as NAMING_STATE_KEY,
};
use synergy_node_ownership::{
    OwnershipRegistrySnapshot, PROTOCOL_STATE_KEY as OWNERSHIP_STATE_KEY,
};
use synergy_posy::MembershipAuthority;
use synergy_rewards::{RewardLedgerSnapshot, PROTOCOL_STATE_KEY as REWARD_STATE_KEY};
use synergy_roles::Capability;
use synergy_state::{FinalizedStateStore, WorldState};
use synergy_storage::{AtomicStore, NodeStorageLayout};
use synergy_transaction::TransactionAction;
use synergy_updater::{stage_artifact, verify_release, SignedReleaseMetadata};
use synergy_validator_management::{
    PersistentValidatorManagement, ValidatorApplication, ValidatorManagementCommand,
    ValidatorManagementStore,
};

use super::ingress::{EtdagControlAction, PeerControlAction, SyncControlAction};
use crate::commands::start::service_capabilities;
use crate::services::authority::VerifiedAuthority;
use crate::services::ingress::AuthenticatedIngress;
use synergy_node_core::{
    CancellationToken, Criticality, ManagedService, ManagementOperation, RestartPolicy,
    RuntimeView, ServiceHealth, ServiceId, ServiceReadiness, ServiceSpec,
};

#[cfg(unix)]
use synergy_admin_api::local::LocalAdminServer;

const MAX_VALIDATOR_MANAGEMENT_STATE_BYTES: usize = 8 * 1024 * 1024;
const VALIDATOR_STATE_PATH: &str = "state.json";
const MAX_UPDATE_METADATA_BYTES: u64 = 1024 * 1024;
const MAX_UPDATE_PUBLIC_KEY_BYTES: u64 = 64 * 1024;
const MAX_ADMIN_UPDATE_ARTIFACT_BYTES: u64 = 512 * 1024 * 1024;
const MAX_ADMIN_AUDIT_BYTES: usize = 16 * 1024 * 1024;
const MAX_ADMIN_AUDIT_RECORDS: usize = 8_192;
const MAX_ADMIN_AUDIT_DETAIL_BYTES: usize = 512;
const ADMIN_AUDIT_PATH: &str = "records.json";

pub fn registration(
    configuration: &NodeConfiguration,
    runtime: RuntimeView,
    authority: Option<Arc<VerifiedAuthority>>,
    ingress: AuthenticatedIngress,
) -> Result<(ServiceSpec, Box<dyn ManagedService>), String> {
    let socket_path = &configuration.admin_socket_path;
    if !socket_path.is_absolute() {
        return Err("Admin API socket path must be absolute".into());
    }

    let layout = NodeStorageLayout::new(configuration.storage.data_directory.clone())
        .map_err(|error| format!("construct canonical storage layout: {error}"))?;
    let store =
        AtomicValidatorManagementStore::new(layout.consensus().join("validator-management"))?;
    let mut validator_management = PersistentValidatorManagement::load(store)?;
    let audit = AtomicAdminAuditLog::load(layout.metadata().join("admin-audit"))?;
    if let Some(authority) = authority.as_ref() {
        validator_management.reconcile_frozen_authority(&authority.registry)?;
    }
    let permissions = BTreeSet::from([
        AdminPermission::Read,
        AdminPermission::Lifecycle,
        AdminPermission::Configuration,
        AdminPermission::Identity,
        AdminPermission::Peers,
        AdminPermission::Validator,
        AdminPermission::Vpn,
        AdminPermission::Consensus,
        AdminPermission::Etdag,
        AdminPermission::Storage,
        AdminPermission::Upgrade,
    ]);

    Ok((
        ServiceSpec {
            id: ServiceId::new("admin-api")?,
            dependencies: vec![
                ServiceId::new("identity")?,
                ServiceId::new("storage")?,
                ServiceId::new("network")?,
            ],
            criticality: Criticality::Required,
            restart_policy: RestartPolicy::OnFailure { max_attempts: 3 },
        },
        Box::new(AdminApiService {
            socket_path: socket_path.to_path_buf(),
            runtime,
            configuration: configuration.clone(),
            authority,
            ingress,
            validator_management: Arc::new(Mutex::new(validator_management)),
            audit: Arc::new(Mutex::new(audit)),
            authorization: AuthorizationContext {
                principal: format!("owner-local:{}", configuration.node_name),
                permissions,
            },
            #[cfg(unix)]
            server: None,
            failure: None,
        }),
    ))
}

#[derive(Clone)]
struct AtomicValidatorManagementStore {
    store: AtomicStore,
}

impl AtomicValidatorManagementStore {
    fn new(root: impl AsRef<Path>) -> Result<Self, String> {
        Ok(Self {
            store: AtomicStore::new(root.as_ref(), MAX_VALIDATOR_MANAGEMENT_STATE_BYTES)
                .map_err(|error| format!("open validator management store: {error}"))?,
        })
    }
}

impl ValidatorManagementStore for AtomicValidatorManagementStore {
    fn load(&self) -> Result<Option<Vec<u8>>, String> {
        if !self
            .store
            .exists(VALIDATOR_STATE_PATH)
            .map_err(|error| format!("inspect validator management state: {error}"))?
        {
            return Ok(None);
        }
        self.store
            .read_bounded(VALIDATOR_STATE_PATH)
            .map(Some)
            .map_err(|error| format!("read validator management state: {error}"))
    }

    fn compare_and_swap(
        &mut self,
        expected: Option<&[u8]>,
        replacement: &[u8],
    ) -> Result<(), String> {
        let current = self.load()?;
        if current.as_deref() != expected {
            return Err("validator management state changed concurrently".into());
        }
        self.store
            .write_atomic(VALIDATOR_STATE_PATH, replacement)
            .map_err(|error| format!("persist validator management state: {error}"))
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct PersistedAdminAuditLog {
    version: u32,
    records: Vec<AdminAuditRecord>,
}

struct AtomicAdminAuditLog {
    store: AtomicStore,
    state: PersistedAdminAuditLog,
}

impl AtomicAdminAuditLog {
    fn load(root: impl AsRef<Path>) -> Result<Self, String> {
        let store = AtomicStore::new(root.as_ref(), MAX_ADMIN_AUDIT_BYTES)
            .map_err(|error| format!("open Admin audit store: {error}"))?;
        let state = if store
            .exists(ADMIN_AUDIT_PATH)
            .map_err(|error| format!("inspect Admin audit log: {error}"))?
        {
            let bytes = store
                .read_bounded(ADMIN_AUDIT_PATH)
                .map_err(|error| format!("read Admin audit log: {error}"))?;
            let state: PersistedAdminAuditLog = serde_json::from_slice(&bytes)
                .map_err(|error| format!("decode Admin audit log: {error}"))?;
            if state.version != 1
                || state.records.len() > MAX_ADMIN_AUDIT_RECORDS
                || state.records.iter().enumerate().any(|(index, record)| {
                    record.validate().is_err()
                        || index > 0
                            && record.sequence
                                != state.records[index - 1].sequence.saturating_add(1)
                })
            {
                return Err("Admin audit log failed canonical validation".into());
            }
            state
        } else {
            PersistedAdminAuditLog {
                version: 1,
                records: Vec::new(),
            }
        };
        Ok(Self { store, state })
    }

    fn append_event(
        &mut self,
        request_id: &str,
        principal: &str,
        operation: &str,
        outcome: &str,
        detail: &str,
    ) -> Result<(), AdminError> {
        let sequence = self
            .state
            .records
            .last()
            .map_or(1, |record| record.sequence.saturating_add(1));
        if sequence == u64::MAX {
            return Err(AdminError::unavailable("Admin audit sequence is exhausted"));
        }
        let record = AdminAuditRecord {
            sequence,
            timestamp_ms: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|_| AdminError::unavailable("system clock precedes Unix epoch"))?
                .as_millis()
                .try_into()
                .map_err(|_| AdminError::unavailable("Admin audit timestamp overflow"))?,
            request_id: if request_id.trim().is_empty() {
                "<missing>".to_owned()
            } else {
                request_id.chars().take(256).collect()
            },
            principal: principal.to_owned(),
            operation: operation.to_owned(),
            outcome: outcome.to_owned(),
            detail: detail.chars().take(MAX_ADMIN_AUDIT_DETAIL_BYTES).collect(),
        };
        record.validate()?;
        let removed = if self.state.records.len() == MAX_ADMIN_AUDIT_RECORDS {
            Some(self.state.records.remove(0))
        } else {
            None
        };
        self.state.records.push(record);
        let encoded = serde_json::to_vec(&self.state)
            .map_err(|error| AdminError::unavailable(format!("encode Admin audit log: {error}")))?;
        if let Err(error) = self.store.write_atomic(ADMIN_AUDIT_PATH, &encoded) {
            self.state.records.pop();
            if let Some(record) = removed {
                self.state.records.insert(0, record);
            }
            return Err(AdminError::unavailable(format!(
                "persist Admin audit log: {error}"
            )));
        }
        Ok(())
    }
}

struct RuntimeAdminService {
    runtime: RuntimeView,
    configuration: NodeConfiguration,
    authority: Option<Arc<VerifiedAuthority>>,
    ingress: AuthenticatedIngress,
    validator_management: Arc<Mutex<PersistentValidatorManagement<AtomicValidatorManagementStore>>>,
    audit: Arc<Mutex<AtomicAdminAuditLog>>,
    cancellation: CancellationToken,
    authorization: AuthorizationContext,
}

impl AdminService for RuntimeAdminService {
    fn handle(&self, request: AdminRequest) -> AdminResponse {
        let audit_label = request.operation.audit_label();
        let shutdown_requested = matches!(
            &request.operation,
            AdminOperation::Lifecycle(LifecycleOperation {
                action: LifecycleAction::Stop,
                ..
            })
        );
        if let Err(error) = request.validate() {
            let _ = self.append_audit(
                &request.request_id,
                audit_label,
                "rejected",
                &format!("{}: {}", error.code, error.message),
            );
            return AdminResponse::failure(request.request_id, error);
        }
        if let Err(error) = self
            .authorization
            .require(request.operation.required_permission())
        {
            let _ = self.append_audit(
                &request.request_id,
                audit_label,
                "forbidden",
                &format!("{}: {}", error.code, error.message),
            );
            return AdminResponse::failure(request.request_id, error);
        }
        if let Err(error) =
            self.append_audit(&request.request_id, audit_label, "accepted", "authorized")
        {
            return AdminResponse::failure(request.request_id, error);
        }

        let request_id = request.request_id.clone();
        let result = match request.operation {
            AdminOperation::Read(operation) => self.handle_read(operation),
            AdminOperation::Validator(operation) => {
                self.handle_validator(operation, request.idempotency_key.as_deref())
            }
            AdminOperation::Ownership(operation) => self.handle_ownership(operation),
            AdminOperation::Naming(operation) => self.handle_naming(operation),
            AdminOperation::Rewards(operation) => self.handle_rewards(operation),
            AdminOperation::Config(operation) => self.handle_config(operation),
            AdminOperation::Storage(operation) => self.handle_storage(operation),
            AdminOperation::Telemetry(operation) => self.handle_telemetry(operation),
            AdminOperation::Upgrade(operation) => self.handle_upgrade(operation),
            AdminOperation::Lifecycle(operation) => self.handle_lifecycle(operation),
            AdminOperation::Peers(operation) => self.handle_peers(operation),
            AdminOperation::Sync(operation) => self.handle_sync(operation),
            AdminOperation::Etdag(operation) => self.handle_etdag(operation),
            _ => Err(AdminError::unavailable(
                "Admin operation has no canonical runtime owner wired",
            )),
        };
        let audit_result = match &result {
            Ok(_) => self.append_audit(&request_id, audit_label, "succeeded", "completed"),
            Err(error) => self.append_audit(
                &request_id,
                audit_label,
                "failed",
                &format!("{}: {}", error.code, error.message),
            ),
        };
        if let Err(error) = audit_result {
            return AdminResponse::failure(request_id, error);
        }
        if shutdown_requested && result.is_ok() {
            self.cancellation.cancel();
        }
        match result {
            Ok(value) => AdminResponse::success(request_id, value),
            Err(error) => AdminResponse::failure(request_id, error),
        }
    }
}

impl RuntimeAdminService {
    fn append_audit(
        &self,
        request_id: &str,
        operation: &str,
        outcome: &str,
        detail: &str,
    ) -> Result<(), AdminError> {
        self.audit
            .lock()
            .map_err(|_| AdminError::unavailable("Admin audit state lock is poisoned"))?
            .append_event(
                request_id,
                &self.authorization.principal,
                operation,
                outcome,
                detail,
            )
    }

    fn handle_lifecycle(
        &self,
        operation: LifecycleOperation,
    ) -> Result<serde_json::Value, AdminError> {
        match operation.action {
            LifecycleAction::Stop => Ok(json!({
                "accepted": true,
                "action": "stop",
                "timeout_ms": operation.timeout_ms,
                "shutdown": "supervised_reverse_dependency_order",
            })),
            LifecycleAction::Start | LifecycleAction::Restart | LifecycleAction::Drain => {
                Err(AdminError::unavailable(
                    "requested lifecycle transition requires an external lifecycle provider",
                ))
            }
        }
    }

    fn handle_peers(&self, operation: PeerOperation) -> Result<serde_json::Value, AdminError> {
        let action = match operation {
            PeerOperation::Disconnect { peer_id } => PeerControlAction::Disconnect {
                peer_id: canonical_peer_id(peer_id)?,
            },
            PeerOperation::Quarantine { peer_id, until } => PeerControlAction::Quarantine {
                peer_id: canonical_peer_id(peer_id)?,
                until,
            },
            PeerOperation::Ban { peer_id, until } => PeerControlAction::Ban {
                peer_id: canonical_peer_id(peer_id)?,
                until,
            },
            PeerOperation::Unban { peer_id } => PeerControlAction::Unban {
                peer_id: canonical_peer_id(peer_id)?,
            },
        };
        let peer_id = action.peer_id().to_owned();
        let action_name = match action {
            PeerControlAction::Disconnect { .. } => "disconnect",
            PeerControlAction::Quarantine { .. } => "quarantine",
            PeerControlAction::Ban { .. } => "ban",
            PeerControlAction::Unban { .. } => "unban",
        };
        self.ingress
            .request_peer_control(action, Duration::from_secs(5))
            .map_err(AdminError::conflict)?;
        Ok(json!({
            "peer_id": peer_id,
            "action": action_name,
            "applied": true,
            "authority": "authenticated_peer_lifecycle_only",
        }))
    }

    fn handle_sync(&self, operation: SyncOperation) -> Result<serde_json::Value, AdminError> {
        let (action, action_name, peer_id) = match operation {
            SyncOperation::Pause => (SyncControlAction::Pause, "pause", None),
            SyncOperation::Resume => (SyncControlAction::Resume, "resume", None),
            SyncOperation::RetrySource { peer_id } => {
                let peer_id = canonical_peer_id(peer_id)?;
                (
                    SyncControlAction::RetrySource {
                        peer_id: peer_id.clone(),
                    },
                    "retry_source",
                    Some(peer_id),
                )
            }
        };
        self.ingress
            .request_sync_control(action, Duration::from_secs(5))
            .map_err(AdminError::conflict)?;
        Ok(json!({
            "action": action_name,
            "peer_id": peer_id,
            "applied": true,
            "authority": "authenticated_verified_sync_source_only",
            "finality_authority": "posy_only",
        }))
    }

    fn handle_etdag(&self, operation: EtdagOperation) -> Result<serde_json::Value, AdminError> {
        let (action, action_name) = match operation {
            EtdagOperation::PauseIngress => (EtdagControlAction::PauseIngress, "pause_ingress"),
            EtdagOperation::ResumeIngress => (EtdagControlAction::ResumeIngress, "resume_ingress"),
            EtdagOperation::RecoverArtifact { .. } => return Err(AdminError::unavailable(
                "ETDAG artifact recovery requires an exact authenticated source and shard index",
            )),
        };
        self.ingress
            .request_etdag_control(action, Duration::from_secs(5))
            .map_err(AdminError::conflict)?;
        Ok(json!({
            "action": action_name,
            "applied": true,
            "scope": "authenticated_etdag_ingress",
            "finality_authority": "posy_only",
        }))
    }

    fn handle_config(&self, operation: ConfigOperation) -> Result<serde_json::Value, AdminError> {
        let (path, reload) = match operation {
            ConfigOperation::Validate { path } => (path, false),
            ConfigOperation::Reload { path } => (path, true),
        };
        let loaded = synergy_config::load(Path::new(&path)).map_err(|error| {
            AdminError::invalid_request(format!("configuration rejected: {error}"))
        })?;
        if reload {
            return Err(AdminError::unavailable(
                "configuration reload requires deterministic service-graph reconstruction and is not performed in place",
            ));
        }
        Ok(json!({
            "valid": true,
            "node_name": loaded.node_name,
            "role": format!("{:?}", loaded.role).to_ascii_lowercase(),
            "chain_id": loaded.chain_id,
        }))
    }

    fn handle_storage(&self, operation: StorageOperation) -> Result<serde_json::Value, AdminError> {
        match operation {
            StorageOperation::Verify => {
                let layout = NodeStorageLayout::new(
                    self.configuration.storage.data_directory.clone(),
                )
                .map_err(|error| AdminError::unavailable(format!("open storage layout: {error}")))?;
                for root in layout.columns() {
                    let metadata = std::fs::symlink_metadata(&root).map_err(|error| {
                        AdminError::unavailable(format!(
                            "inspect storage root {}: {error}",
                            root.display()
                        ))
                    })?;
                    if metadata.file_type().is_symlink() || !metadata.is_dir() {
                        return Err(AdminError::unavailable(format!(
                            "storage root is not a canonical directory: {}",
                            root.display()
                        )));
                    }
                }
                Ok(json!({"verified": true, "data_directory": layout.root()}))
            }
            StorageOperation::CreateSnapshot { .. } => Err(AdminError::unavailable(
                "snapshot creation is finality-driven by the canonical Sync service",
            )),
            StorageOperation::Prune { .. } => Err(AdminError::unavailable(
                "manual pruning is unavailable until the canonical retention executor owns the operation",
            )),
        }
    }

    fn handle_telemetry(
        &self,
        operation: TelemetryOperation,
    ) -> Result<serde_json::Value, AdminError> {
        match operation {
            TelemetryOperation::Snapshot => self
                .runtime
                .read()
                .map_err(|_| AdminError::unavailable("runtime observation state is unavailable"))
                .and_then(|snapshot| {
                    serde_json::to_value(&*snapshot).map_err(|error| {
                        AdminError::unavailable(format!("encode runtime telemetry: {error}"))
                    })
                }),
            TelemetryOperation::SetFilter { .. } => Err(AdminError::unavailable(
                "runtime telemetry filter mutation has no canonical dynamic owner",
            )),
        }
    }

    fn handle_upgrade(&self, operation: UpgradeOperation) -> Result<serde_json::Value, AdminError> {
        match operation {
            UpgradeOperation::Stage {
                release_id,
                metadata_path,
                artifact_path,
            } => {
                let update = &self.configuration.update;
                if !update.enabled {
                    return Err(AdminError::unavailable(
                        "signed updates are disabled by canonical node configuration",
                    ));
                }
                let signer_key_id = update.release_signer_key_id.as_deref().ok_or_else(|| {
                    AdminError::unavailable("governed release signer key ID is unavailable")
                })?;
                let signer_public_key_path = update
                    .release_signer_public_key_path
                    .as_deref()
                    .ok_or_else(|| {
                        AdminError::unavailable("governed release public key path is unavailable")
                    })?;
                let staging_directory = update.staging_directory.as_deref().ok_or_else(|| {
                    AdminError::unavailable("canonical update staging directory is unavailable")
                })?;
                let metadata_bytes = read_bounded_update_file(
                    Path::new(&metadata_path),
                    MAX_UPDATE_METADATA_BYTES,
                    "signed release metadata",
                )?;
                let signed: SignedReleaseMetadata = serde_json::from_slice(&metadata_bytes)
                    .map_err(|error| {
                        AdminError::invalid_request(format!(
                            "decode signed release metadata: {error}"
                        ))
                    })?;
                if signed.release.release_id != release_id {
                    return Err(AdminError::conflict(
                        "requested release ID does not match signed metadata",
                    ));
                }
                let maximum_artifact_bytes = update
                    .maximum_artifact_bytes
                    .min(MAX_ADMIN_UPDATE_ARTIFACT_BYTES);
                let artifact = read_bounded_update_file(
                    Path::new(&artifact_path),
                    maximum_artifact_bytes,
                    "release artifact",
                )?;
                let governed_public_key = read_bounded_update_file(
                    signer_public_key_path,
                    MAX_UPDATE_PUBLIC_KEY_BYTES,
                    "governed release public key",
                )?;
                let governed_signer_key_id =
                    KeyId::new(signer_key_id.to_owned()).map_err(|error| {
                        AdminError::invalid_request(format!(
                            "invalid governed release signer key ID: {error}"
                        ))
                    })?;
                let verifier = super::apqe_provider::verifier(
                    &self.configuration,
                    AegisPolicy {
                        allowed_algorithms: vec![SignatureAlgorithm::MlDsa65],
                        maximum_message_bytes: MAX_UPDATE_METADATA_BYTES as usize,
                        maximum_signature_bytes: 16 * 1024,
                    },
                )
                .map_err(|error| {
                    AdminError::unavailable(format!("construct Aegis release verifier: {error}"))
                })?;
                let verified = verify_release(
                    &verifier,
                    self.configuration.chain_id,
                    update.installed_sequence,
                    &governed_signer_key_id,
                    &governed_public_key,
                    signed,
                    &artifact,
                )
                .map_err(|error| {
                    AdminError::invalid_request(format!("release verification failed: {error:?}"))
                })?;
                let staged =
                    stage_artifact(staging_directory, &verified, &artifact).map_err(|error| {
                        AdminError::unavailable(format!("stage verified release: {error:?}"))
                    })?;
                Ok(json!({
                    "release_id": staged.release_id,
                    "staged_path": staged.path,
                    "verified": true,
                    "installed": false,
                    "protocol_activated": false,
                }))
            }
            UpgradeOperation::Apply { .. } | UpgradeOperation::Rollback { .. } => {
                Err(AdminError::unavailable(
                    "apply/rollback requires the supervised lifecycle updater provider",
                ))
            }
        }
    }

    fn handle_read(&self, operation: ManagementOperation) -> Result<serde_json::Value, AdminError> {
        let snapshot = self
            .runtime
            .read()
            .map_err(|_| AdminError::unavailable("runtime observation state is unavailable"))?
            .clone();
        let value = match operation {
            ManagementOperation::NodeStatus => json!({
                "node_name": snapshot.node_name,
                "role": snapshot.role,
                "chain_id": snapshot.chain_id,
                "lifecycle": snapshot.lifecycle,
            }),
            ManagementOperation::Health => json!({ "services": snapshot.services }),
            ManagementOperation::Readiness => json!({ "ready": snapshot.ready() }),
            ManagementOperation::Diagnostics => json!({
                "lifecycle": snapshot.lifecycle,
                "services": snapshot.services,
            }),
            ManagementOperation::ConfigurationValidation => {
                self.configuration.validate().map_err(|error| {
                    AdminError::invalid_request(format!(
                        "canonical configuration validation failed: {error}"
                    ))
                })?;
                json!({
                    "valid": true,
                    "schema_version": self.configuration.schema_version,
                    "chain_id": self.configuration.chain_id,
                    "network_id": self.configuration.network_id,
                })
            }
            ManagementOperation::RoleInspection => json!({
                "role": self.configuration.role,
                "consensus_mode": self.configuration.consensus.mode,
                "consensus_signing_component_requested": self.configuration.role_hosts_consensus_signer(),
                "role_grants_validator_authority": self.configuration.role_grants_validator_authority(),
                "frozen_posy_authority_loaded": self.authority.is_some(),
                "services": snapshot.services.iter().map(|service| service.id.as_str()).collect::<Vec<_>>(),
            }),
            ManagementOperation::CapabilityDiscovery => {
                let capabilities = snapshot
                    .services
                    .iter()
                    .flat_map(|service| {
                        service_capabilities(service.id.as_str(), &self.configuration)
                    })
                    .collect::<BTreeSet<Capability>>();
                json!({
                    "capabilities": capabilities,
                    "role_grants_validator_authority": false,
                    "frozen_posy_authority_loaded": self.authority.is_some(),
                })
            }
        };
        Ok(value)
    }

    fn finalized_world_state(&self) -> Result<WorldState, AdminError> {
        let layout = NodeStorageLayout::new(self.configuration.storage.data_directory.clone())
            .map_err(|error| AdminError::unavailable(error.to_string()))?;
        FinalizedStateStore::load(layout.state().join("execution"))
            .and_then(|store| store.current_world_state())
            .map_err(|error| {
                AdminError::unavailable(format!("load finalized world state: {error:?}"))
            })
            .map(|state| state.unwrap_or_default())
    }

    fn protocol_state<T: serde::de::DeserializeOwned + Default>(
        &self,
        key: &str,
    ) -> Result<T, AdminError> {
        let world = self.finalized_world_state()?;
        world.protocol.get(key).map_or_else(
            || Ok(T::default()),
            |bytes| {
                serde_json::from_slice(bytes).map_err(|error| {
                    AdminError::unavailable(format!("decode finalized {key}: {error}"))
                })
            },
        )
    }

    fn prepared_native_action(
        module: &str,
        method: &str,
        input: serde_json::Value,
    ) -> Result<serde_json::Value, AdminError> {
        let input = serde_json::to_vec(&input).map_err(|error| {
            AdminError::invalid_request(format!("encode native input: {error}"))
        })?;
        let action = TransactionAction::Native {
            module: module.into(),
            method: method.into(),
            input,
        };
        action
            .validate()
            .map_err(|error| AdminError::invalid_request(error.to_string()))?;
        Ok(json!({
            "transaction_action": action,
            "authoritative_state": "finalized_world_state",
            "submission_required": "wallet-signed protected ETDAG transaction",
            "admin_api_mutated_state": false,
        }))
    }

    fn handle_ownership(
        &self,
        operation: OwnershipOperation,
    ) -> Result<serde_json::Value, AdminError> {
        match operation {
            OwnershipOperation::Inspect { node_address } => {
                let node_address = synergy_protocol_types::NodeAddress::parse(&node_address)
                    .map_err(|error| AdminError::invalid_request(error.to_string()))?;
                let ownership: OwnershipRegistrySnapshot =
                    self.protocol_state(OWNERSHIP_STATE_KEY)?;
                Ok(json!({
                    "node_address": node_address,
                    "owner_wallet": ownership.current_owner(&node_address),
                    "binding": ownership.binding(&node_address),
                    "authoritative_state": "finalized_world_state",
                }))
            }
            OwnershipOperation::PrepareClaim {
                node_address,
                nonce,
                node_possession_proof,
            } => {
                let node_address = synergy_protocol_types::NodeAddress::parse(&node_address)
                    .map_err(|error| AdminError::invalid_request(error.to_string()))?;
                Self::prepared_native_action(
                    "node_ownership",
                    "claim",
                    json!({
                        "node_address": node_address,
                        "nonce": nonce,
                        "node_possession_proof": node_possession_proof,
                    }),
                )
            }
            OwnershipOperation::PrepareTransfer {
                node_address,
                new_owner_wallet,
                nonce,
                new_owner_acceptance_proof,
            } => {
                let node_address = synergy_protocol_types::NodeAddress::parse(&node_address)
                    .map_err(|error| AdminError::invalid_request(error.to_string()))?;
                if synergy_address::address_kind(&new_owner_wallet)
                    != synergy_address::AddressKind::Wallet
                {
                    return Err(AdminError::invalid_request("invalid new owner wallet"));
                }
                Self::prepared_native_action(
                    "node_ownership",
                    "transfer",
                    json!({
                        "node_address": node_address,
                        "new_owner_wallet": new_owner_wallet,
                        "nonce": nonce,
                        "new_owner_acceptance_proof": new_owner_acceptance_proof,
                    }),
                )
            }
        }
    }

    fn handle_naming(&self, operation: NamingOperation) -> Result<serde_json::Value, AdminError> {
        let naming: NamingRegistrySnapshot = self.protocol_state(NAMING_STATE_KEY)?;
        match operation {
            NamingOperation::Resolve { node_id } => {
                let node_id = NodeId::parse(&node_id)
                    .map_err(|error| AdminError::invalid_request(error.to_string()))?;
                Ok(json!({
                    "node_id": node_id,
                    "node_address": resolve(&naming, &node_id),
                    "authoritative_state": "finalized_world_state",
                }))
            }
            NamingOperation::ReverseResolve { node_address } => {
                let node_address = synergy_protocol_types::NodeAddress::parse(&node_address)
                    .map_err(|error| AdminError::invalid_request(error.to_string()))?;
                Ok(json!({
                    "node_address": node_address,
                    "node_id": reverse_resolve(&naming, &node_address),
                    "authoritative_state": "finalized_world_state",
                }))
            }
            NamingOperation::Availability { node_id } => {
                let node_id = NodeId::parse(&node_id)
                    .map_err(|error| AdminError::invalid_request(error.to_string()))?;
                Ok(json!({
                    "node_id": node_id,
                    "available": is_available(&naming, &node_id),
                    "authoritative_state": "finalized_world_state",
                }))
            }
            NamingOperation::PrepareRegister {
                node_id,
                node_address,
                nonce,
            } => {
                let node_id = NodeId::parse(&node_id)
                    .map_err(|error| AdminError::invalid_request(error.to_string()))?;
                let node_address = synergy_protocol_types::NodeAddress::parse(&node_address)
                    .map_err(|error| AdminError::invalid_request(error.to_string()))?;
                Self::prepared_native_action(
                    "naming",
                    "register",
                    json!({
                        "node_id": node_id,
                        "node_address": node_address,
                        "nonce": nonce,
                    }),
                )
            }
            NamingOperation::PrepareRename {
                current_node_id,
                replacement_node_id,
                node_address,
                nonce,
            } => {
                let current_node_id = NodeId::parse(&current_node_id)
                    .map_err(|error| AdminError::invalid_request(error.to_string()))?;
                let replacement_node_id = NodeId::parse(&replacement_node_id)
                    .map_err(|error| AdminError::invalid_request(error.to_string()))?;
                let node_address = synergy_protocol_types::NodeAddress::parse(&node_address)
                    .map_err(|error| AdminError::invalid_request(error.to_string()))?;
                Self::prepared_native_action(
                    "naming",
                    "rename",
                    json!({
                        "current_node_id": current_node_id,
                        "replacement_node_id": replacement_node_id,
                        "node_address": node_address,
                        "nonce": nonce,
                    }),
                )
            }
        }
    }

    fn handle_rewards(&self, operation: RewardOperation) -> Result<serde_json::Value, AdminError> {
        let rewards: RewardLedgerSnapshot = self.protocol_state(REWARD_STATE_KEY)?;
        match operation {
            RewardOperation::InspectAccount { node_address } => {
                let node_address = synergy_protocol_types::NodeAddress::parse(&node_address)
                    .map_err(|error| AdminError::invalid_request(error.to_string()))?;
                Ok(json!({
                    "node_address": node_address,
                    "account": rewards.account(&node_address),
                    "authoritative_state": "finalized_world_state",
                }))
            }
            RewardOperation::InspectWithdrawal { withdrawal_id } => Ok(json!({
                "withdrawal_id": withdrawal_id,
                "withdrawal": rewards.withdrawal(&withdrawal_id),
                "authoritative_state": "finalized_world_state",
            })),
            RewardOperation::PrepareWithdrawal {
                withdrawal_id,
                node_address,
                destination_wallet,
                amount_nwei,
                nonce,
            } => {
                let node_address = synergy_protocol_types::NodeAddress::parse(&node_address)
                    .map_err(|error| AdminError::invalid_request(error.to_string()))?;
                if synergy_address::address_kind(&destination_wallet)
                    != synergy_address::AddressKind::Wallet
                {
                    return Err(AdminError::invalid_request("invalid destination wallet"));
                }
                Self::prepared_native_action(
                    "rewards",
                    "withdraw",
                    json!({
                        "withdrawal_id": withdrawal_id,
                        "node_address": node_address,
                        "destination_wallet": destination_wallet,
                        "amount_nwei": amount_nwei,
                        "nonce": nonce,
                    }),
                )
            }
        }
    }

    fn handle_validator(
        &self,
        operation: ValidatorOperation,
        idempotency_key: Option<&str>,
    ) -> Result<serde_json::Value, AdminError> {
        if let ValidatorOperation::Inspect { node_address } = operation {
            let manager = self.validator_management.lock().map_err(|_| {
                AdminError::unavailable("validator management state lock is poisoned")
            })?;
            return manager
                .record(node_address.as_str())
                .map(|record| json!({ "validator": record }))
                .ok_or_else(|| AdminError::invalid_request("validator is not managed"));
        }

        let idempotency_key = idempotency_key.ok_or_else(|| {
            AdminError::invalid_request("validator operation requires an idempotency key")
        })?;
        let authority = self.authority.as_ref().ok_or_else(|| {
            AdminError::unavailable(
                "validator lifecycle operation requires verified frozen PoSy authority",
            )
        })?;
        let current_epoch = authority.registry.epoch();
        let command = match operation {
            ValidatorOperation::Onboard {
                node_address,
                consensus_key_id,
                operator_identity,
                target_epoch,
                authorization_root,
                required_shadow_blocks,
            } => ValidatorManagementCommand::Onboard {
                current_epoch,
                application: ValidatorApplication {
                    validator_id: node_address.to_string(),
                    consensus_key_id,
                    operator_identity,
                    target_epoch,
                    authorization_root,
                },
                required_shadow_blocks,
            },
            ValidatorOperation::Authorize { node_address } => {
                ValidatorManagementCommand::Authorize {
                    validator_id: node_address.to_string(),
                }
            }
            ValidatorOperation::BeginSynchronization { node_address } => {
                ValidatorManagementCommand::BeginSynchronization {
                    validator_id: node_address.to_string(),
                }
            }
            ValidatorOperation::EnterShadow {
                node_address,
                change_set_root,
                frozen_voting_weight,
            } => ValidatorManagementCommand::EnterShadow {
                validator_id: node_address.to_string(),
                authority: self.membership_authority(change_set_root)?,
                frozen_voting_weight,
            },
            ValidatorOperation::RecordShadowProgress {
                node_address,
                verified_blocks,
            } => ValidatorManagementCommand::RecordShadowProgress {
                validator_id: node_address.to_string(),
                verified_blocks,
            },
            ValidatorOperation::MarkReady { node_address } => {
                ValidatorManagementCommand::MarkReady {
                    validator_id: node_address.to_string(),
                }
            }
            ValidatorOperation::RequestActivation {
                node_address,
                change_set_root,
            } => ValidatorManagementCommand::ScheduleActivation {
                validator_id: node_address.to_string(),
                authority: self.membership_authority(change_set_root)?,
            },
            ValidatorOperation::ConfirmFrozenAuthority { node_address } => {
                ValidatorManagementCommand::ConfirmFrozenAuthority {
                    validator_id: node_address.to_string(),
                }
            }
            ValidatorOperation::ScheduleJailing {
                node_address,
                evidence_root,
                effective_epoch,
                release_epoch,
                authorization_root,
            } => ValidatorManagementCommand::ScheduleJailing {
                validator_id: node_address.to_string(),
                evidence_root,
                current_epoch,
                effective_epoch,
                release_epoch,
                authorization_root,
            },
            ValidatorOperation::ScheduleDeactivation {
                node_address,
                effective_epoch,
                authorization_root,
            } => ValidatorManagementCommand::ScheduleDeactivation {
                validator_id: node_address.to_string(),
                current_epoch,
                effective_epoch,
                authorization_root,
            },
            ValidatorOperation::ScheduleExpulsion {
                node_address,
                evidence_root,
                effective_epoch,
                authorization_root,
            } => ValidatorManagementCommand::ScheduleExpulsion {
                validator_id: node_address.to_string(),
                evidence_root,
                current_epoch,
                effective_epoch,
                authorization_root,
            },
            ValidatorOperation::ScheduleSlashing {
                node_address,
                evidence_root,
                penalty_units,
                effective_epoch,
                authorization_root,
            } => ValidatorManagementCommand::ScheduleSlashing {
                validator_id: node_address.to_string(),
                evidence_root,
                penalty_units,
                current_epoch,
                effective_epoch,
                authorization_root,
            },
            ValidatorOperation::Inspect { .. } => {
                return Err(AdminError::invalid_request(
                    "validator inspection reached mutating dispatch",
                ))
            }
        };

        let result = self
            .validator_management
            .lock()
            .map_err(|_| AdminError::unavailable("validator management state lock is poisoned"))?
            .execute(idempotency_key, command, Some(&authority.registry))
            .map_err(AdminError::conflict)?;
        Ok(json!({
            "receipt": result.receipt,
            "replayed": result.replayed,
            "active_authority_source": "frozen_posy_registry",
            "role_grants_validator_authority": false,
        }))
    }

    fn membership_authority(
        &self,
        change_set_root: String,
    ) -> Result<MembershipAuthority, AdminError> {
        let authority = self.authority.as_ref().ok_or_else(|| {
            AdminError::unavailable("verified frozen PoSy authority is unavailable")
        })?;
        let finalized = self
            .ingress
            .latest_finality()
            .map_err(AdminError::unavailable)?
            .ok_or_else(|| {
                AdminError::unavailable(
                    "finalized epoch-closing record is unavailable for membership authority",
                )
            })?;
        let target_epoch = authority
            .epoch
            .epoch
            .checked_add(1)
            .ok_or_else(|| AdminError::invalid_request("membership target epoch overflow"))?;
        let membership = MembershipAuthority {
            previous_epoch: authority.epoch.epoch,
            previous_epoch_context_root: authority
                .epoch
                .root()
                .map_err(|error| AdminError::invalid_request(error.to_string()))?,
            finalized_height: finalized.height,
            finality_certificate_id: finalized.finality_certificate_id.clone(),
            target_epoch,
            change_set_root,
        };
        membership
            .validate(&authority.epoch, &finalized)
            .map_err(|error| AdminError::invalid_request(error.to_string()))?;
        Ok(membership)
    }
}

fn canonical_peer_id(peer_id: String) -> Result<String, AdminError> {
    synergy_protocol_types::NodeAddress::parse(peer_id)
        .map(|address| address.to_string())
        .map_err(|error| {
            AdminError::invalid_request(format!("invalid canonical peer NodeAddress: {error}"))
        })
}

fn read_bounded_update_file(
    path: &Path,
    maximum_bytes: u64,
    label: &str,
) -> Result<Vec<u8>, AdminError> {
    let metadata = std::fs::symlink_metadata(path).map_err(|error| {
        AdminError::invalid_request(format!("inspect {label} {}: {error}", path.display()))
    })?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() == 0
        || metadata.len() > maximum_bytes
    {
        return Err(AdminError::invalid_request(format!(
            "{label} must be a bounded regular non-symlink file"
        )));
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    File::open(path)
        .and_then(|file| file.take(maximum_bytes + 1).read_to_end(&mut bytes))
        .map_err(|error| {
            AdminError::invalid_request(format!("read {label} {}: {error}", path.display()))
        })?;
    if bytes.is_empty() || bytes.len() as u64 > maximum_bytes {
        return Err(AdminError::invalid_request(format!(
            "{label} changed size while loading"
        )));
    }
    Ok(bytes)
}

struct AdminApiService {
    socket_path: std::path::PathBuf,
    runtime: RuntimeView,
    configuration: NodeConfiguration,
    authority: Option<Arc<VerifiedAuthority>>,
    ingress: AuthenticatedIngress,
    validator_management: Arc<Mutex<PersistentValidatorManagement<AtomicValidatorManagementStore>>>,
    audit: Arc<Mutex<AtomicAdminAuditLog>>,
    authorization: AuthorizationContext,
    #[cfg(unix)]
    server: Option<LocalAdminServer>,
    failure: Option<String>,
}

impl ManagedService for AdminApiService {
    fn start(&mut self, cancellation: &CancellationToken) -> Result<(), String> {
        if cancellation.is_cancelled() {
            return Err("Admin API service start was cancelled".into());
        }
        #[cfg(unix)]
        {
            let server = LocalAdminServer::start(
                &self.socket_path,
                Arc::new(RuntimeAdminService {
                    runtime: Arc::clone(&self.runtime),
                    configuration: self.configuration.clone(),
                    authority: self.authority.clone(),
                    ingress: self.ingress.clone(),
                    validator_management: Arc::clone(&self.validator_management),
                    audit: Arc::clone(&self.audit),
                    cancellation: cancellation.clone(),
                    authorization: self.authorization.clone(),
                }),
            )
            .map_err(|error| format!("start owner-local Admin API: {}", error.message))?;
            self.server = Some(server);
            self.failure = None;
            Ok(())
        }
        #[cfg(not(unix))]
        {
            let _ = &self.socket_path;
            self.failure = Some("owner-local Admin API requires Unix-domain sockets".into());
            Err("owner-local Admin API requires Unix-domain sockets".into())
        }
    }

    fn stop(&mut self) -> Result<(), String> {
        #[cfg(unix)]
        {
            self.server = None;
        }
        Ok(())
    }

    fn health(&self) -> ServiceHealth {
        if let Some(reason) = &self.failure {
            return ServiceHealth::Unhealthy {
                reason: reason.clone(),
            };
        }
        #[cfg(unix)]
        if self.server.is_some() && self.socket_path.exists() {
            return ServiceHealth::Healthy;
        }
        ServiceHealth::Unhealthy {
            reason: "owner-local Admin API socket is not available".into(),
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
