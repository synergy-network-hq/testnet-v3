use std::collections::BTreeSet;
use std::path::Path;
use std::sync::{Arc, Mutex};

use serde_json::json;
use synergy_admin_api::authorization::{AdminPermission, AuthorizationContext};
use synergy_admin_api::operations::{
    AdminOperation, NamingOperation, OwnershipOperation, RewardOperation, ValidatorOperation,
};
use synergy_admin_api::{AdminError, AdminRequest, AdminResponse, AdminService};
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
use synergy_validator_management::{
    PersistentValidatorManagement, ValidatorApplication, ValidatorManagementCommand,
    ValidatorManagementStore,
};

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
    if let Some(authority) = authority.as_ref() {
        validator_management.reconcile_frozen_authority(&authority.registry)?;
    }
    let permissions = BTreeSet::from([AdminPermission::Read, AdminPermission::Validator]);

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

struct RuntimeAdminService {
    runtime: RuntimeView,
    configuration: NodeConfiguration,
    authority: Option<Arc<VerifiedAuthority>>,
    ingress: AuthenticatedIngress,
    validator_management: Arc<Mutex<PersistentValidatorManagement<AtomicValidatorManagementStore>>>,
    authorization: AuthorizationContext,
}

impl AdminService for RuntimeAdminService {
    fn handle(&self, request: AdminRequest) -> AdminResponse {
        if let Err(error) = request.validate() {
            return AdminResponse::failure(request.request_id, error);
        }
        if let Err(error) = self
            .authorization
            .require(request.operation.required_permission())
        {
            return AdminResponse::failure(request.request_id, error);
        }

        let request_id = request.request_id;
        let result = match request.operation {
            AdminOperation::Read(operation) => self.handle_read(operation),
            AdminOperation::Validator(operation) => {
                self.handle_validator(operation, request.idempotency_key.as_deref())
            }
            AdminOperation::Ownership(operation) => self.handle_ownership(operation),
            AdminOperation::Naming(operation) => self.handle_naming(operation),
            AdminOperation::Rewards(operation) => self.handle_rewards(operation),
            _ => Err(AdminError::unavailable(
                "Admin operation has no canonical runtime owner wired",
            )),
        };
        match result {
            Ok(value) => AdminResponse::success(request_id, value),
            Err(error) => AdminResponse::failure(request_id, error),
        }
    }
}

impl RuntimeAdminService {
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
                ValidatorManagementCommand::Authorize { validator_id: node_address.to_string() }
            }
            ValidatorOperation::BeginSynchronization { node_address } => {
                ValidatorManagementCommand::BeginSynchronization { validator_id: node_address.to_string() }
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
                ValidatorManagementCommand::MarkReady { validator_id: node_address.to_string() }
            }
            ValidatorOperation::RequestActivation {
                node_address,
                change_set_root,
            } => ValidatorManagementCommand::ScheduleActivation {
                validator_id: node_address.to_string(),
                authority: self.membership_authority(change_set_root)?,
            },
            ValidatorOperation::ConfirmFrozenAuthority { node_address } => {
                ValidatorManagementCommand::ConfirmFrozenAuthority { validator_id: node_address.to_string() }
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

struct AdminApiService {
    socket_path: std::path::PathBuf,
    runtime: RuntimeView,
    configuration: NodeConfiguration,
    authority: Option<Arc<VerifiedAuthority>>,
    ingress: AuthenticatedIngress,
    validator_management: Arc<Mutex<PersistentValidatorManagement<AtomicValidatorManagementStore>>>,
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
                    authorization: self.authorization.clone(),
                }),
            )
            .map_err(|error| format!("start owner-local Admin API: {}", error.message))?;
            self.server = Some(server);
            self.failure = None;
            return Ok(());
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
