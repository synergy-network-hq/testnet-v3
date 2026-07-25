use crate::agent::{
    self, agent_get_inventory_machines, agent_monitor_initialize_workspace_from_context,
    agent_prepare_hosts_env_from_context, JarvisPrepareHostsEnvInput,
};
use crate::app_context::AppContext;
use crate::event_bus::EventBus;
use crate::innernet;
use crate::monitor::{
    get_monitor_agent_snapshot, get_monitor_inventory_path, get_monitor_node_details,
    get_monitor_security_state, get_monitor_snapshot, get_monitor_user_manual_markdown,
    get_monitor_workspace_path, monitor_apply_testnet_topology_from_context,
    monitor_assign_ssh_binding, monitor_bulk_node_control, monitor_delete_operator,
    monitor_delete_ssh_profile, monitor_detect_local_machine_identity,
    monitor_ensure_ssh_keypair_from_context, monitor_export_node_data, monitor_get_setup_status,
    monitor_initialize_workspace_from_context, monitor_mark_setup_complete, monitor_node_control,
    monitor_remove_ssh_binding, monitor_run_terminal_command, monitor_set_active_operator,
    monitor_update_local_agent_from_context, monitor_upsert_operator, monitor_upsert_ssh_profile,
    MonitorOperatorInput, MonitorSshBindingInput, MonitorSshProfileInput,
};
use crate::testnet::{
    testnet_activate_validator, testnet_align_validator_vpn_config,
    testnet_apply_atlas_validator_profile, testnet_apply_log_retention,
    testnet_apply_validator_snapshot, testnet_apply_validator_vpn_snapshot, testnet_backup_keys,
    testnet_boost_sync, testnet_clear_cache, testnet_create_snapshot,
    testnet_diagnose_onboarding_sync, testnet_discover_validator_snapshot,
    testnet_download_validator_snapshot, testnet_encrypt_validator_keys,
    testnet_enroll_validator_vpn, testnet_erase_local_machine_data, testnet_export_config,
    testnet_force_peer_connect, testnet_get_catalog, testnet_get_chain_blocks,
    testnet_get_device_profile, testnet_get_feature_snapshot, testnet_get_live_status,
    testnet_get_node_logs, testnet_get_node_readiness, testnet_get_rewards_data, testnet_get_state,
    testnet_get_validator_activation_preflight, testnet_get_validator_live_status,
    testnet_import_config, testnet_mark_setup_sync_complete, testnet_node_control,
    testnet_publish_validator_profile_to_atlas, testnet_record_innernet_enrollment,
    testnet_record_validator_funding, testnet_recover_local_fork, testnet_remove_node,
    testnet_rename_node, testnet_request_validator_rejoin, testnet_reset_innernet_client_state,
    testnet_restore_backup, testnet_restore_validator_snapshot, testnet_reuse_innernet_enrollment,
    testnet_run_register_with_seeds, testnet_run_validator_onboarding, testnet_set_validator_owner,
    testnet_setup_node, testnet_stake_validator, testnet_start_validator_normal_sync,
    testnet_sync_catch_up_rejoin, testnet_transfer_validator_tokens, testnet_unstake_validator,
    testnet_validate_path, testnet_validator_vpn_status, testnet_verify_backup,
    testnet_verify_validator_eligibility, testnet_verify_validator_snapshot,
    TestnetApplyAtlasValidatorProfileInput, TestnetEraseNodeDataInput, TestnetFeatureSnapshotInput,
    TestnetFilesystemTargetInput, TestnetForcePeerConnectInput, TestnetInnernetEnrollmentInput,
    TestnetKeyEncryptionInput, TestnetLogRetentionInput, TestnetNodeControlInput,
    TestnetPathValidationInput, TestnetPublishValidatorProfileInput, TestnetRemoveNodeInput,
    TestnetRenameNodeInput, TestnetSetValidatorOwnerInput, TestnetSetupInput,
    TestnetSetupSyncCompleteInput, TestnetSnapshotRestoreInput, TestnetValidatorActivateInput,
    TestnetValidatorCatchUpInput, TestnetValidatorEligibilityInput, TestnetValidatorFundingInput,
    TestnetValidatorOnboardingInput, TestnetValidatorRejoinRequestInput,
    TestnetValidatorSnapshotApplyInput, TestnetValidatorSnapshotDownloadInput,
    TestnetValidatorSnapshotVerifyInput, TestnetValidatorStakeInput, TestnetValidatorTransferInput,
    TestnetValidatorUnstakeInput, TestnetValidatorVpnInput,
};
use crate::validator_vpn::{
    consume_reserved_validator_vpn_onboarding_token, create_validator_vpn_challenge,
    enroll_validator_vpn_node, get_latest_validator_vpn_snapshot,
    import_validator_vpn_bootstrap_nodes, issue_validator_vpn_onboarding_token,
    record_validator_vpn_heartbeat, register_validator_vpn_relayer,
    reserve_validator_vpn_onboarding, validator_vpn_agent_plan, validator_vpn_status,
    ValidatorVpnBootstrapImportRequest, ValidatorVpnChallengeRequest, ValidatorVpnEnrollRequest,
    ValidatorVpnHeartbeatRequest, ValidatorVpnRelayerRegistrationRequest, ValidatorVpnRole,
};
use async_stream::stream;
use axum::extract::{Query, State};
use axum::http::{header, HeaderMap, Method, StatusCode};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::Digest;
use std::collections::HashMap;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::{Duration as StdDuration, Instant};
use tower_http::cors::{Any, CorsLayer};

#[derive(Clone)]
struct ControlServiceState {
    token: Arc<String>,
    app_context: AppContext,
    event_bus: EventBus,
    invite_rate_limiter: Arc<Mutex<InviteRateLimiter>>,
    bootstrap_invite_lock: Arc<Mutex<()>>,
}

#[derive(Default)]
struct InviteRateLimiter {
    by_ip: HashMap<String, Vec<Instant>>,
    by_token: HashMap<String, Vec<Instant>>,
}

#[derive(Debug, Serialize)]
struct ControlServiceHealth {
    status: String,
    version: String,
}

#[derive(Debug, Deserialize)]
struct InvokeRequest {
    command: String,
    #[serde(default)]
    args: Value,
}

#[derive(Debug, Deserialize)]
struct EventQuery {
    token: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ValidatorLiveStatusQuery {
    #[serde(default)]
    token: Option<String>,
    #[serde(default, alias = "node_id")]
    node_id: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct OperatorIdArgs {
    operator_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ProfileIdArgs {
    profile_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct NodeSlotArgs {
    node_slot_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct NodeActionArgs {
    node_slot_id: String,
    action: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct BulkActionArgs {
    action: String,
    scope: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct TestnetEraseNodeDataArgs {
    target_os: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SetupCompleteArgs {
    physical_machine_id: String,
    node_slot_ids: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
struct UpsertOperatorArgs {
    input: MonitorOperatorInput,
}

#[derive(Debug, Deserialize)]
struct UpsertProfileArgs {
    input: MonitorSshProfileInput,
}

#[derive(Debug, Deserialize)]
struct AssignBindingArgs {
    input: MonitorSshBindingInput,
}

#[derive(Debug, Deserialize)]
struct PrepareHostsArgs {
    input: JarvisPrepareHostsEnvInput,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct TerminalCommandArgs {
    command: String,
    cwd: Option<String>,
}

#[derive(Debug, Deserialize)]
struct TestnetSetupArgs {
    input: TestnetSetupInput,
}

#[derive(Debug, Deserialize)]
struct TestnetSnapshotRestoreArgs {
    input: TestnetSnapshotRestoreInput,
}

#[derive(Debug, Deserialize)]
struct TestnetValidatorSnapshotDownloadArgs {
    input: TestnetValidatorSnapshotDownloadInput,
}

#[derive(Debug, Deserialize)]
struct TestnetValidatorSnapshotVerifyArgs {
    input: TestnetValidatorSnapshotVerifyInput,
}

#[derive(Debug, Deserialize)]
struct TestnetValidatorSnapshotApplyArgs {
    input: TestnetValidatorSnapshotApplyInput,
}

#[derive(Debug, Deserialize)]
struct TestnetNodeControlArgs {
    input: TestnetNodeControlInput,
}

#[derive(Debug, Deserialize)]
struct TestnetSetupSyncCompleteArgs {
    input: TestnetSetupSyncCompleteInput,
}

#[derive(Debug, Deserialize)]
struct TestnetRemoveNodeArgs {
    input: TestnetRemoveNodeInput,
}

#[derive(Debug, Deserialize)]
struct TestnetRenameNodeArgs {
    input: TestnetRenameNodeInput,
}

#[derive(Debug, Deserialize)]
struct TestnetSetValidatorOwnerArgs {
    input: TestnetSetValidatorOwnerInput,
}

#[derive(Debug, Deserialize)]
struct TestnetApplyAtlasValidatorProfileArgs {
    input: TestnetApplyAtlasValidatorProfileInput,
}

#[derive(Debug, Deserialize)]
struct TestnetPublishValidatorProfileArgs {
    input: TestnetPublishValidatorProfileInput,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct TestnetNodeLogsArgs {
    node_id: String,
    #[serde(default)]
    lines: Option<usize>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct TestnetFeatureSnapshotArgs {
    input: TestnetFeatureSnapshotInput,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct TestnetChainBlocksArgs {
    node_id: String,
    #[serde(default)]
    count: Option<u64>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct TestnetRegisterWithSeedsArgs {
    node_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct TestnetReadinessArgs {
    node_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct TestnetRewardsArgs {
    node_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct TestnetBoostSyncArgs {
    node_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct TestnetValidatorActivationPreflightArgs {
    node_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct TestnetValidatorLiveStatusArgs {
    #[serde(default)]
    node_id: Option<String>,
}

#[derive(Debug, Deserialize)]
struct TestnetValidatorStakeArgs {
    input: TestnetValidatorStakeInput,
}

#[derive(Debug, Deserialize)]
struct TestnetValidatorFundingArgs {
    input: TestnetValidatorFundingInput,
}

#[derive(Debug, Deserialize)]
struct TestnetValidatorUnstakeArgs {
    input: TestnetValidatorUnstakeInput,
}

#[derive(Debug, Deserialize)]
struct TestnetValidatorTransferArgs {
    input: TestnetValidatorTransferInput,
}

#[derive(Debug, Deserialize)]
struct TestnetValidatorActivateArgs {
    input: TestnetValidatorActivateInput,
}

#[derive(Debug, Deserialize)]
struct TestnetValidatorCatchUpArgs {
    input: TestnetValidatorCatchUpInput,
}

#[derive(Debug, Deserialize)]
struct TestnetValidatorVpnArgs {
    input: TestnetValidatorVpnInput,
}

#[derive(Debug, Deserialize)]
struct TestnetInnernetEnrollmentArgs {
    input: TestnetInnernetEnrollmentInput,
}

#[derive(Debug, Deserialize)]
struct TestnetValidatorOnboardingArgs {
    input: TestnetValidatorOnboardingInput,
}

#[derive(Debug, Deserialize)]
struct TestnetValidatorRejoinRequestArgs {
    input: TestnetValidatorRejoinRequestInput,
}

#[derive(Debug, Deserialize)]
struct TestnetForcePeerConnectArgs {
    input: TestnetForcePeerConnectInput,
}

#[derive(Debug, Deserialize)]
struct ValidatorVpnChallengeArgs {
    input: ValidatorVpnChallengeRequest,
}

#[derive(Debug, Deserialize)]
struct ValidatorVpnEnrollArgs {
    input: ValidatorVpnEnrollRequest,
}

#[derive(Debug, Deserialize)]
struct ValidatorVpnRelayerArgs {
    input: ValidatorVpnRelayerRegistrationRequest,
}

#[derive(Debug, Deserialize)]
struct ValidatorVpnBootstrapImportArgs {
    input: ValidatorVpnBootstrapImportRequest,
}

#[derive(Debug, Deserialize)]
struct ValidatorVpnHeartbeatArgs {
    input: ValidatorVpnHeartbeatRequest,
}

#[derive(Debug, Deserialize)]
struct InviteAuth {
    #[serde(rename = "type")]
    auth_type: String,
    token: String,
}

#[derive(Debug, Deserialize)]
struct InviteRequest {
    auth: InviteAuth,
    peer_name: String,
    peer_type: ValidatorVpnRole,
    #[serde(default)]
    node_id: Option<String>,
    #[serde(default)]
    validator_address: Option<String>,
    #[serde(default)]
    operator_address: Option<String>,
    #[serde(default)]
    stake_tx_hash: Option<String>,
}

#[derive(Debug, Serialize)]
struct InviteResponse {
    invite: Option<String>,
    resume_existing: bool,
    assigned_ip: String,
    interface_name: String,
    expires_at: String,
    enrollment_id: String,
    confirmation_token: String,
    configuration_version: u64,
}

#[derive(Debug, Deserialize)]
struct AdminInviteRequest {
    operator_email: String,
    #[serde(default)]
    peer_type: Option<ValidatorVpnRole>,
    expires_in_hours: u64,
}

#[derive(Debug, Serialize)]
struct AdminInviteResponse {
    token: String,
}

#[derive(Debug, Deserialize)]
struct BootstrapInnernetInviteRequest {
    peer_name: String,
}

#[derive(Debug, Deserialize)]
struct BootstrapInnernetStaleRecoveryRequest {
    peer_name: String,
    acknowledge_stale_unredeemed_handshake: bool,
}

#[derive(Debug, Deserialize)]
struct BootstrapInnernetConfirmationRecoveryRequest {
    peer_name: String,
    acknowledge_redeemed_membership: bool,
}

#[derive(Debug, Deserialize)]
struct InnernetTransportRefreshRequest {
    receipt: innernet::InnernetMembershipReceipt,
}

#[derive(Debug, Serialize)]
struct BootstrapInnernetInviteResponse {
    node_id: String,
    peer_name: String,
    peer_type: String,
    invite: String,
    assigned_ip: String,
    interface_name: String,
    expires_at: String,
    enrollment_id: String,
    confirmation_token: String,
    configuration_version: u64,
}

#[derive(Debug, Serialize)]
struct BootstrapInnernetConfirmationRecoveryResponse {
    node_id: String,
    peer_name: String,
    peer_type: String,
    assigned_ip: String,
    interface_name: String,
    enrollment_id: String,
    confirmation_token: String,
    configuration_version: u64,
}

pub async fn serve(port: u16, token: String, app_context: AppContext) -> Result<(), String> {
    let event_bus = EventBus::new(128);
    let state = ControlServiceState {
        token: Arc::new(token),
        app_context: app_context.clone(),
        event_bus: event_bus.clone(),
        invite_rate_limiter: Arc::new(Mutex::new(InviteRateLimiter::default())),
        bootstrap_invite_lock: Arc::new(Mutex::new(())),
    };

    match monitor_initialize_workspace_from_context(&app_context) {
        Ok(workspace) => {
            event_bus.emit_json(
                "service-startup",
                json!({ "status": "workspace-ready", "workspace": workspace }),
            );
        }
        Err(error) => {
            eprintln!("control-service workspace initialization warning: {error}");
        }
    }

    if local_agent_startup_enabled() {
        if let Err(error) = agent::ensure_local_testnet_agent_from_context(&app_context).await {
            eprintln!("control-service local agent startup warning: {error}");
        }
    }

    let router = Router::new()
        .route("/health", get(health_handler))
        .route("/validator/live-status", get(validator_live_status_handler))
        .route(
            "/v1/validator/live-status",
            get(validator_live_status_handler),
        )
        .route(
            "/events/validator/live-status",
            get(validator_live_status_events_handler),
        )
        .route("/v1/invoke", post(invoke_handler))
        .route("/v1/invite", post(invite_handler))
        .route("/v1/invite/admin", post(admin_invite_handler))
        .route(
            "/v1/migration/bootstrap/invite",
            post(bootstrap_innernet_invite_handler),
        )
        .route(
            "/v1/migration/bootstrap/reissue",
            post(bootstrap_innernet_reissue_handler),
        )
        .route(
            "/v1/migration/bootstrap/recover-stale",
            post(bootstrap_innernet_stale_recovery_handler),
        )
        .route(
            "/v1/migration/bootstrap/recover-confirmation",
            post(bootstrap_innernet_confirmation_recovery_handler),
        )
        .route(
            "/v1/migration/bootstrap/status",
            get(bootstrap_innernet_status_handler),
        )
        .route(
            "/v1/migration/bootstrap/transports",
            get(bootstrap_innernet_transport_snapshot_handler),
        )
        .route("/v1/mesh/confirm", post(innernet_confirm_handler))
        .route("/v1/mesh/status", get(mesh_status_handler))
        .route("/v1/mesh/transports", get(mesh_transport_snapshot_handler))
        .route(
            "/v1/mesh/transports/current",
            get(mesh_transport_snapshot_current_handler),
        )
        .route(
            "/v1/mesh/transports/refresh",
            post(mesh_transport_snapshot_refresh_handler),
        )
        .route("/v1/events/stream", get(events_handler))
        .route(
            "/v1/events/validator/live-status",
            get(validator_live_status_events_handler),
        )
        .route(
            "/api/validator-vpn/status",
            get(legacy_validator_vpn_retired_handler),
        )
        .route(
            "/api/validator-vpn/enrollment/challenge",
            post(legacy_validator_vpn_retired_handler),
        )
        .route(
            "/api/validator-vpn/enroll",
            post(legacy_validator_vpn_retired_handler),
        )
        .route(
            "/api/validator-vpn/snapshots/latest",
            get(legacy_validator_vpn_retired_handler),
        )
        .route(
            "/api/validator-vpn/snapshots/{generation}",
            get(legacy_validator_vpn_retired_handler),
        )
        .route(
            "/api/validator-vpn/nodes/{node_id}/heartbeat",
            post(legacy_validator_vpn_retired_handler),
        )
        .route(
            "/api/validator-vpn/nodes/{node_id}/health",
            post(legacy_validator_vpn_retired_handler),
        )
        .route(
            "/api/validator-vpn/nodes/{node_id}/config-ack",
            post(legacy_validator_vpn_retired_handler),
        )
        .route(
            "/api/validator-vpn/propagation/{generation}",
            get(legacy_validator_vpn_retired_handler),
        )
        .route(
            "/api/validator-vpn/relayers",
            post(legacy_validator_vpn_retired_handler),
        )
        .route(
            "/api/validator-vpn/bootstrap/import",
            post(legacy_validator_vpn_retired_handler),
        )
        .layer(
            CorsLayer::new()
                .allow_origin(Any)
                .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
                .allow_headers(Any),
        )
        .with_state(state);

    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .map_err(|error| format!("Failed to bind control-service on {addr}: {error}"))?;

    axum::serve(listener, router)
        .await
        .map_err(|error| format!("control-service server error: {error}"))
}

fn local_agent_startup_enabled() -> bool {
    !std::env::var("SYNERGY_CONTROL_SERVICE_DISABLE_LOCAL_AGENT")
        .map(|value| {
            matches!(
                value.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes"
            )
        })
        .unwrap_or(false)
}

async fn health_handler() -> impl IntoResponse {
    Json(ControlServiceHealth {
        status: "ok".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
    })
}

async fn mesh_status_handler(
    State(state): State<ControlServiceState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let Some(enrollment_id) = headers
        .get("X-Synergy-Innernet-Enrollment")
        .and_then(|value| value.to_str().ok())
    else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let Some(confirmation_token) = headers
        .get("X-Synergy-Innernet-Token")
        .and_then(|value| value.to_str().ok())
    else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    if innernet::authorize_enrollment_status(&state.app_context, enrollment_id, confirmation_token)
        .is_err()
    {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    match innernet::mesh_status(&state.app_context) {
        Ok(payload) => (StatusCode::OK, Json(payload)).into_response(),
        Err(error) => validator_vpn_error(error),
    }
}

async fn mesh_transport_snapshot_handler(
    State(state): State<ControlServiceState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let Some(enrollment_id) = headers
        .get("X-Synergy-Innernet-Enrollment")
        .and_then(|value| value.to_str().ok())
    else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let Some(confirmation_token) = headers
        .get("X-Synergy-Innernet-Token")
        .and_then(|value| value.to_str().ok())
    else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    if innernet::authorize_enrollment_status(&state.app_context, enrollment_id, confirmation_token)
        .is_err()
    {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    match innernet::validator_transport_snapshot(&state.app_context) {
        Ok(payload) => (StatusCode::OK, Json(payload)).into_response(),
        Err(error) => validator_vpn_error(error),
    }
}

/// Public read-only transport discovery endpoint. The payload is safe to
/// publish because `validator_transport_snapshot` signs it with the
/// coordinator key; callers must verify that signature against their pinned
/// Ed25519 public key.
async fn mesh_transport_snapshot_current_handler(
    State(state): State<ControlServiceState>,
) -> impl IntoResponse {
    match innernet::validator_transport_snapshot(&state.app_context) {
        Ok(payload) => (StatusCode::OK, Json(payload)).into_response(),
        Err(_) => StatusCode::SERVICE_UNAVAILABLE.into_response(),
    }
}

async fn mesh_transport_snapshot_refresh_handler(
    State(state): State<ControlServiceState>,
    Json(input): Json<InnernetTransportRefreshRequest>,
) -> impl IntoResponse {
    if innernet::authorize_membership_receipt(&state.app_context, &input.receipt).is_err() {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    match innernet::validator_transport_snapshot(&state.app_context) {
        Ok(payload) => (StatusCode::OK, Json(payload)).into_response(),
        Err(error) => validator_vpn_error(error),
    }
}

async fn admin_invite_handler(
    State(state): State<ControlServiceState>,
    headers: HeaderMap,
    Json(input): Json<AdminInviteRequest>,
) -> impl IntoResponse {
    let Some(admin_key) = headers
        .get("X-Admin-Key")
        .and_then(|value| value.to_str().ok())
    else {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "unauthorized" })),
        )
            .into_response();
    };
    if admin_key != state.token.as_str() {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "unauthorized" })),
        )
            .into_response();
    }
    if input.operator_email.trim().is_empty() {
        return validator_vpn_error("operator_email is required".to_string());
    }
    let expires_in_hours = input.expires_in_hours.clamp(1, 720);
    let role = input.peer_type.unwrap_or(ValidatorVpnRole::Validator);
    match issue_validator_vpn_onboarding_token(
        &state.app_context,
        Some(input.operator_email),
        role,
        chrono::Utc::now() + chrono::Duration::hours(expires_in_hours as i64),
    ) {
        Ok(token) => (StatusCode::OK, Json(AdminInviteResponse { token })).into_response(),
        Err(error) => validator_vpn_error(error),
    }
}

async fn bootstrap_innernet_invite_handler(
    State(state): State<ControlServiceState>,
    headers: HeaderMap,
    Json(input): Json<BootstrapInnernetInviteRequest>,
) -> impl IntoResponse {
    let Some(admin_key) = headers
        .get("X-Admin-Key")
        .and_then(|value| value.to_str().ok())
    else {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "unauthorized" })),
        )
            .into_response();
    };
    if admin_key != state.token.as_str() {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "unauthorized" })),
        )
            .into_response();
    }
    let _bootstrap_invite_guard = match state.bootstrap_invite_lock.lock() {
        Ok(guard) => guard,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "coordinator_state_lock_failed" })),
            )
                .into_response()
        }
    };
    if innernet::migration_cutover_enabled() {
        return (
            StatusCode::CONFLICT,
            Json(json!({ "error": "innernet_migration_already_cutover" })),
        )
            .into_response();
    }
    if let Err(error) = innernet::require_coordinator_ready() {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({ "error": "innernet_unavailable", "detail": error })),
        )
            .into_response();
    }

    let assignment = match innernet::admin_bootstrap_assignment(input.peer_name.trim()) {
        Ok(assignment) => assignment,
        Err(error) => return validator_vpn_error(error),
    };
    let node_id = format!("bootstrap-{}", assignment.peer_name);
    if let Err(error) =
        innernet::ensure_bootstrap_enrollment_available(&state.app_context, &node_id)
    {
        return (
            StatusCode::CONFLICT,
            Json(json!({ "error": "bootstrap_invitation_unavailable", "detail": error })),
        )
            .into_response();
    }
    let invite = match innernet::generate_invite(
        &assignment.peer_name,
        &assignment.peer_type,
        &assignment.assigned_ip,
    ) {
        Ok(invite) => invite,
        Err(error) => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({ "error": "innernet_unavailable", "detail": error })),
            )
                .into_response()
        }
    };
    let enrollment = match innernet::create_bootstrap_enrollment(
        &state.app_context,
        &node_id,
        &node_id,
        &assignment.peer_name,
        &assignment.peer_type,
        &invite.assigned_ip,
        &invite.interface_name,
        &invite.expires_at,
    ) {
        Ok(enrollment) => enrollment,
        Err(error) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "coordinator_state_commit_failed", "detail": error })),
            )
                .into_response()
        }
    };
    (
        StatusCode::OK,
        Json(BootstrapInnernetInviteResponse {
            node_id,
            peer_name: assignment.peer_name,
            peer_type: assignment.peer_type,
            invite: invite.invite,
            assigned_ip: invite.assigned_ip,
            interface_name: invite.interface_name,
            expires_at: invite.expires_at,
            enrollment_id: enrollment.enrollment_id,
            confirmation_token: enrollment.confirmation_token,
            configuration_version: enrollment.configuration_version,
        }),
    )
        .into_response()
}

async fn bootstrap_innernet_status_handler(
    State(state): State<ControlServiceState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let Some(admin_key) = headers
        .get("X-Admin-Key")
        .and_then(|value| value.to_str().ok())
    else {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "unauthorized" })),
        )
            .into_response();
    };
    if admin_key != state.token.as_str() {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "unauthorized" })),
        )
            .into_response();
    }
    match innernet::mesh_status(&state.app_context) {
        Ok(payload) => (StatusCode::OK, Json(payload)).into_response(),
        Err(error) => validator_vpn_error(error),
    }
}

/// Operator-only inspection endpoint for the signed transport document. This
/// intentionally does not require a consumed per-enrollment confirmation token.
async fn bootstrap_innernet_transport_snapshot_handler(
    State(state): State<ControlServiceState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let Some(admin_key) = headers
        .get("X-Admin-Key")
        .and_then(|value| value.to_str().ok())
    else {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "unauthorized" })),
        )
            .into_response();
    };
    if admin_key != state.token.as_str() {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "unauthorized" })),
        )
            .into_response();
    }
    match innernet::validator_transport_snapshot(&state.app_context) {
        Ok(payload) => (StatusCode::OK, Json(payload)).into_response(),
        Err(error) => validator_vpn_error(error),
    }
}

async fn bootstrap_innernet_reissue_handler(
    State(state): State<ControlServiceState>,
    headers: HeaderMap,
    Json(input): Json<BootstrapInnernetInviteRequest>,
) -> impl IntoResponse {
    let Some(admin_key) = headers
        .get("X-Admin-Key")
        .and_then(|value| value.to_str().ok())
    else {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "unauthorized" })),
        )
            .into_response();
    };
    if admin_key != state.token.as_str() {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "unauthorized" })),
        )
            .into_response();
    }
    let _bootstrap_invite_guard = match state.bootstrap_invite_lock.lock() {
        Ok(guard) => guard,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "coordinator_state_lock_failed" })),
            )
                .into_response()
        }
    };
    if innernet::migration_cutover_enabled() {
        return (
            StatusCode::CONFLICT,
            Json(json!({ "error": "innernet_migration_already_cutover" })),
        )
            .into_response();
    }
    if let Err(error) = innernet::require_coordinator_ready() {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({ "error": "innernet_unavailable", "detail": error })),
        )
            .into_response();
    }
    let (assignment, invite, enrollment) = match innernet::reissue_unredeemed_bootstrap_invite(
        &state.app_context,
        input.peer_name.trim(),
    ) {
        Ok(result) => result,
        Err(error) => {
            return (
                StatusCode::CONFLICT,
                Json(json!({ "error": "bootstrap_reissue_unavailable", "detail": error })),
            )
                .into_response()
        }
    };
    let node_id = format!("bootstrap-{}", assignment.peer_name);
    (
        StatusCode::OK,
        Json(BootstrapInnernetInviteResponse {
            node_id,
            peer_name: assignment.peer_name,
            peer_type: assignment.peer_type,
            invite: invite.invite,
            assigned_ip: invite.assigned_ip,
            interface_name: invite.interface_name,
            expires_at: invite.expires_at,
            enrollment_id: enrollment.enrollment_id,
            confirmation_token: enrollment.confirmation_token,
            configuration_version: enrollment.configuration_version,
        }),
    )
        .into_response()
}

async fn bootstrap_innernet_stale_recovery_handler(
    State(state): State<ControlServiceState>,
    headers: HeaderMap,
    Json(input): Json<BootstrapInnernetStaleRecoveryRequest>,
) -> impl IntoResponse {
    let Some(admin_key) = headers
        .get("X-Admin-Key")
        .and_then(|value| value.to_str().ok())
    else {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "unauthorized" })),
        )
            .into_response();
    };
    if admin_key != state.token.as_str() {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "unauthorized" })),
        )
            .into_response();
    }
    if !input.acknowledge_stale_unredeemed_handshake {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "stale_unredeemed_handshake_acknowledgement_required" })),
        )
            .into_response();
    }
    let _bootstrap_invite_guard = match state.bootstrap_invite_lock.lock() {
        Ok(guard) => guard,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "coordinator_state_lock_failed" })),
            )
                .into_response()
        }
    };
    if innernet::migration_cutover_enabled() {
        return (
            StatusCode::CONFLICT,
            Json(json!({ "error": "innernet_migration_already_cutover" })),
        )
            .into_response();
    }
    if let Err(error) = innernet::require_coordinator_ready() {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({ "error": "innernet_unavailable", "detail": error })),
        )
            .into_response();
    }
    let (assignment, invite, enrollment) = match innernet::recover_stale_unredeemed_bootstrap_invite(
        &state.app_context,
        input.peer_name.trim(),
    ) {
        Ok(result) => result,
        Err(error) => {
            return (
                StatusCode::CONFLICT,
                Json(json!({ "error": "bootstrap_stale_recovery_unavailable", "detail": error })),
            )
                .into_response()
        }
    };
    let node_id = format!("bootstrap-{}", assignment.peer_name);
    (
        StatusCode::OK,
        Json(BootstrapInnernetInviteResponse {
            node_id,
            peer_name: assignment.peer_name,
            peer_type: assignment.peer_type,
            invite: invite.invite,
            assigned_ip: invite.assigned_ip,
            interface_name: invite.interface_name,
            expires_at: invite.expires_at,
            enrollment_id: enrollment.enrollment_id,
            confirmation_token: enrollment.confirmation_token,
            configuration_version: enrollment.configuration_version,
        }),
    )
        .into_response()
}

async fn bootstrap_innernet_confirmation_recovery_handler(
    State(state): State<ControlServiceState>,
    headers: HeaderMap,
    Json(input): Json<BootstrapInnernetConfirmationRecoveryRequest>,
) -> impl IntoResponse {
    let Some(admin_key) = headers
        .get("X-Admin-Key")
        .and_then(|value| value.to_str().ok())
    else {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "unauthorized" })),
        )
            .into_response();
    };
    if admin_key != state.token.as_str() {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "unauthorized" })),
        )
            .into_response();
    }
    if !input.acknowledge_redeemed_membership {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "redeemed_membership_acknowledgement_required" })),
        )
            .into_response();
    }
    let _bootstrap_invite_guard = match state.bootstrap_invite_lock.lock() {
        Ok(guard) => guard,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "coordinator_state_lock_failed" })),
            )
                .into_response()
        }
    };
    if innernet::migration_cutover_enabled() {
        return (
            StatusCode::CONFLICT,
            Json(json!({ "error": "innernet_migration_already_cutover" })),
        )
            .into_response();
    }
    if let Err(error) = innernet::require_coordinator_ready() {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({ "error": "innernet_unavailable", "detail": error })),
        )
            .into_response();
    }
    let (assignment, enrollment, interface_name, assigned_ip) =
        match innernet::recover_redeemed_bootstrap_confirmation(
            &state.app_context,
            input.peer_name.trim(),
        ) {
            Ok(result) => result,
            Err(error) => {
                return (
                    StatusCode::CONFLICT,
                    Json(json!({ "error": "bootstrap_confirmation_recovery_unavailable", "detail": error })),
                )
                    .into_response()
            }
        };
    let node_id = format!("bootstrap-{}", assignment.peer_name);
    (
        StatusCode::OK,
        Json(BootstrapInnernetConfirmationRecoveryResponse {
            node_id,
            peer_name: assignment.peer_name,
            peer_type: assignment.peer_type,
            assigned_ip,
            interface_name,
            enrollment_id: enrollment.enrollment_id,
            confirmation_token: enrollment.confirmation_token,
            configuration_version: enrollment.configuration_version,
        }),
    )
        .into_response()
}

async fn invite_handler(
    State(state): State<ControlServiceState>,
    headers: HeaderMap,
    Json(input): Json<InviteRequest>,
) -> impl IntoResponse {
    if input.auth.auth_type != "onboarding_token" {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "invalid_or_used_token" })),
        )
            .into_response();
    }
    let source = invite_source(&headers);
    if !allow_invite_request(&state.invite_rate_limiter, &source, &input.auth.token) {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(json!({ "error": "rate_limited" })),
        )
            .into_response();
    }
    if let Err(error) = innernet::require_migration_ready(&state.app_context) {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({ "error": "innernet_migration_not_ready", "detail": error })),
        )
            .into_response();
    }
    let node_id = match input
        .node_id
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        Some(node_id) => node_id,
        None => {
            return validator_vpn_error(
                "Innernet enrollment requires the provisioned validator node id.".to_string(),
            )
        }
    };
    if let Err(error) = verify_public_innernet_enrollment(&input).await {
        return validator_vpn_error(error);
    }
    let assignment = match reserve_validator_vpn_onboarding(
        &state.app_context,
        &input.auth.token,
        &input.peer_name,
        input.peer_type.clone(),
    ) {
        Ok(assignment) => assignment,
        Err(error) if error == "invalid_or_used_token" => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({ "error": "invalid_or_used_token" })),
            )
                .into_response();
        }
        Err(error) => return validator_vpn_error(error),
    };
    match innernet::recover_redeemed_enrollment_confirmation(
        &state.app_context,
        node_id,
        &assignment.node_id,
        &input.peer_name,
        input.peer_type.as_str(),
        input.validator_address.as_deref(),
        &assignment.vpn_ip,
        &assignment.expires_at,
    ) {
        Ok(Some(recovery)) => {
            return (
                StatusCode::OK,
                Json(InviteResponse {
                    invite: None,
                    resume_existing: true,
                    assigned_ip: recovery.assigned_ip,
                    interface_name: recovery.interface_name,
                    expires_at: recovery.expires_at,
                    enrollment_id: recovery.enrollment.enrollment_id,
                    confirmation_token: recovery.enrollment.confirmation_token,
                    configuration_version: recovery.enrollment.configuration_version,
                }),
            )
                .into_response();
        }
        Ok(None) => {}
        Err(error) => {
            return (
                StatusCode::CONFLICT,
                Json(json!({ "error": "innernet_recovery_unavailable", "detail": error })),
            )
                .into_response();
        }
    }
    let invite = match innernet::generate_invite(
        &input.peer_name,
        input.peer_type.as_str(),
        &assignment.vpn_ip,
    ) {
        Ok(invite) => invite,
        Err(error) => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({ "error": "innernet_unavailable", "detail": error })),
            )
                .into_response();
        }
    };
    let enrollment_expires_at =
        match innernet::constrained_expiry(&assignment.expires_at, &invite.expires_at) {
            Ok(expires_at) => expires_at,
            Err(error) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({ "error": "coordinator_expiry_invalid", "detail": error })),
                )
                    .into_response()
            }
        };
    let enrollment = match innernet::create_enrollment(
        &state.app_context,
        node_id,
        &assignment.node_id,
        &input.peer_name,
        input.peer_type.as_str(),
        input.validator_address.as_deref(),
        &invite.assigned_ip,
        &invite.interface_name,
        &enrollment_expires_at,
    ) {
        Ok(enrollment) => enrollment,
        Err(error) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "coordinator_state_commit_failed", "detail": error })),
            )
                .into_response();
        }
    };
    (
        StatusCode::OK,
        Json(InviteResponse {
            invite: Some(invite.invite),
            resume_existing: false,
            assigned_ip: invite.assigned_ip,
            interface_name: invite.interface_name,
            expires_at: enrollment_expires_at,
            enrollment_id: enrollment.enrollment_id,
            confirmation_token: enrollment.confirmation_token,
            configuration_version: enrollment.configuration_version,
        }),
    )
        .into_response()
}

async fn innernet_confirm_handler(
    State(state): State<ControlServiceState>,
    Json(input): Json<innernet::EnrollmentConfirmation>,
) -> impl IntoResponse {
    match innernet::confirm_enrollment(&state.app_context, input) {
        Ok(payload) => {
            if !payload.bootstrap {
                if let Err(error) = consume_reserved_validator_vpn_onboarding_token(
                    &state.app_context,
                    &payload.vpn_node_id,
                ) {
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(
                            json!({ "error": "coordinator_state_commit_failed", "detail": error }),
                        ),
                    )
                        .into_response();
                }
            }
            (StatusCode::OK, Json(payload)).into_response()
        }
        Err(error) => validator_vpn_error(error),
    }
}

fn invite_source(headers: &HeaderMap) -> String {
    headers
        .get("x-forwarded-for")
        .or_else(|| headers.get("x-real-ip"))
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(',').next())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("unknown")
        .to_string()
}

fn allow_invite_request(
    limiter: &Arc<Mutex<InviteRateLimiter>>,
    source: &str,
    token: &str,
) -> bool {
    let Ok(mut limiter) = limiter.lock() else {
        return false;
    };
    let cutoff = Instant::now() - StdDuration::from_secs(60);
    let ip_count = {
        let ip_attempts = limiter.by_ip.entry(source.to_string()).or_default();
        ip_attempts.retain(|attempt| *attempt > cutoff);
        ip_attempts.len()
    };
    let token_key = sha2::Sha256::digest(token.as_bytes());
    let token_key = format!("{token_key:x}");
    let token_attempts = limiter.by_token.entry(token_key).or_default();
    token_attempts.retain(|attempt| *attempt > cutoff);
    if ip_count >= 10 || token_attempts.len() >= 5 {
        return false;
    }
    let now = Instant::now();
    token_attempts.push(now);
    limiter
        .by_ip
        .entry(source.to_string())
        .or_default()
        .push(now);
    true
}

async fn invoke_handler(
    State(state): State<ControlServiceState>,
    headers: HeaderMap,
    Json(request): Json<InvokeRequest>,
) -> impl IntoResponse {
    if let Err(response) = authorize(&state, &headers) {
        return response;
    }

    let result = dispatch_command(&state, request).await;
    match result {
        Ok(payload) => {
            (StatusCode::OK, Json(json!({ "ok": true, "data": payload }))).into_response()
        }
        Err(error) if error == STATIC_VALIDATOR_VPN_RETIRED_ERROR => legacy_vpn_retired_response(),
        Err(error) => (
            StatusCode::BAD_REQUEST,
            Json(json!({ "ok": false, "error": error })),
        )
            .into_response(),
    }
}

async fn events_handler(
    State(state): State<ControlServiceState>,
    Query(query): Query<EventQuery>,
) -> impl IntoResponse {
    if query.token != *state.token {
        return StatusCode::UNAUTHORIZED.into_response();
    }

    let mut receiver = state.event_bus.subscribe();
    let stream = stream! {
        loop {
            match receiver.recv().await {
                Ok(message) => {
                    let event = Event::default()
                        .event(message.event)
                        .json_data(message.payload)
                        .unwrap_or_else(|_| Event::default().event("service-error").data("{\"error\":\"failed to encode event\"}"));
                    yield Ok::<Event, Infallible>(event);
                }
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                    yield Ok::<Event, Infallible>(
                        Event::default().event("service-warning").data("{\"warning\":\"event backlog dropped\"}")
                    );
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
            }
        }
    };

    Sse::new(stream)
        .keep_alive(KeepAlive::new().interval(std::time::Duration::from_secs(15)))
        .into_response()
}

async fn validator_live_status_handler(
    State(state): State<ControlServiceState>,
    headers: HeaderMap,
    Query(query): Query<ValidatorLiveStatusQuery>,
) -> impl IntoResponse {
    if let Some(token) = query.token.as_ref() {
        if token != state.token.as_ref() {
            return StatusCode::UNAUTHORIZED.into_response();
        }
    } else if let Err(response) = authorize(&state, &headers) {
        return response;
    }

    match testnet_get_validator_live_status(query.node_id).await {
        Ok(payload) => (StatusCode::OK, Json(payload)).into_response(),
        Err(error) => (
            StatusCode::BAD_REQUEST,
            Json(json!({ "ok": false, "error": error })),
        )
            .into_response(),
    }
}

async fn validator_live_status_events_handler(
    State(state): State<ControlServiceState>,
    Query(query): Query<ValidatorLiveStatusQuery>,
) -> impl IntoResponse {
    if query.token.as_deref() != Some(state.token.as_str()) {
        return StatusCode::UNAUTHORIZED.into_response();
    }

    let node_id = query.node_id.clone();
    let stream = stream! {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(4));
        loop {
            interval.tick().await;
            match testnet_get_validator_live_status(node_id.clone()).await {
                Ok(payload) => {
                    let event = Event::default()
                        .event("validator.status.changed")
                        .json_data(payload)
                        .unwrap_or_else(|_| Event::default().event("error").data("{\"error\":\"failed to encode validator live status\"}"));
                    yield Ok::<Event, Infallible>(event);
                }
                Err(error) => {
                    let event = Event::default()
                        .event("error")
                        .json_data(json!({ "error": error }))
                        .unwrap_or_else(|_| Event::default().event("error").data("{\"error\":\"validator live status failed\"}"));
                    yield Ok::<Event, Infallible>(event);
                }
            }
        }
    };

    Sse::new(stream)
        .keep_alive(KeepAlive::new().interval(std::time::Duration::from_secs(10)))
        .into_response()
}

const STATIC_VALIDATOR_VPN_RETIRED_ERROR: &str = "static_validator_vpn_retired";

fn is_retired_static_validator_vpn_command(command: &str) -> bool {
    matches!(
        command,
        "testnet_enroll_validator_vpn"
            | "testnet_apply_validator_vpn_snapshot"
            | "testnet_align_validator_vpn_config"
            | "testnet_validator_vpn_agent_status"
            | "validator_vpn_status"
            | "testnet_validator_vpn_status"
            | "validator_vpn_agent_plan"
            | "testnet_validator_vpn_agent_plan"
            | "validator_vpn_create_enrollment_challenge"
            | "validator_vpn_enroll"
            | "validator_vpn_register_relayer"
            | "validator_vpn_import_bootstrap_nodes"
            | "testnet_validator_vpn_import_bootstrap_nodes"
            | "validator_vpn_latest_snapshot"
            | "validator_vpn_node_heartbeat"
    )
}

fn legacy_vpn_retired_response() -> axum::response::Response {
    (
        StatusCode::GONE,
        Json(json!({
            "ok": false,
            "error": STATIC_VALIDATOR_VPN_RETIRED_ERROR,
            "detail": "The coordinator is in Innernet cutover mode. Use /v1/invite and /v1/mesh/confirm."
        })),
    )
        .into_response()
}

async fn legacy_validator_vpn_retired_handler() -> axum::response::Response {
    legacy_vpn_retired_response()
}

async fn verify_public_innernet_enrollment(input: &InviteRequest) -> Result<(), String> {
    if !matches!(&input.peer_type, ValidatorVpnRole::Validator) {
        return Ok(());
    }
    let validator_address = input
        .validator_address
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            "Innernet validator enrollment requires the validator synv1 address.".to_string()
        })?;
    let owner_wallet = input
        .operator_address
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            "Innernet validator enrollment requires the operator Synergy wallet address."
                .to_string()
        })?;
    let eligibility = testnet_verify_validator_eligibility(TestnetValidatorEligibilityInput {
        wallet_address: owner_wallet.to_string(),
        node_id: None,
        validator_address: Some(validator_address.to_string()),
        required_stake: None,
        stake_tx_hash: input
            .stake_tx_hash
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned),
    })
    .await?;
    if eligibility.eligible || eligibility.funding_ready_to_bond {
        Ok(())
    } else {
        Err(format!(
            "Innernet validator bootstrap requires 50,000 SNRG confirmed validator funding or bonded stake from owner wallet {} for validator {}. Current status: {}, validator funding: {} SNRG, active stake: {} SNRG, missing: {} SNRG.",
            owner_wallet,
            validator_address,
            eligibility.eligibility_status,
            eligibility.validator_funding_amount,
            eligibility.active_stake_amount,
            eligibility.missing_stake_amount
        ))
    }
}

fn validator_vpn_error(error: String) -> axum::response::Response {
    (
        StatusCode::BAD_REQUEST,
        Json(json!({ "ok": false, "error": error })),
    )
        .into_response()
}

#[allow(clippy::result_large_err)]
fn authorize(
    state: &ControlServiceState,
    headers: &HeaderMap,
) -> Result<(), axum::response::Response> {
    let Some(value) = headers.get(header::AUTHORIZATION) else {
        return Err(StatusCode::UNAUTHORIZED.into_response());
    };

    let Ok(value) = value.to_str() else {
        return Err(StatusCode::UNAUTHORIZED.into_response());
    };

    if value.trim() == format!("Bearer {}", state.token.as_str()) {
        Ok(())
    } else {
        Err(StatusCode::UNAUTHORIZED.into_response())
    }
}

async fn dispatch_command(
    state: &ControlServiceState,
    request: InvokeRequest,
) -> Result<Value, String> {
    if is_retired_static_validator_vpn_command(&request.command) {
        return Err(STATIC_VALIDATOR_VPN_RETIRED_ERROR.to_string());
    }

    if let Some(result) = crate::control_v2::dispatch_control_v2_command(
        &state.app_context,
        request.command.as_str(),
        request.args.clone(),
    ) {
        return to_value(result?);
    }

    match request.command.as_str() {
        "monitor_initialize_workspace" => to_value(monitor_initialize_workspace_from_context(
            &state.app_context,
        )?),
        "monitor_apply_testnet_topology" => to_value(monitor_apply_testnet_topology_from_context(
            &state.app_context,
        )?),
        "monitor_get_setup_status" => to_value(monitor_get_setup_status()?),
        "get_monitor_snapshot" => to_value(get_monitor_snapshot().await?),
        "get_monitor_agent_snapshot" => to_value(get_monitor_agent_snapshot().await?),
        "get_monitor_workspace_path" => to_value(get_monitor_workspace_path()?),
        "get_monitor_inventory_path" => to_value(get_monitor_inventory_path()?),
        "get_monitor_user_manual_markdown" => to_value(get_monitor_user_manual_markdown()?),
        "get_monitor_security_state" => to_value(get_monitor_security_state()?),
        "monitor_detect_local_machine_identity" => {
            to_value(monitor_detect_local_machine_identity()?)
        }
        "monitor_ensure_ssh_keypair" => {
            to_value(monitor_ensure_ssh_keypair_from_context(&state.app_context)?)
        }
        "agent_monitor_initialize_workspace" => to_value(
            agent_monitor_initialize_workspace_from_context(&state.app_context)?,
        ),
        "agent_get_inventory_machines" => to_value(agent_get_inventory_machines()?),
        "monitor_set_active_operator" => {
            let args: OperatorIdArgs = parse_args(request.args)?;
            to_value(monitor_set_active_operator(args.operator_id)?)
        }
        "monitor_upsert_operator" => {
            let args: UpsertOperatorArgs = parse_args(request.args)?;
            to_value(monitor_upsert_operator(args.input)?)
        }
        "monitor_delete_operator" => {
            let args: OperatorIdArgs = parse_args(request.args)?;
            to_value(monitor_delete_operator(args.operator_id)?)
        }
        "monitor_upsert_ssh_profile" => {
            let args: UpsertProfileArgs = parse_args(request.args)?;
            to_value(monitor_upsert_ssh_profile(args.input)?)
        }
        "monitor_delete_ssh_profile" => {
            let args: ProfileIdArgs = parse_args(request.args)?;
            to_value(monitor_delete_ssh_profile(args.profile_id)?)
        }
        "monitor_assign_ssh_binding" => {
            let args: AssignBindingArgs = parse_args(request.args)?;
            to_value(monitor_assign_ssh_binding(args.input)?)
        }
        "monitor_remove_ssh_binding" => {
            let args: NodeSlotArgs = parse_args(request.args)?;
            to_value(monitor_remove_ssh_binding(args.node_slot_id)?)
        }
        "monitor_run_terminal_command" => {
            let args: TerminalCommandArgs = parse_args(request.args)?;
            to_value(monitor_run_terminal_command(args.command, args.cwd).await?)
        }
        "testnet_get_state" => to_value(testnet_get_state()?),
        "testnet_get_live_status" => to_value(testnet_get_live_status().await?),
        "testnet_get_device_profile" => to_value(testnet_get_device_profile()?),
        "testnet_get_catalog" => to_value(testnet_get_catalog()?),
        "testnet_discover_validator_snapshot" => {
            to_value(testnet_discover_validator_snapshot().await?)
        }
        "testnet_erase_local_machine_data" => {
            let args: TestnetEraseNodeDataArgs = parse_args(request.args)?;
            to_value(
                testnet_erase_local_machine_data(
                    &state.app_context,
                    TestnetEraseNodeDataInput {
                        target_os: args.target_os,
                    },
                )
                .await?,
            )
        }
        "testnet_reset_innernet_client_state" => {
            let args: TestnetEraseNodeDataArgs = parse_args(request.args)?;
            to_value(
                testnet_reset_innernet_client_state(TestnetEraseNodeDataInput {
                    target_os: args.target_os,
                })
                .await?,
            )
        }
        "testnet_setup_node" => {
            let args: TestnetSetupArgs = parse_args(request.args)?;
            to_value(testnet_setup_node(args.input).await?)
        }
        "testnet_node_control" => {
            let args: TestnetNodeControlArgs = parse_args(request.args)?;
            to_value(
                testnet_node_control(
                    &state.app_context,
                    Some(state.event_bus.clone()),
                    args.input,
                )
                .await?,
            )
        }
        "testnet_mark_setup_sync_complete" => {
            let args: TestnetSetupSyncCompleteArgs = parse_args(request.args)?;
            to_value(testnet_mark_setup_sync_complete(args.input).await?)
        }
        "testnet_remove_node" => {
            let args: TestnetRemoveNodeArgs = parse_args(request.args)?;
            to_value(testnet_remove_node(&state.app_context, args.input).await?)
        }
        "testnet_rename_node" => {
            let args: TestnetRenameNodeArgs = parse_args(request.args)?;
            to_value(testnet_rename_node(args.input)?)
        }
        "testnet_set_validator_owner" => {
            let args: TestnetSetValidatorOwnerArgs = parse_args(request.args)?;
            to_value(testnet_set_validator_owner(args.input)?)
        }
        "testnet_apply_atlas_validator_profile" => {
            let args: TestnetApplyAtlasValidatorProfileArgs = parse_args(request.args)?;
            to_value(testnet_apply_atlas_validator_profile(args.input)?)
        }
        "testnet_publish_validator_profile_to_atlas" => {
            let args: TestnetPublishValidatorProfileArgs = parse_args(request.args)?;
            to_value(testnet_publish_validator_profile_to_atlas(args.input).await?)
        }
        "testnet_get_node_logs" => {
            let args: TestnetNodeLogsArgs = parse_args(request.args)?;
            to_value(testnet_get_node_logs(args.node_id, args.lines)?)
        }
        "testnet_validate_path" => {
            let args: TestnetPathValidationInput = parse_args(request.args)?;
            to_value(testnet_validate_path(args)?)
        }
        "testnet_create_snapshot" => {
            let args: TestnetFilesystemTargetInput = parse_args(request.args)?;
            to_value(testnet_create_snapshot(args)?)
        }
        "testnet_backup_keys" => {
            let args: TestnetFilesystemTargetInput = parse_args(request.args)?;
            to_value(testnet_backup_keys(args)?)
        }
        "testnet_encrypt_validator_keys" => {
            let args: TestnetKeyEncryptionInput = parse_args(request.args)?;
            to_value(testnet_encrypt_validator_keys(args)?)
        }
        "testnet_export_config" => {
            let args: TestnetFilesystemTargetInput = parse_args(request.args)?;
            to_value(testnet_export_config(args)?)
        }
        "testnet_import_config" => {
            let args: TestnetFilesystemTargetInput = parse_args(request.args)?;
            to_value(testnet_import_config(args)?)
        }
        "testnet_verify_backup" => {
            let args: TestnetFilesystemTargetInput = parse_args(request.args)?;
            to_value(testnet_verify_backup(args)?)
        }
        "testnet_restore_backup" => {
            let args: TestnetFilesystemTargetInput = parse_args(request.args)?;
            to_value(testnet_restore_backup(args)?)
        }
        "testnet_clear_cache" => {
            let args: TestnetFilesystemTargetInput = parse_args(request.args)?;
            to_value(testnet_clear_cache(args)?)
        }
        "testnet_apply_log_retention" => {
            let args: TestnetLogRetentionInput = parse_args(request.args)?;
            to_value(testnet_apply_log_retention(args)?)
        }
        "testnet_get_feature_snapshot" => {
            let args: TestnetFeatureSnapshotArgs = parse_args(request.args)?;
            to_value(testnet_get_feature_snapshot(args.input).await?)
        }
        "testnet_get_chain_blocks" => {
            let args: TestnetChainBlocksArgs = parse_args(request.args)?;
            to_value(testnet_get_chain_blocks(args.node_id, args.count).await?)
        }
        "testnet_run_register_with_seeds" => {
            let args: TestnetRegisterWithSeedsArgs = parse_args(request.args)?;
            to_value(testnet_run_register_with_seeds(&state.app_context, args.node_id).await?)
        }
        "testnet_get_node_readiness" => {
            let args: TestnetReadinessArgs = parse_args(request.args)?;
            to_value(testnet_get_node_readiness(args.node_id).await?)
        }
        "get_rewards_data" | "testnet_get_rewards_data" => {
            let args: TestnetRewardsArgs = parse_args(request.args)?;
            to_value(testnet_get_rewards_data(args.node_id).await?)
        }
        "testnet_boost_sync" => {
            let args: TestnetBoostSyncArgs = parse_args(request.args)?;
            to_value(testnet_boost_sync(&state.app_context, args.node_id).await?)
        }
        "testnet_get_validator_activation_preflight" => {
            let args: TestnetValidatorActivationPreflightArgs = parse_args(request.args)?;
            to_value(testnet_get_validator_activation_preflight(args.node_id).await?)
        }
        "testnet_get_validator_live_status" => {
            let args: TestnetValidatorLiveStatusArgs = parse_args(request.args)?;
            to_value(testnet_get_validator_live_status(args.node_id).await?)
        }
        "testnet_verify_validator_eligibility" => {
            let args: TestnetValidatorEligibilityInput = parse_args(request.args)?;
            to_value(testnet_verify_validator_eligibility(args).await?)
        }
        "testnet_diagnose_onboarding_sync" | "diagnose_onboarding_sync" => {
            let args: TestnetValidatorLiveStatusArgs = parse_args(request.args)?;
            to_value(testnet_diagnose_onboarding_sync(args.node_id).await?)
        }
        "testnet_recover_local_fork" | "recover_local_fork" => {
            let args: TestnetValidatorLiveStatusArgs = parse_args(request.args)?;
            let node_id = args
                .node_id
                .ok_or_else(|| "Local fork recovery requires a node_id.".to_string())?;
            to_value(testnet_recover_local_fork(&state.app_context, node_id).await?)
        }
        "testnet_record_validator_funding" => {
            let args: TestnetValidatorFundingArgs = parse_args(request.args)?;
            to_value(testnet_record_validator_funding(args.input).await?)
        }
        "testnet_stake_validator" => {
            let args: TestnetValidatorStakeArgs = parse_args(request.args)?;
            to_value(testnet_stake_validator(args.input).await?)
        }
        "testnet_unstake_validator" => {
            let args: TestnetValidatorUnstakeArgs = parse_args(request.args)?;
            to_value(testnet_unstake_validator(args.input).await?)
        }
        "testnet_transfer_validator_tokens" => {
            let args: TestnetValidatorTransferArgs = parse_args(request.args)?;
            to_value(testnet_transfer_validator_tokens(args.input).await?)
        }
        "testnet_activate_validator" => {
            let args: TestnetValidatorActivateArgs = parse_args(request.args)?;
            to_value(testnet_activate_validator(args.input).await?)
        }
        "testnet_sync_catch_up_rejoin" => {
            let args: TestnetValidatorCatchUpArgs = parse_args(request.args)?;
            to_value(
                testnet_sync_catch_up_rejoin(
                    &state.app_context,
                    Some(state.event_bus.clone()),
                    args.input,
                )
                .await?,
            )
        }
        "testnet_start_validator_normal_sync" => {
            let args: TestnetValidatorCatchUpArgs = parse_args(request.args)?;
            to_value(testnet_start_validator_normal_sync(&state.app_context, args.input).await?)
        }
        "testnet_enroll_validator_vpn" => {
            let args: TestnetValidatorVpnArgs = parse_args(request.args)?;
            to_value(testnet_enroll_validator_vpn(&state.app_context, args.input).await?)
        }
        "testnet_record_innernet_enrollment" => {
            let args: TestnetInnernetEnrollmentArgs = parse_args(request.args)?;
            to_value(testnet_record_innernet_enrollment(&state.app_context, args.input).await?)
        }
        "testnet_reuse_innernet_enrollment" => {
            let args: TestnetValidatorVpnArgs = parse_args(request.args)?;
            to_value(testnet_reuse_innernet_enrollment(&state.app_context, args.input).await?)
        }
        "testnet_apply_validator_vpn_snapshot" => {
            let args: TestnetValidatorVpnArgs = parse_args(request.args)?;
            to_value(testnet_apply_validator_vpn_snapshot(&state.app_context, args.input).await?)
        }
        "testnet_align_validator_vpn_config" => {
            let args: TestnetValidatorVpnArgs = parse_args(request.args)?;
            to_value(testnet_align_validator_vpn_config(&state.app_context, args.input).await?)
        }
        "testnet_validator_vpn_agent_status" => {
            let args: TestnetValidatorVpnArgs = parse_args(request.args)?;
            to_value(testnet_validator_vpn_status(&state.app_context, args.input).await?)
        }
        "testnet_run_validator_onboarding" | "run_validator_onboarding" => {
            let args: TestnetValidatorOnboardingArgs = parse_args(request.args)?;
            to_value(testnet_run_validator_onboarding(&state.app_context, args.input).await?)
        }
        "testnet_restore_validator_snapshot" => {
            let args: TestnetSnapshotRestoreArgs = parse_args(request.args)?;
            to_value(
                testnet_restore_validator_snapshot(
                    &state.app_context,
                    state.event_bus.clone(),
                    args.input,
                )
                .await?,
            )
        }
        "testnet_download_validator_snapshot" => {
            let args: TestnetValidatorSnapshotDownloadArgs = parse_args(request.args)?;
            to_value(testnet_download_validator_snapshot(args.input).await?)
        }
        "testnet_verify_validator_snapshot" => {
            let args: TestnetValidatorSnapshotVerifyArgs = parse_args(request.args)?;
            to_value(testnet_verify_validator_snapshot(&state.app_context, args.input).await?)
        }
        "testnet_apply_validator_snapshot" => {
            let args: TestnetValidatorSnapshotApplyArgs = parse_args(request.args)?;
            to_value(
                testnet_apply_validator_snapshot(
                    &state.app_context,
                    state.event_bus.clone(),
                    args.input,
                )
                .await?,
            )
        }
        "testnet_request_validator_rejoin" | "request_validator_rejoin" => {
            let args: TestnetValidatorRejoinRequestArgs = parse_args(request.args)?;
            to_value(testnet_request_validator_rejoin(args.input).await?)
        }
        "testnet_force_peer_connect" => {
            let args: TestnetForcePeerConnectArgs = parse_args(request.args)?;
            to_value(testnet_force_peer_connect(&state.app_context, args.input).await?)
        }
        "validator_vpn_status" | "testnet_validator_vpn_status" => {
            to_value(validator_vpn_status(&state.app_context)?)
        }
        "validator_vpn_agent_plan" | "testnet_validator_vpn_agent_plan" => {
            to_value(validator_vpn_agent_plan())
        }
        "validator_vpn_create_enrollment_challenge" => {
            let args: ValidatorVpnChallengeArgs = parse_args(request.args)?;
            to_value(create_validator_vpn_challenge(
                &state.app_context,
                args.input,
            )?)
        }
        "validator_vpn_enroll" => {
            let args: ValidatorVpnEnrollArgs = parse_args(request.args)?;
            to_value(enroll_validator_vpn_node(&state.app_context, args.input)?)
        }
        "validator_vpn_register_relayer" => {
            let args: ValidatorVpnRelayerArgs = parse_args(request.args)?;
            to_value(register_validator_vpn_relayer(
                &state.app_context,
                args.input,
            )?)
        }
        "validator_vpn_import_bootstrap_nodes" | "testnet_validator_vpn_import_bootstrap_nodes" => {
            let args: ValidatorVpnBootstrapImportArgs = parse_args(request.args)?;
            to_value(import_validator_vpn_bootstrap_nodes(
                &state.app_context,
                args.input,
            )?)
        }
        "validator_vpn_latest_snapshot" => {
            to_value(get_latest_validator_vpn_snapshot(&state.app_context)?)
        }
        "validator_vpn_node_heartbeat" => {
            let node_id = request
                .args
                .get("node_id")
                .or_else(|| request.args.get("nodeId"))
                .and_then(Value::as_str)
                .ok_or_else(|| "node_id is required".to_string())?
                .to_string();
            let args: ValidatorVpnHeartbeatArgs = parse_args(request.args)?;
            to_value(record_validator_vpn_heartbeat(
                &state.app_context,
                node_id,
                args.input,
            )?)
        }
        "monitor_mark_setup_complete" => {
            let args: SetupCompleteArgs = parse_args(request.args)?;
            to_value(
                monitor_mark_setup_complete(args.physical_machine_id, args.node_slot_ids).await?,
            )
        }
        "monitor_node_control" => {
            let args: NodeActionArgs = parse_args(request.args)?;
            to_value(monitor_node_control(args.node_slot_id, args.action).await?)
        }
        "monitor_bulk_node_control" => {
            let args: BulkActionArgs = parse_args(request.args)?;
            to_value(monitor_bulk_node_control(args.action, args.scope).await?)
        }
        "get_monitor_node_details" => {
            let args: NodeSlotArgs = parse_args(request.args)?;
            to_value(get_monitor_node_details(args.node_slot_id).await?)
        }
        "monitor_export_node_data" => {
            let args: NodeSlotArgs = parse_args(request.args)?;
            to_value(monitor_export_node_data(args.node_slot_id).await?)
        }
        "monitor_update_local_agent" => {
            let args: NodeSlotArgs = parse_args(request.args)?;
            to_value(
                monitor_update_local_agent_from_context(args.node_slot_id, &state.app_context)
                    .await?,
            )
        }
        "agent_prepare_hosts_env" => {
            let args: PrepareHostsArgs = parse_args(request.args)?;
            to_value(agent_prepare_hosts_env_from_context(
                args.input,
                &state.app_context,
            )?)
        }
        other => Err(format!("Unsupported control-service command: {other}")),
    }
}

fn to_value<T: Serialize>(value: T) -> Result<Value, String> {
    serde_json::to_value(value).map_err(|error| format!("Failed to serialize response: {error}"))
}

fn parse_args<T: DeserializeOwned>(value: Value) -> Result<T, String> {
    serde_json::from_value(value).map_err(|error| format!("Failed to decode command args: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retired_static_validator_vpn_commands_are_rejected() {
        for command in [
            "testnet_enroll_validator_vpn",
            "testnet_apply_validator_vpn_snapshot",
            "testnet_align_validator_vpn_config",
            "testnet_validator_vpn_agent_status",
            "validator_vpn_status",
            "testnet_validator_vpn_status",
            "validator_vpn_agent_plan",
            "testnet_validator_vpn_agent_plan",
            "validator_vpn_create_enrollment_challenge",
            "validator_vpn_enroll",
            "validator_vpn_register_relayer",
            "validator_vpn_import_bootstrap_nodes",
            "testnet_validator_vpn_import_bootstrap_nodes",
            "validator_vpn_latest_snapshot",
            "validator_vpn_node_heartbeat",
        ] {
            assert!(
                is_retired_static_validator_vpn_command(command),
                "legacy command should be retired: {command}"
            );
        }

        for command in [
            "testnet_record_innernet_enrollment",
            "testnet_reuse_innernet_enrollment",
            "testnet_run_validator_onboarding",
        ] {
            assert!(!is_retired_static_validator_vpn_command(command));
        }
    }

    #[test]
    fn retired_validator_vpn_response_is_explicit_gone() {
        let response = legacy_vpn_retired_response();

        assert_eq!(response.status(), StatusCode::GONE);
        assert_eq!(
            STATIC_VALIDATOR_VPN_RETIRED_ERROR,
            "static_validator_vpn_retired"
        );
    }
}
