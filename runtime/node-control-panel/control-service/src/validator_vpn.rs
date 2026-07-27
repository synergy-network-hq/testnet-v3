use crate::app_context::AppContext;
use crate::innernet;
use crate::monitor::ensure_monitor_workspace_with_context;
use base64::{engine::general_purpose, Engine as _};
use chrono::{DateTime, Duration, Utc};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fs;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use synergy_address_engine::{verify_address, verify_identity_proof};
use uuid::Uuid;

pub const VALIDATOR_VPN_NETWORK: &str = "synergy-validator-vpn-testnet";
pub const VALIDATOR_VPN_CIDR: &str = "10.70.0.0/16";
pub const VALIDATOR_VPN_VALIDATOR_CIDR: &str = "10.70.10.0/24";
pub const VALIDATOR_VPN_RELAYER_CIDR: &str = "10.70.20.0/24";
pub const VALIDATOR_VPN_INTERFACE: &str = "sy-validator0";
pub const VALIDATOR_VPN_LISTEN_PORT: u16 = 51_820;
pub const VALIDATOR_VPN_MTU: u16 = 1_380;
const STATE_RELATIVE_PATH: &str = "testnet/runtime/validator-vpn/validator-vpn-state.json";
const SNAPSHOT_URL: &str = "/api/validator-vpn/snapshots/latest";
const CHALLENGE_TTL_MINUTES: i64 = 10;
const HEARTBEAT_DEGRADED_MINUTES: i64 = 5;
const WIREGUARD_INACTIVE_MINUTES: i64 = 15;
const DEFAULT_ENROLLMENT_SIGNATURE_MODE: &str = "challenge-sha256";
const MIN_VERIFIED_HANDSHAKES: usize = 1;
const BOOTSTRAP_VALIDATOR_ADDRESSES: [&str; 6] = [
    "synv11yc4cjehqjm6fp0ey4ppjptv0p3cwdy6r79t",
    "synv11k0vlmkt5gyp3czlgvlfm5yqkxu5nyvp4ekk",
    "synv11jk9pprkz7faykn4ez7hzaj2q7lg04l2fjgj",
    "synv11s7hag82s6d9f8urrv5cl40lyeamxelthpeg",
    "synv11cl92kxcx4jyzusecqydrxc8aj3hsgscrvtu",
    "synv1129lck2uvz73f59wd3yame0w04qnrdpmmmfc",
];
const BOOTSTRAP_RELAYER_COUNT: u32 = 3;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
pub enum ValidatorVpnRole {
    Validator,
    Relayer,
}

impl ValidatorVpnRole {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Validator => "validator",
            Self::Relayer => "relayer",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ValidatorVpnNodeStatus {
    Reserved,
    Enrolling,
    Configuring,
    Pending,
    Syncing,
    Connected,
    Eligible,
    Active,
    Degraded,
    Inactive,
    Quarantined,
    Jailed,
    Removed,
    Revoked,
}

impl ValidatorVpnNodeStatus {
    fn is_snapshot_active(&self) -> bool {
        matches!(
            self,
            Self::Pending
                | Self::Syncing
                | Self::Connected
                | Self::Eligible
                | Self::Active
                | Self::Degraded
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ValidatorVpnLeaseState {
    Available,
    Reserved,
    Assigned,
    Tombstoned,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorVpnNode {
    pub id: String,
    pub role: ValidatorVpnRole,
    pub node_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub validator_pubkey: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operator_address: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wg_pubkey: Option<String>,
    pub vpn_ip: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint_host: Option<String>,
    pub endpoint_port: u16,
    pub status: ValidatorVpnNodeStatus,
    pub bootstrap_node: bool,
    pub assigned_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub activated_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_vpn_handshake_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_agent_heartbeat_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_consensus_seen_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inactive_since: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorVpnIpLease {
    pub vpn_ip: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node_id: Option<String>,
    pub role: ValidatorVpnRole,
    pub state: ValidatorVpnLeaseState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub assigned_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tombstoned_until: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorVpnEnrollmentChallenge {
    pub id: String,
    pub challenge: String,
    pub role: ValidatorVpnRole,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub validator_pubkey: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operator_address: Option<String>,
    pub expires_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub consumed_at: Option<String>,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorVpnPeerRecord {
    pub node_id: String,
    pub node_name: String,
    pub vpn_ip: String,
    pub wg_pubkey: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub validator_pubkey: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operator_address: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorVpnRemovedPeer {
    pub node_id: String,
    pub vpn_ip: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorVpnPeerSnapshot {
    pub generation: u64,
    pub network: String,
    pub cidr: String,
    pub created_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub coordinator_public_signing_key: Option<String>,
    pub relayers: Vec<ValidatorVpnPeerRecord>,
    pub validators: Vec<ValidatorVpnPeerRecord>,
    pub removed: Vec<ValidatorVpnRemovedPeer>,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorVpnEvent {
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node_id: Option<String>,
    pub event_type: String,
    #[serde(default)]
    pub event_payload: serde_json::Value,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorVpnStateFile {
    pub version: u32,
    pub network: String,
    pub cidr: String,
    pub nodes: Vec<ValidatorVpnNode>,
    pub ip_leases: Vec<ValidatorVpnIpLease>,
    pub enrollment_challenges: Vec<ValidatorVpnEnrollmentChallenge>,
    pub peer_snapshots: Vec<ValidatorVpnPeerSnapshot>,
    pub events: Vec<ValidatorVpnEvent>,
    #[serde(default)]
    pub onboarding_tokens: Vec<ValidatorVpnOnboardingToken>,
    #[serde(default)]
    pub config_acks: Vec<ValidatorVpnConfigAck>,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorVpnOnboardingToken {
    pub id: String,
    pub token_hash: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operator_label: Option<String>,
    pub peer_type: ValidatorVpnRole,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub assignment_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub assigned_validator_identity: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub assigned_validator_public_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity_proof_verified_at: Option<String>,
    pub issued_at: String,
    pub expires_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reserved_node_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub used_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorVpnConfigAck {
    pub node_id: String,
    pub generation: u64,
    pub applied: bool,
    pub interface_up: bool,
    pub peers_handshaked: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    pub acknowledged_at: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ValidatorVpnPropagationStatus {
    pub generation: u64,
    pub expected_validator_ids: Vec<String>,
    pub acknowledged_validator_ids: Vec<String>,
    pub pending_validator_ids: Vec<String>,
    pub failed_validator_ids: Vec<String>,
    pub complete: bool,
    pub required_acknowledgements: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct ValidatorVpnMeshStatus {
    pub network: String,
    pub active_validators: usize,
    pub active_relayers: usize,
    pub latest_generation: Option<u64>,
    pub propagation_complete: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct ValidatorVpnInviteAssignment {
    pub node_id: String,
    pub role: ValidatorVpnRole,
    pub vpn_ip: String,
    pub expires_at: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ValidatorVpnConfigAckRequest {
    pub generation: u64,
    #[serde(default)]
    pub applied: bool,
    #[serde(default)]
    pub interface_up: bool,
    #[serde(default)]
    pub peers_handshaked: usize,
    #[serde(default)]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorVpnChallengeRequest {
    pub role: ValidatorVpnRole,
    pub node_name: String,
    #[serde(default)]
    pub validator_pubkey: Option<String>,
    #[serde(default)]
    pub operator_address: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorVpnChallengeResponse {
    pub challenge_id: String,
    pub challenge: String,
    pub expires_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorVpnEnrollRequest {
    pub challenge_id: String,
    pub role: ValidatorVpnRole,
    pub node_name: String,
    #[serde(default)]
    pub validator_pubkey: Option<String>,
    #[serde(default)]
    pub operator_address: Option<String>,
    pub wg_pubkey: String,
    #[serde(default)]
    pub endpoint_host: Option<String>,
    #[serde(default = "default_endpoint_port")]
    pub endpoint_port: u16,
    pub signed_payload: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorVpnEnrollResponse {
    pub node_id: String,
    pub role: ValidatorVpnRole,
    pub vpn_ip: String,
    pub interface: String,
    pub listen_port: u16,
    pub peer_snapshot_generation: u64,
    pub peer_snapshot_url: String,
    pub coordinator_public_signing_key: String,
    pub relayers: Vec<ValidatorVpnPeerRecord>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ValidatorVpnRelayerRegistrationRequest {
    pub node_name: String,
    pub wg_pubkey: String,
    #[serde(default)]
    pub endpoint_host: Option<String>,
    #[serde(default = "default_endpoint_port")]
    pub endpoint_port: u16,
    #[serde(default)]
    pub vpn_ip: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ValidatorVpnBootstrapImportRequest {
    pub nodes: Vec<ValidatorVpnBootstrapNodeInput>,
    #[serde(default, alias = "regenerateSnapshot")]
    pub regenerate_snapshot: Option<bool>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ValidatorVpnBootstrapNodeInput {
    pub role: ValidatorVpnRole,
    #[serde(alias = "nodeName")]
    pub node_name: String,
    #[serde(alias = "vpnIp")]
    pub vpn_ip: String,
    #[serde(alias = "wgPubkey", alias = "wgPublicKey")]
    pub wg_pubkey: String,
    #[serde(default)]
    pub endpoint: Option<String>,
    #[serde(default, alias = "endpointHost")]
    pub endpoint_host: Option<String>,
    #[serde(default, alias = "publicIp")]
    pub public_ip: Option<String>,
    #[serde(
        default,
        alias = "endpointPort",
        alias = "listen_port",
        alias = "listenPort"
    )]
    pub endpoint_port: Option<u16>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ValidatorVpnBootstrapImportResponse {
    pub imported: usize,
    pub updated: usize,
    pub latest_generation: Option<u64>,
    pub nodes: Vec<ValidatorVpnNode>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ValidatorVpnHeartbeatRequest {
    #[serde(default)]
    pub last_vpn_handshake_at: Option<String>,
    #[serde(default)]
    pub last_consensus_seen_at: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ValidatorVpnStatusResponse {
    pub network: String,
    pub cidr: String,
    pub state_path: String,
    pub bootstrap_node_count: usize,
    pub active_peer_count: usize,
    pub latest_generation: Option<u64>,
    pub signing_configured: bool,
    pub snapshot_signature_scheme: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub coordinator_public_signing_key: Option<String>,
    pub enrollment_verifier_configured: bool,
    pub eligibility_configured: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub propagation: Option<ValidatorVpnPropagationStatus>,
    pub nodes: Vec<ValidatorVpnNode>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ValidatorVpnAgentPlan {
    pub private_key_path: String,
    pub public_key_path: String,
    pub interface: String,
    pub listen_port: u16,
    pub mtu: u16,
    pub peer_update_interval: String,
    pub persistent_keepalive: u16,
    pub private_key_policy: String,
    pub update_method: String,
}

fn default_endpoint_port() -> u16 {
    VALIDATOR_VPN_LISTEN_PORT
}

fn now_rfc3339() -> String {
    Utc::now().to_rfc3339()
}

pub fn validator_vpn_status(
    app_context: &AppContext,
) -> Result<ValidatorVpnStatusResponse, String> {
    let state_path = validator_vpn_state_path(app_context)?;
    let state = load_or_initialize_state(&state_path)?;
    let latest_generation = state
        .peer_snapshots
        .last()
        .map(|snapshot| snapshot.generation);
    let active_peer_count = state
        .nodes
        .iter()
        .filter(|node| node.status.is_snapshot_active() && node.wg_pubkey.is_some())
        .count();
    let propagation = state
        .peer_snapshots
        .last()
        .map(|snapshot| propagation_status_for(&state, snapshot.generation));
    Ok(ValidatorVpnStatusResponse {
        network: state.network,
        cidr: state.cidr,
        state_path: state_path.to_string_lossy().to_string(),
        bootstrap_node_count: state
            .nodes
            .iter()
            .filter(|node| node.bootstrap_node)
            .count(),
        active_peer_count,
        latest_generation,
        signing_configured: coordinator_signing_key().is_some(),
        snapshot_signature_scheme: coordinator_signature_scheme(),
        coordinator_public_signing_key: validator_vpn_coordinator_public_signing_key(),
        enrollment_verifier_configured: enrollment_verifier_mode().is_some(),
        eligibility_configured: true,
        propagation,
        nodes: state.nodes,
    })
}

pub fn validator_vpn_mesh_status(
    app_context: &AppContext,
) -> Result<ValidatorVpnMeshStatus, String> {
    let state_path = validator_vpn_state_path(app_context)?;
    let state = load_or_initialize_state(&state_path)?;
    let latest_generation = state
        .peer_snapshots
        .last()
        .map(|snapshot| snapshot.generation);
    let propagation_complete = latest_generation
        .map(|generation| propagation_status_for(&state, generation).complete)
        .unwrap_or(false);
    Ok(ValidatorVpnMeshStatus {
        network: state.network,
        active_validators: state
            .nodes
            .iter()
            .filter(|node| {
                node.role == ValidatorVpnRole::Validator
                    && node.status.is_snapshot_active()
                    && node.wg_pubkey.is_some()
            })
            .count(),
        active_relayers: state
            .nodes
            .iter()
            .filter(|node| {
                node.role == ValidatorVpnRole::Relayer
                    && node.status.is_snapshot_active()
                    && node.wg_pubkey.is_some()
            })
            .count(),
        latest_generation,
        propagation_complete,
    })
}

pub fn issue_validator_vpn_onboarding_token(
    app_context: &AppContext,
    operator_label: Option<String>,
    peer_type: ValidatorVpnRole,
    assignment_id: Option<String>,
    assigned_validator_identity: Option<String>,
    assigned_validator_public_key: Option<String>,
    expires_at: DateTime<Utc>,
) -> Result<String, String> {
    if expires_at <= Utc::now() {
        return Err("Token expiry must be in the future".to_string());
    }
    let assignment_id = clean_optional(assignment_id);
    let assigned_validator_identity = clean_optional(assigned_validator_identity);
    let assigned_validator_public_key = clean_optional(assigned_validator_public_key);
    if peer_type == ValidatorVpnRole::Validator {
        let identity = assigned_validator_identity.as_deref().ok_or_else(|| {
            "Validator onboarding tokens require an assigned synv identity.".to_string()
        })?;
        validate_validator_identity(identity)?;
        let public_key = assigned_validator_public_key.as_deref().ok_or_else(|| {
            "Validator onboarding tokens require the assigned validator public key.".to_string()
        })?;
        if !verify_address(identity, public_key)? {
            return Err(
                "Validator public key does not derive the assigned synv identity.".to_string(),
            );
        }
        let assignment = assignment_id
            .as_deref()
            .ok_or_else(|| "Validator onboarding tokens require an assignment id.".to_string())?;
        if !assignment.starts_with("validator-") {
            return Err("Validator assignment id is invalid.".to_string());
        }
    }
    let state_path = validator_vpn_state_path(app_context)?;
    let mut state = load_or_initialize_state(&state_path)?;
    let mut bytes = [0u8; 32];
    bytes[..16].copy_from_slice(Uuid::new_v4().as_bytes());
    bytes[16..].copy_from_slice(Uuid::new_v4().as_bytes());
    let token = general_purpose::URL_SAFE_NO_PAD.encode(bytes);
    let record = ValidatorVpnOnboardingToken {
        id: Uuid::new_v4().to_string(),
        token_hash: hash_onboarding_token(&token),
        operator_label: clean_optional(operator_label),
        peer_type: peer_type.clone(),
        assignment_id,
        assigned_validator_identity,
        assigned_validator_public_key,
        identity_proof_verified_at: None,
        issued_at: now_rfc3339(),
        expires_at: expires_at.to_rfc3339(),
        reserved_node_id: None,
        used_at: None,
    };
    state.events.push(event(
        None,
        "onboarding_token_issued",
        json!({
            "token_id": record.id.clone(),
            "peer_type": peer_type,
            "expires_at": record.expires_at.clone()
        }),
    ));
    state.onboarding_tokens.push(record);
    save_state(&state_path, &mut state)?;
    Ok(token)
}

pub fn reserve_validator_vpn_onboarding(
    app_context: &AppContext,
    token: &str,
    peer_name: &str,
    role: ValidatorVpnRole,
    assignment_id: Option<&str>,
    validator_identity: Option<&str>,
    validator_public_key: Option<&str>,
    identity_proof: Option<&str>,
    node_id: Option<&str>,
) -> Result<ValidatorVpnInviteAssignment, String> {
    validate_node_name(peer_name)?;
    let _reservation_guard = reservation_lock()
        .lock()
        .map_err(|_| "Validator VPN reservation lock is poisoned".to_string())?;
    let token_hash = hash_onboarding_token(token);
    let state_path = validator_vpn_state_path(app_context)?;
    let mut state = load_or_initialize_state(&state_path)?;
    let token_record = state
        .onboarding_tokens
        .iter()
        .find(|record| {
            record.token_hash == token_hash
                && record.used_at.is_none()
                && record.peer_type == role
                && parse_rfc3339_opt(Some(record.expires_at.as_str()))
                    .map(|expires_at| expires_at > Utc::now())
                    .unwrap_or(false)
        })
        .cloned()
        .ok_or_else(|| "invalid_or_used_token".to_string())?;
    if !onboarding_token_assignment_matches(&token_record, &role, assignment_id, validator_identity)
    {
        return Err("invalid_or_used_token".to_string());
    }
    if role == ValidatorVpnRole::Validator
        && !verify_validator_identity_enrollment_proof(
            &token_record,
            peer_name,
            node_id,
            validator_public_key,
            identity_proof,
        )?
    {
        return Err("invalid_or_used_token".to_string());
    }
    let now = now_rfc3339();
    let existing = state
        .nodes
        .iter()
        .find(|node| node.node_name == peer_name.trim() && node.role == role)
        .cloned();
    let node = if let Some(node) = existing {
        if token_record
            .reserved_node_id
            .as_deref()
            .is_some_and(|reserved_node_id| reserved_node_id != node.id)
        {
            return Err("invalid_or_used_token".to_string());
        }
        if node.status.is_snapshot_active() && node.wg_pubkey.is_some() {
            return Err("peer_name is already enrolled".to_string());
        }
        node
    } else {
        // This reservation backs the coordinator-owned Innernet invite API.
        // Innernet owns its address space and rejects overlapping migrations.
        let authoritative_used = innernet::authoritative_assigned_ips()?;
        let vpn_ip = allocate_next_innernet_ip_excluding(&state, &role, &authoritative_used)?;
        let node = ValidatorVpnNode {
            id: Uuid::new_v4().to_string(),
            role: role.clone(),
            node_name: peer_name.trim().to_string(),
            validator_pubkey: None,
            operator_address: None,
            wg_pubkey: None,
            vpn_ip: vpn_ip.clone(),
            endpoint_host: None,
            endpoint_port: VALIDATOR_VPN_LISTEN_PORT,
            status: ValidatorVpnNodeStatus::Enrolling,
            bootstrap_node: false,
            assigned_at: now.clone(),
            activated_at: None,
            last_vpn_handshake_at: None,
            last_agent_heartbeat_at: None,
            last_consensus_seen_at: None,
            inactive_since: None,
            revoked_at: None,
            created_at: now.clone(),
            updated_at: now.clone(),
        };
        state.nodes.push(node.clone());
        upsert_lease(
            &mut state,
            ValidatorVpnIpLease {
                vpn_ip,
                node_id: Some(node.id.clone()),
                role: role.clone(),
                state: ValidatorVpnLeaseState::Assigned,
                assigned_at: Some(now.clone()),
                tombstoned_until: None,
            },
        );
        node
    };
    state.events.push(event(
        Some(node.id.clone()),
        "enrollment_request_reserved",
        json!({
            "token_id": token_record.id,
            "node_name": node.node_name.clone(),
            "vpn_ip": node.vpn_ip.clone()
        }),
    ));
    if let Some(record) = state
        .onboarding_tokens
        .iter_mut()
        .find(|record| record.id == token_record.id)
    {
        record.reserved_node_id = Some(node.id.clone());
        if role == ValidatorVpnRole::Validator {
            record.identity_proof_verified_at = Some(now_rfc3339());
        }
    }
    save_state(&state_path, &mut state)?;
    Ok(ValidatorVpnInviteAssignment {
        node_id: node.id,
        role,
        vpn_ip: node.vpn_ip,
        expires_at: token_record.expires_at,
    })
}

fn onboarding_token_assignment_matches(
    token_record: &ValidatorVpnOnboardingToken,
    role: &ValidatorVpnRole,
    assignment_id: Option<&str>,
    validator_identity: Option<&str>,
) -> bool {
    role != &ValidatorVpnRole::Validator
        || (token_record.assignment_id.as_deref() == assignment_id.map(str::trim)
            && token_record.assigned_validator_identity.as_deref()
                == validator_identity.map(str::trim))
}

fn validator_identity_proof_message(
    assignment_id: &str,
    validator_identity: &str,
    peer_name: &str,
    node_id: &str,
) -> String {
    format!(
        "synergy-validator-enrollment-proof-v1|{}|{}|{}|{}",
        assignment_id.trim(),
        validator_identity.trim(),
        peer_name.trim(),
        node_id.trim(),
    )
}

fn verify_validator_identity_enrollment_proof(
    token_record: &ValidatorVpnOnboardingToken,
    peer_name: &str,
    node_id: Option<&str>,
    validator_public_key: Option<&str>,
    identity_proof: Option<&str>,
) -> Result<bool, String> {
    let Some(assignment_id) = token_record.assignment_id.as_deref() else {
        return Ok(false);
    };
    let Some(validator_identity) = token_record.assigned_validator_identity.as_deref() else {
        return Ok(false);
    };
    let Some(expected_public_key) = token_record.assigned_validator_public_key.as_deref() else {
        return Ok(false);
    };
    let Some(node_id) = node_id.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(false);
    };
    let Some(provided_public_key) = validator_public_key
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return Ok(false);
    };
    let Some(proof) = identity_proof
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return Ok(false);
    };
    if expected_public_key != provided_public_key {
        return Ok(false);
    }
    let message =
        validator_identity_proof_message(assignment_id, validator_identity, peer_name, node_id);
    Ok(verify_identity_proof(
        validator_identity,
        expected_public_key,
        message.as_bytes(),
        proof,
    )
    .unwrap_or(false))
}

pub fn consume_validator_vpn_onboarding_token(
    app_context: &AppContext,
    token: &str,
    node_id: &str,
) -> Result<(), String> {
    let state_path = validator_vpn_state_path(app_context)?;
    let mut state = load_or_initialize_state(&state_path)?;
    let token_hash = hash_onboarding_token(token);
    let record = state
        .onboarding_tokens
        .iter_mut()
        .find(|record| record.token_hash == token_hash && record.used_at.is_none())
        .ok_or_else(|| "invalid_or_used_token".to_string())?;
    record.used_at = Some(now_rfc3339());
    if let Some(node) = state.nodes.iter_mut().find(|node| node.id == node_id) {
        if node.status == ValidatorVpnNodeStatus::Enrolling {
            node.status = ValidatorVpnNodeStatus::Configuring;
            node.updated_at = now_rfc3339();
        }
    } else {
        return Err(format!("Validator VPN node not found: {node_id}"));
    }
    state.events.push(event(
        Some(node_id.to_string()),
        "onboarding_token_redeemed",
        json!({ "token_hash": token_hash }),
    ));
    save_state(&state_path, &mut state)
}

pub fn consume_reserved_validator_vpn_onboarding_token(
    app_context: &AppContext,
    node_id: &str,
) -> Result<(), String> {
    let state_path = validator_vpn_state_path(app_context)?;
    let mut state = load_or_initialize_state(&state_path)?;
    let record = state
        .onboarding_tokens
        .iter_mut()
        .find(|record| record.reserved_node_id.as_deref() == Some(node_id))
        .ok_or_else(|| "Innernet enrollment token reservation was not found.".to_string())?;
    if record.used_at.is_none() {
        record.used_at = Some(now_rfc3339());
    }
    if let Some(node) = state.nodes.iter_mut().find(|node| node.id == node_id) {
        if node.status == ValidatorVpnNodeStatus::Enrolling {
            node.status = ValidatorVpnNodeStatus::Configuring;
            node.updated_at = now_rfc3339();
        }
    } else {
        return Err(format!("Validator VPN node not found: {node_id}"));
    }
    state.events.push(event(
        Some(node_id.to_string()),
        "onboarding_token_redeemed",
        json!({ "reservation": "innernet" }),
    ));
    save_state(&state_path, &mut state)
}

pub fn record_validator_vpn_config_ack(
    app_context: &AppContext,
    node_id: String,
    request: ValidatorVpnConfigAckRequest,
) -> Result<ValidatorVpnPropagationStatus, String> {
    let state_path = validator_vpn_state_path(app_context)?;
    let mut state = load_or_initialize_state(&state_path)?;
    let latest_generation = state
        .peer_snapshots
        .last()
        .map(|snapshot| snapshot.generation)
        .ok_or_else(|| "No current validator VPN snapshot exists".to_string())?;
    if request.generation != latest_generation {
        return Err(format!(
            "Validator VPN config generation {} is not current; latest generation is {}",
            request.generation, latest_generation
        ));
    }
    if request.peers_handshaked < MIN_VERIFIED_HANDSHAKES {
        return Err(format!(
            "Validator VPN acknowledgement requires at least {} verified peer handshake",
            MIN_VERIFIED_HANDSHAKES
        ));
    }
    let snapshot = state
        .peer_snapshots
        .iter()
        .find(|snapshot| snapshot.generation == request.generation)
        .ok_or_else(|| {
            format!(
                "Validator VPN config generation {} not found",
                request.generation
            )
        })?;
    if !snapshot
        .validators
        .iter()
        .any(|peer| peer.node_id == node_id)
    {
        return Err(
            "Only validators included in the config version may acknowledge it".to_string(),
        );
    }
    let ack = ValidatorVpnConfigAck {
        node_id: node_id.clone(),
        generation: request.generation,
        applied: request.applied,
        interface_up: request.interface_up,
        peers_handshaked: request.peers_handshaked,
        error: clean_optional(request.error),
        acknowledged_at: now_rfc3339(),
    };
    if let Some(existing) = state
        .config_acks
        .iter_mut()
        .find(|existing| existing.node_id == node_id && existing.generation == request.generation)
    {
        *existing = ack.clone();
    } else {
        state.config_acks.push(ack.clone());
    }
    state.events.push(event(
        Some(node_id),
        "config_propagation_acknowledged",
        json!({
            "generation": ack.generation,
            "applied": ack.applied,
            "interface_up": ack.interface_up,
            "peers_handshaked": ack.peers_handshaked,
            "error": ack.error
        }),
    ));
    let propagation = propagation_status_for(&state, request.generation);
    save_state(&state_path, &mut state)?;
    Ok(propagation)
}

pub fn validator_vpn_propagation_status(
    app_context: &AppContext,
    generation: u64,
) -> Result<ValidatorVpnPropagationStatus, String> {
    let state_path = validator_vpn_state_path(app_context)?;
    let state = load_or_initialize_state(&state_path)?;
    if !state
        .peer_snapshots
        .iter()
        .any(|snapshot| snapshot.generation == generation)
    {
        return Err(format!(
            "Validator VPN config generation {generation} not found"
        ));
    }
    Ok(propagation_status_for(&state, generation))
}

fn propagation_status_for(
    state: &ValidatorVpnStateFile,
    generation: u64,
) -> ValidatorVpnPropagationStatus {
    let snapshot_validator_ids = state
        .peer_snapshots
        .iter()
        .find(|snapshot| snapshot.generation == generation)
        .map(|snapshot| {
            snapshot
                .validators
                .iter()
                .map(|peer| peer.node_id.clone())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let expected_validator_ids = snapshot_validator_ids
        .iter()
        .filter(|node_id| {
            state.nodes.iter().any(|node| {
                node.id == **node_id
                    && node.role == ValidatorVpnRole::Validator
                    && node.status.is_snapshot_active()
                    && node.wg_pubkey.is_some()
            })
        })
        .cloned()
        .collect::<Vec<_>>();
    let mut acknowledged_validator_ids = Vec::new();
    let mut failed_validator_ids = Vec::new();
    for node_id in &expected_validator_ids {
        if let Some(ack) = state
            .config_acks
            .iter()
            .find(|ack| ack.node_id == *node_id && ack.generation == generation)
        {
            if ack.applied
                && ack.interface_up
                && ack.peers_handshaked >= MIN_VERIFIED_HANDSHAKES
                && ack.error.is_none()
            {
                acknowledged_validator_ids.push(node_id.clone());
            } else {
                failed_validator_ids.push(node_id.clone());
            }
        }
    }
    let pending_validator_ids = expected_validator_ids
        .iter()
        .filter(|node_id| !acknowledged_validator_ids.contains(node_id))
        .cloned()
        .collect::<Vec<_>>();
    ValidatorVpnPropagationStatus {
        generation,
        required_acknowledgements: expected_validator_ids.len(),
        complete: pending_validator_ids.is_empty() && failed_validator_ids.is_empty(),
        expected_validator_ids,
        acknowledged_validator_ids,
        pending_validator_ids,
        failed_validator_ids,
    }
}

pub fn validator_vpn_agent_plan() -> ValidatorVpnAgentPlan {
    ValidatorVpnAgentPlan {
        private_key_path: "<validator-workspace>/validator-vpn/private.key".to_string(),
        public_key_path: "<validator-workspace>/validator-vpn/public.key".to_string(),
        interface: VALIDATOR_VPN_INTERFACE.to_string(),
        listen_port: VALIDATOR_VPN_LISTEN_PORT,
        mtu: VALIDATOR_VPN_MTU,
        peer_update_interval: "30s".to_string(),
        persistent_keepalive: 25,
        private_key_policy:
            "generate locally in the validator workspace with WireGuard tools, chmod 0600, never upload or log".to_string(),
        update_method: "verify signed snapshot, render exact /32 peers, apply with wg syncconf"
            .to_string(),
    }
}

pub fn create_validator_vpn_challenge(
    app_context: &AppContext,
    request: ValidatorVpnChallengeRequest,
) -> Result<ValidatorVpnChallengeResponse, String> {
    validate_node_name(&request.node_name)?;
    let state_path = validator_vpn_state_path(app_context)?;
    let mut state = load_or_initialize_state(&state_path)?;
    let now = Utc::now();
    let challenge = ValidatorVpnEnrollmentChallenge {
        id: Uuid::new_v4().to_string(),
        challenge: format!(
            "synergy-validator-vpn:{}:{}:{}",
            request.role.as_str(),
            request.node_name.trim(),
            Uuid::new_v4()
        ),
        role: request.role,
        node_name: Some(request.node_name.trim().to_string()),
        validator_pubkey: clean_optional(request.validator_pubkey),
        operator_address: clean_optional(request.operator_address),
        expires_at: (now + Duration::minutes(CHALLENGE_TTL_MINUTES)).to_rfc3339(),
        consumed_at: None,
        created_at: now.to_rfc3339(),
    };
    let response = ValidatorVpnChallengeResponse {
        challenge_id: challenge.id.clone(),
        challenge: challenge.challenge.clone(),
        expires_at: challenge.expires_at.clone(),
    };
    state.events.push(event(
        None,
        "enrollment_challenge_created",
        json!({
            "challenge_id": challenge.id.clone(),
            "role": challenge.role.clone(),
            "node_name": challenge.node_name.clone()
        }),
    ));
    state.enrollment_challenges.push(challenge);
    save_state(&state_path, &mut state)?;
    Ok(response)
}

pub fn enroll_validator_vpn_node(
    app_context: &AppContext,
    request: ValidatorVpnEnrollRequest,
) -> Result<ValidatorVpnEnrollResponse, String> {
    validate_node_name(&request.node_name)?;
    validate_wg_public_key(&request.wg_pubkey)?;
    if let Some(endpoint_host) = request.endpoint_host.as_deref() {
        validate_endpoint_host(endpoint_host)?;
    }
    if request.role == ValidatorVpnRole::Validator {
        let validator_address = request
            .validator_pubkey
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                "Validator VPN enrollment requires the synv1 validator address".to_string()
            })?;
        validate_validator_identity(validator_address)?;
    }

    let state_path = validator_vpn_state_path(app_context)?;
    let mut state = load_or_initialize_state(&state_path)?;
    let challenge_index = state
        .enrollment_challenges
        .iter()
        .position(|challenge| challenge.id == request.challenge_id)
        .ok_or_else(|| "Enrollment challenge not found".to_string())?;
    validate_challenge(&state.enrollment_challenges[challenge_index], &request)?;
    verify_enrollment_signature(&state.enrollment_challenges[challenge_index], &request)?;

    if request.role == ValidatorVpnRole::Validator {
        verify_validator_eligibility(&request)?;
    }

    let node_id = upsert_enrolled_node(&mut state, request.clone())?;
    state.enrollment_challenges[challenge_index].consumed_at = Some(now_rfc3339());
    refresh_health_statuses(&mut state);
    let signing_key = coordinator_signing_key().ok_or_else(|| {
        "SYNERGY_VALIDATOR_VPN_COORDINATOR_SIGNING_KEY is required before enrollment can generate a signed peer snapshot".to_string()
    })?;
    let snapshot = generate_peer_snapshot(&mut state, &signing_key)?;
    let node = state
        .nodes
        .iter()
        .find(|node| node.id == node_id)
        .cloned()
        .ok_or_else(|| "enrolled node disappeared from registry".to_string())?;
    let response = ValidatorVpnEnrollResponse {
        node_id,
        role: node.role,
        vpn_ip: node.vpn_ip,
        interface: VALIDATOR_VPN_INTERFACE.to_string(),
        listen_port: VALIDATOR_VPN_LISTEN_PORT,
        peer_snapshot_generation: snapshot.generation,
        peer_snapshot_url: SNAPSHOT_URL.to_string(),
        coordinator_public_signing_key: coordinator_public_signing_key(),
        relayers: snapshot.relayers,
    };
    save_state(&state_path, &mut state)?;
    Ok(response)
}

pub fn register_validator_vpn_relayer(
    app_context: &AppContext,
    request: ValidatorVpnRelayerRegistrationRequest,
) -> Result<ValidatorVpnNode, String> {
    validate_node_name(&request.node_name)?;
    validate_wg_public_key(&request.wg_pubkey)?;
    if let Some(endpoint_host) = request.endpoint_host.as_deref() {
        validate_endpoint_host(endpoint_host)?;
    }
    let state_path = validator_vpn_state_path(app_context)?;
    let mut state = load_or_initialize_state(&state_path)?;
    if state
        .nodes
        .iter()
        .any(|node| node.wg_pubkey.as_deref() == Some(request.wg_pubkey.as_str()))
    {
        return Err("WireGuard public key is already enrolled".to_string());
    }
    let vpn_ip = match request.vpn_ip.clone() {
        Some(vpn_ip) => vpn_ip,
        None => next_relayer_ip(&state)
            .ok_or_else(|| "Relayer VPN IP range is exhausted".to_string())?,
    };
    validate_relayer_ip(&vpn_ip)?;
    let now = now_rfc3339();
    let node =
        match state.nodes.iter_mut().find(|node| {
            node.node_name == request.node_name && node.role == ValidatorVpnRole::Relayer
        }) {
            Some(node) => {
                if node.vpn_ip != vpn_ip {
                    return Err(format!(
                        "{} is reserved for {}, not {}",
                        node.node_name, node.vpn_ip, vpn_ip
                    ));
                }
                node.wg_pubkey = Some(request.wg_pubkey);
                node.endpoint_host = clean_optional(request.endpoint_host);
                node.endpoint_port = request.endpoint_port;
                node.status = ValidatorVpnNodeStatus::Connected;
                node.updated_at = now.clone();
                node.clone()
            }
            None => {
                let node = ValidatorVpnNode {
                    id: Uuid::new_v4().to_string(),
                    role: ValidatorVpnRole::Relayer,
                    node_name: request.node_name.trim().to_string(),
                    validator_pubkey: None,
                    operator_address: None,
                    wg_pubkey: Some(request.wg_pubkey),
                    vpn_ip: vpn_ip.clone(),
                    endpoint_host: clean_optional(request.endpoint_host),
                    endpoint_port: request.endpoint_port,
                    status: ValidatorVpnNodeStatus::Connected,
                    bootstrap_node: false,
                    assigned_at: now.clone(),
                    activated_at: None,
                    last_vpn_handshake_at: None,
                    last_agent_heartbeat_at: Some(now.clone()),
                    last_consensus_seen_at: None,
                    inactive_since: None,
                    revoked_at: None,
                    created_at: now.clone(),
                    updated_at: now.clone(),
                };
                state.nodes.push(node.clone());
                node
            }
        };
    upsert_lease(
        &mut state,
        ValidatorVpnIpLease {
            vpn_ip: node.vpn_ip.clone(),
            node_id: Some(node.id.clone()),
            role: ValidatorVpnRole::Relayer,
            state: ValidatorVpnLeaseState::Assigned,
            assigned_at: Some(now),
            tombstoned_until: None,
        },
    );
    let signing_key = coordinator_signing_key().ok_or_else(|| {
        "SYNERGY_VALIDATOR_VPN_COORDINATOR_SIGNING_KEY is required before relayer registration can generate a signed peer snapshot".to_string()
    })?;
    generate_peer_snapshot(&mut state, &signing_key)?;
    save_state(&state_path, &mut state)?;
    Ok(node)
}

pub fn import_validator_vpn_bootstrap_nodes(
    app_context: &AppContext,
    request: ValidatorVpnBootstrapImportRequest,
) -> Result<ValidatorVpnBootstrapImportResponse, String> {
    if request.nodes.is_empty() {
        return Err("At least one bootstrap node is required".to_string());
    }
    let state_path = validator_vpn_state_path(app_context)?;
    let mut state = load_or_initialize_state(&state_path)?;
    let now = now_rfc3339();
    let mut imported = 0usize;
    let mut updated = 0usize;

    for input in request.nodes {
        validate_node_name(&input.node_name)?;
        validate_wg_public_key(&input.wg_pubkey)?;
        match &input.role {
            ValidatorVpnRole::Validator => validate_validator_ip(&input.vpn_ip)?,
            ValidatorVpnRole::Relayer => validate_relayer_ip(&input.vpn_ip)?,
        }
        let (endpoint_host, endpoint_port) = bootstrap_endpoint(&input)?;
        if let Some(host) = endpoint_host.as_deref() {
            validate_endpoint_host(host)?;
        }

        let is_bootstrap = bootstrap_assignments().iter().any(|(role, name, ip)| {
            role == &input.role && *name == input.node_name.trim() && *ip == input.vpn_ip
        });
        if !is_bootstrap {
            return Err(format!(
                "{} at {} is not part of the canonical bootstrap validator VPN baseline",
                input.node_name, input.vpn_ip
            ));
        }

        let node_index = state
            .nodes
            .iter()
            .position(|node| node.node_name == input.node_name && node.role == input.role);
        let validator_address = if input.role == ValidatorVpnRole::Validator {
            bootstrap_validator_address(input.node_name.trim()).map(str::to_string)
        } else {
            None
        };
        let node_id = match node_index {
            Some(index) => {
                let node = &mut state.nodes[index];
                if node.vpn_ip != input.vpn_ip {
                    return Err(format!(
                        "{} is reserved for {}, not {}",
                        node.node_name, node.vpn_ip, input.vpn_ip
                    ));
                }
                node.validator_pubkey = validator_address.clone();
                node.wg_pubkey = Some(input.wg_pubkey.clone());
                node.endpoint_host = endpoint_host.clone();
                node.endpoint_port = endpoint_port;
                node.status = ValidatorVpnNodeStatus::Connected;
                node.bootstrap_node = true;
                node.last_agent_heartbeat_at = Some(now.clone());
                node.updated_at = now.clone();
                updated += 1;
                node.id.clone()
            }
            None => {
                let node_id = format!("bootstrap-{}", input.node_name.trim());
                state.nodes.push(ValidatorVpnNode {
                    id: node_id.clone(),
                    role: input.role.clone(),
                    node_name: input.node_name.trim().to_string(),
                    validator_pubkey: validator_address,
                    operator_address: None,
                    wg_pubkey: Some(input.wg_pubkey.clone()),
                    vpn_ip: input.vpn_ip.clone(),
                    endpoint_host: endpoint_host.clone(),
                    endpoint_port,
                    status: ValidatorVpnNodeStatus::Connected,
                    bootstrap_node: true,
                    assigned_at: now.clone(),
                    activated_at: None,
                    last_vpn_handshake_at: None,
                    last_agent_heartbeat_at: Some(now.clone()),
                    last_consensus_seen_at: None,
                    inactive_since: None,
                    revoked_at: None,
                    created_at: now.clone(),
                    updated_at: now.clone(),
                });
                imported += 1;
                node_id
            }
        };

        upsert_lease(
            &mut state,
            ValidatorVpnIpLease {
                vpn_ip: input.vpn_ip,
                node_id: Some(node_id.clone()),
                role: input.role,
                state: ValidatorVpnLeaseState::Assigned,
                assigned_at: Some(now.clone()),
                tombstoned_until: None,
            },
        );
        state.events.push(event(
            Some(node_id),
            "bootstrap_node_imported",
            json!({ "node_name": input.node_name.trim() }),
        ));
    }

    refresh_health_statuses(&mut state);
    let latest_generation = if request.regenerate_snapshot.unwrap_or(true) {
        let signing_key = coordinator_signing_key().ok_or_else(|| {
            "SYNERGY_VALIDATOR_VPN_COORDINATOR_SIGNING_KEY is required before bootstrap import can generate a signed peer snapshot".to_string()
        })?;
        Some(generate_peer_snapshot(&mut state, &signing_key)?.generation)
    } else {
        state
            .peer_snapshots
            .last()
            .map(|snapshot| snapshot.generation)
    };
    let nodes = state.nodes.clone();
    save_state(&state_path, &mut state)?;
    Ok(ValidatorVpnBootstrapImportResponse {
        imported,
        updated,
        latest_generation,
        nodes,
    })
}

pub fn get_latest_validator_vpn_snapshot(
    app_context: &AppContext,
) -> Result<ValidatorVpnPeerSnapshot, String> {
    let state_path = validator_vpn_state_path(app_context)?;
    let mut state = load_or_initialize_state(&state_path)?;
    rotate_legacy_snapshot_with_operator_addresses(&state_path, &mut state)?;
    state
        .peer_snapshots
        .last()
        .cloned()
        .ok_or_else(|| "No validator VPN peer snapshot has been generated".to_string())
}

pub fn get_validator_vpn_snapshot(
    app_context: &AppContext,
    generation: u64,
) -> Result<ValidatorVpnPeerSnapshot, String> {
    let state_path = validator_vpn_state_path(app_context)?;
    let state = load_or_initialize_state(&state_path)?;
    let snapshot = state
        .peer_snapshots
        .into_iter()
        .find(|snapshot| snapshot.generation == generation)
        .ok_or_else(|| format!("Validator VPN peer snapshot generation {generation} not found"))?;
    if snapshot_contains_operator_address(&snapshot) {
        return Err(
            "Requested validator VPN snapshot contains legacy operator identity data; request the newly generated latest snapshot instead."
                .to_string(),
        );
    }
    Ok(snapshot)
}

pub fn record_validator_vpn_heartbeat(
    app_context: &AppContext,
    node_id: String,
    request: ValidatorVpnHeartbeatRequest,
) -> Result<ValidatorVpnNode, String> {
    let state_path = validator_vpn_state_path(app_context)?;
    let mut state = load_or_initialize_state(&state_path)?;
    let now = now_rfc3339();
    let node = state
        .nodes
        .iter_mut()
        .find(|node| node.id == node_id)
        .ok_or_else(|| format!("Validator VPN node not found: {node_id}"))?;
    node.last_agent_heartbeat_at = Some(now.clone());
    if let Some(handshake) = clean_optional(request.last_vpn_handshake_at) {
        node.last_vpn_handshake_at = Some(handshake);
    }
    if let Some(consensus) = clean_optional(request.last_consensus_seen_at) {
        node.last_consensus_seen_at = Some(consensus);
    }
    match node.status {
        ValidatorVpnNodeStatus::Pending if node.role == ValidatorVpnRole::Validator => {
            node.status = ValidatorVpnNodeStatus::Syncing;
            node.inactive_since = None;
        }
        ValidatorVpnNodeStatus::Degraded | ValidatorVpnNodeStatus::Inactive
            if node.role == ValidatorVpnRole::Validator =>
        {
            node.status = ValidatorVpnNodeStatus::Syncing;
            node.inactive_since = None;
        }
        ValidatorVpnNodeStatus::Degraded | ValidatorVpnNodeStatus::Inactive => {
            node.status = ValidatorVpnNodeStatus::Connected;
            node.inactive_since = None;
        }
        _ => {}
    }
    node.updated_at = now;
    let updated = node.clone();
    refresh_health_statuses(&mut state);
    save_state(&state_path, &mut state)?;
    Ok(updated)
}

pub fn render_wireguard_peer_config(
    local_node_id: &str,
    snapshot: &ValidatorVpnPeerSnapshot,
) -> Result<String, String> {
    validate_peer_snapshot(snapshot, None)?;
    let local_is_validator = snapshot
        .validators
        .iter()
        .any(|node| node.node_id == local_node_id);
    let local_is_relayer = snapshot
        .relayers
        .iter()
        .any(|node| node.node_id == local_node_id);
    if !local_is_validator && !local_is_relayer {
        return Err(format!("Local node {local_node_id} is not in snapshot"));
    }

    let mut peers = Vec::new();
    if local_is_validator {
        peers.extend(
            snapshot
                .validators
                .iter()
                .filter(|node| node.node_id != local_node_id),
        );
        peers.extend(snapshot.relayers.iter());
    } else {
        peers.extend(snapshot.validators.iter());
    }

    let mut rendered = String::new();
    for peer in peers {
        rendered.push_str("[Peer]\n");
        rendered.push_str(&format!("PublicKey = {}\n", peer.wg_pubkey));
        rendered.push_str(&format!("AllowedIPs = {}\n", peer.vpn_ip));
        if let Some(endpoint) = peer.endpoint.as_deref() {
            rendered.push_str(&format!("Endpoint = {endpoint}\n"));
            rendered.push_str("PersistentKeepalive = 25\n");
        }
        rendered.push('\n');
    }
    let private_supernet_route = format!("AllowedIPs = {}", VALIDATOR_VPN_CIDR);
    let full_tunnel_route = format!("AllowedIPs = {}", "0.0.0.0/0");
    if rendered.contains(&private_supernet_route) || rendered.contains(&full_tunnel_route) {
        return Err("Rendered peer config contains a broad route".to_string());
    }
    Ok(rendered)
}

pub fn validate_peer_snapshot(
    snapshot: &ValidatorVpnPeerSnapshot,
    signing_key: Option<&str>,
) -> Result<(), String> {
    if snapshot.network != VALIDATOR_VPN_NETWORK {
        return Err(format!(
            "Unexpected validator VPN network {}",
            snapshot.network
        ));
    }
    if snapshot.cidr != VALIDATOR_VPN_CIDR {
        return Err(format!("Unexpected validator VPN CIDR {}", snapshot.cidr));
    }
    if snapshot.signature.trim().is_empty() {
        return Err("Peer snapshot is unsigned".to_string());
    }
    if let Some(key) = signing_key {
        validate_peer_snapshot_signature(snapshot, Some(key), None)?;
    }

    let mut ips = HashSet::new();
    let mut keys = HashSet::new();
    for relayer in &snapshot.relayers {
        validate_relayer_ip(&relayer.vpn_ip)?;
        validate_wg_public_key(&relayer.wg_pubkey)?;
        if !ips.insert(relayer.vpn_ip.clone()) {
            return Err(format!("Duplicate VPN IP {}", relayer.vpn_ip));
        }
        if !keys.insert(relayer.wg_pubkey.clone()) {
            return Err(format!(
                "Duplicate WireGuard public key {}",
                relayer.wg_pubkey
            ));
        }
    }
    for validator in &snapshot.validators {
        validate_validator_ip(&validator.vpn_ip)?;
        validate_wg_public_key(&validator.wg_pubkey)?;
        let validator_address = validator
            .validator_pubkey
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                format!(
                    "Validator VPN peer {} is missing its synv1 validator address",
                    validator.node_id
                )
            })?;
        validate_validator_identity(validator_address)?;
        if !ips.insert(validator.vpn_ip.clone()) {
            return Err(format!("Duplicate VPN IP {}", validator.vpn_ip));
        }
        if !keys.insert(validator.wg_pubkey.clone()) {
            return Err(format!(
                "Duplicate WireGuard public key {}",
                validator.wg_pubkey
            ));
        }
    }
    Ok(())
}

pub fn validate_peer_snapshot_with_configured_signature(
    snapshot: &ValidatorVpnPeerSnapshot,
) -> Result<(), String> {
    let signing_key = coordinator_signing_key();
    let public_key = validator_vpn_coordinator_public_signing_key()
        .or_else(|| snapshot.coordinator_public_signing_key.clone());
    validate_peer_snapshot_signature(snapshot, signing_key.as_deref(), public_key.as_deref())?;
    validate_peer_snapshot(snapshot, None)
}

fn upsert_enrolled_node(
    state: &mut ValidatorVpnStateFile,
    request: ValidatorVpnEnrollRequest,
) -> Result<String, String> {
    let now = now_rfc3339();
    let existing_by_name = state
        .nodes
        .iter()
        .position(|node| node.node_name == request.node_name && node.role == request.role);
    let existing_by_wg = state
        .nodes
        .iter()
        .position(|node| node.wg_pubkey.as_deref() == Some(request.wg_pubkey.as_str()));
    if let (Some(name_index), Some(wg_index)) = (existing_by_name, existing_by_wg) {
        if name_index != wg_index {
            return Err("WireGuard public key is already enrolled to a different node".to_string());
        }
    }
    let existing = existing_by_name.or(existing_by_wg);
    if let Some(index) = existing {
        validate_existing_wireguard_enrollment(&state.nodes[index], &request)?;
    }
    let vpn_ip = match existing {
        Some(index) => state.nodes[index].vpn_ip.clone(),
        None if request.role == ValidatorVpnRole::Validator => allocate_next_validator_ip(state)?,
        None => {
            return Err("Relayers must be registered by an admin before enrollment".to_string());
        }
    };
    let node_id = match existing {
        Some(index) => {
            let node = &mut state.nodes[index];
            if !node.bootstrap_node {
                node.node_name = request.node_name.trim().to_string();
            }
            node.validator_pubkey = clean_optional(request.validator_pubkey);
            node.operator_address = clean_optional(request.operator_address);
            node.wg_pubkey = Some(request.wg_pubkey);
            node.endpoint_host = clean_optional(request.endpoint_host);
            node.endpoint_port = request.endpoint_port;
            node.status = enrolled_node_status(request.role.clone(), Some(node));
            node.last_agent_heartbeat_at = Some(now.clone());
            node.updated_at = now.clone();
            node.id.clone()
        }
        None => {
            let node_id = Uuid::new_v4().to_string();
            state.nodes.push(ValidatorVpnNode {
                id: node_id.clone(),
                role: request.role.clone(),
                node_name: request.node_name.trim().to_string(),
                validator_pubkey: clean_optional(request.validator_pubkey),
                operator_address: clean_optional(request.operator_address),
                wg_pubkey: Some(request.wg_pubkey),
                vpn_ip: vpn_ip.clone(),
                endpoint_host: clean_optional(request.endpoint_host),
                endpoint_port: request.endpoint_port,
                status: enrolled_node_status(request.role.clone(), None),
                bootstrap_node: false,
                assigned_at: now.clone(),
                activated_at: None,
                last_vpn_handshake_at: None,
                last_agent_heartbeat_at: Some(now.clone()),
                last_consensus_seen_at: None,
                inactive_since: None,
                revoked_at: None,
                created_at: now.clone(),
                updated_at: now.clone(),
            });
            node_id
        }
    };
    upsert_lease(
        state,
        ValidatorVpnIpLease {
            vpn_ip,
            node_id: Some(node_id.clone()),
            role: request.role,
            state: ValidatorVpnLeaseState::Assigned,
            assigned_at: Some(now),
            tombstoned_until: None,
        },
    );
    state.events.push(event(
        Some(node_id.clone()),
        "node_enrolled",
        json!({
            "role": state
                .nodes
                .iter()
                .find(|node| node.id == node_id)
                .map(|node| node.role.clone())
        }),
    ));
    Ok(node_id)
}

fn validate_existing_wireguard_enrollment(
    node: &ValidatorVpnNode,
    request: &ValidatorVpnEnrollRequest,
) -> Result<(), String> {
    if node.role != request.role {
        return Err(
            "WireGuard public key is already enrolled for a different VPN role".to_string(),
        );
    }

    let request_node_name = request.node_name.trim();
    if node.bootstrap_node && node.node_name != request_node_name {
        return Err("WireGuard public key is already enrolled to a bootstrap VPN node".to_string());
    }

    if request.role != ValidatorVpnRole::Validator && node.node_name != request_node_name {
        return Err("WireGuard public key is already enrolled to a different node".to_string());
    }

    if request.role == ValidatorVpnRole::Validator {
        let requested_validator = normalized_optional_str(request.validator_pubkey.as_deref())
            .ok_or_else(|| {
                "Validator VPN enrollment requires the synv1 validator address".to_string()
            })?;
        if let Some(existing_validator) = normalized_optional_str(node.validator_pubkey.as_deref())
        {
            if existing_validator != requested_validator {
                return Err(
                    "WireGuard public key is already enrolled to a different validator".to_string(),
                );
            }
        } else if node.bootstrap_node {
            return Err(
                "WireGuard public key is already enrolled to a bootstrap validator without a recoverable validator identity"
                    .to_string(),
            );
        }
    }

    if optional_values_conflict(
        node.operator_address.as_deref(),
        request.operator_address.as_deref(),
    ) {
        return Err(
            "WireGuard public key is already enrolled to a different operator wallet".to_string(),
        );
    }

    Ok(())
}

fn optional_values_conflict(existing: Option<&str>, requested: Option<&str>) -> bool {
    match (
        normalized_optional_str(existing),
        normalized_optional_str(requested),
    ) {
        (Some(existing), Some(requested)) => existing != requested,
        _ => false,
    }
}

fn generate_peer_snapshot(
    state: &mut ValidatorVpnStateFile,
    signing_key: &str,
) -> Result<ValidatorVpnPeerSnapshot, String> {
    let generation = state
        .peer_snapshots
        .last()
        .map(|snapshot| snapshot.generation + 1)
        .unwrap_or(1);
    let mut relayers = Vec::new();
    let mut validators = Vec::new();
    let mut removed = Vec::new();
    for node in &state.nodes {
        if node.status.is_snapshot_active() {
            if let Some(wg_pubkey) = node.wg_pubkey.as_deref() {
                let peer = peer_record(node, wg_pubkey);
                match node.role {
                    ValidatorVpnRole::Relayer => relayers.push(peer),
                    ValidatorVpnRole::Validator => validators.push(peer),
                }
            }
        } else if matches!(
            node.status,
            ValidatorVpnNodeStatus::Inactive
                | ValidatorVpnNodeStatus::Quarantined
                | ValidatorVpnNodeStatus::Jailed
                | ValidatorVpnNodeStatus::Removed
                | ValidatorVpnNodeStatus::Revoked
        ) {
            removed.push(ValidatorVpnRemovedPeer {
                node_id: node.id.clone(),
                vpn_ip: node.vpn_ip.clone(),
                reason: format!("{:?}", node.status).to_ascii_lowercase(),
            });
        }
    }
    relayers.sort_by(|left, right| left.vpn_ip.cmp(&right.vpn_ip));
    validators.sort_by(|left, right| left.vpn_ip.cmp(&right.vpn_ip));
    let mut snapshot = ValidatorVpnPeerSnapshot {
        generation,
        network: VALIDATOR_VPN_NETWORK.to_string(),
        cidr: VALIDATOR_VPN_CIDR.to_string(),
        created_at: now_rfc3339(),
        coordinator_public_signing_key: validator_vpn_coordinator_public_signing_key(),
        relayers,
        validators,
        removed,
        signature: String::new(),
    };
    validate_peer_snapshot_shape(&snapshot)?;
    snapshot.signature = sign_snapshot(&snapshot, signing_key)?;
    validate_peer_snapshot(&snapshot, Some(signing_key))?;
    state.peer_snapshots.push(snapshot.clone());
    state.events.push(event(
        None,
        "peer_snapshot_generated",
        json!({ "generation": generation }),
    ));
    Ok(snapshot)
}

fn peer_record(node: &ValidatorVpnNode, wg_pubkey: &str) -> ValidatorVpnPeerRecord {
    ValidatorVpnPeerRecord {
        node_id: node.id.clone(),
        node_name: node.node_name.clone(),
        vpn_ip: node.vpn_ip.clone(),
        wg_pubkey: wg_pubkey.to_string(),
        endpoint: node
            .endpoint_host
            .as_deref()
            .map(|host| format!("{host}:{}", node.endpoint_port)),
        status: format!("{:?}", node.status).to_ascii_lowercase(),
        validator_pubkey: node.validator_pubkey.clone(),
        // Operator wallets are enrollment authorization data, not peer routing
        // data. Peer snapshots are distributed to every VPN member.
        operator_address: None,
    }
}

fn snapshot_contains_operator_address(snapshot: &ValidatorVpnPeerSnapshot) -> bool {
    snapshot
        .relayers
        .iter()
        .chain(snapshot.validators.iter())
        .any(|peer| peer.operator_address.is_some())
}

fn rotate_legacy_snapshot_with_operator_addresses(
    state_path: &Path,
    state: &mut ValidatorVpnStateFile,
) -> Result<(), String> {
    let Some(latest) = state.peer_snapshots.last() else {
        return Ok(());
    };
    if !snapshot_contains_operator_address(latest) {
        return Ok(());
    }
    let signing_key = coordinator_signing_key().ok_or_else(|| {
        "Legacy validator VPN snapshot contains operator identity data. Configure SYNERGY_VALIDATOR_VPN_COORDINATOR_SIGNING_KEY to rotate a redacted snapshot before serving it."
            .to_string()
    })?;
    let generation = generate_peer_snapshot(state, &signing_key)?.generation;
    state.events.push(event(
        None,
        "peer_snapshot_operator_identity_redacted",
        json!({ "generation": generation }),
    ));
    save_state(state_path, state)
}

fn enrolled_node_status(
    role: ValidatorVpnRole,
    existing: Option<&ValidatorVpnNode>,
) -> ValidatorVpnNodeStatus {
    if role == ValidatorVpnRole::Relayer {
        return ValidatorVpnNodeStatus::Connected;
    }
    if existing.map(|node| node.bootstrap_node).unwrap_or(false) {
        return ValidatorVpnNodeStatus::Connected;
    }
    match existing.map(|node| &node.status) {
        Some(ValidatorVpnNodeStatus::Active) => ValidatorVpnNodeStatus::Active,
        Some(ValidatorVpnNodeStatus::Eligible) => ValidatorVpnNodeStatus::Eligible,
        Some(ValidatorVpnNodeStatus::Syncing) => ValidatorVpnNodeStatus::Syncing,
        Some(ValidatorVpnNodeStatus::Jailed) => ValidatorVpnNodeStatus::Jailed,
        Some(ValidatorVpnNodeStatus::Removed) => ValidatorVpnNodeStatus::Removed,
        Some(ValidatorVpnNodeStatus::Quarantined) => ValidatorVpnNodeStatus::Quarantined,
        Some(ValidatorVpnNodeStatus::Revoked) => ValidatorVpnNodeStatus::Revoked,
        _ => ValidatorVpnNodeStatus::Pending,
    }
}

fn validate_peer_snapshot_shape(snapshot: &ValidatorVpnPeerSnapshot) -> Result<(), String> {
    validate_peer_snapshot(
        &ValidatorVpnPeerSnapshot {
            signature: "shape-only".to_string(),
            ..snapshot.clone()
        },
        None,
    )
}

#[derive(Serialize)]
struct ValidatorVpnSnapshotSigningPayload<'a> {
    generation: u64,
    network: &'a str,
    cidr: &'a str,
    created_at: &'a str,
    relayers: &'a [ValidatorVpnPeerRecord],
    validators: &'a [ValidatorVpnPeerRecord],
    removed: &'a [ValidatorVpnRemovedPeer],
}

fn snapshot_signing_payload_bytes(snapshot: &ValidatorVpnPeerSnapshot) -> Result<Vec<u8>, String> {
    let payload = ValidatorVpnSnapshotSigningPayload {
        generation: snapshot.generation,
        network: &snapshot.network,
        cidr: &snapshot.cidr,
        created_at: &snapshot.created_at,
        relayers: &snapshot.relayers,
        validators: &snapshot.validators,
        removed: &snapshot.removed,
    };
    serde_json::to_vec(&payload)
        .map_err(|error| format!("Failed to encode snapshot signing payload: {error}"))
}

fn sign_snapshot(snapshot: &ValidatorVpnPeerSnapshot, signing_key: &str) -> Result<String, String> {
    let bytes = snapshot_signing_payload_bytes(snapshot)?;
    if let Some(key) = ed25519_signing_key(signing_key)? {
        let signature = key.sign(&bytes);
        return Ok(format!(
            "ed25519:{}",
            general_purpose::STANDARD.encode(signature.to_bytes())
        ));
    }
    let mut hasher = Sha256::new();
    hasher.update(signing_key.as_bytes());
    hasher.update(b":");
    hasher.update(bytes);
    Ok(format!("sha256:{:x}", hasher.finalize()))
}

fn validate_peer_snapshot_signature(
    snapshot: &ValidatorVpnPeerSnapshot,
    signing_key: Option<&str>,
    public_key: Option<&str>,
) -> Result<(), String> {
    let signature = snapshot.signature.trim();
    if signature.is_empty() {
        return Err("Peer snapshot is unsigned".to_string());
    }
    if signature.starts_with("ed25519:") {
        if let Some(key) = public_key {
            return verify_ed25519_snapshot_signature(snapshot, key);
        }
        if let Some(key) = signing_key {
            let expected = sign_snapshot(snapshot, key)?;
            if snapshot.signature == expected {
                return Ok(());
            }
            return Err("Peer snapshot signature is invalid".to_string());
        }
        return Err("Coordinator snapshot verification key is not configured".to_string());
    }
    if signature.starts_with("sha256:") {
        let key = signing_key.ok_or_else(|| {
            "Legacy sha256 peer snapshots require the coordinator signing key".to_string()
        })?;
        let expected = sign_snapshot(snapshot, key)?;
        if snapshot.signature == expected {
            return Ok(());
        }
        return Err("Peer snapshot signature is invalid".to_string());
    }
    Err("Unsupported peer snapshot signature scheme".to_string())
}

fn verify_ed25519_snapshot_signature(
    snapshot: &ValidatorVpnPeerSnapshot,
    public_key: &str,
) -> Result<(), String> {
    let verifying_key = ed25519_verifying_key(public_key)?;
    let signature_value = snapshot
        .signature
        .trim()
        .strip_prefix("ed25519:")
        .ok_or_else(|| "Peer snapshot signature is not ed25519".to_string())?;
    let signature_bytes = general_purpose::STANDARD
        .decode(signature_value.trim())
        .map_err(|error| format!("Invalid Ed25519 peer snapshot signature encoding: {error}"))?;
    let signature_bytes: [u8; 64] = signature_bytes
        .try_into()
        .map_err(|_| "Ed25519 peer snapshot signature must be 64 bytes".to_string())?;
    let signature = Signature::from_bytes(&signature_bytes);
    verifying_key
        .verify(&snapshot_signing_payload_bytes(snapshot)?, &signature)
        .map_err(|_| "Peer snapshot signature is invalid".to_string())
}

fn validate_challenge(
    challenge: &ValidatorVpnEnrollmentChallenge,
    request: &ValidatorVpnEnrollRequest,
) -> Result<(), String> {
    if challenge.consumed_at.is_some() {
        return Err("Enrollment challenge has already been consumed".to_string());
    }
    if challenge.role != request.role {
        return Err("Enrollment challenge role does not match request role".to_string());
    }
    if challenge.node_name.as_deref() != Some(request.node_name.as_str()) {
        return Err("Enrollment challenge node name does not match request".to_string());
    }
    let expires_at = DateTime::parse_from_rfc3339(&challenge.expires_at)
        .map_err(|error| format!("Invalid enrollment challenge expiry: {error}"))?
        .with_timezone(&Utc);
    if Utc::now() >= expires_at {
        return Err("Enrollment challenge has expired".to_string());
    }
    Ok(())
}

fn verify_enrollment_signature(
    challenge: &ValidatorVpnEnrollmentChallenge,
    request: &ValidatorVpnEnrollRequest,
) -> Result<(), String> {
    match enrollment_verifier_mode().as_deref() {
        Some("challenge-sha256") => {
            let expected = expected_test_signature(challenge, request);
            if request.signed_payload == expected {
                Ok(())
            } else {
                Err("Enrollment signature is invalid".to_string())
            }
        }
        Some(other) => Err(format!(
            "Unsupported validator VPN enrollment signature mode: {other}"
        )),
        None => {
            Err("Validator VPN enrollment verifier is not configured; failing closed".to_string())
        }
    }
}

fn expected_test_signature(
    challenge: &ValidatorVpnEnrollmentChallenge,
    request: &ValidatorVpnEnrollRequest,
) -> String {
    let payload = format!(
        "{}|{}|{}|{}|{}|{}|{}",
        VALIDATOR_VPN_NETWORK,
        request.role.as_str(),
        request.validator_pubkey.as_deref().unwrap_or(""),
        request.operator_address.as_deref().unwrap_or(""),
        request.wg_pubkey,
        challenge.challenge,
        request.node_name
    );
    let mut hasher = Sha256::new();
    hasher.update(payload.as_bytes());
    format!("challenge-sha256:{:x}", hasher.finalize())
}

fn verify_validator_eligibility(request: &ValidatorVpnEnrollRequest) -> Result<(), String> {
    if let Some(allowlist) = eligibility_allowlist() {
        return verify_static_validator_eligibility(request, &allowlist);
    }

    verify_packaged_validator_eligibility(request)
}

fn verify_static_validator_eligibility(
    request: &ValidatorVpnEnrollRequest,
    allowlist: &HashSet<String>,
) -> Result<(), String> {
    if allowlist.contains("*") {
        return Ok(());
    }
    for candidate in [
        request.validator_pubkey.as_deref(),
        request.operator_address.as_deref(),
        Some(request.node_name.as_str()),
    ]
    .into_iter()
    .flatten()
    {
        if allowlist.contains(candidate) {
            return Ok(());
        }
    }
    Err("Validator is not eligible for validator VPN enrollment".to_string())
}

fn verify_packaged_validator_eligibility(
    request: &ValidatorVpnEnrollRequest,
) -> Result<(), String> {
    let validator_address = request
        .validator_pubkey
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            "Validator VPN enrollment requires the synv1 validator address from setup.".to_string()
        })?;
    validate_validator_identity(validator_address)?;

    let operator_address = request
        .operator_address
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            "Validator VPN enrollment requires the operator Synergy wallet address after the on-chain stake gate passes."
                .to_string()
        })?;
    validate_operator_wallet_identity(operator_address)?;
    Ok(())
}

fn refresh_health_statuses(state: &mut ValidatorVpnStateFile) {
    let now = Utc::now();
    for node in &mut state.nodes {
        if matches!(
            node.status,
            ValidatorVpnNodeStatus::Reserved
                | ValidatorVpnNodeStatus::Quarantined
                | ValidatorVpnNodeStatus::Jailed
                | ValidatorVpnNodeStatus::Removed
                | ValidatorVpnNodeStatus::Revoked
        ) {
            continue;
        }
        if let Some(last_heartbeat) = parse_rfc3339_opt(node.last_agent_heartbeat_at.as_deref()) {
            if now - last_heartbeat > Duration::minutes(HEARTBEAT_DEGRADED_MINUTES)
                && matches!(
                    node.status,
                    ValidatorVpnNodeStatus::Pending
                        | ValidatorVpnNodeStatus::Syncing
                        | ValidatorVpnNodeStatus::Connected
                )
            {
                node.status = ValidatorVpnNodeStatus::Degraded;
                node.updated_at = now.to_rfc3339();
            }
        }
        if let Some(last_handshake) = parse_rfc3339_opt(node.last_vpn_handshake_at.as_deref()) {
            if now - last_handshake > Duration::minutes(WIREGUARD_INACTIVE_MINUTES)
                && node.role == ValidatorVpnRole::Validator
            {
                node.status = ValidatorVpnNodeStatus::Inactive;
                if node.inactive_since.is_none() {
                    node.inactive_since = Some(now.to_rfc3339());
                }
                node.updated_at = now.to_rfc3339();
            }
        }
    }
}

fn allocate_next_validator_ip(state: &ValidatorVpnStateFile) -> Result<String, String> {
    let used: HashSet<String> = state
        .ip_leases
        .iter()
        .filter(|lease| {
            matches!(
                lease.state,
                ValidatorVpnLeaseState::Reserved
                    | ValidatorVpnLeaseState::Assigned
                    | ValidatorVpnLeaseState::Tombstoned
            )
        })
        .map(|lease| lease.vpn_ip.clone())
        .collect();
    for octet in 7..=254 {
        let candidate = format!("10.70.10.{octet}/32");
        if !used.contains(&candidate) {
            return Ok(candidate);
        }
    }
    Err("Validator VPN IP range is exhausted".to_string())
}

fn next_relayer_ip(state: &ValidatorVpnStateFile) -> Option<String> {
    let used: HashSet<String> = state
        .ip_leases
        .iter()
        .map(|lease| lease.vpn_ip.clone())
        .collect();
    (4..=254)
        .map(|octet| format!("10.70.20.{octet}/32"))
        .find(|candidate| !used.contains(candidate))
}

fn allocate_next_innernet_ip_excluding(
    state: &ValidatorVpnStateFile,
    role: &ValidatorVpnRole,
    authoritative_used: &HashSet<String>,
) -> Result<String, String> {
    let variable = match role {
        ValidatorVpnRole::Validator => "SYNERGY_INNERNET_VALIDATOR_ADDRESS_CIDR",
        ValidatorVpnRole::Relayer => "SYNERGY_INNERNET_RELAYER_ADDRESS_CIDR",
    };
    let cidr = std::env::var(variable)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            format!("{variable} is required for coordinator-managed Innernet enrollment.")
        })?;
    let (network, prefix) = parse_vpn_ip(&cidr)?;
    if !(8..=30).contains(&prefix) {
        return Err(format!(
            "{variable} must be an IPv4 network between /8 and /30."
        ));
    }
    let network = u32::from(network);
    let host_bits = 32 - prefix;
    let host_mask = (1u32 << host_bits) - 1;
    let base = network & !host_mask;
    let used: HashSet<String> = state
        .ip_leases
        .iter()
        .filter(|lease| {
            matches!(
                lease.state,
                ValidatorVpnLeaseState::Reserved
                    | ValidatorVpnLeaseState::Assigned
                    | ValidatorVpnLeaseState::Tombstoned
            )
        })
        .map(|lease| {
            lease
                .vpn_ip
                .split('/')
                .next()
                .unwrap_or_default()
                .to_string()
        })
        .collect();
    // The central Innernet database owns the canonical bootstrap slots even
    // when this state file still contains legacy WireGuard-era leases.
    // Dynamic enrollment must never offer an address already assigned to a
    // bootstrap validator or relayer.
    let bootstrap_host_count = innernet_bootstrap_host_count(role);
    for candidate in (base + bootstrap_host_count + 1)..(base + host_mask) {
        let address = Ipv4Addr::from(candidate).to_string();
        if !used.contains(&address) && !authoritative_used.contains(&address) {
            return Ok(format!("{address}/32"));
        }
    }
    Err(format!("{variable} has no unassigned addresses remaining."))
}

fn innernet_bootstrap_host_count(role: &ValidatorVpnRole) -> u32 {
    match role {
        ValidatorVpnRole::Validator => BOOTSTRAP_VALIDATOR_ADDRESSES.len() as u32,
        ValidatorVpnRole::Relayer => BOOTSTRAP_RELAYER_COUNT,
    }
}

fn validate_validator_ip(ip: &str) -> Result<(), String> {
    let (addr, prefix) = parse_vpn_ip(ip)?;
    if prefix != 32 {
        return Err(format!("{ip} must use an exact /32 route"));
    }
    let octets = addr.octets();
    if octets[0] != 10 || octets[1] != 70 || octets[2] != 10 {
        return Err(format!("{ip} is outside {VALIDATOR_VPN_VALIDATOR_CIDR}"));
    }
    if !(1..=254).contains(&octets[3]) {
        return Err(format!("{ip} is outside the validator VPN range"));
    }
    Ok(())
}

fn validate_relayer_ip(ip: &str) -> Result<(), String> {
    let (addr, prefix) = parse_vpn_ip(ip)?;
    if prefix != 32 {
        return Err(format!("{ip} must use an exact /32 route"));
    }
    let octets = addr.octets();
    if octets[0] != 10 || octets[1] != 70 || octets[2] != 20 {
        return Err(format!("{ip} is outside {VALIDATOR_VPN_RELAYER_CIDR}"));
    }
    if !(1..=254).contains(&octets[3]) {
        return Err(format!("{ip} uses a forbidden relayer host octet"));
    }
    Ok(())
}

fn parse_vpn_ip(ip: &str) -> Result<(Ipv4Addr, u8), String> {
    let (addr, prefix) = ip
        .split_once('/')
        .ok_or_else(|| format!("{ip} must include a CIDR prefix"))?;
    let addr = addr
        .parse::<Ipv4Addr>()
        .map_err(|error| format!("{ip} is not an IPv4 address: {error}"))?;
    let prefix = prefix
        .parse::<u8>()
        .map_err(|error| format!("{ip} has an invalid prefix: {error}"))?;
    Ok((addr, prefix))
}

fn load_or_initialize_state(path: &Path) -> Result<ValidatorVpnStateFile, String> {
    if path.is_file() {
        let raw = fs::read_to_string(path)
            .map_err(|error| format!("Failed to read {}: {error}", path.display()))?;
        let mut state = serde_json::from_str::<ValidatorVpnStateFile>(&raw)
            .map_err(|error| format!("Failed to parse {}: {error}", path.display()))?;
        let migrated = migrate_retired_vpn_state(&mut state);
        let version_upgrade = state.version < 3;
        if version_upgrade {
            state.version = 3;
        }
        ensure_bootstrap_nodes(&mut state);
        if migrated || version_upgrade {
            let mut saveable = state.clone();
            save_state(path, &mut saveable)?;
        }
        return Ok(state);
    }
    let mut state = ValidatorVpnStateFile {
        version: 3,
        network: VALIDATOR_VPN_NETWORK.to_string(),
        cidr: VALIDATOR_VPN_CIDR.to_string(),
        nodes: Vec::new(),
        ip_leases: Vec::new(),
        enrollment_challenges: Vec::new(),
        peer_snapshots: Vec::new(),
        events: Vec::new(),
        onboarding_tokens: Vec::new(),
        config_acks: Vec::new(),
        updated_at: now_rfc3339(),
    };
    ensure_bootstrap_nodes(&mut state);
    let mut saveable = state.clone();
    save_state(path, &mut saveable)?;
    Ok(state)
}

fn is_retired_vpn_ip(ip: &str) -> bool {
    parse_vpn_ip(ip)
        .map(|(address, _)| {
            let octets = address.octets();
            octets[0] == 10 && octets[1] == 69
        })
        .unwrap_or(false)
}

fn migrate_retired_vpn_state(state: &mut ValidatorVpnStateFile) -> bool {
    let assignments = bootstrap_assignments();
    let mut changed = false;

    state.nodes.retain_mut(|node| {
        if !is_retired_vpn_ip(&node.vpn_ip) {
            return true;
        }
        if let Some((_, _, replacement)) = assignments
            .iter()
            .find(|(role, name, _)| role == &node.role && *name == node.node_name)
        {
            node.vpn_ip = (*replacement).to_string();
            node.bootstrap_node = true;
            node.updated_at = now_rfc3339();
            changed = true;
            true
        } else {
            changed = true;
            false
        }
    });
    state.ip_leases.retain(|lease| {
        let keep = !is_retired_vpn_ip(&lease.vpn_ip);
        if !keep {
            changed = true;
        }
        keep
    });
    state.peer_snapshots.retain(|snapshot| {
        let keep = snapshot.cidr == VALIDATOR_VPN_CIDR
            && snapshot
                .relayers
                .iter()
                .chain(snapshot.validators.iter())
                .all(|peer| !is_retired_vpn_ip(&peer.vpn_ip));
        if !keep {
            changed = true;
        }
        keep
    });
    if state.network != VALIDATOR_VPN_NETWORK {
        state.network = VALIDATOR_VPN_NETWORK.to_string();
        changed = true;
    }
    if state.cidr != VALIDATOR_VPN_CIDR {
        state.cidr = VALIDATOR_VPN_CIDR.to_string();
        changed = true;
    }
    changed
}

fn save_state(path: &Path, state: &mut ValidatorVpnStateFile) -> Result<(), String> {
    static STATE_WRITE_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    let _guard = STATE_WRITE_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .map_err(|_| "Validator VPN state write lock is poisoned".to_string())?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| format!("Failed to create {}: {error}", parent.display()))?;
    }
    state.updated_at = now_rfc3339();
    let encoded = serde_json::to_vec_pretty(state)
        .map_err(|error| format!("Failed to encode validator VPN state: {error}"))?;
    let temporary_path = path.with_extension(format!(
        "json.tmp.{}.{}",
        std::process::id(),
        Uuid::new_v4()
    ));
    fs::write(&temporary_path, encoded)
        .map_err(|error| format!("Failed to write {}: {error}", temporary_path.display()))?;
    if let Err(error) = fs::rename(&temporary_path, path) {
        let _ = fs::remove_file(&temporary_path);
        return Err(format!("Failed to replace {}: {error}", path.display()));
    }
    Ok(())
}

fn reservation_lock() -> &'static Mutex<()> {
    static STATE_RESERVATION_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    STATE_RESERVATION_LOCK.get_or_init(|| Mutex::new(()))
}

fn ensure_bootstrap_nodes(state: &mut ValidatorVpnStateFile) {
    let now = now_rfc3339();
    for (role, name, ip) in bootstrap_assignments() {
        if !state
            .nodes
            .iter()
            .any(|node| node.node_name == name && node.role == role)
        {
            let id = format!("bootstrap-{name}");
            state.nodes.push(ValidatorVpnNode {
                id: id.clone(),
                role: role.clone(),
                node_name: name.to_string(),
                validator_pubkey: bootstrap_validator_address(name).map(str::to_string),
                operator_address: None,
                wg_pubkey: None,
                vpn_ip: ip.to_string(),
                endpoint_host: None,
                endpoint_port: VALIDATOR_VPN_LISTEN_PORT,
                status: ValidatorVpnNodeStatus::Reserved,
                bootstrap_node: true,
                assigned_at: now.clone(),
                activated_at: None,
                last_vpn_handshake_at: None,
                last_agent_heartbeat_at: None,
                last_consensus_seen_at: None,
                inactive_since: None,
                revoked_at: None,
                created_at: now.clone(),
                updated_at: now.clone(),
            });
        } else if role == ValidatorVpnRole::Validator {
            if let Some(node) = state
                .nodes
                .iter_mut()
                .find(|node| node.node_name == name && node.role == role)
            {
                if node
                    .validator_pubkey
                    .as_deref()
                    .map(str::trim)
                    .unwrap_or_default()
                    .is_empty()
                {
                    node.validator_pubkey = bootstrap_validator_address(name).map(str::to_string);
                    node.updated_at = now.clone();
                }
            }
        }
        if !state.ip_leases.iter().any(|lease| lease.vpn_ip == ip) {
            state.ip_leases.push(ValidatorVpnIpLease {
                vpn_ip: ip.to_string(),
                node_id: state
                    .nodes
                    .iter()
                    .find(|node| node.node_name == name && node.role == role)
                    .map(|node| node.id.clone()),
                role,
                state: ValidatorVpnLeaseState::Reserved,
                assigned_at: Some(now.clone()),
                tombstoned_until: None,
            });
        }
    }
}

fn bootstrap_validator_address(name: &str) -> Option<&'static str> {
    let slot = name
        .trim()
        .strip_prefix("validator-")
        .and_then(|slot| slot.parse::<usize>().ok())?;
    BOOTSTRAP_VALIDATOR_ADDRESSES
        .get(slot.checked_sub(1)?)
        .copied()
}

fn bootstrap_assignments() -> Vec<(ValidatorVpnRole, &'static str, &'static str)> {
    vec![
        (ValidatorVpnRole::Relayer, "relayer-1", "10.70.20.1/32"),
        (ValidatorVpnRole::Relayer, "relayer-2", "10.70.20.2/32"),
        (ValidatorVpnRole::Relayer, "relayer-3", "10.70.20.3/32"),
        (ValidatorVpnRole::Validator, "validator-1", "10.70.10.1/32"),
        (ValidatorVpnRole::Validator, "validator-2", "10.70.10.2/32"),
        (ValidatorVpnRole::Validator, "validator-3", "10.70.10.3/32"),
        (ValidatorVpnRole::Validator, "validator-4", "10.70.10.4/32"),
        (ValidatorVpnRole::Validator, "validator-5", "10.70.10.5/32"),
        (ValidatorVpnRole::Validator, "validator-6", "10.70.10.6/32"),
    ]
}

fn upsert_lease(state: &mut ValidatorVpnStateFile, lease: ValidatorVpnIpLease) {
    if let Some(existing) = state
        .ip_leases
        .iter_mut()
        .find(|existing| existing.vpn_ip == lease.vpn_ip)
    {
        *existing = lease;
    } else {
        state.ip_leases.push(lease);
    }
}

fn validator_vpn_state_path(app_context: &AppContext) -> Result<PathBuf, String> {
    let workspace = ensure_monitor_workspace_with_context(app_context)?;
    Ok(workspace.join(STATE_RELATIVE_PATH))
}

fn event(
    node_id: Option<String>,
    event_type: &str,
    payload: serde_json::Value,
) -> ValidatorVpnEvent {
    ValidatorVpnEvent {
        id: Uuid::new_v4().to_string(),
        node_id,
        event_type: event_type.to_string(),
        event_payload: payload,
        created_at: now_rfc3339(),
    }
}

fn hash_onboarding_token(token: &str) -> String {
    let digest = Sha256::digest(token.as_bytes());
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn coordinator_signing_key() -> Option<String> {
    std::env::var("SYNERGY_VALIDATOR_VPN_COORDINATOR_SIGNING_KEY")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

pub fn validator_vpn_coordinator_public_signing_key() -> Option<String> {
    std::env::var("SYNERGY_VALIDATOR_VPN_COORDINATOR_PUBLIC_KEY")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .or_else(|| {
            coordinator_signing_key()
                .and_then(|key| ed25519_signing_key(&key).ok().flatten())
                .map(|key| {
                    format!(
                        "ed25519:{}",
                        general_purpose::STANDARD.encode(key.verifying_key().to_bytes())
                    )
                })
        })
}

fn coordinator_public_signing_key() -> String {
    validator_vpn_coordinator_public_signing_key()
        .unwrap_or_else(|| "configured-in-coordinator".to_string())
}

fn coordinator_signature_scheme() -> String {
    match coordinator_signing_key() {
        Some(key) => match ed25519_signing_key(&key) {
            Ok(Some(_)) => "ed25519".to_string(),
            Ok(None) => "sha256-legacy".to_string(),
            Err(_) => "invalid".to_string(),
        },
        None => "unconfigured".to_string(),
    }
}

fn ed25519_signing_key(value: &str) -> Result<Option<SigningKey>, String> {
    let trimmed = value.trim();
    let candidate = trimmed
        .strip_prefix("ed25519:")
        .or_else(|| trimmed.strip_prefix("ed25519-seed:"))
        .or_else(|| trimmed.strip_prefix("base64:"));
    let Some(candidate) = candidate else {
        return Ok(None);
    };
    let bytes = general_purpose::STANDARD
        .decode(candidate.trim())
        .map_err(|error| format!("Invalid Ed25519 coordinator signing key encoding: {error}"))?;
    let key_bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| "Ed25519 coordinator signing key must be a 32-byte seed".to_string())?;
    Ok(Some(SigningKey::from_bytes(&key_bytes)))
}

fn ed25519_verifying_key(value: &str) -> Result<VerifyingKey, String> {
    let trimmed = value.trim();
    let candidate = trimmed
        .strip_prefix("ed25519:")
        .or_else(|| trimmed.strip_prefix("base64:"))
        .unwrap_or(trimmed);
    let bytes = general_purpose::STANDARD
        .decode(candidate.trim())
        .map_err(|error| format!("Invalid Ed25519 coordinator public key encoding: {error}"))?;
    let key_bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| "Ed25519 coordinator public key must be 32 bytes".to_string())?;
    VerifyingKey::from_bytes(&key_bytes)
        .map_err(|error| format!("Invalid Ed25519 coordinator public key: {error}"))
}

fn enrollment_verifier_mode() -> Option<String> {
    Some(
        std::env::var("SYNERGY_VALIDATOR_VPN_ENROLLMENT_SIGNATURE_MODE")
            .ok()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| DEFAULT_ENROLLMENT_SIGNATURE_MODE.to_string()),
    )
}

fn eligibility_allowlist() -> Option<HashSet<String>> {
    std::env::var("SYNERGY_VALIDATOR_VPN_ELIGIBLE_VALIDATORS")
        .ok()
        .map(|value| {
            value
                .split(',')
                .map(str::trim)
                .filter(|entry| !entry.is_empty())
                .map(ToOwned::to_owned)
                .collect::<HashSet<_>>()
        })
        .filter(|set| !set.is_empty())
}

fn clean_optional(value: Option<String>) -> Option<String> {
    value
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn normalized_optional_str(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn validate_node_name(name: &str) -> Result<(), String> {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return Err("node_name is required".to_string());
    }
    if !trimmed
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.'))
    {
        return Err("node_name contains unsupported characters".to_string());
    }
    Ok(())
}

fn validate_wg_public_key(key: &str) -> Result<(), String> {
    let trimmed = key.trim();
    if trimmed.is_empty() {
        return Err("wg_pubkey is required".to_string());
    }
    if trimmed.contains("PrivateKey") || trimmed.contains('\n') || trimmed.contains('\r') {
        return Err("wg_pubkey must be a single public key value".to_string());
    }
    if trimmed.len() < 32 {
        return Err("wg_pubkey is too short to be a WireGuard public key".to_string());
    }
    Ok(())
}

fn validate_validator_identity(address: &str) -> Result<(), String> {
    let trimmed = address.trim();
    if !trimmed.starts_with("synv1") {
        return Err(format!(
            "validator identity must be a synv1 validator address, got {address}"
        ));
    }
    if trimmed.contains(char::is_whitespace) || trimmed.contains('/') || trimmed.contains('\\') {
        return Err("validator identity contains unsupported characters".to_string());
    }
    Ok(())
}

fn validate_operator_wallet_identity(address: &str) -> Result<(), String> {
    let trimmed = address.trim();
    if trimmed.is_empty() {
        return Err("operator wallet address is required".to_string());
    }
    if trimmed.starts_with("synv1") {
        return Err(
            "operator wallet address must be a regular Synergy wallet, not a validator address"
                .to_string(),
        );
    }
    if !trimmed.starts_with("syn") {
        return Err("operator wallet address must be a Synergy address".to_string());
    }
    if trimmed.contains(char::is_whitespace) || trimmed.contains('/') || trimmed.contains('\\') {
        return Err("operator wallet address contains unsupported characters".to_string());
    }
    Ok(())
}

fn validate_endpoint_host(host: &str) -> Result<(), String> {
    let trimmed = host.trim();
    if trimmed.is_empty() {
        return Ok(());
    }
    if trimmed.contains('/') || trimmed.contains('\\') || trimmed.contains(char::is_whitespace) {
        return Err("endpoint_host must be a host or IP address, not a URL or command".to_string());
    }
    Ok(())
}

fn bootstrap_endpoint(
    input: &ValidatorVpnBootstrapNodeInput,
) -> Result<(Option<String>, u16), String> {
    let mut host = clean_optional(input.endpoint_host.clone())
        .or_else(|| clean_optional(input.public_ip.clone()));
    let mut port = input.endpoint_port.unwrap_or(VALIDATOR_VPN_LISTEN_PORT);
    if let Some(endpoint) = clean_optional(input.endpoint.clone()) {
        let (endpoint_host, endpoint_port) = endpoint
            .rsplit_once(':')
            .ok_or_else(|| format!("endpoint for {} must be in host:port form", input.node_name))?;
        host = clean_optional(Some(endpoint_host.to_string()));
        port = endpoint_port.parse::<u16>().map_err(|error| {
            format!(
                "endpoint for {} has invalid WireGuard port {endpoint_port}: {error}",
                input.node_name
            )
        })?;
    }
    Ok((host, port))
}

fn parse_rfc3339_opt(value: Option<&str>) -> Option<DateTime<Utc>> {
    value
        .and_then(|value| DateTime::parse_from_rfc3339(value).ok())
        .map(|value| value.with_timezone(&Utc))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signature, Verifier};
    use std::sync::Mutex;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    struct EnvVarGuard {
        key: &'static str,
        previous: Option<std::ffi::OsString>,
    }

    impl EnvVarGuard {
        fn remove(key: &'static str) -> Self {
            let previous = std::env::var_os(key);
            std::env::remove_var(key);
            Self { key, previous }
        }

        fn set(key: &'static str, value: &str) -> Self {
            let previous = std::env::var_os(key);
            std::env::set_var(key, value);
            Self { key, previous }
        }
    }

    impl Drop for EnvVarGuard {
        fn drop(&mut self) {
            if let Some(previous) = &self.previous {
                std::env::set_var(self.key, previous);
            } else {
                std::env::remove_var(self.key);
            }
        }
    }

    fn state() -> ValidatorVpnStateFile {
        let mut state = ValidatorVpnStateFile {
            version: 1,
            network: VALIDATOR_VPN_NETWORK.to_string(),
            cidr: VALIDATOR_VPN_CIDR.to_string(),
            nodes: Vec::new(),
            ip_leases: Vec::new(),
            enrollment_challenges: Vec::new(),
            peer_snapshots: Vec::new(),
            events: Vec::new(),
            onboarding_tokens: Vec::new(),
            config_acks: Vec::new(),
            updated_at: now_rfc3339(),
        };
        ensure_bootstrap_nodes(&mut state);
        state
    }

    fn fake_wg_key(label: &str) -> String {
        format!("{label}12345678901234567890123456789012345678901234=")
    }

    fn sample_validator_enroll_request() -> ValidatorVpnEnrollRequest {
        ValidatorVpnEnrollRequest {
            challenge_id: "challenge-1".to_string(),
            role: ValidatorVpnRole::Validator,
            node_name: "validator-7".to_string(),
            validator_pubkey: Some("synv1validator7".to_string()),
            operator_address: Some("synw1owner".to_string()),
            wg_pubkey: fake_wg_key("validator-7"),
            endpoint_host: None,
            endpoint_port: VALIDATOR_VPN_LISTEN_PORT,
            signed_payload: "unused-in-unit-test".to_string(),
        }
    }

    #[test]
    fn enrollment_signature_verifies_with_packaged_default_mode() {
        let _env_lock = ENV_LOCK.lock().unwrap();
        let _mode_guard = EnvVarGuard::remove("SYNERGY_VALIDATOR_VPN_ENROLLMENT_SIGNATURE_MODE");
        let challenge = ValidatorVpnEnrollmentChallenge {
            id: "challenge-1".to_string(),
            challenge: "nonce-1".to_string(),
            role: ValidatorVpnRole::Validator,
            node_name: Some("validator-7".to_string()),
            validator_pubkey: Some("synv1validator7".to_string()),
            operator_address: Some("synw1owner".to_string()),
            expires_at: (Utc::now() + Duration::minutes(1)).to_rfc3339(),
            consumed_at: None,
            created_at: now_rfc3339(),
        };
        let mut request = ValidatorVpnEnrollRequest {
            challenge_id: challenge.id.clone(),
            role: ValidatorVpnRole::Validator,
            node_name: "validator-7".to_string(),
            validator_pubkey: Some("synv1validator7".to_string()),
            operator_address: Some("synw1owner".to_string()),
            wg_pubkey: fake_wg_key("validator-7"),
            endpoint_host: None,
            endpoint_port: VALIDATOR_VPN_LISTEN_PORT,
            signed_payload: String::new(),
        };
        request.signed_payload = expected_test_signature(&challenge, &request);

        verify_enrollment_signature(&challenge, &request)
            .expect("packaged default verifier should accept the signed challenge");
    }

    #[test]
    fn validator_onboarding_token_requires_its_exact_assignment_and_identity() {
        let token = ValidatorVpnOnboardingToken {
            id: "token-7".to_string(),
            token_hash: "hash".to_string(),
            operator_label: None,
            peer_type: ValidatorVpnRole::Validator,
            assignment_id: Some("validator-07".to_string()),
            assigned_validator_identity: Some("synv1validator7".to_string()),
            assigned_validator_public_key: Some("public-key".to_string()),
            identity_proof_verified_at: None,
            issued_at: now_rfc3339(),
            expires_at: (Utc::now() + Duration::minutes(5)).to_rfc3339(),
            reserved_node_id: None,
            used_at: None,
        };

        assert!(onboarding_token_assignment_matches(
            &token,
            &ValidatorVpnRole::Validator,
            Some(" validator-07 "),
            Some(" synv1validator7 "),
        ));
        assert!(!onboarding_token_assignment_matches(
            &token,
            &ValidatorVpnRole::Validator,
            Some("validator-08"),
            Some("synv1validator7"),
        ));
        assert!(!onboarding_token_assignment_matches(
            &token,
            &ValidatorVpnRole::Validator,
            Some("validator-07"),
            Some("synv1validator8"),
        ));
    }

    #[test]
    fn validator_onboarding_requires_a_proof_from_its_assigned_key() {
        let identity = synergy_address_engine::generate_identity(
            synergy_address_engine::AddressType::NodeClass1,
        )
        .expect("identity");
        let token = ValidatorVpnOnboardingToken {
            id: "token-7".to_string(),
            token_hash: "hash".to_string(),
            operator_label: None,
            peer_type: ValidatorVpnRole::Validator,
            assignment_id: Some("validator-07".to_string()),
            assigned_validator_identity: Some(identity.address.clone()),
            assigned_validator_public_key: Some(identity.public_key.clone()),
            identity_proof_verified_at: None,
            issued_at: now_rfc3339(),
            expires_at: (Utc::now() + Duration::minutes(5)).to_rfc3339(),
            reserved_node_id: None,
            used_at: None,
        };
        let message = validator_identity_proof_message(
            "validator-07",
            &identity.address,
            "validator-seven",
            "node-7",
        );
        let proof =
            synergy_address_engine::sign_identity_proof(&identity.private_key, message.as_bytes())
                .expect("proof");

        assert!(verify_validator_identity_enrollment_proof(
            &token,
            "validator-seven",
            Some("node-7"),
            Some(&identity.public_key),
            Some(&proof),
        )
        .expect("valid proof"));
        assert!(!verify_validator_identity_enrollment_proof(
            &token,
            "validator-eight",
            Some("node-7"),
            Some(&identity.public_key),
            Some(&proof),
        )
        .expect("proof should be bound to its peer name"));
    }

    #[test]
    fn packaged_validator_eligibility_accepts_stake_gated_operator_without_allowlist() {
        let _env_lock = ENV_LOCK.lock().unwrap();
        let _allowlist_guard = EnvVarGuard::remove("SYNERGY_VALIDATOR_VPN_ELIGIBLE_VALIDATORS");
        let request = sample_validator_enroll_request();

        verify_validator_eligibility(&request)
            .expect("packaged eligibility should accept setup-gated validator enrollment");
    }

    #[test]
    fn packaged_validator_eligibility_requires_operator_wallet() {
        let _env_lock = ENV_LOCK.lock().unwrap();
        let _allowlist_guard = EnvVarGuard::remove("SYNERGY_VALIDATOR_VPN_ELIGIBLE_VALIDATORS");
        let mut request = sample_validator_enroll_request();
        request.operator_address = None;

        let error = verify_validator_eligibility(&request).unwrap_err();
        assert!(
            error.contains("operator Synergy wallet address"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn configured_validator_eligibility_allowlist_remains_enforced() {
        let _env_lock = ENV_LOCK.lock().unwrap();
        let _allowlist_guard =
            EnvVarGuard::set("SYNERGY_VALIDATOR_VPN_ELIGIBLE_VALIDATORS", "synv1allowed");
        let mut request = sample_validator_enroll_request();

        let error = verify_validator_eligibility(&request).unwrap_err();
        assert!(error.contains("not eligible"), "unexpected error: {error}");

        request.validator_pubkey = Some("synv1allowed".to_string());
        verify_validator_eligibility(&request)
            .expect("configured static allowlist should still permit explicit entries");
    }

    #[test]
    fn innernet_allocator_skips_authoritative_database_collisions() {
        let _env_lock = ENV_LOCK.lock().unwrap();
        let _validator_cidr =
            EnvVarGuard::set("SYNERGY_INNERNET_VALIDATOR_ADDRESS_CIDR", "10.70.10.0/24");
        let occupied = HashSet::from(["10.70.10.7".to_string()]);
        assert_eq!(
            allocate_next_innernet_ip_excluding(&state(), &ValidatorVpnRole::Validator, &occupied,)
                .expect("allocator should skip the authoritative peer"),
            "10.70.10.8/32",
        );
    }

    fn sample_snapshot() -> ValidatorVpnPeerSnapshot {
        ValidatorVpnPeerSnapshot {
            generation: 1,
            network: VALIDATOR_VPN_NETWORK.to_string(),
            cidr: VALIDATOR_VPN_CIDR.to_string(),
            created_at: "2026-07-04T00:00:00Z".to_string(),
            coordinator_public_signing_key: None,
            relayers: vec![ValidatorVpnPeerRecord {
                node_id: "relayer-1".to_string(),
                node_name: "relayer-1".to_string(),
                vpn_ip: "10.70.20.1/32".to_string(),
                wg_pubkey: fake_wg_key("relayer"),
                endpoint: Some("relayer1.example.net:51820".to_string()),
                status: "active".to_string(),
                validator_pubkey: None,
                operator_address: None,
            }],
            validators: vec![ValidatorVpnPeerRecord {
                node_id: "validator-1".to_string(),
                node_name: "validator-1".to_string(),
                vpn_ip: "10.70.10.1/32".to_string(),
                wg_pubkey: fake_wg_key("validator"),
                endpoint: Some("validator1.example.net:51820".to_string()),
                status: "active".to_string(),
                validator_pubkey: Some("synv1validator1".to_string()),
                operator_address: None,
            }],
            removed: Vec::new(),
            signature: String::new(),
        }
    }

    #[test]
    fn bootstrap_contains_exact_initial_nine_nodes() {
        let state = state();
        let bootstrap: Vec<_> = state
            .nodes
            .iter()
            .filter(|node| node.bootstrap_node)
            .map(|node| {
                (
                    node.role.clone(),
                    node.node_name.as_str(),
                    node.vpn_ip.as_str(),
                )
            })
            .collect();
        assert_eq!(bootstrap.len(), 9);
        assert!(bootstrap.contains(&(ValidatorVpnRole::Relayer, "relayer-1", "10.70.20.1/32")));
        assert!(bootstrap.contains(&(ValidatorVpnRole::Relayer, "relayer-2", "10.70.20.2/32")));
        assert!(bootstrap.contains(&(ValidatorVpnRole::Relayer, "relayer-3", "10.70.20.3/32")));
        for index in 1..=6 {
            assert!(bootstrap.contains(&(
                ValidatorVpnRole::Validator,
                format!("validator-{index}").as_str(),
                format!("10.70.10.{index}/32").as_str()
            )));
        }
    }

    #[test]
    fn propagation_requires_a_verified_handshake_for_each_active_validator() {
        let mut state = state();
        let validator = state
            .nodes
            .iter_mut()
            .find(|node| node.id == "bootstrap-validator-1")
            .expect("bootstrap validator should exist");
        validator.status = ValidatorVpnNodeStatus::Active;
        validator.wg_pubkey = Some(fake_wg_key("validator-1"));
        let mut snapshot = sample_snapshot();
        snapshot.validators[0].node_id = "bootstrap-validator-1".to_string();
        state.peer_snapshots.push(snapshot);

        let incomplete = propagation_status_for(&state, 1);
        assert!(!incomplete.complete);
        assert_eq!(
            incomplete.pending_validator_ids,
            vec!["bootstrap-validator-1"]
        );

        state.config_acks.push(ValidatorVpnConfigAck {
            node_id: "bootstrap-validator-1".to_string(),
            generation: 1,
            applied: true,
            interface_up: true,
            peers_handshaked: 1,
            error: None,
            acknowledged_at: now_rfc3339(),
        });
        let complete = propagation_status_for(&state, 1);
        assert!(complete.complete);
        assert_eq!(
            complete.acknowledged_validator_ids,
            vec!["bootstrap-validator-1"]
        );
    }

    #[test]
    fn propagation_does_not_count_zero_handshake_acknowledgements() {
        let mut state = state();
        let validator = state
            .nodes
            .iter_mut()
            .find(|node| node.id == "bootstrap-validator-1")
            .expect("bootstrap validator should exist");
        validator.status = ValidatorVpnNodeStatus::Active;
        validator.wg_pubkey = Some(fake_wg_key("validator-1"));
        let mut snapshot = sample_snapshot();
        snapshot.validators[0].node_id = "bootstrap-validator-1".to_string();
        state.peer_snapshots.push(snapshot);
        state.config_acks.push(ValidatorVpnConfigAck {
            node_id: "bootstrap-validator-1".to_string(),
            generation: 1,
            applied: true,
            interface_up: true,
            peers_handshaked: 0,
            error: None,
            acknowledged_at: now_rfc3339(),
        });

        let status = propagation_status_for(&state, 1);
        assert!(!status.complete);
        assert_eq!(status.failed_validator_ids, vec!["bootstrap-validator-1"]);
    }

    #[test]
    fn next_dynamic_validator_gets_10_70_10_7() {
        let state = state();
        assert_eq!(allocate_next_validator_ip(&state).unwrap(), "10.70.10.7/32");
    }

    #[test]
    fn next_dynamic_relayer_gets_10_70_20_4() {
        assert_eq!(next_relayer_ip(&state()).as_deref(), Some("10.70.20.4/32"));
    }

    #[test]
    fn dynamic_validator_enrollment_is_pending_but_in_transport_snapshot() {
        let mut state = state();
        for node in &mut state.nodes {
            if matches!(node.node_name.as_str(), "relayer-1" | "validator-1") {
                node.wg_pubkey = Some(fake_wg_key(&node.node_name));
                node.endpoint_host = Some(format!("{}.example.net", node.node_name));
                node.status = ValidatorVpnNodeStatus::Active;
            }
        }

        let node_id = upsert_enrolled_node(
            &mut state,
            ValidatorVpnEnrollRequest {
                challenge_id: "challenge-1".to_string(),
                role: ValidatorVpnRole::Validator,
                node_name: "validator-7".to_string(),
                validator_pubkey: Some("synv1validator7".to_string()),
                operator_address: Some("synw1owner".to_string()),
                wg_pubkey: fake_wg_key("validator-7"),
                endpoint_host: None,
                endpoint_port: VALIDATOR_VPN_LISTEN_PORT,
                signed_payload: "unused-in-unit-test".to_string(),
            },
        )
        .unwrap();
        let enrolled = state.nodes.iter().find(|node| node.id == node_id).unwrap();
        assert_eq!(enrolled.vpn_ip, "10.70.10.7/32");
        assert_eq!(enrolled.status, ValidatorVpnNodeStatus::Pending);

        let snapshot = generate_peer_snapshot(&mut state, "test-signing-key").unwrap();
        let pending_peer = snapshot
            .validators
            .iter()
            .find(|peer| peer.node_id == node_id)
            .expect("pending validator must be distributed as a transport peer");
        assert_eq!(pending_peer.status, "pending");
        assert_eq!(
            pending_peer.validator_pubkey.as_deref(),
            Some("synv1validator7")
        );
        assert!(
            pending_peer.operator_address.is_none(),
            "operator wallet identity must never be distributed in a peer snapshot"
        );
        assert_eq!(pending_peer.vpn_ip, "10.70.10.7/32");

        let validator_1 = state
            .nodes
            .iter()
            .find(|node| node.node_name == "validator-1")
            .unwrap();
        let rendered = render_wireguard_peer_config(&validator_1.id, &snapshot).unwrap();
        assert!(rendered.contains("AllowedIPs = 10.70.10.7/32"));
        assert!(!rendered.contains("AllowedIPs = 10.70.0.0/16"));
    }

    #[test]
    fn matching_wireguard_retry_reuses_dynamic_validator_enrollment() {
        let mut state = state();
        let wg_pubkey = fake_wg_key("validator-7");
        let first_node_id = upsert_enrolled_node(
            &mut state,
            ValidatorVpnEnrollRequest {
                challenge_id: "challenge-1".to_string(),
                role: ValidatorVpnRole::Validator,
                node_name: "validator-7".to_string(),
                validator_pubkey: Some("synv1validator7".to_string()),
                operator_address: Some("synw1owner".to_string()),
                wg_pubkey: wg_pubkey.clone(),
                endpoint_host: None,
                endpoint_port: VALIDATOR_VPN_LISTEN_PORT,
                signed_payload: "unused-in-unit-test".to_string(),
            },
        )
        .unwrap();

        let retry_node_id = upsert_enrolled_node(
            &mut state,
            ValidatorVpnEnrollRequest {
                challenge_id: "challenge-2".to_string(),
                role: ValidatorVpnRole::Validator,
                node_name: "validator-7-retry".to_string(),
                validator_pubkey: Some("synv1validator7".to_string()),
                operator_address: Some("synw1owner".to_string()),
                wg_pubkey,
                endpoint_host: Some("validator7.example.net".to_string()),
                endpoint_port: VALIDATOR_VPN_LISTEN_PORT,
                signed_payload: "unused-in-unit-test".to_string(),
            },
        )
        .unwrap();

        assert_eq!(retry_node_id, first_node_id);
        let enrolled = state
            .nodes
            .iter()
            .find(|node| node.id == retry_node_id)
            .unwrap();
        assert_eq!(enrolled.vpn_ip, "10.70.10.7/32");
        assert_eq!(enrolled.node_name, "validator-7-retry");
        assert_eq!(
            enrolled.endpoint_host.as_deref(),
            Some("validator7.example.net")
        );
        assert_eq!(
            enrolled.validator_pubkey.as_deref(),
            Some("synv1validator7")
        );
    }

    #[test]
    fn wireguard_retry_rejects_different_validator_identity() {
        let mut state = state();
        let wg_pubkey = fake_wg_key("validator-7");
        upsert_enrolled_node(
            &mut state,
            ValidatorVpnEnrollRequest {
                challenge_id: "challenge-1".to_string(),
                role: ValidatorVpnRole::Validator,
                node_name: "validator-7".to_string(),
                validator_pubkey: Some("synv1validator7".to_string()),
                operator_address: Some("synw1owner".to_string()),
                wg_pubkey: wg_pubkey.clone(),
                endpoint_host: None,
                endpoint_port: VALIDATOR_VPN_LISTEN_PORT,
                signed_payload: "unused-in-unit-test".to_string(),
            },
        )
        .unwrap();

        let error = upsert_enrolled_node(
            &mut state,
            ValidatorVpnEnrollRequest {
                challenge_id: "challenge-2".to_string(),
                role: ValidatorVpnRole::Validator,
                node_name: "validator-8".to_string(),
                validator_pubkey: Some("synv1validator8".to_string()),
                operator_address: Some("synw1owner".to_string()),
                wg_pubkey,
                endpoint_host: None,
                endpoint_port: VALIDATOR_VPN_LISTEN_PORT,
                signed_payload: "unused-in-unit-test".to_string(),
            },
        )
        .unwrap_err();

        assert!(error.contains("different validator"));
    }

    #[test]
    fn allocator_skips_reserved_and_tombstoned_addresses() {
        let mut state = state();
        state.ip_leases.push(ValidatorVpnIpLease {
            vpn_ip: "10.70.10.7/32".to_string(),
            node_id: None,
            role: ValidatorVpnRole::Validator,
            state: ValidatorVpnLeaseState::Tombstoned,
            assigned_at: None,
            tombstoned_until: Some("2099-01-01T00:00:00Z".to_string()),
        });
        assert_eq!(allocate_next_validator_ip(&state).unwrap(), "10.70.10.8/32");
    }

    #[test]
    fn validator_ip_validation_rejects_reserved_ranges() {
        assert!(validate_validator_ip("10.69.1.1/32").is_err());
        assert!(validate_validator_ip("10.69.9.254/32").is_err());
        assert!(validate_validator_ip("10.69.255.1/32").is_err());
        assert!(validate_validator_ip("10.69.10.0/32").is_err());
        assert!(validate_validator_ip("10.69.10.255/32").is_err());
        assert!(validate_validator_ip("10.70.10.7/32").is_ok());
        assert!(validate_relayer_ip("10.70.20.4/32").is_ok());
        assert!(validate_relayer_ip("10.70.20.0/32").is_err());
        assert!(validate_relayer_ip("10.70.20.255/32").is_err());
        assert!(validate_relayer_ip("10.69.0.4/32").is_err());
    }

    #[test]
    fn retired_state_migration_remaps_bootstrap_and_drops_legacy_peers() {
        let mut state = state();
        let bootstrap = state
            .nodes
            .iter_mut()
            .find(|node| node.node_name == "validator-1")
            .expect("bootstrap validator should exist");
        bootstrap.vpn_ip = "10.69.10.1/32".to_string();
        let mut legacy = bootstrap.clone();
        legacy.id = "legacy-validator".to_string();
        legacy.node_name = "legacy-validator".to_string();
        legacy.bootstrap_node = false;
        legacy.vpn_ip = "10.69.10.7/32".to_string();
        state.nodes.push(legacy);
        state.ip_leases.push(ValidatorVpnIpLease {
            vpn_ip: "10.69.10.7/32".to_string(),
            node_id: Some("legacy-validator".to_string()),
            role: ValidatorVpnRole::Validator,
            state: ValidatorVpnLeaseState::Assigned,
            assigned_at: None,
            tombstoned_until: None,
        });

        assert!(migrate_retired_vpn_state(&mut state));
        assert_eq!(
            state
                .nodes
                .iter()
                .find(|node| node.node_name == "validator-1")
                .unwrap()
                .vpn_ip,
            "10.70.10.1/32"
        );
        assert!(!state
            .nodes
            .iter()
            .any(|node| is_retired_vpn_ip(&node.vpn_ip)));
        assert!(!state
            .ip_leases
            .iter()
            .any(|lease| is_retired_vpn_ip(&lease.vpn_ip)));
    }

    #[test]
    fn snapshot_validation_rejects_broad_or_duplicate_peers() {
        let key = "test-signing-key";
        let mut snapshot = sample_snapshot();
        snapshot.signature = sign_snapshot(&snapshot, key).unwrap();
        assert!(validate_peer_snapshot(&snapshot, Some(key)).is_ok());

        let mut duplicate = snapshot.clone();
        duplicate.validators[0].vpn_ip = "10.69.0.1/32".to_string();
        duplicate.signature = sign_snapshot(&duplicate, key).unwrap();
        assert!(validate_peer_snapshot(&duplicate, Some(key)).is_err());

        let mut broad = snapshot;
        broad.validators[0].vpn_ip = "10.69.0.0/16".to_string();
        broad.signature = sign_snapshot(&broad, key).unwrap();
        assert!(validate_peer_snapshot(&broad, Some(key)).is_err());
    }

    #[test]
    fn ed25519_snapshot_signature_verifies_against_public_key() {
        let seed = [7u8; 32];
        let signing_key = SigningKey::from_bytes(&seed);
        let signing_key_env = format!("ed25519:{}", general_purpose::STANDARD.encode(seed));
        let mut snapshot = sample_snapshot();
        snapshot.signature = sign_snapshot(&snapshot, &signing_key_env).unwrap();
        let signature_value = snapshot
            .signature
            .strip_prefix("ed25519:")
            .expect("signature should use ed25519 prefix");
        let signature_bytes: [u8; 64] = general_purpose::STANDARD
            .decode(signature_value)
            .unwrap()
            .try_into()
            .unwrap();
        let signature = Signature::from_bytes(&signature_bytes);
        signing_key
            .verifying_key()
            .verify(
                &snapshot_signing_payload_bytes(&snapshot).unwrap(),
                &signature,
            )
            .expect("snapshot signature should verify");
    }

    #[test]
    fn configured_ed25519_snapshot_verification_rejects_tampering() {
        let seed = [8u8; 32];
        let signing_key = SigningKey::from_bytes(&seed);
        let signing_key_env = format!("ed25519:{}", general_purpose::STANDARD.encode(seed));
        let public_key_env = format!(
            "ed25519:{}",
            general_purpose::STANDARD.encode(signing_key.verifying_key().to_bytes())
        );
        let mut snapshot = sample_snapshot();
        snapshot.signature = sign_snapshot(&snapshot, &signing_key_env).unwrap();
        assert!(validate_peer_snapshot_signature(&snapshot, None, Some(&public_key_env)).is_ok());

        let mut tampered = snapshot.clone();
        tampered.validators[0].vpn_ip = "10.70.10.2/32".to_string();
        assert!(validate_peer_snapshot_signature(&tampered, None, Some(&public_key_env)).is_err());
    }

    #[test]
    fn bootstrap_endpoint_parses_artifact_endpoint() {
        let input = ValidatorVpnBootstrapNodeInput {
            role: ValidatorVpnRole::Relayer,
            node_name: "relayer-1".to_string(),
            vpn_ip: "10.70.20.1/32".to_string(),
            wg_pubkey: fake_wg_key("relayer"),
            endpoint: Some("195.26.241.95:51820".to_string()),
            endpoint_host: None,
            public_ip: Some("ignored.example.net".to_string()),
            endpoint_port: Some(51821),
        };
        let (host, port) = bootstrap_endpoint(&input).unwrap();
        assert_eq!(host.as_deref(), Some("195.26.241.95"));
        assert_eq!(port, 51820);
    }

    #[test]
    fn peer_rendering_uses_only_exact_32_routes() {
        let mut state = state();
        for node in &mut state.nodes {
            if node.node_name == "relayer-1"
                || node.node_name == "validator-1"
                || node.node_name == "validator-2"
            {
                node.wg_pubkey = Some(fake_wg_key(&node.node_name));
                node.endpoint_host = Some(format!("{}.example.net", node.node_name));
                node.status = ValidatorVpnNodeStatus::Active;
            }
        }
        let snapshot = generate_peer_snapshot(&mut state, "test-signing-key").unwrap();
        let validator_1 = state
            .nodes
            .iter()
            .find(|node| node.node_name == "validator-1")
            .unwrap();
        let rendered = render_wireguard_peer_config(&validator_1.id, &snapshot).unwrap();
        assert!(rendered.contains("AllowedIPs = 10.70.10.2/32"));
        assert!(rendered.contains("AllowedIPs = 10.70.20.1/32"));
        let private_supernet_route = format!("AllowedIPs = {}", VALIDATOR_VPN_CIDR);
        let full_tunnel_route = format!("AllowedIPs = {}", "0.0.0.0/0");
        assert!(!rendered.contains(&private_supernet_route));
        assert!(!rendered.contains(&full_tunnel_route));
    }

    #[test]
    fn innernet_dynamic_allocations_skip_canonical_bootstrap_slots() {
        assert_eq!(
            innernet_bootstrap_host_count(&ValidatorVpnRole::Validator),
            6
        );
        assert_eq!(innernet_bootstrap_host_count(&ValidatorVpnRole::Relayer), 3);
    }
}
