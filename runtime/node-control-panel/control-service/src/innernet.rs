use crate::app_context::AppContext;
use crate::monitor::ensure_monitor_workspace_with_context;
use base64::{engine::general_purpose, Engine as _};
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Mutex, OnceLock};
use uuid::Uuid;

const STATE_RELATIVE_PATH: &str = "testnet/runtime/innernet/enrollment-state.json";
const RECEIPT_DOMAIN: &str = "synergy-innernet-membership-v1";
const DEFAULT_INNERNET_INVITE_EXPIRY: &str = "30m";
const SERVER_HANDSHAKE_MAX_AGE_SECONDS: i64 = 300;
/// The Testnet-v3 release verifier rejects all earlier transport registry
/// generations. A fresh nine-peer bootstrap naturally reaches generation 9,
/// so its public release must be explicitly and audibly advanced once the
/// whole canonical mesh is server-confirmed.
pub const TESTNET_V3_MIN_TRANSPORT_RELEASE_GENERATION: u64 = 21;
/// SHA-256 of the immutable, governance-approved Testnet-v3 Genesis document.
///
/// The coordinator intentionally keeps this anchor compiled into the release
/// rather than accepting a caller-provided validator set.  A transport release
/// must never become an alternate source of consensus identity truth.
pub const TESTNET_V3_APPLIED_GENESIS_SHA256: &str =
    "ee554c197a878cbfdaf7d470a0274ab2859a7a0c14c87e425908a69c6fbb51cf";
/// The `header.genesis_hash` committed by that same immutable Genesis document.
pub const TESTNET_V3_APPLIED_GENESIS_HASH: &str =
    "c087b6b7c1aae6f13f4c0140ba9a230a12dea0fa52b611777dee69369457de3d";
/// SHA-256 of the newline-separated, slot-ordered
/// `validator-N=<Genesis synv address>` bindings in
/// `CANONICAL_BOOTSTRAP_VALIDATORS`.  This gives the narrow emergency repair
/// path an independently auditable, immutable binding anchor in addition to
/// the applied Genesis digest above.
pub const TESTNET_V3_CANONICAL_VALIDATOR_BINDINGS_SHA256: &str =
    "602abed04b0e17cfbe3d9720737b851d9cf9d5235393285a7271b2f7e8ecc80e";
// A temporary invitation key that has completed a handshake may belong to a
// client which is still redeeming. Recovery must wait longer than the normal
// confirmation freshness window before it can invalidate that key.
const STALE_UNREDEEMED_HANDSHAKE_RECOVERY_MIN_AGE_SECONDS: i64 =
    SERVER_HANDSHAKE_MAX_AGE_SECONDS + 60;
const CANONICAL_BOOTSTRAP_PEERS: [&str; 9] = [
    "relayer-1",
    "relayer-2",
    "relayer-3",
    "validator-1",
    "validator-2",
    "validator-3",
    "validator-4",
    "validator-5",
    "validator-6",
];
const CANONICAL_BOOTSTRAP_VALIDATORS: [(&str, &str); 6] = [
    ("validator-1", "synv11yc4cjehqjm6fp0ey4ppjptv0p3cwdy6r79t"),
    ("validator-2", "synv11k0vlmkt5gyp3czlgvlfm5yqkxu5nyvp4ekk"),
    ("validator-3", "synv11jk9pprkz7faykn4ez7hzaj2q7lg04l2fjgj"),
    ("validator-4", "synv11s7hag82s6d9f8urrv5cl40lyeamxelthpeg"),
    ("validator-5", "synv11cl92kxcx4jyzusecqydrxc8aj3hsgscrvtu"),
    ("validator-6", "synv1129lck2uvz73f59wd3yame0w04qnrdpmmmfc"),
];

#[derive(Debug, Clone, Serialize)]
pub struct GeneratedInvite {
    pub invite: String,
    pub assigned_ip: String,
    pub interface_name: String,
    pub expires_at: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct EnrollmentOffer {
    pub enrollment_id: String,
    pub confirmation_token: String,
    pub configuration_version: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct RedeemedEnrollmentRecovery {
    pub enrollment: EnrollmentOffer,
    pub assigned_ip: String,
    pub interface_name: String,
    pub expires_at: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct InnernetBootstrapAssignment {
    pub peer_name: String,
    pub peer_type: String,
    pub assigned_ip: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct EnrollmentConfirmation {
    pub enrollment_id: String,
    pub confirmation_token: String,
    pub interface_name: String,
    pub assigned_ip: String,
    pub handshake_confirmed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InnernetMembershipReceipt {
    pub version: u32,
    pub network: String,
    pub migration_id: String,
    pub enrollment_id: String,
    pub node_id: String,
    pub peer_name: String,
    pub peer_type: String,
    pub assigned_ip: String,
    pub interface_name: String,
    pub configuration_version: u64,
    pub confirmed_at: String,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InnernetValidatorTransport {
    pub validator_address: String,
    pub dial_address: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InnernetValidatorTransportSnapshot {
    pub version: u32,
    pub network: String,
    pub migration_id: String,
    pub configuration_version: u64,
    pub transports: Vec<InnernetValidatorTransport>,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct EnrollmentConfirmationResult {
    pub receipt: InnernetMembershipReceipt,
    pub vpn_node_id: String,
    pub bootstrap: bool,
    pub propagation: InnernetMeshStatus,
}

#[derive(Debug, Clone, Serialize)]
pub struct InnernetMeshStatus {
    pub network: String,
    pub migration_id: String,
    pub migration_ready: bool,
    pub latest_generation: u64,
    pub active_members: usize,
    pub acknowledged_member_ids: Vec<String>,
    pub pending_member_ids: Vec<String>,
    pub propagation_complete: bool,
    pub bootstrap_expected_members: usize,
    pub bootstrap_confirmed_member_ids: Vec<String>,
    pub bootstrap_pending_member_ids: Vec<String>,
    pub bootstrap_complete: bool,
}

/// Result of the narrow coordinator-admin generation advancement operation.
/// This deliberately contains no peer material or signing material.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct TransportReleaseGenerationAdvance {
    pub requested_minimum_generation: u64,
    pub previous_generation: u64,
    pub effective_generation: u64,
    pub advanced: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audit_recorded_at: Option<String>,
}

/// Result of the one-time Testnet-v3 canonical validator-address repair.
/// No WireGuard or Innernet peer material is exposed or changed by this
/// operation; the response records only public consensus addresses and the
/// monotonic signed-registry generation it caused.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct CanonicalValidatorAddressBindingCorrection {
    pub applied_genesis_sha256: String,
    pub applied_genesis_hash: String,
    pub canonical_validator_bindings_sha256: String,
    pub prior_snapshot_sha256: String,
    pub previous_generation: u64,
    pub effective_generation: u64,
    pub corrected_bindings: Vec<CanonicalValidatorAddressBindingChange>,
    pub audit_recorded_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CanonicalValidatorAddressBindingChange {
    pub peer_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub previous_validator_address: Option<String>,
    pub canonical_validator_address: String,
}

/// Immutable-in-practice audit data written together with the state change.
/// State mutations in this module only ever append these records; the record
/// is purposefully free of invitations, WireGuard keys, and admin secrets.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct TransportReleaseGenerationAuditRecord {
    requested_minimum_generation: u64,
    previous_generation: u64,
    effective_generation: u64,
    actor: String,
    reason: String,
    recorded_at: String,
}

/// Append-only evidence for the deliberately narrow V3 binding repair.  The
/// audit contains no enrollment secrets, WireGuard public keys, or endpoint
/// material.  It binds the change to both the applied Genesis hash and the
/// compiled canonical six-validator mapping.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct CanonicalValidatorAddressBindingCorrectionAuditRecord {
    applied_genesis_sha256: String,
    applied_genesis_hash: String,
    canonical_validator_bindings_sha256: String,
    prior_snapshot_sha256: String,
    previous_generation: u64,
    effective_generation: u64,
    actor: String,
    reason: String,
    corrected_bindings: Vec<CanonicalValidatorAddressBindingChange>,
    recorded_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct InnernetEnrollmentState {
    version: u32,
    latest_generation: u64,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    transport_release_generation_audit: Vec<TransportReleaseGenerationAuditRecord>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    canonical_validator_address_binding_correction_audit:
        Vec<CanonicalValidatorAddressBindingCorrectionAuditRecord>,
    enrollments: Vec<InnernetEnrollment>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct InnernetEnrollment {
    id: String,
    node_id: String,
    #[serde(default)]
    vpn_node_id: String,
    peer_name: String,
    peer_type: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    validator_address: Option<String>,
    assigned_ip: String,
    interface_name: String,
    configuration_version: u64,
    confirmation_token_hash: String,
    expires_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    confirmed_at: Option<String>,
    #[serde(default)]
    acknowledged_generation: u64,
    #[serde(default)]
    bootstrap: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    handshake_verified_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    preconfigured_wireguard_public_key: Option<String>,
}

/// Validate the coordinator configuration without requiring migration cutover.
/// Bootstrap enrollment uses this gate while the public onboarding caller keeps
/// the separate cutover check below.
pub fn require_coordinator_ready() -> Result<(), String> {
    let _ = required_env("SYNERGY_INNERNET_MIGRATION_ID")?;
    let signing_key = signing_key()?;
    let public_key = verifying_key(&required_env("SYNERGY_INNERNET_COORDINATOR_PUBLIC_KEY")?)?;
    if signing_key.verifying_key().to_bytes() != public_key.to_bytes() {
        return Err(
            "Innernet coordinator signing key does not match SYNERGY_INNERNET_COORDINATOR_PUBLIC_KEY."
                .to_string(),
        );
    }
    let _ = invitation_expiry()?;
    for name in [
        "SYNERGY_INNERNET_SERVER_COMMAND",
        "SYNERGY_INNERNET_INTERFACE",
        "SYNERGY_INNERNET_VALIDATOR_CIDR",
        "SYNERGY_INNERNET_RELAYER_CIDR",
        "SYNERGY_INNERNET_CONFIG_DIR",
        "SYNERGY_INNERNET_DATA_DIR",
        "SYNERGY_INNERNET_INVITE_DIR",
    ] {
        let _ = required_env(name)?;
    }
    let _ = innernet_address_plans()?;
    Ok(())
}

/// Validate the coordinator configuration before state is changed. A central
/// migration must be explicitly marked ready after its existing peers are
/// imported and re-enrolled; otherwise onboarding is blocked rather than
/// creating a second, partial VPN.
pub fn require_migration_ready(app_context: &AppContext) -> Result<(), String> {
    if !migration_cutover_enabled() {
        return Err(
            "Innernet migration is not ready. Complete coordinator bootstrap and validator re-enrollment before enabling new onboarding."
                .to_string(),
        );
    }
    require_coordinator_ready()?;
    reconcile_legacy_bootstrap_confirmations(app_context)?;
    let state = load_state(&state_path(app_context)?)?;
    if !bootstrap_status(&state)?.complete {
        return Err(
            "Innernet migration cutover requires server-verified confirmation from all nine canonical bootstrap peers."
                .to_string(),
        );
    }
    Ok(())
}

#[derive(Debug)]
struct LegacyBootstrapVerification {
    enrollment_index: usize,
    peer_name: String,
    interface_name: String,
    assigned_ip: String,
}

/// Coordinator versions before the server-verification cutover persisted a
/// confirmed bootstrap membership without `handshake_verified_at`. Reconcile
/// that legacy state only after every missing marker is independently proven
/// against the authoritative Innernet registry and live WireGuard interface.
/// State is written only after all nine canonical peers pass verification.
fn reconcile_legacy_bootstrap_confirmations(app_context: &AppContext) -> Result<(), String> {
    let state_path = state_path(app_context)?;
    let _guard = state_lock()
        .lock()
        .map_err(|_| "Innernet enrollment state lock is poisoned".to_string())?;
    let mut state = load_state(&state_path)?;
    if bootstrap_status(&state)?.complete {
        return Ok(());
    }

    let candidates = legacy_bootstrap_verification_candidates(&state)?;
    for candidate in &candidates {
        verify_server_handshake(
            &candidate.peer_name,
            &candidate.interface_name,
            &candidate.assigned_ip,
        )
        .map_err(|error| {
            format!(
                "Innernet migration could not server-verify canonical bootstrap peer {}: {error}",
                candidate.peer_name
            )
        })?;
    }

    if candidates.is_empty() {
        return Ok(());
    }
    let verified_at = Utc::now().to_rfc3339();
    for candidate in candidates {
        state.enrollments[candidate.enrollment_index].handshake_verified_at =
            Some(verified_at.clone());
    }
    save_state(&state_path, &state)
}

fn legacy_bootstrap_verification_candidates(
    state: &InnernetEnrollmentState,
) -> Result<Vec<LegacyBootstrapVerification>, String> {
    let mut candidates = Vec::new();
    for peer_name in CANONICAL_BOOTSTRAP_PEERS {
        let assignment = admin_bootstrap_assignment(peer_name)?;
        let node_id = format!("bootstrap-{peer_name}");
        let expected_ip = assignment
            .assigned_ip
            .split('/')
            .next()
            .expect("bootstrap assignments always contain an IP address");
        let (enrollment_index, enrollment) = state
            .enrollments
            .iter()
            .enumerate()
            .filter(|(_, entry)| entry.node_id == node_id)
            .max_by_key(|(_, entry)| entry.configuration_version)
            .ok_or_else(|| {
                format!("Innernet migration is missing canonical bootstrap peer {peer_name}.")
            })?;
        if !enrollment.bootstrap
            || enrollment.peer_name != peer_name
            || enrollment.peer_type != assignment.peer_type
            || enrollment.assigned_ip != expected_ip
            || enrollment.confirmed_at.is_none()
        {
            return Err(format!(
                "Innernet migration has an incomplete canonical bootstrap record for {peer_name}."
            ));
        }
        if enrollment.handshake_verified_at.is_none() {
            candidates.push(LegacyBootstrapVerification {
                enrollment_index,
                peer_name: enrollment.peer_name.clone(),
                interface_name: enrollment.interface_name.clone(),
                assigned_ip: enrollment.assigned_ip.clone(),
            });
        }
    }
    Ok(candidates)
}

pub fn migration_cutover_enabled() -> bool {
    std::env::var("SYNERGY_INNERNET_MIGRATION_READY")
        .ok()
        .map(|value| {
            matches!(
                value.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes"
            )
        })
        .unwrap_or(false)
}

/// Return the only peer names that may be assigned through the admin bootstrap
/// path. The slot is deliberately derived from the canonical name rather than
/// accepted from a caller, so bootstrap identity and address cannot drift.
pub fn admin_bootstrap_assignment(peer_name: &str) -> Result<InnernetBootstrapAssignment, String> {
    let (peer_type, address_variable, slot) = match peer_name {
        "relayer-1" => ("relayer", "SYNERGY_INNERNET_RELAYER_ADDRESS_CIDR", 1),
        "relayer-2" => ("relayer", "SYNERGY_INNERNET_RELAYER_ADDRESS_CIDR", 2),
        "relayer-3" => ("relayer", "SYNERGY_INNERNET_RELAYER_ADDRESS_CIDR", 3),
        "validator-1" => ("validator", "SYNERGY_INNERNET_VALIDATOR_ADDRESS_CIDR", 1),
        "validator-2" => ("validator", "SYNERGY_INNERNET_VALIDATOR_ADDRESS_CIDR", 2),
        "validator-3" => ("validator", "SYNERGY_INNERNET_VALIDATOR_ADDRESS_CIDR", 3),
        "validator-4" => ("validator", "SYNERGY_INNERNET_VALIDATOR_ADDRESS_CIDR", 4),
        "validator-5" => ("validator", "SYNERGY_INNERNET_VALIDATOR_ADDRESS_CIDR", 5),
        "validator-6" => ("validator", "SYNERGY_INNERNET_VALIDATOR_ADDRESS_CIDR", 6),
        _ => {
            return Err(format!(
                "Innernet bootstrap peer name {peer_name:?} is not canonical."
            ))
        }
    };
    let (validator_network, relayer_network) = innernet_address_plans()?;
    let network = if address_variable == "SYNERGY_INNERNET_VALIDATOR_ADDRESS_CIDR" {
        validator_network
    } else {
        relayer_network
    };
    let address = Ipv4Addr::from(network + slot).to_string();
    Ok(InnernetBootstrapAssignment {
        peer_name: peer_name.to_string(),
        peer_type: peer_type.to_string(),
        assigned_ip: format!("{address}/32"),
    })
}

fn canonical_bootstrap_validator_address(peer_name: &str) -> Option<&'static str> {
    CANONICAL_BOOTSTRAP_VALIDATORS
        .iter()
        .find_map(|(candidate, address)| (*candidate == peer_name).then_some(*address))
}

fn is_validator_address(value: &str) -> bool {
    value.len() >= 8
        && value.len() <= 128
        && value.starts_with("synv1")
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
}

fn innernet_address_plans() -> Result<(u32, u32), String> {
    let validator_network = parse_innernet_address_plan("SYNERGY_INNERNET_VALIDATOR_ADDRESS_CIDR")?;
    let relayer_network = parse_innernet_address_plan("SYNERGY_INNERNET_RELAYER_ADDRESS_CIDR")?;
    if validator_network == relayer_network {
        return Err(
            "Innernet validator and relayer address plans must be non-overlapping /24 networks."
                .to_string(),
        );
    }
    Ok((validator_network, relayer_network))
}

fn parse_innernet_address_plan(variable: &str) -> Result<u32, String> {
    let value = required_env(variable)?;
    let (address, prefix) = value
        .split_once('/')
        .ok_or_else(|| format!("{variable} must be an IPv4 /24 network, such as 10.70.10.0/24."))?;
    let address = address
        .parse::<Ipv4Addr>()
        .map_err(|_| format!("{variable} must use a valid IPv4 address."))?;
    if prefix != "24" || address.octets()[3] != 0 {
        return Err(format!(
            "{variable} must be an IPv4 /24 network with a zero host octet."
        ));
    }
    if !address.is_private() || (address.octets()[0] == 10 && address.octets()[1] == 69) {
        return Err(format!(
            "{variable} must use a private /24 that does not overlap the retiring 10.69.0.0/16 mesh."
        ));
    }
    Ok(u32::from(address))
}

/// Generate a one-time Innernet invitation through the coordinator-owned
/// `innernet-server` administration command. The generated TOML is returned
/// only to the authenticated enrollment caller and is deleted locally before
/// this function returns.
pub fn generate_invite(
    peer_name: &str,
    peer_type: &str,
    assigned_ip: &str,
) -> Result<GeneratedInvite, String> {
    require_coordinator_ready()?;
    let command_name = required_env("SYNERGY_INNERNET_SERVER_COMMAND")?;
    let interface = required_env("SYNERGY_INNERNET_INTERFACE")?;
    let cidr = match peer_type {
        "validator" => required_env("SYNERGY_INNERNET_VALIDATOR_CIDR")?,
        "relayer" => required_env("SYNERGY_INNERNET_RELAYER_CIDR")?,
        _ => return Err("Innernet peer type must be validator or relayer.".to_string()),
    };
    validate_identifier(peer_name, "Innernet peer name")?;
    validate_identifier(&interface, "Innernet interface name")?;
    validate_identifier(&cidr, "Innernet CIDR name")?;
    let assigned_ip = assigned_ip
        .split('/')
        .next()
        .ok_or_else(|| "Innernet peer assignment is missing an IP address.".to_string())?
        .parse::<IpAddr>()
        .map_err(|_| "Innernet peer assignment has an invalid IP address.".to_string())?;

    let config_dir = required_env("SYNERGY_INNERNET_CONFIG_DIR")?;
    let data_dir = required_env("SYNERGY_INNERNET_DATA_DIR")?;
    let (invite_expiry, invite_expires_at) = invitation_expiry()?;
    let invite_directory = PathBuf::from(required_env("SYNERGY_INNERNET_INVITE_DIR")?);
    fs::create_dir_all(&invite_directory).map_err(|error| {
        format!(
            "Failed to create protected Innernet invitation directory {}: {error}",
            invite_directory.display()
        )
    })?;
    let invitation_path = invite_directory.join(format!("invite-{}.toml", Uuid::new_v4()));

    let output = Command::new(command_name)
        .args(["--config-dir", config_dir.as_str()])
        .args(["--data-dir", data_dir.as_str()])
        .args(["add-peer", interface.as_str()])
        .args(["--name", peer_name])
        .args(["--cidr", cidr.as_str()])
        .args(["--ip", &assigned_ip.to_string()])
        .args(["--admin", "false"])
        .args(["--invite-expires", invite_expiry.as_str()])
        .args(["--save-config"])
        .arg(&invitation_path)
        .arg("--yes")
        .output()
        .map_err(|error| format!("Failed to execute Innernet server command: {error}"))?;
    if !output.status.success() {
        let _ = fs::remove_file(&invitation_path);
        let detail = sanitized_command_error(&output.stderr);
        return Err(format!(
            "Innernet server rejected the peer assignment (exit code {:?}){}.",
            output.status.code(),
            detail
        ));
    }

    let invitation = fs::read_to_string(&invitation_path).map_err(|error| {
        format!(
            "Innernet server did not write the one-time invitation {}: {error}",
            invitation_path.display()
        )
    });
    let _ = fs::remove_file(&invitation_path);
    let invitation = invitation?;
    let parsed = parse_invitation(&invitation)?;
    if parsed.interface_name != interface || parsed.assigned_ip != assigned_ip.to_string() {
        return Err(
            "Innernet invitation does not match the coordinator's assigned interface or address."
                .to_string(),
        );
    }
    ensure_unredeemed_server_peer_route(peer_name, &interface, &assigned_ip.to_string())?;
    Ok(GeneratedInvite {
        invite: invitation,
        assigned_ip: assigned_ip.to_string(),
        interface_name: interface,
        expires_at: invite_expires_at.to_rfc3339(),
    })
}

fn sanitized_command_error(stderr: &[u8]) -> String {
    let detail = String::from_utf8_lossy(stderr)
        .chars()
        .filter(|character| !character.is_control() || matches!(character, ' ' | '\t' | '\n'))
        .collect::<String>()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    let detail = detail.chars().take(512).collect::<String>();
    if detail.is_empty() {
        String::new()
    } else {
        format!(": {detail}")
    }
}

/// Bind enrollment state to the shorter of the onboarding-token and actual
/// Innernet invitation lifetimes. Innernet refuses expired invites itself, but
/// the coordinator must also refuse stale confirmation receipts.
pub fn constrained_expiry(
    onboarding_expires_at: &str,
    invite_expires_at: &str,
) -> Result<String, String> {
    let onboarding_expires_at = parse_expiry(onboarding_expires_at)?;
    let invite_expires_at = parse_expiry(invite_expires_at)?;
    Ok(std::cmp::min(onboarding_expires_at, invite_expires_at).to_rfc3339())
}

pub fn create_enrollment(
    app_context: &AppContext,
    node_id: &str,
    vpn_node_id: &str,
    peer_name: &str,
    peer_type: &str,
    validator_address: Option<&str>,
    assigned_ip: &str,
    interface_name: &str,
    expires_at: &str,
) -> Result<EnrollmentOffer, String> {
    require_coordinator_ready()?;
    create_enrollment_state(
        app_context,
        node_id,
        vpn_node_id,
        peer_name,
        peer_type,
        validator_address,
        assigned_ip,
        interface_name,
        expires_at,
        false,
        None,
    )
}

pub fn create_preconfigured_enrollment(
    app_context: &AppContext,
    node_id: &str,
    vpn_node_id: &str,
    peer_name: &str,
    validator_address: &str,
    assigned_ip: &str,
    wireguard_public_key: &str,
    expires_at: &str,
) -> Result<EnrollmentOffer, String> {
    require_coordinator_ready()?;
    let public_key = wireguard_public_key.trim();
    let decoded = general_purpose::STANDARD
        .decode(public_key)
        .map_err(|_| "Preconfigured WireGuard public key is invalid.".to_string())?;
    if decoded.len() != 32 {
        return Err("Preconfigured WireGuard public key is invalid.".to_string());
    }
    create_enrollment_state(
        app_context,
        node_id,
        vpn_node_id,
        peer_name,
        "validator",
        Some(validator_address),
        assigned_ip,
        "sy-vpn",
        expires_at,
        false,
        Some(public_key),
    )
}

/// Rotate only the coordinator confirmation credential for a dynamic peer
/// which already redeemed its invitation. This path never creates, removes, or
/// reassigns an Innernet peer and requires a fresh authoritative handshake.
pub fn recover_redeemed_enrollment_confirmation(
    app_context: &AppContext,
    node_id: &str,
    vpn_node_id: &str,
    peer_name: &str,
    peer_type: &str,
    validator_address: Option<&str>,
    assigned_ip: &str,
    expires_at: &str,
) -> Result<Option<RedeemedEnrollmentRecovery>, String> {
    require_coordinator_ready()?;
    let expires_at = parse_expiry(expires_at)?;
    if expires_at <= Utc::now() {
        return Err("The onboarding token has expired.".to_string());
    }
    let assigned_ip = assigned_ip
        .split('/')
        .next()
        .ok_or_else(|| "Innernet peer assignment is missing an IP address.".to_string())?
        .parse::<IpAddr>()
        .map_err(|_| "Innernet peer assignment has an invalid IP address.".to_string())?
        .to_string();
    let interface_name = required_env("SYNERGY_INNERNET_INTERFACE")?;
    validate_identifier(&interface_name, "Innernet interface name")?;
    let validator_address = validator_address.map(str::trim);
    let state_path = state_path(app_context)?;
    let _guard = state_lock()
        .lock()
        .map_err(|_| "Innernet enrollment state lock is poisoned".to_string())?;
    let mut state = load_state(&state_path)?;
    let index = state
        .enrollments
        .iter()
        .enumerate()
        .filter(|(_, enrollment)| {
            !enrollment.bootstrap
                && enrollment.confirmed_at.is_none()
                && enrollment.node_id == node_id
                && enrollment.vpn_node_id == vpn_node_id
                && enrollment.peer_name == peer_name
                && enrollment.peer_type == peer_type
                && enrollment.validator_address.as_deref() == validator_address
                && enrollment.assigned_ip == assigned_ip
                && enrollment.interface_name == interface_name
        })
        .max_by_key(|(_, enrollment)| enrollment.configuration_version)
        .map(|(index, _)| index);
    let Some(index) = index else {
        return Ok(None);
    };
    if innernet_server_peer(peer_name, &interface_name, &assigned_ip)?.is_none() {
        return Ok(None);
    }
    verify_server_handshake(peer_name, &interface_name, &assigned_ip)?;

    state.latest_generation = state.latest_generation.saturating_add(1).max(1);
    let confirmation_token = random_secret();
    let configuration_version = state.latest_generation;
    let enrollment_id = state.enrollments[index].id.clone();
    state.enrollments[index].confirmation_token_hash = hash_secret(&confirmation_token);
    state.enrollments[index].expires_at = expires_at.to_rfc3339();
    state.enrollments[index].configuration_version = configuration_version;
    state.enrollments[index].acknowledged_generation = 0;
    state.enrollments[index].handshake_verified_at = None;
    save_state(&state_path, &state)?;
    Ok(Some(RedeemedEnrollmentRecovery {
        enrollment: EnrollmentOffer {
            enrollment_id,
            confirmation_token,
            configuration_version,
        },
        assigned_ip,
        interface_name,
        expires_at: expires_at.to_rfc3339(),
    }))
}

pub fn create_bootstrap_enrollment(
    app_context: &AppContext,
    node_id: &str,
    vpn_node_id: &str,
    peer_name: &str,
    peer_type: &str,
    assigned_ip: &str,
    interface_name: &str,
    expires_at: &str,
) -> Result<EnrollmentOffer, String> {
    require_coordinator_ready()?;
    let assignment = admin_bootstrap_assignment(peer_name)?;
    if assignment.peer_type != peer_type {
        return Err(
            "Innernet bootstrap enrollment does not match the canonical peer assignment."
                .to_string(),
        );
    }
    let canonical_node_id = format!("bootstrap-{}", assignment.peer_name);
    if node_id != canonical_node_id || vpn_node_id != canonical_node_id {
        return Err(
            "Innernet bootstrap enrollment does not match the canonical node identity.".to_string(),
        );
    }
    let assigned_ip = normalize_bootstrap_ip(&assignment, assigned_ip)?;
    let validator_address = canonical_bootstrap_validator_address(peer_name);
    create_enrollment_state(
        app_context,
        node_id,
        vpn_node_id,
        peer_name,
        peer_type,
        validator_address,
        &assigned_ip,
        interface_name,
        expires_at,
        true,
        None,
    )
}

/// Reject duplicate bootstrap invitations before the coordinator invokes the
/// stateful upstream `innernet-server add-peer` command. The HTTP caller is
/// admin-only and serializes the resulting invite delivery.
pub fn ensure_bootstrap_enrollment_available(
    app_context: &AppContext,
    node_id: &str,
) -> Result<(), String> {
    require_coordinator_ready()?;
    let state_path = state_path(app_context)?;
    let _guard = state_lock()
        .lock()
        .map_err(|_| "Innernet enrollment state lock is poisoned".to_string())?;
    let state = load_state(&state_path)?;
    if state.enrollments.iter().any(|entry| {
        entry.node_id == node_id
            && entry.confirmed_at.is_none()
            && parse_expiry(&entry.expires_at)
                .map(|expiry| expiry > Utc::now())
                .unwrap_or(false)
    }) {
        return Err("An unconfirmed Innernet invitation already exists for this bootstrap peer. Redeem that invitation or let it expire before requesting another.".to_string());
    }
    Ok(())
}

/// Recreate a bootstrap invitation only after a failed delivery has been
/// proven not to have joined the mesh. This is deliberately narrower than a
/// general retry: it accepts canonical peers only, expires the prior
/// coordinator credential, and removes only an unredeemed peer with no
/// WireGuard handshake before requesting a new server-generated invitation.
pub fn reissue_unredeemed_bootstrap_invite(
    app_context: &AppContext,
    peer_name: &str,
) -> Result<
    (
        InnernetBootstrapAssignment,
        GeneratedInvite,
        EnrollmentOffer,
    ),
    String,
> {
    reissue_bootstrap_invite(app_context, peer_name, false)
}

/// Recover an invitation that reached the temporary WireGuard peer but never
/// redeemed with Innernet. This is intentionally distinct from ordinary
/// reissue: it can only retire an unredeemed peer after its last server-side
/// handshake is older than the normal confirmation freshness window.
pub fn recover_stale_unredeemed_bootstrap_invite(
    app_context: &AppContext,
    peer_name: &str,
) -> Result<
    (
        InnernetBootstrapAssignment,
        GeneratedInvite,
        EnrollmentOffer,
    ),
    String,
> {
    reissue_bootstrap_invite(app_context, peer_name, true)
}

/// Replace a lost coordinator confirmation credential only after the server has
/// already proved that the canonical bootstrap peer redeemed its invitation and
/// completed a fresh handshake. This never changes an Innernet peer, address,
/// invitation, or membership state.
pub fn recover_redeemed_bootstrap_confirmation(
    app_context: &AppContext,
    peer_name: &str,
) -> Result<(InnernetBootstrapAssignment, EnrollmentOffer, String, String), String> {
    require_coordinator_ready()?;
    let assignment = admin_bootstrap_assignment(peer_name)?;
    let node_id = format!("bootstrap-{}", assignment.peer_name);
    let expected_ip = assignment
        .assigned_ip
        .split('/')
        .next()
        .expect("bootstrap assignments always contain an IP address");
    let state_path = state_path(app_context)?;
    let _guard = state_lock()
        .lock()
        .map_err(|_| "Innernet enrollment state lock is poisoned".to_string())?;
    let mut state = load_state(&state_path)?;
    let index = state
        .enrollments
        .iter()
        .enumerate()
        .filter(|(_, entry)| entry.node_id == node_id)
        .max_by_key(|(_, entry)| entry.configuration_version)
        .map(|(index, _)| index)
        .ok_or_else(|| {
            "No prior bootstrap enrollment is available for confirmation recovery.".to_string()
        })?;
    let (interface_name, assigned_ip, configuration_version) = {
        let enrollment = &state.enrollments[index];
        if enrollment.confirmed_at.is_some() {
            return Err(
                "A confirmed bootstrap peer does not need confirmation recovery.".to_string(),
            );
        }
        if parse_expiry(&enrollment.expires_at)? <= Utc::now() {
            return Err("The bootstrap confirmation credential has expired.".to_string());
        }
        if !enrollment.bootstrap
            || enrollment.peer_name != assignment.peer_name
            || enrollment.peer_type != assignment.peer_type
            || enrollment.assigned_ip != expected_ip
        {
            return Err(
                "The prior enrollment does not match the canonical bootstrap peer.".to_string(),
            );
        }
        (
            enrollment.interface_name.clone(),
            enrollment.assigned_ip.clone(),
            enrollment.configuration_version,
        )
    };
    verify_server_handshake(&assignment.peer_name, &interface_name, &assigned_ip)?;

    let confirmation_token = random_secret();
    state.enrollments[index].confirmation_token_hash = hash_secret(&confirmation_token);
    save_state(&state_path, &state)?;
    Ok((
        assignment,
        EnrollmentOffer {
            enrollment_id: state.enrollments[index].id.clone(),
            confirmation_token,
            configuration_version,
        },
        interface_name,
        assigned_ip,
    ))
}

fn reissue_bootstrap_invite(
    app_context: &AppContext,
    peer_name: &str,
    allow_stale_unredeemed_handshake_recovery: bool,
) -> Result<
    (
        InnernetBootstrapAssignment,
        GeneratedInvite,
        EnrollmentOffer,
    ),
    String,
> {
    require_coordinator_ready()?;
    let assignment = admin_bootstrap_assignment(peer_name)?;
    let node_id = format!("bootstrap-{}", assignment.peer_name);
    let expected_ip = assignment
        .assigned_ip
        .split('/')
        .next()
        .expect("bootstrap assignments always contain an IP address");
    let state_path = state_path(app_context)?;
    {
        let _guard = state_lock()
            .lock()
            .map_err(|_| "Innernet enrollment state lock is poisoned".to_string())?;
        let mut state = load_state(&state_path)?;
        let index = state
            .enrollments
            .iter()
            .enumerate()
            .filter(|(_, entry)| entry.node_id == node_id)
            .max_by_key(|(_, entry)| entry.configuration_version)
            .map(|(index, _)| index)
            .ok_or_else(|| {
                "No prior bootstrap enrollment is available for controlled reissue.".to_string()
            })?;
        let enrollment = &mut state.enrollments[index];
        if enrollment.confirmed_at.is_some() {
            return Err("A confirmed bootstrap peer cannot be reissued.".to_string());
        }
        if !enrollment.bootstrap
            || enrollment.peer_name != assignment.peer_name.as_str()
            || enrollment.peer_type != assignment.peer_type.as_str()
            || enrollment.assigned_ip != expected_ip
        {
            return Err(
                "The prior enrollment does not match the canonical bootstrap peer.".to_string(),
            );
        }
        // Invalidate the lost confirmation token before removing the unredeemed
        // server peer. If cleanup is interrupted, this operation remains safe
        // to retry and never revives the old credential.
        enrollment.expires_at = Utc::now().to_rfc3339();
        save_state(&state_path, &state)?;
    }
    remove_unredeemed_server_peer(
        &assignment.peer_name,
        expected_ip,
        allow_stale_unredeemed_handshake_recovery,
    )?;
    let invite = generate_invite(
        &assignment.peer_name,
        &assignment.peer_type,
        &assignment.assigned_ip,
    )?;
    let enrollment = create_bootstrap_enrollment(
        app_context,
        &node_id,
        &node_id,
        &assignment.peer_name,
        &assignment.peer_type,
        &invite.assigned_ip,
        &invite.interface_name,
        &invite.expires_at,
    )?;
    Ok((assignment, invite, enrollment))
}

fn normalize_bootstrap_ip(
    assignment: &InnernetBootstrapAssignment,
    assigned_ip: &str,
) -> Result<String, String> {
    let (address, prefix) = assigned_ip.trim().split_once('/').map_or_else(
        || (assigned_ip.trim(), None),
        |(address, prefix)| (address, Some(prefix)),
    );
    if prefix.is_some_and(|prefix| prefix != "32") {
        return Err(
            "Innernet bootstrap enrollment does not match the canonical peer assignment."
                .to_string(),
        );
    }
    let address = address
        .parse::<IpAddr>()
        .map_err(|_| "Innernet bootstrap enrollment has an invalid IP address.".to_string())?;
    let expected = assignment
        .assigned_ip
        .split('/')
        .next()
        .expect("bootstrap assignment always contains an address");
    if address.to_string() != expected {
        return Err(
            "Innernet bootstrap enrollment does not match the canonical peer assignment."
                .to_string(),
        );
    }
    Ok(address.to_string())
}

fn create_enrollment_state(
    app_context: &AppContext,
    node_id: &str,
    vpn_node_id: &str,
    peer_name: &str,
    peer_type: &str,
    validator_address: Option<&str>,
    assigned_ip: &str,
    interface_name: &str,
    expires_at: &str,
    bootstrap: bool,
    preconfigured_wireguard_public_key: Option<&str>,
) -> Result<EnrollmentOffer, String> {
    let validator_address = match (peer_type, validator_address.map(str::trim)) {
        ("validator", Some(value)) if is_validator_address(value) => Some(value.to_string()),
        ("validator", _) => {
            return Err(
                "Innernet validator enrollment requires a canonical validator address.".to_string(),
            )
        }
        ("relayer", None) => None,
        ("relayer", Some(_)) => {
            return Err(
                "Innernet relayer enrollment must not include a validator address.".to_string(),
            )
        }
        _ => return Err("Innernet peer type must be validator or relayer.".to_string()),
    };
    let expires_at = parse_expiry(expires_at)?;
    let state_path = state_path(app_context)?;
    let _guard = state_lock()
        .lock()
        .map_err(|_| "Innernet enrollment state lock is poisoned".to_string())?;
    let mut state = load_state(&state_path)?;
    if state.enrollments.iter().any(|entry| {
        entry.node_id == node_id
            && entry.confirmed_at.is_none()
            && parse_expiry(&entry.expires_at)
                .map(|expiry| expiry > Utc::now())
                .unwrap_or(false)
    }) {
        return Err("An unconfirmed Innernet invitation already exists for this node. Redeem that invitation or let it expire before requesting another.".to_string());
    }

    state.latest_generation = state.latest_generation.saturating_add(1).max(1);
    let confirmation_token = random_secret();
    let enrollment = InnernetEnrollment {
        id: Uuid::new_v4().to_string(),
        node_id: node_id.to_string(),
        vpn_node_id: vpn_node_id.to_string(),
        peer_name: peer_name.to_string(),
        peer_type: peer_type.to_string(),
        validator_address,
        assigned_ip: assigned_ip.to_string(),
        interface_name: interface_name.to_string(),
        configuration_version: state.latest_generation,
        confirmation_token_hash: hash_secret(&confirmation_token),
        expires_at: expires_at.to_rfc3339(),
        confirmed_at: None,
        acknowledged_generation: 0,
        bootstrap,
        handshake_verified_at: None,
        preconfigured_wireguard_public_key: preconfigured_wireguard_public_key.map(str::to_string),
    };
    let offer = EnrollmentOffer {
        enrollment_id: enrollment.id.clone(),
        confirmation_token,
        configuration_version: enrollment.configuration_version,
    };
    state.enrollments.push(enrollment);
    save_state(&state_path, &state)?;
    Ok(offer)
}

pub fn confirm_enrollment(
    app_context: &AppContext,
    confirmation: EnrollmentConfirmation,
) -> Result<EnrollmentConfirmationResult, String> {
    require_coordinator_ready()?;
    let state_path = state_path(app_context)?;
    let _guard = state_lock()
        .lock()
        .map_err(|_| "Innernet enrollment state lock is poisoned".to_string())?;
    let mut state = load_state(&state_path)?;
    let index = state
        .enrollments
        .iter()
        .position(|entry| entry.id == confirmation.enrollment_id)
        .ok_or_else(|| "Innernet enrollment was not found.".to_string())?;
    let (peer_name, interface_name, assigned_ip, preconfigured_wireguard_public_key) = {
        let enrollment = &state.enrollments[index];
        // Redemption can complete before expiry while the desktop process fails
        // before confirmation. The secret, interface, address, active redeemed
        // peer, and fresh server-observed handshake below are the recovery gate;
        // an expired unredeemed invitation cannot satisfy that proof.
        let _ = parse_expiry(&enrollment.expires_at)?;
        if hash_secret(&confirmation.confirmation_token) != enrollment.confirmation_token_hash {
            return Err("Innernet enrollment confirmation is unauthorized.".to_string());
        }
        if confirmation.interface_name.trim() != enrollment.interface_name
            || confirmation.assigned_ip.trim() != enrollment.assigned_ip
        {
            return Err(
                "Innernet confirmation does not match the assigned interface or address."
                    .to_string(),
            );
        }
        if !confirmation.handshake_confirmed {
            return Err("Innernet confirmation requires local handshake evidence.".to_string());
        }
        (
            enrollment.peer_name.clone(),
            enrollment.interface_name.clone(),
            enrollment.assigned_ip.clone(),
            enrollment.preconfigured_wireguard_public_key.clone(),
        )
    };
    if let Some(public_key) = preconfigured_wireguard_public_key {
        verify_preconfigured_server_handshake(&interface_name, &public_key)?;
    } else {
        verify_server_handshake(&peer_name, &interface_name, &assigned_ip)?;
    }
    let (receipt, vpn_node_id, bootstrap) = {
        let enrollment = &mut state.enrollments[index];
        if enrollment.confirmed_at.is_none() {
            enrollment.confirmed_at = Some(Utc::now().to_rfc3339());
        }
        enrollment.handshake_verified_at = Some(Utc::now().to_rfc3339());
        enrollment.acknowledged_generation = state.latest_generation;
        (
            receipt_for(enrollment)?,
            enrollment.vpn_node_id.clone(),
            enrollment.bootstrap,
        )
    };
    let propagation = mesh_status_from_state(&state)?;
    save_state(&state_path, &state)?;
    Ok(EnrollmentConfirmationResult {
        receipt,
        vpn_node_id,
        bootstrap,
        propagation,
    })
}

pub fn authorize_enrollment_status(
    app_context: &AppContext,
    enrollment_id: &str,
    confirmation_token: &str,
) -> Result<(), String> {
    let state = load_state(&state_path(app_context)?)?;
    let enrollment = state
        .enrollments
        .iter()
        .find(|entry| entry.id == enrollment_id)
        .ok_or_else(|| "Innernet enrollment was not found.".to_string())?;
    if hash_secret(confirmation_token) != enrollment.confirmation_token_hash {
        return Err("Innernet mesh status is unauthorized.".to_string());
    }
    Ok(())
}

/// Authorize recovery of the current signed transport map from a previously
/// confirmed membership receipt. This lets an upgraded control panel repair
/// legacy local evidence without rotating the peer, address, or one-time
/// invitation. The receipt is accepted only while it still matches the
/// coordinator's confirmed enrollment record exactly.
pub fn authorize_membership_receipt(
    app_context: &AppContext,
    receipt: &InnernetMembershipReceipt,
) -> Result<(), String> {
    verify_membership_receipt(receipt)?;
    let state = load_state(&state_path(app_context)?)?;
    let enrollment = state
        .enrollments
        .iter()
        .find(|entry| entry.id == receipt.enrollment_id)
        .ok_or_else(|| "Innernet membership receipt enrollment was not found.".to_string())?;
    let confirmed_at = enrollment
        .confirmed_at
        .as_deref()
        .ok_or_else(|| "Innernet membership receipt enrollment is not confirmed.".to_string())?;
    if !membership_receipt_matches_enrollment(enrollment, confirmed_at, receipt) {
        return Err(
            "Innernet membership receipt no longer matches the confirmed coordinator enrollment."
                .to_string(),
        );
    }
    Ok(())
}

fn membership_receipt_matches_enrollment(
    enrollment: &InnernetEnrollment,
    confirmed_at: &str,
    receipt: &InnernetMembershipReceipt,
) -> bool {
    enrollment.id == receipt.enrollment_id
        && enrollment.node_id == receipt.node_id
        && enrollment.peer_name == receipt.peer_name
        && enrollment.peer_type == receipt.peer_type
        && enrollment.assigned_ip == receipt.assigned_ip
        && enrollment.interface_name == receipt.interface_name
        && enrollment.configuration_version == receipt.configuration_version
        && confirmed_at == receipt.confirmed_at
}

pub fn mesh_status(app_context: &AppContext) -> Result<InnernetMeshStatus, String> {
    require_coordinator_ready()?;
    let state = load_state(&state_path(app_context)?)?;
    mesh_status_from_state(&state)
}

#[derive(Debug, Deserialize)]
struct InnernetServerPeer {
    public_key: String,
    is_redeemed: i64,
    is_disabled: i64,
}

/// Confirm the client-reported handshake against the authoritative Innernet
/// server database and its live WireGuard interface. A confirmation credential
/// alone is never sufficient to produce a membership receipt.
fn verify_server_handshake(
    peer_name: &str,
    interface_name: &str,
    assigned_ip: &str,
) -> Result<(), String> {
    let peer = innernet_server_peer(peer_name, interface_name, assigned_ip)?.ok_or_else(|| {
        "The authoritative Innernet peer registry does not contain the assigned peer.".to_string()
    })?;
    if peer.is_redeemed == 0 || peer.is_disabled != 0 {
        return Err(
            "The Innernet peer has not redeemed an active coordinator invitation.".to_string(),
        );
    }
    let wireguard_dump = wireguard_dump(interface_name)?;
    if !has_fresh_server_handshake(&wireguard_dump, &peer.public_key, Utc::now().timestamp()) {
        return Err(
            "The Innernet peer has not completed a fresh server-observed WireGuard handshake."
                .to_string(),
        );
    }
    Ok(())
}

fn verify_preconfigured_server_handshake(
    interface_name: &str,
    public_key: &str,
) -> Result<(), String> {
    validate_identifier(interface_name, "WireGuard interface name")?;
    let wireguard_dump = wireguard_dump(interface_name)?;
    if !has_fresh_server_handshake(&wireguard_dump, public_key, Utc::now().timestamp()) {
        return Err(
            "The preconfigured validator has not completed a fresh server-observed WireGuard handshake."
                .to_string(),
        );
    }
    Ok(())
}

fn innernet_server_peer(
    peer_name: &str,
    interface_name: &str,
    assigned_ip: &str,
) -> Result<Option<InnernetServerPeer>, String> {
    validate_identifier(peer_name, "Innernet peer name")?;
    validate_identifier(interface_name, "Innernet interface name")?;
    let assigned_ip = assigned_ip
        .parse::<IpAddr>()
        .map_err(|_| "Innernet enrollment has an invalid assigned IP address.".to_string())?;
    let database = innernet_database_path(interface_name)?;
    const PEER_LOOKUP: &str = r#"
import json
import sqlite3
import sys

connection = sqlite3.connect(sys.argv[1])
row = connection.execute(
    "SELECT public_key, is_redeemed, is_disabled FROM peers WHERE name = ? AND ip = ?",
    (sys.argv[2], sys.argv[3]),
).fetchone()
if row is None:
    raise SystemExit(2)
print(json.dumps({"public_key": row[0], "is_redeemed": row[1], "is_disabled": row[2]}))
"#;
    let output = Command::new("python3")
        .args([
            "-c",
            PEER_LOOKUP,
            database.as_str(),
            peer_name,
            &assigned_ip.to_string(),
        ])
        .output()
        .map_err(|_| {
            "The coordinator could not query the authoritative Innernet peer registry.".to_string()
        })?;
    if output.status.code() == Some(2) {
        return Ok(None);
    }
    if !output.status.success() {
        return Err(
            "The coordinator could not query the authoritative Innernet peer registry.".to_string(),
        );
    }
    let peer: InnernetServerPeer = serde_json::from_slice(&output.stdout).map_err(|_| {
        "The authoritative Innernet peer registry returned invalid data.".to_string()
    })?;
    Ok(Some(peer))
}

pub fn authoritative_assigned_ips() -> Result<HashSet<String>, String> {
    let interface_name = required_env("SYNERGY_INNERNET_INTERFACE")?;
    validate_identifier(&interface_name, "Innernet interface name")?;
    let database = innernet_database_path(&interface_name)?;
    const ASSIGNED_IP_LOOKUP: &str = r#"
import json
import sqlite3
import sys

connection = sqlite3.connect(sys.argv[1])
rows = connection.execute("SELECT ip FROM peers").fetchall()
print(json.dumps([row[0] for row in rows]))
"#;
    let output = Command::new("python3")
        .args(["-c", ASSIGNED_IP_LOOKUP, database.as_str()])
        .output()
        .map_err(|_| {
            "The coordinator could not query authoritative Innernet address assignments."
                .to_string()
        })?;
    if !output.status.success() {
        return Err(
            "The coordinator could not query authoritative Innernet address assignments."
                .to_string(),
        );
    }
    let addresses: Vec<String> = serde_json::from_slice(&output.stdout).map_err(|_| {
        "The authoritative Innernet address registry returned invalid data.".to_string()
    })?;
    Ok(addresses
        .into_iter()
        .filter_map(|value| value.parse::<IpAddr>().ok().map(|ip| ip.to_string()))
        .collect())
}

fn innernet_database_path(interface_name: &str) -> Result<String, String> {
    validate_identifier(interface_name, "Innernet interface name")?;
    let data_dir = required_env("SYNERGY_INNERNET_DATA_DIR")?;
    PathBuf::from(data_dir)
        .join(format!("{interface_name}.db"))
        .to_str()
        .map(str::to_string)
        .ok_or_else(|| "Innernet server database path is not valid UTF-8.".to_string())
}

fn wireguard_dump(interface_name: &str) -> Result<String, String> {
    validate_identifier(interface_name, "Innernet interface name")?;
    let output = Command::new("wg")
        .args(["show", interface_name, "dump"])
        .output()
        .map_err(|_| {
            "The coordinator could not inspect the Innernet WireGuard interface.".to_string()
        })?;
    if !output.status.success() {
        return Err("The coordinator Innernet WireGuard interface is unavailable.".to_string());
    }
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

fn remove_unredeemed_server_peer(
    peer_name: &str,
    assigned_ip: &str,
    allow_stale_unredeemed_handshake_recovery: bool,
) -> Result<(), String> {
    let interface_name = required_env("SYNERGY_INNERNET_INTERFACE")?;
    let Some(peer) = innernet_server_peer(peer_name, &interface_name, assigned_ip)? else {
        // A previous interrupted reissue may already have completed this
        // cleanup. The coordinator state has been expired, so generating the
        // replacement invitation is safe and idempotent.
        return Ok(());
    };
    if peer.is_redeemed != 0 {
        return Err("A redeemed Innernet peer cannot be reissued.".to_string());
    }
    let current_dump = wireguard_dump(&interface_name)?;
    if let Some(last_handshake) = server_handshake_timestamp(&current_dump, &peer.public_key) {
        if !allow_stale_unredeemed_handshake_recovery {
            return Err(
                "An Innernet peer with a server-observed handshake cannot be reissued.".to_string(),
            );
        }
        let now = Utc::now().timestamp();
        if last_handshake > now.saturating_add(60) {
            return Err(
                "The Innernet peer reported an invalid future handshake timestamp; stale recovery is blocked."
                    .to_string(),
            );
        }
        let handshake_age = now.saturating_sub(last_handshake);
        if handshake_age < STALE_UNREDEEMED_HANDSHAKE_RECOVERY_MIN_AGE_SECONDS {
            return Err(format!(
                "The unredeemed Innernet peer handshake is too recent for recovery; wait at least {} seconds after the last handshake.",
                STALE_UNREDEEMED_HANDSHAKE_RECOVERY_MIN_AGE_SECONDS
            ));
        }
    } else if allow_stale_unredeemed_handshake_recovery {
        return Err(
            "Stale Innernet recovery requires a server-observed unredeemed handshake. Use the standard reissue endpoint instead."
                .to_string(),
        );
    }
    if current_dump
        .lines()
        .skip(1)
        .any(|line| line.split('\t').next() == Some(peer.public_key.as_str()))
    {
        let removal = Command::new("wg")
            .args(["set", &interface_name, "peer", &peer.public_key, "remove"])
            .output()
            .map_err(|_| {
                "The coordinator could not remove the unredeemed Innernet peer.".to_string()
            })?;
        if !removal.status.success() {
            return Err(
                "The coordinator could not remove the unredeemed Innernet peer.".to_string(),
            );
        }
    }
    let database = innernet_database_path(&interface_name)?;
    const PEER_DELETE: &str = r#"
import sqlite3
import sys

connection = sqlite3.connect(sys.argv[1])
connection.execute("BEGIN IMMEDIATE")
cursor = connection.execute(
    "DELETE FROM peers WHERE name = ? AND ip = ? AND public_key = ? AND is_redeemed = 0",
    (sys.argv[2], sys.argv[3], sys.argv[4]),
)
if cursor.rowcount != 1:
    connection.rollback()
    raise SystemExit(2)
connection.commit()
"#;
    let deleted = Command::new("python3")
        .args([
            "-c",
            PEER_DELETE,
            database.as_str(),
            peer_name,
            assigned_ip,
            &peer.public_key,
        ])
        .output()
        .map_err(|_| {
            "The coordinator could not remove the unredeemed Innernet peer.".to_string()
        })?;
    if !deleted.status.success() {
        return Err("The coordinator could not remove the unredeemed Innernet peer.".to_string());
    }
    Ok(())
}

/// `innernet-server add-peer` should install the temporary invitation key on
/// the running WireGuard device. Some constrained service environments persist
/// the database row without updating that device, which makes first redemption
/// impossible because the client cannot reach the Innernet API over its new
/// tunnel. Attach only the exact unredeemed peer and exact /32, then verify it
/// before returning an invitation.
fn ensure_unredeemed_server_peer_route(
    peer_name: &str,
    interface_name: &str,
    assigned_ip: &str,
) -> Result<(), String> {
    let peer = innernet_server_peer(peer_name, interface_name, assigned_ip)?.ok_or_else(|| {
        "The authoritative Innernet peer registry does not contain the generated invitation peer."
            .to_string()
    })?;
    if peer.is_redeemed != 0 || peer.is_disabled != 0 {
        return Err(
            "The generated Innernet invitation peer is not active and unredeemed.".to_string(),
        );
    }
    let current_dump = wireguard_dump(interface_name)?;
    if !wireguard_has_peer(&current_dump, &peer.public_key) {
        let address = assigned_ip.parse::<IpAddr>().map_err(|_| {
            "The generated Innernet invitation has an invalid IP address.".to_string()
        })?;
        let attached = Command::new("wg")
            .args([
                "set",
                interface_name,
                "peer",
                &peer.public_key,
                "allowed-ips",
                &format!("{address}/32"),
            ])
            .output()
            .map_err(|_| {
                "The coordinator could not attach the Innernet invitation peer.".to_string()
            })?;
        if !attached.status.success() {
            return Err(
                "The coordinator could not attach the Innernet invitation peer.".to_string(),
            );
        }
    }
    if !wireguard_has_peer(&wireguard_dump(interface_name)?, &peer.public_key) {
        return Err(
            "The Innernet invitation peer is not present on the coordinator WireGuard interface."
                .to_string(),
        );
    }
    Ok(())
}

fn has_fresh_server_handshake(wireguard_dump: &str, public_key: &str, now: i64) -> bool {
    wireguard_dump.lines().skip(1).any(|line| {
        let fields: Vec<&str> = line.split('\t').collect();
        if fields.len() < 5 || fields[0] != public_key {
            return false;
        }
        let Ok(last_handshake) = fields[4].parse::<i64>() else {
            return false;
        };
        last_handshake > 0
            && last_handshake <= now.saturating_add(60)
            && now.saturating_sub(last_handshake) <= SERVER_HANDSHAKE_MAX_AGE_SECONDS
    })
}

#[cfg(test)]
fn server_handshake_age_seconds(wireguard_dump: &str, public_key: &str, now: i64) -> Option<i64> {
    let last_handshake = server_handshake_timestamp(wireguard_dump, public_key)?;
    (last_handshake <= now.saturating_add(60)).then(|| now.saturating_sub(last_handshake))
}

fn server_handshake_timestamp(wireguard_dump: &str, public_key: &str) -> Option<i64> {
    wireguard_dump.lines().skip(1).find_map(|line| {
        let fields: Vec<&str> = line.split('\t').collect();
        if fields.len() < 5 || fields[0] != public_key {
            return None;
        }
        let Ok(last_handshake) = fields[4].parse::<i64>() else {
            return None;
        };
        if last_handshake <= 0 {
            return None;
        }
        Some(last_handshake)
    })
}

fn wireguard_has_peer(wireguard_dump: &str, public_key: &str) -> bool {
    wireguard_dump
        .lines()
        .skip(1)
        .any(|line| line.split('\t').next() == Some(public_key))
}

pub fn verify_membership_receipt(receipt: &InnernetMembershipReceipt) -> Result<(), String> {
    if receipt.version != 1 || receipt.network != RECEIPT_DOMAIN {
        return Err(
            "Innernet membership receipt has an unsupported network or version.".to_string(),
        );
    }
    if receipt.node_id.trim().is_empty()
        || receipt.enrollment_id.trim().is_empty()
        || receipt.interface_name.trim().is_empty()
        || receipt.assigned_ip.parse::<IpAddr>().is_err()
        || receipt.configuration_version == 0
    {
        return Err("Innernet membership receipt is incomplete.".to_string());
    }
    let public_key = required_env("SYNERGY_INNERNET_COORDINATOR_PUBLIC_KEY")?;
    let verifying_key = verifying_key(&public_key)?;
    let signature = receipt
        .signature
        .strip_prefix("ed25519:")
        .ok_or_else(|| "Innernet membership receipt must use ed25519.".to_string())?;
    let signature_bytes = general_purpose::STANDARD
        .decode(signature)
        .map_err(|error| format!("Innernet membership receipt signature is invalid: {error}"))?;
    let signature_bytes: [u8; 64] = signature_bytes
        .try_into()
        .map_err(|_| "Innernet membership receipt signature must be 64 bytes.".to_string())?;
    verifying_key
        .verify(
            &receipt_payload(receipt)?,
            &Signature::from_bytes(&signature_bytes),
        )
        .map_err(|_| "Innernet membership receipt signature verification failed.".to_string())
}

/// Return the coordinator-signed validator transport map. Every entry is
/// derived from a confirmed Innernet membership; renderer and node code must
/// not infer a validator address from a peer name or from a local interface.
pub fn validator_transport_snapshot(
    app_context: &AppContext,
) -> Result<InnernetValidatorTransportSnapshot, String> {
    require_coordinator_ready()?;
    let state = load_state(&state_path(app_context)?)?;
    signed_validator_transport_snapshot_from_state(&state)
}

/// Return the public Testnet-v3 transport document only after the coordinator
/// has durably recorded its explicit post-bootstrap release decision. Internal
/// enrollment and bootstrap inspection may still use `validator_transport_snapshot`
/// before this point; the unauthenticated discovery endpoint must not expose a
/// generation that the Testnet-v3 release verifier will reject.
pub fn public_validator_transport_snapshot(
    app_context: &AppContext,
) -> Result<InnernetValidatorTransportSnapshot, String> {
    require_coordinator_ready()?;
    let state = load_state(&state_path(app_context)?)?;
    require_published_transport_release_generation(&state)?;
    signed_validator_transport_snapshot_from_state(&state)
}

/// Advance the signed public transport registry to an explicitly requested
/// Testnet-v3 release generation. This is intentionally not a generic state
/// editor: it only raises the generation, it refuses incomplete or noncanonical
/// bootstrap state, and it records who made the release decision and why in
/// the same atomically-replaced state document.
///
/// The operation is idempotent. Repeating a successful request with the same
/// (or lower) minimum leaves state untouched and returns the already-effective
/// generation. It never changes peer membership, transport addresses, the
/// coordinator signer, or migration configuration.
pub fn advance_transport_release_generation(
    app_context: &AppContext,
    requested_minimum_generation: u64,
    actor: &str,
    reason: &str,
) -> Result<TransportReleaseGenerationAdvance, String> {
    require_coordinator_ready()?;
    validate_transport_release_audit_text(actor, "Transport release actor", 128)?;
    validate_transport_release_audit_text(reason, "Transport release reason", 512)?;
    if requested_minimum_generation < TESTNET_V3_MIN_TRANSPORT_RELEASE_GENERATION {
        return Err(format!(
            "Testnet-v3 transport release generation must be at least {TESTNET_V3_MIN_TRANSPORT_RELEASE_GENERATION}."
        ));
    }

    let path = state_path(app_context)?;
    let _guard = state_lock()
        .lock()
        .map_err(|_| "Innernet enrollment state lock is poisoned".to_string())?;
    let mut state = load_state(&path)?;
    let outcome = advance_transport_release_generation_in_state(
        &mut state,
        requested_minimum_generation,
        actor,
        reason,
        Utc::now(),
    )?;
    if outcome.advanced {
        save_state(&path, &state)?;
    }
    Ok(outcome)
}

/// Correct only the six current bootstrap validator-address bindings after a
/// completed fresh-mesh release has been proven to have published an older,
/// wrong address set.  This is *not* a membership editor: it cannot create,
/// delete, rekey, re-enroll, rename, route, or otherwise alter a peer.
///
/// The caller supplies the two immutable release anchors so an operator cannot
/// accidentally use this exceptional operation against another network.  Both
/// values must match the compiled V3 values, and the compiled mapping is
/// rehashed before state is touched.  The state mutation is atomic and always
/// advances the signed snapshot generation by exactly one.
pub fn correct_canonical_validator_address_bindings(
    app_context: &AppContext,
    applied_genesis_sha256: &str,
    applied_genesis_hash: &str,
    canonical_validator_bindings_sha256: &str,
    prior_snapshot_sha256: &str,
    actor: &str,
    reason: &str,
) -> Result<CanonicalValidatorAddressBindingCorrection, String> {
    require_coordinator_ready()?;
    validate_transport_release_audit_text(actor, "Binding correction actor", 128)?;
    validate_transport_release_audit_text(reason, "Binding correction reason", 512)?;
    require_canonical_validator_binding_anchors(
        applied_genesis_sha256,
        applied_genesis_hash,
        canonical_validator_bindings_sha256,
    )?;
    validate_sha256(
        prior_snapshot_sha256,
        "Prior signed transport snapshot SHA-256",
    )?;

    let path = state_path(app_context)?;
    let _guard = state_lock()
        .lock()
        .map_err(|_| "Innernet enrollment state lock is poisoned".to_string())?;
    let mut state = load_state(&path)?;
    let outcome = correct_canonical_validator_address_bindings_in_state(
        &mut state,
        prior_snapshot_sha256,
        actor,
        reason,
        Utc::now(),
    )?;
    save_state(&path, &state)?;
    Ok(outcome)
}

fn signed_validator_transport_snapshot_from_state(
    state: &InnernetEnrollmentState,
) -> Result<InnernetValidatorTransportSnapshot, String> {
    let transports = validator_transports_from_current_enrollments(
        current_enrollments_by_member(state).into_values(),
    )?;
    if transports.is_empty() {
        return Err(
            "The coordinator does not have any confirmed validator Innernet memberships."
                .to_string(),
        );
    }
    let mut snapshot = InnernetValidatorTransportSnapshot {
        version: 1,
        network: RECEIPT_DOMAIN.to_string(),
        migration_id: required_env("SYNERGY_INNERNET_MIGRATION_ID")?,
        configuration_version: state.latest_generation,
        transports: transports.into_values().collect(),
        signature: String::new(),
    };
    let signature = signing_key()?.sign(&transport_snapshot_payload(&snapshot)?);
    snapshot.signature = format!(
        "ed25519:{}",
        general_purpose::STANDARD.encode(signature.to_bytes())
    );
    Ok(snapshot)
}

fn advance_transport_release_generation_in_state(
    state: &mut InnernetEnrollmentState,
    requested_minimum_generation: u64,
    actor: &str,
    reason: &str,
    now: DateTime<Utc>,
) -> Result<TransportReleaseGenerationAdvance, String> {
    if requested_minimum_generation < TESTNET_V3_MIN_TRANSPORT_RELEASE_GENERATION {
        return Err(format!(
            "Testnet-v3 transport release generation must be at least {TESTNET_V3_MIN_TRANSPORT_RELEASE_GENERATION}."
        ));
    }
    validate_transport_release_audit_text(actor, "Transport release actor", 128)?;
    validate_transport_release_audit_text(reason, "Transport release reason", 512)?;
    require_exact_canonical_bootstrap_for_transport_release(state)?;
    require_exact_current_canonical_validator_transports(state)?;

    let previous_generation = state.latest_generation;
    if previous_generation >= requested_minimum_generation {
        return Ok(TransportReleaseGenerationAdvance {
            requested_minimum_generation,
            previous_generation,
            effective_generation: previous_generation,
            advanced: false,
            audit_recorded_at: None,
        });
    }

    let recorded_at = now.to_rfc3339();
    state.latest_generation = requested_minimum_generation;
    state
        .transport_release_generation_audit
        .push(TransportReleaseGenerationAuditRecord {
            requested_minimum_generation,
            previous_generation,
            effective_generation: requested_minimum_generation,
            actor: actor.trim().to_string(),
            reason: reason.trim().to_string(),
            recorded_at: recorded_at.clone(),
        });
    Ok(TransportReleaseGenerationAdvance {
        requested_minimum_generation,
        previous_generation,
        effective_generation: requested_minimum_generation,
        advanced: true,
        audit_recorded_at: Some(recorded_at),
    })
}

fn correct_canonical_validator_address_bindings_in_state(
    state: &mut InnernetEnrollmentState,
    prior_snapshot_sha256: &str,
    actor: &str,
    reason: &str,
    now: DateTime<Utc>,
) -> Result<CanonicalValidatorAddressBindingCorrection, String> {
    validate_transport_release_audit_text(actor, "Binding correction actor", 128)?;
    validate_transport_release_audit_text(reason, "Binding correction reason", 512)?;
    require_canonical_validator_binding_anchors(
        TESTNET_V3_APPLIED_GENESIS_SHA256,
        TESTNET_V3_APPLIED_GENESIS_HASH,
        TESTNET_V3_CANONICAL_VALIDATOR_BINDINGS_SHA256,
    )?;
    require_published_transport_release_generation(state)?;
    require_exact_canonical_bootstrap_for_transport_release(state)?;
    if state.latest_generation != TESTNET_V3_MIN_TRANSPORT_RELEASE_GENERATION {
        return Err(format!(
            "Testnet-v3 canonical validator-address correction is permitted only for signed transport generation {TESTNET_V3_MIN_TRANSPORT_RELEASE_GENERATION}; current generation is {}.",
            state.latest_generation
        ));
    }
    if !state
        .canonical_validator_address_binding_correction_audit
        .is_empty()
    {
        return Err(
            "Testnet-v3 canonical validator-address bindings have already been corrected; a second rebinding is forbidden."
                .to_string(),
        );
    }

    let computed_prior_snapshot_sha256 = signed_snapshot_sha256(state)?;
    if computed_prior_snapshot_sha256 != prior_snapshot_sha256.trim() {
        return Err(
            "Testnet-v3 canonical validator-address correction prior snapshot SHA-256 does not match the coordinator's current signed generation-21 snapshot."
                .to_string(),
        );
    }

    let current_indices = current_enrollment_indices_by_member(state);
    let mut corrected_bindings = Vec::new();
    for (peer_name, canonical_validator_address) in CANONICAL_BOOTSTRAP_VALIDATORS {
        let node_id = format!("bootstrap-{peer_name}");
        let index = current_indices.get(node_id.as_str()).copied().ok_or_else(|| {
            format!(
                "Testnet-v3 canonical validator-address correction is missing current bootstrap enrollment {node_id}."
            )
        })?;
        let enrollment = state.enrollments.get_mut(index).ok_or_else(|| {
            "Testnet-v3 canonical validator-address correction found an invalid enrollment index."
                .to_string()
        })?;
        if !enrollment.bootstrap
            || enrollment.node_id != node_id
            || enrollment.peer_name != peer_name
            || enrollment.peer_type != "validator"
            || enrollment.confirmed_at.is_none()
            || enrollment.handshake_verified_at.is_none()
        {
            return Err(format!(
                "Testnet-v3 canonical validator-address correction found a noncanonical or unverified bootstrap record for {peer_name}."
            ));
        }
        if enrollment.validator_address.as_deref() != Some(canonical_validator_address) {
            corrected_bindings.push(CanonicalValidatorAddressBindingChange {
                peer_name: peer_name.to_string(),
                previous_validator_address: enrollment.validator_address.clone(),
                canonical_validator_address: canonical_validator_address.to_string(),
            });
            // This is intentionally the only mutable field in this repair.
            enrollment.validator_address = Some(canonical_validator_address.to_string());
        }
    }
    if corrected_bindings.is_empty() {
        return Err(
            "Testnet-v3 canonical validator-address correction is not needed; refusing to advance a signed registry without a binding change."
                .to_string(),
        );
    }

    require_exact_current_canonical_validator_transports(state)?;
    let previous_generation = state.latest_generation;
    let effective_generation = TESTNET_V3_MIN_TRANSPORT_RELEASE_GENERATION
        .checked_add(1)
        .expect("Testnet-v3 fixed correction generation does not overflow");
    let recorded_at = now.to_rfc3339();
    state.latest_generation = effective_generation;
    state
        .canonical_validator_address_binding_correction_audit
        .push(CanonicalValidatorAddressBindingCorrectionAuditRecord {
            applied_genesis_sha256: TESTNET_V3_APPLIED_GENESIS_SHA256.to_string(),
            applied_genesis_hash: TESTNET_V3_APPLIED_GENESIS_HASH.to_string(),
            canonical_validator_bindings_sha256: TESTNET_V3_CANONICAL_VALIDATOR_BINDINGS_SHA256
                .to_string(),
            prior_snapshot_sha256: computed_prior_snapshot_sha256.clone(),
            previous_generation,
            effective_generation,
            actor: actor.trim().to_string(),
            reason: reason.trim().to_string(),
            corrected_bindings: corrected_bindings.clone(),
            recorded_at: recorded_at.clone(),
        });
    Ok(CanonicalValidatorAddressBindingCorrection {
        applied_genesis_sha256: TESTNET_V3_APPLIED_GENESIS_SHA256.to_string(),
        applied_genesis_hash: TESTNET_V3_APPLIED_GENESIS_HASH.to_string(),
        canonical_validator_bindings_sha256: TESTNET_V3_CANONICAL_VALIDATOR_BINDINGS_SHA256
            .to_string(),
        prior_snapshot_sha256: computed_prior_snapshot_sha256,
        previous_generation,
        effective_generation,
        corrected_bindings,
        audit_recorded_at: recorded_at,
    })
}

fn require_canonical_validator_binding_anchors(
    applied_genesis_sha256: &str,
    applied_genesis_hash: &str,
    canonical_validator_bindings_sha256: &str,
) -> Result<(), String> {
    if applied_genesis_sha256.trim() != TESTNET_V3_APPLIED_GENESIS_SHA256 {
        return Err(
            "Testnet-v3 canonical validator-address correction requires the exact applied Genesis SHA-256 anchor."
                .to_string(),
        );
    }
    if applied_genesis_hash.trim() != TESTNET_V3_APPLIED_GENESIS_HASH {
        return Err(
            "Testnet-v3 canonical validator-address correction requires the exact applied Genesis hash anchor."
                .to_string(),
        );
    }
    let compiled_bindings_sha256 = canonical_validator_bindings_digest()?;
    if compiled_bindings_sha256 != TESTNET_V3_CANONICAL_VALIDATOR_BINDINGS_SHA256 {
        return Err(
            "The compiled Testnet-v3 canonical validator binding map does not match its immutable SHA-256 anchor."
                .to_string(),
        );
    }
    if canonical_validator_bindings_sha256.trim() != TESTNET_V3_CANONICAL_VALIDATOR_BINDINGS_SHA256
    {
        return Err(
            "Testnet-v3 canonical validator-address correction requires the exact canonical validator-binding SHA-256 anchor."
                .to_string(),
        );
    }
    Ok(())
}

fn validate_sha256(value: &str, label: &str) -> Result<(), String> {
    let value = value.trim();
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(format!(
            "{label} must be a 64-character hexadecimal digest."
        ));
    }
    Ok(())
}

fn signed_snapshot_sha256(state: &InnernetEnrollmentState) -> Result<String, String> {
    let snapshot = signed_validator_transport_snapshot_from_state(state)?;
    let encoded = serde_json::to_vec(&snapshot)
        .map_err(|error| format!("Failed to encode signed transport snapshot: {error}"))?;
    Ok(Sha256::digest(encoded)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

fn canonical_validator_bindings_digest() -> Result<String, String> {
    let mut payload = String::new();
    for (index, (peer_name, validator_address)) in CANONICAL_BOOTSTRAP_VALIDATORS.iter().enumerate()
    {
        if !is_validator_address(validator_address) {
            return Err(
                "The compiled Testnet-v3 canonical validator binding map contains an invalid address."
                    .to_string(),
            );
        }
        if index > 0 {
            payload.push('\n');
        }
        payload.push_str(peer_name);
        payload.push('=');
        payload.push_str(validator_address);
    }
    Ok(Sha256::digest(payload.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

fn require_exact_current_canonical_validator_transports(
    state: &InnernetEnrollmentState,
) -> Result<(), String> {
    let transports = validator_transports_from_current_enrollments(
        current_enrollments_by_member(state).into_values(),
    )?;
    if transports.len() != CANONICAL_BOOTSTRAP_VALIDATORS.len() {
        return Err(
            "Testnet-v3 canonical validator-address correction did not produce exactly six validator transports."
                .to_string(),
        );
    }
    for (peer_name, canonical_validator_address) in CANONICAL_BOOTSTRAP_VALIDATORS {
        let expected_ip = admin_bootstrap_assignment(peer_name)?
            .assigned_ip
            .split('/')
            .next()
            .expect("canonical assignment contains an IP address")
            .to_string();
        let expected_dial_address = format!("{expected_ip}:5622");
        let actual = transports.get(canonical_validator_address).ok_or_else(|| {
            format!(
                "Testnet-v3 canonical validator-address correction is missing transport for {peer_name}."
            )
        })?;
        if actual.dial_address != expected_dial_address {
            return Err(format!(
                "Testnet-v3 canonical validator-address correction produced an unexpected dial address for {peer_name}."
            ));
        }
    }
    Ok(())
}

fn require_exact_canonical_bootstrap_for_transport_release(
    state: &InnernetEnrollmentState,
) -> Result<(), String> {
    let bootstrap = bootstrap_status(state)?;
    if !bootstrap.complete {
        return Err(
            "Testnet-v3 transport release generation requires all nine canonical bootstrap peers to be confirmed with a server-verified handshake."
                .to_string(),
        );
    }
    let expected: BTreeMap<String, ()> = CANONICAL_BOOTSTRAP_PEERS
        .iter()
        .map(|peer_name| (format!("bootstrap-{peer_name}"), ()))
        .collect();
    let current = current_enrollments_by_member(state);
    let actual: BTreeMap<String, ()> = current
        .keys()
        .map(|node_id| ((*node_id).to_string(), ()))
        .collect();
    if actual != expected {
        return Err(
            "Testnet-v3 transport release generation requires exactly the nine canonical bootstrap peers; current membership contains a different peer set."
                .to_string(),
        );
    }
    Ok(())
}

fn validate_transport_release_audit_text(
    value: &str,
    label: &str,
    maximum_bytes: usize,
) -> Result<(), String> {
    let value = value.trim();
    if value.is_empty()
        || value.len() > maximum_bytes
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_graphic() || byte == b' ')
    {
        return Err(format!(
            "{label} must be non-empty printable text no longer than {maximum_bytes} bytes."
        ));
    }
    Ok(())
}

fn require_published_transport_release_generation(
    state: &InnernetEnrollmentState,
) -> Result<(), String> {
    let published = state.latest_generation >= TESTNET_V3_MIN_TRANSPORT_RELEASE_GENERATION
        && state
            .transport_release_generation_audit
            .iter()
            .any(|record| {
                record.requested_minimum_generation >= TESTNET_V3_MIN_TRANSPORT_RELEASE_GENERATION
                    && record.effective_generation >= TESTNET_V3_MIN_TRANSPORT_RELEASE_GENERATION
                    && record.effective_generation > record.previous_generation
                    && record.effective_generation <= state.latest_generation
            });
    if !published {
        return Err(format!(
            "Testnet-v3 public validator transport registry is not released: the coordinator needs a persisted release-generation audit proving an advance to generation {TESTNET_V3_MIN_TRANSPORT_RELEASE_GENERATION} or later."
        ));
    }
    Ok(())
}

fn validator_transports_from_current_enrollments<'a>(
    enrollments: impl IntoIterator<Item = &'a InnernetEnrollment>,
) -> Result<BTreeMap<String, InnernetValidatorTransport>, String> {
    let mut transports: BTreeMap<String, (String, InnernetValidatorTransport)> = BTreeMap::new();
    for enrollment in enrollments {
        if enrollment.confirmed_at.is_none() || enrollment.peer_type != "validator" {
            continue;
        }
        let validator_address = enrollment
            .validator_address
            .as_deref()
            .or_else(|| canonical_bootstrap_validator_address(&enrollment.peer_name))
            .ok_or_else(|| {
                "A confirmed validator Innernet membership is missing its canonical validator address."
                    .to_string()
            })?;
        if !is_validator_address(validator_address) {
            return Err(
                "A confirmed Innernet membership has an invalid validator address.".to_string(),
            );
        }
        let assigned_ip = enrollment.assigned_ip.parse::<IpAddr>().map_err(|_| {
            "A confirmed Innernet membership has an invalid assigned IP address.".to_string()
        })?;
        if !assigned_ip.is_ipv4() {
            return Err("Innernet validator transport addresses must be IPv4.".to_string());
        }
        let transport = InnernetValidatorTransport {
            validator_address: validator_address.to_string(),
            dial_address: format!("{assigned_ip}:5622"),
        };
        match transports.entry(validator_address.to_string()) {
            std::collections::btree_map::Entry::Vacant(entry) => {
                entry.insert((enrollment.node_id.clone(), transport));
            }
            std::collections::btree_map::Entry::Occupied(entry) => {
                let (existing_node_id, existing_transport) = entry.get();
                if existing_node_id == &enrollment.node_id && existing_transport == &transport {
                    continue;
                }
                return Err(format!(
                    "Conflicting confirmed current Innernet memberships resolve to validator address {}: node IDs {} and {} have dial addresses {} and {}.",
                    validator_address,
                    existing_node_id,
                    enrollment.node_id,
                    existing_transport.dial_address,
                    transport.dial_address,
                ));
            }
        }
    }
    Ok(transports
        .into_iter()
        .map(|(validator_address, (_, transport))| (validator_address, transport))
        .collect())
}

pub fn verify_validator_transport_snapshot(
    snapshot: &InnernetValidatorTransportSnapshot,
) -> Result<(), String> {
    if snapshot.version != 1
        || snapshot.network != RECEIPT_DOMAIN
        || snapshot.configuration_version == 0
    {
        return Err(
            "Innernet validator transport snapshot has an unsupported network or version."
                .to_string(),
        );
    }
    if snapshot.migration_id.trim().is_empty() || snapshot.transports.is_empty() {
        return Err("Innernet validator transport snapshot is incomplete.".to_string());
    }
    let mut validators = BTreeMap::new();
    for transport in &snapshot.transports {
        if !is_validator_address(&transport.validator_address) {
            return Err(
                "Innernet validator transport snapshot has an invalid validator address."
                    .to_string(),
            );
        }
        let socket = transport
            .dial_address
            .parse::<std::net::SocketAddr>()
            .map_err(|_| {
                "Innernet validator transport snapshot has an invalid dial address.".to_string()
            })?;
        if !matches!(socket.ip(), IpAddr::V4(address) if address.is_private())
            || socket.port() != 5622
        {
            return Err(
                "Innernet validator transport snapshot has an unsafe dial address.".to_string(),
            );
        }
        if validators
            .insert(
                transport.validator_address.as_str(),
                transport.dial_address.as_str(),
            )
            .is_some()
        {
            return Err(
                "Innernet validator transport snapshot has duplicate validator entries."
                    .to_string(),
            );
        }
    }
    let public_key = required_env("SYNERGY_INNERNET_COORDINATOR_PUBLIC_KEY")?;
    let verifying_key = verifying_key(&public_key)?;
    let signature = snapshot
        .signature
        .strip_prefix("ed25519:")
        .ok_or_else(|| "Innernet validator transport snapshot must use ed25519.".to_string())?;
    let signature_bytes = general_purpose::STANDARD
        .decode(signature)
        .map_err(|_| "Innernet validator transport snapshot signature is invalid.".to_string())?;
    let signature_bytes: [u8; 64] = signature_bytes.try_into().map_err(|_| {
        "Innernet validator transport snapshot signature must be 64 bytes.".to_string()
    })?;
    verifying_key
        .verify(
            &transport_snapshot_payload(snapshot)?,
            &Signature::from_bytes(&signature_bytes),
        )
        .map_err(|_| {
            "Innernet validator transport snapshot signature verification failed.".to_string()
        })
}

fn receipt_for(enrollment: &InnernetEnrollment) -> Result<InnernetMembershipReceipt, String> {
    let mut receipt = InnernetMembershipReceipt {
        version: 1,
        network: RECEIPT_DOMAIN.to_string(),
        migration_id: required_env("SYNERGY_INNERNET_MIGRATION_ID")?,
        enrollment_id: enrollment.id.clone(),
        node_id: enrollment.node_id.clone(),
        peer_name: enrollment.peer_name.clone(),
        peer_type: enrollment.peer_type.clone(),
        assigned_ip: enrollment.assigned_ip.clone(),
        interface_name: enrollment.interface_name.clone(),
        configuration_version: enrollment.configuration_version,
        confirmed_at: enrollment
            .confirmed_at
            .clone()
            .ok_or_else(|| "Innernet enrollment has not been confirmed.".to_string())?,
        signature: String::new(),
    };
    let signature = signing_key()?.sign(&receipt_payload(&receipt)?);
    receipt.signature = format!(
        "ed25519:{}",
        general_purpose::STANDARD.encode(signature.to_bytes())
    );
    Ok(receipt)
}

fn receipt_payload(receipt: &InnernetMembershipReceipt) -> Result<Vec<u8>, String> {
    serde_json::to_vec(&serde_json::json!({
        "version": receipt.version,
        "network": receipt.network,
        "migration_id": receipt.migration_id,
        "enrollment_id": receipt.enrollment_id,
        "node_id": receipt.node_id,
        "peer_name": receipt.peer_name,
        "peer_type": receipt.peer_type,
        "assigned_ip": receipt.assigned_ip,
        "interface_name": receipt.interface_name,
        "configuration_version": receipt.configuration_version,
        "confirmed_at": receipt.confirmed_at,
    }))
    .map_err(|error| format!("Failed to encode Innernet membership receipt: {error}"))
}

fn transport_snapshot_payload(
    snapshot: &InnernetValidatorTransportSnapshot,
) -> Result<Vec<u8>, String> {
    serde_json::to_vec(&serde_json::json!({
        "version": snapshot.version,
        "network": snapshot.network,
        "migration_id": snapshot.migration_id,
        "configuration_version": snapshot.configuration_version,
        "transports": snapshot.transports,
    }))
    .map_err(|error| format!("Failed to encode Innernet validator transport snapshot: {error}"))
}

fn mesh_status_from_state(state: &InnernetEnrollmentState) -> Result<InnernetMeshStatus, String> {
    let mut acknowledged_member_ids = Vec::new();
    let mut pending_member_ids = Vec::new();
    for enrollment in current_enrollments_by_member(state).values() {
        // Innernet's server-owned peer graph propagates membership itself. A
        // member is acknowledged here only after coordinator confirmation, not
        // after every later enrollment increments the global generation.
        if enrollment.confirmed_at.is_some() {
            acknowledged_member_ids.push(enrollment.node_id.clone());
        } else {
            pending_member_ids.push(enrollment.node_id.clone());
        }
    }
    acknowledged_member_ids.sort();
    acknowledged_member_ids.dedup();
    pending_member_ids.sort();
    pending_member_ids.dedup();
    let bootstrap = bootstrap_status(state)?;
    Ok(InnernetMeshStatus {
        network: RECEIPT_DOMAIN.to_string(),
        migration_id: required_env("SYNERGY_INNERNET_MIGRATION_ID")?,
        migration_ready: migration_cutover_enabled() && bootstrap.complete,
        latest_generation: state.latest_generation,
        active_members: acknowledged_member_ids.len() + pending_member_ids.len(),
        propagation_complete: pending_member_ids.is_empty(),
        acknowledged_member_ids,
        pending_member_ids,
        bootstrap_expected_members: CANONICAL_BOOTSTRAP_PEERS.len(),
        bootstrap_confirmed_member_ids: bootstrap.confirmed_member_ids,
        bootstrap_pending_member_ids: bootstrap.pending_member_ids,
        bootstrap_complete: bootstrap.complete,
    })
}

#[derive(Debug)]
struct BootstrapStatus {
    confirmed_member_ids: Vec<String>,
    pending_member_ids: Vec<String>,
    complete: bool,
}

fn bootstrap_status(state: &InnernetEnrollmentState) -> Result<BootstrapStatus, String> {
    let current = current_enrollments_by_member(state);
    let mut confirmed_member_ids = Vec::new();
    let mut pending_member_ids = Vec::new();
    for peer_name in CANONICAL_BOOTSTRAP_PEERS {
        let assignment = admin_bootstrap_assignment(peer_name)?;
        let node_id = format!("bootstrap-{peer_name}");
        let expected_ip = assignment
            .assigned_ip
            .split('/')
            .next()
            .expect("bootstrap assignments always contain an IP address");
        let confirmed = current.get(node_id.as_str()).is_some_and(|entry| {
            entry.bootstrap
                && entry.node_id == node_id
                && entry.peer_name == peer_name
                && entry.peer_type == assignment.peer_type.as_str()
                && entry.assigned_ip == expected_ip
                && entry.confirmed_at.is_some()
                && entry.handshake_verified_at.is_some()
        });
        if confirmed {
            confirmed_member_ids.push(node_id);
        } else {
            pending_member_ids.push(node_id);
        }
    }
    let complete = pending_member_ids.is_empty()
        && confirmed_member_ids.len() == CANONICAL_BOOTSTRAP_PEERS.len();
    Ok(BootstrapStatus {
        confirmed_member_ids,
        pending_member_ids,
        complete,
    })
}

fn current_enrollments_by_member<'a>(
    state: &'a InnernetEnrollmentState,
) -> BTreeMap<&'a str, &'a InnernetEnrollment> {
    let mut current: BTreeMap<&'a str, &'a InnernetEnrollment> = BTreeMap::new();
    for enrollment in &state.enrollments {
        match current.get(enrollment.node_id.as_str()) {
            Some(existing) if existing.configuration_version > enrollment.configuration_version => {
            }
            _ => {
                current.insert(enrollment.node_id.as_str(), enrollment);
            }
        }
    }
    current
}

/// Match `current_enrollments_by_member` exactly, but retain the mutable index
/// for the narrow canonical-address correction.  In particular, equal
/// configuration versions intentionally use the later record just as the
/// read-only selector above does.
fn current_enrollment_indices_by_member(
    state: &InnernetEnrollmentState,
) -> BTreeMap<String, usize> {
    let mut current: BTreeMap<String, usize> = BTreeMap::new();
    for (index, enrollment) in state.enrollments.iter().enumerate() {
        match current.get(enrollment.node_id.as_str()) {
            Some(existing_index)
                if state.enrollments[*existing_index].configuration_version
                    > enrollment.configuration_version => {}
            _ => {
                current.insert(enrollment.node_id.clone(), index);
            }
        }
    }
    current
}

#[derive(Debug)]
struct ParsedInvitation {
    interface_name: String,
    assigned_ip: String,
}

fn parse_invitation(invitation: &str) -> Result<ParsedInvitation, String> {
    let invitation: toml::Value = invitation
        .parse()
        .map_err(|error| format!("Innernet server returned invalid invitation TOML: {error}"))?;
    let interface = invitation
        .get("interface")
        .and_then(toml::Value::as_table)
        .ok_or_else(|| "Innernet invitation is missing [interface].".to_string())?;
    let interface_name = interface
        .get("network-name")
        .and_then(toml::Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| "Innernet invitation is missing interface.network-name.".to_string())?
        .to_string();
    let assigned_ip = interface
        .get("address")
        .and_then(toml::Value::as_str)
        .and_then(|value| value.split('/').next())
        .map(str::trim)
        .filter(|value| value.parse::<IpAddr>().is_ok())
        .ok_or_else(|| "Innernet invitation is missing a valid interface.address.".to_string())?
        .to_string();
    Ok(ParsedInvitation {
        interface_name,
        assigned_ip,
    })
}

fn state_path(app_context: &AppContext) -> Result<PathBuf, String> {
    Ok(ensure_monitor_workspace_with_context(app_context)?.join(STATE_RELATIVE_PATH))
}

fn load_state(path: &Path) -> Result<InnernetEnrollmentState, String> {
    if !path.is_file() {
        return Ok(InnernetEnrollmentState {
            version: 1,
            latest_generation: 0,
            transport_release_generation_audit: Vec::new(),
            canonical_validator_address_binding_correction_audit: Vec::new(),
            enrollments: Vec::new(),
        });
    }
    let raw = fs::read_to_string(path)
        .map_err(|error| format!("Failed to read {}: {error}", path.display()))?;
    serde_json::from_str(&raw)
        .map_err(|error| format!("Failed to parse {}: {error}", path.display()))
}

fn save_state(path: &Path, state: &InnernetEnrollmentState) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| format!("Innernet state path {} has no parent.", path.display()))?;
    fs::create_dir_all(parent)
        .map_err(|error| format!("Failed to create {}: {error}", parent.display()))?;
    let payload = serde_json::to_vec_pretty(state)
        .map_err(|error| format!("Failed to encode Innernet enrollment state: {error}"))?;
    let temporary = path.with_extension(format!("{}.tmp", Uuid::new_v4()));
    let mut file = fs::File::create(&temporary)
        .map_err(|error| format!("Failed to create {}: {error}", temporary.display()))?;
    file.write_all(&payload)
        .map_err(|error| format!("Failed to write {}: {error}", temporary.display()))?;
    file.sync_all()
        .map_err(|error| format!("Failed to sync {}: {error}", temporary.display()))?;
    drop(file);
    fs::rename(&temporary, path)
        .map_err(|error| format!("Failed to replace {}: {error}", path.display()))?;
    // Durably commit the atomic rename before reporting success. This matters
    // for a release-generation advance because publishing a signed snapshot
    // must never outrun the locally durable coordinator state.
    fs::File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| format!("Failed to sync {}: {error}", parent.display()))
}

fn state_lock() -> &'static Mutex<()> {
    static STATE_WRITE_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    STATE_WRITE_LOCK.get_or_init(|| Mutex::new(()))
}

fn random_secret() -> String {
    let mut bytes = [0u8; 32];
    bytes[..16].copy_from_slice(Uuid::new_v4().as_bytes());
    bytes[16..].copy_from_slice(Uuid::new_v4().as_bytes());
    general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

fn hash_secret(secret: &str) -> String {
    let digest = Sha256::digest(secret.as_bytes());
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn parse_expiry(value: &str) -> Result<DateTime<Utc>, String> {
    DateTime::parse_from_rfc3339(value)
        .map(|value| value.with_timezone(&Utc))
        .map_err(|_| "Innernet enrollment expiry is invalid.".to_string())
}

fn invitation_expiry() -> Result<(String, DateTime<Utc>), String> {
    let value = std::env::var("SYNERGY_INNERNET_INVITE_EXPIRES")
        .unwrap_or_else(|_| DEFAULT_INNERNET_INVITE_EXPIRY.to_string())
        .trim()
        .to_string();
    let duration = parse_innernet_duration(&value)?;
    Ok((value, Utc::now() + duration))
}

fn parse_innernet_duration(value: &str) -> Result<chrono::Duration, String> {
    let value = value.trim();
    if value.len() < 2 {
        return Err(
            "SYNERGY_INNERNET_INVITE_EXPIRES must be a positive duration such as 30m.".to_string(),
        );
    }
    let (amount, unit) = value.split_at(value.len() - 1);
    let amount = amount.parse::<i64>().map_err(|_| {
        "SYNERGY_INNERNET_INVITE_EXPIRES must be a positive duration such as 30m.".to_string()
    })?;
    if amount <= 0 {
        return Err("SYNERGY_INNERNET_INVITE_EXPIRES must be positive.".to_string());
    }
    let duration = match unit {
        "s" => chrono::Duration::seconds(amount),
        "m" => chrono::Duration::minutes(amount),
        "h" => chrono::Duration::hours(amount),
        "d" => chrono::Duration::days(amount),
        "w" => chrono::Duration::weeks(amount),
        _ => {
            return Err(
                "SYNERGY_INNERNET_INVITE_EXPIRES must use s, m, h, d, or w units.".to_string(),
            )
        }
    };
    Ok(duration)
}

fn signing_key() -> Result<SigningKey, String> {
    let value = required_env("SYNERGY_INNERNET_COORDINATOR_SIGNING_KEY")?;
    let value = value
        .strip_prefix("ed25519:")
        .or_else(|| value.strip_prefix("ed25519-seed:"))
        .or_else(|| value.strip_prefix("base64:"))
        .ok_or_else(|| {
            "SYNERGY_INNERNET_COORDINATOR_SIGNING_KEY must be an ed25519 seed.".to_string()
        })?;
    let bytes = general_purpose::STANDARD
        .decode(value.trim())
        .map_err(|error| format!("Invalid Innernet coordinator signing key: {error}"))?;
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| "Innernet coordinator signing key must be a 32-byte seed.".to_string())?;
    Ok(SigningKey::from_bytes(&bytes))
}

fn verifying_key(value: &str) -> Result<VerifyingKey, String> {
    let value = value
        .trim()
        .strip_prefix("ed25519:")
        .or_else(|| value.trim().strip_prefix("base64:"))
        .unwrap_or(value.trim());
    let bytes = general_purpose::STANDARD
        .decode(value)
        .map_err(|error| format!("Invalid Innernet coordinator public key: {error}"))?;
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| "Innernet coordinator public key must be 32 bytes.".to_string())?;
    VerifyingKey::from_bytes(&bytes)
        .map_err(|error| format!("Invalid Innernet coordinator public key: {error}"))
}

fn required_env(name: &str) -> Result<String, String> {
    std::env::var(name)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .ok_or_else(|| format!("{name} is required for coordinator-managed Innernet enrollment."))
}

fn validate_identifier(value: &str, label: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > 63
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    {
        return Err(format!("{label} is invalid."));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        admin_bootstrap_assignment, advance_transport_release_generation_in_state,
        authoritative_assigned_ips, bootstrap_status, canonical_bootstrap_validator_address,
        canonical_validator_bindings_digest, constrained_expiry,
        correct_canonical_validator_address_bindings_in_state, has_fresh_server_handshake,
        is_validator_address, legacy_bootstrap_verification_candidates,
        membership_receipt_matches_enrollment, mesh_status_from_state, parse_innernet_address_plan,
        parse_innernet_duration, parse_invitation, receipt_payload,
        require_canonical_validator_binding_anchors,
        require_published_transport_release_generation, sanitized_command_error,
        server_handshake_age_seconds, server_handshake_timestamp, signed_snapshot_sha256,
        signed_validator_transport_snapshot_from_state, validate_identifier,
        validator_transports_from_current_enrollments, verify_validator_transport_snapshot,
        InnernetEnrollment, InnernetEnrollmentState, InnernetMembershipReceipt,
        TransportReleaseGenerationAuditRecord, CANONICAL_BOOTSTRAP_PEERS,
        STALE_UNREDEEMED_HANDSHAKE_RECOVERY_MIN_AGE_SECONDS, TESTNET_V3_APPLIED_GENESIS_HASH,
        TESTNET_V3_APPLIED_GENESIS_SHA256, TESTNET_V3_CANONICAL_VALIDATOR_BINDINGS_SHA256,
        TESTNET_V3_MIN_TRANSPORT_RELEASE_GENERATION,
    };
    use base64::{engine::general_purpose, Engine as _};
    use chrono::{TimeZone, Utc};
    use ed25519_dalek::SigningKey;
    use std::ffi::OsString;
    use std::sync::{Mutex, MutexGuard, OnceLock};

    fn test_environment_lock() -> MutexGuard<'static, ()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|error| error.into_inner())
    }

    struct EnvVarGuard {
        key: &'static str,
        previous: Option<OsString>,
    }

    impl EnvVarGuard {
        fn set(key: &'static str, value: String) -> Self {
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

    fn snapshot_signing_environment() -> Vec<EnvVarGuard> {
        let signing_key = SigningKey::from_bytes(&[7u8; 32]);
        vec![
            EnvVarGuard::set(
                "SYNERGY_INNERNET_COORDINATOR_SIGNING_KEY",
                format!(
                    "ed25519:{}",
                    general_purpose::STANDARD.encode(signing_key.to_bytes())
                ),
            ),
            EnvVarGuard::set(
                "SYNERGY_INNERNET_COORDINATOR_PUBLIC_KEY",
                general_purpose::STANDARD.encode(signing_key.verifying_key().to_bytes()),
            ),
            EnvVarGuard::set(
                "SYNERGY_INNERNET_MIGRATION_ID",
                "test-migration".to_string(),
            ),
        ]
    }

    fn enrollment(
        id: &str,
        node_id: &str,
        configuration_version: u64,
        confirmed_at: Option<&str>,
        acknowledged_generation: u64,
    ) -> InnernetEnrollment {
        InnernetEnrollment {
            id: id.to_string(),
            node_id: node_id.to_string(),
            vpn_node_id: format!("vpn-{node_id}"),
            peer_name: node_id.to_string(),
            peer_type: "validator".to_string(),
            validator_address: Some("synv1testvalidator9".to_string()),
            assigned_ip: "10.70.10.9".to_string(),
            interface_name: "synergy".to_string(),
            configuration_version,
            confirmation_token_hash: "hash".to_string(),
            expires_at: "2026-07-10T12:00:00Z".to_string(),
            confirmed_at: confirmed_at.map(str::to_string),
            acknowledged_generation,
            bootstrap: false,
            handshake_verified_at: None,
            preconfigured_wireguard_public_key: None,
        }
    }

    fn set_innernet_address_plans() {
        std::env::set_var("SYNERGY_INNERNET_VALIDATOR_ADDRESS_CIDR", "10.70.10.0/24");
        std::env::set_var("SYNERGY_INNERNET_RELAYER_ADDRESS_CIDR", "10.70.20.0/24");
    }

    fn confirmed_bootstrap_enrollment(
        peer_name: &str,
        configuration_version: u64,
    ) -> InnernetEnrollment {
        let assignment = admin_bootstrap_assignment(peer_name).expect("canonical assignment");
        InnernetEnrollment {
            id: format!("enrollment-{peer_name}"),
            node_id: format!("bootstrap-{peer_name}"),
            vpn_node_id: format!("bootstrap-{peer_name}"),
            peer_name: peer_name.to_string(),
            peer_type: assignment.peer_type,
            validator_address: canonical_bootstrap_validator_address(peer_name).map(str::to_string),
            assigned_ip: assignment
                .assigned_ip
                .split('/')
                .next()
                .expect("assignment contains an IP")
                .to_string(),
            interface_name: "sy-vpn".to_string(),
            configuration_version,
            confirmation_token_hash: "hash".to_string(),
            expires_at: "2026-07-10T12:00:00Z".to_string(),
            confirmed_at: Some("2026-07-10T00:00:00Z".to_string()),
            acknowledged_generation: configuration_version,
            bootstrap: true,
            handshake_verified_at: Some("2026-07-10T00:00:00Z".to_string()),
            preconfigured_wireguard_public_key: None,
        }
    }

    fn released_canonical_bootstrap_state() -> InnernetEnrollmentState {
        InnernetEnrollmentState {
            version: 1,
            latest_generation: TESTNET_V3_MIN_TRANSPORT_RELEASE_GENERATION,
            transport_release_generation_audit: vec![TransportReleaseGenerationAuditRecord {
                requested_minimum_generation: TESTNET_V3_MIN_TRANSPORT_RELEASE_GENERATION,
                previous_generation: 9,
                effective_generation: TESTNET_V3_MIN_TRANSPORT_RELEASE_GENERATION,
                actor: "release-operator".to_string(),
                reason: "publish verified fresh Testnet-v3 mesh".to_string(),
                recorded_at: "2026-07-29T00:00:00Z".to_string(),
            }],
            canonical_validator_address_binding_correction_audit: Vec::new(),
            enrollments: CANONICAL_BOOTSTRAP_PEERS
                .iter()
                .enumerate()
                .map(|(index, peer_name)| {
                    confirmed_bootstrap_enrollment(peer_name, index as u64 + 1)
                })
                .collect(),
        }
    }

    #[test]
    fn identifiers_reject_command_injection_characters() {
        assert!(validate_identifier("validator-7", "peer").is_ok());
        assert!(validate_identifier("validators", "cidr").is_ok());
        assert!(validate_identifier("validator;rm", "peer").is_err());
        assert!(validate_identifier("../validator", "peer").is_err());
    }

    #[test]
    fn transport_refresh_receipt_must_match_confirmed_enrollment() {
        let enrollment = enrollment(
            "enrollment-7",
            "testnet-validator7",
            42,
            Some("2026-07-13T12:00:00Z"),
            42,
        );
        let mut receipt = InnernetMembershipReceipt {
            version: 1,
            network: "synergy-innernet-membership-v1".to_string(),
            migration_id: "migration-7".to_string(),
            enrollment_id: enrollment.id.clone(),
            node_id: enrollment.node_id.clone(),
            peer_name: enrollment.peer_name.clone(),
            peer_type: enrollment.peer_type.clone(),
            assigned_ip: enrollment.assigned_ip.clone(),
            interface_name: enrollment.interface_name.clone(),
            configuration_version: enrollment.configuration_version,
            confirmed_at: enrollment.confirmed_at.clone().unwrap(),
            signature: "ed25519:test".to_string(),
        };
        assert!(membership_receipt_matches_enrollment(
            &enrollment,
            enrollment.confirmed_at.as_deref().unwrap(),
            &receipt,
        ));

        receipt.assigned_ip = "10.70.10.10".to_string();
        assert!(!membership_receipt_matches_enrollment(
            &enrollment,
            enrollment.confirmed_at.as_deref().unwrap(),
            &receipt,
        ));
    }

    #[test]
    fn validator_transport_generation_allows_exact_same_member_duplicates() {
        let first = enrollment("enrollment-1", "node-1", 1, Some("2026-07-10T00:00:00Z"), 1);
        let mut duplicate = first.clone();
        duplicate.id = "enrollment-2".to_string();

        let transports = validator_transports_from_current_enrollments([&first, &duplicate])
            .expect("exact same-member duplicate should be retained once");
        assert_eq!(transports.len(), 1);
        assert_eq!(
            transports
                .get("synv1testvalidator9")
                .expect("validator transport")
                .dial_address,
            "10.70.10.9:5622"
        );
    }

    #[test]
    fn validator_transport_generation_rejects_distinct_current_memberships() {
        let first = enrollment("enrollment-1", "node-1", 1, Some("2026-07-10T00:00:00Z"), 1);
        let mut second = enrollment("enrollment-2", "node-2", 2, Some("2026-07-10T00:05:00Z"), 2);
        second.assigned_ip = first.assigned_ip.clone();

        let error = validator_transports_from_current_enrollments([&first, &second])
            .expect_err("distinct node IDs must not share a validator address");
        assert!(error.contains("Conflicting confirmed current Innernet memberships"));
        assert!(error.contains("node-1"));
        assert!(error.contains("node-2"));
    }

    #[test]
    fn validator_transport_generation_rejects_conflicting_same_member_dial_addresses() {
        let first = enrollment("enrollment-1", "node-1", 1, Some("2026-07-10T00:00:00Z"), 1);
        let mut second = first.clone();
        second.id = "enrollment-2".to_string();
        second.assigned_ip = "10.70.10.10".to_string();

        let error = validator_transports_from_current_enrollments([&first, &second])
            .expect_err("a validator address must not have conflicting dial addresses");
        assert!(error.contains("Conflicting confirmed current Innernet memberships"));
        assert!(error.contains("10.70.10.9:5622"));
        assert!(error.contains("10.70.10.10:5622"));
    }

    #[test]
    fn authoritative_assignments_are_loaded_from_innernet_sqlite() {
        let _guard = test_environment_lock();
        let directory =
            std::env::temp_dir().join(format!("synergy-innernet-db-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&directory).expect("create Innernet test directory");
        let database = directory.join("sy-vpn.db");
        let setup = std::process::Command::new("python3")
            .args([
                "-c",
                "import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); c.execute('CREATE TABLE peers (ip TEXT NOT NULL UNIQUE)'); c.executemany('INSERT INTO peers(ip) VALUES (?)', [('10.70.10.7',), ('10.70.10.8',)]); c.commit()",
                database.to_str().expect("UTF-8 database path"),
            ])
            .status()
            .expect("run sqlite fixture setup");
        assert!(setup.success());
        std::env::set_var("SYNERGY_INNERNET_INTERFACE", "sy-vpn");
        std::env::set_var(
            "SYNERGY_INNERNET_DATA_DIR",
            directory.to_str().expect("UTF-8 data directory"),
        );
        let assigned = authoritative_assigned_ips().expect("query authoritative assignments");
        assert_eq!(
            assigned,
            std::collections::HashSet::from(["10.70.10.7".to_string(), "10.70.10.8".to_string(),])
        );
        std::env::remove_var("SYNERGY_INNERNET_INTERFACE");
        std::env::remove_var("SYNERGY_INNERNET_DATA_DIR");
        std::fs::remove_dir_all(directory).expect("remove Innernet test directory");
    }

    #[test]
    fn command_errors_are_bounded_and_strip_control_characters() {
        assert_eq!(sanitized_command_error(b""), "");
        assert_eq!(
            sanitized_command_error(b"peer already exists\n\x00retry later"),
            ": peer already exists retry later"
        );
        assert!(sanitized_command_error(&vec![b'x'; 600]).chars().count() <= 514);
    }

    #[test]
    fn invitation_parser_binds_expected_interface_and_ip() {
        let invitation = r#"
            [interface]
            network-name = "synergy"
            address = "10.70.10.9/24"
        "#;
        let parsed = parse_invitation(invitation).expect("invitation should parse");
        assert_eq!(parsed.interface_name, "synergy");
        assert_eq!(parsed.assigned_ip, "10.70.10.9");
    }

    #[test]
    fn receipt_payload_excludes_signature() {
        let receipt = InnernetMembershipReceipt {
            version: 1,
            network: "synergy-innernet-membership-v1".to_string(),
            migration_id: "migration-1".to_string(),
            enrollment_id: "enrollment-1".to_string(),
            node_id: "node-1".to_string(),
            peer_name: "validator-1".to_string(),
            peer_type: "validator".to_string(),
            assigned_ip: "10.70.10.9".to_string(),
            interface_name: "synergy".to_string(),
            configuration_version: 1,
            confirmed_at: "2026-07-10T00:00:00Z".to_string(),
            signature: "ed25519:signature".to_string(),
        };
        let payload = String::from_utf8(receipt_payload(&receipt).expect("payload should encode"))
            .expect("payload should be UTF-8");
        assert!(!payload.contains("signature"));
    }

    #[test]
    fn invitation_expiry_is_noninteractive_and_bounded() {
        assert_eq!(
            parse_innernet_duration("30m").unwrap(),
            chrono::Duration::minutes(30)
        );
        assert!(parse_innernet_duration("0m").is_err());
        assert!(parse_innernet_duration("30minutes").is_err());
        let expiry = constrained_expiry("2026-07-10T12:00:00Z", "2026-07-10T11:30:00Z")
            .expect("expiry should be valid");
        assert_eq!(expiry, "2026-07-10T11:30:00+00:00");
    }

    #[test]
    fn bootstrap_assignment_accepts_only_canonical_peer_names() {
        let _environment_lock = test_environment_lock();
        set_innernet_address_plans();
        assert!(admin_bootstrap_assignment("relayer-1").is_ok());
        assert!(admin_bootstrap_assignment("validator-6").is_ok());
        assert!(admin_bootstrap_assignment("relayer-4").is_err());
        assert!(admin_bootstrap_assignment("validator-7").is_err());
        assert!(admin_bootstrap_assignment("validator-01").is_err());
        assert!(admin_bootstrap_assignment(" validator-1").is_err());
    }

    #[test]
    fn bootstrap_assignment_is_deterministic_per_address_plan() {
        let _environment_lock = test_environment_lock();
        set_innernet_address_plans();
        assert_eq!(
            admin_bootstrap_assignment("relayer-1").unwrap().assigned_ip,
            "10.70.20.1/32"
        );
        assert_eq!(
            admin_bootstrap_assignment("relayer-3").unwrap().assigned_ip,
            "10.70.20.3/32"
        );
        assert_eq!(
            admin_bootstrap_assignment("validator-1")
                .unwrap()
                .assigned_ip,
            "10.70.10.1/32"
        );
        assert_eq!(
            admin_bootstrap_assignment("validator-6")
                .unwrap()
                .assigned_ip,
            "10.70.10.6/32"
        );
    }

    #[test]
    fn canonical_bootstrap_validator_addresses_are_bound_to_validator_slots() {
        assert_eq!(
            canonical_bootstrap_validator_address("validator-1"),
            Some("synv11yc4cjehqjm6fp0ey4ppjptv0p3cwdy6r79t")
        );
        assert_eq!(
            canonical_bootstrap_validator_address("validator-6"),
            Some("synv1129lck2uvz73f59wd3yame0w04qnrdpmmmfc")
        );
        assert_eq!(canonical_bootstrap_validator_address("relayer-1"), None);
        assert!(is_validator_address(
            "synv11yc4cjehqjm6fp0ey4ppjptv0p3cwdy6r79t"
        ));
        assert!(!is_validator_address("syn1wallet"));
    }

    #[test]
    fn address_plans_reject_public_and_retiring_static_ranges() {
        let _environment_lock = test_environment_lock();
        std::env::set_var("SYNERGY_INNERNET_VALIDATOR_ADDRESS_CIDR", "10.69.10.0/24");
        assert!(parse_innernet_address_plan("SYNERGY_INNERNET_VALIDATOR_ADDRESS_CIDR").is_err());
        std::env::set_var("SYNERGY_INNERNET_VALIDATOR_ADDRESS_CIDR", "198.51.100.0/24");
        assert!(parse_innernet_address_plan("SYNERGY_INNERNET_VALIDATOR_ADDRESS_CIDR").is_err());
        std::env::set_var("SYNERGY_INNERNET_VALIDATOR_ADDRESS_CIDR", "10.70.10.0/24");
        assert!(parse_innernet_address_plan("SYNERGY_INNERNET_VALIDATOR_ADDRESS_CIDR").is_ok());
    }

    #[test]
    fn canonical_bootstrap_status_requires_all_nine_server_verified_members() {
        let _environment_lock = test_environment_lock();
        set_innernet_address_plans();
        let state = InnernetEnrollmentState {
            version: 1,
            latest_generation: 9,
            transport_release_generation_audit: Vec::new(),
            canonical_validator_address_binding_correction_audit: Vec::new(),
            enrollments: CANONICAL_BOOTSTRAP_PEERS
                .iter()
                .enumerate()
                .map(|(index, peer_name)| {
                    confirmed_bootstrap_enrollment(peer_name, index as u64 + 1)
                })
                .collect(),
        };
        let status = bootstrap_status(&state).expect("bootstrap status");
        assert!(status.complete);
        assert_eq!(status.confirmed_member_ids.len(), 9);
        assert!(status.pending_member_ids.is_empty());

        let mut incomplete = state.clone();
        incomplete.enrollments.pop();
        assert!(
            !bootstrap_status(&incomplete)
                .expect("bootstrap status")
                .complete
        );
    }

    #[test]
    fn transport_release_generation_rejects_incomplete_fresh_bootstrap() {
        let _environment_lock = test_environment_lock();
        set_innernet_address_plans();
        let mut state = InnernetEnrollmentState {
            version: 1,
            latest_generation: 9,
            transport_release_generation_audit: Vec::new(),
            canonical_validator_address_binding_correction_audit: Vec::new(),
            enrollments: CANONICAL_BOOTSTRAP_PEERS
                .iter()
                .enumerate()
                .map(|(index, peer_name)| {
                    confirmed_bootstrap_enrollment(peer_name, index as u64 + 1)
                })
                .collect(),
        };
        state.enrollments.pop();

        let error = advance_transport_release_generation_in_state(
            &mut state,
            TESTNET_V3_MIN_TRANSPORT_RELEASE_GENERATION,
            "release-operator",
            "publish Testnet-v3 fresh mesh",
            Utc.with_ymd_and_hms(2026, 7, 28, 12, 0, 0)
                .single()
                .expect("valid timestamp"),
        )
        .expect_err("partial bootstrap must not advance the public registry");
        assert!(error.contains("all nine canonical bootstrap peers"));
        assert_eq!(state.latest_generation, 9);
        assert!(state.transport_release_generation_audit.is_empty());
    }

    #[test]
    fn transport_release_generation_advances_9_to_21_and_signs_snapshot() {
        let _environment_lock = test_environment_lock();
        set_innernet_address_plans();
        let _signing_environment = snapshot_signing_environment();
        let mut state = InnernetEnrollmentState {
            version: 1,
            latest_generation: 9,
            transport_release_generation_audit: Vec::new(),
            canonical_validator_address_binding_correction_audit: Vec::new(),
            enrollments: CANONICAL_BOOTSTRAP_PEERS
                .iter()
                .enumerate()
                .map(|(index, peer_name)| {
                    confirmed_bootstrap_enrollment(peer_name, index as u64 + 1)
                })
                .collect(),
        };
        let before = signed_validator_transport_snapshot_from_state(&state)
            .expect("fresh bootstrap snapshot should sign");
        verify_validator_transport_snapshot(&before).expect("initial snapshot signature");
        assert_eq!(before.configuration_version, 9);
        assert_eq!(before.transports.len(), 6);
        let error = require_published_transport_release_generation(&state)
            .expect_err("public discovery must be gated before the explicit release advance");
        assert!(error.contains("not released"));

        let outcome = advance_transport_release_generation_in_state(
            &mut state,
            TESTNET_V3_MIN_TRANSPORT_RELEASE_GENERATION,
            "release-operator",
            "publish Testnet-v3 fresh mesh",
            Utc.with_ymd_and_hms(2026, 7, 28, 12, 0, 0)
                .single()
                .expect("valid timestamp"),
        )
        .expect("complete canonical bootstrap should advance registry");
        assert!(outcome.advanced);
        assert_eq!(outcome.previous_generation, 9);
        assert_eq!(
            outcome.effective_generation,
            TESTNET_V3_MIN_TRANSPORT_RELEASE_GENERATION
        );
        assert_eq!(state.transport_release_generation_audit.len(), 1);
        assert_eq!(
            state.transport_release_generation_audit[0].reason,
            "publish Testnet-v3 fresh mesh"
        );
        require_published_transport_release_generation(&state)
            .expect("persisted generation audit should publish public discovery");

        let after = signed_validator_transport_snapshot_from_state(&state)
            .expect("advanced bootstrap snapshot should sign");
        verify_validator_transport_snapshot(&after).expect("advanced snapshot signature");
        assert_eq!(
            after.configuration_version,
            TESTNET_V3_MIN_TRANSPORT_RELEASE_GENERATION
        );
        assert_eq!(after.transports, before.transports);
        assert_ne!(after.signature, before.signature);
    }

    #[test]
    fn transport_release_generation_is_idempotent_and_never_downgrades() {
        let _environment_lock = test_environment_lock();
        set_innernet_address_plans();
        let mut state = InnernetEnrollmentState {
            version: 1,
            latest_generation: TESTNET_V3_MIN_TRANSPORT_RELEASE_GENERATION,
            transport_release_generation_audit: Vec::new(),
            canonical_validator_address_binding_correction_audit: Vec::new(),
            enrollments: CANONICAL_BOOTSTRAP_PEERS
                .iter()
                .enumerate()
                .map(|(index, peer_name)| {
                    confirmed_bootstrap_enrollment(peer_name, index as u64 + 1)
                })
                .collect(),
        };

        let idempotent = advance_transport_release_generation_in_state(
            &mut state,
            TESTNET_V3_MIN_TRANSPORT_RELEASE_GENERATION,
            "release-operator",
            "repeat exact release request",
            Utc::now(),
        )
        .expect("same minimum should be idempotent");
        assert!(!idempotent.advanced);
        assert_eq!(idempotent.effective_generation, 21);
        assert!(state.transport_release_generation_audit.is_empty());

        state.latest_generation = 25;
        let no_downgrade = advance_transport_release_generation_in_state(
            &mut state,
            TESTNET_V3_MIN_TRANSPORT_RELEASE_GENERATION,
            "release-operator",
            "do not lower a newer registry",
            Utc::now(),
        )
        .expect("lower requested minimum must leave newer registry intact");
        assert!(!no_downgrade.advanced);
        assert_eq!(no_downgrade.previous_generation, 25);
        assert_eq!(no_downgrade.effective_generation, 25);
        assert_eq!(state.latest_generation, 25);
        assert!(state.transport_release_generation_audit.is_empty());
    }

    #[test]
    fn canonical_binding_correction_rebinds_only_current_validator_addresses_and_advances_21_to_22()
    {
        let _environment_lock = test_environment_lock();
        set_innernet_address_plans();
        let _signing_environment = snapshot_signing_environment();
        let mut state = released_canonical_bootstrap_state();
        for enrollment in state
            .enrollments
            .iter_mut()
            .filter(|enrollment| enrollment.peer_type == "validator")
        {
            enrollment.validator_address = Some(format!(
                "synv1legacybinding{}",
                enrollment.peer_name.replace('-', "")
            ));
            enrollment.preconfigured_wireguard_public_key =
                Some(format!("unchanged-wireguard-key-{}", enrollment.peer_name));
        }
        let before_enrollments = state.enrollments.clone();
        let prior_snapshot_sha256 = signed_snapshot_sha256(&state)
            .expect("the old signed generation-21 snapshot should serialize");
        let outcome = correct_canonical_validator_address_bindings_in_state(
            &mut state,
            &prior_snapshot_sha256,
            "release-operator",
            "correct stale v19.0.53 validator bindings against applied Testnet-v3 Genesis",
            Utc.with_ymd_and_hms(2026, 7, 29, 1, 0, 0)
                .single()
                .expect("valid timestamp"),
        )
        .expect("one-time correction must accept the exact released nine-peer state");

        assert_eq!(outcome.previous_generation, 21);
        assert_eq!(outcome.effective_generation, 22);
        assert_eq!(outcome.corrected_bindings.len(), 6);
        assert_eq!(
            outcome.applied_genesis_sha256,
            TESTNET_V3_APPLIED_GENESIS_SHA256
        );
        assert_eq!(
            outcome.applied_genesis_hash,
            TESTNET_V3_APPLIED_GENESIS_HASH
        );
        assert_eq!(
            outcome.canonical_validator_bindings_sha256,
            TESTNET_V3_CANONICAL_VALIDATOR_BINDINGS_SHA256
        );
        assert_eq!(outcome.prior_snapshot_sha256, prior_snapshot_sha256);
        assert_eq!(state.latest_generation, 22);
        assert_eq!(
            state
                .canonical_validator_address_binding_correction_audit
                .len(),
            1
        );
        assert_eq!(
            state.canonical_validator_address_binding_correction_audit[0].prior_snapshot_sha256,
            prior_snapshot_sha256
        );

        for (before, after) in before_enrollments.iter().zip(&state.enrollments) {
            let mut expected = before.clone();
            if expected.peer_type == "validator" {
                expected.validator_address =
                    canonical_bootstrap_validator_address(&expected.peer_name).map(str::to_string);
            }
            assert_eq!(after, &expected, "only validator_address may change");
        }
        let snapshot = signed_validator_transport_snapshot_from_state(&state)
            .expect("corrected generation-22 snapshot should sign");
        verify_validator_transport_snapshot(&snapshot)
            .expect("corrected generation-22 snapshot signature should verify");
        assert_eq!(snapshot.configuration_version, 22);
        assert_eq!(snapshot.transports.len(), 6);
        for (peer_name, validator_address) in super::CANONICAL_BOOTSTRAP_VALIDATORS {
            let expected_ip = admin_bootstrap_assignment(peer_name)
                .expect("canonical assignment")
                .assigned_ip
                .split('/')
                .next()
                .expect("assigned IP")
                .to_string();
            let transport = snapshot
                .transports
                .iter()
                .find(|transport| transport.validator_address == validator_address)
                .expect("every canonical validator must be present");
            assert_eq!(transport.dial_address, format!("{expected_ip}:5622"));
        }
        assert!(correct_canonical_validator_address_bindings_in_state(
            &mut state,
            &prior_snapshot_sha256,
            "release-operator",
            "a second binding correction must be rejected",
            Utc::now(),
        )
        .is_err());
    }

    #[test]
    fn canonical_binding_correction_rejects_wrong_anchor_or_prior_snapshot() {
        let _environment_lock = test_environment_lock();
        set_innernet_address_plans();
        let _signing_environment = snapshot_signing_environment();
        assert!(require_canonical_validator_binding_anchors(
            "not-the-applied-genesis",
            TESTNET_V3_APPLIED_GENESIS_HASH,
            TESTNET_V3_CANONICAL_VALIDATOR_BINDINGS_SHA256,
        )
        .is_err());
        assert!(require_canonical_validator_binding_anchors(
            TESTNET_V3_APPLIED_GENESIS_SHA256,
            "not-the-applied-genesis-hash",
            TESTNET_V3_CANONICAL_VALIDATOR_BINDINGS_SHA256,
        )
        .is_err());
        assert_eq!(
            canonical_validator_bindings_digest().expect("compiled binding digest"),
            TESTNET_V3_CANONICAL_VALIDATOR_BINDINGS_SHA256
        );

        let mut state = released_canonical_bootstrap_state();
        state.enrollments[3].validator_address = Some("synv1legacywrongaddress".to_string());
        let before = state.clone();
        let error = correct_canonical_validator_address_bindings_in_state(
            &mut state,
            "00",
            "release-operator",
            "reject a digest that does not prove the live signed generation-21 snapshot",
            Utc::now(),
        )
        .expect_err("a mismatched prior snapshot digest must fail before mutation");
        assert!(error.contains("prior snapshot SHA-256"));
        assert_eq!(state.latest_generation, before.latest_generation);
        assert_eq!(state.enrollments, before.enrollments);
        assert!(state
            .canonical_validator_address_binding_correction_audit
            .is_empty());
    }

    #[test]
    fn release_advance_and_binding_correction_fail_closed_on_stale_validator_bindings_or_handshakes(
    ) {
        let _environment_lock = test_environment_lock();
        set_innernet_address_plans();
        let _signing_environment = snapshot_signing_environment();

        let mut unreleased = released_canonical_bootstrap_state();
        unreleased.latest_generation = 9;
        unreleased.transport_release_generation_audit.clear();
        unreleased.enrollments[3].validator_address = Some("synv1legacywrongaddress".to_string());
        let advance_error = advance_transport_release_generation_in_state(
            &mut unreleased,
            TESTNET_V3_MIN_TRANSPORT_RELEASE_GENERATION,
            "release-operator",
            "must reject a stale address map before any future public release",
            Utc::now(),
        )
        .expect_err("release advancement must not sign a stale validator map");
        assert!(
            advance_error.contains("missing transport") || advance_error.contains("exactly six")
        );
        assert_eq!(unreleased.latest_generation, 9);

        let mut unverified = released_canonical_bootstrap_state();
        unverified.enrollments[3].validator_address = Some("synv1legacywrongaddress".to_string());
        unverified.enrollments[3].handshake_verified_at = None;
        let prior_snapshot_sha256 = signed_snapshot_sha256(&unverified)
            .expect("test snapshot should serialize before the handshake gate");
        let correction_error = correct_canonical_validator_address_bindings_in_state(
            &mut unverified,
            &prior_snapshot_sha256,
            "release-operator",
            "must reject a correction when an exact bootstrap handshake is absent",
            Utc::now(),
        )
        .expect_err("correction must require all nine server-verified handshakes");
        assert!(correction_error.contains("all nine canonical bootstrap peers"));
        assert_eq!(unverified.latest_generation, 21);
        assert!(unverified
            .canonical_validator_address_binding_correction_audit
            .is_empty());
    }

    #[test]
    fn legacy_enrollment_state_without_release_audit_deserializes_but_stays_publicly_gated() {
        let state: InnernetEnrollmentState = serde_json::from_str(
            r#"{
                "version": 1,
                "latest_generation": 21,
                "enrollments": []
            }"#,
        )
        .expect("old coordinator state must remain readable after adding the audit field");
        assert!(state.transport_release_generation_audit.is_empty());
        let error = require_published_transport_release_generation(&state)
            .expect_err("an old state cannot publish without release evidence");
        assert!(error.contains("persisted release-generation audit"));
    }

    #[test]
    fn legacy_bootstrap_reconciliation_requires_all_nine_exact_confirmed_members() {
        let _environment_lock = test_environment_lock();
        set_innernet_address_plans();
        let mut state = InnernetEnrollmentState {
            version: 1,
            latest_generation: 9,
            transport_release_generation_audit: Vec::new(),
            canonical_validator_address_binding_correction_audit: Vec::new(),
            enrollments: CANONICAL_BOOTSTRAP_PEERS
                .iter()
                .enumerate()
                .map(|(index, peer_name)| {
                    let mut enrollment =
                        confirmed_bootstrap_enrollment(peer_name, index as u64 + 1);
                    enrollment.handshake_verified_at = None;
                    enrollment
                })
                .collect(),
        };

        let candidates = legacy_bootstrap_verification_candidates(&state)
            .expect("legacy canonical peers should require server verification");
        assert_eq!(candidates.len(), CANONICAL_BOOTSTRAP_PEERS.len());

        state.enrollments[0].bootstrap = false;
        assert!(legacy_bootstrap_verification_candidates(&state).is_err());
        state.enrollments[0].bootstrap = true;
        state.enrollments.pop();
        assert!(legacy_bootstrap_verification_candidates(&state).is_err());
    }

    #[test]
    fn server_handshake_requires_matching_fresh_peer() {
        let dump = concat!(
            "server-private\tserver-public\t51820\t0\n",
            "peer-key\tpsk\t203.0.113.7:51820\t10.70.10.1/32\t1000\t0\t0\t0\n"
        );
        assert!(has_fresh_server_handshake(dump, "peer-key", 1001));
        assert!(!has_fresh_server_handshake(dump, "other-peer", 1001));
        assert!(!has_fresh_server_handshake(dump, "peer-key", 1401));
    }

    #[test]
    fn stale_recovery_requires_an_aged_matching_handshake() {
        let dump = concat!(
            "server-private\tserver-public\t51820\t0\n",
            "peer-key\tpsk\t203.0.113.7:51820\t10.70.10.1/32\t1000\t0\t0\t0\n"
        );
        assert_eq!(
            server_handshake_age_seconds(dump, "peer-key", 1001),
            Some(1)
        );
        assert_eq!(
            server_handshake_age_seconds(
                dump,
                "peer-key",
                1000 + STALE_UNREDEEMED_HANDSHAKE_RECOVERY_MIN_AGE_SECONDS,
            ),
            Some(STALE_UNREDEEMED_HANDSHAKE_RECOVERY_MIN_AGE_SECONDS)
        );
        assert_eq!(server_handshake_age_seconds(dump, "other-peer", 2000), None);
        assert_eq!(server_handshake_timestamp(dump, "peer-key"), Some(1000));
        assert_eq!(server_handshake_age_seconds(dump, "peer-key", 900), None);
    }

    #[test]
    fn mesh_status_reports_pre_cutover_readiness() {
        let _environment_lock = test_environment_lock();
        set_innernet_address_plans();
        std::env::set_var("SYNERGY_INNERNET_MIGRATION_ID", "migration-1");
        std::env::set_var("SYNERGY_INNERNET_MIGRATION_READY", "false");
        let state = InnernetEnrollmentState {
            version: 1,
            latest_generation: 1,
            transport_release_generation_audit: Vec::new(),
            canonical_validator_address_binding_correction_audit: Vec::new(),
            enrollments: vec![enrollment(
                "enrollment-1",
                "node-1",
                1,
                Some("2026-07-10T00:00:00Z"),
                1,
            )],
        };

        let status = mesh_status_from_state(&state).expect("mesh status should resolve");
        assert!(!status.migration_ready);
        assert_eq!(status.latest_generation, 1);
        assert!(status.propagation_complete);
    }

    #[test]
    fn latest_confirmation_supersedes_earlier_confirmation_for_propagation() {
        let _environment_lock = test_environment_lock();
        set_innernet_address_plans();
        std::env::set_var("SYNERGY_INNERNET_MIGRATION_ID", "migration-1");
        let state = InnernetEnrollmentState {
            version: 1,
            latest_generation: 2,
            transport_release_generation_audit: Vec::new(),
            canonical_validator_address_binding_correction_audit: Vec::new(),
            enrollments: vec![
                enrollment("enrollment-1", "node-1", 1, Some("2026-07-10T00:00:00Z"), 1),
                enrollment("enrollment-2", "node-1", 2, Some("2026-07-10T00:05:00Z"), 2),
            ],
        };

        let status = mesh_status_from_state(&state).expect("mesh status should resolve");
        assert_eq!(status.active_members, 1);
        assert_eq!(status.acknowledged_member_ids, vec!["node-1"]);
        assert!(status.pending_member_ids.is_empty());
        assert!(status.propagation_complete);
    }

    #[test]
    fn missing_current_confirmation_blocks_propagation() {
        let _environment_lock = test_environment_lock();
        set_innernet_address_plans();
        std::env::set_var("SYNERGY_INNERNET_MIGRATION_ID", "migration-1");
        let state = InnernetEnrollmentState {
            version: 1,
            latest_generation: 2,
            transport_release_generation_audit: Vec::new(),
            canonical_validator_address_binding_correction_audit: Vec::new(),
            enrollments: vec![
                enrollment("enrollment-1", "node-1", 1, Some("2026-07-10T00:00:00Z"), 1),
                enrollment("enrollment-2", "node-1", 2, None, 0),
            ],
        };

        let status = mesh_status_from_state(&state).expect("mesh status should resolve");
        assert_eq!(status.active_members, 1);
        assert!(status.acknowledged_member_ids.is_empty());
        assert_eq!(status.pending_member_ids, vec!["node-1"]);
        assert!(!status.propagation_complete);
    }
}
