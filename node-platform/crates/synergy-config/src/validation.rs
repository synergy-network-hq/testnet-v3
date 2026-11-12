use std::collections::BTreeSet;
use std::fmt;
use std::path::Path;

use synergy_protocol_types::NodeRole;

use crate::{
    ConsensusMode, NodeConfiguration, UpdateMode, VpnMode, CONFIG_SCHEMA_VERSION,
    GOVERNED_PROTECTED_LOOKAHEAD,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigError {
    NativeTransportNotQualified(NativeTransportPolicyError),
    UnsupportedSchema {
        found: u16,
        supported: u16,
    },
    EmptyField(&'static str),
    InvalidIdentifier(&'static str),
    InvalidAbsolutePath(&'static str),
    InvalidValue {
        field: &'static str,
        reason: &'static str,
    },
    RoleConstraint {
        field: &'static str,
        reason: &'static str,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeTransportPolicyError {
    ClassicalOverlayForbidden,
    MissingPostQuantumAuthenticatedRecordLayer,
}
impl fmt::Display for NativeTransportPolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::ClassicalOverlayForbidden => "NetBird/WireGuard relies on classical asymmetric trust/session establishment and is forbidden as native security",
            Self::MissingPostQuantumAuthenticatedRecordLayer => "native transport is not qualified: explicit APQE ML-KEM-1024 and authenticated AES-256 record protection is not implemented",
        })
    }
}
impl std::error::Error for NativeTransportPolicyError {}

/// Explicit engineering namespace shared by the NodeNetwork formation signer
/// and runtime. Namespace selection grants neither authority nor qualification.
pub fn is_disposable_formation_network(network_id: &str) -> bool {
    network_id.len() <= 128
        && network_id
            .strip_prefix("nodenetwork-formation-disposable-")
            .is_some_and(|suffix| {
                !suffix.is_empty()
                    && suffix.split('-').all(|segment| {
                        !segment.is_empty()
                            && segment
                                .bytes()
                                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
                    })
            })
}

impl NodeConfiguration {
    /// A signature-authenticated TCP socket is not a PQ confidentiality channel.
    /// No configuration flag can waive this missing protocol implementation.
    pub fn require_native_post_quantum_transport(&self) -> Result<(), NativeTransportPolicyError> {
        if self.vpn.mode != VpnMode::Disabled {
            return Err(NativeTransportPolicyError::ClassicalOverlayForbidden);
        }
        Err(NativeTransportPolicyError::MissingPostQuantumAuthenticatedRecordLayer)
    }

    /// Validates the canonical new-platform configuration without consuming it.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.schema_version != CONFIG_SCHEMA_VERSION {
            return Err(ConfigError::UnsupportedSchema {
                found: self.schema_version,
                supported: CONFIG_SCHEMA_VERSION,
            });
        }
        if self.vpn.mode != VpnMode::Disabled {
            return Err(ConfigError::NativeTransportNotQualified(
                NativeTransportPolicyError::ClassicalOverlayForbidden,
            ));
        }
        require_identifier("node_name", &self.node_name)?;
        if self.chain_id == 0 {
            return Err(invalid("chain_id", "must be nonzero"));
        }
        require_identifier("network_id", &self.network_id)?;
        if let Some(provider) = &self.aegis_provider {
            require_absolute("aegis_provider.report_path", &provider.report_path)?;
            let digest = &provider.authenticated_report_sha256;
            if digest.len() != 64
                || !digest
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            {
                return Err(invalid(
                    "aegis_provider.authenticated_report_sha256",
                    "requires 32 bytes of lowercase hex from an authenticated manifest",
                ));
            }
        }
        if let Some(transport) = &self.apqe_transport {
            for digest in [
                &transport.registry_trust_key_sha256,
                &transport.genesis_trust_key_sha256,
            ] {
                if digest.len() != 64
                    || !digest
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                {
                    return Err(invalid(
                        "apqe_transport.trust_fingerprint",
                        "requires independently authenticated lowercase SHA-256 fingerprint",
                    ));
                }
            }
            if self.aegis_provider.is_none()
                || self.genesis_path.is_none()
                || self.consensus.authority_binding.is_none()
                || self.consensus.authority_trust_key_path.is_none()
                || !(is_disposable_formation_network(&self.network_id)
                    || (self.network_id.starts_with("posy-")
                        && self.network_id.contains("-canary-")))
            {
                return Err(invalid("apqe_transport", "requires an isolated engineering incarnation, explicit provider, signed Genesis and governed authority"));
            }
            for (name, path) in [
                ("apqe_transport.registry_path", &transport.registry_path),
                (
                    "apqe_transport.registry_trust_key_path",
                    &transport.registry_trust_key_path,
                ),
                ("apqe_transport.enrollment_path", &transport.enrollment_path),
                ("apqe_transport.custody_path", &transport.custody_path),
                (
                    "apqe_transport.custody_unlock_path",
                    &transport.custody_unlock_path,
                ),
            ] {
                require_absolute(name, path)?;
            }
        }
        if let Some(path) = self
            .consensus
            .authority_recovery_certificate_path
            .as_deref()
        {
            require_absolute("consensus.authority_recovery_certificate_path", path)?;
            if self.consensus.authority_binding.is_none()
                || self.consensus.authority_trust_key_path.is_none()
            {
                return Err(invalid(
                    "consensus.authority_recovery_certificate_path",
                    "requires the original authority and Genesis trust pin",
                ));
            }
        }
        require_absolute("manifest_path", &self.manifest_path)?;
        require_absolute("public_identity_path", &self.public_identity_path)?;
        if self.apqe_transport.is_none() {
            let aegis_bindings = self
                .aegis_key_bindings_path
                .as_deref()
                .ok_or(ConfigError::EmptyField("aegis_key_bindings_path"))?;
            let aegis_signing_key = self
                .aegis_signing_key_path
                .as_deref()
                .ok_or(ConfigError::EmptyField("aegis_signing_key_path"))?;
            require_absolute("aegis_key_bindings_path", aegis_bindings)?;
            require_absolute("aegis_signing_key_path", aegis_signing_key)?;
        }
        require_absolute("admin_socket_path", &self.admin_socket_path)?;
        require_absolute("storage.data_directory", &self.storage.data_directory)?;
        if self.storage.world_memory_budget_bytes == 0 {
            return Err(invalid(
                "storage.world_memory_budget_bytes",
                "must be nonzero",
            ));
        }

        if self.network.listen_addresses.is_empty() {
            return Err(ConfigError::EmptyField("network.listen_addresses"));
        }
        require_unique(
            "network.listen_addresses",
            self.network.listen_addresses.iter().copied(),
        )?;
        require_unique(
            "network.advertised_addresses",
            self.network.advertised_addresses.iter().copied(),
        )?;
        if self
            .network
            .listen_addresses
            .iter()
            .chain(&self.network.advertised_addresses)
            .any(|address| address.port() == 0)
        {
            return Err(invalid("network", "addresses must use a nonzero port"));
        }
        if self.network.dial_timeout_ms == 0 || self.network.idle_connection_timeout_ms == 0 {
            return Err(invalid("network", "timeouts must be nonzero"));
        }

        if self.p2p.max_authenticated_peers == 0 {
            return Err(invalid("p2p.max_authenticated_peers", "must be nonzero"));
        }
        if self.p2p.max_pending_handshakes > self.p2p.max_authenticated_peers {
            return Err(invalid(
                "p2p.max_pending_handshakes",
                "cannot exceed max_authenticated_peers",
            ));
        }
        if !(1_024..=16 * 1024 * 1024).contains(&self.p2p.max_frame_bytes) {
            return Err(invalid(
                "p2p.max_frame_bytes",
                "must be between 1 KiB and 16 MiB",
            ));
        }
        if self.p2p.gossip_fanout == 0 || self.p2p.gossip_fanout > self.p2p.max_authenticated_peers
        {
            return Err(invalid(
                "p2p.gossip_fanout",
                "must be nonzero and not exceed max_authenticated_peers",
            ));
        }

        if self.consensus.proposal_timeout_ms < 100
            || self.consensus.round_timeout_ms < self.consensus.proposal_timeout_ms
            || self.consensus.max_rounds_behind == 0
        {
            return Err(invalid(
                "consensus",
                "timeouts and catch-up bound are not internally consistent",
            ));
        }
        match self.consensus.mode {
            ConsensusMode::ValidateAndVote => {
                if self.role != NodeRole::Validator {
                    return Err(role_error(
                        "consensus.mode",
                        "only validator-role nodes may request voting components",
                    ));
                }
                let binding = self.consensus.authority_binding.as_deref().ok_or_else(|| {
                    role_error(
                        "consensus.authority_binding",
                        "voting requires an explicit verified authority binding",
                    )
                })?;
                require_absolute("consensus.authority_binding", binding)?;
                let trust = self
                    .consensus
                    .authority_trust_key_path
                    .as_deref()
                    .ok_or_else(|| {
                        role_error(
                            "consensus.authority_trust_key_path",
                            "voting requires a pinned authority trust root",
                        )
                    })?;
                require_absolute("consensus.authority_trust_key_path", trust)?;
                if self.apqe_transport.is_none() {
                    let signing_key =
                        self.consensus.signing_key_path.as_deref().ok_or_else(|| {
                            role_error(
                                "consensus.signing_key_path",
                                "voting requires a provisioned consensus signing key",
                            )
                        })?;
                    require_absolute("consensus.signing_key_path", signing_key)?;
                }
                if !self.etdag.enabled {
                    return Err(role_error(
                        "etdag.enabled",
                        "validator voting requires verified ETDAG proposal material",
                    ));
                }
                if self.apqe_transport.is_none() && self.vpn.mode != VpnMode::Required {
                    return Err(role_error(
                        "vpn.mode",
                        "validator voting requires the authenticated validator overlay",
                    ));
                }
            }
            ConsensusMode::Observe => {
                let binding = self.consensus.authority_binding.as_deref().ok_or_else(|| {
                    role_error(
                        "consensus.authority_binding",
                        "observation requires verified authority",
                    )
                })?;
                let trust = self
                    .consensus
                    .authority_trust_key_path
                    .as_deref()
                    .ok_or_else(|| {
                        role_error(
                            "consensus.authority_trust_key_path",
                            "observation requires a pinned authority trust root",
                        )
                    })?;
                require_absolute("consensus.authority_binding", binding)?;
                require_absolute("consensus.authority_trust_key_path", trust)?;
            }
            ConsensusMode::Disabled => {
                if self.consensus.authority_binding.is_some()
                    || self.consensus.authority_trust_key_path.is_some()
                    || self.consensus.signing_key_path.is_some()
                {
                    return Err(role_error(
                        "consensus.authority_binding",
                        "disabled consensus cannot accept authority material",
                    ));
                }
            }
        }

        if let Some(path) = self.etdag.ingress_kem_secret_key_path.as_deref() {
            require_absolute("etdag.ingress_kem_secret_key_path", path)?;
        }
        if self.etdag.enabled {
            if !(GOVERNED_PROTECTED_LOOKAHEAD..=16).contains(&self.etdag.protected_lookahead) {
                return Err(invalid(
                    "etdag.protected_lookahead",
                    "must be within structural lookahead bounds 5..=16; signed authority selects the exact value",
                ));
            }
            if self.etdag.admission_queue_capacity == 0
                || !(1_024..=16 * 1024 * 1024).contains(&self.etdag.max_vertex_bytes)
                || self.etdag.proposal_material_wait_ms == 0
            {
                return Err(invalid(
                    "etdag",
                    "enabled ETDAG limits must be nonzero and bounded",
                ));
            }
        }

        if self.storage.max_open_files < 32 {
            return Err(invalid("storage.max_open_files", "must be at least 32"));
        }
        if self.storage.minimum_free_bytes == 0 {
            return Err(invalid("storage.minimum_free_bytes", "must be nonzero"));
        }
        if self
            .storage
            .prune_finalized_history_after_blocks
            .is_some_and(|blocks| blocks == 0)
        {
            return Err(invalid(
                "storage.prune_finalized_history_after_blocks",
                "must be nonzero when configured",
            ));
        }
        if self.role == NodeRole::Archive
            && self.storage.prune_finalized_history_after_blocks.is_some()
        {
            return Err(role_error(
                "storage.prune_finalized_history_after_blocks",
                "archive nodes must retain finalized history",
            ));
        }

        match (self.rpc.enabled, self.rpc.listen_address) {
            (true, None) => return Err(ConfigError::EmptyField("rpc.listen_address")),
            (false, Some(_)) => {
                return Err(invalid(
                    "rpc.listen_address",
                    "must be absent when RPC is disabled",
                ))
            }
            _ => {}
        }
        if self.rpc.enabled
            && (self.rpc.max_request_bytes == 0 || self.rpc.max_concurrent_requests == 0)
        {
            return Err(invalid("rpc", "enabled RPC limits must be nonzero"));
        }

        require_identifier("telemetry.service_name", &self.telemetry.service_name)?;
        if self.telemetry.trace_sample_per_million > 1_000_000 {
            return Err(invalid(
                "telemetry.trace_sample_per_million",
                "cannot exceed one million",
            ));
        }

        if self.update.enabled {
            let catalog = self
                .update
                .catalog_path
                .as_deref()
                .ok_or(ConfigError::EmptyField("update.catalog_path"))?;
            let signer_key_id = self
                .update
                .release_signer_key_id
                .as_deref()
                .ok_or(ConfigError::EmptyField("update.release_signer_key_id"))?;
            let signer_public_key = self
                .update
                .release_signer_public_key_path
                .as_deref()
                .ok_or(ConfigError::EmptyField(
                    "update.release_signer_public_key_path",
                ))?;
            let staging = self
                .update
                .staging_directory
                .as_deref()
                .ok_or(ConfigError::EmptyField("update.staging_directory"))?;
            require_absolute("update.catalog_path", catalog)?;
            require_absolute("update.release_signer_public_key_path", signer_public_key)?;
            require_absolute("update.staging_directory", staging)?;
            if signer_key_id.trim().is_empty()
                || signer_key_id.len() > 256
                || signer_key_id.contains(char::is_control)
            {
                return Err(invalid(
                    "update.release_signer_key_id",
                    "must contain 1..=256 safe characters",
                ));
            }
            if self.update.minimum_free_bytes == 0
                || self.update.maximum_artifact_bytes == 0
                || self.update.maximum_artifact_bytes > crate::DEFAULT_MAXIMUM_UPDATE_ARTIFACT_BYTES
            {
                return Err(invalid("update", "artifact and disk bounds are invalid"));
            }
            if self.update.mode == UpdateMode::InstallWhenHealthy && !self.update.allow_rollback {
                return Err(invalid(
                    "update.allow_rollback",
                    "automatic installation requires rollback",
                ));
            }
        } else if self.update.catalog_path.is_some()
            || self.update.release_signer_key_id.is_some()
            || self.update.release_signer_public_key_path.is_some()
            || self.update.staging_directory.is_some()
        {
            return Err(invalid(
                "update",
                "disabled updates cannot carry release authority or staging paths",
            ));
        }

        match self.vpn.mode {
            VpnMode::Disabled => {
                if self.vpn.interface_name.is_some()
                    || self.vpn.signed_registry_path.is_some()
                    || self.vpn.attestation_public_key.is_some()
                    || self.vpn.provider_plan_sha256.is_some()
                {
                    return Err(invalid(
                        "vpn",
                        "disabled VPN must not carry interface or registry state",
                    ));
                }
            }
            VpnMode::Preferred | VpnMode::Required => {
                let interface = self
                    .vpn
                    .interface_name
                    .as_deref()
                    .ok_or(ConfigError::EmptyField("vpn.interface_name"))?;
                require_interface_name(interface)?;
                let registry = self
                    .vpn
                    .signed_registry_path
                    .as_deref()
                    .ok_or(ConfigError::EmptyField("vpn.signed_registry_path"))?;
                require_absolute("vpn.signed_registry_path", registry)?;
                let public_key = self
                    .vpn
                    .attestation_public_key
                    .as_deref()
                    .ok_or(ConfigError::EmptyField("vpn.attestation_public_key"))?;
                if !public_key.starts_with("ml-dsa-87:") || public_key.len() != 3466 {
                    return Err(invalid(
                        "vpn.attestation_public_key",
                        "must be a canonical ml-dsa-87: public key; native classical trust is forbidden",
                    ));
                }
                let plan_hash = self
                    .vpn
                    .provider_plan_sha256
                    .as_deref()
                    .ok_or(ConfigError::EmptyField("vpn.provider_plan_sha256"))?;
                if plan_hash.len() != 64
                    || !plan_hash
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                {
                    return Err(invalid(
                        "vpn.provider_plan_sha256",
                        "must be lowercase SHA-256",
                    ));
                }
            }
        }
        Ok(())
    }

    pub fn into_validated(self) -> Result<Self, ConfigError> {
        self.validate()?;
        Ok(self)
    }
}

fn require_identifier(field: &'static str, value: &str) -> Result<(), ConfigError> {
    if value.trim().is_empty() {
        return Err(ConfigError::EmptyField(field));
    }
    let bytes = value.as_bytes();
    if bytes.len() > 63
        || !bytes[0].is_ascii_lowercase()
        || !bytes
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
        || bytes.last() == Some(&b'-')
    {
        return Err(ConfigError::InvalidIdentifier(field));
    }
    Ok(())
}

fn require_interface_name(value: &str) -> Result<(), ConfigError> {
    if value.is_empty()
        || value.len() > 15
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(ConfigError::InvalidIdentifier("vpn.interface_name"));
    }
    Ok(())
}

fn require_absolute(field: &'static str, value: &Path) -> Result<(), ConfigError> {
    if !value.is_absolute() {
        return Err(ConfigError::InvalidAbsolutePath(field));
    }
    Ok(())
}

fn require_unique<T: Ord>(
    field: &'static str,
    values: impl IntoIterator<Item = T>,
) -> Result<(), ConfigError> {
    let mut seen = BTreeSet::new();
    if values.into_iter().any(|value| !seen.insert(value)) {
        return Err(invalid(field, "contains duplicate values"));
    }
    Ok(())
}

const fn invalid(field: &'static str, reason: &'static str) -> ConfigError {
    ConfigError::InvalidValue { field, reason }
}

const fn role_error(field: &'static str, reason: &'static str) -> ConfigError {
    ConfigError::RoleConstraint { field, reason }
}

impl fmt::Display for ConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NativeTransportNotQualified(error) => {
                write!(formatter, "native transport policy refused: {error}")
            }
            Self::UnsupportedSchema { found, supported } => write!(
                formatter,
                "unsupported config schema {found}; this binary supports {supported}"
            ),
            Self::EmptyField(field) => write!(formatter, "configuration field {field} is empty"),
            Self::InvalidIdentifier(field) => {
                write!(
                    formatter,
                    "configuration field {field} is not a canonical identifier"
                )
            }
            Self::InvalidAbsolutePath(field) => {
                write!(formatter, "configuration path {field} must be absolute")
            }
            Self::InvalidValue { field, reason } => {
                write!(
                    formatter,
                    "configuration field {field} is invalid: {reason}"
                )
            }
            Self::RoleConstraint { field, reason } => {
                write!(
                    formatter,
                    "configuration role constraint for {field}: {reason}"
                )
            }
        }
    }
}

impl std::error::Error for ConfigError {}
