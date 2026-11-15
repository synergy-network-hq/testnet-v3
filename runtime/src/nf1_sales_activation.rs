//! Signed execution activation for native NF1 sales on the existing Chain 1266
//! single-authority lineage. This module does not select a height, sign an
//! authorization, or alter the genesis or consensus journal identity.

use std::{collections::BTreeMap, sync::OnceLock};

use serde::{Deserialize, Serialize};

use crate::{
    consensus::{
        chain1266_startup_dispatch::{
            verify_single_authority_v2_activation, SingleAuthorityLaunchPins, LAUNCH_GENESIS_HASH,
            LAUNCH_RELEASE_ID,
        },
        single_authority_finality_store::SINGLE_AUTHORITY_CONSENSUS_PROTOCOL,
        single_authority_startup::{
            StartupExpectation, LAUNCH_CHAIN_ID, LAUNCH_CHAIN_INCARNATION, LAUNCH_NETWORK_ID,
        },
    },
    desired_state_v2::{sha256_hex, SignedDesiredStateV2},
};

pub const NF1_SALES_PROTOCOL: &str = "sts-nf1-sales-v1";
pub const NF1_SALES_ACTIVATION_SCHEMA_VERSION: u32 = 1;
pub const NF1_SALES_ACTIVATION_PATH: &str = "config/chain1266-nf1-sales-activation-v1.json";
pub const MAX_NF1_SALES_ACTIVATION_BYTES: usize = 8 * 1024;

/// The execution fingerprint in the original signed incarnation-5 startup.
/// Only this legacy fingerprint can start without the additional manifest.
pub const LEGACY_EXECUTION_CONFIGURATION_FINGERPRINT: &str =
    "sha256:642339bca236a557493a3666c9c71a6bac075b42732f475593999ff34509a145";

pub const AUTHORITY_BINARY: &str = "synergy-validator-node";
pub const ALLOWED_ROLE_BINARIES: &[&str] = &[
    AUTHORITY_BINARY,
    "synergy-rpc-gateway-node",
    "synergy-observer-light-node",
    "synergy-indexer-and-explorer-node",
    "synergy-relayer-node",
    "synergy-archive",
    "synergy-archive-validator-node",
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActivationCheckpoint {
    pub height: u64,
    pub block_hash: String,
    pub state_root: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Nf1SalesActivationManifest {
    pub schema_version: u32,
    pub chain_id: u64,
    pub chain_incarnation: u64,
    pub network_id: String,
    pub genesis_hash: String,
    pub consensus_release_id: String,
    pub consensus_protocol: String,
    pub protocol: String,
    pub checkpoint: ActivationCheckpoint,
    pub activation_height: u64,
    pub role_binary_sha256: BTreeMap<String, String>,
}

impl Nf1SalesActivationManifest {
    pub fn validate(&self) -> Result<(), String> {
        if self.schema_version != NF1_SALES_ACTIVATION_SCHEMA_VERSION {
            return Err("Unsupported NF1 sales activation schema version".into());
        }
        if self.chain_id != LAUNCH_CHAIN_ID
            || self.chain_incarnation != LAUNCH_CHAIN_INCARNATION
            || self.network_id != LAUNCH_NETWORK_ID
            || self.genesis_hash != LAUNCH_GENESIS_HASH
            || self.consensus_release_id != LAUNCH_RELEASE_ID
            || self.consensus_protocol != SINGLE_AUTHORITY_CONSENSUS_PROTOCOL
            || self.protocol != NF1_SALES_PROTOCOL
        {
            return Err(
                "NF1 sales activation does not bind the pinned Chain 1266 lineage and protocol"
                    .into(),
            );
        }
        if self.checkpoint.height == 0 || self.activation_height <= self.checkpoint.height {
            return Err(
                "NF1 sales activation must follow an earlier nonzero finalized checkpoint".into(),
            );
        }
        require_digest(&self.checkpoint.block_hash, "checkpoint block hash")?;
        require_digest(&self.checkpoint.state_root, "checkpoint state root")?;
        if !self.role_binary_sha256.contains_key(AUTHORITY_BINARY) {
            return Err("NF1 sales activation must pin the authority binary".into());
        }
        for (role, digest) in &self.role_binary_sha256 {
            if !ALLOWED_ROLE_BINARIES.contains(&role.as_str()) {
                return Err(format!("Unexpected NF1 sales role binary {role}"));
            }
            require_digest(digest, "role binary SHA-256")?;
        }
        Ok(())
    }

    /// Struct field order and lexicographic role order define the signed bytes.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, String> {
        self.validate()?;
        serde_json::to_vec(self)
            .map_err(|error| format!("Encode canonical NF1 sales activation: {error}"))
    }

    pub fn fingerprint(&self) -> Result<String, String> {
        Ok(format!("sha256:{}", sha256_hex(&self.canonical_bytes()?)))
    }

    /// The caller hashes the mounted executable for the actual running role,
    /// or hashes the exact candidate artifact during offline verification.
    pub fn verify_role_binary(&self, role: &str, digest: &str) -> Result<(), String> {
        require_digest(digest, "actual role binary SHA-256")?;
        if !ALLOWED_ROLE_BINARIES.contains(&role) {
            return Err(format!("Unexpected local NF1 sales role binary {role}"));
        }
        let expected = self
            .role_binary_sha256
            .get(role)
            .ok_or_else(|| format!("NF1 sales activation does not authorize role binary {role}"))?;
        if expected != digest {
            return Err(format!(
                "NF1 sales activation SHA-256 does not match role binary {role}"
            ));
        }
        Ok(())
    }
}

fn require_digest(value: &str, label: &str) -> Result<(), String> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        || value.bytes().all(|byte| byte == b'0')
    {
        return Err(format!(
            "Invalid {label}: expected nonzero lowercase 32-byte hex"
        ));
    }
    Ok(())
}

pub fn parse_fingerprint(value: &str) -> Result<&str, String> {
    let hex = value
        .strip_prefix("sha256:")
        .ok_or("The activation fingerprint must use sha256:")?;
    require_digest(hex, "activation fingerprint")?;
    Ok(hex)
}

pub fn parse_manifest(bytes: &[u8]) -> Result<Nf1SalesActivationManifest, String> {
    if bytes.is_empty() || bytes.len() > MAX_NF1_SALES_ACTIVATION_BYTES {
        return Err("NF1 sales activation exceeds the canonical document size limit".into());
    }
    let manifest: Nf1SalesActivationManifest = serde_json::from_slice(bytes)
        .map_err(|error| format!("Parse NF1 sales activation: {error}"))?;
    if manifest.canonical_bytes()? != bytes {
        return Err("NF1 sales activation must use its exact canonical JSON bytes".into());
    }
    Ok(manifest)
}

#[derive(Debug, Clone)]
pub struct VerifiedNf1SalesActivation {
    manifest: Nf1SalesActivationManifest,
}

impl VerifiedNf1SalesActivation {
    pub fn manifest(&self) -> &Nf1SalesActivationManifest {
        &self.manifest
    }

    /// The observed checkpoint comes from the local verified finalized archive
    /// or replay, never from the manifest file or an unverified RPC response.
    pub fn verify_checkpoint(
        &self,
        observed: &ActivationCheckpoint,
    ) -> Result<AnchoredNf1SalesActivation, String> {
        if &self.manifest.checkpoint != observed {
            return Err("Local finalized height, block hash, or state root disagrees with the NF1 sales activation checkpoint".into());
        }
        Ok(AnchoredNf1SalesActivation {
            manifest: self.manifest.clone(),
        })
    }
}

#[derive(Debug, Clone)]
pub struct AnchoredNf1SalesActivation {
    manifest: Nf1SalesActivationManifest,
}

impl AnchoredNf1SalesActivation {
    pub fn manifest(&self) -> &Nf1SalesActivationManifest {
        &self.manifest
    }

    /// Pass the height of the block being executed or the finalized block
    /// whose state is being served. No clock or remote head selects activation.
    pub fn is_active_at(&self, processed_block_height: u64) -> bool {
        processed_block_height >= self.manifest.activation_height
    }
}

static INSTALLED_ACTIVATION: OnceLock<AnchoredNf1SalesActivation> = OnceLock::new();

/// Startup installs only the policy authenticated against local finalized
/// history. Installing a different policy requires a new verified start.
pub(crate) fn install_anchored(policy: AnchoredNf1SalesActivation) -> Result<(), String> {
    if !cfg!(feature = "engineering-nf1-sales") {
        return Err("This binary does not support NF1 sales activation".into());
    }
    INSTALLED_ACTIVATION
        .set(policy)
        .map_err(|_| "NF1 sales execution activation is already installed".into())
}

pub fn enabled_at(height: u64) -> bool {
    cfg!(feature = "engineering-nf1-sales")
        && INSTALLED_ACTIVATION
            .get()
            .is_some_and(|policy| policy.is_active_at(height))
}

/// Verify the existing ML-DSA-87 startup authorization, its binding to the
/// canonical activation bytes, and the role-specific executable hash.
pub fn verify_installed_activation(
    manifest: Option<&[u8]>,
    desired_state_bytes: &[u8],
    signed: &SignedDesiredStateV2,
    expectation: &StartupExpectation,
    local_validator_address: &str,
    role_binary: &str,
    binary_sha256: &str,
) -> Result<Option<VerifiedNf1SalesActivation>, String> {
    verify_single_authority_v2_activation(
        desired_state_bytes,
        signed,
        expectation,
        local_validator_address,
        &SingleAuthorityLaunchPins::incarnation5(),
    )?;
    bind_verified_desired_state(
        manifest,
        &signed.desired_state.execution_configuration_fingerprint,
        role_binary,
        binary_sha256,
    )
}

fn bind_verified_desired_state(
    manifest: Option<&[u8]>,
    execution_fingerprint: &str,
    role_binary: &str,
    binary_sha256: &str,
) -> Result<Option<VerifiedNf1SalesActivation>, String> {
    let approved_digest = parse_fingerprint(execution_fingerprint)?;
    let Some(bytes) = manifest else {
        if execution_fingerprint == LEGACY_EXECUTION_CONFIGURATION_FINGERPRINT {
            return Ok(None);
        }
        return Err(
            "Signed execution configuration requires an installed NF1 sales activation manifest"
                .into(),
        );
    };
    if execution_fingerprint == LEGACY_EXECUTION_CONFIGURATION_FINGERPRINT {
        return Err(
            "The legacy startup signature does not authorize an NF1 sales activation".into(),
        );
    }
    let manifest = parse_manifest(bytes)?;
    if sha256_hex(bytes) != approved_digest {
        return Err("The NF1 sales activation does not match the signed execution configuration fingerprint".into());
    }
    manifest.verify_role_binary(role_binary, binary_sha256)?;
    Ok(Some(VerifiedNf1SalesActivation { manifest }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        consensus::chain1266_startup_dispatch::{
            LAUNCH_AUTHORITY_ADDRESS, LAUNCH_DIRECTORY_NAMESPACE,
        },
        crypto::pqc::{PQCAlgorithm, PQCManager},
        desired_state_v2::canonical_signing_payload,
    };
    use base64::{engine::general_purpose, Engine as _};

    const DESIRED_STATE: &[u8] = include_bytes!(
        "../../launch/chain1266-incarnation-5-single-authority-rc1/activation/chain1266-desired-state-v2.json"
    );
    const START_AUTHORIZATION: &[u8] = include_bytes!(
        "../../launch/chain1266-incarnation-5-single-authority-rc1/activation/chain1266-start-authorization-v2.json"
    );

    fn manifest() -> Nf1SalesActivationManifest {
        Nf1SalesActivationManifest {
            schema_version: NF1_SALES_ACTIVATION_SCHEMA_VERSION,
            chain_id: LAUNCH_CHAIN_ID,
            chain_incarnation: LAUNCH_CHAIN_INCARNATION,
            network_id: LAUNCH_NETWORK_ID.into(),
            genesis_hash: LAUNCH_GENESIS_HASH.into(),
            consensus_release_id: LAUNCH_RELEASE_ID.into(),
            consensus_protocol: SINGLE_AUTHORITY_CONSENSUS_PROTOCOL.into(),
            protocol: NF1_SALES_PROTOCOL.into(),
            checkpoint: ActivationCheckpoint {
                height: 100,
                block_hash: "a".repeat(64),
                state_root: "b".repeat(64),
            },
            activation_height: 107,
            role_binary_sha256: BTreeMap::from([
                (AUTHORITY_BINARY.into(), "c".repeat(64)),
                ("synergy-rpc-gateway-node".into(), "d".repeat(64)),
            ]),
        }
    }

    fn expectation(signed: &SignedDesiredStateV2) -> StartupExpectation {
        StartupExpectation {
            genesis_chain_id: LAUNCH_CHAIN_ID,
            genesis_chain_incarnation: LAUNCH_CHAIN_INCARNATION,
            genesis_network_id: LAUNCH_NETWORK_ID.into(),
            genesis_hash: LAUNCH_GENESIS_HASH.into(),
            genesis_directory_namespace: LAUNCH_DIRECTORY_NAMESPACE.into(),
            release_id: LAUNCH_RELEASE_ID.into(),
            authority_id: crate::consensus::single_authority_startup::LAUNCH_AUTHORITY_ID.into(),
            authority_public_key_fingerprint: signed
                .desired_state
                .authority_public_key_fingerprint
                .clone(),
            authority_key_algorithm: PQCAlgorithm::MLDSA65,
        }
    }

    #[test]
    fn canonical_manifest_rejects_ambiguous_or_unpinned_inputs() {
        let manifest = manifest();
        let bytes = manifest.canonical_bytes().unwrap();
        assert_eq!(parse_manifest(&bytes).unwrap(), manifest);
        assert_eq!(
            parse_fingerprint(&manifest.fingerprint().unwrap()).unwrap(),
            sha256_hex(&bytes)
        );
        let text = std::str::from_utf8(&bytes).unwrap();
        assert!(
            text.find("synergy-rpc-gateway-node").unwrap() < text.find(AUTHORITY_BINARY).unwrap()
        );
        for altered in [
            format!("{text}\n"),
            text.replacen(
                "\"chain_id\":1266",
                "\"chain_id\":1266,\"chain_id\":1266",
                1,
            ),
            text.replace("\"height\":100", "\"height\":0"),
            text.replace("\"activation_height\":107", "\"activation_height\":100"),
            text.replacen("incarnation\":5", "incarnation\":4", 1),
            text.replace("sts-nf1-sales-v1", "sts-nf1-sales-v2"),
            text.replace("synergy-rpc-gateway-node", "unsigned-wallet-tool"),
            text.replace(AUTHORITY_BINARY, "synergy-observer-light-node"),
            text.replace(&"a".repeat(64), &"A".repeat(64)),
            text.replace(&"b".repeat(64), &"0".repeat(64)),
        ] {
            assert!(
                parse_manifest(altered.as_bytes()).is_err(),
                "accepted {altered}"
            );
        }
        assert!(parse_fingerprint(&"f".repeat(64)).is_err());
        assert!(parse_manifest(&[b'x'; MAX_NF1_SALES_ACTIVATION_BYTES + 1]).is_err());
    }

    #[test]
    fn authentic_legacy_start_cannot_enable_an_unsigned_or_tampered_manifest() {
        let signed: SignedDesiredStateV2 = serde_json::from_slice(START_AUTHORIZATION).unwrap();
        let expected = expectation(&signed);
        let manifest = manifest();
        let bytes = manifest.canonical_bytes().unwrap();
        let digest = &manifest.role_binary_sha256[AUTHORITY_BINARY];
        let verify = |manifest, desired_state, signed| {
            verify_installed_activation(
                manifest,
                desired_state,
                signed,
                &expected,
                LAUNCH_AUTHORITY_ADDRESS,
                AUTHORITY_BINARY,
                digest,
            )
        };
        assert!(verify(None, DESIRED_STATE, &signed).unwrap().is_none());
        assert!(verify(Some(bytes.as_slice()), DESIRED_STATE, &signed).is_err());

        let mut changed = signed.clone();
        changed.desired_state.execution_configuration_fingerprint = manifest.fingerprint().unwrap();
        let changed_bytes =
            crate::desired_state_v2_canonical::canonical_bytes(&changed.desired_state).unwrap();
        assert!(verify(Some(bytes.as_slice()), &changed_bytes, &changed).is_err());
    }

    #[test]
    fn signed_fingerprint_binds_binary_and_exact_local_checkpoint_before_height_gate() {
        let mut signed: SignedDesiredStateV2 = serde_json::from_slice(START_AUTHORIZATION).unwrap();
        let manifest = manifest();
        let bytes = manifest.canonical_bytes().unwrap();
        let fingerprint = manifest.fingerprint().unwrap();
        let digest = &manifest.role_binary_sha256[AUTHORITY_BINARY];
        signed.desired_state.execution_configuration_fingerprint = fingerprint.clone();

        // Only this test uses an ephemeral ML-DSA-87 key. The public verifier
        // always uses the pinned incumbent authority fingerprint.
        let mut manager = PQCManager::new();
        let (public, private) = manager.generate_keypair(PQCAlgorithm::MLDSA87).unwrap();
        let signed_bytes = canonical_signing_payload(&signed.desired_state).unwrap();
        let signature = manager.sign(&private, &signed_bytes).unwrap();
        signed.start_authority_public_key_base64 =
            general_purpose::STANDARD.encode(&public.key_data);
        signed.start_authority_fingerprint = format!("sha256:{}", sha256_hex(&public.key_data));
        signed.signature_base64 = general_purpose::STANDARD.encode(&signature.signature_data);
        let mut pins = SingleAuthorityLaunchPins::incarnation5();
        pins.start_authority_fingerprint = signed.start_authority_fingerprint.clone();
        let desired =
            crate::desired_state_v2_canonical::canonical_bytes(&signed.desired_state).unwrap();
        verify_single_authority_v2_activation(
            &desired,
            &signed,
            &expectation(&signed),
            LAUNCH_AUTHORITY_ADDRESS,
            &pins,
        )
        .unwrap();
        assert!(verify_installed_activation(
            Some(&bytes),
            &desired,
            &signed,
            &expectation(&signed),
            LAUNCH_AUTHORITY_ADDRESS,
            AUTHORITY_BINARY,
            digest,
        )
        .is_err());
        let bind =
            |bytes, role, digest| bind_verified_desired_state(bytes, &fingerprint, role, digest);
        assert!(bind(None, AUTHORITY_BINARY, digest).is_err());
        let wrong_digest = "1".repeat(64);
        assert!(bind(Some(&bytes), AUTHORITY_BINARY, &wrong_digest).is_err());
        assert!(bind(Some(&bytes), "synergy-observer-light-node", digest).is_err());
        let mut altered = manifest.clone();
        altered.activation_height += 1;
        let altered_bytes = altered.canonical_bytes().unwrap();
        assert!(bind(Some(&altered_bytes), AUTHORITY_BINARY, digest).is_err());

        let verified = bind(Some(&bytes), AUTHORITY_BINARY, digest)
            .unwrap()
            .unwrap();
        let mut checkpoint = manifest.checkpoint.clone();
        checkpoint.state_root = "e".repeat(64);
        assert!(verified.verify_checkpoint(&checkpoint).is_err());
        checkpoint = manifest.checkpoint.clone();
        checkpoint.height += 1;
        assert!(verified.verify_checkpoint(&checkpoint).is_err());
        checkpoint = manifest.checkpoint.clone();
        checkpoint.block_hash = "f".repeat(64);
        assert!(verified.verify_checkpoint(&checkpoint).is_err());
        let anchored = verified.verify_checkpoint(&manifest.checkpoint).unwrap();
        assert!(!anchored.is_active_at(106));
        assert!(anchored.is_active_at(107));
        assert!(anchored.is_active_at(108));
    }
}
