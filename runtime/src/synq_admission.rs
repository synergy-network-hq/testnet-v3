use serde::{Deserialize, Serialize};
use std::fmt;

fn wall_clock_unix_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or_default()
}

use crate::synergy_types::{
    Hash, Transaction, SYNERGY_TESTNET_V3_CHAIN_ID, SYNERGY_TESTNET_V3_NETWORK_ID,
};
use pqsynq::{
    AegisSynQVerifier, AlgorithmId, ChainId, ContractCallEnvelope, ContractDeployEnvelope,
    DomainTag, NetworkId, SignaturePurpose, SynQAddress, SynQSecurityPolicy, VerificationContext,
};

pub const SYNQ_ADMISSION_CARRIER_PREFIX: &[u8] = b"synq-admission-v1:";
pub const SYNQ_ADMISSION_VERSION: u16 = 1;
pub const SYNQ_CANONICAL_TESTNET_NETWORK_ID: &str = "synergy-testnet";
pub const SYNQ_DEPLOY_AUTHORIZATION_PURPOSE: &str = "synq-contract-deploy";
pub const SYNQ_CALL_AUTHORIZATION_PURPOSE: &str = "synq-contract-call";
pub const MAX_SYNQ_DEPLOY_BYTECODE_BYTES: usize = 256 * 1024;
pub const MAX_SYNQ_DEPLOY_ABI_JSON_BYTES: usize = 64 * 1024;
pub const MAX_SYNQ_DEPLOY_MANIFEST_JSON_BYTES: usize = 64 * 1024;
pub const MAX_SYNQ_CONSTRUCTOR_ARGS_BYTES: usize = 16 * 1024;
pub const MAX_SYNQ_CALL_ARGS_BYTES: usize = 16 * 1024;
pub const MAX_STS9_VERIFICATION_JSON_BYTES: usize = 128 * 1024;
pub const MAX_SYNQ_ADMISSION_CARRIER_JSON_BYTES: usize = 2 * 1024 * 1024;
pub const MAX_SYNQ_ENCODED_PQSYNQ_ENVELOPE_BYTES: usize = 256 * 1024;
const MAX_SYNQ_NETWORK_ID_BYTES: usize = 64;
const MAX_SYNQ_SIGNER_BYTES: usize = 128;
const MAX_SYNQ_AUTHORIZATION_PURPOSE_BYTES: usize = 128;
pub const STS9_HORIZON_CONTRACT_NAME: &str = "STS9HorizonToken";
pub const STS9_HORIZON_DEPLOYER_WALLET: &str = "synw1jmtpyjw62nxgattrcjc2tx2hezwj6rka5war";
pub const STS9_HORIZON_SUPPLY_BASE_UNITS: &str = "1000000000000000000";
const SYNQ_CONTRACT_ADDRESS_DERIVATION_DOMAIN: &str = "SYNERGY_SYNQ_CONTRACT_ADDRESS_V1";
const SYNERGY_CUSTOM_CONTRACT_ADDRESS_PREFIX: &str = "sync";
const SYNQ_CONTRACT_ADDRESS_VERSION: u8 = 1;
const SYNQ_CONTRACT_ADDRESS_CLASS: u16 = 0xC001;
const SYNQ_ADDRESS_LEN: usize = 41;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NormalizedSynQNetwork {
    pub chain_id: u64,
    pub node_network_id: String,
    pub pqsynq_network_id: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SynQAdmissionKind {
    Deploy,
    Call,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SynQAdmissionEnvelope {
    pub version: u16,
    pub kind: SynQAdmissionKind,
    pub chain_id: u64,
    pub network_id: String,
    pub signer: String,
    #[serde(default)]
    pub identity_authorization: Option<IdentityAuthorizationBindingCarrier>,
    #[serde(default)]
    pub authorization_purpose: String,
    pub payload_hash: [u8; 32],
    pub bytecode_hash: Option<[u8; 32]>,
    pub manifest_hash: Option<[u8; 32]>,
    pub abi_hash: Option<[u8; 32]>,
    pub encoded_pqsynq_envelope: Vec<u8>,
    #[serde(default)]
    pub bytecode: Option<Vec<u8>>,
    #[serde(default)]
    pub abi_json: Option<String>,
    #[serde(default)]
    pub manifest_json: Option<String>,
    #[serde(default)]
    pub constructor_args: Option<Vec<u8>>,
    #[serde(default)]
    pub encoded_args: Option<Vec<u8>>,
    #[serde(default)]
    pub sts9_verification_json: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SynQVerificationSummary {
    pub chain_id: u64,
    pub normalized_network_id: String,
    pub node_network_id: String,
    pub domain: String,
    pub algorithm: String,
    pub signer: String,
    pub identity_authorization_payload_sha3_256: Option<String>,
    pub payload_hash: [u8; 32],
    pub bytecode_hash: Option<[u8; 32]>,
    pub manifest_hash: Option<[u8; 32]>,
    pub abi_hash: Option<[u8; 32]>,
    pub verified_at_admission: bool,
}

type IdentityAuthorizationBindingCarrier = crate::identity_auth::IdentityAuthorizationCarrier;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SynQAdmissionError {
    Decode {
        code: &'static str,
        message: String,
    },
    UnsupportedVersion {
        found: u16,
    },
    UnsupportedKind {
        expected: SynQAdmissionKind,
        found: SynQAdmissionKind,
    },
    NetworkMismatch {
        chain_id: u64,
        network_id: String,
    },
    PqSynQ {
        code: &'static str,
        message: String,
    },
    MissingRequiredField {
        field: &'static str,
    },
    InvalidCarrier {
        code: &'static str,
        message: String,
    },
}

impl SynQAdmissionError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::Decode { code, .. } => code,
            Self::UnsupportedVersion { .. } => "SYNQ-VERSION",
            Self::UnsupportedKind { .. } => "SYNQ-KIND",
            Self::NetworkMismatch { chain_id, .. } if *chain_id != SYNERGY_TESTNET_V3_CHAIN_ID => {
                "AEGIS-CHAIN"
            }
            Self::NetworkMismatch { .. } => "AEGIS-NETWORK",
            Self::PqSynQ { code, .. } => code,
            Self::MissingRequiredField { .. } => "SYNQ-MISSING-FIELD",
            Self::InvalidCarrier { code, .. } => code,
        }
    }
}

impl fmt::Display for SynQAdmissionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Decode { code, message } => write!(f, "{code}: {message}"),
            Self::UnsupportedVersion { found } => {
                write!(f, "SYNQ-VERSION: unsupported SynQ carrier version {found}")
            }
            Self::UnsupportedKind { expected, found } => write!(
                f,
                "SYNQ-KIND: expected SynQ {:?} carrier, found {:?}",
                expected, found
            ),
            Self::NetworkMismatch {
                chain_id,
                network_id,
            } => write!(
                f,
                "{}: SynQ carrier network {network_id} is not allowed for chain {chain_id}",
                self.code()
            ),
            Self::PqSynQ { code, message } => write!(f, "{code}: {message}"),
            Self::MissingRequiredField { field } => {
                write!(f, "SYNQ-MISSING-FIELD: missing required field {field}")
            }
            Self::InvalidCarrier { code, message } => write!(f, "{code}: {message}"),
        }
    }
}

impl std::error::Error for SynQAdmissionError {}

pub fn normalize_synq_network(
    chain_id: u64,
    network_id: &str,
) -> Result<NormalizedSynQNetwork, SynQAdmissionError> {
    if chain_id != SYNERGY_TESTNET_V3_CHAIN_ID {
        return Err(SynQAdmissionError::NetworkMismatch {
            chain_id,
            network_id: network_id.to_string(),
        });
    }

    match network_id {
        SYNQ_CANONICAL_TESTNET_NETWORK_ID | SYNERGY_TESTNET_V3_NETWORK_ID => {
            Ok(NormalizedSynQNetwork {
                chain_id,
                node_network_id: network_id.to_string(),
                pqsynq_network_id: SYNQ_CANONICAL_TESTNET_NETWORK_ID.to_string(),
            })
        }
        _ => Err(SynQAdmissionError::NetworkMismatch {
            chain_id,
            network_id: network_id.to_string(),
        }),
    }
}

pub fn encode_synq_admission_carrier(
    envelope: &SynQAdmissionEnvelope,
) -> Result<Vec<u8>, SynQAdmissionError> {
    validate_synq_envelope_precrypto_bounds(envelope)?;
    let mut out = SYNQ_ADMISSION_CARRIER_PREFIX.to_vec();
    let bytes = serde_json::to_vec(envelope).map_err(|error| SynQAdmissionError::Decode {
        code: "AEGIS-CANON",
        message: format!("serialize SynQ admission carrier: {error}"),
    })?;
    out.extend_from_slice(&bytes);
    Ok(out)
}

pub fn decode_synq_admission_carrier(
    payload: &[u8],
) -> Result<Option<SynQAdmissionEnvelope>, SynQAdmissionError> {
    let Some(bytes) = payload.strip_prefix(SYNQ_ADMISSION_CARRIER_PREFIX) else {
        return Ok(None);
    };
    if bytes.len() > MAX_SYNQ_ADMISSION_CARRIER_JSON_BYTES {
        return Err(SynQAdmissionError::InvalidCarrier {
            code: "SYNQ-CARRIER-SIZE",
            message: format!(
                "SynQ admission carrier JSON exceeds {MAX_SYNQ_ADMISSION_CARRIER_JSON_BYTES} bytes"
            ),
        });
    }
    let envelope: SynQAdmissionEnvelope =
        serde_json::from_slice(bytes).map_err(|error| SynQAdmissionError::Decode {
            code: "AEGIS-CANON",
            message: format!("decode SynQ admission carrier: {error}"),
        })?;
    validate_synq_envelope_precrypto_bounds(&envelope)?;
    Ok(Some(envelope))
}

pub fn is_synq_admission_carrier(payload: &[u8]) -> bool {
    payload.starts_with(SYNQ_ADMISSION_CARRIER_PREFIX)
}

fn ensure_bounded_carrier_text(
    field: &'static str,
    value: &str,
    maximum: usize,
) -> Result<(), SynQAdmissionError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(SynQAdmissionError::InvalidCarrier {
            code: "AEGIS-CANON",
            message: format!("SynQ carrier field {field} must be non-empty text without controls"),
        });
    }
    if value.len() > maximum {
        return Err(SynQAdmissionError::InvalidCarrier {
            code: "SYNQ-CARRIER-SIZE",
            message: format!("SynQ carrier field {field} exceeds {maximum} bytes"),
        });
    }
    Ok(())
}

/// Applies every inexpensive carrier bound before identity-binding or inner
/// ML-DSA verification. This function must remain the first validation step in
/// deploy/call verification so attacker-controlled allocations cannot amplify
/// post-quantum work.
fn validate_synq_envelope_precrypto_bounds(
    envelope: &SynQAdmissionEnvelope,
) -> Result<(), SynQAdmissionError> {
    ensure_bounded_carrier_text(
        "network_id",
        &envelope.network_id,
        MAX_SYNQ_NETWORK_ID_BYTES,
    )?;
    ensure_bounded_carrier_text("signer", &envelope.signer, MAX_SYNQ_SIGNER_BYTES)?;
    ensure_bounded_carrier_text(
        "authorization_purpose",
        &envelope.authorization_purpose,
        MAX_SYNQ_AUTHORIZATION_PURPOSE_BYTES,
    )?;
    if envelope.encoded_pqsynq_envelope.is_empty() {
        return Err(SynQAdmissionError::MissingRequiredField {
            field: "encoded_pqsynq_envelope",
        });
    }
    if envelope.encoded_pqsynq_envelope.len() > MAX_SYNQ_ENCODED_PQSYNQ_ENVELOPE_BYTES {
        return Err(SynQAdmissionError::InvalidCarrier {
            code: "SYNQ-CARRIER-SIZE",
            message: format!(
                "SynQ encoded aegis-pqsynq envelope exceeds {MAX_SYNQ_ENCODED_PQSYNQ_ENVELOPE_BYTES} bytes"
            ),
        });
    }
    if let Some(bytecode) = envelope.bytecode.as_ref() {
        ensure_artifact_size("bytecode", bytecode.len(), MAX_SYNQ_DEPLOY_BYTECODE_BYTES)?;
    }
    if let Some(abi_json) = envelope.abi_json.as_ref() {
        ensure_artifact_size("abi_json", abi_json.len(), MAX_SYNQ_DEPLOY_ABI_JSON_BYTES)?;
    }
    if let Some(manifest_json) = envelope.manifest_json.as_ref() {
        ensure_artifact_size(
            "manifest_json",
            manifest_json.len(),
            MAX_SYNQ_DEPLOY_MANIFEST_JSON_BYTES,
        )?;
    }
    if let Some(constructor_args) = envelope.constructor_args.as_ref() {
        ensure_artifact_size(
            "constructor_args",
            constructor_args.len(),
            MAX_SYNQ_CONSTRUCTOR_ARGS_BYTES,
        )?;
    }
    if let Some(encoded_args) = envelope.encoded_args.as_ref() {
        ensure_artifact_size("encoded_args", encoded_args.len(), MAX_SYNQ_CALL_ARGS_BYTES)?;
    }
    if let Some(verification) = envelope.sts9_verification_json.as_ref() {
        ensure_artifact_size(
            "sts9_verification_json",
            verification.len(),
            MAX_STS9_VERIFICATION_JSON_BYTES,
        )?;
    }
    Ok(())
}

fn build_deploy_admission_envelope_unverified(
    chain_id: u64,
    network_id: &str,
    encoded_pqsynq_envelope: &[u8],
    identity_authorization: IdentityAuthorizationBindingCarrier,
    authorization_purpose: &str,
    now_unix: u64,
) -> Result<SynQAdmissionEnvelope, SynQAdmissionError> {
    if authorization_purpose != SYNQ_DEPLOY_AUTHORIZATION_PURPOSE {
        return Err(SynQAdmissionError::InvalidCarrier {
            code: "AEGIS-CANON",
            message: format!(
                "SynQ deploy authorization purpose must be {SYNQ_DEPLOY_AUTHORIZATION_PURPOSE}"
            ),
        });
    }
    let deploy: ContractDeployEnvelope =
        decode_pqsynq_envelope(encoded_pqsynq_envelope, "decode SynQ deploy envelope")?;
    let signer = canonical_signer_address_from_carrier_at(
        &identity_authorization,
        &deploy.public_key.bytes,
        authorization_purpose,
        now_unix,
    )?;
    Ok(SynQAdmissionEnvelope {
        version: SYNQ_ADMISSION_VERSION,
        kind: SynQAdmissionKind::Deploy,
        chain_id,
        network_id: network_id.to_string(),
        signer,
        identity_authorization: Some(identity_authorization),
        authorization_purpose: authorization_purpose.to_string(),
        payload_hash: deploy.signing_payload.payload_hash,
        bytecode_hash: Some(deploy.bytecode_hash),
        manifest_hash: Some(deploy.manifest_hash),
        abi_hash: Some(deploy.abi_hash),
        encoded_pqsynq_envelope: encoded_pqsynq_envelope.to_vec(),
        bytecode: None,
        abi_json: None,
        manifest_json: None,
        constructor_args: None,
        encoded_args: None,
        sts9_verification_json: None,
    })
}

pub fn build_deploy_admission_envelope_from_pqsynq_bytes(
    _chain_id: u64,
    _network_id: &str,
    _encoded_pqsynq_envelope: &[u8],
    _now_unix: u64,
) -> Result<SynQAdmissionEnvelope, SynQAdmissionError> {
    Err(SynQAdmissionError::MissingRequiredField {
        field: "identity_authorization",
    })
}

pub fn build_deploy_admission_envelope_from_pqsynq_bytes_with_identity_authorization(
    chain_id: u64,
    network_id: &str,
    encoded_pqsynq_envelope: &[u8],
    identity_authorization: IdentityAuthorizationBindingCarrier,
    authorization_purpose: &str,
    now_unix: u64,
) -> Result<SynQAdmissionEnvelope, SynQAdmissionError> {
    let envelope = build_deploy_admission_envelope_unverified(
        chain_id,
        network_id,
        encoded_pqsynq_envelope,
        identity_authorization,
        authorization_purpose,
        now_unix,
    )?;
    verify_synq_deploy_for_offline_creation(&envelope, now_unix)?;
    Ok(envelope)
}

pub fn build_deploy_admission_envelope_from_pqsynq_bytes_with_artifacts(
    chain_id: u64,
    network_id: &str,
    encoded_pqsynq_envelope: &[u8],
    bytecode: Vec<u8>,
    abi_json: String,
    manifest_json: String,
    now_unix: u64,
) -> Result<SynQAdmissionEnvelope, SynQAdmissionError> {
    let mut envelope = build_deploy_admission_envelope_from_pqsynq_bytes(
        chain_id,
        network_id,
        encoded_pqsynq_envelope,
        now_unix,
    )?;
    attach_deploy_artifacts(&mut envelope, bytecode, abi_json, manifest_json)?;
    Ok(envelope)
}

pub fn build_deploy_admission_envelope_from_pqsynq_bytes_with_artifacts_and_constructor_args(
    _chain_id: u64,
    _network_id: &str,
    _encoded_pqsynq_envelope: &[u8],
    _bytecode: Vec<u8>,
    _abi_json: String,
    _manifest_json: String,
    _constructor_args: Vec<u8>,
    _now_unix: u64,
) -> Result<SynQAdmissionEnvelope, SynQAdmissionError> {
    Err(SynQAdmissionError::MissingRequiredField {
        field: "identity_authorization",
    })
}

#[allow(clippy::too_many_arguments)]
pub fn build_deploy_admission_envelope_from_pqsynq_bytes_with_artifacts_constructor_args_and_identity_authorization(
    chain_id: u64,
    network_id: &str,
    encoded_pqsynq_envelope: &[u8],
    bytecode: Vec<u8>,
    abi_json: String,
    manifest_json: String,
    constructor_args: Vec<u8>,
    identity_authorization: IdentityAuthorizationBindingCarrier,
    authorization_purpose: &str,
    now_unix: u64,
) -> Result<SynQAdmissionEnvelope, SynQAdmissionError> {
    let mut envelope = build_deploy_admission_envelope_unverified(
        chain_id,
        network_id,
        encoded_pqsynq_envelope,
        identity_authorization,
        authorization_purpose,
        now_unix,
    )?;
    attach_deploy_artifacts(&mut envelope, bytecode, abi_json, manifest_json)?;
    attach_constructor_args(&mut envelope, constructor_args)?;
    verify_synq_deploy_for_offline_creation(&envelope, now_unix)?;
    Ok(envelope)
}

pub fn build_deploy_admission_envelope_from_pqsynq_bytes_with_artifacts_and_sts9_verification(
    chain_id: u64,
    network_id: &str,
    encoded_pqsynq_envelope: &[u8],
    bytecode: Vec<u8>,
    abi_json: String,
    manifest_json: String,
    sts9_verification_json: String,
    now_unix: u64,
) -> Result<SynQAdmissionEnvelope, SynQAdmissionError> {
    let mut envelope = build_deploy_admission_envelope_from_pqsynq_bytes_with_artifacts(
        chain_id,
        network_id,
        encoded_pqsynq_envelope,
        bytecode,
        abi_json,
        manifest_json,
        now_unix,
    )?;
    attach_sts9_verification(&mut envelope, sts9_verification_json)?;
    verify_synq_deploy_for_offline_creation(&envelope, now_unix)?;
    Ok(envelope)
}

pub fn build_call_admission_envelope_from_pqsynq_bytes(
    _chain_id: u64,
    _network_id: &str,
    _encoded_pqsynq_envelope: &[u8],
    _now_unix: u64,
) -> Result<SynQAdmissionEnvelope, SynQAdmissionError> {
    Err(SynQAdmissionError::MissingRequiredField {
        field: "identity_authorization",
    })
}

pub fn build_call_admission_envelope_from_pqsynq_bytes_with_identity_authorization(
    chain_id: u64,
    network_id: &str,
    encoded_pqsynq_envelope: &[u8],
    identity_authorization: IdentityAuthorizationBindingCarrier,
    authorization_purpose: &str,
    now_unix: u64,
) -> Result<SynQAdmissionEnvelope, SynQAdmissionError> {
    if authorization_purpose != SYNQ_CALL_AUTHORIZATION_PURPOSE {
        return Err(SynQAdmissionError::InvalidCarrier {
            code: "AEGIS-CANON",
            message: format!(
                "SynQ call authorization purpose must be {SYNQ_CALL_AUTHORIZATION_PURPOSE}"
            ),
        });
    }
    let call: ContractCallEnvelope =
        decode_pqsynq_envelope(encoded_pqsynq_envelope, "decode SynQ call envelope")?;
    let signer = canonical_signer_address_from_carrier_at(
        &identity_authorization,
        &call.public_key.bytes,
        authorization_purpose,
        now_unix,
    )?;
    let envelope = SynQAdmissionEnvelope {
        version: SYNQ_ADMISSION_VERSION,
        kind: SynQAdmissionKind::Call,
        chain_id,
        network_id: network_id.to_string(),
        signer,
        identity_authorization: Some(identity_authorization),
        authorization_purpose: authorization_purpose.to_string(),
        payload_hash: call.signing_payload.payload_hash,
        bytecode_hash: None,
        manifest_hash: None,
        abi_hash: None,
        encoded_pqsynq_envelope: encoded_pqsynq_envelope.to_vec(),
        bytecode: None,
        abi_json: None,
        manifest_json: None,
        constructor_args: None,
        encoded_args: None,
        sts9_verification_json: None,
    };
    verify_synq_call_for_offline_creation(&envelope, now_unix)?;
    Ok(envelope)
}

pub fn build_call_admission_envelope_from_pqsynq_bytes_with_args(
    chain_id: u64,
    network_id: &str,
    encoded_pqsynq_envelope: &[u8],
    encoded_args: Vec<u8>,
    now_unix: u64,
) -> Result<SynQAdmissionEnvelope, SynQAdmissionError> {
    let mut envelope = build_call_admission_envelope_from_pqsynq_bytes(
        chain_id,
        network_id,
        encoded_pqsynq_envelope,
        now_unix,
    )?;
    attach_call_args(&mut envelope, encoded_args)?;
    verify_synq_call_for_offline_creation(&envelope, now_unix)?;
    Ok(envelope)
}

pub fn build_deploy_admission_carrier_from_pqsynq_bytes(
    chain_id: u64,
    network_id: &str,
    encoded_pqsynq_envelope: &[u8],
    now_unix: u64,
) -> Result<Vec<u8>, SynQAdmissionError> {
    let envelope = build_deploy_admission_envelope_from_pqsynq_bytes(
        chain_id,
        network_id,
        encoded_pqsynq_envelope,
        now_unix,
    )?;
    encode_synq_admission_carrier(&envelope)
}

pub fn build_deploy_admission_carrier_from_pqsynq_bytes_with_artifacts(
    chain_id: u64,
    network_id: &str,
    encoded_pqsynq_envelope: &[u8],
    bytecode: Vec<u8>,
    abi_json: String,
    manifest_json: String,
    now_unix: u64,
) -> Result<Vec<u8>, SynQAdmissionError> {
    let envelope = build_deploy_admission_envelope_from_pqsynq_bytes_with_artifacts(
        chain_id,
        network_id,
        encoded_pqsynq_envelope,
        bytecode,
        abi_json,
        manifest_json,
        now_unix,
    )?;
    encode_synq_admission_carrier(&envelope)
}

pub fn build_deploy_admission_carrier_from_pqsynq_bytes_with_artifacts_and_constructor_args(
    chain_id: u64,
    network_id: &str,
    encoded_pqsynq_envelope: &[u8],
    bytecode: Vec<u8>,
    abi_json: String,
    manifest_json: String,
    constructor_args: Vec<u8>,
    now_unix: u64,
) -> Result<Vec<u8>, SynQAdmissionError> {
    let envelope =
        build_deploy_admission_envelope_from_pqsynq_bytes_with_artifacts_and_constructor_args(
            chain_id,
            network_id,
            encoded_pqsynq_envelope,
            bytecode,
            abi_json,
            manifest_json,
            constructor_args,
            now_unix,
        )?;
    encode_synq_admission_carrier(&envelope)
}

pub fn build_deploy_admission_carrier_from_pqsynq_bytes_with_artifacts_and_sts9_verification(
    chain_id: u64,
    network_id: &str,
    encoded_pqsynq_envelope: &[u8],
    bytecode: Vec<u8>,
    abi_json: String,
    manifest_json: String,
    sts9_verification_json: String,
    now_unix: u64,
) -> Result<Vec<u8>, SynQAdmissionError> {
    let envelope =
        build_deploy_admission_envelope_from_pqsynq_bytes_with_artifacts_and_sts9_verification(
            chain_id,
            network_id,
            encoded_pqsynq_envelope,
            bytecode,
            abi_json,
            manifest_json,
            sts9_verification_json,
            now_unix,
        )?;
    encode_synq_admission_carrier(&envelope)
}

pub fn build_call_admission_carrier_from_pqsynq_bytes(
    chain_id: u64,
    network_id: &str,
    encoded_pqsynq_envelope: &[u8],
    now_unix: u64,
) -> Result<Vec<u8>, SynQAdmissionError> {
    let envelope = build_call_admission_envelope_from_pqsynq_bytes(
        chain_id,
        network_id,
        encoded_pqsynq_envelope,
        now_unix,
    )?;
    encode_synq_admission_carrier(&envelope)
}

pub fn build_call_admission_carrier_from_pqsynq_bytes_with_args(
    chain_id: u64,
    network_id: &str,
    encoded_pqsynq_envelope: &[u8],
    encoded_args: Vec<u8>,
    now_unix: u64,
) -> Result<Vec<u8>, SynQAdmissionError> {
    let envelope = build_call_admission_envelope_from_pqsynq_bytes_with_args(
        chain_id,
        network_id,
        encoded_pqsynq_envelope,
        encoded_args,
        now_unix,
    )?;
    encode_synq_admission_carrier(&envelope)
}

/// The canonical public identity of a SynQ envelope signer.
///
/// Derived from the envelope's own ML-DSA-87 public key, so the value the
/// carrier advertises, the value the signature verifies against, and the value
/// the AIVM presents as `msg.sender` are one address that cannot disagree.
pub fn canonical_signer_address(public_key: &[u8]) -> Result<String, SynQAdmissionError> {
    crate::address::derive_standard_account_address(public_key).map_err(|error| {
        SynQAdmissionError::InvalidCarrier {
            code: "AEGIS-ADDRESS",
            message: format!("canonical signer address derivation failed: {error}"),
        }
    })
}

/// Resolves an ML-DSA SynQ signer to its FN-DSA-rooted native identity. New
/// SNTS v1.3 carriers must use this binding-aware path; an operational key is
/// never itself an address derivation preimage.
pub fn canonical_signer_address_from_binding(
    binding: &crate::identity_auth::IdentityAuthorizationBinding,
    public_key: &[u8],
    required_purpose: &str,
) -> Result<String, SynQAdmissionError> {
    canonical_signer_address_from_binding_at(
        binding,
        public_key,
        required_purpose,
        wall_clock_unix_timestamp(),
    )
}

pub fn canonical_signer_address_from_binding_at(
    binding: &crate::identity_auth::IdentityAuthorizationBinding,
    public_key: &[u8],
    required_purpose: &str,
    consensus_timestamp_unix: u64,
) -> Result<String, SynQAdmissionError> {
    crate::identity_auth::identity_address_for_authorization_key_in_context_at(
        binding,
        "ML-DSA-87",
        public_key,
        crate::identity_auth::SYNQ_ADMISSION_AUTHORIZATION_DOMAIN,
        crate::synergy_types::SYNERGY_TESTNET_V3_CHAIN_ID,
        crate::synergy_types::SYNERGY_TESTNET_V3_NETWORK_ID,
        required_purpose,
        consensus_timestamp_unix,
    )
    .map_err(|error| SynQAdmissionError::InvalidCarrier {
        code: "AEGIS-AUTH-BINDING",
        message: format!("SynQ signer authorization binding failed: {error}"),
    })
}

pub fn canonical_signer_address_from_carrier(
    carrier: &IdentityAuthorizationBindingCarrier,
    public_key: &[u8],
    required_purpose: &str,
) -> Result<String, SynQAdmissionError> {
    canonical_signer_address_from_carrier_at(
        carrier,
        public_key,
        required_purpose,
        wall_clock_unix_timestamp(),
    )
}

pub fn canonical_signer_address_from_carrier_at(
    carrier: &IdentityAuthorizationBindingCarrier,
    public_key: &[u8],
    required_purpose: &str,
    consensus_timestamp_unix: u64,
) -> Result<String, SynQAdmissionError> {
    carrier
        .identity_address_for_key_in_context_at(
            crate::identity_auth::SYNQ_ADMISSION_AUTHORIZATION_DOMAIN,
            crate::synergy_types::SYNERGY_TESTNET_V3_CHAIN_ID,
            crate::synergy_types::SYNERGY_TESTNET_V3_NETWORK_ID,
            "ML-DSA-87",
            public_key,
            required_purpose,
            consensus_timestamp_unix,
        )
        .map_err(|error| SynQAdmissionError::InvalidCarrier {
            code: "AEGIS-AUTH-BINDING",
            message: format!("SynQ signer authorization carrier failed: {error}"),
        })
}

fn authorized_envelope_signer(
    envelope: &SynQAdmissionEnvelope,
    public_key: &[u8],
    consensus_timestamp_unix: u64,
) -> Result<String, SynQAdmissionError> {
    let carrier = envelope.identity_authorization.as_ref().ok_or(
        SynQAdmissionError::MissingRequiredField {
            field: "identity_authorization",
        },
    )?;
    let required_purpose = match envelope.kind {
        SynQAdmissionKind::Deploy => SYNQ_DEPLOY_AUTHORIZATION_PURPOSE,
        SynQAdmissionKind::Call => SYNQ_CALL_AUTHORIZATION_PURPOSE,
    };
    if envelope.authorization_purpose != required_purpose {
        return Err(SynQAdmissionError::InvalidCarrier {
            code: "AEGIS-CANON",
            message: format!(
                "SynQ {:?} authorization purpose must be {required_purpose}",
                envelope.kind
            ),
        });
    }
    canonical_signer_address_from_carrier_at(
        carrier,
        public_key,
        required_purpose,
        consensus_timestamp_unix,
    )
}

/// `tsynq…` was an internal execution-signer identifier rendered with an
/// address-like prefix. It is retired on Testnet-v3 and must never appear as a
/// signer, caller or authority.
fn reject_retired_signer_format(signer: &str) -> Result<(), SynQAdmissionError> {
    if signer.starts_with("tsynq") {
        return Err(SynQAdmissionError::InvalidCarrier {
            code: "AEGIS-ADDRESS",
            message: "tsynq signer addresses are not accepted on Testnet-v3; use the canonical syna Standard Account address".to_string(),
        });
    }
    Ok(())
}

#[derive(Debug, Clone, Copy)]
enum IdentityBindingAuthority<'a> {
    FinalizedSnapshot,
    ExactCurrentHash(&'a str),
    OfflineCreation,
}

fn require_current_identity_binding(
    carrier: &IdentityAuthorizationBindingCarrier,
    authority: IdentityBindingAuthority<'_>,
) -> Result<(), SynQAdmissionError> {
    let current_hash = match authority {
        IdentityBindingAuthority::FinalizedSnapshot => {
            crate::execution::finalized_identity_authorization_binding_hash(
                &carrier.binding.identity_address,
            )
            .map_err(|error| SynQAdmissionError::InvalidCarrier {
                code: "AEGIS-AUTH-BINDING",
                message: error,
            })?
        }
        IdentityBindingAuthority::ExactCurrentHash(hash) => hash.to_string(),
        IdentityBindingAuthority::OfflineCreation => return Ok(()),
    };
    crate::identity_auth::require_canonical_current_binding(&carrier.binding, &current_hash)
        .map_err(|error| SynQAdmissionError::InvalidCarrier {
            code: "AEGIS-AUTH-BINDING",
            message: format!("SynQ signer canonical binding check failed: {error}"),
        })
}

pub fn verify_transaction_payload_for_chain_admission(
    tx: &Transaction,
    now_unix: u64,
) -> Result<Option<SynQVerificationSummary>, SynQAdmissionError> {
    verify_transaction_payload(tx, now_unix, IdentityBindingAuthority::FinalizedSnapshot)
}

pub fn verify_transaction_payload_for_chain_admission_at_current_binding(
    tx: &Transaction,
    now_unix: u64,
    canonical_binding_payload_sha3_256: &str,
) -> Result<Option<SynQVerificationSummary>, SynQAdmissionError> {
    verify_transaction_payload(
        tx,
        now_unix,
        IdentityBindingAuthority::ExactCurrentHash(canonical_binding_payload_sha3_256),
    )
}

pub fn verify_transaction_payload_for_offline_creation(
    tx: &Transaction,
    now_unix: u64,
) -> Result<Option<SynQVerificationSummary>, SynQAdmissionError> {
    verify_transaction_payload(tx, now_unix, IdentityBindingAuthority::OfflineCreation)
}

fn verify_transaction_payload(
    tx: &Transaction,
    now_unix: u64,
    authority: IdentityBindingAuthority<'_>,
) -> Result<Option<SynQVerificationSummary>, SynQAdmissionError> {
    let Some(envelope) = decode_synq_admission_carrier(&tx.payload)? else {
        return Ok(None);
    };
    if envelope.chain_id != tx.chain_id.0 {
        return Err(SynQAdmissionError::NetworkMismatch {
            chain_id: envelope.chain_id,
            network_id: envelope.network_id,
        });
    }
    if envelope.network_id != tx.network_id.0
        && normalize_synq_network(envelope.chain_id, &envelope.network_id)?.pqsynq_network_id
            != normalize_synq_network(tx.chain_id.0, &tx.network_id.0)?.pqsynq_network_id
    {
        return Err(SynQAdmissionError::NetworkMismatch {
            chain_id: envelope.chain_id,
            network_id: envelope.network_id,
        });
    }
    verify_synq_carrier(&envelope, now_unix, authority).map(Some)
}

pub fn verify_synq_carrier_for_chain_admission(
    envelope: &SynQAdmissionEnvelope,
    now_unix: u64,
) -> Result<SynQVerificationSummary, SynQAdmissionError> {
    verify_synq_carrier(
        envelope,
        now_unix,
        IdentityBindingAuthority::FinalizedSnapshot,
    )
}

pub fn verify_synq_carrier_for_chain_admission_at_current_binding(
    envelope: &SynQAdmissionEnvelope,
    now_unix: u64,
    canonical_binding_payload_sha3_256: &str,
) -> Result<SynQVerificationSummary, SynQAdmissionError> {
    verify_synq_carrier(
        envelope,
        now_unix,
        IdentityBindingAuthority::ExactCurrentHash(canonical_binding_payload_sha3_256),
    )
}

pub fn verify_synq_carrier_for_offline_creation(
    envelope: &SynQAdmissionEnvelope,
    now_unix: u64,
) -> Result<SynQVerificationSummary, SynQAdmissionError> {
    verify_synq_carrier(
        envelope,
        now_unix,
        IdentityBindingAuthority::OfflineCreation,
    )
}

fn verify_synq_carrier(
    envelope: &SynQAdmissionEnvelope,
    now_unix: u64,
    authority: IdentityBindingAuthority<'_>,
) -> Result<SynQVerificationSummary, SynQAdmissionError> {
    match envelope.kind {
        SynQAdmissionKind::Deploy => verify_synq_deploy(envelope, now_unix, authority),
        SynQAdmissionKind::Call => verify_synq_call(envelope, now_unix, authority),
    }
}

pub fn verify_synq_deploy_for_chain_admission(
    envelope: &SynQAdmissionEnvelope,
    now_unix: u64,
) -> Result<SynQVerificationSummary, SynQAdmissionError> {
    verify_synq_deploy(
        envelope,
        now_unix,
        IdentityBindingAuthority::FinalizedSnapshot,
    )
}

pub fn verify_synq_deploy_for_chain_admission_at_current_binding(
    envelope: &SynQAdmissionEnvelope,
    now_unix: u64,
    canonical_binding_payload_sha3_256: &str,
) -> Result<SynQVerificationSummary, SynQAdmissionError> {
    verify_synq_deploy(
        envelope,
        now_unix,
        IdentityBindingAuthority::ExactCurrentHash(canonical_binding_payload_sha3_256),
    )
}

pub fn verify_synq_deploy_for_offline_creation(
    envelope: &SynQAdmissionEnvelope,
    now_unix: u64,
) -> Result<SynQVerificationSummary, SynQAdmissionError> {
    verify_synq_deploy(
        envelope,
        now_unix,
        IdentityBindingAuthority::OfflineCreation,
    )
}

fn verify_synq_deploy(
    envelope: &SynQAdmissionEnvelope,
    now_unix: u64,
    authority: IdentityBindingAuthority<'_>,
) -> Result<SynQVerificationSummary, SynQAdmissionError> {
    validate_synq_envelope_precrypto_bounds(envelope)?;
    ensure_version(envelope)?;
    ensure_kind(envelope, SynQAdmissionKind::Deploy)?;
    reject_retired_signer_format(&envelope.signer)?;
    ensure_required_hash(envelope.bytecode_hash, "bytecode_hash")?;
    ensure_required_hash(envelope.manifest_hash, "manifest_hash")?;
    ensure_required_hash(envelope.abi_hash, "abi_hash")?;
    let normalized = normalize_synq_network(envelope.chain_id, &envelope.network_id)?;
    let deploy: ContractDeployEnvelope = decode_pqsynq_envelope(
        &envelope.encoded_pqsynq_envelope,
        "decode SynQ deploy envelope",
    )?;
    let carrier = envelope.identity_authorization.as_ref().ok_or(
        SynQAdmissionError::MissingRequiredField {
            field: "identity_authorization",
        },
    )?;
    require_current_identity_binding(carrier, authority)?;
    let authorized_signer =
        authorized_envelope_signer(envelope, &deploy.public_key.bytes, now_unix)?;
    let context = pqsynq_context(envelope.chain_id, &normalized.pqsynq_network_id, now_unix);
    let verified = AegisSynQVerifier::testnet_1266()
        .verify_contract_deploy(&deploy, &context)
        .map_err(pqsynq_error)?;

    let bytecode_hash = envelope
        .bytecode_hash
        .expect("checked required bytecode_hash");
    let manifest_hash = envelope
        .manifest_hash
        .expect("checked required manifest_hash");
    let abi_hash = envelope.abi_hash.expect("checked required abi_hash");
    if deploy.signing_payload.payload_hash != envelope.payload_hash
        || verified.bytecode_hash != bytecode_hash
        || verified.manifest_hash != manifest_hash
        || verified.abi_hash != abi_hash
        || authorized_signer != envelope.signer
    {
        return Err(SynQAdmissionError::InvalidCarrier {
            code: "AEGIS-CANON",
            message: "SynQ deploy carrier fields do not match verified aegis-pqsynq envelope"
                .to_string(),
        });
    }
    validate_attached_deploy_artifacts(envelope)?;
    validate_constructor_args_hash(envelope, &deploy)?;
    validate_sts9_deploy_gate(envelope)?;

    Ok(summary_from_payload(
        envelope,
        &normalized,
        deploy.signing_payload.domain_tag,
        deploy.signing_payload.algorithm_id,
    ))
}

pub fn verify_synq_call_for_chain_admission(
    envelope: &SynQAdmissionEnvelope,
    now_unix: u64,
) -> Result<SynQVerificationSummary, SynQAdmissionError> {
    verify_synq_call(
        envelope,
        now_unix,
        IdentityBindingAuthority::FinalizedSnapshot,
    )
}

pub fn verify_synq_call_for_chain_admission_at_current_binding(
    envelope: &SynQAdmissionEnvelope,
    now_unix: u64,
    canonical_binding_payload_sha3_256: &str,
) -> Result<SynQVerificationSummary, SynQAdmissionError> {
    verify_synq_call(
        envelope,
        now_unix,
        IdentityBindingAuthority::ExactCurrentHash(canonical_binding_payload_sha3_256),
    )
}

pub fn verify_synq_call_for_offline_creation(
    envelope: &SynQAdmissionEnvelope,
    now_unix: u64,
) -> Result<SynQVerificationSummary, SynQAdmissionError> {
    verify_synq_call(
        envelope,
        now_unix,
        IdentityBindingAuthority::OfflineCreation,
    )
}

fn verify_synq_call(
    envelope: &SynQAdmissionEnvelope,
    now_unix: u64,
    authority: IdentityBindingAuthority<'_>,
) -> Result<SynQVerificationSummary, SynQAdmissionError> {
    validate_synq_envelope_precrypto_bounds(envelope)?;
    ensure_version(envelope)?;
    ensure_kind(envelope, SynQAdmissionKind::Call)?;
    reject_retired_signer_format(&envelope.signer)?;
    let normalized = normalize_synq_network(envelope.chain_id, &envelope.network_id)?;
    let call: ContractCallEnvelope = decode_pqsynq_envelope(
        &envelope.encoded_pqsynq_envelope,
        "decode SynQ call envelope",
    )?;
    let carrier = envelope.identity_authorization.as_ref().ok_or(
        SynQAdmissionError::MissingRequiredField {
            field: "identity_authorization",
        },
    )?;
    require_current_identity_binding(carrier, authority)?;
    let authorized_signer = authorized_envelope_signer(envelope, &call.public_key.bytes, now_unix)?;
    let context = pqsynq_context(envelope.chain_id, &normalized.pqsynq_network_id, now_unix);
    AegisSynQVerifier::testnet_1266()
        .verify_contract_call(&call, &context)
        .map_err(pqsynq_error)?;

    if call.signing_payload.payload_hash != envelope.payload_hash
        || authorized_signer != envelope.signer
    {
        return Err(SynQAdmissionError::InvalidCarrier {
            code: "AEGIS-CANON",
            message: "SynQ call carrier fields do not match verified aegis-pqsynq envelope"
                .to_string(),
        });
    }
    validate_call_args_hash(envelope, &call)?;

    Ok(summary_from_payload(
        envelope,
        &normalized,
        call.signing_payload.domain_tag,
        call.signing_payload.algorithm_id,
    ))
}

fn decode_pqsynq_envelope<T: for<'de> Deserialize<'de>>(
    bytes: &[u8],
    context: &'static str,
) -> Result<T, SynQAdmissionError> {
    if bytes.is_empty() {
        return Err(SynQAdmissionError::MissingRequiredField {
            field: "encoded_pqsynq_envelope",
        });
    }
    if bytes.len() > MAX_SYNQ_ENCODED_PQSYNQ_ENVELOPE_BYTES {
        return Err(SynQAdmissionError::InvalidCarrier {
            code: "SYNQ-CARRIER-SIZE",
            message: format!(
                "SynQ encoded aegis-pqsynq envelope exceeds {MAX_SYNQ_ENCODED_PQSYNQ_ENVELOPE_BYTES} bytes"
            ),
        });
    }
    serde_json::from_slice(bytes).map_err(|error| SynQAdmissionError::Decode {
        code: "AEGIS-CANON",
        message: format!("{context}: {error}"),
    })
}

fn attach_deploy_artifacts(
    envelope: &mut SynQAdmissionEnvelope,
    bytecode: Vec<u8>,
    abi_json: String,
    manifest_json: String,
) -> Result<(), SynQAdmissionError> {
    ensure_kind(envelope, SynQAdmissionKind::Deploy)?;
    ensure_artifact_size("bytecode", bytecode.len(), MAX_SYNQ_DEPLOY_BYTECODE_BYTES)?;
    ensure_artifact_size("abi_json", abi_json.len(), MAX_SYNQ_DEPLOY_ABI_JSON_BYTES)?;
    ensure_artifact_size(
        "manifest_json",
        manifest_json.len(),
        MAX_SYNQ_DEPLOY_MANIFEST_JSON_BYTES,
    )?;
    let bytecode_hash = sha256_array(&bytecode);
    let abi_hash = sha256_array(abi_json.as_bytes());
    let manifest_hash = sha256_array(manifest_json.as_bytes());
    if envelope.bytecode_hash != Some(bytecode_hash)
        || envelope.abi_hash != Some(abi_hash)
        || envelope.manifest_hash != Some(manifest_hash)
    {
        return Err(SynQAdmissionError::InvalidCarrier {
            code: "AEGIS-CANON",
            message:
                "SynQ deploy artifact bytes do not match the verified aegis-pqsynq hash envelope"
                    .to_string(),
        });
    }
    envelope.bytecode = Some(bytecode);
    envelope.abi_json = Some(abi_json);
    envelope.manifest_json = Some(manifest_json);
    Ok(())
}

fn attach_call_args(
    envelope: &mut SynQAdmissionEnvelope,
    encoded_args: Vec<u8>,
) -> Result<(), SynQAdmissionError> {
    ensure_kind(envelope, SynQAdmissionKind::Call)?;
    ensure_artifact_size("encoded_args", encoded_args.len(), MAX_SYNQ_CALL_ARGS_BYTES)?;
    envelope.encoded_args = if encoded_args.is_empty() {
        None
    } else {
        Some(encoded_args)
    };
    Ok(())
}

fn attach_constructor_args(
    envelope: &mut SynQAdmissionEnvelope,
    constructor_args: Vec<u8>,
) -> Result<(), SynQAdmissionError> {
    ensure_kind(envelope, SynQAdmissionKind::Deploy)?;
    ensure_artifact_size(
        "constructor_args",
        constructor_args.len(),
        MAX_SYNQ_CONSTRUCTOR_ARGS_BYTES,
    )?;
    envelope.constructor_args = if constructor_args.is_empty() {
        None
    } else {
        Some(constructor_args)
    };
    Ok(())
}

fn attach_sts9_verification(
    envelope: &mut SynQAdmissionEnvelope,
    sts9_verification_json: String,
) -> Result<(), SynQAdmissionError> {
    ensure_kind(envelope, SynQAdmissionKind::Deploy)?;
    ensure_artifact_size(
        "sts9_verification_json",
        sts9_verification_json.len(),
        MAX_STS9_VERIFICATION_JSON_BYTES,
    )?;
    envelope.sts9_verification_json = Some(sts9_verification_json);
    Ok(())
}

fn ensure_artifact_size(
    field: &'static str,
    actual: usize,
    max: usize,
) -> Result<(), SynQAdmissionError> {
    if actual <= max {
        Ok(())
    } else {
        Err(SynQAdmissionError::InvalidCarrier {
            code: "SYNQ-ARTIFACT-SIZE",
            message: format!(
                "SynQ deploy {field} is {actual} bytes, exceeding testnet limit {max}"
            ),
        })
    }
}

fn validate_attached_deploy_artifacts(
    envelope: &SynQAdmissionEnvelope,
) -> Result<(), SynQAdmissionError> {
    let any_artifact = envelope.bytecode.is_some()
        || envelope.abi_json.is_some()
        || envelope.manifest_json.is_some();
    if !any_artifact {
        return Ok(());
    }

    let bytecode = envelope
        .bytecode
        .as_ref()
        .ok_or_else(artifact_availability_error)?;
    let abi_json = envelope
        .abi_json
        .as_ref()
        .ok_or_else(artifact_availability_error)?;
    let manifest_json = envelope
        .manifest_json
        .as_ref()
        .ok_or_else(artifact_availability_error)?;

    ensure_artifact_size("bytecode", bytecode.len(), MAX_SYNQ_DEPLOY_BYTECODE_BYTES)?;
    ensure_artifact_size("abi_json", abi_json.len(), MAX_SYNQ_DEPLOY_ABI_JSON_BYTES)?;
    ensure_artifact_size(
        "manifest_json",
        manifest_json.len(),
        MAX_SYNQ_DEPLOY_MANIFEST_JSON_BYTES,
    )?;

    if envelope.bytecode_hash != Some(sha256_array(bytecode))
        || envelope.abi_hash != Some(sha256_array(abi_json.as_bytes()))
        || envelope.manifest_hash != Some(sha256_array(manifest_json.as_bytes()))
    {
        return Err(SynQAdmissionError::InvalidCarrier {
            code: "AEGIS-CANON",
            message:
                "SynQ deploy artifact bytes do not match the verified aegis-pqsynq hash envelope"
                    .to_string(),
        });
    }

    Ok(())
}

fn validate_call_args_hash(
    envelope: &SynQAdmissionEnvelope,
    call: &ContractCallEnvelope,
) -> Result<(), SynQAdmissionError> {
    let encoded_args = envelope.encoded_args.as_deref().unwrap_or(&[]);
    ensure_artifact_size("encoded_args", encoded_args.len(), MAX_SYNQ_CALL_ARGS_BYTES)?;
    if sha256_array(encoded_args) != call.encoded_args_hash {
        return Err(SynQAdmissionError::InvalidCarrier {
            code: "AEGIS-CANON",
            message:
                "SynQ call encoded_args bytes do not match the verified aegis-pqsynq args hash"
                    .to_string(),
        });
    }
    Ok(())
}

fn validate_constructor_args_hash(
    envelope: &SynQAdmissionEnvelope,
    deploy: &ContractDeployEnvelope,
) -> Result<(), SynQAdmissionError> {
    let constructor_args = envelope.constructor_args.as_deref().unwrap_or(&[]);
    ensure_artifact_size(
        "constructor_args",
        constructor_args.len(),
        MAX_SYNQ_CONSTRUCTOR_ARGS_BYTES,
    )?;
    if sha256_array(constructor_args) != deploy.constructor_args_hash {
        return Err(SynQAdmissionError::InvalidCarrier {
            code: "AEGIS-CANON",
            message:
                "SynQ deploy constructor_args bytes do not match the verified aegis-pqsynq args hash"
                    .to_string(),
        });
    }
    Ok(())
}

fn validate_sts9_deploy_gate(envelope: &SynQAdmissionEnvelope) -> Result<(), SynQAdmissionError> {
    let Some(manifest_json) = envelope.manifest_json.as_deref() else {
        return Ok(());
    };
    let manifest: serde_json::Value =
        serde_json::from_str(manifest_json).map_err(|error| SynQAdmissionError::Decode {
            code: "SYNQ-MANIFEST",
            message: format!("decode SynQ manifest for STS-9 gate: {error}"),
        })?;
    let contract_name = manifest
        .get("contract_name")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default();
    let declares_sts9 = manifest
        .get("standard_id")
        .and_then(serde_json::Value::as_str)
        == Some("STS-9")
        || manifest.get("sts9").is_some();
    if contract_name != STS9_HORIZON_CONTRACT_NAME && !declares_sts9 {
        return Ok(());
    }
    if contract_name != STS9_HORIZON_CONTRACT_NAME {
        return Err(SynQAdmissionError::InvalidCarrier {
            code: "STS9-VERIFY",
            message: format!(
                "STS-9 deploy gate currently accepts only {STS9_HORIZON_CONTRACT_NAME}, found {contract_name}"
            ),
        });
    }
    let verification_json = envelope.sts9_verification_json.as_deref().ok_or_else(|| {
        SynQAdmissionError::InvalidCarrier {
            code: "STS9-VERIFY",
            message: "STS-9 Horizon deploy requires an attached verification artifact".to_string(),
        }
    })?;
    ensure_artifact_size(
        "sts9_verification_json",
        verification_json.len(),
        MAX_STS9_VERIFICATION_JSON_BYTES,
    )?;
    let verification: serde_json::Value =
        serde_json::from_str(verification_json).map_err(|error| SynQAdmissionError::Decode {
            code: "STS9-VERIFY",
            message: format!("decode STS-9 verification artifact: {error}"),
        })?;
    validate_sts9_horizon_verification(envelope, &manifest, &verification)
}

fn validate_sts9_horizon_verification(
    envelope: &SynQAdmissionEnvelope,
    manifest: &serde_json::Value,
    verification: &serde_json::Value,
) -> Result<(), SynQAdmissionError> {
    let deploy: ContractDeployEnvelope = decode_pqsynq_envelope(
        &envelope.encoded_pqsynq_envelope,
        "decode SynQ deploy envelope for STS-9 verification",
    )?;
    let contract_address = synergy_contract_address_from_pqsynq_address(
        &derive_synq_contract_address_from_deploy_for_admission(&deploy)?,
    )?;
    let signer = envelope.signer.clone();

    expect_str_any(
        verification,
        &[&["contract_name"], &["contract", "name"]],
        STS9_HORIZON_CONTRACT_NAME,
    )?;
    expect_str_any(
        verification,
        &[&["standard_id"], &["token", "standard_id"]],
        "STS-9",
    )?;
    expect_str_any(
        verification,
        &[&["standard_version"], &["token", "standard_version"]],
        "1.0",
    )?;
    expect_str_any(
        verification,
        &[&["token_tier"], &["token", "tier"]],
        "synb1",
    )?;
    expect_str_any(
        verification,
        &[&["token_name"], &["token", "name"]],
        "Horizon Token",
    )?;
    expect_str_any(
        verification,
        &[&["token_symbol"], &["token", "symbol"]],
        "HRZN",
    )?;
    expect_u64_any(
        verification,
        &[&["chain_id"], &["network", "chain_id"]],
        1266,
    )?;
    expect_str_any(
        verification,
        &[&["network_id"], &["network", "network_id"]],
        SYNQ_CANONICAL_TESTNET_NETWORK_ID,
    )?;
    expect_u64_any(verification, &[&["decimals"], &["token", "decimals"]], 9)?;
    expect_str_any(
        verification,
        &[
            &["initial_supply_base_units"],
            &["genesis", "initial_supply_base_units"],
        ],
        STS9_HORIZON_SUPPLY_BASE_UNITS,
    )?;
    expect_str_any(
        verification,
        &[
            &["max_supply_base_units"],
            &["genesis", "max_supply_base_units"],
        ],
        STS9_HORIZON_SUPPLY_BASE_UNITS,
    )?;
    expect_str_any(
        verification,
        &[&["deployer_wallet"], &["wallets", "deployer"]],
        STS9_HORIZON_DEPLOYER_WALLET,
    )?;
    expect_str_any(
        verification,
        &[&["issuer_address"], &["wallets", "issuer"]],
        STS9_HORIZON_DEPLOYER_WALLET,
    )?;
    expect_str_any(
        verification,
        &[&["genesis_recipient"], &["wallets", "genesis_recipient"]],
        STS9_HORIZON_DEPLOYER_WALLET,
    )?;
    expect_str_any(
        verification,
        &[&["initial_holder"], &["wallets", "initial_holder"]],
        STS9_HORIZON_DEPLOYER_WALLET,
    )?;
    expect_str_any(
        verification,
        &[&["synq_signer"], &["signer", "synq_address"]],
        &signer,
    )?;
    expect_str_any(
        verification,
        &[&["contract_address"], &["contract", "address"]],
        &contract_address,
    )?;
    expect_str_any(
        verification,
        &[&["verification_status"], &["verification", "status"]],
        "verified",
    )?;
    expect_bool_any(
        verification,
        &[
            &["mintable_after_genesis"],
            &["token", "mintable_after_genesis"],
        ],
        false,
    )?;
    expect_bool_any(verification, &[&["burnable"], &["token", "burnable"]], true)?;
    expect_bool_any(
        verification,
        &[&["pausable"], &["token", "pausable"]],
        false,
    )?;
    expect_bool_any(
        verification,
        &[&["native_asset"], &["classification", "native_asset"]],
        false,
    )?;
    expect_bool_any(
        verification,
        &[
            &["official_native_asset"],
            &["classification", "official_native_asset"],
        ],
        false,
    )?;
    expect_bool_any(
        verification,
        &[
            &["no_other_genesis_allocations"],
            &["genesis", "no_other_allocations"],
        ],
        true,
    )?;

    validate_sts9_hash_binding(envelope, verification)?;
    validate_sts9_manifest_binding(manifest)?;
    validate_sts9_abi_binding(envelope)?;
    validate_sts9_metadata_binding(verification)?;
    Ok(())
}

fn validate_sts9_hash_binding(
    envelope: &SynQAdmissionEnvelope,
    verification: &serde_json::Value,
) -> Result<(), SynQAdmissionError> {
    let bytecode_hash = hex::encode(
        envelope
            .bytecode_hash
            .expect("checked deploy bytecode hash before STS-9 gate"),
    );
    let manifest_hash = hex::encode(
        envelope
            .manifest_hash
            .expect("checked deploy manifest hash before STS-9 gate"),
    );
    let abi_hash = hex::encode(
        envelope
            .abi_hash
            .expect("checked deploy ABI hash before STS-9 gate"),
    );
    expect_str_any(
        verification,
        &[&["bytecode_hash"], &["hashes", "bytecode"]],
        &bytecode_hash,
    )?;
    expect_str_any(
        verification,
        &[&["manifest_hash"], &["hashes", "manifest"]],
        &manifest_hash,
    )?;
    expect_str_any(
        verification,
        &[&["abi_hash"], &["hashes", "abi"]],
        &abi_hash,
    )?;

    if let Some(value) = lookup_any(
        verification,
        &[&["artifact_hash"], &["verification", "artifact_hash"]],
    ) {
        let expected = value
            .as_str()
            .ok_or_else(|| invalid_sts9("artifact_hash must be a string"))?;
        if expected.len() != 64 || !expected.chars().all(|ch| ch.is_ascii_hexdigit()) {
            return Err(invalid_sts9(
                "artifact_hash must be a lowercase SHA-256 hex string",
            ));
        }
        let actual = sts9_artifact_hash_without_hash_field(verification)?;
        if !expected.eq_ignore_ascii_case(&actual) {
            return Err(invalid_sts9(format!(
                "artifact_hash mismatch: expected {expected}, computed {actual}"
            )));
        }
    }
    Ok(())
}

fn validate_sts9_manifest_binding(manifest: &serde_json::Value) -> Result<(), SynQAdmissionError> {
    let contract_name = manifest
        .get("contract_name")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default();
    if contract_name != STS9_HORIZON_CONTRACT_NAME {
        return Err(invalid_sts9(format!(
            "manifest contract_name must be {STS9_HORIZON_CONTRACT_NAME}"
        )));
    }
    let chain_id = manifest
        .get("required_chain_id")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or_default();
    if chain_id != 1266 {
        return Err(invalid_sts9("manifest required_chain_id must be 1266"));
    }
    let network_id = manifest
        .get("required_network_id")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default();
    if network_id != SYNQ_CANONICAL_TESTNET_NETWORK_ID {
        return Err(invalid_sts9(format!(
            "manifest required_network_id must be {SYNQ_CANONICAL_TESTNET_NETWORK_ID}"
        )));
    }
    let algorithm = manifest
        .get("required_signature_algorithm")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default();
    let required = parse_account_domain_algorithm(algorithm)?;
    if !SynQSecurityPolicy::testnet_1266_policy()
        .allowed_deploy_signature_algorithms
        .contains(&required)
    {
        return Err(invalid_sts9(&format!(
            "manifest required_signature_algorithm {} is not admissible in the account/deploy/call domain",
            algorithm_name(required)
        )));
    }
    Ok(())
}

/// Resolves a manifest's `required_signature_algorithm` label to an algorithm.
///
/// Fails closed on unknown labels, and rejects the other domains by name so the
/// error says *why* rather than "unknown algorithm": ML-DSA-65 is validator
/// consensus and FN-DSA-1024 is the Synergy identity/address and SXCP relayer
/// domain. Neither may authorize a deploy or a call. Labels are matched
/// exactly — no aliasing, no silent relabelling.
fn parse_account_domain_algorithm(label: &str) -> Result<AlgorithmId, SynQAdmissionError> {
    match label {
        "ML-DSA-87" => Ok(AlgorithmId::MlDsa87),
        "ML-DSA-65" => Err(invalid_sts9(
            "manifest required_signature_algorithm ML-DSA-65 is the validator consensus domain and cannot authorize a SynQ deploy or call",
        )),
        "FN-DSA" | "FN-DSA-1024" => Err(invalid_sts9(
            "manifest required_signature_algorithm FN-DSA-1024 is the Synergy identity/address domain and cannot authorize a SynQ deploy or call",
        )),
        other => Err(invalid_sts9(&format!(
            "manifest required_signature_algorithm `{other}` is not a recognized signature algorithm"
        ))),
    }
}

fn validate_sts9_abi_binding(envelope: &SynQAdmissionEnvelope) -> Result<(), SynQAdmissionError> {
    let abi_json = envelope
        .abi_json
        .as_deref()
        .ok_or_else(|| invalid_sts9("STS-9 gate requires attached ABI JSON"))?;
    let abi: serde_json::Value =
        serde_json::from_str(abi_json).map_err(|error| SynQAdmissionError::Decode {
            code: "SYNQ-ABI",
            message: format!("decode SynQ ABI for STS-9 gate: {error}"),
        })?;
    expect_str_any(&abi, &[&["contract"]], STS9_HORIZON_CONTRACT_NAME)?;

    let methods = abi
        .get("methods")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| invalid_sts9("STS-9 ABI methods must be an array"))?;
    for required in [
        "name",
        "symbol",
        "decimals",
        "max_supply",
        "total_supply",
        "circulating_supply",
        "balance_of",
        "transfer",
        "approve",
        "allowance",
        "transfer_from",
        "metadata_uri",
        "metadata_hash",
        "issuer_address",
        "verification_status",
        "burn",
    ] {
        let found = methods
            .iter()
            .any(|method| method.get("name").and_then(serde_json::Value::as_str) == Some(required));
        if !found {
            return Err(invalid_sts9(format!(
                "STS-9 ABI is missing required method {required}"
            )));
        }
    }

    let events = abi
        .get("events")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| invalid_sts9("STS-9 ABI events must be an array"))?;
    for required in [
        "Transfer",
        "Approval",
        "Burn",
        "MetadataUpdated",
        "VerificationStatusChanged",
    ] {
        let found = events
            .iter()
            .any(|event| event.get("name").and_then(serde_json::Value::as_str) == Some(required));
        if !found {
            return Err(invalid_sts9(format!(
                "STS-9 ABI is missing required event {required}"
            )));
        }
    }
    Ok(())
}

fn validate_sts9_metadata_binding(
    verification: &serde_json::Value,
) -> Result<(), SynQAdmissionError> {
    if let Some(metadata) = lookup_any(verification, &[&["canonical_metadata"], &["metadata"]]) {
        let metadata_hash = sha256_hex_json(metadata)?;
        expect_str_any(
            verification,
            &[&["metadata_hash"], &["metadata", "hash"]],
            &metadata_hash,
        )?;
    }
    if let Some(attestation) =
        lookup_any(verification, &[&["issuer_attestation"], &["attestation"]])
    {
        let attestation_hash = sha256_hex_json(attestation)?;
        expect_str_any(
            verification,
            &[&["issuer_attestation_hash"], &["attestation", "hash"]],
            &attestation_hash,
        )?;
    }
    Ok(())
}

fn expect_str_any(
    value: &serde_json::Value,
    paths: &[&[&str]],
    expected: &str,
) -> Result<(), SynQAdmissionError> {
    let actual = lookup_any(value, paths)
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| invalid_sts9(format!("missing string field {}", format_paths(paths))))?;
    if actual == expected {
        Ok(())
    } else {
        Err(invalid_sts9(format!(
            "{} must be {expected}, found {actual}",
            format_paths(paths)
        )))
    }
}

fn expect_bool_any(
    value: &serde_json::Value,
    paths: &[&[&str]],
    expected: bool,
) -> Result<(), SynQAdmissionError> {
    let actual = lookup_any(value, paths)
        .and_then(serde_json::Value::as_bool)
        .ok_or_else(|| invalid_sts9(format!("missing boolean field {}", format_paths(paths))))?;
    if actual == expected {
        Ok(())
    } else {
        Err(invalid_sts9(format!(
            "{} must be {expected}, found {actual}",
            format_paths(paths)
        )))
    }
}

fn expect_u64_any(
    value: &serde_json::Value,
    paths: &[&[&str]],
    expected: u64,
) -> Result<(), SynQAdmissionError> {
    let actual = lookup_any(value, paths)
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| invalid_sts9(format!("missing integer field {}", format_paths(paths))))?;
    if actual == expected {
        Ok(())
    } else {
        Err(invalid_sts9(format!(
            "{} must be {expected}, found {actual}",
            format_paths(paths)
        )))
    }
}

fn lookup_any<'a>(
    value: &'a serde_json::Value,
    paths: &[&[&str]],
) -> Option<&'a serde_json::Value> {
    paths.iter().find_map(|path| lookup_path(value, path))
}

fn lookup_path<'a>(value: &'a serde_json::Value, path: &[&str]) -> Option<&'a serde_json::Value> {
    let mut current = value;
    for segment in path {
        current = current.get(*segment)?;
    }
    Some(current)
}

fn format_paths(paths: &[&[&str]]) -> String {
    paths
        .iter()
        .map(|path| path.join("."))
        .collect::<Vec<_>>()
        .join("|")
}

fn invalid_sts9(message: impl Into<String>) -> SynQAdmissionError {
    SynQAdmissionError::InvalidCarrier {
        code: "STS9-VERIFY",
        message: message.into(),
    }
}

fn sha256_hex_json(value: &serde_json::Value) -> Result<String, SynQAdmissionError> {
    let bytes = serde_json::to_vec(value).map_err(|error| SynQAdmissionError::Decode {
        code: "STS9-VERIFY",
        message: format!("canonicalize STS-9 JSON for hash: {error}"),
    })?;
    Ok(hex::encode(sha256_array(&bytes)))
}

fn sts9_artifact_hash_without_hash_field(
    value: &serde_json::Value,
) -> Result<String, SynQAdmissionError> {
    let mut clone = value.clone();
    if let Some(object) = clone.as_object_mut() {
        object.remove("artifact_hash");
        if let Some(verification) = object
            .get_mut("verification")
            .and_then(serde_json::Value::as_object_mut)
        {
            verification.remove("artifact_hash");
        }
    }
    sha256_hex_json(&clone)
}

fn derive_synq_contract_address_from_deploy_for_admission(
    deploy: &ContractDeployEnvelope,
) -> Result<SynQAddress, SynQAdmissionError> {
    if deploy.signing_payload.domain_tag != DomainTag::SynqContractDeployV1
        || deploy.signing_payload.signature_purpose != SignaturePurpose::ContractDeploy
    {
        return Err(invalid_sts9(
            "SynQ contract address derivation requires a deploy signing payload",
        ));
    }
    let network_id = deploy
        .signing_payload
        .network_id
        .numeric_id()
        .map_err(|error| {
            invalid_sts9(format!(
                "contract address network derivation failed: {error}"
            ))
        })?;
    let chain_id = deploy.signing_payload.chain_id.0;
    if chain_id > u16::MAX as u64 {
        return Err(invalid_sts9(format!(
            "contract address derivation requires u16 chain id, found {chain_id}"
        )));
    }

    let mut material = Vec::new();
    push_u64(&mut material, chain_id);
    push_string(&mut material, deploy.signing_payload.network_id.as_str());
    push_u16(&mut material, deploy.signing_payload.protocol_version);
    push_u16(&mut material, deploy.signing_payload.algorithm_id.code());
    push_u64(&mut material, deploy.signing_payload.nonce);
    push_bytes(
        &mut material,
        deploy.signing_payload.signer_address.as_bytes(),
    );
    push_bytes(&mut material, &deploy.signing_payload.payload_hash);
    push_bytes(&mut material, &deploy.bytecode_hash);
    push_bytes(&mut material, &deploy.manifest_hash);
    push_bytes(&mut material, &deploy.abi_hash);
    push_bytes(&mut material, &deploy.constructor_args_hash);

    let digest = Hash::from_domain_bytes(SYNQ_CONTRACT_ADDRESS_DERIVATION_DOMAIN, &material);
    let mut bytes = [0_u8; SYNQ_ADDRESS_LEN];
    bytes[0] = SYNQ_CONTRACT_ADDRESS_VERSION;
    bytes[1..3].copy_from_slice(&network_id.to_be_bytes());
    bytes[3..5].copy_from_slice(&SYNQ_CONTRACT_ADDRESS_CLASS.to_be_bytes());
    bytes[5..37].copy_from_slice(&digest.0);
    let checksum = sha256_array(&bytes[..37]);
    bytes[37..41].copy_from_slice(&checksum[..4]);

    Ok(SynQAddress::from_bytes(bytes))
}

fn synergy_contract_address_from_pqsynq_address(
    address: &SynQAddress,
) -> Result<String, SynQAdmissionError> {
    crate::address::generate_generic_address(
        SYNERGY_CUSTOM_CONTRACT_ADDRESS_PREFIX,
        &hex::encode(address.as_bytes()),
    )
    .map_err(|error| SynQAdmissionError::InvalidCarrier {
        code: "AEGIS-ADDRESS",
        message: format!("synergy contract address derivation failed: {error}"),
    })
}

fn push_u16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn push_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn push_string(out: &mut Vec<u8>, value: &str) {
    push_bytes(out, value.as_bytes());
}

fn push_bytes(out: &mut Vec<u8>, value: &[u8]) {
    out.extend_from_slice(&(value.len() as u64).to_be_bytes());
    out.extend_from_slice(value);
}

fn artifact_availability_error() -> SynQAdmissionError {
    SynQAdmissionError::InvalidCarrier {
        code: "SYNQ-ARTIFACT-AVAILABILITY",
        message: "SynQ deploy artifact availability requires bytecode, ABI, and manifest together"
            .to_string(),
    }
}

fn sha256_array(bytes: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};

    let digest = Sha256::digest(bytes);
    let mut out = [0_u8; 32];
    out.copy_from_slice(&digest);
    out
}

fn pqsynq_context(chain_id: u64, network_id: &str, now_unix: u64) -> VerificationContext {
    VerificationContext {
        chain_id: ChainId(chain_id),
        network_id: NetworkId(network_id.to_string()),
        now_unix,
        policy: SynQSecurityPolicy::testnet_1266_policy(),
    }
}

fn pqsynq_error(error: pqsynq::AegisSynQError) -> SynQAdmissionError {
    SynQAdmissionError::PqSynQ {
        code: error.code(),
        message: error.to_string(),
    }
}

fn summary_from_payload(
    envelope: &SynQAdmissionEnvelope,
    normalized: &NormalizedSynQNetwork,
    domain: DomainTag,
    algorithm: AlgorithmId,
) -> SynQVerificationSummary {
    SynQVerificationSummary {
        chain_id: envelope.chain_id,
        normalized_network_id: normalized.pqsynq_network_id.clone(),
        node_network_id: normalized.node_network_id.clone(),
        domain: domain.as_str().to_string(),
        algorithm: algorithm_name(algorithm).to_string(),
        signer: envelope.signer.clone(),
        identity_authorization_payload_sha3_256: envelope
            .identity_authorization
            .as_ref()
            .map(|carrier| carrier.binding.binding_payload_sha3_256.clone()),
        payload_hash: envelope.payload_hash,
        bytecode_hash: envelope.bytecode_hash,
        manifest_hash: envelope.manifest_hash,
        abi_hash: envelope.abi_hash,
        verified_at_admission: true,
    }
}

fn algorithm_name(algorithm: AlgorithmId) -> &'static str {
    match algorithm {
        AlgorithmId::MlDsa44 => "ML-DSA-44",
        AlgorithmId::MlDsa65 => "ML-DSA-65",
        AlgorithmId::MlDsa87 => "ML-DSA-87",
        AlgorithmId::SlhDsaSha2_128s => "SLH-DSA-SHA2-128s",
        AlgorithmId::SlhDsaSha2_192s => "SLH-DSA-SHA2-192s",
        AlgorithmId::SlhDsaSha2_256s => "SLH-DSA-SHA2-256s",
        AlgorithmId::FnDsa => "FN-DSA",
        AlgorithmId::Hqc128 => "HQC-128",
        AlgorithmId::Hqc192 => "HQC-192",
        AlgorithmId::Hqc256 => "HQC-256",
        AlgorithmId::ClassicMcEliece348864 => "Classic-McEliece-348864",
    }
}

fn ensure_version(envelope: &SynQAdmissionEnvelope) -> Result<(), SynQAdmissionError> {
    if envelope.version == SYNQ_ADMISSION_VERSION {
        Ok(())
    } else {
        Err(SynQAdmissionError::UnsupportedVersion {
            found: envelope.version,
        })
    }
}

fn ensure_kind(
    envelope: &SynQAdmissionEnvelope,
    expected: SynQAdmissionKind,
) -> Result<(), SynQAdmissionError> {
    if envelope.kind == expected {
        Ok(())
    } else {
        Err(SynQAdmissionError::UnsupportedKind {
            expected,
            found: envelope.kind,
        })
    }
}

fn ensure_required_hash(
    value: Option<[u8; 32]>,
    field: &'static str,
) -> Result<(), SynQAdmissionError> {
    if value.is_some() {
        Ok(())
    } else {
        Err(SynQAdmissionError::MissingRequiredField { field })
    }
}

#[cfg(test)]
pub(crate) mod test_support {
    use super::*;
    use pqsynq::{
        canonicalize_signing_payload, derive_synq_address, hash_contract_call_body,
        hash_contract_deploy_body, DigitalSignature, Sign, SignaturePurpose, SynQAddress,
        SynQPublicKey, SynQSignature, SynQSigningPayload,
    };

    pub(crate) const TEST_NOW: u64 = 1_800_000_000;

    pub(crate) fn hash(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    pub(crate) fn deploy_carrier(network_id: &str) -> SynQAdmissionEnvelope {
        deploy_carrier_with_constructor_args(network_id, Vec::new())
    }

    pub(crate) fn deploy_carrier_with_constructor_args(
        network_id: &str,
        constructor_args: Vec<u8>,
    ) -> SynQAdmissionEnvelope {
        let (public_key, private_key, signer) = test_identity();
        let bytecode_hash = hash(1);
        let manifest_hash = hash(2);
        let abi_hash = hash(3);
        let constructor_args_hash = sha256_array(&constructor_args);
        let payload_hash = hash_contract_deploy_body(
            &bytecode_hash,
            &manifest_hash,
            &abi_hash,
            signer.as_bytes(),
            &constructor_args_hash,
        );
        let signing_payload = signing_payload(
            DomainTag::SynqContractDeployV1,
            SignaturePurpose::ContractDeploy,
            signer,
            payload_hash,
            41,
        );
        let signature = sign_payload(&signing_payload, &private_key);
        let deploy = ContractDeployEnvelope {
            signing_payload,
            public_key,
            signature: SynQSignature::new(signature),
            bytecode_hash,
            manifest_hash,
            abi_hash,
            constructor_args_hash,
        };
        let identity_authorization = test_identity_authorization(
            &deploy.public_key.bytes,
            &private_key,
            SYNQ_DEPLOY_AUTHORIZATION_PURPOSE,
        );
        let identity_address = identity_authorization.binding.identity_address.clone();

        SynQAdmissionEnvelope {
            version: SYNQ_ADMISSION_VERSION,
            kind: SynQAdmissionKind::Deploy,
            chain_id: SYNERGY_TESTNET_V3_CHAIN_ID,
            network_id: network_id.to_string(),
            signer: identity_address,
            identity_authorization: Some(identity_authorization),
            authorization_purpose: SYNQ_DEPLOY_AUTHORIZATION_PURPOSE.to_string(),
            payload_hash,
            bytecode_hash: Some(bytecode_hash),
            manifest_hash: Some(manifest_hash),
            abi_hash: Some(abi_hash),
            encoded_pqsynq_envelope: serde_json::to_vec(&deploy).unwrap(),
            bytecode: None,
            abi_json: None,
            manifest_json: None,
            constructor_args: (!constructor_args.is_empty()).then_some(constructor_args),
            encoded_args: None,
            sts9_verification_json: None,
        }
    }

    pub(crate) fn call_carrier(network_id: &str) -> SynQAdmissionEnvelope {
        let (public_key, private_key, signer) = test_identity();
        let contract_address = signer;
        let method_selector = [0x58, 0x42, 0xf1, 0xbe];
        let encoded_args_hash = sha256_array(&[]);
        let payload_hash = hash_contract_call_body(
            contract_address.as_bytes(),
            &method_selector,
            &encoded_args_hash,
            signer.as_bytes(),
        );
        let signing_payload = signing_payload(
            DomainTag::SynqContractCallV1,
            SignaturePurpose::ContractCall,
            signer,
            payload_hash,
            42,
        );
        let signature = sign_payload(&signing_payload, &private_key);
        let call = ContractCallEnvelope {
            signing_payload,
            public_key,
            signature: SynQSignature::new(signature),
            contract_address,
            method_selector,
            encoded_args_hash,
        };
        let identity_authorization = test_identity_authorization(
            &call.public_key.bytes,
            &private_key,
            SYNQ_CALL_AUTHORIZATION_PURPOSE,
        );
        let identity_address = identity_authorization.binding.identity_address.clone();

        SynQAdmissionEnvelope {
            version: SYNQ_ADMISSION_VERSION,
            kind: SynQAdmissionKind::Call,
            chain_id: SYNERGY_TESTNET_V3_CHAIN_ID,
            network_id: network_id.to_string(),
            signer: identity_address,
            identity_authorization: Some(identity_authorization),
            authorization_purpose: SYNQ_CALL_AUTHORIZATION_PURPOSE.to_string(),
            payload_hash,
            bytecode_hash: None,
            manifest_hash: None,
            abi_hash: None,
            encoded_pqsynq_envelope: serde_json::to_vec(&call).unwrap(),
            bytecode: None,
            abi_json: None,
            manifest_json: None,
            constructor_args: None,
            encoded_args: None,
            sts9_verification_json: None,
        }
    }

    fn test_identity() -> (SynQPublicKey, Vec<u8>, SynQAddress) {
        let signer = Sign::mldsa87();
        let (public_key, private_key) = signer.keygen().expect("ML-DSA-87 keygen");
        let public_key = SynQPublicKey::new(public_key);
        let address = derive_synq_address(
            &public_key,
            AlgorithmId::MlDsa87,
            &NetworkId(SYNQ_CANONICAL_TESTNET_NETWORK_ID.to_string()),
        )
        .expect("derive SynQ address");
        (public_key, private_key, address)
    }

    fn test_identity_authorization(
        authorization_public_key: &[u8],
        authorization_private_key: &[u8],
        authorization_purpose: &str,
    ) -> IdentityAuthorizationBindingCarrier {
        let mut manager = crate::crypto::pqc::PQCManager::new();
        let (identity_public, identity_private) = manager
            .generate_keypair(crate::crypto::pqc::PQCAlgorithm::FNDSA)
            .expect("test identity keypair");
        let authorization_public = crate::crypto::pqc::PQCPublicKey {
            algorithm: crate::crypto::pqc::PQCAlgorithm::MLDSA87,
            key_data: authorization_public_key.to_vec(),
            key_id: "test-synq-authorization".to_string(),
            created_at: 0,
        };
        let authorization_private = crate::crypto::pqc::PQCPrivateKey {
            algorithm: crate::crypto::pqc::PQCAlgorithm::MLDSA87,
            key_data: authorization_private_key.to_vec(),
            public_key_id: authorization_public.key_id.clone(),
            created_at: 0,
        };
        let binding = crate::identity_auth::create_single_key_binding_with_scopes(
            "test-synq-identity",
            "syna",
            &identity_public,
            &identity_private,
            "synq-key",
            &authorization_public,
            &authorization_private,
            &[crate::identity_auth::AuthorizationScope::testnet(
                crate::identity_auth::SYNQ_ADMISSION_AUTHORIZATION_DOMAIN,
                authorization_purpose,
            )],
            "2026-08-22T00:00:00Z",
        )
        .expect("test SynQ identity authorization binding");
        IdentityAuthorizationBindingCarrier::new(
            crate::identity_auth::SYNQ_ADMISSION_AUTHORIZATION_DOMAIN,
            binding,
        )
        .expect("test SynQ identity authorization carrier")
    }

    fn signing_payload(
        domain_tag: DomainTag,
        signature_purpose: SignaturePurpose,
        signer_address: SynQAddress,
        payload_hash: [u8; 32],
        nonce: u64,
    ) -> SynQSigningPayload {
        SynQSigningPayload {
            domain_tag,
            chain_id: ChainId(SYNERGY_TESTNET_V3_CHAIN_ID),
            network_id: NetworkId(SYNQ_CANONICAL_TESTNET_NETWORK_ID.to_string()),
            protocol_version: 1,
            algorithm_id: AlgorithmId::MlDsa87,
            signature_purpose,
            nonce,
            not_before_unix: 0,
            expiration_unix: 4_102_444_800,
            signer_address,
            payload_hash,
        }
    }

    fn sign_payload(payload: &SynQSigningPayload, private_key: &[u8]) -> Vec<u8> {
        let canonical = canonicalize_signing_payload(payload).expect("canonical payload");
        Sign::mldsa87()
            .detached_sign(&canonical, private_key)
            .expect("ML-DSA-65 sign")
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::*;
    use super::*;

    #[test]
    fn network_alias_normalization_accepts_testnet_names_for_chain_1266() {
        let canonical = normalize_synq_network(
            SYNERGY_TESTNET_V3_CHAIN_ID,
            SYNQ_CANONICAL_TESTNET_NETWORK_ID,
        )
        .expect("canonical testnet accepted");
        assert_eq!(
            canonical.pqsynq_network_id,
            SYNQ_CANONICAL_TESTNET_NETWORK_ID
        );

        let node_alias =
            normalize_synq_network(SYNERGY_TESTNET_V3_CHAIN_ID, SYNERGY_TESTNET_V3_NETWORK_ID)
                .expect("node testnet alias accepted");
        assert_eq!(
            node_alias.pqsynq_network_id,
            SYNQ_CANONICAL_TESTNET_NETWORK_ID
        );
    }

    #[test]
    fn network_alias_normalization_rejects_wrong_chain_and_unrelated_network() {
        let wrong_chain = normalize_synq_network(999, SYNQ_CANONICAL_TESTNET_NETWORK_ID)
            .expect_err("wrong chain rejected");
        assert_eq!(wrong_chain.code(), "AEGIS-CHAIN");

        let wrong_network = normalize_synq_network(SYNERGY_TESTNET_V3_CHAIN_ID, "mainnet")
            .expect_err("wrong network rejected");
        assert_eq!(wrong_network.code(), "AEGIS-NETWORK");
    }

    #[test]
    fn synq_deploy_carrier_verifies_through_pqsynq() {
        let summary = verify_synq_deploy_for_offline_creation(
            &deploy_carrier(SYNERGY_TESTNET_V3_NETWORK_ID),
            TEST_NOW,
        )
        .expect("SynQ deploy carrier verified");
        assert_eq!(summary.domain, "SYNQ_CONTRACT_DEPLOY_V1");
        assert_eq!(summary.algorithm, "ML-DSA-87");
        assert!(summary.verified_at_admission);
        assert_eq!(summary.bytecode_hash, Some(hash(1)));
    }

    #[test]
    fn synq_chain_admission_requires_exact_current_binding_commitment() {
        let carrier = deploy_carrier(SYNERGY_TESTNET_V3_NETWORK_ID);
        let current_hash = carrier
            .identity_authorization
            .as_ref()
            .expect("test carrier")
            .binding
            .binding_payload_sha3_256
            .clone();
        verify_synq_deploy_for_chain_admission_at_current_binding(
            &carrier,
            TEST_NOW,
            &current_hash,
        )
        .expect("exact finalized binding commitment admits");
        let error = verify_synq_deploy_for_chain_admission_at_current_binding(
            &carrier,
            TEST_NOW,
            &"00".repeat(32),
        )
        .expect_err("stale carrier must not pass canonical-current admission");
        assert_eq!(error.code(), "AEGIS-AUTH-BINDING");
    }

    /// The account domain (deploy/call) must reject every other domain's
    /// algorithm by name, and fail closed on anything unrecognized. A manifest
    /// is attacker-influenced input, so a permissive parse here would let a
    /// consensus or identity key authorize a deployment.
    #[test]
    fn manifest_signature_algorithm_rejects_other_cryptographic_domains() {
        let consensus = parse_account_domain_algorithm("ML-DSA-65")
            .expect_err("ML-DSA-65 is the validator consensus domain");
        assert!(
            format!("{consensus:?}").contains("consensus domain"),
            "rejection must name the domain, got {consensus:?}"
        );

        for identity_label in ["FN-DSA", "FN-DSA-1024"] {
            let identity = parse_account_domain_algorithm(identity_label)
                .expect_err("FN-DSA is the Synergy identity/address domain");
            assert!(
                format!("{identity:?}").contains("identity/address domain"),
                "rejection must name the domain, got {identity:?}"
            );
        }

        for unknown in [
            "",
            "ML-DSA-44",
            "mldsa87",
            "ml-dsa-87",
            "Ed25519",
            "ML-KEM-1024",
        ] {
            assert!(
                parse_account_domain_algorithm(unknown).is_err(),
                "`{unknown}` must fail closed — labels are matched exactly, never aliased"
            );
        }

        assert_eq!(
            parse_account_domain_algorithm("ML-DSA-87").expect("account domain"),
            AlgorithmId::MlDsa87
        );
    }

    #[test]
    fn non_empty_constructor_args_are_hash_bound_and_tamper_evident() {
        let args = br#"["authority","6"]"#.to_vec();
        let carrier =
            deploy_carrier_with_constructor_args(SYNERGY_TESTNET_V3_NETWORK_ID, args.clone());
        verify_synq_deploy_for_offline_creation(&carrier, TEST_NOW)
            .expect("non-empty constructor args verify");

        let mut tampered = carrier;
        tampered.constructor_args = Some(br#"["authority","7"]"#.to_vec());
        let error = verify_synq_deploy_for_offline_creation(&tampered, TEST_NOW)
            .expect_err("constructor argument tampering rejected");
        assert_eq!(error.code(), "AEGIS-CANON");
    }

    #[test]
    fn synq_call_carrier_verifies_through_pqsynq() {
        let summary = verify_synq_call_for_offline_creation(
            &call_carrier(SYNERGY_TESTNET_V3_NETWORK_ID),
            TEST_NOW,
        )
        .expect("SynQ call carrier verified");
        assert_eq!(summary.domain, "SYNQ_CONTRACT_CALL_V1");
        assert_eq!(summary.algorithm, "ML-DSA-87");
        assert!(summary.verified_at_admission);
    }

    #[test]
    fn wrong_chain_preserves_aegis_chain_code() {
        let mut carrier = deploy_carrier(SYNERGY_TESTNET_V3_NETWORK_ID);
        carrier.chain_id = 999;
        let error = verify_synq_deploy_for_offline_creation(&carrier, TEST_NOW)
            .expect_err("wrong chain rejected");
        assert_eq!(error.code(), "AEGIS-CHAIN");
    }

    #[test]
    fn malformed_carrier_preserves_canonicalization_code() {
        let error = decode_synq_admission_carrier(b"synq-admission-v1:{not-json")
            .expect_err("malformed carrier rejected");
        assert_eq!(error.code(), "AEGIS-CANON");
    }

    #[test]
    fn invalid_inner_signature_preserves_pqsynq_error_code() {
        let mut carrier = deploy_carrier(SYNERGY_TESTNET_V3_NETWORK_ID);
        let mut deploy: ContractDeployEnvelope =
            serde_json::from_slice(&carrier.encoded_pqsynq_envelope).unwrap();
        deploy.signature.bytes[0] ^= 0x01;
        carrier.encoded_pqsynq_envelope = serde_json::to_vec(&deploy).unwrap();

        let error = verify_synq_deploy_for_offline_creation(&carrier, TEST_NOW)
            .expect_err("invalid signature rejected");
        assert_eq!(error.code(), "AEGIS-SIG");
    }

    #[test]
    fn envelope_selected_authorization_purpose_is_rejected() {
        let mut deploy = deploy_carrier(SYNERGY_TESTNET_V3_NETWORK_ID);
        deploy.authorization_purpose = SYNQ_CALL_AUTHORIZATION_PURPOSE.to_string();
        let error = verify_synq_deploy_for_offline_creation(&deploy, TEST_NOW)
            .expect_err("deploy must not select the call authorization purpose");
        assert_eq!(error.code(), "AEGIS-CANON");

        let mut call = call_carrier(SYNERGY_TESTNET_V3_NETWORK_ID);
        call.authorization_purpose = SYNQ_DEPLOY_AUTHORIZATION_PURPOSE.to_string();
        let error = verify_synq_call_for_offline_creation(&call, TEST_NOW)
            .expect_err("call must not select the deploy authorization purpose");
        assert_eq!(error.code(), "AEGIS-CANON");
    }

    #[test]
    fn partial_deploy_artifacts_reject_at_admission() {
        let mut carrier = deploy_carrier(SYNERGY_TESTNET_V3_NETWORK_ID);
        carrier.bytecode = Some(Vec::new());

        let error = verify_synq_deploy_for_offline_creation(&carrier, TEST_NOW)
            .expect_err("partial artifacts must fail");
        assert_eq!(error.code(), "SYNQ-ARTIFACT-AVAILABILITY");
    }

    #[test]
    fn oversized_deploy_artifacts_reject_at_admission() {
        let mut carrier = deploy_carrier(SYNERGY_TESTNET_V3_NETWORK_ID);
        carrier.bytecode = Some(vec![0; MAX_SYNQ_DEPLOY_BYTECODE_BYTES + 1]);
        carrier.abi_json = Some(String::new());
        carrier.manifest_json = Some(String::new());

        let error = verify_synq_deploy_for_offline_creation(&carrier, TEST_NOW)
            .expect_err("oversized artifacts must fail");
        assert_eq!(error.code(), "SYNQ-ARTIFACT-SIZE");
    }

    #[test]
    fn oversized_inner_envelope_rejects_before_identity_crypto() {
        let mut carrier = deploy_carrier(SYNERGY_TESTNET_V3_NETWORK_ID);
        carrier.encoded_pqsynq_envelope = vec![0; MAX_SYNQ_ENCODED_PQSYNQ_ENVELOPE_BYTES + 1];
        let binding = &mut carrier
            .identity_authorization
            .as_mut()
            .expect("test identity carrier")
            .binding;
        binding.proofs.identity_root.signature.clear();
        binding.proofs.authorization_key_possession.clear();

        let error = verify_synq_deploy_for_offline_creation(&carrier, TEST_NOW)
            .expect_err("pre-crypto carrier bound must reject first");
        assert_eq!(error.code(), "SYNQ-CARRIER-SIZE");
    }

    #[test]
    fn pqsynq_deploy_bytes_wrap_into_versioned_admission_carrier() {
        let source = deploy_carrier(SYNERGY_TESTNET_V3_NETWORK_ID);
        let envelope =
            build_deploy_admission_envelope_from_pqsynq_bytes_with_identity_authorization(
                SYNERGY_TESTNET_V3_CHAIN_ID,
                SYNERGY_TESTNET_V3_NETWORK_ID,
                &source.encoded_pqsynq_envelope,
                source.identity_authorization.clone().expect("test carrier"),
                &source.authorization_purpose,
                TEST_NOW,
            )
            .expect("wrap deploy envelope");
        let bytes = encode_synq_admission_carrier(&envelope).expect("encode deploy carrier");
        let decoded = decode_synq_admission_carrier(&bytes)
            .expect("decode carrier")
            .expect("carrier present");
        assert_eq!(decoded.kind, SynQAdmissionKind::Deploy);
        assert_eq!(decoded.payload_hash, source.payload_hash);
        assert_eq!(decoded.bytecode_hash, source.bytecode_hash);
        assert_eq!(decoded.signer, source.signer);
    }

    #[test]
    fn pqsynq_call_bytes_wrap_into_versioned_admission_carrier() {
        let source = call_carrier(SYNERGY_TESTNET_V3_NETWORK_ID);
        let envelope = build_call_admission_envelope_from_pqsynq_bytes_with_identity_authorization(
            SYNERGY_TESTNET_V3_CHAIN_ID,
            SYNERGY_TESTNET_V3_NETWORK_ID,
            &source.encoded_pqsynq_envelope,
            source.identity_authorization.clone().expect("test carrier"),
            &source.authorization_purpose,
            TEST_NOW,
        )
        .expect("wrap call envelope");
        let bytes = encode_synq_admission_carrier(&envelope).expect("encode call carrier");
        let decoded = decode_synq_admission_carrier(&bytes)
            .expect("decode carrier")
            .expect("carrier present");
        assert_eq!(decoded.kind, SynQAdmissionKind::Call);
        assert_eq!(decoded.payload_hash, source.payload_hash);
        assert_eq!(decoded.signer, source.signer);
    }
}
