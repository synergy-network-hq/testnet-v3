//! Runtime verifier for canonical SNTS v1.3 identity/authorization bindings.
//!
//! Native addresses remain rooted exclusively in an FN-DSA-1024 identity key.
//! Operational signing keys authorize that identity only through a
//! dual-possession binding produced by the canonical Synergy Address Engine.

use crate::address::{decode_address, derive_key_controlled_address};
use crate::crypto::pqc::{PQCAlgorithm, PQCManager, PQCPrivateKey, PQCPublicKey, PQCSignature};
use crate::snts_registry::IdentifierClass;
use crate::synergy_types::{SYNERGY_TESTNET_V3_CHAIN_ID, SYNERGY_TESTNET_V3_NETWORK_ID};
use bincode::{Decode, Encode};
use chrono::DateTime;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha3::{Digest, Sha3_256};
use std::collections::BTreeMap;

pub const AUTH_BINDING_SCHEMA_VERSION: &str = "synergy-identity-authorization-binding-v1";
pub const AUTH_BINDING_BINARY_ENCODING: &str = "lowercase-hex";
pub const AUTH_BINDING_SIGNATURE_DOMAIN: &[u8] = b"SYNERGY_IDENTITY_AUTHORIZATION_BINDING_V1\0";
pub const IDENTITY_ROOT_ALGORITHM: &str = "FN-DSA-1024";
pub const AUTHORIZATION_CARRIER_SCHEMA_VERSION: u16 = 1;
pub const WALLET_TRANSACTION_AUTHORIZATION_DOMAIN: &str =
    "SYNERGY_WALLET_TRANSACTION_IDENTITY_AUTHORIZATION_V1";
pub const AEGIS_TRANSACTION_AUTHORIZATION_DOMAIN: &str =
    "SYNERGY_AEGIS_TRANSACTION_IDENTITY_AUTHORIZATION_V1";
pub const SYNQ_ADMISSION_AUTHORIZATION_DOMAIN: &str =
    "SYNERGY_SYNQ_ADMISSION_IDENTITY_AUTHORIZATION_V1";
pub const GENESIS_CEREMONY_AUTHORIZATION_DOMAIN: &str =
    "SYNERGY_GENESIS_CEREMONY_IDENTITY_AUTHORIZATION_V1";
const FN_DSA_1024_PUBLIC_KEY_BYTES: usize = 1_793;
const ML_DSA_65_PUBLIC_KEY_BYTES: usize = 1_952;
const ML_DSA_87_PUBLIC_KEY_BYTES: usize = 2_592;
const MAX_CARRIER_DOMAIN_BYTES: usize = 128;
const MAX_SCHEMA_LABEL_BYTES: usize = 128;
const MAX_ALGORITHM_LABEL_BYTES: usize = 64;
const MAX_IDENTITY_ID_BYTES: usize = 256;
const MAX_ADDRESS_BYTES: usize = 128;
const MAX_PRINCIPALS: usize = 64;
const MAX_PRINCIPAL_ID_BYTES: usize = 256;
const MAX_PURPOSES_PER_PRINCIPAL: usize = 32;
const MAX_PURPOSE_BYTES: usize = 128;
const MAX_AUTH_KEY_HISTORY: usize = 256;
const MAX_SUPERSESSION_HISTORY: usize = 256;
const MAX_REASON_BYTES: usize = 512;
const MAX_DERIVATION_STANDARD_BYTES: usize = 128;
const MAX_RFC3339_BYTES: usize = 64;
const MAX_CANONICAL_BINDING_PAYLOAD_BYTES: usize = 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
#[serde(rename_all = "kebab-case")]
pub enum AuthorizationPolicyType {
    SingleKey,
    Threshold,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
#[serde(rename_all = "kebab-case")]
pub enum PrincipalType {
    PublicKey,
    IdentityReference,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
#[serde(rename_all = "lowercase")]
pub enum BindingStatus {
    Active,
    Retired,
    Superseded,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
#[serde(deny_unknown_fields)]
pub struct IdentityRoot {
    pub algorithm: String,
    pub public_key: String,
    pub public_key_sha3_256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
#[serde(deny_unknown_fields)]
pub struct AuthorizationPrincipal {
    pub principal_id: String,
    pub principal_type: PrincipalType,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub algorithm: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_key_sha3_256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity_reference: Option<String>,
    pub status: BindingStatus,
    pub purposes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
#[serde(deny_unknown_fields)]
pub struct AuthorizationPolicy {
    pub policy_type: AuthorizationPolicyType,
    pub threshold: u32,
    pub principals: Vec<AuthorizationPrincipal>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
#[serde(deny_unknown_fields)]
pub struct AuthorizationScope {
    pub signature_domain: String,
    pub chain_id: u64,
    pub network_id: String,
    pub purpose: String,
}

impl AuthorizationScope {
    pub fn testnet(signature_domain: &str, purpose: &str) -> Self {
        Self {
            signature_domain: signature_domain.to_string(),
            chain_id: SYNERGY_TESTNET_V3_CHAIN_ID,
            network_id: SYNERGY_TESTNET_V3_NETWORK_ID.to_string(),
            purpose: purpose.to_string(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
#[serde(deny_unknown_fields)]
pub struct AuthKeyHistoryEntry {
    pub principal_id: String,
    pub algorithm: String,
    pub public_key_sha3_256: String,
    pub status: BindingStatus,
    pub retired_at: String,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
#[serde(deny_unknown_fields)]
pub struct SupersessionEntry {
    pub address: String,
    pub derivation_standard: String,
    pub status: BindingStatus,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
#[serde(deny_unknown_fields)]
pub struct SignatureProof {
    pub algorithm: String,
    pub signature: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
#[serde(deny_unknown_fields)]
pub struct AuthorizationKeyPossessionProof {
    pub principal_id: String,
    pub algorithm: String,
    pub signature: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
#[serde(deny_unknown_fields)]
pub struct BindingProofs {
    pub identity_root: SignatureProof,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub authorization_key_possession: Vec<AuthorizationKeyPossessionProof>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
#[serde(deny_unknown_fields)]
pub struct IdentityAuthorizationBinding {
    pub schema_version: String,
    pub binary_encoding: String,
    pub identity_id: String,
    pub identity_address: String,
    pub identity_root: IdentityRoot,
    pub authorization_policy: AuthorizationPolicy,
    #[serde(default)]
    pub authorization_scopes: Vec<AuthorizationScope>,
    pub current_auth_key_hash: Option<String>,
    pub auth_key_history: Vec<AuthKeyHistoryEntry>,
    pub supersession_history: Vec<SupersessionEntry>,
    pub effective_at: String,
    pub binding_payload_sha3_256: String,
    pub proofs: BindingProofs,
}

/// Explicit wire/storage carrier for an independently verified identity
/// authorization binding. The context domain prevents a valid binding copied
/// from one protocol carrier from being silently accepted in another.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
#[serde(deny_unknown_fields)]
pub struct IdentityAuthorizationCarrier {
    pub schema_version: u16,
    pub signature_domain: String,
    pub binding: IdentityAuthorizationBinding,
}

impl IdentityAuthorizationCarrier {
    pub fn new(
        signature_domain: &str,
        binding: IdentityAuthorizationBinding,
    ) -> Result<Self, String> {
        require_nonempty("identity authorization carrier domain", signature_domain)?;
        let carrier = Self {
            schema_version: AUTHORIZATION_CARRIER_SCHEMA_VERSION,
            signature_domain: signature_domain.to_string(),
            binding,
        };
        carrier.verify_context(signature_domain)?;
        Ok(carrier)
    }

    pub fn verify_context(&self, expected_domain: &str) -> Result<(), String> {
        self.verify_context_at(expected_domain, current_unix_timestamp())
    }

    pub fn verify_context_at(
        &self,
        expected_domain: &str,
        consensus_timestamp_unix: u64,
    ) -> Result<(), String> {
        if self.schema_version != AUTHORIZATION_CARRIER_SCHEMA_VERSION {
            return Err("unsupported identity authorization carrier schema version".to_string());
        }
        require_bounded_text(
            "identity authorization carrier domain",
            &self.signature_domain,
            MAX_CARRIER_DOMAIN_BYTES,
        )?;
        require_bounded_text(
            "expected identity authorization carrier domain",
            expected_domain,
            MAX_CARRIER_DOMAIN_BYTES,
        )?;
        if self.signature_domain != expected_domain {
            return Err(format!(
                "identity authorization carrier domain mismatch: expected '{expected_domain}', found '{}'",
                self.signature_domain
            ));
        }
        verify_binding_at(&self.binding, consensus_timestamp_unix)
    }

    pub fn identity_address_for_key(
        &self,
        expected_domain: &str,
        algorithm: &str,
        authorization_public_key: &[u8],
        required_purpose: &str,
    ) -> Result<String, String> {
        self.identity_address_for_key_at(
            expected_domain,
            algorithm,
            authorization_public_key,
            required_purpose,
            current_unix_timestamp(),
        )
    }

    pub fn identity_address_for_key_at(
        &self,
        expected_domain: &str,
        algorithm: &str,
        authorization_public_key: &[u8],
        required_purpose: &str,
        consensus_timestamp_unix: u64,
    ) -> Result<String, String> {
        self.identity_address_for_key_in_context_at(
            expected_domain,
            SYNERGY_TESTNET_V3_CHAIN_ID,
            SYNERGY_TESTNET_V3_NETWORK_ID,
            algorithm,
            authorization_public_key,
            required_purpose,
            consensus_timestamp_unix,
        )
    }

    /// Resolves an operational key only when its dual-possession binding also
    /// signed the exact protocol domain, chain, network, and purpose used by
    /// the verifier. This is suitable for offline creation and ceremony
    /// verification. Network admission must additionally compare the binding
    /// hash with finalized canonical identity state.
    #[allow(clippy::too_many_arguments)]
    pub fn identity_address_for_key_in_context_at(
        &self,
        expected_domain: &str,
        chain_id: u64,
        network_id: &str,
        algorithm: &str,
        authorization_public_key: &[u8],
        required_purpose: &str,
        consensus_timestamp_unix: u64,
    ) -> Result<String, String> {
        // A single envelope signature cannot satisfy a threshold policy. Check
        // the policy tag before binding verification so malformed threshold
        // carriers cannot force any post-quantum signature work on this path.
        require_single_signature_policy(&self.binding)?;
        self.verify_context_at(expected_domain, consensus_timestamp_unix)?;
        identity_address_for_authorization_key_in_context_at(
            &self.binding,
            algorithm,
            authorization_public_key,
            expected_domain,
            chain_id,
            network_id,
            required_purpose,
            consensus_timestamp_unix,
        )
    }

    /// Consensus admission variant. A self-contained carrier is never enough
    /// to prove freshness: the caller must supply the binding hash committed by
    /// finalized identity state for this exact identity address.
    #[allow(clippy::too_many_arguments)]
    pub fn identity_address_for_key_for_admission_at(
        &self,
        expected_domain: &str,
        chain_id: u64,
        network_id: &str,
        algorithm: &str,
        authorization_public_key: &[u8],
        required_purpose: &str,
        consensus_timestamp_unix: u64,
        canonical_binding_payload_sha3_256: &str,
    ) -> Result<String, String> {
        let address = self.identity_address_for_key_in_context_at(
            expected_domain,
            chain_id,
            network_id,
            algorithm,
            authorization_public_key,
            required_purpose,
            consensus_timestamp_unix,
        )?;
        require_canonical_current_binding(&self.binding, canonical_binding_payload_sha3_256)?;
        Ok(address)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RuntimeSignatureAlgorithm {
    FnDsa1024,
    MlDsa65,
    MlDsa87,
}

impl RuntimeSignatureAlgorithm {
    fn parse(value: &str) -> Result<Self, String> {
        match value {
            "FN-DSA-1024" => Ok(Self::FnDsa1024),
            "ML-DSA-65" => Ok(Self::MlDsa65),
            "ML-DSA-87" => Ok(Self::MlDsa87),
            _ => Err(format!(
                "unsupported runtime authorization algorithm '{value}'"
            )),
        }
    }

    const fn public_key_bytes(self) -> usize {
        match self {
            Self::FnDsa1024 => FN_DSA_1024_PUBLIC_KEY_BYTES,
            Self::MlDsa65 => ML_DSA_65_PUBLIC_KEY_BYTES,
            Self::MlDsa87 => ML_DSA_87_PUBLIC_KEY_BYTES,
        }
    }

    const fn pqc(self) -> PQCAlgorithm {
        match self {
            Self::FnDsa1024 => PQCAlgorithm::FNDSA,
            Self::MlDsa65 => PQCAlgorithm::MLDSA65,
            Self::MlDsa87 => PQCAlgorithm::MLDSA87,
        }
    }

    const fn canonical_name(self) -> &'static str {
        match self {
            Self::FnDsa1024 => "FN-DSA-1024",
            Self::MlDsa65 => "ML-DSA-65",
            Self::MlDsa87 => "ML-DSA-87",
        }
    }

    const fn signature_max_bytes(self) -> usize {
        match self {
            Self::FnDsa1024 => aegis_pqvm::pqc::signatures::fndsa::fndsa1024::signature_bytes(),
            Self::MlDsa65 => aegis_pqvm::pqc::signatures::mldsa::mldsa65::signature_bytes(),
            Self::MlDsa87 => aegis_pqvm::pqc::signatures::mldsa::mldsa87::signature_bytes(),
        }
    }

    fn from_pqc(algorithm: &PQCAlgorithm) -> Result<Self, String> {
        match algorithm {
            PQCAlgorithm::FNDSA => Ok(Self::FnDsa1024),
            PQCAlgorithm::MLDSA65 => Ok(Self::MlDsa65),
            PQCAlgorithm::MLDSA87 => Ok(Self::MlDsa87),
            _ => Err("identity authorization bindings require a signature key".to_string()),
        }
    }
}

fn require_nonempty(field: &str, value: &str) -> Result<(), String> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(format!(
            "{field} must be non-empty and contain no control characters"
        ));
    }
    Ok(())
}

fn require_bounded_text(field: &str, value: &str, max_bytes: usize) -> Result<(), String> {
    require_nonempty(field, value)?;
    if value.len() > max_bytes {
        return Err(format!("{field} exceeds the maximum of {max_bytes} bytes"));
    }
    Ok(())
}

fn require_max_len(field: &str, actual: usize, maximum: usize) -> Result<(), String> {
    if actual > maximum {
        return Err(format!(
            "{field} exceeds the maximum item count of {maximum}"
        ));
    }
    Ok(())
}

fn require_single_signature_policy(binding: &IdentityAuthorizationBinding) -> Result<(), String> {
    if binding.authorization_policy.policy_type != AuthorizationPolicyType::SingleKey {
        return Err(
            "single-signature admission requires a single-key authorization policy".to_string(),
        );
    }
    Ok(())
}

fn current_unix_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or_default()
}

fn decode_lower_hex(
    field: &str,
    value: &str,
    expected_bytes: Option<usize>,
) -> Result<Vec<u8>, String> {
    if value.is_empty()
        || !value.len().is_multiple_of(2)
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(format!(
            "{field} must be non-empty even-length lowercase hexadecimal"
        ));
    }
    if expected_bytes.is_some_and(|expected| value.len() != expected * 2) {
        return Err(format!("{field} has the wrong canonical byte length"));
    }
    hex::decode(value).map_err(|error| format!("decode {field}: {error}"))
}

fn lower_hex_32(field: &str, value: &str) -> Result<(), String> {
    decode_lower_hex(field, value, Some(32)).map(|_| ())
}

fn sha3_256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha3_256::digest(bytes))
}

fn write_canonical_json(value: &Value, output: &mut Vec<u8>) -> Result<(), String> {
    match value {
        Value::Null => output.extend_from_slice(b"null"),
        Value::Bool(true) => output.extend_from_slice(b"true"),
        Value::Bool(false) => output.extend_from_slice(b"false"),
        Value::Number(number) => {
            if number.as_i64().is_none() && number.as_u64().is_none() {
                return Err("canonical native JSON forbids fractional numbers".to_string());
            }
            output.extend_from_slice(number.to_string().as_bytes());
        }
        Value::String(string) => output.extend_from_slice(
            serde_json::to_string(string)
                .map_err(|error| format!("encode canonical JSON string: {error}"))?
                .as_bytes(),
        ),
        Value::Array(values) => {
            output.push(b'[');
            for (index, item) in values.iter().enumerate() {
                if index != 0 {
                    output.push(b',');
                }
                write_canonical_json(item, output)?;
            }
            output.push(b']');
        }
        Value::Object(object) => {
            output.push(b'{');
            let mut keys = object.keys().collect::<Vec<_>>();
            keys.sort_unstable();
            for (index, key) in keys.into_iter().enumerate() {
                if index != 0 {
                    output.push(b',');
                }
                output.extend_from_slice(
                    serde_json::to_string(key)
                        .map_err(|error| format!("encode canonical JSON key: {error}"))?
                        .as_bytes(),
                );
                output.push(b':');
                let item = object
                    .get(key)
                    .ok_or_else(|| "canonical JSON object changed during encoding".to_string())?;
                write_canonical_json(item, output)?;
            }
            output.push(b'}');
        }
    }
    Ok(())
}

fn validate_binding_bounds(binding: &IdentityAuthorizationBinding) -> Result<(), String> {
    require_bounded_text(
        "schema_version",
        &binding.schema_version,
        MAX_SCHEMA_LABEL_BYTES,
    )?;
    require_bounded_text(
        "binary_encoding",
        &binding.binary_encoding,
        MAX_SCHEMA_LABEL_BYTES,
    )?;
    require_bounded_text("identity_id", &binding.identity_id, MAX_IDENTITY_ID_BYTES)?;
    require_bounded_text(
        "identity_address",
        &binding.identity_address,
        MAX_ADDRESS_BYTES,
    )?;
    require_bounded_text("effective_at", &binding.effective_at, MAX_RFC3339_BYTES)?;
    require_max_len(
        "authorization_policy.principals",
        binding.authorization_policy.principals.len(),
        MAX_PRINCIPALS,
    )?;
    require_max_len(
        "authorization_scopes",
        binding.authorization_scopes.len(),
        MAX_PRINCIPALS * MAX_PURPOSES_PER_PRINCIPAL,
    )?;
    require_max_len(
        "auth_key_history",
        binding.auth_key_history.len(),
        MAX_AUTH_KEY_HISTORY,
    )?;
    require_max_len(
        "supersession_history",
        binding.supersession_history.len(),
        MAX_SUPERSESSION_HISTORY,
    )?;
    require_max_len(
        "authorization_key_possession proofs",
        binding.proofs.authorization_key_possession.len(),
        MAX_PRINCIPALS,
    )?;
    if binding.identity_root.public_key.len() > FN_DSA_1024_PUBLIC_KEY_BYTES * 2 {
        return Err("identity_root.public_key exceeds its canonical length".to_string());
    }
    require_bounded_text(
        "identity_root.algorithm",
        &binding.identity_root.algorithm,
        MAX_ALGORITHM_LABEL_BYTES,
    )?;
    if binding.identity_root.public_key_sha3_256.len() > 64 {
        return Err("identity_root.public_key_sha3_256 exceeds its canonical length".to_string());
    }
    if binding
        .current_auth_key_hash
        .as_ref()
        .is_some_and(|hash| hash.len() > 64)
    {
        return Err("current_auth_key_hash exceeds its canonical length".to_string());
    }
    if binding.binding_payload_sha3_256.len() > 64 {
        return Err("binding_payload_sha3_256 exceeds its canonical length".to_string());
    }
    require_bounded_text(
        "identity-root proof algorithm",
        &binding.proofs.identity_root.algorithm,
        MAX_ALGORITHM_LABEL_BYTES,
    )?;
    if binding.proofs.identity_root.signature.len()
        > RuntimeSignatureAlgorithm::FnDsa1024.signature_max_bytes() * 2
    {
        return Err("identity-root proof signature exceeds the maximum length".to_string());
    }
    for principal in &binding.authorization_policy.principals {
        require_bounded_text(
            "principal_id",
            &principal.principal_id,
            MAX_PRINCIPAL_ID_BYTES,
        )?;
        require_max_len(
            "principal purposes",
            principal.purposes.len(),
            MAX_PURPOSES_PER_PRINCIPAL,
        )?;
        for purpose in &principal.purposes {
            require_bounded_text("principal purpose", purpose, MAX_PURPOSE_BYTES)?;
        }
        if principal
            .public_key
            .as_ref()
            .is_some_and(|key| key.len() > ML_DSA_87_PUBLIC_KEY_BYTES * 2)
        {
            return Err("principal public_key exceeds the maximum canonical length".to_string());
        }
        if let Some(algorithm) = principal.algorithm.as_deref() {
            require_bounded_text("principal algorithm", algorithm, MAX_ALGORITHM_LABEL_BYTES)?;
        }
        if principal
            .public_key_sha3_256
            .as_ref()
            .is_some_and(|hash| hash.len() > 64)
        {
            return Err("principal public_key_sha3_256 exceeds its canonical length".to_string());
        }
        if principal
            .identity_reference
            .as_ref()
            .is_some_and(|reference| reference.len() > MAX_ADDRESS_BYTES)
        {
            return Err("principal identity_reference exceeds the maximum length".to_string());
        }
    }
    for scope in &binding.authorization_scopes {
        require_bounded_text(
            "authorization scope signature_domain",
            &scope.signature_domain,
            MAX_CARRIER_DOMAIN_BYTES,
        )?;
        require_bounded_text(
            "authorization scope network_id",
            &scope.network_id,
            MAX_ADDRESS_BYTES,
        )?;
        require_bounded_text(
            "authorization scope purpose",
            &scope.purpose,
            MAX_PURPOSE_BYTES,
        )?;
    }
    for proof in &binding.proofs.authorization_key_possession {
        require_bounded_text(
            "authorization proof principal_id",
            &proof.principal_id,
            MAX_PRINCIPAL_ID_BYTES,
        )?;
        require_bounded_text(
            "authorization proof algorithm",
            &proof.algorithm,
            MAX_ALGORITHM_LABEL_BYTES,
        )?;
        let algorithm = RuntimeSignatureAlgorithm::parse(&proof.algorithm)?;
        if proof.signature.len() > algorithm.signature_max_bytes() * 2 {
            return Err("authorization proof signature exceeds the maximum length".to_string());
        }
    }
    for history in &binding.auth_key_history {
        require_bounded_text(
            "auth_key_history.principal_id",
            &history.principal_id,
            MAX_PRINCIPAL_ID_BYTES,
        )?;
        require_bounded_text(
            "auth_key_history.algorithm",
            &history.algorithm,
            MAX_ALGORITHM_LABEL_BYTES,
        )?;
        if history.public_key_sha3_256.len() > 64 {
            return Err(
                "auth_key_history.public_key_sha3_256 exceeds its canonical length".to_string(),
            );
        }
        require_bounded_text(
            "auth_key_history.retired_at",
            &history.retired_at,
            MAX_RFC3339_BYTES,
        )?;
        require_bounded_text("auth_key_history.reason", &history.reason, MAX_REASON_BYTES)?;
    }
    for supersession in &binding.supersession_history {
        require_bounded_text(
            "supersession_history.address",
            &supersession.address,
            MAX_ADDRESS_BYTES,
        )?;
        require_bounded_text(
            "supersession_history.derivation_standard",
            &supersession.derivation_standard,
            MAX_DERIVATION_STANDARD_BYTES,
        )?;
        require_bounded_text(
            "supersession_history.reason",
            &supersession.reason,
            MAX_REASON_BYTES,
        )?;
    }
    Ok(())
}

pub fn canonical_binding_payload(
    binding: &IdentityAuthorizationBinding,
) -> Result<Vec<u8>, String> {
    validate_binding_bounds(binding)?;
    let mut value = serde_json::to_value(binding)
        .map_err(|error| format!("serialize authorization binding: {error}"))?;
    let object = value
        .as_object_mut()
        .ok_or_else(|| "authorization binding must serialize as an object".to_string())?;
    object.remove("binding_payload_sha3_256");
    object.remove("proofs");
    let mut output = Vec::new();
    write_canonical_json(&value, &mut output)?;
    if output.len() > MAX_CANONICAL_BINDING_PAYLOAD_BYTES {
        return Err(format!(
            "canonical identity authorization binding exceeds {MAX_CANONICAL_BINDING_PAYLOAD_BYTES} bytes"
        ));
    }
    Ok(output)
}

pub(crate) fn binding_signature_message(payload: &[u8]) -> Vec<u8> {
    let mut message = Vec::with_capacity(AUTH_BINDING_SIGNATURE_DOMAIN.len() + payload.len());
    message.extend_from_slice(AUTH_BINDING_SIGNATURE_DOMAIN);
    message.extend_from_slice(payload);
    message
}

/// Creates the canonical single-key dual-possession binding used by wallet
/// creation and offline ceremony tooling. Account identity is always rooted in
/// the FN-DSA-1024 public key; `authorization_public_key` is never an address
/// derivation preimage.
pub fn create_single_key_binding(
    identity_id: &str,
    address_hrp: &str,
    identity_public_key: &PQCPublicKey,
    identity_private_key: &PQCPrivateKey,
    authorization_principal_id: &str,
    authorization_public_key: &PQCPublicKey,
    authorization_private_key: &PQCPrivateKey,
    purpose: &str,
    effective_at: &str,
) -> Result<IdentityAuthorizationBinding, String> {
    create_single_key_binding_with_purposes(
        identity_id,
        address_hrp,
        identity_public_key,
        identity_private_key,
        authorization_principal_id,
        authorization_public_key,
        authorization_private_key,
        &[purpose],
        effective_at,
    )
}

pub fn create_single_key_binding_with_purposes(
    identity_id: &str,
    address_hrp: &str,
    identity_public_key: &PQCPublicKey,
    identity_private_key: &PQCPrivateKey,
    authorization_principal_id: &str,
    authorization_public_key: &PQCPublicKey,
    authorization_private_key: &PQCPrivateKey,
    purposes: &[&str],
    effective_at: &str,
) -> Result<IdentityAuthorizationBinding, String> {
    require_nonempty("identity_id", identity_id)?;
    require_nonempty("authorization principal id", authorization_principal_id)?;
    if purposes.is_empty() || purposes.len() > MAX_PURPOSES_PER_PRINCIPAL {
        return Err("single-key binding requires a bounded non-empty purpose set".to_string());
    }
    let mut canonical_purposes = purposes
        .iter()
        .map(|purpose| {
            require_bounded_text("authorization purpose", purpose, MAX_PURPOSE_BYTES)?;
            Ok((*purpose).to_string())
        })
        .collect::<Result<Vec<_>, String>>()?;
    canonical_purposes.sort();
    canonical_purposes.dedup();
    if canonical_purposes.len() != purposes.len() {
        return Err("authorization purposes must be unique".to_string());
    }
    let effective_at_unix = DateTime::parse_from_rfc3339(effective_at)
        .map_err(|error| format!("effective_at must be RFC3339: {error}"))?
        .timestamp();
    if effective_at_unix < 0 {
        return Err("effective_at must not precede the Unix epoch".to_string());
    }
    if identity_public_key.algorithm != PQCAlgorithm::FNDSA
        || identity_private_key.algorithm != PQCAlgorithm::FNDSA
    {
        return Err("identity root keypair must use FN-DSA-1024".to_string());
    }
    let authorization_algorithm =
        RuntimeSignatureAlgorithm::from_pqc(&authorization_public_key.algorithm)?;
    if authorization_algorithm == RuntimeSignatureAlgorithm::FnDsa1024 {
        return Err("operational authorization key must use ML-DSA-65 or ML-DSA-87".to_string());
    }
    if authorization_private_key.algorithm != authorization_public_key.algorithm {
        return Err("authorization public/private algorithms do not match".to_string());
    }
    if identity_public_key.key_data.len() != FN_DSA_1024_PUBLIC_KEY_BYTES
        || authorization_public_key.key_data.len() != authorization_algorithm.public_key_bytes()
    {
        return Err("identity authorization public key has the wrong canonical length".to_string());
    }

    let identity_address =
        derive_key_controlled_address(address_hrp, &identity_public_key.key_data)?;
    let authorization_key_hash = sha3_256_hex(&authorization_public_key.key_data);
    let mut binding = IdentityAuthorizationBinding {
        schema_version: AUTH_BINDING_SCHEMA_VERSION.to_string(),
        binary_encoding: AUTH_BINDING_BINARY_ENCODING.to_string(),
        identity_id: identity_id.to_string(),
        identity_address,
        identity_root: IdentityRoot {
            algorithm: IDENTITY_ROOT_ALGORITHM.to_string(),
            public_key: hex::encode(&identity_public_key.key_data),
            public_key_sha3_256: sha3_256_hex(&identity_public_key.key_data),
        },
        authorization_policy: AuthorizationPolicy {
            policy_type: AuthorizationPolicyType::SingleKey,
            threshold: 1,
            principals: vec![AuthorizationPrincipal {
                principal_id: authorization_principal_id.to_string(),
                principal_type: PrincipalType::PublicKey,
                algorithm: Some(authorization_algorithm.canonical_name().to_string()),
                public_key: Some(hex::encode(&authorization_public_key.key_data)),
                public_key_sha3_256: Some(authorization_key_hash.clone()),
                identity_reference: None,
                status: BindingStatus::Active,
                purposes: canonical_purposes,
            }],
        },
        authorization_scopes: Vec::new(),
        current_auth_key_hash: Some(authorization_key_hash),
        auth_key_history: Vec::new(),
        supersession_history: Vec::new(),
        effective_at: effective_at.to_string(),
        binding_payload_sha3_256: String::new(),
        proofs: BindingProofs {
            identity_root: SignatureProof {
                algorithm: IDENTITY_ROOT_ALGORITHM.to_string(),
                signature: String::new(),
            },
            authorization_key_possession: Vec::new(),
        },
    };
    let payload = canonical_binding_payload(&binding)?;
    binding.binding_payload_sha3_256 = sha3_256_hex(&payload);
    let message = binding_signature_message(&payload);
    let mut manager = PQCManager::new();
    binding.proofs.identity_root.signature = hex::encode(
        manager
            .sign(identity_private_key, &message)
            .map_err(|error| format!("sign identity-root binding proof: {error}"))?
            .signature_data,
    );
    binding.proofs.authorization_key_possession = vec![AuthorizationKeyPossessionProof {
        principal_id: authorization_principal_id.to_string(),
        algorithm: authorization_algorithm.canonical_name().to_string(),
        signature: hex::encode(
            manager
                .sign(authorization_private_key, &message)
                .map_err(|error| format!("sign authorization-key possession proof: {error}"))?
                .signature_data,
        ),
    }];
    verify_binding_at(&binding, effective_at_unix as u64)?;
    Ok(binding)
}

pub fn create_single_key_binding_with_scopes(
    identity_id: &str,
    address_hrp: &str,
    identity_public_key: &PQCPublicKey,
    identity_private_key: &PQCPrivateKey,
    authorization_principal_id: &str,
    authorization_public_key: &PQCPublicKey,
    authorization_private_key: &PQCPrivateKey,
    scopes: &[AuthorizationScope],
    effective_at: &str,
) -> Result<IdentityAuthorizationBinding, String> {
    if scopes.is_empty() {
        return Err("identity authorization binding requires a signed context scope".to_string());
    }
    let mut canonical_scopes = scopes.to_vec();
    canonical_scopes.sort_by(|left, right| {
        (
            left.signature_domain.as_str(),
            left.chain_id,
            left.network_id.as_str(),
            left.purpose.as_str(),
        )
            .cmp(&(
                right.signature_domain.as_str(),
                right.chain_id,
                right.network_id.as_str(),
                right.purpose.as_str(),
            ))
    });
    canonical_scopes.dedup();
    if canonical_scopes.len() != scopes.len() {
        return Err("identity authorization scopes must be unique".to_string());
    }
    let mut purposes = canonical_scopes
        .iter()
        .map(|scope| scope.purpose.as_str())
        .collect::<Vec<_>>();
    purposes.sort_unstable();
    purposes.dedup();
    let mut binding = create_single_key_binding_with_purposes(
        identity_id,
        address_hrp,
        identity_public_key,
        identity_private_key,
        authorization_principal_id,
        authorization_public_key,
        authorization_private_key,
        &purposes,
        effective_at,
    )?;
    binding.authorization_scopes = canonical_scopes;
    binding.binding_payload_sha3_256.clear();
    binding.proofs.identity_root.signature.clear();
    binding.proofs.authorization_key_possession.clear();
    let payload = canonical_binding_payload(&binding)?;
    binding.binding_payload_sha3_256 = sha3_256_hex(&payload);
    let message = binding_signature_message(&payload);
    let authorization_algorithm =
        RuntimeSignatureAlgorithm::from_pqc(&authorization_public_key.algorithm)?;
    let mut manager = PQCManager::new();
    binding.proofs.identity_root.signature = hex::encode(
        manager
            .sign(identity_private_key, &message)
            .map_err(|error| format!("sign scoped identity-root binding proof: {error}"))?
            .signature_data,
    );
    binding.proofs.authorization_key_possession = vec![AuthorizationKeyPossessionProof {
        principal_id: authorization_principal_id.to_string(),
        algorithm: authorization_algorithm.canonical_name().to_string(),
        signature: hex::encode(
            manager
                .sign(authorization_private_key, &message)
                .map_err(|error| {
                    format!("sign scoped authorization-key possession proof: {error}")
                })?
                .signature_data,
        ),
    }];
    let effective_at_unix = DateTime::parse_from_rfc3339(effective_at)
        .map_err(|error| format!("effective_at must be RFC3339: {error}"))?
        .timestamp();
    if effective_at_unix < 0 {
        return Err("effective_at must not precede the Unix epoch".to_string());
    }
    verify_binding_at(&binding, effective_at_unix as u64)?;
    Ok(binding)
}

fn verify_detached_signature(
    algorithm: RuntimeSignatureAlgorithm,
    public_key_hex: &str,
    message: &[u8],
    signature_hex: &str,
) -> Result<(), String> {
    let public_key = decode_lower_hex(
        "authorization public key",
        public_key_hex,
        Some(algorithm.public_key_bytes()),
    )?;
    let signature = decode_lower_hex("authorization signature", signature_hex, None)?;
    let key = PQCPublicKey {
        algorithm: algorithm.pqc(),
        key_data: public_key,
        key_id: "snts-v1.3-auth-binding".to_string(),
        created_at: 0,
    };
    let proof = PQCSignature {
        algorithm: algorithm.pqc(),
        signature_data: signature,
        message_hash: message.to_vec(),
        public_key_id: key.key_id.clone(),
        created_at: 0,
    };
    if PQCManager::new().verify(&key, &proof, message)? {
        Ok(())
    } else {
        Err("authorization-binding signature verification failed".to_string())
    }
}

fn validate_binding_payload(binding: &IdentityAuthorizationBinding) -> Result<(), String> {
    validate_binding_bounds(binding)?;
    if binding.schema_version != AUTH_BINDING_SCHEMA_VERSION
        || binding.binary_encoding != AUTH_BINDING_BINARY_ENCODING
    {
        return Err("authorization binding schema or binary encoding is not canonical".to_string());
    }
    require_nonempty("identity_id", &binding.identity_id)?;
    DateTime::parse_from_rfc3339(&binding.effective_at)
        .map_err(|error| format!("effective_at must be RFC3339: {error}"))?;

    let decoded_address = decode_address(&binding.identity_address)?;
    if decoded_address.classification != IdentifierClass::KeyControlledAddress {
        return Err("identity_address must use a key-controlled namespace".to_string());
    }
    if binding.identity_root.algorithm != IDENTITY_ROOT_ALGORITHM {
        return Err("identity_root algorithm must be FN-DSA-1024".to_string());
    }
    let identity_public_key = decode_lower_hex(
        "identity_root.public_key",
        &binding.identity_root.public_key,
        Some(FN_DSA_1024_PUBLIC_KEY_BYTES),
    )?;
    lower_hex_32(
        "identity_root.public_key_sha3_256",
        &binding.identity_root.public_key_sha3_256,
    )?;
    if sha3_256_hex(&identity_public_key) != binding.identity_root.public_key_sha3_256 {
        return Err("identity-root public-key hash mismatch".to_string());
    }
    if derive_key_controlled_address(&decoded_address.hrp, &identity_public_key)?
        != binding.identity_address
    {
        return Err("identity_address is not derived from its FN-DSA-1024 root".to_string());
    }

    if binding.authorization_policy.principals.is_empty() {
        return Err("authorization policy must contain at least one principal".to_string());
    }
    let mut prior_principal_id: Option<&str> = None;
    let mut active_count = 0usize;
    let mut active_public_key_hashes = Vec::new();
    for principal in &binding.authorization_policy.principals {
        require_nonempty("principal_id", &principal.principal_id)?;
        if prior_principal_id.is_some_and(|prior| prior >= principal.principal_id.as_str()) {
            return Err(
                "authorization principals must be uniquely sorted by principal_id".to_string(),
            );
        }
        prior_principal_id = Some(&principal.principal_id);
        if principal.status == BindingStatus::Active {
            active_count += 1;
        }
        let mut prior_purpose: Option<&str> = None;
        for purpose in &principal.purposes {
            require_nonempty("principal purpose", purpose)?;
            if prior_purpose.is_some_and(|prior| prior >= purpose.as_str()) {
                return Err("principal purposes must be uniquely sorted".to_string());
            }
            prior_purpose = Some(purpose);
        }
        match principal.principal_type {
            PrincipalType::PublicKey => {
                if principal.identity_reference.is_some() {
                    return Err(
                        "public-key principal must not contain identity_reference".to_string()
                    );
                }
                let algorithm_name = principal
                    .algorithm
                    .as_deref()
                    .ok_or_else(|| "public-key principal is missing algorithm".to_string())?;
                let algorithm = RuntimeSignatureAlgorithm::parse(algorithm_name)?;
                let public_key_hex = principal
                    .public_key
                    .as_deref()
                    .ok_or_else(|| "public-key principal is missing public_key".to_string())?;
                let public_key = decode_lower_hex(
                    "principal public_key",
                    public_key_hex,
                    Some(algorithm.public_key_bytes()),
                )?;
                let key_hash = principal.public_key_sha3_256.as_deref().ok_or_else(|| {
                    "public-key principal is missing public_key_sha3_256".to_string()
                })?;
                lower_hex_32("principal public_key_sha3_256", key_hash)?;
                if sha3_256_hex(&public_key) != key_hash {
                    return Err(format!(
                        "principal '{}' public-key hash mismatch",
                        principal.principal_id
                    ));
                }
                if principal.status == BindingStatus::Active {
                    active_public_key_hashes.push(key_hash);
                }
            }
            PrincipalType::IdentityReference => {
                if principal.algorithm.is_some()
                    || principal.public_key.is_some()
                    || principal.public_key_sha3_256.is_some()
                {
                    return Err(
                        "identity-reference principal must not contain key fields".to_string()
                    );
                }
                let reference = principal.identity_reference.as_deref().ok_or_else(|| {
                    "identity-reference principal is missing identity_reference".to_string()
                })?;
                if decode_address(reference)?.classification
                    != IdentifierClass::KeyControlledAddress
                {
                    return Err("identity_reference must be key-controlled".to_string());
                }
            }
        }
    }

    let threshold = usize::try_from(binding.authorization_policy.threshold)
        .map_err(|_| "authorization threshold does not fit usize".to_string())?;
    if threshold == 0 || threshold > active_count {
        return Err(
            "authorization threshold must be within the active principal count".to_string(),
        );
    }
    match binding.authorization_policy.policy_type {
        AuthorizationPolicyType::SingleKey => {
            if threshold != 1 || active_count != 1 || active_public_key_hashes.len() != 1 {
                return Err(
                    "single-key policy requires one active public-key principal and threshold 1"
                        .to_string(),
                );
            }
            if binding.current_auth_key_hash.as_deref() != Some(active_public_key_hashes[0]) {
                return Err(
                    "current_auth_key_hash does not match the active authorization key".to_string(),
                );
            }
        }
        AuthorizationPolicyType::Threshold => {
            if binding.current_auth_key_hash.is_some() {
                return Err("threshold policy requires null current_auth_key_hash".to_string());
            }
        }
    }

    let mut prior_scope: Option<(&str, u64, &str, &str)> = None;
    for scope in &binding.authorization_scopes {
        let current = (
            scope.signature_domain.as_str(),
            scope.chain_id,
            scope.network_id.as_str(),
            scope.purpose.as_str(),
        );
        if prior_scope.is_some_and(|prior| prior >= current) {
            return Err("authorization scopes must be uniquely sorted".to_string());
        }
        prior_scope = Some(current);
        if scope.chain_id == 0 {
            return Err("authorization scope chain_id must be non-zero".to_string());
        }
        if !binding
            .authorization_policy
            .principals
            .iter()
            .any(|principal| {
                principal.status == BindingStatus::Active
                    && principal
                        .purposes
                        .binary_search_by(|purpose| purpose.as_str().cmp(&scope.purpose))
                        .is_ok()
            })
        {
            return Err(format!(
                "authorization scope purpose '{}' is not granted to an active principal",
                scope.purpose
            ));
        }
    }

    for history in &binding.auth_key_history {
        require_nonempty("auth_key_history.principal_id", &history.principal_id)?;
        RuntimeSignatureAlgorithm::parse(&history.algorithm)?;
        lower_hex_32(
            "auth_key_history.public_key_sha3_256",
            &history.public_key_sha3_256,
        )?;
        if history.status != BindingStatus::Retired {
            return Err("auth_key_history entries must be retired".to_string());
        }
        DateTime::parse_from_rfc3339(&history.retired_at)
            .map_err(|error| format!("retired_at must be RFC3339: {error}"))?;
        require_nonempty("auth_key_history.reason", &history.reason)?;
    }
    for supersession in &binding.supersession_history {
        require_nonempty("supersession_history.address", &supersession.address)?;
        require_nonempty(
            "supersession_history.derivation_standard",
            &supersession.derivation_standard,
        )?;
        require_nonempty("supersession_history.reason", &supersession.reason)?;
        if supersession.status != BindingStatus::Superseded
            || supersession.address == binding.identity_address
        {
            return Err("invalid supersession history entry".to_string());
        }
    }
    Ok(())
}

/// Verifies the canonical payload hash, the FN-DSA identity-root proof, and
/// every active public authorization key's possession proof.
pub fn verify_binding(binding: &IdentityAuthorizationBinding) -> Result<(), String> {
    verify_binding_at(binding, current_unix_timestamp())
}

/// Deterministic consensus verifier. `consensus_timestamp_unix` comes from the
/// block/proposal context; it must never be substituted with an envelope time.
pub fn verify_binding_at(
    binding: &IdentityAuthorizationBinding,
    consensus_timestamp_unix: u64,
) -> Result<(), String> {
    validate_binding_payload(binding)?;
    let effective_at = DateTime::parse_from_rfc3339(&binding.effective_at)
        .map_err(|error| format!("effective_at must be RFC3339: {error}"))?
        .timestamp();
    if effective_at < 0 {
        return Err("effective_at must not precede the Unix epoch".to_string());
    }
    if effective_at as u64 > consensus_timestamp_unix {
        return Err(format!(
            "authorization binding is not effective until {}",
            binding.effective_at
        ));
    }
    lower_hex_32(
        "binding_payload_sha3_256",
        &binding.binding_payload_sha3_256,
    )?;
    let payload = canonical_binding_payload(binding)?;
    if sha3_256_hex(&payload) != binding.binding_payload_sha3_256 {
        return Err("binding payload hash mismatch".to_string());
    }
    let message = binding_signature_message(&payload);
    if binding.proofs.identity_root.algorithm != IDENTITY_ROOT_ALGORITHM {
        return Err("identity-root proof algorithm must be FN-DSA-1024".to_string());
    }
    verify_detached_signature(
        RuntimeSignatureAlgorithm::FnDsa1024,
        &binding.identity_root.public_key,
        &message,
        &binding.proofs.identity_root.signature,
    )
    .map_err(|error| format!("identity-root proof verification failed: {error}"))?;

    let expected = binding
        .authorization_policy
        .principals
        .iter()
        .filter(|principal| {
            principal.status == BindingStatus::Active
                && principal.principal_type == PrincipalType::PublicKey
        })
        .map(|principal| (principal.principal_id.as_str(), principal))
        .collect::<BTreeMap<_, _>>();
    if binding.proofs.authorization_key_possession.len() != expected.len() {
        return Err("authorization-key possession proof count mismatch".to_string());
    }
    let mut prior_proof_id: Option<&str> = None;
    for proof in &binding.proofs.authorization_key_possession {
        if prior_proof_id.is_some_and(|prior| prior >= proof.principal_id.as_str()) {
            return Err("authorization-key proofs must be uniquely sorted".to_string());
        }
        prior_proof_id = Some(&proof.principal_id);
        let principal = expected.get(proof.principal_id.as_str()).ok_or_else(|| {
            format!(
                "unexpected authorization-key proof for '{}'",
                proof.principal_id
            )
        })?;
        let algorithm_name = principal
            .algorithm
            .as_deref()
            .ok_or_else(|| "verified public-key principal lost its algorithm".to_string())?;
        if proof.algorithm != algorithm_name {
            return Err(format!(
                "authorization proof algorithm mismatch for '{}'",
                proof.principal_id
            ));
        }
        let public_key = principal
            .public_key
            .as_deref()
            .ok_or_else(|| "verified public-key principal lost its public key".to_string())?;
        verify_detached_signature(
            RuntimeSignatureAlgorithm::parse(algorithm_name)?,
            public_key,
            &message,
            &proof.signature,
        )
        .map_err(|error| {
            format!(
                "authorization-key proof verification failed for '{}': {error}",
                proof.principal_id
            )
        })?;
    }
    Ok(())
}

/// Resolves a native identity only after proving that the operational key is
/// an active principal with the required purpose in a valid binding.
pub fn identity_address_for_authorization_key(
    binding: &IdentityAuthorizationBinding,
    algorithm: &str,
    authorization_public_key: &[u8],
    required_purpose: &str,
) -> Result<String, String> {
    identity_address_for_authorization_key_at(
        binding,
        algorithm,
        authorization_public_key,
        required_purpose,
        current_unix_timestamp(),
    )
}

pub fn identity_address_for_authorization_key_at(
    binding: &IdentityAuthorizationBinding,
    algorithm: &str,
    authorization_public_key: &[u8],
    required_purpose: &str,
    consensus_timestamp_unix: u64,
) -> Result<String, String> {
    identity_address_for_authorization_key_in_context_at(
        binding,
        algorithm,
        authorization_public_key,
        WALLET_TRANSACTION_AUTHORIZATION_DOMAIN,
        SYNERGY_TESTNET_V3_CHAIN_ID,
        SYNERGY_TESTNET_V3_NETWORK_ID,
        required_purpose,
        consensus_timestamp_unix,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn identity_address_for_authorization_key_in_context_at(
    binding: &IdentityAuthorizationBinding,
    algorithm: &str,
    authorization_public_key: &[u8],
    signature_domain: &str,
    chain_id: u64,
    network_id: &str,
    required_purpose: &str,
    consensus_timestamp_unix: u64,
) -> Result<String, String> {
    require_single_signature_policy(binding)?;
    verify_binding_at(binding, consensus_timestamp_unix)?;
    require_bounded_text(
        "required authorization purpose",
        required_purpose,
        MAX_PURPOSE_BYTES,
    )?;
    require_bounded_text(
        "required authorization signature domain",
        signature_domain,
        MAX_CARRIER_DOMAIN_BYTES,
    )?;
    require_bounded_text(
        "required authorization network_id",
        network_id,
        MAX_ADDRESS_BYTES,
    )?;
    if chain_id == 0 {
        return Err("required authorization chain_id must be non-zero".to_string());
    }
    let runtime_algorithm = RuntimeSignatureAlgorithm::parse(algorithm)?;
    if authorization_public_key.len() != runtime_algorithm.public_key_bytes() {
        return Err("authorization public key has the wrong canonical byte length".to_string());
    }
    let public_key_hex = hex::encode(authorization_public_key);
    let matched = binding
        .authorization_policy
        .principals
        .iter()
        .any(|principal| {
            principal.status == BindingStatus::Active
                && principal.principal_type == PrincipalType::PublicKey
                && principal.algorithm.as_deref() == Some(algorithm)
                && principal.public_key.as_deref() == Some(public_key_hex.as_str())
                && principal
                    .purposes
                    .binary_search_by(|purpose| purpose.as_str().cmp(required_purpose))
                    .is_ok()
        });
    if !matched {
        return Err(format!(
            "authorization key is not actively bound for purpose '{required_purpose}'"
        ));
    }
    let required_scope = (signature_domain, chain_id, network_id, required_purpose);
    let scoped = binding.authorization_scopes.binary_search_by(|scope| {
        (
            scope.signature_domain.as_str(),
            scope.chain_id,
            scope.network_id.as_str(),
            scope.purpose.as_str(),
        )
            .cmp(&required_scope)
    });
    if scoped.is_err() {
        return Err(format!(
            "authorization binding does not grant signed scope domain='{signature_domain}' chain_id={chain_id} network_id='{network_id}' purpose='{required_purpose}'"
        ));
    }
    Ok(binding.identity_address.clone())
}

/// Binds an envelope-carried proof to the consensus state's canonical current
/// binding commitment. Without this external commitment, a previously valid
/// but superseded carrier is cryptographically indistinguishable from current
/// state and must not be treated as fresh.
pub fn require_canonical_current_binding(
    binding: &IdentityAuthorizationBinding,
    canonical_binding_payload_sha3_256: &str,
) -> Result<(), String> {
    lower_hex_32(
        "canonical current binding payload hash",
        canonical_binding_payload_sha3_256,
    )?;
    if binding.binding_payload_sha3_256 != canonical_binding_payload_sha3_256 {
        return Err(
            "identity authorization binding is not the canonical current binding".to_string(),
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn signed_binding() -> (IdentityAuthorizationBinding, Vec<u8>) {
        let mut manager = PQCManager::new();
        let (identity_public, identity_private) = manager
            .generate_keypair(PQCAlgorithm::FNDSA)
            .expect("test FN-DSA identity keypair");
        let (authorization_public, authorization_private) = manager
            .generate_keypair(PQCAlgorithm::MLDSA87)
            .expect("test ML-DSA authorization keypair");
        let identity_address = derive_key_controlled_address("syna", &identity_public.key_data)
            .expect("canonical identity address");
        let authorization_public_hex = hex::encode(&authorization_public.key_data);
        let authorization_key_hash = sha3_256_hex(&authorization_public.key_data);
        let mut binding = IdentityAuthorizationBinding {
            schema_version: AUTH_BINDING_SCHEMA_VERSION.to_string(),
            binary_encoding: AUTH_BINDING_BINARY_ENCODING.to_string(),
            identity_id: "test-identity".to_string(),
            identity_address,
            identity_root: IdentityRoot {
                algorithm: IDENTITY_ROOT_ALGORITHM.to_string(),
                public_key: hex::encode(&identity_public.key_data),
                public_key_sha3_256: sha3_256_hex(&identity_public.key_data),
            },
            authorization_policy: AuthorizationPolicy {
                policy_type: AuthorizationPolicyType::SingleKey,
                threshold: 1,
                principals: vec![AuthorizationPrincipal {
                    principal_id: "transaction-key".to_string(),
                    principal_type: PrincipalType::PublicKey,
                    algorithm: Some("ML-DSA-87".to_string()),
                    public_key: Some(authorization_public_hex),
                    public_key_sha3_256: Some(authorization_key_hash.clone()),
                    identity_reference: None,
                    status: BindingStatus::Active,
                    purposes: vec!["transaction-signing".to_string()],
                }],
            },
            authorization_scopes: vec![AuthorizationScope::testnet(
                WALLET_TRANSACTION_AUTHORIZATION_DOMAIN,
                "transaction-signing",
            )],
            current_auth_key_hash: Some(authorization_key_hash),
            auth_key_history: Vec::new(),
            supersession_history: Vec::new(),
            effective_at: "2026-08-22T00:00:00Z".to_string(),
            binding_payload_sha3_256: String::new(),
            proofs: BindingProofs {
                identity_root: SignatureProof {
                    algorithm: IDENTITY_ROOT_ALGORITHM.to_string(),
                    signature: String::new(),
                },
                authorization_key_possession: Vec::new(),
            },
        };
        let payload = canonical_binding_payload(&binding).expect("canonical binding payload");
        binding.binding_payload_sha3_256 = sha3_256_hex(&payload);
        let message = binding_signature_message(&payload);
        binding.proofs.identity_root.signature = hex::encode(
            manager
                .sign(&identity_private, &message)
                .expect("identity proof")
                .signature_data,
        );
        binding.proofs.authorization_key_possession = vec![AuthorizationKeyPossessionProof {
            principal_id: "transaction-key".to_string(),
            algorithm: "ML-DSA-87".to_string(),
            signature: hex::encode(
                manager
                    .sign(&authorization_private, &message)
                    .expect("authorization proof")
                    .signature_data,
            ),
        }];
        (binding, authorization_public.key_data)
    }

    #[test]
    fn operational_key_cannot_be_used_as_an_address_root() {
        let mldsa_key = vec![7u8; ML_DSA_87_PUBLIC_KEY_BYTES];
        assert!(crate::address::derive_standard_account_address(&mldsa_key).is_err());
    }

    #[test]
    fn missing_or_unproved_binding_fails_closed() {
        let binding = IdentityAuthorizationBinding {
            schema_version: AUTH_BINDING_SCHEMA_VERSION.to_string(),
            binary_encoding: AUTH_BINDING_BINARY_ENCODING.to_string(),
            identity_id: "test-identity".to_string(),
            identity_address: "not-an-address".to_string(),
            identity_root: IdentityRoot {
                algorithm: IDENTITY_ROOT_ALGORITHM.to_string(),
                public_key: hex::encode(vec![0u8; FN_DSA_1024_PUBLIC_KEY_BYTES]),
                public_key_sha3_256: hex::encode(Sha3_256::digest(vec![
                    0u8;
                    FN_DSA_1024_PUBLIC_KEY_BYTES
                ])),
            },
            authorization_policy: AuthorizationPolicy {
                policy_type: AuthorizationPolicyType::SingleKey,
                threshold: 1,
                principals: Vec::new(),
            },
            authorization_scopes: Vec::new(),
            current_auth_key_hash: None,
            auth_key_history: Vec::new(),
            supersession_history: Vec::new(),
            effective_at: "2026-08-22T00:00:00Z".to_string(),
            binding_payload_sha3_256: String::new(),
            proofs: BindingProofs {
                identity_root: SignatureProof {
                    algorithm: IDENTITY_ROOT_ALGORITHM.to_string(),
                    signature: String::new(),
                },
                authorization_key_possession: Vec::new(),
            },
        };
        assert!(identity_address_for_authorization_key(
            &binding,
            "ML-DSA-87",
            &vec![0u8; ML_DSA_87_PUBLIC_KEY_BYTES],
            "transaction-signing",
        )
        .is_err());
    }

    #[test]
    fn dual_possession_binding_resolves_operational_key_to_identity() {
        let (binding, authorization_public_key) = signed_binding();
        verify_binding(&binding).expect("dual-possession binding verifies");
        assert_eq!(
            identity_address_for_authorization_key(
                &binding,
                "ML-DSA-87",
                &authorization_public_key,
                "transaction-signing",
            )
            .expect("bound authorization key resolves"),
            binding.identity_address
        );

        let mut tampered = binding;
        tampered.authorization_policy.principals[0].purposes =
            vec!["governance-signing".to_string()];
        assert!(verify_binding(&tampered).is_err());
    }

    #[test]
    fn single_signature_resolution_rejects_threshold_policy_before_crypto() {
        let (mut binding, authorization_public_key) = signed_binding();
        binding.authorization_policy.policy_type = AuthorizationPolicyType::Threshold;
        binding.current_auth_key_hash = None;
        let error = identity_address_for_authorization_key_at(
            &binding,
            "ML-DSA-87",
            &authorization_public_key,
            "transaction-signing",
            u64::MAX,
        )
        .expect_err("threshold policy must not enter a single-signature admission path");
        assert!(error.contains("single-key authorization policy"));
    }

    #[test]
    fn carrier_single_signature_resolution_rejects_threshold_before_crypto() {
        let (mut binding, authorization_public_key) = signed_binding();
        binding.authorization_policy.policy_type = AuthorizationPolicyType::Threshold;
        binding.current_auth_key_hash = None;
        binding.proofs.identity_root.signature.clear();
        binding.proofs.authorization_key_possession.clear();
        let carrier = IdentityAuthorizationCarrier {
            schema_version: AUTHORIZATION_CARRIER_SCHEMA_VERSION,
            signature_domain: WALLET_TRANSACTION_AUTHORIZATION_DOMAIN.to_string(),
            binding,
        };

        let error = carrier
            .identity_address_for_key_in_context_at(
                WALLET_TRANSACTION_AUTHORIZATION_DOMAIN,
                SYNERGY_TESTNET_V3_CHAIN_ID,
                SYNERGY_TESTNET_V3_NETWORK_ID,
                "ML-DSA-87",
                &authorization_public_key,
                "transaction-signing",
                u64::MAX,
            )
            .expect_err("threshold carrier must fail before its invalid proofs are examined");
        assert!(error.contains("single-key authorization policy"));
    }

    #[test]
    fn signed_scope_requires_exact_domain_chain_network_and_purpose() {
        let (binding, authorization_public_key) = signed_binding();
        for (domain, chain_id, network_id, purpose, expected_error) in [
            (
                SYNQ_ADMISSION_AUTHORIZATION_DOMAIN,
                SYNERGY_TESTNET_V3_CHAIN_ID,
                SYNERGY_TESTNET_V3_NETWORK_ID,
                "transaction-signing",
                "does not grant signed scope",
            ),
            (
                WALLET_TRANSACTION_AUTHORIZATION_DOMAIN,
                SYNERGY_TESTNET_V3_CHAIN_ID + 1,
                SYNERGY_TESTNET_V3_NETWORK_ID,
                "transaction-signing",
                "does not grant signed scope",
            ),
            (
                WALLET_TRANSACTION_AUTHORIZATION_DOMAIN,
                SYNERGY_TESTNET_V3_CHAIN_ID,
                "synergy-testnet",
                "transaction-signing",
                "does not grant signed scope",
            ),
            (
                WALLET_TRANSACTION_AUTHORIZATION_DOMAIN,
                SYNERGY_TESTNET_V3_CHAIN_ID,
                SYNERGY_TESTNET_V3_NETWORK_ID,
                "synq-contract-deploy",
                "not actively bound",
            ),
        ] {
            let error = identity_address_for_authorization_key_in_context_at(
                &binding,
                "ML-DSA-87",
                &authorization_public_key,
                domain,
                chain_id,
                network_id,
                purpose,
                u64::MAX,
            )
            .expect_err("a substituted signed scope must fail closed");
            assert!(error.contains(expected_error));
        }
    }

    #[test]
    fn oversized_carrier_state_rejects_before_signature_verification() {
        let (mut binding, _) = signed_binding();
        binding.authorization_policy.principals =
            vec![binding.authorization_policy.principals[0].clone(); MAX_PRINCIPALS + 1];
        let error = verify_binding_at(&binding, u64::MAX)
            .expect_err("oversized principal list must fail closed");
        assert!(error.contains("maximum item count"));
    }

    #[test]
    fn future_effective_binding_rejects_at_consensus_timestamp() {
        let (binding, _) = signed_binding();
        let effective = DateTime::parse_from_rfc3339(&binding.effective_at)
            .expect("fixture effective time")
            .timestamp() as u64;
        let error = verify_binding_at(&binding, effective.saturating_sub(1))
            .expect_err("future binding must fail at the consensus timestamp");
        assert!(error.contains("not effective until"));
        verify_binding_at(&binding, effective).expect("binding activates exactly at effective_at");
    }

    #[test]
    fn canonical_current_commitment_rejects_stale_binding() {
        let (binding, _) = signed_binding();
        require_canonical_current_binding(&binding, &binding.binding_payload_sha3_256)
            .expect("matching canonical commitment");
        let error = require_canonical_current_binding(&binding, &"00".repeat(32))
            .expect_err("stale carrier commitment must fail");
        assert!(error.contains("not the canonical current binding"));
    }
}
