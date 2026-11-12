//! Canonical SNTS v1.3 identity authorization verification migrated from the
//! frozen semantic reference. Native addresses use FN-DSA-1024 roots; account
//! authorization uses independently bound ML-DSA keys. Admission always needs
//! an external finalized binding commitment and consensus timestamp.
use aegis_pqvm::pqc::signatures::{
    fndsa::fndsa1024,
    mldsa::{mldsa65, mldsa87},
};
use chrono::DateTime;
use pqrust_traits::sign::{DetachedSignature as _, PublicKey as _};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use synergy_address::{decode_address, derive_key_controlled_address, IdentifierClass};
use synergy_aegis::{AegisHashEngine, AegisSha3_256};
pub trait AuthorizationSignatureVerifier: Send + Sync {
    fn verify(
        &self,
        algorithm: &str,
        public: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), String>;
}
impl AuthorizationSignatureVerifier for synergy_aegis::ApqeIdentityVerifier {
    fn verify(
        &self,
        algorithm: &str,
        public: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), String> {
        self.verify_raw(algorithm, public, message, signature)
    }
}
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AuthorizationPolicyType {
    SingleKey,
    Threshold,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PrincipalType {
    PublicKey,
    IdentityReference,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BindingStatus {
    Active,
    Retired,
    Superseded,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityRoot {
    pub algorithm: String,
    pub public_key: String,
    pub public_key_sha3_256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizationPolicy {
    pub policy_type: AuthorizationPolicyType,
    pub threshold: u32,
    pub principals: Vec<AuthorizationPrincipal>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizationScope {
    pub signature_domain: String,
    pub chain_id: u64,
    pub network_id: String,
    pub purpose: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthKeyHistoryEntry {
    pub principal_id: String,
    pub algorithm: String,
    pub public_key_sha3_256: String,
    pub status: BindingStatus,
    pub retired_at: String,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SupersessionEntry {
    pub address: String,
    pub derivation_standard: String,
    pub status: BindingStatus,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignatureProof {
    pub algorithm: String,
    pub signature: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizationKeyPossessionProof {
    pub principal_id: String,
    pub algorithm: String,
    pub signature: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BindingProofs {
    pub identity_root: SignatureProof,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub authorization_key_possession: Vec<AuthorizationKeyPossessionProof>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityAuthorizationCarrier {
    pub schema_version: u16,
    pub signature_domain: String,
    pub binding: IdentityAuthorizationBinding,
}

impl IdentityAuthorizationCarrier {
    /// Checks the scoped dual-possession binding against finalized authority.
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
        self.identity_address_for_key_for_admission_at_with_verifier(
            expected_domain,
            chain_id,
            network_id,
            algorithm,
            authorization_public_key,
            required_purpose,
            consensus_timestamp_unix,
            canonical_binding_payload_sha3_256,
            None,
        )
    }
    #[allow(clippy::too_many_arguments)]
    pub fn identity_address_for_key_for_admission_at_with_verifier(
        &self,
        expected_domain: &str,
        chain_id: u64,
        network_id: &str,
        algorithm: &str,
        authorization_public_key: &[u8],
        required_purpose: &str,
        consensus_timestamp_unix: u64,
        canonical_binding_payload_sha3_256: &str,
        verifier: Option<&dyn AuthorizationSignatureVerifier>,
    ) -> Result<String, String> {
        if self.schema_version != AUTHORIZATION_CARRIER_SCHEMA_VERSION {
            return Err("unsupported identity authorization carrier schema version".into());
        }
        require_bounded_text(
            "identity authorization carrier domain",
            &self.signature_domain,
            MAX_CARRIER_DOMAIN_BYTES,
        )?;
        if self.signature_domain != expected_domain {
            return Err("identity authorization carrier domain mismatch".into());
        }
        require_canonical_current_binding(&self.binding, canonical_binding_payload_sha3_256)?;
        identity_address_for_authorization_key_in_context_at(
            &self.binding,
            algorithm,
            authorization_public_key,
            expected_domain,
            chain_id,
            network_id,
            required_purpose,
            consensus_timestamp_unix,
            verifier,
        )
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

    const fn signature_max_bytes(self) -> usize {
        match self {
            Self::FnDsa1024 => aegis_pqvm::pqc::signatures::fndsa::fndsa1024::signature_bytes(),
            Self::MlDsa65 => aegis_pqvm::pqc::signatures::mldsa::mldsa65::signature_bytes(),
            Self::MlDsa87 => aegis_pqvm::pqc::signatures::mldsa::mldsa87::signature_bytes(),
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
    hex::encode(
        AegisSha3_256
            .sha3_256_segments(&[bytes])
            .expect("fixed SHA3-256 supported"),
    )
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

fn verify_detached_signature(
    algorithm: RuntimeSignatureAlgorithm,
    public_key_hex: &str,
    message: &[u8],
    signature_hex: &str,
    verifier: Option<&dyn AuthorizationSignatureVerifier>,
) -> Result<(), String> {
    if verifier.is_none() && !cfg!(test) {
        return Err("explicit authenticated APQE identity verifier required; embedded native authorization is forbidden".into());
    }
    let public = decode_lower_hex(
        "authorization public key",
        public_key_hex,
        Some(algorithm.public_key_bytes()),
    )?;
    let signature = decode_lower_hex("authorization signature", signature_hex, None)?;
    if let Some(verifier) = verifier {
        let name = match algorithm {
            RuntimeSignatureAlgorithm::FnDsa1024 => "FN-DSA-1024",
            RuntimeSignatureAlgorithm::MlDsa65 => "ML-DSA-65",
            RuntimeSignatureAlgorithm::MlDsa87 => "ML-DSA-87",
        };
        return verifier.verify(name, &public, message, &signature);
    }
    macro_rules! verify {
        ($module:ident) => {{
            let public = $module::PublicKey::from_bytes(&public)
                .map_err(|_| "invalid authorization public key")?;
            let signature = $module::DetachedSignature::from_bytes(&signature)
                .map_err(|_| "invalid authorization signature")?;
            $module::verify_detached_signature(&signature, message, &public)
                .map_err(|_| "authorization-binding signature verification failed".to_string())
        }};
    }
    match algorithm {
        RuntimeSignatureAlgorithm::FnDsa1024 => verify!(fndsa1024),
        RuntimeSignatureAlgorithm::MlDsa65 => verify!(mldsa65),
        RuntimeSignatureAlgorithm::MlDsa87 => verify!(mldsa87),
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

pub fn verify_binding_at(
    binding: &IdentityAuthorizationBinding,
    consensus_timestamp_unix: u64,
) -> Result<(), String> {
    verify_binding_at_with_verifier(binding, consensus_timestamp_unix, None)
}
pub fn verify_binding_at_with_verifier(
    binding: &IdentityAuthorizationBinding,
    consensus_timestamp_unix: u64,
    verifier: Option<&dyn AuthorizationSignatureVerifier>,
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
        verifier,
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
            verifier,
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

#[allow(clippy::too_many_arguments)]
fn identity_address_for_authorization_key_in_context_at(
    binding: &IdentityAuthorizationBinding,
    algorithm: &str,
    authorization_public_key: &[u8],
    signature_domain: &str,
    chain_id: u64,
    network_id: &str,
    required_purpose: &str,
    consensus_timestamp_unix: u64,
    verifier: Option<&dyn AuthorizationSignatureVerifier>,
) -> Result<String, String> {
    require_single_signature_policy(binding)?;
    verify_binding_at_with_verifier(binding, consensus_timestamp_unix, verifier)?;
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

/// Existing canonical commitment table migrated into universal protocol state.
pub const IDENTITY_AUTHORIZATION_BINDINGS_STATE_KEY: &str = "identity_authorization_bindings";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityAuthorizationBindingCommitment {
    pub binding_payload_sha3_256: String,
    pub identity_root_public_key_sha3_256: String,
    pub effective_at_unix: u64,
}

impl IdentityAuthorizationBindingCommitment {
    /// Used by Genesis preparation; cryptographic validity alone does not install authority.
    pub fn from_verified_binding(
        binding: &IdentityAuthorizationBinding,
        consensus_timestamp_unix: u64,
    ) -> Result<Self, String> {
        Self::from_verified_binding_with_verifier(binding, consensus_timestamp_unix, None)
    }
    pub fn from_verified_binding_with_verifier(
        binding: &IdentityAuthorizationBinding,
        consensus_timestamp_unix: u64,
        verifier: Option<&dyn AuthorizationSignatureVerifier>,
    ) -> Result<Self, String> {
        verify_binding_at_with_verifier(binding, consensus_timestamp_unix, verifier)?;
        let effective_at = DateTime::parse_from_rfc3339(&binding.effective_at)
            .map_err(|error| format!("invalid binding effective_at: {error}"))?
            .timestamp();
        Ok(Self {
            binding_payload_sha3_256: binding.binding_payload_sha3_256.clone(),
            identity_root_public_key_sha3_256: binding.identity_root.public_key_sha3_256.clone(),
            effective_at_unix: u64::try_from(effective_at)
                .map_err(|_| "binding effective_at precedes Unix epoch")?,
        })
    }
}

/// Reads only explicitly supplied protocol state. Missing entries are distinct
/// from an absent/malformed table and malformed existing commitments.
pub fn canonical_binding_commitment_if_present(
    finalized_protocol: &BTreeMap<String, Vec<u8>>,
    identity_address: &str,
) -> Result<Option<IdentityAuthorizationBindingCommitment>, String> {
    let bytes = finalized_protocol
        .get(IDENTITY_AUTHORIZATION_BINDINGS_STATE_KEY)
        .ok_or("finalized identity authorization table is absent")?;
    if bytes.len() > MAX_CANONICAL_BINDING_PAYLOAD_BYTES {
        return Err("finalized identity authorization table exceeds the byte limit".into());
    }
    let bindings: BTreeMap<String, IdentityAuthorizationBindingCommitment> =
        serde_json::from_slice(bytes)
            .map_err(|error| format!("decode finalized identity authorization table: {error}"))?;
    let Some(commitment) = bindings.get(identity_address) else {
        return Ok(None);
    };
    lower_hex_32(
        "finalized binding hash",
        &commitment.binding_payload_sha3_256,
    )?;
    lower_hex_32(
        "finalized identity root hash",
        &commitment.identity_root_public_key_sha3_256,
    )?;
    Ok(Some(commitment.clone()))
}

/// A missing first binding is authorized by the self-certifying identity root,
/// its signed delegation and delegated-key possession, never by an allowlist.
/// An existing binding always wins; a carrier cannot replace or revive it.
#[allow(clippy::too_many_arguments)]
pub fn resolve_transaction_binding(
    protocol: &BTreeMap<String, Vec<u8>>,
    sender: &str,
    carrier: &IdentityAuthorizationCarrier,
    signer_public_key: &[u8],
    chain_id: u64,
    network_id: &str,
    consensus_timestamp_unix: u64,
) -> Result<IdentityAuthorizationBindingCommitment, String> {
    resolve_transaction_binding_with_verifier(
        protocol,
        sender,
        carrier,
        signer_public_key,
        chain_id,
        network_id,
        consensus_timestamp_unix,
        None,
    )
}
#[allow(clippy::too_many_arguments)]
pub fn resolve_transaction_binding_with_verifier(
    protocol: &BTreeMap<String, Vec<u8>>,
    sender: &str,
    carrier: &IdentityAuthorizationCarrier,
    signer_public_key: &[u8],
    chain_id: u64,
    network_id: &str,
    consensus_timestamp_unix: u64,
    verifier: Option<&dyn AuthorizationSignatureVerifier>,
) -> Result<IdentityAuthorizationBindingCommitment, String> {
    let binding = match canonical_binding_commitment_if_present(protocol, sender)? {
        Some(binding) => binding,
        None => IdentityAuthorizationBindingCommitment::from_verified_binding_with_verifier(
            &carrier.binding,
            consensus_timestamp_unix,
            verifier,
        )?,
    };
    if binding.effective_at_unix > consensus_timestamp_unix
        || binding.identity_root_public_key_sha3_256
            != carrier.binding.identity_root.public_key_sha3_256
    {
        return Err("transaction account binding is not current".into());
    }
    let address = carrier.identity_address_for_key_for_admission_at_with_verifier(
        AEGIS_TRANSACTION_AUTHORIZATION_DOMAIN,
        chain_id,
        network_id,
        "ML-DSA-87",
        signer_public_key,
        "transaction-signing",
        consensus_timestamp_unix,
        &binding.binding_payload_sha3_256,
        verifier,
    )?;
    if address != sender {
        return Err("transaction signer is not the self-certified sender".into());
    }
    Ok(binding)
}

/// Prepare an immutable first-use update after full carrier verification.
/// The execution owner must commit it atomically with the action and fees.
pub fn first_use_binding_update(
    protocol: &BTreeMap<String, Vec<u8>>,
    sender: &str,
    verified_binding: &IdentityAuthorizationBindingCommitment,
) -> Result<Option<Vec<u8>>, String> {
    if let Some(existing) = canonical_binding_commitment_if_present(protocol, sender)? {
        if &existing != verified_binding {
            return Err(
                "first use cannot replace an existing identity authorization binding".into(),
            );
        }
        return Ok(None);
    }
    let bytes = &protocol[IDENTITY_AUTHORIZATION_BINDINGS_STATE_KEY];
    let mut bindings: BTreeMap<String, IdentityAuthorizationBindingCommitment> =
        serde_json::from_slice(bytes)
            .map_err(|error| format!("decode identity authorization table: {error}"))?;
    bindings.insert(sender.to_owned(), verified_binding.clone());
    let updated = serde_json::to_vec(&bindings).map_err(|error| error.to_string())?;
    if updated.len() > MAX_CANONICAL_BINDING_PAYLOAD_BYTES {
        return Err("identity authorization table exceeds the byte limit".into());
    }
    Ok(Some(updated))
}

/// Requires an already committed binding. Used for operations which explicitly
/// need prior identity authority rather than permissionless transaction access.
pub fn canonical_binding_commitment(
    finalized_protocol: &BTreeMap<String, Vec<u8>>,
    identity_address: &str,
) -> Result<IdentityAuthorizationBindingCommitment, String> {
    canonical_binding_commitment_if_present(finalized_protocol, identity_address)?
        .ok_or_else(|| "identity has no canonical finalized authorization binding".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn signed_carrier() -> (IdentityAuthorizationCarrier, Vec<u8>) {
        let (identity_public, identity_secret) = fndsa1024::keypair();
        let (account_public, account_secret) = mldsa87::keypair();
        let identity_address =
            derive_key_controlled_address("syna", identity_public.as_bytes()).unwrap();
        let account_hash = sha3_256_hex(account_public.as_bytes());
        let mut binding: IdentityAuthorizationBinding = serde_json::from_value(serde_json::json!({
            "schema_version": AUTH_BINDING_SCHEMA_VERSION,
            "binary_encoding": AUTH_BINDING_BINARY_ENCODING,
            "identity_id": "test-account",
            "identity_address": identity_address,
            "identity_root": {
                "algorithm": "FN-DSA-1024",
                "public_key": hex::encode(identity_public.as_bytes()),
                "public_key_sha3_256": sha3_256_hex(identity_public.as_bytes())
            },
            "authorization_policy": {"policy_type":"single-key", "threshold":1,
                "principals":[{"principal_id":"account", "principal_type":"public-key",
                    "algorithm":"ML-DSA-87", "public_key":hex::encode(account_public.as_bytes()),
                    "public_key_sha3_256":account_hash, "status":"active", "purposes":["transaction-signing"]}]},
            "authorization_scopes":[{"signature_domain":AEGIS_TRANSACTION_AUTHORIZATION_DOMAIN,
                "chain_id":1266,"network_id":"testnet", "purpose":"transaction-signing"}],
            "current_auth_key_hash":account_hash,
            "auth_key_history":[], "supersession_history":[],
            "effective_at":"1970-01-01T00:00:10Z",
            "binding_payload_sha3_256":"",
            "proofs":{"identity_root":{"algorithm":"FN-DSA-1024","signature":""}}
        })).unwrap();
        let payload = canonical_binding_payload(&binding).unwrap();
        binding.binding_payload_sha3_256 = sha3_256_hex(&payload);
        let message = binding_signature_message(&payload);
        binding.proofs.identity_root.signature =
            hex::encode(fndsa1024::detached_sign(&message, &identity_secret).as_bytes());
        binding.proofs.authorization_key_possession = vec![AuthorizationKeyPossessionProof {
            principal_id: "account".into(),
            algorithm: "ML-DSA-87".into(),
            signature: hex::encode(mldsa87::detached_sign(&message, &account_secret).as_bytes()),
        }];
        (
            IdentityAuthorizationCarrier {
                schema_version: AUTHORIZATION_CARRIER_SCHEMA_VERSION,
                signature_domain: AEGIS_TRANSACTION_AUTHORIZATION_DOMAIN.into(),
                binding,
            },
            account_public.as_bytes().to_vec(),
        )
    }

    fn admit(
        carrier: &IdentityAuthorizationCarrier,
        key: &[u8],
        timestamp: u64,
        hash: &str,
    ) -> Result<String, String> {
        carrier.identity_address_for_key_for_admission_at(
            AEGIS_TRANSACTION_AUTHORIZATION_DOMAIN,
            1266,
            "testnet",
            "ML-DSA-87",
            key,
            "transaction-signing",
            timestamp,
            hash,
        )
    }

    #[test]
    fn permissionless_first_use_requires_root_key_possession_and_never_rebinds() {
        let (carrier, key) = signed_carrier();
        let sender = &carrier.binding.identity_address;
        let mut protocol = BTreeMap::from([(
            IDENTITY_AUTHORIZATION_BINDINGS_STATE_KEY.into(),
            b"{}".to_vec(),
        )]);
        let resolve =
            |p: &BTreeMap<String, Vec<u8>>,
             who: &str,
             c: &IdentityAuthorizationCarrier,
             k: &[u8],
             chain,
             network,
             time| { resolve_transaction_binding(p, who, c, k, chain, network, time) };
        struct RejectOwner;
        impl AuthorizationSignatureVerifier for RejectOwner {
            fn verify(&self, _: &str, _: &[u8], _: &[u8], _: &[u8]) -> Result<(), String> {
                Err("selected owner rejected proof".into())
            }
        }
        assert!(resolve_transaction_binding_with_verifier(
            &protocol,
            sender,
            &carrier,
            &key,
            1266,
            "testnet",
            10,
            Some(&RejectOwner)
        )
        .unwrap_err()
        .contains("selected owner rejected proof"));
        let binding = resolve(&protocol, sender, &carrier, &key, 1266, "testnet", 10).unwrap();
        assert!(canonical_binding_commitment_if_present(&protocol, sender)
            .unwrap()
            .is_none());
        assert!(resolve(
            &protocol,
            "another-owner",
            &carrier,
            &key,
            1266,
            "testnet",
            10
        )
        .is_err());
        let mut wrong_key = key.clone();
        wrong_key[0] ^= 1;
        assert!(resolve(&protocol, sender, &carrier, &wrong_key, 1266, "testnet", 10).is_err());
        assert!(resolve(&protocol, sender, &carrier, &key, 1267, "testnet", 10).is_err());
        assert!(resolve(&protocol, sender, &carrier, &key, 1266, "other", 10).is_err());
        assert!(resolve(&protocol, sender, &carrier, &key, 1266, "testnet", 9).is_err());
        for root_proof in [true, false] {
            let mut forged = carrier.clone();
            if root_proof {
                flip_hex(&mut forged.binding.proofs.identity_root.signature);
            } else {
                flip_hex(&mut forged.binding.proofs.authorization_key_possession[0].signature);
            }
            assert!(resolve(&protocol, sender, &forged, &key, 1266, "testnet", 10).is_err());
        }
        let updated = first_use_binding_update(&protocol, sender, &binding)
            .unwrap()
            .unwrap();
        protocol.insert(IDENTITY_AUTHORIZATION_BINDINGS_STATE_KEY.into(), updated);
        assert_eq!(
            resolve(&protocol, sender, &carrier, &key, 1266, "testnet", 10).unwrap(),
            binding
        );
        assert!(first_use_binding_update(&protocol, sender, &binding)
            .unwrap()
            .is_none());
        let mut conflicting = binding.clone();
        conflicting.binding_payload_sha3_256 = "0".repeat(64);
        assert!(first_use_binding_update(&protocol, sender, &conflicting).is_err());
        protocol.insert(
            IDENTITY_AUTHORIZATION_BINDINGS_STATE_KEY.into(),
            serde_json::to_vec(&BTreeMap::from([(sender, conflicting)])).unwrap(),
        );
        assert!(resolve(&protocol, sender, &carrier, &key, 1266, "testnet", 10).is_err());
        for malformed in [
            b"not-json".to_vec(),
            b"[]".to_vec(),
            format!("{{\"{sender}\":{{\"binding_payload_sha3_256\":\"bad\"}}}}").into_bytes(),
        ] {
            protocol.insert(IDENTITY_AUTHORIZATION_BINDINGS_STATE_KEY.into(), malformed);
            assert!(resolve(&protocol, sender, &carrier, &key, 1266, "testnet", 10).is_err());
        }
        protocol.clear();
        assert!(resolve(&protocol, sender, &carrier, &key, 1266, "testnet", 10).is_err());
    }

    #[test]
    fn real_dual_possession_resolves_only_current_scoped_account_key() {
        let (carrier, key) = signed_carrier();
        let hash = &carrier.binding.binding_payload_sha3_256;
        assert_eq!(
            admit(&carrier, &key, 10, hash).unwrap(),
            carrier.binding.identity_address
        );
        assert!(admit(&carrier, &key, 9, hash).is_err());
        assert!(admit(&carrier, &key, 10, &"0".repeat(64)).is_err());
        let mut wrong_key = key.clone();
        wrong_key[0] ^= 1;
        assert!(admit(&carrier, &wrong_key, 10, hash).is_err());
        for (domain, chain, network, algorithm, purpose) in [
            (
                WALLET_TRANSACTION_AUTHORIZATION_DOMAIN,
                1266,
                "testnet",
                "ML-DSA-87",
                "transaction-signing",
            ),
            (
                AEGIS_TRANSACTION_AUTHORIZATION_DOMAIN,
                1267,
                "testnet",
                "ML-DSA-87",
                "transaction-signing",
            ),
            (
                AEGIS_TRANSACTION_AUTHORIZATION_DOMAIN,
                1266,
                "other",
                "ML-DSA-87",
                "transaction-signing",
            ),
            (
                AEGIS_TRANSACTION_AUTHORIZATION_DOMAIN,
                1266,
                "testnet",
                "ML-DSA-65",
                "transaction-signing",
            ),
            (
                AEGIS_TRANSACTION_AUTHORIZATION_DOMAIN,
                1266,
                "testnet",
                "ML-DSA-87",
                "consensus-signing",
            ),
        ] {
            assert!(carrier
                .identity_address_for_key_for_admission_at(
                    domain, chain, network, algorithm, &key, purpose, 10, hash
                )
                .is_err());
        }
    }

    #[test]
    fn forged_proofs_roots_duplicate_principals_and_threshold_carriers_fail_closed() {
        let (carrier, key) = signed_carrier();
        let hash = &carrier.binding.binding_payload_sha3_256;
        let mut bad = carrier.clone();
        flip_hex(&mut bad.binding.proofs.identity_root.signature);
        assert!(admit(&bad, &key, 10, hash).is_err());
        let mut bad = carrier.clone();
        bad.binding.proofs.authorization_key_possession.clear();
        assert!(admit(&bad, &key, 10, hash).is_err());
        let mut bad = carrier.clone();
        flip_hex(&mut bad.binding.proofs.authorization_key_possession[0].signature);
        assert!(admit(&bad, &key, 10, hash).is_err());
        let mut bad = carrier.clone();
        flip_hex(&mut bad.binding.identity_root.public_key);
        assert!(admit(&bad, &key, 10, hash).is_err());
        let mut bad = carrier.clone();
        bad.binding
            .authorization_policy
            .principals
            .push(bad.binding.authorization_policy.principals[0].clone());
        assert!(admit(&bad, &key, 10, hash).is_err());
        let mut bad = carrier.clone();
        bad.binding.authorization_policy.policy_type = AuthorizationPolicyType::Threshold;
        assert!(admit(&bad, &key, 10, hash).is_err());
        let mut bad = carrier.clone();
        bad.schema_version = 2;
        assert!(admit(&bad, &key, 10, hash).is_err());
        let mut bad = carrier.clone();
        bad.binding.identity_address = derive_object_address_for_test();
        assert!(admit(&bad, &key, 10, hash).is_err());
    }

    fn flip_hex(value: &mut String) {
        let replacement = if value.starts_with('0') { "1" } else { "0" };
        value.replace_range(..1, replacement);
    }

    fn derive_object_address_for_test() -> String {
        synergy_address::derive_object_address("synq", b"wrong-address-class").unwrap()
    }
}
