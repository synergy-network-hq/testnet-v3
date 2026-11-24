//! Public authoring of the existing sponsored-enrollment payer binding.
use crate::aegis_keys::{read_bounded, write_public_json};
use crate::provider::Engine;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use synergy_aegis::{
    AegisHashEngine, AegisPolicy, AegisProtectedPrimitives, AegisSha3_256, SignatureAlgorithm,
};
use synergy_genesis::{network::AUTONOMOUS_EPOCH_PROTOCOL_V1, signing::SignedGenesis};
use synergy_identity::authorization::{
    canonical_binding_payload, AuthorizationKeyPossessionProof, AuthorizationPolicy,
    AuthorizationPolicyType, AuthorizationPrincipal, AuthorizationScope, BindingProofs,
    BindingStatus, IdentityAuthorizationBinding, IdentityAuthorizationBindingCommitment,
    IdentityAuthorizationCarrier, IdentityRoot, PrincipalType, SignatureProof,
    AEGIS_TRANSACTION_AUTHORIZATION_DOMAIN, AUTHORIZATION_CARRIER_SCHEMA_VERSION,
    AUTH_BINDING_BINARY_ENCODING, AUTH_BINDING_SCHEMA_VERSION, AUTH_BINDING_SIGNATURE_DOMAIN,
    IDENTITY_ROOT_ALGORITHM, PROTECTED_ENROLLMENT_SPONSOR_AUTHORIZATION_DOMAIN,
    PROTECTED_ENROLLMENT_SPONSOR_PURPOSE,
};

pub(super) const USAGE: &str = "synergy-keytool prepare-wallet-sponsor-identity REQUEST_JSON OUTPUT_JSON\nsynergy-keytool attach-wallet-sponsor-identity REQUEST_JSON FN_DSA_1024_SIGNATURE ML_DSA_87_SIGNATURE OUTPUT_JSON\nBoth commands require --apqe-report ABS --apqe-report-sha256 AUTHENTICATED_HEX";

const TRANSACTION_PURPOSE: &str = "transaction-signing";
const SPONSOR_ALGORITHM: &str = "ML-DSA-87";
const PRINCIPAL: &str = "sponsor";
const MAX_GENESIS_BYTES: u64 = 16 * 1024 * 1024;
const ROOT_KEY_BYTES: u64 = 1952;
const FN_DSA_PUBLIC_KEY_BYTES: usize = 1793;
const SPONSOR_PUBLIC_KEY_BYTES: usize = 2592;
const SPONSOR_SIGNATURE_BYTES: u64 = 4627;

#[cfg(test)]
mod tests;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    version: u32,
    genesis_path: PathBuf,
    genesis_sha256: String,
    authority_root_path: PathBuf,
    authority_root_sha256: String,
    identity_id: String,
    identity_root_public_key_hex: String,
    sponsor_public_key_hex: String,
    effective_at_unix: u64,
}

#[derive(Serialize)]
struct Scope {
    chain_id: u64,
    network_id: String,
    genesis_hash: String,
    payer: String,
    effective_at_unix: u64,
}

struct Prepared {
    scope: Scope,
    sponsor_public_key: Vec<u8>,
    binding: IdentityAuthorizationBinding,
    transcript: Vec<u8>,
}

fn load_genesis(request: &Request, engine: &Engine) -> Result<SignedGenesis, String> {
    selected_origin(&request.genesis_path,&request.genesis_sha256,&request.authority_root_path,
        &request.authority_root_sha256,engine)
}

pub(super) fn selected_origin(genesis_path:&Path,genesis_sha256:&str,root_path:&Path,root_sha256:&str,
    engine:&Engine)->Result<SignedGenesis,String>{
    let genesis = read_bounded(genesis_path, MAX_GENESIS_BYTES, "signed Genesis")?;
    let root = read_bounded(
        root_path,
        ROOT_KEY_BYTES,
        "Genesis public root",
    )?;
    if root.len() as u64 != ROOT_KEY_BYTES
        || hex(&AegisProtectedPrimitives.sha256(&genesis)) != genesis_sha256
        || hex(&AegisProtectedPrimitives.sha256(&root)) != root_sha256
    {
        return Err("signed Genesis or original public root differs from reviewed SHA-256".into());
    }
    let genesis: SignedGenesis = serde_json::from_slice(&genesis).map_err(|e| e.to_string())?;
    let verifier = crate::provider::verifier(
        AegisPolicy {
            allowed_algorithms: vec![SignatureAlgorithm::MlDsa65],
            maximum_message_bytes: MAX_GENESIS_BYTES as usize,
            maximum_signature_bytes: 3309,
        },
        Some(engine.clone()),
    )?;
    synergy_genesis::signing::verify(&genesis, &verifier, &root)?;
    if genesis
        .unsigned
        .network
        .autonomous_epoch_protocol
        .as_deref()
        != Some(AUTONOMOUS_EPOCH_PROTOCOL_V1)
    {
        return Err("sponsored Wallet requires its authenticated autonomous PoSy Genesis".into());
    }
    Ok(genesis)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn binding_hash(bytes: &[u8]) -> Result<String, String> {
    AegisSha3_256
        .sha3_256_segments(&[bytes])
        .map(|digest| hex(&digest))
        .map_err(|error| format!("hash native identity binding: {error:?}"))
}

fn decode_key(text: &str, bytes: usize) -> Result<Vec<u8>, String> {
    if text.len() != bytes * 2
        || !text
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
        || !text.bytes().any(|byte| byte != b'0')
    {
        return Err(
            "sponsor public keys require canonical lowercase-hex and exact algorithm lengths"
                .into(),
        );
    }
    text.as_bytes()
        .chunks(2)
        .map(|pair| {
            u8::from_str_radix(
                std::str::from_utf8(pair).map_err(|error| error.to_string())?,
                16,
            )
            .map_err(|error| error.to_string())
        })
        .collect()
}

impl Prepared {
    fn load(request_path: &Path, engine: &Engine) -> Result<Self, String> {
        let request: Request = serde_json::from_slice(&read_bounded(
            request_path,
            128 * 1024,
            "Wallet sponsor identity request",
        )?)
        .map_err(|error| error.to_string())?;
        if request.version != 1
            || !request.genesis_path.is_absolute()
            || !request.authority_root_path.is_absolute()
            || request.identity_id.is_empty()
            || request.identity_id.len() > 128
            || !request
                .identity_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        {
            return Err("invalid Wallet sponsor identity request".into());
        }
        let origin = load_genesis(&request, engine)?;
        let network = &origin.unsigned.network;
        let timestamp = i64::try_from(request.effective_at_unix).ok()
            .filter(|_| request.effective_at_unix >= network.activation_unix)
            .and_then(|seconds| chrono::DateTime::from_timestamp(seconds, 0))
            .ok_or("sponsor binding effective time precedes the authenticated origin or exceeds its bound")?;
        let root_key = decode_key(
            &request.identity_root_public_key_hex,
            FN_DSA_PUBLIC_KEY_BYTES,
        )?;
        let sponsor_public_key =
            decode_key(&request.sponsor_public_key_hex, SPONSOR_PUBLIC_KEY_BYTES)?;
        let payer = synergy_address::derive_key_controlled_address("syna", &root_key)?;
        let key_hash = binding_hash(&sponsor_public_key)?;
        let scope = Scope {
            chain_id: network.chain_id,
            network_id: network.network_id.clone(),
            genesis_hash: origin.genesis_hash,
            payer,
            effective_at_unix: request.effective_at_unix,
        };
        let authorization_scope = |domain: &str, purpose: &str| AuthorizationScope {
            signature_domain: domain.into(),
            chain_id: scope.chain_id,
            network_id: scope.network_id.clone(),
            purpose: purpose.into(),
        };
        let mut binding = IdentityAuthorizationBinding {
            schema_version: AUTH_BINDING_SCHEMA_VERSION.into(),
            binary_encoding: AUTH_BINDING_BINARY_ENCODING.into(),
            identity_id: request.identity_id,
            identity_address: scope.payer.clone(),
            identity_root: IdentityRoot {
                algorithm: IDENTITY_ROOT_ALGORITHM.into(),
                public_key: request.identity_root_public_key_hex,
                public_key_sha3_256: binding_hash(&root_key)?,
            },
            authorization_policy: AuthorizationPolicy {
                policy_type: AuthorizationPolicyType::SingleKey,
                threshold: 1,
                principals: vec![AuthorizationPrincipal {
                    principal_id: PRINCIPAL.into(),
                    principal_type: PrincipalType::PublicKey,
                    algorithm: Some(SPONSOR_ALGORITHM.into()),
                    public_key: Some(request.sponsor_public_key_hex),
                    public_key_sha3_256: Some(key_hash.clone()),
                    identity_reference: None,
                    status: BindingStatus::Active,
                    purposes: vec![
                        PROTECTED_ENROLLMENT_SPONSOR_PURPOSE.into(),
                        TRANSACTION_PURPOSE.into(),
                    ],
                }],
            },
            authorization_scopes: vec![
                authorization_scope(
                    PROTECTED_ENROLLMENT_SPONSOR_AUTHORIZATION_DOMAIN,
                    PROTECTED_ENROLLMENT_SPONSOR_PURPOSE,
                ),
                authorization_scope(AEGIS_TRANSACTION_AUTHORIZATION_DOMAIN, TRANSACTION_PURPOSE),
            ],
            current_auth_key_hash: Some(key_hash),
            auth_key_history: Vec::new(),
            supersession_history: Vec::new(),
            effective_at: timestamp.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            binding_payload_sha3_256: String::new(),
            proofs: BindingProofs {
                identity_root: SignatureProof {
                    algorithm: IDENTITY_ROOT_ALGORITHM.into(),
                    signature: String::new(),
                },
                authorization_key_possession: Vec::new(),
            },
        };
        let payload = canonical_binding_payload(&binding)?;
        binding.binding_payload_sha3_256 = binding_hash(&payload)?;
        let transcript = [AUTH_BINDING_SIGNATURE_DOMAIN, &payload].concat();
        Ok(Self {
            scope,
            sponsor_public_key,
            binding,
            transcript,
        })
    }
}

fn absolute(paths: &[&Path]) -> Result<(), String> {
    if paths.iter().all(|path| path.is_absolute()) {
        Ok(())
    } else {
        Err("Wallet sponsor authoring uses explicit absolute public input and output paths".into())
    }
}

pub(super) fn prepare(request: &Path, output: &Path, engine: Engine) -> Result<(), String> {
    absolute(&[request, output])?;
    let prepared = Prepared::load(request, &engine)?;
    write_public_json(
        output,
        &serde_json::json!({
            "schema":"synergy-wallet-sponsor-identity-review-v1", "scope":prepared.scope,
            "binding":prepared.binding, "transcript_hex":hex(&prepared.transcript),
        }),
    )
}

pub(super) fn attach(
    request: &Path,
    root_proof: &Path,
    sponsor_proof: &Path,
    output: &Path,
    engine: Engine,
) -> Result<(), String> {
    absolute(&[request, root_proof, sponsor_proof, output])?;
    let mut prepared = Prepared::load(request, &engine)?;
    let root = read_bounded(root_proof, 2048, "detached FN-DSA-1024 proof")?;
    let sponsor = read_bounded(
        sponsor_proof,
        SPONSOR_SIGNATURE_BYTES,
        "detached ML-DSA-87 proof",
    )?;
    if sponsor.len() as u64 != SPONSOR_SIGNATURE_BYTES {
        return Err("exact detached ML-DSA-87 sponsor proof required".into());
    }
    prepared.binding.proofs.identity_root.signature = hex(&root);
    prepared.binding.proofs.authorization_key_possession = vec![AuthorizationKeyPossessionProof {
        principal_id: PRINCIPAL.into(),
        algorithm: SPONSOR_ALGORITHM.into(),
        signature: hex(&sponsor),
    }];
    let verifier = synergy_aegis::ApqeIdentityVerifier::new(engine).map_err(|e| e.to_string())?;
    let commitment = IdentityAuthorizationBindingCommitment::from_verified_binding_with_verifier(
        &prepared.binding,
        prepared.scope.effective_at_unix,
        Some(&verifier),
    )?;
    let carrier = |domain: &str, purpose: &str| -> Result<String, String> {
        let carrier = IdentityAuthorizationCarrier {
            schema_version: AUTHORIZATION_CARRIER_SCHEMA_VERSION,
            signature_domain: domain.into(),
            binding: prepared.binding.clone(),
        };
        if prepared.scope.payer
            != carrier.identity_address_for_key_for_admission_at_with_verifier(
                domain,
                prepared.scope.chain_id,
                &prepared.scope.network_id,
                SPONSOR_ALGORITHM,
                &prepared.sponsor_public_key,
                purpose,
                prepared.scope.effective_at_unix,
                &commitment.binding_payload_sha3_256,
                Some(&verifier),
            )?
        {
            return Err("verified Wallet sponsor binding selected a different payer".into());
        }
        String::from_utf8(carrier.canonical_json_bytes()?).map_err(|error| error.to_string())
    };
    write_public_json(
        output,
        &serde_json::json!({
            "schema":"synergy-wallet-sponsor-identity-v1", "scope":prepared.scope, "commitment":commitment,
            "registration_carrier_json":carrier(AEGIS_TRANSACTION_AUTHORIZATION_DOMAIN, TRANSACTION_PURPOSE)?,
            "sponsor_carrier_json":carrier(PROTECTED_ENROLLMENT_SPONSOR_AUTHORIZATION_DOMAIN, PROTECTED_ENROLLMENT_SPONSOR_PURPOSE)?,
            "finalized_registration_verified":false,
        }),
    )
}
