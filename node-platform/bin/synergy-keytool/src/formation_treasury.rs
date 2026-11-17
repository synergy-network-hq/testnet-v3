//! Ordinary engineering treasury custody for the existing Genesis allocation.
//! No raw key export, protected-account enrollment, or runtime mint operation.
use crate::validator_formation::{
    begin, decode, digest, passphrase, private_dir, read, sync, write,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::path::Path;
use synergy_address_engine::{
    apqe::{fixed_digest, provider::SignOptions, FixedDigest, Primitives, SecretBytes},
    encrypt::{decrypt_with_passphrase, encrypt_with_passphrase, EncryptedEnvelope},
    types::Algorithm,
    validator_provisioning::FormationContext,
};
use synergy_identity::authorization::*;

const LIMIT: u64 = 128 * 1024;
const ROLE: &str = "ordinary-genesis-treasury-fndsa1024-mldsa87-v1";
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Parameters {
    formation_sha256: String,
    effective_at_unix: u64,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    version: u32,
    operation: String,
    parameters: Parameters,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Public {
    address: String,
    authorization: IdentityAuthorizationCarrier,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Custody {
    version: u32,
    role: String,
    formation: FormationContext,
    request_sha256: String,
    public_sha256: String,
    identity: EncryptedEnvelope,
    spending: EncryptedEnvelope,
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn hash(bytes: &[u8]) -> String {
    hex(&fixed_digest(&Primitives, FixedDigest::Sha3256, bytes))
}
fn encode(value: &impl Serialize) -> Result<Vec<u8>, String> {
    serde_json::to_vec_pretty(value).map_err(|_| "Cannot encode ordinary treasury".into())
}
fn request(path: &Path, pin: &str, formation_pin: &str) -> Result<(Request, SecretBytes), String> {
    let raw = read(path, 4096, true)?;
    let value: Request = decode(&raw)?;
    if pin.len() != 64
        || digest(raw.as_bytes()) != pin
        || value.version != 1
        || value.operation != "treasury_prepare"
        || value.parameters.formation_sha256 != formation_pin
        || value.parameters.effective_at_unix == 0
        || i64::try_from(value.parameters.effective_at_unix)
            .ok()
            .and_then(|t| chrono::DateTime::from_timestamp(t, 0))
            .is_none()
    {
        return Err("Exact ordinary treasury request and formation required".into());
    }
    Ok((value, raw))
}

pub fn prepare(
    context_path: &Path,
    context_pin: &str,
    request_path: &Path,
    request_pin: &str,
    directory: &Path,
    engine: crate::provider::Engine,
) -> Result<Value, String> {
    let context = crate::validator_formation::pinned_context(context_path, context_pin)?;
    let (request, raw) = request(request_path, request_pin, context_pin)?;
    let chain = u64::from_str_radix(&context.chain_id_hex, 16)
        .map_err(|_| "Treasury chain exceeds supported u64")?;
    // Reserve before generation; incomplete state is reconciled, never regenerated.
    begin(directory)?;
    write(&directory.join("request.json"), raw.as_bytes())?;
    let mut entropy = vec![0; 32];
    let generated = Primitives.random_bytes(&mut entropy);
    let entropy = SecretBytes::from_bytes(entropy);
    generated.map_err(|_| "APQE secure randomness unavailable")?;
    let unlock = SecretBytes::from_bytes(hex(entropy.as_bytes()).into_bytes());
    let provider = engine.lock().map_err(|_| "APQE provider unavailable")?;
    let root = provider
        .generate_keypair(Algorithm::FnDsa1024)
        .map_err(|e| e.to_string())?;
    let spending = provider
        .generate_keypair(Algorithm::MlDsa87)
        .map_err(|e| e.to_string())?;
    let address = synergy_address::derive_key_controlled_address("syna", &root.public_key)?;
    let effective =
        chrono::DateTime::from_timestamp(request.parameters.effective_at_unix as i64, 0)
            .ok_or("Invalid treasury effective time")?
            .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    let mut binding: IdentityAuthorizationBinding = serde_json::from_value(json!({
        "schema_version":AUTH_BINDING_SCHEMA_VERSION,"binary_encoding":AUTH_BINDING_BINARY_ENCODING,
        "identity_id":"formation-treasury","identity_address":address,
        "identity_root":{"algorithm":"FN-DSA-1024","public_key":hex(&root.public_key),"public_key_sha3_256":hash(&root.public_key)},
        "authorization_policy":{"policy_type":"single-key","threshold":1,"principals":[{
            "principal_id":"treasury","principal_type":"public-key","algorithm":"ML-DSA-87",
            "public_key":hex(&spending.public_key),"public_key_sha3_256":hash(&spending.public_key),
            "status":"active","purposes":["transaction-signing"]}]},
        "authorization_scopes":[{"signature_domain":AEGIS_TRANSACTION_AUTHORIZATION_DOMAIN,"chain_id":chain,
            "network_id":context.network_id,"purpose":"transaction-signing"}],
        "current_auth_key_hash":hash(&spending.public_key),"auth_key_history":[],"supersession_history":[],
        "effective_at":effective,"binding_payload_sha3_256":"",
        "proofs":{"identity_root":{"algorithm":"FN-DSA-1024","signature":""}}
    })).map_err(|_| "Cannot form ordinary authorization")?;
    let payload = canonical_binding_payload(&binding)?;
    binding.binding_payload_sha3_256 = hash(&payload);
    let message = [AUTH_BINDING_SIGNATURE_DOMAIN, &payload].concat();
    binding.proofs.identity_root.signature = hex(&provider
        .sign(
            Algorithm::FnDsa1024,
            root.private_key.as_bytes(),
            &message,
            SignOptions::default(),
        )
        .map_err(|e| e.to_string())?);
    binding.proofs.authorization_key_possession = vec![AuthorizationKeyPossessionProof {
        principal_id: "treasury".into(),
        algorithm: "ML-DSA-87".into(),
        signature: hex(&provider
            .sign(
                Algorithm::MlDsa87,
                spending.private_key.as_bytes(),
                &message,
                SignOptions::default(),
            )
            .map_err(|e| e.to_string())?),
    }];
    let public = Public {
        address,
        authorization: IdentityAuthorizationCarrier {
            schema_version: AUTHORIZATION_CARRIER_SCHEMA_VERSION,
            signature_domain: AEGIS_TRANSACTION_AUTHORIZATION_DOMAIN.into(),
            binding,
        },
    };
    let public_raw = encode(&public)?;
    let custody = Custody {
        version: 1,
        role: ROLE.into(),
        formation: context,
        request_sha256: request_pin.into(),
        public_sha256: digest(&public_raw),
        identity: encrypt_with_passphrase(
            &provider,
            &Primitives,
            root.private_key.as_bytes(),
            passphrase(&unlock)?,
        )?,
        spending: encrypt_with_passphrase(
            &provider,
            &Primitives,
            spending.private_key.as_bytes(),
            passphrase(&unlock)?,
        )?,
    };
    drop(provider);
    write(&directory.join("treasury-public.json"), &public_raw)?;
    write(&directory.join("treasury.enc.json"), &encode(&custody)?)?;
    write(&directory.join("unlock"), unlock.as_bytes())?;
    sync(directory)?;
    status(context_path, context_pin, directory, engine, false)
}

pub fn status(
    context_path: &Path,
    context_pin: &str,
    directory: &Path,
    engine: crate::provider::Engine,
    export: bool,
) -> Result<Value, String> {
    private_dir(directory)?;
    let context = crate::validator_formation::pinned_context(context_path, context_pin)?;
    let custody: Custody = decode(&read(&directory.join("treasury.enc.json"), LIMIT, true)?)?;
    let (request, _) = request(
        &directory.join("request.json"),
        &custody.request_sha256,
        context_pin,
    )?;
    let raw = read(&directory.join("treasury-public.json"), LIMIT, true)?;
    let public: Public = decode(&raw)?;
    if custody.version != 1
        || custody.role != ROLE
        || custody.formation != context
        || custody.public_sha256 != digest(raw.as_bytes())
    {
        return Err("Ordinary treasury custody scope differs".into());
    }
    let chain = u64::from_str_radix(&context.chain_id_hex, 16)
        .map_err(|_| "Treasury chain exceeds supported u64")?;
    let binding = &public.authorization.binding;
    let root = synergy_address_engine::snts07::decode_lower_hex(
        "ordinary identity",
        &binding.identity_root.public_key,
        1793,
    )?;
    let principals = &binding.authorization_policy.principals;
    if principals.len() != 1
        || principals[0].principal_id != "treasury"
        || binding.identity_address != public.address
        || !public.address.starts_with("syna")
    {
        return Err("Ordinary treasury public identity differs".into());
    }
    let spending = synergy_address_engine::snts07::decode_lower_hex(
        "ordinary spending key",
        principals[0]
            .public_key
            .as_deref()
            .ok_or("Treasury key absent")?,
        2592,
    )?;
    let verifier = synergy_aegis::ApqeIdentityVerifier::new(engine.clone())?;
    resolve_transaction_binding_with_verifier(
        &std::collections::BTreeMap::from([(
            IDENTITY_AUTHORIZATION_BINDINGS_STATE_KEY.into(), b"{}".to_vec(),
        )]),
        &public.address,
        &public.authorization,
        &spending,
        chain,
        &context.network_id,
        request.parameters.effective_at_unix,
        Some(&verifier),
    )?;
    let unlock = read(&directory.join("unlock"), 64, true)?;
    let provider = engine.lock().map_err(|_| "APQE provider unavailable")?;
    // Fresh possession challenges tie BOTH encrypted keys to the verified public carrier.
    let challenge = format!(
        "SYNERGY-ORDINARY-TREASURY-CUSTODY-V1\0{}\0{}",
        custody.request_sha256, custody.public_sha256
    );
    for (algorithm, envelope, key) in [
        (Algorithm::FnDsa1024, &custody.identity, &root),
        (Algorithm::MlDsa87, &custody.spending, &spending),
    ] {
        let secret = SecretBytes::from_bytes(decrypt_with_passphrase(
            &provider,
            &Primitives,
            envelope,
            passphrase(&unlock)?,
        )?);
        let proof = provider
            .sign(
                algorithm,
                secret.as_bytes(),
                challenge.as_bytes(),
                SignOptions::default(),
            )
            .map_err(|e| e.to_string())?;
        if !provider
            .verify(
                algorithm,
                key,
                challenge.as_bytes(),
                &proof,
                SignOptions::default(),
            )
            .map_err(|e| e.to_string())?
        {
            return Err("Ordinary treasury custody possession failed".into());
        }
    }
    let mut result = json!({"schema":"nodenetwork-formation-treasury-v1","pending":true,
        "address":public.address,"network_id":context.network_id,"chain_id":chain.to_string(),
        "formation_sha256":context_pin,"request_sha256":custody.request_sha256,
        "effective_at_unix":request.parameters.effective_at_unix,"authorization_sha256":digest(&serde_json::to_vec(&serde_json::to_value(&public.authorization).map_err(|_|"Cannot encode public authorization")?).map_err(|_|"Cannot encode public authorization")?),
        "possession_verified":true,"allocation_nwei":"5000000000000000"});
    if export {
        result["schema"] = "nodenetwork-formation-treasury-export-v1".into();
        result["canary_testing_treasury"] =
            serde_json::to_value(public).map_err(|_| "Cannot export public treasury")?;
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs,
        os::unix::fs::{DirBuilderExt, PermissionsExt},
    };

    #[test]
    #[ignore = "requires the independently authenticated native APQE provider"]
    fn ordinary_treasury_custody_roundtrip_and_scope_fail_closed() {
        let base = std::env::temp_dir()
            .canonicalize()
            .unwrap()
            .join(format!("formation-treasury-{}", std::process::id()));
        fs::DirBuilder::new().mode(0o700).create(&base).unwrap();
        struct Cleanup(std::path::PathBuf);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                let _ = fs::remove_dir_all(&self.0);
            }
        }
        let _cleanup = Cleanup(base.clone());
        let context = FormationContext {
            network_id: "new-treasury-fixture".into(),
            chain_id_hex: format!("{:064x}", 99999),
            formation_id: "a".repeat(64),
        };
        let context_path = base.join("context.json");
        let raw = encode(&context).unwrap();
        let pin = digest(&raw);
        write(&context_path, &raw).unwrap();
        let req = json!({"version":1,"operation":"treasury_prepare","parameters":{"formation_sha256":pin,"effective_at_unix":1700000000}});
        let request_path = base.join("approved.json");
        let raw = serde_json::to_vec(&req).unwrap();
        let request_pin = digest(&raw);
        write(&request_path, &raw).unwrap();
        let engine = crate::provider::native_test_engine();
        let dir = base.join("custody");
        assert!(prepare(
            &context_path,
            &pin,
            &request_path,
            &"0".repeat(64),
            &dir,
            engine.clone()
        )
        .is_err());
        assert!(!dir.exists());
        let first = prepare(
            &context_path,
            &pin,
            &request_path,
            &request_pin,
            &dir,
            engine.clone(),
        )
        .unwrap();
        assert_eq!(first["possession_verified"], true);
        assert!(first["address"].as_str().unwrap().starts_with("syna"));
        assert_eq!(
            status(&context_path, &pin, &dir, engine.clone(), false).unwrap(),
            first
        );
        assert!(prepare(
            &context_path,
            &pin,
            &request_path,
            &request_pin,
            &dir,
            engine.clone()
        )
        .is_err());
        let export = status(&context_path, &pin, &dir, engine.clone(), true).unwrap();
        assert_eq!(
            export["canary_testing_treasury"]["address"],
            first["address"]
        );
        assert_eq!(
            export["authorization_sha256"],
            digest(
                &serde_json::to_vec(&export["canary_testing_treasury"]["authorization"]).unwrap()
            )
        );
        crate::prepare_authority::qualify_treasury_allocation(
            export["canary_testing_treasury"].clone(),
            engine.clone(),
        );
        assert!(!serde_json::to_string(&export).unwrap().contains("PRIVATE"));
        let public_raw = fs::read(dir.join("treasury-public.json")).unwrap();
        let mut changed: Value = serde_json::from_slice(&public_raw).unwrap();
        changed["address"] = "synw1forged".into();
        fs::write(dir.join("treasury-public.json"), encode(&changed).unwrap()).unwrap();
        assert!(status(&context_path, &pin, &dir, engine.clone(), true).is_err());
        fs::write(dir.join("treasury-public.json"), public_raw).unwrap();
        let mut other = context;
        other.formation_id = "b".repeat(64);
        let other_raw = encode(&other).unwrap();
        let other_path = base.join("other.json");
        write(&other_path, &other_raw).unwrap();
        assert!(status(
            &other_path,
            &digest(&other_raw),
            &dir,
            engine.clone(),
            false
        )
        .is_err());
        let unlock = fs::read(dir.join("unlock")).unwrap();
        fs::write(dir.join("unlock"), vec![b'0'; 64]).unwrap();
        assert!(status(&context_path, &pin, &dir, engine.clone(), false).is_err());
        fs::write(dir.join("unlock"), unlock).unwrap();
        fs::set_permissions(dir.join("unlock"), fs::Permissions::from_mode(0o644)).unwrap();
        assert!(status(&context_path, &pin, &dir, engine.clone(), false).is_err());
        fs::set_permissions(dir.join("unlock"), fs::Permissions::from_mode(0o600)).unwrap();
        fs::remove_file(dir.join("treasury.enc.json")).unwrap();
        assert!(status(&context_path, &pin, &dir, engine, false).is_err());
    }
}
