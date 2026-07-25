use aegis_pqvm::mldsa::mldsa87::{self, DetachedSignature, PublicKey, SecretKey};
use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine as _};
use pqrust_traits::sign::{
    DetachedSignature as DetachedSignatureTrait, PublicKey as PublicKeyTrait,
    SecretKey as SecretKeyTrait,
};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::env;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

const IDENTITY_SCHEMA: &str = "synergy-aegis-archive-identity-v2";
const SIGNATURE_SCHEMA: &str = "synergy-aegis-detached-json-signature-v2";
const ALGORITHM: &str = "ML-DSA-87";
const SIGNING_PREFIX: &[u8] = b"SYNERGY_AEGIS_ARCHIVE_JSON_V2\0";

#[derive(Debug, Deserialize, Serialize)]
struct ArchiveIdentity {
    schema: String,
    algorithm: String,
    key_id: String,
    public_key_base64: String,
    secret_key_base64: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct DetachedJsonSignatureProof {
    schema: String,
    algorithm: String,
    domain: String,
    payload_sha256: String,
    key_id: String,
    public_key_base64: String,
    signature_base64: String,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("synergy-aegis: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let args = env::args().skip(1).collect::<Vec<_>>();
    let command = args
        .first()
        .map(String::as_str)
        .ok_or_else(|| usage().to_string())?;
    match command {
        "--version" | "version" => {
            println!("synergy-aegis 19.0.0 (Aegis-PQC {ALGORITHM})");
            Ok(())
        }
        "init-archive-identity" => init_archive_identity(&args[1..]),
        "sign-json" => sign_json(&args[1..]),
        "verify-json" => verify_json(&args[1..]),
        _ => Err(usage().to_string()),
    }
}

fn usage() -> &'static str {
    "usage: synergy-aegis <init-archive-identity|sign-json|verify-json|--version>"
}

fn init_archive_identity(args: &[String]) -> Result<(), String> {
    let output = PathBuf::from(required_arg(args, "--output")?);
    if output.exists() {
        return Err(format!(
            "refusing to overwrite existing archive identity {}",
            output.display()
        ));
    }
    let (public_key, secret_key) = mldsa87::keypair();
    let public_key_bytes = public_key.as_bytes();
    let identity = ArchiveIdentity {
        schema: IDENTITY_SCHEMA.to_string(),
        algorithm: ALGORITHM.to_string(),
        key_id: key_id(public_key_bytes),
        public_key_base64: STANDARD_NO_PAD.encode(public_key_bytes),
        secret_key_base64: STANDARD_NO_PAD.encode(secret_key.as_bytes()),
    };
    write_json_new(&output, &identity, true)?;
    println!(
        "{}",
        serde_json::json!({
            "ok": true,
            "algorithm": ALGORITHM,
            "identity_path": output,
            "key_id": identity.key_id,
            "public_key_sha256": sha256_hex(public_key_bytes),
        })
    );
    Ok(())
}

fn sign_json(args: &[String]) -> Result<(), String> {
    let domain = required_arg(args, "--domain")?;
    validate_domain(domain)?;
    let input = PathBuf::from(required_arg(args, "--input")?);
    let output = PathBuf::from(required_arg(args, "--output")?);
    let identity_path = optional_arg(args, "--identity")
        .map(PathBuf::from)
        .or_else(|| env::var_os("SYNERGY_AEGIS_ARCHIVE_IDENTITY").map(PathBuf::from))
        .ok_or_else(|| {
            "sign-json requires --identity or SYNERGY_AEGIS_ARCHIVE_IDENTITY".to_string()
        })?;
    let payload = read_json_payload(&input)?;
    let identity: ArchiveIdentity = read_json(&identity_path)?;
    let (public_key, secret_key) = decode_identity(&identity)?;
    let message = signing_message(domain, &payload);
    let signature = mldsa87::detached_sign(&message, &secret_key);
    mldsa87::verify_detached_signature(&signature, &message, &public_key).map_err(|error| {
        format!("archive identity public key does not verify its signature: {error}")
    })?;
    let proof = DetachedJsonSignatureProof {
        schema: SIGNATURE_SCHEMA.to_string(),
        algorithm: ALGORITHM.to_string(),
        domain: domain.to_string(),
        payload_sha256: sha256_hex(&payload),
        key_id: identity.key_id,
        public_key_base64: STANDARD_NO_PAD.encode(public_key.as_bytes()),
        signature_base64: STANDARD_NO_PAD.encode(signature.as_bytes()),
    };
    write_json_new(&output, &proof, false)?;
    println!(
        "{}",
        serde_json::json!({
            "ok": true,
            "algorithm": ALGORITHM,
            "domain": domain,
            "key_id": proof.key_id,
            "payload_sha256": proof.payload_sha256,
            "public_key_sha256": sha256_hex(public_key.as_bytes()),
        })
    );
    Ok(())
}

fn verify_json(args: &[String]) -> Result<(), String> {
    let domain = required_arg(args, "--domain")?;
    validate_domain(domain)?;
    let input = PathBuf::from(required_arg(args, "--input")?);
    let signature_path = PathBuf::from(required_arg(args, "--signature")?);
    let payload = read_json_payload(&input)?;
    let proof: DetachedJsonSignatureProof = read_json(&signature_path)?;
    if proof.schema != SIGNATURE_SCHEMA || proof.algorithm != ALGORITHM {
        return Err("unsupported Aegis detached JSON signature schema or algorithm".to_string());
    }
    if proof.domain != domain {
        return Err("signature domain mismatch".to_string());
    }
    let payload_sha256 = sha256_hex(&payload);
    if proof.payload_sha256 != payload_sha256 {
        return Err("signed JSON payload hash mismatch".to_string());
    }
    let public_key_bytes = decode_base64("signature public key", &proof.public_key_base64)?;
    if proof.key_id != key_id(&public_key_bytes) {
        return Err("signature key identifier does not match the public key".to_string());
    }
    if let Some(expected) = optional_arg(args, "--expected-signer-sha256") {
        if !sha256_hex(&public_key_bytes).eq_ignore_ascii_case(expected) {
            return Err("archive authority public identity SHA256 mismatch".to_string());
        }
    }
    let public_key = PublicKey::from_bytes(&public_key_bytes)
        .map_err(|error| format!("invalid ML-DSA-87 public key: {error}"))?;
    let signature_bytes = decode_base64("signature", &proof.signature_base64)?;
    let signature = DetachedSignature::from_bytes(&signature_bytes)
        .map_err(|error| format!("invalid ML-DSA-87 signature: {error}"))?;
    let message = signing_message(domain, &payload);
    mldsa87::verify_detached_signature(&signature, &message, &public_key)
        .map_err(|error| format!("Aegis ML-DSA-87 signature verification failed: {error}"))?;
    println!(
        "{}",
        serde_json::json!({
            "ok": true,
            "algorithm": ALGORITHM,
            "domain": domain,
            "key_id": proof.key_id,
            "payload_sha256": payload_sha256,
            "public_key_sha256": sha256_hex(public_key.as_bytes()),
            "canonical_aegis_pqc": true,
        })
    );
    Ok(())
}

fn decode_identity(identity: &ArchiveIdentity) -> Result<(PublicKey, SecretKey), String> {
    if identity.schema != IDENTITY_SCHEMA || identity.algorithm != ALGORITHM {
        return Err("unsupported archive identity schema or algorithm".to_string());
    }
    let public_key_bytes = decode_base64("identity public key", &identity.public_key_base64)?;
    if identity.key_id != key_id(&public_key_bytes) {
        return Err("archive identity key identifier does not match the public key".to_string());
    }
    let public_key = PublicKey::from_bytes(&public_key_bytes)
        .map_err(|error| format!("invalid identity ML-DSA-87 public key: {error}"))?;
    let secret_key_bytes = decode_base64("identity secret key", &identity.secret_key_base64)?;
    let secret_key = SecretKey::from_bytes(&secret_key_bytes)
        .map_err(|error| format!("invalid identity ML-DSA-87 secret key: {error}"))?;
    Ok((public_key, secret_key))
}

fn read_json_payload(path: &Path) -> Result<Vec<u8>, String> {
    let payload =
        fs::read(path).map_err(|error| format!("failed to read {}: {error}", path.display()))?;
    serde_json::from_slice::<serde_json::Value>(&payload)
        .map_err(|error| format!("{} is not valid JSON: {error}", path.display()))?;
    Ok(payload)
}

fn read_json<T: DeserializeOwned>(path: &Path) -> Result<T, String> {
    let contents =
        fs::read(path).map_err(|error| format!("failed to read {}: {error}", path.display()))?;
    serde_json::from_slice(&contents)
        .map_err(|error| format!("failed to parse {}: {error}", path.display()))
}

fn write_json_new<T: Serialize>(path: &Path, value: &T, private: bool) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| format!("{} has no parent directory", path.display()))?;
    fs::create_dir_all(parent)
        .map_err(|error| format!("failed to create {}: {error}", parent.display()))?;
    let payload = serde_json::to_vec_pretty(value)
        .map_err(|error| format!("failed to serialize JSON output: {error}"))?;
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(if private { 0o600 } else { 0o644 });
    }
    let mut file = options
        .open(path)
        .map_err(|error| format!("failed to create {}: {error}", path.display()))?;
    file.write_all(&payload)
        .and_then(|_| file.write_all(b"\n"))
        .and_then(|_| file.sync_all())
        .map_err(|error| format!("failed to write {}: {error}", path.display()))
}

fn signing_message(domain: &str, payload: &[u8]) -> Vec<u8> {
    let payload_digest = Sha256::digest(payload);
    let mut message =
        Vec::with_capacity(SIGNING_PREFIX.len() + domain.len() + payload_digest.len() + 1);
    message.extend_from_slice(SIGNING_PREFIX);
    message.extend_from_slice(domain.as_bytes());
    message.push(0);
    message.extend_from_slice(&payload_digest);
    message
}

fn key_id(public_key: &[u8]) -> String {
    format!("mldsa87-sha256:{}", sha256_hex(public_key))
}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn decode_base64(label: &str, value: &str) -> Result<Vec<u8>, String> {
    STANDARD_NO_PAD
        .decode(value)
        .map_err(|error| format!("invalid {label} base64: {error}"))
}

fn required_arg<'a>(args: &'a [String], name: &str) -> Result<&'a str, String> {
    optional_arg(args, name).ok_or_else(|| format!("missing required argument {name}"))
}

fn optional_arg<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    args.windows(2)
        .find_map(|pair| (pair[0] == name).then_some(pair[1].as_str()))
}

fn validate_domain(domain: &str) -> Result<(), String> {
    if domain.is_empty()
        || domain.len() > 128
        || !domain.bytes().all(|byte| {
            byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_' || byte == b'-'
        })
    {
        return Err(
            "signature domain must contain only ASCII uppercase letters, digits, '_' or '-'"
                .to_string(),
        );
    }
    Ok(())
}
