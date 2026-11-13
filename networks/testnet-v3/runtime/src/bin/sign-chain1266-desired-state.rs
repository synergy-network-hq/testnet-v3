//! Signs one exact Chain 1266 desired-state manifest with the release/start
//! authority. Qualification uses a disposable key; production uses the
//! Governance Authority through its custody signer.

use base64::{engine::general_purpose, Engine as _};
use pqsynq::Sign;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::env;
use std::fs;
use std::path::PathBuf;
use synergy_testnet::desired_state::{
    DesiredStateSignatureRequest, SignedDesiredStateManifest,
    CHAIN1266_DESIRED_STATE_SIGNATURE_DOMAIN,
};

#[derive(Debug, Deserialize)]
struct DesiredStateView {
    release_id: String,
    chain: ChainView,
    start_authority: AuthorityView,
}

#[derive(Debug, Deserialize)]
struct ChainView {
    chain_id: u64,
    incarnation: u64,
    genesis_hash: String,
}

#[derive(Debug, Deserialize)]
struct AuthorityView {
    public_key_fingerprint: String,
}

fn fail(message: impl AsRef<str>) -> ! {
    eprintln!("sign-chain1266-desired-state: {}", message.as_ref());
    std::process::exit(1);
}

fn arg(args: &[String], flag: &str) -> String {
    args.windows(2)
        .find(|pair| pair[0] == flag)
        .map(|pair| pair[1].clone())
        .unwrap_or_else(|| fail(format!("missing {flag} <VALUE>")))
}

fn main() {
    let args = env::args().collect::<Vec<_>>();
    let desired_path = PathBuf::from(arg(&args, "--desired-state"));
    let private_path = PathBuf::from(arg(&args, "--private-key"));
    let output_path = PathBuf::from(arg(&args, "--output"));
    let desired_bytes = fs::read(&desired_path)
        .unwrap_or_else(|error| fail(format!("read {}: {error}", desired_path.display())));
    let desired: DesiredStateView = serde_json::from_slice(&desired_bytes)
        .unwrap_or_else(|error| fail(format!("parse desired state: {error}")));
    let private_key = general_purpose::STANDARD
        .decode(
            fs::read_to_string(&private_path)
                .unwrap_or_else(|error| fail(format!("read {}: {error}", private_path.display())))
                .trim(),
        )
        .unwrap_or_else(|error| fail(format!("decode ML-DSA-87 private key: {error}")));
    let request = DesiredStateSignatureRequest {
        schema_version: 1,
        action: "AUTHORIZE_DESIRED_STATE".to_string(),
        release_id: desired.release_id,
        chain_id: desired.chain.chain_id,
        chain_incarnation: desired.chain.incarnation,
        genesis_hash: desired.chain.genesis_hash,
        desired_state_sha256: hex::encode(Sha256::digest(&desired_bytes)),
        signature_algorithm: "ML-DSA-87".to_string(),
        signature_domain: CHAIN1266_DESIRED_STATE_SIGNATURE_DOMAIN.to_string(),
        authority_public_key_fingerprint: desired.start_authority.public_key_fingerprint,
    };
    let canonical = serde_json::to_vec(&request)
        .unwrap_or_else(|error| fail(format!("encode canonical desired-state request: {error}")));
    let signature = Sign::mldsa87()
        .sign_ctx(
            &canonical,
            &private_key,
            CHAIN1266_DESIRED_STATE_SIGNATURE_DOMAIN.as_bytes(),
        )
        .unwrap_or_else(|error| fail(format!("sign ML-DSA-87 desired state: {error}")));
    let signed = SignedDesiredStateManifest {
        request,
        signature_base64: general_purpose::STANDARD.encode(signature),
    };
    if let Some(parent) = output_path.parent() {
        fs::create_dir_all(parent)
            .unwrap_or_else(|error| fail(format!("create {}: {error}", parent.display())));
    }
    let mut encoded = serde_json::to_vec_pretty(&signed)
        .unwrap_or_else(|error| fail(format!("encode signed desired state: {error}")));
    encoded.push(b'\n');
    fs::write(&output_path, encoded)
        .unwrap_or_else(|error| fail(format!("write {}: {error}", output_path.display())));
    println!("CHAIN1266_DESIRED_STATE_SIGNED {}", output_path.display());
}
