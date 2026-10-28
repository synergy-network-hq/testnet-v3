//! Signs a prebuilt immutable-Genesis P1 activation record with the existing
//! release/start Governance Authority. No fallback signer is permitted.

use base64::{engine::general_purpose, Engine as _};
use pqsynq::Sign;
use std::env;
use std::fs;
use std::path::PathBuf;
use synergy_testnet::consensus_activation::{
    build_consensus_activation_manifest, consensus_activation_signature_request,
    ConsensusActivationManifest, SignedConsensusActivationManifest,
    CHAIN1266_CONSENSUS_ACTIVATION_SIGNATURE_DOMAIN,
};
use synergy_testnet::desired_state::verify_signed_desired_state_file;
use synergy_testnet::genesis::load_genesis_from_path;

fn fail(message: impl AsRef<str>) -> ! {
    eprintln!("sign-chain1266-consensus-activation: {}", message.as_ref());
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
    let activation_path = PathBuf::from(arg(&args, "--activation"));
    let desired_state = PathBuf::from(arg(&args, "--desired-state"));
    let desired_state_signature = PathBuf::from(arg(&args, "--desired-state-signature"));
    let genesis_path = PathBuf::from(arg(&args, "--genesis"));
    let private_key = PathBuf::from(arg(&args, "--private-key"));
    let output = PathBuf::from(arg(&args, "--output"));
    // The activation can only be signed after the exact desired state it names
    // is already signed and independently verified with the frozen authority.
    verify_signed_desired_state_file(&desired_state, &desired_state_signature)
        .unwrap_or_else(|error| fail(format!("verify desired-state authorization: {error}")));
    let activation: ConsensusActivationManifest = serde_json::from_slice(
        &fs::read(&activation_path)
            .unwrap_or_else(|error| fail(format!("read {}: {error}", activation_path.display()))),
    )
    .unwrap_or_else(|error| fail(format!("parse strict activation: {error}")));
    let genesis = load_genesis_from_path(genesis_path)
        .unwrap_or_else(|error| fail(format!("load immutable canonical Genesis: {error}")));
    let expected = build_consensus_activation_manifest(&desired_state, &genesis)
        .unwrap_or_else(|error| fail(format!("rebuild activation from desired state: {error}")));
    if activation != expected {
        fail("activation differs from the immutable-Genesis desired-state binding");
    }
    let private_key = general_purpose::STANDARD
        .decode(
            fs::read_to_string(&private_key)
                .unwrap_or_else(|error| fail(format!("read private key: {error}")))
                .trim(),
        )
        .unwrap_or_else(|error| fail(format!("decode ML-DSA-87 private key: {error}")));
    let request = consensus_activation_signature_request(activation);
    let signature = Sign::mldsa87()
        .sign_ctx(
            &serde_json::to_vec(&request)
                .unwrap_or_else(|error| fail(format!("encode activation request: {error}"))),
            &private_key,
            CHAIN1266_CONSENSUS_ACTIVATION_SIGNATURE_DOMAIN.as_bytes(),
        )
        .unwrap_or_else(|error| fail(format!("sign consensus activation: {error}")));
    let signed = SignedConsensusActivationManifest {
        request,
        signature_base64: general_purpose::STANDARD.encode(signature),
    };
    if let Some(parent) = output.parent() {
        fs::create_dir_all(parent)
            .unwrap_or_else(|error| fail(format!("create {}: {error}", parent.display())));
    }
    let mut encoded = serde_json::to_vec_pretty(&signed)
        .unwrap_or_else(|error| fail(format!("encode signed activation: {error}")));
    encoded.push(b'\n');
    fs::write(&output, encoded)
        .unwrap_or_else(|error| fail(format!("write {}: {error}", output.display())));
    println!("CHAIN1266_CONSENSUS_ACTIVATION_SIGNED {}", output.display());
}
