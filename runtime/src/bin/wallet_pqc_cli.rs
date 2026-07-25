use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::Aes256Gcm;
use base64::{engine::general_purpose, Engine as _};
use rand::RngCore;
use sha3::{Digest, Sha3_256};
use std::env;

use pqcrypto_mlkem::mlkem1024;
use pqcrypto_traits::kem::{
    Ciphertext as KemCiphertext, PublicKey as KemPublicKey, SecretKey as KemSecretKey,
    SharedSecret as KemSharedSecret,
};

use synergy_testnet::crypto::pqc::{PQCAlgorithm, PQCManager, PQCPrivateKey};
use synergy_testnet::transaction::Transaction;

fn usage() {
    eprintln!(
        "wallet-pqc-cli

Usage:
  wallet-pqc-cli gen-keypair [--algo fndsa]
      Generate a real FN-DSA Aegis PQC signing keypair and emit public/private key material as base64.

  wallet-pqc-cli passcode --passcode <secret> --mnemonic <bip39 words>
      Derive ML-KEM-1024 keypair, encapsulate, and seal the passcode with AES-GCM using SHA3-256(shared_secret || mnemonic).

  wallet-pqc-cli sign-tx --private-key <hex> --tx '<json>' [--algo fndsa]
      Sign a Synergy transaction payload with the provided FN-DSA-1024 (default) private key and emit a signed transaction JSON.

  wallet-pqc-cli sign-message --private-key-b64 <base64> --message <text> [--algo fndsa]
      Sign arbitrary UTF-8 message bytes and emit detached signature JSON (base64 + hex).
"
    );
}

fn encrypt_passcode(passcode: &str, mnemonic: &str) -> Result<(), String> {
    let (kem_pk, kem_sk) = mlkem1024::keypair();
    let (kem_ct, shared_secret) = mlkem1024::encapsulate(&kem_pk);

    let mut hasher = Sha3_256::new();
    hasher.update(shared_secret.as_bytes());
    hasher.update(mnemonic.as_bytes());
    let key_material = hasher.finalize();

    let cipher = Aes256Gcm::new_from_slice(&key_material[..32])
        .map_err(|e| format!("Failed to initialise AES-GCM: {e}"))?;

    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let sealed = cipher
        .encrypt(&nonce_bytes.into(), passcode.as_bytes())
        .map_err(|e| format!("Failed to encrypt passcode: {e}"))?;

    let output = serde_json::json!({
        "algorithm": "ML-KEM-1024",
        "kem_public_key": general_purpose::STANDARD.encode(kem_pk.as_bytes()),
        "kem_private_key": general_purpose::STANDARD.encode(kem_sk.as_bytes()),
        "kem_ciphertext": general_purpose::STANDARD.encode(kem_ct.as_bytes()),
        "enc_nonce": general_purpose::STANDARD.encode(nonce_bytes),
        "encrypted_passcode": general_purpose::STANDARD.encode(sealed),
        "key_derivation": "AES-256-GCM key = SHA3-256(shared_secret || mnemonic)"
    });

    println!(
        "{}",
        serde_json::to_string_pretty(&output).unwrap_or_else(|_| "{}".into())
    );
    Ok(())
}

fn parse_algorithm(value: Option<&String>) -> Result<PQCAlgorithm, String> {
    let Some(value) = value else {
        return Ok(PQCAlgorithm::FNDSA);
    };

    match value.trim().to_ascii_lowercase().as_str() {
        "" | "fndsa" | "fn-dsa" | "fn-dsa-512" | "fn-dsa-1024" | "falcon" | "falcon-1024" => {
            Ok(PQCAlgorithm::FNDSA)
        }
        "slhdsa" | "slh-dsa" => Err(format!(
            "unsupported PQC signing algorithm '{}'; use fndsa",
            value
        )),
        "pqc" | "aegis" => Err(format!(
            "ambiguous PQC signing algorithm '{}'; use fndsa",
            value
        )),
        other => Err(format!("unsupported PQC signing algorithm '{other}'")),
    }
}

fn generate_keypair(algorithm: PQCAlgorithm) -> Result<(), String> {
    let mut manager = PQCManager::new();
    let (public_key, private_key) = manager.generate_keypair(algorithm.clone())?;
    let output = serde_json::json!({
        "algorithm": format!("{:?}", algorithm),
        "key_id": public_key.key_id,
        "public_key_base64": general_purpose::STANDARD.encode(&public_key.key_data),
        "private_key_base64": general_purpose::STANDARD.encode(&private_key.key_data),
    });
    println!(
        "{}",
        serde_json::to_string_pretty(&output).unwrap_or_else(|_| "{}".into())
    );
    Ok(())
}

fn sign_transaction(
    private_hex: &str,
    tx_json: &str,
    algorithm: PQCAlgorithm,
) -> Result<(), String> {
    let mut tx: Transaction =
        serde_json::from_str(tx_json).map_err(|e| format!("Invalid transaction JSON: {e}"))?;

    let sk_bytes = hex::decode(private_hex).map_err(|e| format!("Private key must be hex: {e}"))?;

    let key = PQCPrivateKey {
        algorithm: algorithm.clone(),
        key_data: sk_bytes,
        public_key_id: tx.sender.clone(),
        created_at: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    };

    let mut manager = PQCManager::new();
    tx.sign(&key, &mut manager)?;

    let output = serde_json::json!({
        "algorithm": format!("{:?}", algorithm),
        "signature_hex": hex::encode(&tx.signature),
        "transaction": tx,
    });

    println!(
        "{}",
        serde_json::to_string_pretty(&output).unwrap_or_else(|_| "{}".into())
    );
    Ok(())
}

fn sign_message(private_b64: &str, message: &str, algorithm: PQCAlgorithm) -> Result<(), String> {
    let sk_bytes = general_purpose::STANDARD
        .decode(private_b64)
        .map_err(|e| format!("Private key must be base64: {e}"))?;

    let key = PQCPrivateKey {
        algorithm: algorithm.clone(),
        key_data: sk_bytes,
        public_key_id: "cli-sign-message".to_string(),
        created_at: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    };

    let mut manager = PQCManager::new();
    let signature = manager.sign(&key, message.as_bytes())?;

    let output = serde_json::json!({
        "algorithm": format!("{:?}", algorithm),
        "message": message,
        "message_hex": hex::encode(message.as_bytes()),
        "signature_base64": general_purpose::STANDARD.encode(&signature.signature_data),
        "signature_hex": hex::encode(&signature.signature_data),
    });

    println!(
        "{}",
        serde_json::to_string_pretty(&output).unwrap_or_else(|_| "{}".into())
    );
    Ok(())
}

fn main() {
    let mut args = env::args().skip(1).collect::<Vec<_>>();
    if args.is_empty() || args.iter().any(|a| a == "--help" || a == "-h") {
        usage();
        return;
    }

    let command = args.remove(0);
    match command.as_str() {
        "gen-keypair" => {
            let algo_idx = args.iter().position(|a| a == "--algo");
            let algorithm = parse_algorithm(algo_idx.and_then(|idx| args.get(idx + 1)))
                .unwrap_or_else(|err| {
                    eprintln!("Error: {err}");
                    std::process::exit(1);
                });
            if let Err(err) = generate_keypair(algorithm) {
                eprintln!("Error: {err}");
                std::process::exit(1);
            }
        }
        "passcode" => {
            let passcode_idx = args.iter().position(|a| a == "--passcode");
            let mnemonic_idx = args.iter().position(|a| a == "--mnemonic");

            if let (Some(p_idx), Some(m_idx)) = (passcode_idx, mnemonic_idx) {
                let passcode = args.get(p_idx + 1).cloned().unwrap_or_default();
                let mnemonic = args.get(m_idx + 1).cloned().unwrap_or_default();
                if passcode.is_empty() || mnemonic.is_empty() {
                    eprintln!("passcode and mnemonic are required");
                    std::process::exit(1);
                }
                if let Err(err) = encrypt_passcode(&passcode, &mnemonic) {
                    eprintln!("Error: {err}");
                    std::process::exit(1);
                }
            } else {
                usage();
                std::process::exit(1);
            }
        }

        "sign-tx" => {
            let pk_idx = args.iter().position(|a| a == "--private-key");
            let tx_idx = args.iter().position(|a| a == "--tx");
            let algo_idx = args.iter().position(|a| a == "--algo");

            if let (Some(pk_pos), Some(tx_pos)) = (pk_idx, tx_idx) {
                let private_hex = args.get(pk_pos + 1).cloned().unwrap_or_default();
                let tx_json = args.get(tx_pos + 1).cloned().unwrap_or_default();
                let algo =
                    parse_algorithm(algo_idx.and_then(|i| args.get(i + 1))).unwrap_or_else(|err| {
                        eprintln!("Error: {err}");
                        std::process::exit(1);
                    });

                if private_hex.is_empty() || tx_json.is_empty() {
                    eprintln!("private-key and tx payload are required");
                    std::process::exit(1);
                }

                if let Err(err) = sign_transaction(&private_hex, &tx_json, algo) {
                    eprintln!("Error: {err}");
                    std::process::exit(1);
                }
            } else {
                usage();
                std::process::exit(1);
            }
        }
        "sign-message" => {
            let pk_idx = args.iter().position(|a| a == "--private-key-b64");
            let msg_idx = args.iter().position(|a| a == "--message");
            let algo_idx = args.iter().position(|a| a == "--algo");

            if let (Some(pk_pos), Some(msg_pos)) = (pk_idx, msg_idx) {
                let private_b64 = args.get(pk_pos + 1).cloned().unwrap_or_default();
                let message = args.get(msg_pos + 1).cloned().unwrap_or_default();
                let algo =
                    parse_algorithm(algo_idx.and_then(|i| args.get(i + 1))).unwrap_or_else(|err| {
                        eprintln!("Error: {err}");
                        std::process::exit(1);
                    });

                if private_b64.is_empty() || message.is_empty() {
                    eprintln!("private-key-b64 and message are required");
                    std::process::exit(1);
                }

                if let Err(err) = sign_message(&private_b64, &message, algo) {
                    eprintln!("Error: {err}");
                    std::process::exit(1);
                }
            } else {
                usage();
                std::process::exit(1);
            }
        }
        _ => {
            usage();
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(value: &str) -> Result<PQCAlgorithm, String> {
        parse_algorithm(Some(&value.to_string()))
    }

    #[test]
    fn wallet_cli_normalizes_fndsa_aliases() {
        assert_eq!(parse_algorithm(None).unwrap(), PQCAlgorithm::FNDSA);
        assert_eq!(parse("fndsa").unwrap(), PQCAlgorithm::FNDSA);
        assert_eq!(parse("fn-dsa").unwrap(), PQCAlgorithm::FNDSA);
        assert_eq!(parse("falcon").unwrap(), PQCAlgorithm::FNDSA);
    }

    #[test]
    fn wallet_cli_rejects_ambiguous_or_unknown_algorithms() {
        assert!(parse("unsupported-signature").is_err());
        assert!(parse("slhdsa").is_err());
        assert!(parse("pqc").is_err());
        assert!(parse("aegis").is_err());
        assert!(parse("not-an-algorithm").is_err());
    }
}
