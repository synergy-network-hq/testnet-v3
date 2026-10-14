//! Signs one Synergy Testnet v3 faucet transfer using the Genesis custody key.
//! Key material enters on stdin and never appears in process arguments or stdout.

use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde::Deserialize;
use serde_json::json;
use std::io::{self, Read};
use synergy_testnet::aegis_tx_tool::{
    legacy_transaction_from_aegis_envelope, AegisTxSubmissionEnvelope,
    TESTNET_V3_FAUCET_ADDRESS,
};
use synergy_testnet::address::address_matches_public_key;
use synergy_testnet::crypto::aegis_pqvm::{AegisPqvmSigner, AegisPqvmVerifier};
use synergy_testnet::crypto::pqc::{PQCAlgorithm, PQCPrivateKey, PQCPublicKey};
use synergy_testnet::synergy_types::{
    AegisPqKeyId, AegisPqKeyRole, AegisPqSignature, ChainId, Epoch, Height,
    NetworkId, Transaction, UmaId,
};

const FAUCET_UMA: &str = "tnv3-eco-faucet";
const FAUCET_KEY_ID: &str = "tnv3-eco-faucet-fndsa";
const MAX_PAYOUT_NWEI: u128 = 10_000_000_000;

#[derive(Deserialize)]
struct SignRequest {
    public_key_b64: String,
    private_key_b64: String,
    receiver: String,
    nonce: u64,
    amount_nwei: u128,
    ttl_height: u64,
}

fn run() -> Result<(), String> {
    let mut input = String::new();
    io::stdin()
        .take(128 * 1024)
        .read_to_string(&mut input)
        .map_err(|error| format!("read signing request: {error}"))?;
    let request: SignRequest =
        serde_json::from_str(&input).map_err(|error| format!("parse signing request: {error}"))?;
    if request.amount_nwei == 0 || request.amount_nwei > MAX_PAYOUT_NWEI {
        return Err("faucet amount is outside the authorized payout range".to_string());
    }
    if !request.receiver.starts_with("synw1")
        || !synergy_testnet::address::is_valid_address(&request.receiver)
    {
        return Err("recipient must be a canonical synw wallet address".to_string());
    }
    let public_bytes = STANDARD
        .decode(&request.public_key_b64)
        .map_err(|error| format!("decode faucet public key: {error}"))?;
    let private_bytes = STANDARD
        .decode(&request.private_key_b64)
        .map_err(|error| format!("decode faucet private key: {error}"))?;
    if !address_matches_public_key(TESTNET_V3_FAUCET_ADDRESS, &public_bytes) {
        return Err("custody key does not match the signed Genesis faucet address".to_string());
    }
    let mut signer = AegisPqvmSigner::initialize_required().map_err(|error| error.to_string())?;
    let public_key = PQCPublicKey {
        algorithm: PQCAlgorithm::FNDSA,
        key_data: public_bytes,
        key_id: FAUCET_KEY_ID.to_string(),
        created_at: 0,
    };
    let private_key = PQCPrivateKey {
        algorithm: PQCAlgorithm::FNDSA,
        key_data: private_bytes,
        public_key_id: FAUCET_KEY_ID.to_string(),
        created_at: 0,
    };
    let key_id = signer.registry.register_keypair(
        FAUCET_UMA,
        public_key,
        private_key,
        vec![AegisPqKeyRole::Transaction],
        Epoch(0),
    );
    let mut transaction = Transaction {
        version: 1,
        chain_id: ChainId::synergy_testnet_v3(),
        network_id: NetworkId::synergy_testnet_v3(),
        epoch: Epoch(0),
        sender_uma_or_account: TESTNET_V3_FAUCET_ADDRESS.to_string(),
        receiver_uma_or_account: request.receiver,
        account_nonce_or_sequence: request.nonce,
        amount_nwei: request.amount_nwei,
        gas_limit: 400_000,
        max_fee_nwei: 40,
        ttl_height: Height(request.ttl_height),
        explicit_dependencies: vec![],
        read_set_hint: vec![],
        write_set_hint: vec![],
        payload: vec![],
        signer_uma_id: UmaId(FAUCET_UMA.to_string()),
        aegis_pq_key_id: AegisPqKeyId(key_id.0.clone()),
        aegis_pq_signature: AegisPqSignature {
            algorithm: String::new(),
            signature_bytes: vec![],
        },
    };
    transaction.aegis_pq_signature = signer
        .sign_transaction(&transaction.signing_bytes()?, &key_id)
        .map_err(|error| error.to_string())?;
    let verifier: AegisPqvmVerifier = signer.verifier();
    verifier
        .verify_transaction_signature_checked(&transaction)
        .map_err(|error| error.to_string())?;
    let public_key = signer
        .public_key_record(&key_id)
        .map_err(|error| error.to_string())?;
    let lifecycle_record = signer
        .registry
        .lifecycle
        .record_for(FAUCET_UMA, &key_id)
        .cloned()
        .ok_or_else(|| "faucet key lifecycle is unavailable".to_string())?;
    let envelope = AegisTxSubmissionEnvelope {
        transaction,
        public_key,
        lifecycle_record,
    };
    let carrier = legacy_transaction_from_aegis_envelope(&envelope)?;
    println!(
        "{}",
        json!({
            "chain_id": 1266,
            "sender": TESTNET_V3_FAUCET_ADDRESS,
            "receiver": carrier.receiver,
            "nonce": carrier.nonce,
            "amount_nwei": carrier.amount,
            "tx_hash": carrier.hash(),
            "submission_envelope": envelope,
        })
    );
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("faucet signer: {error}");
        std::process::exit(1);
    }
}
