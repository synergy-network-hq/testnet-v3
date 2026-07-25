use crate::crypto::aegis_pqvm::{AegisPqKeyLifecycleRecord, AegisPqvmSigner, AegisPqvmVerifier};
use crate::dag_mempool::{BlockSelectionLimits, DagAdmissionResult, DagMempool};
use crate::synergy_types::{
    AegisPqKeyId, AegisPqKeyRole, AegisPqPublicKey, AegisPqSignature, CanonicalSerialize, ChainId,
    Epoch, Height, NetworkId, Transaction, TxDependency, TxDependencyType, TxId, UmaId,
};
use crate::synq_admission::SynQVerificationSummary;
use base64::{engine::general_purpose, Engine as _};
use serde::{Deserialize, Serialize};
use std::convert::TryFrom;
use std::time::{SystemTime, UNIX_EPOCH};

pub const AEGIS_TX_CARRIER_PREFIX: &str = "aegis-pqvm-tx-v1:";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AegisTxBuildOptions {
    pub signer_uma_id: String,
    pub sender: String,
    pub receiver: String,
    pub nonce: u64,
    pub amount_nwei: u128,
    pub gas_limit: u64,
    pub max_fee_nwei: u128,
    pub ttl_height: u64,
    pub epoch: u64,
    pub read_set_hint: Vec<String>,
    pub write_set_hint: Vec<String>,
    pub explicit_dependencies: Vec<String>,
    pub payload: Vec<u8>,
}

impl Default for AegisTxBuildOptions {
    fn default() -> Self {
        Self {
            signer_uma_id: "aegis-dag-fixture-sender".to_string(),
            sender: "aegis-dag-fixture-sender".to_string(),
            receiver: "aegis-dag-fixture-receiver".to_string(),
            nonce: 0,
            amount_nwei: 1,
            gas_limit: 10,
            max_fee_nwei: 1_000,
            ttl_height: 100,
            epoch: 0,
            read_set_hint: Vec::new(),
            write_set_hint: vec!["fixture-resource".to_string()],
            explicit_dependencies: Vec::new(),
            payload: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AegisSignedTxReport {
    pub tx_id: TxId,
    pub key_id: AegisPqKeyId,
    pub key_role: AegisPqKeyRole,
    pub public_key: AegisPqPublicKey,
    pub lifecycle_record: AegisPqKeyLifecycleRecord,
    pub signature_verification_result: String,
    pub dag_node_id: TxId,
    pub admission_result: DagAdmissionResult,
    pub canonical_tx_bytes_hex: String,
    pub transaction: Transaction,
    pub submission_envelope: AegisTxSubmissionEnvelope,
    pub rpc_transaction: crate::transaction::Transaction,
    pub synq_verification: Option<SynQVerificationSummary>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AegisDagFixtureReport {
    pub chain_id: u64,
    pub network_id: String,
    pub signer_uma_id: String,
    pub key_id: AegisPqKeyId,
    pub key_role: AegisPqKeyRole,
    pub transactions: Vec<AegisSignedTxReport>,
    pub ready_frontier: Vec<TxId>,
    pub selected_ancestor_closed_set: Vec<TxId>,
    pub tx_order_root: String,
    pub dag_frontier_root: String,
    pub atlas_ingestion_status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AegisTxSubmissionEnvelope {
    pub transaction: Transaction,
    pub public_key: AegisPqPublicKey,
    pub lifecycle_record: AegisPqKeyLifecycleRecord,
}

pub fn sign_with_new_aegis_transaction_key(
    mut options: AegisTxBuildOptions,
) -> Result<AegisSignedTxReport, String> {
    let mut signer = AegisPqvmSigner::initialize_required().map_err(|error| error.to_string())?;
    let key_id = signer
        .generate_and_register_key(
            &options.signer_uma_id,
            vec![AegisPqKeyRole::Transaction],
            Epoch(options.epoch),
        )
        .map_err(|error| error.to_string())?;
    apply_generated_address_defaults(&signer, &key_id, &mut options)?;
    let tx = sign_with_existing_aegis_transaction_key(&mut signer, &key_id, options)?;
    let verifier = signer.verifier();
    report_for_transaction(&verifier, tx, key_id)
}

pub fn sign_aegis_transaction_sequence_with_new_key(
    options: Vec<AegisTxBuildOptions>,
    link_explicit_dependencies: bool,
) -> Result<Vec<AegisSignedTxReport>, String> {
    if options.is_empty() {
        return Ok(Vec::new());
    }

    let signer_uma_id = options
        .first()
        .map(|options| options.signer_uma_id.clone())
        .unwrap_or_else(|| AegisTxBuildOptions::default().signer_uma_id);
    let epoch = Epoch(options.first().map(|options| options.epoch).unwrap_or(0));
    let mut signer = AegisPqvmSigner::initialize_required().map_err(|error| error.to_string())?;
    let key_id = signer
        .generate_and_register_key(
            &signer_uma_id,
            vec![AegisPqKeyRole::Transaction],
            epoch.clone(),
        )
        .map_err(|error| error.to_string())?;
    let verifier = signer.verifier();
    let mut mempool = DagMempool::new(&verifier, epoch, Height(0));
    let mut previous_tx_id: Option<TxId> = None;
    let mut reports = Vec::new();

    for mut options in options {
        options.signer_uma_id = signer_uma_id.clone();
        if link_explicit_dependencies {
            if let Some(tx_id) = previous_tx_id.as_ref() {
                options.explicit_dependencies.push(tx_id.0.clone());
            }
        }
        apply_generated_address_defaults(&signer, &key_id, &mut options)?;
        let tx = sign_with_existing_aegis_transaction_key(&mut signer, &key_id, options)?;
        let report =
            report_for_transaction_in_mempool(&verifier, &mut mempool, tx, key_id.clone())?;
        previous_tx_id = Some(report.tx_id.clone());
        reports.push(report);
    }

    Ok(reports)
}

pub fn build_fixture_report() -> Result<AegisDagFixtureReport, String> {
    let signer_uma_id = "aegis-dag-fixture-sender".to_string();
    let mut signer = AegisPqvmSigner::initialize_required().map_err(|error| error.to_string())?;
    let key_id = signer
        .generate_and_register_key(&signer_uma_id, vec![AegisPqKeyRole::Transaction], Epoch(0))
        .map_err(|error| error.to_string())?;
    let independent_uma_id = "aegis-dag-fixture-independent".to_string();
    let independent_key_id = signer
        .generate_and_register_key(
            &independent_uma_id,
            vec![AegisPqKeyRole::Transaction],
            Epoch(0),
        )
        .map_err(|error| error.to_string())?;
    let sender_address = address_for_aegis_key(&signer, &key_id)?;
    let independent_sender_address = address_for_aegis_key(&signer, &independent_key_id)?;
    let receiver_address = crate::address::generate_wallet_address(&format!(
        "aegis-dag-fixture-receiver:{}",
        key_id.0
    ));

    let tx0 = sign_with_existing_aegis_transaction_key(
        &mut signer,
        &key_id,
        AegisTxBuildOptions {
            signer_uma_id: signer_uma_id.clone(),
            sender: sender_address.clone(),
            receiver: receiver_address.clone(),
            nonce: 0,
            write_set_hint: vec!["fixture-account-sequence".to_string()],
            ..AegisTxBuildOptions::default()
        },
    )?;

    let tx0_id = tx_id_from_signed_tx(&signer.verifier(), &tx0)?;
    let tx1 = sign_with_existing_aegis_transaction_key(
        &mut signer,
        &key_id,
        AegisTxBuildOptions {
            signer_uma_id: signer_uma_id.clone(),
            sender: sender_address.clone(),
            receiver: receiver_address.clone(),
            nonce: 1,
            write_set_hint: vec!["fixture-account-sequence".to_string()],
            explicit_dependencies: vec![tx0_id.0.clone()],
            payload: b"explicit dependency on nonce 0".to_vec(),
            ..AegisTxBuildOptions::default()
        },
    )?;

    let tx2 = sign_with_existing_aegis_transaction_key(
        &mut signer,
        &independent_key_id,
        AegisTxBuildOptions {
            signer_uma_id: independent_uma_id,
            sender: independent_sender_address,
            receiver: receiver_address,
            nonce: 0,
            write_set_hint: vec!["fixture-independent".to_string()],
            payload: b"independent transaction".to_vec(),
            ..AegisTxBuildOptions::default()
        },
    )?;

    let verifier = signer.verifier();
    let mut mempool = DagMempool::new(&verifier, Epoch(0), Height(0));
    let mut reports = Vec::new();
    reports.push(report_for_transaction_in_mempool(
        &verifier,
        &mut mempool,
        tx0,
        key_id.clone(),
    )?);
    reports.push(report_for_transaction_in_mempool(
        &verifier,
        &mut mempool,
        tx1,
        key_id.clone(),
    )?);
    reports.push(report_for_transaction_in_mempool(
        &verifier,
        &mut mempool,
        tx2,
        independent_key_id,
    )?);
    let ready_frontier = mempool.ready_frontier();
    let selected_ancestor_closed_set = mempool.ancestor_closed_set(
        &ready_frontier,
        BlockSelectionLimits {
            max_txs: 10,
            max_gas: 1_000_000,
        },
    )?;
    let tx_order_root = mempool.compute_tx_order_root(&selected_ancestor_closed_set)?;
    let dag_frontier_root = mempool.compute_dag_frontier_root()?;

    Ok(AegisDagFixtureReport {
        chain_id: ChainId::synergy_testnet_v3().0,
        network_id: NetworkId::synergy_testnet_v3().0,
        signer_uma_id,
        key_id,
        key_role: AegisPqKeyRole::Transaction,
        transactions: reports,
        ready_frontier,
        selected_ancestor_closed_set,
        tx_order_root: tx_order_root.to_hex(),
        dag_frontier_root: dag_frontier_root.to_hex(),
        atlas_ingestion_status: "not_attempted: typed Aegis DAG transaction RPC is not wired yet; no fabricated Atlas rows were created".to_string(),
    })
}

fn sign_with_existing_aegis_transaction_key(
    signer: &mut AegisPqvmSigner,
    key_id: &AegisPqKeyId,
    options: AegisTxBuildOptions,
) -> Result<Transaction, String> {
    let mut tx = Transaction {
        version: 1,
        chain_id: ChainId::synergy_testnet_v3(),
        network_id: NetworkId::synergy_testnet_v3(),
        epoch: Epoch(options.epoch),
        sender_uma_or_account: options.sender,
        receiver_uma_or_account: options.receiver,
        account_nonce_or_sequence: options.nonce,
        amount_nwei: options.amount_nwei,
        gas_limit: options.gas_limit,
        max_fee_nwei: options.max_fee_nwei,
        ttl_height: Height(options.ttl_height),
        explicit_dependencies: options
            .explicit_dependencies
            .into_iter()
            .map(|tx_id| TxDependency {
                dependency_type: TxDependencyType::ExplicitDependency,
                tx_id: TxId(tx_id),
            })
            .collect(),
        read_set_hint: options.read_set_hint,
        write_set_hint: options.write_set_hint,
        payload: options.payload,
        signer_uma_id: UmaId(options.signer_uma_id),
        aegis_pq_key_id: key_id.clone(),
        aegis_pq_signature: AegisPqSignature {
            algorithm: String::new(),
            signature_bytes: Vec::new(),
        },
    };
    tx.aegis_pq_signature = signer
        .sign_transaction(&tx.signing_bytes()?, key_id)
        .map_err(|error| error.to_string())?;
    Ok(tx)
}

fn report_for_transaction(
    verifier: &AegisPqvmVerifier,
    tx: Transaction,
    key_id: AegisPqKeyId,
) -> Result<AegisSignedTxReport, String> {
    let mut mempool = DagMempool::new(verifier, tx.epoch, Height(0));
    report_for_transaction_in_mempool(verifier, &mut mempool, tx, key_id)
}

fn report_for_transaction_in_mempool(
    verifier: &AegisPqvmVerifier,
    mempool: &mut DagMempool<'_>,
    tx: Transaction,
    key_id: AegisPqKeyId,
) -> Result<AegisSignedTxReport, String> {
    verifier
        .verify_transaction_signature_checked(&tx)
        .map_err(|error| error.to_string())?;
    let public_key = verifier
        .public_key_record(&key_id)
        .map_err(|error| error.to_string())?;
    let lifecycle_record = verifier
        .registry
        .lifecycle
        .record_for(&tx.signer_uma_id.0, &key_id)
        .cloned()
        .ok_or_else(|| "missing Aegis transaction key lifecycle record".to_string())?;
    let submission_envelope = AegisTxSubmissionEnvelope {
        transaction: tx.clone(),
        public_key,
        lifecycle_record,
    };
    let rpc_transaction = legacy_transaction_from_aegis_envelope(&submission_envelope)?;
    let synq_verification = crate::synq_admission::verify_transaction_payload_for_chain_admission(
        &tx,
        current_timestamp(),
    )
    .map_err(|error| error.to_string())?;
    let canonical_tx_bytes = tx.canonical_bytes()?;
    let admission_result = mempool.admit_transaction(tx.clone())?;
    Ok(AegisSignedTxReport {
        tx_id: admission_result.tx_id.clone(),
        key_id,
        key_role: AegisPqKeyRole::Transaction,
        public_key: submission_envelope.public_key.clone(),
        lifecycle_record: submission_envelope.lifecycle_record.clone(),
        signature_verification_result: "verified_through_aegis_pqvm".to_string(),
        dag_node_id: admission_result.tx_id.clone(),
        admission_result,
        canonical_tx_bytes_hex: hex::encode(canonical_tx_bytes),
        transaction: tx,
        submission_envelope,
        rpc_transaction,
        synq_verification,
    })
}

fn tx_id_from_signed_tx(verifier: &AegisPqvmVerifier, tx: &Transaction) -> Result<TxId, String> {
    let mut mempool = DagMempool::new(verifier, tx.epoch, Height(0));
    Ok(mempool.admit_transaction(tx.clone())?.tx_id)
}

pub fn verify_aegis_submission_envelope(
    envelope: &AegisTxSubmissionEnvelope,
) -> Result<(), String> {
    if envelope.public_key.key_id != envelope.transaction.aegis_pq_key_id {
        return Err(
            "Aegis transaction public key id does not match transaction key id".to_string(),
        );
    }
    if envelope.lifecycle_record.uma_id != envelope.transaction.signer_uma_id.0 {
        return Err("Aegis transaction lifecycle UMA does not match signer UMA".to_string());
    }
    if envelope.lifecycle_record.key_id != envelope.transaction.aegis_pq_key_id {
        return Err(
            "Aegis transaction lifecycle key id does not match transaction key id".to_string(),
        );
    }
    if !envelope
        .lifecycle_record
        .roles
        .iter()
        .any(|role| role == &AegisPqKeyRole::Transaction)
    {
        return Err(
            "Aegis transaction key lifecycle does not authorize transaction signing".to_string(),
        );
    }
    let expected_sender =
        crate::address::generate_wallet_address(&hex::encode(&envelope.public_key.key_bytes));
    if envelope.transaction.sender_uma_or_account != expected_sender {
        return Err(format!(
            "Aegis transaction sender does not match transaction public key-derived address; expected {expected_sender}, got {}",
            envelope.transaction.sender_uma_or_account
        ));
    }
    crate::synq_admission::verify_transaction_payload_for_chain_admission(
        &envelope.transaction,
        current_timestamp(),
    )
    .map_err(|error| format!("SynQ admission rejected [{}]: {error}", error.code()))?;
    let verifier = AegisPqvmVerifier::initialize_required_for_public_key(
        envelope.public_key.clone(),
        envelope.lifecycle_record.clone(),
    )
    .map_err(|error| error.to_string())?;
    verifier
        .verify_transaction_signature_checked(&envelope.transaction)
        .map_err(|error| error.to_string())
}

pub fn legacy_transaction_from_aegis_envelope(
    envelope: &AegisTxSubmissionEnvelope,
) -> Result<crate::transaction::Transaction, String> {
    verify_aegis_submission_envelope(envelope)?;
    let tx = &envelope.transaction;
    let amount = u64::try_from(tx.amount_nwei)
        .map_err(|_| "Aegis transaction amount does not fit legacy carrier amount".to_string())?;
    let gas_price = u64::try_from(tx.max_fee_nwei).map_err(|_| {
        "Aegis transaction max fee does not fit legacy carrier gas price".to_string()
    })?;
    let data = encode_aegis_carrier_data(envelope)?;
    Ok(crate::transaction::Transaction {
        chain_id: tx.chain_id.0,
        network_id: tx.network_id.0.clone(),
        sender: tx.sender_uma_or_account.clone(),
        receiver: tx.receiver_uma_or_account.clone(),
        amount,
        nonce: tx.account_nonce_or_sequence,
        signature: tx.aegis_pq_signature.signature_bytes.clone(),
        signer_public_key: envelope.public_key.key_bytes.clone(),
        timestamp: current_timestamp(),
        gas_price,
        gas_limit: tx.gas_limit,
        data: Some(data),
        signature_algorithm: tx.aegis_pq_signature.algorithm.clone(),
    })
}

pub fn validate_legacy_aegis_carrier_transaction(
    transaction: &crate::transaction::Transaction,
) -> Result<(), String> {
    let envelope = decode_aegis_carrier_data(
        transaction
            .data
            .as_deref()
            .ok_or_else(|| "missing Aegis carrier data".to_string())?,
    )?;
    verify_aegis_submission_envelope(&envelope)?;
    let tx = &envelope.transaction;
    if transaction.chain_id != tx.chain_id.0 {
        return Err("Aegis carrier chain_id does not match typed transaction".to_string());
    }
    if transaction.network_id != tx.network_id.0 {
        return Err("Aegis carrier network_id does not match typed transaction".to_string());
    }
    if transaction.sender != tx.sender_uma_or_account {
        return Err("Aegis carrier sender does not match typed transaction".to_string());
    }
    if transaction.receiver != tx.receiver_uma_or_account {
        return Err("Aegis carrier receiver does not match typed transaction".to_string());
    }
    if u128::from(transaction.amount) != tx.amount_nwei {
        return Err("Aegis carrier amount does not match typed transaction".to_string());
    }
    if transaction.nonce != tx.account_nonce_or_sequence {
        return Err("Aegis carrier nonce does not match typed transaction".to_string());
    }
    if transaction.gas_limit != tx.gas_limit {
        return Err("Aegis carrier gas limit does not match typed transaction".to_string());
    }
    if u128::from(transaction.gas_price) != tx.max_fee_nwei {
        return Err("Aegis carrier fee does not match typed transaction".to_string());
    }
    if transaction.signature != tx.aegis_pq_signature.signature_bytes {
        return Err("Aegis carrier signature bytes do not match typed transaction".to_string());
    }
    if transaction.signer_public_key != envelope.public_key.key_bytes {
        return Err("Aegis carrier public key does not match submission envelope".to_string());
    }
    if transaction.signature_algorithm != tx.aegis_pq_signature.algorithm {
        return Err(
            "Aegis carrier signature algorithm does not match typed transaction".to_string(),
        );
    }
    Ok(())
}

pub fn is_legacy_aegis_carrier_transaction(transaction: &crate::transaction::Transaction) -> bool {
    transaction
        .data
        .as_deref()
        .map(|data| data.starts_with(AEGIS_TX_CARRIER_PREFIX))
        .unwrap_or(false)
}

pub fn encode_aegis_carrier_data(envelope: &AegisTxSubmissionEnvelope) -> Result<String, String> {
    let bytes = serde_json::to_vec(envelope)
        .map_err(|error| format!("serialize Aegis transaction envelope: {error}"))?;
    Ok(format!(
        "{AEGIS_TX_CARRIER_PREFIX}{}",
        general_purpose::STANDARD.encode(bytes)
    ))
}

pub fn decode_aegis_carrier_data(data: &str) -> Result<AegisTxSubmissionEnvelope, String> {
    let encoded = data
        .strip_prefix(AEGIS_TX_CARRIER_PREFIX)
        .ok_or_else(|| "not an Aegis transaction carrier".to_string())?;
    let bytes = general_purpose::STANDARD
        .decode(encoded)
        .map_err(|error| format!("decode Aegis transaction carrier: {error}"))?;
    serde_json::from_slice(&bytes)
        .map_err(|error| format!("parse Aegis transaction carrier: {error}"))
}

fn address_for_aegis_key(
    signer: &AegisPqvmSigner,
    key_id: &AegisPqKeyId,
) -> Result<String, String> {
    let public_key = signer
        .public_key_record(key_id)
        .map_err(|error| error.to_string())?;
    Ok(crate::address::generate_wallet_address(&hex::encode(
        public_key.key_bytes,
    )))
}

fn apply_generated_address_defaults(
    signer: &AegisPqvmSigner,
    key_id: &AegisPqKeyId,
    options: &mut AegisTxBuildOptions,
) -> Result<(), String> {
    let generated_sender = address_for_aegis_key(signer, key_id)?;
    if options.sender == AegisTxBuildOptions::default().sender {
        options.sender = generated_sender;
    }
    if options.receiver == AegisTxBuildOptions::default().receiver {
        options.receiver =
            crate::address::generate_wallet_address(&format!("aegis-receiver:{}", key_id.0));
    }
    Ok(())
}

fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn real_aegis_transaction_key_signs_verifies_and_admits_to_dag() {
        let report = sign_with_new_aegis_transaction_key(AegisTxBuildOptions::default()).unwrap();
        assert_eq!(report.key_role, AegisPqKeyRole::Transaction);
        assert_eq!(
            report.signature_verification_result,
            "verified_through_aegis_pqvm"
        );
        assert!(crate::address::is_valid_address(
            &report.transaction.sender_uma_or_account
        ));
        assert_eq!(
            report.transaction.sender_uma_or_account,
            crate::address::generate_wallet_address(&hex::encode(&report.public_key.key_bytes))
        );
        assert!(report.admission_result.ready);
        assert!(!report.canonical_tx_bytes_hex.is_empty());
        validate_legacy_aegis_carrier_transaction(&report.rpc_transaction).unwrap();
    }

    #[test]
    fn real_aegis_transaction_preserves_synq_admission_summary() {
        let synq_carrier = crate::synq_admission::test_support::deploy_carrier(
            crate::synergy_types::SYNERGY_TESTNET_V3_NETWORK_ID,
        );
        let payload = crate::synq_admission::encode_synq_admission_carrier(&synq_carrier)
            .expect("encode SynQ carrier");
        let report = sign_with_new_aegis_transaction_key(AegisTxBuildOptions {
            payload,
            gas_limit: 150_000,
            write_set_hint: vec!["synq-contract-deploy".to_string()],
            ..AegisTxBuildOptions::default()
        })
        .unwrap();

        let summary = report
            .synq_verification
            .as_ref()
            .expect("SynQ verification summary");
        assert_eq!(summary.domain, "SYNQ_CONTRACT_DEPLOY_V1");
        assert_eq!(summary.algorithm, "ML-DSA-65");
        assert_eq!(summary.payload_hash, synq_carrier.payload_hash);
        assert_eq!(summary.bytecode_hash, synq_carrier.bytecode_hash);
        validate_legacy_aegis_carrier_transaction(&report.rpc_transaction).unwrap();
    }

    #[test]
    fn aegis_transaction_sequence_links_dependencies_in_shared_mempool() {
        let reports = sign_aegis_transaction_sequence_with_new_key(
            vec![
                AegisTxBuildOptions {
                    nonce: 0,
                    payload: b"deploy".to_vec(),
                    write_set_hint: vec!["synq-counter".to_string()],
                    ..AegisTxBuildOptions::default()
                },
                AegisTxBuildOptions {
                    nonce: 1,
                    payload: b"increment".to_vec(),
                    write_set_hint: vec!["synq-counter".to_string()],
                    ..AegisTxBuildOptions::default()
                },
            ],
            true,
        )
        .unwrap();

        assert_eq!(reports.len(), 2);
        assert!(reports[0].admission_result.ready);
        assert!(reports[1].admission_result.ready);
        assert_eq!(
            reports[1].transaction.explicit_dependencies[0].tx_id,
            reports[0].tx_id
        );
        assert_eq!(
            reports[1].signature_verification_result,
            "verified_through_aegis_pqvm"
        );
    }

    #[test]
    fn fixture_uses_dependencies_and_no_wallet_cli_path() {
        let report = build_fixture_report().unwrap();
        assert_eq!(report.chain_id, 1264);
        assert_eq!(report.network_id, "synergy-testnet-v3");
        assert_eq!(report.transactions.len(), 3);
        assert!(report
            .transactions
            .iter()
            .all(|tx| tx.signature_verification_result == "verified_through_aegis_pqvm"));
        assert!(report.transactions.iter().any(|tx| !tx
            .admission_result
            .missing_dependencies
            .is_empty()
            || tx.transaction.account_nonce_or_sequence > 0));
        assert!(report.atlas_ingestion_status.contains("not_attempted"));
    }

    #[test]
    fn altered_transaction_bytes_fail_aegis_verification() {
        let mut signer = AegisPqvmSigner::initialize_required().unwrap();
        let key_id = signer
            .generate_and_register_key("alice", vec![AegisPqKeyRole::Transaction], Epoch(0))
            .unwrap();
        let mut tx = sign_with_existing_aegis_transaction_key(
            &mut signer,
            &key_id,
            AegisTxBuildOptions {
                signer_uma_id: "alice".to_string(),
                sender: "alice".to_string(),
                ..AegisTxBuildOptions::default()
            },
        )
        .unwrap();
        tx.amount_nwei = tx.amount_nwei.saturating_add(1);
        let verifier = signer.verifier();
        assert!(verifier.verify_transaction_signature_checked(&tx).is_err());
    }

    #[test]
    fn aegis_submission_envelope_rejects_wrong_chain_and_carrier_tampering() {
        let report = sign_with_new_aegis_transaction_key(AegisTxBuildOptions::default()).unwrap();
        let mut wrong_chain = report.submission_envelope.clone();
        wrong_chain.transaction.chain_id = ChainId(999);
        assert!(verify_aegis_submission_envelope(&wrong_chain).is_err());

        let mut tampered_carrier = report.rpc_transaction.clone();
        tampered_carrier.amount = tampered_carrier.amount.saturating_add(1);
        assert!(validate_legacy_aegis_carrier_transaction(&tampered_carrier).is_err());
    }
}
