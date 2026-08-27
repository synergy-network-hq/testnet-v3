use crate::block::BlockChain;
use crate::config::NodeConfig;
use crate::crypto::aegis_pqvm::AegisPqKeyLifecycleRecord;
use crate::etdag::tests::{fixture, Fixture};
use crate::etdag::{
    seal_transaction, EtdagDigest, EtdagParameters, EtdagSubmissionEnvelope, InnerTransactionV2,
    SealRequest, ETDAG_LANE_ID,
};
use crate::p2p::messages::{
    validate_protected_pipeline_evidence_message, ProtectedPipelineEvidenceMessage,
    ProtectedPipelineSemanticObject,
};
use crate::p2p::networking::{DurableProtectedCiphertextStore, P2PNetwork};
use crate::synergy_types::{
    AegisPqKeyRole, AegisPqSignature, ChainId, Epoch, Hash, Height, NetworkId, Transaction,
};
use rand::rngs::StdRng;
use rand::SeedableRng;
use std::collections::BTreeSet;
use std::fs;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

static TEST_SEQUENCE: AtomicU64 = AtomicU64::new(1);
static ADVERSARIAL_TEST_LOCK: Mutex<()> = Mutex::new(());

fn test_directory(label: &str) -> std::path::PathBuf {
    crate::utils::test_temp_root(format!(
        "protected-ciphertext-adversarial-{label}-{}-{}",
        std::process::id(),
        TEST_SEQUENCE.fetch_add(1, Ordering::Relaxed)
    ))
}

fn encrypted_material(
    fixture: &mut Fixture,
    nonce: u64,
    rng_seed: u64,
) -> ProtectedPipelineSemanticObject {
    let sender = fixture.validator_set.validators[0].clone();
    let mut transaction = Transaction {
        version: 2,
        chain_id: ChainId::synergy_testnet_v3(),
        network_id: NetworkId::fresh_posy_testnet_v3(),
        epoch: Epoch(0),
        sender_uma_or_account: sender.validator_uma_id.0.clone(),
        receiver_uma_or_account: "adversarial-recipient".to_string(),
        account_nonce_or_sequence: nonce,
        amount_nwei: 55,
        gas_limit: 50_000,
        max_fee_nwei: 10_000,
        ttl_height: fixture.context.target_height,
        explicit_dependencies: Vec::new(),
        read_set_hint: Vec::new(),
        write_set_hint: Vec::new(),
        payload: format!("private-adversarial-payload-{nonce}").into_bytes(),
        signer_uma_id: sender.validator_uma_id.clone(),
        aegis_pq_key_id: sender.consensus_public_key.key_id.clone(),
        aegis_pq_signature: AegisPqSignature {
            algorithm: String::new(),
            signature_bytes: Vec::new(),
        },
    };
    transaction.aegis_pq_signature = fixture
        .signer
        .sign_transaction(
            &transaction
                .signing_bytes()
                .expect("transaction signs canonically"),
            &transaction.aegis_pq_key_id,
        )
        .expect("fixture transaction signature");
    let inner = InnerTransactionV2 {
        target_height: fixture.context.target_height,
        lane_id: ETDAG_LANE_ID.to_string(),
        transaction,
    };
    let parameters = EtdagParameters::default();
    let recipients = fixture.ingress_registry.recipients();
    let mut rng = StdRng::seed_from_u64(rng_seed);
    let bundle = seal_transaction(
        &mut fixture.signer,
        SealRequest {
            inner,
            target_context: &fixture.context,
            parameters: &parameters,
            recipients: &recipients,
            gas_class: 2,
            fee_class: 1,
            admission_bond_nwei: 100,
            outer_key_id: sender.consensus_public_key.key_id.clone(),
        },
        &mut rng,
    )
    .expect("fixture seals exact encrypted material");
    let semantic_id = bundle.envelope.tx_commitment.clone();
    ProtectedPipelineSemanticObject::EncryptedMaterial {
        semantic_id,
        submission: EtdagSubmissionEnvelope {
            sealed_bundle: bundle,
            outer_public_key: sender.consensus_public_key.clone(),
            outer_key_lifecycle: AegisPqKeyLifecycleRecord {
                uma_id: sender.validator_uma_id.0,
                key_id: sender.consensus_public_key.key_id,
                roles: vec![
                    AegisPqKeyRole::ConsensusVote,
                    AegisPqKeyRole::ConsensusProposer,
                    AegisPqKeyRole::Transaction,
                ],
                active_from_epoch: Epoch(0),
                active_until_epoch: None,
                revoked_from_epoch: None,
            },
        },
    }
}

#[test]
fn ciphertext_exact_canonical_replay_survives_store_reopen() {
    let _guard = ADVERSARIAL_TEST_LOCK.lock().unwrap();
    let directory = test_directory("canonical-reopen");
    let mut fixture = fixture(5, None);
    let object = encrypted_material(&mut fixture, 7, 101);
    let semantic_id = object.declared_semantic_id().clone();

    let first = DurableProtectedCiphertextStore::at_directory(&directory).unwrap();
    first.install(&object).unwrap();
    let record_path = directory.join(format!("{}.json", semantic_id.0));
    let canonical_before = fs::read(&record_path).expect("durable record exists");
    drop(first);

    let reopened = DurableProtectedCiphertextStore::at_directory(&directory).unwrap();
    assert_eq!(reopened.load(&semantic_id).unwrap(), Some(object));
    assert_eq!(
        fs::read(&record_path).expect("reopened record exists"),
        canonical_before,
        "reopen must replay the exact canonical bytes without rewriting"
    );
}

#[test]
fn ciphertext_same_commitment_distinct_valid_object_is_rejected_as_conflict() {
    let _guard = ADVERSARIAL_TEST_LOCK.lock().unwrap();
    let directory = test_directory("conflict");
    let mut fixture = fixture(5, None);
    let object = encrypted_material(&mut fixture, 7, 102);
    let mut conflicting = object.clone();
    let ProtectedPipelineSemanticObject::EncryptedMaterial { submission, .. } = &mut conflicting
    else {
        unreachable!()
    };
    submission
        .outer_key_lifecycle
        .roles
        .push(AegisPqKeyRole::Governance);
    conflicting
        .validate_shape()
        .expect("additional lifecycle role leaves the transaction authorization valid");

    let store = DurableProtectedCiphertextStore::at_directory(directory).unwrap();
    store.install(&object).unwrap();
    let error = store
        .install(&conflicting)
        .expect_err("one commitment cannot be rebound to distinct valid material metadata");
    assert_eq!(error, "PROTECTED_CIPHERTEXT_MATERIAL_CONFLICT");
}

#[test]
fn ciphertext_wrong_target_and_missing_object_return_no_material() {
    let _guard = ADVERSARIAL_TEST_LOCK.lock().unwrap();
    let directory = test_directory("wrong-target-missing");
    let mut fixture = fixture(5, None);
    let object = encrypted_material(&mut fixture, 7, 103);
    let semantic_id = object.declared_semantic_id().clone();
    let (target_height, target_root) = object.target_binding();
    let missing = EtdagDigest::from_domain_bytes("adversarial-missing", b"not-present");
    let store = DurableProtectedCiphertextStore::at_directory(directory).unwrap();
    store.install(&object).unwrap();

    assert!(store.load(&missing).unwrap().is_none());
    assert!(store
        .load_for_target(
            Height(target_height.0 + 1),
            target_root,
            &[semantic_id.clone()]
        )
        .unwrap()
        .is_empty());
    assert!(store
        .load_for_target(
            target_height,
            Hash::from_domain_bytes("wrong-target", b"context"),
            &[semantic_id]
        )
        .unwrap()
        .is_empty());
    assert!(store
        .load_for_target(target_height, target_root, &[missing])
        .unwrap()
        .is_empty());
}

#[test]
fn ciphertext_tampered_signature_and_noncanonical_durable_bytes_fail_closed() {
    let _guard = ADVERSARIAL_TEST_LOCK.lock().unwrap();
    let directory = test_directory("tamper");
    let mut fixture = fixture(5, None);
    let object = encrypted_material(&mut fixture, 7, 104);
    let semantic_id = object.declared_semantic_id().clone();

    let mut bad_signature = object.clone();
    let ProtectedPipelineSemanticObject::EncryptedMaterial { submission, .. } = &mut bad_signature
    else {
        unreachable!()
    };
    submission
        .sealed_bundle
        .envelope
        .outer_signature
        .signature_bytes[0] ^= 0x80;
    let signature_error = bad_signature
        .validate_shape()
        .expect_err("tampered wallet origin signature must fail closed");
    assert!(signature_error.contains("verify protected envelope origin"));

    let store = DurableProtectedCiphertextStore::at_directory(&directory).unwrap();
    store.install(&object).unwrap();
    let path = directory.join(format!("{}.json", semantic_id.0));
    let canonical = fs::read(&path).unwrap();
    let mut noncanonical = Vec::with_capacity(canonical.len() + 1);
    noncanonical.push(b' ');
    noncanonical.extend_from_slice(&canonical);
    fs::write(&path, noncanonical).unwrap();
    let canonical_error = store
        .load(&semantic_id)
        .expect_err("valid JSON with noncanonical bytes must not replay");
    assert!(canonical_error.contains("not canonically serialized"));
}

#[test]
fn ciphertext_duplicate_install_is_idempotent_and_reordered_lookup_is_exact() {
    let _guard = ADVERSARIAL_TEST_LOCK.lock().unwrap();
    let directory = test_directory("duplicate-reorder");
    let mut fixture = fixture(5, None);
    let first = encrypted_material(&mut fixture, 7, 105);
    let second = encrypted_material(&mut fixture, 8, 106);
    let first_id = first.declared_semantic_id().clone();
    let second_id = second.declared_semantic_id().clone();
    let (target_height, target_root) = first.target_binding();
    assert_eq!(second.target_binding(), (target_height, target_root));

    let store = DurableProtectedCiphertextStore::at_directory(directory).unwrap();
    store.install(&first).unwrap();
    store
        .install(&first)
        .expect("exact duplicate is idempotent");
    store.install(&second).unwrap();
    assert_eq!(
        store
            .load_for_target(target_height, target_root, &[second_id, first_id])
            .unwrap(),
        vec![second, first],
        "retrieval preserves the request order while returning exact objects"
    );
}

#[test]
fn ciphertext_missing_request_rejects_duplicate_ids_and_accepts_reordering() {
    let _guard = ADVERSARIAL_TEST_LOCK.lock().unwrap();
    let target_height = Height(8);
    let target_context_root = Hash::from_domain_bytes("adversarial-target", b"height-eight");
    let first = EtdagDigest::from_domain_bytes("adversarial-request", b"first");
    let second = EtdagDigest::from_domain_bytes("adversarial-request", b"second");
    validate_protected_pipeline_evidence_message(
        &ProtectedPipelineEvidenceMessage::MissingObjectsRequest {
            target_height,
            target_context_root,
            semantic_ids: vec![second.clone(), first.clone()],
        },
    )
    .expect("missing-object IDs may arrive in any order");
    let error = validate_protected_pipeline_evidence_message(
        &ProtectedPipelineEvidenceMessage::MissingObjectsRequest {
            target_height,
            target_context_root,
            semantic_ids: vec![first.clone(), first],
        },
    )
    .expect_err("duplicate missing-object IDs must fail closed");
    assert!(error.contains("duplicate or zero id"));
}

#[test]
fn ciphertext_recovery_flight_survives_network_recreation_and_exhausts_retry_bound() {
    let _guard = ADVERSARIAL_TEST_LOCK.lock().unwrap();
    let recovery_sequence = TEST_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let semantic_id =
        EtdagDigest::from_domain_bytes("adversarial-recovery", &recovery_sequence.to_be_bytes());
    let target_height = Height(8);
    let target_context_root = Hash::from_domain_bytes("adversarial-recovery", b"target");
    let frozen_validator_ids = BTreeSet::from([crate::synergy_types::ValidatorId(
        "validator-00".to_string(),
    )]);

    let first_network = P2PNetwork::new(
        Arc::new(Mutex::new(BlockChain::new())),
        &NodeConfig::default(),
    );
    assert_eq!(
        first_network
            .request_protected_pipeline_objects(
                target_height,
                target_context_root,
                vec![semantic_id.clone()],
                &frozen_validator_ids,
            )
            .unwrap(),
        0,
        "no connected validator means no send, but the recovery flight remains registered"
    );
    drop(first_network);
    let reconnected_network = P2PNetwork::new(
        Arc::new(Mutex::new(BlockChain::new())),
        &NodeConfig::default(),
    );
    for _ in 1..8 {
        reconnected_network
            .request_protected_pipeline_objects(
                target_height,
                target_context_root,
                vec![semantic_id.clone()],
                &frozen_validator_ids,
            )
            .expect("request remains within its bounded retry budget");
    }
    let error = reconnected_network
        .request_protected_pipeline_objects(
            target_height,
            target_context_root,
            vec![semantic_id.clone()],
            &frozen_validator_ids,
        )
        .expect_err("ninth recovery attempt must fail closed");
    assert!(error.contains("retry budget is exhausted"));
}
