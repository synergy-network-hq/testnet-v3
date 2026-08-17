//! Signing-journal tests. Real filesystem, real reopen cycles, and real
//! ML-DSA-65 sign/verify through the same `pqsynq` path `consensus_start.rs`
//! uses for ML-DSA-87. No BFT authorization, vote, QC, cluster, epoch, or
//! round type is imported anywhere in this module.

use super::single_authority_finality_store::SINGLE_AUTHORITY_CONSENSUS_PROTOCOL;
use super::single_authority_signing_journal::*;
use crate::crypto::pqc::{PQCAlgorithm, PQCManager, PQCPrivateKey, PQCPublicKey};
use crate::synergy_types::Hash;
use base64::{engine::general_purpose, Engine as _};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        let mut path = std::env::temp_dir();
        path.push(format!(
            "sa-journal-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&path).expect("temp dir");
        Self(path)
    }
    fn journal(&self) -> PathBuf {
        self.0.join("signing-journal.json")
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn open(dir: &TempDir) -> SingleAuthoritySigningJournal {
    SingleAuthoritySigningJournal::at_path(dir.journal())
}

fn subject_at(height: u64) -> SingleAuthoritySigningSubject {
    SingleAuthoritySigningSubject {
        schema_version: SINGLE_AUTHORITY_JOURNAL_SCHEMA_VERSION,
        chain_id: 1266,
        chain_incarnation: 5,
        consensus_protocol: SINGLE_AUTHORITY_CONSENSUS_PROTOCOL.to_string(),
        authority_id: "authority-node-01".to_string(),
        authority_key_id: "authority-node-01-block-key".to_string(),
        release_id: "chain1266-single-authority-rc1".to_string(),
        height,
        parent_hash: Hash([(height as u8).wrapping_sub(1); 32]),
        canonical_block_hash: Hash([height as u8; 32]),
        canonical_signing_payload_digest: Hash([(height as u8).wrapping_add(64); 32]),
    }
}

fn historical_subject_at(height: u64) -> SingleAuthoritySigningSubject {
    let mut subject = subject_at(height);
    // `subject_at` intentionally uses one-byte fixtures for small tests; the
    // historical fixture crosses that byte boundary, so keep its required
    // digests nonzero for every represented height.
    let marker = (height % 251) as u8 + 1;
    subject.parent_hash = Hash([marker.saturating_sub(1).max(1); 32]);
    subject.canonical_block_hash = Hash([marker; 32]);
    subject.canonical_signing_payload_digest = Hash([marker % 250 + 1; 32]);
    subject
}

/// Canonical signing bytes: the subject itself, serialized deterministically.
fn signing_bytes(subject: &SingleAuthoritySigningSubject) -> Vec<u8> {
    serde_json::to_vec(subject).expect("canonical signing bytes")
}

struct AuthorityKey {
    public: PQCPublicKey,
    private: PQCPrivateKey,
}

fn generate_authority_key() -> AuthorityKey {
    let mut manager = PQCManager::new();
    let (public, private) = manager
        .generate_keypair(PQCAlgorithm::MLDSA65)
        .expect("ML-DSA-65 keypair");
    AuthorityKey { public, private }
}

/// Domain-separated signing payload: domain || len || canonical subject bytes.
fn domain_bound_payload(subject: &SingleAuthoritySigningSubject) -> Vec<u8> {
    let domain = SYNERGY_CHAIN1266_SINGLE_AUTHORITY_BLOCK_V1.as_bytes();
    let body = signing_bytes(subject);
    let mut out = Vec::with_capacity(domain.len() + 8 + body.len());
    out.extend_from_slice(domain);
    out.extend_from_slice(&(domain.len() as u64).to_be_bytes());
    out.extend_from_slice(&body);
    out
}

fn sign_subject(key: &AuthorityKey, subject: &SingleAuthoritySigningSubject) -> Vec<u8> {
    let mut manager = PQCManager::new();
    manager
        .sign(&key.private, &domain_bound_payload(subject))
        .expect("ML-DSA-65 sign")
        .signature_data
}

fn verify_subject(key: &AuthorityKey, subject: &SingleAuthoritySigningSubject, sig: &[u8]) -> bool {
    let manager = PQCManager::new();
    let signature = crate::crypto::pqc::PQCSignature {
        algorithm: PQCAlgorithm::MLDSA65,
        signature_data: sig.to_vec(),
        message_hash: Vec::new(),
        public_key_id: String::new(),
        created_at: 0,
    };
    manager
        .verify(&key.public, &signature, &domain_bound_payload(subject))
        .unwrap_or(false)
}

fn signature_record(sig: &[u8]) -> SingleAuthoritySignatureRecord {
    SingleAuthoritySignatureRecord {
        signature_algorithm: SINGLE_AUTHORITY_SIGNATURE_ALGORITHM.to_string(),
        signature_base64: general_purpose::STANDARD.encode(sig),
        authority_public_key_fingerprint: "sha256:authority-node-01".to_string(),
    }
}

/// The canonical V1 shape, intentionally independent from the new runtime's
/// private implementation.  Parsing this after migration proves a prior
/// runtime can still decode the compact canonical journal during rollback.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyJournalFile {
    #[serde(default)]
    entries: Vec<SingleAuthorityJournalEntry>,
    #[serde(default)]
    safety_halts: Vec<SingleAuthoritySafetyHalt>,
}

#[test]
fn j01_valid_authority_signature_verifies() {
    let key = generate_authority_key();
    let subject = subject_at(1);
    let sig = sign_subject(&key, &subject);
    assert!(verify_subject(&key, &subject, &sig));
}

#[test]
fn j03_modified_payload_fails_verification() {
    let key = generate_authority_key();
    let subject = subject_at(1);
    let sig = sign_subject(&key, &subject);
    let mut tampered = subject.clone();
    tampered.canonical_block_hash = Hash([99u8; 32]);
    assert!(!verify_subject(&key, &tampered, &sig));
}

#[test]
fn j04_modified_height_fails_verification() {
    let key = generate_authority_key();
    let subject = subject_at(1);
    let sig = sign_subject(&key, &subject);
    let mut tampered = subject.clone();
    tampered.height = 2;
    assert!(!verify_subject(&key, &tampered, &sig));
}

#[test]
fn j05_modified_parent_hash_fails_verification() {
    let key = generate_authority_key();
    let subject = subject_at(1);
    let sig = sign_subject(&key, &subject);
    let mut tampered = subject.clone();
    tampered.parent_hash = Hash([7u8; 32]);
    assert!(!verify_subject(&key, &tampered, &sig));
}

#[test]
fn j06_modified_incarnation_fails_verification() {
    let key = generate_authority_key();
    let subject = subject_at(1);
    let sig = sign_subject(&key, &subject);
    let mut tampered = subject.clone();
    tampered.chain_incarnation = 4;
    assert!(!verify_subject(&key, &tampered, &sig));
}

#[test]
fn j07_modified_release_id_fails_verification() {
    let key = generate_authority_key();
    let subject = subject_at(1);
    let sig = sign_subject(&key, &subject);
    let mut tampered = subject.clone();
    tampered.release_id = "chain1266-rc29".to_string();
    assert!(!verify_subject(&key, &tampered, &sig));
}

#[test]
fn j08_wrong_authority_key_fails_verification() {
    let key = generate_authority_key();
    let other = generate_authority_key();
    let subject = subject_at(1);
    let sig = sign_subject(&key, &subject);
    assert!(!verify_subject(&other, &subject, &sig));
}

#[test]
fn j10_height_zero_is_rejected_by_the_authority_journal() {
    let dir = TempDir::new("j10");
    let error = open(&dir)
        .authorize_before_signature(&subject_at(0))
        .unwrap_err();
    assert!(error.contains("not authority-produced"), "{error}");
    assert!(error.contains("ML-DSA-87"), "{error}");
}

#[test]
fn j11_exact_entry_survives_restart() {
    let dir = TempDir::new("j11");
    let subject = subject_at(1);
    assert_eq!(
        open(&dir).authorize_before_signature(&subject).unwrap(),
        SingleAuthoritySigningDecision::SignFresh
    );
    // Reopened from disk.
    assert!(open(&dir).contains_exact(&subject).unwrap());
}

#[test]
fn j12_different_payload_at_same_height_is_rejected() {
    let dir = TempDir::new("j12");
    let journal = open(&dir);
    journal.authorize_before_signature(&subject_at(1)).unwrap();

    let mut different = subject_at(1);
    different.canonical_block_hash = Hash([200u8; 32]);
    let error = open(&dir)
        .authorize_before_signature(&different)
        .unwrap_err();
    assert!(
        error.contains("already bound to a different signing subject"),
        "{error}"
    );
}

#[test]
fn j13_signed_state_retains_the_exact_signature() {
    let dir = TempDir::new("j13");
    let key = generate_authority_key();
    let subject = subject_at(1);
    let journal = open(&dir);
    journal.authorize_before_signature(&subject).unwrap();

    let sig = sign_subject(&key, &subject);
    journal
        .record_signature(&subject, &signature_record(&sig))
        .unwrap();

    let entry = open(&dir).entry_for_height(1).unwrap().expect("entry");
    assert_eq!(entry.state, SingleAuthorityJournalState::Signed);
    let stored = entry.signature.expect("signature");
    let decoded = general_purpose::STANDARD
        .decode(&stored.signature_base64)
        .unwrap();
    assert_eq!(decoded, sig);
    assert!(verify_subject(&key, &subject, &decoded));
}

#[test]
fn j14_authorized_only_restart_enters_safety_halt_not_resign() {
    let dir = TempDir::new("j14");
    let subject = subject_at(1);
    open(&dir).authorize_before_signature(&subject).unwrap();

    // Crash between authorize and record_signature; restart re-attempts.
    let decision = open(&dir).authorize_before_signature(&subject).unwrap();
    match decision {
        SingleAuthoritySigningDecision::SafetyHalt(reason) => {
            assert!(reason.contains("randomized"), "{reason}");
        }
        other => panic!("expected SafetyHalt, got {other:?}"),
    }
}

#[test]
fn j15_signed_but_not_finalized_recovery_replays_exact_signature() {
    let dir = TempDir::new("j15");
    let key = generate_authority_key();
    let subject = subject_at(1);
    let journal = open(&dir);
    journal.authorize_before_signature(&subject).unwrap();
    let sig = sign_subject(&key, &subject);
    journal
        .record_signature(&subject, &signature_record(&sig))
        .unwrap();

    // Crash before finalization; restart must replay, never re-sign.
    match open(&dir).authorize_before_signature(&subject).unwrap() {
        SingleAuthoritySigningDecision::ReplayExisting(replayed) => {
            let decoded = general_purpose::STANDARD
                .decode(&replayed.signature_base64)
                .unwrap();
            assert_eq!(decoded, sig, "restart must replay the exact signature");
            assert!(verify_subject(&key, &subject, &decoded));
        }
        other => panic!("expected ReplayExisting, got {other:?}"),
    }
}

#[test]
fn j16_finalize_requires_a_durable_signature() {
    let dir = TempDir::new("j16");
    let subject = subject_at(1);
    let journal = open(&dir);
    journal.authorize_before_signature(&subject).unwrap();
    let error = journal.mark_finalized(&subject).unwrap_err();
    assert!(error.contains("no durable signature"), "{error}");
}

#[test]
fn j17_safety_halt_survives_restart() {
    let dir = TempDir::new("j17");
    open(&dir)
        .enter_safety_halt(
            &SingleAuthorityHaltNamespace::from_subject(&subject_at(1)),
            1,
            "operator halt",
        )
        .unwrap();
    let error = open(&dir)
        .require_signing_allowed(&SingleAuthorityHaltNamespace::from_subject(&subject_at(1)))
        .unwrap_err();
    assert!(error.contains("SINGLE_AUTHORITY_SAFETY_HALT"), "{error}");
    // and it blocks any further authorization
    let error = open(&dir)
        .authorize_before_signature(&subject_at(2))
        .unwrap_err();
    assert!(error.contains("SAFETY_HALT"), "{error}");
}

#[test]
fn j02_wrong_algorithm_is_rejected_by_the_journal() {
    let dir = TempDir::new("j02");
    let key = generate_authority_key();
    let subject = subject_at(1);
    let journal = open(&dir);
    journal.authorize_before_signature(&subject).unwrap();

    let mut record = signature_record(&sign_subject(&key, &subject));
    record.signature_algorithm = "ed25519".to_string();
    let error = journal.record_signature(&subject, &record).unwrap_err();
    assert!(error.contains("must be mldsa65"), "{error}");
}

#[test]
fn j09_missing_signature_is_rejected_by_the_journal() {
    let dir = TempDir::new("j09");
    let subject = subject_at(1);
    let journal = open(&dir);
    journal.authorize_before_signature(&subject).unwrap();

    let mut record = signature_record(b"");
    record.signature_base64.clear();
    let error = journal.record_signature(&subject, &record).unwrap_err();
    assert!(error.contains("empty"), "{error}");
}

#[test]
fn j18_journal_serialization_contains_no_bft_concepts() {
    let dir = TempDir::new("j18");
    let key = generate_authority_key();
    let subject = subject_at(1);
    let journal = open(&dir);
    journal.authorize_before_signature(&subject).unwrap();
    journal
        .record_signature(&subject, &signature_record(&sign_subject(&key, &subject)))
        .unwrap();

    let raw = fs::read_to_string(dir.journal()).unwrap();
    for forbidden in [
        "quorum",
        "certificate",
        "vote",
        "cluster",
        "epoch",
        "round",
        "coordinator",
        "producer",
    ] {
        assert!(
            !raw.contains(forbidden),
            "journal leaked `{forbidden}`: {raw}"
        );
    }
}

#[test]
fn j19_legacy_52733_height_journal_migrates_once_and_stays_bounded() {
    let dir = TempDir::new("j19");
    const FINALIZED_HEIGHT: u64 = 52_732;
    const PENDING_HEIGHT: u64 = FINALIZED_HEIGHT + 1;

    // This represents the exact number of entries present at the production
    // stall.  The signatures are public, non-empty fixture data; signature
    // cryptography is covered by the tests above, while this one exercises the
    // migration's historical-size and crash-safety shape.
    let entries = (1..=PENDING_HEIGHT)
        .map(|height| SingleAuthorityJournalEntry {
            subject: historical_subject_at(height),
            state: SingleAuthorityJournalState::Signed,
            signature: Some(SingleAuthoritySignatureRecord {
                signature_algorithm: SINGLE_AUTHORITY_SIGNATURE_ALGORITHM.to_string(),
                signature_base64: "AQ==".to_string(),
                authority_public_key_fingerprint: "sha256:authority-node-01".to_string(),
            }),
        })
        .collect();
    let legacy = LegacyJournalFile {
        entries,
        safety_halts: Vec::new(),
    };
    fs::write(dir.journal(), serde_json::to_vec(&legacy).unwrap()).unwrap();

    let tip = historical_subject_at(FINALIZED_HEIGHT);
    let journal = open(&dir);
    journal
        .reconcile_finalized_head(
            &SingleAuthorityHaltNamespace::from_subject(&tip),
            FINALIZED_HEIGHT,
            Some(&tip.canonical_block_hash),
        )
        .unwrap();

    let archive = PathBuf::from(format!(
        "{}.legacy-v1-archive.json",
        dir.journal().display()
    ));
    assert!(archive.exists(), "legacy journal must remain auditable");
    assert!(fs::metadata(&archive).unwrap().len() > 10_000_000);
    let compact: LegacyJournalFile =
        serde_json::from_slice(&fs::read(dir.journal()).unwrap()).unwrap();
    assert_eq!(compact.entries.len(), 1);
    assert_eq!(compact.entries[0].subject.height, PENDING_HEIGHT);
    assert!(fs::metadata(dir.journal()).unwrap().len() < 10_000);

    // The active entry is removed after durable finality.  The following
    // height writes only one V1-compatible entry, rather than re-growing the
    // historical journal.
    journal
        .mark_finalized(&historical_subject_at(PENDING_HEIGHT))
        .unwrap();
    assert!(open(&dir).entries().unwrap().is_empty());
    assert_eq!(
        open(&dir)
            .authorize_before_signature(&subject_at(PENDING_HEIGHT + 1))
            .unwrap(),
        SingleAuthoritySigningDecision::SignFresh
    );
    let rollback_compatible: LegacyJournalFile =
        serde_json::from_slice(&fs::read(dir.journal()).unwrap()).unwrap();
    assert_eq!(rollback_compatible.entries.len(), 1);
    assert_eq!(
        rollback_compatible.entries[0].subject.height,
        PENDING_HEIGHT + 1
    );
}
