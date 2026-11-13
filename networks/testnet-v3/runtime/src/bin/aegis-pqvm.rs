use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use synergy_testnet::consensus::self_realign::{
    create_snapshot_manifest, default_allowed_restore_roles_for_class,
    required_snapshot_quorum_for_validator_count, sign_snapshot_manifest, SnapshotBuildInput,
    SnapshotQcEvidence, SNAPSHOT_CLASS_VALIDATOR_PRUNED,
};
use synergy_testnet::crypto::aegis_pqvm::{
    AegisPqKeyLifecycleRecord, AegisPqvmSigner, AegisPqvmVerifier,
};
use synergy_testnet::crypto::pqc::{PQCPrivateKey, PQCPublicKey};
use synergy_testnet::synergy_types::{
    AegisPqKeyId, AegisPqKeyRole, AegisPqPublicKey, AegisPqSignature, Epoch,
};

const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ArchiveAuthorityIdentity {
    schema: String,
    uma_id: String,
    key_id: AegisPqKeyId,
    roles: Vec<AegisPqKeyRole>,
    active_from_epoch: Epoch,
    public_key: PQCPublicKey,
    private_key: PQCPrivateKey,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DetachedJsonSignatureProof {
    schema: String,
    domain: String,
    payload_sha256: String,
    signer_uma_id: String,
    signing_key_id: AegisPqKeyId,
    signer_public_key: AegisPqPublicKey,
    lifecycle: AegisPqKeyLifecycleRecord,
    aegis_pq_signature: AegisPqSignature,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("aegis-pqvm failed closed: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    match args.first().map(String::as_str).unwrap_or("help") {
        "--version" | "-v" | "version" => {
            println!("aegis-pqvm {VERSION}");
        }
        "smoke-test" => smoke_test(),
        "init-archive-identity" => init_archive_identity(&args),
        "sign-json" => sign_json(&args),
        "verify-json" => verify_json(&args),
        "test-only-create-snapshot-fixture" => test_only_create_snapshot_fixture(&args),
        "help" | "--help" | "-h" => print_usage(),
        other => return Err(format!("unknown command: {other}")),
    }
    Ok(())
}

fn print_usage() {
    println!("aegis-pqvm {VERSION}");
    println!("Commands:");
    println!("  smoke-test");
    println!("  init-archive-identity --output <identity.json> --uma-id <id>");
    println!("  sign-json --identity <identity.json> --domain <domain> --input <json> --output <sig.json>");
    println!("  verify-json --domain <domain> --input <json> --signature <sig.json> [--expected-signer-sha256 <sha256>]");
    println!("  test-only-create-snapshot-fixture --output <directory> --snapshot-class <validator-pruned|support-relayer|support-rpc|support-observer|indexer-replay|indexer-full|archive-full|archive-bootstrap>");
}

fn smoke_test() {
    let mut signer = AegisPqvmSigner::initialize_required().expect("Aegis signer smoke test");
    let key_id = signer
        .generate_and_register_key(
            "aegis-pqvm-smoke-test",
            vec![AegisPqKeyRole::ArchiveSnapshotSigner],
            Epoch(0),
        )
        .expect("Aegis archive smoke key");
    let payload = b"synergy-archive-aegis-pqvm-smoke-test";
    let signature = signer
        .sign_domain("SYNERGY_ARCHIVE_AEGIS_SMOKE_V1", payload, &key_id)
        .expect("Aegis archive smoke signature");
    signer
        .verifier()
        .verify_domain_signature(
            "SYNERGY_ARCHIVE_AEGIS_SMOKE_V1",
            payload,
            "aegis-pqvm-smoke-test",
            &key_id,
            Epoch(0),
            AegisPqKeyRole::ArchiveSnapshotSigner,
            &signature,
        )
        .expect("Aegis archive smoke verification");
    println!(
        "{}",
        serde_json::json!({
            "ok": true,
            "algorithm": signature.algorithm,
            "role": "ARCHIVE_SNAPSHOT_SIGNER",
            "real_aegis_pqvm": true,
        })
    );
}

fn init_archive_identity(args: &[String]) {
    let output = required_arg(args, "--output").expect("--output");
    let uma_id = required_arg(args, "--uma-id").expect("--uma-id");
    let output = PathBuf::from(output);
    if output.exists() {
        panic!("refusing to overwrite existing archive authority identity");
    }
    let mut signer = AegisPqvmSigner::initialize_required().expect("Aegis signer initialization");
    let key_id = signer
        .generate_and_register_key(
            &uma_id,
            vec![
                AegisPqKeyRole::ArchivePeer,
                AegisPqKeyRole::ArchiveSnapshotSigner,
            ],
            Epoch(0),
        )
        .expect("archive authority key generation");
    let public_key = signer
        .registry
        .public_key(&key_id)
        .cloned()
        .expect("archive authority public key");
    let private_key = signer
        .registry
        .private_key(&key_id)
        .cloned()
        .expect("archive authority private key");
    let identity = ArchiveAuthorityIdentity {
        schema: "synergy-archive-authority-identity-v1".to_string(),
        uma_id,
        key_id,
        roles: vec![
            AegisPqKeyRole::ArchivePeer,
            AegisPqKeyRole::ArchiveSnapshotSigner,
        ],
        active_from_epoch: Epoch(0),
        public_key,
        private_key,
    };
    write_private_json(&output, &identity).expect("write archive authority identity");
    let public_sha256 = public_identity_sha256(
        &signer
            .public_key_record(&identity.key_id)
            .expect("archive authority public key record"),
    );
    println!(
        "{}",
        serde_json::json!({
            "ok": true,
            "identity_path": output,
            "signer_uma_id": identity.uma_id,
            "signing_key_id": identity.key_id,
            "public_identity_sha256": public_sha256,
        })
    );
}

fn sign_json(args: &[String]) {
    let identity_path = PathBuf::from(required_arg(args, "--identity").expect("--identity"));
    let domain = required_arg(args, "--domain").expect("--domain");
    let input_path = PathBuf::from(required_arg(args, "--input").expect("--input"));
    let output_path = PathBuf::from(required_arg(args, "--output").expect("--output"));
    let identity: ArchiveAuthorityIdentity =
        read_json(&identity_path).expect("read archive authority identity");
    if identity.schema != "synergy-archive-authority-identity-v1" {
        panic!("unsupported archive authority identity schema");
    }
    let payload = fs::read(&input_path).expect("read JSON payload");
    serde_json::from_slice::<serde_json::Value>(&payload).expect("input must be JSON");
    let mut signer = AegisPqvmSigner::initialize_required().expect("Aegis signer initialization");
    let key_id = signer
        .register_existing_keypair(
            &identity.uma_id,
            identity.public_key.clone(),
            identity.private_key.clone(),
            identity.roles.clone(),
            identity.active_from_epoch,
        )
        .expect("register archive authority identity");
    let signer_public_key = signer
        .public_key_record(&key_id)
        .expect("archive authority public key record");
    let signature = signer
        .sign_domain(&domain, &payload, &key_id)
        .expect("Aegis JSON signing");
    let proof = DetachedJsonSignatureProof {
        schema: "synergy-aegis-detached-json-signature-v1".to_string(),
        domain: domain.clone(),
        payload_sha256: sha256_hex(&payload),
        signer_uma_id: identity.uma_id.clone(),
        signing_key_id: key_id.clone(),
        signer_public_key,
        lifecycle: AegisPqKeyLifecycleRecord {
            uma_id: identity.uma_id,
            key_id,
            roles: identity.roles,
            active_from_epoch: identity.active_from_epoch,
            active_until_epoch: None,
            revoked_from_epoch: None,
        },
        aegis_pq_signature: signature,
    };
    write_public_json(&output_path, &proof).expect("write detached JSON signature proof");
    println!(
        "{}",
        serde_json::json!({
            "ok": true,
            "domain": domain,
            "payload_sha256": proof.payload_sha256,
            "signature_path": output_path,
            "signer_uma_id": proof.signer_uma_id,
            "signing_key_id": proof.signing_key_id,
            "public_identity_sha256": public_identity_sha256(&proof.signer_public_key),
        })
    );
}

fn verify_json(args: &[String]) {
    let domain = required_arg(args, "--domain").expect("--domain");
    let input_path = PathBuf::from(required_arg(args, "--input").expect("--input"));
    let signature_path = PathBuf::from(required_arg(args, "--signature").expect("--signature"));
    let expected_signer_sha256 = arg_value(args, "--expected-signer-sha256");
    let payload = fs::read(&input_path).expect("read JSON payload");
    serde_json::from_slice::<serde_json::Value>(&payload).expect("input must be JSON");
    let proof: DetachedJsonSignatureProof =
        read_json(&signature_path).expect("read detached JSON signature proof");
    if proof.schema != "synergy-aegis-detached-json-signature-v1" {
        panic!("unsupported detached signature schema");
    }
    if proof.domain != domain {
        panic!("signature domain mismatch");
    }
    if proof.payload_sha256 != sha256_hex(&payload) {
        panic!("signed JSON payload hash mismatch");
    }
    let public_sha256 = public_identity_sha256(&proof.signer_public_key);
    if let Some(expected) = expected_signer_sha256 {
        if !public_sha256.eq_ignore_ascii_case(&expected) {
            panic!("archive authority public identity SHA256 mismatch");
        }
    }
    let verifier = AegisPqvmVerifier::initialize_required_for_public_key(
        proof.signer_public_key.clone(),
        proof.lifecycle.clone(),
    )
    .expect("initialize Aegis verifier");
    verifier
        .verify_domain_signature(
            &domain,
            &payload,
            &proof.signer_uma_id,
            &proof.signing_key_id,
            proof.lifecycle.active_from_epoch,
            AegisPqKeyRole::ArchiveSnapshotSigner,
            &proof.aegis_pq_signature,
        )
        .expect("verify Aegis JSON signature");
    println!(
        "{}",
        serde_json::json!({
            "ok": true,
            "domain": domain,
            "payload_sha256": proof.payload_sha256,
            "signer_uma_id": proof.signer_uma_id,
            "signing_key_id": proof.signing_key_id,
            "public_identity_sha256": public_sha256,
            "real_aegis_pqvm": true,
        })
    );
}

fn test_only_create_snapshot_fixture(args: &[String]) {
    if std::env::var("SYNERGY_ARCHIVE_FIXTURE_MODE")
        .ok()
        .as_deref()
        != Some("1")
    {
        panic!("test-only snapshot fixture generation requires SYNERGY_ARCHIVE_FIXTURE_MODE=1");
    }
    let output = PathBuf::from(required_arg(args, "--output").expect("--output"));
    let snapshot_class = required_arg(args, "--snapshot-class").expect("--snapshot-class");
    if output.exists() {
        panic!("refusing to overwrite existing test-only snapshot fixture");
    }
    fs::create_dir_all(&output).expect("create test-only snapshot fixture directory");
    write_public_json(
        &output.join("chain.json"),
        &serde_json::json!([
            {"block_index": 99, "hash": "fixture-parent-hash", "parent_hash": "fixture-grandparent-hash"},
            {"block_index": 100, "hash": "fixture-block-hash", "parent_hash": "fixture-parent-hash"}
        ]),
    )
    .expect("write fixture chain");
    write_public_json(
        &output.join("canonical_locks.json"),
        &serde_json::json!({"100": {"hash": "fixture-block-hash"}}),
    )
    .expect("write fixture canonical lock");
    fs::write(
        output.join("committed_qcs.jsonl"),
        "{\"height\":100,\"block_hash\":\"fixture-block-hash\"}\n",
    )
    .expect("write fixture committed QC");
    write_public_json(
        &output.join("token_state.json"),
        &serde_json::json!({"fixture": true}),
    )
    .expect("write fixture token state");
    write_public_json(
        &output.join("validator_registry.json"),
        &serde_json::json!({"fixture": true}),
    )
    .expect("write fixture validator registry");

    let active_validator_set = (1..=5)
        .map(|index| format!("fixture-validator-{index}"))
        .collect::<Vec<_>>();
    let required_quorum =
        required_snapshot_quorum_for_validator_count(active_validator_set.len()) as usize;
    let qc_signers = active_validator_set
        .iter()
        .take(required_quorum)
        .cloned()
        .collect::<Vec<_>>();
    let mut signer = AegisPqvmSigner::initialize_required().expect("Aegis fixture signer");
    let signer_uma = "snapshot-source:archive-fixture".to_string();
    let signing_key_id = signer
        .generate_and_register_key(
            &signer_uma,
            vec![AegisPqKeyRole::ArchiveSnapshotSigner],
            Epoch(0),
        )
        .expect("fixture snapshot signing key");
    let signer_public_key = signer
        .public_key_record(&signing_key_id)
        .expect("fixture snapshot signer public key");
    let source_role = if snapshot_class == SNAPSHOT_CLASS_VALIDATOR_PRUNED {
        "VALIDATOR"
    } else {
        "ARCHIVE_NODE"
    };
    let manifest = create_snapshot_manifest(SnapshotBuildInput {
        state_dir: output.clone(),
        snapshot_class: snapshot_class.clone(),
        allowed_restore_roles: default_allowed_restore_roles_for_class(&snapshot_class)
            .expect("supported fixture snapshot class"),
        snapshot_height: 100,
        snapshot_block_hash: "fixture-block-hash".to_string(),
        parent_hash: "fixture-parent-hash".to_string(),
        state_root: None,
        canonical_lock_height: 100,
        canonical_lock_hash: "fixture-block-hash".to_string(),
        qc_evidence: SnapshotQcEvidence {
            committed_qc_height: 100,
            committed_qc_hash: "fixture-block-hash".to_string(),
            vote_count: required_quorum as u64,
            signer_set: qc_signers.clone(),
            aegis_pqc_verified: true,
            duplicate_signer_check_passed: true,
            active_validator_count: active_validator_set.len(),
            active_validator_set_meets_baseline: true,
            relayers_rpc_support_counted_toward_quorum: false,
        },
        active_validator_set,
        source_node_id: "archive-fixture".to_string(),
        source_role: source_role.to_string(),
        runtime_checksum: "fixture-runtime-sha256".to_string(),
        source_node_quarantined: false,
        source_node_majority_branch: true,
        conflict_height_hash: None,
        manifest_signer_uma_id: signer_uma,
        manifest_signing_key_id: signing_key_id,
        manifest_signer_public_key: signer_public_key,
        manifest_signature_epoch: 0,
        created_at: now_secs(),
    })
    .expect("create fixture snapshot manifest");
    let signed =
        sign_snapshot_manifest(&mut signer, manifest).expect("sign fixture snapshot manifest");
    let manifest_path = output.join("snapshot-100-manifest.json");
    write_public_json(&manifest_path, &signed).expect("write fixture snapshot manifest");
    println!(
        "{}",
        serde_json::json!({
            "success": true,
            "fixture_only": true,
            "snapshot_path": output,
            "manifest_path": manifest_path,
            "snapshot_height": 100,
            "snapshot_hash": "fixture-block-hash",
            "qc_vote_count": required_quorum,
            "qc_signers": qc_signers,
        })
    );
}

fn required_arg(args: &[String], name: &str) -> Result<String, String> {
    arg_value(args, name).ok_or_else(|| format!("missing {name}"))
}

fn arg_value(args: &[String], name: &str) -> Option<String> {
    args.windows(2)
        .find(|pair| pair[0] == name)
        .map(|pair| pair[1].clone())
}

fn read_json<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T, String> {
    let bytes = fs::read(path).map_err(|error| format!("read {}: {error}", path.display()))?;
    serde_json::from_slice(&bytes).map_err(|error| format!("parse {}: {error}", path.display()))
}

fn write_public_json<T: Serialize>(path: &Path, value: &T) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| format!("create {}: {error}", parent.display()))?;
    }
    let bytes = serde_json::to_vec_pretty(value)
        .map_err(|error| format!("serialize {}: {error}", path.display()))?;
    fs::write(path, bytes).map_err(|error| format!("write {}: {error}", path.display()))
}

fn write_private_json<T: Serialize>(path: &Path, value: &T) -> Result<(), String> {
    write_public_json(path, value)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .map_err(|error| format!("chmod {}: {error}", path.display()))?;
    }
    Ok(())
}

fn public_identity_sha256(public_key: &AegisPqPublicKey) -> String {
    sha256_hex(&serde_json::to_vec(public_key).expect("serialize archive authority public key"))
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or_default()
}
