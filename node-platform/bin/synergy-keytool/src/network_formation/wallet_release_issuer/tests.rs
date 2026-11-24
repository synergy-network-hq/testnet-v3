use super::*;
use std::os::unix::fs::{symlink, PermissionsExt};
use synergy_address_engine::apqe::provider::{
    NativeVerificationQualification, SignOptions, Target, BACKEND_ABI, IMPORT_MANIFEST_SHA256,
    MODULE_REVISION, SELECTED_MANIFEST_SHA256,
};
use synergy_address_engine::apqe::{
    enrollment_commit::UnactivatedCommitmentProfile, enrollment_registry::EnrollmentRegistryRelease,
};
use synergy_genesis::authority::{
    ProtectedWalletDispatchPolicy, SignedWalletDispatchRelease, WalletDispatchReleasePayload,
};

pub(in crate::network_formation) fn exercise(
    context: &Path,
    formation_sha256: &str,
    formation: &Path,
    parent: &Path,
    engine: crate::provider::Engine,
) {
    let prepared = load(context, formation_sha256, formation, engine.clone()).unwrap();
    let signed = prepared.read_signed_formation(formation).unwrap().unwrap();
    let origin = &signed.authority.payload;
    let genesis = &signed.genesis.genesis_hash;
    let report = std::env::var("APQE_AUTHENTICATED_REPORT_SHA256").unwrap();
    let provider_report = parse_digest(&report).unwrap();
    let reviewed = parent.join("reviewed-wallet-release");
    begin(&reviewed).unwrap();
    let engine_guard = engine.lock().unwrap();
    let issuer = engine_guard.generate_keypair(Algorithm::MlDsa65).unwrap();
    let proof = engine_guard
        .provider_provenance(Algorithm::MlDsa87)
        .unwrap();
    let target = match Target::current() {
        Target::DarwinArm64 => "aarch64-apple-darwin",
        Target::LinuxX86_64Gnu => "x86_64-unknown-linux-gnu",
        Target::LinuxArm64Gnu => "aarch64-unknown-linux-gnu",
        _ => panic!("unsupported native qualification fixture target"),
    };
    let index = serde_json::to_vec(&json!({
        "version":1, "chain_id":origin.chain_id, "network_id":origin.network_id, "genesis_hash":genesis,
        "platforms":[{"target":target,"base_package_manifest_sha256":"11".repeat(32),
            "executable_size":1, "executable_sha256":"12".repeat(32), "apqe_report_sha256":report}],
    })).unwrap();
    write(
        &reviewed.join("wallet-dispatch-managed-artifacts.json"),
        &index,
    )
    .unwrap();
    write(
        &reviewed.join("wallet-dispatch-release-issuer.pub"),
        &issuer.public_key,
    )
    .unwrap();
    let registry = FrozenValidatorRegistry::new(
        origin.epoch,
        origin.validators.iter().map(|v| v.record.clone()).collect(),
    )
    .unwrap();
    let predecessor = SimplifiedEpochContext::from_frozen_registry(
        origin.chain_id,
        origin.network_id.clone(),
        origin.epoch,
        origin.epoch_start_height,
        origin.epoch_end_height,
        origin.finalized_epoch_seed_root.clone(),
        origin.consensus_parameter_root.clone(),
        &registry,
    )
    .unwrap();
    let parameters = &origin.protected.as_ref().unwrap().parameters;
    let payload = WalletDispatchReleasePayload {
        version: 1,
        predecessor_context_root: predecessor.root().unwrap(),
        signer_key_id: "wallet-issuer-fixture".into(),
        policy: ProtectedWalletDispatchPolicy {
            version: 1,
            chain_id: origin.chain_id,
            network_id: origin.network_id.clone(),
            genesis_hash: genesis.clone(),
            activation_finalized_height: origin.epoch_end_height + 1,
            managed_release_manifest_sha256: digest(&index),
            off_chain_approval_sha256: "21".repeat(32),
            release_attestation_sha256: "22".repeat(32),
            action_registry_sha256: "23".repeat(32),
            wire_schema_sha256: "24".repeat(32),
            action_vectors_sha256: "25".repeat(32),
            ownership_chain_id: format!("{:064x}", 1),
            enrollment_wire_profile_fingerprint: "27".repeat(32),
            enrollment_commitment_profile_fingerprint:
                EnrollmentRegistryRelease::commitment_fingerprint(
                    UnactivatedCommitmentProfile::candidate_concat_v1(),
                )
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect(),
            enrollment_provider_manifests: vec!["29".repeat(32)],
            enrollment_proof_provider_artifacts: vec![proof
                .artifact_sha256
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect()],
            fee_collector: "synf1fixture".into(),
            fee_class: 1,
            base_fee_per_gas_nwei: 40,
            enroll_commit_gas: 50_000,
            enroll_reveal_gas: 100_000,
            transfer_gas: 21_000,
        },
    };
    let sign = |bytes: &[u8]| {
        engine_guard
            .sign(
                Algorithm::MlDsa65,
                issuer.private_key.as_bytes(),
                bytes,
                SignOptions::default(),
            )
            .unwrap()
    };
    let attachment = SignedWalletDispatchRelease {
        signature: sign(&payload.signing_bytes().unwrap()),
        signature_algorithm: SignatureAlgorithm::MlDsa65,
        payload: payload.clone(),
    };
    let attachment_bytes = serde_json::to_vec(&attachment).unwrap();
    write(
        &reviewed.join("wallet-dispatch-release.json"),
        &attachment_bytes,
    )
    .unwrap();
    let qualification = NativeVerificationQualification {
        version: 1,
        target: target.into(),
        artifact_sha256: proof.artifact_sha256,
        report_sha256: provider_report,
        release_attestation_sha256: parse_digest(&payload.policy.release_attestation_sha256)
            .unwrap(),
        release_context: payload.release_context().unwrap(),
        backend_abi: BACKEND_ABI,
        backend_revision: MODULE_REVISION.into(),
        selected_manifest_sha256: SELECTED_MANIFEST_SHA256.into(),
        import_manifest_sha256: IMPORT_MANIFEST_SHA256.into(),
        native_identity: proof.native_identity.clone(),
    };
    let qualification = serde_json::to_vec(&SignedNativeVerificationQualification {
        signature: sign(&qualification.signing_bytes().unwrap()),
        qualification,
    })
    .unwrap();
    write(&reviewed.join(QUALIFICATION_FILE), &qualification).unwrap();
    drop(engine_guard);

    let request = json!({"version":1, "operation":ACTION, "parameters":{
        "formation_sha256":formation_sha256, "formation_review_sha256":prepared.review_pin,
        "genesis_sha256":digest(signed.genesis_bytes.as_bytes()),
        "authority_sha256":digest(signed.authority_bytes.as_bytes()),
        "authority_root_sha256":prepared.review.authority_root_sha256,
        "attachment_sha256":digest(&attachment_bytes),
        "issuer_sha256":digest(&issuer.public_key),"issuer_key_id":payload.signer_key_id,
        "qualification_sha256":digest(&qualification),
        "managed_release_manifest_sha256":payload.policy.managed_release_manifest_sha256,
        "off_chain_approval_sha256":payload.policy.off_chain_approval_sha256,
        "release_attestation_sha256":payload.policy.release_attestation_sha256,
        "predecessor":predecessor,"parameters":parameters,
    }});
    let request_bytes = serde_json::to_vec(&request).unwrap();
    let request_path = reviewed.join("request.json");
    write(&request_path, &request_bytes).unwrap();
    let request_pin = digest(&request_bytes);
    let invoke = |request: &Path, request_sha256: &str, provider_report_sha256: &str| {
        delegate(
            Inputs {
                context,
                formation_sha256,
                formation,
                reviewed: &reviewed,
                request,
                request_sha256,
                provider_report_sha256,
            },
            engine.clone(),
        )
    };
    let observe = |request: &Path, request_sha256: &str, provider_report_sha256: &str| {
        inspect(
            Inputs {
                context,
                formation_sha256,
                formation,
                reviewed: &reviewed,
                request,
                request_sha256,
                provider_report_sha256,
            },
            engine.clone(),
        )
    };
    let set_custody_permissions = |mode| {
        for file in ["authority.enc.json", "unlock"] {
            fs::set_permissions(formation.join(file), fs::Permissions::from_mode(mode)).unwrap();
        }
    };
    let reservations = formation.join(RESERVATIONS);
    assert!(invoke(&request_path, &"11".repeat(32), &report).is_err());
    assert!(invoke(&request_path, &request_pin, &"11".repeat(32)).is_err());
    assert!(observe(&request_path, &"11".repeat(32), &report).is_err());
    assert!(observe(&request_path, &request_pin, &"11".repeat(32)).is_err());
    set_custody_permissions(0o000);
    let ready = observe(&request_path, &request_pin, &report).unwrap();
    assert_eq!(ready["state"], "ready");
    assert_eq!(ready["request_sha256"], request_pin);
    assert_eq!(ready["genesis_hash"], *genesis);
    assert_eq!(ready["issuer_sha256"], digest(&issuer.public_key));
    assert_eq!(
        ready["predecessor_context_root"],
        predecessor.root().unwrap()
    );
    assert!(ready["delegation"].is_null());
    set_custody_permissions(0o600);
    assert!(!reservations.exists());
    let first = invoke(&request_path, &request_pin, &report).unwrap();
    assert_eq!(first["genesis_hash"], *genesis);
    let output = first["authorization_json"].as_str().unwrap();
    assert_eq!(first["authorization_sha256"], digest(output.as_bytes()));
    assert_eq!(invoke(&request_path, &request_pin, &report).unwrap(), first);
    set_custody_permissions(0o000);
    let observed = observe(&request_path, &request_pin, &report).unwrap();
    assert_eq!(observed["state"], "signed");
    assert_eq!(observed["delegation"], first);
    set_custody_permissions(0o600);
    let mut delegation: WalletDispatchReleaseIssuerAuthorization =
        serde_json::from_str(output).unwrap();
    let check = |public: &[u8]| {
        engine
            .lock()
            .unwrap()
            .verify(
                Algorithm::MlDsa65,
                public,
                &delegation.signing_bytes().unwrap(),
                &delegation.signature,
                SignOptions::default(),
            )
            .unwrap()
    };
    assert!(check(&prepared.public));
    assert!(!check(&issuer.public_key));

    let mut changed_request = request_bytes;
    changed_request.push(b'\n');
    let changed_path = reviewed.join("different-approved-bytes.json");
    write(&changed_path, &changed_request).unwrap();
    assert!(invoke(&changed_path, &digest(&changed_request), &report)
        .unwrap_err()
        .contains("different approved request"));
    assert!(observe(&changed_path, &digest(&changed_request), &report)
        .unwrap_err()
        .contains("different approved request"));
    let slot = reservations.join(first["attachment_sha256"].as_str().unwrap());
    let retained = slot.join(AUTHORIZATION_FILE);
    delegation.signature[0] ^= 1;
    fs::write(&retained, serde_json::to_vec(&delegation).unwrap()).unwrap();
    assert!(observe(&request_path, &request_pin, &report).is_err());
    fs::remove_file(&retained).unwrap();
    symlink(slot.join("absent-authorization"), &retained).unwrap();
    assert!(observe(&request_path, &request_pin, &report).is_err());
    fs::remove_file(&retained).unwrap();
    let interrupted = observe(&request_path, &request_pin, &report).unwrap();
    assert_eq!(interrupted["state"], "interrupted");
    assert!(interrupted["delegation"].is_null());
    assert!(invoke(&request_path, &request_pin, &report)
        .unwrap_err()
        .contains("Interrupted Wallet issuer delegation"));
    fs::remove_file(slot.join(APPROVED_REQUEST)).unwrap();
    assert_eq!(
        observe(&request_path, &request_pin, &report).unwrap()["state"],
        "interrupted"
    );
    assert!(!retained.exists());
    eprintln!(
        "Native Wallet issuer readiness, delegation, verified read-only reopen and interrupted-write refusal passed"
    );
}
