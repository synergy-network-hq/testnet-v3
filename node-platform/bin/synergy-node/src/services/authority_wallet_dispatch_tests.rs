use super::super::wallet_release_artifacts::{self, ManagedArtifacts, Platform, PlatformArtifact};
use super::*;
use synergy_address_engine::{
    apqe::{
        crypto_engine::{CryptoEngine, EncodedKeyPair},
        enrollment_commit::UnactivatedCommitmentProfile,
        enrollment_registry::EnrollmentRegistryRelease,
        provider::{
            NativeVerificationQualification, Operation, Profile, SignOptions,
            SignedNativeVerificationQualification, Target, BACKEND_ABI, IMPORT_MANIFEST_SHA256,
            MODULE_REVISION, SELECTED_MANIFEST_SHA256,
        },
    },
    types::Algorithm,
};
use synergy_aegis::{AegisSigner, PqvmSigner};
use synergy_genesis::authority::{
    ProtectedWalletDispatchPolicy, SignedWalletDispatchRelease,
    WalletDispatchReleaseIssuerAuthorization, WalletDispatchReleasePayload,
    WalletDispatchReleaseTrust, WALLET_RELEASE_ISSUER_DOMAIN,
};

fn fixture_release_policy(
    origin: &VerifiedAuthority,
    genesis_hash: &str,
    artifacts: &[u8],
    provider_manifest_sha256: String,
    proof_artifact_sha256: [u8; 32],
) -> ProtectedWalletDispatchPolicy {
    let hash = apqe_transport::sha256;
    let hex = |value: [u8; 32]| value.iter().map(|byte| format!("{byte:02x}")).collect();
    let wire = crate::services::protected_accounts::inspection::candidate_wire_profile().unwrap();
    ProtectedWalletDispatchPolicy {
        version: 1,
        chain_id: origin.epoch.chain_id,
        network_id: origin.epoch.network_id.clone(),
        genesis_hash: genesis_hash.into(),
        activation_finalized_height: origin.epoch.epoch_end_height + 1,
        managed_release_manifest_sha256: hash(artifacts),
        off_chain_approval_sha256: hash(b"existing off-chain approval fixture"),
        release_attestation_sha256: hash(b"release conformance attestation fixture"),
        action_registry_sha256: hash(include_bytes!("protected_quick_setup_registry.json")),
        wire_schema_sha256: hash(include_bytes!("protected_quick_setup_wire.cddl")),
        action_vectors_sha256: hash(include_bytes!("protected_quick_setup_vectors.json")),
        ownership_chain_id: format!("{:064x}", 1),
        enrollment_wire_profile_fingerprint: hex(wire
            .dual_enrollment_profile_fingerprint()
            .unwrap()),
        enrollment_commitment_profile_fingerprint: hex(
            EnrollmentRegistryRelease::commitment_fingerprint(
                UnactivatedCommitmentProfile::candidate_concat_v1(),
            ),
        ),
        enrollment_provider_manifests: vec![provider_manifest_sha256],
        enrollment_proof_provider_artifacts: vec![hex(proof_artifact_sha256)],
        fee_collector: synergy_address::generate_fee_collector_address("protected-release-fixture")
            .unwrap(),
        fee_class: 1,
        base_fee_per_gas_nwei: 1,
        enroll_commit_gas: 10,
        enroll_reveal_gas: 100,
        transfer_gas: 20,
    }
}

fn fixture_native_qualification(
    engine: &CryptoEngine,
    issuer: &EncodedKeyPair,
    release: &VerifiedWalletDispatchRelease,
    report_pin: &str,
    attestation_pin: &str,
) -> SignedNativeVerificationQualification {
    let selected = engine.provider_provenance(Algorithm::MlDsa87).unwrap();
    let target = match Target::current() {
        Target::DarwinArm64 => "aarch64-apple-darwin",
        Target::LinuxX86_64Gnu => "x86_64-unknown-linux-gnu",
        Target::LinuxArm64Gnu => "aarch64-unknown-linux-gnu",
        _ => panic!("fixture requires the selected native test platform"),
    };
    let qualification = NativeVerificationQualification {
        version: 1,
        target: target.into(),
        artifact_sha256: selected.artifact_sha256,
        report_sha256: synergy_posy::parse_hash_bytes(report_pin).unwrap(),
        release_attestation_sha256: synergy_posy::parse_hash_bytes(attestation_pin).unwrap(),
        release_context: release.enrollment().statement().release_context,
        backend_abi: BACKEND_ABI,
        backend_revision: MODULE_REVISION.into(),
        selected_manifest_sha256: SELECTED_MANIFEST_SHA256.into(),
        import_manifest_sha256: IMPORT_MANIFEST_SHA256.into(),
        native_identity: selected.native_identity.clone(),
    };
    let signature = engine
        .sign(
            Algorithm::MlDsa65,
            issuer.private_key.as_bytes(),
            &qualification.signing_bytes().unwrap(),
            SignOptions::default(),
        )
        .unwrap();
    SignedNativeVerificationQualification {
        qualification,
        signature,
    }
}

fn fixture_origin_endorsement(
    genesis: &synergy_genesis::signing::SignedGenesis,
    pins: &synergy_config::ManagedWalletDispatchReleaseConfiguration,
    signer: &impl AegisSigner,
) -> Vec<u8> {
    let mut authorization = WalletDispatchReleaseIssuerAuthorization {
        version: 1,
        genesis_hash: genesis.genesis_hash.clone(),
        attachment_sha256: pins.attachment_sha256.clone(),
        issuer_sha256: pins.issuer_sha256.clone(),
        issuer_key_id: pins.issuer_key_id.clone(),
        signature: Vec::new(),
    };
    authorization.signature = signer
        .sign(
            &KeyId::new(genesis.unsigned.authority_trust_key_id.clone()).unwrap(),
            &SigningContext {
                domain: WALLET_RELEASE_ISSUER_DOMAIN.into(),
                chain_id: genesis.unsigned.network.chain_id,
                epoch: None,
                height: None,
            },
            &authorization.signing_bytes().unwrap(),
        )
        .unwrap()
        .bytes;
    serde_json::to_vec(&authorization).unwrap()
}

/// Stage independently signed public inputs for the ordinary runtime process.
/// The runtime still authenticates the current executable and consumes the
/// release only when its original PoSy successor is actually certified.
pub(crate) fn stage_process_wallet_release(
    config: &NodeConfiguration,
    binary: &std::path::Path,
    provider_manifest_sha256: String,
    engine: &Arc<Mutex<CryptoEngine>>,
    origin_signer: &impl AegisSigner,
) -> synergy_config::ManagedWalletDispatchReleaseConfiguration {
    use std::io::{Read, Write};
    use synergy_address_engine::apqe::{HashAlgorithm, Primitives};

    let origin = load(config).unwrap().unwrap();
    assert!(origin.autonomous_epochs_enabled());
    assert!(origin.wallet_dispatch_policy().is_none());
    let signed_genesis = crate::commands::selected_network::verified_genesis(config).unwrap();
    let expected_report = &config
        .aegis_provider
        .as_ref()
        .unwrap()
        .authenticated_report_sha256;
    let stamp = apqe_transport::Stamp::capture(binary).unwrap();
    let executable = fs::File::open(binary).unwrap();
    let executable_size = executable.metadata().unwrap().len();
    assert!((1..=512 * 1024 * 1024).contains(&executable_size));
    let mut executable = executable.take(executable_size + 1);
    let mut hash = Primitives.hash_stream(HashAlgorithm::Sha256).unwrap();
    let mut buffer = [0; 16 * 1024];
    let mut read = 0;
    loop {
        let count = executable.read(&mut buffer).unwrap();
        if count == 0 {
            break;
        }
        hash.update(&buffer[..count]);
        read += count as u64;
    }
    assert!(read == executable_size && stamp.unchanged());
    let hex = |value: &[u8]| {
        value
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    };
    let artifacts = serde_json::to_vec(&ManagedArtifacts {
        version: 1,
        chain_id: origin.epoch.chain_id,
        network_id: origin.epoch.network_id.clone(),
        genesis_hash: signed_genesis.genesis_hash.clone(),
        platforms: vec![PlatformArtifact {
            target: Platform::current().unwrap(),
            base_package_manifest_sha256: apqe_transport::sha256(
                b"isolated five-process package fixture",
            ),
            executable_size,
            executable_sha256: hex(&hash.finalize()),
            apqe_report_sha256: expected_report.clone(),
        }],
    })
    .unwrap();
    let provider = engine.lock().unwrap();
    let issuer = provider.generate_keypair(Algorithm::MlDsa65).unwrap();
    let public_at = provider.provider_provenance(Algorithm::MlDsa87).unwrap();
    let verifier_at = provider
        .provider_provenance(Algorithm::MlDsa65)
        .unwrap()
        .artifact_sha256;
    let signer_id = KeyId::new("isolated-protected-release-issuer").unwrap();
    let policy = fixture_release_policy(
        &origin,
        &signed_genesis.genesis_hash,
        &artifacts,
        provider_manifest_sha256,
        public_at.artifact_sha256,
    );
    let payload = WalletDispatchReleasePayload {
        version: 1,
        predecessor_context_root: origin.epoch.root().unwrap(),
        signer_key_id: signer_id.as_str().into(),
        policy,
    };
    let signer = |message: &[u8]| {
        provider
            .sign(
                Algorithm::MlDsa65,
                issuer.private_key.as_bytes(),
                message,
                SignOptions::default(),
            )
            .unwrap()
    };
    let release = SignedWalletDispatchRelease {
        signature: signer(&payload.signing_bytes().unwrap()),
        signature_algorithm: SignatureAlgorithm::MlDsa65,
        payload,
    };
    let policy = &release.payload.policy;
    let attachment = serde_json::to_vec(&release).unwrap();
    let pins = synergy_config::ManagedWalletDispatchReleaseConfiguration {
        from_sealed_package: false,
        attachment_sha256: apqe_transport::sha256(&attachment),
        issuer_key_id: signer_id.as_str().into(),
        issuer_sha256: apqe_transport::sha256(&issuer.public_key),
        release_verifier_artifact_sha256: hex(&verifier_at),
        managed_release_manifest_sha256: policy.managed_release_manifest_sha256.clone(),
        off_chain_approval_sha256: policy.off_chain_approval_sha256.clone(),
        release_attestation_sha256: policy.release_attestation_sha256.clone(),
    };
    let trust = WalletDispatchReleaseTrust {
        genesis_hash: &signed_genesis.genesis_hash,
        release_signer_key_id: &signer_id,
        release_signer_public_key: &issuer.public_key,
        release_verifier_artifact_sha256: verifier_at,
        managed_release_manifest_sha256: &pins.managed_release_manifest_sha256,
        off_chain_approval_sha256: &pins.off_chain_approval_sha256,
        release_attestation_sha256: &pins.release_attestation_sha256,
    };
    let release = VerifiedWalletDispatchRelease::verify(
        &attachment,
        &trust,
        &origin.epoch,
        &origin.protected.as_ref().unwrap().parameters,
        &provider,
    )
    .unwrap();
    let qualification = fixture_native_qualification(
        &provider,
        &issuer,
        &release,
        expected_report,
        &pins.release_attestation_sha256,
    );
    // Release qualification and origin endorsement use distinct signing keys.
    drop(provider);
    let authorization = fixture_origin_endorsement(&signed_genesis, &pins, origin_signer);
    let root = config.genesis_path.as_ref().unwrap().parent().unwrap();
    for (name, bytes) in [
        ("wallet-dispatch-release.json", attachment),
        (
            "wallet-dispatch-release-issuer.pub",
            issuer.public_key.clone(),
        ),
        (
            "wallet-dispatch-release-issuer-authorization.json",
            authorization,
        ),
        (
            "wallet-dispatch-ml-dsa-87-qualification.json",
            serde_json::to_vec(&qualification).unwrap(),
        ),
        (wallet_release_artifacts::FILE_NAME, artifacts),
    ] {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(root.join(name))
            .unwrap();
        file.write_all(&bytes).unwrap();
        file.sync_all().unwrap();
    }
    pins
}

pub(super) fn qualify_signed_release(
    config: &NodeConfiguration,
    origin: &VerifiedAuthority,
    validators: &[ValidatorRecord],
    validators_keys: &[EncodedKeyPair],
    engine: &Arc<Mutex<CryptoEngine>>,
    origin_signer: &impl AegisSigner,
) {
    let previous = &origin.epoch;
    let current = origin.protected.as_ref().unwrap();
    let SimplifiedFinalityParent::Genesis { genesis_hash, .. } = &origin.anchor_parent else {
        panic!("signed release fixture requires its original Genesis");
    };
    let key = engine
        .lock()
        .unwrap()
        .generate_keypair(Algorithm::MlDsa65)
        .unwrap();
    let signer_id = KeyId::new("protected-wallet-release-fixture").unwrap();
    let signer = PqvmSigner::with_apqe(
        AegisPolicy {
            allowed_algorithms: vec![SignatureAlgorithm::MlDsa65],
            maximum_message_bytes: 16 * 1024,
            maximum_signature_bytes: 16 * 1024,
        },
        signer_id.clone(),
        &key.public_key,
        key.private_key.as_bytes().to_vec(),
        Arc::clone(engine),
    )
    .unwrap();
    let hash = |value: &[u8]| apqe_transport::sha256(value);
    let hex = |value: [u8; 32]| value.iter().map(|byte| format!("{byte:02x}")).collect();
    let expected_report = &config
        .aegis_provider
        .as_ref()
        .unwrap()
        .authenticated_report_sha256;
    let (executable_size, executable_sha256) =
        wallet_release_artifacts::measure_executable(u64::MAX).unwrap();
    let mut artifacts = ManagedArtifacts {
        version: 1,
        chain_id: previous.chain_id,
        network_id: previous.network_id.clone(),
        genesis_hash: genesis_hash.clone(),
        platforms: vec![PlatformArtifact {
            target: Platform::current().unwrap(),
            base_package_manifest_sha256: hash(b"managed base package fixture"),
            executable_size,
            executable_sha256,
            apqe_report_sha256: expected_report.clone(),
        }],
    };
    let artifacts_bytes = serde_json::to_vec(&artifacts).unwrap();
    let (verifier_sha256, proof_sha256) = {
        let engine = engine.lock().unwrap();
        (
            engine
                .provider_provenance(Algorithm::MlDsa65)
                .unwrap()
                .artifact_sha256,
            engine
                .provider_provenance(Algorithm::MlDsa87)
                .unwrap()
                .artifact_sha256,
        )
    };
    let policy = fixture_release_policy(
        origin,
        genesis_hash,
        &artifacts_bytes,
        hash(b"fixture provider"),
        proof_sha256,
    );
    let payload = WalletDispatchReleasePayload {
        version: 1,
        predecessor_context_root: previous.root().unwrap(),
        signer_key_id: signer_id.as_str().into(),
        policy: policy.clone(),
    };
    let signature = signer
        .sign(
            &signer_id,
            &payload.signing_context(previous).unwrap(),
            &payload.signing_bytes().unwrap(),
        )
        .unwrap();
    let mut release = SignedWalletDispatchRelease {
        payload,
        signature_algorithm: SignatureAlgorithm::MlDsa65,
        signature: signature.bytes,
    };
    let trust = WalletDispatchReleaseTrust {
        genesis_hash,
        release_signer_key_id: &signer_id,
        release_signer_public_key: &key.public_key,
        release_verifier_artifact_sha256: verifier_sha256,
        managed_release_manifest_sha256: &policy.managed_release_manifest_sha256,
        off_chain_approval_sha256: &policy.off_chain_approval_sha256,
        release_attestation_sha256: &policy.release_attestation_sha256,
    };
    let verify = |bytes: &[u8], trust: &WalletDispatchReleaseTrust<'_>| {
        VerifiedWalletDispatchRelease::verify(
            bytes,
            trust,
            previous,
            &current.parameters,
            &engine.lock().unwrap(),
        )
    };
    let bytes = serde_json::to_vec(&release).unwrap();
    let verified = verify(&bytes, &trust).unwrap();
    let root = config.genesis_path.as_ref().unwrap().parent().unwrap();
    let attachment = root.join("wallet-dispatch-release.json");
    let issuer = root.join("wallet-dispatch-release-issuer.pub");
    let authorization_path = root.join("wallet-dispatch-release-issuer-authorization.json");
    let qualification_path = root.join("wallet-dispatch-ml-dsa-87-qualification.json");
    let artifacts_path = root.join(wallet_release_artifacts::FILE_NAME);
    fs::write(&attachment, &bytes).unwrap();
    fs::write(&issuer, &key.public_key).unwrap();
    let mut selected_config = config.clone();
    selected_config.genesis_path = Some(
        config
            .genesis_path
            .as_ref()
            .unwrap()
            .canonicalize()
            .unwrap(),
    );
    let pins = synergy_config::ManagedWalletDispatchReleaseConfiguration {
        from_sealed_package: false,
        attachment_sha256: hash(&bytes),
        issuer_key_id: signer_id.as_str().into(),
        issuer_sha256: hash(&key.public_key),
        release_verifier_artifact_sha256: hex(verifier_sha256),
        managed_release_manifest_sha256: trust.managed_release_manifest_sha256.into(),
        off_chain_approval_sha256: trust.off_chain_approval_sha256.into(),
        release_attestation_sha256: trust.release_attestation_sha256.into(),
    };
    let genesis = crate::commands::selected_network::verified_genesis(config).unwrap();
    let authorization_bytes = fixture_origin_endorsement(&genesis, &pins, origin_signer);
    fs::write(&authorization_path, &authorization_bytes).unwrap();
    selected_config.consensus.managed_wallet_dispatch_release = Some(pins.clone());
    assert!(load(&selected_config)
        .unwrap_err()
        .contains("production ML-DSA-87 qualification"));
    let (qualifier, proof_fixture) = {
        let engine = engine.lock().unwrap();
        let qualification = fixture_native_qualification(
            &engine, &key, &verified, expected_report, &pins.release_attestation_sha256,
        );
        let proof = engine.generate_keypair(Algorithm::MlDsa87).unwrap();
        let proof_signature = engine
            .sign(
                Algorithm::MlDsa87,
                proof.private_key.as_bytes(),
                b"exact native proof fixture",
                SignOptions::default(),
            )
            .unwrap();
        (qualification, (proof, proof_signature))
    };
    let qualifier_bytes = serde_json::to_vec(&qualifier).unwrap();
    fs::write(&qualification_path, &qualifier_bytes).unwrap();
    assert!(load(&selected_config)
        .unwrap_err()
        .contains("artifact manifest"));
    fs::write(&artifacts_path, &artifacts_bytes).unwrap();
    let managed = load(&selected_config).unwrap().unwrap();
    assert!(managed.wallet_dispatch_policy().is_none());
    assert!(managed.native_wallet_release().is_err());
    assert!(origin.wallet_release_preflight(config).unwrap().is_none());
    let pending =
        serde_json::to_value(managed.wallet_release_preflight(config).unwrap().unwrap()).unwrap();
    assert_eq!(pending["state"], "verified_pending");
    assert_eq!(pending["initial_adoption_before_close"], true);
    assert_eq!(pending["quick_setup_enrollment"], true);
    assert_eq!(
        pending["activation_finalized_height"],
        policy.activation_finalized_height
    );
    assert_eq!(
        pending["managed_release_manifest_sha256"],
        policy.managed_release_manifest_sha256
    );
    assert_eq!(
        pending["base_package_manifest_sha256"],
        artifacts.platforms[0].base_package_manifest_sha256
    );
    assert_eq!(
        pending["executable_sha256"],
        artifacts.platforms[0].executable_sha256
    );
    assert_eq!(pending["apqe_report_sha256"], *expected_report);
    let preflight_config = root.join("managed-wallet-preflight-test.json");
    fs::write(
        &preflight_config,
        serde_json::to_vec(&selected_config).unwrap(),
    )
    .unwrap();
    let preflight = crate::commands::start::preflight_wallet_release(&preflight_config).unwrap();
    assert_eq!(
        preflight["schema"],
        "nodenetwork-wallet-release-preflight-v1"
    );
    assert_eq!(preflight["read_only"], true);
    assert_eq!(preflight["genesis_hash"], *genesis_hash);
    assert_eq!(preflight["wallet_dispatch_release"], pending);
    let safety_path = config.storage.data_directory.join("consensus/posy/sign-once.json");
    assert!(!safety_path.exists());
    fs::create_dir_all(safety_path.parent().unwrap()).unwrap();
    fs::write(&safety_path, serde_json::to_vec(&serde_json::json!({
        "format":"synergy-posy-sign-once-v1", "finalized_floor": 1,
        "records": [{ "slot": { "height": policy.activation_finalized_height - 3,
                                  "domain": "block-vote", "round": 0 }, "subject": "reserved" }],
    })).unwrap()).unwrap();
    let reserved = crate::commands::start::preflight_wallet_release(&preflight_config).unwrap();
    assert_eq!(reserved["wallet_dispatch_release"]["initial_adoption_before_close"], false);
    fs::remove_file(safety_path).unwrap();
    let _ = fs::remove_file(&preflight_config);
    let package = root.join("managed-wallet-fixture-package");
    let libraries = package.join("lib/apqe");
    let packaged_artifacts = package.join("assets/wallet-dispatch");
    fs::create_dir_all(&libraries).unwrap();
    fs::create_dir_all(&packaged_artifacts).unwrap();
    let report = &config.aegis_provider.as_ref().unwrap().report_path;
    fs::copy(report, libraries.join("build-report.json")).unwrap();
    for variant in ["mldsa65", "mldsa87", "fndsa1024", "mlkem768", "mlkem1024"] {
        let name = format!("libaegis{variant}.{}", std::env::consts::DLL_EXTENSION);
        fs::copy(report.parent().unwrap().join(&name), libraries.join(&name)).unwrap();
    }
    for path in [&attachment, &issuer, &authorization_path, &qualification_path, &artifacts_path] {
        fs::copy(path, packaged_artifacts.join(path.file_name().unwrap())).unwrap();
    }
    let mut packaged = selected_config.clone();
    packaged.aegis_provider.as_mut().unwrap().report_path = libraries.join("build-report.json");
    packaged.consensus.managed_wallet_dispatch_release.as_mut().unwrap().from_sealed_package = true;
    fs::write(&preflight_config, serde_json::to_vec(&packaged).unwrap()).unwrap();
    assert_eq!(crate::commands::start::preflight_wallet_release(&preflight_config).unwrap()["wallet_dispatch_release"], pending);
    fs::write(packaged_artifacts.join(wallet_release_artifacts::FILE_NAME), b"{}").unwrap();
    assert!(crate::commands::start::preflight_wallet_release(&preflight_config).unwrap_err().contains("manifest differs from signed pin"));
    fs::remove_file(&preflight_config).unwrap();
    fs::remove_dir_all(&package).unwrap();
    {
        use synergy_address_engine::apqe::provider::{PublicKey, SecretKey, Signature};
        let release = managed.managed_wallet_release.as_ref().unwrap();
        let verifier = release.proof_provider.lock().unwrap();
        let public = PublicKey::from_bytes(&proof_fixture.0.public_key).unwrap();
        let signature = Signature::from_bytes(&proof_fixture.1).unwrap();
        assert_eq!(verifier.provider_provenance().profile, Profile::Production);
        assert!(
            verifier
                .capability(Operation::Verify)
                .unwrap()
                .production_available
        );
        assert!(verifier.generate_keypair().is_err());
        assert!(verifier
            .sign(
                b"exact native proof fixture",
                &SecretKey::from_bytes(proof_fixture.0.private_key.as_bytes()).unwrap(),
                SignOptions::default(),
            )
            .is_err());
        assert!(verifier
            .verify(
                b"exact native proof fixture",
                &signature,
                &public,
                SignOptions::default()
            )
            .is_ok());
        assert!(verifier
            .verify(
                b"altered native proof fixture",
                &signature,
                &public,
                SignOptions::default()
            )
            .is_err());
    }
    fs::write(&artifacts_path, b"{}").unwrap();
    assert!(load(&selected_config)
        .unwrap_err()
        .contains("manifest differs from signed pin"));
    let mut index_policy = policy.clone();
    let original_index_scope =
        std::mem::replace(&mut artifacts.genesis_hash, hash(b"other Genesis"));
    let foreign = serde_json::to_vec(&artifacts).unwrap();
    index_policy.managed_release_manifest_sha256 = hash(&foreign);
    fs::write(&artifacts_path, &foreign).unwrap();
    assert!(
        ManagedArtifacts::verify_current(root, &index_policy, expected_report)
            .unwrap_err()
            .contains("outside the signed scope")
    );
    artifacts.genesis_hash = original_index_scope;
    artifacts.platforms[0].executable_sha256 = hash(b"different signed native executable");
    let wrong_executable = serde_json::to_vec(&artifacts).unwrap();
    index_policy.managed_release_manifest_sha256 = hash(&wrong_executable);
    fs::write(&artifacts_path, &wrong_executable).unwrap();
    assert!(
        ManagedArtifacts::verify_current(root, &index_policy, expected_report)
            .unwrap_err()
            .contains("does not select the running executable")
    );
    fs::write(&artifacts_path, &artifacts_bytes).unwrap();
    assert!(
        ManagedArtifacts::verify_current(root, &policy, &hash(b"wrong APQE report"))
            .unwrap_err()
            .contains("does not select the authenticated APQE report")
    );
    let mut wrong_qualification = qualifier;
    wrong_qualification.qualification.report_sha256[0] ^= 1;
    fs::write(
        &qualification_path,
        serde_json::to_vec(&wrong_qualification).unwrap(),
    )
    .unwrap();
    assert!(load(&selected_config)
        .unwrap_err()
        .contains("production ML-DSA-87 qualification"));
    fs::write(&qualification_path, &qualifier_bytes).unwrap();
    let mut authorization: WalletDispatchReleaseIssuerAuthorization =
        serde_json::from_slice(&authorization_bytes).unwrap();
    authorization.signature[0] ^= 1;
    fs::write(
        &authorization_path,
        serde_json::to_vec(&authorization).unwrap(),
    )
    .unwrap();
    assert!(load(&selected_config)
        .unwrap_err()
        .contains("delegation signature is invalid"));
    selected_config
        .consensus
        .managed_wallet_dispatch_release
        .as_mut()
        .unwrap()
        .issuer_sha256 = hash(b"wrong issuer");
    assert!(load(&selected_config)
        .unwrap_err()
        .contains("outside the signed origin delegation"));
    selected_config.consensus.managed_wallet_dispatch_release = Some(pins.clone());
    fs::write(attachment, b"{}").unwrap();
    assert!(load(&selected_config)
        .unwrap_err()
        .contains("outside the signed origin delegation"));
    assert!(load(config)
        .unwrap()
        .unwrap()
        .wallet_dispatch_policy()
        .is_none());
    for wrong in [
        WalletDispatchReleaseTrust {
            genesis_hash: &"a".repeat(64),
            ..trust
        },
        WalletDispatchReleaseTrust {
            off_chain_approval_sha256: &"b".repeat(64),
            ..trust
        },
        WalletDispatchReleaseTrust {
            release_attestation_sha256: &"c".repeat(64),
            ..trust
        },
        WalletDispatchReleaseTrust {
            managed_release_manifest_sha256: &"d".repeat(64),
            ..trust
        },
        WalletDispatchReleaseTrust {
            release_signer_public_key: &validators_keys[0].public_key,
            ..trust
        },
        WalletDispatchReleaseTrust {
            release_verifier_artifact_sha256: [7; 32],
            ..trust
        },
    ] {
        assert!(verify(&bytes, &wrong).is_err());
    }
    let mut reformatted = bytes.clone();
    reformatted.push(b'\n');
    assert!(verify(&reformatted, &trust).is_err());
    let original_signer = release.payload.signer_key_id.clone();
    let alternate_signer = KeyId::new("same-key-different-release-label").unwrap();
    release.payload.signer_key_id = alternate_signer.as_str().into();
    assert!(verify(
        &serde_json::to_vec(&release).unwrap(),
        &WalletDispatchReleaseTrust {
            release_signer_key_id: &alternate_signer,
            ..trust
        },
    )
    .is_err());
    release.payload.signer_key_id = original_signer;
    release.payload.policy.transfer_gas += 1;
    assert!(verify(&serde_json::to_vec(&release).unwrap(), &trust).is_err());

    let (subject, next_policy) = verified
        .prepare_successor(previous, current, &origin.registry)
        .unwrap();
    assert_eq!(next_policy.wallet_dispatch.as_ref(), Some(&policy));
    assert_eq!(
        next_policy.cryptographic_profile_root,
        current.cryptographic_profile_root
    );
    assert_eq!(next_policy.initial_world_state, current.initial_world_state);
    assert_ne!(
        subject,
        unchanged_successor_subject(previous, &origin.registry, current)
            .unwrap()
            .0
    );
    let (mut proof, _) = signed_derived_test_proof(
        previous,
        subject,
        validators.to_vec(),
        validators_keys,
        engine,
        None,
    );
    let replay = |proof: &DerivedEpochProof, release: Option<&VerifiedWalletDispatchRelease>| {
        verify_next_derived_with_wallet_release(
            Arc::new(origin.clone()),
            &serde_json::to_vec(proof).unwrap(),
            release,
        )
    };
    assert!(replay(&proof, None).is_err());
    let accepted = replay(&proof, Some(&verified)).unwrap();
    assert!(accepted.matches_wallet_dispatch_release(&verified).is_ok());
    assert!(origin.matches_wallet_dispatch_release(&verified).is_err());
    assert_eq!(
        accepted.wallet_dispatch_policy(),
        next_policy.wallet_dispatch.as_ref()
    );
    assert_eq!(
        accepted.epoch.consensus_parameter_root,
        next_policy.commitment().unwrap()
    );
    // The normal admission handle may publish only after the verified release
    // is selected by the certified successor. ETDAG separately confirms the
    // exact durable execution commitment before calling that internal boundary.
    let active = verify_next_derived_with_wallet_release(
        managed.clone(),
        &serde_json::to_vec(&proof).unwrap(),
        None,
    )
    .unwrap();
    crate::services::apqe_rpc_service::qualify_fresh_gateway_successor(
        &selected_config,
        managed.clone(),
        active.clone(),
        &serde_json::to_vec(&proof).unwrap(),
    );
    let active_preflight =
        serde_json::to_value(active.wallet_release_preflight(config).unwrap().unwrap()).unwrap();
    assert_eq!(active_preflight["state"], "active");
    assert_eq!(active_preflight["initial_adoption_before_close"], false);
    assert_eq!(
        active_preflight["managed_release_manifest_sha256"],
        pending["managed_release_manifest_sha256"]
    );
    if let Some(output) = std::env::var_os("SYNERGY_TEST_EXPORT_WALLET_RELEASE") {
        let output = std::path::PathBuf::from(output);
        assert!(
            output.is_absolute()
                && output.canonicalize().unwrap() == output
                && output.read_dir().unwrap().next().is_none()
        );
        let epoch = serde_json::to_string(&proof).unwrap();
        let page = serde_json::to_vec(&serde_json::json!({
            "chain_id": active.epoch.chain_id,
            "network_id": active.epoch.network_id,
            "epoch": active.epoch.epoch,
            "epoch_context_root": active.epoch.root().unwrap(),
            "kind": "derived-v1",
            "sha256": hash(epoch.as_bytes()),
            "artifact_json": epoch,
        }))
        .unwrap();
        let public = |path: &Option<std::path::PathBuf>| fs::read(path.as_ref().unwrap()).unwrap();
        let [finality, block, world, context] =
            signed_sponsor_source(&active, validators, validators_keys, engine);
        for (relative, bytes) in [
            ("genesis.json", public(&config.genesis_path)),
            (
                "authority.json",
                public(&config.consensus.authority_binding),
            ),
            (
                "authority-root.pub",
                public(&config.consensus.authority_trust_key_path),
            ),
            ("wallet-dispatch-release.json", bytes.clone()),
            ("wallet-dispatch-release-issuer.pub", key.public_key.clone()),
            (
                "wallet-dispatch-release-issuer-authorization.json",
                authorization_bytes,
            ),
            (
                "wallet-dispatch-ml-dsa-87-qualification.json",
                qualifier_bytes.clone(),
            ),
            ("wallet-dispatch-managed-artifacts.json", artifacts_bytes),
            ("selection.json", serde_json::to_vec(&pins).unwrap()),
            ("epoch-2-result.json", page),
            ("source-finality.json", finality),
            ("source-block-commitment.json", block),
            ("source-world.json", world),
            ("sponsor-processing-context.json", context),
        ] {
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(output.join(relative))
                .unwrap();
            std::io::Write::write_all(&mut file, &bytes).unwrap();
        }
    }
    let handle = crate::services::protected_admission::AdmissionHandle::default();
    let source = FinalizedBlockRecord {
        height: active.epoch.epoch_start_height,
        block_id: hash(b"fixture execution source"),
        finality_certificate_id: hash(b"fixture finality id"),
        protected_execution_root: hash(b"fixture protected execution"),
    };
    let state_root = hash(b"fixture executed state");
    crate::services::rpc::proofs::qualify_wallet_world_disclosure(&active, &source, genesis_hash);
    assert!(handle
        .publish_wallet_processing_context(&managed, Some((&source, &state_root)))
        .is_err());
    assert!(handle
        .wallet_processing_context(
            &active,
            trust.genesis_hash,
            synergy_etdag::admission::PW13_SPONSOR_CANDIDATE_PROFILE_ID,
        )
        .is_err());
    assert!(handle
        .publish_wallet_processing_context(&active, Some((&proof.finalized, &state_root)))
        .is_err());
    handle
        .publish_wallet_processing_context(&active, Some((&source, &state_root)))
        .unwrap();
    let read =
        |genesis: &str, profile: &str| handle.wallet_processing_context(&active, genesis, profile);
    let sponsor_context = read(
        trust.genesis_hash,
        synergy_etdag::admission::PW13_SPONSOR_CANDIDATE_PROFILE_ID,
    )
    .unwrap();
    let transfer_context = read(
        trust.genesis_hash,
        synergy_etdag::admission::PW13_TRANSFER_CANDIDATE_PROFILE_ID,
    )
    .unwrap();
    assert_eq!(
        sponsor_context["context"]["authority"],
        transfer_context["context"]["authority"]
    );
    assert_ne!(
        sponsor_context["context"]["profile_id"],
        transfer_context["context"]["profile_id"]
    );
    assert_eq!(transfer_context["source"]["state_root"], state_root);
    assert_eq!(
        transfer_context["wallet_dispatch_policy"]["transfer_gas"],
        20
    );
    assert!(read(
        &hash(b"another selected Genesis"),
        synergy_etdag::admission::PW13_SPONSOR_CANDIDATE_PROFILE_ID
    )
    .is_err());
    handle
        .publish_wallet_processing_context(&active, None)
        .unwrap();
    assert!(read(
        trust.genesis_hash,
        synergy_etdag::admission::PW13_SPONSOR_CANDIDATE_PROFILE_ID
    )
    .is_err());
    let mut another_genesis = origin.clone();
    let SimplifiedFinalityParent::Genesis { genesis_hash, .. } = &mut another_genesis.anchor_parent
    else {
        unreachable!()
    };
    *genesis_hash = hash(b"second Genesis with identical chain and epoch identifiers");
    assert!(verify_next_derived_with_wallet_release(
        Arc::new(another_genesis),
        &serde_json::to_vec(&proof).unwrap(),
        Some(&verified),
    )
    .is_err());
    proof.witness.quorum_certificates[2].participants[0].signature[0] ^= 1;
    assert!(replay(&proof, Some(&verified)).is_err());
}

fn signed_sponsor_source(
    authority: &Arc<VerifiedAuthority>,
    validators: &[ValidatorRecord],
    keys: &[EncodedKeyPair],
    engine: &Arc<Mutex<CryptoEngine>>,
) -> [Vec<u8>; 4] {
    use synergy_posy::{
        block_vote_signing_bytes, BlockVote, ConsensusObjectContext, FinalitySyncWitness,
    };
    let start = authority.epoch.epoch_start_height;
    let world = &authority.protected.as_ref().unwrap().initial_world_state;
    let state_root = synergy_state::state_root(world).unwrap();
    let mut parent = authority.anchor_parent.clone();
    let protected_root = synergy_block::hash_block_bytes(b"public Quick Setup source fixture");
    let block = serde_json::to_vec(&(
        start,
        parent.block_id(),
        &protected_root,
        &state_root,
        Vec::<synergy_transaction::SignedTransaction>::new(),
        Vec::<synergy_transaction::TransactionReceipt>::new(),
    ))
    .unwrap();
    let block_id = synergy_block::hash_block_bytes(&block);
    let mut chain = ThreeQcFinality::default();
    let mut certificates = Vec::with_capacity(3);
    for height in start..start + 3 {
        let votes = validators
            .iter()
            .zip(keys)
            .take(4)
            .map(|(validator, key)| {
                let mut vote = BlockVote {
                    context: ConsensusObjectContext::for_height(&authority.epoch, height, 0)
                        .unwrap(),
                    block_id: if height == start {
                        block_id.clone()
                    } else {
                        format!("{height:064x}")
                    },
                    parent_block_id: parent.block_id().into(),
                    parent: parent.clone(),
                    takeover_tc_id: None,
                    protected_execution_root: protected_root.clone(),
                    validator_id: validator.validator_id.clone(),
                    key_id: validator.consensus_key_id.clone(),
                    signature: Vec::new(),
                };
                vote.signature = engine
                    .lock()
                    .unwrap()
                    .sign(
                        Algorithm::MlDsa65,
                        key.private_key.as_bytes(),
                        &block_vote_signing_bytes(&vote).unwrap(),
                        SignOptions::default(),
                    )
                    .unwrap();
                vote
            })
            .collect();
        let qc = SimplifiedQuorumCertificate::from_votes(votes).unwrap();
        qc.verify(&authority.epoch, &authority.registry, authority.as_ref())
            .unwrap();
        chain.accept(qc.clone()).unwrap();
        parent = SimplifiedFinalityParent::QuorumCertificate {
            height,
            block_id: qc.block_id.clone(),
            qc_id: qc.id().unwrap(),
        };
        certificates.push(qc);
    }
    let finalized = chain.last_finalized().unwrap();
    assert_eq!(
        (finalized.height, finalized.block_id.as_str()),
        (start, block_id.as_str())
    );
    #[derive(Serialize)]
    struct Finality<'a> {
        version: u8,
        finalized: &'a FinalizedBlockRecord,
        witness: FinalitySyncWitness,
    }
    let finality = serde_json::to_vec(&Finality {
        version: 1,
        finalized,
        witness: FinalitySyncWitness {
            quorum_certificates: certificates.try_into().unwrap(),
            timeout_certificates: Vec::new(),
        },
    })
    .unwrap();
    let release = authority.native_wallet_release().unwrap();
    let publication = crate::services::protected_admission::AdmissionHandle::default();
    publication
        .publish_wallet_processing_context(authority, Some((finalized, &state_root)))
        .unwrap();
    let sponsor = publication
        .wallet_processing_context(
            authority,
            &release.verified.policy().genesis_hash,
            synergy_etdag::admission::PW13_SPONSOR_CANDIDATE_PROFILE_ID,
        )
        .unwrap();
    [
        finality,
        block,
        serde_json::to_vec(world).unwrap(),
        serde_json::to_vec(&sponsor).unwrap(),
    ]
}
