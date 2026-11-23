use super::*;
use synergy_address_engine::{
    apqe::{
        crypto_engine::{CryptoEngine, EncodedKeyPair},
        enrollment_commit::UnactivatedCommitmentProfile,
        enrollment_registry::EnrollmentRegistryRelease,
        provider::{
            BACKEND_ABI, IMPORT_MANIFEST_SHA256, MODULE_REVISION, NativeVerificationQualification,
            Operation, Profile, SELECTED_MANIFEST_SHA256, SignOptions,
            SignedNativeVerificationQualification, Target,
        },
    },
    types::Algorithm,
};
use synergy_aegis::{AegisSigner, PqvmSigner};
use synergy_genesis::authority::{
    ProtectedWalletDispatchPolicy, SignedWalletDispatchRelease, WalletDispatchReleasePayload,
    WalletDispatchReleaseTrust,
};

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
    let wire = crate::services::protected_accounts::inspection::candidate_wire_profile().unwrap();
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
    let policy = ProtectedWalletDispatchPolicy {
        version: 1,
        chain_id: previous.chain_id,
        network_id: previous.network_id.clone(),
        genesis_hash: genesis_hash.clone(),
        activation_finalized_height: previous.epoch_end_height + 1,
        managed_release_manifest_sha256: hash(b"independent managed release fixture"),
        off_chain_approval_sha256: hash(b"existing off-chain approval fixture"),
        release_attestation_sha256: hash(b"release conformance attestation fixture"),
        action_registry_sha256: hash(include_bytes!(
            "../../../../../docs/protected-accounts-canary-v1/protected-action-registry-v1.json"
        )),
        wire_schema_sha256: hash(include_bytes!(
            "../../../../../docs/protected-accounts-canary-v1/protected-actions-v1.cddl"
        )),
        action_vectors_sha256: hash(include_bytes!(
            "../../../../../docs/protected-accounts-canary-v1/protected-conformance-v1/action-payloads.json"
        )),
        ownership_chain_id: format!("{:064x}", 1),
        enrollment_wire_profile_fingerprint: hex(wire.profile_fingerprint().unwrap()),
        enrollment_commitment_profile_fingerprint: hex(
            EnrollmentRegistryRelease::commitment_fingerprint(
                UnactivatedCommitmentProfile::candidate_concat_v1(),
            ),
        ),
        enrollment_provider_manifests: vec![hash(b"fixture provider")],
        enrollment_proof_provider_artifacts: vec![hex(proof_sha256)],
        fee_collector: synergy_address::generate_fee_collector_address("protected-release-fixture")
            .unwrap(),
        fee_class: 1,
        base_fee_per_gas_nwei: 1,
        enroll_commit_gas: 10,
        enroll_reveal_gas: 100,
        transfer_gas: 20,
    };
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
        attachment_sha256: hash(&bytes),
        issuer_key_id: signer_id.as_str().into(),
        issuer_sha256: hash(&key.public_key),
        release_verifier_artifact_sha256: hex(verifier_sha256),
        managed_release_manifest_sha256: trust.managed_release_manifest_sha256.into(),
        off_chain_approval_sha256: trust.off_chain_approval_sha256.into(),
        release_attestation_sha256: trust.release_attestation_sha256.into(),
    };
    let mut authorization = super::super::managed_wallet::ReleaseIssuerAuthorization {
        version: 1,
        genesis_hash: genesis_hash.clone(),
        attachment_sha256: pins.attachment_sha256.clone(),
        issuer_sha256: pins.issuer_sha256.clone(),
        issuer_key_id: pins.issuer_key_id.clone(),
        signature: vec![],
    };
    let genesis = crate::commands::selected_network::verified_genesis(config).unwrap();
    authorization.signature = origin_signer
        .sign(
            &KeyId::new(genesis.unsigned.authority_trust_key_id).unwrap(),
            &SigningContext {
                domain: super::super::managed_wallet::WALLET_RELEASE_ISSUER_DOMAIN.into(),
                chain_id: previous.chain_id,
                epoch: None,
                height: None,
            },
            &authorization.signing_bytes().unwrap(),
        )
        .unwrap()
        .bytes;
    fs::write(
        &authorization_path,
        serde_json::to_vec(&authorization).unwrap(),
    )
    .unwrap();
    selected_config.consensus.managed_wallet_dispatch_release = Some(pins.clone());
    assert!(
        load(&selected_config)
            .unwrap_err()
            .contains("production ML-DSA-87 qualification")
    );
    let expected_report = &config
        .aegis_provider
        .as_ref()
        .unwrap()
        .authenticated_report_sha256;
    let parse = |value: &str| synergy_posy::parse_hash_bytes(value).unwrap();
    let (qualifier, proof_fixture) = {
        let engine = engine.lock().unwrap();
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
            artifact_sha256: proof_sha256,
            report_sha256: parse(expected_report),
            release_attestation_sha256: parse(&pins.release_attestation_sha256),
            release_context: verified.enrollment().statement().release_context,
            backend_abi: BACKEND_ABI,
            backend_revision: MODULE_REVISION.into(),
            selected_manifest_sha256: SELECTED_MANIFEST_SHA256.into(),
            import_manifest_sha256: IMPORT_MANIFEST_SHA256.into(),
            native_identity: selected.native_identity.clone(),
        };
        let signature = engine
            .sign(
                Algorithm::MlDsa65,
                key.private_key.as_bytes(),
                &qualification.signing_bytes().unwrap(),
                SignOptions::default(),
            )
            .unwrap();
        let proof = engine.generate_keypair(Algorithm::MlDsa87).unwrap();
        let proof_signature = engine
            .sign(
                Algorithm::MlDsa87,
                proof.private_key.as_bytes(),
                b"exact native proof fixture",
                SignOptions::default(),
            )
            .unwrap();
        (
            SignedNativeVerificationQualification {
                qualification,
                signature,
            },
            (proof, proof_signature),
        )
    };
    let qualifier_bytes = serde_json::to_vec(&qualifier).unwrap();
    fs::write(&qualification_path, &qualifier_bytes).unwrap();
    let managed = load(&selected_config).unwrap().unwrap();
    assert!(managed.wallet_dispatch_policy().is_none());
    assert!(managed.native_wallet_release().is_err());
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
        assert!(
            verifier
                .sign(
                    b"exact native proof fixture",
                    &SecretKey::from_bytes(proof_fixture.0.private_key.as_bytes()).unwrap(),
                    SignOptions::default(),
                )
                .is_err()
        );
        assert!(
            verifier
                .verify(
                    b"exact native proof fixture",
                    &signature,
                    &public,
                    SignOptions::default()
                )
                .is_ok()
        );
        assert!(
            verifier
                .verify(
                    b"altered native proof fixture",
                    &signature,
                    &public,
                    SignOptions::default()
                )
                .is_err()
        );
    }
    let mut wrong_qualification = qualifier;
    wrong_qualification.qualification.report_sha256[0] ^= 1;
    fs::write(
        &qualification_path,
        serde_json::to_vec(&wrong_qualification).unwrap(),
    )
    .unwrap();
    assert!(
        load(&selected_config)
            .unwrap_err()
            .contains("production ML-DSA-87 qualification")
    );
    fs::write(&qualification_path, qualifier_bytes).unwrap();
    authorization.signature[0] ^= 1;
    fs::write(
        &authorization_path,
        serde_json::to_vec(&authorization).unwrap(),
    )
    .unwrap();
    assert!(
        load(&selected_config)
            .unwrap_err()
            .contains("delegation signature is invalid")
    );
    selected_config
        .consensus
        .managed_wallet_dispatch_release
        .as_mut()
        .unwrap()
        .issuer_sha256 = hash(b"wrong issuer");
    assert!(
        load(&selected_config)
            .unwrap_err()
            .contains("wallet-dispatch-release-issuer.pub")
    );
    selected_config.consensus.managed_wallet_dispatch_release = Some(pins);
    fs::write(attachment, b"{}").unwrap();
    assert!(
        load(&selected_config)
            .unwrap_err()
            .contains("wallet-dispatch-release.json")
    );
    assert!(
        load(config)
            .unwrap()
            .unwrap()
            .wallet_dispatch_policy()
            .is_none()
    );
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
    assert!(
        verify(
            &serde_json::to_vec(&release).unwrap(),
            &WalletDispatchReleaseTrust {
                release_signer_key_id: &alternate_signer,
                ..trust
            },
        )
        .is_err()
    );
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
        Some(&verified),
    )
    .unwrap();
    let handle = crate::services::protected_admission::AdmissionHandle::default();
    let source = FinalizedBlockRecord {
        height: active.epoch.epoch_start_height,
        block_id: hash(b"fixture execution source"),
        finality_certificate_id: hash(b"fixture finality id"),
        protected_execution_root: hash(b"fixture protected execution"),
    };
    let state_root = hash(b"fixture executed state");
    assert!(
        handle
            .publish_wallet_processing_context(&managed, Some((&source, &state_root)))
            .is_err()
    );
    assert!(
        handle
            .wallet_processing_context(
                &active,
                trust.genesis_hash,
                synergy_etdag::admission::PW13_SPONSOR_CANDIDATE_PROFILE_ID,
            )
            .is_err()
    );
    assert!(
        handle
            .publish_wallet_processing_context(&active, Some((&proof.finalized, &state_root)))
            .is_err()
    );
    handle
        .publish_wallet_processing_context(&active, Some((&source, &state_root)))
        .unwrap();
    let read = |genesis: &str, profile: &str| handle.wallet_processing_context(&active, genesis, profile);
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
    assert!(
        read(
            &hash(b"another selected Genesis"),
            synergy_etdag::admission::PW13_SPONSOR_CANDIDATE_PROFILE_ID
        )
        .is_err()
    );
    handle
        .publish_wallet_processing_context(&active, None)
        .unwrap();
    assert!(
        read(
            trust.genesis_hash,
            synergy_etdag::admission::PW13_SPONSOR_CANDIDATE_PROFILE_ID
        )
        .is_err()
    );
    let mut another_genesis = origin.clone();
    let SimplifiedFinalityParent::Genesis { genesis_hash, .. } = &mut another_genesis.anchor_parent
    else {
        unreachable!()
    };
    *genesis_hash = hash(b"second Genesis with identical chain and epoch identifiers");
    assert!(
        verify_next_derived_with_wallet_release(
            Arc::new(another_genesis),
            &serde_json::to_vec(&proof).unwrap(),
            Some(&verified),
        )
        .is_err()
    );
    proof.witness.quorum_certificates[2].participants[0].signature[0] ^= 1;
    assert!(replay(&proof, Some(&verified)).is_err());
}
