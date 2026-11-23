use super::*;
use serde_json::{json, Value};
use std::{fs, path::PathBuf};
use synergy_address_engine::{
    apqe::{
        enrollment_commit::UnactivatedCommitmentProfile,
        provider::{
            SignOptions, Target, VerifiedNativeVerificationQualification, BACKEND_ABI,
            IMPORT_MANIFEST_SHA256, MODULE_REVISION, SELECTED_MANIFEST_SHA256,
        },
    },
    types::Algorithm,
};
use synergy_aegis::{
    CryptoEngine, EnrollmentRegistryRelease, EnrollmentRegistryReleaseIssuer, PqvmVerifier,
};
use synergy_genesis::authority::{
    ProtectedWalletDispatchPolicy, VerifiedWalletDispatchRelease, WalletDispatchReleaseIssuerTrust,
    WalletDispatchReleaseTrust, WALLET_DISPATCH_RELEASE_DOMAIN,
};
use synergy_genesis::{
    etdag::GenesisEtdag, network::GenesisNetwork, signing::SignedGenesis,
    validator_set::GenesisValidator,
};
use synergy_posy::{FrozenValidatorRegistry, ValidatorRecord, ValidatorStatus};

fn hex(bytes: [u8; 32]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn release_fixture(
    proof_digest: [u8; 32],
) -> (WalletDispatchReleasePayload, SimplifiedEpochContext) {
    let registry = FrozenValidatorRegistry::new(
        4,
        (0..synergy_posy::POSY_MIN_VALIDATOR_COUNT)
            .map(|i| ValidatorRecord {
                validator_id: format!("v{i}"),
                consensus_key_id: format!("k{i}"),
                frozen_voting_weight: 1,
                status: ValidatorStatus::Active,
            })
            .collect(),
    )
    .unwrap();
    let predecessor = SimplifiedEpochContext::from_frozen_registry(
        17,
        "offline-wallet-release-fixture".into(),
        4,
        101,
        1100,
        hex([1; 32]),
        hex([2; 32]),
        &registry,
    )
    .unwrap();
    let payload = WalletDispatchReleasePayload {
        version: 1,
        predecessor_context_root: predecessor.root().unwrap(),
        signer_key_id: "fixture-wallet-release".into(),
        policy: ProtectedWalletDispatchPolicy {
            version: 1,
            chain_id: predecessor.chain_id,
            network_id: predecessor.network_id.clone(),
            genesis_hash: hex([3; 32]),
            activation_finalized_height: 1101,
            managed_release_manifest_sha256: hex([4; 32]),
            off_chain_approval_sha256: hex([5; 32]),
            release_attestation_sha256: hex([6; 32]),
            action_registry_sha256: hex([7; 32]),
            wire_schema_sha256: hex([8; 32]),
            action_vectors_sha256: hex([9; 32]),
            ownership_chain_id: format!("{:064x}", 1),
            enrollment_wire_profile_fingerprint: hex([11; 32]),
            enrollment_commitment_profile_fingerprint: hex(
                EnrollmentRegistryRelease::commitment_fingerprint(
                    UnactivatedCommitmentProfile::candidate_concat_v1(),
                ),
            ),
            enrollment_provider_manifests: vec![hex([12; 32])],
            enrollment_proof_provider_artifacts: vec![hex(proof_digest)],
            fee_collector: "synf1release-test".into(),
            fee_class: 1,
            base_fee_per_gas_nwei: 1,
            enroll_commit_gas: 10,
            enroll_reveal_gas: 100,
            transfer_gas: 20,
        },
    };
    (payload, predecessor)
}

fn unsigned_origin(predecessor: &SimplifiedEpochContext, public_key: &[u8]) -> UnsignedGenesis {
    UnsignedGenesis {
        format_version: 2,
        network: GenesisNetwork {
            chain_id: predecessor.chain_id,
            network_id: predecessor.network_id.clone(),
            protocol_version: predecessor.protocol_version.clone(),
            activation_unix: 1,
            autonomous_epoch_protocol: None,
        },
        validators: predecessor
            .leader_ring
            .iter()
            .map(|id| GenesisValidator {
                record: ValidatorRecord {
                    validator_id: id.clone(),
                    consensus_key_id: format!("{id}-key"),
                    frozen_voting_weight: 1,
                    status: ValidatorStatus::Active,
                },
                algorithm: SignatureAlgorithm::MlDsa65,
                public_key: public_key.to_vec(),
            })
            .collect(),
        etdag: GenesisEtdag {
            parameters: EtdagParameters::default(),
            cryptographic_profile_root: "fixture-profile".into(),
            ingress_kem_registry_root: synergy_etdag::EtdagDigest::from_domain_bytes(
                "test",
                b"wallet-release",
            ),
        },
        initial_state_root: "fixture-world".into(),
        authority_trust_key_id: "fixture-origin-root".into(),
    }
}

fn issuer_request(
    origin: &UnsignedGenesis,
    payload: &WalletDispatchReleasePayload,
    attachment_digest: [u8; 32],
    issuer_digest: [u8; 32],
) -> (WalletDispatchReleaseIssuerAuthorization, Value) {
    let authorization = WalletDispatchReleaseIssuerAuthorization {
        version: 1,
        genesis_hash: payload.policy.genesis_hash.clone(),
        attachment_sha256: hex(attachment_digest),
        issuer_sha256: hex(issuer_digest),
        issuer_key_id: payload.signer_key_id.clone(),
        signature: Vec::new(),
    };
    let request = json!({
        "issuer_delegation":{"origin":origin,"authorization":authorization},
    });
    (authorization, request)
}

fn qualification_fixture(
    payload: &WalletDispatchReleasePayload,
    artifact_sha256: [u8; 32],
    report_sha256: [u8; 32],
    target: &str,
    native_identity: String,
) -> NativeVerificationQualification {
    NativeVerificationQualification {
        version: 1,
        target: target.into(),
        artifact_sha256,
        report_sha256,
        release_attestation_sha256: synergy_posy::parse_hash_bytes(
            &payload.policy.release_attestation_sha256,
        )
        .unwrap(),
        release_context: payload.release_context().unwrap(),
        backend_abi: BACKEND_ABI,
        backend_revision: MODULE_REVISION.into(),
        selected_manifest_sha256: SELECTED_MANIFEST_SHA256.into(),
        import_manifest_sha256: IMPORT_MANIFEST_SHA256.into(),
        native_identity,
    }
}

#[test]
fn dispatch_requires_exact_predecessor_activation_and_resource_bounds() {
    let (payload, predecessor) = release_fixture([13; 32]);
    let request = |payload: WalletDispatchReleasePayload, parameters: EtdagParameters| {
        Request::Dispatch {
            payload,
            predecessor: Box::new(predecessor.clone()),
            parameters,
        }
        .signing_input()
    };
    let (key, context, bytes) = request(payload.clone(), EtdagParameters::default()).unwrap();
    assert_eq!(key.as_str(), payload.signer_key_id);
    assert_eq!(context.domain, WALLET_DISPATCH_RELEASE_DOMAIN);
    assert_eq!(context.epoch, Some(4));
    assert_eq!(context.height, Some(1098));
    assert_eq!(bytes, payload.signing_bytes().unwrap());

    for changed in [
        WalletDispatchReleasePayload {
            predecessor_context_root: hex([42; 32]),
            ..payload.clone()
        },
        WalletDispatchReleasePayload {
            policy: ProtectedWalletDispatchPolicy {
                activation_finalized_height: 1102,
                ..payload.policy.clone()
            },
            ..payload.clone()
        },
        WalletDispatchReleasePayload {
            policy: ProtectedWalletDispatchPolicy {
                network_id: "other-network".into(),
                ..payload.policy.clone()
            },
            ..payload.clone()
        },
    ] {
        assert!(request(changed, EtdagParameters::default()).is_err());
    }
    assert!(request(
        payload,
        EtdagParameters {
            max_protected_gas: 9,
            ..EtdagParameters::default()
        }
    )
    .is_err());
}

#[test]
fn issuer_delegation_and_native_qualification_deny_stale_or_unscoped_requests() {
    let (mut payload, predecessor) = release_fixture([13; 32]);
    let origin = unsigned_origin(&predecessor, &[16; 1952]);
    payload.policy.genesis_hash = origin.genesis_hash().unwrap();
    let (authorization, value) = issuer_request(&origin, &payload, [14; 32], [15; 32]);
    let (key, context, bytes) = serde_json::from_value::<Request>(value.clone())
        .unwrap()
        .signing_input()
        .unwrap();
    assert_eq!(key.as_str(), "fixture-origin-root");
    assert_eq!(context.chain_id, predecessor.chain_id);
    assert_eq!(context.domain, WALLET_RELEASE_ISSUER_DOMAIN);
    assert_eq!(bytes, authorization.signing_bytes().unwrap());
    let mut unexpected_field = value.clone();
    unexpected_field["issuer_delegation"]["private_key_path"] = json!("must not be accepted");
    assert!(serde_json::from_value::<Request>(unexpected_field).is_err());
    let mut wrong_origin = value.clone();
    wrong_origin["issuer_delegation"]["origin"]["network"]["chain_id"] = json!(18);
    assert!(serde_json::from_value::<Request>(wrong_origin)
        .unwrap()
        .signing_input()
        .is_err());
    for (field, wrong) in [
        ("signature", json!([1])),
        ("genesis_hash", json!(hex([0; 32]))),
    ] {
        let mut changed = value.clone();
        changed["issuer_delegation"]["authorization"][field] = wrong;
        assert!(serde_json::from_value::<Request>(changed)
            .unwrap()
            .signing_input()
            .is_err());
    }
    for signature in [vec![1; SIGNATURE_BYTES - 1], vec![0; SIGNATURE_BYTES]] {
        assert!(serde_json::from_value::<Request>(value.clone())
            .unwrap()
            .attach_signature(signature)
            .is_err());
    }
    let mut full_weight_origin = origin;
    full_weight_origin.validators[0].record.frozen_voting_weight = u128::from(u64::MAX) + 1;
    let full_weight_request = Request::IssuerDelegation {
        authorization: WalletDispatchReleaseIssuerAuthorization {
            genesis_hash: full_weight_origin.genesis_hash().unwrap(),
            ..authorization
        },
        origin: Box::new(full_weight_origin),
    };
    let encoded = serde_json::to_vec(&full_weight_request).unwrap();
    assert!(serde_json::from_slice::<Request>(&encoded)
        .unwrap()
        .signing_input()
        .is_ok());

    let qualification = qualification_fixture(
        &payload,
        [13; 32],
        [16; 32],
        "aarch64-apple-darwin",
        "fixture-native-identity".into(),
    );
    let prepare = |qualification: NativeVerificationQualification| {
        Request::NativeVerificationQualification {
            payload: payload.clone(),
            qualification,
        }
        .signing_input()
    };
    let (_, context, bytes) = prepare(qualification.clone()).unwrap();
    assert_eq!(bytes, qualification.signing_bytes().unwrap());
    assert_eq!(context.height, Some(1101));
    assert_eq!(
        context.domain.as_bytes(),
        bytes.split(|byte| *byte == 0).next().unwrap()
    );
    for changed in [
        NativeVerificationQualification {
            artifact_sha256: [17; 32],
            ..qualification.clone()
        },
        NativeVerificationQualification {
            release_context: [18; 32],
            ..qualification.clone()
        },
        NativeVerificationQualification {
            release_attestation_sha256: [19; 32],
            ..qualification.clone()
        },
        NativeVerificationQualification {
            target: "unsupported-target".into(),
            ..qualification
        },
    ] {
        assert!(prepare(changed).is_err());
    }
}

struct Scratch(PathBuf);

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn sign_cli_request(
    root: &Path,
    request: Value,
    preimage: &[u8],
    engine: &CryptoEngine,
    private: &[u8],
) -> (Vec<u8>, Vec<u8>) {
    fs::create_dir(root).unwrap();
    let request_path = root.join("request.json");
    let transcript_path = root.join("transcript.bin");
    let signature_path = root.join("detached.bin");
    let attachment_path = root.join("attached.json");
    fs::write(&request_path, serde_json::to_vec_pretty(&request).unwrap()).unwrap();
    let args = |command: &str, paths: &[&Path]| -> Vec<String> {
        std::iter::once(command.to_owned())
            .chain(paths.iter().map(|path| path.to_str().unwrap().to_string()))
            .collect()
    };
    let prepare = args(
        "wallet-release-transcript",
        &[&request_path, &transcript_path],
    );
    crate::run_arguments(&prepare).unwrap();
    let transcript = fs::read(&transcript_path).unwrap();
    assert_eq!(transcript, preimage);
    let signature = engine
        .sign(
            Algorithm::MlDsa65,
            private,
            &transcript,
            SignOptions::default(),
        )
        .unwrap();
    let attach = args(
        "wallet-release-attach-signature",
        &[&request_path, &signature_path, &attachment_path],
    );
    fs::write(&signature_path, &signature[..signature.len() - 1]).unwrap();
    assert!(crate::run_arguments(&attach).is_err());
    assert!(!attachment_path.exists());
    fs::write(&signature_path, &signature).unwrap();
    crate::run_arguments(&attach).unwrap();
    let attachment = fs::read(&attachment_path).unwrap();
    assert!(crate::run_arguments(&attach)
        .unwrap_err()
        .contains("exists"));
    assert_eq!(fs::read(&attachment_path).unwrap(), attachment);
    (attachment, signature)
}

#[test]
#[ignore = "requires explicitly authenticated immutable APQE native artifacts"]
fn detached_cli_outputs_are_consumed_by_native_ml_dsa_65_verifiers() {
    let report = std::env::var("APQE_TRUSTED_NATIVE_REPORT").unwrap();
    let digest = std::env::var("APQE_AUTHENTICATED_REPORT_SHA256").unwrap();
    let engine =
        synergy_aegis::load_authenticated_native_engine(Path::new(&report), &digest).unwrap();
    let verifier =
        PqvmVerifier::with_apqe(crate::policy(), std::sync::Arc::clone(&engine)).unwrap();
    let engine = engine.lock().unwrap();
    let issuer = engine.generate_keypair(Algorithm::MlDsa65).unwrap();
    let origin = engine.generate_keypair(Algorithm::MlDsa65).unwrap();
    let verifier_sha256 = engine
        .provider_provenance(Algorithm::MlDsa65)
        .unwrap()
        .artifact_sha256;
    let proof = engine.provider_provenance(Algorithm::MlDsa87).unwrap();

    let scratch = std::env::temp_dir().join(format!(
        "core-wallet-release-cli-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir(&scratch).unwrap();
    let scratch = Scratch(scratch);
    let (mut payload, predecessor) = release_fixture(proof.artifact_sha256);
    let unsigned = unsigned_origin(&predecessor, &origin.public_key);
    payload.policy.genesis_hash = unsigned.genesis_hash().unwrap();
    let signed_origin = SignedGenesis {
        genesis_hash: payload.policy.genesis_hash.clone(),
        signer_key_id: unsigned.authority_trust_key_id.clone(),
        signature_algorithm: SignatureAlgorithm::MlDsa65,
        signature: engine
            .sign(
                Algorithm::MlDsa65,
                origin.private_key.as_bytes(),
                &unsigned.canonical_bytes().unwrap(),
                SignOptions::default(),
            )
            .unwrap(),
        unsigned,
    };
    let parameters = EtdagParameters::default();
    let request =
        json!({"dispatch":{"payload":payload,"predecessor":predecessor,"parameters":parameters}});
    let (release_bytes, _) = sign_cli_request(
        &scratch.0.join("dispatch"),
        request,
        &payload.signing_bytes().unwrap(),
        &engine,
        issuer.private_key.as_bytes(),
    );
    let release_key = KeyId::new(&payload.signer_key_id).unwrap();
    let trust = WalletDispatchReleaseTrust {
        genesis_hash: &payload.policy.genesis_hash,
        release_signer_key_id: &release_key,
        release_signer_public_key: &issuer.public_key,
        release_verifier_artifact_sha256: verifier_sha256,
        managed_release_manifest_sha256: &payload.policy.managed_release_manifest_sha256,
        off_chain_approval_sha256: &payload.policy.off_chain_approval_sha256,
        release_attestation_sha256: &payload.policy.release_attestation_sha256,
    };
    let release = VerifiedWalletDispatchRelease::verify(
        &release_bytes,
        &trust,
        &predecessor,
        &parameters,
        &engine,
    )
    .unwrap();

    let (authorization, request) = issuer_request(
        &signed_origin.unsigned,
        &payload,
        AegisProtectedPrimitives.sha256(&release_bytes),
        AegisProtectedPrimitives.sha256(&issuer.public_key),
    );
    let (delegation_bytes, signature) = sign_cli_request(
        &scratch.0.join("delegation"),
        request,
        &authorization.signing_bytes().unwrap(),
        &engine,
        origin.private_key.as_bytes(),
    );
    let delegation: WalletDispatchReleaseIssuerAuthorization =
        serde_json::from_slice(&delegation_bytes).unwrap();
    assert_eq!(
        delegation,
        WalletDispatchReleaseIssuerAuthorization {
            signature,
            ..authorization
        }
    );
    let verify = |key: &[u8]| {
        engine
            .verify(
                Algorithm::MlDsa65,
                key,
                &delegation.signing_bytes().unwrap(),
                &delegation.signature,
                SignOptions::default(),
            )
            .unwrap()
    };
    assert!(verify(&origin.public_key));
    assert!(!verify(&issuer.public_key));

    let target = match Target::current() {
        Target::DarwinArm64 => "aarch64-apple-darwin",
        Target::LinuxX86_64Gnu => "x86_64-unknown-linux-gnu",
        Target::LinuxArm64Gnu => "aarch64-unknown-linux-gnu",
        _ => panic!("test requires a native supported release target"),
    };
    let report_sha256 = synergy_posy::parse_hash_bytes(&digest).unwrap();
    let qualification = qualification_fixture(
        &payload,
        proof.artifact_sha256,
        report_sha256,
        target,
        proof.native_identity.clone(),
    );
    let request = json!({"native_verification_qualification":{"payload":payload,"qualification":qualification}});
    let (signed, _) = sign_cli_request(
        &scratch.0.join("qualification"),
        request,
        &qualification.signing_bytes().unwrap(),
        &engine,
        issuer.private_key.as_bytes(),
    );
    let release_issuer = EnrollmentRegistryReleaseIssuer {
        public_key: &issuer.public_key,
        verifier_artifact_sha256: verifier_sha256,
    };
    let verify_qualification = |report_sha256| {
        VerifiedNativeVerificationQualification::verify(
            &signed,
            release.enrollment(),
            &release_issuer,
            &engine,
            report_sha256,
            qualification.release_attestation_sha256,
        )
    };
    assert!(verify_qualification(report_sha256).is_ok());
    assert!(verify_qualification([21; 32]).is_err());
    drop(engine);

    let issuer_trust = WalletDispatchReleaseIssuerTrust {
        origin: &signed_origin,
        authority_public_key: &origin.public_key,
        attachment_sha256: &delegation.attachment_sha256,
        issuer_sha256: &delegation.issuer_sha256,
    };
    assert_eq!(
        WalletDispatchReleaseIssuerAuthorization::verify(
            &delegation_bytes,
            &release_bytes,
            &trust,
            &issuer_trust,
            &verifier,
        )
        .unwrap(),
        delegation
    );
}
