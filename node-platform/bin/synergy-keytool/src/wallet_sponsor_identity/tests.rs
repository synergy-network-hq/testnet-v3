use super::*;
use std::fs;
use synergy_address_engine::{apqe::provider::SignOptions, types::Algorithm};
use synergy_genesis::{
    builder::UnsignedGenesis, etdag::GenesisEtdag, network::GenesisNetwork,
    validator_set::GenesisValidator,
};
use synergy_identity::authorization::{
    canonical_binding_commitment, IDENTITY_AUTHORIZATION_BINDINGS_STATE_KEY,
};
use synergy_posy::{ValidatorRecord, ValidatorStatus};

struct Scratch(PathBuf);

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
#[ignore = "requires explicitly authenticated immutable APQE native artifacts"]
fn actual_proofs_authorize_the_same_public_binding_for_registration_and_sponsorship() {
    let engine = crate::provider::native_test_engine();
    let (authority, root, sponsor) = {
        let engine = engine.lock().unwrap();
        (
            engine.generate_keypair(Algorithm::MlDsa65).unwrap(),
            engine.generate_keypair(Algorithm::FnDsa1024).unwrap(),
            engine.generate_keypair(Algorithm::MlDsa87).unwrap(),
        )
    };
    let chain_id = 9831;
    let network = "offline-sponsor-identity-fixture";
    let unsigned = UnsignedGenesis {
        format_version: 2,
        network: GenesisNetwork {
            chain_id,
            network_id: network.into(),
            protocol_version: synergy_posy::POSY_SIMPLIFIED_PROTOCOL_VERSION.into(),
            activation_unix: 100,
            autonomous_epoch_protocol: Some(AUTONOMOUS_EPOCH_PROTOCOL_V1.into()),
                    ethereum_compatibility: None,
        },
        validators: (0..synergy_posy::POSY_MIN_VALIDATOR_COUNT)
            .map(|index| GenesisValidator {
                record: ValidatorRecord {
                    validator_id: format!("validator-{index}"),
                    consensus_key_id: format!("key-{index}"),
                    frozen_voting_weight: 1,
                    status: ValidatorStatus::Active,
                },
                algorithm: SignatureAlgorithm::MlDsa65,
                public_key: authority.public_key.clone(),
            })
            .collect(),
        etdag: GenesisEtdag {
            parameters: synergy_etdag::EtdagParameters::default(),
            cryptographic_profile_root: "fixture-profile".into(),
            ingress_kem_registry_root: synergy_etdag::EtdagDigest::from_domain_bytes(
                "fixture", b"sponsor",
            ),
        },
        initial_state_root: "fixture-world".into(),
        authority_trust_key_id: "sponsor-genesis-fixture".into(),
    };
    let genesis = SignedGenesis {
        genesis_hash: unsigned.genesis_hash().unwrap(),
        signer_key_id: unsigned.authority_trust_key_id.clone(),
        signature_algorithm: SignatureAlgorithm::MlDsa65,
        signature: engine
            .lock()
            .unwrap()
            .sign(
                Algorithm::MlDsa65,
                authority.private_key.as_bytes(),
                &unsigned.canonical_bytes().unwrap(),
                SignOptions::default(),
            )
            .unwrap(),
        unsigned,
    };
    let scratch = std::env::temp_dir().join(format!(
        "wallet-sponsor-public-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir(&scratch).unwrap();
    let scratch = Scratch(scratch);
    let genesis_path = scratch.0.join("origin.json");
    let authority_root = scratch.0.join("authority-root.pub");
    let request_path = scratch.0.join("request.json");
    let report_path = scratch.0.join("review.json");
    let root_path = scratch.0.join("fn-dsa-1024.bin");
    let sponsor_path = scratch.0.join("ml-dsa-87.bin");
    let output = scratch.0.join("public-sponsor.json");
    let genesis_bytes = serde_json::to_vec(&genesis).unwrap();
    fs::write(&genesis_path, &genesis_bytes).unwrap();
    fs::write(&authority_root, &authority.public_key).unwrap();
    let request = serde_json::json!({
        "version":1, "genesis_path":genesis_path,
        "genesis_sha256":hex(&AegisProtectedPrimitives.sha256(&genesis_bytes)),
        "authority_root_path":authority_root,
        "authority_root_sha256":hex(&AegisProtectedPrimitives.sha256(&authority.public_key)),
        "identity_id":"operator-sponsor-fixture", "identity_root_public_key_hex":hex(&root.public_key),
        "sponsor_public_key_hex":hex(&sponsor.public_key), "effective_at_unix":123,
    });
    let mut wrong_pin = request.clone();
    wrong_pin["genesis_sha256"] = serde_json::json!("01".repeat(32));
    fs::write(&request_path, serde_json::to_vec(&wrong_pin).unwrap()).unwrap();
    assert!(prepare(&request_path, &report_path, engine.clone()).is_err());
    assert!(!report_path.exists());
    fs::write(&request_path, serde_json::to_vec(&request).unwrap()).unwrap();
    prepare(&request_path, &report_path, engine.clone()).unwrap();
    let report: serde_json::Value =
        serde_json::from_slice(&fs::read(report_path).unwrap()).unwrap();
    assert_eq!(report["scope"]["genesis_hash"], genesis.genesis_hash);
    let binding: IdentityAuthorizationBinding =
        serde_json::from_value(report["binding"].clone()).unwrap();
    let transcript = [
        AUTH_BINDING_SIGNATURE_DOMAIN,
        &canonical_binding_payload(&binding).unwrap(),
    ]
    .concat();
    assert_eq!(report["transcript_hex"], hex(&transcript));
    {
        let engine = engine.lock().unwrap();
        fs::write(
            &root_path,
            engine
                .sign(
                    Algorithm::FnDsa1024,
                    root.private_key.as_bytes(),
                    &transcript,
                    SignOptions::default(),
                )
                .unwrap(),
        )
        .unwrap();
        fs::write(
            &sponsor_path,
            engine
                .sign(
                    Algorithm::MlDsa87,
                    sponsor.private_key.as_bytes(),
                    &transcript,
                    SignOptions::default(),
                )
                .unwrap(),
        )
        .unwrap();
    }
    assert!(attach(
        &request_path,
        &sponsor_path,
        &root_path,
        &output,
        engine.clone()
    )
    .is_err());
    assert!(!output.exists());
    let mut changed_time = request.clone();
    changed_time["effective_at_unix"] = serde_json::json!(124);
    fs::write(&request_path, serde_json::to_vec(&changed_time).unwrap()).unwrap();
    assert!(attach(
        &request_path,
        &root_path,
        &sponsor_path,
        &output,
        engine.clone()
    )
    .is_err());
    assert!(!output.exists());
    fs::write(&request_path, serde_json::to_vec(&request).unwrap()).unwrap();
    attach(
        &request_path,
        &root_path,
        &sponsor_path,
        &output,
        engine.clone(),
    )
    .unwrap();
    let bytes = fs::read(&output).unwrap();
    assert!(attach(
        &request_path,
        &root_path,
        &sponsor_path,
        &output,
        engine.clone()
    )
    .is_err());
    assert_eq!(fs::read(&output).unwrap(), bytes);
    let public: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(public["finalized_registration_verified"], false);
    let carrier = |member: &str| {
        IdentityAuthorizationCarrier::from_canonical_json(
            public[member].as_str().unwrap().as_bytes(),
        )
        .unwrap()
    };
    let registration = carrier("registration_carrier_json");
    let signed_sponsor = carrier("sponsor_carrier_json");
    assert_eq!(registration.binding, signed_sponsor.binding);
    let verifier = synergy_aegis::ApqeIdentityVerifier::new(engine).unwrap();
    let payer = &registration.binding.identity_address;
    let mut protocol = std::collections::BTreeMap::from([(
        IDENTITY_AUTHORIZATION_BINDINGS_STATE_KEY.into(),
        b"{}".to_vec(),
    )]);
    let register = |carrier| {
        synergy_identity::registration::register_authorization_with_verifier(
            &protocol,
            payer,
            carrier,
            chain_id,
            network,
            123,
            Some(&verifier),
        )
    };
    assert!(register(&signed_sponsor).is_err());
    let changed = register(&registration).unwrap();
    protocol.insert(IDENTITY_AUTHORIZATION_BINDINGS_STATE_KEY.into(), changed);
    let committed = canonical_binding_commitment(&protocol, payer).unwrap();
    assert_eq!(
        serde_json::to_value(&committed).unwrap(),
        public["commitment"]
    );
    assert_eq!(
        signed_sponsor
            .identity_address_for_key_for_admission_at_with_verifier(
                PROTECTED_ENROLLMENT_SPONSOR_AUTHORIZATION_DOMAIN,
                chain_id,
                network,
                "ML-DSA-87",
                &sponsor.public_key,
                PROTECTED_ENROLLMENT_SPONSOR_PURPOSE,
                123,
                &committed.binding_payload_sha3_256,
                Some(&verifier),
            )
            .unwrap(),
        *payer
    );
}
