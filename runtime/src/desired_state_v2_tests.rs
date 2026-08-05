//! Track B tests: namespace derivation, tagged binding, V2 ML-DSA-87
//! authorization, and V1-cannot-authorize-V2.

use crate::chain_incarnation_namespace::*;
use crate::crypto::pqc::{PQCAlgorithm, PQCManager, PQCPrivateKey, PQCPublicKey, PQCSignature};
use crate::desired_state_v2::*;
use base64::{engine::general_purpose, Engine as _};

fn single_authority_state() -> DesiredStateV2 {
    DesiredStateV2 {
        schema_version: DESIRED_STATE_SCHEMA_VERSION_V2,
        chain_id: 1266,
        chain_incarnation: 5,
        network_id: TESTNET_V3_NETWORK_ID.to_string(),
        directory_namespace: "chain-1266/incarnation-5".to_string(),
        release_id: "chain1266-single-authority-rc1".to_string(),
        genesis_hash: "sha256:genesis-incarnation-5".to_string(),
        consensus_binding: ConsensusBindingV2::SingleAuthority {
            authority_id: "authority-node-01".to_string(),
            authority_public_key_fingerprint: "sha256:authority-node-01".to_string(),
            target_block_time_ms: 2_000,
            authority_start_height: 1,
            authority_end_height: None,
            pending_consensus_transition: None,
        },
        authority_public_key_fingerprint: "sha256:authority-node-01".to_string(),
        execution_configuration_fingerprint: "sha256:execution-config".to_string(),
    }
}

fn expected() -> ExpectedStartBinding {
    ExpectedStartBinding {
        chain_id: 1266,
        chain_incarnation: 5,
        release_id: "chain1266-single-authority-rc1".to_string(),
        genesis_hash: "sha256:genesis-incarnation-5".to_string(),
        authority_public_key_fingerprint: "sha256:authority-node-01".to_string(),
    }
}

struct StartAuthority {
    public: PQCPublicKey,
    private: PQCPrivateKey,
}

fn start_authority() -> StartAuthority {
    let mut manager = PQCManager::new();
    let (public, private) = manager
        .generate_keypair(PQCAlgorithm::MLDSA87)
        .expect("ML-DSA-87 keypair");
    StartAuthority { public, private }
}

fn sign_v2(authority: &StartAuthority, state: &DesiredStateV2) -> SignedDesiredStateV2 {
    let payload = canonical_signing_payload(state).expect("payload");
    let mut manager = PQCManager::new();
    let signature = manager.sign(&authority.private, &payload).expect("sign");
    SignedDesiredStateV2 {
        desired_state: state.clone(),
        signature_algorithm: START_AUTHORIZATION_ALGORITHM.to_string(),
        signature_domain: CHAIN1266_START_SIGNATURE_DOMAIN_V2.to_string(),
        start_authority_public_key_base64: general_purpose::STANDARD
            .encode(&authority.public.key_data),
        start_authority_fingerprint: format!(
            "sha256:{}",
            sha256_hex(&authority.public.key_data)
        ),
        signature_base64: general_purpose::STANDARD.encode(&signature.signature_data),
    }
}

fn crypto_verify(
    authority: &StartAuthority,
    signed: &SignedDesiredStateV2,
    state: &DesiredStateV2,
) -> bool {
    let payload = canonical_signing_payload(state).expect("payload");
    let signature = PQCSignature {
        algorithm: PQCAlgorithm::MLDSA87,
        signature_data: general_purpose::STANDARD
            .decode(&signed.signature_base64)
            .expect("decode"),
        message_hash: Vec::new(),
        public_key_id: String::new(),
        created_at: 0,
    };
    PQCManager::new()
        .verify(&authority.public, &signature, &payload)
        .unwrap_or(false)
}

#[test]
fn b01_incarnation_five_namespace_derives_correctly() {
    let identity = ChainIncarnationIdentity::new(1266, 5).unwrap();
    assert_eq!(identity.directory_namespace(), "chain-1266/incarnation-5");
    assert_eq!(
        identity.data_directory_component(),
        "chain-1266-incarnation-5"
    );
    // Derivation is generic - no hard-coded incarnation.
    let future = ChainIncarnationIdentity::new(1266, 9).unwrap();
    assert_eq!(future.directory_namespace(), "chain-1266/incarnation-9");
    assert_eq!(
        parse_directory_namespace("chain-1266/incarnation-5").unwrap(),
        identity
    );
}

#[test]
fn b02_namespace_inconsistent_with_signed_incarnation_fails() {
    let mut state = single_authority_state();
    state.directory_namespace = "chain-1266/incarnation-4".to_string();
    let error = state.validate().unwrap_err();
    assert!(error.contains("disagrees with signed chain identity"), "{error}");
}

#[test]
fn b02b_cross_surface_namespace_mismatch_is_detected() {
    let identity = ChainIncarnationIdentity::new(1266, 5).unwrap();
    let mut check = NamespaceCrossCheck {
        genesis: Some("chain-1266/incarnation-5".to_string()),
        atlas_network_identity: Some("chain-1266/incarnation-5".to_string()),
        ..Default::default()
    };
    check.verify(&identity).expect("consistent surfaces pass");
    // An Atlas still bound to the abandoned incarnation must be caught.
    check.atlas_network_identity = Some("chain-1266/incarnation-4".to_string());
    let error = check.verify(&identity).unwrap_err();
    assert!(error.contains("Atlas network identity"), "{error}");
}

#[test]
fn b03_single_authority_binding_round_trips_canonically() {
    let state = single_authority_state();
    let encoded = serde_json::to_string(&state).expect("encode");
    let decoded: DesiredStateV2 = serde_json::from_str(&encoded).expect("decode");
    assert_eq!(decoded, state);
    assert_eq!(decoded.consensus_binding.protocol(), "single_authority_v1");
    // No coordinated concept may appear anywhere in the canonical encoding.
    for forbidden in [
        "coordinator", "producer", "quorum", "certificate", "vote", "round", "cluster",
        "missed_turn",
    ] {
        assert!(!encoded.contains(forbidden), "leaked `{forbidden}`: {encoded}");
    }
}

#[test]
fn b04_coordinated_only_fields_are_rejected_in_a_single_authority_binding() {
    // A single-authority binding carrying coordinator/producer fields must be
    // a hard parse error, not silently ignored.
    let raw = r#"{
        "protocol": "single_authority_v1",
        "authority_id": "authority-node-01",
        "authority_public_key_fingerprint": "sha256:authority-node-01",
        "target_block_time_ms": 2000,
        "authority_start_height": 1,
        "coordinator_id": "validator-node-01",
        "producer_ids": ["validator-node-01"],
        "producer_turn_timeout_ms": 4000
    }"#;
    let error = serde_json::from_str::<ConsensusBindingV2>(raw).unwrap_err();
    assert!(error.to_string().contains("unknown field"), "{error}");
}

#[test]
fn b05_v2_mldsa87_signature_verifies() {
    let authority = start_authority();
    let state = single_authority_state();
    let signed = sign_v2(&authority, &state);
    assert!(crypto_verify(&authority, &signed, &state));
    verify_signed_desired_state_v2(&signed, &expected()).expect("V2 authorization accepted");
}

#[test]
fn b06_modified_v2_payload_fails_verification() {
    let authority = start_authority();
    let state = single_authority_state();
    let signed = sign_v2(&authority, &state);

    let mut tampered = state.clone();
    tampered.release_id = "chain1266-rc29".to_string();
    assert!(
        !crypto_verify(&authority, &signed, &tampered),
        "a modified payload must not verify"
    );
}

#[test]
fn b07_a_v1_signature_cannot_authorize_v2() {
    let authority = start_authority();
    let state = single_authority_state();
    let mut signed = sign_v2(&authority, &state);
    // Same bytes, but presented under the historical V1 domain.
    signed.signature_domain = "SYNERGY_CHAIN1266_START_CONSENSUS_V1".to_string();
    let error = verify_signed_desired_state_v2(&signed, &expected()).unwrap_err();
    assert!(
        error.contains("cannot authorize a V2 single-authority start"),
        "{error}"
    );
}

#[test]
fn b07b_domain_separation_is_cryptographic_not_just_declarative() {
    // The domain is inside the signed bytes, so a signature produced over a
    // different domain cannot verify against the V2 payload.
    let authority = start_authority();
    let state = single_authority_state();
    let body = serde_json::to_vec(&state).unwrap();
    let v1_domain = b"SYNERGY_CHAIN1266_START_CONSENSUS_V1";
    let mut v1_payload = Vec::new();
    v1_payload.extend_from_slice(v1_domain);
    v1_payload.extend_from_slice(&(v1_domain.len() as u64).to_be_bytes());
    v1_payload.extend_from_slice(&body);

    let mut manager = PQCManager::new();
    let v1_signature = manager.sign(&authority.private, &v1_payload).unwrap();
    let signed = SignedDesiredStateV2 {
        desired_state: state.clone(),
        signature_algorithm: START_AUTHORIZATION_ALGORITHM.to_string(),
        signature_domain: CHAIN1266_START_SIGNATURE_DOMAIN_V2.to_string(),
        start_authority_public_key_base64: general_purpose::STANDARD
            .encode(&authority.public.key_data),
        start_authority_fingerprint: format!("sha256:{}", sha256_hex(&authority.public.key_data)),
        signature_base64: general_purpose::STANDARD.encode(&v1_signature.signature_data),
    };
    assert!(
        !crypto_verify(&authority, &signed, &state),
        "a V1-domain signature must not verify against the V2 payload"
    );
}

#[test]
fn b08_wrong_genesis_hash_fails() {
    let signed = sign_v2(&start_authority(), &single_authority_state());
    let mut want = expected();
    want.genesis_hash = "sha256:some-other-genesis".to_string();
    let error = verify_signed_desired_state_v2(&signed, &want).unwrap_err();
    assert!(error.contains("Genesis hash disagrees"), "{error}");
}

#[test]
fn b09_wrong_release_id_fails() {
    let signed = sign_v2(&start_authority(), &single_authority_state());
    let mut want = expected();
    want.release_id = "chain1266-promotable-rc21".to_string();
    let error = verify_signed_desired_state_v2(&signed, &want).unwrap_err();
    assert!(error.contains("release id disagrees"), "{error}");
}

#[test]
fn b10_wrong_authority_fingerprint_fails() {
    let signed = sign_v2(&start_authority(), &single_authority_state());
    let mut want = expected();
    want.authority_public_key_fingerprint = "sha256:validator-node-03".to_string();
    let error = verify_signed_desired_state_v2(&signed, &want).unwrap_err();
    assert!(error.contains("authority fingerprint disagrees"), "{error}");
}

#[test]
fn b11_wrong_chain_incarnation_fails() {
    let signed = sign_v2(&start_authority(), &single_authority_state());
    let mut want = expected();
    want.chain_incarnation = 4;
    let error = verify_signed_desired_state_v2(&signed, &want).unwrap_err();
    assert!(error.contains("incarnation 5 disagrees"), "{error}");
}

#[test]
fn b16_binding_fingerprint_must_match_the_desired_state() {
    let mut state = single_authority_state();
    state.authority_public_key_fingerprint = "sha256:mismatch".to_string();
    let error = state.validate().unwrap_err();
    assert!(
        error.contains("disagrees between the binding and the desired state"),
        "{error}"
    );
}

#[test]
fn b17_pending_consensus_transition_is_null_for_this_launch() {
    let state = single_authority_state();
    match &state.consensus_binding {
        ConsensusBindingV2::SingleAuthority {
            pending_consensus_transition,
            authority_end_height,
            ..
        } => {
            assert!(pending_consensus_transition.is_none());
            assert!(authority_end_height.is_none());
        }
        other => panic!("expected SingleAuthority, got {other:?}"),
    }
}
