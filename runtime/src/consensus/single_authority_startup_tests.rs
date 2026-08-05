//! Verified single-authority startup resolution.
//!
//! Real ML-DSA-87 start-authorization keys, real canonical encoding, real
//! signature verification. Nothing about the protocol selection is mocked.

use super::single_authority_startup::*;
use crate::crypto::pqc::{PQCAlgorithm, PQCManager, PQCPrivateKey, PQCPublicKey};
use crate::desired_state_v2::*;
use crate::desired_state_v2_canonical::canonical_bytes;
use base64::{engine::general_purpose, Engine as _};

const GENESIS_HASH: &str = "e25f4d99ec61e7c2db362549e6d950391ee13c7c21f4e51c6bbd051f063cd4e8";
const RELEASE_ID: &str = "chain1266-single-authority-rc1";
const AUTHORITY_FINGERPRINT: &str = "sha256:0f9c1d2b3a4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8";
const EXECUTION_FINGERPRINT: &str = "sha256:execution-configuration";

struct StartAuthority {
    public: PQCPublicKey,
    private: PQCPrivateKey,
}

fn start_authority() -> StartAuthority {
    let mut manager = PQCManager::new();
    let (public, private) = manager
        .generate_keypair(PQCAlgorithm::MLDSA87)
        .expect("real ML-DSA-87 start-authorization key");
    StartAuthority { public, private }
}

fn single_authority_state() -> DesiredStateV2 {
    DesiredStateV2 {
        schema_version: DESIRED_STATE_SCHEMA_VERSION_V2,
        chain_id: LAUNCH_CHAIN_ID,
        chain_incarnation: LAUNCH_CHAIN_INCARNATION,
        network_id: LAUNCH_NETWORK_ID.to_string(),
        directory_namespace: format!(
            "chain-{LAUNCH_CHAIN_ID}/incarnation-{LAUNCH_CHAIN_INCARNATION}"
        ),
        release_id: RELEASE_ID.to_string(),
        genesis_hash: GENESIS_HASH.to_string(),
        consensus_binding: ConsensusBindingV2::SingleAuthority {
            authority_id: LAUNCH_AUTHORITY_ID.to_string(),
            authority_public_key_fingerprint: AUTHORITY_FINGERPRINT.to_string(),
            target_block_time_ms: LAUNCH_TARGET_BLOCK_TIME_MS,
            authority_start_height: 1,
            authority_end_height: None,
            pending_consensus_transition: None,
        },
        authority_public_key_fingerprint: AUTHORITY_FINGERPRINT.to_string(),
        execution_configuration_fingerprint: EXECUTION_FINGERPRINT.to_string(),
    }
}

fn coordinated_state() -> DesiredStateV2 {
    let mut state = single_authority_state();
    state.consensus_binding = ConsensusBindingV2::CoordinatedRoundRobin {
        coordinator_id: "validator-1".to_string(),
        producer_ids: vec!["validator-2".to_string()],
        producer_turn_timeout_ms: 4_000,
    };
    state
}

/// Signs with the REAL ML-DSA-87 key over the canonical domain-separated
/// payload.
fn sign(authority: &StartAuthority, state: &DesiredStateV2) -> SignedDesiredStateV2 {
    let payload = canonical_signing_payload(state).expect("canonical payload");
    let mut manager = PQCManager::new();
    let signature = manager
        .sign(&authority.private, &payload)
        .expect("ML-DSA-87 signature");
    SignedDesiredStateV2 {
        desired_state: state.clone(),
        signature_algorithm: START_AUTHORIZATION_ALGORITHM.to_string(),
        signature_domain: CHAIN1266_START_SIGNATURE_DOMAIN_V2.to_string(),
        start_authority_public_key_base64: general_purpose::STANDARD
            .encode(&authority.public.key_data),
        start_authority_fingerprint: format!("sha256:{}", sha256_hex(&authority.public.key_data)),
        signature_base64: general_purpose::STANDARD.encode(&signature.signature_data),
    }
}

fn expectation() -> StartupExpectation {
    StartupExpectation {
        genesis_chain_id: LAUNCH_CHAIN_ID,
        genesis_chain_incarnation: LAUNCH_CHAIN_INCARNATION,
        genesis_network_id: LAUNCH_NETWORK_ID.to_string(),
        genesis_hash: GENESIS_HASH.to_string(),
        genesis_directory_namespace: format!(
            "chain-{LAUNCH_CHAIN_ID}/incarnation-{LAUNCH_CHAIN_INCARNATION}"
        ),
        release_id: RELEASE_ID.to_string(),
        authority_id: LAUNCH_AUTHORITY_ID.to_string(),
        authority_public_key_fingerprint: AUTHORITY_FINGERPRINT.to_string(),
        authority_key_algorithm: PQCAlgorithm::MLDSA65,
    }
}

fn resolve(
    state: &DesiredStateV2,
    signed: &SignedDesiredStateV2,
    expectation: &StartupExpectation,
) -> Result<VerifiedConsensusStartup, String> {
    let bytes = canonical_bytes(state).expect("canonical bytes");
    resolve_verified_consensus_startup(&bytes, signed, expectation)
}

// ---------------------------------------------------------------
// D01. A valid signed single-authority activation selects the driver.
// ---------------------------------------------------------------
#[test]
fn d01_valid_signed_activation_selects_single_authority() {
    let authority = start_authority();
    let state = single_authority_state();
    let signed = sign(&authority, &state);

    let resolved = resolve(&state, &signed, &expectation()).expect("valid activation resolves");
    let VerifiedConsensusStartup::SingleAuthority(plan) = resolved else {
        panic!("a signed single-authority binding must select the single-authority driver");
    };
    assert_eq!(plan.chain_id, LAUNCH_CHAIN_ID);
    assert_eq!(plan.chain_incarnation, LAUNCH_CHAIN_INCARNATION);
    assert_eq!(plan.network_id, LAUNCH_NETWORK_ID);
    assert_eq!(plan.authority_id, LAUNCH_AUTHORITY_ID);
    assert_eq!(plan.target_block_time_ms, LAUNCH_TARGET_BLOCK_TIME_MS);
    assert_eq!(plan.authority_start_height, 1);
    assert_eq!(plan.release_id, RELEASE_ID);
    assert_eq!(plan.genesis_hash, GENESIS_HASH);
    assert_eq!(plan.directory_namespace, "chain-1266/incarnation-5");
    assert_eq!(plan.authority_public_key_fingerprint, AUTHORITY_FINGERPRINT);
}

// ---------------------------------------------------------------
// D08. An unsigned binding is rejected.
// ---------------------------------------------------------------
#[test]
fn d08_unsigned_single_authority_binding_is_rejected() {
    let authority = start_authority();
    let state = single_authority_state();
    let mut signed = sign(&authority, &state);
    signed.signature_base64 = String::new();
    let error = resolve(&state, &signed, &expectation()).unwrap_err();
    assert!(error.contains("signature is empty"), "{error}");

    // A structurally present but wrong signature is also rejected.
    let other = start_authority();
    let mut forged = sign(&authority, &state);
    forged.signature_base64 = sign(&other, &state).signature_base64;
    let error = resolve(&state, &forged, &expectation()).unwrap_err();
    assert!(error.contains("verification failed"), "{error}");
}

// ---------------------------------------------------------------
// D09. A V1 coordinated authorization cannot select the V2 driver.
// ---------------------------------------------------------------
#[test]
fn d09_v1_authorization_cannot_select_the_v2_driver() {
    let authority = start_authority();
    let state = single_authority_state();

    // A V1 signature domain can never authorize a V2 start.
    let mut v1_domain = sign(&authority, &state);
    v1_domain.signature_domain = "SYNERGY_CHAIN1266_START_CONSENSUS_V1".to_string();
    let error = resolve(&state, &v1_domain, &expectation()).unwrap_err();
    assert!(error.contains("not the V2 domain"), "{error}");

    // A signature produced over the V1-style payload (no V2 domain prefix)
    // cannot verify against the canonical V2 payload.
    let mut manager = PQCManager::new();
    let v1_style_payload = serde_json::to_vec(&state).expect("v1-style payload");
    let v1_signature = manager
        .sign(&authority.private, &v1_style_payload)
        .expect("sign v1-style payload");
    let mut cross_domain = sign(&authority, &state);
    cross_domain.signature_base64 =
        general_purpose::STANDARD.encode(&v1_signature.signature_data);
    let error = resolve(&state, &cross_domain, &expectation()).unwrap_err();
    assert!(error.contains("verification failed"), "{error}");

    // A signed COORDINATED binding never yields the single-authority driver.
    let coordinated = coordinated_state();
    let signed_coordinated = sign(&authority, &coordinated);
    assert_eq!(
        resolve(&coordinated, &signed_coordinated, &expectation()).expect("coordinated resolves"),
        VerifiedConsensusStartup::CoordinatedRoundRobin
    );
}

// ---------------------------------------------------------------
// D10-D12. Authority fingerprint, release id, namespace.
// ---------------------------------------------------------------
#[test]
fn d10_wrong_authority_fingerprint_is_rejected() {
    let authority = start_authority();
    let state = single_authority_state();
    let signed = sign(&authority, &state);

    let mut wrong = expectation();
    wrong.authority_public_key_fingerprint = "sha256:some-other-authority".to_string();
    let error = resolve(&state, &signed, &wrong).unwrap_err();
    assert!(error.contains("authority fingerprint"), "{error}");
}

#[test]
fn d10b_start_authority_fingerprint_must_match_its_own_public_key() {
    let authority = start_authority();
    let state = single_authority_state();
    let mut signed = sign(&authority, &state);
    signed.start_authority_fingerprint = "sha256:not-this-key".to_string();
    let error = resolve(&state, &signed, &expectation()).unwrap_err();
    assert!(
        error.contains("fingerprint does not match its public key"),
        "{error}"
    );
}

#[test]
fn d11_wrong_release_id_is_rejected() {
    let authority = start_authority();
    let state = single_authority_state();
    let signed = sign(&authority, &state);

    let mut wrong = expectation();
    wrong.release_id = "chain1266-some-other-release".to_string();
    let error = resolve(&state, &signed, &wrong).unwrap_err();
    assert!(error.contains("release id"), "{error}");
}

#[test]
fn d12_wrong_namespace_is_rejected() {
    let authority = start_authority();
    let mut state = single_authority_state();
    // A namespace inconsistent with the signed identity is a structural error.
    state.directory_namespace = "chain-1266/incarnation-4".to_string();
    let signed = sign(&authority, &state);
    let error = resolve(&state, &signed, &expectation()).unwrap_err();
    assert!(
        error.contains("disagrees with signed chain identity"),
        "{error}"
    );
}

// ---------------------------------------------------------------
// D13. Genesis incarnation 4 + DesiredStateV2 incarnation 5 is rejected.
// ---------------------------------------------------------------
#[test]
fn d13_genesis_incarnation_four_with_desired_state_five_is_rejected() {
    let authority = start_authority();
    let state = single_authority_state();
    let signed = sign(&authority, &state);

    let mut stale_genesis = expectation();
    stale_genesis.genesis_chain_incarnation = 4;
    stale_genesis.genesis_directory_namespace = "chain-1266/incarnation-4".to_string();
    let error = resolve(&state, &signed, &stale_genesis).unwrap_err();
    assert!(
        error.contains("Genesis incarnation 4 is not the launch incarnation 5"),
        "{error}"
    );
    // The Genesis gate runs BEFORE any signature work.
    assert!(
        verify_genesis_identity(&stale_genesis).is_err(),
        "the Genesis identity gate must fail on its own"
    );
}

#[test]
fn d13b_launch_constants_are_enforced_on_the_signed_binding() {
    let authority = start_authority();

    // Wrong authority id.
    let mut state = single_authority_state();
    state.consensus_binding = ConsensusBindingV2::SingleAuthority {
        authority_id: "authority-node-99".to_string(),
        authority_public_key_fingerprint: AUTHORITY_FINGERPRINT.to_string(),
        target_block_time_ms: LAUNCH_TARGET_BLOCK_TIME_MS,
        authority_start_height: 1,
        authority_end_height: None,
        pending_consensus_transition: None,
    };
    let signed = sign(&authority, &state);
    let error = resolve(&state, &signed, &expectation()).unwrap_err();
    assert!(error.contains("requires authority authority-node-01"), "{error}");

    // Wrong target block time.
    let mut state = single_authority_state();
    state.consensus_binding = ConsensusBindingV2::SingleAuthority {
        authority_id: LAUNCH_AUTHORITY_ID.to_string(),
        authority_public_key_fingerprint: AUTHORITY_FINGERPRINT.to_string(),
        target_block_time_ms: 500,
        authority_start_height: 1,
        authority_end_height: None,
        pending_consensus_transition: None,
    };
    let signed = sign(&authority, &state);
    let error = resolve(&state, &signed, &expectation()).unwrap_err();
    assert!(error.contains("2000ms block time"), "{error}");

    // A non-null pending transition.
    let mut state = single_authority_state();
    state.consensus_binding = ConsensusBindingV2::SingleAuthority {
        authority_id: LAUNCH_AUTHORITY_ID.to_string(),
        authority_public_key_fingerprint: AUTHORITY_FINGERPRINT.to_string(),
        target_block_time_ms: LAUNCH_TARGET_BLOCK_TIME_MS,
        authority_start_height: 1,
        authority_end_height: None,
        pending_consensus_transition: Some(PendingConsensusTransition {
            from_protocol: "single_authority_v1".to_string(),
            to_protocol: "posy/2.2".to_string(),
            activation_height: 1_000,
            retiring_authority: LAUNCH_AUTHORITY_ID.to_string(),
            successor_validator_set_hash: "sha256:successor".to_string(),
            successor_parameter_hash: "sha256:parameters".to_string(),
            required_parent_hash: "sha256:parent".to_string(),
            required_state_root: "sha256:state".to_string(),
            authorization_hash: "sha256:authorization".to_string(),
            transition_version: 1,
        }),
    };
    let signed = sign(&authority, &state);
    let error = resolve(&state, &signed, &expectation()).unwrap_err();
    assert!(error.contains("null pending consensus transition"), "{error}");

    // A non-ML-DSA-65 authority block key.
    let state = single_authority_state();
    let signed = sign(&authority, &state);
    let mut wrong_algorithm = expectation();
    wrong_algorithm.authority_key_algorithm = PQCAlgorithm::MLDSA87;
    let error = resolve(&state, &signed, &wrong_algorithm).unwrap_err();
    assert!(error.contains("requires ML-DSA-65"), "{error}");
}

// ---------------------------------------------------------------
// D14. No peer/vote/QC/quorum/coordinator/producer input is constructed.
// ---------------------------------------------------------------
#[test]
fn d14_single_authority_plan_constructs_no_coordinated_input() {
    let authority = start_authority();
    let state = single_authority_state();
    let signed = sign(&authority, &state);
    let VerifiedConsensusStartup::SingleAuthority(plan) =
        resolve(&state, &signed, &expectation()).expect("resolve")
    else {
        panic!("expected the single-authority branch");
    };

    let rendered = format!("{plan:?}").to_ascii_lowercase();
    for forbidden in [
        "peer",
        "vote",
        "qc",
        "quorum",
        "coordinator",
        "producer",
        "certificate",
        "round",
        "cluster",
        "relayer",
        "validator_set",
    ] {
        assert!(
            !rendered.contains(forbidden),
            "the single-authority plan leaked `{forbidden}`: {rendered}"
        );
    }

    // The canonical signed encoding carries no coordinated field either.
    let encoded = String::from_utf8(canonical_bytes(&state).expect("bytes")).expect("utf8");
    for forbidden in [
        "coordinator",
        "producer",
        "quorum",
        "certificate",
        "vote",
        "round",
        "cluster",
    ] {
        assert!(!encoded.contains(forbidden), "leaked `{forbidden}`");
    }
}

/// A coordinated field inside a single-authority binding is a hard parse error,
/// so a coordinated input cannot be smuggled through the signed artifact.
#[test]
fn d14b_coordinated_fields_cannot_enter_a_single_authority_binding() {
    let raw = br#"{"schema_version":2,"chain_id":1266,"chain_incarnation":5,"network_id":"synergy-testnet-v3","directory_namespace":"chain-1266/incarnation-5","release_id":"chain1266-single-authority-rc1","genesis_hash":"e25f4d99ec61e7c2db362549e6d950391ee13c7c21f4e51c6bbd051f063cd4e8","consensus_binding":{"protocol":"single_authority_v1","authority_id":"authority-node-01","authority_public_key_fingerprint":"sha256:x","target_block_time_ms":2000,"authority_start_height":1,"coordinator_id":"validator-1"},"authority_public_key_fingerprint":"sha256:x","execution_configuration_fingerprint":"sha256:e"}"#;
    let authority = start_authority();
    let signed = sign(&authority, &single_authority_state());
    let error = resolve_verified_consensus_startup(raw, &signed, &expectation()).unwrap_err();
    assert!(error.contains("strict parse"), "{error}");
}

/// Non-canonical bytes cannot be authorized, even with a valid signature over
/// the canonical form.
#[test]
fn d15_non_canonical_desired_state_bytes_are_rejected() {
    let authority = start_authority();
    let state = single_authority_state();
    let signed = sign(&authority, &state);
    let pretty = serde_json::to_vec_pretty(&state).expect("pretty encoding");
    let error = resolve_verified_consensus_startup(&pretty, &signed, &expectation()).unwrap_err();
    assert!(error.contains("not in canonical form"), "{error}");
}

/// The supplied document must be the document the envelope signed.
#[test]
fn d16_envelope_must_match_the_supplied_document() {
    let authority = start_authority();
    let state = single_authority_state();
    let mut other = single_authority_state();
    other.release_id = "chain1266-single-authority-rc2".to_string();
    let signed_other = sign(&authority, &other);
    let error = resolve(&state, &signed_other, &expectation()).unwrap_err();
    assert!(
        error.contains("does not match the signed envelope"),
        "{error}"
    );
}
