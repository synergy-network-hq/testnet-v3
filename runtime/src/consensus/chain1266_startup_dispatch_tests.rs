//! Chain 1266 startup dispatch.
//!
//! Real ML-DSA-87 keys, real canonical encoding, real signature verification.
//! Nothing about verifier selection is mocked.

use super::chain1266_startup_dispatch::*;
use super::single_authority_startup::*;
use crate::crypto::pqc::{PQCAlgorithm, PQCManager, PQCPrivateKey, PQCPublicKey};
use crate::desired_state_v2::*;
use crate::desired_state_v2_canonical::canonical_bytes;
use base64::{engine::general_purpose, Engine as _};

const EXECUTION_FINGERPRINT: &str =
    "sha256:642339bca236a557493a3666c9c71a6bac075b42732f475593999ff34509a145";
const AUTHORITY_FINGERPRINT: &str =
    "sha256:2420c052e15721755608fdf5fc2f5aecb1741d79ef5ab24a72ed4201fd4a056c";

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

fn launch_state() -> DesiredStateV2 {
    DesiredStateV2 {
        schema_version: DESIRED_STATE_SCHEMA_VERSION_V2,
        chain_id: LAUNCH_CHAIN_ID,
        chain_incarnation: LAUNCH_CHAIN_INCARNATION,
        network_id: LAUNCH_NETWORK_ID.to_string(),
        directory_namespace: LAUNCH_DIRECTORY_NAMESPACE.to_string(),
        release_id: LAUNCH_RELEASE_ID.to_string(),
        genesis_hash: LAUNCH_GENESIS_HASH.to_string(),
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

fn launch_expectation() -> StartupExpectation {
    StartupExpectation {
        genesis_chain_id: LAUNCH_CHAIN_ID,
        genesis_chain_incarnation: LAUNCH_CHAIN_INCARNATION,
        genesis_network_id: LAUNCH_NETWORK_ID.to_string(),
        genesis_hash: LAUNCH_GENESIS_HASH.to_string(),
        genesis_directory_namespace: LAUNCH_DIRECTORY_NAMESPACE.to_string(),
        release_id: LAUNCH_RELEASE_ID.to_string(),
        authority_id: LAUNCH_AUTHORITY_ID.to_string(),
        authority_public_key_fingerprint: AUTHORITY_FINGERPRINT.to_string(),
        authority_key_algorithm: PQCAlgorithm::MLDSA65,
    }
}

/// Production pins, with the bootstrap signer repointed at the test key. The
/// custody ML-DSA-87 private key never leaves its custody directory, so a test
/// cannot produce a signature under the shipped fingerprint; every other launch
/// pin is exercised at its real production value.
fn pins_for(signed: &SignedDesiredStateV2) -> SingleAuthorityLaunchPins {
    let mut pins = SingleAuthorityLaunchPins::incarnation5();
    pins.start_authority_fingerprint = signed.start_authority_fingerprint.clone();
    pins
}

fn verify_with(
    state: &DesiredStateV2,
    signed: &SignedDesiredStateV2,
    pins: &SingleAuthorityLaunchPins,
) -> Result<String, String> {
    let bytes = canonical_bytes(state).expect("canonical bytes");
    verify_single_authority_v2_activation(
        &bytes,
        signed,
        &launch_expectation(),
        LAUNCH_AUTHORITY_ADDRESS,
        pins,
    )
}

// ---------------------------------------------------------------
// T1. Incarnation 5 + single_authority_v1 + a valid V2 activation
//     succeeds with no V1 manifest, no Governance Authority and no
//     compile-time V1 source revision anywhere in the path.
// ---------------------------------------------------------------
#[test]
fn t1_incarnation5_valid_v2_succeeds_without_any_v1_input() {
    assert_eq!(
        dispatch_chain1266_startup(1266, 5, "single_authority_v1"),
        Ok(Chain1266StartupDispatch::SingleAuthorityV2)
    );

    let authority = start_authority();
    let state = launch_state();
    let signed = sign(&authority, &state);

    let release_id =
        verify_with(&state, &signed, &pins_for(&signed)).expect("valid V2 activation must start");
    assert_eq!(release_id, LAUNCH_RELEASE_ID);

    // Nothing in this path consulted the V1 manifest environment.
    for variable in [
        crate::desired_state::DESIRED_STATE_ENV,
        crate::desired_state::DESIRED_STATE_SHA256_ENV,
        crate::desired_state::DESIRED_STATE_SIGNATURE_ENV,
    ] {
        assert!(
            std::env::var(variable).is_err(),
            "the incarnation-5 path must not require {variable}"
        );
    }
}

// ---------------------------------------------------------------
// T2. Incarnation 5 with a missing V2 authorization fails closed.
// ---------------------------------------------------------------
#[test]
fn t2_incarnation5_missing_v2_fails_closed() {
    let pins = SingleAuthorityLaunchPins::incarnation5();
    let state = launch_state();
    let bytes = canonical_bytes(&state).expect("canonical bytes");

    // An empty authorization envelope stands in for "nothing installed".
    let missing = SignedDesiredStateV2 {
        desired_state: state.clone(),
        signature_algorithm: String::new(),
        signature_domain: String::new(),
        start_authority_public_key_base64: String::new(),
        start_authority_fingerprint: String::new(),
        signature_base64: String::new(),
    };
    let error = verify_single_authority_v2_activation(
        &bytes,
        &missing,
        &launch_expectation(),
        LAUNCH_AUTHORITY_ADDRESS,
        &pins,
    )
    .expect_err("a missing V2 authorization must fail closed");
    assert!(
        error.contains("bootstrap identity"),
        "unexpected error: {error}"
    );
}

// ---------------------------------------------------------------
// T3. Incarnation 5 with an invalid V2 signature fails closed.
// ---------------------------------------------------------------
#[test]
fn t3_incarnation5_invalid_v2_signature_fails_closed() {
    let authority = start_authority();
    let state = launch_state();
    let mut signed = sign(&authority, &state);

    // Flip one signature byte. The key, fingerprint, domain and canonical
    // document all stay valid, so only the real ML-DSA-87 verification can
    // reject this.
    let mut signature_bytes = general_purpose::STANDARD
        .decode(&signed.signature_base64)
        .expect("signature decodes");
    let last = signature_bytes.len() - 1;
    signature_bytes[last] ^= 0x01;
    signed.signature_base64 = general_purpose::STANDARD.encode(&signature_bytes);

    let error = verify_with(&state, &signed, &pins_for(&signed))
        .expect_err("an invalid V2 signature must fail closed");
    assert!(
        error.to_lowercase().contains("signature"),
        "unexpected error: {error}"
    );
}

// ---------------------------------------------------------------
// T4. Incarnation 5 with a V1 manifest present still does not invoke
//     or accept V1. A V1-domain authorization is rejected outright.
// ---------------------------------------------------------------
#[test]
fn t4_incarnation5_ignores_a_present_v1_manifest() {
    assert_eq!(
        dispatch_chain1266_startup(1266, 5, "single_authority_v1"),
        Ok(Chain1266StartupDispatch::SingleAuthorityV2),
        "a V1 manifest on disk must not change the Genesis-anchored dispatch"
    );

    let authority = start_authority();
    let state = launch_state();
    let mut signed = sign(&authority, &state);
    signed.signature_domain =
        crate::consensus_start::CHAIN1266_START_SIGNATURE_DOMAIN.to_string();

    let error = verify_with(&state, &signed, &pins_for(&signed))
        .expect_err("a V1-domain authorization must never start incarnation 5");
    assert!(error.contains("domain"), "unexpected error: {error}");
}

// ---------------------------------------------------------------
// T5. Incarnation 4 + coordinated_round_robin_v1 still routes to the
//     unchanged V1 verifier.
// ---------------------------------------------------------------
#[test]
fn t5_incarnation4_coordinated_still_requires_v1() {
    assert_eq!(
        dispatch_chain1266_startup(1266, 4, "coordinated_round_robin_v1"),
        Ok(Chain1266StartupDispatch::CoordinatedV1)
    );
}

// ---------------------------------------------------------------
// T6. Incarnation/protocol mismatches fail closed.
// ---------------------------------------------------------------
#[test]
fn t6_incarnation_protocol_mismatches_fail_closed() {
    for (incarnation, protocol) in [
        (5u64, "coordinated_round_robin_v1"),
        (4, "single_authority_v1"),
        (5, "posy_v2_2"),
        (4, "posy/2.2"),
        (6, "single_authority_v1"),
        (3, "coordinated_round_robin_v1"),
        (5, ""),
    ] {
        let outcome = dispatch_chain1266_startup(1266, incarnation, protocol);
        let error = outcome.expect_err(&format!(
            "incarnation {incarnation} with protocol {protocol} must fail closed"
        ));
        assert!(
            error.contains("unsupported Chain 1266 incarnation/protocol pairing"),
            "unexpected error for ({incarnation}, {protocol}): {error}"
        );
    }

    // A non-1266 chain keeps its existing behaviour.
    assert_eq!(
        dispatch_chain1266_startup(1265, 5, "single_authority_v1"),
        Ok(Chain1266StartupDispatch::NonChain1266)
    );
}

// ---------------------------------------------------------------
// T7. An invalid V2 cannot fall through to the coordinated path.
// ---------------------------------------------------------------
#[test]
fn t7_invalid_v2_never_falls_through_to_coordinated() {
    let authority = start_authority();

    // A correctly signed activation that selects the coordinated binding is
    // still refused, because Genesis bound single_authority_v1.
    let mut coordinated = launch_state();
    coordinated.consensus_binding = ConsensusBindingV2::CoordinatedRoundRobin {
        coordinator_id: "validator-1".to_string(),
        producer_ids: vec![
            "validator-2".to_string(),
            "validator-3".to_string(),
            "validator-4".to_string(),
            "validator-5".to_string(),
            "validator-6".to_string(),
        ],
        producer_turn_timeout_ms: 4_000,
    };
    let signed = sign(&authority, &coordinated);
    let error = verify_with(&coordinated, &signed, &pins_for(&signed))
        .expect_err("a coordinated binding must not start incarnation 5");
    assert!(
        error.contains("must never fall through to the coordinated path"),
        "unexpected error: {error}"
    );

    // A tampered single-authority document is refused rather than downgraded.
    let state = launch_state();
    let signed = sign(&authority, &state);
    let mut tampered = state.clone();
    tampered.release_id = format!("{}-tampered", state.release_id);
    let error = verify_with(&tampered, &signed, &pins_for(&signed))
        .expect_err("a tampered document must fail closed");
    assert!(
        !error.contains("coordinated_round_robin_v1 selected"),
        "unexpected fall-through: {error}"
    );

    // And an off-launch Genesis hash is refused by the launch pins even when
    // the signature over it is perfectly valid.
    let mut other_genesis = launch_state();
    other_genesis.genesis_hash = "00".repeat(32);
    let signed = sign(&authority, &other_genesis);
    let mut expectation = launch_expectation();
    expectation.genesis_hash = other_genesis.genesis_hash.clone();
    let bytes = canonical_bytes(&other_genesis).expect("canonical bytes");
    let error = verify_single_authority_v2_activation(
        &bytes,
        &signed,
        &expectation,
        LAUNCH_AUTHORITY_ADDRESS,
        &pins_for(&signed),
    )
    .expect_err("an off-launch Genesis must fail closed");
    assert!(error.contains("Genesis hash"), "unexpected error: {error}");
}
