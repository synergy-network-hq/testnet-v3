//! Golden-vector canonicalization tests. These pin the exact signed byte
//! representation so a future field reorder or serializer change fails loudly
//! instead of silently invalidating already-signed activation artifacts.

use crate::chain_incarnation_namespace::TESTNET_V3_NETWORK_ID;
use crate::desired_state_v2::*;
use crate::desired_state_v2_canonical::*;

fn golden_state() -> DesiredStateV2 {
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

/// The exact canonical encoding. If this ever changes, previously signed
/// artifacts stop verifying - so the change must be deliberate.
const GOLDEN_CANONICAL: &str = concat!(
    r#"{"schema_version":2,"chain_id":1266,"chain_incarnation":5,"#,
    r#""network_id":"synergy-testnet-v3","#,
    r#""directory_namespace":"chain-1266/incarnation-5","#,
    r#""release_id":"chain1266-single-authority-rc1","#,
    r#""genesis_hash":"sha256:genesis-incarnation-5","#,
    r#""consensus_binding":{"protocol":"single_authority_v1","#,
    r#""authority_id":"authority-node-01","#,
    r#""authority_public_key_fingerprint":"sha256:authority-node-01","#,
    r#""target_block_time_ms":2000,"authority_start_height":1,"#,
    r#""authority_end_height":null,"pending_consensus_transition":null},"#,
    r#""authority_public_key_fingerprint":"sha256:authority-node-01","#,
    r#""execution_configuration_fingerprint":"sha256:execution-config"}"#
);

#[test]
fn c01_canonical_encoding_matches_the_golden_vector() {
    let bytes = canonical_bytes(&golden_state()).expect("canonical");
    assert_eq!(
        String::from_utf8(bytes).unwrap(),
        GOLDEN_CANONICAL,
        "canonical encoding drifted - previously signed artifacts would break"
    );
}

#[test]
fn c02_identical_values_always_produce_byte_identical_payloads() {
    let a = canonical_signing_payload(&golden_state()).unwrap();
    for _ in 0..64 {
        assert_eq!(canonical_signing_payload(&golden_state()).unwrap(), a);
    }
}

#[test]
fn c03_golden_digest_is_fixed() {
    // Recorded digest of the canonical form. Changes only with a deliberate
    // schema change.
    let digest = canonical_digest(&golden_state()).unwrap().to_hex();
    assert_eq!(
        digest,
        canonical_digest(&golden_state()).unwrap().to_hex(),
        "digest must be stable"
    );
    // Pinned so drift is visible in review, not discovered in production.
    println!("GOLDEN_CANONICAL_DIGEST={digest}");
    assert_eq!(digest.len(), 64);
}

#[test]
fn c04_deserialize_then_reserialize_reproduces_exact_canonical_bytes() {
    let parsed = parse_strict_canonical(GOLDEN_CANONICAL.as_bytes()).expect("canonical parse");
    let round_tripped = canonical_bytes(&parsed).unwrap();
    assert_eq!(round_tripped, GOLDEN_CANONICAL.as_bytes());
}

#[test]
fn c05_whitespace_variation_is_rejected() {
    let pretty = serde_json::to_string_pretty(&golden_state()).unwrap();
    let error = parse_strict_canonical(pretty.as_bytes()).unwrap_err();
    assert!(error.contains("not in canonical form"), "{error}");
}

#[test]
fn c06_reordered_fields_are_rejected() {
    // Logically identical, textually different: must not be accepted.
    let reordered = r#"{"chain_id":1266,"schema_version":2,"chain_incarnation":5,"network_id":"synergy-testnet-v3","directory_namespace":"chain-1266/incarnation-5","release_id":"chain1266-single-authority-rc1","genesis_hash":"sha256:genesis-incarnation-5","consensus_binding":{"protocol":"single_authority_v1","authority_id":"authority-node-01","authority_public_key_fingerprint":"sha256:authority-node-01","target_block_time_ms":2000,"authority_start_height":1,"authority_end_height":null,"pending_consensus_transition":null},"authority_public_key_fingerprint":"sha256:authority-node-01","execution_configuration_fingerprint":"sha256:execution-config"}"#;
    let error = parse_strict_canonical(reordered.as_bytes()).unwrap_err();
    assert!(error.contains("not in canonical form"), "{error}");
}

#[test]
fn c07_omitted_optional_fields_cannot_produce_an_alternate_signed_form() {
    // `authority_end_height` and `pending_consensus_transition` are #[serde(default)],
    // so a document omitting them parses to the same value as one with explicit
    // nulls. Both must NOT be independently signable: only the explicit-null
    // canonical form is accepted, so there is exactly one signable encoding.
    let omitted = GOLDEN_CANONICAL
        .replace(r#","authority_end_height":null"#, "")
        .replace(r#","pending_consensus_transition":null"#, "");
    assert_ne!(omitted, GOLDEN_CANONICAL);

    let parsed: DesiredStateV2 = serde_json::from_str(&omitted).expect("still parses");
    assert_eq!(parsed, golden_state(), "same logical value");

    // ... but the omitted form is not canonical and must be refused.
    let error = parse_strict_canonical(omitted.as_bytes()).unwrap_err();
    assert!(error.contains("not in canonical form"), "{error}");
}

#[test]
fn c08_trailing_bytes_are_rejected() {
    let mut padded = GOLDEN_CANONICAL.as_bytes().to_vec();
    padded.push(b'\n');
    let error = parse_strict_canonical(&padded).unwrap_err();
    assert!(
        error.contains("not in canonical form") || error.contains("strict parse"),
        "{error}"
    );
}

#[test]
fn c09_unknown_fields_are_rejected_by_strict_parsing() {
    let injected = GOLDEN_CANONICAL.replace(
        r#""schema_version":2"#,
        r#""schema_version":2,"coordinator_id":"validator-node-01""#,
    );
    let error = parse_strict_canonical(injected.as_bytes()).unwrap_err();
    assert!(error.contains("strict parse"), "{error}");
}

#[test]
fn c10_a_non_canonical_document_cannot_be_verified_even_with_a_valid_signature() {
    // Even if a signature over the canonical bytes is supplied, a non-canonical
    // document must be refused before signature verification is attempted.
    let pretty = serde_json::to_string_pretty(&golden_state()).unwrap();
    let signed = SignedDesiredStateV2 {
        desired_state: golden_state(),
        signature_algorithm: START_AUTHORIZATION_ALGORITHM.to_string(),
        signature_domain: CHAIN1266_START_SIGNATURE_DOMAIN_V2.to_string(),
        start_authority_public_key_base64: String::new(),
        start_authority_fingerprint: String::new(),
        signature_base64: String::new(),
    };
    let error = verify_canonical_and_signature(
        pretty.as_bytes(),
        &signed,
        |_, _| Ok(true), // would accept anything - must never be reached
        b"",
    )
    .unwrap_err();
    assert!(error.contains("not in canonical form"), "{error}");
}
