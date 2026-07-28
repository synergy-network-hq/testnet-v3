//! One-shot generator for the FROZEN test-only genesis authority fixture.
//!
//! PQClean exposes no seeded/derandomized ML-DSA keygen, so deterministic test
//! authorities cannot be derived — they are generated once here and then frozen
//! as a checked-in fixture, which is what makes every subsequent run reproduce
//! identical addresses, receipts and roots.
//!
//! Run once:  cargo run --example gen_test_authorities > <fixture>.json
//! Never run again: regenerating changes every derived test address.

use pqsynq::traits::DigitalSignature;
use pqsynq::Sign;

const ROLES: &[&str] = &[
    "genesis_deployer",
    "governance_authority",
    "emergency_slashing_authority",
    "validator_registry_authority",
    "reward_distributor_authority",
    "emergency_pause_authority",
    "oracle_publisher",
];

fn main() {
    let mut entries = Vec::new();
    for role in ROLES {
        let (public_key, private_key) = Sign::mldsa87().keygen().expect("ML-DSA-87 keygen");
        entries.push(serde_json::json!({
            "role": role,
            "algorithm": "ML-DSA-87",
            "public_key_hex": hex::encode(&public_key),
            "private_key_hex": hex::encode(&private_key),
        }));
    }
    let doc = serde_json::json!({
        "fixture": "TEST_FIXTURE_NOT_FOR_PRODUCTION",
        "purpose": "Deterministic test-only genesis authorities for Track G development.",
        "warning": "These private keys are public. They must never hold value, authorize \
                    a production contract, or appear in a production genesis document.",
        "algorithm": "ML-DSA-87",
        "authorities": entries,
    });
    println!("{}", serde_json::to_string_pretty(&doc).unwrap());
}
