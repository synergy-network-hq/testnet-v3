//! These exercise the normally built library, not its cfg(test) fixtures.
use synergy_aegis::{
    AegisKem, AegisPolicy, KeyId, PqSynqVerifier, PqvmMlKem768, PqvmSigner, PqvmVerifier,
    SignatureAlgorithm,
};
fn policy() -> AegisPolicy {
    AegisPolicy {
        allowed_algorithms: vec![SignatureAlgorithm::MlDsa65],
        maximum_message_bytes: 1024,
        maximum_signature_bytes: 16384,
    }
}
#[test]
fn native_compatibility_providers_are_fail_closed_in_production_library() {
    assert!(PqvmVerifier::new(policy()).is_err());
    assert!(PqvmSigner::from_secret_key_bytes(
        policy(),
        KeyId::new("native").unwrap(),
        vec![7; 4032]
    )
    .is_err());
    assert!(PqSynqVerifier::for_network(1266, "native").is_err());
    assert!(PqvmMlKem768.encapsulate(&[0; 1184]).is_err());
    assert!(PqvmMlKem768.decapsulate(&[0; 1088], &[0; 2400]).is_err());
}
