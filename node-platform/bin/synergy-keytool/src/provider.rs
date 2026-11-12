//! Explicit authenticated native provider context; no discovery.
use std::sync::{Arc, Mutex};
use synergy_address_engine::apqe::crypto_engine::CryptoEngine;
use synergy_aegis::{AegisPolicy, KeyId, PqvmSigner, PqvmVerifier};
pub type Engine = Arc<Mutex<CryptoEngine>>;
pub fn verifier(policy: AegisPolicy, engine: Option<Engine>) -> Result<PqvmVerifier, String> {
    if let Some(engine) = engine {
        return PqvmVerifier::with_apqe(policy, engine).map_err(|e| e.to_string());
    }
    let _ = policy;
    Err("explicit authenticated APQE provider required".into())
}
pub fn signer(
    policy: AegisPolicy,
    id: KeyId,
    public: &[u8],
    secret: Vec<u8>,
    engine: Option<Engine>,
) -> Result<PqvmSigner, String> {
    if let Some(engine) = engine {
        return PqvmSigner::with_apqe(policy, id, public, secret, engine)
            .map_err(|e| e.to_string());
    }
    let _ = (policy, id, public);
    drop(synergy_address_engine::apqe::SecretBytes::from_bytes(
        secret,
    ));
    Err("explicit authenticated APQE provider required".into())
}

#[cfg(test)]
pub fn native_test_engine() -> Engine {
    synergy_aegis::load_authenticated_native_engine(
        std::path::Path::new(
            &std::env::var("APQE_TRUSTED_NATIVE_REPORT").expect("explicit native report"),
        ),
        &std::env::var("APQE_AUTHENTICATED_REPORT_SHA256").expect("authenticated report digest"),
    )
    .unwrap()
}
