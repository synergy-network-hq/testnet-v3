//! Explicit APQE bridge; no discovery, fallback, or rewriting canonical preimages.
use crate::{
    AegisKem, AegisPolicy, AegisSigner, AegisVerifier, KemEncapsulation, KemError, KeyId,
    Signature, SignatureAlgorithm, SigningContext, SigningError, VerificationError,
};
use std::sync::{Arc, Mutex};
use synergy_address_engine::{
    apqe::{
        crypto_engine::{CryptoEngine, EngineError},
        provider::SignOptions,
        SecretBytes,
    },
    types::Algorithm,
};
// Fail closed under contention/poison rather than blocking a consensus poll.
fn with_engine<T>(
    engine: &Mutex<CryptoEngine>,
    operation: impl FnOnce(&CryptoEngine) -> Result<T, EngineError>,
) -> Result<T, String> {
    let provider = engine
        .try_lock()
        .map_err(|_| "APQE provider busy or poisoned".to_string())?;
    operation(&provider).map_err(|e| e.to_string())
}
fn with_engine_access<T>(
    engine: &Mutex<CryptoEngine>,
    serialize: bool,
    operation: impl FnOnce(&CryptoEngine) -> Result<T, EngineError>,
) -> Result<T, String> {
    let provider = if serialize {
        engine
            .lock()
            .map_err(|_| "APQE provider poisoned".to_string())?
    } else {
        engine
            .try_lock()
            .map_err(|_| "APQE provider busy or poisoned".to_string())?
    };
    operation(&provider).map_err(|e| e.to_string())
}
fn algorithm(a: SignatureAlgorithm) -> Result<Algorithm, &'static str> {
    match a {
        SignatureAlgorithm::MlDsa65 => Ok(Algorithm::MlDsa65),
        SignatureAlgorithm::MlDsa87 => Ok(Algorithm::MlDsa87),
        _ => Err("unsupported APQE node signature profile"),
    }
}
#[derive(Clone)]
pub struct ApqeVerifier {
    engine: Arc<Mutex<CryptoEngine>>,
    policy: AegisPolicy,
    serialize: bool,
}
impl std::fmt::Debug for ApqeVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ApqeVerifier")
            .field("policy", &self.policy)
            .finish_non_exhaustive()
    }
}
impl ApqeVerifier {
    pub fn new(
        engine: Arc<Mutex<CryptoEngine>>,
        policy: AegisPolicy,
    ) -> Result<Self, VerificationError> {
        policy.validate().map_err(VerificationError::Policy)?;
        for a in &policy.allowed_algorithms {
            let a = algorithm(*a).map_err(|e| VerificationError::Provider(e.into()))?;
            with_engine(&engine, |e| e.require_algorithm(a))
                .map_err(VerificationError::Provider)?;
        }
        Ok(Self {
            engine,
            policy,
            serialize: false,
        })
    }
}
impl ApqeVerifier {
    /// Serialize calls only on dedicated blocking transport workers. Consensus
    /// callers retain the nonblocking default and must own an exclusive engine.
    pub fn serialized(mut self) -> Self {
        self.serialize = true;
        self
    }
}
impl AegisVerifier for ApqeVerifier {
    fn verify(
        &self,
        context: &SigningContext,
        message: &[u8],
        signature: &Signature,
        public_key: &[u8],
    ) -> Result<(), VerificationError> {
        context
            .validate()
            .map_err(|_| VerificationError::InvalidContext)?;
        self.policy
            .authorize(signature.algorithm, message.len(), signature.bytes.len())
            .map_err(VerificationError::Policy)?;
        let a =
            algorithm(signature.algorithm).map_err(|e| VerificationError::Provider(e.into()))?;
        // Existing canonical preimages bind the context. Preserve the raw empty-context FIPS profile.
        match with_engine_access(&self.engine, self.serialize, |e| {
            e.verify(
                a,
                public_key,
                message,
                &signature.bytes,
                SignOptions::default(),
            )
        }) {
            Ok(true) => Ok(()),
            Ok(false) => Err(VerificationError::InvalidSignature),
            Err(e) => Err(VerificationError::Provider(e.to_string())),
        }
    }
}
pub struct ApqeSigner {
    engine: Arc<Mutex<CryptoEngine>>,
    policy: AegisPolicy,
    key_id: KeyId,
    selected: SignatureAlgorithm,
    secret: SecretBytes,
    serialize: bool,
}
impl ApqeSigner {
    /// Requires exact public/private possession. Owned secret allocation wipes on every exit.
    pub fn new(
        engine: Arc<Mutex<CryptoEngine>>,
        policy: AegisPolicy,
        key_id: KeyId,
        selected: SignatureAlgorithm,
        public: &[u8],
        secret: Vec<u8>,
    ) -> Result<Self, SigningError> {
        let secret = SecretBytes::from_bytes(secret);
        policy
            .authorize(selected, 0, 0)
            .map_err(SigningError::Policy)?;
        let a = algorithm(selected).map_err(|e| SigningError::Provider(e.into()))?;
        if !with_engine(&engine, |e| {
            e.keypair_corresponds(a, public, secret.as_bytes())
        })
        .map_err(SigningError::Provider)?
        {
            return Err(SigningError::KeyUnavailable);
        }
        Ok(Self {
            engine,
            policy,
            key_id,
            selected,
            secret,
            serialize: false,
        })
    }
}
impl ApqeSigner {
    /// Serialize calls only on dedicated blocking transport workers.
    pub fn serialized(mut self) -> Self {
        self.serialize = true;
        self
    }
}
impl AegisSigner for ApqeSigner {
    fn sign(
        &self,
        key_id: &KeyId,
        context: &SigningContext,
        message: &[u8],
    ) -> Result<Signature, SigningError> {
        context.validate()?;
        if key_id != &self.key_id {
            return Err(SigningError::KeyUnavailable);
        }
        self.policy
            .authorize(self.selected, message.len(), 0)
            .map_err(SigningError::Policy)?;
        let a = algorithm(self.selected).map_err(|e| SigningError::Provider(e.into()))?;
        let bytes = with_engine_access(&self.engine, self.serialize, |e| {
            e.sign(a, self.secret.as_bytes(), message, SignOptions::default())
        })
        .map_err(SigningError::Provider)?;
        self.policy
            .authorize(self.selected, message.len(), bytes.len())
            .map_err(SigningError::Policy)?;
        Ok(Signature {
            algorithm: self.selected,
            key_id: key_id.clone(),
            bytes,
        })
    }
}
/// Canonical identity proofs use a separate fixed root profile. This boundary
/// verifies unchanged raw messages; identity admission retains all scope checks.
#[derive(Clone)]
pub struct ApqeIdentityVerifier {
    engine: Arc<Mutex<CryptoEngine>>,
}
impl std::fmt::Debug for ApqeIdentityVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ApqeIdentityVerifier")
            .finish_non_exhaustive()
    }
}
impl ApqeIdentityVerifier {
    pub fn new(engine: Arc<Mutex<CryptoEngine>>) -> Result<Self, String> {
        for algorithm in [Algorithm::FnDsa1024, Algorithm::MlDsa65, Algorithm::MlDsa87] {
            with_engine(&engine, |e| e.require_algorithm(algorithm))?;
        }
        Ok(Self { engine })
    }
    pub fn verify_raw(
        &self,
        algorithm: &str,
        public: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), String> {
        let algorithm = match algorithm {
            "FN-DSA-1024" => Algorithm::FnDsa1024,
            "ML-DSA-65" => Algorithm::MlDsa65,
            "ML-DSA-87" => Algorithm::MlDsa87,
            _ => return Err("unsupported identity authorization profile".into()),
        };
        if with_engine_access(&self.engine, false, |e| {
            e.verify(
                algorithm,
                public,
                message,
                signature,
                SignOptions::default(),
            )
        })? {
            Ok(())
        } else {
            Err("identity authorization signature verification failed".into())
        }
    }
}
pub struct ApqeKem {
    engine: Arc<Mutex<CryptoEngine>>,
    selected: Algorithm,
}
impl ApqeKem {
    pub fn mlkem768(engine: Arc<Mutex<CryptoEngine>>) -> Result<Self, KemError> {
        Self::new(engine, Algorithm::MlKem768)
    }
    pub fn mlkem1024(engine: Arc<Mutex<CryptoEngine>>) -> Result<Self, KemError> {
        Self::new(engine, Algorithm::MlKem1024)
    }
    fn new(engine: Arc<Mutex<CryptoEngine>>, selected: Algorithm) -> Result<Self, KemError> {
        with_engine(&engine, |e| e.require_algorithm(selected))
            .map_err(|_| KemError::ProviderUnavailable)?;
        Ok(Self { engine, selected })
    }
}
impl AegisKem for ApqeKem {
    fn algorithm(&self) -> &'static str {
        if self.selected == Algorithm::MlKem768 {
            "ML-KEM-768"
        } else {
            "ML-KEM-1024"
        }
    }
    fn encapsulate(&self, public_key: &[u8]) -> Result<KemEncapsulation, KemError> {
        let wrapped = with_engine(&self.engine, |e| {
            e.kem_encapsulate(self.selected, public_key)
        })
        .map_err(|_| KemError::ProviderUnavailable)?;
        Ok(KemEncapsulation {
            ciphertext: wrapped.ciphertext,
            shared_secret: wrapped.shared_secret.as_bytes().to_vec(),
        })
    }
    fn decapsulate(&self, ciphertext: &[u8], secret_key: &[u8]) -> Result<Vec<u8>, KemError> {
        with_engine(&self.engine, |e| {
            e.kem_decapsulate(self.selected, ciphertext, secret_key)
        })
        .map(|s| s.as_bytes().to_vec())
        .map_err(|_| KemError::ProviderUnavailable)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn policy(a: SignatureAlgorithm) -> AegisPolicy {
        AegisPolicy {
            allowed_algorithms: vec![a],
            maximum_message_bytes: 1024,
            maximum_signature_bytes: 16384,
        }
    }
    #[test]
    fn missing_apqe_provider_never_falls_back() {
        let e = Arc::new(Mutex::new(CryptoEngine::new()));
        assert!(ApqeVerifier::new(e.clone(), policy(SignatureAlgorithm::MlDsa65)).is_err());
        assert!(ApqeSigner::new(
            e.clone(),
            policy(SignatureAlgorithm::MlDsa65),
            KeyId::new("missing").unwrap(),
            SignatureAlgorithm::MlDsa65,
            &[1],
            vec![1]
        )
        .is_err());
        assert!(ApqeKem::mlkem768(e.clone()).is_err());
        assert!(ApqeKem::mlkem1024(e).is_err());
    }
    #[test]
    fn contended_apqe_provider_returns_without_waiting() {
        let engine = Arc::new(Mutex::new(CryptoEngine::new()));
        let _held = engine.lock().unwrap();
        let result = ApqeVerifier::new(engine.clone(), policy(SignatureAlgorithm::MlDsa65));
        assert!(
            matches!(result, Err(VerificationError::Provider(message)) if message.contains("busy or poisoned"))
        );
    }
    #[test]
    #[ignore = "requires explicitly authenticated immutable APQE native report"]
    fn native_apqe_adapters_preserve_raw_profiles_and_reject_substitution() {
        let report = std::env::var("APQE_TRUSTED_NATIVE_REPORT").expect("trusted report path");
        let digest =
            std::env::var("APQE_AUTHENTICATED_REPORT_SHA256").expect("authenticated report digest");
        assert_eq!(digest.len(), 64);
        let mut hash = [0; 32];
        for (i, b) in hash.iter_mut().enumerate() {
            *b = u8::from_str_radix(&digest[2 * i..2 * i + 2], 16).unwrap();
        }
        // Invoking isolated-test operator authenticates and protects these local artifacts.
        let e = Arc::new(Mutex::new(
            unsafe {
                synergy_address_engine::apqe::native_manifest::validator_engine(
                    std::path::Path::new(&report),
                    hash,
                )
            }
            .unwrap(),
        ));
        let root = with_engine(&e, |e| e.generate_keypair(Algorithm::FnDsa1024)).unwrap();
        let root_signature = with_engine(&e, |e| {
            e.sign(
                Algorithm::FnDsa1024,
                root.private_key.as_bytes(),
                b"original identity proof",
                SignOptions::default(),
            )
        })
        .unwrap();
        let identity = ApqeIdentityVerifier::new(e.clone()).unwrap();
        identity
            .verify_raw(
                "FN-DSA-1024",
                &root.public_key,
                b"original identity proof",
                &root_signature,
            )
            .unwrap();
        assert!(identity
            .verify_raw(
                "FN-DSA-1024",
                &root.public_key,
                b"different proof",
                &root_signature
            )
            .is_err());
        assert!(identity
            .verify_raw(
                "FN-DSA-512",
                &root.public_key,
                b"original identity proof",
                &root_signature
            )
            .is_err());
        for selected in [SignatureAlgorithm::MlDsa65, SignatureAlgorithm::MlDsa87] {
            let a = algorithm(selected).unwrap();
            let pair = with_engine(&e, |e| e.generate_keypair(a)).unwrap();
            let id = KeyId::new("node-adapter").unwrap();
            let signer = ApqeSigner::new(
                e.clone(),
                policy(selected),
                id.clone(),
                selected,
                &pair.public_key,
                pair.private_key.as_bytes().to_vec(),
            )
            .unwrap();
            let verifier = ApqeVerifier::new(e.clone(), policy(selected)).unwrap();
            let c = SigningContext {
                domain: "SYNERGY-POSY-APQE-ADAPTER-V1".into(),
                chain_id: 1266,
                epoch: Some(1),
                height: Some(3),
            };
            let message = b"canonical preimage remains unchanged";
            let s = signer.sign(&id, &c, message).unwrap();
            assert!(with_engine(&e, |e| e.verify(
                a,
                &pair.public_key,
                message,
                &s.bytes,
                SignOptions::default()
            ))
            .unwrap());
            verifier.verify(&c, message, &s, &pair.public_key).unwrap();
            // Cross the existing node wire implementation in both directions.
            crate::PqvmVerifier::new(policy(selected))
                .unwrap()
                .verify(&c, message, &s, &pair.public_key)
                .unwrap();
            if selected == SignatureAlgorithm::MlDsa65 {
                let old = crate::PqvmSigner::from_secret_key_bytes(
                    policy(selected),
                    id.clone(),
                    pair.private_key.as_bytes().to_vec(),
                )
                .unwrap();
                verifier
                    .verify(
                        &c,
                        message,
                        &old.sign(&id, &c, message).unwrap(),
                        &pair.public_key,
                    )
                    .unwrap();
            }

            assert!(verifier
                .verify(&c, b"altered", &s, &pair.public_key)
                .is_err());
            assert!(signer
                .sign(&KeyId::new("foreign").unwrap(), &c, message)
                .is_err());
            let other = with_engine(&e, |e| e.generate_keypair(a)).unwrap();
            assert!(ApqeSigner::new(
                e.clone(),
                policy(selected),
                id,
                selected,
                &other.public_key,
                pair.private_key.as_bytes().to_vec()
            )
            .is_err());
        }
        for a in [Algorithm::MlKem768, Algorithm::MlKem1024] {
            let kem = ApqeKem::new(e.clone(), a).unwrap();
            let pair = with_engine(&e, |e| e.generate_keypair(a)).unwrap();
            let wrapped = kem.encapsulate(&pair.public_key).unwrap();
            if a == Algorithm::MlKem768 {
                let previous = crate::PqvmMlKem768;
                assert_eq!(
                    wrapped.shared_secret,
                    previous
                        .decapsulate(&wrapped.ciphertext, pair.private_key.as_bytes())
                        .unwrap()
                );
                let old = previous.encapsulate(&pair.public_key).unwrap();
                assert_eq!(
                    old.shared_secret,
                    kem.decapsulate(&old.ciphertext, pair.private_key.as_bytes())
                        .unwrap()
                );
            }

            assert_eq!(
                wrapped.shared_secret,
                kem.decapsulate(&wrapped.ciphertext, pair.private_key.as_bytes())
                    .unwrap()
            );
            assert!(kem.encapsulate(&[0]).is_err());
            assert!(kem.decapsulate(&[0], pair.private_key.as_bytes()).is_err());
        }
    }
}
