mod aead;
mod envelope;
mod kem;
mod key_registry;
mod key_rotation;
mod nonce;
mod padding;
mod protected;
mod share;
mod verifier;

pub use aead::{AeadCiphertext, AeadError, AeadProvider};
pub use envelope::{EncryptedTransactionEnvelope, EnvelopeAad, ShareCapsule, ShareCommitment};
pub use kem::{KemEncapsulation, KemError, KemProvider};
pub use key_registry::{IngressKemKeyRecord, IngressKemKeyRegistry, IngressKemPublicKey};
pub use key_rotation::{active_key_for_validator, validate_key_schedule};
pub use nonce::{EnvelopeNonce, NonceError};
pub use padding::{pad_plaintext, unpad_plaintext};
pub use share::{governed_reveal_threshold, ShamirShare};
pub use verifier::{canonical_signing_bytes, SignatureVerifier};

pub use protected::{
    decrypt_historical_share_capsule_diagnostic, decrypt_protected_payload, decrypt_share_capsule,
    decrypt_share_capsule_diagnostic, decrypt_share_capsule_with_kem_diagnostic,
    encrypt_protected_payload, encrypt_protected_payload_with_kem, verify_ingress_key_possession,
    verify_ingress_key_possession_with_kem, CapsuleVerificationFailure, CapsuleVerificationStage,
    GovernedThresholdDecryptor, ProtectedPayload, ProtectedPayloadAad, ProtectedPayloadEnvelope,
    ML_KEM_1024_ALGORITHM, ML_KEM_1024_CIPHERTEXT_BYTES, ML_KEM_1024_PUBLIC_KEY_BYTES,
    ML_KEM_1024_SECRET_KEY_BYTES,
};
