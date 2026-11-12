//! Governed protected-envelope consumer. Callers enforce reveal authorization
//! before releasing shares; these primitives never grant consensus authority.
use super::{
    governed_reveal_threshold, EncryptedTransactionEnvelope, EnvelopeAad, IngressKemKeyRecord,
    ShamirShare, ShareCapsule,
};
use crate::{EtdagDigest, EtdagError};
use aegis_pqvm::pqc::kem::mlkem::mlkem1024;
use pqrust_traits::kem::{Ciphertext as _, PublicKey as _, SecretKey as _, SharedSecret as _};
use std::collections::BTreeSet;
use synergy_aegis::{AegisHashEngine, AegisProtectedPrimitives, AegisSha3_256};
use zeroize::Zeroize;

pub const ML_KEM_1024_ALGORITHM: &str = "ML-KEM-1024";
pub const ML_KEM_1024_CIPHERTEXT_BYTES: usize = mlkem1024::ciphertext_bytes();
pub const ML_KEM_1024_PUBLIC_KEY_BYTES: usize = mlkem1024::public_key_bytes();
pub const ML_KEM_1024_SECRET_KEY_BYTES: usize = mlkem1024::secret_key_bytes();

// Sealed bindings keep the legacy height profile and the asynchronous processing
// profile distinct while sharing exactly the same cryptographic primitives.
mod binding_seal {
    pub trait Aad {}
    pub trait Envelope {}
}

/// Authenticated payload context. The key authorization height is an immutable
/// registry/snapshot anchor; for processing envelopes it is not an inclusion slot.
pub trait ProtectedPayloadAad: binding_seal::Aad {
    fn canonical_payload_bytes(&self) -> Result<Vec<u8>, EtdagError>;
    fn key_authorization_height(&self) -> u64;
    fn share_context_root(&self) -> &EtdagDigest;
    fn validate_encryption_input(
        &self,
        recipients: &[IngressKemKeyRecord],
        plaintext_bytes: usize,
    ) -> Result<(), EtdagError>;
}

impl binding_seal::Aad for EnvelopeAad {}
impl ProtectedPayloadAad for EnvelopeAad {
    fn canonical_payload_bytes(&self) -> Result<Vec<u8>, EtdagError> {
        self.canonical_bytes()
    }
    fn key_authorization_height(&self) -> u64 {
        self.target_height
    }
    fn share_context_root(&self) -> &EtdagDigest {
        &self.target_context_root
    }
    fn validate_encryption_input(
        &self,
        _recipients: &[IngressKemKeyRecord],
        _plaintext_bytes: usize,
    ) -> Result<(), EtdagError> {
        // Preserve the existing primitive's legacy input contract.
        Ok(())
    }
}

impl binding_seal::Aad for crate::admission::ProcessingEnvelopeAad {}
impl ProtectedPayloadAad for crate::admission::ProcessingEnvelopeAad {
    fn canonical_payload_bytes(&self) -> Result<Vec<u8>, EtdagError> {
        self.canonical_bytes()
    }
    fn key_authorization_height(&self) -> u64 {
        self.authorization_height
    }
    fn share_context_root(&self) -> &EtdagDigest {
        &self.processing_context_root
    }
    fn validate_encryption_input(
        &self,
        recipients: &[IngressKemKeyRecord],
        plaintext_bytes: usize,
    ) -> Result<(), EtdagError> {
        let ciphertext_bytes = plaintext_bytes
            .checked_add(16)
            .ok_or(EtdagError::InvalidCapacity)?;
        if !crate::CIPHERTEXT_SIZE_CLASSES.contains(&ciphertext_bytes) {
            return Err(EtdagError::InvalidCiphertextClasses);
        }
        if recipients.iter().any(|record| {
            [&record.validator_id, &record.key_id]
                .into_iter()
                .any(|id| id.trim().is_empty() || id.len() > 256 || id.contains(char::is_control))
        }) {
            return Err(EtdagError::InvalidEnvelope(
                "invalid processing ingress identifier".into(),
            ));
        }
        Ok(())
    }
}

/// Shape-checked encrypted payload, independent of the eventual inclusion block.
/// This primitive interface does not authorize reveal: the owner must verify
/// the profile's original authenticated ordering/reveal evidence first.
pub trait ProtectedPayloadEnvelope: binding_seal::Envelope {
    type Aad: ProtectedPayloadAad;
    fn validate_payload(&self) -> Result<(), EtdagError>;
    fn payload_aad(&self) -> &Self::Aad;
    fn capsules(&self) -> &[ShareCapsule];
    fn payload_nonce(&self) -> &[u8; 12];
    fn encrypted_payload(&self) -> &[u8];
    fn payload_key_commitment(&self) -> &EtdagDigest;
}

macro_rules! payload_envelope {
    ($envelope:ty, $aad:ty) => {
        impl binding_seal::Envelope for $envelope {}
        impl ProtectedPayloadEnvelope for $envelope {
            type Aad = $aad;
            fn validate_payload(&self) -> Result<(), EtdagError> {
                self.validate()
            }
            fn payload_aad(&self) -> &Self::Aad {
                &self.aad
            }
            fn capsules(&self) -> &[ShareCapsule] {
                &self.share_capsules
            }
            fn payload_nonce(&self) -> &[u8; 12] {
                &self.aead_nonce
            }
            fn encrypted_payload(&self) -> &[u8] {
                &self.ciphertext
            }
            fn payload_key_commitment(&self) -> &EtdagDigest {
                &self.key_commitment
            }
        }
    };
}
payload_envelope!(EncryptedTransactionEnvelope, EnvelopeAad);
payload_envelope!(
    crate::admission::ProcessingEnvelope,
    crate::admission::ProcessingEnvelopeAad
);

pub struct ProtectedPayload {
    pub aead_nonce: [u8; 12],
    pub key_commitment: EtdagDigest,
    pub ciphertext: Vec<u8>,
    pub share_capsules: Vec<ShareCapsule>,
}
struct SensitiveSecret(Vec<u8>);
impl SensitiveSecret {
    fn as_slice(&self) -> &[u8] {
        &self.0
    }
    fn fill(&mut self, byte: u8) {
        self.0.fill(byte);
    }
}
impl Drop for SensitiveSecret {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}
fn kem_error(error: synergy_aegis::KemError) -> EtdagError {
    match error {
        synergy_aegis::KemError::ProviderUnavailable => {
            EtdagError::CryptoProvider("APQE KEM unavailable".into())
        }
        _ => invalid(),
    }
}
fn invalid() -> EtdagError {
    EtdagError::UnauthorizedReveal
}
fn validate_key(record: &IngressKemKeyRecord, height: u64) -> Result<(), EtdagError> {
    if record.key_id.is_empty()
        || record.validator_id.is_empty()
        || record.public_key.algorithm != ML_KEM_1024_ALGORITHM
        || record.activation_height == 0
        || height < record.activation_height
        || record.retirement_height.is_some_and(|h| height >= h)
    {
        return Err(invalid());
    }
    mlkem1024::PublicKey::from_bytes(&record.public_key.public_key).map_err(|_| invalid())?;
    Ok(())
}
fn nonce() -> Result<[u8; 12], EtdagError> {
    let mut n = [0; 12];
    AegisProtectedPrimitives
        .random_bytes(&mut n)
        .map_err(|_| EtdagError::CryptoProvider("APQE entropy unavailable".into()))?;
    Ok(n)
}
fn encrypt(
    key: &[u8; 32],
    nonce: &[u8; 12],
    bytes: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, EtdagError> {
    AegisProtectedPrimitives
        .encrypt(key, nonce, aad, bytes)
        .map_err(|_| invalid())
}
fn decrypt(
    key: &[u8; 32],
    nonce: &[u8; 12],
    bytes: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, EtdagError> {
    AegisProtectedPrimitives
        .decrypt(key, nonce, aad, bytes)
        .map(|secret| secret.as_bytes().to_vec())
        .map_err(|_| invalid())
}
fn key_commitment(key: &[u8; 32], aad: &[u8]) -> EtdagDigest {
    let mut bytes = key.to_vec();
    bytes.extend_from_slice(aad);
    let digest = EtdagDigest::from_domain_bytes("PoSy/ETDAG/KeyCommitment/v3", &bytes);
    bytes.fill(0);
    digest
}
fn capsule_context(aad: &[u8], capsule: &ShareCapsule) -> Result<Vec<u8>, EtdagError> {
    capsule.share_commitment.validate()?;
    let mut bytes = aad.to_vec();
    bytes.extend_from_slice(capsule.validator_id.as_bytes());
    bytes.push(capsule.share_index);
    for pair in capsule.share_commitment.0.as_bytes().chunks_exact(2) {
        let s = std::str::from_utf8(pair).map_err(|_| invalid())?;
        bytes.push(u8::from_str_radix(s, 16).map_err(|_| invalid())?);
    }
    Ok(bytes)
}
fn capsule_key(secret: &[u8], context: &[u8]) -> [u8; 32] {
    let mut digest = AegisSha3_256
        .sha3_512_segments(&[
            b"PoSy/ETDAG/CapsuleKey/v3",
            &(secret.len() as u64).to_be_bytes(),
            secret,
            &(context.len() as u64).to_be_bytes(),
            context,
        ])
        .expect("fixed SHA3-512 is supported");
    let mut key = [0; 32];
    key.copy_from_slice(&digest[..32]);
    digest.zeroize();
    key
}
fn mul(mut a: u8, mut b: u8) -> u8 {
    let mut result = 0;
    for _ in 0..8 {
        if b & 1 != 0 {
            result ^= a;
        }
        let high = a & 128;
        a <<= 1;
        if high != 0 {
            a ^= 0x1b;
        }
        b >>= 1;
    }
    result
}
fn inverse(a: u8) -> u8 {
    let mut result = 1;
    for _ in 0..254 {
        result = mul(result, a);
    }
    result
}
fn split(key: &[u8; 32], threshold: usize, count: usize) -> Result<Vec<ShamirShare>, EtdagError> {
    let mut shares: Vec<_> = (1..=count)
        .map(|i| ShamirShare {
            index: i as u8,
            value: vec![0; 32],
        })
        .collect();
    let mut coefficients = vec![0; threshold];
    for (offset, byte) in key.iter().enumerate() {
        coefficients[0] = *byte;
        AegisProtectedPrimitives
            .random_bytes(&mut coefficients[1..])
            .map_err(|_| EtdagError::CryptoProvider("APQE entropy unavailable".into()))?;
        for share in &mut shares {
            share.value[offset] = coefficients
                .iter()
                .rev()
                .fold(0, |value, c| mul(value, share.index) ^ c);
        }
    }
    coefficients.fill(0);
    Ok(shares)
}
fn reconstruct(shares: &[ShamirShare], threshold: usize) -> Result<[u8; 32], EtdagError> {
    let mut indices = BTreeSet::new();
    if shares.len() < threshold {
        return Err(invalid());
    }
    for share in shares {
        share.validate()?;
        if !indices.insert(share.index) {
            return Err(invalid());
        }
    }
    let selected = &shares[..threshold];
    let mut key = [0; 32];
    for (i, share) in selected.iter().enumerate() {
        let mut numerator = 1;
        let mut denominator = 1;
        for (j, other) in selected.iter().enumerate() {
            if i != j {
                numerator = mul(numerator, other.index);
                denominator = mul(denominator, other.index ^ share.index);
            }
        }
        let basis = mul(numerator, inverse(denominator));
        for (byte, value) in key.iter_mut().zip(&share.value) {
            *byte ^= mul(*value, basis);
        }
    }
    Ok(key)
}

pub fn encrypt_protected_payload(
    aad: &impl ProtectedPayloadAad,
    recipients: &[IngressKemKeyRecord],
    count_quorum: usize,
    plaintext: &[u8],
) -> Result<ProtectedPayload, EtdagError> {
    encrypt_protected_payload_using(aad, recipients, count_quorum, plaintext, None)
}
pub fn encrypt_protected_payload_with_kem(
    aad: &impl ProtectedPayloadAad,
    recipients: &[IngressKemKeyRecord],
    count_quorum: usize,
    plaintext: &[u8],
    kem: &dyn synergy_aegis::AegisKem,
) -> Result<ProtectedPayload, EtdagError> {
    if kem.algorithm() != ML_KEM_1024_ALGORITHM {
        return Err(EtdagError::CryptoProvider(
            "protected ingress requires ML-KEM-1024".into(),
        ));
    }
    encrypt_protected_payload_using(aad, recipients, count_quorum, plaintext, Some(kem))
}
fn encrypt_protected_payload_using(
    aad: &impl ProtectedPayloadAad,
    recipients: &[IngressKemKeyRecord],
    count_quorum: usize,
    plaintext: &[u8],
    kem: Option<&dyn synergy_aegis::AegisKem>,
) -> Result<ProtectedPayload, EtdagError> {
    if kem.is_none() && !cfg!(test) {
        return Err(EtdagError::CryptoProvider(
            "explicit authenticated APQE KEM required; embedded encryption is forbidden".into(),
        ));
    }
    let threshold = governed_reveal_threshold(recipients.len(), count_quorum)?;
    aad.validate_encryption_input(recipients, plaintext.len())?;
    let aad_bytes = aad.canonical_payload_bytes()?;
    let mut recipients: Vec<_> = recipients.iter().collect();
    recipients.sort_by_key(|r| &r.validator_id);
    let mut validators = BTreeSet::new();
    let mut ids = BTreeSet::new();
    for record in &recipients {
        validate_key(record, aad.key_authorization_height())?;
        if !validators.insert(&record.validator_id) || !ids.insert(&record.key_id) {
            return Err(invalid());
        }
    }
    let mut key = [0; 32];
    AegisProtectedPrimitives
        .random_bytes(&mut key)
        .map_err(|_| EtdagError::CryptoProvider("APQE entropy unavailable".into()))?;
    let result = (|| {
        let aead_nonce = nonce()?;
        let ciphertext = encrypt(&key, &aead_nonce, plaintext, &aad_bytes)?;
        let key_commitment = key_commitment(&key, &aad_bytes);
        let mut shares = split(&key, threshold, recipients.len())?;
        let mut capsules = Vec::with_capacity(recipients.len());
        for (record, share) in recipients.iter().zip(shares.iter_mut()) {
            let (secret, kem_ciphertext) = match kem {
                Some(kem) => {
                    let encapsulated = kem
                        .encapsulate(&record.public_key.public_key)
                        .map_err(kem_error)?;
                    (
                        SensitiveSecret(encapsulated.shared_secret),
                        encapsulated.ciphertext,
                    )
                }
                None => {
                    let public = mlkem1024::PublicKey::from_bytes(&record.public_key.public_key)
                        .map_err(|_| invalid())?;
                    let (secret, ciphertext) = mlkem1024::encapsulate(&public);
                    (
                        SensitiveSecret(secret.as_bytes().to_vec()),
                        ciphertext.as_bytes().to_vec(),
                    )
                }
            };
            let mut capsule = ShareCapsule {
                validator_id: record.validator_id.clone(),
                ingress_kem_key_id: record.key_id.clone(),
                share_index: share.index,
                share_commitment: share.commitment(
                    &record.validator_id,
                    aad.share_context_root(),
                    aad.key_authorization_height(),
                )?,
                kem_ciphertext,
                aead_nonce: nonce()?,
                encrypted_share: vec![],
            };
            let context = capsule_context(&aad_bytes, &capsule)?;
            let mut wrapping = capsule_key(secret.as_slice(), &context);
            let mut bytes = share.canonical_bytes()?;
            let encrypted = encrypt(&wrapping, &capsule.aead_nonce, &bytes, &context);
            wrapping.fill(0);
            bytes.fill(0);
            share.value.fill(0);
            capsule.encrypted_share = encrypted?;
            capsules.push(capsule);
        }
        Ok(ProtectedPayload {
            aead_nonce,
            key_commitment,
            ciphertext,
            share_capsules: capsules,
        })
    })();
    key.fill(0);
    result
}

/// Public failure stage only; never carries keys, shares or plaintext. This is
/// a diagnostic result, not reveal authorization. The ordinary protocol API
/// still maps every rejected capsule to UnauthorizedReveal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapsuleVerificationStage {
    Provider,
    Envelope,
    RegistryKey,
    CapsuleBinding,
    SecretKey,
    KeyPossession,
    KemCiphertext,
    CapsuleContext,
    CapsuleAead,
    ShareEncoding,
    ShareCommitment,
}

#[derive(Debug)]
pub struct CapsuleVerificationFailure {
    pub stage: CapsuleVerificationStage,
    error: EtdagError,
}
impl CapsuleVerificationFailure {
    pub fn into_error(self) -> EtdagError {
        self.error
    }
    fn new(stage: CapsuleVerificationStage, error: EtdagError) -> Self {
        Self { stage, error }
    }
}

pub fn decrypt_share_capsule(
    envelope: &impl ProtectedPayloadEnvelope,
    capsule: &ShareCapsule,
    record: &IngressKemKeyRecord,
    secret_key: &[u8],
) -> Result<ShamirShare, EtdagError> {
    decrypt_share_capsule_diagnostic(envelope, capsule, record, secret_key)
        .map_err(|failure| failure.error)
}

pub fn decrypt_share_capsule_diagnostic(
    envelope: &impl ProtectedPayloadEnvelope,
    capsule: &ShareCapsule,
    record: &IngressKemKeyRecord,
    secret_key: &[u8],
) -> Result<ShamirShare, CapsuleVerificationFailure> {
    decrypt_capsule_with_recovery(envelope, capsule, record, secret_key, false, None)
}

/// Compatibility for authenticated, already durable version-1 pending records.
/// New admission and ordinary decrypt MUST use the FIPS-only function above.
/// This does not grant reveal permission or bypass any AEAD/share commitment.
pub fn decrypt_historical_share_capsule_diagnostic(
    envelope: &impl ProtectedPayloadEnvelope,
    capsule: &ShareCapsule,
    record: &IngressKemKeyRecord,
    secret_key: &[u8],
) -> Result<ShamirShare, CapsuleVerificationFailure> {
    decrypt_capsule_with_recovery(envelope, capsule, record, secret_key, true, None)
}

/// Explicit KEM ownership. Historical compatibility is permitted only by the
/// caller proving the record was authenticated and durable before this attempt.
pub fn decrypt_share_capsule_with_kem_diagnostic(
    envelope: &impl ProtectedPayloadEnvelope,
    capsule: &ShareCapsule,
    record: &IngressKemKeyRecord,
    secret_key: &[u8],
    historical_pending: bool,
    kem: &dyn synergy_aegis::AegisKem,
) -> Result<ShamirShare, CapsuleVerificationFailure> {
    decrypt_capsule_with_recovery(
        envelope,
        capsule,
        record,
        secret_key,
        historical_pending,
        Some(kem),
    )
}

fn historical_kyber_secret(prekey: &[u8], ciphertext: &[u8]) -> [u8; 32] {
    let ciphertext_hash = AegisSha3_256
        .sha3_256_segments(&[ciphertext])
        .expect("fixed SHA3-256 is supported");
    AegisProtectedPrimitives.shake256_32_segments(&[prekey, &ciphertext_hash])
}

fn decrypt_capsule_with_recovery(
    envelope: &impl ProtectedPayloadEnvelope,
    capsule: &ShareCapsule,
    record: &IngressKemKeyRecord,
    secret_key: &[u8],
    historical_pending: bool,
    kem: Option<&dyn synergy_aegis::AegisKem>,
) -> Result<ShamirShare, CapsuleVerificationFailure> {
    use CapsuleVerificationStage as Stage;
    envelope
        .validate_payload()
        .map_err(|error| CapsuleVerificationFailure::new(Stage::Envelope, error))?;
    validate_key(record, envelope.payload_aad().key_authorization_height())
        .map_err(|error| CapsuleVerificationFailure::new(Stage::RegistryKey, error))?;
    if capsule.validator_id != record.validator_id
        || capsule.ingress_kem_key_id != record.key_id
        || !envelope.capsules().contains(capsule)
    {
        return Err(CapsuleVerificationFailure::new(
            Stage::CapsuleBinding,
            invalid(),
        ));
    }
    verify_ingress_key_possession_using(record, secret_key, kem).map_err(|error| {
        let stage = if matches!(error, EtdagError::CryptoProvider(_)) {
            Stage::Provider
        } else {
            Stage::KeyPossession
        };
        CapsuleVerificationFailure::new(stage, error)
    })?;
    let ciphertext = mlkem1024::Ciphertext::from_bytes(&capsule.kem_ciphertext)
        .map_err(|_| CapsuleVerificationFailure::new(Stage::KemCiphertext, invalid()))?;
    let mut secret = SensitiveSecret(match kem {
        Some(kem) => kem
            .decapsulate(&capsule.kem_ciphertext, secret_key)
            .map_err(|error| {
                let error = kem_error(error);
                let stage = if matches!(error, EtdagError::CryptoProvider(_)) {
                    Stage::Provider
                } else {
                    Stage::KemCiphertext
                };
                CapsuleVerificationFailure::new(stage, error)
            })?,
        None => {
            let private = mlkem1024::SecretKey::from_bytes(secret_key)
                .map_err(|_| CapsuleVerificationFailure::new(Stage::SecretKey, invalid()))?;
            mlkem1024::decapsulate(&ciphertext, &private)
                .as_bytes()
                .to_vec()
        }
    });
    let context = capsule_context(
        &envelope
            .payload_aad()
            .canonical_payload_bytes()
            .map_err(|error| CapsuleVerificationFailure::new(Stage::Envelope, error))?,
        capsule,
    )
    .map_err(|error| CapsuleVerificationFailure::new(Stage::CapsuleContext, error))?;
    let mut wrapping = capsule_key(secret.as_slice(), &context);
    let mut decrypted = decrypt(
        &wrapping,
        &capsule.aead_nonce,
        &capsule.encrypted_share,
        &context,
    );
    wrapping.fill(0);
    if decrypted.is_err() && historical_pending {
        // Old runtime mislabeled Kyber as ML-KEM. Its valid ciphertext yields
        // the same prekey, then hashes prekey || H(ciphertext) using SHAKE256.
        // A malformed ciphertext still faces authenticated decryption and the
        // original share commitment below; implicit rejection cannot authorize it.
        let mut legacy = historical_kyber_secret(secret.as_slice(), &capsule.kem_ciphertext);
        let mut wrapping = capsule_key(&legacy, &context);
        legacy.fill(0);
        decrypted = decrypt(
            &wrapping,
            &capsule.aead_nonce,
            &capsule.encrypted_share,
            &context,
        );
        wrapping.fill(0);
    }
    secret.fill(0);
    let mut bytes =
        decrypted.map_err(|error| CapsuleVerificationFailure::new(Stage::CapsuleAead, error))?;
    let parsed = ShamirShare::from_canonical_bytes(&bytes);
    bytes.fill(0);
    let mut share =
        parsed.map_err(|error| CapsuleVerificationFailure::new(Stage::ShareEncoding, error))?;
    if share.index != capsule.share_index
        || share
            .commitment(
                &capsule.validator_id,
                envelope.payload_aad().share_context_root(),
                envelope.payload_aad().key_authorization_height(),
            )
            .map_err(|error| CapsuleVerificationFailure::new(Stage::ShareCommitment, error))?
            != capsule.share_commitment
    {
        share.value.fill(0);
        return Err(CapsuleVerificationFailure::new(
            Stage::ShareCommitment,
            invalid(),
        ));
    }
    Ok(share)
}

pub fn decrypt_protected_payload(
    envelope: &impl ProtectedPayloadEnvelope,
    shares: &[(String, ShamirShare)],
    member_count: usize,
    count_quorum: usize,
) -> Result<Vec<u8>, EtdagError> {
    envelope.validate_payload()?;
    let threshold = governed_reveal_threshold(member_count, count_quorum)?;
    if envelope.capsules().len() != member_count || shares.len() > member_count {
        return Err(invalid());
    }
    let mut validators = BTreeSet::new();
    let mut plain_shares = Vec::with_capacity(shares.len());
    for (validator, share) in shares {
        if !validators.insert(validator) {
            return Err(invalid());
        }
        let capsule = envelope
            .capsules()
            .iter()
            .find(|c| &c.validator_id == validator)
            .ok_or_else(invalid)?;
        if capsule.share_index != share.index
            || share.commitment(
                validator,
                envelope.payload_aad().share_context_root(),
                envelope.payload_aad().key_authorization_height(),
            )? != capsule.share_commitment
        {
            return Err(invalid());
        }
        plain_shares.push(share.clone());
    }
    let reconstructed = reconstruct(&plain_shares, threshold);
    for share in &mut plain_shares {
        share.value.fill(0);
    }
    let mut key = reconstructed?;
    let result = (|| {
        let aad = envelope.payload_aad().canonical_payload_bytes()?;
        if key_commitment(&key, &aad) != *envelope.payload_key_commitment() {
            return Err(invalid());
        }
        decrypt(
            &key,
            envelope.payload_nonce(),
            envelope.encrypted_payload(),
            &aad,
        )
    })();
    key.fill(0);
    result
}

/// Checks custody key purpose and public/private pairing without releasing data.
pub fn verify_ingress_key_possession(
    record: &IngressKemKeyRecord,
    secret_key: &[u8],
) -> Result<(), EtdagError> {
    verify_ingress_key_possession_using(record, secret_key, None)
}

pub fn verify_ingress_key_possession_with_kem(
    record: &IngressKemKeyRecord,
    secret_key: &[u8],
    kem: &dyn synergy_aegis::AegisKem,
) -> Result<(), EtdagError> {
    verify_ingress_key_possession_using(record, secret_key, Some(kem))
}
fn verify_ingress_key_possession_using(
    record: &IngressKemKeyRecord,
    secret_key: &[u8],
    kem: Option<&dyn synergy_aegis::AegisKem>,
) -> Result<(), EtdagError> {
    if kem.is_none() && !cfg!(test) {
        return Err(EtdagError::CryptoProvider("explicit authenticated APQE KEM required; embedded possession/decapsulation is forbidden".into()));
    }
    if let Some(kem) = kem {
        validate_key(record, record.activation_height)?;
        if kem.algorithm() != ML_KEM_1024_ALGORITHM {
            return Err(invalid());
        }
        let mut challenge = kem
            .encapsulate(&record.public_key.public_key)
            .map_err(kem_error)?;
        let mut secret = SensitiveSecret(std::mem::take(&mut challenge.shared_secret));
        let mut opened = kem
            .decapsulate(&challenge.ciphertext, secret_key)
            .map_err(kem_error)?;
        let matches = opened == secret.as_slice();
        opened.fill(0);
        secret.fill(0);
        return if matches { Ok(()) } else { Err(invalid()) };
    }
    validate_key(record, record.activation_height)?;
    let public =
        mlkem1024::PublicKey::from_bytes(&record.public_key.public_key).map_err(|_| invalid())?;
    let private = mlkem1024::SecretKey::from_bytes(secret_key).map_err(|_| invalid())?;
    let (challenge, ciphertext) = mlkem1024::encapsulate(&public);
    if mlkem1024::decapsulate(&ciphertext, &private).as_bytes() != challenge.as_bytes() {
        return Err(invalid());
    }
    Ok(())
}

pub struct GovernedThresholdDecryptor {
    member_count: usize,
    count_quorum: usize,
}
impl GovernedThresholdDecryptor {
    pub fn new(member_count: usize, count_quorum: usize) -> Result<Self, EtdagError> {
        governed_reveal_threshold(member_count, count_quorum)?;
        Ok(Self {
            member_count,
            count_quorum,
        })
    }
}
impl crate::reveal::ThresholdDecryptor for GovernedThresholdDecryptor {
    fn decrypt(
        &self,
        envelope: &EncryptedTransactionEnvelope,
        verified: &[crate::reveal::VerifiedDecryptShare],
    ) -> Result<Vec<u8>, EtdagError> {
        let mut shares = Vec::with_capacity(verified.len());
        for share in verified {
            if share.envelope_id() != &envelope.envelope_id
                || share.authorization().context_root != envelope.target_context_root
                || share.authorization().target_height != envelope.target_height
            {
                return Err(invalid());
            }
            let decoded = ShamirShare::from_canonical_bytes(share.encrypted_share())?;
            let capsule = envelope
                .share_capsules
                .iter()
                .find(|c| c.validator_id == share.validator_id())
                .ok_or_else(invalid)?;
            if capsule.ingress_kem_key_id != share.ingress_kem_key_id()
                || decoded.index != share.share_index()
                || capsule.share_index != decoded.index
                || &capsule.share_commitment != share.share_commitment()
            {
                return Err(invalid());
            }
            shares.push((share.validator_id().to_owned(), decoded));
        }
        let result =
            decrypt_protected_payload(envelope, &shares, self.member_count, self.count_quorum);
        for (_, share) in &mut shares {
            share.value.fill(0);
        }
        let mut padded = result?;
        let plaintext = super::unpad_plaintext(&padded);
        padded.fill(0);
        plaintext
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::IngressKemPublicKey;
    #[test]
    fn apqe_primitives_preserve_protected_wire_bytes_and_reject_tampering() {
        use aes_gcm::{
            aead::{Aead, KeyInit, Payload},
            Aes256Gcm, Nonce,
        };
        use sha3::digest::{ExtendableOutput, XofReader};
        use sha3::{Digest, Sha3_256, Sha3_512};
        let key = [0x23; 32];
        let nonce = [0x42; 12];
        for (bytes, aad) in [
            (b"".as_slice(), b"".as_slice()),
            (
                b"protected canonical transaction".as_slice(),
                b"chain1266/context".as_slice(),
            ),
        ] {
            let cipher = Aes256Gcm::new_from_slice(&key).unwrap();
            let old = cipher
                .encrypt(Nonce::from_slice(&nonce), Payload { msg: bytes, aad })
                .unwrap();
            assert_eq!(encrypt(&key, &nonce, bytes, aad).unwrap(), old);
            assert_eq!(decrypt(&key, &nonce, &old, aad).unwrap(), bytes);
            assert_eq!(
                cipher
                    .decrypt(
                        Nonce::from_slice(&nonce),
                        Payload {
                            msg: &encrypt(&key, &nonce, bytes, aad).unwrap(),
                            aad
                        }
                    )
                    .unwrap(),
                bytes
            );
            for index in [0, old.len() - 1] {
                let mut corrupt = old.clone();
                corrupt[index] ^= 1;
                assert!(decrypt(&key, &nonce, &corrupt, aad).is_err());
            }
            assert!(decrypt(&key, &nonce, &old, b"wrong context").is_err());
            assert!(decrypt(&[0; 32], &nonce, &old, aad).is_err());
            assert!(decrypt(&key, &[0; 12], &old, aad).is_err());
            assert!(decrypt(&key, &nonce, &old[..old.len() - 1], aad).is_err());
            let mut legacy = Sha3_512::new();
            Digest::update(&mut legacy, b"PoSy/ETDAG/CapsuleKey/v3");
            Digest::update(&mut legacy, (key.len() as u64).to_be_bytes());
            Digest::update(&mut legacy, key);
            Digest::update(&mut legacy, (aad.len() as u64).to_be_bytes());
            Digest::update(&mut legacy, aad);
            assert_eq!(&capsule_key(&key, aad)[..], &legacy.finalize()[..32]);
            let mut legacy = sha3::Shake256::default();
            sha3::digest::Update::update(&mut legacy, &key);
            sha3::digest::Update::update(&mut legacy, &Sha3_256::digest(&old));
            let mut expected = [0; 32];
            legacy.finalize_xof().read(&mut expected);
            assert_eq!(historical_kyber_secret(&key, &old), expected);
            let domain = "PoSy/ETDAG/KeyCommitment/v3";
            let payload = [key.as_slice(), aad].concat();
            let framed = [
                &(domain.len() as u64).to_be_bytes()[..],
                domain.as_bytes(),
                &(payload.len() as u64).to_be_bytes()[..],
                &payload,
            ]
            .concat();
            assert_eq!(
                key_commitment(&key, aad).0,
                format!("{:x}", Sha3_512::digest(&framed))
            );
        }
    }
    fn digest(label: &str) -> EtdagDigest {
        EtdagDigest::from_domain_bytes("test", label.as_bytes())
    }
    #[test]
    fn processing_payload_uses_immutable_context_without_an_inclusion_height() {
        qualify_processing_payload(None);
    }
    #[test]
    #[ignore = "requires explicitly authenticated immutable APQE native artifacts"]
    fn native_apqe_kem_preserves_fips_and_historical_pending_only_recovery() {
        let report = std::env::var("APQE_TRUSTED_NATIVE_REPORT").expect("explicit trusted report");
        let digest =
            std::env::var("APQE_AUTHENTICATED_REPORT_SHA256").expect("authenticated digest");
        assert_eq!(digest.len(), 64);
        let mut hash = [0; 32];
        for (i, b) in hash.iter_mut().enumerate() {
            *b = u8::from_str_radix(&digest[2 * i..2 * i + 2], 16).unwrap();
        }
        // Explicit isolated-test operator authenticates/protects these native artifacts.
        let engine = unsafe {
            synergy_address_engine::apqe::native_manifest::validator_engine(
                std::path::Path::new(&report),
                hash,
            )
        }
        .unwrap();
        let kem =
            synergy_aegis::ApqeKem::mlkem1024(std::sync::Arc::new(std::sync::Mutex::new(engine)))
                .unwrap();
        qualify_processing_payload(Some(&kem));
    }
    fn qualify_processing_payload(kem: Option<&dyn synergy_aegis::AegisKem>) {
        use crate::admission::{ProcessingEnvelope, ProcessingEnvelopeAad};
        let aad = ProcessingEnvelopeAad {
            profile_id: "etdag-async-processing-v1".into(),
            chain_id: 1266,
            network_id: "async-isolated".into(),
            protocol_version: "posy/3.0".into(),
            epoch: 1,
            processing_context_root: digest("processing-authority"),
            authorization_height: 5,
            assigned_cluster_id: 1,
            lane_id: "ordinary-user".into(),
            sender_id: "sender".into(),
            nonce_slot: 0,
        };
        let mut records = Vec::new();
        let mut secrets = Vec::new();
        for i in 1..=5 {
            let (public, secret) = mlkem1024::keypair();
            records.push(IngressKemKeyRecord {
                key_id: format!("async-ingress-{i}"),
                validator_id: format!("val{i}"),
                public_key: IngressKemPublicKey {
                    algorithm: ML_KEM_1024_ALGORITHM.into(),
                    public_key: public.as_bytes().to_vec(),
                },
                activation_height: 1,
                // Key selection is pinned at authorization, not recomputed at
                // the later inclusion block. Lifecycle retirement is external.
                retirement_height: Some(8),
            });
            secrets.push(secret);
        }
        let plaintext = super::super::pad_plaintext(b"async encrypted transaction").unwrap();
        assert_eq!(
            aad.validate_encryption_input(&records, usize::MAX),
            Err(EtdagError::InvalidCapacity)
        );
        assert!(encrypt_protected_payload(&aad, &records, 4, &vec![0; 131_072]).is_err());
        assert!(encrypt_protected_payload(&aad, &records, 4, b"unpadded").is_err());
        let mut invalid_records = records.clone();
        invalid_records[0].validator_id = "v".repeat(257);
        assert!(encrypt_protected_payload(&aad, &invalid_records, 4, &plaintext).is_err());
        invalid_records = records.clone();
        invalid_records[0].key_id = "k".repeat(257);
        assert!(encrypt_protected_payload(&aad, &invalid_records, 4, &plaintext).is_err());
        let payload = match kem {
            Some(kem) => encrypt_protected_payload_with_kem(&aad, &records, 4, &plaintext, kem),
            None => encrypt_protected_payload(&aad, &records, 4, &plaintext),
        }
        .unwrap();
        let mut envelope = ProcessingEnvelope {
            envelope_version: 1,
            envelope_id: digest("pending"),
            aad,
            aead_nonce: payload.aead_nonce,
            key_commitment: payload.key_commitment,
            share_commitment_root: digest("pending"),
            share_capsule_root: digest("pending"),
            ciphertext: payload.ciphertext,
            content_blind_order_key: digest("order"),
            share_capsules: payload.share_capsules,
        };
        envelope.refresh_capsule_roots().unwrap();
        envelope.envelope_id = envelope.commitment().unwrap();
        struct MissingProvider;
        impl synergy_aegis::AegisKem for MissingProvider {
            fn algorithm(&self) -> &'static str {
                ML_KEM_1024_ALGORITHM
            }
            fn encapsulate(
                &self,
                _: &[u8],
            ) -> Result<synergy_aegis::KemEncapsulation, synergy_aegis::KemError> {
                Err(synergy_aegis::KemError::ProviderUnavailable)
            }
            fn decapsulate(&self, _: &[u8], _: &[u8]) -> Result<Vec<u8>, synergy_aegis::KemError> {
                Err(synergy_aegis::KemError::ProviderUnavailable)
            }
        }
        let failure = decrypt_share_capsule_with_kem_diagnostic(
            &envelope,
            &envelope.share_capsules[0],
            &records[0],
            secrets[0].as_bytes(),
            false,
            &MissingProvider,
        )
        .unwrap_err();
        assert_eq!(failure.stage, CapsuleVerificationStage::Provider);
        assert!(matches!(
            failure.into_error(),
            EtdagError::CryptoProvider(_)
        ));
        envelope.validate().unwrap();
        // A KEM owner may hold nonexportable custody. Capsule verification must
        // never parse an embedded private key before invoking that owner.
        if let Some(kem) = kem {
            struct Opaque<'a> {
                provider: &'a dyn synergy_aegis::AegisKem,
                secret: &'a [u8],
            }
            impl synergy_aegis::AegisKem for Opaque<'_> {
                fn algorithm(&self) -> &'static str {
                    ML_KEM_1024_ALGORITHM
                }
                fn encapsulate(
                    &self,
                    public: &[u8],
                ) -> Result<synergy_aegis::KemEncapsulation, synergy_aegis::KemError>
                {
                    self.provider.encapsulate(public)
                }
                fn decapsulate(
                    &self,
                    ciphertext: &[u8],
                    supplied: &[u8],
                ) -> Result<Vec<u8>, synergy_aegis::KemError> {
                    if !supplied.is_empty() {
                        return Err(synergy_aegis::KemError::InvalidSecretKey);
                    }
                    self.provider.decapsulate(ciphertext, self.secret)
                }
            }
            let opaque = Opaque {
                provider: kem,
                secret: secrets[0].as_bytes(),
            };
            let mut share = decrypt_share_capsule_with_kem_diagnostic(
                &envelope,
                &envelope.share_capsules[0],
                &records[0],
                &[],
                false,
                &opaque,
            )
            .unwrap();
            assert_eq!(share.index, envelope.share_capsules[0].share_index);
            share.value.fill(0);
            let mut wrong = records[0].clone();
            wrong.public_key = records[1].public_key.clone();
            assert!(decrypt_share_capsule_with_kem_diagnostic(
                &envelope,
                &envelope.share_capsules[0],
                &wrong,
                &[],
                false,
                &opaque
            )
            .is_err());
        }
        if let Some(kem) = kem {
            let mut share = decrypt_share_capsule_with_kem_diagnostic(
                &envelope,
                &envelope.share_capsules[0],
                &records[0],
                secrets[0].as_bytes(),
                false,
                kem,
            )
            .unwrap();
            assert_eq!(share.index, envelope.share_capsules[0].share_index);
            share.value.fill(0);
        }
        let original = serde_json::to_vec(&envelope).unwrap();
        // Historical Kyber used the identical PKE ciphertext/key encoding but
        // a different shared-secret KDF. New ingress must reject that wrapping;
        // authenticated historical pending recovery may accept it, unchanged.
        let mut legacy = envelope.clone();
        let capsule = &legacy.share_capsules[0];
        let ct = mlkem1024::Ciphertext::from_bytes(&capsule.kem_ciphertext).unwrap();
        let ss = mlkem1024::decapsulate(&ct, &secrets[0]);
        let context =
            capsule_context(&legacy.aad.canonical_payload_bytes().unwrap(), capsule).unwrap();
        let mut wrapping = capsule_key(ss.as_bytes(), &context);
        let mut share_bytes = decrypt(
            &wrapping,
            &capsule.aead_nonce,
            &capsule.encrypted_share,
            &context,
        )
        .unwrap();
        wrapping.fill(0);
        let mut old_secret = historical_kyber_secret(ss.as_bytes(), &capsule.kem_ciphertext);
        let mut old_wrap = capsule_key(&old_secret, &context);
        old_secret.fill(0);
        legacy.share_capsules[0].encrypted_share =
            encrypt(&old_wrap, &capsule.aead_nonce, &share_bytes, &context).unwrap();
        old_wrap.fill(0);
        share_bytes.fill(0);
        legacy.refresh_capsule_roots().unwrap();
        legacy.envelope_id = legacy.commitment().unwrap();
        let legacy_bytes = serde_json::to_vec(&legacy).unwrap();
        for restored in [
            legacy.clone(),
            serde_json::from_slice(&legacy_bytes).unwrap(),
        ] {
            assert_eq!(
                decrypt_share_capsule_diagnostic(
                    &restored,
                    &restored.share_capsules[0],
                    &records[0],
                    secrets[0].as_bytes()
                )
                .unwrap_err()
                .stage,
                CapsuleVerificationStage::CapsuleAead
            );
            if let Some(kem) = kem {
                assert_eq!(
                    decrypt_share_capsule_with_kem_diagnostic(
                        &restored,
                        &restored.share_capsules[0],
                        &records[0],
                        secrets[0].as_bytes(),
                        false,
                        kem
                    )
                    .unwrap_err()
                    .stage,
                    CapsuleVerificationStage::CapsuleAead
                );
                let mut share = decrypt_share_capsule_with_kem_diagnostic(
                    &restored,
                    &restored.share_capsules[0],
                    &records[0],
                    secrets[0].as_bytes(),
                    true,
                    kem,
                )
                .unwrap();
                assert_eq!(share.index, restored.share_capsules[0].share_index);
                share.value.fill(0);
            }
            let mut recovered = decrypt_historical_share_capsule_diagnostic(
                &restored,
                &restored.share_capsules[0],
                &records[0],
                secrets[0].as_bytes(),
            )
            .unwrap();
            assert_eq!(recovered.index, restored.share_capsules[0].share_index);
            recovered.value.fill(0);
        }
        assert_eq!(legacy_bytes, serde_json::to_vec(&legacy).unwrap());
        for corrupt_ciphertext in [false, true] {
            let mut invalid_legacy = legacy.clone();
            if corrupt_ciphertext {
                invalid_legacy.share_capsules[0].kem_ciphertext[0] ^= 1;
            } else {
                invalid_legacy.share_capsules[0].encrypted_share[0] ^= 1;
            }
            invalid_legacy.refresh_capsule_roots().unwrap();
            invalid_legacy.envelope_id = invalid_legacy.commitment().unwrap();
            assert_eq!(
                decrypt_historical_share_capsule_diagnostic(
                    &invalid_legacy,
                    &invalid_legacy.share_capsules[0],
                    &records[0],
                    secrets[0].as_bytes()
                )
                .unwrap_err()
                .stage,
                CapsuleVerificationStage::CapsuleAead
            );
        }
        // Exact mobile failure class: structurally valid, immutable envelope
        // with a corrupted wrapped share. Persistence/recovery must reject the
        // same capsule and must never return an authorized share.
        let mut malformed = envelope.clone();
        malformed.share_capsules[0].encrypted_share[0] ^= 1;
        malformed.refresh_capsule_roots().unwrap();
        malformed.envelope_id = malformed.commitment().unwrap();
        malformed.validate().unwrap();
        let encoded_bad = serde_json::to_vec(&malformed).unwrap();
        for restored in [malformed, serde_json::from_slice(&encoded_bad).unwrap()] {
            assert_eq!(
                decrypt_share_capsule_diagnostic(
                    &restored,
                    &restored.share_capsules[0],
                    &records[0],
                    secrets[0].as_bytes()
                )
                .unwrap_err()
                .stage,
                CapsuleVerificationStage::CapsuleAead,
            );
            assert_eq!(
                decrypt_share_capsule(
                    &restored,
                    &restored.share_capsules[0],
                    &records[0],
                    secrets[0].as_bytes()
                ),
                Err(EtdagError::UnauthorizedReveal),
            );
            assert_eq!(serde_json::to_vec(&restored).unwrap(), encoded_bad);
        }
        assert_eq!(
            decrypt_share_capsule_diagnostic(
                &envelope,
                &envelope.share_capsules[0],
                &records[0],
                secrets[1].as_bytes()
            )
            .unwrap_err()
            .stage,
            CapsuleVerificationStage::KeyPossession,
        );
        let mut shares = Vec::new();
        for i in 0..2 {
            let capsule = &envelope.share_capsules[i];
            shares.push((
                capsule.validator_id.clone(),
                decrypt_share_capsule(&envelope, capsule, &records[i], secrets[i].as_bytes())
                    .unwrap(),
            ));
        }
        assert_eq!(
            decrypt_protected_payload(&envelope, &shares, 5, 4).unwrap(),
            plaintext
        );
        assert!(decrypt_protected_payload(&envelope, &shares[..1], 5, 4).is_err());
        // Reconstructing from the durable wire object keeps the same original
        // authorization. There is deliberately no inclusion-height argument.
        let recovered: ProcessingEnvelope = serde_json::from_slice(&original).unwrap();
        assert_eq!(
            decrypt_protected_payload(&recovered, &shares, 5, 4).unwrap(),
            plaintext
        );
        assert_eq!(serde_json::to_vec(&recovered).unwrap(), original);
        assert!(serde_json::from_slice::<EncryptedTransactionEnvelope>(&original).is_err());

        let mut rebound = recovered.clone();
        rebound.aad.nonce_slot += 1;
        rebound.envelope_id = rebound.commitment().unwrap();
        rebound.validate().unwrap();
        assert!(decrypt_protected_payload(&rebound, &shares, 5, 4).is_err());
        let mut wrong_context = recovered.clone();
        wrong_context.aad.processing_context_root = digest("other-authority");
        wrong_context.envelope_id = wrong_context.commitment().unwrap();
        assert!(decrypt_protected_payload(&wrong_context, &shares, 5, 4).is_err());
        let mut expired_anchor = recovered.clone();
        expired_anchor.aad.authorization_height = 8;
        expired_anchor.envelope_id = expired_anchor.commitment().unwrap();
        assert!(decrypt_share_capsule(
            &expired_anchor,
            &expired_anchor.share_capsules[0],
            &records[0],
            secrets[0].as_bytes()
        )
        .is_err());
        for (_, share) in &mut shares {
            share.value.fill(0);
        }
    }

    #[test]
    fn real_mlkem_two_of_five_roundtrip_and_exact_binding_failures() {
        let aad = EnvelopeAad {
            profile_id: crate::ETDAG_PROFILE_ID.into(),
            chain_id: 1266,
            network_id: "test".into(),
            protocol_version: "v3".into(),
            epoch: 1,
            target_height: 5,
            target_context_root: digest("context"),
            assigned_cluster_id: 1,
            lane_id: "ordinary-user".into(),
            sender_id: "sender".into(),
            nonce_slot: 0,
        };
        let mut records = Vec::new();
        let mut secrets = Vec::new();
        for i in 1..=5 {
            let (pk, sk) = mlkem1024::keypair();
            records.push(IngressKemKeyRecord {
                key_id: format!("ingress-{i}"),
                validator_id: format!("val{i}"),
                public_key: IngressKemPublicKey {
                    algorithm: ML_KEM_1024_ALGORITHM.into(),
                    public_key: pk.as_bytes().to_vec(),
                },
                activation_height: 1,
                retirement_height: None,
            });
            secrets.push(sk);
        }
        assert_eq!(records[0].public_key.public_key.len(), 1568);
        let plaintext = super::super::pad_plaintext(b"governed protected payload").unwrap();
        let payload = encrypt_protected_payload(&aad, &records, 4, &plaintext).unwrap();
        let mut envelope = EncryptedTransactionEnvelope {
            envelope_version: 2,
            envelope_id: digest("envelope"),
            target_context_root: aad.target_context_root.clone(),
            target_height: 5,
            aad,
            aead_nonce: payload.aead_nonce,
            key_commitment: payload.key_commitment,
            share_commitment_root: digest("pending"),
            share_capsule_root: digest("pending"),
            ciphertext: payload.ciphertext,
            content_blind_order_key: digest("order"),
            share_capsules: payload.share_capsules,
        };
        envelope.refresh_capsule_roots().unwrap();
        envelope.validate().unwrap();
        assert!(crate::CIPHERTEXT_SIZE_CLASSES.contains(&envelope.ciphertext.len()));
        let shares: Vec<_> = envelope
            .share_capsules
            .iter()
            .enumerate()
            .map(|(i, c)| {
                (
                    c.validator_id.clone(),
                    decrypt_share_capsule(&envelope, c, &records[i], secrets[i].as_bytes())
                        .unwrap(),
                )
            })
            .collect();
        for i in 0..5 {
            for j in i + 1..5 {
                assert_eq!(
                    decrypt_protected_payload(
                        &envelope,
                        &[shares[i].clone(), shares[j].clone()],
                        5,
                        4
                    )
                    .unwrap(),
                    plaintext
                );
            }
        }
        assert!(decrypt_protected_payload(&envelope, &shares[..1], 5, 4).is_err());
        let mut duplicate = shares[..2].to_vec();
        duplicate.push(shares[0].clone());
        assert!(decrypt_protected_payload(&envelope, &duplicate, 5, 4).is_err());
        let mut wrong_key = records[0].clone();
        wrong_key.public_key = records[1].public_key.clone();
        assert!(decrypt_share_capsule(
            &envelope,
            &envelope.share_capsules[0],
            &wrong_key,
            secrets[0].as_bytes()
        )
        .is_err());
        let mut wrong_purpose = records[0].clone();
        wrong_purpose.public_key.algorithm = "ML-KEM-768".into();
        assert!(decrypt_share_capsule(
            &envelope,
            &envelope.share_capsules[0],
            &wrong_purpose,
            secrets[0].as_bytes()
        )
        .is_err());
        let mut wrong_context = envelope.clone();
        wrong_context.target_context_root = digest("other-context");
        wrong_context.aad.target_context_root = wrong_context.target_context_root.clone();
        assert!(decrypt_protected_payload(&wrong_context, &shares[..2], 5, 4).is_err());
        assert!(decrypt_share_capsule(
            &wrong_context,
            &wrong_context.share_capsules[0],
            &records[0],
            secrets[0].as_bytes()
        )
        .is_err());
        let mut wrong_commitment = envelope.clone();
        wrong_commitment.key_commitment = digest("wrong-key");
        assert!(decrypt_protected_payload(&wrong_commitment, &shares[..2], 5, 4).is_err());
        let mut duplicate_recipient = records.clone();
        duplicate_recipient[1] = duplicate_recipient[0].clone();
        assert!(
            encrypt_protected_payload(&envelope.aad, &duplicate_recipient, 4, &plaintext).is_err()
        );
        envelope.aead_nonce[0] ^= 1;
        assert!(decrypt_protected_payload(&envelope, &shares[..2], 5, 4).is_err());
        envelope.aead_nonce[0] ^= 1;
        envelope.share_capsules[0].encrypted_share[0] ^= 1;
        envelope.refresh_capsule_roots().unwrap();
        assert!(decrypt_share_capsule(
            &envelope,
            &envelope.share_capsules[0],
            &records[0],
            secrets[0].as_bytes()
        )
        .is_err());
    }
    #[test]
    fn gf256_legacy_vector_and_duplicate_tail_rejected() {
        assert_eq!(mul(0x57, 0x13), 0xfe);
        let secret = [42; 32];
        let shares = split(&secret, 2, 5).unwrap();
        assert_eq!(reconstruct(&shares[2..4], 2).unwrap(), secret);
        let mut duplicate = shares[..2].to_vec();
        duplicate.push(shares[0].clone());
        assert!(reconstruct(&duplicate, 2).is_err());
    }
}
