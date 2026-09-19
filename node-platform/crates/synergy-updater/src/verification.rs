use sha3::{Digest, Sha3_256};
use synergy_aegis::{AegisVerifier, SigningContext};

use crate::{discovery::release_is_newer, SignedReleaseMetadata};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedRelease {
    pub signed: SignedReleaseMetadata,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerificationError {
    InvalidMetadata,
    NonMonotonicSequence,
    InvalidEncoding,
    InvalidSignature,
    ArtifactLength,
    ArtifactDigest,
}

pub fn verify_release(
    verifier: &dyn AegisVerifier,
    chain_id: u64,
    installed_sequence: u64,
    signed: SignedReleaseMetadata,
    artifact: &[u8],
) -> Result<VerifiedRelease, VerificationError> {
    signed
        .release
        .validate()
        .map_err(|_| VerificationError::InvalidMetadata)?;
    if !release_is_newer(&signed.release, installed_sequence) {
        return Err(VerificationError::NonMonotonicSequence);
    }
    if signed.release.artifact.length != artifact.len() as u64 {
        return Err(VerificationError::ArtifactLength);
    }
    let digest = hex_digest(Sha3_256::digest(artifact).as_slice());
    if digest != signed.release.artifact.sha3_256.to_ascii_lowercase() {
        return Err(VerificationError::ArtifactDigest);
    }
    let bytes = signed
        .release
        .signing_bytes()
        .map_err(|_| VerificationError::InvalidEncoding)?;
    verifier
        .verify(
            &SigningContext {
                domain: "synergy.software.release.v1".into(),
                chain_id,
                epoch: None,
                height: None,
            },
            &bytes,
            &signed.signature,
            &signed.public_key,
        )
        .map_err(|_| VerificationError::InvalidSignature)?;
    Ok(VerifiedRelease { signed })
}

fn hex_digest(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut result = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        result.push(HEX[(byte >> 4) as usize] as char);
        result.push(HEX[(byte & 0x0f) as usize] as char);
    }
    result
}
