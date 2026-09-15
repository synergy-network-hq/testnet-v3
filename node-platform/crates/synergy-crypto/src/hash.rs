use serde::{Deserialize, Serialize};
use synergy_aegis::{AegisDigest, AegisHashEngine};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Hash32(pub [u8; 32]);

pub fn sha3_256(
    provider: &impl AegisDigest,
    domain: &crate::CryptoDomain,
    message: &[u8],
) -> Result<Hash32, String> {
    let prefix = domain.canonical_prefix()?;
    provider
        .digest(&prefix, message)
        .map(Hash32)
        .map_err(|error| format!("Aegis digest provider failed: {error:?}"))
}

pub fn sha3_256_segments(
    provider: &impl AegisHashEngine,
    segments: &[&[u8]],
) -> Result<Hash32, String> {
    provider
        .sha3_256_segments(segments)
        .map(Hash32)
        .map_err(|error| format!("Aegis hash engine failed: {error:?}"))
}

pub fn sha3_512_segments(
    provider: &impl AegisHashEngine,
    segments: &[&[u8]],
) -> Result<[u8; 64], String> {
    provider
        .sha3_512_segments(segments)
        .map_err(|error| format!("Aegis hash engine failed: {error:?}"))
}
