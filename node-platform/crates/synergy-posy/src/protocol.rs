use serde::Serialize;

use crate::{PosyError, PosyResult, ValidatorRecord};

pub const POSY_SIMPLIFIED_PROTOCOL_VERSION: &str = "posy/3.0";
pub const POSY_SIMPLIFIED_PROPOSAL_DOMAIN: &str = "PoSy/Consensus/v3/Proposal";
pub const POSY_SIMPLIFIED_BLOCK_VOTE_DOMAIN: &str = "PoSy/Consensus/v3/BlockVote";
pub const POSY_SIMPLIFIED_TIMEOUT_VOTE_DOMAIN: &str = "PoSy/Consensus/v3/TimeoutVote";

pub type ValidatorId = String;
pub type KeyId = String;
pub type ConsensusHash = String;
pub type SignatureBytes = Vec<u8>;

/// Crypto adapters own signature algorithm details. The PoSy core owns only
/// the governed domain, transcript, frozen key binding, and epoch context.
pub trait ConsensusSignatureVerifier {
    fn verify_consensus_signature(
        &self,
        domain: &str,
        payload: &[u8],
        validator: &ValidatorRecord,
        key_id: &str,
        epoch: u64,
        signature: &[u8],
    ) -> PosyResult<()>;
}

pub fn require_nonempty(value: &str, name: &str) -> PosyResult<()> {
    if value.trim().is_empty() {
        Err(PosyError::invalid(format!("{name} is empty")))
    } else {
        Ok(())
    }
}

pub fn canonical_hash(domain: &str, value: &impl Serialize) -> PosyResult<ConsensusHash> {
    let bytes = serde_json::to_vec(value)
        .map_err(|error| PosyError::invalid(format!("serialize {domain}: {error}")))?;
    // Match runtime::synergy_types::Hash::from_domain_bytes exactly. The
    // canonical JSON value must still have the frozen runtime's field/types
    // before this digest is a wire-compatible commitment.
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain.as_bytes());
    hasher.update(&(domain.len() as u64).to_be_bytes());
    hasher.update(&bytes);
    Ok(hasher.finalize().to_hex().to_string())
}

pub fn is_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub fn parse_hash_bytes(value: &str) -> PosyResult<[u8; 32]> {
    if !is_hash(value) {
        return Err(PosyError::invalid("expected canonical 32-byte hash hex"));
    }
    let mut bytes = [0u8; 32];
    for (index, chunk) in value.as_bytes().chunks_exact(2).enumerate() {
        let hex = std::str::from_utf8(chunk).map_err(|_| PosyError::invalid("invalid hash hex"))?;
        bytes[index] =
            u8::from_str_radix(hex, 16).map_err(|_| PosyError::invalid("invalid hash hex"))?;
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_matches_frozen_domain_framing_and_width() {
        let value = ("validator-02", 1266u64);
        let domain = "SYNERGY_POSY_TEST_V1";
        let bytes = serde_json::to_vec(&value).unwrap();
        let mut legacy = blake3::Hasher::new();
        legacy.update(domain.as_bytes());
        legacy.update(&(domain.len() as u64).to_be_bytes());
        legacy.update(&bytes);
        let expected = legacy.finalize();
        assert_eq!(
            canonical_hash(domain, &value).unwrap(),
            expected.to_hex().as_str()
        );
        assert_eq!(
            parse_hash_bytes(&expected.to_hex()).unwrap(),
            *expected.as_bytes()
        );
        assert!(!is_hash(&"a".repeat(128)));
    }
}
