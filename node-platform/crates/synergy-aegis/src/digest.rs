//! Canonical Aegis digest-provider boundary.
use synergy_address_engine::apqe::{HashAlgorithm, Primitives};

pub trait AegisDigest: Send + Sync {
    fn digest(&self, domain: &[u8], message: &[u8]) -> Result<[u8; 32], DigestError>;
}

#[derive(Debug, Clone, Copy, Default)]
pub struct AegisSha3_256;

impl AegisDigest for AegisSha3_256 {
    fn digest(&self, domain: &[u8], message: &[u8]) -> Result<[u8; 32], DigestError> {
        if domain.is_empty() || domain.len() > 1024 {
            return Err(DigestError::InvalidDomain);
        }
        self.sha3_256_segments(&[
            &(domain.len() as u64).to_be_bytes(),
            domain,
            &(message.len() as u64).to_be_bytes(),
            message,
        ])
    }
}

/// Primitive hash provider for versioned protocols whose existing transcript
/// framing must remain byte-for-byte stable during caller migration.
pub trait AegisHashEngine: Send + Sync {
    fn sha3_256_segments(&self, segments: &[&[u8]]) -> Result<[u8; 32], DigestError>;
    fn sha3_512_segments(&self, segments: &[&[u8]]) -> Result<[u8; 64], DigestError>;
}

impl AegisHashEngine for AegisSha3_256 {
    fn sha3_256_segments(&self, segments: &[&[u8]]) -> Result<[u8; 32], DigestError> {
        let mut hasher = Primitives
            .hash_stream(HashAlgorithm::Sha3256)
            .map_err(|_| DigestError::ProviderUnavailable)?;
        for segment in segments {
            hasher.update(segment);
        }
        hasher
            .finalize()
            .try_into()
            .map_err(|_| DigestError::ProviderUnavailable)
    }

    fn sha3_512_segments(&self, segments: &[&[u8]]) -> Result<[u8; 64], DigestError> {
        let mut hasher = Primitives
            .hash_stream(HashAlgorithm::Sha3512)
            .map_err(|_| DigestError::ProviderUnavailable)?;
        for segment in segments {
            hasher.update(segment);
        }
        hasher
            .finalize()
            .try_into()
            .map_err(|_| DigestError::ProviderUnavailable)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DigestError {
    InvalidDomain,
    ProviderUnavailable,
}

#[cfg(test)]
mod apqe_hash_tests {
    use super::*;
    use sha3::{Digest, Sha3_256, Sha3_512};
    #[test]
    fn apqe_hashing_preserves_consensus_framing_and_segment_bytes() {
        for segments in [
            vec![],
            vec![b"".as_slice()],
            vec![b"ab".as_slice(), b"c".as_slice()],
            vec![b"a".as_slice(), b"bc".as_slice()],
        ] {
            let joined = segments.concat();
            assert_eq!(
                AegisSha3_256
                    .sha3_256_segments(&segments)
                    .unwrap()
                    .as_slice(),
                Sha3_256::digest(&joined).as_slice()
            );
            assert_eq!(
                AegisSha3_256
                    .sha3_512_segments(&segments)
                    .unwrap()
                    .as_slice(),
                Sha3_512::digest(&joined).as_slice()
            );
        }
        let domain = b"SYNERGY-CONSENSUS-HASH-V1";
        let message = b"unaltered";
        let framed = [
            &(domain.len() as u64).to_be_bytes()[..],
            &domain[..],
            &(message.len() as u64).to_be_bytes()[..],
            &message[..],
        ]
        .concat();
        assert_eq!(
            AegisSha3_256.digest(domain, message).unwrap().as_slice(),
            Sha3_256::digest(&framed).as_slice()
        );
        assert_eq!(
            AegisSha3_256.digest(b"", message),
            Err(DigestError::InvalidDomain)
        );
    }
}
