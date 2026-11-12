//! Bounded transport of exact candidate-response bytes. Chunk hashes provide
//! transport integrity only; reconstructed responses still require PoSy proof
//! and sequential execution verification.
use crate::FinalizedCandidateRequest;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};

pub const CANDIDATE_CHUNK_BYTES: usize = 64 * 1024;
pub const MAX_CANDIDATE_RESPONSE_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_CANDIDATE_WITNESS_BYTES: usize = 16 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CandidateResponseChunk {
    pub request: FinalizedCandidateRequest,
    pub total_bytes: usize,
    pub digest: [u8; 32],
    pub offset: usize,
    pub bytes: Vec<u8>,
}

pub fn candidate_response_digest(bytes: &[u8]) -> [u8; 32] {
    Sha3_256::digest(bytes).into()
}

impl CandidateResponseChunk {
    pub fn validate(&self) -> Result<(), String> {
        if !self.request.validate()
            || self.request.expected_parent_id.len() > 256
            || self.total_bytes == 0
            || self.total_bytes > MAX_CANDIDATE_RESPONSE_BYTES
            || self.offset >= self.total_bytes
            || !self.offset.is_multiple_of(CANDIDATE_CHUNK_BYTES)
            || self.bytes.len() != CANDIDATE_CHUNK_BYTES.min(self.total_bytes - self.offset)
        {
            return Err("invalid bounded candidate-response chunk".into());
        }
        Ok(())
    }
}

/// One assembly owns at most 64 MiB. The caller must bind its lifetime to one
/// exact authenticated peer/session/request and bound progress/absolute age.
pub struct CandidateResponseAssembly {
    request: FinalizedCandidateRequest,
    digest: [u8; 32],
    bytes: Vec<u8>,
    received: Vec<bool>,
    remaining: usize,
}
impl CandidateResponseAssembly {
    pub fn new(chunk: &CandidateResponseChunk) -> Result<Self, String> {
        chunk.validate()?;
        let count = chunk.total_bytes.div_ceil(CANDIDATE_CHUNK_BYTES);
        Ok(Self {
            request: chunk.request.clone(),
            digest: chunk.digest,
            bytes: vec![0; chunk.total_bytes],
            received: vec![false; count],
            remaining: count,
        })
    }
    pub fn push(&mut self, chunk: CandidateResponseChunk) -> Result<bool, String> {
        chunk.validate()?;
        if chunk.request != self.request
            || chunk.digest != self.digest
            || chunk.total_bytes != self.bytes.len()
        {
            return Err("candidate-response chunk changed assembly binding".into());
        }
        let index = chunk.offset / CANDIDATE_CHUNK_BYTES;
        let end = chunk.offset + chunk.bytes.len();
        if self.received[index] {
            if self.bytes[chunk.offset..end] != chunk.bytes {
                return Err("conflicting candidate-response duplicate".into());
            }
            return Ok(false);
        }
        self.bytes[chunk.offset..end].copy_from_slice(&chunk.bytes);
        self.received[index] = true;
        self.remaining -= 1;
        Ok(true)
    }
    pub fn is_complete(&self) -> bool {
        self.remaining == 0
    }
    pub fn finish(self) -> Result<Vec<u8>, String> {
        if !self.is_complete() || candidate_response_digest(&self.bytes) != self.digest {
            return Err("candidate-response assembly is incomplete or corrupt".into());
        }
        Ok(self.bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn chunks(bytes: &[u8]) -> Vec<CandidateResponseChunk> {
        bytes
            .chunks(CANDIDATE_CHUNK_BYTES)
            .enumerate()
            .map(|(index, part)| CandidateResponseChunk {
                request: FinalizedCandidateRequest {
                    height: 7,
                    expected_parent_id: "six".into(),
                },
                total_bytes: bytes.len(),
                digest: candidate_response_digest(bytes),
                offset: index * CANDIDATE_CHUNK_BYTES,
                bytes: part.to_vec(),
            })
            .collect()
    }
    #[test]
    fn candidate_chunks_preserve_oversized_exact_bytes_reordered_and_duplicate() {
        let bytes = (0..(2 * 1024 * 1024 + 17))
            .map(|i| (i % 251) as u8)
            .collect::<Vec<_>>();
        let mut parts = chunks(&bytes);
        let mut assembly = CandidateResponseAssembly::new(&parts[0]).unwrap();
        parts.reverse();
        assert!(assembly.push(parts[0].clone()).unwrap());
        assert!(!assembly.push(parts[0].clone()).unwrap());
        for part in parts.into_iter().skip(1) {
            assembly.push(part).unwrap();
        }
        assert!(assembly.is_complete());
        assert_eq!(assembly.finish().unwrap(), bytes);
    }
    #[test]
    fn candidate_chunks_reject_bounds_corruption_conflicting_metadata_and_missing_parts() {
        let parts = chunks(&vec![7; CANDIDATE_CHUNK_BYTES + 1]);
        for mode in 0..5 {
            let mut bad = parts[0].clone();
            match mode {
                0 => bad.total_bytes = MAX_CANDIDATE_RESPONSE_BYTES + 1,
                1 => bad.offset = 1,
                2 => bad.bytes.clear(),
                3 => bad.total_bytes = 0,
                _ => bad.request.expected_parent_id = "x".repeat(257),
            }
            assert!(CandidateResponseAssembly::new(&bad).is_err());
        }
        let mut assembly = CandidateResponseAssembly::new(&parts[0]).unwrap();
        assembly.push(parts[0].clone()).unwrap();
        let mut bad = parts[0].clone();
        bad.bytes[0] ^= 1;
        assert!(assembly.push(bad).is_err());
        let mut bad = parts[1].clone();
        bad.request.height += 1;
        assert!(assembly.push(bad).is_err());
        let mut bad = parts[1].clone();
        bad.digest[0] ^= 1;
        assert!(assembly.push(bad).is_err());
        assert!(assembly.finish().is_err());
        let mut assembly = CandidateResponseAssembly::new(&parts[0]).unwrap();
        for mut part in parts {
            part.bytes[0] ^= 1;
            assembly.push(part).unwrap();
        }
        assert!(assembly.finish().is_err());
    }
}
