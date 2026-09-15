use serde::{Deserialize, Serialize};
use synergy_crypto::{Hash32, SignatureAlgorithm};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotManifest {
    pub format_version: u32,
    pub chain_id: u64,
    pub network_id: String,
    pub epoch: u64,
    pub height: u64,
    pub finalized_block_id: String,
    pub finality_evidence_id: String,
    pub application_state_root: String,
    pub state_root: Hash32,
    pub chunk_size: u64,
    pub chunk_hashes: Vec<Hash32>,
    pub signing_key_id: String,
    pub signature_algorithm: SignatureAlgorithm,
    pub signature: Vec<u8>,
}

impl SnapshotManifest {
    pub fn signing_bytes(&self) -> Result<Vec<u8>, String> {
        #[derive(Serialize)]
        struct Unsigned<'a> {
            format_version: u32,
            chain_id: u64,
            network_id: &'a str,
            epoch: u64,
            height: u64,
            finalized_block_id: &'a str,
            finality_evidence_id: &'a str,
            application_state_root: &'a str,
            state_root: Hash32,
            chunk_size: u64,
            chunk_hashes: &'a [Hash32],
            signing_key_id: &'a str,
            signature_algorithm: SignatureAlgorithm,
        }
        serde_json::to_vec(&Unsigned {
            format_version: self.format_version,
            chain_id: self.chain_id,
            network_id: &self.network_id,
            epoch: self.epoch,
            height: self.height,
            finalized_block_id: &self.finalized_block_id,
            finality_evidence_id: &self.finality_evidence_id,
            application_state_root: &self.application_state_root,
            state_root: self.state_root,
            chunk_size: self.chunk_size,
            chunk_hashes: &self.chunk_hashes,
            signing_key_id: &self.signing_key_id,
            signature_algorithm: self.signature_algorithm,
        })
        .map_err(|error| format!("serialize snapshot manifest: {error}"))
    }

    pub fn validate_shape(&self) -> Result<(), String> {
        if self.format_version != 1
            || self.chain_id != 1266
            || self.network_id.trim().is_empty()
            || self.network_id.len() > 128
            || self.epoch == 0
            || self.height == 0
            || invalid_identifier(&self.finalized_block_id)
            || invalid_identifier(&self.finality_evidence_id)
            || !is_lower_hex_32(&self.application_state_root)
            || self.chunk_size == 0
            || self.chunk_size > 16 * 1024 * 1024
            || self.chunk_hashes.is_empty()
            || self.chunk_hashes.len() > 1_048_576
            || self.signing_key_id.trim().is_empty()
            || self.signing_key_id.len() > 256
            || self.signature.is_empty()
            || self.signature.len() > 16 * 1024
        {
            return Err("invalid snapshot manifest".into());
        }
        Ok(())
    }
}

fn invalid_identifier(value: &str) -> bool {
    value.trim().is_empty() || value.len() > 256
}

fn is_lower_hex_32(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
