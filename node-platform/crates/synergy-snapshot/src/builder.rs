use synergy_crypto::{sha3_256, AegisDigest, CryptoDomain, SigningContext};

use crate::{SnapshotChunk, SnapshotManifest, SnapshotSigningProvider};

#[allow(clippy::too_many_arguments)]
pub fn build_snapshot(
    digest: &impl AegisDigest,
    signer: &impl SnapshotSigningProvider,
    network_id: &str,
    epoch: u64,
    height: u64,
    finalized_block_id: &str,
    finality_evidence_id: &str,
    application_state_root: &str,
    chunk_size: usize,
    state_bytes: &[u8],
) -> Result<(SnapshotManifest, Vec<SnapshotChunk>), String> {
    if network_id.trim().is_empty()
        || epoch == 0
        || height == 0
        || finalized_block_id.trim().is_empty()
        || finality_evidence_id.trim().is_empty()
        || application_state_root.trim().is_empty()
        || chunk_size == 0
        || state_bytes.is_empty()
    {
        return Err("invalid snapshot build input".into());
    }
    let chunk_domain = CryptoDomain {
        chain_id: 1266,
        network_id: network_id.into(),
        purpose: "snapshot-chunk-v1".into(),
        epoch: Some(epoch),
        height: Some(height),
    };
    let chunks = state_bytes
        .chunks(chunk_size)
        .enumerate()
        .map(|(index, bytes)| {
            SnapshotChunk::new(digest, &chunk_domain, index as u64, bytes.to_vec())
        })
        .collect::<Result<Vec<_>, _>>()?;
    let state_domain = CryptoDomain {
        purpose: "snapshot-state-v1".into(),
        ..chunk_domain
    };
    let state_root = sha3_256(digest, &state_domain, state_bytes)?;
    let mut manifest = SnapshotManifest {
        format_version: 1,
        chain_id: 1266,
        network_id: network_id.into(),
        epoch,
        height,
        finalized_block_id: finalized_block_id.into(),
        finality_evidence_id: finality_evidence_id.into(),
        application_state_root: application_state_root.into(),
        state_root,
        chunk_size: chunk_size as u64,
        chunk_hashes: chunks.iter().map(|chunk| chunk.hash).collect(),
        signing_key_id: signer.snapshot_key_id().as_str().into(),
        signature_algorithm: signer.snapshot_algorithm(),
        signature: Vec::new(),
    };
    let signature = signer.sign_snapshot(
        &SigningContext {
            domain: "SYNERGY-SNAPSHOT-MANIFEST-V1".into(),
            chain_id: manifest.chain_id,
            epoch: Some(manifest.epoch),
            height: Some(manifest.height),
        },
        &manifest.signing_bytes()?,
    )?;
    if signature.key_id.as_str() != manifest.signing_key_id
        || signature.algorithm != manifest.signature_algorithm
    {
        return Err("Aegis snapshot signer returned a different key or algorithm binding".into());
    }
    manifest.signature = signature.bytes;
    manifest.validate_shape()?;
    Ok((manifest, chunks))
}
