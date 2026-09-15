use synergy_crypto::{
    sha3_256, AegisDigest, AegisVerifier, CryptoDomain, KeyId, Signature, SigningContext,
};

use crate::{SnapshotChunk, SnapshotManifest, SnapshotVerificationProvider};

pub fn verify_snapshot_manifest(
    verifier: &impl SnapshotVerificationProvider,
    manifest: &SnapshotManifest,
) -> Result<(), String> {
    manifest.validate_shape()?;
    let key_id = KeyId::new(manifest.signing_key_id.clone())
        .map_err(|error| format!("invalid snapshot key id: {error}"))?;
    let public_key = verifier.governed_public_key(&key_id)?;
    verifier
        .verify(
            &SigningContext {
                domain: "SYNERGY-SNAPSHOT-MANIFEST-V1".into(),
                chain_id: manifest.chain_id,
                epoch: Some(manifest.epoch),
                height: Some(manifest.height),
            },
            &manifest.signing_bytes()?,
            &Signature {
                algorithm: manifest.signature_algorithm,
                key_id,
                bytes: manifest.signature.clone(),
            },
            &public_key,
        )
        .map_err(|error| format!("Aegis snapshot verification failed: {error}"))
}

pub fn verify_snapshot(
    digest: &impl AegisDigest,
    verifier: &impl SnapshotVerificationProvider,
    manifest: &SnapshotManifest,
    chunks: &[SnapshotChunk],
) -> Result<(), String> {
    verify_snapshot_manifest(verifier, manifest)?;
    if chunks.len() != manifest.chunk_hashes.len() {
        return Err("snapshot chunk count mismatch".into());
    }
    let chunk_domain = CryptoDomain {
        chain_id: manifest.chain_id,
        network_id: manifest.network_id.clone(),
        purpose: "snapshot-chunk-v1".into(),
        epoch: Some(manifest.epoch),
        height: Some(manifest.height),
    };
    let mut state = Vec::new();
    for (expected_index, chunk) in chunks.iter().enumerate() {
        let expected_size = usize::try_from(manifest.chunk_size)
            .map_err(|_| "snapshot chunk size exceeds platform range")?;
        let invalid_size = if expected_index + 1 == chunks.len() {
            chunk.bytes.is_empty() || chunk.bytes.len() > expected_size
        } else {
            chunk.bytes.len() != expected_size
        };
        if chunk.index != expected_index as u64
            || chunk.hash != manifest.chunk_hashes[expected_index]
            || invalid_size
        {
            return Err("snapshot chunk order, size, or manifest hash mismatch".into());
        }
        chunk.verify(digest, &chunk_domain)?;
        state.extend_from_slice(&chunk.bytes);
    }
    let state_domain = CryptoDomain {
        purpose: "snapshot-state-v1".into(),
        ..chunk_domain
    };
    if sha3_256(digest, &state_domain, &state)? != manifest.state_root {
        return Err("snapshot state root mismatch".into());
    }
    Ok(())
}
