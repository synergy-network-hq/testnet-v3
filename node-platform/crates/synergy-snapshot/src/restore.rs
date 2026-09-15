use synergy_crypto::AegisDigest;

use crate::{verify_snapshot, SnapshotChunk, SnapshotManifest, SnapshotVerificationProvider};

pub trait SnapshotRestoreSink {
    fn stage(&mut self, height: u64, state: &[u8]) -> Result<(), String>;
    fn commit(&mut self, height: u64) -> Result<(), String>;
}

pub fn restore_verified_snapshot(
    digest: &impl AegisDigest,
    verifier: &impl SnapshotVerificationProvider,
    manifest: &SnapshotManifest,
    chunks: &[SnapshotChunk],
    sink: &mut impl SnapshotRestoreSink,
) -> Result<(), String> {
    verify_snapshot(digest, verifier, manifest, chunks)?;
    let state = chunks
        .iter()
        .flat_map(|chunk| chunk.bytes.iter())
        .copied()
        .collect::<Vec<_>>();
    sink.stage(manifest.height, &state)?;
    sink.commit(manifest.height)
}
