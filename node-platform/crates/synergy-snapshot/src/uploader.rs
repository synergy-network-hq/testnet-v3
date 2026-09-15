use crate::{SnapshotChunk, SnapshotManifest};

pub trait SnapshotUploadSink {
    fn put_manifest(&mut self, manifest: &SnapshotManifest) -> Result<(), String>;
    fn put_chunk(&mut self, height: u64, chunk: &SnapshotChunk) -> Result<(), String>;
    fn commit(&mut self, height: u64) -> Result<(), String>;
}

pub fn upload_snapshot(
    sink: &mut impl SnapshotUploadSink,
    manifest: &SnapshotManifest,
    chunks: &[SnapshotChunk],
) -> Result<(), String> {
    manifest.validate_shape()?;
    if chunks.len() != manifest.chunk_hashes.len() {
        return Err("snapshot chunk count mismatch".into());
    }
    for (index, chunk) in chunks.iter().enumerate() {
        if chunk.index != index as u64 || chunk.hash != manifest.chunk_hashes[index] {
            return Err("snapshot chunk order or hash mismatch".into());
        }
    }
    sink.put_manifest(manifest)?;
    for chunk in chunks {
        sink.put_chunk(manifest.height, chunk)?;
    }
    sink.commit(manifest.height)
}
