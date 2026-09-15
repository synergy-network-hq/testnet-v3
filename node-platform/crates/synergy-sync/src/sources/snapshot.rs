use crate::{SnapshotDownload, SnapshotManifest};

pub trait SnapshotSyncSource {
    fn source_id(&self) -> &str;
    fn authenticated(&self) -> bool;
    fn manifest(&self, height: u64) -> Result<SnapshotManifest, String>;
    fn download(&mut self, manifest: &SnapshotManifest) -> Result<SnapshotDownload, String>;
}

pub fn request_authenticated_snapshot(
    source: &mut impl SnapshotSyncSource,
    height: u64,
) -> Result<SnapshotDownload, String> {
    if !source.authenticated() || source.source_id().trim().is_empty() {
        return Err("ineligible snapshot sync source".into());
    }
    let manifest = source.manifest(height)?;
    if manifest.finalized_height != height {
        return Err("snapshot source returned the wrong finalized height".into());
    }
    source.download(&manifest)
}

pub trait ProductionSnapshotSource {
    fn manifest(&self, height: u64) -> Result<synergy_snapshot::SnapshotManifest, String>;
    fn chunks(
        &mut self,
        manifest: &synergy_snapshot::SnapshotManifest,
    ) -> Result<Vec<synergy_snapshot::SnapshotChunk>, String>;
}

pub fn fetch_verified_production_snapshot(
    source: &mut impl ProductionSnapshotSource,
    digest: &impl synergy_crypto::AegisDigest,
    verifier: &impl synergy_snapshot::SnapshotVerificationProvider,
    height: u64,
) -> Result<Vec<u8>, String> {
    let manifest = source.manifest(height)?;
    if manifest.height != height {
        return Err("production snapshot source returned the wrong height".into());
    }
    let chunks = source.chunks(&manifest)?;
    synergy_snapshot::verify_snapshot(digest, verifier, &manifest, &chunks)?;
    Ok(chunks.into_iter().flat_map(|chunk| chunk.bytes).collect())
}
