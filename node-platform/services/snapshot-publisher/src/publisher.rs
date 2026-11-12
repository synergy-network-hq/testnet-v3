use crate::{
    manifest::PublishedSnapshotManifest, signer::SnapshotSigner, storage::SnapshotStorage,
};
pub fn publish(
    storage: &SnapshotStorage,
    mut manifest: PublishedSnapshotManifest,
    payload: &[u8],
    signer: &dyn SnapshotSigner,
) -> Result<PublishedSnapshotManifest, String> {
    if manifest.height == 0 || manifest.finality_proof.is_empty() {
        return Err("snapshot is not finality bound".into());
    }
    manifest.signature = signer.sign(payload)?;
    manifest.validate().map_err(str::to_string)?;
    let bytes = serde_json::to_vec_pretty(&manifest).map_err(|e| e.to_string())?;
    storage.publish(&manifest.snapshot_id, &bytes)?;
    Ok(manifest)
}
