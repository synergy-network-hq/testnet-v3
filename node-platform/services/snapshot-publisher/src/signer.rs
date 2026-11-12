pub trait SnapshotSigner: Send + Sync {
    fn sign(&self, payload: &[u8]) -> Result<Vec<u8>, String>;
}
