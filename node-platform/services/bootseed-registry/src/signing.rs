pub trait BootseedSigner: Send + Sync {
    fn key_id(&self) -> &str;
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, String>;
}
