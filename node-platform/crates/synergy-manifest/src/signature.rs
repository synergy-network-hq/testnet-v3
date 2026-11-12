use serde::{Deserialize, Serialize};
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestSignature {
    pub key_id: String,
    pub algorithm: String,
    pub signature: Vec<u8>,
}
impl ManifestSignature {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.key_id.trim().is_empty()
            || self.algorithm.trim().is_empty()
            || self.signature.is_empty()
        {
            Err("invalid manifest signature")
        } else {
            Ok(())
        }
    }
}
pub trait ManifestSignatureVerifier: Send + Sync {
    fn verify(
        &self,
        key_id: &str,
        algorithm: &str,
        payload: &[u8],
        signature: &[u8],
    ) -> Result<(), String>;
}
