use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultKeyReference {
    pub vault_id: String,
    pub key_id: String,
    pub policy_id: String,
}

impl VaultKeyReference {
    pub fn validate(&self) -> Result<(), String> {
        if self.vault_id.trim().is_empty()
            || self.key_id.trim().is_empty()
            || self.policy_id.trim().is_empty()
        {
            return Err("invalid SXCP vault key reference".into());
        }
        Ok(())
    }
}

/// Provider retains custody; SXCP never receives private key bytes.
pub trait VaultProvider {
    fn authorize_relay(
        &self,
        key: &VaultKeyReference,
        transcript: &[u8],
    ) -> Result<Vec<u8>, String>;
}
