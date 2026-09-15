use serde::{Deserialize, Serialize};
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CryptoDomain {
    pub chain_id: u64,
    pub network_id: String,
    pub purpose: String,
    pub epoch: Option<u64>,
    pub height: Option<u64>,
}
impl CryptoDomain {
    pub fn validate(&self) -> Result<(), String> {
        if self.chain_id != 1266
            || self.network_id.trim().is_empty()
            || self.network_id.len() > 128
            || self.purpose.trim().is_empty()
            || self.purpose.len() > 128
        {
            return Err("invalid Chain 1266 cryptographic domain".into());
        }
        Ok(())
    }
    pub fn canonical_prefix(&self) -> Result<Vec<u8>, String> {
        self.validate()?;
        let mut out = b"SYNERGY_CRYPTO_DOMAIN_V1".to_vec();
        for value in [&self.network_id, &self.purpose] {
            out.extend_from_slice(&(value.len() as u64).to_be_bytes());
            out.extend_from_slice(value.as_bytes())
        }
        out.extend_from_slice(&self.chain_id.to_be_bytes());
        out.extend_from_slice(&self.epoch.unwrap_or(u64::MAX).to_be_bytes());
        out.extend_from_slice(&self.height.unwrap_or(u64::MAX).to_be_bytes());
        Ok(out)
    }
}
