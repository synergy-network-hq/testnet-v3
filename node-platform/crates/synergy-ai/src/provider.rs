use crate::{valid, AiCapability, AiJob};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderAdvertisement {
    pub provider_id: String,
    pub capabilities: BTreeSet<AiCapability>,
    pub attestation_root: String,
}
impl ProviderAdvertisement {
    pub fn accepts(&self, j: &AiJob) -> Result<(), String> {
        if !valid(&self.provider_id)
            || !valid(&self.attestation_root)
            || !self.capabilities.contains(&j.capability)
        {
            return Err("provider is not eligible".into());
        }
        Ok(())
    }
}
