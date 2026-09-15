use serde::{Deserialize, Serialize};

/// Synergy finality reference used only to authorize a local relay outcome.
/// External-chain observations can never create or override PoSy finality.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SynergyFinalityAnchor {
    pub chain_id: u64,
    pub finalized_height: u64,
    pub finalized_block_id: String,
    pub finality_certificate_id: String,
}

impl SynergyFinalityAnchor {
    pub fn validate(&self) -> Result<(), String> {
        if self.chain_id != 1266
            || self.finalized_block_id.trim().is_empty()
            || self.finality_certificate_id.trim().is_empty()
        {
            return Err("invalid Synergy finality anchor".into());
        }
        Ok(())
    }
}
