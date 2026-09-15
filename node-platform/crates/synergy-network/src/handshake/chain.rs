#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainBinding {
    pub network_id: String,
    pub chain_id: u64,
    pub genesis_hash: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChainBindingError {
    Invalid,
    NetworkMismatch,
    ChainMismatch,
    GenesisMismatch,
}

impl ChainBinding {
    pub fn validate(&self) -> Result<(), ChainBindingError> {
        if self.network_id.trim().is_empty()
            || self.chain_id == 0
            || self.genesis_hash.trim().is_empty()
        {
            return Err(ChainBindingError::Invalid);
        }
        Ok(())
    }

    pub fn verify_remote(&self, remote: &Self) -> Result<(), ChainBindingError> {
        self.validate()?;
        remote.validate()?;
        if self.network_id != remote.network_id {
            return Err(ChainBindingError::NetworkMismatch);
        }
        if self.chain_id != remote.chain_id {
            return Err(ChainBindingError::ChainMismatch);
        }
        if self.genesis_hash != remote.genesis_hash {
            return Err(ChainBindingError::GenesisMismatch);
        }
        Ok(())
    }
}
