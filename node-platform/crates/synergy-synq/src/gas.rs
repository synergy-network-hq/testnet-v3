use crate::SynqError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GasMeter {
    limit: u64,
    used: u64,
}

impl GasMeter {
    pub fn new(limit: u64) -> Result<Self, SynqError> {
        if limit == 0 {
            return Err(SynqError::InvalidGasLimit);
        }
        Ok(Self { limit, used: 0 })
    }

    pub fn charge(&mut self, units: u64) -> Result<(), SynqError> {
        self.used = self.used.checked_add(units).ok_or(SynqError::GasOverflow)?;
        if self.used > self.limit {
            return Err(SynqError::OutOfGas);
        }
        Ok(())
    }

    pub fn used(&self) -> u64 {
        self.used
    }

    pub fn remaining(&self) -> u64 {
        self.limit - self.used
    }
}
