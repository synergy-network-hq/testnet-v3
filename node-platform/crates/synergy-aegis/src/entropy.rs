//! Aegis-owned entropy boundary. Consumers never open an entropy device directly.
use synergy_address_engine::apqe::Primitives;

pub trait AegisEntropy: Send + Sync {
    fn fill(&self, output: &mut [u8]) -> Result<(), EntropyError>;
}

#[derive(Debug, Clone, Copy, Default)]
pub struct OperatingSystemEntropy;

impl AegisEntropy for OperatingSystemEntropy {
    fn fill(&self, output: &mut [u8]) -> Result<(), EntropyError> {
        if output.is_empty() || output.len() > 1024 * 1024 {
            return Err(EntropyError::InvalidRequest);
        }
        Primitives
            .random_bytes(output)
            .map_err(|_| EntropyError::Unavailable)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntropyError {
    InvalidRequest,
    Unavailable,
}
