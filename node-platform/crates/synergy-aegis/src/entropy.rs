//! Aegis-owned entropy boundary. Consumers never open an entropy device directly.
use std::fs::File;
use std::io::Read;

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
        File::open("/dev/urandom")
            .and_then(|mut file| file.read_exact(output))
            .map_err(|_| EntropyError::Unavailable)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntropyError {
    InvalidRequest,
    Unavailable,
}
