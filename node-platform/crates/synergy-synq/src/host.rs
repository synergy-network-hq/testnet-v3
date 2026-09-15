use crate::SynqError;

/// Deterministic host interface. Implementations must not expose wall-clock,
/// random, network, filesystem, or process-global mutable state to programs.
pub trait SynqHost {
    fn read(&self, key: &[u8]) -> Result<Option<Vec<u8>>, SynqError>;
    fn write(&mut self, key: Vec<u8>, value: Vec<u8>) -> Result<(), SynqError>;
    fn emit(&mut self, topic: Vec<u8>, data: Vec<u8>) -> Result<(), SynqError>;
}
