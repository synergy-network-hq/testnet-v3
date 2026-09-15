use crate::{EtdagDigest, EtdagError};

pub fn protected_order_root(vertices: &[EtdagDigest]) -> Result<EtdagDigest, EtdagError> {
    if vertices.is_empty() {
        return Err(EtdagError::InvalidExecutionInput);
    }
    EtdagDigest::from_canonical("PoSy/ProtectedPipeline/OrderRoot/v1", &vertices)
}
