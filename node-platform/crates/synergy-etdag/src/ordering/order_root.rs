use crate::{EtdagDigest, EtdagError};

pub fn protected_order_root(vertices: &[EtdagDigest]) -> Result<EtdagDigest, EtdagError> {
    EtdagDigest::from_canonical("PoSy/ProtectedPipeline/OrderRoot/v1", &vertices)
}
