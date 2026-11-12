use crate::{EtdagDigest, EtdagError};

const DOMAIN_ORDER_SEED: &str = "PoSy/ETDAG/OrderSeed/v3";

/// Use the immutable target context as the canonical finalized-authority
/// commitment. The node must authenticate that context before calling this.
pub fn derive_target_order_seed(
    context: &crate::TargetAdmissionContextV3,
    cut: &super::VerifiedProtectedCut,
) -> Result<EtdagDigest, EtdagError> {
    let context_root = context.root()?;
    if cut.proof().context_root != context_root
        || cut.proof().target_height != context.target_height
        || context.finalized_epoch_seed_root.len() != 64
    {
        return Err(EtdagError::ContextMismatch);
    }
    let mut randomness = [0u8; 32];
    for (index, pair) in context
        .finalized_epoch_seed_root
        .as_bytes()
        .chunks_exact(2)
        .enumerate()
    {
        let pair = std::str::from_utf8(pair).map_err(|_| EtdagError::InvalidDigest)?;
        randomness[index] = u8::from_str_radix(pair, 16).map_err(|_| EtdagError::InvalidDigest)?;
    }
    derive_order_seed(
        randomness,
        &context_root,
        cut.semantic_root(),
        context.target_height,
    )
}

/// Derive the frozen-runtime ETDAG seed from authenticated finalized context
/// and the certified DAG cut. `epoch_randomness` is the raw 32-byte PoSy Hash,
/// whose canonical JSON wire shape is a byte array (not a hex string).
/// This function does not authenticate those inputs; its caller must do so.
pub fn derive_order_seed(
    epoch_randomness: [u8; 32],
    canonical_finality_context: &EtdagDigest,
    dcc_digest: &EtdagDigest,
    target_height: u64,
) -> Result<EtdagDigest, EtdagError> {
    if epoch_randomness.iter().all(|byte| *byte == 0) {
        return Err(EtdagError::InvalidDigest);
    }
    canonical_finality_context.validate()?;
    dcc_digest.validate()?;
    EtdagDigest::from_canonical(
        DOMAIN_ORDER_SEED,
        &(
            epoch_randomness,
            canonical_finality_context,
            dcc_digest,
            target_height,
        ),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seed_binds_every_finalized_input_and_rejects_missing_randomness() {
        let context = EtdagDigest::from_domain_bytes("test", b"finality");
        let dcc = EtdagDigest::from_domain_bytes("test", b"dcc");
        let first = derive_order_seed([7; 32], &context, &dcc, 15).unwrap();
        assert_ne!(
            first,
            derive_order_seed([8; 32], &context, &dcc, 15).unwrap()
        );
        assert_ne!(
            first,
            derive_order_seed([7; 32], &dcc, &context, 15).unwrap()
        );
        assert_ne!(
            first,
            derive_order_seed([7; 32], &context, &dcc, 16).unwrap()
        );
        assert_eq!(
            derive_order_seed([0; 32], &context, &dcc, 15),
            Err(EtdagError::InvalidDigest)
        );
    }
}
