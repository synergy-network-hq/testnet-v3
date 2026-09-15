use crate::{EtdagDigest, EtdagError};

const DOMAIN_ORDER_SEED: &str = "PoSy/ETDAG/OrderSeed/v3";

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
