//! Block commitments and execution-result containers.
//!
//! A block is proposal material. PoSy exclusively validates consensus messages,
//! determines quorum, and declares finality.

mod block;
mod body;
mod builder;
mod commitment;
mod encoding;
mod header;
mod validation;

pub use block::Block;
pub use body::BlockBody;
pub use builder::BlockBuilder;
pub use commitment::{hash_block_bytes, receipt_root, transaction_root};
pub use encoding::{
    validate_decoded, BlockCodec, CanonicalBlockCodec, BLOCK_FORMAT, DEFAULT_MAX_BLOCK_BYTES,
};
pub use header::BlockHeader;
pub use validation::{BlockError, BlockSignatureVerifier};

#[cfg(test)]
mod tests {
    use super::*;
    use synergy_transaction::{
        FeeLimit, NetworkBinding, ReceiptStatus, SignedTransaction, TransactionClass,
        TransactionReceipt, UnsignedTransaction,
    };

    fn transaction(nonce: u64) -> SignedTransaction {
        SignedTransaction {
            unsigned: UnsignedTransaction {
                network: NetworkBinding::testnet_v3("synergy-testnet-v3").unwrap(),
                class: TransactionClass::User,
                sender: "sender".into(),
                receiver: "receiver".into(),
                amount_nwei: 1,
                nonce,
                fee_limit: FeeLimit {
                    gas_limit: 21_000,
                    max_fee_per_gas_nwei: 1,
                },
                timestamp_unix: 1,
                payload: vec![],
            },
            signer_public_key: vec![1],
            signature: vec![2],
            signature_algorithm: "ML-DSA-87".into(),
        }
    }

    #[test]
    fn block_binds_transactions_and_receipts_to_deterministic_commitments() {
        let tx = transaction(1);
        let receipt = TransactionReceipt {
            transaction_id: tx.id().unwrap(),
            status: ReceiptStatus::Applied,
            gas_used: 1,
            state_root_after: "state-root".into(),
            error_code: None,
        };
        let mut builder = BlockBuilder::default();
        builder.push(tx, receipt).unwrap();
        let block = builder
            .build(
                NetworkBinding::testnet_v3("synergy-testnet-v3").unwrap(),
                1,
                "parent",
                1,
                "validator",
                "state-root",
                vec![3],
                "ML-DSA-65",
            )
            .unwrap();
        block.validate_structure().unwrap();
        assert!(!block.may_determine_finality());
    }

    #[test]
    fn duplicate_transactions_are_rejected() {
        let tx = transaction(1);
        let body = BlockBody {
            transactions: vec![tx.clone(), tx],
        };
        assert_eq!(
            body.validate_structure(),
            Err(BlockError::DuplicateTransaction)
        );
    }
}
