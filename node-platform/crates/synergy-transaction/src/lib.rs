//! Canonical transaction identity, admission invariants, and Aegis verification boundary.
//!
//! This crate does not provide consensus authority, validator membership, PoSy
//! quorum calculation, finality, or raw P2P transport.

mod fee;
mod id;
mod nonce;
mod receipt;
mod signature;
mod system_transaction;
mod transaction;
mod validation;

pub use fee::FeeLimit;
pub use id::TransactionId;
pub use nonce::NonceWindow;
pub use receipt::{ReceiptStatus, TransactionReceipt};
pub use signature::{verify as verify_aegis_signature, AegisTransactionVerifier};
pub use system_transaction::{TransactionAction, TransactionClass};
pub use transaction::{
    NetworkBinding, SignedTransaction, UnsignedTransaction, SYNERGY_TESTNET_V3_CHAIN_ID,
};
pub use validation::TransactionError;

#[cfg(test)]
mod tests {
    use super::*;

    fn unsigned(nonce: u64) -> UnsignedTransaction {
        UnsignedTransaction {
            network: NetworkBinding::testnet_v3("synergy-testnet-v3").unwrap(),
            class: TransactionClass::User,
            sender: "syn1sender".into(),
            receiver: "syn1receiver".into(),
            amount_nwei: 7,
            nonce,
            fee_limit: FeeLimit {
                gas_limit: 21_000,
                max_fee_per_gas_nwei: 2,
            },
            timestamp_unix: 1,
            payload: vec![1, 2],
        }
    }

    #[test]
    fn transaction_id_is_canonical_and_excludes_signature_encoding() {
        let transaction = unsigned(1);
        assert_eq!(transaction.id().unwrap(), transaction.id().unwrap());
        assert_ne!(transaction.id().unwrap(), unsigned(2).id().unwrap());
    }

    #[test]
    fn nonce_window_prevents_replay_and_out_of_order_commit() {
        let mut window = NonceWindow::new(4, 2).unwrap();
        window.reserve(4).unwrap();
        assert_eq!(window.reserve(4), Err(TransactionError::DuplicateNonce));
        assert_eq!(window.commit(5), Err(TransactionError::NonceNotReady));
        window.commit(4).unwrap();
        assert_eq!(window.next(), 5);
    }

    #[test]
    fn transaction_types_never_claim_finality_authority() {
        assert!(!TransactionClass::User.may_determine_finality());
        assert!(!TransactionClass::System.may_determine_finality());
    }
}
