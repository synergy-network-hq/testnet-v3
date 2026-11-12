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
pub use signature::{
    verify as verify_aegis_signature,
    verify_with_admission as verify_aegis_signature_with_admission, AegisTransactionVerifier,
    TransactionAdmissionContext,
};
pub use system_transaction::{TransactionAction, TransactionClass};
pub use transaction::{NetworkBinding, SignedTransaction, UnsignedTransaction};
pub use validation::TransactionError;

#[cfg(test)]
mod tests {
    use super::*;

    fn unsigned(nonce: u64) -> UnsignedTransaction {
        let sender = synergy_address::derive_object_address("synq", b"test-sender").unwrap();
        let receiver = synergy_address::derive_object_address("synq", b"test-receiver").unwrap();
        UnsignedTransaction {
            network: NetworkBinding::new(1266, "synergy-testnet-v3").unwrap(),
            class: TransactionClass::User,
            sender,
            receiver,
            amount_nwei: 7,
            nonce,
            fee_limit: FeeLimit {
                gas_limit: 21_000,
                max_fee_per_gas_nwei: 2,
            },
            timestamp_unix: 1,
            payload: vec![],
        }
    }

    #[test]
    fn transaction_id_is_canonical_and_excludes_signature_encoding() {
        let transaction = unsigned(1);
        assert_eq!(transaction.id().unwrap(), transaction.id().unwrap());
        assert_ne!(transaction.id().unwrap(), unsigned(2).id().unwrap());
    }

    #[test]
    fn selected_network_signature_rejects_cross_chain_and_same_chain_incarnation_replay() {
        use aegis_pqvm::pqc::signatures::mldsa::mldsa87;
        let (public, secret) = mldsa87::keypair();
        for (chain_id, network) in [(1266, "testnet-a"), (9001, "beta"), (9002, "mainnet")] {
            let mut tx = unsigned(1);
            tx.network = NetworkBinding::new(chain_id, network).unwrap();
            let bytes = tx.signing_bytes().unwrap();
            let signature = mldsa87::detached_sign(&bytes, &secret);
            assert!(mldsa87::verify_detached_signature(&signature, &bytes, &public).is_ok());
            let original_id = tx.id().unwrap();
            tx.network.chain_id += 1;
            assert!(mldsa87::verify_detached_signature(
                &signature,
                &tx.signing_bytes().unwrap(),
                &public
            )
            .is_err());
            assert_ne!(tx.id().unwrap(), original_id);
            tx.network.chain_id = chain_id;
            tx.network.network_id.push_str("-new-incarnation");
            assert!(mldsa87::verify_detached_signature(
                &signature,
                &tx.signing_bytes().unwrap(),
                &public
            )
            .is_err());
        }
        assert!(NetworkBinding::new(0, "testnet").is_err());
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
