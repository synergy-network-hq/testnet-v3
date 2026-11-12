//! Bounded transaction ingress before protected ETDAG admission.
//!
//! Ingress validates and rate-bounds client submissions. It never decrypts
//! protected payloads, computes PoSy quorum, authorizes membership, or finalizes.

mod admission;
mod governance;
mod internal;
mod metrics;
mod protected;
mod router;
mod system;

pub use admission::TransactionIngress;
pub use governance::GovernanceIngress;
pub use internal::InternalIngress;
pub use metrics::IngressMetrics;
pub use protected::ProtectedIngress;
pub use router::{DirectProtectedIngressRouter, ProtectedIngressRouter};
pub use system::SystemIngress;

use synergy_etdag::EtdagError;
use synergy_transaction::{TransactionError, TransactionId};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IngressReceipt {
    pub transaction_id: TransactionId,
    pub sender: String,
    pub nonce: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IngressError {
    Transaction(TransactionError),
    Etdag(EtdagError),
    InvalidLimits,
    NetworkMismatch,
    Capacity,
    DuplicateTransaction,
    DuplicateEnvelope,
    TargetContextMismatch,
}

impl std::fmt::Display for IngressError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for IngressError {}

#[cfg(test)]
mod tests {
    use super::*;
    use synergy_transaction::{
        AegisTransactionVerifier, FeeLimit, NetworkBinding, SignedTransaction, TransactionClass,
        UnsignedTransaction,
    };

    struct Accept;
    impl AegisTransactionVerifier for Accept {
        type Error = String;
        fn verify_transaction(
            &self,
            _: &[u8],
            _: &[u8],
            _: &[u8],
            _: &str,
        ) -> Result<bool, Self::Error> {
            Ok(true)
        }
    }

    fn transaction(nonce: u64) -> SignedTransaction {
        let signer_public_key = vec![1_u8; synergy_address::FN_DSA_1024_PUBLIC_KEY_BYTES];
        let sender = synergy_address::derive_standard_account_address(&signer_public_key).unwrap();
        let receiver =
            synergy_address::derive_object_address("synq", b"ingress-test-receiver").unwrap();
        SignedTransaction {
            identity_authorization: None,
            unsigned: UnsignedTransaction {
                network: NetworkBinding::new(1266, "synergy-testnet-v3").unwrap(),
                class: TransactionClass::User,
                sender,
                receiver,
                amount_nwei: 1,
                nonce,
                fee_limit: FeeLimit {
                    gas_limit: 21_000,
                    max_fee_per_gas_nwei: 1,
                },
                timestamp_unix: 1,
                payload: vec![],
            },
            signer_public_key,
            signature: vec![2],
            signature_algorithm: "FN-DSA-1024".into(),
        }
    }

    #[test]
    fn user_admission_is_bounded_and_requires_aegis_verification() {
        let network = NetworkBinding::new(1266, "synergy-testnet-v3").unwrap();
        let mut ingress = TransactionIngress::new(network, 1, 2).unwrap();
        ingress.admit_verified(transaction(1), &Accept).unwrap();
        assert_eq!(
            ingress.admit_verified(transaction(2), &Accept),
            Err(IngressError::Capacity)
        );
        assert!(!ingress.may_determine_finality());
    }
}
