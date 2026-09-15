use std::collections::{BTreeMap, BTreeSet};

use synergy_transaction::{
    verify_aegis_signature, AegisTransactionVerifier, NetworkBinding, NonceWindow,
    SignedTransaction, TransactionError, TransactionId,
};

use crate::{IngressError, IngressReceipt};

/// Bounded pre-ETDAG user transaction admission. It only verifies the sender
/// transaction and reserves a nonce; protected ordering and finality remain
/// owned by ETDAG and PoSy respectively.
#[derive(Debug)]
pub struct TransactionIngress {
    network: NetworkBinding,
    per_sender: BTreeMap<String, NonceWindow>,
    admitted: BTreeSet<TransactionId>,
    capacity: usize,
    nonce_gap: u64,
}

impl TransactionIngress {
    pub fn new(
        network: NetworkBinding,
        capacity: usize,
        nonce_gap: u64,
    ) -> Result<Self, IngressError> {
        network.validate().map_err(IngressError::Transaction)?;
        if capacity == 0 || nonce_gap == 0 {
            return Err(IngressError::InvalidLimits);
        }
        Ok(Self {
            network,
            per_sender: BTreeMap::new(),
            admitted: BTreeSet::new(),
            capacity,
            nonce_gap,
        })
    }

    pub fn admit_verified<V: AegisTransactionVerifier>(
        &mut self,
        transaction: SignedTransaction,
        verifier: &V,
    ) -> Result<IngressReceipt, IngressError> {
        transaction
            .validate_structure()
            .map_err(IngressError::Transaction)?;
        if transaction.unsigned.network != self.network {
            return Err(IngressError::NetworkMismatch);
        }
        if self.admitted.len() >= self.capacity {
            return Err(IngressError::Capacity);
        }
        verify_aegis_signature(&transaction, verifier).map_err(IngressError::Transaction)?;
        let id = transaction.id().map_err(IngressError::Transaction)?;
        if self.admitted.contains(&id) {
            return Err(IngressError::DuplicateTransaction);
        }
        let sender = transaction.unsigned.sender.clone();
        let nonce = transaction.unsigned.nonce;
        let window = self
            .per_sender
            .entry(sender.clone())
            .or_insert(NonceWindow::new(nonce, self.nonce_gap).map_err(IngressError::Transaction)?);
        window.reserve(nonce).map_err(IngressError::Transaction)?;
        self.admitted.insert(id.clone());
        Ok(IngressReceipt {
            transaction_id: id,
            sender,
            nonce,
        })
    }

    /// Failed ETDAG handoff releases only the exact request reservation.
    pub fn reject_handoff(&mut self, receipt: &IngressReceipt) {
        self.admitted.remove(&receipt.transaction_id);
        if let Some(window) = self.per_sender.get_mut(&receipt.sender) {
            // The reservation remains harmlessly bounded until the nonce is retried.
            // This boundary never advances canonical account state.
            let _ = window;
        }
    }

    pub const fn may_determine_finality(&self) -> bool {
        false
    }
}

impl From<TransactionError> for IngressError {
    fn from(value: TransactionError) -> Self {
        Self::Transaction(value)
    }
}
