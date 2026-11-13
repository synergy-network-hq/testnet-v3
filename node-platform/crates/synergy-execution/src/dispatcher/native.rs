use synergy_state::{AccountChange, StateDiff, WorldState};
use synergy_transaction::{SignedTransaction, TransactionAction};

use super::{TransactionDispatch, TransactionExecutionContext, TransactionExecutor};

pub const NATIVE_TRANSFER_GAS: u64 = 21_000;

/// Canonical value-transfer executor. Rich native, SynQ, SXCP, governance, and
/// system actions remain separate handlers and are rejected by this boundary.
#[derive(Debug, Default, Clone, Copy)]
pub struct NativeTransferDispatcher;

/// Protocol-native operation supplied by the canonical owning subsystems.
/// The operation returns a deterministic state diff; it cannot persist local
/// state or claim finality.
pub trait NativeOperation {
    type Error: std::fmt::Display;

    fn execute_native(
        &self,
        module: &str,
        method: &str,
        input: &[u8],
        transaction: &SignedTransaction,
        context: TransactionExecutionContext<'_>,
        state: &WorldState,
    ) -> Result<TransactionDispatch, Self::Error>;
}

/// Routes transfers to the canonical balance transition and richer native
/// actions to their registered protocol owner.
#[derive(Debug, Clone, Copy)]
pub struct NativeDispatcher<O> {
    operation: O,
}

impl<O> NativeDispatcher<O> {
    pub const fn new(operation: O) -> Self {
        Self { operation }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NativeDispatchError {
    UnsupportedAction,
    ZeroValueTransfer,
    WrongNetwork,
    InvalidContext,
    AccountNotEnrolled,
}

#[derive(Debug)]
pub enum CanonicalNativeDispatchError<E> {
    Context(super::DispatchContextError),
    UnsupportedAction,
    Transfer(NativeDispatchError),
    Operation(E),
}

impl<O> TransactionExecutor for NativeDispatcher<O>
where
    O: NativeOperation,
{
    type Error = CanonicalNativeDispatchError<O::Error>;

    fn execute(
        &self,
        transaction: &SignedTransaction,
        action: &TransactionAction,
        context: TransactionExecutionContext<'_>,
        state: &WorldState,
    ) -> Result<TransactionDispatch, Self::Error> {
        super::validate_dispatch_context(transaction, context, false)
            .map_err(CanonicalNativeDispatchError::Context)?;
        match action {
            TransactionAction::Transfer => NativeTransferDispatcher
                .execute(transaction, action, context, state)
                .map_err(CanonicalNativeDispatchError::Transfer),
            TransactionAction::Native {
                module,
                method,
                input,
            } => self
                .operation
                .execute_native(module, method, input, transaction, context, state)
                .map_err(CanonicalNativeDispatchError::Operation),
            _ => Err(CanonicalNativeDispatchError::UnsupportedAction),
        }
    }
}

impl TransactionExecutor for NativeTransferDispatcher {
    type Error = NativeDispatchError;

    fn execute(
        &self,
        transaction: &SignedTransaction,
        action: &TransactionAction,
        context: TransactionExecutionContext<'_>,
        _state: &WorldState,
    ) -> Result<TransactionDispatch, Self::Error> {
        if transaction.unsigned.network != *context.network {
            return Err(NativeDispatchError::WrongNetwork);
        }
        if context.block_height == 0 {
            return Err(NativeDispatchError::InvalidContext);
        }
        if !matches!(action, TransactionAction::Transfer) {
            return Err(NativeDispatchError::UnsupportedAction);
        }
        if transaction.unsigned.amount_nwei == 0 {
            return Err(NativeDispatchError::ZeroValueTransfer);
        }
        // The legacy transfer path cannot authenticate a protected account
        // registration. Do not credit synw until the governed registry is live.
        if transaction.unsigned.receiver.starts_with("synw") {
            return Err(NativeDispatchError::AccountNotEnrolled);
        }

        Ok(TransactionDispatch {
            state_diff: StateDiff {
                changes: vec![
                    AccountChange {
                        account: transaction.unsigned.sender.clone(),
                        debit_nwei: transaction.unsigned.amount_nwei,
                        credit_nwei: 0,
                        expected_nonce: Some(transaction.unsigned.nonce),
                        code_hash: None,
                    },
                    AccountChange {
                        account: transaction.unsigned.receiver.clone(),
                        debit_nwei: 0,
                        credit_nwei: transaction.unsigned.amount_nwei,
                        expected_nonce: None,
                        code_hash: None,
                    },
                ],
                protocol_changes: Vec::new(),
            },
            gas_used: NATIVE_TRANSFER_GAS,
        })
    }
}

impl std::fmt::Display for NativeDispatchError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if matches!(self, Self::AccountNotEnrolled) {
            return formatter.write_str("ACCOUNT_NOT_ENROLLED");
        }
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for NativeDispatchError {}

impl<E: std::fmt::Display> std::fmt::Display for CanonicalNativeDispatchError<E> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Context(error) => write!(formatter, "invalid native context: {error}"),
            Self::UnsupportedAction => formatter.write_str("unsupported native action"),
            Self::Transfer(error) => write!(formatter, "native transfer rejected: {error}"),
            Self::Operation(error) => write!(formatter, "native operation rejected: {error}"),
        }
    }
}

impl<E: std::fmt::Display + std::fmt::Debug> std::error::Error for CanonicalNativeDispatchError<E> {}

#[cfg(test)]
mod tests {
    use super::*;
    use synergy_transaction::{FeeLimit, NetworkBinding, TransactionClass, UnsignedTransaction};

    #[test]
    fn legacy_transfer_cannot_credit_an_unregistered_protected_recipient() {
        let network = NetworkBinding::new(99999, "candidate").unwrap();
        let mut transaction = SignedTransaction {
            unsigned: UnsignedTransaction {
                network: network.clone(),
                class: TransactionClass::User,
                sender: "ordinary-sender".into(),
                receiver: "synw52908400098527886E0F7030069857D2E4169EE7".into(),
                amount_nwei: 1,
                nonce: 0,
                fee_limit: FeeLimit {
                    gas_limit: NATIVE_TRANSFER_GAS,
                    max_fee_per_gas_nwei: 40,
                },
                timestamp_unix: 1,
                payload: vec![],
            },
            signer_public_key: vec![],
            signature: vec![],
            signature_algorithm: "ML-DSA-87".into(),
            identity_authorization: None,
        };
        let context = TransactionExecutionContext {
            network: &network,
            block_height: 1,
            transaction_index: 0,
        };
        let world = WorldState::default();
        assert_eq!(
            NativeTransferDispatcher
                .execute(&transaction, &TransactionAction::Transfer, context, &world)
                .unwrap_err(),
            NativeDispatchError::AccountNotEnrolled
        );
        transaction.unsigned.receiver = "ordinary-recipient".into();
        assert!(NativeTransferDispatcher
            .execute(&transaction, &TransactionAction::Transfer, context, &world)
            .is_ok());
    }
}
