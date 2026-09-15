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
