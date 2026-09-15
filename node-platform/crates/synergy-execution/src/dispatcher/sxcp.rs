use synergy_state::WorldState;
use synergy_transaction::{SignedTransaction, TransactionAction};

use super::{
    DispatchContextError, TransactionDispatch, TransactionExecutionContext, TransactionExecutor,
};

/// Deterministic SXCP message executor. Cross-context delivery itself remains
/// outside execution and may not create consensus or finality authority.
pub trait SxcpExecutor {
    type Error: std::fmt::Display;

    fn execute_sxcp(
        &self,
        destination: &str,
        message: &[u8],
        transaction: &SignedTransaction,
        context: TransactionExecutionContext<'_>,
        state: &WorldState,
    ) -> Result<TransactionDispatch, Self::Error>;
}

/// Routes user-class SXCP actions through the registered deterministic bridge.
#[derive(Debug, Clone, Copy)]
pub struct SxcpDispatcher<E> {
    executor: E,
}

impl<E> SxcpDispatcher<E> {
    pub const fn new(executor: E) -> Self {
        Self { executor }
    }
}

#[derive(Debug)]
pub enum SxcpDispatchError<E> {
    Context(DispatchContextError),
    UnsupportedAction,
    Executor(E),
}

impl<E> TransactionExecutor for SxcpDispatcher<E>
where
    E: SxcpExecutor,
{
    type Error = SxcpDispatchError<E::Error>;

    fn execute(
        &self,
        transaction: &SignedTransaction,
        action: &TransactionAction,
        context: TransactionExecutionContext<'_>,
        state: &WorldState,
    ) -> Result<TransactionDispatch, Self::Error> {
        super::validate_dispatch_context(transaction, context, false)
            .map_err(SxcpDispatchError::Context)?;
        let TransactionAction::Sxcp {
            destination,
            message,
        } = action
        else {
            return Err(SxcpDispatchError::UnsupportedAction);
        };
        self.executor
            .execute_sxcp(destination, message, transaction, context, state)
            .map_err(SxcpDispatchError::Executor)
    }
}

impl<E: std::fmt::Display> std::fmt::Display for SxcpDispatchError<E> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Context(error) => write!(formatter, "invalid SXCP context: {error}"),
            Self::UnsupportedAction => write!(formatter, "unsupported SXCP action"),
            Self::Executor(error) => write!(formatter, "SXCP executor rejected action: {error}"),
        }
    }
}

impl<E: std::fmt::Display + std::fmt::Debug> std::error::Error for SxcpDispatchError<E> {}
