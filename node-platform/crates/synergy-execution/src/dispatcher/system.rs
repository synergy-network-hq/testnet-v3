use synergy_state::WorldState;
use synergy_transaction::{SignedTransaction, TransactionAction};

use super::{
    DispatchContextError, TransactionDispatch, TransactionExecutionContext, TransactionExecutor,
};

/// Canonical system-operation implementation. Authorization is explicit input
/// to the authority implementation and is never synthesized by execution.
pub trait SystemOperation {
    type Error: std::fmt::Display;

    fn execute_system(
        &self,
        authorization_id: &str,
        operation: &[u8],
        transaction: &SignedTransaction,
        context: TransactionExecutionContext<'_>,
        state: &WorldState,
    ) -> Result<TransactionDispatch, Self::Error>;
}

/// Routes only system-class transactions to a registered authority-backed
/// operation implementation.
#[derive(Debug, Clone, Copy)]
pub struct SystemDispatcher<O> {
    operation: O,
}

impl<O> SystemDispatcher<O> {
    pub const fn new(operation: O) -> Self {
        Self { operation }
    }
}

#[derive(Debug)]
pub enum SystemDispatchError<E> {
    Context(DispatchContextError),
    UnsupportedAction,
    Operation(E),
}

impl<O> TransactionExecutor for SystemDispatcher<O>
where
    O: SystemOperation,
{
    type Error = SystemDispatchError<O::Error>;

    fn execute(
        &self,
        transaction: &SignedTransaction,
        action: &TransactionAction,
        context: TransactionExecutionContext<'_>,
        state: &WorldState,
    ) -> Result<TransactionDispatch, Self::Error> {
        super::validate_dispatch_context(transaction, context, true)
            .map_err(SystemDispatchError::Context)?;
        let TransactionAction::System {
            authorization_id,
            operation,
        } = action
        else {
            return Err(SystemDispatchError::UnsupportedAction);
        };
        self.operation
            .execute_system(authorization_id, operation, transaction, context, state)
            .map_err(SystemDispatchError::Operation)
    }
}

impl<E: std::fmt::Display> std::fmt::Display for SystemDispatchError<E> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Context(error) => write!(formatter, "invalid system context: {error}"),
            Self::UnsupportedAction => write!(formatter, "unsupported system action"),
            Self::Operation(error) => write!(formatter, "system operation rejected: {error}"),
        }
    }
}

impl<E: std::fmt::Display + std::fmt::Debug> std::error::Error for SystemDispatchError<E> {}
