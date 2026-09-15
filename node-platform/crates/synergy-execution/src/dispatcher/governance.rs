use synergy_state::WorldState;
use synergy_transaction::{SignedTransaction, TransactionAction};

use super::{
    DispatchContextError, TransactionDispatch, TransactionExecutionContext, TransactionExecutor,
};

/// Governed operation implementation supplied by the canonical governance
/// authority. The dispatcher never infers authorization from a role, VPN, or
/// transaction sender.
pub trait GovernanceOperation {
    type Error: std::fmt::Display;

    fn execute_governance(
        &self,
        authorization_id: &str,
        operation: &[u8],
        transaction: &SignedTransaction,
        context: TransactionExecutionContext<'_>,
        state: &WorldState,
    ) -> Result<TransactionDispatch, Self::Error>;
}

/// Routes only explicitly system-classified governance actions after the
/// scheduler has verified the transaction signature.
#[derive(Debug, Clone, Copy)]
pub struct GovernanceDispatcher<O> {
    operation: O,
}

impl<O> GovernanceDispatcher<O> {
    pub const fn new(operation: O) -> Self {
        Self { operation }
    }
}

#[derive(Debug)]
pub enum GovernanceDispatchError<E> {
    Context(DispatchContextError),
    UnsupportedAction,
    Operation(E),
}

impl<O> TransactionExecutor for GovernanceDispatcher<O>
where
    O: GovernanceOperation,
{
    type Error = GovernanceDispatchError<O::Error>;

    fn execute(
        &self,
        transaction: &SignedTransaction,
        action: &TransactionAction,
        context: TransactionExecutionContext<'_>,
        state: &WorldState,
    ) -> Result<TransactionDispatch, Self::Error> {
        super::validate_dispatch_context(transaction, context, true)
            .map_err(GovernanceDispatchError::Context)?;
        let TransactionAction::Governance {
            authorization_id,
            operation,
        } = action
        else {
            return Err(GovernanceDispatchError::UnsupportedAction);
        };
        self.operation
            .execute_governance(authorization_id, operation, transaction, context, state)
            .map_err(GovernanceDispatchError::Operation)
    }
}

impl<E: std::fmt::Display> std::fmt::Display for GovernanceDispatchError<E> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Context(error) => write!(formatter, "invalid governance context: {error}"),
            Self::UnsupportedAction => write!(formatter, "unsupported governance action"),
            Self::Operation(error) => write!(formatter, "governance operation rejected: {error}"),
        }
    }
}

impl<E: std::fmt::Display + std::fmt::Debug> std::error::Error for GovernanceDispatchError<E> {}
