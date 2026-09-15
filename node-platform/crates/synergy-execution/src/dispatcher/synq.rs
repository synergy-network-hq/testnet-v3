use synergy_state::WorldState;
use synergy_transaction::{SignedTransaction, TransactionAction};

use super::{
    DispatchContextError, TransactionDispatch, TransactionExecutionContext, TransactionExecutor,
};

/// Deterministic SynQ execution implementation. Artifact validation and VM
/// semantics are supplied by the registered canonical SynQ runtime.
pub trait SynqRuntime {
    type Error: std::fmt::Display;

    fn execute_synq(
        &self,
        artifact: &[u8],
        input: &[u8],
        transaction: &SignedTransaction,
        context: TransactionExecutionContext<'_>,
        state: &WorldState,
    ) -> Result<TransactionDispatch, Self::Error>;
}

/// Rejects non-SynQ and system-classified actions before invoking a SynQ VM.
#[derive(Debug, Clone, Copy)]
pub struct SynqDispatcher<R> {
    runtime: R,
}

impl<R> SynqDispatcher<R> {
    pub const fn new(runtime: R) -> Self {
        Self { runtime }
    }
}

#[derive(Debug)]
pub enum SynqDispatchError<E> {
    Context(DispatchContextError),
    UnsupportedAction,
    Runtime(E),
}

impl<R> TransactionExecutor for SynqDispatcher<R>
where
    R: SynqRuntime,
{
    type Error = SynqDispatchError<R::Error>;

    fn execute(
        &self,
        transaction: &SignedTransaction,
        action: &TransactionAction,
        context: TransactionExecutionContext<'_>,
        state: &WorldState,
    ) -> Result<TransactionDispatch, Self::Error> {
        super::validate_dispatch_context(transaction, context, false)
            .map_err(SynqDispatchError::Context)?;
        let TransactionAction::Synq { artifact, input } = action else {
            return Err(SynqDispatchError::UnsupportedAction);
        };
        self.runtime
            .execute_synq(artifact, input, transaction, context, state)
            .map_err(SynqDispatchError::Runtime)
    }
}

impl<E: std::fmt::Display> std::fmt::Display for SynqDispatchError<E> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Context(error) => write!(formatter, "invalid SynQ context: {error}"),
            Self::UnsupportedAction => write!(formatter, "unsupported SynQ action"),
            Self::Runtime(error) => write!(formatter, "SynQ runtime rejected action: {error}"),
        }
    }
}

impl<E: std::fmt::Display + std::fmt::Debug> std::error::Error for SynqDispatchError<E> {}
