mod governance;
mod native;
mod sxcp;
mod synq;
mod synq_adapter;
mod system;

use synergy_state::{StateDiff, WorldState};
use synergy_transaction::{NetworkBinding, SignedTransaction, TransactionAction};

pub use governance::{GovernanceDispatchError, GovernanceDispatcher, GovernanceOperation};
pub use native::{
    CanonicalNativeDispatchError, NativeDispatchError, NativeDispatcher, NativeOperation,
    NativeTransferDispatcher,
};
pub use sxcp::{SxcpDispatchError, SxcpDispatcher, SxcpExecutor};
pub use synq::{SynqDispatchError, SynqDispatcher, SynqRuntime};
pub use synq_adapter::{SynqHostFactory, SynqRuntimeAdapter};
pub use system::{SystemDispatchError, SystemDispatcher, SystemOperation};

/// Immutable block position and network binding supplied to transaction
/// execution. It intentionally contains no vote, quorum, or finality state.
#[derive(Debug, Clone, Copy)]
pub struct TransactionExecutionContext<'a> {
    pub network: &'a NetworkBinding,
    pub block_height: u64,
    pub transaction_index: u32,
}

/// Deterministic state transition and resource use produced by one action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransactionDispatch {
    pub state_diff: StateDiff,
    pub gas_used: u64,
}

/// Action-specific execution boundary. Implementations inspect the current
/// speculative state and return a diff; the scheduler owns atomic application.
pub trait TransactionExecutor {
    type Error: std::fmt::Display;

    fn execute(
        &self,
        transaction: &SignedTransaction,
        action: &TransactionAction,
        context: TransactionExecutionContext<'_>,
        state: &WorldState,
    ) -> Result<TransactionDispatch, Self::Error>;
}

/// Canonical action family selected for one signed transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActionRoute {
    Native,
    Synq,
    Sxcp,
    Governance,
    System,
}

/// Routes every protocol action to its owning deterministic executor.
///
/// The router does not apply state or claim finality; the block scheduler
/// retains atomic state application and PoSy retains consensus authority.
#[derive(Debug)]
pub struct CanonicalTransactionDispatcher<N, Q, X, G, S> {
    pub native: N,
    pub synq: Q,
    pub sxcp: X,
    pub governance: G,
    pub system: S,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoutedDispatchError {
    pub route: ActionRoute,
    pub message: String,
}

impl<N, Q, X, G, S> TransactionExecutor for CanonicalTransactionDispatcher<N, Q, X, G, S>
where
    N: TransactionExecutor,
    Q: TransactionExecutor,
    X: TransactionExecutor,
    G: TransactionExecutor,
    S: TransactionExecutor,
{
    type Error = RoutedDispatchError;

    fn execute(
        &self,
        transaction: &SignedTransaction,
        action: &TransactionAction,
        context: TransactionExecutionContext<'_>,
        state: &WorldState,
    ) -> Result<TransactionDispatch, Self::Error> {
        let (route, result) = match action {
            TransactionAction::Transfer | TransactionAction::Native { .. } => (
                ActionRoute::Native,
                self.native
                    .execute(transaction, action, context, state)
                    .map_err(|error| error.to_string()),
            ),
            TransactionAction::Synq { .. } => (
                ActionRoute::Synq,
                self.synq
                    .execute(transaction, action, context, state)
                    .map_err(|error| error.to_string()),
            ),
            TransactionAction::Sxcp { .. } => (
                ActionRoute::Sxcp,
                self.sxcp
                    .execute(transaction, action, context, state)
                    .map_err(|error| error.to_string()),
            ),
            TransactionAction::Governance { .. } => (
                ActionRoute::Governance,
                self.governance
                    .execute(transaction, action, context, state)
                    .map_err(|error| error.to_string()),
            ),
            TransactionAction::System { .. } => (
                ActionRoute::System,
                self.system
                    .execute(transaction, action, context, state)
                    .map_err(|error| error.to_string()),
            ),
        };
        result.map_err(|message| RoutedDispatchError { route, message })
    }
}

impl std::fmt::Display for RoutedDispatchError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "{:?} dispatch failed: {}",
            self.route, self.message
        )
    }
}

impl std::error::Error for RoutedDispatchError {}

/// Shared execution admission checks. Concrete action handlers must use this
/// before touching speculative state; signature verification remains owned by
/// the block scheduler.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DispatchContextError {
    WrongNetwork,
    InvalidBlockHeight,
    WrongTransactionClass,
    InvalidTransaction,
}

pub(crate) fn validate_dispatch_context(
    transaction: &SignedTransaction,
    context: TransactionExecutionContext<'_>,
    requires_system_class: bool,
) -> Result<(), DispatchContextError> {
    transaction
        .validate_structure()
        .map_err(|_| DispatchContextError::InvalidTransaction)?;
    if transaction.unsigned.network != *context.network {
        return Err(DispatchContextError::WrongNetwork);
    }
    if context.block_height == 0 {
        return Err(DispatchContextError::InvalidBlockHeight);
    }
    let is_system = matches!(
        transaction.unsigned.class,
        synergy_transaction::TransactionClass::System
    );
    if is_system != requires_system_class {
        return Err(DispatchContextError::WrongTransactionClass);
    }
    Ok(())
}

impl std::fmt::Display for DispatchContextError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for DispatchContextError {}
