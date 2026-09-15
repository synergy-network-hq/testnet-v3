use synergy_block::BlockError;
use synergy_state::StateError;
use synergy_transaction::TransactionError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlockExecutionError {
    InvalidHeight,
    InvalidBlockId,
    InvalidFeeSchedule,
    Block(BlockError),
    Transaction {
        transaction_index: usize,
        source: TransactionError,
    },
    NetworkMismatch {
        transaction_index: usize,
    },
    Signature {
        transaction_index: usize,
        source: TransactionError,
    },
    Dispatcher {
        transaction_index: usize,
        message: String,
    },
    State {
        transaction_index: usize,
        source: StateError,
    },
    GasLimitExceeded {
        transaction_index: usize,
        used: u64,
        limit: u64,
    },
    FeeCapTooLow {
        transaction_index: usize,
        cap: u64,
        required: u64,
    },
    FeeCollectorIsSender {
        transaction_index: usize,
    },
    FeeOverflow {
        transaction_index: usize,
    },
    GasTotalOverflow,
    FeeTotalOverflow,
    InvalidReceipt {
        transaction_index: usize,
    },
    StateRoot(StateError),
    StateRootMismatch {
        expected: String,
        actual: String,
    },
    ReceiptMismatch,
}

impl std::fmt::Display for BlockExecutionError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for BlockExecutionError {}
