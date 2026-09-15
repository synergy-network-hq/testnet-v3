/// All SynQ inputs must be explicitly committed by the enclosing transaction
/// and finalized block. This marker prevents VM callers from confusing execution
/// output with consensus finality.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeterministicContext {
    pub block_height: u64,
    pub transaction_index: u32,
}

impl DeterministicContext {
    pub const fn may_determine_finality(self) -> bool {
        false
    }
}
