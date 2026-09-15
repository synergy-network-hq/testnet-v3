use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FrozenValidator {
    pub validator_id: String,
    pub frozen_voting_weight: u128,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QuorumError {
    EmptyValidatorSet,
    DuplicateValidator,
    ZeroWeight,
    UnknownSigner(String),
    StrictDistinctSigner { signed: usize, total: usize },
    StrictFrozenWeight { signed: u128, total: u128 },
}
