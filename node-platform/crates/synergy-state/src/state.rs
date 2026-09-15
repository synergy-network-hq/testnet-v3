use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::StateError;

pub(crate) const STATE_RECORD: &str = "finalized-state.json";
pub(crate) const STATE_FORMAT: &str = "synergy-finalized-state-v1";

pub(crate) fn history_record(height: u64) -> String {
    format!("finalized-history/{height:020}.json")
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct WorldState {
    pub accounts: BTreeMap<String, crate::AccountState>,
    #[serde(default)]
    pub protocol: BTreeMap<String, Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FinalizedState {
    pub finalized_height: u64,
    pub finalized_block_id: String,
    pub state_root: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct DurableState {
    pub(crate) format: String,
    pub(crate) state: FinalizedState,
}

pub(crate) fn validate(state: &FinalizedState) -> Result<(), StateError> {
    if state.finalized_block_id.trim().is_empty() || state.state_root.trim().is_empty() {
        Err(StateError::InvalidCommitment)
    } else {
        Ok(())
    }
}
