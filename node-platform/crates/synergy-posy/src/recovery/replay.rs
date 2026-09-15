use serde::{Deserialize, Serialize};

use crate::{is_hash, PosyError, PosyResult};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplayRecord {
    pub sequence: u64,
    pub height: u64,
    pub round: u64,
    pub record_root: String,
}

/// Validates a deterministic persisted replay sequence. Replay records are
/// evidence for rebuilding the one PoSy driver; they do not make decisions.
pub fn validate_replay(records: &[ReplayRecord]) -> PosyResult<()> {
    let mut previous: Option<&ReplayRecord> = None;
    for record in records {
        if !is_hash(&record.record_root) {
            return Err(PosyError::invalid("replay record has an invalid root"));
        }
        if let Some(prior) = previous {
            if record.sequence != prior.sequence.saturating_add(1)
                || (record.height, record.round) < (prior.height, prior.round)
            {
                return Err(PosyError::invalid(
                    "replay records are missing, duplicated, or out of order",
                ));
            }
        }
        previous = Some(record);
    }
    Ok(())
}
