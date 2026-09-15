use crate::{PosyError, PosyResult, SimplifiedEpochContext};

pub fn expected_proposer(
    context: &SimplifiedEpochContext,
    height: u64,
    round: u64,
) -> PosyResult<&str> {
    context
        .authorized_proposer(height, round)
        .map_err(|error| PosyError::invalid(error.to_string()))
}
