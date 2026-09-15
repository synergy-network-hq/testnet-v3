use crate::{PosyError, PosyResult, SimplifiedTimeoutCertificate};

pub fn next_round(timeout: &SimplifiedTimeoutCertificate) -> PosyResult<u64> {
    timeout
        .context
        .round
        .checked_add(1)
        .ok_or_else(|| PosyError::invalid("round overflow"))
}
