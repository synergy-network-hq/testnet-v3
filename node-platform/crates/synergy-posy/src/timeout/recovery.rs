use crate::{PosyResult, SimplifiedTimeoutCertificate};

pub fn recovery_parent(
    timeout: &SimplifiedTimeoutCertificate,
) -> PosyResult<crate::SimplifiedFinalityParent> {
    timeout.highest_parent()
}
