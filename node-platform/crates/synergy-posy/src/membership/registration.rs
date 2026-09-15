use serde::{Deserialize, Serialize};

use crate::{MembershipAuthority, PosyError, PosyResult, ValidatorRecord, ValidatorStatus};

/// A staged shadow-validator registration for a future frozen epoch.
///
/// Registration alone grants no voting, proposal, quorum, or finality power.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidatorRegistration {
    pub target_epoch: u64,
    pub validator: ValidatorRecord,
    pub membership_authority_id: String,
}

impl ValidatorRegistration {
    /// Checks that the shadow record is bound to the supplied next-epoch authority.
    pub fn validate(&self, authority: &MembershipAuthority) -> PosyResult<()> {
        self.validator.validate()?;
        if self.target_epoch != authority.target_epoch
            || self.validator.status != ValidatorStatus::Shadow
            || self.membership_authority_id != authority.id()?
        {
            return Err(PosyError::invalid(
                "validator registration is not a shadow record bound to membership authority",
            ));
        }
        Ok(())
    }
}
