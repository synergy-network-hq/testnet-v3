use std::collections::BTreeSet;

use crate::{Capability, RoleError, RoleProfile};

pub fn validate_profile_set(profiles: &[RoleProfile]) -> Result<(), RoleError> {
    if profiles.is_empty() {
        return Err(RoleError::Invalid("role profile set is empty".into()));
    }
    let mut roles = BTreeSet::new();
    for profile in profiles {
        profile.validate()?;
        if !roles.insert(profile.role) {
            return Err(RoleError::DuplicateRole(
                crate::role_id(profile.role).into(),
            ));
        }
        if profile
            .capabilities
            .iter()
            .any(|capability| capability.grants_consensus_authority())
        {
            return Err(RoleError::Invalid(
                "role capability attempted to grant consensus authority".into(),
            ));
        }
    }
    Ok(())
}
