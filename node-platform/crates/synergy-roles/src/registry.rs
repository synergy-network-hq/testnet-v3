use std::collections::BTreeMap;

use crate::{NodeRole, RoleError, RoleProfile};

#[derive(Debug, Clone, Default)]
pub struct RoleRegistry {
    profiles: BTreeMap<NodeRole, RoleProfile>,
}

impl RoleRegistry {
    pub fn new(profiles: impl IntoIterator<Item = RoleProfile>) -> Result<Self, RoleError> {
        let mut registry = Self::default();
        for profile in profiles {
            registry.register(profile)?;
        }
        Ok(registry)
    }

    pub fn register(&mut self, profile: RoleProfile) -> Result<(), RoleError> {
        profile.validate()?;
        if self
            .profiles
            .insert(profile.role, profile.clone())
            .is_some()
        {
            return Err(RoleError::DuplicateRole(
                crate::role_id(profile.role).into(),
            ));
        }
        Ok(())
    }

    pub fn profile(&self, role: NodeRole) -> Result<&RoleProfile, RoleError> {
        self.profiles
            .get(&role)
            .ok_or_else(|| RoleError::UnknownRole(crate::role_id(role).into()))
    }

    pub fn iter(&self) -> impl Iterator<Item = &RoleProfile> {
        self.profiles.values()
    }
}
