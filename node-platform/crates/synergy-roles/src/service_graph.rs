use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

use crate::{Capability, RoleError, RoleProfile};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ServiceId(pub String);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceBinding {
    pub service_id: ServiceId,
    pub required_capability: Capability,
    pub dependencies: BTreeSet<ServiceId>,
}

pub fn validate_service_graph(
    profile: &RoleProfile,
    services: &[ServiceBinding],
) -> Result<(), RoleError> {
    profile.validate()?;
    let ids = services
        .iter()
        .map(|service| service.service_id.clone())
        .collect::<BTreeSet<_>>();
    if ids.len() != services.len() {
        return Err(RoleError::Invalid("duplicate service id".into()));
    }
    for service in services {
        if service.service_id.0.trim().is_empty()
            || !profile.supports(service.required_capability)
            || service
                .dependencies
                .iter()
                .any(|dependency| !ids.contains(dependency))
        {
            return Err(RoleError::Invalid(format!(
                "invalid service binding for {}",
                service.service_id.0
            )));
        }
    }
    Ok(())
}
