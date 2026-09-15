use std::collections::{BTreeMap, BTreeSet};

use crate::{TransportRoute, VerifiedTransportRegistry};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RegistryDelta {
    pub added: Vec<TransportRoute>,
    pub changed: Vec<TransportRoute>,
    pub removed_identities: Vec<String>,
}

pub fn reconcile_registries(
    current: &VerifiedTransportRegistry,
    next: &VerifiedTransportRegistry,
) -> Result<RegistryDelta, crate::SnapshotError> {
    if next.generation() < current.generation() {
        return Err(crate::SnapshotError::Rollback {
            received: next.generation(),
            current: current.generation(),
        });
    }
    let current_routes = current
        .routes()
        .map(|route| (route.identity.clone(), route))
        .collect::<BTreeMap<_, _>>();
    let next_routes = next
        .routes()
        .map(|route| (route.identity.clone(), route))
        .collect::<BTreeMap<_, _>>();
    let mut delta = RegistryDelta::default();
    for (identity, route) in &next_routes {
        match current_routes.get(identity) {
            None => delta.added.push((*route).clone()),
            Some(existing) if *existing != *route => delta.changed.push((*route).clone()),
            Some(_) => {}
        }
    }
    let next_ids = next_routes.keys().cloned().collect::<BTreeSet<_>>();
    delta.removed_identities = current_routes
        .keys()
        .filter(|identity| !next_ids.contains(*identity))
        .cloned()
        .collect();
    Ok(delta)
}
