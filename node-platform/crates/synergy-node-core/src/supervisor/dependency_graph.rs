use std::collections::{BTreeMap, BTreeSet};

use crate::SupervisorError;

use super::{ServiceId, ServiceSpec};

/// Validated acyclic service dependency graph.
#[derive(Debug, Clone)]
pub struct DependencyGraph {
    specs: BTreeMap<ServiceId, ServiceSpec>,
    startup_order: Vec<ServiceId>,
}

impl DependencyGraph {
    pub fn build(specs: impl IntoIterator<Item = ServiceSpec>) -> Result<Self, SupervisorError> {
        let mut by_id = BTreeMap::new();
        for spec in specs {
            let id = spec.id.clone();
            if by_id.insert(id.clone(), spec).is_some() {
                return Err(SupervisorError::DuplicateService(id));
            }
        }
        for spec in by_id.values() {
            for dependency in &spec.dependencies {
                if !by_id.contains_key(dependency) {
                    return Err(SupervisorError::UnknownDependency {
                        service: spec.id.clone(),
                        dependency: dependency.clone(),
                    });
                }
            }
        }

        let mut permanent = BTreeSet::new();
        let mut temporary = BTreeSet::new();
        let mut order = Vec::with_capacity(by_id.len());
        for id in by_id.keys() {
            visit(id, &by_id, &mut permanent, &mut temporary, &mut order)?;
        }

        Ok(Self {
            specs: by_id,
            startup_order: order,
        })
    }

    pub fn spec(&self, id: &ServiceId) -> Option<&ServiceSpec> {
        self.specs.get(id)
    }

    pub fn startup_order(&self) -> &[ServiceId] {
        &self.startup_order
    }

    pub fn shutdown_order(&self) -> impl DoubleEndedIterator<Item = &ServiceId> {
        self.startup_order.iter().rev()
    }
}

fn visit(
    id: &ServiceId,
    specs: &BTreeMap<ServiceId, ServiceSpec>,
    permanent: &mut BTreeSet<ServiceId>,
    temporary: &mut BTreeSet<ServiceId>,
    order: &mut Vec<ServiceId>,
) -> Result<(), SupervisorError> {
    if permanent.contains(id) {
        return Ok(());
    }
    if !temporary.insert(id.clone()) {
        return Err(SupervisorError::DependencyCycle(
            temporary.iter().cloned().collect(),
        ));
    }
    let spec = specs
        .get(id)
        .ok_or_else(|| SupervisorError::ServiceUnavailable(id.clone()))?;
    for dependency in &spec.dependencies {
        visit(dependency, specs, permanent, temporary, order)?;
    }
    temporary.remove(id);
    permanent.insert(id.clone());
    order.push(id.clone());
    Ok(())
}
