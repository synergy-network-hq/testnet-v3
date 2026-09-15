use std::collections::{BTreeMap, BTreeSet};

use crate::{EtdagDigest, EtdagError, EtdagGraph};

/// Canonical topological traversal. Independent vertices are ordered by their
/// content-blind order key then by vertex digest, never arrival order.
pub fn deterministic_topological_order(graph: &EtdagGraph) -> Result<Vec<EtdagDigest>, EtdagError> {
    let mut remaining = graph
        .vertices()
        .map(|vertex| {
            (
                vertex.vertex_id.clone(),
                (
                    vertex.parents.iter().cloned().collect::<BTreeSet<_>>(),
                    vertex.envelope.content_blind_order_key.clone(),
                ),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let mut emitted = BTreeSet::new();
    let mut order = Vec::with_capacity(remaining.len());

    while !remaining.is_empty() {
        let candidate = remaining
            .iter()
            .filter(|(_, (parents, _))| parents.iter().all(|parent| emitted.contains(parent)))
            .map(|(id, (_, key))| (key.clone(), id.clone()))
            .min();
        let Some((_, id)) = candidate else {
            return Err(EtdagError::Cycle);
        };
        remaining.remove(&id);
        emitted.insert(id.clone());
        order.push(id);
    }
    Ok(order)
}
