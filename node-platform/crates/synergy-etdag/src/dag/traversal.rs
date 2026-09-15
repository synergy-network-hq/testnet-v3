use std::collections::{BTreeMap, BTreeSet, VecDeque};

use crate::{EtdagDigest, EtdagError, EtdagGraph};

pub fn ancestors(
    graph: &EtdagGraph,
    vertex_id: &EtdagDigest,
    max_visited: usize,
) -> Result<BTreeSet<EtdagDigest>, EtdagError> {
    let start = graph
        .get(vertex_id)
        .ok_or_else(|| EtdagError::MissingArtifact(vertex_id.0.clone()))?;
    let mut pending = VecDeque::from(start.parents.clone());
    traverse(graph, &mut pending, max_visited, |vertex| {
        vertex.parents.clone()
    })
}

pub fn descendants(
    graph: &EtdagGraph,
    vertex_id: &EtdagDigest,
    max_visited: usize,
) -> Result<BTreeSet<EtdagDigest>, EtdagError> {
    if !graph.contains(vertex_id) {
        return Err(EtdagError::MissingArtifact(vertex_id.0.clone()));
    }
    let mut children = BTreeMap::<EtdagDigest, Vec<EtdagDigest>>::new();
    for vertex in graph.vertices() {
        for parent in &vertex.parents {
            children
                .entry(parent.clone())
                .or_default()
                .push(vertex.vertex_id.clone());
        }
    }
    let mut pending = VecDeque::from(children.get(vertex_id).cloned().unwrap_or_default());
    traverse(graph, &mut pending, max_visited, |vertex| {
        children.get(&vertex.vertex_id).cloned().unwrap_or_default()
    })
}

fn traverse(
    graph: &EtdagGraph,
    pending: &mut VecDeque<EtdagDigest>,
    max_visited: usize,
    next: impl Fn(&crate::TransactionVertex) -> Vec<EtdagDigest>,
) -> Result<BTreeSet<EtdagDigest>, EtdagError> {
    if max_visited == 0 {
        return Err(EtdagError::InvalidCapacity);
    }
    let mut visited = BTreeSet::new();
    while let Some(id) = pending.pop_front() {
        if !visited.insert(id.clone()) {
            continue;
        }
        if visited.len() > max_visited {
            return Err(EtdagError::InvalidCapacity);
        }
        let vertex = graph
            .get(&id)
            .ok_or_else(|| EtdagError::MissingArtifact(id.0.clone()))?;
        pending.extend(next(vertex));
    }
    Ok(visited)
}
