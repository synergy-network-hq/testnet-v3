use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::{deterministic_topological_order, EtdagDigest, EtdagError, EtdagGraph};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EtdagCut {
    pub context_root: EtdagDigest,
    pub target_height: u64,
    pub ordered_vertex_ids: Vec<EtdagDigest>,
    pub cut_root: EtdagDigest,
}

pub fn certified_cut(
    graph: &EtdagGraph,
    certified: &BTreeSet<EtdagDigest>,
) -> Result<EtdagCut, EtdagError> {
    crate::dag::validate_graph(graph)?;
    let order = deterministic_topological_order(graph)?;
    let mut selected = Vec::new();
    let mut included = BTreeSet::new();
    for vertex_id in order {
        if !certified.contains(&vertex_id) {
            continue;
        }
        let vertex = graph
            .get(&vertex_id)
            .ok_or_else(|| EtdagError::MissingArtifact(vertex_id.0.clone()))?;
        if vertex
            .parents
            .iter()
            .any(|parent| !included.contains(parent))
        {
            return Err(EtdagError::MissingArtifact(
                "certified cut is not dependency closed".into(),
            ));
        }
        included.insert(vertex_id.clone());
        selected.push(vertex_id);
    }
    if selected.is_empty() {
        return Err(EtdagError::InsufficientAvailability {
            signed: 0,
            required: 1,
        });
    }
    let cut_root = EtdagDigest::from_canonical(
        "SYNERGY_ETDAG_CERTIFIED_CUT_V1",
        &(graph.context_root(), graph.target_height(), &selected),
    )?;
    Ok(EtdagCut {
        context_root: graph.context_root().clone(),
        target_height: graph.target_height(),
        ordered_vertex_ids: selected,
        cut_root,
    })
}
