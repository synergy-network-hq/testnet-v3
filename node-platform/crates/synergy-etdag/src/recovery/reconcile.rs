use std::collections::BTreeSet;

use crate::{EtdagDigest, EtdagError, EtdagGraph};

use super::MissingArtifacts;

pub fn reconcile_artifacts(
    graph: &EtdagGraph,
    protected_input_ids: &BTreeSet<EtdagDigest>,
    certified_vertex_ids: &BTreeSet<EtdagDigest>,
) -> Result<MissingArtifacts, EtdagError> {
    let mut missing = MissingArtifacts::default();
    let graph_ids = graph
        .vertices()
        .map(|vertex| vertex.vertex_id.clone())
        .collect::<BTreeSet<_>>();
    for vertex in graph.vertices() {
        vertex.validate()?;
        if !protected_input_ids.contains(&vertex.envelope.envelope_id) {
            missing
                .protected_inputs
                .insert(vertex.envelope.envelope_id.clone());
        }
        for parent in &vertex.parents {
            if !graph_ids.contains(parent) {
                missing.parent_vertices.insert(parent.clone());
            }
        }
        if !certified_vertex_ids.contains(&vertex.vertex_id) {
            missing.certificates.insert(vertex.vertex_id.clone());
        }
    }
    Ok(missing)
}
