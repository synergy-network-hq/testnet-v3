use std::collections::BTreeSet;

use crate::{deterministic_topological_order, EtdagDigest, EtdagError, EtdagGraph};

use super::{reconcile_artifacts, MissingArtifacts};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StartupRecoveryPlan {
    pub vertex_replay_order: Vec<EtdagDigest>,
    pub missing: MissingArtifacts,
    pub ready_for_live_ingress: bool,
}

pub fn build_startup_recovery_plan(
    graph: &EtdagGraph,
    protected_input_ids: &BTreeSet<EtdagDigest>,
    certified_vertex_ids: &BTreeSet<EtdagDigest>,
) -> Result<StartupRecoveryPlan, EtdagError> {
    crate::dag::validate_graph(graph)?;
    let vertex_replay_order = deterministic_topological_order(graph)?;
    let missing = reconcile_artifacts(graph, protected_input_ids, certified_vertex_ids)?;
    let ready_for_live_ingress = missing.is_empty();
    Ok(StartupRecoveryPlan {
        vertex_replay_order,
        missing,
        ready_for_live_ingress,
    })
}
