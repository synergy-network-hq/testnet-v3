use std::collections::{BTreeMap, BTreeSet};

use crate::{AvailabilityCertificate, EtdagDigest, EtdagError, EtdagGraph};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AvailabilityRecoveryPlan {
    pub missing_certificates: BTreeSet<EtdagDigest>,
    pub orphan_certificates: BTreeSet<EtdagDigest>,
}

pub fn availability_recovery_plan(
    graph: &EtdagGraph,
    certificates: &BTreeMap<EtdagDigest, AvailabilityCertificate>,
) -> Result<AvailabilityRecoveryPlan, EtdagError> {
    let graph_ids = graph
        .vertices()
        .map(|vertex| vertex.vertex_id.clone())
        .collect::<BTreeSet<_>>();
    let mut certificate_ids = BTreeSet::new();
    for (vertex_id, certificate) in certificates {
        vertex_id.validate()?;
        certificate.context_root.validate()?;
        certificate.vertex_id.validate()?;
        if &certificate.vertex_id != vertex_id || certificate.context_root != *graph.context_root()
        {
            return Err(EtdagError::ContextMismatch);
        }
        certificate_ids.insert(vertex_id.clone());
    }
    Ok(AvailabilityRecoveryPlan {
        missing_certificates: graph_ids.difference(&certificate_ids).cloned().collect(),
        orphan_certificates: certificate_ids.difference(&graph_ids).cloned().collect(),
    })
}
