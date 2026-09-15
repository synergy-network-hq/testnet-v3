use std::collections::BTreeSet;

use crate::EtdagDigest;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MissingArtifacts {
    pub protected_inputs: BTreeSet<EtdagDigest>,
    pub parent_vertices: BTreeSet<EtdagDigest>,
    pub certificates: BTreeSet<EtdagDigest>,
}

impl MissingArtifacts {
    pub fn is_empty(&self) -> bool {
        self.protected_inputs.is_empty()
            && self.parent_vertices.is_empty()
            && self.certificates.is_empty()
    }

    pub fn len(&self) -> usize {
        self.protected_inputs.len() + self.parent_vertices.len() + self.certificates.len()
    }
}
