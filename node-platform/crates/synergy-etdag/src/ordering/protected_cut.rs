use serde::{Deserialize, Serialize};

use crate::{EtdagDigest, EtdagError};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtectedCutProof {
    pub proof_version: u32,
    pub context_root: EtdagDigest,
    pub target_height: u64,
    pub certified_vertices: Vec<EtdagDigest>,
    pub semantic_root: EtdagDigest,
}

impl ProtectedCutProof {
    pub fn new(
        context_root: EtdagDigest,
        target_height: u64,
        mut certified_vertices: Vec<EtdagDigest>,
    ) -> Result<Self, EtdagError> {
        certified_vertices.sort();
        if certified_vertices.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(EtdagError::DuplicateVertex("protected cut".into()));
        }
        let semantic_root = EtdagDigest::from_canonical(
            "SYNERGY_ETDAG_PROTECTED_CUT_V1",
            &(&context_root, target_height, &certified_vertices),
        )?;
        let proof = Self {
            proof_version: 1,
            context_root,
            target_height,
            certified_vertices,
            semantic_root,
        };
        proof.validate()?;
        Ok(proof)
    }

    pub fn validate(&self) -> Result<(), EtdagError> {
        self.context_root.validate()?;
        self.semantic_root.validate()?;
        if self.proof_version != 1 || self.target_height == 0 || self.certified_vertices.is_empty()
        {
            return Err(EtdagError::InvalidExecutionInput);
        }
        if self
            .certified_vertices
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
        {
            return Err(EtdagError::InvalidExecutionInput);
        }
        let expected = EtdagDigest::from_canonical(
            "SYNERGY_ETDAG_PROTECTED_CUT_V1",
            &(
                &self.context_root,
                self.target_height,
                &self.certified_vertices,
            ),
        )?;
        if expected != self.semantic_root {
            return Err(EtdagError::ConflictingArtifact(
                "protected cut semantic root mismatch".into(),
            ));
        }
        Ok(())
    }
}
