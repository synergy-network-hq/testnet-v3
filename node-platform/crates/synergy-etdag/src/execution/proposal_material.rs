use crate::{EtdagDigest, EtdagError};
use serde::{Deserialize, Serialize};

/// The approved V2 commitments: executed H, certified next batch H+1,
/// and the future VC(H) close boundary for H+2 (never a completed cutoff). The
/// serialized value is committed by the ordinary PoSy protected-execution root.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProtectedProposalMaterial {
    pub material_version: u32,
    pub height: u64,
    pub execution_root: EtdagDigest,
    pub next_batch_root: EtdagDigest,
    pub cutoff_boundary_root: EtdagDigest,
}

impl ProtectedProposalMaterial {
    pub fn validate(&self) -> Result<(), EtdagError> {
        if self.material_version != 2 || self.height == 0 || self.height.checked_add(2).is_none() {
            return Err(EtdagError::InvalidExecutionInput);
        }
        for root in [
            &self.execution_root,
            &self.next_batch_root,
            &self.cutoff_boundary_root,
        ] {
            root.validate()?;
            if root.is_zero() {
                return Err(EtdagError::InvalidDigest);
            }
        }
        Ok(())
    }

    pub fn commitment_bytes(&self) -> Result<Vec<u8>, EtdagError> {
        self.validate()?;
        serde_json::to_vec(&("SYNERGY_POSY_PROTECTED_MATERIAL_V2", self))
            .map_err(|error| EtdagError::Corrupt(error.to_string()))
    }
}

/// Separate signed material for the explicitly governed processing profile.
/// No future ordering group is required to produce a block. The parent ready
/// view fixes selection, and `transition_root` commits the exact verified
/// lifecycle changes supplied with the candidate, including the empty change.
/// Structure validation is NOT readiness, transition or profile authorization.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessingProposalMaterial {
    pub material_version: u32,
    pub profile_id: String,
    pub height: u64,
    pub namespace_root: EtdagDigest,
    pub selection: super::ProcessingSelection,
    pub transition_root: EtdagDigest,
    /// The optional order/close actually supplied in this candidate. Absence
    /// imposes no dependency on unfinished processing or a future block.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ordered_group: Option<super::ProcessingGroupCommitment>,
}
impl ProcessingProposalMaterial {
    pub fn validate(&self) -> Result<(), EtdagError> {
        if let Some(group) = &self.ordered_group {
            group.validate()?;
        }
        if self.material_version != 1
            || self.profile_id != crate::PROCESSING_PROFILE_ID
            || self.height == 0
            || self.selection.maximum_gas == 0
            || self.selection.maximum_bytes == 0
            || self.selection.item_indices.len() > 4096
            || self
                .selection
                .item_indices
                .iter()
                .any(|index| *index >= 4096)
            || self
                .selection
                .item_indices
                .windows(2)
                .any(|pair| pair[0] >= pair[1])
            || self.selection.protected_gas > self.selection.maximum_gas
            || self.selection.protected_bytes > self.selection.maximum_bytes
            || (self.selection.item_indices.is_empty()
                != (self.selection.protected_gas == 0 && self.selection.protected_bytes == 0))
            || (!self.selection.item_indices.is_empty()
                && (self.selection.protected_gas == 0 || self.selection.protected_bytes == 0))
        {
            return Err(EtdagError::InvalidExecutionInput);
        }
        for root in [
            &self.namespace_root,
            &self.selection.parent_ready_root,
            &self.transition_root,
        ] {
            root.validate()?;
            if root.is_zero() {
                return Err(EtdagError::InvalidDigest);
            }
        }
        Ok(())
    }

    pub fn commitment_bytes(&self) -> Result<Vec<u8>, EtdagError> {
        self.validate()?;
        serde_json::to_vec(&("SYNERGY_POSY_PROCESSING_MATERIAL_V1", self))
            .map_err(|error| EtdagError::Corrupt(error.to_string()))
    }
}

/// Candidate persistence/transport preserves old material bytes exactly. The
/// governed native owner must explicitly choose and verify the matching profile;
/// decoding a new material never activates it or reinterprets a legacy batch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum CandidateProtectedMaterial {
    Legacy(ProtectedProposalMaterial),
    Processing(ProcessingProposalMaterial),
}
impl CandidateProtectedMaterial {
    pub fn height(&self) -> u64 {
        match self {
            Self::Legacy(material) => material.height,
            Self::Processing(material) => material.height,
        }
    }
    pub fn validate(&self) -> Result<(), EtdagError> {
        match self {
            Self::Legacy(material) => material.validate(),
            Self::Processing(material) => material.validate(),
        }
    }
    pub fn commitment_bytes(&self) -> Result<Vec<u8>, EtdagError> {
        match self {
            Self::Legacy(material) => material.commitment_bytes(),
            Self::Processing(material) => material.commitment_bytes(),
        }
    }
    pub fn as_legacy(&self) -> Option<&ProtectedProposalMaterial> {
        match self {
            Self::Legacy(material) => Some(material),
            Self::Processing(_) => None,
        }
    }
}
impl From<ProtectedProposalMaterial> for CandidateProtectedMaterial {
    fn from(value: ProtectedProposalMaterial) -> Self {
        Self::Legacy(value)
    }
}
impl From<ProcessingProposalMaterial> for CandidateProtectedMaterial {
    fn from(value: ProcessingProposalMaterial) -> Self {
        Self::Processing(value)
    }
}

/// The PoSy owner authenticates this bounded evidence before reveal. The
/// validation proof is an existing PoSy proof, never an ETDAG batch vote.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ParentProposalRevealEvidence {
    pub material: ProtectedProposalMaterial,
    pub next_batch: crate::DeterministicProtectedBatch,
    pub validation_proof: Vec<u8>,
}

#[cfg(test)]
mod processing_material_tests {
    use super::*;
    fn root(label: &str) -> EtdagDigest {
        EtdagDigest::from_domain_bytes("processing-material-fixture", label.as_bytes())
    }
    fn processing() -> ProcessingProposalMaterial {
        ProcessingProposalMaterial {
            material_version: 1,
            profile_id: crate::PROCESSING_PROFILE_ID.into(),
            height: 100,
            namespace_root: root("fresh-chain"),
            selection: super::super::ProcessingReadyView {
                namespace_root: root("fresh-chain"),
                items: vec![],
            }
            .select(1_000_000, 1024 * 1024)
            .unwrap(),
            transition_root: root("verified-empty-transition"),
            ordered_group: None,
        }
    }
    #[test]
    fn processing_material_is_distinct_and_legacy_bytes_are_preserved() {
        let legacy = ProtectedProposalMaterial {
            material_version: 2,
            height: 100,
            execution_root: root("execution"),
            next_batch_root: root("next"),
            cutoff_boundary_root: root("boundary"),
        };
        let carrier: CandidateProtectedMaterial = legacy.clone().into();
        assert_eq!(
            serde_json::to_vec(&carrier).unwrap(),
            serde_json::to_vec(&legacy).unwrap()
        );
        assert_eq!(
            carrier.commitment_bytes().unwrap(),
            legacy.commitment_bytes().unwrap()
        );
        let restored: CandidateProtectedMaterial =
            serde_json::from_slice(&serde_json::to_vec(&legacy).unwrap()).unwrap();
        assert_eq!(restored, carrier);
        let processing = processing();
        let encoded = serde_json::to_vec(&processing).unwrap();
        assert!(serde_json::from_slice::<ProtectedProposalMaterial>(&encoded).is_err());
        let restored: CandidateProtectedMaterial = serde_json::from_slice(&encoded).unwrap();
        restored.validate().unwrap();
        assert!(restored.as_legacy().is_none());
        assert_ne!(
            carrier.commitment_bytes().unwrap(),
            restored.commitment_bytes().unwrap()
        );
        // Future-height material is absent, not an invented empty legacy cut.
        let value = serde_json::to_value(&processing).unwrap();
        assert!(value.get("next_batch_root").is_none());
        assert!(value.get("cutoff_boundary_root").is_none());
    }
    #[test]
    fn processing_material_rejects_profile_confusion_forged_empty_totals_and_unbounded_selection() {
        let original = processing();
        let mut changed = original.clone();
        changed.material_version = 2;
        assert!(changed.validate().is_err());
        changed = original.clone();
        changed.profile_id = "legacy".into();
        assert!(changed.validate().is_err());
        changed = original.clone();
        changed.selection.protected_gas = 1;
        assert!(changed.validate().is_err());
        changed = original.clone();
        changed.selection.item_indices = vec![0];
        assert!(changed.validate().is_err());
        changed.selection.protected_gas = 1;
        changed.selection.protected_bytes = 1;
        changed.validate().unwrap();
        changed.selection.item_indices = vec![0, 0];
        assert!(changed.validate().is_err());
        changed.selection.item_indices = vec![4096];
        assert!(changed.validate().is_err());
        changed = original;
        changed.transition_root = EtdagDigest("0".repeat(128));
        assert!(changed.validate().is_err());
    }
}
