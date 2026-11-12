//! Content-blind processing groups, independent of eventual inclusion height.
//! These are commitments, not certificates. Native validation authenticates
//! encrypted DAG availability before a group can enter a PoSy candidate.
use serde::{Deserialize, Serialize};

use crate::{CertifiedEnvelopeRef, EtdagDigest, EtdagError};

pub const MAX_PROCESSING_GROUP_ITEMS: usize = 4096;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessingGroupMember {
    pub processing_context_root: EtdagDigest,
    pub authorization_root: EtdagDigest,
    pub envelope: CertifiedEnvelopeRef,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessingOrderGroup {
    pub group_version: u32,
    pub namespace_root: EtdagDigest,
    pub group_number: u64,
    pub previous_group_root: EtdagDigest,
    pub order_seed: EtdagDigest,
    pub members: Vec<ProcessingGroupMember>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessingGroupCommitment {
    pub group_number: u64,
    pub group_root: EtdagDigest,
    pub previous_group_root: EtdagDigest,
}

pub fn processing_genesis_group_root(namespace: &EtdagDigest) -> Result<EtdagDigest, EtdagError> {
    nonzero(namespace)?;
    EtdagDigest::from_canonical("SYNERGY_ETDAG_PROCESSING_GENESIS_GROUP_V1", namespace)
}

fn nonzero(root: &EtdagDigest) -> Result<(), EtdagError> {
    root.validate()?;
    if root.is_zero() {
        return Err(EtdagError::InvalidDigest);
    }
    Ok(())
}

impl ProcessingGroupCommitment {
    pub fn validate(&self) -> Result<(), EtdagError> {
        if self.group_number == 0 {
            return Err(EtdagError::InvalidExecutionInput);
        }
        nonzero(&self.group_root)?;
        nonzero(&self.previous_group_root)
    }
}

impl ProcessingOrderGroup {
    /// Every member is already immutable and encrypted. This uses the existing
    /// certified-DAG round/dependency/nonce ordering, never local arrival time.
    /// The native caller reserves graph and serialization scratch before use.
    pub fn validate(&self) -> Result<(), EtdagError> {
        for root in [
            &self.namespace_root,
            &self.previous_group_root,
            &self.order_seed,
        ] {
            nonzero(root)?;
        }
        if self.group_version != 1
            || self.group_number == 0
            || self.members.len() > MAX_PROCESSING_GROUP_ITEMS
        {
            return Err(EtdagError::InvalidCapacity);
        }
        for member in &self.members {
            nonzero(&member.processing_context_root)?;
            nonzero(&member.authorization_root)?;
            let item = &member.envelope;
            nonzero(&item.tx_commitment)?;
            if item.sender_id.len() > 256
                || item.sender_id.contains(char::is_control)
                || item.nonce_slot == u64::MAX
                || item.protocol_dependencies.len() > 64
            {
                return Err(EtdagError::InvalidExecutionInput);
            }
            item.validate()?;
            for dependency in &item.protocol_dependencies {
                nonzero(dependency)?;
            }
        }
        let eligible = self
            .members
            .iter()
            .map(|member| member.envelope.clone())
            .collect::<Vec<_>>();
        let ordered =
            crate::canonical_content_blind_order(&eligible, &self.order_seed, u64::MAX, u64::MAX)?;
        if ordered != eligible {
            return Err(EtdagError::InvalidExecutionInput);
        }
        Ok(())
    }

    pub fn root(&self) -> Result<EtdagDigest, EtdagError> {
        self.validate()?;
        EtdagDigest::from_canonical("SYNERGY_ETDAG_PROCESSING_ORDER_GROUP_V1", self)
    }

    pub fn commitment(&self) -> Result<ProcessingGroupCommitment, EtdagError> {
        Ok(ProcessingGroupCommitment {
            group_number: self.group_number,
            group_root: self.root()?,
            previous_group_root: self.previous_group_root.clone(),
        })
    }
}
