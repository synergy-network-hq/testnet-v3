use serde::{Deserialize, Serialize};

use super::VerifiedProtectedCut;
use crate::{canonical_content_blind_order, EtdagDigest, EtdagError, EtdagParameters};

/// Deterministic commitment to the exact eligible set and governed selection.
/// Shape validation is not cutoff authentication; derive from a verified cut.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeterministicProtectedBatch {
    pub context_root: EtdagDigest,
    pub target_height: u64,
    pub cut_root: EtdagDigest,
    pub eligible_set_root: EtdagDigest,
    pub order_seed: EtdagDigest,
    pub ordered_transaction_ids: Vec<EtdagDigest>,
    pub order_root: EtdagDigest,
    pub protected_gas: u64,
    pub protected_bytes: u64,
    pub protected_batch_root: EtdagDigest,
}

impl DeterministicProtectedBatch {
    pub fn derive(
        cut: &VerifiedProtectedCut,
        order_seed: &EtdagDigest,
        parameters: &EtdagParameters,
    ) -> Result<Self, EtdagError> {
        parameters.validate()?;
        order_seed.validate()?;
        if order_seed.is_zero() {
            return Err(EtdagError::InvalidDigest);
        }
        let proof = cut.proof();
        let ordered = canonical_content_blind_order(
            &proof.eligible_envelopes,
            order_seed,
            parameters.max_protected_gas,
            parameters.max_protected_bytes,
        )?;
        let protected_gas = ordered.iter().try_fold(0u64, |sum, item| {
            sum.checked_add(item.gas_class_units)
                .ok_or(EtdagError::InvalidCapacity)
        })?;
        let protected_bytes = ordered.iter().try_fold(0u64, |sum, item| {
            sum.checked_add(item.ciphertext_bytes)
                .ok_or(EtdagError::InvalidCapacity)
        })?;
        let ordered_transaction_ids: Vec<_> =
            ordered.into_iter().map(|item| item.tx_commitment).collect();
        let order_root = crate::protected_order_root(&ordered_transaction_ids)?;
        let mut batch = Self {
            context_root: proof.context_root.clone(),
            target_height: proof.target_height,
            cut_root: proof.semantic_root.clone(),
            eligible_set_root: EtdagDigest::from_canonical(
                "PoSy/ProtectedPipeline/EligibleSet/v1",
                &proof.eligible_envelopes,
            )?,
            order_seed: order_seed.clone(),
            ordered_transaction_ids,
            order_root,
            protected_gas,
            protected_bytes,
            protected_batch_root: EtdagDigest::from_domain_bytes("uninitialized", &[]),
        };
        batch.protected_batch_root = batch.semantic_root()?;
        batch.validate()?;
        Ok(batch)
    }

    pub fn semantic_root(&self) -> Result<EtdagDigest, EtdagError> {
        EtdagDigest::from_canonical(
            "SYNERGY_ETDAG_PROTECTED_BATCH_V2",
            &(
                &self.context_root,
                self.target_height,
                &self.cut_root,
                &self.eligible_set_root,
                &self.order_seed,
                &self.ordered_transaction_ids,
                &self.order_root,
                self.protected_gas,
                self.protected_bytes,
            ),
        )
    }

    pub fn validate(&self) -> Result<(), EtdagError> {
        for root in [
            &self.context_root,
            &self.cut_root,
            &self.eligible_set_root,
            &self.order_seed,
            &self.order_root,
            &self.protected_batch_root,
        ] {
            root.validate()?;
        }
        if self.target_height < 3
            || self.order_seed.is_zero()
            || (self.ordered_transaction_ids.is_empty()
                && (self.protected_gas != 0 || self.protected_bytes != 0))
        {
            return Err(EtdagError::InvalidExecutionInput);
        }
        let mut seen = std::collections::BTreeSet::new();
        for id in &self.ordered_transaction_ids {
            id.validate()?;
            if !seen.insert(id) {
                return Err(EtdagError::DuplicateEnvelope);
            }
        }
        if crate::protected_order_root(&self.ordered_transaction_ids)? != self.order_root
            || self.semantic_root()? != self.protected_batch_root
        {
            return Err(EtdagError::InvalidExecutionInput);
        }
        Ok(())
    }
}
