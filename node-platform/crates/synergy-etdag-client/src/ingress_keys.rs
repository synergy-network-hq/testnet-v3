use synergy_etdag::{EtdagDigest, IngressKemKeyRecord, IngressKemKeyRegistry};

use crate::VerifiedTargetContext;

#[derive(Debug, Clone)]
pub struct ActiveIngressKeys {
    context_root: EtdagDigest,
    records: Vec<IngressKemKeyRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IngressKeyError {
    ContextMismatch,
    InvalidRegistry(String),
    NoActiveKeys,
}

impl ActiveIngressKeys {
    pub fn from_registry(
        target: &VerifiedTargetContext,
        registry: IngressKemKeyRegistry,
    ) -> Result<Self, IngressKeyError> {
        registry
            .validate_shape()
            .map_err(|error| IngressKeyError::InvalidRegistry(format!("{error:?}")))?;
        let context_root = target
            .context_root()
            .map_err(|error| IngressKeyError::InvalidRegistry(format!("{error:?}")))?;
        if registry.context_root != context_root
            || registry
                .root()
                .map_err(|error| IngressKeyError::InvalidRegistry(format!("{error:?}")))?
                != target.inner().ingress_kem_registry_root
        {
            return Err(IngressKeyError::ContextMismatch);
        }
        let records = registry
            .records
            .into_iter()
            .filter(|record| {
                record.activation_height <= target.target_height()
                    && record
                        .retirement_height
                        .is_none_or(|height| target.target_height() < height)
            })
            .collect::<Vec<_>>();
        if records.is_empty() {
            return Err(IngressKeyError::NoActiveKeys);
        }
        Ok(Self {
            context_root,
            records,
        })
    }

    pub fn context_root(&self) -> &EtdagDigest {
        &self.context_root
    }

    pub fn records(&self) -> &[IngressKemKeyRecord] {
        &self.records
    }
}
