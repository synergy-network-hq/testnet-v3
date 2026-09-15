use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::{EtdagDigest, EtdagError};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EtdagFeeClass {
    pub class_id: u32,
    pub gas_units: u64,
    pub ciphertext_bytes: u64,
    pub minimum_fee: u128,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EtdagFeeSchedule {
    pub schedule_version: u32,
    pub classes: Vec<EtdagFeeClass>,
}

impl EtdagFeeSchedule {
    pub fn validate(&self) -> Result<(), EtdagError> {
        if self.schedule_version != 1 || self.classes.is_empty() {
            return Err(EtdagError::Governance("invalid ETDAG fee schedule".into()));
        }
        let mut class_ids = BTreeSet::new();
        for class in &self.classes {
            if class.gas_units == 0
                || class.ciphertext_bytes == 0
                || !class_ids.insert(class.class_id)
            {
                return Err(EtdagError::Governance("invalid ETDAG fee class".into()));
            }
        }
        Ok(())
    }

    pub fn root(&self) -> Result<EtdagDigest, EtdagError> {
        self.validate()?;
        let mut classes = self.classes.clone();
        classes.sort_by_key(|class| class.class_id);
        EtdagDigest::from_canonical(
            "SYNERGY_ETDAG_FEE_SCHEDULE_V1",
            &(self.schedule_version, classes),
        )
    }
}
