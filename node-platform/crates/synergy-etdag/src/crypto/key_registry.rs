use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

use crate::{EtdagDigest, EtdagError};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IngressKemPublicKey {
    pub algorithm: String,
    pub public_key: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IngressKemKeyRecord {
    pub key_id: String,
    pub validator_id: String,
    pub public_key: IngressKemPublicKey,
    pub activation_height: u64,
    pub retirement_height: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IngressKemKeyRegistry {
    pub context_root: EtdagDigest,
    pub records: Vec<IngressKemKeyRecord>,
}

impl IngressKemKeyRegistry {
    pub fn validate_shape(&self) -> Result<(), EtdagError> {
        self.context_root.validate()?;
        let mut key_ids = BTreeSet::new();
        let mut validator_windows = BTreeSet::new();
        if self.records.is_empty()
            || self.records.iter().any(|record| {
                record.key_id.trim().is_empty()
                    || record.validator_id.trim().is_empty()
                    || record.public_key.algorithm.trim().is_empty()
                    || record.public_key.public_key.is_empty()
                    || record.activation_height == 0
                    || record
                        .retirement_height
                        .is_some_and(|retirement| retirement <= record.activation_height)
                    || !key_ids.insert(record.key_id.as_str())
                    || !validator_windows
                        .insert((record.validator_id.as_str(), record.activation_height))
            })
        {
            return Err(EtdagError::InvalidEnvelope(
                "invalid ingress KEM key registry".into(),
            ));
        }
        Ok(())
    }

    pub fn root(&self) -> Result<EtdagDigest, EtdagError> {
        self.validate_shape()?;
        EtdagDigest::from_canonical("PoSy/ETDAG/IngressKemRegistry/v3", self)
    }
}
