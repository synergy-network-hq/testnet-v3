use serde::Serialize;
use synergy_aegis::{AegisHashEngine, AegisSha3_256};

use crate::EtdagError;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, serde::Deserialize)]
#[serde(transparent)]
pub struct EtdagDigest(pub String);

impl EtdagDigest {
    pub fn from_domain_bytes(domain: &str, bytes: &[u8]) -> Self {
        let digest = AegisSha3_256
            .sha3_512_segments(&[
                &(domain.len() as u64).to_be_bytes(),
                domain.as_bytes(),
                &(bytes.len() as u64).to_be_bytes(),
                bytes,
            ])
            .expect("fixed SHA3-512 is supported");
        Self(digest.iter().map(|byte| format!("{byte:02x}")).collect())
    }

    pub fn from_canonical(domain: &str, value: &impl Serialize) -> Result<Self, EtdagError> {
        serde_json::to_vec(value)
            .map(|bytes| Self::from_domain_bytes(domain, &bytes))
            .map_err(|error| EtdagError::Corrupt(format!("serialize ETDAG digest: {error}")))
    }

    pub fn validate(&self) -> Result<(), EtdagError> {
        if self.0.len() == 128
            && self
                .0
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            Ok(())
        } else {
            Err(EtdagError::InvalidDigest)
        }
    }

    pub fn is_zero(&self) -> bool {
        self.0.chars().all(|character| character == '0')
    }
}
