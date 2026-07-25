//! SynQ address derivation.

use alloc::{format, string::String};
use serde::{de::Error as DeError, Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};

use crate::{
    algorithms::AlgorithmId, domain::NetworkId, error::AegisSynQError, keys::SynQPublicKey,
};

pub const SYNQ_ADDRESS_VERSION: u8 = 1;
pub const SYNQ_ADDRESS_LEN: usize = 41;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SynQAddress {
    bytes: [u8; SYNQ_ADDRESS_LEN],
}

impl SynQAddress {
    pub fn from_bytes(bytes: [u8; SYNQ_ADDRESS_LEN]) -> Self {
        Self { bytes }
    }

    pub fn as_bytes(&self) -> &[u8; SYNQ_ADDRESS_LEN] {
        &self.bytes
    }

    pub fn to_testnet_debug_string(&self) -> String {
        format!("tsynq1{}", hex::encode(self.bytes))
    }
}

impl Serialize for SynQAddress {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(self.bytes))
    }
}

impl<'de> Deserialize<'de> for SynQAddress {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        let bytes = hex::decode(value).map_err(D::Error::custom)?;
        if bytes.len() != SYNQ_ADDRESS_LEN {
            return Err(D::Error::custom("invalid SynQ address length"));
        }
        let mut out = [0_u8; SYNQ_ADDRESS_LEN];
        out.copy_from_slice(&bytes);
        Ok(Self::from_bytes(out))
    }
}

pub fn derive_synq_address(
    public_key: &SynQPublicKey,
    algorithm: AlgorithmId,
    network: &NetworkId,
) -> Result<SynQAddress, AegisSynQError> {
    if public_key.bytes.is_empty() {
        return Err(AegisSynQError::MalformedPublicKey);
    }

    let network_id = network.numeric_id()?;
    let public_key_hash = Sha256::digest(&public_key.bytes);
    let algorithm_id = algorithm.code();

    let mut bytes = [0_u8; SYNQ_ADDRESS_LEN];
    bytes[0] = SYNQ_ADDRESS_VERSION;
    bytes[1..3].copy_from_slice(&network_id.to_be_bytes());
    bytes[3..5].copy_from_slice(&algorithm_id.to_be_bytes());
    bytes[5..37].copy_from_slice(&public_key_hash);

    let checksum = Sha256::digest(&bytes[..37]);
    bytes[37..41].copy_from_slice(&checksum[..4]);

    Ok(SynQAddress::from_bytes(bytes))
}
