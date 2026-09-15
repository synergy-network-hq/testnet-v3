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

    /// Internal execution-signer identifier — **not an address**.
    ///
    /// These 41 bytes bind the signing key to an algorithm and a network
    /// inside the signed payload, which is what keeps the SynQ deploy and call
    /// domains separated. They are not a public account format and must never
    /// be presented as one: the canonical public identity of an ML-DSA-87
    /// account on Testnet-v3 is its `syna…` Standard Account address.
    ///
    /// The old `to_testnet_debug_string` rendered this as `tsynq1…`, which
    /// looked like a second account address for the same key and leaked into
    /// `msg.sender`, receipts, authority manifests and contract-address
    /// derivation. The prefix here is deliberately not a Bech32 HRP.
    pub fn to_execution_signer_id(&self) -> String {
        format!("synq-signer:{}", hex::encode(self.bytes))
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
