// ============================================================================
// Synergy Network Address Generation Engine Library
// Supports all 35+ address types - Uses FN-DSA-1024 (NIST Level 5)
// ============================================================================

use base64::{engine::general_purpose, Engine as _};
use bech32::{u5, Variant};
use chrono::Utc;
use pqcrypto_falcon::falcon1024;
use pqcrypto_traits::sign::{PublicKey as _, SecretKey as _};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};

pub const TARGET_ADDRESS_LEN: usize = 41;
const SEPARATOR_LEN: usize = 1;
const CHECKSUM_LEN: usize = 6;

// ADDRESS TYPE DEFINITIONS (35+ types)
#[derive(Debug, Clone, Copy)]
pub enum AddressType {
    WalletPrimary,
    WalletUtility,
    WalletAccount,
    WalletSmart,
    TransactionStandard,
    TransactionCrossChain,
    TransactionInternal,
    TokenFungible,
    TokenNonFungibleT1,
    TokenNonFungibleT2,
    TokenMultiAsset,
    TokenIdentity,
    ContractSystem,
    ContractCustom,
    NodeClass1,
    NodeClass2,
    NodeClass3,
    NodeClass4,
    NodeClass5,
    ClusterGroup1,
    ClusterGroup2,
    ClusterGroup3,
    ClusterGroup4,
    ClusterGroup5,
    DaoProposal,
    DaoOversight,
    DaoCommittee,
    MultisigGeneral,
    MultisigTreasury,
    MultisigValidator,
    FeeCollector,
    BurnAddress,
    ReservedE,
    ReservedI,
    ReservedP,
}

impl AddressType {
    pub fn prefix(&self) -> &'static str {
        match self {
            AddressType::WalletPrimary => "syns",
            AddressType::WalletUtility => "synu",
            AddressType::WalletAccount => "syna",
            AddressType::WalletSmart => "synz",
            AddressType::TransactionStandard => "synstxn",
            AddressType::TransactionCrossChain => "synxtxn",
            AddressType::TransactionInternal => "synitxn",
            AddressType::TokenFungible => "synb",
            AddressType::TokenNonFungibleT1 => "synn1",
            AddressType::TokenNonFungibleT2 => "synn2",
            AddressType::TokenMultiAsset => "synj",
            AddressType::TokenIdentity => "synk",
            AddressType::ContractSystem => "synq",
            AddressType::ContractCustom => "sync",
            AddressType::NodeClass1 => "synv1",
            AddressType::NodeClass2 => "synv2",
            AddressType::NodeClass3 => "synv3",
            AddressType::NodeClass4 => "synv4",
            AddressType::NodeClass5 => "synv5",
            AddressType::ClusterGroup1 => "syngrp1",
            AddressType::ClusterGroup2 => "syngrp2",
            AddressType::ClusterGroup3 => "syngrp3",
            AddressType::ClusterGroup4 => "syngrp4",
            AddressType::ClusterGroup5 => "syngrp5",
            AddressType::DaoProposal => "syndao",
            AddressType::DaoOversight => "syno",
            AddressType::DaoCommittee => "syny",
            AddressType::MultisigGeneral => "synm",
            AddressType::MultisigTreasury => "synw",
            AddressType::MultisigValidator => "synl",
            AddressType::FeeCollector => "synf",
            AddressType::BurnAddress => "synr",
            AddressType::ReservedE => "syne",
            AddressType::ReservedI => "syni",
            AddressType::ReservedP => "synp",
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct SynergyIdentity {
    pub address: String,
    pub public_key: String,
    pub private_key: String,
    pub address_type: String,
    pub algorithm: String,
    pub created_at: String,
}

fn extract_base32_values(hash: &[u8], count: usize) -> Vec<u5> {
    let mut values = Vec::with_capacity(count);
    for i in 0..count {
        let bit_offset = i * 5;
        let byte_idx = bit_offset / 8;
        let bit_idx = bit_offset % 8;

        let val = if bit_idx <= 3 {
            (hash[byte_idx] >> (3 - bit_idx)) & 0x1f
        } else {
            let high_bits = (hash[byte_idx] << (bit_idx - 3)) & 0x1f;
            let low_bits = if byte_idx + 1 < hash.len() {
                hash[byte_idx + 1] >> (11 - bit_idx)
            } else {
                0
            };
            high_bits | low_bits
        };

        values.push(u5::try_from_u8(val).expect("5-bit value must be 0..31"));
    }
    values
}

/// Derives address from FN-DSA-1024 public key
/// Process: SHA3-256(public_key) -> exact Bech32m payload for a 41-character address
pub fn derive_address(public_key: &[u8], address_type: AddressType) -> Result<String, String> {
    let prefix = address_type.prefix();
    let data_char_count = TARGET_ADDRESS_LEN
        .checked_sub(prefix.len() + SEPARATOR_LEN + CHECKSUM_LEN)
        .ok_or_else(|| format!("Invalid prefix length for '{prefix}'"))?;
    if data_char_count == 0 {
        return Err(format!("Invalid data length for '{prefix}'"));
    }

    let mut hasher = Sha3_256::new();
    hasher.update(public_key);
    let hash = hasher.finalize();
    let base32_data = extract_base32_values(&hash, data_char_count);

    bech32::encode(prefix, base32_data, Variant::Bech32m)
        .map_err(|e| format!("Failed to encode: {}", e))
}

pub fn is_valid_address(address: &str) -> bool {
    let trimmed = address.trim();
    if trimmed.len() != TARGET_ADDRESS_LEN {
        return false;
    }
    match bech32::decode(trimmed) {
        Ok((_, _, variant)) => variant == Variant::Bech32m,
        Err(_) => false,
    }
}

pub fn generate_identity(address_type: AddressType) -> Result<SynergyIdentity, String> {
    if matches!(address_type, AddressType::BurnAddress) {
        return Ok(SynergyIdentity {
            address: "synr000000burn000000that000000coin".to_string(),
            public_key: String::new(),
            private_key: String::new(),
            address_type: "Burn Address".to_string(),
            algorithm: "FN-DSA-1024".to_string(),
            created_at: Utc::now().to_rfc3339(),
        });
    }
    let (pk, sk) = falcon1024::keypair();
    let public_b64 = general_purpose::STANDARD.encode(pk.as_bytes());
    let private_b64 = general_purpose::STANDARD.encode(sk.as_bytes());
    let address = derive_address(pk.as_bytes(), address_type)?;
    Ok(SynergyIdentity {
        address,
        public_key: public_b64,
        private_key: private_b64,
        address_type: format!("{:?}", address_type),
        algorithm: "FN-DSA-1024".to_string(),
        created_at: Utc::now().to_rfc3339(),
    })
}

pub fn verify_address(address: &str, public_key_b64: &str) -> Result<bool, String> {
    let pk_bytes = general_purpose::STANDARD
        .decode(public_key_b64)
        .map_err(|e| format!("Decode error: {}", e))?;
    let (hrp, data, variant) =
        bech32::decode(address).map_err(|e| format!("Bech32 error: {}", e))?;
    if variant != Variant::Bech32m {
        return Ok(false);
    }

    let mut hasher = Sha3_256::new();
    hasher.update(&pk_bytes);
    let hash = hasher.finalize();
    let data_char_count = TARGET_ADDRESS_LEN
        .checked_sub(hrp.len() + SEPARATOR_LEN + CHECKSUM_LEN)
        .ok_or_else(|| format!("Invalid prefix length for '{hrp}'"))?;
    let expected = extract_base32_values(&hash, data_char_count);

    Ok(data == expected)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_node_addresses_are_canonical_41_character_bech32m() {
        for address_type in [
            AddressType::NodeClass1,
            AddressType::NodeClass2,
            AddressType::NodeClass3,
            AddressType::NodeClass4,
            AddressType::NodeClass5,
        ] {
            let identity = generate_identity(address_type).expect("identity should generate");
            assert_eq!(identity.address.len(), TARGET_ADDRESS_LEN);
            assert!(identity.address.starts_with(address_type.prefix()));
            assert!(is_valid_address(&identity.address));
            assert!(verify_address(&identity.address, &identity.public_key)
                .expect("generated address should verify"));
        }
    }
}
