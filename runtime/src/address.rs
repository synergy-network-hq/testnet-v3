//! Activated SNTS-01 v1.3 / Address Engine v1 derivation and validation.

use crate::snts_registry::{
    expected_address_length, expected_data_symbols, namespace, IdentifierClass, NamespaceStatus,
};
use bech32::{ToBase32, Variant};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};

pub const NETWORK_BURN_ADDRESS: &str = "syn0000000000000000000000000000000";
pub const STANDARD_ACCOUNT_PREFIX: &str = "syna";
pub const FN_DSA_1024_PUBLIC_KEY_BYTES: usize = 1_793;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AddressKind {
    Wallet,
    Validator,
    FeeCollector,
    ValidatorCluster,
    Contract,
    BurnAddress,
    System,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AddressRegistryEntry {
    pub active: bool,
    pub address_type: AddressKind,
    pub classification: IdentifierClass,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedAddress {
    pub hrp: String,
    pub data_words: Vec<u8>,
    pub classification: IdentifierClass,
}

pub fn data_words_from_preimage(hrp: &str, preimage: &[u8]) -> Result<Vec<u8>, String> {
    let expected = expected_data_symbols(hrp)?;
    Ok(Sha3_256::digest(preimage)
        .to_base32()
        .into_iter()
        .take(expected)
        .map(|word| word.to_u8())
        .collect())
}

fn derive_native_address_from_bytes(prefix: &str, preimage: &[u8]) -> Result<String, String> {
    let entry = namespace(prefix).ok_or_else(|| format!("unknown namespace '{prefix}'"))?;
    if entry.status != NamespaceStatus::Active
        || !entry.classification.is_native_address()
        || entry.encoding != "bech32m_v1"
    {
        return Err(format!(
            "namespace '{prefix}' is not an active native address namespace"
        ));
    }
    let expected = expected_data_symbols(prefix)?;
    let data = Sha3_256::digest(preimage)
        .to_base32()
        .into_iter()
        .take(expected)
        .collect::<Vec<_>>();
    debug_assert_eq!(data.len(), expected);
    let address = bech32::encode(prefix, data, Variant::Bech32m)
        .map_err(|error| format!("Bech32m encode failed: {error}"))?;
    if address.len() != expected_address_length(prefix) {
        return Err("Bech32m encoder emitted a non-canonical length".to_string());
    }
    Ok(address)
}

/// Derives a key-controlled address from a canonical raw FN-DSA-1024
/// verification key. Operational authorization keys are not address roots.
pub fn derive_key_controlled_address(
    prefix: &str,
    public_key_bytes: &[u8],
) -> Result<String, String> {
    let entry = namespace(prefix).ok_or_else(|| format!("unknown namespace '{prefix}'"))?;
    if entry.status != NamespaceStatus::Active
        || entry.classification != IdentifierClass::KeyControlledAddress
    {
        return Err(format!(
            "namespace '{prefix}' is not an active key-controlled address namespace"
        ));
    }
    if public_key_bytes.len() != FN_DSA_1024_PUBLIC_KEY_BYTES {
        return Err(format!(
            "key-controlled address derivation requires exactly {FN_DSA_1024_PUBLIC_KEY_BYTES} canonical raw FN-DSA-1024 verification-key bytes"
        ));
    }
    derive_native_address_from_bytes(prefix, public_key_bytes)
}

/// Applies Address Engine v1 to an owning standard's canonical object preimage.
pub fn derive_object_address(prefix: &str, canonical_preimage: &[u8]) -> Result<String, String> {
    let entry = namespace(prefix).ok_or_else(|| format!("unknown namespace '{prefix}'"))?;
    if entry.status != NamespaceStatus::Active
        || entry.classification != IdentifierClass::ObjectAddress
    {
        return Err(format!(
            "namespace '{prefix}' is not an active object-address namespace"
        ));
    }
    if canonical_preimage.is_empty() {
        return Err(
            "object-address derivation requires a non-empty canonical preimage owned by the relevant standard"
                .to_string(),
        );
    }
    derive_native_address_from_bytes(prefix, canonical_preimage)
}

fn decode_nonempty_lower_hex(field: &str, value: &str) -> Result<Vec<u8>, String> {
    if value.is_empty()
        || value.len() % 2 != 0
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(format!(
            "{field} must be non-empty, even-length lowercase hexadecimal"
        ));
    }
    hex::decode(value).map_err(|error| format!("decode {field}: {error}"))
}

fn validator_class_prefix(class: u8) -> Result<String, String> {
    if !(1..=5).contains(&class) {
        return Err(format!(
            "validator class must be in the canonical range 1..=5, found {class}"
        ));
    }
    Ok(format!("synv{class}"))
}

fn cluster_group_prefix(group: u8) -> Result<String, String> {
    if !(1..=5).contains(&group) {
        return Err(format!(
            "cluster group must be in the canonical range 1..=5, found {group}"
        ));
    }
    Ok(format!("syngrp{group}"))
}

pub fn decode_address(address: &str) -> Result<DecodedAddress, String> {
    if address == NETWORK_BURN_ADDRESS {
        return Err("the synthetic burn constant is not a Bech32m address".to_string());
    }
    if address.is_empty() || address != address.to_ascii_lowercase() {
        return Err("address must use lowercase canonical text".to_string());
    }
    let (hrp, data, variant) =
        bech32::decode(address).map_err(|error| format!("Bech32 decode failed: {error}"))?;
    if variant != Variant::Bech32m {
        return Err("address checksum variant must be Bech32m".to_string());
    }
    let entry = namespace(&hrp).ok_or_else(|| format!("unknown namespace '{hrp}'"))?;
    if entry.status != NamespaceStatus::Active {
        return Err(format!("namespace '{hrp}' is reserved"));
    }
    if !entry.classification.is_native_address() || entry.encoding != "bech32m_v1" {
        return Err(format!(
            "namespace '{hrp}' does not encode native addresses"
        ));
    }
    if address.len() != expected_address_length(&hrp) {
        return Err(format!(
            "address length must be {} for HRP '{hrp}'",
            expected_address_length(&hrp)
        ));
    }
    let expected = expected_data_symbols(&hrp)?;
    if data.len() != expected {
        return Err(format!(
            "address data must contain {expected} symbols for HRP '{hrp}'"
        ));
    }
    Ok(DecodedAddress {
        hrp,
        data_words: data.into_iter().map(|word| word.to_u8()).collect(),
        classification: entry.classification,
    })
}

pub fn derive_standard_account_address(public_key_bytes: &[u8]) -> Result<String, String> {
    derive_key_controlled_address(STANDARD_ACCOUNT_PREFIX, public_key_bytes)
}

pub fn is_standard_account_of(address: &str, public_key_bytes: &[u8]) -> bool {
    !public_key_bytes.is_empty()
        && decode_address(address).is_ok_and(|decoded| decoded.hrp == STANDARD_ACCOUNT_PREFIX)
        && derive_standard_account_address(public_key_bytes).is_ok_and(|derived| derived == address)
}

pub fn generate_wallet_address(public_key_hex: &str) -> Result<String, String> {
    let public_key = decode_nonempty_lower_hex("wallet public key", public_key_hex)?;
    derive_key_controlled_address("synw", &public_key)
}

pub fn generate_validator_address(public_key_hex: &str, class: u8) -> Result<String, String> {
    let prefix = validator_class_prefix(class)?;
    let public_key = decode_nonempty_lower_hex("validator public key", public_key_hex)?;
    derive_key_controlled_address(&prefix, &public_key)
}

pub fn generate_class_based_address(public_key: &[u8], class: u8) -> Result<String, String> {
    let prefix = validator_class_prefix(class)?;
    derive_key_controlled_address(&prefix, public_key)
}

/// Applies Address Engine v1 to a canonical key/object preimage. Reserved,
/// typed-identifier, and unknown namespaces fail closed.
pub fn generate_generic_address(
    prefix: &str,
    canonical_preimage_hex: &str,
) -> Result<String, String> {
    let entry = namespace(prefix).ok_or_else(|| format!("unknown namespace '{prefix}'"))?;
    if entry.classification != IdentifierClass::ObjectAddress {
        return Err(format!(
            "generic address derivation accepts only object-address namespaces, found '{prefix}'"
        ));
    }
    let canonical_preimage =
        decode_nonempty_lower_hex("canonical object preimage", canonical_preimage_hex)?;
    derive_object_address(prefix, &canonical_preimage)
}

pub fn address_matches_public_key(address: &str, public_key_bytes: &[u8]) -> bool {
    !public_key_bytes.is_empty()
        && decode_address(address).is_ok_and(|decoded| {
            decoded.classification == IdentifierClass::KeyControlledAddress
                && derive_key_controlled_address(&decoded.hrp, public_key_bytes)
                    .is_ok_and(|derived| derived == address)
        })
}

pub fn generate_fee_collector_address(seed: &str) -> Result<String, String> {
    derive_object_address("synf", seed.as_bytes())
}

pub fn generate_cluster_address(seed: &str, group: u8) -> Result<String, String> {
    if seed.is_empty() {
        return Err("cluster address derivation requires a non-empty canonical seed".to_string());
    }
    let prefix = cluster_group_prefix(group)?;
    derive_object_address(&prefix, seed.as_bytes())
}

pub fn generate_validator_cluster_address(seed: &str) -> Result<String, String> {
    derive_object_address("syngrp1", seed.as_bytes())
}

pub fn is_valid_address(address: &str) -> bool {
    address == NETWORK_BURN_ADDRESS || decode_address(address).is_ok()
}

pub fn is_valid_cluster_address(address: &str) -> bool {
    decode_address(address).is_ok_and(|decoded| {
        matches!(
            decoded.hrp.as_str(),
            "syngrp1" | "syngrp2" | "syngrp3" | "syngrp4" | "syngrp5"
        )
    })
}

fn kind_for_hrp(hrp: &str) -> AddressKind {
    match hrp {
        "synw" | "syns" | "syna" | "synz" | "synm" | "synu" | "synl" => AddressKind::Wallet,
        "synv1" | "synv2" | "synv3" | "synv4" | "synv5" => AddressKind::Validator,
        "synf" => AddressKind::FeeCollector,
        "syngrp1" | "syngrp2" | "syngrp3" | "syngrp4" | "syngrp5" => AddressKind::ValidatorCluster,
        "synq" | "sync" => AddressKind::Contract,
        _ => AddressKind::System,
    }
}

pub fn address_kind(address: &str) -> AddressKind {
    if address == NETWORK_BURN_ADDRESS {
        AddressKind::BurnAddress
    } else {
        decode_address(address)
            .map(|decoded| kind_for_hrp(&decoded.hrp))
            .unwrap_or(AddressKind::Unknown)
    }
}

pub fn is_network_burn_address(address: &str) -> bool {
    address == NETWORK_BURN_ADDRESS
}

pub fn registry_entry_for_prefix(prefix: &str) -> Option<AddressRegistryEntry> {
    let entry = namespace(prefix)?;
    Some(AddressRegistryEntry {
        active: entry.status == NamespaceStatus::Active,
        address_type: if entry.classification.is_native_address() {
            kind_for_hrp(prefix)
        } else {
            AddressKind::Unknown
        },
        classification: entry.classification,
    })
}

pub fn is_protocol_controlled_address(address: &str) -> bool {
    matches!(
        address_kind(address),
        AddressKind::FeeCollector
            | AddressKind::ValidatorCluster
            | AddressKind::BurnAddress
            | AddressKind::System
    )
}

pub fn is_spendable_user_address(address: &str) -> bool {
    is_valid_address(address) && !is_protocol_controlled_address(address)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bech32::u5;

    const OBJECT_PREIMAGE_HEX: &str =
        "0000000000000000000000000000000000000000000000000000000000000000";

    fn zero_identity_key() -> Vec<u8> {
        vec![0_u8; FN_DSA_1024_PUBLIC_KEY_BYTES]
    }

    #[test]
    fn fixed_length_and_leading_big_endian_words_are_exact() {
        let public_key = zero_identity_key();
        let public_key_hex = hex::encode(&public_key);
        let digest = Sha3_256::digest(&public_key);
        let wallet = generate_wallet_address(&public_key_hex).unwrap();
        let validator = generate_validator_address(&public_key_hex, 1).unwrap();
        let cluster = generate_cluster_address("cluster", 1).unwrap();
        assert_eq!(wallet.len(), 41);
        assert_eq!(validator.len(), 41);
        assert_eq!(cluster.len(), 41);
        let expected_words = digest
            .to_base32()
            .into_iter()
            .take(expected_data_symbols("synw").unwrap())
            .map(|word| word.to_u8())
            .collect::<Vec<_>>();
        assert_eq!(decode_address(&wallet).unwrap().data_words, expected_words);
        assert!(address_matches_public_key(&wallet, &public_key));
    }

    #[test]
    fn canonical_burn_is_synthetic_and_protocol_controlled() {
        assert_eq!(NETWORK_BURN_ADDRESS.len(), 34);
        assert!(is_valid_address(NETWORK_BURN_ADDRESS));
        assert!(bech32::decode(NETWORK_BURN_ADDRESS).is_err());
        assert_eq!(address_kind(NETWORK_BURN_ADDRESS), AddressKind::BurnAddress);
        assert!(is_protocol_controlled_address(NETWORK_BURN_ADDRESS));
        assert!(!is_spendable_user_address(NETWORK_BURN_ADDRESS));
    }

    #[test]
    fn decoder_rejects_wrong_checksum_class_case_payload_and_padding() {
        let wallet = generate_wallet_address(&hex::encode(zero_identity_key())).unwrap();
        let mut checksum = wallet.clone().into_bytes();
        let last = checksum.len() - 1;
        checksum[last] = if checksum[last] == b'q' { b'p' } else { b'q' };
        assert!(!is_valid_address(&String::from_utf8(checksum).unwrap()));
        assert!(!is_valid_address(&wallet.to_ascii_uppercase()));
        let typed = bech32::encode(
            "syntxn",
            vec![u5::try_from_u8(0).unwrap(); expected_data_symbols("syntxn").unwrap()],
            Variant::Bech32m,
        )
        .unwrap();
        assert!(!is_valid_address(&typed));
        let reserved = bech32::encode(
            "syne",
            vec![u5::try_from_u8(0).unwrap(); expected_data_symbols("syne").unwrap()],
            Variant::Bech32m,
        )
        .unwrap();
        assert!(!is_valid_address(&reserved));
        let short = bech32::encode(
            "synw",
            vec![u5::try_from_u8(0).unwrap(); expected_data_symbols("synw").unwrap() - 1],
            Variant::Bech32m,
        )
        .unwrap();
        assert!(!is_valid_address(&short));
        let mut padded = vec![u5::try_from_u8(0).unwrap(); expected_data_symbols("synw").unwrap()];
        padded.push(u5::try_from_u8(0).unwrap());
        assert!(!is_valid_address(
            &bech32::encode("synw", padded, Variant::Bech32m).unwrap()
        ));
        assert!(!is_valid_address(
            &bech32::encode(
                "synw",
                vec![u5::try_from_u8(0).unwrap(); expected_data_symbols("synw").unwrap()],
                Variant::Bech32,
            )
            .unwrap()
        ));
    }

    #[test]
    fn wrappers_remain_deterministic_and_classified() {
        let public_key = zero_identity_key();
        let public_key_hex = hex::encode(&public_key);
        assert_eq!(
            generate_class_based_address(&public_key, 3).unwrap(),
            generate_validator_address(&public_key_hex, 3).unwrap()
        );
        assert!(generate_validator_address(&public_key_hex, 0).is_err());
        assert!(generate_validator_address(&public_key_hex, 6).is_err());
        assert!(generate_validator_address("", 1).is_err());
        assert!(generate_validator_address("not-hex", 1).is_err());
        assert!(generate_class_based_address(&[], 1).is_err());
        assert!(!address_matches_public_key(
            &generate_wallet_address(&public_key_hex).unwrap(),
            &[]
        ));
        assert!(generate_class_based_address(&public_key, 0).is_err());
        assert!(generate_cluster_address("cluster", 0).is_err());
        assert!(generate_cluster_address("cluster", 6).is_err());
        assert!(is_valid_cluster_address(
            &generate_cluster_address("cluster", 5).unwrap()
        ));
        let cluster = generate_validator_cluster_address("network:genesis:0:0").unwrap();
        assert!(is_valid_cluster_address(&cluster));
        assert_eq!(address_kind(&cluster), AddressKind::ValidatorCluster);
        let fee = generate_fee_collector_address("fee-collector").unwrap();
        assert_eq!(address_kind(&fee), AddressKind::FeeCollector);
        assert!(is_protocol_controlled_address(&fee));
        let contract = generate_generic_address("sync", OBJECT_PREIMAGE_HEX).unwrap();
        assert_eq!(address_kind(&contract), AddressKind::Contract);
    }

    #[test]
    fn registry_rejects_typed_and_reserved_as_addresses() {
        let typed = registry_entry_for_prefix("syntxn").unwrap();
        assert!(typed.active);
        assert_eq!(typed.classification, IdentifierClass::TypedIdentifier);
        assert_eq!(typed.address_type, AddressKind::Unknown);
        assert!(registry_entry_for_prefix("synixn").is_none());
    }

    #[test]
    fn published_vectors_reproduce_in_core_runtime() {
        let artifact: serde_json::Value = serde_json::from_str(include_str!(
            "../standards/snts-01-address-engine-v1-vectors.json"
        ))
        .unwrap();
        assert_eq!(
            artifact["source_document_sha256"],
            crate::snts_registry::SOURCE_DOCUMENT_SHA256
        );
        assert_eq!(artifact["vectors"].as_array().unwrap().len(), 29);
        for vector in artifact["vectors"].as_array().unwrap() {
            let input = hex::decode(vector["input_hex"].as_str().unwrap()).unwrap();
            let hrp = vector["hrp"].as_str().unwrap();
            let address = match namespace(hrp).unwrap().classification {
                IdentifierClass::KeyControlledAddress => {
                    derive_key_controlled_address(hrp, &input).unwrap()
                }
                IdentifierClass::ObjectAddress => derive_object_address(hrp, &input).unwrap(),
                other => panic!("vector has non-address classification {other:?}"),
            };
            assert_eq!(address, vector["expected_address"]);
            let decoded = decode_address(&address).unwrap();
            let expected_words = vector["expected_data_words"]
                .as_array()
                .unwrap()
                .iter()
                .map(|word| word.as_u64().unwrap() as u8)
                .collect::<Vec<_>>();
            assert_eq!(decoded.data_words, expected_words);
        }
        for vector in artifact["negative_vectors"].as_array().unwrap() {
            assert!(decode_address(vector["value"].as_str().unwrap()).is_err());
        }
    }
}
