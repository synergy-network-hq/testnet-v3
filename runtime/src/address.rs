//! Address generation and validation utilities for the Synergy network.
//!
//! All addresses conform to SNTS-01: SHA3-256 of the public-key bytes,
//! extraction of 5-bit groups, Bech32m encoding, exactly 41 characters.
//! Implementation mirrors the canonical `synergy-address-engine` (`synergy-keygen`).

use bech32::{u5, Variant};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};

/// Target address length per SNTS-01.
pub const TARGET_ADDRESS_LEN: usize = 41;
/// Canonical protocol burn address. This is a reserved sentinel, not a
/// spendable Bech32m account.
pub const NETWORK_BURN_ADDRESS: &str = "syn00000000000000000000000000000000000000";
/// Bech32m checksum length (6 characters).
const CHECKSUM_LEN: usize = 6;
/// Separator character ('1') length.
const SEPARATOR_LEN: usize = 1;

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
}

/// Extracts exactly `count` 5-bit values from a byte slice (big-endian bit order).
/// Identical to the extraction algorithm in `synergy-address-engine/src/address.rs`.
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

/// Core derivation: SHA3-256(`public_key_bytes`) → extract 5-bit groups → Bech32m encode.
/// The number of data characters is derived from the prefix length so that the
/// total encoded address is exactly `TARGET_ADDRESS_LEN` (41) characters.
fn derive_address_from_bytes(prefix: &str, public_key_bytes: &[u8]) -> String {
    let data_char_count = TARGET_ADDRESS_LEN - prefix.len() - SEPARATOR_LEN - CHECKSUM_LEN;

    let mut hasher = Sha3_256::new();
    hasher.update(public_key_bytes);
    let hash = hasher.finalize();

    let base32_data = extract_base32_values(&hash, data_char_count);

    bech32::encode(prefix, base32_data, Variant::Bech32m)
        .unwrap_or_else(|e| panic!("Bech32m encode failed for prefix '{}': {}", prefix, e))
}

/// Decodes a hex-encoded public-key string to raw bytes.  If the string is
/// not valid hex it falls back to the raw UTF-8 bytes of the string so that
/// non-hex seeds (e.g. cluster seeds) are still hashed deterministically.
fn key_bytes_from_str(public_key: &str) -> Vec<u8> {
    hex::decode(public_key).unwrap_or_else(|_| public_key.as_bytes().to_vec())
}

/// Generates a 41-character Synergy wallet address using the `synw` prefix.
///
/// `public_key` must be a hex-encoded public key (as produced by the key
/// generation layer).  Deterministic: same key always yields the same address.
pub fn generate_wallet_address(public_key: &str) -> String {
    derive_address_from_bytes("synw", &key_bytes_from_str(public_key))
}

/// Generates a validator node address using the `synv{1-5}` prefix.
/// `group` is clamped to [1, 5].
pub fn generate_validator_address(public_key: &str, group: u8) -> String {
    let group = group.clamp(1, 5);
    let prefix = format!("synv{}", group);
    derive_address_from_bytes(&prefix, &key_bytes_from_str(public_key))
}

/// Generates a class-based validator address using the `synv{1-5}` prefix.
/// `public_key` is raw public-key bytes (not hex-encoded).
/// `class` is clamped to [1, 5].
pub fn generate_class_based_address(public_key: &[u8], class: u8) -> String {
    let class = class.clamp(1, 5);
    let prefix = format!("synv{}", class);
    derive_address_from_bytes(&prefix, public_key)
}

/// Generates a Synergy address with any caller-supplied prefix.
/// The prefix must yield a positive `data_char_count`; callers are responsible
/// for supplying a valid prefix defined in the address formatting specification.
pub fn generate_generic_address(prefix: &str, public_key: &str) -> String {
    derive_address_from_bytes(prefix, &key_bytes_from_str(public_key))
}

/// Returns true when `address` is the canonical SNTS-01 address for the raw
/// public-key bytes and the address's own Bech32m prefix.
pub fn address_matches_public_key(address: &str, public_key_bytes: &[u8]) -> bool {
    let Ok((prefix, _, variant)) = bech32::decode(address) else {
        return false;
    };
    variant == Variant::Bech32m
        && is_valid_address(address)
        && derive_address_from_bytes(&prefix, public_key_bytes) == address
}

/// Generates the protocol-controlled FeeCollector address with the `synf` prefix.
pub fn generate_fee_collector_address(seed: &str) -> String {
    derive_address_from_bytes("synf", seed.as_bytes())
}

/// Generates a cluster address using the `syngrp{1-5}` prefix (7 characters).
/// The seed (typically a cluster ID + validator addresses string) is hashed
/// deterministically; no timestamp entropy is introduced.
pub fn generate_cluster_address(seed: &str, group: u8) -> String {
    let group = group.clamp(1, 5);
    let prefix = format!("syngrp{}", group);
    derive_address_from_bytes(&prefix, seed.as_bytes())
}

/// Generates the permanent testnet cluster identifier using the `syngrp1` family.
pub fn generate_validator_cluster_address(seed: &str) -> String {
    derive_address_from_bytes("syngrp1", seed.as_bytes())
}

/// Returns `true` if `address` is a structurally valid Synergy Bech32m address:
/// exactly 41 characters, starts with `syn`, and passes Bech32m checksum validation.
pub fn is_valid_address(address: &str) -> bool {
    if is_network_burn_address(address) {
        return true;
    }
    if address.len() != TARGET_ADDRESS_LEN {
        return false;
    }
    if !address.starts_with("syn") {
        return false;
    }
    match bech32::decode(address) {
        Ok((_, _, variant)) => variant == Variant::Bech32m,
        Err(_) => false,
    }
}

pub fn is_valid_cluster_address(address: &str) -> bool {
    address.len() == TARGET_ADDRESS_LEN
        && address.starts_with("syngrp1")
        && matches!(address_kind(address), AddressKind::ValidatorCluster)
        && matches!(bech32::decode(address), Ok((_, _, Variant::Bech32m)))
}

pub fn address_kind(address: &str) -> AddressKind {
    if is_network_burn_address(address) {
        AddressKind::BurnAddress
    } else if address.starts_with("synf") {
        AddressKind::FeeCollector
    } else if address.starts_with("syngrp1") {
        AddressKind::ValidatorCluster
    } else if address.starts_with("synv") {
        AddressKind::Validator
    } else if address.starts_with("synw") || address.starts_with("synu") {
        AddressKind::Wallet
    } else if address.starts_with("synq") || address.starts_with("sync") {
        AddressKind::Contract
    } else if address.starts_with("synb") {
        AddressKind::BurnAddress
    } else if address.starts_with("syn") {
        AddressKind::System
    } else {
        AddressKind::Unknown
    }
}

pub fn is_network_burn_address(address: &str) -> bool {
    address == NETWORK_BURN_ADDRESS
}

pub fn registry_entry_for_prefix(prefix: &str) -> Option<AddressRegistryEntry> {
    let address_type = match prefix {
        "synf" => AddressKind::FeeCollector,
        "syngrp1" => AddressKind::ValidatorCluster,
        "synw" | "synu" => AddressKind::Wallet,
        "synv1" | "synv2" | "synv3" | "synv4" | "synv5" => AddressKind::Validator,
        "synq" | "sync" => AddressKind::Contract,
        "synb" => AddressKind::BurnAddress,
        _ => return None,
    };

    Some(AddressRegistryEntry {
        active: true,
        address_type,
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

    /// A fixed 32-byte test public key (all zeros for determinism).
    const ZERO_KEY_HEX: &str = "0000000000000000000000000000000000000000000000000000000000000000";
    const ZERO_KEY_BYTES: &[u8] = &[0u8; 32];

    #[test]
    fn wallet_address_is_41_chars() {
        let addr = generate_wallet_address(ZERO_KEY_HEX);
        assert_eq!(
            addr.len(),
            TARGET_ADDRESS_LEN,
            "wallet address must be 41 chars, got: {}",
            addr
        );
    }

    #[test]
    fn canonical_network_burn_address_is_protocol_controlled() {
        assert_eq!(NETWORK_BURN_ADDRESS.len(), TARGET_ADDRESS_LEN);
        assert!(is_valid_address(NETWORK_BURN_ADDRESS));
        assert!(is_network_burn_address(NETWORK_BURN_ADDRESS));
        assert_eq!(address_kind(NETWORK_BURN_ADDRESS), AddressKind::BurnAddress);
        assert!(is_protocol_controlled_address(NETWORK_BURN_ADDRESS));
        assert!(!is_spendable_user_address(NETWORK_BURN_ADDRESS));
    }

    #[test]
    fn wallet_address_starts_with_synw() {
        let addr = generate_wallet_address(ZERO_KEY_HEX);
        assert!(
            addr.starts_with("synw"),
            "wallet address must start with synw, got: {}",
            addr
        );
    }

    #[test]
    fn wallet_address_is_deterministic() {
        let a = generate_wallet_address(ZERO_KEY_HEX);
        let b = generate_wallet_address(ZERO_KEY_HEX);
        assert_eq!(a, b, "wallet address must be deterministic");
    }

    #[test]
    fn wallet_address_is_valid_bech32m() {
        let addr = generate_wallet_address(ZERO_KEY_HEX);
        assert!(
            is_valid_address(&addr),
            "wallet address must pass is_valid_address: {}",
            addr
        );
    }

    #[test]
    fn wallet_address_matches_raw_public_key_bytes() {
        let addr = generate_wallet_address(ZERO_KEY_HEX);
        assert!(address_matches_public_key(&addr, ZERO_KEY_BYTES));
        assert!(!address_matches_public_key(&addr, &[1u8; 32]));
    }

    #[test]
    fn validator_address_is_41_chars() {
        for group in 1u8..=5 {
            let addr = generate_validator_address(ZERO_KEY_HEX, group);
            assert_eq!(
                addr.len(),
                TARGET_ADDRESS_LEN,
                "validator address group {} must be 41 chars: {}",
                group,
                addr
            );
        }
    }

    #[test]
    fn validator_address_prefix() {
        for group in 1u8..=5 {
            let addr = generate_validator_address(ZERO_KEY_HEX, group);
            let expected_prefix = format!("synv{}", group);
            assert!(
                addr.starts_with(&expected_prefix),
                "expected prefix {}, got: {}",
                expected_prefix,
                addr
            );
        }
    }

    #[test]
    fn validator_address_group_clamping() {
        let addr_0 = generate_validator_address(ZERO_KEY_HEX, 0);
        let addr_1 = generate_validator_address(ZERO_KEY_HEX, 1);
        assert_eq!(addr_0, addr_1, "group 0 should clamp to group 1");

        let addr_6 = generate_validator_address(ZERO_KEY_HEX, 6);
        let addr_5 = generate_validator_address(ZERO_KEY_HEX, 5);
        assert_eq!(addr_6, addr_5, "group 6 should clamp to group 5");
    }

    #[test]
    fn class_based_address_is_41_chars() {
        let addr = generate_class_based_address(ZERO_KEY_BYTES, 1);
        assert_eq!(
            addr.len(),
            TARGET_ADDRESS_LEN,
            "class-based address must be 41 chars: {}",
            addr
        );
    }

    #[test]
    fn class_based_matches_validator_for_same_key() {
        // generate_class_based_address takes raw bytes; generate_validator_address takes hex.
        // They should produce the same address for the same underlying key.
        let addr_class = generate_class_based_address(ZERO_KEY_BYTES, 3);
        let addr_val = generate_validator_address(ZERO_KEY_HEX, 3);
        assert_eq!(
            addr_class, addr_val,
            "class-based and validator addresses must match for the same key"
        );
    }

    #[test]
    fn cluster_address_is_41_chars() {
        let addr = generate_cluster_address("test-cluster-seed", 1);
        assert_eq!(
            addr.len(),
            TARGET_ADDRESS_LEN,
            "cluster address must be 41 chars: {}",
            addr
        );
    }

    #[test]
    fn cluster_address_prefix() {
        for group in 1u8..=5 {
            let addr = generate_cluster_address("seed", group);
            let expected_prefix = format!("syngrp{}", group);
            assert!(
                addr.starts_with(&expected_prefix),
                "expected prefix {}, got: {}",
                expected_prefix,
                addr
            );
        }
    }

    #[test]
    fn cluster_address_is_deterministic() {
        let a = generate_cluster_address("deterministic-seed-value", 2);
        let b = generate_cluster_address("deterministic-seed-value", 2);
        assert_eq!(a, b, "cluster address must be deterministic");
    }

    #[test]
    fn fee_collector_prefix_is_registered_as_system_account() {
        let entry = registry_entry_for_prefix("synf").expect("synf registry entry");
        assert!(entry.active);
        assert_eq!(entry.address_type, AddressKind::FeeCollector);

        let fee_collector = generate_fee_collector_address("fee-collector");
        assert_eq!(fee_collector.len(), TARGET_ADDRESS_LEN);
        assert!(fee_collector.starts_with("synf"));
        assert!(is_protocol_controlled_address(&fee_collector));
        assert!(!is_spendable_user_address(&fee_collector));
    }

    #[test]
    fn syngrp1_cluster_address_is_protocol_controlled() {
        let addr = generate_validator_cluster_address("network:genesis:0:0");
        assert_eq!(addr.len(), TARGET_ADDRESS_LEN);
        assert!(addr.starts_with("syngrp1"));
        assert!(is_valid_cluster_address(&addr));
        assert_eq!(address_kind(&addr), AddressKind::ValidatorCluster);
        assert!(is_protocol_controlled_address(&addr));
        assert!(!is_spendable_user_address(&addr));
    }

    #[test]
    fn generic_address_is_41_chars() {
        let addr = generate_generic_address("sync", ZERO_KEY_HEX);
        assert_eq!(
            addr.len(),
            TARGET_ADDRESS_LEN,
            "generic address must be 41 chars: {}",
            addr
        );
        assert!(addr.starts_with("sync1"));
        assert_eq!(address_kind(&addr), AddressKind::Contract);
    }

    #[test]
    fn is_valid_address_rejects_wrong_length() {
        assert!(!is_valid_address("synw1short"));
        assert!(!is_valid_address(&"synw1".repeat(10)));
    }

    #[test]
    fn is_valid_address_rejects_non_syn_prefix() {
        // Build a string of the right length that doesn't start with 'syn'.
        let fake = format!("{:041}", "abcdefghijklmnopqrstuvwxyz0123456789abcde");
        assert!(!is_valid_address(&fake));
    }

    #[test]
    fn is_valid_address_accepts_generated_addresses() {
        let addresses = [
            generate_wallet_address(ZERO_KEY_HEX),
            generate_validator_address(ZERO_KEY_HEX, 1),
            generate_class_based_address(ZERO_KEY_BYTES, 2),
            generate_cluster_address("seed", 3),
            generate_generic_address("synq", ZERO_KEY_HEX),
            generate_generic_address("sync", ZERO_KEY_HEX),
        ];
        for addr in &addresses {
            assert!(is_valid_address(addr), "expected valid address: {}", addr);
        }
    }

    #[test]
    fn different_keys_produce_different_addresses() {
        let key_a = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let key_b = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        assert_ne!(
            generate_wallet_address(key_a),
            generate_wallet_address(key_b),
            "different keys must produce different addresses"
        );
    }
}
