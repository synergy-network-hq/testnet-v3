//! Activated SNTS-01 v1.3 / Address Engine v1 registry.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::sync::OnceLock;

pub const REGISTRY_JSON: &str = include_str!("../standards/snts-01-address-registry-v1.3.json");
pub const REGISTRY_VERSION: &str = "SNTS-01-v1.3";
pub const REGISTRY_SHA256: &str =
    "f0c5044508c27f6c53fa27b177b506a67764ebe8c95861ae1c8cb3e1c4177225";
pub const VECTOR_SET_SHA256: &str =
    "f5a427d44c3c3b9269d52eb5b471a6ede9de4031b34f66433d86963ab0b36509";
pub const SOURCE_DOCUMENT_SHA256: &str =
    "7dbf3ac0333f8f40b51502b625ec9242de88b70d612d340581968e69c222635c";
pub const ADDRESS_ENGINE_VERSION: u32 = 1;
pub const ADDRESS_TOTAL_LENGTH: usize = 41;
pub const BECH32_CHECKSUM_SYMBOLS: usize = 6;
pub const CANONICAL_BURN_ADDRESS: &str = "syn0000000000000000000000000000000";
pub const EXPLICITLY_REJECTED_TYPED_PREFIX: &str = "synixn-";

const CANONICAL_NAMESPACES: [&str; 36] = [
    "synw", "syns", "syna", "synz", "syntxn", "synxxn", "synb1", "synb2", "synb3", "synn1",
    "synn2", "synj", "synk", "synq", "sync", "synv1", "synv2", "synv3", "synv4", "synv5",
    "syngrp1", "syngrp2", "syngrp3", "syngrp4", "syngrp5", "syndao", "syno", "syny", "synm",
    "synu", "synl", "synf", "synr", "syni", "synp", "syne",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IdentifierClass {
    KeyControlledAddress,
    ObjectAddress,
    TypedIdentifier,
    AliasCompositeIdentity,
    ProtocolSyntheticAddress,
    TransportLocator,
    ReservedNamespace,
}

impl IdentifierClass {
    pub fn is_native_address(self) -> bool {
        matches!(self, Self::KeyControlledAddress | Self::ObjectAddress)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NamespaceStatus {
    Active,
    Reserved,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NamespaceEntry {
    pub namespace: String,
    pub classification: IdentifierClass,
    pub status: NamespaceStatus,
    pub encoding: String,
    pub purpose: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyntheticAddressEntry {
    pub value: String,
    pub classification: IdentifierClass,
    pub status: NamespaceStatus,
    pub encoding: String,
    pub purpose: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TypedHashEntry {
    pub kind: String,
    pub prefix: String,
    pub hex_chars: usize,
    pub status: NamespaceStatus,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AddressEngineParameters {
    pub envelope: String,
    pub digest: String,
    pub identity_root_algorithm: String,
    pub identity_root_preimage: String,
    pub checksum_symbols: usize,
    pub canonical_case: String,
    pub canonical_total_length: usize,
    pub data_symbol_formula: String,
    pub data_symbol_extraction: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Registry {
    pub registry_id: String,
    pub registry_version: String,
    pub source_document_sha256: String,
    pub address_engine_version: u32,
    pub address_engine: AddressEngineParameters,
    pub declared_protocol_namespace_count: usize,
    pub human_table_namespace_count: usize,
    pub registry_reconciliation: String,
    pub explicitly_rejected_typed_prefixes: Vec<String>,
    pub namespaces: Vec<NamespaceEntry>,
    pub synthetic_addresses: Vec<SyntheticAddressEntry>,
    pub typed_hash_identifiers: Vec<TypedHashEntry>,
}

static REGISTRY: OnceLock<Result<Registry, String>> = OnceLock::new();

pub fn registry() -> Result<&'static Registry, &'static str> {
    REGISTRY
        .get_or_init(|| {
            let parsed: Registry = serde_json::from_str(REGISTRY_JSON)
                .map_err(|error| format!("embedded registry JSON is invalid: {error}"))?;
            validate_registry(&parsed)?;
            Ok(parsed)
        })
        .as_ref()
        .map_err(String::as_str)
}

fn validate_registry(value: &Registry) -> Result<(), String> {
    if hex::encode(Sha256::digest(REGISTRY_JSON.as_bytes())) != REGISTRY_SHA256 {
        return Err("embedded SNTS registry does not match its pinned SHA-256".to_string());
    }
    if value.registry_version != REGISTRY_VERSION
        || value.source_document_sha256 != SOURCE_DOCUMENT_SHA256
        || value.address_engine_version != ADDRESS_ENGINE_VERSION
    {
        return Err("embedded SNTS registry provenance/version mismatch".to_string());
    }
    if value.declared_protocol_namespace_count != CANONICAL_NAMESPACES.len()
        || value.human_table_namespace_count != CANONICAL_NAMESPACES.len()
        || value.namespaces.len() != CANONICAL_NAMESPACES.len()
    {
        return Err("embedded SNTS registry has a contradictory namespace count".to_string());
    }
    let actual = value
        .namespaces
        .iter()
        .map(|entry| entry.namespace.as_str())
        .collect::<BTreeSet<_>>();
    let canonical = CANONICAL_NAMESPACES.into_iter().collect::<BTreeSet<_>>();
    if actual != canonical || actual.len() != value.namespaces.len() {
        return Err("embedded SNTS registry has an unknown or duplicate namespace".to_string());
    }
    if value.explicitly_rejected_typed_prefixes != [EXPLICITLY_REJECTED_TYPED_PREFIX]
        || value
            .namespaces
            .iter()
            .any(|entry| entry.namespace == "synixn")
        || value
            .typed_hash_identifiers
            .iter()
            .any(|entry| entry.prefix == EXPLICITLY_REJECTED_TYPED_PREFIX)
    {
        return Err("embedded SNTS registry does not explicitly prohibit synixn-".to_string());
    }
    Ok(())
}

pub fn namespace(hrp: &str) -> Option<&'static NamespaceEntry> {
    registry()
        .ok()?
        .namespaces
        .iter()
        .find(|entry| entry.namespace == hrp)
}

pub fn expected_data_symbols(hrp: &str) -> Result<usize, String> {
    ADDRESS_TOTAL_LENGTH
        .checked_sub(hrp.len() + 1 + BECH32_CHECKSUM_SYMBOLS)
        .filter(|count| *count > 0)
        .ok_or_else(|| format!("HRP '{hrp}' cannot fit the canonical address envelope"))
}

pub fn expected_address_length(_hrp: &str) -> usize {
    ADDRESS_TOTAL_LENGTH
}

pub fn is_explicitly_rejected_typed_prefix(value: &str) -> bool {
    value.starts_with(EXPLICITLY_REJECTED_TYPED_PREFIX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    #[test]
    fn activated_registry_is_versioned_and_pinned() {
        let registry = registry().unwrap();
        assert_eq!(registry.registry_version, REGISTRY_VERSION);
        assert_eq!(registry.source_document_sha256, SOURCE_DOCUMENT_SHA256);
        assert_eq!(registry.namespaces.len(), 36);
        assert_eq!(registry.declared_protocol_namespace_count, 36);
        assert_eq!(registry.human_table_namespace_count, 36);
        assert_eq!(registry.address_engine.canonical_total_length, 41);
        assert_eq!(
            registry.address_engine.identity_root_algorithm,
            "FN-DSA-1024"
        );
        assert!(namespace("synixn").is_none());
        assert!(is_explicitly_rejected_typed_prefix("synixn-00"));
    }

    #[test]
    fn runtime_registry_and_vectors_match_the_canonical_address_engine() {
        assert_eq!(
            hex::encode(Sha256::digest(REGISTRY_JSON.as_bytes())),
            REGISTRY_SHA256
        );
        let vector_bytes = include_bytes!("../standards/snts-01-address-engine-v1-vectors.json");
        assert_eq!(hex::encode(Sha256::digest(vector_bytes)), VECTOR_SET_SHA256);
        let vectors: serde_json::Value =
            serde_json::from_slice(vector_bytes).expect("embedded vectors parse");
        assert_eq!(vectors["source_document_sha256"], SOURCE_DOCUMENT_SHA256);
        assert_eq!(vectors["registry_version"], REGISTRY_VERSION);
        assert_eq!(vectors["registry_sha256"], REGISTRY_SHA256);
        assert_eq!(vectors["address_engine_version"], 1);
    }

    #[test]
    fn contradictory_counts_unknown_namespaces_and_synixn_fail_closed() {
        let canonical = registry().expect("registry parses").clone();

        let mut wrong_count = canonical.clone();
        wrong_count.declared_protocol_namespace_count += 1;
        assert!(validate_registry(&wrong_count).is_err());

        let mut unknown = canonical.clone();
        unknown.namespaces[0].namespace = "synunknown".to_string();
        assert!(validate_registry(&unknown).is_err());

        let mut prohibited = canonical;
        prohibited.namespaces[0].namespace = "synixn".to_string();
        assert!(validate_registry(&prohibited).is_err());
    }
}
