//! Executable SNTS-06, SNTS-08, and SNTS-09 protocol constants.
//!
//! Testnet-v3 protocol identity is the canonical tuple chain ID `1266`, network
//! ID `testnet`, and release ID `testnet-v3`.

use chrono::{DateTime, Utc};

pub const REVIEWED_STANDARD_DOCX_SHA256: &str =
    "7dbf3ac0333f8f40b51502b625ec9242de88b70d612d340581968e69c222635c";

/// Largest whole-second Unix timestamp representable by the canonical
/// four-digit ISO-8601 UTC display form (`9999-12-31T23:59:59Z`).
/// Contemporary JavaScript millisecond timestamps are larger and are rejected.
pub const MAX_WIRE_TIMESTAMP_SECONDS: u64 = 253_402_300_799;

pub fn validate_wire_timestamp_seconds(timestamp: u64) -> Result<u64, String> {
    if timestamp > MAX_WIRE_TIMESTAMP_SECONDS {
        return Err(format!(
            "timestamp {timestamp} is not a canonical whole-second Unix timestamp; millisecond-scale protocol timestamps are rejected"
        ));
    }
    Ok(timestamp)
}

pub fn format_wire_timestamp_utc(timestamp: u64) -> Result<String, String> {
    validate_wire_timestamp_seconds(timestamp)?;
    let seconds = i64::try_from(timestamp)
        .map_err(|_| "timestamp exceeds the canonical ISO-8601 range".to_string())?;
    let value = DateTime::<Utc>::from_timestamp(seconds, 0)
        .ok_or_else(|| "timestamp is outside the canonical ISO-8601 range".to_string())?;
    Ok(value.format("%Y-%m-%dT%H:%M:%SZ").to_string())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PqcOperationalStatus {
    Active,
    /// Available in the active implementation for diversity, but not the
    /// primary operational algorithm.
    ActiveReserve,
    /// Requires explicit governance authorization before protocol use.
    GovernanceReserve,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PqcFamilySpec {
    pub documentation_name: &'static str,
    pub code_name: &'static str,
    pub status: PqcOperationalStatus,
}

pub const PQC_FAMILIES: &[PqcFamilySpec] = &[
    PqcFamilySpec {
        documentation_name: "ML-KEM",
        code_name: "mlkem",
        status: PqcOperationalStatus::Active,
    },
    PqcFamilySpec {
        documentation_name: "ML-DSA",
        code_name: "mldsa",
        status: PqcOperationalStatus::Active,
    },
    PqcFamilySpec {
        documentation_name: "FN-DSA",
        code_name: "fndsa",
        status: PqcOperationalStatus::Active,
    },
    PqcFamilySpec {
        documentation_name: "SLH-DSA",
        code_name: "slhdsa",
        status: PqcOperationalStatus::GovernanceReserve,
    },
    PqcFamilySpec {
        documentation_name: "HQC-KEM",
        code_name: "hqckem",
        status: PqcOperationalStatus::ActiveReserve,
    },
    PqcFamilySpec {
        documentation_name: "CMCE-KEM",
        code_name: "cmce",
        status: PqcOperationalStatus::GovernanceReserve,
    },
    PqcFamilySpec {
        documentation_name: "UOV-DSA",
        code_name: "uovdsa",
        status: PqcOperationalStatus::GovernanceReserve,
    },
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PqcVariantSpec {
    pub documentation_name: &'static str,
    pub code_name: &'static str,
    pub status: PqcOperationalStatus,
}

macro_rules! pqc_variant {
    ($documentation_name:literal, $code_name:literal, $status:ident) => {
        PqcVariantSpec {
            documentation_name: $documentation_name,
            code_name: $code_name,
            status: PqcOperationalStatus::$status,
        }
    };
}

/// Canonical variant spellings from the SNTS-06 variant tables.  The explicit
/// SLH-DSA table spellings are used here pending governance correction of the
/// conflicting general "hyphen-free" sentence in section 3.2.
pub const PQC_VARIANTS: &[PqcVariantSpec] = &[
    pqc_variant!("ML-KEM-512", "mlkem512", Active),
    pqc_variant!("ML-KEM-768", "mlkem768", Active),
    pqc_variant!("ML-KEM-1024", "mlkem1024", Active),
    pqc_variant!("ML-DSA-44", "mldsa44", Active),
    pqc_variant!("ML-DSA-65", "mldsa65", Active),
    pqc_variant!("ML-DSA-87", "mldsa87", Active),
    pqc_variant!("FN-DSA-512", "fndsa512", Active),
    pqc_variant!("FN-DSA-1024", "fndsa1024", Active),
    pqc_variant!("SLH-DSA-SHAKE-128f", "slhdsa-shake128f", GovernanceReserve),
    pqc_variant!("SLH-DSA-SHAKE-128s", "slhdsa-shake128s", GovernanceReserve),
    pqc_variant!("SLH-DSA-SHAKE-192f", "slhdsa-shake192f", GovernanceReserve),
    pqc_variant!("SLH-DSA-SHAKE-192s", "slhdsa-shake192s", GovernanceReserve),
    pqc_variant!("SLH-DSA-SHAKE-256f", "slhdsa-shake256f", GovernanceReserve),
    pqc_variant!("SLH-DSA-SHAKE-256s", "slhdsa-shake256s", GovernanceReserve),
    pqc_variant!("SLH-DSA-SHA2-128f", "slhdsa-sha2128f", GovernanceReserve),
    pqc_variant!("SLH-DSA-SHA2-128s", "slhdsa-sha2128s", GovernanceReserve),
    pqc_variant!("SLH-DSA-SHA2-192f", "slhdsa-sha2192f", GovernanceReserve),
    pqc_variant!("SLH-DSA-SHA2-192s", "slhdsa-sha2192s", GovernanceReserve),
    pqc_variant!("SLH-DSA-SHA2-256f", "slhdsa-sha2256f", GovernanceReserve),
    pqc_variant!("SLH-DSA-SHA2-256s", "slhdsa-sha2256s", GovernanceReserve),
    pqc_variant!("HQC-KEM-128", "hqckem128", ActiveReserve),
    pqc_variant!("HQC-KEM-192", "hqckem192", ActiveReserve),
    pqc_variant!("HQC-KEM-256", "hqckem256", ActiveReserve),
    pqc_variant!("CMCE-KEM-460896", "cmce460896", GovernanceReserve),
    pqc_variant!("CMCE-KEM-6688128", "cmce6688128", GovernanceReserve),
    pqc_variant!("CMCE-KEM-6960119", "cmce6960119", GovernanceReserve),
    pqc_variant!("CMCE-KEM-8192128", "cmce8192128", GovernanceReserve),
    pqc_variant!("UOV-DSA-Ip", "uovdsaip", GovernanceReserve),
    pqc_variant!("UOV-DSA-Is", "uovdsais", GovernanceReserve),
    pqc_variant!("UOV-DSA-III", "uovdsaiii", GovernanceReserve),
    pqc_variant!("UOV-DSA-V", "uovdsav", GovernanceReserve),
];

pub fn pqc_variant_by_code(code_name: &str) -> Option<&'static PqcVariantSpec> {
    PQC_VARIANTS
        .iter()
        .find(|variant| variant.code_name == code_name)
}

/// Resolves a variant for ordinary protocol activation.  Reserve algorithms
/// remain visible as metadata but require a separate governed activation path.
pub fn active_pqc_variant_by_code(code_name: &str) -> Result<&'static PqcVariantSpec, String> {
    let variant = pqc_variant_by_code(code_name)
        .ok_or_else(|| format!("unknown canonical PQC code name: {code_name}"))?;
    if variant.status != PqcOperationalStatus::Active {
        return Err(format!(
            "PQC variant {} is {:?} and cannot be activated without governed reserve authorization",
            variant.documentation_name, variant.status
        ));
    }
    Ok(variant)
}

pub const TESTNET_BETA_V1_CHAIN_ID: u64 = 1262;
pub const TESTNET_V3_CHAIN_ID: u64 = crate::synergy_types::SYNERGY_TESTNET_V3_CHAIN_ID;
pub const MAINNET_BETA_CHAIN_ID: u64 = 1268;
pub const MAINNET_CHAIN_ID: u64 = 1269;
pub const TESTBETA_ENVIRONMENT: &str = "testbeta";
pub const TESTNET_ENVIRONMENT: &str = "testnet";
pub const MAINNET_ENVIRONMENT: &str = "mainnet";
pub const TESTNET_V3_NETWORK_ID: &str = crate::synergy_types::SYNERGY_TESTNET_V3_NETWORK_ID;
pub const TESTNET_V3_RELEASE_ID: &str = crate::synergy_types::SYNERGY_TESTNET_V3_RELEASE_ID;
/// Accepted only by explicitly scoped migration readers; never emit or bind
/// this retired single-authority-chain identifier into new protocol material.
pub const LEGACY_TESTNET_V3_NETWORK_ID: &str =
    crate::synergy_types::SYNERGY_TESTNET_V3_LEGACY_NETWORK_ID;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RoleAwareEnvironmentPorts {
    pub p2p_default: u16,
    pub p2p_bootnode: u16,
    pub p2p_seed: u16,
    pub p2p_archive: u16,
    pub qrpc_default: u16,
    pub qrpc_archive: u16,
    pub websocket_default: u16,
    pub websocket_archive: u16,
    pub discovery_default: u16,
    pub discovery_seed_archive: u16,
    pub metrics_default: u16,
    pub metrics_archive: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EnvironmentSpec {
    pub display_name: &'static str,
    pub identifier: &'static str,
    /// Only governance-approved, role-aware production assignments appear
    /// here. Environments without an authoritative allocation remain `None`.
    pub approved_ports: Option<RoleAwareEnvironmentPorts>,
}

pub const ENVIRONMENTS: &[EnvironmentSpec] = &[
    EnvironmentSpec {
        display_name: "Testnet Beta",
        identifier: TESTBETA_ENVIRONMENT,
        approved_ports: None,
    },
    EnvironmentSpec {
        display_name: "Testnet",
        identifier: TESTNET_ENVIRONMENT,
        approved_ports: Some(RoleAwareEnvironmentPorts {
            p2p_default: 5_622,
            p2p_bootnode: 5_620,
            p2p_seed: 5_621,
            p2p_archive: 5_615,
            qrpc_default: 5_640,
            qrpc_archive: 5_641,
            websocket_default: 5_660,
            websocket_archive: 5_661,
            discovery_default: 5_680,
            discovery_seed_archive: 5_681,
            metrics_default: 6_030,
            metrics_archive: 6_031,
        }),
    },
    EnvironmentSpec {
        display_name: "Mainnet",
        identifier: MAINNET_ENVIRONMENT,
        approved_ports: None,
    },
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NetworkReleaseSpec {
    pub release_id: &'static str,
    pub display_name: &'static str,
    pub environment: &'static str,
    pub chain_id: u64,
}

/// Canonical release-to-chain mappings. Environments are deliberately
/// separate from releases. Mainnet Beta is a release on the `mainnet`
/// environment rather than a fourth environment identifier.
pub const NETWORK_RELEASES: &[NetworkReleaseSpec] = &[
    NetworkReleaseSpec {
        release_id: "testnet-beta-v1",
        display_name: "Testnet-beta (v1)",
        environment: TESTBETA_ENVIRONMENT,
        chain_id: TESTNET_BETA_V1_CHAIN_ID,
    },
    NetworkReleaseSpec {
        release_id: TESTNET_V3_RELEASE_ID,
        display_name: "Testnet (v3)",
        environment: TESTNET_ENVIRONMENT,
        chain_id: TESTNET_V3_CHAIN_ID,
    },
    NetworkReleaseSpec {
        release_id: "mainnet-beta",
        display_name: "Mainnet-beta",
        environment: MAINNET_ENVIRONMENT,
        chain_id: MAINNET_BETA_CHAIN_ID,
    },
    NetworkReleaseSpec {
        release_id: "mainnet",
        display_name: "Mainnet",
        environment: MAINNET_ENVIRONMENT,
        chain_id: MAINNET_CHAIN_ID,
    },
];

pub fn environment_by_identifier(identifier: &str) -> Option<&'static EnvironmentSpec> {
    ENVIRONMENTS
        .iter()
        .find(|environment| environment.identifier == identifier)
}

pub fn network_release_by_id(release_id: &str) -> Option<&'static NetworkReleaseSpec> {
    NETWORK_RELEASES
        .iter()
        .find(|release| release.release_id == release_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn milliseconds_are_rejected_and_seconds_format_canonically() {
        assert_eq!(
            format_wire_timestamp_utc(1_741_561_800).unwrap(),
            "2025-03-09T23:10:00Z"
        );
        let error = validate_wire_timestamp_seconds(1_741_561_800_000).unwrap_err();
        assert!(error.contains("millisecond-scale"));
    }

    #[test]
    fn pqc_registry_marks_active_and_reserve_algorithms_explicitly() {
        assert_eq!(
            pqc_variant_by_code("mldsa65").unwrap().status,
            PqcOperationalStatus::Active
        );
        assert_eq!(
            pqc_variant_by_code("hqckem192").unwrap().status,
            PqcOperationalStatus::ActiveReserve
        );
        assert_eq!(
            pqc_variant_by_code("uovdsaiii").unwrap().status,
            PqcOperationalStatus::GovernanceReserve
        );
        assert!(active_pqc_variant_by_code("mldsa65").is_ok());
        assert!(active_pqc_variant_by_code("slhdsa-shake128f").is_err());
        assert!(active_pqc_variant_by_code("hqckem192").is_err());
    }

    #[test]
    fn testnet_identity_and_role_aware_ports_are_canonical() {
        let testnet = environment_by_identifier("testnet").unwrap();
        let ports = testnet.approved_ports.expect("Testnet ports are governed");
        assert_eq!(ports.p2p_default, 5622);
        assert_eq!(ports.p2p_bootnode, 5620);
        assert_eq!(ports.p2p_seed, 5621);
        assert_eq!(ports.p2p_archive, 5615);
        assert_eq!(ports.qrpc_default, 5640);
        assert_eq!(ports.qrpc_archive, 5641);
        assert_eq!(ports.websocket_default, 5660);
        assert_eq!(ports.websocket_archive, 5661);
        assert_eq!(ports.discovery_default, 5680);
        assert_eq!(ports.discovery_seed_archive, 5681);
        assert_eq!(ports.metrics_default, 6030);
        assert_eq!(ports.metrics_archive, 6031);
        assert_eq!(TESTNET_V3_NETWORK_ID, "testnet");
        assert_eq!(TESTNET_V3_RELEASE_ID, "testnet-v3");
        assert_eq!(LEGACY_TESTNET_V3_NETWORK_ID, "synergy-testnet-v3");
        assert_ne!(TESTNET_V3_NETWORK_ID, LEGACY_TESTNET_V3_NETWORK_ID);
        assert!(environment_by_identifier("devnet").is_none());
        assert!(environment_by_identifier("mainbeta").is_none());
        assert!(environment_by_identifier("mainnet")
            .unwrap()
            .approved_ports
            .is_none());
        assert_eq!(
            ENVIRONMENTS
                .iter()
                .map(|environment| environment.identifier)
                .collect::<Vec<_>>(),
            vec!["testbeta", "testnet", "mainnet"]
        );
        assert_eq!(NETWORK_RELEASES.len(), 5);
        let release = network_release_by_id(TESTNET_V3_RELEASE_ID).unwrap();
        assert_eq!(release.environment, TESTNET_ENVIRONMENT);
        assert_eq!(release.chain_id, TESTNET_V3_CHAIN_ID);
    }

    #[test]
    fn executable_constants_match_the_v1_3_registry_identity() {
        let registry: serde_json::Value =
            serde_json::from_str(include_str!("../config/protocol-standards.v1.json")).unwrap();
        assert_eq!(
            registry["source_docx_sha256"],
            REVIEWED_STANDARD_DOCX_SHA256
        );
        assert_eq!(
            registry["testnet_v3_compatibility"]["chain_id"],
            TESTNET_V3_CHAIN_ID
        );
        assert_eq!(
            registry["testnet_v3_compatibility"]["network_id"],
            TESTNET_V3_NETWORK_ID
        );
        assert_eq!(
            registry["testnet_v3_compatibility"]["release_id"],
            TESTNET_V3_RELEASE_ID
        );
        assert_eq!(
            registry["testnet_v3_compatibility"]["legacy_network_id"],
            LEGACY_TESTNET_V3_NETWORK_ID
        );
        assert_eq!(
            registry["testnet_v3_compatibility"]["legacy_input_only"],
            true
        );
        let registry_environments = registry["environments"]
            .as_array()
            .unwrap()
            .iter()
            .map(|environment| environment["identifier"].as_str().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(
            registry_environments,
            vec!["testbeta", "testnet", "mainnet"]
        );
        let registry_releases = registry["network_releases"].as_array().unwrap();
        assert_eq!(registry_releases.len(), NETWORK_RELEASES.len());
        for release in NETWORK_RELEASES {
            let registry_release = registry_releases
                .iter()
                .find(|candidate| candidate["release_id"] == release.release_id)
                .unwrap();
            assert_eq!(registry_release["environment"], release.environment);
            assert_eq!(registry_release["chain_id"], release.chain_id);
        }
    }
}
