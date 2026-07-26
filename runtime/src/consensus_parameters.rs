use crate::synergy_types::{
    ChainId, NetworkId, ProtocolConfig, POSY_PROTOCOL_VERSION, TESTNET_V3_CLUSTER_SCHEDULE_VERSION,
    TESTNET_V3_CONSENSUS_SIGNATURE_ALGORITHM,
};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha3::{Digest, Sha3_512};
use std::fmt;
use std::fs;
use std::path::Path;

pub const CONSENSUS_PARAMETER_MANIFEST_SCHEMA_VERSION: u32 = 1;
pub const CONSENSUS_PARAMETER_MANIFEST_RELEASE_ID: &str = "testnet-v3";
pub const CONSENSUS_PARAMETER_MANIFEST_FINALIZED_STATUS: &str = "FINALIZED";
pub const MAX_CONSENSUS_PARAMETER_MANIFEST_BYTES: usize = 64 * 1024;

/// The workbook-mandated 512-bit root of the exact canonical parameter
/// manifest bytes. This is deliberately not the runtime's general 256-bit
/// `Hash` type.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ConsensusParameterRoot([u8; 64]);

impl ConsensusParameterRoot {
    pub const fn zero() -> Self {
        Self([0; 64])
    }

    pub fn from_canonical_manifest_bytes(bytes: &[u8]) -> Self {
        let digest = Sha3_512::digest(bytes);
        let mut root = [0u8; 64];
        root.copy_from_slice(&digest);
        Self(root)
    }

    pub fn from_hex(value: &str) -> Result<Self, String> {
        let bytes = hex::decode(value.trim_start_matches("0x"))
            .map_err(|error| format!("invalid consensus parameter root hex: {error}"))?;
        if bytes.len() != 64 {
            return Err(format!(
                "invalid consensus parameter root length: expected 64, found {}",
                bytes.len()
            ));
        }
        let mut root = [0u8; 64];
        root.copy_from_slice(&bytes);
        Ok(Self(root))
    }

    pub fn to_hex(self) -> String {
        hex::encode(self.0)
    }

    pub fn is_zero(self) -> bool {
        self.0 == [0; 64]
    }
}

impl fmt::Debug for ConsensusParameterRoot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "0x{}", self.to_hex())
    }
}

impl Serialize for ConsensusParameterRoot {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for ConsensusParameterRoot {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let encoded = String::deserialize(deserializer)?;
        Self::from_hex(&encoded).map_err(serde::de::Error::custom)
    }
}

/// The sole machine-readable consensus-parameter source accepted by the typed
/// Testnet-v3 runtime. Unknown fields and non-canonical encodings are rejected.
///
/// `epoch_length_slots` remains optional at the schema boundary only so a
/// governance-pending document can produce an explicit fail-closed error. A
/// finalized manifest must contain a non-zero approved value.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ConsensusParameterManifest {
    pub schema_version: u32,
    pub release_id: String,
    pub status: String,
    pub governance_approval_id: String,
    pub chain_id: ChainId,
    pub network_id: NetworkId,
    pub protocol_version: String,
    pub epoch_length_slots: Option<u64>,
    pub target_block_time_ms: u64,
    pub count_quorum_rule: String,
    pub weight_quorum_rule: String,
    pub cluster_schedule_version: String,
    pub consensus_signature_algorithm: String,
    pub ingress_kem_algorithm: String,
    pub payload_encryption_algorithm: String,
    pub encrypted_transaction_target_offset: u64,
    pub initial_cluster_validator_count: u64,
    pub initial_availability_quorum: u64,
    pub initial_decryption_threshold: u64,
    pub shadow_epochs_required: u64,
    pub activation_delay_epochs: u64,
    pub minimum_shadow_blocks: u64,
    pub max_finalized_lag_blocks: u64,
    pub required_vote_match_rate_ppm: u64,
    pub required_validator_stake_nwei: u128,
    pub allow_over_staking: bool,
    pub anti_divergence_enabled: bool,
    pub auto_reconciliation_enabled: bool,
    pub self_quarantine_on_local_divergence: bool,
    pub peer_quarantine_on_invalid_finality_claim: bool,
    pub require_quorum_peer_confirmation_for_reconciliation: bool,
    pub min_canonical_sync_peers: u64,
    pub max_rejoin_lag_blocks: u64,
    pub rejoin_only_at_round_boundary: bool,
    pub allow_quorum_reduction: bool,
    pub proposal_timeout_ms: u64,
    pub prevote_timeout_ms: u64,
    pub precommit_timeout_ms: u64,
    pub max_round_timeout_ms: u64,
}

impl ConsensusParameterManifest {
    pub fn validate_finalized(&self) -> Result<(), String> {
        if self.schema_version != CONSENSUS_PARAMETER_MANIFEST_SCHEMA_VERSION {
            return Err(format!(
                "unsupported consensus parameter manifest schema version: expected {}, found {}",
                CONSENSUS_PARAMETER_MANIFEST_SCHEMA_VERSION, self.schema_version
            ));
        }
        if self.release_id != CONSENSUS_PARAMETER_MANIFEST_RELEASE_ID {
            return Err(format!(
                "wrong consensus parameter release ID: expected {}, found {}",
                CONSENSUS_PARAMETER_MANIFEST_RELEASE_ID, self.release_id
            ));
        }
        if self.status != CONSENSUS_PARAMETER_MANIFEST_FINALIZED_STATUS {
            return Err(
                "consensus parameter manifest is not governance-finalized; validator startup is prohibited"
                    .to_string(),
            );
        }
        if self.governance_approval_id.trim().is_empty() {
            return Err(
                "finalized consensus parameter manifest is missing governance approval ID"
                    .to_string(),
            );
        }
        self.chain_id.require_testnet_v3()?;
        self.network_id.require_testnet_v3()?;
        if self.protocol_version != POSY_PROTOCOL_VERSION {
            return Err(format!(
                "wrong PoSy protocol version: expected {POSY_PROTOCOL_VERSION}, found {}",
                self.protocol_version
            ));
        }
        match self.epoch_length_slots {
            Some(value) if value > 0 => {}
            _ => {
                return Err(
                    "governance-finalized epoch_length_slots is required and must be non-zero"
                        .to_string(),
                )
            }
        }
        for (name, value) in [
            ("target_block_time_ms", self.target_block_time_ms),
            (
                "encrypted_transaction_target_offset",
                self.encrypted_transaction_target_offset,
            ),
            (
                "initial_cluster_validator_count",
                self.initial_cluster_validator_count,
            ),
            (
                "initial_availability_quorum",
                self.initial_availability_quorum,
            ),
            (
                "initial_decryption_threshold",
                self.initial_decryption_threshold,
            ),
            ("proposal_timeout_ms", self.proposal_timeout_ms),
            ("prevote_timeout_ms", self.prevote_timeout_ms),
            ("precommit_timeout_ms", self.precommit_timeout_ms),
            ("max_round_timeout_ms", self.max_round_timeout_ms),
        ] {
            if value == 0 {
                return Err(format!("consensus parameter {name} must be non-zero"));
            }
        }
        if self.count_quorum_rule != "strict_more_than_two_thirds"
            || self.weight_quorum_rule != "strict_more_than_two_thirds"
        {
            return Err(
                "Testnet-v3 count and weight quorum rules must both be strict_more_than_two_thirds"
                    .to_string(),
            );
        }
        if self.cluster_schedule_version != TESTNET_V3_CLUSTER_SCHEDULE_VERSION {
            return Err(format!(
                "wrong cluster schedule version: expected {TESTNET_V3_CLUSTER_SCHEDULE_VERSION}, found {}",
                self.cluster_schedule_version
            ));
        }
        if self.consensus_signature_algorithm != TESTNET_V3_CONSENSUS_SIGNATURE_ALGORITHM {
            return Err(format!(
                "wrong validator consensus signature algorithm: expected {TESTNET_V3_CONSENSUS_SIGNATURE_ALGORITHM}, found {}",
                self.consensus_signature_algorithm
            ));
        }
        if self.ingress_kem_algorithm != "mlkem1024" {
            return Err("Testnet-v3 ingress KEM algorithm must be mlkem1024".to_string());
        }
        if self.payload_encryption_algorithm != "aes256gcm" {
            return Err("Testnet-v3 encrypted payload algorithm must be aes256gcm".to_string());
        }
        if self.encrypted_transaction_target_offset != 3 {
            return Err("Testnet-v3 encrypted transaction target offset must be H+3".to_string());
        }
        if self.initial_cluster_validator_count != 6
            || self.initial_availability_quorum != 5
            || self.initial_decryption_threshold != 2
        {
            return Err(
                "initial encrypted-DAG parameters must be n=6, q=5, and t_dec=2".to_string(),
            );
        }
        if self.allow_quorum_reduction {
            return Err("Testnet-v3 quorum reduction must remain disabled".to_string());
        }
        if self.required_vote_match_rate_ppm > 1_000_000 {
            return Err("required_vote_match_rate_ppm exceeds 1,000,000".to_string());
        }
        Ok(())
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, String> {
        self.validate_finalized()?;
        serde_json::to_vec(self)
            .map_err(|error| format!("canonical parameter manifest serialization failed: {error}"))
    }

    pub fn root(&self) -> Result<ConsensusParameterRoot, String> {
        Ok(ConsensusParameterRoot::from_canonical_manifest_bytes(
            &self.canonical_bytes()?,
        ))
    }

    pub fn protocol_config(&self) -> Result<ProtocolConfig, String> {
        self.validate_finalized()?;
        let consensus_parameter_root = self.root()?;
        let mut config = ProtocolConfig {
            chain_id: self.chain_id,
            network_id: self.network_id.clone(),
            consensus_parameter_root,
            runtime_config_commitment: crate::synergy_types::Hash::zero(),
            shadow_epochs_required: self.shadow_epochs_required,
            activation_delay_epochs: self.activation_delay_epochs,
            minimum_shadow_blocks: self.minimum_shadow_blocks,
            max_finalized_lag_blocks: self.max_finalized_lag_blocks,
            required_vote_match_rate_ppm: self.required_vote_match_rate_ppm,
            required_validator_stake_nwei: self.required_validator_stake_nwei,
            allow_over_staking: self.allow_over_staking,
            anti_divergence_enabled: self.anti_divergence_enabled,
            auto_reconciliation_enabled: self.auto_reconciliation_enabled,
            self_quarantine_on_local_divergence: self.self_quarantine_on_local_divergence,
            peer_quarantine_on_invalid_finality_claim: self
                .peer_quarantine_on_invalid_finality_claim,
            require_quorum_peer_confirmation_for_reconciliation: self
                .require_quorum_peer_confirmation_for_reconciliation,
            min_canonical_sync_peers: self.min_canonical_sync_peers,
            max_rejoin_lag_blocks: self.max_rejoin_lag_blocks,
            rejoin_only_at_round_boundary: self.rejoin_only_at_round_boundary,
            allow_quorum_reduction: self.allow_quorum_reduction,
            proposal_timeout_ms: self.proposal_timeout_ms,
            prevote_timeout_ms: self.prevote_timeout_ms,
            precommit_timeout_ms: self.precommit_timeout_ms,
            max_round_timeout_ms: self.max_round_timeout_ms,
        };
        config.seal_runtime_binding()?;
        Ok(config)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoadedConsensusParameters {
    pub manifest: ConsensusParameterManifest,
    pub canonical_bytes: Vec<u8>,
    pub root: ConsensusParameterRoot,
    pub protocol_config: ProtocolConfig,
}

pub fn load_finalized_consensus_parameters(
    path: impl AsRef<Path>,
) -> Result<LoadedConsensusParameters, String> {
    let path = path.as_ref();
    let bytes = fs::read(path).map_err(|error| {
        format!(
            "failed to read consensus parameter manifest {}: {error}",
            path.display()
        )
    })?;
    if bytes.is_empty() {
        return Err("consensus parameter manifest is empty".to_string());
    }
    if bytes.len() > MAX_CONSENSUS_PARAMETER_MANIFEST_BYTES {
        return Err(format!(
            "consensus parameter manifest exceeds {} bytes",
            MAX_CONSENSUS_PARAMETER_MANIFEST_BYTES
        ));
    }
    let manifest: ConsensusParameterManifest = serde_json::from_slice(&bytes)
        .map_err(|error| format!("invalid consensus parameter manifest JSON: {error}"))?;
    let canonical_bytes = manifest.canonical_bytes()?;
    if bytes != canonical_bytes {
        return Err(
            "consensus parameter manifest bytes are not canonical; whitespace, field reordering, and trailing bytes are prohibited"
                .to_string(),
        );
    }
    let root = ConsensusParameterRoot::from_canonical_manifest_bytes(&canonical_bytes);
    let protocol_config = manifest.protocol_config()?;
    Ok(LoadedConsensusParameters {
        manifest,
        canonical_bytes,
        root,
        protocol_config,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn finalized_fixture() -> ConsensusParameterManifest {
        ConsensusParameterManifest {
            schema_version: CONSENSUS_PARAMETER_MANIFEST_SCHEMA_VERSION,
            release_id: CONSENSUS_PARAMETER_MANIFEST_RELEASE_ID.to_string(),
            status: CONSENSUS_PARAMETER_MANIFEST_FINALIZED_STATUS.to_string(),
            governance_approval_id: "unit-test-only-approval".to_string(),
            chain_id: ChainId::synergy_testnet_v3(),
            network_id: NetworkId::synergy_testnet_v3(),
            protocol_version: POSY_PROTOCOL_VERSION.to_string(),
            epoch_length_slots: Some(7_200),
            target_block_time_ms: 2_000,
            count_quorum_rule: "strict_more_than_two_thirds".to_string(),
            weight_quorum_rule: "strict_more_than_two_thirds".to_string(),
            cluster_schedule_version: TESTNET_V3_CLUSTER_SCHEDULE_VERSION.to_string(),
            consensus_signature_algorithm: TESTNET_V3_CONSENSUS_SIGNATURE_ALGORITHM.to_string(),
            ingress_kem_algorithm: "mlkem1024".to_string(),
            payload_encryption_algorithm: "aes256gcm".to_string(),
            encrypted_transaction_target_offset: 3,
            initial_cluster_validator_count: 6,
            initial_availability_quorum: 5,
            initial_decryption_threshold: 2,
            shadow_epochs_required: 1,
            activation_delay_epochs: 1,
            minimum_shadow_blocks: 100,
            max_finalized_lag_blocks: 2,
            required_vote_match_rate_ppm: 995_000,
            required_validator_stake_nwei: 50_000_000_000_000,
            allow_over_staking: true,
            anti_divergence_enabled: true,
            auto_reconciliation_enabled: true,
            self_quarantine_on_local_divergence: true,
            peer_quarantine_on_invalid_finality_claim: true,
            require_quorum_peer_confirmation_for_reconciliation: true,
            min_canonical_sync_peers: 4,
            max_rejoin_lag_blocks: 0,
            rejoin_only_at_round_boundary: true,
            allow_quorum_reduction: false,
            proposal_timeout_ms: 1_500,
            prevote_timeout_ms: 1_500,
            precommit_timeout_ms: 1_500,
            max_round_timeout_ms: 10_000,
        }
    }

    fn temporary_manifest_path(label: &str) -> std::path::PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "synergy-testnet-v3-{label}-{}-{nonce}.json",
            std::process::id()
        ))
    }

    #[test]
    fn canonical_manifest_root_is_sha3_512_and_restart_stable() {
        let manifest = finalized_fixture();
        let bytes = manifest.canonical_bytes().unwrap();
        let expected = Sha3_512::digest(&bytes);
        assert_eq!(manifest.root().unwrap().to_hex(), hex::encode(expected));

        let path = temporary_manifest_path("canonical");
        fs::write(&path, &bytes).unwrap();
        let loaded = load_finalized_consensus_parameters(&path).unwrap();
        fs::remove_file(path).unwrap();
        assert_eq!(loaded.manifest, manifest);
        assert_eq!(loaded.canonical_bytes, bytes);
        assert_eq!(loaded.root, manifest.root().unwrap());
        assert_eq!(
            loaded.protocol_config.chain_id,
            ChainId::synergy_testnet_v3()
        );
    }

    #[test]
    fn noncanonical_manifest_bytes_fail_closed() {
        let manifest = finalized_fixture();
        let pretty = serde_json::to_vec_pretty(&manifest).unwrap();
        let path = temporary_manifest_path("noncanonical");
        fs::write(&path, pretty).unwrap();
        let error = load_finalized_consensus_parameters(&path).unwrap_err();
        fs::remove_file(path).unwrap();
        assert!(error.contains("not canonical"));
    }

    #[test]
    fn governance_pending_or_unresolved_epoch_fails_closed() {
        let mut manifest = finalized_fixture();
        manifest.status = "GOVERNANCE_PENDING".to_string();
        manifest.epoch_length_slots = None;
        let error = manifest.canonical_bytes().unwrap_err();
        assert!(error.contains("not governance-finalized"));

        manifest.status = CONSENSUS_PARAMETER_MANIFEST_FINALIZED_STATUS.to_string();
        let error = manifest.canonical_bytes().unwrap_err();
        assert!(error.contains("epoch_length_slots"));
    }

    #[test]
    fn quorum_crypto_and_etdag_downgrades_fail_closed() {
        let mut manifest = finalized_fixture();
        manifest.weight_quorum_rule = "two_thirds_or_more".to_string();
        assert!(manifest
            .validate_finalized()
            .unwrap_err()
            .contains("strict_more_than_two_thirds"));

        manifest = finalized_fixture();
        manifest.consensus_signature_algorithm = "fndsa".to_string();
        assert!(manifest
            .validate_finalized()
            .unwrap_err()
            .contains("mldsa65"));

        manifest = finalized_fixture();
        manifest.initial_availability_quorum = 4;
        assert!(manifest
            .validate_finalized()
            .unwrap_err()
            .contains("n=6, q=5"));
    }
}
