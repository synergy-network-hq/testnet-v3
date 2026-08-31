//! Governed ETDAG artifacts for the fresh Testnet-v3 PoSy chain.
//!
//! ETDAG parameter and fee policy are consensus-adjacent inputs, but they are
//! not a substitute for consensus activation.  This module deliberately
//! defines only the unsigned, canonical payloads that a governance ceremony
//! may approve and sign.  Runtime loading, Genesis binding, RPC publication,
//! and wallet registry generation must all consume a verified artifact; none
//! of those actions is performed here.
//!
//! The roots below are SHA3-512 digests of the exact canonical JSON bytes of
//! their respective manifests.  Canonical JSON is the repository's existing
//! struct-order serialization convention: manifests contain no maps, all
//! vector order is validated, and unknown JSON fields are rejected.

use crate::etdag::EtdagParameters;
use crate::gas::{
    constants::BPS_DENOMINATOR, fee_market::FeeMarketParams, FeeSchedule, TransactionFeeType,
};
use crate::synergy_types::{
    ChainId, NetworkId, TESTNET_V3_CONSENSUS_SIGNATURE_ALGORITHM,
    TESTNET_V3_MLDSA65_PUBLIC_KEY_BYTES,
};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha3::{Digest as _, Sha3_512};
use std::collections::BTreeSet;
use std::fmt;

pub const ETDAG_PARAMETER_MANIFEST_SCHEMA: &str = "synergy-etdag-parameter-manifest-v1";
pub const ETDAG_FEE_SCHEDULE_MANIFEST_SCHEMA: &str = "synergy-etdag-fee-schedule-manifest-v1";
pub const ETDAG_GOVERNED_MEMBERSHIP_PROOF_SCHEMA: &str =
    "synergy-etdag-governed-membership-proof-v1";
pub const ETDAG_GOVERNED_GENESIS_BINDING_SCHEMA_VERSION: u32 = 1;
pub const ETDAG_GOVERNED_GENESIS_BINDING_STATUS: &str = "FINALIZED_AND_BOUND";

/// A lower-case SHA3-512 root as exposed to launch tooling and Wallet.
///
/// The existing `EtdagDigest` is a general digest carrier and intentionally
/// accepts several representations used by older internal paths.  Governed
/// artifacts need a stricter public representation so that a root copied into
/// a registry cannot vary by casing or an `0x` prefix.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EtdagGovernedRoot([u8; 64]);

impl EtdagGovernedRoot {
    pub fn from_canonical_manifest_bytes(bytes: &[u8]) -> Self {
        let digest = Sha3_512::digest(bytes);
        let mut root = [0u8; 64];
        root.copy_from_slice(&digest);
        Self(root)
    }

    pub fn from_hex(value: &str) -> Result<Self, String> {
        if value.len() != 128
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(
                "ETDAG governed root must be 128 lowercase SHA3-512 hex characters".to_string(),
            );
        }
        let bytes = hex::decode(value).map_err(|error| {
            format!("decode ETDAG governed root despite validated hex: {error}")
        })?;
        let mut root = [0u8; 64];
        root.copy_from_slice(&bytes);
        Ok(Self(root))
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    pub fn is_zero(&self) -> bool {
        self.0 == [0u8; 64]
    }
}

impl fmt::Debug for EtdagGovernedRoot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("EtdagGovernedRoot")
            .field(&self.to_hex())
            .finish()
    }
}

impl Serialize for EtdagGovernedRoot {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for EtdagGovernedRoot {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::from_hex(&value).map_err(serde::de::Error::custom)
    }
}

/// The exact ETDAG admission limits submitted to governance.
///
/// The manifest does not carry its own root: self-including a root would make
/// the digest circular.  Use [`EtdagParameterArtifact`] when a serialized
/// artifact must carry both the manifest and its independently recomputable
/// root.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EtdagParameterManifest {
    pub schema: String,
    pub governance_decision_id: String,
    pub chain_id: ChainId,
    pub network_id: NetworkId,
    pub consensus_protocol_version: String,
    pub parameters: EtdagParameters,
}

impl EtdagParameterManifest {
    pub fn validate(&self) -> Result<(), String> {
        require_schema(
            &self.schema,
            ETDAG_PARAMETER_MANIFEST_SCHEMA,
            "ETDAG parameter manifest",
        )?;
        require_final_governance_decision_id(&self.governance_decision_id)?;
        self.chain_id.require_testnet_v3()?;
        self.network_id.require_fresh_posy_testnet_v3()?;
        require_consensus_protocol_version(&self.consensus_protocol_version)?;
        self.parameters.validate()
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, String> {
        self.validate()?;
        serde_json::to_vec(self)
            .map_err(|error| format!("serialize canonical ETDAG parameter manifest: {error}"))
    }

    pub fn root(&self) -> Result<EtdagGovernedRoot, String> {
        Ok(EtdagGovernedRoot::from_canonical_manifest_bytes(
            &self.canonical_bytes()?,
        ))
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, String> {
        let manifest: Self = serde_json::from_slice(bytes)
            .map_err(|error| format!("decode ETDAG parameter manifest: {error}"))?;
        if manifest.canonical_bytes()? != bytes {
            return Err(
                "non-canonical ETDAG parameter manifest serialization rejected".to_string(),
            );
        }
        Ok(manifest)
    }
}

/// Root-bearing transport form of [`EtdagParameterManifest`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EtdagParameterArtifact {
    pub manifest: EtdagParameterManifest,
    pub etdag_parameter_root_sha3_512: EtdagGovernedRoot,
}

impl EtdagParameterArtifact {
    pub fn from_manifest(manifest: EtdagParameterManifest) -> Result<Self, String> {
        let etdag_parameter_root_sha3_512 = manifest.root()?;
        Ok(Self {
            manifest,
            etdag_parameter_root_sha3_512,
        })
    }

    pub fn validate(&self) -> Result<(), String> {
        let expected = self.manifest.root()?;
        if self.etdag_parameter_root_sha3_512 != expected {
            return Err(
                "ETDAG parameter artifact root does not match canonical manifest".to_string(),
            );
        }
        Ok(())
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, String> {
        self.validate()?;
        serde_json::to_vec(self)
            .map_err(|error| format!("serialize canonical ETDAG parameter artifact: {error}"))
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, String> {
        let artifact: Self = serde_json::from_slice(bytes)
            .map_err(|error| format!("decode ETDAG parameter artifact: {error}"))?;
        if artifact.canonical_bytes()? != bytes {
            return Err(
                "non-canonical ETDAG parameter artifact serialization rejected".to_string(),
            );
        }
        Ok(artifact)
    }
}

/// The exact transaction fee schedule submitted to governance.
///
/// The fee manifest is explicitly chained to the parameter-manifest root so a
/// signed schedule cannot be reused with different ETDAG resource limits.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EtdagFeeScheduleManifest {
    pub schema: String,
    pub governance_decision_id: String,
    pub chain_id: ChainId,
    pub network_id: NetworkId,
    pub consensus_protocol_version: String,
    pub etdag_parameter_root_sha3_512: EtdagGovernedRoot,
    pub fee_schedule: FeeSchedule,
    /// Dynamic base-fee parameters are committed under the same governed
    /// root as the transaction fee schedule. Wallet price reporting must
    /// never inherit an ungoverned code default.
    pub fee_market_params: FeeMarketParams,
}

impl EtdagFeeScheduleManifest {
    pub fn validate(&self) -> Result<(), String> {
        require_schema(
            &self.schema,
            ETDAG_FEE_SCHEDULE_MANIFEST_SCHEMA,
            "ETDAG fee schedule manifest",
        )?;
        require_final_governance_decision_id(&self.governance_decision_id)?;
        self.chain_id.require_testnet_v3()?;
        self.network_id.require_fresh_posy_testnet_v3()?;
        require_consensus_protocol_version(&self.consensus_protocol_version)?;
        validate_fee_schedule(&self.fee_schedule)?;
        validate_fee_market_params(&self.fee_market_params)
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, String> {
        self.validate()?;
        serde_json::to_vec(self)
            .map_err(|error| format!("serialize canonical ETDAG fee schedule manifest: {error}"))
    }

    pub fn root(&self) -> Result<EtdagGovernedRoot, String> {
        Ok(EtdagGovernedRoot::from_canonical_manifest_bytes(
            &self.canonical_bytes()?,
        ))
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, String> {
        let manifest: Self = serde_json::from_slice(bytes)
            .map_err(|error| format!("decode ETDAG fee schedule manifest: {error}"))?;
        if manifest.canonical_bytes()? != bytes {
            return Err(
                "non-canonical ETDAG fee schedule manifest serialization rejected".to_string(),
            );
        }
        Ok(manifest)
    }
}

/// Root-bearing transport form of [`EtdagFeeScheduleManifest`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EtdagFeeScheduleArtifact {
    pub manifest: EtdagFeeScheduleManifest,
    pub etdag_fee_schedule_root_sha3_512: EtdagGovernedRoot,
}

impl EtdagFeeScheduleArtifact {
    pub fn from_manifest(manifest: EtdagFeeScheduleManifest) -> Result<Self, String> {
        let etdag_fee_schedule_root_sha3_512 = manifest.root()?;
        Ok(Self {
            manifest,
            etdag_fee_schedule_root_sha3_512,
        })
    }

    pub fn validate(&self) -> Result<(), String> {
        let expected = self.manifest.root()?;
        if self.etdag_fee_schedule_root_sha3_512 != expected {
            return Err(
                "ETDAG fee schedule artifact root does not match canonical manifest".to_string(),
            );
        }
        Ok(())
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, String> {
        self.validate()?;
        serde_json::to_vec(self)
            .map_err(|error| format!("serialize canonical ETDAG fee schedule artifact: {error}"))
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, String> {
        let artifact: Self = serde_json::from_slice(bytes)
            .map_err(|error| format!("decode ETDAG fee schedule artifact: {error}"))?;
        if artifact.canonical_bytes()? != bytes {
            return Err(
                "non-canonical ETDAG fee schedule artifact serialization rejected".to_string(),
            );
        }
        Ok(artifact)
    }
}

/// The ETDAG policy facts committed into fresh PoSy Genesis.
///
/// The final Genesis release approval signs the complete candidate that
/// contains this binding.  Keeping the detached approval out of the Genesis
/// object avoids a candidate-hash/signature cycle while still making both
/// policy roots part of the immutable Genesis and release-approval inputs.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EtdagGovernedGenesisBinding {
    pub schema_version: u32,
    pub status: String,
    pub parameter_artifact: EtdagParameterArtifact,
    pub fee_schedule_artifact: EtdagFeeScheduleArtifact,
}

impl EtdagGovernedGenesisBinding {
    pub fn validate(&self) -> Result<(), String> {
        if self.schema_version != ETDAG_GOVERNED_GENESIS_BINDING_SCHEMA_VERSION
            || self.status != ETDAG_GOVERNED_GENESIS_BINDING_STATUS
        {
            return Err("ETDAG Genesis binding schema or status is invalid".to_string());
        }
        self.parameter_artifact.validate()?;
        self.fee_schedule_artifact.validate()?;
        let parameter_root = &self.parameter_artifact.etdag_parameter_root_sha3_512;
        if parameter_root.is_zero()
            || self
                .fee_schedule_artifact
                .etdag_fee_schedule_root_sha3_512
                .is_zero()
        {
            return Err("ETDAG Genesis binding roots must not be zero".to_string());
        }
        if self
            .fee_schedule_artifact
            .manifest
            .etdag_parameter_root_sha3_512
            != *parameter_root
        {
            return Err(
                "ETDAG Genesis fee schedule is not bound to the committed parameter root"
                    .to_string(),
            );
        }
        if self.parameter_artifact.manifest.chain_id != self.fee_schedule_artifact.manifest.chain_id
            || self.parameter_artifact.manifest.network_id
                != self.fee_schedule_artifact.manifest.network_id
            || self.parameter_artifact.manifest.consensus_protocol_version
                != self
                    .fee_schedule_artifact
                    .manifest
                    .consensus_protocol_version
        {
            return Err(
                "ETDAG Genesis parameter and fee artifacts have inconsistent network bindings"
                    .to_string(),
            );
        }
        if self.parameter_artifact.manifest.governance_decision_id
            != self.fee_schedule_artifact.manifest.governance_decision_id
        {
            return Err(
                "ETDAG Genesis parameter and fee artifacts must carry the same final governance decision"
                    .to_string(),
            );
        }
        Ok(())
    }

    /// The strict, canonical transport encoding of the complete Genesis
    /// binding.  This is intentionally distinct from the two individually
    /// rooted policy artifacts: it is the exact public object the Genesis
    /// finalizer loads and commits atomically with consensus parameters.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, String> {
        self.validate()?;
        serde_json::to_vec(self)
            .map_err(|error| format!("serialize canonical ETDAG Genesis binding: {error}"))
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, String> {
        let binding: Self = serde_json::from_slice(bytes)
            .map_err(|error| format!("decode ETDAG Genesis binding: {error}"))?;
        if binding.canonical_bytes()? != bytes {
            return Err("non-canonical ETDAG Genesis binding serialization rejected".to_string());
        }
        Ok(binding)
    }
}

/// Public consensus key material for one membership-anchor validator.
///
/// This intentionally has no private-key, custody, or test-only field.  The
/// strict schema rejects any attempt to smuggle one into a trust-anchor JSON
/// document rather than silently ignoring it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EtdagMembershipConsensusPublicKey {
    pub key_id: String,
    pub algorithm: String,
    pub key_bytes: Vec<u8>,
}

/// A minimal, public-only validator membership record for the Wallet trust
/// anchor.  It is deliberately distinct from the runtime `ValidatorRecord`:
/// that wider internal type accepts extension fields during deserialization,
/// while a public trust anchor must reject them.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EtdagMembershipValidator {
    pub validator_id: String,
    pub consensus_public_key: EtdagMembershipConsensusPublicKey,
    pub voting_weight: u64,
}

/// Post-Genesis membership-anchor input.  It is not part of the Genesis hash
/// because its `genesis_hash` field binds the already-finalized Genesis.
///
/// Governance must sign this canonical payload separately after Genesis has
/// been finalized.  This avoids the circular dependency that would result
/// from embedding a signature whose payload includes the Genesis hash back
/// into the Genesis document.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EtdagGovernedMembershipAnchor {
    pub schema: String,
    pub governance_decision_id: String,
    pub genesis_hash: String,
    pub deployed_execution_state_root: String,
    pub genesis_activation_binding_digest: EtdagGovernedRoot,
    pub initial_epoch: u64,
    pub initial_consensus_parameter_root: EtdagGovernedRoot,
    pub initial_validator_set: EtdagInitialValidatorSet,
    pub anchor_digest: EtdagGovernedRoot,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EtdagInitialValidatorSet {
    pub validators: Vec<EtdagMembershipValidator>,
}

impl EtdagGovernedMembershipAnchor {
    pub fn validate(&self) -> Result<(), String> {
        require_schema(
            &self.schema,
            ETDAG_GOVERNED_MEMBERSHIP_PROOF_SCHEMA,
            "ETDAG governed membership anchor",
        )?;
        require_final_governance_decision_id(&self.governance_decision_id)?;
        require_lower_hex(
            &self.genesis_hash,
            64,
            "ETDAG membership anchor genesis_hash",
        )?;
        require_lower_hex(
            &self.deployed_execution_state_root,
            64,
            "ETDAG membership anchor deployed_execution_state_root",
        )?;
        if self.genesis_activation_binding_digest.is_zero()
            || self.initial_consensus_parameter_root.is_zero()
            || self.anchor_digest.is_zero()
        {
            return Err("ETDAG membership anchor digests must not be zero".to_string());
        }
        if self.initial_epoch != 0 {
            return Err("ETDAG membership anchor initial_epoch must be zero".to_string());
        }
        validate_initial_validator_set(&self.initial_validator_set).and_then(|_| {
            if self.anchor_digest != self.expected_anchor_digest()? {
                Err(
                    "ETDAG membership anchor digest does not match its canonical payload"
                        .to_string(),
                )
            } else {
                Ok(())
            }
        })
    }

    /// Derives the published `anchor_digest` without serializing the digest
    /// field itself.  The resulting field is therefore deterministic and
    /// non-circular while the full document remains strict canonical JSON.
    pub fn expected_anchor_digest(&self) -> Result<EtdagGovernedRoot, String> {
        self.validate_payload()?;
        let preimage = EtdagGovernedMembershipAnchorPreimage {
            schema: &self.schema,
            governance_decision_id: &self.governance_decision_id,
            genesis_hash: &self.genesis_hash,
            deployed_execution_state_root: &self.deployed_execution_state_root,
            genesis_activation_binding_digest: &self.genesis_activation_binding_digest,
            initial_epoch: self.initial_epoch,
            initial_consensus_parameter_root: &self.initial_consensus_parameter_root,
            initial_validator_set: &self.initial_validator_set,
        };
        let bytes = serde_json::to_vec(&preimage)
            .map_err(|error| format!("serialize ETDAG membership anchor preimage: {error}"))?;
        Ok(EtdagGovernedRoot::from_canonical_manifest_bytes(&bytes))
    }

    fn validate_payload(&self) -> Result<(), String> {
        require_schema(
            &self.schema,
            ETDAG_GOVERNED_MEMBERSHIP_PROOF_SCHEMA,
            "ETDAG governed membership anchor",
        )?;
        require_final_governance_decision_id(&self.governance_decision_id)?;
        require_lower_hex(
            &self.genesis_hash,
            64,
            "ETDAG membership anchor genesis_hash",
        )?;
        require_lower_hex(
            &self.deployed_execution_state_root,
            64,
            "ETDAG membership anchor deployed_execution_state_root",
        )?;
        if self.genesis_activation_binding_digest.is_zero()
            || self.initial_consensus_parameter_root.is_zero()
        {
            return Err("ETDAG membership anchor digests must not be zero".to_string());
        }
        if self.initial_epoch != 0 {
            return Err("ETDAG membership anchor initial_epoch must be zero".to_string());
        }
        validate_initial_validator_set(&self.initial_validator_set)
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, String> {
        self.validate()?;
        serde_json::to_vec(self).map_err(|error| {
            format!("serialize canonical ETDAG governed membership anchor: {error}")
        })
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, String> {
        let anchor: Self = serde_json::from_slice(bytes)
            .map_err(|error| format!("decode ETDAG governed membership anchor: {error}"))?;
        if anchor.canonical_bytes()? != bytes {
            return Err(
                "non-canonical ETDAG governed membership anchor serialization rejected".to_string(),
            );
        }
        Ok(anchor)
    }
}

/// Creates the public-only Wallet/RPC trust anchor after a fresh P3 Genesis
/// candidate has its final execution-state root.  This derives every
/// validator fact from the Genesis-bound activation record; callers cannot
/// supply a parallel validator list or any private key material.
pub fn build_etdag_governed_membership_anchor(
    governance_decision_id: String,
    genesis_hash: String,
    deployed_execution_state_root: String,
    activation: &crate::consensus::simplified_posy::GenesisBoundSimplifiedActivation,
) -> Result<EtdagGovernedMembershipAnchor, String> {
    activation.validate()?;
    require_final_governance_decision_id(&governance_decision_id)?;
    require_lower_hex(&genesis_hash, 64, "ETDAG membership anchor genesis_hash")?;
    require_lower_hex(
        &deployed_execution_state_root,
        64,
        "ETDAG membership anchor deployed_execution_state_root",
    )?;
    if activation.activation_epoch != 0 {
        return Err("fresh PoSy membership anchor must start at epoch zero".to_string());
    }

    let activation_bytes = serde_json::to_vec(activation)
        .map_err(|error| format!("serialize Genesis activation for ETDAG anchor: {error}"))?;
    let genesis_activation_binding_digest =
        EtdagGovernedRoot::from_canonical_manifest_bytes(&activation_bytes);
    let initial_consensus_parameter_root =
        EtdagGovernedRoot::from_hex(&activation.parameter_root_sha3_512)?;
    let mut validators = activation
        .frozen_validator_set
        .active_for_epoch(crate::synergy_types::Epoch(0))
        .validators;
    validators.sort_by(|left, right| left.validator_id.cmp(&right.validator_id));
    let initial_validator_set = EtdagInitialValidatorSet {
        validators: validators
            .into_iter()
            .map(|validator| EtdagMembershipValidator {
                validator_id: validator.validator_id.0,
                consensus_public_key: EtdagMembershipConsensusPublicKey {
                    key_id: validator.consensus_public_key.key_id.0,
                    algorithm: validator.consensus_public_key.algorithm,
                    key_bytes: validator.consensus_public_key.key_bytes,
                },
                voting_weight: validator.voting_weight,
            })
            .collect(),
    };
    let mut anchor = EtdagGovernedMembershipAnchor {
        schema: ETDAG_GOVERNED_MEMBERSHIP_PROOF_SCHEMA.to_string(),
        governance_decision_id,
        genesis_hash,
        deployed_execution_state_root,
        genesis_activation_binding_digest,
        initial_epoch: 0,
        initial_consensus_parameter_root,
        initial_validator_set,
        anchor_digest: EtdagGovernedRoot::from_hex(&"01".repeat(64))?,
    };
    anchor.anchor_digest = anchor.expected_anchor_digest()?;
    anchor.validate()?;
    Ok(anchor)
}

#[derive(Serialize)]
struct EtdagGovernedMembershipAnchorPreimage<'a> {
    schema: &'a str,
    governance_decision_id: &'a str,
    genesis_hash: &'a str,
    deployed_execution_state_root: &'a str,
    genesis_activation_binding_digest: &'a EtdagGovernedRoot,
    initial_epoch: u64,
    initial_consensus_parameter_root: &'a EtdagGovernedRoot,
    initial_validator_set: &'a EtdagInitialValidatorSet,
}

fn require_schema(actual: &str, expected: &str, label: &str) -> Result<(), String> {
    if actual != expected {
        return Err(format!("{label} schema must be {expected}"));
    }
    Ok(())
}

fn require_consensus_protocol_version(value: &str) -> Result<(), String> {
    if value != crate::consensus::simplified_posy::POSY_SIMPLIFIED_PROTOCOL_VERSION {
        return Err(format!(
            "ETDAG governed artifact consensus_protocol_version must be {}",
            crate::consensus::simplified_posy::POSY_SIMPLIFIED_PROTOCOL_VERSION
        ));
    }
    Ok(())
}

fn require_final_governance_decision_id(value: &str) -> Result<(), String> {
    if value.is_empty()
        || value.trim() != value
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
    {
        return Err("governance_decision_id must be a non-empty canonical identifier".to_string());
    }

    let lower = value.to_ascii_lowercase();
    for forbidden in ["test", "pending", "candidate", "provisional"] {
        if lower.contains(forbidden) {
            return Err(format!(
                "governance_decision_id must not contain the non-final marker {forbidden}"
            ));
        }
    }
    Ok(())
}

fn require_lower_hex(value: &str, expected_length: usize, label: &str) -> Result<(), String> {
    if value.len() != expected_length
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(format!(
            "{label} must be {expected_length} lowercase hexadecimal characters"
        ));
    }
    Ok(())
}

fn validate_fee_schedule(schedule: &FeeSchedule) -> Result<(), String> {
    let expected_types = [
        TransactionFeeType::NativeSnrgSend,
        TransactionFeeType::TokenSend,
        TransactionFeeType::Swap,
        TransactionFeeType::Burn,
        TransactionFeeType::Mint,
        TransactionFeeType::Stake,
        TransactionFeeType::Unstake,
        TransactionFeeType::ContractCall,
        TransactionFeeType::ContractDeploy,
        TransactionFeeType::AiJobPayment,
        TransactionFeeType::SxcpCrossChainValueAction,
        TransactionFeeType::Unknown,
    ];

    if schedule.entries.len() != expected_types.len() {
        return Err(format!(
            "ETDAG fee schedule must contain exactly {} transaction fee entries",
            expected_types.len()
        ));
    }

    for (index, (entry, expected_type)) in schedule.entries.iter().zip(expected_types).enumerate() {
        if entry.tx_type != expected_type {
            return Err(format!(
                "ETDAG fee schedule entry {index} is not in the required canonical transaction-type order"
            ));
        }
        if entry.amount_fee_bps > BPS_DENOMINATOR {
            return Err(format!(
                "ETDAG fee schedule entry {} exceeds the basis-point denominator",
                entry.tx_type.as_str()
            ));
        }
        if entry.min_amount_fee_nwei > entry.max_amount_fee_nwei {
            return Err(format!(
                "ETDAG fee schedule entry {} has a minimum above its maximum",
                entry.tx_type.as_str()
            ));
        }
    }
    Ok(())
}

fn validate_fee_market_params(params: &FeeMarketParams) -> Result<(), String> {
    params
        .validate()
        .map_err(|error| format!("ETDAG fee-market parameters are invalid: {error}"))?;
    if !params.fee_market_enabled {
        return Err("ETDAG governed fee market must be enabled".to_string());
    }
    if params.activation_height != 1 {
        return Err("ETDAG governed fee market must activate at fresh P3 block one".to_string());
    }
    if params.initial_base_fee_nwei < params.base_fee_floor_nwei {
        return Err("ETDAG governed initial base fee must not be below its floor".to_string());
    }
    if params.fee_market_version != crate::gas::fee_market::FEE_MARKET_VERSION {
        return Err("ETDAG governed fee-market version is unsupported".to_string());
    }
    Ok(())
}

fn validate_initial_validator_set(set: &EtdagInitialValidatorSet) -> Result<(), String> {
    if set.validators.is_empty() {
        return Err("ETDAG membership anchor validator set must not be empty".to_string());
    }

    let mut prior_id: Option<&str> = None;
    let mut validator_ids = BTreeSet::new();
    let mut key_ids = BTreeSet::new();
    let mut public_key_commitments = BTreeSet::new();
    for validator in &set.validators {
        if validator.validator_id.is_empty()
            || !validator
                .validator_id
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        {
            return Err("ETDAG membership validator_id must be lowercase kebab-case".to_string());
        }
        if prior_id.is_some_and(|prior| prior >= validator.validator_id.as_str()) {
            return Err(
                "ETDAG membership validators must be strictly sorted by validator_id".to_string(),
            );
        }
        prior_id = Some(&validator.validator_id);
        if !validator_ids.insert(&validator.validator_id) {
            return Err("ETDAG membership validator_id is duplicated".to_string());
        }
        if validator.voting_weight == 0 {
            return Err("ETDAG membership validator voting_weight must be non-zero".to_string());
        }

        let key = &validator.consensus_public_key;
        if key.key_id.is_empty()
            || key.key_id.trim() != key.key_id
            || key.key_id.bytes().any(|byte| byte.is_ascii_whitespace())
        {
            return Err("ETDAG membership consensus key_id is invalid".to_string());
        }
        if key.algorithm != TESTNET_V3_CONSENSUS_SIGNATURE_ALGORITHM {
            return Err(format!(
                "ETDAG membership consensus key algorithm must be {TESTNET_V3_CONSENSUS_SIGNATURE_ALGORITHM}"
            ));
        }
        if key.key_bytes.len() != TESTNET_V3_MLDSA65_PUBLIC_KEY_BYTES {
            return Err(format!(
                "ETDAG membership consensus public key must be {TESTNET_V3_MLDSA65_PUBLIC_KEY_BYTES} bytes"
            ));
        }
        if !key_ids.insert(&key.key_id) {
            return Err("ETDAG membership consensus key_id is duplicated".to_string());
        }
        if !public_key_commitments.insert(hex::encode(&key.key_bytes)) {
            return Err("ETDAG membership consensus public key is duplicated".to_string());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gas::FeeScheduleEntry;

    const FINAL_DECISION: &str = "GOV-ETDAG-20260823-001";

    fn parameter_manifest() -> EtdagParameterManifest {
        EtdagParameterManifest {
            schema: ETDAG_PARAMETER_MANIFEST_SCHEMA.to_string(),
            governance_decision_id: FINAL_DECISION.to_string(),
            chain_id: ChainId::synergy_testnet_v3(),
            network_id: NetworkId::fresh_posy_testnet_v3(),
            consensus_protocol_version:
                crate::consensus::simplified_posy::POSY_SIMPLIFIED_PROTOCOL_VERSION.to_string(),
            parameters: EtdagParameters::default(),
        }
    }

    fn fee_schedule_manifest(parameter_root: EtdagGovernedRoot) -> EtdagFeeScheduleManifest {
        EtdagFeeScheduleManifest {
            schema: ETDAG_FEE_SCHEDULE_MANIFEST_SCHEMA.to_string(),
            governance_decision_id: FINAL_DECISION.to_string(),
            chain_id: ChainId::synergy_testnet_v3(),
            network_id: NetworkId::fresh_posy_testnet_v3(),
            consensus_protocol_version:
                crate::consensus::simplified_posy::POSY_SIMPLIFIED_PROTOCOL_VERSION.to_string(),
            etdag_parameter_root_sha3_512: parameter_root,
            fee_schedule: FeeSchedule::default(),
            fee_market_params: FeeMarketParams::testnet_v3_defaults(),
        }
    }

    fn membership_anchor() -> EtdagGovernedMembershipAnchor {
        let mut anchor = EtdagGovernedMembershipAnchor {
            schema: ETDAG_GOVERNED_MEMBERSHIP_PROOF_SCHEMA.to_string(),
            governance_decision_id: FINAL_DECISION.to_string(),
            genesis_hash: "ab".repeat(32),
            deployed_execution_state_root: "ef".repeat(32),
            genesis_activation_binding_digest: EtdagGovernedRoot::from_hex(&"12".repeat(64))
                .expect("fixed SHA3-512 root"),
            initial_epoch: 0,
            initial_consensus_parameter_root: EtdagGovernedRoot::from_hex(&"cd".repeat(64))
                .expect("fixed SHA3-512 root"),
            initial_validator_set: EtdagInitialValidatorSet {
                validators: (2..=6)
                    .map(|index| EtdagMembershipValidator {
                        validator_id: format!("validator-{index:02}"),
                        consensus_public_key: EtdagMembershipConsensusPublicKey {
                            key_id: format!("validator-{index:02}-consensus"),
                            algorithm: TESTNET_V3_CONSENSUS_SIGNATURE_ALGORITHM.to_string(),
                            key_bytes: vec![index as u8; TESTNET_V3_MLDSA65_PUBLIC_KEY_BYTES],
                        },
                        voting_weight: 1,
                    })
                    .collect(),
            },
            anchor_digest: EtdagGovernedRoot::from_hex(&"34".repeat(64))
                .expect("fixed SHA3-512 root"),
        };
        anchor.anchor_digest = anchor.expected_anchor_digest().expect("anchor digest");
        anchor
    }

    #[test]
    fn parameter_artifact_recomputes_a_strict_sha3_512_root() {
        let artifact = EtdagParameterArtifact::from_manifest(parameter_manifest())
            .expect("valid parameter artifact");
        assert_eq!(artifact.etdag_parameter_root_sha3_512.to_hex().len(), 128);
        assert!(artifact.validate().is_ok());
        assert!(
            EtdagGovernedRoot::from_hex(&artifact.etdag_parameter_root_sha3_512.to_hex()).is_ok()
        );
        assert!(EtdagGovernedRoot::from_hex(
            &artifact
                .etdag_parameter_root_sha3_512
                .to_hex()
                .to_uppercase()
        )
        .is_err());
    }

    #[test]
    fn launch_governance_inputs_have_stable_reproducible_roots() {
        let decision = "SNRG-GOV-ETDAG-P3-GENESIS-20260823-01".to_string();
        let mut parameter = parameter_manifest();
        parameter.governance_decision_id = decision.clone();
        let parameter_root = parameter.root().expect("parameter root");
        assert_eq!(
            parameter_root.to_hex(),
            "732e970816589c4eabc7a9c71facb6d73b4805e599c7fccee081ce2d75a7a5ff9ba8f46c7f04dc6ff42ffdb9468e7f18b554ed233cdb8555d5207894fba3dd25"
        );

        let mut fee = fee_schedule_manifest(parameter_root);
        fee.governance_decision_id = decision;
        assert_eq!(
            fee.root().expect("fee root").to_hex(),
            "8478f93ce35b6fd157157263532711f34fd67880a6d6863749ef17cde996aaf653c8e48e97bf5e5b6bf09ec3a08470d854e7fe23e8e75a8204b5b0b5c64e47f0"
        );
    }

    #[test]
    fn parameter_artifact_rejects_a_declared_root_mismatch_and_noncanonical_json() {
        let mut artifact = EtdagParameterArtifact::from_manifest(parameter_manifest())
            .expect("valid parameter artifact");
        artifact.etdag_parameter_root_sha3_512 =
            EtdagGovernedRoot::from_hex(&"00".repeat(64)).expect("valid fixed root");
        assert!(artifact.validate().is_err());

        let canonical = EtdagParameterArtifact::from_manifest(parameter_manifest())
            .expect("valid parameter artifact")
            .canonical_bytes()
            .expect("canonical bytes");
        let mut noncanonical = b" ".to_vec();
        noncanonical.extend(canonical);
        assert!(EtdagParameterArtifact::from_canonical_bytes(&noncanonical).is_err());
    }

    #[test]
    fn fee_schedule_rejects_wrong_order_and_invalid_bounds() {
        let root = parameter_manifest().root().expect("parameter root");
        let mut manifest = fee_schedule_manifest(root.clone());
        manifest.fee_schedule.entries.swap(0, 1);
        assert!(manifest.validate().is_err());

        let mut manifest = fee_schedule_manifest(root);
        manifest.fee_schedule.entries[0] = FeeScheduleEntry {
            min_amount_fee_nwei: 2,
            max_amount_fee_nwei: 1,
            ..manifest.fee_schedule.entries[0].clone()
        };
        assert!(manifest.validate().is_err());
    }

    #[test]
    fn fee_schedule_rejects_ungovernable_fee_market_configuration() {
        let root = parameter_manifest().root().expect("parameter root");
        let mut manifest = fee_schedule_manifest(root);
        manifest.fee_market_params.activation_height = 2;
        assert!(manifest.validate().is_err());

        let root = parameter_manifest().root().expect("parameter root");
        let mut manifest = fee_schedule_manifest(root);
        manifest.fee_market_params.initial_base_fee_nwei = 0;
        assert!(manifest.validate().is_err());
    }

    #[test]
    fn genesis_binding_rejects_fee_artifacts_for_another_parameter_root() {
        let parameter_artifact = EtdagParameterArtifact::from_manifest(parameter_manifest())
            .expect("parameter artifact");
        let fee_schedule_artifact = EtdagFeeScheduleArtifact::from_manifest(fee_schedule_manifest(
            parameter_artifact.etdag_parameter_root_sha3_512.clone(),
        ))
        .expect("fee artifact");
        let binding = EtdagGovernedGenesisBinding {
            schema_version: ETDAG_GOVERNED_GENESIS_BINDING_SCHEMA_VERSION,
            status: ETDAG_GOVERNED_GENESIS_BINDING_STATUS.to_string(),
            parameter_artifact: parameter_artifact.clone(),
            fee_schedule_artifact: fee_schedule_artifact.clone(),
        };
        assert!(binding.validate().is_ok());

        let mut mismatched = binding;
        mismatched
            .fee_schedule_artifact
            .manifest
            .etdag_parameter_root_sha3_512 =
            EtdagGovernedRoot::from_hex(&"ab".repeat(64)).expect("fixed SHA3-512 root");
        assert!(mismatched.validate().is_err());
    }

    #[test]
    fn genesis_binding_requires_one_final_governance_decision_and_canonical_bytes() {
        let parameter_artifact = EtdagParameterArtifact::from_manifest(parameter_manifest())
            .expect("parameter artifact");
        let fee_schedule_artifact = EtdagFeeScheduleArtifact::from_manifest(fee_schedule_manifest(
            parameter_artifact.etdag_parameter_root_sha3_512.clone(),
        ))
        .expect("fee artifact");
        let binding = EtdagGovernedGenesisBinding {
            schema_version: ETDAG_GOVERNED_GENESIS_BINDING_SCHEMA_VERSION,
            status: ETDAG_GOVERNED_GENESIS_BINDING_STATUS.to_string(),
            parameter_artifact,
            fee_schedule_artifact,
        };
        let canonical = binding.canonical_bytes().expect("canonical binding");
        assert_eq!(
            EtdagGovernedGenesisBinding::from_canonical_bytes(&canonical)
                .expect("decode canonical binding"),
            binding
        );

        let mut mismatched_decision = binding;
        mismatched_decision
            .fee_schedule_artifact
            .manifest
            .governance_decision_id = "GOV-ETDAG-20260823-002".to_string();
        assert!(mismatched_decision.validate().is_err());
    }

    #[test]
    fn membership_anchor_rejects_nonfinal_or_secret_bearing_json() {
        let anchor = membership_anchor();
        assert!(anchor.validate().is_ok());

        let mut provisional = anchor.clone();
        provisional.governance_decision_id = "candidate-etdag-root".to_string();
        assert!(provisional.validate().is_err());

        let mut mismatched_digest = anchor.clone();
        mismatched_digest.anchor_digest =
            EtdagGovernedRoot::from_hex(&"56".repeat(64)).expect("fixed SHA3-512 root");
        assert!(mismatched_digest.validate().is_err());

        let mut value = serde_json::to_value(&anchor).expect("serialize anchor");
        value["initial_validator_set"]["validators"][0]["test_only_secret_material"] =
            serde_json::Value::Bool(true);
        assert!(serde_json::from_value::<EtdagGovernedMembershipAnchor>(value).is_err());
    }
}
