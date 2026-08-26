//! PoSy v3 governed encrypted transaction DAG (ETDAG).
//!
//! This module is the consensus-critical sealed-ingress and protected-ordering
//! implementation.  It intentionally does not reuse the legacy plaintext
//! `DagMempool`: ordinary user payloads are encrypted by the wallet, availability
//! and ordering are certified under the immutable target-height context, and
//! plaintext is released only after the BOC/VC reveal gate.

use crate::consensus::simplified_posy::POSY_SIMPLIFIED_PROTOCOL_VERSION;
use crate::consensus_parameters::{ConsensusParameterRoot, EtdagActivationPermit};
use crate::crypto::aegis_pqvm::{AegisPqKeyLifecycleRecord, AegisPqvmSigner, AegisPqvmVerifier};
use crate::synergy_types::{
    AegisPqKeyId, AegisPqKeyRole, AegisPqPublicKey, AegisPqSignature, BlockId, CanonicalSerialize,
    ChainId, ClusterId, ClusterMap, Epoch, Hash, Height, HeightConsensusContext, NetworkId,
    ProtectedBatchCommitment, ProtocolConfig, QuorumCertificate, Round, Transaction, UmaId,
    ValidatorId, ValidatorRecord, ValidatorSet, ValidatorStatus, VotePhase,
    TESTNET_V3_CLUSTER_SCHEDULE_VERSION,
};
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use pqcrypto_mlkem::mlkem1024;
use pqcrypto_traits::kem::{Ciphertext as _, PublicKey as _, SecretKey as _, SharedSecret as _};
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use sha3::{Digest as _, Sha3_512};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

pub const ETDAG_PROFILE_ID: &str = "POSY-ETDAG-v3.0";
pub const ETDAG_LANE_ID: &str = "ordinary-user";
pub const ERR_PLAINTEXT_USER_TX_DISABLED: &str = "ERR_PLAINTEXT_USER_TX_DISABLED";
pub const ETDAG_JOURNAL_FORMAT: &str = "synergy-etdag-safety-journal-v1";
pub const ETDAG_JOURNAL_FILE: &str = "etdag_safety_journal.json";
pub const ETDAG_ADMISSION_STORE_FORMAT: &str = "synergy-etdag-admission-package-store-v1";
pub const ETDAG_ADMISSION_STORE_FILE: &str = "etdag_admission_packages.json";
pub const ETDAG_PROTECTED_INPUT_STORE_FORMAT: &str =
    "synergy-etdag-certified-protected-input-store-v1";
pub const ETDAG_PROTECTED_INPUT_STORE_FILE: &str = "etdag_certified_protected_inputs.json";
/// There can be at most four concurrently useful H+3 admission windows.  The
/// store deliberately refuses unbounded historical accumulation; finalized
/// inputs are consumed by the typed coordinator and need not remain here.
pub const MAX_ETDAG_PROTECTED_INPUT_STORE_ENTRIES: usize = MAX_OUTSTANDING_NONCE_SLOTS as usize;
/// This bound covers complete public proof packages, not just ciphertext.  It
/// is intentionally independent of the RPC ingress-pool limit so a peer cannot
/// turn certificate gossip into durable unbounded storage.
pub const MAX_ETDAG_PROTECTED_INPUT_STORE_SERIALIZED_BYTES: usize = 64 * 1024 * 1024;
/// Certified ETDAG artifacts travel over the existing bounded P2P frame.  Keep
/// a margin below that framing limit for the NetworkMessage envelope and JSON
/// representation, so a locally accepted proof package is never emitted as an
/// oversized transport frame.
pub const MAX_ETDAG_CERTIFIED_INPUT_WIRE_BYTES: usize = 60 * 1024 * 1024;
pub const TARGET_ADMISSION_CONTEXT_VERSION: u32 = 1;
pub const INGRESS_KEM_REGISTRY_VERSION: u32 = 1;
pub const MAX_OUTSTANDING_NONCE_SLOTS: u64 = 4;
pub const MAX_CALL_DEPTH: usize = 64;
pub const CIPHERTEXT_SIZE_CLASSES: &[usize] =
    &[512, 1024, 2048, 4096, 8192, 16384, 32768, 65536, 131072];

pub const DOMAIN_ETE_OUTER: &str = "PoSy/ETDAG/ETE/Outer/v3";
pub const DOMAIN_VERTEX: &str = "PoSy/ETDAG/Vertex/v3";
pub const DOMAIN_VAC: &str = "PoSy/ETDAG/VAC/v3";
pub const DOMAIN_DCC: &str = "PoSy/ETDAG/DCC/v3";
pub const DOMAIN_BATCH_VALIDATE: &str = "PoSy/ETDAG/BatchValidate/v3";
pub const DOMAIN_BATCH_FINALITY: &str = "PoSy/ETDAG/BatchFinality/v3";
pub const DOMAIN_BATCH_TIMEOUT: &str = "PoSy/ETDAG/BatchTimeout/v3";
pub const DOMAIN_DECRYPT_SHARE: &str = "PoSy/ETDAG/DecryptShare/v3";
pub const DOMAIN_TARGET_ADMISSION: &str = "PoSy/ETDAG/TargetAdmission/v3";
/// Commits the 512-bit canonical finalized-context digest into the 256-bit
/// root field used by the target-admission context.  The domain prevents a
/// raw 32-byte consensus hash from being substituted for the full ETDAG
/// finality context.
pub const DOMAIN_TARGET_ADMISSION_SOURCE_FINALITY: &str =
    "PoSy/ETDAG/TargetAdmission/SourceFinality/v3";
pub const DOMAIN_ORDER_SEED: &str = "PoSy/ETDAG/OrderSeed/v3";
pub const DOMAIN_ORDER_KEY: &str = "PoSy/ETDAG/Order/v3";
pub const PROTECTED_PIPELINE_VERSION: u32 = 1;
pub const DOMAIN_PROTECTED_CUT_MARKER_EVIDENCE: &str =
    "PoSy/ProtectedPipeline/CutMarkerEvidence/v1";
pub const DOMAIN_PROTECTED_CUT_SEMANTIC: &str = "PoSy/ProtectedPipeline/CutSemantic/v1";
pub const DOMAIN_PROTECTED_CUT_PROOF: &str = "PoSy/ProtectedPipeline/CutProof/v1";
pub const DOMAIN_PROTECTED_ORDER_ROOT: &str = "PoSy/ProtectedPipeline/OrderRoot/v1";
pub const DOMAIN_PROTECTED_BATCH: &str = "PoSy/ProtectedPipeline/Batch/v1";
pub const DOMAIN_NEXT_PROTECTED_BATCH_COMMITMENT: &str =
    "PoSy/ProtectedPipeline/NextBatchCommitment/v1";
pub const DOMAIN_PROTECTED_REVEAL_AUTHORIZATION: &str =
    "PoSy/ProtectedPipeline/RevealAuthorization/v1";
pub const DOMAIN_PROTECTED_REVEAL_SHARE: &str = "PoSy/ProtectedPipeline/RevealShare/v1";
pub const DOMAIN_PROTECTED_REVEAL_TRANSCRIPT: &str = "PoSy/ProtectedPipeline/RevealTranscript/v1";
pub const DOMAIN_PROTECTED_EXECUTION_INPUT: &str = "PoSy/ProtectedPipeline/ExecutionInput/v1";

fn require_process_wide_consensus_signing_allowed() -> Result<(), String> {
    #[cfg(test)]
    {
        Ok(())
    }
    #[cfg(not(test))]
    {
        crate::consensus::signing_authority::DurableConsensusSigningAuthority::process_wide()
            .require_signing_allowed()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(transparent)]
pub struct EtdagDigest(pub String);

impl EtdagDigest {
    pub fn zero() -> Self {
        Self("0".repeat(128))
    }

    pub fn is_zero(&self) -> bool {
        self.0 == "0".repeat(128)
    }

    pub fn from_domain_bytes(domain: &str, bytes: &[u8]) -> Self {
        let mut hasher = Sha3_512::new();
        hasher.update((domain.len() as u64).to_be_bytes());
        hasher.update(domain.as_bytes());
        hasher.update((bytes.len() as u64).to_be_bytes());
        hasher.update(bytes);
        Self(hex::encode(hasher.finalize()))
    }

    pub fn from_canonical<T: CanonicalSerialize>(domain: &str, value: &T) -> Result<Self, String> {
        Ok(Self::from_domain_bytes(domain, &value.canonical_bytes()?))
    }

    pub fn validate(&self, name: &str) -> Result<(), String> {
        let bytes = hex::decode(&self.0).map_err(|_| format!("{name} is not canonical hex"))?;
        if bytes.len() != 64 {
            return Err(format!("{name} must be a SHA3-512 digest"));
        }
        Ok(())
    }

    fn bytes(&self) -> Result<Vec<u8>, String> {
        self.validate("ETDAG digest")?;
        hex::decode(&self.0).map_err(|error| format!("decode ETDAG digest: {error}"))
    }
}

/// Derive the fixed-width source-finality commitment required by
/// [`TargetAdmissionContext`].  The source digest itself is a SHA3-512
/// `EtdagDigest`, while the context's frozen-root fields use `Hash` (256-bit).
/// This conversion is therefore explicit and domain separated rather than an
/// unchecked truncation or an operator-supplied substitute.
pub fn target_admission_source_finality_root(
    source_finality_context_digest: &EtdagDigest,
) -> Result<Hash, String> {
    let bytes = source_finality_context_digest.bytes()?;
    Ok(Hash::from_domain_bytes(
        DOMAIN_TARGET_ADMISSION_SOURCE_FINALITY,
        &bytes,
    ))
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EtdagParameters {
    pub profile_id: String,
    pub target_height_offset_default: u64,
    pub max_outstanding_nonce_slots: u64,
    pub max_protected_gas: u64,
    pub max_protected_bytes: u64,
    pub ciphertext_size_classes: Vec<u64>,
}

impl Default for EtdagParameters {
    fn default() -> Self {
        Self {
            profile_id: ETDAG_PROFILE_ID.to_string(),
            target_height_offset_default: 3,
            max_outstanding_nonce_slots: MAX_OUTSTANDING_NONCE_SLOTS,
            max_protected_gas: 30_000_000,
            max_protected_bytes: 8 * 1024 * 1024,
            ciphertext_size_classes: CIPHERTEXT_SIZE_CLASSES
                .iter()
                .map(|value| *value as u64)
                .collect(),
        }
    }
}

impl EtdagParameters {
    pub fn validate(&self) -> Result<(), String> {
        if self.profile_id != ETDAG_PROFILE_ID {
            return Err("unsupported ETDAG profile".to_string());
        }
        if self.target_height_offset_default < 3 {
            return Err("ETDAG look-ahead must be at least three heights".to_string());
        }
        if self.max_outstanding_nonce_slots == 0
            || self.max_protected_gas == 0
            || self.max_protected_bytes == 0
        {
            return Err("ETDAG resource limits must be non-zero".to_string());
        }
        let expected = CIPHERTEXT_SIZE_CLASSES
            .iter()
            .map(|value| *value as u64)
            .collect::<Vec<_>>();
        if self.ciphertext_size_classes != expected {
            return Err("ETDAG ciphertext size classes do not match v3.0".to_string());
        }
        Ok(())
    }

    pub fn root(&self) -> Result<EtdagDigest, String> {
        self.validate()?;
        EtdagDigest::from_canonical("PoSy/ETDAG/Parameters/v3", self)
    }
}

/// Immutable H+3 admission authority.
///
/// This object deliberately excludes the target height's proposer schedule and
/// prior-finalized-QC reference: neither exists when a wallet normally seals
/// for H+3. It freezes only the target-height facts that are already determined
/// by the finalized epoch schedule. A later `HeightConsensusContext` must match
/// every overlapping field before the protected batch can execute.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TargetAdmissionContext {
    pub context_version: u32,
    pub chain_id: ChainId,
    pub network_id: NetworkId,
    pub protocol_version: String,
    pub epoch: Epoch,
    pub target_height: Height,
    pub source_finalized_height: Height,
    pub source_finality_context_root: Hash,
    pub active_validator_set_root: Hash,
    pub validator_consensus_key_root: Hash,
    pub frozen_bonded_weight_root: Hash,
    pub cluster_schedule_version: String,
    pub finalized_epoch_seed_root: Hash,
    pub assigned_height_schedule_root: Hash,
    pub cluster_map_root: Hash,
    pub assigned_cluster_id: ClusterId,
    pub assigned_cluster_membership_root: Hash,
    pub assigned_cluster_validator_count: u64,
    pub assigned_cluster_total_voting_weight: u64,
    pub consensus_parameter_root: ConsensusParameterRoot,
    pub cryptographic_profile_root: Hash,
    pub ingress_kem_registry_root: EtdagDigest,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TargetAdmissionContextSpec {
    pub protocol_version: String,
    pub epoch: Epoch,
    pub target_height: Height,
    pub source_finalized_height: Height,
    pub source_finality_context_root: Hash,
    pub assigned_cluster_id: ClusterId,
    pub cluster_schedule_version: String,
    pub finalized_epoch_seed_root: Hash,
    pub assigned_height_schedule_root: Hash,
    pub cryptographic_profile_root: Hash,
    pub ingress_kem_registry_root: EtdagDigest,
}

impl TargetAdmissionContext {
    pub fn derive(
        spec: TargetAdmissionContextSpec,
        validator_set: &ValidatorSet,
        cluster_map: &ClusterMap,
        protocol_config: &ProtocolConfig,
    ) -> Result<Self, String> {
        protocol_config.chain_id.require_testnet_v3()?;
        protocol_config.network_id.require_fresh_posy_testnet_v3()?;
        Self::derive_with_parameter_root(spec, validator_set, cluster_map, protocol_config.hash()?)
    }

    /// Derive an admission context for a schedule-neutral consensus protocol
    /// from its exact finalized 512-bit manifest root.
    pub fn derive_schedule_neutral(
        spec: TargetAdmissionContextSpec,
        validator_set: &ValidatorSet,
        cluster_map: &ClusterMap,
        consensus_parameter_root: ConsensusParameterRoot,
    ) -> Result<Self, String> {
        Self::derive_with_parameter_root(spec, validator_set, cluster_map, consensus_parameter_root)
    }

    fn derive_with_parameter_root(
        spec: TargetAdmissionContextSpec,
        validator_set: &ValidatorSet,
        cluster_map: &ClusterMap,
        consensus_parameter_root: ConsensusParameterRoot,
    ) -> Result<Self, String> {
        validate_target_admission_spec(&spec)?;
        if consensus_parameter_root.is_zero() {
            return Err("target admission consensus parameter root is missing".to_string());
        }
        if validator_set.epoch != spec.epoch || cluster_map.epoch != spec.epoch {
            return Err("target admission epoch does not match frozen topology".to_string());
        }
        let active_set = validator_set.active_for_epoch(spec.epoch);
        if active_set.validators.is_empty() {
            return Err("target admission active validator set is empty".to_string());
        }
        active_set.validate_unique_validator_and_key_ids()?;
        let expected_map = ClusterMap::derive_from_finalized_epoch_seed(
            &active_set,
            spec.finalized_epoch_seed_root,
        )?;
        if cluster_map.canonicalized() != expected_map {
            return Err("target admission cluster map is not deterministic".to_string());
        }
        cluster_map.validate_complete_balanced_assignment(&active_set)?;
        let members = active_set.active_for_cluster(spec.assigned_cluster_id);
        if members.is_empty() {
            return Err("target admission assigned cluster is empty".to_string());
        }
        let member_count = u64::try_from(members.len())
            .map_err(|_| "target admission cluster size exceeds u64".to_string())?;
        let total_weight = members.iter().try_fold(0u64, |total, validator| {
            total
                .checked_add(validator.voting_weight)
                .ok_or_else(|| "target admission voting-weight total overflow".to_string())
        })?;
        if total_weight == 0 {
            return Err("target admission cluster voting weight is zero".to_string());
        }
        let member_ids = members
            .iter()
            .map(|validator| validator.validator_id.clone())
            .collect::<Vec<_>>();
        let membership_root = Hash::from_domain_bytes(
            "SYNERGY_ASSIGNED_CLUSTER_MEMBERSHIP_V1",
            &(spec.epoch, spec.assigned_cluster_id, member_ids).canonical_bytes()?,
        );
        let context = Self {
            context_version: TARGET_ADMISSION_CONTEXT_VERSION,
            chain_id: ChainId::synergy_testnet_v3(),
            network_id: NetworkId::fresh_posy_testnet_v3(),
            protocol_version: spec.protocol_version,
            epoch: spec.epoch,
            target_height: spec.target_height,
            source_finalized_height: spec.source_finalized_height,
            source_finality_context_root: spec.source_finality_context_root,
            active_validator_set_root: active_set.hash()?,
            validator_consensus_key_root: active_set.consensus_key_root()?,
            frozen_bonded_weight_root: active_set.frozen_bonded_weight_root()?,
            cluster_schedule_version: spec.cluster_schedule_version,
            finalized_epoch_seed_root: spec.finalized_epoch_seed_root,
            assigned_height_schedule_root: spec.assigned_height_schedule_root,
            cluster_map_root: cluster_map.hash()?,
            assigned_cluster_id: spec.assigned_cluster_id,
            assigned_cluster_membership_root: membership_root,
            assigned_cluster_validator_count: member_count,
            assigned_cluster_total_voting_weight: total_weight,
            consensus_parameter_root,
            cryptographic_profile_root: spec.cryptographic_profile_root,
            ingress_kem_registry_root: spec.ingress_kem_registry_root,
        };
        context.validate()?;
        Ok(context)
    }

    pub fn root(&self) -> Result<Hash, String> {
        self.validate()?;
        Ok(Hash::from_domain_bytes(
            "SYNERGY_ETDAG_TARGET_ADMISSION_CONTEXT_V1",
            &self.canonical_bytes()?,
        ))
    }

    pub fn validate(&self) -> Result<(), String> {
        self.chain_id.require_testnet_v3()?;
        self.network_id.require_fresh_posy_testnet_v3()?;
        if self.context_version != TARGET_ADMISSION_CONTEXT_VERSION
            || self.protocol_version != POSY_SIMPLIFIED_PROTOCOL_VERSION
            || self.cluster_schedule_version != TESTNET_V3_CLUSTER_SCHEDULE_VERSION
        {
            return Err("unsupported target admission context version".to_string());
        }
        let minimum_target = self
            .source_finalized_height
            .0
            .checked_add(3)
            .ok_or_else(|| "target admission look-ahead overflow".to_string())?;
        if self.target_height.0 < minimum_target {
            return Err("target admission height must be at least finalized H+3".to_string());
        }
        for (name, root) in [
            (
                "source_finality_context_root",
                self.source_finality_context_root,
            ),
            ("active_validator_set_root", self.active_validator_set_root),
            (
                "validator_consensus_key_root",
                self.validator_consensus_key_root,
            ),
            ("frozen_bonded_weight_root", self.frozen_bonded_weight_root),
            ("finalized_epoch_seed_root", self.finalized_epoch_seed_root),
            (
                "assigned_height_schedule_root",
                self.assigned_height_schedule_root,
            ),
            ("cluster_map_root", self.cluster_map_root),
            (
                "assigned_cluster_membership_root",
                self.assigned_cluster_membership_root,
            ),
            (
                "cryptographic_profile_root",
                self.cryptographic_profile_root,
            ),
        ] {
            if root.is_zero() {
                return Err(format!("target admission {name} is missing"));
            }
        }
        if self.consensus_parameter_root.is_zero() {
            return Err("target admission consensus_parameter_root is missing".to_string());
        }
        self.ingress_kem_registry_root
            .validate("target admission ingress KEM registry root")?;
        if self.ingress_kem_registry_root.is_zero()
            || self.assigned_cluster_validator_count == 0
            || self.assigned_cluster_total_voting_weight == 0
        {
            return Err("target admission context has an empty authority field".to_string());
        }
        Ok(())
    }

    pub fn validate_against(
        &self,
        validator_set: &ValidatorSet,
        cluster_map: &ClusterMap,
        protocol_config: &ProtocolConfig,
    ) -> Result<(), String> {
        self.validate_validator_and_cluster_bindings(validator_set, cluster_map)?;
        if self.consensus_parameter_root != protocol_config.hash()? {
            return Err("target admission parameter root mismatch".to_string());
        }
        Ok(())
    }

    /// Validate the immutable topology and the exact finalized parameter root
    /// without importing a consensus scheduler's runtime configuration.
    pub fn validate_against_parameter_root(
        &self,
        validator_set: &ValidatorSet,
        cluster_map: &ClusterMap,
        consensus_parameter_root: ConsensusParameterRoot,
    ) -> Result<(), String> {
        self.validate_validator_and_cluster_bindings(validator_set, cluster_map)?;
        if self.consensus_parameter_root != consensus_parameter_root {
            return Err("target admission parameter root mismatch".to_string());
        }
        Ok(())
    }

    pub fn validate_validator_and_cluster_bindings(
        &self,
        validator_set: &ValidatorSet,
        cluster_map: &ClusterMap,
    ) -> Result<(), String> {
        self.validate()?;
        if validator_set.epoch != self.epoch || cluster_map.epoch != self.epoch {
            return Err("target admission topology epoch mismatch".to_string());
        }
        let active_set = validator_set.active_for_epoch(self.epoch);
        active_set.validate_unique_validator_and_key_ids()?;
        let expected_map = ClusterMap::derive_from_finalized_epoch_seed(
            &active_set,
            self.finalized_epoch_seed_root,
        )?;
        if cluster_map.canonicalized() != expected_map {
            return Err("target admission cluster map is not deterministic".to_string());
        }
        cluster_map.validate_complete_balanced_assignment(&active_set)?;
        let members = active_set.active_for_cluster(self.assigned_cluster_id);
        let member_ids = members
            .iter()
            .map(|validator| validator.validator_id.clone())
            .collect::<Vec<_>>();
        let membership_root = Hash::from_domain_bytes(
            "SYNERGY_ASSIGNED_CLUSTER_MEMBERSHIP_V1",
            &(self.epoch, self.assigned_cluster_id, member_ids).canonical_bytes()?,
        );
        let total_weight = members.iter().try_fold(0u64, |total, validator| {
            total
                .checked_add(validator.voting_weight)
                .ok_or_else(|| "target admission voting-weight total overflow".to_string())
        })?;
        if self.active_validator_set_root != active_set.hash()?
            || self.validator_consensus_key_root != active_set.consensus_key_root()?
            || self.frozen_bonded_weight_root != active_set.frozen_bonded_weight_root()?
            || self.cluster_map_root != cluster_map.hash()?
            || self.assigned_cluster_membership_root != membership_root
            || self.assigned_cluster_validator_count != members.len() as u64
            || self.assigned_cluster_total_voting_weight != total_weight
        {
            return Err("target admission frozen topology root mismatch".to_string());
        }
        Ok(())
    }

    pub fn validate_height_context_compatibility(
        &self,
        height_context: &HeightConsensusContext,
    ) -> Result<(), String> {
        self.validate()?;
        height_context.validate()?;
        if self.chain_id != height_context.chain_id
            || self.network_id != height_context.network_id
            || self.protocol_version != height_context.protocol_version
            || self.epoch != height_context.epoch
            || self.target_height != height_context.height
            || self.active_validator_set_root != height_context.active_validator_set_root
            || self.validator_consensus_key_root != height_context.validator_consensus_key_root
            || self.frozen_bonded_weight_root != height_context.frozen_bonded_weight_root
            || self.cluster_schedule_version != height_context.cluster_schedule_version
            || self.finalized_epoch_seed_root != height_context.finalized_epoch_seed_root
            || self.assigned_height_schedule_root != height_context.assigned_height_schedule_root
            || self.cluster_map_root != height_context.cluster_map_root
            || self.assigned_cluster_id != height_context.assigned_cluster_id
            || self.assigned_cluster_membership_root
                != height_context.assigned_cluster_membership_root
            || self.assigned_cluster_validator_count
                != height_context.assigned_cluster_validator_count
            || self.assigned_cluster_total_voting_weight
                != height_context.assigned_cluster_total_voting_weight
            || self.consensus_parameter_root != height_context.consensus_parameter_root
            || self.cryptographic_profile_root != height_context.cryptographic_profile_root
        {
            return Err(
                "target admission context does not match finalized height context".to_string(),
            );
        }
        Ok(())
    }
}

fn validate_target_admission_spec(spec: &TargetAdmissionContextSpec) -> Result<(), String> {
    if spec.protocol_version != POSY_SIMPLIFIED_PROTOCOL_VERSION
        || spec.cluster_schedule_version != TESTNET_V3_CLUSTER_SCHEDULE_VERSION
    {
        return Err("unsupported target admission context specification".to_string());
    }
    let minimum_target = spec
        .source_finalized_height
        .0
        .checked_add(3)
        .ok_or_else(|| "target admission look-ahead overflow".to_string())?;
    if spec.target_height.0 < minimum_target {
        return Err("target admission height must be at least finalized H+3".to_string());
    }
    for (name, root) in [
        (
            "source_finality_context_root",
            spec.source_finality_context_root,
        ),
        ("finalized_epoch_seed_root", spec.finalized_epoch_seed_root),
        (
            "assigned_height_schedule_root",
            spec.assigned_height_schedule_root,
        ),
        (
            "cryptographic_profile_root",
            spec.cryptographic_profile_root,
        ),
    ] {
        if root.is_zero() {
            return Err(format!("target admission specification {name} is missing"));
        }
    }
    spec.ingress_kem_registry_root
        .validate("target admission ingress KEM registry root")?;
    if spec.ingress_kem_registry_root.is_zero() {
        return Err("target admission ingress KEM registry root is zero".to_string());
    }
    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InnerTransactionV2 {
    pub target_height: Height,
    pub lane_id: String,
    pub transaction: Transaction,
}

impl InnerTransactionV2 {
    pub fn validate(&self) -> Result<(), String> {
        if self.target_height.0 == 0 {
            return Err("inner transaction target height must be positive".to_string());
        }
        if self.lane_id != ETDAG_LANE_ID {
            return Err("wrong ETDAG lane".to_string());
        }
        self.transaction.chain_id.require_testnet_v3()?;
        self.transaction
            .network_id
            .require_fresh_posy_testnet_v3()?;
        if self.transaction.epoch.0 == u64::MAX {
            return Err("inner transaction epoch is invalid".to_string());
        }
        if self.transaction.sender_uma_or_account.trim().is_empty() {
            return Err("inner transaction sender is empty".to_string());
        }
        if !self.transaction.aegis_pq_signature.is_present() {
            return Err("inner transaction signature is missing".to_string());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IngressKemPublicKey {
    pub validator_id: ValidatorId,
    pub share_index: u8,
    pub key_bytes: Vec<u8>,
}

impl IngressKemPublicKey {
    pub fn validate(&self) -> Result<(), String> {
        if self.validator_id.0.trim().is_empty() || self.share_index == 0 {
            return Err("invalid ingress KEM recipient".to_string());
        }
        mlkem1024::PublicKey::from_bytes(&self.key_bytes)
            .map_err(|_| "invalid ML-KEM-1024 public key".to_string())?;
        Ok(())
    }
}

/// Public-only ML-KEM material supplied by the separate identity workstream.
///
/// No secret key, node address, wallet address, or identity-generation helper
/// is present in this schema.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IngressKemKeyRecord {
    pub validator_id: ValidatorId,
    pub ingress_key_id: String,
    pub share_index: u8,
    pub key_bytes: Vec<u8>,
}

impl IngressKemKeyRecord {
    pub fn as_recipient(&self) -> IngressKemPublicKey {
        IngressKemPublicKey {
            validator_id: self.validator_id.clone(),
            share_index: self.share_index,
            key_bytes: self.key_bytes.clone(),
        }
    }

    fn validate(&self) -> Result<(), String> {
        if self.ingress_key_id.trim().is_empty() {
            return Err("ingress KEM key ID is empty".to_string());
        }
        self.as_recipient().validate()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IngressKemKeyRegistry {
    pub registry_version: u32,
    pub chain_id: ChainId,
    pub network_id: NetworkId,
    pub protocol_version: String,
    pub epoch: Epoch,
    pub target_height: Height,
    pub assigned_cluster_id: ClusterId,
    pub records: Vec<IngressKemKeyRecord>,
}

impl IngressKemKeyRegistry {
    pub fn canonical_records(&self) -> Vec<IngressKemKeyRecord> {
        let mut records = self.records.clone();
        records.sort_by(|left, right| {
            left.validator_id
                .cmp(&right.validator_id)
                .then_with(|| left.share_index.cmp(&right.share_index))
                .then_with(|| left.ingress_key_id.cmp(&right.ingress_key_id))
        });
        records
    }

    pub fn root(&self) -> Result<EtdagDigest, String> {
        self.validate_shape()?;
        EtdagDigest::from_canonical(
            "PoSy/ETDAG/IngressKemKeyRegistry/v3",
            &(
                self.registry_version,
                self.chain_id,
                self.network_id.clone(),
                self.protocol_version.clone(),
                self.epoch,
                self.target_height,
                self.assigned_cluster_id,
                self.canonical_records(),
            ),
        )
    }

    pub fn validate_shape(&self) -> Result<(), String> {
        self.chain_id.require_testnet_v3()?;
        self.network_id.require_fresh_posy_testnet_v3()?;
        if self.registry_version != INGRESS_KEM_REGISTRY_VERSION
            || self.protocol_version != POSY_SIMPLIFIED_PROTOCOL_VERSION
            || self.target_height.0 == 0
            || self.records.is_empty()
        {
            return Err("unsupported or empty ingress KEM registry".to_string());
        }
        let mut validator_ids = BTreeSet::new();
        let mut key_ids = BTreeSet::new();
        let mut share_indices = BTreeSet::new();
        for record in &self.records {
            record.validate()?;
            if !validator_ids.insert(record.validator_id.clone())
                || !key_ids.insert(record.ingress_key_id.clone())
                || !share_indices.insert(record.share_index)
            {
                return Err("ingress KEM registry contains a duplicate authority".to_string());
            }
        }
        if self.records != self.canonical_records() {
            return Err("ingress KEM registry records are not canonically ordered".to_string());
        }
        Ok(())
    }

    pub fn validate_against(
        &self,
        context: &TargetAdmissionContext,
        validator_set: &ValidatorSet,
    ) -> Result<(), String> {
        self.validate_shape()?;
        context.validate()?;
        if self.chain_id != context.chain_id
            || self.network_id != context.network_id
            || self.protocol_version != context.protocol_version
            || self.epoch != context.epoch
            || self.target_height != context.target_height
            || self.assigned_cluster_id != context.assigned_cluster_id
            || self.root()? != context.ingress_kem_registry_root
        {
            return Err("ingress KEM registry target context mismatch".to_string());
        }
        let expected_members = validator_set
            .active_for_epoch(context.epoch)
            .active_for_cluster(context.assigned_cluster_id)
            .into_iter()
            .map(|validator| validator.validator_id)
            .collect::<BTreeSet<_>>();
        let registry_members = self
            .records
            .iter()
            .map(|record| record.validator_id.clone())
            .collect::<BTreeSet<_>>();
        if registry_members != expected_members
            || self.records.len() as u64 != context.assigned_cluster_validator_count
        {
            return Err(
                "ingress KEM registry does not contain exactly the assigned cluster".to_string(),
            );
        }
        Ok(())
    }

    pub fn recipients(&self) -> Vec<IngressKemPublicKey> {
        self.records
            .iter()
            .map(IngressKemKeyRecord::as_recipient)
            .collect()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ShareCommitment {
    pub validator_id: ValidatorId,
    pub share_index: u8,
    pub share_commitment: EtdagDigest,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ShareCapsule {
    pub validator_id: ValidatorId,
    pub share_index: u8,
    pub share_commitment: EtdagDigest,
    pub kem_ciphertext: Vec<u8>,
    pub aead_nonce: Vec<u8>,
    pub encrypted_share: Vec<u8>,
}

impl ShareCapsule {
    pub fn digest(&self) -> Result<EtdagDigest, String> {
        EtdagDigest::from_canonical("PoSy/ETDAG/ShareCapsule/v3", self)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ShamirShare {
    pub index: u8,
    pub value: Vec<u8>,
}

impl ShamirShare {
    fn validate(&self) -> Result<(), String> {
        if self.index == 0 || self.value.len() != 32 {
            return Err("invalid Shamir share".to_string());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EncryptedTransactionEnvelope {
    pub envelope_version: u32,
    pub profile_id: String,
    pub chain_id: ChainId,
    pub network_id: NetworkId,
    pub protocol_version: String,
    pub epoch: Epoch,
    pub target_height: Height,
    pub target_context_root: Hash,
    pub assigned_cluster_id: ClusterId,
    pub lane_id: String,
    pub sender_id: String,
    pub nonce_slot: u64,
    pub gas_class: u32,
    pub fee_class: u32,
    pub admission_bond_nwei: u128,
    pub expiry_height: Height,
    pub ciphertext_size_class: u64,
    pub aead_nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
    pub key_commitment: EtdagDigest,
    pub share_commitment_root: EtdagDigest,
    pub share_capsule_root: EtdagDigest,
    pub cryptographic_profile_root: Hash,
    pub tx_commitment: EtdagDigest,
    pub outer_key_id: AegisPqKeyId,
    pub outer_signature: AegisPqSignature,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct UnsignedEnvelope {
    envelope_version: u32,
    profile_id: String,
    chain_id: ChainId,
    network_id: NetworkId,
    protocol_version: String,
    epoch: Epoch,
    target_height: Height,
    target_context_root: Hash,
    assigned_cluster_id: ClusterId,
    lane_id: String,
    sender_id: String,
    nonce_slot: u64,
    gas_class: u32,
    fee_class: u32,
    admission_bond_nwei: u128,
    expiry_height: Height,
    ciphertext_size_class: u64,
    aead_nonce: Vec<u8>,
    ciphertext: Vec<u8>,
    key_commitment: EtdagDigest,
    share_commitment_root: EtdagDigest,
    share_capsule_root: EtdagDigest,
    cryptographic_profile_root: Hash,
    outer_key_id: AegisPqKeyId,
}

impl EncryptedTransactionEnvelope {
    fn unsigned(&self) -> UnsignedEnvelope {
        UnsignedEnvelope {
            envelope_version: self.envelope_version,
            profile_id: self.profile_id.clone(),
            chain_id: self.chain_id,
            network_id: self.network_id.clone(),
            protocol_version: self.protocol_version.clone(),
            epoch: self.epoch,
            target_height: self.target_height,
            target_context_root: self.target_context_root,
            assigned_cluster_id: self.assigned_cluster_id,
            lane_id: self.lane_id.clone(),
            sender_id: self.sender_id.clone(),
            nonce_slot: self.nonce_slot,
            gas_class: self.gas_class,
            fee_class: self.fee_class,
            admission_bond_nwei: self.admission_bond_nwei,
            expiry_height: self.expiry_height,
            ciphertext_size_class: self.ciphertext_size_class,
            aead_nonce: self.aead_nonce.clone(),
            ciphertext: self.ciphertext.clone(),
            key_commitment: self.key_commitment.clone(),
            share_commitment_root: self.share_commitment_root.clone(),
            share_capsule_root: self.share_capsule_root.clone(),
            cryptographic_profile_root: self.cryptographic_profile_root,
            outer_key_id: self.outer_key_id.clone(),
        }
    }

    pub fn signing_bytes(&self) -> Result<Vec<u8>, String> {
        self.unsigned().canonical_bytes()
    }

    pub fn recompute_commitment(&self) -> Result<EtdagDigest, String> {
        EtdagDigest::from_canonical("PoSy/ETDAG/TxCommitment/v3", &self.unsigned())
    }

    pub fn validate_structure(
        &self,
        height_context: &TargetAdmissionContext,
        parameters: &EtdagParameters,
    ) -> Result<(), String> {
        parameters.validate()?;
        height_context.validate()?;
        self.chain_id.require_testnet_v3()?;
        self.network_id.require_fresh_posy_testnet_v3()?;
        if self.envelope_version != 2
            || self.profile_id != ETDAG_PROFILE_ID
            || self.protocol_version != POSY_SIMPLIFIED_PROTOCOL_VERSION
            || self.lane_id != ETDAG_LANE_ID
        {
            return Err("unsupported ETDAG envelope version/profile".to_string());
        }
        if self.epoch != height_context.epoch
            || self.target_height != height_context.target_height
            || self.target_context_root != height_context.root()?
            || self.assigned_cluster_id != height_context.assigned_cluster_id
            || self.cryptographic_profile_root != height_context.cryptographic_profile_root
        {
            return Err("ETDAG envelope target-height context mismatch".to_string());
        }
        if self.expiry_height != self.target_height {
            return Err("ETDAG expiry must equal target height".to_string());
        }
        if self.sender_id.trim().is_empty()
            || self.aead_nonce.len() != 12
            || self.outer_key_id.0.trim().is_empty()
            || !self.outer_signature.is_present()
        {
            return Err("ETDAG envelope is missing required admission data".to_string());
        }
        if !parameters
            .ciphertext_size_classes
            .contains(&self.ciphertext_size_class)
            || self.ciphertext.len() > self.ciphertext_size_class as usize
            || self.ciphertext.len() < 16
        {
            return Err("ETDAG ciphertext size class mismatch".to_string());
        }
        for (name, digest) in [
            ("key commitment", &self.key_commitment),
            ("share commitment root", &self.share_commitment_root),
            ("share capsule root", &self.share_capsule_root),
            ("transaction commitment", &self.tx_commitment),
        ] {
            digest.validate(name)?;
        }
        if self.recompute_commitment()? != self.tx_commitment {
            return Err("ETDAG transaction commitment mismatch".to_string());
        }
        Ok(())
    }

    pub fn verify_outer_signature(&self, verifier: &AegisPqvmVerifier) -> Result<(), String> {
        verifier
            .verify_domain_signature(
                DOMAIN_ETE_OUTER,
                &self.signing_bytes()?,
                &self.sender_id,
                &self.outer_key_id,
                self.epoch,
                AegisPqKeyRole::Transaction,
                &self.outer_signature,
            )
            .map_err(|error| error.to_string())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SealedTransactionBundle {
    pub envelope: EncryptedTransactionEnvelope,
    pub share_commitments: Vec<ShareCommitment>,
    pub share_capsules: Vec<ShareCapsule>,
}

impl SealedTransactionBundle {
    pub fn validate_roots(&self) -> Result<(), String> {
        let mut commitments = self.share_commitments.clone();
        commitments.sort_by(|left, right| left.validator_id.cmp(&right.validator_id));
        let mut capsules = self.share_capsules.clone();
        capsules.sort_by(|left, right| left.validator_id.cmp(&right.validator_id));
        if commitments.len() != capsules.len() || commitments.is_empty() {
            return Err("ETDAG share commitment/capsule set mismatch".to_string());
        }
        let ids = commitments
            .iter()
            .map(|value| (&value.validator_id, value.share_index))
            .collect::<BTreeSet<_>>();
        if ids.len() != commitments.len() {
            return Err("ETDAG share set contains duplicate recipients".to_string());
        }
        for (commitment, capsule) in commitments.iter().zip(capsules.iter()) {
            if commitment.validator_id != capsule.validator_id
                || commitment.share_index != capsule.share_index
                || commitment.share_commitment != capsule.share_commitment
            {
                return Err("ETDAG share commitment does not match capsule".to_string());
            }
        }
        let commitment_root =
            EtdagDigest::from_canonical("PoSy/ETDAG/ShareCommitmentRoot/v3", &commitments)?;
        let capsule_root =
            EtdagDigest::from_canonical("PoSy/ETDAG/ShareCapsuleRoot/v3", &capsules)?;
        if commitment_root != self.envelope.share_commitment_root
            || capsule_root != self.envelope.share_capsule_root
        {
            return Err("ETDAG share roots do not match envelope".to_string());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EtdagSubmissionEnvelope {
    pub sealed_bundle: SealedTransactionBundle,
    pub outer_public_key: AegisPqPublicKey,
    pub outer_key_lifecycle: AegisPqKeyLifecycleRecord,
}

impl EtdagSubmissionEnvelope {
    pub fn verify(
        &self,
        context: &TargetAdmissionContext,
        parameters: &EtdagParameters,
    ) -> Result<(), String> {
        let envelope = &self.sealed_bundle.envelope;
        envelope.validate_structure(context, parameters)?;
        self.sealed_bundle.validate_roots()?;
        if self.outer_public_key.key_id != envelope.outer_key_id
            || self.outer_key_lifecycle.key_id != envelope.outer_key_id
            || self.outer_key_lifecycle.uma_id != envelope.sender_id
            || !self
                .outer_key_lifecycle
                .roles
                .contains(&AegisPqKeyRole::Transaction)
            || self.outer_key_lifecycle.active_from_epoch.0 > envelope.epoch.0
            || self
                .outer_key_lifecycle
                .active_until_epoch
                .is_some_and(|until| envelope.epoch.0 > until.0)
            || self
                .outer_key_lifecycle
                .revoked_from_epoch
                .is_some_and(|revoked| envelope.epoch.0 >= revoked.0)
        {
            return Err("ETDAG outer key lifecycle does not authorize sender".to_string());
        }
        let verifier = AegisPqvmVerifier::initialize_required_for_public_key(
            self.outer_public_key.clone(),
            self.outer_key_lifecycle.clone(),
        )
        .map_err(|error| error.to_string())?;
        envelope.verify_outer_signature(&verifier)
    }
}

#[derive(Debug, Clone)]
pub struct SealRequest<'a> {
    pub inner: InnerTransactionV2,
    pub target_context: &'a TargetAdmissionContext,
    pub parameters: &'a EtdagParameters,
    pub recipients: &'a [IngressKemPublicKey],
    pub gas_class: u32,
    pub fee_class: u32,
    pub admission_bond_nwei: u128,
    pub outer_key_id: AegisPqKeyId,
}

pub fn seal_transaction<R: RngCore + CryptoRng>(
    signer: &mut AegisPqvmSigner,
    request: SealRequest<'_>,
    rng: &mut R,
) -> Result<SealedTransactionBundle, String> {
    request.inner.validate()?;
    request.parameters.validate()?;
    request.target_context.validate()?;
    if request.inner.target_height != request.target_context.target_height
        || request.inner.transaction.epoch != request.target_context.epoch
    {
        return Err("inner transaction target context mismatch".to_string());
    }
    let expected_count = usize::try_from(request.target_context.assigned_cluster_validator_count)
        .map_err(|_| "cluster count exceeds usize".to_string())?;
    if request.recipients.len() != expected_count {
        return Err("share recipients do not equal assigned cluster size".to_string());
    }
    let mut recipients = request.recipients.to_vec();
    recipients.sort_by(|left, right| left.validator_id.cmp(&right.validator_id));
    let unique_ids = recipients
        .iter()
        .map(|recipient| recipient.validator_id.clone())
        .collect::<BTreeSet<_>>();
    let unique_indices = recipients
        .iter()
        .map(|recipient| recipient.share_index)
        .collect::<BTreeSet<_>>();
    if unique_ids.len() != recipients.len() || unique_indices.len() != recipients.len() {
        return Err("duplicate ETDAG recipient or share index".to_string());
    }
    for recipient in &recipients {
        recipient.validate()?;
    }

    let threshold = decryption_threshold(recipients.len())?;
    let mut transaction_key = [0u8; 32];
    rng.fill_bytes(&mut transaction_key);
    let shares = split_secret(&transaction_key, &recipients, threshold, rng)?;
    let inner_bytes = request.inner.canonical_bytes()?;
    let aad = envelope_aad(
        request.target_context,
        &request.inner.transaction.sender_uma_or_account,
        request.inner.transaction.account_nonce_or_sequence,
    )?;
    let mut aead_nonce = [0u8; 12];
    rng.fill_bytes(&mut aead_nonce);
    let cipher = Aes256Gcm::new_from_slice(&transaction_key)
        .map_err(|error| format!("initialize ETDAG AES-256-GCM: {error}"))?;
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&aead_nonce),
            Payload {
                msg: &inner_bytes,
                aad: &aad,
            },
        )
        .map_err(|_| "encrypt ETDAG inner transaction".to_string())?;
    let ciphertext_size_class = ciphertext_size_class(ciphertext.len())? as u64;
    let key_commitment = key_commitment(&transaction_key, &aad);

    let mut share_commitments = Vec::with_capacity(recipients.len());
    let mut share_capsules = Vec::with_capacity(recipients.len());
    for (recipient, share) in recipients.iter().zip(shares.iter()) {
        let share_commitment = share_commitment(
            &recipient.validator_id,
            share,
            request.target_context.root()?,
            request.inner.target_height,
        )?;
        share_commitments.push(ShareCommitment {
            validator_id: recipient.validator_id.clone(),
            share_index: share.index,
            share_commitment: share_commitment.clone(),
        });
        share_capsules.push(encrypt_share_capsule(
            recipient,
            share,
            share_commitment,
            &aad,
            rng,
        )?);
    }
    share_commitments.sort_by(|left, right| left.validator_id.cmp(&right.validator_id));
    share_capsules.sort_by(|left, right| left.validator_id.cmp(&right.validator_id));
    let share_commitment_root =
        EtdagDigest::from_canonical("PoSy/ETDAG/ShareCommitmentRoot/v3", &share_commitments)?;
    let share_capsule_root =
        EtdagDigest::from_canonical("PoSy/ETDAG/ShareCapsuleRoot/v3", &share_capsules)?;

    let mut envelope = EncryptedTransactionEnvelope {
        envelope_version: 2,
        profile_id: ETDAG_PROFILE_ID.to_string(),
        chain_id: request.target_context.chain_id,
        network_id: request.target_context.network_id.clone(),
        protocol_version: request.target_context.protocol_version.clone(),
        epoch: request.target_context.epoch,
        target_height: request.inner.target_height,
        target_context_root: request.target_context.root()?,
        assigned_cluster_id: request.target_context.assigned_cluster_id,
        lane_id: ETDAG_LANE_ID.to_string(),
        sender_id: request.inner.transaction.sender_uma_or_account.clone(),
        nonce_slot: request.inner.transaction.account_nonce_or_sequence,
        gas_class: request.gas_class,
        fee_class: request.fee_class,
        admission_bond_nwei: request.admission_bond_nwei,
        expiry_height: request.inner.target_height,
        ciphertext_size_class,
        aead_nonce: aead_nonce.to_vec(),
        ciphertext,
        key_commitment,
        share_commitment_root,
        share_capsule_root,
        cryptographic_profile_root: request.target_context.cryptographic_profile_root,
        tx_commitment: EtdagDigest::zero(),
        outer_key_id: request.outer_key_id,
        outer_signature: AegisPqSignature {
            algorithm: String::new(),
            signature_bytes: Vec::new(),
        },
    };
    envelope.tx_commitment = envelope.recompute_commitment()?;
    envelope.outer_signature = signer
        .sign_domain(
            DOMAIN_ETE_OUTER,
            &envelope.signing_bytes()?,
            &envelope.outer_key_id,
        )
        .map_err(|error| error.to_string())?;
    transaction_key.fill(0);

    let bundle = SealedTransactionBundle {
        envelope,
        share_commitments,
        share_capsules,
    };
    bundle.validate_roots()?;
    Ok(bundle)
}

fn envelope_aad(
    context: &TargetAdmissionContext,
    sender: &str,
    nonce: u64,
) -> Result<Vec<u8>, String> {
    serde_json::to_vec(&(
        ETDAG_PROFILE_ID,
        context.chain_id,
        context.network_id.clone(),
        context.protocol_version.clone(),
        context.epoch,
        context.target_height,
        context.root()?,
        context.assigned_cluster_id,
        ETDAG_LANE_ID,
        sender,
        nonce,
    ))
    .map_err(|error| format!("serialize ETDAG envelope AAD: {error}"))
}

fn key_commitment(key: &[u8; 32], aad: &[u8]) -> EtdagDigest {
    let mut bytes = Vec::with_capacity(32 + aad.len());
    bytes.extend_from_slice(key);
    bytes.extend_from_slice(aad);
    EtdagDigest::from_domain_bytes("PoSy/ETDAG/KeyCommitment/v3", &bytes)
}

fn share_commitment(
    validator_id: &ValidatorId,
    share: &ShamirShare,
    context_root: Hash,
    target_height: Height,
) -> Result<EtdagDigest, String> {
    EtdagDigest::from_canonical(
        "PoSy/ETDAG/ShareCommitment/v3",
        &(
            validator_id.clone(),
            share.clone(),
            context_root,
            target_height,
        ),
    )
}

fn encrypt_share_capsule<R: RngCore + CryptoRng>(
    recipient: &IngressKemPublicKey,
    share: &ShamirShare,
    share_commitment: EtdagDigest,
    outer_aad: &[u8],
    rng: &mut R,
) -> Result<ShareCapsule, String> {
    let public_key = mlkem1024::PublicKey::from_bytes(&recipient.key_bytes)
        .map_err(|_| "invalid ML-KEM-1024 public key".to_string())?;
    let (shared_secret, kem_ciphertext) = mlkem1024::encapsulate(&public_key);
    let mut capsule_context = Vec::new();
    capsule_context.extend_from_slice(outer_aad);
    capsule_context.extend_from_slice(recipient.validator_id.0.as_bytes());
    capsule_context.push(recipient.share_index);
    capsule_context.extend_from_slice(&share_commitment.bytes()?);
    let capsule_key = derive_capsule_key(shared_secret.as_bytes(), &capsule_context);
    let cipher = Aes256Gcm::new_from_slice(&capsule_key)
        .map_err(|error| format!("initialize capsule AES-256-GCM: {error}"))?;
    let mut nonce = [0u8; 12];
    rng.fill_bytes(&mut nonce);
    let plaintext = share.canonical_bytes()?;
    let encrypted_share = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &plaintext,
                aad: &capsule_context,
            },
        )
        .map_err(|_| "encrypt ETDAG share capsule".to_string())?;
    Ok(ShareCapsule {
        validator_id: recipient.validator_id.clone(),
        share_index: recipient.share_index,
        share_commitment,
        kem_ciphertext: kem_ciphertext.as_bytes().to_vec(),
        aead_nonce: nonce.to_vec(),
        encrypted_share,
    })
}

pub fn decrypt_share_capsule(
    envelope: &EncryptedTransactionEnvelope,
    capsule: &ShareCapsule,
    recipient_secret_key: &[u8],
) -> Result<ShamirShare, String> {
    if capsule.aead_nonce.len() != 12 || capsule.share_index == 0 {
        return Err("invalid ETDAG share capsule shape".to_string());
    }
    let secret_key = mlkem1024::SecretKey::from_bytes(recipient_secret_key)
        .map_err(|_| "invalid ML-KEM-1024 secret key".to_string())?;
    let kem_ciphertext = mlkem1024::Ciphertext::from_bytes(&capsule.kem_ciphertext)
        .map_err(|_| "invalid ML-KEM-1024 capsule ciphertext".to_string())?;
    let shared_secret = mlkem1024::decapsulate(&kem_ciphertext, &secret_key);
    let outer_aad = serde_json::to_vec(&(
        ETDAG_PROFILE_ID,
        envelope.chain_id,
        envelope.network_id.clone(),
        envelope.protocol_version.clone(),
        envelope.epoch,
        envelope.target_height,
        envelope.target_context_root,
        envelope.assigned_cluster_id,
        ETDAG_LANE_ID,
        envelope.sender_id.as_str(),
        envelope.nonce_slot,
    ))
    .map_err(|error| format!("serialize ETDAG capsule AAD: {error}"))?;
    let mut capsule_context = Vec::new();
    capsule_context.extend_from_slice(&outer_aad);
    capsule_context.extend_from_slice(capsule.validator_id.0.as_bytes());
    capsule_context.push(capsule.share_index);
    capsule_context.extend_from_slice(&capsule.share_commitment.bytes()?);
    let capsule_key = derive_capsule_key(shared_secret.as_bytes(), &capsule_context);
    let cipher = Aes256Gcm::new_from_slice(&capsule_key)
        .map_err(|error| format!("initialize capsule AES-256-GCM: {error}"))?;
    let plaintext = cipher
        .decrypt(
            Nonce::from_slice(&capsule.aead_nonce),
            Payload {
                msg: &capsule.encrypted_share,
                aad: &capsule_context,
            },
        )
        .map_err(|_| "ETDAG capsule authentication failed".to_string())?;
    let share = ShamirShare::assert_canonical_bytes(&plaintext)?;
    share.validate()?;
    if share.index != capsule.share_index {
        return Err("ETDAG capsule share index mismatch".to_string());
    }
    let expected = share_commitment(
        &capsule.validator_id,
        &share,
        envelope.target_context_root,
        envelope.target_height,
    )?;
    if expected != capsule.share_commitment {
        return Err("ETDAG capsule share commitment mismatch".to_string());
    }
    Ok(share)
}

fn derive_capsule_key(shared_secret: &[u8], context: &[u8]) -> [u8; 32] {
    let mut hasher = Sha3_512::new();
    hasher.update(b"PoSy/ETDAG/CapsuleKey/v3");
    hasher.update((shared_secret.len() as u64).to_be_bytes());
    hasher.update(shared_secret);
    hasher.update((context.len() as u64).to_be_bytes());
    hasher.update(context);
    let digest = hasher.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&digest[..32]);
    key
}

pub fn certificate_quorum(cluster_size: usize) -> Result<usize, String> {
    if cluster_size == 0 {
        return Err("cluster size must be positive".to_string());
    }
    cluster_size
        .checked_mul(2)
        .and_then(|value| value.checked_div(3))
        .and_then(|value| value.checked_add(1))
        .ok_or_else(|| "cluster quorum overflow".to_string())
}

pub fn decryption_threshold(cluster_size: usize) -> Result<usize, String> {
    let quorum = certificate_quorum(cluster_size)?;
    cluster_size
        .checked_sub(quorum)
        .and_then(|faults| faults.checked_add(1))
        .ok_or_else(|| "decryption threshold overflow".to_string())
}

fn ciphertext_size_class(length: usize) -> Result<usize, String> {
    CIPHERTEXT_SIZE_CLASSES
        .iter()
        .copied()
        .find(|class| length <= *class)
        .ok_or_else(|| "ETDAG ciphertext exceeds 128 KiB class".to_string())
}

fn split_secret<R: RngCore + CryptoRng>(
    secret: &[u8; 32],
    recipients: &[IngressKemPublicKey],
    threshold: usize,
    rng: &mut R,
) -> Result<Vec<ShamirShare>, String> {
    if threshold == 0 || threshold > recipients.len() || recipients.len() > 255 {
        return Err("invalid Shamir threshold".to_string());
    }
    let mut shares = recipients
        .iter()
        .map(|recipient| ShamirShare {
            index: recipient.share_index,
            value: vec![0u8; 32],
        })
        .collect::<Vec<_>>();
    for (byte_index, secret_byte) in secret.iter().enumerate() {
        let mut coefficients = vec![0u8; threshold];
        coefficients[0] = *secret_byte;
        rng.fill_bytes(&mut coefficients[1..]);
        for share in &mut shares {
            let mut value = 0u8;
            for coefficient in coefficients.iter().rev() {
                value = gf_mul(value, share.index) ^ coefficient;
            }
            share.value[byte_index] = value;
        }
        coefficients.fill(0);
    }
    Ok(shares)
}

pub fn reconstruct_secret(shares: &[ShamirShare], threshold: usize) -> Result<[u8; 32], String> {
    if threshold == 0 || shares.len() < threshold {
        return Err("insufficient ETDAG decryption shares".to_string());
    }
    let selected = &shares[..threshold];
    let mut seen = BTreeSet::new();
    for share in selected {
        share.validate()?;
        if !seen.insert(share.index) {
            return Err("duplicate ETDAG decryption share index".to_string());
        }
    }
    let mut secret = [0u8; 32];
    for byte_index in 0..32 {
        let mut value = 0u8;
        for (i, share_i) in selected.iter().enumerate() {
            let mut numerator = 1u8;
            let mut denominator = 1u8;
            for (j, share_j) in selected.iter().enumerate() {
                if i == j {
                    continue;
                }
                numerator = gf_mul(numerator, share_j.index);
                denominator = gf_mul(denominator, share_j.index ^ share_i.index);
            }
            if denominator == 0 {
                return Err("invalid ETDAG Shamir denominator".to_string());
            }
            let basis = gf_mul(numerator, gf_inv(denominator)?);
            value ^= gf_mul(share_i.value[byte_index], basis);
        }
        secret[byte_index] = value;
    }
    Ok(secret)
}

fn gf_mul(mut left: u8, mut right: u8) -> u8 {
    let mut result = 0u8;
    for _ in 0..8 {
        if right & 1 != 0 {
            result ^= left;
        }
        let carry = left & 0x80;
        left <<= 1;
        if carry != 0 {
            left ^= 0x1b;
        }
        right >>= 1;
    }
    result
}

fn gf_inv(value: u8) -> Result<u8, String> {
    if value == 0 {
        return Err("zero has no GF(2^8) inverse".to_string());
    }
    let mut result = 1u8;
    let mut base = value;
    let mut exponent = 254u16;
    while exponent > 0 {
        if exponent & 1 == 1 {
            result = gf_mul(result, base);
        }
        base = gf_mul(base, base);
        exponent >>= 1;
    }
    Ok(result)
}

pub fn decrypt_inner_transaction(
    envelope: &EncryptedTransactionEnvelope,
    shares: &[ShamirShare],
    expected_threshold: usize,
) -> Result<InnerTransactionV2, String> {
    let mut key = reconstruct_secret(shares, expected_threshold)?;
    let aad = serde_json::to_vec(&(
        ETDAG_PROFILE_ID,
        envelope.chain_id,
        envelope.network_id.clone(),
        envelope.protocol_version.clone(),
        envelope.epoch,
        envelope.target_height,
        envelope.target_context_root,
        envelope.assigned_cluster_id,
        ETDAG_LANE_ID,
        envelope.sender_id.as_str(),
        envelope.nonce_slot,
    ))
    .map_err(|error| format!("serialize ETDAG payload AAD: {error}"))?;
    if key_commitment(&key, &aad) != envelope.key_commitment {
        key.fill(0);
        return Err("ETDAG reconstructed key commitment mismatch".to_string());
    }
    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|error| format!("initialize ETDAG AES-256-GCM: {error}"))?;
    let plaintext = cipher
        .decrypt(
            Nonce::from_slice(&envelope.aead_nonce),
            Payload {
                msg: &envelope.ciphertext,
                aad: &aad,
            },
        )
        .map_err(|_| "ETDAG payload authentication failed".to_string())?;
    key.fill(0);
    let inner = InnerTransactionV2::assert_canonical_bytes(&plaintext)?;
    inner.validate()?;
    if inner.target_height != envelope.target_height
        || inner.lane_id != envelope.lane_id
        || inner.transaction.chain_id != envelope.chain_id
        || inner.transaction.network_id != envelope.network_id
        || inner.transaction.epoch != envelope.epoch
        || inner.transaction.sender_uma_or_account != envelope.sender_id
        || inner.transaction.account_nonce_or_sequence != envelope.nonce_slot
    {
        return Err("ETDAG outer/inner transaction mismatch".to_string());
    }
    Ok(inner)
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EtdagPhase {
    Vac,
    Dcc,
    BatchValidate,
    BatchFinality,
    BatchTimeout,
    DecryptShare,
}

impl EtdagPhase {
    fn signature_domain(self) -> &'static str {
        match self {
            Self::Vac => DOMAIN_VAC,
            Self::Dcc => DOMAIN_DCC,
            Self::BatchValidate => DOMAIN_BATCH_VALIDATE,
            Self::BatchFinality => DOMAIN_BATCH_FINALITY,
            Self::BatchTimeout => DOMAIN_BATCH_TIMEOUT,
            Self::DecryptShare => DOMAIN_DECRYPT_SHARE,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EtdagVoteTranscript {
    pub phase: EtdagPhase,
    pub chain_id: ChainId,
    pub network_id: NetworkId,
    pub protocol_version: String,
    pub profile_id: String,
    pub epoch: Epoch,
    pub target_height: Height,
    pub target_context_root: Hash,
    pub assigned_cluster_id: ClusterId,
    pub lane_id: String,
    pub round: Round,
    pub candidate_digest: EtdagDigest,
    pub highest_prepared_bvc_digest: Option<EtdagDigest>,
}

impl EtdagVoteTranscript {
    pub fn validate_against(&self, context: &TargetAdmissionContext) -> Result<(), String> {
        context.validate()?;
        self.chain_id.require_testnet_v3()?;
        self.network_id.require_fresh_posy_testnet_v3()?;
        self.candidate_digest.validate("ETDAG candidate digest")?;
        if self
            .highest_prepared_bvc_digest
            .as_ref()
            .is_some_and(EtdagDigest::is_zero)
        {
            return Err("highest prepared BVC digest cannot be zero".to_string());
        }
        if self.protocol_version != POSY_SIMPLIFIED_PROTOCOL_VERSION
            || self.profile_id != ETDAG_PROFILE_ID
            || self.lane_id != ETDAG_LANE_ID
            || self.chain_id != context.chain_id
            || self.network_id != context.network_id
            || self.epoch != context.epoch
            || self.target_height != context.target_height
            || self.target_context_root != context.root()?
            || self.assigned_cluster_id != context.assigned_cluster_id
        {
            return Err("ETDAG vote transcript target context mismatch".to_string());
        }
        match self.phase {
            EtdagPhase::BatchTimeout => {}
            _ if self.highest_prepared_bvc_digest.is_some() => {
                return Err("highest prepared BVC is only valid in batch timeout".to_string())
            }
            _ => {}
        }
        Ok(())
    }

    pub fn digest(&self) -> Result<EtdagDigest, String> {
        EtdagDigest::from_canonical("PoSy/ETDAG/VoteTranscript/v3", self)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EtdagSignedVote {
    pub signer_validator_id: ValidatorId,
    pub signer_key_id: AegisPqKeyId,
    pub signature: AegisPqSignature,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TargetAdmissionCertificate {
    pub certificate_version: u32,
    pub target_context_root: Hash,
    pub ingress_kem_registry_root: EtdagDigest,
    pub source_finalized_height: Height,
    pub source_finality_context_root: Hash,
    pub signer_count: u64,
    pub signed_weight: u64,
    pub votes: Vec<EtdagSignedVote>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct TargetAdmissionCertificateTranscript {
    domain: String,
    chain_id: ChainId,
    network_id: NetworkId,
    protocol_version: String,
    epoch: Epoch,
    target_height: Height,
    assigned_cluster_id: ClusterId,
    target_context_root: Hash,
    ingress_kem_registry_root: EtdagDigest,
    source_finalized_height: Height,
    source_finality_context_root: Hash,
}

impl TargetAdmissionCertificate {
    pub fn without_votes(context: &TargetAdmissionContext) -> Result<Self, String> {
        context.validate()?;
        Ok(Self {
            certificate_version: 2,
            target_context_root: context.root()?,
            ingress_kem_registry_root: context.ingress_kem_registry_root.clone(),
            source_finalized_height: context.source_finalized_height,
            source_finality_context_root: context.source_finality_context_root,
            signer_count: 0,
            signed_weight: 0,
            votes: Vec::new(),
        })
    }

    /// Returns the canonical pre-signature transcript for this exact target
    /// admission certificate.  Offline custody tooling may request these
    /// bytes, but signature acceptance remains exclusively in [`Self::verify`]
    /// against the finalized runtime context and validator registry.
    pub fn signing_bytes(&self, context: &TargetAdmissionContext) -> Result<Vec<u8>, String> {
        TargetAdmissionCertificateTranscript {
            domain: DOMAIN_TARGET_ADMISSION.to_string(),
            chain_id: context.chain_id,
            network_id: context.network_id.clone(),
            protocol_version: context.protocol_version.clone(),
            epoch: context.epoch,
            target_height: context.target_height,
            assigned_cluster_id: context.assigned_cluster_id,
            target_context_root: self.target_context_root,
            ingress_kem_registry_root: self.ingress_kem_registry_root.clone(),
            source_finalized_height: self.source_finalized_height,
            source_finality_context_root: self.source_finality_context_root,
        }
        .canonical_bytes()
    }

    pub fn verify(
        &self,
        verifier: &AegisPqvmVerifier,
        context: &TargetAdmissionContext,
        validator_set: &ValidatorSet,
        cluster_map: &ClusterMap,
    ) -> Result<(), String> {
        context.validate_validator_and_cluster_bindings(validator_set, cluster_map)?;
        if self.certificate_version != 2
            || self.target_context_root != context.root()?
            || self.ingress_kem_registry_root != context.ingress_kem_registry_root
            || self.source_finalized_height != context.source_finalized_height
            || self.source_finality_context_root != context.source_finality_context_root
            || self.votes.len() as u64 != self.signer_count
        {
            return Err("target admission certificate context mismatch".to_string());
        }
        let members = validator_set
            .active_for_epoch(context.epoch)
            .active_for_cluster(context.assigned_cluster_id);
        let transcript = self.signing_bytes(context)?;
        let mut prior: Option<&ValidatorId> = None;
        let mut seen = BTreeSet::new();
        let mut signed_weight = 0u64;
        for vote in &self.votes {
            if prior.is_some_and(|value| value >= &vote.signer_validator_id)
                || !seen.insert(vote.signer_validator_id.clone())
            {
                return Err(
                    "target admission certificate signers are duplicate or noncanonical"
                        .to_string(),
                );
            }
            prior = Some(&vote.signer_validator_id);
            let member = verify_target_admission_vote_with_transcript(
                vote,
                &transcript,
                verifier,
                context,
                &members,
            )?;
            signed_weight = signed_weight
                .checked_add(member.voting_weight)
                .ok_or_else(|| "target admission signed weight overflow".to_string())?;
        }
        let total_weight = members.iter().try_fold(0u64, |total, member| {
            total
                .checked_add(member.voting_weight)
                .ok_or_else(|| "target admission cluster weight overflow".to_string())
        })?;
        if signed_weight != self.signed_weight
            || u128::from(self.signer_count) * 3
                <= u128::from(context.assigned_cluster_validator_count) * 2
            || u128::from(signed_weight) * 3 <= u128::from(total_weight) * 2
        {
            return Err("target admission certificate strict dual quorum failed".to_string());
        }
        Ok(())
    }
}

fn verify_target_admission_vote_with_transcript<'a>(
    vote: &EtdagSignedVote,
    transcript: &[u8],
    verifier: &AegisPqvmVerifier,
    context: &TargetAdmissionContext,
    members: &'a [ValidatorRecord],
) -> Result<&'a ValidatorRecord, String> {
    let member = members
        .iter()
        .find(|member| member.validator_id == vote.signer_validator_id)
        .ok_or_else(|| {
            "target admission certificate signer is outside assigned cluster".to_string()
        })?;
    if member.consensus_public_key.key_id != vote.signer_key_id {
        return Err("target admission signer key does not match frozen key".to_string());
    }
    verifier
        .verify_domain_signature(
            DOMAIN_TARGET_ADMISSION,
            transcript,
            &member.validator_uma_id.0,
            &vote.signer_key_id,
            context.epoch,
            AegisPqKeyRole::ConsensusVote,
            &vote.signature,
        )
        .map_err(|error| error.to_string())?;
    Ok(member)
}

pub fn verify_target_admission_vote(
    vote: &EtdagSignedVote,
    verifier: &AegisPqvmVerifier,
    context: &TargetAdmissionContext,
    validator_set: &ValidatorSet,
    cluster_map: &ClusterMap,
) -> Result<(), String> {
    context.validate_validator_and_cluster_bindings(validator_set, cluster_map)?;
    let members = validator_set
        .active_for_epoch(context.epoch)
        .active_for_cluster(context.assigned_cluster_id);
    let certificate = TargetAdmissionCertificate::without_votes(context)?;
    verify_target_admission_vote_with_transcript(
        vote,
        &certificate.signing_bytes(context)?,
        verifier,
        context,
        &members,
    )?;
    Ok(())
}

pub fn form_target_admission_certificate(
    context: &TargetAdmissionContext,
    mut votes: Vec<EtdagSignedVote>,
    verifier: &AegisPqvmVerifier,
    validator_set: &ValidatorSet,
    cluster_map: &ClusterMap,
) -> Result<TargetAdmissionCertificate, String> {
    votes.sort_by(|left, right| left.signer_validator_id.cmp(&right.signer_validator_id));
    let members = validator_set
        .active_for_epoch(context.epoch)
        .active_for_cluster(context.assigned_cluster_id);
    let signed_weight = votes.iter().try_fold(0u64, |total, vote| {
        let member = members
            .iter()
            .find(|member| member.validator_id == vote.signer_validator_id)
            .ok_or_else(|| {
                "target admission certificate signer is outside assigned cluster".to_string()
            })?;
        total
            .checked_add(member.voting_weight)
            .ok_or_else(|| "target admission signed weight overflow".to_string())
    })?;
    let mut certificate = TargetAdmissionCertificate::without_votes(context)?;
    certificate.signer_count = u64::try_from(votes.len())
        .map_err(|_| "target admission signer count exceeds u64".to_string())?;
    certificate.signed_weight = signed_weight;
    certificate.votes = votes;
    certificate.verify(verifier, context, validator_set, cluster_map)?;
    Ok(certificate)
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TargetAdmissionPackage {
    pub context: TargetAdmissionContext,
    pub ingress_kem_registry: IngressKemKeyRegistry,
    pub certificate: TargetAdmissionCertificate,
}

impl TargetAdmissionPackage {
    pub fn verify(
        &self,
        verifier: &AegisPqvmVerifier,
        validator_set: &ValidatorSet,
        cluster_map: &ClusterMap,
        protocol_config: &ProtocolConfig,
    ) -> Result<(), String> {
        self.context
            .validate_against(validator_set, cluster_map, protocol_config)?;
        self.ingress_kem_registry
            .validate_against(&self.context, validator_set)?;
        self.certificate
            .verify(verifier, &self.context, validator_set, cluster_map)
    }

    /// Schedule-neutral verification used by simplified consensus. The
    /// finalized manifest root is supplied directly; no legacy runtime
    /// configuration is synthesized to stand in for it.
    pub fn verify_against_parameter_root(
        &self,
        verifier: &AegisPqvmVerifier,
        validator_set: &ValidatorSet,
        cluster_map: &ClusterMap,
        consensus_parameter_root: ConsensusParameterRoot,
    ) -> Result<(), String> {
        self.context.validate_against_parameter_root(
            validator_set,
            cluster_map,
            consensus_parameter_root,
        )?;
        self.ingress_kem_registry
            .validate_against(&self.context, validator_set)?;
        self.certificate
            .verify(verifier, &self.context, validator_set, cluster_map)
    }

    pub fn package_digest(&self) -> Result<EtdagDigest, String> {
        EtdagDigest::from_canonical("PoSy/ETDAG/TargetAdmissionPackage/v3", self)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EtdagCertificate {
    pub certificate_version: u32,
    pub transcript: EtdagVoteTranscript,
    pub signer_count: u64,
    pub signed_weight: u64,
    pub votes: Vec<EtdagSignedVote>,
}

impl EtdagCertificate {
    pub fn digest(&self) -> Result<EtdagDigest, String> {
        EtdagDigest::from_canonical("PoSy/ETDAG/Certificate/v3", self)
    }

    pub fn verify(
        &self,
        verifier: &AegisPqvmVerifier,
        context: &TargetAdmissionContext,
        validator_set: &ValidatorSet,
        cluster_map: &ClusterMap,
    ) -> Result<(), String> {
        if self.certificate_version != 2 {
            return Err("unsupported ETDAG certificate version".to_string());
        }
        self.transcript.validate_against(context)?;
        context.validate_validator_and_cluster_bindings(validator_set, cluster_map)?;
        let members = validator_set
            .active_for_epoch(context.epoch)
            .active_for_cluster(context.assigned_cluster_id);
        if members.len() as u64 != context.assigned_cluster_validator_count {
            return Err("ETDAG certificate cluster size mismatch".to_string());
        }
        let total_weight = members.iter().try_fold(0u64, |sum, member| {
            sum.checked_add(member.voting_weight)
                .ok_or_else(|| "ETDAG cluster weight overflow".to_string())
        })?;
        if total_weight != context.assigned_cluster_total_voting_weight {
            return Err("ETDAG certificate cluster weight mismatch".to_string());
        }
        if self.votes.len() as u64 != self.signer_count {
            return Err("ETDAG certificate signer count mismatch".to_string());
        }
        let mut prior: Option<&ValidatorId> = None;
        let mut seen = BTreeSet::new();
        let mut signed_weight = 0u64;
        let transcript_bytes = self.transcript.canonical_bytes()?;
        for vote in &self.votes {
            if prior.is_some_and(|value| value >= &vote.signer_validator_id) {
                return Err("ETDAG certificate signers are not canonically ordered".to_string());
            }
            prior = Some(&vote.signer_validator_id);
            if !seen.insert(vote.signer_validator_id.clone()) {
                return Err("duplicate ETDAG certificate signer".to_string());
            }
            let member = members
                .iter()
                .find(|member| member.validator_id == vote.signer_validator_id)
                .ok_or_else(|| {
                    "cryptographically valid non-cluster ETDAG signer is ineligible".to_string()
                })?;
            if member.consensus_public_key.key_id != vote.signer_key_id {
                return Err("ETDAG vote signer key does not match frozen key".to_string());
            }
            verifier
                .verify_domain_signature(
                    self.transcript.phase.signature_domain(),
                    &transcript_bytes,
                    &member.validator_uma_id.0,
                    &vote.signer_key_id,
                    context.epoch,
                    AegisPqKeyRole::ConsensusVote,
                    &vote.signature,
                )
                .map_err(|error| error.to_string())?;
            signed_weight = signed_weight
                .checked_add(member.voting_weight)
                .ok_or_else(|| "ETDAG signed weight overflow".to_string())?;
        }
        if signed_weight != self.signed_weight {
            return Err("ETDAG certificate declared weight mismatch".to_string());
        }
        let signer_count = self.signer_count as u128;
        let eligible_count = context.assigned_cluster_validator_count as u128;
        let signed_weight_wide = signed_weight as u128;
        let total_weight_wide = total_weight as u128;
        if signer_count
            .checked_mul(3)
            .is_none_or(|value| value <= eligible_count * 2)
        {
            return Err("ETDAG strict count quorum failed".to_string());
        }
        if signed_weight_wide
            .checked_mul(3)
            .is_none_or(|value| value <= total_weight_wide * 2)
        {
            return Err("ETDAG strict frozen-weight quorum failed".to_string());
        }
        Ok(())
    }
}

pub fn form_etdag_certificate(
    transcript: EtdagVoteTranscript,
    mut votes: Vec<EtdagSignedVote>,
    verifier: &AegisPqvmVerifier,
    context: &TargetAdmissionContext,
    validator_set: &ValidatorSet,
    cluster_map: &ClusterMap,
) -> Result<EtdagCertificate, String> {
    votes.sort_by(|left, right| left.signer_validator_id.cmp(&right.signer_validator_id));
    let members = validator_set
        .active_for_epoch(context.epoch)
        .active_for_cluster(context.assigned_cluster_id);
    let signed_weight = votes.iter().try_fold(0u64, |sum, vote| {
        let weight = members
            .iter()
            .find(|member| member.validator_id == vote.signer_validator_id)
            .ok_or_else(|| "ETDAG vote signer is not in assigned cluster".to_string())?
            .voting_weight;
        sum.checked_add(weight)
            .ok_or_else(|| "ETDAG signed weight overflow".to_string())
    })?;
    let certificate = EtdagCertificate {
        certificate_version: 2,
        transcript,
        signer_count: votes.len() as u64,
        signed_weight,
        votes,
    };
    certificate.verify(verifier, context, validator_set, cluster_map)?;
    Ok(certificate)
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct NonceReservationRecord {
    epoch: Epoch,
    target_height: Height,
    sender_id: String,
    nonce_slot: u64,
    tx_commitment: EtdagDigest,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct AdmissionCloseRecord {
    epoch: Epoch,
    target_height: Height,
    cluster_id: ClusterId,
    validator_id: ValidatorId,
    target_context_root: Hash,
    cutoff_vc_context_root: Hash,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct VoteAuthorizationRecord {
    validator_id: ValidatorId,
    key_id: AegisPqKeyId,
    transcript: EtdagVoteTranscript,
    transcript_digest: EtdagDigest,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct TargetAdmissionAuthorizationRecord {
    validator_id: ValidatorId,
    key_id: AegisPqKeyId,
    epoch: Epoch,
    target_height: Height,
    assigned_cluster_id: ClusterId,
    target_context_root: Hash,
    transcript_digest: EtdagDigest,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct DecryptReleaseRecord {
    epoch: Epoch,
    target_height: Height,
    cluster_id: ClusterId,
    validator_id: ValidatorId,
    batch_candidate_digest: EtdagDigest,
    tx_commitment: EtdagDigest,
    share_digest: EtdagDigest,
    boc_digest: EtdagDigest,
    h_minus_one_vc_root: Hash,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct ProtectedDecryptReleaseRecord {
    epoch: Epoch,
    target_height: Height,
    cluster_id: ClusterId,
    validator_id: ValidatorId,
    authorization_root: EtdagDigest,
    next_commitment_root: EtdagDigest,
    protected_batch_root: EtdagDigest,
    tx_commitment: EtdagDigest,
    share_digest: EtdagDigest,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct EtdagDurableJournal {
    format: String,
    nonce_reservations: Vec<NonceReservationRecord>,
    admission_closes: Vec<AdmissionCloseRecord>,
    vote_authorizations: Vec<VoteAuthorizationRecord>,
    #[serde(default)]
    target_admission_authorizations: Vec<TargetAdmissionAuthorizationRecord>,
    decrypt_releases: Vec<DecryptReleaseRecord>,
    #[serde(default)]
    protected_decrypt_releases: Vec<ProtectedDecryptReleaseRecord>,
}

impl Default for EtdagDurableJournal {
    fn default() -> Self {
        Self {
            format: ETDAG_JOURNAL_FORMAT.to_string(),
            nonce_reservations: Vec::new(),
            admission_closes: Vec::new(),
            vote_authorizations: Vec::new(),
            target_admission_authorizations: Vec::new(),
            decrypt_releases: Vec::new(),
            protected_decrypt_releases: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct EtdagAdmissionStoreEntry {
    package: TargetAdmissionPackage,
    package_digest: EtdagDigest,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct EtdagAdmissionPackageStoreFile {
    format: String,
    packages: BTreeMap<Height, EtdagAdmissionStoreEntry>,
}

impl Default for EtdagAdmissionPackageStoreFile {
    fn default() -> Self {
        Self {
            format: ETDAG_ADMISSION_STORE_FORMAT.to_string(),
            packages: BTreeMap::new(),
        }
    }
}

/// Append-only, certificate-verified H+3 admission-package registry.
///
/// The store exposes no delete or overwrite operation. The final public
/// validator/KEM records are supplied by the separate identity workstream;
/// this API only verifies and persists them.
#[derive(Debug, Clone)]
pub struct EtdagAdmissionPackageStore {
    path: PathBuf,
}

static ETDAG_ADMISSION_STORE_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

impl EtdagAdmissionPackageStore {
    pub fn process_wide() -> Self {
        Self::at_path(crate::utils::resolve_data_path(&format!(
            "data/{ETDAG_ADMISSION_STORE_FILE}"
        )))
    }

    pub fn at_path(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn install_verified(
        &self,
        package: &TargetAdmissionPackage,
        verifier: &AegisPqvmVerifier,
        validator_set: &ValidatorSet,
        cluster_map: &ClusterMap,
        protocol_config: &ProtocolConfig,
    ) -> Result<EtdagDigest, String> {
        package.verify(verifier, validator_set, cluster_map, protocol_config)?;
        self.install_preverified(package)
    }

    fn install_preverified(&self, package: &TargetAdmissionPackage) -> Result<EtdagDigest, String> {
        let package_digest = package.package_digest()?;
        let _guard = ETDAG_ADMISSION_STORE_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .map_err(|_| "ETDAG admission-package store lock poisoned".to_string())?;
        let mut store = self.load_unlocked()?;
        let height = package.context.target_height;
        if let Some(existing) = store.packages.get(&height) {
            if existing.package == *package && existing.package_digest == package_digest {
                return Ok(package_digest);
            }
            return Err("ETDAG_ADMISSION_PACKAGE_CONFLICT".to_string());
        }
        store.packages.insert(
            height,
            EtdagAdmissionStoreEntry {
                package: package.clone(),
                package_digest: package_digest.clone(),
            },
        );
        self.persist_unlocked(&store)?;
        Ok(package_digest)
    }

    pub fn get(&self, height: Height) -> Result<Option<TargetAdmissionPackage>, String> {
        let _guard = ETDAG_ADMISSION_STORE_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .map_err(|_| "ETDAG admission-package store lock poisoned".to_string())?;
        Ok(self
            .load_unlocked()?
            .packages
            .get(&height)
            .map(|entry| entry.package.clone()))
    }

    fn load_unlocked(&self) -> Result<EtdagAdmissionPackageStoreFile, String> {
        if !self.path.exists() {
            return Ok(EtdagAdmissionPackageStoreFile::default());
        }
        let bytes = fs::read(&self.path).map_err(|error| {
            format!(
                "read ETDAG admission-package store {}: {error}",
                self.path.display()
            )
        })?;
        let store: EtdagAdmissionPackageStoreFile =
            serde_json::from_slice(&bytes).map_err(|error| {
                format!(
                    "parse ETDAG admission-package store {}: {error}",
                    self.path.display()
                )
            })?;
        if store.format != ETDAG_ADMISSION_STORE_FORMAT {
            return Err("unsupported or corrupt ETDAG admission-package store".to_string());
        }
        for (height, entry) in &store.packages {
            if entry.package.context.target_height != *height
                || entry.package.package_digest()? != entry.package_digest
            {
                return Err("ETDAG admission-package store digest/key mismatch".to_string());
            }
            entry.package.context.validate()?;
            entry.package.ingress_kem_registry.validate_shape()?;
            if entry.package.ingress_kem_registry.root()?
                != entry.package.context.ingress_kem_registry_root
            {
                return Err("ETDAG admission-package store registry-root mismatch".to_string());
            }
        }
        Ok(store)
    }

    fn persist_unlocked(&self, store: &EtdagAdmissionPackageStoreFile) -> Result<(), String> {
        let parent = self
            .path
            .parent()
            .ok_or_else(|| "ETDAG admission-package store path has no parent".to_string())?;
        fs::create_dir_all(parent)
            .map_err(|error| format!("create ETDAG admission-package directory: {error}"))?;
        let name = self
            .path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| "ETDAG admission-package store has no file name".to_string())?;
        let temp = parent.join(format!(
            ".{name}.tmp-{}-{}",
            std::process::id(),
            current_unix_nanos()
        ));
        let bytes = serde_json::to_vec_pretty(store)
            .map_err(|error| format!("serialize ETDAG admission-package store: {error}"))?;
        let result = (|| {
            let mut file = OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&temp)
                .map_err(|error| format!("create ETDAG admission-package temp file: {error}"))?;
            file.write_all(&bytes)
                .map_err(|error| format!("write ETDAG admission-package store: {error}"))?;
            file.sync_all()
                .map_err(|error| format!("fsync ETDAG admission-package store: {error}"))?;
            fs::rename(&temp, &self.path)
                .map_err(|error| format!("replace ETDAG admission-package store: {error}"))?;
            let directory = OpenOptions::new()
                .read(true)
                .open(parent)
                .map_err(|error| format!("open ETDAG admission-package directory: {error}"))?;
            directory
                .sync_all()
                .map_err(|error| format!("fsync ETDAG admission-package directory: {error}"))
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temp);
        }
        result
    }
}

#[derive(Debug, Clone)]
pub struct EtdagSafetyJournal {
    path: PathBuf,
}

static ETDAG_JOURNAL_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

impl EtdagSafetyJournal {
    pub fn process_wide() -> Self {
        Self::at_path(crate::utils::resolve_data_path(&format!(
            "data/{ETDAG_JOURNAL_FILE}"
        )))
    }

    pub fn at_path(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn reserve_nonce(&self, envelope: &EncryptedTransactionEnvelope) -> Result<(), String> {
        self.with_journal(|journal| {
            let changed = reserve_nonce_in_journal(journal, envelope)?;
            Ok(((), changed))
        })
    }

    pub fn close_admission(
        &self,
        context: &TargetAdmissionContext,
        validator_id: &ValidatorId,
        cutoff_vc_context_root: Hash,
    ) -> Result<(), String> {
        context.validate()?;
        if cutoff_vc_context_root.is_zero() {
            return Err("admission cutoff VC context root is missing".to_string());
        }
        let record = AdmissionCloseRecord {
            epoch: context.epoch,
            target_height: context.target_height,
            cluster_id: context.assigned_cluster_id,
            validator_id: validator_id.clone(),
            target_context_root: context.root()?,
            cutoff_vc_context_root,
        };
        self.with_journal(|journal| {
            if let Some(existing) = journal.admission_closes.iter().find(|existing| {
                existing.epoch == record.epoch
                    && existing.target_height == record.target_height
                    && existing.cluster_id == record.cluster_id
                    && existing.validator_id == record.validator_id
            }) {
                if existing == &record {
                    return Ok(((), false));
                }
                return Err("ETDAG_ADMISSION_CLOSE_CONFLICT".to_string());
            }
            journal.admission_closes.push(record);
            Ok(((), true))
        })
    }

    pub fn admission_is_closed(
        &self,
        context: &TargetAdmissionContext,
        validator_id: &ValidatorId,
    ) -> Result<bool, String> {
        let guard = ETDAG_JOURNAL_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .map_err(|_| "ETDAG journal lock poisoned".to_string())?;
        let journal = self.load_unlocked()?;
        drop(guard);
        Ok(journal.admission_closes.iter().any(|record| {
            record.epoch == context.epoch
                && record.target_height == context.target_height
                && record.cluster_id == context.assigned_cluster_id
                && &record.validator_id == validator_id
        }))
    }

    pub fn authorize_availability_before_signature(
        &self,
        context: &TargetAdmissionContext,
        validator: &ValidatorRecord,
        envelopes: &[EncryptedTransactionEnvelope],
        transcript: &EtdagVoteTranscript,
    ) -> Result<EtdagDigest, String> {
        require_process_wide_consensus_signing_allowed()?;
        transcript.validate_against(context)?;
        if transcript.phase != EtdagPhase::Vac {
            return Err("availability authorization requires VAC phase".to_string());
        }
        let digest = transcript.digest()?;
        self.with_journal(|journal| {
            if journal.admission_closes.iter().any(|record| {
                record.epoch == context.epoch
                    && record.target_height == context.target_height
                    && record.cluster_id == context.assigned_cluster_id
                    && record.validator_id == validator.validator_id
            }) {
                return Err("ETDAG_ADMISSION_CLOSED".to_string());
            }
            let mut changed = false;
            for envelope in envelopes {
                changed |= reserve_nonce_in_journal(journal, envelope)?;
            }
            let changed =
                authorize_vote_in_journal(journal, validator, transcript, digest.clone())?
                    || changed;
            Ok((digest.clone(), changed))
        })
    }

    pub fn authorize_vote_before_signature(
        &self,
        context: &TargetAdmissionContext,
        validator: &ValidatorRecord,
        transcript: &EtdagVoteTranscript,
    ) -> Result<EtdagDigest, String> {
        require_process_wide_consensus_signing_allowed()?;
        transcript.validate_against(context)?;
        if transcript.phase == EtdagPhase::Vac {
            return Err(
                "VAC signatures must use atomic availability/nonce authorization".to_string(),
            );
        }
        let digest = transcript.digest()?;
        self.with_journal(|journal| {
            let changed =
                authorize_vote_in_journal(journal, validator, transcript, digest.clone())?;
            Ok((digest.clone(), changed))
        })
    }

    pub fn authorize_target_admission_before_signature(
        &self,
        context: &TargetAdmissionContext,
        validator: &ValidatorRecord,
        certificate: &TargetAdmissionCertificate,
    ) -> Result<EtdagDigest, String> {
        require_process_wide_consensus_signing_allowed()?;
        context.validate()?;
        if validator.status != ValidatorStatus::Active
            || !validator.is_active_for_epoch(context.epoch)
            || validator.cluster_id != context.assigned_cluster_id
            || validator.consensus_public_key.key_id.0.trim().is_empty()
        {
            return Err("target admission signer is outside its frozen authority".to_string());
        }
        let expected = TargetAdmissionCertificate::without_votes(context)?;
        if certificate != &expected {
            return Err("target admission signer received a noncanonical transcript".to_string());
        }
        let transcript = certificate.signing_bytes(context)?;
        let transcript_digest =
            EtdagDigest::from_domain_bytes(DOMAIN_TARGET_ADMISSION, &transcript);
        self.with_journal(|journal| {
            let record = TargetAdmissionAuthorizationRecord {
                validator_id: validator.validator_id.clone(),
                key_id: validator.consensus_public_key.key_id.clone(),
                epoch: context.epoch,
                target_height: context.target_height,
                assigned_cluster_id: context.assigned_cluster_id,
                target_context_root: context.root()?,
                transcript_digest: transcript_digest.clone(),
            };
            if let Some(existing) =
                journal
                    .target_admission_authorizations
                    .iter()
                    .find(|existing| {
                        existing.validator_id == record.validator_id
                            && existing.epoch == record.epoch
                            && existing.target_height == record.target_height
                            && existing.assigned_cluster_id == record.assigned_cluster_id
                    })
            {
                if existing == &record {
                    return Ok((transcript_digest.clone(), false));
                }
                return Err("ETDAG_TARGET_ADMISSION_SIGNING_CONFLICT".to_string());
            }
            journal.target_admission_authorizations.push(record);
            Ok((transcript_digest.clone(), true))
        })
    }

    pub fn authorize_decrypt_release(
        &self,
        gate: &RevealGate,
        validator_id: &ValidatorId,
        tx_commitment: EtdagDigest,
        share_digest: EtdagDigest,
    ) -> Result<(), String> {
        require_process_wide_consensus_signing_allowed()?;
        gate.validate()?;
        let record = DecryptReleaseRecord {
            epoch: gate.epoch,
            target_height: gate.target_height,
            cluster_id: gate.cluster_id,
            validator_id: validator_id.clone(),
            batch_candidate_digest: gate.batch_candidate_digest.clone(),
            tx_commitment,
            share_digest,
            boc_digest: gate.boc_digest.clone(),
            h_minus_one_vc_root: gate.h_minus_one_vc_root,
        };
        self.with_journal(|journal| {
            if let Some(existing) = journal.decrypt_releases.iter().find(|existing| {
                existing.epoch == record.epoch
                    && existing.target_height == record.target_height
                    && existing.cluster_id == record.cluster_id
                    && existing.validator_id == record.validator_id
                    && existing.tx_commitment == record.tx_commitment
            }) {
                if existing == &record {
                    return Ok(((), false));
                }
                return Err("ETDAG_DECRYPT_RELEASE_CONFLICT".to_string());
            }
            journal.decrypt_releases.push(record);
            Ok(((), true))
        })
    }

    pub fn authorize_protected_decrypt_release(
        &self,
        authorization: &ProtectedRevealAuthorization,
        commitment: &NextProtectedBatchCommitment,
        batch: &DeterministicProtectedBatch,
        context: &TargetAdmissionContext,
        validator_id: &ValidatorId,
        tx_commitment: EtdagDigest,
        share_digest: EtdagDigest,
    ) -> Result<(), String> {
        require_process_wide_consensus_signing_allowed()?;
        authorization.validate_against(context, commitment, batch)?;
        if !batch.ordered_transaction_ids.contains(&tx_commitment) {
            return Err("protected decrypt release is outside committed batch".to_string());
        }
        let record = ProtectedDecryptReleaseRecord {
            epoch: context.epoch,
            target_height: context.target_height,
            cluster_id: context.assigned_cluster_id,
            validator_id: validator_id.clone(),
            authorization_root: authorization.root()?,
            next_commitment_root: commitment.root()?,
            protected_batch_root: batch.protected_batch_root.clone(),
            tx_commitment,
            share_digest,
        };
        self.with_journal(|journal| {
            if let Some(existing) = journal.protected_decrypt_releases.iter().find(|existing| {
                existing.epoch == record.epoch
                    && existing.target_height == record.target_height
                    && existing.cluster_id == record.cluster_id
                    && existing.validator_id == record.validator_id
                    && existing.tx_commitment == record.tx_commitment
            }) {
                if existing == &record {
                    return Ok(((), false));
                }
                return Err("PROTECTED_DECRYPT_RELEASE_CONFLICT".to_string());
            }
            journal.protected_decrypt_releases.push(record);
            Ok(((), true))
        })
    }

    fn with_journal<T>(
        &self,
        operation: impl FnOnce(&mut EtdagDurableJournal) -> Result<(T, bool), String>,
    ) -> Result<T, String> {
        let _guard = ETDAG_JOURNAL_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .map_err(|_| "ETDAG journal lock poisoned".to_string())?;
        let mut journal = self.load_unlocked()?;
        let (result, changed) = operation(&mut journal)?;
        if changed {
            self.persist_unlocked(&journal)?;
        }
        Ok(result)
    }

    fn load_unlocked(&self) -> Result<EtdagDurableJournal, String> {
        if !self.path.exists() {
            return Ok(EtdagDurableJournal::default());
        }
        let bytes = fs::read(&self.path)
            .map_err(|error| format!("read ETDAG journal {}: {error}", self.path.display()))?;
        let journal: EtdagDurableJournal = serde_json::from_slice(&bytes)
            .map_err(|error| format!("parse ETDAG journal {}: {error}", self.path.display()))?;
        if journal.format != ETDAG_JOURNAL_FORMAT {
            return Err("unsupported or corrupt ETDAG journal format".to_string());
        }
        Ok(journal)
    }

    fn persist_unlocked(&self, journal: &EtdagDurableJournal) -> Result<(), String> {
        let parent = self
            .path
            .parent()
            .ok_or_else(|| "ETDAG journal path has no parent".to_string())?;
        fs::create_dir_all(parent)
            .map_err(|error| format!("create ETDAG journal directory: {error}"))?;
        let file_name = self
            .path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| "ETDAG journal path has no file name".to_string())?;
        let temp = parent.join(format!(
            ".{file_name}.tmp-{}-{}",
            std::process::id(),
            current_unix_nanos()
        ));
        let bytes = serde_json::to_vec_pretty(journal)
            .map_err(|error| format!("serialize ETDAG journal: {error}"))?;
        let result = (|| {
            let mut file = OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&temp)
                .map_err(|error| format!("create ETDAG journal temp file: {error}"))?;
            file.write_all(&bytes)
                .map_err(|error| format!("write ETDAG journal: {error}"))?;
            file.sync_all()
                .map_err(|error| format!("fsync ETDAG journal: {error}"))?;
            fs::rename(&temp, &self.path)
                .map_err(|error| format!("replace ETDAG journal: {error}"))?;
            let directory = OpenOptions::new()
                .read(true)
                .open(parent)
                .map_err(|error| format!("open ETDAG journal directory: {error}"))?;
            directory
                .sync_all()
                .map_err(|error| format!("fsync ETDAG journal directory: {error}"))
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temp);
        }
        result
    }
}

fn reserve_nonce_in_journal(
    journal: &mut EtdagDurableJournal,
    envelope: &EncryptedTransactionEnvelope,
) -> Result<bool, String> {
    let record = NonceReservationRecord {
        epoch: envelope.epoch,
        target_height: envelope.target_height,
        sender_id: envelope.sender_id.clone(),
        nonce_slot: envelope.nonce_slot,
        tx_commitment: envelope.tx_commitment.clone(),
    };
    if let Some(existing) = journal.nonce_reservations.iter().find(|existing| {
        existing.epoch == record.epoch
            && existing.target_height == record.target_height
            && existing.sender_id == record.sender_id
            && existing.nonce_slot == record.nonce_slot
    }) {
        if existing == &record {
            return Ok(false);
        }
        return Err("ETDAG_NONCE_RESERVATION_CONFLICT".to_string());
    }
    let mut outstanding_nonces = journal
        .nonce_reservations
        .iter()
        .filter(|existing| {
            existing.epoch == record.epoch
                && existing.target_height == record.target_height
                && existing.sender_id == record.sender_id
        })
        .map(|existing| existing.nonce_slot)
        .collect::<Vec<_>>();
    if outstanding_nonces.len() as u64 >= MAX_OUTSTANDING_NONCE_SLOTS {
        return Err("ETDAG sender outstanding nonce window exhausted".to_string());
    }
    outstanding_nonces.push(record.nonce_slot);
    outstanding_nonces.sort_unstable();
    let first = *outstanding_nonces
        .first()
        .ok_or_else(|| "ETDAG nonce window is empty".to_string())?;
    let last = *outstanding_nonces
        .last()
        .ok_or_else(|| "ETDAG nonce window is empty".to_string())?;
    let span = last
        .checked_sub(first)
        .and_then(|difference| difference.checked_add(1))
        .ok_or_else(|| "ETDAG nonce window overflow".to_string())?;
    if span != outstanding_nonces.len() as u64 {
        return Err("ETDAG sender outstanding nonce slots must be contiguous".to_string());
    }
    journal.nonce_reservations.push(record);
    Ok(true)
}

fn authorize_vote_in_journal(
    journal: &mut EtdagDurableJournal,
    validator: &ValidatorRecord,
    transcript: &EtdagVoteTranscript,
    digest: EtdagDigest,
) -> Result<bool, String> {
    let slot_round = match transcript.phase {
        EtdagPhase::BatchFinality | EtdagPhase::Dcc => None,
        _ => Some(transcript.round),
    };
    let existing = journal.vote_authorizations.iter().find(|existing| {
        existing.validator_id == validator.validator_id
            && existing.key_id == validator.consensus_public_key.key_id
            && existing.transcript.epoch == transcript.epoch
            && existing.transcript.target_height == transcript.target_height
            && existing.transcript.assigned_cluster_id == transcript.assigned_cluster_id
            && existing.transcript.target_context_root == transcript.target_context_root
            && existing.transcript.phase == transcript.phase
            && match transcript.phase {
                EtdagPhase::Vac | EtdagPhase::DecryptShare => {
                    existing.transcript.candidate_digest == transcript.candidate_digest
                }
                _ => {
                    let existing_round = match existing.transcript.phase {
                        EtdagPhase::BatchFinality | EtdagPhase::Dcc => None,
                        _ => Some(existing.transcript.round),
                    };
                    existing_round == slot_round
                }
            }
    });
    if let Some(existing) = existing {
        if existing.transcript == *transcript && existing.transcript_digest == digest {
            return Ok(false);
        }
        return Err(format!("ETDAG_SIGNING_CONFLICT_{:?}", transcript.phase));
    }
    journal.vote_authorizations.push(VoteAuthorizationRecord {
        validator_id: validator.validator_id.clone(),
        key_id: validator.consensus_public_key.key_id.clone(),
        transcript: transcript.clone(),
        transcript_digest: digest,
    });
    Ok(true)
}

pub fn sign_etdag_vote(
    signer: &mut AegisPqvmSigner,
    journal: &EtdagSafetyJournal,
    context: &TargetAdmissionContext,
    validator: &ValidatorRecord,
    transcript: &EtdagVoteTranscript,
) -> Result<EtdagSignedVote, String> {
    journal.authorize_vote_before_signature(context, validator, transcript)?;
    let signature = signer
        .sign_domain(
            transcript.phase.signature_domain(),
            &transcript.canonical_bytes()?,
            &validator.consensus_public_key.key_id,
        )
        .map_err(|error| error.to_string())?;
    Ok(EtdagSignedVote {
        signer_validator_id: validator.validator_id.clone(),
        signer_key_id: validator.consensus_public_key.key_id.clone(),
        signature,
    })
}

pub fn sign_target_admission_vote(
    signer: &mut AegisPqvmSigner,
    journal: &EtdagSafetyJournal,
    context: &TargetAdmissionContext,
    validator: &ValidatorRecord,
) -> Result<EtdagSignedVote, String> {
    let certificate = TargetAdmissionCertificate::without_votes(context)?;
    journal.authorize_target_admission_before_signature(context, validator, &certificate)?;
    let signature = signer
        .sign_domain(
            DOMAIN_TARGET_ADMISSION,
            &certificate.signing_bytes(context)?,
            &validator.consensus_public_key.key_id,
        )
        .map_err(|error| error.to_string())?;
    Ok(EtdagSignedVote {
        signer_validator_id: validator.validator_id.clone(),
        signer_key_id: validator.consensus_public_key.key_id.clone(),
        signature,
    })
}

pub fn sign_vac_vote(
    signer: &mut AegisPqvmSigner,
    journal: &EtdagSafetyJournal,
    context: &TargetAdmissionContext,
    validator: &ValidatorRecord,
    envelopes: &[EncryptedTransactionEnvelope],
    transcript: &EtdagVoteTranscript,
) -> Result<EtdagSignedVote, String> {
    journal.authorize_availability_before_signature(context, validator, envelopes, transcript)?;
    let signature = signer
        .sign_domain(
            DOMAIN_VAC,
            &transcript.canonical_bytes()?,
            &validator.consensus_public_key.key_id,
        )
        .map_err(|error| error.to_string())?;
    Ok(EtdagSignedVote {
        signer_validator_id: validator.validator_id.clone(),
        signer_key_id: validator.consensus_public_key.key_id.clone(),
        signature,
    })
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RevealGate {
    pub epoch: Epoch,
    pub target_height: Height,
    pub cluster_id: ClusterId,
    pub target_context_root: Hash,
    pub batch_candidate_digest: EtdagDigest,
    pub boc_digest: EtdagDigest,
    pub h_minus_one_vc_root: Hash,
    pub h_plus_one_admission_closed: bool,
}

impl RevealGate {
    pub fn validate(&self) -> Result<(), String> {
        if self.target_height.0 < 2
            || self.target_context_root.is_zero()
            || self.h_minus_one_vc_root.is_zero()
            || !self.h_plus_one_admission_closed
        {
            return Err("ETDAG_REVEAL_GATE_CLOSED".to_string());
        }
        self.batch_candidate_digest
            .validate("batch candidate digest")?;
        self.boc_digest.validate("BOC digest")?;
        if self.batch_candidate_digest.is_zero() || self.boc_digest.is_zero() {
            return Err("ETDAG_REVEAL_GATE_CLOSED".to_string());
        }
        Ok(())
    }
}

fn current_unix_nanos() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default()
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum VertexKind {
    Transactions,
    CutoffMarker,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CertifiedEnvelopeRef {
    pub tx_commitment: EtdagDigest,
    pub sender_id: String,
    pub nonce_slot: u64,
    pub certified_dag_round: u64,
    pub gas_class_units: u64,
    pub ciphertext_bytes: u64,
    pub fee_class: u32,
    pub protocol_dependencies: Vec<EtdagDigest>,
}

impl CertifiedEnvelopeRef {
    fn validate(&self) -> Result<(), String> {
        self.tx_commitment.validate("transaction commitment")?;
        if self.sender_id.trim().is_empty()
            || self.gas_class_units == 0
            || self.ciphertext_bytes == 0
        {
            return Err("invalid ETDAG certified envelope reference".to_string());
        }
        let unique = self.protocol_dependencies.iter().collect::<BTreeSet<_>>();
        if unique.len() != self.protocol_dependencies.len()
            || self
                .protocol_dependencies
                .iter()
                .any(|dependency| dependency == &self.tx_commitment)
        {
            return Err("invalid ETDAG protocol dependencies".to_string());
        }
        Ok(())
    }
}

/// Canonical proof that authenticated cutoff evidence deterministically selects
/// one semantic encrypted-data cut. The exact marker evidence root may vary
/// across valid quorum subsets; `cut_root` may not.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProtectedCutProof {
    pub proof_version: u32,
    pub chain_id: ChainId,
    pub network_id: NetworkId,
    pub protocol_version: String,
    pub profile_id: String,
    pub epoch: Epoch,
    pub target_height: Height,
    pub cluster_id: ClusterId,
    pub target_context_root: Hash,
    pub validator_set_commitment: Hash,
    pub parameter_root: ConsensusParameterRoot,
    pub cutoff_vc_context_root: Hash,
    pub cutoff_marker_digests: Vec<EtdagDigest>,
    pub cutoff_marker_evidence_root: EtdagDigest,
    /// Canonical transaction-ancestor closure selected by the authenticated
    /// cutoff. Marker vertices are evidence for the cutoff and are bound by
    /// `cutoff_marker_evidence_root`; they are intentionally excluded here so
    /// valid quorum subsets cannot change the semantic `cut_root`.
    pub causal_closure_digests: Vec<EtdagDigest>,
    pub causal_closure_root: EtdagDigest,
    pub eligible_envelopes: Vec<CertifiedEnvelopeRef>,
    pub eligible_set_root: EtdagDigest,
    pub cut_root: EtdagDigest,
}

#[derive(Serialize, Deserialize, PartialEq)]
struct ProtectedCutSemantic {
    proof_version: u32,
    chain_id: ChainId,
    network_id: NetworkId,
    protocol_version: String,
    profile_id: String,
    epoch: Epoch,
    target_height: Height,
    cluster_id: ClusterId,
    target_context_root: Hash,
    validator_set_commitment: Hash,
    parameter_root: ConsensusParameterRoot,
    cutoff_vc_context_root: Hash,
    causal_closure_root: EtdagDigest,
    eligible_set_root: EtdagDigest,
}

impl ProtectedCutProof {
    pub fn semantic_root(&self) -> Result<EtdagDigest, String> {
        EtdagDigest::from_canonical(
            DOMAIN_PROTECTED_CUT_SEMANTIC,
            &ProtectedCutSemantic {
                proof_version: self.proof_version,
                chain_id: self.chain_id,
                network_id: self.network_id.clone(),
                protocol_version: self.protocol_version.clone(),
                profile_id: self.profile_id.clone(),
                epoch: self.epoch,
                target_height: self.target_height,
                cluster_id: self.cluster_id,
                target_context_root: self.target_context_root,
                validator_set_commitment: self.validator_set_commitment,
                parameter_root: self.parameter_root,
                cutoff_vc_context_root: self.cutoff_vc_context_root,
                causal_closure_root: self.causal_closure_root.clone(),
                eligible_set_root: self.eligible_set_root.clone(),
            },
        )
    }

    pub fn proof_root(&self) -> Result<EtdagDigest, String> {
        EtdagDigest::from_canonical(DOMAIN_PROTECTED_CUT_PROOF, self)
    }

    pub fn validate_declared_roots(&self, context: &TargetAdmissionContext) -> Result<(), String> {
        context.validate()?;
        if self.proof_version != PROTECTED_PIPELINE_VERSION
            || self.chain_id != context.chain_id
            || self.network_id != context.network_id
            || self.protocol_version != context.protocol_version
            || self.profile_id != ETDAG_PROFILE_ID
            || self.epoch != context.epoch
            || self.target_height != context.target_height
            || self.cluster_id != context.assigned_cluster_id
            || self.target_context_root != context.root()?
            || self.validator_set_commitment != context.active_validator_set_root
            || self.parameter_root != context.consensus_parameter_root
            || self.cutoff_vc_context_root.is_zero()
        {
            return Err("protected cut proof context mismatch".to_string());
        }
        let required = certificate_quorum(context.assigned_cluster_validator_count as usize)?;
        if self.cutoff_marker_digests.len() < required
            || !strictly_sorted_unique(&self.cutoff_marker_digests)
            || !strictly_sorted_unique(&self.causal_closure_digests)
        {
            return Err("protected cut proof evidence is not canonical quorum data".to_string());
        }
        let mut prior: Option<&EtdagDigest> = None;
        for envelope in &self.eligible_envelopes {
            envelope.validate()?;
            if prior.is_some_and(|value| value >= &envelope.tx_commitment) {
                return Err("protected cut eligible set is not strictly canonical".to_string());
            }
            prior = Some(&envelope.tx_commitment);
        }
        let marker_root = EtdagDigest::from_canonical(
            DOMAIN_PROTECTED_CUT_MARKER_EVIDENCE,
            &self.cutoff_marker_digests,
        )?;
        let closure_root = EtdagDigest::from_canonical(
            "PoSy/ProtectedPipeline/CausalClosure/v1",
            &self.causal_closure_digests,
        )?;
        let eligible_root = EtdagDigest::from_canonical(
            "PoSy/ProtectedPipeline/EligibleSet/v1",
            &self.eligible_envelopes,
        )?;
        if self.cutoff_marker_evidence_root != marker_root
            || self.causal_closure_root != closure_root
            || self.eligible_set_root != eligible_root
            || self.cut_root != self.semantic_root()?
        {
            return Err("protected cut proof declared roots mismatch".to_string());
        }
        Ok(())
    }
}

fn strictly_sorted_unique<T: Ord>(values: &[T]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

/// Deterministic protected batch derived from one semantic cut and one
/// consensus-provided ordering seed.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeterministicProtectedBatch {
    pub batch_version: u32,
    pub chain_id: ChainId,
    pub network_id: NetworkId,
    pub protocol_version: String,
    pub profile_id: String,
    pub epoch: Epoch,
    pub target_height: Height,
    pub cluster_id: ClusterId,
    pub target_context_root: Hash,
    pub validator_set_commitment: Hash,
    pub parameter_root: ConsensusParameterRoot,
    pub cut_root: EtdagDigest,
    pub eligible_set_root: EtdagDigest,
    pub order_seed: EtdagDigest,
    pub ordered_transaction_ids: Vec<EtdagDigest>,
    pub order_root: EtdagDigest,
    pub protected_count: u64,
    pub protected_gas: u64,
    pub protected_bytes: u64,
    pub protected_batch_root: EtdagDigest,
}

#[derive(Serialize, Deserialize, PartialEq)]
struct ProtectedBatchSemantic {
    batch_version: u32,
    chain_id: ChainId,
    network_id: NetworkId,
    protocol_version: String,
    profile_id: String,
    epoch: Epoch,
    target_height: Height,
    cluster_id: ClusterId,
    target_context_root: Hash,
    validator_set_commitment: Hash,
    parameter_root: ConsensusParameterRoot,
    cut_root: EtdagDigest,
    eligible_set_root: EtdagDigest,
    order_seed: EtdagDigest,
    order_root: EtdagDigest,
    protected_count: u64,
    protected_gas: u64,
    protected_bytes: u64,
}

impl DeterministicProtectedBatch {
    pub fn semantic_root(&self) -> Result<EtdagDigest, String> {
        EtdagDigest::from_canonical(
            DOMAIN_PROTECTED_BATCH,
            &ProtectedBatchSemantic {
                batch_version: self.batch_version,
                chain_id: self.chain_id,
                network_id: self.network_id.clone(),
                protocol_version: self.protocol_version.clone(),
                profile_id: self.profile_id.clone(),
                epoch: self.epoch,
                target_height: self.target_height,
                cluster_id: self.cluster_id,
                target_context_root: self.target_context_root,
                validator_set_commitment: self.validator_set_commitment,
                parameter_root: self.parameter_root,
                cut_root: self.cut_root.clone(),
                eligible_set_root: self.eligible_set_root.clone(),
                order_seed: self.order_seed.clone(),
                order_root: self.order_root.clone(),
                protected_count: self.protected_count,
                protected_gas: self.protected_gas,
                protected_bytes: self.protected_bytes,
            },
        )
    }

    pub fn validate_declared_roots(&self) -> Result<(), String> {
        if self.batch_version != PROTECTED_PIPELINE_VERSION
            || self.profile_id != ETDAG_PROFILE_ID
            || self.target_height.0 == 0
            || self.target_context_root.is_zero()
            || self.validator_set_commitment.is_zero()
            || self.order_seed.is_zero()
            || self.protected_count != self.ordered_transaction_ids.len() as u64
            || self
                .ordered_transaction_ids
                .iter()
                .collect::<BTreeSet<_>>()
                .len()
                != self.ordered_transaction_ids.len()
        {
            return Err("invalid deterministic protected batch".to_string());
        }
        let order_root = EtdagDigest::from_canonical(
            DOMAIN_PROTECTED_ORDER_ROOT,
            &self.ordered_transaction_ids,
        )?;
        if self.order_root != order_root || self.protected_batch_root != self.semantic_root()? {
            return Err("deterministic protected batch declared roots mismatch".to_string());
        }
        Ok(())
    }
}

/// Exact protected batch that the parent PoSy proposal must commit for the
/// target execution height. This is derived, never proposer-selected.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NextProtectedBatchCommitment {
    pub commitment_version: u32,
    pub chain_id: ChainId,
    pub network_id: NetworkId,
    pub protocol_version: String,
    pub epoch: Epoch,
    pub target_height: Height,
    pub cluster_id: ClusterId,
    pub target_context_root: Hash,
    pub validator_set_commitment: Hash,
    pub parameter_root: ConsensusParameterRoot,
    pub cut_root: EtdagDigest,
    pub eligible_set_root: EtdagDigest,
    pub order_seed: EtdagDigest,
    pub order_root: EtdagDigest,
    pub protected_batch_root: EtdagDigest,
    pub protected_count: u64,
    pub protected_gas: u64,
    pub protected_bytes: u64,
}

impl NextProtectedBatchCommitment {
    pub fn root(&self) -> Result<EtdagDigest, String> {
        EtdagDigest::from_canonical(DOMAIN_NEXT_PROTECTED_BATCH_COMMITMENT, self)
    }

    pub fn validate_against(
        &self,
        context: &TargetAdmissionContext,
        batch: &DeterministicProtectedBatch,
    ) -> Result<(), String> {
        context.validate()?;
        self.validate_against_batch(batch)?;
        if self.chain_id != context.chain_id
            || self.network_id != context.network_id
            || self.protocol_version != context.protocol_version
            || self.epoch != context.epoch
            || self.target_height != context.target_height
            || self.cluster_id != context.assigned_cluster_id
            || self.target_context_root != context.root()?
            || self.validator_set_commitment != context.active_validator_set_root
            || self.parameter_root != context.consensus_parameter_root
        {
            return Err("next protected-batch target context mismatch".to_string());
        }
        Ok(())
    }

    pub fn validate_against_batch(
        &self,
        batch: &DeterministicProtectedBatch,
    ) -> Result<(), String> {
        batch.validate_declared_roots()?;
        if self.commitment_version != PROTECTED_PIPELINE_VERSION
            || self.chain_id != batch.chain_id
            || self.network_id != batch.network_id
            || self.protocol_version != batch.protocol_version
            || self.epoch != batch.epoch
            || self.target_height != batch.target_height
            || self.cluster_id != batch.cluster_id
            || self.target_context_root != batch.target_context_root
            || self.validator_set_commitment != batch.validator_set_commitment
            || self.parameter_root != batch.parameter_root
            || self.cut_root != batch.cut_root
            || self.eligible_set_root != batch.eligible_set_root
            || self.order_seed != batch.order_seed
            || self.order_root != batch.order_root
            || self.protected_batch_root != batch.protected_batch_root
            || self.protected_count != batch.protected_count
            || self.protected_gas != batch.protected_gas
            || self.protected_bytes != batch.protected_bytes
        {
            return Err("next protected-batch commitment mismatch".to_string());
        }
        self.root()?
            .validate("next protected-batch commitment root")
    }
}

/// Exact PoSy proposal-validation authority that opens reveal for one target.
///
/// This is a typed binding to the parent proposal and its authenticated n-1
/// ECHO certificate. It is not an ETDAG vote or a READY message.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProtectedRevealAuthorization {
    pub authorization_version: u32,
    pub chain_id: ChainId,
    pub network_id: NetworkId,
    pub protocol_version: String,
    pub epoch: Epoch,
    pub target_height: Height,
    pub cluster_id: ClusterId,
    pub target_context_root: Hash,
    pub validator_set_commitment: Hash,
    pub parameter_root: ConsensusParameterRoot,
    pub parent_proposal_id: BlockId,
    pub parent_block_id: BlockId,
    pub next_commitment_root: EtdagDigest,
    pub protected_batch_root: EtdagDigest,
    pub proposal_validation_certificate_root: Hash,
    pub certificate_evidence_root: EtdagDigest,
}

impl ProtectedRevealAuthorization {
    pub fn root(&self) -> Result<EtdagDigest, String> {
        EtdagDigest::from_canonical(DOMAIN_PROTECTED_REVEAL_AUTHORIZATION, self)
    }

    pub fn validate_against(
        &self,
        context: &TargetAdmissionContext,
        commitment: &NextProtectedBatchCommitment,
        batch: &DeterministicProtectedBatch,
    ) -> Result<(), String> {
        commitment.validate_against(context, batch)?;
        if self.authorization_version != PROTECTED_PIPELINE_VERSION
            || self.chain_id != context.chain_id
            || self.network_id != context.network_id
            || self.protocol_version != context.protocol_version
            || self.epoch != context.epoch
            || self.target_height != context.target_height
            || self.cluster_id != context.assigned_cluster_id
            || self.target_context_root != context.root()?
            || self.validator_set_commitment != context.active_validator_set_root
            || self.parameter_root != context.consensus_parameter_root
            || self.parent_proposal_id.0.trim().is_empty()
            || self.parent_block_id.0.trim().is_empty()
            || self.next_commitment_root != commitment.root()?
            || self.protected_batch_root != batch.protected_batch_root
            || self.proposal_validation_certificate_root.is_zero()
            || self.certificate_evidence_root.is_zero()
        {
            return Err("protected reveal authorization mismatch".to_string());
        }
        self.root()?.validate("protected reveal authorization root")
    }
}

/// Concrete, authenticated execution material for the R11 protected pipeline.
/// No root-only or caller-selected plaintext path is accepted by verification.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeterministicProtectedExecutionInput {
    pub material_version: u32,
    pub source: ProtectedBatchSource,
    pub target_context: ProtectedExecutionTargetContext,
    pub cut_proof: Option<ProtectedCutProof>,
    pub protected_batch: DeterministicProtectedBatch,
    pub next_commitment: NextProtectedBatchCommitment,
    pub reveal_authorization: Option<ProtectedRevealAuthorization>,
    pub envelopes: BTreeMap<EtdagDigest, EncryptedTransactionEnvelope>,
    pub reveal_shares: BTreeMap<EtdagDigest, Vec<ProtectedRevealShareMessage>>,
    pub ordered_transactions: Vec<InnerTransactionV2>,
    pub reveal_transcript_root: EtdagDigest,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ProtectedExecutionTargetContext {
    GenesisBootstrap {
        height_context: HeightConsensusContext,
    },
    NormalEtdag {
        admission_context: TargetAdmissionContext,
    },
}

impl DeterministicProtectedExecutionInput {
    pub fn digest(&self) -> Result<EtdagDigest, String> {
        EtdagDigest::from_canonical(DOMAIN_PROTECTED_EXECUTION_INPUT, self)
    }

    pub fn verify_and_extract_transactions(
        &self,
        verifier: &AegisPqvmVerifier,
        validator_set: &ValidatorSet,
        cluster_map: &ClusterMap,
        parameters: &EtdagParameters,
    ) -> Result<Vec<Transaction>, String> {
        if self.material_version != PROTECTED_PIPELINE_VERSION {
            return Err("unsupported protected execution material version".to_string());
        }
        match self.source {
            ProtectedBatchSource::GenesisBootstrap => {
                self.verify_bootstrap_empty(validator_set, cluster_map)
            }
            ProtectedBatchSource::NormalEtdag | ProtectedBatchSource::NormalEtdagSteadyState => {
                self.verify_normal(verifier, validator_set, cluster_map, parameters)
            }
        }
    }

    fn verify_bootstrap_empty(
        &self,
        validator_set: &ValidatorSet,
        cluster_map: &ClusterMap,
    ) -> Result<Vec<Transaction>, String> {
        let height_context = match &self.target_context {
            ProtectedExecutionTargetContext::GenesisBootstrap { height_context } => height_context,
            ProtectedExecutionTargetContext::NormalEtdag { .. } => {
                return Err("Genesis protected execution has normal admission context".to_string())
            }
        };
        height_context.validate_validator_and_cluster_bindings(validator_set, cluster_map)?;
        self.next_commitment
            .validate_against_batch(&self.protected_batch)?;
        if !matches!(height_context.height.0, 1 | 2)
            || self.protected_batch.chain_id != height_context.chain_id
            || self.protected_batch.network_id != height_context.network_id
            || self.protected_batch.protocol_version != height_context.protocol_version
            || self.protected_batch.epoch != height_context.epoch
            || self.protected_batch.target_height != height_context.height
            || self.protected_batch.cluster_id != height_context.assigned_cluster_id
            || self.protected_batch.target_context_root != height_context.root()?
            || self.protected_batch.validator_set_commitment
                != height_context.active_validator_set_root
            || self.protected_batch.parameter_root != height_context.consensus_parameter_root
            || self.cut_proof.is_some()
            || self.reveal_authorization.is_some()
            || !self.envelopes.is_empty()
            || !self.reveal_shares.is_empty()
            || !self.ordered_transactions.is_empty()
            || self.protected_batch.protected_count != 0
            || self.protected_batch.protected_gas != 0
            || self.protected_batch.protected_bytes != 0
            || !self.protected_batch.ordered_transaction_ids.is_empty()
        {
            return Err(
                "Genesis protected execution input is not the canonical empty H1/H2 batch"
                    .to_string(),
            );
        }
        let empty = BTreeMap::<EtdagDigest, Vec<ProtectedRevealShareMessage>>::new();
        if self.reveal_transcript_root != protected_reveal_transcript_root(&empty)? {
            return Err("Genesis protected reveal transcript root mismatch".to_string());
        }
        Ok(Vec::new())
    }

    fn verify_normal(
        &self,
        verifier: &AegisPqvmVerifier,
        validator_set: &ValidatorSet,
        cluster_map: &ClusterMap,
        parameters: &EtdagParameters,
    ) -> Result<Vec<Transaction>, String> {
        let target_context = match &self.target_context {
            ProtectedExecutionTargetContext::NormalEtdag { admission_context } => admission_context,
            ProtectedExecutionTargetContext::GenesisBootstrap { .. } => {
                return Err("normal protected execution has Genesis height context".to_string())
            }
        };
        target_context.validate_validator_and_cluster_bindings(validator_set, cluster_map)?;
        self.next_commitment
            .validate_against(target_context, &self.protected_batch)?;
        match (self.source, target_context.target_height.0) {
            (ProtectedBatchSource::NormalEtdag, 3) => {}
            (ProtectedBatchSource::NormalEtdagSteadyState, height) if height >= 4 => {}
            _ => return Err("protected execution source/height boundary mismatch".to_string()),
        }
        parameters.validate()?;
        let cut = self
            .cut_proof
            .as_ref()
            .ok_or_else(|| "normal protected execution is missing cut proof".to_string())?;
        cut.validate_declared_roots(target_context)?;
        if self.protected_batch.cut_root != cut.cut_root
            || self.protected_batch.eligible_set_root != cut.eligible_set_root
        {
            return Err("protected execution batch does not match semantic cut".to_string());
        }
        let expected_order = canonical_content_blind_order(
            &cut.eligible_envelopes,
            &self.protected_batch.order_seed,
            parameters.max_protected_gas,
            parameters.max_protected_bytes,
        )?;
        let expected_ids = expected_order
            .iter()
            .map(|reference| reference.tx_commitment.clone())
            .collect::<Vec<_>>();
        let expected_gas = expected_order.iter().try_fold(0u64, |total, reference| {
            total
                .checked_add(reference.gas_class_units)
                .ok_or_else(|| "protected gas total overflow".to_string())
        })?;
        let expected_bytes = expected_order.iter().try_fold(0u64, |total, reference| {
            total
                .checked_add(reference.ciphertext_bytes)
                .ok_or_else(|| "protected byte total overflow".to_string())
        })?;
        if self.protected_batch.ordered_transaction_ids != expected_ids
            || self.protected_batch.protected_gas != expected_gas
            || self.protected_batch.protected_bytes != expected_bytes
        {
            return Err("protected execution order/capacity derivation mismatch".to_string());
        }

        let authorization = self.reveal_authorization.as_ref().ok_or_else(|| {
            "normal protected execution is missing proposal VC reveal authorization".to_string()
        })?;
        authorization.validate_against(
            target_context,
            &self.next_commitment,
            &self.protected_batch,
        )?;
        let expected_set = expected_ids.iter().cloned().collect::<BTreeSet<_>>();
        if self.envelopes.keys().cloned().collect::<BTreeSet<_>>() != expected_set
            || self.reveal_shares.keys().cloned().collect::<BTreeSet<_>>() != expected_set
            || self.ordered_transactions.len() != expected_ids.len()
        {
            return Err("protected execution concrete material set mismatch".to_string());
        }
        let references = cut
            .eligible_envelopes
            .iter()
            .map(|reference| (reference.tx_commitment.clone(), reference))
            .collect::<BTreeMap<_, _>>();
        let threshold =
            decryption_threshold(target_context.assigned_cluster_validator_count as usize)?;
        let mut transactions = Vec::with_capacity(expected_ids.len());
        for (index, commitment) in expected_ids.iter().enumerate() {
            let envelope = self
                .envelopes
                .get(commitment)
                .ok_or_else(|| "protected execution is missing ordered envelope".to_string())?;
            if &envelope.tx_commitment != commitment {
                return Err("protected execution envelope map key mismatch".to_string());
            }
            envelope.validate_structure(target_context, parameters)?;
            envelope.verify_outer_signature(verifier)?;
            let reference = references.get(commitment).ok_or_else(|| {
                "protected execution envelope is outside semantic cut".to_string()
            })?;
            if envelope.sender_id != reference.sender_id
                || envelope.nonce_slot != reference.nonce_slot
                || envelope.ciphertext.len() as u64 != reference.ciphertext_bytes
                || envelope.gas_class as u64 != reference.gas_class_units
                || envelope.fee_class != reference.fee_class
            {
                return Err("protected execution envelope metadata mismatch".to_string());
            }
            let messages = self
                .reveal_shares
                .get(commitment)
                .ok_or_else(|| "protected execution is missing reveal shares".to_string())?;
            let mut validators = BTreeSet::new();
            let mut share_indices = BTreeSet::new();
            for message in messages {
                if !validators.insert(message.validator_id.clone())
                    || !share_indices.insert(message.share.index)
                {
                    return Err(
                        "protected execution contains duplicate reveal authority".to_string()
                    );
                }
                verify_protected_reveal_share(
                    message,
                    authorization,
                    &self.next_commitment,
                    &self.protected_batch,
                    verifier,
                    target_context,
                    validator_set,
                )?;
                if &message.tx_commitment != commitment {
                    return Err("protected reveal share transaction binding mismatch".to_string());
                }
            }
            if messages.len() < threshold {
                return Err("protected execution has insufficient reveal shares".to_string());
            }
            let shares = messages
                .iter()
                .map(|message| message.share.clone())
                .collect::<Vec<_>>();
            let decrypted = decrypt_inner_transaction(envelope, &shares, threshold)?;
            if self.ordered_transactions.get(index) != Some(&decrypted) {
                return Err("protected execution plaintext does not match ciphertext".to_string());
            }
            verifier
                .verify_transaction_signature_checked(&decrypted.transaction)
                .map_err(|error| error.to_string())?;
            transactions.push(decrypted.transaction);
        }
        if self.reveal_transcript_root != protected_reveal_transcript_root(&self.reveal_shares)? {
            return Err("protected reveal transcript root mismatch".to_string());
        }
        self.digest()?
            .validate("protected execution input digest")?;
        Ok(transactions)
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ProtectedPipelinePhase {
    Collecting,
    CutoffReady,
    CutReady,
    OrderReady,
    CommittedInParent,
    RevealAuthorized,
    Revealing,
    ReadyForExecution,
    Consumed,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ProtectedBatchSource {
    GenesisBootstrap,
    NormalEtdag,
    NormalEtdagSteadyState,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProtectedPipelineDiagnostic {
    pub target_height: Height,
    pub phase: ProtectedPipelinePhase,
    pub source: ProtectedBatchSource,
    pub availability_count: u64,
    pub cutoff_marker_count: u64,
    pub cut_ready: bool,
    pub order_ready: bool,
    pub parent_commitment: bool,
    pub reveal_authorized: bool,
    pub reveal_share_count: u64,
    pub execution_ready: bool,
    pub proposal_seen: bool,
    pub vc_seen: bool,
    pub qc_seen: bool,
    pub finalized: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TransactionVertex {
    pub vertex_version: u32,
    pub kind: VertexKind,
    pub chain_id: ChainId,
    pub network_id: NetworkId,
    pub protocol_version: String,
    pub profile_id: String,
    pub epoch: Epoch,
    pub target_height: Height,
    pub target_context_root: Hash,
    pub cluster_map_root: Hash,
    pub assigned_cluster_id: ClusterId,
    pub parameter_root: ConsensusParameterRoot,
    pub dag_round: u64,
    pub author_validator_id: ValidatorId,
    pub author_sequence: u64,
    pub parent_certified_vertex_digests: Vec<EtdagDigest>,
    pub envelopes: Vec<CertifiedEnvelopeRef>,
    pub envelope_root: EtdagDigest,
    pub capsule_root: EtdagDigest,
    pub declared_gas_units: u64,
    pub declared_ciphertext_bytes: u64,
    pub cutoff_vc_context_root: Option<Hash>,
    pub author_key_id: AegisPqKeyId,
    pub author_signature: AegisPqSignature,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct UnsignedVertex {
    vertex_version: u32,
    kind: VertexKind,
    chain_id: ChainId,
    network_id: NetworkId,
    protocol_version: String,
    profile_id: String,
    epoch: Epoch,
    target_height: Height,
    target_context_root: Hash,
    cluster_map_root: Hash,
    assigned_cluster_id: ClusterId,
    parameter_root: ConsensusParameterRoot,
    dag_round: u64,
    author_validator_id: ValidatorId,
    author_sequence: u64,
    parent_certified_vertex_digests: Vec<EtdagDigest>,
    envelopes: Vec<CertifiedEnvelopeRef>,
    envelope_root: EtdagDigest,
    capsule_root: EtdagDigest,
    declared_gas_units: u64,
    declared_ciphertext_bytes: u64,
    cutoff_vc_context_root: Option<Hash>,
    author_key_id: AegisPqKeyId,
}

impl TransactionVertex {
    fn unsigned(&self) -> UnsignedVertex {
        UnsignedVertex {
            vertex_version: self.vertex_version,
            kind: self.kind,
            chain_id: self.chain_id,
            network_id: self.network_id.clone(),
            protocol_version: self.protocol_version.clone(),
            profile_id: self.profile_id.clone(),
            epoch: self.epoch,
            target_height: self.target_height,
            target_context_root: self.target_context_root,
            cluster_map_root: self.cluster_map_root,
            assigned_cluster_id: self.assigned_cluster_id,
            parameter_root: self.parameter_root,
            dag_round: self.dag_round,
            author_validator_id: self.author_validator_id.clone(),
            author_sequence: self.author_sequence,
            parent_certified_vertex_digests: self.parent_certified_vertex_digests.clone(),
            envelopes: self.envelopes.clone(),
            envelope_root: self.envelope_root.clone(),
            capsule_root: self.capsule_root.clone(),
            declared_gas_units: self.declared_gas_units,
            declared_ciphertext_bytes: self.declared_ciphertext_bytes,
            cutoff_vc_context_root: self.cutoff_vc_context_root,
            author_key_id: self.author_key_id.clone(),
        }
    }

    pub fn digest(&self) -> Result<EtdagDigest, String> {
        EtdagDigest::from_canonical("PoSy/ETDAG/TransactionVertex/v3", &self.unsigned())
    }

    pub fn validate(
        &self,
        verifier: &AegisPqvmVerifier,
        context: &TargetAdmissionContext,
        validator_set: &ValidatorSet,
    ) -> Result<(), String> {
        context.validate()?;
        if self.vertex_version != 2
            || self.profile_id != ETDAG_PROFILE_ID
            || self.protocol_version != POSY_SIMPLIFIED_PROTOCOL_VERSION
            || self.chain_id != context.chain_id
            || self.network_id != context.network_id
            || self.epoch != context.epoch
            || self.target_height != context.target_height
            || self.target_context_root != context.root()?
            || self.cluster_map_root != context.cluster_map_root
            || self.assigned_cluster_id != context.assigned_cluster_id
            || self.parameter_root != context.consensus_parameter_root
        {
            return Err("ETDAG vertex target context mismatch".to_string());
        }
        let member = validator_set
            .active_for_epoch(context.epoch)
            .active_for_cluster(context.assigned_cluster_id)
            .into_iter()
            .find(|member| member.validator_id == self.author_validator_id)
            .ok_or_else(|| "ETDAG vertex author is not in assigned cluster".to_string())?;
        if member.consensus_public_key.key_id != self.author_key_id {
            return Err("ETDAG vertex author key mismatch".to_string());
        }
        if self.dag_round == 0 {
            if !self.parent_certified_vertex_digests.is_empty() {
                return Err("ETDAG genesis-round vertex cannot have parents".to_string());
            }
        } else if self.parent_certified_vertex_digests.len()
            < certificate_quorum(context.assigned_cluster_validator_count as usize)?
        {
            return Err("ETDAG vertex has insufficient certified parents".to_string());
        }
        let unique_parents = self
            .parent_certified_vertex_digests
            .iter()
            .collect::<BTreeSet<_>>();
        if unique_parents.len() != self.parent_certified_vertex_digests.len() {
            return Err("ETDAG vertex contains duplicate parents".to_string());
        }
        self.capsule_root.validate("ETDAG vertex capsule root")?;
        let mut envelopes = self.envelopes.clone();
        envelopes.sort_by(|left, right| left.tx_commitment.cmp(&right.tx_commitment));
        for envelope in &envelopes {
            envelope.validate()?;
            if envelope.certified_dag_round != self.dag_round {
                return Err("ETDAG envelope certified round mismatch".to_string());
            }
        }
        let computed_envelope_root =
            EtdagDigest::from_canonical("PoSy/ETDAG/VertexEnvelopeRoot/v3", &envelopes)?;
        let gas = envelopes.iter().try_fold(0u64, |sum, envelope| {
            sum.checked_add(envelope.gas_class_units)
                .ok_or_else(|| "ETDAG vertex gas overflow".to_string())
        })?;
        let bytes = envelopes.iter().try_fold(0u64, |sum, envelope| {
            sum.checked_add(envelope.ciphertext_bytes)
                .ok_or_else(|| "ETDAG vertex byte count overflow".to_string())
        })?;
        if self.envelope_root != computed_envelope_root
            || self.declared_gas_units != gas
            || self.declared_ciphertext_bytes != bytes
        {
            return Err("ETDAG vertex declared roots/totals mismatch".to_string());
        }
        match self.kind {
            VertexKind::Transactions if self.cutoff_vc_context_root.is_some() => {
                return Err("transaction vertex cannot carry cutoff evidence".to_string())
            }
            VertexKind::CutoffMarker => {
                if !self.envelopes.is_empty()
                    || self.cutoff_vc_context_root.is_none_or(Hash::is_zero)
                {
                    return Err("invalid ETDAG cutoff marker".to_string());
                }
            }
            _ => {}
        }
        verifier
            .verify_domain_signature(
                DOMAIN_VERTEX,
                &self.unsigned().canonical_bytes()?,
                &member.validator_uma_id.0,
                &self.author_key_id,
                context.epoch,
                AegisPqKeyRole::ConsensusVote,
                &self.author_signature,
            )
            .map_err(|error| error.to_string())
    }
}

pub fn sign_vertex(
    signer: &mut AegisPqvmSigner,
    context: &TargetAdmissionContext,
    author: &ValidatorRecord,
    kind: VertexKind,
    dag_round: u64,
    author_sequence: u64,
    mut parents: Vec<EtdagDigest>,
    mut envelopes: Vec<CertifiedEnvelopeRef>,
    capsule_root: EtdagDigest,
    cutoff_vc_context_root: Option<Hash>,
) -> Result<TransactionVertex, String> {
    require_process_wide_consensus_signing_allowed()?;
    parents.sort();
    parents.dedup();
    envelopes.sort_by(|left, right| left.tx_commitment.cmp(&right.tx_commitment));
    let envelope_root =
        EtdagDigest::from_canonical("PoSy/ETDAG/VertexEnvelopeRoot/v3", &envelopes)?;
    let declared_gas_units = envelopes.iter().try_fold(0u64, |sum, envelope| {
        sum.checked_add(envelope.gas_class_units)
            .ok_or_else(|| "ETDAG vertex gas overflow".to_string())
    })?;
    let declared_ciphertext_bytes = envelopes.iter().try_fold(0u64, |sum, envelope| {
        sum.checked_add(envelope.ciphertext_bytes)
            .ok_or_else(|| "ETDAG vertex byte count overflow".to_string())
    })?;
    let mut vertex = TransactionVertex {
        vertex_version: 2,
        kind,
        chain_id: context.chain_id,
        network_id: context.network_id.clone(),
        protocol_version: context.protocol_version.clone(),
        profile_id: ETDAG_PROFILE_ID.to_string(),
        epoch: context.epoch,
        target_height: context.target_height,
        target_context_root: context.root()?,
        cluster_map_root: context.cluster_map_root,
        assigned_cluster_id: context.assigned_cluster_id,
        parameter_root: context.consensus_parameter_root,
        dag_round,
        author_validator_id: author.validator_id.clone(),
        author_sequence,
        parent_certified_vertex_digests: parents,
        envelopes,
        envelope_root,
        capsule_root,
        declared_gas_units,
        declared_ciphertext_bytes,
        cutoff_vc_context_root,
        author_key_id: author.consensus_public_key.key_id.clone(),
        author_signature: AegisPqSignature {
            algorithm: String::new(),
            signature_bytes: Vec::new(),
        },
    };
    vertex.author_signature = signer
        .sign_domain(
            DOMAIN_VERTEX,
            &vertex.unsigned().canonical_bytes()?,
            &vertex.author_key_id,
        )
        .map_err(|error| error.to_string())?;
    Ok(vertex)
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CertifiedVertex {
    pub vertex: TransactionVertex,
    pub availability_certificate: EtdagCertificate,
}

impl CertifiedVertex {
    pub fn verify(
        &self,
        verifier: &AegisPqvmVerifier,
        context: &TargetAdmissionContext,
        validator_set: &ValidatorSet,
        cluster_map: &ClusterMap,
    ) -> Result<(), String> {
        self.vertex.validate(verifier, context, validator_set)?;
        if self.availability_certificate.transcript.phase != EtdagPhase::Vac
            || self.availability_certificate.transcript.candidate_digest != self.vertex.digest()?
        {
            return Err("VAC is not bound to exact ETDAG vertex".to_string());
        }
        self.availability_certificate
            .verify(verifier, context, validator_set, cluster_map)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DagCutCandidate {
    pub target_height: Height,
    pub target_context_root: Hash,
    pub cluster_id: ClusterId,
    pub cutoff_vc_context_root: Hash,
    pub cutoff_marker_digests: Vec<EtdagDigest>,
    pub causal_closure_digests: Vec<EtdagDigest>,
    pub eligible_envelopes: Vec<CertifiedEnvelopeRef>,
    pub causal_closure_root: EtdagDigest,
    pub eligible_commitment_root: EtdagDigest,
}

impl DagCutCandidate {
    pub fn digest(&self) -> Result<EtdagDigest, String> {
        EtdagDigest::from_canonical("PoSy/ETDAG/DagCutCandidate/v3", self)
    }

    pub fn validate(&self, context: &TargetAdmissionContext) -> Result<(), String> {
        context.validate()?;
        if self.target_height != context.target_height
            || self.target_context_root != context.root()?
            || self.cluster_id != context.assigned_cluster_id
            || self.cutoff_vc_context_root.is_zero()
        {
            return Err("DCC candidate target/cutoff context mismatch".to_string());
        }
        let required = certificate_quorum(context.assigned_cluster_validator_count as usize)?;
        let marker_set = self
            .cutoff_marker_digests
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>();
        if marker_set.len() != self.cutoff_marker_digests.len()
            || marker_set.len() < required
            || marker_set.iter().cloned().collect::<Vec<_>>() != self.cutoff_marker_digests
        {
            return Err("DCC candidate cutoff-marker set is not canonical quorum".to_string());
        }
        let closure_set = self
            .causal_closure_digests
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>();
        if closure_set.len() != self.causal_closure_digests.len()
            || closure_set.iter().cloned().collect::<Vec<_>>() != self.causal_closure_digests
            || !marker_set.is_subset(&closure_set)
        {
            return Err("DCC candidate causal closure is not canonical or complete".to_string());
        }
        let mut prior: Option<&EtdagDigest> = None;
        for envelope in &self.eligible_envelopes {
            envelope.validate()?;
            if prior.is_some_and(|commitment| commitment >= &envelope.tx_commitment) {
                return Err("DCC eligible commitments are not strictly canonical".to_string());
            }
            prior = Some(&envelope.tx_commitment);
        }
        let causal_closure_root = EtdagDigest::from_canonical(
            "PoSy/ETDAG/CausalClosureRoot/v3",
            &self.causal_closure_digests,
        )?;
        let eligible_commitment_root = EtdagDigest::from_canonical(
            "PoSy/ETDAG/EligibleCommitmentRoot/v3",
            &self.eligible_envelopes,
        )?;
        if self.causal_closure_root != causal_closure_root
            || self.eligible_commitment_root != eligible_commitment_root
        {
            return Err("DCC candidate declared roots mismatch".to_string());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DagCutCertificate {
    pub candidate: DagCutCandidate,
    pub certificate: EtdagCertificate,
}

impl DagCutCertificate {
    pub fn digest(&self) -> Result<EtdagDigest, String> {
        EtdagDigest::from_canonical("PoSy/ETDAG/DCC/v3", self)
    }

    pub fn verify(
        &self,
        verifier: &AegisPqvmVerifier,
        context: &TargetAdmissionContext,
        validator_set: &ValidatorSet,
        cluster_map: &ClusterMap,
    ) -> Result<(), String> {
        self.candidate.validate(context)?;
        if self.certificate.transcript.phase != EtdagPhase::Dcc
            || self.certificate.transcript.candidate_digest != self.candidate.digest()?
        {
            return Err("DCC certificate does not bind exact DAG cut".to_string());
        }
        self.certificate
            .verify(verifier, context, validator_set, cluster_map)
    }
}

pub fn build_dag_cut_candidate(
    context: &TargetAdmissionContext,
    certified_vertices: &BTreeMap<EtdagDigest, CertifiedVertex>,
    marker_digests: &[EtdagDigest],
    verifier: &AegisPqvmVerifier,
    validator_set: &ValidatorSet,
    cluster_map: &ClusterMap,
) -> Result<DagCutCandidate, String> {
    context.validate()?;
    context.validate_validator_and_cluster_bindings(validator_set, cluster_map)?;
    let required = certificate_quorum(context.assigned_cluster_validator_count as usize)?;
    let mut markers = marker_digests.to_vec();
    markers.sort();
    markers.dedup();
    if markers.len() < required {
        return Err("DCC has insufficient distinct cutoff markers".to_string());
    }
    let mut marker_authors = BTreeSet::new();
    let cluster_members = validator_set
        .active_for_epoch(context.epoch)
        .active_for_cluster(context.assigned_cluster_id);
    let mut marker_weight = 0u64;
    let mut cutoff_root: Option<Hash> = None;
    for marker_digest in &markers {
        let marker = certified_vertices
            .get(marker_digest)
            .ok_or_else(|| "DCC cutoff marker is missing".to_string())?;
        if marker.vertex.digest()? != *marker_digest {
            return Err("DCC cutoff marker map key does not match vertex digest".to_string());
        }
        marker.verify(verifier, context, validator_set, cluster_map)?;
        if marker.vertex.kind != VertexKind::CutoffMarker {
            return Err("DCC marker set includes a transaction vertex".to_string());
        }
        if !marker_authors.insert(marker.vertex.author_validator_id.clone()) {
            return Err("DCC marker set contains duplicate authors".to_string());
        }
        let author = cluster_members
            .iter()
            .find(|member| member.validator_id == marker.vertex.author_validator_id)
            .ok_or_else(|| "DCC marker author is not in assigned cluster".to_string())?;
        marker_weight = marker_weight
            .checked_add(author.voting_weight)
            .ok_or_else(|| "DCC marker weight overflow".to_string())?;
        let root = marker
            .vertex
            .cutoff_vc_context_root
            .ok_or_else(|| "DCC marker has no cutoff VC context".to_string())?;
        if cutoff_root.is_some_and(|existing| existing != root) {
            return Err("DCC markers disagree on cutoff VC context".to_string());
        }
        cutoff_root = Some(root);
    }
    if (marker_authors.len() as u128)
        .checked_mul(3)
        .is_none_or(|value| {
            value <= (context.assigned_cluster_validator_count as u128).saturating_mul(2)
        })
    {
        return Err("DCC strict cutoff-marker count quorum failed".to_string());
    }
    if (marker_weight as u128).checked_mul(3).is_none_or(|value| {
        value <= (context.assigned_cluster_total_voting_weight as u128).saturating_mul(2)
    }) {
        return Err("DCC strict cutoff-marker weight quorum failed".to_string());
    }

    let mut closure = BTreeSet::new();
    for marker in &markers {
        collect_certified_ancestors(
            marker,
            certified_vertices,
            &mut closure,
            &mut BTreeSet::new(),
            0,
        )?;
    }
    let closure_digests = closure.into_iter().collect::<Vec<_>>();
    let mut eligible = BTreeMap::<EtdagDigest, CertifiedEnvelopeRef>::new();
    for digest in &closure_digests {
        let certified = certified_vertices
            .get(digest)
            .ok_or_else(|| "DCC closure vertex disappeared".to_string())?;
        verify_certified_vertex_parent_set(
            digest,
            certified,
            certified_vertices,
            verifier,
            context,
            validator_set,
            cluster_map,
        )?;
        for envelope in &certified.vertex.envelopes {
            if let Some(existing) = eligible.get(&envelope.tx_commitment) {
                if existing != envelope {
                    return Err("DCC contains conflicting commitment metadata".to_string());
                }
            } else {
                eligible.insert(envelope.tx_commitment.clone(), envelope.clone());
            }
        }
    }
    let eligible_envelopes = eligible.into_values().collect::<Vec<_>>();
    let causal_closure_root =
        EtdagDigest::from_canonical("PoSy/ETDAG/CausalClosureRoot/v3", &closure_digests)?;
    let eligible_commitment_root =
        EtdagDigest::from_canonical("PoSy/ETDAG/EligibleCommitmentRoot/v3", &eligible_envelopes)?;
    Ok(DagCutCandidate {
        target_height: context.target_height,
        target_context_root: context.root()?,
        cluster_id: context.assigned_cluster_id,
        cutoff_vc_context_root: cutoff_root
            .ok_or_else(|| "DCC has no cutoff VC context".to_string())?,
        cutoff_marker_digests: markers,
        causal_closure_digests: closure_digests,
        eligible_envelopes,
        causal_closure_root,
        eligible_commitment_root,
    })
}

fn verify_certified_vertex_parent_set(
    digest: &EtdagDigest,
    certified: &CertifiedVertex,
    certified_vertices: &BTreeMap<EtdagDigest, CertifiedVertex>,
    verifier: &AegisPqvmVerifier,
    context: &TargetAdmissionContext,
    validator_set: &ValidatorSet,
    cluster_map: &ClusterMap,
) -> Result<(), String> {
    if certified.vertex.digest()? != *digest {
        return Err("ETDAG certified-vertex map key does not match vertex digest".to_string());
    }
    certified.verify(verifier, context, validator_set, cluster_map)?;
    if certified.vertex.dag_round == 0 {
        if !certified.vertex.parent_certified_vertex_digests.is_empty() {
            return Err("ETDAG genesis-round vertex cannot have parents".to_string());
        }
        return Ok(());
    }

    let expected_parent_round = certified
        .vertex
        .dag_round
        .checked_sub(1)
        .ok_or_else(|| "ETDAG parent round underflow".to_string())?;
    let mut parent_authors = BTreeSet::new();
    for parent_digest in &certified.vertex.parent_certified_vertex_digests {
        let parent = certified_vertices
            .get(parent_digest)
            .ok_or_else(|| "ETDAG certified parent is unavailable".to_string())?;
        if parent.vertex.digest()? != *parent_digest {
            return Err("ETDAG certified-parent map key mismatch".to_string());
        }
        parent.verify(verifier, context, validator_set, cluster_map)?;
        if parent.vertex.dag_round != expected_parent_round {
            return Err("ETDAG parent is not from the previous DAG round".to_string());
        }
        if !parent_authors.insert(parent.vertex.author_validator_id.clone()) {
            return Err("ETDAG parent VACs do not have distinct authors".to_string());
        }
    }
    let required = certificate_quorum(context.assigned_cluster_validator_count as usize)?;
    if parent_authors.len() < required {
        return Err(
            "ETDAG vertex has insufficient distinct previous-round VAC authors".to_string(),
        );
    }
    Ok(())
}

fn collect_certified_ancestors(
    digest: &EtdagDigest,
    vertices: &BTreeMap<EtdagDigest, CertifiedVertex>,
    closure: &mut BTreeSet<EtdagDigest>,
    visiting: &mut BTreeSet<EtdagDigest>,
    depth: usize,
) -> Result<(), String> {
    if depth > MAX_CALL_DEPTH {
        return Err("ETDAG parent graph exceeds bounded depth".to_string());
    }
    if closure.contains(digest) {
        return Ok(());
    }
    if !visiting.insert(digest.clone()) {
        return Err("ETDAG parent graph contains a cycle".to_string());
    }
    let vertex = vertices
        .get(digest)
        .ok_or_else(|| "ETDAG causal parent is unavailable".to_string())?;
    for parent in &vertex.vertex.parent_certified_vertex_digests {
        collect_certified_ancestors(parent, vertices, closure, visiting, depth + 1)?;
    }
    visiting.remove(digest);
    closure.insert(digest.clone());
    Ok(())
}

pub fn canonical_finality_context_digest<T: CanonicalSerialize>(
    canonical_finality_context_without_signatures: &T,
) -> Result<EtdagDigest, String> {
    EtdagDigest::from_canonical(
        "PoSy/ETDAG/CanonicalFinalityContext/v3",
        canonical_finality_context_without_signatures,
    )
}

pub fn derive_order_seed(
    epoch_randomness: Hash,
    canonical_finality_context: &EtdagDigest,
    dcc_digest: &EtdagDigest,
    target_height: Height,
) -> Result<EtdagDigest, String> {
    if epoch_randomness.is_zero() {
        return Err("ETDAG order seed epoch randomness is missing".to_string());
    }
    canonical_finality_context.validate("canonical finality context")?;
    dcc_digest.validate("DCC digest")?;
    EtdagDigest::from_canonical(
        DOMAIN_ORDER_SEED,
        &(
            epoch_randomness,
            canonical_finality_context.clone(),
            dcc_digest.clone(),
            target_height,
        ),
    )
}

fn order_key(seed: &EtdagDigest, commitment: &EtdagDigest) -> Result<EtdagDigest, String> {
    EtdagDigest::from_canonical(DOMAIN_ORDER_KEY, &(seed.clone(), commitment.clone()))
}

pub fn canonical_content_blind_order(
    eligible: &[CertifiedEnvelopeRef],
    order_seed: &EtdagDigest,
    max_gas: u64,
    max_bytes: u64,
) -> Result<Vec<CertifiedEnvelopeRef>, String> {
    order_seed.validate("ETDAG order seed")?;
    let mut by_commitment = BTreeMap::new();
    for envelope in eligible {
        envelope.validate()?;
        if by_commitment
            .insert(envelope.tx_commitment.clone(), envelope.clone())
            .is_some()
        {
            return Err("ETDAG eligible set contains duplicate commitment".to_string());
        }
    }
    let mut dependencies = by_commitment
        .keys()
        .map(|commitment| (commitment.clone(), BTreeSet::new()))
        .collect::<BTreeMap<_, _>>();
    for envelope in by_commitment.values() {
        for dependency in &envelope.protocol_dependencies {
            if !by_commitment.contains_key(dependency) {
                return Err("ETDAG protocol dependency is outside eligible closure".to_string());
            }
            dependencies
                .get_mut(&envelope.tx_commitment)
                .expect("dependency map initialized")
                .insert(dependency.clone());
        }
    }
    let mut by_sender = BTreeMap::<String, Vec<&CertifiedEnvelopeRef>>::new();
    for envelope in by_commitment.values() {
        by_sender
            .entry(envelope.sender_id.clone())
            .or_default()
            .push(envelope);
    }
    for sender_envelopes in by_sender.values_mut() {
        sender_envelopes.sort_by(|left, right| {
            left.nonce_slot
                .cmp(&right.nonce_slot)
                .then_with(|| left.tx_commitment.cmp(&right.tx_commitment))
        });
        for pair in sender_envelopes.windows(2) {
            if pair[0].nonce_slot == pair[1].nonce_slot {
                return Err("ETDAG eligible set contains sender nonce conflict".to_string());
            }
            dependencies
                .get_mut(&pair[1].tx_commitment)
                .expect("dependency map initialized")
                .insert(pair[0].tx_commitment.clone());
        }
    }

    let mut indegree = dependencies
        .iter()
        .map(|(commitment, parents)| (commitment.clone(), parents.len()))
        .collect::<BTreeMap<_, _>>();
    let mut children = BTreeMap::<EtdagDigest, BTreeSet<EtdagDigest>>::new();
    for (child, parents) in &dependencies {
        for parent in parents {
            children
                .entry(parent.clone())
                .or_default()
                .insert(child.clone());
        }
    }
    let mut ready = BTreeSet::<(u64, EtdagDigest, EtdagDigest)>::new();
    for (commitment, degree) in &indegree {
        if *degree == 0 {
            let envelope = by_commitment
                .get(commitment)
                .expect("eligible map contains indegree item");
            ready.insert((
                envelope.certified_dag_round,
                order_key(order_seed, commitment)?,
                commitment.clone(),
            ));
        }
    }
    let mut ordered = Vec::with_capacity(eligible.len());
    while let Some(next) = ready.iter().next().cloned() {
        ready.remove(&next);
        let commitment = next.2;
        ordered.push(
            by_commitment
                .get(&commitment)
                .expect("ready item exists")
                .clone(),
        );
        for child in children.get(&commitment).cloned().unwrap_or_default() {
            let degree = indegree
                .get_mut(&child)
                .ok_or_else(|| "ETDAG child is missing indegree".to_string())?;
            *degree = degree
                .checked_sub(1)
                .ok_or_else(|| "ETDAG indegree underflow".to_string())?;
            if *degree == 0 {
                let envelope = by_commitment
                    .get(&child)
                    .ok_or_else(|| "ETDAG child is missing envelope".to_string())?;
                ready.insert((
                    envelope.certified_dag_round,
                    order_key(order_seed, &child)?,
                    child,
                ));
            }
        }
    }
    if ordered.len() != eligible.len() {
        return Err("ETDAG dependency graph contains a cycle".to_string());
    }

    let mut selected = Vec::new();
    let mut gas = 0u64;
    let mut bytes = 0u64;
    for envelope in ordered {
        let next_gas = gas
            .checked_add(envelope.gas_class_units)
            .ok_or_else(|| "ETDAG protected gas overflow".to_string())?;
        let next_bytes = bytes
            .checked_add(envelope.ciphertext_bytes)
            .ok_or_else(|| "ETDAG protected bytes overflow".to_string())?;
        if next_gas > max_gas || next_bytes > max_bytes {
            break;
        }
        gas = next_gas;
        bytes = next_bytes;
        selected.push(envelope);
    }
    Ok(selected)
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum BatchDisposition {
    Ordered,
    EmptyNoEligibleTransactions,
    EmptyCertifiedAvailabilityFailure,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BatchCandidate {
    pub candidate_version: u32,
    pub target_height: Height,
    pub target_context_root: Hash,
    pub cluster_id: ClusterId,
    pub dcc_digest: EtdagDigest,
    pub canonical_finality_context_digest: EtdagDigest,
    pub order_seed: EtdagDigest,
    pub ordered_commitments: Vec<EtdagDigest>,
    pub ordered_commitment_root: EtdagDigest,
    pub deferred_commitment_root: EtdagDigest,
    pub dependency_graph_root: EtdagDigest,
    pub declared_gas_units: u64,
    pub declared_ciphertext_bytes: u64,
    pub disposition: BatchDisposition,
    pub certified_availability_failure_root: Option<EtdagDigest>,
}

impl BatchCandidate {
    pub fn digest(&self) -> Result<EtdagDigest, String> {
        EtdagDigest::from_canonical("PoSy/ETDAG/BatchCandidate/v3", self)
    }

    pub fn validate(&self, dcc: &DagCutCandidate) -> Result<(), String> {
        if self.candidate_version != 2
            || self.target_height != dcc.target_height
            || self.target_context_root != dcc.target_context_root
            || self.cluster_id != dcc.cluster_id
            || self.dcc_digest != dcc.digest()?
        {
            return Err("ETDAG batch candidate does not match DCC".to_string());
        }
        let unique = self.ordered_commitments.iter().collect::<BTreeSet<_>>();
        if unique.len() != self.ordered_commitments.len() {
            return Err("ETDAG batch candidate contains duplicate commitments".to_string());
        }
        let root = EtdagDigest::from_canonical(
            "PoSy/ETDAG/OrderedCommitmentRoot/v3",
            &self.ordered_commitments,
        )?;
        if root != self.ordered_commitment_root {
            return Err("ETDAG ordered commitment root mismatch".to_string());
        }
        match self.disposition {
            BatchDisposition::Ordered if self.ordered_commitments.is_empty() => {
                return Err("ordered ETDAG batch cannot be empty".to_string())
            }
            BatchDisposition::EmptyNoEligibleTransactions
                if !dcc.eligible_envelopes.is_empty()
                    || !self.ordered_commitments.is_empty()
                    || self.certified_availability_failure_root.is_some() =>
            {
                return Err("invalid no-eligible empty ETDAG batch".to_string())
            }
            BatchDisposition::EmptyCertifiedAvailabilityFailure
                if !self.ordered_commitments.is_empty()
                    || self
                        .certified_availability_failure_root
                        .as_ref()
                        .is_none_or(EtdagDigest::is_zero) =>
            {
                return Err("empty ETDAG batch lacks certified failure proof".to_string())
            }
            _ => {}
        }
        Ok(())
    }
}

pub fn build_batch_candidate(
    dcc: &DagCutCandidate,
    canonical_finality_context_digest: EtdagDigest,
    epoch_randomness: Hash,
    parameters: &EtdagParameters,
) -> Result<BatchCandidate, String> {
    parameters.validate()?;
    let dcc_digest = dcc.digest()?;
    let order_seed = derive_order_seed(
        epoch_randomness,
        &canonical_finality_context_digest,
        &dcc_digest,
        dcc.target_height,
    )?;
    let ordered = canonical_content_blind_order(
        &dcc.eligible_envelopes,
        &order_seed,
        parameters.max_protected_gas,
        parameters.max_protected_bytes,
    )?;
    let ordered_commitments = ordered
        .iter()
        .map(|envelope| envelope.tx_commitment.clone())
        .collect::<Vec<_>>();
    let ordered_set = ordered_commitments.iter().cloned().collect::<BTreeSet<_>>();
    let deferred = dcc
        .eligible_envelopes
        .iter()
        .filter(|envelope| !ordered_set.contains(&envelope.tx_commitment))
        .map(|envelope| envelope.tx_commitment.clone())
        .collect::<Vec<_>>();
    let declared_gas_units = ordered.iter().try_fold(0u64, |sum, envelope| {
        sum.checked_add(envelope.gas_class_units)
            .ok_or_else(|| "ETDAG batch gas overflow".to_string())
    })?;
    let declared_ciphertext_bytes = ordered.iter().try_fold(0u64, |sum, envelope| {
        sum.checked_add(envelope.ciphertext_bytes)
            .ok_or_else(|| "ETDAG batch bytes overflow".to_string())
    })?;
    let candidate = BatchCandidate {
        candidate_version: 2,
        target_height: dcc.target_height,
        target_context_root: dcc.target_context_root,
        cluster_id: dcc.cluster_id,
        dcc_digest,
        canonical_finality_context_digest,
        order_seed,
        ordered_commitment_root: EtdagDigest::from_canonical(
            "PoSy/ETDAG/OrderedCommitmentRoot/v3",
            &ordered_commitments,
        )?,
        deferred_commitment_root: EtdagDigest::from_canonical(
            "PoSy/ETDAG/DeferredCommitmentRoot/v3",
            &deferred,
        )?,
        dependency_graph_root: EtdagDigest::from_canonical(
            "PoSy/ETDAG/DependencyGraphRoot/v3",
            &dcc.eligible_envelopes,
        )?,
        ordered_commitments,
        declared_gas_units,
        declared_ciphertext_bytes,
        disposition: if dcc.eligible_envelopes.is_empty() {
            BatchDisposition::EmptyNoEligibleTransactions
        } else {
            BatchDisposition::Ordered
        },
        certified_availability_failure_root: None,
    };
    candidate.validate(dcc)?;
    Ok(candidate)
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BatchValidationCertificate {
    pub batch_candidate: BatchCandidate,
    pub certificate: EtdagCertificate,
}

impl BatchValidationCertificate {
    pub fn digest(&self) -> Result<EtdagDigest, String> {
        EtdagDigest::from_canonical("PoSy/ETDAG/BVC/v3", self)
    }

    pub fn verify(
        &self,
        verifier: &AegisPqvmVerifier,
        context: &TargetAdmissionContext,
        validator_set: &ValidatorSet,
        cluster_map: &ClusterMap,
    ) -> Result<(), String> {
        if self.certificate.transcript.phase != EtdagPhase::BatchValidate
            || self.certificate.transcript.candidate_digest != self.batch_candidate.digest()?
        {
            return Err("BVC does not bind exact batch candidate".to_string());
        }
        self.certificate
            .verify(verifier, context, validator_set, cluster_map)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BatchOrderCertificate {
    pub bvc: BatchValidationCertificate,
    pub finality_certificate: EtdagCertificate,
}

impl BatchOrderCertificate {
    pub fn digest(&self) -> Result<EtdagDigest, String> {
        EtdagDigest::from_canonical("PoSy/ETDAG/BOC/v3", self)
    }

    pub fn verify(
        &self,
        verifier: &AegisPqvmVerifier,
        context: &TargetAdmissionContext,
        validator_set: &ValidatorSet,
        cluster_map: &ClusterMap,
    ) -> Result<(), String> {
        self.bvc
            .verify(verifier, context, validator_set, cluster_map)?;
        if self.finality_certificate.transcript.phase != EtdagPhase::BatchFinality
            || self.finality_certificate.transcript.candidate_digest
                != self.bvc.batch_candidate.digest()?
            || self.finality_certificate.transcript.round != self.bvc.certificate.transcript.round
        {
            return Err("BOC finality is not bound to exact BVC candidate".to_string());
        }
        self.finality_certificate
            .verify(verifier, context, validator_set, cluster_map)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BatchTimeoutCertificate {
    pub certificate: EtdagCertificate,
    pub highest_bvc: Option<BatchValidationCertificate>,
}

impl BatchTimeoutCertificate {
    pub fn verify(
        &self,
        verifier: &AegisPqvmVerifier,
        context: &TargetAdmissionContext,
        validator_set: &ValidatorSet,
        cluster_map: &ClusterMap,
    ) -> Result<(), String> {
        if self.certificate.transcript.phase != EtdagPhase::BatchTimeout {
            return Err("BTC has wrong phase".to_string());
        }
        self.certificate
            .verify(verifier, context, validator_set, cluster_map)?;
        match (
            &self.highest_bvc,
            &self.certificate.transcript.highest_prepared_bvc_digest,
        ) {
            (Some(bvc), Some(root)) => {
                bvc.verify(verifier, context, validator_set, cluster_map)?;
                if &bvc.digest()? != root
                    || self.certificate.transcript.candidate_digest
                        != bvc.batch_candidate.digest()?
                {
                    return Err("BTC highest BVC proof mismatch".to_string());
                }
            }
            (None, None) => {}
            _ => return Err("BTC highest BVC presence mismatch".to_string()),
        }
        Ok(())
    }

    pub fn required_carry_forward(&self) -> Option<&BatchCandidate> {
        self.highest_bvc.as_ref().map(|bvc| &bvc.batch_candidate)
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ExecutionDisposition {
    Executed,
    Reverted,
    InvalidInnerSignature,
    OuterInnerMismatch,
    UndecryptableClientFault,
    DecryptionUnavailableNetwork,
    NonceConflict,
    NonceGap,
    Expired,
    WrongHeight,
    WrongCluster,
    Duplicate,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExecutionManifestEntry {
    pub index: u64,
    pub tx_commitment: EtdagDigest,
    pub disposition: ExecutionDisposition,
    pub transaction_hash: Option<Hash>,
    pub receipt_hash: Option<Hash>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExecutionManifest {
    pub target_height: Height,
    pub batch_candidate_digest: EtdagDigest,
    pub entries: Vec<ExecutionManifestEntry>,
}

impl ExecutionManifest {
    pub fn root(&self) -> Result<EtdagDigest, String> {
        EtdagDigest::from_canonical("PoSy/ETDAG/ExecutionManifest/v3", self)
    }

    pub fn validate_exact(&self, batch_candidate: &BatchCandidate) -> Result<(), String> {
        if self.target_height != batch_candidate.target_height
            || self.batch_candidate_digest != batch_candidate.digest()?
            || self.entries.len() != batch_candidate.ordered_commitments.len()
        {
            return Err("protected execution manifest does not match BOC batch".to_string());
        }
        let mut seen = BTreeSet::new();
        for (index, (entry, commitment)) in self
            .entries
            .iter()
            .zip(batch_candidate.ordered_commitments.iter())
            .enumerate()
        {
            if entry.index != index as u64 || &entry.tx_commitment != commitment {
                return Err(
                    "protected execution contains insertion, omission, or reordering".to_string(),
                );
            }
            if !seen.insert(&entry.tx_commitment) {
                return Err("protected execution contains duplicate commitment".to_string());
            }
        }
        Ok(())
    }
}

/// Threshold reveal share bound to the exact R11 parent commitment and PoSy
/// proposal-validation certificate, rather than the retired BOC reveal gate.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProtectedRevealShareMessage {
    pub share_version: u32,
    pub chain_id: ChainId,
    pub network_id: NetworkId,
    pub protocol_version: String,
    pub profile_id: String,
    pub epoch: Epoch,
    pub target_height: Height,
    pub target_context_root: Hash,
    pub cluster_id: ClusterId,
    pub authorization_root: EtdagDigest,
    pub next_commitment_root: EtdagDigest,
    pub protected_batch_root: EtdagDigest,
    pub tx_commitment: EtdagDigest,
    pub validator_id: ValidatorId,
    pub share: ShamirShare,
    pub share_commitment: EtdagDigest,
    pub parameter_root: ConsensusParameterRoot,
    pub key_id: AegisPqKeyId,
    pub signature: AegisPqSignature,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct UnsignedProtectedRevealShare {
    share_version: u32,
    chain_id: ChainId,
    network_id: NetworkId,
    protocol_version: String,
    profile_id: String,
    epoch: Epoch,
    target_height: Height,
    target_context_root: Hash,
    cluster_id: ClusterId,
    authorization_root: EtdagDigest,
    next_commitment_root: EtdagDigest,
    protected_batch_root: EtdagDigest,
    tx_commitment: EtdagDigest,
    validator_id: ValidatorId,
    share: ShamirShare,
    share_commitment: EtdagDigest,
    parameter_root: ConsensusParameterRoot,
    key_id: AegisPqKeyId,
}

impl ProtectedRevealShareMessage {
    fn unsigned(&self) -> UnsignedProtectedRevealShare {
        UnsignedProtectedRevealShare {
            share_version: self.share_version,
            chain_id: self.chain_id,
            network_id: self.network_id.clone(),
            protocol_version: self.protocol_version.clone(),
            profile_id: self.profile_id.clone(),
            epoch: self.epoch,
            target_height: self.target_height,
            target_context_root: self.target_context_root,
            cluster_id: self.cluster_id,
            authorization_root: self.authorization_root.clone(),
            next_commitment_root: self.next_commitment_root.clone(),
            protected_batch_root: self.protected_batch_root.clone(),
            tx_commitment: self.tx_commitment.clone(),
            validator_id: self.validator_id.clone(),
            share: self.share.clone(),
            share_commitment: self.share_commitment.clone(),
            parameter_root: self.parameter_root,
            key_id: self.key_id.clone(),
        }
    }
}

pub fn release_protected_reveal_share(
    signer: &mut AegisPqvmSigner,
    journal: &EtdagSafetyJournal,
    authorization: &ProtectedRevealAuthorization,
    commitment: &NextProtectedBatchCommitment,
    batch: &DeterministicProtectedBatch,
    context: &TargetAdmissionContext,
    validator: &ValidatorRecord,
    tx_commitment: EtdagDigest,
    share: ShamirShare,
) -> Result<ProtectedRevealShareMessage, String> {
    authorization.validate_against(context, commitment, batch)?;
    share.validate()?;
    if !batch.ordered_transaction_ids.contains(&tx_commitment) {
        return Err("protected reveal share is outside committed batch".to_string());
    }
    let share_commitment = share_commitment(
        &validator.validator_id,
        &share,
        context.root()?,
        context.target_height,
    )?;
    let share_digest =
        EtdagDigest::from_canonical("PoSy/ProtectedPipeline/ReleasedShare/v1", &share)?;
    journal.authorize_protected_decrypt_release(
        authorization,
        commitment,
        batch,
        context,
        &validator.validator_id,
        tx_commitment.clone(),
        share_digest,
    )?;
    let mut message = ProtectedRevealShareMessage {
        share_version: PROTECTED_PIPELINE_VERSION,
        chain_id: context.chain_id,
        network_id: context.network_id.clone(),
        protocol_version: context.protocol_version.clone(),
        profile_id: ETDAG_PROFILE_ID.to_string(),
        epoch: context.epoch,
        target_height: context.target_height,
        target_context_root: context.root()?,
        cluster_id: context.assigned_cluster_id,
        authorization_root: authorization.root()?,
        next_commitment_root: commitment.root()?,
        protected_batch_root: batch.protected_batch_root.clone(),
        tx_commitment,
        validator_id: validator.validator_id.clone(),
        share,
        share_commitment,
        parameter_root: context.consensus_parameter_root,
        key_id: validator.consensus_public_key.key_id.clone(),
        signature: AegisPqSignature {
            algorithm: String::new(),
            signature_bytes: Vec::new(),
        },
    };
    message.signature = signer
        .sign_domain(
            DOMAIN_PROTECTED_REVEAL_SHARE,
            &message.unsigned().canonical_bytes()?,
            &message.key_id,
        )
        .map_err(|error| error.to_string())?;
    Ok(message)
}

pub fn verify_protected_reveal_share(
    message: &ProtectedRevealShareMessage,
    authorization: &ProtectedRevealAuthorization,
    commitment: &NextProtectedBatchCommitment,
    batch: &DeterministicProtectedBatch,
    verifier: &AegisPqvmVerifier,
    context: &TargetAdmissionContext,
    validator_set: &ValidatorSet,
) -> Result<(), String> {
    authorization.validate_against(context, commitment, batch)?;
    message.share.validate()?;
    if message.share_version != PROTECTED_PIPELINE_VERSION
        || message.chain_id != context.chain_id
        || message.network_id != context.network_id
        || message.protocol_version != context.protocol_version
        || message.profile_id != ETDAG_PROFILE_ID
        || message.epoch != context.epoch
        || message.target_height != context.target_height
        || message.target_context_root != context.root()?
        || message.cluster_id != context.assigned_cluster_id
        || message.authorization_root != authorization.root()?
        || message.next_commitment_root != commitment.root()?
        || message.protected_batch_root != batch.protected_batch_root
        || message.parameter_root != context.consensus_parameter_root
        || !batch
            .ordered_transaction_ids
            .contains(&message.tx_commitment)
    {
        return Err("protected reveal share exact binding mismatch".to_string());
    }
    let member = validator_set
        .active_for_epoch(context.epoch)
        .active_for_cluster(context.assigned_cluster_id)
        .into_iter()
        .find(|member| member.validator_id == message.validator_id)
        .ok_or_else(|| "protected reveal share signer is not in cluster".to_string())?;
    if member.consensus_public_key.key_id != message.key_id {
        return Err("protected reveal share key mismatch".to_string());
    }
    let expected = share_commitment(
        &message.validator_id,
        &message.share,
        context.root()?,
        context.target_height,
    )?;
    if expected != message.share_commitment {
        return Err("protected reveal share commitment mismatch".to_string());
    }
    verifier
        .verify_domain_signature(
            DOMAIN_PROTECTED_REVEAL_SHARE,
            &message.unsigned().canonical_bytes()?,
            &member.validator_uma_id.0,
            &message.key_id,
            context.epoch,
            AegisPqKeyRole::ConsensusVote,
            &message.signature,
        )
        .map_err(|error| error.to_string())
}

pub fn protected_reveal_transcript_root(
    shares_by_commitment: &BTreeMap<EtdagDigest, Vec<ProtectedRevealShareMessage>>,
) -> Result<EtdagDigest, String> {
    let mut canonical = Vec::new();
    for (commitment, messages) in shares_by_commitment {
        let mut messages = messages.clone();
        messages.sort_by(|left, right| {
            left.validator_id
                .cmp(&right.validator_id)
                .then_with(|| left.share.index.cmp(&right.share.index))
        });
        if messages
            .iter()
            .any(|message| &message.tx_commitment != commitment)
        {
            return Err("protected reveal transcript map key mismatch".to_string());
        }
        canonical.push((commitment.clone(), messages));
    }
    EtdagDigest::from_canonical(DOMAIN_PROTECTED_REVEAL_TRANSCRIPT, &canonical)
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DecryptShareMessage {
    pub chain_id: ChainId,
    pub network_id: NetworkId,
    pub profile_id: String,
    pub epoch: Epoch,
    pub target_height: Height,
    pub target_context_root: Hash,
    pub cluster_id: ClusterId,
    pub batch_candidate_digest: EtdagDigest,
    pub tx_commitment: EtdagDigest,
    pub validator_id: ValidatorId,
    pub share: ShamirShare,
    pub share_commitment: EtdagDigest,
    pub parameter_root: ConsensusParameterRoot,
    pub key_id: AegisPqKeyId,
    pub signature: AegisPqSignature,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct UnsignedDecryptShare {
    chain_id: ChainId,
    network_id: NetworkId,
    profile_id: String,
    epoch: Epoch,
    target_height: Height,
    target_context_root: Hash,
    cluster_id: ClusterId,
    batch_candidate_digest: EtdagDigest,
    tx_commitment: EtdagDigest,
    validator_id: ValidatorId,
    share: ShamirShare,
    share_commitment: EtdagDigest,
    parameter_root: ConsensusParameterRoot,
    key_id: AegisPqKeyId,
}

impl DecryptShareMessage {
    fn unsigned(&self) -> UnsignedDecryptShare {
        UnsignedDecryptShare {
            chain_id: self.chain_id,
            network_id: self.network_id.clone(),
            profile_id: self.profile_id.clone(),
            epoch: self.epoch,
            target_height: self.target_height,
            target_context_root: self.target_context_root,
            cluster_id: self.cluster_id,
            batch_candidate_digest: self.batch_candidate_digest.clone(),
            tx_commitment: self.tx_commitment.clone(),
            validator_id: self.validator_id.clone(),
            share: self.share.clone(),
            share_commitment: self.share_commitment.clone(),
            parameter_root: self.parameter_root,
            key_id: self.key_id.clone(),
        }
    }
}

pub fn release_decrypt_share(
    signer: &mut AegisPqvmSigner,
    journal: &EtdagSafetyJournal,
    gate: &RevealGate,
    context: &TargetAdmissionContext,
    validator: &ValidatorRecord,
    tx_commitment: EtdagDigest,
    share: ShamirShare,
) -> Result<DecryptShareMessage, String> {
    gate.validate()?;
    context.validate()?;
    share.validate()?;
    if gate.epoch != context.epoch
        || gate.target_height != context.target_height
        || gate.cluster_id != context.assigned_cluster_id
        || gate.target_context_root != context.root()?
    {
        return Err("ETDAG reveal gate context mismatch".to_string());
    }
    let share_commitment = share_commitment(
        &validator.validator_id,
        &share,
        context.root()?,
        context.target_height,
    )?;
    let share_digest = EtdagDigest::from_canonical("PoSy/ETDAG/ReleasedShare/v3", &share)?;
    journal.authorize_decrypt_release(
        gate,
        &validator.validator_id,
        tx_commitment.clone(),
        share_digest,
    )?;
    let mut message = DecryptShareMessage {
        chain_id: context.chain_id,
        network_id: context.network_id.clone(),
        profile_id: ETDAG_PROFILE_ID.to_string(),
        epoch: context.epoch,
        target_height: context.target_height,
        target_context_root: context.root()?,
        cluster_id: context.assigned_cluster_id,
        batch_candidate_digest: gate.batch_candidate_digest.clone(),
        tx_commitment,
        validator_id: validator.validator_id.clone(),
        share,
        share_commitment,
        parameter_root: context.consensus_parameter_root,
        key_id: validator.consensus_public_key.key_id.clone(),
        signature: AegisPqSignature {
            algorithm: String::new(),
            signature_bytes: Vec::new(),
        },
    };
    message.signature = signer
        .sign_domain(
            DOMAIN_DECRYPT_SHARE,
            &message.unsigned().canonical_bytes()?,
            &message.key_id,
        )
        .map_err(|error| error.to_string())?;
    Ok(message)
}

pub fn verify_decrypt_share(
    message: &DecryptShareMessage,
    verifier: &AegisPqvmVerifier,
    context: &TargetAdmissionContext,
    validator_set: &ValidatorSet,
) -> Result<(), String> {
    context.validate()?;
    message.share.validate()?;
    if message.chain_id != context.chain_id
        || message.network_id != context.network_id
        || message.profile_id != ETDAG_PROFILE_ID
        || message.epoch != context.epoch
        || message.target_height != context.target_height
        || message.target_context_root != context.root()?
        || message.cluster_id != context.assigned_cluster_id
        || message.parameter_root != context.consensus_parameter_root
    {
        return Err("ETDAG decrypt share context mismatch".to_string());
    }
    let member = validator_set
        .active_for_epoch(context.epoch)
        .active_for_cluster(context.assigned_cluster_id)
        .into_iter()
        .find(|member| member.validator_id == message.validator_id)
        .ok_or_else(|| "ETDAG decrypt share signer is not in cluster".to_string())?;
    if member.consensus_public_key.key_id != message.key_id {
        return Err("ETDAG decrypt share key mismatch".to_string());
    }
    let expected = share_commitment(
        &message.validator_id,
        &message.share,
        context.root()?,
        context.target_height,
    )?;
    if expected != message.share_commitment {
        return Err("ETDAG decrypt share commitment mismatch".to_string());
    }
    verifier
        .verify_domain_signature(
            DOMAIN_DECRYPT_SHARE,
            &message.unsigned().canonical_bytes()?,
            &member.validator_uma_id.0,
            &message.key_id,
            context.epoch,
            AegisPqKeyRole::ConsensusVote,
            &message.signature,
        )
        .map_err(|error| error.to_string())
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PublicOrderedReveal {
    pub target_height: Height,
    pub batch_candidate_digest: EtdagDigest,
    pub ordered_transactions: Vec<InnerTransactionV2>,
    pub decrypt_share_transcript_root: EtdagDigest,
}

impl PublicOrderedReveal {
    pub fn validate_exact(
        &self,
        batch_candidate: &BatchCandidate,
        envelopes: &BTreeMap<EtdagDigest, EncryptedTransactionEnvelope>,
    ) -> Result<(), String> {
        if self.target_height != batch_candidate.target_height
            || self.batch_candidate_digest != batch_candidate.digest()?
            || self.ordered_transactions.len() != batch_candidate.ordered_commitments.len()
        {
            return Err("public reveal does not match BOC order".to_string());
        }
        for (inner, commitment) in self
            .ordered_transactions
            .iter()
            .zip(batch_candidate.ordered_commitments.iter())
        {
            let envelope = envelopes
                .get(commitment)
                .ok_or_else(|| "public reveal is missing BOC envelope".to_string())?;
            if inner.target_height != batch_candidate.target_height
                || inner.transaction.sender_uma_or_account != envelope.sender_id
                || inner.transaction.account_nonce_or_sequence != envelope.nonce_slot
            {
                return Err("public reveal transaction does not match BOC envelope".to_string());
            }
        }
        self.decrypt_share_transcript_root
            .validate("decrypt share transcript root")
    }

    pub fn validate_cryptographic_exact(
        &self,
        batch_candidate: &BatchCandidate,
        envelopes: &BTreeMap<EtdagDigest, EncryptedTransactionEnvelope>,
        shares_by_commitment: &BTreeMap<EtdagDigest, Vec<DecryptShareMessage>>,
        verifier: &AegisPqvmVerifier,
        context: &TargetAdmissionContext,
        validator_set: &ValidatorSet,
        cluster_map: &ClusterMap,
    ) -> Result<(), String> {
        self.validate_exact(batch_candidate, envelopes)?;
        context.validate_validator_and_cluster_bindings(validator_set, cluster_map)?;
        let expected_commitments = batch_candidate
            .ordered_commitments
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>();
        let supplied_commitments = shares_by_commitment
            .keys()
            .cloned()
            .collect::<BTreeSet<_>>();
        if supplied_commitments != expected_commitments {
            return Err("public reveal share set does not match exact BOC set".to_string());
        }
        let threshold = decryption_threshold(context.assigned_cluster_validator_count as usize)?;
        for (revealed_inner, commitment) in self
            .ordered_transactions
            .iter()
            .zip(batch_candidate.ordered_commitments.iter())
        {
            let envelope = envelopes
                .get(commitment)
                .ok_or_else(|| "public reveal is missing BOC envelope".to_string())?;
            let messages = shares_by_commitment
                .get(commitment)
                .ok_or_else(|| "public reveal is missing decrypt-share transcript".to_string())?;
            let mut validator_ids = BTreeSet::new();
            let mut share_indices = BTreeSet::new();
            for message in messages {
                if message.batch_candidate_digest != batch_candidate.digest()?
                    || &message.tx_commitment != commitment
                {
                    return Err("decrypt share is not bound to exact BOC transaction".to_string());
                }
                if !validator_ids.insert(message.validator_id.clone())
                    || !share_indices.insert(message.share.index)
                {
                    return Err("public reveal contains duplicate decrypt shares".to_string());
                }
                verify_decrypt_share(message, verifier, context, validator_set)?;
            }
            if messages.len() < threshold {
                return Err("public reveal has insufficient threshold decrypt shares".to_string());
            }
            let shares = messages
                .iter()
                .map(|message| message.share.clone())
                .collect::<Vec<_>>();
            let decrypted = decrypt_inner_transaction(envelope, &shares, threshold)?;
            if &decrypted != revealed_inner {
                return Err(
                    "public reveal plaintext is not the authenticated ciphertext plaintext"
                        .to_string(),
                );
            }
        }
        let computed_root = decrypt_share_transcript_root(shares_by_commitment)?;
        if computed_root != self.decrypt_share_transcript_root {
            return Err("public reveal decrypt-share transcript root mismatch".to_string());
        }
        Ok(())
    }
}

pub fn decrypt_share_transcript_root(
    shares_by_commitment: &BTreeMap<EtdagDigest, Vec<DecryptShareMessage>>,
) -> Result<EtdagDigest, String> {
    let mut canonical = Vec::new();
    for (commitment, messages) in shares_by_commitment {
        let mut messages = messages.clone();
        messages.sort_by(|left, right| {
            left.validator_id
                .cmp(&right.validator_id)
                .then_with(|| left.share.index.cmp(&right.share.index))
        });
        if messages
            .iter()
            .any(|message| &message.tx_commitment != commitment)
        {
            return Err("decrypt-share transcript map key mismatch".to_string());
        }
        canonical.push((commitment.clone(), messages));
    }
    EtdagDigest::from_canonical("PoSy/ETDAG/PublicDecryptShareTranscript/v3", &canonical)
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProtectedBlockInput {
    pub dcc: DagCutCertificate,
    pub boc: BatchOrderCertificate,
    pub reveal: PublicOrderedReveal,
    pub epoch_randomness: Hash,
    pub certified_vertices: BTreeMap<EtdagDigest, CertifiedVertex>,
    pub envelopes: BTreeMap<EtdagDigest, EncryptedTransactionEnvelope>,
    pub decrypt_shares: BTreeMap<EtdagDigest, Vec<DecryptShareMessage>>,
}

impl ProtectedBlockInput {
    /// Stable digest used by schedule-neutral protected-material stores.
    /// Verification remains mandatory before this digest gains authority.
    pub fn digest(&self) -> Result<EtdagDigest, String> {
        protected_input_digest(self)
    }

    pub fn verify_and_extract_transactions(
        &self,
        verifier: &AegisPqvmVerifier,
        context: &TargetAdmissionContext,
        validator_set: &ValidatorSet,
        cluster_map: &ClusterMap,
        parameters: &EtdagParameters,
    ) -> Result<Vec<Transaction>, String> {
        parameters.validate()?;
        let rebuilt_cut = build_dag_cut_candidate(
            context,
            &self.certified_vertices,
            &self.dcc.candidate.cutoff_marker_digests,
            verifier,
            validator_set,
            cluster_map,
        )?;
        if rebuilt_cut != self.dcc.candidate {
            return Err(
                "protected proposal DCC is not the complete verified causal union".to_string(),
            );
        }
        self.dcc
            .verify(verifier, context, validator_set, cluster_map)?;
        self.boc
            .verify(verifier, context, validator_set, cluster_map)?;
        let batch = &self.boc.bvc.batch_candidate;
        batch.validate(&self.dcc.candidate)?;
        let rebuilt_batch = build_batch_candidate(
            &self.dcc.candidate,
            batch.canonical_finality_context_digest.clone(),
            self.epoch_randomness,
            parameters,
        )?;
        if &rebuilt_batch != batch {
            return Err(
                "protected proposal batch is not the deterministic DCC-derived order".to_string(),
            );
        }

        let eligible = self
            .dcc
            .candidate
            .eligible_envelopes
            .iter()
            .map(|reference| (reference.tx_commitment.clone(), reference))
            .collect::<BTreeMap<_, _>>();
        if self.envelopes.keys().cloned().collect::<BTreeSet<_>>()
            != eligible.keys().cloned().collect::<BTreeSet<_>>()
        {
            return Err("protected proposal envelope set does not match exact DCC set".to_string());
        }
        for (commitment, envelope) in &self.envelopes {
            if &envelope.tx_commitment != commitment {
                return Err("protected proposal envelope map key mismatch".to_string());
            }
            envelope.validate_structure(context, parameters)?;
            envelope.verify_outer_signature(verifier)?;
            let reference = eligible
                .get(commitment)
                .ok_or_else(|| "protected proposal contains non-DCC envelope".to_string())?;
            if envelope.sender_id != reference.sender_id
                || envelope.nonce_slot != reference.nonce_slot
                || envelope.ciphertext.len() as u64 != reference.ciphertext_bytes
                || envelope.gas_class as u64 != reference.gas_class_units
                || envelope.fee_class != reference.fee_class
            {
                return Err("protected proposal envelope does not match DCC metadata".to_string());
            }
        }
        self.reveal.validate_cryptographic_exact(
            batch,
            &self.envelopes,
            &self.decrypt_shares,
            verifier,
            context,
            validator_set,
            cluster_map,
        )?;
        let transactions = self
            .reveal
            .ordered_transactions
            .iter()
            .map(|inner| inner.transaction.clone())
            .collect::<Vec<_>>();
        for transaction in &transactions {
            verifier
                .verify_transaction_signature_checked(transaction)
                .map_err(|error| error.to_string())?;
        }
        Ok(transactions)
    }

    pub fn build_execution_manifest(
        &self,
        transactions: &[Transaction],
        receipts: &[crate::execution::TransactionReceipt],
    ) -> Result<ExecutionManifest, String> {
        let batch = &self.boc.bvc.batch_candidate;
        if transactions.len() != batch.ordered_commitments.len()
            || receipts.len() != transactions.len()
        {
            return Err("protected execution result length does not match BOC".to_string());
        }
        let mut entries = Vec::with_capacity(transactions.len());
        for (index, ((transaction, receipt), commitment)) in transactions
            .iter()
            .zip(receipts.iter())
            .zip(batch.ordered_commitments.iter())
            .enumerate()
        {
            let transaction_hash = Hash::from_domain_bytes(
                "SYNERGY_EXECUTION_TX_ID_V1",
                &transaction.canonical_bytes()?,
            );
            if receipt.tx_id != crate::synergy_types::TxId::from_hash(transaction_hash) {
                return Err("protected execution receipt transaction ID mismatch".to_string());
            }
            let disposition = match receipt.status {
                crate::execution::ReceiptStatus::Success => ExecutionDisposition::Executed,
                crate::execution::ReceiptStatus::Failed => ExecutionDisposition::Reverted,
            };
            entries.push(ExecutionManifestEntry {
                index: index as u64,
                tx_commitment: commitment.clone(),
                disposition,
                transaction_hash: Some(transaction_hash),
                receipt_hash: Some(Hash::from_domain_bytes(
                    "SYNERGY_ETDAG_RECEIPT_V2",
                    &receipt.canonical_bytes()?,
                )),
            });
        }
        let manifest = ExecutionManifest {
            target_height: batch.target_height,
            batch_candidate_digest: batch.digest()?,
            entries,
        };
        manifest.validate_exact(batch)?;
        Ok(manifest)
    }

    pub fn protected_batch_commitment(
        &self,
        manifest: &ExecutionManifest,
        receipts: &[crate::execution::TransactionReceipt],
    ) -> Result<ProtectedBatchCommitment, String> {
        let batch = &self.boc.bvc.batch_candidate;
        manifest.validate_exact(batch)?;
        let protected_gas_total = receipts.iter().try_fold(0u64, |sum, receipt| {
            sum.checked_add(receipt.gas_used)
                .ok_or_else(|| "protected execution gas total overflow".to_string())
        })?;
        let commitment = ProtectedBatchCommitment {
            profile_id: ETDAG_PROFILE_ID.to_string(),
            target_context_root: self.dcc.candidate.target_context_root.to_hex(),
            boc_digest: self.boc.digest()?.0,
            dcc_digest: self.dcc.digest()?.0,
            encrypted_set_root: self.dcc.candidate.eligible_commitment_root.0.clone(),
            protected_order_root: batch.ordered_commitment_root.0.clone(),
            public_reveal_transcript_root: EtdagDigest::from_canonical(
                "PoSy/ETDAG/PublicOrderedReveal/v3",
                &self.reveal,
            )?
            .0,
            execution_manifest_root: manifest.root()?.0,
            protected_gas_total,
            protected_count: batch.ordered_commitments.len() as u64,
        };
        validate_protected_batch_commitment(&commitment)?;
        Ok(commitment)
    }
}

pub fn validate_protected_batch_commitment(
    commitment: &ProtectedBatchCommitment,
) -> Result<(), String> {
    if commitment.profile_id != ETDAG_PROFILE_ID {
        return Err("block protected-batch profile mismatch".to_string());
    }
    if Hash::from_hex(&commitment.target_context_root)?.is_zero() {
        return Err("block protected-batch target context root is zero".to_string());
    }
    for (name, digest) in [
        ("BOC digest", &commitment.boc_digest),
        ("DCC digest", &commitment.dcc_digest),
        ("encrypted set root", &commitment.encrypted_set_root),
        ("protected order root", &commitment.protected_order_root),
        (
            "public reveal transcript root",
            &commitment.public_reveal_transcript_root,
        ),
        (
            "execution manifest root",
            &commitment.execution_manifest_root,
        ),
    ] {
        let digest = EtdagDigest(digest.clone());
        digest.validate(name)?;
        if digest.is_zero() {
            return Err(format!("{name} cannot be zero"));
        }
    }
    Ok(())
}

/// Durable record of a fully verified ETDAG proposal input.
///
/// This is deliberately *not* a general ETDAG gossip cache.  A record can be
/// created only after the complete public proof package has been verified
/// against a certified H+3 admission package and the immutable consensus
/// context for the target height.  In particular, this boundary never creates
/// transactions, signatures, certificates, shares, or plaintext itself.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct EtdagProtectedInputStoreEntry {
    target_admission_package_digest: EtdagDigest,
    canonical_finality_context_digest: EtdagDigest,
    protected_input: ProtectedBlockInput,
    protected_input_digest: EtdagDigest,
    serialized_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct EtdagProtectedInputStoreFile {
    format: String,
    entries: BTreeMap<Height, EtdagProtectedInputStoreEntry>,
}

impl Default for EtdagProtectedInputStoreFile {
    fn default() -> Self {
        Self {
            format: ETDAG_PROTECTED_INPUT_STORE_FORMAT.to_string(),
            entries: BTreeMap::new(),
        }
    }
}

static ETDAG_PROTECTED_INPUT_STORE_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

/// Internal durable storage for verified public ETDAG proof packages.
///
/// The public API is [`EtdagProtectedInputCoordinator`].  Keeping the raw
/// store private prevents a caller from treating persistence as verification.
#[derive(Debug, Clone)]
struct EtdagProtectedInputStore {
    path: PathBuf,
}

impl EtdagProtectedInputStore {
    fn process_wide() -> Self {
        Self::at_path(crate::utils::resolve_data_path(&format!(
            "data/{ETDAG_PROTECTED_INPUT_STORE_FILE}"
        )))
    }

    fn at_path(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    fn install_verified(
        &self,
        target_admission_package_digest: EtdagDigest,
        protected_input: &ProtectedBlockInput,
        target_context: &TargetAdmissionContext,
        height_context: &HeightConsensusContext,
        expected_finality_context_digest: &EtdagDigest,
        verifier: &AegisPqvmVerifier,
        validator_set: &ValidatorSet,
        cluster_map: &ClusterMap,
        parameters: &EtdagParameters,
    ) -> Result<EtdagDigest, String> {
        verify_certified_protected_input(
            protected_input,
            target_context,
            height_context,
            expected_finality_context_digest,
            verifier,
            validator_set,
            cluster_map,
            parameters,
        )?;
        self.install_verified_entry(
            target_admission_package_digest,
            protected_input,
            height_context.height,
            expected_finality_context_digest,
        )
    }

    fn install_verified_schedule_neutral(
        &self,
        target_admission_package_digest: EtdagDigest,
        protected_input: &ProtectedBlockInput,
        target_context: &TargetAdmissionContext,
        expected_finality_context_digest: &EtdagDigest,
        verifier: &AegisPqvmVerifier,
        validator_set: &ValidatorSet,
        cluster_map: &ClusterMap,
        parameters: &EtdagParameters,
    ) -> Result<EtdagDigest, String> {
        verify_certified_protected_input_schedule_neutral(
            protected_input,
            target_context,
            expected_finality_context_digest,
            verifier,
            validator_set,
            cluster_map,
            parameters,
        )?;
        self.install_verified_entry(
            target_admission_package_digest,
            protected_input,
            target_context.target_height,
            expected_finality_context_digest,
        )
    }

    fn install_verified_entry(
        &self,
        target_admission_package_digest: EtdagDigest,
        protected_input: &ProtectedBlockInput,
        height: Height,
        expected_finality_context_digest: &EtdagDigest,
    ) -> Result<EtdagDigest, String> {
        target_admission_package_digest.validate("target admission package digest")?;
        if target_admission_package_digest.is_zero() {
            return Err("ETDAG_PROTECTED_INPUT_MISSING_ADMISSION_PACKAGE".to_string());
        }
        let protected_input_digest = protected_input_digest(protected_input)?;
        let serialized_bytes = protected_input_serialized_bytes(protected_input)?;
        if serialized_bytes > MAX_ETDAG_PROTECTED_INPUT_STORE_SERIALIZED_BYTES as u64 {
            return Err("ETDAG_PROTECTED_INPUT_STORE_ENTRY_TOO_LARGE".to_string());
        }
        let entry = EtdagProtectedInputStoreEntry {
            target_admission_package_digest,
            canonical_finality_context_digest: expected_finality_context_digest.clone(),
            protected_input: protected_input.clone(),
            protected_input_digest: protected_input_digest.clone(),
            serialized_bytes,
        };

        let _guard = ETDAG_PROTECTED_INPUT_STORE_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .map_err(|_| "ETDAG protected-input store lock poisoned".to_string())?;
        let mut store = self.load_unlocked()?;
        if let Some(existing) = store.entries.get(&height) {
            if existing == &entry {
                return Ok(protected_input_digest);
            }
            return Err("ETDAG_PROTECTED_INPUT_CONFLICT".to_string());
        }
        if store.entries.len() >= MAX_ETDAG_PROTECTED_INPUT_STORE_ENTRIES {
            return Err("ETDAG_PROTECTED_INPUT_STORE_FULL".to_string());
        }
        let current_bytes = store.entries.values().try_fold(0u64, |total, existing| {
            total
                .checked_add(existing.serialized_bytes)
                .ok_or_else(|| "ETDAG protected-input store byte accounting overflow".to_string())
        })?;
        let next_bytes = current_bytes
            .checked_add(serialized_bytes)
            .ok_or_else(|| "ETDAG protected-input store byte accounting overflow".to_string())?;
        if next_bytes > MAX_ETDAG_PROTECTED_INPUT_STORE_SERIALIZED_BYTES as u64 {
            return Err("ETDAG_PROTECTED_INPUT_STORE_FULL".to_string());
        }
        store.entries.insert(height, entry);
        self.persist_unlocked(&store)?;
        Ok(protected_input_digest)
    }

    fn load_verified(
        &self,
        target_admission_package_digest: &EtdagDigest,
        target_context: &TargetAdmissionContext,
        height_context: &HeightConsensusContext,
        expected_finality_context_digest: &EtdagDigest,
        verifier: &AegisPqvmVerifier,
        validator_set: &ValidatorSet,
        cluster_map: &ClusterMap,
        parameters: &EtdagParameters,
    ) -> Result<ProtectedBlockInput, String> {
        let _guard = ETDAG_PROTECTED_INPUT_STORE_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .map_err(|_| "ETDAG protected-input store lock poisoned".to_string())?;
        let store = self.load_unlocked()?;
        let entry = store.entries.get(&height_context.height).ok_or_else(|| {
            "ETDAG_PROTECTED_INPUT_NOT_READY: no verified protected input for target height"
                .to_string()
        })?;
        if &entry.target_admission_package_digest != target_admission_package_digest
            || &entry.canonical_finality_context_digest != expected_finality_context_digest
        {
            return Err("ETDAG_PROTECTED_INPUT_CONTEXT_MISMATCH".to_string());
        }
        verify_protected_input_store_entry(height_context.height, entry)?;
        verify_certified_protected_input(
            &entry.protected_input,
            target_context,
            height_context,
            expected_finality_context_digest,
            verifier,
            validator_set,
            cluster_map,
            parameters,
        )?;
        Ok(entry.protected_input.clone())
    }

    fn load_verified_schedule_neutral(
        &self,
        target_admission_package_digest: &EtdagDigest,
        target_context: &TargetAdmissionContext,
        expected_finality_context_digest: &EtdagDigest,
        verifier: &AegisPqvmVerifier,
        validator_set: &ValidatorSet,
        cluster_map: &ClusterMap,
        parameters: &EtdagParameters,
    ) -> Result<ProtectedBlockInput, String> {
        let _guard = ETDAG_PROTECTED_INPUT_STORE_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .map_err(|_| "ETDAG protected-input store lock poisoned".to_string())?;
        let store = self.load_unlocked()?;
        let entry = store
            .entries
            .get(&target_context.target_height)
            .ok_or_else(|| {
                "ETDAG_PROTECTED_INPUT_NOT_READY: no verified protected input for target height"
                    .to_string()
            })?;
        if &entry.target_admission_package_digest != target_admission_package_digest
            || &entry.canonical_finality_context_digest != expected_finality_context_digest
        {
            return Err("ETDAG_PROTECTED_INPUT_CONTEXT_MISMATCH".to_string());
        }
        verify_protected_input_store_entry(target_context.target_height, entry)?;
        verify_certified_protected_input_schedule_neutral(
            &entry.protected_input,
            target_context,
            expected_finality_context_digest,
            verifier,
            validator_set,
            cluster_map,
            parameters,
        )?;
        Ok(entry.protected_input.clone())
    }

    fn remove_finalized(&self, height: Height) -> Result<bool, String> {
        let _guard = ETDAG_PROTECTED_INPUT_STORE_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .map_err(|_| "ETDAG protected-input store lock poisoned".to_string())?;
        let mut store = self.load_unlocked()?;
        let removed = store.entries.remove(&height).is_some();
        if removed {
            self.persist_unlocked(&store)?;
        }
        Ok(removed)
    }

    fn load_unlocked(&self) -> Result<EtdagProtectedInputStoreFile, String> {
        if !self.path.exists() {
            return Ok(EtdagProtectedInputStoreFile::default());
        }
        let bytes = fs::read(&self.path).map_err(|error| {
            format!(
                "read ETDAG protected-input store {}: {error}",
                self.path.display()
            )
        })?;
        if bytes.len() > MAX_ETDAG_PROTECTED_INPUT_STORE_SERIALIZED_BYTES {
            return Err("ETDAG protected-input store exceeds bounded size".to_string());
        }
        let store: EtdagProtectedInputStoreFile =
            serde_json::from_slice(&bytes).map_err(|error| {
                format!(
                    "parse ETDAG protected-input store {}: {error}",
                    self.path.display()
                )
            })?;
        if store.format != ETDAG_PROTECTED_INPUT_STORE_FORMAT
            || store.entries.len() > MAX_ETDAG_PROTECTED_INPUT_STORE_ENTRIES
        {
            return Err("unsupported or corrupt ETDAG protected-input store".to_string());
        }
        let mut bytes_accounted = 0u64;
        for (height, entry) in &store.entries {
            verify_protected_input_store_entry(*height, entry)?;
            bytes_accounted = bytes_accounted
                .checked_add(entry.serialized_bytes)
                .ok_or_else(|| {
                    "ETDAG protected-input store byte accounting overflow".to_string()
                })?;
        }
        if bytes_accounted > MAX_ETDAG_PROTECTED_INPUT_STORE_SERIALIZED_BYTES as u64 {
            return Err("ETDAG protected-input store exceeds bounded size".to_string());
        }
        Ok(store)
    }

    fn persist_unlocked(&self, store: &EtdagProtectedInputStoreFile) -> Result<(), String> {
        let parent = self
            .path
            .parent()
            .ok_or_else(|| "ETDAG protected-input store path has no parent".to_string())?;
        fs::create_dir_all(parent)
            .map_err(|error| format!("create ETDAG protected-input directory: {error}"))?;
        let file_name = self
            .path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| "ETDAG protected-input store has no file name".to_string())?;
        let temporary = parent.join(format!(".{file_name}.tmp"));
        let bytes = serde_json::to_vec_pretty(store)
            .map_err(|error| format!("serialize ETDAG protected-input store: {error}"))?;
        if bytes.len() > MAX_ETDAG_PROTECTED_INPUT_STORE_SERIALIZED_BYTES {
            return Err("ETDAG protected-input store exceeds bounded size".to_string());
        }
        {
            let mut file = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(&temporary)
                .map_err(|error| format!("create ETDAG protected-input temp file: {error}"))?;
            file.write_all(&bytes)
                .map_err(|error| format!("write ETDAG protected-input store: {error}"))?;
            file.sync_all()
                .map_err(|error| format!("fsync ETDAG protected-input store: {error}"))?;
        }
        fs::rename(&temporary, &self.path)
            .map_err(|error| format!("replace ETDAG protected-input store: {error}"))?;
        #[cfg(unix)]
        {
            let directory = OpenOptions::new()
                .read(true)
                .open(parent)
                .map_err(|error| format!("open ETDAG protected-input directory: {error}"))?;
            directory
                .sync_all()
                .map_err(|error| format!("fsync ETDAG protected-input directory: {error}"))
        }
        #[cfg(not(unix))]
        {
            Ok(())
        }
    }
}

fn protected_input_digest(protected_input: &ProtectedBlockInput) -> Result<EtdagDigest, String> {
    EtdagDigest::from_canonical(
        "PoSy/ETDAG/CertifiedProtectedBlockInput/v3",
        protected_input,
    )
}

fn protected_input_serialized_bytes(protected_input: &ProtectedBlockInput) -> Result<u64, String> {
    u64::try_from(
        serde_json::to_vec(protected_input)
            .map_err(|error| format!("serialize ETDAG protected input for bounds: {error}"))?
            .len(),
    )
    .map_err(|_| "ETDAG protected-input serialized length exceeds u64".to_string())
}

fn verify_protected_input_store_entry(
    height: Height,
    entry: &EtdagProtectedInputStoreEntry,
) -> Result<(), String> {
    entry
        .target_admission_package_digest
        .validate("target admission package digest")?;
    entry
        .canonical_finality_context_digest
        .validate("canonical finality context digest")?;
    if entry.target_admission_package_digest.is_zero()
        || entry.canonical_finality_context_digest.is_zero()
        || entry.protected_input_digest.is_zero()
    {
        return Err("ETDAG protected-input store has an empty proof binding".to_string());
    }
    entry
        .protected_input_digest
        .validate("protected input digest")?;
    if entry.protected_input.boc.bvc.batch_candidate.target_height != height
        || entry.protected_input.dcc.candidate.target_height != height
        || entry.protected_input.reveal.target_height != height
        || entry
            .protected_input
            .boc
            .bvc
            .batch_candidate
            .canonical_finality_context_digest
            != entry.canonical_finality_context_digest
        || protected_input_digest(&entry.protected_input)? != entry.protected_input_digest
        || protected_input_serialized_bytes(&entry.protected_input)? != entry.serialized_bytes
    {
        return Err("ETDAG protected-input store entry integrity mismatch".to_string());
    }
    if entry.serialized_bytes > MAX_ETDAG_PROTECTED_INPUT_STORE_SERIALIZED_BYTES as u64 {
        return Err("ETDAG protected-input store entry exceeds bounded size".to_string());
    }
    Ok(())
}

fn verify_certified_protected_input(
    protected_input: &ProtectedBlockInput,
    target_context: &TargetAdmissionContext,
    height_context: &HeightConsensusContext,
    expected_finality_context_digest: &EtdagDigest,
    verifier: &AegisPqvmVerifier,
    validator_set: &ValidatorSet,
    cluster_map: &ClusterMap,
    parameters: &EtdagParameters,
) -> Result<(), String> {
    target_context.validate_height_context_compatibility(height_context)?;
    expected_finality_context_digest.validate("expected canonical finality context digest")?;
    if expected_finality_context_digest.is_zero() {
        return Err("ETDAG_PROTECTED_INPUT_MISSING_FINALITY_CONTEXT".to_string());
    }
    if protected_input
        .boc
        .bvc
        .batch_candidate
        .canonical_finality_context_digest
        != *expected_finality_context_digest
    {
        return Err("ETDAG_PROTECTED_INPUT_FINALITY_CONTEXT_MISMATCH".to_string());
    }
    protected_input
        .verify_and_extract_transactions(
            verifier,
            target_context,
            validator_set,
            cluster_map,
            parameters,
        )
        .map(|_| ())
}

fn verify_certified_protected_input_schedule_neutral(
    protected_input: &ProtectedBlockInput,
    target_context: &TargetAdmissionContext,
    expected_finality_context_digest: &EtdagDigest,
    verifier: &AegisPqvmVerifier,
    validator_set: &ValidatorSet,
    cluster_map: &ClusterMap,
    parameters: &EtdagParameters,
) -> Result<(), String> {
    target_context.validate_validator_and_cluster_bindings(validator_set, cluster_map)?;
    expected_finality_context_digest.validate("expected canonical finality context digest")?;
    if expected_finality_context_digest.is_zero() {
        return Err("ETDAG_PROTECTED_INPUT_MISSING_FINALITY_CONTEXT".to_string());
    }
    let target_height = target_context.target_height;
    if protected_input.dcc.candidate.target_height != target_height
        || protected_input.boc.bvc.batch_candidate.target_height != target_height
        || protected_input.reveal.target_height != target_height
    {
        return Err("ETDAG_PROTECTED_INPUT_TARGET_HEIGHT_MISMATCH".to_string());
    }
    if protected_input
        .boc
        .bvc
        .batch_candidate
        .canonical_finality_context_digest
        != *expected_finality_context_digest
    {
        return Err("ETDAG_PROTECTED_INPUT_FINALITY_CONTEXT_MISMATCH".to_string());
    }
    protected_input
        .verify_and_extract_transactions(
            verifier,
            target_context,
            validator_set,
            cluster_map,
            parameters,
        )
        .map(|_| ())
}

/// Complete, public ETDAG proof material that may be relayed between
/// authenticated Testnet-v3 validators.
///
/// The local node's height context and finalized-consensus digest are
/// deliberately *not* wire fields.  A remote peer therefore cannot choose the
/// consensus state under which its proof package is evaluated.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CertifiedProtectedInputArtifact {
    pub admission_package: TargetAdmissionPackage,
    pub protected_input: ProtectedBlockInput,
}

impl CertifiedProtectedInputArtifact {
    pub fn validate_wire_size(&self) -> Result<(), String> {
        let serialized = serde_json::to_vec(self)
            .map_err(|error| format!("serialize certified ETDAG input artifact: {error}"))?;
        if serialized.len() > MAX_ETDAG_CERTIFIED_INPUT_WIRE_BYTES {
            return Err(format!(
                "ETDAG_CERTIFIED_INPUT_WIRE_TOO_LARGE: {} bytes exceeds {} byte limit",
                serialized.len(),
                MAX_ETDAG_CERTIFIED_INPUT_WIRE_BYTES
            ));
        }
        Ok(())
    }
}

/// Validator identity supplied only after a Genesis-bound P2P handshake.
/// Socket addresses are intentionally absent: network locations are mutable
/// and cannot authorize durable ETDAG ingress.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EtdagAuthenticatedIngressPeer {
    pub validator_id: ValidatorId,
    pub validator_uma_id: UmaId,
    pub consensus_key_id: AegisPqKeyId,
}

/// Immutable local authority used to validate one target-height's certified
/// protected ETDAG input received from the network.
///
/// This is an ingress boundary, not a scheduler.  It accepts an artifact only
/// from an authenticated active validator and always evaluates the artifact
/// against the locally installed height context and finality digest.
#[derive(Debug, Clone)]
pub struct EtdagCertifiedInputIngress {
    coordinator: EtdagProtectedInputCoordinator,
    height_context: HeightConsensusContext,
    expected_finality_context_digest: EtdagDigest,
    verifier: AegisPqvmVerifier,
    validator_set: ValidatorSet,
    cluster_map: ClusterMap,
    protocol_config: ProtocolConfig,
    parameters: EtdagParameters,
}

impl EtdagCertifiedInputIngress {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        coordinator: EtdagProtectedInputCoordinator,
        height_context: HeightConsensusContext,
        expected_finality_context_digest: EtdagDigest,
        verifier: AegisPqvmVerifier,
        validator_set: ValidatorSet,
        cluster_map: ClusterMap,
        protocol_config: ProtocolConfig,
        parameters: EtdagParameters,
    ) -> Result<Self, String> {
        height_context.validate_against(&validator_set, &cluster_map, &protocol_config)?;
        expected_finality_context_digest.validate("ETDAG ingress finality context digest")?;
        if expected_finality_context_digest.is_zero() {
            return Err("ETDAG_PROTECTED_INPUT_MISSING_FINALITY_CONTEXT".to_string());
        }
        parameters.validate()?;
        Ok(Self {
            coordinator,
            height_context,
            expected_finality_context_digest,
            verifier,
            validator_set,
            cluster_map,
            protocol_config,
            parameters,
        })
    }

    fn authorize_peer(&self, peer: &EtdagAuthenticatedIngressPeer) -> Result<(), String> {
        let validator = self
            .validator_set
            .validators
            .iter()
            .find(|validator| validator.validator_id == peer.validator_id)
            .ok_or_else(|| "ETDAG_CERTIFIED_INPUT_UNTRUSTED_PEER".to_string())?;
        if validator.status != ValidatorStatus::Active
            || !validator.is_active_for_epoch(self.height_context.epoch)
            || validator.validator_uma_id != peer.validator_uma_id
            || validator.consensus_public_key.key_id != peer.consensus_key_id
        {
            return Err("ETDAG_CERTIFIED_INPUT_UNTRUSTED_PEER".to_string());
        }
        Ok(())
    }

    /// Validates and durably admits a complete certified ETDAG artifact.
    ///
    /// The artifact is checked before it reaches durable protected-input
    /// storage.  The coordinator still cryptographically verifies every
    /// certificate, encrypted/revealed transaction, and local context binding.
    pub fn admit_from_authenticated_peer(
        &self,
        peer: &EtdagAuthenticatedIngressPeer,
        artifact: &CertifiedProtectedInputArtifact,
    ) -> Result<EtdagDigest, String> {
        artifact.validate_wire_size()?;
        self.authorize_peer(peer)?;
        if artifact.admission_package.context.target_height != self.height_context.height {
            return Err("ETDAG_PROTECTED_INPUT_TARGET_HEIGHT_MISMATCH".to_string());
        }
        artifact
            .admission_package
            .context
            .validate_height_context_compatibility(&self.height_context)?;
        self.coordinator.admit_certified_public_input(
            &artifact.admission_package,
            &artifact.protected_input,
            &self.height_context,
            &self.expected_finality_context_digest,
            &self.verifier,
            &self.validator_set,
            &self.cluster_map,
            &self.protocol_config,
            &self.parameters,
        )
    }
}

/// Finalized-chain authority used by schedule-neutral ETDAG ingress.
/// Implementations must reject a target context whose source-finality fields
/// do not equal their current durable finalized state.
pub trait EtdagScheduleNeutralFinalityAuthority: Send + Sync {
    fn canonical_finality_context_digest(
        &self,
        target_context: &TargetAdmissionContext,
    ) -> Result<EtdagDigest, String>;
}

/// Authenticated ETDAG ingress for consensus protocols whose scheduling is
/// not represented by [`HeightConsensusContext`].
pub struct EtdagScheduleNeutralCertifiedInputIngress {
    coordinator: EtdagProtectedInputCoordinator,
    finality_authority: Arc<dyn EtdagScheduleNeutralFinalityAuthority>,
    verifier: AegisPqvmVerifier,
    validator_set: ValidatorSet,
    cluster_map: ClusterMap,
    consensus_parameter_root: ConsensusParameterRoot,
    parameters: EtdagParameters,
}

impl EtdagScheduleNeutralCertifiedInputIngress {
    pub fn new(
        coordinator: EtdagProtectedInputCoordinator,
        finality_authority: Arc<dyn EtdagScheduleNeutralFinalityAuthority>,
        verifier: AegisPqvmVerifier,
        validator_set: ValidatorSet,
        cluster_map: ClusterMap,
        consensus_parameter_root: ConsensusParameterRoot,
        parameters: EtdagParameters,
    ) -> Result<Self, String> {
        let active = validator_set.active_for_epoch(validator_set.epoch);
        active.validate_unique_validator_and_key_ids()?;
        if active.validators.is_empty()
            || cluster_map.epoch != validator_set.epoch
            || cluster_map != cluster_map.canonicalized()
            || consensus_parameter_root.is_zero()
        {
            return Err("invalid schedule-neutral ETDAG ingress authority".to_string());
        }
        cluster_map.validate_complete_balanced_assignment(&active)?;
        parameters.validate()?;
        Ok(Self {
            coordinator,
            finality_authority,
            verifier,
            validator_set,
            cluster_map,
            consensus_parameter_root,
            parameters,
        })
    }

    fn authorize_peer(&self, peer: &EtdagAuthenticatedIngressPeer) -> Result<(), String> {
        let validator = self
            .validator_set
            .validators
            .iter()
            .find(|validator| validator.validator_id == peer.validator_id)
            .ok_or_else(|| "ETDAG_CERTIFIED_INPUT_UNTRUSTED_PEER".to_string())?;
        if validator.status != ValidatorStatus::Active
            || !validator.is_active_for_epoch(self.validator_set.epoch)
            || validator.validator_uma_id != peer.validator_uma_id
            || validator.consensus_public_key.key_id != peer.consensus_key_id
        {
            return Err("ETDAG_CERTIFIED_INPUT_UNTRUSTED_PEER".to_string());
        }
        Ok(())
    }

    pub fn admit_from_authenticated_peer(
        &self,
        peer: &EtdagAuthenticatedIngressPeer,
        artifact: &CertifiedProtectedInputArtifact,
    ) -> Result<EtdagDigest, String> {
        artifact.validate_wire_size()?;
        self.authorize_peer(peer)?;
        artifact.admission_package.verify_against_parameter_root(
            &self.verifier,
            &self.validator_set,
            &self.cluster_map,
            self.consensus_parameter_root,
        )?;
        let finality_digest = self
            .finality_authority
            .canonical_finality_context_digest(&artifact.admission_package.context)?;
        self.coordinator
            .admit_certified_public_input_schedule_neutral(
                &artifact.admission_package,
                &artifact.protected_input,
                &finality_digest,
                &self.verifier,
                &self.validator_set,
                &self.cluster_map,
                self.consensus_parameter_root,
                &self.parameters,
            )
    }
}

enum InstalledEtdagCertifiedInputIngress {
    Typed(EtdagCertifiedInputIngress),
    ScheduleNeutral(EtdagScheduleNeutralCertifiedInputIngress),
}

static CERTIFIED_INPUT_INGRESS: OnceLock<Mutex<Option<InstalledEtdagCertifiedInputIngress>>> =
    OnceLock::new();

fn certified_input_ingress_slot() -> &'static Mutex<Option<InstalledEtdagCertifiedInputIngress>> {
    CERTIFIED_INPUT_INGRESS.get_or_init(|| Mutex::new(None))
}

/// Reports whether this process has an activation-permitted, authenticated
/// ETDAG ingress authority for its current typed-consensus height.  Public RPC
/// uses this only as an availability gate; it grants no admission authority
/// and exposes no private ETDAG material.
pub fn etdag_certified_input_ingress_is_active() -> bool {
    certified_input_ingress_slot()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .is_some()
}

/// Installs the one local ETDAG certified-input ingress authority for the
/// current validator lifecycle.  Replacing it is prohibited because that
/// would permit a network package to be evaluated under two different local
/// height/finality contexts.
pub(crate) fn install_etdag_certified_input_ingress(
    _activation_permit: EtdagActivationPermit,
    ingress: EtdagCertifiedInputIngress,
) -> Result<(), String> {
    let mut slot = certified_input_ingress_slot()
        .lock()
        .map_err(|_| "ETDAG certified-input ingress lock is poisoned".to_string())?;
    if slot.is_some() {
        return Err("ETDAG certified-input ingress is already installed".to_string());
    }
    *slot = Some(InstalledEtdagCertifiedInputIngress::Typed(ingress));
    Ok(())
}

/// Install a finalized-manifest-permitted schedule-neutral ingress authority.
pub(crate) fn install_schedule_neutral_etdag_certified_input_ingress(
    _activation_permit: EtdagActivationPermit,
    ingress: EtdagScheduleNeutralCertifiedInputIngress,
) -> Result<(), String> {
    let mut slot = certified_input_ingress_slot()
        .lock()
        .map_err(|_| "ETDAG certified-input ingress lock is poisoned".to_string())?;
    if slot.is_some() {
        return Err("ETDAG certified-input ingress is already installed".to_string());
    }
    *slot = Some(InstalledEtdagCertifiedInputIngress::ScheduleNeutral(
        ingress,
    ));
    Ok(())
}

/// Atomically advance the local ETDAG ingress to the next immutable consensus
/// height after the typed coordinator has verified and durably recorded its
/// finality QC.  This function has no authority to verify or create that QC;
/// it only prevents an old and successor local context from being live at the
/// same time and rejects height skips or a reused finality root.
pub fn rotate_etdag_certified_input_ingress(
    successor: EtdagCertifiedInputIngress,
) -> Result<(), String> {
    let mut slot = certified_input_ingress_slot()
        .lock()
        .map_err(|_| "ETDAG certified-input ingress lock is poisoned".to_string())?;
    let current = slot
        .as_ref()
        .ok_or_else(|| "ETDAG certified-input ingress is not installed".to_string())?;
    let InstalledEtdagCertifiedInputIngress::Typed(current) = current else {
        return Err(
            "ETDAG schedule-neutral ingress cannot be rotated by the typed scheduler".to_string(),
        );
    };
    let expected_height = current
        .height_context
        .height
        .0
        .checked_add(1)
        .ok_or_else(|| "ETDAG certified-input ingress height overflows".to_string())?;
    if successor.height_context.height.0 != expected_height {
        return Err("ETDAG_CERTIFIED_INPUT_INGRESS_NON_SUCCESSOR_HEIGHT".to_string());
    }
    if successor
        .height_context
        .prior_finalized_qc_or_transition_root
        == current.height_context.prior_finalized_qc_or_transition_root
    {
        return Err("ETDAG_CERTIFIED_INPUT_INGRESS_FINALITY_ROOT_NOT_ADVANCED".to_string());
    }
    *slot = Some(InstalledEtdagCertifiedInputIngress::Typed(successor));
    Ok(())
}

/// Removes the local ingress after validator duties stop.  This is not a P2P
/// or RPC action; lifecycle wiring owns this operation.
pub fn remove_etdag_certified_input_ingress() -> Result<(), String> {
    let mut slot = certified_input_ingress_slot()
        .lock()
        .map_err(|_| "ETDAG certified-input ingress lock is poisoned".to_string())?;
    *slot = None;
    Ok(())
}

/// P2P dispatch entrypoint.  The sender identity must originate from a
/// verified Genesis-bound handshake; absent local ingress, absent identity, or
/// a failed proof package all reject without a legacy path.  Admission stays
/// serialized under the ingress lock so concurrent sockets cannot race the
/// bounded durable store's read/verify/write transition.
pub fn dispatch_etdag_certified_input(
    authenticated_peer: Option<EtdagAuthenticatedIngressPeer>,
    artifact: CertifiedProtectedInputArtifact,
) -> Result<EtdagDigest, String> {
    let slot = certified_input_ingress_slot()
        .lock()
        .map_err(|_| "ETDAG certified-input ingress lock is poisoned".to_string())?;
    let ingress = slot.as_ref().ok_or_else(|| {
        "ETDAG certified-input ingress is not running; refusing protected input".to_string()
    })?;
    let peer = authenticated_peer.ok_or_else(|| {
        "ETDAG_CERTIFIED_INPUT_UNAUTHENTICATED_PEER: refusing protected input".to_string()
    })?;
    match ingress {
        InstalledEtdagCertifiedInputIngress::Typed(ingress) => {
            ingress.admit_from_authenticated_peer(&peer, &artifact)
        }
        InstalledEtdagCertifiedInputIngress::ScheduleNeutral(ingress) => {
            ingress.admit_from_authenticated_peer(&peer, &artifact)
        }
    }
}

#[cfg(test)]
pub fn reset_etdag_certified_input_ingress_for_test() {
    let _ = remove_etdag_certified_input_ingress();
}

/// Production ingress boundary for public, already-certified ETDAG artifacts.
///
/// `expected_finality_context_digest` is intentionally supplied by the typed
/// consensus scheduler.  This module has no authority to synthesize a
/// finalized-QC/epoch-transition transcript; accepting a caller-provided
/// expectation and checking it verbatim prevents an ETDAG proof package from
/// being replayed under a different finalized-consensus state.
#[derive(Debug, Clone)]
pub struct EtdagProtectedInputCoordinator {
    admission_store: EtdagAdmissionPackageStore,
    protected_input_store: EtdagProtectedInputStore,
}

impl EtdagProtectedInputCoordinator {
    pub fn process_wide() -> Self {
        Self {
            admission_store: EtdagAdmissionPackageStore::process_wide(),
            protected_input_store: EtdagProtectedInputStore::process_wide(),
        }
    }

    /// Construct a coordinator with explicit durable paths.  This is for node
    /// bootstrap wiring and tests; it does not create either path until a
    /// verified artifact is accepted.
    pub fn at_paths(
        admission_package_path: impl Into<PathBuf>,
        protected_input_path: impl Into<PathBuf>,
    ) -> Self {
        Self {
            admission_store: EtdagAdmissionPackageStore::at_path(admission_package_path),
            protected_input_store: EtdagProtectedInputStore::at_path(protected_input_path),
        }
    }

    /// Verify and durably admit a complete public ETDAG proof package.
    ///
    /// A failed validation writes no protected input.  The independently
    /// verified admission package may have been persisted first, which is safe:
    /// it contains no released private transaction content and can never be
    /// promoted to a proposal without a matching verified input below.
    #[allow(clippy::too_many_arguments)]
    pub fn admit_certified_public_input(
        &self,
        admission_package: &TargetAdmissionPackage,
        protected_input: &ProtectedBlockInput,
        height_context: &HeightConsensusContext,
        expected_finality_context_digest: &EtdagDigest,
        verifier: &AegisPqvmVerifier,
        validator_set: &ValidatorSet,
        cluster_map: &ClusterMap,
        protocol_config: &ProtocolConfig,
        parameters: &EtdagParameters,
    ) -> Result<EtdagDigest, String> {
        let admission_digest = self.admission_store.install_verified(
            admission_package,
            verifier,
            validator_set,
            cluster_map,
            protocol_config,
        )?;
        if admission_package.context.target_height != height_context.height {
            return Err("ETDAG_PROTECTED_INPUT_TARGET_HEIGHT_MISMATCH".to_string());
        }
        self.protected_input_store.install_verified(
            admission_digest,
            protected_input,
            &admission_package.context,
            height_context,
            expected_finality_context_digest,
            verifier,
            validator_set,
            cluster_map,
            parameters,
        )
    }

    /// Verify and durably admit protected input without importing the legacy
    /// height scheduler into the caller's consensus protocol.
    ///
    /// The certified admission package remains the sole authority for ETDAG
    /// topology and H+3 bindings. The caller supplies only the independently
    /// derived canonical finality digest used by deterministic batch order.
    #[allow(clippy::too_many_arguments)]
    pub fn admit_certified_public_input_schedule_neutral(
        &self,
        admission_package: &TargetAdmissionPackage,
        protected_input: &ProtectedBlockInput,
        expected_finality_context_digest: &EtdagDigest,
        verifier: &AegisPqvmVerifier,
        validator_set: &ValidatorSet,
        cluster_map: &ClusterMap,
        consensus_parameter_root: ConsensusParameterRoot,
        parameters: &EtdagParameters,
    ) -> Result<EtdagDigest, String> {
        CertifiedProtectedInputArtifact {
            admission_package: admission_package.clone(),
            protected_input: protected_input.clone(),
        }
        .validate_wire_size()?;
        admission_package.verify_against_parameter_root(
            verifier,
            validator_set,
            cluster_map,
            consensus_parameter_root,
        )?;
        let admission_digest = self
            .admission_store
            .install_preverified(admission_package)?;
        self.protected_input_store
            .install_verified_schedule_neutral(
                admission_digest,
                protected_input,
                &admission_package.context,
                expected_finality_context_digest,
                verifier,
                validator_set,
                cluster_map,
                parameters,
            )
    }

    /// Install a fully certified admission package before its separately
    /// certified protected input arrives. This grants no proposal authority:
    /// [`Self::load_ready_protected_material_schedule_neutral`] still requires
    /// the matching protected input and re-verifies both records.
    pub fn install_certified_admission_package_schedule_neutral(
        &self,
        admission_package: &TargetAdmissionPackage,
        verifier: &AegisPqvmVerifier,
        validator_set: &ValidatorSet,
        cluster_map: &ClusterMap,
        consensus_parameter_root: ConsensusParameterRoot,
    ) -> Result<EtdagDigest, String> {
        admission_package.verify_against_parameter_root(
            verifier,
            validator_set,
            cluster_map,
            consensus_parameter_root,
        )?;
        self.admission_store.install_preverified(admission_package)
    }

    /// Load a proposal-ready protected input only after re-verifying the
    /// durable proof package and its matching certified admission package.
    #[allow(clippy::too_many_arguments)]
    pub fn load_ready_protected_input(
        &self,
        height_context: &HeightConsensusContext,
        expected_finality_context_digest: &EtdagDigest,
        verifier: &AegisPqvmVerifier,
        validator_set: &ValidatorSet,
        cluster_map: &ClusterMap,
        protocol_config: &ProtocolConfig,
        parameters: &EtdagParameters,
    ) -> Result<ProtectedBlockInput, String> {
        let admission_package = self
            .admission_store
            .get(height_context.height)?
            .ok_or_else(|| {
                "ETDAG_PROTECTED_INPUT_NOT_READY: no certified target-admission package for target height"
                    .to_string()
            })?;
        admission_package.verify(verifier, validator_set, cluster_map, protocol_config)?;
        admission_package
            .context
            .validate_height_context_compatibility(height_context)?;
        let admission_digest = admission_package.package_digest()?;
        self.protected_input_store.load_verified(
            &admission_digest,
            &admission_package.context,
            height_context,
            expected_finality_context_digest,
            verifier,
            validator_set,
            cluster_map,
            parameters,
        )
    }

    /// Re-verify and load the exact certified admission context for one target
    /// height without accepting proposer or round schedule input.
    pub fn load_verified_target_admission_context_schedule_neutral(
        &self,
        target_height: Height,
        verifier: &AegisPqvmVerifier,
        validator_set: &ValidatorSet,
        cluster_map: &ClusterMap,
        consensus_parameter_root: ConsensusParameterRoot,
    ) -> Result<TargetAdmissionContext, String> {
        let admission_package = self
            .admission_store
            .get(target_height)?
            .ok_or_else(|| {
                "ETDAG_PROTECTED_INPUT_NOT_READY: no certified target-admission package for target height"
                    .to_string()
            })?;
        admission_package.verify_against_parameter_root(
            verifier,
            validator_set,
            cluster_map,
            consensus_parameter_root,
        )?;
        if admission_package.context.target_height != target_height {
            return Err("ETDAG_PROTECTED_INPUT_TARGET_HEIGHT_MISMATCH".to_string());
        }
        Ok(admission_package.context)
    }

    /// Re-verify and load the exact durable protected material paired with its
    /// certified admission context, while leaving consensus scheduling to the
    /// simplified protocol.
    #[allow(clippy::too_many_arguments)]
    pub fn load_ready_protected_material_schedule_neutral(
        &self,
        target_height: Height,
        expected_finality_context_digest: &EtdagDigest,
        verifier: &AegisPqvmVerifier,
        validator_set: &ValidatorSet,
        cluster_map: &ClusterMap,
        consensus_parameter_root: ConsensusParameterRoot,
        parameters: &EtdagParameters,
    ) -> Result<(TargetAdmissionContext, ProtectedBlockInput), String> {
        let target_context = self.load_verified_target_admission_context_schedule_neutral(
            target_height,
            verifier,
            validator_set,
            cluster_map,
            consensus_parameter_root,
        )?;
        let admission_package = self
            .admission_store
            .get(target_height)?
            .ok_or_else(|| {
                "ETDAG_PROTECTED_INPUT_NOT_READY: no certified target-admission package for target height"
                    .to_string()
            })?;
        if admission_package.context != target_context {
            return Err("ETDAG_ADMISSION_PACKAGE_CONFLICT".to_string());
        }
        let admission_digest = admission_package.package_digest()?;
        let protected_input = self.protected_input_store.load_verified_schedule_neutral(
            &admission_digest,
            &target_context,
            expected_finality_context_digest,
            verifier,
            validator_set,
            cluster_map,
            parameters,
        )?;
        Ok((target_context, protected_input))
    }

    /// Returns the immutable admission context paired with a target height
    /// after verifying its certificate and every consensus binding.  The typed
    /// scheduler uses this together with [`Self::load_ready_protected_input`]
    /// so it never opens a second, potentially divergent admission-store
    /// access path while preparing a proposal.
    pub fn load_verified_target_admission_context(
        &self,
        height_context: &HeightConsensusContext,
        verifier: &AegisPqvmVerifier,
        validator_set: &ValidatorSet,
        cluster_map: &ClusterMap,
        protocol_config: &ProtocolConfig,
    ) -> Result<TargetAdmissionContext, String> {
        let admission_package = self
            .admission_store
            .get(height_context.height)?
            .ok_or_else(|| {
                "ETDAG_PROTECTED_INPUT_NOT_READY: no certified target-admission package for target height"
                    .to_string()
            })?;
        admission_package.verify(verifier, validator_set, cluster_map, protocol_config)?;
        admission_package
            .context
            .validate_height_context_compatibility(height_context)?;
        Ok(admission_package.context)
    }

    /// Remove the no-longer-needed input for an exactly finalized height.
    ///
    /// This is the only removal path, preserving the storage bound without
    /// permitting a timer, RPC caller, or unauthenticated peer to erase a
    /// proposal-ready input.  A valid finality QC proves that no further
    /// proposal can legitimately be produced for this height.
    pub fn prune_finalized_input(
        &self,
        finality_certificate: &QuorumCertificate,
        finalized_height_context: &HeightConsensusContext,
        verifier: &AegisPqvmVerifier,
        validator_set: &ValidatorSet,
        cluster_map: &ClusterMap,
    ) -> Result<bool, String> {
        if finality_certificate.phase != VotePhase::Finality
            || finality_certificate.height != finalized_height_context.height
        {
            return Err("ETDAG_PROTECTED_INPUT_PRUNE_REQUIRES_EXACT_FINALITY_QC".to_string());
        }
        verifier
            .verify_qc_checked(
                finality_certificate,
                validator_set,
                cluster_map,
                finalized_height_context,
            )
            .map_err(|error| error.to_string())?;
        self.protected_input_store
            .remove_finalized(finalized_height_context.height)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::synergy_types::{
        deterministic_test_height_context, AegisPqPublicKey, ClusterMap, ProtocolConfig, UmaId,
        ValidatorStatus,
    };
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    pub(crate) struct Fixture {
        pub(crate) signer: AegisPqvmSigner,
        pub(crate) validator_set: ValidatorSet,
        pub(crate) cluster_map: ClusterMap,
        pub(crate) context: TargetAdmissionContext,
        pub(crate) height_context: HeightConsensusContext,
        pub(crate) ingress_registry: IngressKemKeyRegistry,
        pub(crate) ingress_secret_keys: Vec<Vec<u8>>,
    }

    pub(crate) fn fixture(count: usize, weights: Option<Vec<u64>>) -> Fixture {
        let epoch = Epoch(0);
        let mut signer = AegisPqvmSigner::initialize_required().unwrap();
        let mut validators = Vec::new();
        for index in 0..count {
            let uma = format!("validator-uma-{index}");
            let key_id = signer
                .generate_and_register_key(
                    &uma,
                    vec![
                        AegisPqKeyRole::ConsensusVote,
                        AegisPqKeyRole::ConsensusProposer,
                        AegisPqKeyRole::Transaction,
                    ],
                    epoch,
                )
                .unwrap();
            let public = signer.public_key_record(&key_id).unwrap();
            validators.push(ValidatorRecord {
                validator_id: ValidatorId(format!("validator-{index:02}")),
                validator_uma_id: UmaId(uma),
                consensus_public_key: public.clone(),
                peer_public_key: AegisPqPublicKey {
                    key_id: AegisPqKeyId(format!("peer-{index:02}")),
                    algorithm: public.algorithm.clone(),
                    key_bytes: public.key_bytes.clone(),
                },
                operator_public_key: AegisPqPublicKey {
                    key_id: AegisPqKeyId(format!("operator-{index:02}")),
                    algorithm: public.algorithm.clone(),
                    key_bytes: public.key_bytes.clone(),
                },
                voting_weight: weights
                    .as_ref()
                    .and_then(|values| values.get(index))
                    .copied()
                    .unwrap_or(1),
                status: ValidatorStatus::Active,
                cluster_id: ClusterId(0),
                activation_epoch: epoch,
            });
        }
        let mut validator_set = ValidatorSet { epoch, validators };
        let seed =
            Hash::from_domain_bytes("SYNERGY_TEST_FINALIZED_EPOCH_SEED_V1", b"unit-test-seed");
        let initial = ClusterMap::derive_from_finalized_epoch_seed(&validator_set, seed).unwrap();
        for validator in &mut validator_set.validators {
            validator.cluster_id = initial
                .assignments
                .iter()
                .find(|assignment| assignment.validator_id == validator.validator_id)
                .unwrap()
                .cluster_id;
        }
        let cluster_map =
            ClusterMap::derive_from_finalized_epoch_seed(&validator_set, seed).unwrap();
        let height_context = deterministic_test_height_context(
            &validator_set,
            &cluster_map,
            &ProtocolConfig::testnet_v3(),
            Height(8),
            ClusterId(0),
        );
        let members = validator_set
            .active_for_epoch(epoch)
            .active_for_cluster(height_context.assigned_cluster_id);
        let mut ingress_secret_keys = Vec::new();
        let mut records = Vec::new();
        for (index, member) in members.iter().enumerate() {
            let (public, secret) = mlkem1024::keypair();
            records.push(IngressKemKeyRecord {
                validator_id: member.validator_id.clone(),
                ingress_key_id: format!("test-ingress-{}", member.validator_id.0),
                share_index: (index + 1) as u8,
                key_bytes: public.as_bytes().to_vec(),
            });
            ingress_secret_keys.push(secret.as_bytes().to_vec());
        }
        let ingress_registry = IngressKemKeyRegistry {
            registry_version: INGRESS_KEM_REGISTRY_VERSION,
            chain_id: ChainId::synergy_testnet_v3(),
            network_id: NetworkId::fresh_posy_testnet_v3(),
            protocol_version: POSY_SIMPLIFIED_PROTOCOL_VERSION.to_string(),
            epoch,
            target_height: height_context.height,
            assigned_cluster_id: height_context.assigned_cluster_id,
            records,
        };
        let context = TargetAdmissionContext::derive(
            TargetAdmissionContextSpec {
                protocol_version: POSY_SIMPLIFIED_PROTOCOL_VERSION.to_string(),
                epoch,
                target_height: height_context.height,
                source_finalized_height: Height(height_context.height.0 - 3),
                source_finality_context_root: Hash::from_domain_bytes(
                    "test-source-finality-context",
                    b"height-five",
                ),
                assigned_cluster_id: height_context.assigned_cluster_id,
                cluster_schedule_version: height_context.cluster_schedule_version.clone(),
                finalized_epoch_seed_root: height_context.finalized_epoch_seed_root,
                assigned_height_schedule_root: height_context.assigned_height_schedule_root,
                cryptographic_profile_root: height_context.cryptographic_profile_root,
                ingress_kem_registry_root: ingress_registry.root().unwrap(),
            },
            &validator_set,
            &cluster_map,
            &ProtocolConfig::testnet_v3(),
        )
        .unwrap();
        Fixture {
            signer,
            validator_set,
            cluster_map,
            context,
            height_context,
            ingress_registry,
            ingress_secret_keys,
        }
    }

    fn temp_journal(label: &str) -> EtdagSafetyJournal {
        EtdagSafetyJournal::at_path(crate::utils::test_temp_root(format!(
            "synergy-etdag-{label}-{}-{}/journal.json",
            std::process::id(),
            current_unix_nanos()
        )))
    }

    fn temp_admission_store(label: &str) -> EtdagAdmissionPackageStore {
        EtdagAdmissionPackageStore::at_path(crate::utils::test_temp_root(format!(
            "synergy-etdag-admission-{label}-{}-{}/packages.json",
            std::process::id(),
            current_unix_nanos()
        )))
    }

    fn temp_protected_input_coordinator(label: &str) -> EtdagProtectedInputCoordinator {
        let root = crate::utils::test_temp_root(format!(
            "synergy-etdag-protected-input-{label}-{}-{}",
            std::process::id(),
            current_unix_nanos()
        ));
        EtdagProtectedInputCoordinator::at_paths(
            root.join("admission-packages.json"),
            root.join("protected-inputs.json"),
        )
    }

    fn cluster_members(fixture: &Fixture) -> Vec<ValidatorRecord> {
        fixture
            .validator_set
            .active_for_epoch(fixture.context.epoch)
            .active_for_cluster(fixture.context.assigned_cluster_id)
    }

    fn signed_transaction(
        signer: &mut AegisPqvmSigner,
        sender: &ValidatorRecord,
        nonce: u64,
        fee: u128,
    ) -> Transaction {
        let mut transaction = Transaction {
            version: 2,
            chain_id: ChainId::synergy_testnet_v3(),
            network_id: NetworkId::fresh_posy_testnet_v3(),
            epoch: Epoch(0),
            sender_uma_or_account: sender.validator_uma_id.0.clone(),
            receiver_uma_or_account: "recipient".to_string(),
            account_nonce_or_sequence: nonce,
            amount_nwei: 55,
            gas_limit: 50_000,
            max_fee_nwei: fee,
            ttl_height: Height(8),
            explicit_dependencies: Vec::new(),
            read_set_hint: Vec::new(),
            write_set_hint: Vec::new(),
            payload: b"private-contract-call-data".to_vec(),
            signer_uma_id: sender.validator_uma_id.clone(),
            aegis_pq_key_id: sender.consensus_public_key.key_id.clone(),
            aegis_pq_signature: AegisPqSignature {
                algorithm: String::new(),
                signature_bytes: Vec::new(),
            },
        };
        transaction.aegis_pq_signature = signer
            .sign_transaction(
                &transaction.signing_bytes().unwrap(),
                &transaction.aegis_pq_key_id,
            )
            .unwrap();
        transaction
    }

    fn vote_transcript(
        context: &TargetAdmissionContext,
        phase: EtdagPhase,
        round: u64,
        candidate: &str,
    ) -> EtdagVoteTranscript {
        EtdagVoteTranscript {
            phase,
            chain_id: context.chain_id,
            network_id: context.network_id.clone(),
            protocol_version: context.protocol_version.clone(),
            profile_id: ETDAG_PROFILE_ID.to_string(),
            epoch: context.epoch,
            target_height: context.target_height,
            target_context_root: context.root().unwrap(),
            assigned_cluster_id: context.assigned_cluster_id,
            lane_id: ETDAG_LANE_ID.to_string(),
            round: Round(round),
            candidate_digest: EtdagDigest::from_domain_bytes("candidate", candidate.as_bytes()),
            highest_prepared_bvc_digest: None,
        }
    }

    pub(crate) fn target_admission_package(
        fixture: &mut Fixture,
        context: TargetAdmissionContext,
    ) -> TargetAdmissionPackage {
        let members = fixture
            .validator_set
            .active_for_epoch(context.epoch)
            .active_for_cluster(context.assigned_cluster_id);
        let mut certificate = TargetAdmissionCertificate {
            certificate_version: 2,
            target_context_root: context.root().unwrap(),
            ingress_kem_registry_root: context.ingress_kem_registry_root.clone(),
            source_finalized_height: context.source_finalized_height,
            source_finality_context_root: context.source_finality_context_root,
            signer_count: 0,
            signed_weight: 0,
            votes: Vec::new(),
        };
        let transcript = certificate.signing_bytes(&context).unwrap();
        let quorum = certificate_quorum(members.len()).unwrap();
        certificate.votes = members
            .iter()
            .take(quorum)
            .map(|member| EtdagSignedVote {
                signer_validator_id: member.validator_id.clone(),
                signer_key_id: member.consensus_public_key.key_id.clone(),
                signature: fixture
                    .signer
                    .sign_domain(
                        DOMAIN_TARGET_ADMISSION,
                        &transcript,
                        &member.consensus_public_key.key_id,
                    )
                    .unwrap(),
            })
            .collect();
        certificate.signer_count = certificate.votes.len() as u64;
        certificate.signed_weight = members
            .iter()
            .take(quorum)
            .map(|member| member.voting_weight)
            .sum();
        TargetAdmissionPackage {
            context,
            ingress_kem_registry: fixture.ingress_registry.clone(),
            certificate,
        }
    }

    fn certify_vertex(fixture: &mut Fixture, vertex: TransactionVertex) -> CertifiedVertex {
        let context = fixture.context.clone();
        let validator_set = fixture.validator_set.clone();
        let cluster_map = fixture.cluster_map.clone();
        let members = cluster_members(fixture);
        let mut transcript = vote_transcript(
            &context,
            EtdagPhase::Vac,
            vertex.dag_round,
            "vertex-placeholder",
        );
        transcript.candidate_digest = vertex.digest().unwrap();
        let journal = temp_journal(&format!(
            "vac-{}-{}",
            vertex.author_validator_id.0, vertex.author_sequence
        ));
        let votes = members
            .iter()
            .take(certificate_quorum(members.len()).unwrap())
            .map(|member| {
                sign_vac_vote(
                    &mut fixture.signer,
                    &journal,
                    &context,
                    member,
                    &[],
                    &transcript,
                )
                .unwrap()
            })
            .collect::<Vec<_>>();
        let verifier = fixture.signer.verifier();
        let availability_certificate = form_etdag_certificate(
            transcript,
            votes,
            &verifier,
            &context,
            &validator_set,
            &cluster_map,
        )
        .unwrap();
        CertifiedVertex {
            vertex,
            availability_certificate,
        }
    }

    fn certify_transcript(
        fixture: &mut Fixture,
        transcript: EtdagVoteTranscript,
        label: &str,
    ) -> EtdagCertificate {
        let context = fixture.context.clone();
        let validator_set = fixture.validator_set.clone();
        let cluster_map = fixture.cluster_map.clone();
        let members = cluster_members(fixture);
        let journal = temp_journal(label);
        let votes = members
            .iter()
            .take(certificate_quorum(members.len()).unwrap())
            .map(|member| {
                sign_etdag_vote(&mut fixture.signer, &journal, &context, member, &transcript)
                    .unwrap()
            })
            .collect::<Vec<_>>();
        let verifier = fixture.signer.verifier();
        form_etdag_certificate(
            transcript,
            votes,
            &verifier,
            &context,
            &validator_set,
            &cluster_map,
        )
        .unwrap()
    }

    fn certified_cut_fixture(
        fixture: &mut Fixture,
        eligible_envelopes: Vec<CertifiedEnvelopeRef>,
    ) -> (BTreeMap<EtdagDigest, CertifiedVertex>, DagCutCandidate) {
        let context = fixture.context.clone();
        let members = cluster_members(fixture);
        let quorum = certificate_quorum(members.len()).unwrap();
        let mut graph = BTreeMap::new();
        let mut base_digests = Vec::new();
        for (index, author) in members.iter().take(quorum).enumerate() {
            let envelopes = if index == 0 {
                eligible_envelopes.clone()
            } else {
                Vec::new()
            };
            let vertex = sign_vertex(
                &mut fixture.signer,
                &context,
                author,
                VertexKind::Transactions,
                0,
                index as u64,
                Vec::new(),
                envelopes,
                EtdagDigest::from_domain_bytes("cut-fixture-capsules", &[index as u8]),
                None,
            )
            .unwrap();
            let digest = vertex.digest().unwrap();
            graph.insert(digest.clone(), certify_vertex(fixture, vertex));
            base_digests.push(digest);
        }
        let cutoff_root = Hash::from_domain_bytes("cutoff-vc", b"height-six");
        let mut marker_digests = Vec::new();
        for (index, author) in members.iter().take(quorum).enumerate() {
            let marker = sign_vertex(
                &mut fixture.signer,
                &context,
                author,
                VertexKind::CutoffMarker,
                1,
                100 + index as u64,
                base_digests.clone(),
                Vec::new(),
                EtdagDigest::from_domain_bytes("cut-fixture-marker", &[index as u8]),
                Some(cutoff_root),
            )
            .unwrap();
            let digest = marker.digest().unwrap();
            graph.insert(digest.clone(), certify_vertex(fixture, marker));
            marker_digests.push(digest);
        }
        let verifier = fixture.signer.verifier();
        let cut = build_dag_cut_candidate(
            &context,
            &graph,
            &marker_digests,
            &verifier,
            &fixture.validator_set,
            &fixture.cluster_map,
        )
        .unwrap();
        (graph, cut)
    }

    pub(crate) fn complete_protected_input(fixture: &mut Fixture) -> ProtectedBlockInput {
        let members = cluster_members(fixture);
        let (bundle, secret_keys, _) = sealed_fixture(fixture);
        let commitment = bundle.envelope.tx_commitment.clone();
        let reference = CertifiedEnvelopeRef {
            tx_commitment: commitment.clone(),
            sender_id: bundle.envelope.sender_id.clone(),
            nonce_slot: bundle.envelope.nonce_slot,
            certified_dag_round: 0,
            gas_class_units: bundle.envelope.gas_class as u64,
            ciphertext_bytes: bundle.envelope.ciphertext.len() as u64,
            fee_class: bundle.envelope.fee_class,
            protocol_dependencies: Vec::new(),
        };
        let (certified_vertices, cut_candidate) = certified_cut_fixture(fixture, vec![reference]);
        let mut dcc_transcript =
            vote_transcript(&fixture.context, EtdagPhase::Dcc, 0, "dcc-placeholder");
        dcc_transcript.candidate_digest = cut_candidate.digest().unwrap();
        let dcc = DagCutCertificate {
            candidate: cut_candidate,
            certificate: certify_transcript(fixture, dcc_transcript, "complete-input-dcc"),
        };
        let epoch_randomness = Hash::from_domain_bytes("epoch-randomness", b"complete-input");
        let candidate = build_batch_candidate(
            &dcc.candidate,
            EtdagDigest::from_domain_bytes("finality", b"complete-input"),
            epoch_randomness,
            &EtdagParameters::default(),
        )
        .unwrap();
        let mut bvc_transcript = vote_transcript(
            &fixture.context,
            EtdagPhase::BatchValidate,
            0,
            "bvc-placeholder",
        );
        bvc_transcript.candidate_digest = candidate.digest().unwrap();
        let bvc = BatchValidationCertificate {
            batch_candidate: candidate.clone(),
            certificate: certify_transcript(fixture, bvc_transcript, "complete-input-bvc"),
        };
        let mut boc_transcript = vote_transcript(
            &fixture.context,
            EtdagPhase::BatchFinality,
            0,
            "boc-placeholder",
        );
        boc_transcript.candidate_digest = candidate.digest().unwrap();
        let boc = BatchOrderCertificate {
            bvc,
            finality_certificate: certify_transcript(fixture, boc_transcript, "complete-input-boc"),
        };
        let gate = RevealGate {
            epoch: fixture.context.epoch,
            target_height: fixture.context.target_height,
            cluster_id: fixture.context.assigned_cluster_id,
            target_context_root: fixture.context.root().unwrap(),
            batch_candidate_digest: candidate.digest().unwrap(),
            boc_digest: boc.digest().unwrap(),
            h_minus_one_vc_root: Hash::from_domain_bytes("vc", b"height-seven"),
            h_plus_one_admission_closed: true,
        };
        let threshold =
            decryption_threshold(fixture.context.assigned_cluster_validator_count as usize)
                .unwrap();
        let journal = temp_journal("complete-input-reveal");
        let mut messages = Vec::new();
        let mut raw_shares = Vec::new();
        for index in 0..threshold {
            let share = decrypt_share_capsule(
                &bundle.envelope,
                &bundle.share_capsules[index],
                &secret_keys[index],
            )
            .unwrap();
            raw_shares.push(share.clone());
            messages.push(
                release_decrypt_share(
                    &mut fixture.signer,
                    &journal,
                    &gate,
                    &fixture.context,
                    &members[index],
                    commitment.clone(),
                    share,
                )
                .unwrap(),
            );
        }
        let inner = decrypt_inner_transaction(&bundle.envelope, &raw_shares, threshold).unwrap();
        let envelopes = BTreeMap::from([(commitment.clone(), bundle.envelope)]);
        let decrypt_shares = BTreeMap::from([(commitment, messages)]);
        let reveal = PublicOrderedReveal {
            target_height: fixture.context.target_height,
            batch_candidate_digest: candidate.digest().unwrap(),
            ordered_transactions: vec![inner],
            decrypt_share_transcript_root: decrypt_share_transcript_root(&decrypt_shares).unwrap(),
        };
        ProtectedBlockInput {
            dcc,
            boc,
            reveal,
            epoch_randomness,
            certified_vertices,
            envelopes,
            decrypt_shares,
        }
    }

    fn complete_r11_execution_input(fixture: &mut Fixture) -> DeterministicProtectedExecutionInput {
        use crate::consensus::protected_pipeline::{
            construct_protected_cut_proof, derive_next_protected_batch_commitment,
            derive_protected_batch,
        };

        let members = cluster_members(fixture);
        let (bundle, secret_keys, _) = sealed_fixture(fixture);
        let commitment = bundle.envelope.tx_commitment.clone();
        let reference = CertifiedEnvelopeRef {
            tx_commitment: commitment.clone(),
            sender_id: bundle.envelope.sender_id.clone(),
            nonce_slot: bundle.envelope.nonce_slot,
            certified_dag_round: 0,
            gas_class_units: bundle.envelope.gas_class as u64,
            ciphertext_bytes: bundle.envelope.ciphertext.len() as u64,
            fee_class: bundle.envelope.fee_class,
            protocol_dependencies: Vec::new(),
        };
        let (certified_vertices, legacy_cut) = certified_cut_fixture(fixture, vec![reference]);
        let verifier = fixture.signer.verifier();
        let cut_proof = construct_protected_cut_proof(
            &fixture.context,
            certified_vertices.iter(),
            &legacy_cut.cutoff_marker_digests,
            &verifier,
            &fixture.validator_set,
            &fixture.cluster_map,
        )
        .expect("R11 semantic cut proof");
        let order_seed = EtdagDigest::from_domain_bytes(
            "PoSy/ProtectedPipeline/TestOrderSeed/v1",
            b"height-eight",
        );
        let protected_batch = derive_protected_batch(
            &fixture.context,
            &cut_proof,
            &order_seed,
            &EtdagParameters::default(),
        )
        .expect("R11 protected batch");
        let next_commitment =
            derive_next_protected_batch_commitment(&fixture.context, &cut_proof, &protected_batch)
                .expect("R11 next commitment");
        let authorization = ProtectedRevealAuthorization {
            authorization_version: PROTECTED_PIPELINE_VERSION,
            chain_id: fixture.context.chain_id,
            network_id: fixture.context.network_id.clone(),
            protocol_version: fixture.context.protocol_version.clone(),
            epoch: fixture.context.epoch,
            target_height: fixture.context.target_height,
            cluster_id: fixture.context.assigned_cluster_id,
            target_context_root: fixture.context.root().unwrap(),
            validator_set_commitment: fixture.context.active_validator_set_root,
            parameter_root: fixture.context.consensus_parameter_root,
            parent_proposal_id: BlockId::from("parent-proposal-height-seven"),
            parent_block_id: BlockId::from("parent-block-height-six"),
            next_commitment_root: next_commitment.root().unwrap(),
            protected_batch_root: protected_batch.protected_batch_root.clone(),
            proposal_validation_certificate_root: Hash::from_domain_bytes(
                "PoSy/ProtectedPipeline/TestProposalVc/v1",
                b"height-seven-proposal-vc",
            ),
            certificate_evidence_root: EtdagDigest::from_domain_bytes(
                "PoSy/ProtectedPipeline/TestProposalVcEvidence/v1",
                b"n-minus-one-authenticated-echoes",
            ),
        };
        let threshold =
            decryption_threshold(fixture.context.assigned_cluster_validator_count as usize)
                .unwrap();
        let journal = temp_journal("complete-r11-reveal");
        let mut messages = Vec::new();
        let mut raw_shares = Vec::new();
        for index in 0..threshold {
            let share = decrypt_share_capsule(
                &bundle.envelope,
                &bundle.share_capsules[index],
                &secret_keys[index],
            )
            .unwrap();
            raw_shares.push(share.clone());
            messages.push(
                release_protected_reveal_share(
                    &mut fixture.signer,
                    &journal,
                    &authorization,
                    &next_commitment,
                    &protected_batch,
                    &fixture.context,
                    &members[index],
                    commitment.clone(),
                    share,
                )
                .expect("R11 protected reveal share"),
            );
        }
        let inner = decrypt_inner_transaction(&bundle.envelope, &raw_shares, threshold).unwrap();
        let reveal_shares = BTreeMap::from([(commitment.clone(), messages)]);
        DeterministicProtectedExecutionInput {
            material_version: PROTECTED_PIPELINE_VERSION,
            source: ProtectedBatchSource::NormalEtdagSteadyState,
            target_context: ProtectedExecutionTargetContext::NormalEtdag {
                admission_context: fixture.context.clone(),
            },
            cut_proof: Some(cut_proof),
            protected_batch,
            next_commitment,
            reveal_authorization: Some(authorization),
            envelopes: BTreeMap::from([(commitment, bundle.envelope)]),
            reveal_transcript_root: protected_reveal_transcript_root(&reveal_shares).unwrap(),
            reveal_shares,
            ordered_transactions: vec![inner],
        }
    }

    #[test]
    fn r11_execution_input_replays_exact_ciphertext_and_rejects_root_only_tampering() {
        let mut fixture = fixture(5, None);
        let verifier = fixture.signer.verifier();
        let input = complete_r11_execution_input(&mut fixture);
        let transactions = input
            .verify_and_extract_transactions(
                &verifier,
                &fixture.validator_set,
                &fixture.cluster_map,
                &EtdagParameters::default(),
            )
            .expect("exact R11 protected execution material");
        assert_eq!(transactions.len(), 1);

        let mut missing_ciphertext = input.clone();
        missing_ciphertext.envelopes.clear();
        assert!(missing_ciphertext
            .verify_and_extract_transactions(
                &verifier,
                &fixture.validator_set,
                &fixture.cluster_map,
                &EtdagParameters::default(),
            )
            .unwrap_err()
            .contains("concrete material set mismatch"));

        let mut wrong_vc = input;
        wrong_vc
            .reveal_authorization
            .as_mut()
            .unwrap()
            .proposal_validation_certificate_root = Hash::zero();
        assert!(wrong_vc
            .verify_and_extract_transactions(
                &verifier,
                &fixture.validator_set,
                &fixture.cluster_map,
                &EtdagParameters::default(),
            )
            .unwrap_err()
            .contains("reveal authorization mismatch"));
    }

    fn sealed_fixture(
        fixture: &mut Fixture,
    ) -> (
        SealedTransactionBundle,
        Vec<Vec<u8>>,
        Vec<IngressKemPublicKey>,
    ) {
        let members = cluster_members(fixture);
        let transaction = signed_transaction(&mut fixture.signer, &members[0], 7, 10_000);
        let inner = InnerTransactionV2 {
            target_height: fixture.context.target_height,
            lane_id: ETDAG_LANE_ID.to_string(),
            transaction,
        };
        let recipients = fixture.ingress_registry.recipients();
        let secret_keys = fixture.ingress_secret_keys.clone();
        let parameters = EtdagParameters::default();
        let mut rng = StdRng::seed_from_u64(44);
        let bundle = seal_transaction(
            &mut fixture.signer,
            SealRequest {
                inner,
                target_context: &fixture.context,
                parameters: &parameters,
                recipients: &recipients,
                gas_class: 2,
                fee_class: 1,
                admission_bond_nwei: 100,
                outer_key_id: members[0].consensus_public_key.key_id.clone(),
            },
            &mut rng,
        )
        .unwrap();
        (bundle, secret_keys, recipients)
    }

    #[test]
    fn share_threshold_vectors_and_reconstruction_match_v2_2() {
        for (n, q, threshold) in [(5, 4, 2), (6, 5, 2), (7, 5, 3), (10, 7, 4)] {
            assert_eq!(certificate_quorum(n).unwrap(), q);
            assert_eq!(decryption_threshold(n).unwrap(), threshold);
        }
        let recipients = (1..=7)
            .map(|index| IngressKemPublicKey {
                validator_id: ValidatorId(format!("v-{index}")),
                share_index: index,
                key_bytes: Vec::new(),
            })
            .collect::<Vec<_>>();
        let secret = [0xabu8; 32];
        let mut rng = StdRng::seed_from_u64(9);
        let shares = split_secret(&secret, &recipients, 3, &mut rng).unwrap();
        assert!(reconstruct_secret(&shares[..2], 3).is_err());
        assert_eq!(reconstruct_secret(&shares[1..4], 3).unwrap(), secret);
        let duplicate = vec![shares[0].clone(), shares[0].clone(), shares[1].clone()];
        assert!(reconstruct_secret(&duplicate, 3).is_err());
    }

    #[test]
    fn wallet_seals_complete_inner_transaction_and_threshold_reveal_round_trips() {
        let mut fixture = fixture(6, None);
        let verifier = fixture.signer.verifier();
        let (bundle, secret_keys, _) = sealed_fixture(&mut fixture);
        bundle
            .envelope
            .validate_structure(&fixture.context, &EtdagParameters::default())
            .unwrap();
        bundle.envelope.verify_outer_signature(&verifier).unwrap();
        bundle.validate_roots().unwrap();
        assert!(!bundle
            .envelope
            .ciphertext
            .windows(b"private-contract-call-data".len())
            .any(|window| window == b"private-contract-call-data"));

        let mut shares = Vec::new();
        for (capsule, secret) in bundle.share_capsules.iter().zip(secret_keys.iter()) {
            shares.push(
                decrypt_share_capsule(&bundle.envelope, capsule, secret)
                    .expect("validator decrypts and verifies only its own share"),
            );
        }
        let threshold =
            decryption_threshold(fixture.context.assigned_cluster_validator_count as usize)
                .unwrap();
        assert!(
            decrypt_inner_transaction(&bundle.envelope, &shares[..threshold - 1], threshold)
                .is_err()
        );
        let revealed =
            decrypt_inner_transaction(&bundle.envelope, &shares[..threshold], threshold).unwrap();
        assert_eq!(revealed.transaction.payload, b"private-contract-call-data");
        assert_eq!(revealed.transaction.max_fee_nwei, 10_000);

        let mut wrong_cluster = bundle.envelope.clone();
        wrong_cluster.assigned_cluster_id = ClusterId(99);
        assert!(wrong_cluster
            .validate_structure(&fixture.context, &EtdagParameters::default())
            .is_err());
        let mut wrong_height = bundle.envelope.clone();
        wrong_height.target_height = Height(9);
        assert!(wrong_height
            .validate_structure(&fixture.context, &EtdagParameters::default())
            .is_err());
    }

    #[test]
    fn h_plus_three_target_context_needs_no_synthetic_future_qc_and_links_later_height() {
        let fixture = fixture(6, None);
        assert_eq!(fixture.context.source_finalized_height, Height(5));
        assert_eq!(fixture.context.target_height, Height(8));
        fixture
            .context
            .validate_height_context_compatibility(&fixture.height_context)
            .unwrap();

        let mut different_prior_finality = fixture.height_context.clone();
        different_prior_finality.prior_finalized_qc_or_transition_root =
            Hash::from_domain_bytes("actual-height-seven-qc", b"not-known-at-wallet-seal-time");
        different_prior_finality.validate().unwrap();
        fixture
            .context
            .validate_height_context_compatibility(&different_prior_finality)
            .unwrap();

        let mut changed_weight = different_prior_finality;
        changed_weight.frozen_bonded_weight_root =
            Hash::from_domain_bytes("wrong-weight-root", b"mutation");
        assert!(fixture
            .context
            .validate_height_context_compatibility(&changed_weight)
            .unwrap_err()
            .contains("does not match"));

        let mut too_near = fixture.context.clone();
        too_near.target_height = Height(7);
        assert!(too_near
            .validate()
            .unwrap_err()
            .contains("at least finalized H+3"));
    }

    #[test]
    fn target_admission_registry_and_certificate_fail_closed() {
        let mut fixture = fixture(6, None);
        let context = fixture.context.clone();
        let package = target_admission_package(&mut fixture, context);
        let verifier = fixture.signer.verifier();
        package
            .verify(
                &verifier,
                &fixture.validator_set,
                &fixture.cluster_map,
                &ProtocolConfig::testnet_v3(),
            )
            .unwrap();

        let mut incomplete_registry = package.clone();
        incomplete_registry.ingress_kem_registry.records.pop();
        assert!(incomplete_registry
            .verify(
                &verifier,
                &fixture.validator_set,
                &fixture.cluster_map,
                &ProtocolConfig::testnet_v3(),
            )
            .is_err());

        let mut malformed_key = package.clone();
        malformed_key.ingress_kem_registry.records[0]
            .key_bytes
            .clear();
        assert!(malformed_key
            .verify(
                &verifier,
                &fixture.validator_set,
                &fixture.cluster_map,
                &ProtocolConfig::testnet_v3(),
            )
            .is_err());

        let mut four_of_six = package.clone();
        four_of_six.certificate.votes.truncate(4);
        four_of_six.certificate.signer_count = 4;
        four_of_six.certificate.signed_weight = 4;
        assert!(four_of_six
            .verify(
                &verifier,
                &fixture.validator_set,
                &fixture.cluster_map,
                &ProtocolConfig::testnet_v3(),
            )
            .unwrap_err()
            .contains("dual quorum"));
    }

    #[test]
    fn durable_nonce_admission_batch_and_reveal_slots_fail_closed_after_restart() {
        let mut fixture = fixture(6, None);
        let members = cluster_members(&fixture);
        let (bundle, _, _) = sealed_fixture(&mut fixture);
        let journal = temp_journal("durable-slots");
        journal.reserve_nonce(&bundle.envelope).unwrap();
        let mut replacement = bundle.envelope.clone();
        replacement.tx_commitment = EtdagDigest::from_domain_bytes("replacement", b"higher fee");
        assert!(journal
            .reserve_nonce(&replacement)
            .unwrap_err()
            .contains("NONCE_RESERVATION_CONFLICT"));

        let cutoff_root = Hash::from_domain_bytes("cutoff-vc", b"height-6");
        journal
            .close_admission(&fixture.context, &members[0].validator_id, cutoff_root)
            .unwrap();
        let restarted = EtdagSafetyJournal::at_path(journal.path().to_path_buf());
        let vac = vote_transcript(&fixture.context, EtdagPhase::Vac, 0, "vertex-a");
        assert!(restarted
            .authorize_availability_before_signature(
                &fixture.context,
                &members[0],
                std::slice::from_ref(&bundle.envelope),
                &vac,
            )
            .unwrap_err()
            .contains("ADMISSION_CLOSED"));

        let batch_a = vote_transcript(&fixture.context, EtdagPhase::BatchFinality, 0, "batch-a");
        sign_etdag_vote(
            &mut fixture.signer,
            &restarted,
            &fixture.context,
            &members[1],
            &batch_a,
        )
        .unwrap();
        let batch_b = vote_transcript(&fixture.context, EtdagPhase::BatchFinality, 4, "batch-b");
        assert!(sign_etdag_vote(
            &mut fixture.signer,
            &restarted,
            &fixture.context,
            &members[1],
            &batch_b,
        )
        .unwrap_err()
        .contains("SIGNING_CONFLICT"));

        let closed_gate = RevealGate {
            epoch: fixture.context.epoch,
            target_height: fixture.context.target_height,
            cluster_id: fixture.context.assigned_cluster_id,
            target_context_root: fixture.context.root().unwrap(),
            batch_candidate_digest: batch_a.candidate_digest.clone(),
            boc_digest: EtdagDigest::from_domain_bytes("boc", b"a"),
            h_minus_one_vc_root: Hash::zero(),
            h_plus_one_admission_closed: false,
        };
        assert!(restarted
            .authorize_decrypt_release(
                &closed_gate,
                &members[1].validator_id,
                bundle.envelope.tx_commitment.clone(),
                EtdagDigest::from_domain_bytes("share", b"one"),
            )
            .is_err());
    }

    #[test]
    fn nonce_window_is_contiguous_bounded_and_corrupt_journal_fails_closed() {
        let mut fixture = fixture(6, None);
        let (bundle, _, _) = sealed_fixture(&mut fixture);
        let journal = temp_journal("nonce-window");
        let envelope_for = |nonce: u64| {
            let mut envelope = bundle.envelope.clone();
            envelope.nonce_slot = nonce;
            envelope.tx_commitment =
                EtdagDigest::from_domain_bytes("nonce-window", &nonce.to_be_bytes());
            envelope
        };
        journal.reserve_nonce(&envelope_for(7)).unwrap();
        journal.reserve_nonce(&envelope_for(8)).unwrap();
        assert!(journal
            .reserve_nonce(&envelope_for(10))
            .unwrap_err()
            .contains("contiguous"));
        journal.reserve_nonce(&envelope_for(9)).unwrap();
        journal.reserve_nonce(&envelope_for(10)).unwrap();
        assert!(journal
            .reserve_nonce(&envelope_for(11))
            .unwrap_err()
            .contains("exhausted"));

        let corrupt = temp_journal("corrupt");
        fs::create_dir_all(corrupt.path().parent().unwrap()).unwrap();
        fs::write(corrupt.path(), b"{\"format\":\"truncated").unwrap();
        assert!(corrupt
            .reserve_nonce(&envelope_for(7))
            .unwrap_err()
            .contains("parse ETDAG journal"));
        assert_eq!(
            fs::read(corrupt.path()).unwrap(),
            b"{\"format\":\"truncated"
        );
    }

    #[test]
    fn certified_target_admission_package_store_is_append_only_and_restart_safe() {
        let mut fixture = fixture(6, None);
        let store = temp_admission_store("append-only");
        let initial_context = fixture.context.clone();
        let package = target_admission_package(&mut fixture, initial_context);
        let verifier = fixture.signer.verifier();
        let protocol = ProtocolConfig::testnet_v3();
        let digest = store
            .install_verified(
                &package,
                &verifier,
                &fixture.validator_set,
                &fixture.cluster_map,
                &protocol,
            )
            .unwrap();
        assert_eq!(digest, package.package_digest().unwrap());
        assert_eq!(
            store
                .install_verified(
                    &package,
                    &verifier,
                    &fixture.validator_set,
                    &fixture.cluster_map,
                    &protocol,
                )
                .unwrap(),
            digest
        );

        let restarted = EtdagAdmissionPackageStore::at_path(store.path.clone());
        assert_eq!(
            restarted.get(fixture.context.target_height).unwrap(),
            Some(package.clone())
        );
        let mut conflict = fixture.context.clone();
        conflict.source_finality_context_root =
            Hash::from_domain_bytes("different-finalized-parent", b"same-height");
        assert!(conflict.validate().is_ok());
        let conflicting_package = target_admission_package(&mut fixture, conflict);
        assert!(restarted
            .install_verified(
                &conflicting_package,
                &verifier,
                &fixture.validator_set,
                &fixture.cluster_map,
                &protocol,
            )
            .unwrap_err()
            .contains("ADMISSION_PACKAGE_CONFLICT"));

        let corrupt = temp_admission_store("corrupt");
        fs::create_dir_all(corrupt.path.parent().unwrap()).unwrap();
        fs::write(&corrupt.path, b"{\"format\":\"partial").unwrap();
        assert!(corrupt
            .get(fixture.context.target_height)
            .unwrap_err()
            .contains("parse ETDAG admission-package store"));
    }

    #[test]
    fn protected_input_coordinator_fails_closed_until_every_public_proof_is_verified() {
        let mut fixture = fixture(6, None);
        let coordinator = temp_protected_input_coordinator("fail-closed");
        let protocol = ProtocolConfig::testnet_v3();
        let verifier = fixture.signer.verifier();
        let height_context = fixture.height_context.clone();
        let context = fixture.context.clone();
        let package = target_admission_package(&mut fixture, context);
        let protected = complete_protected_input(&mut fixture);
        let expected_finality_context = protected
            .boc
            .bvc
            .batch_candidate
            .canonical_finality_context_digest
            .clone();

        assert!(coordinator
            .load_ready_protected_input(
                &height_context,
                &expected_finality_context,
                &verifier,
                &fixture.validator_set,
                &fixture.cluster_map,
                &protocol,
                &EtdagParameters::default(),
            )
            .unwrap_err()
            .contains("NOT_READY"));

        let incorrect_finality_context =
            EtdagDigest::from_domain_bytes("incorrect-finality-context", b"wrong");
        assert!(coordinator
            .admit_certified_public_input(
                &package,
                &protected,
                &height_context,
                &incorrect_finality_context,
                &verifier,
                &fixture.validator_set,
                &fixture.cluster_map,
                &protocol,
                &EtdagParameters::default(),
            )
            .unwrap_err()
            .contains("FINALITY_CONTEXT_MISMATCH"));

        // Persisting a valid public admission package does not make a proposal
        // eligible by itself: the matching protected input remains absent.
        assert!(coordinator
            .load_ready_protected_input(
                &height_context,
                &expected_finality_context,
                &verifier,
                &fixture.validator_set,
                &fixture.cluster_map,
                &protocol,
                &EtdagParameters::default(),
            )
            .unwrap_err()
            .contains("NOT_READY"));

        let mut missing_reveal_evidence = protected.clone();
        missing_reveal_evidence.decrypt_shares.clear();
        assert!(coordinator
            .admit_certified_public_input(
                &package,
                &missing_reveal_evidence,
                &height_context,
                &expected_finality_context,
                &verifier,
                &fixture.validator_set,
                &fixture.cluster_map,
                &protocol,
                &EtdagParameters::default(),
            )
            .is_err());

        assert!(coordinator
            .load_ready_protected_input(
                &height_context,
                &expected_finality_context,
                &verifier,
                &fixture.validator_set,
                &fixture.cluster_map,
                &protocol,
                &EtdagParameters::default(),
            )
            .unwrap_err()
            .contains("NOT_READY"));
    }

    #[test]
    fn protected_input_coordinator_reverifies_durable_input_before_proposal_use() {
        let mut fixture = fixture(6, None);
        let root = crate::utils::test_temp_root(format!(
            "synergy-etdag-protected-input-restart-{}-{}",
            std::process::id(),
            current_unix_nanos()
        ));
        let admission_path = root.join("admission-packages.json");
        let protected_path = root.join("protected-inputs.json");
        let coordinator = EtdagProtectedInputCoordinator::at_paths(
            admission_path.clone(),
            protected_path.clone(),
        );
        let protocol = ProtocolConfig::testnet_v3();
        let verifier = fixture.signer.verifier();
        let height_context = fixture.height_context.clone();
        let context = fixture.context.clone();
        let package = target_admission_package(&mut fixture, context);
        let protected = complete_protected_input(&mut fixture);
        let expected_finality_context = protected
            .boc
            .bvc
            .batch_candidate
            .canonical_finality_context_digest
            .clone();

        let digest = coordinator
            .admit_certified_public_input(
                &package,
                &protected,
                &height_context,
                &expected_finality_context,
                &verifier,
                &fixture.validator_set,
                &fixture.cluster_map,
                &protocol,
                &EtdagParameters::default(),
            )
            .unwrap();
        assert_eq!(digest, protected_input_digest(&protected).unwrap());

        let restarted = EtdagProtectedInputCoordinator::at_paths(admission_path, protected_path);
        assert_eq!(
            restarted
                .load_ready_protected_input(
                    &height_context,
                    &expected_finality_context,
                    &verifier,
                    &fixture.validator_set,
                    &fixture.cluster_map,
                    &protocol,
                    &EtdagParameters::default(),
                )
                .unwrap(),
            protected
        );
    }

    #[test]
    fn strict_dual_quorum_rejects_four_of_six_wrong_phase_and_low_weight() {
        let mut base_fixture = fixture(6, None);
        let members = cluster_members(&base_fixture);
        let verifier = base_fixture.signer.verifier();
        let transcript = vote_transcript(
            &base_fixture.context,
            EtdagPhase::BatchValidate,
            0,
            "batch-a",
        );
        let journal = temp_journal("quorum");
        let votes = members
            .iter()
            .take(5)
            .map(|member| {
                sign_etdag_vote(
                    &mut base_fixture.signer,
                    &journal,
                    &base_fixture.context,
                    member,
                    &transcript,
                )
                .unwrap()
            })
            .collect::<Vec<_>>();
        let certificate = form_etdag_certificate(
            transcript.clone(),
            votes.clone(),
            &verifier,
            &base_fixture.context,
            &base_fixture.validator_set,
            &base_fixture.cluster_map,
        )
        .unwrap();
        assert_eq!(certificate.signer_count, 5);
        assert!(form_etdag_certificate(
            transcript.clone(),
            votes[..4].to_vec(),
            &verifier,
            &base_fixture.context,
            &base_fixture.validator_set,
            &base_fixture.cluster_map,
        )
        .unwrap_err()
        .contains("count quorum"));

        let mut wrong_phase = certificate.clone();
        wrong_phase.transcript.phase = EtdagPhase::BatchFinality;
        assert!(wrong_phase
            .verify(
                &verifier,
                &base_fixture.context,
                &base_fixture.validator_set,
                &base_fixture.cluster_map,
            )
            .is_err());

        let mut weighted = fixture(6, Some(vec![100, 1, 1, 1, 1, 1]));
        let weighted_members = cluster_members(&weighted);
        let high_weight_id = weighted_members
            .iter()
            .max_by_key(|member| member.voting_weight)
            .unwrap()
            .validator_id
            .clone();
        let weighted_transcript = vote_transcript(
            &weighted.context,
            EtdagPhase::BatchValidate,
            0,
            "batch-weight",
        );
        let weighted_journal = temp_journal("weight");
        let low_votes = weighted_members
            .iter()
            .filter(|member| member.validator_id != high_weight_id)
            .map(|member| {
                sign_etdag_vote(
                    &mut weighted.signer,
                    &weighted_journal,
                    &weighted.context,
                    member,
                    &weighted_transcript,
                )
                .unwrap()
            })
            .collect::<Vec<_>>();
        let weighted_verifier = weighted.signer.verifier();
        assert_eq!(low_votes.len(), 5);
        assert!(form_etdag_certificate(
            weighted_transcript,
            low_votes,
            &weighted_verifier,
            &weighted.context,
            &weighted.validator_set,
            &weighted.cluster_map,
        )
        .unwrap_err()
        .contains("weight quorum"));
    }

    #[test]
    fn cryptographically_valid_non_cluster_vote_is_consensus_ineligible() {
        let mut fixture = fixture(10, None);
        let members = cluster_members(&fixture);
        let outsider = fixture
            .validator_set
            .active_for_epoch(fixture.context.epoch)
            .validators
            .iter()
            .find(|member| {
                member.cluster_id != fixture.context.assigned_cluster_id
                    && member.status == ValidatorStatus::Active
            })
            .unwrap()
            .clone();
        let transcript = vote_transcript(&fixture.context, EtdagPhase::BatchValidate, 0, "batch-a");
        let journal = temp_journal("wrong-cluster");
        let mut votes = members
            .iter()
            .take(certificate_quorum(members.len()).unwrap() - 1)
            .map(|member| {
                sign_etdag_vote(
                    &mut fixture.signer,
                    &journal,
                    &fixture.context,
                    member,
                    &transcript,
                )
                .unwrap()
            })
            .collect::<Vec<_>>();
        votes.push(
            sign_etdag_vote(
                &mut fixture.signer,
                &journal,
                &fixture.context,
                &outsider,
                &transcript,
            )
            .unwrap(),
        );
        let verifier = fixture.signer.verifier();
        assert!(form_etdag_certificate(
            transcript,
            votes,
            &verifier,
            &fixture.context,
            &fixture.validator_set,
            &fixture.cluster_map,
        )
        .unwrap_err()
        .contains("not in assigned cluster"));
    }

    fn envelope_ref(
        commitment: &str,
        sender: &str,
        nonce: u64,
        fee_class: u32,
        round: u64,
    ) -> CertifiedEnvelopeRef {
        CertifiedEnvelopeRef {
            tx_commitment: EtdagDigest::from_domain_bytes("test-commitment", commitment.as_bytes()),
            sender_id: sender.to_string(),
            nonce_slot: nonce,
            certified_dag_round: round,
            gas_class_units: 10,
            ciphertext_bytes: 512,
            fee_class,
            protocol_dependencies: Vec::new(),
        }
    }

    #[test]
    fn content_blind_order_is_arrival_proposer_and_fee_independent_with_nonce_edges() {
        let seed = EtdagDigest::from_domain_bytes("order-seed", b"fixed");
        let mut entries = vec![
            envelope_ref("alice-1", "alice", 1, 0, 1),
            envelope_ref("bob-0", "bob", 0, 1, 1),
            envelope_ref("alice-0", "alice", 0, 2, 1),
        ];
        let first = canonical_content_blind_order(&entries, &seed, 1_000, 10_000).unwrap();
        let alice_nonces = first
            .iter()
            .filter(|entry| entry.sender_id == "alice")
            .map(|entry| entry.nonce_slot)
            .collect::<Vec<_>>();
        assert_eq!(alice_nonces, vec![0, 1]);

        entries.reverse();
        entries[0].fee_class = 999_999;
        entries[1].fee_class = 0;
        entries[2].fee_class = 42;
        let second = canonical_content_blind_order(&entries, &seed, 1_000, 10_000).unwrap();
        assert_eq!(
            first
                .iter()
                .map(|entry| &entry.tx_commitment)
                .collect::<Vec<_>>(),
            second
                .iter()
                .map(|entry| &entry.tx_commitment)
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn verified_dag_cut_includes_complete_causal_union_and_rejects_wrong_round_parents() {
        let mut fixture = fixture(6, None);
        let context = fixture.context.clone();
        let members = cluster_members(&fixture);
        let quorum = certificate_quorum(members.len()).unwrap();
        let mut graph = BTreeMap::new();
        let mut base_digests = Vec::new();

        for (index, author) in members.iter().take(quorum).enumerate() {
            let envelope = envelope_ref(
                &format!("eligible-{index}"),
                &format!("sender-{index}"),
                index as u64,
                index as u32,
                0,
            );
            let vertex = sign_vertex(
                &mut fixture.signer,
                &context,
                author,
                VertexKind::Transactions,
                0,
                index as u64,
                Vec::new(),
                vec![envelope],
                EtdagDigest::from_domain_bytes("capsule-root", &[index as u8]),
                None,
            )
            .unwrap();
            let digest = vertex.digest().unwrap();
            graph.insert(digest.clone(), certify_vertex(&mut fixture, vertex));
            base_digests.push(digest);
        }

        let cutoff_root = Hash::from_domain_bytes("cutoff-vc", b"height-six");
        let mut marker_digests = Vec::new();
        for (index, author) in members.iter().take(quorum).enumerate() {
            let marker = sign_vertex(
                &mut fixture.signer,
                &context,
                author,
                VertexKind::CutoffMarker,
                1,
                100 + index as u64,
                base_digests.clone(),
                Vec::new(),
                EtdagDigest::from_domain_bytes("marker-capsule-root", &[index as u8]),
                Some(cutoff_root),
            )
            .unwrap();
            let digest = marker.digest().unwrap();
            graph.insert(digest.clone(), certify_vertex(&mut fixture, marker));
            marker_digests.push(digest);
        }

        let verifier = fixture.signer.verifier();
        let cut = build_dag_cut_candidate(
            &context,
            &graph,
            &marker_digests,
            &verifier,
            &fixture.validator_set,
            &fixture.cluster_map,
        )
        .unwrap();
        assert_eq!(cut.eligible_envelopes.len(), quorum);
        assert!(base_digests
            .iter()
            .all(|digest| cut.causal_closure_digests.contains(digest)));

        let mut wrong_round_graph = graph
            .iter()
            .filter(|(digest, _)| base_digests.contains(digest))
            .map(|(digest, certified)| (digest.clone(), certified.clone()))
            .collect::<BTreeMap<_, _>>();
        let mut wrong_round_markers = Vec::new();
        for (index, author) in members.iter().take(quorum).enumerate() {
            let marker = sign_vertex(
                &mut fixture.signer,
                &context,
                author,
                VertexKind::CutoffMarker,
                2,
                200 + index as u64,
                base_digests.clone(),
                Vec::new(),
                EtdagDigest::from_domain_bytes("wrong-round-marker-root", &[index as u8]),
                Some(cutoff_root),
            )
            .unwrap();
            let digest = marker.digest().unwrap();
            wrong_round_graph.insert(digest.clone(), certify_vertex(&mut fixture, marker));
            wrong_round_markers.push(digest);
        }
        let verifier = fixture.signer.verifier();
        assert!(build_dag_cut_candidate(
            &context,
            &wrong_round_graph,
            &wrong_round_markers,
            &verifier,
            &fixture.validator_set,
            &fixture.cluster_map,
        )
        .unwrap_err()
        .contains("previous DAG round"));
    }

    #[test]
    fn exact_protected_execution_rejects_omission_insertion_duplication_and_reorder() {
        let commitments = vec![
            EtdagDigest::from_domain_bytes("tx", b"a"),
            EtdagDigest::from_domain_bytes("tx", b"b"),
        ];
        let candidate = BatchCandidate {
            candidate_version: 2,
            target_height: Height(8),
            target_context_root: Hash::from_domain_bytes("context", b"eight"),
            cluster_id: ClusterId(0),
            dcc_digest: EtdagDigest::from_domain_bytes("dcc", b"eight"),
            canonical_finality_context_digest: EtdagDigest::from_domain_bytes("finality", b"six"),
            order_seed: EtdagDigest::from_domain_bytes("seed", b"eight"),
            ordered_commitment_root: EtdagDigest::from_canonical(
                "PoSy/ETDAG/OrderedCommitmentRoot/v3",
                &commitments,
            )
            .unwrap(),
            deferred_commitment_root: EtdagDigest::from_domain_bytes("deferred", b"none"),
            dependency_graph_root: EtdagDigest::from_domain_bytes("deps", b"two"),
            ordered_commitments: commitments.clone(),
            declared_gas_units: 20,
            declared_ciphertext_bytes: 1024,
            disposition: BatchDisposition::Ordered,
            certified_availability_failure_root: None,
        };
        let entry = |index, commitment: EtdagDigest| ExecutionManifestEntry {
            index,
            tx_commitment: commitment,
            disposition: ExecutionDisposition::Executed,
            transaction_hash: Some(Hash::from_domain_bytes("executed", &[index as u8])),
            receipt_hash: Some(Hash::from_domain_bytes("receipt", &[index as u8])),
        };
        let valid = ExecutionManifest {
            target_height: Height(8),
            batch_candidate_digest: candidate.digest().unwrap(),
            entries: vec![
                entry(0, commitments[0].clone()),
                entry(1, commitments[1].clone()),
            ],
        };
        valid.validate_exact(&candidate).unwrap();

        let mut reordered = valid.clone();
        reordered.entries.swap(0, 1);
        assert!(reordered.validate_exact(&candidate).is_err());
        let mut omitted = valid.clone();
        omitted.entries.pop();
        assert!(omitted.validate_exact(&candidate).is_err());
        let mut duplicated = valid.clone();
        duplicated.entries[1].tx_commitment = commitments[0].clone();
        assert!(duplicated.validate_exact(&candidate).is_err());
    }

    #[test]
    fn public_reveal_requires_authenticated_ciphertext_plaintext_and_signed_threshold_transcript() {
        let mut fixture = fixture(6, None);
        let members = cluster_members(&fixture);
        let verifier = fixture.signer.verifier();
        let (bundle, secret_keys, _) = sealed_fixture(&mut fixture);
        let commitment = bundle.envelope.tx_commitment.clone();
        let reference = CertifiedEnvelopeRef {
            tx_commitment: commitment.clone(),
            sender_id: bundle.envelope.sender_id.clone(),
            nonce_slot: bundle.envelope.nonce_slot,
            certified_dag_round: 0,
            gas_class_units: bundle.envelope.gas_class as u64,
            ciphertext_bytes: bundle.envelope.ciphertext.len() as u64,
            fee_class: bundle.envelope.fee_class,
            protocol_dependencies: Vec::new(),
        };
        let (certified_vertices, cut_candidate) =
            certified_cut_fixture(&mut fixture, vec![reference]);
        let mut dcc_transcript =
            vote_transcript(&fixture.context, EtdagPhase::Dcc, 0, "dcc-placeholder");
        dcc_transcript.candidate_digest = cut_candidate.digest().unwrap();
        let dcc = DagCutCertificate {
            candidate: cut_candidate,
            certificate: certify_transcript(&mut fixture, dcc_transcript, "reveal-dcc"),
        };
        let epoch_randomness = Hash::from_domain_bytes("epoch-randomness", b"reveal");
        let candidate = build_batch_candidate(
            &dcc.candidate,
            EtdagDigest::from_domain_bytes("finality", b"reveal"),
            epoch_randomness,
            &EtdagParameters::default(),
        )
        .unwrap();
        let mut bvc_transcript = vote_transcript(
            &fixture.context,
            EtdagPhase::BatchValidate,
            0,
            "bvc-placeholder",
        );
        bvc_transcript.candidate_digest = candidate.digest().unwrap();
        let bvc = BatchValidationCertificate {
            batch_candidate: candidate.clone(),
            certificate: certify_transcript(&mut fixture, bvc_transcript, "reveal-bvc"),
        };
        let mut boc_transcript = vote_transcript(
            &fixture.context,
            EtdagPhase::BatchFinality,
            0,
            "boc-placeholder",
        );
        boc_transcript.candidate_digest = candidate.digest().unwrap();
        let boc = BatchOrderCertificate {
            bvc,
            finality_certificate: certify_transcript(&mut fixture, boc_transcript, "reveal-boc"),
        };
        let gate = RevealGate {
            epoch: fixture.context.epoch,
            target_height: fixture.context.target_height,
            cluster_id: fixture.context.assigned_cluster_id,
            target_context_root: fixture.context.root().unwrap(),
            batch_candidate_digest: candidate.digest().unwrap(),
            boc_digest: boc.digest().unwrap(),
            h_minus_one_vc_root: Hash::from_domain_bytes("vc", b"height-seven"),
            h_plus_one_admission_closed: true,
        };
        let threshold =
            decryption_threshold(fixture.context.assigned_cluster_validator_count as usize)
                .unwrap();
        let journal = temp_journal("public-reveal");
        let mut messages = Vec::new();
        let mut raw_shares = Vec::new();
        for index in 0..threshold {
            let share = decrypt_share_capsule(
                &bundle.envelope,
                &bundle.share_capsules[index],
                &secret_keys[index],
            )
            .unwrap();
            raw_shares.push(share.clone());
            messages.push(
                release_decrypt_share(
                    &mut fixture.signer,
                    &journal,
                    &gate,
                    &fixture.context,
                    &members[index],
                    commitment.clone(),
                    share,
                )
                .unwrap(),
            );
        }
        let inner = decrypt_inner_transaction(&bundle.envelope, &raw_shares, threshold).unwrap();
        let envelopes = BTreeMap::from([(commitment.clone(), bundle.envelope.clone())]);
        let shares_by_commitment = BTreeMap::from([(commitment.clone(), messages)]);
        let reveal = PublicOrderedReveal {
            target_height: fixture.context.target_height,
            batch_candidate_digest: candidate.digest().unwrap(),
            ordered_transactions: vec![inner],
            decrypt_share_transcript_root: decrypt_share_transcript_root(&shares_by_commitment)
                .unwrap(),
        };
        reveal
            .validate_cryptographic_exact(
                &candidate,
                &envelopes,
                &shares_by_commitment,
                &verifier,
                &fixture.context,
                &fixture.validator_set,
                &fixture.cluster_map,
            )
            .unwrap();
        let protected = ProtectedBlockInput {
            dcc,
            boc,
            reveal: reveal.clone(),
            epoch_randomness,
            certified_vertices,
            envelopes: envelopes.clone(),
            decrypt_shares: shares_by_commitment.clone(),
        };
        let extracted = protected
            .verify_and_extract_transactions(
                &verifier,
                &fixture.context,
                &fixture.validator_set,
                &fixture.cluster_map,
                &EtdagParameters::default(),
            )
            .unwrap();
        assert_eq!(
            extracted,
            reveal
                .ordered_transactions
                .iter()
                .map(|inner| inner.transaction.clone())
                .collect::<Vec<_>>()
        );

        let mut substituted = reveal.clone();
        substituted.ordered_transactions[0]
            .transaction
            .receiver_uma_or_account = "attacker".to_string();
        assert!(substituted
            .validate_cryptographic_exact(
                &candidate,
                &envelopes,
                &shares_by_commitment,
                &verifier,
                &fixture.context,
                &fixture.validator_set,
                &fixture.cluster_map,
            )
            .unwrap_err()
            .contains("authenticated ciphertext plaintext"));
    }

    struct ExactScheduleNeutralFinalityAuthority {
        expected_context: TargetAdmissionContext,
        digest: EtdagDigest,
    }

    impl EtdagScheduleNeutralFinalityAuthority for ExactScheduleNeutralFinalityAuthority {
        fn canonical_finality_context_digest(
            &self,
            target_context: &TargetAdmissionContext,
        ) -> Result<EtdagDigest, String> {
            if target_context != &self.expected_context {
                return Err("test schedule-neutral finality context mismatch".to_string());
            }
            Ok(self.digest.clone())
        }
    }

    #[test]
    fn certified_input_ingress_requires_local_context_authenticated_peer_and_untampered_proof() {
        static INGRESS_TEST_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        let _guard = INGRESS_TEST_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap();
        reset_etdag_certified_input_ingress_for_test();

        let mut fixture = fixture(6, None);
        let protocol = ProtocolConfig::testnet_v3();
        let verifier = fixture.signer.verifier();
        let height_context = fixture.height_context.clone();
        let target_context = fixture.context.clone();
        let package = target_admission_package(&mut fixture, target_context);
        let protected = complete_protected_input(&mut fixture);
        let expected_finality_context = protected
            .boc
            .bvc
            .batch_candidate
            .canonical_finality_context_digest
            .clone();
        let artifact = CertifiedProtectedInputArtifact {
            admission_package: package,
            protected_input: protected.clone(),
        };
        let authenticated_peer = EtdagAuthenticatedIngressPeer {
            validator_id: fixture.validator_set.validators[0].validator_id.clone(),
            validator_uma_id: fixture.validator_set.validators[0].validator_uma_id.clone(),
            consensus_key_id: fixture.validator_set.validators[0]
                .consensus_public_key
                .key_id
                .clone(),
        };

        let missing_context =
            dispatch_etdag_certified_input(Some(authenticated_peer.clone()), artifact.clone())
                .unwrap_err();
        assert!(missing_context.contains("ingress is not running"));

        let ingress = EtdagCertifiedInputIngress::new(
            temp_protected_input_coordinator("network-ingress"),
            height_context.clone(),
            expected_finality_context.clone(),
            verifier.clone(),
            fixture.validator_set.clone(),
            fixture.cluster_map.clone(),
            protocol.clone(),
            EtdagParameters::default(),
        )
        .unwrap();
        install_etdag_certified_input_ingress(EtdagActivationPermit::test_only(), ingress).unwrap();

        let unauthenticated = dispatch_etdag_certified_input(None, artifact.clone()).unwrap_err();
        assert!(unauthenticated.contains("UNAUTHENTICATED_PEER"));

        let digest =
            dispatch_etdag_certified_input(Some(authenticated_peer.clone()), artifact.clone())
                .unwrap();
        assert_eq!(digest, protected_input_digest(&protected).unwrap());
        remove_etdag_certified_input_ingress().unwrap();

        let schedule_neutral_ingress = EtdagScheduleNeutralCertifiedInputIngress::new(
            temp_protected_input_coordinator("network-ingress-schedule-neutral"),
            Arc::new(ExactScheduleNeutralFinalityAuthority {
                expected_context: artifact.admission_package.context.clone(),
                digest: expected_finality_context.clone(),
            }),
            verifier.clone(),
            fixture.validator_set.clone(),
            fixture.cluster_map.clone(),
            artifact.admission_package.context.consensus_parameter_root,
            EtdagParameters::default(),
        )
        .unwrap();
        install_schedule_neutral_etdag_certified_input_ingress(
            EtdagActivationPermit::test_only(),
            schedule_neutral_ingress,
        )
        .unwrap();
        assert_eq!(
            dispatch_etdag_certified_input(Some(authenticated_peer.clone()), artifact.clone(),)
                .unwrap(),
            protected_input_digest(&protected).unwrap()
        );
        remove_etdag_certified_input_ingress().unwrap();

        let untrusted_ingress = EtdagCertifiedInputIngress::new(
            temp_protected_input_coordinator("network-ingress-untrusted"),
            height_context.clone(),
            expected_finality_context.clone(),
            verifier.clone(),
            fixture.validator_set.clone(),
            fixture.cluster_map.clone(),
            protocol.clone(),
            EtdagParameters::default(),
        )
        .unwrap();
        let untrusted_peer = EtdagAuthenticatedIngressPeer {
            validator_id: ValidatorId("untrusted-validator".to_string()),
            validator_uma_id: authenticated_peer.validator_uma_id.clone(),
            consensus_key_id: authenticated_peer.consensus_key_id.clone(),
        };
        assert!(untrusted_ingress
            .admit_from_authenticated_peer(&untrusted_peer, &artifact)
            .unwrap_err()
            .contains("UNTRUSTED_PEER"));

        let tamper_ingress = EtdagCertifiedInputIngress::new(
            temp_protected_input_coordinator("network-ingress-tamper"),
            height_context,
            expected_finality_context,
            verifier,
            fixture.validator_set,
            fixture.cluster_map,
            protocol,
            EtdagParameters::default(),
        )
        .unwrap();
        let mut tampered = artifact;
        tampered.protected_input.reveal.ordered_transactions[0]
            .transaction
            .receiver_uma_or_account = "tampered-recipient".to_string();
        assert!(tamper_ingress
            .admit_from_authenticated_peer(&authenticated_peer, &tampered)
            .is_err());
    }
}
