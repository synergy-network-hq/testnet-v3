use crate::consensus_parameters::ConsensusParameterRoot;
use blake3::Hasher;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_512};
use std::collections::BTreeSet;
use std::fmt;

pub const SYNERGY_TESTNET_V3_CHAIN_ID: u64 = 1266;
pub const SYNERGY_TESTNET_V3_NETWORK_ID: &str = "synergy-testnet-v3";
pub const TESTNET_V3_CHAIN_INCARNATION: u64 = 5;
pub const TESTNET_V3_CONSENSUS_STATE_SCHEMA_VERSION: u32 = 5;
pub const POSY_PROTOCOL_VERSION: &str = "posy/2.2";
pub const TESTNET_V3_CONSENSUS_SIGNATURE_ALGORITHM: &str = "mldsa65";
pub const TESTNET_V3_MLDSA65_PUBLIC_KEY_BYTES: usize = 1_952;
pub const HEIGHT_CONSENSUS_CONTEXT_VERSION: u32 = 1;
pub const TESTNET_V3_CLUSTER_SCHEDULE_VERSION: &str = "dynamic-v3-floor7";

pub trait CanonicalSerialize: Serialize + DeserializeOwned + Sized + PartialEq {
    fn canonical_bytes(&self) -> Result<Vec<u8>, String> {
        serde_json::to_vec(self).map_err(|error| format!("canonical serialize failed: {error}"))
    }

    fn assert_canonical_bytes(bytes: &[u8]) -> Result<Self, String> {
        let decoded: Self = serde_json::from_slice(bytes)
            .map_err(|error| format!("canonical decode failed: {error}"))?;
        let recoded = decoded.canonical_bytes()?;
        if recoded != bytes {
            return Err("non-canonical serialization rejected".to_string());
        }
        Ok(decoded)
    }
}

impl<T> CanonicalSerialize for T where T: Serialize + DeserializeOwned + Sized + PartialEq {}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(transparent)]
pub struct ChainId(pub u64);

impl ChainId {
    pub const fn synergy_testnet_v3() -> Self {
        Self(SYNERGY_TESTNET_V3_CHAIN_ID)
    }

    pub fn require_testnet_v3(self) -> Result<(), String> {
        if self.0 == SYNERGY_TESTNET_V3_CHAIN_ID {
            Ok(())
        } else {
            Err(format!(
                "wrong chain_id: expected {}, found {}",
                SYNERGY_TESTNET_V3_CHAIN_ID, self.0
            ))
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(transparent)]
pub struct NetworkId(pub String);

impl NetworkId {
    pub fn synergy_testnet_v3() -> Self {
        Self(SYNERGY_TESTNET_V3_NETWORK_ID.to_string())
    }

    pub fn require_testnet_v3(&self) -> Result<(), String> {
        if self.0 == SYNERGY_TESTNET_V3_NETWORK_ID {
            Ok(())
        } else {
            Err(format!(
                "wrong network_id: expected {}, found {}",
                SYNERGY_TESTNET_V3_NETWORK_ID, self.0
            ))
        }
    }
}

macro_rules! numeric_id {
    ($name:ident, $inner:ty) => {
        #[derive(
            Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash,
        )]
        #[serde(transparent)]
        pub struct $name(pub $inner);
    };
}

macro_rules! string_id {
    ($name:ident) => {
        #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
        #[serde(transparent)]
        pub struct $name(pub String);

        impl From<&str> for $name {
            fn from(value: &str) -> Self {
                Self(value.to_string())
            }
        }
    };
}

numeric_id!(Epoch, u64);
numeric_id!(Height, u64);
numeric_id!(Round, u64);
numeric_id!(ClusterId, u64);
string_id!(ValidatorId);
string_id!(UmaId);
string_id!(KeyId);
string_id!(AegisPqKeyId);

#[derive(Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(transparent)]
pub struct Hash(pub [u8; 32]);

impl Hash {
    pub const fn zero() -> Self {
        Self([0; 32])
    }

    pub fn from_domain_bytes(domain: &str, bytes: &[u8]) -> Self {
        let mut hasher = Hasher::new();
        hasher.update(domain.as_bytes());
        hasher.update(&(domain.len() as u64).to_be_bytes());
        hasher.update(bytes);
        Self(*hasher.finalize().as_bytes())
    }

    pub fn from_hex(value: &str) -> Result<Self, String> {
        let bytes = hex::decode(value.trim_start_matches("0x"))
            .map_err(|error| format!("invalid hash hex: {error}"))?;
        if bytes.len() != 32 {
            return Err(format!(
                "invalid hash length: expected 32, found {}",
                bytes.len()
            ));
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes);
        Ok(Self(out))
    }

    pub fn to_hex(self) -> String {
        hex::encode(self.0)
    }

    pub fn is_zero(self) -> bool {
        self.0 == [0; 32]
    }
}

impl fmt::Debug for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{}", self.to_hex())
    }
}

string_id!(TxId);
string_id!(BlockId);

impl TxId {
    pub fn from_hash(hash: Hash) -> Self {
        Self(hash.to_hex())
    }
}

impl BlockId {
    pub fn from_hash(hash: Hash) -> Self {
        Self(hash.to_hex())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AegisPqKeyRole {
    Transaction,
    ConsensusVote,
    ConsensusProposer,
    PeerIdentity,
    EpochTransition,
    ValidatorRegistration,
    ValidatorReadiness,
    Governance,
    Operator,
    ArchivePeer,
    ArchiveSnapshotSigner,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AegisPqPublicKey {
    pub key_id: AegisPqKeyId,
    pub algorithm: String,
    pub key_bytes: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AegisPqSignature {
    pub algorithm: String,
    pub signature_bytes: Vec<u8>,
}

impl AegisPqSignature {
    pub fn is_present(&self) -> bool {
        !self.algorithm.is_empty() && !self.signature_bytes.is_empty()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AegisPqVerificationResult {
    pub verified: bool,
    pub key_id: AegisPqKeyId,
    pub role: AegisPqKeyRole,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TxDependencyType {
    AccountSequence,
    ExplicitDependency,
    ResourceConflict,
    SxcpOrExternalProofDependency,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TxDependency {
    pub dependency_type: TxDependencyType,
    pub tx_id: TxId,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TxNodeStatus {
    PendingMissingDependencies,
    Ready,
    Selected,
    Finalized,
    Rejected,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Transaction {
    pub version: u32,
    pub chain_id: ChainId,
    pub network_id: NetworkId,
    pub epoch: Epoch,
    pub sender_uma_or_account: String,
    pub receiver_uma_or_account: String,
    pub account_nonce_or_sequence: u64,
    pub amount_nwei: u128,
    pub gas_limit: u64,
    pub max_fee_nwei: u128,
    pub ttl_height: Height,
    pub explicit_dependencies: Vec<TxDependency>,
    pub read_set_hint: Vec<String>,
    pub write_set_hint: Vec<String>,
    pub payload: Vec<u8>,
    pub signer_uma_id: UmaId,
    pub aegis_pq_key_id: AegisPqKeyId,
    pub aegis_pq_signature: AegisPqSignature,
}

#[derive(Debug, Clone, Serialize)]
struct TransactionSigningPayload<'a> {
    pub version: u32,
    pub chain_id: ChainId,
    pub network_id: &'a NetworkId,
    pub epoch: Epoch,
    pub sender_uma_or_account: &'a str,
    pub receiver_uma_or_account: &'a str,
    pub account_nonce_or_sequence: u64,
    pub amount_nwei: u128,
    pub gas_limit: u64,
    pub max_fee_nwei: u128,
    pub ttl_height: Height,
    pub explicit_dependencies: &'a [TxDependency],
    pub read_set_hint: &'a [String],
    pub write_set_hint: &'a [String],
    pub payload: &'a [u8],
    pub signer_uma_id: &'a UmaId,
    pub aegis_pq_key_id: &'a AegisPqKeyId,
}

impl Transaction {
    pub fn signing_bytes(&self) -> Result<Vec<u8>, String> {
        serde_json::to_vec(&TransactionSigningPayload {
            version: self.version,
            chain_id: self.chain_id,
            network_id: &self.network_id,
            epoch: self.epoch,
            sender_uma_or_account: &self.sender_uma_or_account,
            receiver_uma_or_account: &self.receiver_uma_or_account,
            account_nonce_or_sequence: self.account_nonce_or_sequence,
            amount_nwei: self.amount_nwei,
            gas_limit: self.gas_limit,
            max_fee_nwei: self.max_fee_nwei,
            ttl_height: self.ttl_height,
            explicit_dependencies: &self.explicit_dependencies,
            read_set_hint: &self.read_set_hint,
            write_set_hint: &self.write_set_hint,
            payload: &self.payload,
            signer_uma_id: &self.signer_uma_id,
            aegis_pq_key_id: &self.aegis_pq_key_id,
        })
        .map_err(|error| format!("transaction signing payload serialize failed: {error}"))
    }

    pub fn canonical_tx_bytes_hash(&self) -> Result<Hash, String> {
        Ok(Hash::from_domain_bytes(
            "SYNERGY_TX_CANONICAL_BYTES_V1",
            &self.canonical_bytes()?,
        ))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TxNode {
    pub tx_id: TxId,
    pub canonical_tx_bytes_hash: Hash,
    pub sender_uma_or_account: String,
    pub account_nonce_or_sequence: u64,
    pub explicit_dependencies: Vec<TxDependency>,
    pub inferred_dependencies: Vec<TxDependency>,
    pub read_set_hint: Vec<String>,
    pub write_set_hint: Vec<String>,
    pub gas_limit: u64,
    pub max_fee_nwei: u128,
    pub aegis_pq_signature: AegisPqSignature,
    pub aegis_pq_key_id: AegisPqKeyId,
    pub admission_epoch: Epoch,
    pub admission_height: Height,
    pub status: TxNodeStatus,
}

/// Returns the only validator-cluster schedule permitted for Testnet-v3.
///
/// The values below intentionally preserve a defined result for small unit-test
/// sets while the launch configuration separately enforces the six-validator
/// minimum. For every launch-relevant active set (N >= 6), this is exactly:
/// 6-9 => 1, 10-20 => 2, and floor(N / 7) for N >= 21.
pub fn testnet_v3_cluster_count(active_validator_count: usize) -> usize {
    if active_validator_count == 0 {
        0
    } else if active_validator_count < 10 {
        1
    } else if active_validator_count < 21 {
        2
    } else {
        active_validator_count / 7
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HeightConsensusContextSpec {
    pub protocol_version: String,
    pub height: Height,
    pub epoch: Epoch,
    pub assigned_cluster_id: ClusterId,
    pub cluster_schedule_version: String,
    pub finalized_epoch_seed_root: Hash,
    pub assigned_height_schedule_root: Hash,
    pub cryptographic_profile_root: Hash,
    pub prior_finalized_qc_or_transition_root: Hash,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct ConsensusKeyCommitment {
    validator_id: ValidatorId,
    key_id: AegisPqKeyId,
    algorithm: String,
    public_key_hash: Hash,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct FrozenBondedWeight {
    validator_id: ValidatorId,
    voting_weight: u64,
}

/// The single immutable consensus authority for one block height.
///
/// This is not a chain-state import or an historical snapshot. Height 1 is
/// derived from the finalized Testnet-v3 genesis inputs; later heights are
/// derived from the prior finalized QC or certified epoch transition.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HeightConsensusContext {
    pub context_version: u32,
    pub chain_id: ChainId,
    pub network_id: NetworkId,
    pub protocol_version: String,
    pub height: Height,
    pub epoch: Epoch,
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
    pub leader_schedule: Vec<ValidatorId>,
    pub leader_schedule_root: Hash,
    pub consensus_parameter_root: ConsensusParameterRoot,
    pub cryptographic_profile_root: Hash,
    pub prior_finalized_qc_or_transition_root: Hash,
}

impl HeightConsensusContext {
    pub fn derive(
        spec: HeightConsensusContextSpec,
        validator_set: &ValidatorSet,
        cluster_map: &ClusterMap,
        protocol_config: &ProtocolConfig,
    ) -> Result<Self, String> {
        spec_validate(&spec)?;
        protocol_config.chain_id.require_testnet_v3()?;
        protocol_config.network_id.require_testnet_v3()?;
        if validator_set.epoch != spec.epoch {
            return Err("height context validator-set epoch mismatch".to_string());
        }
        if cluster_map.epoch != spec.epoch {
            return Err("height context cluster-map epoch mismatch".to_string());
        }

        let active_set = validator_set.active_for_epoch(spec.epoch);
        if active_set.validators.is_empty() {
            return Err("height context active validator set is empty".to_string());
        }
        active_set.validate_unique_validator_and_key_ids()?;

        let expected_cluster_map = ClusterMap::derive_from_finalized_epoch_seed(
            &active_set,
            spec.finalized_epoch_seed_root,
        )?;
        if cluster_map.canonicalized() != expected_cluster_map {
            return Err(
                "cluster map is not the deterministic finalized-epoch-seed assignment".to_string(),
            );
        }
        cluster_map.validate_complete_balanced_assignment(&active_set)?;

        let assigned_members = active_set.active_for_cluster(spec.assigned_cluster_id);
        if assigned_members.is_empty() {
            return Err("assigned cluster has no eligible validators".to_string());
        }
        let assigned_cluster_validator_count = u64::try_from(assigned_members.len())
            .map_err(|_| "assigned cluster validator count exceeds u64".to_string())?;
        let assigned_cluster_total_voting_weight = checked_total_weight(&assigned_members)?;
        if assigned_cluster_total_voting_weight == 0 {
            return Err("assigned cluster total voting weight is zero".to_string());
        }

        let active_validator_set_root = active_set.hash()?;
        let validator_consensus_key_root = active_set.consensus_key_root()?;
        let frozen_bonded_weight_root = active_set.frozen_bonded_weight_root()?;
        let cluster_map_root = cluster_map.hash()?;
        let assigned_cluster_membership_root = assigned_cluster_membership_root(
            spec.epoch,
            spec.assigned_cluster_id,
            &assigned_members,
        )?;
        let leader_schedule = derive_leader_schedule(
            spec.height,
            spec.assigned_cluster_id,
            spec.finalized_epoch_seed_root,
            cluster_map_root,
            &assigned_members,
        )?;
        let leader_schedule_root = Hash::from_domain_bytes(
            "SYNERGY_POSY_LEADER_SCHEDULE_V1",
            &leader_schedule.canonical_bytes()?,
        );
        let consensus_parameter_root = protocol_config.hash()?;

        let context = Self {
            context_version: HEIGHT_CONSENSUS_CONTEXT_VERSION,
            chain_id: ChainId::synergy_testnet_v3(),
            network_id: NetworkId::synergy_testnet_v3(),
            protocol_version: spec.protocol_version,
            height: spec.height,
            epoch: spec.epoch,
            active_validator_set_root,
            validator_consensus_key_root,
            frozen_bonded_weight_root,
            cluster_schedule_version: spec.cluster_schedule_version,
            finalized_epoch_seed_root: spec.finalized_epoch_seed_root,
            assigned_height_schedule_root: spec.assigned_height_schedule_root,
            cluster_map_root,
            assigned_cluster_id: spec.assigned_cluster_id,
            assigned_cluster_membership_root,
            assigned_cluster_validator_count,
            assigned_cluster_total_voting_weight,
            leader_schedule,
            leader_schedule_root,
            consensus_parameter_root,
            cryptographic_profile_root: spec.cryptographic_profile_root,
            prior_finalized_qc_or_transition_root: spec.prior_finalized_qc_or_transition_root,
        };
        context.validate()?;
        Ok(context)
    }

    pub fn root(&self) -> Result<Hash, String> {
        self.validate()?;
        Ok(Hash::from_domain_bytes(
            "SYNERGY_HEIGHT_CONSENSUS_CONTEXT_V1",
            &self.canonical_bytes()?,
        ))
    }

    pub fn validate(&self) -> Result<(), String> {
        self.chain_id.require_testnet_v3()?;
        self.network_id.require_testnet_v3()?;
        if self.context_version != HEIGHT_CONSENSUS_CONTEXT_VERSION {
            return Err(format!(
                "unsupported height context version: expected {}, found {}",
                HEIGHT_CONSENSUS_CONTEXT_VERSION, self.context_version
            ));
        }
        if self.protocol_version != POSY_PROTOCOL_VERSION {
            return Err(format!(
                "wrong PoSy protocol version: expected {}, found {}",
                POSY_PROTOCOL_VERSION, self.protocol_version
            ));
        }
        if self.height.0 == 0 {
            return Err("height context cannot target genesis height zero".to_string());
        }
        if self.cluster_schedule_version != TESTNET_V3_CLUSTER_SCHEDULE_VERSION {
            return Err(format!(
                "wrong cluster schedule version: expected {}, found {}",
                TESTNET_V3_CLUSTER_SCHEDULE_VERSION, self.cluster_schedule_version
            ));
        }
        for (name, root) in [
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
            ("leader_schedule_root", self.leader_schedule_root),
            (
                "cryptographic_profile_root",
                self.cryptographic_profile_root,
            ),
            (
                "prior_finalized_qc_or_transition_root",
                self.prior_finalized_qc_or_transition_root,
            ),
        ] {
            if root.is_zero() {
                return Err(format!("height context {name} is missing"));
            }
        }
        if self.consensus_parameter_root.is_zero() {
            return Err("height context consensus_parameter_root is missing".to_string());
        }
        if self.assigned_cluster_validator_count == 0 {
            return Err("assigned cluster validator count is zero".to_string());
        }
        if self.assigned_cluster_total_voting_weight == 0 {
            return Err("assigned cluster total voting weight is zero".to_string());
        }
        if self.leader_schedule.len() as u64 != self.assigned_cluster_validator_count {
            return Err(
                "leader schedule does not contain every assigned-cluster validator".to_string(),
            );
        }
        let unique_leaders = self.leader_schedule.iter().collect::<BTreeSet<_>>();
        if unique_leaders.len() != self.leader_schedule.len() {
            return Err("leader schedule contains duplicate validators".to_string());
        }
        let recomputed_leader_root = Hash::from_domain_bytes(
            "SYNERGY_POSY_LEADER_SCHEDULE_V1",
            &self.leader_schedule.canonical_bytes()?,
        );
        if recomputed_leader_root != self.leader_schedule_root {
            return Err("leader schedule root mismatch".to_string());
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
            return Err(
                "height context consensus parameter root does not match frozen parameters"
                    .to_string(),
            );
        }
        let expected = Self::derive(
            HeightConsensusContextSpec {
                protocol_version: self.protocol_version.clone(),
                height: self.height,
                epoch: self.epoch,
                assigned_cluster_id: self.assigned_cluster_id,
                cluster_schedule_version: self.cluster_schedule_version.clone(),
                finalized_epoch_seed_root: self.finalized_epoch_seed_root,
                assigned_height_schedule_root: self.assigned_height_schedule_root,
                cryptographic_profile_root: self.cryptographic_profile_root,
                prior_finalized_qc_or_transition_root: self.prior_finalized_qc_or_transition_root,
            },
            validator_set,
            cluster_map,
            protocol_config,
        )?;
        if &expected != self {
            return Err("height consensus context does not match frozen inputs".to_string());
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
            return Err("height context epoch does not match validator/cluster inputs".to_string());
        }
        let active_set = validator_set.active_for_epoch(self.epoch);
        active_set.validate_unique_validator_and_key_ids()?;
        let expected_map = ClusterMap::derive_from_finalized_epoch_seed(
            &active_set,
            self.finalized_epoch_seed_root,
        )?;
        if cluster_map.canonicalized() != expected_map {
            return Err("height context cluster map is not deterministic".to_string());
        }
        cluster_map.validate_complete_balanced_assignment(&active_set)?;
        if self.active_validator_set_root != active_set.hash()?
            || self.validator_consensus_key_root != active_set.consensus_key_root()?
            || self.frozen_bonded_weight_root != active_set.frozen_bonded_weight_root()?
            || self.cluster_map_root != cluster_map.hash()?
        {
            return Err("height context validator/key/weight/cluster root mismatch".to_string());
        }
        let members = active_set.active_for_cluster(self.assigned_cluster_id);
        let member_count = u64::try_from(members.len())
            .map_err(|_| "assigned cluster member count exceeds u64".to_string())?;
        let total_weight = checked_total_weight(&members)?;
        let membership_root =
            assigned_cluster_membership_root(self.epoch, self.assigned_cluster_id, &members)?;
        if self.assigned_cluster_validator_count != member_count
            || self.assigned_cluster_total_voting_weight != total_weight
            || self.assigned_cluster_membership_root != membership_root
        {
            return Err("height context assigned-cluster binding mismatch".to_string());
        }
        let schedule = derive_leader_schedule(
            self.height,
            self.assigned_cluster_id,
            self.finalized_epoch_seed_root,
            self.cluster_map_root,
            &members,
        )?;
        if self.leader_schedule != schedule {
            return Err("height context leader schedule mismatch".to_string());
        }
        Ok(())
    }

    pub fn authorized_proposer(&self, round: Round) -> Result<&ValidatorId, String> {
        self.validate()?;
        let len = self.leader_schedule.len() as u64;
        let index = self
            .height
            .0
            .checked_add(round.0)
            .ok_or_else(|| "leader schedule height/round overflow".to_string())?
            % len;
        self.leader_schedule
            .get(index as usize)
            .ok_or_else(|| "authorized proposer missing from leader schedule".to_string())
    }

    pub fn require_authorized_proposer(
        &self,
        round: Round,
        proposer: &ValidatorId,
    ) -> Result<(), String> {
        let authorized = self.authorized_proposer(round)?;
        if authorized != proposer {
            return Err(format!(
                "unauthorized proposer for height {} round {}: expected {}, found {}",
                self.height.0, round.0, authorized.0, proposer.0
            ));
        }
        Ok(())
    }

    pub fn strict_count_quorum(&self) -> Result<u64, String> {
        strict_quorum(self.assigned_cluster_validator_count)
    }

    pub fn strict_weight_quorum(&self) -> Result<u64, String> {
        strict_quorum(self.assigned_cluster_total_voting_weight)
    }
}

fn spec_validate(spec: &HeightConsensusContextSpec) -> Result<(), String> {
    if spec.protocol_version != POSY_PROTOCOL_VERSION {
        return Err(format!(
            "height context spec protocol version must be {}",
            POSY_PROTOCOL_VERSION
        ));
    }
    if spec.height.0 == 0 {
        return Err("height context spec height must be at least one".to_string());
    }
    if spec.cluster_schedule_version != TESTNET_V3_CLUSTER_SCHEDULE_VERSION {
        return Err(format!(
            "height context spec cluster schedule must be {}",
            TESTNET_V3_CLUSTER_SCHEDULE_VERSION
        ));
    }
    for (name, root) in [
        ("finalized_epoch_seed_root", spec.finalized_epoch_seed_root),
        (
            "assigned_height_schedule_root",
            spec.assigned_height_schedule_root,
        ),
        (
            "cryptographic_profile_root",
            spec.cryptographic_profile_root,
        ),
        (
            "prior_finalized_qc_or_transition_root",
            spec.prior_finalized_qc_or_transition_root,
        ),
    ] {
        if root.is_zero() {
            return Err(format!("height context spec {name} is missing"));
        }
    }
    Ok(())
}

fn strict_quorum(total: u64) -> Result<u64, String> {
    if total == 0 {
        return Err("strict quorum denominator is zero".to_string());
    }
    let total = u128::from(total);
    let threshold = total
        .checked_mul(2)
        .ok_or_else(|| "strict quorum multiplication overflow".to_string())?
        / 3
        + 1;
    u64::try_from(threshold).map_err(|_| "strict quorum exceeds u64".to_string())
}

fn checked_total_weight(validators: &[ValidatorRecord]) -> Result<u64, String> {
    validators.iter().try_fold(0u64, |total, validator| {
        total
            .checked_add(validator.voting_weight)
            .ok_or_else(|| "validator voting-weight total overflow".to_string())
    })
}

fn assigned_cluster_membership_root(
    epoch: Epoch,
    cluster_id: ClusterId,
    validators: &[ValidatorRecord],
) -> Result<Hash, String> {
    let mut member_ids = validators
        .iter()
        .map(|validator| validator.validator_id.clone())
        .collect::<Vec<_>>();
    member_ids.sort();
    Ok(Hash::from_domain_bytes(
        "SYNERGY_ASSIGNED_CLUSTER_MEMBERSHIP_V1",
        &(epoch, cluster_id, member_ids).canonical_bytes()?,
    ))
}

fn derive_leader_schedule(
    height: Height,
    cluster_id: ClusterId,
    finalized_epoch_seed_root: Hash,
    cluster_map_root: Hash,
    validators: &[ValidatorRecord],
) -> Result<Vec<ValidatorId>, String> {
    let mut ranked = validators
        .iter()
        .map(|validator| {
            let mut hasher = Sha3_512::new();
            hasher.update(b"PoSy/LeaderSchedule/v2.1");
            hasher.update(finalized_epoch_seed_root.0);
            hasher.update(cluster_map_root.0);
            hasher.update(cluster_id.0.to_be_bytes());
            hasher.update(height.0.to_be_bytes());
            hasher.update((validator.validator_id.0.len() as u64).to_be_bytes());
            hasher.update(validator.validator_id.0.as_bytes());
            (hasher.finalize().to_vec(), validator.validator_id.clone())
        })
        .collect::<Vec<_>>();
    ranked.sort_by(|left, right| left.0.cmp(&right.0).then_with(|| left.1.cmp(&right.1)));
    Ok(ranked
        .into_iter()
        .map(|(_, validator_id)| validator_id)
        .collect())
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProtectedBatchCommitment {
    pub profile_id: String,
    pub target_context_root: String,
    pub boc_digest: String,
    pub dcc_digest: String,
    pub encrypted_set_root: String,
    pub protected_order_root: String,
    pub public_reveal_transcript_root: String,
    pub execution_manifest_root: String,
    pub protected_gas_total: u64,
    pub protected_count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BlockHeader {
    pub version: u32,
    pub chain_id: ChainId,
    pub network_id: NetworkId,
    pub protocol_version: String,
    pub height: Height,
    pub round: Round,
    pub epoch: Epoch,
    pub cluster_id: ClusterId,
    pub height_context_root: Hash,
    pub parent_block_hash: Hash,
    pub parent_state_root: Hash,
    pub last_finalized_qc_hash: Hash,
    pub proposer_validator_id: ValidatorId,
    pub proposer_uma_id: UmaId,
    pub proposer_key_id: AegisPqKeyId,
    pub active_validator_set_hash: Hash,
    pub eligible_validator_set_hash: Hash,
    pub validator_consensus_key_root: Hash,
    pub frozen_bonded_weight_root: Hash,
    pub cluster_schedule_version: String,
    pub cluster_map_hash: Hash,
    pub assigned_cluster_membership_root: Hash,
    pub assigned_cluster_validator_count: u64,
    pub assigned_cluster_total_voting_weight: u64,
    pub proposer_schedule_hash: Hash,
    pub protocol_config_hash: ConsensusParameterRoot,
    pub cryptographic_profile_root: Hash,
    pub dag_frontier_root: Hash,
    pub tx_order_root: Hash,
    pub tx_count: u64,
    #[serde(default)]
    pub protected_batch: Option<ProtectedBatchCommitment>,
    pub evidence_root: Hash,
    pub state_root_before: Hash,
    pub state_root_after: Hash,
    pub receipt_root: Hash,
    pub app_version: u32,
    pub execution_version: u32,
    pub dag_version: u32,
    pub aegis_pqvm_version: String,
    pub timestamp_ms_consensus_bounded: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Block {
    pub header: BlockHeader,
    pub transactions: Vec<Transaction>,
    pub proposer_signature: AegisPqSignature,
}

impl Block {
    pub fn block_id(&self) -> Result<BlockId, String> {
        Ok(BlockId::from_hash(Hash::from_domain_bytes(
            "SYNERGY_BLOCK_ID_V1",
            &self.header.canonical_bytes()?,
        )))
    }

    /// Stable candidate identity excludes only proposal-envelope fields that
    /// legitimately change during TC-authorized carry-forward.
    pub fn candidate_id(&self) -> Result<BlockId, String> {
        let mut stable_header = self.header.clone();
        stable_header.round = Round(0);
        stable_header.proposer_validator_id = ValidatorId(String::new());
        stable_header.proposer_uma_id = UmaId(String::new());
        stable_header.proposer_key_id = AegisPqKeyId(String::new());
        let stable = StableBlockCandidate {
            header: stable_header,
            transactions: self.transactions.clone(),
        };
        Ok(BlockId::from_hash(Hash::from_domain_bytes(
            "SYNERGY_STABLE_CANDIDATE_ID_V1",
            &stable.canonical_bytes()?,
        )))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct StableBlockCandidate {
    header: BlockHeader,
    transactions: Vec<Transaction>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum VotePhase {
    Validate,
    Finality,
    Timeout,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ConsensusSubjectPhase {
    Proposal,
    Validate,
    Finality,
    Timeout,
}

impl From<&VotePhase> for ConsensusSubjectPhase {
    fn from(value: &VotePhase) -> Self {
        match value {
            VotePhase::Validate => Self::Validate,
            VotePhase::Finality => Self::Finality,
            VotePhase::Timeout => Self::Timeout,
        }
    }
}

/// Canonical logical identity of one typed PoSy consensus decision.
///
/// Cryptographic evidence proves this subject but is deliberately absent from
/// it. In particular, signer ordering/subsets, signature bytes, signer
/// bitmaps, certificate serialization, and proof roots must never make two
/// otherwise identical decisions compare unequal.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ConsensusSubject {
    pub domain: ConsensusDomain,
    pub chain_id: ChainId,
    pub network_id: NetworkId,
    pub protocol_version: String,
    pub epoch: Epoch,
    pub height: Height,
    pub round: Round,
    pub cluster_id: ClusterId,
    pub height_context_root: Hash,
    pub phase: ConsensusSubjectPhase,
    pub candidate_id: Option<BlockId>,
    /// The round at which this subject itself prepares/finalizes a candidate.
    ///
    /// Timeout carry evidence currently commits to the prepared certificate
    /// root rather than embedding its round, so timeout subjects leave this
    /// field absent and compare their carried candidate independently of the
    /// selected proof representation.
    pub prepared_round: Option<Round>,
}

impl ConsensusSubject {
    pub fn digest(&self) -> Result<Hash, String> {
        self.domain.validate()?;
        if self.domain.chain_id != self.chain_id {
            return Err("canonical consensus subject domain chain mismatch".to_string());
        }
        let bytes = serde_json::to_vec(self)
            .map_err(|error| format!("canonical consensus subject serialize failed: {error}"))?;
        Ok(Hash::from_domain_bytes(
            "SYNERGY_CONSENSUS_SUBJECT_V1",
            &bytes,
        ))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ConsensusDomain {
    pub chain_id: ChainId,
    pub chain_incarnation: u64,
    pub genesis_hash: Hash,
}

impl ConsensusDomain {
    pub fn validate(&self) -> Result<(), String> {
        self.chain_id.require_testnet_v3()?;
        if self.chain_incarnation != TESTNET_V3_CHAIN_INCARNATION || self.genesis_hash.is_zero() {
            return Err("wrong or incomplete Chain 1266 consensus domain".to_string());
        }
        Ok(())
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, String> {
        self.validate()?;
        serde_json::to_vec(self)
            .map_err(|error| format!("canonical consensus domain serialize failed: {error}"))
    }
}

pub fn current_consensus_domain() -> Result<ConsensusDomain, String> {
    let genesis = crate::genesis::canonical_genesis()?;
    let domain = ConsensusDomain {
        chain_id: ChainId(genesis.chain_id()),
        chain_incarnation: genesis.chain_incarnation(),
        genesis_hash: Hash::from_hex(genesis.hash())?,
    };
    domain.validate()?;
    Ok(domain)
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Vote {
    pub chain_id: ChainId,
    pub network_id: NetworkId,
    pub protocol_version: String,
    pub height: Height,
    pub round: Round,
    pub epoch: Epoch,
    pub cluster_id: ClusterId,
    pub height_context_root: Hash,
    pub phase: VotePhase,
    pub block_id: BlockId,
    pub highest_prepared_vc_root: Option<Hash>,
    pub validator_id: ValidatorId,
    pub validator_uma_id: UmaId,
    pub key_id: AegisPqKeyId,
    pub active_validator_set_hash: Hash,
    pub cluster_map_hash: Hash,
    pub aegis_pq_signature: AegisPqSignature,
}

#[derive(Debug, Clone, Serialize)]
struct VoteSigningPayload<'a> {
    pub chain_id: ChainId,
    pub network_id: &'a NetworkId,
    pub protocol_version: &'a str,
    pub height: Height,
    pub round: Round,
    pub epoch: Epoch,
    pub cluster_id: ClusterId,
    pub height_context_root: Hash,
    pub phase: &'a VotePhase,
    pub block_id: &'a BlockId,
    pub highest_prepared_vc_root: Option<Hash>,
    pub validator_id: &'a ValidatorId,
    pub validator_uma_id: &'a UmaId,
    pub key_id: &'a AegisPqKeyId,
    pub active_validator_set_hash: Hash,
    pub cluster_map_hash: Hash,
}

impl Vote {
    pub fn signing_bytes(&self) -> Result<Vec<u8>, String> {
        serde_json::to_vec(&VoteSigningPayload {
            chain_id: self.chain_id,
            network_id: &self.network_id,
            protocol_version: &self.protocol_version,
            height: self.height,
            round: self.round,
            epoch: self.epoch,
            cluster_id: self.cluster_id,
            height_context_root: self.height_context_root,
            phase: &self.phase,
            block_id: &self.block_id,
            highest_prepared_vc_root: self.highest_prepared_vc_root,
            validator_id: &self.validator_id,
            validator_uma_id: &self.validator_uma_id,
            key_id: &self.key_id,
            active_validator_set_hash: self.active_validator_set_hash,
            cluster_map_hash: self.cluster_map_hash,
        })
        .map_err(|error| format!("vote signing payload serialize failed: {error}"))
    }

    pub fn consensus_subject(&self) -> Result<ConsensusSubject, String> {
        let carries_candidate = !self.block_id.0.is_empty();
        match self.phase {
            VotePhase::Validate | VotePhase::Finality => {
                if !carries_candidate || self.highest_prepared_vc_root.is_some() {
                    return Err(
                        "validate/finality vote has a malformed consensus subject".to_string()
                    );
                }
            }
            VotePhase::Timeout => {
                if carries_candidate != self.highest_prepared_vc_root.is_some() {
                    return Err(
                        "timeout vote prepared proof and candidate must appear together"
                            .to_string(),
                    );
                }
            }
        }
        Ok(ConsensusSubject {
            domain: current_consensus_domain()?,
            chain_id: self.chain_id,
            network_id: self.network_id.clone(),
            protocol_version: self.protocol_version.clone(),
            epoch: self.epoch,
            height: self.height,
            round: self.round,
            cluster_id: self.cluster_id,
            height_context_root: self.height_context_root,
            phase: ConsensusSubjectPhase::from(&self.phase),
            candidate_id: carries_candidate.then(|| self.block_id.clone()),
            prepared_round: matches!(self.phase, VotePhase::Validate | VotePhase::Finality)
                .then_some(self.round),
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct QuorumCertificate {
    pub qc_version: u32,
    pub chain_id: ChainId,
    pub network_id: NetworkId,
    pub protocol_version: String,
    pub height: Height,
    pub round: Round,
    pub epoch: Epoch,
    pub cluster_id: ClusterId,
    pub height_context_root: Hash,
    pub phase: VotePhase,
    pub block_id: BlockId,
    pub highest_prepared_vc_root: Option<Hash>,
    pub active_validator_set_hash: Hash,
    pub cluster_map_hash: Hash,
    pub threshold_weight_required: u64,
    pub signed_weight: u64,
    pub signer_bitmap: Vec<u8>,
    pub aegis_pq_signatures: Vec<AegisPqSignature>,
    pub aegis_pq_key_ids: Vec<AegisPqKeyId>,
}

impl QuorumCertificate {
    pub fn root(&self) -> Result<Hash, String> {
        Ok(Hash::from_domain_bytes(
            "SYNERGY_QUORUM_CERTIFICATE_V1",
            &self.canonical_bytes()?,
        ))
    }

    pub fn consensus_subject(&self) -> Result<ConsensusSubject, String> {
        let carries_candidate = !self.block_id.0.is_empty();
        match self.phase {
            VotePhase::Validate | VotePhase::Finality => {
                if !carries_candidate || self.highest_prepared_vc_root.is_some() {
                    return Err(
                        "validate/finality certificate has a malformed consensus subject"
                            .to_string(),
                    );
                }
            }
            VotePhase::Timeout => {
                if carries_candidate != self.highest_prepared_vc_root.is_some() {
                    return Err(
                        "timeout certificate prepared proof and candidate must appear together"
                            .to_string(),
                    );
                }
            }
        }
        Ok(ConsensusSubject {
            domain: current_consensus_domain()?,
            chain_id: self.chain_id,
            network_id: self.network_id.clone(),
            protocol_version: self.protocol_version.clone(),
            epoch: self.epoch,
            height: self.height,
            round: self.round,
            cluster_id: self.cluster_id,
            height_context_root: self.height_context_root,
            phase: ConsensusSubjectPhase::from(&self.phase),
            candidate_id: carries_candidate.then(|| self.block_id.clone()),
            prepared_round: matches!(self.phase, VotePhase::Validate | VotePhase::Finality)
                .then_some(self.round),
        })
    }

    /// The deterministic finalized-authority binding for the next height.
    ///
    /// A QC's full evidence root intentionally includes its signer bitmap and
    /// ML-DSA signatures, so two valid strict-quorum certificates for the
    /// same finalized subject can have distinct roots. That evidence remains
    /// durable and auditable through [`Self::root`], but it must never choose
    /// a different successor height context based on message timing. This
    /// root commits only to the certificate subject and immutable verifier
    /// context shared by every valid QC for that subject.
    pub fn finality_context_root(&self) -> Result<Hash, String> {
        #[derive(Serialize)]
        struct FinalityContextSubject<'a> {
            qc_version: u32,
            chain_id: ChainId,
            network_id: &'a NetworkId,
            protocol_version: &'a str,
            height: Height,
            round: Round,
            epoch: Epoch,
            cluster_id: ClusterId,
            height_context_root: Hash,
            phase: &'a VotePhase,
            block_id: &'a BlockId,
            highest_prepared_vc_root: Option<Hash>,
            active_validator_set_hash: Hash,
            cluster_map_hash: Hash,
            threshold_weight_required: u64,
        }
        let subject = FinalityContextSubject {
            qc_version: self.qc_version,
            chain_id: self.chain_id,
            network_id: &self.network_id,
            protocol_version: &self.protocol_version,
            height: self.height,
            round: self.round,
            epoch: self.epoch,
            cluster_id: self.cluster_id,
            height_context_root: self.height_context_root,
            phase: &self.phase,
            block_id: &self.block_id,
            highest_prepared_vc_root: self.highest_prepared_vc_root,
            active_validator_set_hash: self.active_validator_set_hash,
            cluster_map_hash: self.cluster_map_hash,
            threshold_weight_required: self.threshold_weight_required,
        };
        let bytes = serde_json::to_vec(&subject)
            .map_err(|error| format!("canonicalize finality context subject: {error}"))?;
        Ok(Hash::from_domain_bytes(
            "SYNERGY_FINALITY_CONTEXT_SUBJECT_V1",
            &bytes,
        ))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ValidationCertificate {
    pub certificate_version: u32,
    pub chain_id: ChainId,
    pub network_id: NetworkId,
    pub protocol_version: String,
    pub height: Height,
    pub round: Round,
    pub epoch: Epoch,
    pub cluster_id: ClusterId,
    pub height_context_root: Hash,
    pub candidate_id: BlockId,
    pub active_validator_set_hash: Hash,
    pub cluster_map_hash: Hash,
    pub threshold_weight_required: u64,
    pub signed_weight: u64,
    pub signer_bitmap: Vec<u8>,
    pub aegis_pq_signatures: Vec<AegisPqSignature>,
    pub aegis_pq_key_ids: Vec<AegisPqKeyId>,
}

impl ValidationCertificate {
    pub fn root(&self) -> Result<Hash, String> {
        Ok(Hash::from_domain_bytes(
            "SYNERGY_VALIDATION_CERTIFICATE_V1",
            &self.canonical_bytes()?,
        ))
    }

    pub fn consensus_subject(&self) -> Result<ConsensusSubject, String> {
        self.as_verification_certificate().consensus_subject()
    }

    pub fn as_verification_certificate(&self) -> QuorumCertificate {
        QuorumCertificate {
            qc_version: self.certificate_version,
            chain_id: self.chain_id,
            network_id: self.network_id.clone(),
            protocol_version: self.protocol_version.clone(),
            height: self.height,
            round: self.round,
            epoch: self.epoch,
            cluster_id: self.cluster_id,
            height_context_root: self.height_context_root,
            phase: VotePhase::Validate,
            block_id: self.candidate_id.clone(),
            highest_prepared_vc_root: None,
            active_validator_set_hash: self.active_validator_set_hash,
            cluster_map_hash: self.cluster_map_hash,
            threshold_weight_required: self.threshold_weight_required,
            signed_weight: self.signed_weight,
            signer_bitmap: self.signer_bitmap.clone(),
            aegis_pq_signatures: self.aegis_pq_signatures.clone(),
            aegis_pq_key_ids: self.aegis_pq_key_ids.clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TimeoutCertificate {
    pub certificate_version: u32,
    pub chain_id: ChainId,
    pub network_id: NetworkId,
    pub protocol_version: String,
    pub height: Height,
    pub closing_round: Round,
    pub next_round: Round,
    pub epoch: Epoch,
    pub cluster_id: ClusterId,
    pub height_context_root: Hash,
    pub highest_prepared_vc_root: Option<Hash>,
    pub carry_forward_candidate_id: Option<BlockId>,
    pub active_validator_set_hash: Hash,
    pub cluster_map_hash: Hash,
    pub threshold_weight_required: u64,
    pub signed_weight: u64,
    pub signer_bitmap: Vec<u8>,
    pub aegis_pq_signatures: Vec<AegisPqSignature>,
    pub aegis_pq_key_ids: Vec<AegisPqKeyId>,
    /// Per-signer timeout subjects, aligned with the signature/key vectors.
    ///
    /// Timeout votes close one height/round and may legitimately report
    /// different local prepared knowledge.  Version-1 certificates omitted
    /// this vector and therefore supported only a homogeneous timeout
    /// subject.  Version-2 certificates retain every signed subject while the
    /// certificate-level fields select the sole prepared candidate and the
    /// lexicographically smallest valid proof root reported for that candidate,
    /// if one exists.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub timeout_vote_subjects: Vec<TimeoutVoteSubject>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TimeoutVoteSubject {
    pub block_id: BlockId,
    pub highest_prepared_vc_root: Option<Hash>,
}

impl TimeoutCertificate {
    pub fn root(&self) -> Result<Hash, String> {
        Ok(Hash::from_domain_bytes(
            "SYNERGY_TIMEOUT_CERTIFICATE_V1",
            &self.canonical_bytes()?,
        ))
    }

    pub fn consensus_subject(&self) -> Result<ConsensusSubject, String> {
        self.as_verification_certificate().consensus_subject()
    }

    pub fn as_verification_certificate(&self) -> QuorumCertificate {
        QuorumCertificate {
            qc_version: self.certificate_version,
            chain_id: self.chain_id,
            network_id: self.network_id.clone(),
            protocol_version: self.protocol_version.clone(),
            height: self.height,
            round: self.closing_round,
            epoch: self.epoch,
            cluster_id: self.cluster_id,
            height_context_root: self.height_context_root,
            phase: VotePhase::Timeout,
            block_id: self
                .carry_forward_candidate_id
                .clone()
                .unwrap_or_else(|| BlockId(String::new())),
            highest_prepared_vc_root: self.highest_prepared_vc_root,
            active_validator_set_hash: self.active_validator_set_hash,
            cluster_map_hash: self.cluster_map_hash,
            threshold_weight_required: self.threshold_weight_required,
            signed_weight: self.signed_weight,
            signer_bitmap: self.signer_bitmap.clone(),
            aegis_pq_signatures: self.aegis_pq_signatures.clone(),
            aegis_pq_key_ids: self.aegis_pq_key_ids.clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ValidatorStatus {
    Unknown,
    Registered,
    KeyBound,
    StakeRequired,
    StakeSubmitted,
    StakeConfirmed,
    Syncing,
    SnapshotVerified,
    Replaying,
    Shadow,
    Ready,
    PendingActivation,
    Active,
    Jailed,
    Exiting,
    Exited,
    SelfQuarantinedDivergence,
    ReconcilingChain,
    SpeedSyncingCanonical,
    VerifyingCanonicalChain,
    ReadyToRejoin,
    RejoiningConsensus,
    FailedClosed,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ValidatorRecord {
    pub validator_id: ValidatorId,
    pub validator_uma_id: UmaId,
    pub consensus_public_key: AegisPqPublicKey,
    pub peer_public_key: AegisPqPublicKey,
    pub operator_public_key: AegisPqPublicKey,
    pub voting_weight: u64,
    pub status: ValidatorStatus,
    pub cluster_id: ClusterId,
    pub activation_epoch: Epoch,
}

impl ValidatorRecord {
    pub fn is_active_for_epoch(&self, epoch: Epoch) -> bool {
        self.status == ValidatorStatus::Active && self.activation_epoch.0 <= epoch.0
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ValidatorSet {
    pub epoch: Epoch,
    pub validators: Vec<ValidatorRecord>,
}

impl ValidatorSet {
    pub fn canonicalized(&self) -> Self {
        let mut validators = self.validators.clone();
        validators.sort_by(|a, b| a.validator_id.cmp(&b.validator_id));
        Self {
            epoch: self.epoch,
            validators,
        }
    }

    pub fn hash(&self) -> Result<Hash, String> {
        Ok(Hash::from_domain_bytes(
            "SYNERGY_VALIDATOR_SET_V1",
            &self.canonicalized().canonical_bytes()?,
        ))
    }

    pub fn threshold_weight(&self) -> u64 {
        self.threshold_weight_checked().unwrap_or(u64::MAX)
    }

    pub fn threshold_weight_checked(&self) -> Result<u64, String> {
        strict_quorum(checked_total_weight(&self.validators)?)
    }

    pub fn active_for_epoch(&self, epoch: Epoch) -> Self {
        let mut validators = self
            .validators
            .iter()
            .filter(|record| record.is_active_for_epoch(epoch))
            .cloned()
            .collect::<Vec<_>>();
        validators.sort_by(|left, right| left.validator_id.cmp(&right.validator_id));
        Self { epoch, validators }
    }

    pub fn consensus_key_root(&self) -> Result<Hash, String> {
        let mut commitments = self
            .validators
            .iter()
            .map(|validator| ConsensusKeyCommitment {
                validator_id: validator.validator_id.clone(),
                key_id: validator.consensus_public_key.key_id.clone(),
                algorithm: validator.consensus_public_key.algorithm.clone(),
                public_key_hash: Hash::from_domain_bytes(
                    "SYNERGY_CONSENSUS_PUBLIC_KEY_V1",
                    &validator.consensus_public_key.key_bytes,
                ),
            })
            .collect::<Vec<_>>();
        commitments.sort_by(|left, right| left.validator_id.cmp(&right.validator_id));
        Ok(Hash::from_domain_bytes(
            "SYNERGY_VALIDATOR_CONSENSUS_KEY_ROOT_V1",
            &commitments.canonical_bytes()?,
        ))
    }

    pub fn frozen_bonded_weight_root(&self) -> Result<Hash, String> {
        let mut weights = self
            .validators
            .iter()
            .map(|validator| FrozenBondedWeight {
                validator_id: validator.validator_id.clone(),
                voting_weight: validator.voting_weight,
            })
            .collect::<Vec<_>>();
        weights.sort_by(|left, right| left.validator_id.cmp(&right.validator_id));
        Ok(Hash::from_domain_bytes(
            "SYNERGY_FROZEN_BONDED_WEIGHT_ROOT_V1",
            &weights.canonical_bytes()?,
        ))
    }

    pub fn validate_unique_validator_and_key_ids(&self) -> Result<(), String> {
        let validator_ids = self
            .validators
            .iter()
            .map(|validator| &validator.validator_id)
            .collect::<BTreeSet<_>>();
        if validator_ids.len() != self.validators.len() {
            return Err("validator set contains duplicate validator IDs".to_string());
        }
        let key_ids = self
            .validators
            .iter()
            .map(|validator| &validator.consensus_public_key.key_id)
            .collect::<BTreeSet<_>>();
        if key_ids.len() != self.validators.len() {
            return Err("validator set contains duplicate consensus key IDs".to_string());
        }
        if self
            .validators
            .iter()
            .any(|validator| validator.voting_weight == 0)
        {
            return Err("validator set contains zero frozen voting weight".to_string());
        }
        if self.validators.iter().any(|validator| {
            validator.consensus_public_key.algorithm != TESTNET_V3_CONSENSUS_SIGNATURE_ALGORITHM
                || validator.consensus_public_key.key_bytes.len()
                    != TESTNET_V3_MLDSA65_PUBLIC_KEY_BYTES
        }) {
            return Err(format!(
                "Testnet-v3 validator consensus keys must be ML-DSA-65 public keys encoded as exactly {TESTNET_V3_MLDSA65_PUBLIC_KEY_BYTES} bytes"
            ));
        }
        Ok(())
    }

    pub fn active_for_cluster(&self, cluster_id: ClusterId) -> Vec<ValidatorRecord> {
        let mut validators = self
            .validators
            .iter()
            .filter(|record| {
                record.status == ValidatorStatus::Active && record.cluster_id == cluster_id
            })
            .cloned()
            .collect::<Vec<_>>();
        validators.sort_by(|a, b| a.validator_id.cmp(&b.validator_id));
        validators
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClusterAssignment {
    pub cluster_id: ClusterId,
    pub validator_id: ValidatorId,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClusterMap {
    pub epoch: Epoch,
    pub assignments: Vec<ClusterAssignment>,
}

impl ClusterMap {
    pub fn canonicalized(&self) -> Self {
        let mut assignments = self.assignments.clone();
        assignments.sort_by(|a, b| {
            a.cluster_id
                .cmp(&b.cluster_id)
                .then_with(|| a.validator_id.cmp(&b.validator_id))
        });
        Self {
            epoch: self.epoch,
            assignments,
        }
    }

    pub fn hash(&self) -> Result<Hash, String> {
        Ok(Hash::from_domain_bytes(
            "SYNERGY_CLUSTER_MAP_V1",
            &self.canonicalized().canonical_bytes()?,
        ))
    }

    pub fn contains(&self, cluster_id: ClusterId, validator_id: &ValidatorId) -> bool {
        self.assignments.iter().any(|assignment| {
            assignment.cluster_id == cluster_id && &assignment.validator_id == validator_id
        })
    }

    pub fn derive_from_finalized_epoch_seed(
        active_set: &ValidatorSet,
        finalized_epoch_seed_root: Hash,
    ) -> Result<Self, String> {
        if finalized_epoch_seed_root.is_zero() {
            return Err("finalized epoch seed root is missing".to_string());
        }
        active_set.validate_unique_validator_and_key_ids()?;
        let cluster_count = testnet_v3_cluster_count(active_set.validators.len());
        if cluster_count == 0 {
            return Err("cannot derive clusters for an empty active set".to_string());
        }
        let mut ranked = active_set
            .validators
            .iter()
            .map(|validator| {
                let mut hasher = Sha3_512::new();
                hasher.update(b"PoSy/ClusterShuffle/v2.1");
                hasher.update(finalized_epoch_seed_root.0);
                hasher.update((validator.validator_id.0.len() as u64).to_be_bytes());
                hasher.update(validator.validator_id.0.as_bytes());
                (hasher.finalize().to_vec(), validator.validator_id.clone())
            })
            .collect::<Vec<_>>();
        ranked.sort_by(|left, right| left.0.cmp(&right.0).then_with(|| left.1.cmp(&right.1)));
        let assignments = ranked
            .into_iter()
            .enumerate()
            .map(|(position, (_, validator_id))| ClusterAssignment {
                cluster_id: ClusterId((position % cluster_count) as u64),
                validator_id,
            })
            .collect();
        Ok(Self {
            epoch: active_set.epoch,
            assignments,
        }
        .canonicalized())
    }

    pub fn validate_complete_balanced_assignment(
        &self,
        active_set: &ValidatorSet,
    ) -> Result<(), String> {
        if self.epoch != active_set.epoch {
            return Err("cluster-map epoch does not match active-set epoch".to_string());
        }
        let active_ids = active_set
            .validators
            .iter()
            .map(|validator| validator.validator_id.clone())
            .collect::<BTreeSet<_>>();
        let assigned_ids = self
            .assignments
            .iter()
            .map(|assignment| assignment.validator_id.clone())
            .collect::<BTreeSet<_>>();
        if assigned_ids.len() != self.assignments.len() {
            return Err("cluster map assigns a validator more than once".to_string());
        }
        if assigned_ids != active_ids {
            return Err(
                "cluster map is not exhaustive over the exact active validator set".to_string(),
            );
        }
        let expected_cluster_count = testnet_v3_cluster_count(active_ids.len());
        let cluster_ids = self
            .assignments
            .iter()
            .map(|assignment| assignment.cluster_id.0)
            .collect::<BTreeSet<_>>();
        let expected_cluster_ids = (0..expected_cluster_count as u64).collect::<BTreeSet<_>>();
        if cluster_ids != expected_cluster_ids {
            return Err(
                "cluster map does not use the canonical contiguous cluster IDs".to_string(),
            );
        }
        let sizes = expected_cluster_ids
            .iter()
            .map(|cluster_id| {
                self.assignments
                    .iter()
                    .filter(|assignment| assignment.cluster_id.0 == *cluster_id)
                    .count()
            })
            .collect::<Vec<_>>();
        let smallest = sizes.iter().min().copied().unwrap_or(0);
        let largest = sizes.iter().max().copied().unwrap_or(0);
        if largest.saturating_sub(smallest) > 1 {
            return Err("cluster sizes differ by more than one validator".to_string());
        }
        for validator in &active_set.validators {
            let assignment = self
                .assignments
                .iter()
                .find(|assignment| assignment.validator_id == validator.validator_id)
                .ok_or_else(|| "active validator is missing a cluster assignment".to_string())?;
            if validator.cluster_id != assignment.cluster_id {
                return Err(format!(
                    "validator {} embedded cluster ID does not match frozen cluster map",
                    validator.validator_id.0
                ));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProtocolConfig {
    pub chain_id: ChainId,
    pub network_id: NetworkId,
    pub consensus_parameter_root: ConsensusParameterRoot,
    #[serde(skip, default = "Hash::zero")]
    pub(crate) runtime_config_commitment: Hash,
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

#[derive(Serialize)]
struct ProtocolConfigBinding<'a> {
    chain_id: ChainId,
    network_id: &'a NetworkId,
    consensus_parameter_root: ConsensusParameterRoot,
    shadow_epochs_required: u64,
    activation_delay_epochs: u64,
    minimum_shadow_blocks: u64,
    max_finalized_lag_blocks: u64,
    required_vote_match_rate_ppm: u64,
    required_validator_stake_nwei: u128,
    allow_over_staking: bool,
    anti_divergence_enabled: bool,
    auto_reconciliation_enabled: bool,
    self_quarantine_on_local_divergence: bool,
    peer_quarantine_on_invalid_finality_claim: bool,
    require_quorum_peer_confirmation_for_reconciliation: bool,
    min_canonical_sync_peers: u64,
    max_rejoin_lag_blocks: u64,
    rejoin_only_at_round_boundary: bool,
    allow_quorum_reduction: bool,
    proposal_timeout_ms: u64,
    prevote_timeout_ms: u64,
    precommit_timeout_ms: u64,
    max_round_timeout_ms: u64,
}

impl ProtocolConfig {
    #[cfg(test)]
    pub fn testnet_v3() -> Self {
        let mut config = Self {
            chain_id: ChainId::synergy_testnet_v3(),
            network_id: NetworkId::synergy_testnet_v3(),
            consensus_parameter_root: ConsensusParameterRoot::from_canonical_manifest_bytes(
                b"SYNERGY_TESTNET_V3_UNIT_TEST_PARAMETERS_ONLY",
            ),
            runtime_config_commitment: Hash::zero(),
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
            proposal_timeout_ms: 1500,
            prevote_timeout_ms: 1500,
            precommit_timeout_ms: 1500,
            max_round_timeout_ms: 10_000,
        };
        config.seal_runtime_binding().expect("unit-test config");
        config
    }

    fn binding_material(&self) -> ProtocolConfigBinding<'_> {
        ProtocolConfigBinding {
            chain_id: self.chain_id,
            network_id: &self.network_id,
            consensus_parameter_root: self.consensus_parameter_root,
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
        }
    }

    fn recompute_runtime_binding(&self) -> Result<Hash, String> {
        Ok(Hash::from_domain_bytes(
            "SYNERGY_PROTOCOL_CONFIG_MANIFEST_BINDING_V1",
            &serde_json::to_vec(&self.binding_material())
                .map_err(|error| format!("protocol config binding failed: {error}"))?,
        ))
    }

    pub(crate) fn seal_runtime_binding(&mut self) -> Result<(), String> {
        self.runtime_config_commitment = self.recompute_runtime_binding()?;
        Ok(())
    }

    pub fn hash(&self) -> Result<ConsensusParameterRoot, String> {
        self.chain_id.require_testnet_v3()?;
        self.network_id.require_testnet_v3()?;
        if self.consensus_parameter_root.is_zero() {
            return Err("consensus parameter root is missing".to_string());
        }
        if self.runtime_config_commitment.is_zero()
            || self.runtime_config_commitment != self.recompute_runtime_binding()?
        {
            return Err(
                "runtime protocol configuration does not match its finalized parameter manifest"
                    .to_string(),
            );
        }
        Ok(self.consensus_parameter_root)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EpochTransition {
    pub chain_id: ChainId,
    pub network_id: NetworkId,
    pub from_epoch: Epoch,
    pub to_epoch: Epoch,
    pub finalized_height: Height,
    pub finalized_block_id: BlockId,
    pub active_validator_set_hash: Hash,
    pub next_validator_set_hash: Hash,
    pub cluster_map_hash: Hash,
    pub height_context_root: Hash,
    pub signer_key_ids: Vec<AegisPqKeyId>,
    pub signatures: Vec<AegisPqSignature>,
}

impl EpochTransition {
    /// Canonical non-signature payload covered by every epoch-transition
    /// signature.  Keeping this beside the transition type prevents a signer
    /// and verifier from independently drifting on the fields that authorize
    /// a new validator topology.
    pub fn signing_bytes(&self) -> Result<Vec<u8>, String> {
        serde_json::to_vec(&EpochTransitionUnsigned {
            chain_id: self.chain_id,
            network_id: &self.network_id,
            from_epoch: self.from_epoch,
            to_epoch: self.to_epoch,
            finalized_height: self.finalized_height,
            finalized_block_id: &self.finalized_block_id,
            active_validator_set_hash: self.active_validator_set_hash,
            next_validator_set_hash: self.next_validator_set_hash,
            cluster_map_hash: self.cluster_map_hash,
            height_context_root: self.height_context_root,
        })
        .map_err(|error| format!("epoch transition unsigned serialize: {error}"))
    }

    /// The transition is signed over its non-signature fields, but the
    /// complete transition also needs one canonical representation before it
    /// can seed the next epoch or serve as a prior-transition root.  Sorting
    /// signer/signature pairs together prevents equivalent quorum signatures
    /// from producing different topology roots merely because they arrived in
    /// a different network order.
    pub fn canonicalized(&self) -> Self {
        let mut signer_pairs = self
            .signer_key_ids
            .iter()
            .cloned()
            .zip(self.signatures.iter().cloned())
            .collect::<Vec<_>>();
        signer_pairs.sort_by(|left, right| left.0.cmp(&right.0));
        let (signer_key_ids, signatures) = signer_pairs.into_iter().unzip();
        Self {
            chain_id: self.chain_id,
            network_id: self.network_id.clone(),
            from_epoch: self.from_epoch,
            to_epoch: self.to_epoch,
            finalized_height: self.finalized_height,
            finalized_block_id: self.finalized_block_id.clone(),
            active_validator_set_hash: self.active_validator_set_hash,
            next_validator_set_hash: self.next_validator_set_hash,
            cluster_map_hash: self.cluster_map_hash,
            height_context_root: self.height_context_root,
            signer_key_ids,
            signatures,
        }
    }

    pub fn validate_structure(&self) -> Result<(), String> {
        self.chain_id.require_testnet_v3()?;
        self.network_id.require_testnet_v3()?;
        if self.to_epoch.0 != self.from_epoch.0.saturating_add(1) {
            return Err("epoch transition must advance exactly one epoch".to_string());
        }
        if self.finalized_height.0 == 0 || self.finalized_block_id.0.trim().is_empty() {
            return Err("epoch transition must bind a non-genesis finalized block".to_string());
        }
        for (name, root) in [
            ("active_validator_set_hash", self.active_validator_set_hash),
            ("next_validator_set_hash", self.next_validator_set_hash),
            ("cluster_map_hash", self.cluster_map_hash),
            ("height_context_root", self.height_context_root),
        ] {
            if root.is_zero() {
                return Err(format!("epoch transition {name} is missing"));
            }
        }
        if self.signer_key_ids.is_empty() || self.signer_key_ids.len() != self.signatures.len() {
            return Err("epoch transition signer/signature list is invalid".to_string());
        }
        if self
            .signatures
            .iter()
            .any(|signature| !signature.is_present())
        {
            return Err("epoch transition contains a missing signature".to_string());
        }
        if self
            .signer_key_ids
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
        {
            return Err("epoch transition signer keys must be canonical and distinct".to_string());
        }
        Ok(())
    }

    pub fn root(&self) -> Result<Hash, String> {
        self.validate_structure()?;
        let canonical = self.canonicalized();
        if canonical != *self {
            return Err("epoch transition is not canonically ordered".to_string());
        }
        Ok(Hash::from_domain_bytes(
            "SYNERGY_EPOCH_TRANSITION_ROOT_V1",
            &canonical.canonical_bytes()?,
        ))
    }

    pub fn finalized_epoch_seed_root(&self) -> Result<Hash, String> {
        // This seed intentionally excludes the next validator-set and
        // cluster-map commitments.  Including either (or the full signed
        // transition root) would make the map derivation circular: the map
        // hash would be required to calculate the seed that derives the map.
        // These fields are all already finalized-chain facts and are also
        // included in the signature payload below.
        Ok(Hash::from_domain_bytes(
            "SYNERGY_EPOCH_TRANSITION_SEED_V1",
            &serde_json::to_vec(&EpochTransitionSeedMaterial {
                chain_id: self.chain_id,
                network_id: &self.network_id,
                from_epoch: self.from_epoch,
                to_epoch: self.to_epoch,
                finalized_height: self.finalized_height,
                finalized_block_id: &self.finalized_block_id,
                active_validator_set_hash: self.active_validator_set_hash,
                height_context_root: self.height_context_root,
            })
            .map_err(|error| format!("epoch transition seed serialize: {error}"))?,
        ))
    }
}

#[derive(Serialize)]
struct EpochTransitionUnsigned<'a> {
    chain_id: ChainId,
    network_id: &'a NetworkId,
    from_epoch: Epoch,
    to_epoch: Epoch,
    finalized_height: Height,
    finalized_block_id: &'a BlockId,
    active_validator_set_hash: Hash,
    next_validator_set_hash: Hash,
    cluster_map_hash: Hash,
    height_context_root: Hash,
}

#[derive(Serialize)]
struct EpochTransitionSeedMaterial<'a> {
    chain_id: ChainId,
    network_id: &'a NetworkId,
    from_epoch: Epoch,
    to_epoch: Epoch,
    finalized_height: Height,
    finalized_block_id: &'a BlockId,
    active_validator_set_hash: Hash,
    height_context_root: Hash,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum StakeStatus {
    NotSubmitted,
    Submitted,
    Finalized,
    Locked,
    Insufficient,
    InvalidSignature,
    WrongChain,
    WrongNetwork,
    Reverted,
    Expired,
    Slashed,
    Unlocking,
    Unlocked,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ValidatorStakeRecord {
    pub validator_id: ValidatorId,
    pub validator_uma_id: UmaId,
    pub stake_owner: String,
    pub stake_amount_nwei: u128,
    pub required_stake_nwei: u128,
    pub stake_tx_hash: TxId,
    pub stake_lock_id: String,
    pub stake_status: StakeStatus,
    pub stake_finalized_height: Height,
    pub stake_finalized_block_hash: Hash,
    pub stake_finalized_qc_hash: Hash,
    pub stake_activation_epoch: Epoch,
    pub stake_unlock_epoch_optional: Option<Epoch>,
    pub stake_slashable: bool,
    pub stake_verified: bool,
}

impl ValidatorStakeRecord {
    pub fn satisfies_required_stake(&self, protocol: &ProtocolConfig) -> bool {
        self.stake_verified
            && self.stake_status == StakeStatus::Locked
            && self.stake_amount_nwei >= protocol.required_validator_stake_nwei
            && self.required_stake_nwei == protocol.required_validator_stake_nwei
            && self.stake_slashable
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PeerHello {
    pub node_id: String,
    pub validator_id_optional: Option<ValidatorId>,
    pub role: String,
    pub chain_id: ChainId,
    pub network_id: NetworkId,
    pub genesis_hash: Hash,
    pub protocol_version: String,
    pub consensus_version: String,
    pub execution_version: String,
    pub dag_version: String,
    pub aegis_pqvm_version: String,
    pub latest_finalized_height: Height,
    pub latest_finalized_hash: Hash,
    pub latest_state_root: Hash,
    pub active_validator_set_hash: Hash,
    pub cluster_map_hash: Hash,
    pub protocol_config_hash: ConsensusParameterRoot,
    pub aegis_pq_public_key_id: AegisPqKeyId,
}

#[cfg(test)]
pub(crate) fn deterministic_test_height_context(
    validator_set: &ValidatorSet,
    cluster_map: &ClusterMap,
    protocol_config: &ProtocolConfig,
    height: Height,
    assigned_cluster_id: ClusterId,
) -> HeightConsensusContext {
    HeightConsensusContext::derive(
        HeightConsensusContextSpec {
            protocol_version: POSY_PROTOCOL_VERSION.to_string(),
            height,
            epoch: validator_set.epoch,
            assigned_cluster_id,
            cluster_schedule_version: TESTNET_V3_CLUSTER_SCHEDULE_VERSION.to_string(),
            finalized_epoch_seed_root: Hash::from_domain_bytes(
                "SYNERGY_TEST_FINALIZED_EPOCH_SEED_V1",
                b"unit-test-seed",
            ),
            assigned_height_schedule_root: Hash::from_domain_bytes(
                "SYNERGY_TEST_ASSIGNED_HEIGHT_SCHEDULE_V1",
                b"unit-test-schedule",
            ),
            cryptographic_profile_root: Hash::from_domain_bytes(
                "SYNERGY_TEST_CRYPTOGRAPHIC_PROFILE_V1",
                b"unit-test-profile",
            ),
            prior_finalized_qc_or_transition_root: Hash::from_domain_bytes(
                "SYNERGY_TEST_PRIOR_FINALIZED_REFERENCE_V1",
                &height.0.saturating_sub(1).to_be_bytes(),
            ),
        },
        validator_set,
        cluster_map,
        protocol_config,
    )
    .expect("test height context")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn root(label: &str) -> Hash {
        Hash::from_domain_bytes("SYNERGY_TEST_ROOT_V1", label.as_bytes())
    }

    fn test_sig() -> AegisPqSignature {
        AegisPqSignature {
            algorithm: "fndsa".to_string(),
            signature_bytes: vec![1, 2, 3],
        }
    }

    #[test]
    fn finality_context_root_excludes_valid_qc_signer_subset_evidence() {
        let certificate = QuorumCertificate {
            qc_version: 1,
            chain_id: ChainId::synergy_testnet_v3(),
            network_id: NetworkId::synergy_testnet_v3(),
            protocol_version: POSY_PROTOCOL_VERSION.to_string(),
            height: Height(9),
            round: Round(2),
            epoch: Epoch(0),
            cluster_id: ClusterId(0),
            height_context_root: root("context"),
            phase: VotePhase::Finality,
            block_id: BlockId("block-9".to_string()),
            highest_prepared_vc_root: None,
            active_validator_set_hash: root("validators"),
            cluster_map_hash: root("clusters"),
            threshold_weight_required: 5,
            signed_weight: 5,
            signer_bitmap: vec![0b0001_1111],
            aegis_pq_signatures: vec![test_sig(); 5],
            aegis_pq_key_ids: (1..=5)
                .map(|index| AegisPqKeyId(format!("key-{index}")))
                .collect(),
        };
        let mut alternate_evidence = certificate.clone();
        alternate_evidence.signer_bitmap = vec![0b0010_1111];
        alternate_evidence.aegis_pq_key_ids[4] = AegisPqKeyId("key-6".to_string());
        alternate_evidence.aegis_pq_signatures[4] = AegisPqSignature {
            algorithm: "mldsa65".to_string(),
            signature_bytes: vec![9, 8, 7],
        };
        assert_ne!(
            certificate.root().unwrap(),
            alternate_evidence.root().unwrap()
        );
        assert_eq!(
            certificate.finality_context_root().unwrap(),
            alternate_evidence.finality_context_root().unwrap()
        );
    }

    #[test]
    fn chain_and_network_serialize_to_testnet_values() {
        let payload = serde_json::to_string(&(
            ChainId::synergy_testnet_v3(),
            NetworkId::synergy_testnet_v3(),
        ))
        .expect("serialize identifiers");
        assert!(payload.contains("1266"));
        assert!(payload.contains(SYNERGY_TESTNET_V3_NETWORK_ID));
    }

    #[test]
    fn block_header_canonical_serialization_is_stable() {
        let header = BlockHeader {
            version: 1,
            chain_id: ChainId::synergy_testnet_v3(),
            network_id: NetworkId::synergy_testnet_v3(),
            protocol_version: POSY_PROTOCOL_VERSION.to_string(),
            height: Height(7),
            round: Round(2),
            epoch: Epoch(0),
            cluster_id: ClusterId(0),
            height_context_root: root("height-context"),
            parent_block_hash: Hash::zero(),
            parent_state_root: Hash::zero(),
            last_finalized_qc_hash: Hash::zero(),
            proposer_validator_id: ValidatorId::from("validator-1"),
            proposer_uma_id: UmaId::from("uma-1"),
            proposer_key_id: AegisPqKeyId::from("key-1"),
            active_validator_set_hash: Hash::zero(),
            eligible_validator_set_hash: Hash::zero(),
            validator_consensus_key_root: root("consensus-keys"),
            frozen_bonded_weight_root: root("weights"),
            cluster_schedule_version: TESTNET_V3_CLUSTER_SCHEDULE_VERSION.to_string(),
            cluster_map_hash: Hash::zero(),
            assigned_cluster_membership_root: root("members"),
            assigned_cluster_validator_count: 6,
            assigned_cluster_total_voting_weight: 6,
            proposer_schedule_hash: Hash::zero(),
            protocol_config_hash: ConsensusParameterRoot::zero(),
            cryptographic_profile_root: root("crypto-profile"),
            dag_frontier_root: Hash::zero(),
            tx_order_root: Hash::zero(),
            tx_count: 0,
            protected_batch: None,
            evidence_root: Hash::zero(),
            state_root_before: Hash::zero(),
            state_root_after: Hash::zero(),
            receipt_root: Hash::zero(),
            app_version: 1,
            execution_version: 1,
            dag_version: 1,
            aegis_pqvm_version: "aegis-pqvm-test".to_string(),
            timestamp_ms_consensus_bounded: 1000,
        };
        let a = header.canonical_bytes().expect("canonical bytes");
        let b = header.canonical_bytes().expect("canonical bytes");
        assert_eq!(a, b);
        let decoded = BlockHeader::assert_canonical_bytes(&a).expect("canonical decode");
        assert_eq!(decoded, header);
    }

    #[test]
    fn vote_signing_payload_excludes_signature() {
        let mut vote = Vote {
            chain_id: ChainId::synergy_testnet_v3(),
            network_id: NetworkId::synergy_testnet_v3(),
            protocol_version: POSY_PROTOCOL_VERSION.to_string(),
            height: Height(1),
            round: Round(0),
            epoch: Epoch(0),
            cluster_id: ClusterId(0),
            height_context_root: root("height-context"),
            phase: VotePhase::Finality,
            block_id: BlockId::from("block"),
            highest_prepared_vc_root: None,
            validator_id: ValidatorId::from("validator-1"),
            validator_uma_id: UmaId::from("uma-1"),
            key_id: AegisPqKeyId::from("key-1"),
            active_validator_set_hash: Hash::zero(),
            cluster_map_hash: Hash::zero(),
            aegis_pq_signature: test_sig(),
        };
        let before = vote.signing_bytes().expect("signing bytes");
        vote.aegis_pq_signature.signature_bytes = vec![9, 9, 9];
        let after = vote.signing_bytes().expect("signing bytes");
        assert_eq!(before, after);
    }

    fn context_fixture(
        validator_count: usize,
    ) -> (
        ValidatorSet,
        ClusterMap,
        ProtocolConfig,
        HeightConsensusContextSpec,
        HeightConsensusContext,
    ) {
        let epoch = Epoch(4);
        let mut set = ValidatorSet {
            epoch,
            validators: (0..validator_count)
                .map(|index| ValidatorRecord {
                    validator_id: ValidatorId(format!("validator-{index:02}")),
                    validator_uma_id: UmaId(format!("uma-{index:02}")),
                    consensus_public_key: AegisPqPublicKey {
                        key_id: AegisPqKeyId(format!("consensus-{index:02}")),
                        algorithm: TESTNET_V3_CONSENSUS_SIGNATURE_ALGORITHM.to_string(),
                        key_bytes: vec![index as u8 + 1; TESTNET_V3_MLDSA65_PUBLIC_KEY_BYTES],
                    },
                    peer_public_key: AegisPqPublicKey {
                        key_id: AegisPqKeyId(format!("peer-{index:02}")),
                        algorithm: "ML-DSA-65".to_string(),
                        key_bytes: vec![index as u8 + 2; 32],
                    },
                    operator_public_key: AegisPqPublicKey {
                        key_id: AegisPqKeyId(format!("operator-{index:02}")),
                        algorithm: "ML-DSA-65".to_string(),
                        key_bytes: vec![index as u8 + 3; 32],
                    },
                    voting_weight: 10 + index as u64,
                    status: ValidatorStatus::Active,
                    cluster_id: ClusterId(0),
                    activation_epoch: epoch,
                })
                .collect(),
        };
        let seed = root("finalized-epoch-seed");
        let initial = ClusterMap::derive_from_finalized_epoch_seed(&set, seed).unwrap();
        for validator in &mut set.validators {
            validator.cluster_id = initial
                .assignments
                .iter()
                .find(|assignment| assignment.validator_id == validator.validator_id)
                .unwrap()
                .cluster_id;
        }
        let cluster_map = ClusterMap::derive_from_finalized_epoch_seed(&set, seed).unwrap();
        let protocol = ProtocolConfig::testnet_v3();
        let spec = HeightConsensusContextSpec {
            protocol_version: POSY_PROTOCOL_VERSION.to_string(),
            height: Height(25),
            epoch,
            assigned_cluster_id: ClusterId(
                1u64.min(testnet_v3_cluster_count(validator_count).saturating_sub(1) as u64),
            ),
            cluster_schedule_version: TESTNET_V3_CLUSTER_SCHEDULE_VERSION.to_string(),
            finalized_epoch_seed_root: seed,
            assigned_height_schedule_root: root("assigned-height-schedule"),
            cryptographic_profile_root: root("aegis-profile"),
            prior_finalized_qc_or_transition_root: root("prior-finalized-qc"),
        };
        let context =
            HeightConsensusContext::derive(spec.clone(), &set, &cluster_map, &protocol).unwrap();
        (set, cluster_map, protocol, spec, context)
    }

    #[test]
    fn cluster_schedule_matches_every_corrected_boundary() {
        for (count, clusters) in [
            (6, 1),
            (9, 1),
            (10, 2),
            (20, 2),
            (21, 3),
            (27, 3),
            (28, 4),
            (34, 4),
            (35, 5),
            (41, 5),
            (42, 6),
            (48, 6),
            (49, 7),
        ] {
            assert_eq!(testnet_v3_cluster_count(count), clusters);
        }
    }

    #[test]
    fn strict_quorum_rejects_exact_two_thirds() {
        assert_eq!(strict_quorum(5).unwrap(), 4);
        assert_eq!(strict_quorum(6).unwrap(), 5);
        assert_eq!(strict_quorum(9).unwrap(), 7);
        assert!(3 * 4 <= 2 * 6);
        assert!(3 * 5 > 2 * 6);

        let (mut set, _, _, _, _) = context_fixture(6);
        for validator in &mut set.validators {
            validator.voting_weight = 10;
        }
        assert_eq!(set.threshold_weight_checked().unwrap(), 41);
        assert!(3 * 40 <= 2 * 60);
        assert!(3 * 41 > 2 * 60);
    }

    #[test]
    fn validator_set_rejects_non_mldsa65_consensus_keys() {
        let (mut set, _, _, _, _) = context_fixture(6);
        set.validate_unique_validator_and_key_ids().unwrap();
        set.validators[0].consensus_public_key.algorithm = "fndsa".to_string();
        assert!(set
            .validate_unique_validator_and_key_ids()
            .unwrap_err()
            .contains("ML-DSA-65"));
    }

    #[test]
    fn validator_set_rejects_malformed_mldsa65_public_key_lengths() {
        let (mut set, _, _, _, _) = context_fixture(6);
        set.validate_unique_validator_and_key_ids().unwrap();
        set.validators[0].consensus_public_key.key_bytes.pop();
        let error = set.validate_unique_validator_and_key_ids().unwrap_err();
        assert!(error.contains("exactly 1952 bytes"));
    }

    #[test]
    fn height_context_is_canonical_and_restart_stable() {
        let (set, cluster_map, protocol, spec, context) = context_fixture(21);
        let independently_derived =
            HeightConsensusContext::derive(spec, &set, &cluster_map, &protocol).unwrap();
        assert_eq!(context, independently_derived);
        assert_eq!(
            context.root().unwrap(),
            independently_derived.root().unwrap()
        );

        let bytes = context.canonical_bytes().unwrap();
        let after_restart = HeightConsensusContext::assert_canonical_bytes(&bytes).unwrap();
        assert_eq!(after_restart.root().unwrap(), context.root().unwrap());
        after_restart
            .validate_against(&set, &cluster_map, &protocol)
            .unwrap();
    }

    #[test]
    fn height_context_changes_for_membership_weight_and_parameters() {
        let (set, cluster_map, protocol, spec, context) = context_fixture(21);

        let mut changed_weight_set = set.clone();
        changed_weight_set.validators[0].voting_weight += 1;
        let changed_weight = HeightConsensusContext::derive(
            spec.clone(),
            &changed_weight_set,
            &cluster_map,
            &protocol,
        )
        .unwrap();
        assert_ne!(changed_weight.root().unwrap(), context.root().unwrap());
        assert_ne!(
            changed_weight.frozen_bonded_weight_root,
            context.frozen_bonded_weight_root
        );

        let mut changed_protocol = protocol.clone();
        changed_protocol.proposal_timeout_ms += 1;
        let error =
            HeightConsensusContext::derive(spec.clone(), &set, &cluster_map, &changed_protocol)
                .unwrap_err();
        assert!(error.contains("does not match its finalized parameter manifest"));

        changed_protocol.consensus_parameter_root =
            ConsensusParameterRoot::from_canonical_manifest_bytes(
                b"SYNERGY_TESTNET_V3_CHANGED_UNIT_TEST_PARAMETERS_ONLY",
            );
        changed_protocol.seal_runtime_binding().unwrap();
        let changed_parameter =
            HeightConsensusContext::derive(spec, &set, &cluster_map, &changed_protocol).unwrap();
        assert_ne!(changed_parameter.root().unwrap(), context.root().unwrap());
        assert_ne!(
            changed_parameter.consensus_parameter_root,
            context.consensus_parameter_root
        );
    }

    #[test]
    fn height_context_rejects_wrong_map_epoch_missing_root_and_wrong_proposer() {
        let (set, cluster_map, protocol, spec, context) = context_fixture(21);

        let mut wrong_map = cluster_map.clone();
        wrong_map.assignments[0].cluster_id = ClusterId(99);
        assert!(HeightConsensusContext::derive(spec.clone(), &set, &wrong_map, &protocol).is_err());

        let mut stale_epoch = spec.clone();
        stale_epoch.epoch = Epoch(spec.epoch.0 - 1);
        assert!(
            HeightConsensusContext::derive(stale_epoch, &set, &cluster_map, &protocol).is_err()
        );
        let mut future_epoch = spec.clone();
        future_epoch.epoch = Epoch(spec.epoch.0 + 1);
        assert!(
            HeightConsensusContext::derive(future_epoch, &set, &cluster_map, &protocol).is_err()
        );

        let mut missing_root = spec;
        missing_root.cryptographic_profile_root = Hash::zero();
        assert!(
            HeightConsensusContext::derive(missing_root, &set, &cluster_map, &protocol).is_err()
        );

        let authorized = context.authorized_proposer(Round(0)).unwrap().clone();
        let wrong = context
            .leader_schedule
            .iter()
            .find(|validator| **validator != authorized)
            .unwrap();
        assert!(context
            .require_authorized_proposer(Round(0), wrong)
            .is_err());
    }

    #[test]
    fn epoch_transition_requires_canonical_distinct_signers_for_a_stable_root() {
        let transition = EpochTransition {
            chain_id: ChainId::synergy_testnet_v3(),
            network_id: NetworkId::synergy_testnet_v3(),
            from_epoch: Epoch(0),
            to_epoch: Epoch(1),
            finalized_height: Height(12),
            finalized_block_id: BlockId::from("finalized-block"),
            active_validator_set_hash: root("active-set"),
            next_validator_set_hash: root("next-set"),
            cluster_map_hash: root("next-clusters"),
            height_context_root: root("current-context"),
            signer_key_ids: vec![AegisPqKeyId::from("key-a"), AegisPqKeyId::from("key-b")],
            signatures: vec![test_sig(), test_sig()],
        };
        let transition_root = transition.root().expect("canonical transition root");
        assert_ne!(transition_root, Hash::zero());
        assert_ne!(
            transition.finalized_epoch_seed_root().unwrap(),
            Hash::zero()
        );

        let mut reordered = transition.clone();
        reordered.signer_key_ids.reverse();
        reordered.signatures.reverse();
        assert!(reordered.root().is_err());
        assert_eq!(reordered.canonicalized().root().unwrap(), transition_root);

        // The next cluster map is derived from finalized evidence, not from a
        // root that already commits to that map.  Otherwise topology
        // derivation would require a circular fixed point.
        let seed = transition.finalized_epoch_seed_root().unwrap();
        let mut changed_topology_commitment = transition.clone();
        changed_topology_commitment.next_validator_set_hash = root("other-next-set");
        changed_topology_commitment.cluster_map_hash = root("other-next-clusters");
        assert_eq!(
            changed_topology_commitment
                .finalized_epoch_seed_root()
                .unwrap(),
            seed
        );
        assert_ne!(changed_topology_commitment.root().unwrap(), transition_root);
    }
}
