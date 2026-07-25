use blake3::Hasher;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::fmt;

pub const SYNERGY_TESTNET_V3_CHAIN_ID: u64 = 1264;
pub const SYNERGY_TESTNET_V3_NETWORK_ID: &str = "synergy-testnet-v3";

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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BlockHeader {
    pub version: u32,
    pub chain_id: ChainId,
    pub network_id: NetworkId,
    pub height: Height,
    pub round: Round,
    pub epoch: Epoch,
    pub cluster_id: ClusterId,
    pub parent_block_hash: Hash,
    pub parent_state_root: Hash,
    pub last_finalized_qc_hash: Hash,
    pub proposer_validator_id: ValidatorId,
    pub proposer_uma_id: UmaId,
    pub proposer_key_id: AegisPqKeyId,
    pub active_validator_set_hash: Hash,
    pub eligible_validator_set_hash: Hash,
    pub cluster_map_hash: Hash,
    pub proposer_schedule_hash: Hash,
    pub protocol_config_hash: Hash,
    pub dag_frontier_root: Hash,
    pub tx_order_root: Hash,
    pub tx_count: u64,
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
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum VotePhase {
    Propose,
    Vote,
    Commit,
    ViewChange,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Vote {
    pub chain_id: ChainId,
    pub network_id: NetworkId,
    pub height: Height,
    pub round: Round,
    pub epoch: Epoch,
    pub cluster_id: ClusterId,
    pub phase: VotePhase,
    pub block_id: BlockId,
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
    pub height: Height,
    pub round: Round,
    pub epoch: Epoch,
    pub cluster_id: ClusterId,
    pub phase: &'a VotePhase,
    pub block_id: &'a BlockId,
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
            height: self.height,
            round: self.round,
            epoch: self.epoch,
            cluster_id: self.cluster_id,
            phase: &self.phase,
            block_id: &self.block_id,
            validator_id: &self.validator_id,
            validator_uma_id: &self.validator_uma_id,
            key_id: &self.key_id,
            active_validator_set_hash: self.active_validator_set_hash,
            cluster_map_hash: self.cluster_map_hash,
        })
        .map_err(|error| format!("vote signing payload serialize failed: {error}"))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct QuorumCertificate {
    pub qc_version: u32,
    pub chain_id: ChainId,
    pub network_id: NetworkId,
    pub height: Height,
    pub round: Round,
    pub epoch: Epoch,
    pub cluster_id: ClusterId,
    pub phase: VotePhase,
    pub block_id: BlockId,
    pub active_validator_set_hash: Hash,
    pub cluster_map_hash: Hash,
    pub threshold_weight_required: u64,
    pub signed_weight: u64,
    pub signer_bitmap: Vec<u8>,
    pub aegis_pq_signatures: Vec<AegisPqSignature>,
    pub aegis_pq_key_ids: Vec<AegisPqKeyId>,
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
        let total: u64 = self
            .validators
            .iter()
            .map(|record| record.voting_weight)
            .sum();
        (total * 2).div_ceil(3)
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
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProtocolConfig {
    pub chain_id: ChainId,
    pub network_id: NetworkId,
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

impl ProtocolConfig {
    pub fn testnet_v3() -> Self {
        Self {
            chain_id: ChainId::synergy_testnet_v3(),
            network_id: NetworkId::synergy_testnet_v3(),
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
        }
    }

    pub fn hash(&self) -> Result<Hash, String> {
        self.chain_id.require_testnet_v3()?;
        self.network_id.require_testnet_v3()?;
        Ok(Hash::from_domain_bytes(
            "SYNERGY_PROTOCOL_CONFIG_V1",
            &self.canonical_bytes()?,
        ))
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
    pub signer_key_ids: Vec<AegisPqKeyId>,
    pub signatures: Vec<AegisPqSignature>,
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
    pub protocol_config_hash: Hash,
    pub aegis_pq_public_key_id: AegisPqKeyId,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_sig() -> AegisPqSignature {
        AegisPqSignature {
            algorithm: "fndsa".to_string(),
            signature_bytes: vec![1, 2, 3],
        }
    }

    #[test]
    fn chain_and_network_serialize_to_testnet_values() {
        let payload = serde_json::to_string(&(
            ChainId::synergy_testnet_v3(),
            NetworkId::synergy_testnet_v3(),
        ))
        .expect("serialize identifiers");
        assert!(payload.contains("1264"));
        assert!(payload.contains(SYNERGY_TESTNET_V3_NETWORK_ID));
    }

    #[test]
    fn block_header_canonical_serialization_is_stable() {
        let header = BlockHeader {
            version: 1,
            chain_id: ChainId::synergy_testnet_v3(),
            network_id: NetworkId::synergy_testnet_v3(),
            height: Height(7),
            round: Round(2),
            epoch: Epoch(0),
            cluster_id: ClusterId(0),
            parent_block_hash: Hash::zero(),
            parent_state_root: Hash::zero(),
            last_finalized_qc_hash: Hash::zero(),
            proposer_validator_id: ValidatorId::from("validator-1"),
            proposer_uma_id: UmaId::from("uma-1"),
            proposer_key_id: AegisPqKeyId::from("key-1"),
            active_validator_set_hash: Hash::zero(),
            eligible_validator_set_hash: Hash::zero(),
            cluster_map_hash: Hash::zero(),
            proposer_schedule_hash: Hash::zero(),
            protocol_config_hash: Hash::zero(),
            dag_frontier_root: Hash::zero(),
            tx_order_root: Hash::zero(),
            tx_count: 0,
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
            height: Height(1),
            round: Round(0),
            epoch: Epoch(0),
            cluster_id: ClusterId(0),
            phase: VotePhase::Commit,
            block_id: BlockId::from("block"),
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
}
