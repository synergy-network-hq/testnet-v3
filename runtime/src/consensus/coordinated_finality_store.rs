//! Crash-safe finality storage for `coordinated_round_robin_v1`.
//!
//! This store is intentionally separate from typed PoSy finality: its durable
//! proof is one signed coordinator commit, never a QC, VC, TC, or aggregate.
//! The role-runtime adapter must verify signatures and execute the block before
//! appending; this store independently preserves the exact verified package,
//! migration anchor, ordering, parent, and state-root continuity across a
//! restart.

use crate::consensus::coordinated_round_robin::CoordinatedRoundRobinConfig;
use crate::p2p::messages::CoordinatedCommittedBlockPackage;
use crate::synergy_types::{BlockId, Hash, Height};
use serde::{Deserialize, Serialize};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

const STORE_VERSION: u32 = 1;
const COORDINATED_FINALITY_FILE: &str = "data/coordinated-round-robin-finality.json";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoordinatedFinalityRecord {
    pub record_version: u32,
    pub height: Height,
    pub block_id: BlockId,
    pub coordinator_commit_hash: Hash,
    pub package: CoordinatedCommittedBlockPackage,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CoordinatedFinalityState {
    store_version: u32,
    migration_parent_block_hash: Hash,
    migration_parent_state_root: Hash,
    first_coordinated_height: Height,
    records: Vec<CoordinatedFinalityRecord>,
}

/// The only persistence boundary for finalized coordinated-mode blocks.
///
/// `migration_parent_*` are supplied from the fully verified predecessor at
/// the activation boundary. They are immutable and are never inferred from a
/// stale local chain journal or remote peer assertion.
#[derive(Debug, Clone)]
pub struct CoordinatedFinalityStore {
    path: PathBuf,
    migration_parent_block_hash: Hash,
    migration_parent_state_root: Hash,
    first_coordinated_height: Height,
}

impl CoordinatedFinalityStore {
    pub fn for_migration_anchor(
        migration_parent_block_hash: Hash,
        migration_parent_state_root: Hash,
        first_coordinated_height: Height,
    ) -> Result<Self, String> {
        Self::at_path(
            default_coordinated_finality_path(),
            migration_parent_block_hash,
            migration_parent_state_root,
            first_coordinated_height,
        )
    }

    pub fn at_path(
        path: PathBuf,
        migration_parent_block_hash: Hash,
        migration_parent_state_root: Hash,
        first_coordinated_height: Height,
    ) -> Result<Self, String> {
        if path.as_os_str().is_empty()
            || migration_parent_block_hash.is_zero()
            || migration_parent_state_root.is_zero()
            || first_coordinated_height.0 == 0
        {
            return Err("coordinated finality store has an invalid migration anchor".to_string());
        }
        Ok(Self {
            path,
            migration_parent_block_hash,
            migration_parent_state_root,
            first_coordinated_height,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn migration_parent_state_root(&self) -> Hash {
        self.migration_parent_state_root
    }

    /// Returns the immutable block anchor that the first coordinated package
    /// must extend. Non-signing observers use this public value to bind their
    /// replay to the same finalized Genesis/migration subject as validators.
    pub fn migration_parent_block_hash(&self) -> Hash {
        self.migration_parent_block_hash
    }

    pub fn first_coordinated_height(&self) -> Height {
        self.first_coordinated_height
    }

    pub fn recover(
        &self,
        config: &CoordinatedRoundRobinConfig,
    ) -> Result<Vec<CoordinatedFinalityRecord>, String> {
        Ok(self.load_state(config)?.records)
    }

    pub fn latest(
        &self,
        config: &CoordinatedRoundRobinConfig,
    ) -> Result<Option<CoordinatedFinalityRecord>, String> {
        Ok(self.load_state(config)?.records.into_iter().last())
    }

    /// Returns the exact durable finalized package at one height. This is a
    /// read-only synchronization surface; callers still authenticate peers and
    /// enforce their own bounded request policy before responding.
    pub fn at_height(
        &self,
        config: &CoordinatedRoundRobinConfig,
        height: Height,
    ) -> Result<Option<CoordinatedFinalityRecord>, String> {
        Ok(self
            .load_state(config)?
            .records
            .into_iter()
            .find(|record| record.height == height))
    }

    /// Returns a bounded, consecutive finalized segment for catch-up. The
    /// store never fills a gap or silently truncates a requested continuation.
    pub fn range(
        &self,
        config: &CoordinatedRoundRobinConfig,
        start_height: Height,
        end_height: Height,
        maximum_records: usize,
    ) -> Result<Vec<CoordinatedFinalityRecord>, String> {
        if start_height.0 == 0 || end_height.0 < start_height.0 || maximum_records == 0 {
            return Err("coordinated finality range request is invalid".to_string());
        }
        let requested = end_height
            .0
            .saturating_sub(start_height.0)
            .saturating_add(1);
        if requested > u64::try_from(maximum_records).unwrap_or(u64::MAX) {
            return Err("coordinated finality range exceeds its configured bound".to_string());
        }
        let records = self
            .load_state(config)?
            .records
            .into_iter()
            .filter(|record| record.height.0 >= start_height.0 && record.height.0 <= end_height.0)
            .collect::<Vec<_>>();
        if records.len() != usize::try_from(requested).unwrap_or(usize::MAX) {
            return Err("coordinated finality range is not fully available".to_string());
        }
        Ok(records)
    }

    /// Writes an independently verified and executed package.  It is
    /// idempotent only for the exact already-persisted record; an alternate
    /// block, commit, or state root at any height fails closed.
    pub fn append_verified_finality(
        &self,
        config: &CoordinatedRoundRobinConfig,
        package: &CoordinatedCommittedBlockPackage,
    ) -> Result<CoordinatedFinalityRecord, String> {
        let mut state = self.load_state(config)?;
        let record = record_from_package(config, package)?;
        if let Some(existing) = state
            .records
            .iter()
            .find(|existing| existing.height == record.height)
        {
            if existing == &record {
                return Ok(existing.clone());
            }
            return Err(
                "coordinated finality store already contains different evidence at this height"
                    .to_string(),
            );
        }
        validate_append(&state, &record)?;
        state.records.push(record.clone());
        self.persist_state(config, &state)?;
        Ok(record)
    }

    fn load_state(
        &self,
        config: &CoordinatedRoundRobinConfig,
    ) -> Result<CoordinatedFinalityState, String> {
        if !self.path.exists() {
            return Ok(self.empty_state());
        }
        let bytes = fs::read(&self.path).map_err(|error| {
            format!(
                "read coordinated finality store {}: {error}",
                self.path.display()
            )
        })?;
        let state: CoordinatedFinalityState = serde_json::from_slice(&bytes).map_err(|error| {
            format!(
                "parse coordinated finality store {}: {error}",
                self.path.display()
            )
        })?;
        let canonical = serde_json::to_vec(&state)
            .map_err(|error| format!("canonicalize coordinated finality store: {error}"))?;
        if bytes != canonical {
            return Err(
                "coordinated finality store is not canonical; refusing mutable or torn state"
                    .to_string(),
            );
        }
        validate_state(config, &state, self)?;
        Ok(state)
    }

    fn empty_state(&self) -> CoordinatedFinalityState {
        CoordinatedFinalityState {
            store_version: STORE_VERSION,
            migration_parent_block_hash: self.migration_parent_block_hash,
            migration_parent_state_root: self.migration_parent_state_root,
            first_coordinated_height: self.first_coordinated_height,
            records: Vec::new(),
        }
    }

    fn persist_state(
        &self,
        config: &CoordinatedRoundRobinConfig,
        state: &CoordinatedFinalityState,
    ) -> Result<(), String> {
        validate_state(config, state, self)?;
        let parent = self.path.parent().ok_or_else(|| {
            format!(
                "coordinated finality store path has no parent: {}",
                self.path.display()
            )
        })?;
        fs::create_dir_all(parent).map_err(|error| {
            format!(
                "create coordinated finality directory {}: {error}",
                parent.display()
            )
        })?;
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|error| {
                format!("clock failure for coordinated finality persistence: {error}")
            })?
            .as_nanos();
        let temporary = parent.join(format!(
            ".{}.tmp-{}-{nonce}",
            self.path
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("coordinated-finality"),
            std::process::id()
        ));
        let bytes = serde_json::to_vec(state)
            .map_err(|error| format!("encode coordinated finality state: {error}"))?;
        let write_result = (|| -> Result<(), String> {
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let mut file = options.open(&temporary).map_err(|error| {
                format!(
                    "create coordinated finality temp file {}: {error}",
                    temporary.display()
                )
            })?;
            file.write_all(&bytes).map_err(|error| {
                format!(
                    "write coordinated finality temp file {}: {error}",
                    temporary.display()
                )
            })?;
            file.sync_all().map_err(|error| {
                format!(
                    "sync coordinated finality temp file {}: {error}",
                    temporary.display()
                )
            })?;
            fs::rename(&temporary, &self.path).map_err(|error| {
                format!(
                    "replace coordinated finality store {}: {error}",
                    self.path.display()
                )
            })?;
            File::open(parent)
                .and_then(|directory| directory.sync_all())
                .map_err(|error| {
                    format!(
                        "sync coordinated finality directory {}: {error}",
                        parent.display()
                    )
                })
        })();
        if write_result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        write_result
    }
}

fn default_coordinated_finality_path() -> PathBuf {
    std::env::var("SYNERGY_COORDINATED_FINALITY_FILE")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| crate::utils::resolve_data_path(COORDINATED_FINALITY_FILE))
}

/// Returns the configured coordinated-finality path without opening or
/// creating it. Public read surfaces use this to distinguish a mode that has
/// not produced a coordinated block yet from an existing store that must be
/// treated as the sole, independently verified finality authority.
pub(crate) fn configured_coordinated_finality_path() -> PathBuf {
    default_coordinated_finality_path()
}

fn record_from_package(
    config: &CoordinatedRoundRobinConfig,
    package: &CoordinatedCommittedBlockPackage,
) -> Result<CoordinatedFinalityRecord, String> {
    package.validate_against(config)?;
    let block_id = package.block.block_id()?;
    if package.coordinator_commit.block_hash
        != Hash::from_hex(&block_id.0)
            .map_err(|error| format!("coordinated finality block ID is not a hash: {error}"))?
    {
        return Err("coordinated finality package block ID does not match commit hash".to_string());
    }
    Ok(CoordinatedFinalityRecord {
        record_version: STORE_VERSION,
        height: package.block.header.height,
        block_id,
        coordinator_commit_hash: package.coordinator_commit.signing_hash()?,
        package: package.clone(),
    })
}

fn validate_state(
    config: &CoordinatedRoundRobinConfig,
    state: &CoordinatedFinalityState,
    store: &CoordinatedFinalityStore,
) -> Result<(), String> {
    config.validate()?;
    if state.store_version != STORE_VERSION
        || state.migration_parent_block_hash != store.migration_parent_block_hash
        || state.migration_parent_state_root != store.migration_parent_state_root
        || state.first_coordinated_height != store.first_coordinated_height
    {
        return Err("coordinated finality store migration anchor mismatch".to_string());
    }
    let mut previous = None;
    for record in &state.records {
        validate_record(config, record)?;
        if let Some(previous) = previous {
            validate_successor(previous, record)?;
        } else if record.height != state.first_coordinated_height
            || record.package.block.header.parent_block_hash != state.migration_parent_block_hash
            || record.package.block.header.state_root_before != state.migration_parent_state_root
        {
            return Err(
                "first coordinated finalized block does not extend the immutable migration anchor"
                    .to_string(),
            );
        }
        previous = Some(record);
    }
    Ok(())
}

fn validate_append(
    state: &CoordinatedFinalityState,
    record: &CoordinatedFinalityRecord,
) -> Result<(), String> {
    if let Some(previous) = state.records.last() {
        validate_successor(previous, record)
    } else if record.height != state.first_coordinated_height
        || record.package.block.header.parent_block_hash != state.migration_parent_block_hash
        || record.package.block.header.state_root_before != state.migration_parent_state_root
    {
        Err(
            "first coordinated finalized block does not extend the immutable migration anchor"
                .to_string(),
        )
    } else {
        Ok(())
    }
}

fn validate_successor(
    previous: &CoordinatedFinalityRecord,
    next: &CoordinatedFinalityRecord,
) -> Result<(), String> {
    if next.height.0 != previous.height.0.saturating_add(1) {
        return Err("coordinated finality store contains a height gap or duplicate".to_string());
    }
    let previous_hash = Hash::from_hex(&previous.block_id.0)
        .map_err(|error| format!("coordinated persisted block ID is not a hash: {error}"))?;
    if next.package.block.header.parent_block_hash != previous_hash
        || next.package.block.header.state_root_before
            != previous.package.block.header.state_root_after
    {
        return Err(
            "coordinated finalized block does not extend the persisted finalized tip".to_string(),
        );
    }
    Ok(())
}

fn validate_record(
    config: &CoordinatedRoundRobinConfig,
    record: &CoordinatedFinalityRecord,
) -> Result<(), String> {
    if record.record_version != STORE_VERSION
        || record.height != record.package.block.header.height
        || record.block_id != record.package.block.block_id()?
        || record.coordinator_commit_hash != record.package.coordinator_commit.signing_hash()?
    {
        return Err("coordinated finality record binding mismatch".to_string());
    }
    record.package.validate_against(config)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::coordinated_admission::coordinated_dag_frontier_root;
    use crate::consensus::coordinated_round_robin::{
        CoordinatedProposal, CoordinatorCommit, ProducerAssignment, COORDINATED_ROUND_ROBIN_V1,
    };
    use crate::consensus_parameters::ConsensusParameterRoot;
    use crate::dag_mempool::compute_tx_order_root;
    use crate::synergy_types::{
        AegisPqKeyId, AegisPqSignature, Block, BlockHeader, ChainId, ClusterId, Epoch, NetworkId,
        Round, UmaId, ValidatorId,
    };

    fn hash(label: &str) -> Hash {
        Hash::from_domain_bytes(
            "SYNERGY_COORDINATED_FINALITY_STORE_TEST_V1",
            label.as_bytes(),
        )
    }

    fn signature(label: &str) -> AegisPqSignature {
        AegisPqSignature {
            algorithm: "mldsa65".to_string(),
            signature_bytes: label.as_bytes().to_vec(),
        }
    }

    fn config() -> CoordinatedRoundRobinConfig {
        CoordinatedRoundRobinConfig {
            chain_id: 1266,
            network_id: "synergy-testnet-v3".to_string(),
            consensus_version: COORDINATED_ROUND_ROBIN_V1.to_string(),
            coordinator_id: "validator-1".to_string(),
            producer_ids: vec![
                "validator-2".to_string(),
                "validator-3".to_string(),
                "validator-4".to_string(),
                "validator-5".to_string(),
                "validator-6".to_string(),
            ],
            target_block_interval_ms: 2_000,
            producer_turn_timeout_ms: 4_000,
        }
    }

    fn package(
        height: u64,
        parent_block_hash: Hash,
        parent_state_root: Hash,
        state_root: Hash,
    ) -> CoordinatedCommittedBlockPackage {
        let transaction_root = compute_tx_order_root(&[]).expect("empty transaction root");
        let receipt_root = hash(&format!("receipt-root-{height}"));
        let prior_finality_reference = hash(&format!("prior-finality-reference-{height}"));
        let assignment = ProducerAssignment {
            chain_id: 1266,
            network_id: "synergy-testnet-v3".to_string(),
            consensus_version: COORDINATED_ROUND_ROBIN_V1.to_string(),
            epoch: 0,
            height,
            producer_round: 0,
            parent_block_hash,
            prior_finality_reference,
            assigned_producer_id: "validator-2".to_string(),
            coordinator_id: "validator-1".to_string(),
            assignment_sequence: height,
            intended_block_timestamp_ms: height.saturating_mul(2_000),
            coordinator_signature: signature("assignment"),
        };
        let block = Block {
            header: BlockHeader {
                version: 1,
                chain_id: ChainId::synergy_testnet_v3(),
                network_id: NetworkId::synergy_testnet_v3(),
                protocol_version: COORDINATED_ROUND_ROBIN_V1.to_string(),
                height: Height(height),
                round: Round(0),
                epoch: Epoch(0),
                cluster_id: ClusterId(0),
                height_context_root: hash("context"),
                parent_block_hash,
                parent_state_root,
                last_finalized_qc_hash: Hash::zero(),
                proposer_validator_id: ValidatorId("validator-2".to_string()),
                proposer_uma_id: UmaId("uma-validator-2".to_string()),
                proposer_key_id: AegisPqKeyId("validator-2-key".to_string()),
                active_validator_set_hash: hash("set"),
                eligible_validator_set_hash: hash("eligible"),
                validator_consensus_key_root: hash("keys"),
                frozen_bonded_weight_root: hash("weights"),
                cluster_schedule_version: "coordinated-v1".to_string(),
                cluster_map_hash: hash("clusters"),
                assigned_cluster_membership_root: hash("members"),
                assigned_cluster_validator_count: 6,
                assigned_cluster_total_voting_weight: 6,
                proposer_schedule_hash: hash("producers"),
                protocol_config_hash: ConsensusParameterRoot::from_canonical_manifest_bytes(
                    b"coordinated-test-parameters",
                ),
                cryptographic_profile_root: hash("crypto"),
                dag_frontier_root: coordinated_dag_frontier_root(
                    parent_block_hash,
                    transaction_root,
                    Hash::zero(),
                ),
                tx_order_root: transaction_root,
                tx_count: 0,
                protected_batch: None,
                evidence_root: prior_finality_reference,
                state_root_before: parent_state_root,
                state_root_after: state_root,
                receipt_root,
                app_version: 1,
                execution_version: 1,
                dag_version: 1,
                aegis_pqvm_version: "aegis-pqvm".to_string(),
                timestamp_ms_consensus_bounded: height.saturating_mul(2_000),
            },
            transactions: Vec::new(),
            proposer_signature: signature("producer"),
        };
        let block_hash =
            Hash::from_hex(&block.block_id().expect("block ID").0).expect("block ID hash");
        let proposal = CoordinatedProposal {
            epoch: 0,
            height,
            producer_round: 0,
            parent_block_hash,
            prior_finality_reference,
            block_hash,
            transaction_root,
            transaction_admission_root: Hash::zero(),
            transaction_admissions: Vec::new(),
            receipt_root,
            state_root,
            producer_id: "validator-2".to_string(),
            assignment_hash: assignment.signing_hash().expect("assignment hash"),
            producer_signature: block.proposer_signature.clone(),
        };
        let coordinator_commit = CoordinatorCommit {
            chain_id: 1266,
            network_id: "synergy-testnet-v3".to_string(),
            consensus_version: COORDINATED_ROUND_ROBIN_V1.to_string(),
            epoch: 0,
            height,
            producer_round: 0,
            parent_block_hash,
            prior_finality_reference,
            block_hash,
            transaction_root,
            transaction_admission_root: Hash::zero(),
            receipt_root,
            state_root,
            producer_id: "validator-2".to_string(),
            coordinator_id: "validator-1".to_string(),
            assignment_hash: assignment.signing_hash().expect("assignment hash"),
            coordinator_signature: signature("commit"),
        };
        CoordinatedCommittedBlockPackage {
            block,
            assignment,
            proposal,
            coordinator_commit,
        }
    }

    fn temp_store() -> (CoordinatedFinalityStore, PathBuf, Hash, Hash) {
        let path = crate::utils::test_temp_root(format!(
            "coordinated-finality-store-{}-{}/finality.json",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        let parent = hash("migration-parent");
        let parent_state = hash("migration-state");
        let store =
            CoordinatedFinalityStore::at_path(path.clone(), parent, parent_state, Height(42))
                .expect("store");
        (store, path, parent, parent_state)
    }

    #[test]
    fn persists_exact_packages_from_the_immutable_migration_anchor() {
        let (store, path, parent, parent_state) = temp_store();
        let first = package(42, parent, parent_state, hash("state-42"));
        let first_record = store
            .append_verified_finality(&config(), &first)
            .expect("persist first coordinated block");
        assert_eq!(
            store
                .append_verified_finality(&config(), &first)
                .expect("exact replay is idempotent"),
            first_record
        );
        let second_parent = Hash::from_hex(&first_record.block_id.0).expect("first block hash");
        let second = package(43, second_parent, hash("state-42"), hash("state-43"));
        store
            .append_verified_finality(&config(), &second)
            .expect("persist successor");
        assert_eq!(store.recover(&config()).expect("recover").len(), 2);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn rejects_alternate_evidence_or_a_gap_at_one_height() {
        let (store, path, parent, parent_state) = temp_store();
        let first = package(42, parent, parent_state, hash("state-42"));
        store
            .append_verified_finality(&config(), &first)
            .expect("persist first block");
        let alternate = package(42, parent, parent_state, hash("alternate-state-42"));
        assert!(store
            .append_verified_finality(&config(), &alternate)
            .expect_err("a height cannot have alternate coordinator evidence")
            .contains("different evidence"));
        let gap = package(44, hash("wrong-parent"), hash("state-42"), hash("state-44"));
        assert!(store.append_verified_finality(&config(), &gap).is_err());
        let _ = fs::remove_file(path);
    }
}
