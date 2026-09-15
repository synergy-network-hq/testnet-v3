//! Crash-safe persistence for typed PoSy finalized blocks and QCs.
//!
//! The inherited `BlockChain` journal stores a different block and certificate
//! format, so it must never be used as evidence for typed PoSy finality. This
//! store accepts only a sequence that has already passed typed QC verification,
//! binds it to a Genesis anchor, and atomically replaces its state file after
//! each finalized block.

use crate::synergy_types::{
    Block, BlockId, Epoch, EpochTransition, Hash, Height, QuorumCertificate, VotePhase,
};
use serde::{Deserialize, Serialize};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

// Version three binds successor consensus context to the QC subject rather
// than its timing-dependent signature subset. Version-two records cannot be
// resumed because they may have derived future heights from different QC
// evidence roots; Testnet-v3 has not been publicly launched, so recovery
// deliberately fails closed and requires a fresh genesis-bound store.
const STORE_VERSION: u32 = 3;
const TYPED_FINALITY_FILE: &str = "data/typed-posy-finality.json";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TypedFinalityRecord {
    pub record_version: u32,
    pub height: Height,
    pub block_id: BlockId,
    pub block: Block,
    pub quorum_certificate: QuorumCertificate,
    pub quorum_certificate_root: Hash,
}

/// Durable evidence that a verified current-validator quorum authorized the
/// next epoch's validator topology.  Signature verification remains the
/// coordinator's responsibility; persistence independently binds the
/// transition to an already-finalized typed block and rejects forks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TypedEpochTransitionRecord {
    pub record_version: u32,
    pub transition: EpochTransition,
    pub transition_root: Hash,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct TypedFinalityState {
    store_version: u32,
    genesis_anchor: Hash,
    records: Vec<TypedFinalityRecord>,
    epoch_transitions: Vec<TypedEpochTransitionRecord>,
}

/// The sole local persistence boundary for typed PoSy finality.
#[derive(Debug, Clone)]
pub struct TypedFinalityStore {
    path: PathBuf,
    genesis_anchor: Hash,
}

impl TypedFinalityStore {
    pub fn for_genesis_anchor(genesis_anchor: Hash) -> Result<Self, String> {
        Self::at_path(default_typed_finality_path(), genesis_anchor)
    }

    pub fn at_path(path: PathBuf, genesis_anchor: Hash) -> Result<Self, String> {
        if genesis_anchor.is_zero() {
            return Err("typed finality Genesis anchor must not be zero".to_string());
        }
        if path.as_os_str().is_empty() {
            return Err("typed finality store path is empty".to_string());
        }
        Ok(Self {
            path,
            genesis_anchor,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn genesis_anchor(&self) -> Hash {
        self.genesis_anchor
    }

    /// Loads and fully validates the persisted typed finality sequence.
    pub fn recover(&self) -> Result<Vec<TypedFinalityRecord>, String> {
        Ok(self.load_state()?.records)
    }

    pub fn latest(&self) -> Result<Option<TypedFinalityRecord>, String> {
        Ok(self.load_state()?.records.into_iter().last())
    }

    pub fn recover_epoch_transitions(&self) -> Result<Vec<TypedEpochTransitionRecord>, String> {
        Ok(self.load_state()?.epoch_transitions)
    }

    pub fn latest_epoch_transition(&self) -> Result<Option<TypedEpochTransitionRecord>, String> {
        Ok(self.load_state()?.epoch_transitions.into_iter().last())
    }

    /// Returns the sole persisted, already-verified epoch transition bound to
    /// one exact finalized typed block.  Callers must not select a transition
    /// by epoch number or peer claim: the finalized height and block identity
    /// are the restart-safe authority boundary.
    pub fn epoch_transition_for_finality(
        &self,
        finality: &TypedFinalityRecord,
    ) -> Result<Option<TypedEpochTransitionRecord>, String> {
        let state = self.load_state()?;
        let transition = state
            .epoch_transitions
            .into_iter()
            .filter(|record| {
                record.transition.finalized_height == finality.height
                    && record.transition.finalized_block_id == finality.block_id
            })
            .collect::<Vec<_>>();
        match transition.as_slice() {
            [] => Ok(None),
            [record] => Ok(Some(record.clone())),
            _ => Err(
                "typed PoSy finality store contains multiple epoch transitions for one finalized block"
                    .to_string(),
            ),
        }
    }

    /// Persists a typed block only after its QC has been verified and accepted
    /// by `ProofOfSynergyBft::commit_block`.
    ///
    /// The store deliberately does not own mutable validator state, therefore
    /// it cannot verify signatures itself. It rechecks every immutable
    /// block/QC binding and refuses forks, gaps, alternate Genesis anchors,
    /// and any attempt to substitute the legacy block journal.
    pub fn append_verified_finality(
        &self,
        block: &Block,
        quorum_certificate: &QuorumCertificate,
    ) -> Result<TypedFinalityRecord, String> {
        let mut state = self.load_state()?;
        let record = TypedFinalityRecord {
            record_version: STORE_VERSION,
            height: block.header.height,
            block_id: block.block_id()?,
            block: block.clone(),
            quorum_certificate: quorum_certificate.clone(),
            quorum_certificate_root: quorum_certificate.root()?,
        };
        validate_record(&record)?;
        validate_append(&state, &record)?;
        state.records.push(record.clone());
        self.persist_state(&state)?;
        Ok(record)
    }

    /// Persists an epoch transition only after the coordinator has verified
    /// its ML-DSA quorum signatures against the current active validator set.
    /// The store ties it to the typed block/QC already on disk, so a restart
    /// cannot silently substitute a different transition or topology.
    pub fn append_verified_epoch_transition(
        &self,
        transition: &EpochTransition,
    ) -> Result<TypedEpochTransitionRecord, String> {
        let mut state = self.load_state()?;
        let record = TypedEpochTransitionRecord {
            record_version: STORE_VERSION,
            transition: transition.clone(),
            transition_root: transition.root()?,
        };
        validate_epoch_transition_append(&state, &record)?;
        state.epoch_transitions.push(record.clone());
        self.persist_state(&state)?;
        Ok(record)
    }

    fn load_state(&self) -> Result<TypedFinalityState, String> {
        if !self.path.exists() {
            return Ok(TypedFinalityState {
                store_version: STORE_VERSION,
                genesis_anchor: self.genesis_anchor,
                records: Vec::new(),
                epoch_transitions: Vec::new(),
            });
        }
        let bytes = fs::read(&self.path).map_err(|error| {
            format!(
                "read typed PoSy finality store {}: {error}",
                self.path.display()
            )
        })?;
        let state: TypedFinalityState = serde_json::from_slice(&bytes).map_err(|error| {
            format!(
                "parse typed PoSy finality store {}: {error}",
                self.path.display()
            )
        })?;
        let canonical = serde_json::to_vec(&state)
            .map_err(|error| format!("canonicalize typed PoSy finality store: {error}"))?;
        if bytes != canonical {
            return Err(
                "typed PoSy finality store is not canonical; refusing mutable or torn state"
                    .to_string(),
            );
        }
        validate_state(&state, self.genesis_anchor)?;
        Ok(state)
    }

    fn persist_state(&self, state: &TypedFinalityState) -> Result<(), String> {
        validate_state(state, self.genesis_anchor)?;
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent).map_err(|error| {
                format!(
                    "create typed PoSy finality directory {}: {error}",
                    parent.display()
                )
            })?;
        }
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|error| format!("clock failure for typed finality persistence: {error}"))?
            .as_nanos();
        let temp_path = self
            .path
            .with_extension(format!("tmp-{}-{nonce}", std::process::id()));
        let bytes = serde_json::to_vec(state)
            .map_err(|error| format!("encode typed PoSy finality state: {error}"))?;
        let write_result = (|| -> Result<(), String> {
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let mut file = options.open(&temp_path).map_err(|error| {
                format!(
                    "open typed PoSy finality temp file {}: {error}",
                    temp_path.display()
                )
            })?;
            file.write_all(&bytes).map_err(|error| {
                format!(
                    "write typed PoSy finality temp file {}: {error}",
                    temp_path.display()
                )
            })?;
            file.sync_all().map_err(|error| {
                format!(
                    "sync typed PoSy finality temp file {}: {error}",
                    temp_path.display()
                )
            })?;
            fs::rename(&temp_path, &self.path).map_err(|error| {
                format!(
                    "atomically replace typed PoSy finality store {}: {error}",
                    self.path.display()
                )
            })?;
            sync_parent_directory(self.path.parent())?;
            Ok(())
        })();
        if write_result.is_err() {
            let _ = fs::remove_file(&temp_path);
        }
        write_result
    }
}

fn default_typed_finality_path() -> PathBuf {
    std::env::var("SYNERGY_TYPED_POSY_FINALITY_FILE")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| crate::utils::resolve_data_path(TYPED_FINALITY_FILE))
}

/// Returns the exact configured typed-finality path without opening or
/// creating it. Read-only surfaces use this to distinguish a node that has
/// not entered typed finality yet from a present store that must be validated
/// and treated as authoritative.
pub(crate) fn configured_typed_finality_path() -> PathBuf {
    default_typed_finality_path()
}

fn sync_parent_directory(parent: Option<&Path>) -> Result<(), String> {
    let Some(parent) = parent else {
        return Ok(());
    };
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| {
            format!(
                "sync typed PoSy finality directory {}: {error}",
                parent.display()
            )
        })
}

fn validate_state(state: &TypedFinalityState, expected_genesis_anchor: Hash) -> Result<(), String> {
    if state.store_version != STORE_VERSION {
        return Err(format!(
            "unsupported typed PoSy finality store version {}; expected {}",
            state.store_version, STORE_VERSION
        ));
    }
    if state.genesis_anchor != expected_genesis_anchor {
        return Err(
            "typed PoSy finality store Genesis anchor does not match this node".to_string(),
        );
    }
    let mut previous: Option<&TypedFinalityRecord> = None;
    for record in &state.records {
        validate_record(record)?;
        if let Some(previous) = previous {
            validate_successor(previous, record)?;
        } else if record.height.0 != 1
            || record.block.header.parent_block_hash != expected_genesis_anchor
        {
            return Err(
                "first typed PoSy finalized block must be height one and extend the Genesis anchor"
                    .to_string(),
            );
        }
        previous = Some(record);
    }
    let mut previous_transition: Option<&TypedEpochTransitionRecord> = None;
    for transition in &state.epoch_transitions {
        validate_epoch_transition_record(state, transition)?;
        if let Some(previous) = previous_transition {
            if transition.transition.from_epoch != previous.transition.to_epoch {
                return Err("typed PoSy epoch transitions are not sequential".to_string());
            }
        } else if transition.transition.from_epoch != Epoch(0) {
            return Err("first typed PoSy epoch transition must begin at epoch zero".to_string());
        }
        previous_transition = Some(transition);
    }
    Ok(())
}

fn validate_append(state: &TypedFinalityState, record: &TypedFinalityRecord) -> Result<(), String> {
    if let Some(previous) = state.records.last() {
        validate_successor(previous, record)
    } else if record.height.0 != 1 || record.block.header.parent_block_hash != state.genesis_anchor
    {
        Err(
            "first typed PoSy finalized block must be height one and extend the Genesis anchor"
                .to_string(),
        )
    } else {
        Ok(())
    }
}

fn validate_successor(
    previous: &TypedFinalityRecord,
    next: &TypedFinalityRecord,
) -> Result<(), String> {
    if next.height.0 != previous.height.0.saturating_add(1) {
        return Err("typed PoSy finality store contains a height gap or duplicate".to_string());
    }
    let previous_hash = Hash::from_hex(&previous.block_id.0)
        .map_err(|error| format!("typed PoSy persisted block ID is not a hash: {error}"))?;
    if next.block.header.parent_block_hash != previous_hash {
        return Err(
            "typed PoSy finalized block does not extend the persisted typed tip".to_string(),
        );
    }
    if next.block.header.state_root_before != previous.block.header.state_root_after {
        return Err(
            "typed PoSy finalized block state root does not extend the persisted typed tip"
                .to_string(),
        );
    }
    Ok(())
}

fn validate_record(record: &TypedFinalityRecord) -> Result<(), String> {
    if record.record_version != STORE_VERSION {
        return Err("unsupported typed PoSy finality record version".to_string());
    }
    if record.height != record.block.header.height || record.block_id != record.block.block_id()? {
        return Err("typed PoSy finality record block height or ID mismatch".to_string());
    }
    let qc = &record.quorum_certificate;
    let candidate_id = record.block.candidate_id()?;
    if qc.phase != VotePhase::Finality
        || qc.block_id != candidate_id
        || qc.height != record.height
        || qc.chain_id != record.block.header.chain_id
        || qc.network_id != record.block.header.network_id
        || qc.protocol_version != record.block.header.protocol_version
        || qc.round != record.block.header.round
        || qc.epoch != record.block.header.epoch
        || qc.cluster_id != record.block.header.cluster_id
        || qc.height_context_root != record.block.header.height_context_root
        || qc.active_validator_set_hash != record.block.header.active_validator_set_hash
        || qc.cluster_map_hash != record.block.header.cluster_map_hash
    {
        return Err("typed PoSy finality record block/QC binding mismatch".to_string());
    }
    if qc.threshold_weight_required == 0
        || qc.signed_weight < qc.threshold_weight_required
        || qc.aegis_pq_signatures.is_empty()
        || qc.aegis_pq_signatures.len() != qc.aegis_pq_key_ids.len()
    {
        return Err("typed PoSy finality record has incomplete QC evidence".to_string());
    }
    if record.quorum_certificate_root != qc.root()? {
        return Err("typed PoSy finality record QC root mismatch".to_string());
    }
    Ok(())
}

fn validate_epoch_transition_append(
    state: &TypedFinalityState,
    record: &TypedEpochTransitionRecord,
) -> Result<(), String> {
    validate_epoch_transition_record(state, record)?;
    if let Some(previous) = state.epoch_transitions.last() {
        if record.transition.from_epoch != previous.transition.to_epoch {
            return Err(
                "typed PoSy epoch transition does not extend the persisted epoch tip".to_string(),
            );
        }
    } else if record.transition.from_epoch != Epoch(0) {
        return Err("first typed PoSy epoch transition must begin at epoch zero".to_string());
    }
    Ok(())
}

fn validate_epoch_transition_record(
    state: &TypedFinalityState,
    record: &TypedEpochTransitionRecord,
) -> Result<(), String> {
    if record.record_version != STORE_VERSION {
        return Err("unsupported typed PoSy epoch-transition record version".to_string());
    }
    record.transition.validate_structure()?;
    if record.transition_root != record.transition.root()? {
        return Err("typed PoSy epoch-transition record root mismatch".to_string());
    }
    let finalized = state
        .records
        .iter()
        .find(|finality| finality.height == record.transition.finalized_height)
        .ok_or_else(|| {
            "epoch transition is not bound to a persisted finalized height".to_string()
        })?;
    if finalized.block_id != record.transition.finalized_block_id
        || finalized.block.header.height_context_root != record.transition.height_context_root
        || finalized.block.header.active_validator_set_hash
            != record.transition.active_validator_set_hash
    {
        return Err(
            "epoch transition does not bind the persisted typed finality evidence".to_string(),
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::synergy_types::{
        AegisPqKeyId, AegisPqSignature, BlockHeader, ChainId, ClusterId, Epoch, NetworkId, Round,
        UmaId, ValidatorId,
    };

    fn hash(label: &str) -> Hash {
        Hash::from_domain_bytes("SYNERGY_TYPED_FINALITY_STORE_TEST_V1", label.as_bytes())
    }

    fn block(height: u64, parent: Hash, state_before: Hash, state_after: Hash) -> Block {
        Block {
            header: BlockHeader {
                version: 2,
                chain_id: ChainId::synergy_testnet_v3(),
                network_id: NetworkId::synergy_testnet_v3(),
                protocol_version: "posy/2.2".to_string(),
                height: Height(height),
                round: Round(0),
                epoch: Epoch(0),
                cluster_id: ClusterId(0),
                height_context_root: hash("context"),
                parent_block_hash: parent,
                parent_state_root: state_before,
                last_finalized_qc_hash: hash("prior-qc"),
                proposer_validator_id: ValidatorId("validator-1".to_string()),
                proposer_uma_id: UmaId("uma-1".to_string()),
                proposer_key_id: AegisPqKeyId("key-1".to_string()),
                active_validator_set_hash: hash("set"),
                eligible_validator_set_hash: hash("eligible"),
                validator_consensus_key_root: hash("keys"),
                frozen_bonded_weight_root: hash("weights"),
                cluster_schedule_version: "dynamic-v3-floor7".to_string(),
                cluster_map_hash: hash("clusters"),
                assigned_cluster_membership_root: hash("members"),
                assigned_cluster_validator_count: 6,
                assigned_cluster_total_voting_weight: 6,
                proposer_schedule_hash: hash("leaders"),
                protocol_config_hash: crate::consensus_parameters::ConsensusParameterRoot::from_canonical_manifest_bytes(b"test-parameters"),
                cryptographic_profile_root: hash("crypto"),
                dag_frontier_root: hash("dag"),
                tx_order_root: hash("txs"),
                tx_count: 0,
                protected_batch: None,
                evidence_root: hash("evidence"),
                state_root_before: state_before,
                state_root_after: state_after,
                receipt_root: hash("receipts"),
                app_version: 1,
                execution_version: 1,
                dag_version: 1,
                aegis_pqvm_version: "aegis-pqvm".to_string(),
                timestamp_ms_consensus_bounded: 1,
                base_fee_per_gas_nwei: 0,
                gas_used: 0,
                gas_limit: 0,
                pq_gas_used: 0,
                pq_gas_limit: 0,
                pq_gas_multiplier: 0,
                fee_market_version: 0,
            },
            transactions: Vec::new(),
            proposer_signature: AegisPqSignature {
                algorithm: "mldsa65".to_string(),
                signature_bytes: vec![1],
            },
        }
    }

    fn qc(block: &Block) -> QuorumCertificate {
        QuorumCertificate {
            qc_version: 1,
            chain_id: block.header.chain_id,
            network_id: block.header.network_id.clone(),
            protocol_version: block.header.protocol_version.clone(),
            height: block.header.height,
            round: block.header.round,
            epoch: block.header.epoch,
            cluster_id: block.header.cluster_id,
            height_context_root: block.header.height_context_root,
            phase: VotePhase::Finality,
            block_id: block.candidate_id().unwrap(),
            highest_prepared_vc_root: None,
            active_validator_set_hash: block.header.active_validator_set_hash,
            cluster_map_hash: block.header.cluster_map_hash,
            threshold_weight_required: 5,
            signed_weight: 5,
            signer_bitmap: vec![0b0001_1111],
            aegis_pq_signatures: vec![AegisPqSignature {
                algorithm: "mldsa65".to_string(),
                signature_bytes: vec![1],
            }],
            aegis_pq_key_ids: vec![AegisPqKeyId("key-1".to_string())],
        }
    }

    fn temp_store(label: &str, anchor: Hash) -> (TypedFinalityStore, PathBuf) {
        let path = crate::utils::test_temp_root(format!(
            "synergy-typed-finality-{label}-{}-{}.json",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        (
            TypedFinalityStore::at_path(path.clone(), anchor).unwrap(),
            path,
        )
    }

    fn epoch_transition(block: &Block) -> EpochTransition {
        EpochTransition {
            chain_id: ChainId::synergy_testnet_v3(),
            network_id: NetworkId::synergy_testnet_v3(),
            from_epoch: Epoch(0),
            to_epoch: Epoch(1),
            finalized_height: block.header.height,
            finalized_block_id: block.block_id().unwrap(),
            active_validator_set_hash: block.header.active_validator_set_hash,
            next_validator_set_hash: hash("next-validator-set"),
            cluster_map_hash: hash("next-cluster-map"),
            height_context_root: block.header.height_context_root,
            signer_key_ids: vec![AegisPqKeyId("key-transition".to_string())],
            signatures: vec![AegisPqSignature {
                algorithm: "mldsa65".to_string(),
                signature_bytes: vec![2],
            }],
        }
    }

    #[test]
    fn persists_and_recovers_a_linear_typed_finality_chain() {
        let anchor = hash("genesis-anchor");
        let (store, path) = temp_store("linear", anchor);
        let one = block(1, anchor, hash("state-0"), hash("state-1"));
        store.append_verified_finality(&one, &qc(&one)).unwrap();
        let one_id = Hash::from_hex(&one.block_id().unwrap().0).unwrap();
        let two = block(2, one_id, hash("state-1"), hash("state-2"));
        store.append_verified_finality(&two, &qc(&two)).unwrap();
        let recovered = store.recover().unwrap();
        assert_eq!(recovered.len(), 2);
        assert_eq!(recovered[1].height, Height(2));
        let _ = fs::remove_file(path);
    }

    #[test]
    fn rejects_a_typed_finality_fork_before_persistence() {
        let anchor = hash("genesis-anchor");
        let (store, path) = temp_store("fork", anchor);
        let one = block(1, anchor, hash("state-0"), hash("state-1"));
        store.append_verified_finality(&one, &qc(&one)).unwrap();
        let conflicting = block(1, anchor, hash("state-0"), hash("other-state-1"));
        let error = store
            .append_verified_finality(&conflicting, &qc(&conflicting))
            .unwrap_err();
        assert!(error.contains("height gap or duplicate"));
        assert_eq!(store.recover().unwrap().len(), 1);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn persists_a_canonical_epoch_transition_only_after_its_finalized_block() {
        let anchor = hash("genesis-anchor");
        let (store, path) = temp_store("transition", anchor);
        let one = block(1, anchor, hash("state-0"), hash("state-1"));
        let transition = epoch_transition(&one);
        assert!(store.append_verified_epoch_transition(&transition).is_err());

        store.append_verified_finality(&one, &qc(&one)).unwrap();
        let persisted = store.append_verified_epoch_transition(&transition).unwrap();
        assert_eq!(persisted.transition, transition);
        assert_eq!(store.recover_epoch_transitions().unwrap(), vec![persisted]);

        let mut alternate = transition;
        alternate.cluster_map_hash = hash("alternate-clusters");
        assert!(store.append_verified_epoch_transition(&alternate).is_err());
        let _ = fs::remove_file(path);
    }
}
