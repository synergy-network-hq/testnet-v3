//! Verified, non-signing typed-finality recovery for service observers.
//!
//! RPC and indexer roles need the same finalized-chain evidence as validators,
//! but must never load a consensus private key or gain proposal/vote authority.
//! This module replays only bounded, typed-QC finality records from canonical
//! finalized Genesis inputs and persists them only after independent proposal,
//! QC, execution, and successor-context verification.

use crate::consensus::posy::{LocalConsensusContext, ProofOfSynergyBft};
use crate::consensus::testnet_v3_bootstrap::{
    load_testnet_v3_genesis_bootstrap, TestnetV3GenesisBootstrap,
};
use crate::consensus::testnet_v3_finality_context::FinalizedTypedContextProvider;
use crate::consensus::typed_finality_store::{TypedFinalityRecord, TypedFinalityStore};
use crate::execution::{compute_state_root_after, execute_block, ExecutionState};
use crate::genesis::{canonical_genesis, GenesisDocument};
use crate::synergy_types::{
    Block, Epoch, Hash, Height, HeightConsensusContext, ProtocolConfig, VotePhase,
};
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

/// Maximum number of finalized records accepted or returned in one observer
/// recovery segment. Longer histories must be transferred as verified,
/// consecutive segments.
pub const MAX_TYPED_FINALITY_OBSERVER_RECORDS: usize = 32;

/// Public, finalized-only dependencies for a non-signing observer.
///
/// Callers must obtain these values from canonical finalized Genesis. This
/// type intentionally has no local validator identifier, private key, or
/// signing authority.
#[derive(Debug, Clone)]
pub struct TypedFinalityObserverInputs {
    /// Public typed validator topology derived from finalized Genesis.
    pub bootstrap: TestnetV3GenesisBootstrap,
    /// Finalized and Genesis-bound consensus configuration.
    pub protocol_config: ProtocolConfig,
    /// Immutable canonical Genesis hash.
    pub genesis_anchor: Hash,
    /// Post-ceremony execution root committed by canonical Genesis.
    pub deployed_genesis_state_root: Hash,
    /// Restored post-ceremony execution state.
    pub execution_state: ExecutionState,
    /// Role-local durable typed finality store.
    pub finality_store: TypedFinalityStore,
}

/// A typed-finality replica that can verify and persist observer data without
/// any validator signing material.
pub struct TypedFinalityObserver {
    consensus: ProofOfSynergyBft,
    execution_state: ExecutionState,
    finality_store: TypedFinalityStore,
    context_provider: FinalizedTypedContextProvider,
    next_context: LocalConsensusContext,
}

// Service roles are intentionally non-signing.  Their P2P receiver therefore
// owns one process-local observer rather than a coordinator mailbox or any
// validator key material.  Installing the receiver before P2P starts makes a
// missing, invalid, or stale local journal a fail-closed service startup
// condition instead of a false public height of zero.
static TYPED_FINALITY_OBSERVER_INGRESS: OnceLock<Mutex<Option<TypedFinalityObserver>>> =
    OnceLock::new();

fn observer_ingress() -> &'static Mutex<Option<TypedFinalityObserver>> {
    TYPED_FINALITY_OBSERVER_INGRESS.get_or_init(|| Mutex::new(None))
}

/// Installs the only non-signing typed-finality receiver for this process.
pub fn install_typed_finality_observer(observer: TypedFinalityObserver) -> Result<(), String> {
    let mut slot = observer_ingress()
        .lock()
        .map_err(|_| "typed finality observer ingress lock is poisoned".to_string())?;
    if slot.is_some() {
        return Err("typed finality observer ingress is already installed".to_string());
    }
    *slot = Some(observer);
    Ok(())
}

/// Removes the service observer before the role runtime exits or restarts.
pub fn remove_typed_finality_observer() -> Result<(), String> {
    let mut slot = observer_ingress()
        .lock()
        .map_err(|_| "typed finality observer ingress lock is poisoned".to_string())?;
    *slot = None;
    Ok(())
}

/// Returns the next verified height required by an installed service observer.
/// `None` means this process is not a typed-finality observer role.
pub fn typed_finality_observer_next_missing_height() -> Option<Height> {
    observer_ingress().lock().ok().and_then(|slot| {
        slot.as_ref()
            .map(TypedFinalityObserver::next_missing_height)
    })
}

/// Imports a verified wire segment into the installed, non-signing observer.
pub fn import_typed_finality_observer_records(
    records: &[TypedFinalityRecord],
) -> Result<usize, String> {
    let mut slot = observer_ingress()
        .lock()
        .map_err(|_| "typed finality observer ingress lock is poisoned".to_string())?;
    let observer = slot
        .as_mut()
        .ok_or_else(|| "typed finality observer ingress is not installed".to_string())?;
    observer.import_records(records)
}

/// Serves a bounded segment from the installed observer's independently
/// validated durable prefix. This is used only by relayers for configured
/// public service observers.
pub fn typed_finality_observer_snapshot_from(
    next_height: Height,
) -> Result<Vec<TypedFinalityRecord>, String> {
    let slot = observer_ingress()
        .lock()
        .map_err(|_| "typed finality observer ingress lock is poisoned".to_string())?;
    let observer = slot
        .as_ref()
        .ok_or_else(|| "typed finality observer ingress is not installed".to_string())?;
    observer.bounded_snapshot_from(next_height)
}

/// Serves already-verified finality from a validator's canonical, Genesis
/// bound journal. Validators do not install a non-signing observer because
/// their coordinator already owns the same durable state; this read-only path
/// lets only the VPN relayer tier pull a bounded replay segment.
pub fn canonical_typed_finality_snapshot_from(
    next_height: Height,
) -> Result<Vec<TypedFinalityRecord>, String> {
    let genesis = canonical_genesis().map_err(|error| {
        format!("typed finality snapshot cannot load canonical Genesis: {error}")
    })?;
    let anchor = Hash::from_hex(genesis.hash())
        .map_err(|error| format!("typed finality snapshot Genesis hash is invalid: {error}"))?;
    let store = TypedFinalityStore::for_genesis_anchor(anchor)
        .map_err(|error| format!("typed finality snapshot cannot open durable store: {error}"))?;
    Ok(store
        .recover()?
        .into_iter()
        .filter(|record| record.height.0 >= next_height.0)
        .take(MAX_TYPED_FINALITY_OBSERVER_RECORDS)
        .collect())
}

impl TypedFinalityObserver {
    /// Creates an observer from the process's canonical finalized Genesis and
    /// its role-local default finality-store path.
    ///
    /// # Errors
    ///
    /// Returns an error when Genesis, its parameter binding, the ceremony
    /// execution state, or existing typed finality cannot be independently
    /// verified.
    pub fn from_canonical_finalized_genesis() -> Result<Self, String> {
        let genesis = canonical_genesis().map_err(|error| {
            format!("typed finality observer cannot load canonical Genesis: {error}")
        })?;
        let genesis_anchor = Hash::from_hex(genesis.hash())
            .map_err(|error| format!("typed finality observer Genesis hash is invalid: {error}"))?;
        let finality_store =
            TypedFinalityStore::for_genesis_anchor(genesis_anchor).map_err(|error| {
                format!("typed finality observer cannot open finality store: {error}")
            })?;
        Self::from_finalized_genesis(genesis, finality_store)
    }

    /// Creates an observer from an already-loaded canonical finalized Genesis
    /// and a role-local durable store.
    ///
    /// # Errors
    ///
    /// Returns an error when the document lacks its finalized binding or when
    /// the supplied store belongs to another Genesis.
    pub fn from_finalized_genesis(
        genesis: &GenesisDocument,
        finality_store: TypedFinalityStore,
    ) -> Result<Self, String> {
        let consensus_parameters = genesis.consensus_parameters().cloned().ok_or_else(|| {
            "typed finality observer requires a finalized consensus parameter binding in canonical Genesis"
                .to_string()
        })?;
        consensus_parameters
            .require_genesis_binding()
            .map_err(|error| {
                format!("typed finality observer rejects an unbound parameter manifest: {error}")
            })?;
        consensus_parameters.manifest.validate_finalized()?;
        if consensus_parameters.root
            != consensus_parameters
                .protocol_config
                .consensus_parameter_root
        {
            return Err(
                "typed finality observer parameter root disagrees with the loaded protocol configuration"
                    .to_string(),
            );
        }

        let bootstrap = load_testnet_v3_genesis_bootstrap(genesis).map_err(|error| {
            format!("typed finality observer cannot derive finalized Genesis bootstrap: {error}")
        })?;
        let genesis_anchor = Hash::from_hex(genesis.hash())
            .map_err(|error| format!("typed finality observer Genesis hash is invalid: {error}"))?;
        let deployed_genesis_state_root = finalized_genesis_execution_root(genesis)?;
        let execution_state = crate::testnet_v3_execution_bootstrap::load_finalized_testnet_v3_genesis_execution_state(genesis)
            .map_err(|error| {
                format!("typed finality observer requires finalized Genesis execution state: {error}")
            })?;

        Self::from_finalized_inputs(TypedFinalityObserverInputs {
            bootstrap,
            protocol_config: consensus_parameters.protocol_config,
            genesis_anchor,
            deployed_genesis_state_root,
            execution_state,
            finality_store,
        })
    }

    /// Creates an observer from finalized public inputs. This is the runtime
    /// integration boundary for roles that have already loaded canonical
    /// Genesis through a release guard.
    ///
    /// # Errors
    ///
    /// Returns an error if public inputs disagree, or if a previously
    /// persisted record fails independent replay.
    pub fn from_finalized_inputs(inputs: TypedFinalityObserverInputs) -> Result<Self, String> {
        if inputs.genesis_anchor.is_zero() || inputs.deployed_genesis_state_root.is_zero() {
            return Err(
                "typed finality observer requires non-zero finalized Genesis bindings".to_string(),
            );
        }
        if inputs.finality_store.genesis_anchor() != inputs.genesis_anchor {
            return Err(
                "typed finality observer store Genesis anchor disagrees with finalized inputs"
                    .to_string(),
            );
        }
        inputs
            .bootstrap
            .validator_set
            .validate_unique_validator_and_key_ids()?;
        inputs
            .bootstrap
            .cluster_map
            .validate_complete_balanced_assignment(
                &inputs.bootstrap.validator_set.active_for_epoch(Epoch(0)),
            )?;
        inputs.protocol_config.hash()?;
        if compute_state_root_after(&inputs.execution_state)? != inputs.deployed_genesis_state_root
        {
            return Err(
                "typed finality observer execution state disagrees with finalized Genesis root"
                    .to_string(),
            );
        }

        let persisted = inputs.finality_store.recover()?;
        let context_provider = FinalizedTypedContextProvider::new(
            inputs.bootstrap.clone(),
            inputs.protocol_config.clone(),
            inputs.finality_store.clone(),
            inputs.deployed_genesis_state_root,
        )?;
        let mut consensus = ProofOfSynergyBft::new(
            &inputs.bootstrap.verifier,
            inputs.bootstrap.validator_set.clone(),
            inputs.bootstrap.cluster_map.clone(),
            inputs.protocol_config.clone(),
        );

        // The durable store contains evidence but has no signing authority.
        // Replay it through a temporary, Genesis-bound store so every
        // historical successor context is reconstructed exclusively by the
        // canonical finalized-context provider.  This prevents an observer
        // from inheriting an old, timing-dependent full-QC evidence root.
        let replay_store = TransientFinalityStore::new(inputs.genesis_anchor)?;
        let replay_provider = FinalizedTypedContextProvider::new(
            inputs.bootstrap.clone(),
            inputs.protocol_config,
            replay_store.store.clone(),
            inputs.deployed_genesis_state_root,
        )?;
        let mut replay_context = replay_provider.recover_next_context()?;
        let mut replay_state = inputs.execution_state.clone();
        for record in &persisted {
            verify_record(&mut consensus, &replay_context, &replay_state, record)?;
            let durable = replay_store
                .store
                .append_verified_finality(&record.block, &record.quorum_certificate)?;
            if !same_finality_subject(&durable, record)? {
                return Err(
                    "typed finality observer persisted recovery evidence conflicts with its finalized subject"
                        .to_string(),
                );
            }
            replay_state = execute_finalized_core_block(&replay_state, &record.block)?;
            replay_context = replay_provider.recover_next_context()?;
        }
        // Do not return a locally-derived replay context. The live store's
        // provider is the only authority for the next height after startup.
        let next_context = context_provider.recover_next_context()?;
        Ok(Self {
            consensus,
            execution_state: replay_state,
            finality_store: inputs.finality_store,
            context_provider,
            next_context,
        })
    }

    /// Returns the exact next finality height this observer requires.
    pub fn next_missing_height(&self) -> Height {
        self.next_context.height_context.height
    }

    /// Returns a clone of the immutable context for [`Self::next_missing_height`].
    pub fn next_context(&self) -> &LocalConsensusContext {
        &self.next_context
    }

    /// Returns the durable finality store used by this observer.
    pub fn finality_store(&self) -> &TypedFinalityStore {
        &self.finality_store
    }

    /// Reads at most [`MAX_TYPED_FINALITY_OBSERVER_RECORDS`] persisted records
    /// starting at `next_height`. Returned records have already passed local
    /// replay during construction or import; a recipient must still verify
    /// them independently before persistence.
    ///
    /// # Errors
    ///
    /// Returns an error if the local durable store is malformed.
    pub fn bounded_snapshot_from(
        &self,
        next_height: Height,
    ) -> Result<Vec<TypedFinalityRecord>, String> {
        Ok(self
            .finality_store
            .recover()?
            .into_iter()
            .filter(|record| record.height.0 >= next_height.0)
            .take(MAX_TYPED_FINALITY_OBSERVER_RECORDS)
            .collect())
    }

    /// Independently verifies and durably imports one bounded, consecutive
    /// finality segment. Exact matching already-persisted records are
    /// idempotent; a gap, fork, rewrite, invalid QC, invalid core proposal, or
    /// execution mismatch is rejected before the next record is persisted.
    ///
    /// # Errors
    ///
    /// Returns an error for an empty or oversized segment, invalid evidence,
    /// or a segment that does not extend the durable typed tip exactly.
    pub fn import_records(&mut self, records: &[TypedFinalityRecord]) -> Result<usize, String> {
        if records.is_empty() || records.len() > MAX_TYPED_FINALITY_OBSERVER_RECORDS {
            return Err("typed finality observer segment has an invalid record count".to_string());
        }

        let mut persisted = self.finality_store.recover()?;
        let mut imported = 0usize;
        for record in records {
            if record.height.0 < self.next_context.height_context.height.0 {
                let index =
                    record.height.0.checked_sub(1).ok_or_else(|| {
                        "typed finality observer record has height zero".to_string()
                    })? as usize;
                let existing = persisted.get(index).ok_or_else(|| {
                    "typed finality observer record is absent from its claimed durable prefix"
                        .to_string()
                })?;
                if !same_finality_subject(existing, record)? {
                    return Err(
                        "TYPED_FINALITY_OBSERVER_SOURCE_CONFLICT: supplied record conflicts with durable finality"
                            .to_string(),
                    );
                }
                continue;
            }
            if record.height != self.next_context.height_context.height {
                return Err(
                    "typed finality observer segment is not an exact successor of the durable tip"
                        .to_string(),
                );
            }

            let execution_state = verify_record(
                &mut self.consensus,
                &self.next_context,
                &self.execution_state,
                record,
            )?;
            let durable = self
                .finality_store
                .append_verified_finality(&record.block, &record.quorum_certificate)?;
            if !same_finality_subject(&durable, record)? {
                return Err(
                    "TYPED_FINALITY_OBSERVER_SOURCE_CONFLICT: persisted record differs from the independently verified finalized subject"
                        .to_string(),
                );
            }
            self.execution_state = execution_state;
            // The full QC signer subset is evidence, not next-height
            // authority. Recover the context only through the canonical
            // finalized-context provider after durable persistence.
            self.next_context = self.context_provider.recover_next_context()?;
            persisted.push(durable);
            imported = imported.saturating_add(1);
        }
        Ok(imported)
    }
}

/// A private, short-lived typed-finality journal used only to independently
/// replay an existing observer store. Its `Drop` implementation removes the
/// evidence copy whether recovery succeeds or fails.
struct TransientFinalityStore {
    store: TypedFinalityStore,
    path: PathBuf,
}

impl TransientFinalityStore {
    fn new(genesis_anchor: Hash) -> Result<Self, String> {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|error| format!("typed finality observer replay clock failure: {error}"))?
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "synergy-typed-finality-observer-replay-{}-{nonce}.json",
            std::process::id()
        ));
        let store = TypedFinalityStore::at_path(path.clone(), genesis_anchor)?;
        Ok(Self { store, path })
    }
}

impl Drop for TransientFinalityStore {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

fn finalized_genesis_execution_root(genesis: &GenesisDocument) -> Result<Hash, String> {
    let root = genesis
        .value()
        .get("execution")
        .and_then(|execution| execution.get("genesis_execution_state_root"))
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| {
            "finalized Genesis omits execution.genesis_execution_state_root".to_string()
        })?;
    Hash::from_hex(root).map_err(|error| {
        format!("finalized Genesis execution state root is not canonical: {error}")
    })
}

fn verify_record(
    consensus: &mut ProofOfSynergyBft,
    context: &LocalConsensusContext,
    execution_state: &ExecutionState,
    record: &TypedFinalityRecord,
) -> Result<ExecutionState, String> {
    if record.height != context.height_context.height {
        return Err(
            "typed finality observer record is not the next immutable consensus height".to_string(),
        );
    }
    // A durable finalized record carries no timeout certificate, so the live
    // TC-driven round check can never be satisfied here and would reject every
    // record finalized at a round greater than zero. Use the finalized-record
    // recovery path, whose round authority is the finality QC verified
    // immediately below, and which still binds `header.round` through the
    // proposer schedule and the proposer's signature over the full header.
    consensus.validate_finalized_core_record(&record.block, context, execution_state)?;
    verify_finality_qc(
        consensus,
        &record.block,
        &record.quorum_certificate,
        &context.height_context,
    )?;
    if record.quorum_certificate_root != record.quorum_certificate.root()? {
        return Err("typed finality observer record QC root mismatch".to_string());
    }
    execute_finalized_core_block(execution_state, &record.block)
}

/// Full QC signer evidence can vary across otherwise-identical quorum
/// certificates. The finalized subject is stable, and is the only value
/// allowed to control successor context or observer idempotency.
fn same_finality_subject(
    durable: &TypedFinalityRecord,
    supplied: &TypedFinalityRecord,
) -> Result<bool, String> {
    Ok(durable.height == supplied.height
        && durable.block_id == supplied.block_id
        && durable.block == supplied.block
        && durable.quorum_certificate.finality_context_root()?
            == supplied.quorum_certificate.finality_context_root()?)
}

fn verify_finality_qc(
    consensus: &ProofOfSynergyBft,
    block: &Block,
    quorum_certificate: &crate::synergy_types::QuorumCertificate,
    height_context: &HeightConsensusContext,
) -> Result<(), String> {
    let expected_context_root = height_context.root()?;
    if block.header.height_context_root != expected_context_root
        || quorum_certificate.height_context_root != expected_context_root
        || quorum_certificate.phase != VotePhase::Finality
        || quorum_certificate.block_id != block.candidate_id()?
    {
        return Err("typed finality observer block/QC binding mismatch".to_string());
    }
    consensus.verify_qc(quorum_certificate, height_context)
}

fn execute_finalized_core_block(
    state: &ExecutionState,
    block: &Block,
) -> Result<ExecutionState, String> {
    let mut authorized = state.clone();
    for transaction in &block.transactions {
        authorized.mark_authorized_at(
            transaction,
            block
                .header
                .timestamp_ms_consensus_bounded
                .saturating_div(1_000),
        )?;
    }
    let execution = execute_block(block, &authorized)?;
    if execution.state_root_after != block.header.state_root_after
        || execution.receipt_root != block.header.receipt_root
    {
        return Err(
            "typed finality observer finalized block execution roots do not match proposal header"
                .to_string(),
        );
    }
    Ok(execution.state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::aegis_pqvm::AegisPqvmSigner;
    use crate::synergy_types::{
        AegisPqKeyRole, ClusterId, ClusterMap, Hash, Round, ValidatorId, ValidatorRecord,
        ValidatorSet, ValidatorStatus,
    };
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_store(label: &str, anchor: Hash) -> (TypedFinalityStore, PathBuf) {
        let path = crate::utils::test_temp_root(format!(
            "typed-finality-observer-{label}-{}-{}.json",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("test clock")
                .as_nanos()
        ));
        let store = TypedFinalityStore::at_path(path.clone(), anchor).expect("test store");
        (store, path)
    }

    fn fixture() -> (
        TestnetV3GenesisBootstrap,
        AegisPqvmSigner,
        ProtocolConfig,
        Hash,
        Hash,
    ) {
        let mut signer = AegisPqvmSigner::initialize_required().expect("Aegis signer");
        let mut validators = Vec::new();
        for index in 0..6 {
            let uma = format!("typed-finality-observer-uma-{index}");
            let key_id = signer
                .generate_and_register_key(
                    &uma,
                    vec![
                        AegisPqKeyRole::ConsensusVote,
                        AegisPqKeyRole::ConsensusProposer,
                        AegisPqKeyRole::EpochTransition,
                    ],
                    Epoch(0),
                )
                .expect("test key");
            let key = signer.public_key_record(&key_id).expect("public test key");
            validators.push(ValidatorRecord {
                validator_id: ValidatorId(format!("typed-finality-observer-validator-{index}")),
                validator_uma_id: crate::synergy_types::UmaId(uma),
                consensus_public_key: key.clone(),
                peer_public_key: key.clone(),
                operator_public_key: key,
                voting_weight: 1,
                status: ValidatorStatus::Active,
                cluster_id: ClusterId(0),
                activation_epoch: Epoch(0),
            });
        }
        let finalized_epoch_seed_root =
            Hash::from_domain_bytes("typed-finality-observer-test", b"epoch-seed");
        let mut validator_set = ValidatorSet {
            epoch: Epoch(0),
            validators,
        };
        let cluster_map =
            ClusterMap::derive_from_finalized_epoch_seed(&validator_set, finalized_epoch_seed_root)
                .expect("cluster map");
        for validator in &mut validator_set.validators {
            validator.cluster_id = cluster_map
                .assignments
                .iter()
                .find(|assignment| assignment.validator_id == validator.validator_id)
                .expect("cluster assignment")
                .cluster_id;
        }
        let cluster_map =
            ClusterMap::derive_from_finalized_epoch_seed(&validator_set, finalized_epoch_seed_root)
                .expect("stable cluster map");
        let bootstrap = TestnetV3GenesisBootstrap {
            validator_set,
            cluster_map,
            verifier: signer.verifier(),
            finalized_epoch_seed_root,
            genesis_transition_root: Hash::from_domain_bytes(
                "typed-finality-observer-test",
                b"genesis-transition",
            ),
            cryptographic_profile_root: Hash::from_domain_bytes(
                "typed-finality-observer-test",
                b"cryptographic-profile",
            ),
        };
        let protocol_config = ProtocolConfig::testnet_v3();
        let genesis_anchor =
            Hash::from_domain_bytes("typed-finality-observer-test", b"genesis-anchor");
        let deployed_genesis_state_root =
            compute_state_root_after(&ExecutionState::new()).expect("empty execution root");
        (
            bootstrap,
            signer,
            protocol_config,
            genesis_anchor,
            deployed_genesis_state_root,
        )
    }

    fn observer(
        bootstrap: TestnetV3GenesisBootstrap,
        protocol_config: ProtocolConfig,
        genesis_anchor: Hash,
        deployed_genesis_state_root: Hash,
        finality_store: TypedFinalityStore,
    ) -> TypedFinalityObserver {
        TypedFinalityObserver::from_finalized_inputs(TypedFinalityObserverInputs {
            bootstrap,
            protocol_config,
            genesis_anchor,
            deployed_genesis_state_root,
            execution_state: ExecutionState::new(),
            finality_store,
        })
        .expect("observer startup")
    }

    fn signed_record(
        consensus: &mut ProofOfSynergyBft,
        signer: &mut AegisPqvmSigner,
        context: &LocalConsensusContext,
        state: &ExecutionState,
        store: &TypedFinalityStore,
    ) -> TypedFinalityRecord {
        let proposer = consensus
            .proposer_for(&context.height_context, context.round)
            .expect("scheduled proposer");
        let block = consensus
            .propose_core_block(signer, &proposer, context, state)
            .expect("signed core block");
        let validators = consensus.validator_set.validators.clone();
        let validation_votes = validators
            .iter()
            .take(5)
            .map(|validator| {
                consensus
                    .validation_vote(signer, validator, &block, &context.height_context)
                    .expect("validation vote")
            })
            .collect::<Vec<_>>();
        let validation_certificate = consensus
            .form_vc(&validation_votes, &context.height_context)
            .expect("validation certificate");
        let finality_votes = validators
            .iter()
            .take(5)
            .map(|validator| {
                consensus
                    .finality_vote(
                        signer,
                        validator,
                        &block,
                        &validation_certificate,
                        &context.height_context,
                    )
                    .expect("finality vote")
            })
            .collect::<Vec<_>>();
        let qc = consensus
            .form_qc(&finality_votes, &context.height_context)
            .expect("finality QC");
        store
            .append_verified_finality(&block, &qc)
            .expect("source finality")
    }

    /// Produces a record finalized at round 1 by driving the *source* coordinator
    /// through a real timeout certificate, exactly as a live validator does.
    fn signed_record_after_round_change(
        consensus: &mut ProofOfSynergyBft,
        signer: &mut AegisPqvmSigner,
        context: &LocalConsensusContext,
        state: &ExecutionState,
        store: &TypedFinalityStore,
    ) -> TypedFinalityRecord {
        let validators = consensus.validator_set.validators.clone();
        let timeout_votes = validators
            .iter()
            .take(5)
            .map(|validator| {
                consensus
                    .timeout_vote(signer, validator, &context.height_context, Round(0), None)
                    .expect("timeout vote")
            })
            .collect::<Vec<_>>();
        let tc = consensus
            .form_tc(&timeout_votes, &context.height_context)
            .expect("timeout certificate");
        assert_eq!(
            consensus
                .advance_round_after_tc(&tc, &context.height_context, Round(0))
                .expect("authorized round advance"),
            Round(1)
        );

        let mut round_one = context.clone();
        round_one.round = Round(1);
        let proposer = consensus
            .proposer_for(&round_one.height_context, Round(1))
            .expect("round-one scheduled proposer");
        let block = consensus
            .propose_core_block(signer, &proposer, &round_one, state)
            .expect("round-one core block");
        assert_eq!(block.header.round, Round(1));

        let validation_votes = validators
            .iter()
            .take(5)
            .map(|validator| {
                consensus
                    .validation_vote(signer, validator, &block, &round_one.height_context)
                    .expect("validation vote")
            })
            .collect::<Vec<_>>();
        let validation_certificate = consensus
            .form_vc(&validation_votes, &round_one.height_context)
            .expect("validation certificate");
        let finality_votes = validators
            .iter()
            .take(5)
            .map(|validator| {
                consensus
                    .finality_vote(
                        signer,
                        validator,
                        &block,
                        &validation_certificate,
                        &round_one.height_context,
                    )
                    .expect("finality vote")
            })
            .collect::<Vec<_>>();
        let qc = consensus
            .form_qc(&finality_votes, &round_one.height_context)
            .expect("finality QC");
        store
            .append_verified_finality(&block, &qc)
            .expect("source finality")
    }

    #[test]
    fn imports_a_finalized_record_produced_after_a_round_change() {
        // Regression for the Testnet-v3 launch blocker: relayer, RPC, and
        // indexer observers rejected every finalized record whose round was
        // greater than zero with
        //   "round 1 is not authorized; valid TC is required to advance from round 0"
        // because `authorized_rounds` is live TC state that a non-signing
        // observer can never populate. Testnet-v3 finalized height 1 at round 1,
        // so no observer store was ever created and the public chain stayed at
        // height 0 while validators advanced normally.
        let (bootstrap, mut signer, protocol_config, anchor, deployed_root) = fixture();
        let (source_store, source_path) = temp_store("source-round-change", anchor);
        let (target_store, target_path) = temp_store("target-round-change", anchor);
        let mut source_consensus = ProofOfSynergyBft::new(
            &bootstrap.verifier,
            bootstrap.validator_set.clone(),
            bootstrap.cluster_map.clone(),
            protocol_config.clone(),
        );
        let initial_context = bootstrap
            .initial_local_consensus_context(&protocol_config, anchor, deployed_root)
            .expect("initial context");
        let record = signed_record_after_round_change(
            &mut source_consensus,
            &mut signer,
            &initial_context,
            &ExecutionState::new(),
            &source_store,
        );
        assert_eq!(record.block.header.round, Round(1));

        let mut target = observer(
            bootstrap,
            protocol_config,
            anchor,
            deployed_root,
            target_store,
        );
        assert_eq!(
            target.import_records(std::slice::from_ref(&record)),
            Ok(1),
            "an observer must accept a valid record finalized after a round change"
        );
        assert_eq!(target.next_missing_height(), Height(2));

        let _ = std::fs::remove_file(source_path);
        let _ = std::fs::remove_file(target.finality_store().path());
        let _ = std::fs::remove_file(target_path);
    }

    #[test]
    fn round_change_recovery_does_not_weaken_the_live_signing_path() {
        // The recovery path must relax the round check *only* for durable
        // finalized records. A live coordinator with no timeout certificate must
        // still refuse the very same block.
        let (bootstrap, mut signer, protocol_config, anchor, deployed_root) = fixture();
        let (source_store, source_path) = temp_store("source-live-guard", anchor);
        let mut source_consensus = ProofOfSynergyBft::new(
            &bootstrap.verifier,
            bootstrap.validator_set.clone(),
            bootstrap.cluster_map.clone(),
            protocol_config.clone(),
        );
        let initial_context = bootstrap
            .initial_local_consensus_context(&protocol_config, anchor, deployed_root)
            .expect("initial context");
        let record = signed_record_after_round_change(
            &mut source_consensus,
            &mut signer,
            &initial_context,
            &ExecutionState::new(),
            &source_store,
        );

        let mut live = ProofOfSynergyBft::new(
            &bootstrap.verifier,
            bootstrap.validator_set.clone(),
            bootstrap.cluster_map.clone(),
            protocol_config.clone(),
        );
        let error = live
            .validate_core_proposal(&record.block, &initial_context, &ExecutionState::new())
            .expect_err("the live signing path must still require a valid TC");
        assert!(
            error.contains("valid TC is required"),
            "unexpected live-path error: {error}"
        );

        let mut recovery = ProofOfSynergyBft::new(
            &bootstrap.verifier,
            bootstrap.validator_set.clone(),
            bootstrap.cluster_map.clone(),
            protocol_config,
        );
        recovery
            .validate_finalized_core_record(
                &record.block,
                &initial_context,
                &ExecutionState::new(),
            )
            .expect("the recovery path must accept a finalized round-one record");

        let _ = std::fs::remove_file(source_path);
    }

    #[test]
    fn round_change_recovery_still_binds_the_round_to_the_proposer_schedule() {
        // `candidate_id()` deliberately zeroes `round`, so the QC alone does not
        // bind it. The proposer-schedule check for the exact round is what keeps
        // the relaxed path sound: re-labelling a finalized block's round must
        // fail even though its QC still verifies.
        let (bootstrap, mut signer, protocol_config, anchor, deployed_root) = fixture();
        let (source_store, source_path) = temp_store("source-round-tamper", anchor);
        let mut source_consensus = ProofOfSynergyBft::new(
            &bootstrap.verifier,
            bootstrap.validator_set.clone(),
            bootstrap.cluster_map.clone(),
            protocol_config.clone(),
        );
        let initial_context = bootstrap
            .initial_local_consensus_context(&protocol_config, anchor, deployed_root)
            .expect("initial context");
        let record = signed_record_after_round_change(
            &mut source_consensus,
            &mut signer,
            &initial_context,
            &ExecutionState::new(),
            &source_store,
        );

        let mut tampered = record.block.clone();
        tampered.header.round = Round(7);

        let mut recovery = ProofOfSynergyBft::new(
            &bootstrap.verifier,
            bootstrap.validator_set.clone(),
            bootstrap.cluster_map.clone(),
            protocol_config,
        );
        recovery
            .validate_finalized_core_record(&tampered, &initial_context, &ExecutionState::new())
            .expect_err("a re-labelled round must not pass the recovery path");

        let _ = std::fs::remove_file(source_path);
    }

    #[test]
    fn imports_valid_consecutive_finality_records_without_signing_authority() {
        let (bootstrap, mut signer, protocol_config, anchor, deployed_root) = fixture();
        let (source_store, source_path) = temp_store("source-valid", anchor);
        let (target_store, target_path) = temp_store("target-valid", anchor);
        let mut source_consensus = ProofOfSynergyBft::new(
            &bootstrap.verifier,
            bootstrap.validator_set.clone(),
            bootstrap.cluster_map.clone(),
            protocol_config.clone(),
        );
        let initial_context = bootstrap
            .initial_local_consensus_context(&protocol_config, anchor, deployed_root)
            .expect("initial context");
        let first = signed_record(
            &mut source_consensus,
            &mut signer,
            &initial_context,
            &ExecutionState::new(),
            &source_store,
        );
        let mut target = observer(
            bootstrap.clone(),
            protocol_config.clone(),
            anchor,
            deployed_root,
            target_store,
        );
        target
            .import_records(std::slice::from_ref(&first))
            .expect("independent first-record recovery");
        let source_state = execute_finalized_core_block(&ExecutionState::new(), &first.block)
            .expect("source execution state after first record");
        let second = signed_record(
            &mut source_consensus,
            &mut signer,
            target.next_context(),
            &source_state,
            &source_store,
        );
        let result = target.import_records(std::slice::from_ref(&second));
        assert_eq!(result, Ok(1));
        assert_eq!(target.next_missing_height(), Height(3));
        assert_eq!(
            target
                .bounded_snapshot_from(Height(1))
                .expect("bounded recovered snapshot")
                .len(),
            2
        );
        let _ = std::fs::remove_file(source_path);
        let _ = std::fs::remove_file(target.finality_store().path());
        let _ = std::fs::remove_file(target_path);
    }

    #[test]
    fn rejects_a_segment_with_a_missing_predecessor() {
        let (bootstrap, mut signer, protocol_config, anchor, deployed_root) = fixture();
        let (source_store, source_path) = temp_store("source-gap", anchor);
        let (target_store, target_path) = temp_store("target-gap", anchor);
        let mut source_consensus = ProofOfSynergyBft::new(
            &bootstrap.verifier,
            bootstrap.validator_set.clone(),
            bootstrap.cluster_map.clone(),
            protocol_config.clone(),
        );
        let initial_context = bootstrap
            .initial_local_consensus_context(&protocol_config, anchor, deployed_root)
            .expect("initial context");
        let first = signed_record(
            &mut source_consensus,
            &mut signer,
            &initial_context,
            &ExecutionState::new(),
            &source_store,
        );
        let source_observer = observer(
            bootstrap.clone(),
            protocol_config.clone(),
            anchor,
            deployed_root,
            source_store.clone(),
        );
        let source_state = execute_finalized_core_block(&ExecutionState::new(), &first.block)
            .expect("source execution state after first record");
        let second = signed_record(
            &mut source_consensus,
            &mut signer,
            source_observer.next_context(),
            &source_state,
            &source_store,
        );
        let mut target = observer(
            bootstrap,
            protocol_config,
            anchor,
            deployed_root,
            target_store,
        );
        let error = target
            .import_records(std::slice::from_ref(&second))
            .expect_err("a height-two record must not bypass height one");
        assert!(error.contains("exact successor"));
        assert_eq!(target.next_missing_height(), Height(1));
        let _ = std::fs::remove_file(source_path);
        let _ = std::fs::remove_file(target.finality_store().path());
        let _ = std::fs::remove_file(target_path);
    }

    #[test]
    fn rejects_a_conflicting_durable_prefix() {
        let (bootstrap, mut signer, protocol_config, anchor, deployed_root) = fixture();
        let (source_store, source_path) = temp_store("source-fork", anchor);
        let (target_store, target_path) = temp_store("target-fork", anchor);
        let mut source_consensus = ProofOfSynergyBft::new(
            &bootstrap.verifier,
            bootstrap.validator_set.clone(),
            bootstrap.cluster_map.clone(),
            protocol_config.clone(),
        );
        let initial_context = bootstrap
            .initial_local_consensus_context(&protocol_config, anchor, deployed_root)
            .expect("initial context");
        let first = signed_record(
            &mut source_consensus,
            &mut signer,
            &initial_context,
            &ExecutionState::new(),
            &source_store,
        );
        let mut target = observer(
            bootstrap,
            protocol_config,
            anchor,
            deployed_root,
            target_store,
        );
        target
            .import_records(std::slice::from_ref(&first))
            .expect("first finality record");
        let mut conflicting = first;
        conflicting.block_id = crate::synergy_types::BlockId("conflicting-block-id".to_string());
        let error = target
            .import_records(std::slice::from_ref(&conflicting))
            .expect_err("a conflicting durable prefix must fail closed");
        assert!(error.contains("SOURCE_CONFLICT"));
        assert_eq!(target.next_missing_height(), Height(2));
        let _ = std::fs::remove_file(source_path);
        let _ = std::fs::remove_file(target.finality_store().path());
        let _ = std::fs::remove_file(target_path);
    }
}
