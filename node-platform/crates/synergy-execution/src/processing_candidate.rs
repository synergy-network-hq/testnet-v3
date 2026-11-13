//! Candidate assembly for the explicit processing profile, behind the existing
//! execution scheduler. No queue, height driver, quorum or finality lives here.
//! The native owner supplies governed context, authenticated publications and
//! durable payload access; it must persist the returned candidate before vote.
use std::collections::BTreeMap;
use std::sync::Arc;

use synergy_block::BlockBody;
use synergy_etdag::execution::ProcessingOrderGroup;
use synergy_etdag::{EtdagDigest, EtdagError};
use synergy_state::world_resources::{BudgetedWorld, WorldResourceError};
use synergy_state::{state_root, StateError, WorldState};
use synergy_transaction::{
    AegisTransactionVerifier, NetworkBinding, SignedTransaction, TransactionClass,
};

use crate::{
    reserve_execution_metadata, BlockExecutionError, BlockExecutionScheduler,
    BudgetedExecutionCandidate, CandidateResourceError, ParentProcessingRegistry,
    ProcessingReadinessVerifier, ProcessingReadyRecord, ProcessingRegistryError,
    TransactionExecutor,
};

const MAX_PROCESSING_PLAINTEXT_BYTES: usize = 4 * 1024 * 1024;

/// Every field is supplied by the sole native PoSy/execution owner, never by a
/// wallet's requested inclusion height or an unauthenticated worker message.
pub struct ProcessingCandidateContext<'a> {
    pub ordered_group: Option<&'a ProcessingOrderGroup>,
    pub height: u64,
    pub parent_block_id: &'a str,
    pub network: &'a NetworkBinding,
    pub consensus_timestamp_unix: u64,
    pub namespace_root: &'a EtdagDigest,
    pub maximum_gas: u64,
    pub maximum_bytes: u64,
    pub finalized_authorization_state: &'a WorldState,
}

/// Bytes remain charged by their existing ETDAG/durable owner. A provider must
/// retrieve a missing canonical payload or return a retryable resource/storage
/// error; absence never removes an item from the mandatory parent selection.
pub trait ProcessingPayloadProvider {
    fn plaintext<'a>(
        &'a self,
        record: &ProcessingReadyRecord,
    ) -> Result<&'a [u8], ProcessingPayloadError>;
}

#[derive(Debug)]
pub enum ProcessingPayloadError {
    Unavailable(EtdagDigest),
    Resource(WorldResourceError),
    Corrupt(String),
}

#[derive(Debug)]
pub enum ProcessingCandidateError {
    Registry(ProcessingRegistryError),
    Resource(WorldResourceError),
    Candidate(CandidateResourceError),
    Payload(ProcessingPayloadError),
    Execution(BlockExecutionError),
    State(StateError),
    Invalid(String),
}
impl std::fmt::Display for ProcessingCandidateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for ProcessingCandidateError {}
impl From<ProcessingRegistryError> for ProcessingCandidateError {
    fn from(value: ProcessingRegistryError) -> Self {
        Self::Registry(value)
    }
}
impl From<WorldResourceError> for ProcessingCandidateError {
    fn from(value: WorldResourceError) -> Self {
        Self::Resource(value)
    }
}
impl From<CandidateResourceError> for ProcessingCandidateError {
    fn from(value: CandidateResourceError) -> Self {
        Self::Candidate(value)
    }
}
impl From<ProcessingPayloadError> for ProcessingCandidateError {
    fn from(value: ProcessingPayloadError) -> Self {
        Self::Payload(value)
    }
}
impl From<BlockExecutionError> for ProcessingCandidateError {
    fn from(value: BlockExecutionError) -> Self {
        Self::Execution(value)
    }
}

/// Stable plaintext binding in ready metadata. Context/envelope stay original;
/// no eventual inclusion height or local completion time is hashed into it.
/// Callers reserve serialization scratch before invoking this on large input.
pub fn processing_payload_root(
    context: &EtdagDigest,
    envelope: &EtdagDigest,
    plaintext: &[u8],
) -> Result<EtdagDigest, EtdagError> {
    context.validate()?;
    envelope.validate()?;
    if context.is_zero()
        || envelope.is_zero()
        || plaintext.is_empty()
        || plaintext.len() > MAX_PROCESSING_PLAINTEXT_BYTES
    {
        return Err(EtdagError::InvalidExecutionInput);
    }
    EtdagDigest::from_canonical(
        "SYNERGY_ETDAG_PROCESSING_READY_PLAINTEXT_V1",
        &(context, envelope, plaintext),
    )
}

impl<D: TransactionExecutor, V: AegisTransactionVerifier> BlockExecutionScheduler<D, V> {
    /// Regenerate the complete candidate from its real parent and authenticated
    /// publications. A stored/remote World or receipt is never execution proof.
    /// Returns the charged regenerated candidate for the native durable handoff.
    #[allow(clippy::too_many_arguments)]
    pub fn replay_processing_candidate(
        &self,
        candidate: &BudgetedExecutionCandidate,
        context: ProcessingCandidateContext<'_>,
        parent: &BudgetedWorld,
        publications: &[ProcessingReadyRecord],
        readiness: &impl ProcessingReadinessVerifier,
        payloads: &impl ProcessingPayloadProvider,
    ) -> Result<BudgetedExecutionCandidate, ProcessingCandidateError> {
        self.replay_processing_candidate_with_epoch_transition(
            candidate,
            context,
            parent,
            publications,
            readiness,
            payloads,
            None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn replay_processing_candidate_with_epoch_transition(
        &self,
        candidate: &BudgetedExecutionCandidate,
        context: ProcessingCandidateContext<'_>,
        parent: &BudgetedWorld,
        publications: &[ProcessingReadyRecord],
        readiness: &impl ProcessingReadinessVerifier,
        payloads: &impl ProcessingPayloadProvider,
        epoch_transition: Option<&crate::ProcessingEpochTransition>,
    ) -> Result<BudgetedExecutionCandidate, ProcessingCandidateError> {
        if !Arc::ptr_eq(parent.budget(), candidate.state.budget()) {
            return Err(ProcessingCandidateError::Invalid(
                "processing replay requires the shared native World pool".into(),
            ));
        }
        let _candidate_root_scratch = parent.budget().reserve(8192)?;
        candidate
            .validate()
            .map_err(ProcessingCandidateError::Invalid)?;
        let replayed = self.execute_processing_candidate_with_epoch_transition(
            context,
            parent,
            publications,
            readiness,
            payloads,
            epoch_transition,
        )?;
        if replayed != *candidate {
            return Err(ProcessingCandidateError::Invalid(
                "processing candidate fails canonical parent execution/registry replay".into(),
            ));
        }
        Ok(replayed)
    }

    /// Build one speculative processing candidate using ONLY its canonical
    /// parent's ready state. New verified publications enter the resulting
    /// World for descendants. Empty selection requires no unfinished group.
    /// Selection, payload, execution or resource failures leave parent unchanged.
    pub fn execute_processing_candidate(
        &self,
        context: ProcessingCandidateContext<'_>,
        parent: &BudgetedWorld,
        publications: &[ProcessingReadyRecord],
        readiness: &impl ProcessingReadinessVerifier,
        payloads: &impl ProcessingPayloadProvider,
    ) -> Result<BudgetedExecutionCandidate, ProcessingCandidateError> {
        self.execute_processing_candidate_with_epoch_transition(
            context,
            parent,
            publications,
            readiness,
            payloads,
            None,
        )
    }

    /// The native authenticated boundary owner supplies the prepared parent and
    /// its exact empty-registry diff. Ordinary candidates retain their original
    /// commitment format. This API itself grants no authority over an epoch.
    pub fn execute_processing_candidate_with_epoch_transition(
        &self,
        context: ProcessingCandidateContext<'_>,
        parent: &BudgetedWorld,
        publications: &[ProcessingReadyRecord],
        readiness: &impl ProcessingReadinessVerifier,
        payloads: &impl ProcessingPayloadProvider,
        epoch_transition: Option<&crate::ProcessingEpochTransition>,
    ) -> Result<BudgetedExecutionCandidate, ProcessingCandidateError> {
        if let Some(transition) = epoch_transition {
            transition.verify_prepared_parent(parent.as_ref())?;
        }
        if context.height == 0
            || context.parent_block_id.trim().is_empty()
            || context.parent_block_id.len() > 256
            || context.consensus_timestamp_unix == 0
        {
            return Err(ProcessingCandidateError::Invalid(
                "invalid governed processing candidate context".into(),
            ));
        }
        context
            .network
            .validate()
            .map_err(|e| ProcessingCandidateError::Invalid(e.to_string()))?;
        let budget = parent.budget();
        let registry =
            ParentProcessingRegistry::read(parent.as_ref(), context.namespace_root, budget)?;
        let selected = registry.select(readiness, context.maximum_gas, context.maximum_bytes)?;
        let transition = selected.transition(
            publications,
            readiness,
            context.maximum_gas,
            context.maximum_bytes,
        )?;
        let groups = crate::processing_group_transition(
            parent.as_ref(),
            context.namespace_root,
            selected.records(),
            context.ordered_group,
            readiness,
            budget,
        )?;
        // Publications also use OLD-parent closure; same-block assignment or
        // successor creation grants no early plaintext permission.
        for record in publications {
            crate::verify_processing_record_assignment(
                parent.as_ref(),
                context.namespace_root,
                record,
            )?;
        }
        let count = selected.selection().item_indices.len();
        let _index = budget.reserve(
            count
                .checked_mul(2048)
                .and_then(|n| n.checked_add(16 * 1024))
                .ok_or(WorldResourceError::ArithmeticOverflow)?,
        )?;
        let mut plaintexts = Vec::with_capacity(count);
        for record in selected.records() {
            let plaintext = payloads.plaintext(record)?;
            if plaintext.is_empty()
                || plaintext.len() > MAX_PROCESSING_PLAINTEXT_BYTES
                || u64::try_from(plaintext.len()).ok() != Some(record.item.encoded_bytes)
            {
                return Err(ProcessingCandidateError::Invalid(
                    "processing payload length differs from committed ready record".into(),
                ));
            }
            plaintexts.push(plaintext);
        }
        // Native graphs, receipts and material are reserved before decoding or
        // cloning. The guard moves into the returned candidate, not a queue.
        let mut metadata = reserve_execution_metadata(plaintexts.iter().copied(), budget)?;
        metadata.grow(
            count
                .checked_mul(32)
                .and_then(|n| n.checked_add(8192))
                .ok_or(WorldResourceError::ArithmeticOverflow)?,
        )?;
        let mut transactions = Vec::with_capacity(count);
        let mut expected_nonces = BTreeMap::new();
        for (record, plaintext) in selected.records().zip(plaintexts) {
            let _hash_scratch = budget.reserve(
                plaintext
                    .len()
                    .checked_mul(8)
                    .and_then(|n| n.checked_add(4096))
                    .ok_or(WorldResourceError::ArithmeticOverflow)?,
            )?;
            let root = processing_payload_root(
                &record.processing_context_root,
                &record.item.envelope_id,
                plaintext,
            )
            .map_err(|e| {
                ProcessingCandidateError::Invalid(format!("processing payload commitment: {e:?}"))
            })?;
            if root != record.item.payload_root {
                return Err(ProcessingCandidateError::Invalid(
                    "processing payload is not the committed plaintext".into(),
                ));
            }
            let transaction: SignedTransaction =
                serde_json::from_slice(plaintext).map_err(|e| {
                    ProcessingCandidateError::Invalid(format!("decode processing transaction: {e}"))
                })?;
            transaction
                .validate_structure()
                .map_err(|e| ProcessingCandidateError::Invalid(e.to_string()))?;
            if transaction.unsigned.class != TransactionClass::User
                || transaction.unsigned.network != *context.network
                || transaction.unsigned.sender != record.sender_wallet
                || transaction.unsigned.nonce != record.sender_nonce
                || transaction.unsigned.fee_limit.gas_limit != record.item.gas_class_units
            {
                return Err(ProcessingCandidateError::Invalid(
                    "processing plaintext differs from signed ready metadata".into(),
                ));
            }
            let nonce = expected_nonces
                .entry(record.sender_wallet.as_str())
                .or_insert_with(|| {
                    parent
                        .accounts
                        .get(&record.sender_wallet)
                        .map_or(0, |a| a.nonce)
                });
            if record.sender_nonce > *nonce {
                return Err(ProcessingCandidateError::Invalid(
                    "future nonce escaped canonical processing selection".into(),
                ));
            }
            if record.sender_nonce == *nonce {
                *nonce = nonce.checked_add(1).ok_or_else(|| {
                    ProcessingCandidateError::Invalid("processing nonce overflow".into())
                })?;
            }
            transactions.push(transaction);
        }
        let body = BlockBody { transactions };
        let mut outcome = self.execute_async_at_budgeted(
            &body,
            context.network,
            context.height,
            context.consensus_timestamp_unix,
            parent,
            context.finalized_authorization_state,
        )?;
        for (sender, expected) in expected_nonces {
            if outcome.state.accounts.get(sender).map_or(0, |a| a.nonce) != expected {
                return Err(ProcessingCandidateError::Invalid(
                    "processing execution did not consume exactly the authenticated nonce".into(),
                ));
            }
        }
        outcome
            .state
            .try_apply(transition.diff())
            .map_err(ProcessingCandidateError::State)?;
        outcome
            .state
            .try_apply(groups.diff())
            .map_err(ProcessingCandidateError::State)?;
        let mut material = selected.proposal_material(context.height, &transition)?;
        material.ordered_group = context
            .ordered_group
            .map(ProcessingOrderGroup::commitment)
            .transpose()
            .map_err(|e| {
                ProcessingCandidateError::Invalid(format!("processing group commitment: {e:?}"))
            })?;
        material.transition_root = match epoch_transition {
            None => EtdagDigest::from_canonical(
                "SYNERGY_POSY_PROCESSING_LIFECYCLE_TRANSITION_V1",
                &(transition.diff(), groups.diff()),
            ),
            Some(epoch) => EtdagDigest::from_canonical(
                "SYNERGY_POSY_PROCESSING_EPOCH_LIFECYCLE_TRANSITION_V1",
                &(epoch.diff(), transition.diff(), groups.diff()),
            ),
        }
        .map_err(|e| {
            ProcessingCandidateError::Invalid(format!("processing lifecycle commitment: {e:?}"))
        })?;
        let _root_scratch = budget.reserve(8192)?;
        let state_root =
            state_root(outcome.state.as_ref()).map_err(ProcessingCandidateError::State)?;
        let protected_execution_root =
            synergy_block::hash_block_bytes(&material.commitment_bytes().map_err(|e| {
                ProcessingCandidateError::Invalid(format!("processing material commitment: {e:?}"))
            })?);
        let mut candidate = BudgetedExecutionCandidate {
            resource_permit: Some(Arc::new(metadata)),
            height: context.height,
            block_id: String::new(),
            parent_block_id: context.parent_block_id.into(),
            protected_execution_root,
            protected_material: material.into(),
            state_root,
            transactions: body.transactions,
            receipts: outcome.receipts,
            state: Arc::new(outcome.state),
        };
        candidate.block_id = candidate
            .commitment_id()
            .map_err(ProcessingCandidateError::Invalid)?;
        candidate
            .validate()
            .map_err(ProcessingCandidateError::Invalid)?;
        Ok(candidate)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{FeeSchedule, NativeTransferDispatcher};
    use synergy_state::world_resources::WorldResourceBudget;

    struct UnusedPipeline;
    impl ProcessingReadinessVerifier for UnusedPipeline {
        fn verify_publication(
            &self,
            _: &ProcessingReadyRecord,
            _: &WorldState,
        ) -> Result<(), String> {
            panic!("empty block must not wait for pending publication")
        }
        fn identity_is_current(
            &self,
            _: &ProcessingReadyRecord,
            _: &WorldState,
        ) -> Result<bool, String> {
            panic!("no ready item exists")
        }
    }
    impl ProcessingPayloadProvider for UnusedPipeline {
        fn plaintext<'a>(
            &'a self,
            _: &ProcessingReadyRecord,
        ) -> Result<&'a [u8], ProcessingPayloadError> {
            panic!("empty block must not fetch an unfinished payload")
        }
    }
    impl AegisTransactionVerifier for UnusedPipeline {
        type Error = String;
        fn verify_transaction(
            &self,
            _: &[u8],
            _: &[u8],
            _: &[u8],
            _: &str,
        ) -> Result<bool, String> {
            panic!("empty block has no wallet signature")
        }
    }
    fn network() -> NetworkBinding {
        NetworkBinding {
            chain_id: 1266,
            network_id: "processing-candidate-fixture".into(),
        }
    }
    fn namespace() -> EtdagDigest {
        EtdagDigest::from_domain_bytes("processing-empty-candidate-fixture", b"namespace")
    }
    fn scheduler() -> BlockExecutionScheduler<NativeTransferDispatcher, UnusedPipeline> {
        BlockExecutionScheduler::new(
            NativeTransferDispatcher,
            UnusedPipeline,
            FeeSchedule {
                base_fee_per_gas_nwei: 40,
                collector: "unused-fixture-collector".into(),
            },
        )
        .unwrap()
    }
    #[test]
    fn processing_candidate_epoch_handoff_replays_and_reopens_without_rewriting_history() {
        // Offline execution/storage test only; no validator or chain is run.
        let budget = WorldResourceBudget::new(16 * 1024 * 1024);
        let historical = crate::processing_epoch::tests::boundary_world();
        let (previous, next) = crate::processing_epoch::tests::namespaces();
        let original_root = state_root(&historical).unwrap();
        let historical = BudgetedWorld::try_clone_world(&historical, &budget).unwrap();
        let handoff = crate::propose_empty_processing_epoch_transition(
            &historical,
            &previous,
            &next,
            &budget,
        )
        .unwrap();
        let mut prepared = historical.try_clone().unwrap();
        prepared.try_apply(handoff.diff()).unwrap();
        let network = network();
        let context = || ProcessingCandidateContext {
            ordered_group: None,
            height: 10001,
            parent_block_id: "verified-epoch-parent",
            network: &network,
            consensus_timestamp_unix: 1_700_010_001,
            namespace_root: &next,
            maximum_gas: 30_000_000,
            maximum_bytes: 8 * 1024 * 1024,
            finalized_authorization_state: &historical,
        };
        let scheduler = scheduler();
        assert!(scheduler
            .execute_processing_candidate_with_epoch_transition(
                context(),
                &historical,
                &[],
                &UnusedPipeline,
                &UnusedPipeline,
                Some(&handoff)
            )
            .is_err());
        let candidate = scheduler
            .execute_processing_candidate_with_epoch_transition(
                context(),
                &prepared,
                &[],
                &UnusedPipeline,
                &UnusedPipeline,
                Some(&handoff),
            )
            .unwrap();
        assert!(candidate.transactions.is_empty());
        assert_eq!(candidate.state.accounts, historical.accounts);
        assert_eq!(state_root(&historical).unwrap(), original_root);
        assert_ne!(candidate.state_root, original_root);
        // Omitting the transition gives a different commitment even though
        // the prepared metadata and resulting World happen to be identical.
        assert!(scheduler
            .replay_processing_candidate(
                &candidate,
                context(),
                &prepared,
                &[],
                &UnusedPipeline,
                &UnusedPipeline
            )
            .is_err());
        scheduler
            .replay_processing_candidate_with_epoch_transition(
                &candidate,
                context(),
                &prepared,
                &[],
                &UnusedPipeline,
                &UnusedPipeline,
                Some(&handoff),
            )
            .unwrap();
        let bytes = serde_json::to_vec(&candidate).unwrap();
        let decoded = crate::decode_budgeted_candidate(&bytes, &budget).unwrap();
        scheduler
            .replay_processing_candidate_with_epoch_transition(
                &decoded,
                context(),
                &prepared,
                &[],
                &UnusedPipeline,
                &UnusedPipeline,
                Some(&handoff),
            )
            .unwrap();
        struct Temp(std::path::PathBuf);
        impl Drop for Temp {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        let temp = Temp(
            std::env::temp_dir().join(format!(
                "epoch-candidate-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            )),
        );
        let mut store =
            crate::BudgetedCandidateStore::new_budgeted(&temp.0, budget.clone()).unwrap();
        store.put_budgeted(&candidate, &historical).unwrap();
        drop(store);
        let store = crate::BudgetedCandidateStore::new_budgeted(&temp.0, budget.clone()).unwrap();
        let restored = store.get_budgeted(candidate.height).unwrap().unwrap();
        assert_eq!(candidate, restored);
        scheduler
            .replay_processing_candidate_with_epoch_transition(
                &restored,
                context(),
                &prepared,
                &[],
                &UnusedPipeline,
                &UnusedPipeline,
                Some(&handoff),
            )
            .unwrap();
        // The next ordinary candidate uses the already committed new namespace
        // and requires no second handoff or special empty-block authority.
        let next_context = ProcessingCandidateContext {
            height: 10002,
            parent_block_id: &candidate.block_id,
            ..context()
        };
        scheduler
            .execute_processing_candidate(
                next_context,
                &restored.state,
                &[],
                &UnusedPipeline,
                &UnusedPipeline,
            )
            .unwrap();
        assert_eq!(state_root(&historical).unwrap(), original_root);
    }
    #[test]
    fn processing_candidate_empty_assembly_spans_heights_without_etdag_material_or_growth() {
        let budget = WorldResourceBudget::new(4 * 1024 * 1024);
        let world = WorldState::default();
        let mut parent = Arc::new(BudgetedWorld::try_clone_world(&world, &budget).unwrap());
        let mut parent_id = "genesis-fixture".to_string();
        let scheduler = scheduler();
        let namespace = namespace();
        let network = network();
        let mut stable = None;
        // Candidate assembly proof only. This does not supply QCs/finality.
        for height in 100..116 {
            let context = || ProcessingCandidateContext {
                ordered_group: None,
                height,
                parent_block_id: &parent_id,
                network: &network,
                consensus_timestamp_unix: 1_700_000_000 + height,
                namespace_root: &namespace,
                maximum_gas: 30_000_000,
                maximum_bytes: 8 * 1024 * 1024,
                finalized_authorization_state: &world,
            };
            let candidate = scheduler
                .execute_processing_candidate(
                    context(),
                    &parent,
                    &[],
                    &UnusedPipeline,
                    &UnusedPipeline,
                )
                .unwrap();
            assert!(candidate.transactions.is_empty());
            assert!(candidate.receipts.is_empty());
            assert_eq!(candidate.state.as_ref().as_ref(), &world);
            let replayed = scheduler
                .replay_processing_candidate(
                    &candidate,
                    context(),
                    &parent,
                    &[],
                    &UnusedPipeline,
                    &UnusedPipeline,
                )
                .unwrap();
            assert_eq!(replayed, candidate);
            drop(replayed);
            parent_id = candidate.block_id;
            parent = candidate.state;
            drop(candidate.resource_permit);
            match stable {
                Some(bytes) => assert_eq!(budget.used(), bytes),
                None => stable = Some(budget.used()),
            }
        }
        drop(parent);
        assert_eq!(budget.used(), 0);
    }
    #[test]
    fn processing_candidate_pressure_leaves_parent_unchanged_and_retry_is_not_self_blocked() {
        let budget = WorldResourceBudget::new(1024 * 1024);
        let world = WorldState::default();
        let parent = BudgetedWorld::try_clone_world(&world, &budget).unwrap();
        let charged = budget.used();
        let scheduler = scheduler();
        let namespace = namespace();
        let network = network();
        let context = || ProcessingCandidateContext {
            ordered_group: None,
            height: 100,
            parent_block_id: "canonical-parent",
            network: &network,
            consensus_timestamp_unix: 1_700_000_100,
            namespace_root: &namespace,
            maximum_gas: 30_000_000,
            maximum_bytes: 8 * 1024 * 1024,
            finalized_authorization_state: &world,
        };
        let pressure = budget.reserve(budget.available()).unwrap();
        assert!(matches!(
            scheduler.execute_processing_candidate(
                context(),
                &parent,
                &[],
                &UnusedPipeline,
                &UnusedPipeline
            ),
            Err(ProcessingCandidateError::Registry(
                ProcessingRegistryError::Resource(WorldResourceError::Capacity { .. })
            ))
        ));
        assert_eq!(parent.as_ref(), &world);
        drop(pressure);
        assert_eq!(budget.used(), charged);
        let candidate = scheduler
            .execute_processing_candidate(context(), &parent, &[], &UnusedPipeline, &UnusedPipeline)
            .unwrap();
        assert_eq!(parent.as_ref(), &world);
        drop(candidate);
        assert_eq!(budget.used(), charged);
    }
}
