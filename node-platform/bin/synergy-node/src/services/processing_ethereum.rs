//! External authorization stays distinct from native identity authorization.
//! This adapter is invoked only inside the canonical ordered PoSy scheduler.
use super::*;
use synergy_aivm::ethereum_execution::{
    self as evm, EvmBlockContext, EvmExecutionError, EvmExecutionReceipt,
};
use synergy_execution::{
    BlockExecutionError, ProcessingCandidateContext, ProcessingNativeWalletActions,
};
use synergy_state::{ProtocolChange, StateDiff};

pub(in crate::services) const TRANSACTION_PREFIX: &str = "aivm/ethereum/v1/transaction/";
const HISTORY_PREFIX: &str = "aivm/ethereum/v1/native-parent/";
pub(in crate::services) const BLOCK_PREFIX: &str = "aivm/ethereum/v1/block/";
const CONSUMPTION_PREFIX: &str = "aivm/ethereum/v1/consumption/";
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct EthereumConsumption {
    height: u64,
    ready: ProcessingReadyRecord,
    transaction_hash: [u8; 32],
}
fn consumption_key(id: &EtdagDigest) -> String {
    format!("{CONSUMPTION_PREFIX}{}", id.0)
}
fn consumption(
    world: &WorldState,
    id: &EtdagDigest,
) -> Result<Option<EthereumConsumption>, String> {
    world
        .protocol
        .get(&consumption_key(id))
        .map(|bytes| {
            if bytes.len() > 32768 {
                return Err("EVM consumption marker exceeds bound".into());
            }
            serde_json::from_slice(bytes)
                .map_err(|error| format!("EVM consumption marker: {error}"))
        })
        .transpose()
}
pub(super) fn matches_pending(
    world: &WorldState,
    height: u64,
    identity: &super::super::processing_store::PendingProcessingIdentity,
) -> Result<bool, String> {
    Ok(
        consumption(world, &identity.envelope_id)?.is_some_and(|marker| {
            marker.height == height
                && marker.ready.item.envelope_id == identity.envelope_id
                && marker.ready.processing_context_root == identity.context_root
                && marker.ready.sender_wallet == identity.sender_wallet
                && marker.ready.sender_nonce == identity.sender_nonce
        }),
    )
}
pub(super) fn verify_selected(
    parent: &WorldState,
    world: &WorldState,
    height: u64,
    ready: &ProcessingReadyRecord,
) -> Result<bool, String> {
    let Some(marker) = consumption(world, &ready.item.envelope_id)? else {
        return Ok(false);
    };
    if marker.height != height
        || marker.ready != *ready
        || parent
            .protocol
            .contains_key(&consumption_key(&ready.item.envelope_id))
    {
        return Err("EVM consumption differs from exact native selection".into());
    }
    let bytes = world
        .protocol
        .get(&format!(
            "{TRANSACTION_PREFIX}{}",
            hex(&marker.transaction_hash)
        ))
        .filter(|bytes| bytes.len() <= 4 * 1024 * 1024)
        .ok_or("EVM consumption lacks committed disposition")?;
    let transaction: EthereumRecord =
        serde_json::from_slice(bytes).map_err(|error| error.to_string())?;
    let policy = evm::EvmCompatibilityPolicy::load(world).map_err(|error| format!("{error:?}"))?;
    let tx = synergy_aivm::ethereum::decode_eip155(&transaction.raw, policy.chain_id)
        .map_err(|error| error.to_string())?;
    if transaction.height > height
        || tx.transaction_hash != marker.transaction_hash
        || tx.nonce != ready.sender_nonce
        || !ready.sender_wallet.starts_with("0x")
        || (transaction.receipt.is_some() == transaction.rejection.is_some())
    {
        return Err("EVM finalized disposition differs from selection".into());
    }
    Ok(true)
}
fn consumption_change(
    record: &ProcessingReadyRecord,
    height: u64,
    hash: [u8; 32],
) -> Result<ProtocolChange, BlockExecutionError> {
    let bytes = serde_json::to_vec(&EthereumConsumption {
        height,
        ready: record.clone(),
        transaction_hash: hash,
    })
    .map_err(invalid)?;
    if bytes.len() > 32768 {
        return Err(invalid("EVM consumption marker exceeds bound"));
    }
    Ok(ProtocolChange {
        key: consumption_key(&record.item.envelope_id),
        expected_value: None,
        value: Some(bytes),
    })
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::services) struct EthereumRecord {
    pub height: u64,
    pub index: u32,
    pub first_log_index: u64,
    pub cumulative_gas_used: u64,
    pub raw: Vec<u8>,
    pub receipt: Option<EvmExecutionReceipt>,
    /// Ordered authorization which became stale/unfunded is retired without
    /// execution, fee or nonce. It never receives an Ethereum mined receipt.
    pub rejection: Option<String>,
}
#[derive(Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::services) struct BlockIndex {
    pub transactions: Vec<[u8; 32]>,
    pub gas_used: u64,
    pub logs: u64,
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
fn invalid(error: impl std::fmt::Display) -> BlockExecutionError {
    BlockExecutionError::Dispatcher {
        transaction_index: 0,
        message: error.to_string(),
    }
}
fn state(error: synergy_state::StateError) -> BlockExecutionError {
    BlockExecutionError::State {
        transaction_index: 0,
        source: error,
    }
}

/// Include the actual parent identity in every compatibility-enabled native
/// candidate, including empty blocks. A current block never hashes itself.
pub(in crate::services) fn finish_candidate(
    authority: &VerifiedAuthority,
    mut candidate: BudgetedExecutionCandidate,
) -> Result<BudgetedExecutionCandidate, synergy_execution::ProcessingCandidateError> {
    if authority.ethereum_genesis().is_none() {
        return Ok(candidate);
    }
    NativeProcessingContext::check_ethereum_policy(authority, candidate.state.as_ref())
        .map_err(synergy_execution::ProcessingCandidateError::Invalid)?;
    let parent_height = candidate.height.checked_sub(1).ok_or_else(|| {
        synergy_execution::ProcessingCandidateError::Invalid("EVM candidate height zero".into())
    })?;
    let parent = synergy_posy::parse_hash_bytes(&candidate.parent_block_id)
        .map_err(|error| synergy_execution::ProcessingCandidateError::Invalid(error.to_string()))?;
    let key = format!("{HISTORY_PREFIX}{parent_height:020}");
    let oldest = parent_height.saturating_sub(256);
    let world = Arc::get_mut(&mut candidate.state).ok_or_else(|| {
        synergy_execution::ProcessingCandidateError::Invalid(
            "candidate World escaped before sealing EVM history".into(),
        )
    })?;
    let mut diff = StateDiff::default();
    diff.protocol_changes.push(ProtocolChange {
        expected_value: world.protocol.get(&key).cloned(),
        key,
        value: Some(parent.to_vec()),
    });
    for (key, value) in world
        .protocol
        .range(HISTORY_PREFIX.to_owned()..)
        .take_while(|(key, _)| key.starts_with(HISTORY_PREFIX))
    {
        let height = key
            .strip_prefix(HISTORY_PREFIX)
            .and_then(|text| text.parse::<u64>().ok())
            .ok_or_else(|| {
                synergy_execution::ProcessingCandidateError::Invalid(
                    "corrupt EVM native history".into(),
                )
            })?;
        if height < oldest {
            diff.protocol_changes.push(ProtocolChange {
                key: key.clone(),
                expected_value: Some(value.clone()),
                value: None,
            });
        }
    }
    world
        .try_apply(&diff)
        .map_err(synergy_execution::ProcessingCandidateError::State)?;
    candidate.state_root = synergy_state::state_root(world)
        .map_err(synergy_execution::ProcessingCandidateError::State)?;
    candidate.block_id = candidate
        .commitment_id()
        .map_err(synergy_execution::ProcessingCandidateError::Invalid)?;
    candidate
        .validate()
        .map_err(synergy_execution::ProcessingCandidateError::Invalid)?;
    Ok(candidate)
}

pub(in crate::services) struct EthereumDispatch<'a, 'p> {
    pub pipeline: &'a NativeProcessingPipeline<'p>,
    pub authority: &'a VerifiedAuthority,
    pub context: ProcessingCandidateContext<'a>,
    pub wallet: Option<&'a dyn ProcessingNativeWalletActions>,
}
impl EthereumDispatch<'_, '_> {
    fn external(&self, record: &ProcessingReadyRecord) -> bool {
        self.pipeline
            .completions
            .get(&record.item.envelope_id)
            .is_some_and(|completion| {
                matches!(completion.authorization, CompletionAuthorization::Ethereum)
            })
    }
}
impl ProcessingNativeWalletActions for EthereumDispatch<'_, '_> {
    fn owns(&self, record: &ProcessingReadyRecord) -> bool {
        self.external(record) || self.wallet.is_some_and(|wallet| wallet.owns(record))
    }
    fn external_nonce_owner(&self, record: &ProcessingReadyRecord) -> bool {
        self.external(record)
    }
    fn authorize_ordinary_protected_credit(
        &self,
        receiver: &str,
        context: synergy_execution::TransactionExecutionContext<'_>,
        world: &WorldState,
    ) -> Result<(), synergy_execution::NativeDispatchError> {
        self.wallet
            .ok_or(synergy_execution::NativeDispatchError::AccountNotEnrolled)?
            .authorize_ordinary_protected_credit(receiver, context, world)
    }
    fn execute(
        &self,
        record: &ProcessingReadyRecord,
        parent: &BudgetedWorld,
        candidate: &mut BudgetedWorld,
    ) -> Result<(), BlockExecutionError> {
        if !self.external(record) {
            return self
                .wallet
                .ok_or_else(|| invalid("native action has no owner"))?
                .execute(record, parent, candidate);
        }
        if !std::ptr::eq(parent, self.pipeline.parent.world()) {
            return Err(invalid("EVM dispatch used a different native parent"));
        }
        NativeProcessingContext::check_ethereum_policy(self.authority, candidate)
            .map_err(invalid)?;
        let raw = self
            .pipeline
            .plaintext(record)
            .map_err(|error| invalid(format!("{error:?}")))?;
        let tx = synergy_aivm::ethereum::decode_eip155(raw, self.context.network.chain_id)
            .map_err(invalid)?;
        let key = format!("{TRANSACTION_PREFIX}{}", hex(&tx.transaction_hash));
        // The immutable original and parent-owned consumption registry prevent
        // duplicate ordering/restarts from executing an identical hash twice.
        if candidate.protocol.contains_key(&key) {
            let _marker = candidate.budget().reserve(256 * 1024).map_err(|error| {
                state(synergy_state::world_resources::resource_state_error(error))
            })?;
            // A distinct ordered carrier for an already settled raw hash still
            // consumes its own exact native READY identity, without a new fee,
            // nonce or Ethereum receipt. Finality retires that carrier normally.
            candidate
                .try_apply(&StateDiff {
                    changes: Vec::new(),
                    protocol_changes: vec![consumption_change(
                        record,
                        self.context.height,
                        tx.transaction_hash,
                    )?],
                })
                .map_err(state)?;
            return Ok(());
        }
        let _metadata = candidate
            .budget()
            .reserve(raw.len() * 16 + 16 * 1024 * 1024)
            .map_err(|error| state(synergy_state::world_resources::resource_state_error(error)))?;
        let block_key = format!("{BLOCK_PREFIX}{:020}", self.context.height);
        let mut block: BlockIndex = match candidate.protocol.get(&block_key) {
            Some(bytes) if bytes.len() <= 4 * 1024 * 1024 => {
                serde_json::from_slice(bytes).map_err(invalid)?
            }
            Some(_) => return Err(invalid("EVM block index exceeds bound")),
            None => BlockIndex::default(),
        };
        if block.transactions.len() >= 1428 {
            return Err(invalid("EVM block transaction count exceeds gas bound"));
        }
        let mut history = BTreeMap::new();
        for (key, value) in candidate
            .protocol
            .range(HISTORY_PREFIX.to_owned()..)
            .take_while(|(key, _)| key.starts_with(HISTORY_PREFIX))
        {
            let height = key
                .strip_prefix(HISTORY_PREFIX)
                .and_then(|text| text.parse::<u64>().ok())
                .ok_or_else(|| invalid("corrupt native block history"))?;
            let hash: [u8; 32] = value
                .as_slice()
                .try_into()
                .map_err(|_| invalid("corrupt native block hash"))?;
            if history.insert(height, hash).is_some() || history.len() > 257 {
                return Err(invalid("native history exceeds bound"));
            }
        }
        history.insert(
            self.context.height - 1,
            synergy_posy::parse_hash_bytes(self.context.parent_block_id).map_err(invalid)?,
        );
        history.retain(|height, _| {
            *height >= self.context.height.saturating_sub(256) && *height < self.context.height
        });
        let signed = self
            .authority
            .ethereum_genesis()
            .ok_or_else(|| invalid("EVM signed Genesis is absent"))?;
        let protected_credit = |account: &[u8; 20], world: &WorldState| {
            let receiver = synergy_address::protected_wallet_native_representation(*account)
                .map_err(|error| error.to_string())?;
            self.authorize_ordinary_protected_credit(
                &receiver,
                synergy_execution::TransactionExecutionContext {
                    network: self.context.network,
                    block_height: self.context.height,
                    transaction_index: record.item.order_position,
                },
                world,
            )
            .map_err(|error| error.to_string())
        };
        let context = EvmBlockContext {
            chain_id: self.context.network.chain_id,
            genesis: synergy_posy::parse_hash_bytes(&signed.genesis_hash).map_err(invalid)?,
            policy_sha256: synergy_posy::parse_hash_bytes(&signed.descriptor.policy_sha256)
                .map_err(invalid)?,
            height: self.context.height,
            timestamp: self.context.consensus_timestamp_unix,
            gas_used_before: block.gas_used,
            randomness: synergy_posy::parse_hash_bytes(
                &self.authority.epoch.finalized_epoch_seed_root,
            )
            .map_err(invalid)?,
            recent_block_hashes: &history,
            protected_credit_verifier: Some(&protected_credit),
        };
        let execution =
            evm::execute_ordered_legacy_evm(raw, &context, candidate, candidate.budget());
        let (mut next, receipt, rejection) = match execution {
            Ok(result) => (result.world, Some(result.receipt), None),
            Err(
                EvmExecutionError::InvalidTransaction(_)
                | EvmExecutionError::SpendingAuthorityRevoked,
            ) => (
                candidate.try_clone().map_err(|error| {
                    state(synergy_state::world_resources::resource_state_error(error))
                })?,
                None,
                Some("authorization-no-longer-executable".to_string()),
            ),
            Err(EvmExecutionError::LocalResource(error)) => {
                return Err(state(synergy_state::world_resources::resource_state_error(
                    error,
                )))
            }
            Err(error) => return Err(invalid(error)),
        };
        let index = block.transactions.len() as u32;
        let first_log_index = block.logs;
        if let Some(receipt) = receipt.as_ref() {
            block.gas_used = block
                .gas_used
                .checked_add(receipt.gas_used)
                .ok_or_else(|| invalid("EVM cumulative gas overflow"))?;
            block.logs = block
                .logs
                .checked_add(receipt.logs.len() as u64)
                .ok_or_else(|| invalid("EVM log index overflow"))?;
            block.transactions.push(tx.transaction_hash);
        }
        #[derive(Serialize)]
        struct Record<'a> {
            height: u64,
            index: u32,
            first_log_index: u64,
            cumulative_gas_used: u64,
            raw: &'a [u8],
            receipt: Option<&'a EvmExecutionReceipt>,
            rejection: Option<String>,
        }
        let encoded = serde_json::to_vec(&Record {
            height: self.context.height,
            index,
            first_log_index,
            cumulative_gas_used: block.gas_used,
            raw,
            receipt: receipt.as_deref(),
            rejection,
        })
        .map_err(invalid)?;
        if encoded.len() > 4 * 1024 * 1024 {
            return Err(invalid("EVM receipt record exceeds native bound"));
        }
        let diff = StateDiff {
            changes: Vec::new(),
            protocol_changes: vec![
                consumption_change(record, self.context.height, tx.transaction_hash)?,
                ProtocolChange {
                    key,
                    expected_value: None,
                    value: Some(encoded),
                },
                ProtocolChange {
                    key: block_key.clone(),
                    expected_value: next.protocol.get(&block_key).cloned(),
                    value: Some(serde_json::to_vec(&block).map_err(invalid)?),
                },
            ],
        };
        next.try_apply(&diff).map_err(state)?;
        *candidate = next;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ethereum_consumption_retirement_matches_only_exact_selected_native_identity() {
        let digest =
            |name: &str| EtdagDigest::from_domain_bytes("evm-retirement-test", name.as_bytes());
        let record = ProcessingReadyRecord {
            item: synergy_etdag::execution::ProcessingReadyItem {
                group_number: 1,
                group_root: digest("group"),
                order_position: 0,
                envelope_id: digest("envelope"),
                payload_root: digest("payload"),
                readiness_root: digest("ready"),
                gas_class_units: 21000,
                encoded_bytes: 100,
                remaining_dependencies: Vec::new(),
            },
            processing_context_root: digest("context"),
            authorization_root: digest("authorization"),
            sender_wallet: format!("0x{}", "35".repeat(20)),
            sender_nonce: 4,
        };
        let identity = super::super::super::processing_store::PendingProcessingIdentity {
            envelope_id: record.item.envelope_id.clone(),
            context_root: record.processing_context_root.clone(),
            sender_wallet: record.sender_wallet.clone(),
            sender_nonce: record.sender_nonce,
        };
        let mut world = WorldState::default();
        let change = consumption_change(&record, 10, [7; 32]).unwrap();
        world
            .protocol
            .insert(change.key.clone(), change.value.unwrap());
        assert!(matches_pending(&world, 10, &identity).unwrap());
        assert!(!matches_pending(&world, 11, &identity).unwrap());
        let mut other = identity.clone();
        other.sender_nonce += 1;
        assert!(!matches_pending(&world, 10, &other).unwrap());
        other = identity.clone();
        other.context_root = digest("foreign context");
        assert!(!matches_pending(&world, 10, &other).unwrap());
        other = identity.clone();
        other.envelope_id = digest("another envelope");
        assert!(!matches_pending(&world, 10, &other).unwrap());
        assert!(
            verify_selected(&world, &world, 10, &record).is_err(),
            "prior native consumption cannot authorize another selection"
        );
        let mut altered = record.clone();
        altered.item.payload_root = digest("substituted plaintext");
        assert!(verify_selected(&WorldState::default(), &world, 10, &altered).is_err());
        assert!(
            verify_selected(&WorldState::default(), &world, 10, &record).is_err(),
            "marker alone is not a settled disposition"
        );
        world.protocol.insert(change.key, vec![0; 32769]);
        assert!(matches_pending(&world, 10, &identity).is_err());
    }
}
