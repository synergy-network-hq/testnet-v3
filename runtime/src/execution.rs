use crate::crypto::aegis_pqvm::SYNERGY_RECEIPT_ROOT_V1;
use crate::sts::{StsSignedPayload, StsState};
use crate::synergy_types::{
    Block, CanonicalSerialize, Hash, Transaction, TxId, SYNERGY_TESTNET_V3_CHAIN_ID,
    SYNERGY_TESTNET_V3_NETWORK_ID, SYNERGY_TESTNET_V3_RELEASE_ID,
};
use crate::synq_admission::SynQVerificationSummary;
use crate::synq_execution::{
    execute_synq_transaction_at, sts_host_context_from_sts_state, SynQAivmReceiptSummary,
    SynQArtifactKey, SynQContractArtifact, SynQDeploymentRecord, SynQExecutionContext,
};
use aivm_core::state::ContractState;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{OnceLock, RwLock};

pub const TESTNET_V3_GENESIS_SNAPSHOT_SCHEMA_VERSION: u32 = 3;
pub const SYNERGY_STATE_ROOT_V2: &str = "SYNERGY_STATE_ROOT_V2";

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityAuthorizationBindingCommitment {
    pub binding_payload_sha3_256: String,
    pub identity_root_public_key_sha3_256: String,
    pub effective_at_unix: u64,
}

impl IdentityAuthorizationBindingCommitment {
    fn from_verified_binding(
        binding: &crate::identity_auth::IdentityAuthorizationBinding,
        consensus_timestamp_unix: u64,
    ) -> Result<Self, String> {
        crate::identity_auth::verify_binding_at(binding, consensus_timestamp_unix)?;
        let effective_at = chrono::DateTime::parse_from_rfc3339(&binding.effective_at)
            .map_err(|error| format!("identity binding effective_at is invalid: {error}"))?
            .timestamp();
        let effective_at_unix = u64::try_from(effective_at)
            .map_err(|_| "identity binding effective_at precedes the Unix epoch".to_string())?;
        Ok(Self {
            binding_payload_sha3_256: binding.binding_payload_sha3_256.clone(),
            identity_root_public_key_sha3_256: binding.identity_root.public_key_sha3_256.clone(),
            effective_at_unix,
        })
    }
}

/// The only RPC-visible execution state is a clone of the state that the
/// finalized typed coordinator has already accepted.  It is deliberately not
/// populated by RPC, mempool admission, or speculative proposal execution.
///
/// The slot is process-local because it is an availability cache, not a source
/// of consensus truth: a restart must rebuild it from finalized Genesis and
/// replayed finality before contract reads are re-enabled.
static FINALIZED_EXECUTION_STATE_SNAPSHOT: OnceLock<RwLock<Option<ExecutionState>>> =
    OnceLock::new();

fn finalized_execution_state_snapshot_slot() -> &'static RwLock<Option<ExecutionState>> {
    FINALIZED_EXECUTION_STATE_SNAPSHOT.get_or_init(|| RwLock::new(None))
}

/// Install the initial, Genesis-bound finalized execution state immediately
/// before the typed coordinator begins serving consensus work.  Replacing a
/// live snapshot is prohibited so a new role lifecycle cannot silently serve
/// reads from a different coordinator instance.
pub(crate) fn install_finalized_execution_state_snapshot(
    state: ExecutionState,
) -> Result<(), String> {
    let mut slot = finalized_execution_state_snapshot_slot()
        .write()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if slot.is_some() {
        return Err("finalized execution-state snapshot is already installed".to_string());
    }
    *slot = Some(state);
    Ok(())
}

/// Publish a state only after the local coordinator has verified the finality
/// certificate and durably appended its finality record.  Returning `false`
/// means no typed runtime is currently serving this process, so RPC remains
/// fail-closed rather than fabricating a contract response.
pub(crate) fn publish_finalized_execution_state_snapshot(state: &ExecutionState) -> bool {
    let mut slot = finalized_execution_state_snapshot_slot()
        .write()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let Some(current) = slot.as_mut() else {
        return false;
    };
    *current = state.clone();
    true
}

/// Returns a copy so RPC static calls can never retain a mutable reference to
/// consensus-owned state.
pub(crate) fn finalized_execution_state_snapshot() -> Result<ExecutionState, String> {
    finalized_execution_state_snapshot_slot()
        .read()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clone()
        .ok_or_else(|| {
            "finalized execution-state snapshot is unavailable; contract reads are not ready"
                .to_string()
        })
}

pub(crate) fn finalized_identity_authorization_binding_hash(
    identity_address: &str,
) -> Result<String, String> {
    finalized_execution_state_snapshot()?
        .identity_authorization_bindings
        .get(identity_address)
        .map(|commitment| commitment.binding_payload_sha3_256.clone())
        .ok_or_else(|| {
            format!("identity {identity_address} has no canonical finalized authorization binding")
        })
}

/// Remove the availability cache whenever the typed role stops.  A stopped
/// node must not continue answering reads from a state that can no longer
/// advance with finalized consensus.
pub(crate) fn remove_finalized_execution_state_snapshot() {
    let mut slot = finalized_execution_state_snapshot_slot()
        .write()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    *slot = None;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionState {
    pub balances_nwei: BTreeMap<String, u128>,
    pub identity_authorization_bindings: BTreeMap<String, IdentityAuthorizationBindingCommitment>,
    pub sts_state: StsState,
    pub fee_events: Vec<FeeChargedEvent>,
    pub burn_events: Vec<BurnAddressTransferEvent>,
    pub verified_authorizations: BTreeMap<TxId, Hash>,
    pub synq_verifications: BTreeMap<TxId, SynQVerificationSummary>,
    pub synq_errors: BTreeMap<TxId, (String, String)>,
    pub synq_artifacts: BTreeMap<SynQArtifactKey, SynQContractArtifact>,
    pub synq_contracts: BTreeMap<String, SynQDeploymentRecord>,
    pub synq_aivm_state: ContractState,
}

impl ExecutionState {
    pub fn new() -> Self {
        Self {
            balances_nwei: BTreeMap::new(),
            identity_authorization_bindings: BTreeMap::new(),
            sts_state: StsState::new(),
            fee_events: Vec::new(),
            burn_events: Vec::new(),
            verified_authorizations: BTreeMap::new(),
            synq_verifications: BTreeMap::new(),
            synq_errors: BTreeMap::new(),
            synq_artifacts: BTreeMap::new(),
            synq_contracts: BTreeMap::new(),
            synq_aivm_state: ContractState::default(),
        }
    }

    pub fn with_balance(mut self, account: &str, amount_nwei: u128) -> Self {
        self.balances_nwei.insert(account.to_string(), amount_nwei);
        self
    }

    pub fn install_genesis_identity_authorization_binding(
        &mut self,
        binding: &crate::identity_auth::IdentityAuthorizationBinding,
    ) -> Result<(), String> {
        let effective_at = chrono::DateTime::parse_from_rfc3339(&binding.effective_at)
            .map_err(|error| format!("identity binding effective_at is invalid: {error}"))?
            .timestamp();
        let effective_at_unix = u64::try_from(effective_at)
            .map_err(|_| "identity binding effective_at precedes the Unix epoch".to_string())?;
        let commitment = IdentityAuthorizationBindingCommitment::from_verified_binding(
            binding,
            effective_at_unix,
        )?;
        match self
            .identity_authorization_bindings
            .get(&binding.identity_address)
        {
            Some(existing) if existing == &commitment => Ok(()),
            Some(_) => Err(format!(
                "Genesis contains conflicting identity authorization bindings for {}",
                binding.identity_address
            )),
            None => {
                self.identity_authorization_bindings
                    .insert(binding.identity_address.clone(), commitment);
                Ok(())
            }
        }
    }

    pub fn apply_identity_authorization_binding_transition(
        &mut self,
        binding: &crate::identity_auth::IdentityAuthorizationBinding,
        expected_current_binding_payload_sha3_256: &str,
        consensus_timestamp_unix: u64,
    ) -> Result<(), String> {
        let next = IdentityAuthorizationBindingCommitment::from_verified_binding(
            binding,
            consensus_timestamp_unix,
        )?;
        let current = self
            .identity_authorization_bindings
            .get(&binding.identity_address)
            .ok_or_else(|| {
                format!(
                    "identity {} has no canonical binding to rotate",
                    binding.identity_address
                )
            })?;
        if current.binding_payload_sha3_256 != expected_current_binding_payload_sha3_256 {
            return Err(
                "identity binding transition does not extend current finalized state".to_string(),
            );
        }
        if current.identity_root_public_key_sha3_256 != next.identity_root_public_key_sha3_256 {
            return Err(
                "identity binding transition attempted to replace the FN-DSA identity root"
                    .to_string(),
            );
        }
        if next.effective_at_unix <= current.effective_at_unix {
            return Err(
                "identity binding transition effective_at must strictly increase".to_string(),
            );
        }
        if next.binding_payload_sha3_256 == current.binding_payload_sha3_256 {
            return Err("identity binding transition does not change the binding".to_string());
        }
        self.identity_authorization_bindings
            .insert(binding.identity_address.clone(), next);
        Ok(())
    }

    pub fn current_identity_authorization_binding_hash(
        &self,
        identity_address: &str,
    ) -> Option<&str> {
        self.identity_authorization_bindings
            .get(identity_address)
            .map(|commitment| commitment.binding_payload_sha3_256.as_str())
    }

    pub(crate) fn mark_authorized(&mut self, tx: &Transaction) -> Result<TxId, String> {
        self.mark_authorized_at(tx, current_unix_timestamp())
    }

    pub(crate) fn mark_authorized_at(
        &mut self,
        tx: &Transaction,
        consensus_timestamp_unix: u64,
    ) -> Result<TxId, String> {
        let tx_id = tx_id(tx)?;
        let synq_result = if crate::synq_admission::is_synq_admission_carrier(&tx.payload) {
            let envelope = crate::synq_admission::decode_synq_admission_carrier(&tx.payload)
                .map_err(|error| error.to_string())?
                .ok_or_else(|| "SynQ carrier prefix decoded without an envelope".to_string())?;
            let carrier = envelope.identity_authorization.as_ref().ok_or_else(|| {
                "SynQ network admission is missing its identity authorization carrier".to_string()
            })?;
            let current_hash = self
                .current_identity_authorization_binding_hash(&carrier.binding.identity_address)
                .ok_or_else(|| {
                    format!(
                        "identity {} has no canonical binding in the parent execution state",
                        carrier.binding.identity_address
                    )
                })?;
            crate::synq_admission::verify_transaction_payload_for_chain_admission_at_current_binding(
                tx,
                consensus_timestamp_unix,
                current_hash,
            )
        } else {
            Ok(None)
        };
        match synq_result {
            Ok(Some(summary)) => {
                self.synq_verifications.insert(tx_id.clone(), summary);
            }
            Ok(None) => {}
            Err(error) => {
                self.verified_authorizations.remove(&tx_id);
                self.synq_verifications.remove(&tx_id);
                self.synq_errors
                    .insert(tx_id.clone(), (error.code().to_string(), error.to_string()));
                return Err(error.to_string());
            }
        }
        self.synq_errors.remove(&tx_id);
        self.verified_authorizations
            .insert(tx_id.clone(), tx.canonical_tx_bytes_hash()?);
        Ok(tx_id)
    }
}

/// Deterministic, public, root-bearing execution state required to boot the
/// finalized Testnet-v3 genesis.
///
/// Admission caches and diagnostic error maps are intentionally excluded:
/// they are transient verification products and do not contribute to
/// `compute_state_root_after`. Every field that does contribute to that root
/// is included so a validator can reconstruct the exact post-ceremony state
/// without access to any custody key.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct GenesisArtifactSnapshot {
    pub key: SynQArtifactKey,
    pub artifact: SynQContractArtifact,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GenesisExecutionSnapshot {
    pub schema_version: u32,
    pub chain_id: u64,
    pub network_id: String,
    pub release_id: String,
    pub state_root: String,
    pub aivm_state_root: String,
    pub balances_nwei: BTreeMap<String, u128>,
    pub identity_authorization_bindings: BTreeMap<String, IdentityAuthorizationBindingCommitment>,
    pub sts_state: StsState,
    pub fee_events: Vec<FeeChargedEvent>,
    pub burn_events: Vec<BurnAddressTransferEvent>,
    pub synq_artifacts: Vec<GenesisArtifactSnapshot>,
    pub synq_contracts: BTreeMap<String, SynQDeploymentRecord>,
    pub synq_aivm_state: ContractState,
}

impl GenesisExecutionSnapshot {
    pub fn capture_testnet_v3(state: &ExecutionState) -> Result<Self, String> {
        Ok(Self {
            schema_version: TESTNET_V3_GENESIS_SNAPSHOT_SCHEMA_VERSION,
            chain_id: SYNERGY_TESTNET_V3_CHAIN_ID,
            network_id: SYNERGY_TESTNET_V3_NETWORK_ID.to_string(),
            release_id: SYNERGY_TESTNET_V3_RELEASE_ID.to_string(),
            state_root: compute_state_root_after(state)?.to_hex(),
            aivm_state_root: hex::encode(state.synq_aivm_state.state_root()),
            balances_nwei: state.balances_nwei.clone(),
            identity_authorization_bindings: state.identity_authorization_bindings.clone(),
            sts_state: state.sts_state.clone(),
            fee_events: state.fee_events.clone(),
            burn_events: state.burn_events.clone(),
            synq_artifacts: state
                .synq_artifacts
                .iter()
                .map(|(key, artifact)| GenesisArtifactSnapshot {
                    key: key.clone(),
                    artifact: artifact.clone(),
                })
                .collect(),
            synq_contracts: state.synq_contracts.clone(),
            synq_aivm_state: state.synq_aivm_state.clone(),
        })
    }

    pub fn restore_testnet_v3(&self) -> Result<ExecutionState, String> {
        if self.schema_version != TESTNET_V3_GENESIS_SNAPSHOT_SCHEMA_VERSION {
            return Err(format!(
                "unsupported Testnet-v3 genesis execution snapshot schema {}",
                self.schema_version
            ));
        }
        if self.chain_id != SYNERGY_TESTNET_V3_CHAIN_ID
            || self.network_id != SYNERGY_TESTNET_V3_NETWORK_ID
            || self.release_id != SYNERGY_TESTNET_V3_RELEASE_ID
        {
            return Err(format!(
                "Testnet-v3 genesis execution snapshot chain/network/release mismatch: chain_id={} network_id={} release_id={}",
                self.chain_id, self.network_id, self.release_id
            ));
        }
        let mut synq_artifacts = BTreeMap::new();
        for entry in &self.synq_artifacts {
            if entry.artifact.key() != entry.key {
                return Err(
                    "Testnet-v3 genesis execution snapshot artifact content does not match its key"
                        .to_string(),
                );
            }
            if synq_artifacts
                .insert(entry.key.clone(), entry.artifact.clone())
                .is_some()
            {
                return Err(
                    "Testnet-v3 genesis execution snapshot contains a duplicate SynQ artifact key"
                        .to_string(),
                );
            }
        }
        for deployment in self.synq_contracts.values() {
            if !synq_artifacts.contains_key(&deployment.artifact_key) {
                return Err(format!(
                    "Testnet-v3 genesis execution snapshot contract {} references a missing artifact",
                    deployment.contract_address
                ));
            }
        }
        for (identity_address, commitment) in &self.identity_authorization_bindings {
            let decoded = crate::address::decode_address(identity_address).map_err(|error| {
                format!(
                    "Testnet-v3 genesis execution snapshot identity address {identity_address} is invalid: {error}"
                )
            })?;
            if decoded.classification != crate::snts_registry::IdentifierClass::KeyControlledAddress
            {
                return Err(format!(
                    "Testnet-v3 genesis execution snapshot identity {identity_address} is not key-controlled"
                ));
            }
            for (field, value) in [
                (
                    "binding payload",
                    commitment.binding_payload_sha3_256.as_str(),
                ),
                (
                    "identity root",
                    commitment.identity_root_public_key_sha3_256.as_str(),
                ),
            ] {
                if value.len() != 64
                    || value
                        .bytes()
                        .any(|byte| !byte.is_ascii_digit() && !(b'a'..=b'f').contains(&byte))
                {
                    return Err(format!(
                        "Testnet-v3 genesis execution snapshot {field} commitment for {identity_address} is not lowercase SHA3-256 hex"
                    ));
                }
            }
        }
        let state = ExecutionState {
            balances_nwei: self.balances_nwei.clone(),
            identity_authorization_bindings: self.identity_authorization_bindings.clone(),
            sts_state: self.sts_state.clone(),
            fee_events: self.fee_events.clone(),
            burn_events: self.burn_events.clone(),
            verified_authorizations: BTreeMap::new(),
            synq_verifications: BTreeMap::new(),
            synq_errors: BTreeMap::new(),
            synq_artifacts,
            synq_contracts: self.synq_contracts.clone(),
            synq_aivm_state: self.synq_aivm_state.clone(),
        };
        let actual_state_root = compute_state_root_after(&state)?.to_hex();
        if actual_state_root != self.state_root {
            return Err(format!(
                "Testnet-v3 genesis execution snapshot state root mismatch: declared {} computed {}",
                self.state_root, actual_state_root
            ));
        }
        let actual_aivm_state_root = hex::encode(state.synq_aivm_state.state_root());
        if actual_aivm_state_root != self.aivm_state_root {
            return Err(format!(
                "Testnet-v3 genesis execution snapshot AIVM root mismatch: declared {} computed {}",
                self.aivm_state_root, actual_aivm_state_root
            ));
        }
        Ok(state)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct FeeChargedEvent {
    pub tx_id: TxId,
    pub payer: String,
    pub fee_collector_address: String,
    /// Ordinary-gas execution fee (`gas_used * base_fee_per_gas`).
    pub gas_fee_nwei: u128,
    pub amount_protocol_fee_nwei: u128,
    pub storage_fee_nwei: u128,
    pub priority_fee_nwei: u128,
    pub total_network_fee_nwei: u128,
    pub block_height: u64,
    pub success: bool,
    /// --- Canonical Live Gas Pricing (fee market) additions, additive and
    /// `#[serde(default)]` so events recorded before this change continue
    /// to decode (as zero-valued / inactive fee-market accounting). ---
    #[serde(default)]
    pub pq_gas_used: u64,
    #[serde(default)]
    pub pq_execution_fee_nwei: u128,
    #[serde(default)]
    pub fee_market_active: bool,
    #[serde(default)]
    pub fee_market_version: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct BurnAddressTransferEvent {
    pub tx_id: TxId,
    pub from: String,
    pub to: String,
    pub amount_nwei: u128,
    pub block_height: u64,
    pub supply_reduced: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionGraph {
    pub batches: Vec<Vec<TxId>>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ReceiptStatus {
    Success,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct TransactionReceipt {
    pub tx_id: TxId,
    pub status: ReceiptStatus,
    pub gas_used: u64,
    pub error: String,
    pub state_root_after: Hash,
    pub synq_verification: Option<SynQVerificationSummary>,
    pub synq_aivm: Option<SynQAivmReceiptSummary>,
    pub synq_error_code: Option<String>,
    pub synq_error_message: Option<String>,
    /// Auditable fee breakdown for this transaction. When
    /// `fee_breakdown.fee_market_active` is `true`, `base_execution_fee_nwei`
    /// / `pq_execution_fee_nwei` / `execution_fee_total_nwei` on this
    /// breakdown were computed from real `gas_used` /
    /// `TransactionReceipt::pq_gas_used` against the protocol
    /// `base_fee_per_gas`, per `crate::gas::fee_market`. When `false`, this
    /// is legacy pre-fee-market pricing (sender-declared `max_fee_nwei`).
    pub fee_breakdown: Option<crate::gas::NetworkFeeBreakdown>,
    /// PQ gas consumed by this transaction (AIVM `PqGasMeter`), tracked
    /// independently of `gas_used` at every layer. `0` for transactions
    /// with no PQ execution component.
    #[serde(default)]
    pub pq_gas_used: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionResult {
    pub state: ExecutionState,
    pub receipts: Vec<TransactionReceipt>,
    pub state_root_after: Hash,
    pub receipt_root: Hash,
    /// Sum of `TransactionReceipt::gas_used` across every receipt in this
    /// block. The block builder writes this into
    /// `BlockHeader::gas_used`; independent replay (block validation)
    /// recomputes it the same way and must match the declared value.
    pub gas_used_total: u64,
    /// Sum of `TransactionReceipt::pq_gas_used` across every receipt,
    /// tracked independently of `gas_used_total` (never combined).
    pub pq_gas_used_total: u64,
    /// The fee market this execution actually charged under, derived from
    /// `block.header` (see `execute_block`). `None` means this block predates
    /// fee-market activation (`fee_market_version == 0`).
    pub applied_fee_market: Option<crate::gas::fee_market::AppliedFeeMarket>,
}

/// Executes every transaction in `block` against a clone of `state`.
///
/// The block's declared `base_fee_per_gas_nwei` / `pq_gas_multiplier` /
/// `fee_market_version` (`block.header`) are treated as authoritative input
/// here -- this function does not itself recompute or validate that the
/// declared base fee is correct; it charges transactions against whatever
/// the header declares. That is intentional and safe as long as every
/// caller that accepts a block from a peer *also* independently verifies
/// `block.header.base_fee_per_gas_nwei ==
/// fee_market::next_base_fee_per_gas(parent_header)` before or alongside
/// calling this function (see
/// `consensus::coordinated_runtime::verify_producer_block` /
/// `execute_coordinated_block`) -- otherwise two nodes that disagreed on the
/// header's correctness would still agree on its *execution*, which is not
/// sufficient to reject a dishonest proposer.
pub fn execute_block(block: &Block, state: &ExecutionState) -> Result<ExecutionResult, String> {
    let graph = build_execution_graph(&block.transactions)?;
    let batches = split_into_parallel_batches(&graph);
    let mut working_state = state.clone();
    let mut receipts = Vec::new();
    let applied_fee_market = fee_market_from_header(&block.header);
    let synq_context = SynQExecutionContext {
        runtime_block_height: block.header.height.0,
        runtime_block_timestamp_unix: block
            .header
            .timestamp_ms_consensus_bounded
            .saturating_div(1_000),
        sts_host: None,
        applied_fee_market,
    };
    for batch in batches {
        let mut batch_receipts = execute_batch_parallel(
            &batch,
            &block.transactions,
            &mut working_state,
            synq_context.clone(),
        )?;
        receipts.append(&mut batch_receipts);
    }
    receipts = merge_results_in_canonical_order(receipts);
    let state_root_after = compute_state_root_after(&working_state)?;
    let receipt_root = compute_receipt_root(&receipts)?;
    let gas_used_total = receipts
        .iter()
        .try_fold(0u64, |total, receipt| total.checked_add(receipt.gas_used))
        .ok_or_else(|| "block gas_used_total overflow".to_string())?;
    let pq_gas_used_total = receipts
        .iter()
        .try_fold(0u64, |total, receipt| {
            total.checked_add(receipt.pq_gas_used)
        })
        .ok_or_else(|| "block pq_gas_used_total overflow".to_string())?;
    Ok(ExecutionResult {
        state: working_state,
        receipts,
        state_root_after,
        receipt_root,
        gas_used_total,
        pq_gas_used_total,
        applied_fee_market,
    })
}

/// Derives the fee market a block's header declares, or `None` if the
/// header predates activation (`fee_market_version == 0`) or is malformed
/// (e.g. `pq_gas_multiplier` overflow) -- a malformed declared fee market is
/// never silently treated as "active with a fabricated price"; it falls
/// back to legacy charging, and the separate header-validation check (see
/// `execute_block` docs) is responsible for rejecting the block outright.
fn fee_market_from_header(
    header: &crate::synergy_types::BlockHeader,
) -> Option<crate::gas::fee_market::AppliedFeeMarket> {
    if header.fee_market_version == 0 {
        return None;
    }
    let effective_pq_gas_price_nwei = crate::gas::fee_market::effective_pq_gas_price(
        header.base_fee_per_gas_nwei,
        header.pq_gas_multiplier,
    )
    .ok()?;
    Some(crate::gas::fee_market::AppliedFeeMarket {
        base_fee_per_gas_nwei: header.base_fee_per_gas_nwei,
        pq_gas_multiplier: header.pq_gas_multiplier,
        effective_pq_gas_price_nwei,
        fee_market_version: header.fee_market_version,
    })
}

pub fn build_execution_graph(transactions: &[Transaction]) -> Result<ExecutionGraph, String> {
    let mut resource_owner = BTreeMap::<String, TxId>::new();
    let mut tx_depth = BTreeMap::<TxId, usize>::new();
    let mut batches: Vec<Vec<TxId>> = Vec::new();
    for tx in transactions {
        let id = tx_id(tx)?;
        let mut depth = 0usize;
        for resource in &tx.write_set_hint {
            if let Some(parent) = resource_owner.get(resource) {
                depth = depth.max(tx_depth.get(parent).copied().unwrap_or(0).saturating_add(1));
            }
        }
        tx_depth.insert(id.clone(), depth);
        for resource in &tx.write_set_hint {
            resource_owner.insert(resource.clone(), id.clone());
        }
        if batches.len() <= depth {
            batches.resize(depth + 1, Vec::new());
        }
        batches[depth].push(id);
    }
    for batch in &mut batches {
        batch.sort();
    }
    Ok(ExecutionGraph { batches })
}

pub fn split_into_parallel_batches(graph: &ExecutionGraph) -> Vec<Vec<TxId>> {
    graph.batches.clone()
}

pub fn execute_batch_parallel(
    batch: &[TxId],
    transactions: &[Transaction],
    state: &mut ExecutionState,
    synq_context: SynQExecutionContext,
) -> Result<Vec<TransactionReceipt>, String> {
    let by_id = transactions
        .iter()
        .map(|tx| tx_id(tx).map(|id| (id, tx)))
        .collect::<Result<BTreeMap<_, _>, _>>()?;
    let mut receipts = Vec::new();
    for tx_id in batch {
        let tx = by_id
            .get(tx_id)
            .ok_or_else(|| format!("transaction {} missing from batch input", tx_id.0))?;
        receipts.push(execute_transaction(
            tx_id.clone(),
            tx,
            state,
            synq_context.clone(),
        )?);
    }
    Ok(receipts)
}

pub fn merge_results_in_canonical_order(
    mut receipts: Vec<TransactionReceipt>,
) -> Vec<TransactionReceipt> {
    receipts.sort_by(|a, b| a.tx_id.cmp(&b.tx_id));
    receipts
}

pub fn compute_state_root_after(state: &ExecutionState) -> Result<Hash, String> {
    #[derive(serde::Serialize)]
    struct ArtifactRootEntry<'a> {
        key: &'a SynQArtifactKey,
        artifact: &'a SynQContractArtifact,
    }

    #[derive(serde::Serialize)]
    struct StateRootPayload<'a> {
        balances_nwei: &'a BTreeMap<String, u128>,
        identity_authorization_bindings:
            &'a BTreeMap<String, IdentityAuthorizationBindingCommitment>,
        sts_state: &'a StsState,
        fee_events: &'a [FeeChargedEvent],
        burn_events: &'a [BurnAddressTransferEvent],
        synq_artifacts: Vec<ArtifactRootEntry<'a>>,
        synq_contracts: &'a BTreeMap<String, SynQDeploymentRecord>,
        synq_aivm_state_root: [u8; 32],
    }

    let synq_artifacts = state
        .synq_artifacts
        .iter()
        .map(|(key, artifact)| ArtifactRootEntry { key, artifact })
        .collect::<Vec<_>>();
    let payload = StateRootPayload {
        balances_nwei: &state.balances_nwei,
        identity_authorization_bindings: &state.identity_authorization_bindings,
        sts_state: &state.sts_state,
        fee_events: &state.fee_events,
        burn_events: &state.burn_events,
        synq_artifacts,
        synq_contracts: &state.synq_contracts,
        synq_aivm_state_root: state.synq_aivm_state.state_root(),
    };
    serde_json::to_vec(&payload)
        .map(|bytes| Hash::from_domain_bytes(SYNERGY_STATE_ROOT_V2, &bytes))
        .map_err(|error| format!("state root serialize failed: {error}"))
}

pub fn compute_receipt_root(receipts: &[TransactionReceipt]) -> Result<Hash, String> {
    serde_json::to_vec(receipts)
        .map(|bytes| Hash::from_domain_bytes(SYNERGY_RECEIPT_ROOT_V1, &bytes))
        .map_err(|error| format!("receipt root serialize failed: {error}"))
}

fn execute_transaction(
    id: TxId,
    tx: &Transaction,
    state: &mut ExecutionState,
    synq_context: SynQExecutionContext,
) -> Result<TransactionReceipt, String> {
    let canonical_hash = tx.canonical_tx_bytes_hash()?;
    match state.verified_authorizations.get(&id) {
        Some(recorded) if *recorded == canonical_hash => {}
        Some(_) => {
            return Err(format!(
                "transaction {} bytes changed after PQC authorization verification",
                id.0
            ));
        }
        None => {
            return Err(format!(
                "transaction {} missing verified Aegis PQC authorization context",
                id.0
            ));
        }
    }

    let sender = tx.sender_uma_or_account.clone();
    if let Some(sts_payload) =
        crate::sts::decode_sts_payload(&tx.payload).map_err(|error| error.to_string())?
    {
        return execute_sts_transaction(id, tx, state, sts_payload, synq_context);
    }

    let synq_verification = state.synq_verifications.get(&id).cloned();
    let synq_error = state.synq_errors.get(&id).cloned();
    let payload = std::str::from_utf8(&tx.payload).unwrap_or_default();
    let applied_fee_market = synq_context.applied_fee_market;

    if crate::address::is_network_burn_address(&sender) {
        let estimated_fee = canonical_network_fee_breakdown(
            tx,
            tx.gas_limit.min(21_000),
            0,
            tx.max_fee_nwei,
            true,
            applied_fee_market.as_ref(),
        )?;
        return Ok(TransactionReceipt {
            tx_id: id,
            status: ReceiptStatus::Failed,
            gas_used: tx.gas_limit.min(21_000),
            error: "NETWORK_BURN_ADDRESS_CANNOT_SEND".to_string(),
            state_root_after: compute_state_root_after(state)?,
            synq_verification,
            synq_aivm: None,
            synq_error_code: synq_error.as_ref().map(|(code, _)| code.clone()),
            synq_error_message: synq_error.map(|(_, message)| message),
            fee_breakdown: Some(estimated_fee),
            pq_gas_used: 0,
        });
    }

    let explicit_native_burn = match parse_explicit_native_burn_payload(payload, tx.amount_nwei) {
        Ok(burn) => burn,
        Err(error) => {
            let gas_used = tx.gas_limit.min(21_000);
            let fee_breakdown = canonical_network_fee_breakdown(
                tx,
                gas_used,
                0,
                tx.max_fee_nwei,
                false,
                applied_fee_market.as_ref(),
            )?;
            if state.balances_nwei.get(&sender).copied().unwrap_or(0)
                >= fee_breakdown.total_network_fee_nwei
            {
                charge_fee_to_collector(state, &sender, fee_breakdown.total_network_fee_nwei)?;
                record_fee_event(
                    state,
                    &id,
                    &sender,
                    &fee_breakdown,
                    synq_context.runtime_block_height,
                    false,
                );
            }
            return Ok(TransactionReceipt {
                tx_id: id,
                status: ReceiptStatus::Failed,
                gas_used,
                error,
                state_root_after: compute_state_root_after(state)?,
                synq_verification,
                synq_aivm: None,
                synq_error_code: synq_error.as_ref().map(|(code, _)| code.clone()),
                synq_error_message: synq_error.map(|(_, message)| message),
                fee_breakdown: Some(fee_breakdown),
                pq_gas_used: 0,
            });
        }
    };
    let transfer_amount_nwei = explicit_native_burn
        .as_ref()
        .map(|burn| burn.amount_nwei)
        .unwrap_or(tx.amount_nwei);
    let estimated_fee = canonical_network_fee_breakdown(
        tx,
        tx.gas_limit.min(21_000),
        0,
        tx.max_fee_nwei,
        true,
        applied_fee_market.as_ref(),
    )?;
    let sender_balance = state.balances_nwei.get(&sender).copied().unwrap_or(0);
    let total_debit = transfer_amount_nwei
        .checked_add(estimated_fee.total_network_fee_nwei)
        .ok_or_else(|| "transaction total debit overflow".to_string())?;
    if sender_balance < total_debit {
        return Ok(TransactionReceipt {
            tx_id: id,
            status: ReceiptStatus::Failed,
            gas_used: tx.gas_limit.min(21_000),
            error: "INSUFFICIENT_FUNDS".to_string(),
            state_root_after: compute_state_root_after(state)?,
            synq_verification,
            synq_aivm: None,
            synq_error_code: synq_error.as_ref().map(|(code, _)| code.clone()),
            synq_error_message: synq_error.map(|(_, message)| message),
            fee_breakdown: Some(estimated_fee),
            pq_gas_used: 0,
        });
    }

    let mut candidate_synq_aivm_state = state.synq_aivm_state.clone();
    let mut candidate_synq_artifacts = state.synq_artifacts.clone();
    let mut candidate_synq_contracts = state.synq_contracts.clone();
    let synq_aivm = if let Some(summary) = synq_verification.as_ref() {
        let mut synq_context = synq_context.clone();
        synq_context.sts_host = Some(sts_host_context_from_sts_state(
            &state.sts_state,
            synq_context.runtime_block_timestamp_unix,
        ));
        execute_synq_transaction_at(
            &id,
            tx,
            summary,
            &mut candidate_synq_aivm_state,
            &mut candidate_synq_artifacts,
            &mut candidate_synq_contracts,
            synq_context,
        )?
    } else {
        None
    };
    let gas_used = synq_aivm
        .as_ref()
        .map(|receipt| receipt.gas_used)
        .unwrap_or_else(|| tx.gas_limit.min(21_000));
    // PQ gas is tracked independently of ordinary gas at every layer (never
    // combined before reporting): AIVM's `PqGasMeter` output on the SynQ
    // receipt, or `0` for transactions with no PQ execution component
    // (e.g. plain native transfers, which are not run through AIVM).
    let pq_gas_used = synq_aivm
        .as_ref()
        .map(|receipt| receipt.pqc_gas_used)
        .unwrap_or(0);

    if synq_aivm
        .as_ref()
        .is_some_and(|receipt| receipt.status != "succeeded")
    {
        let fee_breakdown = canonical_network_fee_breakdown(
            tx,
            gas_used,
            pq_gas_used,
            tx.max_fee_nwei,
            false,
            applied_fee_market.as_ref(),
        )?;
        if let Some(cap_error) = max_fee_cap_violation(&fee_breakdown, tx.max_fee_nwei) {
            return Ok(TransactionReceipt {
                tx_id: id,
                status: ReceiptStatus::Failed,
                gas_used,
                error: cap_error,
                state_root_after: compute_state_root_after(state)?,
                synq_verification,
                synq_aivm,
                synq_error_code: synq_error.as_ref().map(|(code, _)| code.clone()),
                synq_error_message: synq_error.map(|(_, message)| message),
                fee_breakdown: Some(fee_breakdown),
                pq_gas_used,
            });
        }
        charge_fee_to_collector(state, &sender, fee_breakdown.total_network_fee_nwei)?;
        record_fee_event(
            state,
            &id,
            &sender,
            &fee_breakdown,
            synq_context.runtime_block_height,
            false,
        );
        let error = synq_aivm
            .as_ref()
            .and_then(|receipt| receipt.error_message.clone())
            .unwrap_or_else(|| "SYNQ_AIVM_EXECUTION_FAILED".to_string());
        return Ok(TransactionReceipt {
            tx_id: id,
            status: ReceiptStatus::Failed,
            gas_used,
            error,
            state_root_after: compute_state_root_after(state)?,
            synq_verification,
            synq_aivm,
            synq_error_code: synq_error.as_ref().map(|(code, _)| code.clone()),
            synq_error_message: synq_error.map(|(_, message)| message),
            fee_breakdown: Some(fee_breakdown),
            pq_gas_used,
        });
    }

    let fee_breakdown = canonical_network_fee_breakdown(
        tx,
        gas_used,
        pq_gas_used,
        tx.max_fee_nwei,
        true,
        applied_fee_market.as_ref(),
    )?;
    if let Some(cap_error) = max_fee_cap_violation(&fee_breakdown, tx.max_fee_nwei) {
        return Ok(TransactionReceipt {
            tx_id: id,
            status: ReceiptStatus::Failed,
            gas_used,
            error: cap_error,
            state_root_after: compute_state_root_after(state)?,
            synq_verification,
            synq_aivm,
            synq_error_code: synq_error.as_ref().map(|(code, _)| code.clone()),
            synq_error_message: synq_error.map(|(_, message)| message),
            fee_breakdown: Some(fee_breakdown),
            pq_gas_used,
        });
    }
    let total_debit = transfer_amount_nwei
        .checked_add(fee_breakdown.total_network_fee_nwei)
        .ok_or_else(|| "transaction total debit overflow".to_string())?;
    let sender_balance = state.balances_nwei.get(&sender).copied().unwrap_or(0);
    if sender_balance < total_debit {
        return Ok(TransactionReceipt {
            tx_id: id,
            status: ReceiptStatus::Failed,
            gas_used,
            error: "INSUFFICIENT_FUNDS".to_string(),
            state_root_after: compute_state_root_after(state)?,
            synq_verification,
            synq_aivm,
            synq_error_code: synq_error.as_ref().map(|(code, _)| code.clone()),
            synq_error_message: synq_error.map(|(_, message)| message),
            fee_breakdown: Some(fee_breakdown),
            pq_gas_used,
        });
    }

    let mut candidate_balances = state.balances_nwei.clone();
    candidate_balances.insert(sender.clone(), sender_balance - total_debit);
    let collector = fee_breakdown.fee_collector_address.clone();
    let collector_balance = candidate_balances.get(&collector).copied().unwrap_or(0);
    candidate_balances.insert(
        collector,
        collector_balance
            .checked_add(fee_breakdown.total_network_fee_nwei)
            .ok_or_else(|| "fee collector balance overflow".to_string())?,
    );
    if let Some(burn) = explicit_native_burn {
        state.burn_events.push(BurnAddressTransferEvent {
            tx_id: id.clone(),
            from: sender.clone(),
            to: crate::address::NETWORK_BURN_ADDRESS.to_string(),
            amount_nwei: burn.amount_nwei,
            block_height: synq_context.runtime_block_height,
            supply_reduced: true,
        });
    } else {
        let receiver = tx.receiver_uma_or_account.clone();
        let receiver_balance = candidate_balances.get(&receiver).copied().unwrap_or(0);
        candidate_balances.insert(
            receiver.clone(),
            receiver_balance
                .checked_add(tx.amount_nwei)
                .ok_or_else(|| "receiver balance overflow".to_string())?,
        );
        if crate::address::is_network_burn_address(&receiver) && tx.amount_nwei > 0 {
            state.burn_events.push(BurnAddressTransferEvent {
                tx_id: id.clone(),
                from: sender.clone(),
                to: receiver.clone(),
                amount_nwei: tx.amount_nwei,
                block_height: synq_context.runtime_block_height,
                supply_reduced: false,
            });
        }
    }
    if let Some(receipt) = synq_aivm.as_ref() {
        for transfer in &receipt.native_transfers {
            let from_balance = candidate_balances.get(&transfer.from).copied().unwrap_or(0);
            if from_balance < transfer.amount_nwei {
                return Err(format!(
                    "SynQ native transfer effect exceeds balance for {}",
                    transfer.from
                ));
            }
            let to_balance = candidate_balances.get(&transfer.to).copied().unwrap_or(0);
            candidate_balances.insert(transfer.from.clone(), from_balance - transfer.amount_nwei);
            candidate_balances.insert(
                transfer.to.clone(),
                to_balance
                    .checked_add(transfer.amount_nwei)
                    .ok_or_else(|| "SynQ native transfer recipient overflow".to_string())?,
            );
        }
    }
    state.balances_nwei = candidate_balances;
    state.synq_aivm_state = candidate_synq_aivm_state;
    state.synq_artifacts = candidate_synq_artifacts;
    state.synq_contracts = candidate_synq_contracts;
    record_fee_event(
        state,
        &id,
        &sender,
        &fee_breakdown,
        synq_context.runtime_block_height,
        true,
    );

    Ok(TransactionReceipt {
        tx_id: id,
        status: ReceiptStatus::Success,
        gas_used,
        error: String::new(),
        state_root_after: compute_state_root_after(state)?,
        synq_verification,
        synq_aivm,
        synq_error_code: synq_error.as_ref().map(|(code, _)| code.clone()),
        synq_error_message: synq_error.map(|(_, message)| message),
        fee_breakdown: Some(fee_breakdown),
        pq_gas_used,
    })
}

/// Returns a receipt-ready error string when the protocol-computed
/// execution fee would exceed the sender's declared `max_fee_nwei` cap.
/// Only meaningful once the fee market is active (`fee_breakdown
/// .fee_market_active`); before activation the legacy path always charges
/// exactly `max_fee_nwei`, so it can never exceed itself.
fn max_fee_cap_violation(
    fee_breakdown: &crate::gas::NetworkFeeBreakdown,
    max_fee_nwei: u128,
) -> Option<String> {
    if fee_breakdown.fee_market_active && fee_breakdown.execution_fee_total_nwei > max_fee_nwei {
        Some(format!(
            "MAX_FEE_PER_GAS_TOO_LOW: protocol execution fee {} nWei exceeds declared max_fee_nwei {} nWei",
            fee_breakdown.execution_fee_total_nwei, max_fee_nwei
        ))
    } else {
        None
    }
}

fn execute_sts_transaction(
    id: TxId,
    tx: &Transaction,
    state: &mut ExecutionState,
    sts_payload: StsSignedPayload,
    synq_context: SynQExecutionContext,
) -> Result<TransactionReceipt, String> {
    let sender = tx.sender_uma_or_account.clone();
    let sender_balance = state.balances_nwei.get(&sender).copied().unwrap_or(0);
    let fee_nwei = tx.max_fee_nwei;
    let gas_used = tx
        .gas_limit
        .min(crate::sts::estimate_sts_gas(&sts_payload.tx));
    let synq_error = state.synq_errors.get(&id).cloned();
    // STS payloads do not execute through AIVM: no PQ gas component, and
    // (for now, out of scope for this change) STS fees stay on the legacy
    // flat `max_fee_nwei` charge regardless of fee-market activation.
    let fee_breakdown = canonical_network_fee_breakdown(tx, gas_used, 0, fee_nwei, false, None)?;

    if sender_balance < fee_nwei {
        return Ok(TransactionReceipt {
            tx_id: id,
            status: ReceiptStatus::Failed,
            gas_used,
            error: "INSUFFICIENT_FUNDS".to_string(),
            state_root_after: compute_state_root_after(state)?,
            synq_verification: None,
            synq_aivm: None,
            synq_error_code: synq_error.as_ref().map(|(code, _)| code.clone()),
            synq_error_message: synq_error.map(|(_, message)| message),
            fee_breakdown: Some(fee_breakdown),
            pq_gas_used: 0,
        });
    }

    let mut candidate = state.sts_state.clone();
    let apply_result = candidate.apply_signed_payload(&sender, &sts_payload);
    charge_fee_to_collector(state, &sender, fee_breakdown.total_network_fee_nwei)?;

    match apply_result {
        Ok(_) => {
            state.sts_state = candidate;
            record_fee_event(
                state,
                &id,
                &sender,
                &fee_breakdown,
                synq_context.runtime_block_height,
                true,
            );
            Ok(TransactionReceipt {
                tx_id: id,
                status: ReceiptStatus::Success,
                gas_used,
                error: String::new(),
                state_root_after: compute_state_root_after(state)?,
                synq_verification: None,
                synq_aivm: None,
                synq_error_code: synq_error.as_ref().map(|(code, _)| code.clone()),
                synq_error_message: synq_error.map(|(_, message)| message),
                fee_breakdown: Some(fee_breakdown),
                pq_gas_used: 0,
            })
        }
        Err(error) => {
            record_fee_event(
                state,
                &id,
                &sender,
                &fee_breakdown,
                synq_context.runtime_block_height,
                false,
            );
            Ok(TransactionReceipt {
                tx_id: id,
                status: ReceiptStatus::Failed,
                gas_used,
                error: error.to_string(),
                state_root_after: compute_state_root_after(state)?,
                synq_verification: None,
                synq_aivm: None,
                synq_error_code: synq_error.as_ref().map(|(code, _)| code.clone()),
                synq_error_message: synq_error.map(|(_, message)| message),
                fee_breakdown: Some(fee_breakdown),
                pq_gas_used: 0,
            })
        }
    }
}

fn charge_fee_to_collector(
    state: &mut ExecutionState,
    sender: &str,
    fee_nwei: u128,
) -> Result<(), String> {
    if fee_nwei == 0 {
        return Ok(());
    }
    let sender_balance = state.balances_nwei.get(sender).copied().unwrap_or(0);
    if sender_balance < fee_nwei {
        return Err("insufficient SNRG balance for fee".to_string());
    }
    state
        .balances_nwei
        .insert(sender.to_string(), sender_balance - fee_nwei);
    let collector = crate::token::fee_collector_address()?;
    let collector_balance = state.balances_nwei.get(&collector).copied().unwrap_or(0);
    let next_collector_balance = collector_balance
        .checked_add(fee_nwei)
        .ok_or_else(|| "fee collector balance overflow".to_string())?;
    state
        .balances_nwei
        .insert(collector, next_collector_balance);
    Ok(())
}

fn record_fee_event(
    state: &mut ExecutionState,
    tx_id: &TxId,
    payer: &str,
    fee_breakdown: &crate::gas::NetworkFeeBreakdown,
    block_height: u64,
    success: bool,
) {
    state.fee_events.push(FeeChargedEvent {
        tx_id: tx_id.clone(),
        payer: payer.to_string(),
        fee_collector_address: fee_breakdown.fee_collector_address.clone(),
        gas_fee_nwei: fee_breakdown.gas_fee_nwei,
        amount_protocol_fee_nwei: fee_breakdown.amount_protocol_fee_nwei,
        storage_fee_nwei: fee_breakdown.storage_fee_nwei,
        priority_fee_nwei: fee_breakdown.priority_fee_nwei,
        total_network_fee_nwei: fee_breakdown.total_network_fee_nwei,
        block_height,
        success,
        pq_gas_used: fee_breakdown.pq_gas_used,
        pq_execution_fee_nwei: fee_breakdown.pq_execution_fee_nwei,
        fee_market_active: fee_breakdown.fee_market_active,
        fee_market_version: fee_breakdown.fee_market_version,
    });
    if fee_breakdown.total_network_fee_nwei > 0 {
        if let Ok(mut ledger) = crate::rewards::REWARD_LEDGER.lock() {
            let epoch_id = crate::rewards::default_reward_epoch_for_block_height(block_height);
            let _ = ledger.record_fee_charged(
                epoch_id,
                tx_id.0.clone(),
                fee_breakdown.tx_type_name.clone(),
                fee_breakdown.total_network_fee_nwei,
                block_height,
            );
        }
    }
}

/// Computes the auditable, itemized fee breakdown for a transaction.
///
/// When `applied_fee_market` is `Some` (the fee market is active at this
/// block's height), the ordinary-gas and PQ-gas execution fees are computed
/// from *actual* `gas_used` / `pq_gas_used` against the protocol
/// `base_fee_per_gas`, via `crate::gas::fee_market::calculate_execution_fee`
/// -- exactly `gas_used * base_fee_per_gas` and
/// `pq_gas_used * effective_pq_gas_price`, itemized and never combined
/// before being reported. `gas_fee_cap_nwei` (the sender's declared
/// `max_fee_nwei`) is *not* charged directly in this branch; it is only
/// enforced as an affordability ceiling by the caller
/// (`max_fee_cap_violation`), so unused gas is naturally "refunded" by
/// simply never being charged.
///
/// When `applied_fee_market` is `None` (legacy / pre-fee-market blocks),
/// behavior is preserved byte-for-byte from before this change: the
/// sender's `gas_fee_cap_nwei` is charged in full, with an implied
/// "base fee" derived only for display (`gas_fee_cap_nwei / gas_used`).
fn canonical_network_fee_breakdown(
    tx: &Transaction,
    gas_used: u64,
    pq_gas_used: u64,
    gas_fee_cap_nwei: u128,
    include_amount_fee: bool,
    applied_fee_market: Option<&crate::gas::fee_market::AppliedFeeMarket>,
) -> Result<crate::gas::NetworkFeeBreakdown, String> {
    use crate::gas::{
        calculate_network_fee, fee_schedule_for_runtime, NetworkFeeInput, ValuationStatus,
    };

    let payload = std::str::from_utf8(&tx.payload).unwrap_or_default();
    let (tx_type, asset_id, amount_raw, amount_equiv, valuation_status) =
        canonical_fee_value_context(tx, payload);
    let amount_snrgequivalent_nwei = if include_amount_fee { amount_equiv } else { 0 };
    let valuation_status = if include_amount_fee {
        valuation_status
    } else {
        ValuationStatus::NotRequired
    };

    let (
        gas_fee_nwei,
        base_fee_per_gas_nwei,
        pq_gas_multiplier,
        effective_pq_gas_price_nwei,
        pq_execution_fee_nwei,
        fee_market_active,
        fee_market_version,
    ) = match applied_fee_market {
        Some(applied) => {
            let breakdown =
                crate::gas::fee_market::calculate_execution_fee(gas_used, pq_gas_used, applied)
                    .map_err(|error| error.to_string())?;
            (
                breakdown.base_execution_fee_nwei,
                applied.base_fee_per_gas_nwei,
                applied.pq_gas_multiplier,
                applied.effective_pq_gas_price_nwei,
                breakdown.pq_execution_fee_nwei,
                true,
                applied.fee_market_version,
            )
        }
        None => {
            let derived_base_fee_per_gas = if gas_used == 0 {
                0
            } else {
                u64::try_from(gas_fee_cap_nwei / (gas_used as u128)).unwrap_or(u64::MAX)
            };
            (
                gas_fee_cap_nwei,
                derived_base_fee_per_gas,
                0u64,
                0u64,
                0u128,
                false,
                0u32,
            )
        }
    };

    calculate_network_fee(
        NetworkFeeInput {
            tx_type,
            asset_id,
            amount_raw,
            amount_snrgequivalent_nwei,
            valuation_source: valuation_status.as_str().to_string(),
            valuation_status,
            gas_used,
            base_fee_per_gas_nwei,
            gas_fee_nwei,
            storage_fee_nwei: 0,
            priority_fee_nwei: 0,
            pq_gas_used,
            pq_gas_multiplier,
            effective_pq_gas_price_nwei,
            pq_execution_fee_nwei,
            fee_market_active,
            fee_market_version,
        },
        fee_schedule_for_runtime()?,
    )
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct NativeBurnPayload {
    amount_nwei: u128,
}

fn parse_explicit_native_burn_payload(
    payload: &str,
    fallback_amount_nwei: u128,
) -> Result<Option<NativeBurnPayload>, String> {
    let Some(burn_data) = payload.strip_prefix("burn:") else {
        return Ok(None);
    };
    let burn_info: serde_json::Value = serde_json::from_str(burn_data)
        .map_err(|error| format!("INVALID_BURN_PAYLOAD: {error}"))?;
    let asset_id = burn_payload_asset(&burn_info).unwrap_or("SNRG");
    if asset_id != "SNRG" {
        return Err("NON_NATIVE_BURN_REQUIRES_TOKEN_MODULE".to_string());
    }
    let amount_nwei = burn_info
        .get("amount")
        .and_then(json_u128)
        .unwrap_or(fallback_amount_nwei);
    if amount_nwei == 0 {
        return Err("BURN_AMOUNT_MUST_BE_GREATER_THAN_ZERO".to_string());
    }
    Ok(Some(NativeBurnPayload { amount_nwei }))
}

fn burn_payload_fee_context(payload: &str, fallback_amount_nwei: u128) -> Option<(String, u128)> {
    let burn_data = payload.strip_prefix("burn:")?;
    let burn_info = serde_json::from_str::<serde_json::Value>(burn_data).ok()?;
    let asset_id = burn_payload_asset(&burn_info).unwrap_or("SNRG").to_string();
    let amount_nwei = burn_info
        .get("amount")
        .and_then(json_u128)
        .unwrap_or(fallback_amount_nwei);
    Some((asset_id, amount_nwei))
}

fn burn_payload_asset(value: &serde_json::Value) -> Option<&str> {
    value
        .get("asset")
        .or_else(|| value.get("asset_id"))
        .or_else(|| value.get("token"))
        .and_then(|asset| asset.as_str())
}

fn json_u128(value: &serde_json::Value) -> Option<u128> {
    if let Some(number) = value.as_u64() {
        return Some(number as u128);
    }
    value.as_str().and_then(|text| text.parse::<u128>().ok())
}

fn canonical_fee_value_context(
    tx: &Transaction,
    payload: &str,
) -> (
    crate::gas::TransactionFeeType,
    String,
    u128,
    u128,
    crate::gas::ValuationStatus,
) {
    use crate::gas::{TransactionFeeType, ValuationStatus};

    if crate::address::is_network_burn_address(&tx.receiver_uma_or_account)
        || payload.starts_with("burn:")
    {
        let (asset_id, amount_nwei) = burn_payload_fee_context(payload, tx.amount_nwei)
            .unwrap_or_else(|| ("SNRG".to_string(), tx.amount_nwei));
        let (amount_snrgequivalent_nwei, valuation_status) = if asset_id == "SNRG" {
            (amount_nwei, ValuationStatus::NativeSnrg)
        } else {
            (0, ValuationStatus::Unavailable)
        };
        return (
            TransactionFeeType::Burn,
            asset_id,
            amount_nwei,
            amount_snrgequivalent_nwei,
            valuation_status,
        );
    }
    if payload.starts_with("token_transfer:") {
        return (
            TransactionFeeType::TokenSend,
            "UNKNOWN".to_string(),
            tx.amount_nwei,
            0,
            ValuationStatus::Unavailable,
        );
    }
    if payload.starts_with("stake:") {
        return (
            TransactionFeeType::Stake,
            "SNRG".to_string(),
            tx.amount_nwei,
            tx.amount_nwei,
            ValuationStatus::NotRequired,
        );
    }
    if payload.starts_with("unstake:") || payload.starts_with("withdrawal_request:") {
        return (
            TransactionFeeType::Unstake,
            "SNRG".to_string(),
            tx.amount_nwei,
            tx.amount_nwei,
            ValuationStatus::NotRequired,
        );
    }
    if payload.starts_with("swap:") {
        return (
            TransactionFeeType::Swap,
            "UNKNOWN".to_string(),
            tx.amount_nwei,
            0,
            ValuationStatus::Unavailable,
        );
    }
    if tx.receiver_uma_or_account.is_empty() || payload.starts_with("deploy:") {
        return (
            TransactionFeeType::ContractDeploy,
            "SNRG".to_string(),
            tx.amount_nwei,
            tx.amount_nwei,
            if tx.amount_nwei > 0 {
                ValuationStatus::NativeSnrg
            } else {
                ValuationStatus::NotRequired
            },
        );
    }
    if tx.amount_nwei > 0 && payload.is_empty() {
        return (
            TransactionFeeType::NativeSnrgSend,
            "SNRG".to_string(),
            tx.amount_nwei,
            tx.amount_nwei,
            ValuationStatus::NativeSnrg,
        );
    }

    (
        TransactionFeeType::ContractCall,
        "SNRG".to_string(),
        tx.amount_nwei,
        tx.amount_nwei,
        if tx.amount_nwei > 0 {
            ValuationStatus::NativeSnrg
        } else {
            ValuationStatus::NotRequired
        },
    )
}

fn current_unix_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or_default()
}

fn tx_id(tx: &Transaction) -> Result<TxId, String> {
    Ok(TxId::from_hash(Hash::from_domain_bytes(
        "SYNERGY_EXECUTION_TX_ID_V1",
        &tx.canonical_bytes()?,
    )))
}

pub fn verified_context_for_block(
    transactions: &[Transaction],
) -> Result<BTreeMap<TxId, Hash>, String> {
    let mut context = BTreeMap::new();
    let mut seen = BTreeSet::new();
    for tx in transactions {
        let id = tx_id(tx)?;
        if !seen.insert(id.clone()) {
            return Err(format!("duplicate transaction {} in block", id.0));
        }
        context.insert(id, tx.canonical_tx_bytes_hash()?);
    }
    Ok(context)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::synergy_types::{
        AegisPqKeyId, AegisPqSignature, ChainId, Epoch, Height, NetworkId, UmaId,
    };
    use crate::synq_execution::{
        derive_synq_contract_address_from_deploy, synergy_contract_address_from_pqsynq_address,
    };
    use pqsynq::{
        canonicalize_signing_payload, derive_synq_address, hash_contract_call_body,
        hash_contract_deploy_body, AlgorithmId, ChainId as PqSynQChainId, ContractCallEnvelope,
        ContractDeployEnvelope, DigitalSignature, DomainTag, NetworkId as PqSynQNetworkId, Sign,
        SignaturePurpose, SynQAddress, SynQPublicKey, SynQSignature, SynQSigningPayload,
    };
    use sha2::{Digest, Sha256};
    use std::fs;
    use std::path::PathBuf;

    fn tx(sender: &str, receiver: &str, nonce: u64, amount: u128, write: &str) -> Transaction {
        Transaction {
            version: 1,
            chain_id: ChainId::synergy_testnet_v3(),
            network_id: NetworkId::synergy_testnet_v3(),
            epoch: Epoch(0),
            sender_uma_or_account: sender.to_string(),
            receiver_uma_or_account: receiver.to_string(),
            account_nonce_or_sequence: nonce,
            amount_nwei: amount,
            gas_limit: 21_000,
            max_fee_nwei: 1,
            ttl_height: Height(100),
            explicit_dependencies: Vec::new(),
            read_set_hint: Vec::new(),
            write_set_hint: vec![write.to_string()],
            payload: Vec::new(),
            signer_uma_id: UmaId(sender.to_string()),
            aegis_pq_key_id: AegisPqKeyId("key".to_string()),
            aegis_pq_signature: AegisPqSignature {
                algorithm: "fndsa".to_string(),
                signature_bytes: vec![1, 2, 3],
            },
        }
    }

    fn block(transactions: Vec<Transaction>) -> Block {
        Block {
            header: crate::synergy_types::BlockHeader {
                version: 1,
                chain_id: ChainId::synergy_testnet_v3(),
                network_id: NetworkId::synergy_testnet_v3(),
                protocol_version: crate::synergy_types::POSY_PROTOCOL_VERSION.to_string(),
                height: Height(1),
                round: crate::synergy_types::Round(0),
                epoch: Epoch(0),
                cluster_id: crate::synergy_types::ClusterId(0),
                height_context_root: Hash::from_domain_bytes(
                    "SYNERGY_TEST_HEIGHT_CONTEXT_V1",
                    b"execution",
                ),
                parent_block_hash: Hash::zero(),
                parent_state_root: Hash::zero(),
                last_finalized_qc_hash: Hash::zero(),
                proposer_validator_id: crate::synergy_types::ValidatorId("v1".to_string()),
                proposer_uma_id: UmaId("uma-v1".to_string()),
                proposer_key_id: AegisPqKeyId("key".to_string()),
                active_validator_set_hash: Hash::zero(),
                eligible_validator_set_hash: Hash::zero(),
                validator_consensus_key_root: Hash::from_domain_bytes(
                    "SYNERGY_TEST_CONSENSUS_KEY_ROOT_V1",
                    b"execution",
                ),
                frozen_bonded_weight_root: Hash::from_domain_bytes(
                    "SYNERGY_TEST_BONDED_WEIGHT_ROOT_V1",
                    b"execution",
                ),
                cluster_schedule_version: crate::synergy_types::TESTNET_V3_CLUSTER_SCHEDULE_VERSION
                    .to_string(),
                cluster_map_hash: Hash::zero(),
                assigned_cluster_membership_root: Hash::from_domain_bytes(
                    "SYNERGY_TEST_CLUSTER_MEMBERSHIP_ROOT_V1",
                    b"execution",
                ),
                assigned_cluster_validator_count: 6,
                assigned_cluster_total_voting_weight: 6,
                proposer_schedule_hash: Hash::zero(),
                protocol_config_hash: crate::consensus_parameters::ConsensusParameterRoot::zero(),
                cryptographic_profile_root: Hash::from_domain_bytes(
                    "SYNERGY_TEST_CRYPTOGRAPHIC_PROFILE_V1",
                    b"execution",
                ),
                dag_frontier_root: Hash::zero(),
                tx_order_root: Hash::zero(),
                tx_count: transactions.len() as u64,
                protected_batch: None,
                evidence_root: Hash::zero(),
                state_root_before: Hash::zero(),
                state_root_after: Hash::zero(),
                receipt_root: Hash::zero(),
                app_version: 1,
                execution_version: 1,
                dag_version: 1,
                aegis_pqvm_version: "aegis-pqvm".to_string(),
                timestamp_ms_consensus_bounded: 0,
                base_fee_per_gas_nwei: 0,
                gas_used: 0,
                gas_limit: 0,
                pq_gas_used: 0,
                pq_gas_limit: 0,
                pq_gas_multiplier: 0,
                fee_market_version: 0,
            },
            transactions,
            proposer_signature: AegisPqSignature {
                algorithm: "fndsa".to_string(),
                signature_bytes: vec![1],
            },
        }
    }

    fn authorized_state(transactions: &[Transaction]) -> ExecutionState {
        let mut state = ExecutionState::new()
            .with_balance("alice", 1_000_000)
            .with_balance("bob", 1_000_000)
            .with_balance("carol", 0)
            .with_balance("dave", 0);
        state.verified_authorizations = verified_context_for_block(transactions).unwrap();
        state
    }

    fn reward_ledger_test_scope() -> std::sync::MutexGuard<'static, ()> {
        let guard = crate::rewards::reward_ledger_test_guard();
        crate::rewards::reset_reward_ledger_for_test();
        guard
    }

    #[derive(Clone)]
    struct CounterSynQFixture {
        public_key: SynQPublicKey,
        private_key: Vec<u8>,
        address: SynQAddress,
        bytecode: Vec<u8>,
        abi_json: String,
        manifest_json: String,
        bytecode_hash: [u8; 32],
        manifest_hash: [u8; 32],
        abi_hash: [u8; 32],
    }

    impl CounterSynQFixture {
        fn new() -> Option<Self> {
            let signer = Sign::mldsa87();
            let (public_key_bytes, private_key) = signer.keygen().expect("ML-DSA-87 keygen");
            let public_key = SynQPublicKey::new(public_key_bytes);
            let address = derive_synq_address(
                &public_key,
                AlgorithmId::MlDsa87,
                &PqSynQNetworkId(
                    crate::synq_admission::SYNQ_CANONICAL_TESTNET_NETWORK_ID.to_string(),
                ),
            )
            .expect("derive SynQ address");

            let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../../../Volumes/xcode/Synergy-Network-Projects/synq-language/contracts");
            let root = if root.exists() {
                root
            } else {
                PathBuf::from("/Volumes/xcode/Synergy-Network-Projects/synq-language/contracts")
            };
            if !root.join("Counter.compiled.synq").exists()
                || !root.join("Counter.abi.json").exists()
                || !root.join("Counter.manifest.json").exists()
            {
                return None;
            }
            let bytecode = fs::read(root.join("Counter.compiled.synq")).expect("Counter bytecode");
            let abi_json = fs::read_to_string(root.join("Counter.abi.json")).expect("Counter ABI");
            let manifest_json =
                fs::read_to_string(root.join("Counter.manifest.json")).expect("Counter manifest");
            let bytecode_hash = sha256_array(&bytecode);
            let manifest_hash = sha256_array(manifest_json.as_bytes());
            let abi_hash = sha256_array(abi_json.as_bytes());

            Some(Self {
                public_key,
                private_key,
                address,
                bytecode,
                abi_json,
                manifest_json,
                bytecode_hash,
                manifest_hash,
                abi_hash,
            })
        }

        fn deploy_envelope(&self) -> ContractDeployEnvelope {
            let constructor_args_hash = sha256_array(&[]);
            let payload_hash = hash_contract_deploy_body(
                &self.bytecode_hash,
                &self.manifest_hash,
                &self.abi_hash,
                self.address.as_bytes(),
                &constructor_args_hash,
            );
            let signing_payload = self.signing_payload(
                DomainTag::SynqContractDeployV1,
                SignaturePurpose::ContractDeploy,
                payload_hash,
                101,
            );
            let signature = self.sign_payload(&signing_payload);
            ContractDeployEnvelope {
                signing_payload,
                public_key: self.public_key.clone(),
                signature: SynQSignature::new(signature),
                bytecode_hash: self.bytecode_hash,
                manifest_hash: self.manifest_hash,
                abi_hash: self.abi_hash,
                constructor_args_hash,
            }
        }

        fn contract_address(&self) -> SynQAddress {
            derive_synq_contract_address_from_deploy(&self.deploy_envelope())
                .expect("derive SynQ contract address")
        }

        fn deploy_payload(&self, include_artifacts: bool) -> Vec<u8> {
            let deploy = self.deploy_envelope();
            let pqsynq_bytes = serde_json::to_vec(&deploy).expect("deploy JSON");
            if include_artifacts {
                crate::synq_admission::build_deploy_admission_carrier_from_pqsynq_bytes_with_artifacts(
                    crate::synergy_types::SYNERGY_TESTNET_V3_CHAIN_ID,
                    crate::synergy_types::SYNERGY_TESTNET_V3_NETWORK_ID,
                    &pqsynq_bytes,
                    self.bytecode.clone(),
                    self.abi_json.clone(),
                    self.manifest_json.clone(),
                    crate::synq_admission::test_support::TEST_NOW,
                )
                .expect("deploy carrier with artifacts")
            } else {
                crate::synq_admission::build_deploy_admission_carrier_from_pqsynq_bytes(
                    crate::synergy_types::SYNERGY_TESTNET_V3_CHAIN_ID,
                    crate::synergy_types::SYNERGY_TESTNET_V3_NETWORK_ID,
                    &pqsynq_bytes,
                    crate::synq_admission::test_support::TEST_NOW,
                )
                .expect("deploy carrier")
            }
        }

        fn call_payload(
            &self,
            contract_address: SynQAddress,
            method_selector: [u8; 4],
            nonce: u64,
        ) -> Vec<u8> {
            let encoded_args_hash = sha256_array(&[]);
            let payload_hash = hash_contract_call_body(
                contract_address.as_bytes(),
                &method_selector,
                &encoded_args_hash,
                self.address.as_bytes(),
            );
            let signing_payload = self.signing_payload(
                DomainTag::SynqContractCallV1,
                SignaturePurpose::ContractCall,
                payload_hash,
                nonce,
            );
            let signature = self.sign_payload(&signing_payload);
            let call = ContractCallEnvelope {
                signing_payload,
                public_key: self.public_key.clone(),
                signature: SynQSignature::new(signature),
                contract_address,
                method_selector,
                encoded_args_hash,
            };
            crate::synq_admission::build_call_admission_carrier_from_pqsynq_bytes(
                crate::synergy_types::SYNERGY_TESTNET_V3_CHAIN_ID,
                crate::synergy_types::SYNERGY_TESTNET_V3_NETWORK_ID,
                &serde_json::to_vec(&call).expect("call JSON"),
                crate::synq_admission::test_support::TEST_NOW,
            )
            .expect("call carrier")
        }

        fn signing_payload(
            &self,
            domain_tag: DomainTag,
            signature_purpose: SignaturePurpose,
            payload_hash: [u8; 32],
            nonce: u64,
        ) -> SynQSigningPayload {
            SynQSigningPayload {
                domain_tag,
                chain_id: PqSynQChainId(crate::synergy_types::SYNERGY_TESTNET_V3_CHAIN_ID),
                network_id: PqSynQNetworkId(
                    crate::synq_admission::SYNQ_CANONICAL_TESTNET_NETWORK_ID.to_string(),
                ),
                protocol_version: 1,
                algorithm_id: AlgorithmId::MlDsa87,
                signature_purpose,
                nonce,
                not_before_unix: 0,
                expiration_unix: 4_102_444_800,
                signer_address: self.address,
                payload_hash,
            }
        }

        fn sign_payload(&self, payload: &SynQSigningPayload) -> Vec<u8> {
            let canonical = canonicalize_signing_payload(payload).expect("canonical payload");
            Sign::mldsa87()
                .detached_sign(&canonical, &self.private_key)
                .expect("ML-DSA-65 sign")
        }
    }

    fn synq_tx(payload: Vec<u8>, nonce: u64, gas_limit: u64, write: &str) -> Transaction {
        let mut transaction = tx("alice", "carol", nonce, 0, write);
        transaction.payload = payload;
        transaction.gas_limit = gas_limit;
        transaction
    }

    fn run_counter_flow(
        deploy_payload: Vec<u8>,
        increment_payload: Vec<u8>,
        get_payload: Vec<u8>,
        expected_contract_address: &str,
    ) -> (Hash, String, String, String, u64) {
        let _ledger_guard = reward_ledger_test_scope();
        let mut state = ExecutionState::new()
            .with_balance("alice", 1_000_000)
            .with_balance("carol", 0);

        let deploy = synq_tx(deploy_payload, 0, 150_000, "synq-counter");
        state.mark_authorized(&deploy).expect("deploy authorized");
        let deploy_result = execute_block(&block(vec![deploy]), &state).expect("deploy executes");
        let deploy_receipt = deploy_result.receipts.first().expect("deploy receipt");
        assert_eq!(deploy_receipt.status, ReceiptStatus::Success);
        let deploy_aivm = deploy_receipt
            .synq_aivm
            .as_ref()
            .expect("deploy AIVM receipt");
        assert_eq!(deploy_aivm.contract_address, expected_contract_address);
        let deploy_hash = deploy_aivm.receipt_hash.clone();

        let mut state = deploy_result.state;
        let increment = synq_tx(increment_payload, 1, 30_000, "synq-counter");
        state
            .mark_authorized(&increment)
            .expect("increment authorized");
        let increment_result =
            execute_block(&block(vec![increment]), &state).expect("increment executes");
        let increment_receipt = increment_result
            .receipts
            .first()
            .expect("increment receipt");
        assert_eq!(increment_receipt.status, ReceiptStatus::Success);
        let increment_aivm = increment_receipt
            .synq_aivm
            .as_ref()
            .expect("increment AIVM receipt");
        assert_eq!(decode_u256_hex(&increment_aivm.return_data_hex), 1);
        let increment_hash = increment_aivm.receipt_hash.clone();

        let mut state = increment_result.state;
        let get = synq_tx(get_payload, 2, 30_000, "synq-counter");
        state.mark_authorized(&get).expect("get authorized");
        let get_result = execute_block(&block(vec![get]), &state).expect("get executes");
        let get_receipt = get_result.receipts.first().expect("get receipt");
        assert_eq!(get_receipt.status, ReceiptStatus::Success);
        let get_aivm = get_receipt.synq_aivm.as_ref().expect("get AIVM receipt");
        let get_value = decode_u256_hex(&get_aivm.return_data_hex);

        (
            get_result.state_root_after,
            deploy_hash,
            increment_hash,
            get_aivm.receipt_hash.clone(),
            get_value,
        )
    }

    fn decode_u256_hex(value: &str) -> u64 {
        let bytes = hex::decode(value).expect("return data hex");
        assert_eq!(bytes.len(), 32);
        u64::from_be_bytes(bytes[24..32].try_into().expect("u64 tail"))
    }

    fn sha256_array(bytes: &[u8]) -> [u8; 32] {
        let digest = Sha256::digest(bytes);
        let mut out = [0_u8; 32];
        out.copy_from_slice(&digest);
        out
    }

    #[test]
    fn same_block_executed_repeatedly_produces_same_state_root() {
        let _ledger_guard = reward_ledger_test_scope();
        let transactions = vec![
            tx("alice", "carol", 0, 10, "alice"),
            tx("bob", "dave", 0, 20, "bob"),
        ];
        let block = block(transactions.clone());
        let state = authorized_state(&transactions);
        let first = execute_block(&block, &state).unwrap().state_root_after;
        for _ in 0..100 {
            assert_eq!(
                execute_block(&block, &state).unwrap().state_root_after,
                first
            );
        }
    }

    #[test]
    fn failed_receipt_is_deterministic_and_conflicts_execute_in_order() {
        let _ledger_guard = reward_ledger_test_scope();
        let transactions = vec![
            tx("alice", "carol", 0, 10, "alice"),
            tx("alice", "dave", 1, 2_000_000, "alice"),
        ];
        let block = block(transactions.clone());
        let state = authorized_state(&transactions);
        let a = execute_block(&block, &state).unwrap();
        let b = execute_block(&block, &state).unwrap();
        assert_eq!(a.receipts, b.receipts);
        assert!(a
            .receipts
            .iter()
            .any(|receipt| receipt.status == ReceiptStatus::Failed));
    }

    #[test]
    fn receipt_preserves_synq_verification_summary() {
        let _ledger_guard = reward_ledger_test_scope();
        let transaction = tx("alice", "carol", 0, 10, "synq-contract");
        let id = tx_id(&transaction).unwrap();
        let block = block(vec![transaction.clone()]);
        let mut state = authorized_state(&[transaction]);
        state.synq_verifications.insert(
            id,
            crate::synq_admission::SynQVerificationSummary {
                chain_id: crate::synergy_types::SYNERGY_TESTNET_V3_CHAIN_ID,
                normalized_network_id: "synergy-testnet".to_string(),
                node_network_id: crate::synergy_types::SYNERGY_TESTNET_V3_NETWORK_ID.to_string(),
                domain: "SYNQ_CONTRACT_DEPLOY_V1".to_string(),
                algorithm: "ML-DSA-87".to_string(),
                signer: "syna1fixture".to_string(),
                identity_authorization_payload_sha3_256: None,
                payload_hash: [7; 32],
                bytecode_hash: Some([1; 32]),
                manifest_hash: Some([2; 32]),
                abi_hash: Some([3; 32]),
                verified_at_admission: true,
            },
        );

        let result = execute_block(&block, &state).unwrap();
        let receipt = result.receipts.first().expect("receipt");
        assert_eq!(
            receipt
                .synq_verification
                .as_ref()
                .map(|summary| summary.domain.as_str()),
            Some("SYNQ_CONTRACT_DEPLOY_V1")
        );
    }

    #[test]
    fn synq_deploy_carrier_reaches_receipt_through_node_admission() {
        let _ledger_guard = reward_ledger_test_scope();
        let carrier = crate::synq_admission::test_support::deploy_carrier(
            crate::synergy_types::SYNERGY_TESTNET_V3_NETWORK_ID,
        );
        let mut transaction = tx("alice", "carol", 0, 10, "synq-contract");
        transaction.payload = crate::synq_admission::encode_synq_admission_carrier(&carrier)
            .expect("encode SynQ admission carrier");
        transaction.gas_limit = 150_000;

        let block = block(vec![transaction.clone()]);
        let mut state = ExecutionState::new()
            .with_balance("alice", 1_000_000)
            .with_balance("carol", 0);
        state
            .mark_authorized(&transaction)
            .expect("SynQ carrier admitted by node authorization path");

        let result = execute_block(&block, &state).expect("authorized block executes");
        let receipt = result.receipts.first().expect("receipt");
        let summary = receipt
            .synq_verification
            .as_ref()
            .expect("receipt includes SynQ verification summary");
        assert_eq!(summary.domain, "SYNQ_CONTRACT_DEPLOY_V1");
        assert_eq!(summary.algorithm, "ML-DSA-87");
        assert_eq!(summary.signer, carrier.signer);
        assert_eq!(summary.payload_hash, carrier.payload_hash);
        assert_eq!(summary.bytecode_hash, carrier.bytecode_hash);
        assert!(summary.verified_at_admission);
    }

    #[test]
    fn synq_counter_deploy_increment_get_execute_through_aivm_and_replay() {
        let Some(fixture) = CounterSynQFixture::new() else {
            eprintln!("skipping SynQ Counter fixture test; contract artifacts are missing");
            return;
        };
        let deploy_payload = fixture.deploy_payload(true);
        let contract_address = fixture.contract_address();
        let contract_address_text = synergy_contract_address_from_pqsynq_address(&contract_address);
        assert_ne!(
            contract_address_text,
            crate::address::derive_standard_account_address(&fixture.public_key.bytes)
                .expect("fixture FN-DSA public key derives a canonical account address")
        );
        let increment_payload = fixture.call_payload(
            contract_address,
            aivm_core::synq_runtime::COUNTER_INCREMENT_SELECTOR,
            102,
        );
        let get_payload = fixture.call_payload(
            contract_address,
            aivm_core::synq_runtime::COUNTER_GET_SELECTOR,
            103,
        );

        let first = run_counter_flow(
            deploy_payload.clone(),
            increment_payload.clone(),
            get_payload.clone(),
            &contract_address_text,
        );
        let replay = run_counter_flow(
            deploy_payload,
            increment_payload,
            get_payload,
            &contract_address_text,
        );

        assert_eq!(first, replay);
        assert_eq!(first.4, 1);
    }

    #[test]
    fn synq_hash_only_deploy_fails_closed_before_aivm_execution() {
        let Some(fixture) = CounterSynQFixture::new() else {
            eprintln!("skipping SynQ Counter fixture test; contract artifacts are missing");
            return;
        };
        let _ledger_guard = reward_ledger_test_scope();
        let deploy = synq_tx(fixture.deploy_payload(false), 0, 150_000, "synq-counter");
        let mut state = ExecutionState::new()
            .with_balance("alice", 1_000_000)
            .with_balance("carol", 0);
        state.mark_authorized(&deploy).expect("deploy authorized");

        let result = execute_block(&block(vec![deploy]), &state).expect("block executes");
        let receipt = result.receipts.first().expect("receipt");
        assert_eq!(receipt.status, ReceiptStatus::Failed);
        let aivm = receipt
            .synq_aivm
            .as_ref()
            .expect("failure includes AIVM summary");
        assert_eq!(aivm.operation, "deploy");
        assert_eq!(aivm.status, "failed");
        assert_eq!(aivm.error_code.as_deref(), Some("SYNQ-AIVM-ARTIFACT"));
        assert!(result.state.synq_contracts.is_empty());
    }

    #[test]
    fn synq_bad_call_selector_rolls_back_aivm_state() {
        let Some(fixture) = CounterSynQFixture::new() else {
            eprintln!("skipping SynQ Counter fixture test; contract artifacts are missing");
            return;
        };
        let _ledger_guard = reward_ledger_test_scope();
        let deploy = synq_tx(fixture.deploy_payload(true), 0, 150_000, "synq-counter");
        let contract_address = fixture.contract_address();
        let mut state = ExecutionState::new()
            .with_balance("alice", 1_000_000)
            .with_balance("carol", 0);
        state.mark_authorized(&deploy).expect("deploy authorized");
        let deploy_result = execute_block(&block(vec![deploy]), &state).expect("deploy executes");
        assert_eq!(
            deploy_result.receipts.first().expect("receipt").status,
            ReceiptStatus::Success
        );

        let mut state = deploy_result.state;
        let state_root_before = compute_state_root_after(&state).expect("state root");
        let aivm_state_root_before = state.synq_aivm_state.state_root();
        let bad_call = synq_tx(
            fixture.call_payload(contract_address, [0, 0, 0, 0], 104),
            1,
            30_000,
            "synq-counter",
        );
        state
            .mark_authorized(&bad_call)
            .expect("bad call authorized");

        let result = execute_block(&block(vec![bad_call]), &state).expect("bad call executes");
        let receipt = result.receipts.first().expect("receipt");
        assert_eq!(receipt.status, ReceiptStatus::Failed);
        let aivm = receipt
            .synq_aivm
            .as_ref()
            .expect("failure includes AIVM summary");
        assert_eq!(aivm.operation, "call");
        assert_eq!(aivm.status, "failed");
        assert_eq!(aivm.error_code.as_deref(), Some("Abi"));
        assert_eq!(
            result.state.synq_aivm_state.state_root(),
            aivm_state_root_before
        );
        assert_ne!(result.state_root_after, state_root_before);
        assert_eq!(result.state.fee_events.len(), state.fee_events.len() + 1);
    }

    #[test]
    fn native_value_execution_credits_fee_collector_with_total_network_fee() {
        let _ledger_guard = reward_ledger_test_scope();
        let mut transaction = tx("alice", "carol", 0, 1_000_000_000, "alice");
        transaction.max_fee_nwei = 1_000;
        let block = block(vec![transaction.clone()]);
        let mut state = ExecutionState::new()
            .with_balance("alice", 2_000_000_000)
            .with_balance("carol", 0);
        state
            .mark_authorized(&transaction)
            .expect("transaction authorized");

        let result = execute_block(&block, &state).expect("block executes");
        let receipt = result.receipts.first().expect("receipt");
        let fee_breakdown = receipt.fee_breakdown.as_ref().expect("fee breakdown");

        assert_eq!(receipt.status, ReceiptStatus::Success);
        assert_eq!(fee_breakdown.gas_fee_nwei, 1_000);
        assert_eq!(fee_breakdown.amount_protocol_fee_nwei, 200_000);
        assert_eq!(fee_breakdown.total_network_fee_nwei, 201_000);
        assert_eq!(
            result.state.balances_nwei.get("alice").copied(),
            Some(999_799_000)
        );
        assert_eq!(
            result
                .state
                .balances_nwei
                .get(crate::token::FEE_COLLECTOR_ADDRESS)
                .copied(),
            Some(201_000)
        );
        assert_eq!(result.state.fee_events.len(), 1);
    }

    #[test]
    fn transfer_to_network_burn_address_records_non_supply_reducing_event() {
        let _ledger_guard = reward_ledger_test_scope();
        let mut transaction = tx(
            "alice",
            crate::address::NETWORK_BURN_ADDRESS,
            0,
            1_000_000_000,
            "alice",
        );
        transaction.max_fee_nwei = 1_000;
        let block = block(vec![transaction.clone()]);
        let mut state = ExecutionState::new().with_balance("alice", 2_000_000_000);
        state
            .mark_authorized(&transaction)
            .expect("transaction authorized");

        let result = execute_block(&block, &state).expect("block executes");

        assert_eq!(result.receipts[0].status, ReceiptStatus::Success);
        assert_eq!(result.state.burn_events.len(), 1);
        assert_eq!(
            result.state.burn_events[0].to,
            crate::address::NETWORK_BURN_ADDRESS
        );
        assert!(!result.state.burn_events[0].supply_reduced);
        assert_eq!(
            result
                .state
                .balances_nwei
                .get(crate::address::NETWORK_BURN_ADDRESS)
                .copied(),
            Some(1_000_000_000)
        );
    }

    #[test]
    fn explicit_native_burn_reduces_supply_and_charges_total_network_fee() {
        let _ledger_guard = reward_ledger_test_scope();
        let mut transaction = tx("alice", "", 0, 0, "alice");
        transaction.payload = br#"burn:{"asset":"SNRG","amount":"1000000000"}"#.to_vec();
        transaction.max_fee_nwei = 1_000;
        let block = block(vec![transaction.clone()]);
        let mut state = ExecutionState::new().with_balance("alice", 2_000_000_000);
        state
            .mark_authorized(&transaction)
            .expect("transaction authorized");

        let result = execute_block(&block, &state).expect("block executes");
        let receipt = result.receipts.first().expect("receipt");
        let fee_breakdown = receipt.fee_breakdown.as_ref().expect("fee breakdown");

        assert_eq!(receipt.status, ReceiptStatus::Success);
        assert_eq!(fee_breakdown.tx_type, crate::gas::TransactionFeeType::Burn);
        assert_eq!(fee_breakdown.amount_protocol_fee_nwei, 100_000);
        assert_eq!(fee_breakdown.total_network_fee_nwei, 101_000);
        assert_eq!(
            result.state.balances_nwei.get("alice").copied(),
            Some(999_899_000)
        );
        assert_eq!(
            result
                .state
                .balances_nwei
                .get(crate::token::FEE_COLLECTOR_ADDRESS)
                .copied(),
            Some(101_000)
        );
        assert_eq!(
            result
                .state
                .balances_nwei
                .get(crate::address::NETWORK_BURN_ADDRESS)
                .copied(),
            None
        );
        assert_eq!(result.state.burn_events.len(), 1);
        assert_eq!(result.state.burn_events[0].amount_nwei, 1_000_000_000);
        assert!(result.state.burn_events[0].supply_reduced);
    }

    #[test]
    fn missing_or_altered_authorization_context_fails_closed() {
        let _ledger_guard = reward_ledger_test_scope();
        let mut transaction = tx("alice", "carol", 0, 10, "alice");
        let original_block = block(vec![transaction.clone()]);
        let state = ExecutionState::new().with_balance("alice", 100);
        assert!(execute_block(&original_block, &state).is_err());

        let mut state = authorized_state(&[transaction.clone()]);
        transaction.amount_nwei = 11;
        let altered = block(vec![transaction]);
        assert!(execute_block(&altered, &state).is_err());
        state.verified_authorizations.clear();
        assert!(execute_block(&altered, &state).is_err());
    }

    #[test]
    fn testnet_v3_genesis_snapshot_round_trips_all_root_bearing_state() {
        let mut state = ExecutionState::new()
            .with_balance("genesis-account-a", 11)
            .with_balance("genesis-account-b", 22);
        let artifact = SynQContractArtifact::new(
            vec![0x53, 0x59, 0x4e, 0x51],
            "{}".to_string(),
            "{}".to_string(),
        );
        state.synq_artifacts.insert(artifact.key(), artifact);
        let expected_root = compute_state_root_after(&state).expect("state root");
        let snapshot =
            GenesisExecutionSnapshot::capture_testnet_v3(&state).expect("capture snapshot");
        let encoded = serde_json::to_vec(&snapshot).expect("snapshot must be JSON serializable");
        let decoded: GenesisExecutionSnapshot =
            serde_json::from_slice(&encoded).expect("snapshot must decode from JSON");
        let restored = decoded.restore_testnet_v3().expect("restore snapshot");

        assert_eq!(
            compute_state_root_after(&restored).expect("restored state root"),
            expected_root
        );
        assert!(restored.verified_authorizations.is_empty());
        assert!(restored.synq_verifications.is_empty());
        assert!(restored.synq_errors.is_empty());
    }

    #[test]
    fn testnet_v3_genesis_snapshot_rejects_root_bearing_tampering() {
        let state = ExecutionState::new().with_balance("genesis-account", 11);
        let mut snapshot =
            GenesisExecutionSnapshot::capture_testnet_v3(&state).expect("capture snapshot");
        snapshot
            .balances_nwei
            .insert("genesis-account".to_string(), 12);

        assert!(snapshot.restore_testnet_v3().is_err());
    }
}
