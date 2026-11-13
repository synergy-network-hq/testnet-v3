use std::collections::{BTreeSet, VecDeque};
use std::fs;
use std::io::{ErrorKind, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use serde::de::DeserializeOwned;
use serde_json::{json, Value};
use sha1::{Digest, Sha1};
use synergy_config::RpcConfiguration;
use synergy_execution::{BudgetedCandidateStore, BudgetedExecutionCandidate as ExecutionCandidate};
use synergy_node_core::{
    CancellationToken, Criticality, ManagedService, RestartPolicy, RuntimeView, ServiceHealth,
    ServiceId, ServiceReadiness, ServiceSpec,
};
use synergy_posy::persistence::FinalityStore;
use synergy_posy::FinalizedBlockRecord;
use synergy_rpc::{
    auth::PublicOnlyAuthenticator,
    methods::{
        AccountQuery, BlockQuery, TransactionQuery, ACCOUNT_GET, BLOCK_GET, CHAIN_STATUS,
        CHAIN_TELEMETRY, ETDAG_STATUS, NODE_STATUS, POSY_STATUS, PROCESSING_CONTEXT_V1,
        PROCESSING_TRANSACTION_SUBMIT_V1, PROTECTED_ADMISSION_CONTEXT,
        PROTECTED_ADMISSION_CONTEXT_V2, PROTECTED_ADMISSION_RECEIPT, PROTECTED_ADMISSION_STATS,
        PROTECTED_TRANSACTION_SUBMIT, SYNC_STATUS, SYNID_RESOLVE, SYNID_REVERSE, SYSTEM_VERSION,
        TRANSACTION_GET,
    },
    middleware::RpcLimits,
    provider::{
        CanonicalReadProvider, FinalizedAccountView, FinalizedBlockView, FinalizedTransactionView,
    },
    rate_limit::{RateLimit, RpcRateLimiter},
    server::RpcServer,
    RpcDispatcher, RpcError,
};
use synergy_state::world_resources::WorldResourceBudget;
use synergy_state::FinalizedStateStore;
use synergy_storage::NodeStorageLayout;
use synergy_transaction::ReceiptStatus;
use synergy_ws::{server::WsServer, WsTopic};

/// Reads only the durable records jointly owned by execution, PoSy finality,
/// and finalized state. Every public result is re-bound across all three
/// owners; a speculative execution candidate is never exposed as finalized.
pub(crate) struct CanonicalQueryStore {
    layout: NodeStorageLayout,
    candidates: Mutex<BudgetedCandidateStore>,
    world_budget: Arc<WorldResourceBudget>,
}

impl CanonicalQueryStore {
    #[cfg(test)]
    pub(crate) fn load(data_directory: impl Into<PathBuf>) -> Result<Self, String> {
        Self::load_with_world_budget(
            data_directory,
            WorldResourceBudget::new(synergy_config::default_world_memory_budget_bytes()),
        )
    }

    pub(crate) fn load_with_world_budget(
        data_directory: impl Into<PathBuf>,
        world_budget: Arc<WorldResourceBudget>,
    ) -> Result<Self, String> {
        let layout = NodeStorageLayout::new(data_directory.into())
            .map_err(|error| format!("construct canonical storage layout: {error}"))?;
        let candidates = BudgetedCandidateStore::new_budgeted(
            layout.blocks().join("execution-candidates"),
            Arc::clone(&world_budget),
        )
        .map_err(|error| format!("open canonical RPC candidate store: {error}"))?;
        Ok(Self {
            layout,
            candidates: Mutex::new(candidates),
            world_budget,
        })
    }

    fn state_store(&self) -> Result<FinalizedStateStore, RpcError> {
        FinalizedStateStore::load_budgeted(
            self.layout.state().join("execution"),
            Arc::clone(&self.world_budget),
        )
        .map_err(|error| RpcError::unavailable(format!("open finalized state: {error:?}")))
    }

    fn finality_store(&self) -> Result<FinalityStore, RpcError> {
        FinalityStore::new(self.layout.consensus().join("posy"))
            .map_err(|error| RpcError::unavailable(format!("open PoSy finality: {error}")))
    }

    // Commitments attest finalized block identity, not archived world availability.
    // Account, block and recovery paths retain their full-world validation.
    fn finalized_commitment_at(
        &self,
        height: u64,
    ) -> Result<Option<(synergy_execution::CandidateCommitment, String)>, RpcError> {
        let state = self.state_store()?;
        let commitment = match state
            .history_at(height)
            .map_err(|e| RpcError::unavailable(format!("read finalized history: {e:?}")))?
        {
            Some(value) => value,
            None => match state.current() {
                Some(value) if value.finalized_height == height => value.clone(),
                _ => return Ok(None),
            },
        };
        let finality = self
            .finality_store()?
            .get(height)
            .map_err(|e| RpcError::unavailable(format!("read PoSy finality: {e}")))?
            .ok_or_else(|| {
                RpcError::unavailable("finalized state lacks canonical PoSy finality")
            })?;
        let candidate = self
            .candidates
            .lock()
            .map_err(|_| RpcError::unavailable("canonical candidate store lock poisoned"))?
            .commitment(height)
            .map_err(|e| RpcError::unavailable(format!("read candidate commitment: {e}")))?;
        let candidate = match candidate {
            Some(candidate) => candidate,
            None if self.finalized_history_was_retired(height)? => return Ok(None),
            None => {
                return Err(RpcError::unavailable(
                    "finalized state lacks canonical candidate metadata",
                ))
            }
        };
        if commitment.finalized_block_id != finality.block_id
            || commitment.finalized_block_id != candidate.block_id
            || commitment.state_root != candidate.state_root
            || finality.protected_execution_root != candidate.protected_execution_root
        {
            return Err(RpcError::unavailable(
                "canonical block, finality, and state commitments disagree",
            ));
        }
        Ok(Some((candidate, finality.finality_certificate_id)))
    }

    // Execution retires finalized history before candidate history under their
    // separate storage locks. An RPC may have captured the old commitment just
    // before that retirement. Re-read durable state only on a missing candidate;
    // absence at a still-retained/current height remains an integrity failure.
    fn finalized_history_was_retired(&self, height: u64) -> Result<bool, RpcError> {
        let state = self.state_store()?;
        Ok(state
            .current()
            .is_some_and(|tip| tip.finalized_height > height)
            && state
                .history_at(height)
                .map_err(|error| {
                    RpcError::unavailable(format!("recheck retired finalized history: {error:?}"))
                })?
                .is_none())
    }

    fn candidate_at(&self, height: u64) -> Result<Option<ExecutionCandidate>, RpcError> {
        let Some(candidate) = self
            .candidates
            .lock()
            .map_err(|_| RpcError::unavailable("canonical candidate store lock poisoned"))?
            .get_budgeted(height)
            .map_err(|error| RpcError::unavailable(format!("read execution candidate: {error}")))?
        else {
            return Ok(None);
        };
        for (transaction, receipt) in candidate.transactions.iter().zip(&candidate.receipts) {
            let transaction_id = transaction
                .id()
                .map_err(|error| RpcError::unavailable(format!("verify transaction: {error:?}")))?;
            if receipt.transaction_id != transaction_id || !receipt.validate() {
                return Err(RpcError::unavailable(
                    "execution candidate contains an invalid transaction receipt",
                ));
            }
        }
        Ok(Some(candidate))
    }

    fn candidate_heights(&self) -> Result<Vec<u64>, RpcError> {
        let directory = self
            .layout
            .blocks()
            .join("execution-candidates")
            .join("candidate");
        let entries = match fs::read_dir(&directory) {
            Ok(entries) => entries,
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => {
                return Err(RpcError::unavailable(format!(
                    "enumerate execution candidates: {error}"
                )))
            }
        };
        let mut heights = Vec::new();
        for entry in entries {
            let entry = entry.map_err(|error| {
                RpcError::unavailable(format!("enumerate execution candidate: {error}"))
            })?;
            let file_type = entry.file_type().map_err(|error| {
                RpcError::unavailable(format!("inspect execution candidate: {error}"))
            })?;
            if !file_type.is_file() {
                continue;
            }
            let file_name = entry.file_name();
            let file_name = file_name.to_str().ok_or_else(|| {
                RpcError::unavailable("execution candidate has a non-UTF-8 file name")
            })?;
            if !file_name.ends_with(".json") {
                continue;
            }
            let height = file_name
                .strip_suffix(".json")
                .and_then(|stem| stem.parse::<u64>().ok())
                .filter(|height| *height > 0)
                .ok_or_else(|| {
                    RpcError::unavailable("execution candidate has a non-canonical file name")
                })?;
            heights.push(height);
        }
        heights.sort_unstable();
        heights.dedup();
        Ok(heights)
    }

    fn finalized_at(
        &self,
        height: u64,
    ) -> Result<Option<(ExecutionCandidate, FinalizedBlockRecord)>, RpcError> {
        self.finalized_at_with_candidate(height, || self.candidate_at(height))
    }

    fn finalized_at_with_candidate(
        &self,
        height: u64,
        read_candidate: impl FnOnce() -> Result<Option<ExecutionCandidate>, RpcError>,
    ) -> Result<Option<(ExecutionCandidate, FinalizedBlockRecord)>, RpcError> {
        let state_store = self.state_store()?;
        let commitment = match state_store
            .history_at(height)
            .map_err(|error| RpcError::unavailable(format!("read finalized history: {error:?}")))?
        {
            Some(commitment) => commitment,
            None => match state_store.current() {
                Some(current) if current.finalized_height == height => current.clone(),
                _ => return Ok(None),
            },
        };
        let finality = self
            .finality_store()?
            .get(height)
            .map_err(|error| RpcError::unavailable(format!("read PoSy finality: {error}")))?
            .ok_or_else(|| {
                RpcError::unavailable("finalized state lacks its canonical PoSy finality record")
            })?;
        let candidate = match read_candidate()? {
            Some(candidate) => candidate,
            None if self.finalized_history_was_retired(height)? => return Ok(None),
            None => {
                return Err(RpcError::unavailable(
                    "finalized state lacks its canonical execution candidate",
                ))
            }
        };
        if commitment.finalized_block_id != finality.block_id
            || commitment.finalized_block_id != candidate.block_id
            || commitment.state_root != candidate.state_root
            || finality.protected_execution_root != candidate.protected_execution_root
        {
            return Err(RpcError::unavailable(
                "canonical block, finality, and state commitments disagree",
            ));
        }
        Ok(Some((candidate, finality)))
    }

    fn view(
        candidate: ExecutionCandidate,
        finality: FinalizedBlockRecord,
    ) -> Result<FinalizedBlockView, RpcError> {
        let transactions = candidate
            .transactions
            .iter()
            .map(serde_json::to_value)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| RpcError::unavailable(format!("encode transaction view: {error}")))?;
        let receipts = candidate
            .receipts
            .iter()
            .map(serde_json::to_value)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| RpcError::unavailable(format!("encode receipt view: {error}")))?;
        Ok(FinalizedBlockView {
            height: candidate.height,
            block_hash: candidate.block_id,
            parent_block_hash: candidate.parent_block_id,
            protected_execution_root: candidate.protected_execution_root,
            state_root: candidate.state_root,
            finality_certificate_id: finality.finality_certificate_id,
            transactions,
            receipts,
        })
    }
}

impl CanonicalReadProvider for CanonicalQueryStore {
    fn resource_observations(&self) -> Option<Value> {
        Some(json!({"scope":"shared_process_world_reservations",
            "limit_bytes":self.world_budget.limit(), "used_bytes":self.world_budget.used()}))
    }

    fn latest_finalized_height(&self) -> Result<Option<u64>, RpcError> {
        let state_store = self.state_store()?;
        let Some(height) = state_store.current().map(|state| state.finalized_height) else {
            return Ok(None);
        };
        self.finalized_at(height)?
            .ok_or_else(|| RpcError::unavailable("latest finalized data is incomplete"))?;
        Ok(Some(height))
    }

    fn block(&self, query: &BlockQuery) -> Result<Option<FinalizedBlockView>, RpcError> {
        query.validate()?;
        if let Some(height) = query.height {
            return self
                .finalized_at(height)?
                .map(|(candidate, finality)| Self::view(candidate, finality))
                .transpose();
        }
        let requested_hash = query
            .hash
            .as_deref()
            .ok_or_else(|| RpcError::invalid_params("provide exactly one block height or hash"))?;
        for height in self.candidate_heights()?.into_iter().rev() {
            // Most finalized blocks are empty. Bind their compact metadata to
            // durable state/finality before deciding whether transaction payload
            // inspection is needed; do not reconstruct a World just to discover
            // an empty transaction list. Nonempty records keep full validation.
            let Some((commitment, _)) = self.finalized_commitment_at(height)? else {
                continue;
            };
            if commitment.transaction_count == 0 {
                continue;
            }
            let Some((candidate, finality)) = self.finalized_at(height)? else {
                continue;
            };
            if candidate.block_id == requested_hash {
                return Self::view(candidate, finality).map(Some);
            }
        }
        Ok(None)
    }

    fn telemetry_commitments(
        &self,
        at_height: Option<u64>,
    ) -> Result<
        (
            Option<u64>,
            Option<synergy_rpc::provider::FinalizedBlockCommitment>,
        ),
        RpcError,
    > {
        let latest_height = self
            .state_store()?
            .current()
            .map(|state| state.finalized_height);
        let latest = latest_height
            .map(|height| self.finalized_commitment_at(height))
            .transpose()?
            .flatten();
        if latest_height.is_some() && latest.is_none() {
            return Err(RpcError::unavailable("latest finalized data is incomplete"));
        }
        let selected = match at_height {
            Some(height) if Some(height) != latest_height => {
                self.finalized_commitment_at(height)?
            }
            _ => latest,
        };
        Ok((
            latest_height,
            selected.map(|(block, finality_certificate_id)| {
                synergy_rpc::provider::FinalizedBlockCommitment {
                    height: block.height,
                    block_id: block.block_id,
                    protected_execution_root: block.protected_execution_root,
                    state_root: block.state_root,
                    finality_certificate_id,
                    transaction_count: block.transaction_count,
                }
            }),
        ))
    }

    fn transaction(
        &self,
        query: &TransactionQuery,
    ) -> Result<Option<FinalizedTransactionView>, RpcError> {
        query.validate()?;
        for height in self.candidate_heights()?.into_iter().rev() {
            // Most finalized blocks are empty. Bind their compact metadata to
            // durable state/finality before deciding whether transaction payload
            // inspection is needed; do not reconstruct a World just to discover
            // an empty transaction list. Nonempty records keep full validation.
            let Some((commitment, _)) = self.finalized_commitment_at(height)? else {
                continue;
            };
            if commitment.transaction_count == 0 {
                continue;
            }
            let Some((candidate, finality)) = self.finalized_at(height)? else {
                continue;
            };
            for (transaction, receipt) in candidate.transactions.iter().zip(&candidate.receipts) {
                let transaction_id = transaction.id().map_err(|error| {
                    RpcError::unavailable(format!("derive transaction id: {error:?}"))
                })?;
                if transaction_id.0 != query.transaction_id {
                    continue;
                }
                let status = match receipt.status {
                    ReceiptStatus::Applied => "applied",
                    ReceiptStatus::Reverted => "reverted",
                };
                return Ok(Some(FinalizedTransactionView {
                    transaction_id: transaction_id.0,
                    block_height: candidate.height,
                    block_hash: candidate.block_id,
                    finality_certificate_id: finality.finality_certificate_id,
                    status: status.into(),
                    transaction: serde_json::to_value(transaction).map_err(|error| {
                        RpcError::unavailable(format!("encode transaction view: {error}"))
                    })?,
                    receipt: serde_json::to_value(receipt).map_err(|error| {
                        RpcError::unavailable(format!("encode receipt view: {error}"))
                    })?,
                }));
            }
        }
        Ok(None)
    }

    fn wallet_syn_id(&self, value: &str, reverse: bool) -> Result<Value, RpcError> {
        if reverse {
            if value.len() > 256 || !synergy_address::is_valid_address(value) {
                return Err(RpcError::invalid_params(
                    "canonical wallet address required",
                ));
            }
        } else {
            synergy_naming::normalize_wallet_syn_id(value).map_err(RpcError::invalid_params)?;
        }
        let Some(height) = self.latest_finalized_height()? else {
            return Ok(Value::Null);
        };
        let Some((candidate, finality)) = self.finalized_at(height)? else {
            return Ok(Value::Null);
        };
        let block_hash = candidate.block_id.clone();
        let state_root = candidate.state_root.clone();
        drop(candidate);
        let store = self.state_store()?;
        let world = store
            .world_state_at_budgeted(height, &self.world_budget)
            .map_err(|e| RpcError::unavailable(format!("read finalized naming state: {e:?}")))?
            .ok_or_else(|| RpcError::unavailable("finalized commitment lacks naming state"))?;
        let bytes = world
            .protocol
            .get(synergy_naming::WALLET_PROTOCOL_STATE_KEY);
        if bytes.is_some_and(|b| b.len() > synergy_naming::MAX_WALLET_NAMING_BYTES) {
            return Err(RpcError::unavailable("wallet naming state exceeds bound"));
        }
        let _permit = self
            .world_budget
            .reserve(bytes.map_or(4096, |b| b.len().saturating_mul(64).saturating_add(4096)))
            .map_err(|e| RpcError::unavailable(e.to_string()))?;
        let registry = synergy_naming::WalletSynIdRegistry::decode(bytes.map(Vec::as_slice))
            .map_err(RpcError::unavailable)?;
        let view = |record: &synergy_naming::WalletSynIdRecord| {
            json!({
                "synId": record.syn_id, "address": record.address,
                "registered_height": record.registered_height, "finalized_height": height,
                "finalized_block_hash": block_hash, "state_root": state_root,
                "finality_certificate_id": finality.finality_certificate_id,
            })
        };
        if reverse {
            Ok(Value::Array(
                registry
                    .reverse(value)
                    .map_err(RpcError::invalid_params)?
                    .into_iter()
                    .map(view)
                    .collect(),
            ))
        } else {
            Ok(registry
                .resolve(value)
                .map_err(RpcError::invalid_params)?
                .map_or(Value::Null, view))
        }
    }

    fn account(&self, query: &AccountQuery) -> Result<Option<FinalizedAccountView>, RpcError> {
        query.validate()?;
        let height = match query.at_height {
            Some(height) => height,
            None => match self.latest_finalized_height()? {
                Some(height) => height,
                None => return Ok(None),
            },
        };
        let Some((candidate, _)) = self.finalized_at(height)? else {
            return Ok(None);
        };
        // Both archives must still validate, but their decoded Worlds need not
        // coexist. Retain only the verified commitment for the account view.
        let finalized_block_hash = candidate.block_id.clone();
        let state_root = candidate.state_root.clone();
        drop(candidate);
        let state_store = self.state_store()?;
        let world = state_store
            .world_state_at_budgeted(height, &self.world_budget)
            .map_err(|error| {
                RpcError::unavailable(format!("read finalized account state: {error:?}"))
            })?
            .ok_or_else(|| RpcError::unavailable("finalized commitment lacks account state"))?;
        let Some(account) = world.accounts.get(&query.address) else {
            return Ok(None);
        };
        let authorization_binding = finalized_account_authorization_binding(
            &world.protocol,
            &query.address,
            &self.world_budget,
        )?;
        Ok(Some(FinalizedAccountView {
            address: query.address.clone(),
            finalized_height: height,
            finalized_block_hash,
            state_root,
            balance_nwei: account.balance_nwei.to_string(),
            nonce: account.nonce,
            code_hash: account.code_hash.clone(),
            authorization_binding,
        }))
    }
}
fn finalized_account_authorization_binding(
    protocol: &std::collections::BTreeMap<String, Vec<u8>>,
    address: &str,
    budget: &Arc<WorldResourceBudget>,
) -> Result<Option<Value>, RpcError> {
    use synergy_identity::authorization::{
        canonical_binding_commitment, IDENTITY_AUTHORIZATION_BINDINGS_STATE_KEY,
    };
    Ok(
        match protocol.get(IDENTITY_AUTHORIZATION_BINDINGS_STATE_KEY) {
            None => None,
            Some(bytes) => {
                // Match canonical identity verification's table bound before any
                // decode. Charge the temporary typed map to the shared World
                // budget; its BTree nodes and strings must not escape accounting.
                const MAX_BINDING_TABLE_BYTES: usize = 1024 * 1024;
                if bytes.len() > MAX_BINDING_TABLE_BYTES {
                    return Err(RpcError::unavailable(
                        "finalized identity authorization table exceeds the byte limit",
                    ));
                }
                // Every typed entry carries two 64-byte hashes and three field
                // names. 64x plus fixed scratch conservatively covers strings,
                // serde scratch, and even a separately charged BTree node/entry.
                let _decode_permit = budget
                    .reserve(bytes.len().saturating_mul(64).saturating_add(4096))
                    .map_err(|error| RpcError::unavailable(error.to_string()))?;
                match canonical_binding_commitment(protocol, address) {
                    Ok(commitment) => Some(serde_json::to_value(commitment).map_err(|_| {
                        RpcError::unavailable("encode finalized authorization binding")
                    })?),
                    Err(error)
                        if error == "identity has no canonical finalized authorization binding" =>
                    {
                        None
                    }
                    Err(error) => return Err(RpcError::unavailable(error)),
                }
            }
        },
    )
}

const MAX_HTTP_HEADER_BYTES: usize = 8 * 1024;
const MAX_ACCEPTS_PER_POLL: usize = 32;
const MAX_AGGREGATE_HTTP_REQUEST_BYTES: usize = 64 * 1024 * 1024;
const MAX_AGGREGATE_HTTP_RESPONSE_BYTES: usize = 64 * 1024 * 1024;
const MAX_AGGREGATE_WS_BYTES: usize = 64 * 1024 * 1024;
const RPC_OWNER_IDLE: Duration = Duration::from_millis(1);
const MAX_WS_EVENTS_PER_POLL: usize = 64;
const WEBSOCKET_GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

#[derive(Clone)]
pub(crate) struct VerifiedRpcNetwork {
    pub network_id: String,
    pub epoch: u64,
    pub genesis_hash: String,
}

pub fn registration_with_preparation(
    configuration: &RpcConfiguration,
    runtime: RuntimeView,
    query_store: Arc<dyn CanonicalReadProvider>,
    websocket_hub: Arc<WsServer>,
    admission: Option<super::protected_admission::AdmissionHandle>,
    preparation: Option<super::preparation::Handle>,
    network_identity: Option<VerifiedRpcNetwork>,
) -> Result<(ServiceSpec, Box<dyn ManagedService>), String> {
    let (spec, service) = registration_service(
        configuration,
        runtime,
        query_store,
        websocket_hub,
        admission,
        preparation,
        network_identity,
    )?;
    Ok((
        spec,
        super::owned_service::production_with_interval(
            Box::new(service),
            "synergy-rpc-owner",
            RPC_OWNER_IDLE,
        ),
    ))
}

#[cfg(test)]
pub(super) fn registration_with_reserved_admission_listener(
    configuration: &RpcConfiguration,
    runtime: RuntimeView,
    query_store: Arc<dyn CanonicalReadProvider>,
    websocket_hub: Arc<WsServer>,
    admission: Option<super::protected_admission::AdmissionHandle>,
    listener: Arc<TcpListener>,
) -> Result<(ServiceSpec, Box<dyn ManagedService>), String> {
    if listener.local_addr().map_err(|e| e.to_string())?
        != configuration
            .listen_address
            .ok_or("fixture RPC address missing")?
    {
        return Err("fixture RPC reservation differs from configuration".into());
    }
    let (spec, mut service) = registration_service(
        configuration,
        runtime,
        query_store,
        websocket_hub,
        admission,
        None,
        None,
    )?;
    service.reserved_listener = Some(listener);
    Ok((
        spec,
        super::owned_service::production_with_interval(
            Box::new(service),
            "synergy-rpc-owner",
            RPC_OWNER_IDLE,
        ),
    ))
}

fn registration_service(
    configuration: &RpcConfiguration,
    runtime: RuntimeView,
    query_store: Arc<dyn CanonicalReadProvider>,
    websocket_hub: Arc<WsServer>,
    admission: Option<super::protected_admission::AdmissionHandle>,
    preparation: Option<super::preparation::Handle>,
    network_identity: Option<VerifiedRpcNetwork>,
) -> Result<(ServiceSpec, RpcService), String> {
    if !configuration.enabled {
        return Err("RPC service cannot be registered when RPC is disabled".into());
    }
    let listen_address = configuration
        .listen_address
        .ok_or_else(|| "enabled RPC requires a configured listen address".to_string())?;
    let limits = RpcLimits {
        max_body_bytes: configuration.max_request_bytes,
        max_concurrent_requests: configuration.max_concurrent_requests,
        request_timeout_ms: 5_000,
    }
    .validate()
    .map_err(|error| error.message)?;
    Ok((
        ServiceSpec {
            id: ServiceId::new("rpc")?,
            dependencies: vec![ServiceId::new("network")?, ServiceId::new("health")?],
            criticality: Criticality::Required,
            restart_policy: RestartPolicy::OnFailure { max_attempts: 3 },
        },
        RpcService {
            listen_address,
            limits,
            runtime,
            query_store,
            admission,
            preparation,
            network_identity,
            websocket_hub,
            websocket_connections: Vec::new(),
            pending_http: Vec::new(),
            next_websocket_id: 0,
            listener: None,
            #[cfg(test)]
            reserved_listener: None,
            server: None,
        },
    ))
}

struct RuntimeDispatcher {
    runtime: RuntimeView,
    query_store: Arc<dyn CanonicalReadProvider>,
    admission: Option<super::protected_admission::AdmissionHandle>,
    preparation: Option<super::preparation::Handle>,
    network_identity: Option<VerifiedRpcNetwork>,
    telemetry_samples: Mutex<TelemetrySamples>,
}

#[derive(Default)]
struct TelemetrySamples {
    samples: VecDeque<(Instant, [Option<u64>; 4])>,
}

impl TelemetrySamples {
    fn observe(&mut self, totals: [Option<u64>; 4]) -> Value {
        let now = Instant::now();
        while self
            .samples
            .front()
            .is_some_and(|(at, _)| now.duration_since(*at) > Duration::from_secs(30))
        {
            self.samples.pop_front();
        }
        if self
            .samples
            .back()
            .is_none_or(|(at, _)| now.duration_since(*at) >= Duration::from_millis(250))
        {
            if self.samples.len() == 256 {
                self.samples.pop_front();
            }
            self.samples.push_back((now, totals));
        }
        let basis = self.samples.front();
        let seconds = basis.map(|(at, _)| now.duration_since(*at).as_secs_f64());
        let rates: [Option<f64>; 4] = std::array::from_fn(|index| {
            let (at, initial) = basis?;
            let elapsed = now.duration_since(*at).as_secs_f64();
            if elapsed < 0.1 {
                return None;
            }
            Some(totals[index]?.checked_sub(initial[index]?)? as f64 / elapsed)
        });
        json!({"accepted_tps":rates[0],"ordered_tps":rates[1],"executed_tps":rates[2],"finalized_tps":rates[3],
            "window_seconds":seconds,"basis":"native process counters observed over rolling up-to-30s window",
            "accepted_total":totals[0],"ordered_total":totals[1],"executed_total":totals[2],"finalized_total":totals[3]})
    }
}

impl RuntimeDispatcher {
    fn chain_telemetry(&self, params: Value) -> Result<Value, RpcError> {
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Query {
            #[serde(default)]
            at_height: Option<u64>,
        }
        let query: Query = decode_params(params)?;
        let runtime = self
            .runtime
            .read()
            .map_err(|_| RpcError::unavailable("runtime observation state is unavailable"))?
            .clone();
        let admission = self
            .admission
            .as_ref()
            .map(|handle| handle.stats())
            .transpose()
            .map_err(RpcError::unavailable)?;
        let chain = self
            .admission
            .as_ref()
            .map(|handle| handle.chain_observations())
            .transpose()
            .map_err(RpcError::unavailable)?;
        let context = self
            .admission
            .as_ref()
            .and_then(|handle| handle.context_v2().ok());
        let (latest_height, block) = self.query_store.telemetry_commitments(query.at_height)?;
        let totals = [
            admission
                .as_ref()
                .and_then(|value| value.get("accepted_total"))
                .and_then(Value::as_u64),
            admission
                .as_ref()
                .and_then(|value| value.get("etdag_ordered_total"))
                .and_then(Value::as_u64),
            chain
                .as_ref()
                .and_then(|value| value.get("executed_total"))
                .and_then(Value::as_u64),
            chain
                .as_ref()
                .and_then(|value| value.get("finalized_total"))
                .and_then(Value::as_u64),
        ];
        let tps = self
            .telemetry_samples
            .lock()
            .map_err(|_| RpcError::unavailable("TPS observation lock poisoned"))?
            .observe(totals);
        let observed_at_unix_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| RpcError::unavailable("observation clock invalid"))?
            .as_millis();
        let common_commitment = block.as_ref().map(|block| {
            json!({"height":block.height,"block_id":block.block_id,
            "state_root":block.state_root,"finality_certificate_id":block.finality_certificate_id,
            "protected_execution_root":block.protected_execution_root})
        });
        let consensus_height = chain
            .as_ref()
            .and_then(|value| value.pointer("/consensus/height"))
            .and_then(Value::as_u64);
        let execution_height = chain
            .as_ref()
            .and_then(|value| value.get("finalized_execution_height"))
            .and_then(Value::as_u64);
        let execution_lag = consensus_height
            .zip(execution_height)
            .map(|(consensus, execution)| consensus.saturating_sub(2).saturating_sub(execution));
        Ok(
            json!({"schema_version":1,"observed_at_unix_ms":observed_at_unix_ms,"node_name":runtime.node_name,
            "chain_id":runtime.chain_id,"role":runtime.role,"services":runtime.services,"lifecycle":runtime.lifecycle,
            "process_id":std::process::id(),"release":{"package_version":env!("CARGO_PKG_VERSION"),"artifact_digest":null,"source_revision":null},
            "transport":self.admission.as_ref().map(|handle|handle.transport_observations()).transpose().map_err(RpcError::unavailable)?,
            "network_identity":self.network_identity.as_ref().map(|identity|&identity.network_id),
            "epoch":self.network_identity.as_ref().map(|identity|identity.epoch),
            "genesis_hash":self.network_identity.as_ref().map(|identity|&identity.genesis_hash),
            "finalized_height":latest_height,"common_finalized_commitment":common_commitment,
            "commitment_comparison":"request identical at_height from each validator; never compare unmatched observation tips",
            "latest_sampled_block_transaction_count":block.as_ref().map(|block|block.transaction_count),
            "tps":tps,"admission":admission,"chain":chain,"admission_window":context.as_ref().and_then(|value|value.get("observation")),
            "preparation":self.preparation.as_ref().map(|handle|handle.observations()).transpose().map_err(RpcError::unavailable)?,
            "resource_budget":self.query_store.resource_observations(),
            "execution_lag":execution_lag,"wallet_count":null,"restart_counts":null,"recovery_progress":null,
            "unavailable_fields_reason":"unknown observations remain null; package version alone is not exact artifact identity"}),
        )
    }

    fn service(&self, id: &str) -> Result<Value, RpcError> {
        let snapshot = self
            .runtime
            .read()
            .map_err(|_| RpcError::unavailable("runtime observation state is unavailable"))?;
        let service = snapshot
            .service(id)
            .ok_or_else(|| RpcError::unavailable(format!("{id} service is not registered")))?;
        serde_json::to_value(service)
            .map_err(|_| RpcError::unavailable("runtime service observation is not serializable"))
    }
}

impl RpcDispatcher for RuntimeDispatcher {
    fn dispatch(&self, method: &str, params: Value) -> Result<Value, RpcError> {
        match method {
            PROCESSING_CONTEXT_V1 => {
                let mut result = self
                    .admission
                    .as_ref()
                    .ok_or_else(|| {
                        RpcError::unavailable("asynchronous processing admission is not enabled")
                    })?
                    .processing_context()
                    .map_err(RpcError::unavailable)?;
                // Report the same fee schedule used by native execution. This
                // observation never changes the selected network identity.
                result["fee_policy"] = serde_json::json!({
                    "base_fee_per_gas_nwei": super::execution::TESTNET_V3_BASE_FEE_NWEI,
                    "transfer_gas_limit": 21_000,
                    "wallet_synid_gas_limit": 50_000 + synergy_naming::MAX_WALLET_NAMING_BYTES,
                });
                Ok(result)
            }
            PROCESSING_TRANSACTION_SUBMIT_V1 => self
                .admission
                .as_ref()
                .ok_or_else(|| {
                    RpcError::unavailable("asynchronous processing admission is not enabled")
                })?
                .enqueue_processing(decode_params(params)?)
                .map_err(RpcError::invalid_params),
            PROTECTED_ADMISSION_CONTEXT_V2 => self
                .admission
                .as_ref()
                .ok_or_else(|| {
                    RpcError::unavailable("protected transaction admission is not enabled")
                })?
                .context_v2()
                .map_err(RpcError::unavailable),
            CHAIN_TELEMETRY => self.chain_telemetry(params),
            PROTECTED_ADMISSION_STATS => self
                .admission
                .as_ref()
                .ok_or_else(|| {
                    RpcError::unavailable("protected transaction admission is not enabled")
                })?
                .stats()
                .map_err(RpcError::unavailable),
            PROTECTED_ADMISSION_CONTEXT => self
                .admission
                .as_ref()
                .ok_or_else(|| {
                    RpcError::unavailable("protected transaction admission is not enabled")
                })?
                .context()
                .map_err(RpcError::unavailable),
            PROTECTED_TRANSACTION_SUBMIT => self
                .admission
                .as_ref()
                .ok_or_else(|| {
                    RpcError::unavailable("protected transaction admission is not enabled")
                })?
                .enqueue(decode_params(params)?)
                .map_err(RpcError::invalid_params),
            PROTECTED_ADMISSION_RECEIPT => {
                #[derive(serde::Deserialize)]
                #[serde(deny_unknown_fields)]
                struct ReceiptQuery {
                    receipt_id: String,
                }
                let query: ReceiptQuery = decode_params(params)?;
                self.admission
                    .as_ref()
                    .ok_or_else(|| {
                        RpcError::unavailable("protected transaction admission is not enabled")
                    })?
                    .receipt(&query.receipt_id)
                    .map_err(RpcError::unavailable)
            }
            SYSTEM_VERSION => Ok(json!({
                "node": env!("CARGO_PKG_VERSION"),
                "rpc": "1",
            })),
            NODE_STATUS => {
                let snapshot = self.runtime.read().map_err(|_| {
                    RpcError::unavailable("runtime observation state is unavailable")
                })?;
                Ok(json!({
                    "node_name": &snapshot.node_name,
                    "role": &snapshot.role,
                    "chain_id": snapshot.chain_id,
                    "lifecycle": &snapshot.lifecycle,
                    "ready": snapshot.ready(),
                }))
            }
            CHAIN_STATUS => {
                let snapshot = self.runtime.read().map_err(|_| {
                    RpcError::unavailable("runtime observation state is unavailable")
                })?;
                Ok(json!({
                    "chain_id": snapshot.chain_id,
                    "lifecycle": &snapshot.lifecycle,
                    "ready": snapshot.ready(),
                }))
            }
            SYNC_STATUS => self.service("sync"),
            POSY_STATUS => self.service("posy"),
            ETDAG_STATUS => self.service("etdag"),
            BLOCK_GET => encode_query_result(
                self.query_store
                    .block(&decode_params::<BlockQuery>(params)?)?,
            ),
            TRANSACTION_GET => encode_query_result(
                self.query_store
                    .transaction(&decode_params::<TransactionQuery>(params)?)?,
            ),
            SYNID_RESOLVE | SYNID_REVERSE => {
                #[derive(serde::Deserialize)]
                #[serde(deny_unknown_fields)]
                struct NamingQuery {
                    value: String,
                }
                let query: NamingQuery = decode_params(params)?;
                self.query_store
                    .wallet_syn_id(&query.value, method == SYNID_REVERSE)
            }
            ACCOUNT_GET => encode_query_result(
                self.query_store
                    .account(&decode_params::<AccountQuery>(params)?)?,
            ),
            _ => Err(RpcError::method_not_found()),
        }
    }
}

fn decode_params<T: DeserializeOwned>(params: Value) -> Result<T, RpcError> {
    serde_json::from_value(params)
        .map_err(|error| RpcError::invalid_params(format!("invalid method parameters: {error}")))
}

fn encode_query_result<T: serde::Serialize>(result: Option<T>) -> Result<Value, RpcError> {
    serde_json::to_value(result)
        .map_err(|error| RpcError::unavailable(format!("serialize query result: {error}")))
}

struct PendingHttp {
    stream: TcpStream,
    client_id: String,
    deadline: Instant,
    bytes: Vec<u8>,
    response: Option<Vec<u8>>,
    offset: usize,
    upgrade: Option<Vec<u8>>,
    #[cfg(feature = "qualification-timing")]
    diagnostic_request: Option<u64>,
}

impl PendingHttp {
    fn request_bytes(&self) -> usize {
        self.bytes
            .capacity()
            .saturating_add(self.upgrade.as_ref().map_or(0, Vec::capacity))
    }
}

fn http_response(status: u16, body: &[u8]) -> Vec<u8> {
    let (reason, content_type) = match status {
        200 => ("OK", "application/json"),
        400 => ("Bad Request", "text/plain; charset=utf-8"),
        405 => ("Method Not Allowed", "text/plain; charset=utf-8"),
        413 => ("Payload Too Large", "text/plain; charset=utf-8"),
        503 => ("Service Unavailable", "text/plain; charset=utf-8"),
        _ => ("Error", "text/plain; charset=utf-8"),
    };
    let mut response = format!("HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len()).into_bytes();
    response.extend_from_slice(body);
    response
}

struct RpcService {
    listen_address: std::net::SocketAddr,
    limits: RpcLimits,
    runtime: RuntimeView,
    query_store: Arc<dyn CanonicalReadProvider>,
    websocket_hub: Arc<WsServer>,
    admission: Option<super::protected_admission::AdmissionHandle>,
    preparation: Option<super::preparation::Handle>,
    network_identity: Option<VerifiedRpcNetwork>,
    websocket_connections: Vec<WsConnection>,
    pending_http: Vec<PendingHttp>,
    next_websocket_id: u64,
    listener: Option<TcpListener>,
    #[cfg(test)]
    reserved_listener: Option<Arc<TcpListener>>,
    server: Option<RpcServer<RuntimeDispatcher, PublicOnlyAuthenticator>>,
}

impl ManagedService for RpcService {
    fn start(&mut self, cancellation: &CancellationToken) -> Result<(), String> {
        if cancellation.is_cancelled() {
            return Err("RPC service start was cancelled".into());
        }
        let limiter = RpcRateLimiter::new(
            RateLimit {
                requests: 128,
                window_ms: 1_000,
            },
            self.limits.max_concurrent_requests,
        )
        .map_err(|error| error.message)?;
        #[cfg(test)]
        let reserved = self.reserved_listener.as_ref();
        #[cfg(test)]
        let listener = match reserved {
            Some(reservation) => {
                reservation
                    .set_nonblocking(true)
                    .map_err(|e| e.to_string())?;
                let mut drained = false;
                for _ in 0..512 {
                    match reservation.accept() {
                        Ok((stream, _)) => {
                            let _ = stream.shutdown(std::net::Shutdown::Both);
                        }
                        Err(e) if e.kind() == ErrorKind::WouldBlock => {
                            drained = true;
                            break;
                        }
                        Err(e) => return Err(format!("drain fixture RPC listener: {e}")),
                    }
                }
                if !drained {
                    return Err("fixture RPC backlog exceeds drain bound".into());
                }
                reservation.try_clone().map_err(|e| e.to_string())?
            }
            None => TcpListener::bind(self.listen_address)
                .map_err(|error| format!("bind RPC listener {}: {error}", self.listen_address))?,
        };
        #[cfg(not(test))]
        let listener = TcpListener::bind(self.listen_address)
            .map_err(|error| format!("bind RPC listener {}: {error}", self.listen_address))?;
        listener
            .set_nonblocking(true)
            .map_err(|error| format!("configure RPC listener: {error}"))?;
        self.server = Some(
            RpcServer::new(
                Arc::new(RuntimeDispatcher {
                    runtime: Arc::clone(&self.runtime),
                    query_store: Arc::clone(&self.query_store),
                    admission: self.admission.clone(),
                    preparation: self.preparation.clone(),
                    network_identity: self.network_identity.clone(),
                    telemetry_samples: Mutex::new(TelemetrySamples::default()),
                }),
                Arc::new(PublicOnlyAuthenticator),
                self.limits,
                limiter,
            )
            .map_err(|error| error.message)?,
        );
        self.listener = Some(listener);
        Ok(())
    }

    fn poll(&mut self) -> Result<(), String> {
        for _ in 0..MAX_ACCEPTS_PER_POLL {
            let accepted = self
                .listener
                .as_ref()
                .ok_or("RPC listener is stopped")?
                .accept();
            let (stream, peer) = match accepted {
                Ok(connection) => connection,
                Err(error) if error.kind() == ErrorKind::WouldBlock => break,
                Err(error) => return Err(format!("accept RPC connection: {error}")),
            };
            if self.pending_http.len() + self.websocket_connections.len()
                >= self.limits.max_concurrent_requests
            {
                continue;
            }
            if stream.set_nonblocking(true).is_err() {
                continue;
            }
            #[cfg(feature = "qualification-timing")]
            let diagnostic_request = {
                use super::qualification_timing::{self as timing, HttpStage, Phase};
                if timing::enabled() {
                    static REQUEST: std::sync::atomic::AtomicU64 =
                        std::sync::atomic::AtomicU64::new(1);
                    let id = REQUEST.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    timing::http_span(id, HttpStage::Intake, Phase::Start);
                    Some(id)
                } else {
                    None
                }
            };
            self.pending_http.push(PendingHttp {
                stream,
                client_id: peer.to_string(),
                deadline: Instant::now() + Duration::from_millis(self.limits.request_timeout_ms),
                bytes: Vec::new(),
                response: None,
                offset: 0,
                upgrade: None,
                #[cfg(feature = "qualification-timing")]
                diagnostic_request,
            });
        }
        self.poll_http()?;
        self.poll_websockets()
    }

    fn stop(&mut self) -> Result<(), String> {
        for connection in self.websocket_connections.drain(..) {
            let _ = self.websocket_hub.unsubscribe(&connection.subscriber_id);
        }
        self.pending_http.clear();
        self.listener = None;
        self.server = None;
        Ok(())
    }

    fn health(&self) -> ServiceHealth {
        if self.server.is_some() && self.listener.is_some() {
            ServiceHealth::Healthy
        } else {
            ServiceHealth::Unhealthy {
                reason: "RPC and WebSocket request boundary is stopped".into(),
            }
        }
    }

    fn readiness(&self) -> ServiceReadiness {
        if self.server.is_some() && self.listener.is_some() {
            ServiceReadiness::Ready
        } else {
            ServiceReadiness::Blocked {
                reason: "RPC and WebSocket listener is stopped".into(),
            }
        }
    }
}

impl RpcService {
    fn poll_http(&mut self) -> Result<(), String> {
        let mut retained = Vec::new();
        let mut request_bytes: usize = self
            .pending_http
            .iter()
            .map(PendingHttp::request_bytes)
            .sum();
        let mut response_bytes: usize = self
            .pending_http
            .iter()
            .map(|p| p.response.as_ref().map_or(0, Vec::capacity))
            .sum();
        for mut pending in std::mem::take(&mut self.pending_http) {
            request_bytes -= pending.request_bytes();
            response_bytes -= pending.response.as_ref().map_or(0, Vec::capacity);
            if Instant::now() >= pending.deadline {
                continue;
            }
            let result = self.poll_http_connection(
                &mut pending,
                MAX_AGGREGATE_HTTP_REQUEST_BYTES.saturating_sub(request_bytes),
                MAX_AGGREGATE_HTTP_RESPONSE_BYTES.saturating_sub(response_bytes),
            );
            match result {
                Ok(false) => {
                    request_bytes += pending.request_bytes();
                    response_bytes += pending.response.as_ref().map_or(0, Vec::capacity);
                    retained.push(pending);
                }
                Ok(true) => {
                    if let Some(read_buffer) = pending.upgrade.take() {
                        if self
                            .websocket_connections
                            .iter()
                            .map(WsConnection::buffered_bytes)
                            .sum::<usize>()
                            .saturating_add(read_buffer.capacity())
                            > MAX_AGGREGATE_WS_BYTES
                        {
                            continue;
                        }
                        self.next_websocket_id = self
                            .next_websocket_id
                            .checked_add(1)
                            .ok_or("WebSocket connection identifier overflow")?;
                        let subscriber_id =
                            format!("{}#{}", pending.client_id, self.next_websocket_id);
                        if self
                            .websocket_hub
                            .subscribe(subscriber_id.clone(), all_topics())
                            .is_ok()
                        {
                            self.websocket_connections.push(WsConnection {
                                stream: pending.stream,
                                subscriber_id,
                                read_buffer,
                                writes: VecDeque::new(),
                                write_offset: 0,
                            });
                        }
                    }
                }
                Err(_) => {} // Invalid/disconnected clients do not fail the runtime.
            }
        }
        self.pending_http = retained;
        Ok(())
    }

    fn poll_http_connection(
        &self,
        pending: &mut PendingHttp,
        request_budget: usize,
        response_budget: usize,
    ) -> Result<bool, String> {
        if pending.response.is_none() {
            let mut buffer = [0u8; 4096];
            // Bounded work even if a client continuously sends bytes.
            for _ in 0..16 {
                match pending.stream.read(&mut buffer) {
                    Ok(0) => return Err("RPC client disconnected".into()),
                    Ok(count) => {
                        if pending.bytes.len().saturating_add(count) > request_budget {
                            pending.bytes = Vec::new();
                            pending.response = Some(http_response(
                                503,
                                b"RPC request capacity exhausted; retry with backoff",
                            ));
                            break;
                        }
                        pending.bytes.reserve_exact(count);
                        if pending.bytes.capacity() > request_budget {
                            pending.bytes = Vec::new();
                            pending.response = Some(http_response(
                                503,
                                b"RPC request capacity exhausted; retry with backoff",
                            ));
                            break;
                        }
                        pending.bytes.extend_from_slice(&buffer[..count]);
                    }
                    Err(error) if error.kind() == ErrorKind::WouldBlock => break,
                    Err(error) if error.kind() == ErrorKind::Interrupted => continue,
                    Err(error) => return Err(error.to_string()),
                }
                if pending.bytes.len() > self.limits.max_body_bytes + MAX_HTTP_HEADER_BYTES {
                    pending.response = Some(http_response(413, b"request exceeds RPC bound"));
                    break;
                }
                if let Some(response) = self.prepare_http_response(pending)? {
                    pending.response = Some(response);
                    break;
                }
            }
        }
        if pending
            .response
            .as_ref()
            .is_some_and(|response| response.capacity() > response_budget)
        {
            pending.response = Some(http_response(
                503,
                b"RPC response capacity exhausted; reconcile any submission receipt",
            ));
            if pending
                .response
                .as_ref()
                .is_some_and(|response| response.capacity() > response_budget)
            {
                return Err(
                    "aggregate RPC response capacity cannot accommodate overload response".into(),
                );
            }
        }
        if pending.response.is_some() {
            pending.bytes = Vec::new();
        }
        let Some(response) = pending.response.as_ref() else {
            return Ok(false);
        };
        #[cfg(feature = "qualification-timing")]
        if let Some(id) = pending.diagnostic_request {
            use super::qualification_timing::{self as timing, HttpStage, Phase};
            timing::http_span(id, HttpStage::Response, Phase::Start);
        }
        let end = pending.offset.saturating_add(64 * 1024).min(response.len());
        match pending.stream.write(&response[pending.offset..end]) {
            Ok(0) => return Err("RPC response connection closed".into()),
            Ok(count) => pending.offset += count,
            Err(error)
                if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::Interrupted) =>
            {
                return Ok(false)
            }
            Err(error) => return Err(error.to_string()),
        }
        let completed = pending.offset == response.len();
        #[cfg(feature = "qualification-timing")]
        if completed {
            if let Some(id) = pending.diagnostic_request {
                use super::qualification_timing::{self as timing, HttpStage, Phase};
                timing::http_span(id, HttpStage::Response, Phase::End);
            }
        }
        Ok(completed)
    }

    fn prepare_http_response(&self, pending: &mut PendingHttp) -> Result<Option<Vec<u8>>, String> {
        let Some(header_end) = pending
            .bytes
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
        else {
            if pending.bytes.len() > MAX_HTTP_HEADER_BYTES {
                return Ok(Some(http_response(413, b"RPC headers exceed bound")));
            }
            return Ok(None);
        };
        if header_end > MAX_HTTP_HEADER_BYTES {
            return Ok(Some(http_response(413, b"RPC headers exceed bound")));
        }
        let headers = std::str::from_utf8(&pending.bytes[..header_end])
            .map_err(|_| "RPC headers invalid UTF-8")?;
        let mut lines = headers.split("\r\n");
        let request_line = lines.next().ok_or("RPC request line missing")?;
        let header_lines: Vec<_> = lines.map(str::to_owned).collect();
        if request_line == "GET /ws HTTP/1.1" && is_websocket_upgrade(&header_lines) {
            let key =
                header_value(&header_lines, "sec-websocket-key").ok_or("WebSocket key missing")?;
            let decoded = BASE64.decode(key).map_err(|_| "WebSocket key invalid")?;
            if decoded.len() != 16
                || header_value(&header_lines, "sec-websocket-version") != Some("13")
            {
                return Ok(Some(http_response(400, b"unsupported WebSocket handshake")));
            }
            let mut digest = Sha1::new();
            digest.update(key.as_bytes());
            digest.update(WEBSOCKET_GUID.as_bytes());
            let accept = BASE64.encode(digest.finalize());
            pending.upgrade = Some(pending.bytes.split_off(header_end + 4));
            return Ok(Some(format!("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n").into_bytes()));
        }
        if request_line != "POST / HTTP/1.1" && request_line != "POST /rpc HTTP/1.1" {
            return Ok(Some(http_response(
                405,
                b"RPC requires POST / or POST /rpc",
            )));
        }
        let length = header_value(&header_lines, "content-length")
            .and_then(|value| value.parse::<usize>().ok())
            .ok_or("RPC request lacks valid Content-Length")?;
        if length > self.limits.max_body_bytes {
            return Ok(Some(http_response(413, b"RPC body exceeds bound")));
        }
        let total = (header_end + 4)
            .checked_add(length)
            .ok_or("RPC request length overflow")?;
        if pending.bytes.len() < total {
            return Ok(None);
        }
        if pending.bytes.len() != total {
            return Ok(Some(http_response(400, b"invalid RPC request length")));
        }
        #[cfg(feature = "qualification-timing")]
        if let Some(id) = pending.diagnostic_request {
            use super::qualification_timing::{self as timing, HttpStage, Phase};
            timing::http_span(id, HttpStage::Intake, Phase::End);
            timing::http_span(id, HttpStage::Dispatch, Phase::Start);
        }
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| "RPC clock invalid")?
            .as_millis()
            .try_into()
            .map_err(|_| "RPC clock overflow")?;
        let response = self
            .server
            .as_ref()
            .ok_or("RPC server stopped")?
            .handle_bytes(
                &pending.client_id,
                None,
                now_ms,
                &pending.bytes[header_end + 4..],
            );
        #[cfg(feature = "qualification-timing")]
        if let Some(id) = pending.diagnostic_request {
            use super::qualification_timing::{self as timing, HttpStage, Phase};
            timing::http_span(id, HttpStage::Dispatch, Phase::End);
        }
        let response = http_response(200, &response);
        Ok(Some(response))
    }

    fn poll_websockets(&mut self) -> Result<(), String> {
        let mut retained = Vec::with_capacity(self.websocket_connections.len());
        let mut buffered: usize = self
            .websocket_connections
            .iter()
            .map(WsConnection::buffered_bytes)
            .sum();
        for mut connection in self.websocket_connections.drain(..) {
            buffered -= connection.buffered_bytes();
            let budget = MAX_AGGREGATE_WS_BYTES.saturating_sub(buffered);
            match connection.poll(&self.websocket_hub, self.limits.max_body_bytes, budget) {
                Ok(true) => {
                    buffered += connection.buffered_bytes();
                    retained.push(connection);
                }
                Ok(false) | Err(_) => {
                    let _ = self.websocket_hub.unsubscribe(&connection.subscriber_id);
                }
            }
        }
        self.websocket_connections = retained;
        Ok(())
    }
}

struct WsConnection {
    stream: TcpStream,
    subscriber_id: String,
    read_buffer: Vec<u8>,
    writes: VecDeque<Vec<u8>>,
    write_offset: usize,
}

impl WsConnection {
    fn buffered_bytes(&self) -> usize {
        self.read_buffer
            .capacity()
            .saturating_add(self.writes.iter().map(Vec::capacity).sum::<usize>())
    }

    fn queue_frame(&mut self, opcode: u8, payload: &[u8], budget: usize) -> bool {
        if self
            .buffered_bytes()
            .saturating_add(payload.len())
            .saturating_add(10)
            > budget
        {
            return false;
        }
        self.writes.push_back(server_frame(opcode, payload));
        true
    }

    fn poll(
        &mut self,
        hub: &WsServer,
        max_payload_bytes: usize,
        budget: usize,
    ) -> Result<bool, String> {
        let read_bound = max_payload_bytes
            .checked_add(MAX_HTTP_HEADER_BYTES)
            .ok_or("WebSocket read bound overflow")?;
        for _ in 0..16 {
            let mut buffer = [0u8; 4096];
            match self.stream.read(&mut buffer) {
                Ok(0) => return Ok(false),
                Ok(read) => {
                    let required = self.read_buffer.len().saturating_add(read);
                    let additional = required.saturating_sub(self.read_buffer.capacity());
                    if self.buffered_bytes().saturating_add(additional) > budget {
                        return Ok(false);
                    }
                    self.read_buffer.reserve_exact(read);
                    if self.buffered_bytes() > budget {
                        return Ok(false);
                    }
                    self.read_buffer.extend_from_slice(&buffer[..read]);
                    if self.read_buffer.len() > read_bound {
                        return Ok(false);
                    }
                }
                Err(error) if error.kind() == ErrorKind::WouldBlock => break,
                Err(_) => return Ok(false),
            }
        }
        if !self.consume_frames(hub, max_payload_bytes, budget)? {
            return Ok(false);
        }
        for event in hub
            .drain(&self.subscriber_id, MAX_WS_EVENTS_PER_POLL)
            .map_err(|error| format!("drain WebSocket events: {error:?}"))?
        {
            let payload = serde_json::to_vec(&event)
                .map_err(|error| format!("encode WebSocket event: {error}"))?;
            if !self.queue_frame(0x1, &payload, budget) {
                return Ok(false);
            }
        }
        let mut write_budget = 64 * 1024;
        while let Some(frame) = self.writes.front() {
            if write_budget == 0 {
                break;
            }
            let end = self
                .write_offset
                .saturating_add(write_budget)
                .min(frame.len());
            match self.stream.write(&frame[self.write_offset..end]) {
                Ok(0) => return Ok(false),
                Ok(written) => {
                    self.write_offset += written;
                    write_budget -= written;
                    if self.write_offset == frame.len() {
                        self.writes.pop_front();
                        self.write_offset = 0;
                    }
                }
                Err(error) if error.kind() == ErrorKind::WouldBlock => break,
                Err(_) => return Ok(false),
            }
        }
        Ok(true)
    }

    fn consume_frames(
        &mut self,
        hub: &WsServer,
        max_payload_bytes: usize,
        budget: usize,
    ) -> Result<bool, String> {
        loop {
            let Some((consumed, opcode, payload)) =
                client_frame(&self.read_buffer, max_payload_bytes)?
            else {
                return Ok(true);
            };
            self.read_buffer.drain(..consumed);
            match opcode {
                0x1 => {
                    if !payload.is_empty() {
                        let topics = requested_topics(&payload)?;
                        hub.subscribe(self.subscriber_id.clone(), topics)
                            .map_err(|error| format!("update WebSocket subscription: {error:?}"))?;
                    }
                }
                0x8 => return Ok(false),
                0x9 => {
                    if !self.queue_frame(0xA, &payload, budget) {
                        return Ok(false);
                    }
                }
                0xA => {}
                _ => return Ok(false),
            }
        }
    }
}

fn header_value<'a>(headers: &'a [String], name: &str) -> Option<&'a str> {
    headers.iter().find_map(|line| {
        line.split_once(':').and_then(|(candidate, value)| {
            candidate.eq_ignore_ascii_case(name).then_some(value.trim())
        })
    })
}

fn is_websocket_upgrade(headers: &[String]) -> bool {
    header_value(headers, "upgrade").is_some_and(|value| value.eq_ignore_ascii_case("websocket"))
        && header_value(headers, "connection").is_some_and(|value| {
            value
                .split(',')
                .any(|token| token.trim().eq_ignore_ascii_case("upgrade"))
        })
}

fn all_topics() -> BTreeSet<WsTopic> {
    [
        WsTopic::Blocks,
        WsTopic::Finality,
        WsTopic::Transactions,
        WsTopic::Node,
    ]
    .into_iter()
    .collect()
}

fn requested_topics(payload: &[u8]) -> Result<BTreeSet<WsTopic>, String> {
    let value: Value = serde_json::from_slice(payload)
        .map_err(|_| "WebSocket subscription request is not valid JSON")?;
    let topics = value
        .get("topics")
        .and_then(Value::as_array)
        .ok_or("WebSocket subscription request requires a topics array")?;
    let mut selected = BTreeSet::new();
    for topic in topics {
        selected.insert(match topic.as_str() {
            Some("blocks") => WsTopic::Blocks,
            Some("finality") => WsTopic::Finality,
            Some("transactions") => WsTopic::Transactions,
            Some("node") => WsTopic::Node,
            _ => return Err("WebSocket subscription contains an unsupported topic".into()),
        });
    }
    if selected.is_empty() {
        return Err("WebSocket subscription topics cannot be empty".into());
    }
    Ok(selected)
}

fn client_frame(
    bytes: &[u8],
    max_payload_bytes: usize,
) -> Result<Option<(usize, u8, Vec<u8>)>, String> {
    if bytes.len() < 2 {
        return Ok(None);
    }
    let final_frame = bytes[0] & 0x80 != 0;
    let opcode = bytes[0] & 0x0F;
    if !final_frame || !matches!(opcode, 0x1 | 0x8 | 0x9 | 0xA) || bytes[1] & 0x80 == 0 {
        return Err("unsupported WebSocket frame".into());
    }
    let mut cursor = 2usize;
    let length_code = bytes[1] & 0x7F;
    let payload_length = match length_code {
        0..=125 => usize::from(length_code),
        126 => {
            if bytes.len() < cursor + 2 {
                return Ok(None);
            }
            let length = u16::from_be_bytes([bytes[cursor], bytes[cursor + 1]]);
            cursor += 2;
            usize::from(length)
        }
        127 => {
            if bytes.len() < cursor + 8 {
                return Ok(None);
            }
            let mut encoded = [0u8; 8];
            encoded.copy_from_slice(&bytes[cursor..cursor + 8]);
            cursor += 8;
            usize::try_from(u64::from_be_bytes(encoded))
                .map_err(|_| "WebSocket frame length exceeds platform bounds")?
        }
        _ => unreachable!(),
    };
    if payload_length > max_payload_bytes || matches!(opcode, 0x8..=0xA) && payload_length > 125 {
        return Err("WebSocket frame exceeds configured bound".into());
    }
    if bytes.len() < cursor + 4 {
        return Ok(None);
    }
    let mask = [
        bytes[cursor],
        bytes[cursor + 1],
        bytes[cursor + 2],
        bytes[cursor + 3],
    ];
    cursor += 4;
    let frame_end = cursor
        .checked_add(payload_length)
        .ok_or("WebSocket frame length overflow")?;
    if bytes.len() < frame_end {
        return Ok(None);
    }
    let payload = bytes[cursor..frame_end]
        .iter()
        .enumerate()
        .map(|(index, byte)| byte ^ mask[index % 4])
        .collect();
    Ok(Some((frame_end, opcode, payload)))
}

fn server_frame(opcode: u8, payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(payload.len() + 10);
    frame.push(0x80 | opcode);
    match payload.len() {
        length @ 0..=125 => frame.push(length as u8),
        length @ 126..=65_535 => {
            frame.push(126);
            frame.extend_from_slice(&(length as u16).to_be_bytes());
        }
        length => {
            frame.push(127);
            frame.extend_from_slice(&(length as u64).to_be_bytes());
        }
    }
    frame.extend_from_slice(payload);
    frame
}

#[cfg(test)]
mod nonblocking_http_tests {
    use super::*;
    use synergy_execution::{CandidateStore, ExecutionCandidate};
    #[test]
    fn account_authorization_lookup_is_bounded_budgeted_and_canonical() {
        use synergy_identity::authorization::IDENTITY_AUTHORIZATION_BINDINGS_STATE_KEY as KEY;
        let budget = WorldResourceBudget::new(1024 * 1024);
        let mut protocol = std::collections::BTreeMap::new();
        assert!(
            finalized_account_authorization_binding(&protocol, "alice", &budget)
                .unwrap()
                .is_none()
        );
        let commitment = json!({"binding_payload_sha3_256":"a".repeat(64),
            "identity_root_public_key_sha3_256":"b".repeat(64),"effective_at_unix":123});
        protocol.insert(
            KEY.into(),
            serde_json::to_vec(&json!({"alice":commitment})).unwrap(),
        );
        assert_eq!(
            finalized_account_authorization_binding(&protocol, "alice", &budget).unwrap(),
            Some(commitment)
        );
        assert_eq!(budget.used(), 0);
        assert!(
            finalized_account_authorization_binding(&protocol, "unbound", &budget)
                .unwrap()
                .is_none()
        );
        let tiny = WorldResourceBudget::new(1);
        assert!(finalized_account_authorization_binding(&protocol, "alice", &tiny).is_err());
        assert_eq!(tiny.used(), 0);
        protocol.insert(KEY.into(), br#"{"alice":{"binding_payload_sha3_256":"bad","identity_root_public_key_sha3_256":"bad","effective_at_unix":123}}"#.to_vec());
        assert!(finalized_account_authorization_binding(&protocol, "alice", &budget).is_err());
        assert_eq!(budget.used(), 0);
        // Invalid oversized bytes must be rejected before a decoder or budget request.
        protocol.insert(KEY.into(), vec![b'!'; 1024 * 1024 + 1]);
        let error = finalized_account_authorization_binding(&protocol, "alice", &tiny).unwrap_err();
        assert!(format!("{error:?}").contains("exceeds the byte limit"));
        assert_eq!(tiny.used(), 0);
    }

    #[test]
    fn tps_unknown_fields_remain_unknown_and_counter_reset_never_underflows() {
        let mut samples = TelemetrySamples::default();
        samples.samples.push_back((
            Instant::now() - Duration::from_secs(1),
            [Some(10), Some(5), None, None],
        ));
        let observed = samples.observe([Some(12), Some(8), None, None]);
        assert!(observed["accepted_tps"].as_f64().unwrap() > 0.0);
        assert!(observed["executed_tps"].is_null());
        assert!(observed["finalized_tps"].is_null());
        let reset = samples.observe([Some(1), Some(1), None, None]);
        assert!(reset["accepted_tps"].is_null());
        assert!(reset["ordered_tps"].is_null());
    }

    #[test]
    fn finalized_query_retirement_race_skips_only_independently_retired_history() {
        let root = std::env::temp_dir().join(format!(
            "rpc-retirement-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let layout = NodeStorageLayout::new(root.clone()).unwrap();
        let mut candidates =
            CandidateStore::new(layout.blocks().join("execution-candidates")).unwrap();
        let mut states = FinalizedStateStore::load(layout.state().join("execution")).unwrap();
        let finality = FinalityStore::new(layout.consensus().join("posy")).unwrap();
        let world = synergy_state::WorldState::default();
        let mut parent = "genesis".to_string();
        let mut next = None;
        let mut previous_finality = None;
        for height in 1..=2 {
            let material = synergy_etdag::execution::ProtectedProposalMaterial {
                material_version: 2,
                height,
                execution_root: synergy_etdag::EtdagDigest::from_domain_bytes("test", b"execution"),
                next_batch_root: synergy_etdag::EtdagDigest::from_domain_bytes("test", b"batch"),
                cutoff_boundary_root: synergy_etdag::EtdagDigest::from_domain_bytes(
                    "test", b"cutoff",
                ),
            };
            let mut candidate = ExecutionCandidate {
                resource_permit: None,
                height,
                block_id: String::new(),
                parent_block_id: parent,
                protected_execution_root: synergy_block::hash_block_bytes(
                    &material.commitment_bytes().unwrap(),
                ),
                protected_material: material.into(),
                state_root: synergy_state::state_root(&world).unwrap(),
                transactions: vec![],
                receipts: vec![],
                state: Arc::new(world.clone()),
            };
            candidate.block_id = candidate.commitment_id().unwrap();
            candidates.put_once(&candidate, &world).unwrap();
            let record = FinalizedBlockRecord {
                height,
                block_id: candidate.block_id.clone(),
                finality_certificate_id: "a".repeat(64),
                protected_execution_root: candidate.protected_execution_root.clone(),
            };
            finality
                .commit_exactly_once(&record, previous_finality.as_ref())
                .unwrap();
            previous_finality = Some(record);
            let state = synergy_state::FinalizedState {
                finalized_height: height,
                finalized_block_id: candidate.block_id.clone(),
                state_root: candidate.state_root.clone(),
            };
            if height == 1 {
                states.commit_verified_world_state(state, &world).unwrap();
            } else {
                next = Some(state);
            }
            parent = candidate.block_id;
        }
        let query = CanonicalQueryStore::load(&root).unwrap();
        assert!(query.finalized_at(1).unwrap().is_some());
        // Deterministically retire after RPC captured H1's commitment but before
        // it opens H1's candidate; this used to abort a transaction search.
        assert!(query
            .finalized_at_with_candidate(1, || {
                states
                    .commit_verified_world_transition(next.unwrap(), &world, &world)
                    .unwrap();
                states.prune_finalized_history(2, 1).unwrap();
                candidates.prune_finalized_history(2, 1).unwrap();
                query.candidate_at(1)
            })
            .unwrap()
            .is_none());
        assert!(query.finalized_commitment_at(1).unwrap().is_none());
        assert!(query.finalized_at(2).unwrap().is_some());
        // A missing current candidate is corruption, never ordinary retention.
        fs::remove_file(
            layout
                .blocks()
                .join("execution-candidates/candidate/00000000000000000002.json"),
        )
        .unwrap();
        assert!(query.finalized_at(2).is_err());
        assert!(query.finalized_commitment_at(2).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn telemetry_commitments_do_not_load_world_and_fail_closed_on_owner_mismatch() {
        let root = std::env::temp_dir().join(format!(
            "rpc-metadata-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let service = fixture(&root, "127.0.0.1:0".parse().unwrap());
        let layout = NodeStorageLayout::new(root.clone()).unwrap();
        let mut world = synergy_state::WorldState::default();
        world.accounts.insert(
            "alice".into(),
            synergy_state::AccountState {
                balance_nwei: 7,
                nonce: 3,
                code_hash: None,
            },
        );
        let material = synergy_etdag::execution::ProtectedProposalMaterial {
            material_version: 2,
            height: 1,
            execution_root: synergy_etdag::EtdagDigest::from_domain_bytes("test", b"execution"),
            next_batch_root: synergy_etdag::EtdagDigest::from_domain_bytes("test", b"batch"),
            cutoff_boundary_root: synergy_etdag::EtdagDigest::from_domain_bytes("test", b"cutoff"),
        };
        let mut candidate = ExecutionCandidate {
            resource_permit: None,
            height: 1,
            block_id: String::new(),
            parent_block_id: "genesis".into(),
            protected_execution_root: synergy_block::hash_block_bytes(
                &material.commitment_bytes().unwrap(),
            ),
            protected_material: material.into(),
            state_root: synergy_state::state_root(&world).unwrap(),
            transactions: vec![],
            receipts: vec![],
            state: Arc::new(world),
        };
        candidate.block_id = candidate.commitment_id().unwrap();
        CandidateStore::new(layout.blocks().join("execution-candidates"))
            .unwrap()
            .put_once(&candidate, &synergy_state::WorldState::default())
            .unwrap();
        FinalizedStateStore::load(layout.state().join("execution"))
            .unwrap()
            .commit_verified_world_state(
                synergy_state::FinalizedState {
                    finalized_height: 1,
                    finalized_block_id: candidate.block_id.clone(),
                    state_root: candidate.state_root.clone(),
                },
                &candidate.state,
            )
            .unwrap();
        let finality = FinalizedBlockRecord {
            height: 1,
            block_id: candidate.block_id.clone(),
            finality_certificate_id: "a".repeat(64),
            protected_execution_root: candidate.protected_execution_root.clone(),
        };
        FinalityStore::new(layout.consensus().join("posy"))
            .unwrap()
            .commit_exactly_once(&finality, None)
            .unwrap();
        for at_height in [None, Some(1)] {
            let account = service
                .query_store
                .account(&AccountQuery {
                    address: "alice".into(),
                    at_height,
                })
                .unwrap()
                .unwrap();
            assert_eq!(account.finalized_block_hash, candidate.block_id);
            assert_eq!(account.state_root, candidate.state_root);
            assert_eq!(account.balance_nwei, "7");
            assert_eq!(account.nonce, 3);
        }
        // Make account world reconstruction impossible. Repeated telemetry must
        // still bind the exact durable commitment without opening any world.
        let world_path = layout.blocks().join("execution-candidates/candidate-world");
        assert!(world_path.exists());
        fs::remove_dir_all(world_path).unwrap();
        // A transaction search need not load an empty block's World, but must
        // still verify all three durable commitment owners below.
        assert!(service
            .query_store
            .transaction(&TransactionQuery {
                transaction_id: "f".repeat(64),
            })
            .unwrap()
            .is_none());
        let dispatcher = RuntimeDispatcher {
            runtime: service.runtime,
            query_store: service.query_store,
            admission: None,
            preparation: None,
            network_identity: Some(VerifiedRpcNetwork {
                network_id: "test".into(),
                epoch: 1,
                genesis_hash: "a".repeat(64),
            }),
            telemetry_samples: Mutex::new(TelemetrySamples::default()),
        };
        for _ in 0..16 {
            let observed = dispatcher.chain_telemetry(json!({"at_height":1})).unwrap();
            assert_eq!(observed["finalized_height"], 1);
            assert_eq!(
                observed["common_finalized_commitment"]["block_id"],
                candidate.block_id
            );
            assert_eq!(
                observed["common_finalized_commitment"]["finality_certificate_id"],
                finality.finality_certificate_id
            );
            assert_eq!(observed["latest_sampled_block_transaction_count"], 0);
        }
        assert!(dispatcher
            .query_store
            .block(&BlockQuery {
                height: Some(1),
                hash: None
            })
            .is_err());
        assert!(dispatcher
            .query_store
            .account(&AccountQuery {
                address: "alice".into(),
                at_height: Some(1),
            })
            .is_err());
        let metadata_path = layout
            .blocks()
            .join("execution-candidates/candidate/00000000000000000001.json");
        let bytes = fs::read(&metadata_path).unwrap();
        let mut metadata: Value = serde_json::from_slice(&bytes[8..]).unwrap();
        metadata["block_id"] = "wrong".into();
        let mut bytes = b"SNCDV001".to_vec();
        bytes.extend(serde_json::to_vec(&metadata).unwrap());
        fs::write(metadata_path, bytes).unwrap();
        assert!(dispatcher.chain_telemetry(json!({})).is_err());
        assert!(dispatcher
            .query_store
            .transaction(&TransactionQuery {
                transaction_id: "f".repeat(64),
            })
            .is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn telemetry_retains_verified_identity_without_an_open_admission_context() {
        let root = std::env::temp_dir().join(format!(
            "rpc-identity-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let service = fixture(&root, "127.0.0.1:0".parse().unwrap());
        let admission = super::super::protected_admission::AdmissionHandle::default();
        admission
            .bind_ingress(super::super::ingress::AuthenticatedIngress::default())
            .unwrap();
        assert!(admission.context_v2().is_err());
        let dispatcher = RuntimeDispatcher {
            runtime: service.runtime,
            query_store: service.query_store,
            admission: Some(admission),
            preparation: None,
            network_identity: Some(VerifiedRpcNetwork {
                network_id: "verified-incarnation".into(),
                epoch: 7,
                genesis_hash: "a".repeat(64),
            }),
            telemetry_samples: Mutex::new(TelemetrySamples::default()),
        };
        let observed = dispatcher.chain_telemetry(json!({})).unwrap();
        assert_eq!(observed["network_identity"], "verified-incarnation");
        assert_eq!(observed["epoch"], 7);
        assert_eq!(observed["genesis_hash"], "a".repeat(64));
        assert!(observed["admission_window"].is_null());
        if root.exists() {
            fs::remove_dir_all(root).unwrap();
        }
    }

    fn fixture(root: &std::path::Path, address: std::net::SocketAddr) -> RpcService {
        RpcService {
            listen_address: address,
            limits: RpcLimits {
                max_body_bytes: 65536,
                max_concurrent_requests: 8,
                request_timeout_ms: 5000,
            },
            runtime: Arc::new(std::sync::RwLock::new(synergy_node_core::RuntimeSnapshot {
                node_name: "fixture".into(),
                role: "validator".into(),
                chain_id: 1266,
                lifecycle: synergy_node_core::NodeLifecycleState::Starting,
                services: vec![],
            })),
            query_store: Arc::new(CanonicalQueryStore::load(root).unwrap()),
            websocket_hub: Arc::new(WsServer::new(16, 16, 1024 * 1024).unwrap()),
            admission: None,
            preparation: None,
            network_identity: None,
            websocket_connections: vec![],
            pending_http: vec![],
            next_websocket_id: 0,
            listener: None,
            #[cfg(test)]
            reserved_listener: None,
            server: None,
        }
    }

    #[test]
    #[cfg(unix)]
    fn fixture_rpc_listener_handoff_drains_restart_backlog_and_preserves_reservation() {
        use std::{io::Read, os::fd::AsRawFd};
        let root = std::env::temp_dir().join(format!(
            "rpc-reservation-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let reservation = Arc::new(TcpListener::bind("127.0.0.1:0").unwrap());
        let address = reservation.local_addr().unwrap();
        let mut service = fixture(&root, address);
        service.reserved_listener = Some(Arc::clone(&reservation));
        service.start(&CancellationToken::default()).unwrap();
        service.stop().unwrap();
        assert!(TcpListener::bind(address).is_err());
        let deadline = Instant::now() + Duration::from_secs(1);
        let mut stale = TcpStream::connect(address).unwrap();
        // connect() may return before this listener exposes an accept-ready
        // backlog. Observe that precondition without consuming the connection;
        // start() must drain an actually queued socket, not race its arrival.
        // Readiness and EOF share the original one-second deadline.
        loop {
            let remaining = deadline
                .checked_duration_since(Instant::now())
                .expect("fixture connection did not enter the backlog before its deadline");
            let mut descriptor = libc::pollfd {
                fd: reservation.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            // SAFETY: descriptor is one initialized pollfd; reservation owns
            // its live FD for this non-consuming, bounded readiness observation.
            let observed = unsafe {
                libc::poll(
                    &mut descriptor,
                    1,
                    remaining.as_millis().max(1) as libc::c_int,
                )
            };
            if observed < 0 && std::io::Error::last_os_error().kind() == ErrorKind::Interrupted {
                continue;
            }
            assert_eq!(observed, 1, "fixture backlog readiness failed");
            assert_eq!(descriptor.revents, libc::POLLIN);
            break;
        }
        service.start(&CancellationToken::default()).unwrap();
        stale
            .set_read_timeout(Some(
                deadline
                    .checked_duration_since(Instant::now())
                    .expect("fixture restart exceeded its original deadline"),
            ))
            .unwrap();
        assert_eq!(stale.read(&mut [0; 1]).unwrap(), 0);
        assert!(reservation
            .accept()
            .is_err_and(|e| e.kind() == ErrorKind::WouldBlock));
        service.stop().unwrap();
        drop(service);
        assert!(TcpListener::bind(address).is_err());
        drop(reservation);
        if root.exists() {
            fs::remove_dir_all(root).unwrap();
        }
    }

    #[test]
    fn rpc_owner_serves_without_supervisor_socket_polling_and_joins_before_restart() {
        let root = std::env::temp_dir().join(format!(
            "rpc-owner-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let reservation = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = reservation.local_addr().unwrap();
        drop(reservation);
        let mut owner = super::super::owned_service::OwnedService::with_poll_interval(
            Box::new(fixture(&root, address)),
            "rpc-test-owner",
            RPC_OWNER_IDLE,
        );
        owner.start(&CancellationToken::default()).unwrap();
        let mut client = TcpStream::connect(address).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let body = br#"{"jsonrpc":"2.0","id":1,"method":"synergy_nodeStatus","params":{}}"#;
        client
            .write_all(
                format!("POST / HTTP/1.1\r\nContent-Length: {}\r\n\r\n", body.len()).as_bytes(),
            )
            .unwrap();
        client.write_all(body).unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).unwrap();
        assert!(String::from_utf8(response)
            .unwrap()
            .contains("HTTP/1.1 200"));
        // No owner.poll() call was needed to accept, read, dispatch or write.
        owner.stop().unwrap();
        assert!(TcpStream::connect(address).is_err());
        owner.start(&CancellationToken::default()).unwrap();
        assert!(TcpStream::connect(address).is_ok());
        owner.stop().unwrap();
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn websocket_capacity_counts_reserved_input_and_stalled_output() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let _client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (stream, _) = listener.accept().unwrap();
        let mut connection = WsConnection {
            stream,
            subscriber_id: "test".into(),
            read_buffer: Vec::with_capacity(100),
            writes: VecDeque::new(),
            write_offset: 0,
        };
        assert_eq!(connection.buffered_bytes(), 100);
        assert!(connection.queue_frame(1, &[0; 16], 126));
        let before = connection.buffered_bytes();
        assert!(!connection.queue_frame(1, &[0; 16], before + 25));
        assert_eq!(connection.buffered_bytes(), before);
        connection.read_buffer.clear();
        assert_eq!(connection.buffered_bytes(), before);
    }

    #[test]
    fn request_capacity_exhaustion_returns_backpressure_without_dispatch() {
        let root = std::env::temp_dir().join(format!(
            "rpc-bound-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let service = fixture(&root, "127.0.0.1:0".parse().unwrap());
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (stream, _) = listener.accept().unwrap();
        stream.set_nonblocking(true).unwrap();
        client
            .write_all(b"POST / HTTP/1.1\r\nContent-Length: 10\r\n\r\n0123456789")
            .unwrap();
        let mut pending = PendingHttp {
            stream,
            client_id: "fixture".into(),
            deadline: Instant::now() + Duration::from_secs(1),
            bytes: Vec::new(),
            response: None,
            offset: 0,
            upgrade: None,
            #[cfg(feature = "qualification-timing")]
            diagnostic_request: None,
        };
        // A nonblocking socket may need another poll before bytes arrive or
        // its bounded response is fully written; completion is not immediate.
        let deadline = Instant::now() + Duration::from_secs(1);
        loop {
            if service.poll_http_connection(&mut pending, 8, 4096).unwrap() {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "bounded overload response did not complete"
            );
            std::thread::sleep(Duration::from_millis(1));
        }
        assert_eq!(pending.bytes.capacity(), 0);
        assert!(std::str::from_utf8(pending.response.as_ref().unwrap())
            .unwrap()
            .starts_with("HTTP/1.1 503"));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn partial_http_clients_do_not_block_healthy_rpc_or_runtime_poll() {
        let root = std::env::temp_dir().join(format!(
            "rpc-nonblocking-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let runtime = Arc::new(std::sync::RwLock::new(synergy_node_core::RuntimeSnapshot {
            node_name: "fixture".into(),
            role: "validator".into(),
            chain_id: 1266,
            lifecycle: synergy_node_core::NodeLifecycleState::Starting,
            services: vec![],
        }));
        let mut service = RpcService {
            listen_address: "127.0.0.1:0".parse().unwrap(),
            limits: RpcLimits {
                max_body_bytes: 65536,
                max_concurrent_requests: 8,
                request_timeout_ms: 5000,
            },
            runtime,
            query_store: Arc::new(CanonicalQueryStore::load(&root).unwrap()),
            websocket_hub: Arc::new(WsServer::new(16, 16, 1024 * 1024).unwrap()),
            admission: None,
            preparation: None,
            network_identity: None,
            websocket_connections: vec![],
            pending_http: vec![],
            next_websocket_id: 0,
            listener: None,
            #[cfg(test)]
            reserved_listener: None,
            server: None,
        };
        service.start(&CancellationToken::default()).unwrap();
        let address = service.listener.as_ref().unwrap().local_addr().unwrap();
        let _idle = TcpStream::connect(address).unwrap();
        let mut partial = TcpStream::connect(address).unwrap();
        partial
            .write_all(b"POST / HTTP/1.1\r\nContent-Length: 30\r\n\r\n{")
            .unwrap();
        let mut healthy = TcpStream::connect(address).unwrap();
        let body = br#"{"jsonrpc":"2.0","id":1,"method":"synergy_nodeStatus","params":{}}"#;
        healthy
            .write_all(
                format!("POST / HTTP/1.1\r\nContent-Length: {}\r\n\r\n", body.len()).as_bytes(),
            )
            .unwrap();
        healthy.write_all(body).unwrap();
        healthy.set_nonblocking(true).unwrap();
        let started = Instant::now();
        let mut response = Vec::new();
        while started.elapsed() < Duration::from_secs(1) {
            let tick = Instant::now();
            service.poll().unwrap();
            assert!(tick.elapsed() < Duration::from_millis(250));
            let mut buffer = [0u8; 4096];
            match healthy.read(&mut buffer) {
                Ok(0) => break,
                Ok(count) => response.extend_from_slice(&buffer[..count]),
                Err(error) if error.kind() == ErrorKind::WouldBlock => {}
                Err(error) => panic!("{error}"),
            }
        }
        assert!(String::from_utf8(response)
            .unwrap()
            .contains("HTTP/1.1 200"));
        assert_eq!(service.pending_http.len(), 2);
        service.stop().unwrap();
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn partial_websocket_upgrade_preserves_handshake_frames_and_disconnect_cleanup() {
        let root = std::env::temp_dir().join(format!(
            "rpc-nonblocking-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let runtime = Arc::new(std::sync::RwLock::new(synergy_node_core::RuntimeSnapshot {
            node_name: "fixture".into(),
            role: "validator".into(),
            chain_id: 1266,
            lifecycle: synergy_node_core::NodeLifecycleState::Starting,
            services: vec![],
        }));
        let mut service = RpcService {
            listen_address: "127.0.0.1:0".parse().unwrap(),
            limits: RpcLimits {
                max_body_bytes: 65536,
                max_concurrent_requests: 8,
                request_timeout_ms: 5000,
            },
            runtime,
            query_store: Arc::new(CanonicalQueryStore::load(&root).unwrap()),
            websocket_hub: Arc::new(WsServer::new(16, 16, 1024 * 1024).unwrap()),
            admission: None,
            preparation: None,
            network_identity: None,
            websocket_connections: vec![],
            pending_http: vec![],
            next_websocket_id: 0,
            listener: None,
            #[cfg(test)]
            reserved_listener: None,
            server: None,
        };
        service.start(&CancellationToken::default()).unwrap();
        let address = service.listener.as_ref().unwrap().local_addr().unwrap();
        let mut client = TcpStream::connect(address).unwrap();
        client
            .write_all(b"GET /ws HTTP/1.1\r\nUpgrade: websocket\r\n")
            .unwrap();
        service.poll().unwrap();
        assert_eq!(service.pending_http.len(), 1);
        assert!(service.websocket_connections.is_empty());
        client.write_all(b"Connection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n").unwrap();
        client.set_nonblocking(true).unwrap();
        let mut response = Vec::new();
        let deadline = Instant::now() + Duration::from_secs(1);
        while Instant::now() < deadline {
            service.poll().unwrap();
            let mut buffer = [0u8; 1024];
            match client.read(&mut buffer) {
                Ok(count) => response.extend_from_slice(&buffer[..count]),
                Err(error) if error.kind() == ErrorKind::WouldBlock => {}
                Err(error) => panic!("{error}"),
            }
            if response.windows(4).any(|part| part == b"\r\n\r\n") {
                break;
            }
        }
        let headers = String::from_utf8(response).unwrap();
        assert!(headers.starts_with("HTTP/1.1 101 Switching Protocols\r\n"));
        assert!(headers.contains("Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n"));
        assert_eq!(service.websocket_connections.len(), 1);
        let subscriber = service.websocket_connections[0].subscriber_id.clone();
        // A genuine masked ping must be answered by the existing frame owner.
        client
            .write_all(&[0x89, 0x81, 1, 2, 3, 4, b'x' ^ 1])
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(1);
        let mut pong = Vec::new();
        while Instant::now() < deadline && pong.len() < 3 {
            service.poll().unwrap();
            let mut buffer = [0u8; 16];
            match client.read(&mut buffer) {
                Ok(count) => pong.extend_from_slice(&buffer[..count]),
                Err(error) if error.kind() == ErrorKind::WouldBlock => {}
                Err(error) => panic!("{error}"),
            }
        }
        assert_eq!(pong, vec![0x8a, 1, b'x']);
        drop(client);
        let deadline = Instant::now() + Duration::from_secs(1);
        while Instant::now() < deadline && !service.websocket_connections.is_empty() {
            service.poll().unwrap();
        }
        assert!(service.websocket_connections.is_empty());
        assert!(!service.websocket_hub.unsubscribe(&subscriber).unwrap());
        service.stop().unwrap();
        fs::remove_dir_all(root).unwrap();
    }
}
