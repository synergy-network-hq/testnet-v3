//! Full-width native read adapters over the actual R1 finalized store.
//! A verified Genesis token is required for construction. Durable store facts
//! and original public proof bytes are not independent PoSy proof verification.
//! No historical32 key, JSON hashing or invented finality is used here.
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use serde_json::{json, Value};
use std::{
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};
use synergy_genesis::r1::VerifiedR1Genesis;
use synergy_node_core::RuntimeView;
use synergy_protocol_types::{R1NetworkCoordinate, R1ProfileRef};
use synergy_rpc::{
    methods::{AccountQuery, BlockQuery, TransactionQuery},
    provider::{
        CanonicalReadProvider, FinalizedAccountView, FinalizedBlockView, FinalizedTransactionView,
        ReadContract,
    },
    r1_read::{self, AccountArgs, BlockArgs, BlockRead, EmptyArgs, TransactionArgs},
    RpcError,
};
use synergy_state::r1_finalized::{
    R1BlockRead as StoredBlockRead, R1FinalizedAnchor, R1FinalizedStore, R1TransactionStatus,
};
use synergy_state::world_resources::WorldResourceBudget;

#[cfg(test)]
#[path = "rpc_r1_tests.rs"]
mod tests;

/// A managed injected R1 provider selects the narrow read-wire allowlist.
/// Every other method keeps the existing independent access classification.
pub(crate) struct ManagedReadAuthenticator {
    contract: ReadContract,
}
impl ManagedReadAuthenticator {
    pub(crate) fn new(contract: ReadContract) -> Self {
        Self { contract }
    }
}
impl synergy_rpc::auth::RpcAuthenticator for ManagedReadAuthenticator {
    fn authorize(&self, method: &str, credential: Option<&str>) -> Result<(), RpcError> {
        if self.contract == ReadContract::NativeR1V1 && r1_read::is_method(method) {
            Ok(())
        } else {
            synergy_rpc::auth::RpcAuthenticator::authorize(
                &synergy_rpc::auth::PublicOnlyAuthenticator,
                method,
                credential,
            )
        }
    }
}

/// Managed runtime capacity, never supplied by public RPC arguments.
#[derive(Clone, Copy)]
pub(crate) struct R1ReadCapacity {
    pub request_timeout: Duration,
    pub maximum_hashes: u64,
    pub maximum_response_bytes: usize,
}

pub(crate) struct CanonicalR1QueryStore {
    root: PathBuf,
    genesis: Arc<VerifiedR1Genesis>,
    runtime: RuntimeView,
    world_budget: Arc<WorldResourceBudget>,
    capacity: R1ReadCapacity,
}
impl CanonicalR1QueryStore {
    fn response_capacity(
        &self,
        floor: usize,
    ) -> Result<Option<synergy_rpc::provider::RpcResponseCapacity>, RpcError> {
        let peak = self
            .capacity
            .maximum_response_bytes
            .max(floor)
            .checked_mul(3)
            .and_then(|n| n.checked_add(1024))
            .ok_or_else(|| fault("response capacity overflow"))?;
        let permit = self.world_budget.reserve(peak).map_err(fault)?;
        synergy_rpc::provider::RpcResponseCapacity::new(
            self.capacity.maximum_response_bytes,
            Box::new(permit),
        )
        .map(Some)
    }
    pub(crate) fn open(
        root: PathBuf,
        genesis: Arc<VerifiedR1Genesis>,
        runtime: RuntimeView,
        world_budget: Arc<WorldResourceBudget>,
        capacity: R1ReadCapacity,
    ) -> Result<Self, RpcError> {
        // `genesis` has no public bool/data constructor. Its owner verifies the
        // exact artifact, independent pinned PQ roots and activated profiles.
        genesis.coordinate().validate().map_err(fault)?;
        if capacity.request_timeout.is_zero()
            || capacity.maximum_hashes == 0
            || capacity.maximum_response_bytes < 256
            || capacity.maximum_response_bytes
                > super::MAX_AGGREGATE_HTTP_RESPONSE_BYTES.saturating_sub(1024)
            || Instant::now()
                .checked_add(capacity.request_timeout)
                .is_none()
        {
            return Err(fault("invalid runtime read capacity"));
        }
        if runtime.read().map_err(fault)?.chain_id != genesis.coordinate().network.chain_id {
            return Err(fault("runtime chain mismatch"));
        }
        // No store creation/recovery here. A node still acquiring its state can
        // report actual runtime readiness; state reads independently refuse a
        // missing store through the read-only constructor below.
        Ok(Self {
            root,
            genesis,
            runtime,
            world_budget,
            capacity,
        })
    }
    fn store(&self) -> Result<R1FinalizedStore, RpcError> {
        // Open the current atomic pointer once per read. Never mix observations
        // from separately reopened stores inside the same response.
        let deadline = Instant::now()
            .checked_add(self.capacity.request_timeout)
            .ok_or_else(|| fault("read deadline overflow"))?;
        let store = R1FinalizedStore::open_with_budget(
            &self.root,
            self.genesis.coordinate(),
            Arc::clone(&self.world_budget),
            deadline,
            self.capacity.maximum_hashes,
        )
        .map_err(fault)?;
        if store.current_anchor().is_none() {
            return Err(fault("no stored anchor"));
        }
        Ok(store)
    }
    fn anchor(&self, anchor: &R1FinalizedAnchor) -> Result<Value, RpcError> {
        anchor
            .coordinate
            .ensure_matches(self.genesis.coordinate())
            .map_err(fault)?;
        Ok(json!({"height":anchor.height.to_string(),
            "block_commitment":commitment(self.genesis.block_profile(),&anchor.block_digest),
            "state_commitment":commitment(self.genesis.state_profile(),&anchor.state_root)}))
    }
    fn response(&self, request_id: String, result: Value) -> Value {
        json!({"api_version":1,"request_id":request_id,
            "network":coordinate(self.genesis.coordinate()),"result":result,
            "proof_profile_status":"STORED_PROJECTION_REQUIRES_INDEPENDENT_POSY_VERIFICATION",
            "finality_verified_by_rpc":false})
    }
    fn block_value(&self, read: &StoredBlockRead) -> Result<Value, RpcError> {
        if &read.block_profile != self.genesis.block_profile()
            || &read.receipt_profile != self.genesis.receipt_profile()
        {
            return Err(fault("stored profile mismatch"));
        }
        Ok(json!({"stored_anchor":self.anchor(&read.anchor)?,
            "parent_block_commitment":commitment(&read.block_profile,&read.parent_block_digest),
            "epoch":read.epoch.to_string(),"transactions":read.transactions,
            "receipts_commitment":commitment(&read.receipt_profile,&read.receipts_root),
            "public_finality_proof":{"encoding":"base64","value":BASE64.encode(&read.public_finality_proof)}}))
    }
}
fn fault(_: impl std::fmt::Display) -> RpcError {
    RpcError::unavailable("R1 canonical read unavailable")
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn profile(profile: &R1ProfileRef) -> Value {
    json!({"name":profile.name,"revision":profile.revision})
}
fn commitment(profile_ref: &R1ProfileRef, digest: &[u8; 48]) -> Value {
    json!({"profile":profile(profile_ref),"algorithm":"SHA3-384",
        "encoding":"lowercase-hex","value":hex(digest)})
}
fn coordinate(coordinate: &R1NetworkCoordinate) -> Value {
    json!({"chain_id":coordinate.network.chain_id.to_string(),
        "network_incarnation_commitment":{"algorithm":"SHA3-512","encoding":"lowercase-hex","value":hex(&coordinate.network.nic)},
        "genesis_commitment":commitment(&coordinate.genesis.profile,&coordinate.genesis.digest),
        "activated_profiles":{"profile":profile(&coordinate.activated_profiles.profile),"algorithm":"SHA3-512","encoding":"lowercase-hex","value":hex(&coordinate.activated_profiles.commitment)},
        "identity_profile":{"name":"APQE-NATIVE-ID","revision":1},"presentation_version":2})
}
impl CanonicalReadProvider for CanonicalR1QueryStore {
    fn reserve_response_capacity(
        &self,
    ) -> Result<Option<synergy_rpc::provider::RpcResponseCapacity>, RpcError> {
        // Store bounds: public proof <=4MiB plus <=1021 full transaction IDs.
        // Reserve conservative simultaneous owned projection/base64/JSON/HTTP
        // buffers from the same actual process budget, held through HTTP write.
        self.response_capacity(8 * 1024 * 1024)
    }
    fn reserve_response_capacity_for(
        &self,
        method: &str,
    ) -> Result<Option<synergy_rpc::provider::RpcResponseCapacity>, RpcError> {
        // Complete receipt originals add up to1021*(4096+512) bytes before
        // base64/JSON/HTTP buffers; retain the larger shared guard until write.
        if method == "synergy_getBlockReceipts" {
            self.response_capacity(16 * 1024 * 1024)
        } else {
            self.reserve_response_capacity()
        }
    }
    fn read_contract(&self) -> ReadContract {
        ReadContract::NativeR1V1
    }
    fn r1_read(&self, method: &str, params: Value) -> Result<Value, RpcError> {
        let expected = self.genesis.coordinate();
        match method {
            "synergy_getProof" => {
                let query = r1_read::decode::<AccountArgs>(params, expected)?;
                let read = self
                    .store()?
                    .account_with_proof(&query.args.identity, query.args.at_height)
                    .map_err(fault)?
                    .ok_or_else(|| fault("account proof unavailable"))?;
                let result = (|| {
                    if read.identity != query.args.identity.to_text() {
                        return Err(fault("proof identity mismatch"));
                    }
                    let leaves=read.leaves.into_iter().map(|leaf| {
                        let domain=match leaf.key.domain {
                            synergy_state::r1::R1StateDomain::NativeBalance=>"native_balance",
                            synergy_state::r1::R1StateDomain::ReplayCoordinate=>"replay_coordinate",
                            synergy_state::r1::R1StateDomain::AccountAuthorization=>"account_authorization",
                            _=>return Err(fault("unsupported account proof domain")),
                        };
                        let key=leaf.key.canonical_bytes().map_err(fault)?;
                        let value=leaf.value.map(|v|v.canonical_bytes().map_err(fault)).transpose()?;
                        Ok(json!({"domain":domain,
                            "key":{"codec":"QACE-C14N-02","encoding":"base64","value":BASE64.encode(key)},
                            "value":value.map(|v|json!({"codec":"QACE-C14N-02","encoding":"base64","value":BASE64.encode(v)})),
                            "proof":{"profile":profile(self.genesis.state_profile()),"bitmap":hex(&leaf.proof.bitmap),
                                "siblings":leaf.proof.siblings.iter().map(|s|hex(s)).collect::<Vec<_>>()}}))
                    }).collect::<Result<Vec<_>,RpcError>>()?;
                    Ok::<_, RpcError>(
                        json!({"stored_anchor":self.anchor(&read.anchor)?,"identity":read.identity,"leaves":leaves}),
                    )
                })()?;
                Ok(self.response(query.request_id, result))
            }
            "synergy_getBlockReceipts" => {
                let query = r1_read::decode::<BlockArgs>(params, expected)?;
                if let BlockRead::Commitment { profile, .. } = &query.args {
                    if profile != self.genesis.block_profile() {
                        return Err(RpcError::invalid_params("block profile mismatch"));
                    }
                }
                let store = self.store()?;
                let (height, requested_digest) = match query.args {
                    BlockRead::Height(h) => (Some(h), None),
                    BlockRead::Commitment { digest, .. } => (
                        store
                            .block_by_digest(digest)
                            .map_err(fault)?
                            .map(|b| b.anchor.height),
                        Some(digest),
                    ),
                };
                let read = height
                    .map(|h| store.block_receipts(h).map_err(fault))
                    .transpose()?
                    .flatten()
                    .ok_or_else(|| fault("original block receipts unavailable"))?;
                let result = (|| {
                    if requested_digest.is_some_and(|d| d != read.block.anchor.block_digest) {
                        return Err(fault("receipt block mismatch"));
                    }
                    Ok::<_, RpcError>(json!({"block":self.block_value(&read.block)?,
                        "canonical_receipt_cores":read.canonical_receipt_cores.iter().map(|core|
                            json!({"codec":"QACE-C14N-02","encoding":"base64","value":BASE64.encode(core)})).collect::<Vec<_>>()}))
                })()?;
                Ok(self.response(query.request_id, result))
            }
            "synergy_getChainId"
            | "synergy_chainId"
            | "synergy_networkId"
            | "synergy_genesisHash" => {
                let query = r1_read::decode::<EmptyArgs>(params, expected)?;
                let result = match method {
                    "synergy_networkId" => coordinate(expected),
                    "synergy_genesisHash" => {
                        commitment(&expected.genesis.profile, &expected.genesis.digest)
                    }
                    _ => json!({"chain_id":expected.network.chain_id.to_string()}),
                };
                let mut response = self.response(query.request_id, result);
                response["proof_profile_status"] =
                    json!("AUTHENTICATED_GENESIS_REFERENCE_NOT_CURRENT_FINALITY");
                Ok(response)
            }
            "synergy_getHealth"
            | "synergy_getHealthCheck"
            | "synergy_getReadiness"
            | "synergy_getNodeStatus"
            | "synergy_nodeInfo"
            | "synergy_ping" => {
                let query = r1_read::decode::<EmptyArgs>(params, expected)?;
                let runtime = self.runtime.read().map_err(fault)?;
                if runtime.chain_id != expected.network.chain_id {
                    return Err(fault("runtime chain mismatch"));
                }
                if runtime.node_name.len() > 128
                    || runtime.role.len() > 64
                    || runtime.services.len() > 64
                    || runtime.services.iter().any(|s| s.id.as_str().len() > 128)
                {
                    return Err(fault("runtime observation exceeds selected bounds"));
                }
                let services=runtime.services.iter().map(|service|json!({
                    "id":service.id.as_str(),"state":service.state,
                    "health":match service.health {synergy_node_core::ServiceHealth::Healthy=>"healthy",synergy_node_core::ServiceHealth::Degraded{..}=>"degraded",synergy_node_core::ServiceHealth::Unhealthy{..}=>"unhealthy"},
                    "readiness":match service.readiness {synergy_node_core::ServiceReadiness::Ready=>"ready",synergy_node_core::ServiceReadiness::Pending{..}=>"pending",synergy_node_core::ServiceReadiness::Blocked{..}=>"blocked"},
                })).collect::<Vec<_>>();
                let result = if method == "synergy_ping" {
                    json!({"scope":"RPC_LIVENESS_ONLY","responding":true})
                } else {
                    json!({"scope":"NODE_RUNTIME_OBSERVATION","node_name":runtime.node_name,
                        "role":runtime.role,"chain_id":runtime.chain_id.to_string(),
                        "lifecycle":runtime.lifecycle,"services":services,"ready":runtime.ready()})
                };
                let mut response = self.response(query.request_id, result);
                response["proof_profile_status"] = json!("NOT_APPLICABLE_RUNTIME_OBSERVATION");
                Ok(response)
            }
            "synergy_getAccount"
            | "synergy_getBalance"
            | "synergy_getAccountNonce"
            | "synergy_getNonce" => {
                let query = r1_read::decode::<AccountArgs>(params, expected)?;
                let read = self
                    .store()?
                    .account(&query.args.identity, query.args.at_height)
                    .map_err(fault)?;
                let result=read.map(|read| {
                    if read.identity!=query.args.identity.to_text() { return Err(fault("account key mismatch")); }
                    let anchor=self.anchor(&read.anchor)?;
                    Ok(match method {
                        "synergy_getBalance"=>json!({"stored_anchor":anchor,"identity":read.identity,"balance_nwei":read.balance_nwei.to_string()}),
                        "synergy_getAccountNonce"|"synergy_getNonce"=>json!({"stored_anchor":anchor,"identity":read.identity,"nonce":read.nonce.to_string()}),
                        _=>json!({"stored_anchor":anchor,"identity":read.identity,"balance_nwei":read.balance_nwei.to_string(),"nonce":read.nonce.to_string(),"policy_epoch":read.policy_epoch.map(|epoch|epoch.to_string())}),
                    })
                }).transpose()?.unwrap_or(Value::Null);
                Ok(self.response(query.request_id, result))
            }
            "synergy_getTransaction"
            | "synergy_getTransactionByHash"
            | "synergy_getReceipt"
            | "synergy_getTransactionFees"
            | "synergy_getTransactionReceipt"
            | "synergy_getTransactionStatus" => {
                let query = r1_read::decode::<TransactionArgs>(params, expected)?;
                let read = self.store()?.transaction(&query.args).map_err(fault)?;
                let result=read.map(|read| {
                    if read.transaction_id!=query.args.to_text() { return Err(fault("transaction key mismatch")); }
                    let status=match read.status { R1TransactionStatus::Applied=>"applied",R1TransactionStatus::Reverted=>"reverted",R1TransactionStatus::ResourceExhausted=>"resource_exhausted" };
                    Ok(if method=="synergy_getTransactionStatus" {
                        json!({"stored_anchor":self.anchor(&read.anchor)?,"transaction_id":read.transaction_id,"status":status})
                    } else if method=="synergy_getTransactionFees" {
                        json!({"stored_anchor":self.anchor(&read.anchor)?,"transaction_id":read.transaction_id,"fee_paid_nwei":read.fee_paid_nwei.to_string()})
                    } else {
                        json!({"stored_anchor":self.anchor(&read.anchor)?,"transaction_id":read.transaction_id,"status":status,
                            "gas_used":read.gas_used.to_string(),"fee_paid_nwei":read.fee_paid_nwei.to_string(),
                            "receipt_profile":profile(self.genesis.receipt_profile()),
                            "events_commitment":{"encoding":"lowercase-hex","value":hex(&read.events_commitment)},"error_code":read.error_code})
                    })
                }).transpose()?.unwrap_or(Value::Null);
                Ok(self.response(query.request_id, result))
            }
            "synergy_getBlock"
            | "synergy_getBlockByHash"
            | "synergy_getBlockByNumber"
            | "synergy_getBlockTransactionCount"
            | "synergy_getTransactionsInBlock" => {
                let query = r1_read::decode::<BlockArgs>(params, expected)?;
                let store = self.store()?;
                let read = match query.args {
                    BlockRead::Height(height) => {
                        if method == "synergy_getBlockByHash" {
                            return Err(RpcError::invalid_params(
                                "block commitment selector required",
                            ));
                        }
                        store.block(height)
                    }
                    BlockRead::Commitment { profile, digest } => {
                        if method == "synergy_getBlockByNumber" {
                            return Err(RpcError::invalid_params("block height selector required"));
                        }
                        if &profile != self.genesis.block_profile() {
                            return Err(RpcError::invalid_params("block profile mismatch"));
                        }
                        store.block_by_digest(digest)
                    }
                }
                .map_err(fault)?;
                let result=read.map(|read| {
                    let complete=self.block_value(&read)?;
                    Ok(match method {
                        "synergy_getBlockTransactionCount"=>json!({"stored_anchor":self.anchor(&read.anchor)?,"transaction_count":read.transactions.len().to_string()}),
                        "synergy_getTransactionsInBlock"=>json!({"stored_anchor":self.anchor(&read.anchor)?,"transactions":read.transactions}),
                        _=>complete,
                    })
                }).transpose()?.unwrap_or(Value::Null);
                Ok(self.response(query.request_id, result))
            }
            "synergy_getFinalizedHead"
            | "synergy_getLatestBlock"
            | "synergy_getBlockNumber"
            | "synergy_blockNumber" => {
                let query = r1_read::decode::<EmptyArgs>(params, expected)?;
                let store = self.store()?;
                let result = match method {
                    "synergy_getLatestBlock" => store.current_anchor().map(|anchor| {
                        store.block(anchor.height).map_err(fault)?.map(|read|self.block_value(&read)).transpose()
                    }).transpose()?.flatten().unwrap_or(Value::Null),
                    "synergy_getBlockNumber" | "synergy_blockNumber" => store
                        .current_anchor()
                        .map(|a| json!(a.height.to_string()))
                        .unwrap_or(Value::Null),
                    _ => store.current_anchor().map(|anchor| {
                        let block=store.block(anchor.height).map_err(fault)?;
                        Ok::<_,RpcError>(json!({"stored_anchor":self.anchor(anchor)?,
                            "public_finality_proof":block.as_ref().map(|read|json!({"encoding":"base64","value":BASE64.encode(&read.public_finality_proof)}))}))
                    }).transpose()?.unwrap_or(Value::Null),
                };
                Ok(self.response(query.request_id, result))
            }
            _ => Err(RpcError::method_not_found()),
        }
    }
    // Historical32 APIs are deliberately not a fallback for this provider.
    fn latest_finalized_height(&self) -> Result<Option<u64>, RpcError> {
        Err(fault("use R1 envelope"))
    }
    fn block(&self, _: &BlockQuery) -> Result<Option<FinalizedBlockView>, RpcError> {
        Err(fault("use R1 envelope"))
    }
    fn transaction(
        &self,
        _: &TransactionQuery,
    ) -> Result<Option<FinalizedTransactionView>, RpcError> {
        Err(fault("use R1 envelope"))
    }
    fn account(&self, _: &AccountQuery) -> Result<Option<FinalizedAccountView>, RpcError> {
        Err(fault("use R1 envelope"))
    }
}
