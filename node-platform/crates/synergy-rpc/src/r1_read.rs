//! Selected R1 read transport candidate. Identity R1 pp265–271 and QACE R1
//! M03/M06 require complete identifiers and an exact runtime coordinate.
//! Parsing/matching is not authentication. Production handlers must obtain
//! `expected` from the private verified Genesis/authority owner, never RPC input.
//! These DTOs do not reinterpret historical storage, issue identities or activate
//! routes. Public read API version 1 is separate from QACE logical API 3.
use serde::de::DeserializeOwned;
use serde::Deserialize;
use serde_json::Value;
use synergy_address::r1_public::{NativeIdentityPresentation, TransactionIdentifierPresentation};
use synergy_protocol_types::{
    R1GenesisReference, R1NetworkCoordinate, R1NetworkRef, R1ProfileRef, R1ProfileSetReference,
};

use crate::RpcError;

/// Candidate native read adapters. Public transport exposure is separately
/// gated and never implied by inclusion here or by a provider profile label.
pub const METHODS: &[&str] = &[
    "synergy_getAccount",
    "synergy_getProof",
    "synergy_getFinalizedProofPageV1",
    "synergy_getBlock",
    "synergy_getBlockRange",
    "synergy_getBlockReceipts",
    "synergy_getTransaction",
    "synergy_getTransactionByBlockHashAndIndex",
    "synergy_getTransactionByBlockNumberAndIndex",
    "synergy_getBalance",
    "synergy_getAccountNonce",
    "synergy_getBlockNumber",
    "synergy_getFinalizedHead",
    "synergy_getTransactionReceipt",
    "synergy_getTransactionStatus",
    "synergy_getChainId",
    "synergy_genesisHash",
    "synergy_getNonce",
    "synergy_getTransactionByHash",
    "synergy_getReceipt",
    "synergy_getTransactionFees",
    "synergy_getBlockByHash",
    "synergy_getBlockByNumber",
    "synergy_getBlockTransactionCount",
    "synergy_getTransactionsInBlock",
    "synergy_getLatestBlock",
    "synergy_blockNumber",
    "synergy_chainId",
    "synergy_networkId",
    "synergy_getHealth",
    "synergy_getHealthCheck",
    "synergy_getReadiness",
    "synergy_getNodeStatus",
    "synergy_nodeInfo",
    "synergy_ping",
    "synergy_systemVersion",
    "synergy_nodeStatus",
    "synergy_chainStatus",
    "synergy_syncStatus",
    "synergy_posyStatus",
    "synergy_etdagStatus",
];
pub fn is_method(method: &str) -> bool {
    METHODS.contains(&method)
}

/// Stateless current-read carrier validation. `expected` must come from the
/// independently confirmed transport/runtime owner. This checks syntax/context,
/// not that owner's authentication, ledger availability or block-profile proof.
pub fn preflight(
    method: &str,
    params: Value,
    expected: &R1NetworkCoordinate,
) -> Result<(), RpcError> {
    match method {
        "synergy_getBlockRange"=>{decode::<BlockRangeArgs>(params,expected)?;}
        "synergy_getTransactionByBlockHashAndIndex"|"synergy_getTransactionByBlockNumberAndIndex"=>{
            let query=decode::<TransactionInBlockArgs>(params,expected)?;
            if (method=="synergy_getTransactionByBlockHashAndIndex")!=matches!(query.args.block,BlockRead::Commitment{..}) { return Err(invalid()); }
        }
        "synergy_getFinalizedProofPageV1" => { decode::<FinalityProofPageArgs>(params, expected)?; }
        "synergy_getAccount"
        | "synergy_getProof"
        | "synergy_getBalance"
        | "synergy_getAccountNonce"
        | "synergy_getNonce" => {
            decode::<AccountArgs>(params, expected)?;
        }
        "synergy_getTransaction"
        | "synergy_getTransactionByHash"
        | "synergy_getTransactionReceipt"
        | "synergy_getReceipt"
        | "synergy_getTransactionStatus"
        | "synergy_getTransactionFees" => {
            decode::<TransactionArgs>(params, expected)?;
        }
        "synergy_getBlock"
        | "synergy_getBlockReceipts"
        | "synergy_getBlockTransactionCount"
        | "synergy_getTransactionsInBlock" => {
            decode::<BlockArgs>(params, expected)?;
        }
        "synergy_getBlockByHash" => {
            if !matches!(
                decode::<BlockArgs>(params, expected)?.args,
                BlockRead::Commitment { .. }
            ) {
                return Err(invalid());
            }
        }
        "synergy_getBlockByNumber" => {
            if !matches!(
                decode::<BlockArgs>(params, expected)?.args,
                BlockRead::Height(_)
            ) {
                return Err(invalid());
            }
        }
        "synergy_getFinalizedHead"
        | "synergy_getLatestBlock"
        | "synergy_getBlockNumber"
        | "synergy_blockNumber"
        | "synergy_getChainId"
        | "synergy_chainId"
        | "synergy_networkId"
        | "synergy_genesisHash"
        | "synergy_getHealth"
        | "synergy_getHealthCheck"
        | "synergy_getReadiness"
        | "synergy_getNodeStatus"
        | "synergy_nodeInfo"
        | "synergy_ping"
        | "synergy_systemVersion"
        | "synergy_nodeStatus"
        | "synergy_chainStatus"
        | "synergy_syncStatus"
        | "synergy_posyStatus"
        | "synergy_etdagStatus" => {
            decode::<EmptyArgs>(params, expected)?;
        }
        _ => return Err(RpcError::method_not_found()),
    }
    Ok(())
}

fn invalid() -> RpcError {
    RpcError::invalid_params("invalid R1 read request")
}

fn decimal(value: &str) -> Result<u64, RpcError> {
    if value.is_empty()
        || value.len() > 20
        || (value.len() > 1 && value.starts_with('0'))
        || !value.bytes().all(|b| b.is_ascii_digit())
    {
        return Err(invalid());
    }
    value.parse().map_err(|_| invalid())
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileWire {
    pub name: String,
    pub revision: u32,
}
impl ProfileWire {
    fn typed(&self) -> Result<R1ProfileRef, RpcError> {
        let profile = R1ProfileRef {
            name: self.name.clone(),
            revision: self.revision,
        };
        profile.validate().map_err(|_| invalid())?;
        Ok(profile)
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DigestWire {
    pub algorithm: String,
    pub encoding: String,
    pub value: String,
}
impl DigestWire {
    fn bytes<const N: usize>(&self, algorithm: &str) -> Result<[u8; N], RpcError> {
        if self.algorithm != algorithm
            || self.encoding != "lowercase-hex"
            || self.value.len() != N * 2
            || !self
                .value
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(invalid());
        }
        let mut bytes = [0; N];
        for (index, pair) in self.value.as_bytes().chunks_exact(2).enumerate() {
            let nibble = |b: u8| if b <= b'9' { b - b'0' } else { b - b'a' + 10 };
            bytes[index] = (nibble(pair[0]) << 4) | nibble(pair[1]);
        }
        Ok(bytes)
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileCommitmentWire {
    pub profile: ProfileWire,
    pub algorithm: String,
    pub encoding: String,
    pub value: String,
}
impl ProfileCommitmentWire {
    fn bytes<const N: usize>(&self, algorithm: &str) -> Result<[u8; N], RpcError> {
        DigestWire {
            algorithm: self.algorithm.clone(),
            encoding: self.encoding.clone(),
            value: self.value.clone(),
        }
        .bytes(algorithm)
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkCoordinateWire {
    pub chain_id: String,
    pub network_incarnation_commitment: DigestWire,
    pub genesis_commitment: ProfileCommitmentWire,
    pub activated_profiles: ProfileCommitmentWire,
    pub identity_profile: ProfileWire,
    pub presentation_version: u8,
}
impl NetworkCoordinateWire {
    pub fn typed(&self) -> Result<R1NetworkCoordinate, RpcError> {
        if self.identity_profile.name != "APQE-NATIVE-ID"
            || self.identity_profile.revision != 1
            || self.presentation_version != 2
            || self.genesis_commitment.profile.name != "SYNERGY-GENESIS-R1"
            || self.genesis_commitment.profile.revision != 1
        {
            return Err(invalid());
        }
        let coordinate = R1NetworkCoordinate {
            network: R1NetworkRef {
                chain_id: decimal(&self.chain_id)?,
                nic: self.network_incarnation_commitment.bytes("SHA3-512")?,
            },
            genesis: R1GenesisReference {
                profile: self.genesis_commitment.profile.typed()?,
                digest: self.genesis_commitment.bytes("SHA3-384")?,
            },
            activated_profiles: R1ProfileSetReference {
                profile: self.activated_profiles.profile.typed()?,
                commitment: self.activated_profiles.bytes("SHA3-512")?,
            },
        };
        coordinate.validate().map_err(|_| invalid())?;
        Ok(coordinate)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope<A> {
    api_version: u16,
    request_id: String,
    caller_scope: String,
    network: NetworkCoordinateWire,
    args: A,
}

/// Exact caller/expected coordinate match only; this value is not an authority
/// token. The request ID is a local correlation value, never a canonical digest.
#[derive(Debug)]
pub struct MatchedReadRequest<T> {
    pub request_id: String,
    pub coordinate: R1NetworkCoordinate,
    pub args: T,
}

pub trait ReadArguments: DeserializeOwned {
    type Parsed;
    fn parse(self) -> Result<Self::Parsed, RpcError>;
}

pub fn decode<A: ReadArguments>(
    params: Value,
    expected: &R1NetworkCoordinate,
) -> Result<MatchedReadRequest<A::Parsed>, RpcError> {
    // Serde structs can also deserialize positional arrays. This selected wire
    // contract permits only named JSON objects, including every nested tag.
    for pointer in [
        "",
        "/network",
        "/network/network_incarnation_commitment",
        "/network/genesis_commitment",
        "/network/genesis_commitment/profile",
        "/network/activated_profiles",
        "/network/activated_profiles/profile",
        "/network/identity_profile",
        "/args",
    ] {
        if !params.pointer(pointer).is_some_and(Value::is_object) {
            return Err(invalid());
        }
    }
    if let Some(commitment) = params
        .pointer("/args/block_commitment")
        .filter(|v| !v.is_null())
    {
        if !commitment.is_object() || !commitment.get("profile").is_some_and(Value::is_object) {
            return Err(invalid());
        }
    }
    if params.pointer("/args/expected_transport_digest").is_some_and(|v|!v.is_null() && !v.is_object()) { return Err(invalid()); }
    let envelope: Envelope<A> = serde_json::from_value(params).map_err(|_| invalid())?;
    if envelope.api_version != 1
        || envelope.caller_scope != "public_read"
        || envelope.request_id.is_empty()
        || envelope.request_id.len() > 128
        || !envelope.request_id.bytes().all(|b| b.is_ascii_graphic())
    {
        return Err(invalid());
    }
    let coordinate = envelope.network.typed()?;
    coordinate.ensure_matches(expected).map_err(|_| RpcError {
        code: -32010,
        message: "CONTEXT_MISMATCH".into(),
        data: None,
    })?;
    let args = envelope.args.parse()?;
    Ok(MatchedReadRequest {
        request_id: envelope.request_id,
        coordinate,
        args,
    })
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EmptyArgs {}
impl ReadArguments for EmptyArgs {
    type Parsed = ();
    fn parse(self) -> Result<(), RpcError> {
        Ok(())
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountArgs {
    pub address: String,
    pub at_height: Option<String>,
}
#[derive(Debug)]
pub struct AccountRead {
    pub identity: NativeIdentityPresentation,
    pub at_height: Option<u64>,
}
impl ReadArguments for AccountArgs {
    type Parsed = AccountRead;
    fn parse(self) -> Result<Self::Parsed, RpcError> {
        let identity = NativeIdentityPresentation::parse(&self.address).map_err(|_| invalid())?;
        if !matches!(
            identity.namespace(),
            "synw" | "syns" | "syna" | "synm" | "synu" | "synq"
        ) {
            return Err(invalid());
        }
        Ok(AccountRead {
            identity,
            at_height: self.at_height.as_deref().map(decimal).transpose()?,
        })
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransactionArgs {
    pub transaction_id: String,
}
impl ReadArguments for TransactionArgs {
    type Parsed = TransactionIdentifierPresentation;
    fn parse(self) -> Result<Self::Parsed, RpcError> {
        let parsed = TransactionIdentifierPresentation::parse(&self.transaction_id)
            .map_err(|_| invalid())?;
        if !self.transaction_id.starts_with("syntxn") {
            return Err(invalid());
        }
        Ok(parsed)
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlockArgs {
    pub height: Option<String>,
    pub block_commitment: Option<ProfileCommitmentWire>,
}
#[derive(Debug)]
pub enum BlockRead {
    Height(u64),
    Commitment {
        profile: R1ProfileRef,
        digest: [u8; 48],
    },
}
impl ReadArguments for BlockArgs {
    type Parsed = BlockRead;
    fn parse(self) -> Result<Self::Parsed, RpcError> {
        match (self.height, self.block_commitment) {
            (Some(height), None) => Ok(BlockRead::Height(decimal(&height)?)),
            (None, Some(commitment)) => Ok(BlockRead::Commitment {
                profile: commitment.profile.typed()?,
                digest: commitment.bytes("SHA3-384")?,
            }),
            _ => Err(invalid()),
        }
    }
}

/// Local byte transport limits, not consensus validity or finality claims.
pub const MAX_ORIGINAL_FINALITY_PROOF_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_FINALITY_PROOF_PAGE_BYTES: usize = 64 * 1024;
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FinalityProofPageArgs {
    pub kind: String,
    pub height: Option<String>,
    pub block_commitment: Option<ProfileCommitmentWire>,
    pub offset: String,
    pub limit: String,
    pub expected_total_bytes: Option<String>,
    pub expected_transport_digest: Option<DigestWire>,
}
#[derive(Debug)]
pub struct FinalityProofPageRead {
    pub block: BlockRead,
    pub offset: usize,
    pub limit: usize,
    pub expected_total_bytes: Option<usize>,
    pub expected_transport_digest: Option<[u8;48]>,
}
impl ReadArguments for FinalityProofPageArgs {
    type Parsed = FinalityProofPageRead;
    fn parse(self) -> Result<Self::Parsed,RpcError> {
        if self.kind != "finality" { return Err(invalid()); }
        let block=BlockArgs { height:self.height, block_commitment:self.block_commitment }.parse()?;
        let offset=usize::try_from(decimal(&self.offset)?).map_err(|_|invalid())?;
        let limit=usize::try_from(decimal(&self.limit)?).map_err(|_|invalid())?;
        let total=self.expected_total_bytes.as_deref().map(decimal).transpose()?
            .map(usize::try_from).transpose().map_err(|_|invalid())?;
        let digest=self.expected_transport_digest.map(|d|d.bytes("SHA3-384")).transpose()?;
        if offset>=MAX_ORIGINAL_FINALITY_PROOF_BYTES || !(1..=MAX_FINALITY_PROOF_PAGE_BYTES).contains(&limit)
            || total.is_some_and(|n|n==0 || n>MAX_ORIGINAL_FINALITY_PROOF_BYTES || offset>=n)
            || (offset>0 && (!matches!(block,BlockRead::Commitment{..}) || total.is_none() || digest.is_none())) {
            return Err(invalid());
        }
        Ok(FinalityProofPageRead { block,offset,limit,expected_total_bytes:total,expected_transport_digest:digest })
    }
}

#[derive(Debug,Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransactionInBlockArgs {
    pub height:Option<String>,
    pub block_commitment:Option<ProfileCommitmentWire>,
    pub index:String,
}
#[derive(Debug)]
pub struct TransactionInBlockRead { pub block:BlockRead,pub index:u64 }
impl ReadArguments for TransactionInBlockArgs {
    type Parsed=TransactionInBlockRead;
    fn parse(self)->Result<Self::Parsed,RpcError> {
        Ok(TransactionInBlockRead {block:BlockArgs{height:self.height,block_commitment:self.block_commitment}.parse()?,index:decimal(&self.index)?})
    }
}

/// Four complete source-bounded block projections per local read request.
/// This is a resource boundary, not a protocol/finality rule.
pub const MAX_BLOCK_RANGE_COUNT:u64=4;
#[derive(Debug,Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlockRangeArgs {pub from_height:String,pub limit:String}
#[derive(Debug)]
pub struct BlockRangeRead {pub from_height:u64,pub last_height:u64,pub count:u64}
impl ReadArguments for BlockRangeArgs {
    type Parsed=BlockRangeRead;
    fn parse(self)->Result<Self::Parsed,RpcError> {
        let from_height=decimal(&self.from_height)?;let count=decimal(&self.limit)?;
        if !(1..=MAX_BLOCK_RANGE_COUNT).contains(&count) {return Err(invalid());}
        let last_height=from_height.checked_add(count-1).ok_or_else(invalid)?;
        Ok(BlockRangeRead{from_height,last_height,count})
    }
}
