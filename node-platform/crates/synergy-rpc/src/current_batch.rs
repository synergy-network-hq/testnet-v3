//! Shared bounded carrier syntax and current read preflight, not authentication.
//! The native caller supplies its independently verified expected coordinate.
use serde::Deserialize;
use serde_json::{value::RawValue, Value};
use synergy_protocol_types::R1NetworkCoordinate;

use crate::{r1_read, RpcError, RpcRequest};

pub const MAX_DOCUMENT_BYTES: usize = 1_000_000;
pub const MAX_BATCH_CALLS: usize = 32;

#[derive(Deserialize)]
pub struct BorrowedRpcEnvelope<'a> {
    #[serde(borrow)]
    pub jsonrpc: &'a str,
    #[serde(borrow)]
    pub method: &'a str,
    #[serde(borrow)]
    pub id: &'a RawValue,
    #[serde(default, borrow)]
    pub params: Option<&'a RawValue>,
}

fn decode_error(error: serde_json::Error) -> RpcError {
    match error.classify() {
        serde_json::error::Category::Syntax | serde_json::error::Category::Eof => {
            RpcError::parse_error()
        }
        _ => RpcError::invalid_request("invalid bounded RPC carrier"),
    }
}

pub fn validate_envelope(bytes: &[u8]) -> Result<BorrowedRpcEnvelope<'_>, RpcError> {
    if bytes.iter().find(|b| !b.is_ascii_whitespace()) != Some(&b'{') {
        return Err(RpcError::invalid_request(
            "RPC request envelope must be an object",
        ));
    }
    let v: BorrowedRpcEnvelope<'_> = serde_json::from_slice(bytes).map_err(decode_error)?;
    if v.jsonrpc != "2.0" || v.method.is_empty() || v.method.len() > 128 || v.id.get().len() > 256 {
        return Err(RpcError::invalid_request("invalid bounded RPC envelope"));
    }
    let id: Value = serde_json::from_str(v.id.get()).map_err(decode_error)?;
    if !(id.is_string() || id.is_number()) {
        return Err(RpcError::invalid_request(
            "RPC requires a bounded scalar identifier",
        ));
    }
    if v.params
        .is_some_and(|params| !matches!(params.get().as_bytes().first(), Some(b'{') | Some(b'[')))
    {
        return Err(RpcError::invalid_params(
            "RPC params must be an object or array",
        ));
    }
    Ok(v)
}

/// The historical and current native carriers share this one borrowed visitor.
pub fn raw_batch_items(bytes: &[u8]) -> Result<Vec<&RawValue>, RpcError> {
    if bytes.len() > MAX_DOCUMENT_BYTES {
        return Err(RpcError::invalid_request("RPC document exceeds body bound"));
    }
    struct Bounded;
    impl<'de> serde::de::Visitor<'de> for Bounded {
        type Value = Vec<&'de RawValue>;
        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("a bounded JSON-RPC batch")
        }
        fn visit_seq<A: serde::de::SeqAccess<'de>>(
            self,
            mut seq: A,
        ) -> Result<Self::Value, A::Error> {
            let mut items = Vec::with_capacity(MAX_BATCH_CALLS);
            while let Some(item) = seq.next_element::<&'de RawValue>()? {
                if items.len() == MAX_BATCH_CALLS {
                    return Err(serde::de::Error::custom("RPC batch count exceeds limit"));
                }
                items.push(item);
            }
            if items.is_empty() {
                return Err(serde::de::Error::custom("empty RPC batch"));
            }
            Ok(items)
        }
    }
    let mut decoder = serde_json::Deserializer::from_slice(bytes);
    let result =
        serde::Deserializer::deserialize_seq(&mut decoder, Bounded).map_err(decode_error)?;
    decoder.end().map_err(decode_error)?;
    Ok(result)
}

pub(crate) fn requests(
    bytes: &[u8],
    expected: &R1NetworkCoordinate,
) -> Result<(Vec<RpcRequest>, bool), RpcError> {
    if bytes.len() > MAX_DOCUMENT_BYTES {
        return Err(RpcError::invalid_request("RPC document exceeds body bound"));
    }
    let batch = bytes.iter().find(|b| !b.is_ascii_whitespace()) == Some(&b'[');
    let raw = if batch {
        raw_batch_items(bytes)?
    } else {
        vec![serde_json::from_slice::<&RawValue>(bytes).map_err(decode_error)?]
    };
    let mut ids = std::collections::BTreeSet::new();
    let mut requests = Vec::with_capacity(raw.len());
    for item in raw {
        let envelope = validate_envelope(item.get().as_bytes())?;
        let request: RpcRequest =
            serde_json::from_slice(item.get().as_bytes()).map_err(decode_error)?;
        request.validate()?;
        if request.method != envelope.method || !ids.insert(request.id.to_string()) {
            return Err(RpcError::invalid_request(
                "RPC batch requires distinct scalar identifiers",
            ));
        }
        // Validate without rewriting the retained request or creating another
        // transport/signing representation. The input lease covers this clone.
        r1_read::preflight(&request.method, request.params.clone(), expected)?;
        requests.push(request);
    }
    Ok((requests, batch))
}

/// Data-only helper for native ingress that already owns its input allocation.
pub fn validate_document(bytes: &[u8], expected: &R1NetworkCoordinate) -> Result<(), RpcError> {
    requests(bytes, expected).map(|_| ())
}

/// Local engineering ceilings derived from the registered source projections.
/// These are capacity limits, never validity/finality or protocol supply rules.
pub fn response_ceiling(method: &str) -> Option<usize> {
    Some(match method {
        "synergy_getBlockReceipts" => 16 * 1024 * 1024,
        "synergy_getBlock"
        | "synergy_getBlockByHash"
        | "synergy_getBlockByNumber"
        | "synergy_getLatestBlock"
        | "synergy_getFinalizedHead" => 8 * 1024 * 1024,
        "synergy_getProof" => 1024 * 1024,
        "synergy_getHealth"
        | "synergy_getHealthCheck"
        | "synergy_getReadiness"
        | "synergy_getNodeStatus"
        | "synergy_nodeInfo" => 64 * 1024,
        "synergy_getAccount"
        | "synergy_getBalance"
        | "synergy_getAccountNonce"
        | "synergy_getNonce"
        | "synergy_getTransaction"
        | "synergy_getTransactionByHash"
        | "synergy_getTransactionReceipt"
        | "synergy_getReceipt"
        | "synergy_getTransactionStatus"
        | "synergy_getTransactionFees" => 8 * 1024,
        "synergy_getTransactionsInBlock" => 128 * 1024,
        "synergy_getBlockTransactionCount"
        | "synergy_getBlockNumber"
        | "synergy_blockNumber"
        | "synergy_getChainId"
        | "synergy_chainId"
        | "synergy_networkId"
        | "synergy_genesisHash"
        | "synergy_ping" => 4 * 1024,
        _ => return None,
    })
}
