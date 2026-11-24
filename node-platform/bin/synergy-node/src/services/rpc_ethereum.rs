//! Standard legacy Ethereum queries over authenticated native finalized state.
//! No Ethereum header, PoW fields, pending state or speculative receipt is invented.
use super::*;
use std::collections::BTreeMap;
use synergy_aivm::ethereum_execution::{
    call_evm, estimate_evm_gas, read_evm_account, read_evm_storage, EvmBlockContext,
    EvmCallRequest, EvmCompatibilityPolicy, EVM_POLICY_KEY,
};

fn fail(error: impl std::fmt::Display) -> RpcError {
    RpcError::unavailable(error.to_string())
}
fn bytes(value: &Value, maximum: usize) -> Result<Vec<u8>, RpcError> {
    let value = value
        .as_str()
        .and_then(|value| value.strip_prefix("0x"))
        .ok_or_else(|| RpcError::invalid_params("expected 0x-prefixed hex bytes"))?;
    if value.len() % 2 != 0 || value.len() / 2 > maximum {
        return Err(RpcError::invalid_params("hex byte length exceeds limit"));
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let text =
                std::str::from_utf8(pair).map_err(|_| RpcError::invalid_params("invalid hex"))?;
            u8::from_str_radix(text, 16).map_err(|_| RpcError::invalid_params("invalid hex"))
        })
        .collect()
}
fn fixed<const N: usize>(value: &Value) -> Result<[u8; N], RpcError> {
    bytes(value, N)?
        .try_into()
        .map_err(|_| RpcError::invalid_params("incorrect hex byte length"))
}
fn quantity(value: &Value) -> Result<u64, RpcError> {
    let text = value
        .as_str()
        .and_then(|value| value.strip_prefix("0x"))
        .filter(|text| {
            !text.is_empty() && text.len() <= 16 && (text.len() == 1 || !text.starts_with('0'))
        })
        .ok_or_else(|| RpcError::invalid_params("expected canonical hex quantity"))?;
    u64::from_str_radix(text, 16).map_err(|_| RpcError::invalid_params("invalid hex quantity"))
}
fn word_quantity(value: &Value) -> Result<[u8; 32], RpcError> {
    let text = value
        .as_str()
        .and_then(|value| value.strip_prefix("0x"))
        .filter(|text| {
            !text.is_empty() && text.len() <= 64 && (text.len() == 1 || !text.starts_with('0'))
        })
        .ok_or_else(|| RpcError::invalid_params("expected uint256 hex quantity"))?;
    let padded = format!("0x{:0>64}", text);
    fixed(&Value::String(padded))
}
fn hex(bytes: &[u8]) -> String {
    format!(
        "0x{}",
        bytes
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    )
}
fn qword(bytes: &[u8; 32]) -> String {
    let value = hex(bytes);
    let text = value.trim_start_matches("0x").trim_start_matches('0');
    format!("0x{}", if text.is_empty() { "0" } else { text })
}

pub(super) fn decode_raw_params(params: &Value) -> Result<Vec<u8>, RpcError> {
    let params = params
        .as_array()
        .filter(|value| value.len() == 1)
        .ok_or_else(|| RpcError::invalid_params("expected one raw transaction"))?;
    bytes(&params[0], 65536)
}

impl CanonicalQueryStore {
    pub(super) fn canonical_ethereum_query(
        &self,
        method: &str,
        params: &Value,
    ) -> Result<Value, RpcError> {
        let params = params
            .as_array()
            .ok_or_else(|| RpcError::invalid_params("Ethereum params must be an array"))?;
        let (genesis, live) = self
            .wallet_finalized_authority
            .as_ref()
            .ok_or_else(|| RpcError::unavailable("authenticated Ethereum authority unavailable"))?;
        let authority = live
            .read()
            .map_err(|_| fail("authority lock poisoned"))?
            .clone()
            .ok_or_else(|| fail("authenticated Ethereum authority unavailable"))?;
        let signed = authority
            .ethereum_genesis()
            .ok_or_else(|| fail("signed Genesis does not activate Ethereum compatibility"))?;
        signed.descriptor.validate().map_err(fail)?;
        if signed.genesis_hash != *genesis {
            return Err(fail("Ethereum authority differs from selected Genesis"));
        }
        let chain = authority.epoch.chain_id;
        if matches!(method, "eth_chainId" | "net_version") {
            if !params.is_empty() {
                return Err(RpcError::invalid_params("unexpected params"));
            }
            return Ok(Value::String(if method == "eth_chainId" {
                format!("0x{chain:x}")
            } else {
                chain.to_string()
            }));
        }
        let latest = self.latest_finalized_height()?.unwrap_or(0);
        if method == "eth_blockNumber" {
            if !params.is_empty() {
                return Err(RpcError::invalid_params("unexpected params"));
            }
            return Ok(json!(format!("0x{latest:x}")));
        }
        if matches!(
            method,
            "eth_getBlockByNumber" | "eth_getBlockByHash" | "eth_getLogs"
        ) {
            return self.ethereum_blocks_query(method, params, latest, &authority);
        }
        let (minimum, maximum, tag_index) = match method {
            "eth_gasPrice" => (0, 0, None),
            "eth_sendRawTransaction" | "eth_getTransactionReceipt" | "eth_getTransactionByHash" => {
                (1, 1, None)
            }
            "eth_getBalance" | "eth_getTransactionCount" | "eth_getCode" => (2, 2, Some(1)),
            "eth_getStorageAt" => (3, 3, Some(2)),
            "eth_call" => (2, 2, Some(1)),
            "eth_estimateGas" => (1, 2, Some(1)),
            _ => return Err(RpcError::method_not_found()),
        };
        if params.len() < minimum || params.len() > maximum {
            return Err(RpcError::invalid_params(
                "incorrect Ethereum parameter count",
            ));
        }
        let height = match tag_index.and_then(|index| params.get(index)) {
            None => latest,
            Some(Value::String(tag)) if matches!(tag.as_str(), "latest" | "safe" | "finalized") => {
                latest
            }
            Some(Value::String(tag)) if tag == "earliest" => 0,
            Some(tag) => quantity(tag)?,
        };
        if height > latest {
            return Err(fail("requested state is not PoSy-finalized"));
        }
        let (block_id, world) = if height == 0 {
            let origin = authority.autonomous_processing_origin();
            (
                signed.genesis_hash.clone(),
                origin
                    .initial_world_state_budgeted(&self.world_budget)
                    .map_err(fail)?,
            )
        } else {
            let Some((candidate, _)) = self.finalized_at(height)? else {
                return Err(fail("requested finalized candidate was retired"));
            };
            let id = candidate.block_id.clone();
            drop(candidate);
            let world = self
                .state_store()?
                .world_state_at_budgeted(height, &self.world_budget)
                .map_err(|error| fail(format!("finalized World: {error:?}")))?
                .ok_or_else(|| fail("requested finalized World unavailable"))?;
            (id, world)
        };
        let policy = EvmCompatibilityPolicy::load(&world).map_err(fail)?;
        let pin = synergy_posy::parse_hash_bytes(&signed.descriptor.policy_sha256).map_err(fail)?;
        if policy.chain_id != chain
            || synergy_aegis::AegisProtectedPrimitives.sha256(&world.protocol[EVM_POLICY_KEY])
                != pin
        {
            return Err(fail("finalized EVM policy differs from signed Genesis"));
        }
        if matches!(
            method,
            "eth_getTransactionReceipt" | "eth_getTransactionByHash"
        ) {
            let hash = fixed::<32>(&params[0])?;
            let key = format!(
                "{}{}",
                crate::services::processing_pipeline::ethereum::TRANSACTION_PREFIX,
                hex(&hash).trim_start_matches("0x")
            );
            let Some(encoded) = world.protocol.get(&key) else {
                return Ok(Value::Null);
            };
            if encoded.len() > 4 * 1024 * 1024 {
                return Err(fail("Ethereum receipt exceeds native bound"));
            }
            let _permit = self
                .world_budget
                .reserve(encoded.len() * 16 + 65536)
                .map_err(fail)?;
            let record: crate::services::processing_pipeline::ethereum::EthereumRecord =
                serde_json::from_slice(encoded).map_err(fail)?;
            if record.height == 0 || record.height > latest {
                return Err(fail("Ethereum receipt lacks finalized inclusion"));
            }
            let Some(receipt) = &record.receipt else {
                return Ok(Value::Null);
            };
            let Some((inclusion, _)) = self.finalized_at(record.height)? else {
                return Err(fail("Ethereum inclusion candidate is unavailable"));
            };
            if inclusion.state.protocol.get(&key) != Some(encoded) {
                return Err(fail(
                    "Ethereum receipt differs from its claimed finalized inclusion World",
                ));
            }
            let transaction =
                synergy_aivm::ethereum::decode_eip155(&record.raw, chain).map_err(fail)?;
            if transaction.transaction_hash != hash
                || receipt.transaction_hash != hash
                || receipt.gas_used > transaction.gas_limit
                || receipt.fee_nwei
                    != u128::from(receipt.gas_used)
                        * transaction.native_terms().map_err(fail)?.gas_price_nwei as u128
            {
                return Err(fail(
                    "Ethereum finalized receipt conflicts with original transaction",
                ));
            }
            let signer = synergy_aegis::ethereum::verify_eip155_signature(
                chain,
                &transaction.signing_hash,
                transaction.v,
                &transaction.r,
                &transaction.s,
            )
            .map_err(fail)?;
            return ethereum_transaction_view(
                method,
                &record,
                &transaction,
                signer.account_id(),
                &inclusion.block_id,
            );
        }
        if method == "eth_sendRawTransaction" {
            let raw = bytes(&params[0], 65536)?;
            let _permit = self
                .world_budget
                .reserve(raw.len() * 16 + 65536)
                .map_err(fail)?;
            let authenticated = synergy_aivm::ethereum_admission::authenticate_conventional_eip155(
                &raw, chain, &world,
            )
            .map_err(|error| RpcError::invalid_params(error.to_string()))?;
            let transaction = authenticated.transaction();
            let terms = transaction
                .native_terms()
                .map_err(|error| RpcError::invalid_params(error.to_string()))?;
            let sender = synergy_aivm::ethereum_execution::conventional_evm_account_key(
                *authenticated.signer().account_id(),
            );
            let account = world.accounts.get(&sender).ok_or_else(|| {
                RpcError::invalid_params("Ethereum sender lacks finalized funding")
            })?;
            if transaction.nonce < account.nonce
                || transaction.nonce == u64::MAX
                || transaction.gas_limit > policy.block_gas_limit
                || terms.gas_price_nwei < policy.base_fee_nwei
                || account.balance_nwei < terms.maximum_debit_nwei
                || account.code_hash.is_some()
            {
                return Err(RpcError::invalid_params(
                    "Ethereum transaction lacks executable finalized nonce/funds/gas",
                ));
            }
            return Ok(json!({"transaction_hash":hex(&transaction.transaction_hash)}));
        }
        if method == "eth_gasPrice" {
            return Ok(json!(format!(
                "0x{:x}",
                u128::from(policy.base_fee_nwei) * 1_000_000_000
            )));
        }
        if matches!(
            method,
            "eth_getBalance" | "eth_getTransactionCount" | "eth_getCode" | "eth_getStorageAt"
        ) {
            let address = fixed::<20>(&params[0])?;
            let account = read_evm_account(&world, address).map_err(fail)?;
            return Ok(json!(match method {
                "eth_getBalance" => qword(&account.balance_wei),
                "eth_getTransactionCount" => format!("0x{:x}", account.nonce),
                "eth_getCode" => hex(account.code),
                _ => hex(
                    &read_evm_storage(&world, address, word_quantity(&params[1])?).map_err(fail)?
                ),
            }));
        }
        let request = params[0]
            .as_object()
            .ok_or_else(|| RpcError::invalid_params("expected Ethereum call object"))?;
        if request.keys().any(|key| {
            !matches!(
                key.as_str(),
                "from" | "to" | "value" | "data" | "input" | "gas" | "gasPrice" | "type"
            )
        }) || request
            .get("type")
            .is_some_and(|value| quantity(value) != Ok(0))
            || request
                .get("gasPrice")
                .is_some_and(|value| word_quantity(value) != Ok([0; 32]))
        {
            return Err(RpcError::invalid_params(
                "unsupported call override or typed transaction",
            ));
        }
        let from = request
            .get("from")
            .map(fixed::<20>)
            .transpose()?
            .unwrap_or([0; 20]);
        let recipient = request.get("to").map(fixed::<20>).transpose()?;
        let value = request
            .get("value")
            .map(word_quantity)
            .transpose()?
            .unwrap_or([0; 32]);
        let data = request
            .get("data")
            .or_else(|| request.get("input"))
            .map(|value| bytes(value, synergy_aivm::ethereum::MAX_LEGACY_TRANSACTION_BYTES))
            .transpose()?
            .unwrap_or_default();
        if request
            .get("data")
            .zip(request.get("input"))
            .is_some_and(|(left, right)| left != right)
        {
            return Err(RpcError::invalid_params("conflicting call data"));
        }
        let gas = request
            .get("gas")
            .map(quantity)
            .transpose()?
            .unwrap_or(policy.block_gas_limit);
        let original = if height == 0 {
            authority.autonomous_processing_origin()
        } else {
            authority
                .authenticated_history_ref_at(height)
                .ok_or_else(|| fail("historical EVM execution authority unavailable"))?
        };
        let mut history = BTreeMap::new();
        for ancestor in height.saturating_sub(256)..height {
            let key = format!("aivm/ethereum/v1/native-parent/{ancestor:020}");
            let bytes = world
                .protocol
                .get(&key)
                .ok_or_else(|| fail("authenticated native BLOCKHASH history is unavailable"))?;
            history.insert(
                ancestor,
                bytes
                    .as_slice()
                    .try_into()
                    .map_err(|_| fail("corrupt native BLOCKHASH history"))?,
            );
        }
        // PREVRANDAO derives from the authenticated epoch seed. It is neither
        // a caller override nor the current block's self-referential hash.
        let context = EvmBlockContext {
            chain_id: chain,
            genesis: synergy_posy::parse_hash_bytes(genesis).map_err(fail)?,
            policy_sha256: pin,
            height,
            timestamp: if height == 0 {
                signed.activation_unix
            } else {
                original.consensus_timestamp_unix(height).map_err(fail)?
            },
            gas_used_before: 0,
            randomness: synergy_posy::parse_hash_bytes(&original.epoch.finalized_epoch_seed_root)
                .map_err(fail)?,
            recent_block_hashes: &history,
            protected_credit_verifier: None,
        };
        let call = EvmCallRequest {
            from,
            recipient,
            value_wei: value,
            data: &data,
            gas_limit: gas,
        };
        let result = if method == "eth_estimateGas" {
            json!(format!(
                "0x{:x}",
                estimate_evm_gas(&call, &context, &world, &self.world_budget).map_err(fail)?
            ))
        } else {
            let result = call_evm(&call, &context, &world, &self.world_budget).map_err(fail)?;
            if !result.success {
                return Err(RpcError {
                    code: 3,
                    message: "execution reverted".into(),
                    data: Some(json!(hex(&result.output))),
                });
            }
            json!(hex(&result.output))
        };
        // Rebind after simulation: a retained canonical anchor may disappear,
        // but a conflicting owner must never be exposed through a raced read.
        if height > 0
            && self
                .finalized_at(height)?
                .is_none_or(|(candidate, _)| candidate.block_id != block_id)
        {
            return Err(fail("finalized execution anchor changed during query"));
        }
        Ok(result)
    }
}

fn ethereum_transaction_view(
    method: &str,
    record: &crate::services::processing_pipeline::ethereum::EthereumRecord,
    tx: &synergy_aivm::ethereum::DecodedLegacyTransaction,
    from: &[u8; 20],
    block_hash: &str,
) -> Result<Value, RpcError> {
    let receipt = record
        .receipt
        .as_ref()
        .ok_or_else(|| fail("Ethereum receipt absent"))?;
    let block_hash = format!("0x{block_hash}");
    let to = tx.recipient.as_ref().map(|value| hex(value));
    if method == "eth_getTransactionByHash" {
        return Ok(
            json!({"hash":hex(&tx.transaction_hash),"blockHash":block_hash,"blockNumber":format!("0x{:x}",record.height),
            "transactionIndex":format!("0x{:x}",record.index),"from":hex(from),"to":to,"nonce":format!("0x{:x}",tx.nonce),
            "gas":format!("0x{:x}",tx.gas_limit),"gasPrice":qword(&tx.gas_price_wei),"value":qword(&tx.value_wei),
            "input":hex(&tx.data),"chainId":format!("0x{:x}",tx.chain_id),"type":"0x0","v":format!("0x{:x}",tx.v),
            "r":hex(&tx.r),"s":hex(&tx.s)}),
        );
    }
    let mut bloom = [0u8; 256];
    let mut logs = Vec::new();
    for (index, log) in receipt.logs.iter().enumerate() {
        for value in std::iter::once(log.address.as_slice())
            .chain(log.topics.iter().map(|topic| topic.as_slice()))
        {
            bloom_value(&mut bloom, value);
        }
        logs.push(json!({"address":hex(&log.address),"topics":log.topics.iter().map(|topic|hex(topic)).collect::<Vec<_>>(),
            "data":hex(&log.data),"blockNumber":format!("0x{:x}",record.height),"transactionHash":hex(&tx.transaction_hash),
            "transactionIndex":format!("0x{:x}",record.index),"blockHash":block_hash,"removed":false,
            "logIndex":format!("0x{:x}",record.first_log_index+index as u64)}));
    }
    Ok(
        json!({"transactionHash":hex(&tx.transaction_hash),"transactionIndex":format!("0x{:x}",record.index),
        "blockHash":block_hash,"blockNumber":format!("0x{:x}",record.height),"from":hex(from),"to":to,
        "cumulativeGasUsed":format!("0x{:x}",record.cumulative_gas_used),"gasUsed":format!("0x{:x}",receipt.gas_used),
        "contractAddress":receipt.created_address.as_ref().map(|address|hex(address)),"logs":logs,"logsBloom":hex(&bloom),
        "status":if receipt.success{"0x1"}else{"0x0"},"type":"0x0","effectiveGasPrice":qword(&tx.gas_price_wei),
        "synergyNativeException":receipt.native_exception}),
    )
}
fn bloom_value(bloom: &mut [u8; 256], value: &[u8]) {
    synergy_aivm::ethereum_projection::accrue_log_bloom(bloom, value)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn quantities_and_addresses_are_bounded_and_canonical() {
        assert_eq!(quantity(&json!("0x26f1")).unwrap(), 9969);
        for value in ["0x", "0x00", "1", "0x10000000000000000", "0xz"] {
            assert!(quantity(&json!(value)).is_err());
        }
        assert_eq!(qword(&[0; 32]), "0x0");
        assert_eq!(word_quantity(&json!("0x1")).unwrap()[31], 1);
        assert!(fixed::<20>(&json!("0x01")).is_err());
        assert!(bytes(&json!("0xabc"), 8).is_err());
    }
}

impl CanonicalQueryStore {
    fn ethereum_height_by_hash(&self, hash: [u8; 32]) -> Result<Option<u64>, RpcError> {
        let expected = hex(&hash);
        let expected = expected.trim_start_matches("0x");
        if self
            .wallet_finalized_authority
            .as_ref()
            .is_some_and(|(genesis, _)| genesis == expected)
        {
            return Ok(Some(0));
        }
        for height in self.candidate_heights()?.into_iter().rev().take(4096) {
            if self
                .finalized_commitment_at(height)?
                .is_some_and(|(commitment, _)| commitment.block_id == expected)
            {
                return Ok(Some(height));
            }
        }
        Ok(None)
    }
    fn ethereum_blocks_query(
        &self,
        method: &str,
        params: &[Value],
        latest: u64,
        authority: &super::super::authority::VerifiedAuthority,
    ) -> Result<Value, RpcError> {
        if method == "eth_getLogs" {
            return self.ethereum_logs(params, latest, authority);
        }
        if params.len() != 2 || !params[1].is_boolean() {
            return Err(RpcError::invalid_params(
                "expected block identifier and transaction-details flag",
            ));
        }
        let height = if method == "eth_getBlockByHash" {
            match self.ethereum_height_by_hash(fixed(&params[0])?)? {
                Some(height) => height,
                None => return Ok(Value::Null),
            }
        } else {
            block_tag(&params[0], latest)?
        };
        if height > latest {
            return Ok(Value::Null);
        }
        self.ethereum_block_view(height, authority, params[1].as_bool().unwrap())
    }
    fn complete_ethereum_block_schema(mut block: Value, raws: &[&[u8]]) -> Result<Value, RpcError> {
        let mut fields = Vec::with_capacity(16);
        for (name, quantity) in [
            ("parentHash", false),
            ("sha3Uncles", false),
            ("miner", false),
            ("stateRoot", false),
            ("transactionsRoot", false),
            ("receiptsRoot", false),
            ("logsBloom", false),
            ("difficulty", true),
            ("number", true),
            ("gasLimit", true),
            ("gasUsed", true),
            ("timestamp", true),
            ("extraData", false),
            ("mixHash", false),
            ("nonce", false),
            ("baseFeePerGas", true),
        ] {
            if quantity {
                let number = block[name]
                    .as_str()
                    .ok_or_else(|| fail("projected header quantity missing"))?;
                let number = u128::from_str_radix(number.trim_start_matches("0x"), 16)
                    .map_err(fail)?
                    .to_be_bytes();
                let start = number
                    .iter()
                    .position(|byte| *byte != 0)
                    .unwrap_or(number.len());
                fields.push(number[start..].to_vec());
            } else {
                fields.push(bytes(&block[name], 65536)?);
            }
        }
        let size =
            synergy_aivm::ethereum_projection::ethereum_projected_block_rlp_size(&fields, raws)
                .map_err(fail)?;
        block["size"] = json!(format!("0x{size:x}"));
        Ok(block)
    }
    fn ethereum_block_view(
        &self,
        height: u64,
        authority: &super::super::authority::VerifiedAuthority,
        full: bool,
    ) -> Result<Value, RpcError> {
        if height == 0 {
            return self.ethereum_genesis_view(authority);
        }
        use crate::services::processing_pipeline::ethereum::{
            BlockIndex, EthereumRecord, BLOCK_PREFIX, TRANSACTION_PREFIX,
        };
        let Some((candidate, finality)) = self.finalized_at(height)? else {
            return Ok(Value::Null);
        };
        let world = candidate.state.as_ref();
        let policy = EvmCompatibilityPolicy::load(world).map_err(fail)?;
        let signed = authority
            .ethereum_genesis()
            .ok_or_else(|| fail("signed EVM Genesis absent"))?;
        if policy.chain_id != authority.epoch.chain_id
            || hex(&synergy_aegis::AegisProtectedPrimitives.sha256(&world.protocol[EVM_POLICY_KEY]))
                .trim_start_matches("0x")
                != signed.descriptor.policy_sha256
        {
            return Err(fail(
                "EVM block policy differs from independently signed Genesis",
            ));
        }
        let _allocation = self.world_budget.reserve(16 * 1024 * 1024).map_err(fail)?;
        let index: BlockIndex = match world.protocol.get(&format!("{BLOCK_PREFIX}{height:020}")) {
            Some(bytes) if bytes.len() <= 256 * 1024 => {
                serde_json::from_slice(bytes).map_err(fail)?
            }
            Some(_) => return Err(fail("EVM block index exceeds native bound")),
            None => BlockIndex::default(),
        };
        if index.transactions.len() > 1428 {
            return Err(fail("EVM block index exceeds gas bound"));
        }
        let mut records = Vec::<EthereumRecord>::with_capacity(index.transactions.len());
        let mut bytes = 0usize;
        for (position, hash) in index.transactions.iter().enumerate() {
            let key = format!("{TRANSACTION_PREFIX}{}", hex(hash).trim_start_matches("0x"));
            let encoded = world
                .protocol
                .get(&key)
                .ok_or_else(|| fail("EVM block lacks committed receipt"))?;
            bytes = bytes
                .checked_add(encoded.len())
                .filter(|bytes| *bytes <= 4 * 1024 * 1024)
                .ok_or_else(|| fail("EVM block projection exceeds response bound"))?;
            let record: EthereumRecord = serde_json::from_slice(encoded).map_err(fail)?;
            if record.height != height
                || record.index as usize != position
                || record
                    .receipt
                    .as_ref()
                    .is_none_or(|receipt| receipt.transaction_hash != *hash)
            {
                return Err(fail("EVM block index and finalized receipt disagree"));
            }
            records.push(record);
        }
        let raws = records
            .iter()
            .map(|record| record.raw.as_slice())
            .collect::<Vec<_>>();
        let receipts = records
            .iter()
            .map(|record| record.receipt.as_ref().unwrap())
            .collect::<Vec<_>>();
        let roots = synergy_aivm::ethereum_projection::ethereum_block_roots(&raws, &receipts)
            .map_err(fail)?;
        if roots.gas_used != index.gas_used
            || records
                .last()
                .is_some_and(|record| record.cumulative_gas_used != roots.gas_used)
        {
            return Err(fail(
                "EVM cumulative gas disagrees with finalized block index",
            ));
        }
        let mut transactions = Vec::new();
        for record in &records {
            let tx = synergy_aivm::ethereum::decode_eip155(&record.raw, policy.chain_id)
                .map_err(fail)?;
            if full {
                let signer = synergy_aegis::ethereum::verify_eip155_signature(
                    tx.chain_id,
                    &tx.signing_hash,
                    tx.v,
                    &tx.r,
                    &tx.s,
                )
                .map_err(fail)?;
                transactions.push(ethereum_transaction_view(
                    "eth_getTransactionByHash",
                    record,
                    &tx,
                    signer.account_id(),
                    &candidate.block_id,
                )?);
            } else {
                transactions.push(json!(hex(&tx.transaction_hash)));
            }
        }
        let original = authority
            .authenticated_history_ref_at(height)
            .ok_or_else(|| fail("block lacks authenticated historical timestamp/epoch"))?;
        Self::complete_ethereum_block_schema(
            json!({"hash":format!("0x{}",candidate.block_id),"parentHash":format!("0x{}",candidate.parent_block_id),
            "number":format!("0x{height:x}"),"timestamp":format!("0x{:x}",original.consensus_timestamp_unix(height).map_err(fail)?),
            "nonce":"0x0000000000000000","difficulty":"0x0","totalDifficulty":"0x0","uncles":[],
            "sha3Uncles":hex(&synergy_aivm::ethereum::ethereum_keccak256(&[0xc0])),
            "gasLimit":format!("0x{:x}",policy.block_gas_limit),"gasUsed":format!("0x{:x}",roots.gas_used),
            "miner":hex(&policy.fee_collector),"mixHash":format!("0x{}",original.epoch.finalized_epoch_seed_root),"prevRandao":format!("0x{}",original.epoch.finalized_epoch_seed_root),
            "extraData":hex(original.epoch.protocol_version.as_bytes()),"baseFeePerGas":format!("0x{:x}",u128::from(policy.base_fee_nwei)*1_000_000_000),
            "stateRoot":hex(&synergy_aivm::ethereum_projection::ethereum_state_root(&world,&self.world_budget).map_err(fail)?),"transactionsRoot":hex(&roots.transactions_root),"receiptsRoot":hex(&roots.receipts_root),
            "logsBloom":hex(&roots.logs_bloom),"transactions":transactions,
            "synergyProjectionProfile":policy.rpc_projection_policy,"synergyNativeStateRoot":format!("0x{}",candidate.state_root),
            "synergyFinalityCertificateId":finality.finality_certificate_id}),
            &raws,
        )
    }
    fn ethereum_genesis_view(
        &self,
        authority: &super::super::authority::VerifiedAuthority,
    ) -> Result<Value, RpcError> {
        let signed = authority
            .ethereum_genesis()
            .ok_or_else(|| fail("signed Ethereum Genesis absent"))?;
        let world = authority
            .autonomous_processing_origin()
            .initial_world_state_budgeted(&self.world_budget)
            .map_err(fail)?;
        let policy = EvmCompatibilityPolicy::load(&world).map_err(fail)?;
        if hex(&synergy_aegis::AegisProtectedPrimitives.sha256(&world.protocol[EVM_POLICY_KEY]))
            .trim_start_matches("0x")
            != signed.descriptor.policy_sha256
        {
            return Err(fail(
                "initial Ethereum policy differs from independently signed Genesis",
            ));
        }
        let roots =
            synergy_aivm::ethereum_projection::ethereum_block_roots(&[], &[]).map_err(fail)?;
        Self::complete_ethereum_block_schema(
            json!({"hash":format!("0x{}",signed.genesis_hash),"parentHash":hex(&[0;32]),"number":"0x0",
            "timestamp":format!("0x{:x}",signed.activation_unix),"nonce":"0x0000000000000000","difficulty":"0x0","totalDifficulty":"0x0","uncles":[],
            "sha3Uncles":hex(&synergy_aivm::ethereum::ethereum_keccak256(&[0xc0])),
            "gasLimit":format!("0x{:x}",policy.block_gas_limit),"gasUsed":"0x0","miner":hex(&policy.fee_collector),
            "mixHash":format!("0x{}",authority.autonomous_processing_origin().epoch.finalized_epoch_seed_root),"prevRandao":format!("0x{}",authority.autonomous_processing_origin().epoch.finalized_epoch_seed_root),
            "extraData":hex(authority.epoch.protocol_version.as_bytes()),"baseFeePerGas":format!("0x{:x}",u128::from(policy.base_fee_nwei)*1_000_000_000),
            "stateRoot":hex(&synergy_aivm::ethereum_projection::ethereum_state_root(&world,&self.world_budget).map_err(fail)?),"transactionsRoot":hex(&roots.transactions_root),"receiptsRoot":hex(&roots.receipts_root),"logsBloom":hex(&roots.logs_bloom),"transactions":[],
            "synergyProjectionProfile":policy.rpc_projection_policy,"synergyNativeStateRoot":format!("0x{}",authority.autonomous_processing_origin().initial_world_state_root().map_err(fail)?),
            "synergyFinalityCertificateId":null,"synergyFinalityKind":"signed-genesis"}),
            &[],
        )
    }
    fn ethereum_logs(
        &self,
        params: &[Value],
        latest: u64,
        authority: &super::super::authority::VerifiedAuthority,
    ) -> Result<Value, RpcError> {
        if params.len() != 1 {
            return Err(RpcError::invalid_params("expected one bounded log filter"));
        }
        let filter = params[0]
            .as_object()
            .ok_or_else(|| RpcError::invalid_params("expected log filter object"))?;
        if filter.keys().any(|key| {
            !matches!(
                key.as_str(),
                "fromBlock" | "toBlock" | "blockHash" | "address" | "topics"
            )
        }) {
            return Err(RpcError::invalid_params("unknown log filter field"));
        }
        let (from, to) = if let Some(hash) = filter.get("blockHash") {
            if filter.contains_key("fromBlock") || filter.contains_key("toBlock") {
                return Err(RpcError::invalid_params("blockHash conflicts with range"));
            }
            match self.ethereum_height_by_hash(fixed(hash)?)? {
                Some(height) => (height, height),
                None => return Ok(json!([])),
            }
        } else {
            (
                filter
                    .get("fromBlock")
                    .map(|value| block_tag(value, latest))
                    .transpose()?
                    .unwrap_or(latest),
                filter
                    .get("toBlock")
                    .map(|value| block_tag(value, latest))
                    .transpose()?
                    .unwrap_or(latest),
            )
        };
        if from > to || to > latest || to.saturating_sub(from) > 63 {
            return Err(RpcError::invalid_params(
                "log queries require at most64 finalized native blocks",
            ));
        }
        let addresses = filter
            .get("address")
            .map(|value| alternatives::<20>(value))
            .transpose()?;
        let topics = filter
            .get("topics")
            .map(|value| {
                value
                    .as_array()
                    .filter(|topics| topics.len() <= 4)
                    .ok_or_else(|| RpcError::invalid_params("expected at most4 topic positions"))
            })
            .transpose()?
            .map(|topics| {
                topics
                    .iter()
                    .map(|value| {
                        if value.is_null() {
                            Ok(None)
                        } else {
                            alternatives::<32>(value).map(Some)
                        }
                    })
                    .collect::<Result<Vec<_>, RpcError>>()
            })
            .transpose()?
            .unwrap_or_default();
        let _response = self.world_budget.reserve(16 * 1024 * 1024).map_err(fail)?;
        let mut logs = Vec::new();
        let mut total = 0usize;
        for height in from.max(1)..=to {
            let block = self.ethereum_block_view(height, authority, false)?;
            if block.is_null() {
                return Err(fail("requested finalized log history is unavailable"));
            }
            for hash in block["transactions"]
                .as_array()
                .ok_or_else(|| fail("EVM block transactions absent"))?
            {
                let receipt =
                    self.canonical_ethereum_query("eth_getTransactionReceipt", &json!([hash]))?;
                if receipt.is_null() {
                    return Err(fail("finalized block lacks Ethereum receipt"));
                }
                for log in receipt["logs"]
                    .as_array()
                    .ok_or_else(|| fail("Ethereum logs absent"))?
                {
                    let address = fixed::<20>(&log["address"])?;
                    if addresses
                        .as_ref()
                        .is_some_and(|allowed| !allowed.is_empty() && !allowed.contains(&address))
                    {
                        continue;
                    }
                    let actual = log["topics"]
                        .as_array()
                        .ok_or_else(|| fail("Ethereum topics absent"))?;
                    if !topics.iter().enumerate().all(|(index, allowed)| {
                        actual
                            .get(index)
                            .and_then(|value| fixed::<32>(value).ok())
                            .is_some_and(|value| {
                                allowed.as_ref().is_none_or(|allowed| {
                                    allowed.is_empty() || allowed.contains(&value)
                                })
                            })
                    }) {
                        continue;
                    }
                    total += serde_json::to_vec(log).map_err(fail)?.len();
                    if logs.len() >= 4096 || total > 4 * 1024 * 1024 {
                        return Err(fail(
                            "Ethereum log response exceeds bound; narrow the query",
                        ));
                    }
                    logs.push(log.clone());
                }
            }
        }
        Ok(Value::Array(logs))
    }
}
fn alternatives<const N: usize>(value: &Value) -> Result<Vec<[u8; N]>, RpcError> {
    if let Some(values) = value.as_array() {
        if values.len() > 64 {
            return Err(RpcError::invalid_params("hex alternatives exceed bound"));
        }
        values.iter().map(fixed).collect()
    } else {
        Ok(vec![fixed(value)?])
    }
}
fn block_tag(value: &Value, latest: u64) -> Result<u64, RpcError> {
    match value.as_str() {
        Some("latest" | "safe" | "finalized") => Ok(latest),
        Some("earliest") => Ok(0),
        _ => quantity(value),
    }
}
