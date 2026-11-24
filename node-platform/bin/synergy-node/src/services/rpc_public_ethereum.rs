//! Closed disclosure schema for already finalized public EIP155 execution.
//! This permits no local pending/encrypted carrier, custody or recovery record.
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use synergy_aivm::ethereum_execution::{EvmCompatibilityPolicy, EVM_POLICY_KEY};
use synergy_governance::{EthereumActivationSpec, GovernanceExecution};
use synergy_state::WorldState;
const PREFIX: &str = "aivm/ethereum/v1/";
const MAX_RECORD: usize = 768 * 1024;

fn hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn height(value: &str) -> bool {
    value.len() == 20 && value.bytes().all(|b| b.is_ascii_digit()) && value.parse::<u64>().is_ok()
}
fn canonical<T: DeserializeOwned + Serialize>(bytes: &[u8], maximum: usize) -> Result<T, String> {
    if bytes.is_empty() || bytes.len() > maximum {
        return Err("public EVM record exceeds bound".into());
    }
    let value = serde_json::from_slice(bytes).map_err(|e| format!("public EVM schema: {e}"))?;
    if serde_json::to_vec(&value).map_err(|e| e.to_string())? != bytes {
        return Err("noncanonical public EVM record".into());
    }
    Ok(value)
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Log {
    address: [u8; 20],
    topics: Vec<[u8; 32]>,
    data: Vec<u8>,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Receipt {
    transaction_hash: [u8; 32],
    success: bool,
    gas_used: u64,
    fee_nwei: u128,
    created_address: Option<[u8; 20]>,
    output: Vec<u8>,
    logs: Vec<Log>,
    state_root_after: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    native_exception: Option<String>,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Transaction {
    height: u64,
    index: u32,
    first_log_index: u64,
    cumulative_gas_used: u64,
    raw: Vec<u8>,
    receipt: Option<Receipt>,
    rejection: Option<String>,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Block {
    transactions: Vec<[u8; 32]>,
    gas_used: u64,
    logs: u64,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Consumption {
    height: u64,
    ready: synergy_execution::ProcessingReadyRecord,
    transaction_hash: [u8; 32],
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Governed {
    schema_version: u32,
    included_height: u64,
    execution: GovernanceExecution,
}

fn validate_receipt(
    receipt: &Receipt,
    transaction_hash: [u8; 32],
    gas_limit: u64,
) -> Result<(), String> {
    if receipt.transaction_hash != transaction_hash
        || receipt.gas_used > gas_limit
        || !hex(&receipt.state_root_after, 64)
        || receipt.output.len() > 262144
        || receipt.logs.len() > 80_000
        || receipt
            .logs
            .iter()
            .any(|log| log.topics.len() > 4 || log.data.len() > 262144)
        || serde_json::to_vec(receipt)
            .map_err(|e| e.to_string())?
            .len()
            > 262144
        || receipt
            .native_exception
            .as_ref()
            .is_some_and(|v| v.len() > 128 || v.contains(char::is_control))
    {
        return Err("unqualified public EVM receipt/events".into());
    }
    Ok(())
}

/// Disclosure validation is distinct from native signature/finality authority.
pub(super) fn validate_record(world: &WorldState, key: &str, bytes: &[u8]) -> Result<bool, String> {
    use crate::services::ethereum_activation as activation;
    let invalid = || "unqualified public EVM/governance record".to_owned();
    if key == activation::RECORD_KEY {
        let record: Governed = canonical(bytes, 1024 * 1024)?;
        let mutation = &record.execution.mutation;
        let spec: EthereumActivationSpec = canonical(&mutation.value, 32768)?;
        let policy: EvmCompatibilityPolicy = canonical(&spec.policy_bytes, 16384)?;
        if record.schema_version != 1
            || record.included_height == 0
            || mutation.action_kind != activation::ACTION
            || mutation.target != activation::TARGET
            || mutation.expected_value.is_some()
            || spec.schema_version != 1
            || policy.chain_id != spec.chain_id
            || !hex(&spec.genesis_hash, 64)
            || !hex(&spec.frozen_epoch_context_root, 64)
            || !hex(&spec.policy_sha256, 64)
        {
            return Err(invalid());
        }
    } else if let Some(root) = key.strip_prefix("governance/aivm-ethereum-outcome-v1/") {
        let (version, genesis, authorization, at, outcome): (u32, String, String, u64, String) =
            canonical(bytes, 1024)?;
        if !hex(root, 64)
            || version != 1
            || !hex(&genesis, 64)
            || !hex(&authorization, 64)
            || at == 0
            || !matches!(outcome.as_str(), "expired" | "already-installed")
        {
            return Err(invalid());
        }
    } else if key == activation::ACTIVE_KEY {
        let (version, chain, genesis, effective, policy): (u32, u64, String, u64, String) =
            canonical(bytes, 1024)?;
        if version != 1 || chain == 0 || !hex(&genesis, 64) || effective == 0 || !hex(&policy, 64) {
            return Err(invalid());
        }
    } else if key == EVM_POLICY_KEY {
        let _: EvmCompatibilityPolicy = canonical(bytes, 16384)?;
        EvmCompatibilityPolicy::load(world).map_err(|e| e.to_string())?;
    } else if let Some(suffix) = key.strip_prefix(PREFIX) {
        if let Some(hash) = suffix.strip_prefix("code/") {
            if !hex(hash, 64) || bytes.is_empty() || bytes.len() > 24576 {
                return Err(invalid());
            }
        } else if let Some(slot) = suffix.strip_prefix("storage/") {
            let Some((address, slot)) = slot.split_once('/') else {
                return Err(invalid());
            };
            if !hex(address, 40) || !hex(slot, 64) || bytes.len() != 32 {
                return Err(invalid());
            }
        } else if let Some(number) = suffix.strip_prefix("native-parent/") {
            if !height(number) || bytes.len() != 32 {
                return Err(invalid());
            }
        } else if let Some(number) = suffix.strip_prefix("block/") {
            let block: Block = canonical(bytes, 262144)?;
            if !height(number)
                || block.transactions.len() > 1428
                || block.gas_used > 30_000_000
                || block.logs > 80_000
            {
                return Err(invalid());
            }
        } else if let Some(hash) = suffix.strip_prefix("transaction/") {
            let tx: Transaction = canonical(bytes, MAX_RECORD)?;
            let policy = EvmCompatibilityPolicy::load(world).map_err(|e| e.to_string())?;
            let parsed = synergy_aivm::ethereum::decode_eip155(&tx.raw, policy.chain_id)
                .map_err(|e| e.to_string())?;
            let expected = parsed
                .transaction_hash
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>();
            if !hex(hash, 64)
                || hash != expected
                || tx.height == 0
                || tx.raw.len() > 65516
                || tx.receipt.is_some() == tx.rejection.is_some()
                || tx
                    .rejection
                    .as_ref()
                    .is_some_and(|v| v.len() > 4096 || v.contains(char::is_control))
            {
                return Err(invalid());
            }
            if let Some(receipt) = tx.receipt {
                validate_receipt(&receipt, parsed.transaction_hash, parsed.gas_limit)?;
            }
        } else if let Some(envelope) = suffix.strip_prefix("consumption/") {
            let marker: Consumption = canonical(bytes, 32768)?;
            let ready = &marker.ready;
            if !hex(envelope, 128) || ready.item.envelope_id.0 != envelope || marker.height == 0 {
                return Err(invalid());
            }
            let key = format!("etdag-processing-ready-v1/item/{envelope}");
            if !super::public_processing::validate_record(
                &key,
                &serde_json::to_vec(ready).map_err(|e| e.to_string())?,
            )? {
                return Err(invalid());
            }
        } else {
            return Err(invalid());
        }
    } else {
        return Ok(false);
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn public_execution_schema_rejects_hidden_keys_fields_and_oversize_code_storage_events() {
        let mut world = WorldState::default();
        let bytes = serde_json::to_vec(&EvmCompatibilityPolicy {
            schema_version: 1,
            engine: "revm-43.0.3".into(),
            chain_id: 99999,
            fork: synergy_aivm::ethereum_execution::EvmFork::Shanghai,
            block_gas_limit: 30_000_000,
            memory_limit: 65536,
            maximum_accounts: 32,
            maximum_storage_slots: 256,
            maximum_code_bytes: 24576,
            maximum_patch_bytes: 262144,
            maximum_receipt_bytes: 262144,
            base_fee_nwei: 10,
            fee_collector: [0x55; 20],
            retain_base_fee_in_native_treasury: true,
            reject_sub_native_precision: true,
            native_exception_policy: "full-gas-no-action-v1".into(),
            blockhash_policy: "native-posy-block-id-v1".into(),
            randomness_policy: "authenticated-epoch-seed-v1".into(),
            rpc_projection_policy: "native-posy-evm-view-v1".into(),
        })
        .unwrap();
        world.protocol.insert(EVM_POLICY_KEY.into(), bytes.clone());
        assert!(validate_record(&world, EVM_POLICY_KEY, &bytes).unwrap());
        for suffix in [
            "pending/01",
            "custody/secret",
            "recovery/01",
            "decrypted/01",
        ] {
            assert!(validate_record(&world, &format!("{PREFIX}{suffix}"), b"secret").is_err());
        }
        let code = format!("{PREFIX}code/{}", "11".repeat(32));
        assert!(validate_record(&world, &code, &[0x60]).unwrap());
        assert!(validate_record(&world, &code, &vec![0; 24577]).is_err());
        let slot = format!("{PREFIX}storage/{}/{}", "11".repeat(20), "22".repeat(32));
        assert!(validate_record(&world, &slot, &[1; 32]).unwrap());
        assert!(validate_record(&world, &slot, &[1; 33]).is_err());
        assert!(validate_record(
            &world,
            &format!("{PREFIX}storage/../{}", "22".repeat(32)),
            &[1; 32]
        )
        .is_err());
        let block = format!("{PREFIX}block/{:020}", 1);
        assert!(validate_record(
            &world,
            &block,
            br#"{"transactions":[],"gas_used":0,"logs":0}"#
        )
        .unwrap());
        assert!(validate_record(
            &world,
            &block,
            br#"{"transactions":[],"gas_used":0,"logs":0,"secret":"hidden"}"#
        )
        .is_err());
        assert!(canonical::<Receipt>(br#"{"secret":"hidden"}"#, 262144).is_err());
        let mut receipt = Receipt {
            transaction_hash: [1; 32],
            success: true,
            gas_used: 21000,
            fee_nwei: 210000,
            created_address: None,
            output: vec![],
            logs: vec![Log {
                address: [2; 20],
                topics: vec![],
                data: vec![],
            }],
            state_root_after: "33".repeat(32),
            native_exception: None,
        };
        validate_receipt(&receipt, [1; 32], 21000).unwrap();
        receipt.logs[0].topics = vec![[0; 32]; 5];
        assert!(validate_receipt(&receipt, [1; 32], 21000).is_err());
        receipt.logs[0].topics.clear();
        receipt.logs[0].data = vec![0; 262145];
        assert!(validate_receipt(&receipt, [1; 32], 21000).is_err());
        receipt.logs.clear();
        receipt.output = vec![0; 262145];
        assert!(validate_receipt(&receipt, [1; 32], 21000).is_err());
    }
}
