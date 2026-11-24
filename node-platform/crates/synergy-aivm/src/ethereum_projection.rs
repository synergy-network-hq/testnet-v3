//! Pure Ethereum projections of one already authenticated native block.
//! These roots are derived views, not another ledger or finality mechanism.
use crate::ethereum::{encode_bytes, encode_length, ethereum_keccak256};
use crate::ethereum_execution::EvmExecutionReceipt;
#[derive(Debug, PartialEq, Eq)]
pub struct EthereumBlockRoots {
    pub transactions_root: [u8; 32],
    pub receipts_root: [u8; 32],
    pub logs_bloom: [u8; 256],
    pub gas_used: u64,
}
fn bytes(value: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    encode_bytes(value, &mut out);
    out
}
fn list(parts: impl Iterator<Item = Vec<u8>>) -> Vec<u8> {
    let body: Vec<u8> = parts.flatten().collect();
    let mut out = Vec::new();
    encode_length(body.len(), 0xc0, &mut out);
    out.extend(body);
    out
}
fn quantity(value: u64) -> Vec<u8> {
    let value = value.to_be_bytes();
    let first = value.iter().position(|byte| *byte != 0).unwrap_or(8);
    bytes(&value[first..])
}
pub fn accrue_log_bloom(bloom: &mut [u8; 256], value: &[u8]) {
    let hash = ethereum_keccak256(value);
    for index in [0, 2, 4] {
        let bit = (((hash[index] & 7) as usize) << 8) | hash[index + 1] as usize;
        bloom[255 - bit / 8] |= 1 << (bit % 8);
    }
}
/// Ordered canonical legacy receipt RLP: status, cumulative gas, bloom, logs.
pub fn legacy_receipt_rlp(receipt: &EvmExecutionReceipt, cumulative: u64) -> Vec<u8> {
    let mut bloom = [0; 256];
    for log in &receipt.logs {
        accrue_log_bloom(&mut bloom, &log.address);
        for topic in &log.topics {
            accrue_log_bloom(&mut bloom, topic);
        }
    }
    let logs = list(receipt.logs.iter().map(|log| {
        list(
            [
                bytes(&log.address),
                list(log.topics.iter().map(|topic| bytes(topic))),
                bytes(&log.data),
            ]
            .into_iter(),
        )
    }));
    list(
        [
            quantity(u64::from(receipt.success)),
            quantity(cumulative),
            bytes(&bloom),
            logs,
        ]
        .into_iter(),
    )
}
pub fn ethereum_block_roots(
    transactions: &[&[u8]],
    receipts: &[&EvmExecutionReceipt],
) -> Result<EthereumBlockRoots, &'static str> {
    if transactions.len() != receipts.len() || transactions.len() > 1428 {
        return Err("bounded Ethereum transaction/receipt mismatch");
    }
    let mut bloom = [0; 256];
    let mut gas = 0u64;
    let mut encoded = Vec::with_capacity(receipts.len());
    for (raw, receipt) in transactions.iter().zip(receipts) {
        if ethereum_keccak256(raw) != receipt.transaction_hash {
            return Err("Ethereum receipt differs from raw transaction hash");
        }
        gas = gas
            .checked_add(receipt.gas_used)
            .ok_or("Ethereum cumulative gas overflow")?;
        encoded.push(legacy_receipt_rlp(receipt, gas));
        for log in &receipt.logs {
            accrue_log_bloom(&mut bloom, &log.address);
            for topic in &log.topics {
                accrue_log_bloom(&mut bloom, topic);
            }
        }
    }
    Ok(EthereumBlockRoots {
        transactions_root: alloy_trie::root::ordered_trie_root_with_encoder(
            transactions,
            |raw, out| out.extend_from_slice(raw),
        )
        .0,
        receipts_root: alloy_trie::root::ordered_trie_root_with_encoder(
            &encoded,
            |receipt, out| out.extend_from_slice(receipt),
        )
        .0,
        logs_bloom: bloom,
        gas_used: gas,
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn empty_roots_are_the_standard_ethereum_empty_mpt_root() {
        let roots = ethereum_block_roots(&[], &[]).unwrap();
        assert_eq!(roots.transactions_root, alloy_trie::EMPTY_ROOT_HASH.0);
        assert_eq!(roots.transactions_root, roots.receipts_root);
        assert_eq!(roots.logs_bloom, [0; 256]);
        assert_eq!(roots.gas_used, 0);
    }
}

/// Genuine Ethereum account/storage MPT projection over exactly the addresses
/// visible to AIVM's existing resolver. This is recomputed from the one native
/// World; it does not persist or authorize an independent state database.
pub fn ethereum_state_root(
    world: &synergy_state::WorldState,
    budget: &std::sync::Arc<synergy_state::world_resources::WorldResourceBudget>,
) -> Result<[u8; 32], crate::ethereum_execution::EvmExecutionError> {
    use crate::ethereum_execution::{read_evm_account, EvmExecutionError};
    use alloy_trie::{HashBuilder, Nibbles};
    const PROTECTED: &str = "apqe-protected-account-candidate/v1/policy/";
    const STORAGE: &str = "aivm/ethereum/v1/storage/";
    fn word<const N: usize>(text: &str) -> Result<[u8; N], EvmExecutionError> {
        if text.len() != 2 * N {
            return Err(EvmExecutionError::CorruptState);
        }
        let mut value = [0; N];
        for (index, pair) in text.as_bytes().chunks_exact(2).enumerate() {
            if !pair
                .iter()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
            {
                return Err(EvmExecutionError::CorruptState);
            }
            value[index] = u8::from_str_radix(
                std::str::from_utf8(pair).map_err(|_| EvmExecutionError::CorruptState)?,
                16,
            )
            .map_err(|_| EvmExecutionError::CorruptState)?;
        }
        Ok(value)
    }
    let mut allocation = budget
        .reserve(65536)
        .map_err(EvmExecutionError::LocalResource)?;
    let mut addresses = Vec::<([u8; 32], [u8; 20])>::new();
    for key in world.accounts.keys() {
        if let Some(text) = key.strip_prefix("0x") {
            let address = word::<20>(text)?;
            allocation
                .grow(256)
                .map_err(EvmExecutionError::LocalResource)?;
            addresses.push((ethereum_keccak256(&address), address));
        }
    }
    for (key, _) in world
        .protocol
        .range(PROTECTED.to_owned()..)
        .take_while(|(key, _)| key.starts_with(PROTECTED))
    {
        let address = word::<20>(&key[PROTECTED.len()..])?;
        allocation
            .grow(256)
            .map_err(EvmExecutionError::LocalResource)?;
        addresses.push((ethereum_keccak256(&address), address));
    }
    addresses.sort_unstable();
    addresses.dedup();
    let mut state = HashBuilder::default();
    for (key, address) in addresses {
        let account = read_evm_account(world, address)?;
        // Match EIP161 empty-account semantics, including native tombstones left
        // by SELFDESTRUCT. Protected ownership records remain native authority.
        if account.nonce == 0 && account.balance_wei == [0; 32] && account.code.is_empty() {
            continue;
        }
        let prefix = format!(
            "{STORAGE}{}/",
            address
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        );
        let mut storage = HashBuilder::default();
        let mut slots = Vec::new();
        let mut storage_allocation = budget
            .reserve(65536)
            .map_err(EvmExecutionError::LocalResource)?;
        if !account.code.is_empty() {
            for (key, value) in world
                .protocol
                .range(prefix.clone()..)
                .take_while(|(key, _)| key.starts_with(&prefix))
            {
                let slot = word::<32>(&key[prefix.len()..])?;
                let value: [u8; 32] = value
                    .as_slice()
                    .try_into()
                    .map_err(|_| EvmExecutionError::CorruptState)?;
                if value == [0; 32] {
                    continue;
                }
                storage_allocation
                    .grow(256)
                    .map_err(EvmExecutionError::LocalResource)?;
                slots.push((ethereum_keccak256(&slot), value));
            }
        }
        slots.sort_unstable_by_key(|(key, _)| *key);
        for (key, value) in slots {
            let first = value.iter().position(|byte| *byte != 0).unwrap_or(32);
            storage.add_leaf(Nibbles::unpack(key), &bytes(&value[first..]));
        }
        let first = account
            .balance_wei
            .iter()
            .position(|byte| *byte != 0)
            .unwrap_or(32);
        let encoded = list(
            [
                quantity(account.nonce),
                bytes(&account.balance_wei[first..]),
                bytes(storage.root().as_slice()),
                bytes(&ethereum_keccak256(account.code)),
            ]
            .into_iter(),
        );
        state.add_leaf(Nibbles::unpack(key), &encoded);
    }
    Ok(state.root().0)
}

/// Exact byte count of the derived legacy block view [header,transactions,[]].
/// Header fields are the16 canonical RLP byte strings through baseFeePerGas.
/// This measures the projection; it never asserts its header hash is a PoSy ID.
pub fn ethereum_projected_block_rlp_size(
    fields: &[Vec<u8>],
    transactions: &[&[u8]],
) -> Result<usize, &'static str> {
    if fields.len() != 16
        || fields.iter().any(|field| field.len() > 65536)
        || transactions.len() > 1428
    {
        return Err("bounded projected Ethereum header required");
    }
    let header = list(fields.iter().map(|field| bytes(field)));
    let body = transactions.iter().try_fold(0usize, |size, raw| {
        size.checked_add(raw.len())
            .ok_or("projected transaction size overflow")
    })?;
    let mut prefix = Vec::new();
    encode_length(body, 0xc0, &mut prefix);
    let length = header
        .len()
        .checked_add(prefix.len())
        .and_then(|size| size.checked_add(body))
        .and_then(|size| size.checked_add(1))
        .ok_or("projected block size overflow")?;
    prefix.clear();
    encode_length(length, 0xc0, &mut prefix);
    length
        .checked_add(prefix.len())
        .ok_or("projected block size overflow")
}
