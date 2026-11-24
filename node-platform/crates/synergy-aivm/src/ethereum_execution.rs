//! Internal Ethereum compatibility capability of canonical AIVM.
//!
//! No independent node, ledger, network, admission authority or finality exists
//! here. The caller supplies PoSy's actual block context and the common World
//! resource pool. A governed World policy must exist before execution; this
//! module does not install that policy or activate a network.
use crate::{
    ethereum::{nwei_to_wei, wei_to_nwei},
    ethereum_admission::authenticate_conventional_eip155,
};
use revm::bytecode::Bytecode;
use revm::context::{BlockEnv, TxEnv};
use revm::primitives::{hardfork::SpecId, Address, Bytes, TxKind, B256, KECCAK_EMPTY, U256};
use revm::state::AccountInfo;
use revm::{Context, Database, ExecuteEvm, MainBuilder, MainContext};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};
use synergy_state::world_resources::{
    world_owned_bytes, BudgetedWorld, WorldResourceBudget, WorldResourcePermit,
};
use synergy_state::{state_root, AccountState, WorldState};

pub const EVM_POLICY_KEY: &str = "aivm/ethereum/v1/policy";
const CODE_PREFIX: &str = "aivm/ethereum/v1/code/";
const STORAGE_PREFIX: &str = "aivm/ethereum/v1/storage/";
const PROTECTED_PREFIX: &str = "apqe-protected-account-candidate/v1/policy/";
// The canonical1024-frame EVM call-depth bound includes a separate1024-word
// operand stack per frame. Reentrant calls need this reservation even when
// they touch only one account and use almost no linear memory.
const CALL_FRAME_RESERVATION: usize = 64 * 1024 * 1024;
const _: () = assert!(std::mem::size_of::<AccountState>() <= 128);

// Pinned Shanghai allocation bound, not a simulation gas cap. Revm has one
// transaction-wide Vec<JournalEntry>. Repeated dirty SSTORE is its cheapest
// unbounded append (100 gas); cold loads and value CALL/CREATE cost more.
// Account warming/touching/nonce/code metadata is also covered by the fixed
// per-account reservation below. A 96-byte entry with Vec growth <=2x costs
// <2 bytes/gas. LOG costs 375 +375/topic +8/data-byte; its Vec headers, topic
// backing, payload and native hex conversion fit below3 bytes/gas, including
// geometric capacity. These are competing gas consumers, so3 bytes/gas bounds
// their combined live growth. The separate receipt/patch reserve covers native
// serialization. Revm's memory_limit is a GLOBAL shared-buffer limit, including
// nested frames; operand stacks are covered by CALL_FRAME_RESERVATION.
const _: () = assert!(
    std::mem::size_of::<revm::context_interface::journaled_state::entry::JournalEntry>() <= 96
);
const _: () = assert!(std::mem::size_of::<revm::primitives::Log>() <= 96);
fn interpreter_workspace(policy: &EvmCompatibilityPolicy, gas_limit: u64) -> usize {
    CALL_FRAME_RESERVATION
        + policy.memory_limit as usize * 8
        + policy.maximum_accounts * (policy.maximum_code_bytes + 8192) * 8
        + policy.maximum_storage_slots * 2048
        + gas_limit as usize * 3
        + policy.maximum_patch_bytes * 16
}

/// Preserve progress when a bounded pending queue prepays long-lived workers.
/// New intake must leave this scratch available in the common World pool;
/// otherwise all admitted items could wait forever for each other's permits.
pub fn ethereum_execution_headroom(world: &WorldState) -> Result<usize, EvmExecutionError> {
    let policy = EvmCompatibilityPolicy::load(world)?;
    let world = world_owned_bytes(world)
        .map_err(resource)?
        .checked_mul(4)
        .ok_or(EvmExecutionError::InvalidPolicy)?;
    // Four prospective native overlays cover the current action and PoSy's
    // unfinalized execution suffix. Sparse tree entries and owned code/storage
    // are bounded independently of encoded patch size; audit records have
    // explicit adapter bounds (4MiB disposition,32KiB identity,256KiB index).
    let growth = policy
        .maximum_accounts
        .checked_mul(4096 + 256 + policy.maximum_code_bytes)
        .and_then(|bytes| {
            policy
                .maximum_storage_slots
                .checked_mul(4096 + 256)
                .and_then(|slots| bytes.checked_add(slots))
        })
        .and_then(|bytes| bytes.checked_add(4 * 1024 * 1024 + 32 * 1024 + 256 * 1024))
        .and_then(|bytes| bytes.checked_mul(4))
        .ok_or(EvmExecutionError::InvalidPolicy)?;
    interpreter_workspace(&policy, policy.block_gas_limit)
        .checked_add(16 * 1024 * 1024) // native receipt/index metadata scratch
        .and_then(|bytes| bytes.checked_add(growth))
        .and_then(|bytes| bytes.checked_add(world))
        .ok_or(EvmExecutionError::InvalidPolicy)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EvmFork {
    Shanghai,
}

/// Candidate rules must be ratified, included in authenticated Genesis and
/// maintained by governed state transitions. No defaults select a live fork.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvmCompatibilityPolicy {
    pub schema_version: u32,
    pub engine: String,
    pub chain_id: u64,
    pub fork: EvmFork,
    pub block_gas_limit: u64,
    pub memory_limit: u64,
    pub maximum_accounts: usize,
    pub maximum_storage_slots: usize,
    pub maximum_code_bytes: usize,
    pub maximum_patch_bytes: usize,
    pub maximum_receipt_bytes: usize,
    pub base_fee_nwei: u64,
    pub fee_collector: [u8; 20],
    /// Explicit candidate economic rule: full fees reach the canonical native
    /// treasury. Ethereum's base-fee burn is credited there, never lost.
    pub retain_base_fee_in_native_treasury: bool,
    pub reject_sub_native_precision: bool,
    /// Governed native state violations are exceptional halts: discard action
    /// writes, consume the authenticated nonce and charge the full gas limit.
    pub native_exception_policy: String,
    pub blockhash_policy: String,
    pub randomness_policy: String,
    pub rpc_projection_policy: String,
}

#[derive(Debug)]
pub enum EvmExecutionError {
    MissingGovernedPolicy,
    InvalidPolicy,
    WrongNetwork,
    InvalidContext,
    Authorization(String),
    SpendingAuthorityRevoked,
    CryptoProvider,
    Precision,
    ProtectedAccount,
    AmbiguousAccount,
    CorruptState,
    MissingBlockHistory,
    Resource(String),
    LocalResource(synergy_state::world_resources::WorldResourceError),
    Execution(String),
    Conservation,
    InvalidTransaction(String),
}
impl std::fmt::Display for EvmExecutionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for EvmExecutionError {}
impl revm::database_interface::DBErrorMarker for EvmExecutionError {}

impl EvmCompatibilityPolicy {
    pub fn load(world: &WorldState) -> Result<Self, EvmExecutionError> {
        let bytes = world
            .protocol
            .get(EVM_POLICY_KEY)
            .ok_or(EvmExecutionError::MissingGovernedPolicy)?;
        if bytes.len() > 8192 {
            return Err(EvmExecutionError::InvalidPolicy);
        }
        let value: Self =
            serde_json::from_slice(bytes).map_err(|_| EvmExecutionError::InvalidPolicy)?;
        if value.schema_version != 1
            || value.engine != "revm-43.0.3"
            || value.chain_id == 0
            || !(21_000..=30_000_000).contains(&value.block_gas_limit)
            || !(65536..=16 * 1024 * 1024).contains(&value.memory_limit)
            || !(1..=256).contains(&value.maximum_accounts)
            || !(1..=4096).contains(&value.maximum_storage_slots)
            || !(1..=24576).contains(&value.maximum_code_bytes)
            || !(4096..=4 * 1024 * 1024).contains(&value.maximum_patch_bytes)
            || !(4096..=1024 * 1024).contains(&value.maximum_receipt_bytes)
            || value.base_fee_nwei == 0
            || value.base_fee_nwei.checked_mul(1_000_000_000).is_none()
            || !value.retain_base_fee_in_native_treasury
            || !value.reject_sub_native_precision
            || value.native_exception_policy != "full-gas-no-action-v1"
            || value.blockhash_policy != "native-posy-block-id-v1"
            || value.randomness_policy != "authenticated-epoch-seed-v1"
            || value.rpc_projection_policy != "native-posy-evm-view-v1"
        {
            return Err(EvmExecutionError::InvalidPolicy);
        }
        Ok(value)
    }
}

/// Supplied by native PoSy/execution ownership, never by an RPC caller's block
/// overrides. Missing relevant BLOCKHASH ancestors fail instead of fabricating
/// history. The common state checkpoint already authenticates the policy.
pub struct EvmBlockContext<'a> {
    pub chain_id: u64,
    pub genesis: [u8; 32],
    /// Exact initial-policy commitment from independently authenticated signed
    /// Genesis, never a request-supplied or World-self-authorized value.
    pub policy_sha256: [u8; 32],
    pub height: u64,
    pub timestamp: u64,
    /// Actual gas already consumed in this native candidate, supplied by its
    /// execution owner. GASLIMIT still reports the full governed block limit.
    pub gas_used_before: u64,
    pub randomness: [u8; 32],
    pub recent_block_hashes: &'a BTreeMap<u64, [u8; 32]>,
    /// Native protected-account owner must authenticate finalized registration
    /// and unchanged current policy. Absence denies every protected credit.
    pub protected_credit_verifier: Option<&'a dyn Fn(&[u8; 20], &WorldState) -> Result<(), String>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvmLog {
    pub address: [u8; 20],
    pub topics: Vec<[u8; 32]>,
    pub data: Vec<u8>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvmExecutionReceipt {
    pub transaction_hash: [u8; 32],
    pub success: bool,
    pub gas_used: u64,
    pub fee_nwei: u128,
    pub created_address: Option<[u8; 20]>,
    pub output: Vec<u8>,
    pub logs: Vec<EvmLog>,
    pub state_root_after: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub native_exception: Option<String>,
}
pub struct EvmExecutionCandidate {
    pub world: BudgetedWorld,
    pub receipt: BudgetedEvmReceipt,
}
#[derive(Debug)]
pub struct BudgetedEvmReceipt {
    receipt: EvmExecutionReceipt,
    _receipt_allocation: WorldResourcePermit,
}
impl std::ops::Deref for BudgetedEvmReceipt {
    type Target = EvmExecutionReceipt;
    fn deref(&self) -> &Self::Target {
        &self.receipt
    }
}
impl AsRef<EvmExecutionReceipt> for BudgetedEvmReceipt {
    fn as_ref(&self) -> &EvmExecutionReceipt {
        &self.receipt
    }
}
impl PartialEq for BudgetedEvmReceipt {
    fn eq(&self, other: &Self) -> bool {
        self.receipt == other.receipt
    }
}
impl Eq for BudgetedEvmReceipt {}

/// Ordered native execution converts deterministic native-policy violations
/// into governed exceptional halts. Local capacity, corrupt state, missing
/// authenticated history and invalid input remain distinct errors.
pub fn execute_ordered_legacy_evm(
    raw: &[u8],
    context: &EvmBlockContext<'_>,
    world: &WorldState,
    budget: &Arc<WorldResourceBudget>,
) -> Result<EvmExecutionCandidate, EvmExecutionError> {
    let reason = match execute_legacy_evm(raw, context, world, budget) {
        Ok(candidate) => return Ok(candidate),
        Err(EvmExecutionError::Precision) => "sub-native-precision",
        Err(EvmExecutionError::Conservation) => "native-coin-conservation",
        Err(EvmExecutionError::ProtectedAccount) => "protected-account-write",
        Err(EvmExecutionError::Resource(_)) => "governed-state-resource-bound",
        Err(error) => return Err(error),
    };
    let _scratch = budget.reserve(raw.len() * 8 + 65536).map_err(resource)?;
    let policy = EvmCompatibilityPolicy::load(world)?;
    let authenticated =
        authenticate_conventional_eip155(raw, context.chain_id, world).map_err(admission_error)?;
    let tx = authenticated.transaction();
    let terms = tx
        .native_terms()
        .map_err(|_| EvmExecutionError::Precision)?;
    let sender = conventional_evm_account_key(*authenticated.signer().account_id());
    let collector = evm_account_key(world, policy.fee_collector)?;
    if protected(world, Address::from(policy.fee_collector)) {
        return Err(EvmExecutionError::InvalidPolicy);
    }
    let account = world
        .accounts
        .get(&sender)
        .ok_or_else(|| EvmExecutionError::InvalidTransaction("missing funded account".into()))?;
    if account.nonce != tx.nonce
        || account.balance_nwei < terms.maximum_debit_nwei
        || account.code_hash.is_some()
    {
        return Err(EvmExecutionError::InvalidTransaction(
            "native exceptional halt lacks executable nonce/funds".into(),
        ));
    }
    let permit = budget
        .reserve(world_owned_bytes(world).map_err(resource)? + 32768)
        .map_err(resource)?;
    let receipt_permit = budget.reserve(32768).map_err(resource)?;
    let mut next = world.clone();
    let payer = next.accounts.get_mut(&sender).unwrap();
    payer.balance_nwei -= terms.maximum_fee_nwei;
    payer.nonce = payer
        .nonce
        .checked_add(1)
        .ok_or(EvmExecutionError::InvalidContext)?;
    let treasury = next.accounts.entry(collector).or_default();
    treasury.balance_nwei = treasury
        .balance_nwei
        .checked_add(terms.maximum_fee_nwei)
        .ok_or(EvmExecutionError::Conservation)?;
    let root = state_root(&next).map_err(|_| EvmExecutionError::CorruptState)?;
    Ok(EvmExecutionCandidate {
        world: BudgetedWorld::from_reserved(next, permit).map_err(resource)?,
        receipt: BudgetedEvmReceipt {
            receipt: EvmExecutionReceipt {
                transaction_hash: tx.transaction_hash,
                success: false,
                gas_used: tx.gas_limit,
                fee_nwei: terms.maximum_fee_nwei,
                created_address: None,
                output: Vec::new(),
                logs: Vec::new(),
                state_root_after: root,
                native_exception: Some(reason.into()),
            },
            _receipt_allocation: receipt_permit,
        },
    })
}

pub fn conventional_evm_account_key(address: [u8; 20]) -> String {
    format!("0x{}", hex(&address))
}

/// Closed native value-transfer input. The ordinary native signature covers
/// these exact bytes; it grants no ECDSA authority over the debited account.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NativeEvmFunding {
    pub recipient: [u8; 20],
    pub amount_nwei: u128,
}
impl NativeEvmFunding {
    pub const ENCODED_LENGTH: usize = 37;
    /// Same two-account native value transition as an ordinary SNRG transfer.
    pub const GAS_LIMIT: u64 = 21_000;
    /// Reuse the canonical bytes20/EIP55 codec. Parsing never establishes a
    /// protected registration or spending authority over either representation.
    pub fn from_evm_address(recipient: &str, amount_nwei: u128) -> Result<Self, EvmExecutionError> {
        let body = recipient.strip_prefix("0x").ok_or_else(|| EvmExecutionError::InvalidTransaction("checksummed EVM recipient required".into()))?;
        let account = synergy_address::parse_protected_wallet_address(&format!("synw{body}"))
            .map_err(EvmExecutionError::InvalidTransaction)?;
        let value = Self { recipient: *account.as_bytes(), amount_nwei };
        value.encode()?;
        Ok(value)
    }
    pub fn encode(self) -> Result<[u8; Self::ENCODED_LENGTH], EvmExecutionError> {
        if self.recipient == [0; 20] || self.amount_nwei == 0 {
            return Err(EvmExecutionError::InvalidTransaction("positive EOA funding required".into()));
        }
        let mut bytes = [0; Self::ENCODED_LENGTH];
        bytes[0] = 1;
        bytes[1..21].copy_from_slice(&self.recipient);
        bytes[21..].copy_from_slice(&self.amount_nwei.to_be_bytes());
        Ok(bytes)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, EvmExecutionError> {
        if bytes.len() != Self::ENCODED_LENGTH || bytes[0] != 1 {
            return Err(EvmExecutionError::InvalidTransaction("invalid native EOA funding input".into()));
        }
        let request = Self {
            recipient: bytes[1..21].try_into().map_err(|_| EvmExecutionError::InvalidContext)?,
            amount_nwei: u128::from_be_bytes(bytes[21..].try_into().map_err(|_| EvmExecutionError::InvalidContext)?),
        };
        request.encode()?;
        Ok(request)
    }

    /// Return an ordinary atomic native debit/credit in the SAME World. The
    /// canonical native owner must first authenticate the signed transaction
    /// and active governed EVM policy. Contract calls remain EVM execution.
    pub fn prepare(
        self, world: &WorldState, chain_id: u64, payer: &str, nonce: u64,
    ) -> Result<synergy_state::StateDiff, EvmExecutionError> {
        self.encode()?;
        let policy = EvmCompatibilityPolicy::load(world)?;
        if chain_id != policy.chain_id { return Err(EvmExecutionError::WrongNetwork); }
        if !synergy_address::is_valid_address(payer) || payer.starts_with("synw") || nonce == u64::MAX {
            return Err(EvmExecutionError::InvalidTransaction("ordinary native funding authority required".into()));
        }
        if protected(world, Address::from(self.recipient)) {
            return Err(EvmExecutionError::ProtectedAccount);
        }
        let target = evm_account_key(world, self.recipient)?;
        let source = world.accounts.get(payer).ok_or_else(|| EvmExecutionError::InvalidTransaction("native payer absent".into()))?;
        if source.nonce != nonce || source.code_hash.is_some() || source.balance_nwei < self.amount_nwei {
            return Err(EvmExecutionError::InvalidTransaction("native payer nonce or funds insufficient".into()));
        }
        if world.accounts.get(&target).is_some_and(|account| account.code_hash.is_some()) {
            return Err(EvmExecutionError::InvalidTransaction("native funding requires a conventional EOA".into()));
        }
        use synergy_state::AccountChange;
        Ok(synergy_state::StateDiff {
            changes: vec![
                AccountChange { account: payer.into(), debit_nwei: self.amount_nwei, credit_nwei: 0, expected_nonce: Some(nonce), code_hash: None },
                AccountChange { account: target, debit_nwei: 0, credit_nwei: self.amount_nwei, expected_nonce: None, code_hash: None },
            ],
            protocol_changes: Vec::new(),
        })
    }
}
fn protected(world: &WorldState, address: Address) -> bool {
    world
        .protocol
        .contains_key(&format!("{PROTECTED_PREFIX}{}", hex(address.as_slice())))
}

pub struct EvmAccountView<'a> {
    pub balance_wei: [u8; 32],
    pub nonce: u64,
    pub code: &'a [u8],
}
/// Read the same canonical native account used by execution, with exact EVM
/// denomination and validated content-addressed code. The caller must bind the
/// World to the authenticated block selected by its RPC request.
pub fn read_evm_account(
    world: &WorldState,
    address: [u8; 20],
) -> Result<EvmAccountView<'_>, EvmExecutionError> {
    let policy = EvmCompatibilityPolicy::load(world)?;
    let key = evm_account_key(world, address)?;
    let Some(account) = world.accounts.get(&key) else {
        return Ok(EvmAccountView {
            balance_wei: [0; 32],
            nonce: 0,
            code: &[],
        });
    };
    let code = match &account.code_hash {
        None => &[][..],
        Some(hash) => {
            if protected(world, Address::from(address)) {
                return Err(EvmExecutionError::ProtectedAccount);
            }
            let expected = parse_word(hash)?;
            let bytes = world
                .protocol
                .get(&format!("{CODE_PREFIX}{hash}"))
                .ok_or(EvmExecutionError::CorruptState)?;
            if bytes.len() > policy.maximum_code_bytes
                || sha3::Keccak256::digest(bytes).as_slice() != expected
            {
                return Err(EvmExecutionError::CorruptState);
            }
            bytes.as_slice()
        }
    };
    Ok(EvmAccountView {
        balance_wei: nwei_to_wei(account.balance_nwei),
        nonce: account.nonce,
        code,
    })
}
pub fn read_evm_storage(
    world: &WorldState,
    address: [u8; 20],
    index: [u8; 32],
) -> Result<[u8; 32], EvmExecutionError> {
    let account = read_evm_account(world, address)?;
    if account.code.is_empty() {
        return Ok([0; 32]);
    }
    world
        .protocol
        .get(&storage_key(
            Address::from(address),
            U256::from_be_bytes(index),
        ))
        .map(|bytes| {
            bytes
                .as_slice()
                .try_into()
                .map_err(|_| EvmExecutionError::CorruptState)
        })
        .unwrap_or(Ok([0; 32]))
}
/// One balance and nonce owner in the ordinary native World. Protected aliases
/// resolve to the existing synw key; conventional accounts use a canonical
/// lowercase 0x identity in that SAME map. No caller can select an arbitrary
/// native debit key, and coexistence of alias balances is refused.
pub fn evm_account_key(world: &WorldState, address: [u8; 20]) -> Result<String, EvmExecutionError> {
    let external = conventional_evm_account_key(address);
    let native = synergy_address::protected_wallet_native_representation(address)
        .map_err(|_| EvmExecutionError::CorruptState)?;
    let protected = protected(world, Address::from(address));
    if protected {
        if world.accounts.contains_key(&external) {
            return Err(EvmExecutionError::AmbiguousAccount);
        }
        Ok(native)
    } else if world.accounts.contains_key(&native) {
        Err(EvmExecutionError::AmbiguousAccount)
    } else {
        Ok(external)
    }
}

struct WorldDatabase<'a> {
    world: &'a WorldState,
    policy: &'a EvmCompatibilityPolicy,
    context: &'a EvmBlockContext<'a>,
    accounts: BTreeSet<Address>,
    slots: BTreeSet<(Address, U256)>,
}
impl Database for WorldDatabase<'_> {
    type Error = EvmExecutionError;
    fn basic(&mut self, address: Address) -> Result<Option<AccountInfo>, Self::Error> {
        self.accounts.insert(address);
        if self.accounts.len() > self.policy.maximum_accounts {
            return Err(EvmExecutionError::Resource("account-read bound".into()));
        }
        let key = evm_account_key(self.world, address.into_array())?;
        let Some(account) = self.world.accounts.get(&key) else {
            return Ok(None);
        };
        if account.balance_nwei == 0 && account.nonce == 0 && account.code_hash.is_none() {
            return Ok(None);
        }
        let hash = account
            .code_hash
            .as_ref()
            .map(|text| parse_word(text))
            .transpose()?
            .map(B256::from)
            .unwrap_or(KECCAK_EMPTY);
        if protected(self.world, address) && hash != KECCAK_EMPTY {
            return Err(EvmExecutionError::ProtectedAccount);
        }
        Ok(Some(AccountInfo {
            balance: U256::from_be_bytes(nwei_to_wei(account.balance_nwei)),
            nonce: account.nonce,
            code_hash: hash,
            code: None,
            ..Default::default()
        }))
    }
    fn code_by_hash(&mut self, hash: B256) -> Result<Bytecode, Self::Error> {
        if hash == KECCAK_EMPTY {
            return Ok(Bytecode::default());
        }
        let bytes = self
            .world
            .protocol
            .get(&format!("{CODE_PREFIX}{}", hex(hash.as_slice())))
            .ok_or(EvmExecutionError::CorruptState)?;
        if bytes.len() > self.policy.maximum_code_bytes
            || B256::from_slice(&sha3::Keccak256::digest(bytes)) != hash
        {
            return Err(EvmExecutionError::CorruptState);
        }
        Ok(Bytecode::new_legacy(Bytes::copy_from_slice(bytes)))
    }
    fn storage(&mut self, address: Address, index: U256) -> Result<U256, Self::Error> {
        self.slots.insert((address, index));
        if self.slots.len() > self.policy.maximum_storage_slots {
            return Err(EvmExecutionError::Resource("storage-read bound".into()));
        }
        let key = storage_key(address, index);
        match self.world.protocol.get(&key) {
            None => Ok(U256::ZERO),
            Some(bytes) => Ok(U256::from_be_bytes(
                <[u8; 32]>::try_from(bytes.as_slice())
                    .map_err(|_| EvmExecutionError::CorruptState)?,
            )),
        }
    }
    fn block_hash(&mut self, number: u64) -> Result<B256, Self::Error> {
        self.context
            .recent_block_hashes
            .get(&number)
            .copied()
            .map(B256::from)
            .ok_or(EvmExecutionError::MissingBlockHistory)
    }
}
use sha3::Digest;

#[derive(Debug)]
struct ApqeEvmPrecompiles;
impl revm::precompile::Crypto for ApqeEvmPrecompiles {
    fn sha256(&self, input: &[u8]) -> [u8; 32] {
        synergy_aegis::AegisProtectedPrimitives.sha256(input)
    }
    fn secp256k1_ecrecover(
        &self,
        signature: &[u8; 64],
        parity: u8,
        digest: &[u8; 32],
    ) -> Result<[u8; 32], revm::precompile::PrecompileHalt> {
        synergy_aegis::ethereum::recover_ethereum_precompile(signature, parity, digest)
            .map_err(|_| revm::precompile::PrecompileHalt::Secp256k1RecoverFailed)
    }
}
fn require_apqe_precompiles() -> Result<(), EvmExecutionError> {
    static ADMITTED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    if *ADMITTED.get_or_init(|| revm::install_crypto(ApqeEvmPrecompiles)) {
        Ok(())
    } else {
        Err(EvmExecutionError::Authorization(
            "another EVM crypto owner was installed".into(),
        ))
    }
}

/// Execute an externally signed EIP155 transaction speculatively under the
/// selected governed policy. The input World is immutable. Resource failures,
/// precision violations and policy conflicts cannot expose partially applied
/// native changes. The returned candidate still needs ordinary ETDAG/PoSy
/// inclusion and three-QC finality; its receipt is not a standalone proof.
pub fn execute_legacy_evm(
    raw: &[u8],
    context: &EvmBlockContext<'_>,
    world: &WorldState,
    budget: &Arc<WorldResourceBudget>,
) -> Result<EvmExecutionCandidate, EvmExecutionError> {
    if raw.is_empty() || raw.len() > crate::ethereum::MAX_LEGACY_TRANSACTION_BYTES {
        return Err(EvmExecutionError::Authorization(
            "raw transaction size bound".into(),
        ));
    }
    let _input_allocation = budget.reserve(raw.len() * 8 + 16384).map_err(resource)?;
    let policy = EvmCompatibilityPolicy::load(world)?;
    require_apqe_precompiles()?;
    if policy.chain_id != context.chain_id
        || context.genesis == [0; 32]
        || synergy_aegis::AegisProtectedPrimitives.sha256(&world.protocol[EVM_POLICY_KEY])
            != context.policy_sha256
    {
        return Err(EvmExecutionError::WrongNetwork);
    }
    if context.height == 0 || context.timestamp == 0 || context.recent_block_hashes.len() > 256 {
        return Err(EvmExecutionError::InvalidContext);
    }
    let authenticated =
        authenticate_conventional_eip155(raw, policy.chain_id, world).map_err(admission_error)?;
    let tx = authenticated.transaction();
    let terms = tx
        .native_terms()
        .map_err(|_| EvmExecutionError::Precision)?;
    if context.gas_used_before > policy.block_gas_limit
        || tx.gas_limit > policy.block_gas_limit - context.gas_used_before
        || terms.gas_price_nwei < policy.base_fee_nwei
    {
        return Err(EvmExecutionError::InvalidContext);
    }
    let beneficiary = Address::from(policy.fee_collector);
    if protected(world, beneficiary) {
        return Err(EvmExecutionError::ProtectedAccount);
    }
    // Reserve before interpreter allocation. Database reads are independently
    // bounded; code copies, journal growth, output/logs and shared memory are
    // conservatively charged as well as the eventual native write set.
    let workspace = interpreter_workspace(&policy, tx.gas_limit);
    let mut receipt_allocation = budget.reserve(workspace).map_err(resource)?;
    let tx_env = TxEnv {
        tx_type: 0,
        caller: Address::from(*authenticated.signer().account_id()),
        gas_limit: tx.gas_limit,
        gas_price: u128::from(terms.gas_price_nwei) * 1_000_000_000,
        kind: tx
            .recipient
            .map(Address::from)
            .map(TxKind::Call)
            .unwrap_or(TxKind::Create),
        value: U256::from_be_bytes(tx.value_wei),
        data: Bytes::copy_from_slice(&tx.data),
        nonce: tx.nonce,
        chain_id: Some(policy.chain_id),
        ..Default::default()
    };
    let mut result = run_kernel(&policy, context, world, tx_env, false)?;
    let gas_used = result.result.tx_gas_used();
    let base_fee =
        U256::from(gas_used) * U256::from(policy.base_fee_nwei) * U256::from(1_000_000_000u64);
    if !result.state.contains_key(&beneficiary) {
        let mut db = WorldDatabase {
            world,
            policy: &policy,
            context,
            accounts: BTreeSet::new(),
            slots: BTreeSet::new(),
        };
        let info = db.basic(beneficiary)?.unwrap_or_default();
        let mut account = revm::state::Account::from(info);
        account.mark_touch();
        result.state.insert(beneficiary, account);
    }
    let treasury = result
        .state
        .get_mut(&beneficiary)
        .ok_or(EvmExecutionError::CorruptState)?;
    treasury.info.balance = treasury
        .info
        .balance
        .checked_add(base_fee)
        .ok_or(EvmExecutionError::Conservation)?;
    let mut before = U256::ZERO;
    let mut after = U256::ZERO;
    let mut accounts = BTreeMap::new();
    let mut protocol = BTreeMap::<String, Option<Vec<u8>>>::new();
    let mut ordered: Vec<_> = result
        .state
        .iter()
        .filter(|(_, account)| account.is_touched())
        .collect();
    ordered.sort_by_key(|(address, _)| **address);
    if ordered.len() > policy.maximum_accounts {
        return Err(EvmExecutionError::Resource("state account bound".into()));
    }
    for (address, account) in ordered {
        let key = evm_account_key(world, address.into_array())?;
        let original = world.accounts.get(&key).cloned().unwrap_or_default();
        let balance = wei_to_nwei(account.info.balance.to_be_bytes())
            .map_err(|_| EvmExecutionError::Precision)?;
        before = before
            .checked_add(U256::from(original.balance_nwei))
            .ok_or(EvmExecutionError::Conservation)?;
        after = after
            .checked_add(U256::from(balance))
            .ok_or(EvmExecutionError::Conservation)?;
        if protected(world, *address)
            && (balance < original.balance_nwei
                || account.info.nonce != original.nonce
                || account.is_created()
                || account.is_selfdestructed()
                || account.info.code_hash != KECCAK_EMPTY)
        {
            return Err(EvmExecutionError::ProtectedAccount);
        }
        if protected(world, *address) && balance > original.balance_nwei {
            if !world.accounts.contains_key(&key) {
                return Err(EvmExecutionError::ProtectedAccount);
            }
            context
                .protected_credit_verifier
                .ok_or(EvmExecutionError::ProtectedAccount)?(
                &address.into_array(), world
            )
            .map_err(|_| EvmExecutionError::ProtectedAccount)?;
        }
        let destroyed = account.is_selfdestructed();
        let code_hash = (!destroyed && account.info.code_hash != KECCAK_EMPTY)
            .then(|| hex(account.info.code_hash.as_slice()));
        if let Some(code) = account.info.code.as_ref().filter(|_| code_hash.is_some()) {
            let bytes = code.original_bytes();
            if bytes.len() > policy.maximum_code_bytes {
                return Err(EvmExecutionError::Resource("code bound".into()));
            }
            let key = format!("{CODE_PREFIX}{}", code_hash.as_ref().unwrap());
            if world
                .protocol
                .get(&key)
                .is_some_and(|old| old.as_slice() != bytes.as_ref())
            {
                return Err(EvmExecutionError::CorruptState);
            }
            protocol.insert(key, Some(bytes.to_vec()));
        }
        if destroyed || account.is_created() {
            let prefix = format!("{STORAGE_PREFIX}{}/", hex(address.as_slice()));
            for (key, _) in world
                .protocol
                .range(prefix.clone()..)
                .take_while(|(key, _)| key.starts_with(&prefix))
                .take(policy.maximum_storage_slots + 1)
            {
                protocol.insert(key.clone(), None);
                if protocol.len() > policy.maximum_storage_slots {
                    return Err(EvmExecutionError::Resource("storage clear bound".into()));
                }
            }
        }
        if !destroyed {
            for (slot, value) in account.changed_storage_slots() {
                protocol.insert(
                    storage_key(*address, *slot),
                    (!value.present_value.is_zero())
                        .then(|| value.present_value.to_be_bytes::<32>().to_vec()),
                );
            }
        }
        if protocol.len() > policy.maximum_storage_slots + policy.maximum_accounts {
            return Err(EvmExecutionError::Resource("write-set bound".into()));
        }
        accounts.insert(
            key,
            AccountState {
                balance_nwei: balance,
                nonce: if destroyed { 0 } else { account.info.nonce },
                code_hash,
            },
        );
    }
    if before != after {
        return Err(EvmExecutionError::Conservation);
    }
    let patch_bytes = serde_json::to_vec(&(&accounts, &protocol))
        .map_err(|_| EvmExecutionError::CorruptState)?
        .len();
    if patch_bytes > policy.maximum_patch_bytes {
        return Err(EvmExecutionError::Resource(
            "encoded state patch bound".into(),
        ));
    }
    // The staged maps already live under workspace. Charge the native clone
    // only after validation, before allocation, using actual prospective entries.
    //4096 exceeds one full sparse11-slot BTree node for either native value
    // type; separately include every owned key/value/hash capacity. Existing
    // entries are deliberately counted twice when overwritten. A max encoded
    // patch multiplied by128 was unrelated to this actual allocation and could
    // starve an otherwise bounded action or exceptional halt.
    let mut candidate_charge = world_owned_bytes(world).map_err(resource)?;
    for (key, value) in &accounts {
        candidate_charge = candidate_charge
            .checked_add(
                4096 + key.capacity() + value.code_hash.as_ref().map_or(0, String::capacity),
            )
            .ok_or(EvmExecutionError::InvalidPolicy)?;
    }
    for (key, value) in &protocol {
        candidate_charge = candidate_charge
            .checked_add(4096 + key.capacity() + value.as_ref().map_or(0, Vec::capacity))
            .ok_or(EvmExecutionError::InvalidPolicy)?;
    }
    let candidate_permit = budget.reserve(candidate_charge).map_err(resource)?;
    let mut candidate = world.clone();
    for (key, value) in accounts {
        candidate.accounts.insert(key, value);
    }
    for (key, value) in protocol {
        match value {
            Some(bytes) => {
                candidate.protocol.insert(key, bytes);
            }
            None => {
                candidate.protocol.remove(&key);
            }
        }
    }
    let world = BudgetedWorld::from_reserved(candidate, candidate_permit).map_err(resource)?;
    let success = result.result.is_success();
    let logs = if success {
        result
            .result
            .logs()
            .iter()
            .map(|log| EvmLog {
                address: log.address.into_array(),
                topics: log.data.topics().iter().map(|topic| topic.0).collect(),
                data: log.data.data.to_vec(),
            })
            .collect()
    } else {
        Vec::new()
    };
    let receipt = EvmExecutionReceipt {
        native_exception: None,
        transaction_hash: tx.transaction_hash,
        success,
        gas_used,
        fee_nwei: u128::from(gas_used) * u128::from(terms.gas_price_nwei),
        created_address: result
            .result
            .created_address()
            .map(|address| address.into_array()),
        output: result
            .result
            .output()
            .map(|bytes| bytes.to_vec())
            .unwrap_or_default(),
        logs,
        state_root_after: state_root(world.as_ref())
            .map_err(|_| EvmExecutionError::CorruptState)?,
    };
    let encoded_receipt =
        serde_json::to_vec(&receipt).map_err(|_| EvmExecutionError::CorruptState)?;
    if encoded_receipt.len() > policy.maximum_receipt_bytes {
        return Err(EvmExecutionError::Resource("receipt bound".into()));
    }
    let receipt_size = encoded_receipt.len() * 4 + 8192;
    drop(result);
    receipt_allocation.shrink(receipt_size).map_err(resource)?;
    Ok(EvmExecutionCandidate {
        world,
        receipt: BudgetedEvmReceipt {
            receipt,
            _receipt_allocation: receipt_allocation,
        },
    })
}

fn run_kernel<'a>(
    policy: &'a EvmCompatibilityPolicy,
    context: &'a EvmBlockContext<'a>,
    world: &'a WorldState,
    tx: TxEnv,
    simulation: bool,
) -> Result<revm::context_interface::result::ResultAndState, EvmExecutionError> {
    let db = WorldDatabase {
        world,
        policy,
        context,
        accounts: BTreeSet::new(),
        slots: BTreeSet::new(),
    };
    let block = BlockEnv {
        number: U256::from(context.height),
        beneficiary: Address::from(policy.fee_collector),
        timestamp: U256::from(context.timestamp),
        gas_limit: policy.block_gas_limit,
        basefee: policy.base_fee_nwei * 1_000_000_000,
        prevrandao: Some(B256::from(context.randomness)),
        ..Default::default()
    };
    let mut evm = Context::mainnet()
        .with_db(db)
        .with_block(block)
        .modify_cfg_chained(|cfg| {
            cfg.set_spec_and_mainnet_gas_params(SpecId::SHANGHAI);
            cfg.chain_id = policy.chain_id;
            cfg.memory_limit = policy.memory_limit;
            cfg.limit_contract_code_size = Some(policy.maximum_code_bytes);
            cfg.limit_contract_initcode_size = Some(policy.maximum_code_bytes * 2);
            // Only the separate read-only API can waive these checks. Its output
            // contains neither state nor an executable candidate/authorization.
            cfg.disable_base_fee = simulation;
            cfg.disable_fee_charge = simulation;
            cfg.disable_eip3607 = simulation;
            cfg.disable_nonce_check = simulation;
        })
        .build_mainnet();
    evm.transact(tx).map_err(|error| match error {
        revm::context_interface::result::EVMError::Database(error) => error,
        revm::context_interface::result::EVMError::Transaction(error) => {
            EvmExecutionError::InvalidTransaction(error.to_string())
        }
        other => EvmExecutionError::Execution(format!("{other:?}")),
    })
}

pub struct EvmCallRequest<'a> {
    pub from: [u8; 20],
    pub recipient: Option<[u8; 20]>,
    pub value_wei: [u8; 32],
    pub data: &'a [u8],
    pub gas_limit: u64,
    pub gas_price_wei: u128,
}
pub struct EvmCallOutput {
    pub success: bool,
    pub output: Vec<u8>,
    pub gas_used: u64,
}
pub struct EvmCallResult {
    result: EvmCallOutput,
    _output_allocation: WorldResourcePermit,
}
impl std::ops::Deref for EvmCallResult {
    type Target = EvmCallOutput;
    fn deref(&self) -> &Self::Target {
        &self.result
    }
}
/// Unsigned RPC simulation, with the same opcode, state and block semantics.
/// The original native state is immutable, and no candidate or authorization
/// can be extracted from the result. GASPRICE uses the supplied view price;
/// BASEFEE reports the governed fee. The read-only kernel disables fee charging
/// without changing the price visible to contract opcodes.
pub fn call_evm(
    request: &EvmCallRequest<'_>,
    context: &EvmBlockContext<'_>,
    world: &WorldState,
    budget: &Arc<WorldResourceBudget>,
) -> Result<EvmCallResult, EvmExecutionError> {
    if request.data.len() > crate::ethereum::MAX_LEGACY_TRANSACTION_BYTES {
        return Err(EvmExecutionError::InvalidContext);
    }
    let _input = budget
        .reserve(request.data.len() * 4 + 16384)
        .map_err(resource)?;
    let policy = EvmCompatibilityPolicy::load(world)?;
    require_apqe_precompiles()?;
    if context.chain_id != policy.chain_id
        || context.genesis == [0; 32]
        || synergy_aegis::AegisProtectedPrimitives.sha256(&world.protocol[EVM_POLICY_KEY])
            != context.policy_sha256
    {
        return Err(EvmExecutionError::WrongNetwork);
    }
    if context.timestamp == 0
        || context.recent_block_hashes.len() > 256
        || request.gas_limit > policy.block_gas_limit
    {
        return Err(EvmExecutionError::InvalidContext);
    }
    wei_to_nwei(request.value_wei).map_err(|_| EvmExecutionError::Precision)?;
    let mut output_allocation = budget
        .reserve(interpreter_workspace(&policy, request.gas_limit))
        .map_err(resource)?;
    let tx = TxEnv {
        tx_type: 0,
        caller: Address::from(request.from),
        gas_limit: request.gas_limit,
        gas_price: request.gas_price_wei,
        kind: request
            .recipient
            .map(Address::from)
            .map(TxKind::Call)
            .unwrap_or(TxKind::Create),
        value: U256::from_be_bytes(request.value_wei),
        data: Bytes::copy_from_slice(request.data),
        nonce: 0,
        chain_id: Some(policy.chain_id),
        ..Default::default()
    };
    let result = run_kernel(&policy, context, world, tx, true)?;
    let mut before = U256::ZERO;
    let mut after = U256::ZERO;
    for (address, account) in result
        .state
        .iter()
        .filter(|(_, account)| account.is_touched())
    {
        let balance = wei_to_nwei(account.info.balance.to_be_bytes())
            .map_err(|_| EvmExecutionError::Precision)?;
        let key = evm_account_key(world, address.into_array())?;
        let original = world
            .accounts
            .get(&key)
            .map_or(0, |account| account.balance_nwei);
        if protected(world, *address) {
            if balance < original
                || account.is_selfdestructed()
                || account.info.code_hash != KECCAK_EMPTY
            {
                return Err(EvmExecutionError::ProtectedAccount);
            }
            if balance > original {
                context
                    .protected_credit_verifier
                    .ok_or(EvmExecutionError::ProtectedAccount)?(
                    &address.into_array(), world
                )
                .map_err(|_| EvmExecutionError::ProtectedAccount)?;
            }
        }
        before = before
            .checked_add(U256::from_be_bytes(nwei_to_wei(original)))
            .ok_or(EvmExecutionError::Conservation)?;
        after = after
            .checked_add(account.info.balance)
            .ok_or(EvmExecutionError::Conservation)?;
    }
    if before != after {
        return Err(EvmExecutionError::Conservation);
    }
    let success = result.result.is_success();
    let output = result
        .result
        .output()
        .map(|bytes| bytes.to_vec())
        .unwrap_or_default();
    let gas_used = result.result.tx_gas_used();
    drop(result);
    output_allocation
        .shrink(output.len() * 2 + 8192)
        .map_err(resource)?;
    Ok(EvmCallResult {
        result: EvmCallOutput {
            success,
            output,
            gas_used,
        },
        _output_allocation: output_allocation,
    })
}
/// Bounded binary search for a gas limit that actually succeeds on the chosen
/// state. Every probe runs the real interpreter and discards all state changes.
pub fn estimate_evm_gas(
    request: &EvmCallRequest<'_>,
    context: &EvmBlockContext<'_>,
    world: &WorldState,
    budget: &Arc<WorldResourceBudget>,
) -> Result<u64, EvmExecutionError> {
    let upper = call_evm(request, context, world, budget)?;
    if !upper.success {
        return Err(EvmExecutionError::Execution(
            "gas-estimation execution reverted".into(),
        ));
    }
    drop(upper);
    let mut low = 20_999;
    let mut high = request.gas_limit;
    while low + 1 < high {
        let middle = low + (high - low) / 2;
        let probe = EvmCallRequest {
            gas_limit: middle,
            ..*request
        };
        match call_evm(&probe, context, world, budget) {
            Ok(result) if result.success => high = middle,
            Ok(_) | Err(EvmExecutionError::InvalidTransaction(_)) => low = middle,
            Err(error) => return Err(error),
        }
    }
    Ok(high)
}
fn admission_error(error: crate::ethereum_admission::EthereumAdmissionError) -> EvmExecutionError {
    use crate::ethereum_admission::EthereumAdmissionError;
    match error {
        EthereumAdmissionError::ProtectedAccountRequiresQualifiedThresholdAuthorization => {
            EvmExecutionError::SpendingAuthorityRevoked
        }
        EthereumAdmissionError::Signature(
            synergy_aegis::ethereum::EthereumAuthorizationError::Provider,
        ) => EvmExecutionError::CryptoProvider,
        error => EvmExecutionError::Authorization(error.to_string()),
    }
}
fn resource(error: synergy_state::world_resources::WorldResourceError) -> EvmExecutionError {
    EvmExecutionError::LocalResource(error)
}
fn storage_key(address: Address, index: U256) -> String {
    format!(
        "{STORAGE_PREFIX}{}/{}",
        hex(address.as_slice()),
        hex(&index.to_be_bytes::<32>())
    )
}
fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(&mut text, "{byte:02x}").unwrap();
    }
    text
}
fn parse_word(text: &str) -> Result<[u8; 32], EvmExecutionError> {
    if text.len() != 64
        || !text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(EvmExecutionError::CorruptState);
    }
    let mut result = [0; 32];
    for (i, pair) in text.as_bytes().chunks_exact(2).enumerate() {
        result[i] = u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16)
            .map_err(|_| EvmExecutionError::CorruptState)?;
    }
    Ok(result)
}
