//! Current full-width native state view for the SAME canonical AIVM EVM kernel.
//! Read-only simulation only: no state candidate, receipt, enrollment, native
//! authorization or finality can be obtained from this API. Policy/context must
//! come from the actual verified state owner, never RPC-supplied overrides.
use crate::{
    ethereum::{nwei_to_wei, wei_to_nwei},
    ethereum_execution::{
        run_database_kernel, EvmExecutionError as Error, KernelConfiguration, KernelMode,
    },
    r1_addresses,
};
use revm::{
    bytecode::Bytecode,
    context::{BlockEnv, TxEnv},
    primitives::{Address, Bytes, TxKind, B256, KECCAK_EMPTY, U256},
    state::AccountInfo,
    Database,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
    time::Instant,
};
use synergy_address::r1_public::{
    canonical_framing as f, validate_received_identity, BirthBody, HashAlgorithm,
    NativeIdentityPresentation, NetworkRef, ObjectRef, Primitives, ProfileRef,
};
use synergy_protocol_types::{
    c14n02::{Decoder, Encoder},
    R1NetworkCoordinate, R1NetworkRef,
};
use synergy_state::{
    r1::{
        R1StateDomain as Domain, R1StateKey as Key, R1StateMap, R1StateOwner, R1StateValue as Value,
    },
    world_resources::{WorldResourceBudget, WorldResourcePermit},
};
pub const PROFILE_NAME: &str = "AIVM-EVM-STATE-R1";
pub const VM_PROFILE: &str = "AIVM-EVM-SHANGHAI-R1";
pub const VM_PROFILE_SCHEMA: &str = "AIVM-EVM-SHANGHAI-R1/1;canonicalAIVM-interpreter-capability=revm43.0.3/pinnedShanghai;SolidityABI+EVMcomputation+storage-semantics;VM20-computation-handles-only;full-nativeSynq-birth-and-account-authority-remain-APQE/currentstate;no-separate-VM/ledger/ECDSA-native-spending;allnativeassets-exactNwei-times1e9Wei;actualmutations-require-native87/qualifiedcodeadmission/ETDAG/fee4to1/PoSy3QC-finality;readonlyexecution-is-not-mutation-qualification";
pub const PROFILE_SCHEMA:&str=concat!("AIVM-EVM-STATE-R1/1;QACE-C14N02;fullN+typedGen48+activatedProfiles64;Shanghai-computation-in-canonical-AIVM-only;",
"Policy=(U16(1),chainU64,NIC64,blockGasU64,memoryU64,accountsU32,slotsU32,codeU32,outputU32,baseFeeNweiU64,operationalCapacityPolicy48);no-production-defaults;",
"Code=(U16(2),chainU64,NIC64,creatorNamespaceASCII8,creatorRaw48,nonce32,initialCode64,abi64,initializer64,completeCodeBytes24576);owner=synq-full48;recompute-received-APQE-contract-birth;",
"initialCode64=APQESHA3-512(F(AIVM.CODE,[AIVM-EVM-SHANGHAI-R1,1],N,[code]));",
"storage=ContractStorage/fullsynq/localKey32,ProtocolRecord(thisprofile,1,word32);absent-leaf=zero;",
"contractNonce=ProtocolConfiguration/Protocol/aivm/evm/r1/nonce/||synqRaw48,ProtocolRecord(thisprofile,1,U64BE);financialNonce=ReplayCoordinate/fullnative;",
"20byte-computation-handles-explicit-bidirectional-fullN/full48-native-binding;no-truncation/ECDSA-authority/native-EOA-balance-creation;nativeNwei-times1e9exactWei;",
"EVMcodeByHash=computationalKeccak256-only-on-already-native-validated-code;",
"BLOCKHASH=APQESHA3-256(F(AIVM.EVM.BLOCKHASH,[AIVM-EVM-STATE-R1,1],N,[Gen48,profiles64,height,block48]));no-native48truncation;missing-in-window-history-unavailable;",
"readonly-simulation-state-immutable/no-candidate-or-authority;explicitshared-process-budget/deadline/root-hash-bound;",
"actual-mutating-native87/ETDAG/fee4to1/PoSy3QC-finality-and-qualified-code-admission-remain-separate-required-integrations");
fn corrupt<T>() -> Result<T, Error> {
    Err(Error::CorruptState)
}
fn codec(_: synergy_protocol_types::c14n02::Error) -> Error {
    Error::CorruptState
}
fn apqe(n: R1NetworkRef) -> NetworkRef {
    NetworkRef {
        chain_id: n.chain_id,
        nic: n.nic,
    }
}
fn protocol_key(suffix: &[u8]) -> Key {
    Key {
        domain: Domain::ProtocolConfiguration,
        owner: R1StateOwner::Protocol,
        local_key: suffix.to_vec(),
    }
}
fn record(bytes: Vec<u8>) -> Value {
    Value::ProtocolRecord {
        profile_name: PROFILE_NAME.into(),
        profile_revision: 1,
        canonical_bytes: bytes,
    }
}
fn bytes<'a>(s: &'a R1StateMap, k: &Key) -> Result<Option<&'a [u8]>, Error> {
    match s.get(k) {
        None => Ok(None),
        Some(Value::ProtocolRecord {
            profile_name,
            profile_revision: 1,
            canonical_bytes,
        }) if profile_name == PROFILE_NAME => Ok(Some(canonical_bytes)),
        _ => corrupt(),
    }
}
fn policy_key() -> Key {
    protocol_key(b"aivm/evm/r1/policy")
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct R1EvmPolicy {
    pub network: R1NetworkRef,
    pub block_gas_limit: u64,
    pub memory_limit: u64,
    pub maximum_accounts: u32,
    pub maximum_storage_slots: u32,
    pub maximum_code_bytes: u32,
    pub maximum_output_bytes: u32,
    pub base_fee_nwei: u64,
    pub operational_capacity_policy: [u8; 48],
}
impl R1EvmPolicy {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, Error> {
        if self.network.chain_id == 0
            || !(21_000..=30_000_000).contains(&self.block_gas_limit)
            || !(65536..=16 * 1024 * 1024).contains(&self.memory_limit)
            || !(1..=256).contains(&self.maximum_accounts)
            || !(1..=4096).contains(&self.maximum_storage_slots)
            || !(1..=24576).contains(&self.maximum_code_bytes)
            || !(1..=1024 * 1024).contains(&self.maximum_output_bytes)
            || self.base_fee_nwei == 0
            || self.base_fee_nwei.checked_mul(1_000_000_000).is_none()
            || self.operational_capacity_policy == [0; 48]
        {
            return Err(Error::InvalidPolicy);
        }
        let mut e = Encoder::new(256);
        e.u16(1).map_err(codec)?;
        e.u64(self.network.chain_id).map_err(codec)?;
        e.fixed(&self.network.nic).map_err(codec)?;
        e.u64(self.block_gas_limit).map_err(codec)?;
        e.u64(self.memory_limit).map_err(codec)?;
        for v in [
            self.maximum_accounts,
            self.maximum_storage_slots,
            self.maximum_code_bytes,
            self.maximum_output_bytes,
        ] {
            e.u32(v).map_err(codec)?;
        }
        e.u64(self.base_fee_nwei).map_err(codec)?;
        e.fixed(&self.operational_capacity_policy).map_err(codec)?;
        e.finish().map_err(codec)
    }
    pub fn state_entry(&self) -> Result<(Key, Value), Error> {
        Ok((policy_key(), record(self.canonical_bytes()?)))
    }
    fn load(s: &R1StateMap, n: R1NetworkRef) -> Result<Self, Error> {
        let b = bytes(s, &policy_key())?.ok_or(Error::MissingGovernedPolicy)?;
        let mut d = Decoder::new(b, 256).map_err(codec)?;
        if d.u16().map_err(codec)? != 1 {
            return corrupt();
        }
        let p = Self {
            network: R1NetworkRef {
                chain_id: d.u64().map_err(codec)?,
                nic: d.fixed().map_err(codec)?,
            },
            block_gas_limit: d.u64().map_err(codec)?,
            memory_limit: d.u64().map_err(codec)?,
            maximum_accounts: d.u32().map_err(codec)?,
            maximum_storage_slots: d.u32().map_err(codec)?,
            maximum_code_bytes: d.u32().map_err(codec)?,
            maximum_output_bytes: d.u32().map_err(codec)?,
            base_fee_nwei: d.u64().map_err(codec)?,
            operational_capacity_policy: d.fixed().map_err(codec)?,
        };
        d.finish().map_err(codec)?;
        if p.network != n {
            return Err(Error::WrongNetwork);
        }
        if p.canonical_bytes()? != b {
            return corrupt();
        }
        Ok(p)
    }
    fn workspace(&self, gas: u64) -> Result<usize, Error> {
        // Same conservative canonical-kernel stack/journal/account/code bounds as
        // historical adapter; checked arithmetic precedes interpreter allocation.
        let values = [
            64 * 1024 * 1024,
            self.memory_limit
                .checked_mul(8)
                .ok_or(Error::InvalidPolicy)?,
            u64::from(self.maximum_accounts) * (u64::from(self.maximum_code_bytes) + 8192) * 8,
            u64::from(self.maximum_storage_slots) * 2048,
            gas.checked_mul(3).ok_or(Error::InvalidPolicy)?,
            u64::from(self.maximum_output_bytes) * 16,
            1024 * 1024,
        ];
        let total = values
            .into_iter()
            .try_fold(0u64, |a, b| a.checked_add(b))
            .ok_or(Error::InvalidPolicy)?;
        usize::try_from(total).map_err(|_| Error::InvalidPolicy)
    }
}
/// Complete received native contract birth plus code. This is data, not a
/// deployment grant. The actual native contract transition validates admission.
pub struct ReceivedContractCode {
    pub network: R1NetworkRef,
    pub creator: NativeIdentityPresentation,
    pub nonce32: [u8; 32],
    pub initial_code_commit64: [u8; 64],
    pub abi_commit64: [u8; 64],
    pub initializer_commit64: [u8; 64],
    pub code: Vec<u8>,
}
impl ReceivedContractCode {
    pub fn code_commitment(n: R1NetworkRef, code: &[u8]) -> Result<[u8; 64], Error> {
        if code.len() > 24576 {
            return Err(Error::InvalidContext);
        }
        let frame = f::frame(
            "AIVM.CODE",
            ProfileRef {
                name: VM_PROFILE,
                revision: 1,
            },
            Some(apqe(n)),
            f::Value::Array(vec![f::bytes(code)]),
            32768,
        )
        .map_err(|_| Error::CorruptState)?;
        Primitives
            .hash(HashAlgorithm::Sha3512, &frame)
            .map_err(|_| Error::CryptoProvider)?
            .try_into()
            .map_err(|_| Error::CryptoProvider)
    }
    pub fn state_entry(&self, owner: &NativeIdentityPresentation) -> Result<(Key, Value), Error> {
        self.validate(owner)?;
        let mut e = Encoder::new(32768);
        e.u16(2).map_err(codec)?;
        e.u64(self.network.chain_id).map_err(codec)?;
        e.fixed(&self.network.nic).map_err(codec)?;
        e.ascii(self.creator.namespace(), 8).map_err(codec)?;
        e.fixed(self.creator.raw48()).map_err(codec)?;
        e.fixed(&self.nonce32).map_err(codec)?;
        e.fixed(&self.initial_code_commit64).map_err(codec)?;
        e.fixed(&self.abi_commit64).map_err(codec)?;
        e.fixed(&self.initializer_commit64).map_err(codec)?;
        e.bytes(&self.code, 24576).map_err(codec)?;
        Ok((
            Key::native(Domain::ContractBinding, &owner.to_text())
                .map_err(|_| Error::CorruptState)?,
            record(e.finish().map_err(codec)?),
        ))
    }
    fn validate(&self, owner: &NativeIdentityPresentation) -> Result<(), Error> {
        if owner.namespace() != "synq"
            || self.network.chain_id == 0
            || Self::code_commitment(self.network, &self.code)? != self.initial_code_commit64
        {
            return corrupt();
        }
        validate_received_identity(
            &owner.to_text(),
            apqe(self.network),
            &BirthBody::Contract {
                creator: ObjectRef {
                    network: apqe(self.network),
                    namespace: self.creator.namespace(),
                    raw48: self.creator.raw48(),
                },
                nonce32: &self.nonce32,
                initial_code_commit64: &self.initial_code_commit64,
                abi_commit64: &self.abi_commit64,
                initializer_commit64: &self.initializer_commit64,
                vm_profile: ProfileRef {
                    name: VM_PROFILE,
                    revision: 1,
                },
            },
            32768,
        )
        .map_err(|_| Error::CorruptState)?;
        Ok(())
    }
    fn decode(
        b: &[u8],
        owner: &NativeIdentityPresentation,
        n: R1NetworkRef,
    ) -> Result<Self, Error> {
        let mut d = Decoder::new(b, 32768).map_err(codec)?;
        if d.u16().map_err(codec)? != 2
            || d.u64().map_err(codec)? != n.chain_id
            || d.fixed::<64>().map_err(codec)? != n.nic
        {
            return corrupt();
        }
        let ns = d.ascii(8).map_err(codec)?;
        let creator = NativeIdentityPresentation::from_raw(ns, d.fixed().map_err(codec)?)
            .map_err(|_| Error::CorruptState)?;
        let out = Self {
            network: n,
            creator,
            nonce32: d.fixed().map_err(codec)?,
            initial_code_commit64: d.fixed().map_err(codec)?,
            abi_commit64: d.fixed().map_err(codec)?,
            initializer_commit64: d.fixed().map_err(codec)?,
            code: d.bytes(24576).map_err(codec)?.to_vec(),
        };
        d.finish().map_err(codec)?;
        out.validate(owner)?;
        if out.state_entry(owner)?.1 != record(b.to_vec()) {
            return corrupt();
        }
        Ok(out)
    }
}
/// Trusted execution owner supplies actual context/history. This struct itself
/// is only data; matching its root does not authenticate ancestry or finality.
pub struct R1EvmReadContext<'a> {
    pub coordinate: &'a R1NetworkCoordinate,
    pub pre_state_root: [u8; 48],
    pub height: u64,
    pub timestamp: u64,
    pub randomness: [u8; 32],
    pub recent_blocks: &'a BTreeMap<u64, [u8; 48]>,
    pub deadline: Instant,
    pub maximum_root_hashes: u64,
}
pub struct R1EvmCall<'a> {
    pub from: [u8; 20],
    pub recipient: Option<[u8; 20]>,
    pub value_wei: [u8; 32],
    pub data: &'a [u8],
    pub gas_limit: u64,
    pub gas_price_wei: u128,
}
pub struct R1EvmReadResult {
    pub success: bool,
    pub output: Vec<u8>,
    pub gas_used: u64,
    _permit: WorldResourcePermit,
}
struct NativeDatabase<'a> {
    s: &'a R1StateMap,
    p: &'a R1EvmPolicy,
    c: &'a R1EvmReadContext<'a>,
    accounts: BTreeSet<Address>,
    slots: BTreeSet<(Address, U256)>,
    code: BTreeMap<B256, Bytecode>,
}
impl NativeDatabase<'_> {
    fn live(&self) -> Result<(), Error> {
        if Instant::now() >= self.c.deadline {
            Err(Error::InvalidContext)
        } else {
            Ok(())
        }
    }
    fn owner(&self, a: Address) -> Result<Option<NativeIdentityPresentation>, Error> {
        r1_addresses::by_handle(self.s, self.p.network, a.into_array())
            .map(|b| b.map(|b| b.native))
            .map_err(|_| Error::CorruptState)
    }
}
impl Database for NativeDatabase<'_> {
    type Error = Error;
    fn basic(&mut self, a: Address) -> Result<Option<AccountInfo>, Error> {
        self.live()?;
        self.accounts.insert(a);
        if self.accounts.len() > self.p.maximum_accounts as usize {
            return Err(Error::Resource("account-read bound".into()));
        }
        let Some(id) = self.owner(a)? else {
            return Ok(None);
        };
        let text = id.to_text();
        let balance = match self
            .s
            .get(&Key::native(Domain::NativeBalance, &text).map_err(|_| Error::CorruptState)?)
        {
            Some(Value::NativeBalance { amount_nwei }) => *amount_nwei,
            None if id.namespace() == "synq" => 0,
            _ => return corrupt(),
        };
        let (nonce, code) = if id.namespace() == "synq" {
            let b = bytes(
                self.s,
                &Key::native(Domain::ContractBinding, &text).map_err(|_| Error::CorruptState)?,
            )?
            .ok_or(Error::CorruptState)?;
            let code = ReceivedContractCode::decode(b, &id, self.p.network)?.code;
            if code.len() > self.p.maximum_code_bytes as usize {
                return corrupt();
            }
            let mut k = b"aivm/evm/r1/nonce/".to_vec();
            k.extend_from_slice(id.raw48());
            let nonce = match bytes(self.s, &protocol_key(&k))? {
                Some(b) => u64::from_be_bytes(b.try_into().map_err(|_| Error::CorruptState)?),
                None => return corrupt(),
            };
            (nonce, Bytecode::new_legacy(Bytes::from(code)))
        } else {
            if !matches!(
                self.s.get(
                    &Key::native(Domain::AccountAuthorization, &text)
                        .map_err(|_| Error::CorruptState)?
                ),
                Some(Value::AccountPolicy { .. })
            ) {
                return corrupt();
            }
            let nonce = match self.s.get(
                &Key::native(Domain::ReplayCoordinate, &text).map_err(|_| Error::CorruptState)?,
            ) {
                Some(Value::ReplayNonce { nonce }) => *nonce,
                _ => return corrupt(),
            };
            (nonce, Bytecode::default())
        };
        let hash = code.hash_slow();
        self.code.insert(hash, code.clone());
        Ok(Some(AccountInfo {
            balance: U256::from_be_bytes(nwei_to_wei(balance)),
            nonce,
            code_hash: hash,
            code: Some(code),
            ..Default::default()
        }))
    }
    fn code_by_hash(&mut self, h: B256) -> Result<Bytecode, Error> {
        self.live()?;
        if h == KECCAK_EMPTY {
            return Ok(Bytecode::default());
        }
        self.code.get(&h).cloned().ok_or(Error::CorruptState)
    }
    fn storage(&mut self, a: Address, i: U256) -> Result<U256, Error> {
        self.live()?;
        self.slots.insert((a, i));
        if self.slots.len() > self.p.maximum_storage_slots as usize {
            return Err(Error::Resource("storage-read bound".into()));
        }
        let Some(id) = self.owner(a)? else {
            return corrupt();
        };
        if id.namespace() != "synq" {
            return corrupt();
        }
        let mut k =
            Key::native(Domain::ContractStorage, &id.to_text()).map_err(|_| Error::CorruptState)?;
        k.local_key = i.to_be_bytes::<32>().to_vec();
        match bytes(self.s, &k)? {
            None => Ok(U256::ZERO),
            Some(b) => Ok(U256::from_be_bytes::<32>(
                b.try_into().map_err(|_| Error::CorruptState)?,
            )),
        }
    }
    fn block_hash(&mut self, h: u64) -> Result<B256, Error> {
        self.live()?;
        if h >= self.c.height || self.c.height - h > 256 {
            return Ok(B256::ZERO);
        }
        let id = self
            .c
            .recent_blocks
            .get(&h)
            .ok_or(Error::MissingBlockHistory)?;
        let frame = f::frame(
            "AIVM.EVM.BLOCKHASH",
            ProfileRef {
                name: PROFILE_NAME,
                revision: 1,
            },
            Some(apqe(self.p.network)),
            f::Value::Array(vec![
                f::bytes(&self.c.coordinate.genesis.digest),
                f::bytes(&self.c.coordinate.activated_profiles.commitment),
                f::Value::Unsigned(h),
                f::bytes(id),
            ]),
            1024,
        )
        .map_err(|_| Error::CorruptState)?;
        let hash = Primitives
            .hash(HashAlgorithm::Sha3256, &frame)
            .map_err(|_| Error::CryptoProvider)?;
        Ok(B256::from_slice(&hash))
    }
}
/// Actual read-only native state→canonical interpreter adapter. It cannot grant
/// native authority, persist state, charge fees or synthesize missing state.
pub fn call(
    request: &R1EvmCall<'_>,
    context: &R1EvmReadContext<'_>,
    state: &R1StateMap,
    budget: &Arc<WorldResourceBudget>,
) -> Result<R1EvmReadResult, Error> {
    context
        .coordinate
        .validate()
        .map_err(|_| Error::InvalidContext)?;
    if Instant::now() >= context.deadline
        || context.timestamp == 0
        || context.recent_blocks.len() > 256
        || request.data.len() > 131072
    {
        return Err(Error::InvalidContext);
    }
    let p = R1EvmPolicy::load(state, context.coordinate.network)?;
    if request.gas_limit > p.block_gas_limit || request.gas_limit < 21000 {
        return Err(Error::InvalidContext);
    }
    wei_to_nwei(request.value_wei).map_err(|_| Error::Precision)?;
    let hashes = (state.len() as u64)
        .checked_mul(386)
        .and_then(|v| v.checked_add(385))
        .ok_or(Error::InvalidContext)?;
    if hashes > context.maximum_root_hashes {
        return Err(Error::Resource("state-root hash budget".into()));
    }
    let reserve = state
        .canonical_storage_bytes()
        .checked_mul(4)
        .and_then(|n| n.checked_add(state.len().checked_mul(2048)?))
        .and_then(|n| n.checked_add(p.workspace(request.gas_limit).ok()?))
        .ok_or(Error::InvalidPolicy)?;
    let mut permit = budget.reserve(reserve).map_err(Error::LocalResource)?;
    let mut remaining = context.maximum_root_hashes;
    if synergy_state::r1_smt::root_with_limits(state, context.deadline, &mut remaining)
        .map_err(|_| Error::Resource("state-root work bound".into()))?
        != context.pre_state_root
    {
        return Err(Error::InvalidContext);
    }
    if Instant::now() >= context.deadline {
        return Err(Error::InvalidContext);
    }
    let db = NativeDatabase {
        s: state,
        p: &p,
        c: context,
        accounts: BTreeSet::new(),
        slots: BTreeSet::new(),
        code: BTreeMap::new(),
    };
    let block = BlockEnv {
        number: U256::from(context.height),
        beneficiary: Address::ZERO,
        timestamp: U256::from(context.timestamp),
        gas_limit: p.block_gas_limit,
        basefee: p.base_fee_nwei * 1_000_000_000,
        prevrandao: Some(B256::from(context.randomness)),
        ..Default::default()
    };
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
        chain_id: Some(p.network.chain_id),
        ..Default::default()
    };
    let result = run_database_kernel(
        &KernelConfiguration {
            chain_id: p.network.chain_id,
            memory_limit: p.memory_limit,
            maximum_code_bytes: p.maximum_code_bytes as usize,
        },
        block,
        db,
        tx,
        KernelMode::ReadOnlySimulation,
    )?;
    if Instant::now() >= context.deadline {
        return Err(Error::InvalidContext);
    }
    let output = result.result.output().map_or(&[][..], |v| v.as_ref());
    if output.len() > p.maximum_output_bytes as usize {
        return Err(Error::Resource("return-data bound".into()));
    }
    let success = result.result.is_success();
    let gas_used = result.result.tx_gas_used();
    let output = output.to_vec();
    drop(result);
    permit
        .shrink(output.len() * 2 + 8192)
        .map_err(Error::LocalResource)?;
    Ok(R1EvmReadResult {
        success,
        output,
        gas_used,
        _permit: permit,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use synergy_protocol_types::{R1GenesisReference, R1ProfileRef, R1ProfileSetReference};
    fn fixture(code: Vec<u8>) -> (R1StateMap, R1NetworkCoordinate, [u8; 20]) {
        let n = R1NetworkRef {
            chain_id: u64::MAX - 1,
            nic: [7; 64],
        };
        let received = ReceivedContractCode {
            network: n,
            creator: NativeIdentityPresentation::from_raw("synw", [8; 48]).unwrap(),
            nonce32: [9; 32],
            initial_code_commit64: ReceivedContractCode::code_commitment(n, &code).unwrap(),
            abi_commit64: [10; 64],
            initializer_commit64: [11; 64],
            code,
        };
        let id = synergy_address_engine::apqe::native_identity_derivation_r1::derive_candidate(
            apqe(n),
            &BirthBody::Contract {
                creator: ObjectRef {
                    network: apqe(n),
                    namespace: received.creator.namespace(),
                    raw48: received.creator.raw48(),
                },
                nonce32: &received.nonce32,
                initial_code_commit64: &received.initial_code_commit64,
                abi_commit64: &received.abi_commit64,
                initializer_commit64: &received.initializer_commit64,
                vm_profile: ProfileRef {
                    name: VM_PROFILE,
                    revision: 1,
                },
            },
            32768,
        )
        .unwrap()
        .presentation;
        let p = R1EvmPolicy {
            network: n,
            block_gas_limit: 100_000,
            memory_limit: 65536,
            maximum_accounts: 16,
            maximum_storage_slots: 32,
            maximum_code_bytes: 24576,
            maximum_output_bytes: 4096,
            base_fee_nwei: 1,
            operational_capacity_policy: [12; 48],
        };
        let mut s = R1StateMap::new();
        for (k, v) in [p.state_entry().unwrap(), received.state_entry(&id).unwrap()] {
            s.insert(k, v).unwrap();
        }
        let mut nonce = b"aivm/evm/r1/nonce/".to_vec();
        nonce.extend_from_slice(id.raw48());
        s.insert(protocol_key(&nonce), record(1u64.to_be_bytes().to_vec()))
            .unwrap();
        let mut slot = Key::native(Domain::ContractStorage, &id.to_text()).unwrap();
        slot.local_key = vec![0; 32];
        s.insert(slot, record(U256::from(42).to_be_bytes::<32>().to_vec()))
            .unwrap();
        let mut h = [0; 20];
        h[18] = 1;
        r1_addresses::initialize(&mut s, n, h).unwrap();
        r1_addresses::register_contract(&mut s, n, id, h).unwrap();
        let c = R1NetworkCoordinate {
            network: n,
            genesis: R1GenesisReference {
                profile: R1ProfileRef {
                    name: "SYNERGY-GENESIS-R1".into(),
                    revision: 1,
                },
                digest: [13; 48],
            },
            activated_profiles: R1ProfileSetReference {
                profile: R1ProfileRef {
                    name: "APQE-PROFILE-SET".into(),
                    revision: 1,
                },
                commitment: [14; 64],
            },
        };
        (s, c, h)
    }
    fn context<'a>(
        s: &R1StateMap,
        c: &'a R1NetworkCoordinate,
        h: &'a BTreeMap<u64, [u8; 48]>,
    ) -> R1EvmReadContext<'a> {
        R1EvmReadContext {
            coordinate: c,
            pre_state_root: s.root().unwrap(),
            height: 100,
            timestamp: 1234,
            randomness: [15; 32],
            recent_blocks: h,
            deadline: Instant::now() + Duration::from_secs(10),
            maximum_root_hashes: 1_000_000,
        }
    }
    fn request(h: [u8; 20]) -> R1EvmCall<'static> {
        R1EvmCall {
            from: [0; 20],
            recipient: Some(h),
            value_wei: [0; 32],
            data: &[],
            gas_limit: 100_000,
            gas_price_wei: 0,
        }
    }
    #[test]
    fn canonical_interpreter_reads_full_native_contract_storage_and_discards_writes() {
        // Real SSTORE(0,9); SLOAD(0); return word9. The original native slot42
        // remains untouched, and result exposes no state candidate or authority.
        let (s, c, h) = fixture(vec![
            0x60, 9, 0x60, 0, 0x55, 0x60, 0, 0x54, 0x60, 0, 0x52, 0x60, 32, 0x60, 0, 0xf3,
        ]);
        let history = BTreeMap::new();
        let cx = context(&s, &c, &history);
        let before = s.canonical_storage_bytes();
        let root = s.root().unwrap();
        let budget = WorldResourceBudget::new(256 * 1024 * 1024);
        let out = call(&request(h), &cx, &s, &budget).unwrap();
        assert!(out.success);
        assert_eq!(out.output, U256::from(9).to_be_bytes::<32>());
        assert!(out.gas_used > 21000);
        assert!(budget.used() > 0);
        drop(out);
        assert_eq!(budget.used(), 0);
        assert_eq!(s.root().unwrap(), root);
        assert_eq!(s.canonical_storage_bytes(), before);
        let mut db = NativeDatabase {
            s: &s,
            p: &R1EvmPolicy::load(&s, c.network).unwrap(),
            c: &cx,
            accounts: BTreeSet::new(),
            slots: BTreeSet::new(),
            code: BTreeMap::new(),
        };
        assert_eq!(
            db.storage(Address::from(h), U256::ZERO).unwrap(),
            U256::from(42)
        );
    }
    #[test]
    fn missing_context_policy_work_or_capacity_never_runs_a_candidate() {
        let (s, c, h) = fixture(vec![0]);
        let history = BTreeMap::new();
        let mut cx = context(&s, &c, &history);
        let request = request(h);
        let budget = WorldResourceBudget::new(256 * 1024 * 1024);
        cx.pre_state_root[47] ^= 1;
        assert!(call(&request, &cx, &s, &budget).is_err());
        cx.pre_state_root = s.root().unwrap();
        cx.maximum_root_hashes = 1;
        assert!(call(&request, &cx, &s, &budget).is_err());
        cx.maximum_root_hashes = 1_000_000;
        cx.deadline = Instant::now();
        assert!(call(&request, &cx, &s, &budget).is_err());
        assert_eq!(budget.used(), 0);
        let cx = context(&s, &c, &history);
        let tiny = WorldResourceBudget::new(1024);
        assert!(matches!(
            call(&request, &cx, &s, &tiny),
            Err(Error::LocalResource(_))
        ));
        assert_eq!(tiny.used(), 0);
        let mut wrong = c.clone();
        wrong.network.nic[63] ^= 1;
        let cx = context(&s, &wrong, &history);
        assert!(matches!(
            call(&request, &cx, &s, &budget),
            Err(Error::WrongNetwork)
        ));
        assert_eq!(budget.used(), 0);
        let mut missing = s.clone();
        missing.remove(&policy_key()).unwrap();
        let cx = context(&missing, &c, &history);
        assert!(matches!(
            call(&request, &cx, &missing, &budget),
            Err(Error::MissingGovernedPolicy)
        ));
    }
    #[test]
    fn blockhash_is_explicit_full48_projection_and_missing_history_refuses() {
        let (s, c, _) = fixture(vec![0]);
        let mut history = BTreeMap::new();
        let mut full = [16; 48];
        full[47] = 17;
        history.insert(99, full);
        let cx = context(&s, &c, &history);
        let p = R1EvmPolicy::load(&s, c.network).unwrap();
        let mut db = NativeDatabase {
            s: &s,
            p: &p,
            c: &cx,
            accounts: BTreeSet::new(),
            slots: BTreeSet::new(),
            code: BTreeMap::new(),
        };
        let first = db.block_hash(99).unwrap();
        assert_ne!(first, B256::from_slice(&full[..32]));
        assert!(matches!(db.block_hash(98), Err(Error::MissingBlockHistory)));
        assert_eq!(db.block_hash(100).unwrap(), B256::ZERO);
        full[47] ^= 1;
        let mut changed = BTreeMap::new();
        changed.insert(99, full);
        let other = context(&s, &c, &changed);
        let mut db = NativeDatabase {
            s: &s,
            p: &p,
            c: &other,
            accounts: BTreeSet::new(),
            slots: BTreeSet::new(),
            code: BTreeMap::new(),
        };
        assert_ne!(first, db.block_hash(99).unwrap());
    }
}
