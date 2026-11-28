//! Current typed state construction. Historical JSON/SHA3-256 state is separate.
//! QACE v0.4 pp91–95 and108–109 govern the selected SMT384 construction.
//! A map or matching root does not authenticate Genesis, execution or finality.
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use synergy_address::r1_public::{
    validate_account_birth_from_policy_frame, HashAlgorithm, NativeIdentityPresentation,
    NetworkRef, Primitives,
};
use synergy_protocol_types::c14n02::Encoder;
use synergy_protocol_types::{R1NetworkRef, R1ProfileRef};

pub const STATE_PROFILE_NAME: &str = "QACE-SMT384-R1";
pub const STATE_PROFILE_REVISION: u32 = 1;
pub const RECEIPT_PROFILE_NAME: &str = "QACE-RECEIPT-R1";
pub const RECEIPT_PROFILE_REVISION: u32 = 1;
/// Exact ASCII descriptor committed by the closed Genesis profile catalog.
/// This names binary schemas; JSON persistence is deliberately excluded.
pub const STATE_PROFILE_SCHEMA:&str=concat!(
 "QACE-SMT384-R1/1;codec=QACE-C14N-02;H=SHA3-384(U16BE(2),ASCII128(domain),typed-fields);",
 "StateKey=(domain:U16BE,owner:Owner,local_key:Bytes128);",
 "domain=AccountAuthorization:1,NativeBalance:2,ReplayCoordinate:3,ContractBinding:4,ContractStorage:5,StsDefinition:6,AssetOwnership:7,SrpaRegistry:8,AuthorizedMessage:9,SystemSettlement:10,ProtocolConfiguration:11,ValidatorBondPosition:12;",
 "Owner=U16BE(0):Protocol|U16BE(1):ASCII8(namespace),raw48|U16BE(2):srpa_suffix:U16BE|U16BE(3):restricted_kind:U16BE;",
 "restricted_kind=Treasury:0,TreasuryRecovery:1,SecurityForfeiture:2,FeeRoundingEscrow:3;",
 "account=(ASCII8(namespace),raw48);account_namespace=synw,syns,syna,synm,synu,synq;authorization_owner_excludes=synq;",
 "financial_domains=1,2,3,12:local_key_empty;restricted_owner:local_key_empty,domain10;srpa_owner=exact69literal_registry,domain8;protocol_owner=domain9,10,11;native_owner_excludes=domain8,10,11;bond_owner=synv1;",
 "StateValue=(schema:U16BE(1),variant:U16BE,fields);",
    "variant=1:amount:U128BE|2:nonce:U64BE|3:policy_epoch:U64BE,policy_commitment64,complete_APQE_policy_frame:Bytes131072|4:owner:account,beneficiary:account,amount:U128BE|5:amount:U128BE,policy_commitment64|6:amount:U128BE|7:ASCII128(profile_name),revision:U32BE,canonical_bytes:Bytes131072;",
 "domain_value=1:3,2:1,3:2,12:4,10:5-or-6;variant7_excludes_domains=1,2,3,12;restricted_owner_excludes=variant6;protocol_owner_excludes=variant5;",
 "bounds=262144entries,67108864encoded-key-value-bytes;duplicate_full_key_reject;hash_path_collision_reject;",
 "path=H(QACE/STATE/PATH/02,key);leaf=H(QACE/STATE/LEAF/02,key,value);empty384=H(QACE/STATE/EMPTY/02);node(d,l,r)=H(QACE/STATE/NODE/02,U16BE(d),l,r);",
 "path=384bits-MSB-first;empty[d]=node(d,empty[d+1],empty[d+1]);root=depth0;",
 "proof=bitmap48-MSB-first,siblings-increasing-depth,omit-exact-defaults;reject-redundant-default-siblings,wrong-count,more-than384siblings;point-proof-is-not-range-completeness;",
 "initial-account-policy-epoch=1;initial-replay-nonce=0;local-storage-generations-and-current-block-digest-excluded"
);
pub const MAX_KEY_LOCAL_BYTES: usize = 128;
pub const MAX_VALUE_BYTES: usize = 131_072;
pub const MAX_STATE_ENTRIES: usize = 262_144;
pub const MAX_TOTAL_STATE_BYTES: usize = 64 * 1024 * 1024;
pub(crate) const MAX_CANONICAL_BYTES: usize = MAX_VALUE_BYTES + 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum R1StateError {
    InvalidKey,
    InvalidValue,
    InvalidProfile,
    InvalidPolicy,
    InvalidAllocation,
    Duplicate,
    Overflow,
    ResourceLimit,
    PathCollision,
    Proof,
    Context,
    Unavailable,
    Corrupt,
    Storage(String),
    CeremonyRequired,
}
impl std::fmt::Display for R1StateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "R1 state error: {self:?}")
    }
}
impl std::error::Error for R1StateError {}
impl From<synergy_protocol_types::c14n02::Error> for R1StateError {
    fn from(_: synergy_protocol_types::c14n02::Error) -> Self {
        Self::InvalidValue
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[repr(u16)]
pub enum R1StateDomain {
    AccountAuthorization = 1,
    NativeBalance = 2,
    ReplayCoordinate = 3,
    ContractBinding = 4,
    ContractStorage = 5,
    StsDefinition = 6,
    AssetOwnership = 7,
    SrpaRegistry = 8,
    AuthorizedMessage = 9,
    SystemSettlement = 10,
    ProtocolConfiguration = 11,
    ValidatorBondPosition = 12,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[repr(u16)]
pub enum RestrictedRecordKind {
    Treasury = 0,
    TreasuryRecovery = 1,
    SecurityForfeiture = 2,
    FeeRoundingEscrow = 3,
}
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum R1StateOwner {
    Native { identity: String },
    Srpa { suffix: u16 },
    Restricted { record: RestrictedRecordKind },
    Protocol,
}
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct R1StateKey {
    pub domain: R1StateDomain,
    pub owner: R1StateOwner,
    pub local_key: Vec<u8>,
}
impl R1StateKey {
    pub fn native(domain: R1StateDomain, identity: &str) -> Result<Self, R1StateError> {
        let key = Self {
            domain,
            owner: R1StateOwner::Native {
                identity: identity.into(),
            },
            local_key: Vec::new(),
        };
        key.validate()?;
        Ok(key)
    }
    pub fn validate(&self) -> Result<(), R1StateError> {
        if self.local_key.len() > MAX_KEY_LOCAL_BYTES {
            return Err(R1StateError::ResourceLimit);
        }
        if !self.local_key.is_empty()
            && (matches!(
                self.domain,
                R1StateDomain::AccountAuthorization
                    | R1StateDomain::NativeBalance
                    | R1StateDomain::ReplayCoordinate
                    | R1StateDomain::ValidatorBondPosition
            ) || matches!(self.owner, R1StateOwner::Restricted { .. }))
        {
            return Err(R1StateError::InvalidKey);
        }
        match &self.owner {
            R1StateOwner::Native { identity } => {
                let id = NativeIdentityPresentation::parse(identity)
                    .map_err(|_| R1StateError::InvalidKey)?;
                if self.domain == R1StateDomain::AccountAuthorization && id.namespace() == "synq" {
                    return Err(R1StateError::InvalidKey);
                }
                if matches!(
                    self.domain,
                    R1StateDomain::NativeBalance
                        | R1StateDomain::ReplayCoordinate
                        | R1StateDomain::AccountAuthorization
                ) && !matches!(
                    id.namespace(),
                    "synw" | "syns" | "syna" | "synm" | "synu" | "synq"
                ) {
                    return Err(R1StateError::InvalidKey);
                }
                if self.domain == R1StateDomain::ValidatorBondPosition && id.namespace() != "synv1"
                {
                    return Err(R1StateError::InvalidKey);
                }
                if matches!(
                    self.domain,
                    R1StateDomain::SrpaRegistry
                        | R1StateDomain::SystemSettlement
                        | R1StateDomain::ProtocolConfiguration
                ) {
                    return Err(R1StateError::InvalidKey);
                }
            }
            R1StateOwner::Srpa { suffix } => {
                if self.domain != R1StateDomain::SrpaRegistry
                    || synergy_address::r1_public::native_identifier::parse(&format!(
                        "syn{suffix:038x}"
                    ))
                    .is_err()
                {
                    return Err(R1StateError::InvalidKey);
                }
            }
            R1StateOwner::Restricted { .. } => {
                if self.domain != R1StateDomain::SystemSettlement {
                    return Err(R1StateError::InvalidKey);
                }
            }
            R1StateOwner::Protocol => {
                if !matches!(
                    self.domain,
                    R1StateDomain::ProtocolConfiguration
                        | R1StateDomain::SystemSettlement
                        | R1StateDomain::AuthorizedMessage
                ) {
                    return Err(R1StateError::InvalidKey);
                }
            }
        }
        Ok(())
    }
    pub(crate) fn encode(&self, e: &mut Encoder) -> Result<(), R1StateError> {
        self.validate()?;
        e.u16(self.domain as u16)?;
        match &self.owner {
            R1StateOwner::Protocol => e.u16(0)?,
            R1StateOwner::Native { identity } => {
                let id = NativeIdentityPresentation::parse(identity)
                    .map_err(|_| R1StateError::InvalidKey)?;
                e.u16(1)?;
                e.ascii(id.namespace(), 8)?;
                e.fixed(id.raw48())?;
            }
            R1StateOwner::Srpa { suffix } => {
                e.u16(2)?;
                e.u16(*suffix)?;
            }
            R1StateOwner::Restricted { record } => {
                e.u16(3)?;
                e.u16(*record as u16)?;
            }
        }
        e.bytes(&self.local_key, MAX_KEY_LOCAL_BYTES)?;
        Ok(())
    }
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, R1StateError> {
        let mut e = Encoder::new(1024);
        self.encode(&mut e)?;
        Ok(e.finish()?)
    }
}

/// The primitive map commits exact canonical values. Owning execution/profile
/// verification remains mandatory; insertion is not authorization of an effect.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum R1StateValue {
    NativeBalance {
        #[serde(with = "decimal_u128")]
        amount_nwei: u128,
    },
    ReplayNonce {
        nonce: u64,
    },
    AccountPolicy {
        policy_epoch: u64,
        policy_commitment: Vec<u8>,
        full_policy_frame: Vec<u8>,
    },
    ValidatorBond {
        owner: String,
        beneficiary: String,
        #[serde(with = "decimal_u128")]
        amount_nwei: u128,
    },
    RestrictedBalance {
        #[serde(with = "decimal_u128")]
        amount_nwei: u128,
        policy_commitment: Vec<u8>,
    },
    ValidatorFunding {
        #[serde(with = "decimal_u128")]
        amount_nwei: u128,
    },
    ProtocolRecord {
        profile_name: String,
        profile_revision: u32,
        canonical_bytes: Vec<u8>,
    },
}
// Local persistence must preserve all U128 values even through internally
// tagged serde records. Canonical protocol encoding remains fixed-width U128.
pub(crate) mod decimal_u128 {
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(v: &u128, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&v.to_string())
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<u128, D::Error> {
        let text = String::deserialize(d)?;
        if text.is_empty()
            || text.len() > 39
            || (text.len() > 1 && text.starts_with('0'))
            || !text.bytes().all(|b| b.is_ascii_digit())
        {
            return Err(serde::de::Error::custom("noncanonical U128 decimal"));
        }
        text.parse().map_err(serde::de::Error::custom)
    }
}
impl R1StateValue {
    pub(crate) fn encode(&self, e: &mut Encoder) -> Result<(), R1StateError> {
        e.u16(1)?;
        match self {
            Self::NativeBalance { amount_nwei } => {
                e.u16(1)?;
                e.u128(*amount_nwei)?;
            }
            Self::ReplayNonce { nonce } => {
                e.u16(2)?;
                e.u64(*nonce)?;
            }
            Self::AccountPolicy {
                policy_epoch,
                policy_commitment,
                full_policy_frame,
            } => {
                let c: [u8; 64] = policy_commitment
                    .as_slice()
                    .try_into()
                    .map_err(|_| R1StateError::InvalidPolicy)?;
                if full_policy_frame.is_empty() {
                    return Err(R1StateError::InvalidPolicy);
                }
                e.u16(3)?;
                e.u64(*policy_epoch)?;
                e.fixed(&c)?;
                e.bytes(full_policy_frame, MAX_VALUE_BYTES)?;
            }
            Self::ValidatorBond {
                owner,
                beneficiary,
                amount_nwei,
            } => {
                e.u16(4)?;
                encode_account(owner, e)?;
                encode_account(beneficiary, e)?;
                e.u128(*amount_nwei)?;
            }
            Self::RestrictedBalance {
                amount_nwei,
                policy_commitment,
            } => {
                let c: [u8; 64] = policy_commitment
                    .as_slice()
                    .try_into()
                    .map_err(|_| R1StateError::InvalidPolicy)?;
                e.u16(5)?;
                e.u128(*amount_nwei)?;
                e.fixed(&c)?;
            }
            Self::ValidatorFunding { amount_nwei } => {
                e.u16(6)?;
                e.u128(*amount_nwei)?;
            }
            Self::ProtocolRecord {
                profile_name,
                profile_revision,
                canonical_bytes,
            } => {
                R1ProfileRef {
                    name: profile_name.clone(),
                    revision: *profile_revision,
                }
                .validate()
                .map_err(|_| R1StateError::InvalidProfile)?;
                e.u16(7)?;
                e.ascii(profile_name, 128)?;
                e.u32(*profile_revision)?;
                e.bytes(canonical_bytes, MAX_VALUE_BYTES)?;
            }
        }
        Ok(())
    }
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, R1StateError> {
        let mut e = Encoder::new(MAX_CANONICAL_BYTES);
        self.encode(&mut e)?;
        Ok(e.finish()?)
    }
}
fn encode_account(text: &str, e: &mut Encoder) -> Result<(), R1StateError> {
    let id = NativeIdentityPresentation::parse(text).map_err(|_| R1StateError::InvalidKey)?;
    if !matches!(
        id.namespace(),
        "synw" | "syns" | "syna" | "synm" | "synu" | "synq"
    ) {
        return Err(R1StateError::InvalidKey);
    }
    e.ascii(id.namespace(), 8)?;
    e.fixed(id.raw48())?;
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct R1StateMap {
    entries: BTreeMap<R1StateKey, R1StateValue>,
    encoded_bytes: usize,
}
impl R1StateMap {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn len(&self) -> usize {
        self.entries.len()
    }
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
    pub fn get(&self, key: &R1StateKey) -> Option<&R1StateValue> {
        self.entries.get(key)
    }
    pub fn entries(&self) -> impl Iterator<Item = (&R1StateKey, &R1StateValue)> {
        self.entries.iter()
    }
    pub fn insert(
        &mut self,
        key: R1StateKey,
        value: R1StateValue,
    ) -> Result<Option<R1StateValue>, R1StateError> {
        key.validate()?;
        let new_size = key
            .canonical_bytes()?
            .len()
            .checked_add(value.canonical_bytes()?.len())
            .ok_or(R1StateError::Overflow)?;
        let compatible = matches!(
            (&key.domain, &value),
            (
                R1StateDomain::NativeBalance,
                R1StateValue::NativeBalance { .. }
            ) | (
                R1StateDomain::ReplayCoordinate,
                R1StateValue::ReplayNonce { .. }
            ) | (
                R1StateDomain::AccountAuthorization,
                R1StateValue::AccountPolicy { .. }
            ) | (
                R1StateDomain::ValidatorBondPosition,
                R1StateValue::ValidatorBond { .. }
            ) | (
                R1StateDomain::SystemSettlement,
                R1StateValue::RestrictedBalance { .. } | R1StateValue::ValidatorFunding { .. }
            )
        ) || matches!(&value, R1StateValue::ProtocolRecord { .. })
            && !matches!(
                key.domain,
                R1StateDomain::NativeBalance
                    | R1StateDomain::ReplayCoordinate
                    | R1StateDomain::AccountAuthorization
                    | R1StateDomain::ValidatorBondPosition
            );
        if !compatible {
            return Err(R1StateError::InvalidValue);
        }
        if matches!(
            (&key.owner, &value),
            (
                R1StateOwner::Restricted { .. },
                R1StateValue::ValidatorFunding { .. }
            ) | (
                R1StateOwner::Protocol,
                R1StateValue::RestrictedBalance { .. }
            )
        ) {
            return Err(R1StateError::InvalidValue);
        }
        if self.entries.len() >= MAX_STATE_ENTRIES && !self.entries.contains_key(&key) {
            return Err(R1StateError::ResourceLimit);
        }
        let old_size = match self.entries.get(&key) {
            Some(v) => key.canonical_bytes()?.len() + v.canonical_bytes()?.len(),
            None => 0,
        };
        let next = self
            .encoded_bytes
            .checked_sub(old_size)
            .and_then(|n| n.checked_add(new_size))
            .ok_or(R1StateError::Overflow)?;
        if next > MAX_TOTAL_STATE_BYTES {
            return Err(R1StateError::ResourceLimit);
        }
        self.encoded_bytes = next;
        Ok(self.entries.insert(key, value))
    }
    pub fn remove(&mut self, key: &R1StateKey) -> Option<R1StateValue> {
        let removed = self.entries.remove(key)?;
        if let (Ok(k), Ok(v)) = (key.canonical_bytes(), removed.canonical_bytes()) {
            self.encoded_bytes = self.encoded_bytes.saturating_sub(k.len() + v.len());
        }
        Some(removed)
    }
    pub fn root(&self) -> Result<[u8; 48], R1StateError> {
        crate::r1_smt::root(self)
    }
}

pub(crate) fn hash_encoded(domain: &str, parts: &[&[u8]]) -> Result<[u8; 48], R1StateError> {
    let mut bytes = Encoder::with_domain(domain, MAX_CANONICAL_BYTES)?.finish()?;
    for part in parts {
        if bytes
            .len()
            .checked_add(part.len())
            .is_none_or(|n| n > MAX_CANONICAL_BYTES)
        {
            return Err(R1StateError::ResourceLimit);
        }
        bytes.extend_from_slice(part);
    }
    Primitives
        .hash(HashAlgorithm::Sha3384, &bytes)
        .map_err(|_| R1StateError::InvalidProfile)?
        .try_into()
        .map_err(|_| R1StateError::InvalidProfile)
}
pub fn empty_receipts_root() -> Result<[u8; 48], R1StateError> {
    let mut e = Encoder::new(4);
    e.u32(0)?;
    hash_encoded("QACE/RCT-EMPTY/02", &[&e.finish()?])
}

pub struct R1GenesisAccountPolicy {
    pub identity: String,
    pub birth_nonce32: [u8; 32],
    pub nonce: u64,
    pub policy_epoch: u64,
    pub full_policy_frame: Vec<u8>,
    pub policy_commitment: [u8; 64],
}
pub struct R1GenesisAllocation {
    pub allocation_id: String,
    pub amount_nwei: u128,
    pub destination: R1GenesisDestination,
}
pub enum R1GenesisDestination {
    Account {
        identity: String,
    },
    ValidatorBond {
        validator: String,
        owner: String,
        beneficiary: String,
    },
    UnassignedValidatorFunding,
}
pub struct R1RestrictedOpening {
    pub kind: RestrictedRecordKind,
    pub balance_nwei: u128,
    pub policy_commitment: [u8; 64],
}
pub struct R1GenesisProtocolRecord {
    pub key: R1StateKey,
    pub value: R1StateValue,
}
pub struct R1GenesisStateInput {
    pub network: R1NetworkRef,
    pub accounts: Vec<R1GenesisAccountPolicy>,
    pub allocations: Vec<R1GenesisAllocation>,
    pub restricted_records: Vec<R1RestrictedOpening>,
    pub profile_definitions: Vec<R1GenesisProtocolRecord>,
}
pub struct ComputedGenesisState {
    pub profile: R1ProfileRef,
    pub root: [u8; 48],
    pub receipts_root: [u8; 48],
    pub state: R1StateMap,
    pub total_issued_nwei: u128,
}
/// Actual allocation application to typed state, currently callable for isolated
/// fixture coordinates only. The approved native execution path will supply the
/// later ceremony capability; no flag or staged JSON activates production.
pub fn compile_genesis(input: &R1GenesisStateInput) -> Result<ComputedGenesisState, R1StateError> {
    synergy_address::r1_public::require_nonproduction_fixture(input.network.chain_id)
        .map_err(|_| R1StateError::CeremonyRequired)?;
    recompute_received_genesis_state(input)
}
/// Pure recomputation of public received Genesis allocations and birth policies.
/// This returns an untrusted in-memory calculation, never a native execution,
/// issuance, persistence or activation capability. The actual Genesis verifier
/// must independently authenticate the entire core and both root quorums.
/// Construction/ceremony callers continue through the gated compile_genesis API.
pub fn recompute_received_genesis_state(
    input: &R1GenesisStateInput,
) -> Result<ComputedGenesisState, R1StateError> {
    if input.network.chain_id == 0 {
        return Err(R1StateError::Context);
    }
    if input.accounts.len() > 65_536
        || input.allocations.len() > 65_536
        || input.profile_definitions.len() > 65_536
        || input.restricted_records.len() != 4
    {
        return Err(R1StateError::ResourceLimit);
    }
    let mut state = R1StateMap::new();
    let mut account_ids = BTreeSet::new();
    for account in &input.accounts {
        if account.nonce != 0
            || account.policy_epoch != 1
            || !account_ids.insert(account.identity.clone())
        {
            return Err(R1StateError::InvalidPolicy);
        }
        let key = R1StateKey::native(R1StateDomain::AccountAuthorization, &account.identity)?;
        let commitment = validate_account_birth_from_policy_frame(
            NetworkRef {
                chain_id: input.network.chain_id,
                nic: input.network.nic,
            },
            &account.identity,
            &account.birth_nonce32,
            &account.full_policy_frame,
            MAX_VALUE_BYTES,
        )
        .map_err(|_| R1StateError::InvalidPolicy)?;
        if commitment != account.policy_commitment {
            return Err(R1StateError::InvalidPolicy);
        }
        state.insert(
            key,
            R1StateValue::AccountPolicy {
                policy_epoch: 1,
                policy_commitment: commitment.to_vec(),
                full_policy_frame: account.full_policy_frame.clone(),
            },
        )?;
        state.insert(
            R1StateKey::native(R1StateDomain::NativeBalance, &account.identity)?,
            R1StateValue::NativeBalance { amount_nwei: 0 },
        )?;
        state.insert(
            R1StateKey::native(R1StateDomain::ReplayCoordinate, &account.identity)?,
            R1StateValue::ReplayNonce { nonce: 0 },
        )?;
    }
    let mut allocation_ids = BTreeSet::new();
    let mut total = 0u128;
    let mut funding_seen = false;
    for a in &input.allocations {
        if a.allocation_id.is_empty()
            || a.allocation_id.len() > 128
            || !a.allocation_id.bytes().all(|b| b.is_ascii_graphic())
            || !allocation_ids.insert(&a.allocation_id)
        {
            return Err(R1StateError::Duplicate);
        }
        total = total
            .checked_add(a.amount_nwei)
            .ok_or(R1StateError::Overflow)?;
        match &a.destination {
            R1GenesisDestination::Account { identity } => {
                if !account_ids.contains(identity) {
                    return Err(R1StateError::InvalidAllocation);
                }
                let key = R1StateKey::native(R1StateDomain::NativeBalance, identity)?;
                let Some(R1StateValue::NativeBalance { amount_nwei }) = state.get(&key) else {
                    return Err(R1StateError::InvalidAllocation);
                };
                let next = amount_nwei
                    .checked_add(a.amount_nwei)
                    .ok_or(R1StateError::Overflow)?;
                state.insert(key, R1StateValue::NativeBalance { amount_nwei: next })?;
            }
            R1GenesisDestination::ValidatorBond {
                validator,
                owner,
                beneficiary,
            } => {
                if !account_ids.contains(owner) || !account_ids.contains(beneficiary) {
                    return Err(R1StateError::InvalidAllocation);
                }
                let key = R1StateKey::native(R1StateDomain::ValidatorBondPosition, validator)?;
                if state.get(&key).is_some() {
                    return Err(R1StateError::Duplicate);
                }
                state.insert(
                    key,
                    R1StateValue::ValidatorBond {
                        owner: owner.clone(),
                        beneficiary: beneficiary.clone(),
                        amount_nwei: a.amount_nwei,
                    },
                )?;
            }
            R1GenesisDestination::UnassignedValidatorFunding => {
                if funding_seen {
                    return Err(R1StateError::Duplicate);
                }
                funding_seen = true;
                state.insert(
                    R1StateKey {
                        domain: R1StateDomain::SystemSettlement,
                        owner: R1StateOwner::Protocol,
                        local_key: b"unassigned-validator-funding".to_vec(),
                    },
                    R1StateValue::ValidatorFunding {
                        amount_nwei: a.amount_nwei,
                    },
                )?;
            }
        }
    }
    let mut kinds = BTreeSet::new();
    for r in &input.restricted_records {
        if !kinds.insert(r.kind) || r.balance_nwei != 0 {
            return Err(R1StateError::InvalidAllocation);
        }
        state.insert(
            R1StateKey {
                domain: R1StateDomain::SystemSettlement,
                owner: R1StateOwner::Restricted { record: r.kind },
                local_key: Vec::new(),
            },
            R1StateValue::RestrictedBalance {
                amount_nwei: 0,
                policy_commitment: r.policy_commitment.to_vec(),
            },
        )?;
    }
    for r in &input.profile_definitions {
        if !matches!(
            r.key.domain,
            R1StateDomain::ProtocolConfiguration | R1StateDomain::SrpaRegistry
        ) || !matches!(r.value, R1StateValue::ProtocolRecord { .. })
            || state.get(&r.key).is_some()
        {
            return Err(R1StateError::InvalidValue);
        }
        state.insert(r.key.clone(), r.value.clone())?;
    }
    Ok(ComputedGenesisState {
        profile: R1ProfileRef {
            name: STATE_PROFILE_NAME.into(),
            revision: STATE_PROFILE_REVISION,
        },
        root: state.root()?,
        receipts_root: empty_receipts_root()?,
        state,
        total_issued_nwei: total,
    })
}

#[cfg(test)]
mod bounds_tests {
    use super::*;
    #[test]
    fn received_public_validation_is_separate_from_actual_ceremony_construction() {
        // Invalid supplied actual-chain metadata must reach read-only semantic
        // validation without constructing any real identity/state/commitment.
        let mut input = R1GenesisStateInput {
            network: R1NetworkRef {
                chain_id: 9969,
                nic: [0; 64],
            },
            accounts: vec![],
            allocations: vec![],
            restricted_records: vec![],
            profile_definitions: vec![],
        };
        assert!(matches!(
            compile_genesis(&input),
            Err(R1StateError::CeremonyRequired)
        ));
        assert!(matches!(
            recompute_received_genesis_state(&input),
            Err(R1StateError::ResourceLimit)
        ));
        input.network.chain_id = 0;
        assert!(matches!(
            recompute_received_genesis_state(&input),
            Err(R1StateError::Context)
        ));
    }
    #[test]
    fn r1_large_policy_capacity_does_not_expand_global_state_or_create_shadow_balances() {
        let id = NativeIdentityPresentation::from_raw("syns", [9; 48])
            .unwrap()
            .to_text();
        let mut key = R1StateKey::native(R1StateDomain::NativeBalance, &id).unwrap();
        key.local_key.push(1);
        assert_eq!(key.validate(), Err(R1StateError::InvalidKey));
        let contract = NativeIdentityPresentation::from_raw("synq", [8; 48])
            .unwrap()
            .to_text();
        assert_eq!(
            R1StateKey::native(R1StateDomain::AccountAuthorization, &contract),
            Err(R1StateError::InvalidKey)
        );
        let key = R1StateKey {
            domain: R1StateDomain::ProtocolConfiguration,
            owner: R1StateOwner::Protocol,
            local_key: b"public-test-schema".to_vec(),
        };
        let mut state = R1StateMap::new();
        let value = R1StateValue::ProtocolRecord {
            profile_name: "PUBLIC-SYNTHETIC".into(),
            profile_revision: 1,
            canonical_bytes: vec![0; 90_000],
        };
        state.insert(key.clone(), value.clone()).unwrap();
        let root = state.root().unwrap();
        let excessive = R1StateValue::ProtocolRecord {
            profile_name: "PUBLIC-SYNTHETIC".into(),
            profile_revision: 1,
            canonical_bytes: vec![0; MAX_VALUE_BYTES + 1],
        };
        assert!(state.insert(key.clone(), excessive).is_err());
        assert_eq!(state.get(&key), Some(&value));
        assert_eq!(state.root().unwrap(), root);
        assert_eq!(MAX_TOTAL_STATE_BYTES, 64 * 1024 * 1024);
    }
}
