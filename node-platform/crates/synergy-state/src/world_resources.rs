//! Local allocation accounting, never a rule for World validity or finality.
//!
//! The preflight walks JSON without retaining its maps, strings or arrays. Serde's
//! escaped-string scratch is bounded and reserved before starting the walk. The
//! returned charge must remain reserved while the decoded value lives; replay
//! callers must additionally reserve their existing base, all patches, clones
//! and any other metadata. Legacy-candidate mode counts its `state` only, not
//! transaction/receipt metadata. This module does not acquire a global permit.
use std::fmt;
use std::mem::size_of;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

use serde::de::{self, DeserializeSeed, IgnoredAny, MapAccess, SeqAccess, Visitor};

use crate::{AccountState, StateDiff, StateError, WorldState};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WorldResourceFormat {
    Checkpoint,
    Delta,
    LegacyCandidate,
    CandidateResponse,
    TaggedSyncMessage,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WorldResourceEstimate {
    pub encoded_bytes: usize,
    pub scanner_scratch_bytes: usize,
    pub decoded_owned_bytes: usize,
    /// Input, scanner scratch and the prospective decoded value together.
    pub peak_decode_bytes: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WorldResourceError {
    Capacity { requested: usize, limit: usize },
    ArithmeticOverflow,
    Corrupt(String),
}
impl fmt::Display for WorldResourceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Capacity { requested, limit } => write!(
                f,
                "World resource capacity: requested={requested} limit={limit}"
            ),
            Self::ArithmeticOverflow => f.write_str("World resource arithmetic overflow"),
            Self::Corrupt(message) => write!(f, "World JSON preflight: {message}"),
        }
    }
}
impl std::error::Error for WorldResourceError {}

// A deliberately sparse bound: charge an entire maximum-capacity BTree node
// for EVERY entry (rather than amortizing occupied slots). The pinned Rust
// BTreeMap implementation has eleven slots and twelve edges. Header/alignment
// allowance exceeds its node header; separately charge owned key/value data.
fn node_bytes<V>() -> Result<usize, WorldResourceError> {
    add(
        128,
        add(
            mul(11, add(size_of::<String>(), size_of::<V>())?)?,
            mul(12, size_of::<usize>())?,
        )?,
    )
}
fn add(a: usize, b: usize) -> Result<usize, WorldResourceError> {
    a.checked_add(b)
        .ok_or(WorldResourceError::ArithmeticOverflow)
}
fn mul(a: usize, b: usize) -> Result<usize, WorldResourceError> {
    a.checked_mul(b)
        .ok_or(WorldResourceError::ArithmeticOverflow)
}
fn string_allocation(length: usize) -> Result<usize, WorldResourceError> {
    // Geometric growth plus initial allocation/allocator rounding allowance.
    add(mul(length, 2)?, 64)
}

/// Conservative charge for an already owned World, including excess capacities.
/// Shared Arc owners must charge this once per actual allocation, not per Arc.
pub fn world_owned_bytes(world: &WorldState) -> Result<usize, WorldResourceError> {
    let mut bytes = add(size_of::<WorldState>(), 128)?;
    for (key, account) in &world.accounts {
        bytes = add(
            bytes,
            add(node_bytes::<AccountState>()?, add(key.capacity(), 64)?)?,
        )?;
        if let Some(hash) = &account.code_hash {
            bytes = add(bytes, add(hash.capacity(), 64)?)?;
        }
    }
    for (key, value) in &world.protocol {
        bytes = add(
            bytes,
            add(
                node_bytes::<Vec<u8>>()?,
                add(add(key.capacity(), value.capacity())?, 128)?,
            )?,
        )?;
    }
    Ok(bytes)
}

/// Reserve encoded checkpoint/delta buffers before storage serialization.
/// Delta encoding borrows values; the sum includes removed base keys and
/// geometric Vec capacity. The guard also covers the fixed root-hash scratch.
pub fn reserve_world_write(
    world: &WorldState,
    base: Option<&WorldState>,
    budget: &Arc<WorldResourceBudget>,
) -> Result<WorldResourcePermit, WorldResourceError> {
    let mut permit = budget.reserve(8192)?;
    let world_bytes = crate::root::world_encoded_size(world)
        .map_err(|e| WorldResourceError::Corrupt(format!("measure world write: {e:?}")))?;
    let base_bytes = match base {
        Some(base) => crate::root::world_encoded_size(base)
            .map_err(|e| WorldResourceError::Corrupt(format!("measure base write: {e:?}")))?,
        None => 0,
    };
    permit.grow(add(mul(add(world_bytes, base_bytes)?, 2)?, 16 * 1024)?)?;
    Ok(permit)
}

/// One explicitly configured process-wide accounting pool. There is no default
/// limit: the runtime must share this same Arc across all World consumers.
#[derive(Debug)]
pub struct WorldResourceBudget {
    limit: usize,
    used: AtomicUsize,
    // A child pool owns already charged capacity in its parent. Outstanding
    // child permits keep this backing alive even after the worker returns.
    _backing: Option<WorldResourcePermit>,
}
impl WorldResourceBudget {
    pub fn new(limit: usize) -> Arc<Self> {
        Arc::new(Self {
            limit,
            used: AtomicUsize::new(0),
            _backing: None,
        })
    }
    pub fn limit(&self) -> usize {
        self.limit
    }
    pub fn used(&self) -> usize {
        self.used.load(Ordering::Acquire)
    }
    pub fn available(&self) -> usize {
        self.limit.saturating_sub(self.used())
    }
    /// Release a finished worker's unused prepaid capacity. Exclusive Arc
    /// ownership proves that no detached result, permit or worker can still
    /// reserve from the old limit. A busy child is retried after its last
    /// borrower drops; no allocation is transferred without its parent charge.
    pub fn try_shrink_idle_child(
        child: &mut Arc<Self>,
        retain_bytes: usize,
    ) -> Result<bool, WorldResourceError> {
        let Some(pool) = Arc::get_mut(child) else {
            return Ok(false);
        };
        if pool.used() != 0 || retain_bytes > pool.limit {
            return Err(WorldResourceError::Capacity {
                requested: retain_bytes.max(pool.used()),
                limit: pool.limit,
            });
        }
        let Some(backing) = pool._backing.as_mut() else {
            return Ok(false);
        };
        backing.resize(retain_bytes)?;
        pool.limit = retain_bytes;
        Ok(true)
    }
    fn acquire(&self, bytes: usize) -> Result<(), WorldResourceError> {
        self.acquire_with_headroom(bytes, 0)
    }
    fn acquire_with_headroom(
        &self,
        bytes: usize,
        minimum_remaining: usize,
    ) -> Result<(), WorldResourceError> {
        let mut current = self.used();
        loop {
            let requested = add(current, bytes)?;
            let required = add(requested, minimum_remaining)?;
            if required > self.limit {
                return Err(WorldResourceError::Capacity {
                    requested: required,
                    limit: self.limit,
                });
            }
            match self.used.compare_exchange_weak(
                current,
                requested,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return Ok(()),
                Err(observed) => current = observed,
            }
        }
    }
    pub fn reserve(
        self: &Arc<Self>,
        bytes: usize,
    ) -> Result<WorldResourcePermit, WorldResourceError> {
        self.acquire(bytes)?;
        Ok(WorldResourcePermit {
            budget: Arc::clone(self),
            bytes,
        })
    }
    /// Reserve optional new work without consuming the capacity required by
    /// existing owners. The free-space condition and charge share one CAS;
    /// another intake cannot slip between a separate check and reservation.
    /// Only `bytes` is charged. Existing work may reserve the protected remainder.
    pub fn reserve_with_headroom(
        self: &Arc<Self>,
        bytes: usize,
        minimum_remaining: usize,
    ) -> Result<WorldResourcePermit, WorldResourceError> {
        self.acquire_with_headroom(bytes, minimum_remaining)?;
        Ok(WorldResourcePermit {
            budget: Arc::clone(self),
            bytes,
        })
    }
}
/// A reservation cannot be copied; dropping it releases exactly its own charge.
#[derive(Debug)]
pub struct WorldResourcePermit {
    budget: Arc<WorldResourceBudget>,
    bytes: usize,
}
impl WorldResourcePermit {
    /// Hand prepaid capacity to a bounded worker without acquiring it twice.
    /// The parent remains charged until the child and all its permits drop.
    pub fn into_budget(self) -> Arc<WorldResourceBudget> {
        Arc::new(WorldResourceBudget {
            limit: self.bytes,
            used: AtomicUsize::new(0),
            _backing: Some(self),
        })
    }
    pub fn bytes(&self) -> usize {
        self.bytes
    }
    pub fn resize(&mut self, bytes: usize) -> Result<(), WorldResourceError> {
        if bytes > self.bytes {
            self.budget.acquire(bytes - self.bytes)?;
        } else {
            self.budget
                .used
                .fetch_sub(self.bytes - bytes, Ordering::AcqRel);
        }
        self.bytes = bytes;
        Ok(())
    }
    /// Grow an unaccepted allocation while preserving the same intake floor.
    /// Shrinking always releases capacity, including after durable acceptance.
    pub fn resize_with_headroom(
        &mut self,
        bytes: usize,
        minimum_remaining: usize,
    ) -> Result<(), WorldResourceError> {
        if bytes > self.bytes {
            self.budget
                .acquire_with_headroom(bytes - self.bytes, minimum_remaining)?;
            self.bytes = bytes;
            Ok(())
        } else {
            self.resize(bytes)
        }
    }
    pub fn grow(&mut self, additional: usize) -> Result<(), WorldResourceError> {
        self.resize(add(self.bytes, additional)?)
    }
    pub fn shrink(&mut self, bytes: usize) -> Result<(), WorldResourceError> {
        if bytes > self.bytes {
            return Err(WorldResourceError::Capacity {
                requested: bytes,
                limit: self.bytes,
            });
        }
        self.resize(bytes)
    }
}
impl Drop for WorldResourcePermit {
    fn drop(&mut self) {
        self.budget.used.fetch_sub(self.bytes, Ordering::AcqRel);
    }
}

/// Immutable World ownership plus its retained allocation charge. Share an
/// Arc<BudgetedWorld>; deep copies require a fresh reservation via try_clone.
/// There is deliberately no mutable access, Clone or into_unaccounted_world.
#[derive(Debug)]
pub struct BudgetedWorld {
    world: WorldState,
    permit: WorldResourcePermit,
}
impl BudgetedWorld {
    pub fn charged_bytes(&self) -> usize {
        self.permit.bytes()
    }
    /// Attach an ALREADY reserved, preflighted allocation. The caller must
    /// reserve before constructing `world`; this cannot retroactively protect
    /// an unbudgeted decode. A too-small permit is rejected without growing it.
    pub fn from_reserved(
        world: WorldState,
        mut permit: WorldResourcePermit,
    ) -> Result<Self, WorldResourceError> {
        let required = world_owned_bytes(&world)?;
        if required > permit.bytes() {
            return Err(WorldResourceError::Capacity {
                requested: required,
                limit: permit.bytes(),
            });
        }
        permit.shrink(required)?;
        Ok(Self { world, permit })
    }
    /// Clone an existing immutable World only after reserving its deep charge.
    /// The existing owner must independently account for its original allocation.
    pub fn try_clone_world(
        world: &WorldState,
        budget: &Arc<WorldResourceBudget>,
    ) -> Result<Self, WorldResourceError> {
        let permit = budget.reserve(world_owned_bytes(world)?)?;
        Ok(Self {
            world: world.clone(),
            permit,
        })
    }
    pub fn budget(&self) -> &Arc<WorldResourceBudget> {
        &self.permit.budget
    }
    /// StateDiff already stages and validates the whole write set before its
    /// first mutation. Reserve that staging, validation trees and prospective
    /// World entries first; failure restores the original reservation and World.
    pub fn try_apply(&mut self, diff: &StateDiff) -> Result<(), StateError> {
        let original = self.permit.bytes();
        let extra = diff_resource_bytes(&self.world, diff).map_err(resource_state_error)?;
        self.permit.grow(extra).map_err(resource_state_error)?;
        if let Err(error) = diff.apply(&mut self.world) {
            self.permit
                .shrink(original)
                .expect("rollback only releases reservation");
            return Err(error);
        }
        let actual =
            world_owned_bytes(&self.world).expect("preflight checked write-set arithmetic");
        self.permit
            .shrink(actual)
            .expect("write-set reservation covers resulting World");
        Ok(())
    }

    /// Transaction-level action/fee atomicity without copying unrelated World
    /// entries. Reserve all touched originals and sequential staging first.
    pub fn try_apply_ordered_atomic(&mut self, diffs: &[&StateDiff]) -> Result<(), StateError> {
        let original = self.permit.bytes();
        let mut extra = add(size_of::<WorldState>(), 512).map_err(resource_state_error)?;
        for diff in diffs {
            extra = add(
                extra,
                mul(
                    diff_resource_bytes(&self.world, diff).map_err(resource_state_error)?,
                    4,
                )
                .map_err(resource_state_error)?,
            )
            .map_err(resource_state_error)?;
            for change in &diff.changes {
                if let Some(Some(hash)) = &change.code_hash {
                    extra = add(
                        extra,
                        mul(
                            string_allocation(hash.len()).map_err(resource_state_error)?,
                            4,
                        )
                        .map_err(resource_state_error)?,
                    )
                    .map_err(resource_state_error)?;
                }
            }
            for change in &diff.protocol_changes {
                if let Some(value) = self.world.protocol.get(&change.key) {
                    extra = add(
                        extra,
                        add(
                            mul(node_bytes::<Vec<u8>>().map_err(resource_state_error)?, 2)
                                .map_err(resource_state_error)?,
                            mul(value.capacity(), 4).map_err(resource_state_error)?,
                        )
                        .map_err(resource_state_error)?,
                    )
                    .map_err(resource_state_error)?;
                }
            }
        }
        self.permit.grow(extra).map_err(resource_state_error)?;
        if let Err(error) = StateDiff::apply_ordered_atomic(diffs, &mut self.world) {
            self.permit
                .shrink(original)
                .expect("atomic rollback releases scratch");
            return Err(error);
        }
        let actual =
            world_owned_bytes(&self.world).expect("ordered staging preflight checked arithmetic");
        self.permit
            .shrink(actual)
            .expect("ordered staging covers resulting World");
        Ok(())
    }

    pub fn try_clone(&self) -> Result<Self, WorldResourceError> {
        let permit = self
            .permit
            .budget
            .reserve(world_owned_bytes(&self.world)?)?;
        Ok(Self {
            world: self.world.clone(),
            permit,
        })
    }
}
impl PartialEq for BudgetedWorld {
    fn eq(&self, other: &Self) -> bool {
        self.world == other.world
    }
}
impl Eq for BudgetedWorld {}
impl AsRef<WorldState> for WorldState {
    fn as_ref(&self) -> &WorldState {
        self
    }
}

impl serde::Serialize for BudgetedWorld {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serde::Serialize::serialize(&self.world, serializer)
    }
}
/// Preserve capacity as a local resource error, never as corrupt signed state.
pub fn resource_state_error(error: WorldResourceError) -> StateError {
    match error {
        WorldResourceError::Capacity { requested, limit } => {
            StateError::ResourcePressure { requested, limit }
        }
        WorldResourceError::ArithmeticOverflow => StateError::ResourcePressure {
            requested: usize::MAX,
            limit: usize::MAX - 1,
        },
        WorldResourceError::Corrupt(message) => StateError::Corrupt(message),
    }
}
fn diff_resource_bytes(world: &WorldState, diff: &StateDiff) -> Result<usize, WorldResourceError> {
    let mut bytes = add(
        mul(diff.changes.len(), size_of::<(String, AccountState)>())?,
        128,
    )?;
    for change in &diff.changes {
        // Validation BTree, new World node, staged key and account, transient
        // replacement hash, and a cloned error key are all covered separately.
        bytes = add(bytes, mul(node_bytes::<AccountState>()?, 3)?)?;
        bytes = add(bytes, mul(string_allocation(change.account.len())?, 2)?)?;
        if let Some(hash) = world
            .accounts
            .get(&change.account)
            .and_then(|a| a.code_hash.as_ref())
        {
            bytes = add(bytes, mul(string_allocation(hash.len())?, 2)?)?;
        }
        if let Some(Some(hash)) = &change.code_hash {
            bytes = add(bytes, mul(string_allocation(hash.len())?, 2)?)?;
        }
    }
    for change in &diff.protocol_changes {
        bytes = add(bytes, mul(node_bytes::<Vec<u8>>()?, 3)?)?;
        bytes = add(bytes, mul(string_allocation(change.key.len())?, 2)?)?;
        if let Some(value) = &change.value {
            bytes = add(bytes, add(mul(value.len(), 2)?, 64)?)?;
        }
    }
    Ok(bytes)
}

impl AsRef<WorldState> for BudgetedWorld {
    fn as_ref(&self) -> &WorldState {
        &self.world
    }
}
impl std::ops::Deref for BudgetedWorld {
    type Target = WorldState;
    fn deref(&self) -> &Self::Target {
        &self.world
    }
}

/// Reserve scanner scratch BEFORE scanning, then complete decode peak BEFORE
/// native serde allocation. On success release scratch and retain only the World
/// charge. Caller-owned input is included during this operation; after return its
/// continuing lifetime remains the caller's responsibility. Root/authority checks
/// remain mandatory; this helper does not confer authentication or finality.
pub fn decode_budgeted_world(
    bytes: &[u8],
    budget: &Arc<WorldResourceBudget>,
) -> Result<BudgetedWorld, WorldResourceError> {
    decode_with(bytes, budget, |bytes| {
        serde_json::from_slice(bytes).map_err(|e| WorldResourceError::Corrupt(e.to_string()))
    })
}
fn decode_with(
    bytes: &[u8],
    budget: &Arc<WorldResourceBudget>,
    decode: impl FnOnce(&[u8]) -> Result<WorldState, WorldResourceError>,
) -> Result<BudgetedWorld, WorldResourceError> {
    let scanner = add(
        add(bytes.len(), add(mul(bytes.len(), 2)?, 256)?)?,
        add(size_of::<WorldState>(), 128)?,
    )?;
    let mut permit = budget.reserve(scanner)?;
    let estimate = preflight_world_json(bytes, WorldResourceFormat::Checkpoint, budget.limit())?;
    permit.resize(estimate.peak_decode_bytes)?;
    let world = decode(bytes)?;
    permit.shrink(estimate.decoded_owned_bytes)?;
    Ok(BudgetedWorld { world, permit })
}

struct Budget {
    encoded: usize,
    scratch: usize,
    owned: usize,
    limit: usize,
    failure: Option<WorldResourceError>,
}
impl Budget {
    fn charge<E: de::Error>(&mut self, amount: Result<usize, WorldResourceError>) -> Result<(), E> {
        let result = amount.and_then(|amount| {
            self.owned = add(self.owned, amount)?;
            let requested = add(add(self.encoded, self.scratch)?, self.owned)?;
            if requested > self.limit {
                Err(WorldResourceError::Capacity {
                    requested,
                    limit: self.limit,
                })
            } else {
                Ok(())
            }
        });
        result.map_err(|error| {
            self.failure = Some(error);
            E::custom("World resource preflight exhausted")
        })
    }
}

/// Inspect before constructing a World or delta. A capacity result is local
/// backpressure, not evidence that signed state is invalid. Actual native decode
/// and all root/authority verification must still run after this succeeds.
pub fn preflight_world_json(
    bytes: &[u8],
    format: WorldResourceFormat,
    maximum_bytes: usize,
) -> Result<WorldResourceEstimate, WorldResourceError> {
    // serde_json uses one reusable scratch Vec for escaped tokens; allow twice
    // the entire input plus a rounding allowance before it can allocate it.
    let scratch = add(mul(bytes.len(), 2)?, 256)?;
    let mut budget = Budget {
        encoded: bytes.len(),
        scratch,
        owned: 0,
        limit: maximum_bytes,
        failure: None,
    };
    budget
        .charge::<serde_json::Error>(Ok(add(size_of::<WorldState>(), 128)?))
        .map_err(|_| budget.failure.clone().expect("charge records failure"))?;
    let kind = match format {
        WorldResourceFormat::Checkpoint => Kind::World,
        WorldResourceFormat::Delta => Kind::Delta,
        WorldResourceFormat::LegacyCandidate => Kind::Legacy,
        WorldResourceFormat::CandidateResponse => Kind::Response,
        WorldResourceFormat::TaggedSyncMessage => Kind::Tagged,
    };
    let mut decoder = serde_json::Deserializer::from_slice(bytes);
    let result = Seed {
        budget: &mut budget,
        kind,
    }
    .deserialize(&mut decoder)
    .and_then(|()| decoder.end());
    if let Err(error) = result {
        return Err(budget
            .failure
            .unwrap_or_else(|| WorldResourceError::Corrupt(error.to_string())));
    }
    Ok(WorldResourceEstimate {
        encoded_bytes: bytes.len(),
        scanner_scratch_bytes: scratch,
        decoded_owned_bytes: budget.owned,
        peak_decode_bytes: add(add(bytes.len(), scratch)?, budget.owned)?,
    })
}

#[derive(Clone, Copy)]
enum Kind {
    World,
    Delta,
    Legacy,
    Response,
    Tagged,
    Accounts(bool),
    Account,
    Protocol(bool),
    Bytes,
    OptionalBytes,
    OptionalAccount,
    OptionalString,
    String,
}
struct Seed<'a> {
    budget: &'a mut Budget,
    kind: Kind,
}
impl<'de> DeserializeSeed<'de> for Seed<'_> {
    type Value = ();
    fn deserialize<D: de::Deserializer<'de>>(self, deserializer: D) -> Result<(), D::Error> {
        match self.kind {
            Kind::Bytes => deserializer.deserialize_seq(self),
            Kind::String => {
                let length = StringLength.deserialize(deserializer)?;
                self.budget.charge(string_allocation(length))
            }
            Kind::OptionalBytes | Kind::OptionalAccount | Kind::OptionalString => {
                deserializer.deserialize_option(self)
            }
            _ => deserializer.deserialize_map(self),
        }
    }
}
impl<'de> Visitor<'de> for Seed<'_> {
    type Value = ();
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("World resource structure")
    }
    fn visit_none<E: de::Error>(self) -> Result<(), E> {
        Ok(())
    }
    fn visit_unit<E: de::Error>(self) -> Result<(), E> {
        Ok(())
    }
    fn visit_some<D: de::Deserializer<'de>>(self, deserializer: D) -> Result<(), D::Error> {
        match self.kind {
            Kind::OptionalString => {
                let length = StringLength.deserialize(deserializer)?;
                self.budget.charge(string_allocation(length))
            }
            Kind::OptionalBytes => Seed {
                budget: self.budget,
                kind: Kind::Bytes,
            }
            .deserialize(deserializer),
            Kind::OptionalAccount => Seed {
                budget: self.budget,
                kind: Kind::Account,
            }
            .deserialize(deserializer),
            _ => Err(de::Error::custom(
                "invalid optional World resource structure",
            )),
        }
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<(), A::Error> {
        self.budget.charge(Ok(64))?;
        while sequence.next_element::<IgnoredAny>()?.is_some() {
            self.budget.charge(Ok(2))?;
        }
        Ok(())
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<(), A::Error> {
        match self.kind {
            Kind::Accounts(optional) => {
                while let Some(length) = map.next_key_seed(StringLength)? {
                    let node = if optional {
                        node_bytes::<Option<AccountState>>()
                    } else {
                        node_bytes::<AccountState>()
                    };
                    self.budget
                        .charge(node.and_then(|node| add(node, string_allocation(length)?)))?;
                    map.next_value_seed(Seed {
                        budget: self.budget,
                        kind: if optional {
                            Kind::OptionalAccount
                        } else {
                            Kind::Account
                        },
                    })?;
                }
            }
            Kind::Protocol(optional) => {
                while let Some(length) = map.next_key_seed(StringLength)? {
                    let node = if optional {
                        node_bytes::<Option<Vec<u8>>>()
                    } else {
                        node_bytes::<Vec<u8>>()
                    };
                    self.budget
                        .charge(node.and_then(|node| add(node, string_allocation(length)?)))?;
                    map.next_value_seed(Seed {
                        budget: self.budget,
                        kind: if optional {
                            Kind::OptionalBytes
                        } else {
                            Kind::Bytes
                        },
                    })?;
                }
            }
            kind => {
                while let Some(field) = map.next_key_seed(FieldSeed)? {
                    let nested = match (kind, field) {
                        (Kind::World, Field::Accounts) => Some(Kind::Accounts(false)),
                        (Kind::World, Field::Protocol) => Some(Kind::Protocol(false)),
                        (Kind::Delta, Field::Accounts) => Some(Kind::Accounts(true)),
                        (Kind::Delta, Field::Protocol) => Some(Kind::Protocol(true)),
                        (Kind::Legacy, Field::State) => Some(Kind::World),
                        (Kind::Response, Field::Candidate) => Some(Kind::Legacy),
                        (Kind::Tagged, Field::Body) => Some(Kind::Response),
                        (Kind::Delta, Field::Root) => Some(Kind::String),
                        (Kind::Account, Field::CodeHash) => Some(Kind::OptionalString),
                        _ => None,
                    };
                    if let Some(kind) = nested {
                        map.next_value_seed(Seed {
                            budget: self.budget,
                            kind,
                        })?;
                    } else {
                        map.next_value::<IgnoredAny>()?;
                    }
                }
            }
        }
        Ok(())
    }
}
struct StringLength;
impl<'de> DeserializeSeed<'de> for StringLength {
    type Value = usize;
    fn deserialize<D: de::Deserializer<'de>>(self, deserializer: D) -> Result<usize, D::Error> {
        deserializer.deserialize_str(self)
    }
}
impl Visitor<'_> for StringLength {
    type Value = usize;
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("string")
    }
    fn visit_str<E: de::Error>(self, value: &str) -> Result<usize, E> {
        Ok(value.len())
    }
}
enum Field {
    Accounts,
    Protocol,
    State,
    CodeHash,
    Candidate,
    Body,
    Kind,
    Request,
    Witness,
    ProcessingReplay,
    Root,
    Other,
}
struct FieldSeed;
impl<'de> DeserializeSeed<'de> for FieldSeed {
    type Value = Field;
    fn deserialize<D: de::Deserializer<'de>>(self, deserializer: D) -> Result<Field, D::Error> {
        deserializer.deserialize_str(self)
    }
}
impl Visitor<'_> for FieldSeed {
    type Value = Field;
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("field name")
    }
    fn visit_str<E: de::Error>(self, value: &str) -> Result<Field, E> {
        Ok(match value {
            "accounts" => Field::Accounts,
            "protocol" => Field::Protocol,
            "state" => Field::State,
            "code_hash" => Field::CodeHash,
            "candidate" => Field::Candidate,
            "body" => Field::Body,
            "kind" => Field::Kind,
            "request" => Field::Request,
            "finality_witness" => Field::Witness,
            "processing_replay" => Field::ProcessingReplay,
            "state_root" | "parent_state_root" => Field::Root,
            _ => Field::Other,
        })
    }
}

/// Recognized envelope fields for a borrowed, exact-byte JSON range. No
/// reserialization, Value tree, or decoded World is involved.
#[derive(Clone, Copy)]
pub enum JsonObjectField {
    Candidate,
    Body,
    Kind,
    Request,
    FinalityWitness,
    ProcessingReplay,
    State,
}
impl JsonObjectField {
    fn matches(self, field: Field) -> bool {
        matches!(
            (self, field),
            (Self::Candidate, Field::Candidate)
                | (Self::Body, Field::Body)
                | (Self::Kind, Field::Kind)
                | (Self::Request, Field::Request)
                | (Self::FinalityWitness, Field::Witness)
                | (Self::ProcessingReplay, Field::ProcessingReplay)
                | (Self::State, Field::State)
        )
    }
}
struct FieldToken(Field);
impl<'de> serde::Deserialize<'de> for FieldToken {
    fn deserialize<D: de::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        FieldSeed.deserialize(d).map(Self)
    }
}
fn skip_space(bytes: &[u8], mut offset: usize) -> usize {
    while offset < bytes.len() && matches!(bytes[offset], b' ' | b'\n' | b'\r' | b'\t') {
        offset += 1;
    }
    offset
}
/// The entire scanner input/escape scratch is reserved before its first parse.
/// The borrowed result outlives no allocation; the caller retains the input and
/// still must perform native envelope decode/unknown-field/authority checks.
pub fn borrow_json_object_field<'a>(
    bytes: &'a [u8],
    field: JsonObjectField,
    budget: &Arc<WorldResourceBudget>,
) -> Result<Option<&'a [u8]>, WorldResourceError> {
    let _scan = budget.reserve(add(mul(bytes.len(), 3)?, 256)?)?;
    let fail = || WorldResourceError::Corrupt("expected JSON object field boundary".into());
    let mut position = skip_space(bytes, 0);
    if bytes.get(position) != Some(&b'{') {
        return Err(fail());
    }
    position = skip_space(bytes, position + 1);
    let mut found = None;
    if bytes.get(position) == Some(&b'}') {
        return if skip_space(bytes, position + 1) == bytes.len() {
            Ok(None)
        } else {
            Err(fail())
        };
    }
    loop {
        let (key, consumed) = {
            let mut stream =
                serde_json::Deserializer::from_slice(&bytes[position..]).into_iter::<FieldToken>();
            let key = stream
                .next()
                .ok_or_else(fail)?
                .map_err(|e| WorldResourceError::Corrupt(e.to_string()))?;
            (key.0, stream.byte_offset())
        };
        position = skip_space(bytes, position + consumed);
        if bytes.get(position) != Some(&b':') {
            return Err(fail());
        }
        position = skip_space(bytes, position + 1);
        let start = position;
        let consumed = {
            let mut stream =
                serde_json::Deserializer::from_slice(&bytes[position..]).into_iter::<IgnoredAny>();
            stream
                .next()
                .ok_or_else(fail)?
                .map_err(|e| WorldResourceError::Corrupt(e.to_string()))?;
            stream.byte_offset()
        };
        position += consumed;
        if field.matches(key) {
            if found.is_some() {
                return Err(WorldResourceError::Corrupt(
                    "duplicate selected JSON field".into(),
                ));
            }
            found = Some(&bytes[start..position]);
        }
        position = skip_space(bytes, position);
        match bytes.get(position) {
            Some(b',') => position = skip_space(bytes, position + 1),
            Some(b'}') => {
                return if skip_space(bytes, position + 1) == bytes.len() {
                    Ok(found)
                } else {
                    Err(fail())
                }
            }
            _ => return Err(fail()),
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn intake_headroom_is_atomic_and_does_not_charge_reserved_control_capacity() {
        use std::sync::{Arc, Barrier};
        let budget = super::WorldResourceBudget::new(100);
        let start = Arc::new(Barrier::new(3));
        let mut joins = Vec::new();
        for _ in 0..2 {
            let budget = Arc::clone(&budget);
            let start = Arc::clone(&start);
            joins.push(std::thread::spawn(move || {
                start.wait();
                budget.reserve_with_headroom(60, 20)
            }));
        }
        start.wait();
        let reservations = joins
            .into_iter()
            .map(|join| join.join().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(
            reservations.iter().filter(|result| result.is_ok()).count(),
            1
        );
        assert_eq!(budget.used(), 60);
        // Progress owners consume the remaining capacity without the intake floor.
        let progress = budget.reserve(40).unwrap();
        assert_eq!(budget.used(), 100);
        drop(progress);
        drop(reservations);
        assert_eq!(budget.used(), 0);
        let exact = budget.reserve_with_headroom(80, 20).unwrap();
        assert_eq!(budget.used(), 80);
        assert!(budget.reserve_with_headroom(1, 20).is_err());
        let control = budget.reserve(20).unwrap();
        assert_eq!(budget.used(), 100);
        drop(control);
        drop(exact);
        assert_eq!(budget.used(), 0);
    }
    #[test]
    fn intake_headroom_rejection_and_growth_roll_back_exactly() {
        let budget = super::WorldResourceBudget::new(100);
        let mut intake = budget.reserve_with_headroom(50, 20).unwrap();
        assert!(intake.resize_with_headroom(81, 20).is_err());
        assert_eq!(intake.bytes(), 50);
        assert_eq!(budget.used(), 50);
        intake.resize_with_headroom(80, 20).unwrap();
        assert_eq!(budget.used(), 80);
        intake.resize_with_headroom(10, usize::MAX).unwrap();
        assert_eq!(budget.used(), 10);
        assert!(matches!(
            budget.reserve_with_headroom(usize::MAX, 1),
            Err(super::WorldResourceError::ArithmeticOverflow)
        ));
        assert!(matches!(
            budget.reserve_with_headroom(0, usize::MAX),
            Err(super::WorldResourceError::ArithmeticOverflow)
        ));
        assert_eq!(budget.used(), 10);
        drop(intake);
        assert_eq!(budget.used(), 0);
    }
    #[test]
    fn completed_child_releases_scratch_only_after_last_detached_owner_drops() {
        let parent = super::WorldResourceBudget::new(100);
        let mut child = parent.reserve(80).unwrap().into_budget();
        let pressure = parent.reserve(20).unwrap();
        let detached = child.reserve(1).unwrap();
        assert!(!super::WorldResourceBudget::try_shrink_idle_child(&mut child, 8).unwrap());
        assert_eq!(parent.used(), 100);
        drop(detached);
        assert!(super::WorldResourceBudget::try_shrink_idle_child(&mut child, 8).unwrap());
        assert_eq!(parent.used(), 28);
        assert_eq!(child.limit(), 8);
        assert!(child.reserve(9).is_err());
        let retained = child.reserve(8).unwrap();
        assert_eq!(parent.used(), 28);
        drop(retained);
        drop(child);
        drop(pressure);
        assert_eq!(parent.used(), 0);
    }
    #[test]
    fn prepaid_worker_pool_keeps_parent_charge_until_last_worker_drops() {
        let parent = super::WorldResourceBudget::new(100);
        let worker = parent.reserve(80).unwrap().into_budget();
        let pressure = parent.reserve(20).unwrap();
        let retained = worker.reserve(65).unwrap();
        assert!(worker.reserve(16).is_err());
        assert_eq!(parent.used(), 100);
        drop(worker);
        assert_eq!(parent.used(), 100);
        drop(retained);
        assert_eq!(parent.used(), 20);
        drop(pressure);
        assert_eq!(parent.used(), 0);
    }
    use super::*;

    #[test]
    fn world_resources_exact_borrowed_nested_ranges_and_budget() {
        let bytes=br#" {"body":{"request":{},"candi\u0064ate":{"state":{"protocol":{"x":[1,2]},"accounts":{}}}},"kind":"finalized_candidate_response"} "#;
        let budget = WorldResourceBudget::new(1024 * 1024);
        let body = borrow_json_object_field(bytes, JsonObjectField::Body, &budget)
            .unwrap()
            .unwrap();
        let candidate = borrow_json_object_field(body, JsonObjectField::Candidate, &budget)
            .unwrap()
            .unwrap();
        assert_eq!(
            candidate,
            br#"{"state":{"protocol":{"x":[1,2]},"accounts":{}}}"#
        );
        let direct =
            preflight_world_json(candidate, WorldResourceFormat::LegacyCandidate, usize::MAX)
                .unwrap();
        for (input, format) in [
            (body, WorldResourceFormat::CandidateResponse),
            (bytes.as_slice(), WorldResourceFormat::TaggedSyncMessage),
        ] {
            assert_eq!(
                preflight_world_json(input, format, usize::MAX)
                    .unwrap()
                    .decoded_owned_bytes,
                direct.decoded_owned_bytes
            );
        }
        for bad in [
            br#"{"body":{},"body":{}}"#.as_slice(),
            br#"{"body":{}} trailing"#,
            br#"{"body":{},}"#,
        ] {
            assert!(borrow_json_object_field(bad, JsonObjectField::Body, &budget).is_err());
            assert_eq!(budget.used(), 0);
        }
        let tiny = WorldResourceBudget::new(1);
        assert!(matches!(
            borrow_json_object_field(b"malformed", JsonObjectField::Body, &tiny),
            Err(WorldResourceError::Capacity { .. })
        ));
        assert_eq!(tiny.used(), 0);
    }
    fn estimate(bytes: &[u8], format: WorldResourceFormat) -> WorldResourceEstimate {
        preflight_world_json(bytes, format, usize::MAX).unwrap()
    }
    #[test]
    fn world_resources_shared_budget_reserve_rollback_and_drop() {
        let budget = WorldResourceBudget::new(100);
        let mut permit = budget.reserve(60).unwrap();
        assert!(permit.grow(41).is_err());
        assert_eq!(permit.bytes(), 60);
        assert_eq!(budget.used(), 60);
        permit.grow(40).unwrap();
        assert_eq!(budget.used(), 100);
        assert!(budget.reserve(1).is_err());
        permit.shrink(20).unwrap();
        assert_eq!(budget.available(), 80);
        assert!(permit.shrink(21).is_err());
        assert_eq!(budget.used(), 20);
        drop(permit);
        assert_eq!(budget.used(), 0);
        let barrier = Arc::new(std::sync::Barrier::new(3));
        let handles = (0..2)
            .map(|_| {
                let budget = Arc::clone(&budget);
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    let reservation = budget.reserve(60);
                    barrier.wait();
                    barrier.wait();
                    reservation.is_ok()
                })
            })
            .collect::<Vec<_>>();
        barrier.wait();
        assert_eq!(budget.used(), 60);
        barrier.wait();
        assert_eq!(
            handles
                .into_iter()
                .map(|h| h.join().unwrap())
                .filter(|ok| *ok)
                .count(),
            1
        );
        assert_eq!(budget.used(), 0);
    }
    #[test]
    fn world_resources_decode_permit_lifetime_clone_and_failure() {
        let bytes = br#"{"accounts":{"a":{"balance_nwei":0,"nonce":0}},"protocol":{"v":[0,255]}}"#;
        let estimate = estimate(bytes, WorldResourceFormat::Checkpoint);
        let budget = WorldResourceBudget::new(estimate.peak_decode_bytes * 3);
        let world = Arc::new(decode_budgeted_world(bytes, &budget).unwrap());
        assert_eq!(budget.used(), world.charged_bytes());
        let alias = Arc::clone(&world);
        drop(world);
        let copy = alias.try_clone().unwrap();
        assert_eq!(copy.as_ref(), alias.as_ref().as_ref());
        assert_eq!(budget.used(), alias.charged_bytes() + copy.charged_bytes());
        drop(copy);
        drop(alias);
        assert_eq!(budget.used(), 0);
        let owned: WorldState = serde_json::from_slice(bytes).unwrap();
        let required = world_owned_bytes(&owned).unwrap();
        let rejected = BudgetedWorld::from_reserved(owned, budget.reserve(required - 1).unwrap());
        assert!(matches!(rejected, Err(WorldResourceError::Capacity { .. })));
        assert_eq!(budget.used(), 0);
        let attached = BudgetedWorld::from_reserved(
            serde_json::from_slice(bytes).unwrap(),
            budget.reserve(required + 100).unwrap(),
        )
        .unwrap();
        assert_eq!(budget.used(), required);
        drop(attached);
        assert_eq!(budget.used(), 0);
        let called = std::cell::Cell::new(false);
        let small = WorldResourceBudget::new(estimate.peak_decode_bytes - 1);
        assert!(matches!(
            decode_with(bytes, &small, |_| {
                called.set(true);
                Ok(WorldState::default())
            }),
            Err(WorldResourceError::Capacity { .. })
        ));
        assert!(!called.get());
        assert_eq!(small.used(), 0);
        let failed = decode_with(bytes, &budget, |_| {
            Err(WorldResourceError::Corrupt("test".into()))
        });
        assert!(matches!(failed, Err(WorldResourceError::Corrupt(_))));
        assert_eq!(budget.used(), 0);
    }
    #[test]
    fn world_resources_apply_reserves_before_mutation_and_releases_on_failure() {
        let bytes = br#"{"accounts":{"a":{"balance_nwei":10,"nonce":0}},"protocol":{"old":[1]}}"#;
        let budget = WorldResourceBudget::new(1024 * 1024);
        let mut world = decode_budgeted_world(bytes, &budget).unwrap();
        let original = serde_json::to_vec(&world).unwrap();
        let retained = budget.used();
        let diff = StateDiff {
            changes: vec![crate::AccountChange {
                account: "a".into(),
                debit_nwei: 3,
                credit_nwei: 0,
                expected_nonce: Some(0),
                code_hash: None,
            }],
            protocol_changes: vec![crate::ProtocolChange {
                key: "new".into(),
                expected_value: None,
                value: Some(vec![2; 1024]),
            }],
        };
        let obstruction = budget.reserve(budget.available()).unwrap();
        assert!(matches!(
            world.try_apply(&diff),
            Err(StateError::ResourcePressure { .. })
        ));
        assert_eq!(serde_json::to_vec(&world).unwrap(), original);
        drop(obstruction);
        assert_eq!(budget.used(), retained);
        let mut late = diff.clone();
        late.protocol_changes[0].expected_value = Some(vec![9]);
        assert!(matches!(
            world.try_apply(&late),
            Err(StateError::ProtocolValueMismatch(_))
        ));
        assert_eq!(serde_json::to_vec(&world).unwrap(), original);
        assert_eq!(budget.used(), retained);
        world.try_apply(&diff).unwrap();
        assert_eq!(world.accounts["a"].balance_nwei, 7);
        assert_eq!(world.accounts["a"].nonce, 1);
        assert_eq!(world.protocol["new"], vec![2; 1024]);
        assert_eq!(budget.used(), world_owned_bytes(world.as_ref()).unwrap());
        assert_eq!(
            serde_json::to_vec(&world).unwrap(),
            serde_json::to_vec(world.as_ref()).unwrap()
        );
        drop(world);
        assert_eq!(budget.used(), 0);
    }
    #[test]
    fn write_reservation_preserves_exact_sizes_without_recomputing_roots() {
        let mut world = WorldState::default();
        world.accounts.insert(
            "escaped\"\nα".into(),
            AccountState {
                balance_nwei: u128::MAX,
                nonce: u64::MAX,
                code_hash: Some("\u{0}\t\"".into()),
            },
        );
        world.protocol.insert(
            "payload".into(),
            (0..=255).cycle().take(32 * 1024).collect(),
        );
        let mut base = world.clone();
        base.protocol.insert("deleted".into(), vec![255; 1024]);
        let world_bytes = serde_json::to_vec(&world).unwrap().len();
        let base_bytes = serde_json::to_vec(&base).unwrap().len();
        assert_eq!(
            crate::root::world_encoded_size(&world).unwrap(),
            world_bytes
        );
        assert_eq!(crate::root::world_encoded_size(&base).unwrap(), base_bytes);
        let required = 8192 + 2 * (world_bytes + base_bytes) + 16 * 1024;
        let budget = WorldResourceBudget::new(required);
        let permit = reserve_world_write(&world, Some(&base), &budget).unwrap();
        assert_eq!(budget.used(), required);
        drop(permit);
        assert_eq!(budget.used(), 0);
        let small = WorldResourceBudget::new(required - 1);
        assert!(matches!(
            reserve_world_write(&world, Some(&base), &small),
            Err(WorldResourceError::Capacity { .. })
        ));
        assert_eq!(small.used(), 0);
    }

    #[test]
    #[ignore = "explicit CPU/resource measurement; run in isolation with --nocapture"]
    fn measure_world_write_reservation_amplification() {
        let mut world = WorldState::default();
        world
            .protocol
            .insert("unchanged-payload".into(), vec![255; 256 * 1024]);
        for index in 0..1024 {
            world.accounts.insert(
                format!("account-{index:08}"),
                AccountState {
                    balance_nwei: index,
                    nonce: index as u64,
                    code_hash: None,
                },
            );
        }
        let mut base = world.clone();
        base.protocol.insert("deleted".into(), vec![7; 4096]);
        let budget = WorldResourceBudget::new(64 * 1024 * 1024);
        let rounds = 16;
        let started = std::time::Instant::now();
        let mut previous_bytes = 0;
        for _ in 0..rounds {
            let (_, w) = crate::state_root_with_size(std::hint::black_box(&world)).unwrap();
            let (_, b) = crate::state_root_with_size(std::hint::black_box(&base)).unwrap();
            previous_bytes = 8192 + 2 * (w + b) + 16 * 1024;
            let permit = budget.reserve(previous_bytes).unwrap();
            std::hint::black_box(&permit);
        }
        let previous_micros = started.elapsed().as_micros();
        let started = std::time::Instant::now();
        for _ in 0..rounds {
            let permit =
                reserve_world_write(std::hint::black_box(&world), Some(&base), &budget).unwrap();
            assert_eq!(budget.used(), previous_bytes);
            std::hint::black_box(&permit);
        }
        eprintln!("EINSTEIN_WRITE_MEASUREMENT {{\"rounds\":{rounds},\"previous_micros\":{previous_micros},\"corrected_micros\":{},\"same_reserved_bytes\":{previous_bytes},\"live_after_drop\":{}}}", started.elapsed().as_micros(), budget.used());
        assert_eq!(budget.used(), 0);
    }

    #[test]
    fn world_resources_exact_budget_and_owned_capacity() {
        let bytes = br#"{"accounts":{"wallet":{"balance_nwei":0,"nonce":0,"code_hash":"hash"}},"protocol":{"value":[0,255]}}"#;
        let charge = estimate(bytes, WorldResourceFormat::Checkpoint);
        assert_eq!(
            preflight_world_json(
                bytes,
                WorldResourceFormat::Checkpoint,
                charge.peak_decode_bytes
            )
            .unwrap(),
            charge
        );
        assert!(matches!(
            preflight_world_json(
                bytes,
                WorldResourceFormat::Checkpoint,
                charge.peak_decode_bytes - 1
            ),
            Err(WorldResourceError::Capacity { .. })
        ));
        let mut world: WorldState = serde_json::from_slice(bytes).unwrap();
        assert!(world_owned_bytes(&world).unwrap() <= charge.decoded_owned_bytes);
        world.protocol.get_mut("value").unwrap().reserve(100_000);
        assert!(world_owned_bytes(&world).unwrap() > charge.decoded_owned_bytes);
    }
    #[test]
    fn world_resources_many_entries_cost_more_than_blob() {
        let dense = serde_json::json!({"accounts":{},"protocol":(0..100).map(|i|(i.to_string(),Vec::<u8>::new())).collect::<std::collections::BTreeMap<_,_>>()});
        let blob = serde_json::json!({"accounts":{},"protocol":{"blob":vec![0u8;1000]}});
        let dense = serde_json::to_vec(&dense).unwrap();
        let blob = serde_json::to_vec(&blob).unwrap();
        assert!(dense.len() < blob.len());
        assert!(
            estimate(&dense, WorldResourceFormat::Checkpoint).decoded_owned_bytes
                > estimate(&blob, WorldResourceFormat::Checkpoint).decoded_owned_bytes
        );
    }
    #[test]
    fn world_resources_delta_legacy_escapes_and_corruption() {
        let checkpoint = br#"{"accounts":{"\u0061":{"balance_nwei":0,"nonce":0,"code_hash":"a\"b"}},"protocol":{"x":[0,255]}}"#;
        let delta = br#"{"height":2,"parent_height":1,"state_root":"r","parent_state_root":"p","accounts":{"a":null,"b":{"balance_nwei":0,"nonce":0,"code_hash":null}},"protocol":{"x":null,"y":[0,255]}}"#;
        let mut legacy = b"{\"transactions\":[],\"state\":".to_vec();
        legacy.extend_from_slice(checkpoint);
        legacy.push(b'}');
        assert_eq!(
            estimate(checkpoint, WorldResourceFormat::Checkpoint).decoded_owned_bytes,
            estimate(&legacy, WorldResourceFormat::LegacyCandidate).decoded_owned_bytes
        );
        assert!(
            estimate(delta, WorldResourceFormat::Delta).decoded_owned_bytes
                > estimate(checkpoint, WorldResourceFormat::Checkpoint).decoded_owned_bytes
        );
        assert!(matches!(
            preflight_world_json(b"{", WorldResourceFormat::Checkpoint, usize::MAX),
            Err(WorldResourceError::Corrupt(_))
        ));
        assert!(matches!(
            preflight_world_json(checkpoint, WorldResourceFormat::Checkpoint, 1),
            Err(WorldResourceError::Capacity { .. })
        ));
        assert_eq!(
            mul(usize::MAX, 2),
            Err(WorldResourceError::ArithmeticOverflow)
        );
    }
    #[test]
    fn world_resources_delta_roots_and_escape_scratch_are_reserved() {
        let bytes = serde_json::to_vec(&serde_json::json!({
            "accounts":{}, "protocol":{}, "state_root":"x".repeat(10000),
            "parent_state_root":"p".repeat(10000)
        }))
        .unwrap();
        let charge = estimate(&bytes, WorldResourceFormat::Delta);
        assert!(charge.decoded_owned_bytes >= 40000);
        assert_eq!(charge.scanner_scratch_bytes, bytes.len() * 2 + 256);
        // Even ignored escaped tokens cannot allocate parser scratch until the
        // complete scanner reservation has passed the caller's local budget.
        let escaped = br#"{"accounts":{},"protocol":{},"ignored":"\u0061\u0061"}"#;
        let base = estimate(escaped, WorldResourceFormat::Checkpoint);
        assert!(matches!(
            preflight_world_json(
                escaped,
                WorldResourceFormat::Checkpoint,
                base.encoded_bytes + base.scanner_scratch_bytes - 1
            ),
            Err(WorldResourceError::Capacity { .. })
        ));
    }
    #[test]
    fn world_resources_preflight_is_not_validity_authority() {
        // Duplicate/unknown fields are scanned, not accepted as valid state.
        let duplicate = br#"{"accounts":{},"accounts":{},"protocol":{},"unknown":[1,2]}"#;
        assert!(
            preflight_world_json(duplicate, WorldResourceFormat::Checkpoint, usize::MAX).is_ok()
        );
        assert!(serde_json::from_slice::<WorldState>(duplicate).is_err());
    }
}
