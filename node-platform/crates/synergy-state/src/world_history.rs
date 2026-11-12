//! Bounded, root-verified storage representation. This module has no finality authority.
use std::{collections::BTreeMap, io::Write, sync::Arc};

use serde::{ser::SerializeMap, Deserialize, Serialize, Serializer};
use synergy_storage::AtomicStoreReader;

use crate::world_resources::{
    preflight_world_json, resource_state_error, world_owned_bytes, BudgetedWorld,
    WorldResourceBudget, WorldResourceFormat, WorldResourcePermit,
};
use crate::{state_root, AccountState, StateError, WorldState};

const MAGIC: &[u8; 8] = b"SNWDV001";
pub(crate) const CHECKPOINT_INTERVAL: u64 = 64;
const MAX_DELTA_BYTES: usize = 8 * 1024 * 1024;

#[derive(Debug, Clone, Copy)]
pub struct WorldHistoryTip {
    pub(crate) checkpoint_height: u64,
    pub(crate) delta_bytes: usize,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WorldDelta {
    height: u64,
    parent_height: u64,
    state_root: String,
    parent_state_root: String,
    accounts: BTreeMap<String, Option<AccountState>>,
    protocol: BTreeMap<String, Option<Vec<u8>>>,
}

pub(crate) fn world_record(height: u64) -> String {
    format!("finalized-world/{height:020}.json")
}

pub fn checkpoint(
    height: u64,
    world: &WorldState,
) -> Result<(Vec<u8>, WorldHistoryTip), StateError> {
    Ok((
        serde_json::to_vec(world).map_err(corrupt)?,
        WorldHistoryTip {
            checkpoint_height: height,
            delta_bytes: 0,
        },
    ))
}

pub fn encode_transition(
    height: u64,
    root: &str,
    parent_root: &str,
    base: &WorldState,
    world: &WorldState,
    tip: WorldHistoryTip,
) -> Result<(Vec<u8>, WorldHistoryTip), StateError> {
    if height.is_multiple_of(CHECKPOINT_INTERVAL)
        || height.saturating_sub(tip.checkpoint_height) >= CHECKPOINT_INTERVAL
    {
        return checkpoint(height, world);
    }
    let changes = WorldDeltaRef {
        height,
        parent_height: height.checked_sub(1).ok_or(StateError::InvalidCommitment)?,
        state_root: root,
        parent_state_root: parent_root,
        accounts: Changed {
            base: &base.accounts,
            next: &world.accounts,
        },
        protocol: Changed {
            base: &base.protocol,
            next: &world.protocol,
        },
    };
    let mut writer = BoundedDeltaWriter {
        bytes: MAGIC.to_vec(),
        remaining: MAX_DELTA_BYTES
            .saturating_sub(tip.delta_bytes)
            .saturating_sub(MAGIC.len()),
        exceeded: tip.delta_bytes.saturating_add(MAGIC.len()) > MAX_DELTA_BYTES,
    };
    if let Err(error) = serde_json::to_writer(&mut writer, &changes) {
        if writer.exceeded {
            drop(writer);
            return checkpoint(height, world);
        }
        return Err(corrupt(error));
    }
    let bytes = writer.bytes;
    let total = tip.delta_bytes.saturating_add(bytes.len());
    Ok((
        bytes,
        WorldHistoryTip {
            delta_bytes: total,
            ..tip
        },
    ))
}

#[derive(Serialize)]
struct WorldDeltaRef<'a> {
    height: u64,
    parent_height: u64,
    state_root: &'a str,
    parent_state_root: &'a str,
    accounts: Changed<'a, AccountState>,
    protocol: Changed<'a, Vec<u8>>,
}

// Serialize differences directly from the two borrowed worlds. Even a large
// changed protocol value is never cloned into a temporary delta tree.
struct Changed<'a, T> {
    base: &'a BTreeMap<String, T>,
    next: &'a BTreeMap<String, T>,
}
impl<T: PartialEq + Serialize> Serialize for Changed<'_, T> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(None)?;
        for (key, value) in self.next {
            if self.base.get(key) != Some(value) {
                map.serialize_entry(key, &Some(value))?;
            }
        }
        for key in self.base.keys() {
            if !self.next.contains_key(key) {
                map.serialize_entry(key, &Option::<&T>::None)?;
            }
        }
        map.end()
    }
}

struct BoundedDeltaWriter {
    bytes: Vec<u8>,
    remaining: usize,
    exceeded: bool,
}
impl Write for BoundedDeltaWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if self.exceeded || bytes.len() > self.remaining {
            self.exceeded = true;
            return Err(std::io::Error::other("world delta budget exceeded"));
        }
        self.bytes.extend_from_slice(bytes);
        self.remaining -= bytes.len();
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// All dependent reads share the caller's storage lock. At most 63 delta
/// records and 8 MiB of encoded patches are retained during reconstruction.
pub(crate) fn read_world(
    reader: &AtomicStoreReader<'_>,
    height: u64,
    root: &str,
) -> Result<Option<(WorldState, WorldHistoryTip)>, StateError> {
    read_world_records(reader, height, root, world_record, None)
}

/// A previously root-verified immutable world, held by the existing owner.
/// Its opaque replay tip must come from this codec's checkpoint or verified read.
pub struct WorldHistoryBase<'a> {
    pub height: u64,
    pub state_root: &'a str,
    pub world: &'a WorldState,
    pub tip: WorldHistoryTip,
}

/// Reconstruct a world in the caller's namespace under one consistent read.
/// A matching verified parent avoids rereading its checkpoint chain. This is
/// storage integrity only; the caller must independently establish authority.
pub fn read_world_records(
    reader: &AtomicStoreReader<'_>,
    height: u64,
    root: &str,
    record: impl Fn(u64) -> String,
    base: Option<WorldHistoryBase<'_>>,
) -> Result<Option<(WorldState, WorldHistoryTip)>, StateError> {
    read_world_records_internal(reader, height, root, record, base, None)
        .map(|value| value.map(|(world, tip, _)| (world, tip)))
}

/// An already accounted immutable base; its reservation remains held by the
/// caller while reconstruction reserves a separate deep clone.
pub struct BudgetedWorldHistoryBase<'a> {
    pub height: u64,
    pub state_root: &'a str,
    pub world: &'a BudgetedWorld,
    pub tip: WorldHistoryTip,
}
pub fn read_world_records_budgeted(
    reader: &AtomicStoreReader<'_>,
    height: u64,
    root: &str,
    record: impl Fn(u64) -> String,
    base: Option<BudgetedWorldHistoryBase<'_>>,
    budget: &Arc<WorldResourceBudget>,
) -> Result<Option<(BudgetedWorld, WorldHistoryTip)>, StateError> {
    if base
        .as_ref()
        .is_some_and(|base| !Arc::ptr_eq(base.world.budget(), budget))
    {
        return Err(StateError::Storage(
            "World base uses a different resource pool".into(),
        ));
    }
    let base = base.map(|base| WorldHistoryBase {
        height: base.height,
        state_root: base.state_root,
        world: base.world.as_ref(),
        tip: base.tip,
    });
    read_world_records_internal(reader, height, root, record, base, Some(budget))?
        .map(|(world, tip, permit)| {
            BudgetedWorld::from_reserved(world, permit.expect("budgeted replay retains permit"))
                .map(|world| (world, tip))
                .map_err(resource_state_error)
        })
        .transpose()
}

struct RetainedPatch {
    delta: WorldDelta,
    _permit: Option<WorldResourcePermit>,
}
type ReplayResult = Option<(WorldState, WorldHistoryTip, Option<WorldResourcePermit>)>;
fn read_world_records_internal(
    reader: &AtomicStoreReader<'_>,
    height: u64,
    root: &str,
    record: impl Fn(u64) -> String,
    base: Option<WorldHistoryBase<'_>>,
    budget: Option<&Arc<WorldResourceBudget>>,
) -> Result<ReplayResult, StateError> {
    // Hold traversal metadata and each cloned root before allocation.
    let _traversal = budget
        .map(|budget| {
            budget
                .reserve(
                    4096 + 8192
                        + CHECKPOINT_INTERVAL as usize * std::mem::size_of::<RetainedPatch>(),
                )
                .map_err(resource_state_error)
        })
        .transpose()?;
    let mut root_permit = budget
        .map(|budget| {
            budget
                .reserve(
                    root.len()
                        .checked_mul(2)
                        .and_then(|n| n.checked_add(64))
                        .ok_or(StateError::ResourcePressure {
                            requested: usize::MAX,
                            limit: budget.limit(),
                        })?,
                )
                .map_err(resource_state_error)
        })
        .transpose()?;
    let mut cursor = height;
    let mut expected_root = root.to_owned();
    let mut patches = if budget.is_some() {
        Vec::with_capacity(CHECKPOINT_INTERVAL as usize)
    } else {
        Vec::new()
    };
    let mut delta_bytes = 0usize;
    for _ in 0..CHECKPOINT_INTERVAL {
        if let Some(base) = base
            .as_ref()
            .filter(|base| base.height == cursor && base.state_root == expected_root)
        {
            let total = delta_bytes.saturating_add(base.tip.delta_bytes);
            if total > MAX_DELTA_BYTES
                || base.height < base.tip.checkpoint_height
                || height.saturating_sub(base.tip.checkpoint_height) >= CHECKPOINT_INTERVAL
            {
                return Err(StateError::Corrupt(
                    "cached world replay bound exceeded".into(),
                ));
            }
            if state_root(base.world)? != expected_root {
                return Err(StateError::Corrupt(
                    "cached world parent root mismatch".into(),
                ));
            }
            let permit = budget
                .map(|budget| {
                    budget
                        .reserve(world_owned_bytes(base.world).map_err(resource_state_error)?)
                        .map_err(resource_state_error)
                })
                .transpose()?;
            return materialize(
                base.world.clone(),
                patches,
                root,
                WorldHistoryTip {
                    checkpoint_height: base.tip.checkpoint_height,
                    delta_bytes: total,
                },
                permit,
                budget,
            )
            .map(Some);
        }
        let path = record(cursor);
        let Some(length) = reader.optional_record_bytes(&path).map_err(storage_error)? else {
            return if patches.is_empty() {
                Ok(None)
            } else {
                Err(StateError::Corrupt("missing world delta parent".into()))
            };
        };
        let encoded_permit = budget
            .map(|budget| budget.reserve(length).map_err(resource_state_error))
            .transpose()?;
        let Some(bytes) = reader
            .with_maximum_bytes(length)
            .read_optional_bounded(&path)
            .map_err(storage_error)?
        else {
            return Err(StateError::Corrupt(
                "world record disappeared during replay".into(),
            ));
        };
        if bytes.starts_with(MAGIC) {
            delta_bytes = delta_bytes.saturating_add(bytes.len());
            if delta_bytes > MAX_DELTA_BYTES || cursor.is_multiple_of(CHECKPOINT_INTERVAL) {
                return Err(StateError::Corrupt(
                    "world delta replay bound exceeded".into(),
                ));
            }
            let payload = &bytes[MAGIC.len()..];
            let (owned, scan) = reserve_decode(payload, WorldResourceFormat::Delta, budget)?;
            let delta: WorldDelta = serde_json::from_slice(payload).map_err(corrupt)?;
            drop(scan);
            drop(bytes);
            drop(encoded_permit);
            if delta.height != cursor
                || delta.parent_height.checked_add(1) != Some(cursor)
                || delta.state_root != expected_root
            {
                return Err(StateError::Corrupt(
                    "world delta commitment mismatch".into(),
                ));
            }
            let next_root_permit = budget
                .map(|budget| {
                    budget
                        .reserve(
                            delta
                                .parent_state_root
                                .len()
                                .checked_mul(2)
                                .and_then(|n| n.checked_add(64))
                                .ok_or(StateError::ResourcePressure {
                                    requested: usize::MAX,
                                    limit: budget.limit(),
                                })?,
                        )
                        .map_err(resource_state_error)
                })
                .transpose()?;
            cursor = delta.parent_height;
            expected_root = delta.parent_state_root.clone();
            drop(root_permit.take());
            root_permit = next_root_permit;
            patches.push(RetainedPatch {
                delta,
                _permit: owned,
            });
        } else {
            let (permit, scan) = reserve_decode(&bytes, WorldResourceFormat::Checkpoint, budget)?;
            let world: WorldState = serde_json::from_slice(&bytes).map_err(corrupt)?;
            drop(scan);
            drop(bytes);
            drop(encoded_permit);
            if state_root(&world)? != expected_root {
                return Err(StateError::Corrupt("world checkpoint root mismatch".into()));
            }
            return materialize(
                world,
                patches,
                root,
                WorldHistoryTip {
                    checkpoint_height: cursor,
                    delta_bytes,
                },
                permit,
                budget,
            )
            .map(Some);
        }
    }
    Err(StateError::Corrupt(
        "world checkpoint replay height bound exceeded".into(),
    ))
}
fn storage_error(error: synergy_storage::StorageError) -> StateError {
    StateError::Storage(format!("{error:?}"))
}
// Input bytes are separately reserved by the caller. Reserve escaped-string
// scratch before preflight and decoded maps before native serde allocation.
fn reserve_decode(
    bytes: &[u8],
    format: WorldResourceFormat,
    budget: Option<&Arc<WorldResourceBudget>>,
) -> Result<(Option<WorldResourcePermit>, Option<WorldResourcePermit>), StateError> {
    let Some(budget) = budget else {
        return Ok((None, None));
    };
    let scratch = bytes
        .len()
        .checked_mul(2)
        .and_then(|n| n.checked_add(256))
        .ok_or(StateError::ResourcePressure {
            requested: usize::MAX,
            limit: budget.limit(),
        })?;
    let scanner = budget.reserve(scratch).map_err(resource_state_error)?;
    let estimate = preflight_world_json(bytes, format, usize::MAX).map_err(resource_state_error)?;
    let owned = budget
        .reserve(estimate.decoded_owned_bytes)
        .map_err(resource_state_error)?;
    Ok((Some(owned), Some(scanner)))
}
fn materialize(
    mut world: WorldState,
    patches: Vec<RetainedPatch>,
    root: &str,
    tip: WorldHistoryTip,
    mut permit: Option<WorldResourcePermit>,
    budget: Option<&Arc<WorldResourceBudget>>,
) -> Result<(WorldState, WorldHistoryTip, Option<WorldResourcePermit>), StateError> {
    for patch in patches.into_iter().rev() {
        if let Some(permit) = permit.as_mut() {
            // Keep patch nodes and prospective World insert nodes accounted
            // simultaneously until moving the write set has finished.
            permit
                .grow(
                    patch
                        ._permit
                        .as_ref()
                        .expect("budgeted patch retains charge")
                        .bytes(),
                )
                .map_err(resource_state_error)?;
        }
        let WorldDelta {
            accounts,
            protocol,
            state_root,
            parent_state_root,
            ..
        } = patch.delta;
        apply(&mut world.accounts, accounts);
        apply(&mut world.protocol, protocol);
        drop((state_root, parent_state_root));
        drop(patch._permit);
        if let Some(permit) = permit.as_mut() {
            permit
                .shrink(world_owned_bytes(&world).map_err(resource_state_error)?)
                .expect("pre-reserved patch covers World entries");
        }
    }
    if state_root(&world)? != root {
        return Err(StateError::Corrupt(
            "durable account state root differs from commitment".into(),
        ));
    }
    // `budget` is retained by each permit; no independent unaccounted World is
    // exported from the budgeted public entry point.
    let _ = budget;
    Ok((world, tip, permit))
}

/// Keep the fixed checkpoint interval required by every surviving delta.
/// At most 63 additional world records precede the configured history horizon.
pub fn world_prune_through(through_height: u64) -> Option<u64> {
    let anchor = through_height.saturating_add(1) / CHECKPOINT_INTERVAL * CHECKPOINT_INTERVAL;
    anchor.checked_sub(1).filter(|height| *height > 0)
}

fn apply<T>(target: &mut BTreeMap<String, T>, changes: BTreeMap<String, Option<T>>) {
    for (key, value) in changes {
        match value {
            Some(value) => {
                target.insert(key, value);
            }
            None => {
                target.remove(&key);
            }
        }
    }
}

fn corrupt(error: serde_json::Error) -> StateError {
    StateError::Corrupt(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cumulative_patch_budget_forces_checkpoint_before_height_limit() {
        let base = WorldState::default();
        let mut world = base.clone();
        world.protocol.insert("payload".into(), vec![1; 1024]);
        let (_, tip) = checkpoint(1, &base).unwrap();
        let (bytes, tip) = encode_transition(2, "next", "parent", &base, &world, tip).unwrap();
        assert!(bytes.starts_with(MAGIC));
        let (full, reset) = encode_transition(
            3,
            "next",
            "parent",
            &base,
            &world,
            WorldHistoryTip {
                delta_bytes: MAX_DELTA_BYTES - bytes.len() + 1,
                ..tip
            },
        )
        .unwrap();
        assert!(!full.starts_with(MAGIC));
        assert_eq!(serde_json::from_slice::<WorldState>(&full).unwrap(), world);
        assert_eq!(reset.delta_bytes, 0);
        assert_eq!(reset.checkpoint_height, 3);
    }
}

#[cfg(test)]
mod cached_replay_tests {
    use super::*;
    #[test]
    fn verified_parent_reads_only_new_delta_and_keeps_cumulative_byte_bound() {
        let root = std::env::temp_dir().join(format!(
            "synergy-cached-world-replay-{}",
            std::process::id()
        ));
        let store = synergy_storage::AtomicStore::new(&root, 64 * 1024 * 1024).unwrap();
        let one = WorldState::default();
        let mut two = one.clone();
        two.protocol.insert("a".into(), vec![1]);
        let mut three = two.clone();
        three.protocol.insert("b".into(), vec![2]);
        let r1 = state_root(&one).unwrap();
        let r2 = state_root(&two).unwrap();
        let r3 = state_root(&three).unwrap();
        let (full, tip1) = checkpoint(1, &one).unwrap();
        let (d2, tip2) = encode_transition(2, &r2, &r1, &one, &two, tip1).unwrap();
        let (d3, _) = encode_transition(3, &r3, &r2, &two, &three, tip2).unwrap();
        store.write_atomic(world_record(1), &full).unwrap();
        store.write_atomic(world_record(2), &d2).unwrap();
        store.write_atomic(world_record(3), &d3).unwrap();
        let (verified_two, tip2) = store
            .inspect_consistent(|reader| read_world(reader, 2, &r2))
            .unwrap()
            .unwrap()
            .unwrap();
        let reads = std::cell::Cell::new(0);
        let (restored, _) = store
            .inspect_consistent(|reader| {
                read_world_records(
                    reader,
                    3,
                    &r3,
                    |height| {
                        reads.set(reads.get() + 1);
                        world_record(height)
                    },
                    Some(WorldHistoryBase {
                        height: 2,
                        state_root: &r2,
                        world: &verified_two,
                        tip: tip2,
                    }),
                )
            })
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(restored, three);
        assert_eq!(reads.get(), 1);
        let oversized_tip = WorldHistoryTip {
            delta_bytes: MAX_DELTA_BYTES,
            ..tip2
        };
        let result = store
            .inspect_consistent(|reader| {
                read_world_records(
                    reader,
                    3,
                    &r3,
                    world_record,
                    Some(WorldHistoryBase {
                        height: 2,
                        state_root: &r2,
                        world: &verified_two,
                        tip: oversized_tip,
                    }),
                )
            })
            .unwrap();
        assert!(matches!(result, Err(StateError::Corrupt(_))));
        let result = store
            .inspect_consistent(|reader| {
                read_world_records(
                    reader,
                    3,
                    &r3,
                    world_record,
                    Some(WorldHistoryBase {
                        height: 2,
                        state_root: &r2,
                        world: &one,
                        tip: tip2,
                    }),
                )
            })
            .unwrap();
        assert!(matches!(result, Err(StateError::Corrupt(_))));
        reads.set(0);
        let (cold, _) = store
            .inspect_consistent(|reader| {
                read_world_records(
                    reader,
                    3,
                    &r3,
                    |height| {
                        reads.set(reads.get() + 1);
                        world_record(height)
                    },
                    None,
                )
            })
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(cold, three);
        assert_eq!(reads.get(), 3);
        std::fs::remove_dir_all(root).unwrap();
    }
}

#[cfg(test)]
mod budgeted_replay_tests {
    use super::*;
    #[test]
    fn world_resources_budgeted_replay_and_borrowed_base_preserve_bytes() {
        let root = std::env::temp_dir().join(format!(
            "world-budget-replay-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let store = synergy_storage::AtomicStore::new(&root, 64 * 1024 * 1024).unwrap();
        let mut world = WorldState::default();
        world.protocol.insert("initial".into(), vec![1; 1024]);
        let (bytes, mut tip) = checkpoint(1, &world).unwrap();
        store.write_atomic(world_record(1), &bytes).unwrap();
        let mut previous = state_root(&world).unwrap();
        for height in 2..=63 {
            let before = world.clone();
            world
                .protocol
                .insert(format!("key-{height}"), vec![height as u8; 4]);
            let next = state_root(&world).unwrap();
            let (bytes, next_tip) =
                encode_transition(height, &next, &previous, &before, &world, tip).unwrap();
            store.write_atomic(world_record(height), &bytes).unwrap();
            previous = next;
            tip = next_tip;
        }
        let original = store.read_bounded(world_record(63)).unwrap();
        let budget = WorldResourceBudget::new(4 * 1024 * 1024);
        let (restored, tip) = store
            .inspect_consistent(|reader| {
                read_world_records_budgeted(reader, 63, &previous, world_record, None, &budget)
            })
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(restored.as_ref(), &world);
        assert_eq!(tip.checkpoint_height, 1);
        assert_eq!(budget.used(), restored.charged_bytes());
        let reads = std::cell::Cell::new(0);
        let (copy, _) = store
            .inspect_consistent(|reader| {
                read_world_records_budgeted(
                    reader,
                    63,
                    &previous,
                    |h| {
                        reads.set(reads.get() + 1);
                        world_record(h)
                    },
                    Some(BudgetedWorldHistoryBase {
                        height: 63,
                        state_root: &previous,
                        world: &restored,
                        tip,
                    }),
                    &budget,
                )
            })
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(reads.get(), 0);
        assert_eq!(copy.as_ref(), restored.as_ref());
        assert_eq!(
            budget.used(),
            restored.charged_bytes() + copy.charged_bytes()
        );
        drop(copy);
        drop(restored);
        assert_eq!(budget.used(), 0);
        let small = WorldResourceBudget::new(1);
        assert!(matches!(
            store
                .inspect_consistent(|reader| read_world_records_budgeted(
                    reader,
                    63,
                    &previous,
                    world_record,
                    None,
                    &small
                ))
                .unwrap(),
            Err(StateError::ResourcePressure { .. })
        ));
        assert_eq!(small.used(), 0);
        let mid = WorldResourceBudget::new(world_owned_bytes(&world).unwrap() / 2);
        assert!(
            mid.limit()
                > 4096 + CHECKPOINT_INTERVAL as usize * std::mem::size_of::<RetainedPatch>()
        );
        assert!(matches!(
            store
                .inspect_consistent(|reader| read_world_records_budgeted(
                    reader,
                    63,
                    &previous,
                    world_record,
                    None,
                    &mid
                ))
                .unwrap(),
            Err(StateError::ResourcePressure { .. })
        ));
        assert_eq!(mid.used(), 0);
        assert_eq!(store.read_bounded(world_record(63)).unwrap(), original);
        let wrong = store
            .inspect_consistent(|reader| {
                read_world_records_budgeted(reader, 63, "wrong", world_record, None, &budget)
            })
            .unwrap();
        assert!(matches!(wrong, Err(StateError::Corrupt(_))));
        assert_eq!(budget.used(), 0);
        store.write_atomic(world_record(63), b"broken").unwrap();
        assert!(matches!(
            store
                .inspect_consistent(|reader| read_world_records_budgeted(
                    reader,
                    63,
                    &previous,
                    world_record,
                    None,
                    &budget
                ))
                .unwrap(),
            Err(StateError::Corrupt(_))
        ));
        assert_eq!(budget.used(), 0);
        std::fs::remove_dir_all(root).unwrap();
    }
}
