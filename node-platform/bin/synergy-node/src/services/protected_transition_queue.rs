//! Engineering-only transition deadline index. Callers atomically pair these
//! changes with the canonical pending record and independently compare both.
use synergy_address_engine::apqe::address::AccountIdentifier;
#[cfg(test)]
use synergy_state::ProtocolChange;
use synergy_state::WorldState;

use super::TRANSITION_DUE_PREFIX as PREFIX;

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum TransitionMode {
    Ordinary,
    Recovery,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct DueTransition {
    pub account: AccountIdentifier,
    pub activation_at: u64,
    pub reference: [u8; 32],
    pub mode: TransitionMode,
}

impl DueTransition {
    pub(super) fn key(&self) -> String {
        format!(
            "{PREFIX}{:020}/{}",
            self.activation_at,
            self.account.lowercase_hex()
        )
    }

    fn value(&self) -> Result<Vec<u8>, String> {
        self.account
            .validate_spending_destination()
            .map_err(|_| "Invalid transition index account")?;
        if self.activation_at == 0 || self.reference == [0; 32] {
            return Err("Invalid transition index coordinates".into());
        }
        let mut value = Vec::with_capacity(34);
        value.push(1); // Internal candidate storage version, not a wire profile.
        value.push(match self.mode {
            TransitionMode::Ordinary => 0,
            TransitionMode::Recovery => 1,
        });
        value.extend_from_slice(&self.reference);
        Ok(value)
    }

    pub(super) fn verify_index(&self, world: &WorldState) -> Result<(), String> {
        if world.protocol.get(&self.key()) != Some(&self.value()?) {
            return Err("pending transition deadline index is missing or differs".into());
        }
        Ok(())
    }

    #[cfg(test)]
    pub(super) fn insert(&self) -> Result<ProtocolChange, String> {
        Ok(ProtocolChange {
            key: self.key(),
            expected_value: None,
            value: Some(self.value()?),
        })
    }

    #[cfg(test)]
    pub(super) fn remove(&self) -> Result<ProtocolChange, String> {
        Ok(ProtocolChange {
            key: self.key(),
            expected_value: Some(self.value()?),
            value: None,
        })
    }
}

#[cfg(test)]
fn decode(key: &str, value: &[u8]) -> Result<DueTransition, String> {
    let suffix = key
        .strip_prefix(PREFIX)
        .ok_or("Invalid transition index prefix")?;
    let bytes = suffix.as_bytes();
    if bytes.len() != 61
        || bytes[20] != b'/'
        || !bytes[..20].iter().all(u8::is_ascii_digit)
        || !bytes[21..]
            .iter()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b))
        || value.len() != 34
        || value[0] != 1
    {
        return Err("Noncanonical transition index entry".into());
    }
    let activation_at = suffix[..20]
        .parse::<u64>()
        .map_err(|_| "Invalid transition index deadline")?;
    let mut account = [0; 20];
    for (output, pair) in account.iter_mut().zip(bytes[21..].chunks_exact(2)) {
        fn nibble(b: u8) -> u8 {
            if b <= b'9' {
                b - b'0'
            } else {
                b - b'a' + 10
            }
        }
        *output = (nibble(pair[0]) << 4) | nibble(pair[1]);
    }
    let mode = match value[1] {
        0 => TransitionMode::Ordinary,
        1 => TransitionMode::Recovery,
        _ => return Err("Unknown transition index mode".into()),
    };
    let mut reference = [0; 32];
    reference.copy_from_slice(&value[2..]);
    let entry = DueTransition {
        account: AccountIdentifier::from_bytes(account),
        activation_at,
        reference,
        mode,
    };
    if entry.key() != key || entry.value()?.as_slice() != value {
        return Err("Noncanonical transition index entry".into());
    }
    Ok(entry)
}

/// At most `visit_limit` index rows are examined/returned, in deadline/account
/// byte order. This index alone does not establish migration completeness or
/// pending-record authority; callers verify canonical finalized/working state.
#[cfg(test)]
pub(super) fn due(
    world: &WorldState,
    consensus_time: u64,
    visit_limit: usize,
) -> Result<Vec<DueTransition>, String> {
    if visit_limit == 0 {
        return Err("Transition index visit limit must be nonzero".into());
    }
    // The next deadline prefix excludes all future canonical rows without
    // scanning them. At u64::MAX use the exact namespace's lexical successor.
    let end = match consensus_time.checked_add(1) {
        Some(next) => format!("{PREFIX}{next:020}/"),
        None => format!("{}0", PREFIX.trim_end_matches('/')),
    };
    world
        .protocol
        .range(PREFIX.to_owned()..end)
        .take(visit_limit)
        .map(|(key, value)| {
            let entry = decode(key, value)?;
            if entry.activation_at > consensus_time {
                return Err("Transition index deadline outside range".into());
            }
            Ok(entry)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use synergy_state::StateDiff;

    fn entry(account: u8, deadline: u64, mode: TransitionMode) -> DueTransition {
        DueTransition {
            account: AccountIdentifier::from_bytes([account; 20]),
            activation_at: deadline,
            reference: [account; 32],
            mode,
        }
    }
    fn apply(world: &mut WorldState, change: ProtocolChange) -> bool {
        StateDiff {
            changes: vec![],
            protocol_changes: vec![change],
        }
        .apply(world)
        .is_ok()
    }

    #[test]
    fn due_is_ordered_bounded_and_deadline_inclusive() {
        let mut world = WorldState::default();
        let a = entry(1, 10, TransitionMode::Recovery);
        let b = entry(2, 10, TransitionMode::Ordinary);
        let c = entry(3, 11, TransitionMode::Ordinary);
        for row in [c, b, a] {
            assert!(apply(&mut world, row.insert().unwrap()));
        }
        world.protocol.insert("unrelated".into(), vec![0]);
        assert!(due(&world, 10, 0).is_err());
        assert!(due(&world, 9, 3).unwrap().is_empty());
        assert_eq!(due(&world, 10, 1).unwrap(), vec![a]);
        assert_eq!(due(&world, 10, 3).unwrap(), vec![a, b]);
        assert_eq!(due(&world, u64::MAX, 3).unwrap(), vec![a, b, c]);
    }

    #[test]
    fn exact_cas_refuses_duplicate_missing_and_conflicting_removal() {
        let mut world = WorldState::default();
        let row = entry(1, 10, TransitionMode::Ordinary);
        assert!(!apply(&mut world, row.remove().unwrap()));
        assert!(apply(&mut world, row.insert().unwrap()));
        let before = world.clone();
        assert!(!apply(&mut world, row.insert().unwrap()));
        let mut foreign = row;
        foreign.mode = TransitionMode::Recovery;
        assert!(!apply(&mut world, foreign.remove().unwrap()));
        foreign = row;
        foreign.reference = [2; 32];
        assert!(!apply(&mut world, foreign.remove().unwrap()));
        assert_eq!(world, before);
        assert!(apply(&mut world, row.remove().unwrap()));
        assert!(due(&world, 10, 1).unwrap().is_empty());
    }

    #[test]
    fn malformed_head_refuses_without_scanning_past_cap() {
        let mut world = WorldState::default();
        let first = entry(1, 10, TransitionMode::Ordinary);
        let second = entry(2, 10, TransitionMode::Recovery);
        assert!(apply(&mut world, first.insert().unwrap()));
        world.protocol.insert(second.key(), vec![1, 2]);
        assert_eq!(due(&world, 10, 1).unwrap(), vec![first]);
        assert!(due(&world, 10, 2).is_err());
        let mut key = first.key();
        key.replace_range(key.len() - 1.., "A");
        assert!(decode(&key, &first.value().unwrap()).is_err());
        let mut invalid = first;
        invalid.activation_at = 0;
        assert!(invalid.insert().is_err());
        invalid = first;
        invalid.reference = [0; 32];
        assert!(invalid.remove().is_err());
        invalid = first;
        invalid.account = AccountIdentifier::from_bytes([0; 20]);
        assert!(invalid.insert().is_err());
    }
}
