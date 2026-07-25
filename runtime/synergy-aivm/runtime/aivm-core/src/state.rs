use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct StateKey {
    pub contract_namespace: Vec<u8>,
    pub key: Vec<u8>,
}

impl StateKey {
    pub fn new(contract_namespace: impl Into<Vec<u8>>, key: impl Into<Vec<u8>>) -> Self {
        Self {
            contract_namespace: contract_namespace.into(),
            key: key.into(),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContractState {
    #[serde(with = "state_values_serde")]
    values: BTreeMap<StateKey, Vec<u8>>,
}

impl ContractState {
    pub fn get(&self, key: &StateKey) -> Option<&[u8]> {
        self.values.get(key).map(Vec::as_slice)
    }

    pub fn state_root(&self) -> [u8; 32] {
        let mut canonical = Vec::new();
        canonical.extend_from_slice(b"AIVM-STATE-V1");
        push_u64(&mut canonical, self.values.len() as u64);
        for (key, value) in &self.values {
            push_bytes(&mut canonical, &key.contract_namespace);
            push_bytes(&mut canonical, &key.key);
            push_bytes(&mut canonical, value);
        }
        digest(&canonical)
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StateOverlay {
    writes: BTreeMap<StateKey, Option<Vec<u8>>>,
}

impl StateOverlay {
    pub fn read<'a>(&'a self, base: &'a ContractState, key: &StateKey) -> Option<&'a [u8]> {
        match self.writes.get(key) {
            Some(Some(value)) => Some(value),
            Some(None) => None,
            None => base.get(key),
        }
    }

    pub fn write(&mut self, key: StateKey, value: Vec<u8>) {
        self.writes.insert(key, Some(value));
    }

    pub fn delete(&mut self, key: StateKey) {
        self.writes.insert(key, None);
    }

    pub fn commit(self, base: &mut ContractState) {
        for (key, value) in self.writes {
            match value {
                Some(value) => {
                    base.values.insert(key, value);
                }
                None => {
                    base.values.remove(&key);
                }
            }
        }
    }

    pub fn rollback(self) {}
}

pub struct CounterStateMachine {
    namespace: Vec<u8>,
}

impl CounterStateMachine {
    pub fn new(namespace: impl Into<Vec<u8>>) -> Self {
        Self {
            namespace: namespace.into(),
        }
    }

    pub fn is_deployed(&self, base: &ContractState, overlay: &StateOverlay) -> bool {
        overlay.read(base, &self.deployed_key()).is_some()
    }

    pub fn initialize(&self, base: &ContractState, overlay: &mut StateOverlay) -> bool {
        if self.is_deployed(base, overlay) {
            return false;
        }
        overlay.write(self.deployed_key(), vec![1]);
        overlay.write(self.counter_key(), 0_u64.to_be_bytes().to_vec());
        true
    }

    pub fn get(&self, base: &ContractState, overlay: &StateOverlay) -> u64 {
        overlay
            .read(base, &self.counter_key())
            .and_then(|value| value.try_into().ok())
            .map(u64::from_be_bytes)
            .unwrap_or(0)
    }

    pub fn increment(&self, base: &ContractState, overlay: &mut StateOverlay) -> u64 {
        let next = self.get(base, overlay).saturating_add(1);
        overlay.write(self.counter_key(), next.to_be_bytes().to_vec());
        next
    }

    fn counter_key(&self) -> StateKey {
        StateKey::new(self.namespace.clone(), b"counter".to_vec())
    }

    fn deployed_key(&self) -> StateKey {
        StateKey::new(self.namespace.clone(), b"__deployed".to_vec())
    }
}

fn push_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn push_bytes(out: &mut Vec<u8>, value: &[u8]) {
    push_u64(out, value.len() as u64);
    out.extend_from_slice(value);
}

fn digest(bytes: &[u8]) -> [u8; 32] {
    let digest = Sha256::digest(bytes);
    let mut hash = [0_u8; 32];
    hash.copy_from_slice(&digest);
    hash
}

mod state_values_serde {
    use super::*;
    use serde::{Deserializer, Serializer};

    #[derive(Serialize, Deserialize)]
    struct StateEntry {
        contract_namespace: Vec<u8>,
        key: Vec<u8>,
        value: Vec<u8>,
    }

    pub fn serialize<S>(
        values: &BTreeMap<StateKey, Vec<u8>>,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let entries: Vec<StateEntry> = values
            .iter()
            .map(|(key, value)| StateEntry {
                contract_namespace: key.contract_namespace.clone(),
                key: key.key.clone(),
                value: value.clone(),
            })
            .collect();
        entries.serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<BTreeMap<StateKey, Vec<u8>>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let entries = Vec::<StateEntry>::deserialize(deserializer)?;
        Ok(entries
            .into_iter()
            .map(|entry| {
                (
                    StateKey::new(entry.contract_namespace, entry.key),
                    entry.value,
                )
            })
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn overlay_commit_and_rollback_have_distinct_state_effects() {
        let counter = CounterStateMachine::new("counter-contract");
        let mut base = ContractState::default();

        let mut committed = StateOverlay::default();
        assert_eq!(counter.increment(&base, &mut committed), 1);
        committed.commit(&mut base);
        assert_eq!(counter.get(&base, &StateOverlay::default()), 1);

        let root_after_commit = base.state_root();
        let mut rolled_back = StateOverlay::default();
        assert_eq!(counter.increment(&base, &mut rolled_back), 2);
        rolled_back.rollback();

        assert_eq!(counter.get(&base, &StateOverlay::default()), 1);
        assert_eq!(base.state_root(), root_after_commit);
    }

    #[test]
    fn counter_initialization_marks_deploy_without_incrementing() {
        let counter = CounterStateMachine::new("counter-contract");
        let mut base = ContractState::default();
        let mut overlay = StateOverlay::default();

        assert!(!counter.is_deployed(&base, &overlay));
        assert!(counter.initialize(&base, &mut overlay));
        assert!(counter.is_deployed(&base, &overlay));
        assert_eq!(counter.get(&base, &overlay), 0);
        overlay.commit(&mut base);

        assert!(counter.is_deployed(&base, &StateOverlay::default()));
        assert_eq!(counter.get(&base, &StateOverlay::default()), 0);

        let mut duplicate = StateOverlay::default();
        assert!(!counter.initialize(&base, &mut duplicate));
    }

    #[test]
    fn state_root_is_deterministic_for_order_independent_writes() {
        let mut first = ContractState::default();
        let mut first_overlay = StateOverlay::default();
        first_overlay.write(StateKey::new("contract", "b"), vec![2]);
        first_overlay.write(StateKey::new("contract", "a"), vec![1]);
        first_overlay.commit(&mut first);

        let mut second = ContractState::default();
        let mut second_overlay = StateOverlay::default();
        second_overlay.write(StateKey::new("contract", "a"), vec![1]);
        second_overlay.write(StateKey::new("contract", "b"), vec![2]);
        second_overlay.commit(&mut second);

        assert_eq!(first.state_root(), second.state_root());
    }
}
