use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::{AccountState, StateError, WorldState};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountChange {
    pub account: String,
    pub debit_nwei: u128,
    pub credit_nwei: u128,
    pub expected_nonce: Option<u64>,
    pub code_hash: Option<Option<String>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtocolChange {
    pub key: String,
    pub expected_value: Option<Vec<u8>>,
    pub value: Option<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct StateDiff {
    pub changes: Vec<AccountChange>,
    #[serde(default)]
    pub protocol_changes: Vec<ProtocolChange>,
}

impl StateDiff {
    pub fn validate(&self) -> Result<(), StateError> {
        let mut accounts = BTreeMap::<&str, ()>::new();
        for change in &self.changes {
            if change.account.trim().is_empty() || accounts.insert(&change.account, ()).is_some() {
                return Err(StateError::InvalidDiff);
            }
        }
        let mut protocol = BTreeMap::<&str, ()>::new();
        for change in &self.protocol_changes {
            if change.key.trim().is_empty()
                || change.key.len() > 512
                || change.key.contains(char::is_control)
                || change
                    .value
                    .as_ref()
                    .is_some_and(|value| value.is_empty() || value.len() > 4 * 1024 * 1024)
                || protocol.insert(&change.key, ()).is_some()
            {
                return Err(StateError::InvalidDiff);
            }
        }
        Ok(())
    }

    pub fn apply(&self, state: &mut WorldState) -> Result<(), StateError> {
        self.validate()?;
        let mut next = state.clone();
        for change in &self.changes {
            let account = next
                .accounts
                .entry(change.account.clone())
                .or_insert_with(AccountState::default);
            if let Some(nonce) = change.expected_nonce {
                account.consume_nonce(nonce)?;
            }
            account.debit(change.debit_nwei)?;
            account.credit(change.credit_nwei)?;
            if let Some(code_hash) = &change.code_hash {
                account.code_hash = code_hash.clone();
            }
        }
        for change in &self.protocol_changes {
            if next.protocol.get(&change.key) != change.expected_value.as_ref() {
                return Err(StateError::ProtocolValueMismatch(change.key.clone()));
            }
            match &change.value {
                Some(value) => {
                    next.protocol.insert(change.key.clone(), value.clone());
                }
                None => {
                    next.protocol.remove(&change.key);
                }
            }
        }
        *state = next;
        Ok(())
    }
}
