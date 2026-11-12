use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::{StateError, WorldState};

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

    /// Apply ordered action/fee diffs as one atomic transaction. Only touched
    /// entries are copied; all validation runs before the first World mutation.
    /// Budgeted callers must reserve staging before invoking this helper.
    pub fn apply_ordered_atomic(diffs: &[&Self], state: &mut WorldState) -> Result<(), StateError> {
        let mut accounts = BTreeMap::<&str, ()>::new();
        let mut protocol = BTreeMap::<&str, ()>::new();
        for diff in diffs {
            diff.validate()?;
            for change in &diff.changes {
                accounts.insert(&change.account, ());
            }
            for change in &diff.protocol_changes {
                protocol.insert(&change.key, ());
            }
        }
        let mut staged = WorldState::default();
        for key in accounts.keys() {
            if let Some(value) = state.accounts.get(*key) {
                staged.accounts.insert((*key).to_owned(), value.clone());
            }
        }
        for key in protocol.keys() {
            if let Some(value) = state.protocol.get(*key) {
                staged.protocol.insert((*key).to_owned(), value.clone());
            }
        }
        for diff in diffs {
            diff.apply(&mut staged)?;
        }
        // No fallible operation follows the first mutation. Move allocations
        // from the small write-set World; unrelated allocations remain intact.
        for (key, value) in staged.accounts {
            state.accounts.insert(key, value);
        }
        for key in protocol.keys() {
            state.protocol.remove(*key);
        }
        for (key, value) in staged.protocol {
            state.protocol.insert(key, value);
        }
        Ok(())
    }

    pub fn apply(&self, state: &mut WorldState) -> Result<(), StateError> {
        self.validate()?;
        // Stage only the write set. A late account/protocol failure must leave
        // the original world untouched, without cloning unrelated chain state.
        let mut accounts = Vec::with_capacity(self.changes.len());
        for change in &self.changes {
            let mut account = state
                .accounts
                .get(&change.account)
                .cloned()
                .unwrap_or_default();
            if let Some(nonce) = change.expected_nonce {
                account.consume_nonce(nonce)?;
            }
            account.debit(change.debit_nwei)?;
            account.credit(change.credit_nwei)?;
            if let Some(code_hash) = &change.code_hash {
                account.code_hash = code_hash.clone();
            }
            accounts.push((change.account.clone(), account));
        }
        for change in &self.protocol_changes {
            if state.protocol.get(&change.key) != change.expected_value.as_ref() {
                return Err(StateError::ProtocolValueMismatch(change.key.clone()));
            }
        }
        // All fallible validation precedes the first mutation. Duplicate keys
        // are rejected by validate(), so every precondition refers to the base.
        for (key, account) in accounts {
            state.accounts.insert(key, account);
        }
        for change in &self.protocol_changes {
            match &change.value {
                Some(value) => {
                    state.protocol.insert(change.key.clone(), value.clone());
                }
                None => {
                    state.protocol.remove(&change.key);
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AccountState;

    fn account_change(account: &str, debit: u128, credit: u128) -> AccountChange {
        AccountChange {
            account: account.into(),
            debit_nwei: debit,
            credit_nwei: credit,
            expected_nonce: Some(0),
            code_hash: None,
        }
    }

    #[test]
    fn ordered_action_and_fee_diff_failure_is_atomic_and_preserves_unrelated_allocations() {
        let mut world = WorldState::default();
        world.accounts.insert(
            "sender".into(),
            crate::AccountState {
                balance_nwei: 10,
                ..Default::default()
            },
        );
        world.protocol.insert("unrelated".into(), vec![4; 65536]);
        let pointer = world.protocol["unrelated"].as_ptr();
        let action = StateDiff {
            changes: vec![
                account_change("sender", 7, 0),
                AccountChange {
                    account: "receiver".into(),
                    debit_nwei: 0,
                    credit_nwei: 7,
                    expected_nonce: None,
                    code_hash: None,
                },
            ],
            ..Default::default()
        };
        let fee = StateDiff {
            changes: vec![AccountChange {
                account: "sender".into(),
                debit_nwei: 5,
                credit_nwei: 0,
                expected_nonce: None,
                code_hash: None,
            }],
            ..Default::default()
        };
        let original = world.clone();
        assert_eq!(
            StateDiff::apply_ordered_atomic(&[&action, &fee], &mut world),
            Err(StateError::InsufficientBalance)
        );
        assert_eq!(world, original);
        assert_eq!(pointer, world.protocol["unrelated"].as_ptr());
        let fee = StateDiff {
            changes: vec![AccountChange {
                debit_nwei: 3,
                ..fee.changes[0].clone()
            }],
            ..Default::default()
        };
        let mut expected = original.clone();
        action.apply(&mut expected).unwrap();
        fee.apply(&mut expected).unwrap();
        StateDiff::apply_ordered_atomic(&[&action, &fee], &mut world).unwrap();
        assert_eq!(world, expected);
        assert_eq!(pointer, world.protocol["unrelated"].as_ptr());
    }

    #[test]
    fn late_account_and_protocol_failures_leave_the_entire_world_unchanged() {
        let original = WorldState {
            accounts: BTreeMap::from([(
                "funded".into(),
                AccountState {
                    balance_nwei: 10,
                    ..AccountState::default()
                },
            )]),
            protocol: BTreeMap::from([("existing".into(), vec![1])]),
        };
        for diff in [
            StateDiff {
                changes: vec![account_change("funded", 1, 0), account_change("new", 1, 0)],
                ..StateDiff::default()
            },
            StateDiff {
                changes: vec![account_change("funded", 1, 0), account_change("new", 0, 1)],
                protocol_changes: vec![
                    ProtocolChange {
                        key: "new-protocol".into(),
                        expected_value: None,
                        value: Some(vec![2]),
                    },
                    ProtocolChange {
                        key: "existing".into(),
                        expected_value: Some(vec![9]),
                        value: None,
                    },
                ],
            },
        ] {
            let mut state = original.clone();
            assert!(diff.apply(&mut state).is_err());
            assert_eq!(state, original);
        }
    }

    #[test]
    fn successful_write_set_preserves_unrelated_allocations_and_canonical_state() {
        let mut world = WorldState::default();
        world.accounts.insert(
            "sender".into(),
            AccountState {
                balance_nwei: 100,
                ..AccountState::default()
            },
        );
        world.accounts.insert(
            "unrelated".into(),
            AccountState {
                code_hash: Some("keep-allocation".into()),
                ..AccountState::default()
            },
        );
        world
            .protocol
            .insert("unrelated".into(), vec![7; 1024 * 1024]);
        world.protocol.insert("remove".into(), vec![1]);
        let account_pointer = world.accounts["unrelated"]
            .code_hash
            .as_ref()
            .unwrap()
            .as_ptr();
        let protocol_pointer = world.protocol["unrelated"].as_ptr();
        let mut expected = world.clone();
        expected.accounts.get_mut("sender").unwrap().balance_nwei = 60;
        expected.accounts.get_mut("sender").unwrap().nonce = 1;
        expected.accounts.insert(
            "receiver".into(),
            AccountState {
                balance_nwei: 40,
                nonce: 1,
                code_hash: Some("contract".into()),
            },
        );
        expected.protocol.remove("remove");
        expected.protocol.insert("insert".into(), vec![2]);
        let mut receiver = account_change("receiver", 0, 40);
        receiver.code_hash = Some(Some("contract".into()));
        StateDiff {
            changes: vec![account_change("sender", 40, 0), receiver],
            protocol_changes: vec![
                ProtocolChange {
                    key: "remove".into(),
                    expected_value: Some(vec![1]),
                    value: None,
                },
                ProtocolChange {
                    key: "insert".into(),
                    expected_value: None,
                    value: Some(vec![2]),
                },
            ],
        }
        .apply(&mut world)
        .unwrap();
        assert_eq!(
            world.accounts["unrelated"]
                .code_hash
                .as_ref()
                .unwrap()
                .as_ptr(),
            account_pointer
        );
        assert_eq!(world.protocol["unrelated"].as_ptr(), protocol_pointer);
        assert_eq!(
            serde_json::to_vec(&world).unwrap(),
            serde_json::to_vec(&expected).unwrap()
        );
        assert_eq!(
            crate::state_root(&world).unwrap(),
            crate::state_root(&expected).unwrap()
        );
    }
}
