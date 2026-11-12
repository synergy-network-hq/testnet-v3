use std::borrow::Cow;

use crate::{StateDiff, StateError, WorldState};

/// Isolated speculative execution state. Only a caller holding a verified
/// finalization may persist its root through FinalizedStateStore.
#[derive(Debug, Clone)]
pub struct StateOverlay<'a> {
    base: Cow<'a, WorldState>,
    staged: WorldState,
}

impl<'a> StateOverlay<'a> {
    pub fn new(base: WorldState) -> Self {
        Self {
            staged: base.clone(),
            base: Cow::Owned(base),
        }
    }

    /// The caller already retains the immutable parent. Only the speculative
    /// state needs an owned copy; rollback simply drops that copy.
    pub fn from_base(base: &'a WorldState) -> Self {
        Self {
            base: Cow::Borrowed(base),
            staged: base.clone(),
        }
    }

    pub fn apply(&mut self, diff: &StateDiff) -> Result<(), StateError> {
        diff.apply(&mut self.staged)
    }

    pub fn apply_ordered_atomic(&mut self, diffs: &[&StateDiff]) -> Result<(), StateError> {
        StateDiff::apply_ordered_atomic(diffs, &mut self.staged)
    }

    pub fn staged(&self) -> &WorldState {
        &self.staged
    }

    pub fn into_staged(self) -> WorldState {
        self.staged
    }

    pub fn discard(self) -> WorldState {
        self.base.into_owned()
    }

    pub const fn may_determine_finality(&self) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ProtocolChange;

    #[test]
    fn borrowed_overlay_isolates_rollback_and_moves_successful_state_without_copying() {
        let mut base = WorldState::default();
        base.protocol.insert("value".into(), vec![3; 1024 * 1024]);
        let mut overlay = StateOverlay::from_base(&base);
        overlay
            .apply(&StateDiff {
                changes: vec![],
                protocol_changes: vec![ProtocolChange {
                    key: "new".into(),
                    expected_value: None,
                    value: Some(vec![4]),
                }],
            })
            .unwrap();
        assert!(!base.protocol.contains_key("new"));
        let allocation = overlay.staged().protocol["value"].as_ptr();
        let result = overlay.into_staged();
        assert_eq!(result.protocol["value"].as_ptr(), allocation);
        assert_eq!(result.protocol["new"], vec![4]);
        assert_eq!(StateOverlay::from_base(&base).discard(), base);
    }
}
