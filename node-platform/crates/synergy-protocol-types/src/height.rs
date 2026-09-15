//! Overflow-safe finalized-chain height.

use serde::{Deserialize, Serialize};

#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(transparent)]
pub struct Height(u64);

impl Height {
    pub const GENESIS: Self = Self(0);

    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    pub const fn get(self) -> u64 {
        self.0
    }

    pub fn checked_next(self) -> Result<Self, HeightOverflow> {
        self.0.checked_add(1).map(Self).ok_or(HeightOverflow)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HeightOverflow;

impl std::fmt::Display for HeightOverflow {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("height overflow")
    }
}

impl std::error::Error for HeightOverflow {}
