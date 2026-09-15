//! Overflow-safe consensus epoch number.

use serde::{Deserialize, Serialize};

#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(transparent)]
pub struct Epoch(u64);

impl Epoch {
    pub const GENESIS: Self = Self(0);

    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    pub const fn get(self) -> u64 {
        self.0
    }

    pub fn checked_next(self) -> Result<Self, EpochOverflow> {
        self.0.checked_add(1).map(Self).ok_or(EpochOverflow)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EpochOverflow;

impl std::fmt::Display for EpochOverflow {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("epoch overflow")
    }
}

impl std::error::Error for EpochOverflow {}
