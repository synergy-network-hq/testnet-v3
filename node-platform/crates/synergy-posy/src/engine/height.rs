#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct ConsensusHeight(pub u64);

impl ConsensusHeight {
    pub fn next(self) -> Option<Self> {
        self.0.checked_add(1).map(Self)
    }
}
