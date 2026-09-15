#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PeerScore(i32);

impl PeerScore {
    pub const MIN: i32 = -1_000;
    pub const MAX: i32 = 1_000;

    pub fn value(self) -> i32 {
        self.0
    }

    pub fn adjust(&mut self, delta: i32) {
        self.0 = self.0.saturating_add(delta).clamp(Self::MIN, Self::MAX);
    }
}
