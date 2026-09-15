//! Process/service liveness is distinct from readiness.

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Liveness {
    Alive,
    Unresponsive { reason: String },
    Stopped,
}

impl Liveness {
    pub const fn is_alive(&self) -> bool {
        matches!(self, Self::Alive)
    }
}
