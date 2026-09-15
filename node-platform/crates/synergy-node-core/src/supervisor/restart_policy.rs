use serde::{Deserialize, Serialize};

/// Bounded recovery policy for one supervised service.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "mode")]
pub enum RestartPolicy {
    Never,
    OnFailure { max_attempts: u16 },
    Always { max_attempts: u16 },
}

impl RestartPolicy {
    pub fn permits(self, attempts: u16, failed: bool) -> bool {
        match self {
            Self::Never => false,
            Self::OnFailure { max_attempts } => failed && attempts < max_attempts,
            Self::Always { max_attempts } => attempts < max_attempts,
        }
    }
}
