use std::fmt;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeLifecycleState {
    Uninitialized,
    Configured,
    Starting,
    Shadowing,
    Ready,
    Active,
    Stopping,
    Stopped,
    Degraded,
    Failed,
}

impl NodeLifecycleState {
    pub fn permits(self, next: Self) -> bool {
        matches!(
            (self, next),
            (Self::Uninitialized, Self::Configured)
                | (Self::Configured, Self::Starting)
                | (
                    Self::Starting,
                    Self::Shadowing | Self::Ready | Self::Degraded | Self::Failed | Self::Stopping
                )
                | (
                    Self::Shadowing,
                    Self::Ready | Self::Degraded | Self::Stopping | Self::Failed
                )
                | (
                    Self::Ready,
                    Self::Active | Self::Degraded | Self::Stopping | Self::Failed
                )
                | (Self::Active, Self::Degraded | Self::Stopping | Self::Failed)
                | (
                    Self::Degraded,
                    Self::Starting | Self::Stopping | Self::Failed
                )
                | (Self::Stopping, Self::Stopped | Self::Failed)
                | (Self::Stopped, Self::Starting)
                | (Self::Failed, Self::Starting | Self::Stopping)
        )
    }
}

/// Refuses lifecycle jumps that would bypass initialization, readiness, or draining.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct LifecycleController {
    state: NodeLifecycleState,
}

impl LifecycleController {
    pub fn new() -> Self {
        Self {
            state: NodeLifecycleState::Uninitialized,
        }
    }

    pub fn state(&self) -> NodeLifecycleState {
        self.state
    }

    pub fn transition(&mut self, next: NodeLifecycleState) -> Result<(), LifecycleTransitionError> {
        if !self.state.permits(next) {
            return Err(LifecycleTransitionError {
                current: self.state,
                requested: next,
            });
        }
        self.state = next;
        Ok(())
    }
}

impl Default for LifecycleController {
    fn default() -> Self {
        Self::new()
    }
}

/// An attempted lifecycle transition that violates the canonical state graph.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LifecycleTransitionError {
    pub current: NodeLifecycleState,
    pub requested: NodeLifecycleState,
}

impl fmt::Display for LifecycleTransitionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "lifecycle transition from {:?} to {:?} is not permitted",
            self.current, self.requested
        )
    }
}

impl std::error::Error for LifecycleTransitionError {}
