use super::BlockRequest;

/// Bounded retry policy for one immutable block request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetryPolicy {
    pub max_attempts: u32,
    pub base_delay_ms: u64,
    pub max_delay_ms: u64,
}

/// Result of registering a failed request attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetryDecision {
    RetryAt { attempt: u32, not_before_ms: u64 },
    Exhausted { attempts: u32 },
}

/// Invalid retry configuration or timestamp arithmetic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RetryError {
    InvalidPolicy,
    InvalidRequest,
    TimeOverflow,
}

/// Tracks retries without widening or changing the anchored request.
#[derive(Debug, Clone)]
pub struct RetryTracker {
    request: BlockRequest,
    policy: RetryPolicy,
    attempts: u32,
}

impl RetryTracker {
    /// Creates a retry budget for one validated request.
    ///
    /// # Errors
    /// Rejects invalid requests or zero/inverted retry limits.
    pub fn new(policy: RetryPolicy, request: BlockRequest) -> Result<Self, RetryError> {
        if !request.validate() {
            return Err(RetryError::InvalidRequest);
        }
        if policy.max_attempts == 0
            || policy.base_delay_ms == 0
            || policy.max_delay_ms < policy.base_delay_ms
        {
            return Err(RetryError::InvalidPolicy);
        }
        Ok(Self {
            request,
            policy,
            attempts: 0,
        })
    }

    /// Records a failed attempt and returns a bounded deterministic decision.
    ///
    /// # Errors
    /// Returns [`RetryError::TimeOverflow`] if the deadline cannot be represented.
    pub fn register_failure(&mut self, now_ms: u64) -> Result<RetryDecision, RetryError> {
        self.attempts = self
            .attempts
            .checked_add(1)
            .ok_or(RetryError::TimeOverflow)?;
        if self.attempts >= self.policy.max_attempts {
            return Ok(RetryDecision::Exhausted {
                attempts: self.attempts,
            });
        }
        let exponent = self.attempts.saturating_sub(1).min(63);
        let multiplier = 1_u64.checked_shl(exponent).unwrap_or(u64::MAX);
        let delay = self
            .policy
            .base_delay_ms
            .saturating_mul(multiplier)
            .min(self.policy.max_delay_ms);
        let not_before_ms = now_ms.checked_add(delay).ok_or(RetryError::TimeOverflow)?;
        Ok(RetryDecision::RetryAt {
            attempt: self.attempts,
            not_before_ms,
        })
    }

    /// Returns the immutable request governed by this retry budget.
    pub const fn request(&self) -> &BlockRequest {
        &self.request
    }

    /// Returns the number of failed attempts recorded.
    pub const fn attempts(&self) -> u32 {
        self.attempts
    }
}
