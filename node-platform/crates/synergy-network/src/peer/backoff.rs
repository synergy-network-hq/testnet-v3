#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BackoffPolicy {
    pub base_delay_secs: u64,
    pub max_delay_secs: u64,
    pub max_failures: u32,
}

impl BackoffPolicy {
    pub fn validate(self) -> Result<Self, super::ConnectionLimitError> {
        if self.base_delay_secs == 0
            || self.max_delay_secs < self.base_delay_secs
            || self.max_failures == 0
        {
            return Err(super::ConnectionLimitError::InvalidConfiguration);
        }
        Ok(self)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PeerBackoff {
    pub failures: u32,
    pub retry_at: Option<u64>,
}

impl PeerBackoff {
    pub fn record_failure(
        &mut self,
        now: u64,
        policy: BackoffPolicy,
    ) -> Result<u64, super::ConnectionLimitError> {
        let policy = policy.validate()?;
        self.failures = self.failures.saturating_add(1).min(policy.max_failures);
        let shift = self.failures.saturating_sub(1).min(31);
        let delay = policy
            .base_delay_secs
            .checked_mul(1u64 << shift)
            .unwrap_or(policy.max_delay_secs)
            .min(policy.max_delay_secs);
        let retry_at = now.saturating_add(delay);
        self.retry_at = Some(retry_at);
        Ok(retry_at)
    }

    pub fn reset(&mut self) {
        *self = Self::default();
    }

    pub fn permits(&self, now: u64) -> bool {
        self.retry_at.is_none_or(|retry_at| now >= retry_at)
    }
}
