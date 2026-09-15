//! Monotonic progress-window stall assessment.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProgressSample {
    pub observed_at_millis: u64,
    pub progress: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StallPolicy {
    pub warning_after_millis: u64,
    pub critical_after_millis: u64,
}

impl StallPolicy {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.warning_after_millis == 0 || self.critical_after_millis <= self.warning_after_millis
        {
            return Err("stall policy requires 0 < warning < critical");
        }
        Ok(())
    }

    pub fn assess(
        &self,
        previous: ProgressSample,
        current: ProgressSample,
    ) -> Result<StallAssessment, &'static str> {
        self.validate()?;
        if current.observed_at_millis < previous.observed_at_millis
            || current.progress < previous.progress
        {
            return Err("progress samples must be monotonic");
        }
        if current.progress > previous.progress {
            return Ok(StallAssessment::Progressing);
        }
        let elapsed = current
            .observed_at_millis
            .checked_sub(previous.observed_at_millis)
            .ok_or("progress sample time underflow")?;
        if elapsed >= self.critical_after_millis {
            Ok(StallAssessment::Critical)
        } else if elapsed >= self.warning_after_millis {
            Ok(StallAssessment::Warning)
        } else {
            Ok(StallAssessment::WithinWindow)
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StallAssessment {
    Progressing,
    WithinWindow,
    Warning,
    Critical,
}
