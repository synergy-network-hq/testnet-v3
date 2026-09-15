#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BackpressureThresholds {
    pub high_water_mark: usize,
    pub hard_limit: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackpressureState {
    Open,
    Throttled,
    Closed,
}

impl BackpressureThresholds {
    pub fn new(high_water_mark: usize, hard_limit: usize) -> Result<Self, super::QueueError> {
        if high_water_mark == 0 || hard_limit == 0 || high_water_mark >= hard_limit {
            return Err(super::QueueError::InvalidCapacity);
        }
        Ok(Self {
            high_water_mark,
            hard_limit,
        })
    }

    pub fn state(self, depth: usize) -> BackpressureState {
        if depth >= self.hard_limit {
            BackpressureState::Closed
        } else if depth >= self.high_water_mark {
            BackpressureState::Throttled
        } else {
            BackpressureState::Open
        }
    }
}
