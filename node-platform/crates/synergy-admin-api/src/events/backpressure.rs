#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EventBackpressure {
    pub high_water_mark: usize,
    pub capacity: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventBackpressureState {
    Open,
    Throttled,
    Full,
}

impl EventBackpressure {
    pub fn state(self, depth: usize) -> EventBackpressureState {
        if depth >= self.capacity {
            EventBackpressureState::Full
        } else if depth >= self.high_water_mark {
            EventBackpressureState::Throttled
        } else {
            EventBackpressureState::Open
        }
    }
}
