use std::collections::BTreeMap;

use crate::EtdagError;

#[derive(Debug, Clone)]
pub struct IngressRateLimiter {
    window_millis: u64,
    maximum_per_window: u32,
    senders: BTreeMap<String, SenderWindow>,
}

#[derive(Debug, Clone, Copy)]
struct SenderWindow {
    window: u64,
    count: u32,
}

impl IngressRateLimiter {
    pub fn new(window_millis: u64, maximum_per_window: u32) -> Result<Self, EtdagError> {
        if window_millis == 0 || maximum_per_window == 0 {
            return Err(EtdagError::InvalidCapacity);
        }
        Ok(Self {
            window_millis,
            maximum_per_window,
            senders: BTreeMap::new(),
        })
    }

    pub fn check(&self, sender: &str, now_millis: u64) -> Result<(), EtdagError> {
        let window = now_millis / self.window_millis;
        if self
            .senders
            .get(sender)
            .is_some_and(|state| state.window == window && state.count >= self.maximum_per_window)
        {
            Err(EtdagError::RateLimited)
        } else {
            Ok(())
        }
    }

    pub fn record(&mut self, sender: &str, now_millis: u64) {
        let window = now_millis / self.window_millis;
        let state = self
            .senders
            .entry(sender.into())
            .or_insert(SenderWindow { window, count: 0 });
        if state.window != window {
            *state = SenderWindow { window, count: 0 };
        }
        state.count = state.count.saturating_add(1);
    }
}
