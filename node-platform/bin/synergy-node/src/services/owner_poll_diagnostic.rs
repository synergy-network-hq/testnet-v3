//! Opt-in, bounded operation timings only; never participates in service decisions.
use std::{
    cell::RefCell,
    time::{Duration, Instant},
};

struct Limit {
    enabled: bool,
    started: Instant,
    last: Instant,
    previous: Instant,
    rows: usize,
}
thread_local! { static LIMIT: RefCell<Limit> = RefCell::new({
    let now = Instant::now();
    Limit { enabled: std::env::var_os("SYNERGY_SYNC_POLL_DIAGNOSTIC").is_some_and(|v| v == "1"),
        started: now, last: now, previous: now, rows: 0 }
}); }

pub(super) struct PollTrace {
    owner: &'static str,
    start: Instant,
    previous: Instant,
    stages: Vec<(&'static str, u128)>,
    enabled: bool,
    gap: Duration,
}
impl PollTrace {
    pub(super) fn new(owner: &'static str) -> Self {
        let now = Instant::now();
        let (enabled, gap) = LIMIT.with(|limit| {
            let mut limit = limit.borrow_mut();
            let gap = now.saturating_duration_since(limit.previous);
            limit.previous = now;
            (
                limit.enabled
                    && limit.rows < 7200
                    && now.duration_since(limit.started) < Duration::from_secs(1800),
                gap,
            )
        });
        Self {
            owner,
            start: now,
            previous: now,
            stages: if enabled {
                Vec::with_capacity(16)
            } else {
                Vec::new()
            },
            enabled,
            gap,
        }
    }
    pub(super) fn completed(&mut self, stage: &'static str) {
        if !self.enabled {
            return;
        }
        let now = Instant::now();
        if self.stages.len() < 32 {
            self.stages
                .push((stage, now.duration_since(self.previous).as_micros()));
        }
        self.previous = now;
    }
}
impl Drop for PollTrace {
    fn drop(&mut self) {
        if !self.enabled {
            return;
        }
        let now = Instant::now();
        let elapsed = now.duration_since(self.start);
        LIMIT.with(|limit| {
            let mut limit = limit.borrow_mut();
            if limit.rows >= 7200 || now.duration_since(limit.started) >= Duration::from_secs(1800)
                || (elapsed < Duration::from_millis(100) && now.duration_since(limit.last) < Duration::from_millis(250)) { return; }
            limit.last = now; limit.rows += 1;
            eprintln!("OWNER_POLL_DIAGNOSTIC {}", serde_json::json!({
                "owner": self.owner, "elapsed_us": now.duration_since(limit.started).as_micros(),
                "poll_us": elapsed.as_micros(), "start_gap_us": self.gap.as_micros(),
                "stages_us": self.stages, "tail_us": now.duration_since(self.previous).as_micros()
            }));
        });
    }
}
