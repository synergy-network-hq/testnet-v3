use std::collections::{BTreeMap, BTreeSet, VecDeque};
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    pub from: String,
    pub to: String,
    pub payload: Vec<u8>,
    pub deliver_at: u64,
}
#[derive(Default)]
pub struct VirtualNetwork {
    links: BTreeSet<(String, String)>,
    queue: VecDeque<Message>,
    blocked: BTreeSet<(String, String)>,
    latency: BTreeMap<(String, String), u64>,
}
impl VirtualNetwork {
    pub fn connect(&mut self, a: &str, b: &str) {
        self.links.insert((a.into(), b.into()));
        self.links.insert((b.into(), a.into()));
    }
    pub fn block(&mut self, a: &str, b: &str) {
        self.blocked.insert((a.into(), b.into()));
    }
    pub fn heal(&mut self) {
        self.blocked.clear();
    }
    pub fn set_latency(&mut self, a: &str, b: &str, ms: u64) {
        self.latency.insert((a.into(), b.into()), ms);
    }
    pub fn send(&mut self, from: &str, to: &str, payload: Vec<u8>, now: u64) -> Result<(), String> {
        let edge = (from.to_string(), to.to_string());
        if !self.links.contains(&edge) || self.blocked.contains(&edge) {
            return Err("network path unavailable".into());
        }
        let delay = *self.latency.get(&edge).unwrap_or(&0);
        self.queue.push_back(Message {
            from: from.into(),
            to: to.into(),
            payload,
            deliver_at: now.saturating_add(delay),
        });
        Ok(())
    }
    pub fn deliver(&mut self, now: u64) -> Vec<Message> {
        let mut out = Vec::new();
        let mut pending = VecDeque::new();
        while let Some(m) = self.queue.pop_front() {
            if m.deliver_at <= now {
                out.push(m)
            } else {
                pending.push_back(m)
            }
        }
        self.queue = pending;
        out
    }
}
