use std::collections::BTreeSet;
#[derive(Default)]
pub struct SimSentry {
    allowed: BTreeSet<String>,
    pub forwarded: u64,
    pub dropped: u64,
}
impl SimSentry {
    pub fn allow(&mut self, node: impl Into<String>) {
        self.allowed.insert(node.into());
    }
    pub fn forward(&mut self, node: &str, frame: &[u8], max: usize) -> Result<Vec<u8>, String> {
        if !self.allowed.contains(node) || frame.is_empty() || frame.len() > max {
            self.dropped += 1;
            return Err("sentry policy rejected frame".into());
        }
        self.forwarded += 1;
        Ok(frame.to_vec())
    }
}
