#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TraceSpan {
    pub trace_id: String,
    pub span_id: String,
    pub parent_span_id: Option<String>,
    pub subsystem: String,
    pub started_at_ms: u64,
}

impl TraceSpan {
    pub fn validate(&self) -> Result<(), String> {
        if self.trace_id.trim().is_empty()
            || self.span_id.trim().is_empty()
            || self.subsystem.trim().is_empty()
            || self
                .parent_span_id
                .as_ref()
                .is_some_and(|id| id.trim().is_empty())
        {
            return Err("invalid trace span".into());
        }
        Ok(())
    }
}
