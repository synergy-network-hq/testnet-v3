#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SynqTraceEvent {
    ExecutionStarted {
        artifact_hash: String,
        block_height: u64,
        transaction_index: u32,
        gas_limit: u64,
    },
    HostCall {
        operation: String,
        gas_used: u64,
    },
    ExecutionFinished {
        gas_used: u64,
        events: u32,
    },
    ExecutionRejected {
        reason: String,
    },
}

pub trait SynqTraceSink {
    fn record(&mut self, event: SynqTraceEvent);
}

#[derive(Debug, Default)]
pub struct NoopSynqTrace;

impl SynqTraceSink for NoopSynqTrace {
    fn record(&mut self, _event: SynqTraceEvent) {}
}
