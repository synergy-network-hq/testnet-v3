use crate::{BlockRequest, StateCheckpoint};

/// Current bounded recovery phase.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncPhase {
    CollectingHeads,
    SchedulingBlocks,
    ImportingBlocks,
    DownloadingState,
    VerifyingState,
    ImportingState,
    Complete,
    Failed,
}

/// Read-only synchronization status for operators and metrics adapters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncStatus {
    pub phase: SyncPhase,
    pub local_finalized_height: u64,
    pub verified_target_height: Option<u64>,
    pub active_block_request: Option<BlockRequest>,
    pub checkpoint_id: Option<String>,
    pub received_chunks: u64,
    pub total_chunks: u64,
    pub retry_attempts: u32,
    pub last_error: Option<String>,
}

impl SyncStatus {
    /// Creates a status that has not yet accepted a verified network head.
    pub fn collecting(local_finalized_height: u64) -> Self {
        Self {
            phase: SyncPhase::CollectingHeads,
            local_finalized_height,
            verified_target_height: None,
            active_block_request: None,
            checkpoint_id: None,
            received_chunks: 0,
            total_chunks: 0,
            retry_attempts: 0,
            last_error: None,
        }
    }

    /// Records a selected caller-verified synchronization target.
    pub fn select_target(&mut self, height: u64) {
        self.verified_target_height = Some(height);
        self.phase = SyncPhase::SchedulingBlocks;
    }

    /// Records the immutable block request currently in flight.
    pub fn begin_block_request(&mut self, request: &BlockRequest) {
        self.active_block_request = Some(request.clone());
        self.phase = SyncPhase::ImportingBlocks;
    }

    /// Records a state checkpoint and resets per-checkpoint progress.
    pub fn begin_state_download(&mut self, checkpoint: &StateCheckpoint) {
        self.checkpoint_id = Some(checkpoint.checkpoint_id.clone());
        self.received_chunks = 0;
        self.total_chunks = checkpoint.chunk_count;
        self.phase = SyncPhase::DownloadingState;
    }

    /// Updates progress without allowing received count to exceed the manifest.
    pub fn record_received_chunks(&mut self, received: u64) {
        self.received_chunks = received.min(self.total_chunks);
    }

    /// Records a terminal failure without changing finality or signer authority.
    pub fn fail(&mut self, message: impl Into<String>) {
        self.phase = SyncPhase::Failed;
        self.last_error = Some(message.into());
    }

    /// Marks recovery complete at a caller-verified finalized height.
    pub fn complete(&mut self, finalized_height: u64) {
        self.phase = SyncPhase::Complete;
        self.local_finalized_height = finalized_height;
        self.active_block_request = None;
        self.last_error = None;
    }

    /// Status reporting never grants consensus authority.
    pub const fn may_determine_finality(&self) -> bool {
        false
    }
}
