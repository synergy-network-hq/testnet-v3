use super::{BlockImportReceipt, BlockRequest};

/// Invalid scheduler state or request transition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlockScheduleError {
    InvalidAnchor,
    InvalidBatchLimit,
    RequestInFlight,
    NothingToSchedule,
    ReceiptMismatch,
    HeightOverflow,
}

/// Produces one bounded anchored request at a time.
#[derive(Debug, Clone)]
pub struct BlockScheduler {
    next_height: u64,
    parent_id: String,
    max_blocks_per_request: u64,
    in_flight: Option<BlockRequest>,
}

impl BlockScheduler {
    /// Creates a scheduler anchored at the next missing height.
    ///
    /// # Errors
    /// Rejects height zero, an empty parent commitment, or a zero batch limit.
    pub fn new(
        next_height: u64,
        parent_id: impl Into<String>,
        max_blocks_per_request: u64,
    ) -> Result<Self, BlockScheduleError> {
        let parent_id = parent_id.into();
        if next_height == 0 || parent_id.trim().is_empty() {
            return Err(BlockScheduleError::InvalidAnchor);
        }
        if max_blocks_per_request == 0 {
            return Err(BlockScheduleError::InvalidBatchLimit);
        }
        Ok(Self {
            next_height,
            parent_id,
            max_blocks_per_request,
            in_flight: None,
        })
    }

    /// Schedules the next bounded request through an already verified target.
    ///
    /// # Errors
    /// Fails if another request is active, the target is behind, or arithmetic
    /// would overflow.
    pub fn schedule(&mut self, verified_target: u64) -> Result<&BlockRequest, BlockScheduleError> {
        if self.in_flight.is_some() {
            return Err(BlockScheduleError::RequestInFlight);
        }
        if self.next_height > verified_target {
            return Err(BlockScheduleError::NothingToSchedule);
        }
        let inclusive_span = self
            .max_blocks_per_request
            .checked_sub(1)
            .ok_or(BlockScheduleError::InvalidBatchLimit)?;
        let bounded_end = self
            .next_height
            .checked_add(inclusive_span)
            .ok_or(BlockScheduleError::HeightOverflow)?;
        self.in_flight = Some(BlockRequest {
            from_height: self.next_height,
            through_height: bounded_end.min(verified_target),
            expected_parent_id: self.parent_id.clone(),
        });
        self.in_flight
            .as_ref()
            .ok_or(BlockScheduleError::ReceiptMismatch)
    }

    /// Advances the anchor after a matching durable import receipt.
    ///
    /// # Errors
    /// Rejects receipts that do not exactly match the scheduled request.
    pub fn commit(&mut self, receipt: &BlockImportReceipt) -> Result<(), BlockScheduleError> {
        let Some(request) = self.in_flight.as_ref() else {
            return Err(BlockScheduleError::ReceiptMismatch);
        };
        if receipt.from_height != request.from_height
            || receipt.through_height > request.through_height
            || receipt.through_height < receipt.from_height
            || receipt.imported_blocks as u64 != receipt.through_height - receipt.from_height + 1
            || receipt.last_block_id.trim().is_empty()
        {
            return Err(BlockScheduleError::ReceiptMismatch);
        }
        self.next_height = receipt
            .through_height
            .checked_add(1)
            .ok_or(BlockScheduleError::HeightOverflow)?;
        self.parent_id = receipt.last_block_id.clone();
        self.in_flight = None;
        Ok(())
    }

    /// Clears an uncommitted request so the same range can be retried.
    pub fn cancel_in_flight(&mut self) -> Option<BlockRequest> {
        self.in_flight.take()
    }

    /// Returns the next height that remains to be imported.
    pub const fn next_height(&self) -> u64 {
        self.next_height
    }
}
