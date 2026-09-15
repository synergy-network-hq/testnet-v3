use crate::{BlockRequest, BlockResponse, SyncBlock};

pub trait FinalizedBlockSource {
    fn finalized_block(&self, height: u64) -> Result<Option<SyncBlock>, String>;
}

/// Serves only authenticated, bounded requests from the locally finalized
/// block store. Serving data does not establish finality.
pub fn respond_to_block_request(
    authenticated: bool,
    maximum_blocks: u64,
    request: BlockRequest,
    source: &impl FinalizedBlockSource,
) -> Result<BlockResponse, String> {
    if !authenticated || !request.validate() {
        return Err("unauthenticated or invalid block sync request".into());
    }
    let count = request
        .through_height
        .checked_sub(request.from_height)
        .and_then(|delta| delta.checked_add(1))
        .ok_or_else(|| "block sync range overflow".to_string())?;
    if count > maximum_blocks || maximum_blocks == 0 {
        return Err("block sync range exceeds responder limit".into());
    }
    let mut blocks = Vec::with_capacity(count as usize);
    let mut expected_parent = request.expected_parent_id.clone();
    for height in request.from_height..=request.through_height {
        let block = source
            .finalized_block(height)?
            .ok_or_else(|| format!("finalized block {height} unavailable"))?;
        if block.height != height || block.parent_id != expected_parent {
            return Err("finalized block source returned a discontinuous chain".into());
        }
        expected_parent = block.block_id.clone();
        blocks.push(block);
    }
    Ok(BlockResponse { request, blocks })
}
