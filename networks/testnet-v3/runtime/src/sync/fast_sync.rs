use std::sync::{Arc, Mutex};

use crate::block::{Block, BlockChain, BlockHeader};

/// Fast sync helpers: read headers/blocks from the local store.
pub fn download_headers(
    blockchain: &Arc<Mutex<BlockChain>>,
    start: u64,
    end: u64,
) -> Vec<BlockHeader> {
    let chain = blockchain.lock().unwrap();
    chain
        .chain
        .iter()
        .filter(|block| block.block_index >= start && block.block_index <= end)
        .map(|block| block.header())
        .collect()
}

/// Collect block bodies that belong to the requested headers.
pub fn download_block_bodies(
    blockchain: &Arc<Mutex<BlockChain>>,
    headers: &[BlockHeader],
) -> Vec<Block> {
    let chain = blockchain.lock().unwrap();
    headers
        .iter()
        .filter_map(|header| {
            chain
                .chain
                .iter()
                .find(|block| block.block_index == header.number)
                .cloned()
        })
        .collect()
}
