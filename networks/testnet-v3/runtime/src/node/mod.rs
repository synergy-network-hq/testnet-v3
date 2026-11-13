use crate::block::{Block, BlockChain};
use crate::transaction::Transaction;
use std::fs;
use std::path::PathBuf;

/// Initializes and returns the blockchain with a genesis block.
pub fn initialize_blockchain() -> BlockChain {
    let mut chain = BlockChain::new();
    chain
        .genesis()
        .expect("failed to initialize blockchain from canonical genesis");
    chain
}

/// Creates and adds a new block from transactions.
pub fn generate_new_block(chain: &mut BlockChain, transactions: Vec<Transaction>) -> Block {
    let previous_block = chain
        .last()
        .expect("Blockchain must have at least the genesis block");

    let new_block = Block::new(
        previous_block.block_index + 1,
        transactions,
        previous_block.hash.clone(),
        "validator-0001".to_string(),
        previous_block.nonce + 1,
    );

    chain.add_block(new_block.clone());
    new_block
}

/// Saves the blockchain state to a file (basic JSON serialization).
pub fn save_blockchain(chain: &BlockChain, path: &str) {
    let serialized = serde_json::to_string_pretty(&chain.chain).expect("Failed to serialize chain");
    fs::write(PathBuf::from(path), serialized).expect("Unable to write file");
}

/// Loads blockchain state from a file (basic JSON deserialization).
pub fn load_blockchain(path: &str) -> Option<BlockChain> {
    if let Ok(data) = fs::read_to_string(PathBuf::from(path)) {
        if let Ok(blocks) = serde_json::from_str::<Vec<Block>>(&data) {
            let mut chain = BlockChain::new();
            for block in blocks {
                chain.add_block(block);
            }
            return Some(chain);
        }
    }
    None
}
