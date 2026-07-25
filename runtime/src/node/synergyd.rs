use std::sync::{Arc, Mutex};
use std::thread;
use synergy_testnet::{block::Block, consensus, p2p, rpc};
use synergy_testnet::config::load_node_config;

/// Entry point for running a Synergy Network node.
fn main() {
    println!("🚀 Launching Synergy Node...");

    let config = match load_node_config("config/network-config.toml") {
        Ok(cfg) => cfg,
        Err(e) => {
            eprintln!("❌ Failed to load config: {}", e);
            return;
        }
    };

    // Initialize blockchain with genesis block
    let genesis_block = Block::new(
        0,
        "0".repeat(64),
        vec![],
        "genesis-validator".to_string(),
        0,
    );

    let blockchain = Arc::new(Mutex::new(vec![genesis_block]));

    // Launch Consensus Engine
    let consensus_chain = Arc::clone(&blockchain);
    let consensus_thread = thread::spawn(move || {
        consensus::run_consensus(consensus_chain);
    });

    // Launch P2P Network
    let p2p_chain = Arc::clone(&blockchain);
    let p2p_thread = thread::spawn(move || {
        p2p::start_p2p_network(p2p_chain, &config.p2p.listen_address);
    });

    // Launch RPC Server
    let rpc_thread = thread::spawn(move || {
        rpc::start_rpc_server(&config);
    });

    // Wait for all subsystems
    consensus_thread.join().unwrap();
    p2p_thread.join().unwrap();
    rpc_thread.join().unwrap();
}
