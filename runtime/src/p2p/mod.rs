//! Synergy Network P2P Module
//!
//! This module handles peer-to-peer networking for the Synergy Network,
//! including peer discovery, block synchronization, and transaction propagation.

pub mod messages;
pub mod networking;
pub(crate) mod validator_transport_registry;

use self::networking::P2PNetwork;
use crate::block::BlockChain;
use crate::config::NodeConfig;
use lazy_static::lazy_static;
use std::sync::Arc;
use std::sync::Mutex;

lazy_static! {
    static ref GLOBAL_P2P_NETWORK: Mutex<Option<Arc<P2PNetwork>>> = Mutex::new(None);
}

/// Returns the global P2P network handle if the node started P2P.
pub fn get_p2p_network() -> Option<Arc<P2PNetwork>> {
    GLOBAL_P2P_NETWORK
        .lock()
        .ok()
        .and_then(|guard| guard.as_ref().map(Arc::clone))
}

fn set_p2p_network(network: Arc<P2PNetwork>) {
    if let Ok(mut guard) = GLOBAL_P2P_NETWORK.lock() {
        *guard = Some(network);
    }
}

pub fn start_p2p_network(
    blockchain: Arc<std::sync::Mutex<BlockChain>>,
    listen_address: &str,
    config: &NodeConfig,
) -> Arc<P2PNetwork> {
    let mut network = P2PNetwork::new(blockchain, config);
    network.start(listen_address);
    let network = Arc::new(network);

    // Make it available to other subsystems (RPC/consensus) for gossip/broadcast.
    set_p2p_network(Arc::clone(&network));

    // Kick off bootnode connect + periodic peer discovery / sync.
    network.start_bootstrap();

    network
}
