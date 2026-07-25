use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::Mutex;
use log::{info, error};
use crate::network::NetworkService;
use crate::crypto::CryptoService;
use crate::consensus::ConsensusService;
use crate::rpc::RpcService;
use crate::storage::StorageService;

pub struct Node {
    node_id: String,
    node_type: String,
    network_id: u64,
    p2p_port: u16,
    rpc_port: u16,
    data_dir: PathBuf,
    network_service: NetworkService,
    crypto_service: CryptoService,
    consensus_service: ConsensusService,
    rpc_service: RpcService,
    storage_service: StorageService,
    is_running: bool,
}

impl Node {
    pub async fn new(
        node_id: String,
        node_type: String,
        network_id: u64,
        p2p_port: u16,
        rpc_port: u16,
        data_dir: PathBuf,
        network_service: NetworkService,
        crypto_service: CryptoService,
    ) -> Result<Self, String> {
        Ok(Self {
            node_id: node_id.clone(),
            node_type: node_type.clone(),
            network_id,
            p2p_port,
            rpc_port,
            data_dir: data_dir.clone(),
            network_service,
            crypto_service,
            consensus_service: ConsensusService::new(node_type),
            rpc_service: RpcService::new(rpc_port),
            storage_service: StorageService::new(data_dir),
            is_running: false,
        })
    }

    pub async fn start(&mut self) -> Result<(), String> {
        if self.is_running {
            return Err("Node is already running".to_string());
        }

        info!("Starting node {} of type {}", self.node_id, self.node_type);

        // Initialize data directory
        std::fs::create_dir_all(&self.data_dir)
            .map_err(|e| format!("Failed to create data directory: {}", e))?;

        // Start storage service
        self.storage_service.start().await?;

        // Start network service
        self.network_service.start().await?;

        // Initialize crypto
        self.crypto_service.initialize().await?;

        // Start consensus service
        self.consensus_service.start().await?;

        // Start RPC service
        self.rpc_service.start().await?;

        self.is_running = true;
        info!("Node {} started successfully", self.node_id);

        Ok(())
    }

    pub async fn stop(&mut self) -> Result<(), String> {
        if !self.is_running {
            return Err("Node is not running".to_string());
        }

        info!("Stopping node {}", self.node_id);

        // Stop RPC service
        self.rpc_service.stop().await?;

        // Stop consensus service
        self.consensus_service.stop().await?;

        // Stop network service
        self.network_service.stop().await?;

        // Stop storage service
        self.storage_service.stop().await?;

        self.is_running = false;
        info!("Node {} stopped successfully", self.node_id);

        Ok(())
    }

    pub fn is_running(&self) -> bool {
        self.is_running
    }

    pub fn get_node_id(&self) -> &str {
        &self.node_id
    }

    pub fn get_node_type(&self) -> &str {
        &self.node_type
    }
}