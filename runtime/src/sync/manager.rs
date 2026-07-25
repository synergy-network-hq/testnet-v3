use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use crate::block::{Block, BlockChain};
use crate::genesis::canonical_genesis;
use crate::p2p::networking::{P2PNetwork, PeerSnapshot};
use crate::sync::fast_sync;
use crate::sync::validation;

const SYNC_RECONCILIATION_LOOKBACK: u64 = 8;
const SYNC_PROGRESS_OVERLAP: u64 = 2;
const MAX_SYNC_BATCH_BLOCKS: u64 = 48;

fn resolve_local_genesis_hash(blockchain: &Arc<Mutex<BlockChain>>) -> String {
    let canonical = canonical_genesis()
        .map(|genesis| genesis.hash().to_string())
        .unwrap_or_default();
    if !canonical.trim().is_empty() {
        return canonical;
    }

    blockchain
        .lock()
        .ok()
        .and_then(|chain| chain.get_genesis_hash())
        .unwrap_or_default()
}

/// Represents where the sync engine currently is in the lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncState {
    Idle,
    Discovering,
    Downloading,
    Validating,
    Applying,
    Synced,
}

/// Snapshot of sync progress for reporting and RPC.
#[derive(Debug, Clone)]
pub struct SyncProgress {
    pub starting_block: u64,
    pub current_block: u64,
    pub highest_block: u64,
}

impl SyncProgress {
    fn new(starting_block: u64, highest_block: u64) -> Self {
        SyncProgress {
            starting_block,
            current_block: starting_block,
            highest_block,
        }
    }

    fn percentage(&self) -> f64 {
        if self.highest_block == self.starting_block {
            return 100.0;
        }
        let range = self.highest_block.saturating_sub(self.starting_block) as f64;
        let completed = self.current_block.saturating_sub(self.starting_block) as f64;
        if range == 0.0 {
            100.0
        } else {
            (completed / range * 100.0).min(100.0)
        }
    }
}

/// Sync manager errors represent recoverable conditions that should be surfaced via logs.
#[derive(Debug)]
pub enum SyncError {
    NetworkUnavailable,
    NoPeers,
    NoSupportSyncSources,
    SyncSourceUnavailable {
        peer: String,
        requested_height: u64,
    },
    SourceHistoryUnavailable {
        peer: String,
        requested_height: u64,
        reason: String,
    },
    Timeout(String),
    MissingBlock(u64),
    InvalidParentHash {
        height: u64,
        expected: String,
        got: String,
    },
    InvalidTransactionsRoot,
    BlockValidationFailed(String),
}

impl fmt::Display for SyncError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SyncError::NetworkUnavailable => write!(f, "P2P network unavailable"),
            SyncError::NoPeers => write!(f, "No peers available for sync"),
            SyncError::NoSupportSyncSources => write!(
                f,
                "No eligible support/history sync sources available; refusing canonical validator fanout"
            ),
            SyncError::SyncSourceUnavailable {
                peer,
                requested_height,
            } => write!(
                f,
                "Selected sync source {} is unavailable for requested height {}",
                peer, requested_height
            ),
            SyncError::SourceHistoryUnavailable {
                peer,
                requested_height,
                reason,
            } => write!(
                f,
                "Selected sync source {} cannot serve requested next block {}: {}",
                peer, requested_height, reason
            ),
            SyncError::Timeout(reason) => write!(f, "Timeout waiting for {}", reason),
            SyncError::MissingBlock(height) => write!(f, "Missing block at height {}", height),
            SyncError::InvalidParentHash {
                height,
                expected,
                got,
            } => write!(
                f,
                "Header at {} points to {}, expected {}",
                height, got, expected
            ),
            SyncError::InvalidTransactionsRoot => write!(f, "Computed transaction root mismatched"),
            SyncError::BlockValidationFailed(reason) => {
                write!(f, "Block validation failed: {}", reason)
            }
        }
    }
}

/// Lightweight peer information derived from snapshots exposed by the network layer.
#[derive(Debug, Clone)]
pub struct PeerInfo {
    pub address: String,
    pub node_id: Option<String>,
    /// Authenticated and endpoint-authorized by the P2P layer.
    pub authenticated_designated_support: bool,
    pub authenticated_designated_relayer: bool,
    pub validator_address: Option<String>,
    pub block_height: u64,
    pub best_block_hash: String,
    pub genesis_hash: String,
    pub quarantined: bool,
    pub consensus_duties_disabled: bool,
    pub recovery_state: Option<String>,
}

/// Represents a requested range that should be downloaded/applied.
#[derive(Debug, Clone)]
pub struct BlockRange {
    pub start: u64,
    pub end: u64,
}

/// Sync manager responsible for bootstrapping from genesis and keeping the node current.
pub struct SyncManager {
    pub state: SyncState,
    pub local_height: u64,
    pub network_height: u64,
    pub sync_start_height: u64,
    pub pending_blocks: BTreeMap<u64, Block>,
    pub download_queue: VecDeque<BlockRange>,
    pub peers: Vec<PeerInfo>,
    blockchain: Arc<Mutex<BlockChain>>,
    p2p_network: Option<Arc<P2PNetwork>>,
    max_sync_batch_blocks: u64,
    support_sources_only: bool,
    progress: SyncProgress,
}

impl SyncManager {
    pub fn new(blockchain: Arc<Mutex<BlockChain>>) -> Self {
        let tip_height = blockchain
            .lock()
            .ok()
            .and_then(|chain| chain.last().map(|block| block.block_index))
            .unwrap_or(0);
        SyncManager {
            state: SyncState::Idle,
            local_height: tip_height,
            network_height: tip_height,
            sync_start_height: tip_height,
            pending_blocks: BTreeMap::new(),
            download_queue: VecDeque::new(),
            peers: Vec::new(),
            blockchain,
            p2p_network: None,
            max_sync_batch_blocks: MAX_SYNC_BATCH_BLOCKS,
            support_sources_only: false,
            progress: SyncProgress::new(tip_height, tip_height),
        }
    }

    pub fn attach_network(&mut self, network: Arc<P2PNetwork>) {
        self.max_sync_batch_blocks = network.sync_batch_limit().max(1);
        self.p2p_network = Some(network);
    }

    /// Restrict onboarding or duty-disabled sync to support/history peers.
    ///
    /// The role runtime can call this when it has the authoritative local duty
    /// gate. Environment-based initialization remains available for existing
    /// startup paths that construct the manager without passing NodeConfig.
    pub fn set_support_sources_only(&mut self, enabled: bool) {
        self.support_sources_only = enabled;
    }

    fn refresh_authoritative_support_source_policy(&mut self) {
        if let Some(network) = &self.p2p_network {
            self.support_sources_only = network.support_sources_only_policy();
        }
    }

    fn refresh_local_height(&mut self) {
        if let Ok(chain) = self.blockchain.lock() {
            self.local_height = chain.last().map(|b| b.block_index).unwrap_or(0);
            self.progress.current_block = self.local_height;
        }
    }

    fn collect_peer_snapshots(&self) -> Vec<PeerSnapshot> {
        if let Some(network) = &self.p2p_network {
            network.collect_peer_snapshots()
        } else {
            Vec::new()
        }
    }

    fn refresh_peers_from_snapshots(&mut self, snapshots: Vec<PeerSnapshot>) {
        self.peers = snapshots
            .into_iter()
            .map(|snap| PeerInfo {
                address: snap.address,
                node_id: snap.node_id,
                authenticated_designated_support: snap.authenticated_designated_support,
                authenticated_designated_relayer: snap.authenticated_designated_relayer,
                validator_address: snap.validator_address,
                block_height: snap.block_height,
                best_block_hash: snap.best_block_hash,
                genesis_hash: snap.genesis_hash,
                quarantined: snap.quarantined,
                consensus_duties_disabled: snap.consensus_duties_disabled,
                recovery_state: snap.recovery_state,
            })
            .collect();
    }

    fn peer_is_support_sync_source(&self, peer: &PeerInfo) -> bool {
        peer.authenticated_designated_support
    }

    fn peer_is_eligible_sync_source(&self, peer: &PeerInfo, local_genesis: &str) -> bool {
        !peer.quarantined
            && (!peer.consensus_duties_disabled || self.peer_is_support_sync_source(peer))
            && (local_genesis.is_empty() || peer.genesis_hash == local_genesis)
    }

    fn support_sync_sources<'a>(&'a self, local_genesis: &str) -> Vec<&'a PeerInfo> {
        self.peers
            .iter()
            .filter(|peer| {
                self.peer_is_support_sync_source(peer)
                    && self.peer_is_eligible_sync_source(peer, local_genesis)
            })
            .collect()
    }

    fn sync_source_candidates<'a>(&'a self, local_genesis: &str) -> Vec<&'a PeerInfo> {
        if self.support_sources_only {
            return self.support_sync_sources(local_genesis);
        }

        self.peers
            .iter()
            .filter(|peer| self.peer_is_eligible_sync_source(peer, local_genesis))
            .collect()
    }

    fn eligible_network_height(&self, local_genesis: &str) -> u64 {
        let candidates = self.sync_source_candidates(local_genesis);
        let reported_height = candidates
            .iter()
            .map(|peer| peer.block_height)
            .max()
            .unwrap_or(0);

        reported_height
    }

    fn await_peer_snapshots(&self, timeout: Duration) -> Vec<PeerSnapshot> {
        let start = Instant::now();
        let mut last = Vec::new();

        if let Some(network) = &self.p2p_network {
            network.request_peer_statuses();
        }

        loop {
            let snapshots = self.collect_peer_snapshots();
            if !snapshots.is_empty() {
                last = snapshots;
                let has_height = last.iter().any(|peer| peer.block_height > 0);
                if has_height {
                    return last;
                }
            }

            if start.elapsed() >= timeout {
                return last;
            }

            thread::sleep(Duration::from_millis(500));
            if let Some(network) = &self.p2p_network {
                network.request_peer_statuses();
            }
        }
    }

    fn select_sync_peer(&self) -> Option<String> {
        let local_genesis = resolve_local_genesis_hash(&self.blockchain);
        let remaining = self.network_height.saturating_sub(self.local_height);
        let mut candidates = self.sync_source_candidates(&local_genesis);
        candidates.sort_by(|a, b| {
            let a_score = sync_peer_history_score(a, remaining);
            let b_score = sync_peer_history_score(b, remaining);
            let a_key = (
                sync_peer_effective_height(a, remaining, self.network_height),
                a_score,
            );
            let b_key = (
                sync_peer_effective_height(b, remaining, self.network_height),
                b_score,
            );
            b_key.cmp(&a_key)
        });
        candidates.first().map(|peer| peer.address.clone())
    }

    fn support_source_candidates_for_request(
        &self,
        local_genesis: &str,
        request_start: u64,
        target_height: u64,
    ) -> Vec<String> {
        let mut candidates = self
            .support_sync_sources(local_genesis)
            .into_iter()
            .filter(|peer| {
                (peer.block_height == 0 || target_height <= peer.block_height)
                    && (request_start >= self.local_height
                        || self
                            .blockchain
                            .lock()
                            .ok()
                            .map(|chain| chain.block_at_height(request_start).is_some())
                            .unwrap_or(false))
            })
            .collect::<Vec<_>>();
        let remaining = self.network_height.saturating_sub(self.local_height);
        candidates.sort_by(|a, b| {
            let a_key = (
                sync_peer_effective_height(a, remaining, self.network_height),
                sync_peer_history_score(a, remaining),
            );
            let b_key = (
                sync_peer_effective_height(b, remaining, self.network_height),
                sync_peer_history_score(b, remaining),
            );
            b_key.cmp(&a_key).then_with(|| a.address.cmp(&b.address))
        });
        candidates.dedup_by(|a, b| a.address == b.address);
        candidates
            .into_iter()
            .map(|peer| peer.address.clone())
            .collect()
    }

    pub fn discover_network_height(&mut self) -> Result<u64, SyncError> {
        self.refresh_authoritative_support_source_policy();
        let snapshots = self.await_peer_snapshots(Duration::from_secs(10));
        self.refresh_peers_from_snapshots(snapshots);

        if self.peers.is_empty() {
            return Err(SyncError::NoPeers);
        }

        let local_genesis = resolve_local_genesis_hash(&self.blockchain);

        if self.support_sources_only && self.support_sync_sources(&local_genesis).is_empty() {
            return Err(SyncError::NoSupportSyncSources);
        }

        Ok(self.eligible_network_height(&local_genesis))
    }

    pub fn start_sync(&mut self) -> Result<(), SyncError> {
        self.refresh_local_height();
        self.state = SyncState::Discovering;
        let network_height = self.discover_network_height()?;
        self.network_height = network_height;

        if self.local_height >= network_height {
            self.state = SyncState::Synced;
            return Ok(());
        }

        self.sync_start_height = self.local_height;
        self.progress.starting_block = self.local_height;
        self.progress.highest_block = network_height;
        self.state = SyncState::Downloading;

        while self.local_height < self.network_height {
            self.refresh_authoritative_support_source_policy();
            self.refresh_peers_from_snapshots(self.collect_peer_snapshots());
            if let Ok(updated_height) = self.discover_network_height() {
                if updated_height > self.network_height {
                    self.network_height = updated_height;
                }
            }
            let sync_tip = self.local_height;
            let remaining = self.network_height - self.local_height;
            let batch_size = remaining.min(self.max_sync_batch_blocks.max(1));
            let target_height = std::cmp::min(self.network_height, sync_tip + batch_size);
            let request_overlap = self.sync_request_overlap(batch_size, sync_tip);
            let request_start = sync_tip.saturating_sub(request_overlap);
            let request_count = target_height
                .saturating_sub(request_start)
                .saturating_add(1)
                .min(u32::MAX as u64) as u32;

            let Some(network) = self.p2p_network.as_ref().map(Arc::clone) else {
                return Err(SyncError::NetworkUnavailable);
            };

            // Scale timeout with request size because overlap/reconciliation can request
            // a wider range than the net-new block count.
            let batch_timeout_secs =
                std::cmp::max(15, std::cmp::min(180, request_count as u64 / 50 + 10));
            let batch_timeout = Duration::from_secs(batch_timeout_secs);
            let satisfied = if self.support_sources_only {
                let local_genesis = resolve_local_genesis_hash(&self.blockchain);
                // Freeze the authenticated candidate set for this request. A retry may
                // consume each candidate once, but cannot discover a new fallback or
                // reach a canonical validator after the request has started.
                let candidates = self.support_source_candidates_for_request(
                    &local_genesis,
                    request_start,
                    target_height,
                );
                let mut attempted_sources = BTreeSet::new();
                let satisfied = loop {
                    self.request_support_sync_batch(
                        &network,
                        &candidates,
                        &mut attempted_sources,
                        request_start,
                        target_height,
                        request_count,
                    )?;

                    let mut satisfied = self.wait_for_height(target_height, batch_timeout);
                    self.refresh_local_height();
                    if !satisfied && self.local_height > sync_tip {
                        satisfied = true;
                    }
                    if satisfied
                        || !candidates
                            .iter()
                            .any(|candidate| !attempted_sources.contains(candidate))
                    {
                        break satisfied;
                    }
                };
                satisfied
            } else {
                let sync_source = self.select_sync_peer();
                self.validate_sync_request(sync_source.as_deref(), request_start, target_height)?;
                self.request_sync_batch(
                    &network,
                    sync_source.as_deref(),
                    request_start,
                    request_count,
                )?;
                let mut satisfied = self.wait_for_height(target_height, batch_timeout);
                self.refresh_local_height();
                if !satisfied && self.local_height > sync_tip {
                    satisfied = true;
                }
                if !satisfied {
                    self.request_sync_batch(
                        &network,
                        sync_source.as_deref(),
                        request_start,
                        request_count,
                    )?;
                    satisfied = self.wait_for_height(target_height, batch_timeout);
                    self.refresh_local_height();
                    if !satisfied && self.local_height > sync_tip {
                        satisfied = true;
                    }
                }
                satisfied
            };

            if !satisfied {
                return Err(SyncError::Timeout(format!(
                    "blocks up to height {}",
                    target_height
                )));
            }

            self.state = SyncState::Validating;

            let validation_start = sync_tip.saturating_add(1);
            let headers =
                fast_sync::download_headers(&self.blockchain, validation_start, self.local_height);
            let prev_hash = if validation_start > 0 {
                Some(self.get_block_hash(validation_start - 1)?)
            } else {
                None
            };
            validation::validate_header_chain(&headers, prev_hash)?;

            let bodies = fast_sync::download_block_bodies(&self.blockchain, &headers);
            for block in bodies {
                validation::validate_block(&block)?;
            }

            self.progress.current_block = self.local_height;
            self.progress.highest_block = self.network_height;

            self.state = SyncState::Applying;
            self.download_queue.push_back(BlockRange {
                start: validation_start,
                end: target_height,
            });
        }

        self.state = SyncState::Synced;
        Ok(())
    }

    fn request_sync_batch(
        &self,
        network: &P2PNetwork,
        sync_source: Option<&str>,
        request_start: u64,
        request_count: u32,
    ) -> Result<(), SyncError> {
        if let Some(peer) = sync_source {
            if network.request_blocks_from_peer(peer, request_start, request_count) {
                return Ok(());
            }

            if self.support_sources_only {
                return Err(SyncError::SyncSourceUnavailable {
                    peer: peer.to_string(),
                    requested_height: request_start,
                });
            }
        }

        if self.support_sources_only {
            return Err(SyncError::NoSupportSyncSources);
        }

        network.request_blocks(request_start, request_count);
        Ok(())
    }

    fn request_support_sync_batch(
        &self,
        network: &P2PNetwork,
        candidates: &[String],
        attempted_sources: &mut BTreeSet<String>,
        request_start: u64,
        target_height: u64,
        request_count: u32,
    ) -> Result<(), SyncError> {
        let mut last_unavailable = None;
        while let Some(peer) = next_support_source(candidates, attempted_sources) {
            let peer = peer.to_string();
            attempted_sources.insert(peer.clone());

            self.validate_sync_request(Some(&peer), request_start, target_height)?;
            if network.request_blocks_from_peer(&peer, request_start, request_count) {
                return Ok(());
            }
            last_unavailable = Some(peer);
        }

        match last_unavailable {
            Some(peer) => Err(SyncError::SyncSourceUnavailable {
                peer,
                requested_height: request_start,
            }),
            None => Err(SyncError::NoSupportSyncSources),
        }
    }

    fn validate_sync_request(
        &self,
        sync_source: Option<&str>,
        request_start: u64,
        target_height: u64,
    ) -> Result<(), SyncError> {
        let Some(peer_address) = sync_source else {
            return if self.support_sources_only {
                Err(SyncError::NoSupportSyncSources)
            } else {
                Ok(())
            };
        };

        let Some(peer) = self.peers.iter().find(|peer| peer.address == peer_address) else {
            return Err(SyncError::SyncSourceUnavailable {
                peer: peer_address.to_string(),
                requested_height: request_start,
            });
        };

        if peer.block_height > 0 && target_height > peer.block_height {
            return Err(SyncError::SourceHistoryUnavailable {
                peer: peer_address.to_string(),
                requested_height: target_height,
                reason: format!(
                    "source reports height {}, so the requested range is outside its retained history",
                    peer.block_height
                ),
            });
        }

        if request_start < self.local_height {
            let retained = self
                .blockchain
                .lock()
                .ok()
                .and_then(|chain| chain.block_at_height(request_start).map(|_| ()));
            if retained.is_none() {
                return Err(SyncError::SourceHistoryUnavailable {
                    peer: peer_address.to_string(),
                    requested_height: request_start,
                    reason: "requested reconciliation block is outside local retained history"
                        .to_string(),
                });
            }
        }

        Ok(())
    }

    fn wait_for_height(&self, target: u64, timeout: Duration) -> bool {
        let start = Instant::now();
        while Instant::now().duration_since(start) < timeout {
            if let Ok(chain) = self.blockchain.lock() {
                if let Some(last) = chain.last() {
                    if last.block_index >= target {
                        return true;
                    }
                }
            }
            thread::sleep(Duration::from_millis(250));
        }
        false
    }

    fn sync_request_overlap(&self, batch_size: u64, local_height: u64) -> u64 {
        let overlap = sync_progress_overlap(batch_size);
        if overlap == 0 {
            return 0;
        }

        let Ok(chain) = self.blockchain.lock() else {
            return 0;
        };
        if !chain_has_reconciliation_window(&chain, local_height, overlap) {
            return 0;
        }

        overlap
    }

    fn get_block_hash(&self, height: u64) -> Result<String, SyncError> {
        let chain = self
            .blockchain
            .lock()
            .map_err(|_| SyncError::NetworkUnavailable)?;
        chain
            .chain
            .iter()
            .find(|block| block.block_index == height)
            .map(|block| block.hash.clone())
            .ok_or(SyncError::MissingBlock(height))
    }

    pub fn get_state(&self) -> SyncState {
        self.state
    }

    pub fn get_network_height(&self) -> u64 {
        self.network_height
    }

    pub fn get_sync_start_height(&self) -> u64 {
        self.sync_start_height
    }

    pub fn get_progress_percentage(&self) -> f64 {
        self.progress.percentage()
    }
}

fn sync_progress_overlap(batch_size: u64) -> u64 {
    if batch_size <= 1 {
        return 0;
    }

    SYNC_RECONCILIATION_LOOKBACK
        .min(SYNC_PROGRESS_OVERLAP)
        .min(batch_size - 1)
}

fn chain_has_reconciliation_window(chain: &BlockChain, local_height: u64, overlap: u64) -> bool {
    if overlap == 0 {
        return true;
    }

    let start = local_height.saturating_sub(overlap);
    (start..=local_height).all(|height| chain.block_at_height(height).is_some())
}

fn sync_peer_history_score(peer: &PeerInfo, remaining: u64) -> u8 {
    if remaining <= 5_000 {
        return 0;
    }

    if peer.authenticated_designated_support && !peer.authenticated_designated_relayer {
        2
    } else if peer.authenticated_designated_relayer {
        1
    } else {
        0
    }
}

fn sync_peer_effective_height(peer: &PeerInfo, remaining: u64, network_height: u64) -> u64 {
    if peer.block_height == 0 && sync_peer_history_score(peer, remaining) >= 2 {
        network_height
    } else {
        peer.block_height
    }
}

fn next_support_source<'a>(
    candidates: &'a [String],
    attempted_sources: &BTreeSet<String>,
) -> Option<&'a str> {
    candidates
        .iter()
        .find(|candidate| !attempted_sources.contains(*candidate))
        .map(String::as_str)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer(
        address: &str,
        node_id: Option<&str>,
        validator_address: Option<&str>,
        height: u64,
        quarantined: bool,
        duty_disabled: bool,
    ) -> PeerInfo {
        PeerInfo {
            address: address.to_string(),
            node_id: node_id.map(str::to_string),
            authenticated_designated_support: false,
            authenticated_designated_relayer: false,
            validator_address: validator_address.map(str::to_string),
            block_height: height,
            best_block_hash: format!("hash-{height}"),
            genesis_hash: String::new(),
            quarantined,
            consensus_duties_disabled: duty_disabled,
            recovery_state: None,
        }
    }

    fn mark_authenticated_support(peer: &mut PeerInfo, relayer: bool) {
        peer.authenticated_designated_support = true;
        peer.authenticated_designated_relayer = relayer;
    }

    fn assign_peer_genesis(peers: &mut [PeerInfo], local_genesis: &str) {
        for peer in peers {
            peer.genesis_hash = local_genesis.to_string();
        }
    }

    #[test]
    fn sync_overlap_is_smaller_than_support_response_budget() {
        assert_eq!(sync_progress_overlap(0), 0);
        assert_eq!(sync_progress_overlap(1), 0);
        assert_eq!(sync_progress_overlap(2), 1);
        assert_eq!(sync_progress_overlap(64), SYNC_PROGRESS_OVERLAP);
    }

    #[test]
    fn compact_snapshot_chain_disables_sync_overlap() {
        let mut chain = BlockChain::new();
        let mut retained = Block::new_with_timestamp(
            743_026,
            Vec::new(),
            "parent".to_string(),
            "validator".to_string(),
            0,
            2,
        );
        retained.hash = "retained-tip".to_string();
        chain.add_block(retained);

        let blockchain = Arc::new(Mutex::new(chain));
        let manager = SyncManager::new(blockchain);

        assert_eq!(manager.sync_request_overlap(96, 743_026), 0);
    }

    #[test]
    fn contiguous_hot_chain_keeps_sync_overlap() {
        let mut chain = BlockChain::new();
        for height in 100..=102 {
            let mut block = Block::new_with_timestamp(
                height,
                Vec::new(),
                format!("parent-{height}"),
                "validator".to_string(),
                height,
                height,
            );
            block.hash = format!("hash-{height}");
            chain.add_block(block);
        }
        let blockchain = Arc::new(Mutex::new(chain));
        let manager = SyncManager::new(blockchain);

        assert_eq!(manager.sync_request_overlap(96, 102), SYNC_PROGRESS_OVERLAP);
    }

    #[test]
    fn sync_peer_selection_rejects_quarantined_and_duty_disabled_validators() {
        let blockchain = Arc::new(Mutex::new(BlockChain::new()));
        let mut manager = SyncManager::new(blockchain);
        manager.peers = vec![
            peer(
                "quarantined",
                None,
                Some("synv1quarantined"),
                200,
                true,
                true,
            ),
            peer("duty-disabled", None, Some("synv1shadow"), 180, false, true),
            peer("active", None, Some("synv1active"), 100, false, false),
        ];
        let local_genesis = resolve_local_genesis_hash(&manager.blockchain);
        assign_peer_genesis(&mut manager.peers, &local_genesis);

        assert_eq!(manager.select_sync_peer(), Some("active".to_string()));
        assert_eq!(manager.eligible_network_height(""), 100);
    }

    #[test]
    fn sync_peer_selection_accepts_duty_disabled_support_peers() {
        let blockchain = Arc::new(Mutex::new(BlockChain::new()));
        let mut manager = SyncManager::new(blockchain);
        manager.peers = vec![
            peer(
                "active-validator",
                None,
                Some("synv1active"),
                100,
                false,
                false,
            ),
            peer(
                "relayer",
                Some("sentry1"),
                Some("synv21ga3nsdjagzt9pmks4mzjq4vdjyngdwq6jst632"),
                195_000,
                false,
                true,
            ),
        ];
        mark_authenticated_support(&mut manager.peers[1], true);
        let local_genesis = resolve_local_genesis_hash(&manager.blockchain);
        assign_peer_genesis(&mut manager.peers, &local_genesis);

        assert_eq!(manager.select_sync_peer(), Some("relayer".to_string()));
        assert_eq!(manager.eligible_network_height(""), 195_000);
    }

    #[test]
    fn onboarding_sync_uses_only_support_history_sources() {
        let blockchain = Arc::new(Mutex::new(BlockChain::new()));
        let mut manager = SyncManager::new(blockchain);
        manager.set_support_sources_only(true);
        manager.local_height = 100;
        manager.network_height = 200;
        manager.peers = vec![
            peer(
                "canonical-validator",
                Some("validator-node-01"),
                Some("synv1canonical"),
                200,
                false,
                false,
            ),
            peer(
                "relayer",
                Some("relayer-1"),
                Some("synv1relayer"),
                150,
                false,
                true,
            ),
        ];
        mark_authenticated_support(&mut manager.peers[1], true);
        let local_genesis = resolve_local_genesis_hash(&manager.blockchain);
        assign_peer_genesis(&mut manager.peers, &local_genesis);

        assert_eq!(manager.eligible_network_height(&local_genesis), 150);
        assert_eq!(manager.select_sync_peer(), Some("relayer".to_string()));
        assert_eq!(manager.sync_source_candidates(&local_genesis).len(), 1);
    }

    #[test]
    fn support_only_sync_refuses_canonical_fallback() {
        let blockchain = Arc::new(Mutex::new(BlockChain::new()));
        let mut manager = SyncManager::new(blockchain);
        manager.set_support_sources_only(true);
        manager.peers = vec![peer(
            "canonical-validator",
            Some("validator-node-01"),
            Some("synv1canonical"),
            200,
            false,
            false,
        )];
        let local_genesis = resolve_local_genesis_hash(&manager.blockchain);
        assign_peer_genesis(&mut manager.peers, &local_genesis);

        assert!(manager.select_sync_peer().is_none());
        assert_eq!(
            SyncError::NoSupportSyncSources.to_string(),
            "No eligible support/history sync sources available; refusing canonical validator fanout"
        );
    }

    #[test]
    fn support_source_failover_is_bounded_and_stays_support_only() {
        let candidates = vec![
            "support-a".to_string(),
            "support-b".to_string(),
            "support-c".to_string(),
            "support-d".to_string(),
        ];
        let mut attempted = BTreeSet::new();

        assert_eq!(
            next_support_source(&candidates, &attempted),
            Some("support-a")
        );
        attempted.insert("support-a".to_string());
        assert_eq!(
            next_support_source(&candidates, &attempted),
            Some("support-b")
        );
        attempted.insert("support-b".to_string());
        attempted.insert("support-c".to_string());
        assert_eq!(
            next_support_source(&candidates, &attempted),
            Some("support-d")
        );
        attempted.insert("support-d".to_string());
        assert_eq!(next_support_source(&candidates, &attempted), None);
        assert!(!attempted.contains("canonical-validator"));
    }

    #[test]
    fn support_selection_ignores_self_reported_identity_and_recovery_state() {
        let blockchain = Arc::new(Mutex::new(BlockChain::new()));
        let mut manager = SyncManager::new(blockchain);
        manager.set_support_sources_only(true);
        let mut spoofed = peer(
            "rpc.synergynode.xyz:5623",
            Some("sentry-spoof"),
            None,
            200,
            false,
            true,
        );
        spoofed.recovery_state = Some("support-recovery".to_string());
        manager.peers = vec![spoofed];
        let local_genesis = resolve_local_genesis_hash(&manager.blockchain);
        assign_peer_genesis(&mut manager.peers, &local_genesis);

        assert!(manager.sync_source_candidates(&local_genesis).is_empty());
        assert!(manager.select_sync_peer().is_none());
    }

    #[test]
    fn authenticated_support_metadata_propagates_into_peer_info() {
        let blockchain = Arc::new(Mutex::new(BlockChain::new()));
        let mut manager = SyncManager::new(blockchain);
        let snapshot = PeerSnapshot {
            address: "relay1.synergynode.xyz:5622".to_string(),
            authenticated_designated_support: true,
            authenticated_designated_relayer: true,
            ..PeerSnapshot::default()
        };

        manager.refresh_peers_from_snapshots(vec![snapshot]);

        assert!(manager.peers[0].authenticated_designated_support);
        assert!(manager.peers[0].authenticated_designated_relayer);
    }

    #[test]
    fn sync_source_history_error_reports_requested_height() {
        let blockchain = Arc::new(Mutex::new(BlockChain::new()));
        let mut manager = SyncManager::new(blockchain);
        manager.peers = vec![peer(
            "relayer",
            Some("relayer-1"),
            Some("synv1relayer"),
            100,
            false,
            true,
        )];
        manager.local_height = 100;

        let error = manager
            .validate_sync_request(Some("relayer"), 101, 102)
            .expect_err("source head must bound the requested range");
        assert!(matches!(
            error,
            SyncError::SourceHistoryUnavailable {
                requested_height: 102,
                ..
            }
        ));
        assert!(error.to_string().contains("outside its retained history"));
    }

    #[test]
    fn sync_source_history_error_reports_missing_local_reconciliation_block() {
        let mut chain = BlockChain::new();
        chain.add_block(Block::new_with_timestamp(
            10,
            Vec::new(),
            "parent-10".to_string(),
            "validator".to_string(),
            10,
            10,
        ));
        chain.add_block(Block::new_with_timestamp(
            12,
            Vec::new(),
            "parent-12".to_string(),
            "validator".to_string(),
            12,
            12,
        ));
        let blockchain = Arc::new(Mutex::new(chain));
        let mut manager = SyncManager::new(blockchain);
        manager.local_height = 12;
        manager.peers = vec![peer(
            "relayer",
            Some("relayer-1"),
            Some("synv1relayer"),
            12,
            false,
            true,
        )];

        let error = manager
            .validate_sync_request(Some("relayer"), 11, 12)
            .expect_err("missing retained reconciliation block must fail closed");
        assert!(error.to_string().contains("outside local retained history"));
    }

    #[test]
    fn deep_sync_peer_selection_prefers_history_gateway_over_relayers() {
        let blockchain = Arc::new(Mutex::new(BlockChain::new()));
        let mut manager = SyncManager::new(blockchain);
        manager.local_height = 748_937;
        manager.network_height = 760_908;
        manager.peers = vec![
            peer(
                "195.26.241.95:5622",
                Some("sentry1"),
                Some("synv21ga3nsdjagzt9pmks4mzjq4vdjyngdwq6jst632"),
                760_908,
                false,
                true,
            ),
            peer(
                "167.86.83.83:5623",
                Some("genesisrpc"),
                Some("synv5d2b6a255a574438fd8bdcb194a782acbdcf2"),
                0,
                false,
                true,
            ),
            peer(
                "94.72.117.108:5622",
                Some("sentry2"),
                Some("synv21xaqlq808sunuchd0jwr4m324h85fza2ps3s4k7"),
                760_908,
                false,
                true,
            ),
        ];
        mark_authenticated_support(&mut manager.peers[0], true);
        mark_authenticated_support(&mut manager.peers[1], false);
        mark_authenticated_support(&mut manager.peers[2], true);
        let local_genesis = resolve_local_genesis_hash(&manager.blockchain);
        assign_peer_genesis(&mut manager.peers, &local_genesis);

        assert_eq!(
            manager.select_sync_peer(),
            Some("167.86.83.83:5623".to_string())
        );
    }

    #[test]
    fn sync_peer_selection_uses_canonical_genesis_for_compact_chain() {
        std::env::set_var(
            "SYNERGY_GENESIS_FILE",
            concat!(env!("CARGO_MANIFEST_DIR"), "/../config/genesis.json"),
        );
        let canonical_hash = canonical_genesis()
            .expect("canonical genesis should load")
            .hash()
            .to_string();
        assert!(!canonical_hash.is_empty());

        let mut chain = BlockChain::new();
        let mut retained = Block::new_with_timestamp(
            261_825,
            Vec::new(),
            "retained-parent".to_string(),
            "validator".to_string(),
            0,
            1,
        );
        retained.hash = "retained-block-hash".to_string();
        chain.chain.push(retained);

        let blockchain = Arc::new(Mutex::new(chain));
        let mut manager = SyncManager::new(blockchain);
        let mut canonical_peer = peer("canonical", None, Some("synv1active"), 100, false, false);
        canonical_peer.genesis_hash = canonical_hash.clone();
        let mut retained_hash_peer = peer("retained", None, Some("synv1stale"), 200, false, false);
        retained_hash_peer.genesis_hash = "retained-block-hash".to_string();
        manager.peers = vec![retained_hash_peer, canonical_peer];

        assert_eq!(
            resolve_local_genesis_hash(&manager.blockchain),
            canonical_hash
        );
        assert_eq!(manager.select_sync_peer(), Some("canonical".to_string()));
    }
}
