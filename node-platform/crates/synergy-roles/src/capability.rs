use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Capability {
    Identity,
    DurableStorage,
    Telemetry,
    Health,
    Sync,
    NetworkTransport,
    PeerDiscovery,
    PublicRpc,
    AdminApi,
    ArchiveRead,
    ArchiveWrite,
    SnapshotServe,
    SnapshotSign,
    ObserveConsensus,
    ProposeBlocks,
    VoteConsensus,
    ExecuteTransactions,
    ServeSynq,
    RelaySxcp,
    ResolveUma,
    ProvideCryptography,
    ExportAnalytics,
}

impl Capability {
    /// Role capabilities declare which services may run. They never establish
    /// validator membership, voting weight, key custody, or finality authority.
    pub const fn grants_consensus_authority(self) -> bool {
        false
    }
}
