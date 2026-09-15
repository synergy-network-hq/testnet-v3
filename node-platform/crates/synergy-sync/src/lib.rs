//! Verified block, state, and snapshot synchronization boundary.
//!
//! Transport reports are candidates only. This crate plans recovery only after
//! finality evidence is verified by its dedicated verifier integration. It does
//! not determine PoSy finality, calculate quorum, or make a validator active.

pub mod block;
pub mod head;
pub mod sources;
pub mod state;

mod manager;
mod metrics;
mod persistence;
mod readiness;
mod status;
mod wire;

pub use block::{
    BlockCommitError, BlockImportCoordinator, BlockImportError, BlockImportReceipt, BlockRequest,
    BlockResponse, BlockScheduleError, BlockScheduler, PosyBlockFinalityVerifier, RetryDecision,
    RetryError, RetryPolicy, RetryTracker, SyncBlock, VerifiedBlockImporter, VerifiedBlockStore,
};
pub use head::{
    HeadClaim, HeadCollectionError, HeadUpdate, HeadVerificationError, PosyFinalityVerifier,
    SourceSelectionError, SyncPeerCandidate, VerifiedHead, VerifiedHeadCollector,
    VerifiedHeadVerifier, VerifiedSourceSelector,
};
pub use manager::{SyncManager, SyncPlan};
pub use metrics::{SyncMetrics, SyncMetricsSnapshot};
pub use persistence::{
    decode_resume_token, encode_resume_token, read_resume_token, write_resume_token,
    PersistenceError,
};
pub use readiness::SyncReadiness;
pub use sources::*;
pub use state::{
    chunks_root, CanonicalStateStore, CheckpointError, DownloadError, ReceivedChunk, ResumeError,
    ResumeToken, SnapshotDownload, SnapshotDownloadLimits, SnapshotManifest,
    SnapshotValidationError, SnapshotVerifyError, StateCheckpoint, StateChunk, StateImportError,
    StateImportReceipt, StateSnapshotVerifier, VerifiedSnapshot, VerifiedStateImporter,
};
pub use status::{SyncPhase, SyncStatus};
pub use wire::{
    EpochAuthorityRequest, EpochAuthorityResponse, FinalizedCandidateRequest,
    FinalizedCandidateResponse, SnapshotChunkRequest, SnapshotChunkResponse, SyncWireMessage,
};

#[cfg(test)]
mod tests {
    use super::*;

    fn peer(id: &str, height: u64) -> SyncPeerCandidate {
        SyncPeerCandidate {
            peer_id: id.into(),
            authenticated: true,
            protocol_compatible: true,
            genesis_hash: "genesis".into(),
            quarantined: false,
            consensus_duties_disabled: false,
            designated_support: false,
            advertised_height: height,
        }
    }

    fn head(id: &str, height: u64) -> VerifiedHead {
        VerifiedHead {
            peer_id: id.into(),
            finalized_height: height,
            finalized_hash: format!("h{height}"),
            finality_evidence_id: format!("e{height}"),
        }
    }

    #[test]
    fn highest_advertised_height_is_ignored_without_verified_evidence() {
        let selector = VerifiedSourceSelector::new("genesis");
        let sources = selector
            .select(
                &[peer("honest", 10), peer("liar", 999999)],
                &[head("honest", 10)],
            )
            .unwrap();
        assert_eq!(sources[0].peer_id, "honest");
        assert_eq!(sources[0].finalized_height, 10);
    }

    #[test]
    fn verified_block_import_checks_parent_and_height_continuity() {
        let mut importer = VerifiedBlockImporter::new(2, "one");
        let response = BlockResponse {
            request: BlockRequest {
                from_height: 2,
                through_height: 3,
                expected_parent_id: "one".into(),
            },
            blocks: vec![
                SyncBlock {
                    height: 2,
                    block_id: "two".into(),
                    parent_id: "one".into(),
                    finality_evidence_id: "qc-two".into(),
                },
                SyncBlock {
                    height: 3,
                    block_id: "three".into(),
                    parent_id: "two".into(),
                    finality_evidence_id: "qc-three".into(),
                },
            ],
        };
        assert_eq!(importer.validate_response(&response).unwrap().len(), 2);
        assert!(!importer.may_determine_finality());
    }

    #[test]
    fn block_import_rejects_mismatched_request_without_advancing() {
        let mut importer = VerifiedBlockImporter::new(2, "one");
        let mut response = BlockResponse {
            request: BlockRequest {
                from_height: 3,
                through_height: 3,
                expected_parent_id: "one".into(),
            },
            blocks: vec![SyncBlock {
                height: 2,
                block_id: "two".into(),
                parent_id: "one".into(),
                finality_evidence_id: "qc-two".into(),
            }],
        };
        assert_eq!(
            importer.validate_response(&response),
            Err(BlockImportError::RequestAnchorMismatch)
        );
        response.request.from_height = 2;
        response.request.through_height = 2;
        assert_eq!(importer.validate_response(&response).unwrap().len(), 1);
    }

    #[test]
    fn block_import_rejects_extra_block_outside_requested_range() {
        let mut importer = VerifiedBlockImporter::new(2, "one");
        let mut response = BlockResponse {
            request: BlockRequest {
                from_height: 2,
                through_height: 2,
                expected_parent_id: "one".into(),
            },
            blocks: vec![
                SyncBlock {
                    height: 2,
                    block_id: "two".into(),
                    parent_id: "one".into(),
                    finality_evidence_id: "qc-two".into(),
                },
                SyncBlock {
                    height: 3,
                    block_id: "three".into(),
                    parent_id: "two".into(),
                    finality_evidence_id: "qc-three".into(),
                },
            ],
        };
        assert_eq!(
            importer.validate_response(&response),
            Err(BlockImportError::ResponseOutOfRange {
                through_height: 2,
                received: 3
            })
        );
        response.request.through_height = 3;
        assert_eq!(importer.validate_response(&response).unwrap().len(), 2);
    }

    #[test]
    fn snapshot_requires_every_chunk_and_an_expected_root() {
        let chunks = vec![
            StateChunk::from_bytes(0, vec![1]),
            StateChunk::from_bytes(1, vec![2]),
        ];
        let manifest = SnapshotManifest {
            chain_id: 1266,
            genesis_hash: "genesis".into(),
            finalized_height: 7,
            finalized_block_id: "block".into(),
            state_root: "state".into(),
            chunks_root: chunks_root(&chunks),
            chunk_count: 2,
            finality_evidence_id: "qc".into(),
        };
        manifest.validate_chunks(&chunks).unwrap();
        assert!(!manifest.may_determine_finality());
    }
}
