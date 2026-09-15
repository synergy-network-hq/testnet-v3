//! Opaque certificate references shared across subsystems.
//!
//! Certificate contents and quorum validity remain owned by PoSy or ETDAG.

use serde::{Deserialize, Serialize};

use crate::{Epoch, Height, ProtocolHash};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CertificateKind {
    PosyQuorum,
    EtdagAvailability,
    SnapshotFinality,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CertificateReference {
    pub kind: CertificateKind,
    pub epoch: Epoch,
    pub height: Height,
    pub subject_hash: ProtocolHash,
}

impl CertificateReference {
    pub const fn new(
        kind: CertificateKind,
        epoch: Epoch,
        height: Height,
        subject_hash: ProtocolHash,
    ) -> Self {
        Self {
            kind,
            epoch,
            height,
            subject_hash,
        }
    }

    pub const fn may_determine_finality(&self) -> bool {
        false
    }
}
