use std::collections::BTreeMap;

use crate::{FinalizedBlockRecord, PosyError, PosyResult, SimplifiedQuorumCertificate};

/// Implements the governed three-QC finality rule. A QC certifies one block;
/// accepting QC(H) finalizes H-2 only when the retained QC chain is contiguous.
#[derive(Debug, Default)]
pub struct ThreeQcFinality {
    certificates: BTreeMap<u64, SimplifiedQuorumCertificate>,
    last_finalized: Option<FinalizedBlockRecord>,
}

impl ThreeQcFinality {
    /// Installs the already verified two-QC tail from the previous epoch.
    /// The successor epoch then preserves the three-QC finality pipeline
    /// without reinterpreting transport or membership as authority.
    pub fn seed_verified_prefix(
        &mut self,
        finalized: FinalizedBlockRecord,
        certificates: [SimplifiedQuorumCertificate; 2],
    ) -> PosyResult<()> {
        if !self.certificates.is_empty() || self.last_finalized.is_some() {
            return Err(PosyError::Conflict(
                "three-QC finality prefix is already initialized".into(),
            ));
        }
        let [older, newer] = certificates;
        if finalized.height.checked_add(1) != Some(older.context.height)
            || older.context.height.checked_add(1) != Some(newer.context.height)
            || newer.parent.reference_id() != older.id()?
            || newer.parent.height() != older.context.height
            || newer.parent.block_id() != older.block_id
        {
            return Err(PosyError::Conflict(
                "epoch transition finality prefix is not contiguous".into(),
            ));
        }
        self.certificates.insert(older.context.height, older);
        self.certificates.insert(newer.context.height, newer);
        self.last_finalized = Some(finalized);
        Ok(())
    }

    pub fn accept(
        &mut self,
        certificate: SimplifiedQuorumCertificate,
    ) -> PosyResult<Option<FinalizedBlockRecord>> {
        let height = certificate.context.height;
        if let Some(existing) = self.certificates.get(&height) {
            if existing.id()? != certificate.id()? {
                return Err(PosyError::Conflict(
                    "conflicting quorum certificates at one height".into(),
                ));
            }
            return Ok(None);
        }

        // Validate the entire three-QC witness before mutating retained safety
        // state. A rejected certificate must not poison a later valid replay.
        let finalized = if height < 3 {
            None
        } else if let (Some(middle), Some(oldest)) = (
            self.certificates.get(&(height - 1)),
            self.certificates.get(&(height - 2)),
        ) {
            if certificate.parent.reference_id() != middle.id()?
                || middle.parent.reference_id() != oldest.id()?
                || certificate.parent.height() != height - 1
                || middle.parent.height() != height - 2
                || certificate.parent.block_id() != middle.block_id
                || middle.parent.block_id() != oldest.block_id
            {
                return Err(PosyError::Conflict(
                    "three-QC chain has incompatible parent references".into(),
                ));
            }
            let record = FinalizedBlockRecord {
                height: oldest.context.height,
                block_id: oldest.block_id.clone(),
                finality_certificate_id: certificate.id()?,
                protected_execution_root: oldest.protected_execution_root.clone(),
            };
            if let Some(previous) = &self.last_finalized {
                if record.height <= previous.height {
                    None
                } else if record.height != previous.height.saturating_add(1) {
                    return Err(PosyError::Conflict(
                        "three-QC finality skipped a finalized height".into(),
                    ));
                } else {
                    Some(record)
                }
            } else {
                Some(record)
            }
        } else {
            None
        };

        self.certificates.insert(height, certificate);
        if let Some(record) = &finalized {
            self.last_finalized = Some(record.clone());
        }
        Ok(finalized)
    }

    pub fn last_finalized(&self) -> Option<&FinalizedBlockRecord> {
        self.last_finalized.as_ref()
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ConsensusObjectContext, SimplifiedFinalityParent};

    fn hash(character: char) -> String {
        std::iter::repeat_n(character, 64).collect()
    }

    fn genesis() -> SimplifiedFinalityParent {
        SimplifiedFinalityParent::Genesis {
            genesis_hash: hash('a'),
            block_id: "genesis".into(),
            reference_id: hash('b'),
        }
    }

    fn qc(height: u64, parent: SimplifiedFinalityParent) -> SimplifiedQuorumCertificate {
        SimplifiedQuorumCertificate {
            context: ConsensusObjectContext {
                schema_version: 1,
                chain_id: 1266,
                network_id: "testnet".into(),
                protocol_version: "posy/3.0".into(),
                epoch: 1,
                height,
                round: 0,
                epoch_context_root: hash('c'),
                consensus_parameter_root: hash('d'),
                active_validator_set_root: hash('e'),
                validator_consensus_key_root: hash('f'),
                frozen_voting_weight_root: hash('1'),
            },
            block_id: format!("block-{height}"),
            parent_block_id: parent.block_id().into(),
            parent,
            takeover_tc_id: None,
            protected_execution_root: hash('2'),
            participants: Vec::new(),
        }
    }

    fn parent_of(qc: &SimplifiedQuorumCertificate) -> SimplifiedFinalityParent {
        SimplifiedFinalityParent::QuorumCertificate {
            height: qc.context.height,
            block_id: qc.block_id.clone(),
            qc_id: qc.id().unwrap(),
        }
    }

    #[test]
    fn rejected_third_qc_does_not_poison_valid_finality_replay() {
        let first = qc(1, genesis());
        let second = qc(2, parent_of(&first));
        let wrong = qc(3, parent_of(&first));
        let correct = qc(3, parent_of(&second));
        let mut finality = ThreeQcFinality::default();
        assert!(finality.accept(first).unwrap().is_none());
        assert!(finality.accept(second).unwrap().is_none());
        assert!(matches!(
            finality.accept(wrong),
            Err(PosyError::Conflict(_))
        ));
        assert_eq!(finality.last_finalized(), None);
        assert_eq!(finality.certificates.len(), 2);
        let record = finality.accept(correct).unwrap().unwrap();
        assert_eq!(record.height, 1);
        assert_eq!(finality.last_finalized(), Some(&record));
    }
}
