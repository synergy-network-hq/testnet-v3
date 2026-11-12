use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

use crate::{
    ConsensusSignatureVerifier, FinalizedBlockRecord, FrozenValidatorRegistry, PosyError,
    PosyResult, SimplifiedEpochContext, SimplifiedQuorumCertificate, SimplifiedTimeoutCertificate,
    VerifiedTimeoutCertificateStore,
};

/// Complete consensus evidence needed to replay the three certified heights
/// that finalize one execution candidate through the single PoSy driver.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FinalitySyncWitness {
    pub quorum_certificates: [SimplifiedQuorumCertificate; 3],
    pub timeout_certificates: Vec<SimplifiedTimeoutCertificate>,
}

impl FinalitySyncWitness {
    /// R1 recovery proof only. This verifies evidence without changing any
    /// driver, journal, lock, timeout store, or durable finalized record. The
    /// caller must compare the returned record exactly with durable finality
    /// before selecting this certified-history projection. It must also verify
    /// the sequential omitted local timeout predecessor chain from immutable
    /// evidence, beginning at the same-height QC round and takeover TC ID.
    pub fn verify_superseded_timeout(
        &self,
        local: &SimplifiedTimeoutCertificate,
        epoch: &SimplifiedEpochContext,
        validators: &FrozenValidatorRegistry,
        verifier: &impl ConsensusSignatureVerifier,
    ) -> PosyResult<FinalizedBlockRecord> {
        local.verify(epoch, validators, verifier)?;
        for qc in &self.quorum_certificates {
            qc.verify(epoch, validators, verifier)?;
        }
        let [oldest, middle, newest] = &self.quorum_certificates;
        if oldest.context.height.checked_add(1) != Some(middle.context.height)
            || middle.context.height.checked_add(1) != Some(newest.context.height)
            || middle.parent.height() != oldest.context.height
            || middle.parent.block_id() != oldest.block_id
            || middle.parent.reference_id() != oldest.id()?
            || newest.parent.height() != middle.context.height
            || newest.parent.block_id() != middle.block_id
            || newest.parent.reference_id() != middle.id()?
        {
            return Err(PosyError::Conflict(
                "R1 recovery requires an exact contiguous three-QC finality chain".into(),
            ));
        }
        let closure = self.verified_timeout_closure(epoch, validators, verifier)?;
        let by_id = closure
            .values()
            .map(|tc| Ok((tc.id()?, tc)))
            .collect::<PosyResult<BTreeMap<_, _>>>()?;
        let mut referenced = BTreeSet::new();
        for qc in &self.quorum_certificates {
            let mut expected = qc.takeover_tc_id.as_ref();
            for _ in 0..qc.context.round {
                let id =
                    expected.ok_or_else(|| PosyError::invalid("R1 timeout predecessor missing"))?;
                let tc = by_id
                    .get(id)
                    .ok_or_else(|| PosyError::invalid("R1 timeout predecessor missing"))?;
                referenced.insert(id.clone());
                expected = tc.previous_tc_id.as_ref();
            }
        }
        if referenced.len() != by_id.len() {
            return Err(PosyError::invalid(
                "R1 witness contains an unreferenced timeout",
            ));
        }
        if referenced.contains(&local.id()?) {
            return Err(PosyError::invalid(
                "R1 local timeout is already on the certified path",
            ));
        }
        // The caller independently verifies the omitted local predecessor tail
        // from its immutable timeout store, beginning at the certified QC's
        // round/takeover ID. Such local-only predecessors must not be injected
        // into this witness's exact canonical timeout closure.
        let same_height = self
            .quorum_certificates
            .iter()
            .find(|qc| qc.context.height == local.context.height)
            .ok_or_else(|| {
                PosyError::invalid("R1 local timeout height is not certified by witness")
            })?;
        if local.mandatory_carry_candidate()?.as_ref() != Some(&same_height.subject()?)
            || local.highest_parent()? != same_height.parent
        {
            return Err(PosyError::Conflict(
                "R1 timeout carry or parent conflicts with the certified stable candidate".into(),
            ));
        }
        Ok(FinalizedBlockRecord {
            height: oldest.context.height,
            block_id: oldest.block_id.clone(),
            finality_certificate_id: newest.id()?,
            protected_execution_root: oldest.protected_execution_root.clone(),
        })
    }

    /// A takeover survives subsequent heights in the same governed lease.
    /// Follow the signed certificate IDs back to their original slots instead
    /// of requiring fictitious per-height timeout certificates.
    pub fn from_verified_certificates(
        quorum_certificates: [SimplifiedQuorumCertificate; 3],
        store: &VerifiedTimeoutCertificateStore,
        epoch: &SimplifiedEpochContext,
        validators: &FrozenValidatorRegistry,
        verifier: &impl ConsensusSignatureVerifier,
    ) -> PosyResult<Self> {
        let mut timeouts = BTreeMap::new();
        for qc in &quorum_certificates {
            qc.verify(epoch, validators, verifier)?;
            let first = epoch.epoch_start_height
                + epoch.lease_index(qc.context.height)? * epoch.leader_lease_blocks;
            let mut last = qc.context.height;
            let mut expected = qc.takeover_tc_id.clone();
            for round in (0..qc.context.round).rev() {
                let mut found = None;
                for height in (first..=last).rev() {
                    if let Some(tc) =
                        store.get_verified(height, round, epoch, validators, verifier)?
                    {
                        if Some(tc.id()?) == expected {
                            found = Some(tc);
                            break;
                        }
                    }
                }
                let tc = found.ok_or_else(|| {
                    PosyError::NotReady(
                        "Sync witness lacks the referenced lease timeout closure".into(),
                    )
                })?;
                last = tc.context.height;
                expected = tc.previous_tc_id.clone();
                timeouts.insert((tc.context.height, tc.context.round), tc);
            }
            if expected.is_some() {
                return Err(PosyError::invalid(
                    "Sync timeout chain does not start at round zero",
                ));
            }
        }
        Ok(Self {
            quorum_certificates,
            timeout_certificates: timeouts.into_values().collect(),
        })
    }

    pub fn verified_timeout_closure(
        &self,
        epoch: &SimplifiedEpochContext,
        validators: &FrozenValidatorRegistry,
        verifier: &impl ConsensusSignatureVerifier,
    ) -> PosyResult<BTreeMap<(u64, u64), SimplifiedTimeoutCertificate>> {
        let mut by_slot = BTreeMap::new();
        let mut by_id = BTreeMap::new();
        for tc in &self.timeout_certificates {
            tc.verify(epoch, validators, verifier)?;
            if by_slot
                .insert((tc.context.height, tc.context.round), tc.clone())
                .is_some()
                || by_id.insert(tc.id()?, tc).is_some()
            {
                return Err(PosyError::invalid("Sync witness repeats a timeout closure"));
            }
        }
        for qc in &self.quorum_certificates {
            // Bound verification by supplied evidence, never a remote round number.
            if qc.context.round > by_slot.len() as u64 {
                return Err(PosyError::invalid("Sync witness omits timeout closures"));
            }
            let mut last = qc.context.height;
            let mut expected = qc.takeover_tc_id.as_ref();
            for round in (0..qc.context.round).rev() {
                let tc = expected.and_then(|id| by_id.get(id)).ok_or_else(|| {
                    PosyError::invalid("Sync witness omits the referenced timeout closure")
                })?;
                if tc.context.round != round
                    || tc.context.height > last
                    || epoch.lease_index(tc.context.height)?
                        != epoch.lease_index(qc.context.height)?
                {
                    return Err(PosyError::invalid(
                        "Sync timeout closure has incompatible lease or slot",
                    ));
                }
                last = tc.context.height;
                expected = tc.previous_tc_id.as_ref();
            }
            if expected.is_some() {
                return Err(PosyError::invalid(
                    "Sync timeout chain does not start at round zero",
                ));
            }
        }
        Ok(by_slot)
    }
}
