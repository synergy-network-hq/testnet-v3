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

#[cfg(test)]
mod bounded_proof_tests {
    use super::*;
    use crate::{
        ConsensusObjectContext, ParticipantSignature, SimplifiedFinalityParent, TimeoutVote,
        ValidatorRecord, ValidatorStatus,
    };

    struct TestVerifier;
    impl ConsensusSignatureVerifier for TestVerifier {
        fn verify_consensus_signature(
            &self,
            _: &str,
            _: &[u8],
            _: &ValidatorRecord,
            _: &str,
            _: u64,
            signature: &[u8],
        ) -> PosyResult<()> {
            if signature == [1] {
                Ok(())
            } else {
                Err(PosyError::invalid("test signature refused"))
            }
        }
    }
    struct Fixture(std::path::PathBuf);
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn sparse_lease_proof_retains_actual_work_budget_and_exact_authority() {
        let root = Fixture(
            std::env::temp_dir().join(format!(
                "posy-bounded-proof-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            )),
        );
        let registry = FrozenValidatorRegistry::new(
            7,
            (0..5)
                .map(|i| ValidatorRecord {
                    validator_id: format!("validator-{i}"),
                    consensus_key_id: format!("key-{i}"),
                    frozen_voting_weight: 1,
                    status: ValidatorStatus::Active,
                })
                .collect(),
        )
        .unwrap();
        let epoch = SimplifiedEpochContext::from_frozen_registry(
            99999,
            "canary-proof-fixture".into(),
            7,
            1,
            512,
            "a".repeat(64),
            "b".repeat(64),
            &registry,
        )
        .unwrap();
        epoch.validate_against(&registry).unwrap();
        let parent = SimplifiedFinalityParent::Genesis {
            genesis_hash: "c".repeat(64),
            block_id: "genesis".into(),
            reference_id: "d".repeat(64),
        };
        let mut certificates: Vec<SimplifiedTimeoutCertificate> = Vec::new();
        for round in 0..5 {
            let predecessor = certificates.last().map(|tc| tc.id().unwrap());
            let tc = SimplifiedTimeoutCertificate::from_votes(
                (0..4)
                    .map(|i| TimeoutVote {
                        context: ConsensusObjectContext::for_height(&epoch, 1, round).unwrap(),
                        lease_index: 0,
                        timed_out_proposer: epoch.authorized_proposer(1, round).unwrap().into(),
                        highest_parent: parent.clone(),
                        previous_tc_id: predecessor.clone(),
                        last_voted_candidate: None,
                        validator_id: format!("validator-{i}"),
                        key_id: format!("key-{i}"),
                        signature: vec![1],
                    })
                    .collect(),
            )
            .unwrap();
            certificates.push(tc);
        }
        let qc = SimplifiedQuorumCertificate {
            context: ConsensusObjectContext::for_height(&epoch, 1, 5).unwrap(),
            block_id: "block-one".into(),
            parent_block_id: "genesis".into(),
            parent,
            takeover_tc_id: Some(certificates.last().unwrap().id().unwrap()),
            protected_execution_root: "e".repeat(64),
            participants: (0..4)
                .map(|i| ParticipantSignature {
                    validator_id: format!("validator-{i}"),
                    key_id: format!("key-{i}"),
                    signature: vec![1],
                })
                .collect(),
        };
        let store = VerifiedTimeoutCertificateStore::new(&root.0).unwrap();
        for tc in &certificates {
            store
                .put_verified(tc, &epoch, &registry, &TestVerifier)
                .unwrap();
        }
        certificates.reverse();
        let collect = |qc: &SimplifiedQuorumCertificate, budget: &mut u64| {
            FinalitySyncWitness::collect_verified_timeouts_bounded(
                qc,
                &store,
                &epoch,
                &registry,
                &TestVerifier,
                budget,
            )
        };
        // Three QCs at round five previously charged 150 hypothetical lease
        // slot reads. Their actual timeout closures require 15 verifications.
        assert!(qc.context.round * epoch.leader_lease_blocks * 3 > 128);
        let mut budget = 15;
        for remaining in [10, 5, 0] {
            assert_eq!(collect(&qc, &mut budget).unwrap(), certificates);
            assert_eq!(budget, remaining);
        }
        assert_eq!(budget, 0);
        assert!(matches!(
            collect(&qc, &mut budget),
            Err(PosyError::ResourcePressure(_))
        ));
        assert_eq!(budget, 0);
        let mut substituted = qc.clone();
        substituted.takeover_tc_id = Some("f".repeat(64));
        assert!(collect(&substituted, &mut 128).is_err());
        let mut bad_signature = qc;
        bad_signature.participants[0].signature[0] = 2;
        assert!(collect(&bad_signature, &mut 128).is_err());
    }
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
            for tc in Self::collect_verified_timeouts(qc, store, epoch, validators, verifier)? {
                timeouts.insert((tc.context.height, tc.context.round), tc);
            }
        }
        Ok(Self {
            quorum_certificates,
            timeout_certificates: timeouts.into_values().collect(),
        })
    }

    /// Resolve one QC under its original authority; a three-QC witness that
    /// spans epochs must not verify any QC or timeout under substituted keys.
    pub fn collect_verified_timeouts(
        qc: &SimplifiedQuorumCertificate,
        store: &VerifiedTimeoutCertificateStore,
        epoch: &SimplifiedEpochContext,
        validators: &FrozenValidatorRegistry,
        verifier: &impl ConsensusSignatureVerifier,
    ) -> PosyResult<Vec<SimplifiedTimeoutCertificate>> {
        qc.verify(epoch, validators, verifier)?;
        let mut timeouts = Vec::new();
        let first = epoch.epoch_start_height
            + epoch.lease_index(qc.context.height)? * epoch.leader_lease_blocks;
        let mut last = qc.context.height;
        let mut expected = qc.takeover_tc_id.clone();
        for round in (0..qc.context.round).rev() {
            let mut found = None;
            for height in (first..=last).rev() {
                if let Some(tc) = store.get_verified(height, round, epoch, validators, verifier)? {
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
            timeouts.push(tc);
        }
        if expected.is_some() {
            return Err(PosyError::invalid(
                "Sync timeout chain does not start at round zero",
            ));
        }
        Ok(timeouts)
    }

    /// Public proof collection uses the existing bounded slot index, then
    /// authenticates only actual candidate records. Empty governed lease slots
    /// must not exhaust a signature-verification budget. The budget is shared
    /// by the caller across the complete three-QC witness.
    pub fn collect_verified_timeouts_bounded(
        qc: &SimplifiedQuorumCertificate,
        store: &VerifiedTimeoutCertificateStore,
        epoch: &SimplifiedEpochContext,
        validators: &FrozenValidatorRegistry,
        verifier: &impl ConsensusSignatureVerifier,
        remaining: &mut u64,
    ) -> PosyResult<Vec<SimplifiedTimeoutCertificate>> {
        qc.verify(epoch, validators, verifier)?;
        if qc.context.round == 0 {
            return Ok(Vec::new());
        }
        let before = qc
            .context
            .height
            .checked_add(1)
            .ok_or_else(|| PosyError::invalid("timeout proof height overflow"))?;
        let slots =
            store.get_slots_for_lease_before(qc.context.height, before, epoch, validators)?;
        let mut timeouts = Vec::new();
        let mut last = qc.context.height;
        let mut expected = qc.takeover_tc_id.clone();
        for round in (0..qc.context.round).rev() {
            let mut found = None;
            for &(height, candidate_round) in slots.iter().rev() {
                if candidate_round != round || height > last {
                    continue;
                }
                *remaining = remaining.checked_sub(1).ok_or_else(|| {
                    PosyError::ResourcePressure(
                        "proof timeout verification capacity exhausted".into(),
                    )
                })?;
                let tc = store
                    .get_verified(height, round, epoch, validators, verifier)?
                    .ok_or_else(|| {
                        PosyError::NotReady("indexed timeout record disappeared".into())
                    })?;
                if Some(tc.id()?) == expected {
                    found = Some(tc);
                    break;
                }
            }
            let tc = found.ok_or_else(|| {
                PosyError::NotReady(
                    "Sync witness lacks the referenced lease timeout closure".into(),
                )
            })?;
            last = tc.context.height;
            expected = tc.previous_tc_id.clone();
            timeouts.push(tc);
        }
        if expected.is_some() {
            return Err(PosyError::invalid(
                "Sync timeout chain does not start at round zero",
            ));
        }
        Ok(timeouts)
    }

    /// Require the complete and exact takeover closure rather than admitting
    /// an unrelated, albeit valid, timeout as part of an epoch transition.
    pub(crate) fn verify_exact_timeout_closure(
        &self,
        epoch: &SimplifiedEpochContext,
        validators: &FrozenValidatorRegistry,
        verifier: &impl ConsensusSignatureVerifier,
    ) -> PosyResult<()> {
        let closure = self.verified_timeout_closure(epoch, validators, verifier)?;
        let by_id = closure
            .values()
            .map(|tc| Ok((tc.id()?, tc)))
            .collect::<PosyResult<BTreeMap<_, _>>>()?;
        let mut referenced = BTreeSet::new();
        let mut by_lease_round = BTreeMap::new();
        for qc in &self.quorum_certificates {
            let lease = epoch.lease_index(qc.context.height)?;
            let mut predecessor = qc.takeover_tc_id.as_deref();
            for _ in 0..qc.context.round {
                let id =
                    predecessor.ok_or_else(|| PosyError::invalid("missing epoch timeout proof"))?;
                let timeout = by_id
                    .get(id)
                    .ok_or_else(|| PosyError::invalid("missing epoch timeout proof"))?;
                if by_lease_round
                    .insert((lease, timeout.context.round), id)
                    .is_some_and(|prior| prior != id)
                {
                    return Err(PosyError::Conflict(
                        "epoch closing QCs reference conflicting timeout closures".into(),
                    ));
                }
                if let Some(certified) = self
                    .quorum_certificates
                    .iter()
                    .find(|certified| certified.context.height == timeout.context.height)
                {
                    let wrong_carry = match timeout.mandatory_carry_candidate()? {
                        Some(candidate) => candidate != certified.subject()?,
                        None => false,
                    };
                    if timeout.highest_parent()? != certified.parent || wrong_carry {
                        return Err(PosyError::Conflict(
                            "epoch timeout diverges from the certified parent or mandatory carry"
                                .into(),
                        ));
                    }
                }
                referenced.insert(id);
                predecessor = timeout.previous_tc_id.as_deref();
            }
            if predecessor.is_some() {
                return Err(PosyError::invalid("invalid epoch timeout proof ancestry"));
            }
        }
        if referenced.len() != by_id.len() {
            return Err(PosyError::invalid(
                "epoch witness includes an unreferenced timeout",
            ));
        }
        Ok(())
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
