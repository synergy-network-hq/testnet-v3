//! Synthetic isolated durability tests, never provider or platform qualification.
use super::*;
use crate::r1::*;
use sha3::{Digest, Sha3_384};
use std::sync::atomic::{AtomicU64, Ordering};
use synergy_protocol_types::*;
static NEXT: AtomicU64 = AtomicU64::new(0);
struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        Self(std::env::temp_dir().join(format!(
            "r1-journal-synthetic-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        )))
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
fn coordinate() -> R1NetworkCoordinate {
    R1NetworkCoordinate {
        network: R1NetworkRef {
            chain_id: u64::MAX - 111,
            nic: [11; 64],
        },
        genesis: R1GenesisReference {
            profile: R1ProfileRef {
                name: "SYNTHETIC-GENESIS".into(),
                revision: 1,
            },
            digest: [22; 48],
        },
        activated_profiles: R1ProfileSetReference {
            profile: R1ProfileRef {
                name: "SYNTHETIC-PROFILES".into(),
                revision: 1,
            },
            commitment: [33; 64],
        },
    }
}
fn member() -> R1AuthorityMember {
    R1AuthorityMember {
        identity: [1; 48],
        key_id: [5; 48],
        key_version: 7,
        weight: 1,
        signature_bytes: 3309,
    }
}
fn binding() -> R1JournalBinding {
    R1JournalBinding {
        coordinate: coordinate(),
        protocol: [55; 48],
        authority: [44; 48],
        epoch: 1,
        identity: member().identity,
        key_id: member().key_id,
        key_version: 7,
    }
}
fn header() -> R1Header {
    R1Header {
        coordinate: coordinate(),
        protocol_profile: [55; 48],
        epoch: 1,
        height: 1,
        round: 10,
        proposer: [1; 48],
        authority: [44; 48],
        schedule: [77; 48],
        opportunity: [88; 48],
        ledger_parent: coordinate().genesis.digest,
        consensus_parent: R1Parent::Genesis {
            commitment: coordinate().genesis.digest,
        },
        execution_profile: [66; 48],
        execution: R1ExecutionCommitments {
            pre_state: [1; 48],
            post_state: [2; 48],
            receipts: [3; 48],
            payload: [4; 48],
            dependencies: [5; 48],
            resources: [6; 48],
            protocol_effects: [7; 48],
            payload_bytes: 0,
            transaction_count: 0,
            gas_used: 0,
        },
    }
}
fn child(h: &R1Header) -> R1Header {
    let mut n = h.clone();
    n.height += 1;
    n.round += 1;
    n.consensus_parent = h.parent_subject().unwrap();
    n.ledger_parent = h.block_digest().unwrap();
    n.execution.pre_state = h.execution.post_state;
    n.execution.post_state[47] += 1;
    n
}
fn signature(message: &[u8]) -> Vec<u8> {
    let d = Sha3_384::digest(message);
    (0..3309).map(|i| d[i % 48]).collect()
}
struct Synthetic {
    bad_payload: bool,
    bad_key: bool,
}
impl Synthetic {
    fn good() -> Self {
        Self {
            bad_payload: false,
            bad_key: false,
        }
    }
}
impl R1ConsensusVerifier for Synthetic {
    fn authenticate_authority(
        &self,
        h: &R1Header,
    ) -> std::result::Result<Vec<R1AuthorityMember>, R1ProofError> {
        if h.coordinate != coordinate() || h.authority != [44; 48] || h.protocol_profile != [55; 48]
        {
            return Err(R1ProofError::Authority);
        }
        Ok((0..4)
            .map(|i| R1AuthorityMember {
                identity: [i + 1; 48],
                key_id: [i + 5; 48],
                key_version: if self.bad_key { 8 } else { 7 },
                weight: 1,
                signature_bytes: 3309,
            })
            .collect())
    }
    fn verify_proposal_and_execution(&self, _: &R1Header) -> std::result::Result<(), R1ProofError> {
        if self.bad_payload {
            Err(R1ProofError::Payload)
        } else {
            Ok(())
        }
    }
    fn verify_approval(
        &self,
        _: &R1AuthorityMember,
        m: &[u8],
        s: &[u8],
    ) -> std::result::Result<(), R1ProofError> {
        if signature(m) == s {
            Ok(())
        } else {
            Err(R1ProofError::Signature)
        }
    }
    fn verify_finalized_extension(
        &self,
        c: &R1NetworkCoordinate,
        h: u64,
        b: &Digest48,
        t: &R1Header,
    ) -> std::result::Result<(), R1ProofError> {
        if c == &coordinate() && t.height == h + 1 && t.ledger_parent == *b {
            Ok(())
        } else {
            Err(R1ProofError::Parent)
        }
    }
}
fn pending(j: &mut R1SigningJournal, h: &R1Header) -> R1ApprovalReservation {
    match j
        .reserve_ordinary(h, &member(), j.safety_generation().unwrap(), None, None)
        .unwrap()
    {
        R1ReservationOutcome::Pending(p) => p,
        _ => panic!("expected pending"),
    }
}

fn verified(h: R1Header) -> VerifiedR1QuorumCertificate {
    let v = Synthetic::good();
    let mut q = R1QuorumCertificate {
        header: h,
        approvals: vec![],
    };
    for (i, m) in v
        .authenticate_authority(&q.header)
        .unwrap()
        .iter()
        .enumerate()
        .take(3)
    {
        q.approvals.push(R1Approval {
            member_index: i as u32,
            key_version: 7,
            signature: signature(&q.approval_message(m).unwrap()),
        });
    }
    q.into_verified(&v).unwrap()
}

fn anchor() -> VerifiedR1FinalizedAnchor {
    anchor_for(header())
}
fn anchor_for(a: R1Header) -> VerifiedR1FinalizedAnchor {
    let b = child(&a);
    let c = child(&b);
    let v = Synthetic::good();
    let q = |h| {
        let mut q = R1QuorumCertificate {
            header: h,
            approvals: vec![],
        };
        for (i, m) in v
            .authenticate_authority(&q.header)
            .unwrap()
            .iter()
            .enumerate()
            .take(3)
        {
            q.approvals.push(R1Approval {
                member_index: i as u32,
                key_version: 7,
                signature: signature(&q.approval_message(m).unwrap()),
            });
        }
        q
    };
    let proof = R1ThreeQcProof {
        certificates: [q(a), q(b), q(c)],
    };
    R1ThreeQcProof::verify_original(
        &proof.canonical_bytes().unwrap(),
        &coordinate(),
        0,
        &coordinate().genesis.digest,
        &v,
    )
    .unwrap()
}
#[test]
fn reservation_survives_restart_and_replays_original_completed_bytes() {
    let t = Temp::new();
    let mut j = R1SigningJournal::open(&t.0, binding()).unwrap();
    let p = pending(&mut j, &header());
    let original = p.approval_message().to_vec();
    drop(j);
    let mut j = R1SigningJournal::open(&t.0, binding()).unwrap();
    let p = pending(&mut j, &header());
    assert_eq!(p.approval_message(), original);
    let sig = signature(&original);
    j.complete_and_release(&p, &sig, &Synthetic::good())
        .unwrap();
    j.fence(j.safety_generation().unwrap()).unwrap();
    drop(j);
    let mut j = R1SigningJournal::open(&t.0, binding()).unwrap();
    match j
        .reserve_ordinary(&header(), &member(), 0, None, None)
        .unwrap()
    {
        R1ReservationOutcome::Released(r) => {
            assert_eq!(r.signature(), sig);
            assert_eq!(r.approval_message(), original)
        }
        _ => panic!("must replay, never sign"),
    }
}
#[test]
fn authority_global_round_cannot_be_bypassed_by_height_or_proposer_change() {
    let t = Temp::new();
    let mut j = R1SigningJournal::open(&t.0, binding()).unwrap();
    pending(&mut j, &header());
    let mut h = child(&header());
    h.round = header().round;
    h.proposer = [9; 48];
    if let R1Parent::Ordinary { round, .. } = &mut h.consensus_parent {
        *round = 9;
    }
    assert!(matches!(
        j.reserve_ordinary(&h, &member(), 0, None, None),
        Err(R1JournalError::Conflict)
    ));
}
#[test]
fn changed_network_profiles_keys_and_incarnation_cannot_reopen_same_root() {
    let t = Temp::new();
    R1SigningJournal::open(&t.0, binding()).unwrap();
    for i in 0..5 {
        let mut b = binding();
        match i {
            0 => b.coordinate.network.nic[63] ^= 1,
            1 => b.coordinate.genesis.digest[47] ^= 1,
            2 => b.coordinate.activated_profiles.commitment[63] ^= 1,
            3 => b.key_version += 1,
            _ => b.protocol[47] ^= 1,
        };
        assert!(R1SigningJournal::open(&t.0, b).is_err());
    }
}
#[test]
fn suppress_and_intervening_fence_never_release_computed_signature() {
    let t = Temp::new();
    let mut j = R1SigningJournal::open(&t.0, binding()).unwrap();
    let p = pending(&mut j, &header());
    let sig = signature(p.approval_message());
    j.suppress(&p).unwrap();
    assert!(j
        .complete_and_release(&p, &sig, &Synthetic::good())
        .is_err());
    assert!(j
        .reserve_ordinary(&header(), &member(), 0, None, None)
        .is_err());
    let mut h = child(&header());
    h.round += 1;
    let parent = verified(header());
    let p = match j
        .reserve_ordinary(
            &h,
            &member(),
            j.safety_generation().unwrap(),
            Some(&parent),
            None,
        )
        .unwrap()
    {
        R1ReservationOutcome::Pending(p) => p,
        _ => panic!("pending"),
    };
    j.fence(j.safety_generation().unwrap()).unwrap();
    assert!(matches!(
        j.complete_and_release(&p, &signature(p.approval_message()), &Synthetic::good()),
        Err(R1JournalError::Fenced)
    ));
}
#[test]
fn payload_signature_and_key_validation_failure_leaves_reservation_unreleased() {
    let t = Temp::new();
    let mut j = R1SigningJournal::open(&t.0, binding()).unwrap();
    let p = pending(&mut j, &header());
    let sig = signature(p.approval_message());
    assert!(j
        .complete_and_release(
            &p,
            &sig,
            &Synthetic {
                bad_payload: true,
                bad_key: false
            }
        )
        .is_err());
    assert!(j
        .complete_and_release(&p, &vec![0; 3309], &Synthetic::good())
        .is_err());
    assert!(j
        .complete_and_release(
            &p,
            &sig,
            &Synthetic {
                bad_payload: false,
                bad_key: true
            }
        )
        .is_err());
    assert!(matches!(
        j.reserve_ordinary(
            &header(),
            &member(),
            j.safety_generation().unwrap(),
            None,
            None
        )
        .unwrap(),
        R1ReservationOutcome::Pending(_)
    ));
}
#[test]
fn separate_owners_compare_and_commit_one_subject_only() {
    let t = Temp::new();
    let mut a = R1SigningJournal::open(&t.0, binding()).unwrap();
    let mut b = R1SigningJournal::open(&t.0, binding()).unwrap();
    let p = pending(&mut a, &header());
    let mut changed = header();
    changed.execution.payload[47] ^= 1;
    assert!(b
        .reserve_ordinary(&changed, &member(), 0, None, None)
        .is_err());
    b.fence(b.safety_generation().unwrap()).unwrap();
    assert!(a
        .complete_and_release(&p, &signature(p.approval_message()), &Synthetic::good())
        .is_err());
}
#[test]
fn genuine_anchor_proof_cursor_is_contiguous_exact_and_replay_idempotent() {
    let t = Temp::new();
    let mut j = R1SigningJournal::open(&t.0, binding()).unwrap();
    let zero = j.cursor().unwrap();
    let a = anchor();
    let one = j.commit_finalized(&a, &zero).unwrap();
    assert_eq!(one.block_digest(), a.block_digest());
    assert_eq!(one.height(), 1);
    assert_eq!(j.commit_finalized(&a, &one).unwrap(), one);
    assert!(j.commit_finalized(&a, &zero).is_err());
    assert!(j
        .reserve_ordinary(&header(), &member(), 0, None, None)
        .is_err());
    let bytes = j
        .store
        .read_optional_bounded("r1-finality/00000000000000000001.json")
        .unwrap()
        .unwrap();
    let r: Finalized = decode(&bytes).unwrap();
    assert_eq!(r.original_proof, a.original_proof());
    assert_eq!(r.state, a.state_root().as_slice());
    assert_eq!(r.receipts, a.receipts_root().as_slice());
}
#[test]
fn corrupted_slot_or_context_halts_without_releasing() {
    let t = Temp::new();
    let mut j = R1SigningJournal::open(&t.0, binding()).unwrap();
    pending(&mut j, &header());
    std::fs::write(t.0.join(slot_path(header().round)), b"{}").unwrap();
    assert!(j
        .reserve_ordinary(&header(), &member(), 0, None, None)
        .is_err());
    std::fs::write(t.0.join(CONTEXT), b"wrong incarnation").unwrap();
    assert!(j.safety_generation().is_err());
}

#[test]
fn consumed_round_and_pass_fence_are_monotonic_across_restart() {
    let t = Temp::new();
    let mut j = R1SigningJournal::open(&t.0, binding()).unwrap();
    pending(&mut j, &header());
    let mut lower = header();
    lower.round -= 1;
    assert!(j
        .reserve_ordinary(
            &lower,
            &member(),
            j.safety_generation().unwrap(),
            None,
            None
        )
        .is_err());
    j.fence_through_round(j.safety_generation().unwrap(), 20)
        .unwrap();
    drop(j);
    let mut j = R1SigningJournal::open(&t.0, binding()).unwrap();
    let mut h = header();
    h.round = 20;
    assert!(j
        .reserve_ordinary(&h, &member(), j.safety_generation().unwrap(), None, None)
        .is_err());
    assert!(j
        .fence_through_round(j.safety_generation().unwrap(), 19)
        .is_err());
}
#[test]
fn certified_lock_originals_persist_and_unsafe_parent_is_refused() {
    let t = Temp::new();
    let mut j = R1SigningJournal::open(&t.0, binding()).unwrap();
    let a = header();
    let b = child(&a);
    let c = child(&b);
    let parent = verified(b.clone());
    let lock = R1CertifiedLock::from_verified_pair(verified(a.clone()), verified(b)).unwrap();
    let p = match j
        .reserve_ordinary(&c, &member(), 0, Some(&parent), Some(&lock))
        .unwrap()
    {
        R1ReservationOutcome::Pending(p) => p,
        _ => panic!("pending"),
    };
    let safety: Safety = decode(&j.store.read_optional_bounded(SAFETY).unwrap().unwrap()).unwrap();
    assert_eq!(safety.last_approval_round, Some(c.round));
    let stored = safety.lock.unwrap();
    assert_eq!(stored[0], lock.certificates()[0].canonical_qc_bytes());
    assert_eq!(stored[1], lock.certificates()[1].canonical_qc_bytes());
    j.suppress(&p).unwrap();
    let mut next = child(&c);
    next.round += 5;
    let mut bad_parent = a;
    bad_parent.round = 9;
    let parent = verified(bad_parent.clone());
    next.height = 2;
    next.consensus_parent = bad_parent.parent_subject().unwrap();
    next.ledger_parent = bad_parent.block_digest().unwrap();
    next.execution.pre_state = bad_parent.execution.post_state;
    assert!(j
        .reserve_ordinary(
            &next,
            &member(),
            j.safety_generation().unwrap(),
            Some(&parent),
            None
        )
        .is_err());
}

#[test]
fn simultaneous_conflicting_reservations_have_exactly_one_durable_winner() {
    let t = Temp::new();
    let a = R1SigningJournal::open(&t.0, binding()).unwrap();
    let b = R1SigningJournal::open(&t.0, binding()).unwrap();
    let gate = std::sync::Arc::new(std::sync::Barrier::new(2));
    let jobs = [a, b]
        .into_iter()
        .enumerate()
        .map(|(i, mut j)| {
            let gate = gate.clone();
            std::thread::spawn(move || {
                let mut h = header();
                h.execution.payload[47] = i as u8;
                gate.wait();
                j.reserve_ordinary(&h, &member(), 0, None, None).is_ok()
            })
        })
        .collect::<Vec<_>>();
    let winners = jobs
        .into_iter()
        .map(|j| usize::from(j.join().unwrap()))
        .sum::<usize>();
    assert_eq!(winners, 1);
    let j = R1SigningJournal::open(&t.0, binding()).unwrap();
    assert_eq!(j.safety_generation().unwrap(), 1);
}
#[test]
fn storage_failure_after_reservation_cannot_return_release_bytes() {
    let t = Temp::new();
    let mut j = R1SigningJournal::open(&t.0, binding()).unwrap();
    let p = pending(&mut j, &header());
    let path = t.0.join(SAFETY);
    std::fs::remove_file(&path).unwrap();
    std::fs::create_dir(&path).unwrap();
    assert!(j
        .complete_and_release(&p, &signature(p.approval_message()), &Synthetic::good())
        .is_err());
    let bytes = j
        .store
        .read_optional_bounded(slot_path(header().round))
        .unwrap()
        .unwrap();
    let s: Slot = decode(&bytes).unwrap();
    assert!(s.signature.is_none());
}

#[test]
fn missing_safety_after_restart_never_resets_round_pass_or_lock() {
    let t = Temp::new();
    let mut j = R1SigningJournal::open(&t.0, binding()).unwrap();
    let mut h = header();
    h.round = 20;
    pending(&mut j, &h);
    j.fence_through_round(j.safety_generation().unwrap(), 30)
        .unwrap();
    drop(j);
    std::fs::remove_file(t.0.join(SAFETY)).unwrap();
    assert!(R1SigningJournal::open(&t.0, binding()).is_err());
    assert!(!t.0.join(SAFETY).exists());
    std::fs::remove_file(t.0.join(CONTEXT)).unwrap();
    assert!(R1SigningJournal::open(&t.0, binding()).is_err());
    assert!(!t.0.join(CONTEXT).exists());
}

#[test]
fn finality_advancing_during_verification_cannot_release_old_snapshot() {
    struct Racing {
        path: PathBuf,
    }
    impl R1ConsensusVerifier for Racing {
        fn authenticate_authority(
            &self,
            h: &R1Header,
        ) -> std::result::Result<Vec<R1AuthorityMember>, R1ProofError> {
            Synthetic::good().authenticate_authority(h)
        }
        fn verify_proposal_and_execution(
            &self,
            _: &R1Header,
        ) -> std::result::Result<(), R1ProofError> {
            let mut other = R1SigningJournal::open(&self.path, binding()).unwrap();
            let old = other.cursor().unwrap();
            let mut conflicting = header();
            conflicting.execution.payload[0] ^= 1;
            other
                .commit_finalized(&anchor_for(conflicting), &old)
                .unwrap();
            Ok(())
        }
        fn verify_approval(
            &self,
            m: &R1AuthorityMember,
            b: &[u8],
            s: &[u8],
        ) -> std::result::Result<(), R1ProofError> {
            Synthetic::good().verify_approval(m, b, s)
        }
        fn verify_finalized_extension(
            &self,
            _: &R1NetworkCoordinate,
            _: u64,
            _: &Digest48,
            _: &R1Header,
        ) -> std::result::Result<(), R1ProofError> {
            Ok(())
        }
    }
    let t = Temp::new();
    let mut j = R1SigningJournal::open(&t.0, binding()).unwrap();
    let a = header();
    let b = child(&a);
    let c = child(&b);
    let parent = verified(b);
    let p = match j
        .reserve_ordinary(&c, &member(), 0, Some(&parent), None)
        .unwrap()
    {
        R1ReservationOutcome::Pending(p) => p,
        _ => panic!("pending"),
    };
    assert!(j
        .complete_and_release(
            &p,
            &signature(p.approval_message()),
            &Racing { path: t.0.clone() }
        )
        .is_err());
    assert_eq!(j.cursor().unwrap().height(), 1);
    let s: Slot = decode(
        &j.store
            .read_optional_bounded(slot_path(c.round))
            .unwrap()
            .unwrap(),
    )
    .unwrap();
    assert!(s.signature.is_none());
}

#[test]
fn held_writer_uses_same_journal_and_preserves_pending_on_scope_error() {
    let t = Temp::new();
    let mut j = R1SigningJournal::open(&t.0, binding()).unwrap();
    let result: std::result::Result<(), R1JournalError> = j.with_held_writer(|held| {
        let outcome = held.reserve_verified_ordinary(
            &header(),
            &member(),
            0,
            None,
            None,
            &Synthetic::good(),
        )?;
        let R1ReservationOutcome::Pending(p) = outcome else {
            panic!("pending")
        };
        let bytes = held
            .writer()
            .read_optional_bounded(p.relative_path())?
            .unwrap();
        let stored: Slot = decode(&bytes)?;
        assert_eq!(stored.message, p.approval_message());
        assert!(stored.signature.is_none());
        Err(R1JournalError::Conflict)
    });
    assert!(result.is_err());
    drop(j);
    let mut j = R1SigningJournal::open(&t.0, binding()).unwrap();
    assert!(matches!(
        j.reserve_ordinary(&header(), &member(), 1, None, None)
            .unwrap(),
        R1ReservationOutcome::Pending(_)
    ));
}
#[test]
fn held_native_verification_failure_and_missing_outbox_do_not_create_slot() {
    let t = Temp::new();
    let mut j = R1SigningJournal::open(&t.0, binding()).unwrap();
    j.with_held_writer(|held| {
        assert!(held.released_ordinary(&header(), &member()).is_err());
        assert!(held
            .reserve_verified_ordinary(
                &header(),
                &member(),
                0,
                None,
                None,
                &Synthetic {
                    bad_payload: true,
                    bad_key: false
                }
            )
            .is_err());
        assert!(held
            .writer()
            .read_optional_bounded(slot_path(header().round))?
            .is_none());
        Ok(())
    })
    .unwrap();
    assert_eq!(j.safety_generation().unwrap(), 0);
}
#[test]
fn held_original_completion_replay_never_exposes_a_pending_signature() {
    let t = Temp::new();
    let mut j = R1SigningJournal::open(&t.0, binding()).unwrap();
    j.with_held_writer(|held| {
        let R1ReservationOutcome::Pending(p) = held.reserve_verified_ordinary(
            &header(),
            &member(),
            0,
            None,
            None,
            &Synthetic::good(),
        )?
        else {
            panic!("pending")
        };
        assert!(held.released_ordinary(&header(), &member()).is_err());
        // Synthetic durability-only completion through private test access.
        // Production SDK owns private computation+same-slot completion itself.
        let signature = signature(p.approval_message());
        held.access
            .complete_and_release(&p, &signature, &Synthetic::good())?;
        let released = held.released_ordinary(&header(), &member())?;
        assert_eq!(released.signature(), signature);
        Ok(())
    })
    .unwrap();
}
