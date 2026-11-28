//! Isolated, public deterministic fixtures. These test consensus predicates,
//! not APQE qualification, live identities, or production profile activation.
use super::*;
use sha3::{Digest, Sha3_384};
use synergy_protocol_types::*;

fn coordinate() -> R1NetworkCoordinate {
    R1NetworkCoordinate {
        network: R1NetworkRef {
            chain_id: u64::MAX - 9,
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
struct Synthetic {
    weights: Vec<u128>,
    bad_signature: bool,
    bad_payload: bool,
    bad_ancestry: bool,
}
impl Synthetic {
    fn good() -> Self {
        Self {
            weights: vec![1; 4],
            bad_signature: false,
            bad_payload: false,
            bad_ancestry: false,
        }
    }
}
impl R1ConsensusVerifier for Synthetic {
    fn authenticate_authority(&self, h: &R1Header) -> Result<Vec<R1AuthorityMember>> {
        h.coordinate
            .ensure_matches(&coordinate())
            .map_err(|_| R1ProofError::Context)?;
        if h.authority != [44; 48]
            || h.protocol_profile != [55; 48]
            || h.execution_profile != [66; 48]
            || h.epoch != 0
        {
            return Err(R1ProofError::Authority);
        }
        Ok(self
            .weights
            .iter()
            .enumerate()
            .map(|(i, w)| R1AuthorityMember {
                identity: [i as u8 + 1; 48],
                key_id: [i as u8 + 5; 48],
                key_version: 7,
                weight: *w,
                signature_bytes: 48,
            })
            .collect())
    }
    fn verify_proposal_and_execution(&self, _: &R1Header) -> Result<()> {
        if self.bad_payload {
            Err(R1ProofError::Payload)
        } else {
            Ok(())
        }
    }
    fn verify_approval(&self, _: &R1AuthorityMember, m: &[u8], s: &[u8]) -> Result<()> {
        if self.bad_signature || Sha3_384::digest(m).as_slice() != s {
            Err(R1ProofError::Signature)
        } else {
            Ok(())
        }
    }
    fn verify_finalized_extension(
        &self,
        _: &R1NetworkCoordinate,
        h: u64,
        b: &Digest48,
        target: &R1Header,
    ) -> Result<()> {
        if self.bad_ancestry || h != 0 || *b != coordinate().genesis.digest || target.height != 1 {
            Err(R1ProofError::FinalizedConflict)
        } else {
            Ok(())
        }
    }
}
fn first() -> R1Header {
    R1Header {
        coordinate: coordinate(),
        protocol_profile: [55; 48],
        epoch: 0,
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
fn child(p: &R1Header) -> R1Header {
    let mut h = p.clone();
    h.height += 1;
    h.round += 1;
    h.consensus_parent = p.parent_subject().unwrap();
    h.ledger_parent = p.block_digest().unwrap();
    h.execution.pre_state = p.execution.post_state;
    h.execution.post_state[47] += 1;
    h
}
fn sign(h: R1Header, v: &Synthetic, indices: &[u32]) -> R1QuorumCertificate {
    let mut q = R1QuorumCertificate {
        header: h,
        approvals: Vec::new(),
    };
    let members = v.authenticate_authority(&q.header).unwrap();
    q.approvals = indices
        .iter()
        .map(|i| R1Approval {
            member_index: *i,
            key_version: 7,
            signature: Sha3_384::digest(q.approval_message(&members[*i as usize]).unwrap())
                .to_vec(),
        })
        .collect();
    q
}
fn proof() -> R1ThreeQcProof {
    let a = first();
    let b = child(&a);
    let c = child(&b);
    let v = Synthetic::good();
    R1ThreeQcProof {
        certificates: [
            sign(a, &v, &[0, 1, 2]),
            sign(b, &v, &[0, 1, 2]),
            sign(c, &v, &[0, 1, 2]),
        ],
    }
}
fn verify(p: &R1ThreeQcProof, v: &Synthetic) -> Result<VerifiedR1FinalizedAnchor> {
    R1ThreeQcProof::verify_original(
        &p.canonical_bytes()?,
        &coordinate(),
        0,
        &coordinate().genesis.digest,
        v,
    )
}
#[test]
fn exact_three_qc_finalizes_first_preserving_all_48_bytes_and_originals() {
    let p = proof();
    let bytes = p.canonical_bytes().unwrap();
    let anchor = verify(&p, &Synthetic::good()).unwrap();
    assert_eq!(anchor.height(), 1);
    assert_eq!(anchor.coordinate(), &coordinate());
    assert_eq!(
        anchor.block_digest(),
        &p.certificates[0].header.block_digest().unwrap()
    );
    assert_eq!(
        anchor.state_root(),
        &p.certificates[0].header.execution.post_state
    );
    assert_eq!(anchor.receipts_root(), &[3; 48]);
    assert_eq!(anchor.original_proof(), bytes);
    assert_eq!(R1ThreeQcProof::decode(&bytes).unwrap(), p);
}
#[test]
fn every_network_coordinate_component_is_bound() {
    let bytes = proof().canonical_bytes().unwrap();
    for i in 0..6 {
        let mut c = coordinate();
        match i {
            0 => c.network.chain_id -= 1,
            1 => c.network.nic[63] ^= 1,
            2 => c.genesis.digest[47] ^= 1,
            3 => c.genesis.profile.revision += 1,
            4 => c.activated_profiles.commitment[63] ^= 1,
            _ => c.activated_profiles.profile.revision += 1,
        };
        assert!(R1ThreeQcProof::verify_original(
            &bytes,
            &c,
            0,
            &coordinate().genesis.digest,
            &Synthetic::good()
        )
        .is_err());
    }
}
#[test]
fn certificate_rejects_wrong_signature_key_version_and_unknown_signer() {
    for kind in 0..3 {
        let mut p = proof();
        let a = &mut p.certificates[1].approvals[2];
        match kind {
            0 => a.signature[47] ^= 1,
            1 => a.key_version += 1,
            _ => a.member_index = 100,
        };
        assert!(verify(&p, &Synthetic::good()).is_err());
    }
}
#[test]
fn duplicate_or_unsorted_indices_reject_instead_of_being_dropped() {
    let mut p = proof();
    p.certificates[0].approvals[1].member_index = 0;
    assert!(p.canonical_bytes().is_err());
    assert!(p.certificates[0].verify(&Synthetic::good()).is_err());
    let mut p = proof();
    p.certificates[1].approvals.swap(0, 1);
    assert!(p.canonical_bytes().is_err());
}
#[test]
fn strict_count_and_weight_both_use_frozen_network_denominator() {
    let mut p = proof();
    p.certificates[0].approvals.pop();
    assert!(verify(&p, &Synthetic::good()).is_err());
    let v = Synthetic {
        weights: vec![90, 4, 3, 3],
        ..Synthetic::good()
    };
    let h = first();
    let q = sign(h, &v, &[1, 2, 3]);
    assert_eq!(q.verify(&v), Err(R1ProofError::Quorum));
    let v = Synthetic {
        weights: vec![u128::MAX - 3, 1, 1, 1],
        ..Synthetic::good()
    };
    assert!(sign(first(), &v, &[0, 1, 2]).verify(&v).is_ok());
}
#[test]
fn parent_height_round_and_execution_link_are_mandatory() {
    for kind in 0..5 {
        let mut p = proof();
        let h = &mut p.certificates[1].header;
        match kind {
            0 => h.height += 1,
            1 => h.round += 1,
            2 => h.ledger_parent[47] ^= 1,
            3 => h.execution.pre_state[47] ^= 1,
            _ => h.epoch += 1,
        };
        assert!(verify(&p, &Synthetic::good()).is_err());
    }
}
#[test]
fn trusted_payload_signature_and_ancestry_failure_never_mint_token() {
    for v in [
        Synthetic {
            bad_signature: true,
            ..Synthetic::good()
        },
        Synthetic {
            bad_payload: true,
            ..Synthetic::good()
        },
        Synthetic {
            bad_ancestry: true,
            ..Synthetic::good()
        },
    ] {
        assert!(verify(&proof(), &v).is_err());
    }
    let b = proof().canonical_bytes().unwrap();
    assert!(
        R1ThreeQcProof::verify_original(&b, &coordinate(), 1, &[99; 48], &Synthetic::good())
            .is_err()
    );
}
#[test]
fn bounded_strict_decode_rejects_truncation_trailing_unknown_variant_and_length_bombs() {
    let bytes = proof().canonical_bytes().unwrap();
    for end in [0, 1, 4, 20, bytes.len() - 1] {
        assert!(R1ThreeQcProof::decode(&bytes[..end]).is_err());
    }
    let mut extra = bytes.clone();
    extra.push(0);
    assert!(R1ThreeQcProof::decode(&extra).is_err());
    let mut unknown = bytes.clone();
    let tag = 4 + b"POSY/FINALITY/R1".len() + 2;
    unknown[tag] = 9;
    assert!(R1ThreeQcProof::decode(&unknown).is_err());
    let mut bomb = bytes;
    bomb[..4].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(R1ThreeQcProof::decode(&bomb).is_err());
    assert!(R1ThreeQcProof::decode(&vec![0; MAX_PROOF_BYTES + 1]).is_err());
}
#[test]
fn independent_header_frame_uses_little_endian_and_binds_tail_bytes() {
    let h = first();
    let raw = h.canonical_bytes().unwrap();
    assert_eq!(&raw[..2], &[1, 0]);
    assert_eq!(&raw[2..10], &(u64::MAX - 9).to_le_bytes());
    let mut expected = Vec::new();
    expected.extend_from_slice(&13u32.to_le_bytes());
    expected.extend_from_slice(b"POSY/BLOCK/R1");
    expected.extend_from_slice(&[1, 0]);
    expected.extend_from_slice(&raw);
    assert_eq!(
        h.block_digest().unwrap().as_slice(),
        Sha3_384::digest(&expected).as_slice()
    );
    let mut changed = h.clone();
    changed.execution.receipts[47] ^= 1;
    assert_ne!(h.block_digest().unwrap(), changed.block_digest().unwrap());
}

#[test]
fn key_reference_binds_full_public_key_and_generation() {
    let key = [17; 1952];
    let id = consensus_key_id(&key, 7).unwrap();
    let mut changed = key;
    changed[1951] ^= 1;
    assert_ne!(id, consensus_key_id(&changed, 7).unwrap());
    assert_ne!(id, consensus_key_id(&key, 8).unwrap());
    assert!(consensus_key_id(&key[..1951], 7).is_err());
    assert!(consensus_key_id(&key, 0).is_err());
}

#[test]
fn collector_preserves_originals_and_signer_subsets_do_not_change_block_identity() {
    let v = Synthetic::good();
    let a = sign(first(), &v, &[0, 1, 2]);
    let b = sign(first(), &v, &[0, 2, 3]);
    let mut reversed = a.approvals.clone();
    reversed.reverse();
    let verified = R1QuorumCertificate::assemble(a.header.clone(), reversed, &v).unwrap();
    assert_eq!(verified.certificate(), &a);
    assert_eq!(
        verified.subject().unwrap(),
        b.header.parent_subject().unwrap()
    );
    assert_ne!(verified.canonical_qc_bytes(), b.canonical_bytes().unwrap());
    assert_eq!(
        R1QuorumCertificate::decode_canonical(verified.canonical_qc_bytes()).unwrap(),
        a
    );
}

#[test]
fn invalid_original_signature_never_reaches_execution() {
    struct Counted {
        inner: Synthetic,
        executions: std::cell::Cell<usize>,
    }
    impl R1ConsensusVerifier for Counted {
        fn authenticate_authority(&self, h: &R1Header) -> Result<Vec<R1AuthorityMember>> {
            self.inner.authenticate_authority(h)
        }
        fn verify_approval(
            &self,
            m: &R1AuthorityMember,
            message: &[u8],
            signature: &[u8],
        ) -> Result<()> {
            self.inner.verify_approval(m, message, signature)
        }
        fn verify_proposal_and_execution(&self, h: &R1Header) -> Result<()> {
            self.executions.set(self.executions.get() + 1);
            self.inner.verify_proposal_and_execution(h)
        }
        fn verify_finalized_extension(
            &self,
            n: &R1NetworkCoordinate,
            height: u64,
            block: &Digest48,
            h: &R1Header,
        ) -> Result<()> {
            self.inner.verify_finalized_extension(n, height, block, h)
        }
    }
    let v = Counted {
        inner: Synthetic::good(),
        executions: std::cell::Cell::new(0),
    };
    let valid = sign(first(), &v.inner, &[0, 1, 2]);
    let mut bad = valid.clone();
    // Last approval invalid: the earlier valid originals cannot admit execution.
    bad.approvals.last_mut().unwrap().signature[0] ^= 1;
    assert_eq!(bad.verify(&v), Err(R1ProofError::Signature));
    assert_eq!(v.executions.get(), 0);
    valid.verify(&v).unwrap();
    assert_eq!(v.executions.get(), 1);
}

#[test]
fn collector_rejects_duplicate_unknown_bad_signature_and_insufficient_quorum() {
    let v = Synthetic::good();
    let q = sign(first(), &v, &[0, 1, 2]);
    for kind in 0..4 {
        let mut votes = q.approvals.clone();
        match kind {
            0 => votes.push(votes[0].clone()),
            1 => votes[2].member_index = 99,
            2 => votes[2].signature[0] ^= 1,
            _ => {
                votes.pop();
            }
        };
        assert!(R1QuorumCertificate::assemble(q.header.clone(), votes, &v).is_err());
    }
    let mut bytes = q.canonical_bytes().unwrap();
    bytes.push(0);
    assert!(R1QuorumCertificate::decode_canonical(&bytes).is_err());
}

#[test]
fn frozen_authority_digest_binds_interval_schedule_keys_weights_and_full_network() {
    let v = Synthetic::good();
    let mut members = v.authenticate_authority(&first()).unwrap();
    for m in &mut members {
        m.signature_bytes = 3309;
    }
    let n = coordinate();
    let digest = |members: &[R1AuthorityMember], last, schedule| {
        R1AuthoritySubject {
            network: &n.network,
            activated_profiles: &n.activated_profiles,
            protocol_profile: [55; 48],
            epoch: 0,
            first_height: 1,
            last_height: last,
            schedule,
            members,
        }
        .digest()
    };
    let a = digest(&members, 1000, [77; 48]).unwrap();
    assert_ne!(a, digest(&members, 999, [77; 48]).unwrap());
    assert_ne!(a, digest(&members, 1000, [78; 48]).unwrap());
    members[0].weight = 2;
    assert_ne!(a, digest(&members, 1000, [77; 48]).unwrap());
    members[0].weight = 1;
    members[0].key_id[47] ^= 1;
    assert_ne!(a, digest(&members, 1000, [77; 48]).unwrap());
    members.swap(0, 1);
    assert!(digest(&members, 1000, [77; 48]).is_err());
}

struct SyntheticClient(Synthetic);
impl R1ClientFinalityVerifier for SyntheticClient{
 fn authenticate_authority(&self,h:&R1Header)->Result<Vec<R1AuthorityMember>>{self.0.authenticate_authority(h)}
 fn verify_certified_header(&self,h:&R1Header)->Result<()>{h.validate_shape()}
 fn verify_approval(&self,m:&R1AuthorityMember,b:&[u8],s:&[u8])->Result<()>{self.0.verify_approval(m,b,s)}
 fn verify_finalized_extension(&self,c:&R1NetworkCoordinate,h:u64,b:&Digest48,t:&R1Header)->Result<()>{self.0.verify_finalized_extension(c,h,b,t)}
}
#[test]fn client_anchor_preserves_original_certification_without_claiming_execution(){
 let p=proof();let bytes=p.canonical_bytes().unwrap();let mut v=Synthetic::good();v.bad_payload=true;
 assert!(verify(&p,&v).is_err());
 let client=R1ThreeQcProof::verify_client_original(&bytes,&coordinate(),0,&coordinate().genesis.digest,&SyntheticClient(v)).unwrap();
 assert_eq!(client.height(),1);assert_eq!(client.original_proof(),bytes);
 assert_eq!(client.block_digest(),&p.certificates[0].header.block_digest().unwrap());
 assert_eq!(client.state_root(),&p.certificates[0].header.execution.post_state);
}
#[test]fn client_certification_never_skips_original_signatures_quorum_or_cursor(){
 for kind in 0..4{
  let mut p=proof();let mut v=Synthetic::good();
  match kind{
   0=>p.certificates[0].approvals[0].signature[0]^=1,
   1=>{p.certificates[0].approvals.pop();},
   2=>v.bad_ancestry=true,
   _=>p.certificates[2].header.coordinate.network.nic[63]^=1,
  }
  assert!(R1ThreeQcProof::verify_client_original(&p.canonical_bytes().unwrap(),&coordinate(),0,&coordinate().genesis.digest,&SyntheticClient(v)).is_err());
 }
 let mut bytes=proof().canonical_bytes().unwrap();bytes.push(0);
 assert!(R1ThreeQcProof::verify_client_original(&bytes,&coordinate(),0,&coordinate().genesis.digest,&SyntheticClient(Synthetic::good())).is_err());
}

#[test]
fn collector_counts_original_signers_once_and_emits_sorted_verified_qc() {
    let verifier = Synthetic::good();
    let qc = sign(first(), &verifier, &[0, 1, 2]);
    let mut collector = R1ApprovalCollector::new(qc.header.clone(), &verifier).unwrap();
    for index in [2, 2, 0] {
        assert!(collector.accept(qc.approvals[index].clone(), &verifier).unwrap().is_none());
    }
    assert_eq!(collector.approval_count(), 2);
    let checked = collector.accept(qc.approvals[1].clone(), &verifier).unwrap().unwrap();
    assert_eq!(checked.certificate(), &qc);
    assert_eq!(collector.approval_count(), 3);
}
#[test]
fn collector_rejects_bad_signatures_without_consuming_a_signer() {
    let verifier = Synthetic::good();
    let qc = sign(first(), &verifier, &[0, 1, 2]);
    let mut collector = R1ApprovalCollector::new(qc.header.clone(), &verifier).unwrap();
    let mut corrupt = qc.approvals[0].clone();
    corrupt.signature[0] ^= 1;
    assert!(matches!(collector.accept(corrupt, &verifier), Err(R1ProofError::Signature)));
    assert_eq!(collector.approval_count(), 0);
    let mut changed = qc.approvals[0].clone();
    changed.key_version += 1;
    assert!(matches!(collector.accept(changed, &verifier), Err(R1ProofError::Signature)));
    assert_eq!(collector.approval_count(), 0);
    assert!(collector.accept(qc.approvals[0].clone(), &verifier).unwrap().is_none());
}
#[test]
fn collector_never_combines_count_and_weight_subsets_or_reuses_changed_authority() {
    let verifier = Synthetic { weights: vec![1,1,1,7], ..Synthetic::good() };
    let qc = sign(first(), &verifier, &[0,1,2,3]);
    let mut collector = R1ApprovalCollector::new(qc.header.clone(), &verifier).unwrap();
    for approval in &qc.approvals[..3] {
        assert!(collector.accept(approval.clone(), &verifier).unwrap().is_none());
    }
    let changed = Synthetic::good();
    assert!(matches!(collector.accept(qc.approvals[3].clone(), &changed), Err(R1ProofError::Authority)));
    assert_eq!(collector.approval_count(),3);
    assert!(collector.accept(qc.approvals[3].clone(), &verifier).unwrap().is_some());
}
#[test]
fn collector_rechecks_payload_before_emitting_and_never_creates_signing_authority() {
    let verifier = Synthetic::good();
    let qc = sign(first(), &verifier, &[0,1,2]);
    let invalid = Synthetic { bad_payload: true, ..Synthetic::good() };
    assert!(matches!(R1ApprovalCollector::new(qc.header.clone(), &invalid), Err(R1ProofError::Payload)));
    let mut collector = R1ApprovalCollector::new(qc.header.clone(), &verifier).unwrap();
    collector.accept(qc.approvals[0].clone(), &verifier).unwrap();
    collector.accept(qc.approvals[1].clone(), &verifier).unwrap();
    assert!(matches!(collector.accept(qc.approvals[2].clone(), &invalid), Err(R1ProofError::Payload)));
    assert!(collector.accept(qc.approvals[2].clone(), &verifier).unwrap().is_some());
}

#[test]
fn lock_requires_direct_verified_pair_and_preserves_both_original_certificates() {
    let v = Synthetic::good();
    let p = proof();
    let a = p.certificates[0].clone().into_verified(&v).unwrap();
    let b = p.certificates[1].clone().into_verified(&v).unwrap();
    let expected = a.canonical_qc_bytes().to_vec();
    let lock = R1CertifiedLock::from_verified_pair(a,b).unwrap();
    assert_eq!(lock.header(), &p.certificates[0].header);
    assert_eq!(lock.certificates()[0].canonical_qc_bytes(), expected);
}
#[test]
fn lock_rejects_certified_unrelated_round_and_execution_ancestry() {
    let v = Synthetic::good();
    let p = proof();
    for change in 0..3 {
        let a = p.certificates[0].clone().into_verified(&v).unwrap();
        let mut h = p.certificates[1].header.clone();
        match change {
            0 => h.round += 1,
            1 => h.execution.pre_state[47] ^= 1,
            _ => h.execution_profile[47] ^= 1,
        }
        let accept = Synthetic::good();
        // A different execution profile is not accepted by this trusted fixture.
        // Its rejection already occurs before a verified QC can exist.
        if change == 2 {
            let mut wrong_profile = p.certificates[1].clone();
            wrong_profile.header = h;
            assert!(wrong_profile.into_verified(&accept).is_err());
            continue;
        }
        let b = sign(h,&accept,&[0,1,2]).into_verified(&accept).unwrap();
        assert!(R1CertifiedLock::from_verified_pair(a,b).is_err());
    }
}

fn initial_ordinary_header() -> R1Header {
    let mut h=first(); h.epoch=1; h.round=1; h
}
#[test]
fn initial_opportunity_has_independent_sha3_vector_and_no_current_block_cycle() {
    let mut h=initial_ordinary_header();
    let digest=h.initial_ordinary_opportunity_digest().unwrap();
    let hex=digest.iter().map(|b|format!("{b:02x}")).collect::<String>();
    // Independent Python struct/hashlib, complete synthetic coordinate/raw48.
    assert_eq!(hex,"2ece238a2fb6c7c8024249eff62b4aebd274824d439e7e35359828e4b5e45fdbd90b7f84eed6f63c9c843ae08943693c");
    h.opportunity=digest;
    h.execution.payload[47]^=1;
    assert_eq!(h.initial_ordinary_opportunity_digest().unwrap(),digest);
}
#[test]
fn initial_opportunity_binds_full_coordinate_authority_schedule_and_proposer() {
    let h=initial_ordinary_header();
    let expected=h.initial_ordinary_opportunity_digest().unwrap();
    for field in 0..7 {
        let mut other=h.clone();
        match field {
            0=>other.coordinate.network.nic[63]^=1,
            1=>{other.coordinate.genesis.digest[47]^=1;
                other.ledger_parent=other.coordinate.genesis.digest;
                other.consensus_parent=R1Parent::Genesis{commitment:other.coordinate.genesis.digest};},
            2=>other.coordinate.activated_profiles.commitment[63]^=1,
            3=>other.protocol_profile[47]^=1,
            4=>other.authority[47]^=1,
            5=>other.schedule[47]^=1,
            _=>other.proposer[47]^=1,
        }
        assert_ne!(other.initial_ordinary_opportunity_digest().unwrap(),expected);
    }
}
#[test]
fn initial_opportunity_never_fabricates_pass_recovery_or_epoch_handoff() {
    let h=initial_ordinary_header();
    let mut next=child(&h);
    next.epoch=1;
    assert!(next.initial_ordinary_opportunity_digest().is_ok());
    next.round+=1;
    assert!(next.initial_ordinary_opportunity_digest().is_err());
    next=child(&h);next.epoch=2;
    assert!(next.initial_ordinary_opportunity_digest().is_err());
    let mut late=h;late.height=1001;late.round=1001;
    assert!(late.initial_ordinary_opportunity_digest().is_err());
}
