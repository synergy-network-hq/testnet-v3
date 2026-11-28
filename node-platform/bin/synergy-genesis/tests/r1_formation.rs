//! Five-participant public synthetic registry through the actual native verifier.
//! Root-approved registration is deliberately not a qualified randomness proof.
mod common;
use common::*;
use synergy_address_engine::{
    apqe::{
        bootstrap_approvals_r1::{
            ApprovalPurpose, IndexedRootApproval, PinnedBootstrapAuthority, PinnedBootstrapInput,
            VerifiedApprovalPurpose,
        },
        network_birth_r1::{BootstrapKeyRecord, NetworkBirth, ProfileRef},
        r1_framing::NetworkRef,
    },
    types::Algorithm,
};
use synergy_genesis::r1::{
    formation::{
        CandidateSeedEvidence, FormationError, FormationRegistration, FormationRegistrySnapshot,
        Population,
    },
    policy::{IndexedProof, KeyRecord, NodeRecord},
};
use synergy_protocol_types::c14n02::Decoder;
fn data(name: &str) -> serde_json::Value {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../../21-Aegis-Engine/synergy-address-engine/tests/fixtures")
        .join(name);
    let bytes = std::fs::read(path)
        .expect("published genuine public fixture required, never skip qualification");
    assert!(bytes.len() < 2 * 1024 * 1024);
    serde_json::from_slice(&bytes).unwrap()
}
#[test]
fn actual_five_member_registry_root_approval_and_cross_participant_isolation() {
    let f = data("r1_formation_public.json");
    assert_eq!(f["purpose"], "PUBLIC_SYNTHETIC_FORMATION_FIXTURE_ONLY");
    assert_eq!(f["production_import_permitted"], false);
    let g = data("r1_compiled_genesis_public.json");
    assert_eq!(g["chain_id"], u64::MAX - 1);
    let catalog = catalog();
    assert!(
        catalog.canonical_frame().unwrap()
            == bytes(g["profile_catalog_frame_hex"].as_str().unwrap()),
        "refresh genuine public fixture after a catalog change"
    );
    let commitment = catalog.commitment().unwrap();
    let n = NetworkRef {
        chain_id: u64::MAX - 1,
        nic: bytes(g["nic_hex"].as_str().unwrap()).try_into().unwrap(),
    };
    let public_keys = g["roots"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| bytes(r["public_key_hex"].as_str().unwrap()))
        .collect::<Vec<_>>();
    let roots = g["roots"]
        .as_array()
        .unwrap()
        .iter()
        .zip(&public_keys)
        .map(|(r, k)| BootstrapKeyRecord {
            role: r["role"].as_str().unwrap(),
            algorithm: r["algorithm"].as_str().unwrap(),
            key_generation: r["key_generation"].as_u64().unwrap(),
            full_public_key: k,
        })
        .collect::<Vec<_>>();
    let birth = NetworkBirth {
        chain_id: n.chain_id,
        incarnation_nonce: &[3; 32],
        genesis_schema: ProfileRef {
            name: "SYNERGY-GENESIS-R1",
            revision: 1,
        },
        initial_profile_set_commitment: &commitment,
        bootstrap_roots: &roots,
        network_label: "PUBLIC-SYNTHETIC-COMPILED-GENESIS-ONLY",
    };
    let authority = PinnedBootstrapAuthority::from_preparation_pins(
        &PinnedBootstrapInput {
            birth,
            threshold: 2,
        },
        &birth,
    )
    .unwrap();
    assert_eq!(authority.network(), n);
    let nic_sigs = g["approvals"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|a| a["purpose"] == "nic")
        .map(|a| bytes(a["signature_hex"].as_str().unwrap()))
        .collect::<Vec<_>>();
    let nic_approvals = nic_sigs
        .iter()
        .enumerate()
        .map(|(i, s)| IndexedRootApproval {
            root_index: i as u32,
            signature: s,
        })
        .collect::<Vec<_>>();
    let engine = engine();
    let nic = authority
        .verify_approvals(&engine, ApprovalPurpose::Nic, &nic_approvals)
        .unwrap();
    let mut registrations = f["input"]["registrations"]
        .as_array()
        .unwrap()
        .iter()
        .enumerate()
        .map(|(index, r)| {
            let raw = bytes(r["node_record_c14n02_hex"].as_str().unwrap());
            let mut d = Decoder::new(&raw, 1024 * 1024).unwrap();
            let node = NodeRecord::decode_from(&mut d, n).unwrap();
            d.finish().unwrap();
            FormationRegistration {
                node,
                formation_key: KeyRecord {
                    role: "formation_authentication".into(),
                    algorithm: Algorithm::MlDsa87,
                    generation: 1,
                    public_key: bytes(r["formation_public_key_hex"].as_str().unwrap()),
                },
                registration_nonce: [20 + index as u8; 32],
                key_possession: bytes(r["key_possession_signature_hex"].as_str().unwrap()),
                controller_approvals: vec![IndexedProof {
                    index: 0,
                    signature: bytes(r["controller_signature_hex"].as_str().unwrap()),
                }],
            }
        })
        .collect::<Vec<_>>();
    registrations.sort_by_key(|r|*synergy_address_engine::apqe::native_identity_presentation_r1::NativeIdentityPresentation::parse(&r.node.identity).unwrap().raw48());
    let build = |r: Vec<FormationRegistration>, population| {
        FormationRegistrySnapshot::build(&nic, &birth, &catalog, population, r, &engine)
    };
    let registry = build(registrations.clone(), Population::ConditionalFive).unwrap();
    assert_eq!(registry.registrations().len(), 5);
    assert_eq!(
        registry.canonical_bytes(),
        bytes(f["verified"]["registry_frame_hex"].as_str().unwrap())
    );
    assert_eq!(
        registry.preseed_frame().unwrap(),
        bytes(f["verified"]["preseed_frame_hex"].as_str().unwrap())
    );
    assert_eq!(
        registry.commitment().to_vec(),
        bytes(f["verified"]["registry_commitment_hex"].as_str().unwrap())
    );
    let signatures = f["input"]["formation_approvals"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| bytes(a["signature_hex"].as_str().unwrap()))
        .collect::<Vec<_>>();
    let approvals = f["input"]["formation_approvals"]
        .as_array()
        .unwrap()
        .iter()
        .zip(&signatures)
        .map(|(a, s)| IndexedRootApproval {
            root_index: a["root_index"].as_u64().unwrap() as u32,
            signature: s,
        })
        .collect::<Vec<_>>();
    let verified = registry
        .authenticate(&authority, &approvals, &engine)
        .unwrap();
    assert!(matches!(
        verified.approvals().purpose(),
        VerifiedApprovalPurpose::Formation { .. }
    ));
    // Complete schema2 carries the actual five-member cryptographic registry,
    // while a supplied candidate output still cannot manufacture a seed token.
    {
        use synergy_genesis::r1::{
            compiler::{GenesisCoreInput, InitialVoter},
            complete_formation::*,
            GenesisError,
        };
        use synergy_state::r1::{R1GenesisAllocation, R1GenesisDestination};
        let nodes = registrations
            .iter()
            .map(|r| r.node.clone())
            .collect::<Vec<_>>();
        let voters = nodes
            .iter()
            .map(|n| InitialVoter {
                identity: n.identity.clone(),
                weight: 1,
            })
            .collect::<Vec<_>>();
        let make_allocations = || {
            nodes
                .iter()
                .enumerate()
                .map(|(i, n)| R1GenesisAllocation {
                    allocation_id: format!("PUBLIC-FIXTURE-BOND-{i}"),
                    amount_nwei: 50_000_000_000_000,
                    destination: R1GenesisDestination::ValidatorBond {
                        validator: n.identity.clone(),
                        owner: "PUBLIC-NONACCOUNT-NOT-COMPILED".into(),
                        beneficiary: "PUBLIC-NONACCOUNT-NOT-COMPILED".into(),
                    },
                })
                .collect::<Vec<_>>()
        };
        let allocations = make_allocations();
        let network = synergy_protocol_types::R1NetworkRef {
            chain_id: n.chain_id,
            nic: n.nic,
        };
        let profiles = synergy_protocol_types::R1ProfileSetReference {
            profile: synergy_protocol_types::R1ProfileRef {
                name: "APQE-PROFILE-SET".into(),
                revision: 1,
            },
            commitment,
        };
        let protocol =
            synergy_protocol_types::protocol_profile_r1::commitment(&network, &profiles).unwrap();
        let mut candidate=CompleteFormationCandidate{
            population:Population::ConditionalFive,
            registrations:registrations.iter().enumerate().map(|(i,r)|Registration{node_index:i as u32,formation_key:r.formation_key.clone(),nonce:r.registration_nonce,possession:r.key_possession.clone(),controller_approvals:r.controller_approvals.clone()}).collect(),
            registry:*verified.registry().commitment(),preseed:verified.registry().preseed_commitment().unwrap(),
            root_approvals:approvals.iter().map(|a|IndexedProof{index:a.root_index,signature:a.signature.to_vec()}).collect(),
            randomness:HashRandCandidate{qualified_reference:[1;64],public_completion_evidence:b"PUBLIC-NONPROOF-NOT-A-TRANSCRIPT".to_vec(),output:b"PUBLIC-NONPROOF-NOT-A-SEED".to_vec()},
            cluster:UnifiedCluster{identity:synergy_address_engine::apqe::native_identity_presentation_r1::NativeIdentityPresentation::from_raw("syngrp",[1;48]).unwrap().to_text(),assignment_input:[1;64],members:(0..5).collect()},
            proposer_inputs:(0..5).map(|i|ProposerInput{node_index:i,selection_score:1024}).collect(),permutation:(0..5).collect(),schedule:[1;48],
            authority:InitialAuthority{epoch:1,first_height:1,last_height:1000,protocol_profile:protocol,members:nodes.iter().enumerate().map(|(i,n)|{let k=&n.role_keys.iter().find(|k|k.kind==synergy_genesis::r1::policy::RoleKeyKind::Consensus).unwrap().key;AuthorityMember{node_index:i as u32,key_id:synergy_posy::r1::consensus_key_id(&k.public_key,k.generation).unwrap(),key_generation:k.generation,weight:1}}).collect(),commitment:[1;48]},
        };
        candidate
            .validate_structure(&nodes, &voters, &protocol)
            .unwrap();
        let schedule_context = synergy_posy::r1::R1ScheduleContext {
            network,
            activated_profiles: profiles.clone(),
            seed_reference: candidate.randomness.qualified_reference,
            registry_commitment: candidate.registry,
            production_epoch: 1,
            protocol_profile: protocol,
        };
        let assignment = candidate
            .assignment_input_commitment(&schedule_context, &nodes, &voters)
            .unwrap();
        candidate.proposer_inputs[0].selection_score += 1;
        assert_ne!(
            assignment,
            candidate
                .assignment_input_commitment(&schedule_context, &nodes, &voters)
                .unwrap()
        );
        candidate.proposer_inputs[0].selection_score -= 1;
        let mut different_weight = voters.clone();
        different_weight[0].weight += 1;
        assert_ne!(
            assignment,
            candidate
                .assignment_input_commitment(&schedule_context, &nodes, &different_weight)
                .unwrap()
        );

        let scores = candidate
            .validate_initial_scores(&nodes, &allocations)
            .unwrap();
        assert_eq!(scores.len(), 5);
        assert!(scores
            .iter()
            .all(|s| s.stake == 2000 && s.reliability == 6400 && s.synergy_score == 1024));
        candidate.proposer_inputs[0].selection_score = 1;
        assert_eq!(
            candidate.validate_initial_scores(&nodes, &allocations),
            Err(GenesisError::Voter)
        );
        candidate.proposer_inputs[0].selection_score = 1024;
        let mut extra = make_allocations();
        extra.push(R1GenesisAllocation {
            allocation_id: "NONVOTING-CANDIDATE-RESERVATION".into(),
            amount_nwei: 50_000_000_000_000,
            destination: R1GenesisDestination::UnassignedValidatorFunding,
        });
        assert_eq!(
            candidate.validate_initial_scores(&nodes, &extra).unwrap(),
            scores
        );
        // Unselected public candidate data is not an authenticated voter and
        // does not enter the initial-five denominator. Full compilation still
        // requires its own complete node/bond proofs; this only checks scoring.
        let unselected=synergy_address_engine::apqe::native_identity_presentation_r1::NativeIdentityPresentation::from_raw("synv1",[0xfa;48]).unwrap().to_text();
        assert!(nodes.iter().all(|n| n.identity != unselected));
        extra.push(R1GenesisAllocation {
            allocation_id: "PUBLIC-SIXTH-NONVOTING-BOND".into(),
            amount_nwei: 50_000_000_000_000,
            destination: R1GenesisDestination::ValidatorBond {
                validator: unselected,
                owner: "PUBLIC-NONACCOUNT-NOT-COMPILED".into(),
                beneficiary: "PUBLIC-NONACCOUNT-NOT-COMPILED".into(),
            },
        });
        assert_eq!(
            candidate.validate_initial_scores(&nodes, &extra).unwrap(),
            scores
        );
        let mut duplicate = make_allocations();
        duplicate.push(make_allocations().remove(0));
        assert_eq!(
            candidate.validate_initial_scores(&nodes, &duplicate),
            Err(GenesisError::Duplicate)
        );
        let mut wrong = make_allocations();
        wrong[0].amount_nwei -= 1;
        assert_eq!(
            candidate.validate_initial_scores(&nodes, &wrong),
            Err(GenesisError::State)
        );
        let mut encoder = synergy_protocol_types::c14n02::Encoder::new(1024 * 1024);
        candidate.encode_into(&mut encoder).unwrap();
        let encoded = encoder.finish().unwrap();
        let mut decoder = Decoder::new(&encoded, 1024 * 1024).unwrap();
        assert_eq!(
            CompleteFormationCandidate::decode_from(&mut decoder).unwrap(),
            candidate
        );
        decoder.finish().unwrap();
        let mut unknown = encoded.clone();
        unknown[..2].copy_from_slice(&3u16.to_be_bytes());
        assert!(CompleteFormationCandidate::decode_from(
            &mut Decoder::new(&unknown, 1024 * 1024).unwrap()
        )
        .is_err());
        let mut invalid = candidate.clone();
        invalid.authority.last_height = 1001;
        assert_eq!(
            invalid.validate_structure(&nodes, &voters, &protocol),
            Err(GenesisError::Profile)
        );
        invalid = candidate.clone();
        invalid.authority.members[0].key_generation += 1;
        assert_eq!(
            invalid.validate_structure(&nodes, &voters, &protocol),
            Err(GenesisError::Policy)
        );
        invalid = candidate.clone();
        invalid.proposer_inputs.pop();
        invalid.permutation.pop();
        assert_eq!(
            invalid.validate_structure(&nodes, &voters, &protocol),
            Err(GenesisError::Voter)
        );
        let base = GenesisCoreInput {
            network,
            genesis_time: 1,
            catalog: catalog.clone(),
            nodes,
            accounts: vec![],
            initial_voters: voters,
            allocations,
            restricted_records: vec![],
        };
        assert!(matches!(
            candidate.verify_received(&base, &nic, &birth, &authority, &engine),
            Err(GenesisError::FormationUnavailable)
        ));
    }

    // Consume the actual Core-verified original bytes through the APQE session
    // owner. Do not substitute fixture metadata or a candidate authority flag.
    let preseed = verified.registry().preseed_frame().unwrap();
    let channel = synergy_address_engine::apqe::formation_channel::FormationAuthority::from_approved_registry(verified.approvals(),verified.registry().canonical_bytes(),&preseed).unwrap();
    assert_eq!(channel.network(), n);
    assert_eq!(channel.profiles(), &commitment);
    assert_eq!(
        channel.registry_commitment(),
        verified.registry().commitment()
    );
    assert_eq!(
        channel.input_commitment(),
        &verified.registry().preseed_commitment().unwrap()
    );
    assert_eq!(channel.target_epoch(), 1);
    assert_eq!(channel.participants().count(), 5);
    for registration in verified.registry().registrations() {
        let id=synergy_address_engine::apqe::native_identity_presentation_r1::NativeIdentityPresentation::parse(&registration.node.identity).unwrap();
        let participant = channel.participant(id.raw48()).unwrap();
        assert_eq!(
            participant.public_key(),
            registration.formation_key.public_key
        );
        assert_eq!(
            participant.key_generation(),
            registration.formation_key.generation
        );
    }
    let evidence = CandidateSeedEvidence {
        network: n,
        registry_commitment: *verified.registry().commitment(),
        preseed_commitment: verified.registry().preseed_commitment().unwrap(),
        target_epoch: 1,
        construction: "APQE-RAND-HASHRAND-FULL-P1",
        transcript: b"PUBLIC-NONPROOF-NOT-A-HASHRAND-TRANSCRIPT",
        candidate_output: b"PUBLIC-NONPROOF-NOT-A-SEED",
    };
    assert!(matches!(
        verified.verify_seed(&evidence),
        Err(FormationError::ConstructionUnavailable)
    ));
    let mut wrong = evidence;
    wrong.network.nic[0] ^= 1;
    assert!(matches!(
        verified.verify_seed(&wrong),
        Err(FormationError::Context)
    ));
    // This attack used to escape the own-node check: its dedicated key is an
    // otherwise distinct peer's node key. Reject before any stale signature is
    // examined, proving full-population role separation rather than accidental
    // rejection of an unchanged signature over a changed key.
    let mut cross = registrations.clone();
    cross[0].formation_key.public_key = cross[1].node.birth_root.public_key.clone();
    assert!(matches!(
        build(cross, Population::ConditionalFive),
        Err(FormationError::Key)
    ));
    let mut corrupt = registrations.clone();
    corrupt[0].key_possession[0] ^= 1;
    assert!(matches!(
        build(corrupt, Population::ConditionalFive),
        Err(FormationError::Proof)
    ));
    let mut missing = registrations.clone();
    missing[0].controller_approvals.clear();
    assert!(matches!(
        build(missing, Population::ConditionalFive),
        Err(FormationError::Proof)
    ));
    let mut generation = registrations.clone();
    generation[0].formation_key.generation += 1;
    assert!(matches!(
        build(generation, Population::ConditionalFive),
        Err(FormationError::Proof)
    ));
    assert!(matches!(
        build(registrations.clone(), Population::ReferenceSeven),
        Err(FormationError::Population)
    ));
    assert!(matches!(
        build(registrations.clone(), Population::ConditionalFive)
            .unwrap()
            .authenticate(&authority, &nic_approvals, &engine),
        Err(FormationError::Proof)
    ));
    assert!(matches!(
        build(registrations, Population::ConditionalFive)
            .unwrap()
            .authenticate(&authority, &approvals[..1], &engine),
        Err(FormationError::Proof)
    ));
}
