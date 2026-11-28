//! Typed schema2 formation candidate. Parsing/shape checks never create seed,
//! assignment or consensus authority. Qualified HashRand admission is separate.
use super::{
    compiler::InitialVoter,
    formation::Population,
    policy::{self, IndexedProof, KeyRecord, NodeRecord},
    GenesisError,
};
use synergy_address_engine::{
    apqe::{
        bootstrap_approvals_r1::{
            IndexedRootApproval, PinnedBootstrapAuthority, VerifiedBootstrapApprovals,
        },
        crypto_engine::CryptoEngine,
        native_identity_derivation_r1::{validate_received_identity, BirthBody},
        native_identity_presentation_r1::NativeIdentityPresentation,
        network_birth_r1::{NetworkBirth, ProfileRef},
        r1_framing::{self as c, Value},
        HashAlgorithm, Primitives,
    },
    types::Algorithm,
};
use synergy_posy::r1::{
    consensus_key_id, derive_candidate_schedule, R1AuthorityMember, R1AuthoritySubject,
    R1ProposerCandidate, R1ScheduleContext,
};
use synergy_protocol_types::{
    c14n02::{Decoder, Encoder},
    NodeRole,
};
pub const COMPLETE_CORE_SCHEMA: u16 = 2;
pub const ASSIGNMENT_SCHEMA: &[u8] = b"APQE-FORMATION-ASSIGNMENT/1;AssignmentInput64=SHA3-512(F(FORMATION.ASSIGNMENT.INPUT,[APQE-FORMATION-ASSIGNMENT,1],N,[Registry64,Preseed64,QualifiedSeedReference64,ProductionEpoch1,ProtocolProfile48,OrderedEntries]));Entry=[ValidatorRaw48,VotingWeightBstr16BE,SelectionScoreBstr16BE];entries-strict-raw48-order;fullN;noClusterID/noGenesis/noAuthoritySelfDigest;clusterbirth=syngrp,epoch1,slot0,formationCommit64=AssignmentInput64;candidate-commitment-not-qualified-seed-or-operator-authority";

pub const MAX_TRANSCRIPT: usize = 4 * 1024 * 1024;
pub const MAX_SEED_OUTPUT: usize = 65536;
/// Explicit initial-five engineering rule selected by the owner after reading
/// PoSy §§72–83. Values are initialized UNOBSERVED, never earned history.
pub const INITIAL_SCORE_SCHEMA:&[u8]=b"POSY-INITIAL-FIVE-SCORES-R1/1;onlyfiveapprovedinitialvalidators;actualeligiblelockedbond50000SNRGeach;effectivecap100000SNRG;totalexcludesnonvotingcandidate;scale10000;initialrelativeStakeUncapped:S=floor(10000*effective/total);UNOBSERVED-U8000-A8000;noPenaltyL10000;R=floor(U*A*L/100000000)=6400;noCooperationObservationsC8000;neutralP10000;SS=floor(S*R*C/(10000*P));fiveequal50kbondsS2000/SS1024;notearnedhistory/notnewcomerproductionpermission";
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InitializedBootstrapScore {
    pub effective_stake_nwei: u128,
    pub total_effective_nwei: u128,
    pub stake: u128,
    pub availability: u128,
    pub accuracy: u128,
    pub penalty_multiplier: u128,
    pub reliability: u128,
    pub cooperation: u128,
    pub misconduct_divisor: u128,
    pub synergy_score: u128,
}
impl InitializedBootstrapScore {
    fn from_actual_initial_bond(effective: u128, total: u128) -> Result<Self, GenesisError> {
        if effective != 50_000 * 1_000_000_000u128 || total != 5 * effective {
            return Err(GenesisError::State);
        }
        let stake = 10_000u128
            .checked_mul(effective)
            .ok_or(GenesisError::State)?
            / total;
        let reliability = 8_000u128 * 8_000 * 10_000 / 100_000_000;
        let synergy_score = stake
            .checked_mul(reliability)
            .and_then(|n| n.checked_mul(8_000))
            .ok_or(GenesisError::State)?
            / (10_000 * 10_000);
        Ok(Self {
            effective_stake_nwei: effective,
            total_effective_nwei: total,
            stake,
            availability: 8_000,
            accuracy: 8_000,
            penalty_multiplier: 10_000,
            reliability,
            cooperation: 8_000,
            misconduct_divisor: 10_000,
            synergy_score,
        })
    }
}
/// Explicit engineering candidate field order. This is not an activated schema
/// descriptor until the joint catalog freeze. Seed normalization is unselected.
pub const FORMATION_FIELDS_SCHEMA:&[u8]=b"GenesisCoreSchema2.Formation=PopulationU16(ConditionalFive1|ReferenceSeven2),Vector7(Registration=NodeIndexU32,CompleteKeyRecord,Nonce32,Bytes4627(KeyPoP),Vector32(IndexedControllerProof)),Registry64,Preseed64,Vector32(IndexedRootProof),HashRandCandidate(TagU16(1),QualifiedReference64,Bytes4194304(PublicCompletionEvidence),Bytes65536(CandidateOutput)),UnifiedCluster(NamespaceASCII6,Raw48,AssignmentInput64,Vector7(NodeIndexU32)),Vector7(ProposerInput=NodeIndexU32,SelectionScoreU128),Vector7(PermutationNodeIndexU32),Schedule48,InitialAuthority(EpochU64,FirstHeightU64,LastHeightU64,Protocol48,Vector7(Member=NodeIndexU32,KeyID48,KeyGenerationU64,WeightU128),Authority48);fixedproductionepoch1/heights1..1000;nodeindicesrefercompletecanonicalbaseNodeRecords;fullregistry/preseedrecomputed;privatequalifiedHashRandresultrequired;ConditionalFive-initial-score-rule-only;ReferenceSeven-data-shape-not-qualified-initial-score-or-admission;candidatebytesnevermintauthority";
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Registration {
    pub node_index: u32,
    pub formation_key: KeyRecord,
    pub nonce: [u8; 32],
    pub possession: Vec<u8>,
    pub controller_approvals: Vec<IndexedProof>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HashRandCandidate {
    /// A reference digest is not an assertion that the output is 64 bytes.
    /// Its qualified construction/normalization remains owner-unselected.
    pub qualified_reference: [u8; 64],
    pub public_completion_evidence: Vec<u8>,
    pub output: Vec<u8>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnifiedCluster {
    pub identity: String,
    pub assignment_input: [u8; 64],
    pub members: Vec<u32>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProposerInput {
    pub node_index: u32,
    pub selection_score: u128,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorityMember {
    pub node_index: u32,
    pub key_id: [u8; 48],
    pub key_generation: u64,
    pub weight: u128,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InitialAuthority {
    pub epoch: u64,
    pub first_height: u64,
    pub last_height: u64,
    pub protocol_profile: [u8; 48],
    pub members: Vec<AuthorityMember>,
    pub commitment: [u8; 48],
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompleteFormationCandidate {
    pub population: Population,
    pub registrations: Vec<Registration>,
    pub registry: [u8; 64],
    pub preseed: [u8; 64],
    pub root_approvals: Vec<IndexedProof>,
    pub randomness: HashRandCandidate,
    pub cluster: UnifiedCluster,
    pub proposer_inputs: Vec<ProposerInput>,
    pub permutation: Vec<u32>,
    pub schedule: [u8; 48],
    pub authority: InitialAuthority,
}
/// No public constructor or serde: only complete registration/root/qualified
/// seed and deterministic assignment verification can produce this result.
pub struct VerifiedCompleteFormation {
    authority: super::formation::VerifiedFormationAuthority,
    seed: super::formation::VerifiedFormationSeed,
    candidate: CompleteFormationCandidate,
}
impl VerifiedCompleteFormation {
    pub fn registry(&self) -> &super::formation::FormationRegistrySnapshot {
        self.authority.registry()
    }
    pub fn seed(&self) -> &super::formation::VerifiedFormationSeed {
        &self.seed
    }
    pub fn candidate(&self) -> &CompleteFormationCandidate {
        &self.candidate
    }
    pub fn initial_authority(&self) -> &InitialAuthority {
        &self.candidate.authority
    }
}
fn node_id(nodes: &[NodeRecord], index: u32) -> Result<[u8; 48], GenesisError> {
    let n = nodes.get(index as usize).ok_or(GenesisError::Bound)?;
    let id = NativeIdentityPresentation::parse(&n.identity).map_err(|_| GenesisError::Identity)?;
    if id.namespace() != "synv1" || n.primary_role != NodeRole::Validator {
        return Err(GenesisError::Voter);
    }
    Ok(*id.raw48())
}
fn ordered(indices: &[u32]) -> bool {
    !indices.is_empty() && indices.windows(2).all(|p| p[0] < p[1])
}
fn count(d: &mut Decoder<'_>, max: usize, min: usize) -> Result<usize, GenesisError> {
    let n = d.u32()? as usize;
    if n > max || n > d.remaining() / min {
        return Err(GenesisError::Bound);
    }
    Ok(n)
}
impl CompleteFormationCandidate {
    /// Complete received proof chain. Even a genuine registration/root quorum
    /// stops at FormationUnavailable while the qualified HashRand verifier and
    /// result normalization are missing; there is no candidate-output bypass.
    pub fn verify_received(
        &self,
        base: &super::compiler::GenesisCoreInput,
        nic: &VerifiedBootstrapApprovals,
        birth: &NetworkBirth<'_>,
        bootstrap: &PinnedBootstrapAuthority,
        engine: &CryptoEngine,
    ) -> Result<VerifiedCompleteFormation, GenesisError> {
        let selected = synergy_protocol_types::R1ProfileSetReference {
            profile: synergy_protocol_types::R1ProfileRef {
                name: "APQE-PROFILE-SET".into(),
                revision: 1,
            },
            commitment: base.catalog.commitment()?,
        };
        let expected_protocol =
            &synergy_protocol_types::protocol_profile_r1::commitment(&base.network, &selected)
                .map_err(|_| GenesisError::Profile)?;
        self.validate_structure(&base.nodes, &base.initial_voters, expected_protocol)?;
        if self.population != Population::ConditionalFive {
            return Err(GenesisError::FormationUnavailable);
        }
        self.validate_initial_scores(&base.nodes, &base.allocations)?;
        if base
            .initial_voters
            .windows(2)
            .any(|w| w[0].weight != w[1].weight)
        {
            return Err(GenesisError::Voter);
        }
        let registrations = self
            .registrations
            .iter()
            .map(|r| super::formation::FormationRegistration {
                node: base.nodes[r.node_index as usize].clone(),
                formation_key: r.formation_key.clone(),
                registration_nonce: r.nonce,
                key_possession: r.possession.clone(),
                controller_approvals: r.controller_approvals.clone(),
            })
            .collect();
        let snapshot = super::formation::FormationRegistrySnapshot::recompute_received(
            nic,
            birth,
            &base.catalog,
            self.population,
            registrations,
            engine,
        )
        .map_err(|_| GenesisError::Approval)?;
        if snapshot.network().chain_id != base.network.chain_id
            || snapshot.network().nic != base.network.nic
            || snapshot.commitment() != &self.registry
            || snapshot
                .preseed_commitment()
                .map_err(|_| GenesisError::Encoding)?
                != self.preseed
        {
            return Err(GenesisError::Profile);
        }
        let approvals = self
            .root_approvals
            .iter()
            .map(|p| IndexedRootApproval {
                root_index: p.index,
                signature: &p.signature,
            })
            .collect::<Vec<_>>();
        let authority = snapshot
            .authenticate(bootstrap, &approvals, engine)
            .map_err(|_| GenesisError::Approval)?;
        let seed = authority
            .verify_seed(&super::formation::CandidateSeedEvidence {
                network: authority.registry().network(),
                registry_commitment: self.registry,
                preseed_commitment: self.preseed,
                target_epoch: 1,
                construction: "APQE-RAND-HASHRAND-FULL-P1",
                transcript: &self.randomness.public_completion_evidence,
                candidate_output: &self.randomness.output,
            })
            .map_err(|e| {
                if e == super::formation::FormationError::ConstructionUnavailable {
                    GenesisError::FormationUnavailable
                } else {
                    GenesisError::Profile
                }
            })?;
        if seed.network() != authority.registry().network()
            || seed.registry_commitment() != &self.registry
            || seed.preseed_commitment() != &self.preseed
            || seed.qualified_reference() != &self.randomness.qualified_reference
            || seed.output() != self.randomness.output
        {
            return Err(GenesisError::Profile);
        }
        let context = R1ScheduleContext {
            network: base.network,
            activated_profiles: synergy_protocol_types::R1ProfileSetReference {
                profile: synergy_protocol_types::R1ProfileRef {
                    name: "APQE-PROFILE-SET".into(),
                    revision: 1,
                },
                commitment: base.catalog.commitment()?,
            },
            seed_reference: *seed.qualified_reference(),
            registry_commitment: self.registry,
            production_epoch: 1,
            protocol_profile: *expected_protocol,
        };
        self.validate_schedule_data(&context, &base.nodes)?;
        let assignment =
            self.assignment_input_commitment(&context, &base.nodes, &base.initial_voters)?;
        if assignment != self.cluster.assignment_input {
            return Err(GenesisError::Profile);
        }
        validate_received_identity(
            &self.cluster.identity,
            authority.registry().network(),
            &BirthBody::Cluster {
                formation_epoch: 1,
                cluster_slot: 0,
                formation_commit64: &assignment,
            },
            1024 * 1024,
        )
        .map_err(|_| GenesisError::Identity)?;
        Ok(VerifiedCompleteFormation {
            authority,
            seed,
            candidate: self.clone(),
        })
    }
    /// Candidate engineering assignment-input domain, acyclic: no cluster ID,
    /// final Genesis, authority digest or current signature enters its input.
    pub fn assignment_input_commitment(
        &self,
        context: &R1ScheduleContext,
        nodes: &[NodeRecord],
        voters: &[InitialVoter],
    ) -> Result<[u8; 64], GenesisError> {
        if self.registrations.len() != voters.len()
            || self.registrations.len() != self.proposer_inputs.len()
            || context.registry_commitment != self.registry
            || context.seed_reference != self.randomness.qualified_reference
            || context.production_epoch != 1
        {
            return Err(GenesisError::Profile);
        }
        let indices = self
            .registrations
            .iter()
            .map(|r| r.node_index)
            .collect::<Vec<_>>();
        if indices.len() > 7
            || !ordered(&indices)
            || self
                .proposer_inputs
                .iter()
                .map(|p| p.node_index)
                .ne(indices.iter().copied())
        {
            return Err(GenesisError::Order);
        }
        let mut previous = None;
        let rows = self
            .registrations
            .iter()
            .zip(voters)
            .map(|(r, v)| {
                let raw = node_id(nodes, r.node_index)?;
                if nodes[r.node_index as usize].identity != v.identity
                    || v.weight == 0
                    || previous.is_some_and(|p| p >= raw)
                {
                    return Err(GenesisError::Voter);
                }
                previous = Some(raw);
                Ok(Value::Array(vec![
                    c::bytes(&node_id(nodes, r.node_index)?),
                    c::bytes(&v.weight.to_be_bytes()),
                    c::bytes(
                        &self
                            .proposer_inputs
                            .iter()
                            .find(|p| p.node_index == r.node_index)
                            .ok_or(GenesisError::Voter)?
                            .selection_score
                            .to_be_bytes(),
                    ),
                ]))
            })
            .collect::<Result<Vec<_>, GenesisError>>()?;
        let bytes = c::frame(
            "FORMATION.ASSIGNMENT.INPUT",
            ProfileRef {
                name: "APQE-FORMATION-ASSIGNMENT",
                revision: 1,
            },
            Some(synergy_address_engine::apqe::r1_framing::NetworkRef {
                chain_id: context.network.chain_id,
                nic: context.network.nic,
            }),
            Value::Array(vec![
                c::bytes(&self.registry),
                c::bytes(&self.preseed),
                c::bytes(&context.seed_reference),
                Value::Unsigned(1),
                c::bytes(&context.protocol_profile),
                Value::Array(rows),
            ]),
            1024 * 1024,
        )
        .map_err(|_| GenesisError::Encoding)?;
        Primitives
            .hash(HashAlgorithm::Sha3512, &bytes)
            .map_err(|_| GenesisError::Primitive)?
            .try_into()
            .map_err(|_| GenesisError::Primitive)
    }
    /// Read the actual typed bond allocations. Reserved funds and the sixth
    /// nonvoting candidate cannot inflate the initial-five stake denominator.
    pub fn validate_initial_scores(
        &self,
        nodes: &[NodeRecord],
        allocations: &[synergy_state::r1::R1GenesisAllocation],
    ) -> Result<Vec<InitializedBootstrapScore>, GenesisError> {
        if self.population != Population::ConditionalFive || self.registrations.len() != 5 {
            return Err(GenesisError::Voter);
        }
        let mut effective = Vec::new();
        let mut total = 0u128;
        for r in &self.registrations {
            let node = nodes
                .get(r.node_index as usize)
                .ok_or(GenesisError::Bound)?;
            let mut bond = None;
            for allocation in allocations {
                if matches!(&allocation.destination,synergy_state::r1::R1GenesisDestination::ValidatorBond{validator,..} if validator==&node.identity)
                {
                    if bond.replace(allocation.amount_nwei).is_some() {
                        return Err(GenesisError::Duplicate);
                    }
                }
            }
            let value = bond
                .ok_or(GenesisError::State)?
                .min(100_000 * 1_000_000_000u128);
            total = total.checked_add(value).ok_or(GenesisError::State)?;
            effective.push(value);
        }
        let values = effective
            .into_iter()
            .map(|v| InitializedBootstrapScore::from_actual_initial_bond(v, total))
            .collect::<Result<Vec<_>, _>>()?;
        for p in &self.proposer_inputs {
            let index = self
                .registrations
                .iter()
                .position(|r| r.node_index == p.node_index)
                .ok_or(GenesisError::Voter)?;
            if p.selection_score != values[index].synergy_score {
                return Err(GenesisError::Voter);
            }
        }
        Ok(values)
    }
    /// Checks all seed-independent invariants against complete base records and
    /// independently selected protocol inputs. Success is data consistency only.
    pub fn validate_structure(
        &self,
        nodes: &[NodeRecord],
        voters: &[InitialVoter],
        expected_protocol: &[u8; 48],
    ) -> Result<(), GenesisError> {
        let expected = match self.population {
            Population::ConditionalFive => 5,
            Population::ReferenceSeven => 7,
        };
        let indices = self
            .registrations
            .iter()
            .map(|r| r.node_index)
            .collect::<Vec<_>>();
        if self.registrations.len() != expected
            || voters.len() != expected
            || !ordered(&indices)
            || self.cluster.members != indices
            || !ordered(&self.cluster.members)
        {
            return Err(GenesisError::Voter);
        }
        if self.registry == [0; 64]
            || self.preseed == [0; 64]
            || self.cluster.assignment_input == [0; 64]
            || self.randomness.qualified_reference == [0; 64]
            || self.randomness.public_completion_evidence.is_empty()
            || self.randomness.public_completion_evidence.len() > MAX_TRANSCRIPT
            || self.randomness.output.is_empty()
            || self.randomness.output.len() > MAX_SEED_OUTPUT
        {
            return Err(GenesisError::Bound);
        }
        let cluster = NativeIdentityPresentation::parse(&self.cluster.identity)
            .map_err(|_| GenesisError::Identity)?;
        if cluster.namespace() != "syngrp" {
            return Err(GenesisError::Identity);
        }
        for (r, v) in self.registrations.iter().zip(voters) {
            node_id(nodes, r.node_index)?;
            if nodes[r.node_index as usize].identity != v.identity
                || r.nonce == [0; 32]
                || r.formation_key.role != "formation_authentication"
                || r.formation_key.algorithm != Algorithm::MlDsa87
                || r.possession.len() != 4627
                || r.controller_approvals.is_empty()
                || r.controller_approvals.len() > 32
            {
                return Err(GenesisError::Policy);
            }
            r.formation_key.as_apqe()?;
        }
        if self.root_approvals.is_empty()
            || self.root_approvals.len() > 32
            || self
                .root_approvals
                .iter()
                .any(|p| p.signature.len() != 4627)
            || self
                .root_approvals
                .windows(2)
                .any(|p| p[0].index >= p[1].index)
        {
            return Err(GenesisError::Approval);
        }
        let proposer_indices = self
            .proposer_inputs
            .iter()
            .map(|p| p.node_index)
            .collect::<Vec<_>>();
        if !ordered(&proposer_indices)
            || proposer_indices != indices
            || self.permutation.len() != proposer_indices.len()
        {
            return Err(GenesisError::Voter);
        }
        let mut permutation = self.permutation.clone();
        permutation.sort_unstable();
        if permutation != proposer_indices {
            return Err(GenesisError::Order);
        }
        let a = &self.authority;
        if a.epoch != 1
            || a.first_height != 1
            || a.last_height != 1000
            || &a.protocol_profile != expected_protocol
            || a.members.len() != expected
        {
            return Err(GenesisError::Profile);
        }
        let mut total = 0u128;
        for ((member, index), voter) in a.members.iter().zip(&indices).zip(voters) {
            if member.node_index != *index || member.weight == 0 || member.weight != voter.weight {
                return Err(GenesisError::Voter);
            }
            total = total
                .checked_add(member.weight)
                .ok_or(GenesisError::Voter)?;
            let key = nodes[*index as usize]
                .role_keys
                .iter()
                .find(|k| k.kind == policy::RoleKeyKind::Consensus)
                .ok_or(GenesisError::Policy)?;
            if member.key_generation != key.key.generation
                || member.key_id
                    != consensus_key_id(&key.key.public_key, key.key.generation)
                        .map_err(|_| GenesisError::Policy)?
            {
                return Err(GenesisError::Policy);
            }
        }
        Ok(())
    }
    /// Pure deterministic candidate check using the existing PoSy owner. The
    /// caller still must obtain a private qualified seed before admitting it.
    pub(super) fn validate_schedule_data(
        &self,
        context: &R1ScheduleContext,
        nodes: &[NodeRecord],
    ) -> Result<(), GenesisError> {
        let candidates = self
            .proposer_inputs
            .iter()
            .map(|p| {
                Ok(R1ProposerCandidate {
                    identity: node_id(nodes, p.node_index)?,
                    selection_score: p.selection_score,
                })
            })
            .collect::<Result<Vec<_>, GenesisError>>()?;
        let computed = derive_candidate_schedule(context, &self.randomness.output, &candidates)
            .map_err(|_| GenesisError::Profile)?;
        let claimed = self
            .permutation
            .iter()
            .map(|i| node_id(nodes, *i))
            .collect::<Result<Vec<_>, _>>()?;
        if computed.permutation() != claimed || computed.commitment() != &self.schedule {
            return Err(GenesisError::Order);
        }
        let members = self
            .authority
            .members
            .iter()
            .map(|m| {
                Ok(R1AuthorityMember {
                    identity: node_id(nodes, m.node_index)?,
                    key_id: m.key_id,
                    key_version: m.key_generation,
                    weight: m.weight,
                    signature_bytes: 3309,
                })
            })
            .collect::<Result<Vec<_>, GenesisError>>()?;
        let a = &self.authority;
        let digest = R1AuthoritySubject {
            network: &context.network,
            activated_profiles: &context.activated_profiles,
            protocol_profile: a.protocol_profile,
            epoch: a.epoch,
            first_height: a.first_height,
            last_height: a.last_height,
            schedule: self.schedule,
            members: &members,
        }
        .digest()
        .map_err(|_| GenesisError::Voter)?;
        if digest != a.commitment {
            return Err(GenesisError::Voter);
        }
        Ok(())
    }
    pub fn encode_into(&self, e: &mut Encoder) -> Result<(), GenesisError> {
        e.u16(match self.population {
            Population::ConditionalFive => 1,
            Population::ReferenceSeven => 2,
        })?;
        if self.registrations.len() > 7 {
            return Err(GenesisError::Bound);
        }
        e.u32(self.registrations.len() as u32)?;
        for r in &self.registrations {
            e.u32(r.node_index)?;
            r.formation_key.encode_into(e)?;
            e.fixed(&r.nonce)?;
            e.bytes(&r.possession, 4627)?;
            policy::encode_proofs(e, &r.controller_approvals, 32)?;
        }
        e.fixed(&self.registry)?;
        e.fixed(&self.preseed)?;
        policy::encode_proofs(e, &self.root_approvals, 32)?;
        e.u16(1)?;
        e.fixed(&self.randomness.qualified_reference)?;
        e.bytes(&self.randomness.public_completion_evidence, MAX_TRANSCRIPT)?;
        e.bytes(&self.randomness.output, MAX_SEED_OUTPUT)?;
        let id = NativeIdentityPresentation::parse(&self.cluster.identity)
            .map_err(|_| GenesisError::Identity)?;
        if id.namespace() != "syngrp" {
            return Err(GenesisError::Identity);
        }
        e.ascii(id.namespace(), 6)?;
        e.fixed(id.raw48())?;
        e.fixed(&self.cluster.assignment_input)?;
        fn indices(e: &mut Encoder, v: &[u32]) -> Result<(), GenesisError> {
            if v.len() > 7 {
                return Err(GenesisError::Bound);
            }
            e.u32(v.len() as u32)?;
            for i in v {
                e.u32(*i)?;
            }
            Ok(())
        }
        indices(e, &self.cluster.members)?;
        if self.proposer_inputs.len() > 7 {
            return Err(GenesisError::Bound);
        }
        e.u32(self.proposer_inputs.len() as u32)?;
        for p in &self.proposer_inputs {
            e.u32(p.node_index)?;
            e.u128(p.selection_score)?;
        }
        indices(e, &self.permutation)?;
        e.fixed(&self.schedule)?;
        let a = &self.authority;
        e.u64(a.epoch)?;
        e.u64(a.first_height)?;
        e.u64(a.last_height)?;
        e.fixed(&a.protocol_profile)?;
        if a.members.len() > 7 {
            return Err(GenesisError::Bound);
        }
        e.u32(a.members.len() as u32)?;
        for m in &a.members {
            e.u32(m.node_index)?;
            e.fixed(&m.key_id)?;
            e.u64(m.key_generation)?;
            e.u128(m.weight)?;
        }
        e.fixed(&a.commitment)?;
        Ok(())
    }
    pub fn decode_from(d: &mut Decoder<'_>) -> Result<Self, GenesisError> {
        let population = match d.u16()? {
            1 => Population::ConditionalFive,
            2 => Population::ReferenceSeven,
            _ => return Err(GenesisError::Profile),
        };
        let mut registrations = Vec::new();
        for _ in 0..count(d, 7, 50)? {
            registrations.push(Registration {
                node_index: d.u32()?,
                formation_key: KeyRecord::decode_from(d)?,
                nonce: d.fixed()?,
                possession: d.bytes(4627)?.to_vec(),
                controller_approvals: policy::decode_proofs(d, 32)?,
            });
        }
        let registry = d.fixed()?;
        let preseed = d.fixed()?;
        let root_approvals = policy::decode_proofs(d, 32)?;
        if d.u16()? != 1 {
            return Err(GenesisError::Profile);
        }
        let randomness = HashRandCandidate {
            qualified_reference: d.fixed()?,
            public_completion_evidence: d.bytes(MAX_TRANSCRIPT)?.to_vec(),
            output: d.bytes(MAX_SEED_OUTPUT)?.to_vec(),
        };
        let namespace = d.ascii(6)?.to_owned();
        let raw = d.fixed()?;
        if namespace != "syngrp" {
            return Err(GenesisError::Identity);
        }
        let identity = NativeIdentityPresentation::from_raw(&namespace, raw)
            .map_err(|_| GenesisError::Identity)?
            .to_text();
        let assignment_input = d.fixed()?;
        fn indices(d: &mut Decoder<'_>) -> Result<Vec<u32>, GenesisError> {
            let mut v = Vec::new();
            for _ in 0..count(d, 7, 4)? {
                v.push(d.u32()?);
            }
            Ok(v)
        }
        let cluster = UnifiedCluster {
            identity,
            assignment_input,
            members: indices(d)?,
        };
        let mut proposer_inputs = Vec::new();
        for _ in 0..count(d, 7, 20)? {
            proposer_inputs.push(ProposerInput {
                node_index: d.u32()?,
                selection_score: d.u128()?,
            });
        }
        let permutation = indices(d)?;
        let schedule = d.fixed()?;
        let epoch = d.u64()?;
        let first_height = d.u64()?;
        let last_height = d.u64()?;
        let protocol_profile = d.fixed()?;
        let mut members = Vec::new();
        for _ in 0..count(d, 7, 76)? {
            members.push(AuthorityMember {
                node_index: d.u32()?,
                key_id: d.fixed()?,
                key_generation: d.u64()?,
                weight: d.u128()?,
            });
        }
        let authority = InitialAuthority {
            epoch,
            first_height,
            last_height,
            protocol_profile,
            members,
            commitment: d.fixed()?,
        };
        Ok(Self {
            population,
            registrations,
            registry,
            preseed,
            root_approvals,
            randomness,
            cluster,
            proposer_inputs,
            permutation,
            schedule,
            authority,
        })
    }
}
