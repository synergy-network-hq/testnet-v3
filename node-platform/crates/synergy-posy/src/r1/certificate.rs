use super::{
    codec::{Reader, Writer},
    Digest48, R1Header, R1ProofError, Result, MAX_SIGNATURE_BYTES, MAX_VALIDATORS,
};
use synergy_protocol_types::{R1NetworkCoordinate, R1NetworkRef, R1ProfileSetReference};

/// Entry in the independently authenticated, immutable network-wide authority.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct R1AuthorityMember {
    pub identity: Digest48,
    pub key_id: Digest48,
    pub key_version: u64,
    pub weight: u128,
    pub signature_bytes: usize,
}
/// Exact selected ordinary-consensus key reference; a distinct APQE role key
/// is mandatory. This function never derives an identity or generates a key.
pub fn consensus_key_id(public_key: &[u8], generation: u64) -> Result<Digest48> {
    if public_key.len() != 1952 || generation == 0 {
        return Err(R1ProofError::Authority);
    }
    let mut w = Writer::new(4096);
    w.u16(65)?;
    w.u16(0)?; // ML-DSA-65, ordinary consensus role
    w.u64(generation)?;
    w.variable(public_key, 1952)?;
    super::header::framed_digest(b"POSY/KEY/R1", &w.bytes)
}
/// Complete frozen authority subject. Authentication is supplied by Genesis or
/// verified successor evidence; computing this digest alone grants no authority.
pub struct R1AuthoritySubject<'a> {
    /// N and activated profiles are available before final Genesis; including
    /// the final Genesis here would make initial authority self-referential.
    pub network: &'a R1NetworkRef,
    pub activated_profiles: &'a R1ProfileSetReference,
    pub protocol_profile: Digest48,
    pub epoch: u64,
    pub first_height: u64,
    pub last_height: u64,
    pub schedule: Digest48,
    pub members: &'a [R1AuthorityMember],
}
impl R1AuthoritySubject<'_> {
    pub fn digest(&self) -> Result<Digest48> {
        if self.first_height == 0
            || self.last_height < self.first_height
            || self.members.is_empty()
            || self.members.len() > MAX_VALIDATORS
        {
            return Err(R1ProofError::Authority);
        }
        let mut w = Writer::new(super::MAX_PROOF_BYTES);
        if self.network.chain_id == 0 {
            return Err(R1ProofError::Context);
        }
        w.u64(self.network.chain_id)?;
        w.fixed(&self.network.nic)?;
        w.profile(&self.activated_profiles.profile)?;
        w.fixed(&self.activated_profiles.commitment)?;
        w.fixed(&self.protocol_profile)?;
        w.u64(self.epoch)?;
        w.u64(self.first_height)?;
        w.u64(self.last_height)?;
        w.fixed(&self.schedule)?;
        w.u32(self.members.len() as u32)?;
        let mut previous = None;
        let mut keys = std::collections::BTreeSet::new();
        let mut total = 0u128;
        for m in self.members {
            if m.weight == 0
                || m.key_version == 0
                || m.signature_bytes != 3309
                || previous.is_some_and(|id| id >= m.identity)
                || !keys.insert(m.key_id)
            {
                return Err(R1ProofError::Authority);
            }
            previous = Some(m.identity);
            total = total.checked_add(m.weight).ok_or(R1ProofError::Authority)?;
            w.fixed(&m.identity)?;
            w.fixed(&m.key_id)?;
            w.u64(m.key_version)?;
            w.u128(m.weight)?;
        }
        w.u128(total)?;
        super::header::framed_digest(b"POSY/AUTHORITY/R1", &w.bytes)
    }
}
/// Trusted native integration boundary, analogous to ConsensusSignatureVerifier.
/// Implementations MUST authenticate Genesis/successor authority, selected
/// profiles, canonical membership/key roles, and the whole execution/proposal
/// predicate. A caller-provided table, RPC assertion or parsing result is not
/// an implementation of this trust contract.
pub trait R1ConsensusVerifier {
    fn authenticate_authority(&self, header: &R1Header) -> Result<Vec<R1AuthorityMember>>;
    /// Independently establish proposal opportunity, payload validity, all
    /// resource/profile limits, parent proof and extension of trusted ancestry.
    fn verify_proposal_and_execution(&self, header: &R1Header) -> Result<()>;
    /// Verify the exact canonical MESSAGE through the selected APQE provider;
    /// no implicit external prehash, key-role substitution or algorithm fallback.
    fn verify_approval(
        &self,
        member: &R1AuthorityMember,
        message: &[u8],
        signature: &[u8],
    ) -> Result<()>;
    /// Authenticate the checkpoint/Genesis cursor and complete intervening
    /// ancestry to target. No height-only or hash-width conversion acceptance.
    fn verify_finalized_extension(
        &self,
        coordinate: &R1NetworkCoordinate,
        previous_height: u64,
        previous_block: &Digest48,
        target: &R1Header,
    ) -> Result<()>;
}
pub(super) fn authenticated_members(
    header: &R1Header,
    verifier: &impl R1ConsensusVerifier,
) -> Result<Vec<R1AuthorityMember>> {
    let members = verifier.authenticate_authority(header)?;
    if members.is_empty() || members.len() > MAX_VALIDATORS {
        return Err(R1ProofError::Authority);
    }
    let mut last_identity = None;
    let mut keys = std::collections::BTreeSet::new();
    let mut total = 0u128;
    for m in &members {
        if m.weight == 0
            || m.key_version == 0
            || m.signature_bytes == 0
            || m.signature_bytes > MAX_SIGNATURE_BYTES
            || last_identity.is_some_and(|id| id >= m.identity)
            || !keys.insert(m.key_id)
        {
            return Err(R1ProofError::Authority);
        }
        total = total.checked_add(m.weight).ok_or(R1ProofError::Authority)?;
        last_identity = Some(m.identity);
    }
    Ok(members)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct R1Approval {
    pub member_index: u32,
    pub key_version: u64,
    pub signature: Vec<u8>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct R1QuorumCertificate {
    pub header: R1Header,
    pub approvals: Vec<R1Approval>,
}
/// An immutable canonical QC snapshot created only after complete native
/// authority, proposal/execution, signature and dual-quorum verification.
#[derive(Clone, Debug)]
pub struct VerifiedR1QuorumCertificate {
    certificate: R1QuorumCertificate,
    canonical: Vec<u8>,
}
impl VerifiedR1QuorumCertificate {
    pub fn certificate(&self) -> &R1QuorumCertificate {
        &self.certificate
    }
    pub fn canonical_qc_bytes(&self) -> &[u8] {
        &self.canonical
    }
    pub fn subject(&self) -> Result<super::R1Parent> {
        self.certificate.header.parent_subject()
    }
}
impl R1QuorumCertificate {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        let mut w = Writer::new(super::MAX_PROOF_BYTES);
        self.encode(&mut w)?;
        Ok(w.bytes)
    }
    /// Untrusted data decode, not authority. The actual peer protocol supplies
    /// its selected message family; this body cannot be a finality proof.
    pub fn decode_canonical(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader::new(bytes, super::MAX_PROOF_BYTES)?;
        let qc = Self::decode(&mut r)?;
        r.finish()?;
        if qc.canonical_bytes()?.as_slice() != bytes {
            return Err(R1ProofError::Encoding);
        }
        Ok(qc)
    }
    pub fn into_verified(
        self,
        verifier: &impl R1ConsensusVerifier,
    ) -> Result<VerifiedR1QuorumCertificate> {
        let canonical = self.canonical_bytes()?;
        self.verify(verifier)?;
        Ok(VerifiedR1QuorumCertificate {
            certificate: self,
            canonical,
        })
    }
    /// Any collector can package original approvals. Sorting indices changes
    /// neither signed messages nor block identity; duplicates remain errors.
    /// The collector obtains no special issuer or finality authority.
    pub fn assemble(
        header: R1Header,
        mut approvals: Vec<R1Approval>,
        verifier: &impl R1ConsensusVerifier,
    ) -> Result<VerifiedR1QuorumCertificate> {
        if approvals.len() > MAX_VALIDATORS {
            return Err(R1ProofError::Bounds);
        }
        approvals.sort_by_key(|a| a.member_index);
        Self { header, approvals }.into_verified(verifier)
    }
    pub(super) fn encode(&self, w: &mut Writer) -> Result<()> {
        self.header.encode(w)?;
        if self.approvals.is_empty() || self.approvals.len() > MAX_VALIDATORS {
            return Err(R1ProofError::Bounds);
        }
        w.u32(self.approvals.len() as u32)?;
        let mut previous = None;
        for a in &self.approvals {
            if previous.is_some_and(|i| i >= a.member_index) {
                return Err(R1ProofError::Signer);
            }
            previous = Some(a.member_index);
            w.u32(a.member_index)?;
            w.u64(a.key_version)?;
            w.variable(&a.signature, MAX_SIGNATURE_BYTES)?;
        }
        Ok(())
    }
    pub(super) fn decode(r: &mut Reader<'_>) -> Result<Self> {
        let header = R1Header::decode(r)?;
        let n = usize::try_from(r.u32()?).map_err(|_| R1ProofError::Bounds)?;
        if n == 0 || n > MAX_VALIDATORS {
            return Err(R1ProofError::Bounds);
        }
        let mut approvals = Vec::new();
        approvals
            .try_reserve_exact(n)
            .map_err(|_| R1ProofError::Bounds)?;
        for _ in 0..n {
            let member_index = r.u32()?;
            if approvals
                .last()
                .is_some_and(|a: &R1Approval| a.member_index >= member_index)
            {
                return Err(R1ProofError::Signer);
            }
            approvals.push(R1Approval {
                member_index,
                key_version: r.u64()?,
                signature: r.variable(MAX_SIGNATURE_BYTES)?.to_vec(),
            });
        }
        Ok(Self { header, approvals })
    }
    pub fn approval_message(&self, member: &R1AuthorityMember) -> Result<Vec<u8>> {
        use synergy_posy_approval::{ApprovalMessage, Coordinate, Parent, ProfileRef};
        let h = &self.header;
        let profile = |p: &synergy_protocol_types::R1ProfileRef| ProfileRef {
            name: p.name.clone(),
            revision: p.revision,
        };
        ApprovalMessage {
            coordinate: Coordinate {
                chain_id: h.coordinate.network.chain_id,
                nic: h.coordinate.network.nic,
                genesis_profile: profile(&h.coordinate.genesis.profile),
                genesis: h.coordinate.genesis.digest,
                profiles_profile: profile(&h.coordinate.activated_profiles.profile),
                profiles: h.coordinate.activated_profiles.commitment,
            },
            protocol_profile: h.protocol_profile,
            authority: h.authority,
            epoch: h.epoch,
            round: h.round,
            height: h.height,
            block: h.block_digest()?,
            parent: match &h.consensus_parent {
                super::R1Parent::Genesis { commitment } => Parent::Genesis {
                    commitment: *commitment,
                },
                super::R1Parent::Ordinary { epoch, height, round, block, authority } => Parent::Ordinary {
                    epoch: *epoch, height: *height, round: *round,
                    block: *block, authority: *authority,
                },
            },
            opportunity: h.opportunity,
            execution_profile: h.execution_profile,
            payload: h.execution.payload,
            post_state: h.execution.post_state,
            receipts: h.execution.receipts,
            identity: member.identity,
            key_id: member.key_id,
            key_generation: member.key_version,
        }
        .encode()
        .map_err(|error| match error {
            synergy_posy_approval::Error::Bounds => R1ProofError::Bounds,
            synergy_posy_approval::Error::Context => R1ProofError::Context,
            synergy_posy_approval::Error::Profile => R1ProofError::Profile,
            synergy_posy_approval::Error::Encoding => R1ProofError::Encoding,
        })
    }
    pub fn verify(&self, verifier: &impl R1ConsensusVerifier) -> Result<()> {
        self.header.validate_shape()?;
        if self.approvals.is_empty() || self.approvals.len() > MAX_VALIDATORS {
            return Err(R1ProofError::Bounds);
        }
        let members = authenticated_members(&self.header, verifier)?;
        let mut previous = None;
        let mut signers = Vec::with_capacity(self.approvals.len());
        for a in &self.approvals {
            if previous.is_some_and(|i| i >= a.member_index) {
                return Err(R1ProofError::Signer);
            }
            previous = Some(a.member_index);
            let m = members
                .get(a.member_index as usize)
                .ok_or(R1ProofError::Signer)?;
            if a.key_version != m.key_version || a.signature.len() != m.signature_bytes {
                return Err(R1ProofError::Signature);
            }
            signers.push(a.member_index.to_string());
        }
        // Frozen count and frozen weight use precisely the SAME verified set.
        let frozen: Vec<_> = members
            .iter()
            .enumerate()
            .map(|(i, m)| crate::FrozenValidator {
                validator_id: i.to_string(),
                frozen_voting_weight: m.weight,
            })
            .collect();
        crate::verify_strict_dual_quorum(&frozen, &signers).map_err(|_| R1ProofError::Quorum)?;
        for a in &self.approvals {
            let m = &members[a.member_index as usize];
            verifier.verify_approval(m, &self.approval_message(m)?, &a.signature)?;
        }
        // A structurally quorum-sized unauthenticated message must not cause
        // payload/state execution. Authenticate every original approval first.
        verifier.verify_proposal_and_execution(&self.header)?;
        Ok(())
    }
}
