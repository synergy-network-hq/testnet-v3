use super::{
    codec::{Reader, Writer},
    Digest48, R1ConsensusVerifier, R1ProofError, R1QuorumCertificate, Result, MAX_PROOF_BYTES,
};
use synergy_protocol_types::R1NetworkCoordinate;

/// Three original QCs. This is data until verify() succeeds against a trusted
/// native integration and an authenticated finalized cursor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct R1ThreeQcProof {
    pub certificates: [R1QuorumCertificate; 3],
}
/// This token has no public/Serde constructor and cannot be fabricated from
/// storage rows. Only successful full proof verification creates it.
#[derive(Clone, Debug)]
pub struct VerifiedR1FinalizedAnchor {
    coordinate: R1NetworkCoordinate,
    height: u64,
    block: Digest48,
    state: Digest48,
    receipts: Digest48,
    original_proof: Vec<u8>,
}
impl VerifiedR1FinalizedAnchor {
    pub fn coordinate(&self) -> &R1NetworkCoordinate {
        &self.coordinate
    }
    pub fn height(&self) -> u64 {
        self.height
    }
    pub fn block_digest(&self) -> &Digest48 {
        &self.block
    }
    pub fn state_root(&self) -> &Digest48 {
        &self.state
    }
    pub fn receipts_root(&self) -> &Digest48 {
        &self.receipts
    }
    pub fn original_proof(&self) -> &[u8] {
        &self.original_proof
    }
}
impl R1ThreeQcProof {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        let mut w = Writer::new(MAX_PROOF_BYTES);
        w.variable(b"POSY/FINALITY/R1", 128)?;
        w.u16(1)?;
        w.u16(0)?;
        for qc in &self.certificates {
            qc.encode(&mut w)?;
        }
        Ok(w.bytes)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader::new(bytes, MAX_PROOF_BYTES)?;
        if r.variable(128)? != b"POSY/FINALITY/R1" || r.u16()? != 1 || r.u16()? != 0 {
            return Err(R1ProofError::Profile);
        }
        let certificates = [
            R1QuorumCertificate::decode(&mut r)?,
            R1QuorumCertificate::decode(&mut r)?,
            R1QuorumCertificate::decode(&mut r)?,
        ];
        r.finish()?;
        Ok(Self { certificates })
    }
    /// The prior cursor is independently authenticated by the verifier. The
    /// target may be an ancestor advanced by a later qualifying ordinary chain;
    /// complete extension is mandatory, not inferred from a larger height.
    pub fn verify_original(
        bytes: &[u8],
        expected: &R1NetworkCoordinate,
        previous_height: u64,
        previous_block: &Digest48,
        verifier: &impl R1ConsensusVerifier,
    ) -> Result<VerifiedR1FinalizedAnchor> {
        let proof = Self::decode(bytes)?;
        let [a, b, c] = &proof.certificates;
        for qc in &proof.certificates {
            qc.header
                .coordinate
                .ensure_matches(expected)
                .map_err(|_| R1ProofError::Context)?;
            if qc.header.epoch != a.header.epoch
                || qc.header.authority != a.header.authority
                || qc.header.protocol_profile != a.header.protocol_profile
                || qc.header.execution_profile != a.header.execution_profile
            {
                return Err(R1ProofError::Context);
            }
        }
        for (parent, child) in [(a, b), (b, c)] {
            if parent.header.height.checked_add(1) != Some(child.header.height)
                || parent.header.round.checked_add(1) != Some(child.header.round)
                || child.header.consensus_parent != parent.header.parent_subject()?
                || child.header.ledger_parent != parent.header.block_digest()?
                || child.header.execution.pre_state != parent.header.execution.post_state
            {
                return Err(R1ProofError::Parent);
            }
        }
        if a.header.height < previous_height {
            return Err(R1ProofError::FinalizedConflict);
        }
        let target = a.header.block_digest()?;
        if a.header.height == previous_height && target != *previous_block {
            return Err(R1ProofError::FinalizedConflict);
        }
        verifier.verify_finalized_extension(
            expected,
            previous_height,
            previous_block,
            &a.header,
        )?;
        for qc in &proof.certificates {
            qc.verify(verifier)?;
        }
        // Strict decoding + encoding must preserve every original public byte.
        if proof.canonical_bytes()?.as_slice() != bytes {
            return Err(R1ProofError::Encoding);
        }
        Ok(VerifiedR1FinalizedAnchor {
            coordinate: expected.clone(),
            height: a.header.height,
            block: target,
            state: a.header.execution.post_state,
            receipts: a.header.execution.receipts,
            original_proof: bytes.to_vec(),
        })
    }
}

/// A lock justified by an exact direct two-certificate chain. It carries no
/// signing permission; the safe-vote predicate must also establish that the
/// candidate extends this lock or has a strictly higher verified parent QC.
#[derive(Clone, Debug)]
pub struct R1CertifiedLock {
    certificates: [super::VerifiedR1QuorumCertificate; 2],
}
impl R1CertifiedLock {
    /// Preserve both original verified QCs after checking the complete direct
    /// ordinary ancestry. A single QC, height, round or caller flag cannot make a lock.
    pub fn from_verified_pair(
        parent: super::VerifiedR1QuorumCertificate,
        child: super::VerifiedR1QuorumCertificate,
    ) -> Result<Self> {
        let a = &parent.certificate().header;
        let b = &child.certificate().header;
        b.coordinate
            .ensure_matches(&a.coordinate)
            .map_err(|_| R1ProofError::Context)?;
        if a.epoch != b.epoch
            || a.authority != b.authority
            || a.protocol_profile != b.protocol_profile
            || a.execution_profile != b.execution_profile
        {
            return Err(R1ProofError::Context);
        }
        if a.height.checked_add(1) != Some(b.height)
            || a.round.checked_add(1) != Some(b.round)
            || b.consensus_parent != a.parent_subject()?
            || b.ledger_parent != a.block_digest()?
            || b.execution.pre_state != a.execution.post_state
        {
            return Err(R1ProofError::Parent);
        }
        Ok(Self {
            certificates: [parent, child],
        })
    }
    /// The certified ancestor on which this chain justifies a lock.
    pub fn header(&self) -> &super::R1Header {
        &self.certificates[0].certificate().header
    }
    /// Original verified evidence, retained across journal/recovery boundaries.
    pub fn certificates(&self) -> &[super::VerifiedR1QuorumCertificate; 2] {
        &self.certificates
    }
}
