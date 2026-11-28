use super::{
    codec::{Reader, Writer},
    Digest48, R1ProofError, Result,
};
use synergy_address::r1_public::{HashAlgorithm, Primitives};
use synergy_protocol_types::R1NetworkCoordinate;

/// Subject references exclude the replaceable signature bundle.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum R1Parent {
    Genesis {
        commitment: Digest48,
    },
    Ordinary {
        epoch: u64,
        height: u64,
        round: u64,
        block: Digest48,
        authority: Digest48,
    },
}
impl R1Parent {
    pub(super) fn encode(&self, w: &mut Writer) -> Result<()> {
        match self {
            Self::Genesis { commitment } => {
                w.u16(0)?;
                w.fixed(commitment)
            }
            Self::Ordinary {
                epoch,
                height,
                round,
                block,
                authority,
            } => {
                w.u16(1)?;
                w.u64(*epoch)?;
                w.u64(*height)?;
                w.u64(*round)?;
                w.fixed(block)?;
                w.fixed(authority)
            }
        }
    }
    pub(super) fn decode(r: &mut Reader<'_>) -> Result<Self> {
        match r.u16()? {
            0 => Ok(Self::Genesis {
                commitment: r.fixed()?,
            }),
            1 => Ok(Self::Ordinary {
                epoch: r.u64()?,
                height: r.u64()?,
                round: r.u64()?,
                block: r.fixed()?,
                authority: r.fixed()?,
            }),
            _ => Err(R1ProofError::Parent), // No inferred epoch/boundary grammar.
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct R1ExecutionCommitments {
    pub pre_state: Digest48,
    pub post_state: Digest48,
    pub receipts: Digest48,
    pub payload: Digest48,
    pub dependencies: Digest48,
    pub resources: Digest48,
    pub protocol_effects: Digest48,
    pub payload_bytes: u64,
    pub transaction_count: u32,
    pub gas_used: u64,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct R1Header {
    pub coordinate: R1NetworkCoordinate,
    pub protocol_profile: Digest48,
    pub epoch: u64,
    pub height: u64,
    pub round: u64,
    /// Canonical validator identity digest, never its display spelling.
    pub proposer: Digest48,
    pub authority: Digest48,
    pub schedule: Digest48,
    pub opportunity: Digest48,
    pub ledger_parent: Digest48,
    pub consensus_parent: R1Parent,
    pub execution_profile: Digest48,
    pub execution: R1ExecutionCommitments,
}
impl R1Header {
    pub fn validate_shape(&self) -> Result<()> {
        self.coordinate
            .validate()
            .map_err(|_| R1ProofError::Context)?;
        if self.height == 0 {
            return Err(R1ProofError::Header);
        }
        match &self.consensus_parent {
            R1Parent::Genesis { commitment }
                if self.height == 1 && *commitment == self.coordinate.genesis.digest => {}
            R1Parent::Ordinary {
                epoch,
                height,
                round,
                block,
                authority,
            } if *epoch == self.epoch
                && height.checked_add(1) == Some(self.height)
                && *round < self.round
                && *block == self.ledger_parent
                && *authority == self.authority => {}
            _ => return Err(R1ProofError::Parent),
        }
        Ok(())
    }
    pub(super) fn encode(&self, w: &mut Writer) -> Result<()> {
        self.validate_shape()?;
        w.u16(1)?;
        w.coordinate(&self.coordinate)?;
        w.fixed(&self.protocol_profile)?;
        w.u64(self.epoch)?;
        w.u64(self.height)?;
        w.u64(self.round)?;
        for d in [
            &self.proposer,
            &self.authority,
            &self.schedule,
            &self.opportunity,
            &self.ledger_parent,
        ] {
            w.fixed(d)?;
        }
        self.consensus_parent.encode(w)?;
        w.fixed(&self.execution_profile)?;
        let e = &self.execution;
        for d in [
            &e.pre_state,
            &e.post_state,
            &e.receipts,
            &e.payload,
            &e.dependencies,
            &e.resources,
            &e.protocol_effects,
        ] {
            w.fixed(d)?;
        }
        w.u64(e.payload_bytes)?;
        w.u32(e.transaction_count)?;
        w.u64(e.gas_used)
    }
    pub(super) fn decode(r: &mut Reader<'_>) -> Result<Self> {
        if r.u16()? != 1 {
            return Err(R1ProofError::Profile);
        }
        let h = Self {
            coordinate: r.coordinate()?,
            protocol_profile: r.fixed()?,
            epoch: r.u64()?,
            height: r.u64()?,
            round: r.u64()?,
            proposer: r.fixed()?,
            authority: r.fixed()?,
            schedule: r.fixed()?,
            opportunity: r.fixed()?,
            ledger_parent: r.fixed()?,
            consensus_parent: R1Parent::decode(r)?,
            execution_profile: r.fixed()?,
            execution: R1ExecutionCommitments {
                pre_state: r.fixed()?,
                post_state: r.fixed()?,
                receipts: r.fixed()?,
                payload: r.fixed()?,
                dependencies: r.fixed()?,
                resources: r.fixed()?,
                protocol_effects: r.fixed()?,
                payload_bytes: r.u64()?,
                transaction_count: r.u32()?,
                gas_used: r.u64()?,
            },
        };
        h.validate_shape()?;
        Ok(h)
    }

    /// Engineering candidate for the initial no-pass ordinary prefix only.
    /// Native authority must independently check the genuine Genesis schedule.
    /// This commits an opportunity; it never creates proposer authority.
    pub fn initial_ordinary_opportunity_digest(&self) -> Result<Digest48> {
        self.validate_shape()?;
        if self.epoch != 1 || !(1..=1000).contains(&self.height) || self.round != self.height {
            return Err(R1ProofError::Profile);
        }
        if self.height == 1 && self.ledger_parent != self.coordinate.genesis.digest {
            return Err(R1ProofError::Parent);
        }
        if let R1Parent::Ordinary { round, .. } = &self.consensus_parent {
            if round.checked_add(1) != Some(self.round) {
                return Err(R1ProofError::Parent);
            }
        }
        let segment_first = ((self.height - 1) / 10) * 10 + 1;
        let segment_last = segment_first + 9;
        let mut w = Writer::new(2048);
        w.coordinate(&self.coordinate)?;
        w.fixed(&self.protocol_profile)?;
        w.fixed(&self.authority)?;
        w.fixed(&self.schedule)?;
        w.u64(self.epoch)?;
        w.u64(self.height)?;
        w.u64(self.round)?;
        w.fixed(&self.proposer)?;
        self.consensus_parent.encode(&mut w)?;
        w.u64(segment_first)?;
        w.u64(segment_last)?;
        framed_digest(b"POSY/OPPORTUNITY/INITIAL/R1", &w.bytes)
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        let mut w = Writer::new(4096);
        self.encode(&mut w)?;
        Ok(w.bytes)
    }
    pub fn block_digest(&self) -> Result<Digest48> {
        let frame = synergy_posy_approval::block_commitment_frame(&self.canonical_bytes()?)
            .map_err(|_| R1ProofError::Bounds)?;
        Primitives
            .hash(HashAlgorithm::Sha3384, &frame)
            .map_err(|_| R1ProofError::Profile)?
            .try_into()
            .map_err(|_| R1ProofError::Encoding)
    }
    pub fn parent_subject(&self) -> Result<R1Parent> {
        Ok(R1Parent::Ordinary {
            epoch: self.epoch,
            height: self.height,
            round: self.round,
            block: self.block_digest()?,
            authority: self.authority,
        })
    }
}
pub(super) fn framed_digest(domain: &[u8], object: &[u8]) -> Result<Digest48> {
    let mut w = Writer::new(super::MAX_PROOF_BYTES);
    w.variable(domain, 128)?;
    w.u16(1)?;
    w.fixed(object)?;
    Primitives
        .hash(HashAlgorithm::Sha3384, &w.bytes)
        .map_err(|_| R1ProofError::Profile)?
        .try_into()
        .map_err(|_| R1ProofError::Encoding)
}
