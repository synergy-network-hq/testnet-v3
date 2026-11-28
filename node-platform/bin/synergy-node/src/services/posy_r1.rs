//! Current native PoSy cryptographic binding, separate from historical v3.
//! The private Genesis token authenticates the keys, not a live epoch schedule,
//! independent payload validity or successor/revocation authority.
use std::collections::BTreeMap;
use synergy_address_engine::{
    apqe::{crypto_engine::CryptoEngine, provider::SignOptions},
    types::Algorithm,
};
use synergy_genesis::r1::VerifiedR1Genesis;
use synergy_posy::r1::{
    consensus_key_id, Digest48, R1AuthorityMember, R1ProofError, R1QuorumCertificate,
};

use synergy_posy::r1::APPROVAL_CONTEXT;

pub(crate) struct InitialR1ConsensusKeys<'a> {
    genesis: &'a VerifiedR1Genesis,
    members: Vec<R1AuthorityMember>,
    keys: BTreeMap<Digest48, Vec<u8>>,
}
impl<'a> InitialR1ConsensusKeys<'a> {
    pub(crate) fn from_verified_genesis(
        genesis: &'a VerifiedR1Genesis,
    ) -> Result<Self, R1ProofError> {
        let mut entries = genesis.initial_validator_keys();
        entries.sort_by_key(|v| v.identity);
        if entries.is_empty() || entries.len() > synergy_posy::r1::MAX_VALIDATORS {
            return Err(R1ProofError::Authority);
        }
        let mut members = Vec::with_capacity(entries.len());
        let mut keys = BTreeMap::new();
        let mut previous = None;
        for entry in entries {
            let key = entry.consensus_key;
            if key.algorithm != Algorithm::MlDsa65
                || key.role != "consensus"
                || key.public_key.len() != 1952
                || key.generation == 0
                || entry.weight == 0
                || previous.is_some_and(|id| id >= entry.identity)
            {
                return Err(R1ProofError::Authority);
            }
            previous = Some(entry.identity);
            let key_id = consensus_key_id(&key.public_key, key.generation)?;
            if keys.insert(key_id, key.public_key).is_some() {
                return Err(R1ProofError::Authority);
            }
            members.push(R1AuthorityMember {
                identity: entry.identity,
                key_id,
                key_version: key.generation,
                weight: entry.weight,
                signature_bytes: 3309,
            });
        }
        Ok(Self {
            genesis,
            members,
            keys,
        })
    }
    fn verify_member_approval(
        &self,
        member: &R1AuthorityMember,
        message: &[u8],
        signature: &[u8],
        engine: &CryptoEngine,
    ) -> Result<(), R1ProofError> {
        if signature.len() != 3309 || !self.members.iter().any(|m| m == member) {
            return Err(R1ProofError::Signature);
        }
        let key = self
            .keys
            .get(&member.key_id)
            .ok_or(R1ProofError::Authority)?;
        match engine.verify(
            Algorithm::MlDsa65,
            key,
            message,
            signature,
            SignOptions::Pure {
                context: APPROVAL_CONTEXT,
            },
        ) {
            Ok(true) => Ok(()),
            _ => Err(R1ProofError::Signature),
        }
    }
    pub(crate) fn members(&self) -> &[R1AuthorityMember] {
        &self.members
    }
    /// Initial keys are useful only under their exact authenticated network.
    /// This method does not endorse caller authority/schedule/opportunity data.
    pub(crate) fn verify_approval(
        &self,
        qc: &R1QuorumCertificate,
        index: usize,
        engine: &CryptoEngine,
    ) -> Result<(), R1ProofError> {
        qc.header
            .coordinate
            .ensure_matches(self.genesis.coordinate())
            .map_err(|_| R1ProofError::Context)?;
        // PoSy v0.5 pp50–51: the Genesis production epoch is epoch 1,
        // heights 1..=1000. Epoch zero is not an operating authority.
        if qc.header.epoch != 1 || !(1..=1000).contains(&qc.header.height) {
            return Err(R1ProofError::Authority);
        }
        let approval = qc.approvals.get(index).ok_or(R1ProofError::Signer)?;
        let member = self
            .members
            .get(approval.member_index as usize)
            .ok_or(R1ProofError::Signer)?;
        if approval.key_version != member.key_version || approval.signature.len() != 3309 {
            return Err(R1ProofError::Signature);
        }
        let message = qc.approval_message(member)?;
        self.verify_member_approval(member, &message, &approval.signature, engine)
    }
}

/// Native section44 verification. The authority/schedule is genuine complete
/// Genesis, never a supplied member table. This certifies committed execution;
/// it intentionally does not implement the full-validator execution trait.
pub(crate) struct InitialR1ClientVerifier<'a> {
    keys: InitialR1ConsensusKeys<'a>,
    engine: &'a CryptoEngine,
    authority: Digest48,
    protocol: Digest48,
    schedule: Digest48,
    producers: Vec<Digest48>,
    previous_height: u64,
    previous_block: Digest48,
    previous_state: Digest48,
}
impl<'a> InitialR1ClientVerifier<'a> {
    pub(crate) fn new(
        genesis: &'a VerifiedR1Genesis,
        engine: &'a CryptoEngine,
        previous: Option<&synergy_posy::r1::VerifiedR1ClientFinalizedAnchor>,
    ) -> Result<Self, R1ProofError> {
        let formation = genesis
            .compiled()
            .complete_formation()
            .ok_or(R1ProofError::Authority)?;
        let initial = formation.initial_authority();
        if initial.epoch != 1 || initial.first_height != 1 || initial.last_height != 1000 {
            return Err(R1ProofError::Authority);
        }
        let keys = InitialR1ConsensusKeys::from_verified_genesis(genesis)?;
        let schedule = *formation.computed_schedule().commitment();
        let digest = synergy_posy::r1::R1AuthoritySubject {
            network: &genesis.coordinate().network,
            activated_profiles: &genesis.coordinate().activated_profiles,
            protocol_profile: initial.protocol_profile,
            epoch: initial.epoch,
            first_height: initial.first_height,
            last_height: initial.last_height,
            schedule,
            members: keys.members(),
        }
        .digest()?;
        if digest != initial.commitment {
            return Err(R1ProofError::Authority);
        }
        let (previous_height, previous_block, previous_state) = if let Some(anchor) = previous {
            anchor
                .coordinate()
                .ensure_matches(genesis.coordinate())
                .map_err(|_| R1ProofError::Context)?;
            if anchor.height() == 0 || anchor.height() > 1000 {
                return Err(R1ProofError::Authority);
            }
            (
                anchor.height(),
                *anchor.block_digest(),
                *anchor.state_root(),
            )
        } else {
            (
                0,
                genesis.coordinate().genesis.digest,
                *genesis.initial_state_root(),
            )
        };
        Ok(Self {
            keys,
            engine,
            authority: digest,
            protocol: initial.protocol_profile,
            schedule,
            producers: formation.computed_schedule().permutation().to_vec(),
            previous_height,
            previous_block,
            previous_state,
        })
    }
    pub(crate) fn verify_initial_ordinary_header(
        &self,
        h: &synergy_posy::r1::R1Header,
    ) -> Result<(), R1ProofError> {
        synergy_posy::r1::R1ClientFinalityVerifier::authenticate_authority(self, h)?;
        let formation = self
            .keys
            .genesis
            .compiled()
            .complete_formation()
            .ok_or(R1ProofError::Authority)?;
        if formation.computed_schedule().planned_proposer(h.height)? != &h.proposer {
            return Err(R1ProofError::Authority);
        }
        if h.opportunity != h.initial_ordinary_opportunity_digest()? {
            return Err(R1ProofError::Header);
        }
        Ok(())
    }
    pub(crate) fn verify_original(
        &self,
        bytes: &[u8],
    ) -> Result<synergy_posy::r1::VerifiedR1ClientFinalizedAnchor, R1ProofError> {
        synergy_posy::r1::R1ThreeQcProof::verify_client_original(
            bytes,
            self.keys.genesis.coordinate(),
            self.previous_height,
            &self.previous_block,
            self,
        )
    }
}
impl synergy_posy::r1::R1ClientFinalityVerifier for InitialR1ClientVerifier<'_> {
    fn authenticate_authority(
        &self,
        h: &synergy_posy::r1::R1Header,
    ) -> Result<Vec<R1AuthorityMember>, R1ProofError> {
        h.coordinate
            .ensure_matches(self.keys.genesis.coordinate())
            .map_err(|_| R1ProofError::Context)?;
        if h.epoch != 1
            || !(1..=1000).contains(&h.height)
            || h.authority != self.authority
            || h.protocol_profile != self.protocol
            || h.schedule != self.schedule
        {
            return Err(R1ProofError::Authority);
        }
        Ok(self.keys.members.clone())
    }
    fn verify_certified_header(&self, h: &synergy_posy::r1::R1Header) -> Result<(), R1ProofError> {
        h.validate_shape()?;
        synergy_posy::r1::R1ClientFinalityVerifier::authenticate_authority(self, h)?;
        self.verify_initial_ordinary_header(h)?;
        if !self.producers.contains(&h.proposer)
            || !self.keys.members.iter().any(|m| m.identity == h.proposer)
        {
            return Err(R1ProofError::Authority);
        }
        // Exact original approvals attest opportunity/payload/execution predicates.
        // This client never produces a full-validator execution receipt.
        Ok(())
    }
    fn verify_approval(
        &self,
        m: &R1AuthorityMember,
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), R1ProofError> {
        self.keys
            .verify_member_approval(m, message, signature, self.engine)
    }
    fn verify_finalized_extension(
        &self,
        c: &synergy_protocol_types::R1NetworkCoordinate,
        height: u64,
        block: &Digest48,
        target: &synergy_posy::r1::R1Header,
    ) -> Result<(), R1ProofError> {
        c.ensure_matches(self.keys.genesis.coordinate())
            .map_err(|_| R1ProofError::Context)?;
        if height != self.previous_height || *block != self.previous_block {
            return Err(R1ProofError::FinalizedConflict);
        }
        if target.height == height {
            if target.block_digest()? != *block
                || target.execution.post_state != self.previous_state
            {
                return Err(R1ProofError::FinalizedConflict);
            }
            return Ok(());
        }
        // A skipped interval needs a separately verified intervening chain. Never
        // infer ancestry from a server cursor/height or arbitrary stored row.
        if height.checked_add(1) != Some(target.height)
            || target.ledger_parent != *block
            || target.execution.pre_state != self.previous_state
        {
            return Err(R1ProofError::Parent);
        }
        Ok(())
    }
}
