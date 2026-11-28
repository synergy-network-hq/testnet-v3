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
        let key = self
            .keys
            .get(&member.key_id)
            .ok_or(R1ProofError::Authority)?;
        let message = qc.approval_message(member)?;
        match engine.verify(
            Algorithm::MlDsa65,
            key,
            &message,
            &approval.signature,
            SignOptions::Pure {
                context: APPROVAL_CONTEXT,
            },
        ) {
            Ok(true) => Ok(()),
            _ => Err(R1ProofError::Signature),
        }
    }
}
