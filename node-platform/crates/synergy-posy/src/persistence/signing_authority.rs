use crate::{
    domains::is_consensus_signing_domain, JournalError, PosyError, PosyResult, SignOnceJournal,
    SigningSlot,
};

/// External Aegis key-custody boundary. PoSy supplies an already-bound
/// transcript and never owns or exports private key material.
pub trait ConsensusSigner {
    fn validator_id(&self) -> &str;
    fn key_id(&self) -> &str;
    fn sign(&self, domain: &str, height: u64, transcript: &[u8]) -> Result<Vec<u8>, String>;
}

/// Sign-once authority backed by the durable PoSy safety journal.
pub struct DurableSigningAuthority<S> {
    journal: SignOnceJournal,
    signer: S,
}

impl<S: ConsensusSigner> DurableSigningAuthority<S> {
    pub fn new(journal: SignOnceJournal, signer: S) -> Self {
        Self { journal, signer }
    }

    pub fn validator_id(&self) -> &str {
        self.signer.validator_id()
    }

    pub fn key_id(&self) -> &str {
        self.signer.key_id()
    }

    /// Replays cached exact signed bytes after restart. A reserved subject whose
    /// signature never reached durable storage may be signed before publication;
    /// conflicting subjects and transcript changes are refused.
    pub fn sign_once(
        &mut self,
        slot: SigningSlot,
        signing_domain: &str,
        subject: &str,
        transcript: &[u8],
    ) -> PosyResult<Vec<u8>> {
        let expected_slot = match signing_domain {
            crate::POSY_SIMPLIFIED_PROPOSAL_DOMAIN => "proposal",
            crate::POSY_SIMPLIFIED_BLOCK_VOTE_DOMAIN => "block-vote",
            crate::POSY_SIMPLIFIED_TIMEOUT_VOTE_DOMAIN => "timeout-vote",
            crate::PROPOSAL_ECHO_DOMAIN => "proposal-echo",
            crate::PROPOSAL_READY_DOMAIN => "proposal-ready",
            _ => "",
        };
        if !is_consensus_signing_domain(signing_domain)
            || slot.domain != expected_slot
            || subject.trim().is_empty()
            || transcript.is_empty()
        {
            return Err(PosyError::invalid(
                "invalid domain, subject, or transcript for PoSy signing",
            ));
        }
        if slot.domain == "block-vote" {
            let timeout = SigningSlot {
                domain: "timeout-vote".into(),
                ..slot.clone()
            };
            if self.journal.subject(&timeout).is_some() {
                return Err(PosyError::Conflict(
                    "timeout already signed in vote round".into(),
                ));
            }
            if let Some((_, previous)) = self.journal.last_block_vote(slot.height) {
                if previous != subject
                    && self
                        .journal
                        .subject(&SigningSlot {
                            domain: "block-vote-unlock".into(),
                            ..slot.clone()
                        })
                        .is_none()
                {
                    return Err(PosyError::Conflict(
                        "height-wide vote subject conflict".into(),
                    ));
                }
            }
        }
        self.journal
            .record(slot.clone(), subject.to_owned())
            .map_err(map_journal_error)?;
        if let Some(signature) = self
            .journal
            .signed_bytes(&slot, signing_domain, transcript)
            .map_err(map_journal_error)?
        {
            return Ok(signature);
        }
        let signature = self
            .signer
            .sign(signing_domain, slot.height, transcript)
            .map_err(PosyError::Signature)?;
        self.journal
            .record_signature(&slot, signing_domain, transcript, &signature)
            .map_err(map_journal_error)?;
        Ok(signature)
    }

    pub fn sign_block_vote_verified(
        &mut self,
        vote: &crate::BlockVote,
        epoch: &crate::SimplifiedEpochContext,
        validators: &crate::FrozenValidatorRegistry,
        verifier: &impl crate::ConsensusSignatureVerifier,
        unlock: Option<&crate::SimplifiedTimeoutCertificate>,
    ) -> PosyResult<Vec<u8>> {
        if vote.validator_id != self.validator_id() || vote.key_id != self.key_id() {
            return Err(PosyError::invalid("block vote signing identity mismatch"));
        }
        let slot = SigningSlot {
            height: vote.context.height,
            round: vote.context.round,
            domain: "block-vote".into(),
        };
        let timeout_slot = SigningSlot {
            domain: "timeout-vote".into(),
            ..slot.clone()
        };
        if self.journal.subject(&timeout_slot).is_some() {
            return Err(PosyError::Conflict(
                "timeout signing prohibits later same-round block vote".into(),
            ));
        }
        let candidate = crate::CertifiedCandidateSubject::new(
            vote.context.clone(),
            vote.block_id.clone(),
            vote.parent_block_id.clone(),
            vote.parent.clone(),
            vote.protected_execution_root.clone(),
        )?;
        let subject = candidate.id()?;
        if let Some((previous_round, previous)) = self.journal.last_block_vote(slot.height) {
            if previous != subject {
                let tc = unlock.ok_or_else(|| {
                    PosyError::Conflict("height-wide block vote conflict lacks no-carry TC".into())
                })?;
                tc.verify(epoch, validators, verifier)?;
                if tc.context.height != slot.height
                    || tc.context.round <= previous_round
                    || tc.context.round.checked_add(1) != Some(slot.round)
                    || vote.takeover_tc_id.as_deref() != Some(tc.id()?.as_str())
                    || tc.mandatory_carry_candidate()?.is_some()
                    || tc.highest_parent()? != vote.parent
                {
                    return Err(PosyError::Conflict(
                        "block vote conflict unlock is not a later no-carry closure".into(),
                    ));
                }
                self.journal
                    .record(
                        SigningSlot {
                            domain: "block-vote-unlock".into(),
                            ..slot.clone()
                        },
                        tc.id()?,
                    )
                    .map_err(map_journal_error)?;
            }
        }
        self.sign_once(
            slot,
            crate::POSY_SIMPLIFIED_BLOCK_VOTE_DOMAIN,
            &subject,
            &crate::block_vote_signing_bytes(vote)?,
        )
    }

    pub fn record_verified_finalized_floor(&mut self, height: u64) -> PosyResult<()> {
        self.journal
            .advance_finalized_floor(height)
            .map_err(map_journal_error)
    }

    pub fn journal(&self) -> &SignOnceJournal {
        &self.journal
    }
}

fn map_journal_error(error: JournalError) -> PosyError {
    match error {
        JournalError::ConflictingSubject { .. } => {
            PosyError::Conflict("refused conflicting PoSy signing subject".into())
        }
        JournalError::Io(message) | JournalError::Corrupt(message) => {
            PosyError::NotReady(format!("PoSy signing journal unavailable: {message}"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::*;
    struct Signer;
    impl ConsensusSigner for Signer {
        fn validator_id(&self) -> &str {
            "v0"
        }
        fn key_id(&self) -> &str {
            "k0"
        }
        fn sign(&self, _: &str, _: u64, _: &[u8]) -> Result<Vec<u8>, String> {
            Ok(vec![1])
        }
    }
    struct Verifier;
    impl ConsensusSignatureVerifier for Verifier {
        fn verify_consensus_signature(
            &self,
            _: &str,
            _: &[u8],
            _: &ValidatorRecord,
            _: &str,
            _: u64,
            _: &[u8],
        ) -> PosyResult<()> {
            Ok(())
        }
    }
    #[test]
    fn height_vote_conflict_needs_verified_later_no_carry_and_timeout_blocks_vote() {
        let root = std::env::temp_dir().join(format!("posy-height-signing-{}", std::process::id()));
        let registry = FrozenValidatorRegistry::new(
            1,
            (0..5)
                .map(|i| ValidatorRecord {
                    validator_id: format!("v{i}"),
                    consensus_key_id: format!("k{i}"),
                    frozen_voting_weight: 1,
                    status: ValidatorStatus::Active,
                })
                .collect(),
        )
        .unwrap();
        let epoch = SimplifiedEpochContext::from_frozen_registry(
            1266,
            "testnet-v3".into(),
            1,
            1,
            20,
            "a".repeat(64),
            "b".repeat(64),
            &registry,
        )
        .unwrap();
        let parent = SimplifiedFinalityParent::Genesis {
            genesis_hash: "c".repeat(64),
            block_id: "genesis".into(),
            reference_id: "d".repeat(64),
        };
        let mut vote = BlockVote {
            context: ConsensusObjectContext::for_height(&epoch, 1, 0).unwrap(),
            block_id: "A".into(),
            parent_block_id: "genesis".into(),
            parent: parent.clone(),
            takeover_tc_id: None,
            protected_execution_root: "e".repeat(64),
            validator_id: "v0".into(),
            key_id: "k0".into(),
            signature: vec![],
        };
        let mut authority = DurableSigningAuthority::new(
            SignOnceJournal::load(root.join("journal.json")).unwrap(),
            Signer,
        );
        authority
            .sign_block_vote_verified(&vote, &epoch, &registry, &Verifier, None)
            .unwrap();
        vote.context.round = 1;
        vote.block_id = "B".into();
        assert!(authority
            .sign_block_vote_verified(&vote, &epoch, &registry, &Verifier, None)
            .is_err());
        let reports = (0..4)
            .map(|i| TimeoutVote {
                context: vote.context.clone(),
                lease_index: epoch.lease_index(1).unwrap(),
                timed_out_proposer: epoch.authorized_proposer(1, 1).unwrap().into(),
                highest_parent: parent.clone(),
                previous_tc_id: Some("f".repeat(64)),
                last_voted_candidate: None,
                validator_id: format!("v{i}"),
                key_id: format!("k{i}"),
                signature: vec![1],
            })
            .collect();
        let tc = SimplifiedTimeoutCertificate::from_votes(reports).unwrap();
        vote.context.round = 2;
        vote.takeover_tc_id = Some(tc.id().unwrap());
        authority
            .sign_block_vote_verified(&vote, &epoch, &registry, &Verifier, Some(&tc))
            .unwrap();
        authority
            .journal
            .record(
                SigningSlot {
                    height: 1,
                    round: 3,
                    domain: "timeout-vote".into(),
                },
                "timeout".into(),
            )
            .unwrap();
        vote.context.round = 3;
        assert!(authority
            .sign_block_vote_verified(&vote, &epoch, &registry, &Verifier, None)
            .is_err());
        let _ = std::fs::remove_dir_all(root);
    }
}
