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

    /// A previously recorded identical subject may be signed again after a
    /// restart so an interrupted broadcast can recover; conflicting subjects
    /// are always refused by the durable journal.
    pub fn sign_once(
        &mut self,
        slot: SigningSlot,
        signing_domain: &str,
        subject: &str,
        transcript: &[u8],
    ) -> PosyResult<Vec<u8>> {
        if !is_consensus_signing_domain(signing_domain)
            || subject.trim().is_empty()
            || transcript.is_empty()
        {
            return Err(PosyError::invalid(
                "invalid domain, subject, or transcript for PoSy signing",
            ));
        }
        self.journal
            .record(slot.clone(), subject.to_owned())
            .map_err(map_journal_error)?;
        self.signer
            .sign(signing_domain, slot.height, transcript)
            .map_err(PosyError::Signature)
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
