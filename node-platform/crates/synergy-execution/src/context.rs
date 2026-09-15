use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use synergy_etdag::{EtdagDigest, ProtectedRevealAuthorization, TargetAdmissionContextV3};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorizedReveal {
    pub envelope_id: EtdagDigest,
    pub target_height: u64,
    pub content_blind_order_key: EtdagDigest,
    pub plaintext: Vec<u8>,
    /// Verified by ETDAG before this execution boundary is reached. Execution
    /// checks binding only; it never interprets the finality reference itself.
    pub reveal_authorization: ProtectedRevealAuthorization,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeterministicExecutionInput {
    pub context: TargetAdmissionContextV3,
    pub protected_batch_root: EtdagDigest,
    pub reveal_transcript_root: EtdagDigest,
    pub ordered_reveals: Vec<AuthorizedReveal>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExecutionInputError {
    InvalidAdmissionContext,
    InvalidProtectedCommitment,
    WrongTargetHeight(EtdagDigest),
    EmptyPlaintext(EtdagDigest),
    InvalidRevealAuthorization(EtdagDigest),
    DuplicateEnvelope(EtdagDigest),
    DuplicateOrderKey(EtdagDigest),
    NonDeterministicOrder,
}

impl DeterministicExecutionInput {
    pub fn new(
        context: TargetAdmissionContextV3,
        protected_batch_root: EtdagDigest,
        reveal_transcript_root: EtdagDigest,
        ordered_reveals: Vec<AuthorizedReveal>,
    ) -> Result<Self, ExecutionInputError> {
        let input = Self {
            context,
            protected_batch_root,
            reveal_transcript_root,
            ordered_reveals,
        };
        input.validate()?;
        Ok(input)
    }

    /// Recheck the entire public, deserializable input at the execution boundary.
    /// Construction-time validation alone cannot protect against callers
    /// mutating fields or decoding a forged value without using `new`.
    pub fn validate(&self) -> Result<(), ExecutionInputError> {
        let context = &self.context;
        let protected_batch_root = &self.protected_batch_root;
        let reveal_transcript_root = &self.reveal_transcript_root;
        let ordered_reveals = &self.ordered_reveals;
        context
            .validate()
            .map_err(|_| ExecutionInputError::InvalidAdmissionContext)?;
        protected_batch_root
            .validate()
            .map_err(|_| ExecutionInputError::InvalidProtectedCommitment)?;
        reveal_transcript_root
            .validate()
            .map_err(|_| ExecutionInputError::InvalidProtectedCommitment)?;
        let context_root = context
            .root()
            .map_err(|_| ExecutionInputError::InvalidAdmissionContext)?;
        let mut envelope_ids = BTreeSet::new();
        let mut order_keys = BTreeSet::new();
        let mut previous_key: Option<&EtdagDigest> = None;
        for reveal in ordered_reveals {
            reveal
                .envelope_id
                .validate()
                .map_err(|_| ExecutionInputError::InvalidProtectedCommitment)?;
            reveal
                .content_blind_order_key
                .validate()
                .map_err(|_| ExecutionInputError::InvalidProtectedCommitment)?;
            if reveal.target_height != context.target_height {
                return Err(ExecutionInputError::WrongTargetHeight(
                    reveal.envelope_id.clone(),
                ));
            }
            if reveal.plaintext.is_empty() {
                return Err(ExecutionInputError::EmptyPlaintext(
                    reveal.envelope_id.clone(),
                ));
            }
            if reveal.reveal_authorization.validate().is_err()
                || reveal.reveal_authorization.context_root != context_root
                || reveal.reveal_authorization.target_height != context.target_height
                || &reveal.reveal_authorization.protected_batch_root != protected_batch_root
            {
                return Err(ExecutionInputError::InvalidRevealAuthorization(
                    reveal.envelope_id.clone(),
                ));
            }
            if !envelope_ids.insert(reveal.envelope_id.clone()) {
                return Err(ExecutionInputError::DuplicateEnvelope(
                    reveal.envelope_id.clone(),
                ));
            }
            if !order_keys.insert(reveal.content_blind_order_key.clone()) {
                return Err(ExecutionInputError::DuplicateOrderKey(
                    reveal.content_blind_order_key.clone(),
                ));
            }
            if previous_key.is_some_and(|previous| previous >= &reveal.content_blind_order_key) {
                return Err(ExecutionInputError::NonDeterministicOrder);
            }
            previous_key = Some(&reveal.content_blind_order_key);
        }
        Ok(())
    }

    pub fn is_empty(&self) -> bool {
        self.ordered_reveals.is_empty()
    }

    pub const fn may_determine_finality(&self) -> bool {
        false
    }
}
