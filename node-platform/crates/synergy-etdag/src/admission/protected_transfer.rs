//! Candidate transfer admission framing. Only a governed caller may
//! authenticate the finalized policy, fee schedule and ingress context.
use serde::{Deserialize, Serialize};
use synergy_aegis::{AegisHashEngine, AegisSha3_256};

use super::{ProcessingContext, ProcessingEnvelope, PW13_TRANSFER_CANDIDATE_PROFILE_ID};
use crate::{EtdagDigest, EtdagError};

const DIGEST_DOMAIN: &[u8] = b"AEGIS/PW13-TRANSFER-ADMISSION-CANDIDATE/v1\0";
pub const PW13_ADMISSION_CONTEXT: &[u8] = b"AEGIS.PW13.TRANSFER.ADMISSION.CANDIDATE.V1";

/// The signed public resource fields. The native intent digest commits to the
/// canonical DCBOR body without disclosing its private action payload.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Pw13TransferResources {
    pub genesis: [u8; 32],
    pub account: [u8; 20],
    pub policy_epoch: u64,
    pub policy_hash: [u8; 32],
    pub gas_limit: u64,
    pub maximum_total_fee: [u8; 32],
    pub valid_until_finalized_height: u64,
    pub native_intent_digest: Vec<u8>,
    pub envelope_id: EtdagDigest,
}

impl Pw13TransferResources {
    /// Pure ML-DSA-87 signs this digest using the separate admission context.
    /// Sending a valid admission never confers authority to execute an action.
    pub fn signing_digest(&self) -> Result<[u8; 64], EtdagError> {
        self.envelope_id.validate()?;
        if self.genesis == [0; 32]
            || self.policy_hash == [0; 32]
            || self.gas_limit == 0
            || self.maximum_total_fee == [0; 32]
            || self.valid_until_finalized_height == 0
            || self.native_intent_digest.len() != 64
            || self.envelope_id.is_zero()
        {
            return Err(EtdagError::InvalidEnvelope("invalid PW13 resources".into()));
        }
        // Domain-separated native APQE hash of the exact compact struct JSON.
        // The envelope identifier already commits to all ciphertext and AAD.
        let encoded = serde_json::to_vec(self)
            .map_err(|error| EtdagError::Corrupt(format!("encode PW13 resources: {error}")))?;
        AegisSha3_256
            .sha3_512_segments(&[DIGEST_DOMAIN, &encoded])
            .map_err(|error| EtdagError::Corrupt(format!("hash PW13 resources: {error:?}")))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Pw13AdmissionProof {
    pub participant_id: [u8; 32],
    pub key_version: u64,
    pub signature: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Pw13TransferAdmission {
    pub resources: Pw13TransferResources,
    /// Exactly D then P. Keys must come from finalized enrollment.
    pub proofs: [Pw13AdmissionProof; 2],
}

impl Pw13TransferAdmission {
    pub fn validate_context(
        &self,
        envelope: &ProcessingEnvelope,
        context: &ProcessingContext,
    ) -> Result<(), EtdagError> {
        if context.profile_id != PW13_TRANSFER_CANDIDATE_PROFILE_ID
            || self.resources.envelope_id != envelope.envelope_id
            || envelope.aad.nonce_slot == u64::MAX
            || self.resources.valid_until_finalized_height
                < context.authority.source_finalized_height
        {
            return Err(EtdagError::ContextMismatch);
        }
        if self.proofs[0].participant_id == self.proofs[1].participant_id
            || self
                .proofs
                .iter()
                .any(|proof| proof.participant_id == [0; 32] || proof.signature.len() != 4_627)
        {
            return Err(EtdagError::InvalidSignature);
        }
        envelope.validate_context(context)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn candidate_transfer_admission_digest_matches_independent_vector() {
        let resources = Pw13TransferResources {
            genesis: [1; 32],
            account: [2; 20],
            policy_epoch: 4,
            policy_hash: [3; 32],
            gas_limit: 21_000,
            maximum_total_fee: [4; 32],
            valid_until_finalized_height: 123,
            native_intent_digest: vec![5; 64],
            envelope_id: EtdagDigest("ab".repeat(64)),
        };
        assert_eq!(serde_json::to_vec(&resources).unwrap().len(), 663);
        let digest = resources.signing_digest().unwrap();
        let hex: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
        assert_eq!(
            hex,
            concat!(
                "91d188743e596490ef8affc1f6271a26bf8413ad6bc630cfddcea6d9b8bda461",
                "9749b052810f2bd20ed62afe3004090560c778da3b5e8435d0450c4929a0b42d"
            )
        );
        let mut changed = resources;
        changed.maximum_total_fee[0] ^= 1;
        assert_ne!(changed.signing_digest().unwrap(), digest);
    }
}
