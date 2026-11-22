//! Candidate sponsor resource consent for an encrypted enrollment envelope.
use serde::{Deserialize, Serialize};
use synergy_aegis::{AegisHashEngine, AegisSha3_256};
use synergy_identity::authorization::IdentityAuthorizationCarrier;

use super::{ProcessingContext, ProcessingEnvelope, PW13_SPONSOR_CANDIDATE_PROFILE_ID};
use crate::{EtdagDigest, EtdagError};

const DIGEST_DOMAIN: &[u8] = b"AEGIS/PW13-SPONSOR-ADMISSION-CANDIDATE/v1\0";
pub const PW13_SPONSOR_ADMISSION_CONTEXT: &[u8] = b"AEGIS.PW13.SPONSOR.ADMISSION.CANDIDATE.V1";

/// The envelope ID commits to the public payer and nonce in the AAD. The
/// original sponsor intent and enrollment authorization are inside the payload.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Pw13SponsoredResources {
    pub genesis: [u8; 32],
    pub action: u16,
    pub gas_limit: u64,
    pub maximum_total_fee: [u8; 32],
    pub valid_until_finalized_height: u64,
    pub sponsor_intent_digest: Vec<u8>,
    pub envelope_id: EtdagDigest,
}

impl Pw13SponsoredResources {
    pub fn signing_digest(&self) -> Result<[u8; 64], EtdagError> {
        self.envelope_id.validate()?;
        if self.genesis == [0; 32]
            || self.gas_limit == 0
            || self.maximum_total_fee == [0; 32]
            || self.valid_until_finalized_height == 0
            || self.sponsor_intent_digest.len() != 64
            || self.envelope_id.is_zero()
        {
            return Err(EtdagError::InvalidEnvelope(
                "invalid PW13 sponsor resources".into(),
            ));
        }
        let encoded = serde_json::to_vec(self).map_err(|error| {
            EtdagError::Corrupt(format!("encode PW13 sponsor resources: {error}"))
        })?;
        AegisSha3_256
            .sha3_512_segments(&[DIGEST_DOMAIN, &encoded])
            .map_err(|error| EtdagError::Corrupt(format!("hash PW13 sponsor resources: {error:?}")))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Pw13SponsoredAdmission {
    pub resources: Pw13SponsoredResources,
    pub binding: IdentityAuthorizationCarrier,
    pub public_key: Vec<u8>,
    pub signature: Vec<u8>,
}

impl Pw13SponsoredAdmission {
    pub fn validate_context(
        &self,
        envelope: &ProcessingEnvelope,
        context: &ProcessingContext,
    ) -> Result<(), EtdagError> {
        if context.profile_id != PW13_SPONSOR_CANDIDATE_PROFILE_ID
            || self.resources.envelope_id != envelope.envelope_id
            || envelope.aad.nonce_slot == u64::MAX
            || self.resources.valid_until_finalized_height
                < context.authority.source_finalized_height
        {
            return Err(EtdagError::ContextMismatch);
        }
        if self.public_key.len() != 2_592 || self.signature.len() != 4_627 {
            return Err(EtdagError::InvalidSignature);
        }
        envelope.validate_context(context)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sponsor_digest_matches_independent_vector() {
        let resources = Pw13SponsoredResources {
            genesis: [1; 32],
            action: 0x7001,
            gas_limit: 5,
            maximum_total_fee: [2; 32],
            valid_until_finalized_height: 123,
            sponsor_intent_digest: vec![3; 64],
            envelope_id: EtdagDigest("ab".repeat(64)),
        };
        assert_eq!(serde_json::to_vec(&resources).unwrap().len(), 526);
        let digest = resources.signing_digest().unwrap();
        let hex: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
        assert_eq!(
            hex,
            concat!(
                "ac9c4103c991d4bbdc247a5fa8c10bd443a4ebd31bb02c4d9076eeece31951ca1",
                "acf5427119829d787f0ff625a0e64f39984bbeef8b384f44243bb6cac1e180e"
            )
        );
    }
}
