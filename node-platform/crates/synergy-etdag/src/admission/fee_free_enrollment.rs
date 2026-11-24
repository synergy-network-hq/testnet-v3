//! Fee-exempt enrollment is a closed nonfinancial protocol operation. Resource
//! gas remains positive; no account, fee cap, subsidy or payer authorizes it.
use super::{ProcessingContext, ProcessingEnvelope, Pw13AdmissionProof};
use crate::{EtdagDigest, EtdagError};
use serde::{Deserialize, Serialize};
use synergy_aegis::{AegisHashEngine, AegisSha3_256};

pub const PW13_FEE_FREE_ENROLLMENT_PROFILE_ID: &str = "etdag-pw13-fee-free-enrollment-v1";
pub const PW13_FEE_FREE_ENROLLMENT_LANE: &str = "fee-free-enrollment";
pub const PW13_FEE_FREE_ENROLLMENT_ADMISSION_CONTEXT: &[u8] = b"AEGIS.PW13.FEE-FREE.ENROLLMENT.ADMISSION.V1";
pub const FEE_FREE_ENROLL_COMMIT: u16 = 0x7001;
pub const FEE_FREE_ENROLL_REVEAL: u16 = 0x7002;
pub const FEE_FREE_ENROLLMENT_SETTLEMENT_PREFIX:&str="apqe-protected-account-candidate/v1/fee-free-enrollment/";
pub fn fee_free_enrollment_candidate_digest(bytes:&[u8])->Result<[u8;64],EtdagError> {
    AegisSha3_256.sha3_512_segments(&[b"AEGIS/FEE-FREE-ENROLLMENT-CANDIDATE/v1\0",bytes])
        .map_err(|e|EtdagError::Corrupt(format!("{e:?}")))
}
pub fn fee_free_enrollment_settlement_key(session:&[u8;32],action:u16)->Result<String,EtdagError> {
    let stage=match action{FEE_FREE_ENROLL_COMMIT=>0,FEE_FREE_ENROLL_REVEAL=>1,_=>return Err(EtdagError::InvalidExecutionInput)};
    Ok(format!("{FEE_FREE_ENROLLMENT_SETTLEMENT_PREFIX}{}/{stage}",session.iter().map(|b|format!("{b:02x}")).collect::<String>()))
}

#[derive(Clone,Debug,PartialEq,Eq,Serialize,Deserialize)]
#[serde(rename_all="snake_case")]
pub enum FeeFreeEnrollmentOutcome {CommitApplied,CommitAlreadyPresent,RevealApplied,RevealRejectedCommitUsed,Expired}
#[derive(Clone,Debug,PartialEq,Eq,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FeeFreeEnrollmentSettlement {
    pub version:u8,
    pub genesis:[u8;32],
    pub session_id:[u8;32],
    pub account:[u8;20],
    pub action:u16,
    pub commitment:[u8;32],
    pub envelope_id:EtdagDigest,
    pub admission_digest:Vec<u8>,
    pub source_finalized_height:u64,
    pub source_consensus_timestamp_unix:u64,
    pub deciding_finalized_height:u64,
    pub included_height:u64,
    pub inclusion_consensus_timestamp_unix:u64,
    pub gas_used:u64,
    pub fee_nwei:u128,
    pub outcome:FeeFreeEnrollmentOutcome,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FeeFreeEnrollmentIntent {
    pub version: u8,
    pub genesis: [u8;32],
    pub session_id: [u8;32],
    pub account: [u8;20],
    pub action: u16,
    pub commitment: [u8;32],
    pub payload_sha3_256: [u8;32],
    pub valid_until_finalized_height: u64,
}
impl FeeFreeEnrollmentIntent {
    pub fn canonical_bytes(&self)->Result<Vec<u8>,EtdagError> {
        if self.version!=1||self.genesis==[0;32]||self.session_id==[0;32]||self.account==[0;20]
            ||self.commitment==[0;32]||self.payload_sha3_256==[0;32]||self.valid_until_finalized_height==0
            ||!matches!(self.action,FEE_FREE_ENROLL_COMMIT|FEE_FREE_ENROLL_REVEAL) {
            return Err(EtdagError::InvalidEnvelope("invalid closed fee-free enrollment intent".into()));
        }
        serde_json::to_vec(self).map_err(|e|EtdagError::Corrupt(e.to_string()))
    }
    pub fn signing_digest(&self)->Result<[u8;64],EtdagError> {
        AegisSha3_256.sha3_512_segments(&[b"AEGIS/FEE-FREE-ENROLLMENT-INTENT/v1\0",&self.canonical_bytes()?])
            .map_err(|e|EtdagError::Corrupt(format!("{e:?}")))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Pw13FeeFreeEnrollmentResources {
    pub genesis: [u8;32],
    pub session_id: [u8;32],
    pub account: [u8;20],
    pub action: u16,
    pub commitment: [u8;32],
    pub enrollment_digest: Vec<u8>,
    pub enrollment_intent_digest: Vec<u8>,
    pub gas_limit: u64,
    pub valid_until_finalized_height: u64,
    pub envelope_id: EtdagDigest,
}
impl Pw13FeeFreeEnrollmentResources {
    pub fn sender_id(&self)->String {
        format!("enroll:{}",self.session_id.iter().map(|b|format!("{b:02x}")).collect::<String>())
    }
    pub fn stage_nonce(&self)->Result<u64,EtdagError> {
        match self.action {FEE_FREE_ENROLL_COMMIT=>Ok(0),FEE_FREE_ENROLL_REVEAL=>Ok(1),_=>Err(EtdagError::InvalidExecutionInput)}
    }
    pub fn signing_digest(&self)->Result<[u8;64],EtdagError> {
        self.stage_nonce()?;self.envelope_id.validate()?;
        if self.genesis==[0;32]||self.session_id==[0;32]||self.account==[0;20]||self.commitment==[0;32]
            ||self.gas_limit==0||self.valid_until_finalized_height==0||self.enrollment_digest.len()!=64
            ||self.enrollment_intent_digest.len()!=64||self.envelope_id.is_zero() {
            return Err(EtdagError::InvalidEnvelope("invalid fee-free enrollment resources".into()));
        }
        let raw=serde_json::to_vec(self).map_err(|e|EtdagError::Corrupt(e.to_string()))?;
        AegisSha3_256.sha3_512_segments(&[b"AEGIS/PW13-FEE-FREE-ENROLLMENT-ADMISSION/v1\0",&raw])
            .map_err(|e|EtdagError::Corrupt(format!("{e:?}")))
    }
}

/// Existing native ML-DSA-87 initial-enrollment proof, represented without a
/// configurable algorithm or signature context. Role order is D, P, optional R.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InitialEnrollmentProof {
    pub role_id: u8,
    pub participant_id: [u8;32],
    pub key_version: u64,
    pub signed_digest: Vec<u8>,
    pub signature: Vec<u8>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Pw13FeeFreeEnrollmentAdmission {
    pub resources: Pw13FeeFreeEnrollmentResources,
    pub enrollment_bytes: Vec<u8>,
    pub ordinary: [InitialEnrollmentProof;2],
    pub recovery: Option<InitialEnrollmentProof>,
    pub ownership: Vec<u8>,
    pub proofs: [Pw13AdmissionProof;2],
}
impl Pw13FeeFreeEnrollmentAdmission {
    pub fn validate_context(&self,envelope:&ProcessingEnvelope,context:&ProcessingContext)->Result<(),EtdagError> {
        self.resources.signing_digest()?;
        if context.profile_id!=PW13_FEE_FREE_ENROLLMENT_PROFILE_ID
            ||self.resources.envelope_id!=envelope.envelope_id
            ||envelope.aad.sender_id!=self.resources.sender_id()
            ||envelope.aad.nonce_slot!=self.resources.stage_nonce()?
            ||self.resources.valid_until_finalized_height<context.authority.source_finalized_height
            ||self.enrollment_bytes.is_empty()||self.enrollment_bytes.len()>24*1024||self.ownership.len()!=65 {
            return Err(EtdagError::ContextMismatch);
        }
        let digest=fee_free_enrollment_candidate_digest(&self.enrollment_bytes)?;
        if self.resources.enrollment_digest!=digest {return Err(EtdagError::ContextMismatch);}
        for (index,proof) in self.ordinary.iter().enumerate() {
            if proof.role_id!=index as u8||proof.participant_id==[0;32]||proof.key_version==0
                ||proof.signed_digest.len()!=64||proof.signature.len()!=4627
                ||self.proofs[index].participant_id!=proof.participant_id||self.proofs[index].key_version!=proof.key_version
                ||self.proofs[index].signature.len()!=4627 {return Err(EtdagError::InvalidSignature);}
        }
        if self.ordinary[0].participant_id==self.ordinary[1].participant_id
            ||self.recovery.as_ref().is_some_and(|p|p.role_id!=2||p.participant_id==[0;32]||p.key_version==0
                ||p.signed_digest.len()!=64||p.signature.len()!=4627||self.ordinary.iter().any(|d|d.participant_id==p.participant_id)) {
            return Err(EtdagError::InvalidSignature);
        }
        envelope.validate_context(context)
    }
}
