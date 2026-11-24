//! Initial SynID registration is a closed nonfinancial native operation.
use super::{ProcessingContext,ProcessingEnvelope,Pw13AdmissionProof};
use crate::{EtdagDigest,EtdagError};
use serde::{Serialize,Deserialize};
use synergy_aegis::{AegisHashEngine,AegisSha3_256};
pub const PW13_FEE_FREE_SYNID_PROFILE_ID:&str="etdag-pw13-fee-free-synid-v1";
pub const PW13_FEE_FREE_SYNID_LANE:&str="fee-free-synid";
pub const PW13_FEE_FREE_SYNID_ADMISSION_CONTEXT:&[u8]=b"AEGIS.PW13.FEE-FREE.SYNID.ADMISSION.V1";
pub const FEE_FREE_SYNID_SETTLEMENT_PREFIX:&str="apqe-protected-account-candidate/v1/fee-free-synid/";
#[derive(Clone,Debug,PartialEq,Eq,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FeeFreeSynIdIntent {
    pub version:u8,pub genesis:[u8;32],pub account:[u8;20],pub policy_epoch:u64,
    pub policy_hash:[u8;32],pub syn_id:String,pub valid_until_finalized_height:u64,
}
impl FeeFreeSynIdIntent {
    pub fn canonical_bytes(&self)->Result<Vec<u8>,EtdagError>{
        if self.version!=1||self.genesis==[0;32]||self.account==[0;20]||self.policy_hash==[0;32]
            ||self.syn_id.len()>36||!self.syn_id.is_ascii()||self.syn_id.bytes().any(|b|b.is_ascii_control())
            ||self.valid_until_finalized_height==0{return Err(EtdagError::InvalidExecutionInput);}
        serde_json::to_vec(self).map_err(|e|EtdagError::Corrupt(e.to_string()))
    }
    pub fn signing_digest(&self)->Result<[u8;64],EtdagError>{
        AegisSha3_256.sha3_512_segments(&[b"AEGIS/FEE-FREE-SYNID-INTENT/v1\0",&self.canonical_bytes()?]).map_err(|e|EtdagError::Corrupt(format!("{e:?}")))
    }
}
#[derive(Clone,Debug,PartialEq,Eq,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Pw13FeeFreeSynIdResources {
    pub genesis:[u8;32],pub account:[u8;20],pub policy_epoch:u64,pub policy_hash:[u8;32],
    pub intent_digest:Vec<u8>,pub gas_limit:u64,pub valid_until_finalized_height:u64,pub envelope_id:EtdagDigest,
}
impl Pw13FeeFreeSynIdResources {
    pub fn sender_id(&self)->String{format!("synid:{}",self.account.iter().map(|b|format!("{b:02x}")).collect::<String>())}
    pub fn signing_digest(&self)->Result<[u8;64],EtdagError>{
        self.envelope_id.validate()?;
        if self.genesis==[0;32]||self.account==[0;20]||self.policy_hash==[0;32]||self.intent_digest.len()!=64
            ||self.gas_limit==0||self.valid_until_finalized_height==0||self.envelope_id.is_zero(){return Err(EtdagError::InvalidExecutionInput);}
        let bytes=serde_json::to_vec(self).map_err(|e|EtdagError::Corrupt(e.to_string()))?;
        AegisSha3_256.sha3_512_segments(&[b"AEGIS/PW13-FEE-FREE-SYNID-ADMISSION/v1\0",&bytes]).map_err(|e|EtdagError::Corrupt(format!("{e:?}")))
    }
    pub fn settlement_key(&self)->String{format!("{FEE_FREE_SYNID_SETTLEMENT_PREFIX}{}",self.envelope_id.0)}
}
#[derive(Clone,Debug,PartialEq,Eq,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Pw13FeeFreeSynIdAdmission {pub resources:Pw13FeeFreeSynIdResources,pub proofs:[Pw13AdmissionProof;2]}
impl Pw13FeeFreeSynIdAdmission {
    pub fn validate_context(&self,envelope:&ProcessingEnvelope,context:&ProcessingContext)->Result<(),EtdagError>{
        self.resources.signing_digest()?;
        if context.profile_id!=PW13_FEE_FREE_SYNID_PROFILE_ID||envelope.envelope_id!=self.resources.envelope_id
            ||envelope.aad.sender_id!=self.resources.sender_id()||envelope.aad.nonce_slot!=0
            ||self.resources.valid_until_finalized_height<context.authority.source_finalized_height
            ||self.proofs.iter().any(|p|p.participant_id==[0;32]||p.key_version==0||p.signature.len()!=4627)
            ||self.proofs[0].participant_id==self.proofs[1].participant_id{return Err(EtdagError::ContextMismatch);}
        envelope.validate_context(context)
    }
}
#[derive(Clone,Debug,PartialEq,Eq,Serialize,Deserialize)]
#[serde(rename_all="snake_case")]
pub enum FeeFreeSynIdOutcome {Registered,AlreadyRegistered,NameUnavailable,AccountAlreadyNamed,Expired,PolicySuperseded}
#[derive(Clone,Debug,PartialEq,Eq,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FeeFreeSynIdSettlement {
    pub version:u8,pub genesis:[u8;32],pub account:[u8;20],pub envelope_id:EtdagDigest,pub admission_digest:Vec<u8>,
    pub syn_id:String,pub source_finalized_height:u64,pub deciding_finalized_height:u64,pub included_height:u64,
    pub gas_used:u64,pub fee_nwei:u128,pub outcome:FeeFreeSynIdOutcome,
}
