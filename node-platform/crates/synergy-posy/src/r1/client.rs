//! PoSy v0.5 section44 client trust model. These are the same original QCs;
//! certification of execution is distinct from independent validator execution.
use super::{Digest48,R1AuthorityMember,R1ConsensusVerifier,R1Header,R1ThreeQcProof,Result,VerifiedR1FinalizedAnchor};
use synergy_protocol_types::R1NetworkCoordinate;

/// Trusted native client integration, not an RPC callback or supplied table.
/// Authenticate the exact authority/profile/key snapshot and certified header;
/// full validators must continue using R1ConsensusVerifier and execute payloads.
pub trait R1ClientFinalityVerifier{
 fn authenticate_authority(&self,header:&R1Header)->Result<Vec<R1AuthorityMember>>;
 fn verify_certified_header(&self,header:&R1Header)->Result<()>;
 fn verify_approval(&self,member:&R1AuthorityMember,message:&[u8],signature:&[u8])->Result<()>;
 fn verify_finalized_extension(&self,coordinate:&R1NetworkCoordinate,previous_height:u64,previous_block:&Digest48,target:&R1Header)->Result<()>;
}
/// Private provenance: this token proves client finality under section44.
/// It cannot be converted to the full validator execution anchor or used as one.
#[derive(Clone,Debug)]
pub struct VerifiedR1ClientFinalizedAnchor{checked:VerifiedR1FinalizedAnchor}
impl VerifiedR1ClientFinalizedAnchor{
 pub fn coordinate(&self)->&R1NetworkCoordinate{self.checked.coordinate()}
 pub fn height(&self)->u64{self.checked.height()}
 pub fn block_digest(&self)->&Digest48{self.checked.block_digest()}
 pub fn state_root(&self)->&Digest48{self.checked.state_root()}
 pub fn receipts_root(&self)->&Digest48{self.checked.receipts_root()}
 pub fn original_proof(&self)->&[u8]{self.checked.original_proof()}
}
// Internal reuse of all canonical decoding, crypto/dual-quorum/direct ancestry
// checks. The intermediate validator-shaped record never escapes this module.
struct CertificationOnly<'a,V>(&'a V);
impl<V:R1ClientFinalityVerifier> R1ConsensusVerifier for CertificationOnly<'_,V>{
 fn authenticate_authority(&self,h:&R1Header)->Result<Vec<R1AuthorityMember>>{self.0.authenticate_authority(h)}
 fn verify_proposal_and_execution(&self,h:&R1Header)->Result<()>{self.0.verify_certified_header(h)}
 fn verify_approval(&self,m:&R1AuthorityMember,b:&[u8],s:&[u8])->Result<()>{self.0.verify_approval(m,b,s)}
 fn verify_finalized_extension(&self,c:&R1NetworkCoordinate,h:u64,b:&Digest48,t:&R1Header)->Result<()>{self.0.verify_finalized_extension(c,h,b,t)}
}
impl R1ThreeQcProof{
 pub fn verify_client_original(bytes:&[u8],expected:&R1NetworkCoordinate,previous_height:u64,previous_block:&Digest48,verifier:&impl R1ClientFinalityVerifier)->Result<VerifiedR1ClientFinalizedAnchor>{
  let checked=Self::verify_original(bytes,expected,previous_height,previous_block,&CertificationOnly(verifier))?;
  Ok(VerifiedR1ClientFinalizedAnchor{checked})
 }
}
