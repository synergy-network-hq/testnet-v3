//! Native-width R1 PoSy objects. Historical v3 objects remain separate.
//!
//! POSY-CODEC-1 is an engineering profile pending authenticated activation.
//! Merely parsing these objects never authenticates an authority or payload.
mod certificate;
mod codec;
mod finality;
mod header;
pub use certificate::*;
pub use finality::*;
pub use header::*;
#[cfg(test)]
mod tests;

pub type Digest48 = [u8; 48];
pub const MAX_PROOF_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_VALIDATORS: usize = 4096;
pub const MAX_SIGNATURE_BYTES: usize = 16384;

/// Exact engineering schema descriptors for the authenticated profile catalog.
/// Publishing a descriptor does not qualify or activate its implementation.
pub const BLOCK_PROFILE_NAME: &str = "POSY-BLOCK-R1";
pub const FINALITY_PROFILE_NAME: &str = "POSY-FINALITY-R1";
pub const PROFILE_REVISION: u32 = 1;
pub const APPROVAL_CONTEXT: &[u8] = b"POSY/APPROVAL/V1";
pub const CODEC_PROFILE_NAME: &str = "POSY-CODEC-1";
pub const AUTHORITY_PROFILE_NAME: &str = "POSY-AUTHORITY-R1";
pub const AUTHORITY_PROFILE_SCHEMA: &[u8] = b"POSY-AUTHORITY-R1/1;codec=POSY-CODEC-1/1;LE-U16-U32-U64-U128;KeyId=SHA3-384(Bytes(POSY/KEY/R1),U16(1),U16(65),U16(consensus0),U64(nonzero-generation),Bytes(fullMLDSA65public1952));Authority=SHA3-384(Bytes(POSY/AUTHORITY/R1),U16(1),U64(chain),NIC64,Profile(ASCII128,U32revision),ActivatedProfiles64,Protocol48,U64epoch,U64firstHeight,U64lastHeight,Schedule48,U32membercount,sorted(Identity48,KeyId48,U64keyVersion,U128positiveWeight),U128checkedTotalWeight);initial-authority-excludes-finalGenesis-to-avoid-self-reference;runtime-approvals-bind-finalGenesis-separately;frozen-full-network-population;maxmembers4096;unique-keyids;signature=APQE-pureMLDSA65-3309;authenticated-Genesis-or-successor-required";
pub const CODEC_PROFILE_SCHEMA: &[u8] = b"POSY-CODEC-1/1;unsigned-fixed-width-LE;enum-U16;bool-U8-0or1;Bytes-U32length;Vector-U32count;Option-U8-0or1;ordered-unique-vectors;reject-truncated-overflow-excess-trailing;Profile=Bytes(graphicASCII1..128),U32(nonzero-revision);Commit=SHA3-384(Bytes(domain),U16(1),typed-object);KeyId=Commit(POSY/KEY/R1,U16(65),U16(consensus0),U64(nonzero-generation),Bytes(fullMLDSA65public1952));Authority=Commit(POSY/AUTHORITY/R1,N,Protocol48,U64epoch,U64firstHeight,U64lastHeight,Schedule48,U32membercount,sorted(Identity48,KeyId48,U64keyVersion,U128positiveWeight),U128checkedTotalWeight);signature=APQE-pureMLDSA65-3309;no-implicit-prehash;no-production-activation-by-descriptor";
pub const BLOCK_PROFILE_SCHEMA: &[u8] = b"POSY-BLOCK-R1/1;codec=POSY-CODEC-1/1;LE-U16-U32-U64;Bytes=U32(length)||bytes;N=U64(chain),Fixed64(NIC),Profile(ASCII128,U32rev),Genesis48,Profile,Activated64;Header=U16(1),N,Protocol48,U64epoch,U64height,U64round,Proposer48,Authority48,Schedule48,Opportunity48,LedgerParent48,Parent,ExecutionProfile48,PreState48,PostState48,Receipts48,Payload48,Dependencies48,Resources48,ProtocolEffects48,U64payloadBytes,U32txCount,U64gas;Parent=U16(Genesis0),Genesis48|U16(Ordinary1),U64epoch,U64height,U64round,Block48,Authority48;Hash=SHA3-384(U32(domainlen),ASCII(POSY/BLOCK/R1),U16(1),Header);headermax4096;reserved-epoch-boundary-reject";
pub const FINALITY_PROFILE_SCHEMA: &[u8] = b"POSY-FINALITY-R1/1;codec=POSY-CODEC-1/1;APQE-pure-context=POSY/APPROVAL/V1;Proof=Bytes(POSY/FINALITY/R1),U16(1),U16(ordinary0),QC0,QC1,QC2;QC=Header,U32approvalCount,Approvals;Approval=U32memberIndex,U64keyVersion,Bytes(signature);indices=strict-increasing;authority=sorted-unique-raw48;same-fullN-protocol-epoch-authority-executionprofile;direct-parents-consecutive-height-and-round;each-QC=3n>2N-AND-3w>2W-same-frozen-set;APQE-pure-message=Bytes(POSY/APPROVAL/V1),U16(1),N,Protocol48,Authority48,U64epoch,U16(ordinary0),U64round,U64height,Block48,Parent,Opportunity48,ExecutionProfile48,Payload48,PostState48,Receipts48,Identity48,KeyId48,U64keyVersion;maxproof4194304;maxmembers4096;maxsignature16384;selected-key-role-algorithm-and-length;verify-payload-opportunity-ancestry;target=QC0;preserve-original;reject-trailing";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum R1ProofError {
    Bounds,
    Encoding,
    Context,
    Authority,
    Profile,
    Header,
    Parent,
    Signer,
    Signature,
    Quorum,
    Payload,
    FinalizedConflict,
}
impl std::fmt::Display for R1ProofError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "R1 PoSy proof rejected: {self:?}")
    }
}
impl std::error::Error for R1ProofError {}
type Result<T> = std::result::Result<T, R1ProofError>;
