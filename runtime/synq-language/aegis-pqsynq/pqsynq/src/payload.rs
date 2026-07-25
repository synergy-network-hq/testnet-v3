//! SynQ deploy/call envelope types.

use serde::{Deserialize, Serialize};

use crate::{
    address::SynQAddress,
    algorithms::{AlgorithmId, SignaturePurpose},
    domain::{ChainId, DomainTag, NetworkId},
    keys::{SynQPublicKey, SynQSignature},
    policy::SynQSecurityPolicy,
};

pub type Hash32 = [u8; 32];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SynQSigningPayload {
    pub domain_tag: DomainTag,
    pub chain_id: ChainId,
    pub network_id: NetworkId,
    pub protocol_version: u16,
    pub algorithm_id: AlgorithmId,
    pub signature_purpose: SignaturePurpose,
    pub nonce: u64,
    pub not_before_unix: u64,
    pub expiration_unix: u64,
    pub signer_address: SynQAddress,
    pub payload_hash: Hash32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContractDeployEnvelope {
    pub signing_payload: SynQSigningPayload,
    pub public_key: SynQPublicKey,
    pub signature: SynQSignature,
    pub bytecode_hash: Hash32,
    pub manifest_hash: Hash32,
    pub abi_hash: Hash32,
    pub constructor_args_hash: Hash32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContractCallEnvelope {
    pub signing_payload: SynQSigningPayload,
    pub public_key: SynQPublicKey,
    pub signature: SynQSignature,
    pub contract_address: SynQAddress,
    pub method_selector: [u8; 4],
    pub encoded_args_hash: Hash32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SynQTransactionEnvelope {
    ContractDeploy(ContractDeployEnvelope),
    ContractCall(ContractCallEnvelope),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationContext {
    pub chain_id: ChainId,
    pub network_id: NetworkId,
    pub now_unix: u64,
    pub policy: SynQSecurityPolicy,
}

impl VerificationContext {
    pub fn testnet(now_unix: u64) -> Self {
        Self {
            chain_id: ChainId::testnet_1264(),
            network_id: NetworkId::testnet(),
            now_unix,
            policy: SynQSecurityPolicy::testnet_1264_policy(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifiedContractDeploy {
    pub deployer: SynQAddress,
    pub bytecode_hash: Hash32,
    pub manifest_hash: Hash32,
    pub abi_hash: Hash32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifiedContractCall {
    pub caller: SynQAddress,
    pub contract_address: SynQAddress,
    pub method_selector: [u8; 4],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum VerifiedSynQTransaction {
    ContractDeploy(VerifiedContractDeploy),
    ContractCall(VerifiedContractCall),
}
