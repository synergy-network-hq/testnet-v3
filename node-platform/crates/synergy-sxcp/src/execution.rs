use serde::{Deserialize, Serialize};
use synergy_crypto::{sha3_256_segments, AegisSha3_256};
use synergy_uma::{AddressMapping, AddressNamespace, UmaAddress, UmaRegistry};

use crate::{
    resolve_uma_destination, ExternalChain, ExternalFinalityProof, SxcpTransfer,
    SynergyFinalityAnchor, VerifiedExternalTransfer,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SxcpAuthorizationSignature {
    pub validator_id: String,
    pub key_id: String,
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SxcpRelayExecution {
    pub transfer: SxcpTransfer,
    pub proof: ExternalFinalityProof,
    pub destination_chain: ExternalChain,
    pub uma_mapping: AddressMapping,
    pub authorization_root: String,
    pub signatures: Vec<SxcpAuthorizationSignature>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FinalizedSxcpRelayIntent {
    pub transaction_id: String,
    pub execution: SxcpRelayExecution,
    pub synergy_finality: SynergyFinalityAnchor,
}

impl FinalizedSxcpRelayIntent {
    pub fn validate_shape(&self) -> Result<(), String> {
        self.synergy_finality.validate()?;
        self.execution.transfer.validate_shape()?;
        if !matches!(self.transaction_id.len(), 64 | 128)
            || !self
                .transaction_id
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            || self.execution.authorization_root != self.execution.unsigned_root()?
            || self.execution.signatures.is_empty()
        {
            return Err("invalid finalized SXCP relay intent".into());
        }
        Ok(())
    }
}

pub trait SxcpExecutionAuthorizationVerifier {
    fn verify_execution_authorization(&self, execution: &SxcpRelayExecution) -> Result<(), String>;
}

struct QuorumCoveredMapping;

impl synergy_uma::MappingAuthorizationVerifier for QuorumCoveredMapping {
    fn verify_mapping(&self, _mapping: &AddressMapping) -> Result<(), String> {
        Ok(())
    }
}

impl SxcpRelayExecution {
    pub fn unsigned_root(&self) -> Result<String, String> {
        let bytes = serde_json::to_vec(&(
            &self.transfer,
            &self.proof,
            self.destination_chain,
            &self.uma_mapping,
        ))
        .map_err(|error| format!("encode SXCP execution commitment: {error}"))?;
        let root = sha3_256_segments(
            &AegisSha3_256,
            &[b"SYNERGY_SXCP_RELAY_EXECUTION_V1", &bytes],
        )?;
        Ok(root.0.iter().map(|byte| format!("{byte:02x}")).collect())
    }

    pub fn signing_bytes(&self) -> Result<Vec<u8>, String> {
        let root = self.unsigned_root()?;
        serde_json::to_vec(&("SYNERGY_SXCP_RELAY_AUTHORIZATION_V1", root))
            .map_err(|error| format!("encode SXCP authorization transcript: {error}"))
    }

    pub fn verify(
        &self,
        verifier: &impl SxcpExecutionAuthorizationVerifier,
        requested_destination: &str,
    ) -> Result<VerifiedExternalTransfer, String> {
        self.transfer.validate_shape()?;
        self.uma_mapping.validate()?;
        if self.authorization_root != self.unsigned_root()?
            || requested_destination != self.transfer.destination
            || self.signatures.is_empty()
            || self.proof.chain != self.transfer.source_chain
            || self.proof.block_reference.trim().is_empty()
            || self.proof.transaction_reference != self.transfer.source_transaction
            || self.proof.proof_bytes.is_empty()
            || self.proof.proof_bytes.len() > 4 * 1024 * 1024
            || self.destination_chain == self.transfer.source_chain
            || self.transfer.destination != self.uma_mapping.uma.as_str()
        {
            return Err("invalid SXCP relay execution".into());
        }
        let expected_namespace = match self.destination_chain {
            ExternalChain::Bitcoin => AddressNamespace::Bitcoin,
            ExternalChain::Ethereum => AddressNamespace::Ethereum,
            ExternalChain::Solana => AddressNamespace::Solana,
        };
        if self.uma_mapping.namespace != expected_namespace {
            return Err("SXCP UMA mapping uses the wrong destination namespace".into());
        }
        verifier.verify_execution_authorization(self)?;
        let mut registry = UmaRegistry::default();
        registry.apply(&QuorumCoveredMapping, self.uma_mapping.clone())?;
        let uma = UmaAddress::parse(self.transfer.destination.clone())?;
        let resolved = resolve_uma_destination(&registry, &uma, self.destination_chain)?;
        if resolved != self.uma_mapping.destination {
            return Err("SXCP UMA resolution differs from authorized mapping".into());
        }
        Ok(VerifiedExternalTransfer {
            transfer: self.transfer.clone(),
            finality_reference: self.proof.block_reference.clone(),
        })
    }
}
