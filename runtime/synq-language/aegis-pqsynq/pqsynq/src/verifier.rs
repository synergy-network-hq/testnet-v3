//! SynQ-specific security verifier.

use crate::{
    address::{derive_synq_address, SynQAddress},
    algorithms::{AlgorithmId, SecurityLevel, SignaturePurpose},
    domain::{ChainId, DomainTag, NetworkId},
    error::AegisSynQError,
    keys::SynQPublicKey,
    payload::{
        ContractCallEnvelope, ContractDeployEnvelope, SynQSigningPayload, SynQTransactionEnvelope,
        VerificationContext, VerifiedContractCall, VerifiedContractDeploy, VerifiedSynQTransaction,
    },
    policy::SynQSecurityPolicy,
    serialization::{
        canonicalize_signing_payload, hash_contract_call_body, hash_contract_deploy_body,
    },
    signature::verify_signature,
};

#[derive(Debug, Clone)]
pub struct AegisSynQVerifier {
    pub policy: SynQSecurityPolicy,
}

impl AegisSynQVerifier {
    pub fn new(policy: SynQSecurityPolicy) -> Self {
        Self { policy }
    }

    pub fn testnet_1264() -> Self {
        Self::new(SynQSecurityPolicy::testnet_1264_policy())
    }

    pub fn verify_synq_transaction(
        &self,
        tx: &SynQTransactionEnvelope,
        context: &VerificationContext,
    ) -> Result<VerifiedSynQTransaction, AegisSynQError> {
        match tx {
            SynQTransactionEnvelope::ContractDeploy(deploy) => self
                .verify_contract_deploy(deploy, context)
                .map(VerifiedSynQTransaction::ContractDeploy),
            SynQTransactionEnvelope::ContractCall(call) => self
                .verify_contract_call(call, context)
                .map(VerifiedSynQTransaction::ContractCall),
        }
    }

    pub fn verify_contract_deploy(
        &self,
        deploy: &ContractDeployEnvelope,
        context: &VerificationContext,
    ) -> Result<VerifiedContractDeploy, AegisSynQError> {
        let payload = &deploy.signing_payload;
        self.validate_context(payload, context)?;
        self.expect_domain(payload, DomainTag::SynqContractDeployV1)?;
        self.validate_algorithm_policy(
            payload.algorithm_id,
            SignaturePurpose::ContractDeploy,
            self.policy.min_signature_security_level,
        )?;
        self.expect_address(
            &deploy.public_key,
            payload.algorithm_id,
            &payload.network_id,
            payload.signer_address,
        )?;

        let expected_hash = hash_contract_deploy_body(
            &deploy.bytecode_hash,
            &deploy.manifest_hash,
            &deploy.abi_hash,
            payload.signer_address.as_bytes(),
            &deploy.constructor_args_hash,
        );
        if expected_hash != payload.payload_hash {
            return Err(AegisSynQError::PayloadHashMismatch);
        }

        self.verify_payload_signature(payload, &deploy.signature, &deploy.public_key)?;

        Ok(VerifiedContractDeploy {
            deployer: payload.signer_address,
            bytecode_hash: deploy.bytecode_hash,
            manifest_hash: deploy.manifest_hash,
            abi_hash: deploy.abi_hash,
        })
    }

    pub fn verify_contract_call(
        &self,
        call: &ContractCallEnvelope,
        context: &VerificationContext,
    ) -> Result<VerifiedContractCall, AegisSynQError> {
        let payload = &call.signing_payload;
        self.validate_context(payload, context)?;
        self.expect_domain(payload, DomainTag::SynqContractCallV1)?;
        self.validate_algorithm_policy(
            payload.algorithm_id,
            SignaturePurpose::ContractCall,
            self.policy.min_signature_security_level,
        )?;
        self.expect_address(
            &call.public_key,
            payload.algorithm_id,
            &payload.network_id,
            payload.signer_address,
        )?;

        let expected_hash = hash_contract_call_body(
            call.contract_address.as_bytes(),
            &call.method_selector,
            &call.encoded_args_hash,
            payload.signer_address.as_bytes(),
        );
        if expected_hash != payload.payload_hash {
            return Err(AegisSynQError::PayloadHashMismatch);
        }

        self.verify_payload_signature(payload, &call.signature, &call.public_key)?;

        Ok(VerifiedContractCall {
            caller: payload.signer_address,
            contract_address: call.contract_address,
            method_selector: call.method_selector,
        })
    }

    pub fn derive_synq_address(
        &self,
        public_key: &SynQPublicKey,
        algorithm: AlgorithmId,
        network: NetworkId,
    ) -> Result<SynQAddress, AegisSynQError> {
        derive_synq_address(public_key, algorithm, &network)
    }

    pub fn canonicalize_signing_payload(
        &self,
        payload: &SynQSigningPayload,
    ) -> Result<alloc::vec::Vec<u8>, AegisSynQError> {
        canonicalize_signing_payload(payload)
    }

    pub fn validate_algorithm_policy(
        &self,
        algorithm: AlgorithmId,
        purpose: SignaturePurpose,
        security_level: SecurityLevel,
    ) -> Result<(), AegisSynQError> {
        if algorithm.security_level() < security_level {
            return Err(AegisSynQError::AlgorithmBelowSecurityLevel);
        }

        let allowed = match purpose {
            SignaturePurpose::Transaction => &self.policy.allowed_tx_signature_algorithms,
            SignaturePurpose::ContractDeploy => &self.policy.allowed_deploy_signature_algorithms,
            SignaturePurpose::ContractCall => &self.policy.allowed_call_signature_algorithms,
            _ => return Err(AegisSynQError::UnsupportedPurpose),
        };

        if allowed.contains(&algorithm) {
            Ok(())
        } else {
            Err(AegisSynQError::UnsupportedAlgorithm)
        }
    }

    pub fn verify_chain_domain(
        &self,
        domain: &DomainTag,
        chain_id: ChainId,
        network: NetworkId,
    ) -> Result<(), AegisSynQError> {
        if self.policy.require_domain_separation && matches!(domain, DomainTag::SynqWalletAuthV1) {
            return Err(AegisSynQError::WrongDomain);
        }
        if let Some(required) = self.policy.required_chain_id {
            if required != chain_id {
                return Err(AegisSynQError::WrongChain);
            }
        }
        if let Some(required) = &self.policy.required_network_id {
            if *required != network {
                return Err(AegisSynQError::WrongNetwork);
            }
        }
        Ok(())
    }

    fn validate_context(
        &self,
        payload: &SynQSigningPayload,
        context: &VerificationContext,
    ) -> Result<(), AegisSynQError> {
        if context.chain_id != payload.chain_id {
            return Err(AegisSynQError::WrongChain);
        }
        if context.network_id != payload.network_id {
            return Err(AegisSynQError::WrongNetwork);
        }
        if self.policy.require_nonce && payload.nonce == 0 {
            return Err(AegisSynQError::MissingNonce);
        }
        if self.policy.require_expiration && payload.expiration_unix == 0 {
            return Err(AegisSynQError::MissingExpiration);
        }
        if payload.not_before_unix != 0 && context.now_unix < payload.not_before_unix {
            return Err(AegisSynQError::PayloadNotYetValid);
        }
        if payload.expiration_unix != 0 && context.now_unix > payload.expiration_unix {
            return Err(AegisSynQError::ExpiredPayload);
        }
        self.verify_chain_domain(
            &payload.domain_tag,
            payload.chain_id,
            payload.network_id.clone(),
        )
    }

    fn expect_domain(
        &self,
        payload: &SynQSigningPayload,
        expected: DomainTag,
    ) -> Result<(), AegisSynQError> {
        if payload.domain_tag == expected {
            Ok(())
        } else {
            Err(AegisSynQError::WrongDomain)
        }
    }

    fn expect_address(
        &self,
        public_key: &SynQPublicKey,
        algorithm: AlgorithmId,
        network: &NetworkId,
        expected: SynQAddress,
    ) -> Result<(), AegisSynQError> {
        if public_key.bytes.len() > self.policy.max_public_key_size_bytes {
            return Err(AegisSynQError::OversizedPublicKey);
        }
        let derived = derive_synq_address(public_key, algorithm, network)?;
        if derived == expected {
            Ok(())
        } else {
            Err(AegisSynQError::SignerAddressMismatch)
        }
    }

    fn verify_payload_signature(
        &self,
        payload: &SynQSigningPayload,
        signature: &crate::keys::SynQSignature,
        public_key: &SynQPublicKey,
    ) -> Result<(), AegisSynQError> {
        if signature.bytes.len() > self.policy.max_signature_size_bytes {
            return Err(AegisSynQError::OversizedSignature);
        }
        let canonical = canonicalize_signing_payload(payload)?;
        verify_signature(payload.algorithm_id, &canonical, signature, public_key)
    }
}
