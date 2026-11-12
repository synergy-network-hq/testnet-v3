//! Aegis-owned PQSynQ authorization and execution binding.
//!
//! Consumers submit the signed PQSynQ envelope and invocation bytes together;
//! this provider verifies the account-domain signature and exact artifact/input
//! commitments without exposing raw PQ primitives above the Aegis engine.

use pqsynq::{
    AegisSynQVerifier, ChainId, NetworkId, SynQTransactionEnvelope, VerificationContext,
    VerifiedSynQTransaction,
};
use serde::{Deserialize, Serialize};
use synergy_address_engine::apqe::{HashAlgorithm, Primitives};

const MAX_AUTHORIZATION_BYTES: usize = 1024 * 1024;
const MAX_INVOCATION_BYTES: usize = 4 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PqSynqExecutionAuthorization {
    pub envelope: SynQTransactionEnvelope,
    pub invocation_input: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifiedPqSynqOperation {
    Deploy {
        deployer_id: String,
    },
    Call {
        caller_id: String,
        contract_address_preimage: [u8; 41],
        method_selector: [u8; 4],
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedPqSynqExecution {
    pub operation: VerifiedPqSynqOperation,
    pub invocation_input: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct PqSynqVerifier {
    verifier: AegisSynQVerifier,
    apqe: Option<crate::ApqeVerifier>,
}

impl PqSynqVerifier {
    pub fn for_network(chain_id: u64, network_id: &str) -> Result<Self, PqSynqError> {
        #[cfg(not(test))]
        {
            let _ = (chain_id, network_id);
            Err(PqSynqError::Provider("explicit authenticated APQE provider required; embedded native authorization is forbidden".into()))
        }
        #[cfg(test)]
        {
            Self::policy_for_network(chain_id, network_id)
        }
    }
    fn policy_for_network(chain_id: u64, network_id: &str) -> Result<Self, PqSynqError> {
        if chain_id == 0 || network_id.trim().is_empty() || network_id.len() > 128 {
            return Err(PqSynqError::InvalidExecutionInput);
        }
        Ok(Self {
            verifier: AegisSynQVerifier::new(pqsynq::SynQSecurityPolicy::for_network(
                ChainId(chain_id),
                NetworkId(network_id.into()),
            )),
            apqe: None,
        })
    }

    pub fn with_apqe(
        chain_id: u64,
        network_id: &str,
        engine: std::sync::Arc<
            std::sync::Mutex<synergy_address_engine::apqe::crypto_engine::CryptoEngine>,
        >,
    ) -> Result<Self, PqSynqError> {
        let mut verifier = Self::policy_for_network(chain_id, network_id)?;
        verifier.apqe = Some(
            crate::ApqeVerifier::new(
                engine,
                crate::AegisPolicy {
                    allowed_algorithms: vec![crate::SignatureAlgorithm::MlDsa87],
                    maximum_message_bytes: MAX_AUTHORIZATION_BYTES,
                    maximum_signature_bytes: 16 * 1024,
                },
            )
            .map_err(|e| PqSynqError::Provider(e.to_string()))?,
        );
        Ok(verifier)
    }

    pub fn verify_execution(
        &self,
        artifact: &[u8],
        encoded_authorization: &[u8],
        chain_id: u64,
        network_id: &str,
        transaction_time_unix: u64,
        expected_signer_public_key: &[u8],
    ) -> Result<VerifiedPqSynqExecution, PqSynqError> {
        if artifact.is_empty()
            || encoded_authorization.is_empty()
            || encoded_authorization.len() > MAX_AUTHORIZATION_BYTES
            || transaction_time_unix == 0
        {
            return Err(PqSynqError::InvalidExecutionInput);
        }
        let authorization: PqSynqExecutionAuthorization =
            serde_json::from_slice(encoded_authorization)
                .map_err(|_| PqSynqError::InvalidEncoding)?;
        if authorization.invocation_input.len() > MAX_INVOCATION_BYTES {
            return Err(PqSynqError::InvalidExecutionInput);
        }
        let envelope_public_key = match &authorization.envelope {
            SynQTransactionEnvelope::ContractDeploy(envelope) => &envelope.public_key.bytes,
            SynQTransactionEnvelope::ContractCall(envelope) => &envelope.public_key.bytes,
        };
        if envelope_public_key.as_slice() != expected_signer_public_key {
            return Err(PqSynqError::SignerKeyMismatch);
        }
        let network_id = NetworkId(network_id.to_string());
        let context = VerificationContext {
            chain_id: ChainId(chain_id),
            network_id,
            now_unix: transaction_time_unix,
            policy: self.verifier.policy.clone(),
        };
        let provider_error = std::cell::RefCell::new(None);
        let verified = match &self.apqe {
            None => self
                .verifier
                .verify_synq_transaction(&authorization.envelope, &context),
            Some(apqe) => self.verifier.verify_synq_transaction_with(
                &authorization.envelope,
                &context,
                &|algorithm, canonical, signature, public| {
                    use crate::AegisVerifier;
                    if algorithm != pqsynq::AlgorithmId::MlDsa87 {
                        return Err(pqsynq::AegisSynQError::UnsupportedAlgorithm);
                    }
                    if public.bytes.len() != 2592 {
                        return Err(pqsynq::AegisSynQError::MalformedPublicKey);
                    }
                    if signature.bytes.len() != 4627 {
                        return Err(pqsynq::AegisSynQError::MalformedSignature);
                    }
                    match apqe.verify(
                        &crate::SigningContext {
                            domain: "SYNERGY-PQSYNQ-CANONICAL-PAYLOAD-V1".into(),
                            chain_id,
                            epoch: None,
                            height: None,
                        },
                        canonical,
                        &crate::Signature {
                            algorithm: crate::SignatureAlgorithm::MlDsa87,
                            key_id: crate::KeyId::new("pqsynq-presented-key")
                                .expect("constant key id"),
                            bytes: signature.bytes.clone(),
                        },
                        &public.bytes,
                    ) {
                        Ok(()) => Ok(()),
                        Err(crate::VerificationError::Provider(error)) => {
                            *provider_error.borrow_mut() = Some(error);
                            Err(pqsynq::AegisSynQError::InvalidSignature)
                        }
                        Err(_) => Err(pqsynq::AegisSynQError::InvalidSignature),
                    }
                },
            ),
        };
        if let Some(error) = provider_error.into_inner() {
            return Err(PqSynqError::Provider(error));
        }
        let verified = verified.map_err(|error| PqSynqError::Verification(error.to_string()))?;
        let operation = match (&authorization.envelope, verified) {
            (
                SynQTransactionEnvelope::ContractDeploy(envelope),
                VerifiedSynQTransaction::ContractDeploy(verified),
            ) => {
                if sha256(artifact) != envelope.bytecode_hash
                    || sha256(&authorization.invocation_input) != envelope.constructor_args_hash
                    || verified.bytecode_hash != envelope.bytecode_hash
                {
                    return Err(PqSynqError::CommitmentMismatch);
                }
                VerifiedPqSynqOperation::Deploy {
                    deployer_id: verified.deployer.to_execution_signer_id(),
                }
            }
            (
                SynQTransactionEnvelope::ContractCall(envelope),
                VerifiedSynQTransaction::ContractCall(verified),
            ) => {
                if sha256(&authorization.invocation_input) != envelope.encoded_args_hash {
                    return Err(PqSynqError::CommitmentMismatch);
                }
                VerifiedPqSynqOperation::Call {
                    caller_id: verified.caller.to_execution_signer_id(),
                    contract_address_preimage: *verified.contract_address.as_bytes(),
                    method_selector: verified.method_selector,
                }
            }
            _ => return Err(PqSynqError::OperationMismatch),
        };
        Ok(VerifiedPqSynqExecution {
            operation,
            invocation_input: authorization.invocation_input,
        })
    }
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    Primitives
        .hash(HashAlgorithm::Sha256, bytes)
        .expect("fixed SHA256 supported")
        .try_into()
        .expect("fixed SHA256 length")
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PqSynqError {
    InvalidEncoding,
    InvalidExecutionInput,
    CommitmentMismatch,
    OperationMismatch,
    SignerKeyMismatch,
    Verification(String),
    Provider(String),
}

impl std::fmt::Display for PqSynqError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidEncoding => formatter.write_str("invalid PQSynQ execution encoding"),
            Self::InvalidExecutionInput => formatter.write_str("invalid PQSynQ execution input"),
            Self::CommitmentMismatch => formatter.write_str("PQSynQ execution commitment mismatch"),
            Self::OperationMismatch => formatter.write_str("PQSynQ operation mismatch"),
            Self::SignerKeyMismatch => {
                formatter.write_str("PQSynQ signer key does not match the outer transaction")
            }
            Self::Provider(message) => write!(formatter, "PQSynQ provider unavailable: {message}"),
            Self::Verification(message) => {
                write!(formatter, "PQSynQ verification failed: {message}")
            }
        }
    }
}

impl std::error::Error for PqSynqError {}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn absent_apqe_pqsynq_provider_does_not_fall_back() {
        let engine = std::sync::Arc::new(std::sync::Mutex::new(
            synergy_address_engine::apqe::crypto_engine::CryptoEngine::new(),
        ));
        assert!(matches!(
            PqSynqVerifier::with_apqe(1266, "isolated", engine),
            Err(PqSynqError::Provider(_))
        ));
    }
    #[test]
    #[ignore = "requires explicitly authenticated immutable APQE native artifacts"]
    fn native_apqe_pqsynq_preserves_canonical_account_profiles() {
        use pqsynq::{
            AlgorithmId, ContractCallEnvelope, ContractDeployEnvelope, DomainTag, SignaturePurpose,
            SynQPublicKey, SynQSignature, SynQSigningPayload,
        };
        use std::sync::{Arc, Mutex};
        use synergy_address_engine::{
            apqe::{crypto_engine::CryptoEngine, provider::SignOptions},
            types::Algorithm,
        };
        let report = std::env::var("APQE_TRUSTED_NATIVE_REPORT").unwrap();
        let digest = std::env::var("APQE_AUTHENTICATED_REPORT_SHA256").unwrap();
        assert_eq!(digest.len(), 64);
        let mut hash = [0; 32];
        for (i, b) in hash.iter_mut().enumerate() {
            *b = u8::from_str_radix(&digest[2 * i..2 * i + 2], 16).unwrap();
        }
        // Explicit isolated-test operator authenticates/protects these artifacts.
        let engine: Arc<Mutex<CryptoEngine>> = Arc::new(Mutex::new(
            unsafe {
                synergy_address_engine::apqe::native_manifest::validator_engine(
                    std::path::Path::new(&report),
                    hash,
                )
            }
            .unwrap(),
        ));
        let pair = engine
            .lock()
            .unwrap()
            .generate_keypair(Algorithm::MlDsa87)
            .unwrap();
        let public = SynQPublicKey::new(pair.public_key.clone());
        let network = NetworkId("isolated-pqsynq".into());
        let signer = pqsynq::derive_synq_address(&public, AlgorithmId::MlDsa87, &network).unwrap();
        let artifact = b"original AIVM bytecode";
        let invocation = b"original constructor arguments";
        let bytecode_hash = sha256(artifact);
        let manifest_hash = sha256(b"manifest");
        let abi_hash = sha256(b"abi");
        let args_hash = sha256(invocation);
        let payload = SynQSigningPayload {
            domain_tag: DomainTag::SynqContractDeployV1,
            chain_id: ChainId(1266),
            network_id: network.clone(),
            protocol_version: 1,
            algorithm_id: AlgorithmId::MlDsa87,
            signature_purpose: SignaturePurpose::ContractDeploy,
            nonce: 1,
            not_before_unix: 10,
            expiration_unix: 100,
            signer_address: signer,
            payload_hash: pqsynq::serialization::hash_contract_deploy_body(
                &bytecode_hash,
                &manifest_hash,
                &abi_hash,
                signer.as_bytes(),
                &args_hash,
            ),
        };
        let canonical = pqsynq::serialization::canonicalize_signing_payload(&payload).unwrap();
        assert!(canonical.starts_with(b"SQSP\0\x01\0\x02"));
        let signature = engine
            .lock()
            .unwrap()
            .sign(
                Algorithm::MlDsa87,
                pair.private_key.as_bytes(),
                &canonical,
                SignOptions::default(),
            )
            .unwrap();
        let envelope = ContractDeployEnvelope {
            signing_payload: payload.clone(),
            public_key: public.clone(),
            signature: SynQSignature::new(signature.clone()),
            bytecode_hash,
            manifest_hash,
            abi_hash,
            constructor_args_hash: args_hash,
        };
        let authorization = PqSynqExecutionAuthorization {
            envelope: SynQTransactionEnvelope::ContractDeploy(envelope.clone()),
            invocation_input: invocation.to_vec(),
        };
        let verifier = PqSynqVerifier::with_apqe(1266, network.as_str(), engine.clone()).unwrap();
        let check = |authorization: &PqSynqExecutionAuthorization, key: &[u8]| {
            verifier.verify_execution(
                artifact,
                &serde_json::to_vec(authorization).unwrap(),
                1266,
                network.as_str(),
                20,
                key,
            )
        };
        let verified = check(&authorization, &pair.public_key).unwrap();
        assert_eq!(
            verified,
            PqSynqVerifier::for_network(1266, network.as_str())
                .unwrap()
                .verify_execution(
                    artifact,
                    &serde_json::to_vec(&authorization).unwrap(),
                    1266,
                    network.as_str(),
                    20,
                    &pair.public_key
                )
                .unwrap()
        );
        for mutation in 0..7 {
            let mut changed = envelope.clone();
            match mutation {
                0 => changed.signing_payload.domain_tag = DomainTag::SynqContractCallV1,
                1 => changed.signing_payload.chain_id = ChainId(1267),
                2 => changed.signing_payload.network_id = NetworkId("substitute".into()),
                3 => changed.signing_payload.algorithm_id = AlgorithmId::MlDsa65,
                4 => changed.signature.bytes[0] ^= 1,
                5 => changed.public_key.bytes[0] ^= 1,
                _ => changed.signing_payload.nonce = 2,
            }
            let changed = PqSynqExecutionAuthorization {
                envelope: SynQTransactionEnvelope::ContractDeploy(changed),
                invocation_input: invocation.to_vec(),
            };
            assert!(check(&changed, &pair.public_key).is_err());
        }
        let mut wrong_key = pair.public_key.clone();
        wrong_key[0] ^= 1;
        assert!(check(&authorization, &wrong_key).is_err());
        let mut changed = authorization.clone();
        changed.invocation_input[0] ^= 1;
        assert!(check(&changed, &pair.public_key).is_err());
        assert!(verifier
            .verify_execution(
                b"substituted bytecode",
                &serde_json::to_vec(&authorization).unwrap(),
                1266,
                network.as_str(),
                20,
                &pair.public_key
            )
            .is_err());
        let guard = engine.lock().unwrap();
        assert!(
            matches!(
                check(&authorization, &pair.public_key),
                Err(PqSynqError::Provider(_))
            ),
            "contention must remain a provider error"
        );
        drop(guard);
        let mut call_payload = payload;
        call_payload.domain_tag = DomainTag::SynqContractCallV1;
        call_payload.signature_purpose = SignaturePurpose::ContractCall;
        let selector = [1, 2, 3, 4];
        call_payload.payload_hash = pqsynq::serialization::hash_contract_call_body(
            signer.as_bytes(),
            &selector,
            &args_hash,
            signer.as_bytes(),
        );
        let canonical_call =
            pqsynq::serialization::canonicalize_signing_payload(&call_payload).unwrap();
        let signature = engine
            .lock()
            .unwrap()
            .sign(
                Algorithm::MlDsa87,
                pair.private_key.as_bytes(),
                &canonical_call,
                SignOptions::default(),
            )
            .unwrap();
        let call = PqSynqExecutionAuthorization {
            envelope: SynQTransactionEnvelope::ContractCall(ContractCallEnvelope {
                signing_payload: call_payload,
                public_key: public,
                signature: SynQSignature::new(signature),
                contract_address: signer,
                method_selector: selector,
                encoded_args_hash: args_hash,
            }),
            invocation_input: invocation.to_vec(),
        };
        assert!(matches!(
            check(&call, &pair.public_key).unwrap().operation,
            VerifiedPqSynqOperation::Call { .. }
        ));
    }
}
