use crate::{SignedTransaction, TransactionError};

/// Cryptographic verification is supplied by Aegis. Transaction ownership never
/// implies validator, VPN, PoSy quorum, or finality authority.
pub trait AegisTransactionVerifier {
    type Error: std::fmt::Display;
    fn authorization_verifier(
        &self,
    ) -> Option<&dyn synergy_identity::authorization::AuthorizationSignatureVerifier> {
        None
    }

    fn verify_transaction(
        &self,
        signing_bytes: &[u8],
        signer_public_key: &[u8],
        signature: &[u8],
        signature_algorithm: &str,
    ) -> Result<bool, Self::Error>;
}

/// Externally supplied finalized authority and exact governed consensus time.
pub struct TransactionAdmissionContext<'a> {
    pub consensus_timestamp_unix: u64,
    pub canonical_binding:
        &'a synergy_identity::authorization::IdentityAuthorizationBindingCommitment,
}

/// Compatibility boundary without finalized identity authority fails closed.
pub fn verify<V: AegisTransactionVerifier>(
    transaction: &SignedTransaction,
    _verifier: &V,
) -> Result<(), TransactionError> {
    transaction.validate_structure()?;
    Err(TransactionError::InvalidSignature)
}

pub fn verify_with_admission<V: AegisTransactionVerifier>(
    transaction: &SignedTransaction,
    verifier: &V,
    context: TransactionAdmissionContext<'_>,
) -> Result<(), TransactionError> {
    transaction.validate_structure()?;
    if transaction.signature_algorithm != "ML-DSA-87"
        && transaction.signature_algorithm != "ml_dsa_87"
    {
        return Err(TransactionError::InvalidSignature);
    }
    let carrier = transaction
        .identity_authorization
        .as_ref()
        .ok_or(TransactionError::InvalidSignature)?;
    if context.canonical_binding.identity_root_public_key_sha3_256
        != carrier.binding.identity_root.public_key_sha3_256
        || context.canonical_binding.effective_at_unix > context.consensus_timestamp_unix
    {
        return Err(TransactionError::InvalidSignature);
    }
    let sender = carrier
        .identity_address_for_key_for_admission_at_with_verifier(
            synergy_identity::authorization::AEGIS_TRANSACTION_AUTHORIZATION_DOMAIN,
            transaction.unsigned.network.chain_id,
            &transaction.unsigned.network.network_id,
            "ML-DSA-87",
            &transaction.signer_public_key,
            "transaction-signing",
            context.consensus_timestamp_unix,
            &context.canonical_binding.binding_payload_sha3_256,
            verifier.authorization_verifier(),
        )
        .map_err(TransactionError::SignatureVerifier)?;
    if sender != transaction.unsigned.sender {
        return Err(TransactionError::InvalidSignature);
    }
    let verified = verifier
        .verify_transaction(
            &transaction.unsigned.signing_bytes()?,
            &transaction.signer_public_key,
            &transaction.signature,
            &transaction.signature_algorithm,
        )
        .map_err(|error| TransactionError::SignatureVerifier(error.to_string()))?;
    if verified {
        Ok(())
    } else {
        Err(TransactionError::InvalidSignature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{FeeLimit, NetworkBinding, TransactionClass, UnsignedTransaction};
    use aegis_pqvm::pqc::signatures::{fndsa::fndsa1024, mldsa::mldsa87};
    use pqrust_traits::sign::{DetachedSignature as _, PublicKey as _};
    use sha3::{Digest, Sha3_256};
    use synergy_identity::authorization::*;

    struct RealAccountVerifier;
    impl AegisTransactionVerifier for RealAccountVerifier {
        type Error = String;
        fn verify_transaction(
            &self,
            message: &[u8],
            key: &[u8],
            signature: &[u8],
            algorithm: &str,
        ) -> Result<bool, String> {
            if algorithm != "ML-DSA-87" {
                return Ok(false);
            }
            let key = mldsa87::PublicKey::from_bytes(key).map_err(|_| "invalid account key")?;
            let signature = mldsa87::DetachedSignature::from_bytes(signature)
                .map_err(|_| "invalid account signature")?;
            Ok(mldsa87::verify_detached_signature(&signature, message, &key).is_ok())
        }
    }

    fn sha3(bytes: &[u8]) -> String {
        hex::encode(Sha3_256::digest(bytes))
    }
    fn signed_transaction() -> (SignedTransaction, IdentityAuthorizationBindingCommitment) {
        let (root, root_secret) = fndsa1024::keypair();
        let (key, secret) = mldsa87::keypair();
        let sender =
            synergy_address::derive_key_controlled_address("syna", root.as_bytes()).unwrap();
        let key_hash = sha3(key.as_bytes());
        let mut binding: IdentityAuthorizationBinding = serde_json::from_value(serde_json::json!({
            "schema_version":AUTH_BINDING_SCHEMA_VERSION,"binary_encoding":AUTH_BINDING_BINARY_ENCODING,
            "identity_id":"account", "identity_address":sender,
            "identity_root":{"algorithm":"FN-DSA-1024","public_key":hex::encode(root.as_bytes()),"public_key_sha3_256":sha3(root.as_bytes())},
            "authorization_policy":{"policy_type":"single-key","threshold":1,"principals":[{
                "principal_id":"account","principal_type":"public-key","algorithm":"ML-DSA-87",
                "public_key":hex::encode(key.as_bytes()),"public_key_sha3_256":key_hash,"status":"active","purposes":["transaction-signing"]}]},
            "authorization_scopes":[{"signature_domain":AEGIS_TRANSACTION_AUTHORIZATION_DOMAIN,
                "chain_id":1266,"network_id":"testnet","purpose":"transaction-signing"}],
            "current_auth_key_hash":key_hash,"auth_key_history":[],"supersession_history":[],
            "effective_at":"1970-01-01T00:00:10Z","binding_payload_sha3_256":"",
            "proofs":{"identity_root":{"algorithm":"FN-DSA-1024","signature":""}}
        })).unwrap();
        let payload = canonical_binding_payload(&binding).unwrap();
        binding.binding_payload_sha3_256 = sha3(&payload);
        let mut proof_message = AUTH_BINDING_SIGNATURE_DOMAIN.to_vec();
        proof_message.extend_from_slice(&payload);
        binding.proofs.identity_root.signature =
            hex::encode(fndsa1024::detached_sign(&proof_message, &root_secret).as_bytes());
        binding.proofs.authorization_key_possession = vec![AuthorizationKeyPossessionProof {
            principal_id: "account".into(),
            algorithm: "ML-DSA-87".into(),
            signature: hex::encode(mldsa87::detached_sign(&proof_message, &secret).as_bytes()),
        }];
        let commitment =
            IdentityAuthorizationBindingCommitment::from_verified_binding(&binding, 10).unwrap();
        let unsigned = UnsignedTransaction {
            network: NetworkBinding::new(1266, "testnet").unwrap(),
            class: TransactionClass::User,
            sender,
            receiver: synergy_address::derive_object_address("synq", b"receiver").unwrap(),
            amount_nwei: 7,
            nonce: 0,
            fee_limit: FeeLimit {
                gas_limit: 21000,
                max_fee_per_gas_nwei: 2,
            },
            timestamp_unix: 999999,
            payload: vec![],
        };
        let signature = mldsa87::detached_sign(&unsigned.signing_bytes().unwrap(), &secret)
            .as_bytes()
            .to_vec();
        (
            SignedTransaction {
                unsigned,
                signer_public_key: key.as_bytes().to_vec(),
                signature,
                signature_algorithm: "ML-DSA-87".into(),
                identity_authorization: Some(IdentityAuthorizationCarrier {
                    schema_version: AUTHORIZATION_CARRIER_SCHEMA_VERSION,
                    signature_domain: AEGIS_TRANSACTION_AUTHORIZATION_DOMAIN.into(),
                    binding,
                }),
            },
            commitment,
        )
    }

    #[test]
    fn real_account_signatures_need_current_dual_binding_and_external_consensus_time() {
        let (transaction, commitment) = signed_transaction();
        let verifier = RealAccountVerifier;
        let admit =
            |tx: &SignedTransaction, binding: &IdentityAuthorizationBindingCommitment, time| {
                verify_with_admission(
                    tx,
                    &verifier,
                    TransactionAdmissionContext {
                        consensus_timestamp_unix: time,
                        canonical_binding: binding,
                    },
                )
            };
        assert!(admit(&transaction, &commitment, 10).is_ok());
        assert!(verify(&transaction, &verifier).is_err());
        // Envelope time is far in the future; it still cannot activate the binding.
        assert!(admit(&transaction, &commitment, 9).is_err());
        let mut retired = commitment.clone();
        retired.binding_payload_sha3_256 = "0".repeat(64);
        assert!(admit(&transaction, &retired, 10).is_err());
        let mut wrong_root = commitment.clone();
        wrong_root.identity_root_public_key_sha3_256 = "0".repeat(64);
        assert!(admit(&transaction, &wrong_root, 10).is_err());
        let mut bad = transaction.clone();
        bad.identity_authorization = None;
        assert!(admit(&bad, &commitment, 10).is_err());
        let mut bad = transaction.clone();
        bad.signature[0] ^= 1;
        assert!(admit(&bad, &commitment, 10).is_err());
        let mut bad = transaction.clone();
        bad.signer_public_key[0] ^= 1;
        assert!(admit(&bad, &commitment, 10).is_err());
        let mut bad = transaction.clone();
        bad.unsigned.sender = synergy_address::derive_key_controlled_address(
            "synv1",
            &hex::decode(
                &bad.identity_authorization
                    .as_ref()
                    .unwrap()
                    .binding
                    .identity_root
                    .public_key,
            )
            .unwrap(),
        )
        .unwrap();
        assert!(admit(&bad, &commitment, 10).is_err());
        for algorithm in ["ML-DSA-65", "FN-DSA-1024"] {
            let mut bad = transaction.clone();
            bad.signature_algorithm = algorithm.into();
            assert!(admit(&bad, &commitment, 10).is_err());
        }
        let mut protocol = std::collections::BTreeMap::new();
        assert!(canonical_binding_commitment(&protocol, &transaction.unsigned.sender).is_err());
        protocol.insert(
            IDENTITY_AUTHORIZATION_BINDINGS_STATE_KEY.into(),
            serde_json::to_vec(&std::collections::BTreeMap::from([(
                transaction.unsigned.sender.clone(),
                commitment.clone(),
            )]))
            .unwrap(),
        );
        assert_eq!(
            canonical_binding_commitment(&protocol, &transaction.unsigned.sender).unwrap(),
            commitment
        );
        assert!(canonical_binding_commitment(&protocol, &transaction.unsigned.receiver).is_err());
    }
}
