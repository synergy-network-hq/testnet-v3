use serde::{Deserialize, Serialize};

use crate::{EncryptedTransactionEnvelope, EtdagDigest, EtdagError};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransactionVertex {
    pub vertex_id: EtdagDigest,
    pub target_context_root: EtdagDigest,
    pub target_height: u64,
    pub envelope: EncryptedTransactionEnvelope,
    pub envelope_ref: crate::CertifiedEnvelopeRef,
    pub parents: Vec<EtdagDigest>,
    pub author_id: String,
    pub author_signature: Vec<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wallet_admission: Option<crate::WalletAdmission>,
}

impl TransactionVertex {
    fn validate_wallet_request(&self, request: &crate::AdmissionRequest) -> Result<(), EtdagError> {
        request.validate_shape()?;
        // The owner verifies later-round parents against authenticated certificates.
        // This carrier can independently reject parents on a genesis-round vertex.
        if self.envelope_ref.certified_dag_round == 0 && !self.parents.is_empty() {
            return Err(EtdagError::InvalidEnvelope(
                "wallet-backed genesis-round vertex cannot have parents".into(),
            ));
        }
        if request.envelope != self.envelope
            || request.context_root != self.target_context_root
            || request.target_height != self.target_height
            || request.chain_id != self.envelope.aad.chain_id
            || request.network_id != self.envelope.aad.network_id
            || request.sender_wallet != self.envelope_ref.sender_id
            || request.sender_wallet != self.envelope.aad.sender_id
            || request.sender_nonce != self.envelope_ref.nonce_slot
            || request.sender_nonce != self.envelope.aad.nonce_slot
            || request.gas_class_units != self.envelope_ref.gas_class_units
            || request.fee_class != self.envelope_ref.fee_class
            || self.envelope_ref.ciphertext_bytes != request.envelope.ciphertext.len() as u64
            || request.envelope_commitment()? != self.envelope.envelope_id
        {
            return Err(EtdagError::InvalidEnvelope(
                "wallet admission differs from protected vertex".into(),
            ));
        }
        Ok(())
    }

    pub fn validate(&self) -> Result<(), EtdagError> {
        self.vertex_id.validate()?;
        self.target_context_root.validate()?;
        self.envelope.validate()?;
        self.envelope_ref.validate()?;
        if self.target_height == 0
            || self.envelope_ref.tx_commitment != self.envelope.envelope_id
            || self.envelope_ref.ciphertext_bytes != self.envelope.ciphertext.len() as u64
            || self.target_context_root != self.envelope.target_context_root
            || self.target_height != self.envelope.target_height
            || self.author_id.trim().is_empty()
            || self.author_signature.is_empty()
            || self.parents.iter().any(|parent| parent == &self.vertex_id)
        {
            return Err(EtdagError::InvalidEnvelope(
                "invalid ETDAG transaction vertex".into(),
            ));
        }
        if let Some(admission) = &self.wallet_admission {
            self.validate_wallet_request(&admission.request)?;
        }
        crate::dag::canonical_parents(&self.parents, crate::dag::MAX_VERTEX_PARENTS)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AdmissionRequest, CertifiedEnvelopeRef, EnvelopeAad, ShareCapsule};

    fn digest(label: &str) -> EtdagDigest {
        EtdagDigest::from_domain_bytes("wallet-admission-test", label.as_bytes())
    }

    fn fixture() -> (TransactionVertex, AdmissionRequest) {
        let root = digest("context");
        let mut envelope = EncryptedTransactionEnvelope {
            envelope_version: 2,
            envelope_id: digest("pending"),
            target_context_root: root.clone(),
            target_height: 3,
            aad: EnvelopeAad {
                profile_id: crate::ETDAG_PROFILE_ID.into(),
                chain_id: 1266,
                network_id: "test".into(),
                protocol_version: "test".into(),
                epoch: 1,
                target_height: 3,
                target_context_root: root.clone(),
                assigned_cluster_id: 0,
                lane_id: "ordinary-user".into(),
                sender_id: "alice".into(),
                nonce_slot: 0,
            },
            aead_nonce: [0; 12],
            key_commitment: digest("key"),
            share_commitment_root: digest("pending"),
            share_capsule_root: digest("pending"),
            ciphertext: vec![7; 512],
            content_blind_order_key: digest("order"),
            share_capsules: vec![ShareCapsule {
                validator_id: "validator".into(),
                ingress_kem_key_id: "key".into(),
                share_index: 1,
                share_commitment: digest("share"),
                kem_ciphertext: vec![1; crate::crypto::ML_KEM_1024_CIPHERTEXT_BYTES],
                aead_nonce: [0; 12],
                encrypted_share: vec![2; 16],
            }],
        };
        envelope.refresh_capsule_roots().unwrap();
        envelope.envelope_id = crate::envelope_commitment(&envelope).unwrap();
        let request = AdmissionRequest {
            request_version: crate::ADMISSION_REQUEST_VERSION,
            chain_id: 1266,
            network_id: "test".into(),
            context_root: root.clone(),
            target_height: 3,
            sender_wallet: "alice".into(),
            sender_nonce: 0,
            gas_class_units: 10,
            fee_class: 1,
            signature_algorithm: "ML-DSA-87".into(),
            signer_public_key: vec![1],
            envelope: envelope.clone(),
            signature: vec![1],
        };
        let mut vertex = TransactionVertex {
            vertex_id: digest("pending"),
            target_context_root: root,
            target_height: 3,
            envelope_ref: CertifiedEnvelopeRef {
                tx_commitment: envelope.envelope_id.clone(),
                sender_id: "alice".into(),
                nonce_slot: 0,
                certified_dag_round: 0,
                gas_class_units: 10,
                ciphertext_bytes: 512,
                fee_class: 1,
                protocol_dependencies: vec![],
            },
            envelope,
            parents: vec![],
            author_id: "validator".into(),
            author_signature: vec![1],
            wallet_admission: None,
        };
        vertex.vertex_id = crate::dag::derive_vertex_id(&vertex).unwrap();
        (vertex, request)
    }

    #[test]
    fn wallet_metadata_is_signed_and_exactly_bound_to_vertex() {
        let (vertex, request) = fixture();
        vertex.validate_wallet_request(&request).unwrap();
        let original = request.signing_bytes().unwrap();
        for field in 0..5 {
            let mut forged = request.clone();
            match field {
                0 => forged.gas_class_units += 1,
                1 => forged.fee_class += 1,
                2 => forged.sender_nonce += 1,
                3 => forged.sender_wallet = "bob".into(),
                _ => forged.chain_id += 1,
            }
            assert_ne!(original, forged.signing_bytes().unwrap());
            assert!(vertex.validate_wallet_request(&forged).is_err());
        }
        let mut zero = request;
        zero.gas_class_units = 0;
        assert!(zero.validate_shape().is_err());
    }

    #[test]
    fn canonical_envelope_id_excludes_itself_but_binds_order_and_ciphertext() {
        let (mut vertex, mut request) = fixture();
        let commitment = request.envelope_commitment().unwrap();
        request.envelope.envelope_id = digest("forged");
        assert_eq!(request.envelope_commitment().unwrap(), commitment);
        vertex.envelope = request.envelope.clone();
        vertex.envelope_ref.tx_commitment = request.envelope.envelope_id.clone();
        assert!(vertex.validate_wallet_request(&request).is_err());
        request.envelope.content_blind_order_key = digest("different-order");
        assert_ne!(request.envelope_commitment().unwrap(), commitment);
        request.envelope = fixture().1.envelope;
        request.envelope.ciphertext[0] ^= 1;
        assert_ne!(request.envelope_commitment().unwrap(), commitment);
    }

    #[test]
    fn wallet_genesis_round_rejects_parents_and_later_round_defers_certificate_checks() {
        let (mut vertex, request) = fixture();
        vertex.envelope_ref.certified_dag_round = 1;
        assert!(vertex.validate_wallet_request(&request).is_ok());
        // Bare compatibility vertices do not acquire a wallet-only rule.
        vertex.validate().unwrap();
        vertex.envelope_ref.certified_dag_round = 0;
        vertex.parents.push(digest("parent"));
        assert!(vertex.validate_wallet_request(&request).is_err());
        vertex.validate().unwrap();
    }

    #[test]
    fn absent_wallet_proof_preserves_historical_vertex_transcript() {
        let (vertex, _) = fixture();
        let historical = EtdagDigest::from_canonical(
            crate::domains::DAG_VERTEX,
            &(
                &vertex.target_context_root,
                vertex.target_height,
                &vertex.envelope,
                &vertex.envelope_ref,
                crate::dag::canonical_parents(&vertex.parents, crate::dag::MAX_VERTEX_PARENTS)
                    .unwrap(),
                vertex.author_id.trim(),
            ),
        )
        .unwrap();
        assert_eq!(crate::dag::derive_vertex_id(&vertex).unwrap(), historical);
        let mut json = serde_json::to_value(&vertex).unwrap();
        assert!(json.get("wallet_admission").is_none());
        json.as_object_mut().unwrap().remove("wallet_admission");
        let recovered: TransactionVertex = serde_json::from_value(json).unwrap();
        assert_eq!(recovered.wallet_admission, None);
        assert_eq!(recovered.vertex_id, historical);
    }
}
