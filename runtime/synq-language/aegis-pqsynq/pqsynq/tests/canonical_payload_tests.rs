use pqsynq::{
    canonicalize_signing_payload, derive_synq_address, hash_signing_payload, AlgorithmId, ChainId,
    DomainTag, NetworkId, SignaturePurpose, SynQPublicKey, SynQSigningPayload,
};
use sha2::{Digest, Sha256};

fn payload_fixture() -> SynQSigningPayload {
    let public_key = SynQPublicKey::new(vec![0x42, 0x51, 0x60, 0x7f, 0x88, 0x99]);
    let signer_address =
        derive_synq_address(&public_key, AlgorithmId::MlDsa65, &NetworkId::testnet()).unwrap();
    let mut payload_hash = [0_u8; 32];
    payload_hash.copy_from_slice(&Sha256::digest(b"canonical payload test body"));

    SynQSigningPayload {
        domain_tag: DomainTag::SynqContractDeployV1,
        chain_id: ChainId::testnet_1264(),
        network_id: NetworkId::testnet(),
        protocol_version: 1,
        algorithm_id: AlgorithmId::MlDsa65,
        signature_purpose: SignaturePurpose::ContractDeploy,
        nonce: 99,
        not_before_unix: 0,
        expiration_unix: 1_800_000_600,
        signer_address,
        payload_hash,
    }
}

#[test]
fn canonical_payload_bytes_are_deterministic_and_versioned() {
    let payload = payload_fixture();

    let first = canonicalize_signing_payload(&payload).unwrap();
    let second = canonicalize_signing_payload(&payload).unwrap();

    assert_eq!(first, second);
    assert_eq!(&first[0..4], b"SQSP");
    assert_eq!(&first[4..6], &1_u16.to_be_bytes());
    assert_eq!(
        &first[6..8],
        &DomainTag::SynqContractDeployV1.code().to_be_bytes()
    );
    assert_eq!(&first[8..16], &1264_u64.to_be_bytes());
}

#[test]
fn signing_payload_hash_changes_with_domain_and_chain_binding() {
    let payload = payload_fixture();
    let baseline = hash_signing_payload(&payload).unwrap();

    let mut different_domain = payload.clone();
    different_domain.domain_tag = DomainTag::SynqContractCallV1;
    assert_ne!(baseline, hash_signing_payload(&different_domain).unwrap());

    let mut different_chain = payload;
    different_chain.chain_id = ChainId(1);
    assert_ne!(baseline, hash_signing_payload(&different_chain).unwrap());
}

#[test]
fn canonical_payload_rejects_oversized_length_prefixed_fields() {
    let mut payload = payload_fixture();
    payload.network_id = NetworkId("x".repeat(u16::MAX as usize + 1));

    let error = canonicalize_signing_payload(&payload).unwrap_err();

    assert_eq!(error, pqsynq::AegisSynQError::NonCanonicalPayload);
}
