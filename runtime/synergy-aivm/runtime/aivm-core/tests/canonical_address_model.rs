//! Proves the canonical Synergy address model: one ML-DSA-87 public key has
//! exactly one public identity, and the SynQ deploy/call domains stay separated
//! through the signed payload rather than through a second address format.

use pqsynq::traits::DetachedSignature;
use pqsynq::{
    canonicalize_signing_payload, derive_synq_address, hash_contract_call_body,
    hash_contract_deploy_body, AegisSynQVerifier, AlgorithmId, ChainId, ContractCallEnvelope,
    ContractDeployEnvelope, DomainTag, NetworkId, Sign, SignaturePurpose, SynQPublicKey,
    SynQSignature, SynQSigningPayload, VerificationContext,
};

fn keypair() -> (Vec<u8>, Vec<u8>) {
    use pqsynq::traits::DigitalSignature;
    Sign::mldsa87().keygen().expect("ML-DSA-87 keygen")
}

/// Mirrors `runtime::address::derive_standard_account_address`.
fn syna(public_key: &[u8]) -> String {
    use bech32::{u5, Variant};
    use sha3::{Digest, Sha3_256};
    let hash = Sha3_256::digest(public_key);
    let count = 41 - "syna".len() - 1 - 6;
    let mut values = Vec::with_capacity(count);
    for i in 0..count {
        let bit = i * 5;
        let (idx, off) = (bit / 8, bit % 8);
        let v = if off <= 3 {
            (hash[idx] >> (3 - off)) & 0x1f
        } else {
            let hi = (hash[idx] << (off - 3)) & 0x1f;
            let lo = if idx + 1 < hash.len() {
                hash[idx + 1] >> (11 - off)
            } else {
                0
            };
            hi | lo
        };
        values.push(u5::try_from_u8(v).unwrap());
    }
    bech32::encode("syna", values, Variant::Bech32m).unwrap()
}

fn payload(
    domain: DomainTag,
    purpose: SignaturePurpose,
    signer: pqsynq::SynQAddress,
    hash: [u8; 32],
) -> SynQSigningPayload {
    SynQSigningPayload {
        domain_tag: domain,
        chain_id: ChainId(1266),
        network_id: NetworkId("synergy-testnet".to_string()),
        protocol_version: 1,
        algorithm_id: AlgorithmId::MlDsa87,
        signature_purpose: purpose,
        nonce: 1,
        not_before_unix: 0,
        expiration_unix: 4_102_444_800,
        signer_address: signer,
        payload_hash: hash,
    }
}

#[test]
fn a_public_key_has_exactly_one_public_address_and_it_is_syna() {
    let (pk, _) = keypair();
    let account = syna(&pk);
    assert!(
        account.starts_with("syna1"),
        "account address must be syna: {account}"
    );
    assert_eq!(account.len(), 41, "SNTS-01 addresses are 41 characters");

    // The internal execution-signer identifier must not look like an address.
    let internal = derive_synq_address(
        &SynQPublicKey::new(pk.clone()),
        AlgorithmId::MlDsa87,
        &NetworkId("synergy-testnet".to_string()),
    )
    .unwrap()
    .to_execution_signer_id();
    assert!(
        internal.starts_with("synq-signer:"),
        "must not be address-shaped: {internal}"
    );
    assert!(!internal.starts_with("tsynq"), "tsynq form is retired");
    // The prefix is a scheme label with a colon, not a bech32 HRP + separator.
    assert!(
        !internal.starts_with("syn") || internal.contains(':'),
        "internal id must not read as a bech32 address: {internal}"
    );
}

#[test]
fn deploy_and_call_signatures_are_domain_separated() {
    let (pk, sk) = keypair();
    let public_key = SynQPublicKey::new(pk.clone());
    let net = NetworkId("synergy-testnet".to_string());
    let signer = derive_synq_address(&public_key, AlgorithmId::MlDsa87, &net).unwrap();

    let (b, m, a, c) = ([1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32]);
    let deploy_payload = payload(
        DomainTag::SynqContractDeployV1,
        SignaturePurpose::ContractDeploy,
        signer,
        hash_contract_deploy_body(&b, &m, &a, signer.as_bytes(), &c),
    );
    let deploy_sig = SynQSignature::new(
        Sign::mldsa87()
            .detached_sign(&canonicalize_signing_payload(&deploy_payload).unwrap(), &sk)
            .unwrap(),
    );

    let sel = [0x58u8, 0x42, 0xf1, 0xbe];
    let ah = [5u8; 32];
    let call_payload = payload(
        DomainTag::SynqContractCallV1,
        SignaturePurpose::ContractCall,
        signer,
        hash_contract_call_body(signer.as_bytes(), &sel, &ah, signer.as_bytes()),
    );

    let verifier = AegisSynQVerifier::testnet_1266();
    let ctx = VerificationContext::testnet(1_800_000_000);

    // Genuine deploy verifies.
    let deploy = ContractDeployEnvelope {
        signing_payload: deploy_payload,
        public_key: public_key.clone(),
        signature: deploy_sig.clone(),
        bytecode_hash: b,
        manifest_hash: m,
        abi_hash: a,
        constructor_args_hash: c,
    };
    assert!(verifier.verify_contract_deploy(&deploy, &ctx).is_ok());

    // The *deploy* signature must not authorize a call.
    let replay = ContractCallEnvelope {
        signing_payload: call_payload,
        public_key,
        signature: deploy_sig,
        contract_address: signer,
        method_selector: sel,
        encoded_args_hash: ah,
    };
    assert!(
        verifier.verify_contract_call(&replay, &ctx).is_err(),
        "a deploy signature must not verify as a call"
    );
}

#[test]
fn a_public_key_address_mismatch_is_rejected() {
    let (pk, sk) = keypair();
    let (other_pk, _) = keypair();
    let net = NetworkId("synergy-testnet".to_string());
    // Signer address belongs to a different key than the one presented.
    let wrong =
        derive_synq_address(&SynQPublicKey::new(other_pk), AlgorithmId::MlDsa87, &net).unwrap();

    let (b, m, a, c) = ([1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32]);
    let p = payload(
        DomainTag::SynqContractDeployV1,
        SignaturePurpose::ContractDeploy,
        wrong,
        hash_contract_deploy_body(&b, &m, &a, wrong.as_bytes(), &c),
    );
    let sig = SynQSignature::new(
        Sign::mldsa87()
            .detached_sign(&canonicalize_signing_payload(&p).unwrap(), &sk)
            .unwrap(),
    );
    let deploy = ContractDeployEnvelope {
        signing_payload: p,
        public_key: SynQPublicKey::new(pk),
        signature: sig,
        bytecode_hash: b,
        manifest_hash: m,
        abi_hash: a,
        constructor_args_hash: c,
    };
    assert!(
        AegisSynQVerifier::testnet_1266()
            .verify_contract_deploy(&deploy, &VerificationContext::testnet(1_800_000_000))
            .is_err(),
        "signer address must derive from the presented public key"
    );
}
