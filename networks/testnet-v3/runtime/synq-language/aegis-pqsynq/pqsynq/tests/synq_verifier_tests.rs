use pqsynq::{
    canonicalize_signing_payload, hash_contract_call_body, hash_contract_deploy_body,
    AegisSynQError, AegisSynQVerifier, AlgorithmId, ChainId, ContractCallEnvelope,
    ContractDeployEnvelope, DigitalSignature, DomainTag, Hash32, NetworkId, Sign, SignaturePurpose,
    SynQPublicKey, SynQSignature, SynQSigningPayload, SynQTransactionEnvelope, VerificationContext,
};
use sha2::{Digest, Sha256};

const NOW: u64 = 1_800_000_000;

fn hash32(label: &[u8]) -> Hash32 {
    let digest = Sha256::digest(label);
    let mut out = [0_u8; 32];
    out.copy_from_slice(&digest);
    out
}

fn signed_payload(
    domain_tag: DomainTag,
    purpose: SignaturePurpose,
    signer_address: pqsynq::SynQAddress,
    payload_hash: Hash32,
    secret_key: &[u8],
) -> (SynQSigningPayload, SynQSignature) {
    let payload = SynQSigningPayload {
        domain_tag,
        chain_id: ChainId::testnet_1266(),
        network_id: NetworkId::testnet(),
        protocol_version: 1,
        algorithm_id: AlgorithmId::MlDsa65,
        signature_purpose: purpose,
        nonce: 42,
        not_before_unix: 0,
        expiration_unix: NOW + 600,
        signer_address,
        payload_hash,
    };
    let canonical = canonicalize_signing_payload(&payload).unwrap();
    let signature = Sign::mldsa65().sign(&canonical, secret_key).unwrap();
    (payload, SynQSignature::new(signature))
}

fn valid_deploy() -> (
    AegisSynQVerifier,
    VerificationContext,
    ContractDeployEnvelope,
) {
    let verifier = AegisSynQVerifier::testnet_1266();
    let context = VerificationContext::testnet(NOW);
    let (public_key, secret_key) = Sign::mldsa65().keygen().unwrap();
    let public_key = SynQPublicKey::new(public_key);
    let signer_address = verifier
        .derive_synq_address(&public_key, AlgorithmId::MlDsa65, NetworkId::testnet())
        .unwrap();
    let bytecode_hash = hash32(b"bytecode");
    let manifest_hash = hash32(b"manifest");
    let abi_hash = hash32(b"abi");
    let constructor_args_hash = hash32(b"constructor");
    let payload_hash = hash_contract_deploy_body(
        &bytecode_hash,
        &manifest_hash,
        &abi_hash,
        signer_address.as_bytes(),
        &constructor_args_hash,
    );
    let (signing_payload, signature) = signed_payload(
        DomainTag::SynqContractDeployV1,
        SignaturePurpose::ContractDeploy,
        signer_address,
        payload_hash,
        &secret_key,
    );
    (
        verifier,
        context,
        ContractDeployEnvelope {
            signing_payload,
            public_key,
            signature,
            bytecode_hash,
            manifest_hash,
            abi_hash,
            constructor_args_hash,
        },
    )
}

fn valid_call() -> (AegisSynQVerifier, VerificationContext, ContractCallEnvelope) {
    let verifier = AegisSynQVerifier::testnet_1266();
    let context = VerificationContext::testnet(NOW);
    let (public_key, secret_key) = Sign::mldsa65().keygen().unwrap();
    let public_key = SynQPublicKey::new(public_key);
    let caller = verifier
        .derive_synq_address(&public_key, AlgorithmId::MlDsa65, NetworkId::testnet())
        .unwrap();
    let contract_address = caller;
    let method_selector = [0xaa, 0xbb, 0xcc, 0xdd];
    let encoded_args_hash = hash32(b"args");
    let payload_hash = hash_contract_call_body(
        contract_address.as_bytes(),
        &method_selector,
        &encoded_args_hash,
        caller.as_bytes(),
    );
    let (signing_payload, signature) = signed_payload(
        DomainTag::SynqContractCallV1,
        SignaturePurpose::ContractCall,
        caller,
        payload_hash,
        &secret_key,
    );
    (
        verifier,
        context,
        ContractCallEnvelope {
            signing_payload,
            public_key,
            signature,
            contract_address,
            method_selector,
            encoded_args_hash,
        },
    )
}

#[test]
fn valid_mldsa65_deploy_verifies() {
    let (verifier, context, deploy) = valid_deploy();
    let verified = verifier.verify_contract_deploy(&deploy, &context).unwrap();

    assert_eq!(verified.deployer, deploy.signing_payload.signer_address);
    assert_eq!(verified.bytecode_hash, deploy.bytecode_hash);
}

#[test]
fn wrong_chain_fails() {
    let (verifier, context, mut deploy) = valid_deploy();
    deploy.signing_payload.chain_id = ChainId(1);

    assert_eq!(
        verifier
            .verify_contract_deploy(&deploy, &context)
            .unwrap_err(),
        AegisSynQError::WrongChain
    );
}

#[test]
fn wrong_domain_fails() {
    let (verifier, context, mut deploy) = valid_deploy();
    deploy.signing_payload.domain_tag = DomainTag::SynqContractCallV1;

    assert_eq!(
        verifier
            .verify_contract_deploy(&deploy, &context)
            .unwrap_err(),
        AegisSynQError::WrongDomain
    );
}

#[test]
fn wrong_algorithm_fails() {
    let (verifier, context, mut deploy) = valid_deploy();
    deploy.signing_payload.algorithm_id = AlgorithmId::MlDsa44;

    assert_eq!(
        verifier
            .verify_contract_deploy(&deploy, &context)
            .unwrap_err(),
        AegisSynQError::AlgorithmBelowSecurityLevel
    );
}

#[test]
fn wrong_signer_fails() {
    let (verifier, context, mut deploy) = valid_deploy();
    let (other_public_key, _) = Sign::mldsa65().keygen().unwrap();
    let other_public_key = SynQPublicKey::new(other_public_key);
    deploy.signing_payload.signer_address = verifier
        .derive_synq_address(
            &other_public_key,
            AlgorithmId::MlDsa65,
            NetworkId::testnet(),
        )
        .unwrap();

    assert_eq!(
        verifier
            .verify_contract_deploy(&deploy, &context)
            .unwrap_err(),
        AegisSynQError::SignerAddressMismatch
    );
}

#[test]
fn expired_payload_fails() {
    let (verifier, context, mut deploy) = valid_deploy();
    deploy.signing_payload.expiration_unix = NOW - 1;

    assert_eq!(
        verifier
            .verify_contract_deploy(&deploy, &context)
            .unwrap_err(),
        AegisSynQError::ExpiredPayload
    );
}

#[test]
fn malformed_public_key_fails() {
    let (verifier, context, mut deploy) = valid_deploy();
    deploy.public_key = SynQPublicKey::new(Vec::new());

    assert_eq!(
        verifier
            .verify_contract_deploy(&deploy, &context)
            .unwrap_err(),
        AegisSynQError::MalformedPublicKey
    );
}

#[test]
fn oversized_public_key_fails() {
    let (verifier, context, mut deploy) = valid_deploy();
    deploy.public_key =
        SynQPublicKey::new(vec![0x55; verifier.policy.max_public_key_size_bytes + 1]);

    assert_eq!(
        verifier
            .verify_contract_deploy(&deploy, &context)
            .unwrap_err(),
        AegisSynQError::OversizedPublicKey
    );
}

#[test]
fn malformed_signature_fails() {
    let (verifier, context, mut deploy) = valid_deploy();
    deploy.signature = SynQSignature::new(Vec::new());

    assert_eq!(
        verifier
            .verify_contract_deploy(&deploy, &context)
            .unwrap_err(),
        AegisSynQError::MalformedSignature
    );
}

#[test]
fn oversized_signature_fails() {
    let (verifier, context, mut deploy) = valid_deploy();
    deploy.signature = SynQSignature::new(vec![0x55; verifier.policy.max_signature_size_bytes + 1]);

    assert_eq!(
        verifier
            .verify_contract_deploy(&deploy, &context)
            .unwrap_err(),
        AegisSynQError::OversizedSignature
    );
}

#[test]
fn invalid_signature_fails() {
    let (verifier, context, mut deploy) = valid_deploy();
    deploy.signature.bytes[0] ^= 0x01;

    assert_eq!(
        verifier
            .verify_contract_deploy(&deploy, &context)
            .unwrap_err(),
        AegisSynQError::InvalidSignature
    );
}

#[test]
fn valid_mldsa65_call_verifies() {
    let (verifier, context, call) = valid_call();

    let verified = verifier.verify_contract_call(&call, &context).unwrap();

    assert_eq!(verified.caller, call.signing_payload.signer_address);
    assert_eq!(verified.method_selector, call.method_selector);
}

#[test]
fn deploy_domain_cannot_be_replayed_as_call() {
    let (verifier, context, mut call) = valid_call();
    call.signing_payload.domain_tag = DomainTag::SynqContractDeployV1;

    assert_eq!(
        verifier.verify_contract_call(&call, &context).unwrap_err(),
        AegisSynQError::WrongDomain
    );
}

#[test]
fn call_payload_cannot_be_replayed_as_wallet_auth() {
    let (verifier, context, mut call) = valid_call();
    call.signing_payload.domain_tag = DomainTag::SynqWalletAuthV1;

    assert_eq!(
        verifier.verify_contract_call(&call, &context).unwrap_err(),
        AegisSynQError::WrongDomain
    );
}

#[test]
fn testnet_payload_cannot_be_replayed_as_mainnet() {
    let (verifier, mut context, deploy) = valid_deploy();
    context.network_id = NetworkId("mainnet".to_string());

    assert_eq!(
        verifier
            .verify_contract_deploy(&deploy, &context)
            .unwrap_err(),
        AegisSynQError::WrongNetwork
    );
}

#[test]
fn transaction_dispatch_verifies_deploy() {
    let (verifier, context, deploy) = valid_deploy();
    let tx = SynQTransactionEnvelope::ContractDeploy(deploy.clone());

    let verified = verifier.verify_synq_transaction(&tx, &context).unwrap();

    assert_eq!(
        verified,
        pqsynq::VerifiedSynQTransaction::ContractDeploy(pqsynq::VerifiedContractDeploy {
            deployer: deploy.signing_payload.signer_address,
            bytecode_hash: deploy.bytecode_hash,
            manifest_hash: deploy.manifest_hash,
            abi_hash: deploy.abi_hash,
        })
    );
}

#[test]
fn transaction_dispatch_preserves_security_errors() {
    let (verifier, context, mut call) = valid_call();
    call.signing_payload.domain_tag = DomainTag::SynqWalletAuthV1;
    let tx = SynQTransactionEnvelope::ContractCall(call);

    assert_eq!(
        verifier.verify_synq_transaction(&tx, &context).unwrap_err(),
        AegisSynQError::WrongDomain
    );
}
