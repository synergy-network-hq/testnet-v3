use pqsynq::{
    canonicalize_signing_payload, hash_contract_call_body, hash_contract_deploy_body,
    AegisSynQVerifier, AlgorithmId, ChainId, ContractCallEnvelope, ContractDeployEnvelope,
    DigitalSignature, DomainTag, Hash32, NetworkId, Sign, SignaturePurpose, SynQAddress,
    SynQPublicKey, SynQSignature, SynQSigningPayload, VerificationContext,
};
use sha2::{Digest, Sha256};

const NOW_UNIX: u64 = 1_800_000_000;

fn hash32(label: &[u8]) -> Hash32 {
    let digest = Sha256::digest(label);
    let mut out = [0_u8; 32];
    out.copy_from_slice(&digest);
    out
}

fn signed_payload(
    domain_tag: DomainTag,
    purpose: SignaturePurpose,
    signer_address: SynQAddress,
    payload_hash: Hash32,
    secret_key: &[u8],
) -> (SynQSigningPayload, SynQSignature) {
    let payload = SynQSigningPayload {
        domain_tag,
        chain_id: ChainId::testnet_1264(),
        network_id: NetworkId::testnet(),
        protocol_version: 1,
        algorithm_id: AlgorithmId::MlDsa65,
        signature_purpose: purpose,
        nonce: 1264,
        not_before_unix: 0,
        expiration_unix: NOW_UNIX + 600,
        signer_address,
        payload_hash,
    };
    let canonical = canonicalize_signing_payload(&payload).expect("canonical payload");
    let signature = Sign::mldsa65()
        .sign(&canonical, secret_key)
        .expect("ML-DSA-65 signing");
    (payload, SynQSignature::new(signature))
}

fn main() {
    let verifier = AegisSynQVerifier::testnet_1264();
    let context = VerificationContext::testnet(NOW_UNIX);
    let (public_key, secret_key) = Sign::mldsa65().keygen().expect("ML-DSA-65 keypair");
    let public_key = SynQPublicKey::new(public_key);
    let signer_address = verifier
        .derive_synq_address(&public_key, AlgorithmId::MlDsa65, NetworkId::testnet())
        .expect("testnet SynQ address");

    let bytecode_hash = hash32(b"example-counter-bytecode");
    let manifest_hash = hash32(b"example-counter-manifest");
    let abi_hash = hash32(b"example-counter-abi");
    let constructor_args_hash = hash32(b"example-counter-constructor");
    let deploy_payload_hash = hash_contract_deploy_body(
        &bytecode_hash,
        &manifest_hash,
        &abi_hash,
        signer_address.as_bytes(),
        &constructor_args_hash,
    );
    let (deploy_payload, deploy_signature) = signed_payload(
        DomainTag::SynqContractDeployV1,
        SignaturePurpose::ContractDeploy,
        signer_address,
        deploy_payload_hash,
        &secret_key,
    );
    let deploy = ContractDeployEnvelope {
        signing_payload: deploy_payload,
        public_key: public_key.clone(),
        signature: deploy_signature,
        bytecode_hash,
        manifest_hash,
        abi_hash,
        constructor_args_hash,
    };
    let verified_deploy = verifier
        .verify_contract_deploy(&deploy, &context)
        .expect("deploy verifies");

    let contract_address = verified_deploy.deployer;
    let method_selector = [0x69, 0x19, 0x98, 0x01];
    let encoded_args_hash = hash32(b"Counter.increment()");
    let call_payload_hash = hash_contract_call_body(
        contract_address.as_bytes(),
        &method_selector,
        &encoded_args_hash,
        signer_address.as_bytes(),
    );
    let (call_payload, call_signature) = signed_payload(
        DomainTag::SynqContractCallV1,
        SignaturePurpose::ContractCall,
        signer_address,
        call_payload_hash,
        &secret_key,
    );
    let call = ContractCallEnvelope {
        signing_payload: call_payload,
        public_key,
        signature: call_signature,
        contract_address,
        method_selector,
        encoded_args_hash,
    };
    let verified_call = verifier
        .verify_contract_call(&call, &context)
        .expect("call verifies");

    println!("chain_id=1264");
    println!("network=synergy-testnet");
    println!("address={}", verified_call.caller.to_testnet_debug_string());
    println!("deploy=verified");
    println!("call=verified");
}
