use std::{env, fs, path::Path};

use pqsynq::{
    canonicalize_signing_payload, hash_contract_deploy_body, AegisSynQError, AegisSynQVerifier,
    AlgorithmId, ChainId, ContractDeployEnvelope, DigitalSignature, DomainTag, Hash32, NetworkId,
    Sign, SignaturePurpose, SynQPublicKey, SynQSignature, SynQSigningPayload, VerificationContext,
};
use serde::Serialize;
use sha2::{Digest, Sha256};

const NOW: u64 = 1_800_000_000;

#[derive(Serialize)]
struct DeployVector {
    schema_version: u32,
    case: &'static str,
    expected_result: &'static str,
    expected_error_variant: Option<&'static str>,
    expected_error_code: Option<&'static str>,
    context: VerificationContext,
    envelope: ContractDeployEnvelope,
}

fn hash32(label: &[u8]) -> Hash32 {
    let digest = Sha256::digest(label);
    let mut out = [0_u8; 32];
    out.copy_from_slice(&digest);
    out
}

fn valid_deploy() -> ContractDeployEnvelope {
    let verifier = AegisSynQVerifier::testnet_1266();
    let (public_key, secret_key) = Sign::mldsa65().keygen().unwrap();
    let public_key = SynQPublicKey::new(public_key);
    let signer_address = verifier
        .derive_synq_address(&public_key, AlgorithmId::MlDsa65, NetworkId::testnet())
        .unwrap();
    let bytecode_hash = hash32(b"vector-bytecode");
    let manifest_hash = hash32(b"vector-manifest");
    let abi_hash = hash32(b"vector-abi");
    let constructor_args_hash = hash32(b"vector-constructor");
    let payload_hash = hash_contract_deploy_body(
        &bytecode_hash,
        &manifest_hash,
        &abi_hash,
        signer_address.as_bytes(),
        &constructor_args_hash,
    );
    let signing_payload = SynQSigningPayload {
        domain_tag: DomainTag::SynqContractDeployV1,
        chain_id: ChainId::testnet_1266(),
        network_id: NetworkId::testnet(),
        protocol_version: 1,
        algorithm_id: AlgorithmId::MlDsa65,
        signature_purpose: SignaturePurpose::ContractDeploy,
        nonce: 2026,
        not_before_unix: 0,
        expiration_unix: NOW + 600,
        signer_address,
        payload_hash,
    };
    let canonical = canonicalize_signing_payload(&signing_payload).unwrap();
    let signature = Sign::mldsa65().sign(&canonical, &secret_key).unwrap();

    ContractDeployEnvelope {
        signing_payload,
        public_key,
        signature: SynQSignature::new(signature),
        bytecode_hash,
        manifest_hash,
        abi_hash,
        constructor_args_hash,
    }
}

fn vector(
    case: &'static str,
    expected_result: &'static str,
    expected_error: Option<AegisSynQError>,
    envelope: ContractDeployEnvelope,
) -> DeployVector {
    DeployVector {
        schema_version: 1,
        case,
        expected_result,
        expected_error_variant: expected_error.as_ref().map(|error| match error {
            AegisSynQError::InvalidSignature => "InvalidSignature",
            AegisSynQError::WrongChain => "WrongChain",
            AegisSynQError::WrongDomain => "WrongDomain",
            _ => "Unexpected",
        }),
        expected_error_code: expected_error.as_ref().map(AegisSynQError::code),
        context: VerificationContext::testnet(NOW),
        envelope,
    }
}

fn write_vector(out_dir: &Path, filename: &str, vector: &DeployVector) {
    let path = out_dir.join(filename);
    let json = serde_json::to_string_pretty(vector).unwrap();
    fs::write(path, format!("{json}\n")).unwrap();
}

fn main() {
    let out_dir = env::var("PQSYNQ_VECTOR_OUTPUT_DIR")
        .unwrap_or_else(|_| "aegis-pqsynq/pqsynq/tests/vectors".to_string());
    let out_dir = Path::new(&out_dir);
    fs::create_dir_all(out_dir).unwrap();

    let valid = valid_deploy();
    write_vector(
        out_dir,
        "ml_dsa_65_valid_deploy.json",
        &vector("ml_dsa_65_valid_deploy", "ok", None, valid.clone()),
    );

    let mut invalid_signature = valid.clone();
    invalid_signature.signature.bytes[0] ^= 0x01;
    write_vector(
        out_dir,
        "ml_dsa_65_invalid_signature.json",
        &vector(
            "ml_dsa_65_invalid_signature",
            "err",
            Some(AegisSynQError::InvalidSignature),
            invalid_signature,
        ),
    );

    let mut wrong_chain = valid.clone();
    wrong_chain.signing_payload.chain_id = ChainId(1);
    write_vector(
        out_dir,
        "ml_dsa_65_wrong_chain.json",
        &vector(
            "ml_dsa_65_wrong_chain",
            "err",
            Some(AegisSynQError::WrongChain),
            wrong_chain,
        ),
    );

    let mut wrong_domain = valid;
    wrong_domain.signing_payload.domain_tag = DomainTag::SynqContractCallV1;
    write_vector(
        out_dir,
        "ml_dsa_65_wrong_domain.json",
        &vector(
            "ml_dsa_65_wrong_domain",
            "err",
            Some(AegisSynQError::WrongDomain),
            wrong_domain,
        ),
    );
}
