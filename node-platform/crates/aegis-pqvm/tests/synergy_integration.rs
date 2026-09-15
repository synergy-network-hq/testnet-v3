//! Synergy testnet integration smoke tests (AEG1 dispatch + route binding).

use aegis_pqvm::integrations::abi::{self, Alg, Call, Op};
use aegis_pqvm::integrations::synergy::{
    rpc, SynergyIntegration, EVM_PRECOMPILE_ADDRESS, EVM_PRECOMPILE_ADDRESS_HEX, TESTNET_CHAIN_ID,
    TESTNET_CHAIN_ID_HEX, TESTNET_NETWORK_ID,
};
use aegis_pqvm::licensing::{self, Tier};
use aegis_pqvm::mldsa::mldsa44;
use pqrust_traits::sign::{DetachedSignature as _, PublicKey as _};

#[test]
fn synergy_deterministic_verify_roundtrip() {
    licensing::install_dev_test_license(Tier::Pro);

    let (pk, sk) = mldsa44::keypair();
    let msg = b"synergy-pqvm integration test";
    let sig = mldsa44::detached_sign(msg, &sk);

    let call = Call {
        op: Op::MldsaVerifyDetached,
        alg: Alg::Mldsa44,
        args: vec![
            pk.as_bytes().to_vec(),
            msg.to_vec(),
            sig.as_bytes().to_vec(),
        ],
    };
    let payload = abi::encode_call(&call).expect("encode call");
    let response = SynergyIntegration::dispatch_call(&payload).expect("dispatch");
    let out = abi::decode_response(&response).unwrap().unwrap();
    assert_eq!(out, vec![1u8]);
}

#[test]
fn synergy_host_function_route_roundtrip() {
    licensing::install_dev_test_license(Tier::Pro);

    let (pk, sk) = mldsa44::keypair();
    let msg = b"synergy host function route";
    let sig = mldsa44::detached_sign(msg, &sk);
    let call = Call {
        op: Op::MldsaVerifyDetached,
        alg: Alg::Mldsa44,
        args: vec![
            pk.as_bytes().to_vec(),
            msg.to_vec(),
            sig.as_bytes().to_vec(),
        ],
    };
    let payload = abi::encode_call(&call).expect("encode call");
    let response =
        SynergyIntegration::invoke_host_function("aegis", "mldsa44_verify_detached", &payload)
            .expect("invoke host function");
    let out = abi::decode_response(&response).unwrap().unwrap();
    assert_eq!(out, vec![1u8]);
}

#[test]
fn synergy_gas_cost_scales_with_payload_size() {
    licensing::install_dev_test_license(Tier::Pro);

    let small = Call {
        op: Op::MldsaVerifyDetached,
        alg: Alg::Mldsa44,
        args: vec![vec![0u8; 1], vec![0u8; 1], vec![0u8; 1]],
    };
    let large = Call {
        op: Op::MldsaVerifyDetached,
        alg: Alg::Mldsa44,
        args: vec![vec![0u8; 128], vec![0u8; 128], vec![0u8; 128]],
    };

    let small_payload = abi::encode_call(&small).expect("encode");
    let large_payload = abi::encode_call(&large).expect("encode");

    let small_cost = SynergyIntegration::synergy_gas_cost(&small_payload).unwrap();
    let large_cost = SynergyIntegration::synergy_gas_cost(&large_payload).unwrap();
    assert!(large_cost > small_cost);
}

#[test]
fn synergy_offchain_mlkem_decapsulate_roundtrip() {
    use aegis_pqvm::mlkem::mlkem512;
    use pqrust_traits::kem::{Ciphertext as _, SecretKey as _, SharedSecret as _};

    licensing::install_dev_test_license(Tier::Pro);

    let (pk, sk) = mlkem512::keypair();
    let (ss1, ct) = mlkem512::encapsulate(&pk);

    let call = Call {
        op: Op::MlkemDecapsulate,
        alg: Alg::Mlkem512,
        args: vec![ct.as_bytes().to_vec(), sk.as_bytes().to_vec()],
    };
    let payload = abi::encode_call_offchain(&call).expect("encode");
    let response = SynergyIntegration::dispatch_offchain_call(&payload).expect("dispatch");
    let out = abi::decode_response(&response).unwrap().unwrap();
    assert_eq!(out, ss1.as_bytes());
}

#[test]
fn synergy_starter_tier_denies_platform() {
    licensing::install_dev_test_license(Tier::Starter);

    let call = Call {
        op: Op::MldsaVerifyDetached,
        alg: Alg::Mldsa44,
        args: vec![vec![0u8; 1], vec![0u8; 1], vec![0u8; 1]],
    };
    let payload = abi::encode_call(&call).expect("encode");
    let err = SynergyIntegration::dispatch_call(&payload).unwrap_err();
    assert!(err.to_string().contains("Synergy") || err.to_string().contains("platform"));
}

#[test]
fn synergy_testnet_evm_constants_are_stable() {
    assert_eq!(TESTNET_CHAIN_ID, 1264);
    assert_eq!(TESTNET_CHAIN_ID_HEX, "0x4f0");
    assert_eq!(TESTNET_NETWORK_ID, "synergy-testnet-v2");
    assert_eq!(
        EVM_PRECOMPILE_ADDRESS_HEX,
        "0x00000000000000000000000000000000000004f0"
    );
    assert_eq!(&EVM_PRECOMPILE_ADDRESS[18..], &[0x04, 0xf0]);
}

#[test]
fn synergy_rpc_contract_separates_public_and_trusted_methods() {
    assert_eq!(
        rpc::SynergyRpcMethod::AegisDispatch.name(),
        "aegis_dispatch"
    );
    assert_eq!(
        rpc::SynergyRpcMethod::AegisEstimateGas.name(),
        "aegis_estimateGas"
    );
    assert!(rpc::PUBLIC_METHODS.contains(&rpc::SynergyRpcMethod::EthCall));
    assert!(rpc::TRUSTED_ONLY_METHODS.contains(&rpc::SynergyRpcMethod::AegisDispatchOffchain));
    assert!(rpc::SynergyRpcMethod::AegisDispatchOffchain.requires_trusted_transport());
    assert!(!rpc::SynergyRpcMethod::AegisDispatch.requires_trusted_transport());
    assert_eq!(rpc::EVM_PRECOMPILE_ROUTE.chain_id_hex, TESTNET_CHAIN_ID_HEX);
    assert_eq!(
        rpc::EVM_PRECOMPILE_ROUTE.address,
        EVM_PRECOMPILE_ADDRESS_HEX
    );
}
