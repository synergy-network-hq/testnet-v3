use aegis_pqvm::integrations::abi;

#[test]
fn deterministic_encoder_rejects_mlkem_secret_key_payloads() {
    use aegis_pqvm::mlkem::mlkem512;
    use pqrust_traits::kem::{Ciphertext as _, SecretKey as _};

    let (pk, sk) = mlkem512::keypair();
    let (_ss, ct) = mlkem512::encapsulate(&pk);
    let call = abi::Call {
        op: abi::Op::MlkemDecapsulate,
        alg: abi::Alg::Mlkem512,
        args: vec![ct.as_bytes().to_vec(), sk.as_bytes().to_vec()],
    };

    let err = abi::encode_call(&call).unwrap_err();
    assert!(err
        .to_string()
        .contains("payload encoding is off-chain only"));
}

#[test]
fn deterministic_dispatch_rejects_mlkem_secret_key_payloads() {
    use aegis_pqvm::mlkem::mlkem512;
    use pqrust_traits::kem::{Ciphertext as _, SecretKey as _};

    let (pk, sk) = mlkem512::keypair();
    let (_ss, ct) = mlkem512::encapsulate(&pk);

    let call = abi::Call {
        op: abi::Op::MlkemDecapsulate,
        alg: abi::Alg::Mlkem512,
        args: vec![ct.as_bytes().to_vec(), sk.as_bytes().to_vec()],
    };
    let payload = abi::encode_call_offchain(&call).expect("encode call");

    let err = aegis_pqvm::integrations::evm::evm_precompile_call(&payload).unwrap_err();
    assert!(err.to_string().contains("mlkem decapsulation is disabled"));
}

#[test]
fn offchain_mlkem_decapsulate_roundtrip() {
    use aegis_pqvm::mlkem::mlkem512;
    use pqrust_traits::kem::{Ciphertext as _, SecretKey as _, SharedSecret as _};

    let (pk, sk) = mlkem512::keypair();
    let (ss1, ct) = mlkem512::encapsulate(&pk);

    let call = abi::Call {
        op: abi::Op::MlkemDecapsulate,
        alg: abi::Alg::Mlkem512,
        args: vec![ct.as_bytes().to_vec(), sk.as_bytes().to_vec()],
    };
    let payload = abi::encode_call_offchain(&call).expect("encode call");

    let response = abi::dispatch_offchain(&payload).unwrap();
    let out = abi::decode_response(&response).unwrap().unwrap();
    assert_eq!(out, ss1.as_bytes());
}

#[test]
fn mldsa_verify_detached_returns_true_then_false_on_tamper() {
    use aegis_pqvm::mldsa::mldsa44;
    use pqrust_traits::sign::{DetachedSignature as _, PublicKey as _};

    let (pk, sk) = mldsa44::keypair();
    let msg = b"aegis-pqvm integration test";
    let sig = mldsa44::detached_sign(msg, &sk);

    let call = abi::Call {
        op: abi::Op::MldsaVerifyDetached,
        alg: abi::Alg::Mldsa44,
        args: vec![
            pk.as_bytes().to_vec(),
            msg.to_vec(),
            sig.as_bytes().to_vec(),
        ],
    };
    let payload = abi::encode_call(&call).expect("encode call");
    let response =
        aegis_pqvm::integrations::substrate::SubstrateIntegration::dispatch_call(&payload).unwrap();
    let out = abi::decode_response(&response).unwrap().unwrap();
    assert_eq!(out, vec![1u8]);

    // Tamper message
    let mut msg_bad = msg.to_vec();
    msg_bad[0] ^= 0x01;
    let call_bad = abi::Call {
        op: abi::Op::MldsaVerifyDetached,
        alg: abi::Alg::Mldsa44,
        args: vec![pk.as_bytes().to_vec(), msg_bad, sig.as_bytes().to_vec()],
    };
    let payload_bad = abi::encode_call(&call_bad).expect("encode call");
    let response_bad =
        aegis_pqvm::integrations::substrate::SubstrateIntegration::dispatch_call(&payload_bad)
            .unwrap();
    let out_bad = abi::decode_response(&response_bad).unwrap().unwrap();
    assert_eq!(out_bad, vec![0u8]);
}

#[test]
fn fndsa_verify_detached_returns_true() {
    use aegis_pqvm::fndsa::fndsa512;
    use pqrust_traits::sign::{DetachedSignature as _, PublicKey as _};

    let (pk, sk) = fndsa512::keypair();
    let msg = b"aegis-pqvm integration test";
    let sig = fndsa512::detached_sign(msg, &sk);

    let call = abi::Call {
        op: abi::Op::FndsaVerifyDetached,
        alg: abi::Alg::Fndsa512,
        args: vec![
            pk.as_bytes().to_vec(),
            msg.to_vec(),
            sig.as_bytes().to_vec(),
        ],
    };
    let payload = abi::encode_call(&call).expect("encode call");
    let response =
        aegis_pqvm::integrations::solana::SolanaIntegration::invoke_instruction(&payload).unwrap();
    let out = abi::decode_response(&response).unwrap().unwrap();
    assert_eq!(out, vec![1u8]);
}

#[test]
fn evm_gas_cost_scales_with_payload_size() {
    let small = abi::Call {
        op: abi::Op::MldsaVerifyDetached,
        alg: abi::Alg::Mldsa44,
        args: vec![vec![0u8; 1], vec![0u8; 1], vec![0u8; 1]],
    };
    let large = abi::Call {
        op: abi::Op::MldsaVerifyDetached,
        alg: abi::Alg::Mldsa44,
        args: vec![vec![0u8; 128], vec![0u8; 128], vec![0u8; 128]],
    };

    let small_payload = abi::encode_call(&small).expect("encode call");
    let large_payload = abi::encode_call(&large).expect("encode call");

    let small_cost = aegis_pqvm::integrations::evm::evm_gas_cost(&small_payload).unwrap();
    let repeat_small_cost = aegis_pqvm::integrations::evm::evm_gas_cost(&small_payload).unwrap();
    let large_cost = aegis_pqvm::integrations::evm::evm_gas_cost(&large_payload).unwrap();

    assert_eq!(small_cost, repeat_small_cost);
    assert!(large_cost > small_cost);
}
