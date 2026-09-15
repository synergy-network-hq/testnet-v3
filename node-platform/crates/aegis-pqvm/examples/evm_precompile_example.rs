//! EVM precompile integration example
//!
//! Demonstrates how to use aegis-pqvm's EVM-style precompile in a smart contract context.
//! Run with: cargo run --example evm_precompile_example

use aegis_pqvm::integrations::abi::{
    decode_response, encode_call, encode_call_offchain, Alg, Call, Op,
};
use aegis_pqvm::integrations::evm;
use aegis_pqvm::mldsa::mldsa44;
use aegis_pqvm::mlkem::mlkem768;
use pqrust_traits::kem::{Ciphertext as _, SecretKey as _, SharedSecret as _};
use pqrust_traits::sign::{DetachedSignature as _, PublicKey as _};

fn main() {
    println!("=== EVM Precompile Integration Example ===\n");

    // 1. ML-DSA verify detached (deterministic, suitable for precompile)
    println!("1. ML-DSA-44 verify detached (deterministic)");
    let (pk_s, sk_s) = mldsa44::keypair();
    let msg = b"Hello, EVM precompile!";
    let sig = mldsa44::detached_sign(msg, &sk_s);
    let pk_bytes = pk_s.as_bytes().to_vec();
    let msg_vec = msg.to_vec();
    let sig_bytes = sig.as_bytes().to_vec();

    let call = Call {
        op: Op::MldsaVerifyDetached,
        alg: Alg::Mldsa44,
        args: vec![pk_bytes, msg_vec, sig_bytes],
    };
    let payload = encode_call(&call).expect("encode call");
    let gas = evm::evm_gas_cost(&payload).expect("gas cost");
    println!("   Gas estimate: {}", gas);

    let raw = evm::evm_precompile_call(&payload).expect("precompile call");
    let result = decode_response(&raw)
        .expect("decode response")
        .expect("success");
    assert_eq!(result, vec![1u8], "signature should verify");
    println!("   Verification: OK\n");

    // 2. ML-KEM decapsulation (off-chain only; secret key is never allowed on-chain)
    println!("2. ML-KEM-768 decapsulation (off-chain dispatcher)");
    let (pk, sk) = mlkem768::keypair();
    let (_ss_enc, ct) = mlkem768::encapsulate(&pk);
    let offchain_call = Call {
        op: Op::MlkemDecapsulate,
        alg: Alg::Mlkem768,
        args: vec![ct.as_bytes().to_vec(), sk.as_bytes().to_vec()],
    };
    let offchain_payload = encode_call_offchain(&offchain_call).expect("encode call");
    let offchain_raw = aegis_pqvm::integrations::abi::dispatch_offchain(&offchain_payload)
        .expect("off-chain call");
    let offchain_result = decode_response(&offchain_raw)
        .expect("decode response")
        .expect("success");
    let _ss_dec = mlkem768::SharedSecret::from_bytes(&offchain_result).expect("shared secret");
    println!("   Decapsulation succeeded (trusted environment)\n");

    println!("EVM precompile example completed successfully.");
}
