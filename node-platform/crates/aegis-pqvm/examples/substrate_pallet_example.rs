//! Substrate pallet integration example
//!
//! Demonstrates how to use aegis-pqvm's deterministic dispatch in a Substrate pallet context.
//! Run with: cargo run --example substrate_pallet_example

use aegis_pqvm::fndsa::fndsa512;
use aegis_pqvm::integrations::abi::{decode_response, encode_call, Alg, Call, Op};
use aegis_pqvm::integrations::substrate::SubstrateIntegration;
use aegis_pqvm::mldsa::mldsa44;
use pqrust_traits::sign::{DetachedSignature as _, PublicKey as _};

fn main() {
    println!("=== Substrate Pallet Integration Example ===\n");

    // 1. ML-DSA verify
    println!("1. ML-DSA-44 verify via dispatch");
    let (pk, sk) = mldsa44::keypair();
    let msg = b"Substrate PQC message";
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
    let payload = encode_call(&call).expect("encode call");
    let raw = SubstrateIntegration::dispatch_call(&payload).expect("dispatch");
    let body = decode_response(&raw).expect("decode").expect("success");
    assert_eq!(body, vec![1u8]);
    println!("   ML-DSA verify: OK");

    // 2. FN-DSA verify
    println!("2. FN-DSA-512 verify via dispatch");
    let (pk, sk) = fndsa512::keypair();
    let msg = b"FN-DSA on Substrate";
    let sig = fndsa512::detached_sign(msg, &sk);
    let call = Call {
        op: Op::FndsaVerifyDetached,
        alg: Alg::Fndsa512,
        args: vec![
            pk.as_bytes().to_vec(),
            msg.to_vec(),
            sig.as_bytes().to_vec(),
        ],
    };
    let payload = encode_call(&call).expect("encode call");
    let raw = SubstrateIntegration::dispatch_call(&payload).expect("dispatch");
    let body = decode_response(&raw).expect("decode").expect("success");
    assert_eq!(body, vec![1u8]);
    println!("   FN-DSA verify: OK\n");

    println!("Substrate pallet example completed successfully.");
}
