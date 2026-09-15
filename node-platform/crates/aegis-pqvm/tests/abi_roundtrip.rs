//! AEG1 encode/decode round-trips for every in-scope (Op, Alg) pair.

use aegis_pqvm::integrations::abi::{self, Alg, Call, Op};

fn roundtrip(call: &Call, offchain: bool) {
    let payload = if offchain {
        abi::encode_call_offchain(call).expect("encode offchain")
    } else {
        abi::encode_call(call).expect("encode deterministic")
    };
    let decoded = abi::decode_call(&payload).expect("decode");
    assert_eq!(decoded.op, call.op);
    assert_eq!(decoded.alg, call.alg);
    assert_eq!(decoded.args, call.args);
}

#[test]
fn deterministic_verify_ops_roundtrip() {
    let cases = [
        (Op::MldsaVerifyDetached, Alg::Mldsa44),
        (Op::MldsaVerifyDetached, Alg::Mldsa65),
        (Op::MldsaVerifyDetached, Alg::Mldsa87),
        (Op::FndsaVerifyDetached, Alg::Fndsa512),
        (Op::FndsaVerifyDetached, Alg::Fndsa1024),
    ];
    for (op, alg) in cases {
        let call = Call {
            op,
            alg,
            args: vec![vec![0xAA; 8], vec![0xBB; 16], vec![0xCC; 32]],
        };
        roundtrip(&call, false);
    }
}

#[test]
fn offchain_mlkem_decapsulate_roundtrip() {
    for alg in [Alg::Mlkem512, Alg::Mlkem768, Alg::Mlkem1024] {
        let call = Call {
            op: Op::MlkemDecapsulate,
            alg,
            args: vec![vec![0x01; 64], vec![0x02; 64]],
        };
        roundtrip(&call, true);
    }
}

#[test]
fn deterministic_encoder_rejects_mlkem_decapsulate() {
    let call = Call {
        op: Op::MlkemDecapsulate,
        alg: Alg::Mlkem512,
        args: vec![vec![0x01], vec![0x02]],
    };
    let err = abi::encode_call(&call).unwrap_err();
    assert!(err.to_string().contains("off-chain only"));
}
