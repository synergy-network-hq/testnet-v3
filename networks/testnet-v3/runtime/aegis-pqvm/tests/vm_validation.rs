//! VM-specific validation test suite
//!
//! Validates that integration shims (EVM, Substrate, CosmWasm, Solana, Move)
//! behave correctly for blockchain/VM deployment contexts.

use aegis_pqvm::integrations::abi::{self, Alg, Call, Op};
use aegis_pqvm::integrations::bitcoin::BitcoinIntegration;
use aegis_pqvm::integrations::cosmwasm::CosmwasmIntegration;
use aegis_pqvm::integrations::evm;
use aegis_pqvm::integrations::move_vm::MoveIntegration;
use aegis_pqvm::integrations::solana::SolanaIntegration;
use aegis_pqvm::integrations::substrate::SubstrateIntegration;
use aegis_pqvm::mldsa::mldsa44;
use pqrust_traits::sign::{DetachedSignature as _, PublicKey as _};

// --- EVM validation ---

#[test]
fn evm_precompile_rejects_invalid_magic() {
    let bad_payload = [0u8; 20];
    let result = evm::evm_precompile_call(&bad_payload);
    assert!(result.is_err());
}

#[test]
fn evm_precompile_rejects_truncated_payload() {
    let truncated = b"AEG1\x01\x02"; // magic + op + alg, no args
    let result = evm::evm_precompile_call(truncated);
    assert!(result.is_err());
}

#[test]
fn evm_precompile_accepts_valid_decode_then_fails_on_bad_args() {
    // Valid AEG1 format but args may be wrong for the op
    let call = Call {
        op: Op::MldsaVerifyDetached,
        alg: Alg::Mldsa44,
        args: vec![vec![0u8; 10], vec![0u8; 20], vec![0u8; 30]], // invalid pk/sig sizes
    };
    let payload = abi::encode_call(&call).expect("encode call");
    let result = evm::evm_precompile_call(&payload);
    assert!(result.is_err());
}

#[test]
fn evm_gas_cost_rejects_invalid_payload() {
    let bad = b"BAD1";
    let result = evm::evm_gas_cost(bad);
    assert!(result.is_err());
}

#[test]
fn evm_gas_cost_returns_positive_for_valid_op() {
    let call = Call {
        op: Op::MldsaVerifyDetached,
        alg: Alg::Mldsa44,
        args: vec![vec![0u8; 100], vec![0u8; 50], vec![0u8; 200]],
    };
    let payload = abi::encode_call(&call).expect("encode call");
    let result = evm::evm_gas_cost(&payload);
    assert!(result.is_ok());
    assert!(result.unwrap() > 0);
}

// --- Substrate validation ---
#[test]
fn substrate_dispatch_rejects_invalid_payload() {
    let result = SubstrateIntegration::dispatch_call(&[]);
    assert!(result.is_err());
}

// --- CosmWasm validation ---

#[test]
fn cosmwasm_call_rejects_empty_contract() {
    let result = CosmwasmIntegration::call_contract(&[], b"AEG1\x02\x0a\x03");
    assert!(result.is_err());
}

#[test]
fn cosmwasm_call_rejects_invalid_message() {
    let result = CosmwasmIntegration::call_contract(b"contract_addr", &[]);
    assert!(result.is_err());
}

#[test]
fn cosmwasm_call_rejects_contract_mismatch() {
    let call = Call {
        op: Op::MldsaVerifyDetached,
        alg: Alg::Mldsa44,
        args: vec![vec![0u8; 1], vec![0u8; 1], vec![0u8; 1]],
    };
    let payload = abi::encode_call(&call).expect("encode call");
    let bound = CosmwasmIntegration::encode_bound_message(b"contract_a", &payload)
        .expect("encode bound message");

    let result = CosmwasmIntegration::call_contract(b"contract_b", &bound);
    assert!(result.is_err());
}

#[test]
fn cosmwasm_call_accepts_bound_payload() {
    let (pk, sk) = mldsa44::keypair();
    let msg = b"cosmwasm-bound-message";
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
    let bound = CosmwasmIntegration::encode_bound_message(b"contract_addr", &payload)
        .expect("encode bound message");

    let raw = CosmwasmIntegration::call_contract(b"contract_addr", &bound).expect("dispatch");
    let body = abi::decode_response(&raw)
        .expect("decode")
        .expect("success");
    assert_eq!(body, vec![1u8]);
}

// --- Solana validation ---

#[test]
fn solana_invoke_rejects_invalid_payload() {
    let result = SolanaIntegration::invoke_instruction(&[]);
    assert!(result.is_err());
}

// --- Move validation ---

#[test]
fn move_invoke_rejects_missing_payload_arg() {
    let result = MoveIntegration::invoke_entry_function("m", "f", &[]);
    assert!(result.is_err());
}

#[test]
fn move_invoke_rejects_extra_payload_args() {
    let result = MoveIntegration::invoke_entry_function(
        "aegis",
        "mldsa44_verify_detached",
        &[vec![0x01], vec![0x02]],
    );
    assert!(result.is_err());
}

#[test]
fn move_invoke_rejects_route_payload_mismatch() {
    let call = Call {
        op: Op::FndsaVerifyDetached,
        alg: Alg::Fndsa512,
        args: vec![vec![0u8; 1], vec![0u8; 1], vec![0u8; 1]],
    };
    let payload = abi::encode_call(&call).expect("encode call");
    let result =
        MoveIntegration::invoke_entry_function("aegis", "mldsa44_verify_detached", &[payload]);
    assert!(result.is_err());
}

// --- Bitcoin validation ---

#[test]
fn bitcoin_verify_rejects_invalid_payload() {
    let result = BitcoinIntegration::verify_script_payload(&[]);
    assert!(result.is_err());
}
