use aegis_pqvm::integrations::abi::{self, Alg, Call, Op};
use aegis_pqvm::integrations::bitcoin::BitcoinIntegration;
use aegis_pqvm::integrations::cosmwasm::CosmwasmIntegration;
use aegis_pqvm::integrations::evm;
use aegis_pqvm::integrations::move_vm::MoveIntegration;
use aegis_pqvm::integrations::solana::SolanaIntegration;
use aegis_pqvm::integrations::substrate::SubstrateIntegration;
use aegis_pqvm::mlkem::mlkem512;
use aegis_pqvm::security::SecurityPrimitives;
use pqrust_traits::kem::{Ciphertext as _, SecretKey as _};

#[test]
fn deterministic_boundary_blocks_secret_key_payload_encoding() {
    let (pk, sk) = mlkem512::keypair();
    let (_ss, ct) = mlkem512::encapsulate(&pk);
    let secret_call = Call {
        op: Op::MlkemDecapsulate,
        alg: Alg::Mlkem512,
        args: vec![ct.as_bytes().to_vec(), sk.as_bytes().to_vec()],
    };

    let err = abi::encode_call(&secret_call).unwrap_err();
    assert!(err
        .to_string()
        .contains("payload encoding is off-chain only"));

    let offchain =
        abi::encode_call_offchain(&secret_call).expect("off-chain encoding should succeed");

    assert!(evm::evm_precompile_call(&offchain).is_err());
    assert!(SubstrateIntegration::dispatch_call(&offchain).is_err());
    assert!(SolanaIntegration::invoke_instruction(&offchain).is_err());
    assert!(BitcoinIntegration::verify_script_payload(&offchain).is_err());
    assert!(MoveIntegration::invoke_entry_function(
        "aegis",
        "mldsa44_verify_detached",
        std::slice::from_ref(&offchain),
    )
    .is_err());

    let bound = CosmwasmIntegration::encode_bound_message(b"contract_addr", &offchain)
        .expect("encode bound payload");
    assert!(CosmwasmIntegration::call_contract(b"contract_addr", &bound).is_err());
}

#[test]
fn constant_time_compare_semantics_hold_for_equal_length_inputs() {
    let a = [0x55u8; 128];

    let mut diff_first = a;
    diff_first[0] ^= 0x01;

    let mut diff_last = a;
    diff_last[127] ^= 0x01;

    assert!(SecurityPrimitives::constant_time_compare(&a, &a));
    assert!(!SecurityPrimitives::constant_time_compare(&a, &diff_first));
    assert!(!SecurityPrimitives::constant_time_compare(&a, &diff_last));
}
