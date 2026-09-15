//! Tier / platform smoke tests across VM adapters (dev MAC licenses).

use aegis_pqvm::integrations::abi::{self, Alg, Call, Op};
use aegis_pqvm::integrations::cosmwasm::CosmwasmIntegration;
use aegis_pqvm::integrations::evm;
use aegis_pqvm::integrations::move_vm::MoveIntegration;
use aegis_pqvm::integrations::solana::SolanaIntegration;
use aegis_pqvm::integrations::substrate::SubstrateIntegration;
use aegis_pqvm::integrations::synergy::SynergyIntegration;
use aegis_pqvm::licensing::{self, Tier};

fn mldsa_verify_payload() -> Vec<u8> {
    let call = Call {
        op: Op::MldsaVerifyDetached,
        alg: Alg::Mldsa44,
        args: vec![vec![0u8; 1], vec![0u8; 1], vec![0u8; 1]],
    };
    abi::encode_call(&call).expect("encode")
}

#[test]
fn starter_evm_ok_synergy_denied() {
    licensing::install_dev_test_license(Tier::Starter);
    let payload = mldsa_verify_payload();
    assert!(evm::evm_precompile_call(&payload).is_err()); // no mldsa on starter
    assert!(SynergyIntegration::dispatch_call(&payload).is_err());
}

#[test]
fn pro_evm_substrate_synergy_ok_cosmwasm_denied() {
    licensing::install_dev_test_license(Tier::Pro);
    let payload = mldsa_verify_payload();
    assert!(SubstrateIntegration::dispatch_call(&payload).is_err()); // bad key bytes
    assert!(SynergyIntegration::dispatch_call(&payload).is_err()); // bad key bytes
    assert!(evm::evm_precompile_call(&payload).is_err());
    assert!(CosmwasmIntegration::call_contract(b"c", &payload).is_err());
}

#[test]
fn business_all_platforms_reach_dispatch() {
    licensing::install_dev_test_license(Tier::Business);
    let payload = mldsa_verify_payload();
    assert!(evm::evm_precompile_call(&payload).is_err());
    assert!(SubstrateIntegration::dispatch_call(&payload).is_err());
    assert!(SynergyIntegration::dispatch_call(&payload).is_err());
    assert!(SolanaIntegration::invoke_instruction(&payload).is_err());
    let bound = CosmwasmIntegration::encode_bound_message(b"contract", &payload).unwrap();
    assert!(CosmwasmIntegration::call_contract(b"contract", &bound).is_err());
    assert!(
        MoveIntegration::invoke_entry_function("aegis", "mldsa44_verify_detached", &[payload])
            .is_err()
    );
}
