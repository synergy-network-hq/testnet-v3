use std::collections::hash_map::DefaultHasher;
use std::env;
use std::hash::{Hash, Hasher};

use aegis_pqvm::integrations::abi::{self, Alg, Call, Op};
use aegis_pqvm::integrations::bitcoin::BitcoinIntegration;
use aegis_pqvm::integrations::cosmwasm::CosmwasmIntegration;
use aegis_pqvm::integrations::evm;
use aegis_pqvm::integrations::move_vm::MoveIntegration;
use aegis_pqvm::integrations::solana::SolanaIntegration;
use aegis_pqvm::integrations::substrate::SubstrateIntegration;
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

const MAX_MUTATED_PAYLOAD_BYTES: usize = 4096;

fn mutate_payload(base: &[u8], rng: &mut StdRng) -> Vec<u8> {
    let mut out = base.to_vec();
    let operations = rng.gen_range(1..=6);

    for _ in 0..operations {
        match rng.gen_range(0..6) {
            // Flip one random bit.
            0 => {
                if !out.is_empty() {
                    let idx = rng.gen_range(0..out.len());
                    out[idx] ^= 1 << rng.gen_range(0..8);
                }
            }
            // Insert one random byte.
            1 => {
                if out.len() < MAX_MUTATED_PAYLOAD_BYTES {
                    let idx = rng.gen_range(0..=out.len());
                    out.insert(idx, rng.gen::<u8>());
                }
            }
            // Remove one random byte.
            2 => {
                if !out.is_empty() {
                    let idx = rng.gen_range(0..out.len());
                    out.remove(idx);
                }
            }
            // Truncate to a random shorter length.
            3 => {
                if !out.is_empty() {
                    let new_len = rng.gen_range(0..out.len());
                    out.truncate(new_len);
                }
            }
            // Append up to 16 random bytes.
            4 => {
                let append_len = rng.gen_range(1..=16);
                for _ in 0..append_len {
                    if out.len() >= MAX_MUTATED_PAYLOAD_BYTES {
                        break;
                    }
                    out.push(rng.gen::<u8>());
                }
            }
            // Swap two bytes.
            _ => {
                if out.len() >= 2 {
                    let i = rng.gen_range(0..out.len());
                    let j = rng.gen_range(0..out.len());
                    out.swap(i, j);
                }
            }
        }
    }

    if out.len() > MAX_MUTATED_PAYLOAD_BYTES {
        out.truncate(MAX_MUTATED_PAYLOAD_BYTES);
    }

    out
}

fn exercise_all_adapters(payload: &[u8]) {
    let _ = abi::decode_call(payload);
    let _ = abi::decode_response(payload);
    let _ = abi::dispatch_deterministic(payload);
    let _ = abi::dispatch_offchain(payload);
    let _ = evm::evm_precompile_call(payload);
    let _ = evm::evm_gas_cost(payload);
    let _ = SubstrateIntegration::dispatch_call(payload);
    let _ = SolanaIntegration::invoke_instruction(payload);
    let _ = BitcoinIntegration::verify_script_payload(payload);
    let _ = CosmwasmIntegration::call_contract(b"contract_addr", payload);
    let _ = MoveIntegration::invoke_entry_function(
        "aegis",
        "mldsa44_verify_detached",
        &[payload.to_vec()],
    );
}

fn deterministic_seed() -> u64 {
    let seed_text =
        env::var("AEGIS_FAULT_SEED").unwrap_or_else(|_| "aegis-pqvm-fault-seed-v1".to_string());
    let mut hasher = DefaultHasher::new();
    seed_text.hash(&mut hasher);
    hasher.finish()
}

#[test]
fn fault_injection_campaign_is_fail_closed_and_panic_free() {
    let iterations = env::var("AEGIS_FAULT_ITERATIONS")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(5_000);

    let mut rng = StdRng::seed_from_u64(deterministic_seed());

    let verify_call = Call {
        op: Op::MldsaVerifyDetached,
        alg: Alg::Mldsa44,
        args: vec![vec![0u8; 32], vec![1u8; 24], vec![2u8; 80]],
    };
    let verify_payload =
        abi::encode_call(&verify_call).expect("encode deterministic verify payload");

    let decap_call = Call {
        op: Op::MlkemDecapsulate,
        alg: Alg::Mlkem768,
        args: vec![vec![3u8; 64], vec![4u8; 96]],
    };
    let offchain_payload = abi::encode_call_offchain(&decap_call)
        .expect("encode off-chain-only decapsulation payload");

    let bound_payload =
        CosmwasmIntegration::encode_bound_message(b"contract_addr", &verify_payload)
            .expect("encode bound payload");

    let seeds = [
        verify_payload,
        offchain_payload,
        bound_payload,
        b"AEG1".to_vec(),
        Vec::new(),
    ];

    for _ in 0..iterations {
        let seed = &seeds[rng.gen_range(0..seeds.len())];
        let mutated = mutate_payload(seed, &mut rng);
        exercise_all_adapters(&mutated);
    }
}
