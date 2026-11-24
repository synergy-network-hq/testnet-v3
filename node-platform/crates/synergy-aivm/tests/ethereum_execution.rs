use std::{collections::BTreeMap, sync::Arc};
use synergy_aivm::ethereum_execution::*;
use synergy_state::world_resources::WorldResourceBudget;
use synergy_state::{state_root, AccountState, WorldState};

fn unhex(text: &str) -> Vec<u8> {
    text.trim_start_matches("0x")
        .as_bytes()
        .chunks_exact(2)
        .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
        .collect()
}
fn fixture() -> serde_json::Value {
    serde_json::from_str(include_str!("fixtures/evm-counter-shanghai.json")).unwrap()
}
fn address(value: &serde_json::Value, key: &str) -> [u8; 20] {
    unhex(value[key].as_str().unwrap()).try_into().unwrap()
}
fn raw(value: &serde_json::Value, index: usize) -> Vec<u8> {
    unhex(value["transactions"][index]["raw"].as_str().unwrap())
}
fn policy() -> EvmCompatibilityPolicy {
    EvmCompatibilityPolicy {
        schema_version: 1,
        engine: "revm-43.0.3".into(),
        chain_id: 9969,
        fork: EvmFork::Shanghai,
        block_gas_limit: 2_000_000,
        memory_limit: 1024 * 1024,
        maximum_accounts: 16,
        maximum_storage_slots: 128,
        maximum_code_bytes: 24576,
        maximum_receipt_bytes: 262144,
        maximum_patch_bytes: 65536,
        base_fee_nwei: 1,
        fee_collector: [0x55; 20],
        retain_base_fee_in_native_treasury: true,
        reject_sub_native_precision: true,
        native_exception_policy: "full-gas-no-action-v1".into(),
        blockhash_policy: "native-posy-block-id-v1".into(),
        randomness_policy: "authenticated-epoch-seed-v1".into(),
        rpc_projection_policy: "native-posy-evm-view-v1".into(),
    }
}
fn setup() -> (WorldState, Arc<WorldResourceBudget>) {
    let f = fixture();
    let mut world = WorldState::default();
    let policy = policy();
    world
        .protocol
        .insert(EVM_POLICY_KEY.into(), serde_json::to_vec(&policy).unwrap());
    world.accounts.insert(
        conventional_evm_account_key(address(&f, "sender")),
        AccountState {
            balance_nwei: 10_000_000_000,
            nonce: 0,
            code_hash: None,
        },
    );
    (world, WorldResourceBudget::new(256 * 1024 * 1024))
}
fn context<'a>(hashes: &'a BTreeMap<u64, [u8; 32]>) -> EvmBlockContext<'a> {
    EvmBlockContext {
        chain_id: 9969,
        genesis: [8; 32],
        policy_sha256: synergy_aegis::AegisProtectedPrimitives
            .sha256(&serde_json::to_vec(&policy()).unwrap()),
        height: 10,
        timestamp: 1795600000,
        gas_used_before: 0,
        randomness: [7; 32],
        recent_block_hashes: hashes,
        protected_credit_verifier: None,
    }
}
#[test]
fn native_funding_uses_one_ledger_and_denies_protected_aliases_and_contracts() {
    let (mut world, _) = setup();
    let payer = "syna1trr36xu7z866hwyv4njkkun5wy0qzl63vhys";
    world.accounts.insert(payer.into(), AccountState { balance_nwei: 10_000, nonce: 7, code_hash: None });
    let request = NativeEvmFunding { recipient: [0x99; 20], amount_nwei: 1_234 };
    let encoded = request.encode().unwrap();
    assert_eq!(NativeEvmFunding::decode(&encoded).unwrap(), request);
    assert!(NativeEvmFunding::decode(&encoded[..36]).is_err());
    assert!(NativeEvmFunding::decode(&[encoded.as_slice(), &[0]].concat()).is_err());
    let original = world.clone();
    let diff = request.prepare(&world, 9969, payer, 7).unwrap();
    assert_eq!(world, original);
    diff.apply(&mut world).unwrap();
    assert_eq!(world.accounts[payer].balance_nwei, 8_766);
    assert_eq!(world.accounts[payer].nonce, 8);
    assert_eq!(read_evm_account(&world, request.recipient).unwrap().balance_wei,
        synergy_aivm::ethereum::nwei_to_wei(1_234));
    let applied = world.clone();
    assert!(diff.apply(&mut world).is_err());
    assert_eq!(world, applied, "replayed funding changed the one ledger");
    assert!(request.prepare(&original, 99999, payer, 7).is_err());
    assert!(request.prepare(&original, 9969, payer, 8).is_err());
    let mut protected = original.clone();
    protected.protocol.insert(format!("apqe-protected-account-candidate/v1/policy/{}", "99".repeat(20)), b"malformed".to_vec());
    assert!(matches!(request.prepare(&protected, 9969, payer, 7), Err(EvmExecutionError::ProtectedAccount)));
    let alias = synergy_address::protected_wallet_native_representation(request.recipient).unwrap();
    let mut ambiguous = original.clone();
    ambiguous.accounts.insert(alias.clone(), AccountState::default());
    assert!(matches!(request.prepare(&ambiguous, 9969, payer, 7), Err(EvmExecutionError::AmbiguousAccount)));
    assert!(request.prepare(&ambiguous, 9969, &alias, 0).is_err());
    let mut contract = original.clone();
    contract.accounts.insert(conventional_evm_account_key(request.recipient), AccountState {
        code_hash: Some("11".repeat(32)), ..AccountState::default()
    });
    assert!(request.prepare(&contract, 9969, payer, 7).is_err());
    assert!(NativeEvmFunding { recipient: [0;20], ..request }.encode().is_err());
    assert!(NativeEvmFunding { amount_nwei: 0, ..request }.encode().is_err());
}
#[test]
fn unsigned_simulation_exposes_gasprice_and_basefee_without_charging_native_assets() {
    use sha3::{Digest, Keccak256};
    let (mut world, budget) = setup();
    let code = unhex("3a6000524860205260406000f3");
    let hash = Keccak256::digest(&code).iter().map(|b|format!("{b:02x}")).collect::<String>();
    world.protocol.insert(format!("aivm/ethereum/v1/code/{hash}"), code);
    world.accounts.insert(conventional_evm_account_key([0x77;20]), AccountState {
        balance_nwei: 0, nonce: 1, code_hash: Some(hash),
    });
    let original = world.clone();
    let history = BTreeMap::new();
    let request = EvmCallRequest {
        from: [0;20], recipient: Some([0x77;20]), value_wei: [0;32], data: &[],
        gas_limit: 100_000, gas_price_wei: 40_000_000_000,
    };
    let result = call_evm(&request, &context(&history), &world, &budget).unwrap();
    assert!(result.success);
    assert_eq!(result.output.len(),64);
    assert_eq!(&result.output[..32],&synergy_aivm::ethereum::nwei_to_wei(40));
    assert_eq!(&result.output[32..],&synergy_aivm::ethereum::nwei_to_wei(1));
    assert!(result.gas_used>21_000);
    drop(result);
    assert!(estimate_evm_gas(&request,&context(&history),&world,&budget).unwrap()>21_000);
    assert_eq!(world,original);
}
#[test]
fn blockhash_opcode_uses_exact_native_history_window_and_refuses_missing_ancestors() {
    use sha3::{Digest, Keccak256};
    let (mut world, budget) = setup();
    // Real EVM runtime: return BLOCKHASH(calldata[0..32]). No receipt or
    // interpreter is mocked; code executes in the same AIVM call kernel.
    let code = unhex("6000354060005260206000f3");
    let code_hash = Keccak256::digest(&code)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    world
        .protocol
        .insert(format!("aivm/ethereum/v1/code/{code_hash}"), code);
    world.accounts.insert(
        conventional_evm_account_key([0x77; 20]),
        AccountState {
            balance_nwei: 0,
            nonce: 1,
            code_hash: Some(code_hash),
        },
    );
    let original = world.clone();
    let history = BTreeMap::from([(44, [0x44; 32]), (299, [0x99; 32])]);
    let mut ctx = context(&history);
    ctx.height = 300;
    for (number, expected) in [
        (44, [0x44; 32]),
        (299, [0x99; 32]),
        (43, [0; 32]),
        (300, [0; 32]),
        (301, [0; 32]),
    ] {
        let mut data = [0u8; 32];
        data[24..].copy_from_slice(&(number as u64).to_be_bytes());
        let result = call_evm(
            &EvmCallRequest {
                gas_price_wei: 0,
                from: [0x11; 20],
                recipient: Some([0x77; 20]),
                value_wei: [0; 32],
                data: &data,
                gas_limit: 100_000,
            },
            &ctx,
            &world,
            &budget,
        )
        .unwrap();
        assert!(result.success);
        assert_eq!(result.output, expected);
    }
    let mut data = [0u8; 32];
    data[31] = 45;
    assert!(matches!(
        call_evm(
            &EvmCallRequest {
                gas_price_wei: 0,
                from: [0x11; 20],
                recipient: Some([0x77; 20]),
                value_wei: [0; 32],
                data: &data,
                gas_limit: 100_000
            },
            &ctx,
            &world,
            &budget
        ),
        Err(EvmExecutionError::MissingBlockHistory)
    ));
    assert_eq!(world, original);
}

#[test]
fn independent_solidity_and_ethers_deploy_call_logs_storage_revert_and_native_fees() {
    use sha3::{Digest, Keccak256};
    let f = fixture();
    let (mut world, budget) = setup();
    let hashes = BTreeMap::new();
    let ctx = context(&hashes);
    assert_eq!(
        Keccak256::digest(include_bytes!("fixtures/EvmCounter.sol")).as_slice(),
        unhex(f["sourceKeccak"].as_str().unwrap())
    );
    let sender = conventional_evm_account_key(address(&f, "sender"));
    let contract = conventional_evm_account_key(address(&f, "address"));
    let treasury = conventional_evm_account_key([0x55; 20]);
    let mut fees = 0;
    for index in 0..4 {
        let before = world.clone();
        let candidate = execute_legacy_evm(&raw(&f, index), &ctx, &world, &budget).unwrap();
        assert_eq!(
            world, before,
            "speculation must not mutate its native parent"
        );
        let independent = execute_legacy_evm(&raw(&f, index), &ctx, &world, &budget).unwrap();
        assert_eq!(candidate.receipt, independent.receipt);
        assert_eq!(
            state_root(candidate.world.as_ref()).unwrap(),
            state_root(independent.world.as_ref()).unwrap()
        );
        assert_eq!(
            candidate.receipt.transaction_hash.as_slice(),
            unhex(f["transactions"][index]["hash"].as_str().unwrap())
        );
        assert_eq!(candidate.receipt.success, index != 2);
        assert!(candidate.receipt.gas_used > 21000);
        fees += candidate.receipt.fee_nwei;
        assert_eq!(
            candidate.receipt.fee_nwei,
            candidate.receipt.gas_used as u128 * 20
        );
        if index == 0 {
            assert_eq!(
                candidate.receipt.created_address,
                Some(address(&f, "address"))
            );
            assert!(candidate.world.as_ref().accounts[&contract]
                .code_hash
                .is_some());
            let hash = candidate.world.as_ref().accounts[&contract]
                .code_hash
                .as_ref()
                .unwrap();
            assert_eq!(
                candidate.world.as_ref().protocol[&format!("aivm/ethereum/v1/code/{hash}")],
                unhex(f["runtime"].as_str().unwrap())
            );
        }
        if index == 1 {
            assert_eq!(candidate.receipt.logs.len(), 1);
            assert_eq!(candidate.receipt.logs[0].address, address(&f, "address"));
            assert_eq!(candidate.receipt.logs[0].data.last(), Some(&42));
        }
        if index == 2 {
            assert!(candidate.receipt.logs.is_empty());
            assert!(!candidate.receipt.output.is_empty());
        }
        if index == 3 {
            assert_eq!(candidate.receipt.output.len(), 32);
            assert_eq!(candidate.receipt.output[31], 42);
        }
        world =
            serde_json::from_slice(&serde_json::to_vec(candidate.world.as_ref()).unwrap()).unwrap();
        assert_eq!(world.accounts[&sender].nonce, index as u64 + 1);
        assert_eq!(world.accounts[&treasury].balance_nwei, fees);
        assert_eq!(
            world
                .accounts
                .values()
                .map(|account| account.balance_nwei)
                .sum::<u128>(),
            10_000_000_000
        );
        assert!(execute_legacy_evm(&raw(&f, index), &ctx, &world, &budget).is_err());
    }
}
fn after_four() -> (WorldState, Arc<WorldResourceBudget>) {
    let f = fixture();
    let (mut world, budget) = setup();
    let h = BTreeMap::new();
    for i in 0..4 {
        let candidate = execute_legacy_evm(&raw(&f, i), &context(&h), &world, &budget).unwrap();
        world =
            serde_json::from_slice(&serde_json::to_vec(candidate.world.as_ref()).unwrap()).unwrap();
    }
    (world, budget)
}
#[test]
fn sub_native_internal_payment_is_rejected_atomically_and_protected_credit_has_one_balance() {
    let f = fixture();
    let (mut world, budget) = after_four();
    let original = world.clone();
    let hashes = BTreeMap::new();
    assert!(matches!(
        execute_legacy_evm(&raw(&f, 4), &context(&hashes), &world, &budget),
        Err(EvmExecutionError::Precision)
    ));
    assert_eq!(world, original);
    let account = [0x35; 20];
    let native = synergy_address::protected_wallet_native_representation(account).unwrap();
    world.protocol.insert(
        "apqe-protected-account-candidate/v1/policy/3535353535353535353535353535353535353535"
            .into(),
        vec![1],
    );
    world
        .accounts
        .insert(native.clone(), AccountState::default());
    assert!(matches!(
        execute_legacy_evm(&raw(&f, 5), &context(&hashes), &world, &budget),
        Err(EvmExecutionError::ProtectedAccount)
    ));
    let verify_credit = |id: &[u8; 20], _state: &WorldState| {
        if *id == account {
            Ok(())
        } else {
            Err("unregistered".into())
        }
    };
    let mut ctx = context(&hashes);
    ctx.protected_credit_verifier = Some(&verify_credit);
    let result = execute_legacy_evm(&raw(&f, 5), &ctx, &world, &budget).unwrap();
    assert!(result.receipt.success);
    assert_eq!(result.world.as_ref().accounts[&native].balance_nwei, 1);
    assert!(!result
        .world
        .as_ref()
        .accounts
        .contains_key(&conventional_evm_account_key(account)));
    assert_eq!(result.world.as_ref().accounts[&native].nonce, 0);
}
#[test]
fn policy_identity_protected_authority_and_resource_failures_are_closed() {
    let f = fixture();
    let (mut world, budget) = setup();
    let hashes = BTreeMap::new();
    for chain_id in [1266, 99999, 469] {
        let mut ctx = context(&hashes);
        ctx.chain_id = chain_id;
        assert!(matches!(
            execute_legacy_evm(&raw(&f, 0), &ctx, &world, &budget),
            Err(EvmExecutionError::WrongNetwork)
        ));
    }
    let tiny = WorldResourceBudget::new(1024);
    let before = world.clone();
    assert!(matches!(
        execute_legacy_evm(&raw(&f, 0), &context(&hashes), &world, &tiny),
        Err(EvmExecutionError::LocalResource(_))
    ));
    assert_eq!(world, before);
    world.protocol.insert(
        "apqe-protected-account-candidate/v1/policy/9d8a62f656a8d1615c1294fd71e9cfb3e4855a4f"
            .into(),
        vec![0xff],
    );
    assert!(matches!(
        execute_legacy_evm(&raw(&f, 0), &context(&hashes), &world, &budget),
        Err(EvmExecutionError::SpendingAuthorityRevoked)
    ));
    world.protocol.remove(EVM_POLICY_KEY);
    assert!(matches!(
        execute_legacy_evm(&raw(&f, 0), &context(&hashes), &world, &budget),
        Err(EvmExecutionError::MissingGovernedPolicy)
    ));
}

#[test]
fn unsigned_eth_call_and_estimate_gas_use_real_solidity_without_spending_or_returning_state() {
    let f = fixture();
    let (world, budget) = after_four();
    let hashes = BTreeMap::new();
    let original = world.clone();
    let tx = synergy_aivm::ethereum::decode_eip155(&raw(&f, 3), 9969).unwrap();
    let request = EvmCallRequest {
        gas_price_wei: 0,
        from: [0; 20],
        recipient: Some(address(&f, "address")),
        value_wei: [0; 32],
        data: &tx.data,
        gas_limit: 1_000_000,
    };
    let output = call_evm(&request, &context(&hashes), &world, &budget).unwrap();
    assert!(output.success);
    assert_eq!(output.output.len(), 32);
    assert_eq!(output.output[31], 42);
    drop(output);
    let estimate = estimate_evm_gas(&request, &context(&hashes), &world, &budget).unwrap();
    assert!((21_000..1_000_000).contains(&estimate));
    let exact = EvmCallRequest {
        gas_limit: estimate,
        ..request
    };
    assert!(
        call_evm(&exact, &context(&hashes), &world, &budget)
            .unwrap()
            .success
    );
    let below = EvmCallRequest {
        gas_limit: estimate - 1,
        ..request
    };
    assert!(
        !call_evm(&below, &context(&hashes), &world, &budget)
            .unwrap()
            .success
    );
    assert_eq!(world, original);
    let view = read_evm_account(&world, address(&f, "address")).unwrap();
    assert_eq!(view.code, unhex(f["runtime"].as_str().unwrap()));
    assert_eq!(view.nonce, 1);
    let slot = read_evm_storage(&world, address(&f, "address"), [0; 32]).unwrap();
    assert_eq!(slot[31], 42);
}

#[test]
fn actual_transfers_and_shanghai_selfdestruct_share_native_asset_and_clear_storage() {
    let f = fixture();
    let (world, budget) = setup();
    let hashes = BTreeMap::new();
    let transfer = execute_legacy_evm(&raw(&f, 9), &context(&hashes), &world, &budget).unwrap();
    assert_eq!(transfer.receipt.gas_used, 21000);
    assert_eq!(
        transfer.world.as_ref().accounts[&conventional_evm_account_key([0x35; 20])].balance_nwei,
        1_000_000_000
    );
    drop(transfer);
    let (world, budget) = after_four();
    let funded = execute_legacy_evm(&raw(&f, 6), &context(&hashes), &world, &budget).unwrap();
    let contract = conventional_evm_account_key(address(&f, "address"));
    assert_eq!(funded.world.as_ref().accounts[&contract].balance_nwei, 1);
    assert!(matches!(
        execute_legacy_evm(
            &raw(&f, 8),
            &context(&hashes),
            funded.world.as_ref(),
            &budget
        ),
        Err(EvmExecutionError::Conservation)
    ));
    let removed = execute_legacy_evm(
        &raw(&f, 7),
        &context(&hashes),
        funded.world.as_ref(),
        &budget,
    )
    .unwrap();
    assert!(removed.receipt.success);
    assert!(removed.world.as_ref().accounts[&contract]
        .code_hash
        .is_none());
    assert_eq!(removed.world.as_ref().accounts[&contract].nonce, 0);
    assert_eq!(
        removed.world.as_ref().accounts[&conventional_evm_account_key([0x35; 20])].balance_nwei,
        1
    );
    assert!(!removed
        .world
        .as_ref()
        .protocol
        .keys()
        .any(|key| key.starts_with("aivm/ethereum/v1/storage/")));
    assert_eq!(
        removed
            .world
            .as_ref()
            .accounts
            .values()
            .map(|account| account.balance_nwei)
            .sum::<u128>(),
        10_000_000_000
    );
}

#[test]
fn real_ecrecover_precompile_uses_apqe_and_preserves_unsigned_simulation_boundaries() {
    let f = fixture();
    let (world, budget) = setup();
    let hashes = BTreeMap::new();
    let tx = synergy_aivm::ethereum::decode_eip155(&raw(&f, 0), 9969).unwrap();
    let mut data = [0u8; 128];
    data[..32].copy_from_slice(&tx.signing_hash);
    data[63] = 27 + ((tx.v - 35) % 2) as u8;
    data[64..96].copy_from_slice(&tx.r);
    data[96..].copy_from_slice(&tx.s);
    let mut precompile = [0u8; 20];
    precompile[19] = 1;
    let request = EvmCallRequest {
        gas_price_wei: 0,
        from: [0; 20],
        recipient: Some(precompile),
        value_wei: [0; 32],
        data: &data,
        gas_limit: 100_000,
    };
    let result = call_evm(&request, &context(&hashes), &world, &budget).unwrap();
    assert!(result.success);
    assert_eq!(result.output.len(), 32);
    assert_eq!(&result.output[12..], address(&f, "sender"));
}

#[test]
fn ordered_native_exceptions_consume_nonce_full_gas_without_action_or_coin_loss() {
    use synergy_aivm::ethereum_execution::execute_ordered_legacy_evm;
    let f = fixture();
    let (mut world, budget) = setup();
    let hashes = BTreeMap::new();
    let context = context(&hashes);
    let sender = conventional_evm_account_key(address(&f, "sender"));
    let contract = conventional_evm_account_key(address(&f, "address"));
    let treasury = conventional_evm_account_key([0x55; 20]);
    for index in 0..4 {
        world = execute_legacy_evm(&raw(&f, index), &context, &world, &budget)
            .unwrap()
            .world
            .as_ref()
            .clone();
    }
    let original = world.clone();
    let failed = execute_ordered_legacy_evm(&raw(&f, 4), &context, &world, &budget).unwrap();
    assert!(!failed.receipt.success);
    assert_eq!(
        failed.receipt.native_exception.as_deref(),
        Some("sub-native-precision")
    );
    assert_eq!(failed.receipt.gas_used, 1_000_000);
    assert_eq!(failed.receipt.fee_nwei, 20_000_000);
    assert_eq!(failed.world.accounts[&sender].nonce, 5);
    assert_eq!(
        original.accounts[&sender].balance_nwei - failed.world.accounts[&sender].balance_nwei,
        20_000_000
    );
    assert_eq!(
        failed.world.accounts[&treasury].balance_nwei - original.accounts[&treasury].balance_nwei,
        20_000_000
    );
    assert_eq!(
        failed.world.accounts[&contract],
        original.accounts[&contract]
    );
    assert_eq!(failed.world.protocol, original.protocol);
    assert!(failed.receipt.logs.is_empty());
    assert!(
        execute_ordered_legacy_evm(&raw(&f, 4), &context, &failed.world, &budget).is_err(),
        "exception nonce cannot execute twice"
    );
    assert_eq!(world, original);
    // SELFDESTRUCT-to-self must not burn the canonical native asset. Its
    // deterministic rejection also retires the ordered request with a receipt.
    let funded = execute_legacy_evm(&raw(&f, 6), &context, &world, &budget).unwrap();
    let failed = execute_ordered_legacy_evm(&raw(&f, 8), &context, &funded.world, &budget).unwrap();
    assert_eq!(
        failed.receipt.native_exception.as_deref(),
        Some("native-coin-conservation")
    );
    assert_eq!(
        failed.world.accounts[&contract],
        funded.world.accounts[&contract]
    );
    assert_eq!(failed.world.protocol, funded.world.protocol);
    assert_eq!(failed.world.accounts[&sender].nonce, 6);
    assert_eq!(
        failed
            .world
            .accounts
            .values()
            .map(|account| account.balance_nwei)
            .sum::<u128>(),
        funded
            .world
            .accounts
            .values()
            .map(|account| account.balance_nwei)
            .sum::<u128>()
    );
    let tiny = WorldResourceBudget::new(1024);
    assert!(matches!(
        execute_ordered_legacy_evm(&raw(&f, 0), &context, &setup().0, &tiny),
        Err(EvmExecutionError::LocalResource(_))
    ));
    assert_eq!(tiny.used(), 0);
}

#[test]
fn ethereum_state_mpt_matches_independent_ethers_rlp_and_preserves_native_aliases() {
    use synergy_aivm::ethereum_projection::ethereum_state_root;
    let (_, budget) = setup();
    let mut world = WorldState::default();
    world.protocol.insert(
        EVM_POLICY_KEY.into(),
        serde_json::to_vec(&policy()).unwrap(),
    );
    let account = [0x35; 20];
    let external = conventional_evm_account_key(account);
    world.accounts.insert(
        external.clone(),
        AccountState {
            balance_nwei: 1,
            nonce: 0,
            code_hash: None,
        },
    );
    // Independent ethers6.15.0: keccak(RLP([hex-prefix(keccak(address)),
    // RLP([nonce,balanceWei,emptyStorageRoot,keccak(emptyCode)])])).
    let expected = unhex("0xdb3df03b5c10d773773385bc2c5e62dee708335eab18cc6d4ff7363b49d77dd8");
    assert_eq!(
        ethereum_state_root(&world, &budget).unwrap().as_slice(),
        expected
    );
    world.accounts.insert(
        conventional_evm_account_key([0xaa; 20]),
        AccountState::default(),
    );
    assert_eq!(
        ethereum_state_root(&world, &budget).unwrap().as_slice(),
        expected,
        "EIP161 ignores empty native tombstones"
    );
    let value = world.accounts.remove(&external).unwrap();
    let native = synergy_address::protected_wallet_native_representation(account).unwrap();
    world.accounts.insert(native, value);
    world.protocol.insert(
        format!(
            "apqe-protected-account-candidate/v1/policy/{}",
            "35".repeat(20)
        ),
        b"policy presence denies conventional spending".to_vec(),
    );
    assert_eq!(
        ethereum_state_root(&world, &budget).unwrap().as_slice(),
        expected,
        "protected alias is the same projected balance"
    );
    world
        .accounts
        .insert(external.clone(), AccountState::default());
    assert!(matches!(
        ethereum_state_root(&world, &budget),
        Err(EvmExecutionError::AmbiguousAccount)
    ));
    world.accounts.remove(&external);
    world.protocol.remove(&format!(
        "apqe-protected-account-candidate/v1/policy/{}",
        "35".repeat(20)
    ));
    world.accounts.clear();
    let code = "bc36789e7a1e281436464229828f817d6612f7b477d66591ff96a9e064bcc98a";
    world.accounts.insert(
        external,
        AccountState {
            balance_nwei: 0,
            nonce: 1,
            code_hash: Some(code.into()),
        },
    );
    world
        .protocol
        .insert(format!("aivm/ethereum/v1/code/{code}"), vec![0]);
    let mut slot = [0; 32];
    slot[31] = 42;
    world.protocol.insert(
        format!(
            "aivm/ethereum/v1/storage/{}/{}",
            "35".repeat(20),
            "00".repeat(32)
        ),
        slot.to_vec(),
    );
    assert_eq!(
        ethereum_state_root(&world, &budget).unwrap().as_slice(),
        unhex("0xb450d165db6b273ff8ea3836532ac9cd7af9dc19df94dbbcce860a3cdde6659b")
    );
    assert_eq!(budget.used(), 0);
    let tiny = WorldResourceBudget::new(1024);
    assert!(matches!(
        ethereum_state_root(&world, &tiny),
        Err(EvmExecutionError::LocalResource(_))
    ));
    assert_eq!(tiny.used(), 0);
}

#[test]
fn full_governed_gas_simulation_fits_shared_native_history_budget() {
    let f = fixture();
    let (mut world, _) = after_four();
    let mut policy = policy();
    policy.block_gas_limit = 30_000_000;
    policy.memory_limit = 65536;
    policy.maximum_accounts = 32;
    policy.maximum_storage_slots = 256;
    policy.maximum_patch_bytes = 262144;
    world
        .protocol
        .insert(EVM_POLICY_KEY.into(), serde_json::to_vec(&policy).unwrap());
    let budget = WorldResourceBudget::new(512 * 1024 * 1024);
    let history = budget.reserve(330 * 1024 * 1024).unwrap();
    let hashes = BTreeMap::new();
    let mut ctx = context(&hashes);
    ctx.policy_sha256 =
        synergy_aegis::AegisProtectedPrimitives.sha256(&world.protocol[EVM_POLICY_KEY]);
    let tx = synergy_aivm::ethereum::decode_eip155(&raw(&f, 3), 9969).unwrap();
    let request = EvmCallRequest {
        gas_price_wei: 0,
        from: [0; 20],
        recipient: Some(address(&f, "address")),
        value_wei: [0; 32],
        data: &tx.data,
        gas_limit: 30_000_000,
    };
    let output = call_evm(&request, &ctx, &world, &budget).unwrap();
    assert!(output.success);
    assert_eq!(output.output[31], 42);
    drop(output);
    let estimate = estimate_evm_gas(&request, &ctx, &world, &budget).unwrap();
    assert!(estimate > 21000 && estimate < 30_000_000);
    //10,000 paid dirty SSTORE updates: real execution needs more than1M gas.
    // This exercises journal growth and proves estimation keeps the governed
    // upper bound instead of imposing a convenient low RPC default.
    let code = unhex("6127105b805f5560019003806003575000");
    let hash = synergy_aivm::ethereum::ethereum_keccak256(&code);
    let hash = hash.iter().map(|b| format!("{b:02x}")).collect::<String>();
    let contract = [0x33; 20];
    world.accounts.insert(
        conventional_evm_account_key(contract),
        AccountState {
            balance_nwei: 0,
            nonce: 1,
            code_hash: Some(hash.clone()),
        },
    );
    world
        .protocol
        .insert(format!("aivm/ethereum/v1/code/{hash}"), code);
    let heavy = EvmCallRequest {
        recipient: Some(contract),
        data: &[],
        ..request
    };
    let estimate = estimate_evm_gas(&heavy, &ctx, &world, &budget).unwrap();
    assert!(
        estimate > 1_000_000 && estimate < 30_000_000,
        "actual heavy estimate {estimate}"
    );
    let too_small = EvmCallRequest {
        gas_limit: 1_000_000,
        ..heavy
    };
    assert!(!call_evm(&too_small, &ctx, &world, &budget).unwrap().success);
    drop(history);
    assert_eq!(budget.used(), 0);
}

#[test]
fn ordered_precision_exception_does_not_reserve_an_unused_maximum_patch_clone() {
    let f = fixture();
    let (mut world, _) = after_four();
    let hashes = BTreeMap::new();
    let mut policy = policy();
    policy.maximum_patch_bytes = 262144;
    policy.memory_limit = 65536;
    policy.maximum_accounts = 32;
    policy.maximum_storage_slots = 256;
    world
        .protocol
        .insert(EVM_POLICY_KEY.into(), serde_json::to_vec(&policy).unwrap());
    let mut ctx = context(&hashes);
    ctx.policy_sha256 =
        synergy_aegis::AegisProtectedPrimitives.sha256(&world.protocol[EVM_POLICY_KEY]);
    let budget = WorldResourceBudget::new(512 * 1024 * 1024);
    let retained = budget.reserve(411 * 1024 * 1024).unwrap();
    let valid = execute_legacy_evm(&raw(&f, 5), &ctx, &world, &budget).unwrap();
    assert!(valid.receipt.success);
    drop(valid);
    let failed = execute_ordered_legacy_evm(&raw(&f, 4), &ctx, &world, &budget).unwrap();
    assert_eq!(
        failed.receipt.native_exception.as_deref(),
        Some("sub-native-precision")
    );
    assert_eq!(failed.receipt.gas_used, 1_000_000);
    assert_eq!(
        failed.world.accounts[&conventional_evm_account_key(address(&f, "sender"))].nonce,
        5
    );
    drop(failed);
    drop(retained);
    assert_eq!(budget.used(), 0);
}

#[test]
fn bounded_pending_intake_preserves_full_governed_execution_progress() {
    let f = fixture();
    let (mut world, _) = after_four();
    let mut policy = policy();
    policy.block_gas_limit = 30_000_000;
    policy.memory_limit = 65536;
    policy.maximum_accounts = 32;
    policy.maximum_storage_slots = 256;
    policy.maximum_patch_bytes = 262144;
    world
        .protocol
        .insert(EVM_POLICY_KEY.into(), serde_json::to_vec(&policy).unwrap());
    let hashes = BTreeMap::new();
    let mut ctx = context(&hashes);
    ctx.policy_sha256 =
        synergy_aegis::AegisProtectedPrimitives.sha256(&world.protocol[EVM_POLICY_KEY]);
    let budget = WorldResourceBudget::new(512 * 1024 * 1024);
    let base = budget.reserve(60 * 1024 * 1024).unwrap();
    let tx = synergy_aivm::ethereum::decode_eip155(&raw(&f, 3), 9969).unwrap();
    let request = EvmCallRequest {
        gas_price_wei: 0,
        from: [0; 20],
        recipient: Some(address(&f, "address")),
        value_wei: [0; 32],
        data: &tx.data,
        gas_limit: 30_000_000,
    };
    let native_control = 64 * 1024 * 1024;
    let mut old_pending = Vec::new();
    while let Ok(permit) = budget.reserve_with_headroom(64 * 1024 * 1024, native_control) {
        old_pending.push(permit);
    }
    assert!(
        matches!(
            call_evm(&request, &ctx, &world, &budget),
            Err(EvmExecutionError::LocalResource(_))
        ),
        "old admission floor can permanently starve every prepaid EVM worker"
    );
    drop(old_pending);
    let headroom = native_control + ethereum_execution_headroom(&world).unwrap();
    let mut pending = Vec::new();
    while let Ok(permit) = budget.reserve_with_headroom(64 * 1024 * 1024, headroom) {
        pending.push(permit);
    }
    assert!(!pending.is_empty());
    assert!(budget.available() >= headroom);
    let result = call_evm(&request, &ctx, &world, &budget).unwrap();
    assert!(result.success);
    assert_eq!(result.output[31], 42);
    drop(result);
    drop(pending);
    drop(base);
    assert_eq!(budget.used(), 0);
}
