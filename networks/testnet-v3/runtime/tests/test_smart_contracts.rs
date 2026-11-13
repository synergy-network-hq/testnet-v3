use synergy_testnet::node::Blockchain;

#[test]
fn test_smart_contract_deployment() {
    let mut blockchain = Blockchain::new();

    let contract_address = "0xABC123".to_string();
    let contract_code = vec![0x00, 0x61, 0x73, 0x6D]; // Sample WASM header

    blockchain.deploy_smart_contract(contract_address.clone(), contract_code);
    blockchain.execute_smart_contract(&contract_address);

    println!("Smart Contract Test Passed!");
}
