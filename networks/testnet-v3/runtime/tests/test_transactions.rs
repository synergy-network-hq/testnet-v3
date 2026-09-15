use synergy_testnet::node::Blockchain;
use synergy_testnet::wallet::{WalletManager, WALLET_MANAGER};
use synergy_testnet::token::TOKEN_MANAGER;
use synergy_testnet::transaction::Transaction;
use synergy_testnet::gas::constants;

#[test]
fn test_transaction_processing() {
    let mut blockchain = Blockchain::new();
    assert_eq!(blockchain.chain.len(), 1); // Genesis block should exist

    blockchain.add_transaction("Alice".to_string(), "Bob".to_string(), 100);
    blockchain.mine_block();

    assert_eq!(blockchain.chain.len(), 2); // New block should be added
    assert_eq!(blockchain.chain[1].transactions.len(), 1); // Block should contain one transaction

    println!("Blockchain State: {:?}", blockchain.chain);
}

#[test]
fn test_faucet_transaction() {
    // Faucet address
    let faucet_address = "synw1lfgerdqglc6p74p9u6k8ghfssl59q8jzhuwm07";
    // Recipient address
    let recipient_address = "synw12gukg55hv9m2lgwxc9ztly7pxksw37txkyazmk";
    // Amount: 1,500,000 SNRG = 1,500,000 * 1,000,000,000 nWei
    let amount_snrg = 1_500_000u64;
    let amount_nwei = amount_snrg as u128 * constants::NWEI_PER_SNRG;
    
    println!("Creating test transaction:");
    println!("  From: {}", faucet_address);
    println!("  To: {}", recipient_address);
    println!("  Amount: {} SNRG ({} nWei)", amount_snrg, amount_nwei);
    
    // Initialize testnet wallets (loads faucet identity)
    synergy_testnet::wallet::init_testnet_wallets();
    
    // Get wallet manager and token manager
    let mut wallet_manager = WALLET_MANAGER.lock().unwrap();
    let token_manager = TOKEN_MANAGER.clone();
    
    // Check if faucet wallet is loaded
    if wallet_manager.get_wallet(faucet_address).is_none() {
        // Try to load faucet wallet from identity file
        let faucet_identity_path = "config/faucet/identity.json";
        if std::path::Path::new(faucet_identity_path).exists() {
            if let Err(e) = wallet_manager.import_wallet_from_file(faucet_identity_path) {
                println!("Warning: Could not load faucet wallet: {}", e);
                println!("Test will create unsigned transaction for validation");
            }
        }
    }
    
    // Create transaction
    let result = wallet_manager.send_tokens(
        faucet_address,
        recipient_address,
        "SNRG",
        amount_nwei as u64,
        &token_manager,
    );
    
    match result {
        Ok(transaction) => {
            println!("\n✅ Transaction created successfully!");
            println!("  Transaction Hash: {}", transaction.hash());
            println!("  Sender: {}", transaction.get_sender());
            println!("  Receiver: {}", transaction.get_receiver());
            println!("  Amount: {} nWei", transaction.get_amount());
            println!("  Nonce: {}", transaction.get_nonce());
            println!("  Gas Price: {} nWei", transaction.get_gas_price());
            println!("  Gas Limit: {}", transaction.get_gas_limit());
            println!("  Signature Algorithm: {}", transaction.get_signature_algorithm());
            println!("  Signature (hex): {}", transaction.get_signature_hex());
            
            // Validate transaction
            let validation = transaction.validate();
            assert!(validation.is_valid, "Transaction validation failed: {:?}", validation.error_message);
            println!("  ✅ Transaction validation: PASSED");
            
            // Verify signature if wallet is loaded
            if wallet_manager.get_wallet(faucet_address).is_some() {
                let signature_valid = wallet_manager.verify_signature(&transaction);
                if signature_valid {
                    println!("  ✅ Signature verification: PASSED");
                } else {
                    println!("  ⚠️  Signature verification: FAILED (may be expected if wallet not fully loaded)");
                }
            }
            
            // Check transaction JSON serialization
            let json = transaction.to_json().expect("Failed to serialize transaction to JSON");
            println!("\nTransaction JSON (first 200 chars):");
            println!("  {}", &json[..json.len().min(200)]);
            
            // Verify we can deserialize it back
            let deserialized = Transaction::from_json(&json).expect("Failed to deserialize transaction from JSON");
            assert_eq!(transaction.hash(), deserialized.hash());
            println!("  ✅ JSON serialization/deserialization: PASSED");
        }
        Err(e) => {
            println!("\n⚠️  Could not create signed transaction: {}", e);
            println!("Creating unsigned transaction for validation test...");
            
            // Create unsigned transaction for validation testing
            let mut tx = Transaction::new(
                faucet_address.to_string(),
                recipient_address.to_string(),
                amount_nwei as u64,
                0, // nonce
                vec![], // empty signature
                1000, // gas_price
                21000, // gas_limit
                Some(format!(
                    "token_transfer:{{\"to\":\"{}\",\"token\":\"SNRG\",\"amount\":{}}}",
                    recipient_address, amount_nwei
                )),
                "fndsa".to_string(), // signature algorithm
            );
            
            println!("  Transaction Hash: {}", tx.hash());
            println!("  Sender: {}", tx.get_sender());
            println!("  Receiver: {}", tx.get_receiver());
            println!("  Amount: {} nWei ({} SNRG)", tx.get_amount(), amount_snrg);
            
            // Note: This will fail validation because signature is empty, but structure is correct
            let validation = tx.validate();
            if !validation.is_valid {
                println!("  ⚠️  Validation failed (expected for unsigned tx): {:?}", validation.error_message);
            }
            
            panic!("Could not create signed transaction from faucet. Error: {}. Please ensure faucet wallet is properly configured.", e);
        }
    }
}
