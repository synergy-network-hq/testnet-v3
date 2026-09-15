use synergy_testnet::node::Blockchain;

#[test]
fn test_block_creation() {
    let mut blockchain = Blockchain::new();
    assert_eq!(blockchain.chain.len(), 1); // Genesis block should exist

    blockchain.add_transaction("Alice".to_string(), "Bob".to_string(), 100);
    blockchain.mine_block();

    assert_eq!(blockchain.chain.len(), 2); // New block should be added
    assert_eq!(blockchain.chain[1].transactions.len(), 1); // Block should contain one transaction

    println!("Blockchain State: {:?}", blockchain.chain);
}
