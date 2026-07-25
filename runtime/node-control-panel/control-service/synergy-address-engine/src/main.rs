// ============================================================================
// Synergy Network Address Engine - Example Binary
// Demonstrates usage of the synergy-address-engine library
// ============================================================================

use synergy_address_engine::{generate_identity, AddressType};

fn main() {
    println!("Synergy Network Address Engine - FN-DSA-1024\n");

    // Generate examples
    let wallet = generate_identity(AddressType::WalletPrimary).unwrap();
    println!("Wallet: {}", wallet.address);

    let node = generate_identity(AddressType::NodeClass1).unwrap();
    println!("Node:   {}", node.address);

    let contract = generate_identity(AddressType::ContractSystem).unwrap();
    println!("Contract: {}", contract.address);

    println!("\n✅ All addresses cryptographically derived using FN-DSA-1024");
}
