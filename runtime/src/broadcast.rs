use crate::transaction::Transaction;
use crate::{crypto::pqc::PQCAlgorithm, crypto::pqc::PQCManager};
use std::io::Write;
use std::net::TcpStream;

pub fn broadcast_transaction() {
    let mut tx = Transaction::new(
        "synq1zxy8qhj4j59xp5lwkwpd5qws9aygz8pl9m3kmjx3".to_string(),
        "synq1wlt52dlk9scmzphw7uc8p72v28j47yd8g0drmtc".to_string(),
        1000,
        1,                   // nonce
        Vec::new(),          // signature (filled below)
        1,                   // gas_price
        21000,               // gas_limit
        None,                // data
        "fndsa".to_string(), // signature algorithm
    );

    let mut pqc_manager = PQCManager::new();
    let (public_key, private_key) = match pqc_manager.generate_keypair(PQCAlgorithm::FNDSA) {
        Ok(keys) => keys,
        Err(error) => {
            eprintln!("❌ Failed to create FN-DSA keypair: {}", error);
            return;
        }
    };
    if let Err(error) = tx.sign_with_public_key(&public_key, &private_key, &mut pqc_manager) {
        eprintln!("❌ Failed to sign transaction with FN-DSA: {}", error);
        return;
    }

    let tx_data = tx.to_json();

    match tx_data {
        Ok(ref json_data) => {
            println!("\n📡 Broadcasting transaction:\n{}", json_data);

            match TcpStream::connect("192.168.1.68:8545") {
                Ok(mut stream) => {
                    if let Err(e) = stream.write_all(json_data.as_bytes()) {
                        eprintln!("❌ Failed to send transaction: {}", e);
                    } else {
                        println!("✅ Transaction sent successfully");
                    }
                }
                Err(e) => {
                    eprintln!("❌ Failed to connect to node: {}", e);
                }
            }
        }
        Err(e) => {
            eprintln!("❌ Failed to serialize transaction: {}", e);
        }
    }
}
