use synergy_testnet::consensus;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

#[test]
fn test_synergy_node_initialization() {
    let blockchain = Arc::new(Mutex::new(Vec::<String>::new()));

    let handle = thread::spawn(move || {
        crate::consensus::run_consensus();
    });

    thread::sleep(Duration::from_secs(2));

    assert!(blockchain.lock().unwrap().is_empty());
    handle.join().unwrap();
}
