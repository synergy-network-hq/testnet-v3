use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;
use synergy_testnet::p2p;
use tokio;

#[tokio::test]
async fn test_p2p_networking() {
    let blockchain = Arc::new(Mutex::new(Vec::<String>::new()));

    let handle = tokio::spawn(async move {
        crate::p2p::start_p2p_network("0.0.0.0:8080").await.unwrap();
    });

    thread::sleep(Duration::from_secs(2));

    assert!(blockchain.lock().unwrap().is_empty());
    handle.await.unwrap();
}
