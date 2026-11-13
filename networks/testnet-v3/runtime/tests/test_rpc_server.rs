use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::time::Duration;
use synergy_testnet::rpc::rpc_server;

#[test]
fn test_rpc_server() {
    // Check if port 8545 is already in use
    if TcpListener::bind("127.0.0.1:8545").is_ok() {
        // If the port is free, start the RPC server in a separate thread
        thread::spawn(|| {
            rpc_server::start_rpc_server("127.0.0.1:8545", false, vec![]);
        });

        // Wait a few seconds for the server to fully start
        thread::sleep(Duration::from_secs(3));
    } else {
        println!("RPC server is already running, skipping server startup in test.");
    }

    // Attempt to connect to the RPC server
    let mut stream =
        TcpStream::connect("127.0.0.1:8545").expect("Failed to connect to RPC server");

    // Send a health check request to test HTTP handling
    let request = b"GET /healthz HTTP/1.1\r\nHost: localhost\r\n\r\n";
    stream.write_all(request).expect("Failed to send request");

    // Read the response
    let mut buffer = [0; 1024];
    let bytes_read = stream.read(&mut buffer).expect("Failed to read response");

    // Ensure we got a response and check for HTTP 200 OK
    assert!(bytes_read > 0);
    assert!(String::from_utf8_lossy(&buffer).contains("200 OK"));
    assert!(String::from_utf8_lossy(&buffer).contains("ok"));

    println!("RPC server test successfully completed.");
}
