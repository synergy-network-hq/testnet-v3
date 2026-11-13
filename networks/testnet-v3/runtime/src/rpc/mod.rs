pub mod rpc_server;

// Temporarily disabled to avoid tokio runtime issues
// pub fn start_rpc_server() {
//     let listener =
//         TcpListener::bind("0.0.0.0:8545").expect("Failed to bind RPC server to port 8545");

//     println!("RPC server is running...");

//     for stream in listener.incoming() {
//         match stream {
//             Ok(mut stream) => {
//                 let mut buffer = [0; 1024];
//                 stream.read(&mut buffer).unwrap();
//                 println!(
//                     "Received RPC request: {:?}",
//                     String::from_utf8_lossy(&buffer)
//                 );
//                 stream
//                     .write(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")
//                     .unwrap();
//             }
//             Err(e) => {
//                 println!("Connection failed: {}", e);
//             }
//         }
//     }
// }
