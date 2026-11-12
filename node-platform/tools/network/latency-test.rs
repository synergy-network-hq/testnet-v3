use std::{
    env,
    net::{TcpStream, ToSocketAddrs},
    time::{Duration, Instant},
};
fn main() {
    let endpoint = env::args().nth(1).expect("endpoint required");
    let address = endpoint
        .to_socket_addrs()
        .expect("resolve")
        .next()
        .expect("address");
    let start = Instant::now();
    TcpStream::connect_timeout(&address, Duration::from_secs(3)).expect("connect");
    println!("connect_latency_ms={}", start.elapsed().as_millis());
}
