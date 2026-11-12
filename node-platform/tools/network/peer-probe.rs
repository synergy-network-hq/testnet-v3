use std::{
    env,
    net::{TcpStream, ToSocketAddrs},
    time::Duration,
};
fn main() {
    let endpoint = env::args().nth(1).expect("endpoint required");
    let address = endpoint
        .to_socket_addrs()
        .expect("resolve")
        .next()
        .expect("address");
    TcpStream::connect_timeout(&address, Duration::from_secs(3))
        .expect("authenticated transport endpoint unreachable");
    println!("{address} reachable");
}
