use std::env;
fn main() {
    let version = env::args().nth(1).expect("protocol version required");
    let parts = version.split('.').collect::<Vec<_>>();
    assert!(
        parts.len() >= 2 && parts.iter().all(|p| p.parse::<u16>().is_ok()),
        "invalid protocol version"
    );
    println!("protocol_version={version} shape=valid");
}
