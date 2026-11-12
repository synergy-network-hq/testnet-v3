use std::{env, fs};
fn main() {
    let p = env::args().nth(1).expect("WAL path required");
    let b = fs::read(p).expect("read WAL");
    assert!(b.len() <= 64 * 1024 * 1024, "WAL exceeds inspection limit");
    println!("wal_bytes={}", b.len());
}
