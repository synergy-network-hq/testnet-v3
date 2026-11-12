use std::{
    env,
    fs::OpenOptions,
    io::{Read, Seek, SeekFrom, Write},
    path::PathBuf,
};
fn main() {
    let mut a = env::args().skip(1);
    let flag = a.next().unwrap_or_default();
    let path = PathBuf::from(a.next().unwrap_or_default());
    assert_eq!(flag, "--confirm-destructive");
    assert!(
        path.to_string_lossy().contains(".test"),
        "only .test paths may be corrupted"
    );
    let mut f = OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .expect("open");
    let mut b = [0u8; 1];
    f.read_exact(&mut b).expect("read");
    b[0] ^= 0xff;
    f.seek(SeekFrom::Start(0)).unwrap();
    f.write_all(&b).expect("write");
    f.sync_all().expect("fsync");
}
