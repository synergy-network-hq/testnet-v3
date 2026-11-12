use std::{env, fs, path::PathBuf};
fn main() {
    let root = PathBuf::from(env::args().nth(1).expect("database directory required"));
    assert!(root.is_dir(), "database directory missing");
    let count = fs::read_dir(root)
        .expect("read database")
        .filter_map(Result::ok)
        .filter(|e| e.file_type().map(|t| t.is_file()).unwrap_or(false))
        .count();
    assert!(count > 0, "database contains no files");
    println!("database_files={count}");
}
