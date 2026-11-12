#[test]
fn capability_isolation() {
    let roles = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../roles");
    let entries = std::fs::read_dir(roles).expect("role profiles must exist");
    for entry in entries {
        let path = entry.expect("role entry").path();
        if path.extension().and_then(|value| value.to_str()) != Some("toml") {
            continue;
        }
        let text = std::fs::read_to_string(&path).expect("role profile must be readable");
        assert!(
            text.contains("raw_export_forbidden = true"),
            "{}",
            path.display()
        );
        if path.file_stem().and_then(|value| value.to_str()) != Some("validator") {
            assert!(
                !text.contains("vote_consensus"),
                "{} must not receive validator authority",
                path.display()
            );
        }
    }
}
