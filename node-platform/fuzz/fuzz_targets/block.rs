#![no_main]
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data: &[u8]| {
    if data.len() > 1_048_576 { return; }
    let _ = serde_json::from_slice::<serde_json::Value>(data);
    if let Ok(text) = std::str::from_utf8(data) {
        assert!(!text.chars().any(|c| c == '\0') || text.as_bytes().contains(&0));
    }
});
