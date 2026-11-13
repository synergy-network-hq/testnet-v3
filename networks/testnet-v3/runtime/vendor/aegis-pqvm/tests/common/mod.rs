use std::collections::HashMap;
use std::fs;
use std::path::Path;

#[derive(Debug, Clone)]
pub struct RspCase {
    pub count: usize,
    fields: HashMap<String, String>,
}

impl RspCase {
    pub fn get(&self, key: &str) -> &str {
        self.fields
            .get(key)
            .unwrap_or_else(|| panic!("missing key {key:?} in KAT case {}", self.count))
    }

    #[allow(dead_code)]
    pub fn get_usize(&self, key: &str) -> usize {
        self.get(key)
            .parse::<usize>()
            .unwrap_or_else(|e| panic!("bad usize for {key:?} in KAT case {}: {e}", self.count))
    }

    pub fn get_hex_bytes(&self, key: &str) -> Vec<u8> {
        hex_to_bytes(self.get(key))
    }
}

pub fn kat_max_cases(default: usize) -> usize {
    std::env::var("AEGIS_KAT_MAX_CASES")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(default)
}

pub fn parse_rsp(path: &Path) -> Vec<RspCase> {
    let contents = fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("failed to read KAT file {}: {e}", path.display()));

    let mut cases: Vec<RspCase> = Vec::new();
    let mut current: Option<RspCase> = None;

    for raw in contents.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let (k, v) = line
            .split_once('=')
            .unwrap_or_else(|| panic!("unexpected line in {}: {raw:?}", path.display()));
        let key = k.trim();
        let val = v.trim();

        if key == "count" {
            if let Some(prev) = current.take() {
                cases.push(prev);
            }
            current = Some(RspCase {
                count: val
                    .parse::<usize>()
                    .unwrap_or_else(|e| panic!("bad count value {val:?}: {e}")),
                fields: HashMap::new(),
            });
            continue;
        }

        let cur = current
            .as_mut()
            .unwrap_or_else(|| panic!("KAT file {} has key before count: {raw:?}", path.display()));
        cur.fields.insert(key.to_string(), val.to_string());
    }

    if let Some(last) = current.take() {
        cases.push(last);
    }

    cases
}

pub fn hex_to_bytes(s: &str) -> Vec<u8> {
    let s = s.trim();
    assert!(
        s.len() % 2 == 0,
        "hex string length must be even (got {})",
        s.len()
    );
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    for i in (0..bytes.len()).step_by(2) {
        let hi = from_hex_nibble(bytes[i]);
        let lo = from_hex_nibble(bytes[i + 1]);
        out.push((hi << 4) | lo);
    }
    out
}

fn from_hex_nibble(b: u8) -> u8 {
    match b {
        b'0'..=b'9' => b - b'0',
        b'a'..=b'f' => 10 + (b - b'a'),
        b'A'..=b'F' => 10 + (b - b'A'),
        _ => panic!("invalid hex char: {b:?}"),
    }
}
