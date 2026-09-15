//! Aegis pqvm — License Key Generator
//!
//! Generates and validates cryptographically authenticated Aegis pqvm license
//! keys for the 4-tier licensing model (Starter / Pro / Business / Enterprise).
//!
//! # Usage
//!
//! ```text
//! cargo run --bin generate_license -- [OPTIONS]
//!
//! Options:
//!   --tier <starter|pro|business|enterprise>   Tier (default: starter)
//!   --days <N>                                  Expiry in days from today (0 = never, default: 365)
//!   --ops  <N>                                  Per-session op limit override (0 = tier default)
//!   --validate <KEY>                            Validate an existing key
//! ```
//!
//! # Examples
//!
//! ```bash
//! # Generate a Pro key valid for 1 year
//! cargo run --bin generate_license -- --tier pro --days 365
//!
//! # Generate an Enterprise key that never expires
//! cargo run --bin generate_license -- --tier enterprise --days 0
//!
//! # Validate an existing key
//! cargo run --bin generate_license -- --validate "AEGIS-V-..."
//! ```

use std::time::{SystemTime, UNIX_EPOCH};

use aegis_pqvm::licensing_secret;

static MODULE_TAG: &[u8] = b"pqvm";

// ── Base32 ────────────────────────────────────────────────────────────────────
const ALPHA: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

fn base32_encode(data: &[u8]) -> String {
    let mut out = Vec::with_capacity((data.len() * 8).div_ceil(5));
    let mut buf: u64 = 0;
    let mut bits: u32 = 0;
    for &byte in data {
        buf = (buf << 8) | u64::from(byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(ALPHA[((buf >> bits) & 0x1f) as usize]);
        }
    }
    if bits > 0 {
        out.push(ALPHA[((buf << (5 - bits)) & 0x1f) as usize]);
    }
    String::from_utf8(out).unwrap()
}

fn base32_decode(s: &str) -> Option<Vec<u8>> {
    let mut buf: u64 = 0;
    let mut bits: u32 = 0;
    let mut out = Vec::new();
    for ch in s.chars() {
        let val = ALPHA
            .iter()
            .position(|&b| b == ch.to_ascii_uppercase() as u8)? as u64;
        buf = (buf << 5) | val;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(((buf >> bits) & 0xff) as u8);
        }
    }
    Some(out)
}

fn compute_mac(payload: &[u8; 13]) -> [u8; 16] {
    let mut h = blake3::Hasher::new_keyed(licensing_secret::license_secret());
    h.update(MODULE_TAG);
    h.update(payload);
    let full = h.finalize();
    let mut mac = [0u8; 16];
    mac.copy_from_slice(&full.as_bytes()[..16]);
    mac
}

// ── Tier ──────────────────────────────────────────────────────────────────────
#[derive(Debug, Clone, Copy)]
enum Tier {
    Starter = 0,
    Pro = 1,
    Business = 2,
    Enterprise = 3,
}

impl Tier {
    fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "starter" | "0" => Some(Tier::Starter),
            "pro" | "1" => Some(Tier::Pro),
            "business" | "2" => Some(Tier::Business),
            "enterprise" | "3" => Some(Tier::Enterprise),
            _ => None,
        }
    }

    fn name(self) -> &'static str {
        match self {
            Tier::Starter => "Starter",
            Tier::Pro => "Pro",
            Tier::Business => "Business",
            Tier::Enterprise => "Enterprise",
        }
    }

    fn default_ops(self) -> u64 {
        match self {
            Tier::Starter => 1_000,
            Tier::Pro => 100_000,
            Tier::Business => 1_000_000,
            Tier::Enterprise => 0,
        }
    }

    fn platforms(self) -> &'static str {
        match self {
            Tier::Starter => "EVM only",
            Tier::Pro => "EVM, Substrate, Synergy",
            Tier::Business => "EVM, Substrate, Synergy, CosmWasm, Solana, Move",
            Tier::Enterprise => "All platforms (unlimited)",
        }
    }

    fn algorithms(self) -> &'static str {
        match self {
            Tier::Starter => "ML-KEM-512/768",
            Tier::Pro => "ML-KEM-512/768/1024, ML-DSA-44/65/87, FN-DSA-512",
            Tier::Business => "ML-KEM-512/768/1024, ML-DSA-44/65/87, FN-DSA-512/1024",
            Tier::Enterprise => "All (same as Business + future additions)",
        }
    }
}

// ── Key generation ────────────────────────────────────────────────────────────
fn generate_key(tier: Tier, expiry: u32, ops: u32) -> String {
    let nonce: u32 = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_nanos();

    let mut payload = [0u8; 13];
    payload[0] = tier as u8;
    payload[1..5].copy_from_slice(&expiry.to_be_bytes());
    payload[5..9].copy_from_slice(&ops.to_be_bytes());
    payload[9..13].copy_from_slice(&nonce.to_be_bytes());

    let mac = compute_mac(&payload);
    let mut raw = Vec::with_capacity(29);
    raw.extend_from_slice(&payload);
    raw.extend_from_slice(&mac);
    format!("AEGIS-V-{}", base32_encode(&raw))
}

fn validate_key(key: &str) -> Result<(Tier, u32, u32), String> {
    let encoded = key
        .trim()
        .strip_prefix("AEGIS-V-")
        .ok_or("Not an Aegis pqvm key (must start with AEGIS-V-)")?;

    let raw = base32_decode(encoded).ok_or("Base32 decode failed")?;
    if raw.len() != 29 {
        return Err(format!("Expected 29 decoded bytes, got {}", raw.len()));
    }

    let mut payload = [0u8; 13];
    payload.copy_from_slice(&raw[..13]);
    let mut stored_mac = [0u8; 16];
    stored_mac.copy_from_slice(&raw[13..]);

    if compute_mac(&payload) != stored_mac {
        return Err("MAC verification failed — key is invalid or tampered".to_string());
    }

    let tier = match payload[0] {
        0 => Tier::Starter,
        1 => Tier::Pro,
        2 => Tier::Business,
        3 => Tier::Enterprise,
        b => return Err(format!("Unknown tier byte: {}", b)),
    };

    let expiry = u32::from_be_bytes(payload[1..5].try_into().unwrap());
    let ops = u32::from_be_bytes(payload[5..9].try_into().unwrap());
    Ok((tier, expiry, ops))
}

// ── Args ──────────────────────────────────────────────────────────────────────
fn parse_args() -> (Option<String>, Option<Tier>, u32, u32) {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut validate = None;
    let mut tier = None;
    let mut days: u32 = 365;
    let mut ops: u32 = 0;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--validate" => {
                i += 1;
                validate = args.get(i).cloned();
            }
            "--tier" => {
                i += 1;
                if let Some(t) = args.get(i) {
                    tier = Tier::from_str(t);
                    if tier.is_none() {
                        eprintln!("Unknown tier '{}'. Use: starter|pro|business|enterprise", t);
                        std::process::exit(1);
                    }
                }
            }
            "--days" => {
                i += 1;
                if let Some(d) = args.get(i) {
                    days = d.parse().unwrap_or(365);
                }
            }
            "--ops" => {
                i += 1;
                if let Some(o) = args.get(i) {
                    ops = o.parse().unwrap_or(0);
                }
            }
            "--help" | "-h" => {
                print_usage();
                std::process::exit(0);
            }
            unknown => {
                eprintln!("Unknown argument: {}", unknown);
                print_usage();
                std::process::exit(1);
            }
        }
        i += 1;
    }
    (validate, tier, days, ops)
}

fn print_usage() {
    eprintln!(
        r#"
Aegis pqvm License Key Generator
Usage: generate_license [OPTIONS]

Options:
  --tier <starter|pro|business|enterprise>   License tier (default: starter)
  --days <N>                                 Expiry in days from today (0 = never, default: 365)
  --ops  <N>                                 Per-session op limit override (0 = use tier default)
  --validate <KEY>                           Validate and decode an existing key

Tier summary:
  Starter    — EVM only, ML-KEM-512/768,           1 000 ops/session, non-commercial
  Pro        — EVM+Substrate, ML-KEM+ML-DSA+FN-DSA-512,   100 000 ops/session
  Business   — All 5 VM platforms, full algorithm suite, 1 000 000 ops/session
  Enterprise — Everything + unlimited ops, dedicated SLA

Examples:
  generate_license --tier pro --days 365
  generate_license --tier enterprise --days 0
  generate_license --validate "AEGIS-V-..."
"#
    );
}

// ── Main ──────────────────────────────────────────────────────────────────────
fn main() {
    let (validate, tier, days, ops) = parse_args();

    if let Some(key) = validate {
        match validate_key(&key) {
            Ok((t, expiry, ops_override)) => {
                let expiry_str = if expiry == 0 {
                    "never".to_string()
                } else {
                    format!("Unix {}", expiry)
                };
                let ops_display = if ops_override == 0 {
                    format!("{} (tier default)", t.default_ops())
                } else {
                    ops_override.to_string()
                };
                println!("✅ Valid Aegis pqvm license key");
                println!("   Tier        : {} ({})", t.name(), t as u8);
                println!("   Platforms   : {}", t.platforms());
                println!("   Algorithms  : {}", t.algorithms());
                println!("   Expiry      : {}", expiry_str);
                println!("   Ops/session : {}", ops_display);
                println!("   Key         : {}", key);
            }
            Err(e) => {
                eprintln!("❌ Invalid license key: {}", e);
                std::process::exit(1);
            }
        }
        return;
    }

    let tier = tier.unwrap_or(Tier::Starter);

    let expiry: u32 = if days == 0 {
        0
    } else {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock")
            .as_secs();
        let exp = now + u64::from(days) * 86_400;
        if exp > u64::from(u32::MAX) {
            u32::MAX
        } else {
            exp as u32
        }
    };

    let key = generate_key(tier, expiry, ops);
    let expiry_str = if expiry == 0 {
        "never".to_string()
    } else {
        format!("Unix {} (~{} days)", expiry, days)
    };
    let ops_display = if ops == 0 {
        format!("{} (tier default)", tier.default_ops())
    } else {
        ops.to_string()
    };

    println!("Aegis pqvm License Key");
    println!("======================");
    println!("Tier        : {} (code {})", tier.name(), tier as u8);
    println!("Platforms   : {}", tier.platforms());
    println!("Algorithms  : {}", tier.algorithms());
    println!("Expiry      : {}", expiry_str);
    println!("Ops/session : {}", ops_display);
    println!();
    println!("{}", key);
    println!();
    println!("Install in Rust:");
    println!(r#"  aegis_pqvm::licensing::init("{}")?;"#, key);
}
