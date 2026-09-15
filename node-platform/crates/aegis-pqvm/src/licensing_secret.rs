//! License MAC key resolution for pqvm.
//!
//! Production deployments must set a 32-byte secret via `AEGIS_LICENSE_SECRET`
//! (environment variable at runtime, or compile-time via `option_env!`).
//! Tests and production deployments must provide the secret explicitly.

use std::sync::OnceLock;

static RESOLVED: OnceLock<[u8; 32]> = OnceLock::new();

/// Returns the 32-byte BLAKE3 keyed-hash secret for license tokens.
pub fn license_secret() -> &'static [u8; 32] {
    RESOLVED.get_or_init(resolve_license_secret)
}

fn resolve_license_secret() -> [u8; 32] {
    if let Ok(raw) = std::env::var("AEGIS_LICENSE_SECRET") {
        if let Some(secret) = parse_secret(&raw) {
            return secret;
        }
    }

    #[cfg(not(test))]
    if let Some(embedded) = option_env!("AEGIS_LICENSE_SECRET") {
        if let Some(secret) = parse_secret(embedded) {
            return secret;
        }
    }

    panic!("AEGIS_LICENSE_SECRET must be set to a 32-byte or 64-hex-byte secret");
}

fn parse_secret(raw: &str) -> Option<[u8; 32]> {
    let trimmed = raw.trim();
    if trimmed.len() == 32 {
        let mut out = [0u8; 32];
        out.copy_from_slice(trimmed.as_bytes());
        return Some(out);
    }
    if trimmed.len() == 64 && trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
        let mut out = [0u8; 32];
        for i in 0..32 {
            let hi = u8::from_str_radix(&trimmed[i * 2..i * 2 + 1], 16).ok()?;
            let lo = u8::from_str_radix(&trimmed[i * 2 + 1..i * 2 + 2], 16).ok()?;
            out[i] = (hi << 4) | lo;
        }
        return Some(out);
    }
    None
}
