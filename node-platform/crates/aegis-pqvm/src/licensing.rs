//! Aegis PQVM License Validation
//!
//! Enforces the 4-tier licensing model (Starter / Pro / Business / Enterprise)
//! for the `aegis-pqvm` native Rust library via a cryptographically authenticated
//! token. The license is installed once per process (or per-test) by calling
//! [`install_license`] before invoking any cryptographic or ABI-dispatch operations.
//!
//! ## License Key Format
//!
//! ```text
//! AEGIS-V-<BASE32(PAYLOAD || MAC)>
//!
//! PAYLOAD (13 bytes):
//!   [0]      tier     : u8   (0=Starter, 1=Pro, 2=Business, 3=Enterprise)
//!   [1..=4]  expiry   : u32 big-endian Unix timestamp (0 = never expires)
//!   [5..=8]  ops      : u32 big-endian per-session op limit (0 = tier default)
//!   [9..=12] nonce    : u32 big-endian random nonce (anti-replay)
//!
//! MAC (16 bytes):
//!   BLAKE3(AEGIS_LICENSE_SECRET || b"pqvm" || PAYLOAD)[0..16]
//! ```
//!
//! Keys are generated with the `generate_license` binary in this crate.
//! The module tag `"pqvm"` is distinct from `"pqwasm"` so keys are not
//! cross-compatible between modules.

use blake3::Hasher;
use std::cell::RefCell;

use crate::licensing_secret;

static MODULE_TAG: &[u8] = b"pqvm";

// ─── Tier ────────────────────────────────────────────────────────────────────

/// The four Aegis pqvm subscription tiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum Tier {
    /// Starter — evaluation / non-commercial. EVM only, limited algorithms and ops.
    Starter = 0,
    /// Pro — commercial production. EVM + Substrate, full ML-KEM/ML-DSA, FN-DSA-512.
    Pro = 1,
    /// Business — all VM platforms, complete algorithm suite, high op limit.
    Business = 2,
    /// Enterprise — all platforms, unlimited ops, dedicated support.
    Enterprise = 3,
}

impl Tier {
    fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Tier::Starter),
            1 => Some(Tier::Pro),
            2 => Some(Tier::Business),
            3 => Some(Tier::Enterprise),
            _ => None,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Tier::Starter => "Starter",
            Tier::Pro => "Pro",
            Tier::Business => "Business",
            Tier::Enterprise => "Enterprise",
        }
    }

    /// Default per-session operation limit for this tier.
    fn default_ops_limit(&self) -> u64 {
        match self {
            Tier::Starter => 1_000,
            Tier::Pro => 100_000,
            Tier::Business => 1_000_000,
            Tier::Enterprise => 0, // unlimited
        }
    }
}

// ─── VM platform access ──────────────────────────────────────────────────────

/// VM integration platforms supported by Aegis pqvm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmPlatform {
    Evm,
    Substrate,
    CosmWasm,
    Solana,
    Move,
    /// Native Synergy chain host / precompile integration.
    Synergy,
}

/// Returns whether the given tier permits use of the given VM platform.
pub fn tier_allows_platform(tier: Tier, platform: VmPlatform) -> bool {
    match platform {
        VmPlatform::Evm => true, // all tiers
        VmPlatform::Substrate => tier >= Tier::Pro,
        VmPlatform::CosmWasm => tier >= Tier::Business,
        VmPlatform::Solana => tier >= Tier::Business,
        VmPlatform::Move => tier >= Tier::Business,
        VmPlatform::Synergy => tier >= Tier::Pro,
    }
}

// ─── Algorithm access ────────────────────────────────────────────────────────

/// Algorithm variants as used in the ABI and public API.
/// Names are matched case-insensitively.
pub fn tier_allows_algorithm(tier: Tier, alg: &str) -> bool {
    let a = alg.to_lowercase();

    // FN-DSA-1024 — Business and above
    if a.contains("fndsa1024")
        || a.contains("fndsa-1024")
        || a.contains("fn-dsa-1024")
        || a.contains("fn_dsa_1024")
    {
        return tier >= Tier::Business;
    }

    // FN-DSA-512 — Pro and above
    if a.contains("fndsa") || a.contains("fn-dsa") || a.contains("fn_dsa") {
        return tier >= Tier::Pro;
    }

    // ML-DSA-87 — Pro and above
    if a.contains("mldsa87")
        || a.contains("mldsa-87")
        || a.contains("ml-dsa-87")
        || a.contains("ml_dsa_87")
    {
        return tier >= Tier::Pro;
    }

    // ML-DSA-44, ML-DSA-65 — Pro and above (all ML-DSA is Pro+)
    if a.contains("mldsa") || a.contains("ml-dsa") || a.contains("ml_dsa") {
        return tier >= Tier::Pro;
    }

    // ML-KEM-1024 — Pro and above
    if a.contains("mlkem1024")
        || a.contains("mlkem-1024")
        || a.contains("ml-kem-1024")
        || a.contains("ml_kem_1024")
    {
        return tier >= Tier::Pro;
    }

    // SLH-DSA — Business and above (ABI exposure pending)
    if a.contains("slh") || a.contains("slh-dsa") || a.contains("sphincs") {
        return tier >= Tier::Business;
    }

    // HQC — Business and above (ABI exposure pending)
    if a.contains("hqc") {
        return tier >= Tier::Business;
    }

    // ML-KEM-512, ML-KEM-768 — all tiers
    if a.contains("mlkem") || a.contains("ml-kem") || a.contains("ml_kem") {
        return true;
    }

    // Lifecycle manager — Pro and above
    if a.contains("lifecycle") {
        return tier >= Tier::Pro;
    }

    // Quantum beacon — Business and above
    if a.contains("beacon") {
        return tier >= Tier::Business;
    }

    // Anything else (hash utils, self-test) — allow
    true
}

// ─── ABI Alg byte mapping ─────────────────────────────────────────────────────

/// Map an AEG1 `Alg` byte to a canonical algorithm name string for tier checking.
/// Mirrors the `Alg` enum in `integrations::abi`.
pub fn alg_byte_name(alg_byte: u8) -> &'static str {
    match alg_byte {
        1 => "mlkem512",
        2 => "mlkem768",
        3 => "mlkem1024",
        10 => "mldsa44",
        11 => "mldsa65",
        12 => "mldsa87",
        20 => "fndsa512",
        21 => "fndsa1024",
        _ => "unknown",
    }
}

// ─── Parsed license ───────────────────────────────────────────────────────────

/// A validated Aegis pqvm license.
#[derive(Debug, Clone)]
pub struct License {
    pub tier: Tier,
    /// Unix timestamp expiry (0 = never).
    pub expiry: u32,
    /// Per-session op limit override (0 = use tier default).
    pub ops_limit: u32,
}

impl License {
    /// Effective per-session operation limit.
    pub fn effective_ops_limit(&self) -> u64 {
        if self.ops_limit == 0 {
            self.tier.default_ops_limit()
        } else {
            u64::from(self.ops_limit)
        }
    }

    pub fn is_unlimited(&self) -> bool {
        self.effective_ops_limit() == 0
    }
}

// ─── Encoding ─────────────────────────────────────────────────────────────────

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
    String::from_utf8(out).expect("base32 output is always ASCII")
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

// ─── MAC ──────────────────────────────────────────────────────────────────────

fn compute_mac(payload: &[u8; 13]) -> [u8; 16] {
    let mut h = Hasher::new_keyed(licensing_secret::license_secret());
    h.update(MODULE_TAG);
    h.update(payload);
    let full = h.finalize();
    let mut mac = [0u8; 16];
    mac.copy_from_slice(&full.as_bytes()[..16]);
    mac
}

// ─── Validation ───────────────────────────────────────────────────────────────

/// Parse and cryptographically validate a pqvm license key.
///
/// Returns `Ok(License)` or a human-readable `Err` string.
pub fn validate_license(key: &str) -> Result<License, String> {
    let key = key.trim();

    let encoded = key
        .strip_prefix("AEGIS-V-")
        .ok_or_else(|| "Invalid pqvm license key: must start with AEGIS-V-".to_string())?;

    let raw = base32_decode(encoded)
        .ok_or_else(|| "Invalid license key: base32 decode failed".to_string())?;

    if raw.len() != 29 {
        return Err(format!(
            "Invalid license key: expected 29 bytes, got {}",
            raw.len()
        ));
    }

    let mut payload = [0u8; 13];
    payload.copy_from_slice(&raw[..13]);
    let mut stored_mac = [0u8; 16];
    stored_mac.copy_from_slice(&raw[13..]);

    let expected_mac = compute_mac(&payload);
    if expected_mac != stored_mac {
        return Err("Invalid license key: authentication failed".to_string());
    }

    let tier = Tier::from_u8(payload[0])
        .ok_or_else(|| format!("Invalid license key: unknown tier byte {}", payload[0]))?;

    let expiry = u32::from_be_bytes(payload[1..5].try_into().unwrap());
    let ops = u32::from_be_bytes(payload[5..9].try_into().unwrap());

    Ok(License {
        tier,
        expiry,
        ops_limit: ops,
    })
}

// ─── Runtime state ────────────────────────────────────────────────────────────

thread_local! {
    static ACTIVE_LICENSE: RefCell<Option<License>> = const { RefCell::new(None) };
    static OP_COUNTER: RefCell<u64> = const { RefCell::new(0) };
}

/// Install a validated license as the active license for this thread/session.
pub fn install_license(license: License) {
    ACTIVE_LICENSE.with(|l| *l.borrow_mut() = Some(license));
    OP_COUNTER.with(|c| *c.borrow_mut() = 0);
}

/// Validate a license key string and install it if valid.
///
/// Convenience wrapper over [`validate_license`] + [`install_license`].
pub fn init(key: &str) -> Result<(), String> {
    let license = validate_license(key)?;
    install_license(license);
    Ok(())
}

/// Check whether an algorithm is permitted and the op limit has not been reached.
///
/// Returns `Ok(())` on success. Increments the op counter on success.
/// Returns `Err(msg)` with a human-readable message on any failure.
pub fn check_algorithm(alg: &str) -> Result<(), String> {
    ACTIVE_LICENSE.with(|cell| {
        let borrow = cell.borrow();
        let license = borrow.as_ref().ok_or_else(|| {
            "Aegis pqvm: no license installed. Call aegis_pqvm::licensing::init(key) \
             before using the library."
                .to_string()
        })?;

        if !tier_allows_algorithm(license.tier, alg) {
            return Err(format!(
                "Aegis pqvm: algorithm '{}' is not available on the {} tier. \
                 Upgrade your license to access this algorithm.",
                alg,
                license.tier.name()
            ));
        }

        let limit = license.effective_ops_limit();
        if limit != 0 {
            let count = OP_COUNTER.with(|c| *c.borrow());
            if count >= limit {
                return Err(format!(
                    "Aegis pqvm: operation limit ({}) reached for the {} tier. \
                     Upgrade your license or restart the process.",
                    limit,
                    license.tier.name()
                ));
            }
        }

        Ok(())
    })?;

    // Increment counter after passing all checks.
    OP_COUNTER.with(|c| {
        let mut counter = c.borrow_mut();
        *counter = counter.saturating_add(1);
    });

    Ok(())
}

/// Check whether a VM platform is permitted by the active license.
///
/// This does NOT increment the op counter — platform checks are free.
pub fn check_platform(platform: VmPlatform) -> Result<(), String> {
    ACTIVE_LICENSE.with(|cell| {
        let borrow = cell.borrow();
        let license = borrow.as_ref().ok_or_else(|| {
            "Aegis pqvm: no license installed. Call aegis_pqvm::licensing::init(key) \
             before using the library."
                .to_string()
        })?;

        if !tier_allows_platform(license.tier, platform) {
            return Err(format!(
                "Aegis pqvm: VM platform '{:?}' is not available on the {} tier. \
                 Upgrade to Business or Enterprise to unlock all VM integrations.",
                platform,
                license.tier.name()
            ));
        }

        Ok(())
    })
}

/// Install a development-license token for integration tests.
///
/// Uses the same MAC secret resolution path as runtime validation.
/// Do not use in production deployments.
#[doc(hidden)]
pub fn install_dev_test_license(tier: Tier) {
    let mut payload = [0u8; 13];
    payload[0] = tier as u8;
    payload[1..5].copy_from_slice(&0u32.to_be_bytes());
    payload[5..9].copy_from_slice(&0u32.to_be_bytes());
    payload[9..13].copy_from_slice(&0x5359_4E31u32.to_be_bytes()); // "SYN1" nonce tag
    let mac = compute_mac(&payload);
    let mut raw = Vec::with_capacity(29);
    raw.extend_from_slice(&payload);
    raw.extend_from_slice(&mac);
    let key = format!("AEGIS-V-{}", base32_encode(&raw));
    install_license(validate_license(&key).expect("dev test license"));
}

/// Returns a summary of the active license for diagnostics / logging.
pub fn license_summary() -> String {
    ACTIVE_LICENSE.with(|cell| {
        let borrow = cell.borrow();
        match borrow.as_ref() {
            None => "aegis-pqvm: no license installed".to_string(),
            Some(lic) => {
                let ops_used = OP_COUNTER.with(|c| *c.borrow());
                let ops_limit = lic.effective_ops_limit();
                let ops_remaining = if ops_limit == 0 {
                    "unlimited".to_string()
                } else {
                    format!("{}", ops_limit.saturating_sub(ops_used))
                };
                format!(
                    "aegis-pqvm | tier={} | expiry={} | ops_used={} | ops_remaining={}",
                    lic.tier.name(),
                    if lic.expiry == 0 {
                        "never".to_string()
                    } else {
                        lic.expiry.to_string()
                    },
                    ops_used,
                    ops_remaining,
                )
            }
        }
    })
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_key(tier: Tier, expiry: u32, ops: u32, nonce: u32) -> String {
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

    #[test]
    fn roundtrip_all_tiers() {
        for (code, name) in [
            (0u8, "Starter"),
            (1, "Pro"),
            (2, "Business"),
            (3, "Enterprise"),
        ] {
            let tier = Tier::from_u8(code).unwrap();
            let key = make_key(tier, 0, 0, code as u32 * 0x1000);
            let lic = validate_license(&key).expect("valid key");
            assert_eq!(lic.tier.name(), name);
        }
    }

    #[test]
    fn tampered_key_rejected() {
        let key = make_key(Tier::Starter, 0, 0, 42);
        let mut bytes = key.into_bytes();
        if let Some(b) = bytes.get_mut(10) {
            *b ^= 0x04;
        }
        let bad = String::from_utf8(bytes).unwrap();
        assert!(validate_license(&bad).is_err());
    }

    #[test]
    fn wrong_module_prefix_rejected() {
        let key = make_key(Tier::Pro, 0, 0, 1);
        // Swap V for W (pqwasm prefix)
        let bad = key.replace("AEGIS-V-", "AEGIS-W-");
        assert!(validate_license(&bad).is_err());
    }

    #[test]
    fn algorithm_access_starter() {
        assert!(tier_allows_algorithm(Tier::Starter, "mlkem512"));
        assert!(tier_allows_algorithm(Tier::Starter, "mlkem768"));
        assert!(!tier_allows_algorithm(Tier::Starter, "mlkem1024"));
        assert!(!tier_allows_algorithm(Tier::Starter, "mldsa44"));
        assert!(!tier_allows_algorithm(Tier::Starter, "fndsa512"));
    }

    #[test]
    fn algorithm_access_pro() {
        assert!(tier_allows_algorithm(Tier::Pro, "mlkem1024"));
        assert!(tier_allows_algorithm(Tier::Pro, "mldsa87"));
        assert!(tier_allows_algorithm(Tier::Pro, "fndsa512"));
        assert!(!tier_allows_algorithm(Tier::Pro, "fndsa1024"));
    }

    #[test]
    fn algorithm_access_business() {
        assert!(tier_allows_algorithm(Tier::Business, "fndsa1024"));
    }

    #[test]
    fn platform_access() {
        assert!(tier_allows_platform(Tier::Starter, VmPlatform::Evm));
        assert!(!tier_allows_platform(Tier::Starter, VmPlatform::Substrate));
        assert!(tier_allows_platform(Tier::Pro, VmPlatform::Substrate));
        assert!(!tier_allows_platform(Tier::Pro, VmPlatform::CosmWasm));
        assert!(tier_allows_platform(Tier::Business, VmPlatform::CosmWasm));
        assert!(tier_allows_platform(Tier::Business, VmPlatform::Solana));
        assert!(tier_allows_platform(Tier::Business, VmPlatform::Move));
        assert!(tier_allows_platform(Tier::Enterprise, VmPlatform::Move));
        assert!(!tier_allows_platform(Tier::Starter, VmPlatform::Synergy));
        assert!(tier_allows_platform(Tier::Pro, VmPlatform::Synergy));
        assert!(tier_allows_platform(Tier::Business, VmPlatform::Synergy));
    }

    #[test]
    fn op_limit_enforced() {
        // Install a Starter license with a tiny custom op limit of 2.
        let key = make_key(Tier::Starter, 0, 2, 99);
        let lic = validate_license(&key).unwrap();
        install_license(lic);

        assert!(check_algorithm("mlkem512").is_ok()); // op 1
        assert!(check_algorithm("mlkem512").is_ok()); // op 2
        assert!(check_algorithm("mlkem512").is_err()); // op 3 — limit hit
    }
}
