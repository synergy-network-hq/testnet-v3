//! Link regression: another library owns the unprefixed compatibility names.
//! This models libsodium/Stronghold without replacing either entropy backend.
use std::sync::atomic::{AtomicUsize, Ordering};

static FOREIGN_CALLS: AtomicUsize = AtomicUsize::new(0);

#[no_mangle]
unsafe extern "C" fn randombytes(_buf: *mut u8, _len: libc::c_ulonglong) {
    FOREIGN_CALLS.fetch_add(1, Ordering::SeqCst);
}
#[no_mangle]
unsafe extern "C" fn randombytes_init() {
    FOREIGN_CALLS.fetch_add(1, Ordering::SeqCst);
}

extern "C" {
    #[link_name = "SYNERGY_CORE_NIST_randombytes"]
    fn core_randombytes(buf: *mut u8, len: libc::c_ulonglong) -> libc::c_int;
    #[link_name = "SYNERGY_CORE_NIST_randombytes_init"]
    fn core_randombytes_init(entropy: *mut u8, personalization: *mut u8, strength: libc::c_int);
}

#[test]
fn namespaced_nist_rng_links_without_stealing_foreign_rng_symbols() {
    let mut first = [0u8; 64];
    let mut second = [0u8; 64];
    // Force the Rust owner into the link as well as exercising the actual C ABI.
    unsafe {
        assert_eq!(
            aegis_pqvm::utils::nist_randombytes(first.as_mut_ptr(), 64),
            0
        );
        assert_eq!(core_randombytes(second.as_mut_ptr(), 64), 0);
        core_randombytes_init(std::ptr::null_mut(), std::ptr::null_mut(), 256);
    }
    assert_ne!(first, [0; 64]);
    assert_ne!(second, [0; 64]);
    assert_ne!(first, second);
    assert_eq!(FOREIGN_CALLS.load(Ordering::SeqCst), 0);
    unsafe {
        randombytes(std::ptr::null_mut(), 0);
        randombytes_init();
    }
    assert_eq!(FOREIGN_CALLS.load(Ordering::SeqCst), 2);
}

#[test]
fn os_rng_and_compatibility_initialization_preserve_production_entropy() {
    assert!(aegis_pqvm::utils::secure_random_bytes(0)
        .unwrap()
        .is_empty());
    let before = aegis_pqvm::utils::secure_random_bytes(64).unwrap();
    let mut entropy = [7u8; 48];
    let mut personalization = [9u8; 48];
    unsafe {
        aegis_pqvm::utils::nist_randombytes_init(
            entropy.as_mut_ptr(),
            personalization.as_mut_ptr(),
            256,
        );
    }
    assert_eq!(entropy, [7; 48]);
    assert_eq!(personalization, [9; 48]);
    let after = aegis_pqvm::utils::secure_random_bytes(64).unwrap();
    assert_ne!(before, after);
}
