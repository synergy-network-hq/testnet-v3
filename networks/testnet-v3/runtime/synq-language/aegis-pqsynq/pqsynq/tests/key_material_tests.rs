#![cfg(feature = "full")]

use pqsynq::utils::{constant_time_eq, random_bytes, zeroize_bytes};
use pqsynq::SecretBytes;

#[test]
fn test_zeroize_bytes_clears_data() {
    let mut secret = vec![0xAA; 64];
    zeroize_bytes(&mut secret);
    assert!(secret.iter().all(|b| *b == 0));
}

#[test]
fn test_secret_bytes_wrapper_accessors() {
    let raw = vec![1u8, 2, 3, 4, 5];
    let mut secret = SecretBytes::new(raw.clone());

    assert_eq!(secret.len(), raw.len());
    assert!(!secret.is_empty());
    assert_eq!(secret.as_slice(), raw.as_slice());

    secret.as_mut_slice()[0] ^= 0xFF;
    assert_ne!(secret.as_slice(), raw.as_slice());

    let moved = secret.into_vec();
    assert_eq!(moved.len(), raw.len());
}

#[test]
fn test_random_bytes_size_and_non_triviality() {
    let sample = random_bytes(64).expect("random_bytes should succeed under std/full profile");
    assert_eq!(sample.len(), 64);

    // Not a proof of randomness, just a basic sanity check against all-zero output.
    assert!(!constant_time_eq(&sample, &[0u8; 64]));
}
