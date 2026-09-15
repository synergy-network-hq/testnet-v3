use crate::traits::SelfTest;
use crate::utils::{
    constant_time_eq, ensure_key_length, secure_random_bytes, sha3_digest, zeroize,
};
use alloc::vec::Vec;

/// Basic hardened primitives shared by multiple algorithms.
pub struct SecurityPrimitives;

impl SecurityPrimitives {
    pub fn constant_time_compare(a: &[u8], b: &[u8]) -> bool {
        constant_time_eq(a, b)
    }

    pub fn zeroize_secret(buf: &mut [u8]) {
        zeroize(buf);
    }

    pub fn secure_random(len: usize) -> Result<Vec<u8>, getrandom::Error> {
        secure_random_bytes(len)
    }

    pub fn validate_key_material(buf: &[u8], expected_len: usize) -> bool {
        ensure_key_length(buf, expected_len).is_ok()
    }
}

impl SelfTest for SecurityPrimitives {
    fn run_self_tests() -> Result<(), &'static str> {
        let sample = secure_random_bytes(32).map_err(|_| "secure random self-test failed")?;
        let digest = sha3_digest(&sample);

        if digest.iter().all(|b| *b == 0) {
            return Err("digest self-test failed");
        }

        let mut clone = sample.clone();
        SecurityPrimitives::zeroize_secret(&mut clone);
        if clone.iter().any(|b| *b != 0) {
            return Err("zeroization self-test failed");
        }

        if !SecurityPrimitives::constant_time_compare(&sample, &sample) {
            return Err("constant-time comparison failed");
        }

        Ok(())
    }
}
