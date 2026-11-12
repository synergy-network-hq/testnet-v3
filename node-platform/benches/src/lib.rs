pub fn bounded_fold(bytes: &[u8]) -> u64 {
    bytes
        .iter()
        .fold(0u64, |acc, b| acc.rotate_left(5) ^ u64::from(*b))
}
