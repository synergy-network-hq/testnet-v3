pub fn deterministically_drop(sequence: u64, every: u64) -> bool {
    every > 0 && sequence.is_multiple_of(every)
}
