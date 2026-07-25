pub const TESTNET_EPOCH_LENGTH_BLOCKS: u64 = 1_000;

/// Return the canonical one-based block epoch.
///
/// Height zero is the genesis/pre-block state. Blocks 1 through `epoch_length`
/// are epoch zero; the next `epoch_length` blocks are epoch one, and so on.
pub fn epoch_for_block_height(block_height: u64, epoch_length: u64) -> u64 {
    block_height.saturating_sub(1) / epoch_length.max(1)
}

pub fn epoch_start_height(epoch: u64, epoch_length: u64) -> u64 {
    epoch.saturating_mul(epoch_length.max(1)).saturating_add(1)
}

pub fn epoch_end_height(epoch: u64, epoch_length: u64) -> u64 {
    epoch.saturating_add(1).saturating_mul(epoch_length.max(1))
}

pub fn block_position_in_epoch(block_height: u64, epoch_length: u64) -> u64 {
    if block_height == 0 {
        return 0;
    }
    block_height.saturating_sub(1) % epoch_length.max(1) + 1
}

pub fn is_epoch_start_height(block_height: u64, epoch_length: u64) -> bool {
    block_height > 0 && block_position_in_epoch(block_height, epoch_length) == 1
}

pub fn is_epoch_end_height(block_height: u64, epoch_length: u64) -> bool {
    block_height > 0 && block_position_in_epoch(block_height, epoch_length) == epoch_length.max(1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_epoch_boundaries_are_one_based() {
        assert_eq!(epoch_for_block_height(0, 1_000), 0);
        assert_eq!(epoch_for_block_height(1, 1_000), 0);
        assert_eq!(epoch_for_block_height(1_000, 1_000), 0);
        assert_eq!(epoch_for_block_height(1_001, 1_000), 1);
        assert_eq!(epoch_for_block_height(2_000, 1_000), 1);
        assert_eq!(epoch_for_block_height(2_001, 1_000), 2);
    }

    #[test]
    fn canonical_epoch_ranges_are_contiguous() {
        assert_eq!(epoch_start_height(0, 1_000), 1);
        assert_eq!(epoch_end_height(0, 1_000), 1_000);
        assert_eq!(epoch_start_height(1, 1_000), 1_001);
        assert_eq!(epoch_end_height(1, 1_000), 2_000);
    }

    #[test]
    fn canonical_positions_and_boundaries_are_one_based() {
        assert_eq!(block_position_in_epoch(0, 1_000), 0);
        assert_eq!(block_position_in_epoch(1, 1_000), 1);
        assert_eq!(block_position_in_epoch(1_000, 1_000), 1_000);
        assert_eq!(block_position_in_epoch(1_001, 1_000), 1);
        assert!(is_epoch_start_height(1, 1_000));
        assert!(is_epoch_end_height(1_000, 1_000));
        assert!(is_epoch_start_height(1_001, 1_000));
        assert!(is_epoch_end_height(2_000, 1_000));
        assert!(!is_epoch_start_height(0, 1_000));
        assert!(!is_epoch_end_height(0, 1_000));
    }
}
