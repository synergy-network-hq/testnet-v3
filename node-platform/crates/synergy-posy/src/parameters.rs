pub const POSY_OBJECT_SCHEMA_VERSION: u32 = 1;
pub const POSY_LEADER_LEASE_BLOCKS: u64 = 10;
// Four is the smallest committee supporting one Byzantine participant with
// the unchanged strict >2/3 validator-count AND frozen-weight quorums. An
// existing committee changes only through its authenticated epoch transition.
pub const POSY_MIN_VALIDATOR_COUNT: usize = 4;
pub const POSY_LEADER_SCHEDULE_DOMAIN: &str = "PoSy/LeaderSchedule/v3";
