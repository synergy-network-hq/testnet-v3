use crate::cluster::SimCluster;
pub fn assert_monotonic_finality(before: u64, after: &SimCluster) -> Result<(), String> {
    if after.finalized_height < before {
        Err("finality regressed".into())
    } else {
        Ok(())
    }
}
