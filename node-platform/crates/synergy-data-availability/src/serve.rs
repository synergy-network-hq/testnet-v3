use crate::{CustodiedShard, ShardStore};
/// Keeps a complete authenticated shard-custody response below the 1 MiB P2P frame bound.
pub const MAX_SHARD_BYTES: usize = 512 * 1024;

pub fn serve_custody(
    store: &impl ShardStore,
    object_root: &str,
    index: u32,
) -> Result<CustodiedShard, String> {
    if object_root.trim().is_empty() || object_root.len() > 256 {
        return Err("invalid object root".into());
    }
    let custody = store
        .get_custody(object_root, index)?
        .ok_or("availability shard not found")?;
    custody.shard.validate(MAX_SHARD_BYTES)?;
    custody.proof.validate()?;
    if custody.shard.object_root != object_root
        || custody.shard.index != index
        || custody.proof.object_root != object_root
        || custody.proof.shard_root != custody.shard.payload_root
        || custody.proof.shard_index != index
    {
        return Err("stored shard custody binding mismatch".into());
    }
    Ok(custody)
}
