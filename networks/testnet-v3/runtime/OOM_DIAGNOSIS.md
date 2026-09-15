# Testnet OOM (Out of Memory) Diagnosis

## Root Cause

The testnet is being **killed by the Linux OOM (Out Of Memory) killer** when memory usage exceeds available system memory.

### Evidence

From kernel logs (`dmesg`):
```
oom-kill:constraint=CONSTRAINT_NONE,nodemask=(null),cpuset=/,mems_allowed=0,global_oom,task_memcg=/user.slice/user-0.slice/session-1441.scope,task=synergy-testnet,pid=2982477,uid=0
Out of memory: Killed process 2982477 (synergy-testnet) total-vm:7060596kB, anon-rss:3157544kB, file-rss:2176kB, shmem-rss:0kB, UID:0 pgtables:6580kB oom_score_adj:0
```

The process was using **~3GB of RAM** when killed.

## Contributing Factors

### 1. All Blocks Stored in Memory

The blockchain implementation (`src/block.rs`) stores **all blocks in a Vec<Block>** in memory:

```rust
pub struct BlockChain {
    pub chain: Vec<Block>,  // All blocks kept in memory!
}
```

### 2. No Block Pruning

- Configuration has `enable_pruning` and `pruning_interval` fields
- **No pruning implementation exists** in the codebase
- Blocks accumulate indefinitely in memory

### 3. Chain Growth

- Current chain has **25,351+ blocks** (chain.json has 25,351 lines)
- Each block contains full transaction data
- All blocks loaded into memory at startup via `load_from_file()`

### 4. No Swap Space

System has **0B swap space**, so when RAM is exhausted, the OOM killer activates immediately.

### 5. Memory-Intensive Operations

- Full blockchain state loaded at startup
- All validator data, token balances, and transaction history in memory
- P2P network connections and message queues
- Consensus algorithm state

## Current System State

- **Total RAM**: 15GB
- **Used RAM**: 5.0GB
- **Available RAM**: 10GB
- **Swap**: 0B (none configured)
- **Chain size**: 1.1MB on disk, but much larger in memory due to deserialization overhead

## Solutions

### Immediate Fixes (Quick Wins)

#### 1. Add Swap Space
```bash
# Create 4GB swap file
sudo fallocate -l 4G /swapfile
sudo chmod 600 /swapfile
sudo mkswap /swapfile
sudo swapon /swapfile

# Make permanent
echo '/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab
```

#### 2. Set OOM Score Adjustment
Make the testnet less likely to be killed:
```bash
# Lower OOM score (less likely to be killed)
echo -1000 > /proc/$(pgrep synergy-testnet)/oom_score_adj
```

#### 3. Monitor Memory Usage
```bash
# Watch memory usage
watch -n 1 'ps aux | grep synergy-testnet | grep -v grep'
```

### Medium-Term Fixes

#### 1. Implement Block Pruning

Add pruning to limit blocks kept in memory:

```rust
// In src/block.rs
impl BlockChain {
    pub fn prune_old_blocks(&mut self, keep_last_n: usize) {
        if self.chain.len() > keep_last_n {
            let to_remove = self.chain.len() - keep_last_n;
            self.chain.drain(0..to_remove);
        }
    }
}
```

#### 2. Lazy Loading

Only load recent blocks into memory, keep older blocks on disk.

#### 3. Memory Limits

Add memory monitoring and graceful shutdown before OOM:
```rust
// Check memory usage periodically
// If approaching limit, trigger pruning or graceful shutdown
```

### Long-Term Fixes

#### 1. Use RocksDB or Similar

Replace in-memory `Vec<Block>` with a disk-backed database:
- Already mentioned in config templates (`database = "rocksdb"`)
- Not currently implemented
- Would dramatically reduce memory usage

#### 2. State Pruning

Prune old transaction data, keep only essential state:
- Keep only recent N blocks in memory
- Archive older blocks to disk
- Keep only current state (balances, validators)

#### 3. Memory-Efficient Data Structures

- Use references instead of clones where possible
- Implement block headers only in memory, full blocks on disk
- Compress old blocks

## Recommended Action Plan

### Phase 1: Immediate (Today)
1. ✅ Add swap space (4-8GB)
2. ✅ Set OOM score adjustment
3. ✅ Monitor memory usage patterns

### Phase 2: Short-term (This Week)
1. Implement basic block pruning (keep last 10,000 blocks)
2. Add memory monitoring and alerts
3. Add graceful shutdown on high memory usage

### Phase 3: Medium-term (This Month)
1. Implement RocksDB backend
2. Add lazy loading for old blocks
3. Optimize data structures

## Monitoring Commands

```bash
# Check if process is running
ps aux | grep synergy-testnet

# Check memory usage
ps aux | grep synergy-testnet | awk '{print $6/1024 " MB"}'

# Check OOM killer activity
dmesg | grep -i "oom\|killed"

# Monitor in real-time
watch -n 1 'ps aux | grep synergy-testnet | grep -v grep | awk "{print \$6/1024 \" MB\"}"'

# Check swap usage
free -h
```

## Prevention

1. **Set up monitoring** to alert before OOM
2. **Implement pruning** to prevent unbounded growth
3. **Add swap space** as a safety buffer
4. **Use disk-backed storage** for historical data
5. **Set memory limits** and graceful degradation
