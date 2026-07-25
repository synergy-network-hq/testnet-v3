# Synergy Testnet - PoSy Cluster Rotation & Consensus Testing Guide
**Testing Proof-of-Synergy Consensus with Multiple Validator Clusters**

> **Historical scenario archive:** The three-validator commands and examples later in this file predate the current testnet and must not be used as operational instructions. The "Current Testnet Configuration" section below is the canonical policy; live validation must use the Node Control Panel and current runbooks.

---

## Overview

This guide documents how to test the **Proof-of-Synergy (PoSy)** consensus algorithm with multiple validator clusters, including:

- **Cluster Formation**: Validators organized into cooperative clusters
- **Cluster Rotation**: Score-based epoch rotation after the network reaches three clusters
- **Synergy Score Calculation**: Multi-factor validator weighting
- **Dual-Quorum Consensus**: Validation + Cooperation quorums
- **Leader Selection**: Entropy beacon-driven leader rotation
- **Cartel Detection**: Statistical analysis of validator behavior
- **Inter-Cluster Communication**: Bridge relays between clusters

---

## PoSy Architecture Summary

```
┌─────────────────────────────────────────────────────────┐
│                  Global Synergy Network                 │
│                                                         │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐ │
│  │  Cluster A   │  │  Cluster B   │  │  Cluster C   │ │
│  │              │  │              │  │              │ │
│  │ V1  V2  V3   │  │ V4  V5  V6   │  │ V7  V8  V9   │ │
│  │ V10 V11 V12  │  │ V13 V14 V15  │  │ V16 V17 V18  │ │
│  │              │  │              │  │              │ │
│  │ Leader: V2   │  │ Leader: V5   │  │ Leader: V8   │ │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘ │
│         │                 │                 │         │
│         └────────┬────────┴────────┬────────┘         │
│                  │                 │                  │
│         ┌────────▼─────────────────▼────────┐         │
│         │    Inter-Cluster Bridge Relays   │         │
│         │  (Designated validators forward   │         │
│         │   messages between clusters)      │         │
│         └───────────────────────────────────┘         │
│                                                         │
│  ┌───────────────────────────────────────────────────┐ │
│  │          Synergy Oracle Smart Contract           │ │
│  │  • Aggregates metrics from all clusters          │ │
│  │  • Computes global Synergy Scores                │ │
│  │  • Stores epoch snapshots                        │ │
│  │  • Triggers cluster rotation                     │ │
│  └───────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────┘

Every Epoch (~1000 blocks / ~1 hour):
  1. Entropy Beacon generates randomness
  2. With 3+ clusters, two lowest-score validators per cluster rotate
  3. Leaders re-selected based on Synergy Scores
  4. Cartel detection runs on previous epoch
  5. Synergy Scores updated and penalties applied

Every 10th epoch with 3+ clusters:
  - All active validators are deterministically reshuffled
```

---

## Current Testnet Configuration

The canonical cluster policy is derived from the active validator set:

- 1-9 active validators: one cluster.
- 10-20 active validators: two clusters; at 10 validators these are two 5-member clusters with 3-of-5 quorum.
- 21-27 active validators: three clusters; at 21 validators these are three 7-member clusters with 5-of-7 quorum.
- 28 or more active validators: one cluster per complete group of seven (`floor(active / 7)`).
- New validators join the least-populated cluster unless a capacity expansion triggers a deterministic full rebalance.

Epochs contain exactly 1,000 one-based block heights: blocks 1-1,000 are epoch 0, 1,001-2,000 are epoch 1, and so on. Height 0 is genesis and is handled separately.

Cluster rotation is disabled while fewer than three clusters exist. At three or more clusters, the two validators with the lowest finalized Synergy scores in each cluster rotate after each epoch. Every tenth epoch performs a deterministic full reshuffle.

---

## Testing Scenarios

### Scenario 1: Single Cluster Consensus (3 Bootnodes)

**Objective**: Verify dual-quorum consensus with minimal cluster

**Setup**: Current 3-bootnode configuration

**Test Steps:**

1. **Verify Initial State**
   ```bash
   # Check cluster formation
   curl -s -X POST http://localhost:5640/rpc \
     -H "Content-Type: application/json" \
     -d '{
       "jsonrpc": "2.0",
       "method": "consensus_getClusterInfo",
       "id": 1
     }' | jq

   # Expected output:
   # {
   #   "result": {
   #     "cluster_id": "syngrp116xlcwtcuwd8cdkqrftdww5dpqvm699uanux4mc",
   #     "validator_count": 3,
   #     "leader": "synv11lylxla8qjcrk3ef8gjlyyhew3z4mjswwwsn6zv",
   #     "backup_leaders": ["synv11csyhf60yd6gp8n4wflz99km29g7fh8guxrmu04"],
   #     "quorum_threshold": 0.67
   #   }
   # }
   ```

2. **Monitor Block Proposal**
   ```bash
   # Watch block production
   watch -n 2 'curl -s -X POST http://localhost:5640/rpc \
     -H "Content-Type: application/json" \
     -d "{\"jsonrpc\":\"2.0\",\"method\":\"chain_getBlockHeight\",\"id\":1}" \
     | jq -r ".result.height"'
   ```

3. **Verify Dual-Quorum**
   ```bash
   # Check quorum status for recent block
   BLOCK_HEIGHT=$(curl -s -X POST http://localhost:5640/rpc \
     -H "Content-Type: application/json" \
     -d '{"jsonrpc":"2.0","method":"chain_getBlockHeight","id":1}' \
     | jq -r '.result.height')

   curl -s -X POST http://localhost:5640/rpc \
     -H "Content-Type: application/json" \
     -d "{
       \"jsonrpc\": \"2.0\",
       \"method\": \"consensus_getQuorumInfo\",
       \"params\": [${BLOCK_HEIGHT}],
       \"id\": 1
     }" | jq

   # Expected:
   # {
   #   "result": {
   #     "validation_quorum": {
   #       "threshold": 0.67,
   #       "achieved": 1.0,
   #       "participating_weight": "3000000"
   #     },
   #     "cooperation_quorum": {
   #       "threshold": 0.51,
   #       "achieved": 1.0,
   #       "participating_count": 3
   #     },
   #     "quorum_met": true
   #   }
   # }
   ```

4. **Test Validator Failure Tolerance**
   ```bash
   # Stop one validator (e.g., Bootnode 3)
   # Quorum should still be met with 2/3 (67%)

   # On bootnode3 server:
   sudo systemctl stop synergy-validator

   # Verify network continues producing blocks
   watch -n 2 'curl -s -X POST http://localhost:5640/rpc \
     -H "Content-Type: application/json" \
     -d "{\"jsonrpc\":\"2.0\",\"method\":\"chain_getBlockHeight\",\"id\":1}" \
     | jq'

   # Restart validator
   sudo systemctl start synergy-validator
   ```

**Expected Results:**
- ✅ Blocks produced with 3/3 validators (100% participation)
- ✅ Blocks still produced with 2/3 validators (67% quorum met)
- ❌ Block production halts with 1/3 validators (below 67% threshold)

---

### Scenario 2: Multi-Cluster Formation (10+ Validators)

**Objective**: Test dynamic cluster formation and leader selection

**Prerequisites**: At least 10 team validators onboarded ([VALIDATOR_ONBOARDING_GUIDE.md](VALIDATOR_ONBOARDING_GUIDE.md))

**Test Steps:**

1. **Verify Cluster Distribution**
   ```bash
   # List all validators and their clusters
   curl -s -X POST http://localhost:5640/rpc \
     -H "Content-Type: application/json" \
     -d '{
       "jsonrpc": "2.0",
       "method": "validator_getAll",
       "id": 1
     }' | jq -r '.result.validators[] | "\(.address) - Cluster: \(.cluster_id)"'
   ```

2. **Check Cluster Statistics**
   ```bash
   # Get cluster distribution
   curl -s -X POST http://localhost:5640/rpc \
     -H "Content-Type: application/json" \
     -d '{
       "jsonrpc": "2.0",
       "method": "consensus_getClusterStats",
       "id": 1
     }' | jq

   # Expected for 10 validators:
   # {
   #   "result": {
   #     "total_clusters": 1,
   #     "clusters": [
   #       {
   #         "cluster_id": "syngrp1...",
   #         "validator_count": 10,
   #         "total_stake": "10000000",
   #         "leader": "synv1...",
   #         "avg_synergy_score": 0.45
   #       }
   #     ]
   #   }
   # }
   ```

3. **Monitor Leader Selection**
   ```bash
   # Get current leader
   LEADER=$(curl -s -X POST http://localhost:5640/rpc \
     -H "Content-Type: application/json" \
     -d '{"jsonrpc":"2.0","method":"consensus_getCurrentLeader","id":1}' \
     | jq -r '.result.address')

   echo "Current Leader: $LEADER"

   # Get leader's Synergy Score
   curl -s -X POST http://localhost:5640/rpc \
     -H "Content-Type: application/json" \
     -d "{
       \"jsonrpc\": \"2.0\",
       \"method\": \"synergy_getScore\",
       \"params\": [\"$LEADER\"],
       \"id\": 1
     }" | jq
   ```

4. **Verify Leader Rotation Within Epoch**
   ```bash
   # Leaders rotate in round-robin within epoch
   # Monitor for 10 blocks
   for i in {1..10}; do
     LEADER=$(curl -s -X POST http://localhost:5640/rpc \
       -H "Content-Type: application/json" \
       -d '{"jsonrpc":"2.0","method":"consensus_getCurrentLeader","id":1}' \
       | jq -r '.result.address')
     echo "Block $i - Leader: ${LEADER:0:15}..."
     sleep 6  # Wait for next block
   done
   ```

**Expected Results:**
- ✅ Validators evenly distributed across clusters
- ✅ Leader selection weighted by Synergy Score
- ✅ Round-robin rotation among top-ranked validators
- ✅ Backup leaders automatically take over if leader fails

---

### Scenario 3: Epoch Boundary and Cluster Rotation

**Objective**: Test cluster reformation at epoch boundaries

**Setup**: Run for at least 1 complete epoch (~1000 blocks)

**Test Steps:**

1. **Monitor Current Epoch**
   ```bash
   # Get current epoch
   curl -s -X POST http://localhost:5640/rpc \
     -H "Content-Type: application/json" \
     -d '{
       "jsonrpc": "2.0",
       "method": "consensus_getEpoch",
       "id": 1
     }' | jq

   # Example output:
   # {
   #   "result": {
   #     "epoch_number": 5,
   #     "start_block": 4000,
   #     "end_block": 5000,
   #     "current_block": 4523,
   #     "blocks_remaining": 477
   #   }
   # }
   ```

2. **Record Pre-Rotation State**
   ```bash
   # Before epoch boundary, record validator cluster assignments
   curl -s -X POST http://localhost:5640/rpc \
     -H "Content-Type: application/json" \
     -d '{
       "jsonrpc": "2.0",
       "method": "validator_getAll",
       "id": 1
     }' | jq -r '.result.validators[] | "\(.address): \(.cluster_id)"' \
     > pre-rotation-clusters.txt
   ```

3. **Wait for Epoch Boundary**
   ```bash
   # Monitor for epoch transition
   watch -n 5 'curl -s -X POST http://localhost:5640/rpc \
     -H "Content-Type: application/json" \
     -d "{\"jsonrpc\":\"2.0\",\"method\":\"consensus_getEpoch\",\"id\":1}" \
     | jq'

   # Watch for:
   # [INFO] Epoch 5 ending at block 5000
   # [INFO] Generating entropy beacon for epoch 6
   # [INFO] Entropy: 0x1234abcd...
   # [INFO] Reforming validator clusters...
   # [INFO] Cluster 0: 10 validators
   # [INFO] Cluster leaders selected
   # [INFO] Epoch 6 started at block 5001
   ```

4. **Record Post-Rotation State**
   ```bash
   # After epoch boundary, record new cluster assignments
   curl -s -X POST http://localhost:5640/rpc \
     -H "Content-Type: application/json" \
     -d '{
       "jsonrpc": "2.0",
       "method": "validator_getAll",
       "id": 1
     }' | jq -r '.result.validators[] | "\(.address): \(.cluster_id)"' \
     > post-rotation-clusters.txt

   # Compare cluster assignments
   diff pre-rotation-clusters.txt post-rotation-clusters.txt
   ```

5. **Verify Entropy Beacon**
   ```bash
   # Get entropy beacon value for new epoch
   curl -s -X POST http://localhost:5640/rpc \
     -H "Content-Type: application/json" \
     -d '{
       "jsonrpc": "2.0",
       "method": "consensus_getEntropyBeacon",
       "params": [6],
       "id": 1
     }' | jq

   # Expected:
   # {
   #   "result": {
   #     "epoch": 6,
   #     "randomness": "0x1234567890abcdef...",
   #     "ml_kem_secret": "0xabcdef123456...",
   #     "qc_hash": "0x9876543210fedcba...",
   #     "timestamp": 1733512345,
   #     "nonce": 6
   #   }
   # }
   ```

6. **Verify the Applicable Cluster Policy**
   ```bash
   # With fewer than three clusters, cluster rotation must not occur.
   # With three or more clusters, compare assignments at the epoch boundary.

   # Count validators who changed clusters
   echo "Validators that rotated clusters:"
   diff pre-rotation-clusters.txt post-rotation-clusters.txt | grep "^<" | wc -l
   ```

**Expected Results:**
- ✅ Epoch transitions smoothly at block 1000 intervals
- ✅ Entropy beacon generates verifiable randomness
- ✅ Fewer than three clusters remain stable across the epoch boundary
- ✅ Three or more clusters rotate the two lowest finalized-score validators per cluster deterministically
- ✅ Every tenth epoch performs a deterministic full reshuffle when at least three clusters exist
- ✅ New leaders selected based on updated Synergy Scores
- ✅ No block production interruption during rotation

---

### Scenario 4: Synergy Score Calculation & Updates

**Objective**: Verify multi-factor Synergy Score computation

**Test Steps:**

1. **Get Raw Synergy Score Components**
   ```bash
   # For a specific validator
   VALIDATOR="synv11lylxla8qjcrk3ef8gjlyyhew3z4mjswwwsn6zv"  # Bootnode 1

   curl -s -X POST http://localhost:5640/rpc \
     -H "Content-Type: application/json" \
     -d "{
       \"jsonrpc\": \"2.0\",
       \"method\": \"synergy_getScoreBreakdown\",
       \"params\": [\"$VALIDATOR\"],
       \"id\": 1
     }" | jq

   # Expected output:
   # {
   #   "result": {
   #     "address": "synv11lylxla8qjcrk3ef8gjlyyhew3z4mjswwwsn6zv",
   #     "components": {
   #       "stake_weight": 0.334,        # (1M / 3M total) capped
   #       "reputation": 0.95,           # uptime × accuracy × (1 - slashing)
   #       "contribution_index": 0.82,   # proposals + relays + network
   #       "cartelization_penalty": 1.0  # No cartel detected
   #     },
   #     "raw_score": 0.260,             # S_v × R_v × C_v / P_v
   #     "normalized_score": 0.333,      # Normalized across all validators
   #     "rank": 1
   #   }
   # }
   ```

2. **Verify Stake Weight Calculation**
   ```bash
   # Stake weight formula: min(stake_v / total_stake, stake_cap)
   # With 3 validators @ 1M each, total = 3M
   # Expected: 1M / 3M = 0.333

   curl -s -X POST http://localhost:5640/rpc \
     -H "Content-Type: application/json" \
     -d "{
       \"jsonrpc\": \"2.0\",
       \"method\": \"synergy_getStakeWeight\",
       \"params\": [\"$VALIDATOR\"],
       \"id\": 1
     }" | jq
   ```

3. **Verify Reputation Calculation**
   ```bash
   # Reputation formula: uptime_factor × accuracy_factor × (1 - slashing_penalty)

   curl -s -X POST http://localhost:5640/rpc \
     -H "Content-Type: application/json" \
     -d "{
       \"jsonrpc\": \"2.0\",
       \"method\": \"synergy_getReputation\",
       \"params\": [\"$VALIDATOR\"],
       \"id\": 1
     }" | jq

   # Expected:
   # {
   #   "result": {
   #     "uptime_factor": 0.98,           # 9800/10000 blocks participated
   #     "accuracy_factor": 0.99,         # 990/1000 correct votes
   #     "slashing_penalty": 0.0,         # No slashes
   #     "reputation": 0.9702             # 0.98 × 0.99 × 1.0
   #   }
   # }
   ```

4. **Verify Contribution Index**
   ```bash
   # Contribution formula: α×proposals + β×relay_assists + γ×network_score
   # Default: α=0.5, β=0.3, γ=0.2

   curl -s -X POST http://localhost:5640/rpc \
     -H "Content-Type: application/json" \
     -d "{
       \"jsonrpc\": \"2.0\",
       \"method\": \"synergy_getContribution\",
       \"params\": [\"$VALIDATOR\"],
       \"id\": 1
     }" | jq

   # Expected:
   # {
   #   "result": {
   #     "successful_proposals": 150,
   #     "relay_assists": 75,
   #     "network_score": 0.85,          # 1 / avg_latency
   #     "contribution_index": 0.82      # 0.5×150 + 0.3×75 + 0.2×0.85
   #   }
   # }
   ```

5. **Monitor Score Updates Per Block**
   ```bash
   # Synergy Scores update every block (local) and every epoch (global)

   for i in {1..5}; do
     SCORE=$(curl -s -X POST http://localhost:5640/rpc \
       -H "Content-Type: application/json" \
       -d "{\"jsonrpc\":\"2.0\",\"method\":\"synergy_getScore\",\"params\":[\"$VALIDATOR\"],\"id\":1}" \
       | jq -r '.result.synergyScore')
     echo "$(date +%T) - Synergy Score: $SCORE"
     sleep 6
   done
   ```

**Expected Results:**
- ✅ Stake weight accurately reflects validator's stake proportion
- ✅ Reputation decreases with missed blocks and incorrect votes
- ✅ Contribution increases with successful proposals and relays
- ✅ Normalized score sums to 1.0 across all validators
- ✅ Scores update dynamically based on recent behavior

---

### Scenario 5: Cartel Detection Testing

**Objective**: Verify cartelization penalty algorithm

**Setup**: Requires at least 10 validators, 3+ coordinating

**Test Steps:**

1. **Simulate Coordinated Voting**
   ```bash
   # Three validators vote identically on every block
   # This should trigger cartel detection after ~100 blocks

   # Monitor voting patterns
   curl -s -X POST http://localhost:5640/rpc \
     -H "Content-Type: application/json" \
     -d '{
       "jsonrpc": "2.0",
       "method": "consensus_getVotingPatterns",
       "params": [{"blocks": 1000}],
       "id": 1
     }' | jq
   ```

2. **Check Correlation Analysis**
   ```bash
   # Get pairwise correlation matrix
   curl -s -X POST http://localhost:5640/rpc \
     -H "Content-Type: application/json" \
     -d '{
       "jsonrpc": "2.0",
       "method": "synergy_getCorrelationMatrix",
       "id": 1
     }' | jq

   # Expected output:
   # {
   #   "result": {
   #     "correlations": [
   #       {"validator_a": "synv1abc...", "validator_b": "synv1def...", "correlation": 0.92},
   #       {"validator_a": "synv1abc...", "validator_b": "synv1ghi...", "correlation": 0.89},
   #       ...
   #     ]
   #   }
   # }
   ```

3. **Check Timing Similarity**
   ```bash
   # Validators in cartel vote nearly simultaneously
   curl -s -X POST http://localhost:5640/rpc \
     -H "Content-Type: application/json" \
     -d '{
       "jsonrpc": "2.0",
       "method": "synergy_getTimingSimilarity",
       "id": 1
     }' | jq
   ```

4. **Verify Cartel Detection**
   ```bash
   # After 100+ blocks of coordinated behavior, cartel should be detected
   curl -s -X POST http://localhost:5640/rpc \
     -H "Content-Type: application/json" \
     -d '{
       "jsonrpc": "2.0",
       "method": "synergy_getDetectedCartels",
       "id": 1
     }' | jq

   # Expected:
   # {
   #   "result": {
   #     "cartels": [
   #       {
   #         "cartel_id": "cartel_001",
   #         "members": ["synv1abc...", "synv1def...", "synv1ghi..."],
   #         "size": 3,
   #         "avg_correlation": 0.90,
   #         "timing_similarity": 0.95,
   #         "detected_at_block": 1234,
   #         "penalty_applied": true
   #       }
   #     ]
   #   }
   # }
   ```

5. **Verify Penalty Application**
   ```bash
   # Cartel members should have reduced Synergy Scores
   # Penalty formula: P_v = 1 + ρ̄ × n × 0.1
   # For 3 validators with ρ̄ = 0.90: P_v = 1 + 0.90 × 3 × 0.1 = 1.27
   # Score reduction: ~27%

   curl -s -X POST http://localhost:5640/rpc \
     -H "Content-Type: application/json" \
     -d '{
       "jsonrpc": "2.0",
       "method": "synergy_getScoreBreakdown",
       "params": ["synv1abc..."],
       "id": 1
     }' | jq -r '.result.components.cartelization_penalty'

   # Expected: ~1.27
   ```

**Expected Results:**
- ✅ High correlation detected (ρ > 0.85) between coordinating validators
- ✅ High timing similarity detected (> 0.9)
- ✅ Cartel identified after sustained pattern (100+ blocks)
- ✅ Penalty proportional to cartel size
- ✅ Penalized validators lose leader selection probability
- ✅ Next epoch rotation separates cartel members into different clusters

---

### Scenario 6: Inter-Cluster Bridge Communication

**Objective**: Test message relay between validator clusters

**Prerequisites**: At least 2 clusters (60+ validators)

**Test Steps:**

1. **Identify Bridge Validators**
   ```bash
   # Bridge validators selected based on highest Synergy Scores
   # in overlapping cluster pairs

   curl -s -X POST http://localhost:5640/rpc \
     -H "Content-Type: application/json" \
     -d '{
       "jsonrpc": "2.0",
       "method": "consensus_getBridgeValidators",
       "id": 1
     }' | jq

   # Expected:
   # {
   #   "result": {
   #     "bridges": [
   #       {
   #         "cluster_pair": ["cluster_0", "cluster_1"],
   #         "validators": ["synv1abc...", "synv1def...", "synv1ghi..."],
   #         "bridge_count": 3
   #       }
   #     ]
   #   }
   # }
   ```

2. **Monitor Inter-Cluster Messages**
   ```bash
   # Watch bridge message relay
   tail -f data/logs/bootnode1.log | grep "Bridge relay"

   # Expected log output:
   # [INFO] Bridge relay: Forwarding message from cluster_0 to cluster_1
   # [INFO] Bridge relay: Message authenticated with ML-DSA signature
   # [INFO] Bridge relay: Delivery confirmed
   ```

3. **Verify Message Authentication**
   ```bash
   # All inter-cluster messages must be ML-DSA signed
   curl -s -X POST http://localhost:5640/rpc \
     -H "Content-Type: application/json" \
     -d '{
       "jsonrpc": "2.0",
       "method": "consensus_getBridgeMessageLog",
       "params": [{"limit": 10}],
       "id": 1
     }' | jq

   # Verify each message has valid ML-DSA signature
   ```

4. **Test Bridge Rate Limiting**
   ```bash
   # Bridges limited to 1000 messages/minute
   # Attempt to exceed limit and verify rejection

   curl -s -X POST http://localhost:5650/rpc \
     -H "Content-Type: application/json" \
     -d '{
       "jsonrpc": "2.0",
       "method": "consensus_getBridgeStats",
       "id": 1
     }' | jq

   # Check rate_limited_count > 0 if limit exceeded
   ```

**Expected Results:**
- ✅ Top K validators selected as bridges (K = min(3, cluster_size/10))
- ✅ All bridge messages ML-DSA authenticated
- ✅ Rate limiting prevents spam (1000 msgs/min max)
- ✅ Redundant bridges provide fault tolerance
- ✅ Message delivery confirmed across clusters

---

## Monitoring & Metrics

### Key Metrics to Track

1. **Block Production Rate**
   ```bash
   # Blocks per minute (should be ~10 for 6-second blocks)
   curl -s -X POST http://localhost:5640/rpc \
     -H "Content-Type: application/json" \
     -d '{"jsonrpc":"2.0","method":"consensus_getBlockRate","id":1}' | jq
   ```

2. **Validator Participation**
   ```bash
   # Percentage of validators participating in recent blocks
   curl -s -X POST http://localhost:5640/rpc \
     -H "Content-Type: application/json" \
     -d '{"jsonrpc":"2.0","method":"consensus_getParticipationRate","id":1}' | jq
   ```

3. **Cluster Health**
   ```bash
   # Check health of all clusters
   curl -s -X POST http://localhost:5640/rpc \
     -H "Content-Type: application/json" \
     -d '{"jsonrpc":"2.0","method":"consensus_getClusterHealth","id":1}' | jq
   ```

4. **Synergy Score Distribution**
   ```bash
   # Histogram of Synergy Scores
   curl -s -X POST http://localhost:5640/rpc \
     -H "Content-Type: application/json" \
     -d '{"jsonrpc":"2.0","method":"synergy_getScoreDistribution","id":1}' | jq
   ```

5. **Leader Rotation Frequency**
   ```bash
   # Track how often leaders change
   curl -s -X POST http://localhost:5640/rpc \
     -H "Content-Type: application/json" \
     -d '{"jsonrpc":"2.0","method":"consensus_getLeaderRotationStats","id":1}' | jq
   ```

---

## Governance Testing

### Adjust Consensus Parameters via DAO

1. **Submit Parameter Adjustment Proposal**
   ```bash
   # Example: Increase target cluster size from 30 to 40

   curl -X POST http://localhost:5640/rpc \
     -H "Content-Type: application/json" \
     -d '{
       "jsonrpc": "2.0",
       "method": "governance_submitProposal",
       "params": [{
         "type": "parameter_adjustment",
         "parameter": "target_cluster_size",
         "current_value": 30,
         "proposed_value": 40,
         "rationale": "Improve security with larger clusters",
         "voting_period_blocks": 1000
       }],
       "id": 1
     }'
   ```

2. **Vote on Proposal (Weighted by Synergy Score)**
   ```bash
   # Validators vote with their Synergy Score as weight

   curl -X POST http://localhost:5640/rpc \
     -H "Content-Type: application/json" \
     -d '{
       "jsonrpc": "2.0",
       "method": "governance_vote",
       "params": [{
         "proposal_id": "prop_001",
         "vote": "approve",
         "validator_signature": "ML_DSA_SIGNATURE_HERE"
       }],
       "id": 1
     }'
   ```

3. **Check Voting Status**
   ```bash
   curl -s -X POST http://localhost:5640/rpc \
     -H "Content-Type: application/json" \
     -d '{
       "jsonrpc": "2.0",
       "method": "governance_getProposalStatus",
       "params": ["prop_001"],
       "id": 1
     }' | jq
   ```

4. **Automatic Execution at Epoch Boundary**
   ```bash
   # If approved (>50% for parameter adjustments),
   # change takes effect at next epoch

   # Monitor parameter update
   watch -n 5 'curl -s -X POST http://localhost:5640/rpc \
     -H "Content-Type: application/json" \
     -d "{\"jsonrpc\":\"2.0\",\"method\":\"consensus_getParameter\",\"params\":[\"target_cluster_size\"],\"id\":1}" \
     | jq'
   ```

---

## Advanced Testing: Byzantine Fault Scenarios

### Test 1: Malicious Block Proposal

**Setup**: Validator submits invalid block

**Expected**: Other validators reject, reputation slashed

```bash
# Attempt to propose block with invalid transactions
# (This requires modifying validator software - not recommended in production)

# Monitor for slashing event
tail -f data/logs/bootnode1.log | grep "Slashing"

# Verify reputation decrease
curl -s -X POST http://localhost:5640/rpc \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "synergy_getReputation",
    "params": ["MALICIOUS_VALIDATOR_ADDRESS"],
    "id": 1
  }' | jq
```

### Test 2: Double-Signing Attack

**Setup**: Validator signs two different blocks at same height

**Expected**: Immediate slashing with high severity

```bash
# Monitor for double-signing detection
tail -f data/logs/bootnode1.log | grep "Double-sign"

# Verify slashing penalty
curl -s -X POST http://localhost:5640/rpc \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "synergy_getScoreBreakdown",
    "params": ["DOUBLE_SIGNER_ADDRESS"],
    "id": 1
  }' | jq -r '.result.components.reputation'

# Expected: reputation ~0.1 (near zero after slashing)
```

### Test 3: Network Partition

**Setup**: Simulate network split

**Expected**: Minority partition cannot finalize blocks

```bash
# Use iptables to block communication between validator subsets
# Partition 1: 7 validators
# Partition 2: 3 validators

# Only partition 1 should continue producing blocks (67% quorum)
# Partition 2 should halt

# Monitor both partitions
# Partition 1 should show increasing block height
# Partition 2 should show stalled block height

# When partition heals, chain with higher Synergy Score weight becomes canonical
```

---

## Performance Benchmarks

### Target Metrics

| Metric | Target | Acceptable | Critical |
|--------|--------|------------|----------|
| **Block Time** | 6 seconds | < 10 sec | > 15 sec |
| **Finality** | < 5 seconds | < 10 sec | > 30 sec |
| **TPS** | 1000+ | 500+ | < 100 |
| **Validator Participation** | > 95% | > 85% | < 67% |
| **Leader Rotation** | Every 10 blocks | Every 20 | Never |
| **Cluster Quorum** | 100% | > 67% | < 67% |

### Benchmark Commands

```bash
# Transaction throughput test
./scripts/benchmark-tps.sh

# Finality latency test
./scripts/benchmark-finality.sh

# Cluster rotation overhead
./scripts/benchmark-rotation.sh
```

---

## Troubleshooting

### Issue: Cluster Quorum Not Met

**Symptoms**: Block production stalls

**Diagnosis:**
```bash
curl -s -X POST http://localhost:5640/rpc \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"consensus_getQuorumStatus","id":1}' | jq
```

**Solutions:**
- Ensure >67% of Synergy Score weight is online
- Check validator connectivity
- Verify no network partition

### Issue: Cluster Rotation Not Occurring

**Symptoms**: Same cluster assignments after epoch boundary

**Diagnosis:**
```bash
# Check entropy beacon
curl -s -X POST http://localhost:5640/rpc \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"consensus_getEntropyBeacon","id":1}' | jq
```

**Solutions:**
- Verify ML-KEM entropy generation
- Check epoch boundary triggered
- Review cluster reformation logs

### Issue: Cartel Not Detected

**Symptoms**: Coordinating validators not penalized

**Diagnosis:**
```bash
# Check detection threshold
curl -s -X POST http://localhost:5640/rpc \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"consensus_getCartelDetectionParams","id":1}' | jq
```

**Solutions:**
- Ensure correlation threshold set correctly (default 0.85)
- Verify sufficient blocks for analysis (minimum 100)
- Check timing analysis enabled

---

## Next Steps

1. **Scale to 50+ validators** for true multi-cluster testing
2. **Run long-term tests** (7+ days) to verify stability
3. **Simulate Byzantine attacks** to test fault tolerance
4. **Benchmark performance** under heavy load
5. **Test governance proposals** to adjust parameters
6. **Monitor Synergy Score fairness** across diverse validators

---

**PoSy Consensus Testing Complete! 🚀**

The cluster-based architecture with dynamic rotation provides security, scalability, and fairness.

For questions or support, reach out to the Synergy development team.
