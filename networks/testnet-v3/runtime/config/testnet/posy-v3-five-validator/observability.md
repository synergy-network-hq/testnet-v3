# PoSy v3 observability contract

The in-memory bounded sampler exposes deterministic integer summaries for the
following names. The production telemetry adapter must export count, minimum,
maximum, average, p50, p95, and p99 without adding validator IDs or other
unbounded labels.

| Metric | Meaning |
| --- | --- |
| `posy_v3_proposal_latency_us` | proposal construction/validation latency |
| `posy_v3_vote_propagation_us` | ordinary vote propagation latency |
| `posy_v3_qc_formation_latency_us` | first proposal to verified QC |
| `posy_v3_chained_finality_latency_us` | proposal to three-chain commit |
| `posy_v3_tc_recovery_latency_us` | TC signature verification/recovery |
| `posy_v3_leader_takeover_latency_us` | timeout detection to successor authority |
| `posy_v3_pqc_verification_us` | ML-DSA-65 certificate verification |
| `posy_v3_certificate_size_bytes` | canonical QC or TC encoded size |
| `posy_v3_restart_rejoin_time_us` | durable restore or verified state-sync time |

Alert on a durable SafetyHalt immediately. Alert on no QC progress for more
than the governed timeout budget, repeated TC formation, inability to meet
strict 4-of-5 or weight quorum, context-root disagreement, or a restart that
cannot load/verify persisted safety state. A safe quorum stall is an operator
incident, not authority to lower quorum or force a leader.

Performance targets in the proposal are qualification thresholds, not proof
that they have passed. They remain blocked until a production-like five-node
load, fault, and restart profile exports reviewable evidence.
