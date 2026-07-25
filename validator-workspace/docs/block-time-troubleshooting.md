# Block-Time Troubleshooting

Target block-time range: 0.5s to 2.5s.

Before applying a fix, capture:

- recent p50, p90, p95, max, and average block times
- validator binary hash
- genesis and chain-spec hash
- consensus, DAG, mempool, RPC, metrics, and peer config hashes
- peer count and per-peer latency
- CPU, memory, disk IO, network drops, open files, and time sync state
- validator logs around slow rounds or missing quorum
- size and rewrite latency of `canonical_locks.json`; the canonical validator env must keep `SYNERGY_CANONICAL_LOCK_RETAIN_ENTRIES=512`

Apply any consensus, DAG, mempool, firewall, WireGuard, NTP, or service-limit fix uniformly across all validators and measure before and after.
