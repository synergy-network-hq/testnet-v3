# Existing telemetry and passive observation

Existing telemetry is kept separate from controlled measurements.

## Passive snapshot

One workbook-authorized persistent `ssh synergy-rpc` session collected a read-only, sanitized snapshot on 2026-08-14. It retained no hostname, IP address, login name, endpoint, credential, environment-variable dump, key material, or application payload.

The RPC-gateway unit was enabled but inactive, with a successful prior stop, no restart loop, no running Synergy process, and no listener. The last filtered journal height was zero. Ten version-named node binaries were present, but no selected running artifact or commit could be established. Therefore live finality, throughput, Aegis resource use, and six-node health are `NOT_MEASURED`.

The sanitized machine-readable record is `results/live-observation-20260814.json`; `scripts/live-observation.sh` documents the one-session passive procedure but was not rerun.

## Historical incident material

The repository incident ledger describes an older typed-PoSy deployment in which repeated verification of equivalent ML-DSA-65 votes consumed the healthy-path deadline. Those observations motivated the positive cache and are useful architectural context, but their timing and block-interval values are not merged into this benchmark. The ledger also warns that Atlas batch-ingestion timestamps distort historical block intervals.

Historical values are not current Chain 1266 performance results and are excluded from publication statistics.
