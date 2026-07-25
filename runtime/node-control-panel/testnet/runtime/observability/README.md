# Closed Testnet Observability Stack

This stack provides:

- `Prometheus` (metrics)
- `Grafana` (dashboards)
- `Loki` + `Promtail` (logs)
- `synergy_rpc_exporter.py` (RPC-derived chain health metrics)
- `node-exporter` (host CPU/memory/disk metrics)

## Start

```bash
scripts/testnet/start-observability.sh
```

## Stop

```bash
scripts/testnet/stop-observability.sh
```

## URLs

- Prometheus: [http://127.0.0.1:9090](http://127.0.0.1:9090)
- Grafana: [http://127.0.0.1:3000](http://127.0.0.1:3000) (`admin` / `admin`)
- Loki: [http://127.0.0.1:3100](http://127.0.0.1:3100)
- RPC Exporter: [http://127.0.0.1:9168/metrics](http://127.0.0.1:9168/metrics)

## Metrics Coverage

The RPC exporter publishes:

- Block height
- Average block time
- Peer count
- Mempool size
- Estimated TPS
- Active validator count
- Per-method RPC latency
- Per-validator uptime (from validator activity RPC)
- Determinism mismatch/fork indicator via `synergy_getDeterminismDigest`

## Notes

- This repo does not currently expose native `/metrics` endpoints from node processes; exporter metrics are derived from JSON-RPC.
- Promtail tails local logs from `data/testnet15/*/logs`. For multi-machine clusters, deploy promtail/node-exporter on each node and keep scrapes on the monitor host.
