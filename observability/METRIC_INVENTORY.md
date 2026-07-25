# Testnet Metric Inventory

## Application metrics

Validators, the observer, and the RPC gateway expose application metrics on
their approved paths. Live relayers do not currently publish an application
metrics listener on `:6030`; their observer coverage is qRPC plus node_exporter.
The Explorer hostname currently serves the Atlas web UI, so its observer
coverage is the Atlas API exporter route plus HTTP health probes. Native runtime
families include:

- `synergy_chain_height`
- `synergy_chain_last_block_timestamp_seconds`
- `synergy_chain_recent_avg_block_time_seconds`
- `synergy_p2p_peers_connected` and `synergy_peer_count`
- `synergy_validator_registry_total`
- `synergy_validator_status_total`
- `synergy_validators_total`
- `synergy_status_ready_validators`
- `synergy_build_info` and `synergy_node_info`

The RPC gateway's native path is active at `/metrics/node-rpc`. The documented
Explorer `/metrics/node-exp` path currently returns the Atlas web UI, so native
Explorer metrics are not scraped; the published Atlas API node-exporter route
and Explorer HTTP health probe remain active.

## Host metrics

The `node_exporter` job covers the observer, all six validators through the
relayer proxy allocation, relayers 1-3, and the archive host. Standard
Prometheus node metrics include:

- `node_cpu_seconds_total`
- `node_memory_MemAvailable_bytes` and `node_memory_MemTotal_bytes`
- `node_filesystem_avail_bytes` and `node_filesystem_size_bytes`
- `node_network_receive_bytes_total` and `node_network_transmit_bytes_total`

Boot/seed hosts currently have service reachability probes only because no
observer-reachable exporter path is approved for them. Website/coordinator host
exporter collection is enabled only when the public `/metrics/node-exporter`
route is published.

## Probe metrics

Blackbox exporter produces:

- `probe_success` for `synergy-qrpc-probes`,
  `synergy-http-probes`, and `synergy-bootstrap-probes`.
- `probe_duration_seconds`, `probe_http_status_code`, and TCP probe timing
  series where the selected blackbox module supports them.

## Canonical recording rules and alerts

The archive host currently contributes a snapshot reachability probe only; its
qRPC, application, and node_exporter paths are not observer-reachable.

Canonical rules remove duplicate target views and normalize the node identity.
Alerts cover target loss, qRPC route loss, public HTTP failure, exporter loss,
stale finalized/local data, height gaps, quorum safety, and host CPU/memory/disk
pressure. See `live-config-after/observer/rules/` and `VALIDATION.md`.
