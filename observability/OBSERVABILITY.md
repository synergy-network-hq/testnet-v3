# Synergy Testnet Observability

This directory is the canonical Prometheus/Grafana configuration for the
current testnet observer. The observer is a reporting host, not a validator
Innernet/VPN peer.

## Topology contract

- Validators 1-6 use canonical Innernet addresses `10.70.10.1` through
  `10.70.10.6`. Prometheus reaches their application metrics, qRPC, and
  node_exporter endpoints only through the public relayer proxy allocation.
- Relayers 1-3 use canonical Innernet addresses `10.70.20.1` through
  `10.70.20.3`. Prometheus uses `relay1/2/3.synergynode.xyz` for their public
  telemetry surfaces.
- RPC gateway, Explorer/indexer, archive, boot/seed hosts, website, and
  validator-VPN coordinator are monitored on their public service paths.
- Direct validator targets in `10.70.10.0/24` are prohibited. Retired private
  subnet addresses are not part of this configuration.

The complete machine-to-target map and proxy-port contract is in
`TARGET_INVENTORY.md`.

## Prometheus jobs

- `synergy-observer`: observer application metrics.
- `synergy-posy-exporter`: observer-side PoSy collector metrics from the
  approved relayer qRPC route.
- `synergy-validators`: six validator metrics routes through relayer proxies.
- `synergy-rpc-gateway`: RPC gateway native application metrics.
- `synergy-explorer-indexer`: published Atlas API exporter metrics.
- `synergy-archive`: archive snapshot reachability probe.
- `node_exporter`: observer, validator proxy, relayer, and archive host metrics.
- `node_exporter_public`: public exporter routes for RPC, Explorer/indexer, and
  the website/coordinator host where those routes are published.
- `synergy-qrpc-probes`: blackbox TCP checks for validator, relayer, and archive
  qRPC routes.
- `synergy-http-probes`: public health checks for RPC, Explorer, Atlas API,
  website, and coordinator.
- `synergy-bootstrap-probes`: public TCP checks for all six boot/seed services.

Relayer application metrics on `:6030` are not published by the current live
relayer services. Do not add dead Prometheus targets for that route; restoring
that surface requires a separately approved relayer service change.

## Canonical metrics

Recording rules in `live-config-after/observer/rules/synergy-canonical-rules.yml`
normalize chain and availability data into these series:

- `synergy_metrics_target_up`, `synergy_qrpc_probe_up`,
  `synergy_public_health_probe_up`, and `synergy_bootstrap_probe_up`.
- `synergy_node_chain_height`, `synergy_canonical_network_majority_height`,
  and `synergy_canonical_node_height_gap`.
- `synergy_canonical_latest_block_age_seconds` and
  `synergy_canonical_active_validator_count`.

Dashboards should use canonical recording rules and normalized labels (`node`,
`node_type`, `role`, `host`, `instance_label`) instead of raw target names.

## Deployment boundary

The staged observer files are under
`live-config-after/observer`. No live SSH changes are part of this repository
task. Before an approved deployment, validate with `VALIDATION.md`; after
deployment, finish on the observer Prometheus `/api/v1/targets` endpoint.
