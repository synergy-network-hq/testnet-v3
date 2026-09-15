## Testnet Ops Canonicals

This directory holds the source-of-truth operational configs that have to stay
aligned with the live Testnet infrastructure.

- `observability/prometheus.observer.yml`
  Canonical Prometheus config for the observer host.
- `observability/grafana/*.json`
  Importable Grafana dashboards for network overview, consensus/chain health,
  host infrastructure, and public edge/bootstrap reachability.
- `observability/import-grafana-dashboards.sh`
  Imports every dashboard JSON into a Grafana instance using `GRAFANA_URL` plus
  either `GRAFANA_API_TOKEN` or `GRAFANA_USER` / `GRAFANA_PASSWORD`.
- `nginx/testnet-core-rpc.synergy-network.io.conf`
  Canonical public RPC / WS reverse proxy config, including allowlisted metrics
  paths for the observer.
- `nginx/testnet-explorer.conf`
  Canonical public explorer / Atlas / indexer reverse proxy config, including
  the allowlisted explorer metrics path for the observer.
- `systemd/synergy-rpc-router.service.d/40-synid-registry-write.conf`
  Allows the sandboxed public RPC router to persist SynID registrations in its
  dedicated state directory. The directory and registry file must remain
  group-writable by the router's configured `node` supplementary group.

Notes:

- Validators and relayers are scraped directly on the private network plane.
- The shared public service host (`74.208.227.23`) is scraped through HTTPS
  metrics paths on `443` with an observer IP allowlist.
- Bootnode raw metrics ports are not reachable from the observer's public
  network path, so the observer monitors those roles through blackbox TCP
  probes against their public bootstrap and seed ports.
