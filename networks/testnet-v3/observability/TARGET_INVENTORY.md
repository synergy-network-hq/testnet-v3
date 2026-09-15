# Testnet Observability Target Inventory

This is the observer-side target contract for the current testnet topology. It
is intentionally separate from host access credentials and does not authorize
live changes. The observer is not a validator-VPN peer.

The machine-readable proxy allocation is
`relayer-telemetry-proxy-contract.json`; validate it against the staged
Prometheus config with `scripts/deploy_observability.sh validate`.

## Route policy

- `10.70.10.1-6` are the canonical Innernet addresses for validators 1-6.
  They are inventory metadata only. Prometheus must reach validator telemetry
  through the approved public relayer proxy allocation.
- `10.70.20.1-3` are the canonical Innernet addresses for relayers 1-3.
  Prometheus uses their public telemetry names for direct service and exporter
  checks.
- No observer target may use a direct validator address from `10.70.10.0/24`.
- Blackbox probes run on the observer at `127.0.0.1:9115`.

## Machine inventory

| Machine | Role | Canonical Innernet | App metrics target | qRPC probe target | node_exporter target | Observer path |
|---|---|---|---|---|---|---|
| validator-1 | validator | `10.70.10.1` | `relay1.synergynode.xyz:16031` | `relay1.synergynode.xyz:15631` | `relay1.synergynode.xyz:19101` | relayer-1 proxy |
| validator-2 | validator | `10.70.10.2` | `relay1.synergynode.xyz:16032` | `relay1.synergynode.xyz:15632` | `relay1.synergynode.xyz:19102` | relayer-1 proxy |
| validator-3 | validator | `10.70.10.3` | `relay2.synergynode.xyz:16033` | `relay2.synergynode.xyz:15633` | `relay2.synergynode.xyz:19103` | relayer-2 proxy |
| validator-4 | validator | `10.70.10.4` | `relay2.synergynode.xyz:16034` | `relay2.synergynode.xyz:15634` | `relay2.synergynode.xyz:19104` | relayer-2 proxy |
| validator-5 | validator | `10.70.10.5` | `relay3.synergynode.xyz:16035` | `relay3.synergynode.xyz:15635` | `relay3.synergynode.xyz:19105` | relayer-3 proxy |
| validator-6 | validator | `10.70.10.6` | `relay3.synergynode.xyz:16036` | `relay3.synergynode.xyz:15636` | `relay3.synergynode.xyz:19106` | relayer-3 proxy |
| relayer-1 | relayer | `10.70.20.1` | not published on live host (`:6030` absent) | `relay1.synergynode.xyz:5640` | `relay1.synergynode.xyz:9100` | public qRPC/exporter |
| relayer-2 | relayer | `10.70.20.2` | not published on live host (`:6030` absent) | `relay2.synergynode.xyz:5640` | `relay2.synergynode.xyz:9100` | public qRPC/exporter |
| relayer-3 | relayer | `10.70.20.3` | not published on live host (`:6030` absent) | `relay3.synergynode.xyz:5640` | `relay3.synergynode.xyz:9100` | public qRPC/exporter |
| rpc-gateway | RPC gateway | public DNS | `https://testnet-core-rpc.synergy-network.io/metrics/node-rpc` | HTTP health probe | `https://testnet-core-rpc.synergy-network.io/metrics/node-exporter` | public |
| explorer-indexer | Explorer/indexer | public DNS | not published on live Explorer hostname (serves Atlas UI) | HTTP health probe | `https://testnet-atlas-api.synergy-network.io/metrics/node-exporter` | public Atlas API |
| archive | archive | public DNS | snapshot probe `https://archive-store.synergynode.xyz/snapshots/latest.json` | not reachable from observer | not reachable from observer | public snapshot probe |
| observer | observer | local | `127.0.0.1:6030` plus PoSy collector `127.0.0.1:9201` | local process | `127.0.0.1:9100` | local |
| bootseed-1 | bootnode + seed | public | service probe `170.64.187.206:5620` and `:5621` | service probe | not published | public TCP probe |
| bootseed-2 | bootnode + seed | public | service probe `146.190.210.121:5620` and `:5621` | service probe | not published | public TCP probe |
| bootseed-3 | bootnode + seed | public | service probe `157.245.226.240:5620` and `:5621` | service probe | not published | public TCP probe |
| website-coordinator | website + validator-VPN coordinator | public DNS | HTTPS health probes | HTTPS health probes | `https://testnet.synergy-network.io/metrics/node-exporter` and `https://vpn-coordinator.synergy-network.io/metrics/node-exporter` when published | public |

The validator proxy port allocation is intentionally explicit so a target can
be traced to one validator without exposing the validator Innernet address to
Prometheus. If the allocation changes, update this file and the three matching
jobs in `prometheus.yml` together.

## Public HTTP probes

The `synergy-http-probes` job checks `/healthz` for the RPC gateway, Explorer,
Atlas API, website, and validator-VPN coordinator. The RPC application scrape
uses `/metrics/node-rpc`. The Explorer hostname currently serves the Atlas web
UI rather than a Prometheus exposition response, so the live observer uses the
published Atlas API node-exporter route and keeps Explorer health separate.

## Bootstrap probes

The `synergy-bootstrap-probes` job checks public TCP reachability for all six
boot/seed services. These hosts do not have an approved observer-reachable
node_exporter endpoint, so absence of host metrics is not silently treated as
a missing machine.
