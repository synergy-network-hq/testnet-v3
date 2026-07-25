# Public-First P2P Architecture, Rollout, Rollback, and Verification Runbook

## Scope

This runbook defines the public-first Synergy testnet P2P architecture and the operator sequence for rollout, rollback, and verification.

Use this runbook for:

- Stable public P2P topology.
- Seed registry behavior.
- Bootnode behavior.
- Validator peer generation.
- RPC Gateway P2P versus public RPC separation.
- Observer and Grafana monitoring.
- Explorer indexer public P2P integration.
- Archive validator public port `5615`.
- Relayer role normalization.
- Rollout and rollback sequencing.

Do not use this runbook to store evidence, generated proofs, backups, temporary output, or copied secrets under the project tree. If local scratch output is required, put it outside the project tree under `/Volumes/xcode`.

## Hard rules

- Use `testnet` naming for all new files, labels, configs, and operator notes.
- Use workbook-backed `ssh synergy-*` aliases only.
- Do not expose or copy secrets from `node-machine-credentials.xlsx`.
- Do not put VPN, localhost, or LAN endpoints in active public P2P configs.
- Keep WireGuard and VPN access for SSH, administration, and operational access only.
- Do not use VPN as the active validator consensus path.
- Do not describe `rpc.synergynode.xyz:5623` as public JSON-RPC.
- Do not let archive advertise `73.79.66.255:5622`.
- Do not roll validators in parallel.

## Architecture summary

The target network uses public P2P endpoints for node-to-node communication. Stable infrastructure uses DNS names. Active validators use public IP endpoints.

VPN can remain for operations access, but public P2P must carry:

- Validator consensus peer connectivity.
- Block propagation.
- Peer discovery.
- RPC Gateway P2P sync.
- Observer network monitoring.
- Explorer indexing.
- Archive connectivity.
- Relayer connectivity.

## Canonical topology

### Stable infrastructure DNS

| Role | Endpoint | Origin |
| --- | --- | --- |
| Bootnode 1 | `bootnode1.synergynode.xyz:5620` | `170.64.187.206` |
| Bootnode 2 | `bootnode2.synergynode.xyz:5620` | `146.190.210.121` |
| Bootnode 3 | `bootnode3.synergynode.xyz:5620` | `157.245.226.240` |
| Seed 1 | `seed1.synergynode.xyz:5621` | `170.64.187.206` |
| Seed 2 | `seed2.synergynode.xyz:5621` | `146.190.210.121` |
| Seed 3 | `seed3.synergynode.xyz:5621` | `157.245.226.240` |
| Relayer 1 | `relay1.synergynode.xyz:5622` | `195.26.241.95` |
| Relayer 2 | `relay2.synergynode.xyz:5622` | `94.72.117.108` |
| RPC Gateway P2P | `rpc.synergynode.xyz:5623` | `167.86.83.83` |
| Archive P2P | `archive.synergynode.xyz:5615` | `73.79.66.255` |

Stable infrastructure records must be DNS-only origin records. If any stable P2P DNS record resolves to Cloudflare proxy IPs, stop the rollout and fix DNS before continuing.

### Public RPC endpoint

`https://testnet-core-rpc.synergy-network.io` is the public JSON-RPC endpoint for wallets, apps, frontends, and explorer clients.

`rpc.synergynode.xyz:5623` is only the RPC Gateway node P2P endpoint.

### Active validator public P2P endpoints

| Validator | Public P2P endpoint | Validator address |
| --- | --- | --- |
| Val1 | `62.146.182.207:5622` | `synv11qen9x0g9p0f2pqznpqzfrwkrgnsussdwmvs` |
| Val2 | `62.146.182.208:5622` | `synv11s4wc6l4kg4jr0k5meg42cyzxa03cf863srt` |
| Val3 | `62.146.182.209:5622` | `synv11e3ephsarcw6mey0fx5xtnygg2ewegnum4re` |
| Val4 | `73.79.66.255:5622` | `synv11mka64uz049aekwhdvfrq6dvh75d0k7kmdp5` |
| Val5 | `194.163.183.166:5622` | `synv11kguave5fpdpm9hru4acfvw0hcp4fcc7zv9f` |
| Val6 | `157.173.192.45:5622` | `synv11zghr6nsm3ajl57ywxasw9mr5f844slq4mwx` |

The active six-validator set excludes archive and any unapproved future validator.

## Role definitions

### Validators

Validators produce blocks, vote, participate in consensus, and maintain a direct public validator mesh.

Each active validator must use:

- Common bootnodes.
- Common seed servers.
- Common DNS bootstrap.
- Same strict validator allowlist.
- Same peer template with itself removed.
- Other five validators by public IP.
- Relayer 1 and Relayer 2 as auxiliary peers.

Validators must not require relayers or VPN to reach each other.

### Bootnodes

Bootnodes are stable bootstrap entry points. They listen publicly on `5620`.

Bootnodes must:

- Advertise only their `bootnode*.synergynode.xyz:5620` endpoint.
- Use seed servers at `http://seed1.synergynode.xyz:5621`, `http://seed2.synergynode.xyz:5621`, and `http://seed3.synergynode.xyz:5621`.
- Keep relayers as additional stable peers.
- Reject and avoid propagating private, localhost, LAN, and unspecified public endpoints.

### Seed servers

Seed servers are dynamic public peer registries. They listen publicly on `5621`.

Seed servers must expose:

- `GET /health`
- `GET /metrics`
- `GET /peer-list.json`
- `GET /peers`
- `GET /peers?role=validator`
- `GET /peers?role=relayer`
- `GET /peers?role=observer`
- `GET /peers?role=rpc_gateway`
- `GET /peers?role=archive_validator`
- `GET /peers?role=explorer_indexer`
- `POST /register`
- `POST /heartbeat`

Seed registry entries should include:

- `chain_id`
- `role`
- `node_name`
- `validator_address` for validators
- `peer_id` or `node_public_key`
- `public_endpoint`
- `observed_remote_ip`
- `listen_port`
- `protocol_version`
- `app_version`
- `current_height`
- `highest_known_height`
- `sync_gap`
- `last_seen`
- `ttl_seconds`
- `health_status`
- `signature` when supported
- `source_seed`
- `dialback_status`
- `dialback_last_success`
- `dialback_last_failure`
- `failure_count`
- `score`

Seed servers must reject public advertisements for:

- `10.0.0.0/8`
- `172.16.0.0/12`
- `192.168.0.0/16`
- `127.0.0.0/8`
- `169.254.0.0/16`
- `localhost`
- `0.0.0.0`
- `::1`
- Private IPv6 ranges.

Only dial-back-successful healthy peers should be advertised.

### RPC Gateway

The RPC Gateway is both a P2P sync node and the backend for public RPC routing.

Keep the distinction explicit:

- P2P endpoint: `rpc.synergynode.xyz:5623`.
- Public JSON-RPC endpoint: `https://testnet-core-rpc.synergy-network.io`.

Target RPC Gateway P2P peers:

- `relay1.synergynode.xyz:5622`
- `relay2.synergynode.xyz:5622`
- `62.146.182.207:5622`
- `62.146.182.208:5622`
- `62.146.182.209:5622`
- `73.79.66.255:5622`
- `194.163.183.166:5622`
- `157.173.192.45:5622`
- `archive.synergynode.xyz:5615`
- `209.145.50.9:5622`

JSON-RPC should remain local or private unless intentionally routed through the public RPC endpoint.

### Observer and Grafana

The observer node is the network observability node. It is not a validator and not a relayer.

Observer public P2P endpoint:

- `209.145.50.9:5622`

Observer P2P peers:

- `relay1.synergynode.xyz:5622`
- `relay2.synergynode.xyz:5622`
- `rpc.synergynode.xyz:5623`
- `archive.synergynode.xyz:5615`
- `62.146.182.207:5622`
- `62.146.182.208:5622`
- `62.146.182.209:5622`
- `73.79.66.255:5622`
- `194.163.183.166:5622`
- `157.173.192.45:5622`

Observer monitoring targets are separate from observer P2P peers. Monitoring should cover:

- Bootnodes.
- Seed servers.
- Relayers.
- RPC Gateway P2P.
- Public RPC.
- Archive.
- All six validators.
- Explorer indexer after SSH and metrics are verified.

Grafana should make network health clear at a glance:

- Up/down status.
- P2P listener health.
- qRPC health.
- Metrics endpoint health.
- Current height.
- Sync gap.
- Peer count.
- Peer identities.
- Validator proposal and voting status.
- Consensus participation.
- Missed blocks and votes.
- Quorum failures.
- Catch-up failures.
- Failed dials.
- Duplicate peer-session events.
- Stale peer events.
- Socket summaries.
- CPU, RAM, disk, and bandwidth.
- Archive and snapshot health.
- Seed registry health.
- Bootnode mesh health.
- Public RPC health.
- Explorer indexer height and indexing status.
- Relayer cross-chain service health.

### Explorer indexer

The explorer indexer ingests chain data for Atlas and explorer surfaces. It is not a validator, not a relayer, and not the observer.

Known identity:

- SSH alias: `synergy-vps`
- Public IP: `74.208.227.23`
- Expected service: `synergy-explorer-indexer.service`
- Expected config paths: `/etc/synergy/explorer-indexer/node.toml` and `/etc/synergy/explorer-indexer/peers.toml`

Target explorer indexer peers:

- `relay1.synergynode.xyz:5622`
- `relay2.synergynode.xyz:5622`
- `rpc.synergynode.xyz:5623`
- `archive.synergynode.xyz:5615`
- `62.146.182.207:5622`
- `62.146.182.208:5622`
- `62.146.182.209:5622`
- `73.79.66.255:5622`
- `194.163.183.166:5622`
- `157.173.192.45:5622`

Preferred ingestion order:

1. RPC Gateway for normalized RPC ingestion.
2. Validators for direct block and consensus visibility.
3. Archive validator for historical and snapshot depth.
4. Relayers only as auxiliary peers.

### Archive validator

Archive public P2P endpoint:

- `archive.synergynode.xyz:5615`

The archive endpoint must not collide with Val4:

- Val4 remains `73.79.66.255:5622`.
- Archive must advertise `archive.synergynode.xyz:5615`.
- NAT must route `73.79.66.255:5615` to the archive validator host.
- NAT must route `73.79.66.255:5622` to Val4.

If the runtime supports separate listen and advertise addresses, local listen may remain `0.0.0.0:5622` while public advertised P2P is `archive.synergynode.xyz:5615`.

If the runtime requires listen and advertise port equality, set archive P2P listen to `5615` and keep public advertised P2P as `archive.synergynode.xyz:5615`.

Archive target peers:

- `relay1.synergynode.xyz:5622`
- `relay2.synergynode.xyz:5622`
- `rpc.synergynode.xyz:5623`
- `62.146.182.207:5622`
- `62.146.182.208:5622`
- `62.146.182.209:5622`
- `73.79.66.255:5622`
- `194.163.183.166:5622`
- `157.173.192.45:5622`

### Relayers

Relayers remain public P2P peers during migration but should return to their intended cross-chain and interoperability role after direct public validator P2P is healthy.

Relayer 1 public P2P:

- `relay1.synergynode.xyz:5622`

Relayer 1 peers:

- `relay2.synergynode.xyz:5622`
- `rpc.synergynode.xyz:5623`
- `archive.synergynode.xyz:5615`
- `209.145.50.9:5622`
- `62.146.182.207:5622`
- `62.146.182.208:5622`
- `62.146.182.209:5622`
- `73.79.66.255:5622`
- `194.163.183.166:5622`
- `157.173.192.45:5622`

Relayer 2 public P2P:

- `relay2.synergynode.xyz:5622`

Relayer 2 peers:

- `relay1.synergynode.xyz:5622`
- `rpc.synergynode.xyz:5623`
- `archive.synergynode.xyz:5615`
- `209.145.50.9:5622`
- `62.146.182.207:5622`
- `62.146.182.208:5622`
- `62.146.182.209:5622`
- `73.79.66.255:5622`
- `194.163.183.166:5622`
- `157.173.192.45:5622`

## Validator config generation

The canonical source for generated public P2P configs is:

```text
config/testnet/network-topology.toml
```

The generator path is:

```text
scripts/testnet/generate_public_p2p_configs.py
```

Generated configs should be emitted under:

```text
config/testnet/generated/
```

The generator must fail closed if a generated public P2P field contains private, localhost, link-local, unspecified, or LAN endpoints.

Each Val1-Val6 config must be identical except for:

- `public_p2p_address`
- Node identity or key paths.
- The current validator endpoint omitted from its validator peer list.

Common validator bootnodes:

```toml
bootnodes = [
  "snr://bootstrap@bootnode1.synergynode.xyz:5620",
  "snr://bootstrap@bootnode2.synergynode.xyz:5620",
  "snr://bootstrap@bootnode3.synergynode.xyz:5620"
]
```

Common validator seed servers:

```toml
seed_servers = [
  "http://seed1.synergynode.xyz:5621",
  "http://seed2.synergynode.xyz:5621",
  "http://seed3.synergynode.xyz:5621"
]
```

Common validator DNS bootstrap:

```toml
bootstrap_dns_records = ["_dnsaddr.bootstrap.synergynode.xyz"]
```

Common strict allowlist:

```toml
strict_validator_allowlist = true
allowed_validator_addresses = [
  "synv11qen9x0g9p0f2pqznpqzfrwkrgnsussdwmvs",
  "synv11s4wc6l4kg4jr0k5meg42cyzxa03cf863srt",
  "synv11e3ephsarcw6mey0fx5xtnygg2ewegnum4re",
  "synv11mka64uz049aekwhdvfrq6dvh75d0k7kmdp5",
  "synv11kguave5fpdpm9hru4acfvw0hcp4fcc7zv9f",
  "synv11zghr6nsm3ajl57ywxasw9mr5f844slq4mwx"
]
```

## DNS and port preflight

Run DNS preflight before rolling any node:

```bash
for host in \
  bootnode1.synergynode.xyz bootnode2.synergynode.xyz bootnode3.synergynode.xyz \
  seed1.synergynode.xyz seed2.synergynode.xyz seed3.synergynode.xyz \
  relay1.synergynode.xyz relay2.synergynode.xyz rpc.synergynode.xyz archive.synergynode.xyz
do
  printf '%s ' "$host"
  dig +short A "$host" | tr '\n' ' '
  printf '\n'
done
```

Expected A records:

- `bootnode1.synergynode.xyz` -> `170.64.187.206`
- `bootnode2.synergynode.xyz` -> `146.190.210.121`
- `bootnode3.synergynode.xyz` -> `157.245.226.240`
- `seed1.synergynode.xyz` -> `170.64.187.206`
- `seed2.synergynode.xyz` -> `146.190.210.121`
- `seed3.synergynode.xyz` -> `157.245.226.240`
- `relay1.synergynode.xyz` -> `195.26.241.95`
- `relay2.synergynode.xyz` -> `94.72.117.108`
- `rpc.synergynode.xyz` -> `167.86.83.83`
- `archive.synergynode.xyz` -> `73.79.66.255`

Run TCP preflight after DNS is DNS-only:

```bash
for target in \
  bootnode1.synergynode.xyz:5620 bootnode2.synergynode.xyz:5620 bootnode3.synergynode.xyz:5620 \
  seed1.synergynode.xyz:5621 seed2.synergynode.xyz:5621 seed3.synergynode.xyz:5621 \
  relay1.synergynode.xyz:5622 relay2.synergynode.xyz:5622 rpc.synergynode.xyz:5623 \
  archive.synergynode.xyz:5615 \
  62.146.182.207:5622 62.146.182.208:5622 62.146.182.209:5622 \
  73.79.66.255:5622 194.163.183.166:5622 157.173.192.45:5622 \
  209.145.50.9:5622
do
  host="${target%:*}"
  port="${target##*:}"
  nc -vz -w 5 "$host" "$port"
done
```

Stop if any stable DNS record returns Cloudflare proxy IPs or if required public listener checks fail.

## Rollout sequence

Roll out in this order:

1. DNS-only verification and external port checks.
2. Seed server upgrade on `synergy-bootseed1`, `synergy-bootseed2`, and `synergy-bootseed3`.
3. Bootnode upgrade on `synergy-bootseed1`, `synergy-bootseed2`, and `synergy-bootseed3`.
4. Relayer upgrade on `synergy-relayer1` and `synergy-relayer2`.
5. RPC Gateway upgrade on `synergy-rpc`.
6. Observer upgrade on `synergy-observer`.
7. Archive upgrade and `archive.synergynode.xyz:5615` validation.
8. Explorer indexer upgrade on `synergy-vps` after SSH and config access are confirmed.
9. Validators one at a time: `synergy-val6`, `synergy-val5`, `synergy-val1`, `synergy-val2`, `synergy-val3`, then `synergy-val4`.

Before touching each node:

```bash
ssh <synergy-alias> 'ts=$(date -u +%Y%m%dT%H%M%SZ); sudo mkdir -p /var/backups/synergy/p2p-rollout/$ts && sudo systemctl status --no-pager "*" >/tmp/synergy-service-status.$ts.txt || true'
```

Back up active config and peer overlays on the remote node before changing them:

```bash
ssh <synergy-alias> 'ts=$(date -u +%Y%m%dT%H%M%SZ); sudo mkdir -p /var/backups/synergy/p2p-rollout/$ts; sudo cp -a /etc/synergy /var/backups/synergy/p2p-rollout/$ts/etc-synergy'
```

Record remote health before restart:

```bash
ssh <synergy-alias> 'hostname; date -u; ss -ltnp | grep -E ":(5620|5621|5622|5623|5615|5641|5640)\\b" || true; systemctl list-units "synergy*" --no-pager || true'
```

Restart the relevant service only after config is staged:

```bash
ssh <synergy-alias> 'sudo systemctl restart <service-name> && sudo systemctl status --no-pager <service-name>'
```

For archive on macOS, use the installed launchd unit instead of Linux systemd commands:

```bash
ssh synergy-archive 'sudo launchctl kickstart -k system/io.synergynetwork.archive-validator'
```

Do not proceed to the next validator until the current validator is synced or cleanly catching up, has expected public peers, and does not show repeated failed dials to private endpoints.

## Rollback process

Rollback uses the timestamped remote backup created before changing each node.

Linux systemd rollback pattern:

```bash
ssh <synergy-alias> 'backup=<backup-dir>; sudo systemctl stop <service-name>; sudo rsync -a --delete "$backup/etc-synergy/" /etc/synergy/; sudo systemctl start <service-name>; sudo systemctl status --no-pager <service-name>'
```

Archive launchd rollback pattern:

```bash
ssh synergy-archive 'backup=<backup-dir>; sudo cp -a "$backup/etc-synergy/." /etc/synergy/; sudo launchctl kickstart -k system/io.synergynetwork.archive-validator'
```

Post-rollback validation pattern:

```bash
ssh <synergy-alias> 'date -u; ss -ltnp | grep -E ":(5620|5621|5622|5623|5615|5641|5640)\\b" || true; systemctl status --no-pager <service-name> || true'
```

If rollback involves a validator, wait for chain movement and validator peer convergence before touching any other validator.

## Verification commands

Use these repo scripts when present:

```bash
./scripts/testnet/verify-public-p2p-topology.sh
./scripts/testnet/verify-validator-consensus.py
./scripts/testnet/verify-seed-registry.py
./scripts/testnet/verify-observer-grafana-targets.py
./scripts/testnet/verify-explorer-indexer.sh
```

Config hygiene checks:

```bash
rg -n '10\\.69\\.|127\\.0\\.0\\.1:5622|localhost:5622|192\\.168\\.|73\\.79\\.66\\.255:5622' \
  config/testnet generated config node-control-panel/testnet/runtime/configs archive-validator/config templates
```

The archive check is expected to find Val4 only where the role is explicitly the validator. It must not find archive advertising `73.79.66.255:5622`.

Seed registry checks:

```bash
curl -fsS http://seed1.synergynode.xyz:5621/health
curl -fsS http://seed1.synergynode.xyz:5621/peer-list.json
curl -fsS 'http://seed1.synergynode.xyz:5621/peers?role=validator'
curl -fsS 'http://seed1.synergynode.xyz:5621/peers?role=rpc_gateway'
curl -fsS 'http://seed1.synergynode.xyz:5621/peers?role=archive_validator'
```

Public RPC check:

```bash
curl -fsS https://testnet-core-rpc.synergy-network.io \
  -H 'content-type: application/json' \
  --data '{"jsonrpc":"2.0","id":1,"method":"synergy_getBlockNumber","params":[]}'
```

RPC Gateway P2P must not be tested as JSON-RPC:

```bash
nc -vz -w 5 rpc.synergynode.xyz 5623
```

Chain movement check:

```bash
curl -fsS https://testnet-core-rpc.synergy-network.io \
  -H 'content-type: application/json' \
  --data '{"jsonrpc":"2.0","id":1,"method":"synergy_getBlockNumber","params":[]}'
sleep 30
curl -fsS https://testnet-core-rpc.synergy-network.io \
  -H 'content-type: application/json' \
  --data '{"jsonrpc":"2.0","id":2,"method":"synergy_getBlockNumber","params":[]}'
sleep 30
curl -fsS https://testnet-core-rpc.synergy-network.io \
  -H 'content-type: application/json' \
  --data '{"jsonrpc":"2.0","id":3,"method":"synergy_getBlockNumber","params":[]}'
```

Observer and Grafana checks:

```bash
ssh synergy-observer 'systemctl status --no-pager prometheus grafana-server || true'
curl -fsS https://nodemonitor.synergy-network.io/api/health
```

Explorer indexer checks:

```bash
ssh synergy-vps 'systemctl status --no-pager synergy-explorer-indexer.service; sudo rg -n "10\\.|192\\.168\\.|127\\.0\\.0\\.1|localhost" /etc/synergy/explorer-indexer || true'
```

Archive checks:

```bash
nc -vz -w 5 archive.synergynode.xyz 5615
nc -vz -w 5 73.79.66.255 5622
```

## Final completion gate

Do not declare the public P2P rollout complete until:

- Stable P2P DNS resolves to origin IPs.
- Stable P2P DNS is not proxied through Cloudflare.
- Bootnodes are reachable on `5620`.
- Seeds are reachable on `5621`.
- Relayers are reachable on `5622`.
- RPC Gateway P2P is reachable on `5623`.
- Archive is reachable on `archive.synergynode.xyz:5615`.
- All six validators are reachable on public `5622`.
- Observer is reachable on public `5622`.
- Seed servers return clean public peer data.
- All six validators are online.
- All six validators are synced or within accepted tolerance.
- All six validators directly see one another.
- All six validators participate in consensus.
- Chain height advances across multiple samples.
- RPC Gateway has expected P2P peers.
- Public RPC works through `https://testnet-core-rpc.synergy-network.io`.
- Observer feeds Prometheus and Grafana.
- Explorer indexer is indexing.
- Archive health and snapshot surfaces are healthy as expected.
- No active public P2P config depends on VPN, localhost, or LAN endpoints.
