# Synergy Node Control Panel Quick Ops Cheat Sheet

Version: 2026-06-04
Scope: Synergy Testnet post-fork operations and first-start checks

## 1. Core Facts

- Chain ID: `1266`
- Network ID: `synergy-testnet-v3`
- Testnet-v3 genesis: height `0`
- Consensus signing after fork: `FN-DSA`
- Consensus key algorithm: `ML-DSA-65`
- Parser mode: `fail_closed`
- Token: `SNRG`
- Core RPC: `https://testnet-core-rpc.synergy-network.io`
- Core WS: `wss://testnet-core-ws.synergy-network.io`
- API: `https://testnet-api.synergy-network.io`
- Explorer: `https://testnet-explorer.synergy-network.io`
- Atlas API: `https://testnet-atlas-api.synergy-network.io`
- Bootnodes: `bootnode1.synergy-network.io:5620`, `bootnode2.synergy-network.io:5620`, `bootnode3.synergy-network.io:5620`
- Bootnode direct fallbacks: `170.64.187.206:5620`, `146.190.210.121:5620`, `157.245.226.240:5620`
- Seeds: `http://seed1.synergy-network.io:5621`, `http://seed2.synergy-network.io:5621`, `http://seed3.synergy-network.io:5621`
- Seed direct fallbacks: `http://170.64.187.206:5621`, `http://146.190.210.121:5621`, `http://157.245.226.240:5621`

## 2. Genesis Setup Command

Open Jarvis and send:

```text
genesis setup
```

Jarvis switches into ceremony mode and asks for the node role to install.

## 3. Package To Select

- `bootnode`: download the matching `bootnode*.tar.gz` bundle from the Genesis Dashboard.
- `seed_server`: download the matching `seed*.tar.gz` bundle from the Genesis Dashboard.
- `validator`: download the assigned `validator-*-setup-package.json` file from the Genesis Dashboard.
- `rpc_gateway`: download `rpc-gateway-setup-package.json`.
- `indexer`: download `indexer-explorer-setup-package.json`.

## 4. Expected Local Ports

- Bootnode: `5620`
- Seed service: `5621`
- Role P2P: `5622 + assignment`
- Role RPC: `5640 + assignment`
- Role WebSocket: `5660 + assignment`
- Role discovery: `5680 + assignment`
- Role metrics: `6030 + slot`

## 5. Minimum Role Checks

- Bootnode: bootstrap-only workspace imported, `config/node.toml` present, port `5620` reachable.
- Seed server: `seed-service.json` present, `/peer-list.json` reachable on `5621`.
- Genesis validator: `config/genesis.json`, `config/operational-manifest.json`, and validator identity all staged before first start.
- RPC gateway: package imported with the canonical beta manifests and public host set for `testnet-core-rpc` and `testnet-core-ws`.
- Indexer and explorer: package imported with the canonical beta manifests and public host set for `testnet-explorer` and `testnet-atlas-api`.

## 6. Bring-Up Order

1. Bootnodes
2. Seed services
3. Genesis validators
4. Public RPC and API
5. Atlas and explorer
6. Wallet, faucet, and public service checks
7. SXCP runtime

## 7. Immediate Health Checks

- `status`
- `rpc:get_sync_status`
- `rpc:get_peer_info`
- `rpc:get_latest_block`
- `rpc:get_validator_activity`
- `rpc:get_sxcp_status`

## 8. Workspace Locations

- macOS: `~/.synergy-node-control-panel/monitor-workspace`
- Linux: `~/.synergy-node-control-panel/monitor-workspace`
- Windows: `%USERPROFILE%\.synergy-node-control-panel\monitor-workspace`

## 9. Fast Failure Checks

- Import rejected: re-download the package from the Genesis Dashboard and import the exact assigned role package.
- Bootstrap missing: confirm all three bootnodes and at least one seed service respond before starting validators.
- Wrong public host: re-run `genesis setup` and enter the canonical hostname for the role being installed.
- Stale manifests: delete the failed workspace and import the ceremony package again.
