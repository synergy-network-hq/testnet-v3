# Synergy Testnet Bundle

This directory defines the deterministic testnet profile.

## Closed-Testnet Guarantees

- P2P discovery is disabled (`enable_discovery = false`).
- P2P and RPC bind to the rendered inventory addresses for each assigned node.
- Validator registration is strict-allowlist gated.
- Config rendering is deterministic from inventory + key material.

## Files

- `node-inventory.csv`: authoritative machine map, ports, inventory bind addresses, validator auto-register policy.
- `hosts.env.example`: host/address mapping plus optional remote lifecycle hooks.
- `configs/`: per-machine rendered node configuration files (generated).
- `keys/`: per-machine key material and address metadata (generated).
- `observability/`: Prometheus/Grafana/Loki stack and RPC exporter.

## Core Generation Workflow

```bash
cp testnet/runtime/hosts.env.example testnet/runtime/hosts.env
scripts/testnet/generate-node-keys.sh
scripts/testnet/render-configs.sh
scripts/testnet/generate-testnet-genesis.sh
```

For the authoritative validator update path, including which files are the real control-panel source of truth and which generated files should not be edited directly, see:

- `docs/developer/testnet-validator-update-workflow.md`

## One-Command Cluster Reset

```bash
./reset-testnet.sh
```

This executes:

1. Stop nodes.
2. Clear chain/token/validator state.
3. Re-render configs.
4. Regenerate deterministic genesis.
5. Restart cluster in deterministic order.

## Test Harness

```bash
scripts/testnet/run-testnet-test-phases.sh --rpc-url http://127.0.0.1:5652
scripts/testnet/check-determinism.sh
scripts/testnet/load-generator.sh --rpc-url http://127.0.0.1:5652 --rpm 10000 --minutes 1
scripts/testnet/chaos-node.sh --rpc-url http://127.0.0.1:5652
```

## Observability

```bash
scripts/testnet/start-observability.sh
```

For full deployment and operations details, use:

- `guides/LEAN_15_NODE_TESTNET_RUNBOOK.md`
- `guides/CLOSED_TESTNET_IMPLEMENTATION_UPDATE_2026-02-26.md`
