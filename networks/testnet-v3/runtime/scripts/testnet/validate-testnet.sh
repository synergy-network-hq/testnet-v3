#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
GENESIS_FILE="${TESTNET_GENESIS_FILE:-$ROOT_DIR/config/genesis.json}"
NETWORK_IDENTIFIERS_FILE="${TESTNET_NETWORK_IDENTIFIERS_FILE:-$ROOT_DIR/network-identifiers.testnet.json}"
MANIFEST_FILE="${TESTNET_MANIFEST_FILE:-$ROOT_DIR/config/operational-manifest.json}"
BUNDLE_DIR="${TESTNET_BUNDLE_DIR:-$ROOT_DIR/bootstrap-bundles}"
EXPECTED_GENESIS_MIN_VALIDATOR_COUNT="${EXPECTED_GENESIS_MIN_VALIDATOR_COUNT:-4}"
EXPECTED_GENESIS_MIN_QUORUM_THRESHOLD="${EXPECTED_GENESIS_MIN_QUORUM_THRESHOLD:-auto}"
EXPECTED_BASELINE_VALIDATOR_COUNT="${EXPECTED_BASELINE_VALIDATOR_COUNT:-5}"
EXPECTED_DYNAMIC_MAX_VALIDATORS="${EXPECTED_DYNAMIC_MAX_VALIDATORS:-0}"

for required in "$GENESIS_FILE" "$NETWORK_IDENTIFIERS_FILE" "$MANIFEST_FILE" "$BUNDLE_DIR"; do
  if [[ ! -e "$required" ]]; then
    echo "Missing required testnet launch asset: $required" >&2
    exit 1
  fi
done

python3 - "$ROOT_DIR" "$GENESIS_FILE" "$NETWORK_IDENTIFIERS_FILE" "$MANIFEST_FILE" \
  "$EXPECTED_GENESIS_MIN_VALIDATOR_COUNT" "$EXPECTED_GENESIS_MIN_QUORUM_THRESHOLD" \
  "$EXPECTED_BASELINE_VALIDATOR_COUNT" <<'PY'
import importlib.util
import json
import sys
from pathlib import Path

root_dir, genesis_path, identifiers_path, manifest_path = sys.argv[1:5]
expected_min_validator_count = int(sys.argv[5])
expected_min_quorum_threshold_arg = sys.argv[6]
expected_baseline_validator_count = int(sys.argv[7])
if expected_min_quorum_threshold_arg == "auto":
    fault_tolerance = max(0, (expected_baseline_validator_count - 1) // 3)
    expected_min_quorum_threshold = 2 * fault_tolerance + 1
else:
    expected_min_quorum_threshold = int(expected_min_quorum_threshold_arg)
errors = []

with open(genesis_path, encoding="utf-8") as handle:
    genesis = json.load(handle)
with open(identifiers_path, encoding="utf-8") as handle:
    identifiers = json.load(handle)
with open(manifest_path, encoding="utf-8") as handle:
    manifest = json.load(handle)

expected_ports = {
    "bootnode": 5620,
    "seed_http": 5621,
    "node_listener_base": 5622,
    "rpc_base": 5640,
    "ws_base": 5660,
    "discovery_base": 5680,
    "metrics_base": 6030,
}

required_contracts = {
    "validator_registry",
    "synergy_oracle",
    "staking",
    "governance",
    "treasury",
    "reward_distributor",
    "slashing",
    "identity",
}

zero_hash = "0" * 64

def has_placeholder(value):
    if isinstance(value, str):
        return "<" in value and ">" in value
    if isinstance(value, list):
        return any(has_placeholder(item) for item in value)
    if isinstance(value, dict):
        return any(has_placeholder(item) for item in value.values())
    return False

def is_hex_hash(value):
    return isinstance(value, str) and len(value) == 64 and all(ch in "0123456789abcdef" for ch in value.lower())

tool_path = Path(root_dir) / "scripts" / "testnet" / "genesis_tool.py"
spec = importlib.util.spec_from_file_location("synergy_genesis_tool", tool_path)
if spec is None or spec.loader is None:
    errors.append(f"unable to load canonical genesis tool at {tool_path}")
else:
    genesis_tool = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(genesis_tool)
    report = genesis_tool.validate_documents(genesis, identifiers)
    errors.extend(report.get("errors", []))

if genesis.get("schema_version") != "v1":
    errors.append("genesis schema_version must be v1")
if genesis.get("env") != "testnet":
    errors.append("genesis env must be testnet")
if genesis.get("network", {}).get("chain_id") != 1264:
    errors.append("genesis network.chain_id must be 1264")
if genesis.get("network", {}).get("network_id") != 1264:
    errors.append("genesis network.network_id must be 1264")
if genesis.get("header", {}).get("block_height") != 0:
    errors.append("genesis header.block_height must be 0")
if genesis.get("header", {}).get("parent_hash") != zero_hash:
    errors.append("genesis header.parent_hash must be the zero hash")
if not isinstance(genesis.get("header", {}).get("timestamp"), int):
    errors.append("genesis header.timestamp must be an integer unix timestamp")
if genesis.get("token", {}).get("symbol") != "SNRG":
    errors.append("genesis token.symbol must be SNRG")
if genesis.get("token", {}).get("minting_policy") != "fixed_cap":
    errors.append("genesis token.minting_policy must be fixed_cap")
if genesis.get("consensus", {}).get("min_validator_count") != expected_min_validator_count:
    errors.append(
        "genesis consensus.min_validator_count must be "
        f"{expected_min_validator_count}"
    )
if genesis.get("consensus", {}).get("min_quorum_threshold") != expected_min_quorum_threshold:
    errors.append(
        "genesis consensus.min_quorum_threshold must be "
        f"{expected_min_quorum_threshold}"
    )
if len(genesis.get("validators", [])) != expected_baseline_validator_count:
    errors.append(
        "genesis must contain exactly "
        f"{expected_baseline_validator_count} validators"
    )
if not isinstance(genesis.get("contracts"), dict):
    errors.append("genesis contracts must be an object")
else:
    contract_keys = set(genesis["contracts"].keys())
    missing_contracts = sorted(required_contracts - contract_keys)
    if missing_contracts:
        errors.append(f"genesis contracts missing required entries: {', '.join(missing_contracts)}")

if has_placeholder(genesis):
    errors.append("genesis must not contain any <PLACEHOLDER> values")

balances_total = 0
for entry in genesis.get("balances", []):
    try:
        balances_total += int(entry.get("balance_nwei", "0"))
    except (TypeError, ValueError):
        errors.append(f"invalid balance_nwei for {entry.get('address')}")

allocations_total = 0
for entry in genesis.get("allocations", []):
    try:
        allocations_total += int(entry.get("amount_nwei", "0"))
    except (TypeError, ValueError):
        errors.append(f"invalid amount_nwei for allocation {entry.get('name')}")

try:
    total_supply_cap = int(genesis.get("token", {}).get("total_supply_cap_nwei", "0"))
except (TypeError, ValueError):
    total_supply_cap = -1
    errors.append("genesis token.total_supply_cap_nwei must be a decimal string")

if balances_total != total_supply_cap:
    errors.append("genesis balances must sum to token.total_supply_cap_nwei")
if allocations_total != total_supply_cap:
    errors.append("genesis allocations must sum to token.total_supply_cap_nwei")

integrity = genesis.get("integrity", {})
for field in ("genesis_hash", "state_root", "allocation_hash", "validator_hash", "contract_hash"):
    if not is_hex_hash(integrity.get(field)):
        errors.append(f"genesis integrity.{field} must be a 64-character lowercase hex hash")

if manifest.get("network_id") != 1264:
    errors.append("operational manifest network_id must be 1264")
if manifest.get("environment_id") != "testnet":
    errors.append("operational manifest environment_id must be testnet")
if manifest.get("chain_id") != 1264:
    errors.append("operational manifest chain_id must be 1264")
if manifest.get("token", {}).get("symbol") != "SNRG":
    errors.append("operational manifest token.symbol must be SNRG")
if len(manifest.get("bootstrap", {}).get("bootnodes", [])) != 3:
    errors.append("operational manifest must contain exactly 3 bootnodes")
if len(manifest.get("bootstrap", {}).get("seed_servers", [])) != 3:
    errors.append("operational manifest must contain exactly 3 seed servers")
if manifest.get("bootstrap", {}).get("routing", {}).get("bootnodes") != ["sentry1"]:
    errors.append("operational manifest bootnode routing must pin to sentry1")
    if manifest.get("bootstrap", {}).get("routing", {}).get("seed_servers") != ["sentry2"]:
        errors.append("operational manifest seed server routing must pin to sentry2")
if len(manifest.get("validators", [])) < 5:
    errors.append("operational manifest must contain at least the 5 baseline validators")
if manifest.get("ports") != expected_ports:
    errors.append("operational manifest ports must match the frozen public testnet port model")

public_endpoints = manifest.get("public_endpoints", {})
expected_urls = {
    "core_rpc": "https://testnet-core-rpc.synergy-network.io",
    "core_ws": "wss://testnet-core-ws.synergy-network.io",
    "api": "https://testnet-api.synergy-network.io",
}
for key, expected in expected_urls.items():
    actual = public_endpoints.get(key, {}).get("url")
    if actual != expected:
        errors.append(f"operational manifest {key}.url must be {expected}")

if errors:
    for error in errors:
        print(error)
    sys.exit(1)
PY

failures=0
read -r EXPECTED_VALIDATOR_COUNT EXPECTED_VALIDATOR_CLUSTER_SIZE EXPECTED_VALIDATOR_QUORUM < <(
  python3 - "$MANIFEST_FILE" <<'PY'
import json
import sys

manifest = json.load(open(sys.argv[1], encoding="utf-8"))
validator_count = len(manifest.get("validators", []))
min_cluster = 5
target_cluster = 7
if validator_count == 0:
    cluster_count = 0
elif validator_count < min_cluster * 2:
    cluster_count = 1
else:
    cluster_count = max(2, (validator_count + target_cluster - 1) // target_cluster)
    while cluster_count > 1 and validator_count // cluster_count < min_cluster:
        cluster_count -= 1
cluster_size = 0 if cluster_count == 0 else (validator_count + cluster_count - 1) // cluster_count
quorum = (validator_count * 67 + 99) // 100
print(validator_count, cluster_size, quorum)
PY
)

for bundle in bootnode1 bootnode2 bootnode3; do
  node_config="$BUNDLE_DIR/$bundle/config/node.toml"
  bundle_genesis="$BUNDLE_DIR/$bundle/config/genesis.json"
  if [[ ! -f "$node_config" ]]; then
    echo "Missing bootnode bundle config: $node_config" >&2
    failures=$((failures + 1))
    continue
  fi
  if [[ ! -f "$bundle_genesis" ]]; then
    echo "Missing bootnode bundle genesis: $bundle_genesis" >&2
    failures=$((failures + 1))
  elif ! cmp -s "$GENESIS_FILE" "$bundle_genesis"; then
    echo "[$bundle] genesis.json does not match canonical config/genesis.json" >&2
    failures=$((failures + 1))
  fi

  if ! rg -q '^p2p_port = 5620$' "$node_config"; then
    echo "[$bundle] p2p_port must be 5620" >&2
    failures=$((failures + 1))
  fi
  if ! rg -q "^validator_cluster_size = ${EXPECTED_VALIDATOR_CLUSTER_SIZE}$" "$node_config"; then
    echo "[$bundle] validator_cluster_size must be ${EXPECTED_VALIDATOR_CLUSTER_SIZE}" >&2
    failures=$((failures + 1))
  fi
  if ! rg -q "^validator_vote_threshold = 0$" "$node_config"; then
    echo "[$bundle] validator_vote_threshold must be 0 so runtime derives dynamic quorum (${EXPECTED_VALIDATOR_QUORUM} for current manifest)" >&2
    failures=$((failures + 1))
  fi
  if ! rg -q "^max_validators = ${EXPECTED_DYNAMIC_MAX_VALIDATORS}$" "$node_config"; then
    echo "[$bundle] max_validators must be ${EXPECTED_DYNAMIC_MAX_VALIDATORS} so runtime remains uncapped for future validator expansion" >&2
    failures=$((failures + 1))
  fi
  if rg -q '38638|48638|58638|18080|5730|5830|5930' "$node_config"; then
    echo "[$bundle] contains stale closed-testnet ports" >&2
    failures=$((failures + 1))
  fi
done

for bundle in genesisrpc genesisindexer; do
  node_config="$BUNDLE_DIR/$bundle/config/node.toml"
  bundle_genesis="$BUNDLE_DIR/$bundle/config/genesis.json"
  if [[ ! -f "$node_config" ]]; then
    echo "Missing service bundle config: $node_config" >&2
    failures=$((failures + 1))
    continue
  fi

  if [[ ! -f "$bundle_genesis" ]]; then
    echo "Missing service bundle genesis: $bundle_genesis" >&2
    failures=$((failures + 1))
  elif ! cmp -s "$GENESIS_FILE" "$bundle_genesis"; then
    echo "[$bundle] genesis.json does not match canonical config/genesis.json" >&2
    failures=$((failures + 1))
  fi

  if ! rg -q '^seed_servers = \[\]$' "$node_config"; then
    echo "[$bundle] seed_servers must be empty" >&2
    failures=$((failures + 1))
  fi
  if rg -q '38638|48638|58638|18080|5730|5830|5930' "$node_config"; then
    echo "[$bundle] contains stale closed-testnet ports" >&2
    failures=$((failures + 1))
  fi
done

for stale_dir in seed1 seed2 seed3 bootseed2 rpc-gateway indexer-explorer; do
  if [[ -d "$BUNDLE_DIR/$stale_dir" ]]; then
    echo "bootstrap-bundles must not retain stale $stale_dir directory" >&2
    failures=$((failures + 1))
  fi
done

if [[ -d "$BUNDLE_DIR/Bootstrap2" || -d "$BUNDLE_DIR/Bootstrap3" ]]; then
  echo "bootstrap-bundles must not retain stale Bootstrap2 or Bootstrap3 directories" >&2
  failures=$((failures + 1))
fi

for doc in "$BUNDLE_DIR/DEPLOYMENT_GUIDE.md" "$BUNDLE_DIR/DNS_RECORDS.txt" "$BUNDLE_DIR/README.txt"; do
  if [[ ! -f "$doc" ]]; then
    echo "Missing support document: $doc" >&2
    failures=$((failures + 1))
    continue
  fi
  if rg -q '38638|48638|58638|18080|5730|5830|5930|synergy-testnet-closed' "$doc"; then
    echo "Support document contains stale legacy network data: $doc" >&2
    failures=$((failures + 1))
  fi
done

if (( failures > 0 )); then
  echo "Testnet validation failed (${failures} issue(s))." >&2
  exit 2
fi

echo "Testnet validation passed."
