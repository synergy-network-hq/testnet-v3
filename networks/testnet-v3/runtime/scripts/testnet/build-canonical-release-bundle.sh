#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
GENESIS_FILE="${GENESIS_FILE:-$ROOT_DIR/config/genesis.json}"
MANIFEST_FILE="${MANIFEST_FILE:-$ROOT_DIR/config/operational-manifest.json}"
SETUP_PACKAGES_DIR="${SETUP_PACKAGES_DIR:-$HOME/Desktop/setup-packages}"
OUT_DIR="${OUT_DIR:-$ROOT_DIR/dist/testnet-canonical-release}"

for required in "$GENESIS_FILE" "$MANIFEST_FILE"; do
  if [[ ! -f "$required" ]]; then
    echo "Missing required canonical artifact: $required" >&2
    exit 1
  fi
done

if [[ ! -d "$SETUP_PACKAGES_DIR" ]]; then
  echo "Setup packages directory not found: $SETUP_PACKAGES_DIR" >&2
  exit 1
fi

mkdir -p "$OUT_DIR"
cp "$GENESIS_FILE" "$OUT_DIR/genesis.json"
cp "$MANIFEST_FILE" "$OUT_DIR/operational-manifest.json"

python3 - "$GENESIS_FILE" "$MANIFEST_FILE" "$SETUP_PACKAGES_DIR" "$OUT_DIR/release-bundle.json" <<'PY'
import hashlib
import json
import pathlib
import sys
from datetime import datetime, timezone

genesis_path = pathlib.Path(sys.argv[1])
manifest_path = pathlib.Path(sys.argv[2])
packages_dir = pathlib.Path(sys.argv[3])
output_path = pathlib.Path(sys.argv[4])

genesis = json.loads(genesis_path.read_text(encoding="utf-8"))
manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
canonical_genesis_hash = genesis.get("integrity", {}).get("genesis_hash")
if not canonical_genesis_hash:
    raise SystemExit("Canonical genesis is missing integrity.genesis_hash")

canonical_validator_addresses = sorted(
    {
        (entry.get("address") or "").strip().lower()
        for entry in manifest.get("validators", [])
        if (entry.get("address") or "").strip()
    }
)
if not canonical_validator_addresses:
    raise SystemExit("Canonical operational manifest does not contain validator addresses")

expected_ports = manifest.get("ports", {})

def sha256(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()

packages = []
for package_path in sorted(packages_dir.glob("*.json")):
    package = json.loads(package_path.read_text(encoding="utf-8"))
    package_genesis_hash = (
        package.get("artifacts", {})
        .get("genesis", {})
        .get("integrity", {})
        .get("genesis_hash")
    )
    if package_genesis_hash != canonical_genesis_hash:
        raise SystemExit(
            f"{package_path.name}: genesis hash mismatch (expected {canonical_genesis_hash}, got {package_genesis_hash})"
        )

    if package.get("chain_id") != manifest.get("chain_id"):
        raise SystemExit(
            f"{package_path.name}: chain_id mismatch (expected {manifest.get('chain_id')}, got {package.get('chain_id')})"
        )

    package_manifest = package.get("artifacts", {}).get("operational_manifest", {})
    package_validator_addresses = sorted(
        {
            (entry.get("address") or "").strip().lower()
            for entry in package_manifest.get("validators", [])
            if (entry.get("address") or "").strip()
        }
    )
    if package_validator_addresses and package_validator_addresses != canonical_validator_addresses:
        raise SystemExit(f"{package_path.name}: validator registry does not match canonical manifest")

    assigned_ports = package.get("assigned_ports") or {}
    if assigned_ports:
        mismatches = {
            key: value
            for key, value in expected_ports.items()
            if key
            in {
                "node_listener_base",
                "rpc_base",
                "ws_base",
                "discovery_base",
                "metrics_base",
            }
        }
        port_map = {
            "node_listener_base": assigned_ports.get("p2p_port"),
            "rpc_base": assigned_ports.get("rpc_port"),
            "ws_base": assigned_ports.get("ws_port"),
            "discovery_base": assigned_ports.get("discovery_port"),
            "metrics_base": assigned_ports.get("metrics_port"),
        }
        invalid = {
            label: {"expected": mismatches[label], "actual": port_map[label]}
            for label in mismatches
            if port_map[label] != mismatches[label]
        }
        if invalid:
            raise SystemExit(f"{package_path.name}: assigned ports do not match canonical ports: {invalid}")

    packages.append(
        {
            "file": package_path.name,
            "sha256": sha256(package_path),
            "role_id": package.get("role_id"),
            "display_name": package.get("display_name"),
            "validator_slot": package.get("validator_slot"),
            "chain_id": package.get("chain_id"),
            "network_id": package.get("network_id"),
            "genesis_hash": package_genesis_hash,
        }
    )

bundle = {
    "generated_at_utc": datetime.now(timezone.utc).isoformat(),
    "chain_id": manifest.get("chain_id"),
    "network_id": manifest.get("network_id"),
    "canonical_genesis_hash": canonical_genesis_hash,
    "validator_addresses": canonical_validator_addresses,
    "ports": expected_ports,
    "files": [
        {"file": genesis_path.name, "sha256": sha256(genesis_path)},
        {"file": manifest_path.name, "sha256": sha256(manifest_path)},
    ],
    "setup_packages": packages,
}

output_path.write_text(json.dumps(bundle, indent=2) + "\n", encoding="utf-8")
print(f"Wrote canonical release bundle to {output_path}")
PY

echo "Canonical release bundle staged in: $OUT_DIR"
