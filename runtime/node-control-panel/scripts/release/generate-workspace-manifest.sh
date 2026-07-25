#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

MANIFEST_PATH="$ROOT_DIR/testnet/runtime/workspace-manifest.json"
APP_VERSION="$(node -e 'const fs=require("fs");const pkg=JSON.parse(fs.readFileSync("package.json","utf8"));process.stdout.write(pkg.version);')"
python3 - <<'PY' "$ROOT_DIR" "$MANIFEST_PATH" "$APP_VERSION"
import hashlib
import json
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
manifest_path = pathlib.Path(sys.argv[2])
app_version = sys.argv[3]

# Only the macOS and Linux platform binaries are currently bundled into the Electron app.
# Runtime configs are validated separately; ignored key/setup-package material
# must not drive the digest.
platform_binaries = [
    "binaries/synergy-testnet-darwin-arm64",
    "binaries/synergy-testnet-macos-arm64",
    "binaries/synergy-testnet-linux-amd64",
    "binaries/synergy-testnet-windows-amd64.exe",
]

def sha256_file(path: pathlib.Path) -> str:
    with path.open("rb") as fh:
        return hashlib.sha256(fh.read()).hexdigest()

checksums = {}
bundle_hasher = hashlib.sha256()

for rel in platform_binaries:
    path = root / rel
    if not path.is_file():
        raise SystemExit(f"Missing platform binary: {rel}")
    digest = sha256_file(path)
    checksums[rel] = digest
    bundle_hasher.update(rel.encode("utf-8"))
    bundle_hasher.update(digest.encode("utf-8"))

bundle_digest = bundle_hasher.hexdigest()
genesis_path = root / "testnet/runtime/configs/genesis/genesis.json"
genesis = json.loads(genesis_path.read_text(encoding="utf-8"))
genesis_hash = str(genesis.get("integrity", {}).get("genesis_hash", ""))
network_magic_bytes = str(genesis.get("p2p_identity", {}).get("network_magic_bytes", ""))

manifest = {
    "workspace_resource_version": f"{app_version}+{bundle_digest[:12]}",
    "app_version": app_version,
    "chain_id": int(genesis.get("network", {}).get("chain_id", 1264)),
    "chain_id_hex": "0x4f0",
    "network_id": "synergy-testnet-v3",
    "network_native_id": int(genesis.get("network", {}).get("network_id", 1264)),
    "network_slug": "synergy-testnet",
    "genesis_hash": genesis_hash,
    "network_magic_bytes": network_magic_bytes,
    "bundle_digest": bundle_digest,
    "platform_binaries": platform_binaries,
    "required_paths": [
        "testnet/runtime/workspace-manifest.json",
        "testnet/runtime/configs/genesis/genesis.json",
        "testnet/runtime/configs/consensus/consensus-fork-migration.json",
        "testnet/runtime/configs/operational/operational-manifest.json",
        "testnet/runtime/validator-vpn/validator-vpn-coordinator.env",
        "testnet/runtime/installers/Validator-01/config/genesis.json",
        "testnet/runtime/installers/Validator-01/config/consensus-fork-migration.json",
        "testnet/runtime/installers/Validator-01/config/peers.toml",
        "testnet/runtime/installers/Node-RPC/nginx.conf",
        "testnet/runtime/installers/Node-EXP/nginx.conf",
        "testnet/runtime/installers/Node-EXP/explorer-app/dist/index.html",
        "testnet/runtime/installers/Node-EXP/explorer-app/dist/assets",
        "testnet/runtime/installers/Node-EXP/explorer-app/backend/dist",
        "testnet/runtime/installers/Node-EXP/explorer-app/backend/scripts/migrate.js",
        "testnet/runtime/installers/Node-EXP/explorer-app/backend/migrations",
        "testnet/runtime/installers/Node-EXP/explorer-app/backend/node_modules/fastify/package.json",
        "testnet/runtime/installers/Node-EXP/explorer-app/indexer/dist",
        "testnet/runtime/installers/Node-EXP/explorer-app/indexer/scripts/migrate.js",
        "testnet/runtime/installers/Node-EXP/explorer-app/indexer/migrations",
        "testnet/runtime/installers/Node-EXP/explorer-app/indexer/node_modules/pg/package.json",
        "scripts/testnet/validator-vpn-agent.sh",
        "scripts/testnet/remote-node-orchestrator.sh",
        "scripts/reset-testnet.sh",
        "guides/SYNERGY_TESTNET_CONTROL_PANEL_USER_MANUAL.md",
    ],
    "checksums": checksums,
}

manifest_path.parent.mkdir(parents=True, exist_ok=True)
with open(str(manifest_path), "w", encoding="utf-8", newline="\n") as fh:
    fh.write(json.dumps(manifest, indent=2) + "\n")
PY

echo "Workspace manifest ready: $MANIFEST_PATH"
