#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

echo "== Bundle prep =="

ensure_version_alignment() {
  local package_version cargo_version

  package_version="$(node -e 'const fs=require("fs"); const pkg=JSON.parse(fs.readFileSync("package.json","utf8")); process.stdout.write(pkg.version);')"
  cargo_version="$(python3 - <<'PY'
import pathlib
import re

content = pathlib.Path("control-service/Cargo.toml").read_text(encoding="utf-8")
match = re.search(r'^version\s*=\s*"([^"]+)"', content, re.MULTILINE)
if not match:
    raise SystemExit("Missing version in control-service/Cargo.toml")
print(match.group(1), end="")
PY
)"

  if [[ "$package_version" != "$cargo_version" ]]; then
    cat >&2 <<EOF
Version mismatch detected:
  package.json:                $package_version
  control-service/Cargo.toml: $cargo_version
Keep the desktop package version and control-service version aligned before tagging a release.
EOF
    exit 1
  fi
}

sync_platform_binaries() {
  local target_dir="$ROOT_DIR/binaries"
  local source_dir=""
  local candidates=()

  if [[ -n "${SYNERGY_TESTNET_BINARY_SOURCE_DIR:-}" ]]; then
    candidates+=("${SYNERGY_TESTNET_BINARY_SOURCE_DIR}")
  fi

  if [[ -n "${SYNERGY_TESTNET_SOURCE_REPO_ROOT:-}" ]]; then
    candidates+=("${SYNERGY_TESTNET_SOURCE_REPO_ROOT}/binaries")
  fi

  candidates+=(
    "$ROOT_DIR/../binaries"
    "$ROOT_DIR/../../synergy-testnet/binaries"
    "$ROOT_DIR/../../../synergy-testnet/binaries"
  )

  mkdir -p "$target_dir"

  for candidate in "${candidates[@]}"; do
    if [[ -d "$candidate" ]]; then
      source_dir="$(cd "$candidate" && pwd)"
      break
    fi
  done

  if [[ ! -d "$source_dir" ]]; then
    echo "Platform binary source not found; keeping existing binaries in binaries/."
    echo "Checked: ${candidates[*]}"
    return
  fi

  if [[ "$source_dir" == "$target_dir" ]]; then
    echo "Platform binary source resolves to binaries/; skipping sync."
    return
  fi

  echo "Syncing platform binaries from $source_dir"

  for binary_name in \
    synergy-testnet-darwin-arm64 \
    synergy-testnet-macos-arm64 \
    synergy-testnet-linux-amd64 \
    synergy-testnet-windows-amd64.exe
  do
    if [[ -f "$source_dir/$binary_name" ]]; then
      cp "$source_dir/$binary_name" "$target_dir/$binary_name"
      echo "  Synced: $binary_name"
    fi
  done
}

refresh_platform_binary_checksums() {
  local binary_path

  for binary_path in \
    "$ROOT_DIR/binaries/synergy-testnet-darwin-arm64" \
    "$ROOT_DIR/binaries/synergy-testnet-macos-arm64" \
    "$ROOT_DIR/binaries/synergy-testnet-linux-amd64" \
    "$ROOT_DIR/binaries/synergy-testnet-windows-amd64.exe"
  do
    if [[ -f "$binary_path" ]]; then
      if command -v shasum >/dev/null 2>&1; then
        printf "%s  %s\n" "$(shasum -a 256 "$binary_path" | awk '{print $1}')" "$(basename "$binary_path")" > "${binary_path}.sha256"
      elif command -v sha256sum >/dev/null 2>&1; then
        printf "%s  %s\n" "$(sha256sum "$binary_path" | awk '{print $1}')" "$(basename "$binary_path")" > "${binary_path}.sha256"
      fi
    fi
  done
}

sha256_for_file() {
  local file_path="$1"
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$file_path" | awk '{print $1}'
  else
    sha256sum "$file_path" | awk '{print $1}'
  fi
}

write_bundle_binary_status() {
  local bundle_dir="$1"
  local linux_path="$bundle_dir/bin/synergy-testnet-linux-amd64"
  local darwin_path="$bundle_dir/bin/synergy-testnet-darwin-arm64"
  local windows_path="$bundle_dir/bin/synergy-testnet-windows-amd64.exe"

  cat > "$bundle_dir/BINARY_STATUS.txt" <<EOF
Synergy Testnet Binary Status
============================

Linux Binary
------------
Path: ./bin/synergy-testnet-linux-amd64
SHA-256: $(sha256_for_file "$linux_path")

Darwin Binary
-------------
Path: ./bin/synergy-testnet-darwin-arm64
SHA-256: $(sha256_for_file "$darwin_path")

Windows Binary
--------------
Path: ./bin/synergy-testnet-windows-amd64.exe
SHA-256: $(sha256_for_file "$windows_path")

Interpretation
--------------
- These checksums reflect the exact bundled binaries shipped in this installer.
EOF
}

sync_bundle_binary_payload() {
  local bundle_dir="$1"
  local bin_dir="$bundle_dir/bin"

  mkdir -p "$bin_dir"
  cp "$ROOT_DIR/binaries/synergy-testnet-linux-amd64" "$bin_dir/synergy-testnet-linux-amd64"
  cp "$ROOT_DIR/binaries/synergy-testnet-darwin-arm64" "$bin_dir/synergy-testnet-darwin-arm64"
  cp "$ROOT_DIR/binaries/synergy-testnet-windows-amd64.exe" "$bin_dir/synergy-testnet-windows-amd64.exe"
  chmod +x "$bin_dir/synergy-testnet-linux-amd64" "$bin_dir/synergy-testnet-darwin-arm64"
  write_bundle_binary_status "$bundle_dir"
}

sync_installer_bundle_binaries() {
  local installer_root="$ROOT_DIR/testnet/runtime/installers"
  local bundle_dir

  [[ -d "$installer_root" ]] || return 0
  echo "Syncing runtime binaries into installer bundles"
  for bundle_dir in "$installer_root"/*; do
    [[ -d "$bundle_dir" ]] || continue
    sync_bundle_binary_payload "$bundle_dir"
  done
}

sync_bootstrap_bundle_binaries() {
  local bootstrap_root="$ROOT_DIR/../bootstrap-bundles"
  local bundle_dir

  [[ -d "$bootstrap_root" ]] || return 0
  echo "Syncing runtime binaries into bootstrap bundles"
  for bundle_dir in "$bootstrap_root"/bootnode*; do
    [[ -d "$bundle_dir" ]] || continue
    sync_bundle_binary_payload "$bundle_dir"
  done
}

sync_canonical_runtime_assets() {
  local release_env_dir="$ROOT_DIR/testnet/runtime/env-files"
  local canonical_operational_manifest="${SYNERGY_TESTNET_CANONICAL_MANIFEST_FILE:-}"
  if [[ -z "$canonical_operational_manifest" && -n "${SYNERGY_TESTNET_SOURCE_REPO_ROOT:-}" ]]; then
    canonical_operational_manifest="${SYNERGY_TESTNET_SOURCE_REPO_ROOT}/config/operational-manifest.json"
  fi
  if [[ -z "$canonical_operational_manifest" && -f "$ROOT_DIR/testnet-source/config/operational-manifest.json" ]]; then
    canonical_operational_manifest="$ROOT_DIR/testnet-source/config/operational-manifest.json"
  fi
  if [[ -z "$canonical_operational_manifest" ]]; then
    canonical_operational_manifest="$ROOT_DIR/../config/operational-manifest.json"
  fi
  mkdir -p "$release_env_dir"

  echo "Syncing canonical runtime genesis"
  TESTNET_ENV_DIR_RESOLVED="$release_env_dir" \
    SYNERGY_TESTNET_ENV_DIR="$release_env_dir" \
    ./scripts/testnet/generate-testnet-genesis.sh
  [[ -f "$canonical_operational_manifest" ]] || {
    echo "Missing canonical Testnet operational manifest: $canonical_operational_manifest" >&2
    exit 1
  }
  mkdir -p "$ROOT_DIR/testnet/runtime/configs/operational"
  cp "$canonical_operational_manifest" \
    "$ROOT_DIR/testnet/runtime/configs/operational/operational-manifest.json"
  case "${SYNERGY_RELEASE_PRESERVE_COMMITTED_RUNTIME_CONFIGS:-false}" in
    1|true|TRUE|yes|YES)
      echo "Preserving committed canonical Testnet identities"
      ;;
    *)
      echo "Generating canonical Testnet node keys"
      TESTNET_ENV_DIR_RESOLVED="$release_env_dir" \
        SYNERGY_TESTNET_ENV_DIR="$release_env_dir" \
        ./scripts/testnet/generate-node-keys.sh
      ;;
  esac
  echo "Rendering canonical Testnet configs"
  TESTNET_ENV_DIR_RESOLVED="$release_env_dir" \
    SYNERGY_TESTNET_ENV_DIR="$release_env_dir" \
    SYNERGY_TESTNET_CANONICAL_MANIFEST_FILE="$canonical_operational_manifest" \
    ./scripts/testnet/render-configs.sh
  echo "Using committed canonical Testnet installer templates"
}

remove_generated_runtime_identity_files() {
  local keys_root="$ROOT_DIR/testnet/runtime/keys"

  [[ -d "$keys_root" ]] || return 0
  echo "Removing generated local key material from public runtime bundle"
  find "$keys_root" -mindepth 1 -delete
  rmdir "$keys_root"
}

normalize_testnet_operational_manifests() {
  echo "Normalizing Testnet chain and operational manifest metadata"
  python3 - <<'PY' "$ROOT_DIR"
import json
import copy
import os
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
installers_root = root / "testnet/runtime/installers"
runtime_manifest_path = root / "testnet/runtime/configs/operational/operational-manifest.json"
canonical_manifest_candidates = [
    pathlib.Path(value)
    for value in [
        os.environ.get("SYNERGY_TESTNET_CANONICAL_MANIFEST_FILE"),
        os.path.join(os.environ.get("SYNERGY_TESTNET_SOURCE_REPO_ROOT", ""), "config/operational-manifest.json")
            if os.environ.get("SYNERGY_TESTNET_SOURCE_REPO_ROOT") else None,
        root / "testnet-source/config/operational-manifest.json",
        root.parent / "config/operational-manifest.json",
    ]
    if value
]
canonical_manifest_path = next(
    (path for path in canonical_manifest_candidates if path.is_file()),
    canonical_manifest_candidates[-1],
)

def normalize_manifest(manifest):
    if not isinstance(manifest, dict):
        return manifest
    manifest["chain_id"] = 1264
    manifest["chain_id_hex"] = "0x4f0"
    manifest["network_id"] = "synergy-testnet-v3"
    manifest["network_native_id"] = 1264
    return manifest

if not canonical_manifest_path.exists():
    raise SystemExit(f"Missing canonical Testnet operational manifest: {canonical_manifest_path}")
canonical_manifest = normalize_manifest(
    json.loads(canonical_manifest_path.read_text(encoding="utf-8"))
)

for package_path in sorted(installers_root.glob("Validator-*/keys/setup-package.json")):
    package = json.loads(package_path.read_text(encoding="utf-8"))
    package["chain_id"] = 1264
    package["chain_id_hex"] = "0x4f0"
    package["network_id"] = "synergy-testnet-v3"
    package.setdefault("artifacts", {})["operational_manifest"] = copy.deepcopy(canonical_manifest)
    package_path.write_text(json.dumps(package, indent=2) + "\n", encoding="utf-8")

runtime_manifest_path.parent.mkdir(parents=True, exist_ok=True)
runtime_manifest_path.write_text(json.dumps(canonical_manifest, indent=2) + "\n", encoding="utf-8")
PY
}

sync_installer_bundle_configs() {
  local configs_root="$ROOT_DIR/testnet/runtime/configs"
  local installers_root="$ROOT_DIR/testnet/runtime/installers"
  local canonical_fork_migration="$ROOT_DIR/../config/consensus-fork-migration.json"
  local config_path
  local node_id
  local bundle_dir

  [[ -d "$configs_root" && -d "$installers_root" ]] || return 0

  echo "Syncing rendered node configs into installer bundles"
  for config_path in "$configs_root"/*.toml; do
    [[ -f "$config_path" ]] || continue
    node_id="$(basename "$config_path" .toml)"
    bundle_dir="$installers_root/$node_id"
    [[ -d "$bundle_dir" ]] || continue
    mkdir -p "$bundle_dir/config"
    cp "$config_path" "$bundle_dir/config/node.toml"
  done

  python3 - <<'PY' "$installers_root"
import pathlib
import sys

installers_root = pathlib.Path(sys.argv[1])

def network_value(node_toml, key):
    section = None
    for line in node_toml.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            section = stripped.strip("[]")
            continue
        if section != "network" or "=" not in stripped:
            continue
        name, value = stripped.split("=", 1)
        if name.strip() == key:
            return value.strip()
    return "[]"

for node_toml in sorted(installers_root.glob("Validator-0[1-5]/config/node.toml")):
    peers_toml = node_toml.with_name("peers.toml")
    peers_toml.write_text(
        "# Auto-generated for GitHub Actions release packaging\n"
        "[global]\n"
        f"bootnodes = {network_value(node_toml, 'bootnodes')}\n"
        f"seed_servers = {network_value(node_toml, 'seed_servers')}\n"
        f"bootstrap_dns_records = {network_value(node_toml, 'bootstrap_dns_records')}\n"
        f"additional_dial_targets = {network_value(node_toml, 'additional_dial_targets')}\n"
        f"persistent_peers = {network_value(node_toml, 'persistent_peers')}\n\n"
        "[testnet]\n"
        'core_rpc = "https://testnet-rpc.synergy-network.io"\n'
        'core_ws = "wss://testnet-core-ws.synergy-network.io"\n'
        'wallet_api = "https://testnet-wallet-api.synergy-network.io"\n'
        'sxcp_api = "https://testnet-sxcp-api.synergy-network.io"\n\n'
        "[security]\n"
        "strict_tls = true\n"
        "allow_unpinned_dev_endpoints = false\n"
        "bootstrap_connectivity_required = false\n",
        encoding="utf-8",
    )
PY

  if [[ -f "$canonical_fork_migration" ]]; then
    mkdir -p "$configs_root/consensus"
    cp "$canonical_fork_migration" "$configs_root/consensus/consensus-fork-migration.json"
    for bundle_dir in "$installers_root"/*; do
      [[ -d "$bundle_dir" ]] || continue
      mkdir -p "$bundle_dir/config"
      cp "$canonical_fork_migration" "$bundle_dir/config/consensus-fork-migration.json"
    done
  fi

  python3 - <<'PY' "$ROOT_DIR"
import json
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
installers_root = root / "testnet/runtime/installers"

def parse_value(raw):
    raw = raw.strip()
    if raw in ("true", "false"):
        return raw == "true"
    if raw.startswith('"') and raw.endswith('"'):
        return raw[1:-1]
    if raw.startswith("[") and raw.endswith("]"):
        body = raw[1:-1].strip()
        if not body:
            return []
        values = []
        current = []
        in_string = False
        escaped = False
        for char in body:
            if escaped:
                current.append(char)
                escaped = False
                continue
            if char == "\\" and in_string:
                escaped = True
                continue
            if char == '"':
                in_string = not in_string
                continue
            if char == "," and not in_string:
                values.append("".join(current).strip())
                current = []
                continue
            current.append(char)
        values.append("".join(current).strip())
        return values
    try:
        return int(raw)
    except ValueError:
        return raw

def parse_node_toml(path):
    parsed = {}
    section = None
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.startswith("[") and stripped.endswith("]"):
            section = stripped.strip("[]")
            parsed.setdefault(section, {})
            continue
        if "=" not in stripped or section is None:
            continue
        key, value = stripped.split("=", 1)
        parsed.setdefault(section, {})[key.strip()] = parse_value(value)
    return parsed

consensus_keys = [
    "min_validators",
    "validator_vote_threshold",
    "max_validators",
    "status_ready_gate_enabled",
    "status_ready_min_validators",
    "status_ready_genesis_grace_secs",
    "allow_genesis_status_bypass",
    "mesh_settle_secs",
    "leader_timeout_secs",
    "vote_timeout_secs",
    "block_timeout_secs",
    "validator_cluster_size",
    "penalization_enabled",
]
p2p_keys = [
    "enable_discovery",
    "heartbeat_interval",
    "bootstrap_refresh_secs",
    "public_address",
]
network_keys = [
    "additional_dial_targets",
    "persistent_peers",
    "bootnodes",
    "seed_servers",
    "bootstrap_dns_records",
]
node_keys = [
    "auto_register_validator",
    "validator_address",
    "strict_validator_allowlist",
    "allowed_validator_addresses",
]
validator_keys = [
    "participation",
    "verify_quorum_certificates",
    "state_sync_before_join",
]

for package_path in sorted(installers_root.glob("Validator-*/keys/setup-package.json")):
    node_toml = package_path.parents[1] / "config/node.toml"
    if not node_toml.exists():
        continue

    config = parse_node_toml(node_toml)
    package = json.loads(package_path.read_text(encoding="utf-8"))
    package["chain_id"] = 1264
    runtime = package.setdefault("runtime_config", {})

    consensus = config.get("consensus", {})
    runtime["consensus"] = {key: consensus[key] for key in consensus_keys if key in consensus}

    p2p = config.get("p2p", {})
    runtime["p2p"] = {key: p2p[key] for key in p2p_keys if key in p2p}

    network = config.get("network", {})
    runtime["network"] = {key: network.get(key, []) for key in network_keys}

    node = config.get("node", {})
    runtime["node"] = {key: node[key] for key in node_keys if key in node}

    validator = config.get("validator", {})
    existing_validator = runtime.get("validator") or {}
    runtime["validator"] = {
        key: validator.get(key, existing_validator.get(key))
        for key in validator_keys
        if key in validator or key in existing_validator
    }

    package_path.write_text(json.dumps(package, indent=2) + "\n", encoding="utf-8")
PY
}

harden_installer_runtime_wrappers() {
  local installers_root="$ROOT_DIR/testnet/runtime/installers"

  [[ -d "$installers_root" ]] || return 0

  echo "Hardening installer runtime wrappers"
  python3 - <<'PY' "$installers_root" "$ROOT_DIR/testnet/runtime/node-inventory.csv"
import csv
import pathlib
import sys

installers_root = pathlib.Path(sys.argv[1])
inventory_path = pathlib.Path(sys.argv[2])

OLD_MATCH = '[[ "$cmdline" == *"synergy-testnet"* ]] || return 1'
NEW_MATCH = '[[ "$cmdline" == *"/synergy-testnet-linux-amd64"* || "$cmdline" == *"./bin/synergy-testnet-linux-amd64"* ]] || return 1'
EXCLUSIONS = [
    '  [[ "$cmdline" != *"install_and_start.sh"* ]] || return 1',
    '  [[ "$cmdline" != *"nodectl.sh"* ]] || return 1',
    '  [[ "$cmdline" != *"bash -c"* ]] || return 1',
]

for wrapper in list(installers_root.glob("*/nodectl.sh")) + list(installers_root.glob("*/install_and_start.sh")):
    text = wrapper.read_text(encoding="utf-8")
    text = text.replace(OLD_MATCH, NEW_MATCH)
    if EXCLUSIONS[0] not in text:
        text = text.replace(NEW_MATCH, NEW_MATCH + "\n" + "\n".join(EXCLUSIONS))
    wrapper.write_text(text, encoding="utf-8")

for env_file in installers_root.glob("*/node.env"):
    text = env_file.read_text(encoding="utf-8")
    text = text.replace("SYNERGY_NETWORK_ID=1264", "SYNERGY_NETWORK_ID=synergy-testnet-v3")
    env_file.write_text(text, encoding="utf-8")

with inventory_path.open(newline="", encoding="utf-8") as handle:
    inventory = list(csv.DictReader(handle))

def replace_env_value(text, key, value):
    prefix = f"{key}="
    lines = text.splitlines()
    for index, line in enumerate(lines):
        if line.startswith(prefix):
            lines[index] = f"{prefix}{value}"
            return "\n".join(lines) + "\n"
    lines.append(f"{prefix}{value}")
    return "\n".join(lines) + "\n"

for row in inventory:
    if row.get("role_group") != "consensus" or row.get("node_type") != "validator":
        continue
    slot = row["node_slot_id"].strip()
    alias = row["node_alias"].strip()
    bundle_dir = installers_root / slot
    env_file = bundle_dir / "node.env"
    if not env_file.is_file():
        continue
    text = env_file.read_text(encoding="utf-8")
    for key, value in {
        "NODE_SLOT_ID": slot,
        "NODE_ALIAS": alias,
        "NODE_ID": alias,
        "NODE_ROLE": "validator",
        "RPC_FALLBACK_URL": "https://testnet-rpc.synergy-network.io",
    }.items():
        text = replace_env_value(text, key, value)
    env_file.write_text(text, encoding="utf-8")
    for document_name in ("COMMANDS.txt", "README.txt"):
        document = bundle_dir / document_name
        if document.is_file():
            document.write_text(
                document.read_text(encoding="utf-8").replace("Node Slot: GenVal-", "Node Slot: Validator-"),
                encoding="utf-8",
            )
PY
}

resolve_explorer_root() {
  local candidate=""
  local candidates=()

  if [[ -n "${SYNERGY_TESTNET_EXPLORER_APP_ROOT:-}" ]]; then
    candidates+=("${SYNERGY_TESTNET_EXPLORER_APP_ROOT}")
  fi

  candidates+=(
    "$ROOT_DIR/../../synergy-atlas"
    "$ROOT_DIR/../../../synergy-atlas"
    "$ROOT_DIR/../explorer-app"
    "$ROOT_DIR/../../explorer-app"
    "$ROOT_DIR/../../../explorer-app"
  )

  for candidate in "${candidates[@]}"; do
    if [[ -d "$candidate" ]]; then
      (cd "$candidate" && pwd)
      return 0
    fi
  done

  echo "Atlas explorer source not found. Checked: ${candidates[*]}" >&2
  return 1
}

sync_atlas_runtime_bundle() {
  local explorer_root node_exp_bundle frontend_dist_root
  explorer_root="$(resolve_explorer_root)"
  node_exp_bundle="$ROOT_DIR/testnet/runtime/installers/Node-EXP/explorer-app"
  frontend_dist_root="$node_exp_bundle/dist"

  echo "Building Atlas runtime from $explorer_root"
  npm ci --prefix "$explorer_root"
  npm run build --prefix "$explorer_root"

  for package_dir in "$explorer_root/backend" "$explorer_root/indexer"; do
    npm ci --prefix "$package_dir"
    npm run build --prefix "$package_dir"
    npm prune --omit=dev --prefix "$package_dir"
  done

  rm -rf "$node_exp_bundle"
  mkdir -p "$node_exp_bundle/backend" "$node_exp_bundle/indexer"

  rsync -a --delete \
    --exclude '.DS_Store' \
    "$explorer_root/dist/" \
    "$frontend_dist_root/"

  for service_dir in backend indexer; do
    mkdir -p "$node_exp_bundle/$service_dir"
    rsync -a --delete \
      --exclude '.DS_Store' \
      --exclude '.env' \
      "$explorer_root/$service_dir/dist/" \
      "$node_exp_bundle/$service_dir/dist/"
    rsync -a --delete \
      --exclude '.DS_Store' \
      "$explorer_root/$service_dir/migrations/" \
      "$node_exp_bundle/$service_dir/migrations/"
    rsync -a --delete \
      --exclude '.DS_Store' \
      --exclude '.bin' \
      "$explorer_root/$service_dir/node_modules/" \
      "$node_exp_bundle/$service_dir/node_modules/"
    mkdir -p "$node_exp_bundle/$service_dir/scripts"
    cp "$explorer_root/$service_dir/package.json" "$node_exp_bundle/$service_dir/package.json"
    cp "$explorer_root/$service_dir/package-lock.json" "$node_exp_bundle/$service_dir/package-lock.json"
    cp "$explorer_root/$service_dir/.env.example" "$node_exp_bundle/$service_dir/.env.example"
    cp "$explorer_root/$service_dir/scripts/migrate.js" "$node_exp_bundle/$service_dir/scripts/migrate.js"
  done
}

render_public_service_nginx_configs() {
  local rpc_bundle explorer_bundle
  local rpc_host rpc_ws_host rpc_port ws_port
  local explorer_host atlas_api_host indexer_ws_host atlas_api_port indexer_ws_port explorer_static_root

  rpc_bundle="$ROOT_DIR/testnet/runtime/installers/Node-RPC"
  explorer_bundle="$ROOT_DIR/testnet/runtime/installers/Node-EXP"

  # shellcheck disable=SC1090
  source "$rpc_bundle/node.env"
  rpc_host="${HOSTNAME}"
  rpc_ws_host="${RPC_WS_HOSTNAME:-testnet-core-ws.synergy-network.io}"
  rpc_port="${RPC_PORT}"
  ws_port="${WS_PORT}"

  cat > "$rpc_bundle/nginx.conf" <<EOF
# Canonical Testnet RPC gateway reverse proxy.
# Deploy this file on the public RPC host and enable it in nginx.

upstream testnet_rpc_http {
  server 127.0.0.1:${rpc_port};
}

upstream testnet_rpc_ws {
  server 127.0.0.1:${ws_port};
}

server {
  listen 80;
  server_name ${rpc_host} ${rpc_ws_host};
  location ^~ /.well-known/acme-challenge/ {
    root /var/www/letsencrypt;
    default_type "text/plain";
    try_files \$uri =404;
  }
  return 301 https://\$host\$request_uri;
}

server {
  listen 443 ssl http2;
  server_name ${rpc_host};
  ssl_certificate /etc/letsencrypt/live/${rpc_host}/fullchain.pem;
  ssl_certificate_key /etc/letsencrypt/live/${rpc_host}/privkey.pem;
  include /etc/letsencrypt/options-ssl-nginx.conf;
  ssl_dhparam /etc/letsencrypt/ssl-dhparams.pem;

  location = /healthz {
    return 200 "ok\n";
  }

  location / {
    proxy_pass http://testnet_rpc_http;
    proxy_http_version 1.1;
    proxy_set_header Host \$host;
    proxy_set_header X-Real-IP \$remote_addr;
    proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto \$scheme;
    proxy_read_timeout 60s;
    add_header Access-Control-Allow-Origin *;
    add_header Access-Control-Allow-Methods "GET, POST, OPTIONS";
    add_header Access-Control-Allow-Headers "Content-Type";
  }
}

server {
  listen 443 ssl http2;
  server_name ${rpc_ws_host};
  ssl_certificate /etc/letsencrypt/live/${rpc_host}/fullchain.pem;
  ssl_certificate_key /etc/letsencrypt/live/${rpc_host}/privkey.pem;
  include /etc/letsencrypt/options-ssl-nginx.conf;
  ssl_dhparam /etc/letsencrypt/ssl-dhparams.pem;

  location / {
    proxy_pass http://testnet_rpc_ws;
    proxy_http_version 1.1;
    proxy_set_header Upgrade \$http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_set_header Host \$host;
    proxy_read_timeout 3600s;
  }
}
EOF

  # shellcheck disable=SC1090
  source "$explorer_bundle/node.env"
  explorer_host="${EXPLORER_UI_HOSTNAME:-${HOSTNAME}}"
  atlas_api_host="${ATLAS_API_HOSTNAME:-testnet-atlas-api.synergy-network.io}"
  indexer_ws_host="${INDEXER_WS_HOSTNAME:-testnet-indexer.synergy-network.io}"
  atlas_api_port="${EXPLORER_API_PORT:-3020}"
  indexer_ws_port="${INDEXER_WS_PORT:-${WS_PORT}}"
  explorer_static_root="${EXPLORER_STATIC_ROOT:-/opt/synergy/testnet/indexer-explorer/explorer-app/dist}"

  cat > "$explorer_bundle/nginx.conf" <<EOF
# Canonical Testnet Atlas and explorer reverse proxy.
# Deploy this file on the public explorer host and enable it in nginx.

upstream testnet_atlas_api {
  server 127.0.0.1:${atlas_api_port};
}

upstream testnet_indexer_ws {
  server 127.0.0.1:${indexer_ws_port};
}

server {
  listen 80;
  server_name ${explorer_host} ${atlas_api_host} ${indexer_ws_host};
  location ^~ /.well-known/acme-challenge/ {
    root /var/www/letsencrypt;
    default_type "text/plain";
    try_files \$uri =404;
  }
  return 301 https://\$host\$request_uri;
}

server {
  listen 443 ssl http2;
  server_name ${explorer_host};
  ssl_certificate /etc/letsencrypt/live/${explorer_host}/fullchain.pem;
  ssl_certificate_key /etc/letsencrypt/live/${explorer_host}/privkey.pem;
  include /etc/letsencrypt/options-ssl-nginx.conf;
  ssl_dhparam /etc/letsencrypt/ssl-dhparams.pem;

  root ${explorer_static_root};
  index index.html;

  location /api/ {
    proxy_pass http://testnet_atlas_api;
    proxy_http_version 1.1;
    proxy_set_header Host \$host;
    proxy_set_header X-Real-IP \$remote_addr;
    proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto \$scheme;
    proxy_read_timeout 60s;
  }

  location = /healthz {
    proxy_pass http://testnet_atlas_api/healthz;
  }

  location = /readyz {
    proxy_pass http://testnet_atlas_api/readyz;
  }

  location / {
    try_files \$uri \$uri/ /index.html;
  }
}

server {
  listen 443 ssl http2;
  server_name ${atlas_api_host};
  ssl_certificate /etc/letsencrypt/live/${explorer_host}/fullchain.pem;
  ssl_certificate_key /etc/letsencrypt/live/${explorer_host}/privkey.pem;
  include /etc/letsencrypt/options-ssl-nginx.conf;
  ssl_dhparam /etc/letsencrypt/ssl-dhparams.pem;

  location / {
    proxy_pass http://testnet_atlas_api;
    proxy_http_version 1.1;
    proxy_set_header Host \$host;
    proxy_set_header X-Real-IP \$remote_addr;
    proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto \$scheme;
    proxy_read_timeout 60s;
  }
}

server {
  listen 443 ssl http2;
  server_name ${indexer_ws_host};
  ssl_certificate /etc/letsencrypt/live/${explorer_host}/fullchain.pem;
  ssl_certificate_key /etc/letsencrypt/live/${explorer_host}/privkey.pem;
  include /etc/letsencrypt/options-ssl-nginx.conf;
  ssl_dhparam /etc/letsencrypt/ssl-dhparams.pem;

  location / {
    proxy_pass http://testnet_indexer_ws;
    proxy_http_version 1.1;
    proxy_set_header Upgrade \$http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_set_header Host \$host;
    proxy_read_timeout 3600s;
  }
}
EOF
}

# Ensure Unix platform binaries are executable
for binary_path in \
  "$ROOT_DIR/binaries/synergy-testnet-darwin-arm64" \
  "$ROOT_DIR/binaries/synergy-testnet-linux-amd64" \
  "$ROOT_DIR/binaries/synergy-testnet-windows-amd64.exe"
do
  if [[ -f "$binary_path" ]]; then
    case "$binary_path" in
      *.exe) ;;
      *) chmod +x "$binary_path" ;;
    esac
  fi
done

ensure_version_alignment
sync_platform_binaries
refresh_platform_binary_checksums
SYNERGY_SKIP_WORKSPACE_MANIFEST_CHECK=1 npm run test:runtime-version-alignment
sync_canonical_runtime_assets
sync_installer_bundle_configs
harden_installer_runtime_wrappers
sync_installer_bundle_binaries
sync_bootstrap_bundle_binaries
sync_atlas_runtime_bundle
render_public_service_nginx_configs
remove_generated_runtime_identity_files
normalize_testnet_operational_manifests
./scripts/release/generate-workspace-manifest.sh
npm run test:runtime-version-alignment
SKIP_BUNDLED_ASSET_GIT_CLEAN_CHECK=1 ./scripts/release/validate-bundled-assets.sh

npm run build
