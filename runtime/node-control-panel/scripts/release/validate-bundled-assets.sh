#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

host_os="$(uname -s)"

# Reject a stale native Testnet runtime even when its checksum files and the
# generated workspace manifest were refreshed around the wrong binary.
SYNERGY_SKIP_WORKSPACE_MANIFEST_CHECK=1 node scripts/qa/runtime-version-alignment-test.mjs

sha256_file() {
  local file_path="$1"
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$file_path" | awk '{print $1}'
  else
    sha256sum "$file_path" | awk '{print $1}'
  fi
}

# --- Platform binaries ---------------------------------------------------------
# The macOS, Linux, and Windows testnet platform binaries are the bundled
# executables that must exist here. Runtime configs are checked below; ignored key/setup-package
# material must never be required for the public Electron bundle.

unix_binaries=(
  "binaries/synergy-testnet-darwin-arm64"
  "binaries/synergy-testnet-macos-arm64"
  "binaries/synergy-testnet-linux-amd64"
)

windows_binaries=(
  "binaries/synergy-testnet-windows-amd64.exe"
)

required_binaries=("${unix_binaries[@]}" "${windows_binaries[@]}")

for binary_path in "${unix_binaries[@]}"; do
  if [[ ! -f "$binary_path" ]]; then
    echo "Missing platform binary: $binary_path" >&2
    exit 1
  fi
  if [[ ! "$host_os" =~ ^(MINGW|MSYS|CYGWIN) ]] && [[ ! -x "$binary_path" ]]; then
    echo "Platform binary is not executable: $binary_path" >&2
    exit 1
  fi
done

darwin_hash="$(sha256_file binaries/synergy-testnet-darwin-arm64)"
macos_hash="$(sha256_file binaries/synergy-testnet-macos-arm64)"
if [[ "$darwin_hash" != "$macos_hash" ]]; then
  echo "macOS runtime aliases do not contain the same signed release binary" >&2
  exit 1
fi

if [[ -e "testnet/runtime/keys" ]]; then
  echo "Generated runtime key material must not be present in the public bundle" >&2
  exit 1
fi

check_retired_vpn_literals() {
  python3 - <<'PY'
from pathlib import Path
import os
import re
import sys

roots = [
    Path("control-service/src"),
    Path("electron"),
    Path("src"),
    Path("testnet/runtime"),
    Path("scripts/testnet"),
    Path("recipes/validator_vpn.yml"),
]
source_config_extensions = {
    ".bash", ".cfg", ".cjs", ".conf", ".env", ".example", ".ini", ".js",
    ".json", ".jsx", ".mjs", ".plist", ".ps1", ".py", ".rs", ".service",
    ".sh", ".toml", ".ts", ".tsx", ".timer", ".xml", ".yaml", ".yml",
}
documentation_extensions = {".md", ".mdx", ".rst", ".txt"}
ignored_directories = {".git", "node_modules", "target"}
fixture_directories = {"fixture", "fixtures", "test", "tests", "__tests__"}
retired_literal = re.compile(r"10\.69\.")
allowed_retired_source_patterns = {
    Path("control-service/src/innernet.rs"): [
        re.compile(r"does not overlap the retiring 10\.69\.0\.0/16 mesh"),
    ],
}


def candidate_paths(root):
    if not root.exists():
        raise SystemExit(f"Retired VPN literal scan root is missing: {root}")
    if root.is_file():
        return [root]
    return sorted(
        path
        for path in root.rglob("*")
        if path.is_file() and not ignored_directories.intersection(path.parts)
    )


def is_source_or_config(path):
    if path.suffix.lower() in documentation_extensions:
        return False
    return path.suffix.lower() in source_config_extensions or os.access(path, os.X_OK)


def is_fixture(path):
    return bool(fixture_directories.intersection(part.lower() for part in path.parts))


def is_marked_comment(line, marker):
    stripped = line.lstrip()
    return marker in stripped and stripped.startswith(("#", ";", "//", "/*", "*"))


def production_lines(path, lines):
    if path.suffix.lower() != ".rs":
        yield from enumerate(lines, start=1)
        return

    pending_test_module = False
    test_module_depth = None
    for line_number, line in enumerate(lines, start=1):
        stripped = line.strip()
        if test_module_depth is not None:
            test_module_depth += line.count("{") - line.count("}")
            if test_module_depth <= 0:
                test_module_depth = None
            continue
        if stripped == "#[cfg(test)]":
            pending_test_module = True
            continue
        if pending_test_module:
            if re.match(r"^(?:pub(?:\([^)]*\))?\s+)?mod\s+[A-Za-z0-9_]+\s*\{", stripped):
                depth = line.count("{") - line.count("}")
                if depth > 0:
                    test_module_depth = depth
                pending_test_module = False
                continue
            if stripped.startswith("#[") or not stripped:
                continue
            pending_test_module = False
        yield line_number, line


def is_allowed_retired_source(path, line):
    normalized = Path(path.as_posix())
    return any(
        pattern.search(line.strip())
        for pattern in allowed_retired_source_patterns.get(normalized, [])
    )


hits = []
for root in roots:
    for path in candidate_paths(root):
        if not is_source_or_config(path):
            continue
        try:
            contents = path.read_bytes()
            if b"\x00" in contents:
                continue
            lines = contents.decode("utf-8").splitlines()
        except (OSError, UnicodeDecodeError) as error:
            raise SystemExit(f"Unable to inspect release source/config {path}: {error}")

        for line_number, line in production_lines(path, lines):
            if not retired_literal.search(line):
                continue
            if is_allowed_retired_source(path, line):
                continue
            if is_fixture(path) and is_marked_comment(line, "NEGATIVE-TEST-FIXTURE:"):
                continue
            if is_marked_comment(line, "RETIREMENT-DOCUMENTATION:"):
                continue
            hits.append(f"{path}:{line_number}:{line.strip()}")

if hits:
    print(
        "Retired 10.69.* literals found in executable production source/config:",
        file=sys.stderr,
    )
    print("Only NEGATIVE-TEST-FIXTURE comments in fixture paths and "
          "RETIREMENT-DOCUMENTATION comments are permitted.", file=sys.stderr)
    print("\n".join(hits), file=sys.stderr)
    raise SystemExit(1)
PY
}

check_retired_vpn_literals

for binary_path in "${windows_binaries[@]}"; do
  if [[ ! -f "$binary_path" ]]; then
    echo "Missing platform binary: $binary_path" >&2
    exit 1
  fi
done

for binary_path in "${required_binaries[@]}"; do
  checksum_path="${binary_path}.sha256"
  if [[ ! -f "$checksum_path" ]]; then
    echo "Missing platform binary checksum: $checksum_path" >&2
    exit 1
  fi
  expected="$(awk '{print $1}' "$checksum_path")"
  actual="$(sha256_file "$binary_path")"
  if [[ "$expected" != "$actual" ]]; then
    echo "Checksum mismatch for $binary_path: expected $expected got $actual" >&2
    exit 1
  fi
done

# Runtime installer bundles are what the live Control Panel uses to refresh
# node workspaces. Keep them byte-for-byte aligned with the trusted platform
# binaries or the package can silently ship stale per-node runtimes.
for installer_dir in testnet/runtime/installers/*; do
  [[ -d "$installer_dir" ]] || continue
  status_file="$installer_dir/BINARY_STATUS.txt"
  if [[ ! -f "$status_file" ]]; then
    echo "Missing installer binary status: $status_file" >&2
    exit 1
  fi

  installer_binary_names=(
    synergy-testnet-darwin-arm64
    synergy-testnet-linux-amd64
    synergy-testnet-windows-amd64.exe
  )

  for binary_name in "${installer_binary_names[@]}"; do
    top_level_path="binaries/$binary_name"
    installer_path="$installer_dir/bin/$binary_name"
    if [[ ! -f "$installer_path" ]]; then
      echo "Missing installer runtime binary: $installer_path" >&2
      exit 1
    fi
    top_level_hash="$(sha256_file "$top_level_path")"
    installer_hash="$(sha256_file "$installer_path")"
    if [[ "$top_level_hash" != "$installer_hash" ]]; then
      echo "Installer runtime binary drift: $installer_path expected $top_level_hash got $installer_hash" >&2
      exit 1
    fi
    if ! grep -Fqx "Path: ./bin/$binary_name" "$status_file" || ! grep -Fqx "SHA-256: $installer_hash" "$status_file"; then
      echo "Installer binary status drift: $status_file does not describe $binary_name checksum $installer_hash" >&2
      exit 1
    fi
  done
done

if frozen_committee_configs="$(rg -n \
  '^(emergency_stable_committee_mode|freeze_validator_set|freeze_score_weighted_proposer_order) = true$' \
  templates testnet/runtime/installers \
  -g '*.toml' || true)" && [[ -n "$frozen_committee_configs" ]]; then
  echo "Permanent emergency committee freezes are not allowed in shipped validator configuration:" >&2
  printf '%s\n' "$frozen_committee_configs" >&2
  exit 1
fi

# --- Workspace manifest --------------------------------------------------------
if [[ ! -f "testnet/runtime/workspace-manifest.json" ]]; then
  echo "Missing workspace manifest: testnet/runtime/workspace-manifest.json" >&2
  exit 1
fi

missing_manifest_paths="$(python3 - <<'PY'
import json
from pathlib import Path

manifest = json.loads(Path("testnet/runtime/workspace-manifest.json").read_text(encoding="utf-8"))
for relative in manifest.get("required_paths", []):
    if not Path(relative).exists():
        print(relative)
PY
)"
if [[ -n "$missing_manifest_paths" ]]; then
  echo "Workspace manifest required paths are missing from the release bundle:" >&2
  printf '%s\n' "$missing_manifest_paths" >&2
  exit 1
fi

python3 - <<'PY'
import hashlib
import json
from pathlib import Path

package_version = json.loads(Path("package.json").read_text(encoding="utf-8"))["version"]
manifest = json.loads(Path("testnet/runtime/workspace-manifest.json").read_text(encoding="utf-8"))

if manifest.get("app_version") != package_version:
    raise SystemExit(
        f"Workspace manifest app_version {manifest.get('app_version')} does not match package.json {package_version}"
    )

resource_version = str(manifest.get("workspace_resource_version", ""))
if not resource_version.startswith(f"{package_version}+"):
    raise SystemExit(
        f"Workspace resource version {resource_version or 'missing'} does not start with {package_version}+"
    )

for relative in manifest.get("platform_binaries", []):
    path = Path(relative)
    expected = manifest.get("checksums", {}).get(relative)
    if not path.is_file() or not expected:
        raise SystemExit(f"Workspace manifest binary or checksum is missing: {relative}")
    actual = hashlib.sha256(path.read_bytes()).hexdigest()
    if actual != expected:
        raise SystemExit(
            f"Workspace manifest checksum mismatch for {relative}: expected {expected} got {actual}"
        )
PY

# Detect stale manifest (manifest content differs from what the binaries produce).
# This is expected on the very first run after binaries change. CI and release
# prep can skip this git-clean guard because they intentionally regenerate the
# manifest before committing the result.
skip_git_clean_guard="${SKIP_BUNDLED_ASSET_GIT_CLEAN_CHECK:-${ALLOW_DIRTY_BUNDLE_PREP:-0}}"
if [[ "$skip_git_clean_guard" != "1" ]]; then
  BUNDLE_PATHS=(
    testnet/runtime/workspace-manifest.json
    testnet/runtime/configs/operational/operational-manifest.json
  )

  untracked="$(git status --short --untracked-files=all -- "${BUNDLE_PATHS[@]}" | grep '^??' || true)"
  content_diff="$(git diff --ignore-cr-at-eol -- "${BUNDLE_PATHS[@]}" 2>/dev/null || true)"

  if [[ -n "$untracked" || -n "$content_diff" ]]; then
    echo "workspace-manifest.json is stale. Commit it and re-run bundle prep." >&2
    git status --short --untracked-files=all -- "${BUNDLE_PATHS[@]}" >&2 || true
    git diff --ignore-cr-at-eol -- "${BUNDLE_PATHS[@]}" >&2 || true
    exit 1
  fi
fi

# --- Canonical genesis consistency ---------------------------------------------
if [[ -f "testnet-source/config/genesis.json" ]]; then
  canonical_genesis_path="testnet-source/config/genesis.json"
else
  canonical_genesis_path="../config/genesis.json"
fi
runtime_genesis_path="testnet/runtime/configs/genesis/genesis.json"
runtime_operational_manifest_path="testnet/runtime/configs/operational/operational-manifest.json"
runtime_consensus_fork_migration_path="testnet/runtime/configs/consensus/consensus-fork-migration.json"
installer_genesis_path="testnet/runtime/installers/Validator-01/config/genesis.json"
installer_peers_path="testnet/runtime/installers/Validator-01/config/peers.toml"
installer_consensus_fork_migration_path="testnet/runtime/installers/Validator-01/config/consensus-fork-migration.json"

for required_path in \
  "$canonical_genesis_path" \
  "$runtime_genesis_path" \
  "$runtime_operational_manifest_path" \
  "$runtime_consensus_fork_migration_path" \
  "$installer_genesis_path" \
  "$installer_peers_path" \
  "$installer_consensus_fork_migration_path"
do
  if [[ ! -f "$required_path" ]]; then
    echo "Missing genesis consistency input: $required_path" >&2
    exit 1
  fi
done

if [[ -f "../config/consensus-fork-migration.json" ]]; then
  if ! cmp -s "../config/consensus-fork-migration.json" "$runtime_consensus_fork_migration_path"; then
    echo "Runtime consensus fork migration does not match canonical ../config/consensus-fork-migration.json" >&2
    exit 1
  fi
  if ! cmp -s "../config/consensus-fork-migration.json" "$installer_consensus_fork_migration_path"; then
    echo "Installer consensus fork migration does not match canonical ../config/consensus-fork-migration.json" >&2
    exit 1
  fi
fi

read_json_hash() {
  python3 - <<'PY' "$1" "$2"
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
data = json.loads(path.read_text(encoding="utf-8"))
value = data.get("integrity", {}).get("genesis_hash", "")
print(value, end="")
PY
}

canonical_genesis_hash="$(read_json_hash "$canonical_genesis_path" plain)"
runtime_genesis_hash="$(read_json_hash "$runtime_genesis_path" plain)"
installer_genesis_hash="$(read_json_hash "$installer_genesis_path" plain)"

if [[ -z "$canonical_genesis_hash" ]]; then
  echo "Canonical genesis hash missing from $canonical_genesis_path" >&2
  exit 1
fi

for candidate in \
  "$runtime_genesis_hash" \
  "$installer_genesis_hash"
do
  if [[ "$candidate" != "$canonical_genesis_hash" ]]; then
    cat >&2 <<EOF
Bundled genesis drift detected.
  canonical:      $canonical_genesis_hash
  runtime:        $runtime_genesis_hash
  installer:      $installer_genesis_hash
EOF
    exit 1
  fi
done

if ! rg -q '"chain_id"[[:space:]]*:[[:space:]]*1266' "$runtime_operational_manifest_path"; then
  echo "Runtime operational manifest is not pinned to chain_id 1266" >&2
  exit 1
fi

if ! rg -q '"chain_id_hex"[[:space:]]*:[[:space:]]*"0x4f2"' "$runtime_operational_manifest_path"; then
  echo "Runtime operational manifest is not pinned to chain_id_hex 0x4f2" >&2
  exit 1
fi

if ! rg -q '"network_id"[[:space:]]*:[[:space:]]*"synergy-testnet-v3"' "$runtime_operational_manifest_path"; then
  echo "Runtime operational manifest is not pinned to network_id synergy-testnet-v3" >&2
  exit 1
fi

if ! rg -q '"network_id"[[:space:]]*:[[:space:]]*"synergy-testnet-v3"' "testnet/runtime/workspace-manifest.json"; then
  echo "Workspace manifest is not pinned to network_id synergy-testnet-v3" >&2
  exit 1
fi

if ! rg -q '"chain_id_hex"[[:space:]]*:[[:space:]]*"0x4f2"' "testnet/runtime/workspace-manifest.json"; then
  echo "Workspace manifest is not pinned to chain_id_hex 0x4f2" >&2
  exit 1
fi

validator_vpn_env_path="testnet/runtime/validator-vpn/validator-vpn-coordinator.env"
if [[ ! -f "$validator_vpn_env_path" ]]; then
  echo "Missing packaged validator VPN coordinator env: $validator_vpn_env_path" >&2
  exit 1
fi

if ! rg -q '^SYNERGY_VALIDATOR_VPN_COORDINATOR_URL=https://vpn-coordinator\.synergy-network\.io$' "$validator_vpn_env_path"; then
  echo "Packaged validator VPN coordinator env is missing the public coordinator URL" >&2
  exit 1
fi

if ! rg -q '^SYNERGY_VALIDATOR_VPN_ENROLLMENT_SIGNATURE_MODE=challenge-sha256$' "$validator_vpn_env_path"; then
  echo "Packaged validator VPN coordinator env is missing challenge-sha256 enrollment mode" >&2
  exit 1
fi

if ! rg -q '^SYNERGY_VALIDATOR_VPN_COORDINATOR_PUBLIC_KEY=ed25519:[A-Za-z0-9+/=]+$' "$validator_vpn_env_path"; then
  echo "Packaged validator VPN coordinator env is missing the Ed25519 public verifier key" >&2
  exit 1
fi

if ! rg -q '^SYNERGY_INNERNET_COORDINATOR_PUBLIC_KEY=ed25519:[A-Za-z0-9+/=]+$' "$validator_vpn_env_path"; then
  echo "Packaged coordinator env is missing the Innernet Ed25519 receipt verifier key" >&2
  exit 1
fi

if rg -q 'SYNERGY_VALIDATOR_VPN_COORDINATOR_(TOKEN|SIGNING_KEY)=' "$validator_vpn_env_path"; then
  echo "Packaged validator VPN coordinator env must not contain coordinator token or signing key secrets" >&2
  exit 1
fi

if [[ ! -f "scripts/testnet/validator-vpn-agent.sh" ]]; then
  echo "Missing validator VPN agent helper: scripts/testnet/validator-vpn-agent.sh" >&2
  exit 1
fi

stale_identity_hits="$(rg -l --hidden --glob '!.git/**' --glob '!node_modules/**' --glob '!dist/**' --glob '!electron-dist/**' --glob '!build/**' --glob '!*.log' \
  'Chain 1262|Chain 1263|chain_id[[:space:]]*[:=][[:space:]]*1262|chain_id[[:space:]]*[:=][[:space:]]*1263|0x4ee|0x4ef' \
  testnet/runtime scripts/testnet scripts/reset-testnet.sh binaries 2>/dev/null || true)"
if [[ -n "$stale_identity_hits" ]]; then
  echo "Stale chain-1262/chain-1263 identity material is present in deployable artifacts:" >&2
  printf '%s\n' "$stale_identity_hits" >&2
  exit 1
fi

if ! rg -q '"private_host"[[:space:]]*:[[:space:]]*"10\.70\.20\.1"' "$runtime_operational_manifest_path"; then
  echo "Runtime operational manifest is missing canonical relayer-1 private host 10.70.20.1" >&2
  exit 1
fi

if rg -q '10\.69\.(0|10)\.' "$runtime_operational_manifest_path"; then
  echo "Runtime operational manifest contains retired 10.69 validator or relayer routes" >&2
  exit 1
fi

if ! rg -q '"public_ip"[[:space:]]*:[[:space:]]*"195\.26\.241\.95"' "$runtime_operational_manifest_path"; then
  echo "Runtime operational manifest is missing relayer-1 public IP 195.26.241.95" >&2
  exit 1
fi

python3 - "$runtime_operational_manifest_path" <<'PY'
import csv
import json
import pathlib
import re
import sys

manifest = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
root = pathlib.Path("testnet/runtime")
address_file = root / "node-addresses.csv"
with address_file.open(newline="", encoding="utf-8") as handle:
    addresses = {
        row["node_slot_id"]: (row.get("address") or "").strip()
        for row in csv.DictReader(handle)
    }

sentries = manifest.get("bootstrap", {}).get("sentries", [])
expected_sentry_hosts = ["10.70.20.1", "10.70.20.2", "10.70.20.3"]
actual_sentry_hosts = [entry.get("private_host") for entry in sentries]
if actual_sentry_hosts != expected_sentry_hosts:
    raise SystemExit(
        f"operational manifest relayer routes mismatch: expected {expected_sentry_hosts}, got {actual_sentry_hosts}"
    )

def section_value(path, section, key):
    current = None
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if line.startswith("[") and line.endswith("]"):
            current = line.strip("[]")
            continue
        if current == section:
            match = re.fullmatch(rf'{re.escape(key)}\s*=\s*"([^"]+)"', line)
            if match:
                return match.group(1)
    return None

for validator in manifest.get("validators", []):
    label = validator["label"]
    expected = validator["address"]
    expected_host = f"10.70.10.{validator['slot']}"
    if validator.get("private_host") != expected_host:
        raise SystemExit(
            f"operational manifest {label} route mismatch: expected {expected_host}, got {validator.get('private_host')}"
        )
    if addresses.get(label) != expected:
        raise SystemExit(
            f"{address_file} identity mismatch for {label}: expected {expected}, got {addresses.get(label)}"
        )
    paths = [root / "configs" / f"{label}.toml"]
    installer_path = root / "installers" / label / "config/node.toml"
    if installer_path.exists():
        paths.append(installer_path)
    for path in paths:
        identity = section_value(path, "identity", "address")
        node_address = section_value(path, "node", "validator_address")
        if identity != expected or node_address != expected:
            raise SystemExit(
                f"{path} identity mismatch: expected {expected}, identity={identity}, validator_address={node_address}"
            )

for label in ["Node-REL1", "Node-REL2", "Node-REL3", "Node-RPC", "Node-EXP"]:
    path = root / "configs" / f"{label}.toml"
    identity = section_value(path, "identity", "address")
    if not identity or not identity.startswith("synv"):
        raise SystemExit(f"{path} has invalid generated node identity: {identity}")
    if addresses.get(label) != identity:
        raise SystemExit(
            f"{address_file} identity mismatch for {label}: expected {identity}, got {addresses.get(label)}"
        )

for label in ["Node-REL1", "Node-REL2", "Node-REL3", "Node-RPC", "Node-EXP"]:
    path = root / "configs" / f"{label}.toml"
    validator_address = section_value(path, "node", "validator_address")
    if validator_address not in (None, ""):
        raise SystemExit(
            f"{path} must not use the relayer identity as a validator address: {validator_address}"
        )

PY

if ! rg -q '^[[:space:]]*persistent_peers[[:space:]]*=' "$installer_peers_path"; then
  echo "Bundled peers.toml is missing global.persistent_peers" >&2
  exit 1
fi

if ! rg -q '^[[:space:]]*persistent_peers[[:space:]]*=' "testnet/runtime/installers/Validator-01/config/node.toml"; then
  echo "Bundled validator node.toml is missing network.persistent_peers" >&2
  exit 1
fi

if ! rg -q '^[[:space:]]*strict_validator_allowlist[[:space:]]*=[[:space:]]*false' "testnet/runtime/installers/Validator-01/config/node.toml"; then
  echo "Bundled validator node.toml is missing strict_validator_allowlist = false" >&2
  exit 1
fi

if ! rg -q '^[[:space:]]*allowed_validator_addresses[[:space:]]*=' "testnet/runtime/installers/Validator-01/config/node.toml"; then
  echo "Bundled validator node.toml is missing allowed_validator_addresses" >&2
  exit 1
fi

if ! rg -q '^[[:space:]]*status_ready_gate_enabled[[:space:]]*=[[:space:]]*true' "testnet/runtime/installers/Validator-01/config/node.toml"; then
  echo "Bundled validator node.toml is missing status_ready_gate_enabled = true" >&2
  exit 1
fi

if ! rg -q '^[[:space:]]*leader_timeout_secs[[:space:]]*=[[:space:]]*4' "testnet/runtime/installers/Validator-01/config/node.toml"; then
  echo "Bundled validator node.toml is missing leader_timeout_secs = 4" >&2
  exit 1
fi

if ! rg -q '^[[:space:]]*vote_timeout_secs[[:space:]]*=[[:space:]]*2' "testnet/runtime/installers/Validator-01/config/node.toml"; then
  echo "Bundled validator node.toml is missing vote_timeout_secs = 2" >&2
  exit 1
fi

if ! rg -q '^[[:space:]]*bootstrap_refresh_secs[[:space:]]*=[[:space:]]*3600' "testnet/runtime/installers/Validator-01/config/node.toml"; then
  echo "Bundled validator node.toml is missing bootstrap_refresh_secs = 3600" >&2
  exit 1
fi

if ! rg -q '^[[:space:]]*state_sync_before_join[[:space:]]*=[[:space:]]*true' "testnet/runtime/installers/Validator-01/config/node.toml"; then
  echo "Bundled validator node.toml is missing state_sync_before_join = true" >&2
  exit 1
fi

if ! rg -q '^[[:space:]]*bootnodes[[:space:]]*=[[:space:]]*\[\]' "testnet/runtime/installers/Validator-01/config/node.toml"; then
  echo "Bundled validator node.toml must not include bootnodes" >&2
  exit 1
fi

required_atlas_paths=(
  "testnet/runtime/installers/Node-RPC/nginx.conf"
  "testnet/runtime/installers/Node-EXP/nginx.conf"
  "testnet/runtime/installers/Node-EXP/explorer-app/dist/index.html"
  "testnet/runtime/installers/Node-EXP/explorer-app/dist/assets"
  "testnet/runtime/installers/Node-EXP/explorer-app/backend/dist"
  "testnet/runtime/installers/Node-EXP/explorer-app/backend/scripts/migrate.js"
  "testnet/runtime/installers/Node-EXP/explorer-app/backend/migrations"
  "testnet/runtime/installers/Node-EXP/explorer-app/backend/node_modules/fastify/package.json"
  "testnet/runtime/installers/Node-EXP/explorer-app/indexer/dist"
  "testnet/runtime/installers/Node-EXP/explorer-app/indexer/scripts/migrate.js"
  "testnet/runtime/installers/Node-EXP/explorer-app/indexer/migrations"
  "testnet/runtime/installers/Node-EXP/explorer-app/indexer/node_modules/pg/package.json"
)

for required_path in "${required_atlas_paths[@]}"; do
  if [[ ! -e "$required_path" ]]; then
    echo "Missing bundled Atlas/runtime asset: $required_path" >&2
    exit 1
  fi
done

# Public release artifacts must never carry validator/wallet private material.
# Print file names only; never print matching lines or values.
secret_name_hits="$(find testnet/runtime -type f \( \
    -iname 'private.key' -o \
    -iname 'identity.json' -o \
    -iname 'identity.toml' -o \
    -iname '*mnemonic*' -o \
    -iname '*secret*' \
  \) -print 2>/dev/null || true)"
if [[ -n "$secret_name_hits" ]]; then
  echo "Secret-shaped files are present in bundled Testnet runtime artifacts:" >&2
  printf '%s\n' "$secret_name_hits" >&2
  exit 1
fi

secret_field_hits="$(rg -l --pcre2 -i '(^|["[:space:]_])(private[_-]?key|secret[_-]?key|mnemonic|seed[_-]?phrase|recovery[_-]?phrase|\\bsk\\b|\\bpriv\\b)["[:space:]]*[:=]' \
  testnet/runtime/configs \
  testnet/runtime/installers/*/config \
  testnet/runtime/installers/*/keys \
  testnet/runtime/installers/*/node.env \
  testnet/runtime/node-inventory.csv \
  testnet/runtime/hosts.env.example \
  testnet/runtime/workspace-manifest.json 2>/dev/null || true)"
if [[ -n "$secret_field_hits" ]]; then
  echo "Secret-shaped fields are present in bundled Testnet public artifacts:" >&2
  printf '%s\n' "$secret_field_hits" >&2
  exit 1
fi

env_secret_value_hits="$(python3 - <<'PY'
from pathlib import Path

secret_key_parts = ("PASSWORD", "SECRET", "TOKEN", "PRIVATE", "CREDENTIAL", "MNEMONIC", "SEED")
for path in sorted(Path("testnet/runtime/installers").glob("*/node.env")):
    for raw in path.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        if any(part in key.upper() for part in secret_key_parts) and value.strip():
            print(f"{path}:{key}")
PY
)"
if [[ -n "$env_secret_value_hits" ]]; then
  echo "Secret-shaped environment values are present in bundled Testnet public artifacts:" >&2
  printf '%s\n' "$env_secret_value_hits" >&2
  exit 1
fi

if rg -q '^DATABASE_URL=postgres://[^/@:]+:[^/@]+@' "testnet/runtime/installers/Node-EXP/node.env"; then
  echo "Bundled Node-EXP node.env must not embed database credentials in DATABASE_URL" >&2
  exit 1
fi

if ! rg -q '^DATABASE_URL=$' "testnet/runtime/installers/Node-EXP/node.env"; then
  echo "Bundled Node-EXP node.env must leave DATABASE_URL empty for operator injection" >&2
  exit 1
fi

if ! rg -q '^POSTGRES_PASSWORD=$' "testnet/runtime/installers/Node-EXP/node.env"; then
  echo "Bundled Node-EXP node.env must leave POSTGRES_PASSWORD empty for operator injection" >&2
  exit 1
fi

if ! rg -q '^INDEXER_WS_HOSTNAME=testnet-indexer\.synergy-network\.io$' "testnet/runtime/installers/Node-EXP/node.env"; then
  echo "Bundled Node-EXP node.env is missing the canonical INDEXER_WS_HOSTNAME" >&2
  exit 1
fi

python3 - <<'PY'
import csv
from pathlib import Path

inventory_path = Path("testnet/runtime/node-inventory.csv")
installers_root = Path("testnet/runtime/installers")

with inventory_path.open(newline="", encoding="utf-8") as handle:
    rows = list(csv.DictReader(handle))

failures = []
for row in rows:
    if row.get("role_group") != "consensus" or row.get("node_type") != "validator":
        continue
    slot = row["node_slot_id"]
    expected_public_ip = row.get("public_ip", "").strip()
    installer_dir = installers_root / slot
    if not installer_dir.is_dir():
        # Onboarded validators are operational inventory entries,
        # not legacy GenVal setup packages. Only validate bundles that exist.
        continue
    env_path = installers_root / slot / "node.env"
    if not env_path.is_file():
        failures.append(f"{slot}: missing {env_path}")
        continue
    env = {}
    for raw_line in env_path.read_text(encoding="utf-8").splitlines():
        if not raw_line or raw_line.lstrip().startswith("#") or "=" not in raw_line:
            continue
        key, value = raw_line.split("=", 1)
        env[key] = value
    for key in ["PUBLIC_IP", "NODE_PUBLIC_IP", "MONITOR_HOST", "MANAGEMENT_HOST", "ADVERTISE_IP"]:
        actual = env.get(key, "").strip()
        if actual != expected_public_ip:
            failures.append(
                f"{slot}: {key}={actual or '<missing>'} does not match inventory public_ip={expected_public_ip}"
            )

if failures:
    print("Bundled validator installer node.env files are not aligned with node-inventory.csv:", file=__import__("sys").stderr)
    for failure in failures:
        print(f"  - {failure}", file=__import__("sys").stderr)
    raise SystemExit(1)
PY

if ! rg -q 'server_name testnet-core-rpc\.synergy-network\.io' "testnet/runtime/installers/Node-RPC/nginx.conf"; then
  echo "Bundled Node-RPC nginx.conf is missing the canonical RPC hostname" >&2
  exit 1
fi

if ! rg -q 'server_name testnet-core-ws\.synergy-network\.io' "testnet/runtime/installers/Node-RPC/nginx.conf"; then
  echo "Bundled Node-RPC nginx.conf is missing the canonical WS hostname" >&2
  exit 1
fi

for expected_host in \
  'testnet-explorer.synergy-network.io' \
  'testnet-atlas-api.synergy-network.io' \
  'testnet-indexer.synergy-network.io'
do
  if ! rg -q "server_name ${expected_host}" "testnet/runtime/installers/Node-EXP/nginx.conf"; then
    echo "Bundled Node-EXP nginx.conf is missing ${expected_host}" >&2
    exit 1
  fi
done

echo "Bundled assets validated."
