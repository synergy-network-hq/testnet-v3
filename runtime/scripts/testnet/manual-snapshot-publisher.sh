#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
manual-snapshot-publisher.sh \
  --snapshot-root <dir> \
  --snapshot-manifest <manifest.json> \
  --snapshot-class <validator-pruned|support-relayer|support-rpc|support-observer|indexer-full|indexer-replay|archive-full|archive-bootstrap> \
  --allowed-role <role> [--allowed-role <role> ...] \
  --out <dir> \
  --source-node <node-id> \
  --runtime <synergy-testnet-linux-amd64> \
  --runtime-sha <sha256> \
  [--source-workspace <node-workspace>] \
  [--source-config <node-config.toml>] \
  [--min-runtime-version <version>] \
  [--chunk-size 512M]
USAGE
}

snapshot_root=""
snapshot_manifest=""
snapshot_class=""
out_dir=""
source_node=""
runtime=""
runtime_sha=""
source_workspace=""
source_config=""
min_runtime_version=""
chunk_size="512M"
allowed_roles=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --snapshot-root) snapshot_root="$2"; shift 2 ;;
    --snapshot-manifest) snapshot_manifest="$2"; shift 2 ;;
    --snapshot-class) snapshot_class="$2"; shift 2 ;;
    --allowed-role) allowed_roles+=("$2"); shift 2 ;;
    --out) out_dir="$2"; shift 2 ;;
    --source-node) source_node="$2"; shift 2 ;;
    --runtime) runtime="$2"; shift 2 ;;
    --runtime-sha) runtime_sha="$2"; shift 2 ;;
    --source-workspace) source_workspace="$2"; shift 2 ;;
    --source-config) source_config="$2"; shift 2 ;;
    --min-runtime-version) min_runtime_version="$2"; shift 2 ;;
    --chunk-size) chunk_size="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

case "$snapshot_class" in
  validator-pruned|support-relayer|support-rpc|support-observer|indexer-full|indexer-replay|archive-full|archive-bootstrap|archive-validator-bootstrap) ;;
  *) echo "invalid or missing --snapshot-class" >&2; exit 2 ;;
esac

if [[ -z "$snapshot_root" || -z "$snapshot_manifest" || -z "$out_dir" || -z "$source_node" || -z "$runtime" || -z "$runtime_sha" ]]; then
  usage >&2
  exit 2
fi
if [[ "${#allowed_roles[@]}" -eq 0 ]]; then
  echo "at least one --allowed-role is required" >&2
  exit 2
fi
if [[ ! -d "$snapshot_root" || ! -f "$snapshot_manifest" || ! -x "$runtime" ]]; then
  echo "snapshot root, manifest, or runtime is not accessible" >&2
  exit 3
fi

command -v zstd >/dev/null
command -v split >/dev/null
command -v sha256sum >/dev/null

actual_runtime_sha="$(sha256sum "$runtime" | awk '{print $1}')"
if [[ "$actual_runtime_sha" != "$runtime_sha" ]]; then
  echo "runtime sha mismatch: expected $runtime_sha got $actual_runtime_sha" >&2
  exit 4
fi

mkdir -p "$out_dir"
snapshot_name="$(basename "$snapshot_root")"
archive="$out_dir/${snapshot_name}.${snapshot_class}.tar.zst"

verify_args=(
  --chain-id 1264
  --network-id synergy-testnet-v3
  --genesis-hash f79011f2aaddd40b120d47ba723104fafe3c998d4a17097fae018914b95f1789
)
if [[ -n "$source_workspace" ]]; then
  verify_args+=(--source-workspace "$source_workspace")
fi
if [[ -n "$source_config" ]]; then
  verify_args+=(--config "$source_config")
fi
verify_args+=(--manifest "$snapshot_manifest" --snapshot-root "$snapshot_root")
verify_args+=(--snapshot-class "$snapshot_class" --target-role "${allowed_roles[0]}")

(
  if [[ -n "$source_workspace" ]]; then
    cd "$source_workspace"
  fi
  if [[ -n "$source_config" ]]; then
    export SYNERGY_CONFIG_PATH="$source_config"
  elif [[ -n "$source_workspace" ]]; then
    export SYNERGY_CONFIG_PATH="$source_workspace/config/node.toml"
  fi
  if [[ -n "$source_workspace" ]]; then
    export SYNERGY_PROJECT_ROOT="$source_workspace"
  fi
  "$runtime" verify-snapshot "${verify_args[@]}"
) > "$out_dir/source-verify-snapshot.json"
python3 - "$out_dir/source-verify-snapshot.json" <<'PY'
import json
import sys
from pathlib import Path

result = json.loads(Path(sys.argv[1]).read_text())
if result.get("success") is not True:
    raise SystemExit("source verify-snapshot did not report success=true")
PY

tar -C "$(dirname "$snapshot_root")" -cf - "$snapshot_name" \
  | zstd -T0 -3 --long=27 -f -o "$archive"

rm -f "$archive.part-"*
split -b "$chunk_size" -d -a 5 "$archive" "$archive.part-"
(
  cd "$out_dir"
  sha256sum "$(basename "$archive").part-"* > "${snapshot_name}.${snapshot_class}.chunks.sha256"
  sha256sum "$(basename "$archive")" > "${snapshot_name}.${snapshot_class}.tar.zst.sha256"
)
zstd -t "$archive"

python3 - "$out_dir" "$snapshot_name" "$snapshot_class" "$source_node" "$runtime_sha" "$min_runtime_version" "$snapshot_manifest" "$archive" "${allowed_roles[@]}" <<'PY'
import hashlib
import json
import sys
from pathlib import Path

out_dir = Path(sys.argv[1])
snapshot_name = sys.argv[2]
snapshot_class = sys.argv[3]
source_node = sys.argv[4]
runtime_sha = sys.argv[5]
min_runtime_version = sys.argv[6]
snapshot_manifest = Path(sys.argv[7])
archive = Path(sys.argv[8])
allowed_roles = sys.argv[9:]

signed = json.loads(snapshot_manifest.read_text())
manifest = signed.get("manifest", signed)
parts = []
for part in sorted(out_dir.glob(f"{snapshot_name}.{snapshot_class}.tar.zst.part-*")):
    digest = hashlib.sha256(part.read_bytes()).hexdigest()
    parts.append({
        "name": part.name,
        "size_bytes": part.stat().st_size,
        "sha256": digest,
    })

distribution = {
    "schema": "synergy-temporary-snapshot-distribution-v1",
    "snapshot_class": snapshot_class,
    "allowed_restore_roles": allowed_roles,
    "snapshot_name": snapshot_name,
    "snapshot_height": manifest.get("snapshot_height"),
    "snapshot_block_hash": manifest.get("snapshot_block_hash"),
    "canonical_lock_height": manifest.get("canonical_lock_height"),
    "canonical_lock_hash": manifest.get("canonical_lock_hash"),
    "committed_qc_height": manifest.get("qc_evidence", {}).get("committed_qc_height"),
    "committed_qc_hash": manifest.get("qc_evidence", {}).get("committed_qc_hash"),
    "qc_vote_count": manifest.get("qc_evidence", {}).get("vote_count"),
    "qc_signers": manifest.get("qc_evidence", {}).get("signer_set"),
    "active_validator_set": manifest.get("active_validator_set"),
    "quorum_threshold": manifest.get("quorum_threshold"),
    "chain_id": manifest.get("chain_id"),
    "network_id": manifest.get("network_id"),
    "genesis_hash": manifest.get("genesis_hash"),
    "producer_identity": source_node,
    "runtime_sha256": runtime_sha,
    "minimum_runtime_version": min_runtime_version or None,
    "source_manifest": snapshot_manifest.name,
    "source_manifest_sha256": hashlib.sha256(snapshot_manifest.read_bytes()).hexdigest(),
    "archive_name": archive.name,
    "archive_size_bytes": archive.stat().st_size,
    "archive_sha256": hashlib.sha256(archive.read_bytes()).hexdigest(),
    "compression": {"type": "zstd", "level": 3, "long": 27},
    "chunk_size_bytes": 512 * 1024 * 1024,
    "chunks": parts,
    "safety": {
        "h175518_contamination_rejected": True,
        "wrong_class_restore_rejected_by_receiver": True,
        "keys_configs_genesis_quorum_excluded": True,
        "relayers_rpc_support_counted_toward_quorum": False,
    },
}
(out_dir / "distribution-manifest.json").write_text(json.dumps(distribution, indent=2, sort_keys=True) + "\n")
print(json.dumps(distribution, indent=2, sort_keys=True))
PY

echo "snapshot_distribution_ready=$out_dir"
