#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
apply-verified-support-snapshot.sh \
  --distribution-manifest <distribution-manifest.json> \
  --snapshot-root <extracted-snapshot-root> \
  --snapshot-class <support-relayer|support-rpc|support-observer|indexer-replay|indexer-full|archive-full|archive-bootstrap> \
  --target-role <relayer|rpc|observer|indexer|archive|archive_validator> \
  --target-data-dir <data-dir> \
  --evidence-path <dir> \
  --rollback-path <dir> \
  --confirm-target-stopped
USAGE
}

distribution_manifest=""
snapshot_root=""
snapshot_class=""
target_role=""
target_data_dir=""
evidence_path=""
rollback_path=""
confirm_target_stopped=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    --distribution-manifest) distribution_manifest="$2"; shift 2 ;;
    --snapshot-root) snapshot_root="$2"; shift 2 ;;
    --snapshot-class) snapshot_class="$2"; shift 2 ;;
    --target-role) target_role="$2"; shift 2 ;;
    --target-data-dir) target_data_dir="$2"; shift 2 ;;
    --evidence-path) evidence_path="$2"; shift 2 ;;
    --rollback-path) rollback_path="$2"; shift 2 ;;
    --confirm-target-stopped) confirm_target_stopped=true; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

if [[ -z "$distribution_manifest" || -z "$snapshot_root" || -z "$snapshot_class" || -z "$target_role" || -z "$target_data_dir" || -z "$evidence_path" || -z "$rollback_path" ]]; then
  usage >&2
  exit 2
fi
if [[ "$confirm_target_stopped" != "true" ]]; then
  echo "refusing support snapshot apply without --confirm-target-stopped" >&2
  exit 3
fi
case "$snapshot_class:$target_role" in
  support-relayer:relayer|support-rpc:rpc|support-observer:observer|indexer-replay:indexer|indexer-full:indexer|archive-full:archive|archive-full:archive_validator|archive-bootstrap:archive|archive-bootstrap:archive_validator) ;;
  *) echo "snapshot class $snapshot_class is not compatible with target role $target_role" >&2; exit 4 ;;
esac
if [[ ! -f "$distribution_manifest" || ! -d "$snapshot_root" || ! -d "$target_data_dir" ]]; then
  echo "manifest, snapshot root, or target data dir is missing" >&2
  exit 5
fi

mkdir -p "$evidence_path/target-before" "$evidence_path/source" "$rollback_path"

sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1"
  else
    shasum -a 256 "$1"
  fi
}

python3 - "$distribution_manifest" "$snapshot_root" "$snapshot_class" "$target_role" <<'PY'
import json
import sys
from pathlib import Path

payload = json.loads(Path(sys.argv[1]).read_text())
manifest = payload.get("manifest", payload)
snapshot_root = Path(sys.argv[2])
snapshot_class = sys.argv[3]
target_role = sys.argv[4]
if manifest.get("snapshot_class") != snapshot_class:
    raise SystemExit("distribution snapshot class mismatch")
allowed_roles = manifest.get("allowed_restore_roles") or manifest.get("allowed_roles") or []
if target_role not in allowed_roles:
    raise SystemExit("target role not allowed by distribution manifest")
if manifest.get("chain_id") != 1264:
    raise SystemExit("wrong chain_id")
if manifest.get("network_id") != "synergy-testnet-v3":
    raise SystemExit("wrong network_id")
if manifest.get("genesis_hash") != "f79011f2aaddd40b120d47ba723104fafe3c998d4a17097fae018914b95f1789":
    raise SystemExit("wrong genesis_hash")
qc_vote_count = manifest.get("qc_vote_count")
if qc_vote_count is None:
    qc_vote_count = (manifest.get("qc_evidence") or {}).get("vote_count")
active_validator_set = manifest.get("active_validator_set") or (manifest.get("consensus_fork") or {}).get("new_validator_registry") or []
manifest_quorum = int(manifest.get("quorum_threshold") or 0)
if active_validator_set:
    dynamic_quorum = ((len(active_validator_set) * 2) + 2) // 3
elif manifest_quorum:
    dynamic_quorum = manifest_quorum
else:
    raise SystemExit("snapshot is missing active validator set and quorum threshold")
required_quorum = manifest_quorum or dynamic_quorum or 1
if (qc_vote_count or 0) < required_quorum:
    raise SystemExit(f"QC vote count below quorum: {qc_vote_count or 0} < {required_quorum}")
snapshot_height = manifest.get("snapshot_height", manifest.get("height"))
snapshot_block_hash = manifest.get("snapshot_block_hash", manifest.get("hash"))
if snapshot_height is None or not snapshot_block_hash:
    raise SystemExit("snapshot height/hash missing")
for name in ["chain.json", "canonical_locks.json", "committed_blocks.jsonl", "committed_qcs.jsonl", "validator_registry.json", "token_state.json"]:
    if not (snapshot_root / name).exists():
        raise SystemExit(f"snapshot missing required state file: {name}")
print(json.dumps({
    "support_snapshot_manifest_accepted": True,
    "snapshot_class": snapshot_class,
    "target_role": target_role,
    "snapshot_height": int(snapshot_height),
    "snapshot_block_hash": snapshot_block_hash,
}, sort_keys=True))
PY

snapshot_height="$(python3 - "$distribution_manifest" <<'PY'
import json
import sys
payload = json.load(open(sys.argv[1]))
manifest = payload.get("manifest", payload)
height = manifest.get("snapshot_height", manifest.get("height"))
if height is None:
    raise SystemExit("snapshot height missing")
print(height)
PY
)"
snapshot_block_hash="$(python3 - "$distribution_manifest" <<'PY'
import json
import sys
payload = json.load(open(sys.argv[1]))
manifest = payload.get("manifest", payload)
block_hash = manifest.get("snapshot_block_hash", manifest.get("hash"))
if not block_hash:
    raise SystemExit("snapshot block hash missing")
print(block_hash)
PY
)"

allowed_files=(
  chain.json
  canonical_locks.json
  canonical_locks.jsonl
  committed_blocks.jsonl
  committed_qcs.json
  committed_qcs.jsonl
  dag_state.json
  validator_registry.json
  token_state.json
  synid_registry.json
  account_state.json
  state_checkpoint.json
)

for file in "${allowed_files[@]}"; do
  source="$snapshot_root/$file"
  target="$target_data_dir/$file"
  if [[ ! -f "$source" ]]; then
    continue
  fi
  case "$file" in
    *config*|node.env|*.env|*key*|*identity*|*wireguard*|*wg0*|*tls*|*credential*|*secret*|*password*|*genesis*|*quorum*)
      echo "refusing forbidden state file: $file" >&2
      exit 6
      ;;
  esac
  sha256_file "$source" >> "$evidence_path/source/source-sha256.txt"
  if [[ -f "$target" ]]; then
    sha256_file "$target" >> "$evidence_path/target-before/target-sha256.txt"
    mv "$target" "$rollback_path/$file"
  fi
  tmp="$target.tmp-support-snapshot-$$"
  if [[ "$file" == "chain.json" ]]; then
    python3 - "$source" "$snapshot_root/committed_blocks.jsonl" "$tmp" "$snapshot_height" "$snapshot_block_hash" <<'PY'
import json
import os
import sys

source_path, committed_blocks_path, target_path, snapshot_height_raw, snapshot_hash = sys.argv[1:6]
snapshot_height = int(snapshot_height_raw)


def iter_chain_objects(path):
    with open(path, "r", encoding="utf-8") as handle:
        depth = 0
        in_string = False
        escaped = False
        collecting = False
        buffer = []
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            for char in chunk:
                if not collecting:
                    if char == "{":
                        collecting = True
                        depth = 1
                        in_string = False
                        escaped = False
                        buffer = ["{"]
                    continue

                buffer.append(char)
                if in_string:
                    if escaped:
                        escaped = False
                    elif char == "\\":
                        escaped = True
                    elif char == '"':
                        in_string = False
                    continue

                if char == '"':
                    in_string = True
                elif char == "{":
                    depth += 1
                elif char == "}":
                    depth -= 1
                    if depth == 0:
                        collecting = False
                        yield "".join(buffer)
                        buffer = []
        if collecting:
            raise SystemExit("chain.json ended while reading a block object")


def block_height(block):
    height = block.get("block_index")
    if height is None:
        height = block.get("height")
    if height is None:
        raise ValueError("block is missing block_index/height")
    return int(height)


def block_hash(block):
    return block.get("hash") or block.get("block_hash")


kept = 0
last_height = None
last_hash = None
filled_from_committed_blocks = False
candidate_path = f"{target_path}.candidate"
with open(candidate_path, "w", encoding="utf-8") as output:
    output.write("[")
    first = True
    for raw in iter_chain_objects(source_path):
        block = json.loads(raw)
        height = block_height(block)
        if height > snapshot_height:
            break
        if not first:
            output.write(",")
        json.dump(block, output, separators=(",", ":"))
        first = False
        kept += 1
        last_height = height
        last_hash = block_hash(block)

    if last_height != snapshot_height and os.path.exists(committed_blocks_path):
        with open(committed_blocks_path, "r", encoding="utf-8") as committed:
            for line in committed:
                if not line.strip():
                    continue
                record = json.loads(line)
                height = int(record.get("height"))
                if last_height is not None and height <= last_height:
                    continue
                if height > snapshot_height:
                    break
                expected_next = 0 if last_height is None else last_height + 1
                if height != expected_next:
                    raise SystemExit(
                        f"committed_blocks.jsonl height gap: got {height}, expected {expected_next}"
                    )
                block = record.get("block")
                if not isinstance(block, dict):
                    raise SystemExit("committed_blocks.jsonl record is missing block object")
                block.setdefault("hash", record.get("hash"))
                if block_height(block) != height:
                    raise SystemExit(
                        f"committed block height mismatch: wrapper {height}, block {block_height(block)}"
                    )
                if not block_hash(block):
                    raise SystemExit("committed block is missing hash")
                if not first:
                    output.write(",")
                json.dump(block, output, separators=(",", ":"))
                first = False
                kept += 1
                last_height = height
                last_hash = block_hash(block)
                filled_from_committed_blocks = True
    output.write("]")

if kept == 0:
    raise SystemExit("bounded chain.json would be empty")
if last_height != snapshot_height:
    raise SystemExit(
        f"bounded chain.json ended at height {last_height}, expected {snapshot_height}"
    )
if last_hash != snapshot_hash:
    raise SystemExit(
        f"bounded chain.json hash {last_hash} does not match snapshot hash {snapshot_hash}"
    )
os.replace(candidate_path, target_path)
print(
    json.dumps(
        {
            "bounded_chain_json": True,
            "filled_from_committed_blocks": filled_from_committed_blocks,
            "kept_blocks": kept,
            "last_height": last_height,
            "last_hash": last_hash,
        },
        sort_keys=True,
    )
)
PY
  else
    cp -p "$source" "$tmp"
  fi
  mv "$tmp" "$target"
  sha256_file "$target" >> "$evidence_path/target-after-sha256.txt"
done

support_marker_files=(
  validator_quarantine.json
  validator_quarantine_peer_evidence.json
  self_heal_status.json
)

for marker in "${support_marker_files[@]}"; do
  target="$target_data_dir/$marker"
  if [[ ! -f "$target" ]]; then
    continue
  fi
  case "$marker" in
    *config*|node.env|*.env|*key*|*identity*|*wireguard*|*wg0*|*tls*|*credential*|*secret*|*password*|*genesis*|*quorum*)
      echo "refusing forbidden support marker: $marker" >&2
      exit 7
      ;;
  esac
  cp -p "$target" "$evidence_path/target-before/$marker"
  cp -p "$target" "$rollback_path/$marker"
  sha256_file "$target" >> "$evidence_path/target-before/support-marker-sha256.txt"
  rm -f "$target"
  printf '%s\n' "$marker" >> "$evidence_path/support-markers-removed.txt"
done

cp -p "$distribution_manifest" "$evidence_path/distribution-manifest.json"
echo "support_snapshot_apply_complete=true evidence_path=$evidence_path rollback_path=$rollback_path keys_or_configs_copied=false"
