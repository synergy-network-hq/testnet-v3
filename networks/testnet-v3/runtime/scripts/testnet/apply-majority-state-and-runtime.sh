#!/usr/bin/env bash
set -euo pipefail

node="${SYNERGY_NODE:-unknown-node}"
row="${SYNERGY_SPREADSHEET_ROW:-unknown-row}"
snapshot="${SYNERGY_RESTORE_SNAPSHOT:-/tmp/majority-val2-h37440-compact-20260522T205030Z.tar}"
snapshot_sha="${SYNERGY_RESTORE_SNAPSHOT_SHA:-fe81160700e3396b59190f81abc986bc5c28cf1d206e6c3ef4603cdbdcc48458}"
runtime="${SYNERGY_RUNTIME:-/tmp/synergy-testnet-linux-amd64.v13.0.1}"
runtime_sha="${SYNERGY_RUNTIME_SHA:-f5a1cf5b96bd647ba8bf32a6372858c2e7a0e7bc66d8d129ab65c7461314d9d1}"
start_after="${SYNERGY_START_AFTER:-false}"
canonical_height="${SYNERGY_CANONICAL_HEIGHT:-37440}"

workspace="${SYNERGY_WORKSPACE:-}"
if [[ -z "$workspace" ]]; then
  for candidate in \
    "$HOME/.synergy/testnet/nodes/validator-workspace" \
    "$HOME/.synergy/testnet/nodes/relayer-workspace" \
    "/opt/synergy/testnet/relayer" \
    "/opt/synergy/Node-RPC"; do
    if [[ -d "$candidate" ]]; then
      workspace="$candidate"
      break
    fi
  done
fi

if [[ -z "$workspace" || ! -d "$workspace" ]]; then
  echo "unable to resolve workspace for $node" >&2
  exit 2
fi

data_dir="$workspace/data"
binary="$workspace/bin/synergy-testnet-linux-amd64"
if [[ ! -x "$binary" && -f "$binary" ]]; then
  chmod +x "$binary"
fi

test -f "$snapshot"
test -f "$runtime"
actual_snapshot_sha="$(sha256sum "$snapshot" | awk '{print $1}')"
actual_runtime_sha="$(sha256sum "$runtime" | awk '{print $1}')"
if [[ "$actual_snapshot_sha" != "$snapshot_sha" ]]; then
  echo "snapshot checksum mismatch: $actual_snapshot_sha" >&2
  exit 3
fi
if [[ "$actual_runtime_sha" != "$runtime_sha" ]]; then
  echo "runtime checksum mismatch: $actual_runtime_sha" >&2
  exit 4
fi

ts="$(date -u +%Y%m%dT%H%M%SZ)"
backup_root="$HOME/synergy-testnet-state-backups"
backup="$backup_root/${ts}-${node// /_}-pre-restore"
mkdir -p "$backup/data" "$backup/bin" "$backup/transient"

if [[ -x "$workspace/nodectl.sh" ]]; then
  (cd "$workspace" && ./nodectl.sh stop) || true
fi
for pid in $(pgrep -f "synergy-testnet-linux-amd64 start --config" || true); do
  proc_cwd="$(readlink "/proc/$pid/cwd" 2>/dev/null || true)"
  proc_exe="$(readlink "/proc/$pid/exe" 2>/dev/null || true)"
  if [[ "$proc_cwd" == "$workspace" || "$proc_exe" == "$workspace"/bin/* ]]; then
    kill "$pid" 2>/dev/null || true
  fi
done
sleep 2
for pid in $(pgrep -f "synergy-testnet-linux-amd64 start --config" || true); do
  proc_cwd="$(readlink "/proc/$pid/cwd" 2>/dev/null || true)"
  proc_exe="$(readlink "/proc/$pid/exe" 2>/dev/null || true)"
  if [[ "$proc_cwd" == "$workspace" || "$proc_exe" == "$workspace"/bin/* ]]; then
    kill -9 "$pid" 2>/dev/null || true
  fi
done

mkdir -p "$data_dir"
for file in \
  chain.json \
  canonical_locks.json \
  committed_qcs.jsonl \
  dag_state.json \
  validator_registry.json \
  token_state.json \
  synid_registry.json \
  consensus_vote_locks.json \
  validator_quarantine.json \
  validator_quarantine_peer_evidence.json; do
  [[ -f "$data_dir/$file" ]] && cp -p "$data_dir/$file" "$backup/data/$file"
done
if [[ -d "$data_dir/consensus_proposals" ]]; then
  tar -C "$data_dir" -cf "$backup/transient/consensus_proposals.tar" consensus_proposals
  rm -rf "$data_dir/consensus_proposals"
fi
mkdir -p "$data_dir/consensus_proposals"

if [[ -f "$binary" ]]; then
  cp -p "$binary" "$backup/bin/synergy-testnet-linux-amd64"
fi

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
tar -C "$tmp" -xf "$snapshot"
for file in \
  chain.json \
  canonical_locks.json \
  committed_qcs.jsonl \
  dag_state.json \
  validator_registry.json \
  token_state.json \
  synid_registry.json; do
  if [[ "$file" == "synid_registry.json" && ! -f "$tmp/data/$file" ]]; then
    continue
  fi
  test -f "$tmp/data/$file"
  cp -p "$tmp/data/$file" "$data_dir/$file"
done

if [[ -f "$data_dir/consensus_vote_locks.json" ]]; then
  python3 - "$data_dir/consensus_vote_locks.json" "$canonical_height" <<'PY'
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
height = int(sys.argv[2])
try:
    locks = json.loads(path.read_text())
except Exception:
    locks = {}
if isinstance(locks, dict):
    pruned = {}
    for key, value in locks.items():
        if not isinstance(value, dict):
            continue
        try:
            block_index = int(value.get("block_index", 0))
        except Exception:
            continue
        if block_index < height:
            pruned[key] = value
    path.write_text(json.dumps(pruned, indent=2, sort_keys=True) + "\n")
PY
fi

rm -f "$data_dir/validator_quarantine.json" "$data_dir/validator_quarantine_peer_evidence.json"

if [[ "$(readlink -f "$runtime")" != "$(readlink -f "$binary")" ]]; then
  cp -p "$runtime" "$binary"
fi
chmod +x "$binary"

installed_sha="$(sha256sum "$binary" | awk '{print $1}')"
if [[ "$installed_sha" != "$runtime_sha" ]]; then
  echo "installed runtime checksum mismatch: $installed_sha" >&2
  exit 5
fi

if [[ "$start_after" == "true" ]]; then
  if [[ -x "$workspace/nodectl.sh" ]]; then
    (cd "$workspace" && ./nodectl.sh start)
  else
    mkdir -p "$workspace/logs"
    (cd "$workspace" && nohup ./bin/synergy-testnet-linux-amd64 start --config config/node.toml >> logs/manual-v13-start.log 2>&1 &)
  fi
fi

echo "spreadsheet_row_used=true row=$row node=$node workspace=$workspace backup=$backup snapshot_sha=$actual_snapshot_sha installed_runtime_sha=$installed_sha start_after=$start_after"
