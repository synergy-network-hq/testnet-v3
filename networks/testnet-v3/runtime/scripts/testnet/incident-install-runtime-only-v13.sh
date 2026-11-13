#!/usr/bin/env bash
set -euo pipefail

node="${SYNERGY_NODE:-unknown-node}"
row="${SYNERGY_SPREADSHEET_ROW:-unknown-row}"
workspace="${SYNERGY_WORKSPACE:?SYNERGY_WORKSPACE is required}"
runtime_path="${SYNERGY_RUNTIME_PATH:?SYNERGY_RUNTIME_PATH is required}"
runtime_sha="${SYNERGY_RUNTIME_SHA:?SYNERGY_RUNTIME_SHA is required}"
binary_name="${SYNERGY_BINARY_NAME:?SYNERGY_BINARY_NAME is required}"
start_mode="${SYNERGY_START_MODE:?SYNERGY_START_MODE is required}"
service_name="${SYNERGY_SERVICE_NAME:-}"
qrpc_port="${SYNERGY_QRPC_PORT:-5640}"

case "$start_mode" in
  nodectl|systemd) ;;
  *) echo "unsupported start mode: $start_mode" >&2; exit 2 ;;
esac

if [[ "$start_mode" == "systemd" && -z "$service_name" ]]; then
  echo "SYNERGY_SERVICE_NAME is required for systemd start mode" >&2
  exit 2
fi

if [[ ! -d "$workspace" || ! -d "$workspace/bin" ]]; then
  echo "workspace/bin missing: $workspace" >&2
  exit 2
fi
if [[ ! -f "$runtime_path" ]]; then
  echo "runtime file missing: $runtime_path" >&2
  exit 2
fi

binary="$workspace/bin/$binary_name"
case "$binary" in
  "$workspace"/bin/*) ;;
  *) echo "binary path escaped workspace: $binary" >&2; exit 2 ;;
esac

actual_runtime_sha="$(sha256sum "$runtime_path" | awk '{print $1}')"
if [[ "$actual_runtime_sha" != "$runtime_sha" ]]; then
  echo "runtime checksum mismatch: expected=$runtime_sha actual=$actual_runtime_sha" >&2
  exit 3
fi

ts="$(date -u +%Y%m%dT%H%M%SZ)"
safe_node="${node// /_}"
evidence="$HOME/synergy-testnet-evidence/${ts}-${safe_node}-runtime-v13-install"
backup="$HOME/synergy-testnet-state-backups/${ts}-${safe_node}-runtime-v13-install"
mkdir -p "$evidence" "$backup/bin" "$backup/process"

list_workspace_processes() {
  for proc in /proc/[0-9]*; do
    [[ -d "$proc" ]] || continue
    pid="${proc##*/}"
    exe="$(readlink "$proc/exe" 2>/dev/null || true)"
    cwd="$(readlink "$proc/cwd" 2>/dev/null || true)"
    cmd="$(tr '\0' ' ' < "$proc/cmdline" 2>/dev/null || true)"
    [[ -n "$cmd" ]] || continue
    if [[ "$exe" == "$workspace"/bin/* || "$cwd" == "$workspace" ]]; then
      if [[ "$cmd" == *" start --config "* || "$exe" == "$binary" ]]; then
        printf '%s\t%s\t%s\t%s\n' "$pid" "$exe" "$cwd" "$cmd"
      fi
    fi
  done
}

deleted_inode_count() {
  local count=0
  while IFS=$'\t' read -r _pid exe _cwd _cmd; do
    [[ "$exe" == *"(deleted)"* ]] && count=$((count + 1))
  done < <(list_workspace_processes)
  printf '%s\n' "$count"
}

query_latest_block() {
  python3 - "$qrpc_port" <<'PY'
import json
import sys
import urllib.request

port = sys.argv[1]
payload = json.dumps({"jsonrpc": "2.0", "method": "synergy_getLatestBlock", "params": [], "id": 1}).encode()
request = urllib.request.Request(
    f"http://127.0.0.1:{port}",
    data=payload,
    headers={"content-type": "application/json"},
    method="POST",
)
try:
    with urllib.request.urlopen(request, timeout=8) as response:
        value = json.loads(response.read().decode())
    block = value.get("result") if isinstance(value, dict) else None
    if isinstance(block, dict) and isinstance(block.get("block"), dict):
        block = block["block"]
    if isinstance(block, dict):
        print(json.dumps({
            "height": block.get("height") or block.get("number") or block.get("block_number") or block.get("block_index"),
            "hash": block.get("hash") or block.get("block_hash"),
            "parent_hash": block.get("parent_hash") or block.get("parentHash") or block.get("previous_hash"),
            "timestamp": block.get("timestamp"),
        }, sort_keys=True))
    else:
        print(json.dumps({"error": "missing_block_result", "raw": value}, sort_keys=True))
except Exception as exc:
    print(json.dumps({"error": f"{type(exc).__name__}: {exc}"}, sort_keys=True))
PY
}

{
  echo "spreadsheet_row_used=true"
  echo "access_path=workbook_exact"
  echo "row=$row"
  echo "node=$node"
  echo "workspace=$workspace"
  echo "binary=$binary"
  echo "runtime_path=$runtime_path"
  echo "runtime_sha=$runtime_sha"
  echo "start_mode=$start_mode"
  echo "service_name=$service_name"
  echo "keys_or_configs_copied=false"
  echo "genesis_mutated=false"
  echo "quorum_mutated=false"
  echo "chain_state_mutated=false"
  echo "canonical_locks_mutated=false"
  echo "committed_qcs_mutated=false"
  echo "dag_state_mutated=false"
  echo "registry_state_mutated=false"
  echo "token_state_mutated=false"
} > "$evidence/manifest.txt"

list_workspace_processes > "$backup/process/before.tsv" || true
if [[ -f "$binary" ]]; then
  cp -p "$binary" "$backup/bin/$binary_name"
  sha256sum "$binary" > "$backup/bin/$binary_name.sha256"
fi
query_latest_block > "$evidence/pre-latest-block.json" || true

if [[ "$start_mode" == "nodectl" ]]; then
  if [[ ! -x "$workspace/nodectl.sh" ]]; then
    echo "nodectl missing or not executable: $workspace/nodectl.sh" >&2
    exit 2
  fi
  (cd "$workspace" && ./nodectl.sh stop)
else
  systemctl stop "$service_name" || true
fi

sleep 2
while IFS=$'\t' read -r pid _exe _cwd _cmd; do
  kill "$pid" 2>/dev/null || true
done < <(list_workspace_processes)
sleep 2
while IFS=$'\t' read -r pid _exe _cwd _cmd; do
  kill -9 "$pid" 2>/dev/null || true
done < <(list_workspace_processes)

remaining="$(list_workspace_processes | wc -l | tr -d ' ')"
if [[ "$remaining" != "0" ]]; then
  list_workspace_processes > "$evidence/remaining-processes-before-install.tsv" || true
  echo "workspace process still running before install" >&2
  exit 4
fi

cp -p "$runtime_path" "$binary"
chmod +x "$binary"
installed_sha="$(sha256sum "$binary" | awk '{print $1}')"
if [[ "$installed_sha" != "$runtime_sha" ]]; then
  echo "installed runtime checksum mismatch: expected=$runtime_sha actual=$installed_sha" >&2
  exit 5
fi

if [[ "$start_mode" == "nodectl" ]]; then
  (cd "$workspace" && ./nodectl.sh start)
else
  systemctl start "$service_name"
fi

sleep 6
list_workspace_processes > "$backup/process/after.tsv" || true
query_latest_block > "$evidence/post-latest-block.json" || true
process_count="$(list_workspace_processes | wc -l | tr -d ' ')"
deleted_count="$(deleted_inode_count)"
quarantine_marker=false
if [[ -f "$workspace/data/validator_quarantine.json" ]]; then
  quarantine_marker=true
fi

cat > "$evidence/result.json" <<EOF
{
  "spreadsheet_row_used": true,
  "access_path": "workbook_exact",
  "row": "$row",
  "node": "$node",
  "workspace": "$workspace",
  "binary": "$binary",
  "installed_runtime_sha": "$installed_sha",
  "expected_runtime_sha": "$runtime_sha",
  "process_count": $process_count,
  "deleted_inode_count": $deleted_count,
  "quarantine_marker": $quarantine_marker,
  "evidence_path": "$evidence",
  "backup_path": "$backup",
  "keys_or_configs_copied": false,
  "genesis_mutated": false,
  "quorum_mutated": false,
  "chain_state_mutated": false,
  "canonical_locks_mutated": false,
  "committed_qcs_mutated": false
}
EOF

cat "$evidence/result.json"
