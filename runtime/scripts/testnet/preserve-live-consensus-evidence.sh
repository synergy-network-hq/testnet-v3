#!/usr/bin/env bash
set -uo pipefail

node="${SYNERGY_NODE:-unknown-node}"
row="${SYNERGY_SPREADSHEET_ROW:-unknown-row}"
qrpc_port="${SYNERGY_QRPC_PORT:-5640}"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"

workspace="${SYNERGY_WORKSPACE:-}"
if [[ -z "$workspace" ]]; then
  for candidate in \
    "$HOME/.synergy/testnet/nodes/validator-workspace" \
    "$HOME/.synergy/testnet/nodes/relayer-workspace" \
    "/opt/synergy/testnet/relayer" \
    "/opt/synergy/testnet/observer" \
    "/opt/synergy/Node-RPC" \
    "/opt/synergy/Node-EXP" \
    "$PWD"; do
    if [[ -d "$candidate" ]]; then
      workspace="$candidate"
      break
    fi
  done
fi

evidence_root="$HOME/synergy-testnet-evidence"
evidence_dir="$evidence_root/${timestamp}-${node// /_}"
mkdir -p "$evidence_dir"/{rpc,data,logs,proposals}

rpc_call() {
  local method="$1"
  local params="${2:-[]}"
  curl -sS --max-time 8 \
    -H "content-type: application/json" \
    --data "{\"jsonrpc\":\"2.0\",\"method\":\"${method}\",\"params\":${params},\"id\":1}" \
    "http://127.0.0.1:${qrpc_port}" || true
}

{
  echo "spreadsheet_row_used=true"
  echo "spreadsheet_row=$row"
  echo "node=$node"
  echo "host=$(hostname)"
  echo "user=$(id -un)"
  echo "date_utc=$(date -u -Is)"
  echo "workspace=$workspace"
  echo "qrpc_port=$qrpc_port"
  echo
  echo "processes:"
  pgrep -af "synergy-testnet|node-control-panel|atlas|explorer" || true
  echo
  echo "process_exe:"
  for pid in $(pgrep -f "synergy-testnet" || true); do
    echo "pid=$pid exe=$(readlink "/proc/$pid/exe" 2>/dev/null || true) cwd=$(readlink "/proc/$pid/cwd" 2>/dev/null || true)"
  done
  echo
  echo "runtime_checksums:"
  for binary in \
    "$workspace/bin/synergy-testnet-linux-amd64" \
    "$workspace/synergy-testnet-linux-amd64"; do
    [[ -f "$binary" ]] && sha256sum "$binary"
  done
  echo
  echo "workspace_listing:"
  ls -la "$workspace" 2>/dev/null || true
  echo
  echo "data_listing:"
  find "$workspace/data" -maxdepth 2 -type f -printf "%p %s bytes\n" 2>/dev/null | sort || true
  echo
  echo "listeners:"
  ss -ltnp 2>/dev/null | grep -E ":(${SYNERGY_QRPC_PORT:-5640}|${SYNERGY_WS_PORT:-5660}|${SYNERGY_METRICS_PORT:-6030})\\b" || true
  echo
  echo "service_status:"
  systemctl --no-pager --plain status synergy-testnet.service synergy-testnet-relayer.service synergy-node-control-panel.service 2>&1 | tail -240 || true
} > "$evidence_dir/manifest.txt"

rpc_call synergy_getLatestBlock > "$evidence_dir/rpc/latest_block.json"
rpc_call synergy_blockNumber > "$evidence_dir/rpc/block_number.json"
rpc_call synergy_getNodeStatus > "$evidence_dir/rpc/node_status.json"
rpc_call synergy_getCanonicalLock > "$evidence_dir/rpc/canonical_lock.json"
rpc_call synergy_getCommittedQC > "$evidence_dir/rpc/committed_qc.json"
rpc_call synergy_getPeerInfo > "$evidence_dir/rpc/peer_info.json"
rpc_call synergy_getBlockByNumber "[37335]" > "$evidence_dir/rpc/block_37335.json"
rpc_call synergy_getBlockByNumber "[37440]" > "$evidence_dir/rpc/block_37440.json"
if [[ -n "${SYNERGY_STALLED_HEIGHT:-}" ]]; then
  rpc_call synergy_getBlockByNumber "[${SYNERGY_STALLED_HEIGHT}]" > "$evidence_dir/rpc/block_stalled_height_${SYNERGY_STALLED_HEIGHT}.json"
fi

data_dir="$workspace/data"
for file in \
  canonical_locks.json \
  consensus_vote_locks.json \
  dag_state.json \
  validator_registry.json \
  token_state.json \
  validator_quarantine.json \
  validator_quarantine_peer_evidence.json; do
  [[ -f "$data_dir/$file" ]] && cp -p "$data_dir/$file" "$evidence_dir/data/$file"
done

if [[ -f "$data_dir/committed_qcs.jsonl" ]]; then
  wc -c "$data_dir/committed_qcs.jsonl" > "$evidence_dir/data/committed_qcs.jsonl.size"
  sha256sum "$data_dir/committed_qcs.jsonl" > "$evidence_dir/data/committed_qcs.jsonl.sha256"
  tail -200 "$data_dir/committed_qcs.jsonl" > "$evidence_dir/data/committed_qcs.jsonl.tail"
fi

if [[ -d "$data_dir/consensus_proposals" ]]; then
  tar -C "$data_dir" -czf "$evidence_dir/proposals/consensus_proposals.tgz" consensus_proposals 2>/dev/null || true
fi

if [[ -x "$workspace/nodectl.sh" ]]; then
  (cd "$workspace" && ./nodectl.sh status) > "$evidence_dir/nodectl-status.txt" 2>&1 || true
  (cd "$workspace" && ./nodectl.sh logs) > "$evidence_dir/logs/nodectl-logs.txt" 2>&1 || true
fi

find "$workspace/logs" -maxdepth 1 -type f 2>/dev/null | while read -r log_file; do
  tail -2000 "$log_file" > "$evidence_dir/logs/$(basename "$log_file").tail" 2>/dev/null || true
done

sha256sum "$evidence_dir"/rpc/*.json "$evidence_dir"/data/* "$evidence_dir"/proposals/* 2>/dev/null \
  > "$evidence_dir/evidence-file-checksums.sha256" || true

echo "spreadsheet_row_used=true row=$row node=$node evidence_dir=$evidence_dir"
grep -E "workspace=|runtime_checksums|pid=|LISTEN|block_hash|height" "$evidence_dir/manifest.txt" | tail -80 || true
