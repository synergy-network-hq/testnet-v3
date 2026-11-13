#!/usr/bin/env bash
set -uo pipefail

node="${SYNERGY_NODE:-unknown-node}"
row="${SYNERGY_SPREADSHEET_ROW:-unknown-row}"
qrpc_port="${SYNERGY_QRPC_PORT:-5640}"
conflict_height="${SYNERGY_CONFLICT_HEIGHT:-71160}"
runtime_sha_expected="${SYNERGY_RUNTIME_SHA:-}"

workspace="${SYNERGY_WORKSPACE:-}"
if [[ -z "$workspace" ]]; then
  for candidate in \
    "$HOME/.synergy/testnet/nodes/validator-workspace" \
    "$HOME/.synergy/testnet/nodes/relayer-workspace" \
    "/opt/synergy/testnet/relayer" \
    "/opt/synergy/Node-RPC" \
    "/opt/synergy/Node-EXP"; do
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

timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
evidence_dir="$HOME/synergy-testnet-evidence/${timestamp}-${node// /_}-state-recovery-freeze"
data_dir="$workspace/data"
mkdir -p "$evidence_dir"/{rpc,data,logs}

rpc_call() {
  local method="$1"
  local params="${2:-[]}"
  curl -sS --max-time 8 \
    -H "content-type: application/json" \
    --data "{\"jsonrpc\":\"2.0\",\"method\":\"${method}\",\"params\":${params},\"id\":1}" \
    "http://127.0.0.1:${qrpc_port}" || true
}

runtime_sha=""
runtime_path=""
for binary in \
  "$workspace/bin/synergy-rpc-gateway-node-linux-amd64" \
  "$workspace/bin/synergy-testnet-linux-amd64"; do
  if [[ -f "$binary" ]]; then
    runtime_path="$binary"
    runtime_sha="$(sha256sum "$binary" | awk '{print $1}')"
    break
  fi
done

rpc_call synergy_getLatestBlock > "$evidence_dir/rpc/latest_block.json"
rpc_call synergy_getCanonicalLock > "$evidence_dir/rpc/canonical_lock.json"
rpc_call synergy_getCommittedQC > "$evidence_dir/rpc/committed_qc.json"
rpc_call synergy_getNodeStatus > "$evidence_dir/rpc/node_status.json"
rpc_call synergy_getPeerInfo > "$evidence_dir/rpc/peer_info.json"
rpc_call synergy_getBlockByNumber "[${conflict_height}]" > "$evidence_dir/rpc/block_${conflict_height}.json"

for file in canonical_locks.json consensus_vote_locks.json validator_quarantine.json validator_quarantine_peer_evidence.json; do
  [[ -f "$data_dir/$file" ]] && cp -p "$data_dir/$file" "$evidence_dir/data/$file"
done
if [[ -f "$data_dir/committed_qcs.jsonl" ]]; then
  wc -c "$data_dir/committed_qcs.jsonl" > "$evidence_dir/data/committed_qcs.jsonl.size"
  sha256sum "$data_dir/committed_qcs.jsonl" > "$evidence_dir/data/committed_qcs.jsonl.sha256"
  tail -500 "$data_dir/committed_qcs.jsonl" > "$evidence_dir/data/committed_qcs.jsonl.tail"
fi

if [[ -d "$data_dir/logs" ]]; then
  find "$data_dir/logs" -maxdepth 1 -type f -print0 | while IFS= read -r -d '' log_file; do
    tail -3000 "$log_file" > "$evidence_dir/logs/$(basename "$log_file").tail" 2>/dev/null || true
    grep -aiE "canonical|conflict|refus|proposal does not extend|sync|catch|lock validation|fail closed|deep support|vote request|local tip" \
      "$log_file" 2>/dev/null | tail -500 > "$evidence_dir/logs/$(basename "$log_file").recovery-grep" || true
  done
fi

{
  echo "spreadsheet_row_used=true"
  echo "access_path=workbook_exact"
  echo "node=$node"
  echo "row=$row"
  echo "action=state_recovery_freeze"
  echo "workspace=$workspace"
  echo "runtime_path=$runtime_path"
  echo "runtime_checksum=$runtime_sha"
  echo "runtime_checksum_expected=$runtime_sha_expected"
  echo "date_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "processes:"
  pgrep -af "synergy-testnet|synergy-rpc-gateway" || true
  echo "listeners:"
  ss -ltnp 2>/dev/null | grep -E ":(${SYNERGY_QRPC_PORT:-5640}|${SYNERGY_WS_PORT:-5660}|${SYNERGY_METRICS_PORT:-6030})\\b" || true
} > "$evidence_dir/manifest.txt"

python3 - "$evidence_dir" "$node" "$row" "$workspace" "$runtime_path" "$runtime_sha" "$conflict_height" <<'PY'
import json
import sys
from pathlib import Path

evidence_dir = Path(sys.argv[1])
node = sys.argv[2]
row = sys.argv[3]
workspace = sys.argv[4]
runtime_path = sys.argv[5]
runtime_sha = sys.argv[6]
conflict_height = int(sys.argv[7])
data_dir = Path(workspace) / "data"

def read_json(path):
    try:
        return json.loads(Path(path).read_text())
    except Exception as exc:
        return {"error": str(exc)}

def unwrap_rpc(value):
    return value.get("result") if isinstance(value, dict) and "result" in value else value

def block_summary(value):
    value = unwrap_rpc(value)
    if isinstance(value, dict) and isinstance(value.get("block"), dict):
        value = value["block"]
    if not isinstance(value, dict):
        return None
    return {
        "height": value.get("height") or value.get("number") or value.get("block_number") or value.get("block_index"),
        "hash": value.get("hash") or value.get("block_hash"),
        "parent_hash": value.get("parent_hash") or value.get("previous_hash") or value.get("parentHash"),
        "timestamp": value.get("timestamp"),
    }

def lock_summary(value):
    value = unwrap_rpc(value)
    if not isinstance(value, dict):
        return None
    return {
        "height": value.get("height") or value.get("block_height"),
        "hash": value.get("hash") or value.get("block_hash"),
        "round": value.get("round"),
        "epoch": value.get("epoch"),
    }

def qc_summary(value):
    value = unwrap_rpc(value)
    if not isinstance(value, dict):
        return None
    nested = value.get("qc") if isinstance(value.get("qc"), dict) else value
    signatures = (
        nested.get("signatures")
        or nested.get("votes")
        or nested.get("validator_signatures")
        or nested.get("participants")
        or []
    )
    vote_count = nested.get("vote_count")
    if vote_count is None and isinstance(signatures, list):
        vote_count = len(signatures)
    signature_count = nested.get("signature_count")
    if signature_count is None and isinstance(signatures, list):
        signature_count = len(signatures)
    return {
        "height": nested.get("height") or nested.get("block_height"),
        "hash": nested.get("hash") or nested.get("block_hash"),
        "vote_count": vote_count,
        "signature_count": signature_count,
        "participant_bitmap": nested.get("participant_bitmap"),
        "cumulative_weight": nested.get("cumulative_weight"),
    }

def file_lock_at_height(height):
    path = data_dir / "canonical_locks.json"
    try:
        locks = json.loads(path.read_text())
    except Exception as exc:
        return {"error": str(exc)}
    if not isinstance(locks, dict):
        return {"error": "canonical_locks.json is not an object"}
    return locks.get(str(height))

def count_vote_locks_above(finalized_height):
    path = data_dir / "consensus_vote_locks.json"
    if not path.exists():
        return None
    try:
        locks = json.loads(path.read_text())
        finalized = int(finalized_height)
    except Exception as exc:
        return {"error": str(exc)}
    count = 0
    def walk(value):
        nonlocal count
        if isinstance(value, dict):
            height = value.get("height") or value.get("block_height") or value.get("block_index")
            if height is not None:
                try:
                    if int(height) > finalized:
                        count += 1
                except Exception:
                    pass
            for child in value.values():
                walk(child)
        elif isinstance(value, list):
            for child in value:
                walk(child)
    walk(locks)
    return count

latest = block_summary(read_json(evidence_dir / "rpc/latest_block.json"))
canonical_lock = lock_summary(read_json(evidence_dir / "rpc/canonical_lock.json"))
committed_qc = qc_summary(read_json(evidence_dir / "rpc/committed_qc.json"))
conflict_block = block_summary(read_json(evidence_dir / f"rpc/block_{conflict_height}.json"))
node_status = unwrap_rpc(read_json(evidence_dir / "rpc/node_status.json"))
peer_info = unwrap_rpc(read_json(evidence_dir / "rpc/peer_info.json"))
lock_height = canonical_lock.get("height") if isinstance(canonical_lock, dict) else None

print(json.dumps({
    "spreadsheet_row_used": True,
    "access_path": "workbook_exact",
    "node": node,
    "row": row,
    "action": "state_recovery_freeze",
    "evidence_dir": str(evidence_dir),
    "workspace": workspace,
    "runtime_path": runtime_path,
    "runtime_sha256": runtime_sha,
    "latest_block": latest,
    "canonical_lock": canonical_lock,
    "committed_qc": committed_qc,
    "conflict_height": conflict_height,
    "block_at_conflict_height": conflict_block,
    "canonical_lock_file_at_conflict_height": file_lock_at_height(conflict_height),
    "vote_locks_above_canonical": count_vote_locks_above(lock_height) if lock_height is not None else None,
    "quarantine_marker": (data_dir / "validator_quarantine.json").exists(),
    "peer_count": (
        len(peer_info) if isinstance(peer_info, list)
        else peer_info.get("peer_count") if isinstance(peer_info, dict)
        else None
    ),
    "sync_status": node_status.get("sync_status") if isinstance(node_status, dict) else None,
}, sort_keys=True))
PY
