#!/usr/bin/env bash
set -euo pipefail

node="${SYNERGY_NODE:-unknown-node}"
row="${SYNERGY_SPREADSHEET_ROW:-unknown-row}"
workspace="${SYNERGY_WORKSPACE:-$HOME/.synergy/testnet/nodes/validator-workspace}"
out_root="${SYNERGY_SNAPSHOT_ROOT:-$HOME/synergy-testnet-snapshots}"
mkdir -p "$out_root"

data_dir="$workspace/data"
test -d "$data_dir"

height="$(
  python3 - "$data_dir/canonical_locks.json" <<'PY'
import json
import sys
from pathlib import Path
path = Path(sys.argv[1])
data = json.loads(path.read_text())
print(max(int(key) for key in data.keys()))
PY
)"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
snapshot="$out_root/majority-${node// /_}-h${height}-compact-${timestamp}.tar"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/data"

for file in chain.json canonical_locks.json dag_state.json validator_registry.json token_state.json synid_registry.json; do
  if [[ "$file" == "synid_registry.json" && ! -f "$data_dir/$file" ]]; then
    continue
  fi
  test -f "$data_dir/$file"
  cp -p "$data_dir/$file" "$tmp/data/$file"
done
test -f "$data_dir/committed_qcs.jsonl"
tail -200 "$data_dir/committed_qcs.jsonl" > "$tmp/data/committed_qcs.jsonl"

tar -C "$tmp" -cf "$snapshot" data
sha="$(sha256sum "$snapshot" | awk '{print $1}')"
size="$(wc -c < "$snapshot")"
echo "spreadsheet_row_used=true row=$row node=$node snapshot=$snapshot height=$height sha256=$sha size_bytes=$size"
