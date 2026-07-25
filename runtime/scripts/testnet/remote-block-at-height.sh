#!/usr/bin/env bash
set -uo pipefail

height="${SYNERGY_BLOCK_HEIGHT:?SYNERGY_BLOCK_HEIGHT is required}"
python3 - "$height" <<'PY'
import json
import os
import sys
import urllib.request

height = int(sys.argv[1])
port = os.environ.get("SYNERGY_QRPC_PORT", "5640")
payload = json.dumps(
    {"jsonrpc": "2.0", "method": "synergy_getBlockByNumber", "params": [height], "id": 1}
).encode()
request = urllib.request.Request(
    f"http://127.0.0.1:{port}",
    data=payload,
    headers={"content-type": "application/json"},
    method="POST",
)
try:
    with urllib.request.urlopen(request, timeout=5) as response:
        value = json.loads(response.read().decode())
except Exception as exc:
    print(json.dumps({
        "spreadsheet_row_used": True,
        "row": os.environ.get("SYNERGY_SPREADSHEET_ROW"),
        "node": os.environ.get("SYNERGY_NODE"),
        "height": height,
        "error": f"{type(exc).__name__}: {exc}",
    }, sort_keys=True))
    raise SystemExit(0)

block = value.get("result") if isinstance(value, dict) else None
if isinstance(block, dict) and "block" in block and isinstance(block["block"], dict):
    block = block["block"]
hash_value = None
parent_hash = None
timestamp = None
if isinstance(block, dict):
    hash_value = block.get("hash") or block.get("block_hash")
    parent_hash = block.get("previous_hash") or block.get("parent_hash") or block.get("parentHash")
    timestamp = block.get("timestamp")
print(json.dumps({
    "spreadsheet_row_used": True,
    "row": os.environ.get("SYNERGY_SPREADSHEET_ROW"),
    "node": os.environ.get("SYNERGY_NODE"),
    "height": height,
    "hash": hash_value,
    "parent_hash": parent_hash,
    "timestamp": timestamp,
    "found": hash_value is not None,
}, sort_keys=True))
PY
