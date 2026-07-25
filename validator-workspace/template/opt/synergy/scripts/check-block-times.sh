#!/usr/bin/env bash
set -euo pipefail

PORT=${PORT:-5640}
WINDOW=${WINDOW:-20}
python3 - "$PORT" "$WINDOW" <<'PY'
import json, statistics, sys, urllib.request
port = int(sys.argv[1])
window = int(sys.argv[2])
def rpc(method, params=None):
    payload=json.dumps({"jsonrpc":"2.0","method":method,"params":params or [],"id":1}).encode()
    req=urllib.request.Request(f"http://127.0.0.1:{port}",data=payload,headers={"content-type":"application/json"},method="POST")
    with urllib.request.urlopen(req,timeout=5) as r:
        return json.loads(r.read().decode()).get("result")
height = int(rpc("synergy_getBlockNumber"))
timestamps = []
for h in range(max(0, height-window+1), height+1):
    block = rpc("synergy_getBlockByNumber", [h])
    if isinstance(block, dict) and block.get("timestamp") is not None:
        timestamps.append(int(block["timestamp"]))
deltas = [b-a for a,b in zip(timestamps, timestamps[1:]) if b >= a]
if not deltas:
    print(json.dumps({"height": height, "error": "no timestamp deltas"}))
    raise SystemExit(1)
print(json.dumps({
    "height": height,
    "samples": len(deltas),
    "average": sum(deltas)/len(deltas),
    "p50": statistics.median(deltas),
    "p90": sorted(deltas)[int(len(deltas)*0.9)-1],
    "p95": sorted(deltas)[int(len(deltas)*0.95)-1],
    "max": max(deltas),
    "target_range_seconds": [0.5, 2.5],
}, sort_keys=True))
PY

