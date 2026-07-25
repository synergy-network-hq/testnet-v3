#!/usr/bin/env bash
set -euo pipefail

workspace="${REMOTE_WORKSPACE:-}"
if [[ -z "${workspace}" ]]; then
  for candidate in \
    "$HOME/.synergy/testnet/nodes/validator-workspace" \
    /home/*/.synergy/testnet/nodes/validator-workspace; do
    if [[ -d "${candidate}" ]]; then
      workspace="${candidate}"
      break
    fi
  done
fi

if [[ -z "${workspace}" || ! -d "${workspace}" ]]; then
  echo "validator workspace not found" >&2
  exit 2
fi

cd "${workspace}"
stamp="$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p backups/bin backups/config data/logs

if [[ ! -f bin/synergy-testnet-linux-amd64.pending ]]; then
  echo "missing staged binary: ${workspace}/bin/synergy-testnet-linux-amd64.pending" >&2
  exit 2
fi

if [[ -x ./nodectl.sh ]]; then
  ./nodectl.sh stop || true
else
  pkill -f "${workspace}/bin/synergy-testnet" || true
fi
sleep 2

if [[ -f bin/synergy-testnet-linux-amd64 ]]; then
  cp -p bin/synergy-testnet-linux-amd64 \
    "backups/bin/synergy-testnet-linux-amd64.pre-verifier-cache-${stamp}"
fi
cp -p config/node.toml "backups/config/node.toml.pre-verifier-cache-${stamp}"
cp -p config/consensus-fork-migration.json \
  "backups/config/consensus-fork-migration.json.pre-verifier-cache-${stamp}"

install -m 0755 bin/synergy-testnet-linux-amd64.pending bin/synergy-testnet-linux-amd64

python3 - <<'PY'
import json
import re
from pathlib import Path

fork = Path("config/consensus-fork-migration.json")
payload = json.loads(fork.read_text())
payload["old_consensus_algorithm"] = "FN-DSA"
payload["new_consensus_algorithm"] = "FN-DSA"
fork.write_text(json.dumps(payload, indent=2) + "\n")

node = Path("config/node.toml")
text = node.read_text()
if re.search(r"(?m)^heartbeat_interval\s*=", text):
    text = re.sub(r"(?m)^heartbeat_interval\s*=.*$", "heartbeat_interval = 1", text)
else:
    text = text.rstrip() + "\nheartbeat_interval = 1\n"
node.write_text(text)
PY

echo "workspace=${workspace}"
sha256sum bin/synergy-testnet-linux-amd64
grep -n "heartbeat_interval\|old_consensus\|new_consensus\|parser_mode" \
  config/node.toml config/consensus-fork-migration.json || true

if [[ -x ./nodectl.sh ]]; then
  ./nodectl.sh start
else
  nohup bin/synergy-testnet-linux-amd64 start --config "${workspace}/config/node.toml" \
    > data/logs/node.out 2> data/logs/node.err &
  echo "$!" > data/node.pid
fi

python3 - <<'PY'
import json
import time
import urllib.request

url = "http://127.0.0.1:5640"
for attempt in range(30):
    try:
        req = urllib.request.Request(
            url,
            data=json.dumps({
                "jsonrpc": "2.0",
                "method": "synergy_getLatestBlock",
                "params": [],
                "id": 1,
            }).encode(),
            headers={"content-type": "application/json"},
        )
        block = json.load(urllib.request.urlopen(req, timeout=4))["result"]
        print(
            "rpc_ok",
            attempt,
            "height",
            block.get("block_index"),
            "age",
            int(time.time()) - int(block.get("timestamp", 0)),
        )
        break
    except Exception as exc:
        print("rpc_wait", attempt, repr(exc))
        time.sleep(1)
else:
    raise SystemExit("RPC did not become available")
PY

pgrep -af "synergy-testnet|nodectl|install_and_start" || true
ss -ltnp | egrep "(:5622|:5640|:5660|:6030)" || true
tail -80 data/logs/node.err 2>/dev/null || true
