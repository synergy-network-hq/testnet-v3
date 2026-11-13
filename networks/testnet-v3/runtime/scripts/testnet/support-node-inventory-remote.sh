#!/usr/bin/env bash
set -uo pipefail

role="${SUPPORT_NODE_ROLE:-support-node}"
qrpc_port="${SYNERGY_QRPC_PORT:-5640}"
public_rpc_url="${PUBLIC_RPC_URL:-https://testnet-core-rpc.synergy-network.io}"
atlas_api_url="${ATLAS_API_URL:-https://testnet-atlas-api.synergy-network.io}"

json_rpc() {
  local url="$1"
  local method="$2"
  python3 - "$url" "$method" <<'PY' 2>/dev/null || true
import json
import sys
import time
import urllib.request

url, method = sys.argv[1], sys.argv[2]
payload = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": []}).encode()
request = urllib.request.Request(url, data=payload, headers={"content-type": "application/json"}, method="POST")
started = time.time()
try:
    with urllib.request.urlopen(request, timeout=8) as response:
        body = json.loads(response.read().decode())
    print(json.dumps({"elapsed_sec": round(time.time() - started, 3), "response": body}, sort_keys=True))
except Exception as exc:
    print(json.dumps({"elapsed_sec": round(time.time() - started, 3), "error": str(exc)}, sort_keys=True))
PY
}

http_get() {
  local url="$1"
  python3 - "$url" <<'PY' 2>/dev/null || true
import json
import sys
import time
import urllib.request

url = sys.argv[1]
started = time.time()
try:
    request = urllib.request.Request(url, headers={"accept": "application/json"})
    with urllib.request.urlopen(request, timeout=8) as response:
        body = response.read().decode(errors="replace")
    parsed = None
    try:
        parsed = json.loads(body)
    except Exception:
        parsed = body[:1000]
    print(json.dumps({"elapsed_sec": round(time.time() - started, 3), "status": response.status, "body": parsed}, sort_keys=True))
except Exception as exc:
    print(json.dumps({"elapsed_sec": round(time.time() - started, 3), "error": str(exc)}, sort_keys=True))
PY
}

safe_sudo() {
  if command -v sudo >/dev/null 2>&1; then
    sudo -n "$@" 2>/dev/null || "$@" 2>/dev/null
  else
    "$@" 2>/dev/null
  fi
}

service_candidates() {
  systemctl list-units --type=service --all --no-legend --no-pager 2>/dev/null \
    | awk '{print $1}' \
    | grep -Ei 'synergy|atlas|explorer|indexer|rpc|observer|relayer|boot|seed|prometheus|grafana|nginx|node-exporter|node_exporter' \
    | sort -u
  systemctl list-unit-files --type=service --no-legend --no-pager 2>/dev/null \
    | awk '{print $1}' \
    | grep -Ei 'synergy|atlas|explorer|indexer|rpc|observer|relayer|boot|seed|prometheus|grafana|nginx|node-exporter|node_exporter' \
    | sort -u
}

echo "# Support Node Inventory"
echo
echo "role: ${role}"
echo "generated_utc: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "hostname: $(hostname -f 2>/dev/null || hostname)"
echo "kernel: $(uname -a 2>/dev/null || true)"
echo

echo "## Service Units"
echo
echo '~~~text'
mapfile -t services < <(service_candidates | sort -u)
if ((${#services[@]} == 0)); then
  echo "no_matching_services"
else
  printf '%s\n' "${services[@]}"
fi
echo '~~~'
echo

echo "## Service Metadata"
for svc in "${services[@]:-}"; do
  echo
  echo "### ${svc}"
  echo '~~~text'
  systemctl is-active "$svc" 2>/dev/null | sed 's/^/active=/'
  systemctl is-enabled "$svc" 2>/dev/null | sed 's/^/enabled=/' || true
  systemctl show "$svc" \
    -p Id -p Names -p LoadState -p ActiveState -p SubState -p MainPID \
    -p FragmentPath -p DropInPaths -p User -p Group -p WorkingDirectory \
    -p ExecStart -p ExecMainStartTimestamp -p EnvironmentFiles \
    --no-pager 2>/dev/null || true
  echo '~~~'
done
echo

echo "## Processes"
echo
echo '~~~text'
ps -eo pid,ppid,stat,etime,pcpu,pmem,rss,comm,args 2>/dev/null \
  | grep -Ei 'synergy|atlas|explorer|indexer|rpc|observer|relayer|boot|seed|prometheus|grafana|nginx|node_exporter|node-exporter' \
  | grep -v grep || true
echo '~~~'
echo

echo "## Listeners"
echo
echo '~~~text'
(ss -ltnp 2>/dev/null || netstat -ltnp 2>/dev/null || true) \
  | grep -E '(:22|:80|:443|:3000|:4000|:5000|:5173|:5432|:5622|:5640|:5660|:6030|:9090|:9100|:9187|:3001|:4864)' || true
echo '~~~'
echo

echo "## Runtime Paths"
echo
echo '~~~text'
for path in \
  /opt/synergy/testnet/relayer \
  /opt/synergy/testnet/observer \
  /opt/synergy/Node-RPC \
  /opt/synergy/Node-EXP \
  /opt/synergy/testnet/bootstrap \
  /opt/synergy/testnet/seed \
  /var/lib/synergy \
  /etc/synergy \
  /var/log/synergy; do
  if [ -e "$path" ]; then
    safe_sudo du -sh "$path" 2>/dev/null | head -1 || true
    safe_sudo find "$path" -maxdepth 2 -type f \( -name '*.toml' -o -name '*.env' -o -name '*.json' -o -name '*.service' \) -printf '%p\n' 2>/dev/null | sort | head -120 || true
  fi
done
echo '~~~'
echo

echo "## Old Workspace References"
echo
echo '~~~text'
for root in /etc/systemd/system /etc/synergy /etc/default /etc/sysconfig /opt/synergy; do
  [ -e "$root" ] || continue
  safe_sudo grep -RIl --exclude-dir=node_modules --exclude='*.log' --exclude='*.jsonl' 'validator-workspace' "$root" 2>/dev/null | sort || true
done
echo '~~~'
echo

echo "## Local qRPC"
echo
echo '~~~json'
printf '{"health": %s, "latest": %s, "block_number": %s, "node_status": %s, "peer_info": %s}\n' \
  "$(json_rpc "http://127.0.0.1:${qrpc_port}" synergy_getHealth)" \
  "$(json_rpc "http://127.0.0.1:${qrpc_port}" synergy_getLatestBlock)" \
  "$(json_rpc "http://127.0.0.1:${qrpc_port}" synergy_getBlockNumber)" \
  "$(json_rpc "http://127.0.0.1:${qrpc_port}" synergy_getNodeStatus)" \
  "$(json_rpc "http://127.0.0.1:${qrpc_port}" synergy_getPeerInfo)"
echo '~~~'
echo

echo "## Public Endpoint Samples"
echo
echo '~~~json'
printf '{"public_rpc_health": %s, "public_rpc_latest": %s, "atlas_summary": %s, "atlas_readyz": %s}\n' \
  "$(json_rpc "$public_rpc_url" synergy_getHealth)" \
  "$(json_rpc "$public_rpc_url" synergy_getLatestBlock)" \
  "$(http_get "${atlas_api_url}/api/v1/network/summary")" \
  "$(http_get "${atlas_api_url}/readyz")"
echo '~~~'
echo

echo "## Recent Logs"
for svc in "${services[@]:-}"; do
  case "$svc" in
    *ssh*|systemd-*|dbus*) continue ;;
  esac
  echo
  echo "### ${svc}"
  echo '~~~text'
  journalctl -u "$svc" -n 80 --no-pager 2>/dev/null \
    | grep -Ei 'error|warn|panic|fatal|failed|listening|started|connected|sync|block|peer|height|atlas|rpc|relay|observer|boot|seed' \
    | tail -80 || true
  echo '~~~'
done
