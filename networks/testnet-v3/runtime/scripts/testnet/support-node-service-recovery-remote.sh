#!/usr/bin/env bash
set -euo pipefail

role="${SUPPORT_NODE_ROLE:-support-node}"
service="${SUPPORT_SERVICE:?SUPPORT_SERVICE is required}"
workdir="${SUPPORT_WORKDIR:?SUPPORT_WORKDIR is required}"
binary_rel="${SUPPORT_BINARY_REL:-bin/synergy-testnet-linux-amd64}"
expected_sha="${EXPECTED_BINARY_SHA256:-}"
install_from_stdin="${INSTALL_BINARY_FROM_STDIN:-0}"
metrics_url="${SUPPORT_METRICS_URL:-http://127.0.0.1:6030/metrics}"
public_rpc_url="${PUBLIC_RPC_URL:-https://testnet-core-rpc.synergy-network.io}"
post_wait_secs="${SUPPORT_POST_RESTART_WAIT_SECS:-30}"
restart_after_install="${SUPPORT_RESTART_AFTER_INSTALL:-1}"

safe_sudo() {
  if command -v sudo >/dev/null 2>&1; then
    sudo -n "$@" 2>/dev/null || sudo "$@" 2>/dev/null || "$@"
  else
    "$@"
  fi
}

json_rpc_block_number() {
  python3 - "$public_rpc_url" <<'PY' 2>/dev/null || true
import json
import sys
import urllib.request

url = sys.argv[1]
payload = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "synergy_getBlockNumber", "params": []}).encode()
request = urllib.request.Request(url, data=payload, headers={"content-type": "application/json"}, method="POST")
try:
    with urllib.request.urlopen(request, timeout=8) as response:
        body = json.loads(response.read().decode())
    print(body.get("result", ""))
except Exception:
    print("")
PY
}

metrics_summary() {
  python3 - "$metrics_url" "$public_rpc_url" <<'PY' 2>/dev/null || true
import json
import re
import sys
import time
import urllib.request

metrics_url, rpc_url = sys.argv[1], sys.argv[2]

def get_text(url):
    start = time.time()
    try:
        with urllib.request.urlopen(url, timeout=8) as response:
            return response.read().decode(errors="replace"), round(time.time() - start, 3), None
    except Exception as exc:
        return "", round(time.time() - start, 3), str(exc)

def rpc_block_number():
    payload = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "synergy_getBlockNumber", "params": []}).encode()
    request = urllib.request.Request(rpc_url, data=payload, headers={"content-type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=8) as response:
            body = json.loads(response.read().decode())
        return body.get("result")
    except Exception as exc:
        return {"error": str(exc)}

text, elapsed, error = get_text(metrics_url)
result = {"metrics_url": metrics_url, "elapsed_sec": elapsed, "error": error}
if text:
    gauges = {}
    for name in [
        "synergy_chain_height",
        "synergy_chain_blocks_total",
        "synergy_chain_last_block_timestamp_seconds",
        "synergy_chain_last_block_age_seconds",
        "synergy_sync_in_progress",
        "synergy_sync_gap_blocks",
        "synergy_sync_progress_percent",
        "synergy_p2p_peers_connected",
        "synergy_p2p_best_validator_peer_height",
    ]:
        match = re.search(rf"^{re.escape(name)}\\s+([-+0-9.eE]+)$", text, re.MULTILINE)
        if match:
            raw = match.group(1)
            try:
                value = float(raw)
                gauges[name] = int(value) if value.is_integer() else value
            except Exception:
                gauges[name] = raw
    node_info = re.search(r'^synergy_node_info\\{([^}]*)\\}\\s+1$', text, re.MULTILINE)
    if node_info:
        labels = {}
        for key, value in re.findall(r'([a-zA-Z_][a-zA-Z0-9_]*)="([^"]*)"', node_info.group(1)):
            if key.endswith("key") or key in {"secret", "token", "password"}:
                continue
            labels[key] = value
        result["node_info"] = labels
    result["gauges"] = gauges
rpc_height = rpc_block_number()
result["public_rpc_block_number"] = rpc_height
try:
    if isinstance(rpc_height, int) and "gauges" in result and "synergy_chain_height" in result["gauges"]:
        result["height_lag"] = rpc_height - int(result["gauges"]["synergy_chain_height"])
except Exception:
    pass
print(json.dumps(result, sort_keys=True))
PY
}

copy_if_exists() {
  local src="$1"
  local dest="$2"
  if [ -e "$src" ]; then
    safe_sudo mkdir -p "$(dirname "$dest")"
    safe_sudo cp -a "$src" "$dest"
  fi
}

timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
backup_dir="/opt/synergy/backups/support-node-recovery-${role}-${timestamp}"
binary_path="${workdir%/}/${binary_rel}"

echo "# Support Node Service Recovery"
echo
echo "role: ${role}"
echo "service: ${service}"
echo "workdir: ${workdir}"
echo "binary_path: ${binary_path}"
echo "generated_utc: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "hostname: $(hostname -f 2>/dev/null || hostname)"
echo "backup_dir: ${backup_dir}"
echo

echo "## Before"
echo '~~~text'
systemctl is-active "$service" 2>/dev/null | sed 's/^/active=/' || true
systemctl show "$service" \
  -p ActiveState -p SubState -p MainPID -p WorkingDirectory -p ExecStart \
  -p EnvironmentFiles -p FragmentPath -p DropInPaths --no-pager 2>/dev/null || true
if [ -x "$binary_path" ]; then
  sha256sum "$binary_path" 2>/dev/null || shasum -a 256 "$binary_path" 2>/dev/null || true
  "$binary_path" --version 2>/dev/null || true
fi
metrics_summary
echo '~~~'
echo

echo "## Backup"
echo '~~~text'
safe_sudo mkdir -p "$backup_dir"
fragment="$(systemctl show "$service" -p FragmentPath --value 2>/dev/null || true)"
dropins="$(systemctl show "$service" -p DropInPaths --value 2>/dev/null || true)"
envfiles="$(systemctl show "$service" -p EnvironmentFiles --value 2>/dev/null | sed 's/ (ignore_errors=[^)]*)//g' || true)"
copy_if_exists "$fragment" "${backup_dir}/systemd/$(basename "$fragment" 2>/dev/null || echo fragment)"
for path in $dropins $envfiles; do
  [ -n "$path" ] || continue
  copy_if_exists "$path" "${backup_dir}/$(echo "$path" | sed 's#^/##')"
done
copy_if_exists "${workdir%/}/config" "${backup_dir}/workdir/config"
copy_if_exists "${workdir%/}/node.env" "${backup_dir}/workdir/node.env"
copy_if_exists "$binary_path" "${backup_dir}/workdir/${binary_rel}.before"
safe_sudo find "$backup_dir" -maxdepth 4 -type f -printf '%p\n' 2>/dev/null | sort || true
echo '~~~'
echo

if [ "$install_from_stdin" = "1" ]; then
  echo "## Binary Install"
  echo '~~~text'
  tmp_binary="/tmp/support-node-${role}-${timestamp}.bin"
  cat > "$tmp_binary"
  chmod 0755 "$tmp_binary"
  uploaded_sha="$(sha256sum "$tmp_binary" 2>/dev/null | awk '{print $1}')"
  echo "uploaded_sha256=${uploaded_sha}"
  if [ -n "$expected_sha" ] && [ "$uploaded_sha" != "$expected_sha" ]; then
    echo "expected_sha256=${expected_sha}"
    echo "sha256_mismatch=true"
    rm -f "$tmp_binary"
    exit 23
  fi
  owner_group="$(stat -c '%U:%G' "$binary_path" 2>/dev/null || echo root:root)"
  mode="$(stat -c '%a' "$binary_path" 2>/dev/null || echo 755)"
  safe_sudo install -m "$mode" -o "${owner_group%%:*}" -g "${owner_group##*:}" "$tmp_binary" "${binary_path}.new"
  safe_sudo mv "${binary_path}.new" "$binary_path"
  rm -f "$tmp_binary"
  sha256sum "$binary_path" 2>/dev/null || shasum -a 256 "$binary_path" 2>/dev/null || true
  "$binary_path" --version 2>/dev/null || true
  echo '~~~'
  echo
fi

echo "## Restart"
echo '~~~text'
if [ "$restart_after_install" = "0" ]; then
  safe_sudo systemctl daemon-reload
  echo "restart_skipped=true"
else
  safe_sudo systemctl daemon-reload
  safe_sudo systemctl restart "$service"
  sleep "$post_wait_secs"
fi
systemctl is-active "$service" 2>/dev/null | sed 's/^/active=/' || true
systemctl show "$service" \
  -p ActiveState -p SubState -p MainPID -p WorkingDirectory -p ExecStart \
  -p EnvironmentFiles -p FragmentPath -p DropInPaths --no-pager 2>/dev/null || true
echo '~~~'
echo

echo "## After"
echo '~~~text'
if [ -x "$binary_path" ]; then
  sha256sum "$binary_path" 2>/dev/null || shasum -a 256 "$binary_path" 2>/dev/null || true
  "$binary_path" --version 2>/dev/null || true
fi
(ss -ltnp 2>/dev/null || netstat -ltnp 2>/dev/null || true) \
  | grep -Ei 'synergy|atlas|explorer|indexer|rpc|observer|relayer|boot|seed|:562|:564|:566|:6030|:9090|:9100|:80|:443' || true
echo '--- validator-workspace refs ---'
grep -RIn --exclude='*.log' --exclude='*.jsonl' 'validator-workspace' "$fragment" ${dropins:-} "${workdir%/}/config" /etc/default /etc/sysconfig 2>/dev/null || true
echo '--- metrics summary ---'
metrics_summary
echo '--- recent logs ---'
journalctl -u "$service" --since "5 minutes ago" -n 120 --no-pager 2>/dev/null \
  | grep -Ei 'error|warn|panic|fatal|failed|started|listening|connected|sync|block|height|peer|observer|relay|boot|seed' \
  | tail -120 || true
echo '~~~'
