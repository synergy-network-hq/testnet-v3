#!/usr/bin/env bash
set -euo pipefail

echo "== block times =="
/opt/synergy/scripts/check-block-times.sh || true
echo "== system =="
date -u
uptime
free -h || true
df -h /var/lib/synergy/validator /var/log/synergy/validator || true
iostat -xz 1 2 2>/dev/null || true
timedatectl status 2>/dev/null || true
echo "== network =="
ss -ltnp | grep -E ':(5622|5640|5660|6030)\b' || true
echo "== peers =="
curl -fsS -m 5 -H 'content-type: application/json' \
  --data '{"jsonrpc":"2.0","method":"synergy_getPeers","params":[],"id":1}' \
  http://127.0.0.1:5640 || true
echo "== quarantine =="
curl -fsS -m 5 -H 'content-type: application/json' \
  --data '{"jsonrpc":"2.0","method":"synergy_getQuarantineStatus","params":[],"id":1}' \
  http://127.0.0.1:5640 || true

