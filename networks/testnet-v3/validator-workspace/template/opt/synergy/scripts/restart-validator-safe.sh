#!/usr/bin/env bash
set -euo pipefail

SERVICE=${SERVICE:-synergy-validator.service}
echo "pre-restart status"
systemctl --no-pager --plain status "$SERVICE" || true
curl -fsS -m 5 -H 'content-type: application/json' \
  --data '{"jsonrpc":"2.0","method":"synergy_getBlockNumber","params":[],"id":1}' \
  http://127.0.0.1:5640 || true
systemctl restart "$SERVICE"
sleep 10
systemctl is-active --quiet "$SERVICE"
curl -fsS -m 5 -H 'content-type: application/json' \
  --data '{"jsonrpc":"2.0","method":"synergy_getQuarantineStatus","params":[],"id":1}' \
  http://127.0.0.1:5640

