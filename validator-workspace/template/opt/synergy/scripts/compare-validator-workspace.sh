#!/usr/bin/env bash
set -euo pipefail

if [[ $# -gt 0 ]]; then
  ALIASES=("$@")
else
  ALIASES=(synergy-val1 synergy-val2 synergy-val3 synergy-val4 synergy-val5 synergy-val6)
fi

for alias in "${ALIASES[@]}"; do
  echo "== $alias =="
  ssh -o BatchMode=yes -o ConnectTimeout=8 "$alias" 'bash -s' <<'REMOTE'
set -euo pipefail
echo "user=$(id -un)"
pgrep -af 'synergy.* start --config' || true
test -d /home/node/.synergy/testnet/nodes/validator-workspace && echo "workspace=present" || echo "workspace=missing"
sha256sum /opt/synergy/bin/synergy-validator /etc/synergy/validator/genesis.json 2>/dev/null || true
systemctl cat synergy-validator.service 2>/dev/null | grep -E 'User=|ExecStart=|EnvironmentFile=|WorkingDirectory=' || true
REMOTE
done

