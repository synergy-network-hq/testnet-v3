#!/usr/bin/env bash
set -euo pipefail

LEGACY_OK=false
for arg in "$@"; do
  case "$arg" in
    --legacy-ok) LEGACY_OK=true ;;
    *) echo "unknown argument: $arg" >&2; exit 2 ;;
  esac
done

fail=0
check_path() { [[ -e "$1" ]] || { echo "missing: $1"; fail=1; }; }
check_path /etc/synergy/validator/config.toml
check_path /etc/synergy/validator/node.env
check_path /etc/systemd/system/synergy-validator.service
check_path /opt/synergy/bin/synergy-validator
check_path /var/lib/synergy/validator
check_path /var/lib/synergy/validator/identity
check_path /var/lib/synergy/validator/config
check_path /var/lib/synergy/validator/state/store
check_path /var/lib/synergy/validator/state/derived
check_path /var/lib/synergy/validator/state/checkpoints
check_path /var/lib/synergy/validator/state/snapshots
check_path /var/lib/synergy/validator/state/quarantine
check_path /var/lib/synergy/validator/evidence
check_path /var/lib/synergy/validator/logs
check_path /var/lib/synergy/validator/runtime
check_path /var/log/synergy/validator

if systemctl cat synergy-validator.service 2>/dev/null | grep -E '/home/(justin|rob|synergyop)|validator-6-control-panel|validator-workspace'; then
  echo "active service references old user/workspace"
  fail=1
fi

old_workspace=/home/node/.synergy/testnet/nodes/validator-workspace
if [[ -L "$old_workspace" ]]; then
  echo "old validator-workspace remains a symlink"
  fail=1
elif [[ -d "$old_workspace" && ! -f "$old_workspace/README.validator-appliance-migrated.txt" ]]; then
  echo "old validator-workspace remains usable instead of inert marker"
  fail=1
fi

if [[ -d /etc/synergy/validator/keys ]] && find /etc/synergy/validator/keys -type f -perm /077 | grep -q .; then
  echo "secret key files are group/world accessible"
  fail=1
fi

process_users=$(pgrep -af 'synergy.* start --config' | awk '{print $1}' | while read -r pid; do ps -o user= -p "$pid"; done | sort -u || true)
if [[ -n "$process_users" && "$process_users" != "node" && "$LEGACY_OK" != "true" ]]; then
  echo "validator process user is not node: $process_users"
  fail=1
fi

if [[ -f /var/lib/synergy/validator/validator_quarantine.json ]]; then
  echo "active quarantine marker exists"
  fail=1
fi

sha256sum /opt/synergy/bin/synergy-validator /etc/synergy/validator/genesis.json /etc/synergy/validator/config.toml 2>/dev/null || true
exit "$fail"
