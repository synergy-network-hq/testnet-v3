#!/usr/bin/env bash
set -euo pipefail

APPLY=false
FORCE_SECRET_OVERWRITE=false
for arg in "$@"; do
  case "$arg" in
    --apply) APPLY=true ;;
    --dry-run) APPLY=false ;;
    --force-secret-overwrite) FORCE_SECRET_OVERWRITE=true ;;
    *) echo "unknown argument: $arg" >&2; exit 2 ;;
  esac
done

if [[ "$FORCE_SECRET_OVERWRITE" == "true" ]]; then
  echo "refusing --force-secret-overwrite; preserve live validator secrets manually" >&2
  exit 1
fi

run() {
  if [[ "$APPLY" == "true" ]]; then
    "$@"
  else
    printf '[dry-run]'; printf ' %q' "$@"; printf '\n'
  fi
}

run id node >/dev/null 2>&1 || run useradd --create-home --home-dir /home/node --shell /bin/bash node
for dir in \
  /etc/synergy/validator/keys \
  /var/lib/synergy/validator \
  /var/lib/synergy/validator/identity \
  /var/lib/synergy/validator/config \
  /var/lib/synergy/validator/state/store \
  /var/lib/synergy/validator/state/derived \
  /var/lib/synergy/validator/state/checkpoints \
  /var/lib/synergy/validator/state/snapshots \
  /var/lib/synergy/validator/state/quarantine \
  /var/lib/synergy/validator/evidence \
  /var/lib/synergy/validator/logs \
  /var/lib/synergy/validator/runtime \
  /var/log/synergy/validator \
  /var/backups/synergy/validator \
  /opt/synergy/bin \
  /opt/synergy/scripts; do
  run mkdir -p "$dir"
done

run chown -R node:node /var/lib/synergy/validator /var/log/synergy/validator
run chown root:node /etc/synergy/validator /var/backups/synergy/validator
run chown node:node /etc/synergy/validator/keys
run chmod 0750 /home/node /etc/synergy/validator /var/lib/synergy/validator /var/log/synergy/validator /var/backups/synergy/validator
run chmod 0700 /etc/synergy/validator/keys
run systemctl daemon-reload

echo "install-validator-appliance completed (apply=$APPLY)"
