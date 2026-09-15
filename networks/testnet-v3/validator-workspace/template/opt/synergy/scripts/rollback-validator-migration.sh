#!/usr/bin/env bash
set -euo pipefail

BACKUP=${1:-}
if [[ -z "$BACKUP" || ! -d "$BACKUP" ]]; then
  echo "usage: rollback-validator-migration.sh /var/backups/synergy/validator/pre-node-migration-<timestamp>" >&2
  exit 2
fi

echo "restoring from $BACKUP"
if [[ -f "$BACKUP/source-workspace.tar.gz" ]]; then
  mkdir -p /home/node/.synergy/testnet/nodes/validator-workspace
  tar -C /home/node/.synergy/testnet/nodes/validator-workspace -xzf "$BACKUP/source-workspace.tar.gz"
fi
systemctl daemon-reload
echo "rollback files restored; operator must choose which service to start"

