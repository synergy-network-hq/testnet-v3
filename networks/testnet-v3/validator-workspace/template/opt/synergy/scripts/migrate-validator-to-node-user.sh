#!/usr/bin/env bash
set -euo pipefail

APPLY=false
SOURCE_WORKSPACE=""
OLD_SERVICE=""
for arg in "$@"; do
  case "$arg" in
    --apply) APPLY=true ;;
    --dry-run) APPLY=false ;;
    --source-workspace=*) SOURCE_WORKSPACE="${arg#*=}" ;;
    --old-service=*) OLD_SERVICE="${arg#*=}" ;;
    *) echo "unknown argument: $arg" >&2; exit 2 ;;
  esac
done

if [[ -z "$SOURCE_WORKSPACE" ]]; then
  echo "usage: migrate-validator-to-node-user.sh --source-workspace=<path> [--old-service=<name>] [--apply]" >&2
  exit 2
fi
if [[ ! -d "$SOURCE_WORKSPACE" ]]; then
  echo "source workspace does not exist: $SOURCE_WORKSPACE" >&2
  exit 1
fi

TARGET_WORKSPACE=/var/lib/synergy/validator
BACKUP_ROOT=/var/backups/synergy/validator
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
BACKUP="$BACKUP_ROOT/pre-node-migration-$STAMP"

run() {
  if [[ "$APPLY" == "true" ]]; then
    "$@"
  else
    printf '[dry-run]'; printf ' %q' "$@"; printf '\n'
  fi
}

echo "source=$SOURCE_WORKSPACE"
echo "target=$TARGET_WORKSPACE"
echo "backup=$BACKUP"

run mkdir -p "$BACKUP" "$TARGET_WORKSPACE" /etc/synergy/validator/keys /var/lib/synergy/validator /var/log/synergy/validator
for appliance_dir in identity config state/store state/derived state/checkpoints state/snapshots state/quarantine evidence logs runtime; do
  run mkdir -p "/var/lib/synergy/validator/$appliance_dir"
done
run tar -C "$SOURCE_WORKSPACE" -czf "$BACKUP/source-workspace.tar.gz" config keys data 2>/dev/null || true
run cp -a "$SOURCE_WORKSPACE/config/." /etc/synergy/validator/ 2>/dev/null || true
run cp -a "$SOURCE_WORKSPACE/keys/." /etc/synergy/validator/keys/ 2>/dev/null || true
run cp -a "$SOURCE_WORKSPACE/data/." /var/lib/synergy/validator/ 2>/dev/null || true
run chown -R node:node /etc/synergy/validator/keys /var/lib/synergy/validator /var/log/synergy/validator
run find /etc/synergy/validator/keys -type f -exec chmod 0600 {} +

if [[ -n "$OLD_SERVICE" ]]; then
  run systemctl disable "$OLD_SERVICE"
fi
run systemctl daemon-reload
echo "migration staged (apply=$APPLY); start synergy-validator.service only after verify-validator-workspace passes"
