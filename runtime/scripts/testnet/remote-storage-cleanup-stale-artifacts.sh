#!/usr/bin/env bash
set -euo pipefail

apply="${CLEANUP_APPLY:-0}"
min_age_minutes="${CLEANUP_MIN_AGE_MINUTES:-360}"
deleted_kb_total=0

echo "cleanup_apply=${apply}"
echo "cleanup_min_age_minutes=${min_age_minutes}"
echo "host=$(hostname 2>/dev/null || echo unknown)"
echo "timestamp_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date)"
echo "disk_before"
df -h /

delete_path() {
  local path="$1"
  [ -e "$path" ] || return 0
  local kb
  kb="$(du -sk "$path" 2>/dev/null | awk '{print $1}' || true)"
  kb="${kb:-0}"
  echo "cleanup_candidate_kb=${kb} path=${path}"
  if [ "$apply" = "1" ]; then
    rm -rf -- "$path"
    deleted_kb_total=$((deleted_kb_total + kb))
    echo "cleanup_deleted path=${path}"
  fi
}

scan_files() {
  local root="$1"
  [ -d "$root" ] || return 0
  find "$root" \
    -xdev \
    -type f \
    -mmin +"$min_age_minutes" \
    \( -name "*.tar" -o -name "*.tar.gz" -o -name "*.tgz" -o -name "*.tar.zst" -o -name "*.zip" -o -name "synergy-node-control-panel_*.deb" \) \
    -print0 2>/dev/null | while IFS= read -r -d '' path; do
      delete_path "$path"
    done
}

scan_tmp_dirs() {
  local root="$1"
  [ -d "$root" ] || return 0
  find "$root" \
    -xdev \
    -mindepth 1 \
    -maxdepth 2 \
    -type d \
    -mmin +"$min_age_minutes" \
    \( -name "synergy-*" -o -name "validator-pruned-*" -o -name "majority-*" -o -name "canonical-*" -o -name "derived-*" \) \
    -print0 2>/dev/null | while IFS= read -r -d '' path; do
      delete_path "$path"
    done
}

scan_incoming_dirs() {
  local root="$1"
  [ -d "$root" ] || return 0
  find "$root" \
    -xdev \
    -mindepth 1 \
    -maxdepth 2 \
    -type d \
    -mmin +"$min_age_minutes" \
    \( -name "snapshot-*" -o -name "rpc-recovery-*" -o -name "support-*" \) \
    -print0 2>/dev/null | while IFS= read -r -d '' path; do
      delete_path "$path"
    done
  find "$root" \
    -xdev \
    -type f \
    -mmin +"$min_age_minutes" \
    \( -name "snapshot-*.tar" -o -name "snapshot-*.tar.gz" -o -name "snapshot-*.tgz" -o -name "snapshot-*.tar.zst" \) \
    -print0 2>/dev/null | while IFS= read -r -d '' path; do
      delete_path "$path"
    done
}

scan_files /tmp
scan_files /var/tmp
scan_tmp_dirs /tmp
scan_tmp_dirs /var/tmp

if [ -n "${HOME:-}" ]; then
  scan_files "$HOME/.cache/synergy-node-control-panel-updater"
  scan_files "$HOME/Downloads"
  scan_incoming_dirs "$HOME/.synergy/testnet/nodes/validator-workspace/incoming"
  scan_incoming_dirs "$HOME/synergy-snapshot-distribution"
  scan_incoming_dirs "$HOME/synergy-snapshot-distributions"
  scan_incoming_dirs "$HOME/synergy-testnet-snapshots"
fi

scan_incoming_dirs /opt/synergy/testnet/relayer/incoming
scan_incoming_dirs /opt/synergy/Node-RPC/incoming
scan_incoming_dirs /opt/synergy/Node-EXP/incoming
scan_files /opt/synergy/testnet/relayer/incoming
scan_files /opt/synergy/Node-RPC/incoming
scan_files /opt/synergy/Node-EXP/incoming

echo "cleanup_deleted_kb_total=${deleted_kb_total}"
echo "disk_after"
df -h /
