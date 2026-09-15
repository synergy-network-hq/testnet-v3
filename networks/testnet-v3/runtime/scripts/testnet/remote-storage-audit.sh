#!/usr/bin/env bash
set -euo pipefail

echo "host=$(hostname 2>/dev/null || echo unknown)"
echo "kernel=$(uname -a 2>/dev/null || echo unknown)"
echo "timestamp_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date)"
echo "disk_root"
df -h /

echo "top_level_usage_kb"
for dir in /tmp /var/tmp "${HOME:-/root}" /opt/synergy /Volumes/xcode; do
  if [ -d "$dir" ]; then
    du -sk "$dir" 2>/dev/null || true
  fi
done | sort -n

echo "large_artifact_candidates"
find /tmp /var/tmp "${HOME:-/root}" /opt/synergy /Volumes/xcode \
  -xdev \
  -type f \
  \( -name "*.tar" -o -name "*.tar.gz" -o -name "*.tgz" -o -name "*.tar.zst" -o -name "*.zip" -o -name "*.deb" -o -name "*.log" \) \
  -size +200M \
  -exec ls -lh {} \; 2>/dev/null | sort -k5,5hr | head -60 || true

echo "stale_directory_candidates"
find /tmp /var/tmp "${HOME:-/root}" /opt/synergy /Volumes/xcode \
  -xdev \
  -maxdepth 5 \
  -type d \
  \( -name "synergy-*" -o -name "snapshot-*" -o -name "*backup*" -o -name "*evidence*" -o -name "runtime-backups" -o -name "incoming" \) \
  -mtime +0 \
  -print 2>/dev/null | sort | head -120 || true
