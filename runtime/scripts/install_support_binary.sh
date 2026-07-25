#!/usr/bin/env bash
set -euo pipefail

src="$1"
dest="$2"
service="${3:-}"
expected_sha="$4"
backup_suffix="${5:-pre-v19.0.49-20260718T0107Z}"

actual_sha="$(sha256sum "$src" | awk '{print $1}')"
if [ "$actual_sha" != "$expected_sha" ]; then
  echo "checksum mismatch: $actual_sha != $expected_sha" >&2
  exit 1
fi

install -d -m 0755 "$(dirname "$dest")/backups"
if [ -e "$dest" ]; then
  cp -a "$dest" "$(dirname "$dest")/backups/$(basename "$dest").$backup_suffix"
fi
install -m 0755 "$src" "$dest"

if [ -n "$service" ]; then
  systemctl restart "$service"
  sleep 2
  systemctl is-active "$service"
fi

"$dest" --version | head -n 2
sha256sum "$dest"
