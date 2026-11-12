#!/bin/sh
set -eu
command -v systemctl >/dev/null
command -v netbird >/dev/null
test "$(id -u)" -ne 0 || { echo "refusing root bootstrap" >&2; exit 1; }
df -Pk /var/lib | awk 'NR==2 { if ($4 < 10485760) exit 1 }'
