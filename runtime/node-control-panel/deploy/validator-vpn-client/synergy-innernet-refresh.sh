#!/usr/bin/env bash
set -euo pipefail

client="${SYNERGY_INNERNET_CLIENT:-/usr/local/lib/synergy/innernet}"
interface="${SYNERGY_INNERNET_INTERFACE:-sy-vpn}"

[[ -x "$client" ]] || {
  echo "Innernet client is not executable: $client" >&2
  exit 1
}
[[ "$interface" =~ ^[A-Za-z0-9_-]+$ ]] || {
  echo "Innernet interface name is invalid." >&2
  exit 1
}

exec 9>/run/lock/synergy-innernet-refresh.lock
flock -n 9 || exit 0
timeout --signal=TERM --kill-after=10s 90s "$client" fetch "$interface"

