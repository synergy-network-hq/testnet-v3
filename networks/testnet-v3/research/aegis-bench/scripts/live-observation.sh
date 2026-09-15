#!/usr/bin/env bash
set -euo pipefail

OUTPUT_FILE="${1:-}"
if [[ -z "$OUTPUT_FILE" ]]; then
  echo "usage: $0 OUTPUT_FILE" >&2
  exit 2
fi
if [[ -e "$OUTPUT_FILE" ]]; then
  echo "refusing to overwrite existing observation: $OUTPUT_FILE" >&2
  exit 2
fi

mkdir -p "$(dirname "$OUTPUT_FILE")"

# One workbook-authorized SSH connection. The remote command is deliberately
# read-only and omits environment dumps, addresses, socket endpoints, and keys.
ssh synergy-rpc 'bash -s' >"$OUTPUT_FILE" <<'REMOTE'
set -euo pipefail
printf 'classification=LIVE TESTNET OBSERVATION\n'
printf 'observed_at_utc='
date -u '+%Y-%m-%dT%H:%M:%SZ'
printf 'kernel='
uname -srm
systemctl show synergy-chain1266-role@rpc-gateway.service \
  --property=Id,LoadState,ActiveState,SubState,Result,NRestarts,UnitFileState,ActiveEnterTimestamp,InactiveEnterTimestamp \
  --no-pager
printf 'running_synergy_process_count='
ps -eo comm= | awk 'tolower($0) ~ /synergy|testnet|aegis/ {count++} END {print count+0}'
printf 'role_service_wrapper_sha256='
sha256sum /usr/local/libexec/synergy/chain1266-role-service 2>/dev/null | awk '{print $1}'
printf 'legacy_release_guard_sha256='
sha256sum /opt/synergy/testnet-v3/bin/synergy-release-guard 2>/dev/null | awk '{print $1}'
printf 'versioned_node_artifact_count='
find /opt/synergy/testnet-v3/bin -maxdepth 1 -type f -name 'synergy-node-v*' -print 2>/dev/null | wc -l | tr -d ' '
printf 'last_journal_height='
journalctl -u synergy-chain1266-role@rpc-gateway.service -n 100 --no-pager -o cat 2>/dev/null \
  | sed -n 's/.*"height":[[:space:]]*\([0-9][0-9]*\).*/\1/p' \
  | tail -n 1
REMOTE

chmod 600 "$OUTPUT_FILE"
echo "wrote sanitized passive observation to $OUTPUT_FILE"
