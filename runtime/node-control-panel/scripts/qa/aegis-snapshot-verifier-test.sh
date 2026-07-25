#!/usr/bin/env bash
set -euo pipefail

verifier="${1:-}"
[[ -n "$verifier" && -x "$verifier" ]] || {
  echo "usage: $0 <synergy-aegis-verifier>" >&2
  exit 2
}

temp_dir="$(mktemp -d "${TMPDIR:-/tmp}/synergy-aegis-qa.XXXXXX")"
cleanup() {
  rm -rf "$temp_dir"
}
trap cleanup EXIT

identity="$temp_dir/archive-identity.json"
payload="$temp_dir/catalog.json"
signature="$temp_dir/catalog.json.sig"

printf '%s\n' '{"chain_id":1264,"network_id":"synergy-testnet-v3","snapshot":"qa"}' > "$payload"
"$verifier" init-archive-identity --output "$identity" >/dev/null
SYNERGY_AEGIS_ARCHIVE_IDENTITY="$identity" \
  "$verifier" sign-json --domain SYNERGY_ARCHIVE_SNAPSHOT_CATALOG_V1 --input "$payload" --output "$signature" >/dev/null
"$verifier" verify-json --domain SYNERGY_ARCHIVE_SNAPSHOT_CATALOG_V1 --input "$payload" --signature "$signature" >/dev/null

printf '%s\n' '{"chain_id":1264,"network_id":"synergy-testnet-v3","snapshot":"tampered"}' > "$payload"
if "$verifier" verify-json --domain SYNERGY_ARCHIVE_SNAPSHOT_CATALOG_V1 --input "$payload" --signature "$signature" >/dev/null 2>&1; then
  echo "tampered payload unexpectedly verified" >&2
  exit 1
fi

echo "canonical Aegis snapshot verifier QA passed"
