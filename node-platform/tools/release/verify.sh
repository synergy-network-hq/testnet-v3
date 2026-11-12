#!/bin/sh
set -eu
dir=${1:?release directory required}
: "${SYNERGY_RELEASE_TRUST_KEY_PATH:?explicit pinned release public-key file required}"
: "${SYNERGY_RELEASE_KEY_ID:?explicit governed release signer key ID required}"
: "${SYNERGY_RELEASE_CHAIN_ID:?explicit release chain ID required}"
: "${SYNERGY_RELEASE_INSTALLED_SEQUENCE:?explicit installed sequence required; use 0 for a fresh install}"
keytool=${SYNERGY_KEYTOOL_BINARY:-synergy-keytool}
command -v "$keytool" >/dev/null || { echo "synergy-keytool is unavailable" >&2; exit 1; }
(cd "$dir" && sha256sum -c SHA256SUMS)
python3 "$(dirname "$0")/provenance.py" verify --binary "$dir/synergy-node" \
    --provenance "$dir/build-provenance.json" --qualification "$dir/qualification.json"
"$keytool" verify-release "$dir/release-metadata.json" "$dir/synergy-node" \
    "$SYNERGY_RELEASE_CHAIN_ID" "$SYNERGY_RELEASE_KEY_ID" \
    "$SYNERGY_RELEASE_TRUST_KEY_PATH" "$SYNERGY_RELEASE_INSTALLED_SEQUENCE"
