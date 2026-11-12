#!/bin/sh
set -eu
test "$#" -eq 7 || {
    echo "usage: $0 METADATA BINARY CHAIN_ID KEY_ID SECRET_KEY TRUST_PUBLIC_KEY OUTPUT" >&2
    exit 2
}
keytool=${SYNERGY_KEYTOOL_BINARY:-synergy-keytool}
command -v "$keytool" >/dev/null || { echo "synergy-keytool is unavailable" >&2; exit 1; }
"$keytool" sign-release "$@"
