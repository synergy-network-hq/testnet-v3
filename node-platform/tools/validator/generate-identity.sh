#!/bin/sh
# Fresh APQE custody only. This never registers a validator or starts PoSy.
set -eu
if [ "$#" -ne 6 ]; then
    echo "usage: generate-identity.sh TRUSTED_BUILD_REPORT REPORT_SHA256 NODE_CLASS CHAIN_ID_HEX GENESIS_HASH_HEX NEW_PRIVATE_DIRECTORY" >&2
    exit 2
fi
if [ "$3" != "synv1" ]; then
    echo "validator role requires the canonical synv1 node class" >&2
    exit 2
fi
umask 077
# The operator selects an authenticated APQE release. No legacy keytool fallback.
exec "${APQE_BIN:-/usr/bin/apqe}" validator-provision "$@"
