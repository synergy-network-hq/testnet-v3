#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

cat >&2 <<EOF
This legacy template generator is disabled because it embeds obsolete addresses
and does not produce the current canonical genesis schema.

Build Testnet-v3 genesis from NEW public key/address inputs with:

  $ROOT_DIR/scripts/testnet/rebuild-genesis-from-keyfiles.sh <public-key-directory>

or rebuild from an approved public manifest with:

  $ROOT_DIR/scripts/testnet/rebuild-genesis-from-public-manifest.sh <public-manifest.json>

Then validate the result with:

  python3 $ROOT_DIR/scripts/testnet/genesis_tool.py validate \\
    --genesis $ROOT_DIR/config/genesis.json \\
    --network-identifiers $ROOT_DIR/network-identifiers.testnet.json
EOF

exit 1
