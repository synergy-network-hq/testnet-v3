#!/usr/bin/env bash
set -euo pipefail

# Interactive Synergy Testnet transfer helper for the Token Sales wallet.
# Reuses the same signed synergy_sendTransaction flow as the faucet helper.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

export SYNERGY_SOURCE_LABEL="${SYNERGY_SOURCE_LABEL:-Token Sales wallet}"
export SYNERGY_SOURCE_KEYFILE="${SYNERGY_SOURCE_KEYFILE:-/Users/devpup/Desktop/synergy-testnet-data-files/new-network-addresses/TokenSalesWallet.dec.json}"

exec "$SCRIPT_DIR/faucet-transfer-interactive.sh"
