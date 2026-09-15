#!/usr/bin/env bash
set -euo pipefail

# Send SNRG from the local faucet key using the signed public-RPC path.
#
# Usage:
#   ./scripts/send-tokens.sh <recipient_address> <amount_snrg>
#
# This wrapper intentionally delegates signing/submission to
# faucet-transfer-interactive.sh so public sends use synergy_sendTransaction
# instead of the off-host-blocked synergy_sendTokens helper method.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ $# -ne 2 ]]; then
  echo "Usage: $0 <recipient_address> <amount_snrg>" >&2
  echo "Example: $0 synw17nh265ug2fgc8guv2ad7tt8kv0wlhesxndl8 1" >&2
  exit 1
fi

RECIPIENT="$(printf '%s' "$1" | tr -d '[:space:]')"
AMOUNT_SNRG="$(printf '%s' "$2" | tr -d '[:space:]')"

if [[ ! "$RECIPIENT" =~ ^syn[0-9a-z]{10,70}$ ]]; then
  echo "Invalid Synergy address: $RECIPIENT" >&2
  echo "Expected a lowercase address beginning with syn." >&2
  exit 1
fi

echo "Synergy Testnet signed faucet send"
echo "Recipient: $RECIPIENT"
echo "Amount:    $AMOUNT_SNRG SNRG"
echo

if [[ "${SYNERGY_ASSUME_YES:-0}" != "1" ]]; then
  read -r -p "Type yes to continue: " CONFIRM
  if [[ "$CONFIRM" != "yes" ]]; then
    echo "Cancelled. No transaction was submitted."
    exit 0
  fi
fi

printf '%s\n%s\nyes\n' "$RECIPIENT" "$AMOUNT_SNRG" | "$SCRIPT_DIR/faucet-transfer-interactive.sh"
