#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

CLASSICAL_CRYPTO_PATTERN='k256|secp256k1|ecdsa|(?i:ed25519)'
BYPASS_PATTERN='SYNERGY_CONSENSUS_ALLOW_GENESIS_STATUS_BYPASS|allow_genesis_status_bypass[[:space:]]*=[[:space:]]*true|return true;[[:space:]]*//[[:space:]]*Placeholder|simulate VRF|placeholder QC|fallback_pub|skipping signature verification|EPHEMERAL_.*(VALIDATOR|LEADER).*KEY|get_or_create_(validator|leader)_keypair'

# The coordinator signs validator transport metadata outside the consensus protocol.
# Keep that narrowly scoped control-plane verifier out of the consensus-crypto scan.
if rg -n "$CLASSICAL_CRYPTO_PATTERN" src \
  -g '*.rs' \
  -g '!src/p2p/validator_transport_registry.rs'; then
  echo "PQC consensus guard failed: runtime source outside the approved transport-metadata verifier references prohibited classical crypto." >&2
  exit 1
fi

if rg -n "$BYPASS_PATTERN" src config scripts .github \
  -g '!target' \
  -g '!scripts/testnet/check-pqc-consensus-guard.sh'; then
  echo "PQC consensus guard failed: consensus-critical paths reference a prohibited bypass or placeholder crypto pattern." >&2
  exit 1
fi

echo "PQC consensus guard passed."
