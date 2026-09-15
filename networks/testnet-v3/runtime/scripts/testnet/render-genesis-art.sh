#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
GENESIS_FILE="${GENESIS_FILE:-$ROOT_DIR/genesis.testnet.json}"
NETWORK_IDENTIFIERS_FILE="${NETWORK_IDENTIFIERS_FILE:-$ROOT_DIR/network-identifiers.testnet.json}"
OUT_DIR="${OUT_DIR:-$ROOT_DIR/release-artifacts/testnet/artwork}"
PNG_SIZE="${PNG_SIZE:-4096}"
MINIMAL_PNG_SIZE="${MINIMAL_PNG_SIZE:-2048}"
POSTER_PNG_WIDTH="${POSTER_PNG_WIDTH:-5400}"
POSTER_PNG_HEIGHT="${POSTER_PNG_HEIGHT:-7200}"
PLAQUE_PNG_WIDTH="${PLAQUE_PNG_WIDTH:-3600}"
PLAQUE_PNG_HEIGHT="${PLAQUE_PNG_HEIGHT:-2400}"
CERTIFICATE_PNG_WIDTH="${CERTIFICATE_PNG_WIDTH:-3300}"
CERTIFICATE_PNG_HEIGHT="${CERTIFICATE_PNG_HEIGHT:-2550}"

ARGS=(
  --genesis "$GENESIS_FILE"
  --network-identifiers "$NETWORK_IDENTIFIERS_FILE"
  --out "$OUT_DIR"
  --png-size "$PNG_SIZE"
  --minimal-png-size "$MINIMAL_PNG_SIZE"
  --poster-png-width "$POSTER_PNG_WIDTH"
  --poster-png-height "$POSTER_PNG_HEIGHT"
  --plaque-png-width "$PLAQUE_PNG_WIDTH"
  --plaque-png-height "$PLAQUE_PNG_HEIGHT"
  --certificate-png-width "$CERTIFICATE_PNG_WIDTH"
  --certificate-png-height "$CERTIFICATE_PNG_HEIGHT"
)

DEFAULT_EXPLORER_ART_DIR="$ROOT_DIR/../explorer-app/public/genesis/artwork"
if [[ -d "$(dirname "$DEFAULT_EXPLORER_ART_DIR")" ]]; then
  ARGS+=(--copy-to "$DEFAULT_EXPLORER_ART_DIR")
fi

exec python3 "$ROOT_DIR/scripts/testnet/genesis_art.py" "${ARGS[@]}"
