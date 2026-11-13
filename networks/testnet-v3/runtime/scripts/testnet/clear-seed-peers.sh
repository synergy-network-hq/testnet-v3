#!/usr/bin/env bash
set -euo pipefail

TOKEN="${SEED_ADMIN_TOKEN:-${BOOTSTRAP_SEED_ADMIN_TOKEN:-}}"
SEEDS=(
  "${SEED1_URL:-http://seed1.synergy-network.io:5621/peers}"
  "${SEED2_URL:-http://seed2.synergy-network.io:5621/peers}"
  "${SEED3_URL:-http://seed3.synergy-network.io:5621/peers}"
)

if ! command -v curl >/dev/null 2>&1; then
  echo "curl is required." >&2
  exit 1
fi

if [[ -z "$TOKEN" ]]; then
  echo "SEED_ADMIN_TOKEN is not set." >&2
  echo "Remote clears will be rejected unless you run this on the seed host itself or through an SSH tunnel." >&2
fi

for url in "${SEEDS[@]}"; do
  echo "Clearing $url"
  if [[ -n "$TOKEN" ]]; then
    curl --fail --silent --show-error \
      -X DELETE \
      -H "X-Seed-Admin-Token: $TOKEN" \
      "$url"
  else
    curl --fail --silent --show-error \
      -X DELETE \
      "$url"
  fi
  printf '\n'
done
