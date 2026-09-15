#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${ROOT_DIR}"

manifest_list="$(mktemp)"
trap 'rm -f "${manifest_list}"' EXIT

find . \
  -path './.git' -prune -o \
  -path './target' -prune -o \
  -path './archive-validator/dist' -prune -o \
  -path './node-control-panel/*/target' -prune -o \
  -name Cargo.toml -type f -print | sort > "${manifest_list}"

if xargs rg -n 'path\s*=\s*"(/Volumes/|/Users/|/mnt/|/home/)' < "${manifest_list}"; then
  echo "release_manifest_guard=FAIL absolute local Cargo dependency path found" >&2
  exit 1
fi

rg -n '^\[patch\.[^]]+\]' Cargo.toml src/Cargo.toml aegis-pqvm/Cargo.toml || true

cargo metadata --locked --format-version 1 --no-deps >/dev/null

echo "release_manifest_guard=PASS"
