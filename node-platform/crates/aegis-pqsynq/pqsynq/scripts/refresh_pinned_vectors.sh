#!/usr/bin/env bash

set -euo pipefail

find_synq_workspace_root() {
  local dir="$1"
  while [[ "$dir" != "/" ]]; do
    if [[ -f "$dir/Cargo.toml" ]] && grep -q '"aegis-pqsynq/pqsynq"' "$dir/Cargo.toml"; then
      echo "$dir"
      return 0
    fi
    dir="$(dirname "$dir")"
  done
  return 1
}

WORKSPACE_ROOT="$(find_synq_workspace_root "$PWD" || true)"
if [[ -z "$WORKSPACE_ROOT" ]]; then
  echo "Error: could not find SynQ workspace root with member 'aegis-pqsynq/pqsynq'." >&2
  exit 1
fi

cd "$WORKSPACE_ROOT"

VECTORS_DIR="$WORKSPACE_ROOT/aegis-pqsynq/pqsynq/tests/vectors"
VECTORS_FILE="$VECTORS_DIR/pinned_vectors.json"
MANIFEST_FILE="$VECTORS_DIR/manifest.json"

mkdir -p "$VECTORS_DIR"

echo "Generating pinned vectors..."
cargo run -p aegis-pqsynq --example generate_pinned_vectors --features full > "$VECTORS_FILE"

SHA256="$(shasum -a 256 "$VECTORS_FILE" | awk '{print $1}')"
GENERATED_AT="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"

cat > "$MANIFEST_FILE" <<JSON
{
  "schema_version": 1,
  "vectors_file": "pinned_vectors.json",
  "sha256": "$SHA256",
  "source": "Generated locally from current crate implementation; deterministic replay fixtures for regression guarding.",
  "generated_by": "cargo run -p aegis-pqsynq --example generate_pinned_vectors --features full",
  "generated_at_utc": "$GENERATED_AT",
  "profile": "synq-pq-full"
}
JSON

echo "Pinned vectors refreshed."
echo "- vectors:  $VECTORS_FILE"
echo "- manifest: $MANIFEST_FILE"
echo "- sha256:   $SHA256"
