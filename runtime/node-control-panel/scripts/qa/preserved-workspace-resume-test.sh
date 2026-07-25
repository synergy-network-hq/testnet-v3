#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

cd "$REPO_ROOT"

cargo fmt --manifest-path control-service/Cargo.toml --check

for test_name in \
  preserved_validator_workspace_reconstructs_missing_registry_entry \
  legacy_validator_evidence_is_migrated_without_removing_receipt \
  already_synced_normal_resume_accepts_safe_height_without_snapshot_receipt \
  valid_existing_innernet_receipt_is_reusable_for_resume
do
  cargo test --manifest-path control-service/Cargo.toml "$test_name" --lib -- --nocapture
done

echo "Preserved-workspace resume QA passed."
