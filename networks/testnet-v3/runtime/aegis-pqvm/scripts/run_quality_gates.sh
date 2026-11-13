#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

echo "Aegis PQVM production quality gates"
echo "==================================="

echo "[1/17] cargo fmt --check"
cargo fmt --all -- --check

echo "[2/17] cargo check"
cargo check --all-targets --all-features --locked

echo "[3/17] cargo test"
cargo test --all-targets --all-features --locked

echo "[4/17] cargo clippy -D warnings"
cargo clippy --all-targets --all-features --locked -- -D warnings

echo "[5/17] cargo audit"
if ! command -v cargo-audit >/dev/null 2>&1; then
  cargo install cargo-audit --locked
fi
cargo audit

echo "[6/17] naming policy"
./scripts/check_naming_policy.sh

echo "[7/17] ignored KAT policy"
./scripts/check_no_ignored_kat.sh

echo "[8/17] absolute-path policy"
./scripts/check_no_absolute_paths.sh

echo "[9/17] effective PQC source marker policy"
./scripts/check_effective_pqc_source_markers.sh

echo "[10/17] deterministic KAT replay"
./scripts/run_deterministic_kat.sh

echo "[11/17] side-channel boundary review"
./scripts/run_side_channel_review.sh

echo "[12/17] fuzz + fault-injection campaign"
./scripts/run_fuzz_fault_campaign.sh

echo "[13/17] traceability matrix"
./scripts/check_traceability_matrix.sh

echo "[14/17] independent security sign-off"
./scripts/check_independent_security_signoff.sh

echo "[15/17] benchmark reproducibility report"
./scripts/run_benchmark_report.sh

echo "[16/17] release evidence generation"
./scripts/generate_release_manifest.sh
./scripts/generate_sbom.sh

echo "[17/17] customer bundle packaging"
./scripts/package_customer_bundle.sh

echo "All PQVM quality gates passed."
