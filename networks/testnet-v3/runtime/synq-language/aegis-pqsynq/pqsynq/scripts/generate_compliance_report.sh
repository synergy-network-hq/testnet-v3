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

SCRIPT_DIR_LOGICAL="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT_DIR_PHYSICAL="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
CRATE_DIR_LOGICAL="$(cd "${SCRIPT_DIR_LOGICAL}/.." && pwd)"
CRATE_DIR_PHYSICAL="$(cd "${SCRIPT_DIR_PHYSICAL}/.." && pwd -P)"
AEGIS_ROOT="$(cd "${CRATE_DIR_PHYSICAL}/../.." && pwd -P)"
NIST_ROOT="${AEGIS_ROOT}/5-nist-kat-vectors"
ARTIFACTS_DIR="${CRATE_DIR_LOGICAL}/artifacts"
REPORT_PATH="${ARTIFACTS_DIR}/pqsynq-compliance-report.md"

WORKSPACE_ROOT="$(find_synq_workspace_root "$PWD" || true)"
if [[ -z "${WORKSPACE_ROOT}" ]]; then
  WORKSPACE_ROOT="$(find_synq_workspace_root "${CRATE_DIR_LOGICAL}" || true)"
fi
if [[ -z "${WORKSPACE_ROOT}" ]]; then
  echo "Error: could not locate SynQ workspace root with member 'aegis-pqsynq/pqsynq'."
  echo "Run this script from / within the SynQ workspace."
  exit 1
fi

mkdir -p "${ARTIFACTS_DIR}"

compute_sha256() {
  local path="$1"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "${path}" | awk '{print $1}'
  else
    shasum -a 256 "${path}" | awk '{print $1}'
  fi
}

run_with_log() {
  local label="$1"
  shift

  local log_path="${ARTIFACTS_DIR}/${label}.log"
  if "$@" >"${log_path}" 2>&1; then
    echo "PASS"
  else
    echo "FAIL"
  fi
}

NIST_STATUS="$(
  run_with_log \
    "nist_vector_replay" \
    bash -lc "cd \"${WORKSPACE_ROOT}\" && cargo test -p aegis-pqsynq --all-features --locked --test nist_vector_replay_tests"
)"
PINNED_STATUS="$(
  run_with_log \
    "pinned_vector_manifest" \
    bash -lc "cd \"${WORKSPACE_ROOT}\" && cargo test -p aegis-pqsynq --all-features --locked --test vector_manifest_tests"
)"

MAX_VECTORS="${PQSYNQ_NIST_MAX_VECTORS:-10}"
GENERATED_AT="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
GIT_COMMIT="$(git -C "${AEGIS_ROOT}" rev-parse --short HEAD 2>/dev/null || echo "unknown")"

{
  echo "# Aegis-PQSynQ Compliance Report"
  echo
  echo "- Generated (UTC): ${GENERATED_AT}"
  echo "- Commit: ${GIT_COMMIT}"
  echo "- NIST replay vectors per algorithm: ${MAX_VECTORS}"
  echo
  echo "## Test Results"
  echo
  echo "| Check | Status | Log |"
  echo "|---|---|---|"
  echo "| Official NIST replay (nist_vector_replay_tests) | ${NIST_STATUS} | artifacts/nist_vector_replay.log |"
  echo "| Pinned fixture manifest integrity (vector_manifest_tests) | ${PINNED_STATUS} | artifacts/pinned_vector_manifest.log |"
  echo
  echo "## Official Source Files (SHA-256)"
  echo
  echo "| Algorithm | File | SHA-256 |"
  echo "|---|---|---|"
} >"${REPORT_PATH}"

mldsa_kat_response() {
  local level="$1"
  printf 'PQCsignKAT_%s%s.rsp' "Di" "lithium${level}"
}

declare -a SOURCE_ROWS=(
  "ML-KEM-512|NIST-ml-kem/reference/ml-kem-512/PQCkemKAT_1632.rsp"
  "ML-KEM-768|NIST-ml-kem/reference/ml-kem-768/PQCkemKAT_2400.rsp"
  "ML-KEM-1024|NIST-ml-kem/reference/ml-kem-1024/PQCkemKAT_3168.rsp"
  "ML-DSA-44|NIST-ml-dsa/reference/ml-dsa-44/$(mldsa_kat_response 2)"
  "ML-DSA-65|NIST-ml-dsa/reference/ml-dsa-65/$(mldsa_kat_response 3)"
  "ML-DSA-87|NIST-ml-dsa/reference/ml-dsa-87/$(mldsa_kat_response 5)"
  "FN-DSA-512|NIST-fn-dsa/reference/falcon512-KAT.rsp"
  "FN-DSA-1024|NIST-fn-dsa/reference/falcon1024-KAT.rsp"
  "HQC-KEM-128|NIST-hqc-kem/reference/hqc-kem-128/hqc-128_kat.rsp"
  "HQC-KEM-192|NIST-hqc-kem/reference/hqc-kem-192/hqc-192_kat.rsp"
  "HQC-KEM-256|NIST-hqc-kem/reference/hqc-kem-256/hqc-256_kat.rsp"
)

for row in "${SOURCE_ROWS[@]}"; do
  IFS='|' read -r algorithm relative_path <<<"${row}"
  absolute_path="${NIST_ROOT}/${relative_path}"
  if [[ -f "${absolute_path}" ]]; then
    sha_value="$(compute_sha256 "${absolute_path}")"
    echo "| ${algorithm} | ${relative_path} | ${sha_value} |" >>"${REPORT_PATH}"
  else
    echo "| ${algorithm} | ${relative_path} | MISSING |" >>"${REPORT_PATH}"
  fi
done

echo >>"${REPORT_PATH}"
echo "## Notes" >>"${REPORT_PATH}"
echo >>"${REPORT_PATH}"
echo "- Report generation exits non-zero if any mandatory replay check fails." >>"${REPORT_PATH}"
echo "- Full logs are available in \`${ARTIFACTS_DIR}\`." >>"${REPORT_PATH}"

cat "${REPORT_PATH}"

if [[ "${NIST_STATUS}" != "PASS" || "${PINNED_STATUS}" != "PASS" ]]; then
  exit 1
fi
