#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
GATE="${ROOT_DIR}/scripts/release/validate-bundled-assets.sh"
TMP_DIR="$(mktemp -d "${ROOT_DIR}/scripts/testnet/.release-gate-qa.XXXXXX")"
PRODUCTION_SOURCE="${TMP_DIR}/injected-production.sh"
PRODUCTION_CONFIG="${TMP_DIR}/injected-production.yml"
RUST_PRODUCTION_SOURCE="${ROOT_DIR}/control-service/src/.release-gate-injected-production.rs"
RUST_TEST_FIXTURE="${ROOT_DIR}/control-service/src/.release-gate-injected-test.rs"
NEGATIVE_FIXTURE="${TMP_DIR}/fixtures/rejected-old-vpn.test.sh"
RETIREMENT_DOCUMENT="${TMP_DIR}/retirement-note.yml"
RETIRED_LITERAL="10.69.0.99"
trap 'rm -rf "${TMP_DIR}"; rm -f "${RUST_PRODUCTION_SOURCE}" "${RUST_TEST_FIXTURE}"' EXIT

assert_contains() {
  local haystack="$1"
  local needle="$2"
  local label="$3"
  if [[ "${haystack}" != *"${needle}"* ]]; then
    echo "assertion failed: ${label}" >&2
    echo "expected to find: ${needle}" >&2
    echo "actual output:" >&2
    echo "${haystack}" >&2
    exit 1
  fi
}

printf '# Deliberate production source injection\nVPN_ENDPOINT=%s\n' "${RETIRED_LITERAL}" >"${PRODUCTION_SOURCE}"
printf 'vpn_endpoint: %s\n' "${RETIRED_LITERAL}" >"${PRODUCTION_CONFIG}"
printf 'const RETIRED_PRODUCTION_ROUTE: &str = "%s";\n' "${RETIRED_LITERAL}" >"${RUST_PRODUCTION_SOURCE}"
chmod +x "${PRODUCTION_SOURCE}"

if output="$(
  SKIP_BUNDLED_ASSET_GIT_CLEAN_CHECK=1 \
    bash "${GATE}" 2>&1
)"; then
  echo "release gate unexpectedly accepted injected retired VPN literals" >&2
  exit 1
fi
assert_contains "${output}" "Retired 10.69.* literals found" "gate rejects retired literal"
assert_contains "${output}" "${PRODUCTION_SOURCE#"${ROOT_DIR}/"}" "gate reports production source"
assert_contains "${output}" "${PRODUCTION_CONFIG#"${ROOT_DIR}/"}" "gate reports production config"
assert_contains "${output}" "${RUST_PRODUCTION_SOURCE#"${ROOT_DIR}/"}" "gate reports Rust production source"

rm -f "${PRODUCTION_SOURCE}" "${PRODUCTION_CONFIG}" "${RUST_PRODUCTION_SOURCE}"
mkdir -p "$(dirname "${NEGATIVE_FIXTURE}")"
printf '# NEGATIVE-TEST-FIXTURE: rejection input contains %s\n' "${RETIRED_LITERAL}" >"${NEGATIVE_FIXTURE}"
printf '# RETIREMENT-DOCUMENTATION: Former %s mesh is retired.\n' "${RETIRED_LITERAL}" >"${RETIREMENT_DOCUMENT}"
cat >"${RUST_TEST_FIXTURE}" <<EOF
#[cfg(test)]
mod tests {
    const RETIRED_REJECTION_FIXTURE: &str = "${RETIRED_LITERAL}";
}
EOF
chmod +x "${NEGATIVE_FIXTURE}"

output="$(
  SKIP_BUNDLED_ASSET_GIT_CLEAN_CHECK=1 \
    bash "${GATE}" 2>&1
)"
assert_contains "${output}" "Bundled assets validated." "corrected tree passes with explicit exceptions"

echo "release retired VPN literal gate tests passed"
