#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
AGENT="${ROOT_DIR}/scripts/testnet/validator-vpn-agent.sh"
TMP_DIR="$(mktemp -d)"
BASH_BIN="${BASH:-/bin/bash}"
trap 'rm -rf "${TMP_DIR}"' EXIT

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

if output="$(
  VALIDATOR_VPN_TEST_UNAME=Darwin \
    VALIDATOR_VPN_TOOL_PATH="${TMP_DIR}/missing-tools" \
    VALIDATOR_VPN_DIR="${TMP_DIR}/vpn" \
    "${BASH_BIN}" "${AGENT}" preflight 2>&1
)"; then
  echo "preflight unexpectedly succeeded without WireGuard tools" >&2
  exit 1
fi
assert_contains "${output}" "wg_present=false" "preflight reports missing wg"
assert_contains "${output}" "brew install wireguard-tools" "macOS remediation is explicit"
assert_contains "${output}" "openssl_present=false" "preflight reports missing openssl"

BIN_DIR="${TMP_DIR}/bin"
mkdir -p "${BIN_DIR}"
cat > "${BIN_DIR}/wg" <<'WG'
#!/usr/bin/env bash
set -euo pipefail
case "${1:-}" in
  genkey) echo "test-private-key" ;;
  pubkey) cat >/dev/null; echo "test-public-key" ;;
  show) exit 1 ;;
  *) exit 0 ;;
esac
WG
cat > "${BIN_DIR}/wg-quick" <<'WGQUICK'
#!/usr/bin/env bash
exit 0
WGQUICK
cat > "${BIN_DIR}/openssl" <<'OPENSSL'
#!/usr/bin/env bash
exit 0
OPENSSL
cat > "${BIN_DIR}/ifconfig" <<'IFCONFIG'
#!/usr/bin/env bash
exit 0
IFCONFIG
cat > "${BIN_DIR}/route" <<'ROUTE'
#!/usr/bin/env bash
exit 0
ROUTE
chmod +x "${BIN_DIR}/wg" "${BIN_DIR}/wg-quick" "${BIN_DIR}/openssl" "${BIN_DIR}/ifconfig" "${BIN_DIR}/route"

output="$(
  VALIDATOR_VPN_TEST_UNAME=Darwin \
    VALIDATOR_VPN_TOOL_PATH="${BIN_DIR}:/usr/bin:/bin" \
    VALIDATOR_VPN_DIR="${TMP_DIR}/vpn" \
    "${BASH_BIN}" "${AGENT}" preflight
)"
assert_contains "${output}" "validator_vpn_agent_ok=true action=preflight" "preflight succeeds with required tools"
assert_contains "${output}" "vpn_dir=${TMP_DIR}/vpn" "preflight reports writable VPN directory"

output="$(
  VALIDATOR_VPN_TEST_UNAME=Darwin \
    VALIDATOR_VPN_TOOL_PATH="${BIN_DIR}:/usr/bin:/bin" \
    VALIDATOR_VPN_DIR="${TMP_DIR}/vpn" \
    "${BASH_BIN}" "${AGENT}" prepare
)"
assert_contains "${output}" "validator_vpn_agent_ok=true action=prepare" "prepare succeeds with stubbed WireGuard tools"
test -f "${TMP_DIR}/vpn/private.key"
test -f "${TMP_DIR}/vpn/public.key"

if output="$(
  VALIDATOR_VPN_TEST_UNAME=Linux \
    VALIDATOR_VPN_TOOL_PATH="${BIN_DIR}:/usr/bin:/bin" \
    VALIDATOR_VPN_DIR="${TMP_DIR}/vpn" \
    "${BASH_BIN}" "${AGENT}" apply-latest --vpn-ip 10.70.10.7/32 2>&1
)"; then
  echo "apply-latest unexpectedly succeeded without node id" >&2
  exit 1
fi
assert_contains "${output}" "--node-id is required" "packaged coordinator DNS default avoids missing URL failure"

if grep -q '/opt/homebrew/etc/wireguard\|/usr/local/etc/wireguard' "${AGENT}"; then
  echo "macOS WireGuard config path must stay under VALIDATOR_VPN_DIR, not Homebrew system directories" >&2
  exit 1
fi

echo "validator-vpn-agent preflight tests passed"
