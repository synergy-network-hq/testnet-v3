#!/usr/bin/env bash
set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
OUTPUT_PATH=""
TIMEOUT_SECONDS=3
SKIP_DNS=0
SKIP_TCP=0
SKIP_CONFIG=0
EXPLORER_PORT=""

usage() {
  cat <<'EOF'
Usage: verify-public-p2p-topology.sh [options]

Verifies the Synergy testnet public P2P topology without creating local report
files unless --output is explicitly provided.

Options:
  --output PATH          Write report to PATH. Defaults to stdout.
  --repo-root PATH       Repository root. Defaults to this script's repo.
  --timeout SECONDS      TCP/DNS timeout in seconds. Default: 3.
  --explorer-port PORT   Also TCP-check explorer indexer 74.208.227.23:PORT.
  --skip-dns             Skip stable DNS origin checks.
  --skip-tcp             Skip public TCP checks.
  --skip-config          Skip local active-config hygiene checks.
  -h, --help             Show this help.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --output)
      OUTPUT_PATH="${2:-}"
      shift 2
      ;;
    --repo-root)
      REPO_ROOT="${2:-}"
      shift 2
      ;;
    --timeout)
      TIMEOUT_SECONDS="${2:-}"
      shift 2
      ;;
    --explorer-port)
      EXPLORER_PORT="${2:-}"
      shift 2
      ;;
    --skip-dns)
      SKIP_DNS=1
      shift
      ;;
    --skip-tcp)
      SKIP_TCP=1
      shift
      ;;
    --skip-config)
      SKIP_CONFIG=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if [[ -n "${OUTPUT_PATH}" ]]; then
  if ! exec >"${OUTPUT_PATH}"; then
    echo "failed to open output path: ${OUTPUT_PATH}" >&2
    exit 2
  fi
fi

STATUS=0
PASS_COUNT=0
FAIL_COUNT=0
WARN_COUNT=0

pass() {
  PASS_COUNT=$((PASS_COUNT + 1))
  printf 'PASS %s\n' "$*"
}

fail() {
  FAIL_COUNT=$((FAIL_COUNT + 1))
  STATUS=1
  printf 'FAIL %s\n' "$*"
}

warn() {
  WARN_COUNT=$((WARN_COUNT + 1))
  printf 'WARN %s\n' "$*"
}

is_cloudflare_ip() {
  python3 - "$1" <<'PY'
import ipaddress
import sys

candidate = ipaddress.ip_address(sys.argv[1])
cloudflare = [
    "103.21.244.0/22",
    "103.22.200.0/22",
    "103.31.4.0/22",
    "104.16.0.0/13",
    "108.162.192.0/18",
    "131.0.72.0/22",
    "141.101.64.0/18",
    "162.158.0.0/15",
    "172.64.0.0/13",
    "173.245.48.0/20",
    "188.114.96.0/20",
    "190.93.240.0/20",
    "197.234.240.0/22",
    "198.41.128.0/17",
    "2400:cb00::/32",
    "2606:4700::/32",
    "2803:f800::/32",
    "2405:b500::/32",
    "2405:8100::/32",
    "2a06:98c0::/29",
    "2c0f:f248::/32",
]
if any(candidate in ipaddress.ip_network(network) for network in cloudflare):
    sys.exit(0)
sys.exit(1)
PY
}

resolve_records() {
  local rrtype="$1"
  local host="$2"

  if command -v dig >/dev/null 2>&1; then
    dig +time="${TIMEOUT_SECONDS}" +tries=1 +short "${rrtype}" "${host}" | sed '/^$/d'
  else
    python3 - "$rrtype" "$host" <<'PY'
import socket
import sys

rrtype, host = sys.argv[1], sys.argv[2]
family = socket.AF_INET if rrtype == "A" else socket.AF_INET6
seen = set()
try:
    for item in socket.getaddrinfo(host, None, family, socket.SOCK_STREAM):
        addr = item[4][0]
        if addr not in seen:
            seen.add(addr)
            print(addr)
except OSError:
    pass
PY
  fi
}

tcp_probe() {
  local host="$1"
  local port="$2"
  python3 - "$host" "$port" "$TIMEOUT_SECONDS" <<'PY'
import socket
import sys

host, port, timeout = sys.argv[1], int(sys.argv[2]), float(sys.argv[3])
try:
    with socket.create_connection((host, port), timeout=timeout):
        pass
except OSError as exc:
    print(str(exc))
    sys.exit(1)
sys.exit(0)
PY
}

check_dns() {
  local name="$1"
  local host="$2"
  local expected="$3"
  local a_records
  local aaaa_records
  local matched=0
  local unexpected=0

  mapfile -t a_records < <(resolve_records A "${host}")
  mapfile -t aaaa_records < <(resolve_records AAAA "${host}")

  if [[ "${#a_records[@]}" -eq 0 ]]; then
    fail "dns ${name} ${host} has no A record; expected ${expected}"
    return
  fi

  for ip in "${a_records[@]}"; do
    if [[ "${ip}" == "${expected}" ]]; then
      matched=1
    else
      unexpected=1
      if is_cloudflare_ip "${ip}"; then
        fail "dns ${name} ${host} resolves to Cloudflare proxy ${ip}; expected origin ${expected}"
      else
        fail "dns ${name} ${host} resolves to unexpected A ${ip}; expected ${expected}"
      fi
    fi
  done

  if [[ "${matched}" -eq 1 && "${unexpected}" -eq 0 ]]; then
    pass "dns ${name} ${host} resolves to origin ${expected}"
  elif [[ "${matched}" -eq 0 ]]; then
    fail "dns ${name} ${host} did not return expected origin ${expected}"
  fi

  for ip in "${aaaa_records[@]}"; do
    if is_cloudflare_ip "${ip}"; then
      fail "dns ${name} ${host} has Cloudflare AAAA ${ip}; P2P records must be DNS-only origins"
    else
      warn "dns ${name} ${host} has AAAA ${ip}; no IPv6 origin was specified in topology"
    fi
  done
}

check_tcp() {
  local name="$1"
  local host="$2"
  local port="$3"
  local err

  if err="$(tcp_probe "${host}" "${port}" 2>&1)"; then
    pass "tcp ${name} ${host}:${port} reachable"
  else
    fail "tcp ${name} ${host}:${port} unreachable: ${err}"
  fi
}

check_config_hygiene() {
  local roots=(
    "${REPO_ROOT}/config"
    "${REPO_ROOT}/archive-validator/config"
    "${REPO_ROOT}/bootstrap-bundles"
    "${REPO_ROOT}/node-control-panel/testnet/runtime/configs"
  )
  local found=0
  local file
  local bad
  local public_p2p_key_re='^[[:space:]]*"?((public_)?p2p_)?(public_address|public_endpoint|public_p2p_address|discovery_public_address|additional_dial_targets|persistent_peers|bootnodes|seed_servers|bootstrap_dns_records|p2p_peers|peers|rpc_gateway_p2p_endpoint|archive_public_endpoint)"?[[:space:]]*[:=]'
  local forbidden_endpoint_re='10\.69\.|10\.[0-9]+\.[0-9]+\.[0-9]+:5622|127\.0\.0\.1:5622|localhost:5622|192\.168\.[0-9]+\.[0-9]+:5622|172\.(1[6-9]|2[0-9]|3[01])\.[0-9]+\.[0-9]+:5622'

  for root in "${roots[@]}"; do
    [[ -d "${root}" ]] || continue
    while IFS= read -r file; do
      found=1

      if bad="$(grep -nE "${public_p2p_key_re}" "${file}" 2>/dev/null | grep -E "${forbidden_endpoint_re}" || true)"; [[ -n "${bad}" ]]; then
        fail "config hygiene ${file} contains private/VPN/localhost public P2P endpoint"
        printf '%s\n' "${bad}"
      fi

      case "${file}" in
        *archive*toml|*archive*json)
          if bad="$(grep -nE '(public|advertis|external).*73\.79\.66\.255:5622|73\.79\.66\.255:5622.*(public|advertis|external)' "${file}" 2>/dev/null || true)"; [[ -n "${bad}" ]]; then
            fail "archive hygiene ${file} advertises validator P2P endpoint 73.79.66.255:5622"
            printf '%s\n' "${bad}"
          fi
          ;;
      esac
    done < <(find "${root}" -type f \( -name '*.toml' -o -name '*.json' -o -name '*.env' \) -print)
  done

  if [[ "${found}" -eq 0 ]]; then
    warn "config hygiene found no active config files under expected roots"
  elif [[ "${STATUS}" -eq 0 ]]; then
    pass "config hygiene found no private/VPN public P2P endpoints in expected active config roots"
  fi
}

cat <<EOF
Synergy public P2P topology verification
repo_root=${REPO_ROOT}
timeout_seconds=${TIMEOUT_SECONDS}
output=${OUTPUT_PATH:-stdout}
EOF

if [[ "${SKIP_CONFIG}" -eq 0 ]]; then
  echo
  echo "== Config hygiene =="
  check_config_hygiene
fi

if [[ "${SKIP_DNS}" -eq 0 ]]; then
  echo
  echo "== Stable DNS origin checks =="
  DNS_TARGETS=(
    "bootnode1|bootnode1.synergynode.xyz|170.64.187.206"
    "bootnode2|bootnode2.synergynode.xyz|146.190.210.121"
    "bootnode3|bootnode3.synergynode.xyz|157.245.226.240"
    "seed1|seed1.synergynode.xyz|170.64.187.206"
    "seed2|seed2.synergynode.xyz|146.190.210.121"
    "seed3|seed3.synergynode.xyz|157.245.226.240"
    "relay1|relay1.synergynode.xyz|195.26.241.95"
    "relay2|relay2.synergynode.xyz|94.72.117.108"
    "rpc-gateway-p2p|rpc.synergynode.xyz|167.86.83.83"
    "archive|archive.synergynode.xyz|73.79.66.255"
  )
  for target in "${DNS_TARGETS[@]}"; do
    IFS='|' read -r name host expected <<<"${target}"
    check_dns "${name}" "${host}" "${expected}"
  done
fi

if [[ "${SKIP_TCP}" -eq 0 ]]; then
  echo
  echo "== External TCP checks =="
  TCP_TARGETS=(
    "bootnode1|bootnode1.synergynode.xyz|5620"
    "bootnode2|bootnode2.synergynode.xyz|5620"
    "bootnode3|bootnode3.synergynode.xyz|5620"
    "seed1|seed1.synergynode.xyz|5621"
    "seed2|seed2.synergynode.xyz|5621"
    "seed3|seed3.synergynode.xyz|5621"
    "relay1|relay1.synergynode.xyz|5622"
    "relay2|relay2.synergynode.xyz|5622"
    "rpc-gateway-p2p|rpc.synergynode.xyz|5623"
    "archive|archive.synergynode.xyz|5615"
    "observer|209.145.50.9|5622"
  )
  if [[ -n "${EXPLORER_PORT}" ]]; then
    TCP_TARGETS+=("explorer-indexer|74.208.227.23|${EXPLORER_PORT}")
  else
    warn "explorer-indexer TCP check skipped; pass --explorer-port when a public P2P or health port is defined"
  fi
  for target in "${TCP_TARGETS[@]}"; do
    IFS='|' read -r name host port <<<"${target}"
    check_tcp "${name}" "${host}" "${port}"
  done
fi

echo
printf 'Summary: pass=%s fail=%s warn=%s\n' "${PASS_COUNT}" "${FAIL_COUNT}" "${WARN_COUNT}"
exit "${STATUS}"
