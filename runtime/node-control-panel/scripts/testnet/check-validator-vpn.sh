#!/usr/bin/env bash
set -euo pipefail

VPN_IFACE="${VALIDATOR_VPN_IFACE:-sy-validator0}"
VPN_CIDR="${VALIDATOR_VPN_CIDR:-10.70.0.0/16}"
CONSENSUS_PORT="${VALIDATOR_VPN_CONSENSUS_PORT:-5622}"
SSH_TIMEOUT="${VALIDATOR_VPN_SSH_TIMEOUT:-8}"
BOOTSTRAP_ALIASES=(
  synergy-relayer1
  synergy-relayer2
  synergy-relayer3
  synergy-val1
  synergy-val2
  synergy-val3
  synergy-val4
  synergy-val5
  synergy-val6
)

usage() {
  cat <<USAGE
Usage:
  $0 --local
  $0 [--aliases alias1 alias2 ...]

Read-only validator VPN check. It does not print private keys, edit configs,
restart services, or apply WireGuard updates.
USAGE
}

fail() {
  echo "validator_vpn_check_ok=false reason=$*" >&2
  exit 1
}

warn() {
  echo "warning=$*" >&2
}

run_local_check() {
  local broad_cidr_route
  local default_route
  broad_cidr_route="${VPN_CIDR}"
  default_route="0.0.0.0""/0"

  if command -v ip >/dev/null 2>&1; then
    ip link show "${VPN_IFACE}" >/dev/null 2>&1 || fail "${VPN_IFACE} interface missing"
    ip -o addr show dev "${VPN_IFACE}" | grep -Eq '10\.70\.(10|20)\.' || fail "${VPN_IFACE} has no canonical 10.70 validator or relayer address"
  elif command -v ifconfig >/dev/null 2>&1; then
    ifconfig "${VPN_IFACE}" >/dev/null 2>&1 || fail "${VPN_IFACE} interface missing"
    ifconfig "${VPN_IFACE}" | grep -Eq '10\.70\.(10|20)\.' || fail "${VPN_IFACE} has no canonical 10.70 validator or relayer address"
  else
    warn "no ip or ifconfig command available"
  fi

  if command -v wg >/dev/null 2>&1; then
    local allowed
    allowed="$(wg show "${VPN_IFACE}" allowed-ips 2>/dev/null || true)"
    [[ -n "${allowed}" ]] || fail "wg has no allowed-ip data for ${VPN_IFACE}"
    grep -Fq "${broad_cidr_route}" <<<"${allowed}" && fail "broad validator VPN route is configured"
    grep -Fq "${default_route}" <<<"${allowed}" && fail "full-tunnel route is configured"
    echo "${allowed}" | awk '{print $2}' | grep -Eq '/32$' || fail "no exact /32 peer routes found"
    if command -v ip >/dev/null 2>&1; then
      while IFS= read -r peer_route; do
        [[ -n "${peer_route}" ]] || continue
        peer_host="${peer_route%%/*}"
        route_iface="$(ip route get "${peer_host}" 2>/dev/null | awk '{for (i=1; i<=NF; i++) if ($i == "dev") {print $(i+1); exit}}')"
        [[ "${route_iface}" == "${VPN_IFACE}" ]] || fail "route for ${peer_route} uses ${route_iface:-unknown}, expected ${VPN_IFACE}"
      done < <(echo "${allowed}" | awk '{print $2}' | grep -E '^10\.70\.(10|20)\.[0-9]+/32$')
    fi
    wg show "${VPN_IFACE}" latest-handshakes >/dev/null 2>&1 || fail "wg latest-handshakes failed"
  else
    fail "wireguard wg command missing"
  fi

  if command -v ss >/dev/null 2>&1; then
    ss -lnt 2>/dev/null | grep -q ":${CONSENSUS_PORT} " || warn "consensus port ${CONSENSUS_PORT} is not listening"
  fi

  echo "validator_vpn_check_ok=true host=$(hostname -s 2>/dev/null || hostname) iface=${VPN_IFACE}"
}

run_alias_check() {
  local aliases=("$@")
  local alias_name
  local failures=0
  for alias_name in "${aliases[@]}"; do
    echo "checking_alias=${alias_name}"
    if ! ssh \
      -o BatchMode=yes \
      -o ConnectTimeout="${SSH_TIMEOUT}" \
      -o ServerAliveInterval=5 \
      -o ServerAliveCountMax=1 \
      "${alias_name}" 'bash -s -- --local' < "$0"; then
      failures=$((failures + 1))
      warn "validator VPN check failed for ${alias_name}"
    fi
  done

  if [[ "${failures}" -gt 0 ]]; then
    fail "${failures} alias check(s) failed"
  fi
  echo "validator_vpn_alias_check_ok=true checked=${#aliases[@]}"
}

main() {
  if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
    usage
    exit 0
  fi
  if [[ "${1:-}" == "--local" ]]; then
    run_local_check
    exit 0
  fi
  if [[ "${1:-}" == "--aliases" ]]; then
    shift
    [[ "$#" -gt 0 ]] || fail "--aliases requires at least one alias"
    run_alias_check "$@"
    exit 0
  fi
  run_alias_check "${BOOTSTRAP_ALIASES[@]}"
}

main "$@"
