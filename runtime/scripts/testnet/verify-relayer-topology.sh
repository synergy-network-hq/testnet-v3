#!/usr/bin/env bash
set -euo pipefail

RPC_PAYLOAD='{"jsonrpc":"2.0","id":1,"method":"synergy_getPeerInfo","params":[]}'
SSH_OPTS=(
  -o StrictHostKeyChecking=no
  -o ConnectTimeout="${SYNERGY_TOPOLOGY_CONNECT_TIMEOUT_SECS:-8}"
)

if [[ "${SYNERGY_TOPOLOGY_BATCH_MODE:-0}" == "1" ]]; then
  SSH_OPTS+=(-o BatchMode=yes)
fi

json_rpc() {
  local port="$1"
  curl -fsS --max-time "${SYNERGY_TOPOLOGY_RPC_TIMEOUT_SECS:-5}" \
    -H 'content-type: application/json' \
    -d "${RPC_PAYLOAD}" \
    "http://127.0.0.1:${port}"
}

ssh_json_rpc() {
  local label="$1"
  local ssh_port="$2"
  local user_host="$3"
  local rpc_port="$4"
  local ssh_cmd=(ssh "${SSH_OPTS[@]}")
  if [[ -n "${ssh_port}" ]]; then
    ssh_cmd+=(-p "${ssh_port}")
  fi
  ssh_cmd+=("${user_host}")

  local payload
  payload="$("${ssh_cmd[@]}" "bash -lc '$(declare -f json_rpc); json_rpc ${rpc_port}'")"
  printf '%s\t%s\n' "${label}" "${payload}"
}

is_allowed_validator_peer() {
  local address="$1"
  case "${address}" in
    10.69.0.1:*|10.69.0.2:*|10.69.0.3:*|10.69.0.4:*|10.69.0.5:*|10.69.0.20:*|10.69.0.202:*|10.69.0.250:*)
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

check_validator_peer_table() {
  local label="$1"
  local payload="$2"
  python3 - "${label}" "${payload}" <<'PY'
import json
import sys

label = sys.argv[1]
payload = json.loads(sys.argv[2])
result = payload.get("result") or {}
peers = result.get("peers") or []
bad = []
for peer in peers:
    address = str(peer.get("address") or "")
    if not (
        address.startswith("10.69.0.1:")
        or address.startswith("10.69.0.2:")
        or address.startswith("10.69.0.3:")
        or address.startswith("10.69.0.4:")
        or address.startswith("10.69.0.5:")
        or address.startswith("10.69.0.20:")
        or address.startswith("10.69.0.202:")
        or address.startswith("10.69.0.250:")
    ):
        bad.append(address)

print(json.dumps({
    "node": label,
    "peer_count": result.get("peer_count"),
    "unexpected_validator_peers": sorted(bad),
}, sort_keys=True))
if bad:
    sys.exit(2)
PY
}

check_relayer_peer_table() {
  local label="$1"
  local payload="$2"
  python3 - "${label}" "${payload}" <<'PY'
import json
import sys

label = sys.argv[1]
payload = json.loads(sys.argv[2])
result = payload.get("result") or {}
peers = result.get("peers") or []
validator_private = [p.get("address") for p in peers if str(p.get("address") or "").startswith("10.69.0.")]
public_support = [p.get("node_id") for p in peers if str(p.get("address") or "").startswith("74.208.227.23:")]

print(json.dumps({
    "node": label,
    "peer_count": result.get("peer_count"),
    "private_plane_peers": sorted(validator_private),
    "public_support_node_ids": sorted([p for p in public_support if p]),
}, sort_keys=True))
if len(validator_private) < 5:
    sys.exit(2)
PY
}

main() {
  local failures=0
  local line label payload

  for line in \
    "$(ssh_json_rpc Validator1 '' justin@62.146.182.207 5640)" \
    "$(ssh_json_rpc Validator2 '' rob@62.146.182.208 5640)" \
    "$(ssh_json_rpc Validator3 '' rob@62.146.182.209 5640)" \
    "$(ssh_json_rpc Validator4 5619 node@73.79.66.255 5640)" \
    "$(ssh_json_rpc Validator5 '' justin@194.163.183.166 5640)"
  do
    label="${line%%$'\t'*}"
    payload="${line#*$'\t'}"
    if ! check_validator_peer_table "${label}" "${payload}"; then
      failures=$((failures + 1))
    fi
  done

  for line in \
    "$(ssh_json_rpc Relayer1 '' root@195.26.241.95 5640)" \
    "$(ssh_json_rpc Relayer2 '' root@94.72.117.108 5640)"
  do
    label="${line%%$'\t'*}"
    payload="${line#*$'\t'}"
    if ! check_relayer_peer_table "${label}" "${payload}"; then
      failures=$((failures + 1))
    fi
  done

  if (( failures > 0 )); then
    echo "Topology verification failed with ${failures} peer-table issue(s)." >&2
    return 2
  fi

  echo "Topology verification passed."
}

main "$@"
