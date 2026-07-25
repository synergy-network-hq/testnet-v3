#!/usr/bin/env bash
set -euo pipefail

platform_name() {
  echo "${VALIDATOR_VPN_TEST_UNAME:-$(uname -s)}"
}

is_darwin() {
  [[ "$(platform_name)" == "Darwin" ]]
}

is_linux() {
  [[ "$(platform_name)" == "Linux" ]]
}

DEFAULT_VALIDATOR_VPN_IFACE="sy-validator0"
if is_darwin; then
  DEFAULT_VALIDATOR_VPN_IFACE="syvalidator0"
fi
VPN_IFACE="${VALIDATOR_VPN_IFACE:-${DEFAULT_VALIDATOR_VPN_IFACE}}"
VPN_DIR="${VALIDATOR_VPN_DIR:-/etc/synergy/validator-vpn}"
PRIVATE_KEY_PATH="${VALIDATOR_VPN_PRIVATE_KEY:-${VPN_DIR}/private.key}"
PUBLIC_KEY_PATH="${VALIDATOR_VPN_PUBLIC_KEY:-${VPN_DIR}/public.key}"
STATE_PATH="${VALIDATOR_VPN_STATE_PATH:-${VPN_DIR}/agent-state.json}"
SNAPSHOT_PATH="${VALIDATOR_VPN_SNAPSHOT_PATH:-${VPN_DIR}/latest-snapshot.json}"
RESULT_OWNER_UID="${VALIDATOR_VPN_RESULT_OWNER_UID:-}"
RESULT_OWNER_GID="${VALIDATOR_VPN_RESULT_OWNER_GID:-}"
LISTEN_PORT="${VALIDATOR_VPN_LISTEN_PORT:-51820}"
MTU="${VALIDATOR_VPN_MTU:-1380}"
NETWORK_ID="${VALIDATOR_VPN_NETWORK:-synergy-validator-vpn-testnet}"
CIDR="${VALIDATOR_VPN_CIDR:-10.70.0.0/16}"
COORDINATOR_URL="${VALIDATOR_VPN_COORDINATOR_URL:-${SYNERGY_VALIDATOR_VPN_COORDINATOR_URL:-https://vpn-coordinator.synergy-network.io}}"
if [[ -n "${VALIDATOR_VPN_TOOL_PATH:-}" ]]; then
  export PATH="${VALIDATOR_VPN_TOOL_PATH}"
else
  export PATH="/opt/homebrew/bin:/usr/local/bin:/usr/sbin:/sbin:/usr/bin:/bin:${PATH:-}"
fi

case "${SYNERGY_INNERNET_MIGRATION_READY:-false}" in
  1|true|TRUE|yes|YES)
    echo "validator_vpn_agent_ok=false reason=static_validator_vpn_retired_use_innernet" >&2
    exit 1
    ;;
esac

usage() {
  cat <<USAGE
Usage:
  $0 status
  $0 preflight
  $0 prepare
  $0 render --snapshot PATH --node-id NODE_ID
  $0 apply --snapshot PATH --node-id NODE_ID --vpn-ip CIDR
  $0 apply-latest [--coordinator-url URL] --node-id NODE_ID --vpn-ip CIDR
  $0 poll [--coordinator-url URL] --node-id NODE_ID --vpn-ip CIDR

Validator VPN agent helper. It never prints private keys and never overwrites
existing WireGuard keys unless key rotation is implemented separately.
USAGE
}

fail() {
  echo "validator_vpn_agent_ok=false reason=$*" >&2
  exit 1
}

need_root() {
  [[ "$(id -u)" == "0" ]] || fail "must run as root"
}

need_wg() {
  command -v wg >/dev/null 2>&1 || fail "$(wireguard_install_hint wg)"
}

need_wg_quick() {
  command -v wg-quick >/dev/null 2>&1 || fail "$(wireguard_install_hint wg-quick)"
}

need_openssl() {
  command -v openssl >/dev/null 2>&1 || fail "openssl is missing; install OpenSSL before applying signed validator VPN snapshots"
}

need_ip() {
  command -v ip >/dev/null 2>&1 || fail "Linux WireGuard apply requires the ip command from iproute2; install iproute2 and wireguard-tools before retrying"
}

wireguard_install_hint() {
  local missing="$1"
  if is_darwin; then
    echo "WireGuard tool '${missing}' is missing. Install WireGuard CLI tools with: brew install wireguard-tools"
  elif is_linux; then
    echo "WireGuard tool '${missing}' is missing. Install WireGuard tools with your package manager, for example: sudo apt-get install wireguard-tools iproute2"
  else
    echo "WireGuard tool '${missing}' is missing. Install WireGuard tools for this platform before retrying"
  fi
}

need_python() {
  command -v python3 >/dev/null 2>&1 || fail "python3 is missing"
}

shell_quote() {
  printf "'%s'" "$(printf '%s' "$1" | sed "s/'/'\\\\''/g")"
}

restore_result_file_permissions() {
  local path="$1"
  local mode="${2:-0644}"
  [[ -n "${path}" && -e "${path}" ]] || return 0
  if [[ "$(id -u)" == "0" && -n "${RESULT_OWNER_UID}" && -n "${RESULT_OWNER_GID}" ]]; then
    chown "${RESULT_OWNER_UID}:${RESULT_OWNER_GID}" "${path}" 2>/dev/null || true
  fi
  chmod "${mode}" "${path}" 2>/dev/null || true
}

rerun_with_macos_admin_if_needed() {
  is_darwin || return 1
  [[ "${VALIDATOR_VPN_ALLOW_ADMIN_PROMPT:-}" == "1" ]] || return 1
  [[ "${VALIDATOR_VPN_ADMIN_PROMPTED:-}" != "1" ]] || return 1
  [[ "$(id -u)" != "0" ]] || return 1
  command -v osascript >/dev/null 2>&1 || return 1

  local script_path command_text arg
  script_path="$(cd "$(dirname "$0")" && pwd)/$(basename "$0")"
  command_text="env"
  for arg in \
    "PATH=${PATH}" \
    "VALIDATOR_VPN_ADMIN_PROMPTED=1" \
    "VALIDATOR_VPN_DIR=${VPN_DIR}" \
    "VALIDATOR_VPN_PRIVATE_KEY=${PRIVATE_KEY_PATH}" \
    "VALIDATOR_VPN_PUBLIC_KEY=${PUBLIC_KEY_PATH}" \
    "VALIDATOR_VPN_STATE_PATH=${STATE_PATH}" \
    "VALIDATOR_VPN_SNAPSHOT_PATH=${SNAPSHOT_PATH}" \
    "VALIDATOR_VPN_RESULT_OWNER_UID=${RESULT_OWNER_UID}" \
    "VALIDATOR_VPN_RESULT_OWNER_GID=${RESULT_OWNER_GID}" \
    "VALIDATOR_VPN_IFACE=${VPN_IFACE}" \
    "VALIDATOR_VPN_LISTEN_PORT=${LISTEN_PORT}" \
    "VALIDATOR_VPN_MTU=${MTU}" \
    "VALIDATOR_VPN_NETWORK=${NETWORK_ID}" \
    "VALIDATOR_VPN_CIDR=${CIDR}" \
    "VALIDATOR_VPN_COORDINATOR_URL=${COORDINATOR_URL}" \
    "VALIDATOR_VPN_COORDINATOR_PUBLIC_KEY=${VALIDATOR_VPN_COORDINATOR_PUBLIC_KEY:-}" \
    "VALIDATOR_VPN_COORDINATOR_SIGNING_KEY=${VALIDATOR_VPN_COORDINATOR_SIGNING_KEY:-}"
  do
    command_text+=" $(shell_quote "$arg")"
  done
  command_text+=" bash $(shell_quote "$script_path")"
  for arg in "$@"; do
    command_text+=" $(shell_quote "$arg")"
  done

  osascript - "$command_text" <<'OSA'
on run argv
  do shell script item 1 of argv with administrator privileges
end run
OSA
}

json_get_generation() {
  local json_path="$1"
  need_python
  python3 - "$json_path" <<'PY'
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as handle:
    payload = json.load(handle)
print(int(payload.get("generation") or 0))
PY
}

current_applied_generation() {
  if [[ ! -f "${STATE_PATH}" ]]; then
    echo 0
    return
  fi
  need_python
  python3 - "${STATE_PATH}" <<'PY'
import json
import sys

try:
    with open(sys.argv[1], "r", encoding="utf-8") as handle:
        payload = json.load(handle)
    print(int(payload.get("applied_generation") or 0))
except Exception:
    print(0)
PY
}

verified_peer_handshake_count() {
  need_wg
  local count
  count="$(wg show "${VPN_IFACE}" latest-handshakes 2>/dev/null \
    | awk '$2 ~ /^[0-9]+$/ && $2 > 0 { count += 1 } END { print count + 0 }')" \
    || fail "cannot inspect WireGuard peer handshakes on ${VPN_IFACE}"
  [[ "${count}" =~ ^[0-9]+$ ]] || fail "WireGuard returned an invalid peer handshake count"
  printf '%s\n' "${count}"
}

write_agent_state() {
  local generation="$1"
  local node_id="$2"
  local vpn_ip="$3"
  need_python
  install -d -m 0755 "$(dirname "${STATE_PATH}")"
  python3 - "${STATE_PATH}" "${generation}" "${node_id}" "${vpn_ip}" "${VPN_IFACE}" <<'PY'
import json
import os
import sys
from datetime import datetime, timezone

path, generation, node_id, vpn_ip, iface = sys.argv[1:6]
payload = {
    "applied_generation": int(generation),
    "node_id": node_id,
    "vpn_ip": vpn_ip,
    "interface": iface,
    "applied_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
}
tmp = f"{path}.tmp.{os.getpid()}"
with open(tmp, "w", encoding="utf-8") as handle:
    json.dump(payload, handle, indent=2, sort_keys=True)
    handle.write("\n")
os.replace(tmp, path)
PY
  chmod 0644 "${STATE_PATH}"
  restore_result_file_permissions "${STATE_PATH}" 0644
}

ack_config_generation() {
  local coordinator_url="$1"
  local node_id="$2"
  local generation="$3"
  local peers_handshaked="$4"
  local auth_token="${VALIDATOR_VPN_COORDINATOR_TOKEN:-${SYNERGY_VALIDATOR_VPN_COORDINATOR_TOKEN:-}}"
  [[ -n "${auth_token}" ]] \
    || fail "VALIDATOR_VPN_COORDINATOR_TOKEN is required to acknowledge config propagation"
  need_python
  python3 - "${coordinator_url}" "${node_id}" "${generation}" "${peers_handshaked}" "${auth_token}" <<'PY'
import json
import sys
import urllib.error
import urllib.request

base_url, node_id, generation, peers_handshaked, token = sys.argv[1:6]
payload = json.dumps({
    "generation": int(generation),
    "applied": True,
    "interface_up": True,
    "peers_handshaked": int(peers_handshaked),
}).encode("utf-8")
request = urllib.request.Request(
    base_url.rstrip("/") + f"/api/validator-vpn/nodes/{node_id}/config-ack",
    data=payload,
    method="POST",
    headers={
        "Accept": "application/json",
        "Content-Type": "application/json",
        "Authorization": f"Bearer {token}",
    },
)
try:
    with urllib.request.urlopen(request, timeout=10) as response:
        if response.status != 200:
            raise SystemExit(f"config acknowledgement failed: HTTP {response.status}")
        result = json.loads(response.read().decode("utf-8"))
        print(
            "validator_vpn_agent_config_ack="
            + json.dumps(result, separators=(",", ":"))[:800]
        )
except urllib.error.HTTPError as exc:
    detail = exc.read().decode("utf-8", errors="replace")
    raise SystemExit(f"config acknowledgement failed: HTTP {exc.code}: {detail[:400]}")
except urllib.error.URLError as exc:
    raise SystemExit(f"config acknowledgement failed: {exc.reason}")
PY
}

verify_coordinator_propagation() {
  local coordinator_url="$1"
  local generation="$2"
  local auth_token="${VALIDATOR_VPN_COORDINATOR_TOKEN:-${SYNERGY_VALIDATOR_VPN_COORDINATOR_TOKEN:-}}"
  [[ -n "${auth_token}" ]] \
    || fail "VALIDATOR_VPN_COORDINATOR_TOKEN is required to verify config propagation"
  need_python
  python3 - "${coordinator_url}" "${generation}" "${auth_token}" <<'PY'
import json
import sys
import urllib.error
import urllib.request

base_url, generation, token = sys.argv[1:4]
request = urllib.request.Request(
    base_url.rstrip("/") + f"/api/validator-vpn/propagation/{int(generation)}",
    headers={
        "Accept": "application/json",
        "Authorization": f"Bearer {token}",
    },
)
try:
    with urllib.request.urlopen(request, timeout=10) as response:
        result = json.loads(response.read().decode("utf-8"))
except urllib.error.HTTPError as exc:
    detail = exc.read().decode("utf-8", errors="replace")
    raise SystemExit(f"propagation verification failed: HTTP {exc.code}: {detail[:400]}")
except urllib.error.URLError as exc:
    raise SystemExit(f"propagation verification failed: {exc.reason}")
if result.get("complete") is not True:
    raise SystemExit(
        "coordinator propagation is incomplete: "
        + json.dumps(result, separators=(",", ":"))[:800]
    )
PY
}

prepare_keys() {
  need_wg
  install -d -m 0700 "${VPN_DIR}" 2>/dev/null \
    || fail "cannot create validator VPN key directory ${VPN_DIR}; rerun with root or configure VALIDATOR_VPN_DIR to a writable validator workspace path"
  if [[ ! -f "${PRIVATE_KEY_PATH}" ]]; then
    umask 077
    wg genkey > "${PRIVATE_KEY_PATH}" \
      || fail "failed to generate WireGuard private key at ${PRIVATE_KEY_PATH}"
    chmod 0600 "${PRIVATE_KEY_PATH}"
  fi
  [[ -r "${PRIVATE_KEY_PATH}" ]] || fail "cannot read WireGuard private key at ${PRIVATE_KEY_PATH}"
  local derived_public_key current_public_key
  derived_public_key="$(wg pubkey < "${PRIVATE_KEY_PATH}")" \
    || fail "failed to derive WireGuard public key from ${PRIVATE_KEY_PATH}"
  current_public_key=""
  [[ -f "${PUBLIC_KEY_PATH}" ]] && current_public_key="$(tr -d '\n\r' < "${PUBLIC_KEY_PATH}")"
  if [[ "${current_public_key}" != "${derived_public_key}" ]]; then
    printf '%s\n' "${derived_public_key}" > "${PUBLIC_KEY_PATH}" \
      || fail "failed to write WireGuard public key at ${PUBLIC_KEY_PATH}"
    chmod 0644 "${PUBLIC_KEY_PATH}"
  fi
  echo "validator_vpn_agent_ok=true action=prepare public_key_path=${PUBLIC_KEY_PATH}"
  echo "public_key_path=${PUBLIC_KEY_PATH}"
  echo "wireguard_public_key=$(tr -d '\n\r' < "${PUBLIC_KEY_PATH}")"
}

status() {
  local private_present=false
  local public_present=false
  local iface_present=false
  local wg_present=false
  local address=""
  local actual_iface="${VPN_IFACE}"
  [[ -f "${PRIVATE_KEY_PATH}" ]] && private_present=true
  [[ -f "${PUBLIC_KEY_PATH}" ]] && public_present=true
  command -v wg >/dev/null 2>&1 && wg_present=true
  if is_linux && command -v ip >/dev/null 2>&1 && ip link show "${VPN_IFACE}" >/dev/null 2>&1; then
    iface_present=true
    address="$(ip -o addr show dev "${VPN_IFACE}" 2>/dev/null | awk '{print $4}' | paste -sd, -)"
  elif command -v ifconfig >/dev/null 2>&1 && ifconfig "${VPN_IFACE}" >/dev/null 2>&1; then
    iface_present=true
    address="$(ifconfig "${VPN_IFACE}" | awk '/inet / {print $2}' | paste -sd, -)"
  elif is_darwin && [[ -r "${STATE_PATH}" ]] && command -v ifconfig >/dev/null 2>&1; then
    local expected_address
    expected_address="$(python3 - "${STATE_PATH}" <<'PY'
import json
import sys

try:
    with open(sys.argv[1], "r", encoding="utf-8") as handle:
        payload = json.load(handle)
    print(str(payload.get("vpn_ip") or "").split("/", 1)[0])
except Exception:
    print("")
PY
)"
    if [[ -n "${expected_address}" ]]; then
      local detected_iface
      detected_iface="$(ifconfig 2>/dev/null | awk -v expected="${expected_address}" '/^[a-zA-Z0-9_.-]+:/{iface=$1; sub(":$","",iface)} $0 ~ "inet " expected " " {print iface; exit}')"
      if [[ -n "${detected_iface}" ]]; then
        iface_present=true
        actual_iface="${detected_iface}"
        address="${expected_address}"
      fi
    fi
  fi
  echo "validator_vpn_agent_ok=true action=status wg_present=${wg_present} iface_present=${iface_present} private_key_present=${private_present} public_key_present=${public_present} interface=${actual_iface} address=${address}"
  echo "public_key_path=${PUBLIC_KEY_PATH}"
  if [[ -f "${PUBLIC_KEY_PATH}" ]]; then
    echo "wireguard_public_key=$(tr -d '\n\r' < "${PUBLIC_KEY_PATH}")"
  fi
}

preflight() {
  local ok=true
  local platform
  platform="$(platform_name)"
  command -v python3 >/dev/null 2>&1 || { echo "python3_present=false"; ok=false; }
  command -v openssl >/dev/null 2>&1 || { echo "openssl_present=false"; echo "openssl_remediation=Install OpenSSL before applying signed validator VPN snapshots"; ok=false; }
  command -v wg >/dev/null 2>&1 || { echo "wg_present=false"; echo "wg_remediation=$(wireguard_install_hint wg)"; ok=false; }
  command -v wg-quick >/dev/null 2>&1 || { echo "wg_quick_present=false"; echo "wg_quick_remediation=$(wireguard_install_hint wg-quick)"; ok=false; }
  if is_linux; then
    command -v ip >/dev/null 2>&1 || { echo "ip_present=false"; echo "ip_remediation=Install iproute2 before applying the validator VPN interface"; ok=false; }
  elif is_darwin; then
    command -v ifconfig >/dev/null 2>&1 || { echo "ifconfig_present=false"; ok=false; }
    command -v route >/dev/null 2>&1 || { echo "route_present=false"; ok=false; }
  fi

  if [[ "${ok}" == "true" ]]; then
    echo "validator_vpn_agent_ok=true action=preflight platform=${platform} vpn_dir=${VPN_DIR} interface=${VPN_IFACE}"
    return 0
  fi
  echo "validator_vpn_agent_ok=false action=preflight platform=${platform} vpn_dir=${VPN_DIR} interface=${VPN_IFACE}" >&2
  return 1
}

validate_snapshot() {
  local snapshot_path="$1"
  local node_id="$2"
  local expected_vpn_ip="${3:-}"
  need_python
  python3 - "$snapshot_path" "$node_id" "$NETWORK_ID" "$CIDR" "$expected_vpn_ip" <<'PY'
import ipaddress
import json
import sys

snapshot_path, node_id, expected_network, expected_cidr, expected_vpn_ip = sys.argv[1:6]
with open(snapshot_path, "r", encoding="utf-8") as handle:
    snapshot = json.load(handle)

if snapshot.get("network") != expected_network:
    raise SystemExit(f"unexpected network {snapshot.get('network')}")
if snapshot.get("cidr") != expected_cidr:
    raise SystemExit(f"unexpected cidr {snapshot.get('cidr')}")
if not str(snapshot.get("signature", "")).strip():
    raise SystemExit("snapshot is unsigned")

seen_ips = set()
seen_keys = set()
found_local = False
local_vpn_ip = None

def check_peer(peer, role):
    global found_local, local_vpn_ip
    vpn_ip = peer.get("vpn_ip", "")
    wg_pubkey = peer.get("wg_pubkey", "")
    if peer.get("node_id") == node_id:
        found_local = True
        local_vpn_ip = vpn_ip
    if not wg_pubkey or "\n" in wg_pubkey or "PrivateKey" in wg_pubkey:
        raise SystemExit(f"invalid wg public key for {peer.get('node_name')}")
    interface = ipaddress.ip_interface(vpn_ip)
    if interface.network.prefixlen != 32:
        raise SystemExit(f"peer route is not exact /32: {vpn_ip}")
    octets = [int(part) for part in str(interface.ip).split(".")]
    if octets[0] != 10 or octets[1] != 69:
        raise SystemExit(f"peer outside validator VPN: {vpn_ip}")
    if role == "relayer" and octets[2] != 0:
        raise SystemExit(f"relayer outside relayer range: {vpn_ip}")
    if role == "validator":
        if octets[2] < 10 or octets[2] > 254:
            raise SystemExit(f"validator outside validator range: {vpn_ip}")
        if octets[3] in (0, 255):
            raise SystemExit(f"validator uses forbidden host octet: {vpn_ip}")
    if vpn_ip in seen_ips:
        raise SystemExit(f"duplicate VPN IP: {vpn_ip}")
    if wg_pubkey in seen_keys:
        raise SystemExit(f"duplicate WireGuard public key: {wg_pubkey}")
    seen_ips.add(vpn_ip)
    seen_keys.add(wg_pubkey)

for peer in snapshot.get("relayers", []):
    check_peer(peer, "relayer")
for peer in snapshot.get("validators", []):
    check_peer(peer, "validator")
if not found_local:
    raise SystemExit(f"local node {node_id} is not present in snapshot")
if expected_vpn_ip and local_vpn_ip != expected_vpn_ip:
    raise SystemExit(f"local node {node_id} has vpn_ip {local_vpn_ip}, expected {expected_vpn_ip}")
PY
}

verify_snapshot_signature() {
  local snapshot_path="$1"
  local signing_key="${VALIDATOR_VPN_COORDINATOR_SIGNING_KEY:-}"
  local public_key="${VALIDATOR_VPN_COORDINATOR_PUBLIC_KEY:-}"
  need_python
  need_openssl
  python3 - "$snapshot_path" "$public_key" "$signing_key" <<'PY'
import base64
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import textwrap

snapshot_path, public_key, signing_key = sys.argv[1:4]
with open(snapshot_path, "r", encoding="utf-8") as handle:
    snapshot = json.load(handle)
if not public_key:
    public_key = str(snapshot.get("coordinator_public_signing_key") or "")
if not signing_key and not public_key:
    raise SystemExit("coordinator snapshot verification key is missing")
signature = str(snapshot.get("signature") or "")
payload = {
    "generation": snapshot.get("generation"),
    "network": snapshot.get("network"),
    "cidr": snapshot.get("cidr"),
    "created_at": snapshot.get("created_at"),
    "relayers": [],
    "validators": [],
    "removed": [],
}

def canonical_peer(peer):
    output = {
        "node_id": peer.get("node_id"),
        "node_name": peer.get("node_name"),
        "vpn_ip": peer.get("vpn_ip"),
        "wg_pubkey": peer.get("wg_pubkey"),
    }
    if peer.get("endpoint") is not None:
        output["endpoint"] = peer.get("endpoint")
    output["status"] = peer.get("status")
    if peer.get("validator_pubkey") is not None:
        output["validator_pubkey"] = peer.get("validator_pubkey")
    if peer.get("operator_address") is not None:
        output["operator_address"] = peer.get("operator_address")
    return output

def canonical_removed(peer):
    return {
        "node_id": peer.get("node_id"),
        "vpn_ip": peer.get("vpn_ip"),
        "reason": peer.get("reason"),
    }

payload["relayers"] = [canonical_peer(peer) for peer in snapshot.get("relayers", [])]
payload["validators"] = [canonical_peer(peer) for peer in snapshot.get("validators", [])]
payload["removed"] = [canonical_removed(peer) for peer in snapshot.get("removed", [])]
encoded = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

def decode_prefixed_base64(value, *prefixes):
    value = str(value or "").strip()
    for prefix in prefixes:
        if value.startswith(prefix):
            value = value[len(prefix):]
            break
    return base64.b64decode(value, validate=True)

def verify_sha256_legacy():
    if not signing_key:
        raise SystemExit("legacy sha256 snapshots require the coordinator signing key")
    digest = hashlib.sha256(signing_key.encode("utf-8") + b":" + encoded).hexdigest()
    expected = f"sha256:{digest}"
    if signature != expected:
        raise SystemExit("snapshot signature verification failed")

def verify_ed25519():
    if not public_key:
        raise SystemExit("ed25519 snapshots require VALIDATOR_VPN_COORDINATOR_PUBLIC_KEY")
    pubkey = decode_prefixed_base64(public_key, "ed25519:", "base64:")
    if len(pubkey) != 32:
        raise SystemExit("ed25519 public key must decode to 32 bytes")
    sig = decode_prefixed_base64(signature, "ed25519:")
    if len(sig) != 64:
        raise SystemExit("ed25519 signature must decode to 64 bytes")
    der = bytes.fromhex("302a300506032b6570032100") + pubkey
    pem_body = base64.encodebytes(der).decode("ascii").replace("\n", "")
    pem = "-----BEGIN PUBLIC KEY-----\n"
    pem += "\n".join(textwrap.wrap(pem_body, 64))
    pem += "\n-----END PUBLIC KEY-----\n"
    with tempfile.TemporaryDirectory() as tmp:
        pub_path = os.path.join(tmp, "coordinator-public.pem")
        payload_path = os.path.join(tmp, "snapshot-payload.json")
        sig_path = os.path.join(tmp, "snapshot.sig")
        with open(pub_path, "w", encoding="ascii") as handle:
            handle.write(pem)
        with open(payload_path, "wb") as handle:
            handle.write(encoded)
        with open(sig_path, "wb") as handle:
            handle.write(sig)
        result = subprocess.run(
            [
                "openssl",
                "pkeyutl",
                "-verify",
                "-pubin",
                "-inkey",
                pub_path,
                "-rawin",
                "-in",
                payload_path,
                "-sigfile",
                sig_path,
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "verification failed").strip()
        raise SystemExit(f"snapshot signature verification failed: {detail}")

if signature.startswith("ed25519:"):
    verify_ed25519()
elif signature.startswith("sha256:"):
    verify_sha256_legacy()
else:
    raise SystemExit("unsupported snapshot signature format")
PY
}

fetch_latest_snapshot() {
  local coordinator_url="$1"
  local output_path="$2"
  local auth_token="${VALIDATOR_VPN_COORDINATOR_TOKEN:-}"
  [[ -n "${coordinator_url}" ]] || fail "--coordinator-url is required"
  need_python
  install -d -m 0700 "$(dirname "${output_path}")"
  python3 - "$coordinator_url" "$output_path" "$auth_token" <<'PY'
import json
import os
import sys
import urllib.error
import urllib.request

base_url, output_path, token = sys.argv[1:4]
url = base_url.rstrip("/") + "/api/validator-vpn/snapshots/latest"
request = urllib.request.Request(url, headers={"Accept": "application/json"})
if token:
    request.add_header("Authorization", f"Bearer {token}")
try:
    with urllib.request.urlopen(request, timeout=10) as response:
        payload = response.read()
except urllib.error.HTTPError as exc:
    detail = exc.read().decode("utf-8", errors="replace")
    raise SystemExit(f"snapshot fetch failed: HTTP {exc.code}: {detail[:400]}")
tmp = f"{output_path}.tmp"
decoded = json.loads(payload.decode("utf-8"))
with open(tmp, "w", encoding="utf-8") as handle:
    json.dump(decoded, handle, indent=2, sort_keys=True)
    handle.write("\n")
os.replace(tmp, output_path)
PY
  restore_result_file_permissions "${output_path}" 0644
}

render_peers() {
  local snapshot_path="$1"
  local node_id="$2"
  validate_snapshot "${snapshot_path}" "${node_id}"
  python3 - "$snapshot_path" "$node_id" <<'PY'
import json
import sys

snapshot_path, node_id = sys.argv[1:3]
with open(snapshot_path, "r", encoding="utf-8") as handle:
    snapshot = json.load(handle)

validators = snapshot.get("validators", [])
relayers = snapshot.get("relayers", [])
local_is_validator = any(peer.get("node_id") == node_id for peer in validators)
local_is_relayer = any(peer.get("node_id") == node_id for peer in relayers)
if not local_is_validator and not local_is_relayer:
    raise SystemExit(f"local node {node_id} is not in snapshot")

if local_is_validator:
    peers = [peer for peer in validators if peer.get("node_id") != node_id] + relayers
else:
    peers = validators

for peer in peers:
    print("[Peer]")
    print(f"PublicKey = {peer['wg_pubkey']}")
    print(f"AllowedIPs = {peer['vpn_ip']}")
    endpoint = peer.get("endpoint")
    if endpoint:
        print(f"Endpoint = {endpoint}")
        print("PersistentKeepalive = 25")
    print()
PY
}

snapshot_peer_routes() {
  local snapshot_path="$1"
  local node_id="$2"
  validate_snapshot "${snapshot_path}" "${node_id}"
  python3 - "$snapshot_path" "$node_id" <<'PY'
import json
import sys

snapshot_path, node_id = sys.argv[1:3]
with open(snapshot_path, "r", encoding="utf-8") as handle:
    snapshot = json.load(handle)

validators = snapshot.get("validators", [])
relayers = snapshot.get("relayers", [])
local_is_validator = any(peer.get("node_id") == node_id for peer in validators)
local_is_relayer = any(peer.get("node_id") == node_id for peer in relayers)
if not local_is_validator and not local_is_relayer:
    raise SystemExit(f"local node {node_id} is not in snapshot")

if local_is_validator:
    peers = [peer for peer in validators if peer.get("node_id") != node_id] + relayers
else:
    peers = validators

for peer in peers:
    print(peer["vpn_ip"])
PY
}

darwin_wireguard_interface() {
  local vpn_ip="$1"
  local expected_address="${vpn_ip%%/*}"
  ifconfig 2>/dev/null | awk -v expected="${expected_address}" '
    /^[a-zA-Z0-9_.-]+:/ { iface=$1; sub(":$", "", iface) }
    $0 ~ "inet " expected " " { print iface; exit }
  '
}

reconcile_peer_routes() {
  local snapshot_path="$1"
  local node_id="$2"
  local vpn_ip="$3"
  local desired_routes
  desired_routes="$(mktemp)"
  snapshot_peer_routes "${snapshot_path}" "${node_id}" > "${desired_routes}"

  if is_linux && command -v ip >/dev/null 2>&1; then
    local route
    while IFS= read -r route; do
      [[ -n "${route}" ]] || continue
      ip route replace "${route}" dev "${VPN_IFACE}"
    done < "${desired_routes}"

    while IFS= read -r route; do
      [[ -n "${route}" ]] || continue
      if [[ "${route}" != "${vpn_ip}" ]] && ! grep -Fxq "${route}" "${desired_routes}"; then
        ip route delete "${route}" dev "${VPN_IFACE}" >/dev/null 2>&1 || true
      fi
    done < <(
      ip route show dev "${VPN_IFACE}" 2>/dev/null \
        | awk '{print $1}' \
        | grep -E '^10\.69\.[0-9]+\.[0-9]+/32$' \
        || true
    )
  elif is_darwin && command -v route >/dev/null 2>&1; then
    local actual_iface
    actual_iface="$(darwin_wireguard_interface "${vpn_ip}")"
    if [[ -n "${actual_iface}" ]]; then
      local route host
      while IFS= read -r route; do
        [[ -n "${route}" ]] || continue
        host="${route%%/*}"
        route -n add -host "${host}" -interface "${actual_iface}" >/dev/null 2>&1 \
          || route -n change -host "${host}" -interface "${actual_iface}" >/dev/null 2>&1 \
          || true
      done < "${desired_routes}"
    fi
  fi

  rm -f "${desired_routes}"
}

apply_snapshot() {
  rerun_with_macos_admin_if_needed apply "$@" && return 0
  local snapshot_path=""
  local node_id=""
  local vpn_ip=""
  while [[ "$#" -gt 0 ]]; do
    case "$1" in
      --snapshot) snapshot_path="${2:-}"; shift 2 ;;
      --node-id) node_id="${2:-}"; shift 2 ;;
      --vpn-ip) vpn_ip="${2:-}"; shift 2 ;;
      *) fail "unknown apply argument: $1" ;;
    esac
  done
  [[ -n "${snapshot_path}" && -f "${snapshot_path}" ]] || fail "--snapshot file is required"
  [[ -n "${node_id}" ]] || fail "--node-id is required"
  [[ -n "${vpn_ip}" ]] || fail "--vpn-ip is required"
  need_root
  need_wg
  need_wg_quick
  prepare_keys >/dev/null
  validate_snapshot "${snapshot_path}" "${node_id}" "${vpn_ip}"
  verify_snapshot_signature "${snapshot_path}"

  if is_linux; then
    need_ip
    ip link show "${VPN_IFACE}" >/dev/null 2>&1 || ip link add "${VPN_IFACE}" type wireguard
    ip link set mtu "${MTU}" up dev "${VPN_IFACE}"
    ip address show dev "${VPN_IFACE}" | grep -Fq "${vpn_ip%%/*}" || ip address add "${vpn_ip}" dev "${VPN_IFACE}"
  elif is_darwin; then
    command -v ifconfig >/dev/null 2>&1 || fail "macOS WireGuard apply requires ifconfig"
    command -v route >/dev/null 2>&1 || fail "macOS WireGuard apply requires route"
    install -d -m 0700 "${VPN_DIR}/wireguard" \
      || fail "cannot create macOS WireGuard config directory ${VPN_DIR}/wireguard"
  else
    fail "unsupported platform $(platform_name) for validator VPN apply"
  fi

  local tmp_conf
  tmp_conf="$(mktemp)"
  chmod 0600 "${tmp_conf}"
  {
    echo "[Interface]"
    printf '%s = %s\n' "PrivateKey" "$(tr -d '\n\r' < "${PRIVATE_KEY_PATH}")"
    echo "Address = ${vpn_ip}"
    echo "ListenPort = ${LISTEN_PORT}"
    echo "MTU = ${MTU}"
    echo
    render_peers "${snapshot_path}" "${node_id}"
  } > "${tmp_conf}"

  if is_linux; then
    local linux_conf="/etc/wireguard/${VPN_IFACE}.conf"
    install -d -m 0700 "$(dirname "${linux_conf}")"
    cp "${tmp_conf}" "${linux_conf}"
    chmod 0600 "${linux_conf}"
    wg syncconf "${VPN_IFACE}" <(wg-quick strip "${linux_conf}")
    reconcile_peer_routes "${snapshot_path}" "${node_id}" "${vpn_ip}"
  elif is_darwin; then
    local mac_conf_dir="${VPN_DIR}/wireguard"
    local mac_conf="${mac_conf_dir}/${VPN_IFACE}.conf"
    cp "${tmp_conf}" "${mac_conf}"
    chmod 0600 "${mac_conf}"
    local mac_wg_iface
    mac_wg_iface="$(darwin_wireguard_interface "${vpn_ip}")"
    if [[ -n "${mac_wg_iface}" ]] && wg show "${mac_wg_iface}" >/dev/null 2>&1; then
      wg syncconf "${mac_wg_iface}" <(wg-quick strip "${mac_conf}")
    else
      wg-quick up "${mac_conf}"
    fi
    reconcile_peer_routes "${snapshot_path}" "${node_id}" "${vpn_ip}"
  fi
  rm -f "${tmp_conf}"
  local generation
  generation="$(json_get_generation "${snapshot_path}")"
  local peers_handshaked
  peers_handshaked="$(verified_peer_handshake_count)"
  [[ "${peers_handshaked}" -ge 1 ]] \
    || fail "config applied locally but no verified peer handshake is present"
  write_agent_state "${generation}" "${node_id}" "${vpn_ip}"
  if [[ "${snapshot_path}" == "${SNAPSHOT_PATH}" ]]; then
    restore_result_file_permissions "${SNAPSHOT_PATH}" 0644
  fi
  restore_result_file_permissions "${STATE_PATH}" 0644
  ack_config_generation "${COORDINATOR_URL}" "${node_id}" "${generation}" "${peers_handshaked}" \
    || fail "config applied locally but coordinator acknowledgement failed"
  echo "validator_vpn_agent_ok=true action=apply iface=${VPN_IFACE} vpn_ip=${vpn_ip} generation=${generation} peers_handshaked=${peers_handshaked}"
}

apply_latest_snapshot() {
  rerun_with_macos_admin_if_needed apply-latest "$@" && return 0
  local coordinator_url="${COORDINATOR_URL}"
  local node_id=""
  local vpn_ip=""
  while [[ "$#" -gt 0 ]]; do
    case "$1" in
      --coordinator-url) coordinator_url="${2:-}"; shift 2 ;;
      --node-id) node_id="${2:-}"; shift 2 ;;
      --vpn-ip) vpn_ip="${2:-}"; shift 2 ;;
      *) fail "unknown apply-latest argument: $1" ;;
    esac
  done
  [[ -n "${coordinator_url}" ]] || fail "--coordinator-url or VALIDATOR_VPN_COORDINATOR_URL is required"
  [[ -n "${node_id}" ]] || fail "--node-id is required"
  [[ -n "${vpn_ip}" ]] || fail "--vpn-ip is required"
  need_root
  need_wg
  need_wg_quick
  prepare_keys >/dev/null
  local fetched_snapshot
  fetched_snapshot="${SNAPSHOT_PATH}.download.$$"
  trap '[[ -n "${fetched_snapshot:-}" ]] && rm -f "${fetched_snapshot}"' RETURN
  rm -f "${fetched_snapshot}"
  fetch_latest_snapshot "${coordinator_url}" "${fetched_snapshot}"
  validate_snapshot "${fetched_snapshot}" "${node_id}" "${vpn_ip}"
  verify_snapshot_signature "${fetched_snapshot}"
  local latest_generation current_generation
  latest_generation="$(json_get_generation "${fetched_snapshot}")"
  current_generation="$(current_applied_generation)"
  if [[ "${latest_generation}" -le "${current_generation}" ]]; then
    rm -f "${fetched_snapshot}"
    fetched_snapshot=""
    trap - RETURN
    restore_result_file_permissions "${SNAPSHOT_PATH}" 0644
    restore_result_file_permissions "${STATE_PATH}" 0644
    verify_coordinator_propagation "${coordinator_url}" "${latest_generation}"
    echo "validator_vpn_agent_ok=true action=apply-latest skipped=true reason=already_current generation=${latest_generation}"
    return 0
  fi
  mkdir -p "$(dirname "${SNAPSHOT_PATH}")"
  mv "${fetched_snapshot}" "${SNAPSHOT_PATH}"
  restore_result_file_permissions "${SNAPSHOT_PATH}" 0644
  fetched_snapshot=""
  trap - RETURN
  apply_snapshot --snapshot "${SNAPSHOT_PATH}" --node-id "${node_id}" --vpn-ip "${vpn_ip}"
}

poll_latest_snapshot() {
  apply_latest_snapshot "$@"
}

render_command() {
  local snapshot_path=""
  local node_id=""
  while [[ "$#" -gt 0 ]]; do
    case "$1" in
      --snapshot) snapshot_path="${2:-}"; shift 2 ;;
      --node-id) node_id="${2:-}"; shift 2 ;;
      *) fail "unknown render argument: $1" ;;
    esac
  done
  [[ -n "${snapshot_path}" && -f "${snapshot_path}" ]] || fail "--snapshot file is required"
  [[ -n "${node_id}" ]] || fail "--node-id is required"
  render_peers "${snapshot_path}" "${node_id}"
}

case "${1:-}" in
  status) shift; status "$@" ;;
  preflight) shift; preflight "$@" ;;
  prepare) shift; prepare_keys "$@" ;;
  render) shift; render_command "$@" ;;
  apply) shift; apply_snapshot "$@" ;;
  apply-latest) shift; apply_latest_snapshot "$@" ;;
  poll) shift; poll_latest_snapshot "$@" ;;
  ""|--help|-h) usage ;;
  *) usage; fail "unknown command: ${1:-}" ;;
esac
