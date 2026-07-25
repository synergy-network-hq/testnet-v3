#!/usr/bin/env bash
set -uo pipefail

DEFAULT_ENV_FILE="/etc/synergy/validator-vpn-coordinator.env"
DEFAULT_COORDINATOR_URL="https://vpn-coordinator.synergy-network.io"

ENV_FILE="${SYNERGY_VALIDATOR_VPN_COORDINATOR_ENV_FILE:-$DEFAULT_ENV_FILE}"
COORDINATOR_URL=""
SKIP_HTTP=0
ALLOW_HTTP=0

failures=0
warnings=0

usage() {
  cat <<USAGE
Usage: $0 [--env-file PATH] [--url URL] [--allow-http] [--skip-http]

Read-only readiness checks for the public validator VPN coordinator.
Secrets are checked for presence/shape only and are never printed.
USAGE
}

info() {
  printf '[INFO] %s\n' "$*"
}

pass() {
  printf '[PASS] %s\n' "$*"
}

warn() {
  warnings=$((warnings + 1))
  printf '[WARN] %s\n' "$*" >&2
}

fail() {
  failures=$((failures + 1))
  printf '[FAIL] %s\n' "$*" >&2
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --env-file)
      ENV_FILE="${2:-}"
      shift 2
      ;;
    --url)
      COORDINATOR_URL="${2:-}"
      shift 2
      ;;
    --skip-http)
      SKIP_HTTP=1
      shift
      ;;
    --allow-http)
      ALLOW_HTTP=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      fail "unknown argument: $1"
      usage
      exit 2
      ;;
  esac
done

read_env_key() {
  local key="$1"
  local current="${!key:-}"
  if [[ -n "$current" ]]; then
    printf '%s\n' "$current"
    return 0
  fi
  if [[ ! -f "$ENV_FILE" ]]; then
    return 0
  fi
  python3 - "$ENV_FILE" "$key" <<'PY'
import pathlib
import shlex
import sys

path = pathlib.Path(sys.argv[1])
key = sys.argv[2]
value = ""
for raw in path.read_text(encoding="utf-8").splitlines():
    line = raw.strip()
    if not line or line.startswith("#"):
        continue
    if line.startswith("export "):
        line = line[len("export "):].lstrip()
    if "=" not in line:
        continue
    candidate, raw_value = line.split("=", 1)
    if candidate.strip() != key:
        continue
    raw_value = raw_value.strip()
    if raw_value:
        try:
            parts = shlex.split(raw_value, comments=False, posix=True)
            value = parts[0] if parts else ""
        except ValueError:
            value = raw_value.strip('"').strip("'")
    else:
        value = ""
print(value)
PY
}

placeholder_value() {
  local value="$1"
  [[ "$value" == *replace-with* || "$value" == *example* || "$value" == *"<"* || "$value" == *">"* ]]
}

require_env() {
  local key="$1"
  local value
  value="$(read_env_key "$key")"
  if [[ -z "$value" ]]; then
    fail "$key is missing"
    return 1
  fi
  if placeholder_value "$value"; then
    fail "$key is still a placeholder"
    return 1
  fi
  pass "$key is set"
  return 0
}

validate_key32() {
  local label="$1"
  local value="$2"
  python3 - "$label" "$value" <<'PY'
import base64
import sys

label, value = sys.argv[1], sys.argv[2].strip()
for prefix in ("ed25519-seed:", "ed25519:", "base64:"):
    if value.startswith(prefix):
        value = value[len(prefix):].strip()
        break
try:
    decoded = base64.b64decode(value, validate=True)
except Exception as exc:
    print(f"{label} is not valid base64: {exc}", file=sys.stderr)
    sys.exit(1)
if len(decoded) != 32:
    print(f"{label} must decode to 32 bytes, got {len(decoded)}", file=sys.stderr)
    sys.exit(1)
PY
}

http_get() {
  local url="$1"
  local body_path="$2"
  local token="${3:-}"
  local args=(-sS --max-time 10 -o "$body_path" -w "%{http_code}")
  if [[ -n "$token" ]]; then
    args+=(-H "Authorization: Bearer $token")
  fi
  curl "${args[@]}" "$url"
}

json_field() {
  local path="$1"
  local field="$2"
  python3 - "$path" "$field" <<'PY'
import json
import sys

path, field = sys.argv[1], sys.argv[2]
try:
    payload = json.load(open(path, encoding="utf-8"))
except Exception:
    sys.exit(1)
value = payload
for part in field.split("."):
    if not isinstance(value, dict) or part not in value:
        sys.exit(1)
    value = value[part]
if isinstance(value, bool):
    print("true" if value else "false")
elif value is None:
    print("")
else:
    print(value)
PY
}

if [[ -f "$ENV_FILE" ]]; then
  pass "env file exists: $ENV_FILE"
else
  fail "env file is missing: $ENV_FILE"
fi

if ! command -v python3 >/dev/null 2>&1; then
  fail "python3 is required for env/key/JSON validation"
fi

if ! command -v curl >/dev/null 2>&1 && [[ "$SKIP_HTTP" -eq 0 ]]; then
  fail "curl is required for HTTP readiness checks"
fi

require_env SYNERGY_RESOURCE_ROOT
require_env SYNERGY_APP_DATA_DIR
require_env SYNERGY_VALIDATOR_VPN_COORDINATOR_TOKEN
require_env SYNERGY_VALIDATOR_VPN_COORDINATOR_SIGNING_KEY
require_env SYNERGY_VALIDATOR_VPN_COORDINATOR_PUBLIC_KEY
require_env SYNERGY_VALIDATOR_VPN_ENROLLMENT_SIGNATURE_MODE
require_env SYNERGY_INNERNET_SERVER_COMMAND
require_env SYNERGY_INNERNET_INTERFACE
require_env SYNERGY_INNERNET_VALIDATOR_CIDR
require_env SYNERGY_INNERNET_RELAYER_CIDR
require_env SYNERGY_INNERNET_VALIDATOR_ADDRESS_CIDR
require_env SYNERGY_INNERNET_RELAYER_ADDRESS_CIDR
require_env SYNERGY_INNERNET_CONFIG_DIR
require_env SYNERGY_INNERNET_DATA_DIR
require_env SYNERGY_INNERNET_INVITE_DIR
require_env SYNERGY_INNERNET_MIGRATION_ID
require_env SYNERGY_INNERNET_COORDINATOR_SIGNING_KEY
require_env SYNERGY_INNERNET_COORDINATOR_PUBLIC_KEY

invite_expires="$(read_env_key SYNERGY_INNERNET_INVITE_EXPIRES)"
if [[ -z "$invite_expires" ]]; then
  invite_expires="30m"
fi
if [[ "$invite_expires" =~ ^[1-9][0-9]*[smhdw]$ ]]; then
  pass "Innernet invitation expiry is a positive non-interactive duration: $invite_expires"
else
  fail "SYNERGY_INNERNET_INVITE_EXPIRES must match ^[1-9][0-9]*[smhdw]$"
fi

innernet_migration_ready="$(read_env_key SYNERGY_INNERNET_MIGRATION_READY)"
if [[ "$innernet_migration_ready" == "true" ]]; then
  innernet_server="$(read_env_key SYNERGY_INNERNET_SERVER_COMMAND)"
  innernet_interface="$(read_env_key SYNERGY_INNERNET_INTERFACE)"
  innernet_config_dir="$(read_env_key SYNERGY_INNERNET_CONFIG_DIR)"
  innernet_data_dir="$(read_env_key SYNERGY_INNERNET_DATA_DIR)"
  if [[ "$(id -u)" != "0" ]]; then
    fail "Innernet cutover readiness must run as root"
  fi
  if [[ ! -x "$innernet_server" ]]; then
    fail "Innernet server command is not executable: $innernet_server"
  elif ! "$innernet_server" --version 2>/dev/null | grep -q 'innernet-server 2\.0\.0'; then
    fail "Innernet server command must report v2.0.0"
  else
    pass "Innernet server command reports v2.0.0"
  fi
  if [[ -z "$innernet_interface" || ! "$innernet_interface" =~ ^[A-Za-z0-9_-]{1,15}$ ]]; then
    fail "Innernet interface name is invalid"
  fi
  innernet_config_file=""
  for suffix in conf toml; do
    candidate="$innernet_config_dir/${innernet_interface}.${suffix}"
    if [[ -s "$candidate" ]]; then
      innernet_config_file="$candidate"
      break
    fi
  done
  if [[ -z "$innernet_config_file" ]]; then
    fail "Innernet server configuration is missing for $innernet_interface (.conf or .toml)"
  elif [[ ! -s "$innernet_data_dir/${innernet_interface}.db" ]]; then
    fail "Innernet server database is missing for $innernet_interface"
  elif ! systemctl is-active --quiet "innernet-server@${innernet_interface}.service"; then
    fail "Innernet server service is not active for $innernet_interface"
  elif ! ip link show "$innernet_interface" >/dev/null 2>&1 || ! wg show "$innernet_interface" >/dev/null 2>&1; then
    fail "Innernet WireGuard interface is not active: $innernet_interface"
  else
    pass "Innernet server configuration, database, service, and WireGuard interface are active"
  fi
elif [[ "$innernet_migration_ready" == "false" || -z "$innernet_migration_ready" ]]; then
  pass "Innernet migration remains disabled until existing peers are re-enrolled"
else
  fail "SYNERGY_INNERNET_MIGRATION_READY must be true or false"
fi

local_agent="$(read_env_key SYNERGY_CONTROL_SERVICE_DISABLE_LOCAL_AGENT)"
if [[ "$local_agent" == "true" || "$local_agent" == "1" || "$local_agent" == "yes" ]]; then
  pass "local desktop agent startup is disabled for coordinator service"
else
  fail "SYNERGY_CONTROL_SERVICE_DISABLE_LOCAL_AGENT must be true on the public coordinator host"
fi

mode="$(read_env_key SYNERGY_VALIDATOR_VPN_ENROLLMENT_SIGNATURE_MODE)"
if [[ "$mode" == "challenge-sha256" ]]; then
  pass "enrollment verifier mode is challenge-sha256"
elif [[ -n "$mode" ]]; then
  fail "unsupported enrollment verifier mode: $mode"
fi

signing_key="$(read_env_key SYNERGY_VALIDATOR_VPN_COORDINATOR_SIGNING_KEY)"
if [[ -n "$signing_key" ]] && ! placeholder_value "$signing_key"; then
  case "$signing_key" in
    ed25519:*|ed25519-seed:*)
      if validate_key32 "coordinator signing key" "$signing_key"; then
        pass "coordinator signing key is an Ed25519 32-byte seed"
      else
        fail "coordinator signing key is not a valid Ed25519 32-byte seed"
      fi
      ;;
    *)
      fail "coordinator signing key must use ed25519:<base64-seed> or ed25519-seed:<base64-seed>"
      ;;
  esac
fi

public_key="$(read_env_key SYNERGY_VALIDATOR_VPN_COORDINATOR_PUBLIC_KEY)"
if [[ -n "$public_key" ]] && ! placeholder_value "$public_key"; then
  case "$public_key" in
    ed25519:*|base64:*)
      if validate_key32 "coordinator public key" "$public_key"; then
        pass "coordinator public key decodes to 32 bytes"
      else
        fail "coordinator public key is not a valid 32-byte Ed25519 public key"
      fi
      ;;
    *)
      fail "coordinator public key must use ed25519:<base64-public-key> or base64:<base64-public-key>"
      ;;
  esac
fi

innernet_signing_key="$(read_env_key SYNERGY_INNERNET_COORDINATOR_SIGNING_KEY)"
if [[ -n "$innernet_signing_key" ]] && ! placeholder_value "$innernet_signing_key"; then
  case "$innernet_signing_key" in
    ed25519:*|ed25519-seed:*)
      validate_key32 "Innernet coordinator signing key" "$innernet_signing_key" \
        && pass "Innernet coordinator signing key is an Ed25519 32-byte seed" \
        || fail "Innernet coordinator signing key is not a valid Ed25519 32-byte seed"
      ;;
    *) fail "Innernet coordinator signing key must use ed25519:<base64-seed> or ed25519-seed:<base64-seed>" ;;
  esac
fi

innernet_public_key="$(read_env_key SYNERGY_INNERNET_COORDINATOR_PUBLIC_KEY)"
if [[ -n "$innernet_public_key" ]] && ! placeholder_value "$innernet_public_key"; then
  case "$innernet_public_key" in
    ed25519:*|base64:*)
      validate_key32 "Innernet coordinator public key" "$innernet_public_key" \
        && pass "Innernet coordinator public key decodes to 32 bytes" \
        || fail "Innernet coordinator public key is not a valid 32-byte Ed25519 public key"
      ;;
    *) fail "Innernet coordinator public key must use ed25519:<base64-public-key> or base64:<base64-public-key>" ;;
  esac
fi

allowlist="$(read_env_key SYNERGY_VALIDATOR_VPN_ELIGIBLE_VALIDATORS)"
if [[ -n "$allowlist" ]]; then
  pass "optional static validator VPN allowlist is configured"
else
  info "optional static allowlist is unset; public enrollment still uses the live 50,000 SNRG stake gate"
fi

if [[ -z "$COORDINATOR_URL" ]]; then
  COORDINATOR_URL="$(read_env_key SYNERGY_VALIDATOR_VPN_COORDINATOR_URL)"
fi
if [[ -z "$COORDINATOR_URL" ]]; then
  COORDINATOR_URL="$DEFAULT_COORDINATOR_URL"
fi
COORDINATOR_URL="${COORDINATOR_URL%/}"

case "$COORDINATOR_URL" in
  https://*)
    pass "coordinator URL uses HTTPS: $COORDINATOR_URL"
    ;;
  http://127.0.0.1:*|http://localhost:*)
    if [[ "$ALLOW_HTTP" -eq 1 ]]; then
      pass "coordinator URL uses local HTTP for host-local readiness: $COORDINATOR_URL"
    else
      fail "local HTTP readiness requires --allow-http: $COORDINATOR_URL"
    fi
    ;;
  *)
    fail "coordinator URL must use HTTPS: $COORDINATOR_URL"
    ;;
esac

token="$(read_env_key SYNERGY_VALIDATOR_VPN_COORDINATOR_TOKEN)"

if [[ "$SKIP_HTTP" -eq 1 ]]; then
  info "HTTP checks skipped"
else
  host="$(
    python3 - "$COORDINATOR_URL" <<'PY'
from urllib.parse import urlparse
import sys

print(urlparse(sys.argv[1]).hostname or "")
PY
  )"
  if [[ -z "$host" ]]; then
    fail "could not parse coordinator host from $COORDINATOR_URL"
  else
    if python3 - "$host" <<'PY'
import socket
import sys

socket.getaddrinfo(sys.argv[1], 443)
PY
    then
      pass "DNS resolves for $host"
    else
      fail "DNS does not resolve for $host"
    fi
  fi

  tmp_dir="$(mktemp -d)"
  trap 'rm -rf "$tmp_dir"' EXIT

  health_body="$tmp_dir/health.json"
  health_code="$(http_get "$COORDINATOR_URL/health" "$health_body")"
  if [[ "$health_code" == "200" ]]; then
    status="$(json_field "$health_body" status || true)"
    if [[ "$status" == "ok" ]]; then
      pass "/health returned status=ok"
    else
      fail "/health returned HTTP 200 but did not report status=ok"
    fi
  else
    fail "/health returned HTTP $health_code"
  fi

  latest_body="$tmp_dir/latest.json"
  latest_code="$(http_get "$COORDINATOR_URL/api/validator-vpn/snapshots/latest" "$latest_body")"
  case "$latest_code" in
    200)
      generation="$(json_field "$latest_body" generation || true)"
      if [[ -n "$generation" ]]; then
        pass "latest peer snapshot is public and generated: generation=$generation"
      else
        fail "latest peer snapshot returned HTTP 200 without generation"
      fi
      ;;
    400)
      if grep -qi "No validator VPN peer snapshot" "$latest_body"; then
        warn "coordinator is reachable but no signed peer snapshot has been generated yet"
      else
        fail "latest snapshot returned HTTP 400: $(head -c 200 "$latest_body")"
      fi
      ;;
    *)
      fail "latest snapshot endpoint returned HTTP $latest_code"
      ;;
  esac

  status_body="$tmp_dir/status.json"
  status_code="$(http_get "$COORDINATOR_URL/api/validator-vpn/status" "$status_body" "$token")"
  if [[ "$status_code" == "200" ]]; then
    signing_configured="$(json_field "$status_body" signing_configured || true)"
    scheme="$(json_field "$status_body" snapshot_signature_scheme || true)"
    public_key_status="$(json_field "$status_body" coordinator_public_signing_key || true)"
    verifier_configured="$(json_field "$status_body" enrollment_verifier_configured || true)"
    latest_generation="$(json_field "$status_body" latest_generation || true)"
    if [[ "$signing_configured" == "true" ]]; then
      pass "status reports signing_configured=true"
    else
      fail "status reports signing_configured=$signing_configured"
    fi
    if [[ "$scheme" == "ed25519" ]]; then
      pass "status reports Ed25519 snapshot signing"
    else
      fail "status reports snapshot_signature_scheme=$scheme"
    fi
    if [[ -n "$public_key_status" ]]; then
      pass "status reports a coordinator public signing key"
    else
      fail "status is missing coordinator_public_signing_key"
    fi
    if [[ "$verifier_configured" == "true" ]]; then
      pass "status reports enrollment verifier configured"
    else
      fail "status reports enrollment_verifier_configured=$verifier_configured"
    fi
    if [[ -n "$latest_generation" ]]; then
      pass "status reports latest peer snapshot generation=$latest_generation"
    else
      warn "status has no latest peer snapshot generation yet"
    fi
  elif [[ "$status_code" == "401" ]]; then
    fail "status endpoint rejected the configured bearer token"
  else
    fail "status endpoint returned HTTP $status_code"
  fi
fi

if [[ "$failures" -gt 0 ]]; then
  printf 'validator VPN coordinator readiness failed: failures=%s warnings=%s\n' "$failures" "$warnings" >&2
  exit 1
fi

printf 'validator VPN coordinator readiness passed: warnings=%s\n' "$warnings"
