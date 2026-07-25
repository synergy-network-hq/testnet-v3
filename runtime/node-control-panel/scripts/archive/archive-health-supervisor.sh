#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'
umask 077

MODE="${1:---once}"
[[ "$MODE" == "--once" ]] || { echo "usage: $0 --once" >&2; exit 64; }

ROOT="${SYNERGY_ARCHIVE_ROOT:-/Users/Shared/Synergy/archive-validator}"
HEALTH_DIR="${SYNERGY_ARCHIVE_HEALTH_DIR:-${ROOT}/health}"
EVIDENCE="${SYNERGY_ARCHIVE_HEALTH_EVIDENCE:-${HEALTH_DIR}/supervisor.json}"
PROGRESS="${SYNERGY_ARCHIVE_HEALTH_PROGRESS:-${HEALTH_DIR}/progress.json}"
RESTART_STATE="${SYNERGY_ARCHIVE_RESTART_STATE:-${HEALTH_DIR}/restart-budget.json}"
LOCK="${SYNERGY_ARCHIVE_HEALTH_LOCK:-${HEALTH_DIR}/supervisor.flock}"
LOCAL_RPC="${SYNERGY_ARCHIVE_LOCAL_RPC_URL:-http://127.0.0.1:5640}"
QUORUM_URLS="${SYNERGY_ARCHIVE_QUORUM_URLS:-http://195.26.241.95:5640,http://94.72.117.108:5640,https://testnet-rpc.synergy-network.io}"
MAX_LAG_BLOCKS="${SYNERGY_ARCHIVE_MAX_LAG_BLOCKS:-128}"
MAX_QUORUM_SPREAD_BLOCKS="${SYNERGY_ARCHIVE_MAX_QUORUM_SPREAD_BLOCKS:-16}"
NO_PROGRESS_SECONDS="${SYNERGY_ARCHIVE_NO_PROGRESS_SECONDS:-300}"
RESTART_BUDGET="${SYNERGY_ARCHIVE_RESTART_BUDGET:-3}"
RESTART_WINDOW_SECONDS="${SYNERGY_ARCHIVE_RESTART_WINDOW_SECONDS:-3600}"
RESTART_BACKOFF_SECONDS="${SYNERGY_ARCHIVE_RESTART_BACKOFF_SECONDS:-60}"
RESTART_MAX_BACKOFF_SECONDS="${SYNERGY_ARCHIVE_RESTART_MAX_BACKOFF_SECONDS:-900}"
RUNTIME_DOMAIN="${SYNERGY_ARCHIVE_RUNTIME_LAUNCHD_DOMAIN:-system}"
RUNTIME_LABEL="${SYNERGY_ARCHIVE_RUNTIME_LAUNCHD_LABEL:-network.synergy.archive-validator}"
LAUNCHCTL="${SYNERGY_LAUNCHCTL:-/bin/launchctl}"

mkdir -p "$HEALTH_DIR"
if [[ "${SYNERGY_ARCHIVE_HEALTH_LOCK_HELD:-}" == "1" ]]; then
  python3 - "$LOCK" <<'PY'
import fcntl
import os
import sys

fd = 9
lock_path = sys.argv[1]
try:
    descriptor_stat = os.fstat(fd)
    path_stat = os.stat(lock_path)
    if (descriptor_stat.st_dev, descriptor_stat.st_ino) != (path_stat.st_dev, path_stat.st_ino):
        raise OSError("inherited archive health lock points to the wrong file")
    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    os.set_inheritable(fd, True)
except BlockingIOError:
    print("archive health supervisor is already running")
    raise SystemExit(0)
except OSError as error:
    raise SystemExit(f"inherited archive health lock is invalid: {error}")
PY
  unset SYNERGY_ARCHIVE_HEALTH_LOCK_HELD
else
  exec python3 - "$LOCK" "$0" "$@" <<'PY'
import fcntl
import os
import sys

fd = 9
lock_path, script, *args = sys.argv[1:]
lock_file = open(lock_path, "a+", encoding="utf-8")
try:
    fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
except BlockingIOError:
    print("archive health supervisor is already running")
    raise SystemExit(0)
os.set_inheritable(lock_file.fileno(), True)
if lock_file.fileno() != fd:
    os.dup2(lock_file.fileno(), fd)
    os.set_inheritable(fd, True)
environment = os.environ.copy()
environment["SYNERGY_ARCHIVE_HEALTH_LOCK_HELD"] = "1"
os.execve("/bin/bash", ["/bin/bash", script, *args], environment)
PY
fi

WORK="${HEALTH_DIR}/.supervisor.$$"
mkdir -p "$WORK"
cleanup() { rm -rf "$WORK"; }
trap cleanup EXIT

query_rpc() {
  local url="$1"
  local output="$2"
  local payload='{"jsonrpc":"2.0","method":"synergy_blockNumber","params":[],"id":1}'
  if curl -fsS --connect-timeout 5 --max-time 12 --retry 0 \
    -H 'content-type: application/json' --data "$payload" "$url" -o "$output"; then
    if python3 - "$output" <<'PY'
import json
import sys

try:
    value = json.load(open(sys.argv[1], encoding="utf-8")).get("result")
    if isinstance(value, dict):
        value = value.get("height", value.get("block_number", value.get("number")))
    if isinstance(value, str):
        value = int(value, 16) if value.lower().startswith("0x") else int(value)
    raise SystemExit(0 if isinstance(value, int) and not isinstance(value, bool) and value > 0 else 1)
except (OSError, ValueError, TypeError, json.JSONDecodeError):
    raise SystemExit(1)
PY
    then
      return 0
    fi
  fi
  payload='{"jsonrpc":"2.0","method":"synergy_getLatestBlock","params":[],"id":1}'
  if curl -fsS --connect-timeout 5 --max-time 12 --retry 0 \
    -H 'content-type: application/json' --data "$payload" "$url" -o "$output"; then
    if python3 - "$output" <<'PY'
import json
import sys

try:
    value = json.load(open(sys.argv[1], encoding="utf-8")).get("result")
    if isinstance(value, dict):
        value = value.get("height", value.get("block_number", value.get("number")))
    if isinstance(value, str):
        value = int(value, 16) if value.lower().startswith("0x") else int(value)
    raise SystemExit(0 if isinstance(value, int) and not isinstance(value, bool) and value > 0 else 1)
except (OSError, ValueError, TypeError, json.JSONDecodeError):
    raise SystemExit(1)
PY
    then
      return 0
    fi
  fi
  printf '%s\n' '{"_supervisor_error":"rpc request failed"}' > "$output"
}

query_rpc "$LOCAL_RPC" "$WORK/local.json"
IFS=',' read -r -a QUORUM_ARRAY <<< "$QUORUM_URLS"
QUORUM_ARGS=()
for index in "${!QUORUM_ARRAY[@]}"; do
  url="${QUORUM_ARRAY[$index]}"
  [[ -n "$url" ]] || continue
  query_rpc "$url" "$WORK/quorum-${index}.json"
  QUORUM_ARGS+=("$url" "$WORK/quorum-${index}.json")
done

python3 - "$WORK/local.json" "$PROGRESS" "$RESTART_STATE" "$WORK/decision.json" "$LOCAL_RPC" \
  "$MAX_LAG_BLOCKS" "$MAX_QUORUM_SPREAD_BLOCKS" "$NO_PROGRESS_SECONDS" "$RESTART_BUDGET" \
  "$RESTART_WINDOW_SECONDS" "$RESTART_BACKOFF_SECONDS" "$RESTART_MAX_BACKOFF_SECONDS" "${QUORUM_ARGS[@]}" <<'PY'
import json
import os
import pwd
import sys
import time

local_path, progress_path, restart_path, decision_path, local_url = sys.argv[1:6]
max_lag, max_spread, no_progress_seconds, restart_budget = map(int, sys.argv[6:10])
restart_window, restart_backoff, restart_max_backoff = map(int, sys.argv[10:13])
quorum_args = sys.argv[13:]
now = int(time.time())

def read_json(path, fallback):
    try:
        with open(path, encoding="utf-8") as handle:
            value = json.load(handle)
        return value if isinstance(value, dict) else fallback
    except (OSError, json.JSONDecodeError):
        return fallback

def parse_height(path):
    value = read_json(path, {})
    if value.get("_supervisor_error"):
        return None, value["_supervisor_error"]
    result = value.get("result", value)
    if isinstance(result, dict):
        result = result.get("height", result.get("block_number", result.get("number")))
    try:
        if isinstance(result, str):
            result = int(result, 16) if result.lower().startswith("0x") else int(result)
        if isinstance(result, bool) or not isinstance(result, int) or result <= 0:
            raise ValueError("height is not a positive integer")
        return result, None
    except (TypeError, ValueError) as error:
        return None, f"invalid RPC height: {error}"

local_height, local_error = parse_height(local_path)
quorum = []
for offset in range(0, len(quorum_args), 2):
    url, path = quorum_args[offset:offset + 2]
    height, error = parse_height(path)
    quorum.append({
        "name": ["relayer-1", "relayer-2", "public-core-rpc"][len(quorum)] if len(quorum) < 3 else f"quorum-{len(quorum) + 1}",
        "url": url,
        "height": height,
        "status": "ok" if height is not None else "unavailable",
        **({} if error is None else {"error": error}),
    })

available = [item["height"] for item in quorum if item["height"] is not None]
quorum_height = sorted(available)[len(available) // 2] if available else None
spread = max(available) - min(available) if available else None
progress = read_json(progress_path, {})
previous_local = progress.get("local_height")
previous_quorum = progress.get("quorum_height")
if local_height is not None and local_height == previous_local:
    local_height_since = int(progress.get("local_height_since", now))
else:
    local_height_since = now
unchanged_for = max(0, now - local_height_since)
quorum_advanced = isinstance(quorum_height, int) and isinstance(previous_quorum, int) and quorum_height > previous_quorum

reasons = []
if local_height is None:
    reasons.append("local_rpc_unavailable")
if len(quorum) != 3:
    reasons.append("quorum_configuration_invalid")
if len(available) < 2:
    reasons.append("quorum_below_2_of_3")
if spread is not None and spread > max_spread:
    reasons.append("quorum_disagreement")
lag = None
if local_height is not None and quorum_height is not None:
    lag = max(0, quorum_height - local_height)
    if lag > max_lag:
        reasons.append("excessive_lag")
    if local_height > quorum_height + max_spread:
        reasons.append("local_ahead_of_quorum")
no_progress = (
    local_height is not None
    and quorum_height is not None
    and unchanged_for >= no_progress_seconds
    and quorum_advanced
)
if no_progress:
    reasons.append("no_progress")

restart_state = read_json(restart_path, {})
window_start = int(restart_state.get("window_started_at", now))
restart_count = int(restart_state.get("restart_count", 0))
if now - window_start >= restart_window or now < window_start:
    window_start = now
    restart_count = 0
last_restart_at = int(restart_state.get("last_restart_at", 0))
backoff = min(restart_max_backoff, restart_backoff * (2 ** restart_count))
restart_reasons = {"local_rpc_unavailable", "excessive_lag", "no_progress", "local_ahead_of_quorum"}
restart_needed = bool(restart_reasons.intersection(reasons))
restart_allowed = restart_needed and restart_count < restart_budget and now - last_restart_at >= backoff
if restart_needed and restart_count >= restart_budget:
    reasons.append("restart_budget_exhausted")
elif restart_needed and not restart_allowed and last_restart_at:
    reasons.append("restart_backoff_active")

decision = {
    "schema": "synergy-archive-health-v1",
    "checked_at": now,
    "local": {"url": local_url, "height": local_height, "status": "ok" if local_height is not None else "unavailable"},
    "quorum": quorum,
    "quorum_available": len(available),
    "quorum_required": 2,
    "quorum_height": quorum_height,
    "quorum_spread_blocks": spread,
    "lag_blocks": lag,
    "local_height_since": local_height_since,
    "unchanged_for_seconds": unchanged_for,
    "reasons": reasons,
    "restart_needed": restart_needed,
    "restart_allowed": restart_allowed,
    "restart_count": restart_count,
    "restart_budget": restart_budget,
    "restart_budget_remaining": max(0, restart_budget - restart_count),
    "restart_window_started_at": window_start,
    "restart_backoff_seconds": backoff,
    "last_restart_at": last_restart_at,
    "progress": {"local_height": local_height, "quorum_height": quorum_height, "local_height_since": local_height_since, "checked_at": now},
    "restart_state": {"window_started_at": window_start, "restart_count": restart_count, "last_restart_at": last_restart_at},
}
with open(decision_path, "w", encoding="utf-8") as handle:
    json.dump(decision, handle, sort_keys=True, indent=2)
    handle.write("\n")
PY

RESTART_ALLOWED="$(python3 -c 'import json,sys; print("1" if json.load(open(sys.argv[1], encoding="utf-8"))["restart_allowed"] else "0")' "$WORK/decision.json")"
RESTART_ATTEMPTED=0
RESTART_SUCCEEDED=0
ACTION=none
if [[ "$RESTART_ALLOWED" == "1" ]]; then
  RESTART_ATTEMPTED=1
  if "$LAUNCHCTL" kickstart -k "${RUNTIME_DOMAIN}/${RUNTIME_LABEL}"; then
    RESTART_SUCCEEDED=1
    ACTION=restart
  else
    ACTION=restart_failed
  fi
fi

python3 - "$WORK/decision.json" "$EVIDENCE" "$PROGRESS" "$RESTART_STATE" "$RESTART_ATTEMPTED" "$RESTART_SUCCEEDED" "$ACTION" <<'PY'
import json
import os
import pwd
import sys
import tempfile
import time

decision_path, evidence_path, progress_path, restart_path, attempted, succeeded, action = sys.argv[1:]
decision = json.load(open(decision_path, encoding="utf-8"))
attempted = int(attempted)
succeeded = int(succeeded)
now = int(time.time())
restart_count = int(decision["restart_count"]) + attempted
last_restart_at = now if attempted else int(decision["last_restart_at"])
restart_state = {
    "schema": "synergy-archive-restart-budget-v1",
    "window_started_at": int(decision["restart_window_started_at"]),
    "restart_count": restart_count,
    "restart_budget": int(decision["restart_budget"]),
    "last_restart_at": last_restart_at,
    "updated_at": now,
}
status = "green" if not decision["reasons"] else "red"
evidence = dict(decision)
evidence.update({
    "status": status,
    "health_verified": status == "green",
    "action": action,
    "restart_count": restart_count,
    "restart_budget_remaining": max(0, int(decision["restart_budget"]) - restart_count),
    "restart_succeeded": bool(succeeded),
    "updated_at": now,
})
if attempted and "restart_budget_exhausted" not in evidence["reasons"] and restart_count >= int(decision["restart_budget"]):
    evidence["reasons"].append("restart_budget_exhausted")
    evidence["status"] = "red"
    evidence["health_verified"] = False

def atomic_write(path, value):
    directory = os.path.dirname(path)
    os.makedirs(directory, mode=0o750, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=".archive-health-", dir=directory, text=True)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(value, handle, sort_keys=True, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        os.chmod(path, 0o640)
        if os.geteuid() == 0:
            reader = pwd.getpwnam(os.environ.get("SYNERGY_ARCHIVE_HEALTH_READER_USER", "synergynode"))
            os.chown(path, reader.pw_uid, reader.pw_gid)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)

atomic_write(progress_path, decision["progress"])
atomic_write(restart_path, restart_state)
atomic_write(evidence_path, evidence)
print(json.dumps({"status": evidence["status"], "action": action, "reasons": evidence["reasons"]}, sort_keys=True))
PY

STATUS="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1], encoding="utf-8"))["status"])' "$EVIDENCE")"
ACTION_VALUE="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1], encoding="utf-8"))["action"])' "$EVIDENCE")"
echo "archive health supervisor status=${STATUS} action=${ACTION_VALUE} evidence=${EVIDENCE}"
