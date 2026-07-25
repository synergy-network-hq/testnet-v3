#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'
umask 077

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SUPERVISOR="$ROOT_DIR/scripts/archive/archive-health-supervisor.sh"
HEALTH_GATE="$ROOT_DIR/scripts/archive/require-archive-health-green.sh"
PLIST="$ROOT_DIR/scripts/archive/network.synergy.archive-health-supervisor.plist"
INSTALLER="$ROOT_DIR/scripts/archive/install-archive-health-supervisor.sh"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/synergy-archive-health-qa.XXXXXX")"
trap 'rm -rf "$TMP_DIR"' EXIT

plutil -lint "$PLIST" >/dev/null
python3 - "$PLIST" <<'PY'
import plistlib
import sys

with open(sys.argv[1], "rb") as handle:
    value = plistlib.load(handle)
assert value["UserName"] == "root"
assert value["RunAtLoad"] is True
PY
if rg -Fq '/bin/launchctl kickstart -k "system/${LABEL}"' "$INSTALLER"; then
  echo "RunAtLoad archive health supervisor must not be kickstarted immediately after bootstrap" >&2
  exit 1
fi
rg -Fq 'chown root:"$HEALTH_READER_GROUP" "$BIN_DIR/require-archive-health-green.sh"' "$INSTALLER"
python3 - "$SUPERVISOR" <<'PY'
import sys

script = open(sys.argv[1], encoding="utf-8").read()
evidence_writer = script.split('python3 - "$WORK/decision.json"', 1)[1].split("\nPY", 1)[0]
assert "\nimport pwd\n" in evidence_writer, "root-owned health evidence writer must import pwd"
PY

FAKE_BIN="$TMP_DIR/bin"
FIXTURES="$TMP_DIR/fixtures"
mkdir -p "$FAKE_BIN" "$FIXTURES"

cat > "$FAKE_BIN/curl" <<'SH'
#!/usr/bin/env bash
set -Eeuo pipefail
output=""
url=""
previous=""
for argument in "$@"; do
  if [[ "$previous" == "-o" ]]; then output="$argument"; fi
  if [[ "$argument" == *://* ]]; then url="$argument"; fi
  previous="$argument"
done
case "$url" in
  local://*) source="$FIXTURES/local.json" ;;
  relay1://*) source="$FIXTURES/relay1.json" ;;
  relay2://*) source="$FIXTURES/relay2.json" ;;
  public://*) source="$FIXTURES/public.json" ;;
  *) exit 1 ;;
esac
cp "$source" "$output"
SH
cat > "$FAKE_BIN/launchctl" <<'SH'
#!/usr/bin/env bash
set -Eeuo pipefail
printf '%s\n' "$*" >> "$LAUNCHCTL_LOG"
[[ "${FAKE_LAUNCHCTL_FAIL:-0}" != "1" ]]
SH
chmod +x "$FAKE_BIN/curl" "$FAKE_BIN/launchctl"

write_heights() {
  printf '{"result":"0x%x"}\n' "$1" > "$FIXTURES/local.json"
  printf '{"result":"0x%x"}\n' "$2" > "$FIXTURES/relay1.json"
  printf '{"result":"0x%x"}\n' "$3" > "$FIXTURES/relay2.json"
  printf '{"result":"0x%x"}\n' "$4" > "$FIXTURES/public.json"
}

run_supervisor() {
  PATH="$FAKE_BIN:$PATH" \
  FIXTURES="$FIXTURES" \
  LAUNCHCTL_LOG="$TMP_DIR/launchctl.log" \
  SYNERGY_ARCHIVE_ROOT="$TMP_DIR/state" \
  SYNERGY_ARCHIVE_LOCAL_RPC_URL=local://archive \
  SYNERGY_ARCHIVE_QUORUM_URLS=relay1://one,relay2://two,public://three \
  SYNERGY_ARCHIVE_MAX_LAG_BLOCKS=100 \
  SYNERGY_ARCHIVE_MAX_QUORUM_SPREAD_BLOCKS=16 \
  SYNERGY_ARCHIVE_NO_PROGRESS_SECONDS=0 \
  SYNERGY_ARCHIVE_RESTART_BUDGET="${SYNERGY_ARCHIVE_RESTART_BUDGET:-3}" \
  SYNERGY_ARCHIVE_RESTART_BACKOFF_SECONDS=0 \
  SYNERGY_ARCHIVE_RESTART_MAX_BACKOFF_SECONDS=0 \
  SYNERGY_LAUNCHCTL="$FAKE_BIN/launchctl" \
  "$SUPERVISOR" --once >/dev/null
}

health_status() { python3 - "$TMP_DIR/state/health/supervisor.json" "$1" <<'PY'
import json
import sys
value = json.load(open(sys.argv[1], encoding="utf-8"))
assert value["status"] == sys.argv[2], value
print(value.get("reasons", []))
PY
}

write_heights 100 100 101 100
run_supervisor
health_status green >/dev/null
[[ ! -s "$TMP_DIR/launchctl.log" ]]

write_heights 1 200 201 200
run_supervisor
health_status red | rg -q excessive_lag
rg -q 'kickstart -k system/network.synergy.archive-validator' "$TMP_DIR/launchctl.log"

rm -f "$TMP_DIR/state/health/restart-budget.json" "$TMP_DIR/launchctl.log"
write_heights 100 100 100 100
run_supervisor
write_heights 100 150 150 150
run_supervisor
health_status red | rg -q no_progress

rm -rf "$TMP_DIR/state/health"; mkdir -p "$TMP_DIR/state/health"
: > "$TMP_DIR/launchctl.log"
export SYNERGY_ARCHIVE_RESTART_BUDGET=1
write_heights 1 200 200 200
run_supervisor
run_supervisor
health_status red | rg -q restart_budget_exhausted
[[ "$(rg -c 'kickstart -k system/network.synergy.archive-validator' "$TMP_DIR/launchctl.log")" == "1" ]]

SYNERGY_ARCHIVE_ROOT="$TMP_DIR/state" "$HEALTH_GATE" >/dev/null 2>&1 || true
python3 - "$TMP_DIR/state/health/supervisor.json" <<'PY'
import json
import sys
import time
path = sys.argv[1]
value = json.load(open(path, encoding="utf-8"))
value.update({"status": "green", "health_verified": True, "action": "none", "reasons": [], "checked_at": int(time.time())})
json.dump(value, open(path, "w", encoding="utf-8"))
PY
SYNERGY_ARCHIVE_ROOT="$TMP_DIR/state" SYNERGY_ARCHIVE_HEALTH_MAX_AGE_SECONDS=9999999999 "$HEALTH_GATE" >/dev/null
python3 - "$TMP_DIR/state/health/supervisor.json" <<'PY'
import json
import sys
path = sys.argv[1]
value = json.load(open(path, encoding="utf-8"))
value["status"] = "red"
json.dump(value, open(path, "w", encoding="utf-8"))
PY
if SYNERGY_ARCHIVE_ROOT="$TMP_DIR/state" SYNERGY_ARCHIVE_HEALTH_MAX_AGE_SECONDS=9999999999 "$HEALTH_GATE" >/dev/null 2>&1; then
  echo "publication gate unexpectedly passed red supervisor evidence" >&2
  exit 1
fi

INSTALL_ROOT="$TMP_DIR/installed-archive"
LAUNCHD_DIR="$TMP_DIR/launchd"
SYNERGY_ARCHIVE_INSTALL_ROOT="$INSTALL_ROOT" \
SYNERGY_ARCHIVE_LAUNCHD_DIR="$LAUNCHD_DIR" \
SYNERGY_ARCHIVE_INSTALL_SKIP_LAUNCHCTL=1 \
  bash "$ROOT_DIR/scripts/archive/install-archive-health-supervisor.sh" >/dev/null
[[ -x "$INSTALL_ROOT/bin/archive-health-supervisor.sh" ]]
[[ -x "$INSTALL_ROOT/bin/require-archive-health-green.sh" ]]
[[ -f "$LAUNCHD_DIR/network.synergy.archive-health-supervisor.plist" ]]
python3 - "$INSTALL_ROOT/health" <<'PY'
import os
import stat
import sys

assert stat.S_IMODE(os.stat(sys.argv[1]).st_mode) == 0o750
PY
grep -Fq "/bin/archive-health-supervisor.sh</string>" "$LAUNCHD_DIR/network.synergy.archive-health-supervisor.plist"

for script in \
  "$ROOT_DIR/scripts/archive/run-snapshot-worker-remote.sh" \
  "$ROOT_DIR/scripts/archive/revalidate-public-catalog-remote.sh" \
  "$ROOT_DIR/scripts/archive/upload-public-catalog-local.sh"; do
  rg -q 'require-archive-health-green' "$script"
done
UPLOADER="$ROOT_DIR/scripts/archive/upload-public-catalog-local.sh"
rg -Fq 'ssh -o BatchMode=yes "$REMOTE_ALIAS" "$REMOTE_HEALTH_GATE"' "$UPLOADER"
rg -Fq 'cd "$STATE_ROOT"' "$UPLOADER"
if rg -q '^ARCHIVE_ROOT=|^HEALTH_GATE=|^"\$HEALTH_GATE"$' "$UPLOADER"; then
  echo "local catalog uploader must check archive health on the remote archive host" >&2
  exit 1
fi
SNAPSHOT_WORKER="$ROOT_DIR/scripts/archive/run-snapshot-worker-remote.sh"
rg -Fq '"$RUNTIME" create-snapshot' "$SNAPSHOT_WORKER"
rg -Fq -- '--import-snapshot-root "$SNAPSHOT_ROOT"' "$SNAPSHOT_WORKER"
rg -Fq -- '--runtime-report "$WORK/runtime-create-report.json"' "$SNAPSHOT_WORKER"
rg -Fq 'generated archive snapshot hash does not match the public canonical block' "$SNAPSHOT_WORKER"
[[ "$(rg -c 'stdout\(Stdio::null\(\)\)' "$ROOT_DIR/control-service/src/archive_snapshot.rs")" -ge 2 ]]
rg -Fq '.stderr(Stdio::piped())' "$ROOT_DIR/control-service/src/archive_snapshot.rs"
rg -Fq 'Verifier detail:' "$ROOT_DIR/control-service/src/archive_snapshot.rs"
rg -Fq 'report_hash = report.get("snapshot_hash") or report.get("committed_qc_hash")' \
  "$ROOT_DIR/scripts/archive/revalidate-public-catalog-remote.sh"
rg -Fq 'rm -f "$WORK/latest.json.sig"' \
  "$ROOT_DIR/scripts/archive/revalidate-public-catalog-remote.sh"
rg -Fq 'for candidate in "$LOCAL_CATALOG" "$OUT/latest.json"; do' \
  "$ROOT_DIR/scripts/archive/revalidate-public-catalog-remote.sh"
rg -Fq 'CATALOG_SOURCE=public_fallback' \
  "$ROOT_DIR/scripts/archive/revalidate-public-catalog-remote.sh"
rg -Fq '[[ -f "$candidate" && -f "${candidate}.sig" ]] || continue' \
  "$ROOT_DIR/scripts/archive/revalidate-public-catalog-remote.sh"

echo "Archive health supervisor QA passed: healthy, lagged, stalled, restart-budget, and publication-gate cases."
