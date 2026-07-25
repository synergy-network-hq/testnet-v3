#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'
umask 077

ROOT="${SYNERGY_ARCHIVE_ROOT:-/Users/Shared/Synergy/archive-validator}"
EVIDENCE="${SYNERGY_ARCHIVE_HEALTH_EVIDENCE:-${ROOT}/health/supervisor.json}"
MAX_AGE_SECONDS="${SYNERGY_ARCHIVE_HEALTH_MAX_AGE_SECONDS:-180}"

python3 - "$EVIDENCE" "$MAX_AGE_SECONDS" <<'PY'
import json
import sys
import time

path, max_age = sys.argv[1:]
try:
    with open(path, encoding="utf-8") as handle:
        evidence = json.load(handle)
except (OSError, json.JSONDecodeError) as error:
    raise SystemExit(f"archive supervisor health evidence is unavailable: {error}")

if evidence.get("schema") != "synergy-archive-health-v1":
    raise SystemExit("archive supervisor health evidence schema is unsupported")
if evidence.get("status") != "green" or evidence.get("health_verified") is not True:
    raise SystemExit("archive supervisor health is not green")
if evidence.get("action") not in (None, "none", "healthy"):
    raise SystemExit("archive supervisor has not completed a healthy observation")
if int(evidence.get("quorum_available", 0)) < 2:
    raise SystemExit("archive supervisor quorum evidence is below the 2-of-3 requirement")
if evidence.get("reasons"):
    raise SystemExit("archive supervisor health has active blockers")

try:
    checked_at = int(evidence["checked_at"])
    age = int(time.time()) - checked_at
    max_age_value = int(max_age)
except (KeyError, TypeError, ValueError) as error:
    raise SystemExit(f"archive supervisor health timestamp is invalid: {error}")
if age < 0 or age > max_age_value:
    raise SystemExit(f"archive supervisor health evidence is stale: age={age}s max={max_age_value}s")

print(f"archive supervisor health gate passed: local_height={evidence['local']['height']} quorum_height={evidence['quorum_height']}")
PY
