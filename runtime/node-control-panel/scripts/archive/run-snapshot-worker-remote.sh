#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'
umask 077

ROOT="${SYNERGY_ARCHIVE_ROOT:-/Users/Shared/Synergy/archive-validator}"
HEALTH_GATE="${SYNERGY_ARCHIVE_HEALTH_GATE:-${ROOT}/bin/require-archive-health-green.sh}"
WORKSPACE="${SYNERGY_ARCHIVE_WORKSPACE:-${ROOT}/workspace}"
PUBLISH_ROOT="${SYNERGY_SNAPSHOT_PUBLISH_ROOT:-${ROOT}/published-snapshots-v19}"
PUBLISHER="${SYNERGY_ARCHIVE_PUBLISHER:-${ROOT}/bin/synergy-archive-publisher}"
RUNTIME="${SYNERGY_ARCHIVE_RUNTIME:-/usr/local/synergy/bin/synergy-archive-validator-node}"
AEGIS="${SYNERGY_AEGIS_CLI:-${ROOT}/bin/synergy-aegis-v19-mldsa87}"
IDENTITY="${SYNERGY_AEGIS_ARCHIVE_IDENTITY:-${ROOT}/keys/aegis-archive-identity-v19-mldsa87.json}"
EXPECTED_SIGNER="${SYNERGY_AEGIS_ARCHIVE_SIGNER_SHA256:-8411d9bff2e669f69e1d649600ea80fb60aad663959dbb4d45b5e64c3c613199}"
CONSENSUS_FORK="${SYNERGY_CONSENSUS_FORK_MIGRATION_FILE:-${WORKSPACE}/config/consensus-fork-migration.json}"
PUBLIC_RPC="${SYNERGY_TESTNET_PUBLIC_RPC_URL:-https://testnet-rpc.synergy-network.io}"
PUBLIC_BASE_URL="${SYNERGY_SNAPSHOT_PUBLIC_BASE_URL:-https://archive-store.synergynode.xyz}"
BUCKET="${SYNERGY_SNAPSHOT_R2_BUCKET:-testnet-snapshot}"
MAX_SOURCE_LAG_BLOCKS="${SYNERGY_ARCHIVE_MAX_SOURCE_LAG_BLOCKS:-128}"
MAX_GENERATED_SNAPSHOT_LAG_BLOCKS="${SYNERGY_ARCHIVE_MAX_GENERATED_SNAPSHOT_LAG_BLOCKS:-2048}"
# Keep published snapshots comfortably inside the validator onboarding catch-up
# window even when one scheduled worker run is delayed.
SNAPSHOT_CADENCE_BLOCKS="${SYNERGY_ARCHIVE_SNAPSHOT_CADENCE_BLOCKS:-2500}"
LOCK="${ROOT}/state/snapshot-worker.flock"
WORK="${ROOT}/tmp/snapshot-worker.$$"
STATUS="${ROOT}/public-catalog-freshness/snapshot-worker-status.json"

for required in "$PUBLISHER" "$RUNTIME" "$AEGIS" "$IDENTITY" "$CONSENSUS_FORK"; do
  [[ -f "$required" ]] || { echo "required snapshot worker file is missing: $required" >&2; exit 1; }
done
[[ -x "$HEALTH_GATE" ]] || { echo "archive supervisor health gate is missing: $HEALTH_GATE" >&2; exit 1; }
"$HEALTH_GATE"
[[ -f "$WORKSPACE/data/committed_qcs.jsonl" ]] || {
  echo "archive committed QC log is unavailable" >&2
  exit 1
}
[[ -f "$WORKSPACE/data/canonical_locks.json" ]] || {
  echo "archive canonical lock state is unavailable" >&2
  exit 1
}

mkdir -p "$(dirname "$LOCK")" "$(dirname "$STATUS")"
if [[ "${SYNERGY_ARCHIVE_FLOCK_HELD:-}" == "1" ]]; then
  python3 - "$LOCK" <<'PY'
import fcntl
import os
import sys

FLOCK_FD = 9
lock_path = sys.argv[1]
try:
    descriptor_stat = os.fstat(FLOCK_FD)
    path_stat = os.stat(lock_path)
    if (descriptor_stat.st_dev, descriptor_stat.st_ino) != (path_stat.st_dev, path_stat.st_ino):
        raise OSError("inherited archive lock descriptor points to the wrong file")
    fcntl.flock(FLOCK_FD, fcntl.LOCK_EX | fcntl.LOCK_NB)
    os.set_inheritable(FLOCK_FD, True)
except BlockingIOError:
    print(f"archive persistence job is already running for {lock_path}")
    raise SystemExit(0)
except OSError as error:
    raise SystemExit(f"inherited archive lock descriptor is invalid: {error}")
PY
  unset SYNERGY_ARCHIVE_FLOCK_HELD
else
  exec python3 - "$LOCK" "$0" "$@" <<'PY'
import fcntl
import os
import sys

FLOCK_FD = 9
lock_path, script, *args = sys.argv[1:]
lock_file = open(lock_path, "a+", encoding="utf-8")
try:
    fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
except BlockingIOError:
    print(f"archive persistence job is already running for {lock_path}")
    raise SystemExit(0)
os.set_inheritable(lock_file.fileno(), True)
if lock_file.fileno() != FLOCK_FD:
    os.dup2(lock_file.fileno(), FLOCK_FD)
    os.set_inheritable(FLOCK_FD, True)
environment = os.environ.copy()
environment["SYNERGY_ARCHIVE_FLOCK_HELD"] = "1"
os.execve("/bin/bash", ["/bin/bash", script, *args], environment)
PY
fi
cleanup() {
  rm -rf "$WORK"
}
record_failure() {
  code=$?
  python3 - "$STATUS" "$code" <<'PY'
import json
import sys
import time

with open(sys.argv[1], "w", encoding="utf-8") as handle:
    json.dump({"status": "red", "checked_at": int(time.time()), "exit_code": int(sys.argv[2])}, handle, sort_keys=True, indent=2)
    handle.write("\n")
PY
  exit "$code"
}
trap cleanup EXIT
trap record_failure ERR
mkdir -p "$WORK"

/usr/bin/tail -n 1 "$WORKSPACE/data/committed_qcs.jsonl" > "$WORK/latest-qc.json"
python3 - "$WORK/latest-qc.json" "$WORKSPACE/data/canonical_locks.json" "$WORK/source-meta.json" <<'PY'
import json
import sys

qc = json.load(open(sys.argv[1], encoding="utf-8"))
block_hash = str(qc.get("block_hash", "")).strip().lower()
if len(block_hash) != 64:
    raise SystemExit("latest committed QC is missing a block hash")
locks = json.load(open(sys.argv[2], encoding="utf-8"))
matches = []
for raw_height, value in locks.items():
    candidate = value if isinstance(value, str) else value.get("block_hash") or value.get("hash")
    if str(candidate or "").strip().lower() == block_hash:
        matches.append(int(raw_height))
if not matches:
    raise SystemExit("latest committed QC hash is absent from canonical locks")
with open(sys.argv[3], "w", encoding="utf-8") as handle:
    json.dump({"height": max(matches), "hash": block_hash}, handle, sort_keys=True)
    handle.write("\n")
PY
SOURCE_HEIGHT="$(python3 -c 'import json,sys; print(int(json.load(open(sys.argv[1], encoding="utf-8"))["height"]))' "$WORK/source-meta.json")"
SOURCE_HASH="$(python3 -c 'import json,sys; print(str(json.load(open(sys.argv[1], encoding="utf-8"))["hash"]))' "$WORK/source-meta.json")"
[[ "$SOURCE_HEIGHT" =~ ^[0-9]+$ && "$SOURCE_HEIGHT" -gt 0 ]] || {
  echo "archive source metadata did not contain a positive committed height" >&2
  exit 1
}
[[ "$SOURCE_HASH" =~ ^[0-9a-f]{64}$ ]] || {
  echo "archive source metadata did not contain a canonical block hash" >&2
  exit 1
}

curl -fsSL --retry 3 --max-time 30 \
  -H 'content-type: application/json' \
  --data '{"jsonrpc":"2.0","method":"synergy_blockNumber","params":[],"id":1}' \
  "$PUBLIC_RPC" -o "$WORK/public-height.json"
curl -fsSL --retry 3 --max-time 30 \
  -H 'content-type: application/json' \
  --data "{\"jsonrpc\":\"2.0\",\"method\":\"synergy_getBlockByNumber\",\"params\":[${SOURCE_HEIGHT}],\"id\":2}" \
  "$PUBLIC_RPC" -o "$WORK/public-block.json"
python3 - "$WORK/public-height.json" "$WORK/public-block.json" "$SOURCE_HEIGHT" "$SOURCE_HASH" "$MAX_SOURCE_LAG_BLOCKS" "$WORK/public-meta.json" <<'PY'
import json
import sys

height_value = json.load(open(sys.argv[1], encoding="utf-8")).get("result")
if isinstance(height_value, str):
    height_value = int(height_value, 16) if height_value.startswith("0x") else int(height_value)
if not isinstance(height_value, int) or height_value <= 0:
    raise SystemExit("public RPC did not return a positive chain height")
block = json.load(open(sys.argv[2], encoding="utf-8")).get("result") or {}
public_hash = str(block.get("hash", "")).strip().lower()
source_height = int(sys.argv[3])
source_hash = sys.argv[4].lower()
lag = height_value - source_height
if lag < 0 or lag > int(sys.argv[5]):
    raise SystemExit(f"archive source is {lag} blocks behind public height {height_value}")
if public_hash != source_hash:
    raise SystemExit("archive committed QC hash does not match the public canonical block")
with open(sys.argv[6], "w", encoding="utf-8") as handle:
    json.dump({"height": height_value, "hash": public_hash, "source_lag": lag}, handle, sort_keys=True)
    handle.write("\n")
PY
PUBLIC_HEIGHT="$(python3 -c 'import json,sys; print(int(json.load(open(sys.argv[1], encoding="utf-8"))["height"]))' "$WORK/public-meta.json")"
PUBLIC_HASH="$(python3 -c 'import json,sys; print(str(json.load(open(sys.argv[1], encoding="utf-8"))["hash"]))' "$WORK/public-meta.json")"
SOURCE_LAG="$(python3 -c 'import json,sys; print(int(json.load(open(sys.argv[1], encoding="utf-8"))["source_lag"]))' "$WORK/public-meta.json")"

LATEST_PUBLISHED="$(python3 - "$PUBLISH_ROOT" <<'PY'
import json
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
for name in ("latest.json", "catalog.json"):
    path = root / name
    if not path.is_file():
        continue
    value = json.load(open(path, encoding="utf-8"))
    candidates = [
        int(entry.get("height", 0)) for entry in value.get("snapshots", [])
        if entry.get("snapshot_class") == "validator-pruned" and entry.get("status") == "published"
    ]
    if candidates:
        print(max(candidates))
        break
else:
    print(0)
PY
)"

if (( SOURCE_HEIGHT - LATEST_PUBLISHED < SNAPSHOT_CADENCE_BLOCKS )); then
  python3 - "$STATUS" "$SOURCE_HEIGHT" "$PUBLIC_HEIGHT" "$SOURCE_LAG" "$LATEST_PUBLISHED" <<'PY'
import json
import sys
import time

status = {
    "status": "green",
    "action": "not_due",
    "checked_at": int(time.time()),
    "source_height": int(sys.argv[2]),
    "public_height": int(sys.argv[3]),
    "source_lag_blocks": int(sys.argv[4]),
    "latest_published_height": int(sys.argv[5]),
}
with open(sys.argv[1], "w", encoding="utf-8") as handle:
    json.dump(status, handle, sort_keys=True, indent=2)
    handle.write("\n")
PY
  echo "archive snapshot is current at height ${LATEST_PUBLISHED}; next snapshot is not due"
  exit 0
fi

"$HEALTH_GATE"
"$RUNTIME" create-snapshot \
  --chain-id 1264 \
  --network-id synergy-testnet-v3 \
  --genesis-hash f79011f2aaddd40b120d47ba723104fafe3c998d4a17097fae018914b95f1789 \
  --source-workspace "$WORKSPACE" \
  --source-node-majority-branch-proven \
  --source-role VALIDATOR \
  --snapshot-class validator-pruned \
  --allowed-role validator \
  --allowed-role onboarding_validator \
  --allowed-role quarantined_validator > "$WORK/runtime-create-report.json"

python3 - "$WORK/runtime-create-report.json" "$WORKSPACE" "$WORK/runtime-snapshot-meta.json" <<'PY'
import json
import pathlib
import sys

report_path, workspace_path, output_path = sys.argv[1:]
report = json.load(open(report_path, encoding="utf-8"))
if report.get("success") is not True or report.get("fail_closed") is True:
    raise SystemExit("archive runtime did not create a usable snapshot")
height = report.get("snapshot_height")
block_hash = str(report.get("snapshot_hash", "")).strip().lower()
snapshot_root = pathlib.Path(str(report.get("snapshot_path", ""))).resolve()
manifest_path = pathlib.Path(str(report.get("manifest_path", ""))).resolve()
allowed_root = (pathlib.Path(workspace_path).resolve() / "data" / "snapshots")
if not isinstance(height, int) or height <= 0:
    raise SystemExit("archive runtime report is missing a positive snapshot height")
if len(block_hash) != 64 or any(character not in "0123456789abcdef" for character in block_hash):
    raise SystemExit("archive runtime report is missing a canonical snapshot hash")
if snapshot_root.parent != allowed_root or not snapshot_root.is_dir():
    raise SystemExit("archive runtime snapshot path is outside the canonical workspace")
if manifest_path.parent != snapshot_root or not manifest_path.is_file():
    raise SystemExit("archive runtime manifest path is outside the generated snapshot")
with open(output_path, "w", encoding="utf-8") as handle:
    json.dump({
        "height": height,
        "hash": block_hash,
        "snapshot_root": str(snapshot_root),
        "manifest_path": str(manifest_path),
    }, handle, sort_keys=True)
    handle.write("\n")
PY
SNAPSHOT_HEIGHT="$(python3 -c 'import json,sys; print(int(json.load(open(sys.argv[1], encoding="utf-8"))["height"]))' "$WORK/runtime-snapshot-meta.json")"
SNAPSHOT_HASH="$(python3 -c 'import json,sys; print(str(json.load(open(sys.argv[1], encoding="utf-8"))["hash"]))' "$WORK/runtime-snapshot-meta.json")"
SNAPSHOT_ROOT="$(python3 -c 'import json,sys; print(str(json.load(open(sys.argv[1], encoding="utf-8"))["snapshot_root"]))' "$WORK/runtime-snapshot-meta.json")"

curl -fsSL --retry 3 --max-time 30 \
  -H 'content-type: application/json' \
  --data '{"jsonrpc":"2.0","method":"synergy_blockNumber","params":[],"id":3}' \
  "$PUBLIC_RPC" -o "$WORK/post-create-public-height.json"
curl -fsSL --retry 3 --max-time 30 \
  -H 'content-type: application/json' \
  --data "{\"jsonrpc\":\"2.0\",\"method\":\"synergy_getBlockByNumber\",\"params\":[${SNAPSHOT_HEIGHT}],\"id\":4}" \
  "$PUBLIC_RPC" -o "$WORK/post-create-public-block.json"
python3 - "$WORK/post-create-public-height.json" "$WORK/post-create-public-block.json" "$SNAPSHOT_HEIGHT" "$SNAPSHOT_HASH" "$MAX_GENERATED_SNAPSHOT_LAG_BLOCKS" "$WORK/post-create-public-meta.json" <<'PY'
import json
import sys

height_value = json.load(open(sys.argv[1], encoding="utf-8")).get("result")
if isinstance(height_value, str):
    height_value = int(height_value, 16) if height_value.startswith("0x") else int(height_value)
if not isinstance(height_value, int) or height_value <= 0:
    raise SystemExit("public RPC did not return a positive post-snapshot chain height")
block = json.load(open(sys.argv[2], encoding="utf-8")).get("result") or {}
public_hash = str(block.get("hash", "")).strip().lower()
snapshot_height = int(sys.argv[3])
snapshot_hash = sys.argv[4].lower()
lag = height_value - snapshot_height
if lag < 0 or lag > int(sys.argv[5]):
    raise SystemExit(f"generated archive snapshot is {lag} blocks behind public height {height_value}")
if public_hash != snapshot_hash:
    raise SystemExit("generated archive snapshot hash does not match the public canonical block")
with open(sys.argv[6], "w", encoding="utf-8") as handle:
    json.dump({"height": height_value, "hash": public_hash, "snapshot_lag": lag}, handle, sort_keys=True)
    handle.write("\n")
PY
SNAPSHOT_PUBLIC_HEIGHT="$(python3 -c 'import json,sys; print(int(json.load(open(sys.argv[1], encoding="utf-8"))["height"]))' "$WORK/post-create-public-meta.json")"
SNAPSHOT_PUBLIC_HASH="$(python3 -c 'import json,sys; print(str(json.load(open(sys.argv[1], encoding="utf-8"))["hash"]))' "$WORK/post-create-public-meta.json")"
SNAPSHOT_LAG="$(python3 -c 'import json,sys; print(int(json.load(open(sys.argv[1], encoding="utf-8"))["snapshot_lag"]))' "$WORK/post-create-public-meta.json")"

EVIDENCE="$ROOT/evidence/automatic-majority-proof-${SNAPSHOT_HEIGHT}.json"
MARKER="$ROOT/evidence/source-majority-branch-proven.json"
python3 - "$EVIDENCE" "$MARKER" "$SNAPSHOT_HEIGHT" "$SNAPSHOT_HASH" "$SNAPSHOT_PUBLIC_HEIGHT" "$SNAPSHOT_PUBLIC_HASH" <<'PY'
import json
import os
import sys
import tempfile
import time

evidence_path, marker_path, height, source_hash, public_height, public_hash = sys.argv[1:]
height = int(height)
evidence = {
    "chain_id": 1264,
    "network_id": "synergy-testnet-v3",
    "genesis_hash": "f79011f2aaddd40b120d47ba723104fafe3c998d4a17097fae018914b95f1789",
    "height": height,
    "hash": source_hash,
    "public_height": int(public_height),
    "public_hash_at_height": public_hash,
    "proofs": ["runtime_snapshot_committed_aegis_qc", "runtime_snapshot_canonical_lock", "public_rpc_exact_hash_match"],
    "recorded_at": int(time.time()),
}
os.makedirs(os.path.dirname(evidence_path), exist_ok=True)
with open(evidence_path, "w", encoding="utf-8") as handle:
    json.dump(evidence, handle, sort_keys=True, indent=2)
    handle.write("\n")
marker = dict(evidence)
marker["source_node_majority_branch_proven"] = True
marker["source_evidence_path"] = evidence_path
fd, temp_path = tempfile.mkstemp(prefix=".source-majority-branch-proven.", dir=os.path.dirname(marker_path))
try:
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        json.dump(marker, handle, sort_keys=True, indent=2)
        handle.write("\n")
    os.replace(temp_path, marker_path)
finally:
    if os.path.exists(temp_path):
        os.unlink(temp_path)
PY

"$HEALTH_GATE"
env \
  SYNERGY_ARCHIVE_RUNTIME="$RUNTIME" \
  SYNERGY_AEGIS_CLI="$AEGIS" \
  SYNERGY_AEGIS_ARCHIVE_IDENTITY="$IDENTITY" \
  SYNERGY_AEGIS_ARCHIVE_SIGNER_SHA256="$EXPECTED_SIGNER" \
  SYNERGY_SNAPSHOT_LOCAL_ONLY=true \
  SYNERGY_SNAPSHOT_R2_BUCKET="$BUCKET" \
  SYNERGY_SNAPSHOT_PUBLIC_BASE_URL="$PUBLIC_BASE_URL" \
  "$PUBLISHER" \
    --workspace "$WORKSPACE" \
    --publish-root "$PUBLISH_ROOT" \
    --source-node-id archive-validator \
    --chain-id 1264 \
    --network-id synergy-testnet-v3 \
    --genesis-hash f79011f2aaddd40b120d47ba723104fafe3c998d4a17097fae018914b95f1789 \
    --consensus-fork "$CONSENSUS_FORK" \
    --majority-proof-marker "$MARKER" \
    --import-snapshot-root "$SNAPSHOT_ROOT" \
    --runtime-report "$WORK/runtime-create-report.json" > "$WORK/publication.json"

"$AEGIS" verify-json \
  --domain SYNERGY_ARCHIVE_SNAPSHOT_CATALOG_V1 \
  --input "$PUBLISH_ROOT/latest.json" \
  --signature "$PUBLISH_ROOT/latest.json.sig" \
  --expected-signer-sha256 "$EXPECTED_SIGNER" >/dev/null
python3 - "$WORK/publication.json" "$STATUS" "$SNAPSHOT_PUBLIC_HEIGHT" "$SNAPSHOT_LAG" "$PUBLIC_HEIGHT" "$SOURCE_LAG" <<'PY'
import json
import sys
import time

publication = json.load(open(sys.argv[1], encoding="utf-8"))
status = {
    "status": "green",
    "action": "published_locally",
    "checked_at": int(time.time()),
    "public_height": int(sys.argv[3]),
    "snapshot_lag_blocks": int(sys.argv[4]),
    "preflight_public_height": int(sys.argv[5]),
    "preflight_source_lag_blocks": int(sys.argv[6]),
    "publication": publication,
}
with open(sys.argv[2], "w", encoding="utf-8") as handle:
    json.dump(status, handle, sort_keys=True, indent=2)
    handle.write("\n")
PY
echo "archive snapshot worker published a verified local snapshot at height ${SNAPSHOT_HEIGHT}"
