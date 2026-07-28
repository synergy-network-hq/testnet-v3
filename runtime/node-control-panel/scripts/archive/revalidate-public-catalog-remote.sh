#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'
umask 077

ROOT="${SYNERGY_ARCHIVE_ROOT:-/Users/Shared/Synergy/archive-validator}"
HEALTH_GATE="${SYNERGY_ARCHIVE_HEALTH_GATE:-${ROOT}/bin/require-archive-health-green.sh}"
RUNTIME="${SYNERGY_ARCHIVE_CATALOG_RUNTIME:-${ROOT}/bin/synergy-testnet-catalog-verifier}"
AEGIS="${SYNERGY_ARCHIVE_CATALOG_AEGIS:-${ROOT}/bin/synergy-aegis-v19-mldsa87}"
IDENTITY="${SYNERGY_AEGIS_ARCHIVE_IDENTITY:-${ROOT}/keys/aegis-archive-identity-v19-mldsa87.json}"
EXPECTED_SIGNER="${SYNERGY_AEGIS_ARCHIVE_SIGNER_SHA256:-8411d9bff2e669f69e1d649600ea80fb60aad663959dbb4d45b5e64c3c613199}"
PUBLIC_CATALOG="${SYNERGY_SNAPSHOT_PUBLIC_CATALOG_URL:-https://archive-store.synergynode.xyz/snapshots/latest.json}"
PUBLIC_RPC="${SYNERGY_TESTNET_PUBLIC_RPC_URL:-https://testnet-rpc.synergy-network.io}"
MAX_SNAPSHOT_LAG_BLOCKS="${SYNERGY_ARCHIVE_MAX_SNAPSHOT_LAG_BLOCKS:-10000}"
LOCAL_CATALOG="${SYNERGY_ARCHIVE_LOCAL_PUBLIC_CATALOG:-${ROOT}/published-snapshots-v19/latest.json}"
OUT="${ROOT}/public-catalog-freshness"
LOCK="${ROOT}/state/public-catalog-freshness.flock"
WORK="${ROOT}/tmp/public-catalog-freshness.$$"

for required in "$RUNTIME" "$AEGIS" "$IDENTITY"; do
  [[ -f "$required" ]] || { echo "required archive freshness file is missing: $required" >&2; exit 1; }
done
[[ -x "$HEALTH_GATE" ]] || { echo "archive supervisor health gate is missing: $HEALTH_GATE" >&2; exit 1; }
"$HEALTH_GATE"

mkdir -p "$(dirname "$LOCK")"
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
trap cleanup EXIT
mkdir -p "$WORK" "$OUT"

# The archive host is the signed source of truth. A corrupt public pair must
# never prevent it from producing a verified replacement, otherwise a failed
# two-object publication becomes a permanent recovery deadlock.
CATALOG_SOURCE=""
for candidate in "$LOCAL_CATALOG" "$OUT/latest.json"; do
  [[ -f "$candidate" && -f "${candidate}.sig" ]] || continue
  if "$AEGIS" verify-json \
    --domain SYNERGY_ARCHIVE_SNAPSHOT_CATALOG_V1 \
    --input "$candidate" \
    --signature "${candidate}.sig" \
    --expected-signer-sha256 "$EXPECTED_SIGNER" >/dev/null 2>&1; then
    cp "$candidate" "$WORK/latest.json"
    cp "${candidate}.sig" "$WORK/latest.json.sig"
    CATALOG_SOURCE=local_snapshot_worker
    break
  fi
done

if [[ -z "$CATALOG_SOURCE" ]]; then
  curl -fsSL --retry 3 --max-time 60 "$PUBLIC_CATALOG" -o "$WORK/public-latest.json"
  curl -fsSL --retry 3 --max-time 60 "${PUBLIC_CATALOG}.sig" -o "$WORK/public-latest.json.sig"
  "$AEGIS" verify-json \
    --domain SYNERGY_ARCHIVE_SNAPSHOT_CATALOG_V1 \
    --input "$WORK/public-latest.json" \
    --signature "$WORK/public-latest.json.sig" \
    --expected-signer-sha256 "$EXPECTED_SIGNER" >/dev/null
  cp "$WORK/public-latest.json" "$WORK/latest.json"
  cp "$WORK/public-latest.json.sig" "$WORK/latest.json.sig"
  CATALOG_SOURCE=public_fallback
fi

python3 - "$WORK/latest.json" "$WORK/snapshot-meta.json" <<'PY'
import json
import sys

catalog = json.load(open(sys.argv[1], encoding="utf-8"))
candidates = [
    entry for entry in catalog.get("snapshots", [])
    if entry.get("snapshot_class") == "validator-pruned"
    and entry.get("status") == "published"
]
if not candidates:
    raise SystemExit("public catalog has no published validator-pruned snapshot")
entry = max(candidates, key=lambda value: (int(value.get("height", 0)), str(value.get("snapshot_id", ""))))
with open(sys.argv[2], "w", encoding="utf-8") as handle:
    json.dump({"snapshot_id": entry["snapshot_id"], "height": int(entry["height"]), "hash": entry["hash"]}, handle, sort_keys=True)
    handle.write("\n")
PY
SNAPSHOT_ID="$(python3 -c 'import json,sys; print(str(json.load(open(sys.argv[1], encoding="utf-8"))["snapshot_id"]))' "$WORK/snapshot-meta.json")"
HEIGHT="$(python3 -c 'import json,sys; print(int(json.load(open(sys.argv[1], encoding="utf-8"))["height"]))' "$WORK/snapshot-meta.json")"
EXPECTED_HASH="$(python3 -c 'import json,sys; print(str(json.load(open(sys.argv[1], encoding="utf-8"))["hash"]))' "$WORK/snapshot-meta.json")"

curl -fsSL --retry 3 --max-time 30 \
  -H 'content-type: application/json' \
  --data '{"jsonrpc":"2.0","method":"synergy_blockNumber","params":[],"id":1}' \
  "$PUBLIC_RPC" -o "$WORK/public-height.json"
PUBLIC_HEIGHT="$(python3 - "$WORK/public-height.json" <<'PY'
import json
import sys

value = json.load(open(sys.argv[1], encoding="utf-8")).get("result")
if isinstance(value, str):
    value = int(value, 16) if value.startswith("0x") else int(value)
if not isinstance(value, int) or value <= 0:
    raise SystemExit("public RPC did not return a positive chain height")
print(value)
PY
)"
if (( PUBLIC_HEIGHT < HEIGHT )); then
  echo "public chain height ${PUBLIC_HEIGHT} is behind snapshot height ${HEIGHT}" >&2
  exit 1
fi
SNAPSHOT_LAG=$((PUBLIC_HEIGHT - HEIGHT))
if (( SNAPSHOT_LAG > MAX_SNAPSHOT_LAG_BLOCKS )); then
  echo "snapshot ${SNAPSHOT_ID} is ${SNAPSHOT_LAG} blocks behind public height ${PUBLIC_HEIGHT}; refusing to refresh stale metadata" >&2
  exit 1
fi

MANIFEST="$(find "$ROOT/staging" "$ROOT/workspace/data/snapshots" \
  -type f -name "snapshot-${HEIGHT}-manifest.json" -print 2>/dev/null | sort | tail -n 1)"
[[ -n "$MANIFEST" && -f "$MANIFEST" ]] || {
  echo "local source manifest for public snapshot height ${HEIGHT} is unavailable" >&2
  exit 1
}
SNAPSHOT_ROOT="$(dirname "$MANIFEST")"
SOURCE_WORKSPACE="${MANIFEST%%/data/snapshots/*}"
[[ -f "${SOURCE_WORKSPACE}/config/node.toml" ]] || {
  echo "source workspace config is unavailable for ${MANIFEST}" >&2
  exit 1
}

env \
  SYNERGY_PROJECT_ROOT="$SOURCE_WORKSPACE" \
  SYNERGY_CONFIG_PATH="${SOURCE_WORKSPACE}/config/node.toml" \
  SYNERGY_SNAPSHOT_SOURCE_NODE_ID=archive-validator \
  "$RUNTIME" verify-snapshot \
    --chain-id 1266 \
    --network-id synergy-testnet-v3 \
    --genesis-hash f79011f2aaddd40b120d47ba723104fafe3c998d4a17097fae018914b95f1789 \
    --source-workspace "$SOURCE_WORKSPACE" \
    --manifest "$MANIFEST" \
    --snapshot-root "$SNAPSHOT_ROOT" \
    --snapshot-class validator-pruned \
    --target-role validator > "$WORK/runtime-verification.json"

python3 - "$WORK/latest.json" "$WORK/runtime-verification.json" "$SNAPSHOT_ID" "$HEIGHT" "$EXPECTED_HASH" "$PUBLIC_HEIGHT" "$SNAPSHOT_LAG" "$CATALOG_SOURCE" <<'PY'
import hashlib
import json
import sys
import time

catalog_path, report_path, snapshot_id, height, expected_hash, public_height, snapshot_lag, catalog_source = sys.argv[1:]
height = int(height)
public_height = int(public_height)
snapshot_lag = int(snapshot_lag)
catalog = json.load(open(catalog_path, encoding="utf-8"))
report = json.load(open(report_path, encoding="utf-8"))
if report.get("success") is not True or report.get("errors"):
    raise SystemExit("runtime snapshot verification did not succeed")
if int(report.get("snapshot_height", 0)) != height or int(report.get("committed_qc_height", 0)) != height:
    raise SystemExit("runtime verification height does not match the public snapshot")
report_hash = report.get("snapshot_hash") or report.get("committed_qc_hash")
if report_hash != expected_hash or report.get("committed_qc_hash") != expected_hash:
    raise SystemExit("runtime verification hash does not match the public snapshot")
if report.get("source_qc_aegis_pqc_verified") is not True or report.get("manifest_signature_verified") is not True:
    raise SystemExit("runtime verification did not prove the Aegis-signed source QC and manifest")

now = int(time.time())
entry = next(value for value in catalog["snapshots"] if value.get("snapshot_id") == snapshot_id)
entry["last_verified_at"] = now
catalog["updated_at"] = now
digest = hashlib.sha256()
for value in catalog["snapshots"]:
    digest.update(json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode())
    digest.update(b"\0")
catalog["catalog_content_root"] = digest.hexdigest()
with open(catalog_path, "w", encoding="utf-8") as handle:
    json.dump(catalog, handle, sort_keys=True, indent=2, separators=(",", ": "), ensure_ascii=False)
    handle.write("\n")
with open(sys.argv[2], encoding="utf-8") as handle:
    report = json.load(handle)
status = {
    "status": "green",
    "snapshot_id": snapshot_id,
    "height": height,
    "verified_at": now,
    "runtime_version": report.get("version"),
    "public_height": public_height,
    "snapshot_lag_blocks": snapshot_lag,
    "catalog_source": catalog_source,
    "catalog_content_root": catalog["catalog_content_root"],
}
with open(report_path + ".status", "w", encoding="utf-8") as handle:
    json.dump(status, handle, sort_keys=True, indent=2)
    handle.write("\n")
PY

"$HEALTH_GATE"
rm -f "$WORK/latest.json.sig"
"$AEGIS" sign-json \
  --identity "$IDENTITY" \
  --domain SYNERGY_ARCHIVE_SNAPSHOT_CATALOG_V1 \
  --input "$WORK/latest.json" \
  --output "$WORK/latest.json.sig" >/dev/null
"$AEGIS" verify-json \
  --domain SYNERGY_ARCHIVE_SNAPSHOT_CATALOG_V1 \
  --input "$WORK/latest.json" \
  --signature "$WORK/latest.json.sig" \
  --expected-signer-sha256 "$EXPECTED_SIGNER" >/dev/null

install -m 0644 "$WORK/runtime-verification.json" "$OUT/runtime-verification.json"
install -m 0644 "$WORK/runtime-verification.json.status" "$OUT/status.json"
install -m 0644 "$WORK/latest.json.sig" "$OUT/latest.json.sig"
install -m 0644 "$WORK/latest.json" "$OUT/latest.json"
echo "archive catalog revalidated: ${SNAPSHOT_ID} at height ${HEIGHT}"
