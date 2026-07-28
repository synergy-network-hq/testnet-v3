#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'
umask 077

REMOTE_ALIAS="${SYNERGY_ARCHIVE_SSH_ALIAS:-synergy-archive}"
REMOTE_HEALTH_GATE="${SYNERGY_ARCHIVE_REMOTE_HEALTH_GATE:-/Users/Shared/Synergy/archive-validator/bin/require-archive-health-green.sh}"
REMOTE_SCRIPT="${SYNERGY_ARCHIVE_REFRESH_SCRIPT:-/Users/Shared/Synergy/archive-validator/bin/revalidate-public-catalog.sh}"
REMOTE_OUT="${SYNERGY_ARCHIVE_REFRESH_OUT:-/Users/Shared/Synergy/archive-validator/public-catalog-freshness}"
BUCKET="${SYNERGY_SNAPSHOT_R2_BUCKET:-testnet-snapshot}"
PUBLIC_CATALOG="${SYNERGY_SNAPSHOT_PUBLIC_CATALOG_URL:-https://archive-store.synergynode.xyz/snapshots/latest.json}"
PUBLIC_RPC="${SYNERGY_TESTNET_PUBLIC_RPC_URL:-https://testnet-rpc.synergy-network.io}"
MAX_SNAPSHOT_LAG_BLOCKS="${SYNERGY_ARCHIVE_MAX_SNAPSHOT_LAG_BLOCKS:-10000}"
EXPECTED_SIGNER="${SYNERGY_AEGIS_ARCHIVE_SIGNER_SHA256:-8411d9bff2e669f69e1d649600ea80fb60aad663959dbb4d45b5e64c3c613199}"
AEGIS="${SYNERGY_LOCAL_AEGIS_CLI:-/Applications/Synergy Node Control Panel.app/Contents/Resources/binaries/synergy-aegis-darwin-arm64}"
WRANGLER_SPEC="${SYNERGY_WRANGLER_SPEC:-wrangler@4.110.0}"
STATE_ROOT="${HOME}/Library/Application Support/Synergy Network/archive-catalog-freshness"
WORK="${STATE_ROOT}/work.$$"
LOCK="${STATE_ROOT}/upload.flock"

mkdir -p "$STATE_ROOT"
cd "$STATE_ROOT"
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
notify_failure() {
  /usr/bin/osascript -e 'display notification "Archive catalog freshness publication failed. Review the Synergy archive freshness log." with title "Synergy Network"' >/dev/null 2>&1 || true
}
record_failure() {
  code=$?
  printf '%s status=red exit_code=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$code" >> "$STATE_ROOT/events.log"
  notify_failure
  exit "$code"
}
trap cleanup EXIT
trap record_failure ERR
mkdir -p "$WORK"

[[ -x "$AEGIS" ]] || { echo "local canonical Aegis verifier is unavailable: $AEGIS" >&2; exit 1; }
ssh -o BatchMode=yes "$REMOTE_ALIAS" "$REMOTE_HEALTH_GATE"
ssh -o BatchMode=yes "$REMOTE_ALIAS" "$REMOTE_SCRIPT"
scp -q "${REMOTE_ALIAS}:${REMOTE_OUT}/latest.json" "$WORK/latest.json"
scp -q "${REMOTE_ALIAS}:${REMOTE_OUT}/latest.json.sig" "$WORK/latest.json.sig"

"$AEGIS" verify-json \
  --domain SYNERGY_ARCHIVE_SNAPSHOT_CATALOG_V1 \
  --input "$WORK/latest.json" \
  --signature "$WORK/latest.json.sig" \
  --expected-signer-sha256 "$EXPECTED_SIGNER" >/dev/null

CURRENT_TRUSTED_CATALOG="$WORK/current-trusted.json"
if curl -fsSL --retry 3 --max-time 60 "$PUBLIC_CATALOG" -o "$WORK/current-public.json" \
    && curl -fsSL --retry 3 --max-time 60 "${PUBLIC_CATALOG}.sig" -o "$WORK/current-public.json.sig" \
    && "$AEGIS" verify-json \
      --domain SYNERGY_ARCHIVE_SNAPSHOT_CATALOG_V1 \
      --input "$WORK/current-public.json" \
      --signature "$WORK/current-public.json.sig" \
      --expected-signer-sha256 "$EXPECTED_SIGNER" >/dev/null 2>&1; then
  cp "$WORK/current-public.json" "$CURRENT_TRUSTED_CATALOG"
elif [[ -f "$STATE_ROOT/last-published.json" && -f "$STATE_ROOT/last-published.json.sig" ]] \
    && "$AEGIS" verify-json \
      --domain SYNERGY_ARCHIVE_SNAPSHOT_CATALOG_V1 \
      --input "$STATE_ROOT/last-published.json" \
      --signature "$STATE_ROOT/last-published.json.sig" \
      --expected-signer-sha256 "$EXPECTED_SIGNER" >/dev/null 2>&1; then
  cp "$STATE_ROOT/last-published.json" "$CURRENT_TRUSTED_CATALOG"
  printf '%s status=repairing reason=invalid_public_catalog reference=last_published\n' \
    "$(date -u +%Y-%m-%dT%H:%M:%SZ)" >> "$STATE_ROOT/events.log"
else
  printf '{"snapshots":[]}\n' > "$CURRENT_TRUSTED_CATALOG"
  printf '%s status=repairing reason=invalid_public_catalog reference=verified_archive_candidate\n' \
    "$(date -u +%Y-%m-%dT%H:%M:%SZ)" >> "$STATE_ROOT/events.log"
fi
curl -fsSL --retry 3 --max-time 30 \
  -H 'content-type: application/json' \
  --data '{"jsonrpc":"2.0","method":"synergy_blockNumber","params":[],"id":1}' \
  "$PUBLIC_RPC" -o "$WORK/public-height.json"
python3 - "$WORK/latest.json" "$WORK/public-height.json" "$MAX_SNAPSHOT_LAG_BLOCKS" <<'PY'
import json
import sys
import time

catalog = json.load(open(sys.argv[1], encoding="utf-8"))
age = int(time.time()) - int(catalog.get("updated_at", 0))
if age < 0 or age > 1800:
    raise SystemExit(f"refusing to publish catalog with unexpected age {age} seconds")
height_response = json.load(open(sys.argv[2], encoding="utf-8"))
public_height = height_response.get("result")
if isinstance(public_height, str):
    public_height = int(public_height, 16) if public_height.startswith("0x") else int(public_height)
if not isinstance(public_height, int) or public_height <= 0:
    raise SystemExit("public RPC did not return a positive chain height")
candidates = [
    entry for entry in catalog.get("snapshots", [])
    if entry.get("snapshot_class") == "validator-pruned" and entry.get("status") == "published"
]
if not candidates:
    raise SystemExit("catalog has no published validator-pruned snapshot")
snapshot_height = max(int(entry.get("height", 0)) for entry in candidates)
lag = public_height - snapshot_height
if lag < 0 or lag > int(sys.argv[3]):
    raise SystemExit(f"refusing snapshot lag of {lag} blocks at public height {public_height}")
PY

if [[ -x /opt/homebrew/bin/npx ]]; then
  NPX=/opt/homebrew/bin/npx
elif [[ -x /usr/local/bin/npx ]]; then
  NPX=/usr/local/bin/npx
else
  echo "npx is required for authenticated Cloudflare R2 publication" >&2
  exit 1
fi

put_and_verify() {
  local key="$1"
  local source="$2"
  local content_type="$3"
  local readback="$WORK/readback.$$.tmp"
  local attempt
  for attempt in 1 2 3 4; do
    rm -f "$readback"
    if "$NPX" --yes "$WRANGLER_SPEC" r2 object put "${BUCKET}/${key}" \
        --file="$source" --content-type="$content_type" --remote \
        && "$NPX" --yes "$WRANGLER_SPEC" r2 object get "${BUCKET}/${key}" \
          --file="$readback" --remote \
        && cmp "$source" "$readback"; then
      rm -f "$readback"
      return 0
    fi
    printf 'R2 publication attempt %s/4 failed for %s\n' "$attempt" "$key" >&2
    sleep "$((attempt * 2))"
  done
  rm -f "$readback"
  echo "R2 publication failed after 4 attempts for $key" >&2
  return 1
}

public_snapshot_artifacts_ready() {
  local catalog="$1"
  local manifest_url
  local manifest_signature_url
  local headers="$WORK/public-artifact.headers"
  local url
  local expected_size

  IFS=$'\t' read -r manifest_url manifest_signature_url < <(python3 - "$catalog" <<'PY'
import json
import sys

catalog = json.load(open(sys.argv[1], encoding="utf-8"))
candidates = [
    entry for entry in catalog.get("snapshots", [])
    if entry.get("snapshot_class") == "validator-pruned" and entry.get("status") == "published"
]
candidate = max(candidates, key=lambda entry: int(entry.get("height", 0))) if candidates else {}
print(f'{candidate.get("manifest_url", "")}\t{candidate.get("manifest_signature_url", "")}')
PY
  )
  [[ -n "$manifest_url" && -n "$manifest_signature_url" ]] || return 1
  curl -fsSL --retry 3 --max-time 60 "$manifest_url" -o "$WORK/public-distribution-manifest.json" || return 1
  curl -fsSL --retry 3 --max-time 60 "$manifest_signature_url" -o "$WORK/public-distribution-manifest.sig" || return 1
  "$AEGIS" verify-json \
    --domain SYNERGY_ARCHIVE_SNAPSHOT_DISTRIBUTION_V1 \
    --input "$WORK/public-distribution-manifest.json" \
    --signature "$WORK/public-distribution-manifest.sig" \
    --expected-signer-sha256 "$EXPECTED_SIGNER" >/dev/null 2>&1 || return 1

  while IFS=$'\t' read -r url expected_size; do
    [[ -n "$url" ]] || return 1
    curl -fsSI --retry 3 --max-time 60 "$url" -o "$headers" || return 1
    python3 - "$headers" "$expected_size" <<'PY' || return 1
import re
import sys

headers = open(sys.argv[1], encoding="utf-8", errors="replace").read()
matches = re.findall(r"(?im)^content-length:\s*(\d+)\s*$", headers)
if not matches:
    raise SystemExit("public snapshot artifact response omitted content-length")
actual = int(matches[-1])
expected = int(sys.argv[2])
if expected >= 0 and actual != expected:
    raise SystemExit(f"public snapshot artifact size mismatch: expected {expected}, received {actual}")
if expected < 0 and actual <= 0:
    raise SystemExit("public snapshot artifact is empty")
PY
  done < <(python3 - "$catalog" "$WORK/public-distribution-manifest.json" <<'PY'
import json
import sys
from urllib.parse import quote

catalog = json.load(open(sys.argv[1], encoding="utf-8"))
manifest = json.load(open(sys.argv[2], encoding="utf-8"))
candidates = [
    entry for entry in catalog.get("snapshots", [])
    if entry.get("snapshot_class") == "validator-pruned" and entry.get("status") == "published"
]
candidate = max(candidates, key=lambda entry: int(entry.get("height", 0))) if candidates else None
if not candidate:
    raise SystemExit("catalog has no validator-pruned snapshot")
for field in ("snapshot_url", "manifest_url", "manifest_signature_url", "checksums_url"):
    url = str(candidate.get(field, ""))
    expected = int(candidate.get("compressed_size_bytes", 0)) if field == "snapshot_url" else -1
    print(f"{url}\t{expected}")
base_url = str(candidate.get("manifest_url", "")).rsplit("/", 1)[0]
for chunk in manifest.get("chunks", []):
    print(f'{base_url}/{quote(str(chunk.get("name", "")))}\t{int(chunk.get("size_bytes", 0))}')
PY
  )
}

download_snapshot_artifacts() {
  local remote_snapshot_path="$1"
  local destination="$2"
  local artifact

  # A published archive directory can include the expanded chain state used to
  # build the compressed snapshot. Operators only need the receiver artifacts;
  # copying the whole directory can exhaust the publisher disk and leaves the
  # public catalog stale even though the archive itself is healthy.
  mkdir -p "$destination"
  for artifact in distribution-manifest.json distribution-manifest.sig checksums.sha256 verification-report.json; do
    scp -q "${REMOTE_ALIAS}:${remote_snapshot_path}/${artifact}" "$destination/${artifact}"
  done
  "$AEGIS" verify-json \
    --domain SYNERGY_ARCHIVE_SNAPSHOT_DISTRIBUTION_V1 \
    --input "$destination/distribution-manifest.json" \
    --signature "$destination/distribution-manifest.sig" \
    --expected-signer-sha256 "$EXPECTED_SIGNER" >/dev/null

  while IFS= read -r artifact; do
    [[ "$artifact" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]] \
      || { echo "distribution manifest contains an unsafe artifact name: $artifact" >&2; return 1; }
    scp -q "${REMOTE_ALIAS}:${remote_snapshot_path}/${artifact}" "$destination/${artifact}"
  done < <(python3 - "$destination/distribution-manifest.json" <<'PY'
import json
import pathlib
import sys

manifest = json.load(open(sys.argv[1], encoding="utf-8"))
names = [str(manifest.get("archive_filename", ""))]
names.extend(str(chunk.get("name", "")) for chunk in manifest.get("chunks", []))
for name in names:
    if not name or pathlib.PurePosixPath(name).name != name:
        raise SystemExit(f"unsafe snapshot artifact name: {name}")
    print(name)
PY
  )
}

verify_public_catalog_pair() {
  local catalog="$1"
  local signature="$2"
  local nonce
  local attempt

  for attempt in 1 2 3 4 5; do
    nonce="$(date +%s)-${attempt}"
    if curl -fsSL --retry 3 --max-time 60 "${PUBLIC_CATALOG}?freshness=${nonce}" -o "$catalog" \
      && curl -fsSL --retry 3 --max-time 60 "${PUBLIC_CATALOG}.sig?freshness=${nonce}" -o "$signature" \
      && "$AEGIS" verify-json \
        --domain SYNERGY_ARCHIVE_SNAPSHOT_CATALOG_V1 \
        --input "$catalog" \
        --signature "$signature" \
        --expected-signer-sha256 "$EXPECTED_SIGNER" >/dev/null; then
      return 0
    fi
    sleep "$attempt"
  done
  echo "public archive catalog and detached signature did not converge after publication" >&2
  return 1
}

python3 - "$WORK/latest.json" "$CURRENT_TRUSTED_CATALOG" "$WORK/snapshot-meta.json" <<'PY'
import json
import sys

def latest(path):
    value = json.load(open(path, encoding="utf-8"))
    candidates = [
        entry for entry in value.get("snapshots", [])
        if entry.get("snapshot_class") == "validator-pruned" and entry.get("status") == "published"
    ]
    return max(candidates, key=lambda entry: int(entry.get("height", 0))) if candidates else None

candidate = latest(sys.argv[1])
current = latest(sys.argv[2])
if not candidate:
    raise SystemExit("candidate catalog has no validator-pruned snapshot")
candidate_height = int(candidate.get("height", 0))
current_height = int(current.get("height", 0)) if current else 0
if candidate_height < current_height:
    raise SystemExit(
        f"refusing catalog downgrade from trusted height {current_height} to {candidate_height}"
    )
local_path = str(candidate.get("local_path", ""))
allowed = "/Users/Shared/Synergy/archive-validator/published-snapshots-v19/testnet-1266/validator-pruned/snapshot-"
if candidate_height > current_height and not local_path.startswith(allowed):
    raise SystemExit("new snapshot local_path is outside the canonical archive publication root")
with open(sys.argv[3], "w", encoding="utf-8") as handle:
    json.dump({
        "candidate_height": candidate_height,
        "current_height": current_height,
        "remote_snapshot_path": local_path,
    }, handle, sort_keys=True)
    handle.write("\n")
PY
CANDIDATE_HEIGHT="$(python3 -c 'import json,sys; print(int(json.load(open(sys.argv[1], encoding="utf-8"))["candidate_height"]))' "$WORK/snapshot-meta.json")"
CURRENT_HEIGHT="$(python3 -c 'import json,sys; print(int(json.load(open(sys.argv[1], encoding="utf-8"))["current_height"]))' "$WORK/snapshot-meta.json")"
REMOTE_SNAPSHOT_PATH="$(python3 -c 'import json,sys; print(str(json.load(open(sys.argv[1], encoding="utf-8"))["remote_snapshot_path"]))' "$WORK/snapshot-meta.json")"

PUBLISH_ARTIFACTS=0
if (( CANDIDATE_HEIGHT > CURRENT_HEIGHT )); then
  PUBLISH_ARTIFACTS=1
elif ! public_snapshot_artifacts_ready "$WORK/latest.json"; then
  PUBLISH_ARTIFACTS=1
  printf '%s status=repairing reason=incomplete_public_snapshot_artifacts height=%s\n' \
    "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$CANDIDATE_HEIGHT" >> "$STATE_ROOT/events.log"
fi

if (( PUBLISH_ARTIFACTS == 1 )); then
  SNAPSHOT_DIR="$WORK/snapshot-artifacts"
  download_snapshot_artifacts "$REMOTE_SNAPSHOT_PATH" "$SNAPSHOT_DIR"
  python3 - "$SNAPSHOT_DIR" "$CANDIDATE_HEIGHT" <<'PY'
import hashlib
import json
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
manifest = json.load(open(root / "distribution-manifest.json", encoding="utf-8"))
if int(manifest.get("height", 0)) != int(sys.argv[2]):
    raise SystemExit("distribution manifest height does not match the candidate catalog")
archive = root / str(manifest.get("archive_filename", ""))
if not archive.is_file():
    raise SystemExit("distribution archive is missing")
def sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()
if sha256(archive) != manifest.get("archive_sha256"):
    raise SystemExit("distribution archive checksum mismatch")
for chunk in manifest.get("chunks", []):
    path = root / str(chunk.get("name", ""))
    if not path.is_file() or sha256(path) != chunk.get("sha256"):
        raise SystemExit(f"snapshot chunk checksum mismatch: {path.name}")
PY
  while IFS=$'\t' read -r local_name object_name content_type; do
    put_and_verify "snapshots/${CANDIDATE_HEIGHT}/${object_name}" "$SNAPSHOT_DIR/$local_name" "$content_type"
  done < <(python3 - "$SNAPSHOT_DIR/distribution-manifest.json" <<'PY'
import json
import sys

manifest = json.load(open(sys.argv[1], encoding="utf-8"))
print(f'{manifest["archive_filename"]}\tsnapshot.tar.zst\tapplication/zstd')
print('distribution-manifest.json\tdistribution-manifest.json\tapplication/json')
print('distribution-manifest.sig\tsignature.sig\tapplication/json')
print('checksums.sha256\tchecksums.sha256\ttext/plain')
print('verification-report.json\tverification-report.json\tapplication/json')
for chunk in manifest.get("chunks", []):
    name = str(chunk["name"])
    print(f'{name}\t{name}\tapplication/octet-stream')
PY
  )
fi

public_snapshot_artifacts_ready "$WORK/latest.json" || {
  echo "public snapshot artifacts did not pass URL, size, and manifest-signature verification" >&2
  exit 1
}

ssh -o BatchMode=yes "$REMOTE_ALIAS" "$REMOTE_HEALTH_GATE"
put_and_verify "snapshots/latest.json.sig" "$WORK/latest.json.sig" application/json
put_and_verify "snapshots/latest.json" "$WORK/latest.json" application/json

verify_public_catalog_pair "$WORK/public-latest.json" "$WORK/public-latest.json.sig"
cmp "$WORK/latest.json" "$WORK/public-latest.json"
cmp "$WORK/latest.json.sig" "$WORK/public-latest.json.sig"
cp "$WORK/public-latest.json" "$STATE_ROOT/last-published.json"
cp "$WORK/public-latest.json.sig" "$STATE_ROOT/last-published.json.sig"
printf '%s status=green\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" >> "$STATE_ROOT/events.log"
echo "archive catalog freshness publication completed"
