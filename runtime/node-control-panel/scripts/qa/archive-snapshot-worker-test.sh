#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'
umask 077

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
WORKER="$ROOT_DIR/scripts/archive/run-snapshot-worker-remote.sh"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/synergy-archive-worker-qa.XXXXXX")"
trap 'rm -rf "$TMP_DIR"' EXIT

grep -q 'SYNERGY_ARCHIVE_SNAPSHOT_CADENCE_BLOCKS:-2500' "$WORKER" \
  || { echo "snapshot worker default cadence exceeds the onboarding safety margin" >&2; exit 1; }

BIN="$TMP_DIR/bin"
ARCHIVE_ROOT="$TMP_DIR/archive"
WORKSPACE="$ARCHIVE_ROOT/workspace"
PUBLISH_ROOT="$ARCHIVE_ROOT/published-snapshots-v19"
HASH_A="$(printf 'a%.0s' {1..64})"
HASH_B="$(printf 'b%.0s' {1..64})"
mkdir -p "$BIN" "$WORKSPACE/data" "$WORKSPACE/config" "$ARCHIVE_ROOT/keys" "$PUBLISH_ROOT"
printf '{"block_hash":"%s"}\n' "$HASH_A" > "$WORKSPACE/data/committed_qcs.jsonl"
printf '{"100":{"block_hash":"%s"}}\n' "$HASH_A" > "$WORKSPACE/data/canonical_locks.json"
printf '{}\n' > "$WORKSPACE/config/consensus-fork-migration.json"
printf '{}\n' > "$ARCHIVE_ROOT/keys/archive-identity.json"

cat > "$BIN/health-gate" <<'SH'
#!/usr/bin/env bash
exit 0
SH
cat > "$BIN/aegis" <<'SH'
#!/usr/bin/env bash
exit 0
SH
cat > "$BIN/curl" <<'SH'
#!/usr/bin/env bash
set -Eeuo pipefail
output=""
payload=""
previous=""
for argument in "$@"; do
  if [[ "$previous" == "-o" ]]; then output="$argument"; fi
  if [[ "$previous" == "--data" ]]; then payload="$argument"; fi
  previous="$argument"
done
if [[ "$payload" == *synergy_getBlockByNumber* ]]; then
  if [[ "$payload" == *'[100]'* ]]; then hash="$HASH_A"; else hash="$HASH_B"; fi
  printf '{"result":{"hash":"%s"}}\n' "$hash" > "$output"
else
  printf '{"result":101}\n' > "$output"
fi
SH
cat > "$BIN/runtime" <<'SH'
#!/usr/bin/env bash
set -Eeuo pipefail
[[ "$1" == "create-snapshot" ]]
workspace=""
previous=""
for argument in "$@"; do
  if [[ "$previous" == "--source-workspace" ]]; then workspace="$argument"; fi
  previous="$argument"
done
snapshot_root="$workspace/data/snapshots/snapshot-101-worker-qa"
manifest="$snapshot_root/snapshot-101-manifest.json"
mkdir -p "$snapshot_root"
printf '{}\n' > "$manifest"
python3 - "$snapshot_root" "$manifest" "$HASH_B" <<'PY'
import json
import sys
snapshot_root, manifest, block_hash = sys.argv[1:]
print(json.dumps({
    "success": True,
    "fail_closed": False,
    "snapshot_height": 101,
    "snapshot_hash": block_hash,
    "snapshot_path": snapshot_root,
    "manifest_path": manifest,
}))
PY
SH
cat > "$BIN/publisher" <<'SH'
#!/usr/bin/env bash
set -Eeuo pipefail
publish_root=""
marker=""
snapshot_root=""
runtime_report=""
previous=""
for argument in "$@"; do
  case "$previous" in
    --publish-root) publish_root="$argument" ;;
    --majority-proof-marker) marker="$argument" ;;
    --import-snapshot-root) snapshot_root="$argument" ;;
    --runtime-report) runtime_report="$argument" ;;
  esac
  previous="$argument"
done
python3 - "$marker" "$runtime_report" "$snapshot_root" <<'PY'
import json
import pathlib
import sys
marker = json.load(open(sys.argv[1], encoding="utf-8"))
report = json.load(open(sys.argv[2], encoding="utf-8"))
assert marker["height"] == report["snapshot_height"] == 101
assert marker["hash"] == report["snapshot_hash"]
assert pathlib.Path(sys.argv[3]).resolve() == pathlib.Path(report["snapshot_path"]).resolve()
PY
mkdir -p "$publish_root"
printf '{}\n' > "$publish_root/latest.json"
printf '{}\n' > "$publish_root/latest.json.sig"
printf '{"snapshot_id":"worker-qa","height":101}\n'
SH
chmod +x "$BIN"/*

PATH="$BIN:$PATH" \
HASH_A="$HASH_A" \
HASH_B="$HASH_B" \
SYNERGY_ARCHIVE_ROOT="$ARCHIVE_ROOT" \
SYNERGY_ARCHIVE_HEALTH_GATE="$BIN/health-gate" \
SYNERGY_ARCHIVE_WORKSPACE="$WORKSPACE" \
SYNERGY_SNAPSHOT_PUBLISH_ROOT="$PUBLISH_ROOT" \
SYNERGY_ARCHIVE_PUBLISHER="$BIN/publisher" \
SYNERGY_ARCHIVE_RUNTIME="$BIN/runtime" \
SYNERGY_AEGIS_CLI="$BIN/aegis" \
SYNERGY_AEGIS_ARCHIVE_IDENTITY="$ARCHIVE_ROOT/keys/archive-identity.json" \
SYNERGY_CONSENSUS_FORK_MIGRATION_FILE="$WORKSPACE/config/consensus-fork-migration.json" \
SYNERGY_TESTNET_PUBLIC_RPC_URL=public://worker-qa \
SYNERGY_ARCHIVE_MAX_SOURCE_LAG_BLOCKS=10 \
SYNERGY_ARCHIVE_MAX_GENERATED_SNAPSHOT_LAG_BLOCKS=10 \
SYNERGY_ARCHIVE_SNAPSHOT_CADENCE_BLOCKS=1 \
  "$WORKER" >/dev/null

python3 - "$ARCHIVE_ROOT/public-catalog-freshness/snapshot-worker-status.json" <<'PY'
import json
import sys
status = json.load(open(sys.argv[1], encoding="utf-8"))
assert status["status"] == "green", status
assert status["action"] == "published_locally", status
assert status["snapshot_lag_blocks"] == 0, status
assert status["preflight_source_lag_blocks"] == 1, status
assert status["publication"]["height"] == 101, status
PY

echo "Archive snapshot worker QA passed: post-create canonical proof and two-phase import publication."
