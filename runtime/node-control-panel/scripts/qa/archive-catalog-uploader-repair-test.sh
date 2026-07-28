#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'
umask 077

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
UPLOADER="$ROOT_DIR/scripts/archive/upload-public-catalog-local.sh"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/synergy-archive-catalog-repair-qa.XXXXXX")"
trap 'rm -rf "$TMP_DIR"' EXIT

FAKE_BIN="$TMP_DIR/bin"
FIXTURES="$TMP_DIR/fixtures"
OBJECTS="$TMP_DIR/objects"
PUBLIC="$TMP_DIR/public"
STATE_HOME="$TMP_DIR/home"
mkdir -p "$FAKE_BIN" "$FIXTURES" "$OBJECTS" "$PUBLIC" "$STATE_HOME"

# Exercise the checked-in uploader while redirecting its platform npx choice to
# the hermetic fake below. The production script itself remains untouched.
TEST_UPLOADER="$TMP_DIR/upload-public-catalog-local.sh"
sed "s#/opt/homebrew/bin/npx#${FAKE_BIN}/npx#" "$UPLOADER" > "$TEST_UPLOADER"
chmod 0700 "$TEST_UPLOADER"

make_catalog() {
  python3 - "$1" "$2" "$3" <<'PY'
import json
import sys
import time

path, height, snapshot = sys.argv[1:]
json.dump({
    "chain_id": 1266,
    "network_id": "synergy-testnet-v3",
    "updated_at": int(time.time()),
    "snapshots": [{
        "snapshot_class": "validator-pruned",
        "status": "published",
        "height": int(height),
        "snapshot_id": snapshot,
        "local_path": "/Users/Shared/Synergy/archive-validator/published-snapshots-v19/testnet-1266/validator-pruned/snapshot-" + snapshot,
        "snapshot_url": "public://snapshot",
        "manifest_url": "public://manifest",
        "manifest_signature_url": "public://manifest.sig",
        "checksums_url": "public://checksums",
        "compressed_size_bytes": 4,
    }],
}, open(path, "w", encoding="utf-8"), sort_keys=True)
PY
}

sign_catalog() {
  printf 'sig-%s\n' "$(shasum -a 256 "$1" | awk '{print $1}')" > "$2"
}

cat > "$FAKE_BIN/synergy-aegis" <<'SH'
#!/usr/bin/env bash
set -Eeuo pipefail
[[ "$1" == verify-json ]] || exit 2
input=""; signature=""
previous=""
for argument in "$@"; do
  [[ "$previous" == --input ]] && input="$argument"
  [[ "$previous" == --signature ]] && signature="$argument"
  previous="$argument"
done
[[ -n "$input" && -n "$signature" ]]
expected="sig-$(shasum -a 256 "$input" | awk '{print $1}')"
[[ "$(<"$signature")" == "$expected" ]]
SH

cat > "$FAKE_BIN/ssh" <<'SH'
#!/usr/bin/env bash
set -Eeuo pipefail
exit 0
SH

cat > "$FAKE_BIN/scp" <<'SH'
#!/usr/bin/env bash
set -Eeuo pipefail
destination="${@: -1}"
source="${@: -2:1}"
printf '%s\n' "$source" >> "$TMP_DIR/scp-sources.log"
case "$source" in
  *latest.json) cp "$FIXTURES/candidate.json" "$destination" ;;
  *latest.json.sig) cp "$FIXTURES/candidate.json.sig" "$destination" ;;
  *distribution-manifest.json) cp "$FIXTURES/distribution-manifest.json" "$destination" ;;
  *distribution-manifest.sig) cp "$FIXTURES/distribution-manifest.json.sig" "$destination" ;;
  *checksums.sha256) cp "$FIXTURES/checksums.sha256" "$destination" ;;
  *verification-report.json) cp "$FIXTURES/verification-report.json" "$destination" ;;
  *snapshot.tar.zst) cp "$FIXTURES/snapshot.tar.zst" "$destination" ;;
  *snapshot.part-000000) cp "$FIXTURES/snapshot.part-000000" "$destination" ;;
  *) echo "unexpected scp source: $source" >&2; exit 2 ;;
esac
SH

cat > "$FAKE_BIN/curl" <<'SH'
#!/usr/bin/env bash
set -Eeuo pipefail
output=""; url=""; previous=""; headers_only=0
for argument in "$@"; do
  [[ "$previous" == -o ]] && output="$argument"
  [[ "$argument" == *://* ]] && url="$argument"
  [[ "$argument" == -*I* ]] && headers_only=1
  previous="$argument"
done
if [[ "$headers_only" == 1 ]]; then
  case "$url" in
    public://snapshot|public://snapshot.part-000000) size=4 ;;
    public://manifest|public://manifest.sig|public://checksums) size=8 ;;
    *) echo "unexpected HEAD URL: $url" >&2; exit 2 ;;
  esac
  printf 'HTTP/2 200\r\ncontent-length: %s\r\n\r\n' "$size" > "$output"
  exit 0
fi
case "$url" in
  public://catalog\?*|public://catalog) cp "$PUBLIC/latest.json" "$output" ;;
  public://catalog.sig\?*|public://catalog.sig) cp "$PUBLIC/latest.json.sig" "$output" ;;
  public://manifest) cp "$FIXTURES/distribution-manifest.json" "$output" ;;
  public://manifest.sig) cp "$FIXTURES/distribution-manifest.json.sig" "$output" ;;
  rpc://height) printf '{"result":"0x3e8"}\n' > "$output" ;;
  *) echo "unexpected curl URL: $url" >&2; exit 2 ;;
esac
SH

cat > "$FAKE_BIN/npx" <<'SH'
#!/usr/bin/env bash
set -Eeuo pipefail
operation=""; key=""; source=""; previous=""
for argument in "$@"; do
  [[ "$argument" == put || "$argument" == get ]] && operation="$argument"
  [[ "$previous" == put || "$previous" == get ]] && key="$argument"
  [[ "$argument" == --file=* ]] && source="${argument#--file=}"
  previous="$argument"
done
key="${key#*/}"
case "$operation:$key" in
  put:snapshots/101/*)
    target="$OBJECTS/${key#snapshots/101/}"
    mkdir -p "$(dirname "$target")"
    cp "$source" "$target"
    ;;
  get:snapshots/101/*)
    cp "$OBJECTS/${key#snapshots/101/}" "$source"
    ;;
  put:snapshots/latest.json.sig)
    cp "$source" "$OBJECTS/latest.json.sig"
    if [[ "${INJECT_SPLIT:-0}" == 1 && ! -e "$TMP_DIR/split-injected" ]]; then
      cp "$source" "$PUBLIC/latest.json.sig"
      : > "$TMP_DIR/split-injected"
    else
      cp "$source" "$PUBLIC/latest.json.sig"
    fi
    ;;
  put:snapshots/latest.json)
    if [[ "${FAIL_JSON_ONCE:-0}" == 1 && ! -e "$TMP_DIR/json-failed" ]]; then
      count=0
      [[ -f "$TMP_DIR/json-failed-count" ]] && count="$(<"$TMP_DIR/json-failed-count")"
      count=$((count + 1))
      printf '%s\n' "$count" > "$TMP_DIR/json-failed-count"
      [[ "$count" == 4 ]] && : > "$TMP_DIR/json-failed"
      exit 42
    fi
    cp "$source" "$OBJECTS/latest.json"
    cp "$source" "$PUBLIC/latest.json"
    ;;
  get:snapshots/latest.json.sig)
    cp "$OBJECTS/latest.json.sig" "$source"
    ;;
  get:snapshots/latest.json)
    cp "$OBJECTS/latest.json" "$source"
    ;;
  *)
    # The uploader only reaches this fake for the two latest catalog objects.
    echo "unexpected npx invocation: $*" >&2
    exit 2
    ;;
esac
SH

# Keep the fake R2 command deliberately narrow: it must cover both publication
# writes and readbacks, while any unrelated uploader write remains a failure.
chmod 0700 "$FAKE_BIN"/*

printf '%s\n' '{"height":101,"archive_filename":"snapshot.tar.zst","archive_sha256":"3a6eb0790f39ac87c94f3856b2dd2c5d110e6811602261a9a923d3bb23adc8b7","chunks":[{"name":"snapshot.part-000000","sha256":"3a6eb0790f39ac87c94f3856b2dd2c5d110e6811602261a9a923d3bb23adc8b7","size_bytes":4}]}' \
  > "$FIXTURES/distribution-manifest.json"
sign_catalog "$FIXTURES/distribution-manifest.json" "$FIXTURES/distribution-manifest.json.sig"
printf 'data' > "$FIXTURES/snapshot.tar.zst"
printf 'data' > "$FIXTURES/snapshot.part-000000"
printf 'qa\n' > "$FIXTURES/checksums.sha256"
printf '{"ok":true}\n' > "$FIXTURES/verification-report.json"

make_catalog "$FIXTURES/candidate.json" 100 checkpoint
sign_catalog "$FIXTURES/candidate.json" "$FIXTURES/candidate.json.sig"
cp "$FIXTURES/candidate.json" "$PUBLIC/latest.json"
cp "$FIXTURES/candidate.json.sig" "$PUBLIC/latest.json.sig"

make_catalog "$FIXTURES/candidate.json" 101 candidate
sign_catalog "$FIXTURES/candidate.json" "$FIXTURES/candidate.json.sig"

STATE_ROOT="$STATE_HOME/Library/Application Support/Synergy Network/archive-catalog-freshness"
mkdir -p "$STATE_ROOT"
cp "$PUBLIC/latest.json" "$STATE_ROOT/last-published.json"
cp "$PUBLIC/latest.json.sig" "$STATE_ROOT/last-published.json.sig"

run_uploader() {
  PATH="$FAKE_BIN:$PATH" HOME="$STATE_HOME" \
  FIXTURES="$FIXTURES" PUBLIC="$PUBLIC" OBJECTS="$OBJECTS" TMP_DIR="$TMP_DIR" \
  SYNERGY_LOCAL_AEGIS_CLI="$FAKE_BIN/synergy-aegis" \
  SYNERGY_ARCHIVE_SSH_ALIAS=synergy-archive \
  SYNERGY_ARCHIVE_REMOTE_HEALTH_GATE=/fake/health-green \
  SYNERGY_ARCHIVE_REFRESH_SCRIPT=/fake/revalidate \
  SYNERGY_ARCHIVE_REFRESH_OUT=/fake/catalog \
  SYNERGY_SNAPSHOT_PUBLIC_CATALOG_URL=public://catalog \
  SYNERGY_TESTNET_PUBLIC_RPC_URL=rpc://height \
  SYNERGY_WRANGLER_SPEC=wrangler@qa \
  "$TEST_UPLOADER"
}

# A failed JSON write leaves the public signature newer than public JSON.
if INJECT_SPLIT=1 FAIL_JSON_ONCE=1 run_uploader >"$TMP_DIR/first.out" 2>"$TMP_DIR/first.err"; then
  echo "split-publication fixture unexpectedly completed" >&2
  exit 1
fi
[[ "$(<"$PUBLIC/latest.json")" == "$(<"$STATE_ROOT/last-published.json")" ]]
cmp "$PUBLIC/latest.json.sig" "$FIXTURES/candidate.json.sig"
if cmp -s "$PUBLIC/latest.json.sig" "$STATE_ROOT/last-published.json.sig"; then
  echo "fixture did not reproduce a split public catalog" >&2
  exit 1
fi
if "$FAKE_BIN/synergy-aegis" verify-json \
  --domain SYNERGY_ARCHIVE_SNAPSHOT_CATALOG_V1 \
  --input "$PUBLIC/latest.json" \
  --signature "$PUBLIC/latest.json.sig" \
  --expected-signer-sha256 test-signer; then
  echo "split public catalog unexpectedly passed Aegis verification" >&2
  exit 1
fi

# The retry must restore the valid checkpoint pair, then publish the candidate.
run_uploader >"$TMP_DIR/repair.out"
cmp "$FIXTURES/candidate.json" "$PUBLIC/latest.json"
cmp "$FIXTURES/candidate.json.sig" "$PUBLIC/latest.json.sig"
cmp "$PUBLIC/latest.json" "$STATE_ROOT/last-published.json"
cmp "$PUBLIC/latest.json.sig" "$STATE_ROOT/last-published.json.sig"
if grep -Fq '/.' "$TMP_DIR/scp-sources.log"; then
  echo "uploader copied an archive directory instead of declared snapshot artifacts" >&2
  exit 1
fi
grep -Fq 'snapshot.tar.zst' "$TMP_DIR/scp-sources.log"
grep -Fq 'snapshot.part-000000' "$TMP_DIR/scp-sources.log"

# A lower candidate must fail closed and leave the newer publication intact.
make_catalog "$FIXTURES/candidate.json" 99 downgrade
sign_catalog "$FIXTURES/candidate.json" "$FIXTURES/candidate.json.sig"
if run_uploader >"$TMP_DIR/downgrade.out" 2>"$TMP_DIR/downgrade.err"; then
  echo "downgrade candidate unexpectedly published" >&2
  exit 1
fi
if cmp -s "$FIXTURES/candidate.json" "$STATE_ROOT/last-published.json"; then
  echo "downgrade replaced the local publication checkpoint" >&2
  exit 1
fi

echo "Archive catalog uploader repair QA passed: split publication recovery and downgrade protection."
