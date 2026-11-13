#!/usr/bin/env bash
set -euo pipefail

workspace="${SYNERGY_WORKSPACE:-$HOME/.synergy/testnet/nodes/validator-workspace}"
evidence_root="${SYNERGY_EVIDENCE_ROOT:-$HOME/synergy-testnet-evidence}"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
evidence="$evidence_root/${timestamp}-Val5-authorized-narrow-cleanup"
mkdir -p "$evidence/preserved-markers"

log="$evidence/cleanup.log"
exec > >(tee -a "$log") 2>&1

echo "spreadsheet_row_used=true"
echo "node=${SYNERGY_NODE:-unknown}"
echo "row=${SYNERGY_SPREADSHEET_ROW:-unknown}"
echo "workspace=$workspace"
echo "evidence_path=$evidence"

if [[ ! -d "$workspace/data" ]]; then
  echo "missing workspace data dir: $workspace/data" >&2
  exit 2
fi

runtime_process_count() {
  local count=0
  for proc in /proc/[0-9]*; do
    [[ -d "$proc" ]] || continue
    local exe cwd cmd
    exe="$(readlink "$proc/exe" 2>/dev/null || true)"
    cwd="$(readlink "$proc/cwd" 2>/dev/null || true)"
    cmd="$(tr '\0' ' ' < "$proc/cmdline" 2>/dev/null || true)"
    if [[ "$exe" == "$workspace"/bin/* || "$cwd" == "$workspace" ]]; then
      if [[ "$cmd" == *"synergy-testnet-linux-amd64 start --config"* ]]; then
        count=$((count + 1))
      fi
    fi
  done
  printf '%s\n' "$count"
}

qrpc_serving() {
  curl -fsS --max-time 3 \
    -H "content-type: application/json" \
    --data '{"jsonrpc":"2.0","method":"synergy_getLatestBlock","params":[],"id":1}' \
    http://127.0.0.1:5640 >/dev/null
}

echo "free_disk_before"
df -h "$HOME" "$workspace" /tmp

process_before="$(runtime_process_count)"
echo "process_count_before=$process_before"
if [[ "$process_before" != "0" ]]; then
  echo "refusing cleanup: Val5 runtime process is active" >&2
  exit 3
fi

if qrpc_serving; then
  echo "refusing cleanup: Val5 qRPC is serving on 127.0.0.1:5640" >&2
  exit 4
fi
echo "qrpc_serving_before=false"

echo "listeners_before"
ss -ltnp | grep -E ':(5622|5640|5660|5680|6030)\b' || true

marker_files=(
  "$workspace/data/validator_quarantine.json"
  "$workspace/data/validator_quarantine_peer_evidence.json"
  "$workspace/data/self_heal_status.json"
  "$workspace/data/divergence_status.json"
)

for marker in "${marker_files[@]}"; do
  if [[ -f "$marker" ]]; then
    cp -p "$marker" "$evidence/preserved-markers/$(basename "$marker")"
    sha256sum "$marker" >> "$evidence/preserved-markers/marker-sha256-before.txt"
  fi
done

protected_manifest="$evidence/protected-files-before.sha256"
find "$workspace/config" "$workspace/keys" -type f -print0 2>/dev/null \
  | sort -z \
  | xargs -0r sha256sum > "$protected_manifest"
find "$workspace" -maxdepth 4 -type f \( -iname '*genesis*' -o -iname '*quorum*' \) -print0 2>/dev/null \
  | sort -z \
  | xargs -0r sha256sum >> "$protected_manifest"

inventory="$evidence/cleanup-inventory.tsv"
listings="$evidence/cleanup-top-level-listings.txt"
printf 'action\tpath\tsize_bytes\tfile_count\tmtime\tpreserve_reason\n' > "$inventory"
: > "$listings"

size_bytes() {
  du -sb "$1" 2>/dev/null | awk '{print $1}'
}

file_count() {
  find "$1" -xdev -type f 2>/dev/null | wc -l | tr -d ' '
}

mtime_utc() {
  stat -c '%y' "$1" 2>/dev/null || printf 'unknown'
}

inventory_path() {
  local action="$1"
  local path="$2"
  local reason="$3"
  if [[ ! -e "$path" ]]; then
    return 0
  fi
  local size count mtime
  size="$(size_bytes "$path")"
  count="$(file_count "$path")"
  mtime="$(mtime_utc "$path")"
  printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$action" "$path" "$size" "$count" "$mtime" "$reason" >> "$inventory"
  {
    echo "===== $action $path ====="
    ls -la "$path" 2>/dev/null | sed -n '1,80p' || true
  } >> "$listings"
}

delete_targets=()

add_children_for_delete() {
  local parent="$1"
  local reason="$2"
  if [[ ! -d "$parent" ]]; then
    inventory_path preserve "$parent" "missing_parent"
    return 0
  fi
  inventory_path preserve "$parent" "container_preserved_children_considered"
  shopt -s nullglob dotglob
  local child
  for child in "$parent"/*; do
    [[ -e "$child" ]] || continue
    inventory_path delete "$child" "$reason"
    delete_targets+=("$child")
  done
  shopt -u nullglob dotglob
}

add_children_for_delete "$workspace/data/incoming-snapshots" "authorized_stale_incoming_snapshot"
add_children_for_delete "$workspace/data/snapshots" "authorized_stale_local_snapshot"
add_children_for_delete "$workspace/data/self-heal-evidence" "authorized_prior_stale_self_heal_payload"

shopt -s nullglob
for tmp_target in \
  /tmp/synergy-snapshot-* \
  /tmp/synergy-snapshots* \
  /tmp/validator-pruned-* \
  /tmp/snapshot-*-extract* \
  /tmp/synergy-val5-receiver-*; do
  if [[ -e "$tmp_target" ]]; then
    inventory_path delete "$tmp_target" "authorized_stale_tmp_snapshot_or_receiver_staging"
    delete_targets+=("$tmp_target")
  fi
done
shopt -u nullglob

expected_reclaim=0
for target in "${delete_targets[@]}"; do
  if [[ -e "$target" ]]; then
    bytes="$(size_bytes "$target")"
    expected_reclaim=$((expected_reclaim + bytes))
  fi
done
echo "expected_reclaim_bytes=$expected_reclaim"

printf '%s\n' "${delete_targets[@]}" > "$evidence/delete-targets.txt"

for target in "${delete_targets[@]}"; do
  case "$target" in
    "$workspace/data/incoming-snapshots/"*|"$workspace/data/snapshots/"*|"$workspace/data/self-heal-evidence/"*|/tmp/synergy-snapshot-*|/tmp/synergy-snapshots*|/tmp/validator-pruned-*|/tmp/snapshot-*-extract*|/tmp/synergy-val5-receiver-*)
      ;;
    *)
      echo "refusing unapproved cleanup target: $target" >&2
      exit 5
      ;;
  esac
  rm -rf -- "$target"
done

protected_after="$evidence/protected-files-after.sha256"
find "$workspace/config" "$workspace/keys" -type f -print0 2>/dev/null \
  | sort -z \
  | xargs -0r sha256sum > "$protected_after"
find "$workspace" -maxdepth 4 -type f \( -iname '*genesis*' -o -iname '*quorum*' \) -print0 2>/dev/null \
  | sort -z \
  | xargs -0r sha256sum >> "$protected_after"

if cmp -s "$protected_manifest" "$protected_after"; then
  echo "protected_files_untouched=true"
else
  echo "protected_files_untouched=false" >&2
  diff -u "$protected_manifest" "$protected_after" || true
  exit 6
fi

for marker in "$workspace/data/validator_quarantine.json" "$workspace/data/self_heal_status.json"; do
  if [[ ! -f "$marker" ]]; then
    echo "required active marker missing after cleanup: $marker" >&2
    exit 7
  fi
done
sha256sum "$workspace/data/validator_quarantine.json" "$workspace/data/self_heal_status.json" \
  > "$evidence/active-marker-sha256-after.txt"

process_after="$(runtime_process_count)"
echo "process_count_after=$process_after"
if [[ "$process_after" != "0" ]]; then
  echo "Val5 runtime process started unexpectedly" >&2
  exit 8
fi

if qrpc_serving; then
  echo "Val5 qRPC started unexpectedly" >&2
  exit 9
fi
echo "qrpc_serving_after=false"

echo "listeners_after"
ss -ltnp | grep -E ':(5622|5640|5660|5680|6030)\b' || true

echo "free_disk_after"
df -h "$HOME" "$workspace" /tmp

free_kb="$(df -Pk "$HOME" | awk 'NR==2 {print $4}')"
free_gib=$((free_kb / 1024 / 1024))
echo "free_gib_after_floor=$free_gib"
if (( free_gib < 35 )); then
  echo "cleanup did not reach required 35 GiB free floor" >&2
  exit 10
fi

echo "cleanup_complete=true"
