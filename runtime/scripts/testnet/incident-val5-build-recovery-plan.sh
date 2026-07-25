#!/usr/bin/env bash
set -euo pipefail

workspace="${SYNERGY_WORKSPACE:-$HOME/.synergy/testnet/nodes/validator-workspace}"
cli="${SYNERGY_RECOVERY_CLI:?SYNERGY_RECOVERY_CLI is required}"
cli_expected="${SYNERGY_RECOVERY_CLI_SHA:?SYNERGY_RECOVERY_CLI_SHA is required}"
snapshot="${SYNERGY_SOURCE_SNAPSHOT:?SYNERGY_SOURCE_SNAPSHOT is required}"
snapshot_expected="${SYNERGY_SOURCE_SNAPSHOT_SHA:?SYNERGY_SOURCE_SNAPSHOT_SHA is required}"
target_runtime_expected="${SYNERGY_TARGET_RUNTIME_SHA:?SYNERGY_TARGET_RUNTIME_SHA is required}"
conflict_height="${SYNERGY_CONFLICT_HEIGHT:?SYNERGY_CONFLICT_HEIGHT is required}"
expected_target_conflict_hash="${SYNERGY_EXPECTED_TARGET_CONFLICT_HASH:?SYNERGY_EXPECTED_TARGET_CONFLICT_HASH is required}"
expected_source_conflict_hash="${SYNERGY_EXPECTED_SOURCE_CONFLICT_HASH:?SYNERGY_EXPECTED_SOURCE_CONFLICT_HASH is required}"

sha_file() {
  sha256sum "$1" | cut -d " " -f1
}

test -d "$workspace/data"
test -f "$cli"
test -f "$snapshot"

cli_actual="$(sha_file "$cli")"
if [[ "$cli_actual" != "$cli_expected" ]]; then
  echo "trusted recovery CLI checksum mismatch: $cli_actual" >&2
  exit 3
fi
chmod 700 "$cli"

snapshot_actual="$(sha_file "$snapshot")"
if [[ "$snapshot_actual" != "$snapshot_expected" ]]; then
  echo "source snapshot checksum mismatch: $snapshot_actual" >&2
  exit 4
fi

runtime_actual="$(sha_file "$workspace/bin/synergy-testnet-linux-amd64")"
if [[ "$runtime_actual" != "$target_runtime_expected" ]]; then
  echo "target runtime checksum mismatch: $runtime_actual" >&2
  exit 5
fi

process_count=0
for proc in /proc/[0-9]*; do
  pid="${proc##*/}"
  exe="$(readlink "$proc/exe" 2>/dev/null || true)"
  cwd="$(readlink "$proc/cwd" 2>/dev/null || true)"
  cmd="$(tr '\0' ' ' < "$proc/cmdline" 2>/dev/null || true)"
  if [[ "$exe" == "$workspace"/bin/* || "$cwd" == "$workspace" ]]; then
    if [[ "$cmd" == *"synergy-testnet-linux-amd64 start --config"* ]]; then
      process_count=$((process_count + 1))
    fi
  fi
done
if [[ "$process_count" != "0" ]]; then
  echo "Val5 must be stopped before building recovery plan; process_count=$process_count" >&2
  exit 6
fi

timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
source_root="/tmp/synergy-recovery-source-relayer1-h76150-${timestamp}"
derived_source_root="${source_root}-consistent"
evidence_dir="$HOME/synergy-testnet-evidence/${timestamp}-Val5-incident-recovery-plan"
rollback_dir="$HOME/synergy-testnet-state-backups/${timestamp}-Val5-incident-recovery-rollback"

rm -rf "$source_root" "$derived_source_root"
mkdir -p "$source_root" "$derived_source_root" "$evidence_dir" "$rollback_dir"
tar -C "$source_root" -xf "$snapshot"
cp -a "$source_root/data" "$derived_source_root/data"

python3 - \
  "$source_root/data" \
  "$derived_source_root/data" \
  "$evidence_dir/source-snapshot-summary.json" \
  "$conflict_height" \
  "$expected_source_conflict_hash" <<'PY'
import json
import sys
from pathlib import Path

source = Path(sys.argv[1])
derived = Path(sys.argv[2])
summary_path = Path(sys.argv[3])
conflict_height = int(sys.argv[4])
expected_source_conflict_hash = sys.argv[5]

allowed = {
    "chain.json",
    "canonical_locks.json",
    "committed_qcs.jsonl",
    "dag_state.json",
    "validator_registry.json",
    "token_state.json",
}
seen = sorted(p.name for p in source.iterdir() if p.is_file())
for name in seen:
    if name not in allowed:
        raise SystemExit(f"source snapshot contains forbidden or unexpected file: {name}")
for name in allowed:
    if not (source / name).is_file():
        raise SystemExit(f"source snapshot missing required file: {name}")

chain = json.loads((source / "chain.json").read_text())
if not chain:
    raise SystemExit("source chain.json has no blocks")
latest = chain[-1]
chain_latest_height = int(latest.get("block_index") or latest.get("height"))
chain_latest_hash = latest.get("hash") or latest.get("block_hash")
if chain_latest_height < conflict_height:
    raise SystemExit("source chain latest is below conflict height")

locks = json.loads((source / "canonical_locks.json").read_text())
if not isinstance(locks, dict):
    raise SystemExit("canonical_locks.json is not an object")
if str(conflict_height) not in locks:
    raise SystemExit(f"source canonical locks do not include h{conflict_height}")
source_conflict_hash = locks[str(conflict_height)].get("block_hash") or locks[
    str(conflict_height)
].get("hash")
if source_conflict_hash != expected_source_conflict_hash:
    raise SystemExit(
        f"source h{conflict_height} hash mismatch: {source_conflict_hash}"
    )

original_max_lock_height = max(int(key) for key in locks)
original_max_lock = locks[str(original_max_lock_height)]
pruned_locks = {
    key: value for key, value in locks.items() if int(key) <= chain_latest_height
}
(derived / "canonical_locks.json").write_text(
    json.dumps(pruned_locks, indent=2, sort_keys=True) + "\n"
)
derived_max_lock_height = max(int(key) for key in pruned_locks)
derived_max_lock = pruned_locks[str(derived_max_lock_height)]

last_qc = None
last_qc_height = None
written = 0
with (source / "committed_qcs.jsonl").open("r", encoding="utf-8") as src, (
    derived / "committed_qcs.jsonl"
).open("w", encoding="utf-8") as dst:
    for raw in src:
        line = raw.strip()
        if not line:
            continue
        entry = json.loads(line)
        qc = entry["qc"]
        heights = {int(v["block_index"]) for v in qc.get("votes", [])}
        if len(heights) != 1:
            raise SystemExit("committed QC line has votes for multiple heights")
        height = heights.pop()
        if height <= chain_latest_height:
            dst.write(json.dumps(entry, separators=(",", ":"), sort_keys=True) + "\n")
            last_qc = qc
            last_qc_height = height
            written += 1
if last_qc is None:
    raise SystemExit("derived committed_qcs.jsonl has no entries at or below chain latest")

qc_hash = last_qc.get("block_hash")
if not qc_hash:
    raise SystemExit("latest derived QC is missing block_hash")
if str(last_qc_height) not in pruned_locks:
    raise SystemExit("derived canonical locks do not include latest derived QC height")
lock_hash_at_qc = pruned_locks[str(last_qc_height)].get("block_hash") or pruned_locks[
    str(last_qc_height)
].get("hash")
if lock_hash_at_qc != qc_hash:
    raise SystemExit(
        f"derived lock hash at QC height {last_qc_height} does not match QC hash"
    )

summary = {
    "source_snapshot_excludes_forbidden_material": sorted(seen) == sorted(allowed),
    "original_chain_latest_height": chain_latest_height,
    "original_chain_latest_hash": chain_latest_hash,
    "original_canonical_lock_max_height": original_max_lock_height,
    "original_canonical_lock_max_hash": original_max_lock.get("block_hash")
    or original_max_lock.get("hash"),
    "derived_canonical_lock_max_height": derived_max_lock_height,
    "derived_canonical_lock_max_hash": derived_max_lock.get("block_hash")
    or derived_max_lock.get("hash"),
    "derived_committed_qc_height": last_qc_height,
    "derived_committed_qc_hash": qc_hash,
    "derived_committed_qc_vote_count": len(last_qc.get("votes") or []),
    "derived_committed_qc_signers": sorted(
        vote.get("validator_address") for vote in last_qc.get("votes") or []
    ),
    "derived_committed_qc_participant_bitmap": last_qc.get("participant_bitmap"),
    "derived_committed_qc_cumulative_weight": last_qc.get("cumulative_weight"),
    "conflict_height": conflict_height,
    "source_conflict_hash": source_conflict_hash,
    "derived_qc_lines_written": written,
    "derived_source_root": str(derived.parent),
}
summary_path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
print(json.dumps(summary, sort_keys=True))
PY

qc_height="$(
  python3 - "$evidence_dir/source-snapshot-summary.json" <<'PY'
import json
import sys
print(json.load(open(sys.argv[1]))["derived_committed_qc_height"])
PY
)"
qc_hash="$(
  python3 - "$evidence_dir/source-snapshot-summary.json" <<'PY'
import json
import sys
print(json.load(open(sys.argv[1]))["derived_committed_qc_hash"])
PY
)"

(
  cd "$workspace"
  "$cli" recovery build-plan \
    --chain-id 1264 \
    --network-id synergy-testnet-v3 \
    --target-node-id Val5 \
    --target-role validator \
    --target-data-dir "$workspace/data" \
    --source-state-dir "$derived_source_root" \
    --source-node Val1 --source-node Val2 --source-node Val3 --source-node Val4 \
    --source-common-height "$qc_height" \
    --source-common-hash "$qc_hash" \
    --source-canonical-lock-height "$qc_height" \
    --source-canonical-lock-hash "$qc_hash" \
    --target-runtime-sha256 "$target_runtime_expected" \
    --recovery-type canonical_state_reconcile \
    --conflict-height "$conflict_height" \
    --expected-target-conflict-hash "$expected_target_conflict_hash" \
    --expected-source-conflict-hash "$expected_source_conflict_hash" \
    --target-stopped-or-quarantined \
    --evidence-path "$evidence_dir" \
    --rollback-path "$rollback_dir" \
    --output "$evidence_dir/val5-recovery-plan.json" \
    > "$evidence_dir/val5-recovery-plan.stdout.json"

  "$cli" recovery verify-plan \
    --chain-id 1264 \
    --network-id synergy-testnet-v3 \
    --plan "$evidence_dir/val5-recovery-plan.json" \
    > "$evidence_dir/val5-recovery-plan.verify.json"
)

python3 - "$evidence_dir" "$rollback_dir" "$snapshot" "$snapshot_actual" "$cli_actual" <<'PY'
import json
import sys
from pathlib import Path

evidence = Path(sys.argv[1])
rollback = Path(sys.argv[2])
snapshot = sys.argv[3]
snapshot_sha = sys.argv[4]
cli_sha = sys.argv[5]
plan = json.loads((evidence / "val5-recovery-plan.json").read_text())
verify = json.loads((evidence / "val5-recovery-plan.verify.json").read_text())
summary = json.loads((evidence / "source-snapshot-summary.json").read_text())

def _active_validator_set_meets_baseline(plan):
    return plan.get("active_validator_set_meets_baseline", False)

out = {
    "spreadsheet_row_used": True,
    "access_path": "workbook_exact",
    "target_node": "Val5",
    "source_snapshot_node": "Relayer-1",
    "source_snapshot": snapshot,
    "source_snapshot_sha256": snapshot_sha,
    "trusted_recovery_cli_sha256": cli_sha,
    "source_common_height": plan.get("source_common_height"),
    "source_common_hash": plan.get("source_common_hash"),
    "source_canonical_lock_height": plan.get("source_canonical_lock_height"),
    "source_canonical_lock_hash": plan.get("source_canonical_lock_hash"),
    "source_conflict_height_76109_hash": summary.get("source_conflict_hash"),
    "source_committed_qc_height": summary.get("derived_committed_qc_height"),
    "source_committed_qc_hash": summary.get("derived_committed_qc_hash"),
    "source_qc_vote_count": summary.get("derived_committed_qc_vote_count"),
    "source_qc_signers": summary.get("derived_committed_qc_signers"),
    "source_qc_aegis_pqc_verified": plan.get("source_qc_aegis_pqc_verified"),
    "duplicate_signer_check_passed": plan.get("duplicate_signer_check_passed"),
    "active_validator_set_meets_baseline": _active_validator_set_meets_baseline(plan),
    "relayers_rpc_support_counted_toward_quorum": False,
    "evidence_path": str(evidence),
    "rollback_path": str(rollback),
    "valid_for_apply": verify.get("valid_for_apply"),
    "verification_errors": verify.get("errors"),
    "canonical_locks_mutated": plan.get("canonical_locks_mutated"),
    "committed_qcs_mutated": plan.get("committed_qcs_mutated"),
    "chain_state_mutated": plan.get("chain_state_mutated"),
    "dag_state_mutated": plan.get("dag_state_mutated"),
    "registry_state_mutated": plan.get("registry_state_mutated"),
    "token_state_mutated": plan.get("token_state_mutated"),
    "keys_or_configs_copied": plan.get("keys_or_configs_copied"),
    "genesis_mutated": plan.get("genesis_mutated"),
    "quorum_mutated": plan.get("quorum_mutated"),
    "exact_files_to_back_up": plan.get("files_to_backup"),
    "exact_files_to_mutate": plan.get("files_to_mutate"),
    "exact_files_never_to_touch": plan.get("files_never_to_touch"),
}
print(json.dumps(out, indent=2, sort_keys=True))
PY
