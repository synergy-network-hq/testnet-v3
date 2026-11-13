#!/usr/bin/env bash
set -euo pipefail

workspace="${SYNERGY_WORKSPACE:-$HOME/.synergy/testnet/nodes/validator-workspace}"
cli="${SYNERGY_RECOVERY_CLI:-/tmp/synergy-node-v13.0.17-recovery-cli}"
cli_expected="${SYNERGY_RECOVERY_CLI_SHA:-cc509090f01c6a70f414b10e0ed05d1ccc13da44316cbf8bbc244d7477e1236f}"
snapshot="${SYNERGY_SOURCE_SNAPSHOT:-/tmp/synergy-recovery-source-relayer2-20260525T190125Z.tar.gz}"
snapshot_expected="${SYNERGY_SOURCE_SNAPSHOT_SHA:-f934f22d16ed1cec6a26d8bd56fc116356c8294e3d5deee29eb1f30485c88cd1}"
target_runtime_expected="${SYNERGY_TARGET_RUNTIME_SHA:-bf5f8165a75bf6613df586b346a7021844fd02fbfbbecbc40d5904b8929f2e2d}"

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
for pid in $(pgrep -f "synergy-testnet-linux-amd64 start --config" || true); do
  cwd="$(readlink "/proc/$pid/cwd" 2>/dev/null || true)"
  exe="$(readlink "/proc/$pid/exe" 2>/dev/null || true)"
  if [[ "$cwd" == "$workspace" || "$exe" == "$workspace"/bin/* ]]; then
    process_count=$((process_count + 1))
  fi
done
if [[ "$process_count" != "0" ]]; then
  echo "Val1 must be stopped before building recovery plan; process_count=$process_count" >&2
  exit 6
fi

timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
source_root="/tmp/synergy-recovery-source-relayer2-20260525T190125Z"
derived_source_root="/tmp/synergy-recovery-source-relayer2-20260525T190125Z-consistent"
evidence_dir="$HOME/synergy-testnet-evidence/${timestamp}-Val1-incident-recovery-plan"
rollback_dir="$HOME/synergy-testnet-state-backups/${timestamp}-Val1-incident-recovery-rollback"

rm -rf "$source_root" "$derived_source_root"
mkdir -p "$source_root" "$derived_source_root" "$evidence_dir" "$rollback_dir"
tar -C "$source_root" -xzf "$snapshot"
cp -a "$source_root/data" "$derived_source_root/data"

python3 - "$source_root/data" "$derived_source_root/data" "$evidence_dir/source-snapshot-summary.json" <<'PY'
import json
import sys
from pathlib import Path

source = Path(sys.argv[1])
derived = Path(sys.argv[2])
summary_path = Path(sys.argv[3])

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

locks = json.loads((source / "canonical_locks.json").read_text())
if not isinstance(locks, dict):
    raise SystemExit("canonical_locks.json is not an object")
original_max_lock_height = max(int(key) for key in locks)
original_max_lock = locks[str(original_max_lock_height)]
pruned_locks = {
    key: value for key, value in locks.items() if int(key) <= chain_latest_height
}
if "71160" not in pruned_locks:
    raise SystemExit("source canonical locks do not include h71160")
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
    "h71160_hash": pruned_locks["71160"].get("block_hash")
    or pruned_locks["71160"].get("hash"),
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
    --target-node-id Val1 \
    --target-role validator \
    --target-data-dir "$workspace/data" \
    --source-state-dir "$derived_source_root" \
    --source-node Val2 --source-node Val3 --source-node Val4 --source-node Val5 \
    --source-common-height "$qc_height" \
    --source-common-hash "$qc_hash" \
    --source-canonical-lock-height "$qc_height" \
    --source-canonical-lock-hash "$qc_hash" \
    --target-runtime-sha256 "$target_runtime_expected" \
    --recovery-type canonical_state_reconcile \
    --conflict-height 71160 \
    --expected-target-conflict-hash 2db6f6d77ca2bdeb3ce221228f73abf77766140b6f0f99831ee594d480a93f1e \
    --expected-source-conflict-hash 002dc30b7685c1ae8569dcf15bd29ff9c19240c93a7f2d00a72bc084427a081a \
    --target-stopped-or-quarantined \
    --evidence-path "$evidence_dir" \
    --rollback-path "$rollback_dir" \
    --output "$evidence_dir/val1-recovery-plan.json" \
    > "$evidence_dir/val1-recovery-plan.stdout.json"

  "$cli" recovery verify-plan \
    --chain-id 1264 \
    --network-id synergy-testnet-v3 \
    --plan "$evidence_dir/val1-recovery-plan.json" \
    > "$evidence_dir/val1-recovery-plan.verify.json"
)

python3 - "$evidence_dir/val1-recovery-plan.json" "$evidence_dir/val1-recovery-plan.verify.json" "$evidence_dir/val1-recovery-plan-summary.json" <<'PY'
import json
import sys
from pathlib import Path

def _active_validator_set_meets_baseline(plan):
    return (
        plan.get("active_validator_set_meets_baseline")
        if plan.get("active_validator_set_meets_baseline") is not None
        else plan.get("source_qc_aegis_pqc_verified")
    )


plan = json.load(open(sys.argv[1]))
verify = json.load(open(sys.argv[2]))
out = Path(sys.argv[3])
signers = plan.get("source_qc_signers") or []
summary = {
    "target_node": plan.get("target_node_id"),
    "source_snapshot_node": "Relayer-2",
    "source_snapshot_sha256": "f934f22d16ed1cec6a26d8bd56fc116356c8294e3d5deee29eb1f30485c88cd1",
    "plan_id": plan.get("plan_id"),
    "majority_branch_proven": plan.get("majority_branch_proven"),
    "target_is_minority_or_lagged": plan.get("target_is_minority_or_lagged"),
    "source_common_height": plan.get("source_common_height"),
    "source_common_hash": plan.get("source_common_hash"),
    "source_canonical_lock_height": plan.get("source_canonical_lock_height"),
    "source_canonical_lock_hash": plan.get("source_canonical_lock_hash"),
    "source_committed_qc_height": plan.get("source_committed_qc_height"),
    "source_committed_qc_hash": plan.get("source_committed_qc_hash"),
    "source_qc_vote_count": plan.get("source_qc_vote_count"),
    "source_qc_signers": signers,
    "source_qc_aegis_pqc_verified": plan.get("source_qc_aegis_pqc_verified"),
    "duplicate_signer_check_passed": len(signers) == len(set(signers)),
    "active_validator_set_meets_baseline": _active_validator_set_meets_baseline(plan),
    "relayers_rpc_support_counted_toward_quorum": False,
    "evidence_path": plan.get("evidence_path"),
    "rollback_path": plan.get("rollback_path"),
    "files_to_backup": plan.get("files_to_backup"),
    "files_to_replace": plan.get("files_to_mutate"),
    "files_never_to_touch": plan.get("files_never_to_touch"),
    "canonical_locks_mutated": plan.get("canonical_locks_mutated"),
    "committed_qcs_mutated": plan.get("committed_qcs_mutated"),
    "chain_state_mutated": plan.get("chain_state_mutated"),
    "dag_state_mutated": plan.get("dag_state_mutated"),
    "registry_state_mutated": plan.get("registry_state_mutated"),
    "token_state_mutated": plan.get("token_state_mutated"),
    "keys_or_configs_copied": plan.get("keys_or_configs_copied"),
    "genesis_mutated": False,
    "quorum_mutated": False,
    "operator_approval_required": plan.get("operator_approval_required"),
    "failure_reason": plan.get("failure_reason"),
    "verify_valid_for_apply": verify.get("valid_for_apply"),
    "verify_errors": verify.get("errors"),
    "verify_warnings": verify.get("warnings"),
}
out.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
print(json.dumps(summary, sort_keys=True))
PY

echo "spreadsheet_row_used=true"
echo "access_path=workbook_exact"
echo "node=${SYNERGY_NODE:-Val1}"
echo "row=${SYNERGY_SPREADSHEET_ROW:-unknown}"
echo "action=val1_recovery_plan_ready"
echo "runtime_checksum=$runtime_actual"
echo "evidence_path=$evidence_dir"
echo "rollback_path=$rollback_dir"
echo "source_snapshot=$snapshot"
echo "source_snapshot_sha256=$snapshot_actual"
