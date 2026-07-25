#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage:
  scripts/testnet/archive-validator-recovery.sh status [--node "Archive Validator"] [--timeout 120] [--workbook /path/to/node-machine-credentials.xlsx] [--output <local-report.json>] [--remote-output <remote-report.json>]
  scripts/testnet/archive-validator-recovery.sh verify-canonical --manifest <manifest.json> --snapshot-root <dir> --expected-height <height> --expected-block-hash <hash> --expected-snapshot-class <class> [--allow-validator-pruned-support-snapshot] [--current-finalized-height <height>] [--output <local-report.json>] [--remote-output <remote-report.json>]
  scripts/testnet/archive-validator-recovery.sh reseed-plan --manifest <manifest.json> --snapshot-root <dir> [--current-finalized-height <height>] [--output <local-report.json>] [--remote-output <remote-plan.json>]
  scripts/testnet/archive-validator-recovery.sh reseed --plan <json> [--output <local-report.json>] [--remote-output <remote-report.json>]
  scripts/testnet/archive-validator-recovery.sh publish-snapshot --manifest <manifest.json> --snapshot-root <dir> [--unsafe-snapshot] [--current-finalized-height <height>] [--output <local-report.json>] [--remote-output <remote-report.json>]
  scripts/testnet/archive-validator-recovery.sh list-unsafe-snapshots [--inventory <inventory.json>] [--output <local-report.json>] [--remote-output <remote-report.json>]
  scripts/testnet/archive-validator-recovery.sh mark-unsafe-snapshot --snapshot-id <id> --height <height> --snapshot-class <class> --block-hash <hash> --reason <text> [--execute] [--output <local-report.json>] [--remote-output <remote-report.json>]
  scripts/testnet/archive-validator-recovery.sh quarantine-snapshot --snapshot-id <id> --height <height> --snapshot-class <class> --block-hash <hash> --reason <text> [--execute] [--output <local-report.json>] [--remote-output <remote-report.json>]

Generic archive-validator recovery helper.

This helper uses workbook-backed access via scripts/testnet/spreadsheet_host_access.py and node
names from the workbook-backed host list (default node name: Archive Validator).

Read-only phases are safe by default:
- status
- verify-canonical
- reseed-plan
- reseed (runtime dry-run only)
- publish-snapshot
- list-unsafe-snapshots

Mutation-only phases require --execute:
- mark-unsafe-snapshot
- quarantine-snapshot
USAGE
}

phase="${1:-}"
if [[ -z "$phase" || "$phase" == "--help" || "$phase" == "-h" ]]; then
  usage
  exit 0
fi
shift || true

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
access_py="$repo_root/scripts/testnet/spreadsheet_host_access.py"

node_name="Archive Validator"
workbook="/Users/devpup/Desktop/node-machine-credentials.xlsx"
timeout=120
output=""
remote_output=""
execute=false
manifest_path=""
snapshot_root=""
snapshot_id=""
snapshot_class=""
snapshot_block_hash=""
snapshot_reason="operator_reviewed_archive_snapshot"
snapshot_height=""
expected_height=""
expected_block_hash=""
expected_snapshot_class=""
current_finalized_height=""
allow_validator_pruned_support_snapshot=false
unsafe_snapshot=false
plan_path=""
inventory_path=""
chain_id=1264
network_id="synergy-testnet-v3"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --node) node_name="${2:-}"; shift 2 ;;
    --workbook) workbook="${2:-}"; shift 2 ;;
    --timeout) timeout="${2:-}"; shift 2 ;;
    --manifest) manifest_path="${2:-}"; shift 2 ;;
    --snapshot-root) snapshot_root="${2:-}"; shift 2 ;;
    --snapshot-id) snapshot_id="${2:-}"; shift 2 ;;
    --snapshot-class) snapshot_class="${2:-}"; shift 2 ;;
    --block-hash) snapshot_block_hash="${2:-}"; shift 2 ;;
    --height) snapshot_height="${2:-}"; shift 2 ;;
    --reason) snapshot_reason="${2:-}"; shift 2 ;;
    --plan) plan_path="${2:-}"; shift 2 ;;
    --inventory) inventory_path="${2:-}"; shift 2 ;;
    --remote-output) remote_output="${2:-}"; shift 2 ;;
    --expected-height) expected_height="${2:-}"; shift 2 ;;
    --expected-block-hash) expected_block_hash="${2:-}"; shift 2 ;;
    --expected-snapshot-class) expected_snapshot_class="${2:-}"; shift 2 ;;
    --current-finalized-height) current_finalized_height="${2:-}"; shift 2 ;;
    --allow-validator-pruned-support-snapshot) allow_validator_pruned_support_snapshot=true; shift ;;
    --unsafe-snapshot) unsafe_snapshot=true; shift ;;
    --output) output="${2:-}"; shift 2 ;;
    --execute) execute=true; shift ;;
    --chain-id) chain_id="${2:-}"; shift 2 ;;
    --network-id) network_id="${2:-}"; shift 2 ;;
    --help|-h) usage; exit 0 ;;
    *) echo "unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

if [[ ! -f "$workbook" ]]; then
  echo "workbook not found: $workbook" >&2
  exit 2
fi

stamp="$(date -u +%Y%m%dT%H%M%SZ)"
safe_node="$(printf "%s" "$node_name" | tr '[:space:]' '_' | tr -dc 'A-Za-z0-9._-')"
output_dir="$repo_root/outputs/archive-validator-recovery"
mkdir -p "$output_dir"
if [[ -z "$output" ]]; then
  output="$output_dir/${safe_node}-${phase}-${stamp}.json"
fi

runbook_line="$(python3 "$access_py" --workbook "$workbook" inventory --nodes "$node_name" 2>/tmp/archivex_node_inventory.err || true)"
if [[ -z "$runbook_line" ]]; then
  node_error="$(cat /tmp/archivex_node_inventory.err 2>/dev/null || true)"
  echo "missing or invalid workbook node: ${node_name}" >&2
  if [[ -n "$node_error" ]]; then
    echo "$node_error" >&2
  fi
  echo "blocker: live workbook access is unavailable for node ${node_name}" >&2
  exit 2
fi

stdout_file="$(mktemp)"
stderr_file="$(mktemp)"
trap 'rm -f "$stdout_file" "$stderr_file"' EXIT
true > "$stdout_file"
true > "$stderr_file"

run_remote() {
  local -a command_parts=("$@")
  local command_text
  command_text="$(printf '%q ' "${command_parts[@]}")"
  if [[ "${#command_parts[@]}" -eq 0 ]]; then
    echo "empty remote command" >&2
    return 2
  fi
  set +e
  python3 "$access_py" --workbook "$workbook" run "$node_name" "$command_text" --timeout "$timeout" --remote-sudo-from-workbook >"$stdout_file" 2>"$stderr_file"
  local rc=$?
  set -e
  return "$rc"
}

emit_report() {
  local phase_name="$1"
  local command_json="$2"
  local exit_code="$3"
  local blocker="$4"
  python3 - "$output" "$phase_name" "$node_name" "$workbook" "$runbook_line" "$timeout" "$chain_id" "$network_id" "$execute" "$command_json" "$exit_code" "$blocker" "$stdout_file" "$stderr_file" <<'PY'
import json
import pathlib
import sys

out_path, phase, node_name, workbook, runbook_line, timeout, chain_id, network_id, execute, command_json, exit_code, blocker, stdout_file, stderr_file = sys.argv[1:]

def _read(path):
    try:
        text = pathlib.Path(path).read_text(errors="replace")
    except FileNotFoundError:
        text = ""
    return text

stdout_text = _read(stdout_file)
stderr_text = _read(stderr_file)

report = {
    "tool": "archive-validator-recovery.sh",
    "generated_utc": __import__("datetime").datetime.utcnow().isoformat() + "Z",
    "phase": phase,
    "execute": json.loads(execute.lower()),
    "node": node_name,
    "workbook": workbook,
    "runbook_line": runbook_line,
    "chain_id": int(chain_id),
    "network_id": network_id,
    "timeout_seconds": int(timeout),
    "command": json.loads(command_json),
    "exit_code": int(exit_code),
    "remote_stdout": {
        "bytes": len(stdout_text),
        "text": stdout_text[:12000]
    },
    "remote_stderr": {
        "bytes": len(stderr_text),
        "text": stderr_text[:12000]
    },
    "ok": exit_code == 0,
    "blocker": blocker,
}
if len(stdout_text) > 12000 or len(stderr_text) > 12000:
    report["truncated"] = True

pathlib.Path(out_path).write_text(json.dumps(report, sort_keys=True, indent=2) + "\n")
print(pathlib.Path(out_path).resolve())
PY
}

require_execute() {
  local action="$1"
  if [[ "$execute" != true ]]; then
    echo "${action} requires --execute; run in read-only mode without --execute first if you want to generate evidence." >&2
    return 2
  fi
}

remote_command=()
case "$phase" in
  status)
    remote_command+=(synergy-node archive status --archive-services-disabled --snapshot-api-disabled --snapshot-worker-disabled --archive-publication-disabled --unsafe-inventory-reviewed --chain-id "$chain_id" --network-id "$network_id")
    if [[ -n "$remote_output" ]]; then
      remote_command+=(--output "$remote_output")
    fi
    ;;
  verify-canonical)
    [[ -n "$manifest_path" ]] || { echo "--manifest is required for verify-canonical" >&2; exit 2; }
    [[ -n "$snapshot_root" ]] || { echo "--snapshot-root is required for verify-canonical" >&2; exit 2; }
    [[ -n "$expected_height" ]] || { echo "--expected-height is required for verify-canonical" >&2; exit 2; }
    [[ -n "$expected_block_hash" ]] || { echo "--expected-block-hash is required for verify-canonical" >&2; exit 2; }
    [[ -n "$expected_snapshot_class" ]] || { echo "--expected-snapshot-class is required for verify-canonical" >&2; exit 2; }
    remote_command+=(synergy-node archive verify-canonical --manifest "$manifest_path" --snapshot-root "$snapshot_root" --expected-height "$expected_height" --expected-block-hash "$expected_block_hash" --expected-snapshot-class "$expected_snapshot_class" --source-canonical)
    if [[ "$allow_validator_pruned_support_snapshot" == true ]]; then
      remote_command+=(--allow-validator-pruned-support-snapshot)
    fi
    if [[ -n "$current_finalized_height" ]]; then
      remote_command+=(--current-finalized-height "$current_finalized_height")
    fi
    remote_command+=(--chain-id "$chain_id" --network-id "$network_id")
    if [[ -n "$remote_output" ]]; then
      remote_command+=(--output "$remote_output")
    fi
    ;;
  reseed-plan)
    [[ -n "$manifest_path" ]] || { echo "--manifest is required for reseed-plan" >&2; exit 2; }
    [[ -n "$snapshot_root" ]] || { echo "--snapshot-root is required for reseed-plan" >&2; exit 2; }
    remote_command+=(synergy-node archive reseed-plan --manifest "$manifest_path" --snapshot-root "$snapshot_root" --archive-services-disabled --archive-publication-disabled --unsafe-inventory-reviewed)
    if [[ -n "$current_finalized_height" ]]; then
      remote_command+=(--current-finalized-height "$current_finalized_height")
    fi
    remote_command+=(--chain-id "$chain_id" --network-id "$network_id")
    if [[ -n "$remote_output" ]]; then
      remote_command+=(--output "$remote_output")
    fi
    ;;
  reseed)
    [[ -n "$plan_path" ]] || { echo "--plan is required for reseed" >&2; exit 2; }
    if [[ "$execute" == true ]]; then
      echo "archive reseed is dry-run-only in the current runtime; refusing --execute" >&2
      exit 2
    fi
    remote_command+=(synergy-node archive reseed --plan "$plan_path" --dry-run)
    if [[ -n "$remote_output" ]]; then
      remote_command+=(--output "$remote_output")
    fi
    remote_command+=(--chain-id "$chain_id" --network-id "$network_id")
    ;;
  publish-snapshot)
    [[ -n "$manifest_path" ]] || { echo "--manifest is required for publish-snapshot" >&2; exit 2; }
    [[ -n "$snapshot_root" ]] || { echo "--snapshot-root is required for publish-snapshot" >&2; exit 2; }
    remote_command+=(synergy-node archive publish-snapshot --dry-run --manifest "$manifest_path" --snapshot-root "$snapshot_root" --snapshot-api-disabled --snapshot-worker-disabled --source-canonical)
    if [[ "$unsafe_snapshot" == true ]]; then
      remote_command+=(--unsafe-snapshot)
    fi
    if [[ -n "$current_finalized_height" ]]; then
      remote_command+=(--current-finalized-height "$current_finalized_height")
    fi
    remote_command+=(--chain-id "$chain_id" --network-id "$network_id")
    if [[ -n "$remote_output" ]]; then
      remote_command+=(--output "$remote_output")
    fi
    ;;
  list-unsafe-snapshots)
    remote_command+=(synergy-node archive list-unsafe-snapshots --chain-id "$chain_id" --network-id "$network_id")
    if [[ -n "$inventory_path" ]]; then
      remote_command+=(--inventory "$inventory_path")
    fi
    if [[ -n "$remote_output" ]]; then
      remote_command+=(--output "$remote_output")
    fi
    ;;
  mark-unsafe-snapshot|quarantine-snapshot)
    require_execute "$phase"
    [[ -n "$snapshot_id" ]] || { echo "--snapshot-id is required for ${phase}" >&2; exit 2; }
    [[ -n "$snapshot_height" ]] || { echo "--height is required for ${phase}" >&2; exit 2; }
    [[ -n "$snapshot_class" ]] || { echo "--snapshot-class is required for ${phase}" >&2; exit 2; }
    [[ -n "$snapshot_block_hash" ]] || { echo "--block-hash is required for ${phase}" >&2; exit 2; }
    [[ -n "$snapshot_reason" ]] || { echo "--reason is required for ${phase}" >&2; exit 2; }
    remote_command+=(synergy-node archive "$phase" --snapshot-id "$snapshot_id" --height "$snapshot_height" --snapshot-class "$snapshot_class" --block-hash "$snapshot_block_hash" --reason "$snapshot_reason" --chain-id "$chain_id" --network-id "$network_id")
    if [[ -n "$remote_output" ]]; then
      remote_command+=(--output "$remote_output")
    fi
    ;;
  *)
    usage
    exit 2
    ;;
esac

command_json="$(python3 - "${remote_command[@]}" <<'PY'
import json
import sys
print(json.dumps(sys.argv[1:]))
PY
)"

if run_remote "${remote_command[@]}"; then
  remote_rc=0
  blocker=""
else
  remote_rc=$?
  blocker="$(python3 - "$stderr_file" "$stdout_file" <<'PY'
import pathlib
import sys
err = pathlib.Path(sys.argv[1]).read_text(errors="replace")
out = pathlib.Path(sys.argv[2]).read_text(errors="replace")
needles = [
    "No route to host",
    "Network is unreachable",
    "Operation timed out",
    "Connection timed out",
    "Temporary failure in name resolution",
    "Could not resolve host",
    "ssh: connect to host",
]
combined = f"{err}\n{out}"
for needle in needles:
    if needle in combined:
        print(f"connectivity_blocker_detected: {needle}")
        break
else:
    for line in combined.splitlines():
        if "Permission denied" in line and "publickey" in line:
            print("connectivity_or_auth_blocked: Permission denied (publickey)")
            break
        if "refused forced password-auth" in line:
            print("connectivity_or_auth_blocked: password auth path blocked by workbook helper")
            break
PY
)"
fi

report_path="$(emit_report "$phase" "$command_json" "$remote_rc" "$blocker")"
cat "$report_path"

if [[ "$blocker" == connectivity_blocker_detected:* ]]; then
  echo "blocker: $blocker" >&2
  echo "live VPN/SSH connectivity appears blocked; no brute-force reconnect attempts were performed." >&2
fi

if [[ "$phase" == "reseed" && "$execute" == false ]]; then
  echo "reseed run was executed in runtime dry-run mode."
elif [[ "$phase" == "reseed" && "$execute" == true ]]; then
  echo "reseed --execute was refused before remote execution."
fi

if [[ "$remote_rc" -ne 0 ]]; then
  exit "$remote_rc"
fi
