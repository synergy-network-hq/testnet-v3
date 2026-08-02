#!/usr/bin/env python3
"""State-aware, single-writer Chain 1266 operational controller.

Read-only inventory and monitoring use workbook-backed `ssh synergy-*`
aliases. Mutations are fail-closed, serialize through one local lock, reread
the full stall ledger, and require an exact desired-state manifest.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import datetime as dt
import fcntl
import hashlib
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import uuid
from dataclasses import dataclass
from typing import Any


ROOT = pathlib.Path(__file__).resolve().parents[2]
DEFAULT_FLEET = ROOT / "launch" / "CHAIN_1266_FLEET.json"
DEFAULT_INCIDENT_ROOT = ROOT / "launch" / "chain1266-incidents"
DEFAULT_DELETION_MANIFEST_ROOT = ROOT / "launch" / "chain1266-deletion-manifests"
LOCK_PATH = pathlib.Path("/tmp/synergy-chain1266-control-plane.lock")
PROMETHEUS_SAMPLE = re.compile(
    r"^(?P<name>[a-zA-Z_:][a-zA-Z0-9_:]*)(?:\{(?P<labels>[^}]*)\})?\s+(?P<value>\S+)$"
)
CORE_ROLES = {
    "validator",
    "relayer",
    "rpc_gateway",
    "explorer_indexer",
    "observer",
}
ROLE_BINARY = {
    "validator": "synergy-validator-node",
    "relayer": "synergy-relayer-node",
    "rpc_gateway": "synergy-rpc-gateway-node",
    "explorer_indexer": "synergy-indexer-and-explorer-node",
    "observer": "synergy-observer-light-node",
}
ROLE_ARTIFACT_KEY = {
    "validator": "validator_node",
    "relayer": "relayer_node",
    "rpc_gateway": "rpc_gateway_node",
    "explorer_indexer": "indexer_and_explorer_node",
    "observer": "observer_light_node",
}
P1_CONSENSUS_MODE = "coordinated_round_robin_v1"
P1_COORDINATOR_ID = "validator-1"
P1_PRODUCER_IDS = ["validator-2", "validator-3", "validator-4", "validator-5", "validator-6"]
P1_RING1_CASE_IDS = frozenset(
    {
        "canonical_val1_assignment",
        "p1_config_exactly_one_coordinator_five_producers",
        "dedicated_authenticated_consensus_ingress",
        "no_legacy_consensus_fallback",
        "strict_val2_to_val6_rotation",
        "timeout_skips_turn_not_height",
        "replacement_assignment_recovers_lagging_validator",
        "stale_producer_round_rejected",
        "coordinator_cannot_equivocate_at_height",
        "coordinator_cursor_is_durable",
        "assignment_and_block_signatures_are_durable",
        "independent_execution_of_user_transaction",
        "runtime_timeout_preserves_height",
        "coordinator_persists_committed_finality",
        "exact_finality_packages_are_anchored",
        "support_observer_verifies_without_signing",
        "user_admission_is_exact_and_deterministic",
        "fresh_reset_requires_genesis_only",
        "fresh_reset_rejects_stale_p1_finality",
        "support_roles_are_non_signing_observers",
    }
)


def fail(message: str) -> "NoReturn":
    raise SystemExit(f"chain1266-control-plane: {message}")


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def sha256(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verify_checksum_manifest(root: pathlib.Path) -> None:
    manifest = root / "SHA256SUMS"
    if not manifest.is_file():
        fail(f"checksum manifest is missing: {manifest}")
    for line in manifest.read_text().splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  (.+)", line)
        if not match:
            fail(f"malformed checksum line in {manifest}")
        expected, relative = match.groups()
        path = (root / relative).resolve()
        try:
            path.relative_to(root.resolve())
        except ValueError:
            fail(f"checksum path escapes release root: {relative}")
        if not path.is_file() or sha256(path) != expected:
            fail(f"checksum mismatch: {relative}")


def config_source_for(node: "Node", release: pathlib.Path) -> pathlib.Path:
    if node.role == "validator":
        match = re.fullmatch(r"validator-node-0([1-6])", node.id)
        if not match:
            fail(f"invalid validator node ID: {node.id}")
        return release / "config" / "validators" / f"val{match.group(1)}.toml"
    if node.role == "relayer":
        return release / "config" / "relayers" / f"{node.id}.toml"
    if node.role == "rpc_gateway":
        return release / "config" / "rpc-gateway" / "rpc-gateway.toml"
    if node.role == "explorer_indexer":
        return release / "config" / "explorer-indexer" / "explorer-indexer.toml"
    if node.role == "observer":
        return release / "config" / "observer" / "observer.toml"
    fail(f"node {node.id} is not a staged Chain 1266 role")


def validate_promotable_release(
    root: pathlib.Path,
    desired_signature: pathlib.Path,
    consensus_activation: pathlib.Path,
) -> dict[str, Any]:
    root = root.resolve()
    release = root / "release"
    ring1 = root / "qualification" / "ring1"
    # P1 launches after the deterministic Ring-1 proof.  The required 5,000
    # block real-host soak is an operational post-launch gate, never a
    # fabricated pre-launch report or a local substitute for the live fleet.
    for target in (root, release, ring1):
        verify_checksum_manifest(target)
    qualification = json.loads((root / "release-qualification.json").read_text())
    report1 = json.loads((ring1 / "report.json").read_text())
    desired_path = release / "desired-state.json"
    desired = json.loads(desired_path.read_text())
    release_id = desired.get("release_id", "")
    p1 = report1.get("p1_invariants", {})
    desired_p1 = desired.get("state", {})
    if (
        qualification.get("result") not in {"LAUNCH_READY", "PROMOTABLE"}
        or qualification.get("public_deployment_authorized") is not True
        or report1.get("result") != "PASS"
        or report1.get("consensus_mode") != P1_CONSENSUS_MODE
        or report1.get("cases_passed") != len(P1_RING1_CASE_IDS)
        or report1.get("cases_total") != len(P1_RING1_CASE_IDS)
        or frozenset(report1.get("case_ids", [])) != P1_RING1_CASE_IDS
        or p1.get("coordinator_id") != P1_COORDINATOR_ID
        or p1.get("producer_ids") != P1_PRODUCER_IDS
        or any(
            p1.get(field) is not True
            for field in (
                "val1_is_not_a_normal_producer",
                "timeout_skips_producer_turn_not_height",
                "assignment_and_commit_signatures_required",
                "all_validators_execute_identically",
                "legacy_posy_qc_vc_tc_vote_aggregation_disabled",
                "durable_signing_and_restart_replay",
                "fresh_reset_requires_block_zero_genesis",
                "support_roles_verify_without_signing",
            )
        )
        or desired.get("chain", {}).get("chain_id") != 1266
        or desired["chain"].get("incarnation") != 4
        or desired_p1.get("mode") != P1_CONSENSUS_MODE
        or desired_p1.get("coordinator_id") != P1_COORDINATOR_ID
        or desired_p1.get("producer_ids") != P1_PRODUCER_IDS
        or desired_p1.get("producer_turn_timeout_ms") != 4_000
        or qualification.get("consensus_mode") != P1_CONSENSUS_MODE
        or qualification.get("genesis_hash") != desired["chain"].get("genesis_hash")
        or qualification.get("desired_state_sha256") != sha256(desired_path)
        or not re.fullmatch(r"chain1266-incarnation-4-rc[0-9]+", release_id)
    ):
        fail("release has not passed the immutable Genesis, authorization, and Ring-1 launch gate")
    if not desired_signature.is_file():
        fail("Governance desired-state signature is missing")
    if not consensus_activation.is_file():
        fail("signed immutable-Genesis consensus activation is missing")
    verifier = release / "bin" / "verify-chain1266-release-authorization"
    result = subprocess.run(
        [
            str(verifier),
            "--desired-state",
            str(desired_path),
            "--desired-state-signature",
            str(desired_signature),
            "--consensus-activation",
            str(consensus_activation),
            "--genesis",
            str(release / "genesis.json"),
        ],
        text=True,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        fail(f"Governance desired-state signature rejected: {result.stderr.strip()}")
    return {
        "root": root,
        "release": release,
        "desired_path": desired_path,
        "desired": desired,
        "desired_signature": desired_signature.resolve(),
        "consensus_activation": consensus_activation.resolve(),
        "qualification": qualification,
        "ring1": report1,
    }


@dataclass(frozen=True)
class Node:
    id: str
    role: str
    ssh_alias: str
    service: str
    metrics_url: str
    config_path: str
    genesis_path: str
    state_root: str
    legacy_service: str = ""


class Controller:
    def __init__(self, fleet_path: pathlib.Path) -> None:
        self.fleet_path = fleet_path
        self.fleet = json.loads(fleet_path.read_text())
        if (
            self.fleet.get("schema_version") != 1
            or self.fleet.get("chain_id") != 1266
            or self.fleet.get("chain_incarnation") != 4
        ):
            fail("fleet is outside Chain 1266 incarnation 4")
        expected = self.fleet.get("genesis_hash", "")
        if not re.fullmatch(r"[a-f0-9]{64}", expected):
            fail("fleet has no canonical incarnation-4 Genesis hash")
        self.nodes = [Node(**record) for record in self.fleet["nodes"]]
        self.wipe_roots = self.fleet.get("wipe_roots", {})
        if set(self.wipe_roots) != {node.id for node in self.nodes}:
            fail("fleet wipe roots do not cover the exact role inventory")
        aliases = {node.ssh_alias for node in self.nodes}
        if any(not alias.startswith("synergy-") for alias in aliases):
            fail("fleet contains a non-workbook SSH alias")
        ssh = self.fleet["ssh"]
        # The fleet file carries the portable default.  Operators may relocate
        # only the local ControlMaster socket when their workstation's default
        # temporary volume is constrained; this never changes a remote target
        # or permits bypassing the workbook-backed aliases above.
        control_path = os.environ.get("CHAIN1266_SSH_CONTROL_PATH", ssh["control_path"])
        self.ssh_options = [
            "-o",
            "BatchMode=yes" if ssh["batch_mode"] else "BatchMode=no",
            "-o",
            f"ConnectTimeout={ssh['connect_timeout_seconds']}",
            "-o",
            "ControlMaster=auto",
            "-o",
            f"ControlPersist={ssh['control_persist_seconds']}",
            "-o",
            f"ControlPath={control_path}",
        ]
        self.stall_log = ROOT / self.fleet["stall_log"]

    def ssh(self, node: Node, script: str, timeout: int = 30) -> subprocess.CompletedProcess[str]:
        command = ["ssh", *self.ssh_options, node.ssh_alias, "bash", "-s"]
        return subprocess.run(
            command,
            input=script,
            text=True,
            capture_output=True,
            timeout=timeout,
            check=False,
        )

    def collect(self, node: Node, include_logs: bool = False) -> dict[str, Any]:
        metrics = node.metrics_url or "-"
        config = node.config_path or "-"
        genesis = node.genesis_path or "-"
        log_lines = 250 if include_logs else 0
        script = f"""set -u
service={json.dumps(node.service)}
metrics={json.dumps(metrics)}
config={json.dumps(config)}
genesis={json.dumps(genesis)}
printf 'SECTION=SYSTEMD\\n'
systemctl show "$service" --no-pager \
  --property=ActiveState,SubState,MainPID,NRestarts,ExecMainStatus,MemoryCurrent,CPUUsageNSec 2>&1 || true
pid="$(systemctl show "$service" --property=MainPID --value 2>/dev/null || true)"
if [[ "$pid" =~ ^[1-9][0-9]*$ && -e "/proc/$pid/exe" ]]; then
  printf 'ExecutablePath=%s\\n' "$(readlink -f "/proc/$pid/exe")"
  printf 'ExecutableSHA256=%s\\n' "$(sha256sum "/proc/$pid/exe" | awk '{{print $1}}')"
fi
[[ "$config" != - && -f "$config" ]] && printf 'ConfigSHA256=%s\\n' "$(sha256sum "$config" | awk '{{print $1}}')"
[[ "$genesis" != - && -f "$genesis" ]] && printf 'GenesisSHA256=%s\\n' "$(sha256sum "$genesis" | awk '{{print $1}}')"
printf 'SECTION=METRICS\\n'
[[ "$metrics" != - ]] && curl --fail --silent --max-time 3 "$metrics" 2>&1 || true
printf '\\nSECTION=JOURNAL\\n'
if (( {log_lines} > 0 )); then
  journalctl -u "$service" --no-pager -n {log_lines} -o short-iso-precise 2>&1 || true
fi
printf '\\nSECTION=FAULTS\\n'
journalctl -u "$service" --since '-15 seconds' --no-pager -o cat 2>/dev/null \
  | grep -Ei 'signing.{0,40}(conflict|equivocation)|prepared.{0,40}(source conflict|candidate conflict)|mailbox.{0,30}(overflow|full)|chain.{0,20}incarnation.{0,20}mismatch|genesis.{0,20}mismatch' \
  | tail -n 20 || true
"""
        started = time.monotonic()
        try:
            result = self.ssh(node, script, timeout=35)
            raw = result.stdout
            error = result.stderr.strip()
            return {
                "node_id": node.id,
                "role": node.role,
                "ssh_alias": node.ssh_alias,
                "service": node.service,
                "collected_utc": utc_now(),
                "duration_seconds": round(time.monotonic() - started, 3),
                "ssh_exit": result.returncode,
                "ssh_error": error,
                "raw": raw,
                "parsed": parse_snapshot(raw),
            }
        except subprocess.TimeoutExpired:
            return {
                "node_id": node.id,
                "role": node.role,
                "ssh_alias": node.ssh_alias,
                "service": node.service,
                "collected_utc": utc_now(),
                "duration_seconds": round(time.monotonic() - started, 3),
                "ssh_exit": 124,
                "ssh_error": "collection timeout",
                "raw": "",
                "parsed": {},
            }

    def collect_all(self, include_logs: bool = False) -> list[dict[str, Any]]:
        # Multiple logical services on one host share one ControlMaster socket.
        # This remains one persistent workbook-backed connection per machine.
        with concurrent.futures.ThreadPoolExecutor(max_workers=6) as executor:
            futures = [executor.submit(self.collect, node, include_logs) for node in self.nodes]
            return [future.result() for future in futures]

    def append_incident(self, incident: dict[str, Any], bundle: pathlib.Path) -> None:
        # The complete ledger is read before append so every intervention is
        # informed by all prior stalls, as required by the operating directive.
        previous = self.stall_log.read_text()
        if not previous.strip():
            fail("stall ledger is unexpectedly empty")
        lines = [
            "",
            f"## Incident {incident['incident_id']} — {incident['detected_utc']}",
            "",
            f"- Operational state: `{incident['operational_state']}`",
            f"- Chain: `1266`, incarnation: `4`",
            f"- Trigger(s): {', '.join(f'`{item}`' for item in incident['triggers'])}",
            f"- Common/min/max finalized height: `{incident['height']['common']}` / "
            f"`{incident['height']['minimum']}` / `{incident['height']['maximum']}`",
            f"- Responsible/affected node(s): "
            f"{', '.join(f'`{item}`' for item in incident['affected_nodes']) or '`unresolved`'}",
            f"- Automatic action: compact read-only evidence capture; no validator mutation",
            f"- Outcome: `{incident['status']}`",
            f"- Evidence bundle: `{bundle}`",
            "",
        ]
        with self.stall_log.open("a") as handle:
            handle.write("\n".join(lines))

    def capture_incident(
        self,
        triggers: list[str],
        snapshots: list[dict[str, Any]] | None = None,
        state: str = "DEGRADED",
    ) -> pathlib.Path:
        snapshots = snapshots or self.collect_all(include_logs=True)
        if snapshots and not any("SECTION=JOURNAL" in item.get("raw", "") for item in snapshots):
            snapshots = self.collect_all(include_logs=True)
        incident_id = (
            dt.datetime.now(dt.timezone.utc).strftime("chain1266-%Y%m%dT%H%M%SZ-")
            + uuid.uuid4().hex[:8]
        )
        bundle = DEFAULT_INCIDENT_ROOT / incident_id
        bundle.mkdir(parents=True, exist_ok=False)
        validators = [item for item in snapshots if item["role"] == "validator"]
        heights = [
            int(item["parsed"].get("metrics", {}).get("consensus_finalized_height", 0))
            for item in validators
        ]
        affected = sorted(
            {
                item["node_id"]
                for item in snapshots
                if item["ssh_exit"] != 0
                or item["parsed"].get("systemd", {}).get("ActiveState") != "active"
                or float(
                    item["parsed"].get("metrics", {}).get("consensus_current_round", 0)
                )
                > 0
            }
            | {
                trigger.rsplit(":", 1)[1]
                for trigger in triggers
                if ":" in trigger
                and any(trigger.endswith(f":{item['node_id']}") for item in snapshots)
            }
        )
        common = heights[0] if heights and len(set(heights)) == 1 else None
        incident = {
            "schema_version": 1,
            "incident_id": incident_id,
            "detected_utc": utc_now(),
            "operational_state": state,
            "triggers": triggers,
            "chain": {
                "chain_id": 1266,
                "incarnation": 4,
                "genesis_hash": self.fleet["genesis_hash"],
            },
            "height": {
                "common": common,
                "minimum": min(heights, default=0),
                "maximum": max(heights, default=0),
            },
            "affected_nodes": affected,
            "actions": [
                {
                    "action": "READ_ONLY_COMPACT_EVIDENCE_CAPTURE",
                    "outcome": "COMPLETE",
                    "utc": utc_now(),
                }
            ],
            "status": "OPEN",
            "snapshots": [
                {key: value for key, value in item.items() if key != "raw"} for item in snapshots
            ],
        }
        (bundle / "incident.json").write_text(json.dumps(incident, indent=2, sort_keys=True) + "\n")
        for item in snapshots:
            (bundle / f"{item['node_id']}.txt").write_text(item.get("raw", ""))
        checksum_lines = []
        for path in sorted(bundle.iterdir()):
            checksum_lines.append(f"{sha256(path)}  {path.name}")
        (bundle / "SHA256SUMS").write_text("\n".join(checksum_lines) + "\n")
        self.append_incident(incident, bundle)
        return bundle

    def require_mutation_authority(self, desired_state: pathlib.Path) -> dict[str, Any]:
        # Lock first, then reread the entire ledger before any remote mutation.
        self._lock_handle = LOCK_PATH.open("a+")
        try:
            fcntl.flock(self._lock_handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            fail("another Chain 1266 writer holds the incident-command lock")
        ledger = self.stall_log.read_text()
        if not ledger.strip():
            fail("full stall ledger cannot be read")
        desired = json.loads(desired_state.read_text())
        if (
            desired.get("chain", {}).get("chain_id") != 1266
            or desired["chain"].get("incarnation") != 4
            or desired["chain"].get("genesis_hash") != self.fleet["genesis_hash"]
        ):
            fail("desired state disagrees with the canonical fleet identity")
        return desired

    def append_operation(
        self, operation: str, release_id: str, outcomes: list[dict[str, Any]]
    ) -> None:
        previous = self.stall_log.read_text()
        if not previous.strip():
            fail("full stall ledger cannot be read before operation logging")
        lines = [
            "",
            f"## Controlled operation — {utc_now()}",
            "",
            f"- Operation: `{operation}`",
            f"- Release: `{release_id}`",
            "- Chain: `1266`, incarnation: `4`",
        ]
        for outcome in outcomes:
            lines.append(
                f"- `{outcome['node_id']}`: `{outcome['result']}`"
                + (f" — {outcome['detail']}" if outcome.get("detail") else "")
            )
        lines.append("")
        with self.stall_log.open("a") as handle:
            handle.write("\n".join(lines) + "\n")

    def record_ring2_real_host_qualification_start(self, release_id: str) -> None:
        if not re.fullmatch(r"chain1266-incarnation-4-rc[0-9]+", release_id):
            fail("Ring-2 qualification release ID is invalid")
        self._lock_handle = LOCK_PATH.open("a+")
        try:
            fcntl.flock(self._lock_handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            fail("another Chain 1266 writer holds the incident-command lock")
        if not self.stall_log.read_text().strip():
            fail("full stall ledger cannot be read before Ring-2 qualification")
        validators = [node for node in self.nodes if node.role == "validator"]
        if len(validators) != 6:
            fail("fleet does not contain exactly six validator hosts")
        outcomes = []
        for node in validators:
            services = [node.service]
            if node.legacy_service and node.legacy_service not in services:
                services.append(node.legacy_service)
            quoted = " ".join(json.dumps(service) for service in services)
            result = self.ssh(
                node,
                f"""set -eu
services=({quoted})
for service in "${{services[@]}}"; do
  state="$(systemctl is-active "$service" 2>/dev/null || true)"
  [[ "$state" != active && "$state" != activating ]]
  printf 'canonical_service=%s state=%s\\n' "$service" "$state"
done
""",
            )
            outcomes.append(
                {
                    "node_id": node.id,
                    "result": "PASS" if result.returncode == 0 else "FAIL",
                    "detail": (result.stdout + result.stderr).strip()[-2000:],
                }
            )
        if any(outcome["result"] != "PASS" for outcome in outcomes):
            fail("a canonical validator service is active; refuse private Ring-2 qualification")
        self.append_operation("RING2_REAL_HOST_QUALIFICATION_BEGIN", release_id, outcomes)

    def mutate(self, node: Node, script: str, timeout: int = 120) -> dict[str, Any]:
        result = self.ssh(node, script, timeout=timeout)
        return {
            "node_id": node.id,
            "result": "PASS" if result.returncode == 0 else "FAIL",
            "detail": (result.stdout + result.stderr).strip()[-2000:],
            "exit": result.returncode,
        }

    def stop_for_reset(self, release_id: str) -> None:
        outcomes = []
        for node in self.nodes:
            services = [node.service]
            if node.legacy_service and node.legacy_service not in services:
                services.append(node.legacy_service)
            quoted = " ".join(json.dumps(service) for service in services)
            outcome = self.mutate(
                node,
                f"""set -euo pipefail
services=({quoted})
for service in "${{services[@]}}"; do
  sudo -n systemctl stop "$service" 2>/dev/null || true
done
for service in "${{services[@]}}"; do
  state="$(systemctl is-active "$service" 2>/dev/null || true)"
  [[ "$state" != active && "$state" != activating ]] || {{
    echo "$service did not stop" >&2
    exit 1
  }}
done
echo CHAIN1266_ROLE_STOPPED
""",
            )
            outcomes.append(outcome)
            if outcome["exit"] != 0:
                self.append_operation("STOP_FOR_FULL_RESET_FAILED", release_id, outcomes)
                fail(f"failed to stop {node.id}: {outcome['detail']}")
        self.append_operation("STOP_FOR_FULL_RESET", release_id, outcomes)

    def dry_run_wipe(self, release_id: str) -> pathlib.Path:
        """Record the exact public-reset scope without deleting any node state."""
        manifest_nodes: list[dict[str, Any]] = []
        for node in self.nodes:
            roots = list(dict.fromkeys(self.wipe_roots[node.id]))
            if node.state_root not in roots:
                fail(f"wipe roots omit canonical state root for {node.id}")
            for root in roots:
                path = pathlib.PurePosixPath(root)
                if (
                    not path.is_absolute()
                    or ".." in path.parts
                    or not root.startswith(("/var/lib/synergy", "/var/cache/synergy"))
                    or path.name not in {"data", "cache", "chain", "snapshots"}
                ):
                    fail(f"unsafe exact wipe root for {node.id}: {root}")
            quoted_roots = " ".join(json.dumps(root) for root in roots)
            services = [node.service]
            if node.legacy_service and node.legacy_service not in services:
                services.append(node.legacy_service)
            quoted_services = " ".join(json.dumps(service) for service in services)
            script = f"""set -euo pipefail
roots=({quoted_roots})
services=({quoted_services})
for service in "${{services[@]}}"; do
  state="$(systemctl is-active "$service" 2>/dev/null || true)"
  [[ "$state" != active && "$state" != activating ]] || {{
    echo "refusing deletion manifest while $service is active" >&2
    exit 1
  }}
done
for root in "${{roots[@]}}"; do
  case "$root" in
    /var/lib/synergy*/data|/var/lib/synergy*/cache|/var/lib/synergy*/chain|/var/lib/synergy*/snapshots|\\
    /var/cache/synergy*/data|/var/cache/synergy*/cache|/var/cache/synergy*/chain|/var/cache/synergy*/snapshots) ;;
    *) echo "unsafe exact Chain 1266 wipe root: $root" >&2; exit 1 ;;
  esac
  if [[ -d "$root" ]]; then
    protected="$(sudo -n find "$root" -xdev -type f \\
      \\( -iname '*.key' -o -iname '*private*' -o -iname '*identity*' \\
         -o -iname '*credential*' -o -iname '*custody*' -o -iname '*wireguard*' \\
         -o -iname '*innernet*' \\) -print -quit)"
    [[ -z "$protected" ]] || {{
      echo "protected material would be in deletion scope: $protected" >&2
      exit 1
    }}
    entries="$(sudo -n find "$root" -xdev -mindepth 1 -maxdepth 1 -print | wc -l | tr -d ' ')"
    bytes="$(sudo -n du -sk "$root" | awk '{{print $1 * 1024}}')"
    printf 'ROOT=%s\\tEXISTS=true\\tENTRIES=%s\\tBYTES=%s\\n' "$root" "$entries" "$bytes"
  elif [[ -e "$root" ]]; then
    echo "wipe target exists but is not a directory: $root" >&2
    exit 1
  else
    printf 'ROOT=%s\\tEXISTS=false\\tENTRIES=0\\tBYTES=0\\n' "$root"
  fi
done
"""
            result = self.ssh(node, script, timeout=90)
            if result.returncode != 0:
                fail(
                    f"cannot prepare deletion manifest for {node.id}: "
                    f"{(result.stdout + result.stderr).strip()[-2000:]}"
                )
            targets = []
            for line in result.stdout.splitlines():
                match = re.fullmatch(
                    r"ROOT=(.+)\\tEXISTS=(true|false)\\tENTRIES=([0-9]+)\\tBYTES=([0-9]+)",
                    line,
                )
                if not match:
                    fail(f"malformed deletion-manifest row from {node.id}: {line!r}")
                root, exists, entries, bytes_on_disk = match.groups()
                if root not in roots:
                    fail(f"deletion manifest returned an unexpected root for {node.id}: {root}")
                targets.append(
                    {
                        "root": root,
                        "exists": exists == "true",
                        "top_level_entries": int(entries),
                        "bytes_on_disk": int(bytes_on_disk),
                    }
                )
            if {item["root"] for item in targets} != set(roots):
                fail(f"deletion manifest did not cover every exact root for {node.id}")
            manifest_nodes.append({"node_id": node.id, "targets": targets})
        manifest = {
            "schema_version": 1,
            "result": "DRY_RUN_ONLY",
            "created_utc": utc_now(),
            "release_id": release_id,
            "chain": {"chain_id": 1266, "incarnation": 4},
            "deletion_scope": "chain-derived state only; protected material excluded",
            "nodes": manifest_nodes,
        }
        DEFAULT_DELETION_MANIFEST_ROOT.mkdir(parents=True, exist_ok=True)
        manifest_path = DEFAULT_DELETION_MANIFEST_ROOT / f"{release_id}-{int(time.time())}.json"
        manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
        manifest_path.with_suffix(".json.sha256").write_text(
            f"{sha256(manifest_path)}  {manifest_path.name}\n"
        )
        return manifest_path

    def validate_wipe_manifest(self, release_id: str, manifest_path: pathlib.Path) -> None:
        try:
            manifest = json.loads(manifest_path.read_text())
        except (OSError, json.JSONDecodeError) as error:
            fail(f"read deletion manifest {manifest_path}: {error}")
        if (
            manifest.get("schema_version") != 1
            or manifest.get("result") != "DRY_RUN_ONLY"
            or manifest.get("release_id") != release_id
            or manifest.get("chain") != {"chain_id": 1266, "incarnation": 4}
        ):
            fail("deletion manifest does not bind this exact Chain 1266 release")
        expected = {
            (node.id, root)
            for node in self.nodes
            for root in dict.fromkeys(self.wipe_roots[node.id])
        }
        supplied = {
            (node.get("node_id"), target.get("root"))
            for node in manifest.get("nodes", [])
            for target in node.get("targets", [])
        }
        if supplied != expected:
            fail("deletion manifest scope differs from the exact fleet wipe roots")

    def wipe_all_chain_state(self, release_id: str, deletion_manifest: pathlib.Path) -> None:
        self.validate_wipe_manifest(release_id, deletion_manifest)
        outcomes = []
        for node in self.nodes:
            roots = list(dict.fromkeys(self.wipe_roots[node.id]))
            if node.state_root not in roots:
                fail(f"wipe roots omit canonical state root for {node.id}")
            for root in roots:
                path = pathlib.PurePosixPath(root)
                if (
                    not path.is_absolute()
                    or ".." in path.parts
                    or not root.startswith(("/var/lib/synergy", "/var/cache/synergy"))
                    or path.name not in {"data", "cache", "chain", "snapshots"}
                ):
                    fail(f"unsafe exact wipe root for {node.id}: {root}")
            quoted_roots = " ".join(json.dumps(root) for root in roots)
            outcome = self.mutate(
                node,
                f"""set -euo pipefail
state={json.dumps(node.state_root)}
roots=({quoted_roots})
for service in {json.dumps(node.service)} {json.dumps(node.legacy_service or node.service)}; do
  service_state="$(systemctl is-active "$service" 2>/dev/null || true)"
  [[ "$service_state" != active && "$service_state" != activating ]] || {{
    echo "$service is not stopped" >&2
    exit 1
  }}
done
for root in "${{roots[@]}}"; do
  case "$root" in
    /var/lib/synergy*/data|/var/lib/synergy*/cache|/var/lib/synergy*/chain|/var/lib/synergy*/snapshots|\
    /var/cache/synergy*/data|/var/cache/synergy*/cache|/var/cache/synergy*/chain|/var/cache/synergy*/snapshots) ;;
    *) echo "unsafe exact Chain 1266 wipe root: $root" >&2; exit 1 ;;
  esac
  if [[ -d "$root" ]]; then
    protected="$(sudo -n find "$root" -xdev -type f \
      \\( -iname '*.key' -o -iname '*private*' -o -iname '*identity*' \
         -o -iname '*credential*' -o -iname '*custody*' -o -iname '*wireguard*' \
         -o -iname '*innernet*' \\) -print -quit)"
    [[ -z "$protected" ]] || {{
      echo "refusing to delete protected material under $root: $protected" >&2
      exit 1
    }}
    sudo -n find "$root" -mindepth 1 -maxdepth 1 -exec rm -rf -- {{}} +
  fi
done
sudo -n install -d -m 0700 "$state"
sudo -n touch "$state/.reset_flag"
remaining="$(sudo -n find "$state" -mindepth 1 -maxdepth 1 ! -name .reset_flag -print -quit)"
[[ -z "$remaining" ]] || {{
  echo "state root is not empty after reset" >&2
  exit 1
}}
echo CHAIN1266_ALL_CHAIN_DERIVED_STATE_WIPED
""",
            )
            outcomes.append(outcome)
            if outcome["exit"] != 0:
                self.append_operation("WIPE_ALL_CHAIN_STATE_FAILED", release_id, outcomes)
                fail(f"failed to wipe {node.id}: {outcome['detail']}")
        self.append_operation("WIPE_ALL_CHAIN_STATE", release_id, outcomes)

    def stage_node(
        self,
        node: Node,
        validated: dict[str, Any],
    ) -> dict[str, Any]:
        if node.role not in CORE_ROLES:
            return {"node_id": node.id, "result": "SKIP", "detail": "non-runtime role", "exit": 0}
        release: pathlib.Path = validated["release"]
        desired = validated["desired"]
        release_id = desired["release_id"]
        binary_name = ROLE_BINARY[node.role]
        artifact_key = ROLE_ARTIFACT_KEY[node.role]
        binary = release / "bin" / binary_name
        config = config_source_for(node, release)
        genesis = release / "genesis.json"
        expected_binary = desired["artifacts"][artifact_key]
        expected_config = desired["configuration"][node.id]
        if (
            not binary.is_file()
            or not config.is_file()
            or sha256(binary) != expected_binary
            or sha256(config) != expected_config
        ):
            fail(f"local staged inputs disagree with desired state for {node.id}")
        project_root = str(pathlib.PurePosixPath(node.state_root).parent)
        remote_release = f"/opt/synergy/chain1266/releases/{release_id}"
        with tempfile.TemporaryDirectory(prefix=f"chain1266-{node.id}-") as temporary:
            payload = pathlib.Path(temporary) / "payload"
            (payload / "bin").mkdir(parents=True)
            (payload / "systemd").mkdir()
            shutil.copy2(binary, payload / "bin" / binary_name)
            shutil.copy2(config, payload / "config.toml")
            shutil.copy2(genesis, payload / "genesis.json")
            shutil.copy2(validated["desired_path"], payload / "desired-state.json")
            shutil.copy2(
                validated["desired_signature"], payload / "desired-state.signature.json"
            )
            shutil.copy2(
                validated["consensus_activation"], payload / "consensus-activation.json"
            )
            shutil.copy2(
                release / "systemd" / "synergy-chain1266-role@.service",
                payload / "systemd" / "synergy-chain1266-role@.service",
            )
            shutil.copy2(
                release / "systemd" / "chain1266-role-service",
                payload / "systemd" / "chain1266-role-service",
            )
            environment = [
                f"CHAIN1266_ROLE_BINARY={remote_release}/bin/{binary_name}",
                f"CHAIN1266_ROLE_CONFIG={node.config_path}",
                f"SYNERGY_PROJECT_ROOT={project_root}",
                f"SYNERGY_DATA_PATH={node.state_root}",
                f"SYNERGY_GENESIS_FILE={node.genesis_path}",
                f"SYNERGY_DESIRED_STATE_MANIFEST={remote_release}/desired-state.json",
                f"SYNERGY_DESIRED_STATE_MANIFEST_SHA256={sha256(validated['desired_path'])}",
                f"SYNERGY_DESIRED_STATE_SIGNATURE={remote_release}/desired-state.signature.json",
                f"SYNERGY_CONSENSUS_ACTIVATION_MANIFEST={remote_release}/consensus-activation.json",
                "SYNERGY_ENABLE_METRICS=true",
            ]
            if node.role == "validator":
                environment.extend(
                    [
                        "CONSENSUS_START_PAUSED=1",
                        "SYNERGY_CONSENSUS_START_RELEASE_FILE=/etc/synergy/chain1266/start-consensus.json",
                        "SYNERGY_VALIDATOR_MLDSA65_CONSENSUS_PRIVATE_KEY_FILE=/var/lib/synergy/validator/config/validator/mldsa65-consensus.private.key",
                    ]
                )
            (payload / "node.env").write_text("\n".join(environment) + "\n")
            metadata = {
                "release_id": release_id,
                "node_id": node.id,
                "binary_sha256": expected_binary,
                "config_sha256": expected_config,
                "genesis_sha256": sha256(genesis),
                "desired_state_sha256": sha256(validated["desired_path"]),
                "desired_state_signature_sha256": sha256(validated["desired_signature"]),
                "consensus_activation_sha256": sha256(validated["consensus_activation"]),
            }
            (payload / "metadata.json").write_text(
                json.dumps(metadata, sort_keys=True) + "\n"
            )
            archive = pathlib.Path(temporary) / f"{node.id}.tar"
            with tarfile.open(archive, "w") as handle:
                handle.add(payload, arcname="payload")
            remote_archive = f"/tmp/chain1266-{release_id}-{node.id}.tar"
            copy = subprocess.run(
                ["scp", *self.ssh_options, str(archive), f"{node.ssh_alias}:{remote_archive}"],
                text=True,
                capture_output=True,
                check=False,
                timeout=120,
            )
            if copy.returncode != 0:
                return {
                    "node_id": node.id,
                    "result": "FAIL",
                    "detail": copy.stderr.strip(),
                    "exit": copy.returncode,
                }
            script = f"""set -euo pipefail
archive={json.dumps(remote_archive)}
release_id={json.dumps(release_id)}
node_id={json.dumps(node.id)}
release_dir={json.dumps(remote_release)}
staging="/opt/synergy/chain1266/releases/.staging-${{release_id}}-${{node_id}}"
config_path={json.dumps(node.config_path)}
genesis_path={json.dumps(node.genesis_path)}
project_root={json.dumps(project_root)}
state_root={json.dumps(node.state_root)}
sudo -n rm -rf -- "$staging"
sudo -n install -d -m 0755 "$staging"
sudo -n tar -xf "$archive" -C "$staging" --strip-components=1
metadata="$staging/metadata.json"
[[ "$(jq -er .release_id "$metadata")" == "$release_id" ]]
[[ "$(jq -er .node_id "$metadata")" == "$node_id" ]]
[[ "$(sha256sum "$staging/bin/{binary_name}" | awk '{{print $1}}')" == "$(jq -er .binary_sha256 "$metadata")" ]]
[[ "$(sha256sum "$staging/config.toml" | awk '{{print $1}}')" == "$(jq -er .config_sha256 "$metadata")" ]]
[[ "$(sha256sum "$staging/genesis.json" | awk '{{print $1}}')" == "$(jq -er .genesis_sha256 "$metadata")" ]]
[[ "$(sha256sum "$staging/desired-state.json" | awk '{{print $1}}')" == "$(jq -er .desired_state_sha256 "$metadata")" ]]
[[ "$(sha256sum "$staging/consensus-activation.json" | awk '{{print $1}}')" == "$(jq -er .consensus_activation_sha256 "$metadata")" ]]
if [[ -e "$release_dir" ]]; then
  echo "immutable release directory already exists" >&2
  exit 1
fi
sudo -n mv "$staging" "$release_dir"
sudo -n chmod 0755 "$release_dir/bin/{binary_name}" "$release_dir/systemd/chain1266-role-service"
sudo -n install -d -m 0755 "$(dirname "$config_path")" "$(dirname "$genesis_path")" "$project_root/config" "$state_root"
sudo -n install -m 0644 "$release_dir/config.toml" "$config_path"
sudo -n install -m 0644 "$release_dir/config.toml" "$project_root/config/node_config.toml"
sudo -n install -m 0644 "$release_dir/genesis.json" "$genesis_path"
sudo -n install -m 0644 "$release_dir/genesis.json" "$project_root/config/genesis.json"
sudo -n install -d -m 0755 /usr/local/libexec/synergy /etc/synergy/chain1266
sudo -n install -m 0755 "$release_dir/systemd/chain1266-role-service" /usr/local/libexec/synergy/chain1266-role-service
sudo -n install -m 0644 "$release_dir/systemd/synergy-chain1266-role@.service" /etc/systemd/system/synergy-chain1266-role@.service
sudo -n install -m 0600 "$release_dir/node.env" "/etc/synergy/chain1266/${{node_id}}.env"
sudo -n systemctl daemon-reload
sudo -n systemctl enable {json.dumps(node.service)}
sudo -n rm -f "$archive"
echo CHAIN1266_IMMUTABLE_ROLE_STAGED
"""
            return self.mutate(node, script, timeout=180)

    def stage_release(self, validated: dict[str, Any]) -> None:
        outcomes = []
        release_id = validated["desired"]["release_id"]
        for node in self.nodes:
            outcome = self.stage_node(node, validated)
            outcomes.append(outcome)
            if outcome["exit"] != 0:
                self.append_operation("STAGE_IMMUTABLE_RELEASE_FAILED", release_id, outcomes)
                fail(f"failed to stage {node.id}: {outcome['detail']}")
        self.append_operation("STAGE_IMMUTABLE_RELEASE", release_id, outcomes)

    def start_role_group(
        self, release_id: str, roles: set[str], operation: str
    ) -> None:
        outcomes = []
        for node in self.nodes:
            if node.role not in roles:
                continue
            outcome = self.mutate(
                node,
                f"""set -euo pipefail
sudo -n systemctl start {json.dumps(node.service)}
systemctl is-active --quiet {json.dumps(node.service)}
echo CHAIN1266_ROLE_ACTIVE
""",
                timeout=180,
            )
            outcomes.append(outcome)
            if outcome["exit"] != 0:
                self.append_operation(f"{operation}_FAILED", release_id, outcomes)
                fail(f"failed to start {node.id}: {outcome['detail']}")
        self.append_operation(operation, release_id, outcomes)

    def assert_paused_barrier(self, release_id: str, timeout_seconds: int) -> None:
        deadline = time.monotonic() + timeout_seconds
        while True:
            snapshots = [
                self.collect(node)
                for node in self.nodes
                if node.role == "validator"
            ]
            ready = []
            identities = set()
            for item in snapshots:
                metrics = item["parsed"].get("metrics", {})
                phase = metrics.get("consensus_startup_phase_info", {})
                identity = metrics.get("chain1266_desired_state_info", {})
                labels = identity.get("labels", {}) if isinstance(identity, dict) else {}
                if (
                    item["ssh_exit"] == 0
                    and phase.get("labels", {}).get("phase") == "PAUSED_READY"
                    and labels.get("release_id") == release_id
                    and labels.get("chain_incarnation") == "4"
                    and labels.get("genesis_hash") == self.fleet["genesis_hash"]
                ):
                    ready.append(item["node_id"])
                    identities.add(
                        (
                            labels.get("release_id"),
                            labels.get("binary_sha256"),
                            labels.get("desired_state_sha256"),
                            labels.get("genesis_hash"),
                            labels.get("validator_set_root"),
                        )
                    )
            if len(ready) == 6 and len(identities) == 1:
                self.append_operation(
                    "VALIDATOR_PAUSED_BARRIER_READY",
                    release_id,
                    [
                        {"node_id": node_id, "result": "PAUSED_READY", "detail": ""}
                        for node_id in ready
                    ],
                )
                return
            if time.monotonic() >= deadline:
                bundle = self.capture_incident(
                    ["VALIDATOR_PAUSED_BARRIER_TIMEOUT"], snapshots, "STARTING"
                )
                fail(f"validators did not reach one identical paused barrier; evidence {bundle}")
            time.sleep(2)

    def distribute_start_command(
        self,
        validated: dict[str, Any],
        start_command: pathlib.Path,
    ) -> None:
        verifier = validated["release"] / "bin" / "verify-chain1266-release-authorization"
        result = subprocess.run(
            [
                str(verifier),
                "--desired-state",
                str(validated["desired_path"]),
                "--desired-state-signature",
                str(validated["desired_signature"]),
                "--consensus-activation",
                str(validated["consensus_activation"]),
                "--genesis",
                str(validated["release"] / "genesis.json"),
                "--start-command",
                str(start_command),
            ],
            text=True,
            capture_output=True,
            check=False,
        )
        if result.returncode != 0:
            fail(f"signed START_CONSENSUS command rejected: {result.stderr.strip()}")
        release_id = validated["desired"]["release_id"]
        outcomes = []
        remote_temp = f"/tmp/{release_id}-start-consensus.json"
        for node in self.nodes:
            if node.role != "validator":
                continue
            copy = subprocess.run(
                [
                    "scp",
                    *self.ssh_options,
                    str(start_command),
                    f"{node.ssh_alias}:{remote_temp}",
                ],
                text=True,
                capture_output=True,
                check=False,
                timeout=60,
            )
            if copy.returncode == 0:
                outcome = self.mutate(
                    node,
                    f"""set -euo pipefail
sudo -n install -m 0644 {json.dumps(remote_temp)} /etc/synergy/chain1266/start-consensus.json
rm -f {json.dumps(remote_temp)}
echo CHAIN1266_SIGNED_START_INSTALLED
""",
                )
            else:
                outcome = {
                    "node_id": node.id,
                    "result": "FAIL",
                    "detail": copy.stderr.strip(),
                    "exit": copy.returncode,
                }
            outcomes.append(outcome)
            if outcome["exit"] != 0:
                self.append_operation("SIGNED_START_DISTRIBUTION_FAILED", release_id, outcomes)
                fail(f"failed to release start command to {node.id}: {outcome['detail']}")
        self.append_operation("SIGNED_START_DISTRIBUTED", release_id, outcomes)

    def reset_atlas_schema(
        self,
        validated: dict[str, Any],
        database_env_file: str,
        offline: bool,
    ) -> None:
        if (
            not database_env_file.startswith("/etc/synergy/")
            or ".." in pathlib.PurePosixPath(database_env_file).parts
        ):
            fail("Atlas database environment file must be an exact /etc/synergy path")
        release: pathlib.Path = validated["release"]
        atlas_root = release / "atlas"
        network_config = release / "atlas-network.json"
        if not (atlas_root / "ops" / "reset-schema.sh").is_file():
            fail("promotable release omits the Atlas reset operation")
        if not network_config.is_file():
            fail("promotable release omits the finalized Atlas network configuration")
        release_id = validated["desired"]["release_id"]
        node = next(item for item in self.nodes if item.role == "atlas_indexer")
        phase = "offline-reset" if offline else "operational-bind"
        remote_root = f"/opt/synergy/chain1266/atlas-ops/{release_id}"
        with tempfile.TemporaryDirectory(prefix="chain1266-atlas-reset-") as temporary:
            payload = pathlib.Path(temporary) / "payload"
            shutil.copytree(atlas_root, payload / "atlas")
            shutil.copy2(network_config, payload / "atlas-network.json")
            metadata = {
                "release_id": release_id,
                "network_config_sha256": sha256(network_config),
                "reset_script_sha256": sha256(atlas_root / "ops" / "reset-schema.sh"),
            }
            (payload / "metadata.json").write_text(
                json.dumps(metadata, sort_keys=True) + "\n"
            )
            archive = pathlib.Path(temporary) / "atlas-reset.tar"
            with tarfile.open(archive, "w") as handle:
                handle.add(payload, arcname="payload")
            remote_archive = f"/tmp/{release_id}-atlas-reset.tar"
            copy = subprocess.run(
                [
                    "scp",
                    *self.ssh_options,
                    str(archive),
                    f"{node.ssh_alias}:{remote_archive}",
                ],
                text=True,
                capture_output=True,
                check=False,
                timeout=120,
            )
            if copy.returncode != 0:
                fail(f"failed to transfer Atlas reset operation: {copy.stderr.strip()}")
        offline_argument = "--offline-reset" if offline else ""
        outcome = self.mutate(
            node,
            f"""set -euo pipefail
archive={json.dumps(remote_archive)}
root={json.dumps(remote_root)}
env_file={json.dumps(database_env_file)}
evidence="/var/lib/synergy/chain1266-evidence/{release_id}/atlas-{phase}"
[[ -f "$env_file" ]] || {{ echo "Atlas database environment file is missing" >&2; exit 1; }}
if [[ ! -d "$root" ]]; then
  staging="${{root}}.staging"
  sudo -n rm -rf -- "$staging"
  sudo -n install -d -m 0755 "$staging"
  sudo -n tar -xf "$archive" -C "$staging" --strip-components=1
  sudo -n mv "$staging" "$root"
fi
rm -f "$archive"
metadata="$root/metadata.json"
[[ "$(jq -er .release_id "$metadata")" == {json.dumps(release_id)} ]]
[[ "$(sha256sum "$root/atlas-network.json" | awk '{{print $1}}')" == "$(jq -er .network_config_sha256 "$metadata")" ]]
[[ "$(sha256sum "$root/atlas/ops/reset-schema.sh" | awk '{{print $1}}')" == "$(jq -er .reset_script_sha256 "$metadata")" ]]
[[ ! -e "$evidence" ]] || {{ echo "Atlas reset evidence already exists" >&2; exit 1; }}
sudo -n install -d -m 0750 -o "$(id -un)" -g "$(id -gn)" "$(dirname "$evidence")"
set -a
source <(sudo -n cat "$env_file")
set +a
export ATLAS_DATABASE_URL
"$root/atlas/ops/reset-schema.sh" \
  --network-config "$root/atlas-network.json" \
  --evidence-dir "$evidence" \
  {offline_argument} \
  --apply
echo CHAIN1266_ATLAS_{phase.upper().replace("-", "_")}_COMPLETE
""",
            timeout=300,
        )
        operation = (
            "ATLAS_OFFLINE_CHAIN_DATA_RESET"
            if offline
            else "ATLAS_OPERATIONAL_RPC_BOUND"
        )
        self.append_operation(operation, release_id, [outcome])
        if outcome["exit"] != 0:
            fail(f"Atlas {phase} failed: {outcome['detail']}")


def parse_snapshot(raw: str) -> dict[str, Any]:
    systemd: dict[str, str] = {}
    metrics: dict[str, Any] = {}
    faults: list[str] = []
    section = ""
    for line in raw.splitlines():
        if line.startswith("SECTION="):
            section = line.removeprefix("SECTION=")
            continue
        if section == "SYSTEMD" and "=" in line:
            key, value = line.split("=", 1)
            systemd[key] = value
        elif section == "METRICS":
            match = PROMETHEUS_SAMPLE.match(line)
            if not match:
                continue
            name = match.group("name")
            value = match.group("value")
            labels = match.group("labels") or ""
            try:
                parsed_value: Any = float(value)
            except ValueError:
                parsed_value = value
            if labels:
                label_values = dict(re.findall(r'([a-zA-Z_]+)="([^"]*)"', labels))
                metrics[name] = {"labels": label_values, "value": parsed_value}
            elif not labels:
                metrics[name] = parsed_value
        elif section == "FAULTS" and line.strip():
            faults.append(line.strip())
    return {"systemd": systemd, "metrics": metrics, "faults": faults}


def analyze(
    snapshots: list[dict[str, Any]],
    previous_height: int | None,
    stagnant_for: float,
    saturated_nodes: set[str] | None = None,
) -> tuple[list[str], str]:
    triggers: list[str] = []
    saturated_nodes = saturated_nodes or set()
    validators = [item for item in snapshots if item["role"] == "validator"]
    if len(validators) != 6 or any(item["ssh_exit"] != 0 for item in validators):
        triggers.append("VALIDATOR_UNREACHABLE")
    active = [
        item
        for item in validators
        if item["parsed"].get("systemd", {}).get("ActiveState") == "active"
    ]
    if len(active) < 5:
        triggers.append("FEWER_THAN_FIVE_ACTIVE_VALIDATORS")
    heights = [
        int(item["parsed"].get("metrics", {}).get("consensus_finalized_height", 0))
        for item in validators
    ]
    current = min(heights, default=0)
    if previous_height is not None and current <= previous_height and stagnant_for >= 6:
        triggers.append("NO_FINALITY_FOR_SIX_SECONDS")
    if heights and max(heights) - min(heights) > 2:
        triggers.append("VALIDATOR_TIP_DIVERGENCE")
    by_height: dict[int, set[str]] = {}
    prepared_by_slot: dict[tuple[int, int], set[str]] = {}
    for item in validators:
        metrics = item["parsed"].get("metrics", {})
        systemd = item["parsed"].get("systemd", {})
        height = int(metrics.get("consensus_finalized_height", 0))
        block = metrics.get("consensus_finalized_block_id", {})
        block_id = block.get("labels", {}).get("block_id", "") if isinstance(block, dict) else ""
        if height and block_id:
            by_height.setdefault(height, set()).add(block_id)
        prepared_height = int(float(metrics.get("consensus_prepared_height", 0)))
        prepared_round = int(float(metrics.get("consensus_prepared_round", 0)))
        prepared = metrics.get("consensus_prepared_candidate", {})
        prepared_id = (
            prepared.get("labels", {}).get("candidate_id", "")
            if isinstance(prepared, dict)
            else ""
        )
        if prepared_height and prepared_id:
            prepared_by_slot.setdefault((prepared_height, prepared_round), set()).add(
                prepared_id
            )
        if float(metrics.get("consensus_current_round", 0)) > 0:
            triggers.append(f"NONZERO_ROUND:{item['node_id']}")
        if float(metrics.get("consensus_mailbox_depth", 0)) > 1000:
            triggers.append(f"MAILBOX_THRESHOLD:{item['node_id']}")
        if (
            float(metrics.get("pqc_verification_queue_depth", 0)) >= 64
            or float(metrics.get("pqc_verification_queue_rejections", 0)) > 0
        ):
            triggers.append(f"PQ_QUEUE_THRESHOLD:{item['node_id']}")
        if height >= 1000 and (
            float(metrics.get("consensus_finality_interval_sample_count", 0))
            < min(height - 1, 10_000)
            or float(metrics.get("consensus_finality_interval_mean_seconds", 0)) > 2.0
            or float(metrics.get("consensus_finality_interval_median_seconds", 0)) > 1.5
            or float(metrics.get("consensus_finality_interval_p95_seconds", 0)) > 3.0
            or float(metrics.get("consensus_round_zero_ratio", 0)) < 0.99
        ):
            triggers.append(f"FINALITY_SLO:{item['node_id']}")
        if int(float(systemd.get("NRestarts", 0) or 0)) > 0 or float(
            metrics.get("consensus_restart_count", 0)
        ) > 0:
            triggers.append(f"VALIDATOR_RESTART:{item['node_id']}")
        identity = metrics.get("chain1266_desired_state_info", {})
        labels = identity.get("labels", {}) if isinstance(identity, dict) else {}
        if (
            labels.get("chain_id") != "1266"
            or labels.get("chain_incarnation") != "4"
            or labels.get("genesis_hash")
            != "c087b6b7c1aae6f13f4c0140ba9a230a12dea0fa52b611777dee69369457de3d"
            or not labels.get("state_root", "").endswith(
                "chain-1266/incarnation-4/data"
            )
        ):
            triggers.append(f"DESIRED_STATE_MISMATCH:{item['node_id']}")
        for fault in item["parsed"].get("faults", []):
            lowered = fault.lower()
            if "signing" in lowered and (
                "conflict" in lowered or "equivocation" in lowered
            ):
                triggers.append(f"SIGNING_JOURNAL_CONFLICT:{item['node_id']}")
            if "prepared" in lowered and "conflict" in lowered:
                triggers.append(f"PREPARED_SOURCE_CONFLICT:{item['node_id']}")
    for node_id in sorted(saturated_nodes):
        triggers.append(f"CPU_SATURATED:{node_id}")
    for item in snapshots:
        if item["role"] not in CORE_ROLES or item["role"] == "validator":
            continue
        if item["parsed"].get("systemd", {}).get("ActiveState") != "active":
            continue
        metrics = item["parsed"].get("metrics", {})
        identity = metrics.get("chain1266_desired_state_info", {})
        labels = identity.get("labels", {}) if isinstance(identity, dict) else {}
        if (
            labels.get("chain_id") != "1266"
            or labels.get("chain_incarnation") != "4"
            or labels.get("genesis_hash")
            != "c087b6b7c1aae6f13f4c0140ba9a230a12dea0fa52b611777dee69369457de3d"
        ):
            triggers.append(f"DOWNSTREAM_IDENTITY_MISMATCH:{item['node_id']}")
    validator_tip = max(heights, default=0)
    for item in snapshots:
        if item["role"] not in {
            "relayer",
            "rpc_gateway",
            "explorer_indexer",
            "observer",
            "atlas_indexer",
        }:
            continue
        support_height = int(
            item["parsed"].get("metrics", {}).get("consensus_finalized_height", 0)
        )
        if validator_tip > 0 and validator_tip - support_height > 2:
            triggers.append(f"OBSERVER_LAG:{item['node_id']}")
    if any(len(blocks) > 1 for blocks in by_height.values()):
        triggers.append("CONFLICTING_FINALITY_BLOCK_IDS")
    if any(len(candidates) > 1 for candidates in prepared_by_slot.values()):
        triggers.append("CONFLICTING_PREPARED_CANDIDATES")
    safety_triggers = {
        "CONFLICTING_FINALITY_BLOCK_IDS",
        "CONFLICTING_PREPARED_CANDIDATES",
    }
    state = "SAFE_HALT" if any(trigger in safety_triggers or trigger.startswith(
        ("SIGNING_JOURNAL_CONFLICT:", "PREPARED_SOURCE_CONFLICT:")
    ) for trigger in triggers) else (
        "CRITICAL"
        if "FEWER_THAN_FIVE_ACTIVE_VALIDATORS" in triggers
        else "DEGRADED"
    )
    return sorted(set(triggers)), state


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--fleet", type=pathlib.Path, default=DEFAULT_FLEET)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("inventory")
    ring2_start = sub.add_parser("record-ring2-real-host-qualification-start")
    ring2_start.add_argument("--release-id", required=True)
    capture = sub.add_parser("capture")
    capture.add_argument("--trigger", action="append", required=True)
    monitor = sub.add_parser("monitor")
    monitor.add_argument("--interval-seconds", type=float, default=2)
    monitor.add_argument("--once", action="store_true")
    gate = sub.add_parser("assert-mutation-ready")
    gate.add_argument("--desired-state", type=pathlib.Path, required=True)
    release_commands = {}
    for name in (
        "validate-promotable",
        "stop-for-reset",
        "dry-run-wipe",
        "wipe-all-chain-state",
        "reset-atlas-offline",
        "stage-release",
        "start-support",
        "start-validators-paused",
        "assert-paused-barrier",
        "distribute-start-command",
        "activate-atlas",
    ):
        command = sub.add_parser(name)
        command.add_argument("--promotable", type=pathlib.Path, required=True)
        command.add_argument(
            "--desired-state-signature", type=pathlib.Path, required=True
        )
        command.add_argument(
            "--consensus-activation", type=pathlib.Path, required=True
        )
        release_commands[name] = command
    release_commands["assert-paused-barrier"].add_argument(
        "--timeout-seconds", type=int, default=600
    )
    release_commands["distribute-start-command"].add_argument(
        "--start-command", type=pathlib.Path, required=True
    )
    release_commands["wipe-all-chain-state"].add_argument(
        "--deletion-manifest", type=pathlib.Path, required=True
    )
    for name in ("reset-atlas-offline", "activate-atlas"):
        release_commands[name].add_argument(
            "--atlas-database-env-file", required=True
        )
    args = parser.parse_args()
    controller = Controller(args.fleet)

    if args.command == "inventory":
        snapshots = controller.collect_all()
        print(json.dumps(snapshots, indent=2, sort_keys=True))
        if any(item["ssh_exit"] != 0 for item in snapshots):
            raise SystemExit(1)
    elif args.command == "record-ring2-real-host-qualification-start":
        controller.record_ring2_real_host_qualification_start(args.release_id)
        print("CHAIN1266_RING2_REAL_HOST_QUALIFICATION_RECORDED")
    elif args.command == "capture":
        bundle = controller.capture_incident(args.trigger)
        print(bundle)
    elif args.command == "assert-mutation-ready":
        desired = controller.require_mutation_authority(args.desired_state)
        print(
            json.dumps(
                {
                    "result": "CHAIN1266_MUTATION_AUTHORITY_HELD",
                    "release_id": desired["release_id"],
                    "desired_state_sha256": sha256(args.desired_state),
                    "stall_log_reread": True,
                },
                sort_keys=True,
            )
        )
    elif args.command in release_commands:
        validated = validate_promotable_release(
            args.promotable, args.desired_state_signature, args.consensus_activation
        )
        release_id = validated["desired"]["release_id"]
        if args.command == "validate-promotable":
            print(
                json.dumps(
                    {
                        "result": "CHAIN1266_PROMOTABLE_RELEASE_VERIFIED",
                        "release_id": release_id,
                        "ring1_cases": validated["ring1"]["cases_passed"],
                        "desired_state_sha256": sha256(validated["desired_path"]),
                        "consensus_activation_sha256": sha256(validated["consensus_activation"]),
                    },
                    sort_keys=True,
                )
            )
            return
        controller.require_mutation_authority(validated["desired_path"])
        if args.command == "stop-for-reset":
            controller.stop_for_reset(release_id)
        elif args.command == "dry-run-wipe":
            print(controller.dry_run_wipe(release_id))
        elif args.command == "wipe-all-chain-state":
            controller.wipe_all_chain_state(release_id, args.deletion_manifest)
        elif args.command == "reset-atlas-offline":
            controller.reset_atlas_schema(
                validated, args.atlas_database_env_file, True
            )
        elif args.command == "stage-release":
            controller.stage_release(validated)
        elif args.command == "start-support":
            controller.start_role_group(
                release_id,
                {"relayer", "rpc_gateway", "explorer_indexer", "observer"},
                "PASSIVE_SUPPORT_ROLES_STARTED",
            )
        elif args.command == "start-validators-paused":
            controller.start_role_group(
                release_id, {"validator"}, "VALIDATORS_STARTED_PAUSED"
            )
        elif args.command == "assert-paused-barrier":
            controller.assert_paused_barrier(release_id, args.timeout_seconds)
        elif args.command == "distribute-start-command":
            controller.distribute_start_command(validated, args.start_command)
        elif args.command == "activate-atlas":
            validators = [
                controller.collect(node)
                for node in controller.nodes
                if node.role == "validator"
            ]
            heights = [
                int(
                    item["parsed"]
                    .get("metrics", {})
                    .get("consensus_finalized_height", 0)
                )
                for item in validators
            ]
            if len(heights) != 6 or min(heights, default=0) < 100:
                fail("Atlas cannot activate before the 100-block OPERATIONAL gate")
            controller.reset_atlas_schema(
                validated, args.atlas_database_env_file, False
            )
            controller.start_role_group(
                release_id, {"atlas_api", "atlas_indexer"}, "ATLAS_ACTIVATED"
            )
        print(
            json.dumps(
                {"result": "PASS", "operation": args.command, "release_id": release_id},
                sort_keys=True,
            )
        )
    elif args.command == "monitor":
        previous_height: int | None = None
        last_progress = time.monotonic()
        last_signature: tuple[str, ...] = ()
        previous_cpu: dict[str, tuple[int, float]] = {}
        saturated_counts: dict[str, int] = {}
        while True:
            snapshots = controller.collect_all()
            sampled_at = time.monotonic()
            saturated_nodes: set[str] = set()
            for item in snapshots:
                if item["role"] != "validator":
                    continue
                raw_cpu = item["parsed"].get("systemd", {}).get("CPUUsageNSec", "0")
                try:
                    cpu_ns = int(raw_cpu)
                except (TypeError, ValueError):
                    cpu_ns = 0
                prior = previous_cpu.get(item["node_id"])
                previous_cpu[item["node_id"]] = (cpu_ns, sampled_at)
                if prior and sampled_at > prior[1] and cpu_ns >= prior[0]:
                    utilization = (cpu_ns - prior[0]) / ((sampled_at - prior[1]) * 1e9)
                    saturated_counts[item["node_id"]] = (
                        saturated_counts.get(item["node_id"], 0) + 1
                        if utilization >= 0.95
                        else 0
                    )
                    if saturated_counts[item["node_id"]] >= 3:
                        saturated_nodes.add(item["node_id"])
            validators = [item for item in snapshots if item["role"] == "validator"]
            heights = [
                int(item["parsed"].get("metrics", {}).get("consensus_finalized_height", 0))
                for item in validators
            ]
            current = min(heights, default=0)
            if previous_height is None or current > previous_height:
                previous_height = current
                last_progress = time.monotonic()
            triggers, state = analyze(
                snapshots,
                previous_height,
                time.monotonic() - last_progress,
                saturated_nodes,
            )
            signature = tuple(triggers)
            print(
                json.dumps(
                    {
                        "utc": utc_now(),
                        "state": (
                            state
                            if triggers
                            else "STABLE"
                            if current >= 10000
                            else "HEALTHY"
                            if current >= 1000
                            else "OPERATIONAL"
                            if current >= 100
                            else "STARTING"
                        ),
                        "height": current,
                        "triggers": triggers,
                    },
                    sort_keys=True,
                ),
                flush=True,
            )
            if triggers and signature != last_signature:
                bundle = controller.capture_incident(triggers, snapshots, state)
                print(json.dumps({"incident_bundle": str(bundle)}, sort_keys=True), flush=True)
            last_signature = signature
            if args.once:
                break
            time.sleep(max(0.5, args.interval_seconds))


if __name__ == "__main__":
    main()
