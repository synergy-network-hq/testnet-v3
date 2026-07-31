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
import subprocess
import sys
import time
import uuid
from dataclasses import dataclass
from typing import Any


ROOT = pathlib.Path(__file__).resolve().parents[2]
DEFAULT_FLEET = ROOT / "launch" / "CHAIN_1266_FLEET.json"
DEFAULT_INCIDENT_ROOT = ROOT / "launch" / "chain1266-incidents"
LOCK_PATH = pathlib.Path("/tmp/synergy-chain1266-control-plane.lock")
PROMETHEUS_SAMPLE = re.compile(
    r"^(?P<name>[a-zA-Z_:][a-zA-Z0-9_:]*)(?:\{(?P<labels>[^}]*)\})?\s+(?P<value>\S+)$"
)


def fail(message: str) -> "NoReturn":
    raise SystemExit(f"chain1266-control-plane: {message}")


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def sha256(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


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
        aliases = {node.ssh_alias for node in self.nodes}
        if any(not alias.startswith("synergy-") for alias in aliases):
            fail("fleet contains a non-workbook SSH alias")
        ssh = self.fleet["ssh"]
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
            f"ControlPath={ssh['control_path']}",
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
        with concurrent.futures.ThreadPoolExecutor(max_workers=12) as executor:
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


def parse_snapshot(raw: str) -> dict[str, Any]:
    systemd: dict[str, str] = {}
    metrics: dict[str, Any] = {}
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
            if labels and name in {
                "consensus_finalized_block_id",
                "consensus_prepared_candidate",
                "consensus_startup_phase_info",
                "chain1266_desired_state_info",
            }:
                label_values = dict(re.findall(r'([a-zA-Z_]+)="([^"]*)"', labels))
                metrics[name] = {"labels": label_values, "value": parsed_value}
            elif not labels:
                metrics[name] = parsed_value
    return {"systemd": systemd, "metrics": metrics}


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
    for item in validators:
        metrics = item["parsed"].get("metrics", {})
        systemd = item["parsed"].get("systemd", {})
        height = int(metrics.get("consensus_finalized_height", 0))
        block = metrics.get("consensus_finalized_block_id", {})
        block_id = block.get("labels", {}).get("block_id", "") if isinstance(block, dict) else ""
        if height and block_id:
            by_height.setdefault(height, set()).add(block_id)
        if float(metrics.get("consensus_current_round", 0)) > 0:
            triggers.append(f"NONZERO_ROUND:{item['node_id']}")
        if float(metrics.get("consensus_mailbox_depth", 0)) > 1000:
            triggers.append(f"MAILBOX_THRESHOLD:{item['node_id']}")
        if float(metrics.get("pqc_verification_queue_depth", 0)) > 64:
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
            != "859c40e33cca7e02e7a3b3ebeafecbbf04ce29080863313ef893a8a5e6341c1d"
            or not labels.get("state_root", "").endswith(
                "chain-1266/incarnation-4/data"
            )
        ):
            triggers.append(f"DESIRED_STATE_MISMATCH:{item['node_id']}")
    for node_id in sorted(saturated_nodes):
        triggers.append(f"CPU_SATURATED:{node_id}")
    validator_tip = max(heights, default=0)
    for item in snapshots:
        if item["role"] not in {"rpc_gateway", "explorer_indexer", "atlas_indexer"}:
            continue
        support_height = int(
            item["parsed"].get("metrics", {}).get("consensus_finalized_height", 0)
        )
        if validator_tip > 0 and validator_tip - support_height > 2:
            triggers.append(f"OBSERVER_LAG:{item['node_id']}")
    if any(len(blocks) > 1 for blocks in by_height.values()):
        triggers.append("CONFLICTING_FINALITY_BLOCK_IDS")
    state = "SAFE_HALT" if "CONFLICTING_FINALITY_BLOCK_IDS" in triggers else (
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
    capture = sub.add_parser("capture")
    capture.add_argument("--trigger", action="append", required=True)
    monitor = sub.add_parser("monitor")
    monitor.add_argument("--interval-seconds", type=float, default=2)
    monitor.add_argument("--once", action="store_true")
    gate = sub.add_parser("assert-mutation-ready")
    gate.add_argument("--desired-state", type=pathlib.Path, required=True)
    args = parser.parse_args()
    controller = Controller(args.fleet)

    if args.command == "inventory":
        snapshots = controller.collect_all()
        print(json.dumps(snapshots, indent=2, sort_keys=True))
        if any(item["ssh_exit"] != 0 for item in snapshots):
            raise SystemExit(1)
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
