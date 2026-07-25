#!/usr/bin/env python3
"""Verify that a validator host is cut over to the appliance layout.

This is a read-only checker. It does not stop services, edit files, remove the
old workspace, or mutate validator state.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
from pathlib import Path


OLD_WORKSPACE_DEFAULT = "/home/node/.synergy/testnet/nodes/validator-workspace"
APPLIANCE_ROOT_DEFAULT = "/var/lib/synergy/validator"
CONFIG_ROOT_DEFAULT = "/etc/synergy/validator"
SERVICE_NAME_DEFAULT = "synergy-validator.service"


def run_text(command: list[str]) -> tuple[int, str, str]:
    proc = subprocess.run(command, text=True, capture_output=True, check=False)
    return proc.returncode, proc.stdout, proc.stderr


def add_finding(findings: list[dict], severity: str, code: str, detail: str) -> None:
    findings.append({"severity": severity, "code": code, "detail": detail})


def path_state(path: Path) -> dict:
    exists = path.exists() or path.is_symlink()
    result = {
        "path": str(path),
        "exists": exists,
        "is_dir": path.is_dir(),
        "is_file": path.is_file(),
        "is_symlink": path.is_symlink(),
        "target": os.readlink(path) if path.is_symlink() else None,
    }
    try:
        stat = path.stat()
        result["mode_octal"] = oct(stat.st_mode & 0o777)
        result["uid"] = stat.st_uid
        result["gid"] = stat.st_gid
    except OSError:
        result["mode_octal"] = None
        result["uid"] = None
        result["gid"] = None
    return result


def grep_references(roots: list[Path], old_workspace: str) -> list[dict]:
    refs: list[dict] = []
    for root in roots:
        if not root.exists():
            continue
        if root.is_file():
            candidates = [root]
        else:
            candidates = [path for path in root.rglob("*") if path.is_file()]
        for path in candidates:
            try:
                text = path.read_text(errors="ignore")
            except OSError:
                continue
            for number, line in enumerate(text.splitlines(), 1):
                if old_workspace in line:
                    refs.append(
                        {
                            "path": str(path),
                            "line": number,
                            "text": line.strip(),
                        }
                    )
    return refs


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--service", default=SERVICE_NAME_DEFAULT)
    parser.add_argument("--appliance-root", default=APPLIANCE_ROOT_DEFAULT)
    parser.add_argument("--config-root", default=CONFIG_ROOT_DEFAULT)
    parser.add_argument("--old-workspace", default=OLD_WORKSPACE_DEFAULT)
    args = parser.parse_args()

    service_rc, service_stdout, service_stderr = run_text(
        [
            "systemctl",
            "show",
            args.service,
            "-p",
            "FragmentPath",
            "-p",
            "WorkingDirectory",
            "-p",
            "ExecStart",
            "-p",
            "EnvironmentFiles",
            "-p",
            "ReadWritePaths",
            "-p",
            "User",
            "-p",
            "Group",
        ]
    )
    active_rc, active_stdout, active_stderr = run_text(["systemctl", "is-active", args.service])

    service_values: dict[str, str] = {}
    for line in service_stdout.splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            service_values[key] = value

    appliance_root = Path(args.appliance_root)
    config_root = Path(args.config_root)
    old_workspace = Path(args.old_workspace)
    service_path = Path(service_values.get("FragmentPath", ""))

    findings: list[dict] = []
    if active_stdout.strip() == "active":
        add_finding(findings, "error", "validator_service_active", f"{args.service} is active")
    if service_rc != 0:
        add_finding(
            findings,
            "error",
            "systemd_show_failed",
            service_stderr.strip() or f"systemctl show exited {service_rc}",
        )
    if not appliance_root.is_dir():
        add_finding(
            findings,
            "error",
            "appliance_root_missing",
            f"{appliance_root} is not a directory",
        )
    if not config_root.is_dir():
        add_finding(findings, "error", "config_root_missing", f"{config_root} is not a directory")

    service_text = service_stdout
    if str(old_workspace) in service_text or "validator-workspace" in service_text:
        add_finding(
            findings,
            "error",
            "service_references_old_workspace",
            f"{args.service} still references {old_workspace}",
        )
    if service_values.get("WorkingDirectory") != str(appliance_root):
        add_finding(
            findings,
            "error",
            "service_working_directory_not_appliance_root",
            f"WorkingDirectory={service_values.get('WorkingDirectory', '')}",
        )
    if str(appliance_root) not in service_text:
        add_finding(
            findings,
            "error",
            "service_missing_appliance_root",
            f"{args.service} does not reference {appliance_root}",
        )

    roots = [config_root]
    if service_path.is_file():
        roots.append(service_path)
    old_refs = grep_references(roots, str(old_workspace))
    for ref in old_refs:
        add_finding(
            findings,
            "error",
            "active_config_references_old_workspace",
            f"{ref['path']}:{ref['line']}: {ref['text']}",
        )

    old_state = path_state(old_workspace)
    if old_state["is_symlink"]:
        add_finding(
            findings,
            "error",
            "old_workspace_is_symlink",
            f"{old_workspace} -> {old_state['target']}",
        )
    elif old_state["is_dir"]:
        marker = old_workspace / "README.validator-appliance-migrated.txt"
        children = []
        try:
            children = [child.name for child in old_workspace.iterdir()]
        except OSError:
            pass
        allowed = marker.is_file() and sorted(children) == [marker.name]
        if not allowed:
            add_finding(
                findings,
                "error",
                "old_workspace_not_inert",
                f"{old_workspace} still exists and is not an inert README-only marker",
            )

    required_dirs = [
        appliance_root / "identity",
        appliance_root / "config",
        appliance_root / "state",
        appliance_root / "state" / "store",
        appliance_root / "state" / "derived",
        appliance_root / "state" / "checkpoints",
        appliance_root / "state" / "snapshots",
        appliance_root / "state" / "quarantine",
        appliance_root / "evidence",
        appliance_root / "logs",
        appliance_root / "runtime",
    ]
    layout = {str(path): path_state(path) for path in required_dirs}
    for path, state in layout.items():
        if not state["is_dir"]:
            add_finding(findings, "error", "required_appliance_dir_missing", path)

    ok = not any(finding["severity"] == "error" for finding in findings)
    report = {
        "ok": ok,
        "decision": "GO" if ok else "NO_GO",
        "service": args.service,
        "service_active": active_stdout.strip(),
        "systemctl_is_active_rc": active_rc,
        "systemctl_is_active_stderr": active_stderr.strip(),
        "systemctl_show_rc": service_rc,
        "systemctl_show_stderr": service_stderr.strip(),
        "service_values": service_values,
        "appliance_root": path_state(appliance_root),
        "config_root": path_state(config_root),
        "old_workspace": old_state,
        "required_layout": layout,
        "old_workspace_references": old_refs,
        "findings": findings,
    }
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
