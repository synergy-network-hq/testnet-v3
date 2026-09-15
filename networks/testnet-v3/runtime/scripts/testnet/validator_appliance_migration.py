#!/usr/bin/env python3
"""Migrate a stopped validator host to the appliance filesystem layout.

The tool is intentionally conservative:
- dry-run is the default;
- validator service must be stopped unless --allow-active is supplied;
- old validator-workspace is archived and made inert, never symlinked;
- consensus JSON/JSONL contents are not edited;
- service/env/config path rewrites are limited to runtime layout paths.
"""

from __future__ import annotations

import argparse
import dataclasses
import hashlib
import json
import os
import shutil
import subprocess
import tarfile
import time
from pathlib import Path


OLD_WORKSPACE = "/home/node/.synergy/testnet/nodes/validator-workspace"
APPLIANCE_ROOT = "/var/lib/synergy/validator"
CONFIG_ROOT = "/etc/synergy/validator"
LOG_ROOT = "/var/log/synergy/validator"
SERVICE_PATH = "/etc/systemd/system/synergy-validator.service"
SERVICE_NAME = "synergy-validator.service"
ARCHIVE_ROOT = "/var/backups/synergy/validator-workspace-archives"
ROLLBACK_ROOT = "/opt/synergy/backups"

REQUIRED_APPLIANCE_DIRS = [
    "identity",
    "config",
    "state",
    "state/store",
    "state/derived",
    "state/checkpoints",
    "state/checkpoints/current",
    "state/checkpoints/previous",
    "state/checkpoints/manifests",
    "state/snapshots",
    "state/snapshots/inbound",
    "state/snapshots/verified",
    "state/snapshots/rejected",
    "state/quarantine",
    "state/quarantine/current",
    "state/quarantine/history",
    "evidence",
    "logs",
    "runtime",
    "runtime/socket",
    "runtime/pid",
    "runtime/health",
]

STATE_FILES = [
    "chain.json",
    "canonical_locks.json",
    "committed_qcs.json",
    "committed_qcs.jsonl",
    "dag_state.json",
    "token_state.json",
    "validator_registry.json",
    "state_checkpoint.json",
]

DERIVED_EXPORT_NAMES = {
    "chain.json": "chain_export.json",
    "canonical_locks.json": "canonical_locks.json",
    "committed_qcs.json": "committed_qcs_export.json",
    "committed_qcs.jsonl": "committed_qcs_export.jsonl",
}


@dataclasses.dataclass
class Finding:
    severity: str
    code: str
    detail: str


class MigrationError(RuntimeError):
    pass


def now_stamp() -> str:
    return time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def run_text(command: list[str]) -> tuple[int, str, str]:
    proc = subprocess.run(command, text=True, capture_output=True, check=False)
    return proc.returncode, proc.stdout, proc.stderr


def file_summary(path: Path, *, hash_file: bool = False) -> dict:
    exists = path.exists() or path.is_symlink()
    item = {
        "path": str(path),
        "exists": exists,
        "is_dir": path.is_dir(),
        "is_file": path.is_file(),
        "is_symlink": path.is_symlink(),
        "symlink_target": os.readlink(path) if path.is_symlink() else None,
        "size_bytes": None,
        "sha256": None,
    }
    if exists:
        try:
            stat = path.stat()
            item["size_bytes"] = stat.st_size
            item["mode_octal"] = oct(stat.st_mode & 0o777)
            item["uid"] = stat.st_uid
            item["gid"] = stat.st_gid
        except OSError:
            pass
    if hash_file and path.is_file():
        item["sha256"] = sha256_file(path)
    return item


def ensure_parent(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)


def copy_or_hardlink(src: Path, dst: Path, *, apply: bool) -> str:
    if not src.exists():
        return "missing"
    if not apply:
        return "would_link_or_copy"
    ensure_parent(dst)
    if dst.exists() or dst.is_symlink():
        return "exists"
    try:
        os.link(src, dst)
        return "hardlinked"
    except OSError:
        shutil.copy2(src, dst)
        return "copied"


def rewrite_key_values(path: Path, replacements: dict[str, str], *, apply: bool) -> dict:
    if not path.is_file():
        return {"path": str(path), "exists": False, "changed": False}
    original = path.read_text(errors="ignore")
    lines = []
    changed = False
    for line in original.splitlines():
        stripped = line.strip()
        replaced = False
        for key, value in replacements.items():
            if stripped.startswith(f"{key}="):
                lines.append(f"{key}={value}")
                changed = changed or line != f"{key}={value}"
                replaced = True
                break
        if not replaced:
            lines.append(line)
    updated = "\n".join(lines) + ("\n" if original.endswith("\n") else "")
    if changed and apply:
        path.write_text(updated)
    return {"path": str(path), "exists": True, "changed": changed}


def rewrite_toml_strings(path: Path, replacements: dict[str, str], *, apply: bool) -> dict:
    if not path.is_file():
        return {"path": str(path), "exists": False, "changed": False}
    original = path.read_text(errors="ignore")
    lines = []
    changed = False
    for line in original.splitlines():
        stripped = line.strip()
        replaced = False
        for key, value in replacements.items():
            if stripped.startswith(f"{key} "):
                new_line = f'{key} = "{value}"'
                prefix = line[: len(line) - len(line.lstrip())]
                lines.append(prefix + new_line)
                changed = changed or line != prefix + new_line
                replaced = True
                break
        if not replaced:
            lines.append(line)
    updated = "\n".join(lines) + ("\n" if original.endswith("\n") else "")
    if changed and apply:
        path.write_text(updated)
    return {"path": str(path), "exists": True, "changed": changed}


def rewrite_service(path: Path, appliance_root: Path, log_root: Path, archive_root: Path, *, apply: bool) -> dict:
    if not path.is_file():
        return {"path": str(path), "exists": False, "changed": False}
    original = path.read_text(errors="ignore")
    lines = []
    changed = False
    for line in original.splitlines():
        if line.startswith("WorkingDirectory="):
            new_line = f"WorkingDirectory={appliance_root}"
        elif line.startswith("ReadWritePaths="):
            new_line = f"ReadWritePaths={appliance_root} {log_root} {archive_root}"
        else:
            new_line = line.replace(OLD_WORKSPACE, str(appliance_root))
        lines.append(new_line)
        changed = changed or new_line != line
    updated = "\n".join(lines) + ("\n" if original.endswith("\n") else "")
    if changed and apply:
        path.write_text(updated)
    return {"path": str(path), "exists": True, "changed": changed}


def contains_old_workspace(path: Path, old_workspace: str) -> list[dict]:
    refs = []
    if path.is_file():
        candidates = [path]
    elif path.is_dir():
        candidates = [item for item in path.rglob("*") if item.is_file()]
    else:
        return refs
    for candidate in candidates:
        try:
            text = candidate.read_text(errors="ignore")
        except OSError:
            continue
        for line_no, line in enumerate(text.splitlines(), 1):
            if old_workspace in line:
                refs.append({"path": str(candidate), "line": line_no, "text": line.strip()})
    return refs


def create_tar_archive(source: Path, archive_path: Path, manifest_path: Path, *, apply: bool) -> dict:
    manifest = []
    if source.exists() and not source.is_symlink():
        for item in sorted(source.rglob("*")):
            rel = item.relative_to(source)
            manifest.append(
                {
                    "path": str(rel),
                    "type": "dir" if item.is_dir() else "file" if item.is_file() else "other",
                    "size_bytes": item.stat().st_size if item.is_file() else None,
                    "is_symlink": item.is_symlink(),
                    "symlink_target": os.readlink(item) if item.is_symlink() else None,
                }
            )
    result = {
        "archive": str(archive_path),
        "manifest": str(manifest_path),
        "entry_count": len(manifest),
        "sha256": None,
        "listed_ok": False,
    }
    if not apply:
        return result
    ensure_parent(archive_path)
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    with tarfile.open(archive_path, "w:gz", dereference=False) as tar:
        tar.add(source, arcname=source.name)
    result["sha256"] = sha256_file(archive_path)
    with tarfile.open(archive_path, "r:gz") as tar:
        result["listed_ok"] = bool(tar.getmembers() or not source.exists())
    (archive_path.with_suffix(archive_path.suffix + ".sha256")).write_text(
        f"{result['sha256']}  {archive_path.name}\n"
    )
    return result


def write_json(path: Path, value: dict, *, apply: bool) -> None:
    if apply:
        ensure_parent(path)
        path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def write_text(path: Path, text: str, *, apply: bool) -> None:
    if apply:
        ensure_parent(path)
        path.write_text(text)


def service_active(service_name: str, no_systemd: bool) -> dict:
    if no_systemd:
        return {"checked": False, "active": False, "stdout": "no_systemd", "stderr": "", "rc": 0}
    rc, stdout, stderr = run_text(["systemctl", "is-active", service_name])
    return {
        "checked": True,
        "active": stdout.strip() == "active",
        "stdout": stdout.strip(),
        "stderr": stderr.strip(),
        "rc": rc,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--dry-run", action="store_true")
    mode.add_argument("--apply", action="store_true")
    parser.add_argument("--validator-name", required=True)
    parser.add_argument("--source-workspace", default=OLD_WORKSPACE, type=Path)
    parser.add_argument("--target-root", default=APPLIANCE_ROOT, type=Path)
    parser.add_argument("--config-root", default=CONFIG_ROOT, type=Path)
    parser.add_argument("--log-root", default=LOG_ROOT, type=Path)
    parser.add_argument("--service-path", default=SERVICE_PATH, type=Path)
    parser.add_argument("--service-name", default=SERVICE_NAME)
    parser.add_argument("--archive-root", default=ARCHIVE_ROOT, type=Path)
    parser.add_argument("--rollback-root", default=ROLLBACK_ROOT, type=Path)
    parser.add_argument("--evidence-dir", type=Path)
    parser.add_argument("--runtime-user", default="node")
    parser.add_argument("--runtime-group", default="node")
    parser.add_argument("--expected-chain-id", default="1264")
    parser.add_argument("--expected-network-id", default="synergy-testnet-v3")
    parser.add_argument("--allow-active", action="store_true")
    parser.add_argument("--no-systemd", action="store_true")
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    apply = bool(args.apply)
    stamp = now_stamp()
    evidence_dir = args.evidence_dir or (
        args.target_root / "evidence" / "rollout" / f"appliance-migration-{stamp}"
    )
    rollback_dir = args.rollback_root / f"appliance-layout-migration-{stamp}-{args.validator_name}"
    archive_dir = args.archive_root / args.validator_name / stamp
    archive_path = archive_dir / "validator-workspace.tar.gz"
    archive_manifest_path = archive_dir / "validator-workspace-manifest.json"
    findings: list[Finding] = []
    actions: list[str] = []

    if not args.dry_run and not args.apply:
        apply = False

    active = service_active(args.service_name, args.no_systemd)
    if active["active"] and not args.allow_active:
        findings.append(Finding("error", "validator_service_active", args.service_name))

    source_workspace = args.source_workspace
    old_data = source_workspace / "data"
    data_source = old_data.resolve() if old_data.exists() else args.target_root
    config_file = args.config_root / "config.toml"
    env_file = args.config_root / "node.env"
    genesis_file = args.config_root / "genesis.json"

    if not source_workspace.exists() and not source_workspace.is_symlink():
        findings.append(Finding("error", "source_workspace_missing", str(source_workspace)))
    if source_workspace.is_symlink():
        actions.append(f"old workspace symlink will be removed: {source_workspace} -> {os.readlink(source_workspace)}")
    if not data_source.exists():
        findings.append(Finding("error", "state_source_missing", str(data_source)))
    if not config_file.is_file():
        findings.append(Finding("error", "config_missing", str(config_file)))
    if not env_file.is_file():
        findings.append(Finding("warning", "env_missing", str(env_file)))
    if not genesis_file.is_file():
        findings.append(Finding("error", "genesis_missing", str(genesis_file)))

    config_text = config_file.read_text(errors="ignore") if config_file.is_file() else ""
    if f"chain_id = {args.expected_chain_id}" not in config_text and f"SYNERGY_CHAIN_ID={args.expected_chain_id}" not in (
        env_file.read_text(errors="ignore") if env_file.is_file() else ""
    ):
        findings.append(Finding("error", "chain_id_not_verified", args.expected_chain_id))
    if args.expected_network_id not in config_text and args.expected_network_id not in (
        env_file.read_text(errors="ignore") if env_file.is_file() else ""
    ):
        findings.append(Finding("error", "network_id_not_verified", args.expected_network_id))

    state_summaries = {
        name: file_summary(data_source / name, hash_file=False)
        for name in STATE_FILES
        if (data_source / name).exists()
    }
    for required in ["chain.json", "canonical_locks.json", "committed_qcs.jsonl"]:
        if required not in state_summaries:
            findings.append(Finding("error", "required_state_file_missing", str(data_source / required)))

    private_paths = []
    key_root = args.config_root / "keys"
    if key_root.is_dir():
        private_paths.extend(sorted(path for path in key_root.rglob("*") if path.is_file()))
    key_manifest = {
        "format": "synergy-validator-key-manifest-v1",
        "generated_at": stamp,
        "keys_preserved_at": str(key_root),
        "private_key_file_count": len(private_paths),
        "private_key_files": [str(path) for path in private_paths],
    }

    if any(f.severity == "error" for f in findings):
        report = {
            "ok": False,
            "decision": "NO_GO",
            "dry_run": not apply,
            "apply": apply,
            "validator_name": args.validator_name,
            "findings": [dataclasses.asdict(f) for f in findings],
            "service": active,
            "source_workspace": file_summary(source_workspace),
            "state_source": file_summary(data_source),
            "target_root": str(args.target_root),
            "config_root": str(args.config_root),
            "state_files": state_summaries,
        }
        print(json.dumps(report, indent=2, sort_keys=True))
        return 1

    created_dirs = [str(args.target_root / item) for item in REQUIRED_APPLIANCE_DIRS]
    if apply:
        for directory in created_dirs:
            Path(directory).mkdir(parents=True, exist_ok=True)
        evidence_dir.mkdir(parents=True, exist_ok=True)
        rollback_dir.mkdir(parents=True, exist_ok=True)
        for path in [args.service_path, config_file, env_file, genesis_file]:
            if path.exists() or path.is_symlink():
                dest = rollback_dir / "rootfs" / str(path).lstrip("/")
                ensure_parent(dest)
                if path.is_dir():
                    shutil.copytree(path, dest, symlinks=True, dirs_exist_ok=True)
                else:
                    shutil.copy2(path, dest, follow_symlinks=False)

    actions.append(f"create appliance directories under {args.target_root}")
    actions.append(f"write evidence under {evidence_dir}")
    actions.append(f"write rollback files under {rollback_dir}")

    derived_actions = {}
    for source_name, derived_name in DERIVED_EXPORT_NAMES.items():
        src = data_source / source_name
        dst = args.target_root / "state" / "derived" / derived_name
        if src.exists():
            derived_actions[source_name] = {
                "source": str(src),
                "target": str(dst),
                "action": copy_or_hardlink(src, dst, apply=apply),
            }

    metadata = {
        "format": "synergy-validator-appliance-metadata-v1",
        "generated_at": stamp,
        "validator_name": args.validator_name,
        "state_source": str(data_source),
        "state_files": state_summaries,
        "no_manual_consensus_edits": True,
    }
    write_json(args.target_root / "state" / "store" / "metadata.json", metadata, apply=apply)
    write_json(args.target_root / "identity" / "key_manifest.json", key_manifest, apply=apply)
    write_json(args.target_root / "evidence" / "rollout" / f"appliance-migration-{stamp}.json", metadata, apply=apply)
    write_text(
        args.target_root / "runtime" / "lifecycle.json",
        json.dumps(
            {
                "format": "synergy-validator-lifecycle-v1",
                "state": "OFFLINE_APPLIANCE_MIGRATED" if apply else "DRY_RUN",
                "updated_at": stamp,
                "validator_name": args.validator_name,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        apply=apply,
    )

    active_profile = args.config_root / "active-profile.toml"
    service_env = args.config_root / "service.env"
    cluster_assignment = args.config_root / "cluster-assignment.toml"
    write_text(
        active_profile,
        f'profile = "validator-appliance"\nvalidator_name = "{args.validator_name}"\nappliance_root = "{args.target_root}"\n',
        apply=apply and not active_profile.exists(),
    )
    if apply and env_file.is_file() and not service_env.exists():
        shutil.copy2(env_file, service_env)
    write_text(
        cluster_assignment,
        f'network_id = "{args.expected_network_id}"\nvalidator_name = "{args.validator_name}"\n',
        apply=apply and not cluster_assignment.exists(),
    )

    env_replacements = {
        "BASE_DIR": str(args.target_root),
        "SYNERGY_PROJECT_ROOT": str(args.target_root),
        "SYNERGY_DATA_DIR": str(args.target_root),
        "SYNERGY_LOG_DIR": str(args.log_root),
    }
    rewrite_results = {
        "service": rewrite_service(
            args.service_path,
            args.target_root,
            args.log_root,
            args.archive_root,
            apply=apply,
        ),
        "env": rewrite_key_values(env_file, env_replacements, apply=apply),
        "service_env": rewrite_key_values(service_env, env_replacements, apply=apply),
        "config": rewrite_toml_strings(
            config_file,
            {
                "workspace": str(args.target_root),
                "data_dir": str(args.target_root),
                "log_dir": str(args.log_root),
            },
            apply=apply,
        ),
    }

    if apply:
        if source_workspace.is_symlink():
            source_workspace.unlink()
            source_workspace.mkdir(parents=True, exist_ok=True)
        elif source_workspace.exists():
            archive_result = create_tar_archive(
                source_workspace,
                archive_path,
                archive_manifest_path,
                apply=True,
            )
            shutil.rmtree(source_workspace)
            source_workspace.mkdir(parents=True, exist_ok=True)
        else:
            archive_result = create_tar_archive(
                source_workspace,
                archive_path,
                archive_manifest_path,
                apply=False,
            )
        readme = source_workspace / "README.validator-appliance-migrated.txt"
        readme.write_text(
            f"This validator was migrated to {args.target_root} at {stamp}.\n"
            f"The old validator-workspace is intentionally inert and must not be used as a runtime root.\n"
            f"Archive path: {archive_path}\n"
        )
    else:
        archive_result = create_tar_archive(
            source_workspace,
            archive_path,
            archive_manifest_path,
            apply=False,
        )

    if apply:
        old_refs = []
        for root in [args.service_path, args.config_root]:
            old_refs.extend(contains_old_workspace(root, str(source_workspace)))
        if old_refs:
            findings.append(Finding("error", "old_workspace_reference_remaining", json.dumps(old_refs)))
        if source_workspace.is_symlink():
            findings.append(Finding("error", "old_workspace_symlink_remaining", str(source_workspace)))

    report = {
        "ok": not any(f.severity == "error" for f in findings),
        "decision": "GO" if apply and not any(f.severity == "error" for f in findings) else "DRY_RUN_GO" if not any(f.severity == "error" for f in findings) else "NO_GO",
        "dry_run": not apply,
        "apply": apply,
        "validator_name": args.validator_name,
        "timestamp": stamp,
        "source_workspace": file_summary(source_workspace),
        "state_source": file_summary(data_source),
        "target_root": str(args.target_root),
        "config_root": str(args.config_root),
        "log_root": str(args.log_root),
        "service_path": str(args.service_path),
        "service": active,
        "created_dirs": created_dirs,
        "derived_exports": derived_actions,
        "identity_manifest": key_manifest,
        "archive": archive_result,
        "rollback_dir": str(rollback_dir),
        "evidence_dir": str(evidence_dir),
        "rewrite_results": rewrite_results,
        "state_files": state_summaries,
        "findings": [dataclasses.asdict(f) for f in findings],
        "actions": actions,
        "confirmation": {
            "genesis_not_edited": True,
            "chain_id_expected": args.expected_chain_id,
            "network_id_expected": args.expected_network_id,
            "manual_consensus_json_jsonl_edit": False,
            "old_workspace_final_symlink_allowed": False,
        },
    }
    report_path = evidence_dir / "appliance-migration-report.json"
    write_json(report_path, report, apply=apply)
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
