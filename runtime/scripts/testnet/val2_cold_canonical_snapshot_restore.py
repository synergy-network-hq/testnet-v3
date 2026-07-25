#!/usr/bin/env python3
"""Cold-restore validator chain/state from a canonical stopped-validator bundle.

This is not a bridge repair tool. It does not synthesize or edit consensus
JSON/JSONL. It copies only an explicit state-file allowlist from an approved
canonical source into a staged directory, archives the target's existing state
files, and atomically replaces the active state files only after offline checks
pass.
"""

from __future__ import annotations

import argparse
import dataclasses
import grp
import hashlib
import json
import os
import pwd
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path


APPLIANCE_ROOT = Path("/var/lib/synergy/validator")
CONFIG_ROOT = Path("/etc/synergy/validator")
OLD_WORKSPACE = Path("/home/node/.synergy/testnet/nodes/validator-workspace")
SERVICE_NAME = "synergy-validator.service"
SERVICE_PATH = Path("/etc/systemd/system/synergy-validator.service")
ARCHIVE_ROOT = Path("/var/backups/synergy")
EXPECTED_GENESIS_HASH = "f79011f2aaddd40b120d47ba723104fafe3c998d4a17097fae018914b95f1789"
LARGE_FILE_FAST_SUMMARY_BYTES = 64 * 1024 * 1024

STATE_COPY_ALLOWLIST = [
    "chain.json",
    "committed_blocks.jsonl",
    "canonical_locks.json",
    "committed_qcs.json",
    "committed_qcs.jsonl",
    "dag_state.json",
    "token_state.json",
    "account_state.json",
    "validator_registry.json",
    "synid_registry.json",
    "state_checkpoint.json",
    "state_checkpoint.recovery_manifest.json",
]

REQUIRED_SOURCE_FILES = [
    "chain.json",
    "canonical_locks.json",
    "committed_qcs.jsonl",
    "dag_state.json",
    "token_state.json",
    "validator_registry.json",
]

TARGET_STALE_STATE_FILES = [
    "consensus_vote_locks.json",
    "consensus_vote_locks.jsonl",
    "consensus_proposals",
    "consensus_proposals.json",
    "consensus_proposals.jsonl",
    "self_heal_status.json",
    "state_checkpoint.json",
    "state_checkpoint.recovery_manifest.json",
]

FORBIDDEN_SOURCE_NAME_PATTERNS = [
    re.compile(pattern, re.IGNORECASE)
    for pattern in [
        r"(^|[-_.])key(s)?($|[-_.])",
        r"private",
        r"secret",
        r"identity",
        r"wallet",
        r"p2p",
        r"node\.env$",
        r"service\.env$",
        r"config\.toml$",
        r"genesis\.json$",
        r"\.pem$",
        r"\.key$",
    ]
]

BLOCK_RE = re.compile(
    rb'"block_index"\s*:\s*(\d+).*?"hash"\s*:\s*"([0-9a-fA-F]{64})"',
    re.DOTALL,
)
TOP_LEVEL_BLOCK_RE = re.compile(
    rb'"block_index"\s*:\s*(\d+)\s*,\s*"timestamp"\s*:.*?"hash"\s*:\s*"([0-9a-fA-F]{64})"',
    re.DOTALL,
)
HEIGHT_RE = re.compile(r'"(?:block_index|block_height|height)"\s*:\s*(\d+)')


@dataclasses.dataclass
class Finding:
    severity: str
    code: str
    detail: str


def now_stamp() -> str:
    return time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())


def safe_name(value: str) -> str:
    safe = re.sub(r"[^A-Za-z0-9_.-]+", "-", value.strip())
    return safe.strip("-") or "validator"


def run_text(command: list[str]) -> tuple[int, str, str]:
    proc = subprocess.run(command, text=True, capture_output=True, check=False)
    return proc.returncode, proc.stdout, proc.stderr


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def file_info(path: Path, *, hash_file: bool = False) -> dict:
    info = {
        "path": str(path),
        "exists": path.exists() or path.is_symlink(),
        "is_file": path.is_file(),
        "is_dir": path.is_dir(),
        "is_symlink": path.is_symlink(),
        "symlink_target": os.readlink(path) if path.is_symlink() else None,
        "size_bytes": None,
        "sha256": None,
    }
    if info["exists"]:
        try:
            stat = path.stat()
            info["size_bytes"] = stat.st_size
            info["mode_octal"] = oct(stat.st_mode & 0o777)
            info["uid"] = stat.st_uid
            info["gid"] = stat.st_gid
        except OSError:
            pass
    if hash_file and path.is_file() and (info["size_bytes"] or 0) <= LARGE_FILE_FAST_SUMMARY_BYTES:
        info["sha256"] = sha256_file(path)
    return info


def service_state(service_name: str, no_systemd: bool) -> dict:
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


def process_check() -> dict:
    rc, stdout, stderr = run_text(["ps", "-axo", "pid=,comm=,args="])
    own = str(os.getpid())
    lines = []
    for line in stdout.splitlines():
        parts = line.strip().split(None, 2)
        if len(parts) < 2 or parts[0] == own:
            continue
        pid, comm = parts[0], parts[1]
        args = parts[2] if len(parts) > 2 else ""
        argv0 = args.split(None, 1)[0] if args else ""
        if comm in {"synergy-validator", "synergy-validat"} or argv0 == "/opt/synergy/bin/synergy-validator":
            lines.append(f"{pid} {comm} {args}".strip())
    return {"rc": rc, "stdout": "\n".join(lines), "stderr": stderr.strip(), "running": bool(lines)}


def read_text_if_exists(path: Path) -> str:
    if not path.is_file():
        return ""
    return path.read_text(errors="ignore")


def discover_validator_identity(config_root: Path) -> dict:
    combined = "\n".join(
        read_text_if_exists(path)
        for path in [
            config_root / "node.env",
            config_root / "service.env",
            config_root / "config.toml",
            config_root / "active-profile.toml",
            config_root / "cluster-assignment.toml",
        ]
    )
    addresses = sorted(set(re.findall(r"synv1[0-9a-z]+", combined)))
    key_files = []
    for root in [config_root / "keys", config_root / "identity"]:
        if root.is_dir():
            key_files.extend(str(path) for path in sorted(root.rglob("*")) if path.is_file())
    return {
        "addresses": addresses,
        "key_files": key_files,
        "config_root": str(config_root),
        "config_root_sha256": tree_digest(config_root, include_content=False) if config_root.exists() else None,
    }


def tree_digest(root: Path, *, include_content: bool = True) -> str:
    digest = hashlib.sha256()
    if not root.exists():
        return ""
    for path in sorted(root.rglob("*")):
        rel = path.relative_to(root).as_posix()
        digest.update(rel.encode())
        if path.is_symlink():
            digest.update(b"SYMLINK")
            digest.update(os.readlink(path).encode())
        elif path.is_file():
            stat = path.stat()
            digest.update(str(stat.st_size).encode())
            if include_content:
                with path.open("rb") as handle:
                    for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                        digest.update(chunk)
        elif path.is_dir():
            digest.update(b"DIR")
    return digest.hexdigest()


def quick_chain_summary(path: Path) -> dict:
    size_bytes = path.stat().st_size
    if size_bytes > LARGE_FILE_FAST_SUMMARY_BYTES:
        with path.open("rb") as handle:
            first = handle.read(8 * 1024 * 1024)
            handle.seek(max(0, size_bytes - 32 * 1024 * 1024))
            tail = handle.read(32 * 1024 * 1024)
        first_matches = list(TOP_LEVEL_BLOCK_RE.finditer(first))
        tail_matches = list(TOP_LEVEL_BLOCK_RE.finditer(tail))
        if len(first_matches) < 2 or not tail_matches:
            raise ValueError("large chain summary could not parse required edge blocks")
        first_match = first_matches[0]
        tip_match = tail_matches[-1]
        return {
            "path": str(path),
            "block_count_detected": len(first_matches[:2]) + len(tail_matches[-1:]),
            "summary_mode": "large_file_edges",
            "first_height": int(first_match.group(1)),
            "first_hash": first_match.group(2).decode().lower(),
            "tip_height": int(tip_match.group(1)),
            "tip_hash": tip_match.group(2).decode().lower(),
            "size_bytes": size_bytes,
            "sha256": None,
        }
    first_height = None
    first_hash = None
    last_height = None
    last_hash = None
    count = 0
    buffer = b""
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(4 * 1024 * 1024), b""):
            buffer += chunk
            matches = list(BLOCK_RE.finditer(buffer))
            for match in matches:
                height = int(match.group(1))
                block_hash = match.group(2).decode().lower()
                if first_height is None:
                    first_height = height
                    first_hash = block_hash
                last_height = height
                last_hash = block_hash
                count += 1
            if matches:
                buffer = buffer[matches[-1].end() :]
            if len(buffer) > 16 * 1024 * 1024:
                buffer = buffer[-1024 * 1024 :]
    return {
        "path": str(path),
        "block_count_detected": count,
        "first_height": first_height,
        "first_hash": first_hash,
        "tip_height": last_height,
        "tip_hash": last_hash,
        "size_bytes": size_bytes,
        "sha256": sha256_file(path) if size_bytes <= LARGE_FILE_FAST_SUMMARY_BYTES else None,
    }


def load_locks_summary(path: Path, heights: list[int]) -> dict:
    selected = {}
    for height in heights:
        lock_hash = find_lock_hash(path, height)
        if lock_hash:
            selected[str(height)] = lock_hash
    return {
        "path": str(path),
        "count": None,
        "min_height": None,
        "max_height": None,
        "selected_hashes": selected,
        "sha256": None,
    }


def find_lock_hash(path: Path, height: int) -> str | None:
    pattern = re.compile(
        rb'"' + str(height).encode() + rb'"\s*:\s*\{.*?"(?:block_hash|hash)"\s*:\s*"([0-9a-fA-F]{64})"',
        re.DOTALL,
    )
    overlap = b""
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(4 * 1024 * 1024), b""):
            buffer = overlap + chunk
            match = pattern.search(buffer)
            if match:
                return match.group(1).decode().lower()
            overlap = buffer[-256 * 1024 :]
    return None


def qc_height_hash(entry: dict) -> tuple[int, str]:
    qc = entry.get("qc") or entry
    votes = qc.get("votes") or []
    heights = []
    for vote in votes:
        if isinstance(vote, dict):
            value = vote.get("block_index") or vote.get("height") or vote.get("block_height")
            if value is not None:
                heights.append(int(value))
    height = max(heights) if heights else int(qc.get("height") or qc.get("block_height") or entry.get("height") or entry.get("block_height") or 0)
    block_hash = qc.get("block_hash") or qc.get("hash") or entry.get("block_hash") or entry.get("hash")
    if not height or not block_hash:
        raise ValueError("committed QC entry missing height/hash")
    return height, str(block_hash).lower()


def committed_block_height_hash(entry: dict) -> tuple[int, str]:
    block = entry.get("block") if isinstance(entry.get("block"), dict) else {}
    height = entry.get("height") or entry.get("block_height") or entry.get("block_index")
    if height is None:
        height = block.get("block_index") or block.get("height") or block.get("block_height")
    block_hash = entry.get("hash") or entry.get("block_hash") or block.get("hash") or block.get("block_hash")
    if height is None or not block_hash:
        raise ValueError("committed block entry missing height/hash")
    return int(height), str(block_hash).lower()


def first_line(path: Path) -> str:
    with path.open("r", encoding="utf-8", errors="ignore") as handle:
        for line in handle:
            if line.strip():
                return line.strip()
    raise ValueError(f"{path} is empty")


def last_line(path: Path) -> str:
    with path.open("rb") as handle:
        handle.seek(0, os.SEEK_END)
        pos = handle.tell()
        buffer = b""
        while pos > 0:
            step = min(1024 * 1024, pos)
            pos -= step
            handle.seek(pos)
            buffer = handle.read(step) + buffer
            lines = [line for line in buffer.splitlines() if line.strip()]
            if len(lines) >= 2 or pos == 0:
                return lines[-1].decode("utf-8", "ignore")
    raise ValueError(f"{path} is empty")


def qc_summary(path: Path) -> dict:
    first = json.loads(first_line(path))
    last = json.loads(last_line(path))
    first_height, first_hash = qc_height_hash(first)
    last_height, last_hash = qc_height_hash(last)
    return {
        "path": str(path),
        "first_height": first_height,
        "first_hash": first_hash,
        "last_height": last_height,
        "last_hash": last_hash,
        "size_bytes": path.stat().st_size,
        "sha256": None,
    }


def committed_blocks_summary(path: Path) -> dict:
    first = json.loads(first_line(path))
    last = json.loads(last_line(path))
    first_height, first_hash = committed_block_height_hash(first)
    last_height, last_hash = committed_block_height_hash(last)
    return {
        "path": str(path),
        "first_height": first_height,
        "first_hash": first_hash,
        "last_height": last_height,
        "last_hash": last_hash,
        "size_bytes": path.stat().st_size,
        "sha256": None,
    }


def source_inventory(source: Path) -> tuple[list[str], list[str], list[str]]:
    files = []
    forbidden = []
    unexpected = []
    for item in sorted(source.rglob("*")):
        if item.is_dir():
            continue
        rel = item.relative_to(source).as_posix()
        if item.name.startswith("._") or rel.startswith("__MACOSX/"):
            continue
        files.append(rel)
        name = item.name
        if any(pattern.search(rel) or pattern.search(name) for pattern in FORBIDDEN_SOURCE_NAME_PATTERNS):
            forbidden.append(rel)
        if "/" in rel or rel not in STATE_COPY_ALLOWLIST:
            unexpected.append(rel)
    return files, forbidden, unexpected


def hardlink_or_copy(src: Path, dst: Path) -> str:
    dst.parent.mkdir(parents=True, exist_ok=True)
    if dst.exists() or dst.is_symlink():
        dst.unlink()
    try:
        os.link(src, dst)
        return "hardlinked"
    except OSError:
        shutil.copy2(src, dst)
        return "copied"


def archive_existing_state(target_root: Path, archive_dir: Path, names: list[str]) -> dict:
    files_dir = archive_dir / "files"
    files_dir.mkdir(parents=True, exist_ok=True)
    manifest = []
    for name in names:
        src = target_root / name
        if not src.exists() and not src.is_symlink():
            continue
        dst = files_dir / name
        action = "skipped"
        sha = None
        if src.is_file():
            action = hardlink_or_copy(src, dst)
            sha = sha256_file(dst) if dst.stat().st_size <= LARGE_FILE_FAST_SUMMARY_BYTES else None
        elif src.is_symlink():
            dst.parent.mkdir(parents=True, exist_ok=True)
            dst.symlink_to(os.readlink(src))
            action = "symlink_recorded"
        manifest.append(
            {
                "path": name,
                "source": str(src),
                "archive": str(dst),
                "action": action,
                "sha256": sha,
                "size_bytes": dst.stat().st_size if dst.exists() and dst.is_file() else None,
            }
        )
    manifest_path = archive_dir / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    checksums_path = archive_dir / "SHA256SUMS"
    with checksums_path.open("w", encoding="utf-8") as handle:
        for entry in manifest:
            if entry["sha256"]:
                handle.write(f"{entry['sha256']}  files/{entry['path']}\n")
    archive_digest = sha256_file(checksums_path) if checksums_path.exists() else None
    return {
        "archive_dir": str(archive_dir),
        "manifest": str(manifest_path),
        "checksums": str(checksums_path),
        "checksums_sha256": archive_digest,
        "file_count": len(manifest),
        "listed_ok": files_dir.is_dir() and manifest_path.is_file(),
        "files": manifest,
    }


def stage_source(source: Path, stage_dir: Path, copied_names: list[str]) -> dict:
    stage_dir.mkdir(parents=True, exist_ok=False)
    copied = []
    for name in copied_names:
        src = source / name
        if not src.is_file():
            continue
        dst = stage_dir / name
        action = hardlink_or_copy(src, dst)
        copied.append(
            {
                "path": name,
                "source": str(src),
                "staged": str(dst),
                "action": action,
                "sha256": sha256_file(dst) if dst.stat().st_size <= LARGE_FILE_FAST_SUMMARY_BYTES else None,
                "size_bytes": dst.stat().st_size,
            }
        )
    return {"stage_dir": str(stage_dir), "files": copied}


def verify_helper(
    helper: Path,
    state_root: Path,
    report_dir: Path,
    expected_chain_id: str,
    expected_network_id: str,
    allow_testnet_recovery_checkpoint: bool,
) -> dict:
    if not helper.is_file() or not os.access(helper, os.X_OK):
        return {"available": False, "ok": False, "detail": f"helper not executable: {helper}"}
    report_dir.mkdir(parents=True, exist_ok=True)
    inspect_path = report_dir / "inspect-state.json"
    verify_path = report_dir / "verify-state.json"
    inspect_rc, inspect_out, inspect_err = run_text(
        [
            str(helper),
            "validator",
            "inspect-state",
            "--state-root",
            str(state_root),
            "--chain-id",
            expected_chain_id,
            "--network-id",
            expected_network_id,
        ]
    )
    inspect_path.write_text(inspect_out or inspect_err)
    verify_command = [
        str(helper),
        "validator",
        "verify-state",
        "--state-root",
        str(state_root),
        "--chain-id",
        expected_chain_id,
        "--network-id",
        expected_network_id,
    ]
    if allow_testnet_recovery_checkpoint:
        verify_command.append("--allow-testnet-recovery-checkpoint")
    verify_rc, verify_out, verify_err = run_text(verify_command)
    verify_path.write_text(verify_out or verify_err)
    return {
        "available": True,
        "ok": inspect_rc == 0 and verify_rc == 0,
        "inspect_rc": inspect_rc,
        "inspect_output": str(inspect_path),
        "inspect_stderr": inspect_err[-2000:],
        "verify_rc": verify_rc,
        "verify_command": verify_command,
        "verify_output": str(verify_path),
        "verify_stderr": verify_err[-2000:],
        "allow_testnet_recovery_checkpoint": allow_testnet_recovery_checkpoint,
    }


def chown_paths(paths: list[Path], user: str, group: str) -> None:
    uid = pwd.getpwnam(user).pw_uid
    gid = grp.getgrnam(group).gr_gid
    for path in paths:
        try:
            os.chown(path, uid, gid)
        except PermissionError:
            raise


def replace_active_files(stage_dir: Path, target_root: Path, names: list[str]) -> list[dict]:
    replaced = []
    for name in names:
        src = stage_dir / name
        if not src.exists():
            continue
        dst = target_root / name
        dst.parent.mkdir(parents=True, exist_ok=True)
        os.replace(src, dst)
        replaced.append({
            "path": name,
            "target": str(dst),
            "sha256": sha256_file(dst) if dst.stat().st_size <= LARGE_FILE_FAST_SUMMARY_BYTES else None,
        })
    return replaced


def remove_stale_target_files(target_root: Path, names: list[str]) -> list[str]:
    removed = []
    for name in names:
        path = target_root / name
        if path.exists() or path.is_symlink():
            if path.is_dir():
                shutil.rmtree(path)
            else:
                path.unlink()
            removed.append(str(path))
    return removed


def write_json(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--dry-run", action="store_true")
    mode.add_argument("--apply", action="store_true")
    parser.add_argument("--validator-name", default="Val2")
    parser.add_argument("--source-state-dir", required=True, type=Path)
    parser.add_argument("--target-root", default=APPLIANCE_ROOT, type=Path)
    parser.add_argument("--config-root", default=CONFIG_ROOT, type=Path)
    parser.add_argument("--old-workspace", default=OLD_WORKSPACE, type=Path)
    parser.add_argument("--service-name", default=SERVICE_NAME)
    parser.add_argument("--service-path", default=SERVICE_PATH, type=Path)
    parser.add_argument("--archive-root", default=ARCHIVE_ROOT, type=Path)
    parser.add_argument("--staging-root", default=Path("/var/lib/synergy"), type=Path)
    parser.add_argument("--report-dir", type=Path)
    parser.add_argument("--helper", default=Path("/opt/synergy/bin/synergy-node"), type=Path)
    parser.add_argument("--runtime-user", default="node")
    parser.add_argument("--runtime-group", default="node")
    parser.add_argument("--expected-chain-id", default="1264")
    parser.add_argument("--expected-network-id", default="synergy-testnet-v3")
    parser.add_argument("--expected-genesis-hash", default=EXPECTED_GENESIS_HASH)
    parser.add_argument("--expected-source-tip-height", type=int)
    parser.add_argument("--expected-source-tip-hash")
    parser.add_argument("--allow-testnet-recovery-checkpoint", action="store_true")
    parser.add_argument("--no-systemd", action="store_true")
    parser.add_argument("--skip-helper-verify", action="store_true")
    parser.add_argument("--skip-chown", action="store_true")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    stamp = now_stamp()
    apply = bool(args.apply)
    if not args.apply and not args.dry_run:
        apply = False
    validator_slug = safe_name(args.validator_name).lower()
    report_dir = args.report_dir or (
        args.target_root / "evidence" / f"{validator_slug}-cold-canonical-snapshot-restore-{stamp}"
    )
    archive_dir = args.archive_root / f"{validator_slug}-pre-snapshot-restore-{stamp}"
    stage_dir = args.staging_root / f".{validator_slug}-cold-restore-stage-{stamp}"
    findings: list[Finding] = []

    service = service_state(args.service_name, args.no_systemd)
    processes = process_check()
    if service["active"]:
        findings.append(Finding("error", "validator_service_active", args.service_name))
    if processes["running"]:
        findings.append(Finding("error", "validator_process_running", processes["stdout"]))
    if not args.source_state_dir.is_dir():
        findings.append(Finding("error", "source_state_dir_missing", str(args.source_state_dir)))
    if not args.target_root.is_dir():
        findings.append(Finding("error", "target_root_missing", str(args.target_root)))
    if not args.config_root.is_dir():
        findings.append(Finding("error", "config_root_missing", str(args.config_root)))
    try:
        source_real = args.source_state_dir.resolve()
        target_real = args.target_root.resolve()
        stage_real_parent = args.staging_root.resolve()
        if source_real == target_real or source_real in target_real.parents or target_real in source_real.parents:
            findings.append(Finding("error", "unsafe_source_target_overlap", f"{source_real} <> {target_real}"))
        if stage_real_parent == target_real or stage_real_parent in source_real.parents:
            findings.append(Finding("error", "unsafe_staging_overlap", str(stage_real_parent)))
    except OSError as error:
        findings.append(Finding("error", "path_resolution_failed", str(error)))

    source_files, forbidden_source, unexpected_source = source_inventory(args.source_state_dir) if args.source_state_dir.is_dir() else ([], [], [])
    if forbidden_source:
        findings.append(Finding("error", "source_contains_forbidden_identity_or_key_material", json.dumps(forbidden_source)))
    if unexpected_source:
        findings.append(Finding("error", "source_contains_unexpected_files", json.dumps(unexpected_source)))
    for required in REQUIRED_SOURCE_FILES:
        if not (args.source_state_dir / required).is_file():
            findings.append(Finding("error", "source_required_file_missing", required))

    config_text = "\n".join(
        read_text_if_exists(path)
        for path in [
            args.config_root / "config.toml",
            args.config_root / "node.env",
            args.config_root / "service.env",
            args.config_root / "genesis.json",
        ]
    )
    if args.expected_network_id not in config_text:
        findings.append(Finding("error", "target_network_id_not_verified", args.expected_network_id))
    if args.expected_chain_id not in config_text:
        findings.append(Finding("error", "target_chain_id_not_verified", args.expected_chain_id))
    if args.expected_genesis_hash not in config_text:
        findings.append(Finding("warning", "target_genesis_hash_not_visible_in_config_text", args.expected_genesis_hash))

    identity_before = discover_validator_identity(args.config_root)
    copied_names = [name for name in STATE_COPY_ALLOWLIST if (args.source_state_dir / name).is_file()]
    stale_target_names = [name for name in TARGET_STALE_STATE_FILES if name not in copied_names]
    source_summary = {}
    try:
        if not any(f.severity == "error" for f in findings):
            chain = quick_chain_summary(args.source_state_dir / "chain.json")
            committed_blocks = None
            committed_blocks_path = args.source_state_dir / "committed_blocks.jsonl"
            if committed_blocks_path.is_file():
                committed_blocks = committed_blocks_summary(committed_blocks_path)
            qcs = qc_summary(args.source_state_dir / "committed_qcs.jsonl")
            effective_tip = {
                "source": "committed_blocks" if committed_blocks else "chain",
                "height": (committed_blocks or chain)["last_height"] if committed_blocks else chain["tip_height"],
                "hash": (committed_blocks or chain)["last_hash"] if committed_blocks else chain["tip_hash"],
            }
            locks = load_locks_summary(
                args.source_state_dir / "canonical_locks.json",
                [height for height in [chain["tip_height"], effective_tip["height"], qcs["last_height"]] if height is not None],
            )
            source_summary = {
                "chain": chain,
                "committed_blocks": committed_blocks,
                "committed_qcs": qcs,
                "canonical_locks": locks,
                "effective_tip": effective_tip,
            }
            if args.expected_source_tip_height is not None and effective_tip["height"] != args.expected_source_tip_height:
                findings.append(Finding("error", "source_tip_height_mismatch", f"{effective_tip['height']} != {args.expected_source_tip_height}"))
            if args.expected_source_tip_hash and effective_tip["hash"] != args.expected_source_tip_hash.lower():
                findings.append(Finding("error", "source_tip_hash_mismatch", f"{effective_tip['hash']} != {args.expected_source_tip_hash.lower()}"))
            tip_lock = locks["selected_hashes"].get(str(effective_tip["height"]))
            if tip_lock and tip_lock.lower() != effective_tip["hash"]:
                findings.append(Finding("error", "source_tip_lock_hash_mismatch", f"{tip_lock} != {effective_tip['hash']}"))
            qc_lock = locks["selected_hashes"].get(str(qcs["last_height"]))
            if qc_lock and qc_lock.lower() != qcs["last_hash"]:
                findings.append(Finding("error", "source_qc_lock_hash_mismatch", f"{qc_lock} != {qcs['last_hash']}"))
            if qcs["last_height"] and effective_tip["height"] and qcs["last_height"] > effective_tip["height"]:
                findings.append(Finding("error", "source_qc_tail_above_effective_tip", f"{qcs['last_height']} > {effective_tip['height']}"))
            if qcs["last_height"] and effective_tip["height"] and qcs["last_height"] == effective_tip["height"] and qcs["last_hash"] != effective_tip["hash"]:
                findings.append(Finding("error", "source_qc_tail_effective_tip_hash_mismatch", f"{qcs['last_hash']} != {effective_tip['hash']}"))
            if chain["tip_height"] and effective_tip["height"] and chain["tip_height"] > effective_tip["height"]:
                findings.append(Finding("error", "source_chain_tip_above_effective_tip", f"{chain['tip_height']} > {effective_tip['height']}"))
    except Exception as error:
        findings.append(Finding("error", "source_integrity_check_failed", f"{type(error).__name__}: {error}"))

    pre_state = {name: file_info(args.target_root / name, hash_file=False) for name in STATE_COPY_ALLOWLIST + TARGET_STALE_STATE_FILES}
    report = {
        "format": "synergy-validator-cold-canonical-snapshot-restore-v1",
        "timestamp": stamp,
        "validator_name": args.validator_name,
        "dry_run": not apply,
        "apply": apply,
        "service": service,
        "process_check": processes,
        "source_state_dir": str(args.source_state_dir),
        "source_files": source_files,
        "source_summary": source_summary,
        "target_root": str(args.target_root),
        "config_root": str(args.config_root),
        "old_workspace": file_info(args.old_workspace),
        "identity_before": identity_before,
        "pre_restore_state": pre_state,
        "files_to_copy": copied_names,
        "files_excluded": {
            "source_identity_key_config_files": forbidden_source,
            "target_identity_config_root_preserved": str(args.config_root),
            "copy_allowlist": STATE_COPY_ALLOWLIST,
            "target_stale_state_files_archived_and_removed": stale_target_names,
            "configured_target_stale_state_files": TARGET_STALE_STATE_FILES,
        },
        "archive": None,
        "stage": None,
        "replaced_files": [],
        "removed_stale_target_files": [],
        "helper_verification": None,
        "identity_after": None,
        "findings": [dataclasses.asdict(f) for f in findings],
    }

    if any(f.severity == "error" for f in findings):
        report["ok"] = False
        report["decision"] = "NO_GO"
        print(json.dumps(report, indent=2, sort_keys=True))
        return 1

    if not apply:
        report["ok"] = True
        report["decision"] = "DRY_RUN_GO"
        report["archive"] = {
            "archive_dir": str(archive_dir),
            "would_archive": [name for name, info in pre_state.items() if info["exists"]],
        }
        report["stage"] = {"stage_dir": str(stage_dir), "would_stage": copied_names}
        print(json.dumps(report, indent=2, sort_keys=True))
        return 0

    if stage_dir.exists():
        findings.append(Finding("error", "stage_dir_exists", str(stage_dir)))
        report["ok"] = False
        report["decision"] = "NO_GO"
        report["findings"] = [dataclasses.asdict(f) for f in findings]
        print(json.dumps(report, indent=2, sort_keys=True))
        return 1

    report_dir.mkdir(parents=True, exist_ok=True)
    archive_names = copied_names + [name for name in stale_target_names if (args.target_root / name).exists()]
    archive = archive_existing_state(args.target_root, archive_dir, archive_names)
    stage = stage_source(args.source_state_dir, stage_dir, copied_names)
    helper_stage = None
    if not args.skip_helper_verify:
        helper_stage = verify_helper(
            args.helper,
            stage_dir,
            report_dir / "staged-helper-verification",
            args.expected_chain_id,
            args.expected_network_id,
            args.allow_testnet_recovery_checkpoint,
        )
        if not helper_stage["ok"]:
            findings.append(Finding("error", "staged_helper_verification_failed", json.dumps(helper_stage)))
    if any(f.severity == "error" for f in findings):
        report.update({"archive": archive, "stage": stage, "helper_verification": {"stage": helper_stage}})
        report["ok"] = False
        report["decision"] = "NO_GO"
        report["findings"] = [dataclasses.asdict(f) for f in findings]
        write_json(report_dir / f"{validator_slug}-cold-restore-report.json", report)
        print(json.dumps(report, indent=2, sort_keys=True))
        return 1

    replaced = replace_active_files(stage_dir, args.target_root, copied_names)
    removed = remove_stale_target_files(args.target_root, stale_target_names)
    shutil.rmtree(stage_dir, ignore_errors=True)
    if not args.skip_chown:
        chown_paths([args.target_root, *[args.target_root / item["path"] for item in replaced]], args.runtime_user, args.runtime_group)
    helper_active = None
    if not args.skip_helper_verify:
        helper_active = verify_helper(
            args.helper,
            args.target_root,
            report_dir / "active-helper-verification",
            args.expected_chain_id,
            args.expected_network_id,
            args.allow_testnet_recovery_checkpoint,
        )
        if not helper_active["ok"]:
            findings.append(Finding("error", "active_helper_verification_failed", json.dumps(helper_active)))
    identity_after = discover_validator_identity(args.config_root)
    if identity_after != identity_before:
        findings.append(Finding("error", "target_identity_changed", json.dumps({"before": identity_before, "after": identity_after})))

    report.update(
        {
            "archive": archive,
            "stage": stage,
            "replaced_files": replaced,
            "removed_stale_target_files": removed,
            "helper_verification": {"stage": helper_stage, "active": helper_active},
            "identity_after": identity_after,
            "post_restore_state": {name: file_info(args.target_root / name, hash_file=True) for name in copied_names},
            "findings": [dataclasses.asdict(f) for f in findings],
        }
    )
    report["ok"] = not any(f.severity == "error" for f in findings)
    report["decision"] = "GO" if report["ok"] else "NO_GO"
    write_json(report_dir / f"{validator_slug}-cold-restore-report.json", report)
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
