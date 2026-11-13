#!/usr/bin/env python3
"""Reconcile support-node fork/allowlist config from a signed snapshot manifest."""

from __future__ import annotations

import argparse
import json
import re
import shutil
import time
from pathlib import Path


def load_manifest(path: Path) -> dict:
    raw = json.loads(path.read_text(encoding="utf-8"))
    return raw.get("manifest", raw)


def replace_allowed_validator_addresses(config_text: str, addresses: list[str]) -> str:
    encoded = json.dumps(addresses)
    pattern = re.compile(r"(^\s*allowed_validator_addresses\s*=\s*)\[(.*?)\]", re.M | re.S)
    replacement = rf"\1{encoded}"
    updated, count = pattern.subn(replacement, config_text, count=1)
    if count:
        return updated
    if re.search(r"^\s*\[node\]\s*$", config_text, re.M):
        return re.sub(
            r"(^\s*\[node\]\s*$)",
            rf"\1\nallowed_validator_addresses = {encoded}",
            config_text,
            count=1,
            flags=re.M,
        )
    return config_text.rstrip() + f"\n\n[node]\nallowed_validator_addresses = {encoded}\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--snapshot-manifest", type=Path, required=True)
    parser.add_argument("--node-config", type=Path, required=True)
    parser.add_argument("--fork-config", type=Path, required=True)
    parser.add_argument("--backup-dir", type=Path, required=True)
    args = parser.parse_args()

    manifest = load_manifest(args.snapshot_manifest)
    snapshot_class = str(manifest.get("snapshot_class") or "")
    if not snapshot_class.startswith("support-") and not snapshot_class.startswith("indexer-"):
        raise SystemExit(f"refusing non-support snapshot class: {snapshot_class}")
    active_validator_set = manifest.get("active_validator_set")
    if not isinstance(active_validator_set, list) or not all(
        isinstance(address, str) and address for address in active_validator_set
    ):
        raise SystemExit("snapshot manifest is missing active_validator_set")
    consensus_fork = manifest.get("consensus_fork")
    if not isinstance(consensus_fork, dict):
        raise SystemExit("snapshot manifest is missing consensus_fork metadata")

    timestamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    backup_dir = args.backup_dir / f"support-config-reconcile-{timestamp}"
    backup_dir.mkdir(parents=True, exist_ok=True)
    for path in (args.node_config, args.fork_config):
        if path.exists():
            shutil.copy2(path, backup_dir / path.name)

    node_text = args.node_config.read_text(encoding="utf-8")
    args.node_config.write_text(
        replace_allowed_validator_addresses(node_text, active_validator_set),
        encoding="utf-8",
    )
    args.fork_config.write_text(
        json.dumps(consensus_fork, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    print(
        json.dumps(
            {
                "support_config_reconciled": True,
                "snapshot_class": snapshot_class,
                "snapshot_height": manifest.get("snapshot_height"),
                "active_validator_count": len(active_validator_set),
                "quorum_threshold": manifest.get("quorum_threshold"),
                "node_config": str(args.node_config),
                "fork_config": str(args.fork_config),
                "backup_dir": str(backup_dir),
                "keys_or_consensus_state_copied": False,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
