#!/usr/bin/env python3
"""Create a compact support-node state seed from local qRPC and canonical locks."""

from __future__ import annotations

import json
import os
import shutil
import tarfile
import tempfile
import time
import urllib.request
from pathlib import Path


def rpc(url: str, method: str, params: list[object], timeout: int = 60) -> object:
    payload = {"jsonrpc": "2.0", "method": method, "params": params, "id": 1}
    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"content-type": "application/json"},
    )
    response = json.load(urllib.request.urlopen(request, timeout=timeout))
    if "error" in response:
        raise SystemExit(f"{method} failed: {response['error']}")
    return response["result"]


def block_height(block: dict[str, object]) -> int:
    value = block.get("block_index", block.get("height"))
    if value is None:
        raise SystemExit("block is missing block_index/height")
    return int(value)


def block_hash(block: dict[str, object]) -> str:
    value = block.get("hash", block.get("block_hash"))
    if not value:
        raise SystemExit(f"block {block_height(block)} is missing hash")
    return str(value)


def lock_height(key: str, value: object) -> int:
    if isinstance(value, dict):
        height = value.get("height", value.get("block_index"))
        if height is not None:
            return int(height)
    return int(key)


def main() -> int:
    workspace = Path(
        os.environ.get("SYNERGY_WORKSPACE", "~/.synergy/testnet/nodes/validator-workspace")
    ).expanduser()
    data_dir = Path(os.environ.get("SYNERGY_DATA_DIR", workspace / "data")).expanduser()
    qrpc_port = os.environ.get("SYNERGY_QRPC_PORT", "5640")
    rpc_url = os.environ.get("SYNERGY_RPC_URL", f"http://127.0.0.1:{qrpc_port}")
    retain_blocks = int(os.environ.get("SYNERGY_RETAIN_BLOCKS", "2048"))
    if retain_blocks < 32:
        raise SystemExit("SYNERGY_RETAIN_BLOCKS must be at least 32")

    output_root = Path(os.environ.get("SYNERGY_SEED_ROOT", "/tmp")).expanduser()
    output_root.mkdir(parents=True, exist_ok=True)
    timestamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())

    latest = rpc(rpc_url, "synergy_getLatestBlock", [])
    latest_height = block_height(latest)

    locks_path = data_dir / "canonical_locks.json"
    locks = json.loads(locks_path.read_text(encoding="utf-8"))
    if not isinstance(locks, dict) or not locks:
        raise SystemExit("canonical_locks.json must be a non-empty object")

    lock_items: list[tuple[str, dict[str, object], int]] = []
    for key, value in locks.items():
        if not isinstance(value, dict):
            continue
        height = lock_height(key, value)
        if height <= latest_height:
            lock_items.append((str(key), value, height))
    if not lock_items:
        raise SystemExit("no canonical locks at or below latest qRPC height")

    snapshot_tip = max(height for _, _, height in lock_items)
    snapshot_start = max(0, snapshot_tip - retain_blocks + 1)
    blocks = rpc(rpc_url, "synergy_getBlockRange", [snapshot_start, snapshot_tip])
    if not isinstance(blocks, list) or not blocks:
        raise SystemExit("synergy_getBlockRange returned no blocks")

    expected_height = snapshot_start
    previous_hash: str | None = None
    for block in blocks:
        if not isinstance(block, dict):
            raise SystemExit("block range returned a non-object block")
        height = block_height(block)
        if height != expected_height:
            raise SystemExit(f"non-contiguous block range: expected {expected_height}, got {height}")
        parent = str(block.get("previous_hash", block.get("parent_hash", "")))
        if previous_hash is not None and parent != previous_hash:
            raise SystemExit(f"block {height} parent {parent} does not match previous {previous_hash}")
        previous_hash = block_hash(block)
        expected_height += 1
    if block_height(blocks[-1]) != snapshot_tip:
        raise SystemExit("block range did not end at canonical lock tip")

    kept_locks = {
        key: value
        for key, value, height in lock_items
        if snapshot_start <= height <= snapshot_tip
    }
    if str(snapshot_tip) not in kept_locks:
        raise SystemExit("trimmed canonical locks do not include snapshot tip")
    tip_hash = block_hash(blocks[-1])
    tip_lock_hash = kept_locks[str(snapshot_tip)].get("block_hash") or kept_locks[
        str(snapshot_tip)
    ].get("hash")
    if tip_lock_hash != tip_hash:
        raise SystemExit(
            f"snapshot tip hash {tip_hash} does not match canonical lock hash {tip_lock_hash}"
        )

    package_name = f"val2-rpc-state-seed-h{snapshot_tip}-{timestamp}.tar.gz"
    package_path = output_root / package_name
    manifest = {
        "created_at": timestamp,
        "source": os.environ.get("SYNERGY_NODE", "unknown"),
        "rpc_url": rpc_url,
        "retain_blocks": retain_blocks,
        "snapshot_start": snapshot_start,
        "snapshot_height": snapshot_tip,
        "snapshot_hash": tip_hash,
        "latest_qrpc_height": latest_height,
        "chain_blocks": len(blocks),
        "canonical_locks": len(kept_locks),
        "append_journals_reset": True,
        "forbidden_material_copied": False,
    }

    with tempfile.TemporaryDirectory(prefix="synergy-state-seed-") as tmp_raw:
        tmp = Path(tmp_raw)
        out_data = tmp / "data"
        out_data.mkdir(parents=True)
        (out_data / "chain.json").write_text(
            json.dumps(blocks, separators=(",", ":")) + "\n",
            encoding="utf-8",
        )
        (out_data / "canonical_locks.json").write_text(
            json.dumps(kept_locks, separators=(",", ":"), sort_keys=True) + "\n",
            encoding="utf-8",
        )
        for name in (
            "validator_registry.json",
            "token_state.json",
            "dag_state.json",
            "account_state.json",
            "synid_registry.json",
        ):
            source = data_dir / name
            if source.exists():
                shutil.copy2(source, out_data / name)
        (out_data / "committed_blocks.jsonl").write_text("", encoding="utf-8")
        (out_data / "committed_qcs.jsonl").write_text("", encoding="utf-8")
        (tmp / "manifest.json").write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        with tarfile.open(package_path, "w:gz") as archive:
            archive.add(out_data, arcname="data")
            archive.add(tmp / "manifest.json", arcname="manifest.json")

    print(json.dumps({"package": str(package_path), **manifest}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
