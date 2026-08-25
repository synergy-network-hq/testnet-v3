#!/usr/bin/env python3
"""Derive the public H1/H2/H3 ingress registry set from a verified H3 record."""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
from pathlib import Path
from typing import Any


FORMAT = "synergy-posy-simplified-ingress-kem-registry-v1"
DOMAIN = "PoSy/ETDAG/IngressKemKeyRegistry/v3"
TARGET_HEIGHTS = (1, 2, 3)


def fail(message: str) -> "NoReturn":
    raise SystemExit(f"generate-posy-v3-bootstrap-ingress-registries: {message}")


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def registry_root(registry: dict[str, Any]) -> str:
    payload = canonical_json([
        registry["registry_version"], registry["chain_id"], registry["network_id"],
        registry["protocol_version"], registry["epoch"], registry["target_height"],
        registry["assigned_cluster_id"], registry["records"],
    ])
    domain = DOMAIN.encode("utf-8")
    digest = hashlib.sha3_512()
    digest.update(struct.pack(">Q", len(domain)))
    digest.update(domain)
    digest.update(struct.pack(">Q", len(payload)))
    digest.update(payload)
    return digest.hexdigest()


def read_verified_h3(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        fail("source H3 registry must be a regular file")
    try:
        encoded = path.read_bytes()
        wrapper = json.loads(encoded)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        fail(f"cannot read source H3 registry: {error}")
    if not isinstance(wrapper, dict) or canonical_json(wrapper) != encoded:
        fail("source H3 registry must be exact canonical JSON")
    required = {
        "format", "epoch_context_root", "epoch", "target_height", "assigned_cluster_id",
        "registry_root", "registry",
    }
    registry = wrapper.get("registry")
    if (set(wrapper) != required or wrapper.get("format") != FORMAT or wrapper.get("epoch") != 0
            or wrapper.get("target_height") != 3 or wrapper.get("assigned_cluster_id") != 0
            or not isinstance(registry, dict) or registry.get("target_height") != 3
            or wrapper.get("registry_root") != registry_root(registry)):
        fail("source H3 registry fails its immutable target/root binding")
    root = wrapper.get("epoch_context_root")
    if not (isinstance(root, list) and len(root) == 32
            and all(isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= 255
                    for value in root)):
        fail("source H3 registry has an invalid epoch-context root")
    return wrapper


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-h3", required=True, type=Path)
    parser.add_argument("--output-root", required=True, type=Path)
    args = parser.parse_args()

    source = read_verified_h3(args.source_h3.resolve())
    output_root = args.output_root.resolve()
    if output_root.exists() or output_root.is_symlink():
        fail(f"refusing to replace existing output root: {output_root}")
    epoch_root = bytes(source["epoch_context_root"]).hex()
    registry_directory = output_root / epoch_root
    registry_directory.mkdir(parents=True)
    for target_height in TARGET_HEIGHTS:
        registry = dict(source["registry"])
        registry["target_height"] = target_height
        wrapper = {
            "format": FORMAT,
            "epoch_context_root": source["epoch_context_root"],
            "epoch": 0,
            "target_height": target_height,
            "assigned_cluster_id": 0,
            "registry_root": registry_root(registry),
            "registry": registry,
        }
        path = registry_directory / f"epoch-0-height-{target_height}-cluster-0.json"
        try:
            with path.open("xb") as handle:
                handle.write(canonical_json(wrapper))
        except OSError as error:
            fail(f"write {path}: {error}")
    print(f"POSY_V3_BOOTSTRAP_INGRESS_REGISTRIES_READY {registry_directory}")


if __name__ == "__main__":
    main()
