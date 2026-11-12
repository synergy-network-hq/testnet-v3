#!/usr/bin/env python3
"""Prepare existing ReleaseMetadata v2 for explicit trust-root signing.

This command creates only the requested unsigned metadata, never reads a secret,
and does not deploy or infer governed protocol/schema versions.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re


def positive(value):
    parsed = int(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be positive")
    return parsed


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--release-id", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--sequence", type=positive, required=True)
    parser.add_argument("--published-at", type=positive, required=True)
    parser.add_argument("--source", required=True)
    parser.add_argument("--config-schema", type=positive, required=True)
    parser.add_argument("--database-schema", type=positive, required=True)
    parser.add_argument("--protocol", action="append", required=True,
                        help="governed component=version; repeat for each component")
    args = parser.parse_args()
    if not re.fullmatch(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)", args.version):
        parser.error("version must be canonical major.minor.patch")
    versions = [int(part) for part in args.version.split(".")]
    if any(version > 65535 for version in versions):
        parser.error("release version component exceeds u16")
    if not args.release_id or len(args.release_id) > 256 or not args.source:
        parser.error("release ID/source is invalid")
    protocols = {}
    for item in args.protocol:
        component, separator, version = item.partition("=")
        if not separator or component not in {"p2p", "posy", "etdag", "sync", "snapshot", "admin"}:
            parser.error("invalid protocol component/version")
        if component in protocols:
            parser.error("duplicate protocol component")
        protocols[component] = positive(version)
        if protocols[component] > 0xFFFFFFFF:
            parser.error("protocol version exceeds u32")
    if args.binary.is_symlink() or not args.binary.is_file():
        parser.error("binary must be a regular non-symlink file")
    length = args.binary.stat().st_size
    if not 64 <= length <= 256 * 1024 * 1024:
        parser.error("binary length outside release-tool bounds")
    digest = hashlib.sha3_256()
    with args.binary.open("rb") as binary:
        header = binary.read(64)
        if (header[:7] != b"\x7fELF\x02\x01\x01" or header[18:20] != b"\x3e\x00"
                or int.from_bytes(header[16:18], "little") not in (2, 3)
                or header[20:24] != b"\x01\x00\x00\x00"):
            parser.error("binary must be Linux x86-64 ELF")
        digest.update(header)
        for chunk in iter(lambda: binary.read(1024 * 1024), b""):
            digest.update(chunk)
    release = {
        "format_version": 2, "release_id": args.release_id,
        "version": dict(zip(("major", "minor", "patch"), versions)),
        "channel": "candidate", "sequence": args.sequence,
        "published_at_unix_seconds": args.published_at,
        "artifact": {"platform": "x86_64-unknown-linux-gnu", "length": length,
                     "sha3_256": digest.hexdigest(), "source": args.source},
        "protocols": sorted(protocols.items()), "config_schema": args.config_schema,
        "database_schema": args.database_schema, "protocol_activation_commitment": None,
    }
    with args.output.open("x", encoding="utf-8") as output:
        json.dump(release, output, indent=2)
        output.write("\n")
        output.flush()
        os.fsync(output.fileno())
    print("unsigned release metadata prepared; signature verification still required")


if __name__ == "__main__":
    main()
