#!/usr/bin/env python3
"""Verify a coordinator-signed Testnet-v3 validator transport snapshot.

This is an offline preflight only: it never contacts the coordinator, SSHes a
node, writes a registry, or handles a private key.  It verifies the exact
payload format consumed by ``runtime/src/p2p/validator_transport_registry.rs``
and then proves that the snapshot maps *exactly* the active validators in the
specified Testnet-v3 Genesis document.

The coordinator snapshot is a transport routing artefact, not a consensus
authority.  Nevertheless a valid signature alone is insufficient for a
launch: an older network can use the same coordinator and signing key.  The
Genesis-set comparison prevents an otherwise valid, but wrong-network, signed
snapshot from satisfying the Testnet-v3 transport gate.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any


DEFAULT_PUBLIC_KEY = "ed25519:0tA5eh5BHCPxXFUlHtb5+GOJFPqLhmnxDOqli39Y+iI="
DEFAULT_NETWORK = "synergy-innernet-membership-v1"
DEFAULT_MIGRATION_ID = "synergy-testnet-innernet-v19-14450ae4d67455c7"
MAX_SNAPSHOT_BYTES = 256 * 1024
VALIDATOR_ADDRESS_RE = re.compile(r"^synv1[a-z0-9]{4,123}$")


@dataclass
class Finding:
    status: str
    name: str
    detail: str


def add(findings: list[Finding], status: str, name: str, detail: str) -> None:
    findings.append(Finding(status=status, name=name, detail=detail))


def read_json(path: Path, limit: int | None = None) -> Any:
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise ValueError(f"cannot stat {path}: {exc}") from exc
    if limit is not None and size > limit:
        raise ValueError(f"{path} exceeds {limit} byte limit")
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot parse JSON {path}: {exc}") from exc


def decode_prefixed_base64(value: Any, label: str, *prefixes: str) -> bytes:
    text = str(value or "").strip()
    for prefix in prefixes:
        if text.startswith(prefix):
            text = text[len(prefix) :]
            break
    else:
        expected = " or ".join(prefixes)
        raise ValueError(f"{label} must use {expected}")
    try:
        return base64.b64decode(text, validate=True)
    except Exception as exc:  # noqa: BLE001 - report invalid input cleanly
        raise ValueError(f"{label} is not valid base64") from exc


def rust_signed_payload(snapshot: dict[str, Any]) -> bytes:
    """Mirror serde_json::json! serialization used by the Rust verifier.

    ``serde_json::Map`` is key-sorted without the preserve_order feature.  The
    nested transport objects are maps too, so sort every object key while
    retaining the coordinator-provided transport vector order.
    """

    payload = {
        "version": snapshot.get("version"),
        "network": snapshot.get("network"),
        "migration_id": snapshot.get("migration_id"),
        "configuration_version": snapshot.get("configuration_version"),
        "transports": snapshot.get("transports"),
    }
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def verify_ed25519(public_key: str, signature: str, payload: bytes) -> None:
    public = decode_prefixed_base64(public_key, "coordinator public key", "ed25519:", "base64:")
    signature_bytes = decode_prefixed_base64(signature, "snapshot signature", "ed25519:")
    if len(public) != 32:
        raise ValueError("coordinator public key must decode to 32 bytes")
    if len(signature_bytes) != 64:
        raise ValueError("snapshot signature must decode to 64 bytes")

    # SubjectPublicKeyInfo DER for an Ed25519 raw 32-byte key.  OpenSSL is used
    # because this checker intentionally has no third-party Python dependency.
    der = bytes.fromhex("302a300506032b6570032100") + public
    pem = "-----BEGIN PUBLIC KEY-----\n"
    pem += "\n".join(
        base64.b64encode(der).decode("ascii")[index : index + 64]
        for index in range(0, len(base64.b64encode(der).decode("ascii")), 64)
    )
    pem += "\n-----END PUBLIC KEY-----\n"
    with tempfile.TemporaryDirectory(prefix="synergy-transport-verify-") as directory:
        root = Path(directory)
        public_path = root / "coordinator-public.pem"
        payload_path = root / "snapshot-payload.json"
        signature_path = root / "snapshot.sig"
        public_path.write_text(pem, encoding="ascii")
        payload_path.write_bytes(payload)
        signature_path.write_bytes(signature_bytes)
        result = subprocess.run(
            [
                "openssl",
                "pkeyutl",
                "-verify",
                "-pubin",
                "-inkey",
                str(public_path),
                "-rawin",
                "-in",
                str(payload_path),
                "-sigfile",
                str(signature_path),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "verification failed").strip()
        raise ValueError(f"Ed25519 signature verification failed: {detail}")


def validate_runtime_schema(
    snapshot: dict[str, Any], expected_network: str, expected_migration_id: str, minimum_generation: int
) -> dict[str, str]:
    if snapshot.get("version") != 1:
        raise ValueError(f"unsupported snapshot version {snapshot.get('version')!r}")
    if snapshot.get("network") != expected_network:
        raise ValueError(f"unexpected snapshot network {snapshot.get('network')!r}")
    if snapshot.get("migration_id") != expected_migration_id:
        raise ValueError(f"unexpected migration_id {snapshot.get('migration_id')!r}")
    generation = snapshot.get("configuration_version")
    if not isinstance(generation, int) or isinstance(generation, bool) or generation <= 0:
        raise ValueError("configuration_version must be a positive integer")
    if generation < minimum_generation:
        raise ValueError(
            f"configuration_version {generation} is below the required minimum {minimum_generation}; "
            "a node that persisted the previous coordinator snapshot would reject it as a rollback or equivocation"
        )
    transports = snapshot.get("transports")
    if not isinstance(transports, list) or not transports:
        raise ValueError("snapshot has no transports")

    result: dict[str, str] = {}
    dial_addresses: set[str] = set()
    for index, transport in enumerate(transports):
        if not isinstance(transport, dict):
            raise ValueError(f"transport {index} is not an object")
        validator = transport.get("validator_address")
        dial = transport.get("dial_address")
        if not isinstance(validator, str) or not VALIDATOR_ADDRESS_RE.fullmatch(validator):
            raise ValueError(f"transport {index} has invalid validator address {validator!r}")
        if not isinstance(dial, str):
            raise ValueError(f"transport {index} has invalid dial address {dial!r}")
        host, separator, port = dial.rpartition(":")
        if not separator or port != "5622":
            raise ValueError(f"transport {index} has invalid dial port {dial!r}")
        match = re.fullmatch(r"10\.70\.10\.(\d{1,3})", host)
        if not match or not 1 <= int(match.group(1)) <= 255:
            raise ValueError(f"transport {index} has unsafe validator dial address {dial!r}")
        if validator in result:
            raise ValueError(f"duplicate validator address {validator}")
        if dial in dial_addresses:
            raise ValueError(f"duplicate validator dial address {dial}")
        result[validator] = dial
        dial_addresses.add(dial)
    return result


def active_genesis_validator_addresses(genesis: dict[str, Any]) -> set[str]:
    validators = genesis.get("validators")
    if not isinstance(validators, list) or not validators:
        raise ValueError("Genesis has no validators list")
    addresses: set[str] = set()
    for index, validator in enumerate(validators):
        if not isinstance(validator, dict):
            raise ValueError(f"Genesis validator {index} is not an object")
        if validator.get("status") != "active_at_genesis":
            raise ValueError(
                f"Genesis validator {validator.get('validator_id', index)!r} is not active_at_genesis"
            )
        address = validator.get("operator_address")
        if not isinstance(address, str) or not VALIDATOR_ADDRESS_RE.fullmatch(address):
            raise ValueError(f"Genesis validator {validator.get('validator_id', index)!r} has invalid operator_address")
        if address in addresses:
            raise ValueError(f"Genesis has duplicate active validator address {address}")
        addresses.add(address)
    return addresses


def report(
    findings: list[Finding], snapshot_path: Path, genesis_path: Path, output: Path | None
) -> int:
    passed = sum(item.status == "PASS" for item in findings)
    failed = sum(item.status == "FAIL" for item in findings)
    payload = {
        "check": "testnet-v3-coordinator-signed-validator-transport-registry",
        "snapshot": str(snapshot_path),
        "genesis": str(genesis_path),
        "passed": passed,
        "failed": failed,
        "status": "PASS" if failed == 0 else "FAIL",
        "findings": [asdict(item) for item in findings],
    }
    encoded = json.dumps(payload, indent=2, sort_keys=True) + "\n"
    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(encoded, encoding="utf-8")
    print(encoded, end="")
    return 0 if failed == 0 else 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--snapshot", required=True, type=Path, help="Downloaded coordinator snapshot JSON")
    parser.add_argument(
        "--genesis",
        type=Path,
        default=Path("genesis.testnet-v3.identity-assigned.json"),
        help="Final Testnet-v3 Genesis document (default: %(default)s)",
    )
    parser.add_argument("--public-key", default=DEFAULT_PUBLIC_KEY, help="Pinned Ed25519 coordinator public key")
    parser.add_argument("--network", default=DEFAULT_NETWORK, help="Expected snapshot network")
    parser.add_argument("--migration-id", default=DEFAULT_MIGRATION_ID, help="Expected migration id")
    parser.add_argument(
        "--minimum-generation",
        type=int,
        default=1,
        help="Reject a snapshot below this coordinator generation (default: %(default)s)",
    )
    parser.add_argument("--output", type=Path, help="Optional JSON report path")
    args = parser.parse_args()

    findings: list[Finding] = []
    if args.minimum_generation < 1:
        parser.error("--minimum-generation must be at least 1")
    try:
        snapshot = read_json(args.snapshot, MAX_SNAPSHOT_BYTES)
        if not isinstance(snapshot, dict):
            raise ValueError("snapshot root is not an object")
        transports = validate_runtime_schema(
            snapshot, args.network, args.migration_id, args.minimum_generation
        )
        add(
            findings,
            "PASS",
            "runtime snapshot schema",
            f"version 1, generation {snapshot['configuration_version']}, {len(transports)} unique transports",
        )
        payload = rust_signed_payload(snapshot)
        verify_ed25519(args.public_key, str(snapshot.get("signature") or ""), payload)
        add(
            findings,
            "PASS",
            "coordinator signature",
            f"Ed25519 verifies; signed payload SHA-256 {hashlib.sha256(payload).hexdigest()}",
        )
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        add(findings, "FAIL", "signed snapshot", str(exc))
        return report(findings, args.snapshot, args.genesis, args.output)

    try:
        genesis = read_json(args.genesis)
        if not isinstance(genesis, dict):
            raise ValueError("Genesis root is not an object")
        expected = active_genesis_validator_addresses(genesis)
        add(findings, "PASS", "Genesis active validator set", f"{len(expected)} active validators")
        actual = set(transports)
        missing = sorted(expected - actual)
        unexpected = sorted(actual - expected)
        if missing or unexpected:
            parts: list[str] = []
            if missing:
                parts.append("missing=" + ",".join(missing))
            if unexpected:
                parts.append("unexpected=" + ",".join(unexpected))
            raise ValueError("signed transport set does not exactly match active Testnet-v3 Genesis validators: " + "; ".join(parts))
        add(findings, "PASS", "Genesis transport-set binding", "signed transports exactly match active Testnet-v3 Genesis validators")
    except (OSError, ValueError) as exc:
        add(findings, "FAIL", "Genesis transport-set binding", str(exc))

    return report(findings, args.snapshot, args.genesis, args.output)


if __name__ == "__main__":
    sys.exit(main())
