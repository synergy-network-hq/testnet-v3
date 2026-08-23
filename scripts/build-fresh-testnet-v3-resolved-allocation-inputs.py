#!/usr/bin/env python3
"""Resolve fresh Testnet-v3 allocation addresses from public identity inputs.

This tool is deliberately public-only.  It never decrypts a bundle and never
reads a passphrase.  The immutable allocation plan remains the amount authority;
identity-bundle amount fields are checked only as provenance metadata because a
governed tokenomics change may supersede them without changing custody keys.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import sys
from typing import Any


CHAIN_ID = 1266
NETWORK_ID = "testnet"
RELEASE_ID = "testnet-v3"
PROTOCOL_VERSION = "posy/3.0"
TOTAL_SUPPLY_NWEI = 12_000_000_000_000_000_000
VALIDATOR_IDS = [f"validator-{ordinal:02d}" for ordinal in range(1, 22)]
VALIDATOR_ACCOUNT_IDS = [f"VNS-A{ordinal:02d}" for ordinal in range(2, 23)]
ACTIVE_VALIDATOR_IDS = [f"validator-{ordinal:02d}" for ordinal in range(2, 7)]
ADDRESS_RE = re.compile(r"^[a-z0-9]{41}$")
HEX_64_RE = re.compile(r"^[0-9a-f]{64}$")


def fail(message: str) -> "NoReturn":
    raise SystemExit(f"build-fresh-testnet-v3-resolved-allocation-inputs: {message}")


def read_bytes(path: Path, label: str) -> bytes:
    try:
        return path.read_bytes()
    except OSError as error:
        fail(f"read {label} {path}: {error}")


def read_json(path: Path, label: str) -> tuple[dict[str, Any], bytes]:
    raw = read_bytes(path, label)
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        fail(f"decode {label} {path}: {error}")
    if not isinstance(value, dict):
        fail(f"{label} must be a JSON object")
    return value, raw


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def require_hex64(value: Any, label: str) -> str:
    if not isinstance(value, str) or HEX_64_RE.fullmatch(value) is None:
        fail(f"{label} must be 64 lowercase hexadecimal characters")
    return value


def require_address(value: Any, prefix: str, label: str) -> str:
    if not isinstance(value, str) or ADDRESS_RE.fullmatch(value) is None:
        fail(f"{label} is not an exact 41-character lowercase SNTS-01 address")
    if not value.startswith(prefix):
        fail(f"{label} does not start with declared prefix {prefix!r}")
    return value


def require_network_tuple(value: dict[str, Any], label: str) -> None:
    expected = {
        "chain_id": CHAIN_ID,
        "network_id": NETWORK_ID,
        "release_id": RELEASE_ID,
        "protocol_version": PROTOCOL_VERSION,
    }
    for field, wanted in expected.items():
        if value.get(field) != wanted:
            fail(f"{label}.{field} must be {wanted!r}, got {value.get(field)!r}")


def identity_directory(root: Path, account_id: str) -> Path:
    matches = sorted(path for path in root.glob(f"{account_id}_*") if path.is_dir())
    if len(matches) != 1:
        fail(f"expected exactly one public identity directory for {account_id}, found {len(matches)}")
    return matches[0]


def validate_public_bundle(
    identity_root: Path, account_id: str, approved_amount: str
) -> tuple[str, dict[str, Any]]:
    directory = identity_directory(identity_root, account_id)
    manifest, manifest_raw = read_json(directory / "manifest.json", f"{account_id} manifest")
    public, public_raw = read_json(
        directory / "identity.pub.json", f"{account_id} public identity"
    )

    if manifest.get("id") != account_id:
        fail(f"{account_id} manifest id mismatch")
    prefix = manifest.get("prefix")
    if not isinstance(prefix, str) or not prefix:
        fail(f"{account_id} manifest prefix is missing")
    address = require_address(public.get("address"), prefix, f"{account_id} public address")
    if manifest.get("address") != address or public.get("prefix", prefix) != prefix:
        fail(f"{account_id} manifest/public address correspondence failed")

    public_sha = sha256(public_raw)
    if manifest.get("public_file_sha256") != public_sha:
        fail(f"{account_id} public identity SHA-256 mismatch")
    encrypted_path = directory / "identity.enc.json"
    encrypted_sha: str | None = None
    if encrypted_path.exists():
        encrypted_sha = sha256(read_bytes(encrypted_path, f"{account_id} encrypted bundle"))
        if manifest.get("encrypted_file_sha256") != encrypted_sha:
            fail(f"{account_id} encrypted bundle SHA-256 mismatch")
    elif manifest.get("key_bundle") != "multisig-policy-only-no-shared-private-key" and not (
        account_id == "SYS-04"
        and address == "syn00000000000000000000000000000000000000"
        and manifest.get("encrypted_file_sha256") is None
    ):
        fail(f"{account_id} encrypted bundle is missing")

    embedded_amount = manifest.get("genesis_amount_nwei")
    amount_matches = str(embedded_amount) == approved_amount
    provenance = {
        "identity_directory": directory.name,
        "manifest_sha256": sha256(manifest_raw),
        "public_identity_sha256": public_sha,
        "encrypted_bundle_sha256": encrypted_sha,
        "address_correspondence_verified": True,
        "bundle_checksum_verified": True,
        "embedded_genesis_amount_nwei": embedded_amount,
        "embedded_amount_matches_approved_plan": amount_matches,
    }
    if not amount_matches:
        provenance["embedded_amount_status"] = (
            "SUPERSEDED_METADATA_ONLY_APPROVED_ALLOCATION_PLAN_IS_AUTHORITATIVE"
        )
    return address, provenance


def write_new(path: Path, value: dict[str, Any]) -> None:
    if path.exists():
        fail(f"refusing to overwrite {path}; remove only after reviewing the existing artifact")
    path.parent.mkdir(parents=True, exist_ok=True)
    encoded = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    descriptor = os.open(path, flags, 0o644)
    try:
        with os.fdopen(descriptor, "wb") as output:
            output.write(encoded)
            output.flush()
            os.fsync(output.fileno())
    except BaseException:
        try:
            path.unlink()
        except OSError:
            pass
        raise


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--allocation-manifest", type=Path, required=True)
    parser.add_argument("--validator-inputs", type=Path, required=True)
    parser.add_argument("--identity-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    allocation, allocation_raw = read_json(args.allocation_manifest, "allocation manifest")
    validator, validator_raw = read_json(args.validator_inputs, "validator source inputs")
    require_network_tuple(allocation, "allocation manifest")
    require_network_tuple(validator, "validator source inputs")
    if validator.get("status") != "COMPLETE" or validator.get("public_only") is not True:
        fail("validator source inputs are not a complete public-only artifact")

    allocations = allocation.get("allocations")
    if not isinstance(allocations, list) or len(allocations) != 36:
        fail("allocation plan must contain exactly 36 records")
    by_id: dict[str, dict[str, Any]] = {}
    total = 0
    for entry in allocations:
        if not isinstance(entry, dict) or not isinstance(entry.get("account_id"), str):
            fail("allocation entry is malformed")
        account_id = entry["account_id"]
        if account_id in by_id:
            fail(f"duplicate allocation account {account_id}")
        try:
            amount = int(entry["amount_nwei"])
        except (KeyError, TypeError, ValueError):
            fail(f"{account_id} amount_nwei is not a decimal integer")
        if amount < 0 or str(amount) != entry["amount_nwei"]:
            fail(f"{account_id} amount_nwei is not canonical")
        total += amount
        by_id[account_id] = entry
    if total != TOTAL_SUPPLY_NWEI or allocation.get("grand_total_nwei") != str(total):
        fail(f"allocation total must be exactly {TOTAL_SUPPLY_NWEI} nwei")

    source_fields = validator.get("genesis_source_fields")
    if not isinstance(source_fields, dict):
        fail("validator source inputs have no genesis_source_fields")
    bindings = source_fields.get("allocation_address_bindings")
    if not isinstance(bindings, list) or len(bindings) != 21:
        fail("validator adapter must provide exactly 21 allocation address bindings")
    validator_by_account: dict[str, dict[str, Any]] = {}
    for binding in bindings:
        if not isinstance(binding, dict):
            fail("validator allocation binding is malformed")
        account_id = binding.get("account_id")
        if account_id in validator_by_account:
            fail(f"duplicate validator binding {account_id}")
        validator_by_account[account_id] = binding
    if set(validator_by_account) != set(VALIDATOR_ACCOUNT_IDS):
        fail("validator adapter account set is not exactly VNS-A02 through VNS-A22")

    resolved: list[dict[str, Any]] = []
    stale_amount_metadata: list[str] = []
    for entry in allocations:
        account_id = entry["account_id"]
        amount = entry["amount_nwei"]
        if account_id in validator_by_account:
            binding = validator_by_account[account_id]
            ordinal = int(account_id.split("A", 1)[1]) - 1
            validator_id = f"validator-{ordinal:02d}"
            if binding.get("validator_id") != validator_id or binding.get("amount_nwei") != amount:
                fail(f"{account_id} validator ID or approved amount mismatch")
            address = require_address(binding.get("address"), "synv1", f"{account_id} validator address")
            result = {
                "account_id": account_id,
                "address": address,
                "amount_nwei": amount,
                "address_source": "fresh-validator-identity-ceremony",
                "validator_id": validator_id,
                "initially_active": validator_id in ACTIVE_VALIDATOR_IDS,
            }
        else:
            address, provenance = validate_public_bundle(args.identity_root, account_id, amount)
            if not provenance["embedded_amount_matches_approved_plan"]:
                stale_amount_metadata.append(account_id)
            result = {
                "account_id": account_id,
                "address": address,
                "amount_nwei": amount,
                "address_source": "canonical-testnet-v3-custody-public-identity",
                "identity_provenance": provenance,
            }
            if account_id == "TEM-A01":
                result["genesis_funding_target"] = "DEPLOYED_TEAM_VESTING_CONTRACT"
                result["address_role"] = "administrative-and-custody-identity"
        resolved.append(result)

    artifact: dict[str, Any] = {
        "schema_version": 1,
        "artifact_type": "testnet-v3-fresh-resolved-allocation-inputs",
        "status": "COMPLETE",
        "public_only": True,
        "chain_id": CHAIN_ID,
        "network_id": NETWORK_ID,
        "release_id": RELEASE_ID,
        "protocol_version": PROTOCOL_VERSION,
        "allocation_plan_sha256": sha256(allocation_raw),
        "validator_source_inputs_sha256": sha256(validator_raw),
        "approved_total_supply_nwei": str(total),
        "allocation_count": len(resolved),
        "resolved_allocations": resolved,
        "superseded_identity_manifest_amount_metadata": stale_amount_metadata,
        "amount_authority": "runtime/testnet-allocation-manifest.json",
        "identity_amount_policy": (
            "Identity manifests establish public-key/address custody correspondence only; "
            "the approved allocation plan exclusively controls Genesis amounts."
        ),
    }
    write_new(args.output, artifact)
    print(
        json.dumps(
            {
                "result": "FRESH_TESTNET_V3_ALLOCATION_INPUTS_RESOLVED",
                "output": str(args.output),
                "output_sha256": sha256(read_bytes(args.output, "resolved output")),
                "allocation_count": len(resolved),
                "approved_total_supply_nwei": str(total),
                "superseded_identity_manifest_amount_metadata": stale_amount_metadata,
            },
            indent=2,
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
