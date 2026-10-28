#!/usr/bin/env python3
"""Build public-only Testnet-v3 validator Genesis source inputs.

The adapter consumes the completed Address Engine validator ceremony, the
canonical public identity bundles, the Core validator roster, and the public
allocation plan. It never decrypts or parses custody envelopes. Outputs use
exclusive, manifest-last publication and are refused when either destination
already exists.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import secrets
import stat
import sys
from pathlib import Path
from typing import Any

try:
    import blake3
except ImportError as error:  # pragma: no cover - environment gate
    raise SystemExit("the existing Core Python dependency 'blake3' is required") from error


CHAIN_ID = 1266
NETWORK_ID = "testnet"
RELEASE_ID = "testnet-v3"
PROTOCOL_VERSION = "posy/3.0"
VALIDATOR_COUNT = 21
ACTIVE_IDS = [f"validator-{ordinal:02}" for ordinal in range(2, 7)]
VALIDATOR_IDS = [f"validator-{ordinal:02}" for ordinal in range(1, 22)]
INACTIVE_IDS = [validator_id for validator_id in VALIDATOR_IDS if validator_id not in ACTIVE_IDS]
STAKE_NWEI = "50000000000000"
VOTING_POWER = 100
COMMISSION_RATE_BPS = 500

INDEX_FILE = "validator-identity-ceremony-index.json"
CEREMONY_COMPLETION_FILE = "validator-identity-ceremony-completion.json"
PUBLIC_FILE = "identity.pub.json"
ENCRYPTED_FILE = "identity.enc.json"
BUNDLE_COMPLETION_FILE = "identity.enc.json.snts07-complete.json"
CHECKSUM_FILE = "SHA256SUMS"
BUNDLE_MANIFEST_FILE = "manifest.json"

HEX_64 = re.compile(r"^[0-9a-f]{64}$")
HEX_128 = re.compile(r"^[0-9a-f]{128}$")
LOWER_HEX = re.compile(r"^[0-9a-f]+$")
ADDRESS = re.compile(r"^synv11[023456789acdefghjklmnpqrstuvwxyz]{35}$")
FORBIDDEN_OUTPUT_KEY = re.compile(r"(?:^|_)(?:legacy|migration|v2)(?:$|_)", re.IGNORECASE)
SECRET_OUTPUT_KEY = re.compile(
    r"(?:^|_)(?:private(?:_key)?|secret|seed|mnemonic|passphrase|ciphertext)(?:$|_)",
    re.IGNORECASE,
)

KEY_PROFILE = {
    "primary": ("FN-DSA-1024", 1_793),
    "consensus": ("ML-DSA-65", 1_952),
    "node_identity": ("Ed25519", 32),
    "account": ("ML-DSA-87", 2_592),
    "entropy_contribution": ("ML-KEM-768", 1_184),
}
KEY_HASH_FIELDS = {
    "primary": "primary_fn_dsa_1024_sha256",
    "consensus": "consensus_ml_dsa_65_sha256",
    "node_identity": "node_identity_ed25519_sha256",
    "account": "account_ml_dsa_87_sha256",
    "entropy_contribution": "entropy_ml_kem_768_sha256",
}
BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
BECH32M_CONSTANT = 0x2BC830A3
MAX_JSON_BYTES = 16 * 1024 * 1024
MAX_CIPHERTEXT_BYTES = 32 * 1024 * 1024


class InputError(RuntimeError):
    """An input failed a closed validation gate."""


def fail(message: str) -> None:
    raise InputError(message)


def expect(condition: bool, message: str) -> None:
    if not condition:
        fail(message)


def canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def hash_json(value: Any) -> str:
    return blake3.blake3(canonical_json(value).encode("utf-8")).hexdigest()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha3_512_bytes(data: bytes) -> str:
    return hashlib.sha3_512(data).hexdigest()


def require_hex(value: Any, label: str, pattern: re.Pattern[str] = HEX_64) -> str:
    expect(isinstance(value, str) and pattern.fullmatch(value) is not None, f"{label} is not canonical lowercase hex")
    return value


def require_exact(value: dict[str, Any], field: str, expected: Any, label: str) -> None:
    expect(value.get(field) == expected, f"{label}.{field} must equal {expected!r}")


def reject_symlink_components(path: Path, label: str) -> None:
    absolute = Path(os.path.abspath(path))
    current = Path(absolute.anchor)
    for component in absolute.parts[1:]:
        current = current / component
        try:
            mode = os.lstat(current).st_mode
        except FileNotFoundError:
            fail(f"{label} does not exist: {current}")
        expect(not stat.S_ISLNK(mode), f"{label} contains a symlink component: {current}")


def read_regular_bytes(path: Path, label: str, maximum: int = MAX_JSON_BYTES) -> bytes:
    reject_symlink_components(path, label)
    before = os.lstat(path)
    expect(stat.S_ISREG(before.st_mode), f"{label} is not a regular file: {path}")
    expect(before.st_size <= maximum, f"{label} exceeds the {maximum}-byte limit")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        expect(
            (opened.st_dev, opened.st_ino) == (before.st_dev, before.st_ino),
            f"{label} changed while it was opened",
        )
        chunks: list[bytes] = []
        remaining = maximum + 1
        while remaining:
            chunk = os.read(descriptor, min(64 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        expect(len(data) <= maximum, f"{label} exceeds the {maximum}-byte limit")
        after = os.fstat(descriptor)
        expect(
            (after.st_size, after.st_mtime_ns) == (opened.st_size, opened.st_mtime_ns),
            f"{label} changed while it was read",
        )
        return data
    finally:
        os.close(descriptor)


def read_json(path: Path, label: str) -> tuple[dict[str, Any], bytes]:
    data = read_regular_bytes(path, label)
    try:
        value = json.loads(data)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        fail(f"{label} is not valid UTF-8 JSON: {error}")
    expect(isinstance(value, dict), f"{label} must contain one JSON object")
    return value, data


def reject_forbidden_fields(value: Any, label: str, path: str = "$") -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            expect(not FORBIDDEN_OUTPUT_KEY.search(key), f"{label} contains forbidden field {path}.{key}")
            expect(not SECRET_OUTPUT_KEY.search(key), f"{label} contains secret-bearing field {path}.{key}")
            reject_forbidden_fields(item, label, f"{path}.{key}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            reject_forbidden_fields(item, label, f"{path}[{index}]")


def convert_bits(data: bytes, from_bits: int, to_bits: int) -> list[int]:
    accumulator = 0
    bit_count = 0
    result: list[int] = []
    maximum = (1 << to_bits) - 1
    for value in data:
        accumulator = (accumulator << from_bits) | value
        bit_count += from_bits
        while bit_count >= to_bits:
            bit_count -= to_bits
            result.append((accumulator >> bit_count) & maximum)
    if bit_count:
        result.append((accumulator << (to_bits - bit_count)) & maximum)
    return result


def bech32_polymod(values: list[int]) -> int:
    generators = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    checksum = 1
    for value in values:
        top = checksum >> 25
        checksum = ((checksum & 0x1FFFFFF) << 5) ^ value
        for index, generator in enumerate(generators):
            if (top >> index) & 1:
                checksum ^= generator
    return checksum


def bech32m_encode(hrp: str, words: list[int]) -> str:
    expanded = [ord(character) >> 5 for character in hrp] + [0]
    expanded.extend(ord(character) & 31 for character in hrp)
    polymod = bech32_polymod(expanded + words + [0] * 6) ^ BECH32M_CONSTANT
    checksum = [(polymod >> (5 * (5 - index))) & 31 for index in range(6)]
    return hrp + "1" + "".join(BECH32_CHARSET[word] for word in words + checksum)


def derive_validator_address(primary_public_key: bytes) -> str:
    words = convert_bits(hashlib.sha3_256(primary_public_key).digest(), 8, 5)
    return bech32m_encode("synv1", words[:29])


def validate_public_identity(public: dict[str, Any], label: str) -> dict[str, bytes]:
    reject_forbidden_fields(public, label)
    expect(
        set(public)
        == {
            "schema_version",
            "binary_encoding",
            "address",
            "public_key",
            "address_type",
            "algorithm",
            "created_at",
            "consensus_key",
            "node_identity_key",
            "account_key",
            "entropy_contribution_key",
        },
        f"{label} has missing or unexpected top-level fields",
    )
    require_exact(public, "schema_version", "synergy-validator-public-identity-v3", label)
    require_exact(public, "binary_encoding", "lowercase-hex", label)
    require_exact(public, "address_type", "NodeClass1", label)
    require_exact(public, "algorithm", "FN-DSA-1024", label)
    expect(isinstance(public.get("created_at"), str) and public["created_at"], f"{label}.created_at is missing")

    entries = {
        "primary": (public.get("algorithm"), public.get("public_key")),
        "consensus": (
            (public.get("consensus_key") or {}).get("algorithm"),
            (public.get("consensus_key") or {}).get("public_key"),
        ),
        "node_identity": (
            (public.get("node_identity_key") or {}).get("algorithm"),
            (public.get("node_identity_key") or {}).get("public_key"),
        ),
        "account": (
            (public.get("account_key") or {}).get("algorithm"),
            (public.get("account_key") or {}).get("public_key"),
        ),
        "entropy_contribution": (
            (public.get("entropy_contribution_key") or {}).get("algorithm"),
            (public.get("entropy_contribution_key") or {}).get("public_key"),
        ),
    }
    decoded: dict[str, bytes] = {}
    for role, (algorithm, public_key) in entries.items():
        expected_algorithm, expected_length = KEY_PROFILE[role]
        expect(algorithm == expected_algorithm, f"{label}.{role} algorithm must be {expected_algorithm}")
        expect(
            isinstance(public_key, str)
            and len(public_key) == expected_length * 2
            and LOWER_HEX.fullmatch(public_key) is not None,
            f"{label}.{role} public key is not canonical {expected_length}-byte lowercase hex",
        )
        decoded[role] = bytes.fromhex(public_key)

    address = public.get("address")
    expect(isinstance(address, str) and ADDRESS.fullmatch(address) is not None, f"{label}.address is not canonical synv1")
    expect(derive_validator_address(decoded["primary"]) == address, f"{label}.address does not derive from its primary key")
    peer_id = (public.get("node_identity_key") or {}).get("peer_id")
    require_hex(peer_id, f"{label}.node_identity_key.peer_id")
    expect(hashlib.sha3_256(decoded["node_identity"]).hexdigest() == peer_id, f"{label}.peer_id does not derive from its Ed25519 key")
    return decoded


def validate_roster(roster: dict[str, Any]) -> None:
    label = "validator roster"
    for field, expected in [
        ("schema_version", 1),
        ("chain_id", CHAIN_ID),
        ("network_id", NETWORK_ID),
        ("release_id", RELEASE_ID),
        ("protocol_version", PROTOCOL_VERSION),
        ("identity_count", VALIDATOR_COUNT),
        ("initial_active_validator_count", len(ACTIVE_IDS)),
        ("future_inactive_validator_count", len(INACTIVE_IDS)),
        ("stake_per_validator_nwei", STAKE_NWEI),
        ("membership_is_dynamic", True),
        ("initial_active_validator_ids", ACTIVE_IDS),
        ("future_inactive_validator_ids", INACTIVE_IDS),
    ]:
        require_exact(roster, field, expected, label)
    slots = roster.get("validator_slots")
    expect(isinstance(slots, list) and len(slots) == VALIDATOR_COUNT, f"{label} must contain exactly 21 slots")
    for ordinal, slot in enumerate(slots, 1):
        validator_id = VALIDATOR_IDS[ordinal - 1]
        account_id = f"VNS-A{ordinal + 1:02}"
        expect(isinstance(slot, dict), f"{label} slot {ordinal} is not an object")
        require_exact(slot, "validator_id", validator_id, label)
        require_exact(slot, "allocation_account_id", account_id, label)
        require_exact(slot, "genesis_status", "ACTIVE" if validator_id in ACTIVE_IDS else "INACTIVE", label)


def allocation_by_account(allocation: dict[str, Any]) -> dict[str, dict[str, Any]]:
    label = "allocation manifest"
    for field, expected in [
        ("schema_version", 4),
        ("chain_id", CHAIN_ID),
        ("network_id", NETWORK_ID),
        ("release_id", RELEASE_ID),
        ("protocol_version", PROTOCOL_VERSION),
    ]:
        require_exact(allocation, field, expected, label)
    policy = allocation.get("validator_allocation") or {}
    require_exact(policy, "pre_generated_identity_count", VALIDATOR_COUNT, label)
    require_exact(policy, "initial_active_validator_ids", ACTIVE_IDS, label)
    require_exact(policy, "future_inactive_validator_ids", INACTIVE_IDS, label)
    entries = allocation.get("allocations")
    expect(isinstance(entries, list), f"{label}.allocations must be an array")
    by_account: dict[str, dict[str, Any]] = {}
    for entry in entries:
        expect(isinstance(entry, dict), f"{label} has a non-object allocation")
        account_id = entry.get("account_id")
        expect(isinstance(account_id, str) and account_id not in by_account, f"{label} has a duplicate or missing account_id")
        by_account[account_id] = entry
    for ordinal, validator_id in enumerate(VALIDATOR_IDS, 1):
        account_id = f"VNS-A{ordinal + 1:02}"
        entry = by_account.get(account_id)
        expect(entry is not None, f"{label} is missing {account_id}")
        for field, expected in [
            ("name", validator_id),
            ("alias", validator_id),
            ("control_reference", f"{validator_id} encrypted key bundle"),
            ("amount_nwei", STAKE_NWEI),
        ]:
            require_exact(entry, field, expected, label)
        expect(entry.get("address") is None or isinstance(entry.get("address"), str), f"{label} {account_id} address has invalid type")
    return by_account


def validate_completion(completion: dict[str, Any], completion_bytes: bytes, index_bytes: bytes) -> dict[str, str]:
    label = "ceremony completion"
    expected = {
        "schema_version": 1,
        "artifact_type": "testnet-v3-fresh-21-validator-identity-ceremony-completion",
        "status": "COMPLETE",
        "chain_id": CHAIN_ID,
        "network_id": NETWORK_ID,
        "release_id": RELEASE_ID,
        "validator_count": VALIDATOR_COUNT,
        "initial_active_validator_count": len(ACTIVE_IDS),
        "dynamic_validator_membership": True,
        "ceremony_index_file": "ceremony-index.json",
        "sequential_low_memory_generation": True,
        "all_public_private_correspondence_verified": True,
        "all_addresses_rederived": True,
        "all_peer_ids_rederived": True,
        "all_output_hashes_verified": True,
        "publication_protocol": "no-clobber-manifest-last",
        "address_registry_version": "SNTS-01-v1.3",
        "address_engine_version": 1,
    }
    for field, value in expected.items():
        require_exact(completion, field, value, label)
    expect(completion.get("ceremony_index_sha256") == sha256_bytes(index_bytes), f"{label} does not bind the ceremony index")
    for field in [
        "ceremony_index_sha256",
        "registry_sha256",
        "vector_set_sha256",
        "source_document_sha256",
        "engine_executable_sha256",
    ]:
        require_hex(completion.get(field), f"{label}.{field}")
    require_hex(completion.get("bundle_manifest_root_sha3_512"), f"{label}.bundle_manifest_root_sha3_512", HEX_128)
    return {
        "ceremony_completion_sha256": sha256_bytes(completion_bytes),
        "ceremony_index_sha256": sha256_bytes(index_bytes),
    }


def validate_index(index: dict[str, Any]) -> list[dict[str, Any]]:
    label = "ceremony index"
    expected = {
        "schema_version": 1,
        "artifact_type": "testnet-v3-fresh-validator-identity-ceremony-index",
        "chain_id": CHAIN_ID,
        "network_id": NETWORK_ID,
        "release_id": RELEASE_ID,
        "dynamic_validator_membership": True,
        "validator_count": VALIDATOR_COUNT,
        "expected_validator_ids": VALIDATOR_IDS,
        "initial_active_validator_ids": ACTIVE_IDS,
        "initial_inactive_validator_ids": INACTIVE_IDS,
    }
    for field, value in expected.items():
        require_exact(index, field, value, label)
    records = index.get("records")
    expect(isinstance(records, list) and len(records) == VALIDATOR_COUNT, f"{label} must contain exactly 21 records")
    return records


def validate_bundle(
    bundle_root: Path,
    record: dict[str, Any],
    ordinal: int,
    ceremony_completion: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, bytes], dict[str, str]]:
    validator_id = VALIDATOR_IDS[ordinal - 1]
    account_id = f"VNS-A{ordinal + 1:02}"
    status_value = "ACTIVE" if validator_id in ACTIVE_IDS else "INACTIVE"
    label = f"ceremony record {validator_id}"
    for field, expected in [
        ("ordinal", ordinal),
        ("validator_id", validator_id),
        ("allocation_account_id", account_id),
        ("genesis_status", status_value),
        ("bundle_directory", f"validator-bundles/{account_id}_{validator_id}"),
    ]:
        require_exact(record, field, expected, label)
    for field in ["public_file_sha256", "encrypted_file_sha256", "key_bundle_hash", "bundle_manifest_sha256"]:
        require_hex(record.get(field), f"{label}.{field}")

    bundle = bundle_root / f"{account_id}_{validator_id}"
    reject_symlink_components(bundle, f"{validator_id} bundle")
    expect(stat.S_ISDIR(os.lstat(bundle).st_mode), f"{validator_id} bundle is not a directory")
    expected_names = {PUBLIC_FILE, ENCRYPTED_FILE, BUNDLE_COMPLETION_FILE, CHECKSUM_FILE, BUNDLE_MANIFEST_FILE}
    actual_names = {entry.name for entry in os.scandir(bundle)}
    expect(actual_names == expected_names, f"{validator_id} bundle inventory is not canonical: {sorted(actual_names)}")

    manifest, manifest_bytes = read_json(bundle / BUNDLE_MANIFEST_FILE, f"{validator_id} bundle manifest")
    expect(sha256_bytes(manifest_bytes) == record["bundle_manifest_sha256"], f"{validator_id} bundle manifest hash mismatch")
    expected_manifest = {
        "schema_version": 1,
        "artifact_type": "testnet-v3-fresh-validator-identity-bundle",
        "candidate_only": True,
        "deployment_status": "not-deployed",
        "chain_id": CHAIN_ID,
        "network_id": NETWORK_ID,
        "release_id": RELEASE_ID,
        "id": account_id,
        "identity_kind": "validator-node",
        "key_bundle": "full-node-key-set",
        "validator_id": validator_id,
        "allocation_account_id": account_id,
        "genesis_status": status_value,
        "dynamic_validator_membership": True,
        "five_key_profile": {role: profile[0] for role, profile in KEY_PROFILE.items()},
        "public_file": PUBLIC_FILE,
        "encrypted_file": ENCRYPTED_FILE,
        "completion_file": BUNDLE_COMPLETION_FILE,
        "checksums_file": CHECKSUM_FILE,
        "address_registry_version": "SNTS-01-v1.3",
        "address_engine_version": 1,
        "publication_protocol": "no-clobber-manifest-last",
    }
    for field, expected in expected_manifest.items():
        require_exact(manifest, field, expected, f"{validator_id} bundle manifest")
    for field in [
        "public_file_sha256",
        "encrypted_file_sha256",
        "completion_file_sha256",
        "checksums_file_sha256",
        "key_bundle_hash",
        "registry_sha256",
        "vector_set_sha256",
        "source_document_sha256",
        "engine_executable_sha256",
    ]:
        require_hex(manifest.get(field), f"{validator_id} manifest.{field}")
    for field in ["registry_sha256", "vector_set_sha256", "source_document_sha256", "engine_executable_sha256"]:
        expect(manifest[field] == ceremony_completion[field], f"{validator_id} manifest.{field} differs from ceremony completion")

    public, public_bytes = read_json(bundle / PUBLIC_FILE, f"{validator_id} public identity")
    encrypted_bytes = read_regular_bytes(bundle / ENCRYPTED_FILE, f"{validator_id} encrypted envelope", MAX_CIPHERTEXT_BYTES)
    bundle_completion, bundle_completion_bytes = read_json(bundle / BUNDLE_COMPLETION_FILE, f"{validator_id} bundle completion")
    checksum_bytes = read_regular_bytes(bundle / CHECKSUM_FILE, f"{validator_id} checksums")
    actual_hashes = {
        "public": sha256_bytes(public_bytes),
        "encrypted": sha256_bytes(encrypted_bytes),
        "completion": sha256_bytes(bundle_completion_bytes),
        "checksums": sha256_bytes(checksum_bytes),
        "manifest": sha256_bytes(manifest_bytes),
    }
    for source, field in [
        ("public", "public_file_sha256"),
        ("encrypted", "encrypted_file_sha256"),
        ("completion", "completion_file_sha256"),
        ("checksums", "checksums_file_sha256"),
    ]:
        expect(actual_hashes[source] == manifest[field], f"{validator_id} {source} hash differs from its manifest")
    for source, field in [("public", "public_file_sha256"), ("encrypted", "encrypted_file_sha256")]:
        expect(actual_hashes[source] == record[field], f"{validator_id} {source} hash differs from the ceremony index")

    checksum_lines = checksum_bytes.decode("ascii", errors="strict").splitlines()
    expected_checksums = [
        f"{actual_hashes['public']}  {PUBLIC_FILE}",
        f"{actual_hashes['encrypted']}  {ENCRYPTED_FILE}",
        f"{actual_hashes['completion']}  {BUNDLE_COMPLETION_FILE}",
    ]
    expect(checksum_lines == expected_checksums, f"{validator_id} checksum inventory is not exact")

    keys = validate_public_identity(public, f"{validator_id} public identity")
    address = public["address"]
    peer_id = public["node_identity_key"]["peer_id"]
    expect(record.get("address") == address == manifest.get("address"), f"{validator_id} address binding mismatch")
    expect(record.get("peer_id") == peer_id == manifest.get("peer_id"), f"{validator_id} peer binding mismatch")
    computed_key_bundle_hash = hashlib.sha256(
        b"SYNERGY_TESTNET_V3_VALIDATOR_KEY_BUNDLE_V1"
        + actual_hashes["public"].encode("ascii")
        + actual_hashes["encrypted"].encode("ascii")
    ).hexdigest()
    expect(computed_key_bundle_hash == record["key_bundle_hash"] == manifest["key_bundle_hash"], f"{validator_id} key-bundle hash mismatch")

    expected_bundle_completion = {
        "schema_version": "snts07-validator-bundle-generation-completion-v1",
        "chain_id": CHAIN_ID,
        "network_id": NETWORK_ID,
        "release_id": RELEASE_ID,
        "validator_id": validator_id,
        "allocation_account_id": account_id,
        "binary_encoding": "lowercase-hex",
        "target_public_schema_version": "synergy-validator-public-identity-v3",
        "target_private_schema_version": "synergy-validator-private-identity-v3",
        "target_envelope_version": 3,
        "public_output_sha256": actual_hashes["public"],
        "encrypted_output_sha256": actual_hashes["encrypted"],
        "key_bundle_hash": computed_key_bundle_hash,
        "public_identity_sha3_512": sha3_512_bytes(public_bytes),
        "key_material_correspondence_verified": True,
        "address_rederivation_verified": True,
        "peer_id_derivation_verified": True,
        "post_encrypt_decrypt_verified": True,
        "engine_executable_sha256": ceremony_completion["engine_executable_sha256"],
    }
    for field, expected in expected_bundle_completion.items():
        require_exact(bundle_completion, field, expected, f"{validator_id} bundle completion")
    key_hashes = bundle_completion.get("public_key_hashes_sha256")
    expect(isinstance(key_hashes, dict), f"{validator_id} bundle completion key hashes are missing")
    for role, key_bytes in keys.items():
        expect(
            key_hashes.get(KEY_HASH_FIELDS[role]) == sha256_bytes(key_bytes),
            f"{validator_id} {role} public-key hash mismatch",
        )
    return public, keys, actual_hashes


def validator_record(
    validator_id: str,
    account_id: str,
    status_value: str,
    public: dict[str, Any],
    keys: dict[str, bytes],
    key_bundle_hash: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    metadata = {
        "address": public["address"],
        "address_type": public["address_type"],
        "algorithm": public["algorithm"],
        "created_at": public["created_at"],
        "validator_id": validator_id,
    }
    record = {
        "account_key_type": "ML-DSA-87",
        "account_public_key": base64.b64encode(keys["account"]).decode("ascii"),
        "activation_height": 0 if status_value == "ACTIVE" else None,
        "address_type": "NodeClass1",
        "allocation_account_id": account_id,
        "commission_rate_bps": COMMISSION_RATE_BPS,
        "consensus_key_type": "ML-DSA-65",
        "consensus_public_key": base64.b64encode(keys["consensus"]).decode("ascii"),
        "deactivation_height": None,
        "entropy_contribution_key": base64.b64encode(keys["entropy_contribution"]).decode("ascii"),
        "entropy_key_type": "ML-KEM-768",
        "identity": validator_id,
        "identity_key_type": "FN-DSA-1024",
        "identity_public_key": base64.b64encode(keys["primary"]).decode("ascii"),
        "key_bundle_hash": key_bundle_hash,
        "metadata_hash": hash_json(metadata),
        "moniker": validator_id,
        "node_identity_key": base64.b64encode(keys["node_identity"]).decode("ascii"),
        "node_identity_key_type": "Ed25519",
        "operator_address": public["address"],
        "peer_id": public["node_identity_key"]["peer_id"],
        "reward_address": public["address"],
        "slashing_status": "none",
        "stake_nwei": STAKE_NWEI,
        "status": "active_at_genesis" if status_value == "ACTIVE" else "preconfigured_pending_activation",
        "validator_id": validator_id,
        "validator_id_hash": hash_json({"validator_id": validator_id}),
        "voting_power": VOTING_POWER,
    }
    return record, metadata


def build(args: argparse.Namespace) -> tuple[dict[str, Any], dict[str, Any]]:
    index, index_bytes = read_json(args.ceremony_index, "ceremony index")
    completion, completion_bytes = read_json(args.ceremony_completion, "ceremony completion")
    roster, roster_bytes = read_json(args.roster, "validator roster")
    allocation, allocation_bytes = read_json(args.allocation_manifest, "allocation manifest")
    records = validate_index(index)
    completion_hashes = validate_completion(completion, completion_bytes, index_bytes)
    validate_roster(roster)
    allocations = allocation_by_account(allocation)

    reject_symlink_components(args.bundle_root, "bundle root")
    expect(stat.S_ISDIR(os.lstat(args.bundle_root).st_mode), "bundle root is not a directory")
    preconfigured: list[dict[str, Any]] = []
    active: list[dict[str, Any]] = []
    accounts: list[dict[str, Any]] = []
    bindings: list[dict[str, Any]] = []
    metadata_records: list[dict[str, Any]] = []
    bundle_bindings: list[dict[str, Any]] = []
    bundle_manifest_hashes: list[str] = []
    unique_values: dict[str, set[str]] = {
        "address": set(),
        "peer_id": set(),
        **{f"{role}_key": set() for role in KEY_PROFILE},
    }

    for ordinal, ceremony_record in enumerate(records, 1):
        validator_id = VALIDATOR_IDS[ordinal - 1]
        account_id = f"VNS-A{ordinal + 1:02}"
        status_value = "ACTIVE" if validator_id in ACTIVE_IDS else "INACTIVE"
        expect(isinstance(ceremony_record, dict), f"ceremony record {ordinal} is not an object")
        public, keys, hashes = validate_bundle(args.bundle_root, ceremony_record, ordinal, completion)
        allocation_entry = allocations[account_id]
        expect(
            allocation_entry.get("address") is None or allocation_entry["address"] == public["address"],
            f"allocation {account_id} is already bound to a different address",
        )
        for label, value in [("address", public["address"]), ("peer_id", public["node_identity_key"]["peer_id"])]:
            expect(value not in unique_values[label], f"duplicate validator {label}: {value}")
            unique_values[label].add(value)
        for role, key_bytes in keys.items():
            key_hex = key_bytes.hex()
            label = f"{role}_key"
            expect(key_hex not in unique_values[label], f"duplicate validator {role} public key")
            unique_values[label].add(key_hex)

        generated, metadata = validator_record(
            validator_id,
            account_id,
            status_value,
            public,
            keys,
            ceremony_record["key_bundle_hash"],
        )
        preconfigured.append(generated)
        if status_value == "ACTIVE":
            active.append(generated)
        accounts.append(
            {
                "account_id": account_id,
                "account_name": validator_id,
                "account_type": "NodeClass1",
                "address": public["address"],
                "alias": validator_id,
                "category": "Validators / Staking / Network Security",
                "control_reference": f"{validator_id} encrypted key bundle",
            }
        )
        bindings.append(
            {
                "account_id": account_id,
                "validator_id": validator_id,
                "address": public["address"],
                "amount_nwei": STAKE_NWEI,
            }
        )
        metadata_records.append({"validator_id": validator_id, "metadata": metadata, "metadata_hash": generated["metadata_hash"]})
        bundle_bindings.append(
            {
                "validator_id": validator_id,
                "allocation_account_id": account_id,
                "public_identity_sha256": hashes["public"],
                "bundle_manifest_sha256": hashes["manifest"],
                "key_bundle_hash": ceremony_record["key_bundle_hash"],
            }
        )
        bundle_manifest_hashes.append(hashes["manifest"])

    bundle_root_hasher = hashlib.sha3_512()
    bundle_root_hasher.update(b"SYNERGY_TESTNET_V3_VALIDATOR_BUNDLE_MANIFEST_ROOT_V1")
    for digest in bundle_manifest_hashes:
        bundle_root_hasher.update(digest.encode("ascii"))
    expect(
        bundle_root_hasher.hexdigest() == completion["bundle_manifest_root_sha3_512"],
        "ceremony bundle-manifest root does not match the 21 canonical bundles",
    )
    expect([entry["validator_id"] for entry in active] == ACTIVE_IDS, "active validator output is not exact")

    registry_init = {
        "initial_validator_count": len(ACTIVE_IDS),
        "preconfigured_validator_count": VALIDATOR_COUNT,
        "min_validator_count": len(ACTIVE_IDS),
        "validator_set_mutable": True,
        "validators": active,
    }
    registry_init["validator_set_hash"] = hash_json(registry_init["validators"])
    output = {
        "schema_version": 1,
        "artifact_type": "testnet-v3-fresh-validator-genesis-source-inputs",
        "status": "COMPLETE",
        "public_only": True,
        "chain_id": CHAIN_ID,
        "network_id": NETWORK_ID,
        "release_id": RELEASE_ID,
        "protocol_version": PROTOCOL_VERSION,
        "ceremony_binding": {
            **completion_hashes,
            "bundle_manifest_root_sha3_512": completion["bundle_manifest_root_sha3_512"],
            "address_registry_version": completion["address_registry_version"],
            "address_engine_version": completion["address_engine_version"],
            "registry_sha256": completion["registry_sha256"],
            "vector_set_sha256": completion["vector_set_sha256"],
            "source_document_sha256": completion["source_document_sha256"],
            "engine_executable_sha256": completion["engine_executable_sha256"],
            "validator_roster_sha256": sha256_bytes(roster_bytes),
            "allocation_manifest_sha256": sha256_bytes(allocation_bytes),
            "validator_bundles": bundle_bindings,
        },
        "membership": {
            "dynamic_validator_membership": True,
            "preconfigured_validator_count": VALIDATOR_COUNT,
            "initial_active_validator_count": len(ACTIVE_IDS),
            "initial_inactive_validator_count": len(INACTIVE_IDS),
            "initial_active_validator_ids": ACTIVE_IDS,
            "initial_inactive_validator_ids": INACTIVE_IDS,
        },
        "hash_profile": {
            "genesis_subtree_hash": "BLAKE3 over RFC-8785-compatible sorted compact JSON",
            "validator_id_hash_preimage": "sorted compact JSON object containing only validator_id",
            "metadata_hash_preimage": "sorted compact JSON object emitted in validator_metadata",
        },
        "genesis_source_fields": {
            "validator_accounts": accounts,
            "allocation_address_bindings": bindings,
            "validators": active,
            "preconfigured_validators": preconfigured,
            "validator_registry_init_params": registry_init,
            "validator_metadata": metadata_records,
        },
    }
    reject_forbidden_fields(output, "adapter output")
    completion_output = {
        "schema_version": 1,
        "artifact_type": "testnet-v3-fresh-validator-genesis-source-inputs-completion",
        "status": "COMPLETE",
        "chain_id": CHAIN_ID,
        "network_id": NETWORK_ID,
        "release_id": RELEASE_ID,
        "protocol_version": PROTOCOL_VERSION,
        "public_only": True,
        "validator_count": VALIDATOR_COUNT,
        "initial_active_validator_count": len(ACTIVE_IDS),
        "initial_inactive_validator_count": len(INACTIVE_IDS),
        "exact_validator_ids_verified": True,
        "exact_initial_active_validator_ids_verified": True,
        "all_bundle_hashes_verified": True,
        "all_public_key_profiles_verified": True,
        "all_addresses_rederived": True,
        "all_peer_ids_rederived": True,
        "allocation_bindings_verified": True,
        "publication_protocol": "no-clobber-completion-last",
    }
    reject_forbidden_fields(completion_output, "adapter completion")
    return output, completion_output


def pretty_json(value: dict[str, Any]) -> bytes:
    return (json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8")


def validate_output_destination(path: Path, label: str) -> Path:
    absolute = Path(os.path.abspath(path))
    expect(not absolute.exists(), f"refusing to overwrite existing {label}: {absolute}")
    parent = absolute.parent
    reject_symlink_components(parent, f"{label} parent")
    expect(stat.S_ISDIR(os.lstat(parent).st_mode), f"{label} parent is not a directory")
    return absolute


def write_temporary(parent: Path, destination_name: str, data: bytes) -> Path:
    temporary = parent / f".{destination_name}.tmp-{os.getpid()}-{secrets.token_hex(8)}"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(temporary, flags, 0o644)
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
    finally:
        os.close(descriptor)
    return temporary


def fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def publish_pair(output_path: Path, output: dict[str, Any], completion_path: Path, completion: dict[str, Any]) -> None:
    output_path = validate_output_destination(output_path, "source-input output")
    completion_path = validate_output_destination(completion_path, "completion output")
    expect(output_path != completion_path, "output and completion paths must be distinct")
    output_bytes = pretty_json(output)
    completion = dict(completion)
    completion["source_inputs_file"] = output_path.name
    completion["source_inputs_sha256"] = sha256_bytes(output_bytes)
    completion_bytes = pretty_json(completion)
    output_temp = write_temporary(output_path.parent, output_path.name, output_bytes)
    completion_temp = write_temporary(completion_path.parent, completion_path.name, completion_bytes)
    published_output = False
    published_completion = False
    try:
        os.link(output_temp, output_path, follow_symlinks=False)
        published_output = True
        fsync_directory(output_path.parent)
        os.link(completion_temp, completion_path, follow_symlinks=False)
        published_completion = True
        fsync_directory(completion_path.parent)
    except Exception:
        if published_completion:
            try:
                os.unlink(completion_path)
                fsync_directory(completion_path.parent)
            except OSError:
                pass
        if published_output:
            try:
                os.unlink(output_path)
                fsync_directory(output_path.parent)
            except OSError:
                pass
        raise
    finally:
        for temporary in [output_temp, completion_temp]:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass


def build_activation(source_path: Path, manifest_path: Path) -> dict[str, Any]:
    source, _ = read_json(source_path, "fresh validator Genesis source inputs")
    reject_forbidden_fields(source, "fresh validator Genesis source inputs")
    for field, expected in [
        ("schema_version", 1),
        ("artifact_type", "testnet-v3-fresh-validator-genesis-source-inputs"),
        ("status", "COMPLETE"),
        ("public_only", True),
        ("chain_id", CHAIN_ID),
        ("network_id", NETWORK_ID),
        ("release_id", RELEASE_ID),
        ("protocol_version", PROTOCOL_VERSION),
    ]:
        require_exact(source, field, expected, "fresh validator Genesis source inputs")
    membership = source.get("membership") or {}
    require_exact(membership, "initial_active_validator_ids", ACTIVE_IDS, "fresh validator Genesis source inputs")
    require_exact(membership, "initial_active_validator_count", len(ACTIVE_IDS), "fresh validator Genesis source inputs")
    validators = (source.get("genesis_source_fields") or {}).get("validators")
    expect(isinstance(validators, list) and len(validators) == len(ACTIVE_IDS), "source inputs must expose exactly five active validators")
    expect([entry.get("validator_id") for entry in validators] == ACTIVE_IDS, "source active validator order is not canonical")

    manifest, manifest_bytes = read_json(manifest_path, "finalized simplified PoSy manifest")
    canonical_manifest_bytes = json.dumps(
        manifest, ensure_ascii=False, separators=(",", ":")
    ).encode("utf-8")
    expect(manifest_bytes == canonical_manifest_bytes, "finalized simplified PoSy manifest bytes are not canonical")
    expected_manifest = {
        "schema_version": 4,
        "release_id": RELEASE_ID,
        "status": "FINALIZED",
        "chain_id": CHAIN_ID,
        "network_id": NETWORK_ID,
        "protocol_version": PROTOCOL_VERSION,
        "activation_boundary": "fresh_genesis_block_zero",
        "activation_epoch": 0,
        "activation_height": 1,
        "active_validator_count": len(ACTIVE_IDS),
        "consensus_cluster_count": 1,
        "consensus_signature_algorithm": "mldsa65",
        "required_distinct_signers": 4,
        "allow_quorum_reduction": False,
        "allow_local_leader_election": False,
        "require_single_validator_failure_liveness": True,
        "signer_journal_required": True,
        "safety_halt_on_conflicting_valid_qcs": True,
        "etdag_finality_separation_required": True,
        "protected_execution_binding_required": True,
        "initial_etdag_activation": "governed_genesis_binding_required",
    }
    for field, expected in expected_manifest.items():
        require_exact(manifest, field, expected, "finalized simplified PoSy manifest")
    decision_id = manifest.get("governance_approval_id")
    expect(isinstance(decision_id, str) and decision_id.strip() == decision_id and decision_id, "finalized simplified PoSy manifest has no Decision ID")
    expect(
        not any(word in decision_id.lower() for word in ["test", "pending", "candidate", "provisional"]),
        "finalized simplified PoSy Decision ID is not release-final",
    )

    frozen_records: list[dict[str, Any]] = []
    key_ids: set[str] = set()
    for record in validators:
        validator_id = record["validator_id"]
        expect(record.get("status") == "active_at_genesis", f"{validator_id} is not active at Genesis")
        expect(record.get("activation_height") == 0, f"{validator_id} source activation height must be zero")
        expect(record.get("voting_power") == VOTING_POWER, f"{validator_id} voting power must be 100")
        operator_address = record.get("operator_address")
        peer_id = require_hex(record.get("peer_id"), f"{validator_id}.peer_id")
        expect(isinstance(operator_address, str) and ADDRESS.fullmatch(operator_address) is not None, f"{validator_id} operator address is invalid")
        encoded_keys = {
            "consensus": (record.get("consensus_public_key"), "mldsa65", 1_952),
            "peer": (record.get("node_identity_key"), "ed25519", 32),
            "operator": (record.get("account_public_key"), "mldsa87", 2_592),
        }
        decoded_keys: dict[str, bytes] = {}
        for role, (encoded, _algorithm, expected_length) in encoded_keys.items():
            expect(isinstance(encoded, str), f"{validator_id} {role} key is missing")
            try:
                decoded = base64.b64decode(encoded, validate=True)
            except ValueError as error:
                fail(f"{validator_id} {role} key is not canonical base64: {error}")
            expect(len(decoded) == expected_length, f"{validator_id} {role} key has the wrong length")
            expect(base64.b64encode(decoded).decode("ascii") == encoded, f"{validator_id} {role} key is not canonical base64")
            decoded_keys[role] = decoded
        expected_peer = hashlib.sha3_256(decoded_keys["peer"]).hexdigest()
        expect(expected_peer == peer_id, f"{validator_id} peer ID does not match its public key")
        consensus_key_id = f"validator-consensus:{operator_address}"
        peer_key_id = f"validator-peer:{peer_id}"
        operator_key_id = f"validator-operator:{validator_id}"
        for key_id in [consensus_key_id, peer_key_id, operator_key_id]:
            expect(key_id not in key_ids, f"duplicate activation key ID {key_id}")
            key_ids.add(key_id)
        frozen_records.append(
            {
                "validator_id": validator_id,
                "validator_uma_id": operator_address,
                "consensus_public_key": {
                    "key_id": consensus_key_id,
                    "algorithm": "mldsa65",
                    "key_bytes": list(decoded_keys["consensus"]),
                },
                "peer_public_key": {
                    "key_id": peer_key_id,
                    "algorithm": "ed25519",
                    "key_bytes": list(decoded_keys["peer"]),
                },
                "operator_public_key": {
                    "key_id": operator_key_id,
                    "algorithm": "mldsa87",
                    "key_bytes": list(decoded_keys["operator"]),
                },
                "voting_weight": VOTING_POWER,
                "status": "ACTIVE",
                "cluster_id": 0,
                "activation_epoch": 0,
            }
        )
    activation = {
        "binding_schema_version": 1,
        "binding_status": "FINALIZED_AND_GENESIS_BOUND",
        "governance_decision_id": decision_id,
        "parameter_root_sha3_512": hashlib.sha3_512(manifest_bytes).hexdigest(),
        "activation_epoch": 0,
        "activation_height": 1,
        "manifest": manifest,
        "frozen_validator_set": {"epoch": 0, "validators": frozen_records},
    }
    reject_forbidden_fields(activation, "five-validator Genesis activation")
    return activation


def publish_single(path: Path, value: dict[str, Any], label: str) -> None:
    path = validate_output_destination(path, label)
    temporary = write_temporary(path.parent, path.name, pretty_json(value))
    try:
        os.link(temporary, path, follow_symlinks=False)
        fsync_directory(path.parent)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ceremony-index", type=Path)
    parser.add_argument("--ceremony-completion", type=Path)
    parser.add_argument("--bundle-root", type=Path)
    parser.add_argument("--roster", type=Path)
    parser.add_argument("--allocation-manifest", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--completion-output", type=Path)
    parser.add_argument("--activation-source-inputs", type=Path)
    parser.add_argument("--consensus-manifest", type=Path)
    parser.add_argument("--activation-output", type=Path)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        activation_values = [args.activation_source_inputs, args.consensus_manifest, args.activation_output]
        if any(activation_values):
            expect(all(activation_values), "activation mode requires --activation-source-inputs, --consensus-manifest, and --activation-output")
            source_values = [
                args.ceremony_index,
                args.ceremony_completion,
                args.bundle_root,
                args.roster,
                args.allocation_manifest,
                args.output,
                args.completion_output,
            ]
            expect(not any(source_values), "activation mode cannot be combined with source-input build flags")
            activation = build_activation(args.activation_source_inputs, args.consensus_manifest)
            publish_single(args.activation_output, activation, "five-validator Genesis activation")
            print(f"activation         {Path(os.path.abspath(args.activation_output))}")
            print(f"activation sha256  {sha256_bytes(pretty_json(activation))}")
            return 0
        source_values = [
            args.ceremony_index,
            args.ceremony_completion,
            args.bundle_root,
            args.roster,
            args.allocation_manifest,
            args.output,
            args.completion_output,
        ]
        expect(all(source_values), "source-input mode requires all ceremony, roster, allocation, and output flags")
        output, completion = build(args)
        publish_pair(args.output, output, args.completion_output, completion)
    except (InputError, OSError) as error:
        print(f"build-fresh-testnet-v3-validator-genesis-inputs: {error}", file=sys.stderr)
        return 1
    print(f"source inputs      {Path(os.path.abspath(args.output))}")
    print(f"completion         {Path(os.path.abspath(args.completion_output))}")
    print(f"source sha256      {sha256_bytes(pretty_json(output))}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
