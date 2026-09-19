#!/usr/bin/env python3
"""Freeze the existing SNTS-v1.3 Testnet-v3 Genesis authorities.

This command is public-only. It verifies the Address Engine's public artifacts,
encrypted-bundle hashes, and manifest-last completion records without opening
custody material. Output is deterministic, no-clobber, and contains everything
the Core Genesis ceremony needs to bind the three canonical identities.
"""

from __future__ import annotations

import argparse
from datetime import datetime
import hashlib
import json
import os
import re
import sys
from pathlib import Path
from typing import Any


CHAIN_ID = 1266
NETWORK_ID = "testnet"
RELEASE_ID = "testnet-v3"
REGISTRY_VERSION = "SNTS-01-v1.3"
ROOT_SCHEMA = "synergy-native-public-identity-v3"
AUTH_SCHEMAS = {
    "SNRG-TESTNET-V3-GENESIS-DEPLOYER": "synergy-authorization-public-key-v1",
    "SNRG-TESTNET-V3-GOVERNANCE-AUTHORITY":
        "synergy-governance-authorization-public-key-v1",
    "SNRG-TESTNET-V3-VALIDATOR-REGISTRY-AUTHORITY":
        "synergy-authorization-public-key-v1",
}
ROLES = tuple(AUTH_SCHEMAS)
ROLE_KINDS = {
    ROLES[0]: "genesis-deployer",
    ROLES[1]: "governance-authority",
    ROLES[2]: "validator-registry-authority",
}
ROOT_ALGORITHM = "FN-DSA-1024"
AUTH_ALGORITHM = "ML-DSA-87"
ROOT_PUBLIC_KEY_BYTES = 1793
AUTH_PUBLIC_KEY_BYTES = 2592
LOWER_HEX = re.compile(r"^[0-9a-f]+$")
ADDRESS = re.compile(r"^syna1[023456789acdefghjklmnpqrstuvwxyz]{36}$")
GENESIS_DOMAIN = "SYNERGY_GENESIS_CEREMONY_IDENTITY_AUTHORIZATION_V1"
SYNQ_DOMAIN = "SYNERGY_SYNQ_ADMISSION_IDENTITY_AUTHORIZATION_V1"
SCOPES = (
    {
        "signature_domain": GENESIS_DOMAIN,
        "chain_id": CHAIN_ID,
        "network_id": NETWORK_ID,
        "purpose": "genesis-signing",
    },
    {
        "signature_domain": SYNQ_DOMAIN,
        "chain_id": CHAIN_ID,
        "network_id": NETWORK_ID,
        "purpose": "synq-contract-call",
    },
    {
        "signature_domain": SYNQ_DOMAIN,
        "chain_id": CHAIN_ID,
        "network_id": NETWORK_ID,
        "purpose": "synq-contract-deploy",
    },
)
FILES = {
    "identity_root_public": "identity-root.pub.json",
    "identity_root_encrypted": "identity-root.enc.json",
    "identity_root_completion": "identity-root.enc.json.snts07-complete.json",
    "authorization_public": "identity.pub.json",
    "authorization_encrypted": "identity.enc.json",
    "authorization_completion": "identity.enc.json.snts07-complete.json",
    "binding": "genesis-authorization-binding.json",
    "binding_completion": "genesis-authorization-binding.json.complete.json",
}
RELEASE_SCOPE = {
    "signature_domain": "SYNERGY_TESTNET_V3_GENESIS_RELEASE_APPROVAL_V4",
    "chain_id": CHAIN_ID,
    "network_id": NETWORK_ID,
    "purpose": "testnet-v3-genesis-release-approval",
}


class FreezeError(Exception):
    pass


def fail(message: str) -> None:
    raise FreezeError(message)


def canonical_json_bytes(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
            + "\n").encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha3_256_bytes(value: bytes) -> str:
    return hashlib.sha3_256(value).hexdigest()


def require_file(path: Path, label: str) -> bytes:
    if path.is_symlink() or not path.is_file():
        fail(f"{label} must be a regular non-symlink file: {path}")
    return path.read_bytes()


def read_json(path: Path, label: str) -> tuple[dict[str, Any], bytes]:
    raw = require_file(path, label)
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        fail(f"{label} is not valid UTF-8 JSON: {error}")
    if not isinstance(value, dict):
        fail(f"{label} must be a JSON object")
    return value, raw


def require_equal(actual: Any, expected: Any, label: str) -> None:
    if actual != expected:
        fail(f"{label} mismatch: expected {expected!r}, found {actual!r}")


def require_true(actual: Any, label: str) -> None:
    if actual is not True:
        fail(f"{label} must be true")


def decode_hex(value: Any, byte_length: int, label: str) -> bytes:
    if (not isinstance(value, str) or len(value) != byte_length * 2
            or LOWER_HEX.fullmatch(value) is None):
        fail(f"{label} must be exactly {byte_length} bytes of lowercase hex")
    return bytes.fromhex(value)


def require_hash(value: Any, label: str) -> str:
    decode_hex(value, 32, label)
    return value


def require_chain_tuple(value: dict[str, Any], label: str) -> None:
    require_equal(value.get("chain_id"), CHAIN_ID, f"{label}.chain_id")
    require_equal(value.get("network_id"), NETWORK_ID, f"{label}.network_id")
    require_equal(value.get("release_id"), RELEASE_ID, f"{label}.release_id")


def require_completion_common(value: dict[str, Any], label: str) -> None:
    require_chain_tuple(value, label)
    require_equal(value.get("registry_version"), REGISTRY_VERSION,
                  f"{label}.registry_version")
    require_equal(value.get("publication_protocol"), "no-clobber-manifest-last",
                  f"{label}.publication_protocol")


def require_hash_matches(raw: bytes, expected: Any, label: str) -> str:
    expected_hash = require_hash(expected, label)
    actual = sha256_bytes(raw)
    if actual != expected_hash:
        fail(f"{label} mismatch: expected {expected_hash}, computed {actual}")
    return actual


REPLACEMENT_MANIFEST = "authority-replacement.complete.json"
REPLACEMENT_DERIVATION = "SNTS-01-v1.3-FN-DSA-1024-key-derived-authority-address"


def derive_authority_address(public_key: bytes) -> str:
    # SNTS-01 v1.3: first 30 base32 symbols of SHA3-256(raw FN key), Bech32m.
    # Same polymod as the validator public adapter; no BLAKE3 dependency needed.
    digest = hashlib.sha3_256(public_key).digest()
    bits = int.from_bytes(digest, "big")
    words = [(bits >> (256 - 5 * (index + 1))) & 31 for index in range(30)]
    hrp = "syna"
    values = [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]
    checksum = 1
    generators = (0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3)
    for value in values + words + [0] * 6:
        top = checksum >> 25
        checksum = ((checksum & 0x1FFFFFF) << 5) ^ value
        for index, generator in enumerate(generators):
            if (top >> index) & 1:
                checksum ^= generator
    checksum ^= 0x2BC830A3
    suffix = [(checksum >> (5 * (5 - index))) & 31 for index in range(6)]
    alphabet = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
    return hrp + "1" + "".join(alphabet[word] for word in words + suffix)


def read_prior_freeze(path: Path) -> tuple[dict[str, dict[str, Any]], str]:
    prior, raw = read_json(path, "prior authority freeze")
    require_chain_tuple(prior, "prior authority freeze")
    for field, expected in (
        ("schema_version", "synergy-testnet-v3-genesis-authority-freeze-v1"),
        ("artifact_type", "fresh-testnet-v3-genesis-authority-public-freeze"),
        ("address_registry_version", REGISTRY_VERSION),
        ("authority_count", 3), ("authority_role_ids", list(ROLES)),
    ):
        require_equal(prior.get(field), expected, f"prior freeze {field}")
    entries = prior.get("authorities")
    if not isinstance(entries, list) or len(entries) != 3:
        fail("prior freeze requires exactly three authorities")
    result = {}
    addresses, keys = set(), set()
    for role in ROLES:
        matches = [entry for entry in entries
                   if isinstance(entry, dict) and entry.get("role_id") == role]
        if len(matches) != 1:
            fail(f"prior freeze has missing or duplicate role {role}")
        entry = matches[0]
        root = entry.get("identity_root_public", {})
        auth = entry.get("authorization_public", {})
        for field, expected in (
            ("schema_version", ROOT_SCHEMA), ("identity_id", role),
            ("algorithm", ROOT_ALGORITHM), ("address_type", "WalletAccount"),
            ("binary_encoding", "lowercase-hex"),
        ):
            require_equal(root.get(field), expected, f"{role} prior root {field}")
        root_key = decode_hex(root.get("public_key"), ROOT_PUBLIC_KEY_BYTES,
                              f"{role} prior root public key")
        address = derive_authority_address(root_key)
        require_equal(root.get("address"), address, f"{role} prior root address")
        require_equal(entry.get("identity_address"), address, f"{role} prior identity address")
        for field, expected in (
            ("schema_version", AUTH_SCHEMAS[role]), ("role_id", role),
            ("algorithm", AUTH_ALGORITHM), ("binary_encoding", "lowercase-hex"),
        ):
            require_equal(auth.get(field), expected, f"{role} prior authorization {field}")
        digest = sha3_256_bytes(decode_hex(auth.get("public_key"), AUTH_PUBLIC_KEY_BYTES,
                                         f"{role} prior authorization public key"))
        binding = entry.get("identity_authorization_binding", {})
        require_equal(binding.get("identity_id"), role, f"{role} prior binding identity ID")
        require_equal(binding.get("identity_address"), address, f"{role} prior binding address")
        require_equal(binding.get("identity_root", {}).get("public_key"), root["public_key"],
                      f"{role} prior binding root key")
        require_equal(binding.get("current_auth_key_hash"), digest, f"{role} prior binding key")
        if address in addresses or digest in keys:
            fail("prior freeze authority addresses and keys must be unique")
        addresses.add(address)
        keys.add(digest)
        result[role] = {"address": address, "auth_digest": digest}
    return result, sha256_bytes(raw)


def validate_replacement_manifest(authority_root: Path, prior_sha256: str) -> tuple[dict[str, Any], str]:
    manifest, raw = read_json(authority_root / REPLACEMENT_MANIFEST,
                              "authority replacement completion")
    require_completion_common(manifest, "authority replacement completion")
    require_equal(manifest.get("schema_version"),
                  "synergy-testnet-v3-authority-custody-replacement-completion-v1",
                  "authority replacement completion schema")
    require_equal(manifest.get("replacement_prior_freeze_sha256"), prior_sha256,
                  "authority replacement prior freeze SHA-256")
    require_equal(manifest.get("authority_role_ids"), list(ROLES), "replacement authority roles")
    require_equal(manifest.get("authority_count"), 3, "replacement authority count")
    effective_at = manifest.get("effective_at")
    try:
        if not isinstance(effective_at, str):
            raise ValueError("missing timestamp")
        parsed_effective = datetime.fromisoformat(effective_at.replace("Z", "+00:00"))
        if parsed_effective.tzinfo is None:
            raise ValueError("missing timezone")
    except ValueError:
        fail("authority replacement completion effective_at must be an RFC3339 timestamp")
    hashes = manifest.get("artifact_sha256")
    expected = {f"{role}/{name}" for role in ROLES for name in FILES.values()}
    expected.update(f"{ROLES[1]}/{name}" for name in (
        "release-authorization-binding.json", "release-authorization-binding.json.complete.json"))
    if not isinstance(hashes, dict) or set(hashes) != expected:
        fail("authority replacement completion artifact inventory is incomplete or unexpected")
    for name in sorted(expected):
        require_hash_matches(require_file(authority_root / name, f"replacement {name}"),
                             hashes[name], f"replacement {name} SHA-256")
    if not isinstance(manifest.get("replacement_reason"), str) or not manifest["replacement_reason"].strip():
        fail("authority replacement completion requires a reason")
    return manifest, sha256_bytes(raw)


def validate_replacement_receipt(receipt: dict[str, Any], prior: dict[str, Any],
                                 manifest: dict[str, Any], label: str) -> None:
    for field, expected in (
        ("replacement_prior_freeze_sha256", manifest["replacement_prior_freeze_sha256"]),
        ("superseded_identity_address", prior["address"]),
        ("superseded_public_key_sha3_256", prior["auth_digest"]),
        ("replacement_reason", manifest["replacement_reason"]),
        ("effective_at", manifest["effective_at"]),
    ):
        require_equal(receipt.get(field), expected, f"{label} {field}")


def validate_replacement_history(binding: dict[str, Any], prior: dict[str, Any],
                                 manifest: dict[str, Any], role: str) -> None:
    history = binding.get("auth_key_history")
    supersession = binding.get("supersession_history")
    if not isinstance(history, list) or len(history) != 1:
        fail(f"{role} replacement must record exactly one retired authorization key")
    if not isinstance(supersession, list) or len(supersession) != 1:
        fail(f"{role} replacement must record exactly one superseded identity")
    require_equal(binding.get("effective_at"), manifest["effective_at"],
                  f"{role} replacement effective boundary")
    for field, expected in (
        ("principal_id", role), ("algorithm", AUTH_ALGORITHM),
        ("public_key_sha3_256", prior["auth_digest"]), ("status", "retired"),
        ("retired_at", binding["effective_at"]), ("reason", manifest["replacement_reason"]),
    ):
        require_equal(history[0].get(field), expected, f"{role} replacement retired key {field}")
    for field, expected in (
        ("address", prior["address"]), ("derivation_standard", REPLACEMENT_DERIVATION),
        ("status", "superseded"), ("reason", manifest["replacement_reason"]),
    ):
        require_equal(supersession[0].get(field), expected, f"{role} replacement supersession {field}")
    if (binding.get("identity_address") == prior["address"]
            or binding.get("current_auth_key_hash") == prior["auth_digest"]):
        fail(f"{role} replacement must use a new identity root and authorization key")


def validate_role(authority_root: Path, role: str,
                  prior: dict[str, Any] | None = None,
                  replacement: dict[str, Any] | None = None) -> dict[str, Any]:
    role_dir = authority_root / role
    if role_dir.is_symlink() or not role_dir.is_dir():
        fail(f"authority role directory is missing or is a symlink: {role_dir}")

    docs: dict[str, dict[str, Any]] = {}
    raws: dict[str, bytes] = {}
    for key, filename in FILES.items():
        docs[key], raws[key] = read_json(role_dir / filename, f"{role} {key}")

    if replacement is None:
        if any("replacement_prior_freeze_sha256" in doc for doc in docs.values()):
            fail(f"{role} replacement requires explicit --prior-freeze and completion manifest")
    else:
        for key in ("identity_root_completion", "authorization_completion", "binding_completion"):
            validate_replacement_receipt(docs[key], prior, replacement, f"{role} {key}")

    root = docs["identity_root_public"]
    require_equal(root.get("schema_version"), ROOT_SCHEMA,
                  f"{role} identity root schema")
    require_equal(root.get("binary_encoding"), "lowercase-hex",
                  f"{role} identity root encoding")
    require_equal(root.get("identity_id"), role, f"{role} identity root ID")
    require_equal(root.get("address_type"), "WalletAccount",
                  f"{role} identity root address type")
    require_equal(root.get("algorithm"), ROOT_ALGORITHM,
                  f"{role} identity root algorithm")
    address = root.get("address")
    if not isinstance(address, str) or ADDRESS.fullmatch(address) is None:
        fail(f"{role} identity root address is not a canonical 41-character syna address")
    root_key = decode_hex(root.get("public_key"), ROOT_PUBLIC_KEY_BYTES,
                          f"{role} FN-DSA public key")

    authorization = docs["authorization_public"]
    require_equal(authorization.get("schema_version"), AUTH_SCHEMAS[role],
                  f"{role} authorization public schema")
    require_equal(authorization.get("binary_encoding"), "lowercase-hex",
                  f"{role} authorization encoding")
    require_equal(authorization.get("role_id"), role,
                  f"{role} authorization role ID")
    require_equal(authorization.get("algorithm"), AUTH_ALGORITHM,
                  f"{role} authorization algorithm")
    auth_key = decode_hex(authorization.get("public_key"), AUTH_PUBLIC_KEY_BYTES,
                          f"{role} ML-DSA public key")

    root_complete = docs["identity_root_completion"]
    require_equal(root_complete.get("schema_version"),
                  "snts07-new-key-root-completion-v1",
                  f"{role} identity root completion schema")
    require_completion_common(root_complete, f"{role} identity root completion")
    require_equal(root_complete.get("identity_id"), role,
                  f"{role} identity root completion ID")
    require_equal(root_complete.get("address"), address,
                  f"{role} identity root completion address")
    require_equal(root_complete.get("algorithm"), ROOT_ALGORITHM,
                  f"{role} identity root completion algorithm")
    for field in ("key_material_correspondence_verified",
                  "address_rederivation_verified", "post_encrypt_decrypt_verified"):
        require_true(root_complete.get(field), f"{role} identity root completion {field}")
    require_hash_matches(raws["identity_root_public"],
                         root_complete.get("public_output_sha256"),
                         f"{role} identity root public SHA-256")
    require_hash_matches(raws["identity_root_encrypted"],
                         root_complete.get("encrypted_output_sha256"),
                         f"{role} identity root encrypted SHA-256")

    auth_complete = docs["authorization_completion"]
    expected_auth_completion_schema = (
        "snts07-governance-authorization-key-rotation-completion-v1"
        if role == "SNRG-TESTNET-V3-GOVERNANCE-AUTHORITY"
        else "snts07-authorization-key-generation-completion-v1"
    )
    require_equal(auth_complete.get("schema_version"),
                  expected_auth_completion_schema,
                  f"{role} authorization completion schema")
    require_completion_common(auth_complete, f"{role} authorization completion")
    require_equal(auth_complete.get("role_id"), role,
                  f"{role} authorization completion role ID")
    if role != "SNRG-TESTNET-V3-GOVERNANCE-AUTHORITY":
        require_equal(auth_complete.get("algorithm"), AUTH_ALGORITHM,
                      f"{role} authorization completion algorithm")
    for field in ("ml_dsa_87_signing_correspondence_verified",
                  "same_passphrase_decrypt_verified"):
        require_true(auth_complete.get(field), f"{role} authorization completion {field}")
    require_hash_matches(raws["authorization_public"],
                         auth_complete.get("public_output_sha256"),
                         f"{role} authorization public SHA-256")
    require_hash_matches(raws["authorization_encrypted"],
                         auth_complete.get("encrypted_output_sha256"),
                         f"{role} authorization encrypted SHA-256")
    auth_completion_key_digest = (
        auth_complete.get("new_public_key_sha3_256")
        if role == "SNRG-TESTNET-V3-GOVERNANCE-AUTHORITY"
        else auth_complete.get("public_key_sha3_256")
    )
    require_equal(require_hash(auth_completion_key_digest,
                               f"{role} authorization public-key SHA3-256"),
                  sha3_256_bytes(auth_key), f"{role} authorization public-key digest")

    binding = docs["binding"]
    require_equal(binding.get("schema_version"),
                  "synergy-identity-authorization-binding-v1",
                  f"{role} binding schema")
    require_equal(binding.get("binary_encoding"), "lowercase-hex",
                  f"{role} binding encoding")
    require_equal(binding.get("identity_id"), role, f"{role} binding identity ID")
    require_equal(binding.get("identity_address"), address,
                  f"{role} binding identity address")
    binding_root = binding.get("identity_root")
    if not isinstance(binding_root, dict):
        fail(f"{role} binding identity_root must be an object")
    require_equal(binding_root.get("algorithm"), ROOT_ALGORITHM,
                  f"{role} binding root algorithm")
    require_equal(binding_root.get("public_key"), root.get("public_key"),
                  f"{role} binding root public key")
    require_equal(require_hash(binding_root.get("public_key_sha3_256"),
                               f"{role} binding root public-key SHA3-256"),
                  sha3_256_bytes(root_key), f"{role} binding root public-key digest")

    policy = binding.get("authorization_policy")
    if not isinstance(policy, dict):
        fail(f"{role} binding authorization_policy must be an object")
    require_equal(policy.get("policy_type"), "single-key", f"{role} policy type")
    require_equal(policy.get("threshold"), 1, f"{role} policy threshold")
    principals = policy.get("principals")
    if not isinstance(principals, list) or len(principals) != 1:
        fail(f"{role} binding must contain exactly one authorization principal")
    principal = principals[0]
    require_equal(principal.get("principal_id"), role, f"{role} principal ID")
    require_equal(principal.get("principal_type"), "public-key",
                  f"{role} principal type")
    require_equal(principal.get("algorithm"), AUTH_ALGORITHM,
                  f"{role} principal algorithm")
    require_equal(principal.get("public_key"), authorization.get("public_key"),
                  f"{role} principal public key")
    require_equal(require_hash(principal.get("public_key_sha3_256"),
                               f"{role} principal public-key SHA3-256"),
                  sha3_256_bytes(auth_key), f"{role} principal public-key digest")
    require_equal(principal.get("status"), "active", f"{role} principal status")
    require_equal(principal.get("purposes"),
                  [scope["purpose"] for scope in SCOPES], f"{role} purposes")
    require_equal(binding.get("authorization_scopes"), list(SCOPES), f"{role} scopes")
    current_auth_key_hash = sha3_256_bytes(auth_key)
    require_equal(binding.get("current_auth_key_hash"), current_auth_key_hash,
                  f"{role} current authorization-key digest")
    if replacement is not None:
        require_equal(address, derive_authority_address(root_key),
                      f"{role} replacement FN identity address")
    key_history = binding.get("auth_key_history")
    supersession_history = binding.get("supersession_history")
    if replacement is not None:
        validate_replacement_history(binding, prior, replacement, role)
    elif role == "SNRG-TESTNET-V3-GOVERNANCE-AUTHORITY":
        if not isinstance(key_history, list) or len(key_history) != 1:
            fail(f"{role} must record exactly one retired authorization key")
        retired = key_history[0]
        require_equal(retired.get("principal_id"), role,
                      f"{role} retired principal ID")
        require_equal(retired.get("algorithm"), AUTH_ALGORITHM,
                      f"{role} retired principal algorithm")
        retired_digest = require_hash(retired.get("public_key_sha3_256"),
                                      f"{role} retired public-key digest")
        if retired_digest == current_auth_key_hash:
            fail(f"{role} retired authorization key equals the current key")
        require_equal(retired.get("status"), "retired", f"{role} retired-key status")
        require_equal(retired.get("retired_at"), binding.get("effective_at"),
                      f"{role} retired-key boundary")
        if not isinstance(retired.get("reason"), str) or not retired["reason"].strip():
            fail(f"{role} retired authorization key must state a reason")
        if not isinstance(supersession_history, list) or len(supersession_history) != 1:
            fail(f"{role} must record exactly one superseded pre-v1.3 address")
        superseded = supersession_history[0]
        old_address = superseded.get("address")
        if (not isinstance(old_address, str) or ADDRESS.fullmatch(old_address) is None
                or old_address == address):
            fail(f"{role} superseded address is invalid or equals the current identity")
        require_equal(superseded.get("derivation_standard"),
                      "pre-SNTS-01-v1.3-ML-DSA-87-key-derived-authority-address",
                      f"{role} superseded-address derivation")
        require_equal(superseded.get("status"), "superseded",
                      f"{role} superseded-address status")
        if not isinstance(superseded.get("reason"), str) or not superseded["reason"].strip():
            fail(f"{role} superseded address must state a reason")
    elif key_history != [] or supersession_history != []:
        fail(f"{role} fresh binding must have empty key and supersession histories")
    proofs = binding.get("proofs")
    if not isinstance(proofs, dict):
        fail(f"{role} binding proofs must be an object")
    require_equal(proofs.get("identity_root", {}).get("algorithm"), ROOT_ALGORITHM,
                  f"{role} root proof algorithm")
    possessions = proofs.get("authorization_key_possession")
    if not isinstance(possessions, list) or len(possessions) != 1:
        fail(f"{role} binding must have exactly one authorization possession proof")
    require_equal(possessions[0].get("principal_id"), role,
                  f"{role} possession principal ID")
    require_equal(possessions[0].get("algorithm"), AUTH_ALGORITHM,
                  f"{role} possession algorithm")
    require_hash(binding.get("binding_payload_sha3_256"), f"{role} binding payload digest")

    bind_complete = docs["binding_completion"]
    require_equal(bind_complete.get("schema_version"),
                  "synergy-authorization-binding-completion-v1",
                  f"{role} binding completion schema")
    require_completion_common(bind_complete, f"{role} binding completion")
    require_equal(bind_complete.get("identity_id"), role,
                  f"{role} binding completion identity ID")
    require_equal(bind_complete.get("role_id"), role,
                  f"{role} binding completion role ID")
    require_equal(bind_complete.get("identity_address"), address,
                  f"{role} binding completion address")
    require_equal(bind_complete.get("signature_domain"), GENESIS_DOMAIN,
                  f"{role} binding completion signature domain")
    require_equal(bind_complete.get("purpose"), "genesis-signing",
                  f"{role} binding completion purpose")
    require_equal(bind_complete.get("authorization_scopes"), list(SCOPES),
                  f"{role} binding completion scopes")
    for field in ("authorization_scope_signed", "dual_possession_proofs_verified",
                  "fn_identity_root_correspondence_verified",
                  "ml_authorization_key_correspondence_verified"):
        require_true(bind_complete.get(field), f"{role} binding completion {field}")
    require_hash_matches(raws["binding"], bind_complete.get("binding_output_sha256"),
                         f"{role} binding SHA-256")
    require_equal(bind_complete.get("binding_payload_sha3_256"),
                  binding.get("binding_payload_sha3_256"),
                  f"{role} binding payload digest")
    require_hash_matches(raws["identity_root_public"],
                         bind_complete.get("fn_public_input_sha256"),
                         f"{role} binding FN public input SHA-256")
    require_hash_matches(raws["identity_root_encrypted"],
                         bind_complete.get("fn_encrypted_input_sha256"),
                         f"{role} binding FN encrypted input SHA-256")
    require_hash_matches(raws["authorization_public"],
                         bind_complete.get("ml_public_input_sha256"),
                         f"{role} binding ML public input SHA-256")
    require_hash_matches(raws["authorization_encrypted"],
                         bind_complete.get("ml_encrypted_input_sha256"),
                         f"{role} binding ML encrypted input SHA-256")

    artifact_hashes = {key: sha256_bytes(raws[key]) for key in FILES}
    result = {
        "role_id": role,
        "role_kind": ROLE_KINDS[role],
        "identity_address": address,
        "identity_root_public": root,
        "authorization_public": authorization,
        "identity_authorization_binding": binding,
        "custody_inputs": {
            "identity_root_encrypted_relative_path":
                f"{role}/{FILES['identity_root_encrypted']}",
            "identity_root_encrypted_sha256": artifact_hashes["identity_root_encrypted"],
            "authorization_encrypted_relative_path":
                f"{role}/{FILES['authorization_encrypted']}",
            "authorization_encrypted_sha256": artifact_hashes["authorization_encrypted"],
        },
        "source_artifact_sha256": artifact_hashes,
    }
    if role == "SNRG-TESTNET-V3-GOVERNANCE-AUTHORITY":
        release, release_raw = read_json(
            role_dir / "release-authorization-binding.json",
            f"{role} release authorization binding",
        )
        release_complete, release_complete_raw = read_json(
            role_dir / "release-authorization-binding.json.complete.json",
            f"{role} release authorization binding completion",
        )
        require_equal(release.get("schema_version"),
                      "synergy-identity-authorization-binding-v1",
                      f"{role} release binding schema")
        require_equal(release.get("binary_encoding"), "lowercase-hex",
                      f"{role} release binding encoding")
        require_equal(release.get("identity_id"), role,
                      f"{role} release binding identity ID")
        require_equal(release.get("identity_address"), address,
                      f"{role} release binding identity address")
        require_equal(release.get("identity_root"), binding.get("identity_root"),
                      f"{role} release binding identity root")
        release_policy = release.get("authorization_policy")
        if not isinstance(release_policy, dict):
            fail(f"{role} release binding authorization policy must be an object")
        require_equal(release_policy.get("policy_type"), "single-key",
                      f"{role} release policy type")
        require_equal(release_policy.get("threshold"), 1,
                      f"{role} release policy threshold")
        release_principals = release_policy.get("principals")
        if not isinstance(release_principals, list) or len(release_principals) != 1:
            fail(f"{role} release binding must contain exactly one principal")
        release_principal = release_principals[0]
        for field in ("principal_id", "principal_type", "algorithm", "public_key",
                      "public_key_sha3_256", "status"):
            require_equal(release_principal.get(field), principal.get(field),
                          f"{role} release principal {field}")
        require_equal(release_principal.get("purposes"),
                      [RELEASE_SCOPE["purpose"]], f"{role} release principal purposes")
        require_equal(release.get("authorization_scopes"), [RELEASE_SCOPE],
                      f"{role} release authorization scope")
        require_hash(release.get("binding_payload_sha3_256"),
                     f"{role} release binding payload digest")
        require_equal(release_complete.get("schema_version"),
                      "synergy-authorization-binding-completion-v1",
                      f"{role} release binding completion schema")
        require_completion_common(release_complete,
                                  f"{role} release binding completion")
        require_equal(release_complete.get("authorization_scopes"), [RELEASE_SCOPE],
                      f"{role} release binding completion scopes")
        for field in ("authorization_scope_signed", "dual_possession_proofs_verified",
                      "fn_identity_root_correspondence_verified",
                      "ml_authorization_key_correspondence_verified"):
            require_true(release_complete.get(field),
                         f"{role} release binding completion {field}")
        require_hash_matches(release_raw,
                             release_complete.get("binding_output_sha256"),
                             f"{role} release binding SHA-256")
        require_equal(release_complete.get("binding_payload_sha3_256"),
                      release.get("binding_payload_sha3_256"),
                      f"{role} release binding payload digest")
        if replacement is not None:
            validate_replacement_receipt(release_complete, prior, replacement,
                                         f"{role} release completion")
            validate_replacement_history(release, prior, replacement, role)
        result["release_authorization_binding"] = release
        result["source_artifact_sha256"].update({
            "release_binding": sha256_bytes(release_raw),
            "release_binding_completion": sha256_bytes(release_complete_raw),
        })
    return result


def write_no_clobber(path: Path, raw: bytes) -> None:
    if path.exists() or path.is_symlink():
        fail(f"refusing to overwrite existing output: {path}")
    if not path.parent.is_dir():
        fail(f"output parent directory does not exist: {path.parent}")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    descriptor = os.open(path, flags, 0o644)
    try:
        with os.fdopen(descriptor, "wb") as output:
            output.write(raw)
            output.flush()
            os.fsync(output.fileno())
    except BaseException:
        try:
            path.unlink(missing_ok=True)
        finally:
            raise


def build(authority_root: Path, prior_freeze: Path | None = None) -> dict[str, Any]:
    if authority_root.is_symlink() or not authority_root.is_dir():
        fail(f"authority root must be a real directory: {authority_root}")
    prior, replacement, replacement_hash = None, None, None
    if prior_freeze is not None:
        prior, prior_hash = read_prior_freeze(prior_freeze)
        replacement, replacement_hash = validate_replacement_manifest(authority_root, prior_hash)
    elif (authority_root / REPLACEMENT_MANIFEST).exists():
        fail("authority replacement requires explicit --prior-freeze")
    authorities = [validate_role(authority_root, role,
                                prior[role] if prior else None, replacement) for role in ROLES]
    addresses = [authority["identity_address"] for authority in authorities]
    if len(set(addresses)) != len(addresses):
        fail("Genesis authority identity addresses are not unique")
    auth_key_hashes = [sha3_256_bytes(bytes.fromhex(
        authority["authorization_public"]["public_key"])) for authority in authorities]
    if len(set(auth_key_hashes)) != len(auth_key_hashes):
        fail("Genesis authority authorization keys are not unique")
    freeze = {
        "schema_version": "synergy-testnet-v3-genesis-authority-freeze-v1",
        "artifact_type": "fresh-testnet-v3-genesis-authority-public-freeze",
        "chain_id": CHAIN_ID,
        "network_id": NETWORK_ID,
        "release_id": RELEASE_ID,
        "consensus_protocol": "posy/3.0",
        "genesis_boundary": "fresh_genesis_block_zero",
        "address_registry_version": REGISTRY_VERSION,
        "authority_count": len(authorities),
        "authority_role_ids": list(ROLES),
        "authorities": authorities,
    }

    if replacement is not None:
        freeze["authority_replacement"] = {
            "prior_freeze_sha256": replacement["replacement_prior_freeze_sha256"],
            "completion_sha256": replacement_hash,
            "effective_at": replacement["effective_at"],
            "reason": replacement["replacement_reason"],
        }
    return freeze


def production_authority_view(freeze: dict[str, Any], bundle_dir_prefix: str) -> dict[str, Any]:
    prefix = Path(bundle_dir_prefix)
    if (not bundle_dir_prefix or prefix.is_absolute()
            or any(part in ("", ".", "..") for part in prefix.parts)):
        fail("bundle-dir-prefix must be a non-empty repository-relative path without dot segments")
    entries = []
    for authority in freeze["authorities"]:
        public_key = bytes.fromhex(authority["authorization_public"]["public_key"])
        hashes = authority["source_artifact_sha256"]
        entry = {
            "role_id": authority["role_id"],
            "standard_account_address": authority["identity_address"],
            "identity_root_algorithm": ROOT_ALGORITHM,
            "identity_root_public_sha256": hashes["identity_root_public"],
            "identity_root_encrypted_sha256": hashes["identity_root_encrypted"],
            "authorization_algorithm": AUTH_ALGORITHM,
            "authorization_public_sha256": hashes["authorization_public"],
            "authorization_encrypted_sha256": hashes["authorization_encrypted"],
            "public_key_fingerprint": f"sha256:{sha256_bytes(public_key)}",
            "genesis_authorization_binding_sha256": hashes["binding"],
            "genesis_authorization_binding_payload_sha3_256":
                authority["identity_authorization_binding"]["binding_payload_sha3_256"],
            "bundle_dir": str(prefix / authority["role_id"]),
        }
        if authority["role_id"] == "SNRG-TESTNET-V3-GOVERNANCE-AUTHORITY":
            entry.update({
                "release_authorization_binding_sha256": hashes["release_binding"],
                "release_authorization_binding_payload_sha3_256":
                    authority["release_authorization_binding"]["binding_payload_sha3_256"],
            })
        entries.append(entry)
    return {
        "version": 4,
        "artifact": "TESTNET_V3_PRODUCTION_AUTHORITIES",
        "status": "FROZEN",
        "test_fixture": False,
        "current_release_authority": False,
        "chain_id": CHAIN_ID,
        "network_id": NETWORK_ID,
        "release_id": RELEASE_ID,
        "address_registry_version": REGISTRY_VERSION,
        "canonical_synergy_address_model": True,
        "active_address_field": "standard_account_address",
        "authorities": entries,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--authority-root", required=True, type=Path)
    parser.add_argument("--prior-freeze", type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--completion", required=True, type=Path)
    parser.add_argument("--production-authorities-output", type=Path)
    parser.add_argument("--production-authorities-completion", type=Path)
    parser.add_argument("--bundle-dir-prefix", default="testnet-v3-identity-files")
    args = parser.parse_args()
    if args.output == args.completion:
        fail("freeze output and completion output must be different paths")
    if ((args.production_authorities_output is None)
            != (args.production_authorities_completion is None)):
        fail("production authority output and completion must be supplied together")
    if args.output.exists() or args.output.is_symlink():
        fail(f"refusing to overwrite existing output: {args.output}")
    if args.completion.exists() or args.completion.is_symlink():
        fail(f"refusing to overwrite existing completion: {args.completion}")
    for candidate in (args.production_authorities_output,
                      args.production_authorities_completion):
        if candidate is not None and (candidate.exists() or candidate.is_symlink()):
            fail(f"refusing to overwrite existing production authority output: {candidate}")

    freeze = build(args.authority_root.resolve(strict=True), args.prior_freeze)
    freeze_raw = canonical_json_bytes(freeze)
    completion = {
        "schema_version": "synergy-testnet-v3-genesis-authority-freeze-completion-v1",
        "chain_id": CHAIN_ID,
        "network_id": NETWORK_ID,
        "release_id": RELEASE_ID,
        "authority_role_ids": list(ROLES),
        "authority_freeze_sha256": sha256_bytes(freeze_raw),
        "publication_protocol": "no-clobber-manifest-last",
    }
    write_no_clobber(args.output, freeze_raw)
    try:
        write_no_clobber(args.completion, canonical_json_bytes(completion))
        if args.production_authorities_output is not None:
            authority_view = production_authority_view(freeze, args.bundle_dir_prefix)
            authority_view_raw = canonical_json_bytes(authority_view)
            authority_completion = {
                "schema_version":
                    "synergy-testnet-v3-production-authorities-completion-v1",
                "chain_id": CHAIN_ID,
                "network_id": NETWORK_ID,
                "release_id": RELEASE_ID,
                "authority_freeze_sha256": completion["authority_freeze_sha256"],
                "production_authorities_sha256": sha256_bytes(authority_view_raw),
                "publication_protocol": "no-clobber-manifest-last",
            }
            write_no_clobber(args.production_authorities_output, authority_view_raw)
            write_no_clobber(args.production_authorities_completion,
                             canonical_json_bytes(authority_completion))
    except BaseException:
        args.output.unlink(missing_ok=True)
        raise
    print(f"FRESH_TESTNET_V3_GENESIS_AUTHORITY_FREEZE_SHA256={completion['authority_freeze_sha256']}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except FreezeError as error:
        print(f"build-fresh-testnet-v3-genesis-authority-freeze: {error}", file=sys.stderr)
        raise SystemExit(1)
