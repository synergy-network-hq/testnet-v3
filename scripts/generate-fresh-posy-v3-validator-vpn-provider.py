#!/usr/bin/env python3
"""Build and verify the fresh Testnet-v3 validator VPN provider plan.

This is deliberately a *public desired-state* adapter.  It does not create a
WireGuard key, an enrollment token, a NetBird account, or a host configuration.
Those are provider-side custody operations.  Its output is instead the exact
release-bound input an authenticated NetBird reconciliation service must apply
after a finalized governed membership transition.

The older Innernet registry and its candidate bundles are intentionally not
accepted as inputs.  They carry a different identity lineage and cannot become
transport authority for the fresh block-zero PoSy network.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Any, NoReturn


CHAIN_ID = 1266
NETWORK_ID = "testnet"
RELEASE_ID = "testnet-v3"
PROTOCOL_VERSION = "posy/3.0"
GENESIS_ACTIVE_IDS = tuple(f"validator-{number:02d}" for number in range(2, 7))
PREGENERATED_IDS = tuple(f"validator-{number:02d}" for number in range(1, 22))
VALIDATOR_ID_RE = re.compile(r"validator-([0-9]{2,})$")
HEX_64_RE = re.compile(r"[0-9a-f]{64}$")

HUB = {
    "vpn_ip": "10.69.0.1",
    "public_endpoint": "68.183.139.56:51820",
    "udp_port": 51820,
}
ACTIVE_HOST_ALIASES = {
    "validator-02": "synergy-val2",
    "validator-03": "synergy-val3",
    "validator-04": "synergy-val4",
    "validator-05": "synergy-val5",
    "validator-06": "synergy-val6",
}
RELAYER_ASSIGNMENTS = tuple(
    {
        "node_id": f"relayer-{number}",
        "role": "relayer",
        "vpn_ip": f"10.69.1.{number}",
        "ssh_alias": f"synergy-relayer{number}",
        "activation_status": "POST_GENESIS_GOVERNED_SERVICE_ENROLLMENT_REQUIRED",
    }
    for number in range(1, 4)
)


def fail(message: str) -> NoReturn:
    raise SystemExit(f"fresh-posy-v3-validator-vpn-provider: {message}")


def canonical_bytes(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode()


def read_bytes(path: Path) -> bytes:
    try:
        return path.read_bytes()
    except OSError as error:
        fail(f"cannot read {path}: {error}")


def read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(read_bytes(path))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        fail(f"cannot parse JSON {path}: {error}")
    if not isinstance(value, dict):
        fail(f"{path} must contain a JSON object")
    return value


def sha256_file(path: Path) -> str:
    return hashlib.sha256(read_bytes(path)).hexdigest()


def sha256_value(value: Any) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def require(condition: bool, message: str) -> None:
    if not condition:
        fail(message)


def validator_ordinal(validator_id: str) -> int:
    matched = VALIDATOR_ID_RE.fullmatch(validator_id)
    require(matched is not None, f"noncanonical validator identifier: {validator_id!r}")
    ordinal = int(matched.group(1))
    require(1 <= ordinal <= 254, f"validator VPN ordinal outside usable 10.69.10.0/24: {validator_id}")
    return ordinal


def assert_public_only(value: Any, location: str = "") -> None:
    """Reject secret-bearing fields without mistaking public key material for secrets."""
    forbidden = ("private_key", "passphrase", "password", "enrollment_token", "access_token", "client_secret")
    if isinstance(value, dict):
        for key, nested in value.items():
            normalized = str(key).lower()
            require(not any(term in normalized for term in forbidden),
                    f"secret-bearing field is forbidden in public provider plan: {location}/{key}")
            assert_public_only(nested, f"{location}/{key}")
    elif isinstance(value, list):
        for index, nested in enumerate(value):
            assert_public_only(nested, f"{location}/{index}")


def validate_fresh_validator_inputs(value: dict[str, Any]) -> dict[str, dict[str, Any]]:
    require(value.get("artifact_type") == "testnet-v3-fresh-validator-genesis-source-inputs",
            "validator inputs are not the fresh Testnet-v3 ceremony output")
    require(value.get("chain_id") == CHAIN_ID and value.get("network_id") == NETWORK_ID,
            "validator inputs have the wrong network tuple")
    require(value.get("release_id") == RELEASE_ID and value.get("protocol_version") == PROTOCOL_VERSION,
            "validator inputs have the wrong release tuple")
    require(value.get("public_only") is True and value.get("status") == "COMPLETE",
            "validator inputs are not complete public fresh-ceremony evidence")
    membership = value.get("membership")
    require(isinstance(membership, dict), "validator inputs have no membership section")
    require(membership.get("dynamic_validator_membership") is True,
            "validator input does not declare dynamic membership")
    require(membership.get("initial_active_validator_ids") == list(GENESIS_ACTIVE_IDS),
            "validator input does not bind canonical Genesis-active validators")
    source = value.get("genesis_source_fields")
    require(isinstance(source, dict), "validator inputs have no genesis source fields")
    records = source.get("preconfigured_validators")
    require(isinstance(records, list) and len(records) == len(PREGENERATED_IDS),
            "fresh ceremony must contain exactly validator-01 through validator-21")
    by_id: dict[str, dict[str, Any]] = {}
    for record in records:
        require(isinstance(record, dict), "fresh ceremony contains a non-object validator record")
        validator_id = record.get("validator_id")
        require(isinstance(validator_id, str) and validator_id not in by_id,
                "fresh ceremony contains a missing or duplicate validator identifier")
        validator_ordinal(validator_id)
        for field in ("allocation_account_id", "operator_address", "peer_id", "identity_public_key",
                      "consensus_public_key", "key_bundle_hash", "validator_id_hash"):
            require(isinstance(record.get(field), str) and record[field],
                    f"{validator_id} has no public {field}")
        by_id[validator_id] = record
    require(tuple(by_id) == PREGENERATED_IDS,
            "preconfigured validator records are not the canonical validator-01 through validator-21 order")
    active_records = source.get("validators")
    require(isinstance(active_records, list), "fresh ceremony has no Genesis-active validator list")
    require(tuple(record.get("validator_id") for record in active_records if isinstance(record, dict)) == GENESIS_ACTIVE_IDS,
            "fresh ceremony Genesis-active records are not validator-02 through validator-06")
    for validator_id in GENESIS_ACTIVE_IDS:
        require(by_id[validator_id].get("status") == "active_at_genesis",
                f"{validator_id} is not active_at_genesis in fresh ceremony")
    for validator_id in PREGENERATED_IDS:
        if validator_id not in GENESIS_ACTIVE_IDS:
            require(by_id[validator_id].get("status") == "preconfigured_pending_activation",
                    f"{validator_id} must be preconfigured_pending_activation")
    return by_id


def validate_authority_freeze(value: dict[str, Any]) -> None:
    require(value.get("artifact_type") == "fresh-testnet-v3-genesis-authority-public-freeze",
            "authority input is not the fresh public authority freeze")
    require(value.get("chain_id") == CHAIN_ID and value.get("network_id") == NETWORK_ID,
            "authority freeze has the wrong network tuple")
    require(value.get("release_id") == RELEASE_ID and value.get("consensus_protocol") == PROTOCOL_VERSION,
            "authority freeze has the wrong release tuple")
    require(value.get("genesis_boundary") == "fresh_genesis_block_zero",
            "authority freeze is not bound to fresh block zero")
    roles = value.get("authority_role_ids")
    require(isinstance(roles, list) and set(roles) == {
        "SNRG-TESTNET-V3-GENESIS-DEPLOYER",
        "SNRG-TESTNET-V3-GOVERNANCE-AUTHORITY",
        "SNRG-TESTNET-V3-VALIDATOR-REGISTRY-AUTHORITY",
    }, "fresh authority freeze lacks the three required authorities")


def validator_participant(record: dict[str, Any]) -> dict[str, Any]:
    validator_id = record["validator_id"]
    ordinal = validator_ordinal(validator_id)
    active = validator_id in GENESIS_ACTIVE_IDS
    if active:
        status = "GENESIS_ACTIVE_PROVIDER_ENROLLMENT_REQUIRED"
    elif validator_id == "validator-01":
        status = "RESERVED_INACTIVE_NOT_DEPLOYED"
    else:
        status = "PREGENERATED_INACTIVE_GOVERNED_TRANSITION_REQUIRED"
    return {
        "validator_id": validator_id,
        "role": "validator",
        "identity_id": record["allocation_account_id"],
        "synv_address": record["operator_address"],
        "peer_id": record["peer_id"],
        "identity_public_key_sha256": hashlib.sha256(record["identity_public_key"].encode()).hexdigest(),
        "consensus_public_key_sha256": hashlib.sha256(record["consensus_public_key"].encode()).hexdigest(),
        "ceremony_bundle_hash": record["key_bundle_hash"],
        "vpn_ip": f"10.69.10.{ordinal}",
        "ssh_alias": ACTIVE_HOST_ALIASES.get(validator_id),
        "activation_status": status,
    }


def build_registry(validator_inputs_path: Path, authority_freeze_path: Path) -> dict[str, Any]:
    validator_inputs = read_json(validator_inputs_path)
    authority_freeze = read_json(authority_freeze_path)
    by_id = validate_fresh_validator_inputs(validator_inputs)
    validate_authority_freeze(authority_freeze)
    participants = [validator_participant(by_id[validator_id]) for validator_id in PREGENERATED_IDS]
    active_transports = [
        {
            "validator_id": participant["validator_id"],
            "validator_address": participant["synv_address"],
            "dial_address": f"{participant['vpn_ip']}:5622",
        }
        for participant in participants
        if participant["validator_id"] in GENESIS_ACTIVE_IDS
    ]
    registry: dict[str, Any] = {
        "schema_version": "synergy-testnet-v3-fresh-vpn-provider-plan-v1",
        "artifact_type": "testnet-v3-fresh-validator-vpn-provider-plan",
        "status": "PUBLIC_DESIRED_STATE_EXTERNAL_PROVIDER_ATTESTATION_REQUIRED",
        "chain_id": CHAIN_ID,
        "network_id": NETWORK_ID,
        "release_id": RELEASE_ID,
        "protocol_version": PROTOCOL_VERSION,
        "genesis_boundary": "fresh_genesis_block_zero",
        "private_material_present": False,
        "provider": {
            "kind": "netbird",
            "mode": "external_authenticated_reconciliation",
            "management_api_credentials": "external_operator_custody_only",
            "release_artifact_contains_provider_credentials": False,
            "network_name": "synergy-testnet-v3-validator-vpn",
            "transport": "wireguard",
            "hub_udp_port": HUB["udp_port"],
        },
        "hub": HUB,
        "authoritative_bindings": {
            "fresh_validator_inputs_sha256": sha256_file(validator_inputs_path),
            "fresh_authority_freeze_sha256": sha256_file(authority_freeze_path),
            "fresh_validator_input_status": validator_inputs["status"],
            "authority_role_ids": authority_freeze["authority_role_ids"],
        },
        "initial_active_validator_ids": list(GENESIS_ACTIVE_IDS),
        "pre_generated_validator_ids": list(PREGENERATED_IDS),
        "participants": participants,
        "relayer_assignments": list(RELAYER_ASSIGNMENTS),
        "transport_snapshot_request": {
            "schema": "synergy-testnet-v3-validator-transport-snapshot-v1",
            "network": "synergy-testnet-v3-validator-transport-v1",
            "registry_id": "synergy-testnet-v3-block-zero-transport-v1",
            "configuration_version": 1,
            "status": "UNSIGNED_EXTERNAL_TRANSPORT_ATTESTATION_REQUIRED",
            "signature_algorithm": "ed25519",
            "signature_authorization": "external_release_bound_transport_attestation_key",
            "provider_plan_binding": "the finalized signed snapshot must bind this registry SHA-256",
            "transports": active_transports,
            "runtime_configuration": {
                "snapshot_url_environment": "SYNERGY_TESTNET_V3_VALIDATOR_TRANSPORT_SNAPSHOT_URL",
                "attestation_public_key_environment": "SYNERGY_TESTNET_V3_TRANSPORT_ATTESTATION_PUBLIC_KEY",
                "persisted_snapshot_relative_path": "data/validator_transport_registry.json",
                "missing_snapshot_behavior": "production_validator_network_start_refused",
            },
        },
        "dynamic_onboarding": {
            "validator_id_pattern": "validator-NN",
            "usable_validator_vpn_ordinal_range": {"first": 1, "last": 254},
            "pre_generated_identity_pool": list(PREGENERATED_IDS),
            "governed_extension_allowed": True,
            "provider_reconciliation_trigger": "finalized_governed_validator_set_transition",
            "required_preconditions": [
                "finalized_membership_proof",
                "validator_registry_authorization",
                "unique_canonical_validator_identity",
                "unique_vpn_ip_and_provider_peer",
                "release_and_configuration_hash_match",
                "explicit_activation_epoch_or_height",
            ],
            "transport_not_consensus_authority": True,
        },
        "external_provider_attestation_requirement": {
            "required_before_host_activation": True,
            "must_bind_provider_network_name": "synergy-testnet-v3-validator-vpn",
            "must_bind_plan_sha256": "computed_in_offline_proof",
            "must_confirm_hub_udp_port": HUB["udp_port"],
            "must_confirm_assigned_routes": True,
            "must_not_include_provider_credentials": True,
        },
    }
    assert_public_only(registry)
    return registry


def validate_registry(registry: dict[str, Any], validator_inputs_path: Path, authority_freeze_path: Path) -> list[str]:
    require(registry.get("schema_version") == "synergy-testnet-v3-fresh-vpn-provider-plan-v1",
            "VPN registry has the wrong schema")
    require(registry.get("artifact_type") == "testnet-v3-fresh-validator-vpn-provider-plan",
            "VPN registry is not the fresh provider plan")
    require(registry.get("chain_id") == CHAIN_ID and registry.get("network_id") == NETWORK_ID,
            "VPN registry has the wrong network tuple")
    require(registry.get("release_id") == RELEASE_ID and registry.get("protocol_version") == PROTOCOL_VERSION,
            "VPN registry has the wrong release tuple")
    require(registry.get("genesis_boundary") == "fresh_genesis_block_zero",
            "VPN registry is not block-zero bound")
    require(registry.get("private_material_present") is False,
            "VPN registry declares private material")
    provider = registry.get("provider")
    require(isinstance(provider, dict) and provider.get("kind") == "netbird",
            "fresh provider plan must target the NetBird management plane")
    require(provider.get("mode") == "external_authenticated_reconciliation",
            "fresh provider plan has unsafe provider mode")
    require(provider.get("hub_udp_port") == 51820, "VPN provider uses the wrong public UDP port")
    hub = registry.get("hub")
    require(hub == HUB, "fresh VPN hub assignment differs from canonical 10.69/51820 assignment")
    snapshot = registry.get("transport_snapshot_request")
    require(isinstance(snapshot, dict), "VPN registry has no fresh transport snapshot request")
    require(snapshot.get("schema") == "synergy-testnet-v3-validator-transport-snapshot-v1",
            "VPN transport snapshot request has the wrong schema")
    require(snapshot.get("network") == "synergy-testnet-v3-validator-transport-v1"
            and snapshot.get("registry_id") == "synergy-testnet-v3-block-zero-transport-v1",
            "VPN transport snapshot request is not fresh-P3 bound")
    require(snapshot.get("configuration_version") == 1
            and snapshot.get("status") == "UNSIGNED_EXTERNAL_TRANSPORT_ATTESTATION_REQUIRED",
            "VPN transport snapshot request has unsafe lifecycle state")
    require(snapshot.get("signature_algorithm") == "ed25519"
            and snapshot.get("signature_authorization") == "external_release_bound_transport_attestation_key",
            "VPN transport snapshot request has an invalid attestation policy")
    bindings = registry.get("authoritative_bindings")
    require(isinstance(bindings, dict), "VPN registry lacks authoritative input bindings")
    require(bindings.get("fresh_validator_inputs_sha256") == sha256_file(validator_inputs_path),
            "VPN registry is not bound to supplied fresh validator inputs")
    require(bindings.get("fresh_authority_freeze_sha256") == sha256_file(authority_freeze_path),
            "VPN registry is not bound to supplied fresh authority freeze")
    expected = build_registry(validator_inputs_path, authority_freeze_path)
    require(registry == expected, "VPN registry differs from deterministic fresh provider desired state")
    participants = registry.get("participants")
    require(isinstance(participants, list) and len(participants) == len(PREGENERATED_IDS),
            "VPN registry must contain the 21 pre-generated validator slots")
    require(tuple(item.get("validator_id") for item in participants if isinstance(item, dict)) == PREGENERATED_IDS,
            "VPN registry validators are not canonical validator-01 through validator-21")
    require(registry.get("initial_active_validator_ids") == list(GENESIS_ACTIVE_IDS),
            "VPN registry initial set is not validator-02 through validator-06")
    active = [item for item in participants if item["validator_id"] in GENESIS_ACTIVE_IDS]
    require(all(item["activation_status"] == "GENESIS_ACTIVE_PROVIDER_ENROLLMENT_REQUIRED" for item in active),
            "Genesis-active validator VPN enrollment states are invalid")
    require(all(item["ssh_alias"] == ACTIVE_HOST_ALIASES[item["validator_id"]] for item in active),
            "Genesis-active validator SSH aliases are invalid")
    for item in participants:
        ordinal = validator_ordinal(item["validator_id"])
        require(item["vpn_ip"] == f"10.69.10.{ordinal}",
                f"{item['validator_id']} does not have its canonical 10.69.10 VPN slot")
    expected_transports = [
        {
            "validator_id": item["validator_id"],
            "validator_address": item["synv_address"],
            "dial_address": f"{item['vpn_ip']}:5622",
        }
        for item in active
    ]
    require(snapshot.get("transports") == expected_transports,
            "VPN transport snapshot request does not bind the exact Genesis-active routes")
    runtime_configuration = snapshot.get("runtime_configuration")
    require(runtime_configuration == {
        "snapshot_url_environment": "SYNERGY_TESTNET_V3_VALIDATOR_TRANSPORT_SNAPSHOT_URL",
        "attestation_public_key_environment": "SYNERGY_TESTNET_V3_TRANSPORT_ATTESTATION_PUBLIC_KEY",
        "persisted_snapshot_relative_path": "data/validator_transport_registry.json",
        "missing_snapshot_behavior": "production_validator_network_start_refused",
    }, "VPN transport snapshot request runtime contract is invalid")
    relayers = registry.get("relayer_assignments")
    require(relayers == list(RELAYER_ASSIGNMENTS), "relayer VPN assignments are not canonical")
    dynamic = registry.get("dynamic_onboarding")
    require(isinstance(dynamic, dict) and dynamic.get("governed_extension_allowed") is True,
            "VPN plan does not permit governed dynamic validator onboarding")
    require(dynamic.get("usable_validator_vpn_ordinal_range") == {"first": 1, "last": 254},
            "VPN plan has an invalid future validator slot range")
    serialized = canonical_bytes(registry).decode().lower()
    for retired in ("innernet", "10.70.", "posy-validator", "candidate bundle", "legacy"):
        require(retired not in serialized, f"fresh VPN plan contains retired term or route: {retired}")
    assert_public_only(registry)
    return [
        "fresh validator ceremony binding",
        "fresh authority-freeze binding",
        "canonical 10.69 route plan",
        "canonical validator and relayer identifiers",
        "dynamic governed onboarding policy",
        "fresh signed-transport snapshot request",
        "public-only release artifact",
        "retired-provider exclusion",
    ]


def write_pair(registry_path: Path, proof_path: Path, registry: dict[str, Any], checks: list[str]) -> None:
    require(registry_path != proof_path, "registry and proof paths must differ")
    require(not registry_path.exists(), f"refusing to overwrite registry: {registry_path}")
    require(not proof_path.exists(), f"refusing to overwrite proof: {proof_path}")
    registry_path.parent.mkdir(parents=True, exist_ok=True)
    proof_path.parent.mkdir(parents=True, exist_ok=True)
    require(registry_path.parent == proof_path.parent,
            "registry and proof must be created in the same output directory")
    staging = Path(tempfile.mkdtemp(prefix=".fresh-vpn-provider.", dir=registry_path.parent))
    try:
        staged_registry = staging / registry_path.name
        staged_registry.write_bytes(canonical_bytes(registry))
        proof = {
            "schema_version": "synergy-testnet-v3-fresh-vpn-provider-proof-v1",
            "artifact_type": "testnet-v3-fresh-validator-vpn-provider-offline-proof",
            "status": "OFFLINE_VALIDATED_EXTERNAL_PROVIDER_ATTESTATION_REQUIRED",
            "registry_sha256": sha256_file(staged_registry),
            "registry_canonical_sha256": sha256_value(registry),
            "checks": checks,
            "external_prerequisites": [
                "A NetBird management endpoint and project/network configured for synergy-testnet-v3-validator-vpn.",
                "An externally held least-privilege reconciliation credential; it must never enter this repository or release artifact.",
                "A public provider attestation binding the management-network identity, this registry SHA-256, the 10.69 assignments, and hub UDP 51820.",
                "A signed fresh transport snapshot matching transport_snapshot_request and a release-bound public attestation key configured on every validator.",
                "Live per-host route, peer-authentication, firewall, and reachability preflight after approved identity installation.",
            ],
            "transport_authorization": "none; consensus authority remains the finalized governed validator set",
        }
        staged_proof = staging / proof_path.name
        staged_proof.write_bytes(canonical_bytes(proof))
        os.chmod(staged_registry, 0o644)
        os.chmod(staged_proof, 0o644)
        os.rename(staged_registry, registry_path)
        os.rename(staged_proof, proof_path)
    finally:
        shutil.rmtree(staging, ignore_errors=True)


def verify(registry_path: Path, proof_path: Path, validator_inputs_path: Path, authority_freeze_path: Path) -> None:
    registry = read_json(registry_path)
    checks = validate_registry(registry, validator_inputs_path, authority_freeze_path)
    proof = read_json(proof_path)
    require(proof.get("schema_version") == "synergy-testnet-v3-fresh-vpn-provider-proof-v1",
            "VPN proof has the wrong schema")
    require(proof.get("artifact_type") == "testnet-v3-fresh-validator-vpn-provider-offline-proof",
            "VPN proof has the wrong artifact type")
    require(proof.get("registry_sha256") == sha256_file(registry_path),
            "VPN proof does not bind the registry bytes")
    require(proof.get("registry_canonical_sha256") == sha256_value(registry),
            "VPN proof does not bind the canonical registry")
    require(proof.get("checks") == checks, "VPN proof check list is incomplete")
    require(proof.get("transport_authorization") == "none; consensus authority remains the finalized governed validator set",
            "VPN proof does not preserve transport/consensus separation")
    assert_public_only(proof)
    print("FRESH_POSY_V3_NETBIRD_PROVIDER_OFFLINE_VERIFIED")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    build = subparsers.add_parser("build", help="create fresh public desired state and offline proof")
    build.add_argument("--validator-inputs", required=True, type=Path)
    build.add_argument("--authority-freeze", required=True, type=Path)
    build.add_argument("--output-registry", required=True, type=Path)
    build.add_argument("--output-proof", required=True, type=Path)
    check = subparsers.add_parser("verify", help="verify an existing fresh public desired state and proof")
    check.add_argument("--validator-inputs", required=True, type=Path)
    check.add_argument("--authority-freeze", required=True, type=Path)
    check.add_argument("--registry", required=True, type=Path)
    check.add_argument("--proof", required=True, type=Path)
    args = parser.parse_args()
    if args.command == "build":
        registry = build_registry(args.validator_inputs, args.authority_freeze)
        checks = validate_registry(registry, args.validator_inputs, args.authority_freeze)
        write_pair(args.output_registry.resolve(), args.output_proof.resolve(), registry, checks)
        print(f"FRESH_POSY_V3_NETBIRD_PROVIDER_PLAN_READY {args.output_registry.resolve()}")
        return
    verify(args.registry, args.proof, args.validator_inputs, args.authority_freeze)


if __name__ == "__main__":
    main()
