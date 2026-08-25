#!/usr/bin/env python3
"""Verify fresh public deployment evidence and compose its source Genesis.

This command performs no deployment and has no custody access.  It refuses any
evidence not bound to the exact fresh P3 predeployment input, ceremony
authority freeze, matching V4 release authority record, allocation plan,
resolved allocation artifact, validator adapter, and staged contract artifact
set.  Derived receipt and Genesis integrity roots are
recomputed locally; no root is copied from a historical Genesis document.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import re
from typing import Any

import blake3


CHAIN_ID = 1266
NETWORK_ID = "testnet"
RELEASE_ID = "testnet-v3"
PROTOCOL_VERSION = "posy/3.0"
CANONICAL_CAIP2 = "synergy:testnet-v3"
CONTRACT_ORDER = [
    "Identity",
    "ValidatorRegistry",
    "Staking",
    "Governance",
    "Treasury",
    "Slashing",
    "RewardDistributor",
    "SynergyOracle",
    "TeamVesting",
]
CONTRACT_KEYS = {
    "Identity": "identity",
    "ValidatorRegistry": "validator_registry",
    "Staking": "staking",
    "Governance": "governance",
    "Treasury": "treasury",
    "Slashing": "slashing",
    "RewardDistributor": "reward_distributor",
    "TeamVesting": "team_vesting",
    "SynergyOracle": "synergy_oracle",
}
GENESIS_AUTHORITY_ROLES = [
    "SNRG-TESTNET-V3-GENESIS-DEPLOYER",
    "SNRG-TESTNET-V3-GOVERNANCE-AUTHORITY",
    "SNRG-TESTNET-V3-VALIDATOR-REGISTRY-AUTHORITY",
]
RETIRED = {"posy/2.2", "posy/v2.2", "synergy-testnet-v3", "ProofOfSynergy"}
HEX64 = re.compile(r"^[0-9a-f]{64}$")


def fail(message: str) -> "NoReturn":
    raise SystemExit(f"compose-fresh-posy-v3-executed-genesis: {message}")


def read_bytes(path: Path, label: str) -> bytes:
    try:
        return path.read_bytes()
    except OSError as error:
        fail(f"read {label} {path}: {error}")


def read_json(path: Path, label: str) -> tuple[Any, bytes]:
    raw = read_bytes(path, label)
    try:
        return json.loads(raw), raw
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        fail(f"decode {label} {path}: {error}")


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def require_hash(value: Any, label: str) -> str:
    if not isinstance(value, str) or HEX64.fullmatch(value) is None:
        fail(f"{label} is not a 64-character lowercase hash")
    return value


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()


def hash_json(value: Any) -> str:
    return blake3.blake3(canonical_json(value)).hexdigest()


def domain_hash(domain: str, material: bytes) -> str:
    encoded = domain.encode() + len(domain).to_bytes(8, "big") + material
    return blake3.blake3(encoded).hexdigest()


def receipt_root(deployments: list[dict[str, Any]], initializations: list[dict[str, Any]]) -> str:
    domain = "SYNERGY_GENESIS_RECEIPT_ROOT_V1"
    material = bytearray(domain.encode())
    for receipt in deployments + initializations:
        for field in [
            "operation",
            "contract_address",
            "status",
            "return_data_hex",
            "pre_state_root",
            "post_state_root",
        ]:
            value = receipt.get(field)
            if not isinstance(value, str):
                fail(f"receipt {field} is missing")
            material.extend(value.encode())
        logs = receipt.get("logs")
        if not isinstance(logs, list) or not all(isinstance(log, str) for log in logs):
            fail("receipt logs must be an array of strings")
        for log in logs:
            material.extend(log.encode())
    return domain_hash(domain, bytes(material))


def validate_receipts(receipts: Any, count: int, label: str) -> list[dict[str, Any]]:
    if not isinstance(receipts, list) or len(receipts) != count:
        fail(f"{label} must contain exactly {count} receipts")
    for index, receipt in enumerate(receipts):
        if not isinstance(receipt, dict):
            fail(f"{label}[{index}] is not an object")
        if receipt.get("status") != "succeeded" or receipt.get("error_code") is not None:
            fail(f"{label}[{index}] did not succeed")
        if index and receipts[index - 1].get("post_state_root") != receipt.get("pre_state_root"):
            fail(f"{label} state transition is discontinuous at index {index}")
    return receipts


def artifact_set_hash(directory: Path) -> tuple[str, list[dict[str, str]]]:
    entries: list[dict[str, str]] = []
    for contract in CONTRACT_ORDER:
        for suffix in ["synq", "compiled.synq", "abi.json", "manifest.json"]:
            path = directory / f"{contract}.{suffix}"
            entries.append({"file": path.name, "sha256": sha256(read_bytes(path, "contract artifact"))})
    return sha256(canonical_json(entries)), entries


def has_retired(value: Any) -> bool:
    if isinstance(value, dict):
        return any(key.lower().startswith("synixn") or has_retired(entry) for key, entry in value.items())
    if isinstance(value, list):
        return any(has_retired(entry) for entry in value)
    return isinstance(value, str) and (value in RETIRED or "synixn" in value.lower())


def require_equal(actual: Any, expected: Any, label: str) -> None:
    if actual != expected:
        fail(f"{label} differs from the canonical fresh-P3 value")


def require_object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        fail(f"{label} must be an object")
    return value


def require_array(value: Any, label: str) -> list[Any]:
    if not isinstance(value, list):
        fail(f"{label} must be an array")
    return value


def validate_authority_cross_binding(
    ceremony_freeze: dict[str, Any], release_authorities: dict[str, Any]
) -> None:
    """Bind ceremony custody evidence to the distinct V4 release authority view."""
    expected_freeze = {
        "schema_version": "synergy-testnet-v3-genesis-authority-freeze-v1",
        "artifact_type": "fresh-testnet-v3-genesis-authority-public-freeze",
        "chain_id": CHAIN_ID,
        "network_id": NETWORK_ID,
        "release_id": RELEASE_ID,
        "consensus_protocol": PROTOCOL_VERSION,
        "genesis_boundary": "fresh_genesis_block_zero",
        "authority_count": len(GENESIS_AUTHORITY_ROLES),
        "authority_role_ids": GENESIS_AUTHORITY_ROLES,
    }
    for field, expected in expected_freeze.items():
        require_equal(ceremony_freeze.get(field), expected, f"ceremony freeze {field}")
    freeze_entries = require_array(ceremony_freeze.get("authorities"), "ceremony freeze authorities")
    if [entry.get("role_id") if isinstance(entry, dict) else None for entry in freeze_entries] != GENESIS_AUTHORITY_ROLES:
        fail("ceremony freeze authority role order is not canonical")

    expected_release = {
        "version": 4,
        "artifact": "TESTNET_V3_PRODUCTION_AUTHORITIES",
        "status": "FROZEN",
        "test_fixture": False,
        "current_release_authority": False,
        "chain_id": CHAIN_ID,
        "network_id": NETWORK_ID,
        "release_id": RELEASE_ID,
        "canonical_synergy_address_model": True,
        "active_address_field": "standard_account_address",
    }
    for field, expected in expected_release.items():
        require_equal(release_authorities.get(field), expected, f"V4 release authority {field}")
    if any(field in release_authorities for field in [
        "technical_network_id", "runtime_network_id", "network_slug", "network_native_id"
    ]):
        fail("V4 release authority record contains a retired network field")
    release_entries = require_array(release_authorities.get("authorities"), "V4 release authorities")
    if [entry.get("role_id") if isinstance(entry, dict) else None for entry in release_entries] != GENESIS_AUTHORITY_ROLES:
        fail("V4 release authority role order is not canonical")

    for freeze_entry_raw, release_entry_raw in zip(freeze_entries, release_entries):
        freeze_entry = require_object(freeze_entry_raw, "ceremony freeze authority entry")
        release_entry = require_object(release_entry_raw, "V4 release authority entry")
        role = freeze_entry["role_id"]
        source_hashes = require_object(
            freeze_entry.get("source_artifact_sha256"), f"{role} ceremony source hashes"
        )
        custody = require_object(freeze_entry.get("custody_inputs"), f"{role} ceremony custody inputs")
        authorization = require_object(
            freeze_entry.get("authorization_public"), f"{role} ceremony authorization public key"
        )
        public_key = authorization.get("public_key")
        if not isinstance(public_key, str):
            fail(f"{role} ceremony authorization public key is missing")
        try:
            public_key_bytes = bytes.fromhex(public_key)
        except ValueError:
            fail(f"{role} ceremony authorization public key is not lowercase hex")
        expected_entry = {
            "role_id": role,
            "standard_account_address": freeze_entry.get("identity_address"),
            "identity_root_algorithm": require_object(
                freeze_entry.get("identity_root_public"), f"{role} ceremony identity root"
            ).get("algorithm"),
            "identity_root_public_sha256": source_hashes.get("identity_root_public"),
            "identity_root_encrypted_sha256": custody.get("identity_root_encrypted_sha256"),
            "authorization_algorithm": authorization.get("algorithm"),
            "authorization_public_sha256": source_hashes.get("authorization_public"),
            "authorization_encrypted_sha256": custody.get("authorization_encrypted_sha256"),
            "public_key_fingerprint": f"sha256:{sha256(public_key_bytes)}",
            "genesis_authorization_binding_sha256": source_hashes.get("binding"),
            "genesis_authorization_binding_payload_sha3_256": require_object(
                freeze_entry.get("identity_authorization_binding"),
                f"{role} ceremony authorization binding",
            ).get("binding_payload_sha3_256"),
        }
        for field, expected in expected_entry.items():
            if expected is None:
                fail(f"{role} ceremony freeze is missing {field}")
            require_equal(release_entry.get(field), expected, f"{role} V4 release authority {field}")
        if not isinstance(release_entry.get("bundle_dir"), str) or not release_entry["bundle_dir"]:
            fail(f"{role} V4 release authority has no bundle_dir")
        if role == "SNRG-TESTNET-V3-GOVERNANCE-AUTHORITY":
            release_binding = freeze_entry.get("release_authorization_binding")
            if not isinstance(release_binding, dict):
                fail("governance ceremony freeze has no release authorization binding")
            for field, expected in {
                "release_authorization_binding_sha256": source_hashes.get("release_binding"),
                "release_authorization_binding_payload_sha3_256": release_binding.get("binding_payload_sha3_256"),
            }.items():
                if expected is None:
                    fail(f"governance ceremony freeze is missing {field}")
                require_equal(release_entry.get(field), expected, f"governance V4 release authority {field}")


def account_map(entries: Any, label: str) -> dict[str, dict[str, Any]]:
    if not isinstance(entries, list):
        fail(f"{label} must be an array")
    result: dict[str, dict[str, Any]] = {}
    for entry in entries:
        if not isinstance(entry, dict) or not isinstance(entry.get("account_id"), str):
            fail(f"{label} contains a malformed record")
        if entry["account_id"] in result:
            fail(f"{label} contains duplicate {entry['account_id']}")
        result[entry["account_id"]] = entry
    return result


def remove_dotted_path(value: Any, path: str) -> None:
    parts = path.split(".")
    current = value
    for part in parts[:-1]:
        if not isinstance(current, dict) or part not in current:
            return
        current = current[part]
    if isinstance(current, dict):
        current.pop(parts[-1], None)


def recompute_integrity(candidate: dict[str, Any]) -> None:
    empty_hash = blake3.blake3(b"").hexdigest()
    allocation_hash = hash_json(candidate["allocations"])
    validator_hash = hash_json(candidate["validators"])
    validator_set_hash = hash_json(candidate["contracts"]["validator_registry"]["init_params"]["validators"])
    candidate["contracts"]["validator_registry"]["init_params"]["validator_set_hash"] = validator_set_hash
    contract_hash = hash_json(candidate["contracts"])
    state_components = {
        key: candidate[key]
        for key in [
            "accounts",
            "balances",
            "allocations",
            "contracts",
            "consensus",
            "governance",
            "modules",
            "network",
            "security",
            "synergy_state",
            "token",
            "validators",
        ]
    }
    state_components["execution"] = candidate["execution"]
    state_components["genesis_deployment"] = candidate["genesis_deployment"]
    if "contract_address_migration" in candidate:
        state_components["contract_address_migration"] = candidate["contract_address_migration"]
    state_root = hash_json(state_components)
    data_root = hash_json(
        {"contracts": candidate["contracts"], "modules": candidate["modules"], "precompiles": candidate["precompiles"]}
    )
    receipts = candidate["genesis_deployment"]["receipt_root"]
    candidate["header"].update(
        {
            "parent_hash": "0" * 64,
            "transactions_root": empty_hash,
            "receipts_root": receipts,
            "state_root": state_root,
            "data_root": data_root,
        }
    )
    candidate["integrity"].update(
        {
            "allocation_hash": allocation_hash,
            "validator_hash": validator_hash,
            "validator_set_hash": validator_set_hash,
            "contract_hash": contract_hash,
            "state_root": state_root,
            "receipt_root": receipts,
            "signed_by": [],
        }
    )
    inputs = candidate["canonicalization"]["genesis_hash_inputs"]
    if "genesis_deployment" not in inputs:
        inputs.append("genesis_deployment")
    if "contract_address_migration" not in inputs:
        inputs.append("contract_address_migration")
    payload = {key: copy.deepcopy(candidate[key]) for key in inputs if key in candidate}
    excluded = set(candidate["canonicalization"].get("excluded_from_genesis_hash", []))
    excluded.update(
        {
            "integrity.genesis_hash",
            "integrity.signed_by",
            "integrity.draft_artifact_sha256",
            "integrity.recompute_required",
            "integrity.recompute_reason",
            "p2p_identity.network_magic_bytes",
            "p2p_identity.provisional_derivation_note",
        }
    )
    for path in sorted(excluded):
        remove_dotted_path(payload, path)
    genesis_hash = hash_json(payload)
    candidate["integrity"]["genesis_hash"] = genesis_hash
    magic_material = b"synergy-network-magic-v1" + CANONICAL_CAIP2.encode() + genesis_hash.encode()
    candidate["network_magic_bytes"]["value"] = blake3.blake3(magic_material).digest()[:4].hex()
    candidate["network_magic_bytes"]["status"] = "FRESH_P3_DEPLOYMENT_BOUND"


def write_new(path: Path, value: dict[str, Any]) -> None:
    if path.exists():
        fail(f"refusing to overwrite {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    raw = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
    with os.fdopen(descriptor, "wb") as output:
        output.write(raw)
        output.flush()
        os.fsync(output.fileno())


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-genesis", type=Path, required=True)
    parser.add_argument("--allocation-manifest", type=Path, required=True)
    parser.add_argument("--resolved-allocations", type=Path, required=True)
    parser.add_argument("--validator-inputs", type=Path, required=True)
    parser.add_argument("--authority-record", type=Path, required=True)
    parser.add_argument("--release-authority-record", type=Path, required=True)
    parser.add_argument("--contracts-dir", type=Path, required=True)
    parser.add_argument("--execution-status", type=Path, required=True)
    parser.add_argument("--deployment-receipts", type=Path, required=True)
    parser.add_argument("--initialization-receipts", type=Path, required=True)
    parser.add_argument("--execution-state", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    source, source_raw = read_json(args.source_genesis, "fresh predeployment Genesis")
    allocation, allocation_raw = read_json(args.allocation_manifest, "allocation plan")
    resolved, resolved_raw = read_json(args.resolved_allocations, "resolved allocations")
    validator, validator_raw = read_json(args.validator_inputs, "validator inputs")
    authority, authority_raw = read_json(args.authority_record, "ceremony authority freeze")
    release_authority, release_authority_raw = read_json(
        args.release_authority_record, "V4 release authority record"
    )
    status, status_raw = read_json(args.execution_status, "execution status")
    deployments_value, deployments_raw = read_json(args.deployment_receipts, "deployment receipts")
    initializations_value, initializations_raw = read_json(args.initialization_receipts, "initialization receipts")
    snapshot, snapshot_raw = read_json(args.execution_state, "execution snapshot")
    if not all(
        isinstance(value, dict)
        for value in [source, allocation, resolved, validator, authority, release_authority, status, snapshot]
    ):
        fail("object input decoded to a non-object")

    validate_authority_cross_binding(authority, release_authority)

    if source.get("network", {}).get("chain_id") != CHAIN_ID or source.get("network", {}).get("network_id") != NETWORK_ID:
        fail("source Genesis is not Chain 1266 / technical network testnet")
    if source.get("network", {}).get("release_id") != RELEASE_ID or source.get("network", {}).get("consensus_version") != PROTOCOL_VERSION:
        fail("source Genesis is not Testnet-v3 PoSy 3.0")
    if has_retired(source):
        fail("source Genesis contains a retired chain identifier")
    if source.get("genesis_deployment") is not None:
        fail("source Genesis already contains deployment state")

    artifacts_sha, artifact_entries = artifact_set_hash(args.contracts_dir)
    expected_inputs = {
        "source_genesis_sha256": sha256(source_raw),
        "allocation_manifest_sha256": sha256(allocation_raw),
        "resolved_allocations_sha256": sha256(resolved_raw),
        "validator_inputs_sha256": sha256(validator_raw),
        "authority_record_sha256": sha256(authority_raw),
        "contract_artifact_set_sha256": artifacts_sha,
    }
    expected_candidate_input_id = sha256(canonical_json(expected_inputs))
    if status.get("schema_version") != 1 or status.get("artifact_type") != "fresh-p3-executed-deployment-evidence":
        fail("execution status has the wrong schema/artifact type")
    if status.get("status") != "EXECUTION_PASSED" or status.get("mode") != "execute":
        fail("execution status is not a completed execute record")
    if status.get("chain_id") != CHAIN_ID or status.get("network_id") != NETWORK_ID:
        fail("execution evidence has the wrong chain/network")
    if status.get("release_id") != RELEASE_ID or status.get("protocol_version") != PROTOCOL_VERSION:
        fail("execution evidence has the wrong release/protocol")
    if status.get("inputs") != expected_inputs:
        fail("execution evidence input hashes do not match the exact fresh P3 inputs")
    if status.get("candidate_input_id") != expected_candidate_input_id:
        fail("execution evidence candidate_input_id does not rederive from its public input hashes")
    if status.get("contract_artifacts") != artifact_entries:
        fail("execution evidence contract artifact inventory differs")

    deployments = validate_receipts(deployments_value, 9, "deployment receipts")
    initializations = validate_receipts(initializations_value, 25, "initialization receipts")
    if deployments[-1]["post_state_root"] != initializations[0]["pre_state_root"]:
        fail("deployment and initialization receipt chains are discontinuous")
    computed_receipt_root = receipt_root(deployments, initializations)
    evidence_files = status.get("evidence_files")
    expected_evidence_files = {
        "deployment_receipts_sha256": sha256(deployments_raw),
        "initialization_receipts_sha256": sha256(initializations_raw),
        "execution_state_sha256": sha256(snapshot_raw),
        "execution_state_canonical_sha256": sha256(
            json.dumps(snapshot, ensure_ascii=False, separators=(",", ":")).encode()
        ),
    }
    if evidence_files != expected_evidence_files:
        fail("execution evidence file hashes differ")
    if status.get("receipt_root") != computed_receipt_root:
        fail("fresh deployment receipt root failed independent recomputation")

    if snapshot.get("chain_id") != CHAIN_ID or snapshot.get("network_id") != NETWORK_ID:
        fail("execution snapshot has the wrong chain/network")
    if snapshot.get("state_root") != status.get("post_deployment_execution_state_root"):
        fail("execution snapshot state root differs from execution status")
    if snapshot.get("aivm_state_root") != status.get("post_deployment_aivm_state_root"):
        fail("execution snapshot AIVM root differs from execution status")
    if len(snapshot.get("balances_nwei", {})) != 36 or len(snapshot.get("synq_contracts", {})) != 9:
        fail("execution snapshot does not contain 36 balances and 9 contracts")
    if len(snapshot.get("synq_artifacts", [])) != 9:
        fail("execution snapshot does not contain 9 contract artifacts")

    addresses = status.get("contract_addresses")
    if not isinstance(addresses, dict) or set(addresses) != set(CONTRACT_ORDER):
        fail("execution evidence does not contain the exact nine contract addresses")
    if len(set(addresses.values())) != 9:
        fail("executed contract addresses are not unique")
    balances = account_map(source["balances"], "source balances")
    snapshot_balances = snapshot["balances_nwei"]
    for account_id, balance in balances.items():
        target = addresses["TeamVesting"] if account_id == "TEM-A01" else balance["address"]
        if str(snapshot_balances.get(target)) != balance["balance_nwei"]:
            fail(f"execution snapshot balance differs for {account_id}")

    candidate = copy.deepcopy(source)
    migrations: list[dict[str, Any]] = []
    deployment_bindings: list[dict[str, Any]] = []
    for index, name in enumerate(CONTRACT_ORDER):
        key = CONTRACT_KEYS[name]
        record = candidate["contracts"][key]
        identity_address = record.get("address")
        address = addresses[name]
        if deployments[index].get("contract_address") != address:
            fail(f"{name} deployment receipt address mismatch")
        record["address"] = address
        record["status"] = "deployed_initialized_genesis_bound"
        record["contract_identity"] = {
            "address": identity_address,
            "relationship": "administrative and custody identity only; not the deployed instance address",
        }
        record["deployment"] = {"receipt": deployments[index], "receipt_hash": deployments[index].get("receipt_hash")}
        migrations.append(
            {
                "contract": name,
                "identity_or_custody_address": identity_address,
                "deployed_contract_address": address,
                "migration_rule": "runtime consumers use deployed address; identity registries preserve custody identity",
            }
        )
        deployment_bindings.append(
            {"contract": name, "contract_address": address, "deployment_receipt_hash": deployments[index].get("receipt_hash")}
        )

    candidate["modules"]["identity"]["contract_address"] = addresses["Identity"]
    candidate["modules"]["treasury"]["contract_address"] = addresses["Treasury"]
    if isinstance(candidate.get("vesting"), list) and candidate["vesting"]:
        candidate["vesting"][0]["contract_address"] = addresses["TeamVesting"]
    for table, address_field in [("accounts", "address"), ("allocations", "address"), ("balances", "address")]:
        record = account_map(candidate[table], table)["TEM-A01"]
        record[address_field] = addresses["TeamVesting"]
        record["address_role"] = "deployed TeamVesting contract instance"
    for record in candidate["address_assignment_register"]:
        if record.get("account_id") == "TEM-A01":
            record["assignment_role"] = "administrative and custody identity only"
            record["deployed_contract_address"] = addresses["TeamVesting"]
    candidate["contract_address_migration"] = {
        "schema_version": 1,
        "status": "APPLIED_FRESH_P3_DEPLOYMENT",
        "active_contract_count": 9,
        "sale_claim": "DEFERRED_TO_MAINNET_BETA_NOT_DEPLOYED",
        "entries": migrations,
    }
    candidate["execution"].update(
        {
            "genesis_execution_state_root": status["post_deployment_execution_state_root"],
            "genesis_aivm_state_root": status["post_deployment_aivm_state_root"],
            "genesis_receipt_root": computed_receipt_root,
            "genesis_deployment_manifest_hash": status["deployment_manifest_hash"],
        }
    )
    candidate["genesis_deployment"] = {
        "schema_version": 1,
        "status": "EXECUTED_AND_BOUND",
        "chain_id": CHAIN_ID,
        "network_id": NETWORK_ID,
        "runtime_network_id": NETWORK_ID,
        "release_id": RELEASE_ID,
        "protocol_version": PROTOCOL_VERSION,
        "synq_network_id": "synergy-testnet",
        "candidate_input_id": status["candidate_input_id"],
        "input_bindings": expected_inputs,
        "execution_status_sha256": sha256(status_raw),
        "deployment_receipts_sha256": sha256(deployments_raw),
        "initialization_receipts_sha256": sha256(initializations_raw),
        "execution_state_snapshot_sha256": sha256(snapshot_raw),
        "execution_state_snapshot_canonical_sha256": expected_evidence_files[
            "execution_state_canonical_sha256"
        ],
        "ceremony_authority_freeze_sha256": sha256(authority_raw),
        "authority_record_sha256": sha256(release_authority_raw),
        "contracts": deployment_bindings,
        "deployment_receipts": deployments,
        "initialization_receipts": initializations,
        "execution_state": snapshot,
        "deployment_count": 9,
        "initialization_count": 25,
        "receipt_root": computed_receipt_root,
        "post_deployment_execution_state_root": status["post_deployment_execution_state_root"],
        "post_deployment_aivm_state_root": status["post_deployment_aivm_state_root"],
        "deployment_manifest_hash": status["deployment_manifest_hash"],
        "genesis_deployer_lifecycle": "PermanentlyRetired",
    }
    candidate["schema_version"] = "v1.5-fresh-p3-deployment-bound"
    candidate["network"]["status"] = "FRESH_P3_DEPLOYMENT_EXECUTED_PENDING_AUTHORITY_BINDING"
    candidate["integrity"] = {
        "status": "fresh_p3_deployment_bound_pending_consensus_and_etdag_authority_binding",
        "signed_by": [],
        "post_deployment_execution_state_root": status["post_deployment_execution_state_root"],
        "post_deployment_aivm_state_root": status["post_deployment_aivm_state_root"],
        "deployment_manifest_hash": status["deployment_manifest_hash"],
    }
    recompute_integrity(candidate)
    if has_retired(candidate):
        fail("composed Genesis contains a retired chain identifier")
    write_new(args.output, candidate)
    print(
        json.dumps(
            {
                "result": "FRESH_P3_EXECUTED_DEPLOYMENT_GENESIS_WRITTEN",
                "output": str(args.output),
                "output_sha256": sha256(read_bytes(args.output, "output")),
                "genesis_hash": candidate["integrity"]["genesis_hash"],
                "receipt_root": computed_receipt_root,
                "post_deployment_execution_state_root": status["post_deployment_execution_state_root"],
            },
            indent=2,
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
