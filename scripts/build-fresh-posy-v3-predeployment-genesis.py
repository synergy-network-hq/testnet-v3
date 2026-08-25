#!/usr/bin/env python3
"""Build the public declarative source for a fresh PoSy-v3 deployment.

The input template contributes only schema and still-canonical contract policy.
All allocation addresses/amounts and all validator records are replaced from
the separately verified fresh public artifacts.  Every execution-derived field
is removed; a custody ceremony must execute this exact source before the public
post-deployment composer can emit a launchable Genesis.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import sys
from typing import Any


CHAIN_ID = 1266
NETWORK_ID = "testnet"
RELEASE_ID = "testnet-v3"
PROTOCOL_VERSION = "posy/3.0"
ACTIVE_IDS = [f"validator-{ordinal:02d}" for ordinal in range(2, 7)]
RETIRED_EXACT = {"posy/2.2", "posy/v2.2", "synergy-testnet-v3", "ProofOfSynergy"}
RETIRED_NETWORK_FIELDS = {
    "technical_network_id",
    "runtime_network_id",
    "network_slug",
    "network_native_id",
}
CHAIN_INCARNATION = 5
SYNQ_NETWORK_ID = "synergy-testnet"
CONTRACT_SIGNATURE_ALGORITHM = "ML-DSA-87"
CONTRACT_ORDER = [
    "Identity",
    "ValidatorRegistry",
    "Staking",
    "Governance",
    "Treasury",
    "Slashing",
    "RewardDistributor",
    "TeamVesting",
    "SynergyOracle",
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


def fail(message: str) -> "NoReturn":
    raise SystemExit(f"build-fresh-posy-v3-predeployment-genesis: {message}")


def read(path: Path, label: str) -> tuple[dict[str, Any], bytes]:
    try:
        raw = path.read_bytes()
        value = json.loads(raw)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        fail(f"read {label} {path}: {error}")
    if not isinstance(value, dict):
        fail(f"{label} must be an object")
    return value, raw


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()


def by_account(entries: Any, label: str) -> dict[str, dict[str, Any]]:
    if not isinstance(entries, list):
        fail(f"{label} must be an array")
    result: dict[str, dict[str, Any]] = {}
    for entry in entries:
        if not isinstance(entry, dict) or not isinstance(entry.get("account_id"), str):
            fail(f"{label} has a malformed account record")
        if entry["account_id"] in result:
            fail(f"{label} has duplicate account {entry['account_id']}")
        result[entry["account_id"]] = entry
    return result


def transform_retired(value: Any, key: str | None = None) -> Any:
    if isinstance(value, dict):
        return {
            name: transform_retired(entry, name)
            for name, entry in value.items()
            if not name.lower().startswith("synixn") and name not in RETIRED_NETWORK_FIELDS
        }
    if isinstance(value, list):
        return [transform_retired(entry, key) for entry in value]
    if value == "synergy-testnet-v3":
        return "synergy-testnet" if key in {"required_network_id", "synq_network_id"} else NETWORK_ID
    if value in {"posy/2.2", "posy/v2.2"}:
        return PROTOCOL_VERSION
    if value == "ProofOfSynergy":
        return "SimplifiedPoSy"
    return value


def retired_paths(value: Any, path: str = "$") -> list[str]:
    found: list[str] = []
    if isinstance(value, dict):
        for key, entry in value.items():
            if key.lower().startswith("synixn"):
                found.append(f"{path}.{key}")
            found.extend(retired_paths(entry, f"{path}.{key}"))
    elif isinstance(value, list):
        for index, entry in enumerate(value):
            found.extend(retired_paths(entry, f"{path}[{index}]"))
    elif isinstance(value, str) and (value in RETIRED_EXACT or "synixn" in value.lower()):
        found.append(path)
    return found


def replace_account_tables(
    candidate: dict[str, Any],
    plan: dict[str, Any],
    resolved: dict[str, Any],
) -> None:
    plan_entries = by_account(plan.get("allocations"), "allocation plan")
    resolved_entries = by_account(resolved.get("resolved_allocations"), "resolved allocations")
    if set(plan_entries) != set(resolved_entries) or len(plan_entries) != 36:
        fail("allocation plan and resolved allocation account sets differ")
    for account_id, approved in plan_entries.items():
        bound = resolved_entries[account_id]
        if bound.get("amount_nwei") != approved.get("amount_nwei"):
            fail(f"resolved amount differs from approved plan for {account_id}")

    source_accounts = by_account(candidate.get("accounts"), "template accounts")
    source_allocations = by_account(candidate.get("allocations"), "template allocations")
    source_balances = by_account(candidate.get("balances"), "template balances")
    source_register = by_account(
        candidate.get("address_assignment_register"), "template address register"
    )
    if not set(plan_entries).issubset(source_accounts):
        fail("template does not contain every approved allocation account")

    accounts: list[dict[str, Any]] = []
    allocations: list[dict[str, Any]] = []
    balances: list[dict[str, Any]] = []
    register: list[dict[str, Any]] = []
    for approved in plan["allocations"]:
        account_id = approved["account_id"]
        bound = resolved_entries[account_id]
        address = bound["address"]
        amount = approved["amount_nwei"]

        account = copy.deepcopy(source_accounts[account_id])
        account.update(
            {
                "account_name": approved["name"],
                "address": address,
                "alias": approved["alias"],
                "control_reference": approved["control_reference"],
            }
        )
        allocation = copy.deepcopy(
            source_allocations.get(
                account_id,
                {
                    "account_id": account_id,
                    "category": account.get("category", "System reserved address"),
                    "locked": True,
                    "release_path": "protocol-defined zero-balance system destination",
                },
            )
        )
        allocation.update(
            {
                "address": address,
                "alias": approved["alias"],
                "amount_nwei": amount,
                "control_reference": approved["control_reference"],
                "name": approved["name"],
            }
        )
        balance = copy.deepcopy(source_balances[account_id])
        balance.update({"address": address, "balance_nwei": amount})
        assignment = copy.deepcopy(source_register[account_id])
        assignment.update(
            {
                "account_name": approved["name"],
                "alias": approved["alias"],
                "amount_nwei": amount,
                "assigned_address": address,
                "control_reference": approved["control_reference"],
            }
        )
        if account_id == "TEM-A01":
            for record in (account, allocation, balance):
                record["address_role"] = "administrative_and_custody_identity_predeployment"
            assignment["assignment_role"] = "administrative_and_custody_identity_predeployment"
            assignment["deployment_funding_target"] = "TeamVesting"
        accounts.append(account)
        allocations.append(allocation)
        balances.append(balance)
        register.append(assignment)

    candidate["accounts"] = accounts
    candidate["allocations"] = allocations
    candidate["balances"] = balances
    candidate["address_assignment_register"] = register
    candidate["allocation_sum_check"] = {
        "allocation_count": len(allocations),
        "grand_total_nwei": plan["grand_total_nwei"],
        "total_supply_cap_nwei": plan["total_supply_cap_nwei"],
        "status": "VERIFIED_FROM_APPROVED_FRESH_P3_ALLOCATION_PLAN",
    }
    candidate["token"]["total_supply_cap_nwei"] = plan["total_supply_cap_nwei"]


def replace_validators(candidate: dict[str, Any], validator: dict[str, Any]) -> None:
    fields = validator.get("genesis_source_fields")
    if not isinstance(fields, dict):
        fail("validator source inputs have no genesis_source_fields")
    validators = fields.get("validators")
    preconfigured = fields.get("preconfigured_validators")
    if not isinstance(validators, list) or [entry.get("validator_id") for entry in validators] != ACTIVE_IDS:
        fail("active validator set is not exactly validator-02 through validator-06")
    if not isinstance(preconfigured, list) or len(preconfigured) != 21:
        fail("preconfigured validator set must contain exactly 21 records")
    candidate["validators"] = copy.deepcopy(validators)
    candidate["preconfigured_validators"] = copy.deepcopy(preconfigured)
    registry_init_params = copy.deepcopy(
        candidate["contracts"]["validator_registry"]["init_params"]
    )
    registry_init_params.update(
        copy.deepcopy(fields["validator_registry_init_params"])
    )
    candidate["contracts"]["validator_registry"]["init_params"] = registry_init_params
    candidate["validator_metadata"] = copy.deepcopy(fields["validator_metadata"])
    candidate["node_identities"] = []


def bind_fresh_contract_artifacts(
    candidate: dict[str, Any], contracts_dir: Path
) -> tuple[str, list[dict[str, str]]]:
    contracts = candidate.get("contracts")
    if not isinstance(contracts, dict):
        fail("schema template contracts must be an object")
    inventory: list[dict[str, str]] = []
    fresh_contracts: dict[str, Any] = {}
    for contract_name in CONTRACT_ORDER:
        contract_key = CONTRACT_KEYS[contract_name]
        prior = contracts.get(contract_key)
        if not isinstance(prior, dict) or not isinstance(prior.get("init_params"), dict):
            fail(f"schema template has no declarative init_params for {contract_name}")
        paths = {
            "source": contracts_dir / f"{contract_name}.synq",
            "bytecode": contracts_dir / f"{contract_name}.compiled.synq",
            "abi": contracts_dir / f"{contract_name}.abi.json",
            "manifest": contracts_dir / f"{contract_name}.manifest.json",
        }
        raws: dict[str, bytes] = {}
        for label, path in paths.items():
            try:
                raws[label] = path.read_bytes()
            except OSError as error:
                fail(f"read {contract_name} {label} artifact {path}: {error}")
        try:
            manifest = json.loads(raws["manifest"])
            abi = json.loads(raws["abi"])
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            fail(f"decode {contract_name} artifact metadata: {error}")
        if not isinstance(manifest, dict) or not isinstance(abi, dict):
            fail(f"{contract_name} manifest/ABI must be objects")
        expected_manifest = {
            "contract_name": contract_name,
            "required_chain_id": CHAIN_ID,
            "required_network_id": SYNQ_NETWORK_ID,
            "required_signature_algorithm": CONTRACT_SIGNATURE_ALGORITHM,
            "source_hash": sha256(raws["source"]),
            "bytecode_hash": sha256(raws["bytecode"]),
            "abi_hash": sha256(raws["abi"]),
        }
        for field, expected in expected_manifest.items():
            if manifest.get(field) != expected:
                fail(
                    f"{contract_name} manifest {field} differs: "
                    f"expected {expected!r}, found {manifest.get(field)!r}"
                )
        artifact = copy.deepcopy(manifest)
        artifact.update(
            {
                "source_path": f"genesis-contracts/contracts/{contract_name}.synq",
                "bytecode_path": f"genesis-contracts/contracts/{contract_name}.compiled.synq",
                "abi_path": f"genesis-contracts/contracts/{contract_name}.abi.json",
                "manifest_path": f"genesis-contracts/contracts/{contract_name}.manifest.json",
                "manifest_sha256": sha256(raws["manifest"]),
            }
        )
        init_params = copy.deepcopy(prior["init_params"])
        init_params.pop("receipt_root", None)
        fresh_contracts[contract_key] = {
            "address": None,
            "artifact": artifact,
            "bytecode_hash": manifest["bytecode_hash"],
            "init_params": init_params,
        }
        for suffix in ["synq", "compiled.synq", "abi.json", "manifest.json"]:
            path = contracts_dir / f"{contract_name}.{suffix}"
            inventory.append({"file": path.name, "sha256": sha256(path.read_bytes())})
    candidate["contracts"] = fresh_contracts
    return sha256(canonical_json(inventory)), inventory


def clear_execution_derived_fields(candidate: dict[str, Any]) -> None:
    for field in [
        "genesis_deployment",
        "contract_address_migration",
        "etdag_governance",
        "consensus_parameters",
    ]:
        candidate.pop(field, None)
    candidate["contract_identities"] = []
    header = candidate.get("header")
    if not isinstance(header, dict):
        fail("schema template header must be an object")
    header.update(
        {
            "data_root": None,
            "receipts_root": None,
            "state_root": None,
            "transactions_root": None,
        }
    )
    modules = candidate.get("modules")
    if isinstance(modules, dict):
        for module in modules.values():
            if isinstance(module, dict) and "contract_address" in module:
                module["contract_address"] = None
    vesting = candidate.get("vesting")
    if isinstance(vesting, list):
        for schedule in vesting:
            if isinstance(schedule, dict) and "contract_address" in schedule:
                schedule["contract_address"] = None
    crypto = candidate.get("crypto")
    if isinstance(crypto, dict):
        crypto.pop("legacy_ecdsa_supported", None)
        key_types = crypto.get("key_types")
        if isinstance(key_types, dict):
            key_types["governance"] = CONTRACT_SIGNATURE_ALGORITHM


def validate_fresh_boundaries(
    candidate: dict[str, Any], activation: dict[str, Any], authority: dict[str, Any]
) -> None:
    manifest = activation.get("manifest")
    if not isinstance(manifest, dict):
        fail("Genesis activation has no manifest")
    expected_manifest = {
        "chain_id": CHAIN_ID,
        "network_id": NETWORK_ID,
        "release_id": RELEASE_ID,
        "protocol_version": PROTOCOL_VERSION,
        "activation_height": 1,
        "active_validator_count": 5,
    }
    for field, expected in expected_manifest.items():
        if manifest.get(field) != expected:
            fail(f"Genesis activation manifest {field} differs from {expected!r}")
    frozen_set = activation.get("frozen_validator_set")
    frozen = frozen_set.get("validators") if isinstance(frozen_set, dict) else None
    frozen_ids = (
        [entry.get("validator_id") for entry in frozen]
        if isinstance(frozen, list) and all(isinstance(entry, dict) for entry in frozen)
        else []
    )
    if frozen_ids != ACTIVE_IDS:
        fail("Genesis activation frozen validator set is not exactly validator-02 through validator-06")
    expected_authority = {
        "artifact_type": "fresh-testnet-v3-genesis-authority-public-freeze",
        "schema_version": "synergy-testnet-v3-genesis-authority-freeze-v1",
        "chain_id": CHAIN_ID,
        "network_id": NETWORK_ID,
        "release_id": RELEASE_ID,
        "consensus_protocol": PROTOCOL_VERSION,
        "authority_count": 3,
    }
    for field, expected in expected_authority.items():
        if authority.get(field) != expected:
            fail(f"fresh authority record {field} differs from {expected!r}")
    if candidate.get("network", {}).get("chain_incarnation") != CHAIN_INCARNATION:
        fail("candidate chain_incarnation is not 5")
    consensus = candidate.get("consensus")
    if not isinstance(consensus, dict):
        fail("candidate consensus must be an object")
    expected_state_namespace = f"chain-{CHAIN_ID}/incarnation-{CHAIN_INCARNATION}"
    if (
        consensus.get("state_directory_namespace") != expected_state_namespace
        or consensus.get("state_schema_version") != CHAIN_INCARNATION
    ):
        fail("candidate consensus state domain is not the fresh P3 incarnation-5 domain")
    if set(candidate.get("contracts", {})) != set(CONTRACT_KEYS.values()):
        fail("candidate does not contain the exact nine fresh Genesis contracts")
    if candidate.get("contract_identities") != []:
        fail("predeployment candidate contains carried-forward contract identities")
    forbidden_paths: list[str] = []

    def walk(value: Any, path: str = "$") -> None:
        if isinstance(value, dict):
            for key, entry in value.items():
                current = f"{path}.{key}"
                lowered = key.lower()
                if lowered.startswith("synixn") or lowered in {
                    "genesis_deployment",
                    "contract_address_migration",
                    "deployment_receipts",
                    "initialization_receipts",
                    "post_deployment_state_root",
                    "post_deployment_execution_state_root",
                    "post_deployment_aivm_state_root",
                    "receipt_root",
                    "deployment_manifest_hash",
                }:
                    forbidden_paths.append(current)
                if key == "chain_incarnation" and entry != CHAIN_INCARNATION:
                    forbidden_paths.append(current)
                walk(entry, current)
        elif isinstance(value, list):
            for index, entry in enumerate(value):
                walk(entry, f"{path}[{index}]")
        elif isinstance(value, str) and len(value) <= 256:
            lowered = value.lower()
            if any(
                marker in lowered
                for marker in [
                    "testnet-v2",
                    "posy/2.2",
                    "posy/v2.2",
                    "six-validator",
                    "six_validator",
                    "old authority host",
                ]
            ):
                forbidden_paths.append(path)

    walk(candidate)
    if forbidden_paths:
        fail(f"carried-forward chain/deployment material remains at {', '.join(forbidden_paths[:8])}")


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


def args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--schema-template", type=Path, required=True)
    parser.add_argument("--allocation-manifest", type=Path, required=True)
    parser.add_argument("--resolved-allocations", type=Path, required=True)
    parser.add_argument("--validator-inputs", type=Path, required=True)
    parser.add_argument("--activation", type=Path, required=True)
    parser.add_argument("--authority-record", type=Path, required=True)
    parser.add_argument("--contracts-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


def main() -> None:
    options = args()
    template, template_raw = read(options.schema_template, "schema template")
    plan, plan_raw = read(options.allocation_manifest, "allocation plan")
    resolved, resolved_raw = read(options.resolved_allocations, "resolved allocations")
    validator, validator_raw = read(options.validator_inputs, "validator inputs")
    activation, activation_raw = read(options.activation, "Genesis activation")
    authority, authority_raw = read(options.authority_record, "fresh authority record")

    for value, label in [(plan, "plan"), (resolved, "resolved"), (validator, "validator")]:
        if value.get("chain_id") != CHAIN_ID or value.get("network_id") != NETWORK_ID:
            fail(f"{label} input has the wrong chain/network identity")
        if value.get("release_id") != RELEASE_ID or value.get("protocol_version") != PROTOCOL_VERSION:
            fail(f"{label} input has the wrong release/protocol identity")
    if resolved.get("allocation_plan_sha256") != sha256(plan_raw):
        fail("resolved allocation inputs do not bind the exact allocation plan")
    if resolved.get("validator_source_inputs_sha256") != sha256(validator_raw):
        fail("resolved allocation inputs do not bind the exact validator adapter")

    candidate = transform_retired(copy.deepcopy(template))
    clear_execution_derived_fields(candidate)
    replace_account_tables(candidate, plan, resolved)
    replace_validators(candidate, validator)
    artifact_set_sha256, artifact_inventory = bind_fresh_contract_artifacts(
        candidate, options.contracts_dir
    )

    candidate["schema_version"] = "v1.5-fresh-p3-predeployment-public-input"
    candidate["env"] = NETWORK_ID
    candidate["network"].update(
        {
            "chain_id": CHAIN_ID,
            "chain_incarnation": CHAIN_INCARNATION,
            "network_id": NETWORK_ID,
            "release_id": RELEASE_ID,
            "consensus_version": PROTOCOL_VERSION,
            "status": "FRESH_P3_PUBLIC_INPUT_READY_FOR_CUSTODY_DEPLOYMENT",
        }
    )
    candidate["header"]["block_height"] = 0
    candidate["header"]["consensus_fields"].update(
        {"engine_id": PROTOCOL_VERSION, "epoch": 0, "round": 0, "proposer": None, "seal": None}
    )
    candidate["consensus"].update(
        {
            "algorithm": "SimplifiedPoSy",
            # The schema template is policy-only. Never carry a predecessor
            # chain's state domain into a fresh block-zero P3 candidate.
            "state_directory_namespace": f"chain-{CHAIN_ID}/incarnation-{CHAIN_INCARNATION}",
            "state_schema_version": CHAIN_INCARNATION,
            "dynamic_validator_membership": True,
            "epoch": 0,
            "initial_active_validator_count": 5,
            "min_validator_count": 5,
            "min_quorum_threshold": 4,
            "protocol_validator_count_cap": None,
            "initial_validator_ssh_aliases": [
                "synergy-val2",
                "synergy-val3",
                "synergy-val4",
                "synergy-val5",
                "synergy-val6",
            ],
            "cluster_assignment_derivation": (
                "sha3-512 PoSy/ClusterShuffle/v3 over the finalized epoch seed; "
                "the five active Genesis validators occupy cluster ID 0; later "
                "clusters are created only by finalized dynamic membership transitions"
            ),
            "posy_v3_activation": activation,
        }
    )
    candidate["fresh_p3_public_input_binding"] = {
        "schema_template_sha256": sha256(template_raw),
        "allocation_plan_sha256": sha256(plan_raw),
        "resolved_allocations_sha256": sha256(resolved_raw),
        "validator_source_inputs_sha256": sha256(validator_raw),
        "five_validator_activation_sha256": sha256(activation_raw),
        "fresh_authority_record_sha256": sha256(authority_raw),
        "contract_artifact_set_sha256": artifact_set_sha256,
        "contract_artifacts": artifact_inventory,
        "execution_derived_fields_present": False,
        "custody_material_present": False,
    }
    candidate["integrity"] = {
        "status": "RECOMPUTE_ONLY_AFTER_FRESH_DEPLOYMENT_EXECUTION",
        "signed_by": [],
    }
    candidate["network_magic_bytes"] = {
        "status": "RECOMPUTE_ONLY_AFTER_FRESH_DEPLOYMENT_EXECUTION",
        "value": None,
    }
    candidate["testnet_v3_initialization"] = {
        "finalization_status": "fresh_p3_public_input_ready_for_custody_deployment",
        "chain_incarnation": CHAIN_INCARNATION,
        "initial_validator_count": 5,
        "preconfigured_validator_count": 21,
        "active_validator_ids": ACTIVE_IDS,
        "execution_evidence_present": False,
        "reuse_prior_network_addresses": False,
        "reuse_prior_peer_ids": False,
        "reuse_prior_validator_addresses": False,
        "reuse_prior_validator_keys": False,
        "validator_activation_policy": (
            "validator-02 through validator-06 are active at Genesis; all other "
            "preconfigured validators require a finalized dynamic epoch transition"
        ),
    }
    validate_fresh_boundaries(candidate, activation, authority)
    stale = retired_paths(candidate)
    if stale:
        fail(f"retired chain values remain at {', '.join(stale[:8])}")

    write_new(options.output, candidate)
    output_raw = options.output.read_bytes()
    print(
        json.dumps(
            {
                "result": "FRESH_P3_PREDEPLOYMENT_PUBLIC_INPUT_WRITTEN",
                "output": str(options.output),
                "output_sha256": sha256(output_raw),
                "allocation_count": len(candidate["allocations"]),
                "active_validator_ids": ACTIVE_IDS,
                "preconfigured_validator_count": len(candidate["preconfigured_validators"]),
                "execution_required": True,
            },
            indent=2,
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
