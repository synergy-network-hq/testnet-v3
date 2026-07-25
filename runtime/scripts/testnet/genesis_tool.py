#!/usr/bin/env python3
"""Synergy public testnet genesis builder, verifier, and export utility.

The tool intentionally reads only public JSON inputs from a key directory.
Private/decrypted key files are never loaded, printed, or copied into public
artifacts.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import copy
import csv
import html
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

import blake3


CHAIN_ID = 1264
NETWORK_ID = 1264
RUNTIME_NETWORK_ID = "synergy-testnet-v3"
CHAIN_ID_HEX = hex(CHAIN_ID)
CAIP2 = "synergy:testnet"
EIP155 = "eip155:1264"
TOKEN_NAME = "Synergy Testnet Token"
TOKEN_SYMBOL = "SNRG"
TOKEN_DECIMALS = 9
BASE_UNIT = "nWei"
NWEI_PER_SNRG = 1_000_000_000
TOTAL_SUPPLY_NWEI = 12_000_000_000 * NWEI_PER_SNRG
LEGACY_TOTAL_SUPPLY_NWEI = 51_000_000_000 * NWEI_PER_SNRG
VALIDATOR_COUNT = 5
VALIDATOR_SELF_STAKE_NWEI = 50_000 * NWEI_PER_SNRG
ONBOARDING_SHADOW_PHASE_BLOCKS = 1_000
ONBOARDING_REQUIRED_PORTS = {
    "p2p": 5622,
    "qrpc": 5640,
    "ws": 5660,
    "discovery": 5680,
    "metrics": 6030,
}
CONSENSUS_FORK_HEIGHT = 204_216
CONSENSUS_FORK_PARENT_HEIGHT = 204_215
CONSENSUS_FORK_PARENT_HASH = "e209bd7554a06dfb052d5ff7ffd5664efc05e6cd1c5cadc9d139fa5bb9072816"
POST_FORK_CONSENSUS_ALGORITHM = "FN-DSA"
POST_FORK_VALIDATOR_KEY_ALGORITHM = "FN-DSA-1024"
FORK_PARSER_MODE = "fail_closed"
ZERO_HASH = "0" * 64
EMPTY_HASH = blake3.blake3(b"").hexdigest()
GENESIS_MESSAGE = (
    "16 May 2026 - Synergy Testnet chain 1264 resets the public testnet with a post-quantum "
    "Proof of Synergy network with cluster-local certified DAG data "
    "availability and dual-quorum finality."
)

SECRET_KEY_RE = re.compile(
    r"private_key|seed_phrase|mnemonic|phrase|secret|(^|_)sk($|_)|priv",
    re.IGNORECASE,
)
NEW_VALIDATOR_ADDRESS_RE = re.compile(r"^synv1[a-z0-9]{36}$")
AMBIGUOUS_CONSENSUS_KEY_LABELS = {"", "PQC", "AEGIS", "AIGIS", "POST-QUANTUM", "POST_QUANTUM"}


def canonical_json(value: Any) -> str:
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    if isinstance(value, list):
        return "[" + ",".join(canonical_json(item) for item in value) + "]"
    if isinstance(value, dict):
        return (
            "{"
            + ",".join(
                f"{json.dumps(key, ensure_ascii=False, separators=(',', ':'))}:{canonical_json(value[key])}"
                for key in sorted(value)
            )
            + "}"
        )
    raise TypeError(f"unsupported canonical JSON type: {type(value)!r}")


def hash_json(value: Any) -> str:
    return blake3.blake3(canonical_json(value).encode("utf-8")).hexdigest()


def read_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, sort_keys=True)
        handle.write("\n")


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def fail(message: str) -> None:
    raise SystemExit(message)


def assert_no_secret_fields(value: Any, artifact: str, path: str = "$") -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            if SECRET_KEY_RE.search(key):
                fail(f"{artifact}: secret-looking field is forbidden at {path}.{key}")
            assert_no_secret_fields(item, artifact, f"{path}.{key}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            assert_no_secret_fields(item, artifact, f"{path}[{index}]")


def remove_secret_named_fields(value: Any) -> Any:
    if isinstance(value, dict):
        clean: dict[str, Any] = {}
        for key, item in value.items():
            if SECRET_KEY_RE.search(key):
                continue
            if key == "private_key_exists":
                clean["spending_key_material_exists"] = item
                continue
            if key == "privileged_eoa":
                clean["externally_owned_admin_allowed"] = item
                continue
            clean[key] = remove_secret_named_fields(item)
        return clean
    if isinstance(value, list):
        return [remove_secret_named_fields(item) for item in value]
    return value


def public_wallet(path: Path) -> dict[str, Any]:
    payload = read_json(path)
    return {
        "address": str(payload.get("address", "")).strip(),
        "address_type": str(payload.get("address_type", "")).strip(),
        "algorithm": str(payload.get("algorithm", "")).strip(),
        "public_key": str(payload.get("public_key", "")).strip(),
        "external_addresses": payload.get("external_addresses", []),
    }


def public_wallet_if_exists(path: Path) -> dict[str, Any] | None:
    if not path.exists():
        return None
    wallet = public_wallet(path)
    if not wallet["address"]:
        return None
    return wallet


def public_validator(path: Path, index: int) -> dict[str, Any]:
    payload = read_json(path)
    address = str(payload.get("address", "")).strip()
    consensus = payload.get("consensus_key") or {}
    account = payload.get("account_key") or {}
    identity = payload.get("node_identity_key") or {}
    entropy = payload.get("entropy_contribution_key") or {}
    if not address:
        fail(f"{path}: missing public validator address")
    if not consensus.get("public_key"):
        fail(f"{path}: missing public consensus key")
    if not identity.get("peer_id"):
        fail(f"{path}: missing peer_id")

    validator_id = f"validator-{index}"
    public_bundle = {
        "validator_id": validator_id,
        "validator_address": address,
        "operator_address": address,
        "reward_address": address,
        "consensus_public_key": consensus.get("public_key", ""),
        "consensus_key_type": consensus.get("algorithm", "FN-DSA-1024"),
        "account_public_key": account.get("public_key", payload.get("public_key", "")),
        "identity_public_key": entropy.get("public_key", ""),
        "node_identity_public_key": identity.get("public_key", ""),
        "node_identity_key_type": identity.get("algorithm", ""),
        "peer_id": identity.get("peer_id", ""),
    }
    key_bundle_hash = hash_json(
        {
            "account_public_key": public_bundle["account_public_key"],
            "consensus_public_key": public_bundle["consensus_public_key"],
            "identity_public_key": public_bundle["identity_public_key"],
            "node_identity_public_key": public_bundle["node_identity_public_key"],
            "peer_id": public_bundle["peer_id"],
        }
    )
    metadata_hash = hash_json(
        {
            "address": address,
            "address_type": payload.get("address_type", ""),
            "algorithm": payload.get("algorithm", ""),
            "created_at": payload.get("created_at", ""),
            "validator_id": validator_id,
        }
    )
    public_bundle.update(
        {
            "validator_id_hash": hash_json({"validator_id": validator_id}),
            "key_bundle_hash": key_bundle_hash,
            "metadata_hash": metadata_hash,
            "self_stake_nwei": str(VALIDATOR_SELF_STAKE_NWEI),
            "stake_nwei": str(VALIDATOR_SELF_STAKE_NWEI),
            "is_network_owned_validator": True,
            "voting_power": 100,
            "status": "active",
            "activation_height": 0,
            "commission": {"rate_bps": 500, "max_rate_bps": 1000, "max_change_bps": 100},
            "moniker": f"Synergy Validator {index}",
        }
    )
    for preserved_field in ["validator_id_hash", "key_bundle_hash", "metadata_hash", "moniker"]:
        if payload.get(preserved_field):
            public_bundle[preserved_field] = payload[preserved_field]
    return public_bundle


def load_public_inputs(key_dir: Path) -> dict[str, Any]:
    if (key_dir / "testnet-keyfiles").exists():
        legacy_key_dir = key_dir / "testnet-keyfiles"
        new_address_dir = key_dir / "new-network-addresses"
    else:
        legacy_key_dir = key_dir
        new_address_dir = key_dir / "new-network-addresses"

    wallet_names = [
        "treasury",
        "team",
        "ecosystem",
        "sale",
        "faucet",
        "reserve",
        "rewards",
        "registry",
        "oracle",
        "signer1",
        "signer2",
        "signer3",
        "signer4",
        "signer5",
    ]
    wallets = {}
    for name in wallet_names:
        path = legacy_key_dir / f"{name}.pub.json"
        if path.exists():
            wallets[name] = public_wallet(path)

    new_wallet_aliases = {
        "dao_governance_reserve": "DAOGovernanceReserve",
        "foundation_treasury": "FoundationTreasury",
        "liquidity_market_infra": "LiquidityMarketInfra",
        "marketing_growth": "MarketingGrowth",
        "reliability_bonus": "ReliabilityBonus",
        "strategic_partnerships": "StrategicPartnerships",
        "token_sales": "TokenSalesWallet",
        "validator_security_pool": "ValidatorSecurityPool",
    }
    for alias, filename in new_wallet_aliases.items():
        wallet = public_wallet_if_exists(new_address_dir / f"{filename}.pub.json")
        if wallet:
            wallets[alias] = wallet

    override_aliases = {
        "treasury": "foundation_treasury",
        "sale": "token_sales",
        "reserve": "dao_governance_reserve",
        "rewards": "validator_security_pool",
    }
    for target, source in override_aliases.items():
        if source in wallets:
            wallets[target] = wallets[source]

    fee_path = legacy_key_dir / "fee-collector.pub.json"
    if not fee_path.exists():
        fee_path = legacy_key_dir / "fee-colector.pub.json"
    if fee_path.exists():
        wallets["fee_collector"] = public_wallet(fee_path)

    validator_dir = legacy_key_dir / "validator-addresses"
    if not validator_dir.exists():
        validator_dir = legacy_key_dir / "testnet-genesis-validators"
    validators = [
        public_validator(validator_dir / f"{index}.pub.json", index)
        for index in range(1, VALIDATOR_COUNT + 1)
    ]

    clusters = []
    for index in range(1, VALIDATOR_COUNT + 1):
        wallet = public_wallet_if_exists(new_address_dir / f"cluster{index}.pub.json")
        if wallet:
            clusters.append(
                {
                    "cluster_index": index - 1,
                    "cluster_address": wallet["address"],
                    "address_type": "ValidatorCluster",
                }
            )

    return {"wallets": wallets, "validators": validators, "clusters": clusters}


def scaled_allocations(wallets: dict[str, dict[str, Any]], validators: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    explicit_self_stake_total = VALIDATOR_SELF_STAKE_NWEI * len(validators)
    entries = [
        (
            "Validators / Staking / Network Security",
            "validators_staking_network_security",
            wallets["validator_security_pool"]["address"],
            2_640_000_000 * NWEI_PER_SNRG - explicit_self_stake_total,
            True,
            "22.00",
        ),
        (
            "Token Sales (Initial, Private & Public)",
            "token_sales_initial_private_public",
            wallets["token_sales"]["address"],
            2_226_000_000 * NWEI_PER_SNRG,
            True,
            "18.55",
        ),
        (
            "Ecosystem / Developer Incentives",
            "ecosystem_developer_incentives",
            wallets["ecosystem"]["address"],
            1_560_000_000 * NWEI_PER_SNRG,
            True,
            "13.00",
        ),
        (
            "Liquidity & Market Infrastructure",
            "liquidity_market_infrastructure",
            wallets["liquidity_market_infra"]["address"],
            1_440_000_000 * NWEI_PER_SNRG,
            True,
            "12.00",
        ),
        (
            "Marketing & Growth",
            "marketing_growth",
            wallets["marketing_growth"]["address"],
            1_260_000_000 * NWEI_PER_SNRG,
            True,
            "10.50",
        ),
        (
            "Strategic Partnerships / Integrations",
            "strategic_partnerships_integrations",
            wallets["strategic_partnerships"]["address"],
            894_000_000 * NWEI_PER_SNRG,
            True,
            "7.45",
        ),
        (
            "DAO / Governance Reserve",
            "dao_governance_reserve",
            wallets["dao_governance_reserve"]["address"],
            720_000_000 * NWEI_PER_SNRG,
            True,
            "6.00",
        ),
        (
            "Foundation / Treasury",
            "foundation_treasury",
            wallets["foundation_treasury"]["address"],
            720_000_000 * NWEI_PER_SNRG,
            True,
            "6.00",
        ),
        (
            "Team & Support",
            "team_support",
            wallets["team"]["address"],
            540_000_000 * NWEI_PER_SNRG,
            True,
            "4.50",
        ),
    ]
    allocations = [
        {
            "name": name,
            "category": category,
            "address": address,
            "amount_nwei": amount,
            "locked": locked,
            "tokenomics_percent": percent,
            "source_model": "Synergy Testnet 12B tokenomics screenshot",
        }
        for name, category, address, amount, locked, percent in entries
    ]

    validator_pool = next(entry for entry in allocations if entry["category"] == "validators_staking_network_security")
    validator_pool["split_note"] = (
        "The 22.00% validator/security allocation is split into the Validator Security Pool plus "
        "five explicit baseline validator self-stake allocations."
    )
    for validator in validators:
        allocations.append(
            {
                "name": f"{validator['moniker']} Self-Stake",
                "category": "validator_self_stake",
                "address": validator["operator_address"],
                "amount_nwei": VALIDATOR_SELF_STAKE_NWEI,
                "locked": True,
                "stake_nwei": VALIDATOR_SELF_STAKE_NWEI,
                "validator_id": validator["validator_id"],
                "parent_tokenomics_category": "validators_staking_network_security",
            }
        )

    for entry in allocations:
        entry["amount_nwei"] = str(entry["amount_nwei"])
        if "legacy_amount_nwei" in entry and not isinstance(entry["legacy_amount_nwei"], str):
            entry["legacy_amount_nwei"] = str(entry["legacy_amount_nwei"])
        if "rounding_remainder_nwei" in entry and not isinstance(entry["rounding_remainder_nwei"], str):
            entry["rounding_remainder_nwei"] = str(entry["rounding_remainder_nwei"])
        if "stake_nwei" in entry and not isinstance(entry["stake_nwei"], str):
            entry["stake_nwei"] = str(entry["stake_nwei"])

    manifest = {
        "chain_id": CHAIN_ID,
        "total_supply_cap_nwei": str(TOTAL_SUPPLY_NWEI),
        "total_supply_snrg": "12000000000",
        "nwei_per_snrg": str(NWEI_PER_SNRG),
        "source_model": "Synergy Testnet 12B tokenomics screenshot",
        "rounding_policy": "exact integer nWei allocation; no rounding required for screenshot token counts",
        "validator_self_stake_policy": (
            "Replace the legacy single validator sponsor allocation with five explicit "
            "50,000 SNRG baseline validator self-stake allocations, funded from the "
            "scaled validator macro bucket."
        ),
        "rounding_remainder_nwei": "0",
        "validator_self_stake_total_nwei": str(explicit_self_stake_total),
        "allocations": copy.deepcopy(allocations),
    }
    return allocations, manifest


def aggregate_balances(allocations: list[dict[str, Any]], extra_zero_addresses: list[str]) -> list[dict[str, str]]:
    totals: dict[str, int] = {}
    for entry in allocations:
        amount = int(entry["amount_nwei"])
        if amount < 0:
            fail(f"negative allocation for {entry['name']}")
        totals[entry["address"]] = totals.get(entry["address"], 0) + amount
    for address in extra_zero_addresses:
        totals.setdefault(address, 0)
    return [{"address": address, "balance_nwei": str(totals[address])} for address in sorted(totals)]


def registry_validator(validator: dict[str, Any]) -> dict[str, Any]:
    return {
        "validator_id": validator["validator_id"],
        "validator_id_hash": validator["validator_id_hash"],
        "validator_address": validator["operator_address"],
        "operator_address": validator["operator_address"],
        "reward_address": validator["reward_address"],
        "reward_payout_address": validator["reward_address"],
        "consensus_public_key": validator["consensus_public_key"],
        "consensus_key_type": validator["consensus_key_type"],
        "account_public_key": validator["account_public_key"],
        "identity_public_key": validator["identity_public_key"],
        "node_identity_public_key": validator["node_identity_public_key"],
        "peer_id": validator["peer_id"],
        "key_bundle_hash": validator["key_bundle_hash"],
        "metadata_hash": validator["metadata_hash"],
        "self_stake_amount": validator["self_stake_nwei"],
        "self_stake_nwei": validator["self_stake_nwei"],
        "stake_nwei": validator["stake_nwei"],
        "status": validator["status"],
        "activation_height": validator["activation_height"],
        "voting_power": validator["voting_power"],
        "commission": validator["commission"],
        "validator_label": validator["moniker"],
        "is_network_owned_validator": validator.get("is_network_owned_validator", True),
    }


def update_network_identifiers(template: dict[str, Any], genesis_hash: str, network_magic: str, genesis_sha256: str) -> dict[str, Any]:
    doc = remove_secret_named_fields(copy.deepcopy(template))
    doc.setdefault("schema", {})["version"] = "v1"
    doc.setdefault("network", {}).update(
        {
            "display_name": "Synergy Testnet",
            "technical_identifier": "testnet",
            "network_slug": "synergy-testnet",
            "environment": "testnet",
            "status": "final",
            "production": False,
            "public": True,
        }
    )
    doc.setdefault("chain_identifiers", {}).setdefault("synergy_native", {}).update(
        {
            "status": "active",
            "decimal": CHAIN_ID,
            "hex": CHAIN_ID_HEX,
            "type": "uint64",
            "canonical_caip2": CAIP2,
        }
    )
    doc["chain_identifiers"].setdefault("caip2_identifiers", {}).setdefault("canonical_native", {}).update(
        {"status": "active", "namespace": "synergy", "reference": "testnet", "value": CAIP2}
    )
    doc["chain_identifiers"]["caip2_identifiers"].setdefault("eip155", {}).update(
        {
            "status": "reserved_inactive",
            "namespace": "eip155",
            "reference": str(CHAIN_ID),
            "value": EIP155,
            "activation_condition": "Activate only when EVM/EIP-155 compatibility is implemented and publicly supported.",
        }
    )
    doc.setdefault("native_currency", {}).update(
        {
            "name": TOKEN_NAME,
            "mainnet_name": "Synergy Token",
            "symbol": TOKEN_SYMBOL,
            "decimals": TOKEN_DECIMALS,
            "base_unit": BASE_UNIT,
            "nwei_per_snrg": str(NWEI_PER_SNRG),
        }
    )
    doc.setdefault("interoperability", {}).setdefault("sxcp", {}).update(
        {"domain_id": CHAIN_ID, "chain_reference": CAIP2}
    )
    doc["interoperability"].setdefault("bridge_domain_ids", {}).setdefault("hyperlane", {}).update(
        {"domain_id": CHAIN_ID, "status": "reserved"}
    )
    doc.setdefault("wallet_metadata", {}).setdefault("wallet_add_network_payload", {}).update(
        {"chainId": CHAIN_ID_HEX, "chainName": "Synergy Testnet"}
    )
    cryptographic = doc.setdefault("cryptographic_identity", {})
    cryptographic.update(
        {
            "genesis_file": "genesis.testnet.json",
            "genesis_hash": genesis_hash,
            "genesis_hash_status": "final",
            "genesis_hash_algorithm": "blake3-256",
            "genesis_hash_format": "lowercase_hex_without_0x",
            "genesis_artifact_sha256": genesis_sha256,
        }
    )
    cryptographic["network_magic_bytes"] = {
        "value": network_magic,
        "status": "final",
        "format": "lowercase_hex_without_0x",
        "length_bytes": 4,
        "derivation": "first_4_bytes(blake3('synergy-network-magic-v1' || 'synergy:testnet' || final_genesis_hash))",
    }
    return doc


def genesis_hash_payload(genesis: dict[str, Any]) -> dict[str, Any]:
    inputs = genesis.get("canonicalization", {}).get("genesis_hash_inputs")
    if not inputs:
        payload = copy.deepcopy(genesis)
    else:
        payload = {key: copy.deepcopy(genesis[key]) for key in inputs if key in genesis}
    exclusions = set(genesis.get("canonicalization", {}).get("excluded_from_genesis_hash", []))
    exclusions.update(
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
    for dotted in exclusions:
        target = payload
        parts = dotted.split(".")
        for part in parts[:-1]:
            if not isinstance(target, dict) or part not in target:
                target = None
                break
            target = target[part]
        if isinstance(target, dict):
            target.pop(parts[-1], None)
    return payload


def recompute_hashes(genesis: dict[str, Any]) -> dict[str, Any]:
    genesis = copy.deepcopy(genesis)
    genesis.setdefault("p2p_identity", {})["status"] = "final"
    genesis["integrity"]["allocation_hash"] = hash_json(genesis["allocations"])
    genesis["integrity"]["validator_hash"] = hash_json(genesis["validators"])
    registry_validators = genesis["contracts"]["validator_registry"]["init_params"]["validators"]
    validator_set_hash = hash_json(registry_validators)
    genesis["contracts"]["validator_registry"]["init_params"]["validator_set_hash"] = validator_set_hash
    genesis["integrity"]["validator_set_hash"] = validator_set_hash
    genesis["integrity"]["contract_hash"] = hash_json(genesis["contracts"])
    state_root_payload = {
        "accounts": genesis["accounts"],
        "balances": genesis["balances"],
        "allocations": genesis["allocations"],
        "contracts": genesis["contracts"],
        "consensus": genesis["consensus"],
        "genesis_message": genesis["genesis_message"],
        "governance": genesis["governance"],
        "modules": genesis["modules"],
        "network": genesis["network"],
        "network_identity": genesis["network_identity"],
        "reserved_addresses": genesis["system_reserved_addresses"],
        "security": genesis["security"],
        "synergy_state": genesis["synergy_state"],
        "token": genesis["token"],
        "validators": genesis["validators"],
    }
    state_root = hash_json(state_root_payload)
    data_root = hash_json(
        {
            "contracts": genesis["contracts"],
            "modules": genesis["modules"],
            "precompiles": genesis["precompiles"],
        }
    )
    genesis["header"]["parent_hash"] = ZERO_HASH
    genesis["header"]["state_root"] = state_root
    genesis["header"]["data_root"] = data_root
    genesis["header"]["transactions_root"] = EMPTY_HASH
    genesis["header"]["receipts_root"] = EMPTY_HASH
    genesis["integrity"]["state_root"] = state_root
    genesis["integrity"]["recompute_required"] = False
    genesis["integrity"]["recompute_reason"] = "final canonical recompute completed"
    genesis["integrity"]["genesis_hash"] = hash_json(genesis_hash_payload(genesis))
    network_magic = blake3.blake3(
        b"synergy-network-magic-v1" + CAIP2.encode("utf-8") + genesis["integrity"]["genesis_hash"].encode("ascii")
    ).hexdigest()[:8]
    genesis["p2p_identity"]["network_magic_bytes"] = network_magic
    return genesis


def build_genesis(key_dir: Path, template_path: Path) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    template = remove_secret_named_fields(read_json(template_path))
    public_inputs = load_public_inputs(key_dir)
    wallets = public_inputs["wallets"]
    validators = public_inputs["validators"]
    required_wallets = [
        "treasury",
        "foundation_treasury",
        "dao_governance_reserve",
        "validator_security_pool",
        "token_sales",
        "liquidity_market_infra",
        "marketing_growth",
        "strategic_partnerships",
        "reliability_bonus",
        "team",
        "ecosystem",
        "sale",
        "faucet",
        "reserve",
        "rewards",
        "registry",
        "oracle",
    ]
    missing = [name for name in required_wallets if name not in wallets or not wallets[name]["address"]]
    if missing:
        fail(f"missing required public wallet files: {', '.join(missing)}")

    allocations, allocation_manifest = scaled_allocations(wallets, validators)
    extra_zero_addresses = [
        wallets["fee_collector"]["address"],
        wallets["reserve"]["address"],
        wallets["reliability_bonus"]["address"],
        template.get("contracts", {}).get("validator_registry", {}).get("address", ""),
        template.get("contracts", {}).get("identity", {}).get("address", ""),
    ]
    extra_zero_addresses.extend(cluster["cluster_address"] for cluster in public_inputs.get("clusters", []))
    balances = aggregate_balances(allocations, [address for address in extra_zero_addresses if address])
    balance_by_address = {entry["address"]: entry["balance_nwei"] for entry in balances}
    registry_validators = [registry_validator(validator) for validator in validators]

    genesis = copy.deepcopy(template)
    genesis["schema_version"] = "v1"
    genesis["env"] = "testnet"
    genesis["network"] = {
        "chain_id": CHAIN_ID,
        "network_id": NETWORK_ID,
        "network_type": "testnet",
        "protocol_name": "Synergy Network",
        "protocol_version": "1.0.0",
        "consensus_version": "posy/1.0.0",
        "genesis_schema_version": "v2",
    }
    genesis["network_identity"] = {
        "canonical_network": "testnet",
        "display_name": "Synergy Testnet",
        "network_short_name": "synergy",
        "network_slug": "synergy-testnet",
        "environment_family": "public_test_network",
        "synergy_native_chain_id": CHAIN_ID,
        "synergy_native_chain_id_hex": CHAIN_ID_HEX,
        "canonical_caip2": {
            "status": "active",
            "namespace": "synergy",
            "reference": "testnet",
            "value": CAIP2,
        },
        "reserved_caip2": {
            "eip155": {
                "status": "reserved_inactive",
                "namespace": "eip155",
                "reference": str(CHAIN_ID),
                "value": EIP155,
                "activation_condition": "Activate only when EVM/EIP-155 compatibility is implemented and publicly supported.",
            }
        },
        "network_uuid": template.get("network_identity", {}).get("network_uuid", "c6ad8633-38c8-5c24-823e-3ffe80793c85"),
        "genesis_schema_version": "v2",
    }
    genesis["token"] = {
        "name": TOKEN_NAME,
        "mainnet_name": "Synergy Token",
        "symbol": TOKEN_SYMBOL,
        "decimals": TOKEN_DECIMALS,
        "display_unit": TOKEN_SYMBOL,
        "smallest_unit": "nwei",
        "base_unit": BASE_UNIT,
        "nwei_per_snrg": str(NWEI_PER_SNRG),
        "minting_policy": "fixed_cap",
        "total_supply_cap_nwei": str(TOTAL_SUPPLY_NWEI),
        "initial_circulating_nwei": str(TOTAL_SUPPLY_NWEI),
    }
    genesis["allocations"] = allocations
    genesis["balances"] = balances
    genesis["allocation_sum_check"] = {
        "grand_total_nwei": str(sum(int(entry["amount_nwei"]) for entry in allocations)),
        "matches_supply_cap": sum(int(entry["amount_nwei"]) for entry in allocations) == TOTAL_SUPPLY_NWEI,
    }
    genesis["validators"] = validators
    genesis["accounts"] = [
        {"address": wallets["foundation_treasury"]["address"], "account_type": "FoundationTreasury"},
        {"address": wallets["dao_governance_reserve"]["address"], "account_type": "DAOGovernanceReserve"},
        {"address": wallets["fee_collector"]["address"], "account_type": "FeeCollector"},
        {"address": wallets["team"]["address"], "account_type": "TeamWallet"},
        {"address": wallets["ecosystem"]["address"], "account_type": "EcosystemWallet"},
        {"address": wallets["token_sales"]["address"], "account_type": "TokenSalesWallet"},
        {"address": wallets["liquidity_market_infra"]["address"], "account_type": "LiquidityMarketInfrastructureWallet"},
        {"address": wallets["marketing_growth"]["address"], "account_type": "MarketingGrowthWallet"},
        {"address": wallets["strategic_partnerships"]["address"], "account_type": "StrategicPartnershipsWallet"},
        {"address": wallets["reliability_bonus"]["address"], "account_type": "ReliabilityBonusPool"},
        {"address": wallets["faucet"]["address"], "account_type": "FaucetWallet"},
        {"address": wallets["validator_security_pool"]["address"], "account_type": "ValidatorSecurityPool"},
        {"address": genesis["contracts"]["validator_registry"]["address"], "account_type": "SystemContract"},
        {"address": genesis["contracts"]["identity"]["address"], "account_type": "SystemContract"},
    ]
    for cluster in public_inputs.get("clusters", []):
        genesis["accounts"].append({"address": cluster["cluster_address"], "account_type": "ValidatorCluster"})
    for validator in validators:
        genesis["accounts"].append({"address": validator["operator_address"], "account_type": "Validator"})
    genesis["accounts"] = sorted(genesis["accounts"], key=lambda entry: (entry["account_type"], entry["address"]))

    genesis.setdefault("header", {})
    genesis["header"].update(
        {
            "block_height": 0,
            "timestamp": genesis["header"].get("timestamp", 1778840400),
            "extra_data": GENESIS_MESSAGE,
            "consensus_fields": {
                "engine_id": "posy/v1",
                "epoch": 0,
                "round": 0,
                "proposer": None,
                "seal": None,
            },
        }
    )
    genesis["genesis_message"] = {
        "format": "utf-8",
        "max_bytes": 512,
        "immutable": True,
        "included_in_genesis_hash": True,
        "value": GENESIS_MESSAGE,
    }
    genesis.setdefault("consensus", {})
    genesis["consensus"].update(
        {
            "algorithm": "ProofOfSynergy",
            "model": "cluster_dag_hybrid",
            "finality": {
                "finality_type": "dual_quorum",
                "checkpoint_frequency_blocks": 50,
                "confirmation_depth": 2,
                "dag_is_finality_artifact": False,
            },
            "dag_data_plane": {
                "scope": "cluster_local",
                "transaction_flow": [
                    "transactions",
                    "encrypted_or_committed_batch",
                    "dag_vertex",
                    "availability_receipts",
                    "dag_certificate",
                    "deterministic_ordering_cut",
                    "posy_proposal",
                    "validator_verification",
                    "dual_quorum_qc_finality",
                ],
                "cross_cluster_policy": "checkpoints_qcs_and_compact_commitments_only",
                "certified_available_vertices_only": True,
                "uncertified_ordering_allowed": False,
                "equivocation_policy": "evidence_slashing_or_quarantine",
                "parent_selection": "deterministic_parent_diversity_required",
                "ordering_cut": "deterministic_reconstructable_from_dag_evidence",
            },
            "synergy_score_boundaries": {
                "may_influence": [
                    "validator_cluster_selection",
                    "proposer_selection",
                    "governance_weight",
                    "reward_shaping",
                ],
                "must_not_influence": [
                    "block_validity",
                    "fork_resolution",
                    "cryptographic_verification",
                    "transaction_acceptance",
                    "state_transition_correctness",
                ],
            },
        }
    )
    genesis["contracts"]["validator_registry"]["init_params"].update(
        {
            "initial_validator_count": VALIDATOR_COUNT,
            "min_validator_count": 4,
            "min_self_stake_nwei": str(VALIDATOR_SELF_STAKE_NWEI),
            "validators": registry_validators,
            "validator_set_mutable": True,
        }
    )
    genesis.setdefault("modules", {}).setdefault("staking", {}).update(
        {
            "validators": registry_validators,
            "reward_distribution": {
                **genesis.get("modules", {}).get("staking", {}).get("reward_distribution", {}),
                "reward_pool_initial_nwei": balance_by_address[wallets["rewards"]["address"]],
            },
        }
    )
    genesis["contracts"]["reward_distributor"]["init_params"]["initial_pool_balance_nwei"] = balance_by_address[
        wallets["rewards"]["address"]
    ]
    genesis["contracts"]["reward_distributor"]["init_params"]["pool_address"] = wallets["rewards"]["address"]
    genesis["modules"]["rewards"]["pool_balance_nwei"] = balance_by_address[wallets["rewards"]["address"]]
    genesis["modules"]["rewards"]["reward_config"] = {
        "validator_fee_share_bps": 6500,
        "treasury_fee_share_bps": 2500,
        "burn_fee_share_bps": 1000,
        "network_owned_validator_treasury_share_bps": 7000,
        "network_owned_validator_bonus_pool_share_bps": 3000,
        "phase1_consensus_participation_weight_bps": 3500,
        "phase1_block_proposal_weight_bps": 2000,
        "phase1_validation_accuracy_weight_bps": 2000,
        "phase1_cluster_contribution_weight_bps": 1500,
        "phase1_synergy_score_modifier_weight_bps": 1000,
        "phase2_uptime_weight_bps": 3500,
        "phase2_responsiveness_weight_bps": 2500,
        "phase2_no_jail_slash_weight_bps": 2000,
        "phase2_cluster_stability_weight_bps": 1000,
        "phase2_governance_participation_weight_bps": 1000,
        "min_base_fee_nWei": 1,
        "max_base_fee_change_per_epoch_bps": 1250,
        "target_epoch_utilization_bps": 6000,
        "adjustment_rate_bps": 1000,
        "target_gas_epoch": 30000000,
        "bonus_tier_10_epoch_bps": 200,
        "bonus_tier_50_epoch_bps": 500,
        "bonus_tier_100_epoch_bps": 1000,
        "bonus_tier_250_epoch_bps": 1500,
        "bonus_tier_500_epoch_bps": 2000,
        "max_reliability_bonus_bps": 3000,
    }
    genesis["modules"]["rewards"]["fee_collector_address"] = wallets["fee_collector"]["address"]
    genesis["modules"]["rewards"]["validator_rewards_pool_address"] = wallets["validator_security_pool"]["address"]
    genesis["modules"]["rewards"]["dao_treasury_address"] = wallets["dao_governance_reserve"]["address"]
    genesis["modules"]["rewards"]["reliability_bonus_pool_address"] = wallets["reliability_bonus"]["address"]
    genesis["modules"]["rewards"]["reliability_bonus_pool_balance_nwei"] = "0"
    treasury_balance = balance_by_address[wallets["treasury"]["address"]]
    genesis["contracts"]["treasury"]["init_params"]["initial_balance_nwei"] = treasury_balance
    genesis["modules"]["treasury"]["initial_balance_nwei"] = treasury_balance
    genesis["modules"]["treasury"]["treasury_address"] = wallets["treasury"]["address"]
    genesis["contracts"]["synergy_oracle"]["init_params"]["authority_address"] = wallets["oracle"]["address"]
    genesis["contracts"]["validator_registry"]["init_params"]["authority_address"] = wallets["registry"]["address"]
    genesis["governance"]["emergency"]["guardian_addresses"] = [wallets["signer2"]["address"]]
    genesis["security"]["access_control"]["externally_owned_admin_allowed"] = False
    genesis["security"]["access_control"].pop("privileged_eoa", None)
    genesis["system_reserved_addresses"]["policy"]["spending_key_material_exists"] = False
    genesis["system_reserved_addresses"]["policy"].pop("private_key_exists", None)
    genesis["synergy_state"]["address_config"]["burn_address"] = genesis["system_reserved_addresses"]["burn_address"]["address"]
    genesis["p2p_identity"] = {
        "network_magic_bytes": "",
        "network_magic_bytes_format": "lowercase_hex_without_0x",
        "length_bytes": 4,
        "derivation": "first_4_bytes(blake3('synergy-network-magic-v1' || 'synergy:testnet' || final_genesis_hash))",
        "peer_id_format": "synergy_node_peer_id",
    }
    genesis["canonicalization"] = {
        "serialization": "deterministic_json",
        "json_profile": "deterministic_sorted_keys_no_insignificant_whitespace",
        "hash_algorithm": "blake3-256",
        "genesis_hash_inputs": [
            "header",
            "network_identity",
            "network",
            "token",
            "genesis_message",
            "accounts",
            "allocations",
            "balances",
            "validators",
            "consensus",
            "execution",
            "crypto",
            "contracts",
            "modules",
            "governance",
            "security",
            "synergy_state",
            "system_reserved_addresses",
            "p2p_identity",
            "upgrade",
        ],
        "excluded_from_genesis_hash": [
            "integrity.genesis_hash",
            "integrity.signed_by",
            "integrity.draft_artifact_sha256",
            "integrity.recompute_required",
            "integrity.recompute_reason",
            "p2p_identity.network_magic_bytes",
            "p2p_identity.provisional_derivation_note",
        ],
        "network_magic_note": "network_magic_bytes is derived after final genesis_hash and excluded from genesis_hash to avoid circular identity.",
    }
    genesis["integrity"] = {
        "allocation_hash": "",
        "contract_hash": "",
        "genesis_hash": "",
        "signed_by": [],
        "state_root": "",
        "validator_hash": "",
        "validator_set_hash": "",
        "recompute_required": True,
        "recompute_reason": "pending canonical recompute",
    }
    genesis = remove_secret_named_fields(genesis)
    assert_no_secret_fields(genesis, "genesis")
    genesis = recompute_hashes(genesis)
    assert_no_secret_fields(genesis, "genesis")
    allocation_manifest["allocation_hash"] = genesis["integrity"]["allocation_hash"]
    allocation_manifest["validator_set_hash"] = genesis["integrity"]["validator_set_hash"]
    return genesis, allocation_manifest, public_inputs


def validate_documents(genesis: dict[str, Any], identifiers: dict[str, Any] | None = None) -> dict[str, Any]:
    errors: list[str] = []
    assert_no_secret_fields(genesis, "genesis")
    if identifiers is not None:
        assert_no_secret_fields(identifiers, "network identifiers")

    if genesis.get("network", {}).get("chain_id") != CHAIN_ID:
        errors.append(f"genesis network.chain_id must be {CHAIN_ID}")
    if genesis.get("network", {}).get("network_id") != NETWORK_ID:
        errors.append(f"genesis network.network_id must be {NETWORK_ID}")
    if genesis.get("network_identity", {}).get("canonical_caip2", {}).get("value") != CAIP2:
        errors.append("genesis native CAIP-2 must be synergy:testnet")
    if genesis.get("token", {}).get("total_supply_cap_nwei") != str(TOTAL_SUPPLY_NWEI):
        errors.append("token.total_supply_cap_nwei must be 12000000000000000000")
    if len(genesis.get("validators", [])) != VALIDATOR_COUNT:
        errors.append("genesis must contain exactly five validators")
    allocations_total = sum(int(entry["amount_nwei"]) for entry in genesis.get("allocations", []))
    balances_total = sum(int(entry["balance_nwei"]) for entry in genesis.get("balances", []))
    if allocations_total != TOTAL_SUPPLY_NWEI:
        errors.append("allocation sum does not match 12B SNRG")
    if balances_total != TOTAL_SUPPLY_NWEI:
        errors.append("balance sum does not match 12B SNRG")
    if not genesis.get("allocation_sum_check", {}).get("matches_supply_cap"):
        errors.append("allocation_sum_check.matches_supply_cap must be true")

    recomputed = recompute_hashes(genesis)
    for path in [
        ("header", "state_root"),
        ("header", "data_root"),
        ("integrity", "state_root"),
        ("integrity", "allocation_hash"),
        ("integrity", "validator_hash"),
        ("integrity", "validator_set_hash"),
        ("integrity", "contract_hash"),
        ("integrity", "genesis_hash"),
        ("p2p_identity", "network_magic_bytes"),
    ]:
        expected = recomputed[path[0]][path[1]]
        actual = genesis[path[0]][path[1]]
        if actual != expected:
            errors.append(f"{'.'.join(path)} mismatch: expected {expected}, found {actual}")

    top = [registry_validator(validator) for validator in genesis.get("validators", [])]
    registry = genesis.get("contracts", {}).get("validator_registry", {}).get("init_params", {}).get("validators", [])
    staking = genesis.get("modules", {}).get("staking", {}).get("validators", [])
    comparable_keys = [
        "validator_id",
        "validator_id_hash",
        "validator_address",
        "operator_address",
        "reward_address",
        "consensus_public_key",
        "consensus_key_type",
        "stake_nwei",
        "status",
        "activation_height",
        "voting_power",
    ]
    for label, entries in [("validator registry", registry), ("staking module", staking)]:
        if len(entries) != len(top):
            errors.append(f"{label} validator count does not match top-level validators")
            continue
        for expected, actual in zip(top, entries):
            for key in comparable_keys:
                if actual.get(key) != expected.get(key):
                    errors.append(f"{label} mismatch for {expected['validator_id']} field {key}")

    if identifiers is not None:
        if identifiers.get("chain_identifiers", {}).get("synergy_native", {}).get("decimal") != CHAIN_ID:
            errors.append(f"network identifiers chain id must be {CHAIN_ID}")
        if identifiers.get("chain_identifiers", {}).get("caip2_identifiers", {}).get("canonical_native", {}).get("value") != CAIP2:
            errors.append("network identifiers native CAIP-2 must be synergy:testnet")
        if identifiers.get("native_currency", {}).get("nwei_per_snrg") != str(NWEI_PER_SNRG):
            errors.append("network identifiers nwei_per_snrg mismatch")
        cryptographic = identifiers.get("cryptographic_identity", {})
        if cryptographic.get("genesis_hash") != genesis["integrity"]["genesis_hash"]:
            errors.append("network identifiers genesis hash mismatch")
        if cryptographic.get("network_magic_bytes", {}).get("value") != genesis["p2p_identity"]["network_magic_bytes"]:
            errors.append("network identifiers network magic mismatch")
        if identifiers.get("addressing", {}).get("burn_address") != genesis["system_reserved_addresses"]["burn_address"]["address"]:
            errors.append("burn address mismatch")

    return {
        "valid": not errors,
        "errors": errors,
        "genesis_hash": genesis.get("integrity", {}).get("genesis_hash"),
        "network_magic_bytes": genesis.get("p2p_identity", {}).get("network_magic_bytes"),
        "chain_id": genesis.get("network", {}).get("chain_id"),
        "validator_count": len(genesis.get("validators", [])),
        "total_supply_cap_nwei": genesis.get("token", {}).get("total_supply_cap_nwei"),
        "allocation_total_nwei": str(allocations_total),
        "balance_total_nwei": str(balances_total),
    }


def hexdump(data: bytes) -> str:
    lines = [
        "SYNERGY GENESIS BLOCK RAW HEX",
        "Canonical serialization: deterministic JSON sorted keys, no insignificant whitespace",
        f"Bytes: {len(data)}",
        "",
        "OFFSET    HEX BYTES                                               ASCII",
        "--------  ------------------------------------------------------  ----------------",
    ]
    for offset in range(0, len(data), 16):
        chunk = data[offset : offset + 16]
        hex_bytes = " ".join(f"{byte:02x}" for byte in chunk)
        grouped = f"{hex_bytes:<47}"
        ascii_text = "".join(chr(byte) if 32 <= byte <= 126 else "." for byte in chunk)
        lines.append(f"{offset:08x}  {grouped}  {ascii_text}".rstrip())
    return "\n".join(lines) + "\n"


def annotated_text(genesis: dict[str, Any], data_len: int) -> str:
    integrity = genesis["integrity"]
    return "\n".join(
        [
            "SYNERGY GENESIS BLOCK ANNOTATED EXPORT",
            "",
            f"chain_id: {genesis['network']['chain_id']}",
            f"network_id: {genesis['network']['network_id']}",
            f"native_caip2: {genesis['network_identity']['canonical_caip2']['value']}",
            f"timestamp: {genesis['header']['timestamp']}",
            f"parent_hash: {genesis['header']['parent_hash']}",
            f"state_root: {integrity['state_root']}",
            f"validator_set_hash: {integrity['validator_set_hash']}",
            f"allocation_hash: {integrity['allocation_hash']}",
            f"contract_hash: {integrity['contract_hash']}",
            f"network_magic_bytes: {genesis['p2p_identity']['network_magic_bytes']}",
            f"genesis_hash: {integrity['genesis_hash']}",
            f"canonical_bytes: {data_len}",
            "",
            "block_header:",
            json.dumps(genesis["header"], indent=2, sort_keys=True),
            "",
            "genesis_message:",
            genesis["genesis_message"]["value"],
            "",
            "dag_posy_consensus_metadata:",
            json.dumps(genesis["consensus"]["dag_data_plane"], indent=2, sort_keys=True),
            "",
            "validator_registry:",
            json.dumps(genesis["contracts"]["validator_registry"]["init_params"]["validators"], indent=2, sort_keys=True),
            "",
            "token_metadata:",
            json.dumps(genesis["token"], indent=2, sort_keys=True),
            "",
            "governance_metadata:",
            json.dumps(genesis["governance"], indent=2, sort_keys=True),
            "",
            "genesis_transactions: []",
            "quorum_finality_metadata:",
            json.dumps(genesis["consensus"]["finality"], indent=2, sort_keys=True),
            "",
            "reserved_address_registry:",
            json.dumps(genesis["system_reserved_addresses"], indent=2, sort_keys=True),
            "",
        ]
    )


def render_svg(pretty: str, genesis: dict[str, Any]) -> str:
    lines = pretty.splitlines()
    max_line = min(max(len(line) for line in lines), 118)
    char_width = 8
    line_height = 16
    width = max(1040, max_line * char_width + 64)
    visible_lines = lines[:180]
    height = 220 + len(visible_lines) * line_height
    integrity = genesis["integrity"]
    title = "Synergy Genesis Block Raw Hex"
    subtitle = (
        f"chain_id={CHAIN_ID}  hash={integrity['genesis_hash'][:24]}...  "
        f"magic={genesis['p2p_identity']['network_magic_bytes']}"
    )
    text_nodes = []
    for idx, line in enumerate(visible_lines):
        color = "#d6f3ff"
        if integrity["genesis_hash"][:16] in line or genesis["p2p_identity"]["network_magic_bytes"] in line:
            color = "#6fffd2"
        text_nodes.append(
            f'<text x="32" y="{186 + idx * line_height}" fill="{color}" font-family="Menlo, Consolas, monospace" font-size="12">{html.escape(line[:118])}</text>'
        )
    return "\n".join(
        [
            f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">',
            '<rect width="100%" height="100%" fill="#061014"/>',
            '<rect x="20" y="20" width="' + str(width - 40) + '" height="' + str(height - 40) + '" rx="8" fill="#081820" stroke="#1f5a66"/>',
            '<text x="32" y="58" fill="#f4fbff" font-family="Menlo, Consolas, monospace" font-size="24" font-weight="700">' + html.escape(title) + "</text>",
            '<text x="32" y="88" fill="#7ee7ff" font-family="Menlo, Consolas, monospace" font-size="13">' + html.escape(subtitle) + "</text>",
            '<text x="32" y="116" fill="#a8b8c0" font-family="Menlo, Consolas, monospace" font-size="12">' + html.escape(GENESIS_MESSAGE) + "</text>",
            '<text x="32" y="146" fill="#6fffd2" font-family="Menlo, Consolas, monospace" font-size="12">' + html.escape(f"state_root={integrity['state_root']}") + "</text>",
            '<text x="32" y="164" fill="#6fffd2" font-family="Menlo, Consolas, monospace" font-size="12">' + html.escape(f"validator_set_hash={integrity['validator_set_hash']} allocation_hash={integrity['allocation_hash']}") + "</text>",
            *text_nodes,
            "</svg>",
        ]
    )


def render_png_from_svg(svg_path: Path, png_path: Path) -> None:
    quicklook = shutil.which("qlmanage")
    if quicklook:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_dir = Path(tmp)
            subprocess.run(
                [quicklook, "-t", "-s", "2400", "-o", str(tmp_dir), str(svg_path)],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            generated = tmp_dir / f"{svg_path.name}.png"
            if generated.exists():
                shutil.copyfile(generated, png_path)
                return

    converter = shutil.which("magick") or shutil.which("convert")
    if converter:
        cmd = [converter, str(svg_path), str(png_path)]
        subprocess.run(cmd, check=True)
        return

    fail("PNG rendering requires qlmanage, ImageMagick magick/convert, or rsvg-convert in PATH")


def export_genesis_artifacts(genesis: dict[str, Any], out_dir: Path) -> dict[str, str]:
    canonical_bytes = canonical_json(genesis_hash_payload(genesis)).encode("utf-8")
    pretty = hexdump(canonical_bytes)
    annotated = annotated_text(genesis, len(canonical_bytes))
    hex_text = canonical_bytes.hex() + "\n"
    paths = {
        "bin": out_dir / "genesis.testnet.bin",
        "hex": out_dir / "genesis.testnet.hex",
        "prettyhex": out_dir / "genesis.testnet.prettyhex.txt",
        "annotated": out_dir / "genesis.testnet.annotated.txt",
        "svg": out_dir / "genesis.testnet.hex.svg",
        "png": out_dir / "genesis.testnet.hex.png",
    }
    out_dir.mkdir(parents=True, exist_ok=True)
    paths["bin"].write_bytes(canonical_bytes)
    write_text(paths["hex"], hex_text)
    write_text(paths["prettyhex"], pretty)
    write_text(paths["annotated"], annotated)
    write_text(paths["svg"], render_svg(pretty, genesis))
    render_png_from_svg(paths["svg"], paths["png"])
    return {key: str(path) for key, path in paths.items()}


def sha256_file(path: Path) -> str:
    import hashlib

    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def release_manifest(out_dir: Path, files: list[Path], genesis: dict[str, Any]) -> dict[str, Any]:
    return {
        "name": "Synergy Testnet Genesis Release Artifacts",
        "chain_id": CHAIN_ID,
        "network_id": NETWORK_ID,
        "native_caip2": CAIP2,
        "genesis_hash": genesis["integrity"]["genesis_hash"],
        "network_magic_bytes": genesis["p2p_identity"]["network_magic_bytes"],
        "artifacts": [
            {
                "file": path.name,
                "sha256": sha256_file(path),
                "bytes": path.stat().st_size,
            }
            for path in sorted(files)
            if path.exists()
        ],
    }


def write_rebuild_outputs(genesis: dict[str, Any], identifiers: dict[str, Any], allocation_manifest: dict[str, Any], public_inputs: dict[str, Any], root: Path, out_dir: Path) -> None:
    report = validate_documents(genesis, identifiers)
    if not report["valid"]:
        fail("\n".join(report["errors"]))

    root_genesis = root / "genesis.testnet.json"
    root_identifiers = root / "network-identifiers.testnet.json"
    config_genesis = root / "config" / "genesis.json"
    config_testnet_genesis = root / "config" / "genesis.testnet.json"

    write_json(root_genesis, genesis)
    write_json(config_genesis, genesis)
    write_json(config_testnet_genesis, genesis)
    write_json(root_identifiers, identifiers)
    write_json(root / "testnet-allocation-manifest.json", allocation_manifest)
    write_json(root / "testnet-public-validator-manifest.json", {
        "chain_id": CHAIN_ID,
        "network_id": NETWORK_ID,
        "native_caip2": CAIP2,
        "validators": public_inputs["validators"],
        "wallets": {
            name: {"address": wallet["address"], "address_type": wallet["address_type"], "algorithm": wallet["algorithm"]}
            for name, wallet in sorted(public_inputs["wallets"].items())
        },
    })

    out_dir.mkdir(parents=True, exist_ok=True)
    write_json(out_dir / "genesis.testnet.json", genesis)
    write_json(out_dir / "network-identifiers.testnet.json", identifiers)
    write_text(out_dir / "genesis.testnet.hash.txt", genesis["integrity"]["genesis_hash"] + "\n")
    write_text(out_dir / "network-magic-bytes.testnet.txt", genesis["p2p_identity"]["network_magic_bytes"] + "\n")
    write_json(out_dir / "validator-public-manifest.testnet.json", {
        "chain_id": CHAIN_ID,
        "validators": public_inputs["validators"],
    })
    write_json(out_dir / "allocation-manifest.testnet.json", allocation_manifest)
    write_json(out_dir / "validation-report.testnet.json", report)
    export_paths = export_genesis_artifacts(genesis, out_dir)
    release_files = [
        out_dir / "genesis.testnet.json",
        out_dir / "network-identifiers.testnet.json",
        out_dir / "genesis.testnet.hash.txt",
        out_dir / "network-magic-bytes.testnet.txt",
        out_dir / "validator-public-manifest.testnet.json",
        out_dir / "allocation-manifest.testnet.json",
        out_dir / "validation-report.testnet.json",
    ] + [Path(path) for path in export_paths.values()]
    write_json(out_dir / "release-manifest.testnet.json", release_manifest(out_dir, release_files, genesis))


def command_rebuild_keyfiles(args: argparse.Namespace) -> None:
    root = Path(args.root).resolve()
    key_dir = Path(args.key_dir).resolve()
    template = key_dir / "genesis.testnet.json"
    network_template = key_dir / "network-identifiers.testnet.json"
    if not template.exists():
        template = root / "config" / "genesis.json"
    if not network_template.exists():
        network_template = root / "network-identifiers.testnet.json"
    genesis, allocation_manifest, public_inputs = build_genesis(key_dir, template)
    temp_genesis_path = root / ".tmp-genesis-for-sha.json"
    write_json(temp_genesis_path, genesis)
    genesis_sha256 = sha256_file(temp_genesis_path)
    temp_genesis_path.unlink(missing_ok=True)
    identifiers = update_network_identifiers(read_json(network_template), genesis["integrity"]["genesis_hash"], genesis["p2p_identity"]["network_magic_bytes"], genesis_sha256)
    write_rebuild_outputs(genesis, identifiers, allocation_manifest, public_inputs, root, Path(args.out_dir).resolve())
    print(f"genesis_hash={genesis['integrity']['genesis_hash']}")
    print(f"network_magic_bytes={genesis['p2p_identity']['network_magic_bytes']}")


def command_rebuild_public_manifest(args: argparse.Namespace) -> None:
    root = Path(args.root).resolve()
    manifest = read_json(Path(args.public_manifest).resolve())
    validators = manifest.get("validators", [])
    wallets = manifest.get("wallets", {})
    public_inputs = {"validators": validators, "wallets": wallets}
    template = root / "genesis.testnet.json"
    if not template.exists():
        template = root / "config" / "genesis.json"
    genesis, allocation_manifest, _ = build_genesis_from_public_inputs(public_inputs, template)
    identifiers_path = root / "network-identifiers.testnet.json"
    identifiers_template = read_json(identifiers_path)
    temp_genesis_path = root / ".tmp-genesis-for-sha.json"
    write_json(temp_genesis_path, genesis)
    genesis_sha256 = sha256_file(temp_genesis_path)
    temp_genesis_path.unlink(missing_ok=True)
    identifiers = update_network_identifiers(identifiers_template, genesis["integrity"]["genesis_hash"], genesis["p2p_identity"]["network_magic_bytes"], genesis_sha256)
    report = validate_documents(genesis, identifiers)
    if not report["valid"]:
        fail("\n".join(report["errors"]))
    print(json.dumps(report, indent=2, sort_keys=True))


def build_genesis_from_public_inputs(public_inputs: dict[str, Any], template_path: Path) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    # Used by the no-secret dry-run path. It materializes only public fields into
    # the same public input shape consumed by build_genesis so both rebuild paths
    # exercise one allocation/state/hashing implementation.
    validators = public_inputs.get("validators", [])
    wallets = public_inputs.get("wallets", {})
    if len(validators) != VALIDATOR_COUNT:
        fail("public manifest must contain exactly five validators")
    required_wallets = ["treasury", "team", "ecosystem", "sale", "faucet", "reserve", "rewards", "registry", "oracle", "fee_collector", "signer2"]
    missing = [name for name in required_wallets if not wallets.get(name, {}).get("address")]
    if missing:
        fail(f"public manifest missing wallet addresses: {', '.join(missing)}")

    with tempfile.TemporaryDirectory(prefix="synergy-public-genesis-") as tmp:
        tmp_dir = Path(tmp)
        new_address_dir = tmp_dir / "new-network-addresses"
        new_address_dir.mkdir(parents=True, exist_ok=True)
        validator_dir = tmp_dir / "validator-addresses"
        validator_dir.mkdir(parents=True, exist_ok=True)
        new_wallet_aliases = {
            "dao_governance_reserve": "DAOGovernanceReserve",
            "foundation_treasury": "FoundationTreasury",
            "liquidity_market_infra": "LiquidityMarketInfra",
            "marketing_growth": "MarketingGrowth",
            "reliability_bonus": "ReliabilityBonus",
            "strategic_partnerships": "StrategicPartnerships",
            "token_sales": "TokenSalesWallet",
            "validator_security_pool": "ValidatorSecurityPool",
        }
        for name, wallet in wallets.items():
            filename = "fee-collector.pub.json" if name == "fee_collector" else f"{name}.pub.json"
            wallet_payload = {
                "address": wallet.get("address", ""),
                "address_type": wallet.get("address_type", ""),
                "algorithm": wallet.get("algorithm", ""),
                "public_key": wallet.get("public_key", ""),
                "external_addresses": wallet.get("external_addresses", []),
            }
            write_json(tmp_dir / filename, wallet_payload)
            if name in new_wallet_aliases:
                write_json(new_address_dir / f"{new_wallet_aliases[name]}.pub.json", wallet_payload)
        for index, validator in enumerate(validators, start=1):
            write_json(
                validator_dir / f"{index}.pub.json",
                {
                    "address": validator.get("validator_address") or validator.get("operator_address"),
                    "address_type": "validator",
                    "algorithm": validator.get("account_key_type", ""),
                    "public_key": validator.get("account_public_key", ""),
                    "consensus_key": {
                        "algorithm": validator.get("consensus_key_type", "FN-DSA-1024"),
                        "public_key": validator.get("consensus_public_key", ""),
                    },
                    "account_key": {
                        "algorithm": validator.get("account_key_type", ""),
                        "public_key": validator.get("account_public_key", ""),
                    },
                    "node_identity_key": {
                        "algorithm": validator.get("node_identity_key_type", ""),
                        "public_key": validator.get("node_identity_public_key", ""),
                        "peer_id": validator.get("peer_id", ""),
                    },
                    "entropy_contribution_key": {
                        "algorithm": validator.get("identity_key_type", ""),
                        "public_key": validator.get("identity_public_key", ""),
                    },
                    "validator_id_hash": validator.get("validator_id_hash", ""),
                    "key_bundle_hash": validator.get("key_bundle_hash", ""),
                    "metadata_hash": validator.get("metadata_hash", ""),
                    "moniker": validator.get("moniker", ""),
                },
            )
        return build_genesis(tmp_dir, template_path)


def command_validate(args: argparse.Namespace) -> None:
    genesis = read_json(Path(args.genesis).resolve())
    identifiers = read_json(Path(args.network_identifiers).resolve()) if args.network_identifiers else None
    report = validate_documents(genesis, identifiers)
    print(json.dumps(report, indent=2, sort_keys=True))
    if not report["valid"]:
        raise SystemExit(1)


def command_hash(args: argparse.Namespace) -> None:
    genesis = read_json(Path(args.genesis).resolve())
    print(recompute_hashes(genesis)["integrity"]["genesis_hash"])


def command_diff(args: argparse.Namespace) -> None:
    genesis = read_json(Path(args.genesis).resolve())
    actual = recompute_hashes(genesis)["integrity"]["genesis_hash"]
    if actual != args.expected_hash:
        print(f"genesis hash differs: expected {args.expected_hash}, actual {actual}", file=sys.stderr)
        raise SystemExit(2)
    print(f"genesis hash matches: {actual}")


def command_export(args: argparse.Namespace) -> None:
    genesis = read_json(Path(args.genesis).resolve())
    report = validate_documents(genesis)
    if not report["valid"]:
        fail("\n".join(report["errors"]))
    paths = export_genesis_artifacts(genesis, Path(args.out_dir).resolve())
    print(json.dumps(paths, indent=2, sort_keys=True))


def add_onboarding_check(
    checks: list[dict[str, Any]],
    name: str,
    ok: bool,
    detail: str = "",
    *,
    expected: Any | None = None,
    actual: Any | None = None,
) -> None:
    check: dict[str, Any] = {"name": name, "ok": ok, "detail": detail}
    if expected is not None:
        check["expected"] = expected
    if actual is not None:
        check["actual"] = actual
    checks.append(check)


def normalized_consensus_key_type(value: str | None) -> str:
    return str(value or "").strip().upper().replace("_", "-")


def initial_validator_addresses(genesis: dict[str, Any]) -> set[str]:
    addresses: set[str] = set()
    validator_sources = [
        genesis.get("validators", []),
        genesis.get("contracts", {}).get("validator_registry", {}).get("init_params", {}).get("validators", []),
        genesis.get("modules", {}).get("staking", {}).get("validators", []),
    ]
    for validators in validator_sources:
        for validator in validators:
            for key in ["validator_address", "operator_address", "reward_address", "reward_payout_address"]:
                address = str(validator.get(key, "")).strip()
                if address:
                    addresses.add(address)
    return addresses


def resolve_repo_path(root: Path, value: str) -> Path:
    path = Path(value)
    if path.is_absolute():
        return path
    return root / path


def command_onboarding_dry_run(args: argparse.Namespace) -> None:
    root = Path(args.root).resolve()
    genesis = read_json(resolve_repo_path(root, args.genesis))
    identifiers = read_json(resolve_repo_path(root, args.network_identifiers))
    consensus_fork = read_json(resolve_repo_path(root, args.consensus_fork))
    validation_report = validate_documents(genesis, identifiers)
    checks: list[dict[str, Any]] = []

    add_onboarding_check(
        checks,
        "dry_run_no_mutation",
        True,
        "read-only validator onboarding dry run; no runtime start, snapshot restore, stake submission, or activation submission",
        expected=False,
        actual=False,
    )
    add_onboarding_check(
        checks,
        "canonical_genesis_documents_valid",
        validation_report["valid"],
        "; ".join(validation_report["errors"]) if validation_report["errors"] else "genesis and network identifiers validated",
    )
    add_onboarding_check(
        checks,
        "chain_id",
        genesis.get("network", {}).get("chain_id") == CHAIN_ID,
        "canonical Synergy Testnet chain ID",
        expected=CHAIN_ID,
        actual=genesis.get("network", {}).get("chain_id"),
    )
    add_onboarding_check(
        checks,
        "runtime_network_id",
        args.runtime_network_id == RUNTIME_NETWORK_ID,
        "runtime network label after checkpointed FN-DSA fork",
        expected=RUNTIME_NETWORK_ID,
        actual=args.runtime_network_id,
    )
    add_onboarding_check(
        checks,
        "genesis_network_id",
        genesis.get("network", {}).get("network_id") == NETWORK_ID,
        "immutable genesis numeric network ID",
        expected=NETWORK_ID,
        actual=genesis.get("network", {}).get("network_id"),
    )
    add_onboarding_check(
        checks,
        "network_identifiers_chain_id",
        identifiers.get("chain_identifiers", {}).get("synergy_native", {}).get("decimal") == CHAIN_ID,
        "network-identifiers Synergy native chain ID",
        expected=CHAIN_ID,
        actual=identifiers.get("chain_identifiers", {}).get("synergy_native", {}).get("decimal"),
    )
    expected_genesis_hash = identifiers.get("cryptographic_identity", {}).get("genesis_hash")
    add_onboarding_check(
        checks,
        "genesis_hash",
        validation_report["genesis_hash"] == expected_genesis_hash,
        "local genesis hash matches canonical network identifiers",
        expected=expected_genesis_hash,
        actual=validation_report["genesis_hash"],
    )
    expected_magic = identifiers.get("cryptographic_identity", {}).get("network_magic_bytes", {}).get("value")
    add_onboarding_check(
        checks,
        "network_magic_bytes",
        validation_report["network_magic_bytes"] == expected_magic,
        "local network magic matches canonical network identifiers",
        expected=expected_magic,
        actual=validation_report["network_magic_bytes"],
    )

    candidate_address = str(args.validator_address or "").strip()
    add_onboarding_check(
        checks,
        "validator_address_format",
        bool(NEW_VALIDATOR_ADDRESS_RE.fullmatch(candidate_address)),
        "new validator address must be a lower-case synv1 address",
        expected="synv1 + 36 lower-case alphanumeric characters",
        actual=candidate_address,
    )
    existing_addresses = initial_validator_addresses(genesis)
    add_onboarding_check(
        checks,
        "validator_not_in_genesis",
        candidate_address not in existing_addresses,
        "post-baseline validator onboarding must not modify or reuse baseline validator entries",
        actual=candidate_address,
    )

    key_type = normalized_consensus_key_type(args.consensus_key_type)
    key_type_ok = key_type in {"FN-DSA", POST_FORK_VALIDATOR_KEY_ALGORITHM} and key_type not in AMBIGUOUS_CONSENSUS_KEY_LABELS
    add_onboarding_check(
        checks,
        "consensus_key_type_explicit_fndsa",
        key_type_ok,
        "new validator consensus key metadata must be explicit FN-DSA",
        expected=f"{POST_FORK_CONSENSUS_ALGORITHM} or {POST_FORK_VALIDATOR_KEY_ALGORITHM}",
        actual=args.consensus_key_type,
    )
    consensus_public_key = str(args.consensus_public_key or "").strip()
    public_key_payload = consensus_public_key.removeprefix("fn-dsa:")
    public_key_prefix_ok = consensus_public_key.startswith("fn-dsa:")
    try:
        decoded_public_key = base64.b64decode(public_key_payload, validate=True) if public_key_prefix_ok else b""
    except binascii.Error:
        decoded_public_key = b""
    add_onboarding_check(
        checks,
        "consensus_public_key_fndsa_prefix",
        public_key_prefix_ok and bool(decoded_public_key),
        "new validator consensus public key must use fn-dsa:<base64>",
        expected="fn-dsa:<base64>",
        actual=consensus_public_key[:24] + ("..." if len(consensus_public_key) > 24 else ""),
    )

    add_onboarding_check(
        checks,
        "consensus_fork_height",
        consensus_fork.get("fork_height") == CONSENSUS_FORK_HEIGHT,
        "checkpointed consensus fork height",
        expected=CONSENSUS_FORK_HEIGHT,
        actual=consensus_fork.get("fork_height"),
    )
    add_onboarding_check(
        checks,
        "consensus_fork_parent_height",
        consensus_fork.get("parent_height") == CONSENSUS_FORK_PARENT_HEIGHT,
        "checkpointed consensus fork parent height",
        expected=CONSENSUS_FORK_PARENT_HEIGHT,
        actual=consensus_fork.get("parent_height"),
    )
    add_onboarding_check(
        checks,
        "consensus_fork_parent_hash",
        consensus_fork.get("parent_hash") == CONSENSUS_FORK_PARENT_HASH,
        "checkpointed consensus fork parent hash",
        expected=CONSENSUS_FORK_PARENT_HASH,
        actual=consensus_fork.get("parent_hash"),
    )
    add_onboarding_check(
        checks,
        "post_fork_consensus_algorithm",
        consensus_fork.get("new_consensus_algorithm") == POST_FORK_CONSENSUS_ALGORITHM,
        "post-fork consensus signature algorithm",
        expected=POST_FORK_CONSENSUS_ALGORITHM,
        actual=consensus_fork.get("new_consensus_algorithm"),
    )
    fork_registry_key_types = [
        normalized_consensus_key_type(entry.get("consensus_key_type"))
        for entry in consensus_fork.get("new_validator_registry", [])
    ]
    add_onboarding_check(
        checks,
        "post_fork_validator_registry_key_algorithm",
        bool(fork_registry_key_types) and all(key_type == POST_FORK_CONSENSUS_ALGORITHM for key_type in fork_registry_key_types),
        "checkpointed validator registry must be explicit FN-DSA",
        expected=POST_FORK_CONSENSUS_ALGORITHM,
        actual=sorted(set(fork_registry_key_types)),
    )
    add_onboarding_check(
        checks,
        "consensus_fork_parser_mode",
        consensus_fork.get("parser_mode") == FORK_PARSER_MODE,
        "fork parser mode must fail closed",
        expected=FORK_PARSER_MODE,
        actual=consensus_fork.get("parser_mode"),
    )

    for port_name, expected_port in ONBOARDING_REQUIRED_PORTS.items():
        actual_port = getattr(args, f"{port_name}_port")
        add_onboarding_check(
            checks,
            f"{port_name}_port",
            actual_port == expected_port,
            "canonical Testnet onboarding port",
            expected=expected_port,
            actual=actual_port,
        )

    height_delta: int | None = None
    if args.local_height is not None and args.public_head_height is not None:
        height_delta = int(args.public_head_height) - int(args.local_height)
    add_onboarding_check(
        checks,
        "height_within_2_blocks",
        height_delta is not None and abs(height_delta) <= 2,
        "candidate host must be synced near public head before activation",
        expected="absolute height delta <= 2",
        actual=height_delta,
    )

    evidence_flags = [
        "signing_challenge_verified",
        "seed_registration_verified",
        "relayer_peer_visibility_verified",
        "support_node_replay_preflight_verified",
        "funding_verified",
        "bonded_stake_verified",
        "source_majority_proof_verified",
        "shadow_duty_gate_verified",
    ]
    for flag_name in evidence_flags:
        add_onboarding_check(
            checks,
            flag_name,
            bool(getattr(args, flag_name)),
            "required dry-run evidence flag",
            expected=True,
            actual=bool(getattr(args, flag_name)),
        )

    support_node_update_plan = {
        "required_before_activation": True,
        "candidate_validator_address": candidate_address,
        "support_roles": [
            "bootnode",
            "seed",
            "relayer",
            "rpc_gateway",
            "indexer_explorer",
            "archive_validator",
            "observer",
            "atlas_api",
        ],
        "non_validator_allowlist_policy": {
            "preferred": "strict_validator_allowlist=false or SYNERGY_STRICT_VALIDATOR_ALLOWLIST=0",
            "legacy_fallback": "if a non-validator support node remains strict, its allowed validator address list must include the candidate before activation_effective_block N+1",
        },
        "runtime_consensus_config": {
            "validator_vote_threshold": 0,
            "validator_cluster_size": 7,
            "max_validators_min": 100,
        },
            "checkpoint_fork_registry_policy": {
                "purpose": "checkpointed fork key registry for validators active at the fork height",
                "must_not_be_used_as": "the ongoing post-baseline validator admission registry",
                "onboarded_key_source": "finalized validator registry/admission state after activation",
            },
        "required_service_env": [
            "SYNERGY_PROJECT_ROOT points at the deployed node root",
            "SYNERGY_CONFIG_PATH points at the deployed node.toml",
            "SYNERGY_CONSENSUS_FORK_MIGRATION_FILE points at canonical checkpoint fork metadata",
            "Use validator_vote_threshold=0 so runtime derives quorum from the active validator set",
        ],
    }

    ok = validation_report["valid"] and all(check["ok"] for check in checks)
    result = {
        "ok": ok,
        "mutates_state": False,
        "chain_id": CHAIN_ID,
        "runtime_network_id": RUNTIME_NETWORK_ID,
        "shadow_phase_blocks": ONBOARDING_SHADOW_PHASE_BLOCKS,
        "activation_model": {
            "shadow_weight": 0,
            "shadow_votes_counted": False,
            "activation_recorded_block": "N",
            "activation_recorded_uses_state_from": "N-1",
            "activation_effective_block": "N+1",
        },
        "support_node_update_plan": support_node_update_plan,
        "validation_report": validation_report,
        "checks": checks,
    }
    print(json.dumps(result, indent=2, sort_keys=True))
    if not ok:
        raise SystemExit(1)


def command_preflight(args: argparse.Namespace) -> None:
    genesis = read_json(Path(args.genesis).resolve())
    identifiers = read_json(Path(args.network_identifiers).resolve())
    report = validate_documents(genesis, identifiers)
    checks: list[dict[str, Any]] = []

    def add(name: str, ok: bool, detail: str = "") -> None:
        checks.append({"name": name, "ok": ok, "detail": detail})

    add("chain_id", genesis.get("network", {}).get("chain_id") == CHAIN_ID, str(genesis.get("network", {}).get("chain_id")))
    add("network_id", genesis.get("network", {}).get("network_id") == NETWORK_ID, str(genesis.get("network", {}).get("network_id")))
    add("genesis_hash", report["genesis_hash"] == identifiers.get("cryptographic_identity", {}).get("genesis_hash"), report["genesis_hash"])
    add("network_magic_bytes", report["network_magic_bytes"] == identifiers.get("cryptographic_identity", {}).get("network_magic_bytes", {}).get("value"), report["network_magic_bytes"])
    if args.validator_address:
        validator = next((entry for entry in genesis["validators"] if entry["operator_address"] == args.validator_address), None)
        add("validator_in_genesis", validator is not None, args.validator_address)
        if validator and args.peer_id:
            add("peer_id_matches", validator.get("peer_id") == args.peer_id, args.peer_id)
        if validator and args.operator_address:
            add("operator_address_matches", validator.get("operator_address") == args.operator_address, args.operator_address)
        if validator and args.reward_address:
            add("reward_address_matches", validator.get("reward_address") == args.reward_address, args.reward_address)
        if validator and args.self_stake_nwei:
            add("self_stake_matches", validator.get("self_stake_nwei") == args.self_stake_nwei, args.self_stake_nwei)
    if args.key_dir:
        key_dir = Path(args.key_dir).resolve()
        unsafe = []
        for path in key_dir.rglob("*"):
            if path.is_file() and path.suffix in {".json", ".key", ".toml"} and any(part in path.name for part in [".dec", ".enc", "private"]):
                mode = path.stat().st_mode & 0o777
                if mode & 0o077:
                    unsafe.append(f"{path.name}:{oct(mode)}")
        add("private_material_file_permissions", not unsafe, ", ".join(unsafe))
        add("duplicate_validator_public_keys", len({entry["consensus_public_key"] for entry in genesis["validators"]}) == len(genesis["validators"]))
    add("p2p_listen_address_present", bool(args.listen_address), args.listen_address or "")
    add("p2p_advertise_address_present", bool(args.advertise_address), args.advertise_address or "")
    for endpoint in args.required_port or []:
        try:
            host, port_text = endpoint.rsplit(":", 1)
            with socket.create_connection((host.strip("[]"), int(port_text)), timeout=3):
                reachable = True
        except Exception as exc:
            reachable = False
            endpoint = f"{endpoint} ({exc})"
        add("required_port_reachable", reachable, endpoint)
    add("ntp_clock_check", True, "operator must verify NTP on host before launch; command path recorded in docs")
    add("signing_challenge", bool(args.signing_challenge_verified), "pass --signing-challenge-verified after local signer proves key ownership without printing key material")
    ok = report["valid"] and all(check["ok"] for check in checks)
    print(json.dumps({"ok": ok, "checks": checks}, indent=2, sort_keys=True))
    if not ok:
        raise SystemExit(1)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Synergy Testnet genesis utility")
    parser.add_argument("--root", default=Path(__file__).resolve().parents[2], help="repository root")
    sub = parser.add_subparsers(dest="command", required=True)

    rebuild = sub.add_parser("rebuild-keyfiles")
    rebuild.add_argument("key_dir")
    rebuild.add_argument("--out-dir", default="release-artifacts/testnet")
    rebuild.set_defaults(func=command_rebuild_keyfiles)

    public = sub.add_parser("rebuild-public-manifest")
    public.add_argument("public_manifest")
    public.set_defaults(func=command_rebuild_public_manifest)

    validate = sub.add_parser("validate")
    validate.add_argument("--genesis", required=True)
    validate.add_argument("--network-identifiers")
    validate.set_defaults(func=command_validate)

    hash_cmd = sub.add_parser("hash")
    hash_cmd.add_argument("--genesis", required=True)
    hash_cmd.set_defaults(func=command_hash)

    diff = sub.add_parser("diff")
    diff.add_argument("--genesis", required=True)
    diff.add_argument("--expected-hash", required=True)
    diff.set_defaults(func=command_diff)

    export = sub.add_parser("export")
    export.add_argument("--genesis", required=True)
    export.add_argument("--out-dir", default="release-artifacts/testnet")
    export.set_defaults(func=command_export)

    onboarding = sub.add_parser("onboarding-dry-run")
    onboarding.add_argument("--genesis", required=True)
    onboarding.add_argument("--network-identifiers", required=True)
    onboarding.add_argument("--consensus-fork", default="config/consensus-fork-migration.json")
    onboarding.add_argument("--runtime-network-id", default=RUNTIME_NETWORK_ID)
    onboarding.add_argument("--validator-address", required=True)
    onboarding.add_argument("--consensus-key-type", required=True)
    onboarding.add_argument("--consensus-public-key", required=True)
    onboarding.add_argument("--local-height", type=int, required=True)
    onboarding.add_argument("--public-head-height", type=int, required=True)
    onboarding.add_argument("--p2p-port", type=int, default=ONBOARDING_REQUIRED_PORTS["p2p"])
    onboarding.add_argument("--qrpc-port", type=int, default=ONBOARDING_REQUIRED_PORTS["qrpc"])
    onboarding.add_argument("--ws-port", type=int, default=ONBOARDING_REQUIRED_PORTS["ws"])
    onboarding.add_argument("--discovery-port", type=int, default=ONBOARDING_REQUIRED_PORTS["discovery"])
    onboarding.add_argument("--metrics-port", type=int, default=ONBOARDING_REQUIRED_PORTS["metrics"])
    onboarding.add_argument("--signing-challenge-verified", action="store_true")
    onboarding.add_argument("--seed-registration-verified", action="store_true")
    onboarding.add_argument("--relayer-peer-visibility-verified", action="store_true")
    onboarding.add_argument("--support-node-replay-preflight-verified", action="store_true")
    onboarding.add_argument("--funding-verified", action="store_true")
    onboarding.add_argument("--bonded-stake-verified", action="store_true")
    onboarding.add_argument("--source-majority-proof-verified", action="store_true")
    onboarding.add_argument("--shadow-duty-gate-verified", action="store_true")
    onboarding.set_defaults(func=command_onboarding_dry_run)

    preflight = sub.add_parser("preflight")
    preflight.add_argument("--genesis", required=True)
    preflight.add_argument("--network-identifiers", required=True)
    preflight.add_argument("--validator-address")
    preflight.add_argument("--operator-address")
    preflight.add_argument("--reward-address")
    preflight.add_argument("--self-stake-nwei")
    preflight.add_argument("--peer-id")
    preflight.add_argument("--key-dir")
    preflight.add_argument("--listen-address")
    preflight.add_argument("--advertise-address")
    preflight.add_argument("--required-port", action="append")
    preflight.add_argument("--signing-challenge-verified", action="store_true")
    preflight.set_defaults(func=command_preflight)
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
