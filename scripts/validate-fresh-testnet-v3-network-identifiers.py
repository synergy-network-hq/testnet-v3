#!/usr/bin/env python3
"""Fail closed on the public fresh-P3 network-identifier input boundary."""

from __future__ import annotations

import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
IDENTIFIERS_PATH = ROOT / "network-identifiers.testnet-v3.identity-assigned.json"
FRESH_GENESIS_PATH = (
    ROOT / "launch" / "posy-v3-genesis-inputs" / "fresh-p3-genesis-predeployment-public-input.json"
)
CHAIN_ID = 1266
TECHNICAL_NETWORK_ID = "testnet"
RELEASE_ID = "testnet-v3"
PROTOCOL_VERSION = "posy/3.0"
FRESH_P3_CHAIN_INCARNATION = 5
FRESH_P3_CONSENSUS_STATE_SCHEMA_VERSION = 5
NATIVE_ASSET_NAME = "Synergy Testnet Coin"
BURN_ADDRESS = "syn00000000000000000000000000000000000000"

CANONICAL_NETWORK_IDENTITY = {
    "canonical_caip2": {
        "namespace": "synergy",
        "reference": "testnet",
        "status": "active_internal",
        "value": "synergy:testnet",
    },
    "eip155": {
        "activation_condition": "Activate only when EVM/EIP-155 compatibility is implemented and publicly supported.",
        "namespace": "eip155",
        "reference": "1266",
        "status": "reserved",
        "value": "eip155:1266",
    },
    "network_uuid": {
        "consensus_critical": False,
        "derivation": "uuidv5(uuidv5(NAMESPACE_DNS, 'synergy-network.io'), 'synergy:testnet')",
        "format": "uuid",
        "immutable": True,
        "value": "c6ad8633-38c8-5c24-823e-3ffe80793c85",
    },
}

SYSTEM_RESERVED_ADDRESSES = {
    "burn_address": {
        "address": BURN_ADDRESS,
        "purpose": "Canonical irreversible token destruction address.",
        "receive_policy": "accept_burn_only",
        "spend_policy": "impossible",
        "status": "active",
        "type": "BurnAddress",
    },
    "named_addresses": {
        "address_prefix_registry": "syn00000000000000000000000000000000000101",
        "asset_registry": "syn00000000000000000000000000000000000102",
        "governance_registry": "syn00000000000000000000000000000000000106",
        "protocol_registry": "syn00000000000000000000000000000000000100",
        "sxcp_registry": "syn00000000000000000000000000000000000105",
        "synid_registry": "syn00000000000000000000000000000000000103",
        "uma_registry": "syn00000000000000000000000000000000000104",
        "validator_registry": "syn00000000000000000000000000000000000107",
    },
    "policy": {
        "address_length": 41,
        "contract_deployable": False,
        "derivable": False,
        "governance_rule": "Any addition, removal, activation, or semantic reassignment requires DAO approval and SNTS amendment.",
        "requires_consensus_reservation": True,
        "requires_explorer_label": True,
        "requires_indexer_classification": True,
        "requires_wallet_warning": True,
        "spendable": False,
        "status": "canonical_proposed",
        "user_assignable": False,
    },
    "reserved_ranges": [
        {
            "default_policy": "reject_unless_explicitly_allowlisted",
            "end": "syn000000000000000000000000000000000000ff",
            "name": "system_null_burn_sentinel_range",
            "start": BURN_ADDRESS,
        },
        {
            "default_policy": "reserved_for_protocol_registries",
            "end": "syn000000000000000000000000000000000001ff",
            "name": "protocol_registry_range",
            "start": "syn00000000000000000000000000000000000100",
        },
        {
            "default_policy": "reserved_for_synthetic_protocol_origins",
            "end": "syn000000000000000000000000000000000002ff",
            "name": "protocol_sentinel_range",
            "start": "syn00000000000000000000000000000000000200",
        },
        {
            "default_policy": "reserved_for_emergency_governance_aliases",
            "end": "syn000000000000000000000000000000000003ff",
            "name": "emergency_governance_range",
            "start": "syn00000000000000000000000000000000000300",
        },
        {
            "default_policy": "reserved_for_migration_and_quarantine",
            "end": "syn000000000000000000000000000000000004ff",
            "name": "migration_sink_range",
            "start": "syn00000000000000000000000000000000000400",
        },
    ],
}


def read_object(path: Path) -> dict:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path.relative_to(ROOT)} must contain a JSON object")
    return value


def require_equal(actual: object, expected: object, label: str) -> None:
    if actual != expected:
        raise ValueError(f"{label}: expected {expected!r}, found {actual!r}")


def main() -> int:
    identifiers = read_object(IDENTIFIERS_PATH)
    fresh_genesis = read_object(FRESH_GENESIS_PATH)

    network = identifiers.get("network")
    if not isinstance(network, dict):
        raise ValueError("identifiers network is missing")
    for key, expected in {
        "environment": TECHNICAL_NETWORK_ID,
        "network_slug": TECHNICAL_NETWORK_ID,
        "technical_identifier": TECHNICAL_NETWORK_ID,
        "release_id": RELEASE_ID,
        "protocol_version": PROTOCOL_VERSION,
    }.items():
        require_equal(network.get(key), expected, f"identifiers network.{key}")

    chain = identifiers.get("chain_identifiers")
    if not isinstance(chain, dict):
        raise ValueError("identifiers chain_identifiers is missing")
    require_equal(chain.get("synergy_native", {}).get("decimal"), CHAIN_ID,
                  "identifiers chain_identifiers.synergy_native.decimal")
    caip2 = chain.get("caip2_identifiers", {})
    require_equal(caip2.get("canonical_native", {}).get("value"), "synergy:testnet",
                  "identifiers canonical CAIP-2 value")
    require_equal(caip2.get("eip155", {}).get("value"), "eip155:1266",
                  "identifiers EIP-155 value")

    require_equal(identifiers.get("addressing", {}).get("burn_address"), BURN_ADDRESS,
                  "identifiers addressing.burn_address")
    require_equal(identifiers.get("system_reserved_addresses"), SYSTEM_RESERVED_ADDRESSES,
                  "identifiers system_reserved_addresses")
    require_equal(fresh_genesis.get("system_reserved_addresses"), SYSTEM_RESERVED_ADDRESSES,
                  "fresh Genesis system_reserved_addresses")
    require_equal(fresh_genesis.get("network_identity"), CANONICAL_NETWORK_IDENTITY,
                  "fresh Genesis network_identity")
    if "network_identity" not in fresh_genesis.get("canonicalization", {}).get(
        "genesis_hash_inputs", []
    ):
        raise ValueError("fresh Genesis canonical hash inputs omit network_identity")

    require_equal(identifiers.get("native_currency", {}).get("name"), NATIVE_ASSET_NAME,
                  "identifiers native_currency.name")
    wallet = identifiers.get("wallet_metadata", {}).get("wallet_add_network_payload", {})
    require_equal(wallet.get("chainId"), "0x4f2", "wallet chain ID")
    require_equal(wallet.get("nativeCurrency", {}).get("name"), NATIVE_ASSET_NAME,
                  "wallet native currency name")
    require_equal(fresh_genesis.get("token", {}).get("name"), NATIVE_ASSET_NAME,
                  "fresh Genesis token.name")

    genesis_network = fresh_genesis.get("network", {})
    for key, expected in {
        "chain_id": CHAIN_ID,
        "chain_incarnation": FRESH_P3_CHAIN_INCARNATION,
        "network_id": TECHNICAL_NETWORK_ID,
        "release_id": RELEASE_ID,
        "consensus_version": PROTOCOL_VERSION,
    }.items():
        require_equal(genesis_network.get(key), expected, f"fresh Genesis network.{key}")

    consensus = fresh_genesis.get("consensus")
    if not isinstance(consensus, dict):
        raise ValueError("fresh Genesis consensus is missing")
    require_equal(
        consensus.get("state_directory_namespace"),
        f"chain-{CHAIN_ID}/incarnation-{FRESH_P3_CHAIN_INCARNATION}",
        "fresh Genesis consensus.state_directory_namespace",
    )
    require_equal(
        consensus.get("state_schema_version"),
        FRESH_P3_CONSENSUS_STATE_SCHEMA_VERSION,
        "fresh Genesis consensus.state_schema_version",
    )

    print("fresh Testnet-v3 network-identifier integrity: PASS")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(f"fresh Testnet-v3 network-identifier integrity: FAIL: {error}", file=sys.stderr)
        raise SystemExit(1)
