#!/usr/bin/env python3
"""Review pinned public inputs before Portal's native formation workflow."""
import argparse
import hashlib
import json
from pathlib import Path
import re


HOSTS = {"val1", "val2", "val3", "val4", "val6"}
NON_REPLACEMENT_NETWORKS = {"synergy-testnet-v3", "synergy-posy-canary-20261117"}
HEX = re.compile(r"[0-9a-f]{64}")
U128_MAX = 2**128 - 1
TREASURY_NWEI = 5_000_000_000_000_000
PURPOSES = {"treasury", "authorized_funding", "validator", "other_approved"}


def unique_fields(pairs):
    result = {}
    for name, value in pairs:
        if name in result:
            raise ValueError(f"duplicate JSON field {name}")
        result[name] = value
    return result


def read_json(path, limit, expected=None):
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"{path.name} must be a regular public input")
    with path.open("rb") as stream:
        raw = stream.read(limit + 1)
    if len(raw) > limit:
        raise ValueError(f"{path.name} exceeds its byte limit")
    if expected is not None and hashlib.sha256(raw).hexdigest() != expected:
        raise ValueError(f"{path.name} does not match the reviewed SHA-256")
    return json.loads(raw, object_pairs_hook=unique_fields)


def review_allocations(recipe, approved):
    accounts = recipe["authority"]["protected"]["initial_world_state"]["accounts"]
    if not isinstance(accounts, dict) or not isinstance(approved, dict):
        raise ValueError("explicit approved allocation map required")
    allocations = {}
    for address, account in accounts.items():
        balance = account["balance_nwei"]
        if (type(balance) is not int or not 0 <= balance <= U128_MAX
                or type(account["nonce"]) is not int or account["nonce"] != 0):
            raise ValueError("initial accounts require an exact balance and zero nonce")
        allocations[address] = balance
    treasury = recipe.get("canary_testing_treasury")
    if treasury is not None:
        address = treasury["address"]
        if address in allocations or approved.get(address, {}).get("purpose") != "treasury":
            raise ValueError("native treasury allocation requires a distinct approved treasury")
        allocations[address] = TREASURY_NWEI
    if set(allocations) != set(approved):
        raise ValueError("initial accounts differ from the approved allocation map")
    for address, balance in allocations.items():
        entry = approved[address]
        if (not isinstance(entry, dict) or set(entry) != {"purpose", "balance_nwei"}
                or entry["purpose"] not in PURPOSES or entry["balance_nwei"] != str(balance)):
            raise ValueError("initial balance or purpose differs from the approved allocations")
    return str(sum(allocations.values()))


def exact_public_key(encoded, size):
    if not isinstance(encoded, str) or len(encoded) != 2 * size or not re.fullmatch("[a-f0-9]+", encoded):
        raise ValueError("registration has an invalid public-key encoding")
    return bytes.fromhex(encoded)


def review_signers(authority, identities, height):
    roster = authority["validators"]
    proposed = [entry["record"]["validator_id"] for entry in roster]
    if len(proposed) != len(identities) or set(proposed) != set(identities):
        raise ValueError("authority roster differs from the five pinned registrations")
    ingress = authority["protected"]["ingress_kem_registry"]["records"]
    active_ingress = {}
    for entry in ingress:
        if entry["activation_height"] <= height and (
                entry["retirement_height"] is None or entry["retirement_height"] > height):
            address = entry["validator_id"]
            if address in active_ingress:
                raise ValueError("duplicate active Genesis ingress key")
            active_ingress[address] = entry["public_key"]
    if set(active_ingress) != set(identities):
        raise ValueError("active Genesis ingress roster differs from the registrations")
    weights = {}
    for entry in roster:
        record = entry["record"]
        address = record["validator_id"]
        consensus_key, ingress_key = identities[address]
        member_ingress = active_ingress[address]
        weight = record["frozen_voting_weight"]
        if (record["status"] != "active" or type(weight) is not int or not 0 < weight <= U128_MAX
                or entry["algorithm"] != "ml_dsa65" or list(consensus_key) != entry["public_key"]
                or member_ingress["algorithm"] != "ML-KEM-1024"
                or list(ingress_key) != member_ingress["public_key"]
                or any(type(byte) is not int for key in (entry["public_key"], member_ingress["public_key"]) for byte in key)):
            raise ValueError("authority signer, frozen weight or ingress key differs from formation")
        weights[address] = weight
    total = sum(weights.values())
    minimum_weight = 2 * total // 3 + 1
    if 2 * total > U128_MAX or 3 * minimum_weight > U128_MAX:
        raise ValueError("frozen voting weight would overflow native quorum arithmetic")
    return {"validator_count": len(weights), "minimum_distinct_signers": 2 * len(weights) // 3 + 1,
            "total_frozen_voting_weight": str(total), "minimum_signed_weight": str(minimum_weight),
            "weights_by_validator": {address: str(weight) for address, weight in weights.items()}}


def review(directory, approval):
    required = {"chain_id", "network_id", "formation_sha256", "recipe_sha256", "registrations", "allocations"}
    if set(approval) != required:
        raise ValueError("exact independent formation expectations required")
    chain = approval["chain_id"]
    network = approval["network_id"]
    registrations = approval["registrations"]
    if (type(chain) is not int or not 0 < chain < 2**64
            or not isinstance(network, str) or not re.fullmatch("[a-z0-9][a-z0-9_-]{1,127}", network)
            or network in NON_REPLACEMENT_NETWORKS or chain == 99999
            or not isinstance(registrations, dict) or set(registrations) != HOSTS):
        raise ValueError("fresh network and exact replacement host roster required")
    for pin in (approval["formation_sha256"], approval["recipe_sha256"], *registrations.values()):
        if not isinstance(pin, str) or not HEX.fullmatch(pin) or pin == "0" * 64:
            raise ValueError("nonzero lowercase SHA-256 pins required")

    context = read_json(directory / "formation.json", 16 * 1024, approval["formation_sha256"])
    if (set(context) != {"chain_id_hex", "network_id", "formation_id"}
            or context["chain_id_hex"] != f"{chain:064x}" or context["network_id"] != network
            or not HEX.fullmatch(context["formation_id"]) or context["formation_id"] == "0" * 64):
        raise ValueError("formation context differs from the replacement scope")
    recipe = read_json(directory / "recipe.json", 1024 * 1024, approval["recipe_sha256"])
    authority = recipe["authority"]
    declared = recipe["network"]
    protected = authority["protected"]
    if (any(item["chain_id"] != chain or item["network_id"] != network
            for item in (authority, declared))
            or declared["protocol_version"] != "posy/3.0"
            or declared.get("autonomous_epoch_protocol") != "posy-autonomous-epochs-v1"
            or recipe.get("genesis_format_version", 2) != 2
            or [authority[key] for key in ("epoch", "epoch_start_height", "epoch_end_height")] != [1, 1, 1000]
            or authority["anchor_parent"] != {
                "kind": "genesis", "reference": {"genesis_hash": "", "block_id": "", "reference_id": ""}
            }
            or recipe["seed_source"] != {"kind": "genesis_hash"}
            or recipe["validators"] != [] or recipe.get("formation_registrations", []) != []
            or protected["version"] != 2 or protected["cutoff_relationship"] != "processing_groups_v1"
            or protected["assigned_cluster_id"] != 0
            or protected["cluster_schedule_version"] not in ("", "single-cluster-processing-groups-v1")
            or type(declared["activation_unix"]) is not int or declared["activation_unix"] <= 0
            or protected["epoch_start_timestamp_ms"] != 1000 * declared["activation_unix"]):
        raise ValueError("recipe differs from fresh PoSy Genesis, epoch or asynchronous ETDAG scope")
    addresses = {}
    identities = {}
    for host, pin in sorted(registrations.items()):
        payload = read_json(directory / f"{host}.json", 128 * 1024, pin)["payload"]
        address = payload["identity"]["address"]
        if (payload["schema_version"] != "apqe-validator-formation-registration-v1"
                or payload["formation"] != context
                or not isinstance(address, str) or not address.startswith("synv1")
                or address in addresses.values()):
            raise ValueError(f"{host} registration differs from the reviewed formation")
        consensus = exact_public_key(payload["identity"]["consensus_key"]["public_key"], 1952)
        ingress = exact_public_key(payload["ingress_key"]["public_key"], 1568)
        if any(consensus == c or ingress == k for c, k in identities.values()):
            raise ValueError("validator registrations reuse a consensus or ingress public key")
        identities[address] = (consensus, ingress)
        addresses[host] = address
    quorum = review_signers(authority, identities, 1)
    allocation_total = review_allocations(recipe, approval["allocations"])
    return {"chain_id": chain, "network_id": network, "formation_id": context["formation_id"],
            "formation_sha256": approval["formation_sha256"], "recipe_sha256": approval["recipe_sha256"],
            "registration_sha256_by_host": registrations, "validators_by_host": addresses,
            "initial_quorum": quorum, "initial_allocation_total_nwei": allocation_total,
            "native_signature_verification_required": True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path, help="directory containing the pinned public inputs")
    parser.add_argument("expectations", type=Path, help="independently reviewed network, recipe and host pins")
    args = parser.parse_args()
    try:
        result = review(args.directory, read_json(args.expectations, 16 * 1024))
    except (KeyError, TypeError, ValueError, OSError) as error:
        parser.exit(1, f"Formation input review failed: {error}\n")
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
