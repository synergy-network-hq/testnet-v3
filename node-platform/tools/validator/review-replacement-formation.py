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


def review(directory, approval):
    required = {"chain_id", "network_id", "formation_sha256", "recipe_sha256", "registrations"}
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
    if (any(item["chain_id"] != chain or item["network_id"] != network
            for item in (authority, declared))
            or declared["protocol_version"] != "posy/3.0"
            or [authority[key] for key in ("epoch", "epoch_start_height", "epoch_end_height")] != [1, 1, 1000]
            or authority["anchor_parent"] != {
                "kind": "genesis", "reference": {"genesis_hash": "", "block_id": "", "reference_id": ""}
            }
            or recipe["seed_source"] != {"kind": "genesis_hash"}
            or recipe["validators"] != [] or recipe.get("formation_registrations", []) != []
            or authority["protected"]["cutoff_relationship"] != "processing_groups_v1"):
        raise ValueError("recipe differs from fresh PoSy Genesis, epoch or asynchronous ETDAG scope")
    addresses = {}
    for host, pin in sorted(registrations.items()):
        payload = read_json(directory / f"{host}.json", 128 * 1024, pin)["payload"]
        address = payload["identity"]["address"]
        if (payload["schema_version"] != "apqe-validator-formation-registration-v1"
                or payload["formation"] != context
                or not isinstance(address, str) or not address.startswith("synv1")
                or address in addresses.values()):
            raise ValueError(f"{host} registration differs from the reviewed formation")
        addresses[host] = address
    proposed = [entry["record"]["validator_id"] for entry in authority["validators"]]
    if len(proposed) != len(HOSTS) or set(proposed) != set(addresses.values()):
        raise ValueError("authority roster differs from the five pinned registrations")
    return {"chain_id": chain, "network_id": network, "formation_id": context["formation_id"],
            "formation_sha256": approval["formation_sha256"], "recipe_sha256": approval["recipe_sha256"],
            "registration_sha256_by_host": registrations, "validators_by_host": addresses,
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
