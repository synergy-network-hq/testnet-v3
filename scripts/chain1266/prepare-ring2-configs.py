#!/usr/bin/env python3
"""Render isolated Ring-2 configs without permitting any public-network dial."""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import re
import shutil


HOST_MAP = {
    "relay1.synergynode.xyz": "10.126.20.1",
    "relay2.synergynode.xyz": "10.126.20.2",
    "relay3.synergynode.xyz": "10.126.20.3",
    "rpc.synergynode.xyz": "10.126.30.1",
    "atlas.synergynode.xyz": "10.126.30.2",
}

NODE_IPS = {
    "validator-node-01": "10.126.10.1",
    "validator-node-02": "10.126.10.2",
    "validator-node-03": "10.126.10.3",
    "validator-node-04": "10.126.10.4",
    "validator-node-05": "10.126.10.5",
    "validator-node-06": "10.126.10.6",
    "relay1": "10.126.20.1",
    "relay2": "10.126.20.2",
    "relay3": "10.126.20.3",
    "rpc-gateway": "10.126.30.1",
    "explorer-indexer": "10.126.30.2",
    "observer": "10.126.30.3",
}

# The source configs were rendered for the first disposable overlay.  Replace
# every role endpoint explicitly, rather than relying on hostname substitutions:
# persistent validator records retain their dial_address as an IP literal.
LEGACY_NODE_IPS = {
    "validator-node-01": "10.70.10.1",
    "validator-node-02": "10.70.10.2",
    "validator-node-03": "10.70.10.3",
    "validator-node-04": "10.70.10.4",
    "validator-node-05": "10.70.10.5",
    "validator-node-06": "10.70.10.6",
    "relay1": "10.70.20.1",
    "relay2": "10.70.20.2",
    "relay3": "10.70.20.3",
    "rpc-gateway": "10.70.30.1",
    "explorer-indexer": "10.70.30.2",
    "observer": "10.70.30.3",
}

VALIDATOR_ADDRESSES = [
    "synv11yc4cjehqjm6fp0ey4ppjptv0p3cwdy6r79t",
    "synv11k0vlmkt5gyp3czlgvlfm5yqkxu5nyvp4ekk",
    "synv11jk9pprkz7faykn4ez7hzaj2q7lg04l2fjgj",
    "synv11s7hag82s6d9f8urrv5cl40lyeamxelthpeg",
    "synv11cl92kxcx4jyzusecqydrxc8aj3hsgscrvtu",
    "synv1129lck2uvz73f59wd3yame0w04qnrdpmmmfc",
]


def sha256(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def rewrite_config(source: pathlib.Path, target: pathlib.Path, genesis: dict, genesis_sha: str) -> None:
    text = source.read_text()
    node_match = re.search(r'^node_id = "([^"]+)"$', text, flags=re.MULTILINE)
    if not node_match or node_match.group(1) not in NODE_IPS:
        raise SystemExit(f"{source}: unknown Ring-2 node identity")
    node_id = node_match.group(1)
    node_ip = NODE_IPS[node_id]
    p2p_match = re.search(r"^p2p_port = ([0-9]+)$", text, flags=re.MULTILINE)
    if not p2p_match:
        raise SystemExit(f"{source}: missing P2P port")
    p2p_port = p2p_match.group(1)
    old_hashes = set(re.findall(r'genesis_hash = "([0-9a-f]{64})"', text))
    old_shas = set(re.findall(r'genesis_file_sha256 = "([0-9a-f]{64})"', text))
    for value in old_hashes:
        text = text.replace(value, genesis["integrity"]["genesis_hash"])
    for value in old_shas:
        text = text.replace(value, genesis_sha)
    for public, private in HOST_MAP.items():
        text = text.replace(public, private)
    for role, legacy_ip in LEGACY_NODE_IPS.items():
        text = text.replace(legacy_ip, NODE_IPS[role])
    text = re.sub(r'^bootnodes = .*$', 'bootnodes = []', text, flags=re.MULTILINE)
    text = re.sub(r'^seed_servers = .*$', 'seed_servers = []', text, flags=re.MULTILINE)
    text = re.sub(
        r'^bootstrap_dns_records = .*$', 'bootstrap_dns_records = []', text, flags=re.MULTILINE
    )
    text = re.sub(
        r'^reject_private_advertise_addrs = true$',
        'reject_private_advertise_addrs = false',
        text,
        flags=re.MULTILINE,
    )
    validator_targets = [
        address
        for index, address in enumerate(VALIDATOR_ADDRESSES, start=1)
        if node_id != f"validator-node-0{index}"
    ]
    isolated_targets = validator_targets + [
        address
        for address in ("10.126.20.1:5622", "10.126.20.2:5622", "10.126.20.3:5622")
        if address != f"{node_ip}:5622"
    ]
    encoded_targets = json.dumps(isolated_targets, separators=(", ", ": "))
    text = re.sub(
        r"^persistent_peers = .*$",
        f"persistent_peers = {encoded_targets}",
        text,
        flags=re.MULTILINE,
    )
    text = re.sub(
        r"^additional_dial_targets = .*$",
        f"additional_dial_targets = {encoded_targets}",
        text,
        flags=re.MULTILINE,
    )
    text = re.sub(
        r'^listen_address = ".*"$',
        f'listen_address = "{node_ip}:{p2p_port}"',
        text,
        count=1,
        flags=re.MULTILINE,
    )
    text = re.sub(
        r'^public_address = ".*"$',
        f'public_address = "{node_ip}:{p2p_port}"',
        text,
        count=1,
        flags=re.MULTILINE,
    )
    text = re.sub(
        r'^discovery_listen_address = ".*"$',
        f'discovery_listen_address = "{node_ip}:5680"',
        text,
        count=1,
        flags=re.MULTILINE,
    )
    text = re.sub(
        r'^discovery_public_address = ".*"$',
        f'discovery_public_address = "{node_ip}:{p2p_port}"',
        text,
        count=1,
        flags=re.MULTILINE,
    )
    text = re.sub(
        r'^genesis_deploy_path = ".*"$',
        'genesis_deploy_path = "genesis.json"',
        text,
        flags=re.MULTILINE,
    )
    if "synergynode.xyz" in text or re.search(
        r"\b(?:10\.70\.|65\.21\.202\.144|73\.79\.66\.255|209\.145\.50\.9|74\.208\.227\.23)\b",
        text,
    ):
        raise SystemExit(f"{source}: public-network target survived Ring-2 rendering")
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--release-dir", type=pathlib.Path, required=True)
    parser.add_argument("--genesis", type=pathlib.Path, required=True)
    parser.add_argument("--output", type=pathlib.Path, required=True)
    args = parser.parse_args()

    genesis = json.loads(args.genesis.read_text())
    if genesis["network"]["chain_id"] != 1266 or genesis["network"]["chain_incarnation"] != 4:
        raise SystemExit("qualification Genesis is outside Chain 1266 incarnation 4")
    genesis_sha = sha256(args.genesis)
    if args.output.exists():
        shutil.rmtree(args.output)
    roles = {
        "validators": args.release_dir / "config" / "validators",
        "relayers": args.release_dir / "config" / "relayers",
        "rpc-gateway": args.release_dir / "config" / "rpc-gateway",
        "explorer-indexer": args.release_dir / "config" / "explorer-indexer",
        "observer": args.release_dir / "config" / "observer",
    }
    rendered = []
    for role, root in roles.items():
        for source in sorted(root.glob("*.toml")):
            target = args.output / role / source.name
            rewrite_config(source, target, genesis, genesis_sha)
            rendered.append(str(target.relative_to(args.output)))
    if len(rendered) != 12:
        raise SystemExit(f"expected 12 Ring-2 configs, rendered {len(rendered)}")
    (args.output / "manifest.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "network": "CHAIN1266_PRIVATE_QUALIFICATION",
                "public_network_dials": False,
                "chain_id": 1266,
                "chain_incarnation": 4,
                "genesis_hash": genesis["integrity"]["genesis_hash"],
                "genesis_sha256": genesis_sha,
                "configs": {path: sha256(args.output / path) for path in rendered},
            },
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )


if __name__ == "__main__":
    main()
