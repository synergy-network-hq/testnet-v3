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

# The real-host qualification deliberately co-locates support roles with
# validators on hosts 4--6.  A production config can reuse loopback ports
# because these roles normally reside on separate machines; a private run may
# not.  Every configured listener therefore has an explicit host-aware,
# deterministic allocation.  The frozen RC6 runtime accepts authenticated
# validator VPN transports only on the canonical validator P2P port, so the
# six validators retain that port; they run on separate hosts and cannot
# collide with one another.  All other qualification listeners use the
# dedicated range below.
VALIDATOR_P2P_PORT = 5622
QUALIFICATION_PORT_BASE = 22000
QUALIFICATION_PORT_LIMIT = 29999
QUALIFICATION_HOST_STRIDE = 1000
QUALIFICATION_ROLE_STRIDE = 10
QUALIFICATION_CONFIGURATION_ID = "ring2-config-r7"

HOST_ROLES = {
    "synergy-val1": ("validator-node-01",),
    "synergy-val2": ("validator-node-02",),
    "synergy-val3": ("validator-node-03",),
    "synergy-val4": ("validator-node-04", "relay1"),
    "synergy-val5": ("validator-node-05", "relay2", "rpc-gateway"),
    "synergy-val6": ("validator-node-06", "relay3", "explorer-indexer", "observer"),
}
ROLE_HOST = {
    role: host for host, roles in HOST_ROLES.items() for role in roles
}
ROLE_SLOT = {
    role: slot for roles in HOST_ROLES.values() for slot, role in enumerate(roles)
}
HOST_SLOT = {host: slot for slot, host in enumerate(HOST_ROLES)}


def socket_ports(node_id: str) -> dict[str, int]:
    """Return the reproducible port allocation for one private role."""
    host = ROLE_HOST[node_id]
    base = (
        QUALIFICATION_PORT_BASE
        + (HOST_SLOT[host] * QUALIFICATION_HOST_STRIDE)
        + (ROLE_SLOT[node_id] * QUALIFICATION_ROLE_STRIDE)
    )
    return {
        "http_rpc": base,
        "websocket_rpc": base + 1,
        "grpc": base + 2,
        "metrics": base + 3,
        "p2p_tcp": VALIDATOR_P2P_PORT if node_id.startswith("validator-node-") else base + 4,
        "discovery_tcp": base + 5,
    }


def socket_manifest(run_id=None) -> dict:
    """Build the exact socket inventory used by every private role."""
    hosts: dict[str, list[dict]] = {}
    for host, roles in HOST_ROLES.items():
        entries: list[dict] = []
        for role in roles:
            ports = socket_ports(role)
            entries.extend(
                [
                    {"role": role, "purpose": "http_rpc", "protocol": "tcp", "bind": "127.0.0.1", "port": ports["http_rpc"], "required": True},
                    {"role": role, "purpose": "websocket_rpc", "protocol": "tcp", "bind": "127.0.0.1", "port": ports["websocket_rpc"], "required": True},
                    {"role": role, "purpose": "grpc", "protocol": "tcp", "bind": "127.0.0.1", "port": ports["grpc"], "required": False},
                    {"role": role, "purpose": "metrics", "protocol": "tcp", "bind": NODE_IPS[role], "port": ports["metrics"], "required": True},
                    {"role": role, "purpose": "p2p_tcp", "protocol": "tcp", "bind": NODE_IPS[role], "port": ports["p2p_tcp"], "required": True},
                    {"role": role, "purpose": "discovery_tcp", "protocol": "tcp", "bind": NODE_IPS[role], "port": ports["discovery_tcp"], "required": False},
                ]
            )
        hosts[host] = entries
    return {
        "schema_version": 1,
        "qualification_configuration": QUALIFICATION_CONFIGURATION_ID,
        "run_id": run_id,
        "port_policy": {
            "range_start": QUALIFICATION_PORT_BASE,
            "range_end": QUALIFICATION_PORT_LIMIT,
            "validator_p2p_port": VALIDATOR_P2P_PORT,
            "host_stride": QUALIFICATION_HOST_STRIDE,
            "role_stride": QUALIFICATION_ROLE_STRIDE,
            "wildcard_binds_overlap": ["0.0.0.0", "::", "[::]"],
        },
        "hosts": hosts,
        "not_configured_as_listeners": [
            "administrative_api",
            "health_readiness_api",
            "debug_profiling",
            "ipc_tcp_bridge",
            "embedded_database",
            "p2p_udp_or_quic",
        ],
        "disabled_configuration_fields": {
            "grpc": "no gRPC listener implementation exists in this runtime",
            "discovery_tcp": "private qualification uses explicit P2P peers; this runtime has no discovery listener implementation",
        },
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
    if node_id not in ROLE_HOST:
        raise SystemExit(f"{source}: no private host assignment for {node_id}")
    ports = socket_ports(node_id)
    if not re.search(r"^p2p_port = [0-9]+$", text, flags=re.MULTILINE):
        raise SystemExit(f"{source}: missing P2P port")
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
        for address in (
            f"{NODE_IPS['relay1']}:{socket_ports('relay1')['p2p_tcp']}",
            f"{NODE_IPS['relay2']}:{socket_ports('relay2')['p2p_tcp']}",
            f"{NODE_IPS['relay3']}:{socket_ports('relay3')['p2p_tcp']}",
        )
        if address != f"{node_ip}:{ports['p2p_tcp']}"
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
        r"^p2p_port = [0-9]+$",
        f"p2p_port = {ports['p2p_tcp']}",
        text,
        flags=re.MULTILINE,
    )
    text = re.sub(
        r'^listen_address = ".*"$',
        f'listen_address = "{node_ip}:{ports["p2p_tcp"]}"',
        text,
        count=1,
        flags=re.MULTILINE,
    )
    text = re.sub(
        r'^public_address = ".*"$',
        f'public_address = "{node_ip}:{ports["p2p_tcp"]}"',
        text,
        count=1,
        flags=re.MULTILINE,
    )
    text = re.sub(
        r"^discovery_port = [0-9]+$",
        f"discovery_port = {ports['discovery_tcp']}",
        text,
        flags=re.MULTILINE,
    )
    text = re.sub(
        r'^discovery_listen_address = ".*"$',
        f'discovery_listen_address = "{node_ip}:{ports["discovery_tcp"]}"',
        text,
        count=1,
        flags=re.MULTILINE,
    )
    text = re.sub(
        r'^discovery_public_address = ".*"$',
        f'discovery_public_address = "{node_ip}:{ports["p2p_tcp"]}"',
        text,
        count=1,
        flags=re.MULTILINE,
    )
    text = re.sub(r"^enable_discovery = (?:true|false)$", "enable_discovery = false", text, flags=re.MULTILINE)
    text = re.sub(r"^enable_peer_exchange = (?:true|false)$", "enable_peer_exchange = false", text, flags=re.MULTILINE)
    text = re.sub(
        r'^genesis_deploy_path = ".*"$',
        'genesis_deploy_path = "genesis.json"',
        text,
        flags=re.MULTILINE,
    )
    for validator_index, validator_address in enumerate(VALIDATOR_ADDRESSES, start=1):
        validator_role = f"validator-node-0{validator_index}"
        validator_transport = f"{NODE_IPS[validator_role]}:{socket_ports(validator_role)['p2p_tcp']}"
        text = re.sub(
            rf'(validator_address = "{re.escape(validator_address)}"\ndial_address = ")[^"]+(")',
            rf'\g<1>{validator_transport}\g<2>',
            text,
        )
    text = re.sub(r"^rpc_port = [0-9]+$", f"rpc_port = {ports['http_rpc']}", text, flags=re.MULTILINE)
    text = re.sub(r"^ws_port = [0-9]+$", f"ws_port = {ports['websocket_rpc']}", text, flags=re.MULTILINE)
    text = re.sub(
        r'^bind_address = ".*"$',
        f'bind_address = "127.0.0.1:{ports["http_rpc"]}"',
        text,
        count=1,
        flags=re.MULTILINE,
    )
    text = re.sub(r"^http_port = [0-9]+$", f"http_port = {ports['http_rpc']}", text, flags=re.MULTILINE)
    text = re.sub(r"^ws_port = [0-9]+$", f"ws_port = {ports['websocket_rpc']}", text, flags=re.MULTILINE)
    text = re.sub(r"^grpc_port = [0-9]+$", f"grpc_port = {ports['grpc']}", text, flags=re.MULTILINE)
    text = re.sub(r"^enable_grpc = true$", "enable_grpc = false", text, flags=re.MULTILINE)
    text = re.sub(
        r'^metrics_bind = ".*"$',
        f'metrics_bind = "{node_ip}:{ports["metrics"]}"',
        text,
        count=1,
        flags=re.MULTILINE,
    )
    if "synergynode.xyz" in text or re.search(
        r"\b(?:10\.70\.|65\.21\.202\.144|73\.79\.66\.255|209\.145\.50\.9|74\.208\.227\.23)\b",
        text,
    ):
        raise SystemExit(f"{source}: public-network target survived Ring-2 rendering")
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text)


def config_value(text: str, section: str, key: str) -> str:
    """Read one scalar field from a generated TOML section without a dependency."""
    active = False
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if line.startswith("[") and line.endswith("]"):
            active = line == f"[{section}]"
            continue
        if active and line.startswith(f"{key} = "):
            return line.split("=", 1)[1].strip().strip('"')
    raise SystemExit(f"generated configuration lacks [{section}].{key}")


def split_socket(value: str) -> tuple[str, int]:
    host, separator, raw_port = value.rpartition(":")
    if not separator or not host or not raw_port.isdecimal():
        raise SystemExit(f"invalid configured socket address: {value}")
    return host, int(raw_port)


def configured_listeners(path: pathlib.Path) -> tuple[str, dict[str, tuple[str, int]], dict[str, bool]]:
    text = path.read_text()
    node_id = config_value(text, "identity", "node_id")
    rpc_bind, rpc_bind_port = split_socket(config_value(text, "rpc", "bind_address"))
    http_port = int(config_value(text, "rpc", "http_port"))
    ws_port = int(config_value(text, "rpc", "ws_port"))
    grpc_port = int(config_value(text, "rpc", "grpc_port"))
    p2p_bind, p2p_port = split_socket(config_value(text, "p2p", "listen_address"))
    discovery_bind, discovery_port = split_socket(config_value(text, "p2p", "discovery_listen_address"))
    metrics_bind, metrics_port = split_socket(config_value(text, "telemetry", "metrics_bind"))
    if int(config_value(text, "network", "rpc_port")) != http_port:
        raise SystemExit(f"{path}: network RPC port disagrees with RPC listener")
    if int(config_value(text, "network", "ws_port")) != ws_port:
        raise SystemExit(f"{path}: network WebSocket port disagrees with RPC listener")
    if int(config_value(text, "network", "p2p_port")) != p2p_port:
        raise SystemExit(f"{path}: network P2P port disagrees with P2P listener")
    if rpc_bind_port != http_port:
        raise SystemExit(f"{path}: RPC bind address disagrees with HTTP port")
    return (
        node_id,
        {
            "http_rpc": (rpc_bind, http_port),
            "websocket_rpc": (rpc_bind, ws_port),
            "grpc": (rpc_bind, grpc_port),
            "metrics": (metrics_bind, metrics_port),
            "p2p_tcp": (p2p_bind, p2p_port),
            "discovery_tcp": (discovery_bind, discovery_port),
        },
        {
            "discovery_tcp": config_value(text, "p2p", "enable_discovery") == "true",
            "grpc": config_value(text, "rpc", "enable_grpc") == "true",
        },
    )


def binds_overlap(left: str, right: str) -> bool:
    wildcard = {"0.0.0.0", "::", "[::]"}
    return left == right or left in wildcard or right in wildcard


def socket_port_follows_policy(role: str, purpose: str, port: int) -> bool:
    if role.startswith("validator-node-") and purpose == "p2p_tcp":
        return port == VALIDATOR_P2P_PORT
    return QUALIFICATION_PORT_BASE <= port <= QUALIFICATION_PORT_LIMIT


def validate_socket_manifest(manifest: dict, configs: dict[str, pathlib.Path]) -> None:
    if manifest["qualification_configuration"] != QUALIFICATION_CONFIGURATION_ID:
        raise SystemExit("unexpected private qualification socket manifest identity")
    if set(manifest["hosts"]) != set(HOST_ROLES):
        raise SystemExit("private qualification socket manifest has an unexpected host set")
    claimed: list[tuple[str, str, str, int, str]] = []
    entries_by_role: dict[str, dict[str, dict]] = {}
    for host, entries in manifest["hosts"].items():
        for entry in entries:
            role = entry.get("role")
            purpose = entry.get("purpose")
            protocol = entry.get("protocol")
            bind = entry.get("bind")
            port = entry.get("port")
            required = entry.get("required")
            if role not in HOST_ROLES[host] or purpose not in socket_ports(role):
                raise SystemExit(f"socket manifest has an invalid role or endpoint on {host}")
            if protocol != "tcp" or not isinstance(bind, str) or not isinstance(port, int):
                raise SystemExit(f"socket manifest has an invalid socket assignment for {role}/{purpose}")
            if not isinstance(required, bool) or not socket_port_follows_policy(role, purpose, port):
                raise SystemExit(f"socket manifest has an invalid socket policy for {role}/{purpose}")
            for prior_host, prior_protocol, prior_bind, prior_port, prior_role in claimed:
                if (
                    prior_host == host
                    and prior_protocol == protocol
                    and prior_port == port
                    and binds_overlap(prior_bind, bind)
                ):
                    raise SystemExit(
                        f"socket collision on {host}: {role}/{purpose} overlaps {prior_role}"
                    )
            claimed.append((host, protocol, bind, port, f"{role}/{purpose}"))
            role_entries = entries_by_role.setdefault(role, {})
            if purpose in role_entries:
                raise SystemExit(f"socket manifest duplicates {role}/{purpose}")
            role_entries[purpose] = entry
    for role in ROLE_HOST:
        if set(entries_by_role.get(role, {})) != set(socket_ports(role)):
            raise SystemExit(f"socket manifest is missing or duplicates an endpoint for {role}")
    for role, path in configs.items():
        node_id, listeners, enabled = configured_listeners(path)
        if node_id != role:
            raise SystemExit(f"{path}: role mapping disagrees with socket manifest")
        for purpose, (bind, port) in listeners.items():
            entry = entries_by_role.get(role, {}).get(purpose)
            if entry is None or entry["protocol"] != "tcp" or entry["bind"] != bind or entry["port"] != port:
                raise SystemExit(f"{path}: {purpose} disagrees with qualification socket manifest")
            if not socket_port_follows_policy(role, purpose, port):
                raise SystemExit(f"{path}: {purpose} violates the qualification socket policy")
            if entry["required"] != enabled.get(purpose, True):
                raise SystemExit(
                    f"{path}: {purpose} activation disagrees with qualification socket manifest"
                )


def write_json(path: pathlib.Path, value: dict) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--release-dir", type=pathlib.Path)
    parser.add_argument("--genesis", type=pathlib.Path)
    parser.add_argument("--output", type=pathlib.Path)
    parser.add_argument("--run-id")
    parser.add_argument("--write-socket-manifest", type=pathlib.Path)
    args = parser.parse_args()

    if set(ROLE_HOST) != set(NODE_IPS):
        raise SystemExit("private Ring-2 host map does not cover exactly the rendered roles")
    if args.write_socket_manifest:
        write_json(args.write_socket_manifest, socket_manifest())
        return
    if not args.release_dir or not args.genesis or not args.output or not args.run_id:
        parser.error("--release-dir, --genesis, --output, and --run-id are required for rendering")
    if not re.fullmatch(r"c1266q[a-z0-9]{6,24}", args.run_id):
        raise SystemExit("invalid qualification run ID for socket manifest")

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
    rendered: list[str] = []
    configs: dict[str, pathlib.Path] = {}
    for role, root in roles.items():
        for source in sorted(root.glob("*.toml")):
            target = args.output / role / source.name
            rewrite_config(source, target, genesis, genesis_sha)
            node_id = config_value(target.read_text(), "identity", "node_id")
            configs[node_id] = target
            rendered.append(str(target.relative_to(args.output)))
    if len(rendered) != 12 or set(configs) != set(NODE_IPS):
        raise SystemExit("expected exactly twelve private Ring-2 role configurations")
    sockets = socket_manifest(args.run_id)
    validate_socket_manifest(sockets, configs)
    socket_path = args.output / "QUALIFICATION_SOCKET_MANIFEST.json"
    write_json(socket_path, sockets)
    write_json(
        args.output / "manifest.json",
        {
            "schema_version": 1,
            "network": "CHAIN1266_PRIVATE_QUALIFICATION",
            "public_network_dials": False,
            "chain_id": 1266,
            "chain_incarnation": 4,
            "genesis_hash": genesis["integrity"]["genesis_hash"],
            "genesis_sha256": genesis_sha,
            "qualification_socket_manifest_sha256": sha256(socket_path),
            "configs": {path: sha256(args.output / path) for path in rendered},
        },
    )


if __name__ == "__main__":
    main()
