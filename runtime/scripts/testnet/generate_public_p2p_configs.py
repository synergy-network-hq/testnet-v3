#!/usr/bin/env python3
from __future__ import annotations

import argparse
import datetime as dt
import ipaddress
import json
import re
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import urlparse

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover
    tomllib = None  # type: ignore[assignment]


ROOT_DIR = Path(__file__).resolve().parents[2]
DEFAULT_MANIFEST = ROOT_DIR / "config" / "testnet" / "network-topology.toml"
DEFAULT_OUTPUT_DIR = ROOT_DIR / "config" / "testnet" / "generated"
STABLE_INFRA_SUFFIX = ".synergynode.xyz"
VALIDATOR_VPN_CIDR = ipaddress.ip_network("10.70.10.0/24")
RELAYER_VPN_CIDR = ipaddress.ip_network("10.70.20.0/24")
RETIRED_VALIDATOR_VPN_CIDR = ipaddress.ip_network("10.69.0.0/16")
VALIDATOR_LOOPBACK_HOST = "127.0.0.1"
VALIDATOR_DISCOVERY_PORT = 5680


class TopologyError(ValueError):
    pass


def split_endpoint(endpoint: str) -> tuple[str, int | None]:
    if "://" in endpoint:
        parsed = urlparse(endpoint)
        return parsed.hostname or "", parsed.port
    if endpoint.startswith("[") and "]:" in endpoint:
        host, port = endpoint.rsplit("]:", 1)
        return host.removeprefix("["), int(port)
    if ":" not in endpoint:
        return endpoint, None
    host, port = endpoint.rsplit(":", 1)
    return host, int(port)


def is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def is_public_ip_literal(host: str) -> bool:
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    return not (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


def endpoint_is_public_advertisement(endpoint: str) -> bool:
    host, _port = split_endpoint(endpoint)
    host_lc = host.lower().strip()
    if host_lc in {"", "localhost", "0.0.0.0", "::1"}:
        return False
    if host_lc.endswith(".local"):
        return False
    if is_ip_literal(host_lc):
        return is_public_ip_literal(host_lc)
    return True


def endpoint_host_is_dns(endpoint: str) -> bool:
    host, _port = split_endpoint(endpoint)
    return bool(host) and not is_ip_literal(host)


def endpoint_host_is_public_ip(endpoint: str) -> bool:
    host, _port = split_endpoint(endpoint)
    return is_public_ip_literal(host)


def assert_public_endpoints(label: str, endpoints: list[str]) -> None:
    for endpoint in endpoints:
        if not endpoint_is_public_advertisement(endpoint):
            raise TopologyError(f"{label} contains non-public advertised endpoint: {endpoint}")
        if "10.69." in endpoint:
            raise TopologyError(f"{label} contains forbidden VPN endpoint: {endpoint}")


def parse_toml_subset(text: str) -> dict[str, Any]:
    data: dict[str, Any] = {}
    current: dict[str, Any] = data
    pending_key: str | None = None
    pending_lines: list[str] = []

    def set_section(section_name: str) -> None:
        nonlocal current
        cursor = data
        for part in section_name.split("."):
            cursor = cursor.setdefault(part, {})
        current = cursor

    def set_array_section(section_name: str) -> None:
        nonlocal current
        cursor = data
        parts = section_name.split(".")
        for part in parts[:-1]:
            cursor = cursor.setdefault(part, {})
        item: dict[str, Any] = {}
        cursor.setdefault(parts[-1], []).append(item)
        current = item

    def assign(key: str, raw_value: str) -> None:
        current[key] = parse_toml_value(raw_value)

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if pending_key is not None:
            pending_lines.append(line)
            if line.endswith("]"):
                assign(pending_key, "\n".join(pending_lines))
                pending_key = None
                pending_lines = []
            continue
        if line.startswith("[[") and line.endswith("]]"):
            set_array_section(line[2:-2].strip())
            continue
        if line.startswith("[") and line.endswith("]"):
            set_section(line[1:-1].strip())
            continue
        if "=" not in line:
            raise TopologyError(f"unsupported TOML line: {raw_line}")
        key, raw_value = line.split("=", 1)
        key = key.strip()
        raw_value = raw_value.strip()
        if raw_value.startswith("[") and not raw_value.endswith("]"):
            pending_key = key
            pending_lines = [raw_value]
            continue
        assign(key, raw_value)

    if pending_key is not None:
        raise TopologyError(f"unterminated TOML array for {pending_key}")
    return data


def parse_toml_value(raw_value: str) -> Any:
    raw_value = raw_value.strip()
    if raw_value.startswith('"') and raw_value.endswith('"'):
        return json.loads(raw_value)
    if raw_value == "true":
        return True
    if raw_value == "false":
        return False
    if raw_value.startswith("[") and raw_value.endswith("]"):
        if raw_value == "[]":
            return []
        return [json.loads(item) for item in re.findall(r'"(?:\\.|[^"\\])*"', raw_value)]
    try:
        return int(raw_value)
    except ValueError:
        raise TopologyError(f"unsupported TOML value: {raw_value}") from None


def load_topology(path: Path = DEFAULT_MANIFEST) -> dict[str, Any]:
    if tomllib is not None:
        with path.open("rb") as handle:
            topology = tomllib.load(handle)
    else:
        topology = parse_toml_subset(path.read_text(encoding="utf-8"))
    validate_topology(topology)
    return topology


def validate_topology(topology: dict[str, Any]) -> None:
    if topology.get("schema_version") != 1:
        raise TopologyError("network-topology.toml schema_version must be 1")
    network = topology["network"]
    if network["environment_id"] != "testnet":
        raise TopologyError("environment_id must be testnet")
    if network.get("release_id") != "testnet-v3":
        raise TopologyError("release_id must be testnet-v3")
    if network.get("runtime_network_id") != "synergy-testnet-v3":
        raise TopologyError("runtime_network_id must be synergy-testnet-v3")
    if network["network_id"] != 1264 or network["chain_id"] != 1264:
        raise TopologyError("Testnet-v3 must preserve canonical chain and numeric network ID 1264")
    if network["rpc_gateway_p2p_endpoint"] == network["public_rpc_host"]:
        raise TopologyError("RPC Gateway P2P endpoint must not equal the public JSON-RPC host")
    if network["rpc_gateway_p2p_endpoint"] != "rpc.synergynode.xyz:5623":
        raise TopologyError("RPC Gateway P2P endpoint must be rpc.synergynode.xyz:5623")
    if network["public_rpc_endpoint"] != "https://testnet-core-rpc.synergy-network.io":
        raise TopologyError("public RPC endpoint must remain testnet-core-rpc.synergy-network.io")

    common = topology["common"]
    if topology["policies"].get("validator_endpoint_policy") != "coordinator_private_runtime_only":
        raise TopologyError("validator endpoint policy must be coordinator_private_runtime_only")
    assert_public_endpoints("common bootnodes", list(common["bootnodes"]))
    assert_public_endpoints("common seed servers", list(common["seed_servers"]))
    assert_public_endpoints("common relayer peers", list(common["relayer_peers"]))

    for section in ("bootnodes", "seed_servers", "relayers", "rpc_gateways", "archive_validators"):
        for node in topology.get(section, []):
            endpoint = node["public_endpoint"]
            host, port = split_endpoint(endpoint)
            if not endpoint_host_is_dns(endpoint):
                raise TopologyError(f"{section}.{node['name']} must use DNS public endpoint")
            if not host.endswith(STABLE_INFRA_SUFFIX):
                raise TopologyError(f"{section}.{node['name']} must use synergynode.xyz DNS")
            if port != node["port"]:
                raise TopologyError(f"{section}.{node['name']} endpoint port drift")
            assert_public_endpoints(f"{section}.{node['name']}", [endpoint])

    validators = list(topology["validators"])
    if len(validators) != 6:
        raise TopologyError("exactly six active consensus validators are required")
    allowlist = list(topology["consensus"]["strict_validator_allowlist"])
    validator_addresses = [validator["validator_address"] for validator in validators]
    if validator_addresses != allowlist:
        raise TopologyError("validator allowlist must match active validator manifest order")
    for validator in validators:
        if "public_endpoint" in validator:
            raise TopologyError(f"{validator['name']} must not define a public endpoint")
        if validator.get("port") != 5622:
            raise TopologyError(f"{validator['name']} must use port 5622")
        if not str(validator.get("validator_address", "")).startswith("synv1"):
            raise TopologyError(f"{validator['name']} must use a synv1 identity")

    relayer_endpoints = [relayer["public_endpoint"] for relayer in topology["relayers"]]
    if len(relayer_endpoints) != 3 or len(set(relayer_endpoints)) != 3 or list(common["relayer_peers"]) != relayer_endpoints:
        raise TopologyError("public consensus boundary must contain exactly the three canonical relayers")

    archive = topology["archive_validators"][0]
    if archive["public_endpoint"] != "archive.synergynode.xyz:5615":
        raise TopologyError("archive must advertise archive.synergynode.xyz:5615")

    observer = topology["observers"][0]
    if set(observer["p2p_peers"]) == set(observer["monitoring_targets"]):
        raise TopologyError("observer P2P peers and monitoring targets must be separate lists")
    assert_public_endpoints("observer p2p", [observer["public_endpoint"], *observer["p2p_peers"]])

    if not topology.get("explorer_indexers"):
        raise TopologyError("explorer indexer must be present in topology")
    assert_public_endpoints("explorer indexer", [topology["explorer_indexers"][0]["public_endpoint"]])

    for relayer in topology["relayers"]:
        assert_public_endpoints(relayer["name"], list(relayer["peers"]))
        if any(peer in {str(validator.get("public_endpoint")) for validator in validators} for peer in relayer["peers"]):
            raise TopologyError(f"{relayer['name']} must not dial public validator endpoints")
    for rpc_gateway in topology["rpc_gateways"]:
        assert_public_endpoints(rpc_gateway["name"], list(rpc_gateway["peers"]))
    for archive_validator in topology["archive_validators"]:
        assert_public_endpoints(archive_validator["name"], list(archive_validator["peers"]))
    for indexer in topology["explorer_indexers"]:
        assert_public_endpoints(indexer["name"], list(indexer["peers"]))


def parse_iso8601(value: str) -> dt.datetime:
    normalized = value.replace("Z", "+00:00")
    parsed = dt.datetime.fromisoformat(normalized)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=dt.timezone.utc)
    return parsed.astimezone(dt.timezone.utc)


def seed_registry_entry_is_fresh(entry: dict[str, Any], now: dt.datetime | None = None) -> bool:
    if now is None:
        now = dt.datetime.now(dt.timezone.utc)
    last_seen_raw = entry.get("last_seen")
    if not last_seen_raw:
        return False
    ttl_seconds = int(entry.get("ttl_seconds", 0))
    if ttl_seconds <= 0:
        return False
    last_seen = parse_iso8601(str(last_seen_raw))
    return (now.astimezone(dt.timezone.utc) - last_seen).total_seconds() <= ttl_seconds


def seed_registry_entry_is_advertisable(entry: dict[str, Any], now: dt.datetime | None = None) -> bool:
    endpoint = str(entry.get("public_endpoint", ""))
    if not endpoint_is_public_advertisement(endpoint):
        return False
    if str(entry.get("dialback_status", "")).lower() != "success":
        return False
    if str(entry.get("health_status", "")).lower() != "healthy":
        return False
    return seed_registry_entry_is_fresh(entry, now=now)


def seed_registry_peer_view(
    entries: list[dict[str, Any]],
    role: str | None = None,
    now: dt.datetime | None = None,
) -> list[str]:
    visible: list[str] = []
    for entry in entries:
        if role is not None and entry.get("role") != role:
            continue
        if seed_registry_entry_is_advertisable(entry, now=now):
            visible.append(str(entry["public_endpoint"]))
    return visible


def validator_peer_identities(topology: dict[str, Any], _self_address: str) -> list[str]:
    # Pre-enrollment configs have no VPN transport map. Bare synv1 identities
    # are policy identifiers, not routable dial targets until the coordinator
    # injects their post-enrollment transports.
    return list(topology["common"]["relayer_peers"])


def base_config(
    topology: dict[str, Any],
    node: dict[str, Any],
    role: str,
    peers: list[str],
    strict_validator_allowlist: bool,
) -> dict[str, dict[str, Any]]:
    network = topology["network"]
    common = topology["common"]
    allowlist = topology["consensus"]["strict_validator_allowlist"]
    endpoint = node.get("public_endpoint")
    port = int(node["port"]) if endpoint is None else split_endpoint(endpoint)[1]
    if port is None:
        raise TopologyError(f"{node['name']} must define a P2P port")
    is_validator = role == "validator"
    network_config: dict[str, Any] = {
        "id": network["network_id"],
        "name": network["network_name"],
        "network_id": network["runtime_network_id"],
        "chain_id": network["chain_id"],
        "p2p_port": port,
        "bootnodes": [] if is_validator else list(common["bootnodes"]),
        "seed_servers": [] if is_validator else list(common["seed_servers"]),
        "bootstrap_dns_records": [] if is_validator else list(common["bootstrap_dns_records"]),
        "additional_dial_targets": list(peers),
        "persistent_peers": list(peers),
    }
    if endpoint is not None:
        network_config["public_p2p_address"] = endpoint
    network_config["public_rpc_endpoint"] = network["public_rpc_endpoint"]
    if is_validator:
        network_config["validator_vpn_transports"] = []
    config: dict[str, dict[str, Any]] = {
        "identity": {
            "node_id": node["node_id"],
            "role": role,
            "role_display": role.replace("_", " "),
            "address": node.get("validator_address", ""),
            "label": node["name"],
        },
        "network": network_config,
        "p2p": {
            "listen_address": (
                f"{VALIDATOR_LOOPBACK_HOST}:{port}"
                if is_validator
                else f"0.0.0.0:{port}"
            ),
            "public_address": endpoint or "",
            "node_name": node["node_id"],
            "enable_discovery": not is_validator,
            "enable_peer_exchange": not is_validator,
            "discovery_port": VALIDATOR_DISCOVERY_PORT,
            "discovery_listen_address": (
                f"{VALIDATOR_LOOPBACK_HOST}:{VALIDATOR_DISCOVERY_PORT}"
                if is_validator
                else f"0.0.0.0:{VALIDATOR_DISCOVERY_PORT}"
            ),
            "discovery_public_address": "" if is_validator else (endpoint or ""),
            "reject_private_advertise_addrs": True,
        },
        "node": {
            "strict_validator_allowlist": strict_validator_allowlist,
            "allowed_validator_addresses": list(allowlist),
            "validator_address": node.get("validator_address", ""),
            # The topology manifest describes the eventual validator set. A
            # generated validator is pre-enrollment and cannot activate
            # consensus until the coordinator installs its private transport.
            "active_consensus_validator": False if is_validator else bool(node.get("active_consensus", False)),
        },
        "seed_registration": {
            "enabled": not is_validator,
            "register_endpoints": [] if is_validator else list(common["seed_servers"]),
            "heartbeat_endpoints": [] if is_validator else list(common["seed_servers"]),
            "dialback_required": bool(topology["seed_registry"]["dialback_required"]),
        },
    }
    return config


def generate_configs(topology: dict[str, Any]) -> dict[PurePosixPath, dict[str, dict[str, Any]]]:
    configs: dict[PurePosixPath, dict[str, dict[str, Any]]] = {}
    public_support_peers = list(topology["common"]["relayer_peers"])

    for validator in topology["validators"]:
        peers = validator_peer_identities(topology, validator["validator_address"])
        configs[PurePosixPath("validators") / f"{validator['name'].lower()}.toml"] = base_config(
            topology,
            validator,
            "validator",
            peers,
            strict_validator_allowlist=True,
        )

    for bootnode in topology["bootnodes"]:
        configs[PurePosixPath("bootnodes") / f"{bootnode['name']}.toml"] = base_config(
            topology,
            bootnode,
            "bootnode",
            list(topology["common"]["relayer_peers"]),
            strict_validator_allowlist=False,
        )

    for seed in topology["seed_servers"]:
        config = base_config(
            topology,
            seed,
            "seed_server",
            public_support_peers,
            strict_validator_allowlist=False,
        )
        config["seed_registry_policy"] = {
            "ttl_seconds": topology["seed_registry"]["ttl_seconds"],
            "dialback_required": topology["seed_registry"]["dialback_required"],
            "replication_required": topology["seed_registry"]["replication_required"],
            "roles": list(topology["seed_registry"]["roles"]),
            "reject_cidrs": list(topology["policies"]["private_advertise_cidrs"]),
            "reject_hosts": list(topology["policies"]["private_advertise_hosts"]),
            "health_endpoint": topology["seed_registry"]["health_endpoint"],
            "metrics_endpoint": topology["seed_registry"]["metrics_endpoint"],
            "peer_list_endpoint": topology["seed_registry"]["peer_list_endpoint"],
            "peers_endpoint": topology["seed_registry"]["peers_endpoint"],
            "register_endpoint": topology["seed_registry"]["register_endpoint"],
            "heartbeat_endpoint": topology["seed_registry"]["heartbeat_endpoint"],
        }
        configs[PurePosixPath("seed-servers") / f"{seed['name']}.toml"] = config

    for relayer in topology["relayers"]:
        configs[PurePosixPath("relayers") / f"{relayer['name']}.toml"] = base_config(
            topology,
            relayer,
            "relayer",
            list(relayer["peers"]),
            strict_validator_allowlist=False,
        )

    for rpc_gateway in topology["rpc_gateways"]:
        config = base_config(
            topology,
            rpc_gateway,
            "rpc_gateway",
            public_support_peers,
            strict_validator_allowlist=False,
        )
        config["rpc_gateway"] = {
            "p2p_endpoint": rpc_gateway["public_endpoint"],
            "public_json_rpc_endpoint": rpc_gateway["public_json_rpc_endpoint"],
            "json_rpc_bind_policy": "local_or_private_proxy_only",
        }
        configs[PurePosixPath("rpc-gateway") / f"{rpc_gateway['name']}.toml"] = config

    for observer in topology["observers"]:
        config = base_config(
            topology,
            observer,
            "observer",
            public_support_peers,
            strict_validator_allowlist=False,
        )
        config["observer"] = {
            "p2p_peers": public_support_peers,
            "monitoring_targets": list(observer["monitoring_targets"]),
        }
        configs[PurePosixPath("observer") / f"{observer['name']}.toml"] = config

    for indexer in topology["explorer_indexers"]:
        config = base_config(
            topology,
            indexer,
            "explorer_indexer",
            public_support_peers,
            strict_validator_allowlist=False,
        )
        config["explorer_indexer"] = {
            "service_name": indexer["service_name"],
            "config_paths": list(indexer["config_paths"]),
        }
        configs[PurePosixPath("explorer-indexer") / f"{indexer['name']}.toml"] = config

    for archive in topology["archive_validators"]:
        config = base_config(
            topology,
            archive,
            "archive_validator",
            public_support_peers,
            strict_validator_allowlist=False,
        )
        config["archive_validator"] = {
            "public_archive_endpoint": archive["public_endpoint"],
            "advertise_addr_preferred": archive["public_endpoint"],
        }
        configs[PurePosixPath("archive-validator") / f"{archive['name']}.toml"] = config

    return configs


def toml_value(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, str):
        return json.dumps(value)
    if isinstance(value, list):
        return "[" + ", ".join(toml_value(item) for item in value) + "]"
    raise TypeError(f"unsupported TOML value: {type(value).__name__}")


def render_toml(config: dict[str, dict[str, Any]]) -> str:
    lines = [
        "# Generated by scripts/testnet/generate_public_p2p_configs.py",
        "# Source: config/testnet/network-topology.toml",
        "# Do not hand-edit generated configs; update the manifest and regenerate.",
        "",
    ]
    for section, values in config.items():
        lines.append(f"[{section}]")
        for key, value in values.items():
            lines.append(f"{key} = {toml_value(value)}")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def write_generated_configs(configs: dict[PurePosixPath, dict[str, dict[str, Any]]], output_dir: Path) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    for relative_path, config in sorted(configs.items(), key=lambda item: str(item[0])):
        path = output_dir / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(render_toml(config), encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate public P2P testnet configs from the canonical topology manifest.")
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    args = parser.parse_args()

    topology = load_topology(args.manifest)
    configs = generate_configs(topology)
    write_generated_configs(configs, args.output_dir)
    print(f"generated {len(configs)} configs under {args.output_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
