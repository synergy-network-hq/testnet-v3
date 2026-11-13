#!/usr/bin/env python3
"""Read-only Synergy validator VPN/runtime pre-start validation.

This checker is intended to run before consensus is started or restarted. It
does not SSH, does not mutate WireGuard state, and does not print key material.
It verifies that validator configs keep consensus identity, VPN transport
routes, and EpochValidatorSet membership evidence separate.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import subprocess
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python < 3.11
    tomllib = None  # type: ignore[assignment]


TESTNET_CHAIN_ID = 1264
VALIDATOR_P2P_PORT = 5622
DEFAULT_VALIDATOR_VPN_IFACE = "sy-validator0"
OLD_WIREGUARD_IFACE = "wg0"

VALIDATOR_TRANSPORT_RE = re.compile(r"^10\.70\.10\.(?:[1-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-4])$")
RELAYER_TRANSPORT_RE = re.compile(r"^10\.70\.20\.(?:[1-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-4])$")
RETIRED_TRANSPORT_RE = re.compile(r"^10\.69\.")


@dataclass
class Finding:
    status: str
    name: str
    detail: str
    path: str | None = None


def finding(status: str, name: str, detail: str, path: Path | str | None = None) -> Finding:
    return Finding(status=status, name=name, detail=detail, path=str(path) if path else None)


def load_toml(path: Path) -> dict[str, Any]:
    if tomllib is None:
        raise RuntimeError("Python 3.11+ is required for TOML parsing")
    with path.open("rb") as handle:
        payload = tomllib.load(handle)
    if not isinstance(payload, dict):
        raise ValueError(f"{path} did not parse as a TOML table")
    return payload


def as_string_list(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    if isinstance(value, str) and value.strip():
        return [value.strip()]
    return []


def unique(values: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for value in values:
        if value not in seen:
            seen.add(value)
            out.append(value)
    return out


def is_synv_address(value: str) -> bool:
    return value.strip().startswith("synv1")


def host_port(value: str) -> tuple[str, int | None]:
    text = value.strip()
    if "://" in text:
        text = text.split("://", 1)[1]
    if "@" in text:
        text = text.rsplit("@", 1)[1]
    if text.startswith("[") and "]:" in text:
        host, port = text[1:].split("]:", 1)
        return host, parse_port(port)
    if text.count(":") == 1:
        host, port = text.rsplit(":", 1)
        return host, parse_port(port)
    return text, None


def parse_port(value: str) -> int | None:
    try:
        return int(value)
    except ValueError:
        return None


def is_validator_vpn_host(host: str) -> bool:
    return bool(VALIDATOR_TRANSPORT_RE.match(host.strip()))


def is_relayer_vpn_host(host: str) -> bool:
    return bool(RELAYER_TRANSPORT_RE.match(host.strip()))


def is_retired_vpn_host(host: str) -> bool:
    return bool(RETIRED_TRANSPORT_RE.match(host.strip()))


def is_private_host(host: str) -> bool:
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return host in {"localhost"}
    return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_unspecified


def section(config: dict[str, Any], name: str) -> dict[str, Any]:
    value = config.get(name)
    return value if isinstance(value, dict) else {}


def read_peer_targets(node_config: dict[str, Any], peers_config: dict[str, Any] | None) -> list[str]:
    network = section(node_config, "network")
    targets = as_string_list(network.get("persistent_peers"))
    targets.extend(as_string_list(network.get("additional_dial_targets")))
    if peers_config:
        global_section = section(peers_config, "global")
        targets.extend(as_string_list(global_section.get("persistent_peers")))
        targets.extend(as_string_list(global_section.get("additional_dial_targets")))
    return unique(targets)


def read_transports(node_config: dict[str, Any]) -> list[dict[str, str]]:
    network = section(node_config, "network")
    raw = network.get("validator_vpn_transports") or []
    transports: list[dict[str, str]] = []
    if isinstance(raw, list):
        for item in raw:
            if isinstance(item, dict):
                transports.append(
                    {
                        "validator_address": str(item.get("validator_address") or "").strip(),
                        "dial_address": str(item.get("dial_address") or "").strip(),
                    }
                )
    return transports


def advertised_validator_addresses(node_config: dict[str, Any]) -> list[tuple[str, str]]:
    network = section(node_config, "network")
    p2p = section(node_config, "p2p")
    values = [
        ("network.public_p2p_address", str(network.get("public_p2p_address") or "").strip()),
        ("p2p.public_address", str(p2p.get("public_address") or "").strip()),
        ("p2p.public_p2p_address", str(p2p.get("public_p2p_address") or "").strip()),
        ("p2p.discovery_public_address", str(p2p.get("discovery_public_address") or "").strip()),
    ]
    return [(key, value) for key, value in values if value]


def check_config(
    workspace: Path,
    role: str,
    expected_validator_address: str | None,
) -> tuple[list[Finding], dict[str, Any]]:
    findings: list[Finding] = []
    node_path = workspace / "config" / "node.toml"
    peers_path = workspace / "config" / "peers.toml"

    if not node_path.is_file():
        return [finding("FAIL", "node config", "config/node.toml is missing", node_path)], {}

    try:
        node_config = load_toml(node_path)
    except Exception as exc:  # noqa: BLE001 - include parser detail in report
        return [finding("FAIL", "node config parse", str(exc), node_path)], {}

    peers_config: dict[str, Any] | None = None
    if peers_path.is_file():
        try:
            peers_config = load_toml(peers_path)
            findings.append(finding("PASS", "peers.toml role", "peers.toml parsed as transport-only peer input", peers_path))
        except Exception as exc:  # noqa: BLE001
            findings.append(finding("FAIL", "peers.toml parse", str(exc), peers_path))
    else:
        findings.append(finding("WARN", "peers.toml", "config/peers.toml is missing; node.toml will be the only peer input", peers_path))

    node_section = section(node_config, "node")
    local_validator = expected_validator_address or str(node_section.get("validator_address") or "").strip()
    if role == "validator":
        if local_validator and is_synv_address(local_validator):
            findings.append(finding("PASS", "local validator identity", local_validator, node_path))
        else:
            findings.append(finding("FAIL", "local validator identity", "validator_address must be a synv1 identity", node_path))

        strict_allowlist = bool(node_section.get("strict_validator_allowlist"))
        if strict_allowlist:
            findings.append(
                finding(
                    "FAIL",
                    "config allowlist authority",
                    "strict_validator_allowlist is true; validator config must not be consensus membership authority",
                    node_path,
                )
            )
        else:
            findings.append(finding("PASS", "config allowlist authority", "strict_validator_allowlist is disabled", node_path))

        for key, value in advertised_validator_addresses(node_config):
            host, _port = host_port(value)
            if is_synv_address(value):
                findings.append(finding("PASS", f"{key}", "advertises canonical validator identity", node_path))
            elif is_private_host(host):
                findings.append(finding("FAIL", f"{key}", f"validator advertises private/public transport endpoint {value}; expected synv1 identity", node_path))
            else:
                findings.append(finding("FAIL", f"{key}", f"validator advertises public endpoint {value}; validators must not expose public endpoints", node_path))

    peer_targets = read_peer_targets(node_config, peers_config)
    validator_identity_targets = {target for target in peer_targets if is_synv_address(target)}
    for target in peer_targets:
        host, port = host_port(target)
        if is_retired_vpn_host(host):
            findings.append(finding("FAIL", "retired validator VPN route", f"{target} is a retired 10.69.* VPN route; current Innernet evidence must use 10.70.10.1-254 or 10.70.20.1-254", node_path))
        elif is_validator_vpn_host(host):
            findings.append(finding("FAIL", "validator peer identity", f"validator peer list contains raw validator VPN route {target}", node_path))
        elif is_relayer_vpn_host(host):
            findings.append(finding("PASS", "relayer support route", f"{target} is a relayer/support VPN route", node_path))
        elif is_synv_address(target):
            findings.append(finding("PASS", "validator peer identity", f"{target} is a canonical validator identity", node_path))
        elif port == VALIDATOR_P2P_PORT:
            findings.append(finding("WARN", "non-synv peer target", f"{target} is not a synv1 identity; verify it is a support node, not validator membership", node_path))

    transports = read_transports(node_config)
    if role == "validator" and not transports:
        findings.append(finding("FAIL", "validator VPN transport map", "network.validator_vpn_transports is empty", node_path))

    for transport in transports:
        validator_address = transport["validator_address"]
        dial_address = transport["dial_address"]
        host, port = host_port(dial_address)
        if not is_synv_address(validator_address):
            findings.append(finding("FAIL", "validator VPN transport identity", f"invalid validator_address {validator_address!r}", node_path))
        elif validator_address == local_validator:
            findings.append(finding("FAIL", "validator VPN transport self route", f"transport map contains local validator {validator_address}", node_path))
        elif validator_address not in validator_identity_targets:
            findings.append(finding("FAIL", "validator VPN transport peer target", f"{validator_address} has a VPN route but is not present as a synv1 peer target", node_path))
        else:
            findings.append(finding("PASS", "validator VPN transport peer target", f"{validator_address} is dialed by synv1 identity", node_path))

        if is_validator_vpn_host(host) and port == VALIDATOR_P2P_PORT:
            findings.append(finding("PASS", "validator VPN transport route", f"{validator_address} resolves to {dial_address}", node_path))
        else:
            findings.append(finding("FAIL", "validator VPN transport route", f"{dial_address} is not a 10.70.10.1-254:{VALIDATOR_P2P_PORT} route", node_path))

    return findings, node_config


def validator_members(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    members: list[str] = []
    for item in value:
        if isinstance(item, str):
            candidate = item.strip()
        elif isinstance(item, dict):
            candidate = str(item.get("address") or item.get("validator_address") or item.get("validatorAddress") or "").strip()
        else:
            candidate = ""
        if candidate:
            members.append(candidate)
    return members


def choose_epoch_snapshot(document: Any) -> dict[str, Any]:
    if isinstance(document, dict):
        for key in ("epoch_validator_set", "epochValidatorSet", "validator_set", "validatorSet"):
            if isinstance(document.get(key), dict):
                return document[key]
        sets = document.get("epoch_validator_sets") or document.get("epochValidatorSets")
        if isinstance(sets, list):
            candidates = [item for item in sets if isinstance(item, dict)]
            latest = [item for item in candidates if item.get("is_latest") is True or item.get("isLatest") is True]
            if latest:
                return latest[-1]
            if candidates:
                return sorted(candidates, key=lambda item: int(item.get("effective_from_height") or item.get("effectiveFromHeight") or 0))[-1]
        return document
    raise ValueError("EpochValidatorSet document must be a JSON object")


def json_u64(snapshot: dict[str, Any], *keys: str) -> int | None:
    for key in keys:
        value = snapshot.get(key)
        if value is None:
            continue
        try:
            return int(value)
        except (TypeError, ValueError):
            return None
    return None


def json_text(snapshot: dict[str, Any], *keys: str) -> str | None:
    for key in keys:
        value = snapshot.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def epoch_snapshot_candidate_paths(workspace: Path) -> list[Path]:
    return [
        workspace / "config" / "epoch-validator-set-latest.json",
        workspace / "config" / "epoch-validator-sets.json",
        workspace / "onboarding" / "epoch-validator-set-latest.json",
        workspace / "validator-onboarding" / "epoch-validator-set-latest.json",
        workspace / "evidence" / "epoch-validator-set-latest.json",
    ]


def check_epoch_snapshot(
    workspace: Path,
    explicit_path: Path | None,
    local_validator: str | None,
    expected_active_count: int | None,
) -> list[Finding]:
    findings: list[Finding] = []
    path = explicit_path
    if path is None:
        path = next((candidate for candidate in epoch_snapshot_candidate_paths(workspace) if candidate.is_file()), None)
    if path is None:
        expected = workspace / "config" / "epoch-validator-set-latest.json"
        return [finding("FAIL", "EpochValidatorSet snapshot", "latest EpochValidatorSet snapshot is missing", expected)]

    try:
        document = json.loads(path.read_text(encoding="utf-8"))
        snapshot = choose_epoch_snapshot(document)
    except Exception as exc:  # noqa: BLE001
        return [finding("FAIL", "EpochValidatorSet parse", str(exc), path)]

    chain_id = json_u64(snapshot, "chain_id", "chainId")
    if chain_id == TESTNET_CHAIN_ID:
        findings.append(finding("PASS", "EpochValidatorSet chain_id", str(chain_id), path))
    else:
        findings.append(finding("FAIL", "EpochValidatorSet chain_id", f"actual={chain_id!r} expected={TESTNET_CHAIN_ID}", path))

    required_fields = {
        "epoch": json_u64(snapshot, "epoch_id", "epochId", "epoch"),
        "validator_set_version": json_u64(snapshot, "validator_set_version", "validatorSetVersion", "version"),
        "effective_from_height": json_u64(snapshot, "effective_from_height", "effectiveFromHeight", "effective_height", "effectiveHeight"),
        "quorum_threshold": json_u64(snapshot, "quorum_threshold", "quorumThreshold"),
    }
    for name, value in required_fields.items():
        findings.append(
            finding(
                "PASS" if value is not None else "FAIL",
                f"EpochValidatorSet {name}",
                str(value) if value is not None else "missing",
                path,
            )
        )

    validator_set_hash = json_text(snapshot, "validator_set_hash", "validatorSetHash", "set_hash", "setHash")
    local_hash = json_text(snapshot, "local_validator_set_hash", "localValidatorSetHash", "local_set_hash", "localSetHash") or validator_set_hash
    network_hash = json_text(snapshot, "network_validator_set_hash", "networkValidatorSetHash", "expected_validator_set_hash", "expectedValidatorSetHash") or validator_set_hash
    if validator_set_hash:
        findings.append(finding("PASS", "EpochValidatorSet hash", validator_set_hash, path))
    else:
        findings.append(finding("FAIL", "EpochValidatorSet hash", "validator_set_hash is missing", path))
    if local_hash and network_hash and local_hash.lower() == network_hash.lower():
        findings.append(finding("PASS", "EpochValidatorSet hash agreement", f"local={local_hash} network={network_hash}", path))
    else:
        findings.append(finding("FAIL", "EpochValidatorSet hash agreement", f"local={local_hash!r} network={network_hash!r}", path))

    active = validator_members(snapshot.get("active_validators") or snapshot.get("activeValidators"))
    pending = validator_members(snapshot.get("pending_validators") or snapshot.get("pendingValidators"))
    syncing = validator_members(snapshot.get("syncing_validators") or snapshot.get("syncingValidators"))
    eligible = validator_members(snapshot.get("eligible_validators") or snapshot.get("eligibleValidators"))
    jailed = validator_members(snapshot.get("jailed_validators") or snapshot.get("jailedValidators"))
    removed = validator_members(snapshot.get("removed_validators") or snapshot.get("removedValidators"))
    if expected_active_count is not None and len(active) != expected_active_count:
        findings.append(finding("FAIL", "EpochValidatorSet active count", f"actual={len(active)} expected={expected_active_count}", path))
    elif active:
        findings.append(finding("PASS", "EpochValidatorSet active count", str(len(active)), path))
    else:
        findings.append(finding("FAIL", "EpochValidatorSet active validators", "active_validators is empty or missing", path))

    if local_validator:
        if local_validator in jailed:
            findings.append(finding("FAIL", "local validator lifecycle", "local validator is Jailed", path))
        elif local_validator in removed:
            findings.append(finding("FAIL", "local validator lifecycle", "local validator is Removed", path))
        elif local_validator in active:
            findings.append(finding("PASS", "local validator lifecycle", "Active", path))
        elif local_validator in pending:
            findings.append(finding("PASS", "local validator lifecycle", "Pending", path))
        elif local_validator in syncing:
            findings.append(finding("PASS", "local validator lifecycle", "Syncing", path))
        elif local_validator in eligible:
            findings.append(finding("PASS", "local validator lifecycle", "Eligible", path))
        else:
            findings.append(finding("FAIL", "local validator lifecycle", f"{local_validator} is absent from EpochValidatorSet lifecycle lists", path))

    return findings


def check_old_vpn_material(workspace: Path) -> list[Finding]:
    findings: list[Finding] = []
    candidates = [
        Path("/etc/wireguard/wg0.conf"),
        Path("/etc/systemd/system/wg-quick@wg0.service"),
        workspace / "config" / "wg0.conf",
        workspace / "wireguard" / "wg0.conf",
        workspace / "validator-vpn" / "wg0.conf",
    ]
    present = [path for path in candidates if path.exists()]
    if present:
        findings.append(finding("FAIL", "old WireGuard material", "old wg0 config/service material exists: " + ", ".join(str(path) for path in present)))
    else:
        findings.append(finding("PASS", "old WireGuard material", "no checked wg0 config/service files are present"))
    return findings


def command_ok(command: list[str]) -> bool:
    try:
        return subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False).returncode == 0
    except OSError:
        return False


def check_system_interfaces(vpn_iface: str) -> list[Finding]:
    findings: list[Finding] = []
    if command_ok(["ip", "link", "show", vpn_iface]) or command_ok(["ifconfig", vpn_iface]):
        findings.append(finding("PASS", "validator VPN interface", f"{vpn_iface} is present"))
    else:
        findings.append(finding("FAIL", "validator VPN interface", f"{vpn_iface} is not present"))
    if command_ok(["ip", "link", "show", OLD_WIREGUARD_IFACE]) or command_ok(["ifconfig", OLD_WIREGUARD_IFACE]):
        findings.append(finding("FAIL", "old VPN interface", f"{OLD_WIREGUARD_IFACE} is active/present"))
    else:
        findings.append(finding("PASS", "old VPN interface", f"{OLD_WIREGUARD_IFACE} is not active"))
    if command_ok(["wg", "show", vpn_iface]):
        findings.append(finding("PASS", "WireGuard runtime", f"wg can inspect {vpn_iface}"))
    else:
        findings.append(finding("WARN", "WireGuard runtime", f"wg cannot inspect {vpn_iface}; tool may be missing or interface may be down"))
    return findings


def render_text(findings: list[Finding]) -> str:
    lines = ["Synergy validator VPN runtime validation", ""]
    for item in findings:
        suffix = f" [{item.path}]" if item.path else ""
        lines.append(f"{item.status} {item.name}: {item.detail}{suffix}")
    counts = {status: sum(1 for item in findings if item.status == status) for status in ("PASS", "WARN", "FAIL")}
    lines.extend(["", f"Summary: pass={counts['PASS']} warn={counts['WARN']} fail={counts['FAIL']}"])
    return "\n".join(lines) + "\n"


def write_output(text: str, output: str | None) -> None:
    if output:
        Path(output).write_text(text, encoding="utf-8")
    else:
        sys.stdout.write(text)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", required=True, help="Validator workspace root containing config/node.toml.")
    parser.add_argument("--role", choices=("validator", "relayer"), default="validator")
    parser.add_argument("--validator-address", help="Expected local synv1 validator address.")
    parser.add_argument("--epoch-validator-set", help="Explicit EpochValidatorSet JSON path.")
    parser.add_argument("--expected-active-count", type=int, help="Expected active validator count in EpochValidatorSet.")
    parser.add_argument("--vpn-interface", default=DEFAULT_VALIDATOR_VPN_IFACE)
    parser.add_argument("--check-system", action="store_true", help="Also check local system interfaces and WireGuard runtime.")
    parser.add_argument("--format", choices=("text", "json"), default="text")
    parser.add_argument("--output", help="Write report to PATH. Defaults to stdout.")
    args = parser.parse_args(argv)

    workspace = Path(args.workspace).expanduser().resolve()
    findings: list[Finding] = []
    if not workspace.is_dir():
        findings.append(finding("FAIL", "workspace", f"{workspace} is not a directory", workspace))
        rendered = render_text(findings) if args.format == "text" else json.dumps([asdict(item) for item in findings], indent=2) + "\n"
        write_output(rendered, args.output)
        return 1

    config_findings, node_config = check_config(workspace, args.role, args.validator_address)
    findings.extend(config_findings)
    node_section = section(node_config, "node")
    local_validator = args.validator_address or str(node_section.get("validator_address") or "").strip() or None
    epoch_path = Path(args.epoch_validator_set).expanduser().resolve() if args.epoch_validator_set else None
    findings.extend(check_epoch_snapshot(workspace, epoch_path, local_validator, args.expected_active_count))
    findings.extend(check_old_vpn_material(workspace))
    if args.check_system:
        findings.extend(check_system_interfaces(args.vpn_interface))

    if args.format == "json":
        rendered = json.dumps([asdict(item) for item in findings], indent=2) + "\n"
    else:
        rendered = render_text(findings)
    write_output(rendered, args.output)
    return 1 if any(item.status == "FAIL" for item in findings) else 0


if __name__ == "__main__":
    raise SystemExit(main())
