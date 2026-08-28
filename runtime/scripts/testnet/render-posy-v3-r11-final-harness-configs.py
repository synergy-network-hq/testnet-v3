#!/usr/bin/env python3
"""Render final R11 validator configs from preserved pre-finalization templates."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
import tomllib
from pathlib import Path
from typing import Any, NoReturn


VALIDATORS = tuple(f"validator-{number:02d}" for number in range(2, 7))
ROOT_LINE = re.compile(
    r'^(consensus_parameter_root_sha3_512\s*=\s*)"[0-9a-f]{128}"\s*$',
    re.MULTILINE,
)


def fail(message: str) -> NoReturn:
    raise SystemExit(f"render-posy-v3-r11-final-harness-configs: {message}")


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read_json(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        fail(f"read {label} {path}: {error}")
    if not isinstance(value, dict):
        fail(f"{label} must be a JSON object: {path}")
    return value


def finalized_binding(genesis: dict[str, Any]) -> tuple[str, dict[str, str]]:
    try:
        activation = genesis["consensus"]["posy_v3_activation"]
        parameter_root = activation["parameter_root_sha3_512"]
        manifest = activation["manifest"]
        bound_root = genesis["consensus_parameters"]["parameter_root_sha3_512"]
        validators = {
            record["validator_id"]: record["operator_address"]
            for record in genesis["validators"]
        }
    except (KeyError, TypeError, ValueError) as error:
        fail(f"finalized Genesis is missing an R11 binding: {error}")
    if (
        not isinstance(parameter_root, str)
        or re.fullmatch(r"[0-9a-f]{128}", parameter_root) is None
        or parameter_root != bound_root
        or manifest.get("target_block_time_ms") != 500
        or manifest.get("active_validator_count") != len(VALIDATORS)
        or set(validators) != set(VALIDATORS)
    ):
        fail("Genesis does not bind one finalized 500ms root and the exact five validators")
    return parameter_root, validators


def parsed_config(path: Path) -> dict[str, Any]:
    try:
        with path.open("rb") as handle:
            return tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError) as error:
        fail(f"parse validator config {path}: {error}")


def validate_config(
    path: Path,
    validator: str,
    parameter_root: str,
    operator_address: str,
) -> tuple[int, int, list[str]]:
    value = parsed_config(path)
    identity = value.get("identity", {})
    consensus = value.get("consensus", {})
    blockchain = value.get("blockchain", {})
    network = value.get("network", {})
    p2p = value.get("p2p", {})
    rpc = value.get("rpc", {})
    if (
        identity.get("node_id") != validator
        or identity.get("address") != operator_address
        or consensus.get("algorithm") != "posy/3.0"
        or consensus.get("mode") != "posy_simplified_v3"
        or consensus.get("target_block_time_ms") != 500
        or consensus.get("consensus_parameter_root_sha3_512") != parameter_root
        or blockchain.get("chain_id") != 1266
        or blockchain.get("target_block_time_ms") != 500
        or network.get("network_id") != "testnet"
        or network.get("id") != 1266
    ):
        fail(f"{validator} rendered config does not bind the exact final R11 identity")
    p2p_port = network.get("p2p_port")
    rpc_port = network.get("rpc_port")
    targets = network.get("additional_dial_targets")
    if (
        not isinstance(p2p_port, int)
        or not isinstance(rpc_port, int)
        or not isinstance(targets, list)
        or len(targets) != 4
        or len(set(targets)) != 4
        or p2p.get("listen_address") != f"127.0.0.1:{p2p_port}"
        or rpc.get("bind_address") != f"127.0.0.1:{rpc_port}"
    ):
        fail(f"{validator} rendered config does not bind its isolated loopback transports")
    return p2p_port, rpc_port, targets


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--genesis", required=True, type=Path)
    parser.add_argument("--template-dir", required=True, type=Path)
    parser.add_argument("--validator-binary", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    args = parser.parse_args()

    if args.output_dir.exists():
        fail(f"refusing to overwrite output directory: {args.output_dir}")
    if not args.validator_binary.is_file() or not os.access(args.validator_binary, os.X_OK):
        fail(f"validator binary is not executable: {args.validator_binary}")
    genesis = read_json(args.genesis, "finalized Genesis")
    parameter_root, operator_addresses = finalized_binding(genesis)
    args.output_dir.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=f".{args.output_dir.name}.", dir=args.output_dir.parent))
    lineage: dict[str, dict[str, str]] = {}
    topology: dict[str, tuple[int, int, list[str]]] = {}
    try:
        for validator in VALIDATORS:
            source = args.template_dir / validator / "config.toml"
            if not source.is_file() or source.is_symlink():
                fail(f"preserved template is missing: {source}")
            text = source.read_text(encoding="utf-8")
            rendered, count = ROOT_LINE.subn(
                rf'\1"{parameter_root}"',
                text,
            )
            if count != 1:
                fail(f"{validator} template must contain exactly one consensus parameter root")
            destination = staging / validator / "config.toml"
            destination.parent.mkdir(parents=True)
            destination.write_text(rendered, encoding="utf-8")
            topology[validator] = validate_config(
                destination, validator, parameter_root, operator_addresses[validator],
            )
            result = subprocess.run(
                [str(args.validator_binary), "validate-config", "--config", str(destination)],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                check=False,
            )
            if (
                result.returncode != 0
                or f"validator_id={validator}" not in result.stdout
                or "chain_id=1266 network_id=testnet protocol=posy/3.0 mode=posy_simplified_v3"
                not in result.stdout
            ):
                fail(f"production parser rejected {validator}: {result.stdout.strip()}")
            lineage[validator] = {
                "template_sha256": sha256(source),
                "rendered_sha256": sha256(destination),
            }

        p2p_ports = {validator: entry[0] for validator, entry in topology.items()}
        rpc_ports = {validator: entry[1] for validator, entry in topology.items()}
        if len(set(p2p_ports.values())) != 5 or len(set(rpc_ports.values())) != 5:
            fail("rendered configs do not have five distinct P2P and RPC ports")
        for validator, (_, _, targets) in topology.items():
            expected = {
                f"127.0.0.1:{p2p_ports[peer]}" for peer in VALIDATORS if peer != validator
            }
            if set(targets) != expected:
                fail(f"{validator} does not dial the exact other four loopback validators")

        report = {
            "schema_version": 1,
            "artifact_type": "local-r11-final-validator-config-lineage",
            "environment": "LOCAL_R11_QUALIFICATION",
            "status": "VALIDATED",
            "genesis_sha256": sha256(args.genesis),
            "consensus_parameter_root_sha3_512": parameter_root,
            "target_block_time_ms": 500,
            "validators": lineage,
        }
        (staging / "validation-report.json").write_text(
            json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8",
        )
        sums = "".join(
            f"{sha256(staging / validator / 'config.toml')}  {validator}/config.toml\n"
            for validator in VALIDATORS
        )
        sums += f"{sha256(staging / 'validation-report.json')}  validation-report.json\n"
        (staging / "SHA256SUMS").write_text(sums, encoding="utf-8")
        os.replace(staging, args.output_dir)
    except BaseException:
        shutil.rmtree(staging, ignore_errors=True)
        raise

    print("R11_FINAL_CONFIGS_RENDERED=YES")
    print(f"CONSENSUS_PARAMETER_ROOT_SHA3_512={parameter_root}")
    print(f"OUTPUT_DIR={args.output_dir}")


if __name__ == "__main__":
    main()
