#!/usr/bin/env python3
"""Build the public-only package manifest for the fresh Testnet-v3 P3 launch.

This is a release-assembly gate, not a deployer.  It verifies the supplied
frozen-governance V4 approval with the packaged public verifier, checks that
the exact five runtime-parsed validator configurations and one validator
binary are those bound by desired-state/approval, and emits one new JSON
manifest.  It neither reads custody material nor contacts a host.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import tomllib
from pathlib import Path
from typing import Any


CHAIN_ID = 1266
NETWORK_ID = "testnet"
RELEASE_ID = "testnet-v3"
PROTOCOL = "posy/3.0"
ACTIVE_IDS = [f"validator-{ordinal:02d}" for ordinal in range(2, 7)]
HEX_64 = "0123456789abcdef"


def fail(message: str) -> "NoReturn":
    raise SystemExit(f"build-fresh-posy-v3-release-package-manifest: {message}")


def require(condition: bool, message: str) -> None:
    if not condition:
        fail(message)


def read_bytes(path: Path) -> bytes:
    try:
        return path.read_bytes()
    except OSError as error:
        fail(f"cannot read {path}: {error}")


def read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(read_bytes(path))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        fail(f"cannot parse strict JSON {path}: {error}")
    require(isinstance(value, dict), f"{path} is not a JSON object")
    return value


def sha256_file(path: Path) -> str:
    return hashlib.sha256(read_bytes(path)).hexdigest()


def require_sha256(value: Any, label: str) -> str:
    require(isinstance(value, str) and len(value) == 64 and set(value) <= set(HEX_64),
            f"{label} is not a lowercase SHA-256 digest")
    return value


def object_value(value: dict[str, Any], key: str, label: str) -> dict[str, Any]:
    nested = value.get(key)
    require(isinstance(nested, dict), f"{label} must be an object")
    return nested


def reject_symlink(path: Path, label: str) -> None:
    require(not path.is_symlink(), f"{label} must not be a symlink")
    require(path.is_file(), f"{label} is not a regular file")


def verify_release_approval(
    verifier: Path,
    candidate: Path,
    authority_record: Path,
    desired_state: Path,
    genesis: Path,
    approval: Path,
) -> str:
    reject_symlink(verifier, "release verifier")
    require(os.access(verifier, os.X_OK), "release verifier is not executable")
    environment = {key: value for key, value in os.environ.items() if not key.startswith("SYNERGY_")}
    command = [
        str(verifier),
        "--release-approval", str(approval),
        "--release-candidate", str(candidate),
        "--authority-record", str(authority_record),
        "--desired-state", str(desired_state),
        "--genesis", str(genesis),
    ]
    try:
        result = subprocess.run(
            command,
            check=False,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=60,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        fail(f"cannot run public V4 release verifier: {error}")
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip()
        fail(f"public V4 release verifier rejected the assembled inputs: {detail or 'no diagnostic'}")
    line = next((line for line in result.stdout.splitlines()
                 if line.startswith("CHAIN1266_P3_RELEASE_AUTHORIZATION_VERIFIED ")), None)
    require(line is not None, "release verifier did not emit a fresh P3 approval attestation")
    return line


def validate_bundle_root(root: Path) -> tuple[dict[str, Any], dict[str, str]]:
    require(root.is_dir() and not root.is_symlink(), "validator bundle root must be a real directory")
    manifest_path = root / "manifest.json"
    validation_path = root / "runtime-parser-validation.json"
    reject_symlink(manifest_path, "validator bundle manifest")
    reject_symlink(validation_path, "runtime parser validation")
    manifest = read_json(manifest_path)
    require(manifest.get("schema_version") == 1,
            "validator bundle manifest schema version is not 1")
    require(manifest.get("artifact_type") == "testnet-v3-posy-validator-public-deployment-bundle",
            "validator bundle manifest has the wrong artifact type")
    require(manifest.get("status") == "PUBLIC_CONFIGS_RENDERED_NOT_STARTED",
            "validator bundle must be public configs rendered but not started")
    for key, expected in [("chain_id", CHAIN_ID), ("network_id", NETWORK_ID),
                          ("release_id", RELEASE_ID), ("protocol_version", PROTOCOL)]:
        require(manifest.get(key) == expected, f"validator bundle manifest {key} is not canonical")
    require(manifest.get("private_material_present") is False,
            "validator bundle manifest declares private material")
    require(manifest.get("initial_active_validator_ids") == ACTIVE_IDS,
            "validator bundle manifest does not name exactly validator-02 through validator-06")

    output_hashes = object_value(manifest, "outputs", "validator bundle outputs")
    expected_paths = {f"{validator_id}/config.toml" for validator_id in ACTIVE_IDS}
    expected_paths.add("runtime-parser-validation.json")
    require(set(output_hashes) == expected_paths,
            "validator bundle outputs must contain only five configs and parser validation")
    for relative, digest in output_hashes.items():
        require_sha256(digest, f"validator bundle output {relative}")
        path = root / relative
        reject_symlink(path, f"validator bundle output {relative}")
        require(sha256_file(path) == digest,
                f"validator bundle output hash mismatch: {relative}")

    validation = read_json(validation_path)
    require(validation.get("schema_version") == 1
            and validation.get("artifact_type") == "testnet-v3-posy-validator-runtime-parser-validation"
            and validation.get("status") == "RUNTIME_PARSER_ACCEPTED",
            "validator runtime-parser attestation is missing or invalid")
    for key, expected in [("chain_id", CHAIN_ID), ("network_id", NETWORK_ID),
                          ("release_id", RELEASE_ID), ("protocol_version", PROTOCOL)]:
        require(validation.get(key) == expected,
                f"runtime parser validation {key} is not canonical")
    require_sha256(validation.get("runtime_validator_sha256"), "runtime validator SHA-256")
    validation_hashes = object_value(validation, "validated_configuration_sha256",
                                    "runtime parser validation configuration hashes")
    require(set(validation_hashes) == set(ACTIVE_IDS),
            "runtime parser validation does not cover exactly validator-02 through validator-06")
    config_hashes: dict[str, str] = {}
    for validator_id in ACTIVE_IDS:
        relative = f"{validator_id}/config.toml"
        digest = output_hashes[relative]
        require(validation_hashes.get(validator_id) == digest,
                f"runtime parser validation hash disagrees for {validator_id}")
        try:
            config = tomllib.loads(read_bytes(root / relative).decode("utf-8"))
        except (UnicodeDecodeError, tomllib.TOMLDecodeError) as error:
            fail(f"cannot parse generated {validator_id} configuration: {error}")
        identity = object_value(config, "identity", f"{validator_id} identity")
        network = object_value(config, "network", f"{validator_id} network")
        consensus = object_value(config, "consensus", f"{validator_id} consensus")
        node = object_value(config, "node", f"{validator_id} node")
        expected_vpn_ip = f"10.69.10.{int(validator_id[-2:])}"
        peer_addresses = [
            transport.get("validator_address")
            for transport in network.get("validator_vpn_transports", [])
            if isinstance(transport, dict)
        ]
        peer_dials = [
            transport.get("dial_address")
            for transport in network.get("validator_vpn_transports", [])
            if isinstance(transport, dict)
        ]
        require(identity.get("node_id") == validator_id and identity.get("role") == "validator"
                and network.get("id") == CHAIN_ID and network.get("network_id") == NETWORK_ID
                and network.get("p2p_port") == 5622 and network.get("rpc_port") == 5640
                and network.get("ws_port") == 5660 and network.get("additional_dial_targets") == []
                and consensus.get("algorithm") == PROTOCOL
                and consensus.get("mode") == "posy_simplified_v3"
                and consensus.get("coordinator_id") == "" and consensus.get("producer_ids") == []
                and consensus.get("producer_turn_timeout_ms") == 0
                and consensus.get("max_validators") == 0
                and node.get("strict_validator_allowlist") is True
                and len(peer_addresses) == 5 and len(set(peer_addresses)) == 5
                and peer_dials == [f"10.69.10.{ordinal}:5622" for ordinal in range(2, 7)]
                and network.get("persistent_peers") == [address for address in peer_addresses
                                                        if address != identity.get("address")]
                and object_value(config, "p2p", f"{validator_id} p2p").get("listen_address")
                    == f"{expected_vpn_ip}:5622"
                and object_value(config, "p2p", f"{validator_id} p2p").get("discovery_port") == 5680
                and object_value(config, "telemetry", f"{validator_id} telemetry").get("metrics_bind")
                    == "127.0.0.1:6030",
                f"{validator_id} configuration is not the canonical dynamic-membership P3 VPN topology")
        config_hashes[validator_id] = digest

    actual_files = {
        path.relative_to(root).as_posix()
        for path in root.rglob("*") if path.is_file() and not path.is_symlink()
    }
    require(actual_files == expected_paths | {"manifest.json"},
            "validator bundle root contains files outside the public release contract")
    return validation, config_hashes


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--release-verifier", required=True, type=Path)
    parser.add_argument("--release-candidate", required=True, type=Path)
    parser.add_argument("--authority-record", required=True, type=Path)
    parser.add_argument("--desired-state", required=True, type=Path)
    parser.add_argument("--genesis", required=True, type=Path)
    parser.add_argument("--release-approval", required=True, type=Path)
    parser.add_argument("--validator-binary", required=True, type=Path)
    parser.add_argument("--validator-bundle-root", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()

    output = args.output.resolve()
    require(not output.exists(), f"output already exists: {output}")
    for path, label in [(args.release_candidate, "release candidate"),
                        (args.authority_record, "public authority record"),
                        (args.desired_state, "desired state"), (args.genesis, "Genesis"),
                        (args.release_approval, "V4 approval"),
                        (args.validator_binary, "validator binary")]:
        reject_symlink(path, label)

    verifier_line = verify_release_approval(
        args.release_verifier.resolve(), args.release_candidate.resolve(),
        args.authority_record.resolve(), args.desired_state.resolve(), args.genesis.resolve(),
        args.release_approval.resolve(),
    )
    parser_validation, config_hashes = validate_bundle_root(args.validator_bundle_root.resolve())
    binary_hash = sha256_file(args.validator_binary)
    require(parser_validation["runtime_validator_sha256"] == binary_hash,
            "runtime parser validation used a different validator binary")
    genesis = read_json(args.genesis)
    network = object_value(genesis, "network", "Genesis network")
    integrity = object_value(genesis, "integrity", "Genesis integrity")
    require(network.get("chain_id") == CHAIN_ID and network.get("network_id") == NETWORK_ID,
            "Genesis does not bind Chain 1266/testnet")
    genesis_hash = require_sha256(integrity.get("genesis_hash"), "Genesis hash")
    desired_state_bytes = read_bytes(args.desired_state)
    desired_state = read_json(args.desired_state)
    approval = read_json(args.release_approval)

    # Replace the raw-byte digest hook with the exact desired-state bytes,
    # avoiding any JSON reserialization ambiguity in the approval binding.
    request = object_value(approval, "request", "V4 approval request")
    require(request.get("desired_state_sha256") == hashlib.sha256(desired_state_bytes).hexdigest(),
            "V4 approval desired-state digest disagrees with exact file bytes")
    # The remainder of the structural checks does not re-serialize desired state.
    chain = object_value(desired_state, "chain", "desired state chain")
    state = object_value(desired_state, "state", "desired state state")
    artifacts = object_value(desired_state, "artifacts", "desired state artifacts")
    configurations = object_value(desired_state, "configuration", "desired state configuration")
    require(desired_state.get("schema_version") == 1
            and desired_state.get("release_id", "").startswith("chain1266-incarnation-5-")
            and chain.get("chain_id") == CHAIN_ID and chain.get("incarnation") == 5
            and chain.get("genesis_hash") == genesis_hash
            and state.get("consensus_schema_version") == 5
            and state.get("directory_namespace") == "chain-1266/incarnation-5"
            and state.get("mode") == "posy_simplified_v3"
            and state.get("coordinator_id") == "" and state.get("producer_ids") == []
            and state.get("producer_turn_timeout_ms") == 0 and "start_authority" not in desired_state
            and artifacts == {"validator_node": binary_hash}
            and configurations == config_hashes
            and request.get("desired_state_role_binary_sha256") == {"validator_node": binary_hash}
            and request.get("desired_state_role_configuration_sha256") == config_hashes,
            "desired state or V4 approval does not bind this exact fresh P3 package")

    package = {
        "schema_version": 1,
        "artifact_type": "testnet-v3-fresh-posy-release-package",
        "status": "PUBLIC_PACKAGE_VERIFIED_NOT_DEPLOYED",
        "chain_id": CHAIN_ID,
        "network_id": NETWORK_ID,
        "release_id": RELEASE_ID,
        "protocol_version": PROTOCOL,
        "initial_active_validator_ids": ACTIVE_IDS,
        "dynamic_validator_membership": True,
        "membership_ceiling": None,
        "private_material_present": False,
        "verification": {"public_v4_release_verifier": verifier_line},
        "artifacts": {
            "release_candidate_sha256": sha256_file(args.release_candidate),
            "public_authority_record_sha256": sha256_file(args.authority_record),
            "desired_state_sha256": hashlib.sha256(desired_state_bytes).hexdigest(),
            "genesis_sha256": sha256_file(args.genesis),
            "genesis_hash": genesis_hash,
            "release_approval_sha256": sha256_file(args.release_approval),
            "validator_binary_sha256": binary_hash,
            "validator_bundle_manifest_sha256": sha256_file(args.validator_bundle_root / "manifest.json"),
            "runtime_parser_validation_sha256": sha256_file(args.validator_bundle_root / "runtime-parser-validation.json"),
            "validator_configuration_sha256": config_hashes,
        },
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    try:
        output.write_text(json.dumps(package, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    except OSError as error:
        fail(f"cannot write {output}: {error}")
    print(f"FRESH_POSY_V3_RELEASE_PACKAGE_PUBLIC_MANIFEST_READY {output}")


if __name__ == "__main__":
    main()
