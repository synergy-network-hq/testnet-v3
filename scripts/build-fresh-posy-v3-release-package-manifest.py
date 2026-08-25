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
import base64
import hashlib
import json
import os
import struct
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
HEX_128 = HEX_64
INGRESS_RECORDS_ARTIFACT_TYPE = "testnet-v3-etdag-ingress-key-records"
INGRESS_RECORDS_STATUS = "generated_pending_target_admission_certificate"
INGRESS_REGISTRY_FORMAT = "synergy-posy-simplified-ingress-kem-registry-v1"
INGRESS_REGISTRY_DOMAIN = "PoSy/ETDAG/IngressKemKeyRegistry/v3"
INGRESS_REGISTRY_VERSION = 1
BOOTSTRAP_ETDAG_TARGET_HEIGHTS = (1, 2, 3)
INITIAL_CLUSTER_ID = 0


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


def require_sha3_512(value: Any, label: str) -> str:
    require(isinstance(value, str) and len(value) == 128 and set(value) <= set(HEX_128),
            f"{label} is not a lowercase SHA3-512 digest")
    return value


def object_value(value: dict[str, Any], key: str, label: str) -> dict[str, Any]:
    nested = value.get(key)
    require(isinstance(nested, dict), f"{label} must be an object")
    return nested


def reject_symlink(path: Path, label: str) -> None:
    require(not path.is_symlink(), f"{label} must not be a symlink")
    require(path.is_file(), f"{label} is not a regular file")


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def etdag_domain_digest(domain: str, payload: bytes) -> str:
    hasher = hashlib.sha3_512()
    domain_bytes = domain.encode("utf-8")
    hasher.update(struct.pack(">Q", len(domain_bytes)))
    hasher.update(domain_bytes)
    hasher.update(struct.pack(">Q", len(payload)))
    hasher.update(payload)
    return hasher.hexdigest()


def validate_one_etdag_ingress_artifact(
    ingress_records_path: Path,
    ingress_registry_path: Path,
    genesis_sha256: str,
    genesis_hash: str,
    target_height: int,
) -> dict[str, Any]:
    reject_symlink(ingress_records_path, "ETDAG ingress records")
    reject_symlink(ingress_registry_path, "ETDAG ingress registry")
    records_artifact = read_json(ingress_records_path)
    require(records_artifact.get("schema_version") == 1
            and records_artifact.get("artifact_type") == INGRESS_RECORDS_ARTIFACT_TYPE
            and records_artifact.get("status") == INGRESS_RECORDS_STATUS
            and records_artifact.get("chain_id") == CHAIN_ID
            and records_artifact.get("runtime_network_id") == NETWORK_ID
            and records_artifact.get("protocol_version") == PROTOCOL
            and records_artifact.get("genesis_candidate_sha256") == genesis_sha256
            and records_artifact.get("genesis_hash") == genesis_hash,
            "ETDAG ingress records are not bound to this exact Testnet-v3 Genesis")
    public_records = records_artifact.get("records")
    require(isinstance(public_records, list) and len(public_records) == len(ACTIVE_IDS),
            "ETDAG ingress records must contain exactly validator-02 through validator-06")

    wrapper_bytes = read_bytes(ingress_registry_path)
    try:
        wrapper = json.loads(wrapper_bytes)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        fail(f"cannot parse strict JSON {ingress_registry_path}: {error}")
    require(isinstance(wrapper, dict), "ETDAG ingress registry is not a JSON object")
    expected_wrapper_fields = {
        "format", "epoch_context_root", "epoch", "target_height",
        "assigned_cluster_id", "registry_root", "registry",
    }
    require(set(wrapper) == expected_wrapper_fields,
            "ETDAG ingress registry wrapper fields are not canonical")
    epoch_context_bytes = wrapper.get("epoch_context_root")
    require(isinstance(epoch_context_bytes, list) and len(epoch_context_bytes) == 32
            and all(isinstance(value, int) and not isinstance(value, bool)
                    and 0 <= value <= 255 for value in epoch_context_bytes),
            "ETDAG ingress registry epoch-context root is not exactly 32 bytes")
    epoch_context_root = bytes(epoch_context_bytes).hex()
    require(epoch_context_root != "0" * 64,
            "ETDAG ingress registry epoch-context root must not be zero")
    expected_filename = f"epoch-0-height-{target_height}-cluster-0.json"
    require(ingress_registry_path.name == expected_filename
            and ingress_registry_path.parent.name == epoch_context_root,
            f"ETDAG ingress registry must end in {epoch_context_root}/{expected_filename}")
    require(wrapper.get("format") == INGRESS_REGISTRY_FORMAT
            and wrapper.get("epoch") == 0
            and wrapper.get("target_height") == target_height
            and wrapper.get("assigned_cluster_id") == INITIAL_CLUSTER_ID,
            "ETDAG ingress registry wrapper target context is not canonical")

    registry = wrapper.get("registry")
    require(isinstance(registry, dict), "ETDAG ingress registry payload must be an object")
    expected_registry_fields = {
        "registry_version", "chain_id", "network_id", "protocol_version",
        "epoch", "target_height", "assigned_cluster_id", "records",
    }
    require(set(registry) == expected_registry_fields,
            "ETDAG ingress registry payload fields are not canonical")
    require(registry.get("registry_version") == INGRESS_REGISTRY_VERSION
            and registry.get("chain_id") == CHAIN_ID
            and registry.get("network_id") == NETWORK_ID
            and registry.get("protocol_version") == PROTOCOL
            and registry.get("epoch") == wrapper.get("epoch")
            and registry.get("target_height") == wrapper.get("target_height")
            and registry.get("assigned_cluster_id") == wrapper.get("assigned_cluster_id"),
            "ETDAG ingress registry payload context disagrees with its wrapper")
    registry_records = registry.get("records")
    require(isinstance(registry_records, list) and len(registry_records) == len(ACTIVE_IDS),
            "ETDAG ingress registry must contain exactly five records")

    canonical_registry_records: list[dict[str, Any]] = []
    registry_by_validator: dict[str, dict[str, Any]] = {}
    for record in registry_records:
        require(isinstance(record, dict)
                and set(record) == {"validator_id", "ingress_key_id", "share_index", "key_bytes"},
                "ETDAG ingress registry record fields are not canonical")
        validator_id = record.get("validator_id")
        ingress_key_id = record.get("ingress_key_id")
        share_index = record.get("share_index")
        key_bytes = record.get("key_bytes")
        require(validator_id in ACTIVE_IDS and validator_id not in registry_by_validator,
                "ETDAG ingress registry validators are not exactly validator-02 through validator-06")
        require(isinstance(ingress_key_id, str) and ingress_key_id.strip() != ""
                and isinstance(share_index, int) and not isinstance(share_index, bool)
                and 1 <= share_index <= 255
                and isinstance(key_bytes, list) and key_bytes
                and all(isinstance(value, int) and not isinstance(value, bool)
                        and 0 <= value <= 255 for value in key_bytes),
                f"ETDAG ingress registry record is invalid for {validator_id}")
        canonical_record = {
            "validator_id": validator_id,
            "ingress_key_id": ingress_key_id,
            "share_index": share_index,
            "key_bytes": key_bytes,
        }
        canonical_registry_records.append(canonical_record)
        registry_by_validator[validator_id] = canonical_record
    expected_order = sorted(
        canonical_registry_records,
        key=lambda record: (record["validator_id"], record["share_index"], record["ingress_key_id"]),
    )
    require(canonical_registry_records == expected_order
            and list(registry_by_validator) == ACTIVE_IDS
            and len({record["share_index"] for record in canonical_registry_records}) == len(ACTIVE_IDS)
            and len({record["ingress_key_id"] for record in canonical_registry_records}) == len(ACTIVE_IDS),
            "ETDAG ingress registry records are not unique and canonically ordered")

    public_by_validator: dict[str, dict[str, Any]] = {}
    for record in public_records:
        require(isinstance(record, dict), "ETDAG public ingress record must be an object")
        validator_id = record.get("validator_id")
        require(validator_id in ACTIVE_IDS and validator_id not in public_by_validator,
                "ETDAG public ingress validators are not exactly validator-02 through validator-06")
        public_by_validator[validator_id] = record
    require(list(public_by_validator) == ACTIVE_IDS,
            "ETDAG public ingress records are not canonically ordered")
    for validator_id in ACTIVE_IDS:
        public = public_by_validator[validator_id]
        runtime = registry_by_validator[validator_id]
        try:
            public_key = base64.b64decode(public.get("public_key_base64"), validate=True)
        except (TypeError, ValueError) as error:
            fail(f"ETDAG public ingress key is not canonical base64 for {validator_id}: {error}")
        require(public.get("ingress_key_id") == runtime["ingress_key_id"]
                and public.get("share_index") == runtime["share_index"]
                and list(public_key) == runtime["key_bytes"],
                f"ETDAG public ingress record disagrees with runtime registry for {validator_id}")

    canonical_registry = {
        "registry_version": INGRESS_REGISTRY_VERSION,
        "chain_id": CHAIN_ID,
        "network_id": NETWORK_ID,
        "protocol_version": PROTOCOL,
        "epoch": 0,
        "target_height": target_height,
        "assigned_cluster_id": INITIAL_CLUSTER_ID,
        "records": canonical_registry_records,
    }
    registry_root = etdag_domain_digest(
        INGRESS_REGISTRY_DOMAIN,
        canonical_json([
            INGRESS_REGISTRY_VERSION, CHAIN_ID, NETWORK_ID, PROTOCOL, 0,
            target_height, INITIAL_CLUSTER_ID, canonical_registry_records,
        ]),
    )
    require(require_sha3_512(wrapper.get("registry_root"), "ETDAG ingress registry root")
            == registry_root,
            "ETDAG ingress registry root does not match its canonical registry")
    canonical_wrapper = {
        "format": INGRESS_REGISTRY_FORMAT,
        "epoch_context_root": epoch_context_bytes,
        "epoch": 0,
        "target_height": target_height,
        "assigned_cluster_id": INITIAL_CLUSTER_ID,
        "registry_root": registry_root,
        "registry": canonical_registry,
    }
    require(wrapper_bytes == canonical_json(canonical_wrapper),
            "ETDAG ingress registry is not exact canonical compact JSON")
    return {
        "epoch_context_root": epoch_context_root,
        "epoch": 0,
        "target_height": target_height,
        "assigned_cluster_id": INITIAL_CLUSTER_ID,
        "registry_root_sha3_512": registry_root,
    }


def validate_etdag_ingress_artifacts(
    ingress_records_path: Path,
    ingress_registry_directory: Path,
    genesis_sha256: str,
    genesis_hash: str,
) -> dict[str, Any]:
    require(ingress_registry_directory.is_dir() and not ingress_registry_directory.is_symlink(),
            "ETDAG ingress registry directory must be a real directory")
    contexts: dict[str, dict[str, Any]] = {}
    epoch_context_root: str | None = None
    for target_height in BOOTSTRAP_ETDAG_TARGET_HEIGHTS:
        path = ingress_registry_directory / f"epoch-0-height-{target_height}-cluster-0.json"
        context = validate_one_etdag_ingress_artifact(
            ingress_records_path, path, genesis_sha256, genesis_hash, target_height,
        )
        if epoch_context_root is None:
            epoch_context_root = context["epoch_context_root"]
            require(ingress_registry_directory.name == epoch_context_root,
                    "ETDAG ingress registry directory does not match its epoch-context root")
        else:
            require(context["epoch_context_root"] == epoch_context_root,
                    "ETDAG bootstrap ingress registries disagree on epoch-context root")
        contexts[str(target_height)] = {
            "sha256": sha256_file(path),
            "registry_root_sha3_512": context["registry_root_sha3_512"],
        }
    return {
        "epoch_context_root": epoch_context_root,
        "epoch": 0,
        "assigned_cluster_id": INITIAL_CLUSTER_ID,
        "registries": contexts,
    }


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
    parser.add_argument("--etdag-ingress-records", required=True, type=Path)
    parser.add_argument("--etdag-ingress-registries", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()

    output = args.output.resolve()
    require(not output.exists(), f"output already exists: {output}")
    for path, label in [(args.release_candidate, "release candidate"),
                        (args.authority_record, "public authority record"),
                        (args.desired_state, "desired state"), (args.genesis, "Genesis"),
                        (args.release_approval, "V4 approval"),
                        (args.validator_binary, "validator binary"),
                        (args.etdag_ingress_records, "ETDAG ingress records")]:
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
    genesis_sha256 = sha256_file(args.genesis)
    ingress_context = validate_etdag_ingress_artifacts(
        args.etdag_ingress_records.resolve(),
        args.etdag_ingress_registries.resolve(),
        genesis_sha256,
        genesis_hash,
    )
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
            "genesis_sha256": genesis_sha256,
            "genesis_hash": genesis_hash,
            "release_approval_sha256": sha256_file(args.release_approval),
            "validator_binary_sha256": binary_hash,
            "validator_bundle_manifest_sha256": sha256_file(args.validator_bundle_root / "manifest.json"),
            "runtime_parser_validation_sha256": sha256_file(args.validator_bundle_root / "runtime-parser-validation.json"),
            "validator_configuration_sha256": config_hashes,
            "etdag_ingress_records_sha256": sha256_file(args.etdag_ingress_records),
            "etdag_ingress_registry_epoch_context_root": ingress_context["epoch_context_root"],
            "etdag_ingress_registry_epoch": ingress_context["epoch"],
            "etdag_ingress_registry_assigned_cluster_id": ingress_context["assigned_cluster_id"],
            "etdag_ingress_bootstrap_registries": ingress_context["registries"],
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
