#!/usr/bin/env python3
"""Render public-only validator-02..06 deployment inputs for fresh PoSy v3.

This program never opens, decrypts, copies, or names a private ceremony file.
It refuses to replace an output root and binds every rendered configuration to
the final Genesis, completed public ceremony index, and validator VPN registry.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import tomllib
from pathlib import Path
from typing import Any


CHAIN_ID = 1266
NETWORK_ID = "testnet"
RELEASE_ID = "testnet-v3"
PROTOCOL = "posy/3.0"
ACTIVE_IDS = [f"validator-{ordinal:02d}" for ordinal in range(2, 7)]
ALL_IDS = [f"validator-{ordinal:02d}" for ordinal in range(1, 22)]
VPN_IPS = {validator_id: f"10.69.10.{ordinal}" for ordinal, validator_id in enumerate(ACTIVE_IDS, 2)}
SSH_ALIASES = {validator_id: f"synergy-val{ordinal}" for ordinal, validator_id in enumerate(ACTIVE_IDS, 2)}
LOWER_HEX_64 = re.compile(r"[0-9a-f]{64}")
LOWER_HEX_128 = re.compile(r"[0-9a-f]{128}")


def fail(message: str) -> "NoReturn":
    raise SystemExit(f"generate-posy-v3-validator-deployment-bundles: {message}")


def read_bytes(path: Path) -> bytes:
    try:
        return path.read_bytes()
    except OSError as error:
        fail(f"cannot read {path}: {error}")


def read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(read_bytes(path))
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        fail(f"cannot parse strict JSON {path}: {error}")
    if not isinstance(value, dict):
        fail(f"{path} is not a JSON object")
    return value


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    return sha256_bytes(read_bytes(path))


def require(condition: bool, message: str) -> None:
    if not condition:
        fail(message)


def object_at(value: dict[str, Any], *keys: str) -> dict[str, Any]:
    current: Any = value
    for key in keys:
        require(isinstance(current, dict) and key in current, f"missing JSON object /{'/'.join(keys)}")
        current = current[key]
    require(isinstance(current, dict), f"JSON /{'/'.join(keys)} is not an object")
    return current


def validate_public_inputs(
    genesis_path: Path,
    ceremony_index_path: Path,
    ceremony_completion_path: Path,
    vpn_registry_path: Path,
) -> tuple[dict[str, Any], dict[str, dict[str, Any]], dict[str, dict[str, Any]]]:
    genesis = read_json(genesis_path)
    ceremony = read_json(ceremony_index_path)
    completion = read_json(ceremony_completion_path)
    vpn = read_json(vpn_registry_path)

    network = object_at(genesis, "network")
    require(network.get("chain_id") == CHAIN_ID, "Genesis chain ID is not 1266")
    require(network.get("network_id") == NETWORK_ID, "Genesis technical network ID is not testnet")
    require(network.get("network_slug") == NETWORK_ID, "Genesis network slug is not testnet")
    require(network.get("consensus_version") == PROTOCOL, "Genesis consensus version is not posy/3.0")
    integrity = object_at(genesis, "integrity")
    genesis_hash = integrity.get("genesis_hash")
    require(isinstance(genesis_hash, str) and LOWER_HEX_64.fullmatch(genesis_hash) is not None,
            "Genesis integrity.genesis_hash is not canonical SHA-256")
    parameter_root = integrity.get("etdag_parameter_root_sha3_512")
    fee_root = integrity.get("etdag_fee_schedule_root_sha3_512")
    require(isinstance(parameter_root, str) and LOWER_HEX_128.fullmatch(parameter_root) is not None,
            "final Genesis has no canonical ETDAG parameter root")
    require(isinstance(fee_root, str) and LOWER_HEX_128.fullmatch(fee_root) is not None,
            "final Genesis has no canonical ETDAG fee-schedule root")

    deployment = object_at(genesis, "genesis_deployment")
    require(deployment.get("status") == "EXECUTED_AND_BOUND",
            "Genesis deployment is not EXECUTED_AND_BOUND")
    require(deployment.get("deployment_count") == 9 and deployment.get("initialization_count") == 27,
            "Genesis deployment does not contain nine deployments and 27 initializations")
    require(deployment.get("genesis_deployer_lifecycle") == "PermanentlyRetired",
            "Genesis deployment authority is not permanently retired")
    for field in ("receipt_root", "post_deployment_execution_state_root",
                  "post_deployment_aivm_state_root", "deployment_manifest_hash"):
        value = deployment.get(field)
        require(isinstance(value, str) and LOWER_HEX_64.fullmatch(value) is not None,
                f"Genesis deployment {field} is not canonical")

    etdag = object_at(genesis, "etdag_governance")
    require(etdag.get("schema_version") == 1 and etdag.get("status") == "FINALIZED_AND_BOUND",
            "Genesis ETDAG governance is not finalized and bound")
    require(object_at(etdag, "parameter_artifact").get("etdag_parameter_root_sha3_512") == parameter_root,
            "Genesis ETDAG parameter artifact disagrees with integrity root")
    require(object_at(etdag, "fee_schedule_artifact").get("etdag_fee_schedule_root_sha3_512") == fee_root,
            "Genesis ETDAG fee artifact disagrees with integrity root")
    anchor = object_at(genesis, "etdag_membership_anchor")
    require(anchor.get("schema") == "synergy-etdag-governed-membership-proof-v1",
            "Genesis ETDAG membership anchor has the wrong schema")
    require(anchor.get("genesis_hash") == genesis_hash,
            "Genesis ETDAG membership anchor does not bind the Genesis hash")
    require(anchor.get("deployed_execution_state_root") == deployment["post_deployment_execution_state_root"],
            "Genesis ETDAG membership anchor does not bind executed state")
    anchor_validators = object_at(anchor, "initial_validator_set").get("validators")
    require(isinstance(anchor_validators, list), "Genesis ETDAG membership anchor has no validator set")
    anchor_validator_ids = [
        item.get("validator_id") for item in anchor_validators if isinstance(item, dict)
    ]
    require(len(anchor_validator_ids) == 5 and all(isinstance(item, str) for item in anchor_validator_ids),
            "Genesis ETDAG membership anchor validator IDs are malformed")
    require(sorted(anchor_validator_ids) == ACTIVE_IDS,
            "Genesis ETDAG membership anchor does not bind validator-02 through validator-06")

    activation = object_at(genesis, "consensus", "posy_v3_activation")
    require(activation.get("binding_schema_version") == 1, "Genesis simplified activation schema is not 1")
    require(activation.get("binding_status") == "FINALIZED_AND_GENESIS_BOUND",
            "Genesis simplified activation is not finalized and Genesis-bound")
    require(activation.get("activation_epoch") == 0 and activation.get("activation_height") == 1,
            "Genesis simplified activation does not start epoch 0 at block 1")
    manifest = object_at(activation, "manifest")
    require(manifest.get("status") == "FINALIZED", "Genesis simplified manifest is not FINALIZED")
    require(manifest.get("chain_id") == CHAIN_ID and manifest.get("network_id") == NETWORK_ID,
            "Genesis simplified manifest has the wrong network identity")
    require(manifest.get("release_id") == RELEASE_ID and manifest.get("protocol_version") == PROTOCOL,
            "Genesis simplified manifest has the wrong release or protocol")
    require(manifest.get("active_validator_count") == 5, "Genesis must start with exactly five active validators")
    require(manifest.get("required_distinct_signers") == 4, "Genesis initial quorum must require four distinct signers")
    require(anchor.get("initial_consensus_parameter_root") == activation.get("parameter_root_sha3_512"),
            "Genesis ETDAG membership anchor disagrees with simplified consensus root")
    for field in ("target_block_time_ms", "proposal_timeout_ms", "vote_timeout_ms",
                  "max_round_timeout_ms", "epoch_length_blocks"):
        require(isinstance(manifest.get(field), int) and manifest[field] > 0,
                f"Genesis simplified manifest {field} is invalid")
    require(manifest["target_block_time_ms"] % 1000 == 0,
            "node TOML cannot represent a sub-second Genesis target block time")

    frozen = object_at(activation, "frozen_validator_set")
    validators = frozen.get("validators")
    require(frozen.get("epoch") == 0 and isinstance(validators, list),
            "Genesis frozen validator set is invalid")
    genesis_by_id: dict[str, dict[str, Any]] = {}
    for validator in validators:
        require(isinstance(validator, dict), "Genesis validator entry is not an object")
        validator_id = validator.get("validator_id")
        require(isinstance(validator_id, str) and validator_id not in genesis_by_id,
                "Genesis validator IDs are absent or duplicated")
        genesis_by_id[validator_id] = validator
    require(list(genesis_by_id) == ACTIVE_IDS, "Genesis active set must be canonical validator-02 through validator-06")
    for validator_id, validator in genesis_by_id.items():
        require(validator.get("status") == "ACTIVE" and validator.get("activation_epoch") == 0,
                f"{validator_id} is not active at epoch 0")
        require(isinstance(validator.get("validator_uma_id"), str), f"{validator_id} has no synv identity")

    require(ceremony.get("chain_id") == CHAIN_ID and ceremony.get("network_id") == NETWORK_ID,
            "ceremony index has the wrong network identity")
    require(ceremony.get("release_id") == RELEASE_ID and ceremony.get("validator_count") == 21,
            "ceremony index does not describe all 21 Testnet-v3 validators")
    require(ceremony.get("dynamic_validator_membership") is True,
            "ceremony index does not declare dynamic validator membership")
    require(ceremony.get("expected_validator_ids") == ALL_IDS,
            "ceremony index validator IDs are not canonical validator-01 through validator-21")
    require(ceremony.get("initial_active_validator_ids") == ACTIVE_IDS,
            "ceremony index initial active set is not validator-02 through validator-06")
    records = ceremony.get("records")
    require(isinstance(records, list) and len(records) == 21, "ceremony index must have exactly 21 records")
    ceremony_by_id: dict[str, dict[str, Any]] = {}
    for record in records:
        require(isinstance(record, dict), "ceremony record is not an object")
        validator_id = record.get("validator_id")
        require(validator_id in ALL_IDS and validator_id not in ceremony_by_id,
                "ceremony record validator ID is absent, unknown, or duplicated")
        ceremony_by_id[validator_id] = record
    require(list(ceremony_by_id) == ALL_IDS, "ceremony records are not in canonical validator order")

    require(completion.get("status") == "COMPLETE", "validator identity ceremony is not COMPLETE")
    require(completion.get("chain_id") == CHAIN_ID and completion.get("network_id") == NETWORK_ID,
            "ceremony completion has the wrong network identity")
    require(completion.get("release_id") == RELEASE_ID and completion.get("validator_count") == 21,
            "ceremony completion does not bind all 21 Testnet-v3 validators")
    require(completion.get("initial_active_validator_count") == 5,
            "ceremony completion does not bind five initial active validators")
    for flag in ("all_addresses_rederived", "all_peer_ids_rederived",
                 "all_public_private_correspondence_verified", "all_output_hashes_verified"):
        require(completion.get(flag) is True, f"ceremony completion flag {flag} is not true")
    require(completion.get("ceremony_index_sha256") == sha256_file(ceremony_index_path),
            "ceremony completion does not hash-bind the supplied ceremony index")

    for validator_id in ACTIVE_IDS:
        record = ceremony_by_id[validator_id]
        validator = genesis_by_id[validator_id]
        require(record.get("genesis_status") == "ACTIVE", f"{validator_id} ceremony status is not ACTIVE")
        require(record.get("address") == validator.get("validator_uma_id"),
                f"{validator_id} Genesis identity differs from the completed ceremony")

    # Only the new, public NetBird desired-state adapter may supply fresh P3
    # validator routes.  The older Innernet registry has a different identity
    # lineage and must not be substituted merely because its IP range looks
    # similar.
    require(vpn.get("schema_version") == "synergy-testnet-v3-fresh-vpn-provider-plan-v1",
            "VPN registry is not the fresh Testnet-v3 provider plan")
    require(vpn.get("artifact_type") == "testnet-v3-fresh-validator-vpn-provider-plan",
            "VPN registry has the wrong fresh provider artifact type")
    require(vpn.get("chain_id") == CHAIN_ID and vpn.get("network_id") == NETWORK_ID,
            "VPN registry has the wrong network identity")
    require(vpn.get("release_id") == RELEASE_ID and vpn.get("protocol_version") == PROTOCOL,
            "VPN registry has the wrong release or protocol")
    require(vpn.get("genesis_boundary") == "fresh_genesis_block_zero",
            "VPN registry is not bound to fresh block zero")
    require(vpn.get("private_material_present") is False, "VPN public registry declares private material")
    provider = object_at(vpn, "provider")
    require(provider.get("kind") == "netbird" and provider.get("mode") == "external_authenticated_reconciliation",
            "VPN registry does not use the approved fresh NetBird provider mode")
    require(provider.get("hub_udp_port") == 51820, "VPN registry has the wrong public hub UDP port")
    hub = object_at(vpn, "hub")
    require(hub == {"vpn_ip": "10.69.0.1", "public_endpoint": "68.183.139.56:51820", "udp_port": 51820},
            "VPN registry hub assignment is not canonical")
    participants = vpn.get("participants")
    require(isinstance(participants, list), "VPN registry participants are missing")
    vpn_by_id = {
        item.get("validator_id"): item
        for item in participants
        if isinstance(item, dict) and item.get("role") == "validator"
    }
    require(set(vpn_by_id) == set(ALL_IDS),
            "VPN registry must carry the full pre-generated validator-01 through validator-21 transport pool")
    for validator_id in ACTIVE_IDS:
        participant = vpn_by_id[validator_id]
        require(participant.get("vpn_ip") == VPN_IPS[validator_id], f"{validator_id} VPN IP is not canonical")
        require(participant.get("ssh_alias") == SSH_ALIASES[validator_id], f"{validator_id} SSH alias is not canonical")
        declared_address = participant.get("synv_address")
        require(declared_address == ceremony_by_id[validator_id]["address"],
                f"{validator_id} VPN registry identity is absent or conflicts with ceremony")
        require(participant.get("activation_status") == "GENESIS_ACTIVE_PROVIDER_ENROLLMENT_REQUIRED",
                f"{validator_id} VPN registry activation state is not fresh Genesis-active")
    for validator_id in ALL_IDS:
        participant = vpn_by_id[validator_id]
        ordinal = int(validator_id.rsplit("-", 1)[1])
        require(participant.get("vpn_ip") == f"10.69.10.{ordinal}",
                f"{validator_id} VPN IP is not its canonical dynamic slot")
    dynamic = object_at(vpn, "dynamic_onboarding")
    require(dynamic.get("governed_extension_allowed") is True,
            "VPN registry does not support governed dynamic validator onboarding")
    require(dynamic.get("usable_validator_vpn_ordinal_range") == {"first": 1, "last": 254},
            "VPN registry has an invalid dynamic validator VPN range")
    require(dynamic.get("transport_not_consensus_authority") is True,
            "VPN registry incorrectly treats transport as consensus authority")
    return manifest, ceremony_by_id, vpn_by_id


def toml_string(value: str) -> str:
    return json.dumps(value, ensure_ascii=True)


def toml_array(values: list[str]) -> str:
    return "[" + ", ".join(toml_string(value) for value in values) + "]"


def contains_secret_bearing_field(value: Any) -> bool:
    if isinstance(value, dict):
        for key, nested in value.items():
            normalized = str(key).lower()
            if "private_key" in normalized or "passphrase" in normalized or "secret" in normalized:
                return True
            if contains_secret_bearing_field(nested):
                return True
    elif isinstance(value, list):
        return any(contains_secret_bearing_field(item) for item in value)
    return False


def render_config(validator_id: str, address: str, manifest: dict[str, Any], ceremony_by_id: dict[str, dict[str, Any]]) -> bytes:
    vpn_ip = VPN_IPS[validator_id]
    all_addresses = [ceremony_by_id[item]["address"] for item in ACTIVE_IDS]
    peer_addresses = [value for value in all_addresses if value != address]
    transports = "\n".join(
        "[[network.validator_vpn_transports]]\n"
        f"validator_address = {toml_string(ceremony_by_id[item]['address'])}\n"
        f"dial_address = {toml_string(VPN_IPS[item] + ':5622')}"
        for item in ACTIVE_IDS
    )
    block_time_secs = manifest["target_block_time_ms"] // 1000
    text = f'''# Generated public-only fresh Testnet-v3 validator configuration.
# No private key, passphrase, VPN private key, or custody bundle is present.

[identity]
node_id = {toml_string(validator_id)}
role = "validator"
role_display = "validator"
address = {toml_string(address)}
label = {toml_string(validator_id)}

[role]
compiled_profile = "validator_node"
services = ["consensus"]

[network]
id = 1266
network_id = "testnet"
name = "Synergy Testnet v3"
p2p_port = 5622
rpc_port = 5640
ws_port = 5660
max_peers = 50
bootnodes = []
seed_servers = []
bootstrap_dns_records = []
persistent_peers = {toml_array(peer_addresses)}
# A validator target is always an authenticated `synv...` identity.  The
# separately signed/public transport registry resolves that identity to the
# canonical Validator VPN address; raw endpoint targets are deliberately not
# release inputs.
additional_dial_targets = []

{transports}

[blockchain]
block_time = {block_time_secs}
max_gas_limit = "0x2fefd8"
chain_id = 1266

[consensus]
algorithm = "posy/3.0"
mode = "posy_simplified_v3"
coordinator_id = ""
producer_ids = []
producer_turn_timeout_ms = 0
block_time_secs = {block_time_secs}
epoch_length = {manifest['epoch_length_blocks']}
target_block_time_ms = {manifest['target_block_time_ms']}
proposal_timeout_ms = {manifest['proposal_timeout_ms']}
prevote_timeout_ms = {manifest['vote_timeout_ms']}
precommit_timeout_ms = {manifest['vote_timeout_ms']}
max_round_timeout_ms = {manifest['max_round_timeout_ms']}
min_validators = 5
validator_cluster_size = 5
validator_vote_threshold = 4
max_validators = 0
status_ready_gate_enabled = true
status_ready_min_validators = 4
status_ready_genesis_grace_secs = 15
allow_genesis_status_bypass = false
mesh_settle_secs = 1
leader_timeout_secs = 0
vote_timeout_secs = 2
block_timeout_secs = 6
penalization_enabled = true
synergy_score_decay_rate = 0.05
vrf_enabled = true
vrf_seed_epoch_interval = {manifest['epoch_length_blocks']}
max_synergy_points_per_epoch = 100
max_tasks_per_validator = 10

[consensus.reward_weighting]
task_accuracy = 0.5
uptime = 0.3
collaboration = 0.2

[logging]
log_level = "info"
log_file = "data/logs/synergy-node.log"
enable_console = true
max_file_size = 10485760
max_files = 5

[rpc]
bind_address = "127.0.0.1:5640"
enable_http = true
http_port = 5640
enable_ws = true
ws_port = 5660
enable_grpc = true
grpc_port = 5640
cors_enabled = false
cors_origins = []

[p2p]
listen_address = {toml_string(vpn_ip + ':5622')}
public_address = {toml_string(vpn_ip + ':5622')}
discovery_listen_address = {toml_string(vpn_ip + ':5680')}
discovery_public_address = {toml_string(vpn_ip + ':5680')}
node_name = {toml_string(validator_id)}
enable_discovery = false
enable_peer_exchange = false
reject_private_advertise_addrs = true
discovery_port = 5680
heartbeat_interval = 10
bootstrap_refresh_secs = 10

[storage]
database = "rocksdb"
path = "data/chain"
enable_pruning = true
pruning_interval = 86400

[node]
bootstrap_only = false
auto_register_validator = false
validator_address = {toml_string(address)}
strict_validator_allowlist = true
allowed_validator_addresses = {toml_array(all_addresses)}

[validator]
participation = "active"
verify_quorum_certificates = true
state_sync_before_join = true

[telemetry]
enabled = true
metrics_bind = "127.0.0.1:6030"
structured_logs = true
log_level = "info"
'''
    return text.encode("utf-8")


def validate_with_runtime_parser(runtime_validator: Path, files: dict[str, bytes], output_root: Path) -> bytes:
    """Use the release runtime's actual TOML parser before publishing a bundle.

    This deliberately invokes only the parser-validation subcommand.  It does
    not start a node, open custody material, bind a socket, or load release
    state.  The command is supplied by the exact validator binary that will be
    recorded in the desired state, so a Python TOML parse cannot become a
    substitute for runtime acceptance.
    """
    require(runtime_validator.is_file(), f"runtime config validator is not a file: {runtime_validator}")
    require(os.access(runtime_validator, os.X_OK),
            f"runtime config validator is not executable: {runtime_validator}")
    sanitized_environment = {
        key: value for key, value in os.environ.items() if not key.startswith("SYNERGY_")
    }
    parsed_configs: dict[str, str] = {}
    for validator_id in ACTIVE_IDS:
        relative = f"{validator_id}/config.toml"
        destination = output_root / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(files[relative])
        os.chmod(destination, stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IROTH)
        try:
            result = subprocess.run(
                [str(runtime_validator), "validate-config", "--config", str(destination)],
                check=False,
                cwd=output_root,
                env=sanitized_environment,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=30,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            fail(f"cannot run runtime config validator for {validator_id}: {error}")
        if result.returncode != 0:
            detail = (result.stderr or result.stdout).strip()
            fail(f"runtime config parser rejected {validator_id}: {detail or 'no diagnostic'}")
        expected = f"CHAIN1266_VALIDATOR_CONFIG_PARSED validator_id={validator_id}"
        require(expected in result.stdout,
                f"runtime config validator did not attest {validator_id}")
        parsed_configs[validator_id] = sha256_bytes(files[relative])
    evidence = {
        "schema_version": 1,
        "artifact_type": "testnet-v3-posy-validator-runtime-parser-validation",
        "status": "RUNTIME_PARSER_ACCEPTED",
        "chain_id": CHAIN_ID,
        "network_id": NETWORK_ID,
        "release_id": RELEASE_ID,
        "protocol_version": PROTOCOL,
        "runtime_validator_sha256": sha256_file(runtime_validator),
        "validated_configuration_sha256": parsed_configs,
    }
    return (json.dumps(evidence, indent=2, sort_keys=True) + "\n").encode("utf-8")


def write_new_root(output_root: Path, files: dict[str, bytes], manifest: dict[str, Any]) -> None:
    require(not output_root.exists(), f"output root already exists: {output_root}")
    output_root.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=f".{output_root.name}.", dir=output_root.parent))
    try:
        for relative, content in files.items():
            destination = staging / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(content)
            os.chmod(destination, stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IROTH)
        manifest_bytes = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode()
        (staging / "manifest.json").write_bytes(manifest_bytes)
        for relative, expected in manifest["outputs"].items():
            require(sha256_file(staging / relative) == expected, f"output read-back hash mismatch: {relative}")
        os.rename(staging, output_root)
    except BaseException:
        shutil.rmtree(staging, ignore_errors=True)
        raise


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--genesis", required=True, type=Path)
    parser.add_argument("--ceremony-index", required=True, type=Path)
    parser.add_argument("--ceremony-completion", required=True, type=Path)
    parser.add_argument("--vpn-registry", required=True, type=Path)
    parser.add_argument("--runtime-config-validator", required=True, type=Path,
                        help="exact freshly built synergy-validator-node with validate-config support")
    parser.add_argument("--output-root", required=True, type=Path)
    args = parser.parse_args()

    manifest, ceremony_by_id, vpn_by_id = validate_public_inputs(
        args.genesis, args.ceremony_index, args.ceremony_completion, args.vpn_registry
    )
    files: dict[str, bytes] = {}
    deployments = []
    for validator_id in ACTIVE_IDS:
        address = ceremony_by_id[validator_id]["address"]
        relative = f"{validator_id}/config.toml"
        files[relative] = render_config(validator_id, address, manifest, ceremony_by_id)
        try:
            parsed = tomllib.loads(files[relative].decode("utf-8"))
        except (UnicodeDecodeError, tomllib.TOMLDecodeError) as error:
            fail(f"rendered {validator_id} configuration is invalid TOML: {error}")
        require(parsed.get("identity", {}).get("node_id") == validator_id,
                f"rendered {validator_id} configuration lost its exact node identity")
        require(parsed.get("node", {}).get("validator_address") == address,
                f"rendered {validator_id} configuration lost its Genesis address")
        require(parsed.get("consensus", {}).get("mode") == "posy_simplified_v3",
                f"rendered {validator_id} configuration lost fresh P3 mode")
        require(not contains_secret_bearing_field(parsed),
                f"rendered {validator_id} configuration contains a secret-bearing field")
        deployments.append({
            "validator_id": validator_id,
            "validator_address": address,
            "peer_id": ceremony_by_id[validator_id]["peer_id"],
            "ssh_alias": vpn_by_id[validator_id]["ssh_alias"],
            "vpn_ip": vpn_by_id[validator_id]["vpn_ip"],
            "config": relative,
        })
    # The runtime parser needs concrete files.  It receives a private staging
    # directory that is atomically promoted only after every config is accepted.
    output_root = args.output_root.resolve()
    require(not output_root.exists(), f"output root already exists: {output_root}")
    output_root.parent.mkdir(parents=True, exist_ok=True)
    parser_staging = Path(tempfile.mkdtemp(prefix=f".{output_root.name}.parser.", dir=output_root.parent))
    try:
        files["runtime-parser-validation.json"] = validate_with_runtime_parser(
            args.runtime_config_validator.resolve(), files, parser_staging
        )
    finally:
        shutil.rmtree(parser_staging, ignore_errors=True)

    output_manifest = {
        "schema_version": 1,
        "artifact_type": "testnet-v3-posy-validator-public-deployment-bundle",
        "status": "PUBLIC_CONFIGS_RENDERED_NOT_STARTED",
        "chain_id": CHAIN_ID,
        "chain_incarnation": 5,
        "consensus_state_schema_version": 5,
        "network_id": NETWORK_ID,
        "release_id": RELEASE_ID,
        "protocol_version": PROTOCOL,
        "private_material_present": False,
        "initial_active_validator_ids": ACTIVE_IDS,
        "inputs": {
            "genesis_file_sha256": sha256_file(args.genesis),
            "genesis_hash": read_json(args.genesis)["integrity"]["genesis_hash"],
            "ceremony_index_sha256": sha256_file(args.ceremony_index),
            "ceremony_completion_sha256": sha256_file(args.ceremony_completion),
            "vpn_registry_sha256": sha256_file(args.vpn_registry),
        },
        "deployments": deployments,
        "outputs": {relative: sha256_bytes(content) for relative, content in sorted(files.items())},
    }
    write_new_root(output_root, files, output_manifest)
    print(f"POSY_V3_VALIDATOR_PUBLIC_BUNDLES_READY {output_root}")


if __name__ == "__main__":
    main()
