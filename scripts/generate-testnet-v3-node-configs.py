#!/usr/bin/env python3
"""Generate Testnet-v3 node configs from finalized, public launch records.

This tool intentionally contains no private key, passphrase, or live-node logic.
It fails closed unless the supplied Genesis is deployment-bound, its exact
ML-DSA-87 governance approval has been verified by the runtime verifier, and a
matching Phase-7/8 apply-integrity record proves that the candidate was applied.
The generated files are deterministic and are bound to the exact Genesis,
topology, VPN registry, consensus manifest root, approval, and apply record.

The coordinator-signed validator transport registry is deliberately not produced
here.  Runtime production code will not use static validator VPN transports as a
fallback, so publication of that signed registry remains an independent launch
gate.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import plistlib
import re
import subprocess
import sys
import tempfile
import tomllib
from pathlib import Path
from typing import Any


GENERATOR_VERSION = "testnet-v3-node-configs/v7-coordinated-round-robin-p1"
CHAIN_ID = 1266
NETWORK_ID = "synergy-testnet-v3"
VALIDATOR_P2P_PORT = 5622
COORDINATED_CONSENSUS_MODE = "coordinated_round_robin_v1"
COORDINATED_COORDINATOR_ID = "validator-1"
COORDINATED_PRODUCER_IDS = (
    "validator-2",
    "validator-3",
    "validator-4",
    "validator-5",
    "validator-6",
)
RELEASE_INTEGRITY_STATUS = "PHASE_7_8_APPLIED_PENDING_RELEASE_GATES"
RELEASE_APPROVAL_RESULT = "RELEASE_APPROVAL_VERIFIED"
UNRESOLVED_PLACEHOLDER = re.compile(r"<[A-Z][A-Z0-9_:-]*>")

# Every production node receives this same immutable Genesis payload.  The
# runtime's canonical loader reads SYNERGY_GENESIS_FILE; it must never fall
# back to a working-directory-relative config/genesis.json in a launch unit.
LINUX_GENESIS_DEPLOY_PATH = "/etc/synergy/testnet-v3/genesis.json"
MACOS_ARCHIVE_GENESIS_DEPLOY_PATH = "/Users/Shared/Synergy/archive-validator/workspace/config/testnet-v3-genesis.json"
GENESIS_DEPLOY_MODE = "0444"
GENESIS_PAYLOAD_PATH = Path("canonical-genesis/genesis.json")
GENESIS_CHECKSUM_PATH = Path("canonical-genesis/genesis.json.sha256")
SYSTEMD_GENESIS_DROPIN_NAME = "50-synergy-testnet-v3-genesis.conf"
LAUNCHD_GENESIS_BINDING_NAME = "50-synergy-testnet-v3-genesis.binding.plist"
SUPPORT_SERVICE_SEQUENCE_PAYLOAD_PATH = Path("support-service-activation-sequence.json")

# This sequence is deliberately a release artifact rather than an automation
# instruction.  It keeps validator activation behind the supporting network
# services, but never permits a generator or an activation plan to start a
# service or to infer live readiness from static configuration.
SUPPORT_SERVICE_ACTIVATION_STAGES = (
    (
        "boot_and_seed",
        1,
        (
            ("bootnodes", "bootnode1"),
            ("bootnodes", "bootnode2"),
            ("bootnodes", "bootnode3"),
            ("seed_servers", "seed1"),
            ("seed_servers", "seed2"),
            ("seed_servers", "seed3"),
        ),
        (
            "Every listed bootnode or seed service is explicitly activated only after its local service-contract, port, identity, runtime, and immutable Genesis checks pass.",
            "Independent host evidence records an active service and a listener bound to the approved Testnet-v3 endpoint.",
            "Each service reports or is inspected for chain 1266, network synergy-testnet-v3, and the exact canonical Genesis SHA-256 before the relayer stage is considered.",
        ),
    ),
    (
        "relayers",
        2,
        (("relayers", "relay1"), ("relayers", "relay2"), ("relayers", "relay3")),
        (
            "The complete boot-and-seed readiness evidence is accepted first.",
            "Each relayer has an active service, its V3 Genesis binding, and successful approved bootstrap connectivity without a legacy/Testnet-v2 fallback.",
            "The three relayers present mutually consistent chain, network, Genesis SHA-256, and consensus-parameter-root observations.",
        ),
    ),
    (
        "rpc_gateway",
        3,
        (("rpc_gateways", "rpc-gateway"),),
        (
            "The complete relayer readiness evidence is accepted first.",
            "The RPC gateway has an active service and exposes a health/identity response bound to chain 1266, network synergy-testnet-v3, and the exact canonical Genesis SHA-256.",
            "The RPC endpoint is observed through the approved relayer-backed path; a process-list or open-port observation alone is insufficient.",
        ),
    ),
    (
        "atlas_explorer_indexer",
        4,
        (("explorer_indexers", "explorer-indexer"),),
        (
            "The complete RPC-gateway readiness evidence is accepted first.",
            "Atlas explorer indexer has an active service, is configured only for the approved V3 RPC source, and reports chain 1266, network synergy-testnet-v3, and the exact canonical Genesis SHA-256.",
            "Indexer startup evidence includes a successful canonical RPC read and an indexed-height/lag observation; neither is asserted by this offline artifact.",
        ),
    ),
)


class ValidationError(ValueError):
    """An input is not safe to bind into a Testnet-v3 launch config."""


def linux_service_contract(
    *,
    service_unit: str,
    fragment_path: str,
    exec_start: str,
    config_path: str,
    service_user: str,
    environment_file_path: str | None = None,
    manual_service_remediation_reason: str | None = None,
    generated_config_compatible: bool = True,
    config_install_mode: str = "manual_merge_only_preserve_existing_identity_key_port_and_endpoint_settings",
    manual_config_merge_required: bool = True,
) -> dict[str, Any]:
    """Describe a verified Linux service without treating it as mutable input.

    These are deployment contracts captured by the release preflight, not
    instructions to replace an installed service unit.  The release generator
    emits a narrow Genesis-only systemd drop-in only when the contract has no
    known incompatibility.  It never rewrites ExecStart or existing environment
    files. A role may opt into full config replacement only when the runtime
    proves that its consensus key is external to TOML and a checksum-bound
    canonical config is required for startup.
    """
    return {
        "platform": "linux-systemd",
        "service_unit": service_unit,
        "service_fragment_path": fragment_path,
        "service_exec_start": exec_start,
        "service_user": service_user,
        "existing_config_path": config_path,
        "existing_environment_file_path": environment_file_path,
        "generated_config_compatible": generated_config_compatible,
        "genesis_deploy_path": LINUX_GENESIS_DEPLOY_PATH,
        "manual_service_remediation_required": manual_service_remediation_reason is not None,
        "manual_service_remediation_reason": manual_service_remediation_reason,
        "manual_config_merge_required": manual_config_merge_required,
        "config_install_mode": config_install_mode,
        "manual_activation_required": True,
    }


def macos_launchd_contract() -> dict[str, Any]:
    """Describe the verified archive launchd contract without replacing it."""
    return {
        "platform": "macos-launchd",
        "service_label": "network.synergy.archive-validator",
        "service_plist_path": "/Library/LaunchDaemons/network.synergy.archive-validator.plist",
        "service_exec_start": "/usr/local/synergy/bin/synergy-archive-validator-node start --config /Users/Shared/Synergy/archive-validator/workspace/config/node.toml",
        "service_user": "synergynode",
        "existing_config_path": "/Users/Shared/Synergy/archive-validator/workspace/config/node.toml",
        "existing_environment_file_path": None,
        "generated_config_compatible": True,
        "genesis_deploy_path": MACOS_ARCHIVE_GENESIS_DEPLOY_PATH,
        "manual_service_remediation_required": False,
        "manual_service_remediation_reason": None,
        "manual_config_merge_required": True,
        "manual_activation_required": True,
    }


def dedicated_linux_service_contract(
    *,
    role_name: str,
    service_unit: str,
    runtime_kind: str,
    legacy_service_contract: dict[str, str],
) -> dict[str, Any]:
    """Describe a new isolated V3 service, never a legacy-unit replacement.

    Dedicated services receive an unambiguous Testnet-v3 name, configuration
    root, Genesis path, and state root.  For runtime binaries the release tree
    also carries a fail-closed launcher: activation requires an operator to
    provide a content-addressed V3 binary mapping.  We intentionally do not
    infer that mapping from a legacy or testbeta installation.
    """
    config_root = f"/etc/synergy/testnet-v3/{role_name}"
    data_root = f"/var/lib/synergy-testnet-v3-{role_name}"
    contract: dict[str, Any] = {
        "platform": "linux-systemd",
        "deployment_mode": "dedicated-testnet-v3-service",
        "service_unit": service_unit,
        "service_fragment_path": f"/etc/systemd/system/{service_unit}",
        "service_user": "DynamicUser",
        "existing_config_path": f"{config_root}/node.toml",
        "existing_environment_file_path": None,
        "generated_config_compatible": True,
        "genesis_deploy_path": f"{config_root}/genesis.json",
        "dedicated_config_root": config_root,
        "dedicated_data_root": data_root,
        "legacy_service_contract_do_not_modify": legacy_service_contract,
        "manual_service_remediation_required": False,
        "manual_service_remediation_reason": None,
        "manual_config_merge_required": False,
        "config_install_mode": "install_new_isolated_testnet_v3_config_only",
        "manual_activation_required": True,
        "operator_port_preflight_required": True,
        "operator_identity_mapping_required": runtime_kind in {"runtime", "indexer"},
        "operator_runtime_binary_mapping_required": runtime_kind in {"runtime", "indexer"},
        "runtime_kind": runtime_kind,
    }
    if runtime_kind == "seed":
        seed_name = role_name
        config_root = "/etc/synergy/testnet-v3/seed-services"
        data_root = f"/var/lib/synergy-testnet-v3-seed-{seed_name}"
        contract.update(
            {
                "service_unit_template": "synergy-testnet-v3-seed@.service",
                "service_instance": seed_name,
                # systemd template, shared by the three V3 seed instances.
                # The service_unit above remains the explicit instance name
                # used for activation, but the artifact is installed at the
                # template path below.
                "service_fragment_path": "/etc/systemd/system/synergy-testnet-v3-seed@.service",
                "existing_config_path": f"{config_root}/{seed_name}.json",
                "generated_config_compatible": False,
                "seed_service_script_deploy_path": "/opt/synergy/testnet-v3/seed-service/seed_service.py",
                "seed_launch_guard_deploy_path": "/opt/synergy/testnet-v3/bin/synergy-seed-release-guard",
                "seed_state_file": f"{data_root}/peers.json",
                "genesis_deploy_path": f"{config_root}/{seed_name}.genesis.json",
                "dedicated_config_root": config_root,
                "dedicated_data_root": data_root,
                "operator_identity_mapping_required": False,
                "operator_runtime_binary_mapping_required": False,
            }
        )
    else:
        contract.update(
            {
                "runtime_environment_file": f"{config_root}/runtime.env",
                "runtime_launch_guard_deploy_path": "/opt/synergy/testnet-v3/bin/synergy-release-guard",
            }
        )
    return contract


# This is the source-controlled counterpart of the 2026-07-28 service
# preflight.  It deliberately records service names and non-secret filesystem
# contracts only.  Any activation must re-verify the unit/plist before applying
# the prepare-only binding artifact.  In particular, no role is allowed to
# inherit an arbitrary working-directory config path. Validators and relayers
# are the narrow exception: their typed runtime loads the consensus key from a
# root-only file outside TOML, and their full canonical config must replace
# stale values after an inactive-service preflight and recoverable backup.
SERVICE_CONTRACTS: dict[tuple[str, str], dict[str, Any]] = {
    **{
        ("validators", f"Val{number}"): linux_service_contract(
            service_unit="synergy-validator.service",
            fragment_path="/etc/systemd/system/synergy-validator.service",
            exec_start="/opt/synergy/bin/synergy-validator start --config /etc/synergy/validator/config.toml",
            config_path="/etc/synergy/validator/config.toml",
            service_user="root",
            config_install_mode="replace_with_checksum_bound_canonical_testnet_v3_config_after_backup_and_inactive_service_preflight",
            manual_config_merge_required=False,
        )
        for number in range(1, 7)
    },
    **{
        ("relayers", f"relay{number}"): linux_service_contract(
            service_unit="synergy-testnet-relayer.service",
            fragment_path="/etc/systemd/system/synergy-testnet-relayer.service",
            exec_start="./bin/synergy-testnet-linux-amd64 start --config config/node.toml",
            config_path="config/node.toml",
            service_user="root",
            config_install_mode="replace_with_checksum_bound_canonical_testnet_v3_config_after_backup_and_inactive_service_preflight",
            manual_config_merge_required=False,
        )
        for number in range(1, 4)
    },
    ("bootnodes", "bootnode1"): linux_service_contract(
        service_unit="synergy-testnet-bootnode1.service",
        fragment_path="/etc/systemd/system/synergy-testnet-bootnode1.service",
        exec_start="/opt/synergy/testnet/bootnode1/bin/synergy-testnet-linux-amd64 start --config /opt/synergy/testnet/bootnode1/config/node.toml",
        config_path="/opt/synergy/testnet/bootnode1/config/node.toml",
        service_user="root",
    ),
    ("bootnodes", "bootnode2"): dedicated_linux_service_contract(
        role_name="bootnode2",
        service_unit="synergy-testnet-v3-bootnode2.service",
        runtime_kind="runtime",
        legacy_service_contract={
            "service_unit": "synergy-testnet-bootnode2.service",
            "fragment_path": "/etc/systemd/system/synergy-testnet-bootnode2.service",
            "status": "emergency-held",
            "instruction": "Do not modify, unhold, enable, or reuse this legacy unit.",
        },
    ),
    ("bootnodes", "bootnode3"): dedicated_linux_service_contract(
        role_name="bootnode3",
        service_unit="synergy-testnet-v3-bootnode3.service",
        runtime_kind="runtime",
        legacy_service_contract={
            "service_unit": "synergy-testbeta-bootnode3.service",
            "fragment_path": "/etc/systemd/system/synergy-testbeta-bootnode3.service",
            "status": "testbeta-named-and-emergency-held",
            "instruction": "Do not modify, unhold, enable, or reuse this testbeta unit.",
        },
    ),
    **{
        ("seed_servers", f"seed{number}"): dedicated_linux_service_contract(
            role_name=f"seed{number}",
            service_unit=f"synergy-testnet-v3-seed@seed{number}.service",
            runtime_kind="seed",
            legacy_service_contract={
                "service_unit": f"synergy-seed-service@seed{number}.service",
                "fragment_path": "/etc/systemd/system/synergy-seed-service@.service",
                "status": "legacy-json-config",
                "instruction": "Do not modify, enable, or reuse this legacy seed instance.",
            },
        )
        for number in range(1, 4)
    },
    ("rpc_gateways", "rpc-gateway"): linux_service_contract(
        service_unit="synergy-rpc-gateway.service",
        fragment_path="/etc/systemd/system/synergy-rpc-gateway.service",
        exec_start="/opt/synergy/bin/synergy-rpc-gateway start --config /etc/synergy/rpc-gateway/node.toml",
        config_path="/etc/synergy/rpc-gateway/node.toml",
        environment_file_path="/etc/synergy/rpc-gateway/node.env",
        service_user="node",
    ),
    ("observers", "observer"): linux_service_contract(
        service_unit="synergy-observer.service",
        fragment_path="/etc/systemd/system/synergy-observer.service",
        exec_start="/opt/synergy/bin/synergy-observer start --config /etc/synergy/observer/node.toml",
        config_path="/etc/synergy/observer/node.toml",
        environment_file_path="/etc/synergy/observer/node.env",
        service_user="node",
    ),
    ("explorer_indexers", "explorer-indexer"): dedicated_linux_service_contract(
        role_name="explorer-indexer",
        service_unit="synergy-testnet-v3-explorer-indexer.service",
        runtime_kind="indexer",
        legacy_service_contract={
            "service_unit": "synergy-node-exp.service",
            "fragment_path": "/etc/systemd/system/synergy-node-exp.service",
            "status": "referenced-config-and-environment-absent-with-oom-guard",
            "instruction": "Do not modify, enable, or reuse this legacy unit.",
        },
    ),
    ("archive_validators", "archive-validator"): macos_launchd_contract(),
}


def fail(message: str) -> None:
    raise ValidationError(message)


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def repository_root() -> Path:
    return Path(__file__).resolve().parent.parent


def require_sha256(value: Any, label: str) -> str:
    if not isinstance(value, str) or len(value) != 64:
        fail(f"{label} must be a 64-character SHA-256 digest")
    try:
        int(value, 16)
    except ValueError:
        fail(f"{label} must be hexadecimal")
    return value.lower()


def recorded_path(root: Path, value: Any, label: str) -> Path:
    if not isinstance(value, str) or not value.strip():
        fail(f"{label} must be a non-empty path")
    candidate = Path(value)
    return (candidate if candidate.is_absolute() else root / candidate).resolve()


def require_path_within_repository(root: Path, value: Any, label: str) -> Path:
    resolved = recorded_path(root, value, label)
    try:
        resolved.relative_to(root.resolve())
    except ValueError:
        fail(f"{label} escapes the repository root")
    return resolved


def read_json_object(path: Path, label: str) -> dict[str, Any]:
    try:
        loaded = json.loads(path.read_text())
    except OSError as error:
        fail(f"read {label} {path}: {error}")
    except json.JSONDecodeError as error:
        fail(f"parse {label} {path}: {error}")
    if not isinstance(loaded, dict):
        fail(f"{label} {path} must contain a JSON object")
    if contains_placeholder(loaded):
        fail(f"{label} {path} contains a placeholder")
    return loaded


def genesis_deployment(genesis: dict[str, Any]) -> dict[str, Any]:
    deployment = genesis.get("genesis_deployment")
    initialization = genesis.get("testnet_v3_initialization")
    if deployment is None and isinstance(initialization, dict):
        deployment = initialization.get("genesis_deployment")
    if not isinstance(deployment, dict):
        fail("Genesis must contain a genesis_deployment object")
    return deployment


def verify_release_authorization(
    *,
    genesis_path: Path,
    genesis: dict[str, Any],
    approval_path: Path,
    release_integrity_path: Path,
    authorities_path: Path,
    approval_verifier: Path,
) -> dict[str, str]:
    """Verify both signed governance approval and post-apply integrity evidence.

    The Python generator deliberately does not parse or verify ML-DSA material.
    The pinned runtime executable is the only approval verifier.  The separate
    integrity record ensures the approved candidate was atomically applied to
    the exact canonical Genesis given to this generator.
    """
    root = repository_root()
    for path, label in (
        (approval_path, "release approval artifact"),
        (release_integrity_path, "Phase-7/8 release integrity record"),
        (authorities_path, "frozen authorities record"),
        (approval_verifier, "release approval verifier"),
    ):
        if not path.is_file():
            fail(f"Required {label} does not exist: {path}")
    if not os.access(approval_verifier, os.X_OK):
        fail(f"Release approval verifier is not executable: {approval_verifier}")

    release = read_json_object(release_integrity_path, "Phase-7/8 release integrity record")
    if release.get("schema_version") != 1:
        fail("Phase-7/8 release integrity record schema_version must be 1")
    if release.get("status") != RELEASE_INTEGRITY_STATUS:
        fail("Phase-7/8 release integrity record is not in the applied release-gates state")

    applied_genesis = require_path_within_repository(root, release.get("genesis_file"), "release integrity genesis_file")
    if genesis_path.resolve() != applied_genesis:
        fail("Supplied Genesis is not the exact canonical Genesis named by release integrity evidence")
    if not applied_genesis.is_file():
        fail(f"Release integrity canonical Genesis does not exist: {applied_genesis}")
    if sha256_file(genesis_path) != require_sha256(release.get("genesis_file_sha256"), "release integrity genesis_file_sha256"):
        fail("Supplied Genesis SHA-256 disagrees with Phase-7/8 release integrity evidence")

    integrity = genesis.get("integrity")
    consensus_parameters = genesis.get("consensus_parameters")
    deployment = genesis_deployment(genesis)
    if not isinstance(integrity, dict) or not isinstance(consensus_parameters, dict):
        fail("Genesis must contain integrity and consensus_parameters objects")
    comparisons = (
        (integrity.get("genesis_hash"), release.get("genesis_hash"), "genesis_hash"),
        (deployment.get("post_deployment_execution_state_root"), release.get("execution_state_root"), "execution_state_root"),
        (deployment.get("post_deployment_aivm_state_root"), release.get("aivm_state_root"), "aivm_state_root"),
        (deployment.get("receipt_root"), release.get("receipt_root"), "receipt_root"),
        (consensus_parameters.get("decision_id"), release.get("consensus_parameter_decision_id"), "consensus_parameter_decision_id"),
        (consensus_parameters.get("canonical_manifest_sha256"), release.get("consensus_parameter_manifest_sha256"), "consensus_parameter_manifest_sha256"),
        (consensus_parameters.get("parameter_root_sha3_512"), release.get("consensus_parameter_root_sha3_512"), "consensus_parameter_root_sha3_512"),
    )
    for genesis_value, release_value, label in comparisons:
        if not isinstance(genesis_value, str) or genesis_value != release_value:
            fail(f"Genesis {label} disagrees with Phase-7/8 release integrity evidence")

    # Finalizer records a repository-relative artifact by default, but permits
    # an explicitly supplied offline approval path.  It is read-only here and
    # remains SHA-256-bound to both evidence and the Rust verifier result.
    approved_artifact = recorded_path(
        root, release.get("release_approval_artifact"), "release integrity release_approval_artifact"
    )
    if approval_path.resolve() != approved_artifact:
        fail("Supplied approval artifact is not the exact artifact named by release integrity evidence")
    approval_sha256 = sha256_file(approval_path)
    if approval_sha256 != require_sha256(
        release.get("release_approval_artifact_sha256"), "release integrity release_approval_artifact_sha256"
    ):
        fail("Release approval artifact SHA-256 disagrees with Phase-7/8 release integrity evidence")

    try:
        completed = subprocess.run(
            [
                str(approval_verifier),
                "--verify",
                "--approval",
                str(approval_path),
                "--candidate",
                str(genesis_path),
                "--authorities",
                str(authorities_path),
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
    except OSError as error:
        fail(f"run release approval verifier: {error}")
    except subprocess.TimeoutExpired:
        fail("release approval verifier timed out")
    if completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip() or f"exit {completed.returncode}"
        fail(f"release approval verifier rejected the artifact: {detail}")
    try:
        verifier_output = json.loads(completed.stdout)
    except json.JSONDecodeError as error:
        fail(f"release approval verifier emitted invalid JSON: {error}")
    if not isinstance(verifier_output, dict):
        fail("release approval verifier emitted a non-object result")
    if verifier_output.get("result") != RELEASE_APPROVAL_RESULT:
        fail("release approval verifier did not report RELEASE_APPROVAL_VERIFIED")
    if verifier_output.get("approval_sha256") != approval_sha256:
        fail("release approval verifier approval SHA-256 disagrees with the supplied artifact")
    if verifier_output.get("candidate_sha256") != sha256_file(genesis_path):
        fail("release approval verifier candidate SHA-256 disagrees with the supplied Genesis")
    if verifier_output.get("genesis_hash") != integrity.get("genesis_hash"):
        fail("release approval verifier genesis hash disagrees with the supplied Genesis")
    approval_identity_fields = (
        ("governance_authority_role", "release_approval_governance_role"),
        ("governance_standard_account_address", "release_approval_governance_address"),
    )
    for verifier_field, integrity_field in approval_identity_fields:
        if verifier_output.get(verifier_field) != release.get(integrity_field):
            fail(
                f"release approval verifier {verifier_field} disagrees with "
                "Phase-7/8 release integrity evidence"
            )

    return {
        "release_approval_artifact_sha256": approval_sha256,
        "phase7_release_integrity_sha256": sha256_file(release_integrity_path),
        "release_approval_governance_role": str(verifier_output["governance_authority_role"]),
        "release_approval_governance_address": str(verifier_output["governance_standard_account_address"]),
    }


def q(value: str) -> str:
    """JSON basic strings are also valid TOML basic strings."""
    return json.dumps(value, ensure_ascii=False)


def array(values: list[str]) -> str:
    return "[" + ", ".join(q(value) for value in values) + "]"


def contains_placeholder(value: Any) -> bool:
    if isinstance(value, str):
        # AIVM ABI types legitimately contain generic syntax such as
        # ``map<address,u8>``.  Treat only an actual all-caps placeholder token
        # or a known unresolved Testnet-v3 template marker as unresolved.
        return bool(UNRESOLVED_PLACEHOLDER.search(value)) or "TESTNET_V3_" in value
    if isinstance(value, dict):
        return any(contains_placeholder(item) for item in value.values())
    if isinstance(value, list):
        return any(contains_placeholder(item) for item in value)
    return False


def require_string(mapping: dict[str, Any], key: str, label: str) -> str:
    value = mapping.get(key)
    if not isinstance(value, str) or not value.strip():
        fail(f"{label}.{key} must be a non-empty string")
    if contains_placeholder(value):
        fail(f"{label}.{key} contains a placeholder")
    return value.strip()


def require_int(mapping: dict[str, Any], key: str, label: str) -> int:
    value = mapping.get(key)
    if not isinstance(value, int):
        fail(f"{label}.{key} must be an integer")
    return value


def finalized_release(genesis: dict[str, Any]) -> None:
    network = genesis.get("network")
    integrity = genesis.get("integrity")
    if not isinstance(network, dict) or not isinstance(integrity, dict):
        fail("Genesis must contain network and integrity objects")
    if network.get("chain_id") != CHAIN_ID or network.get("network_id") != CHAIN_ID:
        fail("Genesis does not bind chain_id/network_id 1266")
    if network.get("network_slug") != NETWORK_ID:
        fail("Genesis does not bind network_slug synergy-testnet-v3")
    if not isinstance(integrity.get("genesis_hash"), str) or len(integrity["genesis_hash"]) != 64:
        fail("Genesis integrity.genesis_hash is missing or malformed")
    deployment = genesis_deployment(genesis)
    if deployment.get("status") != "EXECUTED_AND_BOUND":
        fail("Genesis deployment is not EXECUTED_AND_BOUND")


def active_validator_addresses(genesis: dict[str, Any]) -> list[str]:
    validators = genesis.get("validators")
    consensus = genesis.get("consensus")
    if not isinstance(validators, list) or not isinstance(consensus, dict):
        fail("Genesis validators or consensus section is missing")
    active: list[str] = []
    for index, validator in enumerate(validators):
        if not isinstance(validator, dict):
            fail(f"Genesis validators[{index}] is not an object")
        status = str(validator.get("status", validator.get("activation_status", ""))).lower()
        address = validator.get("operator_address", validator.get("address", validator.get("validator_address")))
        if status in {"active", "active_at_genesis"}:
            if not isinstance(address, str) or not address.startswith("synv1"):
                fail(f"Genesis active validator {index} has no canonical synv1 operator address")
            active.append(address)
    if len(active) != 6 or len(set(active)) != 6:
        fail("Genesis must have exactly six distinct active Testnet-v3 validators")
    if consensus.get("initial_active_validator_count") != 6 or consensus.get("min_validator_count") != 6:
        fail("Genesis consensus validator count is not bound to the approved six-validator launch")
    if consensus.get("target_block_time_ms") != 2000:
        fail("Genesis target_block_time_ms is not the approved 2000 ms value")
    timeouts = consensus.get("timeouts")
    if not isinstance(timeouts, dict) or {timeouts.get("proposal_ms"), timeouts.get("prevote_ms"), timeouts.get("precommit_ms")} != {1500} or timeouts.get("max_round_ms") != 10000:
        fail("Genesis does not bind the approved 1500/10000 ms consensus timeouts")
    return active


def topology_nodes(topology: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    groups = (
        "bootnodes",
        "seed_servers",
        "relayers",
        "validators",
        "rpc_gateways",
        "observers",
        "explorer_indexers",
        "archive_validators",
    )
    output: list[tuple[str, dict[str, Any]]] = []
    for group in groups:
        entries = topology.get(group)
        if not isinstance(entries, list) or not entries:
            fail(f"Topology {group} must be a non-empty list")
        for item in entries:
            if not isinstance(item, dict):
                fail(f"Topology {group} contains a non-object entry")
            output.append((group, item))
    return output


def workbook_node(group: str, entry: dict[str, Any]) -> str:
    name = require_string(entry, "name", f"topology.{group}")
    if group == "validators":
        return name
    if group == "bootnodes":
        return "Bootnode" + name.removeprefix("bootnode")
    if group == "seed_servers":
        return "Seed Server" + name.removeprefix("seed")
    if group == "relayers":
        return "Relayer-" + name.removeprefix("relay")
    return {
        "rpc_gateways": "RPC Gateway",
        "observers": "Observer",
        "explorer_indexers": "Explorer Indexer",
        "archive_validators": "Archive Validator",
    }[group]


def output_path(group: str, entry: dict[str, Any]) -> Path:
    name = require_string(entry, "name", f"topology.{group}")
    if group == "validators":
        return Path("validators") / f"{name.lower()}.toml"
    directories = {
        "bootnodes": "bootnodes",
        "seed_servers": "seed-servers",
        "relayers": "relayers",
        "rpc_gateways": "rpc-gateway",
        "observers": "observer",
        "explorer_indexers": "explorer-indexer",
        "archive_validators": "archive-validator",
    }
    return Path(directories[group]) / f"{name}.toml"


def role_fields(group: str) -> tuple[str, str, list[str]]:
    return {
        # The runtime uses the observer/light profile for non-consensus
        # bootstrap peers. `bootstrap_only = true` below still suppresses
        # sync, RPC, and consensus while keeping the P2P bootstrap surface.
        "bootnodes": ("observer_light", "observer_light_node", ["observer"]),
        "seed_servers": ("seed_server", "", []),
        "relayers": ("relayer", "relayer_node", ["relayer"]),
        "validators": ("validator", "validator_node", ["consensus"]),
        "rpc_gateways": ("rpc_gateway", "rpc_gateway_node", ["rpc_gateway"]),
        "observers": ("observer_light", "observer_light_node", ["observer"]),
        "explorer_indexers": ("indexer_explorer", "indexer_and_explorer_node", ["indexer"]),
        "archive_validators": ("archive_validator", "archive_validator_node", ["archive"]),
    }[group]


def deployment_contract(group: str, entry: dict[str, Any]) -> dict[str, Any]:
    """Return the exact preflight service contract for one generated role.

    A missing contract is a launch-blocking error rather than permission to use
    a generic path.  Return a copy because callers attach release-specific
    fields while the source-of-truth contract remains immutable for the run.
    """
    name = require_string(entry, "name", f"topology.{group}")
    contract = SERVICE_CONTRACTS.get((group, name))
    if contract is None:
        fail(f"No verified service deployment contract exists for topology.{group}.{name}")
    copied = dict(contract)
    for required in ("platform", "existing_config_path", "genesis_deploy_path"):
        value = copied.get(required)
        if not isinstance(value, str) or not value:
            fail(f"Service deployment contract {group}.{name} is missing {required}")
    genesis_path = copied["genesis_deploy_path"]
    if not genesis_path.startswith("/"):
        fail(f"Service deployment contract {group}.{name} has a non-absolute Genesis path")
    if copied["platform"] == "linux-systemd" and not copied.get("service_unit"):
        fail(f"Linux service deployment contract {group}.{name} has no service unit")
    if copied["platform"] == "macos-launchd" and not copied.get("service_label"):
        fail(f"launchd service deployment contract {group}.{name} has no service label")
    return copied


def public_endpoint(group: str, entry: dict[str, Any]) -> str:
    if group == "validators":
        return ""
    return require_string(entry, "public_endpoint", f"topology.{group}")


def peers_for(group: str, entry: dict[str, Any], topology: dict[str, Any]) -> list[str]:
    peers = entry.get("peers")
    if peers is None:
        peers = topology["common"]["relayer_peers"]
    if not isinstance(peers, list) or not all(isinstance(peer, str) for peer in peers):
        fail(f"topology.{group}.peers must be a string list")
    return list(peers)


def toml_config(
    *,
    group: str,
    entry: dict[str, Any],
    topology: dict[str, Any],
    identity: dict[str, Any],
    active_validators: list[str],
    active_validator_transports: list[tuple[str, str]],
    active_relayer_transports: list[str],
    binding: dict[str, str],
    service_contract: dict[str, Any],
) -> str:
    name = require_string(entry, "name", f"topology.{group}")
    node_id = require_string(entry, "node_id", f"topology.{group}")
    role, compiled_profile, services = role_fields(group)
    port = require_int(entry, "port", f"topology.{group}")
    is_validator = group == "validators"
    validator_address = require_string(entry, "validator_address", "topology.validators") if is_validator else ""
    if is_validator and validator_address not in active_validators:
        fail(f"Topology validator {name} is not an active finalized Genesis validator")
    if is_validator and identity["address"] != validator_address:
        fail(f"Genesis identity address disagrees with topology for {name}")

    if is_validator:
        own_transport = dict(active_validator_transports).get(validator_address)
        if own_transport is None:
            fail(f"No active VPN transport exists for {validator_address}")
        listen_address = own_transport
        advertised_address = validator_address
        peers = [address for address in active_validators if address != validator_address] + active_relayer_transports
        discovery = False
    else:
        advertised_address = public_endpoint(group, entry)
        listen_address = f"0.0.0.0:{port}"
        peers = peers_for(group, entry, topology)
        discovery = group not in {"archive_validators", "explorer_indexers", "observers"}

    common = topology["common"]
    lines = [
        f"# Generated by scripts/generate-testnet-v3-node-configs.py ({GENERATOR_VERSION})",
        "# Inputs are SHA-256-bound below. Do not hand-edit; regenerate from release records.",
        "",
        "[identity]",
        f"node_id = {q(node_id)}",
        f"role = {q(role)}",
        f"role_display = {q(role)}",
        f"address = {q(require_string(identity, 'address', 'Genesis node identity'))}",
        f"label = {q(name)}",
        "",
        "[role]",
        f"compiled_profile = {q(compiled_profile)}",
        f"services = {array(services)}",
        "",
        "[network]",
        "id = 1266",
        f"network_id = {q(NETWORK_ID)}",
        f"name = {q(NETWORK_ID)}",
        f"p2p_port = {port}",
        "rpc_port = 5640",
        "ws_port = 5660",
        "max_peers = 50",
        f"bootnodes = {array(list(common['bootnodes']))}",
        f"seed_servers = {array(list(common['seed_servers']))}",
        f"bootstrap_dns_records = {array(list(common['bootstrap_dns_records']))}",
        f"persistent_peers = {array(peers)}",
        f"additional_dial_targets = {array(peers)}",
        "",
    ]
    for validator, transport in active_validator_transports:
        lines.extend([
            "[[network.validator_vpn_transports]]",
            f"validator_address = {q(validator)}",
            f"dial_address = {q(transport)}",
            "",
        ])
    lines.extend([
        "[blockchain]",
        "block_time = 2",
        'max_gas_limit = "0x2fefd8"',
        "chain_id = 1266",
        "",
        "[consensus]",
        f"algorithm = {q(COORDINATED_CONSENSUS_MODE)}",
        f"mode = {q(COORDINATED_CONSENSUS_MODE)}",
        f"coordinator_id = {q(COORDINATED_COORDINATOR_ID)}",
        f"producer_ids = {array(COORDINATED_PRODUCER_IDS)}",
        "block_time_secs = 2",
        "epoch_length = 1000",
        "target_block_time_ms = 2000",
        "producer_turn_timeout_ms = 4000",
        "min_validators = 6",
        "validator_cluster_size = 6",
        "allow_genesis_status_bypass = false",
        "",
        "[p2p]",
        f"listen_address = {q(listen_address)}",
        f"public_address = {q(advertised_address)}",
        f"node_name = {q(node_id)}",
        f"enable_discovery = {'true' if discovery else 'false'}",
        f"enable_peer_exchange = {'true' if discovery else 'false'}",
        "discovery_port = 5680",
        f"discovery_listen_address = {q(listen_address.rsplit(':', 1)[0] + ':5680')}",
        f"discovery_public_address = {q(advertised_address)}",
        "heartbeat_interval = 10",
        "bootstrap_refresh_secs = 10",
        "reject_private_advertise_addrs = true",
        "",
        "[node]",
        f"bootstrap_only = {'true' if group == 'bootnodes' else 'false'}",
        "auto_register_validator = false",
        f"validator_address = {q(validator_address)}",
        f"strict_validator_allowlist = {'true' if is_validator else 'false'}",
        f"allowed_validator_addresses = {array(active_validators)}",
        "",
        "[validator]",
        f"participation = {q('active' if is_validator else 'observer')}",
        "verify_quorum_certificates = true",
        f"state_sync_before_join = {'true' if is_validator else 'false'}",
        "",
        "[logging]",
        'log_level = "info"',
        'log_file = "data/logs/synergy-node.log"',
        "enable_console = true",
        "max_file_size = 10485760",
        "max_files = 5",
        "",
        "[rpc]",
        'bind_address = "127.0.0.1:5640"',
        "enable_http = true",
        "http_port = 5640",
        "enable_ws = true",
        "ws_port = 5660",
        "enable_grpc = true",
        "grpc_port = 5640",
        "cors_enabled = false",
        "cors_origins = []",
        "",
        "[storage]",
        'database = "rocksdb"',
        'path = "data/chain"',
        "enable_pruning = true",
        "pruning_interval = 86400",
        "",
        "[telemetry]",
        "enabled = true",
        'metrics_bind = "127.0.0.1:6030"',
        "structured_logs = true",
        'log_level = "info"',
        "",
        "[launch_binding]",
        f"generator_version = {q(GENERATOR_VERSION)}",
        f"genesis_hash = {q(binding['genesis_hash'])}",
        f"genesis_file_sha256 = {q(binding['genesis_file_sha256'])}",
        f"genesis_deploy_path = {q(require_string(service_contract, 'genesis_deploy_path', 'service deployment contract'))}",
        f"genesis_environment_variable = {q('SYNERGY_GENESIS_FILE')}",
        f"topology_sha256 = {q(binding['topology_sha256'])}",
        f"vpn_registry_sha256 = {q(binding['vpn_registry_sha256'])}",
        f"consensus_parameter_root_sha3_512 = {q(binding['consensus_parameter_root_sha3_512'])}",
        f"consensus_parameter_decision_id = {q(binding['consensus_parameter_decision_id'])}",
        f"release_approval_artifact_sha256 = {q(binding['release_approval_artifact_sha256'])}",
        f"phase7_release_integrity_sha256 = {q(binding['phase7_release_integrity_sha256'])}",
        f"release_approval_governance_role = {q(binding['release_approval_governance_role'])}",
        f"release_approval_governance_address = {q(binding['release_approval_governance_address'])}",
        "signed_transport_registry_required = true",
        "",
    ])
    content = "\n".join(lines)
    try:
        tomllib.loads(content)
    except tomllib.TOMLDecodeError as error:
        fail(f"generator emitted invalid TOML for {name}: {error}")
    if contains_placeholder(content):
        fail(f"generator emitted a placeholder for {name}")
    return content


def deployment_directory(config_path: Path) -> Path:
    """Return the release-payload directory belonging to one node config."""
    if config_path.suffix != ".toml":
        fail(f"Generated node config does not have a .toml suffix: {config_path}")
    return Path("deployment") / config_path.with_suffix("")


def node_environment(binding: dict[str, str], service_contract: dict[str, Any]) -> str:
    """Render a reference-only release environment for one service contract.

    This payload is never an instruction to overwrite a host's existing
    EnvironmentFile.  It contains only immutable release binding values.  A
    service-specific installer must merge those keys after preserving local
    credential, key, port, and endpoint settings.
    """
    genesis_path = require_string(service_contract, "genesis_deploy_path", "service deployment contract")
    if not genesis_path.startswith("/"):
        fail("node environment Genesis path must be absolute")
    lines = [
        "# Generated Testnet-v3 release binding. Reference-only; do not replace a host EnvironmentFile.",
        f"SYNERGY_RELEASE_ID={NETWORK_ID}",
        f"SYNERGY_CHAIN_ID={CHAIN_ID}",
        f"SYNERGY_NETWORK_ID={NETWORK_ID}",
        f"SYNERGY_GENESIS_FILE={genesis_path}",
        f"SYNERGY_GENESIS_SHA256={binding['genesis_file_sha256']}",
        f"SYNERGY_GENESIS_HASH={binding['genesis_hash']}",
    ]
    config_path = require_string(service_contract, "existing_config_path", "service deployment contract")
    if service_contract.get("generated_config_compatible") is True and config_path.startswith("/"):
        lines.append(f"SYNERGY_CONFIG_FILE={config_path}")
    lines.append("")
    rendered = "\n".join(lines)
    if contains_placeholder(rendered):
        fail("generator emitted a placeholder in a node environment file")
    if f"SYNERGY_GENESIS_FILE={genesis_path}" not in rendered:
        fail("node environment file did not bind the absolute Genesis deploy path")
    if "config/genesis.json" in rendered:
        fail("node environment file contains a working-directory Genesis fallback")
    return rendered


def systemd_genesis_dropin(binding: dict[str, str], service_contract: dict[str, Any]) -> str:
    """Render a service drop-in that enforces the same Genesis environment.

    This narrow drop-in has no ExecStart, EnvironmentFile, port, user, or key
    changes.  It exists only for contracts that passed preflight as suitable;
    it never clears a safety hold or attempts to rehabilitate a legacy unit.
    """
    if service_contract.get("platform") != "linux-systemd":
        fail("systemd Genesis drop-in requested for a non-systemd contract")
    if service_contract.get("manual_service_remediation_required") is True:
        fail("systemd Genesis drop-in requested for a manual-remediation contract")
    genesis_path = require_string(service_contract, "genesis_deploy_path", "service deployment contract")
    if not genesis_path.startswith("/"):
        fail("systemd Genesis path must be absolute")
    lines = [
        "# Generated Testnet-v3 Genesis binding. Do not hand-edit.",
        "# Prepare-only: no service is enabled, started, restarted, or reloaded by this payload.",
        "[Service]",
        f"Environment=SYNERGY_GENESIS_FILE={genesis_path}",
        f"Environment=SYNERGY_GENESIS_SHA256={binding['genesis_file_sha256']}",
        f"Environment=SYNERGY_GENESIS_HASH={binding['genesis_hash']}",
        "",
    ]
    rendered = "\n".join(lines)
    if contains_placeholder(rendered):
        fail("generator emitted a placeholder in a systemd Genesis drop-in")
    if f"Environment=SYNERGY_GENESIS_FILE={genesis_path}" not in rendered:
        fail("systemd Genesis drop-in did not bind the absolute Genesis deploy path")
    if "config/genesis.json" in rendered:
        fail("systemd Genesis drop-in contains a working-directory Genesis fallback")
    return rendered


def launchd_genesis_binding(binding: dict[str, str], service_contract: dict[str, Any]) -> bytes:
    """Render a plist merge fragment for the existing macOS archive job.

    launchd has no systemd-style drop-in directory.  This is therefore a
    syntactically valid plist *merge artifact*, not a replacement job and not a
    loadable second daemon.  An operator must merge only EnvironmentVariables
    into the named, re-verified existing plist and preserve ProgramArguments,
    user, key material, ports, and all unrelated launchd settings.
    """
    if service_contract.get("platform") != "macos-launchd":
        fail("launchd Genesis binding requested for a non-launchd contract")
    genesis_path = require_string(service_contract, "genesis_deploy_path", "service deployment contract")
    if not genesis_path.startswith("/"):
        fail("launchd Genesis path must be absolute")
    label = require_string(service_contract, "service_label", "launchd service deployment contract")
    payload = {
        "Label": label,
        "EnvironmentVariables": {
            "SYNERGY_RELEASE_ID": NETWORK_ID,
            "SYNERGY_CHAIN_ID": str(CHAIN_ID),
            "SYNERGY_NETWORK_ID": NETWORK_ID,
            "SYNERGY_GENESIS_FILE": genesis_path,
            "SYNERGY_GENESIS_SHA256": binding["genesis_file_sha256"],
            "SYNERGY_GENESIS_HASH": binding["genesis_hash"],
        },
    }
    rendered = plistlib.dumps(payload, fmt=plistlib.FMT_XML, sort_keys=True)
    if b"SYNERGY_GENESIS_FILE" not in rendered or genesis_path.encode() not in rendered:
        fail("launchd binding did not bind SYNERGY_GENESIS_FILE")
    if b"config/genesis.json" in rendered:
        fail("launchd binding contains a working-directory Genesis fallback")
    return rendered


def port_preflight(group: str, entry: dict[str, Any]) -> list[dict[str, Any]]:
    """List the exact binds an operator must prove collision-free before start."""
    primary_port = require_int(entry, "port", f"topology.{group}")
    if group == "seed_servers":
        return [{"purpose": "seed_http", "port": primary_port, "protocol": "tcp"}]
    return [
        {"purpose": "p2p", "port": primary_port, "protocol": "tcp"},
        {"purpose": "rpc", "port": 5640, "protocol": "tcp"},
        {"purpose": "websocket", "port": 5660, "protocol": "tcp"},
        {"purpose": "discovery", "port": 5680, "protocol": "tcp"},
        {"purpose": "metrics", "port": 6030, "protocol": "tcp"},
    ]


def runtime_release_guard() -> bytes:
    """Return the content-addressed launcher for dedicated V3 runtime units."""
    rendered = """#!/bin/sh
# Generated Testnet-v3 dedicated-runtime guard. Do not hand-edit.
set -eu

required() {
    eval "value=\\${$1-}"
    if [ -z "$value" ]; then
        echo "missing required environment: $1" >&2
        exit 64
    fi
}

sha256_file() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$1" | awk '{print $1}'
    else
        echo "no SHA-256 utility is available" >&2
        exit 69
    fi
}

required SYNERGY_RELEASE_RUNTIME_BINARY
required SYNERGY_RELEASE_RUNTIME_SHA256
required SYNERGY_CONFIG_FILE
required SYNERGY_CONFIG_SHA256
required SYNERGY_GENESIS_FILE
required SYNERGY_GENESIS_SHA256
case "$SYNERGY_RELEASE_RUNTIME_BINARY" in
  /opt/synergy/testnet-v3/*) ;;
  *) echo "runtime binary is outside the dedicated Testnet-v3 root" >&2; exit 65 ;;
esac
case "$SYNERGY_CONFIG_FILE" in
  /etc/synergy/testnet-v3/*) ;;
  *) echo "config is outside the dedicated Testnet-v3 root" >&2; exit 65 ;;
esac
case "$SYNERGY_GENESIS_FILE" in
  /etc/synergy/testnet-v3/*) ;;
  *) echo "genesis is outside the dedicated Testnet-v3 root" >&2; exit 65 ;;
esac
[ -x "$SYNERGY_RELEASE_RUNTIME_BINARY" ] || { echo "runtime binary is not executable" >&2; exit 66; }
[ -r "$SYNERGY_CONFIG_FILE" ] || { echo "config is unreadable" >&2; exit 66; }
[ -r "$SYNERGY_GENESIS_FILE" ] || { echo "genesis is unreadable" >&2; exit 66; }
[ "$(sha256_file "$SYNERGY_RELEASE_RUNTIME_BINARY")" = "$SYNERGY_RELEASE_RUNTIME_SHA256" ] || { echo "runtime binary SHA-256 mismatch" >&2; exit 67; }
[ "$(sha256_file "$SYNERGY_CONFIG_FILE")" = "$SYNERGY_CONFIG_SHA256" ] || { echo "runtime config SHA-256 mismatch" >&2; exit 67; }
[ "$(sha256_file "$SYNERGY_GENESIS_FILE")" = "$SYNERGY_GENESIS_SHA256" ] || { echo "genesis SHA-256 mismatch" >&2; exit 67; }
exec "$SYNERGY_RELEASE_RUNTIME_BINARY" start --config "$SYNERGY_CONFIG_FILE"
"""
    return rendered.encode()


def seed_release_guard() -> bytes:
    """Return a Genesis/config/source verifying launcher for the V3 seed service."""
    rendered = """#!/bin/sh
# Generated Testnet-v3 dedicated-seed guard. Do not hand-edit.
set -eu

required() {
    eval "value=\\${$1-}"
    if [ -z "$value" ]; then
        echo "missing required environment: $1" >&2
        exit 64
    fi
}

sha256_file() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$1" | awk '{print $1}'
    else
        echo "no SHA-256 utility is available" >&2
        exit 69
    fi
}

required SYNERGY_SEED_SERVICE_SCRIPT
required SYNERGY_SEED_SERVICE_SCRIPT_SHA256
required SYNERGY_SEED_CONFIG_FILE
required SYNERGY_SEED_CONFIG_SHA256
required SYNERGY_GENESIS_FILE
required SYNERGY_GENESIS_SHA256
case "$SYNERGY_SEED_SERVICE_SCRIPT" in
  /opt/synergy/testnet-v3/*) ;;
  *) echo "seed service source is outside the dedicated Testnet-v3 root" >&2; exit 65 ;;
esac
case "$SYNERGY_SEED_CONFIG_FILE" in
  /etc/synergy/testnet-v3/*) ;;
  *) echo "seed config is outside the dedicated Testnet-v3 root" >&2; exit 65 ;;
esac
case "$SYNERGY_GENESIS_FILE" in
  /etc/synergy/testnet-v3/*) ;;
  *) echo "genesis is outside the dedicated Testnet-v3 root" >&2; exit 65 ;;
esac
[ -r "$SYNERGY_SEED_SERVICE_SCRIPT" ] || { echo "seed service source is unreadable" >&2; exit 66; }
[ -r "$SYNERGY_SEED_CONFIG_FILE" ] || { echo "seed config is unreadable" >&2; exit 66; }
[ -r "$SYNERGY_GENESIS_FILE" ] || { echo "genesis is unreadable" >&2; exit 66; }
[ "$(sha256_file "$SYNERGY_SEED_SERVICE_SCRIPT")" = "$SYNERGY_SEED_SERVICE_SCRIPT_SHA256" ] || { echo "seed source SHA-256 mismatch" >&2; exit 67; }
[ "$(sha256_file "$SYNERGY_SEED_CONFIG_FILE")" = "$SYNERGY_SEED_CONFIG_SHA256" ] || { echo "seed config SHA-256 mismatch" >&2; exit 67; }
[ "$(sha256_file "$SYNERGY_GENESIS_FILE")" = "$SYNERGY_GENESIS_SHA256" ] || { echo "genesis SHA-256 mismatch" >&2; exit 67; }
exec /usr/bin/python3 "$SYNERGY_SEED_SERVICE_SCRIPT" --config "$SYNERGY_SEED_CONFIG_FILE"
"""
    return rendered.encode()


def dedicated_runtime_environment_example() -> bytes:
    """Render an intentionally unusable example for the operator-only binary map."""
    return (
        b"# Create the deployed runtime.env only after independently verifying the V3 binary.\n"
        b"# This example is not a deployable EnvironmentFile.\n"
        b"SYNERGY_RELEASE_RUNTIME_BINARY=\n"
        b"SYNERGY_RELEASE_RUNTIME_SHA256=\n"
    )


def dedicated_systemd_unit(
    *,
    group: str,
    entry: dict[str, Any],
    binding: dict[str, str],
    service_contract: dict[str, Any],
    seed_config_sha256: str | None = None,
    seed_script_sha256: str | None = None,
    runtime_config_sha256: str | None = None,
) -> bytes:
    """Render a new isolated systemd unit without an [Install] section."""
    if service_contract.get("deployment_mode") != "dedicated-testnet-v3-service":
        fail("dedicated systemd unit requested for a non-dedicated contract")
    role_name = require_string(entry, "name", f"topology.{group}")
    unit = require_string(service_contract, "service_unit", "dedicated service contract")
    config_path = require_string(service_contract, "existing_config_path", "dedicated service contract")
    genesis_path = require_string(service_contract, "genesis_deploy_path", "dedicated service contract")
    data_root = require_string(service_contract, "dedicated_data_root", "dedicated service contract")
    state_directory = data_root.rsplit("/", 1)[-1]
    common = [
        "# Generated dedicated Testnet-v3 service. Prepare-only; no legacy unit is modified.",
        "[Unit]",
        f"Description=Synergy Testnet-v3 dedicated {role_name}",
        "After=network-online.target",
        "Wants=network-online.target",
        f"ConditionPathExists={genesis_path}",
        f"ConditionPathExists={config_path}",
        "",
        "[Service]",
        "Type=simple",
        "DynamicUser=yes",
        f"StateDirectory={state_directory}",
        f"WorkingDirectory={data_root}",
        f"Environment=SYNERGY_RELEASE_ID={NETWORK_ID}",
        f"Environment=SYNERGY_CHAIN_ID={CHAIN_ID}",
        f"Environment=SYNERGY_NETWORK_ID={NETWORK_ID}",
        f"Environment=SYNERGY_GENESIS_FILE={genesis_path}",
        f"Environment=SYNERGY_GENESIS_SHA256={binding['genesis_file_sha256']}",
        f"Environment=SYNERGY_GENESIS_HASH={binding['genesis_hash']}",
        "NoNewPrivileges=yes",
        "PrivateTmp=yes",
        "ProtectHome=yes",
        "ProtectSystem=strict",
        "Restart=on-failure",
        "RestartSec=5",
    ]
    if service_contract.get("runtime_kind") == "seed":
        script_path = require_string(service_contract, "seed_service_script_deploy_path", "seed service contract")
        guard_path = require_string(service_contract, "seed_launch_guard_deploy_path", "seed service contract")
        if seed_config_sha256 is None or seed_script_sha256 is None:
            fail("dedicated seed unit requires source and config SHA-256 values")
        common.extend([
            f"Environment=SYNERGY_SEED_SERVICE_SCRIPT={script_path}",
            f"Environment=SYNERGY_SEED_SERVICE_SCRIPT_SHA256={seed_script_sha256}",
            f"Environment=SYNERGY_SEED_CONFIG_FILE={config_path}",
            f"Environment=SYNERGY_SEED_CONFIG_SHA256={seed_config_sha256}",
            f"ExecStart={guard_path}",
        ])
    else:
        runtime_environment = require_string(service_contract, "runtime_environment_file", "dedicated service contract")
        guard_path = require_string(service_contract, "runtime_launch_guard_deploy_path", "dedicated service contract")
        if runtime_config_sha256 is None:
            fail("dedicated runtime unit requires a config SHA-256 value")
        common.extend([
            f"EnvironmentFile={runtime_environment}",
            f"Environment=SYNERGY_PROJECT_ROOT={data_root}",
            f"Environment=SYNERGY_CONFIG_PATH={config_path}",
            f"Environment=SYNERGY_CONFIG_FILE={config_path}",
            f"Environment=SYNERGY_CONFIG_SHA256={runtime_config_sha256}",
            f"ExecStartPre=/usr/bin/mkdir -p {data_root}/config",
            f"ExecStart={guard_path}",
        ])
    rendered = ("\n".join(common) + "\n").encode()
    if b"SYNERGY_GENESIS_FILE" not in rendered or b"ExecStart=" not in rendered:
        fail("dedicated systemd unit failed Genesis/ExecStart invariants")
    if b"[Install]" in rendered or b"systemctl " in rendered or b"config/genesis.json" in rendered:
        fail("dedicated systemd unit contains an unsafe activation/fallback directive")
    return rendered


def seed_service_config(
    *,
    entry: dict[str, Any],
    topology: dict[str, Any],
    binding: dict[str, str],
    service_contract: dict[str, Any],
) -> bytes:
    """Render the V3 JSON contract consumed by the included seed service."""
    name = require_string(entry, "name", "topology.seed_servers")
    port = require_int(entry, "port", "topology.seed_servers")
    seed_entries = topology.get("seed_servers")
    relayers = topology.get("relayers")
    seed_policy = topology.get("seed_registry")
    if not isinstance(seed_entries, list) or not isinstance(relayers, list) or not isinstance(seed_policy, dict):
        fail("Topology seed service inputs are malformed")
    replication_peers = [
        require_string(seed, "http_endpoint", "topology.seed_servers")
        for seed in seed_entries
        if require_string(seed, "name", "topology.seed_servers") != name
    ]
    static_registry = [
        {
            "role": "relayer",
            "node_name": require_string(relayer, "node_id", "topology.relayers"),
            "public_endpoint": require_string(relayer, "public_endpoint", "topology.relayers"),
            "protocol_version": "synergy-p2p/1",
            "app_version": "testnet-v3-static",
        }
        for relayer in relayers
    ]
    payload = {
        "schema_version": 1,
        "release_id": NETWORK_ID,
        "chain_id": NETWORK_ID,
        "label": name,
        "seed_id": name,
        "listen_host": "0.0.0.0",
        "port": port,
        "admin_token_env": "SYNERGY_SEED_ADMIN_TOKEN",
        "allow_dynamic_registration": True,
        "state_file": require_string(service_contract, "seed_state_file", "seed service contract"),
        "default_ttl_seconds": require_int(seed_policy, "ttl_seconds", "topology.seed_registry"),
        "max_ttl_seconds": 3600,
        "dialback_timeout_seconds": 1.5,
        "static_dialback_on_start": True,
        "replication_timeout_seconds": 1.0,
        "replication_peers": replication_peers,
        "public_bootstrap_roles": ["relayer"],
        "bootnodes": [],
        "static_peers": [],
        "static_registry": static_registry,
        "dnsaddr_bootstrap": [],
        "release_binding": {
            "genesis_file_sha256": binding["genesis_file_sha256"],
            "genesis_hash": binding["genesis_hash"],
            "consensus_parameter_root_sha3_512": binding["consensus_parameter_root_sha3_512"],
        },
    }
    rendered = (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode()
    if contains_placeholder(rendered.decode()):
        fail("seed service JSON contains an unresolved placeholder")
    if b"config/genesis.json" in rendered:
        fail("seed service JSON contains a working-directory Genesis fallback")
    return rendered


def support_service_activation_context(group: str, entry: dict[str, Any]) -> dict[str, Any] | None:
    """Return the immutable, offline sequence gate for a topology role.

    A context says what *evidence must exist before an operator activates the
    role*.  It is not evidence itself, and contains no command or endpoint that
    could cause the generator to touch a live host.
    """
    name = require_string(entry, "name", f"topology.{group}")
    completed: list[str] = []
    for stage_id, stage_order, participants, _ in SUPPORT_SERVICE_ACTIVATION_STAGES:
        if (group, name) in participants:
            return {
                "sequence_payload": str(SUPPORT_SERVICE_SEQUENCE_PAYLOAD_PATH),
                "activation_stage": stage_id,
                "activation_stage_order": stage_order,
                "requires_completed_live_readiness_stages": completed,
                "offline_contract_only": True,
            }
        completed.append(stage_id)
    if group == "validators":
        return {
            "sequence_payload": str(SUPPORT_SERVICE_SEQUENCE_PAYLOAD_PATH),
            "activation_stage": "validator_start_gate",
            "activation_stage_order": len(SUPPORT_SERVICE_ACTIVATION_STAGES) + 1,
            "requires_completed_live_readiness_stages": completed,
            "offline_contract_only": True,
        }
    return None


def support_service_activation_sequence(
    *,
    binding: dict[str, str],
    nodes: dict[str, dict[str, Any]],
) -> bytes:
    """Render the immutable pre-validator service sequencing contract."""
    stages: list[dict[str, Any]] = []
    for stage_id, stage_order, participants, readiness_requirements in SUPPORT_SERVICE_ACTIVATION_STAGES:
        plans: list[str] = []
        for group, name in participants:
            config_path = output_path(group, {"name": name})
            node = nodes.get(str(config_path))
            if not isinstance(node, dict):
                fail(f"Support sequence participant {group}.{name} was not rendered")
            plan_payload = node.get("activation_plan_payload")
            if not isinstance(plan_payload, str) or not plan_payload:
                fail(f"Support sequence participant {group}.{name} has no activation plan")
            plans.append(plan_payload)
        stages.append(
            {
                "id": stage_id,
                "order": stage_order,
                "activation_plan_payloads": plans,
                "requires_completed_live_readiness_stages": [item[0] for item in SUPPORT_SERVICE_ACTIVATION_STAGES if item[1] < stage_order],
                "required_live_readiness_evidence": list(readiness_requirements),
            }
        )
    validator_plans = [
        node["activation_plan_payload"]
        for config_path, node in sorted(nodes.items())
        if config_path.startswith("validators/")
    ]
    if len(validator_plans) != 6:
        fail("Support sequence requires exactly six generated validator activation plans")
    payload = {
        "schema_version": 1,
        "artifact_type": "testnet-v3-support-service-activation-sequence",
        "prepare_only": True,
        "starts_or_restarts_services": False,
        "contacts_live_hosts": False,
        "offline_contract_only": True,
        "chain_id": CHAIN_ID,
        "network_id": NETWORK_ID,
        "canonical_binding": {
            "genesis_hash": binding["genesis_hash"],
            "genesis_file_sha256": binding["genesis_file_sha256"],
            "consensus_parameter_root_sha3_512": binding["consensus_parameter_root_sha3_512"],
            "consensus_parameter_decision_id": binding["consensus_parameter_decision_id"],
        },
        "stages": stages,
        "validator_start_gate": {
            "activation_plan_payloads": validator_plans,
            "requires_completed_live_readiness_stages": [stage[0] for stage in SUPPORT_SERVICE_ACTIVATION_STAGES],
            "require_external_evidence_record": True,
            "offline_contract_does_not_assert_live_readiness": True,
        },
    }
    return (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode()


def activation_plan(
    *,
    group: str,
    entry: dict[str, Any],
    config_path: Path,
    service_contract: dict[str, Any],
    binding: dict[str, str],
    environment_payload: Path,
    service_binding_payload: Path | None,
    dedicated_payloads: dict[str, str] | None = None,
    service_config_payload: Path | None = None,
    service_config_sha256: str | None = None,
    dedicated_install_map: dict[str, dict[str, str]] | None = None,
    support_service_sequence: dict[str, Any] | None = None,
) -> bytes:
    """Create an explicit non-destructive activation contract per node."""
    dedicated = service_contract.get("deployment_mode") == "dedicated-testnet-v3-service"
    config_install_mode = service_contract.get(
        "config_install_mode",
        "manual_merge_only_preserve_existing_identity_key_port_and_endpoint_settings",
    )
    operator_preconditions: list[str] = []
    if service_contract.get("operator_runtime_binary_mapping_required") is True:
        operator_preconditions.append(
            "A content-addressed Testnet-v3 runtime binary path and its SHA-256 must be supplied in the new dedicated runtime.env; no legacy/testbeta binary path is accepted."
        )
    if service_contract.get("operator_identity_mapping_required") is True:
        operator_preconditions.append(
            "The verified non-validator P2P/private-identity import contract is not present in this release package; map an approved V3 identity or explicitly prove that the runtime may create an isolated replacement identity before activation."
        )
    if service_contract.get("operator_port_preflight_required") is True:
        operator_preconditions.append(
            "Prove all listed ports are unoccupied and match the approved host mapping before activation; do not copy a legacy port or listener configuration blindly."
        )
    effective_config_payload = service_config_payload or config_path
    if service_config_sha256 is None:
        fail("activation plan requires the exact activated config SHA-256")
    plan = {
        "schema_version": 2,
        "prepare_only": True,
        "starts_or_restarts_services": False,
        "reverify_service_contract_before_activation": True,
        # Seeds use the packaged JSON contract consumed by seed_service.py;
        # their generated TOML remains an audit/topology artifact only.  All
        # other roles activate the normal generated TOML payload.
        "config_payload": str(effective_config_payload),
        "config_payload_sha256": service_config_sha256,
        "topology_audit_config_payload": (
            str(config_path) if effective_config_payload != config_path else None
        ),
        "config_install_mode": config_install_mode,
        "environment_payload": str(environment_payload),
        "environment_install_mode": (
            "reference_only_dedicated_unit_embeds_immutable_genesis_binding" if dedicated
            else "merge_release_binding_only_never_replace_existing_environment_file"
        ),
        "service_binding_payload": str(service_binding_payload) if service_binding_payload else None,
        "service_binding_install_mode": (
            "install_new_dedicated_systemd_unit_only_never_replace_or_modify_legacy_unit" if dedicated
            and service_binding_payload is not None
            else
            "write_new_systemd_dropin_only" if service_contract["platform"] == "linux-systemd"
            and service_binding_payload is not None
            else "merge_launchd_environment_variables_only" if service_contract["platform"] == "macos-launchd"
            and service_binding_payload is not None
            else "none_until_manual_service_remediation"
        ),
        "genesis_payload": str(GENESIS_PAYLOAD_PATH),
        "genesis_deploy_path": service_contract["genesis_deploy_path"],
        "genesis_file_sha256": binding["genesis_file_sha256"],
        "runtime_environment": "SYNERGY_GENESIS_FILE",
        "manual_service_remediation_required": service_contract["manual_service_remediation_required"],
        "manual_service_remediation_reason": service_contract["manual_service_remediation_reason"],
        "manual_config_merge_required": service_contract["manual_config_merge_required"],
        "manual_activation_required": True,
        "support_service_activation_sequence": support_service_sequence,
        "operator_preconditions": operator_preconditions,
        "port_preflight": port_preflight(group, entry),
        "dedicated_payloads": dedicated_payloads or {},
        "dedicated_install_map": dedicated_install_map or {},
        "service_contract": service_contract,
    }
    rendered = (json.dumps(plan, indent=2, sort_keys=True) + "\n").encode()
    if b"SYNERGY_GENESIS_FILE" not in rendered or b"config/genesis.json" in rendered:
        fail("activation plan failed Genesis binding invariants")
    return rendered


def deployment_assets(
    genesis_path: Path,
    outputs: dict[Path, str],
    binding: dict[str, str],
    service_contracts: dict[Path, dict[str, Any]],
    service_contexts: dict[Path, tuple[str, dict[str, Any]]],
    topology: dict[str, Any],
) -> tuple[dict[Path, bytes], dict[str, Any]]:
    """Build a single canonical Genesis payload plus per-node install assets.

    The payload is intentionally copied once into the release tree instead of
    making independent per-node Genesis copies.  The deployment manifest binds
    every node to the same source digest and its role-specific absolute
    destination path.
    """
    genesis_bytes = genesis_path.read_bytes()
    genesis_sha256 = sha256_file(genesis_path)
    if genesis_sha256 != binding["genesis_file_sha256"]:
        fail("Genesis payload SHA-256 disagrees with the generated launch binding")
    rendered: dict[Path, bytes] = {
        GENESIS_PAYLOAD_PATH: genesis_bytes,
        GENESIS_CHECKSUM_PATH: f"{genesis_sha256}  genesis.json\n".encode(),
    }
    nodes: dict[str, dict[str, Any]] = {}
    for config_path in sorted(outputs):
        service_contract = service_contracts.get(config_path)
        if service_contract is None:
            fail(f"Generated config {config_path} has no service deployment contract")
        context = service_contexts.get(config_path)
        if context is None:
            fail(f"Generated config {config_path} has no topology service context")
        group, entry = context
        payload_root = deployment_directory(config_path)
        env_path = payload_root / "node.env"
        plan_path = payload_root / "activation-plan.json"
        env_content = node_environment(binding, service_contract).encode()
        rendered[env_path] = env_content
        binding_path: Path | None = None
        dedicated_payloads: dict[str, str] = {}
        dedicated_install_map: dict[str, dict[str, str]] = {}
        service_config_payload: Path | None = None
        if service_contract.get("deployment_mode") == "dedicated-testnet-v3-service":
            unit_name = require_string(
                service_contract,
                "service_unit_template" if service_contract.get("runtime_kind") == "seed" else "service_unit",
                "dedicated systemd service contract",
            )
            binding_path = payload_root / "dedicated-systemd" / unit_name
            if service_contract.get("runtime_kind") == "seed":
                seed_source_path = repository_root() / "runtime/scripts/testnet/seed_service.py"
                if not seed_source_path.is_file():
                    fail(f"Dedicated V3 seed service source is missing: {seed_source_path}")
                seed_source = seed_source_path.read_bytes()
                seed_config = seed_service_config(
                    entry=entry,
                    topology=topology,
                    binding=binding,
                    service_contract=service_contract,
                )
                source_payload_path = payload_root / "dedicated-seed" / "seed_service.py"
                seed_config_path = payload_root / "dedicated-seed" / "seed-service.json"
                guard_payload_path = payload_root / "dedicated-seed" / "synergy-seed-release-guard"
                rendered[source_payload_path] = seed_source
                rendered[seed_config_path] = seed_config
                rendered[guard_payload_path] = seed_release_guard()
                rendered[binding_path] = dedicated_systemd_unit(
                    group=group,
                    entry=entry,
                    binding=binding,
                    service_contract=service_contract,
                    seed_config_sha256=hashlib.sha256(seed_config).hexdigest(),
                    seed_script_sha256=hashlib.sha256(seed_source).hexdigest(),
                )
                dedicated_payloads = {
                    "systemd_unit": str(binding_path),
                    "seed_service_source": str(source_payload_path),
                    "seed_service_config": str(seed_config_path),
                    "seed_launch_guard": str(guard_payload_path),
                }
                service_config_payload = seed_config_path
                dedicated_install_map = {
                    "systemd_unit": {
                        "payload": str(binding_path),
                        "deploy_path": require_string(service_contract, "service_fragment_path", "seed service contract"),
                        "install_mode": "copy_new_v3_template_unit_do_not_enable_or_start",
                    },
                    "seed_service_source": {
                        "payload": str(source_payload_path),
                        "deploy_path": require_string(service_contract, "seed_service_script_deploy_path", "seed service contract"),
                        "install_mode": "copy_new_v3_source_mode_0555",
                    },
                    "seed_launch_guard": {
                        "payload": str(guard_payload_path),
                        "deploy_path": require_string(service_contract, "seed_launch_guard_deploy_path", "seed service contract"),
                        "install_mode": "copy_new_v3_guard_mode_0555",
                    },
                }
            else:
                guard_payload_path = payload_root / "dedicated-runtime" / "synergy-release-guard"
                runtime_env_example_path = payload_root / "dedicated-runtime" / "runtime.env.example"
                rendered[guard_payload_path] = runtime_release_guard()
                rendered[runtime_env_example_path] = dedicated_runtime_environment_example()
                rendered[binding_path] = dedicated_systemd_unit(
                    group=group,
                    entry=entry,
                    binding=binding,
                    service_contract=service_contract,
                    runtime_config_sha256=hashlib.sha256(outputs[config_path].encode()).hexdigest(),
                )
                dedicated_payloads = {
                    "systemd_unit": str(binding_path),
                    "runtime_launch_guard": str(guard_payload_path),
                    "runtime_environment_example": str(runtime_env_example_path),
                }
                dedicated_install_map = {
                    "systemd_unit": {
                        "payload": str(binding_path),
                        "deploy_path": require_string(service_contract, "service_fragment_path", "dedicated service contract"),
                        "install_mode": "copy_new_v3_unit_do_not_enable_or_start",
                    },
                    "runtime_launch_guard": {
                        "payload": str(guard_payload_path),
                        "deploy_path": require_string(service_contract, "runtime_launch_guard_deploy_path", "dedicated service contract"),
                        "install_mode": "copy_new_v3_guard_mode_0555",
                    },
                    "runtime_environment_example": {
                        "payload": str(runtime_env_example_path),
                        "deploy_path": require_string(service_contract, "runtime_environment_file", "dedicated service contract"),
                        "install_mode": "operator_create_filled_content_addressed_environment_file_mode_0600",
                    },
                }
        elif service_contract["platform"] == "linux-systemd" and not service_contract["manual_service_remediation_required"]:
            unit = require_string(service_contract, "service_unit", "systemd service deployment contract")
            binding_path = payload_root / "systemd" / f"{unit}.d" / SYSTEMD_GENESIS_DROPIN_NAME
            rendered[binding_path] = systemd_genesis_dropin(binding, service_contract).encode()
        elif service_contract["platform"] == "macos-launchd":
            binding_path = payload_root / "launchd" / LAUNCHD_GENESIS_BINDING_NAME
            rendered[binding_path] = launchd_genesis_binding(binding, service_contract)
        effective_config_payload = service_config_payload or config_path
        effective_config_bytes = (
            rendered[effective_config_payload]
            if effective_config_payload in rendered
            else outputs[config_path].encode()
        )
        effective_config_sha256 = hashlib.sha256(effective_config_bytes).hexdigest()
        rendered[plan_path] = activation_plan(
            group=group,
            entry=entry,
            config_path=config_path,
            service_contract=service_contract,
            binding=binding,
            environment_payload=env_path,
            service_binding_payload=binding_path,
            dedicated_payloads=dedicated_payloads,
            service_config_payload=service_config_payload,
            service_config_sha256=effective_config_sha256,
            dedicated_install_map=dedicated_install_map,
            support_service_sequence=support_service_activation_context(group, entry),
        )
        nodes[str(config_path)] = {
            "config_payload": str(effective_config_payload),
            "config_payload_sha256": effective_config_sha256,
            "topology_audit_config_payload": (
                str(config_path) if effective_config_payload != config_path else None
            ),
            "config_deploy_path": service_contract["existing_config_path"],
            "config_install_mode": service_contract.get(
                "config_install_mode",
                "manual_merge_only_preserve_existing_identity_key_port_and_endpoint_settings",
            ),
            "environment_payload": str(env_path),
            "environment_install_mode": (
                "reference_only_dedicated_unit_embeds_immutable_genesis_binding"
                if service_contract.get("deployment_mode") == "dedicated-testnet-v3-service"
                else "merge_release_binding_only_never_replace_existing_environment_file"
            ),
            "service_binding_payload": str(binding_path) if binding_path else None,
            "activation_plan_payload": str(plan_path),
            "dedicated_payloads": dedicated_payloads,
            "dedicated_install_map": dedicated_install_map,
            "service_contract": service_contract,
            "genesis_deploy_path": service_contract["genesis_deploy_path"],
            "genesis_file_sha256": genesis_sha256,
            "support_service_activation_sequence": support_service_activation_context(group, entry),
        }

    rendered[SUPPORT_SERVICE_SEQUENCE_PAYLOAD_PATH] = support_service_activation_sequence(
        binding=binding,
        nodes=nodes,
    )
    destinations = sorted({record["genesis_deploy_path"] for record in nodes.values()})
    remediation = sorted(
        config_path for config_path, record in nodes.items()
        if record["service_contract"]["manual_service_remediation_required"]
    )
    manifest = {
        "schema_version": 2,
        "prepare_only": True,
        "starts_or_restarts_services": False,
        "canonical_genesis": {
            "payload": str(GENESIS_PAYLOAD_PATH),
            "payload_sha256": genesis_sha256,
            "deploy_paths": destinations,
            "deploy_mode": GENESIS_DEPLOY_MODE,
            "content_addressed": True,
            "runtime_environment": "SYNERGY_GENESIS_FILE",
        },
        "nodes": nodes,
        "manual_service_remediation_required": remediation,
        "deployment_files": {
            str(path): hashlib.sha256(content).hexdigest()
            for path, content in sorted(rendered.items())
        },
    }
    return rendered, manifest


def build_outputs(
    genesis_path: Path,
    topology_path: Path,
    registry_path: Path,
    release_binding: dict[str, str],
) -> tuple[dict[Path, str], dict[str, Any], dict[Path, bytes]]:
    genesis = read_json_object(genesis_path, "Genesis")
    registry = read_json_object(registry_path, "VPN registry")
    with topology_path.open("rb") as handle:
        topology = tomllib.load(handle)
    if contains_placeholder(topology) or contains_placeholder(registry):
        fail("Topology or VPN registry still contains a placeholder")
    finalized_release(genesis)
    active_validators = active_validator_addresses(genesis)
    if topology.get("network", {}).get("chain_id") != CHAIN_ID or topology.get("network", {}).get("network_id") != CHAIN_ID:
        fail("Topology does not bind chain_id/network_id 1266")
    strict = topology.get("consensus", {}).get("strict_validator_allowlist")
    if strict != active_validators:
        fail("Topology strict validator allowlist disagrees with finalized Genesis active order")

    identities = genesis.get("node_identities")
    if not isinstance(identities, list):
        fail("Genesis node_identities is missing")
    identities_by_workbook: dict[str, dict[str, Any]] = {}
    for identity in identities:
        if not isinstance(identity, dict):
            fail("Genesis contains a malformed node identity")
        # The finalized identity inventory retains future validators without a
        # workbook assignment.  They are not launch nodes and must not make the
        # six-validator release config generator fail.
        workbook_value = identity.get("workbook_node")
        if workbook_value is None or not str(workbook_value).strip():
            continue
        workbook = require_string(identity, "workbook_node", "Genesis node identity")
        if workbook in identities_by_workbook:
            fail(f"Genesis has duplicate workbook identity {workbook}")
        identities_by_workbook[workbook] = identity

    participants = registry.get("participants")
    if not isinstance(participants, list):
        fail("VPN registry participants is missing")
    active_vpn_validators = [
        item for item in participants
        if isinstance(item, dict) and item.get("role") == "validator" and item.get("activation_status") == "active"
    ]
    if len(active_vpn_validators) != 6:
        fail("VPN registry must contain exactly six active validator transports")
    transports: list[tuple[str, str]] = []
    for participant in active_vpn_validators:
        address = require_string(participant, "synv_address", "VPN validator participant")
        vpn_ip = require_string(participant, "vpn_ip", "VPN validator participant")
        if address not in active_validators:
            fail(f"Active VPN validator {address} is not active in finalized Genesis")
        transports.append((address, f"{vpn_ip}:{VALIDATOR_P2P_PORT}"))
    transports.sort(key=lambda item: active_validators.index(item[0]))
    if [address for address, _ in transports] != active_validators:
        fail("VPN registry validator order/set disagrees with finalized Genesis")

    active_relayer_transports = sorted(
        f"{require_string(item, 'vpn_ip', 'VPN relayer participant')}:{VALIDATOR_P2P_PORT}"
        for item in participants
        if isinstance(item, dict) and item.get("role") == "relayer" and item.get("activation_status") == "active"
    )
    if len(active_relayer_transports) != 3:
        fail("VPN registry must contain exactly three active relayer transports")

    integrity = genesis["integrity"]
    binding = {
        "genesis_hash": integrity["genesis_hash"],
        "genesis_file_sha256": sha256_file(genesis_path),
        "topology_sha256": sha256_file(topology_path),
        "vpn_registry_sha256": sha256_file(registry_path),
        "consensus_parameter_root_sha3_512": require_string(integrity, "consensus_parameter_root_sha3_512", "Genesis integrity"),
        "consensus_parameter_decision_id": require_string(integrity, "consensus_parameter_decision_id", "Genesis integrity"),
        **release_binding,
    }
    outputs: dict[Path, str] = {}
    service_contracts: dict[Path, dict[str, Any]] = {}
    service_contexts: dict[Path, tuple[str, dict[str, Any]]] = {}
    for group, entry in topology_nodes(topology):
        workbook = workbook_node(group, entry)
        identity = identities_by_workbook.get(workbook)
        if identity is None:
            fail(f"Finalized Genesis has no node identity for {workbook}")
        config_path = output_path(group, entry)
        service_contract = deployment_contract(group, entry)
        outputs[config_path] = toml_config(
            group=group,
            entry=entry,
            topology=topology,
            identity=identity,
            active_validators=active_validators,
            active_validator_transports=transports,
            active_relayer_transports=active_relayer_transports,
            binding=binding,
            service_contract=service_contract,
        )
        service_contracts[config_path] = service_contract
        service_contexts[config_path] = (group, entry)
    payloads, deployment = deployment_assets(
        genesis_path,
        outputs,
        binding,
        service_contracts,
        service_contexts,
        topology,
    )
    manifest = {
        "schema_version": 2,
        "generator_version": GENERATOR_VERSION,
        "chain_id": CHAIN_ID,
        "network_id": NETWORK_ID,
        "binding": binding,
        "deployment": deployment,
        "signed_validator_transport_registry_required": True,
        "config_files": {str(path): hashlib.sha256(text.encode()).hexdigest() for path, text in sorted(outputs.items())},
    }
    return outputs, manifest, payloads


def expected_tree(
    outputs: dict[Path, str],
    manifest: dict[str, Any],
    deployment_payloads: dict[Path, bytes],
) -> dict[Path, bytes]:
    rendered = {path: text.encode() for path, text in outputs.items()}
    if set(rendered).intersection(deployment_payloads):
        fail("Generated config and deployment payload paths overlap")
    rendered.update(deployment_payloads)
    rendered[Path("release-config-manifest.json")] = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode()
    return rendered


def check_output(output_dir: Path, expected: dict[Path, bytes]) -> None:
    actual = {path.relative_to(output_dir): path.read_bytes() for path in output_dir.rglob("*") if path.is_file()}
    if actual.keys() != expected.keys():
        missing = sorted(str(item) for item in expected.keys() - actual.keys())
        unexpected = sorted(str(item) for item in actual.keys() - expected.keys())
        fail(f"Generated config tree differs (missing={missing}, unexpected={unexpected})")
    mismatched = [str(path) for path in expected if actual[path] != expected[path]]
    if mismatched:
        fail(f"Generated config content differs: {', '.join(sorted(mismatched))}")


def publish_output(output_dir: Path, expected: dict[Path, bytes]) -> Path | None:
    output_dir.parent.mkdir(parents=True, exist_ok=True)
    stage = Path(tempfile.mkdtemp(prefix=f".{output_dir.name}.stage-", dir=output_dir.parent))
    for path, content in expected.items():
        target = stage / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)
    backup: Path | None = None
    if output_dir.exists():
        backup = output_dir.with_name(f"{output_dir.name}.backup-{sha256_file(stage / 'release-config-manifest.json')[:12]}")
        if backup.exists():
            fail(f"Refusing to overwrite existing backup {backup}")
        os.rename(output_dir, backup)
    try:
        os.rename(stage, output_dir)
    except Exception:
        if backup is not None and not output_dir.exists():
            os.rename(backup, output_dir)
        raise
    return backup


def self_test(genesis_path: Path, topology_path: Path, registry_path: Path) -> None:
    """Exercise release authorization and rendering using an isolated fake verifier.

    Production always uses the runtime ML-DSA verifier.  The fake executable
    below exists only inside this self-test so a signed governance artifact is
    neither needed nor manufactured during a local generator check.
    """
    candidate = read_json_object(genesis_path, "Genesis")
    root = repository_root()
    deployment = genesis_deployment(candidate)
    integrity = candidate["integrity"]
    consensus_parameters = candidate["consensus_parameters"]
    with tempfile.TemporaryDirectory(prefix=".testnet-v3-config-generator-", dir=root) as temp:
        temp_path = Path(temp)
        fake_genesis = temp_path / "genesis.testnet-v3.identity-assigned.json"
        fake_genesis.write_text(json.dumps(candidate, sort_keys=True))
        fake_approval = temp_path / "testnet-v3-genesis-release-approval.json"
        fake_approval.write_text('{"synthetic":"approval"}\n')
        fake_integrity = temp_path / "phase7-release-integrity.json"
        fake_verifier = temp_path / "testnet-v3-genesis-release-approval"
        fake_verifier.write_text(
            "#!/usr/bin/env python3\n"
            "import hashlib, json, pathlib, sys\n"
            "def value(flag):\n"
            "    return pathlib.Path(sys.argv[sys.argv.index(flag) + 1])\n"
            "approval = value('--approval')\n"
            "candidate = value('--candidate')\n"
            "payload = json.loads(candidate.read_text())\n"
            "print(json.dumps({\n"
            "    'result': 'RELEASE_APPROVAL_VERIFIED',\n"
            "    'approval_sha256': hashlib.sha256(approval.read_bytes()).hexdigest(),\n"
            "    'candidate_sha256': hashlib.sha256(candidate.read_bytes()).hexdigest(),\n"
            "    'genesis_hash': payload['integrity']['genesis_hash'],\n"
            "    'governance_authority_role': 'SNRG-TESTNET-V3-GOVERNANCE-AUTHORITY',\n"
            "    'governance_standard_account_address': 'syna1adxk7errymz8p8s0k5ysmka9pjv9ntf9jlml',\n"
            "}))\n"
        )
        fake_verifier.chmod(0o700)
        fake_release = {
            "schema_version": 1,
            "status": RELEASE_INTEGRITY_STATUS,
            "genesis_file": str(fake_genesis.relative_to(root)),
            "genesis_file_sha256": sha256_file(fake_genesis),
            "genesis_hash": integrity["genesis_hash"],
            "execution_state_root": deployment["post_deployment_execution_state_root"],
            "aivm_state_root": deployment["post_deployment_aivm_state_root"],
            "receipt_root": deployment["receipt_root"],
            "consensus_parameter_decision_id": consensus_parameters["decision_id"],
            "consensus_parameter_manifest_sha256": consensus_parameters["canonical_manifest_sha256"],
            "consensus_parameter_root_sha3_512": consensus_parameters["parameter_root_sha3_512"],
            "release_approval_artifact": str(fake_approval.relative_to(root)),
            "release_approval_artifact_sha256": sha256_file(fake_approval),
            "release_approval_governance_role": "SNRG-TESTNET-V3-GOVERNANCE-AUTHORITY",
            "release_approval_governance_address": "syna1adxk7errymz8p8s0k5ysmka9pjv9ntf9jlml",
        }
        fake_integrity.write_text(json.dumps(fake_release, sort_keys=True))
        release_binding = verify_release_authorization(
            genesis_path=fake_genesis,
            genesis=candidate,
            approval_path=fake_approval,
            release_integrity_path=fake_integrity,
            authorities_path=repository_root() / "launch/TESTNET_V3_PRODUCTION_AUTHORITIES.json",
            approval_verifier=fake_verifier,
        )
        outputs, manifest, deployment_payloads = build_outputs(
            fake_genesis, topology_path, registry_path, release_binding
        )
        expected = expected_tree(outputs, manifest, deployment_payloads)
        if len(outputs) != 19 or any(contains_placeholder(value.decode()) for value in expected.values()):
            fail("self-test did not build all placeholder-free node configs")
        deployment = manifest.get("deployment")
        if not isinstance(deployment, dict):
            fail("self-test did not produce a deployment binding")
        canonical_genesis = deployment.get("canonical_genesis")
        if not isinstance(canonical_genesis, dict):
            fail("self-test did not produce a canonical Genesis deployment binding")
        expected_genesis_paths = sorted({
            require_string(contract, "genesis_deploy_path", "service deployment contract")
            for contract in SERVICE_CONTRACTS.values()
        })
        if canonical_genesis.get("deploy_paths") != expected_genesis_paths:
            fail("self-test did not bind the role-specific absolute Genesis deploy paths")
        if (
            canonical_genesis.get("deploy_mode") != GENESIS_DEPLOY_MODE
            or canonical_genesis.get("content_addressed") is not True
        ):
            fail("self-test did not preserve immutable Genesis deployment metadata")
        if canonical_genesis.get("payload_sha256") != sha256_file(fake_genesis):
            fail("self-test Genesis payload SHA-256 does not match the canonical Genesis")
        if expected.get(GENESIS_PAYLOAD_PATH) != fake_genesis.read_bytes():
            fail("self-test generated Genesis payload is not byte-identical to canonical Genesis")
        expected_node_envs = [path for path in expected if path.name == "node.env"]
        expected_dropins = [path for path in expected if path.name == SYSTEMD_GENESIS_DROPIN_NAME]
        expected_plans = [path for path in expected if path.name == "activation-plan.json"]
        expected_launchd = [path for path in expected if path.name == LAUNCHD_GENESIS_BINDING_NAME]
        expected_dedicated_units = [path for path in expected if "dedicated-systemd" in path.parts and path.suffix == ".service"]
        expected_seed_configs = [path for path in expected if path.name == "seed-service.json"]
        expected_seed_sources = [path for path in expected if path.name == "seed_service.py"]
        if (
            len(expected_node_envs) != 19
            or len(expected_plans) != 19
            or len(expected_dropins) != 12
            or len(expected_launchd) != 1
            or len(expected_dedicated_units) != 6
            or len(expected_seed_configs) != 3
            or len(expected_seed_sources) != 3
        ):
            fail("self-test did not produce the expected role-specific prepare-only binding artifacts")
        sequence_payload = expected.get(SUPPORT_SERVICE_SEQUENCE_PAYLOAD_PATH)
        if sequence_payload is None:
            fail("self-test did not produce the support-service activation sequence artifact")
        sequence = json.loads(sequence_payload)
        if (
            sequence.get("prepare_only") is not True
            or sequence.get("starts_or_restarts_services") is not False
            or sequence.get("contacts_live_hosts") is not False
            or [stage.get("id") for stage in sequence.get("stages", [])]
            != [stage[0] for stage in SUPPORT_SERVICE_ACTIVATION_STAGES]
        ):
            fail("self-test found an unsafe or incomplete support-service activation sequence")
        validator_gate = sequence.get("validator_start_gate")
        if not isinstance(validator_gate, dict) or len(validator_gate.get("activation_plan_payloads", [])) != 6:
            fail("self-test found a support sequence without the six-validator start gate")
        if any(b"SYNERGY_GENESIS_FILE=" not in expected[path] for path in expected_node_envs):
            fail("self-test found a node environment without the absolute Genesis binding")
        if any(
            f"Environment=SYNERGY_GENESIS_FILE={LINUX_GENESIS_DEPLOY_PATH}".encode() not in expected[path]
            for path in expected_dropins
        ):
            fail("self-test found a service drop-in without the absolute Genesis binding")
        launchd_payload = plistlib.loads(expected[expected_launchd[0]])
        if launchd_payload.get("Label") != "network.synergy.archive-validator" or launchd_payload.get("EnvironmentVariables", {}).get("SYNERGY_GENESIS_FILE") != MACOS_ARCHIVE_GENESIS_DEPLOY_PATH:
            fail("self-test found an invalid macOS archive launchd binding")
        if any(b"config/genesis.json" in expected[path] for path in expected):
            fail("self-test found a working-directory Genesis fallback in deployment assets")
        remediation = deployment.get("manual_service_remediation_required")
        if remediation != []:
            fail("self-test did not eliminate legacy service-remediation P0s with dedicated V3 templates")
        validator_env = expected[Path("deployment/validators/val1/node.env")]
        if b"SYNERGY_CONFIG_FILE=/etc/synergy/validator/config.toml" not in validator_env:
            fail("self-test did not preserve the validator service config path")
        relayer_env = expected[Path("deployment/relayers/relay1/node.env")]
        if b"SYNERGY_CONFIG_FILE=" in relayer_env:
            fail("self-test treated a relative relayer config path as globally deployable")
        for plan_path in expected_plans:
            plan = json.loads(expected[plan_path])
            if plan.get("prepare_only") is not True or plan.get("starts_or_restarts_services") is not False:
                fail("self-test found a non-prepare-only activation plan")
            sequence_context = plan.get("support_service_activation_sequence")
            if plan_path.parts[1] in {"bootnodes", "seed-servers", "relayers", "rpc-gateway", "explorer-indexer", "validators"}:
                if not isinstance(sequence_context, dict) or sequence_context.get("sequence_payload") != str(SUPPORT_SERVICE_SEQUENCE_PAYLOAD_PATH):
                    fail("self-test found a support or validator plan without the immutable sequence gate")
            elif sequence_context is not None:
                fail("self-test found a non-support plan incorrectly bound to the support sequence")
            config_payload = Path(plan.get("config_payload", ""))
            if config_payload not in expected or plan.get("config_payload_sha256") != hashlib.sha256(expected[config_payload]).hexdigest():
                fail("self-test found an activation plan without the exact activated config payload hash")
            is_dedicated = plan.get("service_contract", {}).get("deployment_mode") == "dedicated-testnet-v3-service"
            if is_dedicated:
                if plan.get("config_install_mode") != "install_new_isolated_testnet_v3_config_only":
                    fail("self-test found a dedicated activation plan that could reuse a legacy config")
                if plan.get("service_binding_install_mode") != "install_new_dedicated_systemd_unit_only_never_replace_or_modify_legacy_unit":
                    fail("self-test found a dedicated activation plan that could alter a legacy unit")
                install_map = plan.get("dedicated_install_map")
                if not isinstance(install_map, dict) or "systemd_unit" not in install_map:
                    fail("self-test found a dedicated activation plan without exact artifact deployment paths")
                if not install_map["systemd_unit"].get("deploy_path", "").startswith("/etc/systemd/system/synergy-testnet-v3-"):
                    fail("self-test found a dedicated unit deployment outside the isolated V3 systemd namespace")
                if plan_path == Path("deployment/seed-servers/seed1/activation-plan.json"):
                    if plan.get("config_payload") != "deployment/seed-servers/seed1/dedicated-seed/seed-service.json":
                        fail("self-test did not use the JSON seed service config as the activated config payload")
                    if plan.get("topology_audit_config_payload") != "seed-servers/seed1.toml":
                        fail("self-test did not retain the seed TOML as an audit-only payload")
                    if install_map["systemd_unit"].get("deploy_path") != "/etc/systemd/system/synergy-testnet-v3-seed@.service":
                        fail("self-test did not install the seed template at its template path")
            elif plan_path.parts[1] in {"validators", "relayers"}:
                if (
                    plan.get("config_install_mode")
                    != "replace_with_checksum_bound_canonical_testnet_v3_config_after_backup_and_inactive_service_preflight"
                    or plan.get("manual_config_merge_required") is not False
                ):
                    fail("self-test found a validator or relayer plan without the required canonical config replacement contract")
            elif plan.get("config_install_mode") != "manual_merge_only_preserve_existing_identity_key_port_and_endpoint_settings":
                fail("self-test found an activation plan that could overwrite host-specific settings")
        for unit_path in expected_dedicated_units:
            unit = expected[unit_path]
            if b"DynamicUser=yes" not in unit or b"[Install]" in unit or b"systemctl " in unit:
                fail("self-test found a dedicated service unit with unsafe ownership or activation behavior")
            if b"testbeta" in unit or b"synergy-node-exp.service" in unit or b"synergy-testnet-bootnode2.service" in unit:
                fail("self-test found a dedicated service unit that references a legacy P0 unit")
            if b"seed@.service" not in unit_path.name.encode() and b"Environment=SYNERGY_CONFIG_SHA256=" not in unit:
                fail("self-test found a dedicated runtime unit without an immutable config hash")
        for seed_config_path in expected_seed_configs:
            seed_config = json.loads(expected[seed_config_path])
            if seed_config.get("chain_id") != NETWORK_ID or seed_config.get("release_binding", {}).get("genesis_file_sha256") != sha256_file(fake_genesis):
                fail("self-test found a seed configuration not bound to Testnet-v3 Genesis")
        target = temp_path / "generated"
        publish_output(target, expected)
        check_output(target, expected)
        # A changed allowlist must be rejected before any config is rendered.
        bad_topology = tomllib.loads(topology_path.read_text())
        bad_topology["consensus"]["strict_validator_allowlist"] = []
        bad_path = temp_path / "bad-topology.toml"
        bad_path.write_text(topology_path.read_text().replace(
            "strict_validator_allowlist = [", "strict_validator_allowlist = [\n  \"not-a-validator\",", 1
        ))
        try:
            build_outputs(fake_genesis, bad_path, registry_path, release_binding)
        except ValidationError:
            pass
        else:
            fail("self-test expected malformed allowlist rejection")
        # A generic fallback is forbidden: every topology role needs an exact
        # service contract before the release tree can be rendered.
        validator_contract = SERVICE_CONTRACTS.pop(("validators", "Val1"))
        try:
            try:
                build_outputs(fake_genesis, topology_path, registry_path, release_binding)
            except ValidationError:
                pass
            else:
                fail("self-test expected missing service contract rejection")
        finally:
            SERVICE_CONTRACTS[("validators", "Val1")] = validator_contract
        fake_release["genesis_file_sha256"] = "0" * 64
        fake_integrity.write_text(json.dumps(fake_release, sort_keys=True))
        try:
            verify_release_authorization(
                genesis_path=fake_genesis,
                genesis=candidate,
                approval_path=fake_approval,
                release_integrity_path=fake_integrity,
                authorities_path=repository_root() / "launch/TESTNET_V3_PRODUCTION_AUTHORITIES.json",
                approval_verifier=fake_verifier,
            )
        except ValidationError:
            pass
        else:
            fail("self-test expected mismatched release-integrity rejection")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--genesis", type=Path, required=True, help="finalized Testnet-v3 Genesis JSON")
    parser.add_argument("--topology", type=Path, required=True, help="canonical Testnet-v3 topology TOML")
    parser.add_argument("--vpn-public-registry", type=Path, required=True, help="validated public VPN registry JSON")
    parser.add_argument(
        "--authorities-file",
        type=Path,
        default=repository_root() / "launch/TESTNET_V3_PRODUCTION_AUTHORITIES.json",
        help="frozen production authority record used by the Rust approval verifier",
    )
    parser.add_argument(
        "--release-approval",
        type=Path,
        default=repository_root() / "launch/production-genesis-ceremony/testnet-v3-genesis-release-approval.json",
        help="exact signed Testnet-v3 governance release-approval artifact",
    )
    parser.add_argument(
        "--release-integrity",
        type=Path,
        default=repository_root() / "launch/production-genesis-ceremony/phase7-release-integrity.json",
        help="Phase-7/8 post-apply release-integrity evidence",
    )
    parser.add_argument(
        "--approval-verifier",
        type=Path,
        default=repository_root() / "runtime/target/debug/testnet-v3-genesis-release-approval",
        help="built Rust release-approval verifier (never a signing tool)",
    )
    parser.add_argument("--output-dir", type=Path, help="generated config output directory")
    mode = parser.add_mutually_exclusive_group(required=False)
    mode.add_argument("--apply", action="store_true", help="publish a newly generated tree (backs up an existing tree)")
    mode.add_argument("--check", action="store_true", help="verify an existing generated tree is exact")
    mode.add_argument("--self-test", action="store_true", help="exercise deterministic rendering without publishing")
    args = parser.parse_args()
    try:
        for path in (args.genesis, args.topology, args.vpn_public_registry):
            if not path.is_file():
                fail(f"Required input does not exist: {path}")
        if args.self_test:
            self_test(args.genesis, args.topology, args.vpn_public_registry)
            print(
                "SELF_TEST_PASSED configs=19 genesis_payload=byte_identical "
                "role_specific_prepare_plans=19 systemd_dropins=12 dedicated_systemd_units=6 "
                "launchd_bindings=1 manual_service_remediation=0 release_gate_rejection=passed "
                "service_contract_rejection=passed placeholder_rejection=passed"
            )
            return 0
        if not args.apply and not args.check:
            fail("Specify exactly one of --apply, --check, or --self-test")
        if args.output_dir is None:
            fail("--output-dir is required for --apply or --check")
        genesis = read_json_object(args.genesis, "Genesis")
        release_binding = verify_release_authorization(
            genesis_path=args.genesis,
            genesis=genesis,
            approval_path=args.release_approval,
            release_integrity_path=args.release_integrity,
            authorities_path=args.authorities_file,
            approval_verifier=args.approval_verifier,
        )
        outputs, manifest, deployment_payloads = build_outputs(
            args.genesis, args.topology, args.vpn_public_registry, release_binding
        )
        expected = expected_tree(outputs, manifest, deployment_payloads)
        if args.check:
            check_output(args.output_dir, expected)
            print(f"CHECK_PASSED configs={len(outputs)} output={args.output_dir}")
        else:
            backup = publish_output(args.output_dir, expected)
            print(f"APPLY_PASSED configs={len(outputs)} output={args.output_dir}")
            if backup is not None:
                print(f"PREVIOUS_TREE_BACKUP={backup}")
    except (OSError, ValueError, json.JSONDecodeError, tomllib.TOMLDecodeError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
