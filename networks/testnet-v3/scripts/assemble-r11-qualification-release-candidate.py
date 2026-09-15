#!/usr/bin/env python3
"""Seal an R11 local-qualification release candidate without deploying it.

The inputs are deliberately supplied by the caller after the five-validator
qualification run.  This command never creates custody material, signs
anything, starts a node, or contacts a host.  It invokes the repository's
canonical desired-state and unsigned V4-request tools, then writes a
checksumed, read-only evidence package.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


VALIDATORS = tuple(f"validator-{number:02d}" for number in range(2, 7))
REGISTRY_HEIGHTS = tuple(range(3, 21))
SUMMARY_MARKERS = (
    "H1_H2_BOOTSTRAP_FINALIZED=YES",
    "H3_NORMAL_ETDAG_FINALIZED=YES",
    "H4_STEADY_STATE_FINALIZED=YES",
    "HARNESS_20_BLOCK_PASS=YES",
    "VALIDATOR_RESTART_PASS=YES",
)
V4_DOMAIN = "SYNERGY_TESTNET_V3_GENESIS_RELEASE_APPROVAL_V4"
PRIVATE_NAME = re.compile(r"(?:^|[-_.])(key|keys|private|secret|seed|wallet|keystore|custody)(?:$|[-_.])", re.I)
REVISION = re.compile(r"^[0-9a-f]{40}$")


def fail(message: str) -> "NoReturn":
    raise SystemExit(f"assemble-r11-qualification-release-candidate: {message}")


def require(condition: bool, message: str) -> None:
    if not condition:
        fail(message)


def sha256_path(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def read_json(path: Path) -> dict[str, Any]:
    require(path.is_file() and not path.is_symlink(), f"expected regular JSON file: {path}")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        fail(f"read {path}: {error}")
    require(isinstance(value, dict), f"{path} must be a JSON object")
    return value


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def require_regular(path: Path, label: str, executable: bool = False) -> None:
    require(path.is_file() and not path.is_symlink(), f"{label} must be a regular file: {path}")
    require(os.access(path, os.R_OK), f"{label} is not readable: {path}")
    if executable:
        require(os.access(path, os.X_OK), f"{label} is not executable: {path}")


def copy_regular(source: Path, destination: Path) -> None:
    require_regular(source, "package input")
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, destination)


def assert_no_private_name(path: Path) -> None:
    for part in path.parts:
        require(not PRIVATE_NAME.search(part), f"refusing private/custody-named package input: {path}")


def checked_configurations(config_dir: Path, validator_binary: Path) -> dict[str, Path]:
    require(config_dir.is_dir() and not config_dir.is_symlink(), f"config directory is invalid: {config_dir}")
    output: dict[str, Path] = {}
    for validator in VALIDATORS:
        path = config_dir / validator / "config.toml"
        require_regular(path, f"{validator} configuration")
        assert_no_private_name(path.relative_to(config_dir))
        try:
            result = subprocess.run(
                [str(validator_binary), "validate-config", "--config", str(path)],
                check=False,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
            )
        except OSError as error:
            fail(f"run validator config parser for {validator}: {error}")
        require(result.returncode == 0, f"{validator} failed production config parser: {result.stdout.strip()}")
        require(f"validator_id={validator}" in result.stdout,
                f"{validator} parser output does not bind its validator identity")
        require("chain_id=1266 network_id=testnet protocol=posy/3.0 mode=posy_simplified_v3" in result.stdout,
                f"{validator} parser output is not the fresh Chain-1266 P3 profile")
        output[validator] = path
    return output


def validate_final_genesis(path: Path) -> dict[str, Any]:
    value = read_json(path)
    activation = value.get("consensus", {}).get("posy_v3_activation", {})
    manifest = activation.get("manifest", {}) if isinstance(activation, dict) else {}
    require(value.get("network", {}).get("chain_id") == 1266,
            "final Genesis does not bind Chain 1266")
    require(manifest.get("protocol_version") == "posy/3.0" and manifest.get("network_id") == "testnet",
            "final Genesis is not the fresh testnet PoSy/3.0 artifact")
    require(manifest.get("initial_validator_ids") == list(VALIDATORS),
            "final Genesis must bind exactly validator-02 through validator-06")
    require(manifest.get("target_block_time_ms") == 500,
            "final Genesis does not bind the R11 500 ms target")
    deployment = value.get("genesis_deployment", {})
    require(isinstance(deployment, dict) and deployment.get("status") == "EXECUTED_AND_BOUND",
            "final Genesis does not contain verified deployment evidence")
    require(value.get("integrity", {}).get("status") == "candidate_deployment_bound_pending_release_approval",
            "final Genesis integrity status is not release-final")
    return value


def validate_finalized_manifest(genesis: dict[str, Any], path: Path) -> dict[str, Any]:
    manifest = read_json(path)
    activation = genesis["consensus"]["posy_v3_activation"]
    binding = genesis.get("consensus_parameters", {})
    require(activation.get("manifest") == manifest,
            "finalized consensus manifest differs from the Genesis activation manifest")
    require(binding.get("canonical_manifest_sha256") == sha256_path(path),
            "Genesis consensus-parameter binding does not commit the supplied manifest bytes")
    require(binding.get("parameter_root_sha3_512") == activation.get("parameter_root_sha3_512"),
            "Genesis consensus-parameter root differs from its activation root")
    require(manifest.get("status") == "FINALIZED"
            and manifest.get("target_block_time_ms") == 500,
            "consensus manifest is not the finalized R11 500 ms manifest")
    return manifest


def read_binary_provenance(binary: Path, revisions: dict[str, str]) -> dict[str, Any]:
    try:
        result = subprocess.run(
            [str(binary), "build-provenance"], check=False, text=True,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        )
    except OSError as error:
        fail(f"read validator build provenance: {error}")
    require(result.returncode == 0, f"validator build-provenance failed: {result.stdout.strip()}")
    try:
        value = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        fail(f"validator build-provenance emitted invalid JSON: {error}")
    require(isinstance(value, dict)
            and value.get("schema_version") == 1
            and value.get("artifact") == "synergy-validator-node",
            "validator build-provenance has an unsupported identity")
    require(value.get("source") == revisions,
            "validator binary was not compiled from the three frozen source revisions")
    return value


def select_registries(registry_dir: Path) -> dict[int, Path]:
    require(registry_dir.is_dir() and not registry_dir.is_symlink(),
            f"ingress registry directory is invalid: {registry_dir}")
    candidates = sorted(path for path in registry_dir.rglob("*.json") if path.is_file() and not path.is_symlink())
    selected: dict[int, Path] = {}
    for height in REGISTRY_HEIGHTS:
        matches: list[Path] = []
        for path in candidates:
            value = read_json(path)
            registry = value.get("registry", {})
            if (
                value.get("format") == "synergy-posy-simplified-ingress-kem-registry-v1"
                and value.get("epoch") == 0
                and value.get("target_height") == height
                and registry.get("registry_version") == 1
                and registry.get("chain_id") == 1266
                and registry.get("network_id") == "testnet"
                and registry.get("protocol_version") == "posy/3.0"
                and registry.get("epoch") == 0
                and registry.get("target_height") == height
                and isinstance(registry.get("records"), list)
                and len(registry["records"]) == 5
            ):
                matches.append(path)
        require(len(matches) == 1,
                f"need exactly one canonical ingress KEM registry for H{height}, found {len(matches)}")
        selected[height] = matches[0]
    return selected


def qualification_evidence(evidence_dir: Path) -> tuple[Path, Path, list[tuple[int, int, int]]]:
    require(evidence_dir.is_dir() and not evidence_dir.is_symlink(), f"evidence directory is invalid: {evidence_dir}")
    summary = evidence_dir / "qualification-summary.txt"
    timing = evidence_dir / "block-timing-ms.tsv"
    require_regular(summary, "qualification summary")
    require_regular(timing, "block timing evidence")
    text = summary.read_text(encoding="utf-8")
    for marker in SUMMARY_MARKERS:
        require(marker in text, f"qualification summary is missing {marker}")
    samples: list[tuple[int, int, int]] = []
    for line in timing.read_text(encoding="utf-8").splitlines():
        match = re.fullmatch(r"\s*(\d+)\s*->\s*(\d+)\s*\t\s*(\d+)\s*", line)
        require(match is not None, f"malformed timing evidence line: {line!r}")
        start, end, interval = (int(group) for group in match.groups())
        samples.append((start, end, interval))
    expected = {(height, height + 1) for height in range(3, 20)}
    actual = {(start, end) for start, end, _ in samples}
    require(expected <= actual, "timing evidence omits one or more H3-H20 finalized intervals")
    qualified = [(start, end, interval) for start, end, interval in samples if (start, end) in expected]
    require(all(100 <= interval <= 1100 for _, _, interval in qualified),
            "H3-H20 timing evidence is outside the 100-1100 ms qualification range")
    return summary, timing, qualified


def timing_statistics(samples: list[tuple[int, int, int]]) -> dict[str, int]:
    values = sorted(interval for _, _, interval in samples)
    require(bool(values), "steady-state timing evidence is empty")
    return {
        "count": len(values),
        "minimum": values[0],
        "p50": values[len(values) // 2],
        "p95": values[math.ceil(len(values) * 0.95) - 1],
        "maximum": values[-1],
    }


def copy_candidate_inputs(source: Path, destination: Path) -> dict[str, str]:
    names = (
        "consensus-parameter-manifest.unsigned.json",
        "genesis-predeployment-candidate.unsigned.json",
        "desired-state-input.unsigned.json",
        "governance-signing-request.unsigned.json",
        "validation-report.json",
    )
    report = read_json(source / "validation-report.json")
    require(report.get("NEW_TIMING") == 500 and report.get("runtime_config_status") == "MILLISECOND_CADENCE_FIELDS_BOUND",
            "candidate inputs are not the approved R11 500 ms public proposal")
    hashes: dict[str, str] = {}
    for name in names:
        input_path = source / name
        assert_no_private_name(input_path.relative_to(source))
        copy_regular(input_path, destination / name)
        hashes[name] = sha256_path(input_path)
    return hashes


def run_checked(command: list[str], label: str) -> None:
    try:
        result = subprocess.run(command, check=False, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    except OSError as error:
        fail(f"run {label}: {error}")
    require(result.returncode == 0, f"{label} failed: {result.stdout.strip()}")


def verify_desired_state(path: Path, binary: Path, configs: dict[str, Path]) -> dict[str, Any]:
    value = read_json(path)
    require(value.get("schema_version") == 1, "desired state has unsupported schema")
    chain = value.get("chain", {})
    state = value.get("state", {})
    require(chain.get("chain_id") == 1266 and chain.get("incarnation") == 5,
            "desired state is not the fresh Chain-1266 incarnation")
    require(state.get("consensus_schema_version") == 5
            and state.get("directory_namespace") == "chain-1266/incarnation-5"
            and state.get("mode") == "posy_simplified_v3"
            and state.get("coordinator_id") == ""
            and state.get("producer_ids") == []
            and state.get("producer_turn_timeout_ms") == 0,
            "desired state does not carry the canonical fresh P3 profile")
    require(value.get("artifacts") == {"validator_node": sha256_path(binary)},
            "desired state does not bind the supplied validator binary")
    expected_configs = {validator: sha256_path(path) for validator, path in configs.items()}
    require(value.get("configuration") == expected_configs,
            "desired state does not bind exactly the five supplied validator configs")
    return value


def verify_v4_request(path: Path) -> dict[str, Any]:
    value = read_json(path)
    require(value.get("schema_version") == 4
            and value.get("signature_algorithm") == "ML-DSA-87"
            and value.get("signature_domain") == V4_DOMAIN,
            "canonical V4 request has an invalid signing profile")
    require(not any(key in value for key in ("signature", "private_key", "secret_key")),
            "canonical V4 request must remain unsigned")
    return value


def build_compatibility_report(
    genesis_path: Path,
    genesis: dict[str, Any],
    manifest_path: Path,
    desired_path: Path,
    desired: dict[str, Any],
    request_path: Path,
    request: dict[str, Any],
    authority_path: Path,
    binary_path: Path,
    configs: dict[str, Path],
    registries: dict[int, Path],
    provenance: dict[str, Any],
) -> dict[str, Any]:
    activation = genesis["consensus"]["posy_v3_activation"]
    parameter_binding = genesis["consensus_parameters"]
    expected_config_hashes = {validator: sha256_path(path) for validator, path in configs.items()}
    expected_revisions = desired["source"]
    expected_request = {
        "candidate_sha256": sha256_path(genesis_path),
        "genesis_hash": genesis["integrity"]["genesis_hash"],
        "frozen_authority_record_sha256": sha256_path(authority_path),
        "desired_state_sha256": sha256_path(desired_path),
        "desired_state_testnet_v3_revision": expected_revisions["testnet_v3_revision"],
        "desired_state_synq_revision": expected_revisions["synq_revision"],
        "desired_state_aegis_revision": expected_revisions["aegis_revision"],
        "desired_state_role_binary_sha256": {"validator_node": sha256_path(binary_path)},
        "desired_state_role_configuration_sha256": expected_config_hashes,
        "consensus_parameter_manifest_sha256": sha256_path(manifest_path),
        "consensus_parameter_root_sha3_512": activation["parameter_root_sha3_512"],
    }
    for field, expected in expected_request.items():
        require(request.get(field) == expected, f"V4 request does not bind compatible {field}")
    require(parameter_binding.get("canonical_manifest_sha256") == sha256_path(manifest_path),
            "Genesis and finalized consensus manifest are incompatible")
    require(desired.get("artifacts") == {"validator_node": sha256_path(binary_path)}
            and desired.get("configuration") == expected_config_hashes,
            "desired state is incompatible with the staged binary/configuration set")
    require(provenance.get("source") == expected_revisions,
            "binary provenance is incompatible with desired-state source revisions")
    return {
        "schema_version": 1,
        "artifact_type": "r11-release-candidate-compatibility-report",
        "status": "PASS",
        "bindings": {
            "genesis_sha256": expected_request["candidate_sha256"],
            "genesis_hash": expected_request["genesis_hash"],
            "consensus_manifest_sha256": expected_request["consensus_parameter_manifest_sha256"],
            "consensus_parameter_root_sha3_512": expected_request["consensus_parameter_root_sha3_512"],
            "authority_record_sha256": expected_request["frozen_authority_record_sha256"],
            "validator_binary_sha256": sha256_path(binary_path),
            "validator_config_sha256": expected_config_hashes,
            "desired_state_sha256": expected_request["desired_state_sha256"],
            "unsigned_v4_request_sha256": sha256_path(request_path),
            "ingress_kem_registry_sha256": {
                f"H{height}": sha256_path(path) for height, path in registries.items()
            },
            "source_revisions": expected_revisions,
        },
        "checked_edges": [
            "Genesis -> finalized consensus manifest",
            "Genesis -> frozen authority record",
            "desired state -> validator binary",
            "desired state -> five validator configs",
            "validator binary -> three compiled source revisions",
            "unsigned V4 request -> Genesis/authority/desired state/provenance",
            "H3-H20 ingress registries -> Chain 1266/P3/five validators",
        ],
    }


def preflight_definition() -> dict[str, Any]:
    return {
        "schema_version": 1,
        "artifact_type": "r11-pre-signature-preflight-definition",
        "status": "READY",
        "gates": [
            {"id": "QUALIFICATION", "requires": list(SUMMARY_MARKERS)},
            {"id": "STEADY_STATE_TIMING", "heights": "H3-H20", "minimum_ms": 100, "maximum_ms": 1100},
            {"id": "PROVENANCE", "requires": ["Testnet-v3 revision", "SynQ revision", "Aegis revision"]},
            {"id": "CONFIGURATION", "requires": list(VALIDATORS)},
            {"id": "CRYPTOGRAPHIC_REGISTRIES", "heights": [f"H{height}" for height in REGISTRY_HEIGHTS]},
            {"id": "V4_REQUEST", "signature_state": "UNSIGNED", "requires_external_signing": True},
            {"id": "PACKAGE_INTEGRITY", "requires": ["SHA256SUMS", "deterministic tar archive", "archive SHA-256"]},
        ],
    }


def relative_files(root: Path) -> Iterable[Path]:
    return sorted(path for path in root.rglob("*") if path.is_file() and not path.is_symlink())


def seal_package(root: Path) -> None:
    sums_path = root / "SHA256SUMS"
    entries = []
    for path in relative_files(root):
        relative = path.relative_to(root).as_posix()
        if relative == "SHA256SUMS":
            continue
        entries.append(f"{sha256_path(path)}  {relative}\n")
    sums_path.write_text("".join(entries), encoding="utf-8")
    for path in relative_files(root):
        mode = stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH
        if path.relative_to(root).parts[0] == "bin":
            mode |= stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH
        path.chmod(mode)
    for path in sorted((path for path in root.rglob("*") if path.is_dir()), reverse=True):
        path.chmod(stat.S_IRUSR | stat.S_IXUSR | stat.S_IRGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IXOTH)
    root.chmod(stat.S_IRUSR | stat.S_IXUSR | stat.S_IRGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IXOTH)


def archive_paths(root: Path) -> tuple[Path, Path]:
    archive = root.parent / f"{root.name}.tar"
    return archive, archive.parent / f"{archive.name}.sha256"


def create_archive(root: Path) -> tuple[Path, Path]:
    archive, sidecar = archive_paths(root)
    require(not archive.exists() and not sidecar.exists(),
            f"refusing to overwrite existing release archive: {archive}")
    with tarfile.open(archive, mode="w", format=tarfile.USTAR_FORMAT) as handle:
        for path in relative_files(root):
            relative = Path(root.name) / path.relative_to(root)
            info = tarfile.TarInfo(relative.as_posix())
            info.size = path.stat().st_size
            info.mode = path.stat().st_mode & 0o777
            info.uid = 0
            info.gid = 0
            info.uname = ""
            info.gname = ""
            info.mtime = 0
            with path.open("rb") as source:
                handle.addfile(info, source)
    digest = sha256_path(archive)
    sidecar.write_text(f"{digest}  {archive.name}\n", encoding="utf-8")
    archive.chmod(stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)
    sidecar.chmod(stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)
    return archive, sidecar


def verify_archive(root: Path) -> None:
    archive, sidecar = archive_paths(root)
    require_regular(archive, "immutable release archive")
    require_regular(sidecar, "release archive checksum")
    require(not archive.stat().st_mode & (stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH),
            "release archive is writable")
    require(not sidecar.stat().st_mode & (stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH),
            "release archive checksum is writable")
    require(sidecar.read_text(encoding="utf-8") == f"{sha256_path(archive)}  {archive.name}\n",
            "release archive SHA-256 sidecar is invalid")
    expected = {
        (Path(root.name) / path.relative_to(root)).as_posix(): sha256_path(path)
        for path in relative_files(root)
    }
    actual: dict[str, str] = {}
    with tarfile.open(archive, mode="r:") as handle:
        for member in handle.getmembers():
            require(member.isfile() and not member.issym() and not member.islnk(),
                    f"release archive contains a non-regular entry: {member.name}")
            require(member.name not in actual, f"release archive contains a duplicate entry: {member.name}")
            source = handle.extractfile(member)
            require(source is not None, f"release archive entry is unreadable: {member.name}")
            actual[member.name] = hashlib.sha256(source.read()).hexdigest()
    require(actual == expected, "release archive content differs from the sealed package directory")


def verify_package(root: Path, require_archive: bool = True) -> None:
    require(root.is_dir() and not root.is_symlink(), f"package directory is invalid: {root}")
    manifest = read_json(root / "package-manifest.json")
    require(manifest.get("status") == "LOCAL_R11_QUALIFIED_V4_REQUEST_UNSIGNED",
            "package is not an unsigned post-H20 R11 release candidate")
    require(manifest.get("chain") == {"chain_id": 1266, "network_id": "testnet", "protocol_version": "posy/3.0", "target_block_time_ms": 500},
            "package chain identity/timing is invalid")
    require(not root.stat().st_mode & (stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH),
            "package root is writable; immutable sealing is missing")
    for path in root.rglob("*"):
        require(not path.is_symlink(), f"sealed package must not contain symlinks: {path.relative_to(root)}")
        require(not path.stat().st_mode & (stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH),
                f"sealed package contains writable entry: {path.relative_to(root)}")
    for path in relative_files(root):
        assert_no_private_name(path.relative_to(root))
    sums = root / "SHA256SUMS"
    require_regular(sums, "package checksum manifest")
    expected_paths: set[str] = set()
    for line in sums.read_text(encoding="utf-8").splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  (.+)", line)
        require(match is not None, f"malformed SHA256SUMS line: {line!r}")
        digest, relative = match.groups()
        require(relative not in expected_paths and relative != "SHA256SUMS",
                f"duplicate or recursive checksum entry: {relative}")
        expected_paths.add(relative)
        path = root / relative
        require(path.is_file() and not path.is_symlink() and sha256_path(path) == digest,
                f"checksum mismatch: {relative}")
    actual_paths = {path.relative_to(root).as_posix() for path in relative_files(root) if path.name != "SHA256SUMS"}
    require(actual_paths == expected_paths,
            "package contains an unchecksummed file or SHA256SUMS omits a payload file")
    binary = root / "bin" / "synergy-validator-node"
    configs = checked_configurations(root / "configs", binary)
    genesis_path = root / "genesis" / "genesis.final.json"
    manifest_path = root / "consensus" / "consensus-parameter-manifest.final.json"
    genesis = validate_final_genesis(genesis_path)
    validate_finalized_manifest(genesis, manifest_path)
    desired_path = root / "desired-state.json"
    desired = verify_desired_state(desired_path, binary, configs)
    provenance = read_binary_provenance(binary, desired["source"])
    request_path = root / "v4-governance-request.unsigned.json"
    request = verify_v4_request(request_path)
    registries = select_registries(root / "ingress-kem-registries")
    compatibility = read_json(root / "compatibility-report.json")
    expected_compatibility = build_compatibility_report(
        genesis_path, genesis, manifest_path, desired_path, desired,
        request_path, request, root / "authority" / "testnet-v3-v4-authorities.json",
        binary, configs, registries, provenance,
    )
    require(compatibility == expected_compatibility,
            "artifact compatibility report does not match the staged release outputs")
    preflight = read_json(root / "preflight-definition.json")
    require(preflight.get("status") == "READY", "pre-signature preflight definition is not ready")
    if require_archive:
        verify_archive(root)
    print(f"R11_RELEASE_CANDIDATE_PREFLIGHT_PASS package={root.resolve()}")


def assemble(args: argparse.Namespace) -> None:
    for label, revision in (("testnet-v3", args.testnet_v3_revision), ("synq", args.synq_revision), ("aegis", args.aegis_revision)):
        require(REVISION.fullmatch(revision) is not None, f"{label} revision must be a full lowercase Git revision")
    revisions = {
        "testnet_v3_revision": args.testnet_v3_revision,
        "synq_revision": args.synq_revision,
        "aegis_revision": args.aegis_revision,
    }
    output = args.output_dir.resolve()
    require(not output.exists(), f"refusing to overwrite existing output: {output}")
    for path, label, executable in (
        (args.genesis, "final engine-produced Genesis", False),
        (args.finalized_consensus_manifest, "finalized consensus parameter manifest", False),
        (args.validator_binary, "validator binary", True),
        (args.desired_state_builder, "desired-state builder", True),
        (args.release_approval_tool, "V4 request tool", True),
        (args.authority_record, "dated public V4 authority record", False),
    ):
        require_regular(path, label, executable)
    genesis = validate_final_genesis(args.genesis)
    validate_finalized_manifest(genesis, args.finalized_consensus_manifest)
    binary_provenance = read_binary_provenance(args.validator_binary, revisions)
    configs = checked_configurations(args.config_dir, args.validator_binary)
    registries = select_registries(args.ingress_kem_registry_dir)
    summary, timing, qualified = qualification_evidence(args.evidence_dir)
    authority = read_json(args.authority_record)
    require("private_key" not in authority and "secret_key" not in authority,
            "authority record must be public-only")

    output.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=f".{output.name}.", dir=output.parent))
    try:
        copy_regular(args.genesis, staging / "genesis" / "genesis.final.json")
        copy_regular(args.finalized_consensus_manifest,
                     staging / "consensus" / "consensus-parameter-manifest.final.json")
        copy_regular(args.validator_binary, staging / "bin" / "synergy-validator-node")
        copy_regular(args.authority_record, staging / "authority" / "testnet-v3-v4-authorities.json")
        copy_regular(summary, staging / "qualification" / "qualification-summary.txt")
        copy_regular(timing, staging / "qualification" / "block-timing-ms.tsv")
        candidate_hashes = copy_candidate_inputs(args.candidate_input_dir, staging / "candidate-inputs")
        for validator, path in configs.items():
            copy_regular(path, staging / "configs" / validator / "config.toml")
        registry_hashes: dict[str, str] = {}
        staged_registries: dict[int, Path] = {}
        for height, path in registries.items():
            relative = Path("ingress-kem-registries") / f"h{height:02d}-registry.json"
            copy_regular(path, staging / relative)
            staged_registries[height] = staging / relative
            registry_hashes[f"H{height}"] = sha256_path(path)

        write_json(staging / "provenance" / "validator-build-provenance.json", binary_provenance)
        write_json(staging / "provenance" / "source-provenance.json", {
            "schema_version": 1,
            "artifact_type": "r11-source-provenance",
            "release_id": args.release_id,
            "release_tag": args.release_tag,
            "source": revisions,
        })

        desired_state = staging / "desired-state.json"
        desired_command = [
            str(args.desired_state_builder), "--release-id", args.release_id, "--release-tag", args.release_tag,
            "--testnet-revision", args.testnet_v3_revision, "--synq-revision", args.synq_revision,
            "--aegis-revision", args.aegis_revision, "--genesis", str(staging / "genesis" / "genesis.final.json"),
            "--artifact", f"validator_node={staging / 'bin' / 'synergy-validator-node'}",
            "--output", str(desired_state),
        ]
        for validator in VALIDATORS:
            desired_command.extend(("--configuration", f"{validator}={staging / 'configs' / validator / 'config.toml'}"))
        run_checked(desired_command, "canonical desired-state generator")
        staged_configs = {validator: staging / "configs" / validator / "config.toml" for validator in VALIDATORS}
        desired = verify_desired_state(
            desired_state, staging / "bin" / "synergy-validator-node", staged_configs,
        )

        request = staging / "v4-governance-request.unsigned.json"
        run_checked([
            str(args.release_approval_tool), "--write-request", "--candidate", str(staging / "genesis" / "genesis.final.json"),
            "--desired-state", str(desired_state), "--authorities", str(staging / "authority" / "testnet-v3-v4-authorities.json"),
            "--output", str(request),
        ], "canonical unsigned V4 governance request generator")
        request_value = verify_v4_request(request)

        compatibility = build_compatibility_report(
            staging / "genesis" / "genesis.final.json",
            genesis,
            staging / "consensus" / "consensus-parameter-manifest.final.json",
            desired_state,
            desired,
            request,
            request_value,
            staging / "authority" / "testnet-v3-v4-authorities.json",
            staging / "bin" / "synergy-validator-node",
            staged_configs,
            staged_registries,
            binary_provenance,
        )
        write_json(staging / "compatibility-report.json", compatibility)
        write_json(staging / "preflight-definition.json", preflight_definition())

        manifest = {
            "schema_version": 1,
            "artifact_type": "testnet-v3-r11-qualified-release-candidate",
            "status": "LOCAL_R11_QUALIFIED_V4_REQUEST_UNSIGNED",
            "created_utc": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
            "chain": {"chain_id": 1266, "network_id": "testnet", "protocol_version": "posy/3.0", "target_block_time_ms": 500},
            "provenance": {
                "release_id": args.release_id, "release_tag": args.release_tag,
                "testnet_v3_revision": args.testnet_v3_revision, "synq_revision": args.synq_revision,
                "aegis_revision": args.aegis_revision, "candidate_input_sha256": candidate_hashes,
                "authority_record_sha256": sha256_path(args.authority_record),
                "validator_build_provenance": binary_provenance,
            },
            "qualification": {
                "required_markers": list(SUMMARY_MARKERS), "summary_sha256": sha256_path(summary),
                "timing_sha256": sha256_path(timing), "h3_h20_interval_ms": [interval for _, _, interval in qualified],
                "timing_statistics_ms": timing_statistics(qualified),
                "validator_restart": "PASS", "finalized_height": 20,
            },
            "artifacts": {
                "final_genesis_sha256": sha256_path(args.genesis),
                "finalized_consensus_manifest_sha256": sha256_path(args.finalized_consensus_manifest),
                "validator_node_sha256": sha256_path(args.validator_binary),
                "validator_config_sha256": {validator: sha256_path(path) for validator, path in configs.items()},
                "ingress_kem_registry_sha256": registry_hashes, "desired_state_sha256": sha256_path(desired_state),
                "unsigned_v4_governance_request_sha256": sha256_path(request),
                "compatibility_report": "PASS",
                "pre_signature_preflight": "READY",
            },
            "prohibitions": ["no private keys", "no V4 release-approval signature", "no deployment", "no live host access"],
            "next_external_action": "obtain governance signature for the exact canonical V4 request",
        }
        write_json(staging / "package-manifest.json", manifest)
        seal_package(staging)
        os.replace(staging, output)
    except BaseException:
        shutil.rmtree(staging, ignore_errors=True)
        raise
    verify_package(output, require_archive=False)
    archive, archive_sha256 = create_archive(output)
    verify_package(output)
    print(f"R11_RELEASE_CANDIDATE_ASSEMBLED output={output}")
    print(f"IMMUTABLE_ARCHIVE={archive}")
    print(f"IMMUTABLE_ARCHIVE_SHA256={sha256_path(archive)}")
    print(f"IMMUTABLE_ARCHIVE_SHA256_FILE={archive_sha256}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--verify-package", type=Path, metavar="DIR")
    parser.add_argument("--genesis", type=Path)
    parser.add_argument("--finalized-consensus-manifest", type=Path)
    parser.add_argument("--ingress-kem-registry-dir", type=Path)
    parser.add_argument("--evidence-dir", type=Path)
    parser.add_argument("--validator-binary", type=Path)
    parser.add_argument("--config-dir", type=Path)
    parser.add_argument("--desired-state-builder", type=Path)
    parser.add_argument("--release-approval-tool", type=Path)
    parser.add_argument("--authority-record", type=Path)
    parser.add_argument("--candidate-input-dir", type=Path,
                        default=Path(__file__).resolve().parents[1] / "launch" / "r11-500ms-qualification-candidate")
    parser.add_argument("--release-id")
    parser.add_argument("--release-tag")
    parser.add_argument("--testnet-v3-revision")
    parser.add_argument("--synq-revision")
    parser.add_argument("--aegis-revision")
    parser.add_argument("--output-dir", type=Path)
    args = parser.parse_args()
    if args.verify_package is not None:
        supplied = [args.genesis, args.finalized_consensus_manifest, args.ingress_kem_registry_dir, args.evidence_dir, args.validator_binary,
                    args.config_dir, args.desired_state_builder, args.release_approval_tool, args.authority_record,
                    args.release_id, args.release_tag, args.testnet_v3_revision, args.synq_revision,
                    args.aegis_revision, args.output_dir]
        require(not any(item is not None for item in supplied), "--verify-package cannot be combined with assembly inputs")
        verify_package(args.verify_package.resolve())
        return
    required = ("genesis", "finalized_consensus_manifest", "ingress_kem_registry_dir", "evidence_dir", "validator_binary", "config_dir",
                "desired_state_builder", "release_approval_tool", "authority_record", "release_id", "release_tag",
                "testnet_v3_revision", "synq_revision", "aegis_revision", "output_dir")
    missing = [name for name in required if getattr(args, name) is None]
    require(not missing, f"missing required arguments: {', '.join('--' + name.replace('_', '-') for name in missing)}")
    assemble(args)


if __name__ == "__main__":
    main()
