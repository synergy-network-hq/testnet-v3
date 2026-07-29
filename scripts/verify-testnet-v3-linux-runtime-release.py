#!/usr/bin/env python3
"""Verify the checksum-bound Linux runtime artifacts for Testnet-v3 staging."""

from __future__ import annotations

import argparse
import hashlib
import json
import stat
import subprocess
import sys
import tomllib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def fail(message: str) -> None:
    raise SystemExit(f"verify-testnet-v3-linux-runtime-release: {message}")


def require_string(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        fail(f"{label} must be a non-empty string")
    return value


def verify_linux_x86_64_elf(path: Path) -> None:
    try:
        header = path.read_bytes()[:20]
    except OSError as error:
        fail(f"read artifact {path}: {error}")
    if len(header) < 20 or header[:4] != b"\x7fELF":
        fail(f"artifact is not an ELF executable: {path}")
    if header[4] != 2 or header[5] != 1 or int.from_bytes(header[18:20], "little") != 62:
        fail(f"artifact is not a 64-bit little-endian x86_64 ELF: {path}")
    if not path.stat().st_mode & stat.S_IXUSR:
        fail(f"artifact is not owner-executable: {path}")


def canonical_runtime_binding(release: dict[str, object]) -> dict[str, object]:
    version = require_string(release.get("runtime_version"), "runtime_version")
    if version != "20.0.0":
        fail("runtime release must be version 20.0.0")
    relative = Path(require_string(release.get("runtime_binding_file"), "runtime_binding_file"))
    if relative.is_absolute() or ".." in relative.parts:
        fail("runtime_binding_file must remain within the Testnet-v3 checkout")
    binding_path = ROOT / relative
    if sha256(binding_path) != require_string(release.get("runtime_binding_sha256"), "runtime_binding_sha256"):
        fail("runtime binding SHA-256 disagrees with the runtime release manifest")
    try:
        binding = json.loads(binding_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        fail(f"read runtime binding: {error}")
    if not isinstance(binding, dict) or binding.get("schema_version") != 1:
        fail("runtime binding schema_version must be 1")
    if binding.get("runtime_package") != "synergy-testnet" or binding.get("runtime_version") != version:
        fail("runtime binding does not identify synergy-testnet v20.0.0")
    if binding.get("chain_id") != 1266 or binding.get("network_id") != "synergy-testnet-v3":
        fail("runtime binding does not identify Testnet-v3 chain 1266")
    if binding.get("activation_boundary") != "genesis":
        fail("runtime binding must activate only from genesis")

    genesis_path = ROOT / "genesis.testnet-v3.identity-assigned.json"
    try:
        genesis = json.loads(genesis_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        fail(f"read canonical Genesis: {error}")
    expected = {
        "genesis_file_sha256": sha256(genesis_path),
        "genesis_hash": genesis.get("integrity", {}).get("genesis_hash"),
        "genesis_deployment_status": genesis.get("genesis_deployment", {}).get("status"),
        "genesis_execution_state_root": genesis.get("execution", {}).get("genesis_execution_state_root"),
        "consensus_parameter_root_sha3_512": genesis.get("consensus_parameters", {}).get("parameter_root_sha3_512"),
    }
    if expected["genesis_deployment_status"] != "EXECUTED_AND_BOUND":
        fail("canonical Genesis was not executed and bound")
    if any(not isinstance(value, str) or not value for value in expected.values()):
        fail("canonical Genesis omits an executed release binding field")
    for key, value in expected.items():
        if binding.get(key) != value:
            fail(f"runtime binding {key} disagrees with canonical executed Genesis")

    cargo_path = ROOT / "runtime" / "src" / "Cargo.toml"
    try:
        cargo_version = tomllib.loads(cargo_path.read_text(encoding="utf-8"))["package"]["version"]
    except (OSError, KeyError, TypeError, tomllib.TOMLDecodeError) as error:
        fail(f"read runtime Cargo version: {error}")
    if cargo_version != version:
        fail("runtime Cargo package version disagrees with release binding")
    return binding


def verify_native_candidate(candidate: Path, kind: str, binding: dict[str, object]) -> None:
    if candidate.is_symlink() or not candidate.is_file() or not candidate.stat().st_mode & stat.S_IXUSR:
        fail("candidate must be a regular owner-executable file, not a symlink")
    try:
        version = subprocess.run(
            [str(candidate), "--version"], check=True, capture_output=True, text=True, timeout=5
        ).stdout.strip()
        embedded = subprocess.run(
            [str(candidate), "release-binding"], check=True, capture_output=True, text=True, timeout=5
        ).stdout
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
        fail(f"execute candidate immutable metadata command: {error}")
    expected_version = "synergy-node 20.0.0" if kind == "node" else "Synergy Testnet Node v20.0.0"
    if expected_version not in version.splitlines():
        fail(f"{kind} candidate version is not 20.0.0")
    if kind == "validator" and "Binary: synergy-validator-node" not in version.splitlines():
        fail("candidate validator role identity is not synergy-validator-node")
    try:
        candidate_binding = json.loads(embedded)
    except json.JSONDecodeError as error:
        fail(f"candidate release binding is not JSON: {error}")
    if candidate_binding != binding:
        fail("candidate embedded binding disagrees with canonical immutable release binding")
    print(f"candidate_kind={kind}")
    print(f"candidate_sha256={sha256(candidate)}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--release-manifest",
        type=Path,
        default=ROOT / "launch" / "TESTNET_V3_LINUX_RUNTIME_RELEASE.json",
    )
    parser.add_argument("--candidate", type=Path)
    parser.add_argument("--candidate-kind", choices=("node", "validator"))
    arguments = parser.parse_args()
    if (arguments.candidate is None) != (arguments.candidate_kind is None):
        fail("--candidate and --candidate-kind must be supplied together")

    try:
        release = json.loads(arguments.release_manifest.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        fail(f"read release manifest: {error}")
    if release.get("schema_version") != 1:
        fail("release manifest schema_version must be 1")
    if release.get("network_id") != "synergy-testnet-v3" or release.get("chain_id") != 1266:
        fail("release manifest does not bind Testnet-v3 chain 1266")
    binding = canonical_runtime_binding(release)

    genesis_path = ROOT / "genesis.testnet-v3.identity-assigned.json"
    if sha256(genesis_path) != require_string(release.get("genesis_file_sha256"), "genesis_file_sha256"):
        fail("canonical Genesis hash disagrees with the runtime release manifest")

    config_manifest_path = ROOT / "launch" / "production-node-configs" / "release-config-manifest.json"
    config_manifest_hash = sha256(config_manifest_path)
    if config_manifest_hash != require_string(
        release.get("release_config_manifest_sha256"), "release_config_manifest_sha256"
    ):
        fail("release-config manifest hash disagrees with the runtime release manifest")
    try:
        config_manifest = json.loads(config_manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        fail(f"read release-config manifest: {error}")
    if config_manifest.get("generator_version") != release.get("release_config_generator_version"):
        fail("release-config generator version disagrees with the runtime release manifest")

    artifacts = release.get("artifacts")
    if not isinstance(artifacts, dict) or set(artifacts) != {"validator", "relayer"}:
        fail("release manifest must contain exactly validator and relayer artifacts")
    for name, artifact in artifacts.items():
        if not isinstance(artifact, dict):
            fail(f"{name} artifact must be an object")
        relative = require_string(artifact.get("local_path"), f"{name}.local_path")
        relative_path = Path(relative)
        if relative_path.is_absolute() or ".." in relative_path.parts:
            fail(f"{name}.local_path must remain within the Testnet-v3 checkout")
        artifact_path = ROOT / relative_path
        expected_hash = require_string(artifact.get("sha256"), f"{name}.sha256")
        if sha256(artifact_path) != expected_hash:
            fail(f"{name} artifact SHA-256 mismatch")
        if artifact.get("linux_elf_machine") != "x86_64":
            fail(f"{name} artifact is not declared x86_64")
        verify_linux_x86_64_elf(artifact_path)
        require_string(artifact.get("installed_path"), f"{name}.installed_path")
        require_string(artifact.get("service_unit"), f"{name}.service_unit")

    if arguments.candidate is not None:
        verify_native_candidate(arguments.candidate, arguments.candidate_kind, binding)

    print("TESTNET_V3_LINUX_RUNTIME_RELEASE_VERIFIED")
    print(f"release_id={release['release_id']}")
    print(f"validator_sha256={artifacts['validator']['sha256']}")
    print(f"relayer_sha256={artifacts['relayer']['sha256']}")


if __name__ == "__main__":
    main()
