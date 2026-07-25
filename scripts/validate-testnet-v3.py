#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover
    tomllib = None  # type: ignore[assignment]


ROOT = Path(__file__).resolve().parents[1]
RUNTIME = ROOT / "runtime"
REFERENCE = ROOT / "launch" / "reference"
RETIRED_V2_GENESIS_SHA256 = (
    "085c4283cf587ff8a22e8bf4a3de022f86a99d8af7d9fe9b4c0dbdfd082a5a95"
)
EXPECTED_CHAIN_ID = 1264
EXPECTED_RELEASE_ID = "testnet-v3"
EXPECTED_RUNTIME_NETWORK_ID = "synergy-testnet-v3"
ZERO_HASH = "0" * 64


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_json(path: Path, errors: list[str]) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        errors.append(f"{path.relative_to(ROOT)}: invalid or missing JSON: {error}")
        return {}
    if not isinstance(value, dict):
        errors.append(f"{path.relative_to(ROOT)}: top-level JSON must be an object")
        return {}
    return value


def load_topology(path: Path, errors: list[str]) -> dict:
    if tomllib is None:
        errors.append("Python 3.11 or newer is required to validate TOML")
        return {}
    try:
        with path.open("rb") as handle:
            return tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError) as error:
        errors.append(f"{path.relative_to(ROOT)}: invalid or missing TOML: {error}")
        return {}


def secret_filename_findings() -> list[str]:
    findings: list[str] = []
    ignored_roots = {REFERENCE}
    for path in ROOT.rglob("*"):
        if (
            not path.is_file()
            or any(parent in ignored_roots for parent in path.parents)
            or "target" in path.parts
            or ".git" in path.parts
        ):
            continue
        lower = path.name.lower()
        if (
            lower == ".env"
            or lower.endswith(".pem")
            or lower.endswith(".key")
            or lower.endswith(".dec.json")
            or lower in {"id_rsa", "id_ed25519"}
        ):
            findings.append(f"secret-bearing filename is forbidden: {path.relative_to(ROOT)}")
    return findings


def active_v2_marker_findings() -> list[str]:
    findings: list[str] = []
    text_suffixes = {
        "",
        ".c",
        ".conf",
        ".cpp",
        ".css",
        ".env",
        ".example",
        ".h",
        ".html",
        ".js",
        ".json",
        ".md",
        ".mjs",
        ".ps1",
        ".py",
        ".rs",
        ".sh",
        ".toml",
        ".ts",
        ".tsx",
        ".txt",
        ".yaml",
        ".yml",
    }
    markers = (
        "synergy-testnet-v2",
        "synergy_testnet_v2",
        "SYNERGY_TESTNET_V2",
        "testnet-v2",
    )
    active_roots = [RUNTIME, ROOT / "validator-workspace", ROOT / "observability"]
    for active_root in active_roots:
        for path in active_root.rglob("*"):
            if not path.is_file() or "target" in path.parts or ".git" in path.parts:
                continue
            if path.suffix.lower() not in text_suffixes or path.stat().st_size > 2_000_000:
                continue
            try:
                text = path.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                continue
            if any(marker in text for marker in markers):
                findings.append(
                    f"active Testnet-v2 marker remains: {path.relative_to(ROOT)}"
                )
    return findings


def validate_structure() -> list[str]:
    errors: list[str] = []
    required_paths = [
        ROOT / "README.md",
        ROOT / "VERSION",
        ROOT / "SOURCE_PROVENANCE.md",
        ROOT / "launch" / "launch-readiness.json",
        RUNTIME / "Cargo.toml",
        RUNTIME / "config" / "testnet" / "network-topology.toml",
        RUNTIME / "src" / "synergy_types.rs",
        ROOT / "validator-workspace" / "template" / "MANIFEST.yaml",
        ROOT / "observability" / "OBSERVABILITY.md",
    ]
    for path in required_paths:
        if not path.exists():
            errors.append(f"required path is missing: {path.relative_to(ROOT)}")

    topology = load_topology(
        RUNTIME / "config" / "testnet" / "network-topology.toml", errors
    )
    network = topology.get("network", {})
    if network.get("environment_id") != "testnet":
        errors.append("topology environment_id must remain testnet")
    if network.get("release_id") != EXPECTED_RELEASE_ID:
        errors.append(f"topology release_id must be {EXPECTED_RELEASE_ID}")
    if network.get("runtime_network_id") != EXPECTED_RUNTIME_NETWORK_ID:
        errors.append(
            f"topology runtime_network_id must be {EXPECTED_RUNTIME_NETWORK_ID}"
        )
    if network.get("chain_id") != EXPECTED_CHAIN_ID:
        errors.append(f"topology chain_id must be {EXPECTED_CHAIN_ID}")
    if network.get("network_id") != EXPECTED_CHAIN_ID:
        errors.append(f"topology numeric network_id must be {EXPECTED_CHAIN_ID}")

    readiness = load_json(ROOT / "launch" / "launch-readiness.json", errors)
    if readiness.get("release_id") != EXPECTED_RELEASE_ID:
        errors.append(f"launch readiness release_id must be {EXPECTED_RELEASE_ID}")
    if readiness.get("runtime_network_id") != EXPECTED_RUNTIME_NETWORK_ID:
        errors.append(
            f"launch readiness runtime_network_id must be {EXPECTED_RUNTIME_NETWORK_ID}"
        )
    if readiness.get("chain_id") != EXPECTED_CHAIN_ID:
        errors.append(f"launch readiness chain_id must be {EXPECTED_CHAIN_ID}")

    constants_path = RUNTIME / "src" / "synergy_types.rs"
    if constants_path.is_file():
        constants = constants_path.read_text(encoding="utf-8")
        if "SYNERGY_TESTNET_V3_CHAIN_ID: u64 = 1264" not in constants:
            errors.append("runtime Testnet-v3 chain constant is missing or incorrect")
        if (
            'SYNERGY_TESTNET_V3_NETWORK_ID: &str = "synergy-testnet-v3"'
            not in constants
        ):
            errors.append("runtime Testnet-v3 network constant is missing or incorrect")

    errors.extend(secret_filename_findings())
    errors.extend(active_v2_marker_findings())
    return errors


def validate_full_launch() -> list[str]:
    errors: list[str] = []
    topology = load_topology(
        RUNTIME / "config" / "testnet" / "network-topology.toml", errors
    )
    topology_text = (
        RUNTIME / "config" / "testnet" / "network-topology.toml"
    ).read_text(encoding="utf-8")
    if "<TESTNET_V3_" in topology_text:
        errors.append("fresh validator addresses have not been installed in topology")

    genesis_paths = [
        RUNTIME / "genesis.testnet.json",
        RUNTIME / "config" / "genesis.json",
        RUNTIME / "config" / "genesis.testnet.json",
    ]
    genesis_hashes: list[str] = []
    for path in genesis_paths:
        genesis = load_json(path, errors)
        if not genesis:
            continue
        digest = sha256(path)
        genesis_hashes.append(digest)
        if digest == RETIRED_V2_GENESIS_SHA256:
            errors.append(f"{path.relative_to(ROOT)} is the retired Testnet-v2 genesis")
        if genesis.get("release_id") != EXPECTED_RELEASE_ID:
            errors.append(f"{path.relative_to(ROOT)} release_id is not testnet-v3")
        if genesis.get("launch_status"):
            errors.append(f"{path.relative_to(ROOT)} is still a blocking placeholder")
        network = genesis.get("network", {})
        if network.get("chain_id") != EXPECTED_CHAIN_ID:
            errors.append(f"{path.relative_to(ROOT)} chain_id must be 1264")
        if network.get("network_id") != EXPECTED_CHAIN_ID:
            errors.append(f"{path.relative_to(ROOT)} numeric network_id must be 1264")
        if network.get("runtime_network_id") != EXPECTED_RUNTIME_NETWORK_ID:
            errors.append(
                f"{path.relative_to(ROOT)} runtime network ID must be synergy-testnet-v3"
            )
        integrity = genesis.get("integrity", {})
        if integrity.get("recompute_required") is not False:
            errors.append(f"{path.relative_to(ROOT)} integrity must be fully recomputed")
        if not integrity.get("signed_by"):
            errors.append(f"{path.relative_to(ROOT)} has no approved genesis signatures")
        for field in (
            "genesis_hash",
            "state_root",
            "allocation_hash",
            "validator_hash",
            "contract_hash",
        ):
            value = integrity.get(field)
            if (
                not isinstance(value, str)
                or len(value) != 64
                or value == ZERO_HASH
                or any(character not in "0123456789abcdef" for character in value.lower())
            ):
                errors.append(
                    f"{path.relative_to(ROOT)} integrity.{field} is not finalized"
                )
    if genesis_hashes and len(set(genesis_hashes)) != 1:
        errors.append("the three active genesis files are not byte-identical")

    readiness = load_json(ROOT / "launch" / "launch-readiness.json", errors)
    gates = readiness.get("gates", {})
    incomplete = sorted(name for name, passed in gates.items() if passed is not True)
    if readiness.get("status") != "approved_for_launch":
        errors.append("launch readiness status is not approved_for_launch")
    if incomplete:
        errors.append(f"launch readiness gates are incomplete: {', '.join(incomplete)}")
    if genesis_hashes and readiness.get("approved_genesis_sha256") != genesis_hashes[0]:
        errors.append("approved_genesis_sha256 does not match active genesis bytes")

    validator_dir = RUNTIME / "config" / "genesis-validators"
    identity_files = sorted(validator_dir.glob("*.identity.json"))
    if len(identity_files) < 5:
        errors.append("new genesis validator identity documents are missing")

    bootstrap_dir = RUNTIME / "bootstrap-bundles"
    bundle_geneses = sorted(bootstrap_dir.glob("*/config/genesis.json"))
    if len(bundle_geneses) < 5:
        errors.append("Testnet-v3 bootstrap bundles have not been regenerated")
    elif genesis_hashes:
        for path in bundle_geneses:
            if sha256(path) != genesis_hashes[0]:
                errors.append(
                    f"{path.relative_to(ROOT)} does not match canonical genesis"
                )

    checksums = ROOT / "artifacts" / "SHA256SUMS"
    if not checksums.is_file() or not checksums.read_text(encoding="utf-8").strip():
        errors.append("signed release artifact checksum manifest is missing")

    if topology.get("network", {}).get("runtime_network_id") != EXPECTED_RUNTIME_NETWORK_ID:
        errors.append("topology is not bound to synergy-testnet-v3")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Validate the dedicated Synergy Testnet-v3 preparation tree."
    )
    parser.add_argument(
        "--structure",
        action="store_true",
        help="validate safe structure and v3 identity only; do not require launch artifacts",
    )
    args = parser.parse_args()

    errors = validate_structure()
    mode = "structure"
    if not args.structure:
        mode = "full launch"
        errors.extend(validate_full_launch())

    if errors:
        print(f"Testnet-v3 {mode} validation: FAIL")
        for error in dict.fromkeys(errors):
            print(f"- {error}")
        return 1

    print(f"Testnet-v3 {mode} validation: PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
