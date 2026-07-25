#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
MANIFEST_PATH = ROOT / "launch" / "component-parity-manifest.json"
VENDORED_DEPENDENCIES = (
    ROOT / "runtime" / "synergy-aivm",
    ROOT / "runtime" / "synq-language",
    ROOT / "runtime" / "aegis-pqvm",
)


def relative(path: Path) -> str:
    return str(path.relative_to(ROOT))


def load_manifest(errors: list[str]) -> dict[str, Any]:
    try:
        value = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        errors.append(f"cannot load {relative(MANIFEST_PATH)}: {error}")
        return {}
    if not isinstance(value, dict):
        errors.append("component manifest must be a JSON object")
        return {}
    return value


def check_component(component: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    component_id = component.get("id", "<unnamed>")

    for raw_path in component.get("required_paths", []):
        path = ROOT / raw_path
        if not path.exists():
            errors.append(f"{component_id}: required path missing: {raw_path}")

    for marker_rule in component.get("required_markers", []):
        raw_path = marker_rule.get("path", "")
        path = ROOT / raw_path
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as error:
            errors.append(f"{component_id}: cannot inspect {raw_path}: {error}")
            continue
        for marker in marker_rule.get("contains", []):
            if marker not in text:
                errors.append(
                    f"{component_id}: wiring marker {marker!r} missing from {raw_path}"
                )

    contracts = component.get("contracts", [])
    for contract in contracts:
        contract_root = ROOT / "genesis-contracts" / "contracts"
        source = contract_root / f"{contract}.synq"
        bytecode = contract_root / f"{contract}.compiled.synq"
        abi_path = contract_root / f"{contract}.abi.json"
        manifest_path = contract_root / f"{contract}.manifest.json"

        if not source.is_file():
            errors.append(f"{component_id}: SynQ source missing: {relative(source)}")
            continue
        try:
            bytecode_bytes = bytecode.read_bytes()
        except OSError as error:
            errors.append(
                f"{component_id}: cannot read bytecode {relative(bytecode)}: {error}"
            )
            continue
        if len(bytecode_bytes) < 8 or not bytecode_bytes.startswith(b"\x00MVQ"):
            errors.append(
                f"{component_id}: invalid SynQ bytecode header: {relative(bytecode)}"
            )

        try:
            abi = json.loads(abi_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            errors.append(
                f"{component_id}: invalid SynQ ABI {relative(abi_path)}: {error}"
            )
            continue
        if abi.get("contract") != contract:
            errors.append(
                f"{component_id}: ABI contract mismatch: {relative(abi_path)}"
            )
        if not isinstance(abi.get("methods"), list) or not abi["methods"]:
            errors.append(f"{component_id}: ABI methods are empty: {relative(abi_path)}")
        security = abi.get("security_requirements", {})
        if security.get("signature_algorithm") != "ML-DSA-65":
            errors.append(
                f"{component_id}: ABI is not bound to ML-DSA-65: {relative(abi_path)}"
            )

        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            errors.append(
                f"{component_id}: invalid SynQ manifest "
                f"{relative(manifest_path)}: {error}"
            )
            continue
        expected_values = {
            "contract_name": contract,
            "artifact_format": "synq-bytecode-v1",
            "required_chain_id": 1264,
            "required_network_id": "synergy-testnet-v3",
            "required_signature_algorithm": "ML-DSA-65",
        }
        for field, expected in expected_values.items():
            if manifest.get(field) != expected:
                errors.append(
                    f"{component_id}: manifest {field} must be {expected!r}: "
                    f"{relative(manifest_path)}"
                )
        hashes = {
            "source_hash": hashlib.sha256(source.read_bytes()).hexdigest(),
            "bytecode_hash": hashlib.sha256(bytecode_bytes).hexdigest(),
            "abi_hash": hashlib.sha256(abi_path.read_bytes()).hexdigest(),
        }
        for field, expected in hashes.items():
            if manifest.get(field) != expected:
                errors.append(
                    f"{component_id}: manifest {field} does not match artifact: "
                    f"{relative(manifest_path)}"
                )

    solidity_files = list((ROOT / "genesis-contracts").rglob("*.sol"))
    for path in solidity_files:
        errors.append(
            f"{component_id}: Solidity is not a Synergy deployment format: "
            f"{relative(path)}"
        )

    return errors


def check_vendored_dependencies() -> list[str]:
    errors: list[str] = []
    for dependency in VENDORED_DEPENDENCIES:
        if not dependency.is_dir():
            errors.append(f"vendored dependency missing: {relative(dependency)}")
            continue
        git_metadata = list(dependency.rglob(".git"))
        for path in git_metadata:
            errors.append(
                f"vendored dependency contains nested Git metadata and would not be "
                f"self-contained: {relative(path)}"
            )
    return errors


def audit() -> dict[str, Any]:
    errors: list[str] = []
    manifest = load_manifest(errors)
    components = manifest.get("components", []) if manifest else []
    results: list[dict[str, Any]] = []

    if manifest:
        if manifest.get("chain_id") != 1264:
            errors.append("component manifest chain_id must be 1264")
        if manifest.get("runtime_network_id") != "synergy-testnet-v3":
            errors.append(
                "component manifest runtime_network_id must be synergy-testnet-v3"
            )
    if not isinstance(components, list) or not components:
        errors.append("component manifest has no components")
        components = []

    seen: set[str] = set()
    for component in components:
        if not isinstance(component, dict):
            errors.append("component entry must be an object")
            continue
        component_id = str(component.get("id", "<unnamed>"))
        if component_id in seen:
            errors.append(f"duplicate component id: {component_id}")
        seen.add(component_id)
        component_errors = check_component(component)
        errors.extend(component_errors)
        results.append(
            {
                "id": component_id,
                "status": "pass" if not component_errors else "fail",
                "errors": component_errors,
            }
        )

    vendor_errors = check_vendored_dependencies()
    errors.extend(vendor_errors)
    operational_blockers = manifest.get("operational_blockers", []) if manifest else []
    active_blockers = [
        blocker
        for blocker in operational_blockers
        if isinstance(blocker, dict) and blocker.get("status") == "blocked"
    ]

    return {
        "schema_version": 1,
        "target_release": manifest.get("target_release"),
        "chain_id": manifest.get("chain_id"),
        "runtime_network_id": manifest.get("runtime_network_id"),
        "status": "fail" if errors else ("blocked" if active_blockers else "pass"),
        "packaging_status": "pass" if not errors else "fail",
        "component_count": len(results),
        "components": results,
        "vendored_dependencies": {
            "status": "pass" if not vendor_errors else "fail",
            "errors": vendor_errors,
        },
        "operational_blockers": active_blockers,
        "errors": errors,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Check Testnet-v3 functional component packaging and wiring."
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="emit the full machine-readable result",
    )
    args = parser.parse_args()

    result = audit()
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    elif result["status"] in {"pass", "blocked"} and result["packaging_status"] == "pass":
        print(
            "Testnet-v3 component packaging check: PASS "
            f"({result['component_count']} components)"
        )
        for component in result["components"]:
            print(f"- PASS {component['id']}")
        print("- PASS vendored_dependencies")
        if result["status"] == "blocked":
            print("Testnet-v3 operational capability check: BLOCKED")
            for blocker in result["operational_blockers"]:
                print(f"- BLOCKED {blocker.get('id')}: {blocker.get('reason')}")
    else:
        print("Testnet-v3 component parity check: FAIL")
        for error in result["errors"]:
            print(f"- {error}")

    return 0 if result["status"] == "pass" else 1


if __name__ == "__main__":
    sys.exit(main())
