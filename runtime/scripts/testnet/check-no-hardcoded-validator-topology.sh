#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

python3 - "$ROOT_DIR" <<'PY'
import re
import sys
from pathlib import Path

root = Path(sys.argv[1])

scan_roots = [
    root / "src",
    root / "scripts",
    root / "tools",
    root / "templates",
    root / "config",
    root / ".github" / "workflows",
    root / "README.md",
]

allowed_suffixes = {
    ".rs",
    ".sh",
    ".py",
    ".toml",
    ".json",
    ".md",
    ".yml",
    ".yaml",
    ".txt",
}

allowed_validator_name_paths = (
    "scripts/testnet/check-no-hardcoded-validator-topology.sh",
    "scripts/testnet/incident-val1-build-recovery-plan.sh",
    "scripts/testnet/incident-val5-build-recovery-plan.sh",
    "scripts/testnet/incident-relayer1-build-recovery-plan.sh",
    "scripts/testnet/repro-mixed-runtime-rollout.sh",
    "scripts/testnet/run-launch-stability-soak.sh",
    "scripts/testnet/val5-authorized-narrow-cleanup.sh",
    "scripts/testnet/val5-fndsa-rejoin-workflow.sh",
    "scripts/testnet/val2_cold_canonical_snapshot_restore.py",
    "config/seed-services/seed1.json",
    "config/seed-services/seed2.json",
    "config/seed-services/seed3.json",
    "config/consensus-fork-migration.json",
    "config/testnet/network-topology.toml",
    "config/testnet/generated/validators/val1.toml",
    "config/testnet/generated/validators/val2.toml",
    "config/testnet/generated/validators/val3.toml",
    "config/testnet/generated/validators/val4.toml",
    "config/testnet/generated/validators/val5.toml",
    "config/testnet/generated/validators/val6.toml",
)

allowed_cluster_size_paths = (
    "config/",
    "templates/",
    "tools/generate_templates.sh",
    "src/config/mod.rs",
)

failures = []


def rel(path: Path) -> str:
    return path.relative_to(root).as_posix()


def iter_files():
    for entry in scan_roots:
        if not entry.exists():
            continue
        if entry.is_file():
            yield entry
            continue
        for path in entry.rglob("*"):
            if not path.is_file():
                continue
            relative = rel(path)
            if any(part in {".git", "target", "node_modules", "aegis-pqvm"} for part in path.parts):
                continue
            if path.suffix in allowed_suffixes:
                yield path


def is_allowed_validator_name(path: str) -> bool:
    return path in allowed_validator_name_paths


def is_allowed_cluster_size(path: str) -> bool:
    return path.startswith(allowed_cluster_size_paths)


def is_rust_test_context(path: str, lines: list[str], line_index: int) -> bool:
    if not path.endswith(".rs"):
        return False
    window = lines[max(0, line_index - 400):line_index]
    return any(
        "#[test]" in candidate
        or "#[cfg(test)]" in candidate
        or "mod tests" in candidate
        for candidate in window
    )


def report(path: str, line_no: int, message: str, line: str) -> None:
    failures.append(f"{path}:{line_no}: {message}: {line.strip()}")


for path in sorted(iter_files(), key=lambda item: rel(item)):
    relative = rel(path)
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except UnicodeDecodeError:
        continue

    for index, line in enumerate(lines, start=1):
        if relative.startswith(("config/", "templates/")) and re.search(
            r"^\s*(emergency_stable_committee_mode|freeze_validator_set|freeze_score_weighted_proposer_order)\s*=\s*true\s*(#.*)?$",
            line,
        ):
            report(
                relative,
                index,
                "permanent emergency committee freezes are not allowed in shipped runtime configuration",
                line,
            )

        if re.search(r"^\s*max_validators\s*=\s*[1-9][0-9]*\s*(#.*)?$", line):
            report(
                relative,
                index,
                "fixed max_validators cap is not allowed; use 0 for dynamic validator expansion",
                line,
            )

        if re.search(r"^\s*validator_vote_threshold\s*=\s*[1-9][0-9]*\s*(#.*)?$", line):
            report(
                relative,
                index,
                "fixed validator_vote_threshold is not allowed; use 0 so runtime derives quorum",
                line,
            )

        if re.search(r"^\s*validator_cluster_size\s*=\s*6\s*(#.*)?$", line):
            if not is_allowed_cluster_size(relative):
                report(
                    relative,
                    index,
                    "validator_cluster_size = 6 is only allowed in current-live config/templates",
                    line,
                )

        if re.search(r"\b(4-of-6|6/6|six-validator)\b", line, flags=re.IGNORECASE):
            if relative == "scripts/testnet/check-no-hardcoded-validator-topology.sh":
                continue
            report(
                relative,
                index,
                "current six-validator fleet wording must not be used as protocol truth",
                line,
            )

        if re.search(r"\bVal[1-6]\b", line):
            if not is_allowed_validator_name(relative) and not is_rust_test_context(
                relative, lines, index
            ):
                report(
                    relative,
                    index,
                    "Val1-Val6 names are allowed only in current-live or historical incident fixtures",
                    line,
                )

if failures:
    print("Hard-coded validator topology guard failed:", file=sys.stderr)
    for failure in failures:
        print(failure, file=sys.stderr)
    sys.exit(1)

print("Dynamic validator topology guard passed.")
PY
