#!/usr/bin/env python3
"""Structural launch gate: no retired Testnet-v2 validator address may appear
in any active Testnet-v3 runtime path.

FAIL scope (active inputs): runtime/config/**, runtime/templates/**,
runtime/bootstrap-bundles/**, runtime/deploy/**, runtime root-level manifests,
service env/plist files anywhere outside quarantine, topology files, and
production (non-test) regions of runtime/src.

Allowed (classified, reported as INFO): launch/reference/** (quarantined v2
evidence), #[cfg(test)] regions of Rust sources, test/benchmark fixtures,
retired v2 operational scripts under runtime/scripts/testnet (reference only).

Exit 0 = PASS, exit 1 = FAIL.
"""
import os, re, sys

ROOT = os.environ.get(
    "TNV3_ROOT",
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
)

RETIRED = [
    "synv11qen9x0g9p0f2pqznpqzfrwkrgnsussdwmvs",
    "synv11s4wc6l4kg4jr0k5meg42cyzxa03cf863srt",
    "synv11e3ephsarcw6mey0fx5xtnygg2ewegnum4re",
    "synv11mka64uz049aekwhdvfrq6dvh75d0k7kmdp5",
    "synv11kguave5fpdpm9hru4acfvw0hcp4fcc7zv9f",
    "synv11zghr6nsm3ajl57ywxasw9mr5f844slq4mwx",
]
PAT = re.compile("|".join(RETIRED))

SKIP_DIRS = {".git", "target", "node_modules", "__pycache__"}
QUARANTINE = os.path.join("launch", "reference")

ACTIVE_PREFIXES = (
    os.path.join("runtime", "config"),
    os.path.join("runtime", "templates"),
    os.path.join("runtime", "bootstrap-bundles"),
    os.path.join("runtime", "deploy"),
)
ACTIVE_SUFFIXES = (".env", ".plist", ".plist.in", ".service")
TOPOLOGY_MARKERS = ("topology",)


def rust_hit_in_production_region(path, text):
    """True if a retired address appears before the tests module marker."""
    m = re.search(r"^\s*(#\[cfg\(test\)\]|mod tests)\b", text, re.M)
    cut = m.start() if m else len(text)
    return bool(PAT.search(text[:cut]))


def classify(rel, text):
    if rel.startswith(QUARANTINE):
        return "INFO", "quarantined v2 reference evidence"
    if rel.startswith(os.path.join("runtime", "src")) and rel.endswith(".rs"):
        if rust_hit_in_production_region(os.path.join(ROOT, rel), text):
            return "FAIL", "retired address in production Rust code region"
        return "INFO", "Rust test-region fixture"
    if rel.startswith(os.path.join("runtime", "src", "bin")):
        return "INFO", "benchmark/tool fixture"
    if rel.startswith(ACTIVE_PREFIXES):
        return "FAIL", "retired address in active runtime input"
    if rel.endswith(ACTIVE_SUFFIXES):
        return "FAIL", "retired address in service/environment file"
    if any(t in os.path.basename(rel).lower() for t in TOPOLOGY_MARKERS):
        return "FAIL", "retired address in topology file"
    if os.path.dirname(rel) == "runtime" and rel.endswith(".json"):
        return "FAIL", "retired address in runtime root-level manifest"
    if rel.startswith(os.path.join("runtime", "scripts", "testnet")):
        return "INFO", "retired v2 operational script (reference only; do not run against v3)"
    if "/tests/" in rel or rel.startswith("scripts"):
        return "INFO", "test or tooling fixture"
    return "FAIL", "retired address in unclassified active path"


def main():
    failures, infos = [], []
    for dirpath, dirs, files in os.walk(ROOT):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for f in files:
            fp = os.path.join(dirpath, f)
            rel = os.path.relpath(fp, ROOT)
            if rel.startswith(".git"):
                continue
            try:
                if os.path.getsize(fp) > 30_000_000:
                    continue
                with open(fp, errors="ignore") as fh:
                    text = fh.read()
            except OSError:
                continue
            if not PAT.search(text):
                continue
            status, why = classify(rel, text)
            (failures if status == "FAIL" else infos).append((rel, why))
    for rel, why in infos:
        print(f"[INFO] {rel}: {why}")
    for rel, why in failures:
        print(f"[FAIL] {rel}: {why}")
    print(
        f"retired-v2-binding check: {'FAIL' if failures else 'PASS'} "
        f"({len(failures)} active violations, {len(infos)} classified references)"
    )
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
