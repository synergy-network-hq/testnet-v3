#!/usr/bin/env python3
"""Offline tests for the fresh NetBird provider desired-state adapter."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "generate-fresh-posy-v3-validator-vpn-provider.py"
INPUTS = ROOT / "launch" / "posy-v3-genesis-inputs" / "authority-rotation-20260823"


def command(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run([sys.executable, str(SCRIPT), *args], text=True, capture_output=True, check=False)


class FreshProviderPlanTests(unittest.TestCase):
    def test_fresh_plan_is_public_canonical_and_verifiable(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary)
            registry = output / "registry.json"
            proof = output / "proof.json"
            result = command(
                "build",
                "--validator-inputs", str(INPUTS / "fresh-validator-genesis-source-inputs.json"),
                "--authority-freeze", str(INPUTS / "fresh-genesis-authority-freeze.json"),
                "--output-registry", str(registry),
                "--output-proof", str(proof),
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            data = json.loads(registry.read_text())
            self.assertEqual(data["provider"]["kind"], "netbird")
            self.assertEqual(data["hub"]["udp_port"], 51820)
            self.assertEqual(data["initial_active_validator_ids"], [f"validator-{number:02d}" for number in range(2, 7)])
            self.assertEqual(len(data["participants"]), 21)
            self.assertEqual(data["participants"][0]["vpn_ip"], "10.69.10.1")
            self.assertEqual(data["participants"][-1]["vpn_ip"], "10.69.10.21")
            self.assertEqual([entry["vpn_ip"] for entry in data["relayer_assignments"]],
                             ["10.69.1.1", "10.69.1.2", "10.69.1.3"])
            self.assertEqual(data["dynamic_onboarding"]["usable_validator_vpn_ordinal_range"],
                             {"first": 1, "last": 254})
            snapshot = data["transport_snapshot_request"]
            self.assertEqual(snapshot["network"], "synergy-testnet-v3-validator-transport-v1")
            self.assertEqual(snapshot["registry_id"], "synergy-testnet-v3-block-zero-transport-v1")
            self.assertEqual([entry["dial_address"] for entry in snapshot["transports"]],
                             [f"10.69.10.{number}:5622" for number in range(2, 7)])
            check = command(
                "verify",
                "--validator-inputs", str(INPUTS / "fresh-validator-genesis-source-inputs.json"),
                "--authority-freeze", str(INPUTS / "fresh-genesis-authority-freeze.json"),
                "--registry", str(registry),
                "--proof", str(proof),
            )
            self.assertEqual(check.returncode, 0, check.stderr)
            self.assertIn("FRESH_POSY_V3_NETBIRD_PROVIDER_OFFLINE_VERIFIED", check.stdout)

    def test_legacy_provider_marker_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary)
            registry = output / "registry.json"
            proof = output / "proof.json"
            built = command(
                "build",
                "--validator-inputs", str(INPUTS / "fresh-validator-genesis-source-inputs.json"),
                "--authority-freeze", str(INPUTS / "fresh-genesis-authority-freeze.json"),
                "--output-registry", str(registry),
                "--output-proof", str(proof),
            )
            self.assertEqual(built.returncode, 0, built.stderr)
            data = json.loads(registry.read_text())
            data["provider"]["kind"] = "innernet"
            registry.write_text(json.dumps(data, sort_keys=True) + "\n")
            check = command(
                "verify",
                "--validator-inputs", str(INPUTS / "fresh-validator-genesis-source-inputs.json"),
                "--authority-freeze", str(INPUTS / "fresh-genesis-authority-freeze.json"),
                "--registry", str(registry),
                "--proof", str(proof),
            )
            self.assertNotEqual(check.returncode, 0)
            self.assertIn("NetBird", check.stderr)


if __name__ == "__main__":
    unittest.main()
