#!/usr/bin/env python3
"""Regression test for the public-only R11 500 ms candidate generator."""

import hashlib
import json
import subprocess
import tempfile
import tomllib
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "build-r11-500ms-qualification-candidate.py"
GENESIS = ROOT / "launch" / "posy-v3-genesis-inputs" / "fresh-p3-genesis-predeployment-public-input.json"
MANIFEST = ROOT / "launch" / "posy-v3-etdag-governance-inputs" / "posy-simplified-parameter-manifest.for-release.json"


class CandidateTests(unittest.TestCase):
    def test_derives_unsigned_500ms_candidate_without_changing_sources(self) -> None:
        before = {path: hashlib.sha256(path.read_bytes()).hexdigest() for path in (GENESIS, MANIFEST)}
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "candidate"
            subprocess.run([
                "python3", str(SCRIPT), "--source-genesis", str(GENESIS),
                "--source-manifest", str(MANIFEST), "--output-dir", str(output),
                "--source-revision", "test-revision",
            ], check=True, text=True, capture_output=True)
            report = json.loads((output / "validation-report.json").read_text())
            manifest = json.loads((output / "consensus-parameter-manifest.unsigned.json").read_text())
            genesis = json.loads((output / "genesis-predeployment-candidate.unsigned.json").read_text())
            request = json.loads((output / "governance-signing-request.unsigned.json").read_text())
            self.assertEqual((report["OLD_TIMING"], report["NEW_TIMING"]), (2000, 500))
            self.assertEqual(manifest["status"], "PROPOSED_NOT_ACTIVATED")
            self.assertIsNone(manifest["governance_approval_id"])
            self.assertEqual(genesis["consensus"]["target_block_time_ms"], 500)
            self.assertEqual(genesis["consensus"]["posy_v3_activation"]["parameter_root_sha3_512"],
                             report["candidate_parameter_root_sha3_512"])
            self.assertEqual(request["status"], "UNSIGNED_EXTERNAL_GOVERNANCE_ACTION_REQUIRED")
            rendered = list((output / "rendered-configs").glob("*/config.toml"))
            self.assertEqual(len(rendered), 5)
            config = rendered[0].read_text()
            self.assertIn('compiled_profile = "validator_node"', config)
            self.assertIn("target_block_time_ms = 500", config)
            self.assertNotIn("block_time_secs", config)
            self.assertIn("[logging]", config)
            self.assertIn("[rpc]", config)
            self.assertIn("[storage]", config)
            for path in rendered:
                validator = path.parent.name
                with path.open("rb") as handle:
                    parsed = tomllib.load(handle)
                expected = {
                    f"127.0.0.1:{5600 + int(peer.rsplit('-', 1)[1])}"
                    for peer in (f"validator-{ordinal:02d}" for ordinal in range(2, 7))
                    if peer != validator
                }
                self.assertEqual(set(parsed["network"]["additional_dial_targets"]), expected)
            self.assertEqual(before, {path: hashlib.sha256(path.read_bytes()).hexdigest() for path in before})


if __name__ == "__main__":
    unittest.main()
