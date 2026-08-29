#!/usr/bin/env python3
"""Focused tests for final R11 validator-config rendering."""

from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).with_name("render-posy-v3-r11-final-harness-configs.py")
VALIDATORS = tuple(f"validator-{number:02d}" for number in range(2, 7))
OLD_ROOT = "a" * 128
FINAL_ROOT = "b" * 128


class FinalConfigRendererTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.genesis = self.root / "genesis.json"
        self.genesis.write_text(json.dumps({
            "consensus": {"posy_v3_activation": {
                "parameter_root_sha3_512": FINAL_ROOT,
                "manifest": {
                    "target_block_time_ms": 500,
                    "initial_validator_ids": list(VALIDATORS),
                },
            }},
            "consensus_parameters": {"parameter_root_sha3_512": FINAL_ROOT},
            "validators": [
                {"validator_id": validator, "operator_address": f"synv1{validator}"}
                for validator in VALIDATORS
            ],
        }), encoding="utf-8")
        self.templates = self.root / "templates"
        p2p_ports = {validator: 5602 + index for index, validator in enumerate(VALIDATORS)}
        for index, validator in enumerate(VALIDATORS):
            targets = ", ".join(
                f'"127.0.0.1:{p2p_ports[peer]}"' for peer in VALIDATORS if peer != validator
            )
            path = self.templates / validator / "config.toml"
            path.parent.mkdir(parents=True)
            path.write_text(
                f"[identity]\nnode_id = \"{validator}\"\naddress = \"synv1{validator}\"\n"
                "[blockchain]\nchain_id = 1266\ntarget_block_time_ms = 500\n"
                "[consensus]\nalgorithm = \"posy/3.0\"\nmode = \"posy_simplified_v3\"\n"
                f"target_block_time_ms = 500\nconsensus_parameter_root_sha3_512 = \"{OLD_ROOT}\"\n"
                f"[network]\nid = 1266\nnetwork_id = \"testnet\"\np2p_port = {p2p_ports[validator]}\n"
                f"rpc_port = {6202 + index}\nadditional_dial_targets = [{targets}]\n"
                f"[p2p]\nlisten_address = \"127.0.0.1:{p2p_ports[validator]}\"\n"
                f"[rpc]\nbind_address = \"127.0.0.1:{6202 + index}\"\n",
                encoding="utf-8",
            )
        self.binary = self.root / "synergy-validator-node"
        self.binary.write_text(
            """#!/usr/bin/env python3
import pathlib, sys
node = pathlib.Path(sys.argv[3]).parent.name
print(f"validator_id={node} chain_id=1266 network_id=testnet protocol=posy/3.0 mode=posy_simplified_v3")
""",
            encoding="utf-8",
        )
        self.binary.chmod(0o755)

    def run_renderer(self, output: Path) -> subprocess.CompletedProcess[str]:
        return subprocess.run([
            "python3", str(SCRIPT), "--genesis", str(self.genesis),
            "--template-dir", str(self.templates),
            "--validator-binary", str(self.binary), "--output-dir", str(output),
        ], text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False)

    def test_renders_new_directory_bound_to_final_root(self) -> None:
        output = self.root / "rendered"
        result = self.run_renderer(output)
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn("R11_FINAL_CONFIGS_RENDERED=YES", result.stdout)
        for validator in VALIDATORS:
            text = (output / validator / "config.toml").read_text(encoding="utf-8")
            self.assertIn(FINAL_ROOT, text)
            self.assertNotIn(OLD_ROOT, text)
        report = json.loads((output / "validation-report.json").read_text(encoding="utf-8"))
        self.assertEqual(report["status"], "VALIDATED")
        self.assertEqual(report["consensus_parameter_root_sha3_512"], FINAL_ROOT)

    def test_refuses_to_mutate_existing_output(self) -> None:
        output = self.root / "rendered"
        output.mkdir()
        result = self.run_renderer(output)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("refusing to overwrite", result.stdout)


if __name__ == "__main__":
    unittest.main()
