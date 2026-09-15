#!/usr/bin/env python3
"""Focused tests for deterministic final-binary desired-state refresh."""

from __future__ import annotations

import hashlib
import json
import subprocess
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).with_name("prepare-posy-v3-r11-harness-desired-state.sh")
VALIDATORS = tuple(f"validator-{number:02d}" for number in range(2, 7))
REVISIONS = {
    "testnet_v3_revision": "1" * 40,
    "synq_revision": "2" * 40,
    "aegis_revision": "3" * 40,
}
PARAMETER_ROOT = "a" * 128


def write_executable(path: Path, text: str) -> None:
    path.write_text(text, encoding="utf-8")
    path.chmod(0o755)


class DesiredStateRefreshTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.binary = self.root / "synergy-validator-node"
        write_executable(
            self.binary,
            """#!/usr/bin/env python3
import json, pathlib, sys
if sys.argv[1] == "build-provenance":
    print(json.dumps({"schema_version":1,"artifact":"synergy-validator-node","source":{"testnet_v3_revision":"%s","synq_revision":"%s","aegis_revision":"%s"}}, separators=(",",":")))
elif sys.argv[1] == "validate-config":
    node = pathlib.Path(sys.argv[3]).parent.name
    print(f"validator_id={node} chain_id=1266 network_id=testnet protocol=posy/3.0 mode=posy_simplified_v3")
else:
    raise SystemExit(2)
"""
            % tuple(REVISIONS.values()),
        )
        self.genesis = self.root / "genesis.json"
        self.genesis.write_text(json.dumps({
            "consensus": {"posy_v3_activation": {
                "parameter_root_sha3_512": PARAMETER_ROOT,
                "manifest": {"target_block_time_ms": 500},
            }},
            "consensus_parameters": {"parameter_root_sha3_512": PARAMETER_ROOT},
        }), encoding="utf-8")
        self.config_dir = self.root / "configs"
        for validator in VALIDATORS:
            config = self.config_dir / validator / "config.toml"
            config.parent.mkdir(parents=True)
            config.write_text(
                f"[identity]\nnode_id = \"{validator}\"\n"
                "[blockchain]\ntarget_block_time_ms = 500\n"
                "[consensus]\ntarget_block_time_ms = 500\n"
                f"consensus_parameter_root_sha3_512 = \"{PARAMETER_ROOT}\"\n",
                encoding="utf-8",
            )
        self.builder = self.root / "build-chain1266-desired-state"
        write_executable(
            self.builder,
            """#!/usr/bin/env python3
import hashlib, json, pathlib, sys
args = sys.argv[1:]
def one(flag): return args[args.index(flag)+1]
def repeated(flag): return [args[i+1] for i, value in enumerate(args) if value == flag]
artifacts = {name: hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest() for name, path in (item.split("=",1) for item in repeated("--artifact"))}
configs = {name: hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest() for name, path in (item.split("=",1) for item in repeated("--configuration"))}
value = {"schema_version":1,"release_id":one("--release-id"),"release_tag":one("--release-tag"),"chain":{"chain_id":1266,"incarnation":5},"source":{"testnet_v3_revision":one("--testnet-revision"),"synq_revision":one("--synq-revision"),"aegis_revision":one("--aegis-revision")},"state":{"consensus_schema_version":5,"directory_namespace":"chain-1266/incarnation-5","mode":"posy_simplified_v3","coordinator_id":"","producer_ids":[],"producer_turn_timeout_ms":0},"artifacts":artifacts,"configuration":configs}
pathlib.Path(one("--output")).write_text(json.dumps(value, indent=2)+"\\n", encoding="utf-8")
""",
        )

    def command(self, output: Path, testnet_revision: str = REVISIONS["testnet_v3_revision"]) -> list[str]:
        return [
            "bash", str(SCRIPT),
            "--builder", str(self.builder),
            "--binary", str(self.binary),
            "--genesis", str(self.genesis),
            "--config-dir", str(self.config_dir),
            "--release-id", "chain1266-incarnation-5-local-r11",
            "--release-tag", "chain1266-v20.0.0-local-r11",
            "--testnet-revision", testnet_revision,
            "--synq-revision", REVISIONS["synq_revision"],
            "--aegis-revision", REVISIONS["aegis_revision"],
            "--output", str(output),
        ]

    def test_refresh_binds_exact_binary_and_configs(self) -> None:
        output = self.root / "desired-state.json"
        result = subprocess.run(
            self.command(output), text=True, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn("R11_DESIRED_STATE_REFRESHED=YES", result.stdout)
        value = json.loads(output.read_text(encoding="utf-8"))
        self.assertEqual(
            value["artifacts"],
            {"validator_node": hashlib.sha256(self.binary.read_bytes()).hexdigest()},
        )
        self.assertEqual(
            value["configuration"],
            {
                validator: hashlib.sha256(
                    (self.config_dir / validator / "config.toml").read_bytes()
                ).hexdigest()
                for validator in VALIDATORS
            },
        )

    def test_refresh_rejects_revision_not_embedded_in_binary(self) -> None:
        output = self.root / "desired-state.json"
        result = subprocess.run(
            self.command(output, testnet_revision="4" * 40), text=True,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False,
        )
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("binary provenance does not match", result.stdout)
        self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
