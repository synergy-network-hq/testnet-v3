#!/usr/bin/env python3
"""Focused contract checks for the production-role R11 harness wiring."""

import hashlib
import json
import os
import subprocess
import tempfile
import tomllib
import unittest
from pathlib import Path


HARNESS = Path(os.environ.get(
    "R11_HARNESS_UNDER_TEST",
    str(Path(__file__).with_name("run-posy-v3-r11-production-role-harness.sh")),
))
VALIDATORS = [f"validator-{number:02d}" for number in range(2, 7)]


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, separators=(",", ":")), encoding="utf-8")


class HarnessContractTests(unittest.TestCase):
    def test_missing_release_binding_fails_before_process_start(self) -> None:
        result = subprocess.run(
            ["bash", str(HARNESS), "--genesis", "/dev/null", "--ingress-kem-registry-dir", "/tmp"],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=False,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("--desired-state is required", result.stdout)

    def test_preflight_receives_all_release_bindings_and_runtime_layout(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            captures = root / "captures"
            captures.mkdir()
            genesis = root / "genesis.json"
            write_json(genesis, {
                "network": {"chain_id": 1266},
                "consensus": {"posy_v3_activation": {"manifest": {
                    "protocol_version": "posy/3.0", "network_id": "testnet",
                    "initial_validator_ids": VALIDATORS,
                }}},
            })
            epoch_root_name = "01" * 32
            registry_root = root / "registries" / epoch_root_name
            for height in range(3, 21):
                write_json(registry_root / f"epoch-0-height-{height}-cluster-0.json", {
                    "format": "synergy-posy-simplified-ingress-kem-registry-v1",
                    "epoch_context_root": [1] * 32,
                    "epoch": 0,
                    "target_height": height,
                    "assigned_cluster_id": 0,
                    "registry_root": "a" * 128,
                    "registry": {
                        "registry_version": 1, "chain_id": 1266, "network_id": "testnet",
                        "protocol_version": "posy/3.0", "epoch": 0, "target_height": height,
                        "assigned_cluster_id": 0,
                        "records": [
                            {"validator_id": validator, "ingress_key_id": f"{validator}-h{height}",
                             "share_index": index, "key_bytes": [index] * 1568}
                            for index, validator in enumerate(VALIDATORS, 1)
                        ],
                    },
                })
            configs = root / "configs"
            keys = root / "keys"
            p2p_ports = {validator: 5602 + index for index, validator in enumerate(VALIDATORS)}
            rpc_ports = {validator: 6202 + index for index, validator in enumerate(VALIDATORS)}
            for validator in VALIDATORS:
                path = configs / validator / "config.toml"
                path.parent.mkdir(parents=True)
                targets = [
                    f'"127.0.0.1:{p2p_ports[peer]}"'
                    for peer in VALIDATORS if peer != validator
                ]
                path.write_text(
                    f"[identity]\nnode_id = \"{validator}\"\naddress = \"synv1fixture{validator[-2:]}\"\n"
                    f"[network]\np2p_port = {p2p_ports[validator]}\nrpc_port = {rpc_ports[validator]}\n"
                    f"additional_dial_targets = [{','.join(targets)}]\n"
                    f"[p2p]\nlisten_address = \"127.0.0.1:{p2p_ports[validator]}\"\n"
                    f"[rpc]\nbind_address = \"127.0.0.1:{rpc_ports[validator]}\"\n",
                    encoding="utf-8",
                )
                (keys / f"{validator}.key").parent.mkdir(parents=True, exist_ok=True)
                (keys / f"{validator}.key").write_text("fixture", encoding="utf-8")
            desired = root / "desired-state.json"
            desired.write_text("{}", encoding="utf-8")
            desired_sha = hashlib.sha256(desired.read_bytes()).hexdigest()
            authority = root / "authority.json"
            approval = root / "approval.json"
            candidate = root / "candidate.json"
            for path in (authority, approval, candidate):
                path.write_text("{}", encoding="utf-8")
            binary = root / "synergy-validator-node"
            binary.write_text("""#!/usr/bin/env bash
set -euo pipefail
case "$1" in
  validate-config)
    node="$(awk -F'\"' '/node_id/ { print $2; exit }' "$3")"
    printf 'validator_id=%s chain_id=1266 network_id=testnet protocol=posy/3.0 mode=posy_simplified_v3\\n' "$node"
    ;;
  preflight-release)
    node="$(basename "$(dirname "$(dirname "$3")")")"
    env | LC_ALL=C sort >"$CAPTURE_DIR/$node.env"
    printf 'CHAIN1266_ROLE_RELEASE_PREFLIGHT_VERIFIED\\n'
    ;;
  start) sleep 5 ;;
  *) exit 2 ;;
esac
""", encoding="utf-8")
            binary.chmod(0o755)
            work_dir = root / "work"
            command = [
                "bash", str(HARNESS), "--genesis", str(genesis), "--ingress-kem-registry-dir", str(root / "registries"),
                "--desired-state", str(desired), "--desired-state-sha256", desired_sha,
                "--authority-record", str(authority), "--release-approval", str(approval),
                "--release-candidate", str(candidate), "--binary", str(binary), "--work-dir", str(work_dir),
                "--timeout-secs", "1",
            ]
            for validator in VALIDATORS:
                command.extend((f"--{validator}-config", str(configs / validator / "config.toml")))
                command.extend((f"--{validator}-key", str(keys / f"{validator}.key")))
            result = subprocess.run(command, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                    env={**os.environ, "CAPTURE_DIR": str(captures)}, check=False)
            self.assertNotEqual(result.returncode, 0, result.stdout)
            staged = work_dir / "nodes" / "validator-02" / "chain-1266" / "incarnation-5" / "data"
            self.assertTrue((staged / "posy-v3-ingress-kem-registries" / epoch_root_name / "epoch-0-height-3-cluster-0.json").is_file(), result.stdout)
            self.assertEqual(sorted(path.name for path in captures.glob("*.env")),
                             [f"{validator}.env" for validator in VALIDATORS], result.stdout)
            for validator in VALIDATORS:
                env = (captures / f"{validator}.env").read_text(encoding="utf-8")
                self.assertIn(f"SYNERGY_DESIRED_STATE_MANIFEST={desired}", env)
                self.assertIn(f"SYNERGY_DESIRED_STATE_MANIFEST_SHA256={desired_sha}", env)
                self.assertIn(f"SYNERGY_TESTNET_V3_AUTHORITY_RECORD={authority}", env)
                self.assertIn(f"SYNERGY_TESTNET_V3_RELEASE_APPROVAL={approval}", env)
                self.assertIn(f"SYNERGY_TESTNET_V3_RELEASE_CANDIDATE={candidate}", env)
                expected_data = work_dir / "nodes" / validator / "chain-1266" / "incarnation-5" / "data"
                self.assertIn(f"SYNERGY_DATA_PATH={expected_data}", env)
                self.assertNotIn("SYNERGY_CHAIN1266_QUALIFICATION_MODE=", env)
                staged_config = work_dir / "nodes" / validator / "config" / "node.toml"
                self.assertEqual(staged_config.read_bytes(), (configs / validator / "config.toml").read_bytes())
                with staged_config.open("rb") as handle:
                    staged_toml = tomllib.load(handle)
                expected_targets = {
                    f"127.0.0.1:{p2p_ports[peer]}" for peer in VALIDATORS if peer != validator
                }
                self.assertEqual(set(staged_toml["network"]["additional_dial_targets"]), expected_targets)


if __name__ == "__main__":
    unittest.main()
