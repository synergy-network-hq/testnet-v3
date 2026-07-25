#!/usr/bin/env python3
from __future__ import annotations

import base64
import json
import subprocess
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "scripts" / "testnet" / "genesis_tool.py"
GENESIS = ROOT / "genesis.testnet.json"
NETWORK_IDENTIFIERS = ROOT / "network-identifiers.testnet.json"
CONSENSUS_FORK = ROOT / "config" / "consensus-fork-migration.json"
VALIDATOR_ADDRESS = "synv1" + "a" * 36
FN_DSA_PUBLIC_KEY = "fn-dsa:" + base64.b64encode(b"fake-fndsa-public-key").decode("ascii")


class OnboardingDryRunTests(unittest.TestCase):
    def command(
        self,
        *,
        validator_address: str = VALIDATOR_ADDRESS,
        consensus_key_type: str = "FN-DSA",
        consensus_public_key: str = FN_DSA_PUBLIC_KEY,
        include_bonded_stake: bool = True,
        include_support_node_preflight: bool = True,
    ) -> list[str]:
        command = [
            sys.executable,
            str(TOOL),
            "--root",
            str(ROOT),
            "onboarding-dry-run",
            "--genesis",
            str(GENESIS),
            "--network-identifiers",
            str(NETWORK_IDENTIFIERS),
            "--consensus-fork",
            str(CONSENSUS_FORK),
            "--validator-address",
            validator_address,
            "--consensus-key-type",
            consensus_key_type,
            "--consensus-public-key",
            consensus_public_key,
            "--local-height",
            "304792",
            "--public-head-height",
            "304793",
            "--p2p-port",
            "5622",
            "--qrpc-port",
            "5640",
            "--ws-port",
            "5660",
            "--discovery-port",
            "5680",
            "--metrics-port",
            "6030",
            "--signing-challenge-verified",
            "--seed-registration-verified",
            "--relayer-peer-visibility-verified",
            "--funding-verified",
            "--source-majority-proof-verified",
            "--shadow-duty-gate-verified",
        ]
        if include_bonded_stake:
            command.append("--bonded-stake-verified")
        if include_support_node_preflight:
            command.append("--support-node-replay-preflight-verified")
        return command

    def run_dry_run(self, *args: str, **kwargs: object) -> tuple[subprocess.CompletedProcess[str], dict[str, object]]:
        process = subprocess.run(
            self.command(**kwargs),
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            payload = json.loads(process.stdout)
        except json.JSONDecodeError as exc:
            self.fail(f"dry-run did not emit JSON: {exc}\nstdout={process.stdout}\nstderr={process.stderr}")
        return process, payload

    def check_by_name(self, payload: dict[str, object], name: str) -> dict[str, object]:
        checks = payload.get("checks")
        self.assertIsInstance(checks, list)
        matches = [check for check in checks if isinstance(check, dict) and check.get("name") == name]
        self.assertEqual(len(matches), 1, name)
        return matches[0]

    def test_accepts_clean_onboarded_validator_dry_run(self) -> None:
        process, payload = self.run_dry_run()
        self.assertEqual(process.returncode, 0, process.stderr)
        self.assertTrue(payload["ok"])
        self.assertFalse(payload["mutates_state"])
        self.assertEqual(payload["chain_id"], 1264)
        self.assertEqual(payload["runtime_network_id"], "synergy-testnet-v3")
        self.assertEqual(payload["shadow_phase_blocks"], 1000)
        self.assertTrue(self.check_by_name(payload, "validator_not_in_genesis")["ok"])
        self.assertTrue(self.check_by_name(payload, "consensus_key_type_explicit_fndsa")["ok"])
        support_plan = payload["support_node_update_plan"]
        self.assertTrue(support_plan["required_before_activation"])
        self.assertIn("rpc_gateway", support_plan["support_roles"])
        self.assertEqual(
            support_plan["checkpoint_fork_registry_policy"]["onboarded_key_source"],
            "finalized validator registry/admission state after activation",
        )

    def test_rejects_reusing_initial_validator_address(self) -> None:
        genesis = json.loads(GENESIS.read_text(encoding="utf-8"))
        existing_validator = genesis["validators"][0]["operator_address"]
        process, payload = self.run_dry_run(validator_address=existing_validator)
        self.assertNotEqual(process.returncode, 0)
        self.assertFalse(payload["ok"])
        self.assertFalse(self.check_by_name(payload, "validator_not_in_genesis")["ok"])

    def test_rejects_mldsa_or_unprefixed_consensus_key(self) -> None:
        process, payload = self.run_dry_run(
            consensus_key_type="ML-DSA",
            consensus_public_key=base64.b64encode(b"wrong-key").decode("ascii"),
        )
        self.assertNotEqual(process.returncode, 0)
        self.assertFalse(payload["ok"])
        self.assertFalse(self.check_by_name(payload, "consensus_key_type_explicit_fndsa")["ok"])
        self.assertFalse(self.check_by_name(payload, "consensus_public_key_fndsa_prefix")["ok"])

    def test_rejects_missing_bonded_stake_evidence(self) -> None:
        process, payload = self.run_dry_run(include_bonded_stake=False)
        self.assertNotEqual(process.returncode, 0)
        self.assertFalse(payload["ok"])
        self.assertFalse(self.check_by_name(payload, "bonded_stake_verified")["ok"])

    def test_rejects_missing_support_node_replay_preflight(self) -> None:
        process, payload = self.run_dry_run(include_support_node_preflight=False)
        self.assertNotEqual(process.returncode, 0)
        self.assertFalse(payload["ok"])
        self.assertFalse(self.check_by_name(payload, "support_node_replay_preflight_verified")["ok"])


if __name__ == "__main__":
    unittest.main()
