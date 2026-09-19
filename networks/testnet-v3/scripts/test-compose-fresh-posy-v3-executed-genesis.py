#!/usr/bin/env python3
"""Focused fail-closed checks for public SGEN source composition."""
import copy
import importlib.util
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location(
    "executed_genesis", Path(__file__).with_name("compose-fresh-posy-v3-executed-genesis.py")
)
composer = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(composer)


class SgenSourceTests(unittest.TestCase):
    def setUp(self):
        self.authority_raw = b'{"replacement_authority":"public-only"}'
        self.source = {
            "fresh_p3_public_input_binding": {
                "fresh_authority_record_sha256": composer.sha256(self.authority_raw),
            },
            "consensus": {"posy_v3_activation": {
                "binding_status": "FINALIZED_AND_GENESIS_BOUND",
                "manifest": {"target_block_time_ms": 500},
            }},
            "validators": [{"validator_id": f"validator-{i:02d}"} for i in range(2, 7)],
        }

    def test_current_source_binds_exact_authority_bytes(self):
        composer.validate_sgen_source(self.source, self.authority_raw)
        with self.assertRaisesRegex(SystemExit, "freeze hash"):
            composer.validate_sgen_source(self.source, self.authority_raw + b" ")

    def test_old_cadence_is_rejected(self):
        self.source["consensus"]["posy_v3_activation"]["manifest"]["target_block_time_ms"] = 2000
        with self.assertRaisesRegex(SystemExit, "block time"):
            composer.validate_sgen_source(self.source, self.authority_raw)

    def test_unfinalized_activation_is_rejected(self):
        self.source["consensus"]["posy_v3_activation"]["binding_status"] = "DRAFT"
        with self.assertRaisesRegex(SystemExit, "activation status"):
            composer.validate_sgen_source(self.source, self.authority_raw)

    def test_replaced_or_missing_validator_is_rejected(self):
        for ids in ([1, 2, 3, 4, 5], [2, 3, 4, 5], [2, 3, 4, 5, 5]):
            with self.subTest(ids=ids):
                source = copy.deepcopy(self.source)
                source["validators"] = [{"validator_id": f"validator-{i:02d}"} for i in ids]
                with self.assertRaisesRegex(SystemExit, "validator IDs"):
                    composer.validate_sgen_source(source, self.authority_raw)

    def test_freeze_requires_current_chain_and_exact_three_roles(self):
        freeze = {
            "schema_version": "synergy-testnet-v3-genesis-authority-freeze-v1",
            "artifact_type": "fresh-testnet-v3-genesis-authority-public-freeze",
            "chain_id": 1266, "network_id": "testnet", "release_id": "testnet-v3",
            "consensus_protocol": "posy/3.0", "genesis_boundary": "fresh_genesis_block_zero",
            "authority_count": 3, "authority_role_ids": composer.GENESIS_AUTHORITY_ROLES,
            "authorities": [{"role_id": role} for role in composer.GENESIS_AUTHORITY_ROLES],
        }
        self.assertEqual(len(composer.validate_authority_freeze(freeze)), 3)
        freeze["authorities"].reverse()
        with self.assertRaisesRegex(SystemExit, "role order"):
            composer.validate_authority_freeze(freeze)

    def test_receipt_count_and_chain_remain_enforced(self):
        receipts = [
            {"status": "succeeded", "error_code": None,
             "pre_state_root": str(i), "post_state_root": str(i + 1)}
            for i in range(27)
        ]
        composer.validate_receipts(receipts, 27, "initialization receipts")
        with self.assertRaisesRegex(SystemExit, "exactly 27"):
            composer.validate_receipts(receipts[:25], 27, "initialization receipts")
        receipts[4]["pre_state_root"] = "tampered"
        with self.assertRaisesRegex(SystemExit, "discontinuous"):
            composer.validate_receipts(receipts, 27, "initialization receipts")

    def parse(self, extra):
        required = [
            "source-genesis", "allocation-manifest", "resolved-allocations",
            "validator-inputs", "authority-record", "contracts-dir", "execution-status",
            "deployment-receipts", "initialization-receipts", "signed-replay-operations",
            "execution-state", "output",
        ]
        argv = ["composer"] + [item for flag in required for item in ["--" + flag, flag]]
        with patch.object(sys, "argv", argv + extra):
            return composer.parse_args()

    def test_sgen_mode_does_not_require_historical_release_view(self):
        self.assertTrue(self.parse(["--sgen-source"]).sgen_source)

    def test_historical_mode_still_requires_release_view(self):
        with patch("sys.stderr"), self.assertRaises(SystemExit):
            self.parse([])
        self.assertFalse(self.parse(["--release-authority-record", "release.json"]).sgen_source)

    def test_modes_cannot_be_mixed(self):
        with patch("sys.stderr"), self.assertRaises(SystemExit):
            self.parse(["--sgen-source", "--release-authority-record", "release.json"])


if __name__ == "__main__":
    unittest.main()
