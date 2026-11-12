#!/usr/bin/env python3
"""Focused tests for the read-only sequence-15 commitment verifier."""

import importlib.util
from pathlib import Path
import unittest


MODULE_PATH = Path(__file__).with_name("verify-r3-activation-commitment.py")
SPEC = importlib.util.spec_from_file_location("verify_r3_activation_commitment", MODULE_PATH)
assert SPEC and SPEC.loader
verifier = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(verifier)


class ActivationPayloadTests(unittest.TestCase):
    def test_sequence_15_matches_canonical_amendment_and_manifest(self):
        repo = Path(__file__).resolve().parents[3]
        node_platform = repo / "node-platform"
        amendment = repo / "protocol/posy-v3/POSY-00E-SIMPLIFIED-CONSENSUS-AMENDMENT.md"
        manifest = node_platform / "networks/testnet/posy-stability/release-r3-recovery.unsigned.json"
        self.assertEqual(
            verifier.commitment(amendment.read_text(encoding="utf-8")),
            __import__("json").loads(manifest.read_text(encoding="utf-8"))["protocol_activation_commitment"],
        )

    def test_status_prose_is_excluded_and_unicode_is_utf8(self):
        content = "\n".join(
            f"{heading}\nrule — approved\nStatus: status prose\n"
            for heading in verifier.HEADINGS
        )
        expected = "".join(f"{heading}\nrule — approved\n" for heading in verifier.HEADINGS).encode("utf-8")
        self.assertEqual(verifier.activation_payload(content), expected)

    def test_missing_heading_fails_closed(self):
        content = "\n".join(f"{heading}\nrule\nStatus: approved" for heading in verifier.HEADINGS[:-1])
        with self.assertRaisesRegex(ValueError, "missing or out-of-order"):
            verifier.activation_payload(content)


if __name__ == "__main__":
    unittest.main()
