#!/usr/bin/env python3
"""Focused checks for the canonical Prometheus validator-state rule."""

from __future__ import annotations

import re
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
RULES_PATH = REPO_ROOT / "ops" / "observability" / "rules" / "synergy-canonical-validator-state.yml"


class CanonicalValidatorRuleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.rules = RULES_PATH.read_text(encoding="utf-8")

    def test_active_validator_count_uses_live_job_and_max_deduplication(self) -> None:
        expected_expression = (
            r'expr:\s*max\(synergy_validator_status_total\{'
            r'job="synergy-validators",status="active"\}\)'
        )
        self.assertEqual(
            len(re.findall(expected_expression, self.rules)),
            1,
            "canonical count must use the live validator job exactly once",
        )
        self.assertNotRegex(
            self.rules,
            r"synergy_validator_status_total\{[^}]*job=~",
            "canonical count must not broaden the selector across duplicate sources",
        )
        self.assertNotRegex(
            self.rules,
            r"(?:sum|count)\([^)]*synergy_validator_status_total",
            "replicated validator gauges must not be summed or counted",
        )

    def test_quorum_alert_consumes_canonical_count(self) -> None:
        self.assertIn(
            "expr: synergy_canonical_active_validator_count < 4",
            self.rules,
        )
        self.assertIn("alert: SynergyActiveValidatorCountBelowQuorum", self.rules)


if __name__ == "__main__":
    unittest.main()
