#!/usr/bin/env python3
"""Tests for validate-validator-vpn-runtime.py."""

from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPT_PATH = Path(__file__).with_name("validate-validator-vpn-runtime.py")
SPEC = importlib.util.spec_from_file_location("validator_vpn_runtime", SCRIPT_PATH)
assert SPEC and SPEC.loader
checker = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = checker
SPEC.loader.exec_module(checker)


LOCAL_VALIDATOR = "synv1localvalidator000000000000000000000000000"
PEER_VALIDATOR = "synv1peervalidator0000000000000000000000000000"


def write_workspace(
    workspace: Path,
    *,
    validator_address: str = LOCAL_VALIDATOR,
    public_p2p_address: str | None = LOCAL_VALIDATOR,
    strict_allowlist: bool = False,
    persistent_peers: list[str] | None = None,
    transports: list[tuple[str, str]] | None = None,
) -> None:
    config = workspace / "config"
    config.mkdir(parents=True)
    peers = persistent_peers if persistent_peers is not None else [PEER_VALIDATOR]
    transport_rows = transports if transports is not None else [(PEER_VALIDATOR, "10.70.10.2:5622")]
    lines = [
        "[node]",
        f'validator_address = "{validator_address}"',
        f"strict_validator_allowlist = {str(strict_allowlist).lower()}",
        "",
        "[network]",
        "persistent_peers = [" + ", ".join(json.dumps(peer) for peer in peers) + "]",
    ]
    if public_p2p_address is not None:
        lines.append(f'public_p2p_address = "{public_p2p_address}"')
    for validator, dial_address in transport_rows:
        lines.extend(
            [
                "",
                "[[network.validator_vpn_transports]]",
                f'validator_address = "{validator}"',
                f'dial_address = "{dial_address}"',
            ]
        )
    (config / "node.toml").write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_epoch_snapshot(
    workspace: Path,
    *,
    local_hash: str = "abc123",
    network_hash: str = "abc123",
    active_validators: list[str] | None = None,
) -> Path:
    path = workspace / "config" / "epoch-validator-set-latest.json"
    payload = {
        "chain_id": 1264,
        "epoch_id": 6,
        "validator_set_version": 3,
        "effective_from_height": 100,
        "quorum_threshold": 2,
        "validator_set_hash": local_hash,
        "local_validator_set_hash": local_hash,
        "network_validator_set_hash": network_hash,
        "active_validators": active_validators or [LOCAL_VALIDATOR, PEER_VALIDATOR],
        "pending_validators": [],
        "jailed_validators": [],
        "removed_validators": [],
    }
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def statuses(findings: list[object]) -> dict[str, list[str]]:
    grouped: dict[str, list[str]] = {}
    for item in findings:
        grouped.setdefault(item.status, []).append(item.name)
    return grouped


class ValidatorVpnRuntimeValidationTests(unittest.TestCase):
    def test_valid_validator_workspace_separates_identity_and_transport(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            write_workspace(workspace, persistent_peers=[PEER_VALIDATOR, "10.70.20.1:5622"])
            write_epoch_snapshot(workspace)

            config_findings, _config = checker.check_config(workspace, "validator", LOCAL_VALIDATOR)
            epoch_findings = checker.check_epoch_snapshot(workspace, None, LOCAL_VALIDATOR, 2)

            self.assertNotIn("FAIL", statuses(config_findings + epoch_findings))

    def test_raw_validator_vpn_ip_in_peer_list_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            write_workspace(workspace, persistent_peers=["10.70.10.2:5622"])

            findings, _config = checker.check_config(workspace, "validator", LOCAL_VALIDATOR)

            self.assertIn("validator peer identity", statuses(findings).get("FAIL", []))

    def test_retired_vpn_route_fails_as_current_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            write_workspace(
                workspace,
                persistent_peers=["10.69.10.2:5622"],
                transports=[(PEER_VALIDATOR, "10.69.10.2:5622")],
            )

            findings, _config = checker.check_config(workspace, "validator", LOCAL_VALIDATOR)
            failed = statuses(findings).get("FAIL", [])

            self.assertIn("retired validator VPN route", failed)
            self.assertIn("validator VPN transport route", failed)

    def test_canonical_vpn_ranges_are_bounded_to_innernet_hosts(self) -> None:
        self.assertTrue(checker.is_validator_vpn_host("10.70.10.1"))
        self.assertTrue(checker.is_validator_vpn_host("10.70.10.254"))
        self.assertFalse(checker.is_validator_vpn_host("10.70.10.0"))
        self.assertFalse(checker.is_validator_vpn_host("10.70.10.255"))
        self.assertTrue(checker.is_relayer_vpn_host("10.70.20.1"))
        self.assertTrue(checker.is_relayer_vpn_host("10.70.20.254"))
        self.assertFalse(checker.is_relayer_vpn_host("10.70.20.0"))
        self.assertFalse(checker.is_relayer_vpn_host("10.70.20.255"))
        self.assertFalse(checker.is_validator_vpn_host("10.69.10.2"))
        self.assertFalse(checker.is_relayer_vpn_host("10.69.0.1"))

    def test_strict_validator_allowlist_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            write_workspace(workspace, strict_allowlist=True)

            findings, _config = checker.check_config(workspace, "validator", LOCAL_VALIDATOR)

            self.assertIn("config allowlist authority", statuses(findings).get("FAIL", []))

    def test_validator_public_endpoint_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            write_workspace(workspace, public_p2p_address="8.8.8.8:5622")

            findings, _config = checker.check_config(workspace, "validator", LOCAL_VALIDATOR)

            self.assertIn("network.public_p2p_address", statuses(findings).get("FAIL", []))

    def test_epoch_validator_set_hash_mismatch_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            (workspace / "config").mkdir(parents=True)
            write_epoch_snapshot(workspace, local_hash="local-hash", network_hash="network-hash")

            findings = checker.check_epoch_snapshot(workspace, None, LOCAL_VALIDATOR, 2)

            self.assertIn("EpochValidatorSet hash agreement", statuses(findings).get("FAIL", []))

    def test_epoch_validator_set_active_count_mismatch_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            (workspace / "config").mkdir(parents=True)
            write_epoch_snapshot(workspace, active_validators=[LOCAL_VALIDATOR])

            findings = checker.check_epoch_snapshot(workspace, None, LOCAL_VALIDATOR, 2)

            self.assertIn("EpochValidatorSet active count", statuses(findings).get("FAIL", []))


if __name__ == "__main__":
    unittest.main()
