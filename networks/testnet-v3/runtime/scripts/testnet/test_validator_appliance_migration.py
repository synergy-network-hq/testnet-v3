#!/usr/bin/env python3
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).with_name("validator_appliance_migration.py")


def write_valid_fixture(root: Path):
    workspace = root / "home/node/.synergy/testnet/nodes/validator-workspace"
    config_root = root / "etc/synergy/validator"
    target = root / "var/lib/synergy/validator"
    log_root = root / "var/log/synergy/validator"
    service = root / "etc/systemd/system/synergy-validator.service"
    workspace.mkdir(parents=True)
    (workspace / "data").mkdir()
    for name in [
        "chain.json",
        "canonical_locks.json",
        "committed_qcs.jsonl",
        "committed_qcs.json",
        "dag_state.json",
        "token_state.json",
        "validator_registry.json",
    ]:
        (workspace / "data" / name).write_text("{}\n")
    (workspace / "data" / "chain.json").write_text('[{"block_index":1,"hash":"h1"}]\n')
    (workspace / "data" / "canonical_locks.json").write_text('{"1":{"block_hash":"h1"}}\n')
    (workspace / "data" / "committed_qcs.jsonl").write_text(
        '{"qc":{"block_hash":"h1","votes":[{"block_index":1}]}}\n'
    )
    config_root.mkdir(parents=True)
    (config_root / "keys").mkdir()
    (config_root / "keys" / "validator-key.json").write_text("secret\n")
    (config_root / "genesis.json").write_text('{"genesis":"ok"}\n')
    (config_root / "node.env").write_text(
        "SYNERGY_NETWORK=synergy-testnet-v3\n"
        "SYNERGY_CHAIN_ID=1264\n"
        "BASE_DIR=/home/node/.synergy/testnet/nodes/validator-workspace\n"
        "SYNERGY_PROJECT_ROOT=/home/node/.synergy/testnet/nodes/validator-workspace\n"
        "SYNERGY_DATA_DIR=/var/lib/synergy/validator\n"
    )
    (config_root / "config.toml").write_text(
        '[node]\n'
        'network = "synergy-testnet-v3"\n'
        "chain_id = 1264\n"
        'workspace = "/home/node/.synergy/testnet/nodes/validator-workspace"\n'
        'data_dir = "/var/lib/synergy/validator"\n'
        'log_dir = "/var/log/synergy/validator"\n'
    )
    service.parent.mkdir(parents=True)
    service.write_text(
        "[Service]\n"
        "WorkingDirectory=/home/node/.synergy/testnet/nodes/validator-workspace\n"
        "EnvironmentFile=/etc/synergy/validator/node.env\n"
        "ExecStart=/opt/synergy/bin/synergy-validator start --config /etc/synergy/validator/config.toml\n"
        "ReadWritePaths=/var/lib/synergy/validator /var/log/synergy/validator /home/node/.synergy/testnet/nodes/validator-workspace\n"
    )
    target.mkdir(parents=True)
    log_root.mkdir(parents=True)
    return workspace, config_root, target, log_root, service


class ValidatorApplianceMigrationTests(unittest.TestCase):
    def run_script(self, *args, check=True):
        proc = subprocess.run(
            [sys.executable, str(SCRIPT), *args],
            text=True,
            capture_output=True,
            check=False,
        )
        if check and proc.returncode != 0:
            raise AssertionError(proc.stderr + proc.stdout)
        return proc

    def test_dry_run_does_not_mutate_old_workspace(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            workspace, config_root, target, log_root, service = write_valid_fixture(root)
            proc = self.run_script(
                "--dry-run",
                "--no-systemd",
                "--validator-name",
                "ValX",
                "--source-workspace",
                str(workspace),
                "--target-root",
                str(target),
                "--config-root",
                str(config_root),
                "--log-root",
                str(log_root),
                "--service-path",
                str(service),
                "--archive-root",
                str(root / "archives"),
                "--rollback-root",
                str(root / "rollback"),
            )
            report = json.loads(proc.stdout)
            self.assertTrue(report["ok"], report)
            self.assertEqual(report["decision"], "DRY_RUN_GO")
            self.assertTrue((workspace / "data").is_dir())
            self.assertIn("validator-workspace", service.read_text())

    def test_apply_archives_old_workspace_and_rewrites_paths(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            workspace, config_root, target, log_root, service = write_valid_fixture(root)
            proc = self.run_script(
                "--apply",
                "--no-systemd",
                "--validator-name",
                "ValX",
                "--source-workspace",
                str(workspace),
                "--target-root",
                str(target),
                "--config-root",
                str(config_root),
                "--log-root",
                str(log_root),
                "--service-path",
                str(service),
                "--archive-root",
                str(root / "archives"),
                "--rollback-root",
                str(root / "rollback"),
            )
            report = json.loads(proc.stdout)
            self.assertTrue(report["ok"], report)
            self.assertEqual(report["decision"], "GO")
            self.assertFalse(workspace.is_symlink())
            self.assertEqual(
                [p.name for p in workspace.iterdir()],
                ["README.validator-appliance-migrated.txt"],
            )
            self.assertNotIn("validator-workspace", service.read_text())
            self.assertIn(f"WorkingDirectory={target}", service.read_text())
            self.assertNotIn("validator-workspace", (config_root / "node.env").read_text())
            self.assertNotIn("validator-workspace", (config_root / "service.env").read_text())
            self.assertNotIn("validator-workspace", (config_root / "config.toml").read_text())
            self.assertTrue(Path(report["archive"]["archive"]).is_file())
            self.assertTrue(target.joinpath("state/derived/chain_export.json").is_file())
            self.assertTrue(target.joinpath("identity/key_manifest.json").is_file())


if __name__ == "__main__":
    unittest.main()
